package providerplan

import (
	"strings"
	"testing"
)

func graphPlanCompletionStructuralFixture(rowKinds map[string][]string) graphPlanSchemaBindingProof {
	return graphPlanSchemaBindingProof{
		seal:              graphPlanSchemaBindingAuthority,
		plan:              stageArtifactIdentity{RawSHA256: sha256Hex([]byte(`{"row_kind":"fixture"}`))},
		setKindsByRowKind: rowKinds,
	}
}

func graphPlanCompletionReceipt() StageReceiptReference {
	return StageReceiptReference{
		StageKind:        stageGraphCompile,
		ReceiptSHA256:    strings.Repeat("a", 64),
		OutputRootSHA256: strings.Repeat("b", 64),
	}
}

func TestNewGraphPlanParseProofRequiresASealedStructuralProof(t *testing.T) {
	request := strings.Repeat("c", 64)

	unsealed := graphPlanCompletionStructuralFixture(map[string][]string{"fixture": {"symbols"}})
	unsealed.seal = nil
	if _, err := newGraphPlanParseProof(unsealed, request, graphPlanCompletionReceipt()); err == nil ||
		!strings.Contains(err.Error(), "requires a sealed structural proof") {
		t.Fatalf("unsealed structural error = %v, want a sealed-proof refusal", err)
	}

	noDigest := graphPlanCompletionStructuralFixture(map[string][]string{"fixture": {"symbols"}})
	noDigest.plan.RawSHA256 = "not-a-sha256"
	if _, err := newGraphPlanParseProof(noDigest, request, graphPlanCompletionReceipt()); err == nil ||
		!strings.Contains(err.Error(), "requires a sealed structural proof") {
		t.Fatalf("malformed plan digest error = %v, want a sealed-proof refusal", err)
	}
}

func TestNewGraphPlanParseProofRequiresExactRequestAndReceiptIdentities(t *testing.T) {
	structural := graphPlanCompletionStructuralFixture(map[string][]string{"fixture": {"symbols"}})
	valid := strings.Repeat("c", 64)

	for _, test := range []struct {
		name    string
		request string
		receipt StageReceiptReference
	}{
		{
			name:    "malformed request digest",
			request: "not-a-sha256",
			receipt: graphPlanCompletionReceipt(),
		},
		{
			name:    "wrong stage kind",
			request: valid,
			receipt: StageReceiptReference{StageKind: "evidence_intake", ReceiptSHA256: strings.Repeat("a", 64), OutputRootSHA256: strings.Repeat("b", 64)},
		},
		{
			name:    "malformed receipt digest",
			request: valid,
			receipt: StageReceiptReference{StageKind: stageGraphCompile, ReceiptSHA256: "short", OutputRootSHA256: strings.Repeat("b", 64)},
		},
		{
			name:    "malformed output root digest",
			request: valid,
			receipt: StageReceiptReference{StageKind: stageGraphCompile, ReceiptSHA256: strings.Repeat("a", 64), OutputRootSHA256: ""},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newGraphPlanParseProof(structural, test.request, test.receipt); err == nil ||
				!strings.Contains(err.Error(), "exact graph request/receipt/root identities") {
				t.Fatalf("error = %v, want an exact-identity refusal", err)
			}
		})
	}
}

func TestRequireGraphPlanParseProofRefusesUnsealedAndRosterFreeProofs(t *testing.T) {
	raw := []byte(`{"row_kind":"fixture"}`)

	var unsealed graphPlanParseProof
	if err := requireGraphPlanParseProof(unsealed, raw); err == nil ||
		!strings.Contains(err.Error(), "requires sealed structural and body-free stage proofs") {
		t.Fatalf("unsealed proof error = %v, want a sealed-proof refusal", err)
	}

	// A structurally sealed proof whose row-disposition roster is empty cannot
	// close the set of admissible row kinds, so parsing must refuse it.
	rosterFree, err := newGraphPlanParseProof(graphPlanCompletionStructuralFixture(nil), strings.Repeat("c", 64), graphPlanCompletionReceipt())
	if err != nil {
		t.Fatal(err)
	}
	if err := requireGraphPlanParseProof(rosterFree, raw); err == nil ||
		!strings.Contains(err.Error(), "no closed row disposition roster") {
		t.Fatalf("roster-free proof error = %v, want a closed-roster refusal", err)
	}
}

func TestGraphPlanSetKindsRefusesAnUnsealedProof(t *testing.T) {
	var unsealed graphPlanParseProof
	if kinds, ok := graphPlanSetKinds(unsealed, "fixture"); ok || kinds != nil {
		t.Fatalf("unsealed set kinds = %v, %v, want nil and false", kinds, ok)
	}

	sealed, err := newGraphPlanParseProof(
		graphPlanCompletionStructuralFixture(map[string][]string{"fixture": {"symbols"}}),
		strings.Repeat("c", 64), graphPlanCompletionReceipt())
	if err != nil {
		t.Fatal(err)
	}
	broken := sealed
	broken.structural.seal = nil
	if kinds, ok := graphPlanSetKinds(broken, "fixture"); ok || kinds != nil {
		t.Fatalf("unsealed structural set kinds = %v, %v, want nil and false", kinds, ok)
	}
	if _, ok := graphPlanSetKinds(sealed, "absent_row_kind"); ok {
		t.Fatal("an undeclared row kind reported a disposition")
	}
}

func TestScanGraphPlanRowKindsRefusesMalformedAndNoncanonicalRows(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "truncated row", raw: `{"row_kind":`, want: "graph plan line 1"},
		{name: "row kind is not a string", raw: `{"row_kind":7}`, want: "row-kind envelope"},
		{name: "empty row kind", raw: `{"row_kind":""}`, want: "no canonical row_kind"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := scanGraphPlanRowKinds([]byte(test.raw)); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestScanGraphPlanRowKindsSkipsBlankLinesAndCollectsEveryKind(t *testing.T) {
	raw := []byte("{\"row_kind\":\"symbols\"}\n\n   \n{\"row_kind\":\"relationships\"}\n")
	kinds, err := scanGraphPlanRowKinds(raw)
	if err != nil {
		t.Fatalf("well-formed graph plan was rejected: %v", err)
	}
	if len(kinds) != 2 {
		t.Fatalf("row kinds = %v, want both declared kinds", kinds)
	}
	for _, want := range []string{"symbols", "relationships"} {
		if _, ok := kinds[want]; !ok {
			t.Fatalf("row kinds = %v, want %q present", kinds, want)
		}
	}
}
