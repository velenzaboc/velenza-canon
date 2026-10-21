package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

type typedGraphPredecessorArtifacts = map[string]struct {
	input artifactInput
	rows  dependencySemanticRows
}

func typedGraphCompletionFact() typedGraphPredecessorFact {
	return typedGraphPredecessorFact{
		ArtifactRole:     typedGraphArtifactRoleSourceContract,
		ArtifactID:       "source_contract_index",
		ArtifactVersion:  "1",
		ArtifactSHA256:   sha256Hex([]byte("artifact")),
		RowKind:          "api_operation",
		RowIdentityField: "source_symbol",
		RowIdentityValue: "list_invoices",
		RowRawSHA256:     sha256Hex([]byte(`{"row_kind":"api_operation"}`)),
		FactKind:         typedGraphFactSourceOperationAccess,
		FactOrdinal:      0,
	}
}

func TestValidateAndResolveTypedGraphPredecessorBindingRefusesUnprovenRosters(t *testing.T) {
	const candidateKind = "api_relationship"
	const candidateIdentity = "capi_rel_fixture"
	fact := typedGraphCompletionFact()

	ordered, err := typedGraphPredecessorDerivationBindingFor(candidateKind, candidateIdentity, []typedGraphPredecessorFact{fact})
	if err != nil {
		t.Fatal(err)
	}

	unordered := typedGraphPredecessorDerivationBinding{
		Kind:             typedGraphPredecessorDerivationKind,
		PredecessorFacts: []typedGraphPredecessorFact{fact, fact},
	}
	unordered.ID = typedGraphPredecessorDerivationBindingID(candidateKind, candidateIdentity, unordered.PredecessorFacts)
	unorderedRaw, err := json.Marshal(unordered)
	if err != nil {
		t.Fatal(err)
	}

	rewrittenID := typedGraphPredecessorDerivationBinding{
		Kind: typedGraphPredecessorDerivationKind, ID: "capider_rewritten",
		PredecessorFacts: []typedGraphPredecessorFact{fact},
	}
	rewrittenRaw, err := json.Marshal(rewrittenID)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name      string
		raw       json.RawMessage
		artifacts typedGraphPredecessorArtifacts
		want      string
	}{
		{
			name: "not the closed contract",
			raw:  json.RawMessage(`{"unknown_member":1}`),
			want: "is not the closed",
		},
		{
			name: "wrong binding kind",
			raw:  json.RawMessage(`{"derivation_binding_kind":"some_other_kind","derivation_binding_id":"x","predecessor_facts":[]}`),
			want: "wrong kind or an empty predecessor fact roster",
		},
		{
			name: "empty predecessor roster",
			raw:  json.RawMessage(`{"derivation_binding_kind":"` + typedGraphPredecessorDerivationKind + `","derivation_binding_id":"x","predecessor_facts":[]}`),
			want: "wrong kind or an empty predecessor fact roster",
		},
		{
			name: "roster is not in strict canonical order",
			raw:  unorderedRaw,
			want: "not in strict canonical order",
		},
		{
			name: "binding id is not content-derived",
			raw:  rewrittenRaw,
			want: "not content-derived from the outer candidate",
		},
		{
			name:      "artifact role is outside the closed roster",
			raw:       ordered,
			artifacts: typedGraphPredecessorArtifacts{},
			want:      "outside the closed source/protocol-independent predecessor roster",
		},
		{
			name: "artifact identity does not bind the selected artifact",
			raw:  ordered,
			artifacts: typedGraphPredecessorArtifacts{
				typedGraphArtifactRoleSourceContract: {
					input: artifactInput{
						Raw:      []byte("different artifact bytes"),
						Manifest: map[string]interface{}{"artifact": "source_contract_index", "artifact_version": "1"},
					},
				},
			},
			want: "does not bind the exact selected artifact identity/version/raw SHA",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			artifacts := test.artifacts
			if artifacts == nil {
				artifacts = typedGraphPredecessorArtifacts{}
			}
			resolved, err := validateAndResolveTypedGraphPredecessorBinding(candidateKind, candidateIdentity, test.raw, artifacts)
			if err == nil {
				t.Fatalf("an unproven predecessor binding was accepted")
			}
			if resolved != nil {
				t.Fatalf("a refused binding resolved %d predecessors, want none", len(resolved))
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestValidateAndResolveTypedGraphPredecessorBindingRequiresExactlyOneRow(t *testing.T) {
	const candidateKind = "api_relationship"
	const candidateIdentity = "capi_rel_fixture"
	artifactRaw := []byte("artifact")
	rowRaw := []byte(`{"row_kind":"api_operation","source_symbol":"list_invoices"}`)

	fact := typedGraphCompletionFact()
	fact.ArtifactSHA256 = sha256Hex(artifactRaw)
	fact.RowRawSHA256 = sha256Hex(rowRaw)
	ordered, err := typedGraphPredecessorDerivationBindingFor(candidateKind, candidateIdentity, []typedGraphPredecessorFact{fact})
	if err != nil {
		t.Fatal(err)
	}
	input := artifactInput{Raw: artifactRaw, Manifest: map[string]interface{}{"artifact": "source_contract_index", "artifact_version": "1"}}

	matching := dependencySemanticRow{
		kind: "api_operation", raw: rowRaw,
		data: map[string]interface{}{"row_kind": "api_operation", "source_symbol": "list_invoices"},
	}

	t.Run("no row resolves", func(t *testing.T) {
		artifacts := typedGraphPredecessorArtifacts{
			typedGraphArtifactRoleSourceContract: {input: input, rows: dependencySemanticRows{byKind: map[string][]dependencySemanticRow{}}},
		}
		if _, err := validateAndResolveTypedGraphPredecessorBinding(candidateKind, candidateIdentity, ordered, artifacts); err == nil ||
			!strings.Contains(err.Error(), "resolves 0 rows, want exactly 1") {
			t.Fatalf("error = %v, want a single-row resolution refusal", err)
		}
	})

	t.Run("two rows resolve", func(t *testing.T) {
		artifacts := typedGraphPredecessorArtifacts{
			typedGraphArtifactRoleSourceContract: {input: input, rows: dependencySemanticRows{byKind: map[string][]dependencySemanticRow{
				"api_operation": {matching, matching},
			}}},
		}
		if _, err := validateAndResolveTypedGraphPredecessorBinding(candidateKind, candidateIdentity, ordered, artifacts); err == nil ||
			!strings.Contains(err.Error(), "resolves 2 rows, want exactly 1") {
			t.Fatalf("error = %v, want a single-row resolution refusal", err)
		}
	})

	t.Run("resolved row bytes differ from the sealed digest", func(t *testing.T) {
		altered := matching
		altered.raw = []byte(`{"row_kind":"api_operation","source_symbol":"list_invoices","extra":1}`)
		artifacts := typedGraphPredecessorArtifacts{
			typedGraphArtifactRoleSourceContract: {input: input, rows: dependencySemanticRows{byKind: map[string][]dependencySemanticRow{
				"api_operation": {altered},
			}}},
		}
		if _, err := validateAndResolveTypedGraphPredecessorBinding(candidateKind, candidateIdentity, ordered, artifacts); err == nil ||
			!strings.Contains(err.Error(), "row_raw_sha256 does not equal exact selected row bytes") {
			t.Fatalf("error = %v, want an exact-row-bytes refusal", err)
		}
	})
}

func TestValidateSourceOperationAccessRelationshipDerivationRefusesUntypedPredecessors(t *testing.T) {
	if err := validateSourceOperationAccessRelationshipDerivation(nil, loadedEvidence{}, apiRelationship{}, nil); err == nil ||
		!strings.Contains(err.Error(), "want exactly one typed source operation access") {
		t.Fatalf("empty predecessor error = %v, want a single-predecessor refusal", err)
	}

	wrongFamily := typedGraphCompletionFact()
	wrongFamily.FactKind = typedGraphFactGraphApplicabilityRule
	predecessors := []resolvedTypedGraphPredecessor{{fact: wrongFamily}}
	if err := validateSourceOperationAccessRelationshipDerivation(nil, loadedEvidence{}, apiRelationship{}, predecessors); err == nil ||
		!strings.Contains(err.Error(), "not a typed source_contract_index api_operation.resource_accesses member") {
		t.Fatalf("wrong predecessor family error = %v, want a typed-family refusal", err)
	}
}

func TestValidateGraphApplicabilityGapDerivationRefusesUngovernedGaps(t *testing.T) {
	applicabilityFact := func(rowKind string) typedGraphPredecessorFact {
		return typedGraphPredecessorFact{
			ArtifactRole:     typedGraphArtifactRoleAPIApplicability,
			RowKind:          rowKind,
			RowIdentityField: "applicability_rule_id",
			RowIdentityValue: "rule_one",
			FactKind:         typedGraphFactGraphApplicabilityRule,
			FactOrdinal:      -1,
		}
	}
	gap := graphGap{ApplicabilityRuleID: "rule_one", BlockedClaimKind: "api_relationship", BlockedSubjectKind: "api_symbol"}

	if err := validateGraphApplicabilityGapDerivation(gap, nil); err == nil ||
		!strings.Contains(err.Error(), "want exactly one graph applicability rule") {
		t.Fatalf("empty predecessor error = %v, want a single-predecessor refusal", err)
	}

	for _, test := range []struct {
		name string
		gap  graphGap
		fact typedGraphPredecessorFact
		data map[string]interface{}
		want string
	}{
		{
			name: "predecessor is not the gap's own applicability rule",
			gap:  gap,
			fact: func() typedGraphPredecessorFact {
				fact := applicabilityFact("relationship_applicability_rule")
				fact.RowIdentityValue = "a_different_rule"
				return fact
			}(),
			want: "not the gap's exact whole-row API graph applicability rule",
		},
		{
			name: "relationship rule does not govern a relationship gap",
			gap:  graphGap{ApplicabilityRuleID: "rule_one", BlockedClaimKind: "api_property_claim"},
			fact: applicabilityFact("relationship_applicability_rule"),
			data: map[string]interface{}{"relationship_label": "reads"},
			want: "does not govern an API relationship gap",
		},
		{
			name: "property rule does not govern a property gap",
			gap:  gap,
			fact: applicabilityFact("property_family_applicability_rule"),
			data: map[string]interface{}{"property_family": "identity"},
			want: "does not govern an API property gap",
		},
		{
			name: "claim rule does not govern the blocked claim and subject",
			gap:  gap,
			fact: applicabilityFact("claim_applicability_rule"),
			data: map[string]interface{}{"blocked_claim_kind": "api_property_claim", "blocked_subject_kind": "api_symbol"},
			want: "does not exactly govern the gap's blocked claim/subject kinds",
		},
		{
			name: "unsupported applicability row kind",
			gap:  gap,
			fact: applicabilityFact("some_other_rule"),
			want: "is unsupported",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			predecessor := resolvedTypedGraphPredecessor{fact: test.fact, row: dependencySemanticRow{data: test.data}}
			err := validateGraphApplicabilityGapDerivation(test.gap, []resolvedTypedGraphPredecessor{predecessor})
			if err == nil {
				t.Fatalf("an ungoverned gap was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestTypedGraphPredecessorFactForRowRequiresExactArtifactAndRowIdentity(t *testing.T) {
	row := dependencySemanticRow{kind: "api_operation", raw: []byte(`{"row_kind":"api_operation"}`)}
	for _, test := range []struct {
		name  string
		input artifactInput
		row   dependencySemanticRow
	}{
		{name: "manifest has no artifact", input: artifactInput{Manifest: map[string]interface{}{"artifact_version": "1"}}, row: row},
		{name: "manifest has no version", input: artifactInput{Manifest: map[string]interface{}{"artifact": "source_contract_index"}}, row: row},
		{
			name:  "row carries no bytes",
			input: artifactInput{Manifest: map[string]interface{}{"artifact": "source_contract_index", "artifact_version": "1"}},
			row:   dependencySemanticRow{kind: "api_operation"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := typedGraphPredecessorFactForRow(typedGraphArtifactRoleSourceContract, test.input, test.row, "source_symbol", "list_invoices", typedGraphFactSourceOperationAccess, 0)
			if err == nil || !strings.Contains(err.Error(), "no exact artifact and row identity") {
				t.Fatalf("error = %v, want an exact-identity refusal", err)
			}
		})
	}
}
