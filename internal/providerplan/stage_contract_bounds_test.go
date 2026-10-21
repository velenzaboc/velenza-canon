package providerplan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStageContractPinsCoordinatesAndDigestLedgerFailClosed(t *testing.T) {
	digest := strings.Repeat("a", 64)
	pin := immutableStageArtifactPin{Role: "source_contract", ID: "source.contract", Version: "v1", RawSHA256: digest, AuthorityClass: "admitted"}
	ledger := newStageDigestLedger()
	if err := validateImmutableStageArtifactPin("fixture", pin, ledger); err != nil {
		t.Fatalf("valid immutable pin: %v", err)
	}
	if err := validateImmutableStageArtifactPin("other", pin, ledger); err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("digest alias error=%v", err)
	}
	for name, mutate := range map[string]func(*immutableStageArtifactPin){
		"invalid role":       func(value *immutableStageArtifactPin) { value.Role = "Organization_ID" },
		"invalid coordinate": func(value *immutableStageArtifactPin) { value.ID = "org_id" },
		"invalid version":    func(value *immutableStageArtifactPin) { value.Version = "V1" },
		"invalid authority":  func(value *immutableStageArtifactPin) { value.AuthorityClass = "untrusted" },
		"invalid digest":     func(value *immutableStageArtifactPin) { value.RawSHA256 = "not-a-digest" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := pin
			mutate(&candidate)
			if err := validateImmutableStageArtifactPin("fixture", candidate, newStageDigestLedger()); err == nil {
				t.Fatal("invalid immutable pin was accepted")
			}
		})
	}
	identity := stageArtifactIdentity{Role: "profile", ID: "profile.id", Version: "v1", RawSHA256: strings.Repeat("b", 64)}
	if err := validateStageArtifactIdentity("identity", identity, newStageDigestLedger()); err != nil {
		t.Fatalf("valid identity: %v", err)
	}
	if err := validateStageReference(StageReceiptReference{StageKind: "invented", ReceiptSHA256: digest, OutputRootSHA256: digest}); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown stage reference error=%v", err)
	}
}

func TestStageContractEvidenceContentAndCommitmentOrderingAreExact(t *testing.T) {
	bodies := map[string]exactEvidenceBody{}
	digest := strings.Repeat("a", 64)
	if err := addExactStageEvidenceContent(bodies, digest, []byte("exact bytes")); err != nil {
		t.Fatalf("add exact evidence: %v", err)
	}
	if err := addExactStageEvidenceContent(bodies, digest, []byte("exact bytes")); err != nil {
		t.Fatalf("re-add equal evidence: %v", err)
	}
	if err := addExactStageEvidenceContent(bodies, digest, []byte("altered")); err == nil || !strings.Contains(err.Error(), "unequal") {
		t.Fatalf("digest substitution error=%v", err)
	}
	if !bytes.Equal(bodies[digest].Bytes, []byte("exact bytes")) {
		t.Fatalf("stored exact bytes=%q", bodies[digest].Bytes)
	}
	commitments := []StageEvidenceCommitment{
		{ManifestRole: "evidence_manifest", ManifestID: "manifest.a", ManifestVersion: "v1", ComponentOrdinal: 0, BodySHA256: digest, ByteCount: 10},
		{ManifestRole: "evidence_manifest", ManifestID: "manifest.a", ManifestVersion: "v1", ComponentOrdinal: 1, BodySHA256: strings.Repeat("b", 64), ByteCount: 5},
		{ManifestRole: "evidence_manifest", ManifestID: "manifest.b", ManifestVersion: "v1", ComponentOrdinal: 0, BodySHA256: strings.Repeat("c", 64), ByteCount: 1},
	}
	if err := validateStageEvidenceCommitmentRoster(commitments); err != nil {
		t.Fatalf("ordered commitment roster: %v", err)
	}
	gap := append([]StageEvidenceCommitment(nil), commitments...)
	gap[1].ComponentOrdinal = 2
	if err := validateStageEvidenceCommitmentRoster(gap); err == nil || !strings.Contains(err.Error(), "contiguous") {
		t.Fatalf("ordinal gap error=%v", err)
	}
	reordered := append([]StageEvidenceCommitment(nil), commitments...)
	reordered[0], reordered[2] = reordered[2], reordered[0]
	if err := validateStageEvidenceCommitmentRoster(reordered); err == nil || !strings.Contains(err.Error(), "strictly ordered") {
		t.Fatalf("roster ordering error=%v", err)
	}
	zeroBytes := append([]StageEvidenceCommitment(nil), commitments...)
	zeroBytes[0].ByteCount = 0
	if err := validateStageEvidenceCommitmentRoster(zeroBytes); err == nil || !strings.Contains(err.Error(), "zero") {
		t.Fatalf("zero byte commitment error=%v", err)
	}
}

func TestStageContractSegmentationBudgetsAndWrappedBoundaries(t *testing.T) {
	if stageEvidenceSegmentationPrefix([]byte("abcdef")) != stageEvidenceSegmentationPrefix([]byte("abcdef")) || stageEvidenceSortComparisonBound(1) != 0 || stageEvidenceSortComparisonBound(16) <= 16 {
		t.Fatal("segmentation prefix or comparison bound is not deterministic")
	}
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 2, indexBytesLimit: 2, candidateBytesLimit: 2, scalarIndexWorkLimit: 2}
	if err := budget.consumeComparisons(2, "fixture"); err != nil {
		t.Fatal(err)
	}
	if err := budget.consumeComparisons(1, "fixture"); err == nil || !strings.Contains(err.Error(), "comparison") {
		t.Fatalf("comparison cap error=%v", err)
	}
	if err := budget.consumeIndexBytes(3); err == nil || !strings.Contains(err.Error(), "index") {
		t.Fatalf("index cap error=%v", err)
	}
	if err := budget.consumeCandidateBytes(3); err == nil || !strings.Contains(err.Error(), "candidate") {
		t.Fatalf("candidate cap error=%v", err)
	}
	if err := budget.consumeScalarIndexWork(3); err == nil || !strings.Contains(err.Error(), "linear-work") {
		t.Fatalf("scalar work cap error=%v", err)
	}
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("abc")}}, {representations: [][]byte{[]byte("def")}},
	}
	found, err := stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithBudget([]byte("abcdef"), carriers, &stageEvidenceSegmentationBudget{statesRemaining: 1024, comparisonsRemaining: 1 << 20})
	if err != nil || !found {
		t.Fatalf("two-occurrence wrapped segmentation found=%v err=%v", found, err)
	}
	if found, err := stageEvidenceTargetHasWrappedTwoOccurrenceSegmentationWithBudget([]byte("abc"), carriers, &stageEvidenceSegmentationBudget{statesRemaining: 1024, comparisonsRemaining: 1 << 20}); err != nil || found {
		t.Fatalf("short wrapped target found=%v err=%v", found, err)
	}
	if multiplicity := stageEvidenceCarrierOccurrenceMultiplicity(stageEvidenceCarrierOccurrence{}); multiplicity != 1 || !stageEvidenceMultiplicitiesAtLeast([]int{1, 1}, 2) || stageEvidenceMultiplicitiesAtLeast([]int{1}, 2) {
		t.Fatal("occurrence multiplicity accounting changed")
	}
}

func TestStageContractBodyFreeSchemaAndExternalEvidenceProofBoundaries(t *testing.T) {
	constant := map[string]interface{}{"required": []interface{}{"name"}, "properties": map[string]interface{}{"name": map[string]interface{}{"const": "bound"}}}
	if !stageBodyFreeSchemaCouldMatch(map[string]interface{}{"name": "bound"}, constant, 0) {
		t.Fatal("matching constrained value was rejected")
	}
	for _, value := range []interface{}{"bound", map[string]interface{}{}, map[string]interface{}{"name": "changed"}} {
		if stageBodyFreeSchemaCouldMatch(value, constant, 0) {
			t.Fatalf("schema accepted nonmatching value %#v", value)
		}
	}
	proofs := map[stageBodyFreePointerCoordinate]string{}
	stageBodyFreeProveConstantValue(map[string]interface{}{"name": "bound", "items": []interface{}{"one", "two"}}, 7, "", proofs, 0)
	if proofs[stageBodyFreePointerCoordinate{row: 7, pointer: "/name"}] != "bound" || proofs[stageBodyFreePointerCoordinate{row: 7, pointer: "/items/1"}] != "two" {
		t.Fatalf("constant proofs lost nested values: %#v", proofs)
	}
	schemaProofs := stageBodyFreeJSONSchemaDocumentProofs([]byte(`{"type":"object","properties":{"name":{"const":"bound"}},"required":["name"]}`))
	for _, pointer := range []string{jsonPointerObjectKey("", "type"), jsonPointerObjectKey("", "properties"), jsonPointerObjectKey("", "required"), jsonPointerObjectKey("/properties/name", "const")} {
		if _, ok := schemaProofs[stageBodyFreePointerCoordinate{row: 1, pointer: pointer}]; !ok {
			t.Fatalf("schema keyword %s was not proven: %#v", pointer, schemaProofs)
		}
	}
	if len(stageBodyFreeJSONSchemaDocumentProofs([]byte(`{`))) != 0 {
		t.Fatal("malformed schema generated trust proofs")
	}
	body := []byte("exact selected body")
	digest := sha256Hex(body)
	rows := []byte(`{"row_kind":"external_evidence_body","content_sha256":"` + digest + `","content_bytes":19,"component_sha256":"` + digest + `","component_byte_length":19}` + "\n" + `{"row_kind":"external_evidence_body","content_sha256":"` + digest + `","content_bytes":18}`)
	external := stageBodyFreeExternalBodyRowProofs(rows, map[string]exactEvidenceBody{digest: {Bytes: body}})
	if external[stageBodyFreePointerCoordinate{row: 1, pointer: "/content_sha256"}] != digest || external[stageBodyFreePointerCoordinate{row: 1, pointer: "/component_sha256"}] != digest {
		t.Fatalf("exact external body row was not proven: %#v", external)
	}
	if _, found := external[stageBodyFreePointerCoordinate{row: 2, pointer: "/content_sha256"}]; found {
		t.Fatal("wrong byte count external row was trusted")
	}
	for _, value := range []interface{}{json.Number("19"), json.Number("19.0"), json.Number("1e2"), "19"} {
		got, ok := stageBodyFreeJSONUint64(value)
		if number, numeric := value.(json.Number); numeric && string(number) == "19" {
			if !ok || got != 19 {
				t.Fatalf("exact integer parse = %d,%v", got, ok)
			}
		} else if ok {
			t.Fatalf("noncanonical number %v was accepted", value)
		}
	}
}

func TestStageContractCarrierRepresentationsFoldAndSegmentationRefusals(t *testing.T) {
	storage := &stageEvidenceCarrierStorageBudget{}
	for _, carrier := range []orderedJSONCarrier{
		{bytes: []byte("YWJj"), kind: orderedJSONStringValue},
		{bytes: []byte("616263"), kind: orderedJSONStringValue},
		{bytes: []byte{1, 2, 3}, kind: orderedJSONByteArray},
	} {
		representations, err := stageEvidenceCarrierRepresentations(carrier, storage)
		if err != nil || len(representations) < 1 {
			t.Fatalf("representations for %q = %#v, %v", carrier.bytes, representations, err)
		}
	}
	if got, err := stageEvidenceCarrierRepresentations(orderedJSONCarrier{bytes: []byte("zz"), kind: orderedJSONStringValue}, storage); err != nil || len(got) != 1 {
		t.Fatalf("ordinary scalar representations=%q err=%v", got, err)
	}
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("AB"), []byte("AB")}, multiplicity: 2}, {representations: [][]byte{[]byte("cd")}}}
	folded, err := stageEvidenceHexFoldedCarrierOccurrences(carriers, storage)
	if err != nil || len(folded[0].representations) != 2 || !bytes.Equal(folded[0].representations[1], []byte("ab")) || folded[0].multiplicity != 2 {
		t.Fatalf("hex folding=%#v err=%v", folded, err)
	}
	index, err := newStageEvidenceSegmentationIndexBounded([]stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("ab")}}, {representations: [][]byte{[]byte("cd")}}}, &stageEvidenceSegmentationBudget{})
	if err != nil {
		t.Fatal(err)
	}
	budget := &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 4096, comparisonsRemaining: 4096, statesRemaining: 4096}
	reachable, err := stageEvidenceTargetReachableWithoutOccurrenceReuse([]byte("abcd"), index, budget)
	if err != nil || !reachable {
		t.Fatalf("reachable segmentation=%v err=%v", reachable, err)
	}
	if reachable, err = stageEvidenceTargetReachableWithoutOccurrenceReuse([]byte("abce"), index, &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 4096, comparisonsRemaining: 4096}); err != nil || reachable {
		t.Fatalf("unreachable segmentation=%v err=%v", reachable, err)
	}
	_, capacity, feasible, err := stageEvidenceSegmentationFeasible([]byte("abcd"), []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("ab")}}, {representations: [][]byte{[]byte("cd")}}}, true, &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 4096})
	if err != nil || !feasible || capacity != 4 {
		t.Fatalf("feasibility capacity=%d feasible=%v err=%v", capacity, feasible, err)
	}
	_, _, feasible, err = stageEvidenceSegmentationFeasible([]byte("abcde"), []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("ab")}}}, true, &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 4096})
	if err != nil || feasible {
		t.Fatalf("short capacity was accepted: feasible=%v err=%v", feasible, err)
	}
}

func TestStageContractClosedDecodersRejectTamperedNestedBindings(t *testing.T) {
	fixture := newStageContractFixture(t)
	validHeaders := [][]byte{fixture.evidenceRequest.raw, fixture.semanticRequest.raw, fixture.graphRequest.raw, fixture.fullRequest.raw}
	for _, raw := range validHeaders {
		header, err := decodeStageRequestHeader(raw)
		if err != nil || !validStageKind(header.StageKind) {
			t.Fatalf("valid request header=%+v err=%v", header, err)
		}
	}
	for name, raw := range map[string][]byte{
		"missing":       []byte(`{"request_kind":"stage_compile","request_version":"v1"}`),
		"wrong kind":    []byte(`{"request_kind":"wrong","request_version":"v1","stage_kind":"evidence_intake"}`),
		"unknown stage": []byte(`{"request_kind":"stage_compile","request_version":"v1","stage_kind":"unknown"}`),
		"duplicate":     []byte(`{"request_kind":"stage_compile","request_kind":"stage_compile","request_version":"v1","stage_kind":"evidence_intake"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStageRequestHeader(raw); err == nil {
				t.Fatal("invalid request header was accepted")
			}
		})
	}
	var evidence, semantic, graph stageReceipt
	for _, item := range []struct {
		raw  []byte
		dest *stageReceipt
	}{{fixture.evidenceReceipt, &evidence}, {fixture.semanticReceipt, &semantic}, {fixture.graphReceipt, &graph}} {
		if err := json.Unmarshal(item.raw, item.dest); err != nil {
			t.Fatal(err)
		}
	}
	var evidenceBinding evidenceIntakeStageBinding
	if err := decodeEvidenceIntakeBinding(evidence.Binding, &evidenceBinding); err != nil || validateEvidenceIntakeBinding(evidenceBinding) != nil {
		t.Fatalf("valid evidence binding err=%v", err)
	}
	var semanticBinding semanticExtractionStageBinding
	if err := decodeSemanticExtractionBinding(semantic.Binding, &semanticBinding); err != nil || validateSemanticExtractionBinding(semanticBinding) != nil {
		t.Fatalf("valid semantic binding err=%v", err)
	}
	var graphBinding graphCompileStageBinding
	if err := decodeGraphCompileBinding(graph.Binding, &graphBinding); err != nil || validateGraphCompileBinding(graphBinding) != nil {
		t.Fatalf("valid graph binding err=%v", err)
	}
	for name, raw := range map[string][]byte{
		"evidence extra": append(append([]byte{}, evidence.Binding[:len(evidence.Binding)-1]...), []byte(`,"extra":true}`)...),
		"semantic extra": append(append([]byte{}, semantic.Binding[:len(semantic.Binding)-1]...), []byte(`,"extra":true}`)...),
		"graph extra":    append(append([]byte{}, graph.Binding[:len(graph.Binding)-1]...), []byte(`,"extra":true}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			switch name[:4] {
			case "evid":
				if err := decodeEvidenceIntakeBinding(raw, &evidenceBinding); err == nil {
					t.Fatal("extra evidence field accepted")
				}
			case "sema":
				if err := decodeSemanticExtractionBinding(raw, &semanticBinding); err == nil {
					t.Fatal("extra semantic field accepted")
				}
			default:
				if err := decodeGraphCompileBinding(raw, &graphBinding); err == nil {
					t.Fatal("extra graph field accepted")
				}
			}
		})
	}
	if err := requireExactStageKeys([]byte(`{"one":1,"two":2}`), "one"); err == nil {
		t.Fatal("closed object accepted unbound field")
	}
	if err := requireExactStageKeys([]byte(`{"one":1}`), "one", "two"); err == nil {
		t.Fatal("closed object accepted missing field")
	}
}

func TestStageContractWrappedCandidateSearchAndRawCarrierProjection(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("prefix-abcdef-suffix"), []byte("alternate")}, provenDigestIdentity: true, multiplicity: 2},
		{representations: [][]byte{[]byte("abcdef")}},
		{},
	}
	raw := stageEvidenceRawCarrierOccurrences(carriers)
	if len(raw) != len(carriers) || len(raw[0].representations) != 1 || !bytes.Equal(raw[0].representations[0], carriers[0].representations[0]) || !raw[0].provenDigestIdentity || raw[0].multiplicity != 2 || len(raw[2].representations) != 0 {
		t.Fatalf("raw carrier projection changed occurrence identity: %#v", raw)
	}
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 4096, candidateBytesLimit: 4096}
	candidates, err := stageEvidenceWrappedCandidates([]byte("abcdef"), 0, carriers, true, budget)
	if err != nil || len(candidates) != 2 || candidates[0].occurrence != 0 || candidates[0].length != 5 || candidates[1].occurrence != 1 || candidates[1].length != 5 {
		t.Fatalf("initial wrapped candidates=%#v err=%v", candidates, err)
	}
	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 4096, candidateBytesLimit: 4096}
	candidates, err = stageEvidenceWrappedCandidates([]byte("abcdef"), 0, carriers, false, budget)
	if err != nil || len(candidates) != 2 || candidates[0].length != 6 || candidates[1].length != 6 {
		t.Fatalf("noninitial wrapped candidates=%#v err=%v", candidates, err)
	}
	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 1, candidateBytesLimit: 4096}
	if candidates, err = stageEvidenceWrappedCandidates([]byte("abcdef"), 0, carriers, false, budget); err == nil || candidates != nil {
		t.Fatalf("comparison exhaustion returned candidates=%#v err=%v", candidates, err)
	}
	pattern := []byte("ababa")
	budget = &stageEvidenceSegmentationBudget{comparisonsRemaining: 4096}
	table, err := budget.stageEvidencePatternPrefixTable(pattern)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		representation []byte
		reverse        bool
		want           int
	}{
		{[]byte("xxababaxx"), false, 5}, {[]byte("xxabaz"), false, 3}, {[]byte("ababa"), true, 5}, {nil, false, 0},
	} {
		got, err := stageEvidenceLongestPatternPrefixContained(pattern, table, test.representation, test.reverse, &stageEvidenceSegmentationBudget{comparisonsRemaining: 4096})
		if err != nil || got != test.want {
			t.Fatalf("prefix in %q reverse=%v got=%d err=%v", test.representation, test.reverse, got, err)
		}
	}
	if _, err := stageEvidenceLongestPatternPrefixContained(pattern, table, []byte("ababa"), false, &stageEvidenceSegmentationBudget{}); err == nil {
		t.Fatal("unbudgeted prefix comparison was accepted")
	}
}

func TestStageContractSchemaProofDerivationIntersectsAmbiguousBranches(t *testing.T) {
	value := map[string]interface{}{"name": "bound", "values": []interface{}{"one", "two"}}
	schema := map[string]interface{}{
		"allOf": []interface{}{map[string]interface{}{"properties": map[string]interface{}{"name": map[string]interface{}{"const": "bound"}}}},
		"anyOf": []interface{}{
			map[string]interface{}{"properties": map[string]interface{}{"name": map[string]interface{}{"const": "bound"}}},
			map[string]interface{}{"properties": map[string]interface{}{"name": map[string]interface{}{"const": "bound"}, "values": map[string]interface{}{"prefixItems": []interface{}{map[string]interface{}{"const": "one"}}, "items": map[string]interface{}{"const": "two"}}}},
		},
		"properties": map[string]interface{}{"name": map[string]interface{}{"const": "bound"}, "values": map[string]interface{}{"prefixItems": []interface{}{map[string]interface{}{"const": "one"}}, "items": map[string]interface{}{"const": "two"}}},
	}
	proofs := map[stageBodyFreePointerCoordinate]string{}
	stageBodyFreeDeriveSchemaProofs(value, schema, 3, "", proofs, 0)
	for _, pointer := range []string{"/name", "/values/0", "/values/1"} {
		if _, found := proofs[stageBodyFreePointerCoordinate{row: 3, pointer: pointer}]; !found {
			t.Fatalf("schema derivation omitted %s: %#v", pointer, proofs)
		}
	}
	noMatch := map[stageBodyFreePointerCoordinate]string{}
	stageBodyFreeDeriveSchemaProofs("bound", map[string]interface{}{"oneOf": []interface{}{map[string]interface{}{"const": "other"}, map[string]interface{}{"const": "different"}}}, 4, "", noMatch, 0)
	if len(noMatch) != 0 {
		t.Fatalf("nonmatching branches generated proofs: %#v", noMatch)
	}
	ambiguous := map[stageBodyFreePointerCoordinate]string{}
	stageBodyFreeDeriveSchemaProofs("bound", map[string]interface{}{"oneOf": []interface{}{map[string]interface{}{"const": "bound"}, map[string]interface{}{"const": "bound"}}}, 4, "", ambiguous, 0)
	if ambiguous[stageBodyFreePointerCoordinate{row: 4, pointer: ""}] != "bound" {
		t.Fatalf("equal branch intersection not retained: %#v", ambiguous)
	}
}

func TestStageContractSearchEnginesBacktrackAndFailClosedAtBounds(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abc")}}, {representations: [][]byte{[]byte("def")}}, {representations: [][]byte{[]byte("zzz")}}}
	segmentation, err := newStageEvidenceSegmentationIndexBounded(carriers, &stageEvidenceSegmentationBudget{})
	if err != nil {
		t.Fatal(err)
	}
	budget := &stageEvidenceSegmentationBudget{statesRemaining: 128, comparisonsRemaining: 4096, scalarIndexWorkLimit: 4096}
	found, err := stageEvidenceUnorderedSegmentationSearch([]byte("abcdef"), 9, []int{3, 3, 3}, make([]int, len(carriers)), carriers, segmentation, budget)
	if err != nil || !found {
		t.Fatalf("unordered search found=%v err=%v", found, err)
	}
	if _, err := stageEvidenceUnorderedSegmentationSearch([]byte("abcdef"), 9, []int{3, 3, 3}, make([]int, len(carriers)), carriers, segmentation, &stageEvidenceSegmentationBudget{}); err == nil {
		t.Fatal("unordered search accepted exhausted state budget")
	}
	wrapped, err := newStageEvidenceWrappedIndexBounded(carriers, &stageEvidenceSegmentationBudget{})
	if err != nil {
		t.Fatal(err)
	}
	finish := make([]bool, len("abcdef")+1)
	for i := range finish {
		finish[i] = true
	}
	budget = &stageEvidenceSegmentationBudget{statesRemaining: 128, comparisonsRemaining: 4096, candidateBytesLimit: 4096, scalarIndexWorkLimit: 4096}
	found, err = stageEvidenceWrappedSegmentationSearch([]byte("abcdef"), make([]int, len(carriers)), map[int][]stageEvidenceWrappedCandidate{}, finish, 8, &wrapped, false, budget)
	if err != nil || !found {
		t.Fatalf("wrapped search found=%v err=%v", found, err)
	}
	finish[3] = false
	found, err = stageEvidenceWrappedSegmentationSearch([]byte("abcdef"), make([]int, len(carriers)), map[int][]stageEvidenceWrappedCandidate{}, finish, 8, &wrapped, false, &stageEvidenceSegmentationBudget{statesRemaining: 128, comparisonsRemaining: 4096, candidateBytesLimit: 4096, scalarIndexWorkLimit: 4096})
	if err != nil || found {
		t.Fatalf("unfinishable wrapped path found=%v err=%v", found, err)
	}
	bad := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abc")}, multiplicity: -1}}
	if _, err := newStageEvidenceSegmentationIndexBounded(bad, &stageEvidenceSegmentationBudget{}); err == nil {
		t.Fatal("segmentation index accepted nonpositive multiplicity")
	}
}
