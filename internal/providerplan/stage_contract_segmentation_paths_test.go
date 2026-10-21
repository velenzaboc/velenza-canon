package providerplan

import (
	"strings"
	"testing"
)

func TestStageContractCarrierStorageAndClosureFailClosed(t *testing.T) {
	storage := &stageEvidenceCarrierStorageBudget{}
	if err := storage.retainAuxiliary(-1); err == nil {
		t.Fatal("negative auxiliary allocation was accepted")
	}
	if err := storage.retainAuxiliary(stageEvidenceMaxRetainedCarrierBytes + 1); err == nil {
		t.Fatal("oversized auxiliary allocation was accepted")
	}
	if err := storage.ensureDecodePeak(-1); err == nil {
		t.Fatal("negative decode length was accepted")
	}
	if err := storage.ensureDecodePeak(12); err != nil {
		t.Fatalf("small decode peak: %v", err)
	}
	if _, ok := stageEvidenceCarrierDecodePeakBytes(-1); ok {
		t.Fatal("negative decode peak reported valid")
	}
	storage.uniqueRepresentations = stageEvidenceMaxUniqueRepresentations
	if err := storage.retain(1); err == nil {
		t.Fatal("unique representation limit was accepted")
	}
	if _, ok := stageEvidenceAnalyzerPeakAuxiliaryBytes(-1); ok {
		t.Fatal("negative analyzer body size reported valid")
	}

	if err := validateStageBodyFreeClosure("empty", nil, nil); err != nil {
		t.Fatalf("empty closure: %v", err)
	}
	items := []stageBodyFreeItem{{label: "raw", raw: []byte("isolated value")}}
	if err := validateStageBodyFreeClosure("raw", items, nil); err != nil {
		t.Fatalf("non-reconstructing raw closure: %v", err)
	}
	structured := []candidateClosureItem{{label: "structured", raw: []byte(`{"value":"isolated value"}`)}}
	if err := validateStageStructuredBodyFreeClosure("structured", structured, nil); err != nil {
		t.Fatalf("non-reconstructing structured closure: %v", err)
	}
	for name, fixture := range map[string]struct {
		items []stageBodyFreeItem
		body  []byte
	}{
		"distinct fragments": {
			items: []stageBodyFreeItem{{label: "left", raw: []byte("abc")}, {label: "right", raw: []byte("def")}},
			body:  []byte("abcdef"),
		},
		"repeated occurrence": {
			items: []stageBodyFreeItem{{label: "first", raw: []byte("abc")}, {label: "second", raw: []byte("abc")}},
			body:  []byte("abcabc"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			digest := sha256Hex(fixture.body)
			err := validateStageBodyFreeClosure("reconstruction", fixture.items, map[string]exactEvidenceBody{digest: {Bytes: fixture.body}})
			if err == nil || !strings.Contains(err.Error(), "not body-free") {
				t.Fatalf("reconstructing closure error=%v", err)
			}
		})
	}
}

func TestStageContractUnorderedSegmentationRejectsEveryGate(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("abc")}},
		{representations: [][]byte{[]byte("def")}},
	}
	index, err := newStageEvidenceSegmentationIndexBounded(carriers, &stageEvidenceSegmentationBudget{comparisonsRemaining: 4096, scalarIndexWorkLimit: 4096, indexBytesLimit: 4096})
	if err != nil {
		t.Fatal(err)
	}
	full := func() *stageEvidenceSegmentationBudget {
		return &stageEvidenceSegmentationBudget{statesRemaining: 128, comparisonsRemaining: 4096, scalarIndexWorkLimit: 4096, indexBytesLimit: 4096}
	}
	if found, err := stageEvidenceTargetHasUnorderedSegmentationWithBudget(nil, carriers, index, full()); err != nil || found {
		t.Fatalf("empty target found=%v err=%v", found, err)
	}
	if found, err := stageEvidenceTargetHasUnorderedSegmentationWithBudget([]byte("zzz"), carriers, index, full()); err != nil || found {
		t.Fatalf("frequency-impossible target found=%v err=%v", found, err)
	}
	shortProfile := index
	shortProfile.profile.maxLengths = nil
	if found, err := stageEvidenceTargetHasUnorderedSegmentationWithBudget([]byte("abcdef"), carriers, shortProfile, full()); err != nil || !found {
		t.Fatalf("fallback feasibility segmentation found=%v err=%v", found, err)
	}
	if found, err := stageEvidenceTargetHasUnorderedSegmentationWithBudget([]byte("abcdef"), carriers, index, &stageEvidenceSegmentationBudget{statesRemaining: 128, comparisonsRemaining: 4096, scalarIndexWorkLimit: 1}); err == nil || found {
		t.Fatalf("scalar-work exhaustion found=%v err=%v", found, err)
	}
	if found, err := stageEvidenceRepresentationMatches([]byte("abc"), []byte("abd"), &stageEvidenceSegmentationBudget{comparisonsRemaining: 10}); err != nil || found {
		t.Fatalf("mismatched representation found=%v err=%v", found, err)
	}
	if _, err := stageEvidenceRepresentationMatches([]byte("abc"), []byte("abc"), &stageEvidenceSegmentationBudget{}); err == nil || !strings.Contains(err.Error(), "byte-comparison") {
		t.Fatalf("comparison exhaustion err=%v", err)
	}
}

func TestStageContractWrappedSegmentationGatesAndSearch(t *testing.T) {
	carriers := []stageEvidenceCarrierOccurrence{
		{representations: [][]byte{[]byte("abcdef")}},
		{representations: [][]byte{[]byte("defghi")}},
	}
	index, err := newStageEvidenceWrappedIndexBounded(carriers, &stageEvidenceSegmentationBudget{comparisonsRemaining: 1 << 20, scalarIndexWorkLimit: 1 << 20, indexBytesLimit: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	full := func() *stageEvidenceSegmentationBudget {
		return &stageEvidenceSegmentationBudget{statesRemaining: 256, comparisonsRemaining: 1 << 20, scalarIndexWorkLimit: 1 << 20, indexBytesLimit: 1 << 20, candidateBytesLimit: 1 << 20}
	}
	if found, err := stageEvidenceTargetHasWrappedSegmentationWithIndex([]byte("a"), &index, false, full()); err != nil || found {
		t.Fatalf("short wrapped target found=%v err=%v", found, err)
	}
	if found, err := stageEvidenceTargetHasWrappedSegmentationWithIndex([]byte("zzzzzz"), &index, false, full()); err != nil || found {
		t.Fatalf("infeasible wrapped target found=%v err=%v", found, err)
	}
	if found, err := stageEvidenceTargetHasWrappedSegmentationWithIndex([]byte("abcdefghi"), &index, false, full()); err != nil || !found {
		t.Fatalf("wrapped segmentation found=%v err=%v", found, err)
	}
	if found, err := stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex([]byte("abcdefghi"), &index, false, full()); err != nil || !found {
		t.Fatalf("cascade segmentation found=%v err=%v", found, err)
	}
	if found, err := stageEvidenceTargetHasWrappedSegmentationCascadeWithIndex([]byte("abcdefghi"), &index, false, &stageEvidenceSegmentationBudget{}); err == nil || found {
		t.Fatalf("cascade budget exhaustion found=%v err=%v", found, err)
	}
}

func TestStageContractExactMaterialAndEvidenceClaimBoundaries(t *testing.T) {
	valid := StageMaterial{Role: "profile", ID: "profile.example", Version: "v1", Raw: []byte(`{"kind":"fixture"}`)}
	if indexed, err := indexExactStageMaterials([]StageMaterial{valid}); err != nil || len(indexed) != 1 {
		t.Fatalf("valid exact material indexed=%v err=%v", indexed, err)
	}
	if _, err := indexExactStageMaterials(nil); err == nil {
		t.Fatal("empty exact material roster was accepted")
	}
	for name, materials := range map[string][]StageMaterial{
		"invalid role":         {{Role: "Organization_ID", ID: valid.ID, Version: valid.Version, Raw: valid.Raw}},
		"empty raw":            {{Role: valid.Role, ID: valid.ID, Version: valid.Version}},
		"duplicate coordinate": {valid, valid},
		"digest alias": {
			valid,
			{Role: "schema", ID: "schema.example", Version: "v1", Raw: valid.Raw},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := indexExactStageMaterials(materials); err == nil {
				t.Fatal("invalid exact-material roster was accepted")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte("1.5"), []byte("999999999999999999999999999999")} {
		if _, err := exactStageUint(raw); err == nil {
			t.Fatalf("unsafe exact count %q was accepted", raw)
		}
	}
	if value, err := exactStageUint([]byte("2")); err != nil || value != 2 {
		t.Fatalf("exact count value=%d err=%v", value, err)
	}
	if value, err := exactStageUint([]byte(`"2"`)); err != nil || value != 2 {
		t.Fatalf("JSON string count value=%d err=%v", value, err)
	}
	digestA, digestB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	validRows := []byte(`{"row_kind":"note"}` + "\n" + `{"row_kind":"external_evidence_body","component_ordinal":0,"content_bytes":3,"content_sha256":"` + digestA + `"}` + "\n" + `{"row_kind":"external_evidence_body","component_ordinal":1,"content_bytes":4,"content_sha256":"` + digestB + `"}`)
	claims, err := parseStageEvidenceComponentClaims(validRows)
	if err != nil || len(claims) != 2 || claims[1].bytes != 4 {
		t.Fatalf("valid evidence claims=%#v err=%v", claims, err)
	}
	for name, raw := range map[string][]byte{
		"no rows":       []byte(`{"row_kind":"note"}`),
		"malformed":     []byte(`{`),
		"missing count": []byte(`{"row_kind":"external_evidence_body","component_ordinal":0,"content_sha256":"` + digestA + `"}`),
		"ordinal gap":   []byte(`{"row_kind":"external_evidence_body","component_ordinal":1,"content_bytes":1,"content_sha256":"` + digestA + `"}`),
		"bad digest":    []byte(`{"row_kind":"external_evidence_body","component_ordinal":0,"content_bytes":1,"content_sha256":"upper"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseStageEvidenceComponentClaims(raw); err == nil {
				t.Fatal("invalid evidence claims were accepted")
			}
		})
	}
}

func TestStageContractClosedJSONHeadersAndReferencesFailClosed(t *testing.T) {
	request := []byte(`{"request_kind":"` + stageRequestKind + `","request_version":"` + stageContractVersion + `","stage_kind":"` + stageFullFactory + `"}`)
	header, err := decodeStageRequestHeader(request)
	if err != nil || header.StageKind != stageFullFactory {
		t.Fatalf("valid request header=%+v err=%v", header, err)
	}
	for name, raw := range map[string][]byte{
		"not object":     []byte(`[]`),
		"missing field":  []byte(`{"request_kind":"stage_compile","request_version":"v1"}`),
		"wrong kind":     []byte(`{"request_kind":"wrong","request_version":"` + stageContractVersion + `","stage_kind":"` + stageFullFactory + `"}`),
		"wrong version":  []byte(`{"request_kind":"` + stageRequestKind + `","request_version":"v0","stage_kind":"` + stageFullFactory + `"}`),
		"unknown stage":  []byte(`{"request_kind":"` + stageRequestKind + `","request_version":"` + stageContractVersion + `","stage_kind":"unknown"}`),
		"duplicate key":  []byte(`{"request_kind":"` + stageRequestKind + `","request_kind":"` + stageRequestKind + `","request_version":"` + stageContractVersion + `","stage_kind":"` + stageFullFactory + `"}`),
		"malformed json": []byte(`{`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStageRequestHeader(raw); err == nil {
				t.Fatal("invalid stage request header was accepted")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"valid":   []byte(`{"one":1,"two":2}`),
		"extra":   []byte(`{"one":1,"two":2,"three":3}`),
		"missing": []byte(`{"one":1}`),
		"array":   []byte(`[]`),
	} {
		t.Run(name, func(t *testing.T) {
			err := requireExactStageKeys(raw, "one", "two")
			if name == "valid" && err != nil {
				t.Fatalf("valid closed object: %v", err)
			}
			if name != "valid" && err == nil {
				t.Fatal("invalid closed object was accepted")
			}
		})
	}
	digestA, digestB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	validRef := StageReceiptReference{StageKind: stageEvidenceIntake, ReceiptSHA256: digestA, OutputRootSHA256: digestB}
	if err := validateStageReference(validRef); err != nil {
		t.Fatalf("valid stage reference: %v", err)
	}
	for name, ref := range map[string]StageReceiptReference{
		"unknown stage": {StageKind: "unknown", ReceiptSHA256: digestA, OutputRootSHA256: digestB},
		"bad receipt":   {StageKind: stageEvidenceIntake, ReceiptSHA256: "bad", OutputRootSHA256: digestB},
		"bad output":    {StageKind: stageEvidenceIntake, ReceiptSHA256: digestA, OutputRootSHA256: "bad"},
		"alias":         {StageKind: stageEvidenceIntake, ReceiptSHA256: digestA, OutputRootSHA256: digestA},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateStageReference(ref); err == nil {
				t.Fatal("invalid stage reference was accepted")
			}
		})
	}
}

func TestStageContractLineageValidatorsRejectBrokenTopology(t *testing.T) {
	digestA, digestB, digestC, digestD, digestE, digestF := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64), strings.Repeat("e", 64), strings.Repeat("f", 64)
	evidence := StageReceiptReference{StageKind: stageEvidenceIntake, ReceiptSHA256: digestA, OutputRootSHA256: digestB}
	semantic := StageReceiptReference{StageKind: stageSemanticExtraction, ReceiptSHA256: digestC, OutputRootSHA256: digestD}
	graph := StageReceiptReference{StageKind: stageGraphCompile, ReceiptSHA256: digestE, OutputRootSHA256: digestF}
	semanticParsed := parsedStageReceipt{Summary: StageReceiptSummary{StageKind: stageSemanticExtraction, Predecessors: []StageReceiptReference{evidence}}}
	if err := validateGraphExtractionLineage([]StageReceiptReference{semantic}, []parsedStageReceipt{semanticParsed}); err != nil {
		t.Fatalf("valid graph extraction lineage: %v", err)
	}
	if err := validateGraphExtractionLineage(nil, nil); err == nil {
		t.Fatal("empty graph extraction lineage was accepted")
	}
	wrongSemantic := semanticParsed
	wrongSemantic.Summary.StageKind = stageGraphCompile
	if err := validateGraphExtractionLineage([]StageReceiptReference{semantic}, []parsedStageReceipt{wrongSemantic}); err == nil {
		t.Fatal("wrong graph extraction stage was accepted")
	}
	missingIntake := semanticParsed
	missingIntake.Summary.Predecessors = nil
	if err := validateGraphExtractionLineage([]StageReceiptReference{semantic}, []parsedStageReceipt{missingIntake}); err == nil {
		t.Fatal("semantic extraction without intake was accepted")
	}

	fullRefs := []StageReceiptReference{evidence, semantic, graph}
	fullResolved := []parsedStageReceipt{
		{Summary: StageReceiptSummary{StageKind: stageEvidenceIntake}},
		semanticParsed,
		{Summary: StageReceiptSummary{StageKind: stageGraphCompile, Predecessors: []StageReceiptReference{semantic}}},
	}
	if err := validateFullFactoryLineage(fullRefs, fullResolved); err != nil {
		t.Fatalf("valid full-factory lineage: %v", err)
	}
	if err := validateFullFactoryLineage(fullRefs[:2], fullResolved[:2]); err == nil {
		t.Fatal("short full-factory lineage was accepted")
	}
	wrongOrder := append([]StageReceiptReference(nil), fullRefs...)
	wrongOrder[0] = semantic
	if err := validateFullFactoryLineage(wrongOrder, fullResolved); err == nil {
		t.Fatal("wrong full-factory endpoint order was accepted")
	}
	wrongGraph := append([]parsedStageReceipt(nil), fullResolved...)
	wrongGraph[2].Summary.Predecessors = nil
	if err := validateFullFactoryLineage(fullRefs, wrongGraph); err == nil {
		t.Fatal("graph without semantic predecessors was accepted")
	}

	commitment := StageEvidenceCommitment{ManifestRole: "evidence_manifest", ManifestID: "manifest.example", ManifestVersion: "v1", ComponentOrdinal: 0, BodySHA256: digestA, ByteCount: 1}
	if lineage, err := resolveStageEvidenceLineage(stageEvidenceIntake, nil); err != nil || lineage != nil {
		t.Fatalf("intake lineage=%#v err=%v", lineage, err)
	}
	if _, err := resolveStageEvidenceLineage(stageEvidenceIntake, []parsedStageReceipt{{}}); err == nil {
		t.Fatal("intake predecessor was accepted")
	}
	if _, err := resolveStageEvidenceLineage(stageSemanticExtraction, nil); err == nil {
		t.Fatal("missing inherited lineage was accepted")
	}
	resolved := []parsedStageReceipt{{Receipt: stageReceipt{EvidenceCommitments: []StageEvidenceCommitment{commitment}}}}
	if lineage, err := resolveStageEvidenceLineage(stageSemanticExtraction, resolved); err != nil || len(lineage) != 1 {
		t.Fatalf("semantic lineage=%#v err=%v", lineage, err)
	}
	mismatch := append([]parsedStageReceipt(nil), resolved...)
	mismatch = append(mismatch, parsedStageReceipt{Receipt: stageReceipt{EvidenceCommitments: nil}})
	if _, err := resolveStageEvidenceLineage(stageGraphCompile, mismatch); err == nil {
		t.Fatal("mismatched inherited lineages were accepted")
	}
}

func TestStageContractReceiptAndNestedShapeGuardsFailClosed(t *testing.T) {
	digestA, digestB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	evidence := StageReceiptReference{StageKind: stageEvidenceIntake, ReceiptSHA256: digestA, OutputRootSHA256: digestB}
	semantic := StageReceiptReference{StageKind: stageSemanticExtraction, ReceiptSHA256: digestB, OutputRootSHA256: digestA}
	for name, receipt := range map[string]stageReceipt{
		"intake predecessor": {StageKind: stageEvidenceIntake, Predecessors: []StageReceiptReference{evidence}},
		"semantic no intake": {StageKind: stageSemanticExtraction},
		"graph no semantic":  {StageKind: stageGraphCompile},
		"factory order":      {StageKind: stageFullFactory, Predecessors: []StageReceiptReference{evidence, semantic, semantic}},
		"unknown":            {StageKind: "unknown"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateReceiptStageShape(receipt); err == nil {
				t.Fatal("invalid receipt shape was accepted")
			}
		})
	}
	if _, err := ValidateStageReceipt([]byte{0xff}); err == nil {
		t.Fatal("invalid UTF-8 receipt was accepted")
	}
	if _, err := ValidateStageReceipt([]byte(`{"receipt_kind":"x","receipt_kind":"x"}`)); err == nil {
		t.Fatal("duplicate-key receipt was accepted")
	}
	if _, err := ValidateStageReceipt([]byte(`[]`)); err == nil {
		t.Fatal("array receipt was accepted")
	}
	if _, _, err := stageNestedValues([]byte(`{"object":{},"rows":[]}`), "object", "rows"); err != nil {
		t.Fatalf("valid nested values: %v", err)
	}
	if _, _, err := stageNestedValues([]byte(`{"object":{},"rows":{}}`), "object", "rows"); err == nil {
		t.Fatal("non-array nested rows were accepted")
	}
	if err := requireGraphCompileDependencyArtifactKeys([]byte(`{"dependency_artifacts":[{"role":"r"}]}`)); err == nil {
		t.Fatal("incomplete graph dependency was accepted")
	}
	if err := requireStageValidationKeys([]byte(`{"schema":{},"profile":{}}`)); err == nil {
		t.Fatal("incomplete stage validation pins were accepted")
	}
}

func TestStageContractBindingAndIdentityLedgerBoundaries(t *testing.T) {
	digestA, digestB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	schema := immutableStageArtifactPin{Role: "schema", ID: "schema.example", Version: "v1", RawSHA256: digestA, AuthorityClass: "canonical"}
	profile := immutableStageArtifactPin{Role: "profile", ID: "profile.example", Version: "v1", RawSHA256: digestB, AuthorityClass: "admitted"}
	if err := validateStageValidationBinding("fixture", stageValidationBinding{Schema: schema, Profile: profile}, newStageDigestLedger()); err != nil {
		t.Fatalf("valid stage validation binding: %v", err)
	}
	badSchema := schema
	badSchema.AuthorityClass = "untrusted"
	if err := validateStageValidationBinding("fixture", stageValidationBinding{Schema: badSchema, Profile: profile}, newStageDigestLedger()); err == nil {
		t.Fatal("invalid schema pin was accepted")
	}
	aliasProfile := profile
	aliasProfile.RawSHA256 = digestA
	if err := validateStageValidationBinding("fixture", stageValidationBinding{Schema: schema, Profile: aliasProfile}, newStageDigestLedger()); err == nil {
		t.Fatal("aliased stage validation pins were accepted")
	}
	ledger := newStageDigestLedger()
	identity := stageArtifactIdentity{Role: "artifact", ID: "artifact.example", Version: "v1", RawSHA256: digestA}
	if err := validateStageArtifactIdentity("artifact", identity, ledger); err != nil {
		t.Fatalf("valid stage artifact identity: %v", err)
	}
	if err := validateStageArtifactIdentity("duplicate", identity, ledger); err == nil {
		t.Fatal("aliased artifact identity was accepted")
	}
	invalidIdentity := identity
	invalidIdentity.Version = "V1"
	if err := validateStageArtifactIdentity("invalid", invalidIdentity, newStageDigestLedger()); err == nil {
		t.Fatal("invalid artifact identity was accepted")
	}
	if err := requireSafeStageCount("zero", 0); err != nil {
		t.Fatalf("zero safe count: %v", err)
	}
	if err := requireSafeStageCount("unsafe", maxExactStageCount+1); err == nil {
		t.Fatal("unsafe count was accepted")
	}
}

func TestStageContractSearchIndexesRejectMalformedOccurrences(t *testing.T) {
	badMultiplicity := []stageEvidenceCarrierOccurrence{{representations: [][]byte{[]byte("abc")}, multiplicity: -1}}
	budget := &stageEvidenceSegmentationBudget{comparisonsRemaining: 4096, scalarIndexWorkLimit: 4096, indexBytesLimit: 4096}
	if _, err := newStageEvidenceSegmentationIndexBounded(badMultiplicity, budget); err == nil {
		t.Fatal("segmentation index accepted nonpositive multiplicity")
	}
	if _, err := newStageEvidenceWrappedIndexBounded(badMultiplicity, &stageEvidenceSegmentationBudget{comparisonsRemaining: 4096, scalarIndexWorkLimit: 1 << 20, indexBytesLimit: 1 << 20}); err == nil {
		t.Fatal("wrapped index accepted nonpositive multiplicity")
	}
	representations := make([][]byte, stageEvidenceMaxRepresentationsPerOccurrence+1)
	for index := range representations {
		representations[index] = []byte("abc")
	}
	if _, err := newStageEvidenceSegmentationIndexBounded([]stageEvidenceCarrierOccurrence{{representations: representations}}, &stageEvidenceSegmentationBudget{comparisonsRemaining: 4096, scalarIndexWorkLimit: 4096, indexBytesLimit: 4096}); err == nil {
		t.Fatal("segmentation index accepted too many representations")
	}

	malformedIndex := stageEvidenceSegmentationIndex{byPrefix: map[string][]stageEvidenceCarrierRepresentation{
		stageEvidenceSegmentationPrefix([]byte("abc")): {{occurrence: 0, raw: []byte("abc")}},
	}}
	if _, err := stageEvidenceUnorderedSegmentationSearch([]byte("abcd"), 4, []int{3}, make([]int, 1), badMultiplicity, malformedIndex, &stageEvidenceSegmentationBudget{statesRemaining: 8, comparisonsRemaining: 32}); err == nil {
		t.Fatal("unordered search accepted nonpositive multiplicity")
	}
	wrapped := &stageEvidenceWrappedIndex{multiplicities: []int{-1}}
	finish := make([]bool, 7)
	for index := range finish {
		finish[index] = true
	}
	if _, err := stageEvidenceWrappedSegmentationSearch([]byte("abcdef"), make([]int, 1), map[int][]stageEvidenceWrappedCandidate{0: {{occurrence: 0, length: 3}}}, finish, 4, wrapped, false, &stageEvidenceSegmentationBudget{statesRemaining: 8, scalarIndexWorkLimit: 32}); err == nil {
		t.Fatal("wrapped search accepted nonpositive multiplicity")
	}
}

func TestStageContractSmallDeterministicGuardBranches(t *testing.T) {
	if err := scanStageStructuredMetadata("invalid", []byte{0xff}); err == nil {
		t.Fatal("invalid UTF-8 structured metadata was accepted")
	}
	if err := scanStageStructuredMetadata("valid", []byte(`{"kind":"fixture"}`)); err != nil {
		t.Fatalf("valid structured metadata: %v", err)
	}
	if stageEvidenceMultiplicitiesAtLeast([]int{-1, 0}, 1) || !stageEvidenceMultiplicitiesAtLeast(nil, 0) {
		t.Fatal("multiplicity threshold guards changed")
	}
	base := stageEvidenceCarrierOccurrence{representations: [][]byte{[]byte("abc")}}
	if stageEvidenceCarrierOccurrencesEquivalent(base, stageEvidenceCarrierOccurrence{provenDigestIdentity: true, representations: base.representations}) {
		t.Fatal("different provenance was treated as equivalent")
	}
	if stageEvidenceCarrierOccurrencesEquivalent(base, stageEvidenceCarrierOccurrence{representations: nil}) {
		t.Fatal("different representation counts were treated as equivalent")
	}
	if stageEvidenceCarrierOccurrencesEquivalent(base, stageEvidenceCarrierOccurrence{representations: [][]byte{[]byte("abd")}}) {
		t.Fatal("different representation bytes were treated as equivalent")
	}
	if _, ok := stageEvidenceAnalyzerPeakAuxiliaryBytes(1 << 62); ok {
		t.Fatal("overflowing analyzer body size reported valid")
	}
	if peak, ok := stageEvidenceAnalyzerPeakAuxiliaryBytes(1); !ok || peak <= stageEvidenceMaxRetainedCarrierBytes {
		t.Fatalf("valid analyzer peak=%d ok=%v", peak, ok)
	}
	for name, coordinate := range map[string]stageMaterialCoordinate{
		"bad id":      {Role: "profile", ID: "org_id", Version: "v1"},
		"bad version": {Role: "profile", ID: "profile.example", Version: "V1"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateStageMaterialCoordinate(coordinate); err == nil {
				t.Fatal("invalid material coordinate was accepted")
			}
		})
	}
	index := stageEvidenceSegmentationIndex{byPrefix: map[string][]stageEvidenceCarrierRepresentation{}, profile: stageEvidenceSegmentationProfile{maxLengths: []int{3}, totalCapacity: 3}}
	if reachable, err := stageEvidenceTargetReachableWithoutOccurrenceReuse([]byte("abc"), index, &stageEvidenceSegmentationBudget{scalarIndexWorkLimit: 4096, comparisonsRemaining: 4096}); err != nil || reachable {
		t.Fatalf("unreachable target reachable=%v err=%v", reachable, err)
	}
}
