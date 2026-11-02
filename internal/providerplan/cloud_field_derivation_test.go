package providerplan

import (
	"bytes"
	"testing"
)

func TestCloudFieldDerivationExecutesActualS3BucketNameBytes(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	var target CloudSourceObjectTarget
	for _, candidate := range request.Targets {
		if candidate.OperationID == "com.amazonaws.s3#ListBuckets" {
			target = candidate
			break
		}
	}
	if target.MappingContract == nil {
		t.Fatal("S3 ListBuckets target missing")
	}
	catalog, ok := findCloudCandidateCatalog(request.Catalogs, target)
	if !ok {
		t.Fatal("S3 catalog missing")
	}
	models := loadPinnedCloudModelsForCompilerProof(t)
	var model PinnedCloudModel
	for _, candidate := range models {
		if candidate.Source.ID == catalog.Source.ID {
			model = candidate
			break
		}
	}
	candidate, err := BuildCloudFieldDerivationCandidate(catalog, target, model, "/Name", "aws_s3_bucket")
	if err != nil {
		t.Fatal(err)
	}
	locator := evidenceLocator{RowKind: "evidence_locator", EvidenceManifestSHA256: sha256Hex([]byte("test manifest")), SourceContentSHA256: sha256Hex(model.Raw), ByteStartOffset: int64(candidate.FieldLocator.StartByte), ByteEndOffsetExclusive: int64(candidate.FieldLocator.EndByte), SelectedRangeByteCount: int64(candidate.FieldLocator.EndByte - candidate.FieldLocator.StartByte), SelectedRangeSHA256: sha256Hex(model.Raw[candidate.FieldLocator.StartByte:candidate.FieldLocator.EndByte]), SourceRefs: []string{model.Source.StableCoordinate}, SourceURLs: []string{model.Source.URI}, LocatorSemantics: exactLocatorSemantics, SourceBytesPresent: false}
	locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
	proof := newSourceClassificationSelectionProof("aws", sha256Hex([]byte("test selection roster")), map[string][]sourceClassificationOccurrence{candidate.SourceSymbol: {{Binding: classificationArtifactBinding{ArtifactID: "test_classification", ArtifactVersion: "1", ArtifactSHA256: sha256Hex([]byte("test classification"))}, SourceSymbol: candidate.SourceSymbol, SurfaceKind: "resource", Locator: locator}}})
	bodies := map[string]exactEvidenceBody{sha256Hex(model.Raw): {Bytes: model.Raw, Coordinates: map[evidenceSourceCoordinate]string{{Ref: model.Source.StableCoordinate, URL: model.Source.URI}: locator.EvidenceManifestSHA256}}}
	facts, err := executeExactDocumentationDerivationProgram(candidate.Reference, candidate.Program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[0].FactID == "" || facts[0].EvidenceLocatorID != locator.ID {
		t.Fatalf("facts = %+v", facts)
	}
	if facts[0].ByteStartOffset != locator.ByteStartOffset || facts[0].ByteEndOffsetExclusive != locator.ByteEndOffsetExclusive || facts[0].SelectedMatchSHA256 != locator.SelectedRangeSHA256 {
		t.Fatalf("fact does not bind selected model bytes: %+v", facts[0])
	}
	output, err := decodeExactDocumentationFactOutputFields(facts[0])
	if err != nil {
		t.Fatal(err)
	}
	if output["field_name"] != "Name" || output["provider_type"] == "" || output["official_json_pointer"] != candidate.FieldLocator.JSONPointer {
		t.Fatalf("actual parsed field output = %#v", output)
	}
	selected := model.Raw[candidate.FieldLocator.StartByte:candidate.FieldLocator.EndByte]
	if !bytes.Contains(selected, []byte(`"target"`)) {
		t.Fatalf("selected S3 Name member is not exact model bytes: %q", selected)
	}
}

func TestCloudFieldDerivationRefusesMismatchedModelBytes(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	target := request.Targets[0]
	catalog, _ := findCloudCandidateCatalog(request.Catalogs, target)
	model := loadPinnedCloudModelsForCompilerProof(t)[0]
	model.Raw = append([]byte(nil), model.Raw...)
	model.Raw[0] ^= 1
	if _, err := BuildCloudFieldDerivationCandidate(catalog, target, model, target.MappingContract.Fields[0].SourcePointer, "x"); err == nil {
		t.Fatal("changed model bytes accepted")
	}
}

func TestCloudFieldDerivationRefusesMutatedParsedCatalog(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	target := request.Targets[0]
	catalog, _ := findCloudCandidateCatalog(request.Catalogs, target)
	catalog.APIVersion = "invented"
	model := loadPinnedCloudModelsForCompilerProof(t)[0]
	if _, err := BuildCloudFieldDerivationCandidate(catalog, target, model, target.MappingContract.Fields[0].SourcePointer, "x"); err == nil {
		t.Fatal("mutated parsed catalog accepted")
	}
}

func TestCloudFieldDerivationRosterAccountsForEverySelectedField(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	models := loadPinnedCloudModelsForCompilerProof(t)
	total, candidates, unresolved := 0, 0, 0
	executedPrograms := 0
	for _, target := range request.Targets {
		catalog, ok := findCloudCandidateCatalog(request.Catalogs, target)
		if !ok {
			t.Fatal("catalog missing")
		}
		var model PinnedCloudModel
		for _, value := range models {
			if value.Source.ID == catalog.Source.ID {
				model = value
				break
			}
		}
		// The retained snapshot source is the canonical test-only evidence
		// coordinate. Candidate programs still consume the exact model bytes.
		model.Source = cloudNativeSnapshotSource(t, model.Source.ID)
		catalog, err = ParsePinnedCloudModel(model)
		if err != nil {
			t.Fatal(err)
		}
		roster, err := BuildCloudTargetFieldDerivationRoster(catalog, target, model, "cloud_target")
		if err != nil {
			t.Fatalf("%s: %v", target.OperationID, err)
		}
		fieldCount := len(target.MappingContract.Fields)
		for _, nested := range target.MappingContract.Nested {
			fieldCount += len(nested.Fields)
		}
		if len(roster.Candidates)+len(roster.Unresolved) != fieldCount {
			t.Fatalf("%s field accounting %d+%d, want %d", target.OperationID, len(roster.Candidates), len(roster.Unresolved), fieldCount)
		}
		for _, candidate := range roster.Candidates {
			rawProgram, err := canonicalFactoryJSON(candidate.Program)
			if err != nil || !bytes.Contains(rawProgram, []byte(`"target_row_selector":[]`)) || !bytes.Contains(rawProgram, []byte(`"target_member_identity_json_pointers":[]`)) {
				t.Fatal("whole-row candidate must preserve empty selector arrays for native schema composition")
			}
			if candidate.ProviderType != "boolean" && candidate.NumericDisposition["numeric_semantics"] != "unclassified_fail_closed" {
				t.Fatalf("%s %s assigned numeric semantics from model type %q", target.OperationID, candidate.FieldPointer, candidate.ProviderType)
			}
			locator := cloudFieldDerivationTestLocator(candidate, model)
			proof := newSourceClassificationSelectionProof(catalog.ProviderID, sha256Hex([]byte("test selection roster "+candidate.FieldPointer)), map[string][]sourceClassificationOccurrence{candidate.SourceSymbol: {{Binding: classificationArtifactBinding{ArtifactID: "test_classification", ArtifactVersion: "1", ArtifactSHA256: sha256Hex([]byte("test classification"))}, SourceSymbol: candidate.SourceSymbol, SurfaceKind: "resource", Locator: locator}}})
			bodies := map[string]exactEvidenceBody{sha256Hex(model.Raw): {Bytes: model.Raw, Coordinates: map[evidenceSourceCoordinate]string{{Ref: model.Source.StableCoordinate, URL: model.Source.URI}: locator.EvidenceManifestSHA256}}}
			facts, execErr := executeExactDocumentationDerivationProgram(candidate.Reference, candidate.Program, proof, bodies)
			if execErr != nil || len(facts) != 1 || facts[0].SelectedMatchSHA256 != locator.SelectedRangeSHA256 {
				t.Fatalf("%s %s executor result=%d err=%v", target.OperationID, candidate.FieldPointer, len(facts), execErr)
			}
			executedPrograms++
		}
		total += fieldCount
		candidates += len(roster.Candidates)
		unresolved += len(roster.Unresolved)
	}
	if total != 255 || candidates == 0 || candidates+unresolved != 255 || executedPrograms != 255 {
		t.Fatalf("candidate accounting = total:%d candidates:%d unresolved:%d", total, candidates, unresolved)
	}
	t.Logf("candidate program coverage: %d/%d; explicit unresolved exact-member spans: %d", candidates, total, unresolved)
}

func cloudFieldDerivationTestLocator(candidate CloudFieldDerivationCandidate, model PinnedCloudModel) evidenceLocator {
	locator := evidenceLocator{RowKind: "evidence_locator", EvidenceManifestSHA256: sha256Hex([]byte("test manifest " + candidate.FieldPointer)), SourceContentSHA256: sha256Hex(model.Raw), ByteStartOffset: int64(candidate.FieldLocator.StartByte), ByteEndOffsetExclusive: int64(candidate.FieldLocator.EndByte), SelectedRangeByteCount: int64(candidate.FieldLocator.EndByte - candidate.FieldLocator.StartByte), SelectedRangeSHA256: sha256Hex(model.Raw[candidate.FieldLocator.StartByte:candidate.FieldLocator.EndByte]), SourceRefs: []string{model.Source.StableCoordinate}, SourceURLs: []string{model.Source.URI}, LocatorSemantics: exactLocatorSemantics}
	locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
	return locator
}
