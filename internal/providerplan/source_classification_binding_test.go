package providerplan

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEvidenceSelectionRosterBindsManyToManySemanticOccurrencesWithinOneExactDocumentBody(t *testing.T) {
	dir := t.TempDir()
	body := []byte("alpha and beta")
	manifestPath := writeClassificationEvidenceManifest(t, dir, "fixture_reference_evidence", "fixture.reference", "https://example.com/reference", body, nil)
	evidenceBytesBeforeSelection, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read evidence manifest before selection: %v", err)
	}
	loaded := loadClassificationEvidence(t, []string{manifestPath})
	metadata := soleClassificationMetadata(t, loaded)

	roster, dependencies, binding := sourceClassificationFixtureAt(t, dir,
		sourceClassificationRow("alpha", "data_entity"),
		sourceClassificationRow("beta", "data_entity"),
	)
	sharedLocator := sourceClassificationLocator(metadata, body, 0, int64(len(body)))
	betaSpecificLocator := sourceClassificationLocator(metadata, body, 10, 14)
	manifestArtifact, _ := manifestString(loaded.Artifacts[metadata.ManifestSHA256].Manifest, "artifact")
	manifestVersion, _ := manifestString(loaded.Artifacts[metadata.ManifestSHA256].Manifest, "artifact_version")
	roster.RowsByKind = map[string][]map[string]interface{}{
		"selected_source_document": {{
			"row_kind":                           "selected_source_document",
			"evidence_manifest_artifact":         manifestArtifact,
			"evidence_manifest_artifact_version": manifestVersion,
			"source_ref":                         metadata.SourceRef,
			"current_reference_url":              metadata.SourceURL,
			"representation":                     metadata.Representation,
			"representation_coordinate":          metadata.RepresentationCoordinate,
			"source_representation_kind":         metadata.SourceRepresentationKind,
			"consumer_roles":                     []interface{}{"api_graph_projection"},
			"classification_occurrences": []interface{}{
				sourceClassificationOccurrenceObject(binding, "alpha", "data_entity", sharedLocator),
				sourceClassificationOccurrenceObject(binding, "beta", "data_entity", sharedLocator),
				sourceClassificationOccurrenceObject(binding, "beta", "data_entity", betaSpecificLocator),
			},
		}},
	}
	roster.RowKindCounts = map[string]int{"artifact_manifest": 1, "selected_source_document": 1, "validation_summary": 1}
	roster.ValidationSummary = sourceClassificationSelectionSummary(1, 1, 3)
	roster.Manifest["selected_source_count"] = json.Number("1")
	roster.Manifest["provider"] = "fixture_provider"
	roster.Manifest["row_kind"] = "artifact_manifest"
	roster.Manifest["artifact"] = "fixture_documentation_evidence_selection_roster"
	roster.Manifest["artifact_version"] = "4"
	roster.Manifest["status"] = "candidate_source_selection_input"
	selectionPath := filepath.Join(dir, "fixture-selection-roster.jsonl")
	writeClassificationJSONL(t, selectionPath, []map[string]interface{}{roster.Manifest, roster.RowsByKind["selected_source_document"][0], roster.ValidationSummary})
	roster, err = readArtifactInput(selectionPath)
	if err != nil {
		t.Fatalf("read exact selection roster: %v", err)
	}
	evidenceBytesAfterSelection, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read evidence manifest after selection: %v", err)
	}
	if sha256Hex(evidenceBytesBeforeSelection) != sha256Hex(evidenceBytesAfterSelection) || strings.Contains(string(evidenceBytesAfterSelection), "evidence_selection_roster_sha256") || strings.Contains(string(evidenceBytesAfterSelection), roster.SHA256) {
		t.Fatal("immutable evidence leaf back-binds or changed after the higher selection roster was hashed")
	}

	plan := &parsedPlan{
		Manifest: &artifactManifest{
			Provider:                      "fixture_provider",
			EvidenceSelectionRosterSHA256: roster.SHA256,
			EvidenceManifestBindings: []evidenceManifestBinding{{
				EvidenceManifestSHA256: metadata.ManifestSHA256,
				EvidenceBodyKind:       evidenceBodyKindSourceDocument,
				ConsumerRoles:          []string{"api_graph_projection"},
			}},
		},
		Locators: map[string]evidenceLocator{sharedLocator.ID: sharedLocator, betaSpecificLocator.ID: betaSpecificLocator},
	}
	if err := validateEvidenceSelectionRoster(roster, "fixture_provider", loaded, dependencies, map[string]struct{}{}, plan); err != nil {
		t.Fatalf("validateEvidenceSelectionRoster: %v", err)
	}
	if loaded.BodyCoordinateRows != 1 || len(loaded.MetadataByIdentity) != 1 {
		t.Fatalf("selected documents=%d identities=%d, want one document body", loaded.BodyCoordinateRows, len(loaded.MetadataByIdentity))
	}
	if !isLowerSHA256(roster.SHA256) || plan.Manifest.EvidenceSelectionRosterSHA256 != roster.SHA256 || metadata.ManifestSHA256 != sha256Hex(evidenceBytesBeforeSelection) {
		t.Fatal("real on-disk plan -> selection roster -> immutable evidence digest chain is not exact")
	}
	if len(loaded.ClassificationsBySourceSymbol["alpha"]) != 1 || len(loaded.ClassificationsBySourceSymbol["beta"]) != 2 {
		t.Fatalf("classification occurrence index = %#v, want alpha=1 and beta=2", loaded.ClassificationsBySourceSymbol)
	}
	alphaOccurrence := loaded.ClassificationsBySourceSymbol["alpha"][0]
	betaOccurrence := loaded.ClassificationsBySourceSymbol["beta"][0]
	if alphaOccurrence.Locator.SourceContentSHA256 != betaOccurrence.Locator.SourceContentSHA256 || alphaOccurrence.Locator.SourceRefs[0] != betaOccurrence.Locator.SourceRefs[0] || alphaOccurrence.Locator.SourceURLs[0] != betaOccurrence.Locator.SourceURLs[0] {
		t.Fatal("two semantic occurrences do not share the one exact selected document identity")
	}
	if alphaOccurrence.Locator.ID != betaOccurrence.Locator.ID {
		t.Fatal("one exact byte-range locator did not bind both semantic targets")
	}
	if loaded.ClassificationsBySourceSymbol["beta"][1].Locator.ID == betaOccurrence.Locator.ID {
		t.Fatal("one semantic target did not retain its second distinct exact locator")
	}
}

func TestSourceClassificationBindingAllowsOneSymbolAcrossDistinctDocuments(t *testing.T) {
	dir := t.TempDir()
	firstBody := []byte("alpha in first document")
	secondBody := []byte("second document says alpha")
	firstPath := writeClassificationEvidenceManifest(t, dir, "fixture_first_evidence", "alpha.first", "https://example.com/first", firstBody, nil)
	secondPath := writeClassificationEvidenceManifest(t, dir, "fixture_second_evidence", "alpha.second", "https://example.com/second", secondBody, nil)
	loaded := loadClassificationEvidence(t, []string{firstPath, secondPath})
	roster, dependencies, binding := sourceClassificationFixture(t, sourceClassificationRow("alpha", "data_entity"))
	bindings, err := validateClassificationArtifactBindings(roster, "fixture_provider", dependencies, map[string]struct{}{})
	if err != nil {
		t.Fatalf("validateClassificationArtifactBindings: %v", err)
	}
	usedBindings := map[classificationArtifactBinding]struct{}{}
	usedRows := map[string]struct{}{}
	usedOccurrences := map[string]string{}
	for index, metadata := range sortedClassificationMetadata(loaded) {
		body := loaded.Bodies[metadata.ContentSHA256].Bytes
		locator := sourceClassificationLocator(metadata, body, 0, int64(len(body)))
		raw := sourceClassificationOccurrenceObject(binding, "alpha", "data_entity", locator)
		occurrence, err := bindSelectedSourceClassification(roster, index, 0, raw, metadata, bindings, loaded.Bodies, usedBindings, usedRows, usedOccurrences)
		if err != nil {
			t.Fatalf("bind document %d: %v", index, err)
		}
		loaded.ClassificationsBySourceSymbol[occurrence.SourceSymbol] = append(loaded.ClassificationsBySourceSymbol[occurrence.SourceSymbol], occurrence)
	}
	if len(usedRows) != 1 || len(usedOccurrences) != 2 || len(loaded.ClassificationsBySourceSymbol["alpha"]) != 2 {
		t.Fatalf("semantic rows=%d occurrences=%d symbol occurrences=%d, want 1/2/2", len(usedRows), len(usedOccurrences), len(loaded.ClassificationsBySourceSymbol["alpha"]))
	}
}

func TestSourceClassificationBindingAllowsOneLocatorForManyTargetsAndRejectsDuplicatePairs(t *testing.T) {
	body := []byte("alpha beta")
	manifestPath := writeClassificationEvidenceManifest(t, t.TempDir(), "fixture_reference_evidence", "fixture.reference", "https://example.com/reference", body, nil)
	loaded := loadClassificationEvidence(t, []string{manifestPath})
	metadata := soleClassificationMetadata(t, loaded)
	roster, dependencies, binding := sourceClassificationFixture(t,
		sourceClassificationRow("alpha", "data_entity"),
		sourceClassificationRow("beta", "data_entity"),
	)
	bindings, err := validateClassificationArtifactBindings(roster, "fixture_provider", dependencies, map[string]struct{}{})
	if err != nil {
		t.Fatalf("validateClassificationArtifactBindings: %v", err)
	}
	locator := sourceClassificationLocator(metadata, body, 0, 5)
	usedBindings := map[classificationArtifactBinding]struct{}{}
	usedRows := map[string]struct{}{}
	usedOccurrences := map[string]string{}
	alpha := sourceClassificationOccurrenceObject(binding, "alpha", "data_entity", locator)
	if _, err := bindSelectedSourceClassification(roster, 0, 0, alpha, metadata, bindings, loaded.Bodies, usedBindings, usedRows, usedOccurrences); err != nil {
		t.Fatalf("first occurrence: %v", err)
	}
	if _, err := bindSelectedSourceClassification(roster, 0, 1, alpha, metadata, bindings, loaded.Bodies, usedBindings, usedRows, usedOccurrences); err == nil || !strings.Contains(err.Error(), "duplicates exact classification occurrence") {
		t.Fatalf("duplicate error = %v, want exact duplicate refusal", err)
	}
	beta := sourceClassificationOccurrenceObject(binding, "beta", "data_entity", locator)
	if _, err := bindSelectedSourceClassification(roster, 0, 2, beta, metadata, bindings, loaded.Bodies, usedBindings, usedRows, usedOccurrences); err != nil {
		t.Fatalf("same locator for a second semantic target: %v", err)
	}
	if len(usedOccurrences) != 2 {
		t.Fatalf("exact locator/semantic-target pairs = %d, want 2", len(usedOccurrences))
	}
}

func TestSourceClassificationBindingRejectsTamperedRangeAndSemanticMetadata(t *testing.T) {
	body := []byte("alpha")
	manifestPath := writeClassificationEvidenceManifest(t, t.TempDir(), "fixture_reference_evidence", "fixture.reference", "https://example.com/reference", body, nil)
	loaded := loadClassificationEvidence(t, []string{manifestPath})
	metadata := soleClassificationMetadata(t, loaded)
	roster, dependencies, binding := sourceClassificationFixture(t, sourceClassificationRow("alpha", "data_entity"))
	bindings, err := validateClassificationArtifactBindings(roster, "fixture_provider", dependencies, map[string]struct{}{})
	if err != nil {
		t.Fatalf("validateClassificationArtifactBindings: %v", err)
	}
	locator := sourceClassificationLocator(metadata, body, 0, int64(len(body)))

	t.Run("tampered selected-range digest", func(t *testing.T) {
		tampered := locator
		tampered.SelectedRangeSHA256 = strings.Repeat("0", 64)
		tampered.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(tampered))
		raw := sourceClassificationOccurrenceObject(binding, "alpha", "data_entity", tampered)
		_, err := bindSelectedSourceClassification(roster, 0, 0, raw, metadata, bindings, loaded.Bodies, map[classificationArtifactBinding]struct{}{}, map[string]struct{}{}, map[string]string{})
		if err == nil || !strings.Contains(err.Error(), "selected bytes do not match") {
			t.Fatalf("error = %v, want selected-range digest refusal", err)
		}
	})

	t.Run("conflicting surface kind", func(t *testing.T) {
		raw := sourceClassificationOccurrenceObject(binding, "alpha", "report", locator)
		_, err := bindSelectedSourceClassification(roster, 0, 0, raw, metadata, bindings, loaded.Bodies, map[classificationArtifactBinding]struct{}{}, map[string]struct{}{}, map[string]string{})
		if err == nil || !strings.Contains(err.Error(), "semantic symbol/surface") {
			t.Fatalf("error = %v, want semantic metadata mismatch refusal", err)
		}
	})

	t.Run("locator does not belong to selected document", func(t *testing.T) {
		otherMetadata := metadata
		otherMetadata.SourceRef = "other.reference"
		otherMetadata.SourceURL = "https://example.com/other"
		otherBody := exactEvidenceBody{Bytes: body, Coordinates: map[evidenceSourceCoordinate]string{{Ref: otherMetadata.SourceRef, URL: otherMetadata.SourceURL}: otherMetadata.ManifestSHA256}}
		bodies := map[string]exactEvidenceBody{metadata.ContentSHA256: otherBody}
		otherLocator := sourceClassificationLocator(otherMetadata, body, 0, int64(len(body)))
		raw := sourceClassificationOccurrenceObject(binding, "alpha", "data_entity", otherLocator)
		_, err := bindSelectedSourceClassification(roster, 0, 0, raw, metadata, bindings, bodies, map[classificationArtifactBinding]struct{}{}, map[string]struct{}{}, map[string]string{})
		if err == nil || !strings.Contains(err.Error(), "does not equal its selected document") {
			t.Fatalf("error = %v, want selected-document identity refusal", err)
		}
	})
}

func TestEvidenceBodyMetadataRejectsEmbeddedSemanticClassification(t *testing.T) {
	body := []byte("document body")
	dir := t.TempDir()
	validPath := writeClassificationEvidenceManifest(t, dir, "fixture_document_evidence", "fixture.document", "https://example.com/document", body, nil)
	loaded := loadClassificationEvidence(t, []string{validPath})
	if len(loaded.MetadataByIdentity) != 1 || len(loaded.ClassificationsBySourceSymbol) != 0 {
		t.Fatalf("document metadata or classification index is not document-only: metadata=%d classifications=%d", len(loaded.MetadataByIdentity), len(loaded.ClassificationsBySourceSymbol))
	}

	legacyPath := writeClassificationEvidenceManifest(t, dir, "fixture_legacy_evidence", "fixture.legacy", "https://example.com/legacy", body, map[string]interface{}{
		"source_symbol":         "alpha",
		"surface_kind":          "data_entity",
		"official_json_pointer": "/entities/alpha",
	})
	if _, err := loadEvidenceBodies([]string{legacyPath}, map[string]struct{}{supportedEvidenceRepresentationKind: {}}); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("error = %v, want document/semantic-boundary refusal", err)
	}
}

func TestSourceClassificationArtifactRejectsSemanticIdentityAliasing(t *testing.T) {
	t.Run("duplicate within artifact", func(t *testing.T) {
		roster, dependencies, _ := sourceClassificationFixture(t,
			sourceClassificationRow("alpha", "data_entity"),
			sourceClassificationRow("alpha", "report"),
		)
		_, err := validateClassificationArtifactBindings(roster, "fixture_provider", dependencies, map[string]struct{}{})
		if err == nil || !strings.Contains(err.Error(), "duplicates source_symbol") {
			t.Fatalf("error = %v, want duplicate semantic identity refusal", err)
		}
	})

	t.Run("duplicate across artifacts", func(t *testing.T) {
		roster, dependencies, _ := sourceClassificationFixture(t, sourceClassificationRow("alpha", "data_entity"))
		secondInput, secondBinding := writeSourceClassificationArtifact(t, t.TempDir(), "fixture_source_classification_roster_two", sourceClassificationRow("alpha", "data_entity"))
		roster.Manifest["classification_artifact_bindings"] = append(roster.Manifest["classification_artifact_bindings"].([]interface{}), map[string]interface{}{
			"artifact_id":      secondBinding.ArtifactID,
			"artifact_version": secondBinding.ArtifactVersion,
			"artifact_sha256":  secondBinding.ArtifactSHA256,
		})
		dependencies[secondBinding.ArtifactSHA256] = secondInput
		_, err := validateClassificationArtifactBindings(roster, "fixture_provider", dependencies, map[string]struct{}{})
		if err == nil || !strings.Contains(err.Error(), "alias semantic source_symbol") {
			t.Fatalf("error = %v, want cross-artifact semantic alias refusal", err)
		}
	})
}

func sourceClassificationFixture(t *testing.T, rows ...map[string]interface{}) (artifactInput, map[string]artifactInput, classificationArtifactBinding) {
	t.Helper()
	return sourceClassificationFixtureAt(t, t.TempDir(), rows...)
}

func sourceClassificationFixtureAt(t *testing.T, dir string, rows ...map[string]interface{}) (artifactInput, map[string]artifactInput, classificationArtifactBinding) {
	t.Helper()
	classification, binding := writeSourceClassificationArtifact(t, dir, "fixture_source_classification_roster", rows...)
	roster := artifactInput{
		Path:       "fixture-selection-roster.jsonl",
		Structured: true,
		Manifest: map[string]interface{}{
			"classification_artifact_bindings": []interface{}{map[string]interface{}{
				"artifact_id": binding.ArtifactID, "artifact_version": binding.ArtifactVersion, "artifact_sha256": binding.ArtifactSHA256,
			}},
		},
	}
	dependencies := map[string]artifactInput{binding.ArtifactSHA256: classification}
	return roster, dependencies, binding
}

func writeSourceClassificationArtifact(t *testing.T, dir, artifactID string, rows ...map[string]interface{}) (artifactInput, classificationArtifactBinding) {
	t.Helper()
	manifest := map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactID, "artifact_version": "2", "status": "candidate_source_selection_input", "provider": "fixture_provider",
		"authority_posture": "semantic_source_element_identity_only_not_documentation_evidence", "source_symbol_count": len(rows),
	}
	path := filepath.Join(dir, artifactID+".jsonl")
	writeClassificationJSONL(t, path, append([]map[string]interface{}{manifest}, rows...))
	input, err := readArtifactInput(path)
	if err != nil {
		t.Fatalf("read classification artifact: %v", err)
	}
	return input, classificationArtifactBinding{ArtifactID: artifactID, ArtifactVersion: "2", ArtifactSHA256: input.SHA256}
}

func sourceClassificationRow(symbol, surfaceKind string) map[string]interface{} {
	return map[string]interface{}{"row_kind": "source_symbol", "source_symbol": symbol, "surface_kind": surfaceKind}
}

func sourceClassificationOccurrenceObject(binding classificationArtifactBinding, sourceSymbol, surfaceKind string, locator evidenceLocator) map[string]interface{} {
	return map[string]interface{}{
		"artifact_id": binding.ArtifactID, "artifact_version": binding.ArtifactVersion, "artifact_sha256": binding.ArtifactSHA256,
		"row_kind": "source_classification_occurrence", "source_symbol": sourceSymbol, "surface_kind": surfaceKind,
		"evidence_locator": sourceClassificationLocatorObject(locator),
	}
}

func sourceClassificationLocator(metadata evidenceBodyMetadata, body []byte, start, end int64) evidenceLocator {
	selected := body[start:end]
	locator := evidenceLocator{
		RowKind: "candidate_evidence_locator", EvidenceManifestSHA256: metadata.ManifestSHA256, SourceContentSHA256: metadata.ContentSHA256,
		ByteStartOffset: start, ByteEndOffsetExclusive: end, SelectedRangeByteCount: end - start, SelectedRangeSHA256: sha256Hex(selected),
		SourceRefs: []string{metadata.SourceRef}, SourceURLs: []string{metadata.SourceURL}, LocatorSemantics: exactLocatorSemantics, SourceBytesPresent: false,
	}
	locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
	return locator
}

func sourceClassificationLocatorObject(locator evidenceLocator) map[string]interface{} {
	encoded, _ := json.Marshal(locator)
	object, _ := decodeJSONObject(encoded)
	return object
}

func sourceClassificationSelectionSummary(selectedDocuments, classifiedDocuments, occurrences int) map[string]interface{} {
	return map[string]interface{}{
		"row_kind": "validation_summary", "selected_source_count": json.Number(strconv.Itoa(selectedDocuments)), "evidence_manifest_artifact_count": json.Number("1"),
		"classified_source_document_count": json.Number(strconv.Itoa(classifiedDocuments)), "classification_occurrence_count": json.Number(strconv.Itoa(occurrences)),
		"captured_consumer_role_counts": map[string]interface{}{"api_graph_projection": json.Number(strconv.Itoa(selectedDocuments))}, "result": "structural_candidate_source_selection_roster",
	}
}

func loadClassificationEvidence(t *testing.T, paths []string) loadedEvidence {
	t.Helper()
	loaded, err := loadEvidenceBodies(paths, map[string]struct{}{supportedEvidenceRepresentationKind: {}})
	if err != nil {
		t.Fatalf("loadEvidenceBodies: %v", err)
	}
	return loaded
}

func soleClassificationMetadata(t *testing.T, loaded loadedEvidence) evidenceBodyMetadata {
	t.Helper()
	if len(loaded.MetadataByIdentity) != 1 {
		t.Fatalf("metadata identities = %d, want 1", len(loaded.MetadataByIdentity))
	}
	for _, metadata := range loaded.MetadataByIdentity {
		return metadata
	}
	return evidenceBodyMetadata{}
}

func sortedClassificationMetadata(loaded loadedEvidence) []evidenceBodyMetadata {
	values := make([]evidenceBodyMetadata, 0, len(loaded.MetadataByCoordinate))
	for _, metadata := range loaded.MetadataByCoordinate {
		values = append(values, metadata)
	}
	if len(values) == 2 && values[0].SourceRef > values[1].SourceRef {
		values[0], values[1] = values[1], values[0]
	}
	return values
}

func writeClassificationEvidenceManifest(t *testing.T, dir, artifact, sourceRef, sourceURL string, body []byte, bodyExtras map[string]interface{}) string {
	t.Helper()
	bodySHA256 := sha256Hex(body)
	stagingFile := artifact + ".md.b64"
	if err := os.WriteFile(filepath.Join(dir, stagingFile), []byte(base64.StdEncoding.EncodeToString(body)), 0o600); err != nil {
		t.Fatalf("write staged evidence: %v", err)
	}
	bodyRow := map[string]interface{}{
		"row_kind": "external_evidence_body", "component_ordinal": 0, "component_stable_coordinate": "source_ref_url_pair_v1|" + lengthPrefixedIdentityKey(sourceRef, sourceURL),
		"component_byte_length": len(body), "component_sha256": bodySHA256, "component_byte_domain_profile": componentByteDomainProfile,
		"source_ref": sourceRef, "source_url": sourceURL, "representation": "source_declared_copy_all_for_ai_markdown", "representation_coordinate": "button[aria-label=Copy all for AI]",
		"source_representation_kind": supportedEvidenceRepresentationKind, "content_sha256": bodySHA256, "content_bytes": len(body), "source_content_hash_profile": sourceContentHashProfile,
		"observed_line_delimiter_profile": "none", "staging_file": stagingFile, "body_authority": evidenceBodyAuthorityExact,
	}
	for key, value := range bodyExtras {
		bodyRow[key] = value
	}
	rows := []map[string]interface{}{
		{
			"row_kind": "artifact_manifest", "artifact": artifact, "artifact_version": "1", "status": "candidate_not_admissible", "provider": "fixture_provider",
			"representation": "source_declared_copy_all_for_ai_markdown", "representation_coordinate": "button[aria-label=Copy all for AI]", "source_representation_kind": supportedEvidenceRepresentationKind,
			"canonical_bytes": manifestCanonicalBytesProfile,
		},
		bodyRow,
		{
			"row_kind": "validation_summary", "selected_source_count": 1, "captured_source_count": 1, "total_exact_source_bytes": len(body), "missing_source_refs": []string{}, "unexpected_source_refs": []string{},
			"selected_representation_is_only_evidence_body": true, "rendered_dom_body_accepted": false, "result": "structural_candidate_selected_source_document_capture",
		},
	}
	path := filepath.Join(dir, artifact+".jsonl")
	writeClassificationJSONL(t, path, rows)
	return path
}

func writeClassificationJSONL(t *testing.T, path string, rows []map[string]interface{}) {
	t.Helper()
	var lines strings.Builder
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatalf("marshal JSONL row: %v", err)
		}
		lines.Write(encoded)
		lines.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0o600); err != nil {
		t.Fatalf("write JSONL artifact: %v", err)
	}
}
