//go:build externalfixture

package providerplan

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type officialProviderEvidenceConfig struct {
	Provider                 string
	ArtifactPrefix           string
	SourceRef                string
	SourceURL                string
	Representation           string
	RepresentationCoordinate string
	BodySHA256               string
	BodyByteCount            int
	Ranges                   []officialProviderEvidenceRange
}

type officialProviderEvidenceFixture struct {
	ManifestPath       string
	ClassificationPath string
	SelectionPath      string
	ManifestSHA256     string
	SelectionSHA256    string
	Proof              sourceClassificationSelectionProof
	Bodies             map[string]exactEvidenceBody
	LocatorRootSHA256  string
	Locators           map[string]evidenceLocator
}

// buildOfficialProviderEvidenceFixture turns the immutable official source
// bytes and pinned half-open ranges into the same closed on-disk manifest,
// classification, and selection artifacts consumed by Verify. No digest in
// the returned proof is minted from an in-memory pseudo-manifest.
func buildOfficialProviderEvidenceFixture(t *testing.T, body []byte, config officialProviderEvidenceConfig) officialProviderEvidenceFixture {
	t.Helper()
	if len(body) != config.BodyByteCount || sha256Hex(body) != config.BodySHA256 {
		t.Fatalf("%s official evidence body differs from its byte-count/SHA-256 pin", config.Provider)
	}
	dir := t.TempDir()
	carrierName := config.ArtifactPrefix + ".source-document.b64"
	carrierPath := filepath.Join(dir, carrierName)
	if err := os.WriteFile(carrierPath, []byte(base64.StdEncoding.EncodeToString(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, config.ArtifactPrefix+"_evidence_manifest.jsonl")
	writeClassificationJSONL(t, manifestPath, []map[string]interface{}{
		{
			"row_kind": "artifact_manifest", "artifact": config.ArtifactPrefix + "_evidence_manifest", "artifact_version": "1",
			"status": "candidate_not_admissible", "provider": config.Provider,
			"representation": config.Representation, "representation_coordinate": config.RepresentationCoordinate,
			"source_representation_kind": supportedEvidenceRepresentationKind, "canonical_bytes": manifestCanonicalBytesProfile,
		},
		{
			"row_kind": "external_evidence_body", "component_ordinal": 0,
			"component_stable_coordinate": "source_ref_url_pair_v1|" + lengthPrefixedIdentityKey(config.SourceRef, config.SourceURL),
			"component_byte_length":       len(body), "component_sha256": config.BodySHA256,
			"component_byte_domain_profile": componentByteDomainProfile,
			"source_ref":                    config.SourceRef, "source_url": config.SourceURL,
			"representation": config.Representation, "representation_coordinate": config.RepresentationCoordinate,
			"source_representation_kind": supportedEvidenceRepresentationKind,
			"content_sha256":             config.BodySHA256, "content_bytes": len(body),
			"source_content_hash_profile":     sourceContentHashProfile,
			"observed_line_delimiter_profile": exactLineDelimiterProfile(body),
			"staging_file":                    carrierName, "body_authority": evidenceBodyAuthorityExact,
		},
		{
			"row_kind": "validation_summary", "selected_source_count": 1, "captured_source_count": 1,
			"total_exact_source_bytes": len(body), "missing_source_refs": []string{}, "unexpected_source_refs": []string{},
			"selected_representation_is_only_evidence_body": true, "rendered_dom_body_accepted": false,
			"result": "structural_candidate_selected_source_document_capture",
		},
	})
	loaded, err := loadEvidenceBodies([]string{manifestPath}, map[string]struct{}{supportedEvidenceRepresentationKind: {}})
	if err != nil {
		t.Fatalf("load %s official evidence manifest: %v", config.Provider, err)
	}
	metadata, ok := loaded.MetadataByCoordinate[evidenceSourceCoordinate{Ref: config.SourceRef, URL: config.SourceURL}]
	if !ok || metadata.ContentSHA256 != config.BodySHA256 {
		t.Fatalf("%s official evidence manifest did not hydrate its exact pinned coordinate", config.Provider)
	}

	surfaceBySymbol := map[string]string{}
	locators := make(map[string]evidenceLocator, len(config.Ranges))
	locatorRows := make([][]byte, 0, len(config.Ranges))
	for _, selected := range config.Ranges {
		if selected.ByteStartOffset < 0 || selected.ByteEndOffsetExclusive <= selected.ByteStartOffset || selected.ByteEndOffsetExclusive > int64(len(body)) {
			t.Fatalf("%s evidence range %q is outside the exact body", config.Provider, selected.Name)
		}
		if got := sha256Hex(body[selected.ByteStartOffset:selected.ByteEndOffsetExclusive]); got != selected.SelectedRangeSHA256 {
			t.Fatalf("%s evidence range %q SHA-256 = %s, want %s", config.Provider, selected.Name, got, selected.SelectedRangeSHA256)
		}
		if prior, exists := surfaceBySymbol[selected.SourceSymbol]; exists && prior != selected.SurfaceKind {
			t.Fatalf("%s source symbol %q has conflicting surfaces %q and %q", config.Provider, selected.SourceSymbol, prior, selected.SurfaceKind)
		}
		surfaceBySymbol[selected.SourceSymbol] = selected.SurfaceKind
		locator := sourceClassificationLocator(metadata, body, selected.ByteStartOffset, selected.ByteEndOffsetExclusive)
		locators[locator.ID] = locator
		locatorRows = append(locatorRows, []byte(lengthPrefixedIdentityKey(locator.ID, candidateEvidenceLocatorIdentityKey(locator))))
	}

	symbols := sortedSetKeys(stringMapKeysAsSet(surfaceBySymbol))
	classificationRows := make([]map[string]interface{}, 0, len(symbols)+1)
	classificationRows = append(classificationRows, map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": config.ArtifactPrefix + "_source_classification", "artifact_version": "2",
		"status": "candidate_source_selection_input", "provider": config.Provider,
		"authority_posture": "semantic_source_element_identity_only_not_documentation_evidence", "source_symbol_count": len(symbols),
	})
	for _, symbol := range symbols {
		classificationRows = append(classificationRows, sourceClassificationRow(symbol, surfaceBySymbol[symbol]))
	}
	classificationPath := filepath.Join(dir, config.ArtifactPrefix+"_source_classification.jsonl")
	writeClassificationJSONL(t, classificationPath, classificationRows)
	classification, err := readArtifactInput(classificationPath)
	if err != nil {
		t.Fatalf("read %s official classification artifact: %v", config.Provider, err)
	}
	binding := classificationArtifactBinding{
		ArtifactID: config.ArtifactPrefix + "_source_classification", ArtifactVersion: "2", ArtifactSHA256: classification.SHA256,
	}

	type orderedOccurrence struct {
		key string
		row map[string]interface{}
		occ sourceClassificationOccurrence
	}
	occurrences := make([]orderedOccurrence, 0, len(config.Ranges))
	expectedClassifications := map[string][]sourceClassificationOccurrence{}
	for _, selected := range config.Ranges {
		locator := sourceClassificationLocator(metadata, body, selected.ByteStartOffset, selected.ByteEndOffsetExclusive)
		occurrence := sourceClassificationOccurrence{Binding: binding, SourceSymbol: selected.SourceSymbol, SurfaceKind: selected.SurfaceKind, Locator: locator}
		key := selected.SourceSymbol + "\x00" + selected.SurfaceKind + "\x00" + locator.EvidenceManifestSHA256 + "\x00" + locator.SourceRefs[0] + "\x00" + locator.SourceURLs[0] + "\x00" + locator.SourceContentSHA256 + "\x00" + formatCanonicalOffset(locator.ByteStartOffset) + "\x00" + formatCanonicalOffset(locator.ByteEndOffsetExclusive) + "\x00" + locator.SelectedRangeSHA256 + "\x00" + binding.ArtifactSHA256
		occurrences = append(occurrences, orderedOccurrence{key: key, row: sourceClassificationOccurrenceObject(binding, selected.SourceSymbol, selected.SurfaceKind, locator), occ: occurrence})
		expectedClassifications[selected.SourceSymbol] = append(expectedClassifications[selected.SourceSymbol], occurrence)
	}
	sort.Slice(occurrences, func(i, j int) bool { return occurrences[i].key < occurrences[j].key })
	rawOccurrences := make([]interface{}, len(occurrences))
	for index, occurrence := range occurrences {
		rawOccurrences[index] = occurrence.row
	}
	selectionManifest := map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": config.ArtifactPrefix + "_evidence_selection_roster", "artifact_version": "4",
		"status": "candidate_source_selection_input", "provider": config.Provider, "selected_source_count": 1,
		"classification_artifact_bindings": []interface{}{map[string]interface{}{
			"artifact_id": binding.ArtifactID, "artifact_version": binding.ArtifactVersion, "artifact_sha256": binding.ArtifactSHA256,
		}},
	}
	manifestArtifact, _ := manifestString(loaded.Artifacts[metadata.ManifestSHA256].Manifest, "artifact")
	manifestVersion, _ := manifestString(loaded.Artifacts[metadata.ManifestSHA256].Manifest, "artifact_version")
	selectionRow := map[string]interface{}{
		"row_kind": "selected_source_document", "evidence_manifest_artifact": manifestArtifact,
		"evidence_manifest_artifact_version": manifestVersion, "source_ref": config.SourceRef,
		"current_reference_url": config.SourceURL, "representation": config.Representation,
		"representation_coordinate": config.RepresentationCoordinate, "source_representation_kind": supportedEvidenceRepresentationKind,
		"consumer_roles": []interface{}{"api_graph_projection"}, "classification_occurrences": rawOccurrences,
	}
	selectionSummary := sourceClassificationSelectionSummary(1, 1, len(occurrences))
	selectionPath := filepath.Join(dir, config.ArtifactPrefix+"_evidence_selection_roster.jsonl")
	writeClassificationJSONL(t, selectionPath, []map[string]interface{}{selectionManifest, selectionRow, selectionSummary})
	selection, err := readArtifactInput(selectionPath)
	if err != nil {
		t.Fatalf("read %s official selection roster: %v", config.Provider, err)
	}
	dependencies := map[string]artifactInput{classification.SHA256: classification}
	plan := &parsedPlan{
		Manifest: &artifactManifest{
			Provider: config.Provider, EvidenceSelectionRosterSHA256: selection.SHA256,
			EvidenceManifestBindings: []evidenceManifestBinding{{
				EvidenceManifestSHA256: metadata.ManifestSHA256, EvidenceBodyKind: evidenceBodyKindSourceDocument,
				ConsumerRoles: []string{"api_graph_projection"},
			}},
		},
		Locators: locators,
	}
	if err := validateEvidenceSelectionRoster(selection, config.Provider, loaded, dependencies, map[string]struct{}{}, plan); err != nil {
		t.Fatalf("validate %s official selection roster: %v", config.Provider, err)
	}
	proof, ok := loaded.ClassificationSelectionProofs[selection.SHA256]
	if !ok {
		t.Fatalf("%s official selection roster did not mint a proof", config.Provider)
	}
	independent := newSourceClassificationSelectionProof(config.Provider, selection.SHA256, expectedClassifications)
	if err := validateSourceClassificationSelectionProof(independent); err != nil {
		t.Fatal(err)
	}
	if proof.contentSHA256 != independent.contentSHA256 {
		t.Fatalf("%s production-loaded classification proof differs from independent pinned-range recomputation", config.Provider)
	}
	return officialProviderEvidenceFixture{
		ManifestPath: manifestPath, ClassificationPath: classificationPath, SelectionPath: selectionPath,
		ManifestSHA256: metadata.ManifestSHA256, SelectionSHA256: selection.SHA256, Proof: proof,
		Bodies: loaded.Bodies, LocatorRootSHA256: stageCanonicalSetRoot(locatorRows), Locators: locators,
	}
}

func formatCanonicalOffset(value int64) string {
	return fmt.Sprintf("%020d", value)
}
