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

func TestExactEvidenceBodyAndLocatorAreByteNeutral(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := []byte{0xff, 0x00, 0xfe, '\n'}
	bodySHA := sha256Hex(body)
	bodyPath := filepath.Join(dir, "body.bin.b64")
	if err := os.WriteFile(bodyPath, []byte(base64.StdEncoding.EncodeToString(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	const sourceRef = "fixture.byte_neutral"
	const sourceURL = "https://example.invalid/byte-neutral"
	manifestPath := filepath.Join(dir, "evidence.jsonl")
	writeParseOutcomeJSONL(t, manifestPath, []map[string]interface{}{
		{
			"row_kind": "artifact_manifest", "artifact": "byte_neutral_evidence", "artifact_version": "1", "status": "candidate_not_admissible", "provider": "fixture_provider",
			"representation": "source_declared_binary_export", "representation_coordinate": "fixture-export", "source_representation_kind": supportedEvidenceRepresentationKind, "canonical_bytes": manifestCanonicalBytesProfile,
		},
		{
			"row_kind": "external_evidence_body", "component_ordinal": 0, "component_stable_coordinate": "source_ref_url_pair_v1|" + lengthPrefixedIdentityKey(sourceRef, sourceURL),
			"component_byte_length": len(body), "component_sha256": bodySHA, "component_byte_domain_profile": componentByteDomainProfile,
			"source_ref": sourceRef, "source_url": sourceURL, "representation": "source_declared_binary_export", "representation_coordinate": "fixture-export", "source_representation_kind": supportedEvidenceRepresentationKind,
			"content_sha256": bodySHA, "content_bytes": len(body), "source_content_hash_profile": sourceContentHashProfile, "observed_line_delimiter_profile": "LF", "staging_file": filepath.Base(bodyPath), "body_authority": evidenceBodyAuthorityExact,
		},
		{
			"row_kind": "validation_summary", "selected_source_count": 1, "captured_source_count": 1, "total_exact_source_bytes": len(body), "missing_source_refs": []string{}, "unexpected_source_refs": []string{},
			"selected_representation_is_only_evidence_body": true, "rendered_dom_body_accepted": false, "result": "structural_candidate_selected_source_document_capture",
		},
	})

	loaded, err := loadEvidenceBodies([]string{manifestPath}, map[string]struct{}{supportedEvidenceRepresentationKind: {}})
	if err != nil {
		t.Fatalf("loadEvidenceBodies() rejected byte-faithful non-UTF-8 evidence: %v", err)
	}
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	locator := evidenceLocator{
		EvidenceManifestSHA256: sha256Hex(manifestRaw), SourceContentSHA256: bodySHA,
		ByteStartOffset: 0, ByteEndOffsetExclusive: 1, SelectedRangeByteCount: 1, SelectedRangeSHA256: sha256Hex(body[:1]),
		SourceRefs: []string{sourceRef}, SourceURLs: []string{sourceURL}, LocatorSemantics: exactLocatorSemantics,
	}
	locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
	if err := validateLocator(locator, loaded.Bodies); err != nil {
		t.Fatalf("validateLocator() rejected exact non-UTF-8 byte range: %v", err)
	}
	coordinateObject := map[string]interface{}{
		"source_content_sha256": bodySHA, "byte_start_offset": json.Number("0"), "byte_end_offset_exclusive": json.Number("1"),
		"selected_range_byte_count": json.Number("1"), "selected_range_sha256": sha256Hex(body[:1]),
	}
	semanticRows := dependencySemanticRows{path: "byte-neutral.jsonl"}
	semanticRow := dependencySemanticRow{line: 1, kind: "fixture", data: map[string]interface{}{"evidence_hydration_coordinate": coordinateObject}}
	semanticCoordinate, err := parseDependencyHydrationCoordinate(coordinateObject)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExactHydrationCoordinate(semanticRows, semanticRow, semanticCoordinate, sourceRef, sourceURL, loaded); err != nil {
		t.Fatalf("semantic hydration rejected exact non-UTF-8 byte range: %v", err)
	}
	hydrated := map[string]struct{}{}
	if err := addHydratedEvidenceIdentity(coordinateObject, sourceRef, sourceURL, loaded, hydrated); err != nil {
		t.Fatalf("evidence identity hydration rejected exact non-UTF-8 byte range: %v", err)
	}
	if len(hydrated) != 1 {
		t.Fatalf("hydrated evidence identity count = %d, want 1", len(hydrated))
	}
}

func TestSampleParseOutcomeValidJSONRecomputesExactShapes(t *testing.T) {
	t.Parallel()
	fixture := newSampleParseOutcomeFixture(t, []byte(`{"amount":12.34,"label":"ok"}`), "application/json", "utf-8", sampleDecoderKindUTF8Strict, sampleParserKindJSONRFC8259, sampleParseOutcomeParsed, "", "", true)
	if err := fixture.validate(); err != nil {
		t.Fatalf("valid JSON parse fixture rejected: %v", err)
	}

	t.Run("shape omission", func(t *testing.T) {
		fixture := newSampleParseOutcomeFixture(t, []byte(`{"amount":12.34,"label":"ok"}`), "application/json", "utf-8", sampleDecoderKindUTF8Strict, sampleParserKindJSONRFC8259, sampleParseOutcomeParsed, "", "", true)
		fixture.rows.byKind["sample_json_shape"] = fixture.rows.byKind["sample_json_shape"][:2]
		fixture.summary().data["sample_json_shape_row_count"] = json.Number("2")
		fixture.summary().data["exact_evidence_locator_binding_count"] = json.Number("3")
		if err := fixture.validate(); err == nil || !strings.Contains(err.Error(), "pointer roster") {
			t.Fatalf("shape omission error = %v, want exact pointer-roster refusal", err)
		}
	})

	t.Run("schema authority tamper", func(t *testing.T) {
		fixture := newSampleParseOutcomeFixture(t, []byte(`{"amount":12.34,"label":"ok"}`), "application/json", "utf-8", sampleDecoderKindUTF8Strict, sampleParserKindJSONRFC8259, sampleParseOutcomeParsed, "", "", true)
		fixture.rows.byKind["sample_json_shape"][0].data["schema_authority"] = "authoritative_schema"
		if err := fixture.validate(); err == nil || !strings.Contains(err.Error(), "non-sample schema authority") {
			t.Fatalf("schema-authority error = %v, want sample-only refusal", err)
		}
	})

	t.Run("string class tamper", func(t *testing.T) {
		fixture := newSampleParseOutcomeFixture(t, []byte(`{"amount":12.34,"label":"ok"}`), "application/json", "utf-8", sampleDecoderKindUTF8Strict, sampleParserKindJSONRFC8259, sampleParseOutcomeParsed, "", "", true)
		fixture.rows.byKind["sample_json_shape"][2].data["observed_string_classes"] = []interface{}{"currency"}
		if err := fixture.validate(); err == nil || !strings.Contains(err.Error(), "observed_string_classes") {
			t.Fatalf("string-class error = %v, want exact parser-derived class refusal", err)
		}
	})
}

func TestSampleParseOutcomeMalformedJSONIsFailedAndShapeFree(t *testing.T) {
	t.Parallel()
	fixture := newSampleParseOutcomeFixture(t, []byte(`{"amount":`), "application/json", "utf-8", sampleDecoderKindUTF8Strict, sampleParserKindJSONRFC8259, sampleParseOutcomeFailed, "malformed_json", "parser", false)
	if err := fixture.validate(); err != nil {
		t.Fatalf("truthful malformed-JSON failure rejected: %v", err)
	}

	t.Run("outcome tamper", func(t *testing.T) {
		fixture := newSampleParseOutcomeFixture(t, []byte(`{"amount":`), "application/json", "utf-8", sampleDecoderKindUTF8Strict, sampleParserKindJSONRFC8259, sampleParseOutcomeParsed, "", "", false)
		if err := fixture.validate(); err == nil || !strings.Contains(err.Error(), "deterministic profile result") {
			t.Fatalf("outcome tamper error = %v, want deterministic result refusal", err)
		}
	})

	t.Run("failure tamper", func(t *testing.T) {
		fixture := newSampleParseOutcomeFixture(t, []byte(`{"amount":`), "application/json", "utf-8", sampleDecoderKindUTF8Strict, sampleParserKindJSONRFC8259, sampleParseOutcomeFailed, "duplicate_json_key", "parser", false)
		if err := fixture.validate(); err == nil || !strings.Contains(err.Error(), "deterministic typed failure") {
			t.Fatalf("failure tamper error = %v, want typed failure refusal", err)
		}
	})

	t.Run("shape tamper", func(t *testing.T) {
		fixture := newSampleParseOutcomeFixture(t, []byte(`{"amount":`), "application/json", "utf-8", sampleDecoderKindUTF8Strict, sampleParserKindJSONRFC8259, sampleParseOutcomeFailed, "malformed_json", "parser", false)
		fixture.addShape("", []interface{}{"object"}, nil, nil)
		fixture.summary().data["sample_json_shape_row_count"] = json.Number("1")
		fixture.summary().data["exact_evidence_locator_binding_count"] = json.Number("2")
		if err := fixture.validate(); err == nil || !strings.Contains(err.Error(), "only parsed JSON may emit shapes") {
			t.Fatalf("failed-outcome shape error = %v, want parsed-only refusal", err)
		}
	})
}

func TestSampleParseOutcomeUnsupportedMediaIsTypedAndShapeFree(t *testing.T) {
	t.Parallel()
	fixture := newSampleParseOutcomeFixture(t, []byte(`<sample/>`), "application/xml", "utf-8", sampleDecoderKindNone, sampleParserKindUnsupported, sampleParseOutcomeUnsupported, "unsupported_media_type", "media_type_selection", false)
	if err := fixture.validate(); err != nil {
		t.Fatalf("truthful unsupported-media outcome rejected: %v", err)
	}

	t.Run("profile cannot reject supported JSON", func(t *testing.T) {
		fixture := newSampleParseOutcomeFixture(t, []byte(`{"ok":true}`), "application/json", "utf-8", sampleDecoderKindNone, sampleParserKindUnsupported, sampleParseOutcomeUnsupported, "unsupported_media_type", "media_type_selection", false)
		if err := fixture.validate(); err == nil || !strings.Contains(err.Error(), "rejects the supported JSON/UTF-8 pair") {
			t.Fatalf("supported-media rejection error = %v, want unsupported-profile refusal", err)
		}
	})
}

func TestSampleParseOutcomeInvalidUTF8IsRetainedAsTypedDecoderFailure(t *testing.T) {
	t.Parallel()
	fixture := newSampleParseOutcomeFixture(t, []byte{0xff, 0xfe}, "application/json", "utf-8", sampleDecoderKindUTF8Strict, sampleParserKindJSONRFC8259, sampleParseOutcomeFailed, "invalid_charset_sequence", "decoder", false)
	if err := fixture.validate(); err != nil {
		t.Fatalf("truthful invalid-UTF-8 decoder failure rejected: %v", err)
	}
}

func TestSampleParseOutcomeNotApplicableIsClosedAndShapeFree(t *testing.T) {
	t.Parallel()
	fixture := newSampleParseOutcomeFixture(t, []byte{0x00, 0x01}, "application/octet-stream", "binary", sampleDecoderKindNone, sampleParserKindNotApplicable, sampleParseOutcomeNotApplicable, "", "", false)
	if err := fixture.validate(); err != nil {
		t.Fatalf("truthful not-applicable outcome rejected: %v", err)
	}
}

func TestFieldMappingSummaryDoesNotInferResourceSurfaceCountFromDocumentCount(t *testing.T) {
	t.Parallel()
	input := artifactInput{
		Path:     "field-mapping.jsonl",
		Manifest: map[string]interface{}{"field_security_policy_sha256": strings.Repeat("a", 64)},
		RowKindCounts: map[string]int{
			"field_occurrence_disposition": 0,
		},
		ValidationSummary: map[string]interface{}{
			"row_kind": "validation_summary", "result": "candidate_complete_atomic_field_occurrence_disposition_with_explicit_quarantine_and_no_passthrough",
			"source_document_count": json.Number("1"), "surface_family_count": json.Number("2"), "documented_field_occurrence_count": json.Number("0"), "disposed_field_occurrence_count": json.Number("0"),
			"exact_locator_binding_count": json.Number("0"), "silent_unknown_count": json.Number("0"), "arbitrary_provider_json_passthrough_count": json.Number("0"), "raw_value_embedding_count": json.Number("0"),
			"binary_float_authoritative_count": json.Number("0"), "restricted_no_embed_count": json.Number("0"), "standard_no_raw_value_embedding_count": json.Number("0"),
			"canonical_target_contracts_locked": false, "security_policy_sha256": strings.Repeat("a", 64),
		},
	}
	source := artifactInput{RowKindCounts: map[string]int{"source_document": 1, "field_contract": 0}}
	if err := validateFieldMappingValidationSummary(input, source); err != nil {
		t.Fatalf("artifact-only field summary inferred one surface per document: %v", err)
	}
}

type sampleParseOutcomeFixture struct {
	rows   dependencySemanticRows
	source sourceContractSemanticState
	loaded loadedEvidence
}

func newSampleParseOutcomeFixture(t *testing.T, body []byte, mediaType, charset, decoderKind, parserKind, outcome, failureClass, failureStage string, includeShapes bool) *sampleParseOutcomeFixture {
	t.Helper()
	const sourceSymbol = "resource_fixture"
	const sourceRef = "fixture.sample"
	const sourceURL = "https://example.invalid/sample"
	manifestSHA := strings.Repeat("a", 64)
	bodySHA := sha256Hex(body)
	coordinateObject := map[string]interface{}{
		"source_content_sha256": bodySHA, "byte_start_offset": json.Number("0"), "byte_end_offset_exclusive": json.Number(intString(len(body))),
		"selected_range_byte_count": json.Number(intString(len(body))), "selected_range_sha256": bodySHA,
	}

	decoderProgram := map[string]interface{}{"kind": decoderKind}
	parserProgram := map[string]interface{}{"kind": parserKind}
	if parserKind == sampleParserKindJSONRFC8259 {
		parserProgram["duplicate_key_policy"] = "reject"
		parserProgram["trailing_content_policy"] = "reject"
		parserProgram["number_handling"] = "preserve_raw_lexeme"
	}
	decoderProfile := newExecutableSampleProfile(t, "decoder_profile", "fixture_decoder", decoderProgram)
	parserProfile := newExecutableSampleProfile(t, "parser_profile", "fixture_parser", parserProgram)
	profileID := "fixture_sample_parse_profile"
	profileVersion := "1"
	profileDefinition := map[string]interface{}{
		"parse_profile_id": profileID, "parse_profile_version": profileVersion,
		"source_representation_media_type": mediaType, "transport_charset": charset,
		"decoder_profile": decoderProfile, "parser_profile": parserProfile,
	}
	canonicalProfile := canonicalSampleProfileJSON(t, profileDefinition)
	profileSHA := sha256Hex([]byte(canonicalProfile))
	profileReference := map[string]interface{}{"parse_profile_id": profileID, "parse_profile_version": profileVersion, "parse_profile_sha256": profileSHA}
	profileRow := dependencySemanticRow{line: 2, kind: "sample_parse_profile", data: map[string]interface{}{
		"row_kind": "sample_parse_profile", "parse_profile_id": profileID, "parse_profile_version": profileVersion, "parse_profile_sha256": profileSHA, "canonical_profile_json": canonicalProfile,
	}}

	failureValue := interface{}(nil)
	if failureClass != "" {
		failureValue = map[string]interface{}{
			"failure_class": failureClass, "failure_stage": failureStage,
			"parse_profile_id": profileID, "parse_profile_version": profileVersion, "parse_profile_sha256": profileSHA,
		}
	}
	blockRow := dependencySemanticRow{line: 3, kind: "sample_json_block", data: map[string]interface{}{
		"row_kind": "sample_json_block", "source_symbol": sourceSymbol, "surface_kind": "resource", "source_ref": sourceRef, "source_url": sourceURL,
		"document_content_sha256": bodySHA, "block_content_sha256": bodySHA, "block_content_bytes": json.Number(intString(len(body))), "section_path": []interface{}{"Fixture", "Sample"},
		"parse_outcome": outcome, "parse_profile_binding": profileReference, "parse_failure": failureValue, "evidence_hydration_coordinate": coordinateObject,
	}}
	summaryRow := dependencySemanticRow{line: 10, kind: "validation_summary", data: map[string]interface{}{
		"row_kind": "validation_summary", "expected_source_documents": json.Number("1"), "sample_json_block_count": json.Number("1"), "sample_parse_profile_count": json.Number("1"),
		"parsed_sample_json_block_count": json.Number(boolIntString(outcome == sampleParseOutcomeParsed)), "unparsed_sample_json_block_count": json.Number(boolIntString(outcome != sampleParseOutcomeParsed)),
		"failed_sample_json_block_count": json.Number(boolIntString(outcome == sampleParseOutcomeFailed)), "unsupported_sample_json_block_count": json.Number(boolIntString(outcome == sampleParseOutcomeUnsupported)),
		"not_applicable_sample_json_block_count": json.Number(boolIntString(outcome == sampleParseOutcomeNotApplicable)), "sample_json_shape_row_count": json.Number("0"),
		"exact_evidence_locator_binding_count": json.Number("1"), "raw_numeric_lexemes_preserved": true, "source_examples_treated_as_schema": false,
	}}

	evidenceCoordinate := evidenceSourceCoordinate{Ref: sourceRef, URL: sourceURL}
	locator := evidenceLocator{
		EvidenceManifestSHA256: manifestSHA, SourceContentSHA256: bodySHA, ByteStartOffset: 0, ByteEndOffsetExclusive: int64(len(body)), SelectedRangeByteCount: int64(len(body)), SelectedRangeSHA256: bodySHA,
		SourceRefs: []string{sourceRef}, SourceURLs: []string{sourceURL}, LocatorSemantics: exactLocatorSemantics,
	}
	fixture := &sampleParseOutcomeFixture{
		rows: dependencySemanticRows{path: "sample.jsonl", byKind: map[string][]dependencySemanticRow{
			"sample_parse_profile": {profileRow}, "sample_json_block": {blockRow}, "validation_summary": {summaryRow},
		}},
		source: sourceContractSemanticState{
			documentsByIdentity:     map[evidenceBodyIdentity]dependencySemanticRow{{ManifestSHA256: manifestSHA, SourceRef: sourceRef, ContentSHA256: bodySHA}: {}},
			classificationsBySymbol: map[string][]sourceClassificationOccurrence{sourceSymbol: {{SourceSymbol: sourceSymbol, SurfaceKind: "resource", Locator: locator}}},
			resourceSymbols:         map[string]struct{}{sourceSymbol: {}},
		},
		loaded: loadedEvidence{Bodies: map[string]exactEvidenceBody{bodySHA: {Bytes: body, Coordinates: map[evidenceSourceCoordinate]string{evidenceCoordinate: manifestSHA}}}},
	}
	if includeShapes {
		fixture.addShape("", []interface{}{"object"}, nil, nil)
		fixture.addShape("/amount", []interface{}{"number"}, []interface{}{"12.34"}, nil)
		fixture.addShape("/label", []interface{}{"string"}, nil, []interface{}{"text"})
		fixture.summary().data["sample_json_shape_row_count"] = json.Number("3")
		fixture.summary().data["exact_evidence_locator_binding_count"] = json.Number("4")
	}
	return fixture
}

func (fixture *sampleParseOutcomeFixture) addShape(pointer string, kinds, lexemes, stringClasses []interface{}) {
	block := fixture.rows.byKind["sample_json_block"][0]
	row := dependencySemanticRow{line: 4 + len(fixture.rows.byKind["sample_json_shape"]), kind: "sample_json_shape", data: map[string]interface{}{
		"row_kind": "sample_json_shape", "source_symbol": block.data["source_symbol"], "surface_kind": block.data["surface_kind"], "source_ref": block.data["source_ref"], "source_url": block.data["source_url"], "block_content_sha256": block.data["block_content_sha256"],
		"normalized_json_pointer": pointer, "observed_kinds": kinds, "occurrences": json.Number("1"), "observed_raw_number_lexemes": lexemes, "observed_string_classes": stringClasses,
		"schema_authority": "sample_only_not_schema", "binary_float_authoritative": false, "evidence_hydration_coordinate": block.data["evidence_hydration_coordinate"],
	}}
	fixture.rows.byKind["sample_json_shape"] = append(fixture.rows.byKind["sample_json_shape"], row)
}

func (fixture *sampleParseOutcomeFixture) summary() *dependencySemanticRow {
	return &fixture.rows.byKind["validation_summary"][0]
}

func (fixture *sampleParseOutcomeFixture) validate() error {
	return validateSampleShapeSemanticRows(fixture.rows, fixture.source, fixture.loaded)
}

func newExecutableSampleProfile(t *testing.T, prefix, id string, program map[string]interface{}) map[string]interface{} {
	t.Helper()
	version := "1"
	preimage := map[string]interface{}{prefix + "_id": id, prefix + "_version": version, "program": program}
	digest := sha256Hex([]byte(canonicalSampleProfileJSON(t, preimage)))
	result := map[string]interface{}{prefix + "_id": id, prefix + "_version": version, prefix + "_sha256": digest, "program": program}
	return result
}

func canonicalSampleProfileJSON(t *testing.T, value interface{}) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

func writeParseOutcomeJSONL(t *testing.T, path string, rows []map[string]interface{}) {
	t.Helper()
	var raw []byte
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, encoded...)
		raw = append(raw, '\n')
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func intString(value int) string {
	return strconv.Itoa(value)
}

func boolIntString(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
