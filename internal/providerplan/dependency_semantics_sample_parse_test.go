package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDependencySemanticsSampleParseProgramsFailClosed(t *testing.T) {
	jsonDecoder := map[string]interface{}{"kind": sampleDecoderKindUTF8Strict}
	jsonParser := map[string]interface{}{
		"kind": sampleParserKindJSONRFC8259, "duplicate_key_policy": "reject",
		"trailing_content_policy": "reject", "number_handling": "preserve_raw_lexeme",
	}
	if err := validateSampleParseProgram(jsonDecoder, jsonParser, "application/problem+json", "utf-8"); err != nil {
		t.Fatalf("valid JSON parser program: %v", err)
	}
	badNumberPolicy := cloneSemanticObjectForTest(t, jsonParser)
	badNumberPolicy["number_handling"] = "float64"
	if err := validateSampleParseProgram(jsonDecoder, badNumberPolicy, "application/json", "utf-8"); err == nil || !strings.Contains(err.Error(), "raw-number") {
		t.Fatalf("number policy error=%v", err)
	}
	if err := validateSampleParseProgram(map[string]interface{}{"kind": sampleDecoderKindNone}, map[string]interface{}{"kind": sampleParserKindUnsupported}, "text/csv", "utf-8"); err != nil {
		t.Fatalf("valid unsupported parser profile: %v", err)
	}
	if err := validateSampleParseProgram(map[string]interface{}{"kind": sampleDecoderKindNone}, map[string]interface{}{"kind": sampleParserKindUnsupported}, "application/json", "utf-8"); err == nil || !strings.Contains(err.Error(), "supported JSON") {
		t.Fatalf("unsupported JSON parser error=%v", err)
	}
	if err := validateSampleParseProgram(map[string]interface{}{"kind": sampleDecoderKindNone}, map[string]interface{}{"kind": sampleParserKindNotApplicable}, "text/plain", "us-ascii"); err != nil {
		t.Fatalf("valid not-applicable parser profile: %v", err)
	}
	if err := validateSampleParseProgram(map[string]interface{}{"kind": "invented"}, map[string]interface{}{"kind": sampleParserKindNotApplicable}, "text/plain", "us-ascii"); err == nil || !strings.Contains(err.Error(), "unsupported decoder") {
		t.Fatalf("invented decoder error=%v", err)
	}
}

func TestDependencySemanticsSampleParseExecutionIsTypedAndDeterministic(t *testing.T) {
	reference := dependencyProfileReference{id: "parse_profile", version: "v1", digest: strings.Repeat("a", 64)}
	jsonProfile := sampleParseProfile{reference: reference, mediaType: "application/json", transportCharset: "utf-8", decoderKind: sampleDecoderKindUTF8Strict, parserKind: sampleParserKindJSONRFC8259}
	cases := []struct {
		name, input, outcome, class, stage string
	}{
		{"parsed", `{"amount":12.30,"name":"paid"}`, sampleParseOutcomeParsed, "", ""},
		{"invalid UTF-8", string([]byte{0xff}), sampleParseOutcomeFailed, "invalid_charset_sequence", "decoder"},
		{"duplicate key", `{"amount":1,"amount":2}`, sampleParseOutcomeFailed, "duplicate_json_key", "parser"},
		{"trailing", `{"amount":1} {}`, sampleParseOutcomeFailed, "trailing_json_content", "parser"},
		{"malformed", `{"amount":`, sampleParseOutcomeFailed, "malformed_json", "parser"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			outcome, failure, parsed := executeSampleParseProfile(jsonProfile, []byte(test.input))
			if outcome != test.outcome {
				t.Fatalf("outcome=%q want %q", outcome, test.outcome)
			}
			if test.class == "" {
				value, ok := parsed.(map[string]interface{})
				if failure != nil || !ok || value["amount"] != json.Number("12.30") {
					t.Fatalf("parsed=%#v failure=%#v; raw numeric lexeme was not preserved", parsed, failure)
				}
				return
			}
			if parsed != nil || failure == nil || failure.class != test.class || failure.stage != test.stage || failure.profile != reference {
				t.Fatalf("parsed=%#v failure=%#v", parsed, failure)
			}
		})
	}
	unsupported := sampleParseProfile{reference: reference, mediaType: "application/json", transportCharset: "iso-8859-1", parserKind: sampleParserKindUnsupported}
	if outcome, failure, parsed := executeSampleParseProfile(unsupported, []byte("{}")); outcome != sampleParseOutcomeUnsupported || parsed != nil || failure == nil || failure.class != "unsupported_charset" || failure.stage != "decoder" {
		t.Fatalf("unsupported JSON charset outcome=%q failure=%#v parsed=%#v", outcome, failure, parsed)
	}
	if outcome, failure, parsed := executeSampleParseProfile(sampleParseProfile{reference: reference, parserKind: sampleParserKindNotApplicable}, []byte("ignored")); outcome != sampleParseOutcomeNotApplicable || failure != nil || parsed != nil {
		t.Fatalf("not-applicable outcome=%q failure=%#v parsed=%#v", outcome, failure, parsed)
	}
	if outcome, failure, _ := executeSampleParseProfile(sampleParseProfile{reference: reference, parserKind: "invented"}, []byte("{}")); outcome != sampleParseOutcomeFailed || failure == nil || failure.class != "invalid_parse_profile" {
		t.Fatalf("invented profile outcome=%q failure=%#v", outcome, failure)
	}
}

func TestDependencySemanticsParseProfileAndFailureBindingsAreExact(t *testing.T) {
	decoderProgram := map[string]interface{}{"kind": sampleDecoderKindUTF8Strict}
	decoder := sampleExecutableProfileForTest(t, "decoder_profile", "decoder", "v1", decoderProgram)
	reference, program, err := parseSampleExecutableProfile(decoder, "decoder_profile")
	if err != nil || reference.id != "decoder" || program["kind"] != sampleDecoderKindUTF8Strict {
		t.Fatalf("parse executable profile reference=%#v program=%#v err=%v", reference, program, err)
	}
	tampered := cloneSemanticObjectForTest(t, decoder)
	tampered["program"].(map[string]interface{})["kind"] = sampleDecoderKindNone
	if _, _, err := parseSampleExecutableProfile(tampered, "decoder_profile"); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered executable profile error=%v", err)
	}

	rows := dependencySemanticRows{path: "fixture.jsonl"}
	row := dependencySemanticRow{line: 7, data: map[string]interface{}{}}
	if err := validateSampleParseFailure(rows, row, nil, reference); err == nil || !strings.Contains(err.Error(), "omits") {
		t.Fatalf("missing failure arm error=%v", err)
	}
	row.data["parse_failure"] = nil
	if err := validateSampleParseFailure(rows, row, nil, reference); err != nil {
		t.Fatalf("nil success failure arm: %v", err)
	}
	expected := &sampleParseFailure{class: "malformed_json", stage: "parser", profile: reference}
	row.data["parse_failure"] = map[string]interface{}{
		"failure_class": expected.class, "failure_stage": expected.stage,
		"parse_profile_id": reference.id, "parse_profile_version": reference.version, "parse_profile_sha256": reference.digest,
	}
	if err := validateSampleParseFailure(rows, row, expected, reference); err != nil {
		t.Fatalf("exact typed failure: %v", err)
	}
	row.data["parse_failure"].(map[string]interface{})["failure_stage"] = "decoder"
	if err := validateSampleParseFailure(rows, row, expected, reference); err == nil || !strings.Contains(err.Error(), "does not equal") {
		t.Fatalf("tampered typed failure error=%v", err)
	}
}

func TestDependencySemanticsParseProfileRowsBindCanonicalPrograms(t *testing.T) {
	decoder := sampleExecutableProfileForTest(t, "decoder_profile", "decoder", "v1", map[string]interface{}{"kind": sampleDecoderKindUTF8Strict})
	parser := sampleExecutableProfileForTest(t, "parser_profile", "parser", "v1", map[string]interface{}{
		"kind": sampleParserKindJSONRFC8259, "duplicate_key_policy": "reject",
		"trailing_content_policy": "reject", "number_handling": "preserve_raw_lexeme",
	})
	definition := map[string]interface{}{
		"parse_profile_id": "profile", "parse_profile_version": "v1",
		"source_representation_media_type": "application/json", "transport_charset": "utf-8",
		"decoder_profile": decoder, "parser_profile": parser,
	}
	raw, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	canonicalProfile := string(canonical)
	profileRow := dependencySemanticRow{line: 3, data: map[string]interface{}{
		"parse_profile_id": "profile", "parse_profile_version": "v1", "parse_profile_sha256": sha256Hex(canonical), "canonical_profile_json": canonicalProfile,
	}}
	rows := dependencySemanticRows{path: "sample-shape.jsonl", byKind: map[string][]dependencySemanticRow{"sample_parse_profile": {profileRow}}}
	profiles, err := parseSampleParseProfiles(rows)
	if err != nil || len(profiles) != 1 {
		t.Fatalf("parsed profiles=%#v err=%v", profiles, err)
	}
	profile, err := resolveSampleParseProfile(rows, dependencySemanticRow{line: 4, data: map[string]interface{}{"parse_profile_binding": map[string]interface{}{
		"parse_profile_id": "profile", "parse_profile_version": "v1", "parse_profile_sha256": sha256Hex(canonical),
	}}}, profiles)
	if err != nil || profile.parserKind != sampleParserKindJSONRFC8259 || profile.decoderKind != sampleDecoderKindUTF8Strict {
		t.Fatalf("resolved profile=%#v err=%v", profile, err)
	}
	if _, err := resolveSampleParseProfile(rows, dependencySemanticRow{line: 5, data: map[string]interface{}{}}, profiles); err == nil || !strings.Contains(err.Error(), "no parse_profile_binding") {
		t.Fatalf("missing parse binding error=%v", err)
	}
	tamperedRows := rows
	tamperedRows.byKind = map[string][]dependencySemanticRow{"sample_parse_profile": {profileRow}}
	tamperedRows.byKind["sample_parse_profile"][0].data = cloneSemanticObjectForTest(t, profileRow.data)
	tamperedRows.byKind["sample_parse_profile"][0].data["canonical_profile_json"] = strings.Replace(canonicalProfile, "application/json", "Application/json", 1)
	if _, err := parseSampleParseProfiles(tamperedRows); err == nil || !strings.Contains(err.Error(), "exact canonical bytes") {
		t.Fatalf("tampered canonical profile error=%v", err)
	}
	noProfiles := dependencySemanticRows{path: "sample-shape.jsonl", byKind: map[string][]dependencySemanticRow{"sample_json_block": {{line: 1}}}}
	if _, err := parseSampleParseProfiles(noProfiles); err == nil || !strings.Contains(err.Error(), "no exact sample_parse_profile") {
		t.Fatalf("missing profile roster error=%v", err)
	}
}

func TestDependencySemanticsSampleOutcomeRosterIsClosed(t *testing.T) {
	input := artifactInput{Path: "sample-shape.jsonl", RowsByKind: map[string][]map[string]interface{}{"sample_json_block": {
		{"parse_outcome": sampleParseOutcomeParsed}, {"parse_outcome": sampleParseOutcomeParsed}, {"parse_outcome": sampleParseOutcomeFailed},
	}}}
	counts, err := sampleParseOutcomeCountsFromArtifact(input)
	if err != nil || counts[sampleParseOutcomeParsed] != 2 || counts[sampleParseOutcomeFailed] != 1 || counts[sampleParseOutcomeUnsupported] != 0 {
		t.Fatalf("outcome counts=%#v err=%v", counts, err)
	}
	input.RowsByKind["sample_json_block"][1] = map[string]interface{}{"parse_outcome": "invented"}
	if _, err := sampleParseOutcomeCountsFromArtifact(input); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("invented outcome error=%v", err)
	}
	input.RowsByKind["sample_json_block"][1] = map[string]interface{}{}
	if _, err := sampleParseOutcomeCountsFromArtifact(input); err == nil || !strings.Contains(err.Error(), "no parse_outcome") {
		t.Fatalf("missing outcome error=%v", err)
	}
}

func TestDependencySemanticsComputedShapesAndCoordinatesPreserveExactForms(t *testing.T) {
	shapes := map[string]computedSampleShape{}
	accumulateComputedSampleShapes(shapes, "", map[string]interface{}{"a/b~c": []interface{}{json.Number("12.30"), nil, true, "text"}})
	if _, ok := shapes["/a~1b~0c/*"]; !ok || shapes["/a~1b~0c/*"].occurrences != 4 || len(shapes["/a~1b~0c/*"].kinds) != 4 {
		t.Fatalf("array shape=%#v", shapes["/a~1b~0c/*"])
	}
	if got := shapes["/a~1b~0c/*"].numberLexemes; len(got) != 1 {
		t.Fatalf("numeric lexemes=%#v", got)
	}
	if escapeJSONPointerSegment("a/b~c") != "a~1b~0c" || len(expectedShapePointerSet(shapes)) != len(shapes) {
		t.Fatal("JSON pointer escaping or exact pointer roster changed")
	}
	coordinate := dependencyHydrationCoordinate{digest: strings.Repeat("a", 64), start: 1, end: 4, count: 3, rangeSHA: strings.Repeat("b", 64)}
	first := coordinateIdentity(coordinate)
	coordinate.count = 2
	if coordinateIdentity(coordinate) == first || sampleBlockIdentity("source", "block", coordinate) == "" {
		t.Fatal("exact hydration coordinate identity ignored an asserted field")
	}
	if value, ok := semanticJSONInt64(json.Number("42")); !ok || value != 42 {
		t.Fatalf("JSON integral number=%d ok=%v", value, ok)
	}
	if _, ok := semanticJSONInt64(json.Number("4.2")); ok {
		t.Fatal("fractional JSON number was accepted as an exact integer")
	}
}

func sampleExecutableProfileForTest(t *testing.T, prefix, id, version string, program map[string]interface{}) map[string]interface{} {
	t.Helper()
	preimage := map[string]interface{}{prefix + "_id": id, prefix + "_version": version, "program": program}
	raw, err := json.Marshal(preimage)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]interface{}{prefix + "_id": id, prefix + "_version": version, prefix + "_sha256": sha256Hex(canonical), "program": program}
}
