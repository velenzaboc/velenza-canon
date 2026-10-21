package providerplan

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestExactDocumentationDerivationProgramReexecutesStableFacts(t *testing.T) {
	body := []byte("# Fixture\r\n\r\n| Field | Type | Required |\r\n| --- | --- | --- |\r\n| amount | Decimal | Required |\r\n| memo | String | Optional |\r\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 2, 2)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	first, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	second, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("fact counts = %d/%d, want 2/2", len(first), len(second))
	}
	if first[0].FactID != second[0].FactID || first[1].FactID != second[1].FactID || exactDocumentationFactRoot(first) != exactDocumentationFactRoot(second) {
		t.Fatalf("repeated exact derivation changed identity or root")
	}
	observed := map[string]string{}
	for _, fact := range first {
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			t.Fatal(err)
		}
		field, _ := output["field_name"].(string)
		requirement, _ := output["provider_requirement"].(string)
		observed[field] = requirement
		if fact.ByteEndOffsetExclusive <= fact.ByteStartOffset || fact.SelectedMatchSHA256 == "" || fact.EvidenceLocatorID == "" || fact.PredecessorLocatorID == "" {
			t.Fatalf("fact %s has incomplete exact match provenance", fact.FactID)
		}
		if fact.EvidenceLocator.ID != fact.EvidenceLocatorID || fact.EvidenceLocator.ByteStartOffset != fact.ByteStartOffset || fact.EvidenceLocator.ByteEndOffsetExclusive != fact.ByteEndOffsetExclusive || fact.EvidenceLocator.SelectedRangeSHA256 != fact.SelectedMatchSHA256 {
			t.Fatalf("fact %s claim locator does not exactly bind the derived match", fact.FactID)
		}
	}
	if observed["amount"] != "Required" || observed["memo"] != "Optional" {
		t.Fatalf("derived fields = %#v", observed)
	}
}

func TestExactDocumentationDerivationProgramRejectsProfileDigestMismatch(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, _, _ := exactDocumentationProgramFixture(t, body, 1, 1)
	reference.digest = strings.Repeat("0", 64)
	if _, err := parseExactDocumentationDerivationProgram(raw, reference); err == nil || !strings.Contains(err.Error(), "executable program bytes") {
		t.Fatalf("error = %v, want exact program-digest refusal", err)
	}
}

func TestExactDocumentationDerivationProgramRejectsFactOmission(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n| memo | String | Optional |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 3, 3)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "outside [3,3]") {
		t.Fatalf("error = %v, want per-occurrence totality refusal", err)
	}
}

func TestExactDocumentationDerivationProgramRejectsChangedPredecessorCoordinate(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	for sourceSymbol, occurrences := range proof.classificationsBySourceSymbol {
		occurrences[0].Locator.SelectedRangeSHA256 = strings.Repeat("f", 64)
		occurrences[0].Locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(occurrences[0].Locator))
		proof.classificationsBySourceSymbol[sourceSymbol] = occurrences
	}
	if _, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "sealed exact identity") {
		t.Fatalf("error = %v, want sealed predecessor-coordinate refusal", err)
	}
}

func TestExactDocumentationDerivationProgramRejectsMixedMalformedTemplate(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, _, _ := exactDocumentationProgramFixture(t, body, 1, 1)
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	rule := object["ordered_rules"].([]interface{})[0].(map[string]interface{})
	outputs := rule["output_fields"].(map[string]interface{})
	outputs["field_name"] = "${field_name}-${unterminated"
	mutated, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	if _, err := parseExactDocumentationDerivationProgram(canonical, reference); err == nil || !strings.Contains(err.Error(), "malformed capture template") {
		t.Fatalf("error = %v, want mixed malformed-template refusal", err)
	}
}

func TestExactDocumentationDerivationProgramRevalidatesMutatedProgram(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	program.OrderedRules[0].Pattern = "("
	if _, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies); err == nil || !strings.Contains(err.Error(), "executable program bytes") {
		t.Fatalf("error = %v, want mutated-program digest refusal", err)
	}
}

func TestExactDocumentationDerivationProgramRejectsResourceBoundViolations(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	tests := []struct {
		name          string
		wantSubstring string
		mutate        func(map[string]interface{})
	}{
		{name: "pattern bytes", wantSubstring: "closed", mutate: func(rule map[string]interface{}) {
			rule["pattern"] = strings.Repeat("a", maxDocumentationDerivationPatternBytes+1)
		}},
		{name: "template depth", wantSubstring: fmt.Sprintf("nesting depth %d", maxProviderJSONNestingDepth), mutate: func(rule map[string]interface{}) {
			var nested interface{} = "${field_name}"
			for depth := 0; depth <= maxDocumentationDerivationTemplateDepth; depth++ {
				nested = []interface{}{nested}
			}
			rule["output_fields"].(map[string]interface{})["field_name"] = nested
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, reference, _, _ := exactDocumentationProgramFixture(t, body, 1, 1)
			var object map[string]interface{}
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			test.mutate(object["ordered_rules"].([]interface{})[0].(map[string]interface{}))
			mutated, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalizeCandidateJSON(mutated)
			if err != nil {
				if !strings.Contains(err.Error(), test.wantSubstring) {
					t.Fatalf("canonicalization error = %v, want %q resource-bound refusal", err, test.wantSubstring)
				}
				return
			}
			reference.digest = sha256Hex(canonical)
			if _, err := parseExactDocumentationDerivationProgram(canonical, reference); err == nil || !strings.Contains(err.Error(), test.wantSubstring) {
				t.Fatalf("error = %v, want %q resource-bound refusal", err, test.wantSubstring)
			}
		})
	}
}

func TestExactDocumentationDerivationProgramPreservesCapturedTemplateLikeBytes(t *testing.T) {
	body := []byte("| ${literal} | Decimal | Required |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	rule := object["ordered_rules"].([]interface{})[0].(map[string]interface{})
	rule["pattern"] = `(?m)^\| (?P<field_name>[^|\r\n]{1,64}) \| (?P<provider_type>[A-Za-z]{1,64}) \| (?P<provider_requirement>Required|Optional) \|\r?$`
	mutated, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 {
		t.Fatalf("fact count = %d, want 1", len(facts))
	}
	output, decodeErr := decodeExactDocumentationFactOutputFields(facts[0])
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	if output["field_name"] != "${literal}" {
		t.Fatalf("captured template-like bytes were not preserved exactly: %#v", facts)
	}
}

func TestExactDocumentationDerivationProgramRejectsUnusedOrUnknownCaptures(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, _, _ := exactDocumentationProgramFixture(t, body, 1, 1)
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	rules := object["ordered_rules"].([]interface{})
	rule := rules[0].(map[string]interface{})
	outputs := rule["output_fields"].(map[string]interface{})
	outputs["field_name"] = "${missing}"
	mutated, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	if _, err := parseExactDocumentationDerivationProgram(canonical, reference); err == nil || !strings.Contains(err.Error(), "unknown capture") {
		t.Fatalf("error = %v, want unknown-capture refusal", err)
	}
}

func TestExactDocumentationDerivationProgramValidatesTargetBindingCoordinates(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	tests := []struct {
		name      string
		kind      string
		pointer   string
		wantError string
	}{
		{name: "whole row", kind: exactDocumentationTargetWholeRow},
		{name: "escaped row member missing selectors", kind: exactDocumentationTargetRowMember, pointer: "/properties/a~1b~0c", wantError: "requires nonempty"},
		{name: "unknown kind", kind: "record", wantError: "closed structural set"},
		{name: "whole row with member", kind: exactDocumentationTargetWholeRow, pointer: "/properties/amount", wantError: "whole_row requires"},
		{name: "row member without pointer", kind: exactDocumentationTargetRowMember, wantError: "nonempty canonical RFC6901"},
		{name: "row member without leading slash", kind: exactDocumentationTargetRowMember, pointer: "properties/amount", wantError: "nonempty canonical RFC6901"},
		{name: "row member with empty token", kind: exactDocumentationTargetRowMember, pointer: "/", wantError: "empty property token"},
		{name: "row member with empty nested token", kind: exactDocumentationTargetRowMember, pointer: "/properties//amount", wantError: "empty property token"},
		{name: "row member with unknown escape", kind: exactDocumentationTargetRowMember, pointer: "/properties/a~2b", wantError: "noncanonical RFC6901 escape"},
		{name: "row member with trailing escape", kind: exactDocumentationTargetRowMember, pointer: "/properties/amount~", wantError: "noncanonical RFC6901 escape"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, reference, _, _ := exactDocumentationProgramFixture(t, body, 1, 1)
			var object map[string]interface{}
			if err := json.Unmarshal(raw, &object); err != nil {
				t.Fatal(err)
			}
			rule := object["ordered_rules"].([]interface{})[0].(map[string]interface{})
			rule["target_binding_kind"] = test.kind
			rule["target_member_json_pointer"] = test.pointer
			mutated, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalizeCandidateJSON(mutated)
			if err != nil {
				t.Fatal(err)
			}
			reference.digest = sha256Hex(canonical)
			_, err = parseExactDocumentationDerivationProgram(canonical, reference)
			if test.wantError == "" {
				if err != nil {
					t.Fatalf("parse target binding: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestExactDocumentationDerivedFactTargetBindingIsContentAddressed(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(facts) != 1 || facts[0].TargetBindingKind != exactDocumentationTargetWholeRow || facts[0].TargetMemberJSONPointer != "" {
		t.Fatalf("emitted target coordinate = %#v, want whole_row with an empty pointer", facts)
	}

	original := facts[0]
	mismatch := original
	mismatch.TargetMemberJSONPointer = "/properties/amount"
	if err := validateExactDocumentationDerivedFactTargetIdentity(mismatch); err == nil || !strings.Contains(err.Error(), "whole_row requires") {
		t.Fatalf("whole/member mismatch error = %v", err)
	}

	malformed := original
	malformed.TargetBindingKind = exactDocumentationTargetRowMember
	malformed.TargetMemberJSONPointer = "/properties/a~2b"
	if err := validateExactDocumentationDerivedFactTargetIdentity(malformed); err == nil || !strings.Contains(err.Error(), "noncanonical RFC6901 escape") {
		t.Fatalf("malformed pointer error = %v", err)
	}

	escapedMember := original
	escapedMember.TargetBindingKind = exactDocumentationTargetRowMember
	escapedMember.TargetMemberJSONPointer = "/properties/a~1b~0c"
	if err := validateExactDocumentationDerivedFactTargetIdentity(escapedMember); err == nil || !strings.Contains(err.Error(), "empty row selector") {
		t.Fatalf("unbound row-member target error = %v", err)
	}
}

func exactDocumentationProgramFixture(t *testing.T, body []byte, minimumMatches, maximumMatches int64) (json.RawMessage, dependencyProfileReference, sourceClassificationSelectionProof, map[string]exactEvidenceBody) {
	t.Helper()
	manifestSHA := sha256Hex([]byte("fixture manifest"))
	bodySHA := sha256Hex(body)
	locator := evidenceLocator{
		RowKind: "candidate_evidence_locator", EvidenceManifestSHA256: manifestSHA, SourceContentSHA256: bodySHA,
		ByteStartOffset: 0, ByteEndOffsetExclusive: int64(len(body)), SelectedRangeByteCount: int64(len(body)), SelectedRangeSHA256: bodySHA,
		SourceRefs: []string{"fixture.copy_all"}, SourceURLs: []string{"https://example.com/fixture"}, LocatorSemantics: exactLocatorSemantics,
	}
	locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
	classification := sourceClassificationOccurrence{
		Binding:      classificationArtifactBinding{ArtifactID: "fixture_classification", ArtifactVersion: "2", ArtifactSHA256: sha256Hex([]byte("fixture classification"))},
		SourceSymbol: "fixture_fields", SurfaceKind: "schema_element", Locator: locator,
	}
	proof := newSourceClassificationSelectionProof("fixture_provider", sha256Hex([]byte("fixture selection")), map[string][]sourceClassificationOccurrence{"fixture_fields": {classification}})
	programValue := map[string]interface{}{
		"program_kind":                           exactDocumentationDerivationProgramKind,
		"input_encoding":                         exactDocumentationDerivationEncodingUTF8,
		"max_parse_bytes":                        json.Number("512"),
		"max_output_bytes_per_fact":              json.Number("4096"),
		"max_output_facts_per_page":              json.Number("64"),
		"max_output_bytes_per_page":              json.Number("65536"),
		"max_output_facts_per_run":               json.Number("1024"),
		"max_output_bytes_per_run":               json.Number("1048576"),
		"max_output_pages_per_run":               json.Number("1024"),
		"max_matcher_evaluations_per_input_unit": json.Number("4096"),
		"max_matcher_evaluations_per_run":        json.Number("65536"),
		"max_matcher_input_bytes_per_input_unit": json.Number("4194304"),
		"max_matcher_input_bytes_per_run":        json.Number("67108864"),
		"max_occurrence_outcomes_per_run":        json.Number("1024"),
		"max_canonical_outcome_bytes_per_run":    json.Number("1048576"),
		"input_source_symbols":                   []interface{}{"fixture_fields"},
		"ordered_rules": []interface{}{map[string]interface{}{
			"ordinal": json.Number("0"), "rule_id": "extract_field_rows", "input_source_symbol": "fixture_fields",
			"target_artifact_role": "source_contract_index", "target_row_kind": "field_contract",
			"target_binding_kind": exactDocumentationTargetWholeRow, "target_member_json_pointer": "",
			"target_row_selector": []interface{}{}, "target_member_identity_json_pointers": []interface{}{},
			"pattern":                        `(?m)^\| (?P<field_name>[a-z_]{1,64}) \| (?P<provider_type>[A-Za-z]{1,64}) \| (?P<provider_requirement>Required|Optional) \|\r?$`,
			"maximum_match_bytes":            json.Number("512"),
			"minimum_matches_per_occurrence": json.Number(strconv.FormatInt(minimumMatches, 10)),
			"maximum_matches_per_occurrence": json.Number(strconv.FormatInt(maximumMatches, 10)),
			"output_fields":                  map[string]interface{}{"field_name": "${field_name}", "provider_requirement": "${provider_requirement}", "provider_type": "${provider_type}"},
			"exact_output_field_names":       []interface{}{"field_name", "provider_requirement", "provider_type"},
		}},
	}
	raw, err := json.Marshal(programValue)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	reference := dependencyProfileReference{id: "fixture_documentation_derivation", version: "1", digest: sha256Hex(canonical)}
	bodies := map[string]exactEvidenceBody{bodySHA: {Bytes: body, Coordinates: map[evidenceSourceCoordinate]string{{Ref: "fixture.copy_all", URL: "https://example.com/fixture"}: manifestSHA}}}
	return canonical, reference, proof, bodies
}
