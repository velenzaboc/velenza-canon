package providerplan

import (
	"strings"
	"testing"
)

func TestExactValueClassifierPredicateGrammarBoundaries(t *testing.T) {
	invalid := []struct {
		name string
		raw  map[string]interface{}
		want string
	}{
		{"missing identity", map[string]interface{}{}, "absent"},
		{"unregistered pointer", map[string]interface{}{"predicate_kind": exactValuePredicateStringEquals, "input_json_pointer": "/numeric_disposition", "expected_string": "Decimal"}, "outside"},
		{"extra equality field", map[string]interface{}{"predicate_kind": exactValuePredicateStringEquals, "input_json_pointer": "/provider_type", "expected_string": "Decimal", "ignored": true}, "fields"},
		{"empty equality value", map[string]interface{}{"predicate_kind": exactValuePredicateStringEquals, "input_json_pointer": "/provider_type", "expected_string": ""}, "noncanonical"},
		{"extra membership field", map[string]interface{}{"predicate_kind": exactValuePredicateStringIn, "input_json_pointer": "/provider_type", "expected_strings": []interface{}{"Decimal"}, "ignored": true}, "fields"},
		{"duplicate membership value", map[string]interface{}{"predicate_kind": exactValuePredicateStringIn, "input_json_pointer": "/provider_type", "expected_strings": []interface{}{"Decimal", "Decimal"}}, "canonical sorted set"},
		{"unknown predicate", map[string]interface{}{"predicate_kind": "contains", "input_json_pointer": "/provider_type"}, "closed executable grammar"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseExactValueClassifierPredicate(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parse error = %v, want %q", err, tc.want)
			}
		})
	}
	predicate, err := parseExactValueClassifierPredicate(map[string]interface{}{
		"predicate_kind": exactValuePredicateStringIn, "input_json_pointer": "/provider_type",
		"expected_strings": []interface{}{"Decimal", "Integer"},
	})
	if err != nil || predicate.kind != exactValuePredicateStringIn || len(predicate.expectedStrings) != 2 {
		t.Fatalf("valid membership predicate = %#v, %v", predicate, err)
	}
}

func TestExactValueClassifierOutputGrammarBoundaries(t *testing.T) {
	valid := map[string]interface{}{
		"numeric_semantics": "exact_decimal", "authoritative_carrier": "source_lexeme", "computation_path": "unresolved_fail_closed_gap",
	}
	withExtra := cloneSemanticMap(valid)
	withExtra["ignored"] = true
	if _, err := parseExactValueClassifierOutput(withExtra); err == nil {
		t.Fatal("output with an extra field was accepted")
	}
	missing := cloneSemanticMap(valid)
	delete(missing, "authoritative_carrier")
	if _, err := parseExactValueClassifierOutput(missing); err == nil {
		t.Fatal("incomplete output tuple was accepted")
	}
	invalid := cloneSemanticMap(valid)
	invalid["authoritative_carrier"] = "not_applicable"
	if _, err := parseExactValueClassifierOutput(invalid); err == nil {
		t.Fatal("inconsistent numeric disposition was accepted")
	}
	output, err := parseExactValueClassifierOutput(valid)
	if err != nil || output.numericSemantics != "exact_decimal" || output.authoritativeCarrier != "source_lexeme" {
		t.Fatalf("valid output = %#v, %v", output, err)
	}
}

func TestExactValueClassifierSchemaBranchBoundaries(t *testing.T) {
	if _, err := exactValueClassifierSchemaObjectBranches("not-an-object", nil, "$", map[string]bool{}); err == nil {
		t.Fatal("non-object schema node was accepted")
	}
	nonStringRef := map[string]interface{}{"$ref": true}
	if _, err := exactValueClassifierSchemaObjectBranches(nonStringRef, nonStringRef, "$", map[string]bool{}); err == nil {
		t.Fatal("non-string schema reference was accepted")
	}
	missingRef := map[string]interface{}{"$ref": "#/$defs/missing"}
	if _, err := exactValueClassifierSchemaObjectBranches(missingRef, missingRef, "$", map[string]bool{}); err == nil {
		t.Fatal("unresolved schema reference was accepted")
	}
	cycle := map[string]interface{}{
		"$ref": "#/$defs/loop",
		"$defs": map[string]interface{}{
			"loop": map[string]interface{}{"$ref": "#/$defs/loop"},
		},
	}
	if _, err := exactValueClassifierSchemaObjectBranches(cycle, cycle, "$", map[string]bool{}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("schema cycle error = %v", err)
	}
	closed := map[string]interface{}{
		"$ref": "#/$defs/closed",
		"$defs": map[string]interface{}{
			"closed": map[string]interface{}{"properties": map[string]interface{}{"provider_type": map[string]interface{}{"type": "string"}}},
		},
	}
	branches, err := exactValueClassifierSchemaObjectBranches(closed, closed, "$", map[string]bool{})
	if err != nil || len(branches) != 1 {
		t.Fatalf("closed referenced schema branches = %#v, %v", branches, err)
	}
	leaf := map[string]interface{}{"properties": map[string]interface{}{"provider_type": map[string]interface{}{"type": "string"}}}
	mixed := map[string]interface{}{"oneOf": []interface{}{leaf}, "anyOf": []interface{}{leaf}}
	if _, err := exactValueClassifierSchemaObjectBranches(mixed, mixed, "$", map[string]bool{}); err == nil {
		t.Fatal("mixed oneOf/anyOf schema was accepted")
	}
	empty := map[string]interface{}{"oneOf": []interface{}{}}
	if _, err := exactValueClassifierSchemaObjectBranches(empty, empty, "$", map[string]bool{}); err == nil {
		t.Fatal("empty oneOf schema was accepted")
	}
	allOf := map[string]interface{}{"allOf": []interface{}{leaf}}
	if _, err := exactValueClassifierSchemaObjectBranches(allOf, allOf, "$", map[string]bool{}); err == nil {
		t.Fatal("ambiguous allOf schema was accepted")
	}
	badBranch := map[string]interface{}{"oneOf": []interface{}{leaf, "not-an-object"}}
	if _, err := exactValueClassifierSchemaObjectBranches(badBranch, badBranch, "$", map[string]bool{}); err == nil {
		t.Fatal("non-object composition branch was accepted")
	}
	if _, err := exactValueClassifierSchemaObjectBranches(map[string]interface{}{}, map[string]interface{}{}, "$", map[string]bool{}); err == nil {
		t.Fatal("schema branch without properties was accepted")
	}
}

func TestExactValueClassifierProjectionAndExecutionBoundaries(t *testing.T) {
	claim := map[string]interface{}{"provider_type": "Decimal", "nested": map[string]interface{}{"value": true}}
	for name, pointers := range map[string][]string{
		"invalid pointer":  {"provider_type"},
		"missing value":    {"/missing"},
		"non-string value": {"/nested/value"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := canonicalExactValueClassifierInputProjection(pointers, claim); err == nil {
				t.Fatal("invalid classifier projection was accepted")
			}
		})
	}

	fact, validation := exactValueClassifierFactAndSchemaFixture(t)
	if _, err := executeExactValueClassifier(exactValueClassifierProgram{}, fact, validation); err == nil {
		t.Fatal("classifier with a mismatched validation authority was executed")
	}
	matchedProgram := exactValueClassifierProgram{
		inputClaimKind: validation.claimKind, inputValidationSchema: validation.authority.reference,
		inputProjectionPointers: []string{"/provider_type"},
		rules: []exactValueClassifierRule{{
			ruleID:     "membership_rule",
			predicates: []exactValueClassifierPredicate{{kind: exactValuePredicateStringIn, inputPointer: "/provider_type", expectedStrings: map[string]struct{}{"Decimal": {}}}},
			output:     exactValueClassifierOutput{numericSemantics: "exact_decimal", authoritativeCarrier: "source_lexeme", computationPath: "unresolved_fail_closed_gap"},
		}},
	}
	execution, err := executeExactValueClassifier(matchedProgram, fact, validation)
	if err != nil || execution.ruleID != "membership_rule" {
		t.Fatalf("membership execution = %#v, %v", execution, err)
	}
	badPointerProgram := matchedProgram
	badPointerProgram.inputProjectionPointers = []string{"not-a-pointer"}
	if _, err := executeExactValueClassifier(badPointerProgram, fact, validation); err == nil {
		t.Fatal("classifier with an invalid projection pointer was executed")
	}
	unsupportedProgram := matchedProgram
	unsupportedProgram.rules = []exactValueClassifierRule{{
		ruleID: "unsupported_rule", predicates: []exactValueClassifierPredicate{{kind: "unknown", inputPointer: "/provider_type"}},
	}}
	if _, err := executeExactValueClassifier(unsupportedProgram, fact, validation); err == nil {
		t.Fatal("classifier with an unsupported compiled predicate was executed")
	}
}
