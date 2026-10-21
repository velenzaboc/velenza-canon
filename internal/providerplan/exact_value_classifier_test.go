package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExactValueClassifierExecutesExactSchemaValidatedClaim(t *testing.T) {
	fact, validation := exactValueClassifierFactAndSchemaFixture(t)
	profile, reference := exactValueClassifierProfileFixture(t, validation)
	program, err := parseExactValueClassifierProgram(profile, reference, exactValueClassifierSchemaMap(validation))
	if err != nil {
		t.Fatal(err)
	}
	execution, err := executeExactValueClassifier(program, fact, validation)
	if err != nil {
		t.Fatal(err)
	}
	if execution.ruleID != "decimal_provider_type" || execution.output.numericSemantics != "exact_decimal" || execution.output.authoritativeCarrier != "source_lexeme" || execution.output.computationPath != "unresolved_fail_closed_gap" || !isLowerSHA256(execution.inputProjectionSHA256) {
		t.Fatalf("exact classifier execution = %#v", execution)
	}

	tampered := profile
	tampered.program = cloneSemanticMap(profile.program)
	tampered.program["numeric_lexeme_preserved"] = false
	if _, err := parseExactValueClassifierProgram(tampered, reference, exactValueClassifierSchemaMap(validation)); err == nil || !strings.Contains(err.Error(), "classifier_profile_sha256") {
		t.Fatalf("same-coordinate program substitution error = %v", err)
	}

	multiOutput := profile
	multiOutput.semanticClasses = map[string]struct{}{"exact_decimal": {}, "binary_float": {}}
	if _, err := parseExactValueClassifierProgram(multiOutput, reference, exactValueClassifierSchemaMap(validation)); err == nil || !strings.Contains(err.Error(), "closed unions") {
		t.Fatalf("non-executable output-union member error = %v", err)
	}
}

func TestExactValueClassifierFailsClosedOnZeroOrMultipleRules(t *testing.T) {
	fact, validation := exactValueClassifierFactAndSchemaFixture(t)
	profile, _ := exactValueClassifierProfileFixture(t, validation)

	for name, mutate := range map[string]func(map[string]interface{}){
		"zero": func(program map[string]interface{}) {
			predicate := program["ordered_rules"].([]interface{})[0].(map[string]interface{})["predicates"].([]interface{})[0].(map[string]interface{})
			predicate["expected_string"] = "Integer"
		},
		"multiple": func(program map[string]interface{}) {
			first := program["ordered_rules"].([]interface{})[0].(map[string]interface{})
			program["ordered_rules"] = append(program["ordered_rules"].([]interface{}), map[string]interface{}{
				"ordinal": json.Number("1"), "rule_id": "duplicate_decimal_match", "predicates": first["predicates"], "output": first["output"],
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := profile
			candidate.program = deepCloneSemanticMap(t, profile.program)
			mutate(candidate.program)
			canonical, err := canonicalOperationClassifierProgram(candidate.program)
			if err != nil {
				t.Fatal(err)
			}
			reference := dependencyProfileReference{id: "exact_value_fixture", version: "1", digest: sha256Hex(canonical)}
			program, err := parseExactValueClassifierProgram(candidate, reference, exactValueClassifierSchemaMap(validation))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := executeExactValueClassifier(program, fact, validation); err == nil || !strings.Contains(err.Error(), "want exactly one") {
				t.Fatalf("fail-closed match error = %v", err)
			}
		})
	}
}

func TestExactValueClassifierRejectsCircularOrIgnoredGrammar(t *testing.T) {
	_, validation := exactValueClassifierFactAndSchemaFixture(t)
	profile, _ := exactValueClassifierProfileFixture(t, validation)
	for name, test := range map[string]struct {
		mutate func(map[string]interface{})
		want   string
	}{
		"binary float": {
			mutate: func(program map[string]interface{}) { program["binary_float_authoritative"] = true },
			want:   "lexeme, or float contract",
		},
		"ignored field": {
			mutate: func(program map[string]interface{}) { program["ignored"] = false },
			want:   "fields",
		},
		"circular output pointer": {
			mutate: func(program map[string]interface{}) {
				program["input_projection_json_pointers"] = []interface{}{map[string]interface{}{"not": "a string"}}
			},
			want: "input",
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := profile
			candidate.program = deepCloneSemanticMap(t, profile.program)
			test.mutate(candidate.program)
			canonical, err := canonicalOperationClassifierProgram(candidate.program)
			if err != nil {
				t.Fatal(err)
			}
			reference := dependencyProfileReference{id: "exact_value_fixture", version: "1", digest: sha256Hex(canonical)}
			if _, err := parseExactValueClassifierProgram(candidate, reference, exactValueClassifierSchemaMap(validation)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("rehashed weakening error = %v, want %q", err, test.want)
			}
		})
	}
}

func exactValueClassifierProfileFixture(t *testing.T, validation documentationValidationSchema) (documentationClassifierProfile, dependencyProfileReference) {
	t.Helper()
	program := map[string]interface{}{
		"program_kind":     exactValueClassifierProgramKind,
		"input_claim_kind": "field_contract",
		"input_validation_schema_binding": map[string]interface{}{
			"validation_schema_id": validation.authority.reference.id, "validation_schema_version": validation.authority.reference.version,
			"validation_schema_sha256": validation.authority.reference.digest,
		},
		"input_projection_json_pointers": []interface{}{"/provider_type"},
		"match_semantics":                exactValueClassifierMatchExactlyOne,
		"ordered_rules": []interface{}{map[string]interface{}{
			"ordinal": json.Number("0"), "rule_id": "decimal_provider_type",
			"predicates": []interface{}{map[string]interface{}{
				"predicate_kind": exactValuePredicateStringEquals, "input_json_pointer": "/provider_type", "expected_string": "Decimal",
			}},
			"output": map[string]interface{}{
				"numeric_semantics": "exact_decimal", "authoritative_carrier": "source_lexeme", "computation_path": "unresolved_fail_closed_gap",
			},
		}},
		"terminal_default":           exactValueClassifierTerminalFailClosed,
		"numeric_lexeme_preserved":   true,
		"binary_float_authoritative": false,
	}
	canonical, err := canonicalOperationClassifierProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	reference := dependencyProfileReference{id: "exact_value_fixture", version: "1", digest: sha256Hex(canonical)}
	return documentationClassifierProfile{
		claimKind: "field_contract", semanticClasses: map[string]struct{}{"exact_decimal": {}},
		carriers: map[string]struct{}{"source_lexeme": {}}, computationPaths: map[string]struct{}{"unresolved_fail_closed_gap": {}}, program: program,
	}, reference
}

func exactValueClassifierFactAndSchemaFixture(t *testing.T) (exactDocumentationDerivedFact, documentationValidationSchema) {
	t.Helper()
	body := []byte("| amount | Decimal | Required |\n")
	raw, derivationReference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	program, err := parseExactDocumentationDerivationProgram(raw, derivationReference)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := executeExactDocumentationDerivationProgram(derivationReference, program, proof, bodies)
	if err != nil || len(facts) != 1 {
		t.Fatalf("exact fact fixture = %d facts, %v", len(facts), err)
	}
	generation := exactDocumentationFieldClaimSchemaFixture(t, derivationReference)
	return facts[0], documentationValidationSchema{claimKind: generation.claimKind, authority: generation.claimSchema}
}

func exactValueClassifierSchemaMap(validation documentationValidationSchema) map[string]documentationValidationSchema {
	return map[string]documentationValidationSchema{dependencyProfileReferenceKey(validation.authority.reference): validation}
}

func cloneSemanticMap(input map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func deepCloneSemanticMap(t *testing.T, input map[string]interface{}) map[string]interface{} {
	t.Helper()
	raw, err := canonicalOperationClassifierProgram(input)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]interface{}
	if err := decodeOneValidationProfileJSON(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
