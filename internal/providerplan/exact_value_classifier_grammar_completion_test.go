package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseExactValueClassifierProgramRequiresItsBoundValidationSchema(t *testing.T) {
	_, validation := exactValueClassifierFactAndSchemaFixture(t)
	profile, reference := exactValueClassifierProfileFixture(t, validation)
	// The program pins a validation schema by coordinate; without that exact
	// same-claim schema in scope it cannot be compiled at all.
	if _, err := parseExactValueClassifierProgram(profile, reference, map[string]documentationValidationSchema{}); err == nil ||
		!strings.Contains(err.Error(), "does not bind one exact same-claim validation schema") {
		t.Fatalf("error = %v, want a same-claim validation schema refusal", err)
	}
}

func TestParseExactValueClassifierProgramRefusesUngrammaticalRules(t *testing.T) {
	_, validation := exactValueClassifierFactAndSchemaFixture(t)
	profile, _ := exactValueClassifierProfileFixture(t, validation)

	for _, test := range []struct {
		name   string
		mutate func(map[string]interface{})
		want   string
	}{
		{
			name: "projection pointer outside the closed provider-fact registry",
			mutate: func(program map[string]interface{}) {
				program["input_projection_json_pointers"] = []interface{}{"/not_a_provider_fact"}
			},
			want: "outside the closed pre-classification provider-fact registry",
		},
		{
			name: "two rules share one rule_id",
			mutate: func(program map[string]interface{}) {
				first := program["ordered_rules"].([]interface{})[0].(map[string]interface{})
				program["ordered_rules"] = append(program["ordered_rules"].([]interface{}), map[string]interface{}{
					"ordinal": json.Number("1"), "rule_id": first["rule_id"],
					"predicates": first["predicates"], "output": first["output"],
				})
			},
			want: "duplicates rule_id",
		},
		{
			name: "one rule repeats a single input pointer",
			mutate: func(program map[string]interface{}) {
				first := program["ordered_rules"].([]interface{})[0].(map[string]interface{})
				predicate := first["predicates"].([]interface{})[0]
				first["predicates"] = []interface{}{predicate, predicate}
			},
			want: "repeats input pointer",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := profile
			candidate.program = deepCloneSemanticMap(t, profile.program)
			test.mutate(candidate.program)
			canonical, err := canonicalOperationClassifierProgram(candidate.program)
			if err != nil {
				t.Fatal(err)
			}
			reference := dependencyProfileReference{id: "exact_value_fixture", version: "1", digest: sha256Hex(canonical)}
			if _, err := parseExactValueClassifierProgram(candidate, reference, exactValueClassifierSchemaMap(validation)); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestExecuteExactValueClassifierRequiresItsCompiledValidationSchema(t *testing.T) {
	fact, validation := exactValueClassifierFactAndSchemaFixture(t)
	profile, reference := exactValueClassifierProfileFixture(t, validation)
	program, err := parseExactValueClassifierProgram(profile, reference, exactValueClassifierSchemaMap(validation))
	if err != nil {
		t.Fatal(err)
	}
	// Executing against a schema the program was not compiled against would let
	// a classified claim be validated by a contract it never bound.
	substituted := documentationValidationSchema{claimKind: "a_different_claim_kind", authority: validation.authority}
	if _, err := executeExactValueClassifier(program, fact, substituted); err == nil ||
		!strings.Contains(err.Error(), "validation schema differs from its compiled program") {
		t.Fatalf("error = %v, want a compiled-schema refusal", err)
	}
}

func TestExactValueClassifierSchemaProvesInputPointerRequiresResolvedAuthority(t *testing.T) {
	if err := exactValueClassifierSchemaProvesInputPointer(documentationClaimSchemaAuthority{}, "/provider_type"); err == nil ||
		!strings.Contains(err.Error(), "claim schema authority is absent or inexact") {
		t.Fatalf("error = %v, want an absent-authority refusal", err)
	}
}
