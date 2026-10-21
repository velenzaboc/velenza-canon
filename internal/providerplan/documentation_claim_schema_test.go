package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func exactDocumentationFieldClaimSchemaFixture(t *testing.T, program dependencyProfileReference) documentationSemanticGenerationBinding {
	t.Helper()
	id := "urn:test:documentation:field-claim"
	schemaBytes := mustValidationProfileJSON(t, map[string]interface{}{
		"$schema":              validationProfileDraft202012,
		"$id":                  id,
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"field_name", "provider_requirement", "provider_type"},
		"properties": map[string]interface{}{
			"field_name":           map[string]interface{}{"type": "string"},
			"provider_requirement": map[string]interface{}{"type": "string"},
			"provider_type":        map[string]interface{}{"type": "string"},
		},
	})
	schemaReference := dependencyProfileReference{id: id, version: "1", digest: sha256Hex(schemaBytes)}
	authority, err := resolveDocumentationClaimSchema(schemaReference, "field_contract", string(schemaBytes))
	if err != nil {
		t.Fatal(err)
	}
	generation, err := newDocumentationSemanticGenerationBinding("field_contract", program, authority)
	if err != nil {
		t.Fatal(err)
	}
	return generation
}

func TestDocumentationClaimSchemaValidatesEveryExactOutput(t *testing.T) {
	program := dependencyProfileReference{id: "fixture_program", version: "1", digest: sha256Hex([]byte("program"))}
	generation := exactDocumentationFieldClaimSchemaFixture(t, program)
	valid := []byte(`{"field_name":"amount","provider_requirement":"Required","provider_type":"Decimal"}`)
	if err := validateDocumentationClaimOutput(generation.claimSchema, valid); err != nil {
		t.Fatalf("valid exact claim output rejected: %v", err)
	}
	for name, invalid := range map[string][]byte{
		"missing required field": []byte(`{"field_name":"amount","provider_type":"Decimal"}`),
		"unknown field":          []byte(`{"field_name":"amount","provider_requirement":"Required","provider_type":"Decimal","unknown":true}`),
		"noncanonical bytes":     []byte(`{ "field_name":"amount","provider_requirement":"Required","provider_type":"Decimal"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateDocumentationClaimOutput(generation.claimSchema, invalid); err == nil {
				t.Fatal("invalid documentation claim output was accepted")
			}
		})
	}
}

func TestDocumentationClaimSchemaRejectsEmptyClosedSchemaForNonemptyClaim(t *testing.T) {
	id := "urn:test:documentation:empty-claim"
	bytes := mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012, "$id": id,
		"type": "object", "additionalProperties": false, "properties": map[string]interface{}{},
	})
	authority, err := resolveDocumentationClaimSchema(
		dependencyProfileReference{id: id, version: "1", digest: sha256Hex(bytes)},
		"field_contract", string(bytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDocumentationClaimOutput(authority, []byte(`{"field_name":"amount"}`)); err == nil {
		t.Fatal("empty closed validation schema accepted a nonempty derived claim")
	}
}

func TestDocumentationClaimSchemaUsesExactRuntimeNumberPath(t *testing.T) {
	id := "urn:test:documentation:numeric-claim"
	schemaBytes := mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012, "$id": id,
		"type": "object", "additionalProperties": false,
		"required":   []string{"amount"},
		"properties": map[string]interface{}{"amount": map[string]interface{}{"type": "number"}},
	})
	authority, err := resolveDocumentationClaimSchema(
		dependencyProfileReference{id: id, version: "1", digest: sha256Hex(schemaBytes)},
		"numeric_claim", string(schemaBytes),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDocumentationClaimOutput(authority, []byte(`{"amount":1.5}`)); err != nil {
		t.Fatalf("exactly representable number rejected: %v", err)
	}
	if err := validateDocumentationClaimOutput(authority, []byte(`{"amount":0.1}`)); err == nil || !strings.Contains(err.Error(), "cannot be represented exactly") {
		t.Fatalf("rounded number error = %v", err)
	}
}

func TestDocumentationSemanticGenerationBindsClaimProgramAndExactSchema(t *testing.T) {
	program := dependencyProfileReference{id: "fixture_program", version: "1", digest: sha256Hex([]byte("program"))}
	first := exactDocumentationFieldClaimSchemaFixture(t, program)
	second := exactDocumentationFieldClaimSchemaFixture(t, program)
	if first.identitySHA256 != second.identitySHA256 || !isLowerSHA256(first.identitySHA256) {
		t.Fatalf("semantic generation is not stable: %q / %q", first.identitySHA256, second.identitySHA256)
	}

	mutatedProgram := program
	mutatedProgram.digest = sha256Hex([]byte("different-program"))
	mutated, err := newDocumentationSemanticGenerationBinding(first.claimKind, mutatedProgram, first.claimSchema)
	if err != nil {
		t.Fatal(err)
	}
	if mutated.identitySHA256 == first.identitySHA256 {
		t.Fatal("program digest mutation did not change semantic generation")
	}

	tampered := first
	tampered.identitySHA256 = strings.Repeat("0", 64)
	if err := validateDocumentationSemanticGenerationBinding(tampered); err == nil {
		t.Fatal("tampered semantic generation identity was accepted")
	}
	tampered = first
	tampered.claimSchema.canonicalSchemaBytes = append([]byte(nil), first.claimSchema.canonicalSchemaBytes...)
	tampered.claimSchema.canonicalSchemaBytes[0] ^= 0xff
	if err := validateDocumentationSemanticGenerationBinding(tampered); err == nil {
		t.Fatal("tampered exact validation-schema bytes were accepted")
	}
}

func TestDocumentationClaimSchemaRejectsCoordinateAndExternalReferenceDrift(t *testing.T) {
	for name, schema := range map[string]map[string]interface{}{
		"id mismatch": {
			"$schema": validationProfileDraft202012, "$id": "urn:test:different",
			"type": "object", "additionalProperties": false, "properties": map[string]interface{}{},
		},
		"external reference": {
			"$schema": validationProfileDraft202012, "$id": "urn:test:documentation:claim",
			"$ref": "https://example.com/external.schema.json",
		},
	} {
		t.Run(name, func(t *testing.T) {
			bytes, err := json.Marshal(schema)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalizeCandidateJSON(bytes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolveDocumentationClaimSchema(
				dependencyProfileReference{id: "urn:test:documentation:claim", version: "1", digest: sha256Hex(canonical)},
				"claim", string(canonical),
			); err == nil {
				t.Fatal("claim schema drift was accepted")
			}
		})
	}
}
