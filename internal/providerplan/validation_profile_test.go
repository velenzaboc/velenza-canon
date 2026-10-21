package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateValidationProfileBindingsAcceptsClosedOfflineSchema(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	if err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema}); err != nil {
		t.Fatalf("validateValidationProfileBindings() error = %v", err)
	}
}

func TestValidateValidationProfileBindingsAcceptsRelativeSchemaIDUnderDeterministicOfflineBase(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	schema.ID = "provider_documentation_artifact_schema_sample_shape_index"
	schema.Bytes = minimalValidationProfileSchemaBytes(t, schema.ID, validationProfileDraft202012)
	binding.SchemaID = schema.ID
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	if err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema}); err != nil {
		t.Fatalf("relative schema ID under deterministic offline base: %v", err)
	}
}

func TestValidateValidationProfileBindingsRejectsDuplicateKeysBeforeSchemaValidation(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	artifact.Bytes = []byte(`{"row_kind":"record","row_kind":"record","value":"ok"}` + "\n")
	binding.ArtifactSHA256 = validationProfileSHA256(artifact.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON keys") {
		t.Fatalf("error = %v, want duplicate-key rejection", err)
	}
}

func TestValidateValidationProfileBindingsRejectsUnknownRowShapeViaSchema(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	artifact.Bytes = []byte(`{"row_kind":"unregistered","value":"ok"}` + "\n")
	binding.ArtifactSHA256 = validationProfileSHA256(artifact.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "outside the schema-proven finite roster") {
		t.Fatalf("error = %v, want unknown-row-shape schema rejection", err)
	}
}

func TestValidateValidationProfileBindingsRejectsSchemaThatAcceptsUnknownRowKinds(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	schema.Bytes = mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     schema.ID,
		"type":    "object",
		"required": []string{
			"row_kind",
		},
		"properties": map[string]interface{}{
			"row_kind":         map[string]interface{}{"type": "string"},
			"artifact_id":      map[string]interface{}{"type": "string"},
			"artifact_version": map[string]interface{}{"type": "string"},
			"value":            map[string]interface{}{"type": "string"},
		},
		"additionalProperties": false,
	})
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "finite required string discriminator") {
		t.Fatalf("error = %v, want fail-closed discriminator roster rejection", err)
	}
}

func TestValidateValidationProfileBindingsAcceptsSchemaOwnedLegacyKindDiscriminator(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	artifact.Bytes = []byte(
		`{"kind":"mapping_manifest","schema_version":"source_neutral_mapping_candidate.v1"}` + "\n" +
			`{"kind":"mapping_row","source_field":"Amount"}` + "\n",
	)
	schema.Bytes = mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     schema.ID,
		"oneOf": []interface{}{
			map[string]interface{}{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"kind", "schema_version"},
				"properties": map[string]interface{}{
					"kind":           map[string]interface{}{"const": "mapping_manifest"},
					"schema_version": map[string]interface{}{"const": "source_neutral_mapping_candidate.v1"},
				},
			},
			map[string]interface{}{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"kind", "source_field"},
				"properties": map[string]interface{}{
					"kind":         map[string]interface{}{"const": "mapping_row"},
					"source_field": map[string]interface{}{"type": "string"},
				},
			},
		},
	})
	binding.ArtifactSHA256 = validationProfileSHA256(artifact.Bytes)
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	if err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema}); err != nil {
		t.Fatalf("schema-owned legacy kind discriminator error = %v", err)
	}
}

func TestValidateValidationProfileBindingsRejectsExternalAndMalformedReferences(t *testing.T) {
	for _, test := range []struct {
		name string
		ref  string
	}{
		{name: "network", ref: "https://example.invalid/schema.json"},
		{name: "relative", ref: "schema.json"},
		{name: "malformed", ref: "http://[::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding, artifact, schema := minimalValidationProfileFixture(t)
			schema.Bytes = mustValidationProfileJSON(t, map[string]interface{}{
				"$schema": validationProfileDraft202012,
				"$id":     schema.ID,
				"$ref":    test.ref,
			})
			binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
			err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
			if err == nil || !strings.Contains(err.Error(), "schema reference") {
				t.Fatalf("error = %v, want offline reference-resolution rejection", err)
			}
		})
	}
}

func TestValidateValidationProfileBindingsRejectsWrongDraftAndSchemaIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		draft  string
		id     string
		needle string
	}{
		{name: "wrong draft", draft: "http://json-schema.org/draft-07/schema#", id: "urn:test:schema:closed-jsonl", needle: "$schema must equal"},
		{name: "identity mismatch", draft: validationProfileDraft202012, id: "urn:test:schema:different", needle: "does not equal bound schema_id"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding, artifact, schema := minimalValidationProfileFixture(t)
			schema.Bytes = minimalValidationProfileSchemaBytes(t, test.id, test.draft)
			binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
			err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
			if err == nil || !strings.Contains(err.Error(), test.needle) {
				t.Fatalf("error = %v, want %q", err, test.needle)
			}
		})
	}
}

func TestValidateValidationProfileBindingsRejectsDigestAndVersionMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*validationProfileBinding)
		needle string
	}{
		{name: "artifact digest", mutate: func(binding *validationProfileBinding) { binding.ArtifactSHA256 = strings.Repeat("0", 64) }, needle: "artifact digest mismatch"},
		{name: "schema digest", mutate: func(binding *validationProfileBinding) { binding.SchemaSHA256 = strings.Repeat("0", 64) }, needle: "schema digest mismatch"},
		{name: "artifact version", mutate: func(binding *validationProfileBinding) { binding.ArtifactVersion = "2" }, needle: "binds absent artifact"},
		{name: "schema version", mutate: func(binding *validationProfileBinding) { binding.SchemaVersion = "2" }, needle: "binds absent schema"},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding, artifact, schema := minimalValidationProfileFixture(t)
			test.mutate(&binding)
			err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
			if err == nil || !strings.Contains(err.Error(), test.needle) {
				t.Fatalf("error = %v, want %q", err, test.needle)
			}
		})
	}
}

func TestValidateValidationProfileBindingsRejectsDuplicateRolesAndDigests(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	duplicateRole := binding
	err := validateValidationProfileBindings([]validationProfileBinding{binding, duplicateRole}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "role \"primary\" is duplicated") {
		t.Fatalf("duplicate role error = %v", err)
	}

	duplicateArtifact := artifact
	duplicateArtifact.ID = "artifact-copy"
	err = validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact, duplicateArtifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "artifact digest") || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate artifact digest error = %v", err)
	}

	duplicateSchema := schema
	duplicateSchema.Version = "2"
	err = validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema, duplicateSchema})
	if err == nil || !strings.Contains(err.Error(), "schema digest") || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate schema digest error = %v", err)
	}

	artifact.Bytes = schema.Bytes
	binding.ArtifactSHA256 = validationProfileSHA256(artifact.Bytes)
	err = validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "duplicated across supplied inputs") {
		t.Fatalf("cross-kind duplicate digest error = %v", err)
	}
}

func TestValidateValidationProfileBindingsReusesOneExactSchemaAcrossArtifactRoles(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	secondArtifact := validationProfileArtifact{
		ID:      "fixture_artifact_two",
		Version: artifact.Version,
		Bytes:   []byte("{\"row_kind\":\"record\",\"value\":\"second\"}\n"),
	}
	secondBinding := binding
	secondBinding.Role = "fixture_role_two"
	secondBinding.ArtifactID = secondArtifact.ID
	secondBinding.ArtifactSHA256 = validationProfileSHA256(secondArtifact.Bytes)

	if err := validateValidationProfileBindings(
		[]validationProfileBinding{binding, secondBinding},
		[]validationProfileArtifact{artifact, secondArtifact},
		[]validationProfileSchema{schema},
	); err != nil {
		t.Fatalf("validateValidationProfileBindings() schema reuse error = %v", err)
	}
}

func TestValidateValidationProfileBindingsRejectsUnboundSupplies(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	extraArtifact := artifact
	extraArtifact.ID = "extra-artifact"
	extraArtifact.Bytes = []byte(`{"row_kind":"record","value":"different"}` + "\n")
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact, extraArtifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "extra-artifact") || !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("extra artifact error = %v", err)
	}

	extraSchema := validationProfileSchema{
		ID:      "urn:test:schema:extra",
		Version: "1",
	}
	extraSchema.Bytes = minimalValidationProfileSchemaBytes(t, extraSchema.ID, validationProfileDraft202012)
	err = validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema, extraSchema})
	if err == nil || !strings.Contains(err.Error(), "urn:test:schema:extra") || !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("extra schema error = %v", err)
	}
}

func TestValidateValidationProfileBindingsRejectsDuplicateSchemaJSONKeys(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	schema.Bytes = []byte(`{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:test:schema:closed-jsonl","$id":"urn:test:schema:closed-jsonl","type":"object"}`)
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON keys") {
		t.Fatalf("error = %v, want duplicate schema-key rejection", err)
	}
}

func TestValidateValidationProfileBindingsPreservesIntegerBeyondIEEEExactRange(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	artifact.Bytes = []byte(
		`{"row_kind":"artifact_manifest","artifact_id":"artifact-alpha","artifact_version":"1"}` + "\n" +
			`{"row_kind":"record","value":9007199254740993}` + "\n",
	)
	schema.Bytes = numericValidationProfileSchemaBytes(t, schema.ID, json.Number("9007199254740992"))
	binding.ArtifactSHA256 = validationProfileSHA256(artifact.Bytes)
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "fails its bound schema") {
		t.Fatalf("error = %v, want 9007199254740993 to fail const/maximum 9007199254740992 without float rounding", err)
	}
}

func TestValidateValidationProfileBindingsRejectsUnsafeSchemaNumericLiteral(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	schema.Bytes = numericValidationProfileSchemaBytes(t, schema.ID, json.Number("9007199254740993"))
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "would round") {
		t.Fatalf("error = %v, want unsafe schema numeric literal rejection", err)
	}
}

func TestValidateValidationProfileBindingsRejectsInexactMultipleOfEvaluator(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	schema.Bytes = mustValidationProfileJSON(t, map[string]interface{}{
		"$schema":              validationProfileDraft202012,
		"$id":                  schema.ID,
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"row_kind", "value"},
		"properties": map[string]interface{}{
			"row_kind": map[string]interface{}{"const": "record"},
			"value":    map[string]interface{}{"type": "integer", "multipleOf": 2},
		},
	})
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "multipleOf") || !strings.Contains(err.Error(), "exact numeric evaluation") {
		t.Fatalf("error = %v, want fail-closed multipleOf evaluator rejection", err)
	}
}

func TestValidateValidationProfileBindingsRejectsPermissiveCompositionBranch(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	schema.Bytes = mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     schema.ID,
		"oneOf": []interface{}{
			map[string]interface{}{
				"type":                 "object",
				"additionalProperties": false,
				"required":             []string{"row_kind"},
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "artifact_manifest"},
				},
			},
			map[string]interface{}{"type": "object"},
		},
	})
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "does not prove a closed object shape") {
		t.Fatalf("error = %v, want permissive object branch rejection", err)
	}
}

func TestValidateValidationProfileBindingsAcceptsUnevaluatedPropertiesClosure(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	schema.Bytes = mustValidationProfileJSON(t, map[string]interface{}{
		"$schema":               validationProfileDraft202012,
		"$id":                   schema.ID,
		"type":                  "object",
		"unevaluatedProperties": false,
		"required":              []string{"row_kind"},
		"properties": map[string]interface{}{
			"row_kind":         map[string]interface{}{"enum": []string{"artifact_manifest", "record"}},
			"artifact_id":      map[string]interface{}{"type": "string"},
			"artifact_version": map[string]interface{}{"type": "string"},
			"value":            map[string]interface{}{"type": "string"},
		},
	})
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	if err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema}); err != nil {
		t.Fatalf("unevaluatedProperties closure error = %v", err)
	}
}

func TestValidateValidationProfileBindingsRejectsOpenNestedObjectShape(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	schema.Bytes = mustValidationProfileJSON(t, map[string]interface{}{
		"$schema":              validationProfileDraft202012,
		"$id":                  schema.ID,
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"row_kind"},
		"properties": map[string]interface{}{
			"row_kind":         map[string]interface{}{"enum": []string{"artifact_manifest", "record"}},
			"artifact_id":      map[string]interface{}{"type": "string"},
			"artifact_version": map[string]interface{}{"type": "string"},
			"value": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{"nested": map[string]interface{}{"type": "string"}},
			},
		},
	})
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "does not prove a closed object shape") {
		t.Fatalf("error = %v, want open nested-object rejection", err)
	}
}

func TestValidateValidationProfileBindingsRejectsPatternPropertiesBypass(t *testing.T) {
	binding, artifact, schema := minimalValidationProfileFixture(t)
	schema.Bytes = mustValidationProfileJSON(t, map[string]interface{}{
		"$schema":              validationProfileDraft202012,
		"$id":                  schema.ID,
		"type":                 "object",
		"additionalProperties": false,
		"required":             []string{"row_kind"},
		"properties": map[string]interface{}{
			"row_kind": map[string]interface{}{"const": "record"},
		},
		"patternProperties": map[string]interface{}{
			".*": map[string]interface{}{},
		},
	})
	artifact.Bytes = []byte(`{"row_kind":"record","opaque_source_body":"accepted-by-pattern"}` + "\n")
	binding.ArtifactSHA256 = validationProfileSHA256(artifact.Bytes)
	binding.SchemaSHA256 = validationProfileSHA256(schema.Bytes)
	err := validateValidationProfileBindings([]validationProfileBinding{binding}, []validationProfileArtifact{artifact}, []validationProfileSchema{schema})
	if err == nil || !strings.Contains(err.Error(), "uses patternProperties") {
		t.Fatalf("error = %v, want patternProperties authority-bypass rejection", err)
	}
}

func minimalValidationProfileFixture(t *testing.T) (validationProfileBinding, validationProfileArtifact, validationProfileSchema) {
	t.Helper()
	artifact := validationProfileArtifact{
		ID:      "artifact-alpha",
		Version: "1",
		Bytes: []byte(
			`{"row_kind":"artifact_manifest","artifact_id":"artifact-alpha","artifact_version":"1"}` + "\n" +
				`{"row_kind":"record","value":"ok"}` + "\n",
		),
	}
	schema := validationProfileSchema{
		ID:      "urn:test:schema:closed-jsonl",
		Version: "1",
	}
	schema.Bytes = minimalValidationProfileSchemaBytes(t, schema.ID, validationProfileDraft202012)
	binding := validationProfileBinding{
		Role:            "primary",
		ArtifactID:      artifact.ID,
		ArtifactVersion: artifact.Version,
		ArtifactSHA256:  validationProfileSHA256(artifact.Bytes),
		SchemaID:        schema.ID,
		SchemaVersion:   schema.Version,
		SchemaSHA256:    validationProfileSHA256(schema.Bytes),
	}
	return binding, artifact, schema
}

func minimalValidationProfileSchemaBytes(t *testing.T, id, draft string) []byte {
	t.Helper()
	return mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": draft,
		"$id":     id,
		"$defs": map[string]interface{}{
			"manifest": map[string]interface{}{
				"type":                 "object",
				"required":             []string{"row_kind", "artifact_id", "artifact_version"},
				"additionalProperties": false,
				"properties": map[string]interface{}{
					"row_kind":         map[string]interface{}{"const": "artifact_manifest"},
					"artifact_id":      map[string]interface{}{"const": "artifact-alpha"},
					"artifact_version": map[string]interface{}{"const": "1"},
				},
			},
			"record": map[string]interface{}{
				"type":                 "object",
				"required":             []string{"row_kind", "value"},
				"additionalProperties": false,
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "record"},
					"value":    map[string]interface{}{"type": "string"},
				},
			},
		},
		"oneOf": []interface{}{
			map[string]interface{}{"$ref": "#/$defs/manifest"},
			map[string]interface{}{"$ref": "#/$defs/record"},
		},
	})
}

func numericValidationProfileSchemaBytes(t *testing.T, id string, bound json.Number) []byte {
	t.Helper()
	return mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     id,
		"oneOf": []interface{}{
			map[string]interface{}{
				"type":                 "object",
				"required":             []string{"row_kind", "artifact_id", "artifact_version"},
				"additionalProperties": false,
				"properties": map[string]interface{}{
					"row_kind":         map[string]interface{}{"const": "artifact_manifest"},
					"artifact_id":      map[string]interface{}{"const": "artifact-alpha"},
					"artifact_version": map[string]interface{}{"const": "1"},
				},
			},
			map[string]interface{}{
				"type":                 "object",
				"required":             []string{"row_kind", "value"},
				"additionalProperties": false,
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "record"},
					"value": map[string]interface{}{
						"type":    "integer",
						"const":   bound,
						"maximum": bound,
					},
				},
			},
		},
	})
}

func mustValidationProfileJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
