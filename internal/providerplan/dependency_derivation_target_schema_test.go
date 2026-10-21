package providerplan

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestDependencySemanticDerivationTargetSchemaAuthorityIsSchemaDriven(t *testing.T) {
	fixture := newDependencyDerivationTargetSchemaFixture(t, "future_financial_contract", "row_kind")
	authority, err := resolveDependencySemanticDerivationTargetSchemaAuthority(fixture.proof, fixture.dependencies)
	if err != nil {
		t.Fatalf("resolveDependencySemanticDerivationTargetSchemaAuthority() error = %v", err)
	}

	resolved, err := authority.validateDocumentationDerivationTarget(fixture.role, "future_nested_record")
	if err != nil {
		t.Fatalf("schema-declared custom target was rejected: %v", err)
	}
	if resolved.artifactRole != fixture.role || resolved.targetRowKind != "future_nested_record" {
		t.Fatalf("resolved target = %#v, want exact custom role and row kind", resolved)
	}
	if resolved.discriminatorProperty != "row_kind" {
		t.Fatalf("discriminator property = %q, want row_kind", resolved.discriminatorProperty)
	}
	if got, want := resolved.discriminatorValues, []string{"future_manifest", "future_nested_record"}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("finite schema roster = %v, want %v", got, want)
	}
	if resolved.schemaID != fixture.schemaID || resolved.schemaVersion != "1" || resolved.schemaSHA256 != fixture.schemaSHA256 {
		t.Fatalf("schema coordinate = %#v, want exact fixture coordinate", resolved)
	}
	if !bytes.Equal(resolved.schemaBytes, fixture.schemaBytes) {
		t.Fatal("resolution did not retain the exact schema bytes")
	}

	// Callers receive deep clones. Mutating a resolution cannot alter the
	// sealed authority used by later target/member validation.
	resolved.schemaBytes[0] ^= 0xff
	resolved.discriminatorValues[0] = "mutated_by_caller"
	again, err := authority.validateDocumentationDerivationTarget(fixture.role, "future_nested_record")
	if err != nil {
		t.Fatalf("authority changed after caller mutation: %v", err)
	}
	if !bytes.Equal(again.schemaBytes, fixture.schemaBytes) || again.discriminatorValues[0] != "future_manifest" {
		t.Fatal("authority leaked mutable schema bytes or discriminator values")
	}

	if _, err := authority.validateDocumentationDerivationTarget("unbound_future_role", "future_nested_record"); err == nil || !strings.Contains(err.Error(), "not present") {
		t.Fatalf("unknown role error = %v", err)
	}
	if _, err := authority.validateDocumentationDerivationTarget(fixture.role, "go_owned_guess"); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("unknown row-kind error = %v", err)
	}
}

func TestDependencySemanticDerivationTargetSchemaAuthorityRequiresRowKindDiscriminator(t *testing.T) {
	fixture := newDependencyDerivationTargetSchemaFixture(t, "future_financial_contract", "shape_kind")
	authority, err := resolveDependencySemanticDerivationTargetSchemaAuthority(fixture.proof, fixture.dependencies)
	if err != nil {
		t.Fatalf("generic schema authority construction error = %v", err)
	}
	if _, err := authority.validateDocumentationDerivationTarget(fixture.role, "future_nested_record"); err == nil || !strings.Contains(err.Error(), `proves discriminator "shape_kind" rather than required row_kind`) {
		t.Fatalf("non-row_kind discriminator error = %v", err)
	}
}

func TestDependencySemanticDerivationTargetSchemaAuthorityRejectsSchemaDigestDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*dependencyDerivationTargetSchemaFixture)
	}{
		{
			name: "exact bytes mutated under pinned digest",
			mutate: func(fixture *dependencyDerivationTargetSchemaFixture) {
				input := fixture.dependencies[fixture.schemaSHA256]
				input.Raw = append(bytes.Clone(input.Raw), '\n')
				fixture.dependencies[fixture.schemaSHA256] = input
			},
		},
		{
			name: "supplied digest metadata disagrees",
			mutate: func(fixture *dependencyDerivationTargetSchemaFixture) {
				input := fixture.dependencies[fixture.schemaSHA256]
				input.SHA256 = validationProfileSHA256([]byte("different-schema"))
				fixture.dependencies[fixture.schemaSHA256] = input
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDependencyDerivationTargetSchemaFixture(t, "future_financial_contract", "row_kind")
			test.mutate(&fixture)
			if _, err := resolveDependencySemanticDerivationTargetSchemaAuthority(fixture.proof, fixture.dependencies); err == nil || !strings.Contains(err.Error(), "does not bind its exact supplied bytes") {
				t.Fatalf("schema digest drift error = %v", err)
			}
		})
	}
}

func TestDependencySemanticDerivationTargetSchemaAuthorityRejectsDialectSplit(t *testing.T) {
	row := func(kind string) map[string]interface{} {
		return map[string]interface{}{
			"type": "object", "additionalProperties": false,
			"required": []string{"row_kind", "payload"},
			"properties": map[string]interface{}{
				"row_kind": map[string]interface{}{"const": kind},
				"payload":  map[string]interface{}{"type": "string"},
			},
		}
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"ref with sibling": func(schema map[string]interface{}) {
			schema["$defs"] = map[string]interface{}{"row": row("future_manifest")}
			schema["oneOf"] = []interface{}{
				map[string]interface{}{"$ref": "#/$defs/row", "description": "ignored by the current materializer"},
				row("future_nested_record"),
			}
		},
		"external ref": func(schema map[string]interface{}) {
			schema["oneOf"] = []interface{}{
				map[string]interface{}{"$ref": "https://example.com/row.schema.json"},
				row("future_nested_record"),
			}
		},
		"anchor ref": func(schema map[string]interface{}) {
			schema["oneOf"] = []interface{}{
				map[string]interface{}{"$ref": "#manifest"},
				row("future_nested_record"),
			}
		},
		"allOf": func(schema map[string]interface{}) {
			delete(schema, "oneOf")
			schema["allOf"] = []interface{}{row("future_manifest")}
		},
		"overlapping anyOf": func(schema map[string]interface{}) {
			delete(schema, "oneOf")
			schema["anyOf"] = []interface{}{row("future_manifest"), row("future_manifest")}
		},
		"dynamic reference": func(schema map[string]interface{}) {
			schema["$defs"] = map[string]interface{}{"row": row("future_manifest")}
			schema["oneOf"] = []interface{}{
				map[string]interface{}{"$dynamicRef": "#/$defs/row"},
				row("future_nested_record"),
			}
		},
		"dynamic anchor": func(schema map[string]interface{}) {
			schema["$dynamicAnchor"] = "rows"
		},
		"root oneOf assertion sibling": func(schema map[string]interface{}) {
			schema["minProperties"] = 1
		},
		"composed type": func(schema map[string]interface{}) {
			first := schema["oneOf"].([]interface{})[0].(map[string]interface{})
			first["properties"].(map[string]interface{})["payload"] = map[string]interface{}{"type": []interface{}{"string", "null"}}
		},
		"schema valued additional properties": func(schema map[string]interface{}) {
			first := schema["oneOf"].([]interface{})[0].(map[string]interface{})
			first["additionalProperties"] = map[string]interface{}{"type": "string"}
		},
		"composed field": func(schema map[string]interface{}) {
			first := schema["oneOf"].([]interface{})[0].(map[string]interface{})
			first["properties"].(map[string]interface{})["payload"] = map[string]interface{}{
				"anyOf": []interface{}{map[string]interface{}{"type": "string"}, map[string]interface{}{"const": "manifest"}},
			}
		},
		"composed items": func(schema map[string]interface{}) {
			first := schema["oneOf"].([]interface{})[0].(map[string]interface{})
			first["required"] = []string{"row_kind", "payload", "items"}
			first["properties"].(map[string]interface{})["items"] = map[string]interface{}{
				"type": "array", "items": map[string]interface{}{
					"oneOf": []interface{}{map[string]interface{}{"type": "string"}, map[string]interface{}{"const": "x"}},
				},
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDependencyDerivationTargetSchemaFixture(t, "future_financial_contract", "row_kind")
			var schema map[string]interface{}
			if err := decodeOneValidationProfileJSON(fixture.schemaBytes, &schema); err != nil {
				t.Fatal(err)
			}
			mutate(schema)
			setDependencyDerivationTargetSchema(t, &fixture, schema)
			if _, err := resolveDependencySemanticDerivationTargetSchemaAuthority(fixture.proof, fixture.dependencies); err == nil || !strings.Contains(err.Error(), "outside the exact materializer subset") {
				t.Fatalf("dialect split error = %v", err)
			}
		})
	}
}

func TestDependencySemanticDerivationTargetSchemaAuthorityAcceptsSimpleLocalPointerRefs(t *testing.T) {
	fixture := newDependencyDerivationTargetSchemaFixture(t, "future_financial_contract", "row_kind")
	var schema map[string]interface{}
	if err := decodeOneValidationProfileJSON(fixture.schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	branches := schema["oneOf"].([]interface{})
	schema["$defs"] = map[string]interface{}{
		"manifest": branches[0],
		"nested":   branches[1],
	}
	schema["oneOf"] = []interface{}{
		map[string]interface{}{"$ref": "#/$defs/manifest"},
		map[string]interface{}{"$ref": "#/$defs/nested"},
	}
	setDependencyDerivationTargetSchema(t, &fixture, schema)
	if _, err := resolveDependencySemanticDerivationTargetSchemaAuthority(fixture.proof, fixture.dependencies); err != nil {
		t.Fatalf("simple local-pointer oneOf schema rejected: %v", err)
	}
}

func setDependencyDerivationTargetSchema(t *testing.T, fixture *dependencyDerivationTargetSchemaFixture, schema map[string]interface{}) {
	t.Helper()
	schemaBytes := mustValidationProfileJSON(t, schema)
	oldDigest := fixture.schemaSHA256
	newDigest := validationProfileSHA256(schemaBytes)
	delete(fixture.dependencies, oldDigest)
	fixture.dependencies[newDigest] = artifactInput{Path: "future-financial-contract.schema.json", Raw: bytes.Clone(schemaBytes), SHA256: newDigest}
	validated := fixture.proof.byRole[fixture.role]
	validated.schemaSHA256 = newDigest
	fixture.proof.byRole[fixture.role] = validated
	fixture.schemaSHA256 = newDigest
	fixture.schemaBytes = schemaBytes
}

type dependencyDerivationTargetSchemaFixture struct {
	proof        dependencySemanticValidationProof
	dependencies map[string]artifactInput
	role         string
	schemaID     string
	schemaSHA256 string
	schemaBytes  []byte
}

func newDependencyDerivationTargetSchemaFixture(t *testing.T, role, discriminatorProperty string) dependencyDerivationTargetSchemaFixture {
	t.Helper()
	schemaID := "urn:test:provider-documentation:future-financial-contract"
	row := func(kind string) map[string]interface{} {
		return map[string]interface{}{
			"type": "object", "additionalProperties": false,
			"required": []string{discriminatorProperty, "payload"},
			"properties": map[string]interface{}{
				discriminatorProperty: map[string]interface{}{"const": kind},
				"payload":             map[string]interface{}{"type": "string"},
			},
		}
	}
	schemaBytes := mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     schemaID,
		"oneOf": []interface{}{
			row("future_manifest"),
			row("future_nested_record"),
		},
	})
	artifactBytes := []byte(fmt.Sprintf(
		"{%q:%q,%q:%q}\n{%q:%q,%q:%q}\n",
		discriminatorProperty, "future_manifest", "payload", "manifest",
		discriminatorProperty, "future_nested_record", "payload", "nested",
	))
	schemaSHA256 := validationProfileSHA256(schemaBytes)
	artifactSHA256 := validationProfileSHA256(artifactBytes)
	proof, err := validateDependencySemanticProfiles(
		[]validationProfileBinding{{
			Role: role, ArtifactID: "future_financial_contract", ArtifactVersion: "1", ArtifactSHA256: artifactSHA256,
			SchemaID: schemaID, SchemaVersion: "1", SchemaSHA256: schemaSHA256,
		}},
		[]validationProfileArtifact{{ID: "future_financial_contract", Version: "1", Bytes: artifactBytes}},
		[]validationProfileSchema{{ID: schemaID, Version: "1", Bytes: schemaBytes}},
	)
	if err != nil {
		t.Fatalf("validateDependencySemanticProfiles() fixture error = %v", err)
	}
	validated := proof.byRole[role]
	validated.schemaRole = "future_financial_contract_schema"
	proof.byRole[role] = validated
	return dependencyDerivationTargetSchemaFixture{
		proof: proof,
		dependencies: map[string]artifactInput{
			schemaSHA256: {Path: "future-financial-contract.schema.json", Raw: bytes.Clone(schemaBytes), SHA256: schemaSHA256},
		},
		role: role, schemaID: schemaID, schemaSHA256: schemaSHA256, schemaBytes: schemaBytes,
	}
}
