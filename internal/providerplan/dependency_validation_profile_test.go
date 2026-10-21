package providerplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDependencySemanticArtifactPinsBindAllFiveDirectPlanAuthorities(t *testing.T) {
	plan, fieldMapping := dependencySemanticPlanPinFixture()
	pins, err := dependencySemanticArtifactPins(plan, fieldMapping)
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != len(dependencySemanticRequiredRoles) {
		t.Fatalf("pin count = %d, want closed %d-role roster", len(pins), len(dependencySemanticRequiredRoles))
	}
	byRole := map[string]string{}
	for _, pin := range pins {
		byRole[pin.role] = pin.digest
	}
	for role, want := range map[string]string{
		dependencySemanticRoleOperationApplicability:       plan.Manifest.OperationApplicabilityProfileSHA256,
		dependencySemanticRoleAPIGraphApplicability:        plan.Manifest.APIGraphApplicabilityProfileSHA256,
		dependencySemanticRoleFieldSecurityPolicy:          plan.Manifest.FieldSecurityPolicySHA256,
		dependencySemanticRoleMappingTransitiveRoster:      plan.Manifest.MappingTransitiveDependencyRosterSHA256,
		dependencySemanticRoleDocumentationClaimDerivation: plan.Manifest.DocumentationClaimDerivationProfileSHA256,
		dependencySemanticRoleSurfaceDisposition:           fieldMapping.Manifest["surface_family_disposition_sha256"].(string),
	} {
		if got := byRole[role]; got != want {
			t.Errorf("role %q digest = %q, want %q", role, got, want)
		}
	}
}

func TestDependencySemanticArtifactPinsRejectMissingFiveDirectPlanAuthorities(t *testing.T) {
	for _, test := range []struct {
		name  string
		clear func(*artifactManifest)
	}{
		{name: "operation applicability", clear: func(manifest *artifactManifest) { manifest.OperationApplicabilityProfileSHA256 = "" }},
		{name: "API graph applicability", clear: func(manifest *artifactManifest) { manifest.APIGraphApplicabilityProfileSHA256 = "" }},
		{name: "field security", clear: func(manifest *artifactManifest) { manifest.FieldSecurityPolicySHA256 = "" }},
		{name: "mapping transitive roster", clear: func(manifest *artifactManifest) { manifest.MappingTransitiveDependencyRosterSHA256 = "" }},
		{name: "documentation derivation", clear: func(manifest *artifactManifest) { manifest.DocumentationClaimDerivationProfileSHA256 = "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, fieldMapping := dependencySemanticPlanPinFixture()
			test.clear(plan.Manifest)
			if _, err := dependencySemanticArtifactPins(plan, fieldMapping); err == nil {
				t.Fatal("missing direct plan authority was accepted")
			}
		})
	}
}

func TestDependencySemanticArtifactPinsRejectNestedAuthorityMismatch(t *testing.T) {
	for _, field := range []string{
		"field_security_policy_artifact_sha256",
		"mapping_transitive_dependency_roster_sha256",
		"documentation_claim_derivation_profile_sha256",
	} {
		t.Run(field, func(t *testing.T) {
			plan, fieldMapping := dependencySemanticPlanPinFixture()
			fieldMapping.Manifest[field] = sha256Hex([]byte("mismatch:" + field))
			if _, err := dependencySemanticArtifactPins(plan, fieldMapping); err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("nested mismatch error = %v, want %s refusal", err, field)
			}
		})
	}
}

func TestDependencySemanticArtifactPinsRejectDigestAlias(t *testing.T) {
	plan, fieldMapping := dependencySemanticPlanPinFixture()
	plan.Manifest.APIGraphApplicabilityProfileSHA256 = plan.Manifest.OperationApplicabilityProfileSHA256
	if _, err := dependencySemanticArtifactPins(plan, fieldMapping); err == nil || !strings.Contains(err.Error(), "aliases roles") {
		t.Fatalf("digest alias error = %v", err)
	}
}

func TestResolveDependencySemanticValidationProfileAcceptsClosedElevenRoleRosterAndSchemaReuse(t *testing.T) {
	dir := t.TempDir()
	dependencies := map[string]artifactInput{}
	roleArtifacts := map[string]artifactInput{}

	targetSchemaID := "urn:test:provider-documentation:semantic-artifact"
	targetSchemaRaw := dependencySemanticTargetSchema(t, targetSchemaID)
	targetSchema := writeDependencyValidationInput(t, dir, "semantic-artifact.schema.json", targetSchemaRaw)
	dependencies[targetSchema.SHA256] = targetSchema

	profileBindings := make([]map[string]interface{}, 0, len(dependencySemanticRequiredRoles))
	for index, role := range dependencySemanticRequiredRoles {
		artifactID := fmt.Sprintf("fixture_semantic_artifact_%02d", index)
		raw := []byte(fmt.Sprintf(
			"{\"row_kind\":\"artifact_manifest\",\"artifact\":%q,\"artifact_version\":\"1\"}\n{\"row_kind\":\"validation_summary\",\"result\":\"candidate\"}\n",
			artifactID,
		))
		input := writeDependencyValidationInput(t, dir, artifactID+".jsonl", raw)
		dependencies[input.SHA256] = input
		roleArtifacts[role] = input
		profileBindings = append(profileBindings, map[string]interface{}{
			"row_kind": "artifact_schema_binding", "role": role,
			"artifact_id": artifactID, "artifact_version": "1", "artifact_raw_sha256": input.SHA256,
			"schema_role": role + "_schema", "schema_id": targetSchemaID, "schema_version": "1", "schema_raw_sha256": targetSchema.SHA256,
		})
	}

	profileID := "provider_documentation_dependency_semantic_validation_profile"
	profileRows := []map[string]interface{}{{
		"row_kind": "artifact_manifest", "artifact": dependencySemanticValidationProfileArtifact,
		"artifact_version": "1", "status": dependencySemanticValidationProfileStatus,
		"profile_id": profileID, "profile_version": "1", "binding_count": len(profileBindings),
		"canonical_admission_authorized": false,
	}}
	profileRows = append(profileRows, profileBindings...)
	profileRows = append(profileRows, map[string]interface{}{
		"row_kind": "validation_summary", "binding_count": len(profileBindings),
		"artifact_count": len(profileBindings), "schema_count": 1,
		"canonical_admission_authorized": false, "result": dependencySemanticValidationProfileResult,
	})
	profileRaw := dependencyValidationJSONL(t, profileRows)
	profile := writeDependencyValidationInput(t, dir, "dependency-semantic-validation-profile.jsonl", profileRaw)
	dependencies[profile.SHA256] = profile

	profileSchemaID := "urn:test:provider-documentation:semantic-validation-profile"
	profileSchemaRaw := dependencySemanticProfileSchema(t, profileSchemaID)
	profileSchema := writeDependencyValidationInput(t, dir, "dependency-semantic-validation-profile.schema.json", profileSchemaRaw)
	dependencies[profileSchema.SHA256] = profileSchema

	used := map[string]struct{}{}
	proof, err := resolveDependencySemanticValidationProfile(
		dependencySemanticValidationPlanBinding{
			Profile: dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile", ID: profileID, Version: "1", RawSHA256: profile.SHA256},
			Schema:  dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile_schema", ID: profileSchemaID, Version: "1", RawSHA256: profileSchema.SHA256},
		},
		dependencies,
		roleArtifacts,
		used,
	)
	if err != nil {
		t.Fatalf("resolveDependencySemanticValidationProfile() error = %v", err)
	}
	if proof.seal != dependencySemanticValidationAuthority || len(proof.byRole) != len(dependencySemanticRequiredRoles) {
		t.Fatalf("proof = %#v, want sealed %d-role proof", proof, len(dependencySemanticRequiredRoles))
	}
	if len(used) != 3 {
		t.Fatalf("used dependency count = %d, want profile + profile schema + one reused target schema", len(used))
	}
}

func TestResolveDependencySemanticValidationProfileRejectsMissingAndExtraRole(t *testing.T) {
	for _, test := range []struct {
		name  string
		roles []string
	}{
		{name: "missing", roles: append([]string(nil), dependencySemanticRequiredRoles[:len(dependencySemanticRequiredRoles)-1]...)},
		{name: "extra", roles: append(append([]string(nil), dependencySemanticRequiredRoles...), "unbound_extra_semantic_role")},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDependencySemanticResolutionFixture(t, test.roles, false)
			if _, err := fixture.resolve(); err == nil || !strings.Contains(err.Error(), "roles") {
				t.Fatalf("role roster error = %v", err)
			}
		})
	}
}

func TestResolveDependencySemanticValidationProfileRejectsArtifactDigestAlias(t *testing.T) {
	fixture := newDependencySemanticResolutionFixture(t, dependencySemanticRequiredRoles, true)
	if _, err := fixture.resolve(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("artifact digest alias error = %v", err)
	}
}

func TestResolveDependencySemanticValidationProfileWithTargetsRejectsSemanticOnlyBindings(t *testing.T) {
	fixture := newDependencySemanticResolutionFixture(t, dependencySemanticRequiredRoles, false)
	_, err := resolveDependencySemanticValidationProfileWithTargets(
		fixture.binding,
		fixture.dependencies,
		fixture.roleArtifacts,
		map[string]struct{}{},
	)
	if err == nil || !strings.Contains(err.Error(), "no distinct exact documentation target artifact bindings") {
		t.Fatalf("semantic-only target resolution error = %v", err)
	}
}

func TestVerifyRejectsDocumentationTargetCoordinateAliasesAcrossSemanticAndTargetMaps(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(map[string]interface{}, map[string]interface{})
		want   string
	}{
		{
			name: "artifact coordinate",
			mutate: func(target, semantic map[string]interface{}) {
				target["artifact_id"] = semantic["artifact_id"]
				target["artifact_version"] = semantic["artifact_version"]
			},
			want: "artifact coordinate",
		},
		{
			name: "schema coordinate",
			mutate: func(target, semantic map[string]interface{}) {
				target["schema_id"] = semantic["schema_id"]
				target["schema_version"] = semantic["schema_version"]
			},
			want: "schema coordinate",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			role := dependencySemanticRoleSourceContract
			profilePath := fixture.dependencyByRole["dependency_semantic_validation_profile"]
			semanticDigest := fileSHA256(t, fixtureSemanticArtifactPath(fixture, role))
			targetDigest := fileSHA256(t, fixture.derivationTargetPaths[role])
			_, rows := fixtureDependencySemanticArtifact(t, profilePath)
			var semanticBinding map[string]interface{}
			for _, row := range rows.byKind["artifact_schema_binding"] {
				rowRole, _ := semanticString(row.data, "role")
				digest, _ := semanticString(row.data, "artifact_raw_sha256")
				if rowRole == role && digest == semanticDigest {
					semanticBinding = cloneSemanticObjectForTest(t, row.data)
				}
			}
			if semanticBinding == nil || semanticDigest == targetDigest {
				t.Fatal("fixture does not expose distinct semantic and exact-target bindings")
			}
			mutated := 0
			mutateJSONLMatchingRow(t, profilePath, "artifact_schema_binding", func(row map[string]interface{}) bool {
				rowRole, _ := semanticString(row, "role")
				digest, _ := semanticString(row, "artifact_raw_sha256")
				return rowRole == role && digest == targetDigest
			}, func(row map[string]interface{}) {
				test.mutate(row, semanticBinding)
				mutated++
			})
			if mutated != 1 {
				t.Fatalf("mutated %d exact target bindings, want 1", mutated)
			}
			fixture.manifest().DependencySemanticValidation.Profile.RawSHA256 = fileSHA256(t, profilePath)
			writeJSONL(t, fixture.planPath, fixture.planRows)
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), "different exact bytes") {
				t.Fatalf("cross-map %s alias error = %v, want deterministic different-byte coordinate refusal", test.name, err)
			}
		})
	}
}

type dependencySemanticResolutionFixture struct {
	binding       dependencySemanticValidationPlanBinding
	dependencies  map[string]artifactInput
	roleArtifacts map[string]artifactInput
}

func newDependencySemanticResolutionFixture(t *testing.T, roles []string, aliasFirstTwo bool) dependencySemanticResolutionFixture {
	t.Helper()
	dir := t.TempDir()
	dependencies := map[string]artifactInput{}
	roleArtifacts := map[string]artifactInput{}
	targetSchemaID := "urn:test:provider-documentation:semantic-artifact"
	targetSchema := writeDependencyValidationInput(t, dir, "semantic-artifact.schema.json", dependencySemanticTargetSchema(t, targetSchemaID))
	dependencies[targetSchema.SHA256] = targetSchema

	profileBindings := make([]map[string]interface{}, 0, len(roles))
	artifactCoordinates := map[string]struct{}{}
	var first artifactInput
	for index, role := range roles {
		var input artifactInput
		if aliasFirstTwo && index == 1 {
			input = first
		} else {
			artifactID := fmt.Sprintf("fixture_semantic_artifact_%02d", index)
			raw := []byte(fmt.Sprintf("{\"row_kind\":\"artifact_manifest\",\"artifact\":%q,\"artifact_version\":\"1\"}\n{\"row_kind\":\"validation_summary\",\"result\":\"candidate\"}\n", artifactID))
			input = writeDependencyValidationInput(t, dir, fmt.Sprintf("semantic-artifact-%02d.jsonl", index), raw)
			if index == 0 {
				first = input
			}
		}
		dependencies[input.SHA256] = input
		roleArtifacts[role] = input
		artifactID, _ := manifestString(input.Manifest, "artifact")
		artifactVersion, _ := manifestString(input.Manifest, "artifact_version")
		artifactCoordinates[artifactID+"\x00"+artifactVersion] = struct{}{}
		profileBindings = append(profileBindings, map[string]interface{}{
			"row_kind": "artifact_schema_binding", "role": role,
			"artifact_id": artifactID, "artifact_version": artifactVersion, "artifact_raw_sha256": input.SHA256,
			"schema_role": role + "_schema", "schema_id": targetSchemaID, "schema_version": "1", "schema_raw_sha256": targetSchema.SHA256,
		})
	}

	profileID := "provider_documentation_dependency_semantic_validation_profile"
	rows := []map[string]interface{}{{
		"row_kind": "artifact_manifest", "artifact": dependencySemanticValidationProfileArtifact,
		"artifact_version": "1", "status": dependencySemanticValidationProfileStatus,
		"profile_id": profileID, "profile_version": "1", "binding_count": len(profileBindings),
		"canonical_admission_authorized": false,
	}}
	rows = append(rows, profileBindings...)
	rows = append(rows, map[string]interface{}{
		"row_kind": "validation_summary", "binding_count": len(profileBindings),
		"artifact_count": len(artifactCoordinates), "schema_count": 1,
		"canonical_admission_authorized": false, "result": dependencySemanticValidationProfileResult,
	})
	profile := writeDependencyValidationInput(t, dir, "dependency-semantic-validation-profile.jsonl", dependencyValidationJSONL(t, rows))
	dependencies[profile.SHA256] = profile
	profileSchemaID := "urn:test:provider-documentation:semantic-validation-profile"
	profileSchema := writeDependencyValidationInput(t, dir, "dependency-semantic-validation-profile.schema.json", dependencySemanticProfileSchema(t, profileSchemaID))
	dependencies[profileSchema.SHA256] = profileSchema

	return dependencySemanticResolutionFixture{
		binding: dependencySemanticValidationPlanBinding{
			Profile: dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile", ID: profileID, Version: "1", RawSHA256: profile.SHA256},
			Schema:  dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile_schema", ID: profileSchemaID, Version: "1", RawSHA256: profileSchema.SHA256},
		},
		dependencies: dependencies, roleArtifacts: roleArtifacts,
	}
}

func (fixture dependencySemanticResolutionFixture) resolve() (dependencySemanticValidationProof, error) {
	return resolveDependencySemanticValidationProfile(fixture.binding, fixture.dependencies, fixture.roleArtifacts, map[string]struct{}{})
}

func dependencySemanticPlanPinFixture() (*parsedPlan, artifactInput) {
	digest := func(label string) string { return sha256Hex([]byte(label)) }
	manifest := &artifactManifest{
		ProviderNeutralProfileSHA256:              digest("provider-neutral"),
		SourceContractIndexSHA256:                 digest("source-contract"),
		SampleShapeIndexSHA256:                    digest("sample-shape"),
		ProtocolContractIndexSHA256:               digest("protocol-contract"),
		FieldMappingCandidateSHA256:               digest("field-mapping"),
		OperationApplicabilityProfileSHA256:       digest("operation-applicability"),
		APIGraphApplicabilityProfileSHA256:        digest("api-graph-applicability"),
		FieldSecurityPolicySHA256:                 digest("field-security"),
		MappingTransitiveDependencyRosterSHA256:   digest("mapping-transitive"),
		DocumentationClaimDerivationProfileSHA256: digest("documentation-derivation"),
	}
	fieldMapping := artifactInput{Manifest: map[string]interface{}{
		"surface_family_disposition_sha256":             digest("surface-disposition"),
		"field_security_policy_artifact_sha256":         manifest.FieldSecurityPolicySHA256,
		"mapping_transitive_dependency_roster_sha256":   manifest.MappingTransitiveDependencyRosterSHA256,
		"documentation_claim_derivation_profile_sha256": manifest.DocumentationClaimDerivationProfileSHA256,
	}}
	return &parsedPlan{Manifest: manifest}, fieldMapping
}

func writeDependencyValidationInput(t *testing.T, dir, name string, raw []byte) artifactInput {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := readArtifactInput(path)
	if err != nil {
		t.Fatalf("readArtifactInput(%s): %v", name, err)
	}
	return input
}

func dependencyValidationJSONL(t *testing.T, rows []map[string]interface{}) []byte {
	t.Helper()
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	return output.Bytes()
}

func dependencySemanticTargetSchema(t *testing.T, id string) []byte {
	t.Helper()
	return mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     id,
		"oneOf": []interface{}{
			map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required": []string{"row_kind", "artifact", "artifact_version"},
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "artifact_manifest"},
					"artifact": map[string]interface{}{"type": "string"}, "artifact_version": map[string]interface{}{"const": "1"},
				},
			},
			map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required": []string{"row_kind", "result"},
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "validation_summary"}, "result": map[string]interface{}{"const": "candidate"},
				},
			},
		},
	})
}

func dependencySemanticProfileSchema(t *testing.T, id string) []byte {
	t.Helper()
	pinProperties := map[string]interface{}{
		"row_kind": map[string]interface{}{"const": "artifact_schema_binding"},
		"role":     map[string]interface{}{"type": "string"}, "artifact_id": map[string]interface{}{"type": "string"},
		"artifact_version": map[string]interface{}{"type": "string"}, "artifact_raw_sha256": map[string]interface{}{"type": "string"},
		"schema_role": map[string]interface{}{"type": "string"}, "schema_id": map[string]interface{}{"type": "string"},
		"schema_version": map[string]interface{}{"type": "string"}, "schema_raw_sha256": map[string]interface{}{"type": "string"},
	}
	return mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     id,
		"oneOf": []interface{}{
			map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required": []string{"row_kind", "artifact", "artifact_version", "status", "profile_id", "profile_version", "binding_count", "canonical_admission_authorized"},
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "artifact_manifest"}, "artifact": map[string]interface{}{"const": dependencySemanticValidationProfileArtifact},
					"artifact_version": map[string]interface{}{"const": "1"}, "status": map[string]interface{}{"const": dependencySemanticValidationProfileStatus},
					"profile_id": map[string]interface{}{"type": "string"}, "profile_version": map[string]interface{}{"const": "1"},
					"binding_count": map[string]interface{}{"type": "integer", "minimum": 1}, "canonical_admission_authorized": map[string]interface{}{"const": false},
				},
			},
			map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required":   []string{"row_kind", "role", "artifact_id", "artifact_version", "artifact_raw_sha256", "schema_role", "schema_id", "schema_version", "schema_raw_sha256"},
				"properties": pinProperties,
			},
			map[string]interface{}{
				"type": "object", "additionalProperties": false,
				"required": []string{"row_kind", "binding_count", "artifact_count", "schema_count", "canonical_admission_authorized", "result"},
				"properties": map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "validation_summary"}, "binding_count": map[string]interface{}{"type": "integer", "minimum": 1},
					"artifact_count": map[string]interface{}{"type": "integer", "minimum": 1}, "schema_count": map[string]interface{}{"type": "integer", "minimum": 1},
					"canonical_admission_authorized": map[string]interface{}{"const": false}, "result": map[string]interface{}{"const": dependencySemanticValidationProfileResult},
				},
			},
		},
	})
}
