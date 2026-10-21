package providerplan

import (
	"strings"
	"testing"
)

func TestDocumentationMaterializerSchemaDialectRejectsUnsupportedAndAmbiguousForms(t *testing.T) {
	tests := []struct {
		name    string
		schema  map[string]interface{}
		wantErr string
	}{
		{name: "nil root", wantErr: "root is not an object"},
		{name: "unsupported applicator", schema: map[string]interface{}{"allOf": []interface{}{}}, wantErr: `unsupported applicator "allOf"`},
		{name: "non-string reference", schema: map[string]interface{}{"$ref": true}, wantErr: "is not a string"},
		{name: "reference siblings", schema: map[string]interface{}{"$ref": "#/defs/row", "title": "row"}, wantErr: "has siblings"},
		{name: "root reference cycle", schema: map[string]interface{}{"$ref": "#"}, wantErr: "root-reference cycle"},
		{name: "nested one of", schema: map[string]interface{}{"properties": map[string]interface{}{"nested": map[string]interface{}{"oneOf": []interface{}{map[string]interface{}{}}}}}, wantErr: "composed below the root"},
		{name: "root one of sibling", schema: map[string]interface{}{"oneOf": []interface{}{map[string]interface{}{}}, "type": "object"}, wantErr: "unsupported sibling"},
		{name: "empty one of", schema: map[string]interface{}{"oneOf": []interface{}{}}, wantErr: "empty or malformed"},
		{name: "composed type", schema: map[string]interface{}{"type": []interface{}{"object"}}, wantErr: "composed rather than"},
		{name: "schema valued additional properties", schema: map[string]interface{}{"additionalProperties": map[string]interface{}{}}, wantErr: "schema-valued"},
		{name: "tuple items", schema: map[string]interface{}{"items": []interface{}{}}, wantErr: "items at $ is composed"},
		{name: "malformed properties", schema: map[string]interface{}{"properties": []interface{}{}}, wantErr: "properties at $ is malformed"},
		{name: "non schema child", schema: map[string]interface{}{"properties": map[string]interface{}{"row": "not-a-schema"}}, wantErr: "neither an object nor boolean"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDocumentationMaterializerSchemaDialect(test.schema)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("validateDocumentationMaterializerSchemaDialect() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestDependencyValidationProfilePrimitiveBoundariesRejectTampering(t *testing.T) {
	validDigest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name string
		pin  dependencySemanticValidationPin
		want string
	}{
		{name: "wrong role", pin: dependencySemanticValidationPin{Role: "wrong", ID: "profile", Version: "1", RawSHA256: validDigest}, want: "does not equal"},
		{name: "bad coordinate", pin: dependencySemanticValidationPin{Role: "expected", ID: " profile", Version: "1", RawSHA256: validDigest}, want: "empty, padded"},
		{name: "bad digest", pin: dependencySemanticValidationPin{Role: "expected", ID: "profile", Version: "1", RawSHA256: "UPPER"}, want: "malformed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateDependencySemanticValidationPin("test", test.pin, "expected")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateDependencySemanticValidationPin() error = %v, want %q", err, test.want)
			}
		})
	}

	for _, test := range []struct {
		name string
		row  map[string]interface{}
		want string
	}{
		{name: "absent role", row: map[string]interface{}{}, want: "role is absent"},
		{name: "absent artifact id", row: map[string]interface{}{"role": "role"}, want: "artifact_id is absent"},
		{name: "absent artifact version", row: map[string]interface{}{"role": "role", "artifact_id": "artifact"}, want: "artifact_version is absent"},
		{name: "malformed artifact digest", row: map[string]interface{}{"role": "role", "artifact_id": "artifact", "artifact_version": "1", "artifact_raw_sha256": "not-a-digest", "schema_role": "schema", "schema_id": "schema", "schema_version": "1", "schema_raw_sha256": validDigest}, want: "artifact_raw_sha256"},
		{name: "absent schema role", row: map[string]interface{}{"role": "role", "artifact_id": "artifact", "artifact_version": "1", "artifact_raw_sha256": validDigest}, want: "schema_role is absent"},
		{name: "absent schema id", row: map[string]interface{}{"role": "role", "artifact_id": "artifact", "artifact_version": "1", "artifact_raw_sha256": validDigest, "schema_role": "schema"}, want: "schema_id is absent"},
		{name: "absent schema version", row: map[string]interface{}{"role": "role", "artifact_id": "artifact", "artifact_version": "1", "artifact_raw_sha256": validDigest, "schema_role": "schema", "schema_id": "schema"}, want: "schema_version is absent"},
		{name: "malformed schema digest", row: map[string]interface{}{"role": "role", "artifact_id": "artifact", "artifact_version": "1", "artifact_raw_sha256": validDigest, "schema_role": "schema", "schema_id": "schema", "schema_version": "1", "schema_raw_sha256": "not-a-digest"}, want: "schema_raw_sha256"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeDependencySemanticProfileBinding(test.row)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("decodeDependencySemanticProfileBinding() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDerivationTargetAuthorityRejectsUnsealedAndMalformedProofs(t *testing.T) {
	validDigest := strings.Repeat("b", 64)
	if _, err := (dependencySemanticDerivationTargetSchemaAuthority{}).validateDocumentationDerivationTarget("role", "row_kind"); err == nil || !strings.Contains(err.Error(), "absent or unsealed") {
		t.Fatalf("unsealed authority error = %v", err)
	}

	for _, test := range []struct {
		name  string
		role  string
		entry dependencySemanticValidatedArtifact
		want  string
	}{
		{name: "noncanonical role", role: " bad", entry: dependencySemanticValidatedArtifact{artifactSHA256: validDigest}, want: "noncanonical"},
		{name: "bad artifact digest", role: "role", entry: dependencySemanticValidatedArtifact{artifactSHA256: "bad"}, want: "no exact validated artifact digest"},
		{name: "bad schema role", role: "role", entry: dependencySemanticValidatedArtifact{artifactSHA256: validDigest, schemaRole: " bad"}, want: "no exact validation-profile schema role"},
		{name: "bad schema coordinate", role: "role", entry: dependencySemanticValidatedArtifact{artifactSHA256: validDigest, schemaRole: "schema", schemaID: "", schemaVersion: "1"}, want: "schema_id"},
		{name: "bad schema digest", role: "role", entry: dependencySemanticValidatedArtifact{artifactSHA256: validDigest, schemaRole: "schema", schemaID: "schema", schemaVersion: "1", schemaSHA256: "bad"}, want: "no exact schema digest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof := dependencySemanticValidationProof{seal: dependencySemanticValidationAuthority, byRole: map[string]dependencySemanticValidatedArtifact{test.role: test.entry}}
			_, err := resolveDependencySemanticDerivationTargetSchemaAuthority(proof, map[string]artifactInput{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("resolveDependencySemanticDerivationTargetSchemaAuthority() error = %v, want %q", err, test.want)
			}
		})
	}
}
