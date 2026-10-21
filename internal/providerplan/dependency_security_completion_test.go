package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDependencySecuritySchemaHelpersKeepExemptionsNarrow(t *testing.T) {
	if dependencyJSONSchemaTypeDeclaration(nil) {
		t.Fatal("empty path was treated as a schema type declaration")
	}
	if dependencyJSONSchemaTypeDeclaration([]string{"properties", "field", "format"}) {
		t.Fatal("non-type keyword was treated as a schema type declaration")
	}
	if !dependencyJSONSchemaTypeDeclaration([]string{"properties", "field", "type"}) {
		t.Fatal("exact property type declaration was not recognized")
	}
	if dependencySecurityLastKey(nil) != "" || dependencySecurityLastKey([]string{"root", "leaf"}) != "leaf" {
		t.Fatal("last-key helper did not preserve its exact boundary")
	}
	if !dependencyJSONSchemaKeyword("properties") || dependencyJSONSchemaKeyword("providerPayload") {
		t.Fatal("JSON Schema keyword allowlist accepted the wrong surface")
	}

	valid := map[string]interface{}{"type": "integer", "minimum": json.Number("0"), "maximum": json.Number("64"), "multipleOf": json.Number("1")}
	if !dependencyIntegerMetadataPropertySchema([]string{"properties", "source_byte_count"}, valid) {
		t.Fatal("bounded integer metadata schema was rejected")
	}
	for _, testCase := range []struct {
		name  string
		path  []string
		value interface{}
	}{
		{name: "outside properties", path: []string{"source_byte_count"}, value: valid},
		{name: "not an object", path: []string{"properties", "source_byte_count"}, value: "integer"},
		{name: "empty object", path: []string{"properties", "source_byte_count"}, value: map[string]interface{}{}},
		{name: "noninteger type", path: []string{"properties", "source_byte_count"}, value: map[string]interface{}{"type": "number"}},
		{name: "negative bound", path: []string{"properties", "source_byte_count"}, value: map[string]interface{}{"type": "integer", "minimum": json.Number("-1")}},
		{name: "zero multiple", path: []string{"properties", "source_byte_count"}, value: map[string]interface{}{"type": "integer", "multipleOf": json.Number("0")}},
		{name: "value carrier", path: []string{"properties", "source_byte_count"}, value: map[string]interface{}{"type": "integer", "default": json.Number("12")}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if dependencyIntegerMetadataPropertySchema(testCase.path, testCase.value) {
				t.Fatal("unsafe integer metadata exemption was accepted")
			}
		})
	}
	for _, value := range []interface{}{"1", json.Number("not-an-integer"), json.Number("-1"), json.Number("9223372036854775808")} {
		if _, ok := dependencyBoundedIntegerSchemaNumber(value); ok {
			t.Fatalf("unbounded integer schema value %#v was accepted", value)
		}
	}
}

func TestDependencySecurityCredentialPlaceholdersAreSymbolicOnly(t *testing.T) {
	accepted := []struct {
		value      string
		currentKey string
		contextKey string
	}{
		{value: "<credential>", currentKey: "apikey"},
		{value: "${api_key}", currentKey: "apikey"},
		{value: "{{vault_binding}}", currentKey: "secret"},
		{value: "<auth_token>", currentKey: "field", contextKey: "authtoken"},
	}
	for _, testCase := range accepted {
		if !dependencySymbolicCredentialPlaceholder(testCase.value, testCase.currentKey, testCase.contextKey) {
			t.Fatalf("symbolic placeholder %q was rejected", testCase.value)
		}
		if dependencyCredentialScalarIsMaterial(testCase.value, testCase.currentKey, testCase.contextKey) {
			t.Fatalf("symbolic placeholder %q was classified as credential material", testCase.value)
		}
	}
	for _, value := range []string{
		"plain-secret-value",
		"<>",
		"< padded >",
		"<actual-secret-1234567890>",
		"<" + strings.Repeat("a", 129) + ">",
		"[credential]",
	} {
		if dependencySymbolicCredentialPlaceholder(value, "apikey", "") {
			t.Fatalf("credential-like value %q was accepted as symbolic", value)
		}
	}
}

func TestDependencySecurityCredentialMetadataAllowsOnlyClosedVocabulary(t *testing.T) {
	for _, testCase := range []struct {
		key   string
		value string
		want  bool
	}{
		{key: "rowkind", value: "api_operation", want: true},
		{key: "rowkind", value: "Bad Kind", want: false},
		{key: "type", value: "integer", want: true},
		{key: "type", value: "credential", want: false},
		{key: "format", value: "opaque", want: true},
		{key: "format", value: "secret-material", want: false},
		{key: "location", value: "connector_vault", want: true},
		{key: "location", value: "inline", want: false},
		{key: "description", value: "Opaque credential reference supplied by the connector vault", want: true},
		{key: "description", value: "token", want: false},
		{key: "unknown", value: "string", want: false},
	} {
		if got := dependencyCredentialMetadataValueAllowed(testCase.key, testCase.value); got != testCase.want {
			t.Fatalf("metadata %s=%q allowed=%v, want %v", testCase.key, testCase.value, got, testCase.want)
		}
	}
	if dependencyCredentialDescriptionLooksLikeProse(strings.Repeat("word ", 110)) {
		t.Fatal("oversized credential description was accepted")
	}
	if dependencyCredentialDescriptionLooksLikeProse("single_token") {
		t.Fatal("single credential-shaped token was accepted as prose")
	}
	if dependencyCredentialDescriptionLooksLikeProse("description with an_excessively_long_credential_shaped_token embedded") {
		t.Fatal("credential-shaped long token was accepted as prose")
	}
}
