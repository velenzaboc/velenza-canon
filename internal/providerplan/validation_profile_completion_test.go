package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidationProfileCompletionBindingAndJSONBoundaries(t *testing.T) {
	validDigest := strings.Repeat("a", 64)
	valid := validationProfileBinding{
		Role:            "primary",
		ArtifactID:      "artifact",
		ArtifactVersion: "v1",
		ArtifactSHA256:  validDigest,
		SchemaID:        "schema",
		SchemaVersion:   "v1",
		SchemaSHA256:    validDigest,
	}
	if err := validateValidationProfileBindingShape(valid); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*validationProfileBinding)
		want   string
	}{
		{name: "padded role", mutate: func(v *validationProfileBinding) { v.Role = " primary" }, want: "role"},
		{name: "control artifact id", mutate: func(v *validationProfileBinding) { v.ArtifactID = "artifact\n" }, want: "artifact_id"},
		{name: "empty schema version", mutate: func(v *validationProfileBinding) { v.SchemaVersion = "" }, want: "schema_version"},
		{name: "uppercase artifact digest", mutate: func(v *validationProfileBinding) { v.ArtifactSHA256 = strings.Repeat("A", 64) }, want: "artifact_sha256"},
		{name: "short schema digest", mutate: func(v *validationProfileBinding) { v.SchemaSHA256 = "abc" }, want: "schema_sha256"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			err := validateValidationProfileBindingShape(candidate)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}

	var decoded map[string]interface{}
	if err := decodeOneValidationProfileJSON([]byte(`{"n":1}`), &decoded); err != nil {
		t.Fatalf("decode one JSON value: %v", err)
	}
	if got, ok := decoded["n"].(json.Number); !ok || got.String() != "1" {
		t.Fatalf("decoded number = %#v, want json.Number(1)", decoded["n"])
	}
	for _, raw := range [][]byte{[]byte(`{"n":1} {"n":2}`), []byte(`{"n":1} trailing`), []byte(`{"n":1,"n":2}`)} {
		if err := decodeOneValidationProfileJSON(raw, &decoded); err == nil {
			t.Fatalf("decodeOneValidationProfileJSON(%q) unexpectedly succeeded", raw)
		}
	}
	if got := unknownValidationProfileDiscriminatorValue(map[string]struct{}{unknownValidationRowKind: {}, unknownValidationRowKind + "_1": {}}); got != unknownValidationRowKind+"_2" {
		t.Fatalf("unknown discriminator = %q", got)
	}
}

func TestValidationProfileCompletionNumericBoundaries(t *testing.T) {
	if err := validateValidationProfileSchemaNumbers(map[string]interface{}{
		"array": []interface{}{json.Number("1"), json.Number("0.5")},
	}, "$"); err != nil {
		t.Fatalf("exact schema numbers rejected: %v", err)
	}
	for _, value := range []interface{}{
		map[string]interface{}{"multipleOf": json.Number("2")},
		json.Number("9007199254740993"),
	} {
		if err := validateValidationProfileSchemaNumbers(value, "$"); err == nil {
			t.Fatalf("unsafe schema value %#v unexpectedly accepted", value)
		}
	}

	normalized, err := normalizeValidationProfileNumbers(map[string]interface{}{
		"integer": json.Number("42"),
		"array":   []interface{}{json.Number("18446744073709551615"), json.Number("0.5")},
	}, "$")
	if err != nil {
		t.Fatalf("normalize exact numbers: %v", err)
	}
	object := normalized.(map[string]interface{})
	if got, ok := object["integer"].(int64); !ok || got != 42 {
		t.Fatalf("normalized integer = %#v", object["integer"])
	}
	array := object["array"].([]interface{})
	if got, ok := array[0].(uint64); !ok || got != ^uint64(0) {
		t.Fatalf("normalized uint64 = %#v", array[0])
	}
	if got, ok := array[1].(float64); !ok || got != 0.5 {
		t.Fatalf("normalized float = %#v", array[1])
	}
	if _, err := normalizeValidationProfileNumbers(json.Number("0.1"), "$"); err == nil {
		t.Fatal("inexact decimal unexpectedly normalized")
	}
	for _, test := range []struct {
		number json.Number
		ok     bool
	}{
		{number: json.Number("-2"), ok: true},
		{number: json.Number("0.5"), ok: true},
		{number: json.Number("0.1"), ok: false},
		{number: json.Number("not-a-number"), ok: false},
	} {
		_, got := exactValidationProfileRuntimeNumber(test.number)
		if got != test.ok {
			t.Fatalf("exactValidationProfileRuntimeNumber(%q) ok = %t, want %t", test.number, got, test.ok)
		}
	}
}

func TestValidationProfileCompletionDiscriminatorAndObjectExclusion(t *testing.T) {
	for _, test := range []struct {
		name   string
		schema map[string]interface{}
		want   bool
	}{
		{name: "string type", schema: map[string]interface{}{"type": "string"}, want: true},
		{name: "type union without object", schema: map[string]interface{}{"type": []interface{}{"null", "string"}}, want: true},
		{name: "type union with object", schema: map[string]interface{}{"type": []interface{}{"object", "string"}}, want: false},
		{name: "scalar const", schema: map[string]interface{}{"const": "literal"}, want: true},
		{name: "object const", schema: map[string]interface{}{"const": map[string]interface{}{}}, want: false},
		{name: "scalar enum", schema: map[string]interface{}{"enum": []interface{}{1, "x"}}, want: true},
		{name: "object enum", schema: map[string]interface{}{"enum": []interface{}{map[string]interface{}{}}}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validationProfileSchemaExcludesObjects(test.schema); got != test.want {
				t.Fatalf("excludes objects = %t, want %t", got, test.want)
			}
		})
	}
	if !validationProfileSchemaHasLocalObjectClosure(map[string]interface{}{"unevaluatedProperties": false}) {
		t.Fatal("unevaluatedProperties:false did not close object")
	}
	if validationProfileSchemaHasLocalObjectClosure(map[string]interface{}{"additionalProperties": true}) {
		t.Fatal("additionalProperties:true closed object")
	}

	values, ok := finiteValidationProfileStringValues(map[string]interface{}{"const": "fixed"})
	if !ok || len(values) != 1 {
		t.Fatalf("const values = %#v, %t", values, ok)
	}
	values, ok = finiteValidationProfileStringValues(map[string]interface{}{"enum": []interface{}{"one", "two"}})
	if !ok || len(values) != 2 {
		t.Fatalf("enum values = %#v, %t", values, ok)
	}
	for _, schema := range []map[string]interface{}{
		{"const": " padded"},
		{"enum": []interface{}{}},
		{"enum": []interface{}{"same", "same"}},
		{"enum": []interface{}{"valid", 3}},
	} {
		if _, ok := finiteValidationProfileStringValues(schema); ok {
			t.Fatalf("non-finite schema accepted: %#v", schema)
		}
	}

	closed := map[string]interface{}{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []interface{}{"kind"},
		"properties": map[string]interface{}{
			"kind": map[string]interface{}{"enum": []interface{}{"alpha", "beta"}},
		},
	}
	candidates, applicable, err := validationProfileDiscriminatorCandidates(closed, closed, "$", map[string]bool{}, 1, &validationProfileWalkBudget{})
	if err != nil || !applicable || len(candidates["kind"]) != 2 {
		t.Fatalf("candidates = %#v, applicable=%t, err=%v", candidates, applicable, err)
	}
	discriminator, err := validationProfileSchemaDiscriminator(closed)
	if err != nil || discriminator.property != "kind" || len(discriminator.values) != 2 {
		t.Fatalf("discriminator = %#v, err=%v", discriminator, err)
	}
	for _, node := range []interface{}{true, false, "not-schema"} {
		_, _, err := validationProfileDiscriminatorCandidates(node, closed, "$", map[string]bool{}, 1, &validationProfileWalkBudget{})
		if node == "not-schema" && err == nil {
			t.Fatal("scalar schema node unexpectedly accepted")
		}
	}
}

func TestValidationProfileCompletionClosureAndLocalPointers(t *testing.T) {
	root := map[string]interface{}{
		"a/b~c": []interface{}{map[string]interface{}{"closed": true}},
		"$defs": map[string]interface{}{
			"closed": map[string]interface{}{"type": "object", "additionalProperties": false},
		},
	}
	value, path, err := resolveValidationProfileLocalJSONPointer(root, "#/a~1b~0c/0/closed")
	if err != nil || value != true || path != "$/a~1b~0c/0/closed" {
		t.Fatalf("pointer result = %#v, %q, %v", value, path, err)
	}
	value, path, err = resolveValidationProfileLocalJSONPointer(root, "#")
	returnedRoot, isRoot := value.(map[string]interface{})
	if err != nil || !isRoot || len(returnedRoot) != len(root) || path != "$" {
		t.Fatalf("root pointer = %#v, %q, %v", value, path, err)
	}
	for _, ref := range []string{"https://example.invalid/schema", "#anchor", "#/missing", "#/a~1b~0c/-1", "#/a~2b"} {
		if _, _, err := resolveValidationProfileLocalJSONPointer(root, ref); err == nil {
			t.Fatalf("reference %q unexpectedly resolved", ref)
		}
	}
	if err := validateValidationProfileClosedObjectShapes(map[string]interface{}{"$ref": "#/$defs/closed", "$defs": root["$defs"]}); err != nil {
		t.Fatalf("local reference to closed object rejected: %v", err)
	}
	for _, schema := range []map[string]interface{}{
		{},
		{"patternProperties": map[string]interface{}{}, "additionalProperties": false},
		{"type": "object", "additionalProperties": true},
	} {
		if err := validateValidationProfileClosedObjectShapes(schema); err == nil {
			t.Fatalf("open or pattern schema accepted: %#v", schema)
		}
	}
	closed, err := validationProfileSchemaProvesClosedObject(false, root, "$", map[string]bool{}, 1, &validationProfileWalkBudget{})
	if err != nil || !closed {
		t.Fatalf("false schema should exclude all objects: closed=%t err=%v", closed, err)
	}
}
