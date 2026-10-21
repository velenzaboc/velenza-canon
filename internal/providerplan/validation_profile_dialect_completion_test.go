package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

// The materializer dialect gate exists so the generic JSON Schema validator and
// the target-member materializer can never assign different meaning to the same
// exact schema bytes. Every refusal below is a schema shape the validator would
// accept but the materializer could not traverse identically.
func TestValidateDocumentationMaterializerSchemaDialectRefusesUntraversableShapes(t *testing.T) {
	for _, test := range []struct {
		name string
		root map[string]interface{}
		want string
	}{
		{
			name: "nil root",
			root: nil,
			want: "schema root is not an object",
		},
		{
			name: "composition applicator the materializer cannot compose",
			root: map[string]interface{}{"allOf": []interface{}{}},
			want: `unsupported applicator "allOf"`,
		},
		{
			name: "conditional applicator",
			root: map[string]interface{}{"if": map[string]interface{}{}},
			want: `unsupported applicator "if"`,
		},
		{
			name: "dynamic reference applicator",
			root: map[string]interface{}{"$dynamicRef": "#meta"},
			want: `unsupported applicator "$dynamicRef"`,
		},
		{
			name: "pattern-keyed properties",
			root: map[string]interface{}{"patternProperties": map[string]interface{}{}},
			want: `unsupported applicator "patternProperties"`,
		},
		{
			name: "non-string reference",
			root: map[string]interface{}{"$ref": json.Number("7")},
			want: "$ref at $ is not a string",
		},
		{
			name: "reference with siblings",
			root: map[string]interface{}{"$ref": "#/$defs/thing", "title": "sibling"},
			want: "has siblings the materializer cannot compose exactly",
		},
		{
			name: "external reference",
			root: map[string]interface{}{"$ref": "https://example.invalid/schema.json"},
			want: "is not a simple local JSON Pointer",
		},
		{
			name: "root self reference",
			root: map[string]interface{}{"$ref": "#"},
			want: "forms an unsupported root-reference cycle",
		},
		{
			name: "oneOf composed below the root",
			root: map[string]interface{}{
				"properties": map[string]interface{}{
					"nested": map[string]interface{}{"oneOf": []interface{}{true}},
				},
			},
			want: "composed below the root row-variant union",
		},
		{
			name: "root oneOf with an uninterpretable sibling",
			root: map[string]interface{}{
				"oneOf": []interface{}{true},
				"type":  "object",
			},
			want: `unsupported sibling "type"`,
		},
		{
			name: "empty root oneOf",
			root: map[string]interface{}{"oneOf": []interface{}{}},
			want: "is empty or malformed",
		},
		{
			name: "composed type union",
			root: map[string]interface{}{"type": []interface{}{"object", "null"}},
			want: "composed rather than one exact materializer type",
		},
		{
			name: "schema-valued additionalProperties",
			root: map[string]interface{}{"additionalProperties": map[string]interface{}{"type": "string"}},
			want: "is schema-valued and cannot be interpreted exactly by the materializer",
		},
		{
			name: "schema-valued unevaluatedProperties",
			root: map[string]interface{}{"unevaluatedProperties": map[string]interface{}{"type": "string"}},
			want: "is schema-valued and cannot be interpreted exactly by the materializer",
		},
		{
			name: "tuple-composed items",
			root: map[string]interface{}{"items": []interface{}{map[string]interface{}{"type": "string"}}},
			want: "items at $ is composed",
		},
		{
			name: "malformed properties container",
			root: map[string]interface{}{"properties": "not-an-object"},
			want: "properties at $ is malformed",
		},
		{
			name: "malformed defs container",
			root: map[string]interface{}{"$defs": []interface{}{}},
			want: "$defs at $ is malformed",
		},
		{
			name: "scalar in a schema position",
			root: map[string]interface{}{
				"properties": map[string]interface{}{"nested": "string"},
			},
			want: "is neither an object nor boolean",
		},
		{
			name: "nested reference into a scalar",
			root: map[string]interface{}{
				"scalar":     "value",
				"properties": map[string]interface{}{"nested": map[string]interface{}{"$ref": "#/scalar/deeper"}},
			},
			want: "is not a simple local JSON Pointer",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateDocumentationMaterializerSchemaDialect(test.root)
			if err == nil {
				t.Fatalf("a schema outside the exact materializer subset was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestValidateDocumentationMaterializerSchemaDialectAcceptsTheExactSubset(t *testing.T) {
	// The fixture schema is the shape the production profile actually uses: a
	// root oneOf over local $ref branches into closed $defs objects.
	var root map[string]interface{}
	if err := json.Unmarshal(minimalValidationProfileSchemaBytes(t, "urn:test:schema:closed-jsonl", validationProfileDraft202012), &root); err != nil {
		t.Fatal(err)
	}
	if err := validateDocumentationMaterializerSchemaDialect(root); err != nil {
		t.Fatalf("the exact materializer subset was rejected: %v", err)
	}

	// A boolean schema and a single-valued items schema are both inside the
	// subset, so the walk must terminate on them rather than refuse.
	if err := validateDocumentationMaterializerSchemaDialect(map[string]interface{}{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]interface{}{
			"anything": true,
			"list":     map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
		},
	}); err != nil {
		t.Fatalf("boolean and single-schema items forms were rejected: %v", err)
	}
}

// Local JSON Pointer resolution is the only reference mechanism the closure and
// dialect proofs accept, so every non-local or unresolvable form must refuse
// rather than silently resolve to something else.
func TestResolveValidationProfileLocalJSONPointerRefusesNonLocalAndUnresolvableRefs(t *testing.T) {
	root := map[string]interface{}{
		"$defs":  map[string]interface{}{"thing": map[string]interface{}{"type": "string"}},
		"list":   []interface{}{"first", "second"},
		"scalar": "value",
		"a/b":    "slash-escaped",
		"a~b":    "tilde-escaped",
	}
	for _, test := range []struct {
		name string
		ref  string
		want string
	}{
		{name: "malformed url", ref: "http://[::1", want: "malformed schema reference"},
		{name: "network reference", ref: "https://example.invalid/schema.json", want: "external schema reference"},
		{name: "relative file reference", ref: "schema.json", want: "external schema reference"},
		{name: "internal anchor", ref: "#thing", want: "internal anchor reference"},
		{name: "absent pointer", ref: "#/$defs/absent", want: "does not resolve"},
		{name: "array index out of range", ref: "#/list/9", want: "invalid array index"},
		{name: "non-numeric array index", ref: "#/list/first", want: "invalid array index"},
		{name: "traversal through a scalar", ref: "#/scalar/deeper", want: "traverses a scalar"},
		{name: "malformed pointer escape", ref: "#/~2bad", want: "malformed local JSON Pointer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := resolveValidationProfileLocalJSONPointer(root, test.ref); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}

	// The root reference resolves to the root itself; the dialect gate, not the
	// pointer resolver, is what refuses it as a cycle.
	target, path, err := resolveValidationProfileLocalJSONPointer(root, "#")
	if err != nil {
		t.Fatalf("root reference error = %v", err)
	}
	if path != "$" {
		t.Fatalf("root reference path = %q, want %q", path, "$")
	}
	if resolved, ok := target.(map[string]interface{}); !ok || len(resolved) != len(root) {
		t.Fatalf("root reference did not resolve to the schema root")
	}

	for _, test := range []struct {
		name string
		ref  string
		want string
	}{
		{name: "escaped slash token", ref: "#/a~1b", want: "slash-escaped"},
		{name: "escaped tilde token", ref: "#/a~0b", want: "tilde-escaped"},
		{name: "array element", ref: "#/list/1", want: "second"},
	} {
		t.Run(test.name, func(t *testing.T) {
			target, _, err := resolveValidationProfileLocalJSONPointer(root, test.ref)
			if err != nil {
				t.Fatalf("error = %v, want the escaped token to resolve", err)
			}
			if got, ok := target.(string); !ok || got != test.want {
				t.Fatalf("resolved = %v, want %q", target, test.want)
			}
		})
	}
}

func TestValidateDependencySemanticValidationPinRefusesInexactCoordinates(t *testing.T) {
	const role = "dependency_semantic_validation_profile"
	digest := validationProfileSHA256([]byte("profile bytes"))
	for _, test := range []struct {
		name string
		pin  dependencySemanticValidationPin
		want string
	}{
		{
			name: "role does not equal the expected pin role",
			pin:  dependencySemanticValidationPin{Role: "some_other_role", ID: "profile", Version: "1", RawSHA256: digest},
			want: "does not equal",
		},
		{
			name: "empty identity coordinate",
			pin:  dependencySemanticValidationPin{Role: role, ID: "", Version: "1", RawSHA256: digest},
			want: "is empty, padded, or contains a control character",
		},
		{
			name: "padded version coordinate",
			pin:  dependencySemanticValidationPin{Role: role, ID: "profile", Version: " 1 ", RawSHA256: digest},
			want: "is empty, padded, or contains a control character",
		},
		{
			name: "malformed raw digest",
			pin:  dependencySemanticValidationPin{Role: role, ID: "profile", Version: "1", RawSHA256: strings.ToUpper(digest)},
			want: "raw_sha256",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateDependencySemanticValidationPin("profile", test.pin, role)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}

	if err := validateDependencySemanticValidationPin(
		"profile",
		dependencySemanticValidationPin{Role: role, ID: "profile", Version: "1", RawSHA256: digest},
		role,
	); err != nil {
		t.Fatalf("an exact pin was rejected: %v", err)
	}
}

func TestDecodeDependencySemanticProfileBindingRefusesIncompleteRows(t *testing.T) {
	digest := validationProfileSHA256([]byte("artifact bytes"))
	schemaDigest := validationProfileSHA256([]byte("schema bytes"))
	exact := func() map[string]interface{} {
		return map[string]interface{}{
			"role":                "field_security_policy",
			"artifact_id":         "artifact",
			"artifact_version":    "1",
			"artifact_raw_sha256": digest,
			"schema_role":         "schema_role",
			"schema_id":           "schema",
			"schema_version":      "1",
			"schema_raw_sha256":   schemaDigest,
		}
	}

	for _, field := range []string{
		"role", "artifact_id", "artifact_version", "artifact_raw_sha256",
		"schema_role", "schema_id", "schema_version", "schema_raw_sha256",
	} {
		t.Run("absent "+field, func(t *testing.T) {
			row := exact()
			delete(row, field)
			if _, err := decodeDependencySemanticProfileBinding(row); err == nil ||
				!strings.Contains(err.Error(), field) {
				t.Fatalf("error = %v, want a refusal naming %q", err, field)
			}
		})
	}

	// An uppercase digest is a well-formed string but not the exact lowercase
	// digest form, so the two digest fields must refuse it specifically.
	for _, field := range []string{"artifact_raw_sha256", "schema_raw_sha256"} {
		t.Run("uppercase "+field, func(t *testing.T) {
			row := exact()
			row[field] = strings.ToUpper(digest)
			if _, err := decodeDependencySemanticProfileBinding(row); err == nil ||
				!strings.Contains(err.Error(), "malformed") {
				t.Fatalf("error = %v, want a malformed-digest refusal", err)
			}
		})
	}

	parsed, err := decodeDependencySemanticProfileBinding(exact())
	if err != nil {
		t.Fatalf("an exact binding row was rejected: %v", err)
	}
	if parsed.Role != "field_security_policy" || parsed.ArtifactRawSHA256 != digest || parsed.SchemaRawSHA256 != schemaDigest {
		t.Fatalf("decoded binding = %+v, want the exact supplied coordinates", parsed)
	}
}

func documentationDerivationTargetProofFixture(t *testing.T, role string) (dependencySemanticValidationProof, map[string]artifactInput) {
	t.Helper()
	schemaBytes := minimalValidationProfileSchemaBytes(t, "urn:test:schema:closed-jsonl", validationProfileDraft202012)
	schemaDigest := validationProfileSHA256(schemaBytes)
	proof := dependencySemanticValidationProof{
		seal: dependencySemanticValidationAuthority,
		byRole: map[string]dependencySemanticValidatedArtifact{
			role: {
				artifactSHA256: validationProfileSHA256([]byte("target artifact bytes")),
				schemaRole:     "documentation_target_schema",
				schemaID:       "urn:test:schema:closed-jsonl",
				schemaVersion:  "1",
				schemaSHA256:   schemaDigest,
			},
		},
	}
	dependencies := map[string]artifactInput{
		schemaDigest: {Raw: schemaBytes, SHA256: schemaDigest, Path: "target-schema.json"},
	}
	return proof, dependencies
}

func TestResolveDependencySemanticDerivationTargetSchemaAuthorityRetainsSchemaProvenDiscriminators(t *testing.T) {
	const role = "documentation_claim_derivation_profile"
	proof, dependencies := documentationDerivationTargetProofFixture(t, role)

	authority, err := resolveDependencySemanticDerivationTargetSchemaAuthority(proof, dependencies)
	if err != nil {
		t.Fatalf("an exact schema-validation proof was rejected: %v", err)
	}
	retained, ok := authority.byRole[role]
	if !ok {
		t.Fatalf("authority retained no schema for role %q", role)
	}
	// The discriminator must come from the exact schema bytes, never from a
	// binary-owned row vocabulary.
	if retained.discriminatorProperty != "row_kind" {
		t.Fatalf("discriminator property = %q, want the schema-proven row_kind", retained.discriminatorProperty)
	}
	for _, want := range []string{"artifact_manifest", "record"} {
		if _, present := retained.discriminatorValues[want]; !present {
			t.Fatalf("schema-proven roster is missing %q", want)
		}
	}
	if len(retained.discriminatorValues) != 2 {
		t.Fatalf("schema-proven roster = %v, want exactly the two closed row kinds", retained.discriminatorValues)
	}
}

func TestResolveDependencySemanticDerivationTargetSchemaAuthorityRefusesInexactProofs(t *testing.T) {
	const role = "documentation_claim_derivation_profile"

	if _, err := resolveDependencySemanticDerivationTargetSchemaAuthority(
		dependencySemanticValidationProof{}, map[string]artifactInput{},
	); err == nil || !strings.Contains(err.Error(), "requires an exact schema-validation proof") {
		t.Fatalf("unsealed proof error = %v, want a proof-seal refusal", err)
	}

	for _, test := range []struct {
		name    string
		mutate  func(*dependencySemanticValidationProof, map[string]artifactInput)
		wantKey string
	}{
		{
			name: "noncanonical artifact role",
			mutate: func(proof *dependencySemanticValidationProof, _ map[string]artifactInput) {
				proof.byRole[" padded_role "] = proof.byRole[role]
				delete(proof.byRole, role)
			},
			wantKey: "is noncanonical",
		},
		{
			name: "validated artifact digest is not exact",
			mutate: func(proof *dependencySemanticValidationProof, _ map[string]artifactInput) {
				binding := proof.byRole[role]
				binding.artifactSHA256 = "not-a-sha256"
				proof.byRole[role] = binding
			},
			wantKey: "no exact validated artifact digest",
		},
		{
			name: "schema role is absent",
			mutate: func(proof *dependencySemanticValidationProof, _ map[string]artifactInput) {
				binding := proof.byRole[role]
				binding.schemaRole = ""
				proof.byRole[role] = binding
			},
			wantKey: "no exact validation-profile schema role",
		},
		{
			name: "schema coordinate is noncanonical",
			mutate: func(proof *dependencySemanticValidationProof, _ map[string]artifactInput) {
				binding := proof.byRole[role]
				binding.schemaVersion = ""
				proof.byRole[role] = binding
			},
			wantKey: "is empty, padded, or contains a control character",
		},
		{
			name: "schema digest is malformed",
			mutate: func(proof *dependencySemanticValidationProof, _ map[string]artifactInput) {
				binding := proof.byRole[role]
				binding.schemaSHA256 = "not-a-sha256"
				proof.byRole[role] = binding
			},
			wantKey: "no exact schema digest",
		},
		{
			name: "schema bytes are not supplied",
			mutate: func(_ *dependencySemanticValidationProof, dependencies map[string]artifactInput) {
				for digest := range dependencies {
					delete(dependencies, digest)
				}
			},
			wantKey: "is not supplied",
		},
		{
			name: "supplied schema bytes do not match the pinned digest",
			mutate: func(proof *dependencySemanticValidationProof, dependencies map[string]artifactInput) {
				digest := proof.byRole[role].schemaSHA256
				supplied := dependencies[digest]
				supplied.Raw = []byte(`{"different":"bytes"}`)
				dependencies[digest] = supplied
			},
			wantKey: "does not bind its exact supplied bytes",
		},
		{
			name: "schema is supplied as a structured JSONL artifact",
			mutate: func(proof *dependencySemanticValidationProof, dependencies map[string]artifactInput) {
				digest := proof.byRole[role].schemaSHA256
				supplied := dependencies[digest]
				supplied.Structured = true
				dependencies[digest] = supplied
			},
			wantKey: "must be one exact JSON Schema document",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof, dependencies := documentationDerivationTargetProofFixture(t, role)
			test.mutate(&proof, dependencies)
			_, err := resolveDependencySemanticDerivationTargetSchemaAuthority(proof, dependencies)
			if err == nil {
				t.Fatalf("an inexact derivation-target proof was accepted")
			}
			if !strings.Contains(err.Error(), test.wantKey) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.wantKey)
			}
		})
	}
}

func TestValidateDocumentationDerivationTargetBindsRowKindToItsSchemaProvenRoster(t *testing.T) {
	const role = "documentation_claim_derivation_profile"
	proof, dependencies := documentationDerivationTargetProofFixture(t, role)
	authority, err := resolveDependencySemanticDerivationTargetSchemaAuthority(proof, dependencies)
	if err != nil {
		t.Fatal(err)
	}

	resolution, err := authority.validateDocumentationDerivationTarget(role, "record")
	if err != nil {
		t.Fatalf("a schema-proven row kind was rejected: %v", err)
	}
	if resolution.targetRowKind != "record" || resolution.artifactRole != role {
		t.Fatalf("resolution = %+v, want the exact requested target coordinate", resolution)
	}
	// The resolution must carry a copy of the schema bytes so a later mutation
	// of the returned slice cannot change the retained authority.
	if len(resolution.schemaBytes) == 0 {
		t.Fatalf("resolution carries no schema bytes")
	}
	resolution.schemaBytes[0] = 'X'
	again, err := authority.validateDocumentationDerivationTarget(role, "record")
	if err != nil {
		t.Fatal(err)
	}
	if again.schemaBytes[0] == 'X' {
		t.Fatalf("mutating returned schema bytes changed the retained authority")
	}

	for _, test := range []struct {
		name      string
		authority dependencySemanticDerivationTargetSchemaAuthority
		role      string
		rowKind   string
		want      string
	}{
		{
			name:      "unsealed authority",
			authority: dependencySemanticDerivationTargetSchemaAuthority{},
			role:      role,
			rowKind:   "record",
			want:      "absent or unsealed",
		},
		{
			name:      "noncanonical artifact role",
			authority: authority,
			role:      " padded ",
			rowKind:   "record",
			want:      "artifact role",
		},
		{
			name:      "noncanonical row kind",
			authority: authority,
			role:      role,
			rowKind:   "",
			want:      "row kind",
		},
		{
			name:      "artifact role outside the proof",
			authority: authority,
			role:      "an_unproven_role",
			rowKind:   "record",
			want:      "not present in the exact schema-validation proof",
		},
		{
			name:      "row kind outside the schema-proven roster",
			authority: authority,
			role:      role,
			rowKind:   "an_undeclared_row_kind",
			want:      "outside artifact role",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.authority.validateDocumentationDerivationTarget(test.role, test.rowKind); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

// Exactly one JSON value may be decoded from a supplied artifact. The
// duplicate-key scanner is the first gate inside decodeOneValidationProfileJSON,
// so it is what reports a second value or trailing garbage; the decoder's own
// multiple-value guard stands behind it as defense in depth.
func TestDecodeOneValidationProfileJSONRefusesMultipleAndTrailingValues(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "two whole values", raw: `{"a":1} {"b":2}`, want: "trailing JSON token"},
		{name: "trailing garbage", raw: `{"a":1} not-json`, want: "invalid character"},
		{name: "duplicate keys", raw: `{"a":1,"a":2}`, want: "duplicate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var target interface{}
			if err := decodeOneValidationProfileJSON([]byte(test.raw), &target); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

// Exact numeric preservation is a security property: a value that silently
// rounds through float64 would let two different source amounts compare equal.
func TestExactValidationProfileRuntimeNumberPreservesWidthWithoutRounding(t *testing.T) {
	for _, test := range []struct {
		name   string
		lexeme string
		want   interface{}
	}{
		{name: "signed integer", lexeme: "-42", want: int64(-42)},
		{name: "integer beyond IEEE exact range", lexeme: "9007199254740993", want: int64(9007199254740993)},
		{name: "unsigned integer beyond int64", lexeme: "18446744073709551615", want: uint64(18446744073709551615)},
		{name: "exact fraction", lexeme: "0.5", want: 0.5},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := exactValidationProfileRuntimeNumber(json.Number(test.lexeme))
			if !ok {
				t.Fatalf("an exactly representable literal %s was refused", test.lexeme)
			}
			if got != test.want {
				t.Fatalf("value = %#v, want %#v", got, test.want)
			}
		})
	}

	// A decimal fraction with no exact binary representation must fail closed
	// rather than round to the nearest float64.
	if _, ok := exactValidationProfileRuntimeNumber(json.Number("0.1")); ok {
		t.Fatalf("0.1 was accepted, but it cannot be represented exactly")
	}
	if _, ok := exactValidationProfileRuntimeNumber(json.Number("not-a-number")); ok {
		t.Fatalf("a malformed numeric lexeme was accepted")
	}
}

func TestUnknownValidationProfileDiscriminatorValueAvoidsDeclaredRowKinds(t *testing.T) {
	if got := unknownValidationProfileDiscriminatorValue(map[string]struct{}{}); got != unknownValidationRowKind {
		t.Fatalf("value = %q, want the base unknown row kind", got)
	}
	// When the artifact itself declares the probe value, the probe must move to
	// a value outside the roster, or the unknown-shape check would be vacuous.
	occupied := map[string]struct{}{
		unknownValidationRowKind:        {},
		unknownValidationRowKind + "_1": {},
	}
	got := unknownValidationProfileDiscriminatorValue(occupied)
	if _, declared := occupied[got]; declared {
		t.Fatalf("probe value %q collides with a declared row kind", got)
	}
}

func TestValidationProfileSchemaExcludesObjectsReadsOnlyExactTypeEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		schema map[string]interface{}
		want   bool
	}{
		{name: "string type", schema: map[string]interface{}{"type": "string"}, want: true},
		{name: "object type", schema: map[string]interface{}{"type": "object"}, want: false},
		{name: "union without object", schema: map[string]interface{}{"type": []interface{}{"string", "null"}}, want: true},
		{name: "union containing object", schema: map[string]interface{}{"type": []interface{}{"string", "object"}}, want: false},
		{name: "scalar const", schema: map[string]interface{}{"const": "value"}, want: true},
		{name: "object const", schema: map[string]interface{}{"const": map[string]interface{}{}}, want: false},
		{name: "scalar enum", schema: map[string]interface{}{"enum": []interface{}{"a", "b"}}, want: true},
		{name: "enum containing an object", schema: map[string]interface{}{"enum": []interface{}{"a", map[string]interface{}{}}}, want: false},
		{name: "no type evidence at all", schema: map[string]interface{}{"description": "open"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validationProfileSchemaExcludesObjects(test.schema); got != test.want {
				t.Fatalf("validationProfileSchemaExcludesObjects() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestFiniteValidationProfileStringValuesRequiresAClosedStringRoster(t *testing.T) {
	values, ok := finiteValidationProfileStringValues(map[string]interface{}{"const": "record"})
	if !ok || len(values) != 1 {
		t.Fatalf("const roster = %v ok = %v, want the single closed value", values, ok)
	}
	if _, present := values["record"]; !present {
		t.Fatalf("const roster does not contain its own value")
	}

	values, ok = finiteValidationProfileStringValues(map[string]interface{}{"enum": []interface{}{"a", "b"}})
	if !ok || len(values) != 2 {
		t.Fatalf("enum roster = %v ok = %v, want both closed values", values, ok)
	}

	for _, test := range []struct {
		name   string
		schema map[string]interface{}
	}{
		{name: "non-string const", schema: map[string]interface{}{"const": json.Number("1")}},
		{name: "padded const", schema: map[string]interface{}{"const": " padded "}},
		{name: "absent roster", schema: map[string]interface{}{"type": "string"}},
		{name: "empty enum", schema: map[string]interface{}{"enum": []interface{}{}}},
		{name: "non-string enum member", schema: map[string]interface{}{"enum": []interface{}{"a", json.Number("1")}}},
		{name: "duplicated enum member", schema: map[string]interface{}{"enum": []interface{}{"a", "a"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := finiteValidationProfileStringValues(test.schema); ok {
				t.Fatalf("an open or inexact roster was accepted as finite")
			}
		})
	}
}
