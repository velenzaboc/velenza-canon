package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCloudConfigurationRecipeRequiresTypedCompleteEvidenceDomain(t *testing.T) {
	target := CloudNeutralFieldSchema{ID: "encryption_configuration_observation", ValueType: "string", Cardinality: "one", AllowedValues: []string{"configured", "not_configured"}, PresenceStates: []string{"present", "absent", "unknown"}}
	source := cloudResolvedField{ID: "Encrypted", ValueType: "boolean", Cardinality: "one"}
	makeField := func() CloudMappingContractField {
		return CloudMappingContractField{SourceFieldID: source.ID, Disposition: CloudSourceMapsExactSourceFact, TargetField: target.ID, Projection: CloudMappingProjectionEvidenceClosedScalar, ExplicitAbsentDisposition: CloudAbsentToUnknown, ValueRecipe: &CloudEvidenceValueRecipe{EvidenceRefs: []string{"exact-document-slice"}, SourceToNeutral: map[string]string{"true": "configured", "false": "not_configured"}, UnknownValuePolicy: "refuse"}}
	}
	if err := validateCloudMappingField(makeField(), source, map[string]CloudNeutralFieldSchema{target.ID: target}); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CloudMappingContractField){
		"missing recipe":            func(f *CloudMappingContractField) { f.ValueRecipe = nil },
		"missing evidence":          func(f *CloudMappingContractField) { f.ValueRecipe.EvidenceRefs = nil },
		"incomplete boolean domain": func(f *CloudMappingContractField) { delete(f.ValueRecipe.SourceToNeutral, "false") },
		"invented boolean literal":  func(f *CloudMappingContractField) { f.ValueRecipe.SourceToNeutral["yes"] = "configured" },
		"unknown fallback":          func(f *CloudMappingContractField) { f.ValueRecipe.UnknownValuePolicy = "guess" },
		"unowned target enum":       func(f *CloudMappingContractField) { f.ValueRecipe.SourceToNeutral["true"] = "secure" },
		"contradictory disposition": func(f *CloudMappingContractField) { f.ValueRecipe.UnsupportedSourceValues = []string{"true"} },
		"unknown absence policy":    func(f *CloudMappingContractField) { f.ExplicitAbsentDisposition = "false" },
		"bypass projection":         func(f *CloudMappingContractField) { f.Projection = CloudMappingProjectionExact },
	} {
		t.Run(name, func(t *testing.T) {
			f := makeField()
			mutate(&f)
			if validateCloudMappingField(f, source, map[string]CloudNeutralFieldSchema{target.ID: target}) == nil {
				t.Fatal("hostile mapping accepted")
			}
		})
	}
	contract := CloudMappingContract{Fields: []CloudMappingContractField{makeField()}}
	if validateCloudMappingEvidenceReferences(contract) == nil {
		t.Fatal("unloaded evidence reference accepted")
	}
	for _, tc := range []struct {
		value       any
		xml, wantOK bool
	}{{true, false, true}, {false, false, true}, {"true", true, true}, {"false", true, true}, {"true", false, false}, {true, true, false}, {"TRUE", true, false}, {"1", true, false}, {json.Number("1"), false, false}, {nil, false, false}} {
		_, err := cloudEvidenceScalarKey(tc.value, source, tc.xml)
		if (err == nil) != tc.wantOK {
			t.Fatalf("wire %v XML=%v: %v", tc.value, tc.xml, err)
		}
	}
}

func TestCloudManyRelationshipsPreserveCompleteScopedSet(t *testing.T) {
	bindings := map[cloudNeutralBindingKey]string{{"s", "a"}: "neutral-a", {"s", "b"}: "neutral-b", {"s", "alias-a"}: "neutral-a", {"other", "x"}: "neutral-x"}
	values, err := cloudNeutralManyRelationships([]any{"b", "a"}, "s", bindings)
	if err != nil || strings.Join(values, ",") != "neutral-a,neutral-b" {
		t.Fatalf("set: %v %v", values, err)
	}
	values, err = cloudNeutralManyRelationships([]any{}, "s", bindings)
	if err != nil || values == nil || len(values) != 0 {
		t.Fatalf("observed zero must be present empty set: %v %v", values, err)
	}
	for _, hostile := range []any{[]any{"a", "a"}, []any{"a", "alias-a"}, []any{"a", "x"}, []any{"a", "unresolved"}, []any{nil}, []any{7}, nil, ""} {
		if _, err := cloudNeutralManyRelationships(hostile, "s", bindings); err == nil {
			t.Fatalf("bad relation accepted: %v", hostile)
		}
	}
	root := map[string]any{"attachments": []any{map[string]any{"id": "a"}, map[string]any{"other": "b"}}}
	if _, _, err := resolveCloudNeutralProjectionPointerMode(root, "/attachments/*/id", true); err == nil {
		t.Fatal("incomplete attachment silently dropped")
	}
}

func TestCloudNeutralArraySchemaActuallyEnforcesClosure(t *testing.T) {
	raw := json.RawMessage(`{"type":"array","minItems":0,"maxItems":2,"uniqueItems":true,"items":{"type":"string","pattern":"^neutral-[a-z]+$"}}`)
	for _, valid := range []any{[]any{}, []any{"neutral-a"}, []any{"neutral-a", "neutral-b"}} {
		if err := validateCloudJSONSchema(raw, nil, valid, map[string]bool{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, invalid := range []any{[]any{"neutral-a", "neutral-a"}, []any{"neutral-a", "neutral-b", "neutral-c"}, []any{"aws-native"}, []any{nil}, []any{3}, "neutral-a"} {
		if validateCloudJSONSchema(raw, nil, invalid, map[string]bool{}) == nil {
			t.Fatalf("invalid array accepted: %v", invalid)
		}
	}
}

func TestCloudPrivatePresenceRequiresExplicitNonemptyLeafSemantics(t *testing.T) {
	f := CloudMappingContractField{Disposition: CloudSourceMapsExactSourceFact, TargetField: "configuration", Projection: CloudMappingProjectionPresentPrivateLeaf, ValueRecipe: &CloudEvidenceValueRecipe{EvidenceRefs: []string{"private-key-presence-semantics"}, SourceToNeutral: map[string]string{"present": "configured"}, UnknownValuePolicy: "refuse"}}
	source := cloudResolvedField{ID: "private-key-name", ValueType: "string", Cardinality: "one"}
	target := CloudNeutralFieldSchema{ID: "configuration", ValueType: "string", Cardinality: "one", AllowedValues: []string{"configured"}}
	if err := validateCloudEvidenceValueRecipe(f, source, target); err != nil {
		t.Fatal(err)
	}
	f.ValueRecipe.SourceToNeutral = map[string]string{"anything": "configured"}
	if validateCloudEvidenceValueRecipe(f, source, target) == nil {
		t.Fatal("arbitrary presence sentinel accepted")
	}
}

func TestCloudExactTimestampRejectsLenientParserSpellings(t *testing.T) {
	for _, value := range []string{"2026-02-30T12:00:00Z", "2026-02-29T12:00:00Z", "2026-04-31T12:00:00Z", "2026-10-30T24:00:00Z", "2026-10-30T12:00:00,123Z", "2026-10-30T12:00:00+00:00"} {
		if validateCloudUTCInstant(value) == nil {
			t.Fatalf("invalid timestamp accepted: %s", value)
		}
	}
	for _, value := range []string{"2024-02-29T12:00:00Z", "2026-10-30T12:00:00.123456789123Z"} {
		if err := validateCloudUTCInstant(value); err != nil {
			t.Fatal(err)
		}
	}
}
