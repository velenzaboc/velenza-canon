package providerplan

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStructuredObservationKeepsCorrelatedItems(t *testing.T) {
	raw := json.RawMessage(`{"type":"array","items":{"type":"object","properties":{"addr":{"type":"string"},"net":{"type":"string"},"credential":{"type":"string"}}}}`)
	rule := CloudStructuredRule{Kind: "list", Item: &CloudStructuredRule{Kind: "object", Members: []CloudStructuredMember{
		{Source: "addr", Target: "address", OnNull: "unknown", Rule: CloudStructuredRule{Kind: "string"}},
		{Source: "net", Target: "network", OnAbsent: "refuse", Rule: CloudStructuredRule{Kind: "scoped_reference"}},
		{Source: "credential", Rule: CloudStructuredRule{Kind: "private", ReasonCode: "credential", Rationale: "Opaque credential remains in the source credential boundary."}},
	}}}
	c := cloudStructuredCompiler{}
	plan, err := c.compile(&rule, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	bind := map[cloudNeutralBindingKey]string{{"scope", "net-one"}: "id-1", {"scope", "net-two"}: "id-2", {"foreign", "net-foreign"}: "foreign-id"}
	input := []any{map[string]any{"net": "net-one", "credential": "canary"}, map[string]any{"addr": "192.0.2.1", "net": "net-two"}, map[string]any{"addr": nil, "net": "net-one"}}
	got, err := plan.project(input, false, "scope", bind)
	if err != nil {
		t.Fatal(err)
	}
	expected := []any{
		map[string]any{"network": map[string]any{"state": "present", "value": "id-1"}, "address": map[string]any{"state": "not_observed"}},
		map[string]any{"network": map[string]any{"state": "present", "value": "id-2"}, "address": map[string]any{"state": "present", "value": "192.0.2.1"}},
		map[string]any{"network": map[string]any{"state": "present", "value": "id-1"}, "address": map[string]any{"state": "unknown"}},
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("lost item association or presence: %#v", got)
	}
	for _, bad := range []map[string]any{{"net": "net-foreign"}, {"addr": "192.0.2.2"}, {"net": nil}, {"net": "net-one", "surprise": true}} {
		if _, err := plan.project([]any{bad}, false, "scope", bind); err == nil {
			t.Fatal("accepted invalid group", bad)
		}
	}
	rule.Item.Members = rule.Item.Members[:2]
	if _, err := c.compile(&rule, raw, 0); err == nil {
		t.Fatal("accepted omitted private source member")
	}
}

func TestStructuredLabelsPreserveKeysAndValues(t *testing.T) {
	c := cloudStructuredCompiler{}
	p, err := c.compile(&CloudStructuredRule{Kind: "key_value_entries", Item: &CloudStructuredRule{Kind: "string"}}, json.RawMessage(`{"type":"object","additionalProperties":{"type":"string"}}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.project(map[string]any{"z": "first", "a": "second"}, false, "scope", nil)
	want := []any{map[string]any{"key": "a", "value": "second"}, map[string]any{"key": "z", "value": "first"}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal(got, err)
	}
	if _, err := p.project(map[string]any{"z": map[string]any{"value": "hidden"}}, false, "scope", nil); err == nil {
		t.Fatal("accepted untyped label value")
	}
}

func TestStructuredKeyValuePairList(t *testing.T) {
	c := cloudStructuredCompiler{catalog: CloudCatalog{SchemaShapes: []CloudCatalogSchemaShape{
		{ID: "Tag", RawJSON: json.RawMessage(`{"type":"structure","members":{"Key":{"target":"String","traits":{"smithy.api#xmlName":"key"}},"Value":{"target":"String","traits":{"smithy.api#xmlName":"value"}}}}`)},
		{ID: "String", RawJSON: json.RawMessage(`{"type":"string"}`)},
	}}}
	p, err := c.compile(&CloudStructuredRule{Kind: "key_value_entries", KeyMember: "Key", ValueMember: "Value", Item: &CloudStructuredRule{Kind: "string"}}, json.RawMessage(`{"type":"list","member":{"target":"Tag"}}`), 0)
	if err != nil {
		t.Fatal(err)
	}
	wire := map[string]any{"item": []any{map[string]any{"key": "z", "value": "a"}, map[string]any{"key": "a", "value": "z"}}}
	got, err := p.project(wire, true, "scope", nil)
	if err != nil || !reflect.DeepEqual(got, []any{map[string]any{"key": "a", "value": "z"}, map[string]any{"key": "z", "value": "a"}}) {
		t.Fatal(got, err)
	}
	if _, err := p.project([]any{map[string]any{"Key": "x", "Value": "v"}, map[string]any{"Key": "x", "Value": "other"}}, false, "scope", nil); err == nil {
		t.Fatal("accepted conflicting label keys")
	}
}

func TestNestedTerminalListRetainsItsContainingRule(t *testing.T) {
	entry := map[string]any{"modes": []any{"a", "b"}}
	got, state, err := selectCloudStructuredLeafList(map[string]any{"rules": []any{entry}}, "/rules/*/modes/*", false)
	if err != nil || state != "present" || !reflect.DeepEqual(got, []any{"a", "b"}) {
		t.Fatal(got, state, err)
	}
	if _, _, err = selectCloudStructuredLeafList(map[string]any{"rules": []any{entry, entry}}, "/rules/*/modes/*", false); err == nil {
		t.Fatal("merged separate JSON policies")
	}
	if _, _, err = selectCloudStructuredLeafList(map[string]any{"Rule": []any{entry, entry}}, "/Rule/modes", true); err == nil {
		t.Fatal("merged separate XML policies")
	}
}
