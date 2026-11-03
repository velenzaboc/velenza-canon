package providerplan

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Resolve only the local definitions in the already pinned owner export.
func cloudStructuredOwnerNode(raw json.RawMessage, defs map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	for i := 0; i < 32; i++ {
		n, err := rawObject(raw)
		if err != nil {
			return nil, err
		}
		if ref, ok := n["$ref"]; ok {
			var name string
			if json.Unmarshal(ref, &name) != nil || !strings.HasPrefix(name, "#/$defs/") {
				return nil, fmt.Errorf("nonlocal owner reference")
			}
			raw = defs[strings.TrimPrefix(name, "#/$defs/")]
			if len(raw) == 0 {
				return nil, fmt.Errorf("unknown owner reference %q", name)
			}
			continue
		}
		return n, nil
	}
	return nil, fmt.Errorf("cyclic or unbounded owner reference")
}

func cloudStructuredPresentValue(raw json.RawMessage, defs map[string]json.RawMessage) (json.RawMessage, error) {
	n, err := cloudStructuredOwnerNode(raw, defs)
	if err != nil {
		return nil, err
	}
	arms := []json.RawMessage{raw}
	if choices, ok := n["oneOf"]; ok {
		if err := json.Unmarshal(choices, &arms); err != nil {
			return nil, err
		}
	}
	var value json.RawMessage
	for _, arm := range arms {
		part, err := cloudStructuredOwnerNode(arm, defs)
		if err != nil {
			return nil, err
		}
		var props map[string]json.RawMessage
		if json.Unmarshal(part["properties"], &props) != nil || len(props["state"]) == 0 {
			continue
		}
		state, err := cloudStructuredOwnerNode(props["state"], defs)
		if err != nil {
			return nil, err
		}
		var label string
		if json.Unmarshal(state["const"], &label) == nil && label == "present" {
			if len(value) != 0 || len(props["value"]) == 0 {
				return nil, fmt.Errorf("ambiguous owner present value")
			}
			value = props["value"]
		}
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("missing owner present value")
	}
	return value, nil
}

func validateCloudStructuredOwner(schema CloudNeutralRecordSchema, field string, plan *cloudStructuredPlan) error {
	for _, f := range schema.Fields {
		if f.ID == field {
			v, err := cloudStructuredPresentValue(f.WireSchema, schema.definitions)
			if err != nil {
				return err
			}
			return checkCloudStructuredShape(plan, v, schema.definitions)
		}
	}
	return fmt.Errorf("unknown owner field %q", field)
}

func checkCloudStructuredShape(plan *cloudStructuredPlan, raw json.RawMessage, defs map[string]json.RawMessage) error {
	n, err := cloudStructuredOwnerNode(raw, defs)
	if err != nil {
		return err
	}
	var typ string
	_ = json.Unmarshal(n["type"], &typ)
	switch plan.kind {
	case "object":
		if typ != "object" || string(n["additionalProperties"]) != "false" {
			return fmt.Errorf("closed owner object required")
		}
		props, err := rawObject(n["properties"])
		if err != nil {
			return err
		}
		public := 0
		unobserved := map[string]bool{}
		for _, name := range plan.unobserved {
			if len(props[name]) == 0 {
				return fmt.Errorf("unknown unobserved owner member %q", name)
			}
			if err := validateCloudJSONSchema(props[name], defs, map[string]any{"state": "not_observed"}, map[string]bool{}); err != nil {
				return fmt.Errorf("owner member %s cannot be not_observed", name)
			}
			unobserved[name] = true
		}
		for _, m := range plan.members {
			if m.target == "" {
				continue
			}
			public++
			if len(props[m.target]) == 0 {
				return fmt.Errorf("unknown owner member %q", m.target)
			}
			for _, state := range []string{m.onAbsent, m.onNull} {
				if state == "refuse" {
					continue
				}
				if err := validateCloudJSONSchema(props[m.target], defs, map[string]any{"state": state}, map[string]bool{}); err != nil {
					return fmt.Errorf("owner member %s lacks %s", m.target, state)
				}
			}
			value, err := cloudStructuredPresentValue(props[m.target], defs)
			if err != nil {
				return err
			}
			if err := checkCloudStructuredShape(m.node, value, defs); err != nil {
				return fmt.Errorf("%s: %w", m.target, err)
			}
		}
		// Different services can project different subsets of an owner object,
		// but every required member must have an explicit source disposition.
		if public == 0 {
			return fmt.Errorf("empty public owner object")
		}
		var required []string
		if b := n["required"]; len(b) > 0 {
			if err := json.Unmarshal(b, &required); err != nil {
				return err
			}
		}
		for _, name := range required {
			if unobserved[name] {
				continue
			}
			found := false
			for _, m := range plan.members {
				if m.target == name {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("missing required owner member %q", name)
			}
		}
	case "list", "key_value_entries":
		if typ != "array" || len(n["items"]) == 0 {
			return fmt.Errorf("typed owner array required")
		}
		items := n["items"]
		if plan.kind == "key_value_entries" {
			item, err := cloudStructuredOwnerNode(items, defs)
			if err != nil {
				return err
			}
			if string(item["additionalProperties"]) != "false" {
				return fmt.Errorf("closed key/value entry required")
			}
			props, err := rawObject(item["properties"])
			if err != nil || len(props) != 2 || len(props["key"]) == 0 || len(props["value"]) == 0 {
				return fmt.Errorf("owner key/value entry required")
			}
			key, err := cloudStructuredOwnerNode(props["key"], defs)
			if err != nil || string(key["type"]) != "\"string\"" {
				return fmt.Errorf("string dictionary key required")
			}
			items = props["value"]
		}
		return checkCloudStructuredShape(plan.item, items, defs)
	case "enum":
		for _, token := range plan.values {
			if err := validateCloudJSONSchema(raw, defs, token, map[string]bool{}); err != nil {
				return fmt.Errorf("enum emits token outside owner domain")
			}
		}
	case "boolean":
		if typ != "boolean" {
			return fmt.Errorf("boolean target required")
		}
	default:
		if typ != "string" {
			return fmt.Errorf("string target required for %s", plan.kind)
		}
	}
	return nil
}
