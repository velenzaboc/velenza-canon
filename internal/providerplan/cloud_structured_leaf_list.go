package providerplan

import (
	"fmt"
	"strings"
)

// A terminal item collection has one containing object. Flattening item
// values from multiple rules would change a rule-scoped setting into a
// resource-wide policy. Refuse that ambiguity before projecting any value.
func selectCloudStructuredLeafList(root map[string]any, pointer string, xml bool) (any, string, error) {
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	var current any = root
	for i, token := range parts {
		if current == nil {
			return nil, "null", nil
		}
		if token == "*" {
			list, ok := current.([]any)
			if !ok {
				return nil, "", fmt.Errorf("expected source list at %s", pointer)
			}
			if i == len(parts)-1 {
				return list, "present", nil
			}
			if len(list) != 1 {
				return nil, "", fmt.Errorf("nested collection has %d containing items; expected exactly one", len(list))
			}
			current = list[0]
			continue
		}
		if xml {
			if list, ok := current.([]any); ok {
				if len(list) != 1 {
					return nil, "", fmt.Errorf("ambiguous enclosing XML items at %s", pointer)
				}
				current = list[0]
			}
		}
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, "", fmt.Errorf("expected enclosing object at %s", pointer)
		}
		key := strings.NewReplacer("~1", "/", "~0", "~").Replace(token)
		current, ok = obj[key]
		if !ok {
			return nil, "absent", nil
		}
	}
	if current == nil {
		return nil, "null", nil
	}
	if _, ok := current.([]any); !ok {
		if !xml {
			return nil, "", fmt.Errorf("expected terminal item list")
		}
		current = []any{current}
	}
	return current, "present", nil
}
