package providerplan

import (
	"encoding/json"
	"fmt"
	"strings"
)

func cloudDecompositionLeaves(catalog CloudCatalog, parent cloudResolvedField) (map[string]cloudResolvedField, error) {
	if parent.ShapeID == "" && catalog.Format == CloudCatalogFormatGoogleDiscoveryREST {
		return cloudDiscoveryNestedLeaves(catalog, parent.InlineSchema, parent.Pointer, parent.WirePointer, parent.Cardinality, 0, map[string]bool{})
	}
	return cloudNestedLeaves(catalog, parent.ShapeID, parent.Pointer, parent.WirePointer, parent.Cardinality, 0, map[string]bool{})
}

// Discovery embeds complete anonymous object schemas inside properties. Walk
// those exact retained bytes rather than inventing a named schema or assuming
// every leaf is a string. The same depth/ref-cycle limits apply to both forms.
func cloudDiscoveryNestedLeaves(catalog CloudCatalog, raw json.RawMessage, prefix, wire, cardinality string, depth int, seen map[string]bool) (map[string]cloudResolvedField, error) {
	if depth >= cloudNestedMaxDepth {
		return nil, fmt.Errorf("inline schema exceeds depth bound")
	}
	var shape struct {
		Ref                  string                     `json:"$ref"`
		Type                 string                     `json:"type"`
		Format               string                     `json:"format"`
		Nullable             bool                       `json:"nullable"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Items                json.RawMessage            `json:"items"`
		AdditionalProperties json.RawMessage            `json:"additionalProperties"`
	}
	if err := json.Unmarshal(raw, &shape); err != nil {
		return nil, err
	}
	if shape.Ref != "" {
		return cloudNestedLeaves(catalog, shape.Ref, prefix, wire, cardinality, depth+1, seen)
	}
	if shape.Type == "array" {
		if len(shape.Items) == 0 {
			return nil, fmt.Errorf("inline array lacks items")
		}
		return cloudDiscoveryNestedLeaves(catalog, shape.Items, prefix+"/*", wire+"/*", "many", depth+1, seen)
	}
	if len(shape.AdditionalProperties) > 0 {
		if len(shape.Properties) > 0 {
			return nil, fmt.Errorf("mixed named and open map properties require an explicit owner")
		}
		return cloudDiscoveryNestedLeaves(catalog, shape.AdditionalProperties, prefix+"/*", wire+"/*", "many", depth+1, seen)
	}
	if shape.Type == "object" || len(shape.Properties) > 0 {
		if len(shape.Properties) == 0 {
			return nil, fmt.Errorf("inline object has no closed properties")
		}
		result := map[string]cloudResolvedField{}
		for _, name := range sortedCloudCatalogKeys(shape.Properties) {
			suffix := "/" + cloudCatalogEscapePointer(name)
			leaves, err := cloudDiscoveryNestedLeaves(catalog, shape.Properties[name], prefix+suffix, wire+suffix, cardinality, depth+1, seen)
			if err != nil {
				return nil, err
			}
			for pointer, leaf := range leaves {
				result[pointer] = leaf
			}
		}
		return result, nil
	}
	typ, card, err := cloudDiscoveryType(shape.Type, shape.Format, nil)
	if err != nil {
		return nil, err
	}
	if cardinality == "many" {
		card = "many"
	}
	name := prefix[strings.LastIndex(prefix, "/")+1:]
	name = strings.ReplaceAll(strings.ReplaceAll(name, "~1", "/"), "~0", "~")
	return map[string]cloudResolvedField{prefix: {ID: name, Pointer: prefix, WirePointer: wire, ValueType: typ, Cardinality: card, Nullable: shape.Nullable, InlineSchema: raw, KnownEnumValues: cloudDiscoveryEnumValues(raw)}}, nil
}
