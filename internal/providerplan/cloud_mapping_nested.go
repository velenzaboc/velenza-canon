package providerplan

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CloudNestedDecomposition is an explicit opt-in to a bounded descendant
// closure. ParentPointer is itself the parent's disposition: it cannot also
// be privately discarded or mapped directly.
type CloudNestedDecomposition struct {
	ParentPointer    string                      `json:"parent_pointer"`
	WireCodecProfile string                      `json:"wire_codec_profile"`
	Fields           []CloudMappingContractField `json:"fields"`
}

const cloudNestedMaxDepth = 8

func validateCloudNestedDecompositions(catalog CloudCatalog, contract CloudMappingContract, neutral map[string]CloudNeutralFieldSchema, direct map[string]cloudResolvedField) (map[string]struct{}, error) {
	parents := map[string]struct{}{}
	for _, decomposition := range contract.Nested {
		parent, ok := direct[decomposition.ParentPointer]
		if !ok || (parent.ValueType != "opaque_complex" && parent.ValueType != "opaque_list") {
			return nil, fmt.Errorf("nested parent %q is not a decomposable retained complex field", decomposition.ParentPointer)
		}
		if err := validateCloudNestedWireCodec(catalog, decomposition.WireCodecProfile); err != nil {
			return nil, fmt.Errorf("nested parent %q: %w", decomposition.ParentPointer, err)
		}
		if _, duplicate := parents[decomposition.ParentPointer]; duplicate {
			return nil, fmt.Errorf("duplicate nested parent %q", decomposition.ParentPointer)
		}
		leaves, err := cloudDecompositionLeaves(catalog, parent)
		if err != nil {
			return nil, err
		}
		if len(leaves) != len(decomposition.Fields) {
			return nil, fmt.Errorf("nested parent %q has incomplete leaf dispositions", decomposition.ParentPointer)
		}
		seen := map[string]struct{}{}
		for _, mapping := range decomposition.Fields {
			field, exists := leaves[mapping.SourcePointer]
			if !exists {
				return nil, fmt.Errorf("nested pointer %q is not a retained leaf", mapping.SourcePointer)
			}
			if mapping.SourceFieldID != field.ID {
				return nil, fmt.Errorf("nested pointer %q source id mismatch", mapping.SourcePointer)
			}
			if mapping.WirePointer == "" || mapping.WirePointer != field.WirePointer {
				return nil, fmt.Errorf("nested pointer %q wire pointer is not retained-model exact", mapping.SourcePointer)
			}
			if _, duplicate := seen[mapping.SourcePointer]; duplicate {
				return nil, fmt.Errorf("duplicate nested pointer %q", mapping.SourcePointer)
			}
			seen[mapping.SourcePointer] = struct{}{}
			if err := validateCloudNullDisposition(mapping, field, neutral); err != nil {
				return nil, err
			}
			if err := validateCloudMappingField(mapping, field, neutral); err != nil {
				return nil, err
			}
		}
		parents[decomposition.ParentPointer] = struct{}{}
	}
	return parents, nil
}

func validateCloudNestedWireCodec(catalog CloudCatalog, profile string) error {
	var expected string
	switch catalog.Format {
	case CloudCatalogFormatSmithyJSON:
		if profile == "smithy_ec2_query_xml" {
			expected = "aws.protocols#ec2Query"
		} else if profile == "smithy_rest_xml" {
			expected = "aws.protocols#restXml"
		} else {
			return fmt.Errorf("wire codec profile is not valid for Smithy catalog")
		}
	case CloudCatalogFormatGoogleDiscoveryREST:
		if profile != "discovery_json" {
			return fmt.Errorf("wire codec profile is not valid for Discovery catalog")
		}
		expected = "discovery#rest_json"
	default:
		return fmt.Errorf("catalog has no recognized format")
	}
	count := 0
	for _, binding := range catalog.ProtocolBindings {
		if binding.ID == expected && binding.Status == cloudCatalogProtocolDocumentedSupported && len(binding.Locators) > 0 {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("wire codec profile lacks exactly one documented supported protocol binding")
	}
	return nil
}

func cloudInlineDiscoveryListLeaf(parent cloudResolvedField) (map[string]cloudResolvedField, error) {
	object, err := rawObject(parent.InlineSchema)
	if err != nil {
		return nil, err
	}
	items, ok := object["items"]
	if !ok {
		return nil, fmt.Errorf("inline list %q lacks items", parent.Pointer)
	}
	var item struct {
		Type   string `json:"type"`
		Format string `json:"format"`
		Ref    string `json:"$ref"`
	}
	if err := json.Unmarshal(items, &item); err != nil || item.Ref != "" || item.Type == "" {
		return nil, fmt.Errorf("inline list %q has unsupported item schema", parent.Pointer)
	}
	typ, _, err := cloudDiscoveryType(item.Type, item.Format, nil)
	if err != nil {
		return nil, err
	}
	pointer := parent.Pointer + "/*"
	return map[string]cloudResolvedField{pointer: {ID: "*", Pointer: pointer, WirePointer: parent.WirePointer + "/*", ValueType: typ, Cardinality: "many"}}, nil
}

func cloudNestedLeaves(catalog CloudCatalog, shapeID, prefix, wirePrefix, cardinality string, depth int, seen map[string]bool) (map[string]cloudResolvedField, error) {
	if depth >= cloudNestedMaxDepth || seen[shapeID] {
		return nil, fmt.Errorf("nested schema %q is recursive or exceeds depth bound", shapeID)
	}
	shape, ok := cloudCatalogShape(catalog, shapeID)
	if !ok {
		return nil, fmt.Errorf("nested schema %q absent", shapeID)
	}
	seen[shapeID] = true
	defer delete(seen, shapeID)
	object, err := rawObject(shape.RawJSON)
	if err != nil {
		return nil, err
	}
	if catalog.Format == CloudCatalogFormatGoogleDiscoveryREST {
		return cloudDiscoveryNestedLeaves(catalog, shape.RawJSON, prefix, wirePrefix, cardinality, depth, seen)
	}
	var declaredType string
	_ = json.Unmarshal(object["type"], &declaredType)
	if declaredType != "structure" && declaredType != "list" && declaredType != "map" {
		typ, card, err := cloudShapeType(shape)
		if err != nil {
			return nil, err
		}
		if cardinality == "many" {
			card = "many"
		}
		name := prefix[strings.LastIndex(prefix, "/")+1:]
		name = strings.ReplaceAll(strings.ReplaceAll(name, "~1", "/"), "~0", "~")
		return map[string]cloudResolvedField{prefix: {ID: name, Pointer: prefix, WirePointer: wirePrefix, ValueType: typ, Cardinality: card, ShapeID: shapeID, KnownEnumValues: cloudSmithyEnumValues(shape.RawJSON)}}, nil
	}
	if memberRaw, ok := object["member"]; ok {
		var member struct {
			Target string                     `json:"target"`
			Traits map[string]json.RawMessage `json:"traits"`
		}
		if json.Unmarshal(memberRaw, &member) != nil || member.Target == "" {
			return nil, fmt.Errorf("nested list %q has no member", shapeID)
		}
		return cloudNestedLeaves(catalog, member.Target, prefix+"/*", wirePrefix+"/"+cloudSmithyWireMemberName("item", member.Traits), "many", depth+1, seen)
	}
	if itemsRaw, ok := object["items"]; ok {
		var item struct {
			Ref  string `json:"$ref"`
			Type string `json:"type"`
		}
		if json.Unmarshal(itemsRaw, &item) != nil {
			return nil, fmt.Errorf("nested array %q invalid", shapeID)
		}
		if item.Ref != "" {
			return cloudNestedLeaves(catalog, item.Ref, prefix+"/*", wirePrefix+"/*", "many", depth+1, seen)
		}
		return map[string]cloudResolvedField{prefix + "/*": {ID: "*", Pointer: prefix + "/*", WirePointer: wirePrefix + "/*", ValueType: "string", Cardinality: "many"}}, nil
	}
	result := map[string]cloudResolvedField{}
	if membersRaw, ok := object["members"]; ok {
		members, e := rawObject(membersRaw)
		if e != nil {
			return nil, e
		}
		for name, raw := range members {
			var member struct {
				Target   string                     `json:"target"`
				Nullable bool                       `json:"nullable"`
				Traits   map[string]json.RawMessage `json:"traits"`
			}
			if json.Unmarshal(raw, &member) != nil || member.Target == "" {
				return nil, fmt.Errorf("nested member %q invalid", name)
			}
			target, _ := cloudCatalogShape(catalog, member.Target)
			typ, card, e := cloudShapeType(target)
			if e != nil {
				return nil, e
			}
			pointer := prefix + "/" + cloudCatalogEscapePointer(name)
			wireName := cloudSmithyWireMemberName(name, member.Traits)
			wirePointer := wirePrefix + "/" + cloudCatalogEscapePointer(wireName)
			if cardinality == "many" {
				card = "many"
			}
			if typ == "opaque_complex" || typ == "opaque_list" {
				var nested map[string]cloudResolvedField
				var e error
				if _, flattened := member.Traits["smithy.api#xmlFlattened"]; flattened && typ == "opaque_list" {
					var list struct {
						Member struct {
							Target string `json:"target"`
						} `json:"member"`
					}
					if json.Unmarshal(target.RawJSON, &list) != nil || list.Member.Target == "" {
						return nil, fmt.Errorf("flattened list lacks retained member")
					}
					nested, e = cloudNestedLeaves(catalog, list.Member.Target, pointer+"/*", wirePointer, "many", depth+1, seen)
				} else {
					nested, e = cloudNestedLeaves(catalog, member.Target, pointer, wirePointer, card, depth+1, seen)
				}
				if e != nil {
					return nil, e
				}
				for k, v := range nested {
					result[k] = v
				}
			} else {
				if cardinality == "many" {
					card = "many"
				}
				result[pointer] = cloudResolvedField{ID: name, Pointer: pointer, WirePointer: wirePointer, ValueType: typ, Cardinality: card, Nullable: member.Nullable, ShapeID: member.Target, KnownEnumValues: cloudSmithyEnumValues(target.RawJSON)}
			}
		}
		return result, nil
	}
	if propsRaw, ok := object["properties"]; ok {
		props, e := rawObject(propsRaw)
		if e != nil {
			return nil, e
		}
		for name, raw := range props {
			var p struct {
				Ref      string          `json:"$ref"`
				Type     string          `json:"type"`
				Format   string          `json:"format"`
				Items    json.RawMessage `json:"items"`
				Nullable bool            `json:"nullable"`
			}
			if json.Unmarshal(raw, &p) != nil {
				return nil, fmt.Errorf("nested property %q invalid", name)
			}
			pointer := prefix + "/" + cloudCatalogEscapePointer(name)
			if p.Ref != "" {
				nested, e := cloudNestedLeaves(catalog, p.Ref, pointer, wirePrefix+"/"+cloudCatalogEscapePointer(name), cardinality, depth+1, seen)
				if e != nil {
					return nil, e
				}
				for k, v := range nested {
					result[k] = v
				}
				continue
			}
			typ, card, e := cloudDiscoveryType(p.Type, p.Format, p.Items)
			if e != nil {
				return nil, e
			}
			if cardinality == "many" {
				card = "many"
			}
			result[pointer] = cloudResolvedField{ID: name, Pointer: pointer, WirePointer: wirePrefix + "/" + cloudCatalogEscapePointer(name), ValueType: typ, Cardinality: card, Nullable: p.Nullable, KnownEnumValues: cloudDiscoveryEnumValues(raw)}
		}
		return result, nil
	}
	return nil, fmt.Errorf("nested schema %q has unsupported form", shapeID)
}

func cloudSmithyWireMemberName(modelName string, traits map[string]json.RawMessage) string {
	if raw, ok := traits["smithy.api#xmlName"]; ok {
		var name string
		if json.Unmarshal(raw, &name) == nil && name != "" {
			return name
		}
	}
	return modelName
}

func _cloudNestedUnused(_ string) { _ = strings.Builder{} }
