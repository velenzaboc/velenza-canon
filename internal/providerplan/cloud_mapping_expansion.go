package providerplan

import (
	"encoding/json"
	"fmt"
)

func validateCloudArrayAssertions(schema, definitions map[string]json.RawMessage, values []any) error {
	for _, key := range []string{"minItems", "maxItems"} {
		if raw, exists := schema[key]; exists {
			var count int
			if json.Unmarshal(raw, &count) != nil || count < 0 || (key == "minItems" && len(values) < count) || (key == "maxItems" && len(values) > count) {
				return fmt.Errorf("array violates %s", key)
			}
		}
	}
	var unique bool
	if raw, exists := schema["uniqueItems"]; exists && json.Unmarshal(raw, &unique) != nil {
		return fmt.Errorf("uniqueItems is not boolean")
	}
	seen := map[string]bool{}
	for _, value := range values {
		if unique {
			encoded, err := canonicalFactoryJSON(value)
			if err != nil || seen[string(encoded)] {
				return fmt.Errorf("array has duplicate or malformed member")
			}
			seen[string(encoded)] = true
		}
		if item, exists := schema["items"]; exists {
			if err := validateCloudJSONSchema(item, definitions, value, map[string]bool{}); err != nil {
				return fmt.Errorf("array item: %w", err)
			}
		}
	}
	return nil
}

func validateCloudAbsentDisposition(mapping CloudMappingContractField, target CloudNeutralFieldSchema) error {
	state := ""
	switch mapping.ExplicitAbsentDisposition {
	case "", CloudAbsentRefuse:
		return nil
	case CloudAbsentToAbsent:
		state = "absent"
	case CloudAbsentToUnknown:
		state = "unknown"
	default:
		return fmt.Errorf("unknown absent disposition for %q", mapping.SourceFieldID)
	}
	if !cloudHasPresenceState(target, state) {
		return fmt.Errorf("target %q has no %s presence arm", target.ID, state)
	}
	return nil
}

func validateCloudEvidenceValueRecipe(mapping CloudMappingContractField, source cloudResolvedField, target CloudNeutralFieldSchema) error {
	recipe := mapping.ValueRecipe
	wantSourceCardinality := "one"
	if mapping.Projection == CloudMappingProjectionBoundedOneEvidenceScalar {
		wantSourceCardinality = "many"
	}
	if mapping.Disposition != CloudSourceMapsExactSourceFact || mapping.LifecycleRecipe != nil || source.Cardinality != wantSourceCardinality || target.Cardinality != "one" || target.ValueType != "string" || target.Unit != "" || mapping.SourceUnit != "" {
		return fmt.Errorf("evidence value projection requires one scalar configuration fact")
	}
	if recipe == nil || recipe.UnknownValuePolicy != "refuse" || len(recipe.EvidenceRefs) == 0 || len(recipe.SourceToNeutral) == 0 {
		return fmt.Errorf("value projection lacks a complete evidence-bound recipe")
	}
	known := append([]string(nil), source.KnownEnumValues...)
	if mapping.Projection == CloudMappingProjectionPresentPrivateLeaf {
		if source.ValueType != "string" || len(recipe.SourceToNeutral) != 1 || recipe.SourceToNeutral["present"] == "" || len(recipe.UnsupportedSourceValues) != 0 {
			return fmt.Errorf("private presence projection needs one nonempty string leaf and a present recipe")
		}
		known = []string{"present"}
	} else {
		switch source.ValueType {
		case "boolean":
			known = []string{"false", "true"}
		case "string":
		default:
			return fmt.Errorf("value recipe cannot coerce a non-string/non-boolean source")
		}
	}
	// Reuse the complete enum-domain check. The field/disposition routing stays
	// separate so a configuration recipe can never stand in for lifecycle.
	proxy := mapping
	proxy.LifecycleRecipe = &CloudLifecycleEnumRecipe{EvidenceRefs: recipe.EvidenceRefs, SourceToNeutral: recipe.SourceToNeutral, UnsupportedSourceValues: recipe.UnsupportedSourceValues, UnknownValuePolicy: recipe.UnknownValuePolicy}
	source.KnownEnumValues = known
	if err := validateCloudLifecycleRecipe(proxy, source, target); err != nil {
		return err
	}
	for value := range recipe.SourceToNeutral {
		if len(known) > 0 {
			found := false
			for _, candidate := range known {
				if value == candidate {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("recipe source value %q is outside documented domain", value)
			}
		}
		for _, unsupported := range recipe.UnsupportedSourceValues {
			if value == unsupported {
				return fmt.Errorf("recipe both maps and refuses source value %q", value)
			}
		}
	}
	return nil
}

func cloudProjectionResolvedFields(catalog CloudCatalog, contract CloudMappingContract) (map[string]cloudResolvedField, error) {
	fields, err := cloudCatalogObjectFields(catalog, contract.ObjectSchemaID)
	if err != nil {
		return nil, err
	}
	for _, decomposition := range contract.Nested {
		parent := fields[decomposition.ParentPointer]
		leaves, err := cloudDecompositionLeaves(catalog, parent)
		if err != nil {
			return nil, err
		}
		for key, field := range leaves {
			fields[key] = field
		}
	}
	return fields, nil
}

func cloudEvidenceScalarKey(value any, source cloudResolvedField, xmlWire bool) (string, error) {
	if source.ValueType == "boolean" {
		if boolean, ok := value.(bool); ok && !xmlWire {
			if boolean {
				return "true", nil
			}
			return "false", nil
		}
		if text, ok := value.(string); ok && xmlWire && (text == "true" || text == "false") {
			return text, nil
		}
		return "", fmt.Errorf("boolean observation has an invalid wire type or value")
	}
	if source.ValueType == "string" {
		if text, ok := value.(string); ok {
			return text, nil
		}
	}
	return "", fmt.Errorf("scalar observation does not match its retained source type")
}
