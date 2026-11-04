package providerplan

import "fmt"

func validateCloudSourceAliases(catalog CloudCatalog, contract CloudMappingContract) error {
	roster := cloudNeutralProjectionFields(contract)
	byPointer := map[string]CloudMappingContractField{}
	for _, f := range roster {
		byPointer[f.SourcePointer] = f
	}
	var sources map[string]cloudResolvedField
	claimed := map[string]bool{}
	refs := mappingEvidenceIDs(contract)
	for _, f := range roster {
		if f.SourceAliasOf == "" && f.SourceAliasEvidenceRef == "" && f.SourceAliasComparison == "" {
			continue
		}
		dst, ok := byPointer[f.SourceAliasOf]
		_, bound := refs[f.SourceAliasEvidenceRef]
		if !ok || !bound || claimed[f.SourceAliasOf] || f.Disposition != CloudSourcePrivateOnly || dst.SourceAliasOf != "" || dst.TargetField == "" || dst.StructuredRecipe != nil {
			return fmt.Errorf("invalid or unbound source alias %s", f.SourcePointer)
		}
		if f.SourceAliasComparison != "" && (f.SourceAliasComparison != "scoped_reference" || dst.Projection != CloudMappingProjectionRelationship) {
			return fmt.Errorf("invalid source alias comparison for %s", f.SourcePointer)
		}
		claimed[f.SourceAliasOf] = true
		if sources == nil {
			var err error
			sources, err = cloudProjectionResolvedFields(catalog, contract)
			if err != nil {
				return err
			}
		}
		a, aOK := sources[f.SourcePointer]
		b, bOK := sources[dst.SourcePointer]
		if !aOK || !bOK || a.ValueType != b.ValueType || a.Cardinality != "one" || b.Cardinality != "one" {
			return fmt.Errorf("source alias %s changes type or cardinality", f.SourcePointer)
		}
	}
	return nil
}

type cloudAliasValue struct {
	value any
	state string
}

func cloudAliasValues(contract CloudMappingContract, obj map[string]any, source map[string]cloudResolvedField, xml bool, scope string, bindings map[cloudNeutralBindingKey]string) (map[string]cloudAliasValue, error) {
	var result map[string]cloudAliasValue
	read := func(ptr string) (any, string, error) {
		if xml {
			ptr = source[ptr].WirePointer
		}
		return resolveCloudNeutralProjectionPointerMode(obj, ptr, true)
	}
	for _, f := range cloudNeutralProjectionFields(contract) {
		if f.SourceAliasOf == "" {
			continue
		}
		old, state, err := read(f.SourcePointer)
		if err != nil {
			return nil, err
		}
		if state == "absent" {
			continue
		}
		curr, cs, err := read(f.SourceAliasOf)
		if err != nil {
			return nil, err
		}
		if cs == "absent" {
			if result == nil {
				result = map[string]cloudAliasValue{}
			}
			result[f.SourceAliasOf] = cloudAliasValue{old, state}
			continue
		}
		equal := cloudJSONEquivalent(curr, old)
		if f.SourceAliasComparison == "scoped_reference" && cs == "present" && state == "present" {
			a, aOK := old.(string)
			b, bOK := curr.(string)
			x, xOK := bindings[cloudNeutralBindingKey{scope, a}]
			y, yOK := bindings[cloudNeutralBindingKey{scope, b}]
			equal = aOK && bOK && xOK && yOK && x == y
		}
		if cs != state || !equal {
			return nil, fmt.Errorf("conflicting documented aliases %s and %s", f.SourcePointer, f.SourceAliasOf)
		}
	}
	return result, nil
}
