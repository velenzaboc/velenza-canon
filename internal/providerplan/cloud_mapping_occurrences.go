package providerplan

import (
	"fmt"
	"sort"
)

// CloudMappingOccurrence is the complete source-contract handoff for one
// selected provider field occurrence.  It is deliberately not a graph row or
// a qualified source fact: Program is an exact retained-model candidate whose
// execution still requires the existing selected-evidence compiler path.
type CloudMappingOccurrence struct {
	TargetKey             string `json:"target_key"`
	ResourceKey           string `json:"resource_key"`
	ProviderID            string `json:"provider_id"`
	ServiceID             string `json:"service_id"`
	APISurfaceID          string `json:"api_surface_id"`
	OperationID           string `json:"operation_id"`
	RecordClassSymbol     string `json:"record_class_symbol"`
	ObjectSchemaID        string `json:"object_schema_id"`
	ModelSourceID         string `json:"model_source_id"`
	ModelSHA256           string `json:"model_sha256"`
	CandidateSourceSymbol string `json:"candidate_source_symbol"`
	// FieldSourceSymbol is the unique classified evidence occurrence consumed
	// by Program. CandidateSourceSymbol identifies the target-level candidate
	// only and must never be used to coalesce all field programs at runtime.
	FieldSourceSymbol string `json:"field_source_symbol"`
	// SourceSchemaOwnerSymbol is intentionally independent from the endpoint
	// resource symbol: it owns the declared source schema/field contract.
	SourceSchemaOwnerSymbol      string                      `json:"source_schema_owner_symbol"`
	SourceSchemaOwnerLocator     CloudCatalogEvidenceLocator `json:"source_schema_owner_locator"`
	SourceSchemaOwnerRangeSHA256 string                      `json:"source_schema_owner_range_sha256"`
	APIResourceID                string                      `json:"api_resource_id"`
	APIResourceSymbol            string                      `json:"api_resource_symbol"`
	Field                        CloudMappingContractField   `json:"field"`
	Program                      cloudMappingFieldProgram    `json:"program"`
}

// CloudMappingOccurrenceRoster preserves every selected source occurrence and
// makes the mapping disposition plus its neutral recipe available to the
// source-package compiler without re-parsing candidate JSON.
type CloudMappingOccurrenceRoster struct {
	Occurrences []CloudMappingOccurrence       `json:"occurrences"`
	Resources   []CloudMappingSelectedResource `json:"selected_resources"`
	Totals      CloudMappingDispositionTotals  `json:"totals"`
}

// CloudMappingSelectedResource keeps an explicit bridge record even when a
// selected resource has zero field occurrences.
type CloudMappingSelectedResource struct {
	// ResourceKey is catalog-local and may have several selected operations.
	// TargetKeys preserves that many-to-one relationship explicitly.
	ResourceKey       string                      `json:"resource_key"`
	TargetKeys        []string                    `json:"target_keys"`
	APIResourceID     string                      `json:"api_resource_id"`
	APIResourceSymbol string                      `json:"api_resource_symbol"`
	EvidenceLocator   CloudCatalogEvidenceLocator `json:"evidence_locator"`
	Disposition       string                      `json:"selected_resource_disposition"`
}

// CloudMappingResourceFieldGroup is the composition boundary for one real API
// endpoint.  Several selected operations may project fields from that same
// endpoint, so a source-contract bridge must consume the group, not one
// target at a time.
type CloudMappingResourceFieldGroup struct {
	Resource       CloudMappingSelectedResource
	Occurrences    []CloudMappingOccurrence
	SchemaSurfaces []CloudMappingSourceSchemaSurface
}

// CloudMappingSourceSchemaSurface is one declared schema artifact behind an
// endpoint. Its owner evidence is separate from its field evidence: an
// endpoint such as an object resource can expose several output schemas.
type CloudMappingSourceSchemaSurface struct {
	SourceSchemaOwnerSymbol      string
	SourceSchemaOwnerLocator     CloudCatalogEvidenceLocator
	SourceSchemaOwnerRangeSHA256 string
	Occurrences                  []CloudMappingOccurrence
	FieldSourceSymbols           []string
}

// BuildCloudMappingResourceFieldGroups closes target-level occurrences over
// their selected API-resource endpoint. It does not create native candidate
// IDs or classify evidence; those remain sealed compiler inputs.
func BuildCloudMappingResourceFieldGroups(roster CloudMappingOccurrenceRoster) ([]CloudMappingResourceFieldGroup, error) {
	if err := ValidateCloudMappingOccurrenceRoster(roster, roster.Totals); err != nil {
		return nil, fmt.Errorf("mapping occurrence roster: %w", err)
	}
	byResource := map[string][]CloudMappingOccurrence{}
	for _, occurrence := range roster.Occurrences {
		byResource[occurrence.ResourceKey] = append(byResource[occurrence.ResourceKey], occurrence)
	}
	groups := make([]CloudMappingResourceFieldGroup, 0, len(roster.Resources))
	for _, resource := range roster.Resources {
		occurrences := append([]CloudMappingOccurrence(nil), byResource[resource.ResourceKey]...)
		if len(occurrences) == 0 {
			groups = append(groups, CloudMappingResourceFieldGroup{Resource: resource})
			continue
		}
		sort.Slice(occurrences, func(i, j int) bool {
			if occurrences[i].FieldSourceSymbol != occurrences[j].FieldSourceSymbol {
				return occurrences[i].FieldSourceSymbol < occurrences[j].FieldSourceSymbol
			}
			return occurrences[i].TargetKey < occurrences[j].TargetKey
		})
		byOwner := map[string][]CloudMappingOccurrence{}
		for _, occurrence := range occurrences {
			byOwner[occurrence.SourceSchemaOwnerSymbol] = append(byOwner[occurrence.SourceSchemaOwnerSymbol], occurrence)
		}
		ownerSymbols := sortedSetKeys(stringMapKeysAsSet(byOwner))
		surfaces := make([]CloudMappingSourceSchemaSurface, 0, len(ownerSymbols))
		for _, owner := range ownerSymbols {
			members := byOwner[owner]
			sort.Slice(members, func(i, j int) bool { return members[i].FieldSourceSymbol < members[j].FieldSourceSymbol })
			symbols := make([]string, len(members))
			for i := range members {
				symbols[i] = members[i].FieldSourceSymbol
				if i != 0 && symbols[i-1] == symbols[i] {
					return nil, fmt.Errorf("schema owner %q repeats field source symbol %q", owner, symbols[i])
				}
			}
			first := members[0]
			for _, member := range members[1:] {
				if member.SourceSchemaOwnerLocator != first.SourceSchemaOwnerLocator || member.SourceSchemaOwnerRangeSHA256 != first.SourceSchemaOwnerRangeSHA256 {
					return nil, fmt.Errorf("schema owner %q has inconsistent evidence", owner)
				}
			}
			surfaces = append(surfaces, CloudMappingSourceSchemaSurface{SourceSchemaOwnerSymbol: owner, SourceSchemaOwnerLocator: first.SourceSchemaOwnerLocator, SourceSchemaOwnerRangeSHA256: first.SourceSchemaOwnerRangeSHA256, Occurrences: members, FieldSourceSymbols: symbols})
		}
		groups = append(groups, CloudMappingResourceFieldGroup{Resource: resource, Occurrences: occurrences, SchemaSurfaces: surfaces})
	}
	return groups, nil
}

// BuildCloudMappingOccurrenceRoster combines the selected scope, exact model
// fields, and generated derivation programs. It refuses a missing program,
// gap, duplicate, or changed program identity rather than allowing a caller
// to compile a convenient subset.
func BuildCloudMappingOccurrenceRoster(request CloudSourceCandidateRequest, scope CloudMappingPackageScope) (CloudMappingOccurrenceRoster, error) {
	if err := validateCloudMappingPackageScope(request, scope); err != nil {
		return CloudMappingOccurrenceRoster{}, err
	}
	models := map[string]PinnedCloudModel{}
	for _, m := range request.retainedModels {
		models[m.Source.ID] = m
	}
	result := CloudMappingOccurrenceRoster{}
	resources := map[string]*CloudMappingSelectedResource{}
	for _, target := range request.Targets {
		catalog, ok := findCloudCandidateCatalog(request.Catalogs, target)
		if !ok {
			return CloudMappingOccurrenceRoster{}, fmt.Errorf("occurrence target has no exact catalog")
		}
		model, ok := models[catalog.Source.ID]
		if !ok {
			return CloudMappingOccurrenceRoster{}, fmt.Errorf("occurrence target has no retained model")
		}
		key := cloudTargetKey(target)
		symbol := stableID("cloud_field_candidate", key)
		roster, err := buildCloudTargetFieldDerivationRosterWithSymbol(catalog, target, model, func(pointer string) string {
			return cloudMappingFieldSourceSymbol(key, pointer)
		})
		if err != nil {
			return CloudMappingOccurrenceRoster{}, err
		}
		if len(roster.Unresolved) != 0 {
			return CloudMappingOccurrenceRoster{}, fmt.Errorf("occurrence target %q has unresolved exact fields", key)
		}
		byPointer := map[string]CloudFieldDerivationCandidate{}
		for _, c := range roster.Candidates {
			if _, dup := byPointer[c.FieldPointer]; dup {
				return CloudMappingOccurrenceRoster{}, fmt.Errorf("duplicate candidate %q", c.FieldPointer)
			}
			byPointer[c.FieldPointer] = c
		}
		fields := append([]CloudMappingContractField(nil), target.MappingContract.Fields...)
		for _, n := range target.MappingContract.Nested {
			fields = append(fields, n.Fields...)
		}
		op, ok := findCloudCatalogOperation(catalog, target.OperationID)
		if !ok || len(op.ResourceIDs) != 1 {
			return CloudMappingOccurrenceRoster{}, fmt.Errorf("target %q has no single exact API resource", key)
		}
		resourceID := op.ResourceIDs[0]
		resourceKey := lengthPrefixedIdentityKey(model.Source.ID, resourceID)
		schemaLocator, err := cloudSourceSchemaOwnerLocator(catalog, target, model)
		if err != nil {
			return CloudMappingOccurrenceRoster{}, err
		}
		schemaSymbol := cloudSourceSchemaOwnerSymbol(model.Source.ID, schemaLocator)
		resourceSymbol := stableID("cloud_api_resource", target.ProviderID+"|"+target.ServiceID+"|"+target.APISurfaceID+"|"+resourceID)
		before := len(result.Occurrences)
		for _, field := range fields {
			c, ok := byPointer[field.SourcePointer]
			if !ok {
				return CloudMappingOccurrenceRoster{}, fmt.Errorf("field %q has no exact program", field.SourcePointer)
			}
			raw, err := canonicalFactoryJSON(c.Program)
			if err != nil {
				return CloudMappingOccurrenceRoster{}, err
			}
			result.Occurrences = append(result.Occurrences, CloudMappingOccurrence{TargetKey: key, ResourceKey: resourceKey, ProviderID: target.ProviderID, ServiceID: target.ServiceID, APISurfaceID: target.APISurfaceID, OperationID: target.OperationID, RecordClassSymbol: target.RecordClassSymbol, ObjectSchemaID: target.MappingContract.ObjectSchemaID, ModelSourceID: model.Source.ID, ModelSHA256: model.ExpectedSHA256, CandidateSourceSymbol: symbol, FieldSourceSymbol: c.SourceSymbol, SourceSchemaOwnerSymbol: schemaSymbol, SourceSchemaOwnerLocator: schemaLocator, SourceSchemaOwnerRangeSHA256: sha256Hex(model.Raw[schemaLocator.StartByte:schemaLocator.EndByte]), APIResourceID: resourceID, APIResourceSymbol: resourceSymbol, Field: field, Program: cloudMappingFieldProgram{FieldPointer: c.FieldPointer, SourceSymbol: c.SourceSymbol, Locator: c.FieldLocator, SelectedRangeSHA256: sha256Hex(model.Raw[c.FieldLocator.StartByte:c.FieldLocator.EndByte]), ProfileID: c.Reference.id, ProfileVersion: c.Reference.version, ProgramSHA256: c.Reference.digest, Program: raw}})
			addCloudOccurrenceDisposition(&result.Totals, field.Disposition)
		}
		disposition := "observed"
		if len(result.Occurrences) == before {
			disposition = "no_fields_observed"
		}
		if existing := resources[resourceKey]; existing != nil {
			if existing.APIResourceID != resourceID || existing.APIResourceSymbol != resourceSymbol {
				return CloudMappingOccurrenceRoster{}, fmt.Errorf("resource %q identity changed across targets", resourceKey)
			}
			existing.TargetKeys = append(existing.TargetKeys, key)
			if disposition == "observed" {
				existing.Disposition = "observed"
			}
		} else {
			resource := CloudMappingSelectedResource{ResourceKey: resourceKey, TargetKeys: []string{key}, APIResourceID: resourceID, APIResourceSymbol: resourceSymbol, EvidenceLocator: op.Locator, Disposition: disposition}
			resources[resourceKey] = &resource
		}
	}
	for _, resource := range resources {
		sort.Strings(resource.TargetKeys)
		result.Resources = append(result.Resources, *resource)
	}
	sort.Slice(result.Occurrences, func(i, j int) bool {
		a, b := result.Occurrences[i], result.Occurrences[j]
		if a.TargetKey != b.TargetKey {
			return a.TargetKey < b.TargetKey
		}
		return a.Field.SourcePointer < b.Field.SourcePointer
	})
	sort.Slice(result.Resources, func(i, j int) bool { return result.Resources[i].ResourceKey < result.Resources[j].ResourceKey })
	if err := ValidateCloudMappingOccurrenceRoster(result, scope.ExpectedDispositionTotals); err != nil {
		return CloudMappingOccurrenceRoster{}, err
	}
	return result, nil
}

// CloudMappingOccurrenceRosterForProvider partitions the complete selected
// closure for the native compiler's one-provider graph boundary. It is not a
// convenience subset: every selected occurrence and resource for that
// provider is retained, and the returned totals are recomputed and sealed.
func CloudMappingOccurrenceRosterForProvider(roster CloudMappingOccurrenceRoster, providerID string) (CloudMappingOccurrenceRoster, error) {
	if providerID == "" {
		return CloudMappingOccurrenceRoster{}, fmt.Errorf("provider occurrence partition is empty")
	}
	result := CloudMappingOccurrenceRoster{}
	targets := map[string]struct{}{}
	for _, occurrence := range roster.Occurrences {
		if occurrence.ProviderID != providerID {
			continue
		}
		result.Occurrences = append(result.Occurrences, occurrence)
		targets[occurrence.TargetKey] = struct{}{}
		addCloudOccurrenceDisposition(&result.Totals, occurrence.Field.Disposition)
	}
	if len(result.Occurrences) == 0 {
		return CloudMappingOccurrenceRoster{}, fmt.Errorf("provider %q has no selected occurrences", providerID)
	}
	for _, resource := range roster.Resources {
		keys := make([]string, 0, len(resource.TargetKeys))
		for _, target := range resource.TargetKeys {
			if _, selected := targets[target]; selected {
				keys = append(keys, target)
			}
		}
		if len(keys) == 0 {
			continue
		}
		copy := resource
		copy.TargetKeys = keys
		result.Resources = append(result.Resources, copy)
	}
	if err := ValidateCloudMappingOccurrenceRoster(result, result.Totals); err != nil {
		return CloudMappingOccurrenceRoster{}, err
	}
	return result, nil
}

func addCloudOccurrenceDisposition(t *CloudMappingDispositionTotals, d CloudSourceFieldDisposition) {
	switch d {
	case CloudSourceMapsExactSourceFact, CloudSourceMapsExactLifecycleFact, CloudSourceMapsExactRelationshipFact:
		t.Mapped++
	case CloudSourceNotObserved:
		t.NotObserved++
	case CloudSourcePrivateOnly:
		t.Private++
	case CloudSourceUnknown:
		t.Unknown++
	case CloudSourceUnsupported:
		t.Unsupported++
	}
}

func ValidateCloudMappingOccurrenceRoster(r CloudMappingOccurrenceRoster, want CloudMappingDispositionTotals) error {
	if len(r.Occurrences) == 0 || len(r.Resources) == 0 || r.Totals != want {
		return fmt.Errorf("occurrence roster totals/closure mismatch")
	}
	seen := map[string]bool{}
	actual := CloudMappingDispositionTotals{}
	resources := map[string]CloudMappingSelectedResource{}
	for _, resource := range r.Resources {
		if resource.ResourceKey == "" || len(resource.TargetKeys) == 0 || resource.APIResourceID == "" || resource.APIResourceSymbol == "" || resource.EvidenceLocator.EvidenceID == "" || resource.Disposition == "" {
			return fmt.Errorf("invalid selected resource")
		}
		if _, duplicate := resources[resource.ResourceKey]; duplicate {
			return fmt.Errorf("duplicate selected resource")
		}
		for i, target := range resource.TargetKeys {
			if target == "" || (i != 0 && resource.TargetKeys[i-1] >= target) {
				return fmt.Errorf("selected resource target roster is not exact")
			}
		}
		resources[resource.ResourceKey] = resource
	}
	for _, x := range r.Occurrences {
		k := x.TargetKey + "\x00" + x.Field.SourcePointer
		resource, exists := resources[x.ResourceKey]
		if seen[k] || !exists || !containsCloudString(resource.TargetKeys, x.TargetKey) || resource.APIResourceID != x.APIResourceID || resource.APIResourceSymbol != x.APIResourceSymbol || x.TargetKey == "" || x.RecordClassSymbol == "" || x.ResourceKey != lengthPrefixedIdentityKey(x.ModelSourceID, x.APIResourceID) || x.CandidateSourceSymbol == "" || x.FieldSourceSymbol != cloudMappingFieldSourceSymbol(x.TargetKey, x.Field.SourcePointer) || x.Program.SourceSymbol != x.FieldSourceSymbol || x.SourceSchemaOwnerSymbol != cloudSourceSchemaOwnerSymbol(x.ModelSourceID, x.SourceSchemaOwnerLocator) || x.SourceSchemaOwnerSymbol == x.APIResourceSymbol || x.SourceSchemaOwnerLocator.EvidenceID != "model" || x.SourceSchemaOwnerLocator.JSONPointer == "" || x.SourceSchemaOwnerLocator.StartByte < 0 || x.SourceSchemaOwnerLocator.EndByte <= x.SourceSchemaOwnerLocator.StartByte || !isLowerSHA256(x.SourceSchemaOwnerRangeSHA256) || x.APIResourceID == "" || x.APIResourceSymbol == "" || x.ModelSourceID == "" || !isLowerSHA256(x.ModelSHA256) || x.Program.FieldPointer != x.Field.SourcePointer || x.Program.Locator.EvidenceID != "model" || !isLowerSHA256(x.Program.ProgramSHA256) || sha256Hex(x.Program.Program) != x.Program.ProgramSHA256 {
			return fmt.Errorf("invalid occurrence %q", k)
		}
		ref := dependencyProfileReference{id: x.Program.ProfileID, version: x.Program.ProfileVersion, digest: x.Program.ProgramSHA256}
		program, err := parseExactDocumentationDerivationProgram(x.Program.Program, ref)
		if err != nil || len(program.InputSourceSymbols) != 1 || program.InputSourceSymbols[0] != x.FieldSourceSymbol || len(program.OrderedRules) != 1 {
			return fmt.Errorf("invalid exact program %q", k)
		}
		rule := program.OrderedRules[0]
		if rule.InputSourceSymbol != x.FieldSourceSymbol || rule.TargetArtifactRole != dependencySemanticRoleSourceContract || rule.OutputFields["official_json_pointer"] != x.Program.Locator.JSONPointer || rule.OutputFields["source_symbol"] != x.FieldSourceSymbol {
			return fmt.Errorf("program binding mismatch %q", k)
		}
		seen[k] = true
		addCloudOccurrenceDisposition(&actual, x.Field.Disposition)
	}
	if actual != r.Totals {
		return fmt.Errorf("occurrence disposition totals forged")
	}
	for resourceKey, resource := range resources {
		found := false
		for _, occurrence := range r.Occurrences {
			if occurrence.ResourceKey == resourceKey {
				found = true
				break
			}
		}
		if resource.Disposition != "observed" && resource.Disposition != "no_fields_observed" && resource.Disposition != "unsupported" && resource.Disposition != "not_observed" {
			return fmt.Errorf("invalid selected resource disposition")
		}
		if !found && resource.Disposition == "observed" {
			return fmt.Errorf("observed resource omitted occurrences")
		}
	}
	return nil
}

func containsCloudString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
