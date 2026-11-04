package providerplan

import (
	"encoding/json"
	"fmt"
	"sort"
)

// These programs are proposed extraction recipes, not executed facts or
// selected profiles. The native compiler must select and execute them against
// qualified evidence before their output can become a field-contract row.
type cloudMappingFieldProgram struct {
	FieldPointer string `json:"field_pointer"`
	// SourceSymbol is intentionally per occurrence.  A derivation program has
	// a one-outcome bound, so sharing a target-wide input symbol would make a
	// composed execution either ambiguous or exceed that bound.
	SourceSymbol        string                      `json:"source_symbol"`
	Locator             CloudCatalogEvidenceLocator `json:"locator"`
	SelectedRangeSHA256 string                      `json:"selected_range_sha256"`
	ProfileID           string                      `json:"profile_id"`
	ProfileVersion      string                      `json:"profile_version"`
	ProgramSHA256       string                      `json:"program_sha256"`
	Program             json.RawMessage             `json:"program"`
}

type cloudMappingFieldGap struct {
	FieldPointer string `json:"field_pointer"`
	Reason       string `json:"reason"`
}

type cloudMappingFieldDerivationPackage struct {
	TargetKey                    string                      `json:"target_key"`
	CandidateSourceSymbol        string                      `json:"candidate_source_symbol"`
	SourceSchemaOwnerSymbol      string                      `json:"source_schema_owner_symbol"`
	SourceSchemaOwnerLocator     CloudCatalogEvidenceLocator `json:"source_schema_owner_locator"`
	SourceSchemaOwnerRangeSHA256 string                      `json:"source_schema_owner_range_sha256"`
	ModelSourceID                string                      `json:"model_source_id"`
	ModelSHA256                  string                      `json:"model_sha256"`
	Programs                     []cloudMappingFieldProgram  `json:"candidate_programs"`
	Gaps                         []cloudMappingFieldGap      `json:"unresolved_fields"`
}

func buildCloudMappingFieldPackages(request CloudSourceCandidateRequest, targets []CloudSourceObjectTarget) ([]cloudMappingFieldDerivationPackage, error) {
	models := map[string]PinnedCloudModel{}
	for _, model := range request.retainedModels {
		models[model.Source.ID] = model
	}
	result := make([]cloudMappingFieldDerivationPackage, 0, len(targets))
	for _, target := range targets {
		catalog, ok := findCloudCandidateCatalog(request.Catalogs, target)
		if !ok {
			return nil, fmt.Errorf("field derivation has no exact catalog")
		}
		model, ok := models[catalog.Source.ID]
		if !ok {
			return nil, fmt.Errorf("field derivation has no retained model")
		}
		key := cloudTargetKey(target)
		symbol := stableID("cloud_field_candidate", key)
		schemaLocator, err := cloudSourceSchemaOwnerLocator(catalog, target, model)
		if err != nil {
			return nil, err
		}
		// Each field program consumes a distinct classified occurrence.  The
		// target symbol remains a package identity only; it is not an executable
		// input symbol once the package is composed with its siblings.
		roster, err := buildCloudTargetFieldDerivationRosterWithSymbol(catalog, target, model, func(pointer string) string {
			return cloudMappingFieldSourceSymbol(key, pointer)
		})
		if err != nil {
			return nil, err
		}
		item := cloudMappingFieldDerivationPackage{TargetKey: key, CandidateSourceSymbol: symbol, SourceSchemaOwnerSymbol: cloudSourceSchemaOwnerSymbol(model.Source.ID, schemaLocator), SourceSchemaOwnerLocator: schemaLocator, SourceSchemaOwnerRangeSHA256: sha256Hex(model.Raw[schemaLocator.StartByte:schemaLocator.EndByte]), ModelSourceID: model.Source.ID, ModelSHA256: model.ExpectedSHA256, Programs: []cloudMappingFieldProgram{}, Gaps: []cloudMappingFieldGap{}}
		for _, candidate := range roster.Candidates {
			raw, err := canonicalFactoryJSON(candidate.Program)
			if err != nil {
				return nil, err
			}
			loc := candidate.FieldLocator
			if loc.StartByte < 0 || loc.EndByte <= loc.StartByte || loc.EndByte > len(model.Raw) {
				return nil, fmt.Errorf("field derivation emitted invalid range")
			}
			item.Programs = append(item.Programs, cloudMappingFieldProgram{FieldPointer: candidate.FieldPointer, SourceSymbol: candidate.SourceSymbol, Locator: loc, SelectedRangeSHA256: sha256Hex(model.Raw[loc.StartByte:loc.EndByte]), ProfileID: candidate.Reference.id, ProfileVersion: candidate.Reference.version, ProgramSHA256: candidate.Reference.digest, Program: raw})
		}
		for pointer, reason := range roster.Unresolved {
			item.Gaps = append(item.Gaps, cloudMappingFieldGap{FieldPointer: pointer, Reason: reason})
		}
		sort.Slice(item.Gaps, func(i, j int) bool { return item.Gaps[i].FieldPointer < item.Gaps[j].FieldPointer })
		result = append(result, item)
	}
	return result, nil
}

// Validate structural package closure again immediately before publication.
// This cannot qualify the candidates: no source authority or model body is
// supplied at this boundary, and no verification receipt is produced.
func validateCloudMappingFieldPackages(doc cloudMappingProviderDocument) error {
	if len(doc.FieldDerivations) != len(doc.Targets) {
		return fmt.Errorf("field derivation target roster is incomplete")
	}
	for index, target := range doc.Targets {
		item := doc.FieldDerivations[index]
		if item.TargetKey != cloudTargetKey(target) || item.CandidateSourceSymbol != stableID("cloud_field_candidate", item.TargetKey) || item.SourceSchemaOwnerSymbol != cloudSourceSchemaOwnerSymbol(item.ModelSourceID, item.SourceSchemaOwnerLocator) || item.SourceSchemaOwnerLocator.EvidenceID != "model" || item.SourceSchemaOwnerLocator.JSONPointer == "" || item.SourceSchemaOwnerLocator.EndByte <= item.SourceSchemaOwnerLocator.StartByte || !isLowerSHA256(item.SourceSchemaOwnerRangeSHA256) {
			return fmt.Errorf("field derivation target identity mismatch")
		}
		found := false
		for _, catalog := range doc.Catalogs {
			if catalog.ProviderID == target.ProviderID && catalog.ServiceID == target.ServiceID && catalog.APISurfaceID == target.APISurfaceID {
				found = catalog.Source.ID == item.ModelSourceID && catalog.ModelSHA256 == item.ModelSHA256
				break
			}
		}
		if !found {
			return fmt.Errorf("field derivation retained model identity mismatch")
		}
		var catalogFormat CloudCatalogFormat
		for _, catalog := range doc.Catalogs {
			if catalog.ProviderID == target.ProviderID && catalog.ServiceID == target.ServiceID && catalog.APISurfaceID == target.APISurfaceID {
				catalogFormat = catalog.Format
				break
			}
		}
		var expectedSchemaPointer string
		switch catalogFormat {
		case CloudCatalogFormatSmithyJSON:
			expectedSchemaPointer = "/shapes/" + cloudCatalogEscapePointer(target.MappingContract.ObjectSchemaID)
		case CloudCatalogFormatGoogleDiscoveryREST:
			expectedSchemaPointer = "/schemas/" + cloudCatalogEscapePointer(target.MappingContract.ObjectSchemaID)
		default:
			return fmt.Errorf("field derivation has unsupported schema-owner catalog format")
		}
		if item.SourceSchemaOwnerLocator.JSONPointer != expectedSchemaPointer {
			return fmt.Errorf("field derivation schema-owner locator does not identify its declared schema")
		}
		fields := append([]CloudMappingContractField(nil), target.MappingContract.Fields...)
		for _, nested := range target.MappingContract.Nested {
			fields = append(fields, nested.Fields...)
		}
		want := map[string]bool{}
		for _, field := range fields {
			if want[field.SourcePointer] {
				return fmt.Errorf("duplicate source field occurrence")
			}
			want[field.SourcePointer] = true
		}
		seen := map[string]bool{}
		add := func(pointer string) error {
			if !want[pointer] || seen[pointer] {
				return fmt.Errorf("unknown or repeated field derivation occurrence")
			}
			seen[pointer] = true
			return nil
		}
		for _, program := range item.Programs {
			if err := add(program.FieldPointer); err != nil {
				return err
			}
			if program.SourceSymbol != cloudMappingFieldSourceSymbol(item.TargetKey, program.FieldPointer) || program.Locator.EvidenceID != "model" || program.Locator.JSONPointer == "" || program.Locator.StartByte < 0 || program.Locator.EndByte <= program.Locator.StartByte || !isLowerSHA256(program.SelectedRangeSHA256) || sha256Hex(program.Program) != program.ProgramSHA256 {
				return fmt.Errorf("field derivation bytes or locator mismatch")
			}
			ref := dependencyProfileReference{id: program.ProfileID, version: program.ProfileVersion, digest: program.ProgramSHA256}
			parsed, err := parseExactDocumentationDerivationProgram(program.Program, ref)
			if err != nil || len(parsed.InputSourceSymbols) != 1 || parsed.InputSourceSymbols[0] != program.SourceSymbol {
				return fmt.Errorf("field derivation program is not the exact proposed profile")
			}
			if len(parsed.OrderedRules) != 1 {
				return fmt.Errorf("field derivation requires exactly one extraction rule")
			}
			rule := parsed.OrderedRules[0]
			if rule.InputSourceSymbol != program.SourceSymbol || rule.TargetArtifactRole != dependencySemanticRoleSourceContract || rule.TargetRowKind != "field_contract" || rule.TargetBindingKind != exactDocumentationTargetWholeRow || rule.OutputFields["official_json_pointer"] != program.Locator.JSONPointer || rule.OutputFields["source_symbol"] != program.SourceSymbol {
				return fmt.Errorf("field derivation rule does not bind its selected source field")
			}
		}
		for _, gap := range item.Gaps {
			if err := add(gap.FieldPointer); err != nil {
				return err
			}
			if gap.Reason == "" {
				return fmt.Errorf("field derivation gap has no reason")
			}
		}
		if len(seen) != len(want) {
			return fmt.Errorf("field derivation omits source occurrences")
		}
	}
	return nil
}
