package providerplan

// This file is the fixture-side projection of the production full mapping
// composer.  It deliberately creates rows from executed facts, never from the
// candidate contract alone. Native fixture assembly supplies the sealed
// evidence/profile context and writes these rows into its artifacts.

import (
	"fmt"
	"testing"
)

type cloudMappingFullFixtureArtifactSet struct {
	SourceContractFields   []map[string]interface{}
	SourceContractBindings []map[string]interface{}
	SampleShapeRows        []map[string]interface{}
	SurfaceDispositionRows []map[string]interface{}
	FieldMappingRows       []map[string]interface{}
	Mapped                 int
	Private                int
	Unsupported            int
	DerivationProfileRows  dependencySemanticRows
	ProfilePageSetRoot     string
	ProfileResultSetRoot   string
	ProfileExecutionRoot   string
}

func cloudMappingFullFixtureArtifacts(t *testing.T, fixture *testFixture, execution CloudMappingProviderDerivationBundle, native map[string]CloudMappingNativeResourceIdentity) cloudMappingFullFixtureArtifactSet {
	t.Helper()
	projection, err := ComposeCloudMappingSourceContractProjection(execution.Execution.Roster, native, execution.Execution.FieldFacts)
	if err != nil {
		t.Fatal(err)
	}
	bySymbol := map[string]CloudMappingOccurrence{}
	for _, occurrence := range execution.Execution.Roster.Occurrences {
		bySymbol[occurrence.FieldSourceSymbol] = occurrence
	}
	facts := map[string]exactDocumentationDerivedFact{}
	for _, fact := range execution.Execution.FieldFacts {
		facts[fact.InputSourceSymbol] = fact
	}
	result := cloudMappingFullFixtureArtifactSet{SourceContractFields: projection.FieldContracts, SourceContractBindings: projection.ResourceSchemaBindings, DerivationProfileRows: execution.ProfileRows, ProfilePageSetRoot: execution.ProfileExecution.ProfilePageSetRootSHA256, ProfileResultSetRoot: execution.ProfileExecution.ProfileResultSetRootSHA256, ProfileExecutionRoot: execution.ProfileExecution.ExecutionSetRootSHA256}
	for _, row := range projection.FieldContracts {
		symbol := row["source_symbol"].(string)
		occurrence := bySymbol[symbol]
		fact := facts[symbol]
		identity, err := sourceFieldOccurrenceIdentity(row)
		if err != nil {
			t.Fatal(err)
		}
		coordinate := row["evidence_hydration_coordinate"]
		// The field member itself is valid JSON and is the only sample payload
		// used here; no provider response is invented for an unsupported field.
		sample := map[string]interface{}{"row_kind": "sample_json_block", "source_symbol": symbol, "surface_kind": "resource", "source_ref": row["source_ref"], "source_url": row["source_url"], "document_content_sha256": row["source_content_sha256"], "section_path": row["section_path"], "start_line_number": row["line_number"], "end_line_number": row["line_number"], "block_content_sha256": fact.SelectedMatchSHA256, "block_content_bytes": fact.ByteEndOffsetExclusive - fact.ByteStartOffset, "parse_outcome": sampleParseOutcomeNotApplicable, "parse_failure": "schema_member_declaration_not_response_sample", "evidence_hydration_coordinate": coordinate, "diagnostic_navigation_coordinate": map[string]interface{}{"start_line_number": row["line_number"], "end_line_number": row["line_number"], "section_path": row["section_path"]}}
		result.SampleShapeRows = append(result.SampleShapeRows, sample)
		disposition := "unsupported"
		securityClass := "restricted_no_raw_value_embedding"
		switch occurrence.Field.Disposition {
		case CloudSourceMapsExactSourceFact, CloudSourceMapsExactLifecycleFact, CloudSourceMapsExactRelationshipFact:
			disposition, securityClass = "typed_field", "standard_no_raw_value_embedding"
			result.Mapped++
		case CloudSourcePrivateOnly:
			disposition = "private_only"
			result.Private++
		case CloudSourceUnsupported:
			result.Unsupported++
		default:
			t.Fatal(fmt.Errorf("unexpected full mapping disposition %q", occurrence.Field.Disposition))
		}
		surface := map[string]interface{}{"row_kind": "surface_disposition", "source_symbol": symbol, "surface_kind": "resource", "source_ref": row["source_ref"], "source_url": row["source_url"], "official_json_pointer": row["official_json_pointer"], "evidence_content_sha256": row["source_content_sha256"], "source_neutral_family": occurrence.RecordClassSymbol, "target_kind": "typed_record", "target_contract_status": "candidate_contract_unlocked", "business_record_projection": disposition == "typed_field", "typed_home_rule": "canonical typed contract required before admission", "lattice_rule": "source-blind projection only", "numeric_ingress": "preserve source lexeme as typed exact candidate", "numeric_computation": "unresolved fail closed exact pipeline", "unsupported_field_disposition": disposition, "security_class": securityClass, "evidence_hydration_coordinate": coordinate, "documentation_derived_fact_id": fact.FactID, "field_contract_occurrence_identity": identity}
		result.SurfaceDispositionRows = append(result.SurfaceDispositionRows, surface)
		mapping := map[string]interface{}{"row_kind": "field_occurrence_disposition", "documentation_derived_fact_id": fact.FactID, "source_symbol": symbol, "surface_kind": "resource", "source_ref": row["source_ref"], "source_url": row["source_url"], "target_record_family": occurrence.RecordClassSymbol, "source_field": row["field_name"], "source_provider_type": row["provider_type"], "source_cardinality": row["cardinality"], "source_requirement": row["provider_requirement"], "source_section_path": row["section_path"], "disposition": disposition, "mapping_source": "candidate source-neutral compiler", "mapping_is_provider_documentation_fact": false, "provider_field_contract_is_evidence": true, "absence_semantics": "absent remains absent", "raw_source_value_embedding_allowed": false, "normal_consumer_visibility": disposition == "typed_field", "evidence_hydration_coordinate": coordinate}
		// Bind the complete declared field contract, including null handling,
		// identity and every future recipe member. A selected subset of keys
		// could silently lose a newly added semantic requirement.
		recipe, err := canonicalFactoryJSON(occurrence.Field)
		if err != nil {
			t.Fatal(err)
		}
		mapping["mapping_contract_recipe"] = string(recipe)
		mapping["mapping_contract_recipe_sha256"] = sha256Hex(recipe)
		if disposition == "typed_field" {
			if occurrence.Field.TargetField == "" || occurrence.Field.Projection == "" {
				t.Fatal(fmt.Errorf("mapped field %q omits neutral recipe", symbol))
			}
			mapping["target_role"] = "candidate_neutral_field"
			mapping["target_candidate_path"] = occurrence.Field.TargetField
		} else {
			if occurrence.Field.TargetField != "" || occurrence.Field.Projection != "" || occurrence.Field.ValueRecipe != nil || occurrence.Field.LifecycleRecipe != nil || occurrence.Field.ExplicitAbsentDisposition != "" {
				t.Fatal(fmt.Errorf("non-mapped field %q carries neutral recipe", symbol))
			}
			mapping["target_role"] = "quarantined"
			mapping["target_candidate_path"] = ""
		}
		result.FieldMappingRows = append(result.FieldMappingRows, mapping)
	}
	if len(result.SourceContractFields) != len(execution.Execution.Roster.Occurrences) || len(result.SampleShapeRows) != len(result.SourceContractFields) || len(result.SurfaceDispositionRows) != len(result.SourceContractFields) || len(result.FieldMappingRows) != len(result.SourceContractFields) || result.Mapped+result.Private+result.Unsupported != len(result.SourceContractFields) {
		t.Fatal("full fixture artifact closure is incomplete")
	}
	return result
}
