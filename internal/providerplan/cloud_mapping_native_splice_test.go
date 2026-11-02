package providerplan

// The all-target native test starts from the deliberately small generic
// fixture.  This splice replaces only its mapping-owned projections with the
// exact closure already executed by the native field programs.

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

type cloudMappingSpliceClassifierBinding struct {
	ref        dependencyProfileReference
	rule       string
	projection string
}

func cloudMappingSpliceFullArtifacts(t *testing.T, fixture *testFixture, execution CloudMappingProviderDerivationBundle, native map[string]CloudMappingNativeResourceIdentity) {
	t.Helper()
	set := cloudMappingFullFixtureArtifacts(t, fixture, execution, native)
	if fixture.documentationDerivation == nil {
		t.Fatal("full native splice requires the independently materialized documentation closure")
	}

	// The base fixture's derivation document already contains every generated
	// program/schema and the exact target closure.  Add one exact classifier per
	// executed fact; the classifier is bound to that fact's own schema, never a
	// guessed common schema or semantic meaning.
	docPath := fixture.dependencyByRole["documentation_claim_derivation_profile"]
	_, docRows := fixtureDependencySemanticArtifact(t, docPath)
	derivationSchema := map[string]dependencyProfileReference{}
	for _, row := range docRows.byKind["derivation_profile"] {
		id, _ := semanticString(row.data, "derivation_profile_id")
		version, _ := semanticString(row.data, "derivation_profile_version")
		digest, _ := semanticString(row.data, "derivation_profile_sha256")
		binding, _ := semanticObject(row.data, "validation_schema_binding")
		sid, _ := semanticString(binding, "validation_schema_id")
		sversion, _ := semanticString(binding, "validation_schema_version")
		sdigest, _ := semanticString(binding, "validation_schema_sha256")
		derivationSchema[dependencyProfileReferenceKey(dependencyProfileReference{id: id, version: version, digest: digest})] = dependencyProfileReference{id: sid, version: sversion, digest: sdigest}
	}

	classifiers := map[string]cloudMappingSpliceClassifierBinding{}
	var classifierRows []interface{}
	requiresResolution := false
	for _, fact := range execution.Execution.FieldFacts {
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			t.Fatal(err)
		}
		numeric, ok := output["numeric_disposition"].(map[string]interface{})
		if !ok {
			t.Fatalf("field %q has no exact numeric disposition", fact.FactID)
		}
		semantics, sok := semanticString(numeric, "numeric_semantics")
		carrier, cok := semanticString(numeric, "authoritative_carrier")
		path, pok := semanticString(numeric, "computation_path")
		if !sok || !cok || !pok {
			t.Fatalf("field %q has incomplete exact numeric disposition", fact.FactID)
		}
		if carrier != "not_applicable" || path != "not_applicable" {
			requiresResolution = true
		}
		schema, ok := derivationSchema[dependencyProfileReferenceKey(fact.Profile)]
		if !ok {
			t.Fatalf("field %q profile has no exact schema binding", fact.FactID)
		}
		program := map[string]interface{}{
			"program_kind": exactValueClassifierProgramKind, "input_claim_kind": "field_contract",
			"input_validation_schema_binding": map[string]interface{}{"validation_schema_id": schema.id, "validation_schema_version": schema.version, "validation_schema_sha256": schema.digest},
			"input_projection_json_pointers":  []string{"/provider_type"}, "match_semantics": exactValueClassifierMatchExactlyOne,
			"ordered_rules":    []interface{}{map[string]interface{}{"ordinal": 0, "rule_id": "exact_provider_type", "predicates": []interface{}{map[string]interface{}{"predicate_kind": exactValuePredicateStringEquals, "input_json_pointer": "/provider_type", "expected_string": output["provider_type"]}}, "output": map[string]interface{}{"numeric_semantics": semantics, "authoritative_carrier": carrier, "computation_path": path}}},
			"terminal_default": exactValueClassifierTerminalFailClosed, "numeric_lexeme_preserved": true, "binary_float_authoritative": false,
		}
		raw, err := canonicalOperationClassifierProgram(program)
		if err != nil {
			t.Fatal(err)
		}
		ref := dependencyProfileReference{id: "cloud_mapping_exact_" + fact.FactID, version: "1", digest: sha256Hex(raw)}
		projection, err := canonicalExactValueClassifierInputProjection([]string{"/provider_type"}, output)
		if err != nil {
			t.Fatal(err)
		}
		classifiers[fact.FactID] = cloudMappingSpliceClassifierBinding{ref: ref, rule: "exact_provider_type", projection: sha256Hex(projection)}
		classifierRows = append(classifierRows, map[string]interface{}{"row_kind": "classifier_profile", "classifier_profile_id": ref.id, "classifier_profile_version": ref.version, "classifier_profile_sha256": ref.digest, "input_claim_kind": "field_contract", "closed_output_union": []string{semantics}, "authoritative_carrier_union": []string{carrier}, "computation_path_union": []string{path}, "program": program})
	}
	resolution := spliceExactResolutionProfile(t, docPath, requiresResolution)
	spliceAppendClassifierRows(t, docPath, classifierRows)

	// Source-contract fields and v1 resource/schema bridges are compiler output.
	sourcePath := fixture.dependencyByRole["source_contract"]
	sourceRows := spliceReadJSONL(t, sourcePath)
	sourceRows = spliceReplaceKinds(sourceRows, map[string][]map[string]interface{}{"field_contract": set.SourceContractFields, "api_resource_source_schema_binding": set.SourceContractBindings})
	spliceSummary(sourceRows, "field_contract_count", len(set.SourceContractFields))
	writeJSONL(t, sourcePath, spliceInterfaces(sourceRows))

	// Build a closed security policy from exact mapped occurrence identities. The
	// default class is deliberately restricted; private and unsupported fields
	// never gain visibility merely because they were selected.
	standardSet := map[string]struct{}{}
	for _, row := range set.FieldMappingRows {
		if row["disposition"] == "typed_field" {
			standardSet[row["source_symbol"].(string)] = struct{}{}
		}
	}
	standard := sortedSetKeys(standardSet)
	policy := map[string]interface{}{"policy_id": "fixture_security", "policy_version": "1", "source_neutral": true, "authority_bindings": []string{"fixture.authority"}, "closed_security_classes": []string{"restricted_no_embed", "standard_no_raw_value_embedding"}, "precedence": []string{"standard_exact_field_occurrence", "restricted_unclassified_default"}, "standard_exact_field_occurrence_registry": standard, "unknown_security_class_allowed": false, "unclassified_field_disposition": "restricted_no_embed", "raw_source_value_embedding_allowed": false, "authority_posture": "candidate", "ordered_rules": []interface{}{map[string]interface{}{"ordinal": 0, "rule_id": "standard_exact_field_occurrence", "input_member": "source_symbol", "match_kind": "exact_registry_membership", "registry_member": "standard_exact_field_occurrence_registry", "output_security_class": "standard_no_raw_value_embedding"}, map[string]interface{}{"ordinal": 1, "rule_id": "restricted_unclassified_default", "input_member": "*", "match_kind": "default", "registry_member": nil, "output_security_class": "restricted_no_embed"}}}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := sha256Hex(policyRaw)
	securityPath := fixture.dependencyByRole["field_security_policy"]
	security := spliceReadJSONL(t, securityPath)
	for _, row := range security {
		switch row["row_kind"] {
		case "artifact_manifest":
			row["profile_sha256"] = policyDigest
		case "security_classification_profile":
			row["profile"] = policy
			row["profile_sha256"] = policyDigest
		case "security_class_definition":
			row["profile_sha256"] = policyDigest
		case "validation_summary":
			row["security_class_definition_count"] = 2
		}
	}
	writeJSONL(t, securityPath, spliceInterfaces(security))

	// Surface and mapping rows need the per-fact classifier binding.  Preserve
	// the compiler-generated recipe bytes from cloudMappingFullFixtureArtifacts.
	facts := map[string]exactDocumentationDerivedFact{}
	for _, f := range execution.Execution.FieldFacts {
		facts[f.FactID] = f
	}
	for _, row := range set.SurfaceDispositionRows {
		fact := facts[row["documentation_derived_fact_id"].(string)]
		c := classifiers[fact.FactID]
		row["security_class"] = "restricted_no_embed"
		// A surface remains a typed source family even when an individual field
		// is quarantined; field visibility is enforced by the mapping/security
		// rows, not by replacing the whole surface with an untyped container.
		row["business_record_projection"] = true
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			t.Fatal(err)
		}
		numeric, ok := output["numeric_disposition"].(map[string]interface{})
		if !ok {
			t.Fatalf("field %q has no numeric disposition", fact.FactID)
		}
		semanticClass, ok := numeric["numeric_semantics"].(string)
		if !ok || semanticClass == "" {
			t.Fatalf("field %q has no numeric semantic class", fact.FactID)
		}
		row["exact_numeric_profile"] = map[string]interface{}{semanticClass + "_occurrences": 1}
		row["derivation_binding"] = spliceSurfaceBinding(fact, derivationSchema[dependencyProfileReferenceKey(fact.Profile)], c.ref)
	}
	surfacePath := fixture.dependencyByRole["surface_disposition"]
	surface := spliceReadJSONL(t, surfacePath)
	surface = spliceReplaceKinds(surface, map[string][]map[string]interface{}{"surface_disposition": set.SurfaceDispositionRows})
	spliceSummary(surface, "documented_field_occurrence_count", len(set.SurfaceDispositionRows))
	spliceSummary(surface, "disposed_field_occurrence_count", len(set.SurfaceDispositionRows))
	spliceSummary(surface, "exact_locator_binding_count", len(set.SurfaceDispositionRows))
	for _, row := range surface {
		if row["row_kind"] == "artifact_manifest" {
			row["source_contract_index_sha256"] = fileSHA256(t, sourcePath)
			row["documentation_claim_derivation_profile_sha256"] = fileSHA256(t, docPath)
		}
		if row["row_kind"] == "validation_summary" {
			count := len(set.SurfaceDispositionRows)
			row["expected_surface_count"] = count
			row["selected_source_count"] = count
			row["disposed_surface_count"] = count
			row["canonical_contracts_still_unlocked"] = count
			row["exact_evidence_locator_binding_count"] = count
			row["captured_surface_kind_counts"] = []interface{}{map[string]interface{}{"surface_kind": "resource", "count": count}}
			row["disposed_surface_kind_counts"] = []interface{}{map[string]interface{}{"surface_kind": "resource", "count": count}}
		}
	}
	writeJSONL(t, surfacePath, spliceInterfaces(surface))

	mapped, private, unsupported := 0, 0, 0
	numericCounts := map[string]int{}
	for _, row := range set.FieldMappingRows {
		fact := facts[row["documentation_derived_fact_id"].(string)]
		c := classifiers[fact.FactID]
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			t.Fatal(err)
		}
		numeric := output["numeric_disposition"].(map[string]interface{})
		row["exact_numeric_semantics"] = numeric["numeric_semantics"]
		row["numeric_authoritative_carrier"] = numeric["authoritative_carrier"]
		row["financial_computation_path"] = numeric["computation_path"]
		row["binary_float_authoritative"] = false
		row["typed_home_contract_locked"] = false
		disposition := row["disposition"].(string)
		role := "quarantined"
		class, reason, visible := "restricted_no_embed", "restricted_unclassified_default", false
		if disposition == "typed_field" {
			mapped++
			class, reason, visible = "standard_no_raw_value_embedding", "standard_exact_field_occurrence", true
			target := row["target_candidate_path"].(string)
			role = target[strings.LastIndex(target, ".")+1:]
		} else if disposition == "private_only" {
			private++
		} else {
			unsupported++
		}
		family := row["target_record_family"].(string)
		if disposition != "typed_field" {
			// target_candidate_path is a closed structural coordinate required by
			// the generic mapping validator.  It is not a field projection: the
			// immutable compiler recipe remains the authority for that question.
			recipeRaw := []byte(row["mapping_contract_recipe"].(string))
			var recipe CloudMappingContractField
			if err := json.Unmarshal(recipeRaw, &recipe); err != nil {
				t.Fatal(err)
			}
			if recipe.TargetField != "" || recipe.Projection != "" || recipe.ValueRecipe != nil || recipe.LifecycleRecipe != nil {
				t.Fatalf("quarantined field %q acquired a positive neutral mapping recipe", row["source_symbol"])
			}
		}
		row["target_role"] = role
		row["target_candidate_path"] = family + "." + role
		row["security_class"], row["security_classification_reason"], row["normal_consumer_visibility"] = class, reason, visible
		row["security_policy_id"], row["security_policy_version"], row["security_policy_profile_sha256"] = "fixture_security", "1", policyDigest
		row["applicable_transitive_dependency_binding_ids"] = []string{"fixture_mapping_seed_binding"}
		carrier, carrierOK := numeric["authoritative_carrier"].(string)
		computation, computationOK := numeric["computation_path"].(string)
		if !carrierOK || !computationOK {
			t.Fatalf("field %q has malformed exact numeric disposition", fact.FactID)
		}
		if carrier == "not_applicable" && computation == "not_applicable" {
			row["exact_computation_dependency"] = map[string]interface{}{"applicability": "not_applicable", "resolution_status": "not_applicable", "resolution_profile_id": nil, "resolution_profile_version": nil, "resolution_profile_sha256": nil}
		} else {
			if resolution.id == "" {
				t.Fatalf("field %q requires an exact fail-closed resolution profile", fact.FactID)
			}
			row["exact_computation_dependency"] = map[string]interface{}{"applicability": "required", "resolution_status": "unresolved_fail_closed_gap", "resolution_profile_id": resolution.id, "resolution_profile_version": resolution.version, "resolution_profile_sha256": resolution.digest}
		}
		row["derivation_binding"] = spliceFieldBinding(fact, derivationSchema[dependencyProfileReferenceKey(fact.Profile)], c)
		numericCounts[numeric["numeric_semantics"].(string)]++
	}
	mapPath := fixture.dependencyByRole["field_mapping"]
	mappings := spliceReadJSONL(t, mapPath)
	mappings = spliceReplaceKinds(mappings, map[string][]map[string]interface{}{"field_occurrence_disposition": set.FieldMappingRows})
	spliceSummary(mappings, "documented_field_occurrence_count", len(set.FieldMappingRows))
	spliceSummary(mappings, "disposed_field_occurrence_count", len(set.FieldMappingRows))
	spliceSummary(mappings, "exact_locator_binding_count", len(set.FieldMappingRows))
	spliceSummary(mappings, "explicit_quarantine_count", private+unsupported)
	spliceSummary(mappings, "standard_no_raw_value_embedding_count", mapped)
	spliceSummary(mappings, "restricted_no_embed_count", private+unsupported)
	spliceSummary(mappings, "restricted_unclassified_default_count", private+unsupported)
	for _, r := range mappings {
		if r["row_kind"] == "artifact_manifest" {
			r["source_contract_index_sha256"] = fileSHA256(t, sourcePath)
			r["surface_family_disposition_sha256"] = fileSHA256(t, surfacePath)
			r["field_security_policy_artifact_sha256"] = fileSHA256(t, securityPath)
			r["field_security_policy_profile_sha256"] = policyDigest
			r["field_security_policy_sha256"] = policyDigest
			r["documentation_claim_derivation_profile_sha256"] = fileSHA256(t, docPath)
		}
		if r["row_kind"] == "validation_summary" {
			r["surface_family_count"] = len(set.SurfaceDispositionRows)
			r["direct_role_count"] = mapped
			r["security_policy_sha256"] = policyDigest
			r["security_policy_artifact_sha256"] = fileSHA256(t, securityPath)
			r["security_policy_profile_sha256"] = policyDigest
			for semanticClass, count := range numericCounts {
				r[semanticClass+"_count"] = count
			}
		}
	}
	writeJSONL(t, mapPath, spliceInterfaces(mappings))

	// Every changed semantic artifact gets a fresh exact schema before its
	// profile binding is resealed.  This is the same mechanism used by the
	// fixture mutations; it keeps validator authority data-driven.
	for _, role := range []string{dependencySemanticRoleSourceContract, dependencySemanticRoleSurfaceDisposition, dependencySemanticRoleFieldSecurityPolicy, dependencySemanticRoleFieldMapping, dependencySemanticRoleDocumentationClaimDerivation} {
		path := fixtureSemanticArtifactPath(fixture, role)
		writeFixtureExactJSONLSchema(t, path, fixture.schemaByRole[role], "urn:fixture:provider-documentation:"+role+":schema")
	}
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleSourceContract, dependencySemanticRoleSurfaceDisposition, dependencySemanticRoleFieldSecurityPolicy, dependencySemanticRoleFieldMapping, dependencySemanticRoleDocumentationClaimDerivation)
	spliceRebindSemanticSchemaHashes(t, fixture, dependencySemanticRoleSourceContract, dependencySemanticRoleSurfaceDisposition, dependencySemanticRoleFieldSecurityPolicy, dependencySemanticRoleFieldMapping, dependencySemanticRoleDocumentationClaimDerivation)
	fixture.manifest().SourceContractIndexSHA256 = fileSHA256(t, sourcePath)
	fixture.manifest().DocumentationClaimDerivationProfileSHA256 = fileSHA256(t, docPath)
	fixture.manifest().FieldMappingCandidateSHA256 = fileSHA256(t, mapPath)
	fixture.manifest().FieldSecurityPolicySHA256 = fileSHA256(t, securityPath)
	resealFixtureGraph(t, fixture)
}

func spliceRebindSemanticSchemaHashes(t *testing.T, fixture *testFixture, roles ...string) {
	t.Helper()
	profilePath := fixture.dependencyByRole["dependency_semantic_validation_profile"]
	for _, role := range roles {
		schemaPath := fixture.schemaByRole[role]
		if schemaPath == "" {
			t.Fatalf("semantic role %q has no schema path", role)
		}
		coordinate, ok := fixture.artifactCoordinateByRole[role]
		if !ok {
			t.Fatalf("semantic role %q has no frozen artifact coordinate", role)
		}
		artifactDigest := fileSHA256(t, fixtureSemanticArtifactPath(fixture, role))
		mutateJSONLMatchingRow(t, profilePath, "artifact_schema_binding", func(row map[string]interface{}) bool {
			rowRole, _ := semanticString(row, "role")
			artifactID, _ := semanticString(row, "artifact_id")
			artifactVersion, _ := semanticString(row, "artifact_version")
			boundDigest, _ := semanticString(row, "artifact_raw_sha256")
			return rowRole == role && artifactID == coordinate.ID && artifactVersion == coordinate.Version && boundDigest == artifactDigest
		}, func(row map[string]interface{}) {
			row["schema_raw_sha256"] = fileSHA256(t, schemaPath)
		})
	}
	fixture.manifest().DependencySemanticValidation.Profile.RawSHA256 = fileSHA256(t, profilePath)
	writeJSONL(t, fixture.planPath, fixture.planRows)
}

func spliceSurfaceBinding(f exactDocumentationDerivedFact, schema, classifier dependencyProfileReference) map[string]interface{} {
	return map[string]interface{}{"derivation_profile_id": f.Profile.id, "derivation_profile_version": f.Profile.version, "derivation_profile_sha256": f.Profile.digest, "validation_schema_id": schema.id, "validation_schema_version": schema.version, "validation_schema_sha256": schema.digest, "classifier_profile_id": classifier.id, "classifier_profile_version": classifier.version, "classifier_profile_sha256": classifier.digest, "exact_input_source_content_sha256": f.EvidenceLocator.SourceContentSHA256}
}
func spliceFieldBinding(f exactDocumentationDerivedFact, schema dependencyProfileReference, c cloudMappingSpliceClassifierBinding) map[string]interface{} {
	return map[string]interface{}{"derivation_profile_id": f.Profile.id, "derivation_profile_version": f.Profile.version, "derivation_profile_sha256": f.Profile.digest, "validation_schema_id": schema.id, "validation_schema_version": schema.version, "validation_schema_sha256": schema.digest, "classifier_profile_id": c.ref.id, "classifier_profile_version": c.ref.version, "classifier_profile_sha256": c.ref.digest, "exact_input_documentation_fact_id": f.FactID, "exact_input_evidence_locator_id": f.EvidenceLocatorID, "exact_input_claim_sha256": sha256Hex(f.CanonicalOutputFields), "exact_input_projection_sha256": c.projection, "exact_classifier_rule_id": c.rule, "exact_input_coordinate": map[string]interface{}{"source_content_sha256": f.EvidenceLocator.SourceContentSHA256, "byte_start_offset": f.EvidenceLocator.ByteStartOffset, "byte_end_offset_exclusive": f.EvidenceLocator.ByteEndOffsetExclusive, "selected_range_byte_count": f.EvidenceLocator.SelectedRangeByteCount, "selected_range_sha256": f.EvidenceLocator.SelectedRangeSHA256}, "reexecution_status": "complete_exact_generic_reexecution"}
}
func spliceReadJSONL(t *testing.T, path string) []map[string]interface{} {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	out := []map[string]interface{}{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		r, err := decodeJSONObject(line)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}
func spliceReplaceKinds(rows []map[string]interface{}, replacements map[string][]map[string]interface{}) []map[string]interface{} {
	out := []map[string]interface{}{}
	used := map[string]bool{}
	for _, r := range rows {
		k, _ := r["row_kind"].(string)
		if repl, ok := replacements[k]; ok {
			if !used[k] {
				out = append(out, repl...)
				used[k] = true
			}
			continue
		}
		out = append(out, r)
	}
	return out
}
func spliceInterfaces(rows []map[string]interface{}) []interface{} {
	out := make([]interface{}, len(rows))
	for i := range rows {
		out[i] = rows[i]
	}
	return out
}
func spliceSummary(rows []map[string]interface{}, key string, value int) {
	for _, r := range rows {
		if r["row_kind"] == "validation_summary" {
			r[key] = value
		}
	}
}
func spliceAppendClassifierRows(t *testing.T, path string, add []interface{}) {
	rows := spliceReadJSONL(t, path)
	out := []interface{}{}
	classifierCount := 0
	for _, row := range rows {
		if row["row_kind"] == "classifier_profile" {
			classifierCount++
		}
	}
	for _, r := range rows {
		if r["row_kind"] == "validation_summary" {
			out = append(out, add...)
			r["classifier_profile_count"] = classifierCount + len(add)
		}
		out = append(out, r)
	}
	writeJSONL(t, path, out)
}

// spliceExactResolutionProfile returns an already sealed fail-closed
// computation profile, or adds the fixture's exact profile when the expanded
// field closure has value-of-record fields and the single-field base did not.
func spliceExactResolutionProfile(t *testing.T, path string, required bool) dependencyProfileReference {
	t.Helper()
	rows := spliceReadJSONL(t, path)
	var references []dependencyProfileReference
	for _, row := range rows {
		if row["row_kind"] != "dependency_resolution_profile" {
			continue
		}
		id, idOK := semanticString(row, "resolution_profile_id")
		version, versionOK := semanticString(row, "resolution_profile_version")
		digest, digestOK := semanticString(row, "resolution_profile_sha256")
		unresolved, unresolvedOK := semanticString(row, "unresolved_disposition")
		publication, publicationOK := semanticBool(row, "publication_allowed_without_complete_coordinates")
		if !idOK || !versionOK || !digestOK || unresolved != "fail_closed" || !unresolvedOK || !publicationOK || publication {
			t.Fatalf("documentation resolution profile is not one exact fail-closed binding")
		}
		references = append(references, dependencyProfileReference{id: id, version: version, digest: digest})
	}
	if len(references) != 0 {
		sort.Slice(references, func(i, j int) bool {
			return dependencyProfileReferenceKey(references[i]) < dependencyProfileReferenceKey(references[j])
		})
		return references[0]
	}
	if !required {
		return dependencyProfileReference{}
	}
	ref := dependencyProfileReference{id: "fixture_source_neutral_exact_computation_resolution", version: "1", digest: sha256Hex([]byte("fixture source-neutral exact-computation resolution profile v1"))}
	addition := map[string]interface{}{"row_kind": "dependency_resolution_profile", "resolution_profile_id": ref.id, "resolution_profile_version": ref.version, "resolution_profile_sha256": ref.digest, "unresolved_disposition": "fail_closed", "publication_allowed_without_complete_coordinates": false}
	out := make([]interface{}, 0, len(rows)+1)
	for _, row := range rows {
		if row["row_kind"] == "validation_summary" {
			out = append(out, addition)
			row["dependency_resolution_profile_count"] = 1
		}
		out = append(out, row)
	}
	writeJSONL(t, path, out)
	return ref
}
