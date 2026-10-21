package providerplan

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestAPIGraphApplicabilityUsesProductionBindingAndPropertyMechanics(t *testing.T) {
	t.Parallel()
	ood := minimalSourceSemanticOOD()
	oodDigest := strings.Repeat("a", 64)
	evaluationDigest := strings.Repeat("b", 64)
	rows := dependencySemanticRows{
		path: "api-applicability.jsonl",
		raw:  []byte("api-applicability"),
		byKind: map[string][]dependencySemanticRow{
			"artifact_manifest": {{line: 1, kind: "artifact_manifest", data: map[string]interface{}{
				"row_kind": "artifact_manifest", "canonical_ood_graph_sha256": oodDigest,
				"source_neutral": true, "transient_expansion_required": true, "candidate_rows_are_authority": false,
				"closed_dispositions": []interface{}{"required", "optional", "inapplicable"},
				"evaluation_profile_binding": map[string]interface{}{
					"evaluation_profile_id": "fixture_api_applicability", "evaluation_profile_version": "1", "evaluation_profile_sha256": evaluationDigest,
				},
			}}},
			"relationship_applicability_rule": {{line: 2, kind: "relationship_applicability_rule", data: map[string]interface{}{
				"row_kind": "relationship_applicability_rule", "applicability_rule_id": "fixture_write_rule",
				"relationship_label": "operation_writes_resource", "source_api_element_role": "operation", "target_api_element_role": "resource",
				"applicability_subject_endpoint": "source", "applicability_subject_role": "operation", "default_disposition": "optional",
				"ordered_conditional_rules": []interface{}{map[string]interface{}{
					"ordinal": json.Number("0"), "predicate": map[string]interface{}{
						"predicate_kind": "classifier_output_in", "classifier_profile_id": "fixture_access_classifier",
						// Authored profile order is data, not a Go-owned lexical convention.
						"values": []interface{}{"writes_exact_source_resource", "event_reports_mutation_of_exact_source_resource"},
					}, "disposition": "required",
				}},
				"required_cardinality":           map[string]interface{}{"minimum": json.Number("1"), "maximum": json.Number("1")},
				"unmatched_endpoint_disposition": "inapplicable",
			}}},
			"property_family_applicability_rule": {{line: 3, kind: "property_family_applicability_rule", data: map[string]interface{}{
				"row_kind": "property_family_applicability_rule", "applicability_rule_id": "fixture_property_rule", "property_family": "fixture_property",
				"eligible_subject_kinds": []interface{}{"api_symbol_object"}, "allowed_api_symbol_roles": []interface{}{"operation"},
				"api_relationship_label_scope": []interface{}{}, "default_disposition": "optional", "ordered_conditional_rules": []interface{}{},
				"disallowed_subject_disposition": "inapplicable", "maximum_claims_per_subject": json.Number("1"),
			}}},
			"claim_applicability_rule": {{line: 4, kind: "claim_applicability_rule", data: map[string]interface{}{
				"row_kind": "claim_applicability_rule", "applicability_rule_id": "fixture_claim_rule", "blocked_claim_kind": "fixture_required_claim",
				"blocked_subject_kind": "api_symbol_object", "default_disposition": "optional",
				"ordered_conditional_rules": []interface{}{map[string]interface{}{"ordinal": json.Number("0"), "predicate": map[string]interface{}{"predicate_kind": "always"}, "disposition": "required"}},
				"required_cardinality":      map[string]interface{}{"minimum": json.Number("1"), "maximum": json.Number("1")},
			}}},
			"validation_summary": {{line: 5, kind: "validation_summary", data: map[string]interface{}{
				"row_kind": "validation_summary", "relationship_applicability_rule_count": json.Number("1"),
				"property_family_applicability_rule_count": json.Number("1"), "claim_applicability_rule_count": json.Number("1"),
				"subject_expansion_persisted": false, "optional_absence_rows_persisted": false, "canonical_admission_authorized": false,
			}}},
		},
	}
	plan := &parsedPlan{Manifest: &artifactManifest{CanonicalOODGraphSHA256: oodDigest}, Gaps: map[string]graphGap{}}
	state, err := validateAPIGraphApplicabilityRows(rows, plan, ood)
	if err != nil {
		t.Fatalf("validateAPIGraphApplicabilityRows() error = %v", err)
	}
	if state.binding != (applicabilityProfileBinding{id: "fixture_api_applicability", version: "1", digest: evaluationDigest}) {
		t.Fatalf("evaluation binding = %+v", state.binding)
	}
	if state.propertyByID["fixture_property_rule"].maximumClaimsPerSubject != 1 {
		t.Fatalf("property rule mechanics were not parsed from maximum_claims_per_subject")
	}
}

func TestOperationApplicabilityPredicateFailsClosedOnMissingTrait(t *testing.T) {
	t.Parallel()
	predicate := applicabilityPredicate{kind: "subject_trait_equals", trait: "documented_capability", value: true}
	_, err := operationApplicabilityPredicateMatches(predicate, operationApplicabilityEntry{subjectTraits: map[string]interface{}{}})
	if err == nil || !strings.Contains(err.Error(), "omits required subject trait") {
		t.Fatalf("error = %v, want missing-trait refusal", err)
	}
}

func TestApplicabilityBindingNamespacesAreNotInterchangeable(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("c", 64)
	object := map[string]interface{}{
		"evaluation_profile_binding": map[string]interface{}{
			"evaluation_profile_id": "evaluation", "evaluation_profile_version": "1", "evaluation_profile_sha256": digest,
		},
		"applicability_profile_binding": map[string]interface{}{
			"applicability_profile_id": "applicability", "applicability_profile_version": "1", "applicability_profile_sha256": digest,
		},
	}
	evaluation, err := parseEvaluationProfileBinding(object, "evaluation_profile_binding")
	if err != nil || evaluation.id != "evaluation" {
		t.Fatalf("evaluation binding = %+v, err = %v", evaluation, err)
	}
	applicability, err := parseApplicabilityProfileBinding(object, "applicability_profile_binding")
	if err != nil || applicability.id != "applicability" {
		t.Fatalf("applicability binding = %+v, err = %v", applicability, err)
	}
	if _, err := parseApplicabilityProfileBinding(object, "evaluation_profile_binding"); err == nil {
		t.Fatal("applicability parser accepted evaluation_* field names")
	}
}

func TestOperationApplicabilityRejectsDuplicateProtocolDispositionAuthority(t *testing.T) {
	t.Parallel()
	rows := dependencySemanticRows{
		path: "operation-applicability.jsonl",
		byKind: map[string][]dependencySemanticRow{
			"artifact_manifest":              {{line: 1, kind: "artifact_manifest", data: map[string]interface{}{"row_kind": "artifact_manifest"}}},
			"protocol_assertion_disposition": {{line: 2, kind: "protocol_assertion_disposition", data: map[string]interface{}{"row_kind": "protocol_assertion_disposition"}}},
		},
	}
	_, err := validateOperationApplicabilityRows(rows, dependencySemanticRows{}, dependencySemanticRows{}, dependencySemanticRows{}, dependencySemanticRows{}, &parsedPlan{}, apiGraphApplicabilityState{}, documentationClaimDerivationState{})
	if err == nil || !strings.Contains(err.Error(), "duplicate protocol_assertion_disposition") || !strings.Contains(err.Error(), "sole disposition authority") {
		t.Fatalf("error = %v, want duplicate protocol-disposition authority refusal", err)
	}
}

func TestRelationshipApplicabilityCoversResourceAndSchemaSubjects(t *testing.T) {
	t.Parallel()
	maximum := int64(1)
	state := apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{
		"resource_uses_lifecycle_shape": {
			id: "resource_rule", label: "resource_uses_lifecycle_shape", sourceRole: "resource", targetRole: "lifecycle_shape", subjectEndpoint: "source", subjectRole: "resource", defaultDisposition: applicabilityDispositionRequired, cardinality: applicabilityCardinality{minimum: 1, maximum: &maximum},
		},
		"schema_uses_reference_and_discriminated_union_shape": {
			id: "schema_rule", label: "schema_uses_reference_and_discriminated_union_shape", sourceRole: "schema_element", targetRole: "reference_and_discriminated_union_shape", subjectEndpoint: "source", subjectRole: "schema_element", defaultDisposition: applicabilityDispositionRequired, cardinality: applicabilityCardinality{minimum: 1, maximum: &maximum},
		},
	}, propertyByID: map[string]propertyApplicabilityRule{}, claimByID: map[string]claimApplicabilityRule{}, allRuleKindsByID: map[string]string{}}
	newPlan := func() *parsedPlan {
		return &parsedPlan{
			Symbols: map[string]apiSymbol{
				"resource": {ID: "resource", Role: "resource"}, "lifecycle": {ID: "lifecycle", Role: "lifecycle_shape"},
				"schema": {ID: "schema", Role: "schema_element"}, "reference": {ID: "reference", Role: "reference_and_discriminated_union_shape"},
			},
			Relationships: map[string]apiRelationship{
				"resource_fact": {ID: "resource_fact", Label: "resource_uses_lifecycle_shape", SourceID: "resource", TargetID: "lifecycle"},
				"schema_fact":   {ID: "schema_fact", Label: "schema_uses_reference_and_discriminated_union_shape", SourceID: "schema", TargetID: "reference"},
			},
			Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{},
		}
	}
	if err := validateGraphApplicabilityCoverage(newPlan(), state, operationApplicabilityState{}); err != nil {
		t.Fatalf("complete resource/schema relationship coverage rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		remove string
		want   string
	}{{name: "resource", remove: "resource_fact", want: "resource_uses_lifecycle_shape"}, {name: "schema", remove: "schema_fact", want: "schema_uses_reference_and_discriminated_union_shape"}} {
		t.Run(test.name, func(t *testing.T) {
			plan := newPlan()
			delete(plan.Relationships, test.remove)
			err := validateGraphApplicabilityCoverage(plan, state, operationApplicabilityState{})
			if err == nil || !strings.Contains(err.Error(), test.want) || !strings.Contains(err.Error(), "below minimum") {
				t.Fatalf("error = %v, want missing required non-operation relationship refusal", err)
			}
		})
	}
	t.Run("required non-operation gap is consumed", func(t *testing.T) {
		plan := newPlan()
		delete(plan.Relationships, "resource_fact")
		plan.Gaps["resource_gap"] = graphGap{ID: "resource_gap", ApplicabilityRuleID: "resource_rule", BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "resource", BlockedClaimKind: "api_relationship"}
		proof, err := compileGraphApplicabilityCoverage(plan, state, operationApplicabilityState{})
		if err != nil {
			t.Fatalf("required non-operation relationship gap rejected: %v", err)
		}
		if err := validateNoOrphanGraphGaps(plan, operationApplicabilityState{coverageProof: proof}); err != nil {
			t.Fatalf("required non-operation relationship gap was not consumed: %v", err)
		}
	})
}

func TestRelationshipApplicabilityRejectsOptionalAndInapplicableGaps(t *testing.T) {
	t.Parallel()
	maximum := int64(1)
	for _, disposition := range []string{applicabilityDispositionOptional, applicabilityDispositionInapplicable} {
		t.Run(disposition, func(t *testing.T) {
			rule := relationshipApplicabilityRule{id: "resource_rule", label: "resource_uses_lifecycle_shape", sourceRole: "resource", targetRole: "lifecycle_shape", subjectEndpoint: "source", subjectRole: "resource", defaultDisposition: disposition, cardinality: applicabilityCardinality{minimum: 1, maximum: &maximum}}
			state := apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{rule.label: rule}, propertyByID: map[string]propertyApplicabilityRule{}, claimByID: map[string]claimApplicabilityRule{}, allRuleKindsByID: map[string]string{rule.id: "relationship"}}
			plan := &parsedPlan{Symbols: map[string]apiSymbol{"resource": {ID: "resource", Role: "resource"}}, Relationships: map[string]apiRelationship{}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{
				"gap": {ID: "gap", ApplicabilityRuleID: rule.id, BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "resource", BlockedClaimKind: "api_relationship"},
			}}
			err := validateGraphApplicabilityCoverage(plan, state, operationApplicabilityState{})
			if err == nil || !strings.Contains(err.Error(), disposition+" disposition") {
				t.Fatalf("error = %v, want %s relationship-gap refusal", err, disposition)
			}
		})
	}
}

func TestRelationshipApplicabilityFailsClosedWithoutNonOperationPredicateInputs(t *testing.T) {
	t.Parallel()
	maximum := int64(1)
	state := apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{
		"resource_uses_lifecycle_shape": {
			id: "resource_rule", label: "resource_uses_lifecycle_shape", sourceRole: "resource", targetRole: "lifecycle_shape", subjectEndpoint: "source", subjectRole: "resource", defaultDisposition: applicabilityDispositionOptional, cardinality: applicabilityCardinality{minimum: 1, maximum: &maximum}, conditionalRules: []applicabilityConditionalRule{{disposition: applicabilityDispositionRequired, predicate: applicabilityPredicate{kind: "subject_trait_equals", trait: "has_lifecycle", value: true}}},
		},
	}, propertyByID: map[string]propertyApplicabilityRule{}, claimByID: map[string]claimApplicabilityRule{}, allRuleKindsByID: map[string]string{}}
	plan := &parsedPlan{Symbols: map[string]apiSymbol{"resource": {ID: "resource", Role: "resource"}}, Relationships: map[string]apiRelationship{}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{}}
	err := validateGraphApplicabilityCoverage(plan, state, operationApplicabilityState{})
	if err == nil || !strings.Contains(err.Error(), "classifier inputs unavailable") {
		t.Fatalf("error = %v, want non-operation predicate-input refusal", err)
	}
}

func TestPropertyApplicabilityEnforcesSubjectDispositionAndCardinality(t *testing.T) {
	t.Parallel()
	basePlan := func() *parsedPlan {
		return &parsedPlan{Symbols: map[string]apiSymbol{"operation": {ID: "operation", Role: "operation"}, "resource": {ID: "resource", Role: "resource"}}, Relationships: map[string]apiRelationship{}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{}}
	}
	stateFor := func(disposition string, maximum int64) apiGraphApplicabilityState {
		return apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{}, propertyByID: map[string]propertyApplicabilityRule{
			"property_rule": {id: "property_rule", family: "fixture_property", eligibleSubjectKinds: map[string]struct{}{"api_symbol_object": {}}, allowedRoles: map[string]struct{}{"operation": {}}, relationshipLabelScope: map[string]struct{}{}, defaultDisposition: disposition, disallowedSubjectDisposition: applicabilityDispositionInapplicable, maximumClaimsPerSubject: maximum},
		}, claimByID: map[string]claimApplicabilityRule{}, allRuleKindsByID: map[string]string{"property_rule": "property_family"}}
	}
	t.Run("disallowed role fact", func(t *testing.T) {
		plan := basePlan()
		plan.Properties["property"] = apiPropertyClaim{ID: "property", Family: "fixture_property", SubjectKind: "api_symbol_object", SubjectID: "resource"}
		err := validateGraphApplicabilityCoverage(plan, stateFor(applicabilityDispositionOptional, 1), operationApplicabilityState{})
		if err == nil || !strings.Contains(err.Error(), "inapplicable disposition") {
			t.Fatalf("error = %v, want disallowed property-fact refusal", err)
		}
	})
	t.Run("over maximum", func(t *testing.T) {
		plan := basePlan()
		plan.Properties["one"] = apiPropertyClaim{ID: "one", Family: "fixture_property", SubjectKind: "api_symbol_object", SubjectID: "operation"}
		plan.Properties["two"] = apiPropertyClaim{ID: "two", Family: "fixture_property", SubjectKind: "api_symbol_object", SubjectID: "operation"}
		err := validateGraphApplicabilityCoverage(plan, stateFor(applicabilityDispositionOptional, 1), operationApplicabilityState{})
		if err == nil || !strings.Contains(err.Error(), "maximum_claims_per_subject") {
			t.Fatalf("error = %v, want over-maximum property refusal", err)
		}
	})
	t.Run("missing required fact or gap", func(t *testing.T) {
		err := validateGraphApplicabilityCoverage(basePlan(), stateFor(applicabilityDispositionRequired, 1), operationApplicabilityState{})
		if err == nil || !strings.Contains(err.Error(), "no materialized fact or exact fail-closed gap") {
			t.Fatalf("error = %v, want missing required property coverage refusal", err)
		}
	})
	t.Run("required exact gap", func(t *testing.T) {
		plan := basePlan()
		plan.Gaps["gap"] = graphGap{ID: "gap", ApplicabilityRuleID: "property_rule", BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "operation", BlockedClaimKind: "api_property_claim"}
		proof, err := compileGraphApplicabilityCoverage(plan, stateFor(applicabilityDispositionRequired, 1), operationApplicabilityState{})
		if err != nil {
			t.Fatalf("exact required property gap rejected: %v", err)
		}
		if err := validateNoOrphanGraphGaps(plan, operationApplicabilityState{coverageProof: proof}); err != nil {
			t.Fatalf("exact required property gap was not consumed by its applicability proof: %v", err)
		}
	})
	for _, disposition := range []string{applicabilityDispositionOptional, applicabilityDispositionInapplicable} {
		t.Run(disposition+" gap", func(t *testing.T) {
			plan := basePlan()
			plan.Gaps["gap"] = graphGap{ID: "gap", ApplicabilityRuleID: "property_rule", BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "operation", BlockedClaimKind: "api_property_claim"}
			err := validateGraphApplicabilityCoverage(plan, stateFor(disposition, 1), operationApplicabilityState{})
			if err == nil || !strings.Contains(err.Error(), disposition+" disposition") {
				t.Fatalf("error = %v, want %s property-gap refusal", err, disposition)
			}
		})
	}
	t.Run("inapplicable fact", func(t *testing.T) {
		plan := basePlan()
		plan.Properties["property"] = apiPropertyClaim{ID: "property", Family: "fixture_property", SubjectKind: "api_symbol_object", SubjectID: "operation"}
		err := validateGraphApplicabilityCoverage(plan, stateFor(applicabilityDispositionInapplicable, 1), operationApplicabilityState{})
		if err == nil || !strings.Contains(err.Error(), "inapplicable disposition") {
			t.Fatalf("error = %v, want inapplicable property-fact refusal", err)
		}
	})
	t.Run("relationship label scope", func(t *testing.T) {
		rule := propertyApplicabilityRule{
			id: "relationship_property_rule", family: "fixture_relationship_property", eligibleSubjectKinds: map[string]struct{}{"api_relationship_edge": {}}, allowedRoles: map[string]struct{}{},
			relationshipLabelScope: map[string]struct{}{"operation_uses_schema": {}}, defaultDisposition: applicabilityDispositionOptional, disallowedSubjectDisposition: applicabilityDispositionInapplicable, maximumClaimsPerSubject: 1,
		}
		state := apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{}, propertyByID: map[string]propertyApplicabilityRule{rule.id: rule}, claimByID: map[string]claimApplicabilityRule{}, allRuleKindsByID: map[string]string{rule.id: "property_family"}}
		plan := &parsedPlan{Symbols: map[string]apiSymbol{}, Relationships: map[string]apiRelationship{
			"allowed":    {ID: "allowed", Label: "operation_uses_schema"},
			"disallowed": {ID: "disallowed", Label: "operation_reads_resource"},
		}, Properties: map[string]apiPropertyClaim{
			"allowed_property": {ID: "allowed_property", Family: rule.family, SubjectKind: "api_relationship_edge", SubjectID: "allowed"},
		}, Gaps: map[string]graphGap{}}
		if err := validateGraphApplicabilityCoverage(plan, state, operationApplicabilityState{}); err != nil {
			t.Fatalf("allowed relationship-scoped property rejected: %v", err)
		}
		plan.Properties["disallowed_property"] = apiPropertyClaim{ID: "disallowed_property", Family: rule.family, SubjectKind: "api_relationship_edge", SubjectID: "disallowed"}
		if err := validateGraphApplicabilityCoverage(plan, state, operationApplicabilityState{}); err == nil || !strings.Contains(err.Error(), "inapplicable disposition") {
			t.Fatalf("error = %v, want out-of-scope relationship property refusal", err)
		}
	})
}

func TestNoOrphanGraphGapsConsumesOnlySealedRequiredDispositionProof(t *testing.T) {
	t.Parallel()
	plan := &parsedPlan{Gaps: map[string]graphGap{"required_gap": {ID: "required_gap"}}}
	if err := validateNoOrphanGraphGaps(plan, operationApplicabilityState{}); err == nil || !strings.Contains(err.Error(), "no independently evaluated applicability proof") {
		t.Fatalf("error = %v, want missing-proof refusal", err)
	}
	proof := applicabilityCoverageProof{seal: applicabilityCoverageProofSeal, requiredGapIDs: map[string]struct{}{"required_gap": {}}}
	if err := validateNoOrphanGraphGaps(plan, operationApplicabilityState{coverageProof: proof}); err != nil {
		t.Fatalf("exact sealed required-gap proof rejected: %v", err)
	}
	proof.requiredGapIDs["orphan"] = struct{}{}
	if err := validateNoOrphanGraphGaps(plan, operationApplicabilityState{coverageProof: proof}); err == nil || !strings.Contains(err.Error(), "does not equal") {
		t.Fatalf("error = %v, want extra/orphan proof refusal", err)
	}
}

func TestClaimApplicabilityIsTotalAcrossIndependentSubjectRoster(t *testing.T) {
	t.Parallel()
	maximum := int64(1)
	stateFor := func(disposition string) apiGraphApplicabilityState {
		return apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{}, propertyByID: map[string]propertyApplicabilityRule{}, claimByID: map[string]claimApplicabilityRule{
			"claim_rule": {id: "claim_rule", blockedClaimKind: "fixture_claim", blockedSubjectKind: "api_symbol_object", defaultDisposition: disposition, cardinality: applicabilityCardinality{minimum: 1, maximum: &maximum}},
		}, allRuleKindsByID: map[string]string{"claim_rule": "claim"}}
	}
	newPlan := func() *parsedPlan {
		return &parsedPlan{Symbols: map[string]apiSymbol{"operation": {ID: "operation", Role: "operation"}}, Relationships: map[string]apiRelationship{}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{}}
	}
	if err := validateGraphApplicabilityCoverage(newPlan(), stateFor(applicabilityDispositionRequired), operationApplicabilityState{}); err == nil || !strings.Contains(err.Error(), "below minimum") {
		t.Fatalf("error = %v, want required claim zero-coverage refusal", err)
	}
	plan := newPlan()
	plan.Gaps["gap"] = graphGap{ID: "gap", ApplicabilityRuleID: "claim_rule", BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "operation", BlockedClaimKind: "fixture_claim"}
	proof, err := compileGraphApplicabilityCoverage(plan, stateFor(applicabilityDispositionRequired), operationApplicabilityState{})
	if err != nil {
		t.Fatalf("required exact claim gap rejected: %v", err)
	}
	if err := validateNoOrphanGraphGaps(plan, operationApplicabilityState{coverageProof: proof}); err != nil {
		t.Fatalf("required exact claim gap was not consumed: %v", err)
	}
	for _, disposition := range []string{applicabilityDispositionOptional, applicabilityDispositionInapplicable} {
		t.Run(disposition, func(t *testing.T) {
			if err := validateGraphApplicabilityCoverage(newPlan(), stateFor(disposition), operationApplicabilityState{}); err != nil {
				t.Fatalf("zero-coverage %s claim subject rejected: %v", disposition, err)
			}
			plan := newPlan()
			plan.Gaps["gap"] = graphGap{ID: "gap", ApplicabilityRuleID: "claim_rule", BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "operation", BlockedClaimKind: "fixture_claim"}
			err := validateGraphApplicabilityCoverage(plan, stateFor(disposition), operationApplicabilityState{})
			if err == nil || !strings.Contains(err.Error(), disposition+" disposition") {
				t.Fatalf("error = %v, want %s claim-gap refusal", err, disposition)
			}
		})
	}
}

func TestRelationshipDeletionCannotChangeIndependentlyEstablishedDisposition(t *testing.T) {
	t.Parallel()
	maximum := int64(1)
	rule := relationshipApplicabilityRule{id: "write_rule", label: "operation_writes_resource", sourceRole: "operation", targetRole: "resource", subjectEndpoint: "source", subjectRole: "operation", defaultDisposition: applicabilityDispositionInapplicable, conditionalRules: []applicabilityConditionalRule{{disposition: applicabilityDispositionRequired, predicate: applicabilityPredicate{kind: "subject_trait_equals", trait: "writes_resource", value: true}}}, cardinality: applicabilityCardinality{minimum: 1, maximum: &maximum}}
	apiState := apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{rule.label: rule}, propertyByID: map[string]propertyApplicabilityRule{}, claimByID: map[string]claimApplicabilityRule{}, allRuleKindsByID: map[string]string{rule.id: "relationship"}}
	entry := operationApplicabilityEntry{operationID: "operation", subjectTraits: map[string]interface{}{"writes_resource": true}, resourceAccesses: []operationResourceAccess{{resourceID: "resource", relationshipLabel: "operation_writes_resource"}}}
	operations := operationApplicabilityState{byOperationID: map[string]operationApplicabilityEntry{"operation": entry}}
	plan := &parsedPlan{Symbols: map[string]apiSymbol{"operation": {ID: "operation", Role: "operation"}, "resource": {ID: "resource", Role: "resource"}}, Relationships: map[string]apiRelationship{"writes": {ID: "writes", Label: rule.label, SourceID: "operation", TargetID: "resource"}}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{}}
	subject := graphApplicabilitySubject{kind: "api_symbol_object", id: "operation"}
	before, err := evaluateGraphSubjectDisposition(rule.defaultDisposition, rule.conditionalRules, subject, operations)
	if err != nil || before != applicabilityDispositionRequired {
		t.Fatalf("pre-deletion disposition = %q, err = %v, want required", before, err)
	}
	delete(plan.Relationships, "writes")
	after, err := evaluateGraphSubjectDisposition(rule.defaultDisposition, rule.conditionalRules, subject, operations)
	if err != nil || after != before {
		t.Fatalf("post-deletion disposition = %q, err = %v, want unchanged %q", after, err, before)
	}
	if err := validateGraphApplicabilityCoverage(plan, apiState, operations); err == nil || !strings.Contains(err.Error(), "fact-or-gap coverage 0") {
		t.Fatalf("error = %v, want deleted required fact refusal without disposition feedback", err)
	}
}

func TestOperationClassifierRejectsNumericOnlyProgram(t *testing.T) {
	t.Parallel()
	program := map[string]interface{}{"numeric_lexeme_preserved": true}
	canonical, err := canonicalOperationClassifierProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	reference := dependencyProfileReference{id: "numeric_classifier", version: "1", digest: sha256Hex(canonical)}
	derivation := documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{dependencyProfileReferenceKey(reference): {
		claimKind: "documented_field_claim", semanticClasses: map[string]struct{}{"exact_decimal": {}}, carriers: map[string]struct{}{"source_lexeme": {}}, computationPaths: map[string]struct{}{"unresolved_fail_closed_gap": {}}, program: program,
	}}}
	entry := operationApplicabilityEntry{operationID: "operation", classifierReference: reference, subjectTraits: map[string]interface{}{"writes_resource": true}}
	err = validateOperationClassifierOutput(entry, derivation, dependencySemanticRows{}, dependencySemanticRows{})
	if err == nil || (!strings.Contains(err.Error(), "program_kind") && !strings.Contains(err.Error(), "program fields")) {
		t.Fatalf("error = %v, want numeric-only classifier refusal", err)
	}
}

func TestOperationClassifierReexecutesAcyclicSourceAndProtocolFacts(t *testing.T) {
	t.Parallel()
	profile, reference := testOperationClassifierProfile(t)
	derivation := documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{dependencyProfileReferenceKey(reference): profile}}
	digest := strings.Repeat("a", 64)
	coordinate := map[string]interface{}{"source_content_sha256": digest, "byte_start_offset": json.Number("0"), "byte_end_offset_exclusive": json.Number("1"), "selected_range_byte_count": json.Number("1"), "selected_range_sha256": digest}
	sourceOperationIdentity := map[string]interface{}{"identity_kind": "message_queue_consumer", "identity_components": map[string]interface{}{"delivery_mode": "at_least_once", "subscription": "records"}}
	sourceData := map[string]interface{}{
		"row_kind": "api_operation", "source_symbol": "fixture", "source_operation_identity": sourceOperationIdentity,
		"resource_accesses": []interface{}{map[string]interface{}{"source_symbol": "fixture", "relationship_label": "operation_reads_resource", "evidence_locator_ids": []interface{}{"locator_a"}, "documentation_derived_fact_ids": []interface{}{"docfact_read"}}}, "evidence_hydration_coordinate": coordinate,
	}
	sourceRaw, err := json.Marshal(sourceData)
	if err != nil {
		t.Fatal(err)
	}
	sourceRows := dependencySemanticRows{raw: []byte("source-artifact"), byKind: map[string][]dependencySemanticRow{"api_operation": {{line: 1, kind: "api_operation", raw: sourceRaw, data: sourceData}}}}
	sourceIdentity, err := sourceOperationSemanticKey("fixture", sourceOperationIdentity)
	if err != nil {
		t.Fatal(err)
	}
	readTraits := map[string]interface{}{"emits_change_event": false, "reads_resource": true, "writes_resource": false}
	sourceBinding := operationClassifierInputBinding{artifactRole: operationClassifierSourceArtifactRole, artifactSHA256: sha256Hex(sourceRows.raw), rowKind: "api_operation", rowIdentity: sourceIdentity, rowSHA256: sha256Hex(sourceRaw), factLocatorKind: "resource_access_ordinal", factOrdinal: 0}
	sourceEntry := operationApplicabilityEntry{
		operationID: "operation", semanticIdentity: sourceIdentity, operationKind: "request_response_read_operation", subjectTraits: readTraits, sourceSymbol: "fixture", classifierReference: reference,
		sourceIdentity: sourceOperationIdentity, evidenceLocatorIDs: map[string]struct{}{"locator_a": {}}, evidenceFactIDs: map[string]struct{}{"docfact_read": {}},
		resourceAccesses: []operationResourceAccess{{id: "source_access", resourceID: "resource", resourceSemanticIdentity: "resource:fixture", resourceSourceSymbol: "fixture", relationshipLabel: "operation_reads_resource", accessSemantics: "reads_exact_source_resource", classifierInputBinding: sourceBinding, evidenceLocatorIDs: map[string]struct{}{"locator_a": {}}, evidenceFactIDs: map[string]struct{}{"docfact_read": {}}}},
	}
	if err := validateOperationClassifierOutput(sourceEntry, derivation, sourceRows, dependencySemanticRows{}); err != nil {
		t.Fatalf("source predecessor classifier reexecution rejected: %v", err)
	}
	mutated := sourceEntry
	mutated.subjectTraits = map[string]interface{}{"emits_change_event": true, "reads_resource": true, "writes_resource": false}
	if err := validateOperationClassifierOutput(mutated, derivation, sourceRows, dependencySemanticRows{}); err == nil || !strings.Contains(err.Error(), "does not equal generic classifier reexecution") {
		t.Fatalf("error = %v, want sidecar trait substitution refusal", err)
	}

	protocolOperationIdentity := map[string]interface{}{"identity_kind": "protocol_assertion_operation", "identity_components": map[string]interface{}{"assertion_set": "fixture_change_event_write"}}
	canonicalProtocolIdentity, err := canonicalSourceOperationIdentity(protocolOperationIdentity)
	if err != nil {
		t.Fatal(err)
	}
	protocolFactID := stableID("opfact", lengthPrefixedIdentityKey("fixture", "fixture", "change_event_write", string(canonicalProtocolIdentity), "fixture_protocol_a", "fixture_protocol_b"))
	protocolData := map[string]interface{}{
		"row_kind": "operation_classifier_fact", "operation_classifier_fact_id": protocolFactID, "source_symbol": "fixture", "resource_source_symbol": "fixture", "semantic_class": "change_event_write",
		"source_operation_identity": protocolOperationIdentity, "protocol_assertion_ids": []interface{}{"fixture_protocol_a", "fixture_protocol_b"}, "evidence_locator_ids": []interface{}{"locator_a"}, "source_bytes_present": false,
	}
	protocolRaw, err := json.Marshal(protocolData)
	if err != nil {
		t.Fatal(err)
	}
	protocolRows := dependencySemanticRows{raw: []byte("protocol-artifact"), byKind: map[string][]dependencySemanticRow{
		"operation_classifier_fact": {{line: 1, kind: "operation_classifier_fact", raw: protocolRaw, data: protocolData}},
		"protocol_assertion_projection": {
			{line: 2, kind: "protocol_assertion_projection", data: map[string]interface{}{"assertion_id": "fixture_protocol_a"}},
			{line: 3, kind: "protocol_assertion_projection", data: map[string]interface{}{"assertion_id": "fixture_protocol_b"}},
		},
	}}
	writeTraits := map[string]interface{}{"emits_change_event": true, "reads_resource": false, "writes_resource": true}
	protocolBinding := operationClassifierInputBinding{artifactRole: operationClassifierProtocolArtifactRole, artifactSHA256: sha256Hex(protocolRows.raw), rowKind: "operation_classifier_fact", rowIdentity: protocolFactID, rowSHA256: sha256Hex(protocolRaw), factLocatorKind: "whole_row", factOrdinal: -1}
	protocolEntry := operationApplicabilityEntry{
		operationID: "operation", operationKind: "event_driven_write_operation", subjectTraits: writeTraits, sourceSymbol: "fixture", classifierReference: reference, evidenceLocatorIDs: map[string]struct{}{"locator_a": {}}, evidenceFactIDs: map[string]struct{}{"fixture_protocol_a": {}, "fixture_protocol_b": {}},
		sourceIdentity:   protocolOperationIdentity,
		resourceAccesses: []operationResourceAccess{{id: "protocol_access", resourceID: "resource", resourceSemanticIdentity: "resource:fixture", resourceSourceSymbol: "fixture", relationshipLabel: "operation_writes_resource", accessSemantics: "writes_exact_source_resource", classifierInputBinding: protocolBinding, evidenceLocatorIDs: map[string]struct{}{"locator_a": {}}, evidenceFactIDs: map[string]struct{}{"fixture_protocol_a": {}, "fixture_protocol_b": {}}}},
	}
	if err := validateOperationClassifierOutput(protocolEntry, derivation, dependencySemanticRows{}, protocolRows); err != nil {
		t.Fatalf("protocol predecessor classifier reexecution rejected: %v", err)
	}
}

func TestOperationClassifierReexecutesCompleteReadWriteResourceRoster(t *testing.T) {
	t.Parallel()
	profile, reference := testOperationClassifierProfile(t)
	derivation := documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{dependencyProfileReferenceKey(reference): profile}}
	digest := strings.Repeat("a", 64)
	identity := map[string]interface{}{"identity_kind": "message_queue_transform", "identity_components": map[string]interface{}{"consumer": "incoming_records", "producer": "normalized_records"}}
	coordinate := map[string]interface{}{"source_content_sha256": digest, "byte_start_offset": json.Number("0"), "byte_end_offset_exclusive": json.Number("1"), "selected_range_byte_count": json.Number("1"), "selected_range_sha256": digest}
	sourceData := map[string]interface{}{
		"row_kind": "api_operation", "source_symbol": "operation_source", "source_operation_identity": identity,
		"resource_accesses": []interface{}{
			map[string]interface{}{"source_symbol": "resource_a", "relationship_label": "operation_reads_resource", "evidence_locator_ids": []interface{}{"locator_read_a"}, "documentation_derived_fact_ids": []interface{}{"docfact_read_a"}},
			map[string]interface{}{"source_symbol": "resource_b", "relationship_label": "operation_writes_resource", "evidence_locator_ids": []interface{}{"locator_write_b"}, "documentation_derived_fact_ids": []interface{}{"docfact_write_b"}},
		},
		"evidence_hydration_coordinate": coordinate,
	}
	sourceRaw, err := json.Marshal(sourceData)
	if err != nil {
		t.Fatal(err)
	}
	sourceRows := dependencySemanticRows{raw: []byte("source-artifact"), byKind: map[string][]dependencySemanticRow{"api_operation": {{line: 1, kind: "api_operation", raw: sourceRaw, data: sourceData}}}}
	semanticKey, err := sourceOperationSemanticKey("operation_source", identity)
	if err != nil {
		t.Fatal(err)
	}
	newAccess := func(ordinal int64, resourceID, sourceSymbol, label, semantics, locatorID, factID string) operationResourceAccess {
		return operationResourceAccess{
			id: "access_" + resourceID, resourceID: resourceID, resourceSemanticIdentity: "resource:" + sourceSymbol, resourceSourceSymbol: sourceSymbol, relationshipLabel: label, accessSemantics: semantics,
			classifierInputBinding: operationClassifierInputBinding{artifactRole: operationClassifierSourceArtifactRole, artifactSHA256: sha256Hex(sourceRows.raw), rowKind: "api_operation", rowIdentity: semanticKey, rowSHA256: sha256Hex(sourceRaw), factLocatorKind: "resource_access_ordinal", factOrdinal: ordinal},
			evidenceLocatorIDs:     map[string]struct{}{locatorID: {}}, evidenceFactIDs: map[string]struct{}{factID: {}},
		}
	}
	entry := operationApplicabilityEntry{
		operationID: "operation", semanticIdentity: semanticKey, operationKind: "resource_read_write_operation", sourceSymbol: "operation_source", sourceIdentity: identity, classifierReference: reference,
		subjectTraits: map[string]interface{}{"emits_change_event": false, "reads_resource": true, "writes_resource": true}, evidenceLocatorIDs: map[string]struct{}{"locator_read_a": {}, "locator_write_b": {}}, evidenceFactIDs: map[string]struct{}{"docfact_read_a": {}, "docfact_write_b": {}},
		resourceAccesses: []operationResourceAccess{
			newAccess(0, "resource_a", "resource_a", "operation_reads_resource", "reads_exact_source_resource", "locator_read_a", "docfact_read_a"),
			newAccess(1, "resource_b", "resource_b", "operation_writes_resource", "writes_exact_source_resource", "locator_write_b", "docfact_write_b"),
		},
	}
	if err := validateOperationClassifierOutput(entry, derivation, sourceRows, dependencySemanticRows{}); err != nil {
		t.Fatalf("read-A/write-B classifier roster rejected: %v", err)
	}
	t.Run("omission", func(t *testing.T) {
		mutated := entry
		mutated.resourceAccesses = append([]operationResourceAccess(nil), entry.resourceAccesses[:1]...)
		if err := validateOperationClassifierOutput(mutated, derivation, sourceRows, dependencySemanticRows{}); err == nil || !strings.Contains(err.Error(), "source-contract predecessor fact partition") {
			t.Fatalf("error = %v, want omitted predecessor fact refusal", err)
		}
	})
	t.Run("ordinal retarget", func(t *testing.T) {
		mutated := entry
		mutated.resourceAccesses = append([]operationResourceAccess(nil), entry.resourceAccesses...)
		mutated.resourceAccesses[1].classifierInputBinding.factOrdinal = 0
		if err := validateOperationClassifierOutput(mutated, derivation, sourceRows, dependencySemanticRows{}); err == nil || !strings.Contains(err.Error(), "selected access") {
			t.Fatalf("error = %v, want ordinal/resource retarget refusal", err)
		}
	})
	t.Run("label substitution", func(t *testing.T) {
		mutated := entry
		mutated.resourceAccesses = append([]operationResourceAccess(nil), entry.resourceAccesses...)
		mutated.resourceAccesses[0].relationshipLabel = "operation_writes_resource"
		if err := validateOperationClassifierOutput(mutated, derivation, sourceRows, dependencySemanticRows{}); err == nil || !strings.Contains(err.Error(), "selected access") {
			t.Fatalf("error = %v, want relationship-label substitution refusal", err)
		}
	})
	t.Run("aggregate kind substitution", func(t *testing.T) {
		mutated := entry
		mutated.operationKind = "request_response_read_operation"
		if err := validateOperationClassifierOutput(mutated, derivation, sourceRows, dependencySemanticRows{}); err == nil || !strings.Contains(err.Error(), "generic classifier reexecution") {
			t.Fatalf("error = %v, want aggregate operation-kind substitution refusal", err)
		}
	})
}

func TestOperationClassifierComposesExactSourceAndProtocolRolePartitions(t *testing.T) {
	t.Parallel()
	profile, reference := testOperationClassifierProfile(t)
	rules := profile.program["ordered_access_rules"].([]interface{})
	protocolOutput := rules[2].(map[string]interface{})["output"].(map[string]interface{})
	protocolOutput["subject_trait_contributions"].(map[string]interface{})["emits_change_event"] = false
	canonical, err := canonicalOperationClassifierProgram(profile.program)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	derivation := documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{dependencyProfileReferenceKey(reference): profile}}

	digest := strings.Repeat("a", 64)
	identity := map[string]interface{}{"identity_kind": "http_transform", "identity_components": map[string]interface{}{"method": "POST", "path": "/records/normalize"}}
	coordinate := map[string]interface{}{"source_content_sha256": digest, "byte_start_offset": json.Number("0"), "byte_end_offset_exclusive": json.Number("2"), "selected_range_byte_count": json.Number("2"), "selected_range_sha256": digest}
	sourceData := map[string]interface{}{
		"row_kind": "api_operation", "source_symbol": "operation_source", "source_operation_identity": identity,
		"resource_accesses": []interface{}{map[string]interface{}{
			"source_symbol": "resource_a", "relationship_label": "operation_reads_resource", "evidence_locator_ids": []interface{}{"locator_read_a"}, "documentation_derived_fact_ids": []interface{}{"docfact_read_a"},
		}}, "evidence_hydration_coordinate": coordinate,
	}
	sourceRaw, err := json.Marshal(sourceData)
	if err != nil {
		t.Fatal(err)
	}
	sourceRows := dependencySemanticRows{raw: []byte("source-artifact"), byKind: map[string][]dependencySemanticRow{"api_operation": {{line: 1, kind: "api_operation", raw: sourceRaw, data: sourceData}}}}
	semanticKey, err := sourceOperationSemanticKey("operation_source", identity)
	if err != nil {
		t.Fatal(err)
	}
	canonicalIdentity, err := canonicalSourceOperationIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	protocolFactID := stableID("opfact", lengthPrefixedIdentityKey("operation_source", "resource_b", "change_event_write", string(canonicalIdentity), "protocol_write_fact"))
	protocolData := map[string]interface{}{
		"row_kind": "operation_classifier_fact", "operation_classifier_fact_id": protocolFactID, "source_symbol": "operation_source", "resource_source_symbol": "resource_b", "semantic_class": "change_event_write",
		"source_operation_identity": identity, "protocol_assertion_ids": []interface{}{"protocol_write_fact"}, "evidence_locator_ids": []interface{}{"locator_write_b"}, "source_bytes_present": false,
	}
	protocolRaw, err := json.Marshal(protocolData)
	if err != nil {
		t.Fatal(err)
	}
	protocolRows := dependencySemanticRows{raw: []byte("protocol-artifact"), byKind: map[string][]dependencySemanticRow{
		"operation_classifier_fact":     {{line: 1, kind: "operation_classifier_fact", raw: protocolRaw, data: protocolData}},
		"protocol_assertion_projection": {{line: 2, kind: "protocol_assertion_projection", data: map[string]interface{}{"assertion_id": "protocol_write_fact"}}},
	}}
	sourceBinding := operationClassifierInputBinding{artifactRole: operationClassifierSourceArtifactRole, artifactSHA256: sha256Hex(sourceRows.raw), rowKind: "api_operation", rowIdentity: semanticKey, rowSHA256: sha256Hex(sourceRaw), factLocatorKind: "resource_access_ordinal", factOrdinal: 0}
	protocolBinding := operationClassifierInputBinding{artifactRole: operationClassifierProtocolArtifactRole, artifactSHA256: sha256Hex(protocolRows.raw), rowKind: "operation_classifier_fact", rowIdentity: protocolFactID, rowSHA256: sha256Hex(protocolRaw), factLocatorKind: "whole_row", factOrdinal: -1}
	entry := operationApplicabilityEntry{
		operationID: "operation", semanticIdentity: semanticKey, operationKind: "resource_read_write_operation", sourceSymbol: "operation_source", sourceIdentity: identity, classifierReference: reference,
		subjectTraits: map[string]interface{}{"emits_change_event": false, "reads_resource": true, "writes_resource": true}, evidenceLocatorIDs: map[string]struct{}{"locator_read_a": {}, "locator_write_b": {}}, evidenceFactIDs: map[string]struct{}{"docfact_read_a": {}, "protocol_write_fact": {}},
		resourceAccesses: []operationResourceAccess{
			{id: "read_a", resourceID: "resource_a", resourceSemanticIdentity: "resource:resource_a", resourceSourceSymbol: "resource_a", relationshipLabel: "operation_reads_resource", accessSemantics: "reads_exact_source_resource", classifierInputBinding: sourceBinding, evidenceLocatorIDs: map[string]struct{}{"locator_read_a": {}}, evidenceFactIDs: map[string]struct{}{"docfact_read_a": {}}},
			{id: "write_b", resourceID: "resource_b", resourceSemanticIdentity: "resource:resource_b", resourceSourceSymbol: "resource_b", relationshipLabel: "operation_writes_resource", accessSemantics: "writes_exact_source_resource", classifierInputBinding: protocolBinding, evidenceLocatorIDs: map[string]struct{}{"locator_write_b": {}}, evidenceFactIDs: map[string]struct{}{"protocol_write_fact": {}}},
		},
	}
	if err := validateOperationClassifierOutput(entry, derivation, sourceRows, protocolRows); err != nil {
		t.Fatalf("cross-carrier read/write composition rejected: %v", err)
	}
	t.Run("omitted protocol role partition", func(t *testing.T) {
		mutated := entry
		mutated.resourceAccesses = append([]operationResourceAccess(nil), entry.resourceAccesses[:1]...)
		if err := validateOperationClassifierOutput(mutated, derivation, sourceRows, protocolRows); err == nil || !strings.Contains(err.Error(), "protocol-contract predecessor fact partition") {
			t.Fatalf("error = %v, want omitted protocol partition refusal", err)
		}
	})
	t.Run("duplicate protocol role partition", func(t *testing.T) {
		mutated := entry
		mutated.resourceAccesses = append(append([]operationResourceAccess(nil), entry.resourceAccesses...), entry.resourceAccesses[1])
		mutated.resourceAccesses[2].id = "write_b_duplicate"
		if err := validateOperationClassifierOutput(mutated, derivation, sourceRows, protocolRows); err == nil || !strings.Contains(err.Error(), "duplicate predecessor row") {
			t.Fatalf("error = %v, want duplicate protocol partition refusal", err)
		}
	})
	t.Run("swapped access locator", func(t *testing.T) {
		mutated := entry
		mutated.resourceAccesses = append([]operationResourceAccess(nil), entry.resourceAccesses...)
		mutated.resourceAccesses[0].evidenceLocatorIDs = map[string]struct{}{"locator_write_b": {}}
		if err := validateOperationClassifierOutput(mutated, derivation, sourceRows, protocolRows); err == nil || !strings.Contains(err.Error(), "selected predecessor access") {
			t.Fatalf("error = %v, want swapped source access locator refusal", err)
		}
	})
}

func TestOperationResourceApplicabilityExactSetsEachClassifiedAccess(t *testing.T) {
	t.Parallel()
	maximum := int64(1)
	readRule := relationshipApplicabilityRule{id: "read_rule", label: "operation_reads_resource", sourceRole: "operation", targetRole: "resource", subjectEndpoint: "source", subjectRole: "operation", defaultDisposition: applicabilityDispositionRequired, cardinality: applicabilityCardinality{minimum: 1, maximum: &maximum}}
	writeRule := relationshipApplicabilityRule{id: "write_rule", label: "operation_writes_resource", sourceRole: "operation", targetRole: "resource", subjectEndpoint: "source", subjectRole: "operation", defaultDisposition: applicabilityDispositionRequired, cardinality: applicabilityCardinality{minimum: 1, maximum: &maximum}}
	apiState := apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{readRule.label: readRule, writeRule.label: writeRule}, propertyByID: map[string]propertyApplicabilityRule{}, claimByID: map[string]claimApplicabilityRule{}, allRuleKindsByID: map[string]string{readRule.id: "relationship", writeRule.id: "relationship"}}
	entry := operationApplicabilityEntry{operationID: "operation", resourceAccesses: []operationResourceAccess{
		{resourceID: "resource_a", relationshipLabel: readRule.label, accessSemantics: "reads_exact_source_resource"},
		{resourceID: "resource_b", relationshipLabel: writeRule.label, accessSemantics: "writes_exact_source_resource"},
	}}
	operations := operationApplicabilityState{byOperationID: map[string]operationApplicabilityEntry{"operation": entry}}
	readID := stableID("capi_rel", lengthPrefixedIdentityKey(readRule.label, "operation", "resource_a"))
	writeID := stableID("capi_rel", lengthPrefixedIdentityKey(writeRule.label, "operation", "resource_b"))
	newPlan := func() *parsedPlan {
		return &parsedPlan{
			Symbols: map[string]apiSymbol{"operation": {ID: "operation", Role: "operation"}, "resource_a": {ID: "resource_a", Role: "resource"}, "resource_b": {ID: "resource_b", Role: "resource"}},
			Relationships: map[string]apiRelationship{
				readID:  {ID: readID, Label: readRule.label, SourceID: "operation", TargetID: "resource_a"},
				writeID: {ID: writeID, Label: writeRule.label, SourceID: "operation", TargetID: "resource_b"},
			}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{},
		}
	}
	if err := validateGraphApplicabilityCoverage(newPlan(), apiState, operations); err != nil {
		t.Fatalf("read-A/write-B exact relationship roster rejected: %v", err)
	}
	t.Run("omission", func(t *testing.T) {
		plan := newPlan()
		delete(plan.Relationships, writeID)
		if err := validateGraphApplicabilityCoverage(plan, apiState, operations); err == nil || !strings.Contains(err.Error(), "fact-or-gap coverage 0") {
			t.Fatalf("error = %v, want omitted write-B refusal", err)
		}
	})
	t.Run("retarget", func(t *testing.T) {
		plan := newPlan()
		relationship := plan.Relationships[writeID]
		relationship.TargetID = "resource_a"
		plan.Relationships[writeID] = relationship
		if err := validateGraphApplicabilityCoverage(plan, apiState, operations); err == nil || !strings.Contains(err.Error(), "absent from the exact independently classified access roster") {
			t.Fatalf("error = %v, want write-B retarget refusal", err)
		}
	})
	t.Run("exact gap", func(t *testing.T) {
		plan := newPlan()
		delete(plan.Relationships, writeID)
		plan.Gaps["write_gap"] = graphGap{ID: "write_gap", ApplicabilityRuleID: writeRule.id, BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "operation", BlockedClaimKind: "api_relationship", BlockedClaimID: writeID}
		proof, err := compileGraphApplicabilityCoverage(plan, apiState, operations)
		if err != nil {
			t.Fatalf("exact write-B gap rejected: %v", err)
		}
		if err := validateNoOrphanGraphGaps(plan, operationApplicabilityState{coverageProof: proof}); err != nil {
			t.Fatalf("exact write-B gap was not consumed: %v", err)
		}
	})
	t.Run("wrong gap", func(t *testing.T) {
		plan := newPlan()
		delete(plan.Relationships, writeID)
		plan.Gaps["write_gap"] = graphGap{ID: "write_gap", ApplicabilityRuleID: writeRule.id, BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "operation", BlockedClaimKind: "api_relationship", BlockedClaimID: readID}
		if err := validateGraphApplicabilityCoverage(plan, apiState, operations); err == nil || !strings.Contains(err.Error(), "absent from the exact independently classified access roster") {
			t.Fatalf("error = %v, want wrong exact gap refusal", err)
		}
	})
	t.Run("fact plus gap", func(t *testing.T) {
		plan := newPlan()
		plan.Gaps["write_gap"] = graphGap{ID: "write_gap", ApplicabilityRuleID: writeRule.id, BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "operation", BlockedClaimKind: "api_relationship", BlockedClaimID: writeID}
		if err := validateGraphApplicabilityCoverage(plan, apiState, operations); err == nil || !strings.Contains(err.Error(), "coverage 2") {
			t.Fatalf("error = %v, want fact-plus-gap duplicate coverage refusal", err)
		}
	})
}

func TestRelationshipClassifierPredicateIsScopedToItsAccessLabel(t *testing.T) {
	t.Parallel()
	predicate := applicabilityPredicate{kind: "classifier_output_in", classifierProfileID: "classifier", values: map[string]struct{}{"writes_exact_source_resource": {}}}
	entry := operationApplicabilityEntry{classifierReference: dependencyProfileReference{id: "classifier"}, resourceAccesses: []operationResourceAccess{
		{relationshipLabel: "operation_reads_resource", accessSemantics: "reads_exact_source_resource"},
		{relationshipLabel: "operation_writes_resource", accessSemantics: "writes_exact_source_resource"},
	}}
	matched, err := operationApplicabilityPredicateMatches(predicate, entry, "operation_reads_resource")
	if err != nil || matched {
		t.Fatalf("read-rule predicate cross-triggered from write access: matched=%t err=%v", matched, err)
	}
	matched, err = operationApplicabilityPredicateMatches(predicate, entry, "operation_writes_resource")
	if err != nil || !matched {
		t.Fatalf("write-rule predicate did not consume its own access output: matched=%t err=%v", matched, err)
	}
}

func TestOperationClassifierRejectsContentDigestAndCandidateGraphInput(t *testing.T) {
	t.Parallel()
	profile, reference := testOperationClassifierProfile(t)
	profile.program["closed_input_fact_contracts"] = []interface{}{map[string]interface{}{
		"ordinal": json.Number("0"), "fact_kind": "candidate_graph_relationship", "artifact_role": "graph_plan", "row_kind": "candidate_api_relationship", "match_fields": []interface{}{"relationship_label"},
	}}
	if _, err := parseOperationClassifierProgram(profile, reference); err == nil || (!strings.Contains(err.Error(), "classifier_profile_sha256") && !strings.Contains(err.Error(), "unsupported acyclic fact_kind")) {
		t.Fatalf("error = %v, want content-bound candidate-graph input refusal", err)
	}
}

func TestOperationClassifierProgramRejectsUnknownFieldsAtEveryObjectLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{"program", func(program map[string]interface{}) { program["unknown"] = true }},
		{"input fact contract", func(program map[string]interface{}) {
			program["closed_input_fact_contracts"].([]interface{})[0].(map[string]interface{})["unknown"] = true
		}},
		{"trait aggregation", func(program map[string]interface{}) {
			program["subject_trait_aggregation"].(map[string]interface{})["unknown"] = true
		}},
		{"access rule", func(program map[string]interface{}) {
			program["ordered_access_rules"].([]interface{})[0].(map[string]interface{})["unknown"] = true
		}},
		{"access predicate", func(program map[string]interface{}) {
			program["ordered_access_rules"].([]interface{})[0].(map[string]interface{})["predicate"].(map[string]interface{})["unknown"] = true
		}},
		{"access output", func(program map[string]interface{}) {
			program["ordered_access_rules"].([]interface{})[0].(map[string]interface{})["output"].(map[string]interface{})["unknown"] = true
		}},
		{"access trait contribution", func(program map[string]interface{}) {
			program["ordered_access_rules"].([]interface{})[0].(map[string]interface{})["output"].(map[string]interface{})["subject_trait_contributions"].(map[string]interface{})["unknown"] = false
		}},
		{"aggregate rule", func(program map[string]interface{}) {
			program["ordered_operation_rules"].([]interface{})[0].(map[string]interface{})["unknown"] = true
		}},
		{"aggregate predicate", func(program map[string]interface{}) {
			program["ordered_operation_rules"].([]interface{})[0].(map[string]interface{})["predicate"].(map[string]interface{})["unknown"] = true
		}},
		{"aggregate traits", func(program map[string]interface{}) {
			program["ordered_operation_rules"].([]interface{})[0].(map[string]interface{})["predicate"].(map[string]interface{})["subject_traits"].(map[string]interface{})["unknown"] = false
		}},
		{"aggregate output", func(program map[string]interface{}) {
			program["ordered_operation_rules"].([]interface{})[0].(map[string]interface{})["output"].(map[string]interface{})["unknown"] = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile, reference := testOperationClassifierProfile(t)
			profile.program = cloneSemanticObjectForTest(t, profile.program)
			test.mutate(profile.program)
			canonical, err := canonicalOperationClassifierProgram(profile.program)
			if err != nil {
				t.Fatal(err)
			}
			reference.digest = sha256Hex(canonical)
			if _, err := parseOperationClassifierProgram(profile, reference); err == nil || (!strings.Contains(err.Error(), "fields") && !strings.Contains(err.Error(), "subject_trait")) {
				t.Fatalf("error = %v, want strict nested object grammar refusal", err)
			}
		})
	}
}

func TestOperationClassifierProgramBindsHashedInputClaimKind(t *testing.T) {
	t.Parallel()
	t.Run("program substitution", func(t *testing.T) {
		profile, reference := testOperationClassifierProfile(t)
		profile.program["input_claim_kind"] = "forged_operation_claim"
		canonical, err := canonicalOperationClassifierProgram(profile.program)
		if err != nil {
			t.Fatal(err)
		}
		reference.digest = sha256Hex(canonical)
		if _, err := parseOperationClassifierProgram(profile, reference); err == nil || !strings.Contains(err.Error(), "hashed input_claim_kind") {
			t.Fatalf("error = %v, want hashed program claim-kind substitution refusal", err)
		}
	})
	t.Run("profile substitution", func(t *testing.T) {
		profile, reference := testOperationClassifierProfile(t)
		profile.claimKind = "forged_operation_claim"
		if _, err := parseOperationClassifierProgram(profile, reference); err == nil || !strings.Contains(err.Error(), "hashed input_claim_kind") {
			t.Fatalf("error = %v, want profile claim-kind substitution refusal", err)
		}
	})
}

func TestOperationClassifierProgramClosedUnionsEqualExecutableRules(t *testing.T) {
	t.Parallel()
	t.Run("unused fact contract", func(t *testing.T) {
		profile, reference := testOperationClassifierProfile(t)
		rules := profile.program["ordered_access_rules"].([]interface{})
		profile.program["ordered_access_rules"] = rules[:2]
		canonical, err := canonicalOperationClassifierProgram(profile.program)
		if err != nil {
			t.Fatal(err)
		}
		reference.digest = sha256Hex(canonical)
		if _, err := parseOperationClassifierProgram(profile, reference); err == nil || !strings.Contains(err.Error(), "executable input fact kinds") {
			t.Fatalf("error = %v, want unused predecessor fact contract refusal", err)
		}
	})
	t.Run("unused operation output", func(t *testing.T) {
		profile, reference := testOperationClassifierProfile(t)
		profile.program["closed_operation_kind_outputs"] = []interface{}{"event_driven_write_operation", "request_response_read_operation", "resource_read_write_operation", "unused_operation_kind"}
		canonical, err := canonicalOperationClassifierProgram(profile.program)
		if err != nil {
			t.Fatal(err)
		}
		reference.digest = sha256Hex(canonical)
		if _, err := parseOperationClassifierProgram(profile, reference); err == nil || !strings.Contains(err.Error(), "executable operation-kind outputs") {
			t.Fatalf("error = %v, want non-executable closed output refusal", err)
		}
	})
}

func TestOperationClassifierIndexConstructionIsBounded(t *testing.T) {
	t.Parallel()
	t.Run("distinct programs", func(t *testing.T) {
		profile, first := testOperationClassifierProfile(t)
		second := first
		second.id = "classifier.operation.alternate"
		limits := canonicalOperationClassifierResourceLimits
		limits.programs = 1
		rows := dependencySemanticRows{byKind: map[string][]dependencySemanticRow{"operation_applicability": {
			{data: map[string]interface{}{"derivation_binding": map[string]interface{}{"classifier_profile_id": first.id, "classifier_profile_version": first.version, "classifier_profile_sha256": first.digest}}},
			{data: map[string]interface{}{"derivation_binding": map[string]interface{}{"classifier_profile_id": second.id, "classifier_profile_version": second.version, "classifier_profile_sha256": second.digest}}},
		}}}
		derivation := documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{
			dependencyProfileReferenceKey(first):  profile,
			dependencyProfileReferenceKey(second): profile,
		}}
		if _, err := newOperationClassifierValidationContext(rows, derivation, apiGraphApplicabilityState{}, dependencySemanticRows{}, dependencySemanticRows{}, nil, limits); err == nil || !strings.Contains(err.Error(), "program count") {
			t.Fatalf("error = %v, want distinct-program resource-cap refusal during reference indexing", err)
		}
	})
	t.Run("source accesses", func(t *testing.T) {
		limits := canonicalOperationClassifierResourceLimits
		limits.sourceAccesses = 1
		if _, err := newOperationClassifierPredecessorContext(operationClassifierTestSourceRows(t, 2), dependencySemanticRows{}, limits); err == nil || !strings.Contains(err.Error(), "source-access count") {
			t.Fatalf("error = %v, want source-access resource-cap refusal", err)
		}
	})
	t.Run("source evidence references", func(t *testing.T) {
		limits := canonicalOperationClassifierResourceLimits
		limits.sourceEvidenceRefs = 3
		if _, err := newOperationClassifierPredecessorContext(operationClassifierTestSourceRows(t, 2), dependencySemanticRows{}, limits); err == nil || !strings.Contains(err.Error(), "source-evidence reference count") {
			t.Fatalf("error = %v, want source-evidence resource-cap refusal", err)
		}
	})
	t.Run("protocol assertions", func(t *testing.T) {
		limits := canonicalOperationClassifierResourceLimits
		limits.protocolAssertions = 1
		protocolRows := dependencySemanticRows{byKind: map[string][]dependencySemanticRow{"protocol_assertion_projection": {
			{data: map[string]interface{}{"assertion_id": "assertion_a"}},
			{data: map[string]interface{}{"assertion_id": "assertion_b"}},
		}}}
		if _, err := newOperationClassifierPredecessorContext(dependencySemanticRows{}, protocolRows, limits); err == nil || !strings.Contains(err.Error(), "protocol-assertion count") {
			t.Fatalf("error = %v, want protocol-assertion resource-cap refusal", err)
		}
	})
	t.Run("plan relationships", func(t *testing.T) {
		limits := canonicalOperationClassifierResourceLimits
		limits.planRelationships = 1
		context, err := newOperationClassifierPredecessorContext(dependencySemanticRows{}, dependencySemanticRows{}, limits)
		if err != nil {
			t.Fatal(err)
		}
		plan := &parsedPlan{Relationships: map[string]apiRelationship{
			"relationship_a": {ID: "relationship_a", SourceID: "operation", TargetID: "resource_a"},
			"relationship_b": {ID: "relationship_b", SourceID: "operation", TargetID: "resource_b"},
		}, Properties: map[string]apiPropertyClaim{}}
		if err := indexOperationClassifierPlan(context, plan); err == nil || !strings.Contains(err.Error(), "plan-relationship count") {
			t.Fatalf("error = %v, want plan-relationship resource-cap refusal", err)
		}
	})
	t.Run("invalid caller limit", func(t *testing.T) {
		limits := canonicalOperationClassifierResourceLimits
		limits.programs = canonicalOperationClassifierResourceLimits.programs + 1
		if _, err := newOperationClassifierPredecessorContext(dependencySemanticRows{}, dependencySemanticRows{}, limits); err == nil || !strings.Contains(err.Error(), "closed canonical ceiling") {
			t.Fatalf("error = %v, want caller limit above canonical ceiling refusal", err)
		}
	})
}

func TestOperationClassifierContextCachesOneProgramAndIndexesCorpusOnce(t *testing.T) {
	t.Parallel()
	profile, reference := testOperationClassifierProfile(t)
	derivation := documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{dependencyProfileReferenceKey(reference): profile}}
	rows := dependencySemanticRows{byKind: map[string][]dependencySemanticRow{"operation_applicability": {}}}
	for index := 0; index < 128; index++ {
		rows.byKind["operation_applicability"] = append(rows.byKind["operation_applicability"], dependencySemanticRow{data: map[string]interface{}{
			"derivation_binding": map[string]interface{}{"classifier_profile_id": reference.id, "classifier_profile_version": reference.version, "classifier_profile_sha256": reference.digest},
		}})
	}
	apiState := apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{
		"operation_reads_resource":  {label: "operation_reads_resource", sourceRole: "operation", targetRole: "resource", subjectEndpoint: "source"},
		"operation_writes_resource": {label: "operation_writes_resource", sourceRole: "operation", targetRole: "resource", subjectEndpoint: "source"},
	}}
	plan := &parsedPlan{Symbols: map[string]apiSymbol{
		"selected_operation":    {ID: "selected_operation", Role: "operation"},
		"selected_resource":     {ID: "selected_resource", Role: "resource"},
		"distractor_resource_a": {ID: "distractor_resource_a", Role: "resource"},
		"distractor_resource_b": {ID: "distractor_resource_b", Role: "resource"},
	}, Relationships: map[string]apiRelationship{}, Properties: map[string]apiPropertyClaim{}}
	plan.Relationships["selected_incident"] = apiRelationship{ID: "selected_incident", SourceID: "selected_operation", TargetID: "selected_resource"}
	plan.Properties["selected_property"] = apiPropertyClaim{ID: "selected_property", SubjectKind: "api_symbol_object", SubjectID: "selected_operation"}
	for index := 0; index < 4095; index++ {
		id := fmt.Sprintf("distractor_%04d", index)
		plan.Relationships[id] = apiRelationship{ID: id, SourceID: "distractor_resource_a", TargetID: "distractor_resource_b"}
		plan.Properties[id] = apiPropertyClaim{ID: id, SubjectKind: "api_symbol_object", SubjectID: "distractor_resource_a"}
	}
	context, err := newOperationClassifierValidationContext(rows, derivation, apiState, dependencySemanticRows{}, dependencySemanticRows{}, plan, canonicalOperationClassifierResourceLimits)
	if err != nil {
		t.Fatal(err)
	}
	if context.actuals.programs != 1 || len(context.programsByReference) != 1 {
		t.Fatalf("compiled programs = %d/%d, want one distinct referenced program", context.actuals.programs, len(context.programsByReference))
	}
	if context.actuals.entries != 128 || context.actuals.planRelationships != 4096 || context.actuals.planProperties != 4096 {
		t.Fatalf("resource actuals = %+v, want one corpus indexing pass independent of operation count", context.actuals)
	}
	if incidents := context.incidentRelationshipIDsBySymbol["selected_operation"]; len(incidents) != 1 {
		t.Fatalf("selected operation incident index has %d relationships, want 1", len(incidents))
	}
	if properties := context.propertyIDsByOperation["selected_operation"]; len(properties) != 1 {
		t.Fatalf("selected operation property index has %d properties, want 1", len(properties))
	}
}

func operationClassifierTestSourceRows(t *testing.T, accessCount int) dependencySemanticRows {
	t.Helper()
	digest := strings.Repeat("a", 64)
	identity := map[string]interface{}{"identity_kind": "test_operation", "identity_components": map[string]interface{}{"name": "bounded_index"}}
	accesses := make([]interface{}, 0, accessCount)
	for index := 0; index < accessCount; index++ {
		accesses = append(accesses, map[string]interface{}{
			"source_symbol":                  fmt.Sprintf("resource_%04d", index),
			"relationship_label":             "operation_reads_resource",
			"evidence_locator_ids":           []interface{}{fmt.Sprintf("locator_%04d", index)},
			"documentation_derived_fact_ids": []interface{}{fmt.Sprintf("fact_%04d", index)},
		})
	}
	data := map[string]interface{}{
		"row_kind": "api_operation", "source_symbol": "operation", "source_operation_identity": identity, "resource_accesses": accesses,
		"evidence_hydration_coordinate": map[string]interface{}{"source_content_sha256": digest, "byte_start_offset": json.Number("0"), "byte_end_offset_exclusive": json.Number("1"), "selected_range_byte_count": json.Number("1"), "selected_range_sha256": digest},
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return dependencySemanticRows{raw: []byte("source-artifact"), byKind: map[string][]dependencySemanticRow{"api_operation": {{line: 1, kind: "api_operation", raw: raw, data: data}}}}
}

func testOperationClassifierProfile(t *testing.T) (documentationClassifierProfile, dependencyProfileReference) {
	t.Helper()
	program := map[string]interface{}{
		"program_kind": operationClassifierProgramKind, "input_claim_kind": "operation_applicability_predecessor_fact", "match_semantics": "exactly_one_rule_required", "operation_match_semantics": "exactly_one_rule_required", "closed_predicate_kinds": []interface{}{"exact_string_equals", "exact_subject_traits_equals"},
		"closed_input_fact_contracts": []interface{}{
			map[string]interface{}{"ordinal": json.Number("0"), "fact_kind": operationClassifierSourceFactKind, "artifact_role": operationClassifierSourceArtifactRole, "row_kind": "api_operation", "match_fields": []interface{}{"relationship_label"}},
			map[string]interface{}{"ordinal": json.Number("1"), "fact_kind": operationClassifierProtocolFactKind, "artifact_role": operationClassifierProtocolArtifactRole, "row_kind": "operation_classifier_fact", "match_fields": []interface{}{"semantic_class"}},
		},
		"closed_operation_kind_outputs":     []interface{}{"event_driven_write_operation", "request_response_read_operation", "resource_read_write_operation"},
		"closed_access_semantics_outputs":   []interface{}{"reads_exact_source_resource", "writes_exact_source_resource"},
		"closed_relationship_label_outputs": []interface{}{"operation_reads_resource", "operation_writes_resource"},
		"closed_subject_trait_names":        []interface{}{"emits_change_event", "reads_resource", "writes_resource"},
		"subject_trait_aggregation":         map[string]interface{}{"aggregation_kind": "boolean_or_across_accesses", "empty_access_roster_allowed": false},
		"ordered_access_rules": []interface{}{
			operationClassifierRuleObject(0, operationClassifierSourceFactKind, "relationship_label", "operation_reads_resource", "operation_reads_resource", "reads_exact_source_resource", false, true, false),
			operationClassifierRuleObject(1, operationClassifierSourceFactKind, "relationship_label", "operation_writes_resource", "operation_writes_resource", "writes_exact_source_resource", false, false, true),
			operationClassifierRuleObject(2, operationClassifierProtocolFactKind, "semantic_class", "change_event_write", "operation_writes_resource", "writes_exact_source_resource", true, false, true),
		},
		"ordered_operation_rules": []interface{}{
			operationClassifierAggregateRuleObject(0, "request_response_read_operation", false, true, false),
			operationClassifierAggregateRuleObject(1, "event_driven_write_operation", false, false, true),
			operationClassifierAggregateRuleObject(2, "event_driven_write_operation", true, false, true),
			operationClassifierAggregateRuleObject(3, "resource_read_write_operation", false, true, true),
		},
	}
	canonical, err := canonicalOperationClassifierProgram(program)
	if err != nil {
		t.Fatal(err)
	}
	reference := dependencyProfileReference{id: "fixture_operation_classifier", version: "1", digest: sha256Hex(canonical)}
	return documentationClassifierProfile{
		claimKind: "operation_applicability_predecessor_fact", semanticClasses: map[string]struct{}{"reads_exact_source_resource": {}, "writes_exact_source_resource": {}},
		carriers: map[string]struct{}{operationClassifierSourceArtifactRole: {}, operationClassifierProtocolArtifactRole: {}}, computationPaths: map[string]struct{}{operationClassifierProgramKind: {}}, program: program,
	}, reference
}

func operationClassifierRuleObject(ordinal int64, factKind, field, value, relationshipLabel, access string, emits, reads, writes bool) map[string]interface{} {
	return map[string]interface{}{
		"ordinal": json.Number(fmt.Sprintf("%d", ordinal)), "input_fact_kind": factKind,
		"predicate": map[string]interface{}{"predicate_kind": "exact_string_equals", "input_field": field, "value": value},
		"output":    map[string]interface{}{"relationship_label": relationshipLabel, "access_semantics": access, "subject_trait_contributions": map[string]interface{}{"emits_change_event": emits, "reads_resource": reads, "writes_resource": writes}},
	}
}

func operationClassifierAggregateRuleObject(ordinal int64, operationKind string, emits, reads, writes bool) map[string]interface{} {
	return map[string]interface{}{
		"ordinal":   json.Number(fmt.Sprintf("%d", ordinal)),
		"predicate": map[string]interface{}{"predicate_kind": "exact_subject_traits_equals", "subject_traits": map[string]interface{}{"emits_change_event": emits, "reads_resource": reads, "writes_resource": writes}},
		"output":    map[string]interface{}{"operation_kind": operationKind},
	}
}
