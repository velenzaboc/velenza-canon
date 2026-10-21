package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDependencyApplicabilityCompletionParsesClosedDispositionGrammar(t *testing.T) {
	t.Parallel()
	rows := dependencySemanticRows{path: "applicability.jsonl"}
	row := dependencySemanticRow{line: 7, data: map[string]interface{}{
		"default_disposition": "optional",
		"ordered_conditional_rules": []interface{}{
			map[string]interface{}{"ordinal": json.Number("0"), "disposition": "required", "predicate": map[string]interface{}{"predicate_kind": "always"}},
			map[string]interface{}{"ordinal": json.Number("1"), "disposition": "inapplicable", "predicate": map[string]interface{}{"predicate_kind": "subject_trait_equals", "trait": "has_secret", "value": true}},
			map[string]interface{}{"ordinal": json.Number("2"), "disposition": "optional", "predicate": map[string]interface{}{"predicate_kind": "classifier_output_in", "classifier_profile_id": "classifier", "values": []interface{}{"read", "write"}}},
		},
		"required_cardinality": map[string]interface{}{"minimum": json.Number("1"), "maximum": json.Number("3")},
	}}
	mechanics, err := parseApplicabilityRuleMechanics(rows, row)
	if err != nil {
		t.Fatalf("parseApplicabilityRuleMechanics() error = %v", err)
	}
	if mechanics.defaultDisposition != "optional" || len(mechanics.conditionalRules) != 3 || mechanics.cardinality.minimum != 1 || mechanics.cardinality.maximum == nil || *mechanics.cardinality.maximum != 3 {
		t.Fatalf("mechanics = %#v", mechanics)
	}
	if mechanics.conditionalRules[1].predicate.trait != "has_secret" || len(mechanics.conditionalRules[2].predicate.values) != 2 {
		t.Fatalf("conditional predicates = %#v", mechanics.conditionalRules)
	}

	for _, test := range []struct {
		name string
		data map[string]interface{}
		want string
	}{
		{
			"noncontiguous ordinal",
			map[string]interface{}{"default_disposition": "optional", "ordered_conditional_rules": []interface{}{
				map[string]interface{}{"ordinal": json.Number("1"), "disposition": "required", "predicate": map[string]interface{}{"predicate_kind": "always"}},
			}},
			"not contiguous",
		},
		{"unknown disposition", map[string]interface{}{"default_disposition": "invented", "ordered_conditional_rules": []interface{}{}}, "incomplete"},
		{
			"unknown predicate",
			map[string]interface{}{"default_disposition": "optional", "ordered_conditional_rules": []interface{}{
				map[string]interface{}{"ordinal": json.Number("0"), "disposition": "required", "predicate": map[string]interface{}{"predicate_kind": "invented"}},
			}},
			"unknown source-neutral",
		},
		{
			"trait missing value",
			map[string]interface{}{"default_disposition": "optional", "ordered_conditional_rules": []interface{}{
				map[string]interface{}{"ordinal": json.Number("0"), "disposition": "required", "predicate": map[string]interface{}{"predicate_kind": "subject_trait_equals", "trait": "has_secret"}},
			}},
			"subject_trait_equals is incomplete",
		},
		{
			"classifier duplicated values",
			map[string]interface{}{"default_disposition": "optional", "ordered_conditional_rules": []interface{}{
				map[string]interface{}{"ordinal": json.Number("0"), "disposition": "required", "predicate": map[string]interface{}{"predicate_kind": "classifier_output_in", "classifier_profile_id": "classifier", "values": []interface{}{"read", "read"}}},
			}},
			"classifier_output_in is incomplete",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := dependencySemanticRow{line: 8, data: test.data}
			_, _, err := parseApplicabilityDispositionRules(rows, bad)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDependencyApplicabilityCompletionValidatesExactGapBindings(t *testing.T) {
	t.Parallel()
	state := apiGraphApplicabilityState{
		binding:             applicabilityProfileBinding{id: "evaluation", version: "1", digest: strings.Repeat("a", 64)},
		relationshipByLabel: map[string]relationshipApplicabilityRule{"operation_reads_resource": {id: "relationship", subjectRole: "operation"}},
		propertyByID:        map[string]propertyApplicabilityRule{"property": {id: "property", family: "security", eligibleSubjectKinds: map[string]struct{}{"api_symbol_object": {}}}},
		claimByID:           map[string]claimApplicabilityRule{"claim": {id: "claim", blockedClaimKind: "policy", blockedSubjectKind: "api_relationship_edge"}},
		allRuleKindsByID:    map[string]string{"relationship": "relationship", "property": "property_family", "claim": "claim"},
	}
	base := func() *parsedPlan {
		return &parsedPlan{Symbols: map[string]apiSymbol{"operation": {ID: "operation", Role: "operation"}, "resource": {ID: "resource", Role: "resource"}}, Relationships: map[string]apiRelationship{"edge": {ID: "edge"}}, Gaps: map[string]graphGap{}}
	}
	gap := func(id, rule, kind, subject, claim string) graphGap {
		return graphGap{ID: id, ApplicabilityProfileID: state.binding.id, ApplicabilityProfileVersion: state.binding.version, ApplicabilityProfileSHA256: state.binding.digest, Disposition: "fail_closed", ApplicabilityRuleID: rule, BlockedSubjectKind: kind, BlockedSubjectID: subject, BlockedClaimKind: claim}
	}
	plan := base()
	plan.Gaps["relationship"] = gap("relationship", "relationship", "api_symbol_object", "operation", "api_relationship")
	plan.Gaps["property"] = gap("property", "property", "api_symbol_object", "resource", "api_property_claim")
	plan.Gaps["claim"] = gap("claim", "claim", "api_relationship_edge", "edge", "policy")
	if err := validateGraphGapApplicabilityBindings(plan, state); err != nil {
		t.Fatalf("exact gap bindings rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*parsedPlan)
		want   string
	}{
		{"profile substitution", func(plan *parsedPlan) {
			item := plan.Gaps["relationship"]
			item.ApplicabilityProfileID = "forged"
			plan.Gaps["relationship"] = item
		}, "exact API applicability"},
		{"materializable", func(plan *parsedPlan) {
			item := plan.Gaps["relationship"]
			item.MaterializationEligible = true
			plan.Gaps["relationship"] = item
		}, "non-materializable"},
		{"unknown rule", func(plan *parsedPlan) {
			item := plan.Gaps["relationship"]
			item.ApplicabilityRuleID = "missing"
			plan.Gaps["relationship"] = item
		}, "unknown applicability rule"},
		{"relationship role mismatch", func(plan *parsedPlan) {
			item := plan.Gaps["relationship"]
			item.BlockedSubjectID = "resource"
			plan.Gaps["relationship"] = item
		}, "does not equal applicability role"},
		{"property wrong claim", func(plan *parsedPlan) {
			item := plan.Gaps["property"]
			item.BlockedClaimKind = "api_relationship"
			plan.Gaps["property"] = item
		}, "property-family applicability"},
		{"claim wrong subject", func(plan *parsedPlan) {
			item := plan.Gaps["claim"]
			item.BlockedSubjectKind = "api_symbol_object"
			plan.Gaps["claim"] = item
		}, "does not equal its claim"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base()
			candidate.Gaps["relationship"] = gap("relationship", "relationship", "api_symbol_object", "operation", "api_relationship")
			candidate.Gaps["property"] = gap("property", "property", "api_symbol_object", "resource", "api_property_claim")
			candidate.Gaps["claim"] = gap("claim", "claim", "api_relationship_edge", "edge", "policy")
			test.mutate(candidate)
			if err := validateGraphGapApplicabilityBindings(candidate, state); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDependencyApplicabilityCompletionParserRejectsBadRuleShapes(t *testing.T) {
	t.Parallel()
	rows := dependencySemanticRows{path: "rules.jsonl"}
	valid := dependencySemanticRow{line: 4, data: map[string]interface{}{
		"applicability_rule_id": "relationship", "relationship_label": "operation_reads_resource", "source_api_element_role": "operation", "target_api_element_role": "resource", "applicability_subject_endpoint": "source", "applicability_subject_role": "operation", "unmatched_endpoint_disposition": "inapplicable",
		"default_disposition": "required", "ordered_conditional_rules": []interface{}{}, "required_cardinality": map[string]interface{}{"minimum": json.Number("0"), "maximum": nil},
	}}
	if rule, err := parseRelationshipApplicabilityRule(rows, valid); err != nil || rule.cardinality.maximum != nil || rule.label != "operation_reads_resource" {
		t.Fatalf("relationship rule = %#v, err = %v", rule, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]interface{})
		want   string
	}{
		{"invalid endpoint", func(data map[string]interface{}) { data["applicability_subject_endpoint"] = "middle" }, "endpoint"},
		{"invalid maximum", func(data map[string]interface{}) {
			data["required_cardinality"] = map[string]interface{}{"minimum": json.Number("2"), "maximum": json.Number("1")}
		}, "maximum is invalid"},
		{"missing cardinality", func(data map[string]interface{}) { delete(data, "required_cardinality") }, "mechanics are incomplete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := cloneSemanticObjectForTest(t, valid.data)
			test.mutate(copy)
			_, err := parseRelationshipApplicabilityRule(rows, dependencySemanticRow{line: 5, data: copy})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDependencyApplicabilityCompletionIndexesExactPredecessors(t *testing.T) {
	t.Parallel()
	sourceRows := operationClassifierTestSourceRows(t, 2)
	identity := map[string]interface{}{
		"identity_kind":       "test_operation",
		"identity_components": map[string]interface{}{"name": "bounded_index"},
	}
	canonical, err := canonicalSourceOperationIdentity(identity)
	if err != nil {
		t.Fatal(err)
	}
	parts := []string{"operation", "resource_0000", "change_event_write", string(canonical), "assertion"}
	protocolFact := map[string]interface{}{
		"operation_classifier_fact_id": stableID("opfact", lengthPrefixedIdentityKey(parts...)),
		"source_symbol":                "operation",
		"resource_source_symbol":       "resource_0000",
		"semantic_class":               "change_event_write",
		"protocol_assertion_ids":       []interface{}{"assertion"},
		"evidence_locator_ids":         []interface{}{"locator"},
		"source_bytes_present":         false,
		"source_operation_identity":    identity,
	}
	protocolRows := dependencySemanticRows{
		raw: []byte("protocol-contract"),
		byKind: map[string][]dependencySemanticRow{
			"operation_classifier_fact":     {{line: 2, data: protocolFact, raw: []byte("protocol-fact")}},
			"protocol_assertion_projection": {{line: 3, data: map[string]interface{}{"assertion_id": "assertion"}}},
		},
	}
	context, err := newOperationClassifierPredecessorContext(sourceRows, protocolRows, canonicalOperationClassifierResourceLimits)
	if err != nil {
		t.Fatalf("newOperationClassifierPredecessorContext() error = %v", err)
	}
	semanticIdentity, err := sourceOperationSemanticKey("operation", identity)
	if err != nil {
		t.Fatal(err)
	}
	if len(context.sourceBySemanticIdentity[semanticIdentity]) != 1 || len(context.protocolByOperationSemanticIdentity[semanticIdentity]) != 1 || context.protocolAssertionCounts["assertion"] != 1 {
		t.Fatalf("predecessor indexes = %#v", context)
	}
	plan := &parsedPlan{
		Symbols: map[string]apiSymbol{"operation": {ID: "operation", Role: "operation"}, "resource": {ID: "resource", Role: "resource"}},
		Relationships: map[string]apiRelationship{
			"incident": {ID: "incident", SourceID: "operation", TargetID: "resource"},
			"self":     {ID: "self", SourceID: "operation", TargetID: "operation"},
		},
		Properties: map[string]apiPropertyClaim{
			"operation_property": {ID: "operation_property", SubjectKind: "api_symbol_object", SubjectID: "operation"},
			"ignored_property":   {ID: "ignored_property", SubjectKind: "api_relationship_edge", SubjectID: "incident"},
		},
	}
	if err := indexOperationClassifierPlan(context, plan); err != nil {
		t.Fatalf("indexOperationClassifierPlan() error = %v", err)
	}
	if len(context.incidentRelationshipIDsBySymbol["operation"]) != 2 || len(context.propertyIDsByOperation["operation"]) != 1 {
		t.Fatalf("plan indexes = relationships=%#v properties=%#v", context.incidentRelationshipIDsBySymbol, context.propertyIDsByOperation)
	}
	predecessor := context.sourceBySemanticIdentity[semanticIdentity][0]
	protocolID := protocolFact["operation_classifier_fact_id"].(string)
	entry := operationApplicabilityEntry{
		applicabilityID:         "applicability",
		operationID:             "operation",
		semanticIdentity:        semanticIdentity,
		sourceSymbol:            "operation",
		sourceIdentity:          identity,
		sourceIdentityCanonical: string(canonical),
		resourceAccesses: []operationResourceAccess{
			{
				id: "source_0", resourceSourceSymbol: "resource_0000", relationshipLabel: "operation_reads_resource", accessSemantics: "reads_exact_source_resource",
				evidenceLocatorIDs: map[string]struct{}{"locator_0000": {}}, evidenceFactIDs: map[string]struct{}{"fact_0000": {}},
				classifierInputBinding: operationClassifierInputBinding{artifactRole: operationClassifierSourceArtifactRole, artifactSHA256: context.sourceArtifactSHA256, rowKind: "api_operation", rowIdentity: semanticIdentity, rowSHA256: predecessor.rowSHA256, factLocatorKind: "resource_access_ordinal", factOrdinal: 0},
			},
			{
				id: "source_1", resourceSourceSymbol: "resource_0001", relationshipLabel: "operation_reads_resource", accessSemantics: "reads_exact_source_resource",
				evidenceLocatorIDs: map[string]struct{}{"locator_0001": {}}, evidenceFactIDs: map[string]struct{}{"fact_0001": {}},
				classifierInputBinding: operationClassifierInputBinding{artifactRole: operationClassifierSourceArtifactRole, artifactSHA256: context.sourceArtifactSHA256, rowKind: "api_operation", rowIdentity: semanticIdentity, rowSHA256: predecessor.rowSHA256, factLocatorKind: "resource_access_ordinal", factOrdinal: 1},
			},
			{
				id: "protocol", resourceSourceSymbol: "resource_0000", relationshipLabel: "operation_writes_resource", accessSemantics: "writes_exact_source_resource",
				evidenceLocatorIDs: map[string]struct{}{"locator": {}}, evidenceFactIDs: map[string]struct{}{"assertion": {}},
				classifierInputBinding: operationClassifierInputBinding{artifactRole: operationClassifierProtocolArtifactRole, artifactSHA256: context.protocolArtifactSHA256, rowKind: "operation_classifier_fact", rowIdentity: protocolID, rowSHA256: sha256Hex([]byte("protocol-fact")), factLocatorKind: "whole_row"},
			},
		},
	}
	facts, err := resolveOperationClassifierFacts(entry, context)
	if err != nil || len(facts) != 3 || facts[0].kind != operationClassifierSourceFactKind || facts[2].kind != operationClassifierProtocolFactKind {
		t.Fatalf("resolveOperationClassifierFacts() facts=%#v err=%v", facts, err)
	}
	sourceOnlyContext, err := newOperationClassifierPredecessorContext(sourceRows, dependencySemanticRows{}, canonicalOperationClassifierResourceLimits)
	if err != nil {
		t.Fatal(err)
	}
	entry.resourceAccesses = entry.resourceAccesses[:2]
	facts = facts[:2]
	profile, reference := testOperationClassifierProfile(t)
	program, err := parseOperationClassifierProgram(profile, reference)
	if err != nil {
		t.Fatal(err)
	}
	output, accessOutputs, err := executeOperationClassifierProgram(program, facts)
	if err != nil {
		t.Fatal(err)
	}
	entry.classifierReference = reference
	entry.operationKind = output.operationKind
	entry.subjectTraits = output.subjectTraits
	sourceOnlyContext.programsByReference = map[string]operationClassifierProgram{dependencyProfileReferenceKey(reference): program}
	if err := validateOperationClassifierOutputWithContext(entry, sourceOnlyContext); err != nil {
		t.Fatalf("contextual classifier validation rejected exact output: %v", err)
	}
	if len(accessOutputs) != len(entry.resourceAccesses) {
		t.Fatalf("access outputs=%d want %d", len(accessOutputs), len(entry.resourceAccesses))
	}
	derivation := documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{dependencyProfileReferenceKey(reference): profile}}
	if err := validateOperationClassifierOutput(entry, derivation, sourceRows, dependencySemanticRows{}); err != nil {
		t.Fatalf("full classifier validation rejected exact output: %v", err)
	}
}

func TestDependencyApplicabilityCompletionSubjectsAndClaimCardinalityFailClosed(t *testing.T) {
	t.Parallel()
	plan := &parsedPlan{
		Symbols:       map[string]apiSymbol{"operation": {ID: "operation", Role: "operation"}, "resource": {ID: "resource", Role: "resource"}},
		Relationships: map[string]apiRelationship{"read": {ID: "read", Label: "operation_reads_resource"}},
	}
	symbolRule := propertyApplicabilityRule{eligibleSubjectKinds: map[string]struct{}{"api_symbol_object": {}}, allowedRoles: map[string]struct{}{"operation": {}}}
	if !propertySubjectAllowed(plan, symbolRule, graphApplicabilitySubject{kind: "api_symbol_object", id: "operation"}) || propertySubjectAllowed(plan, symbolRule, graphApplicabilitySubject{kind: "api_symbol_object", id: "resource"}) || propertySubjectAllowed(plan, symbolRule, graphApplicabilitySubject{kind: "api_symbol_object", id: "missing"}) {
		t.Fatal("symbol property eligibility did not enforce the closed role roster")
	}
	relationshipRule := propertyApplicabilityRule{eligibleSubjectKinds: map[string]struct{}{"api_relationship_edge": {}}, relationshipLabelScope: map[string]struct{}{"operation_reads_resource": {}}}
	if !propertySubjectAllowed(plan, relationshipRule, graphApplicabilitySubject{kind: "api_relationship_edge", id: "read"}) || propertySubjectAllowed(plan, relationshipRule, graphApplicabilitySubject{kind: "api_relationship_edge", id: "missing"}) || propertySubjectAllowed(plan, relationshipRule, graphApplicabilitySubject{kind: "unknown", id: "read"}) {
		t.Fatal("relationship property eligibility did not enforce the closed label roster")
	}
	for _, subjectKind := range []string{"api_symbol_object", "api_relationship_edge"} {
		subjects, err := graphApplicabilitySubjectsForKind(plan, subjectKind)
		if err != nil || len(subjects) == 0 {
			t.Fatalf("subjects for %q = %#v, %v", subjectKind, subjects, err)
		}
	}
	if _, err := graphApplicabilitySubjectsForKind(plan, "external_subject"); err == nil || !strings.Contains(err.Error(), "independently enumerable") {
		t.Fatalf("unknown subject kind error = %v", err)
	}
	maximum := int64(1)
	required := claimApplicabilityRule{cardinality: applicabilityCardinality{minimum: 1, maximum: &maximum}}
	for _, test := range []struct {
		name        string
		disposition string
		count       int
		want        string
	}{
		{"required below minimum", "required", 0, "below minimum"},
		{"required above maximum", "required", 2, "above maximum"},
		{"optional persisted", "optional", 1, "optional disposition"},
		{"inapplicable persisted", "inapplicable", 1, "inapplicable disposition"},
		{"unknown disposition", "invented", 0, "unknown applicability"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateClaimGapCardinality(required, test.disposition, test.count); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	if err := validateClaimGapCardinality(required, "required", 1); err != nil {
		t.Fatalf("exact required gap rejected: %v", err)
	}
	if err := validateApplicabilityGapSubject(plan, "api_symbol_object", "operation", "operation"); err != nil {
		t.Fatalf("operation subject rejected: %v", err)
	}
	if err := validateApplicabilityGapSubject(plan, "api_relationship_edge", "read", ""); err != nil {
		t.Fatalf("relationship subject rejected: %v", err)
	}
	if err := validateApplicabilityGapSubject(plan, "external_subject", "external", ""); err != nil {
		t.Fatalf("external typed claim subject rejected: %v", err)
	}
	if err := validateApplicabilityGapSubject(plan, "api_symbol_object", "missing", ""); err == nil || !strings.Contains(err.Error(), "no plan API symbol") {
		t.Fatalf("missing symbol error = %v", err)
	}
	if err := validateApplicabilityGapSubject(plan, "external_subject", "external", "operation"); err == nil || !strings.Contains(err.Error(), "cannot satisfy") {
		t.Fatalf("external role error = %v", err)
	}
}

func TestDependencyApplicabilityCompletionParsesResourceAccessAndBothBindings(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("b", 64)
	build := func(role, rowKind, locatorKind string, ordinal interface{}) map[string]interface{} {
		locator := map[string]interface{}{"locator_kind": locatorKind}
		if ordinal != nil {
			locator["ordinal"] = ordinal
		}
		return map[string]interface{}{
			"artifact_role": role, "artifact_sha256": digest, "row_kind": rowKind, "row_identity": "predecessor", "row_sha256": digest, "fact_locator": locator,
		}
	}
	for _, test := range []struct {
		name    string
		role    string
		rowKind string
		locator string
		ordinal interface{}
	}{
		{"source ordinal", operationClassifierSourceArtifactRole, "api_operation", "resource_access_ordinal", json.Number("0")},
		{"protocol whole row", operationClassifierProtocolArtifactRole, "operation_classifier_fact", "whole_row", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding := build(test.role, test.rowKind, test.locator, test.ordinal)
			parsedBinding, err := parseOperationClassifierInputBinding(map[string]interface{}{"predecessor_fact_binding": binding})
			if err != nil || parsedBinding.artifactRole != test.role || parsedBinding.rowKind != test.rowKind {
				t.Fatalf("binding = %#v, err = %v", parsedBinding, err)
			}
			locators := []interface{}{"locator_a"}
			facts := []interface{}{"fact_a"}
			identityParts := []string{"operation", "resource", "resource_id", "resource_identity", "operation_reads_resource", "reads_exact_source_resource", test.role, digest, test.rowKind, "predecessor", digest, test.locator, "-1"}
			if test.ordinal != nil {
				identityParts[len(identityParts)-1] = "0"
			}
			identityParts = append(identityParts, "locator_a", "fact_a")
			object := map[string]interface{}{
				"resource_access_id": stableID("opaccess", lengthPrefixedIdentityKey(identityParts...)), "source_symbol": "resource", "resource_candidate_api_symbol_id": "resource_id", "resource_semantic_identity": "resource_identity",
				"relationship_label": "operation_reads_resource", "access_semantics": "reads_exact_source_resource", "evidence_locator_ids": locators, "evidence_fact_ids": facts, "predecessor_fact_binding": binding,
			}
			access, err := parseOperationResourceAccess(object, "operation")
			if err != nil || access.id == "" || access.classifierInputBinding.factLocatorKind != test.locator {
				t.Fatalf("access = %#v, err = %v", access, err)
			}
		})
	}
	for _, test := range []struct {
		name    string
		binding map[string]interface{}
		want    string
	}{
		{"missing binding", nil, "predecessor_fact_binding is missing"},
		{"bad source ordinal", build(operationClassifierSourceArtifactRole, "api_operation", "resource_access_ordinal", json.Number("-1")), "nonnegative"},
		{"bad protocol locator", build(operationClassifierProtocolArtifactRole, "operation_classifier_fact", "whole_row", json.Number("0")), "exact whole row"},
		{"unsupported role", build("candidate_graph", "api_operation", "resource_access_ordinal", json.Number("0")), "outside the closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			object := map[string]interface{}{}
			if test.binding != nil {
				object["predecessor_fact_binding"] = test.binding
			}
			if _, err := parseOperationClassifierInputBinding(object); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDependencyApplicabilityCompletionProtectsSourceAndProtocolIdentities(t *testing.T) {
	t.Parallel()
	identity := map[string]interface{}{"identity_kind": "operation", "identity_components": map[string]interface{}{"name": "get"}}
	if parsed, err := parseSourceOperationIdentity(map[string]interface{}{"source_operation_identity": identity}); err != nil || parsed["identity_kind"] != "operation" {
		t.Fatalf("identity = %#v, err = %v", parsed, err)
	}
	if key, err := sourceOperationSemanticKey("source", identity); err != nil || key == "" {
		t.Fatalf("semantic key = %q, err = %v", key, err)
	}
	if equal, err := equalCanonicalSourceOperationIdentities(identity, map[string]interface{}{"identity_components": map[string]interface{}{"name": "get"}, "identity_kind": "operation"}); err != nil || !equal {
		t.Fatalf("canonical identity equality = %t, %v", equal, err)
	}
	if equal, err := equalCanonicalSourceOperationIdentities(identity, map[string]interface{}{"identity_kind": "operation", "identity_components": map[string]interface{}{"name": "put"}}); err != nil || equal {
		t.Fatalf("distinct canonical identity equality = %t, %v", equal, err)
	}
	for _, test := range []struct {
		name   string
		object map[string]interface{}
		want   string
	}{
		{"missing identity", map[string]interface{}{}, "source_operation_identity is missing"},
		{"empty components", map[string]interface{}{"source_operation_identity": map[string]interface{}{"identity_kind": "operation", "identity_components": map[string]interface{}{}}}, "requires a canonical"},
		{"noncanonical kind", map[string]interface{}{"source_operation_identity": map[string]interface{}{"identity_kind": "bad kind", "identity_components": map[string]interface{}{"name": "get"}}}, "requires a canonical"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseSourceOperationIdentity(test.object); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	if _, err := sourceOperationSemanticKey("", identity); err == nil || !strings.Contains(err.Error(), "incomplete source symbol") {
		t.Fatalf("empty source symbol error = %v", err)
	}
	if _, _, err := parseSourceOperationAccessEvidence(map[string]interface{}{"evidence_locator_ids": []interface{}{"locator"}, "documentation_derived_fact_ids": []interface{}{"fact"}}); err != nil {
		t.Fatalf("exact source access evidence rejected: %v", err)
	}
	for _, object := range []map[string]interface{}{
		{"evidence_locator_ids": []interface{}{}, "documentation_derived_fact_ids": []interface{}{"fact"}},
		{"evidence_locator_ids": []interface{}{"locator"}, "documentation_derived_fact_ids": []interface{}{"fact", "fact"}},
	} {
		if _, _, err := parseSourceOperationAccessEvidence(object); err == nil {
			t.Fatalf("noncanonical source evidence accepted: %#v", object)
		}
	}
}

func TestDependencyApplicabilityCompletionRejectsClassifierSemanticSubstitution(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(map[string]interface{})
		want   string
	}{
		{"empty predecessor contract", func(program map[string]interface{}) { program["closed_input_fact_contracts"] = []interface{}{} }, "acyclic input bound"},
		{"open aggregation", func(program map[string]interface{}) {
			program["subject_trait_aggregation"] = map[string]interface{}{"aggregation_kind": "boolean_or_across_accesses", "empty_access_roster_allowed": true}
		}, "empty-roster refusal"},
		{"access reads undeclared field", func(program map[string]interface{}) {
			program["ordered_access_rules"].([]interface{})[0].(map[string]interface{})["predicate"].(map[string]interface{})["input_field"] = "forged"
		}, "absent from fact contract"},
		{"access labels outside union", func(program map[string]interface{}) {
			program["ordered_access_rules"].([]interface{})[0].(map[string]interface{})["output"].(map[string]interface{})["relationship_label"] = "forged_label"
		}, "outside the closed output union"},
		{"nonboolean trait contribution", func(program map[string]interface{}) {
			program["ordered_access_rules"].([]interface{})[0].(map[string]interface{})["output"].(map[string]interface{})["subject_trait_contributions"].(map[string]interface{})["reads_resource"] = "true"
		}, "not boolean"},
		{"empty aggregate roster", func(program map[string]interface{}) { program["ordered_operation_rules"] = []interface{}{} }, "bounded rule roster"},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile, reference := testOperationClassifierProfile(t)
			profile.program = cloneSemanticObjectForTest(t, profile.program)
			test.mutate(profile.program)
			canonical, err := canonicalOperationClassifierProgram(profile.program)
			if err != nil {
				t.Fatal(err)
			}
			reference.digest = sha256Hex(canonical)
			if _, err := parseOperationClassifierProgram(profile, reference); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func operationClassifierDerivationRowForTest(reference dependencyProfileReference) dependencySemanticRow {
	return dependencySemanticRow{line: 1, data: map[string]interface{}{
		"derivation_binding": map[string]interface{}{
			"classifier_profile_id": reference.id, "classifier_profile_version": reference.version,
			"classifier_profile_sha256": reference.digest,
		},
	}}
}

func operationClassifierAPIStateForTest() apiGraphApplicabilityState {
	return apiGraphApplicabilityState{relationshipByLabel: map[string]relationshipApplicabilityRule{
		"operation_reads_resource":  {sourceRole: "operation", targetRole: "resource", subjectEndpoint: "source"},
		"operation_writes_resource": {sourceRole: "operation", targetRole: "resource", subjectEndpoint: "source"},
	}}
}

func TestDependencyApplicabilityCompletionValidationContextFailures(t *testing.T) {
	if _, err := newOperationClassifierValidationContext(dependencySemanticRows{}, documentationClaimDerivationState{}, apiGraphApplicabilityState{}, dependencySemanticRows{}, dependencySemanticRows{}, nil, operationClassifierResourceBudget{}); err == nil {
		t.Fatal("validation context accepted an invalid resource budget")
	}

	limits := canonicalOperationClassifierResourceLimits
	limits.sourceRows = 1
	sourceRows := operationClassifierTestSourceRows(t, 1)
	sourceRows.byKind["api_operation"] = append(sourceRows.byKind["api_operation"], sourceRows.byKind["api_operation"][0])
	if _, err := newOperationClassifierValidationContext(dependencySemanticRows{}, documentationClaimDerivationState{}, apiGraphApplicabilityState{}, sourceRows, dependencySemanticRows{}, nil, limits); err == nil {
		t.Fatal("validation context accepted a predecessor roster above its resource budget")
	}

	limits = canonicalOperationClassifierResourceLimits
	limits.entries = 1
	twoRows := dependencySemanticRows{byKind: map[string][]dependencySemanticRow{
		"operation_applicability": {{line: 1, data: map[string]interface{}{}}, {line: 2, data: map[string]interface{}{}}},
	}}
	if _, err := newOperationClassifierValidationContext(twoRows, documentationClaimDerivationState{}, apiGraphApplicabilityState{}, dependencySemanticRows{}, dependencySemanticRows{}, nil, limits); err == nil {
		t.Fatal("validation context accepted operation entries above its resource budget")
	}

	missingBinding := dependencySemanticRows{byKind: map[string][]dependencySemanticRow{
		"operation_applicability": {{line: 1, data: map[string]interface{}{}}},
	}}
	if _, err := newOperationClassifierValidationContext(missingBinding, documentationClaimDerivationState{}, apiGraphApplicabilityState{}, dependencySemanticRows{}, dependencySemanticRows{}, nil, canonicalOperationClassifierResourceLimits); err == nil {
		t.Fatal("validation context accepted an operation without a classifier binding")
	}

	profile, reference := testOperationClassifierProfile(t)
	row := operationClassifierDerivationRowForTest(reference)
	rows := dependencySemanticRows{byKind: map[string][]dependencySemanticRow{"operation_applicability": {row}}}
	if _, err := newOperationClassifierValidationContext(rows, documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{}}, apiGraphApplicabilityState{}, dependencySemanticRows{}, dependencySemanticRows{}, nil, canonicalOperationClassifierResourceLimits); err == nil {
		t.Fatal("validation context accepted an absent classifier profile")
	}
	invalidProfiles := documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{
		dependencyProfileReferenceKey(reference): {},
	}}
	if _, err := newOperationClassifierValidationContext(rows, invalidProfiles, apiGraphApplicabilityState{}, dependencySemanticRows{}, dependencySemanticRows{}, nil, canonicalOperationClassifierResourceLimits); err == nil {
		t.Fatal("validation context accepted an invalid classifier profile")
	}
	validProfiles := documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{
		dependencyProfileReferenceKey(reference): profile,
	}}
	limits = canonicalOperationClassifierResourceLimits
	limits.programBytes = 1
	if _, err := newOperationClassifierValidationContext(rows, validProfiles, apiGraphApplicabilityState{}, dependencySemanticRows{}, dependencySemanticRows{}, nil, limits); err == nil {
		t.Fatal("validation context accepted classifier bytes above its resource budget")
	}
	if _, err := newOperationClassifierValidationContext(rows, validProfiles, apiGraphApplicabilityState{}, dependencySemanticRows{}, dependencySemanticRows{}, nil, canonicalOperationClassifierResourceLimits); err == nil {
		t.Fatal("validation context accepted classifier relationship labels without API applicability authority")
	}
	limits = canonicalOperationClassifierResourceLimits
	limits.planRelationships = 1
	plan := &parsedPlan{
		Symbols: map[string]apiSymbol{}, Properties: map[string]apiPropertyClaim{},
		Relationships: map[string]apiRelationship{
			"one": {ID: "one"}, "two": {ID: "two"},
		},
	}
	if _, err := newOperationClassifierValidationContext(rows, validProfiles, operationClassifierAPIStateForTest(), dependencySemanticRows{}, dependencySemanticRows{}, plan, limits); err == nil {
		t.Fatal("validation context accepted plan relationships above its resource budget")
	}
}

func TestDependencyApplicabilityCompletionResourceAccessFieldFailures(t *testing.T) {
	digest := strings.Repeat("a", 64)
	binding := map[string]interface{}{
		"artifact_role": operationClassifierSourceArtifactRole, "artifact_sha256": digest,
		"row_kind": "api_operation", "row_identity": "source-row", "row_sha256": digest,
		"fact_locator": map[string]interface{}{"locator_kind": "resource_access_ordinal", "ordinal": json.Number("0")},
	}
	base := map[string]interface{}{
		"resource_access_id": "access", "source_symbol": "resource", "resource_candidate_api_symbol_id": "resource-id",
		"resource_semantic_identity": "resource-identity", "relationship_label": "operation_reads_resource",
		"access_semantics": "reads_exact_source_resource", "evidence_locator_ids": []interface{}{"locator"},
		"evidence_fact_ids": []interface{}{"fact"}, "predecessor_fact_binding": binding,
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{"resource access identity", func(value map[string]interface{}) { delete(value, "resource_access_id") }},
		{"source symbol", func(value map[string]interface{}) { delete(value, "source_symbol") }},
		{"resource candidate", func(value map[string]interface{}) { delete(value, "resource_candidate_api_symbol_id") }},
		{"resource semantic identity", func(value map[string]interface{}) { delete(value, "resource_semantic_identity") }},
		{"relationship label", func(value map[string]interface{}) { value["relationship_label"] = "bad label" }},
		{"access semantics", func(value map[string]interface{}) { value["access_semantics"] = "bad semantics" }},
		{"locator roster", func(value map[string]interface{}) { value["evidence_locator_ids"] = []interface{}{} }},
		{"fact roster", func(value map[string]interface{}) { value["evidence_fact_ids"] = []interface{}{} }},
		{"predecessor binding", func(value map[string]interface{}) { delete(value, "predecessor_fact_binding") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneSemanticObjectForTest(t, base)
			tc.mutate(candidate)
			if _, err := parseOperationResourceAccess(candidate, "operation"); err == nil {
				t.Fatal("malformed operation resource access was accepted")
			}
		})
	}

	for _, tc := range []struct {
		name   string
		mutate func(map[string]interface{})
	}{
		{"artifact role", func(value map[string]interface{}) { delete(value, "artifact_role") }},
		{"artifact digest", func(value map[string]interface{}) { value["artifact_sha256"] = "short" }},
		{"row kind", func(value map[string]interface{}) { delete(value, "row_kind") }},
		{"row identity", func(value map[string]interface{}) { value["row_identity"] = "" }},
		{"row digest", func(value map[string]interface{}) { value["row_sha256"] = "short" }},
		{"fact locator", func(value map[string]interface{}) { delete(value, "fact_locator") }},
	} {
		t.Run("binding "+tc.name, func(t *testing.T) {
			candidate := cloneSemanticObjectForTest(t, binding)
			tc.mutate(candidate)
			if _, err := parseOperationClassifierInputBinding(map[string]interface{}{"predecessor_fact_binding": candidate}); err == nil {
				t.Fatal("malformed operation classifier input binding was accepted")
			}
		})
	}
}

func TestDependencyApplicabilityCompletionClassifierOutputContextFailures(t *testing.T) {
	profile, reference := testOperationClassifierProfile(t)
	entry := operationApplicabilityEntry{classifierReference: reference}
	if err := validateOperationClassifierOutput(entry, documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{}}, dependencySemanticRows{}, dependencySemanticRows{}); err == nil {
		t.Fatal("classifier output accepted an absent profile")
	}
	if err := validateOperationClassifierOutput(entry, documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{dependencyProfileReferenceKey(reference): {}}}, dependencySemanticRows{}, dependencySemanticRows{}); err == nil {
		t.Fatal("classifier output accepted an invalid profile")
	}
	malformedSource := dependencySemanticRows{byKind: map[string][]dependencySemanticRow{
		"api_operation": {{line: 1, data: map[string]interface{}{}}},
	}}
	if err := validateOperationClassifierOutput(entry, documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{dependencyProfileReferenceKey(reference): profile}}, malformedSource, dependencySemanticRows{}); err == nil {
		t.Fatal("classifier output accepted an invalid predecessor context")
	}
	entry.sourceIdentity = map[string]interface{}{"unsupported": make(chan int)}
	if err := validateOperationClassifierOutput(entry, documentationClaimDerivationState{classifiers: map[string]documentationClassifierProfile{dependencyProfileReferenceKey(reference): profile}}, dependencySemanticRows{}, dependencySemanticRows{}); err == nil {
		t.Fatal("classifier output accepted a noncanonical source identity")
	}
	if err := validateOperationClassifierOutputWithContext(operationApplicabilityEntry{classifierReference: reference}, &operationClassifierValidationContext{programsByReference: map[string]operationClassifierProgram{}}); err == nil {
		t.Fatal("classifier output accepted a missing compiled program")
	}
	program, err := parseOperationClassifierProgram(profile, reference)
	if err != nil {
		t.Fatal(err)
	}
	context := &operationClassifierValidationContext{programsByReference: map[string]operationClassifierProgram{dependencyProfileReferenceKey(reference): program}}
	if err := validateOperationClassifierOutputWithContext(operationApplicabilityEntry{classifierReference: reference}, context); err == nil {
		t.Fatal("classifier output accepted an empty predecessor roster")
	}
}
