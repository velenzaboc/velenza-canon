package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCandidateAPISymbolDerivationBindingManyToMany(t *testing.T) {
	plan, loaded, rosterSHA := graphSymbolBindingFixture(t)
	if err := validateCandidateAPISymbolDerivationBindings(plan, loaded, rosterSHA); err != nil {
		t.Fatalf("validate exact many-to-many symbol binding: %v", err)
	}
	if len(loaded.CandidateSymbolsBySourceSymbol) != 2 {
		t.Fatalf("typed symbol index has %d entries, want 2", len(loaded.CandidateSymbolsBySourceSymbol))
	}
	for sourceSymbol, symbolID := range loaded.CandidateSymbolsBySourceSymbol {
		if plan.Symbols[symbolID].ID != symbolID {
			t.Fatalf("source symbol %q resolves absent candidate %q", sourceSymbol, symbolID)
		}
	}
}

func TestCandidateAPISymbolDerivationBindingRejectsUnclosedAndTamperedProofs(t *testing.T) {
	tests := []struct {
		name string
		edit func(t *testing.T, plan *parsedPlan, loaded loadedEvidence, rosterSHA string)
		want string
	}{
		{
			name: "fixture assertion",
			edit: func(_ *testing.T, plan *parsedPlan, _ loadedEvidence, _ string) {
				first := firstGraphSymbol(plan)
				first.DerivationBinding = json.RawMessage(`{"fixture":true}`)
				plan.Symbols[first.ID] = first
			},
			want: "closed source_classification_api_symbol_v1 contract",
		},
		{
			name: "semantic alias",
			edit: func(t *testing.T, plan *parsedPlan, loaded loadedEvidence, rosterSHA string) {
				original := symbolByRoleForGraphTest(plan, "resource")
				alias := original
				alias.SemanticKey = "resource:alias"
				alias.ID = stableID("capi_sym", lengthPrefixedIdentityKey(alias.Role, alias.SemanticKey))
				binding, err := candidateAPISymbolDerivationBindingFor(alias, rosterSHA, loaded.ClassificationsBySourceSymbol["source.resource"])
				if err != nil {
					t.Fatal(err)
				}
				alias.DerivationBinding = binding
				plan.Symbols[alias.ID] = alias
			},
			want: "semantically alias authoritative source_symbol",
		},
		{
			name: "omitted occurrence",
			edit: func(t *testing.T, plan *parsedPlan, _ loadedEvidence, _ string) {
				mutateGraphSymbolBinding(t, plan, "resource", func(symbol apiSymbol, binding *candidateAPISymbolDerivationBinding) {
					binding.ClassificationOccurrenceLocatorIDs = binding.ClassificationOccurrenceLocatorIDs[:1]
					binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, *binding)
				})
			},
			want: "not content-derived and set-equal",
		},
		{
			name: "extra occurrence",
			edit: func(t *testing.T, plan *parsedPlan, _ loadedEvidence, _ string) {
				mutateGraphSymbolBinding(t, plan, "operation", func(symbol apiSymbol, binding *candidateAPISymbolDerivationBinding) {
					binding.ClassificationOccurrenceLocatorIDs = append(binding.ClassificationOccurrenceLocatorIDs, "evloc_extra")
					binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, *binding)
				})
			},
			want: "not content-derived and set-equal",
		},
		{
			name: "unsorted occurrences",
			edit: func(t *testing.T, plan *parsedPlan, _ loadedEvidence, _ string) {
				mutateGraphSymbolBinding(t, plan, "resource", func(symbol apiSymbol, binding *candidateAPISymbolDerivationBinding) {
					binding.ClassificationOccurrenceLocatorIDs[0], binding.ClassificationOccurrenceLocatorIDs[1] = binding.ClassificationOccurrenceLocatorIDs[1], binding.ClassificationOccurrenceLocatorIDs[0]
					binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, *binding)
				})
			},
			want: "not content-derived and set-equal",
		},
		{
			name: "wrong surface",
			edit: func(t *testing.T, plan *parsedPlan, _ loadedEvidence, _ string) {
				mutateGraphSymbolBinding(t, plan, "resource", func(symbol apiSymbol, binding *candidateAPISymbolDerivationBinding) {
					binding.SurfaceKind = "operation"
					binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, *binding)
				})
			},
			want: "does not exactly equal authoritative classification surface_kind",
		},
		{
			name: "unknown source coordinate",
			edit: func(t *testing.T, plan *parsedPlan, _ loadedEvidence, _ string) {
				mutateGraphSymbolBinding(t, plan, "resource", func(symbol apiSymbol, binding *candidateAPISymbolDerivationBinding) {
					binding.SourceSymbol = "source.unknown"
					binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, *binding)
				})
			},
			want: "unknown classified source_symbol",
		},
		{
			name: "tampered classification artifact",
			edit: func(t *testing.T, plan *parsedPlan, _ loadedEvidence, _ string) {
				mutateGraphSymbolBinding(t, plan, "operation", func(symbol apiSymbol, binding *candidateAPISymbolDerivationBinding) {
					binding.ClassificationArtifactSHA256 = strings.Repeat("9", 64)
					binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, *binding)
				})
			},
			want: "not content-derived and set-equal",
		},
		{
			name: "unknown classification artifact coordinate",
			edit: func(t *testing.T, plan *parsedPlan, _ loadedEvidence, _ string) {
				mutateGraphSymbolBinding(t, plan, "operation", func(symbol apiSymbol, binding *candidateAPISymbolDerivationBinding) {
					binding.ClassificationArtifactID = "unknown_classification"
					binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, *binding)
				})
			},
			want: "not content-derived and set-equal",
		},
		{
			name: "ambiguous occurrence roster",
			edit: func(_ *testing.T, _ *parsedPlan, loaded loadedEvidence, rosterSHA string) {
				proof := loaded.ClassificationSelectionProofs[rosterSHA]
				proof.classificationsBySourceSymbol["source.operation"] = append(proof.classificationsBySourceSymbol["source.operation"], proof.classificationsBySourceSymbol["source.operation"][0])
				loaded.ClassificationSelectionProofs[rosterSHA] = proof
			},
			want: "duplicates locator",
		},
		{
			name: "wrong selection digest",
			edit: func(t *testing.T, plan *parsedPlan, _ loadedEvidence, _ string) {
				mutateGraphSymbolBinding(t, plan, "operation", func(symbol apiSymbol, binding *candidateAPISymbolDerivationBinding) {
					binding.EvidenceSelectionRosterSHA256 = strings.Repeat("8", 64)
					binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, *binding)
				})
			},
			want: "does not select the exact sealed classification roster",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, loaded, rosterSHA := graphSymbolBindingFixture(t)
			test.edit(t, plan, loaded, rosterSHA)
			err := validateCandidateAPISymbolDerivationBindings(plan, loaded, rosterSHA)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}
}

func TestTypedGraphRelationshipDerivationUsesSourceAccessNotLocatorCoincidence(t *testing.T) {
	plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows := graphPredecessorFixture(t)
	if err := validateTypedGraphCandidateDerivationBindings(plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows); err != nil {
		t.Fatalf("validate typed source access relationship: %v", err)
	}
}

func TestTypedGraphPositiveClaimsRejectSelfAssertionWithExplicitGapDisposition(t *testing.T) {
	t.Run("relationship", func(t *testing.T) {
		plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows := graphPredecessorFixture(t)
		for id, relationship := range plan.Relationships {
			relationship.DerivationBinding = json.RawMessage(`{"fixture":true}`)
			plan.Relationships[id] = relationship
		}
		err := validateTypedGraphCandidateDerivationBindings(plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows)
		if err == nil || !strings.Contains(err.Error(), "candidate_graph_gap") || !strings.Contains(err.Error(), typedGraphFactSourceOperationAccess) {
			t.Fatalf("got %v, want explicit source-access/gap refusal", err)
		}
	})

	t.Run("property", func(t *testing.T) {
		plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows := graphPredecessorFixture(t)
		plan.Relationships = map[string]apiRelationship{}
		property := apiPropertyClaim{RowKind: "candidate_api_property_claim", ID: "capi_prop_self_asserted", Family: "http_method", DerivationBinding: json.RawMessage(`{"fixture":true}`)}
		plan.Properties[property.ID] = property
		err := validateTypedGraphCandidateDerivationBindings(plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows)
		if err == nil || !strings.Contains(err.Error(), "candidate API property claim capi_prop_self_asserted") || !strings.Contains(err.Error(), "emit candidate_graph_gap") {
			t.Fatalf("got %v, want explicit unsupported-property gap refusal", err)
		}
	})
}

func TestTypedGraphGapBindsExactApplicabilityRule(t *testing.T) {
	plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows := graphPredecessorFixture(t)
	plan.Relationships = map[string]apiRelationship{}
	ruleRow := applicabilityRows.byKind["relationship_applicability_rule"][0]
	fact, err := typedGraphPredecessorFactForRow(typedGraphArtifactRoleAPIApplicability, applicabilityInput, ruleRow, "applicability_rule_id", "rule_reads", typedGraphFactGraphApplicabilityRule, -1)
	if err != nil {
		t.Fatal(err)
	}
	gap := graphGap{RowKind: "candidate_graph_gap", ID: "capi_gap_fixture", GapClass: "required_api_relationship_incomplete", BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: "operation_id", BlockedClaimKind: "api_relationship", BlockedClaimID: "missing_relationship", Disposition: "fail_closed", ApplicabilityProfileID: "profile", ApplicabilityProfileVersion: "1", ApplicabilityProfileSHA256: strings.Repeat("4", 64), ApplicabilityRuleID: "rule_reads", GapProofBinding: json.RawMessage(`{"proof":"exact"}`)}
	targetIdentity, err := graphGapDerivationTargetIdentity(gap)
	if err != nil {
		t.Fatal(err)
	}
	gap.DerivationBinding, err = typedGraphPredecessorDerivationBindingFor(gap.RowKind, targetIdentity, []typedGraphPredecessorFact{fact})
	if err != nil {
		t.Fatal(err)
	}
	plan.Gaps[gap.ID] = gap
	if err := validateTypedGraphCandidateDerivationBindings(plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows); err != nil {
		t.Fatalf("validate exact applicability-backed gap: %v", err)
	}

	mutate := gap
	var binding typedGraphPredecessorDerivationBinding
	if err := strictUnmarshal(mutate.DerivationBinding, &binding); err != nil {
		t.Fatal(err)
	}
	binding.PredecessorFacts[0].RowRawSHA256 = strings.Repeat("7", 64)
	binding.ID = typedGraphPredecessorDerivationBindingID(mutate.RowKind, targetIdentity, binding.PredecessorFacts)
	mutate.DerivationBinding = mustGraphJSON(t, binding)
	plan.Gaps[gap.ID] = mutate
	err = validateTypedGraphCandidateDerivationBindings(plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows)
	if err == nil || !strings.Contains(err.Error(), "row_raw_sha256") {
		t.Fatalf("got %v, want exact row-byte tamper refusal", err)
	}

	mutate.DerivationBinding = json.RawMessage(`{"fixture":true}`)
	plan.Gaps[gap.ID] = mutate
	err = validateTypedGraphCandidateDerivationBindings(plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows)
	if err == nil || !strings.Contains(err.Error(), "candidate graph gap capi_gap_fixture requires the admitted graph_applicability_rule predecessor family") {
		t.Fatalf("got %v, want self-asserted gap refusal", err)
	}
}

func graphSymbolBindingFixture(t *testing.T) (*parsedPlan, loadedEvidence, string) {
	t.Helper()
	rosterSHA := strings.Repeat("1", 64)
	classificationSHA := strings.Repeat("2", 64)
	binding := classificationArtifactBinding{ArtifactID: "fixture_classification", ArtifactVersion: "2", ArtifactSHA256: classificationSHA}
	locatorA := evidenceLocator{ID: "evloc_a"}
	locatorB := evidenceLocator{ID: "evloc_b"}
	classifications := map[string][]sourceClassificationOccurrence{
		"source.operation": {{Binding: binding, SourceSymbol: "source.operation", SurfaceKind: "operation", Locator: locatorA}},
		"source.resource": {
			{Binding: binding, SourceSymbol: "source.resource", SurfaceKind: "resource", Locator: locatorA},
			{Binding: binding, SourceSymbol: "source.resource", SurfaceKind: "resource", Locator: locatorB},
		},
	}
	plan := &parsedPlan{Manifest: &artifactManifest{Provider: "fixture_provider"}, Symbols: map[string]apiSymbol{}, Relationships: map[string]apiRelationship{}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{}}
	for sourceSymbol, occurrences := range classifications {
		role := occurrences[0].SurfaceKind
		semanticKey := "semantic:" + sourceSymbol
		symbol := apiSymbol{RowKind: "candidate_api_symbol", Role: role, SemanticKey: semanticKey, EvidenceLocatorIDs: sortedSetKeys(map[string]struct{}{})}
		symbol.ID = stableID("capi_sym", lengthPrefixedIdentityKey(role, semanticKey))
		locatorSet := map[string]struct{}{}
		for _, occurrence := range occurrences {
			locatorSet[occurrence.Locator.ID] = struct{}{}
		}
		symbol.EvidenceLocatorIDs = sortedSetKeys(locatorSet)
		var err error
		symbol.DerivationBinding, err = candidateAPISymbolDerivationBindingFor(symbol, rosterSHA, occurrences)
		if err != nil {
			t.Fatal(err)
		}
		plan.Symbols[symbol.ID] = symbol
	}
	proof := newSourceClassificationSelectionProof("fixture_provider", rosterSHA, classifications)
	loaded := loadedEvidence{
		ClassificationsBySourceSymbol:  classifications,
		ClassificationSelectionProofs:  map[string]sourceClassificationSelectionProof{rosterSHA: proof},
		CandidateSymbolsBySourceSymbol: map[string]string{},
	}
	return plan, loaded, rosterSHA
}

func graphPredecessorFixture(t *testing.T) (*parsedPlan, loadedEvidence, artifactInput, dependencySemanticRows, artifactInput, dependencySemanticRows) {
	t.Helper()
	operation := apiSymbol{RowKind: "candidate_api_symbol", ID: "operation_id", Role: "operation", EvidenceLocatorIDs: []string{"shared_locator"}}
	resource := apiSymbol{RowKind: "candidate_api_symbol", ID: "resource_id", Role: "resource", EvidenceLocatorIDs: []string{"shared_locator"}}
	relationship := apiRelationship{RowKind: "candidate_api_relationship", Label: "operation_reads_resource", SourceID: operation.ID, TargetID: resource.ID, LocatorIDs: []string{"shared_locator"}}
	relationship.ID = stableID("capi_rel", lengthPrefixedIdentityKey(relationship.Label, relationship.SourceID, relationship.TargetID))

	sourceInput, sourceRows := graphTestArtifact(t, "source_contract", "2", []map[string]interface{}{{
		"row_kind": "api_operation", "source_symbol": "source.operation", "surface_kind": "operation", "resource_accesses": []interface{}{map[string]interface{}{"source_symbol": "source.resource", "relationship_label": relationship.Label}},
	}})
	accessRow := sourceRows.byKind["api_operation"][0]
	fact, err := typedGraphPredecessorFactForRow(typedGraphArtifactRoleSourceContract, sourceInput, accessRow, "source_symbol", "source.operation", typedGraphFactSourceOperationAccess, 0)
	if err != nil {
		t.Fatal(err)
	}
	relationship.DerivationBinding, err = typedGraphPredecessorDerivationBindingFor(relationship.RowKind, relationship.ID, []typedGraphPredecessorFact{fact})
	if err != nil {
		t.Fatal(err)
	}

	applicabilityInput, applicabilityRows := graphTestArtifact(t, "api_applicability", "1", []map[string]interface{}{{
		"row_kind": "relationship_applicability_rule", "applicability_rule_id": "rule_reads", "relationship_label": relationship.Label,
	}})
	plan := &parsedPlan{Symbols: map[string]apiSymbol{operation.ID: operation, resource.ID: resource}, Relationships: map[string]apiRelationship{relationship.ID: relationship}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{}}
	loaded := loadedEvidence{CandidateSymbolsBySourceSymbol: map[string]string{"source.operation": operation.ID, "source.resource": resource.ID}}
	return plan, loaded, sourceInput, sourceRows, applicabilityInput, applicabilityRows
}

func graphTestArtifact(t *testing.T, artifactID, version string, bodyRows []map[string]interface{}) (artifactInput, dependencySemanticRows) {
	t.Helper()
	manifest := map[string]interface{}{"row_kind": "artifact_manifest", "artifact": artifactID, "artifact_version": version}
	rows := []map[string]interface{}{manifest}
	rows = append(rows, bodyRows...)
	rows = append(rows, map[string]interface{}{"row_kind": "validation_summary"})
	raw := make([]byte, 0)
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, encoded...)
		raw = append(raw, '\n')
	}
	input := artifactInput{Path: artifactID + ".jsonl", Raw: raw, SHA256: sha256Hex(raw), Manifest: manifest, Structured: true}
	parsed, err := parseDependencySemanticRows(input)
	if err != nil {
		t.Fatal(err)
	}
	return input, parsed
}

func mutateGraphSymbolBinding(t *testing.T, plan *parsedPlan, role string, mutate func(apiSymbol, *candidateAPISymbolDerivationBinding)) {
	t.Helper()
	symbol := symbolByRoleForGraphTest(plan, role)
	var binding candidateAPISymbolDerivationBinding
	if err := strictUnmarshal(symbol.DerivationBinding, &binding); err != nil {
		t.Fatal(err)
	}
	mutate(symbol, &binding)
	symbol.DerivationBinding = mustGraphJSON(t, binding)
	plan.Symbols[symbol.ID] = symbol
}

func symbolByRoleForGraphTest(plan *parsedPlan, role string) apiSymbol {
	for _, symbol := range plan.Symbols {
		if symbol.Role == role {
			return symbol
		}
	}
	return apiSymbol{}
}

func firstGraphSymbol(plan *parsedPlan) apiSymbol {
	for _, symbol := range plan.Symbols {
		return symbol
	}
	return apiSymbol{}
}

func mustGraphJSON(t *testing.T, value interface{}) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
