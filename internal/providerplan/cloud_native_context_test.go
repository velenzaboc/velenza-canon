package providerplan

import (
	"encoding/json"
	"testing"
)

// cloudNativeFixtureSelections consumes (rather than recreates) the fixture's
// sealed selection roster.  Callers map its source-symbol keys to the cloud
// semantic keys they selected before calling candidateAPISymbolDerivationBindingFor.
func cloudNativeFixtureSelections(t *testing.T, fixture *testFixture) map[string][]sourceClassificationOccurrence {
	t.Helper()
	rosterDigest := fixture.manifest().EvidenceSelectionRosterSHA256
	if cached := fixture.classificationSelections[rosterDigest]; cached != nil {
		return cached
	}
	loaded, err := loadEvidenceBodies(fixture.options.EvidenceManifestPath, map[string]struct{}{supportedEvidenceRepresentationKind: {}})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := loadDependencyArtifacts(fixture.options.DependencyArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	roster, ok := artifacts[rosterDigest]
	if !ok {
		t.Fatalf("fixture omits sealed selection roster %s", rosterDigest)
	}
	used := map[string]struct{}{}
	if err := validateEvidenceSelectionRoster(roster, fixture.manifest().Provider, loaded, artifacts, used, cloudNativeFixtureParsedPlan(fixture)); err != nil {
		t.Fatal(err)
	}
	proof, ok := loaded.ClassificationSelectionProofs[rosterDigest]
	if !ok {
		t.Fatalf("fixture did not seal selection proof %s", rosterDigest)
	}
	if fixture.classificationSelections == nil {
		fixture.classificationSelections = map[string]map[string][]sourceClassificationOccurrence{}
	}
	fixture.classificationSelections[rosterDigest] = proof.classificationsBySourceSymbol
	return proof.classificationsBySourceSymbol
}

// cloudNativeFixtureParsedPlan is only the already-built sealed fixture graph
// index needed to validate its selection roster; it does not mint a plan.
func cloudNativeFixtureParsedPlan(fixture *testFixture) *parsedPlan {
	plan := &parsedPlan{Manifest: fixture.manifest(), Locators: map[string]evidenceLocator{}, Symbols: map[string]apiSymbol{}, Relationships: map[string]apiRelationship{}, Properties: map[string]apiPropertyClaim{}, Gaps: map[string]graphGap{}}
	for _, row := range fixture.planRows {
		switch value := row.(type) {
		case *evidenceLocator:
			plan.Locators[value.ID] = *value
		case *apiSymbol:
			plan.Symbols[value.ID] = *value
		case *apiRelationship:
			plan.Relationships[value.ID] = *value
		case *apiPropertyClaim:
			plan.Properties[value.ID] = *value
		case *graphGap:
			plan.Gaps[value.ID] = *value
		}
	}
	return plan
}

// cloudNativeFixtureSymbolBinding derives the same closed binding Verify will
// recompute; no raw binding may be supplied by a test caller.
func cloudNativeFixtureSymbolBinding(t *testing.T, fixture *testFixture, sourceSymbol string, role, semantic string) json.RawMessage {
	t.Helper()
	occurrences := cloudNativeFixtureSelections(t, fixture)[sourceSymbol]
	if len(occurrences) == 0 {
		t.Fatalf("fixture has no selected occurrences for %q", sourceSymbol)
	}
	ids := make([]string, len(occurrences))
	for i := range occurrences {
		ids[i] = occurrences[i].Locator.ID
	}
	symbol := apiSymbol{ID: stableID("capi_sym", lengthPrefixedIdentityKey(role, semantic)), Role: role, SemanticKey: semantic, EvidenceLocatorIDs: sortedCloudNativeStrings(ids)}
	binding, err := candidateAPISymbolDerivationBindingFor(symbol, fixture.manifest().EvidenceSelectionRosterSHA256, occurrences)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

// cloudNativeFixtureManifest copies only the exact commitments already sealed
// into the fixture graph manifest.  The caller supplies a distinct native
// artifact identity and the evidence-manifest bindings for its retained model.
func cloudNativeFixtureManifest(fixture *testFixture, artifact, version string, evidence []evidenceManifestBinding) CloudNativeGraphManifest {
	m := fixture.manifest()
	return CloudNativeGraphManifest{Artifact: artifact, ArtifactVersion: version,
		CanonicalOODGraphSHA256: m.CanonicalOODGraphSHA256, ProviderNeutralProfileSHA256: m.ProviderNeutralProfileSHA256,
		SourceContractIndexSHA256: m.SourceContractIndexSHA256, SampleShapeIndexSHA256: m.SampleShapeIndexSHA256,
		ProtocolContractIndexSHA256: m.ProtocolContractIndexSHA256, EvidenceSelectionRosterSHA256: m.EvidenceSelectionRosterSHA256,
		OperationApplicabilityProfileSHA256: m.OperationApplicabilityProfileSHA256, FieldMappingCandidateSHA256: m.FieldMappingCandidateSHA256,
		FieldSecurityPolicySHA256: m.FieldSecurityPolicySHA256, MappingTransitiveDependencyRosterSHA256: m.MappingTransitiveDependencyRosterSHA256,
		DocumentationClaimDerivationProfileSHA256: m.DocumentationClaimDerivationProfileSHA256, APIGraphApplicabilityProfileSHA256: m.APIGraphApplicabilityProfileSHA256,
		DependencySemanticValidation: m.DependencySemanticValidation, EvidenceLocatorManifestSHA256: m.EvidenceLocatorManifestSHA256,
		EvidenceManifestBindings: append([]evidenceManifestBinding(nil), evidence...)}
}

// cloudNativeFixtureGapContext derives a gap context from the fixture's
// admitted applicability row.  It deliberately accepts locator IDs only to
// form the proof; callers cannot inject a derivation binding.
func cloudNativeFixtureGapContext(t *testing.T, fixture *testFixture, subjectID, claimID, label string, locatorIDs []string) CloudNativeGapContext {
	t.Helper()
	ruleID := fixture.ruleByLabel[label]
	if ruleID == "" {
		t.Fatalf("fixture has no applicability rule for cloud label %q", label)
	}
	gap := graphGap{RowKind: "candidate_graph_gap", GapClass: "unqualified_catalog_association", BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: subjectID, BlockedClaimKind: "api_relationship", BlockedClaimID: claimID, Disposition: "fail_closed", ApplicabilityProfileID: fixture.applicability.ProfileID, ApplicabilityProfileVersion: fixture.applicability.ProfileVersion, ApplicabilityProfileSHA256: fixture.applicability.ProfileSHA256, ApplicabilityRuleID: ruleID, EvidenceLocatorIDs: sortedCloudNativeStrings(locatorIDs), GapProofBinding: fixtureGapProof(locatorIDs...)}
	gap.DerivationBinding = fixtureGapDerivationBinding(t, fixture.dependencyByRole["api_graph_applicability"], gap)
	return CloudNativeGapContext{GapClass: gap.GapClass, BlockedSubjectKind: gap.BlockedSubjectKind, BlockedClaimKind: gap.BlockedClaimKind, BlockedClaimID: gap.BlockedClaimID, ApplicabilityProfileID: gap.ApplicabilityProfileID, ApplicabilityProfileVersion: gap.ApplicabilityProfileVersion, ApplicabilityProfileSHA256: gap.ApplicabilityProfileSHA256, ApplicabilityRuleID: gap.ApplicabilityRuleID, GapProofBinding: gap.GapProofBinding, DerivationBinding: gap.DerivationBinding}
}
