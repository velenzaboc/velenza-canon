package providerplan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildCloudNativeGraphCandidateJSONLUsesOnlyNativeRowsAndRetainedEvidence(t *testing.T) {
	model := nativeGraphTestModel(t)
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	context := nativeGraphTestContext(t, model, catalog)
	first, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("native graph JSONL is not deterministic")
	}

	allowed := map[string]bool{"artifact_manifest": true, "candidate_evidence_locator": true, "candidate_api_symbol": true, "candidate_graph_gap": true, "validation_summary": true}
	seen := map[string]int{}
	for _, line := range bytes.Split(bytes.TrimSpace(first), []byte{'\n'}) {
		var row map[string]json.RawMessage
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		var kind string
		if err := json.Unmarshal(row["row_kind"], &kind); err != nil {
			t.Fatal(err)
		}
		if !allowed[kind] {
			t.Fatalf("emitted non-native row kind %q", kind)
		}
		seen[kind]++
		if kind == "candidate_evidence_locator" {
			var locator evidenceLocator
			if err := strictUnmarshal(line, &locator); err != nil {
				t.Fatal(err)
			}
			if locator.SourceContentSHA256 != model.ExpectedSHA256 || locator.SourceRefs[0] != model.Source.StableCoordinate || locator.SourceURLs[0] != model.Source.URI {
				t.Fatalf("locator did not retain model evidence: %#v", locator)
			}
		}
	}
	if seen["artifact_manifest"] != 1 || seen["validation_summary"] != 1 || seen["candidate_api_symbol"] < 3 || seen["candidate_graph_gap"] == 0 {
		t.Fatalf("native body lacks required rows: %#v", seen)
	}
	if bytes.Contains(first, []byte(`cloud_api_`)) {
		t.Fatal("legacy arbitrary cloud_api row leaked into native body")
	}
}

func TestBuildCloudNativeGraphCandidateJSONLRefusesMissingProofOrMixedProvider(t *testing.T) {
	model := nativeGraphTestModel(t)
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	context := nativeGraphTestContext(t, model, catalog)
	delete(context.SymbolDerivationBindings, CloudNativeSymbolBindingKey("operation", cloudNativeSemanticKey(catalog, "operation", catalog.Operations[0].ID)))
	if _, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "sealed classification") {
		t.Fatalf("missing proof error = %v", err)
	}
	context = nativeGraphTestContext(t, model, catalog)
	mixed := model
	mixed.ProviderID = "aws"
	if _, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model, mixed}); err == nil || !strings.Contains(err.Error(), "per-provider") {
		t.Fatalf("mixed provider error = %v", err)
	}
	context = nativeGraphTestContext(t, model, catalog)
	context.Manifest.EvidenceManifestBindings[0].EvidenceManifestSHA256 = strings.Repeat("c", 64)
	if _, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "absent from artifact manifest") {
		t.Fatalf("unbound evidence-manifest error = %v", err)
	}
}

func nativeGraphTestModel(t *testing.T) PinnedCloudModel {
	t.Helper()
	raw := []byte(`{"kind":"discovery#restDescription","name":"example","version":"v1","protocol":"rest","resources":{"things":{"methods":{"list":{"id":"example.things.list"}}}}}`)
	return PinnedCloudModel{Format: CloudCatalogFormatGoogleDiscoveryREST, Source: CloudCatalogSourceIdentity{ID: "model", URI: "https://example.invalid/discovery", StableCoordinate: "example/discovery", FormatRevision: "v1"}, ProviderID: "gcp", ServiceID: "example", APISurfaceID: "example", APIVersion: "v1", Raw: raw, ExpectedSHA256: sha256Hex(raw)}
}

func nativeGraphTestContext(t *testing.T, model PinnedCloudModel, catalog CloudCatalog) CloudNativeGraphContext {
	t.Helper()
	digest := strings.Repeat("a", 64)
	manifest := CloudNativeGraphManifest{Artifact: "cloud_native_graph_candidate", ArtifactVersion: "1", CanonicalOODGraphSHA256: digest, ProviderNeutralProfileSHA256: digest, SourceContractIndexSHA256: digest, SampleShapeIndexSHA256: digest, ProtocolContractIndexSHA256: digest, EvidenceSelectionRosterSHA256: digest, OperationApplicabilityProfileSHA256: digest, FieldMappingCandidateSHA256: digest, FieldSecurityPolicySHA256: digest, MappingTransitiveDependencyRosterSHA256: digest, DocumentationClaimDerivationProfileSHA256: digest, APIGraphApplicabilityProfileSHA256: digest, EvidenceLocatorManifestSHA256: digest, EvidenceManifestBindings: []evidenceManifestBinding{{EvidenceManifestSHA256: strings.Repeat("b", 64), EvidenceBodyKind: evidenceBodyKindSourceDocument, ConsumerRoles: []string{"api_graph_projection"}}}}
	context := CloudNativeGraphContext{Provider: model.ProviderID, Manifest: manifest, EvidenceManifestSHA256ByEvidenceID: map[string]string{"model": strings.Repeat("b", 64)}, SymbolDerivationBindings: map[string]json.RawMessage{}, GapContexts: map[string]CloudNativeGapContext{}}
	bind := func(role, kind, id string) {
		context.SymbolDerivationBindings[CloudNativeSymbolBindingKey(role, cloudNativeSemanticKey(catalog, kind, id))] = json.RawMessage(`{"candidate_only":true}`)
	}
	providerSemantic := cloudNativeProviderSemanticKey(catalog.ProviderID)
	serviceSemantic := cloudNativeServiceSemanticKey(catalog.ProviderID, catalog.ServiceID)
	context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("provider", providerSemantic)] = json.RawMessage(`{"candidate_only":true}`)
	context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("service", serviceSemantic)] = json.RawMessage(`{"candidate_only":true}`)
	if len(catalog.Operations) == 0 {
		t.Fatal("fixture has no operation evidence")
	}
	context.HierarchyEvidence = map[string][]CloudNativeEvidenceReference{CloudNativeSymbolBindingKey("provider", providerSemantic): {{ModelSourceID: model.Source.ID, Locator: catalog.Operations[0].Locator}}, CloudNativeSymbolBindingKey("service", serviceSemantic): {{ModelSourceID: model.Source.ID, Locator: catalog.Operations[0].Locator}}}
	bind("vendor_api", "api", catalog.APISurfaceID)
	for _, resource := range catalog.Resources {
		bind("resource", "resource", resource.ID)
	}
	for _, operation := range catalog.Operations {
		bind("operation", "operation", operation.ID)
	}
	for _, requirement := range catalog.Authentication {
		bind("auth_scheme", "auth", requirement.ID)
	}
	gap := func(subject, claim string) {
		context.GapContexts[CloudNativeGapBindingKey(subject, claim)] = CloudNativeGapContext{GapClass: "unqualified_catalog_association", ApplicabilityProfileID: "test_profile", ApplicabilityProfileVersion: "1", ApplicabilityProfileSHA256: digest, ApplicabilityRuleID: "test_rule", GapProofBinding: json.RawMessage(`{"candidate_only":true}`), DerivationBinding: json.RawMessage(`{"candidate_only":true}`)}
	}
	apiID := stableID("capi_sym", lengthPrefixedIdentityKey("vendor_api", cloudNativeSemanticKey(catalog, "api", catalog.APISurfaceID)))
	providerID := stableID("capi_sym", lengthPrefixedIdentityKey("provider", providerSemantic))
	serviceID := stableID("capi_sym", lengthPrefixedIdentityKey("service", serviceSemantic))
	gap(providerID, "provider_has_service:"+serviceID)
	gap(serviceID, "service_has_api:"+apiID)
	for _, resource := range catalog.Resources {
		resourceID := stableID("capi_sym", lengthPrefixedIdentityKey("resource", cloudNativeSemanticKey(catalog, "resource", resource.ID)))
		gap(apiID, "api_has_resource:"+resourceID)
	}
	for _, operation := range catalog.Operations {
		opID := stableID("capi_sym", lengthPrefixedIdentityKey("operation", cloudNativeSemanticKey(catalog, "operation", operation.ID)))
		gap(apiID, "api_has_operation:"+opID)
		for _, resourceID := range operation.ResourceIDs {
			resource := stableID("capi_sym", lengthPrefixedIdentityKey("resource", cloudNativeSemanticKey(catalog, "resource", resourceID)))
			gap(opID, "operation_resource_association:"+resource)
			gap(resource, "resource_has_operation:"+opID)
		}
		for _, requirementID := range operation.AuthenticationRequirementIDs {
			requirement := stableID("capi_sym", lengthPrefixedIdentityKey("auth_scheme", cloudNativeSemanticKey(catalog, "auth", requirementID)))
			gap(opID, "operation_requires_auth_scheme:"+requirement)
		}
	}
	return context
}
