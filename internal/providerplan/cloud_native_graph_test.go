package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileCloudNativeOfflineVerificationRequiresExactSealedGraph(t *testing.T) {
	model := nativeGraphTestModel(t)
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSourcePackageCompilerTestFixture(t, "native_offline")
	_, err = CompileCloudNativeOfflineVerification(CloudNativeOfflineVerificationOptions{Context: nativeGraphTestContext(t, model, catalog), Models: []PinnedCloudModel{model}, SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot})
	if err == nil || !strings.Contains(err.Error(), "does not bind exact native offline graph bytes") {
		t.Fatalf("unbound native graph = %v", err)
	}
	if _, statErr := os.Stat(fixture.outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("unbound graph published output: %v", statErr)
	}
}

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

func TestBuildCloudNativeGraphCandidateJSONLKeepsSupplementalAssociationOutOfOperationSymbol(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cloudapi", "official", "aws", "s3-2006-03-01.json"))
	if err != nil {
		t.Fatal(err)
	}
	model := awsDeclaredCandidateModel(t, raw, "s3", "2006-03-01", sha256Hex(raw), []cloudCatalogTestAssociation{{resource: "com.amazonaws.s3#Bucket", operation: "com.amazonaws.s3#ListBuckets"}})
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	var operation CloudCatalogOperation
	for _, candidate := range catalog.Operations {
		if candidate.ID == "com.amazonaws.s3#ListBuckets" {
			operation = candidate
			break
		}
	}
	if operation.ID == "" || len(operation.ResourceAssociationEvidence) != 1 {
		t.Fatalf("fixture did not retain asserted association: %#v", operation)
	}
	context := nativeGraphTestContext(t, model, catalog)
	context.SelectedOperationIDs = map[string][]string{model.Source.ID: {operation.ID}}
	const supplementalManifest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	context.EvidenceManifestSHA256ByEvidenceID["declarations"] = supplementalManifest
	context.Manifest.EvidenceManifestBindings = append(context.Manifest.EvidenceManifestBindings, evidenceManifestBinding{EvidenceManifestSHA256: supplementalManifest, EvidenceBodyKind: evidenceBodyKindSourceDocument, ConsumerRoles: []string{"api_graph_projection"}})
	primary, err := cloudNativeEvidenceLocator(context, model, operation.Locator)
	if err != nil {
		t.Fatal(err)
	}
	association, err := cloudNativeEvidenceLocator(context, model, operation.ResourceAssociationEvidence[0].EvidenceLocator)
	if err != nil {
		t.Fatal(err)
	}
	body, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model})
	if err != nil {
		t.Fatal(err)
	}
	opID := stableID("capi_sym", lengthPrefixedIdentityKey("operation", cloudNativeSemanticKey(catalog, "operation", operation.ID)))
	apiID := stableID("capi_sym", lengthPrefixedIdentityKey("vendor_api", cloudNativeSemanticKey(catalog, "api", catalog.APISurfaceID)))
	var foundOperation, foundAPIGap bool
	for _, line := range bytes.Split(bytes.TrimSpace(body), []byte{'\n'}) {
		var row struct {
			RowKind string `json:"row_kind"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		switch row.RowKind {
		case "candidate_api_symbol":
			var symbol apiSymbol
			if err := strictUnmarshal(line, &symbol); err != nil {
				t.Fatal(err)
			}
			if symbol.ID == opID {
				foundOperation = true
				if got := symbol.EvidenceLocatorIDs; len(got) != 1 || got[0] != primary.ID {
					t.Fatalf("operation classification roster=%v, want only primary locator %q", got, primary.ID)
				}
			}
		case "candidate_graph_gap":
			var gap graphGap
			if err := strictUnmarshal(line, &gap); err != nil {
				t.Fatal(err)
			}
			if gap.BlockedSubjectID == apiID && gap.BlockedClaimID == "api_has_operation:"+opID {
				foundAPIGap = true
				if got := stringSliceSet(gap.EvidenceLocatorIDs); !containsCloudNativeString(got, primary.ID) || !containsCloudNativeString(got, association.ID) || len(got) != 2 {
					t.Fatalf("API/operation provenance roster=%v, want primary and supplemental association", gap.EvidenceLocatorIDs)
				}
			}
		}
	}
	if !foundOperation || !foundAPIGap {
		t.Fatalf("missing operation or association provenance gap: operation=%t api_gap=%t", foundOperation, foundAPIGap)
	}
}

func containsCloudNativeString(values map[string]struct{}, want string) bool {
	_, ok := values[want]
	return ok
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

func TestBuildCloudNativeGraphCandidateJSONLStrictModeRefusesMissingCrosswalk(t *testing.T) {
	model := nativeGraphTestModel(t)
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	context := nativeGraphTestContext(t, model, catalog)
	context.OperationCrosswalks = map[string]CloudNativeOperationCrosswalk{}
	if _, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model}); err == nil || (!strings.Contains(err.Error(), "lacks sealed source crosswalk") && !strings.Contains(err.Error(), "lacks sealed canonical selection")) {
		t.Fatalf("strict missing crosswalk = %v", err)
	}
}

func TestBuildCloudNativeGraphCandidateJSONLStrictModeUsesCanonicalCrosswalks(t *testing.T) {
	model := nativeGraphTestModel(t)
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	context := nativeGraphStrictTestContext(t, model, catalog)
	raw, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model})
	if err != nil {
		t.Fatal(err)
	}
	var operationSemantic string
	claims := map[string]bool{}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var row map[string]json.RawMessage
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		var kind string
		_ = json.Unmarshal(row["row_kind"], &kind)
		if kind == "candidate_api_symbol" {
			var symbol apiSymbol
			if err := strictUnmarshal(line, &symbol); err != nil {
				t.Fatal(err)
			}
			if symbol.Role == "operation" {
				operationSemantic = symbol.SemanticKey
			}
		}
		if kind == "candidate_graph_gap" {
			var gap graphGap
			if err := strictUnmarshal(line, &gap); err != nil {
				t.Fatal(err)
			}
			claims[gap.BlockedClaimID] = true
		}
	}
	crosswalk := context.OperationCrosswalks[CloudNativeOperationBindingKey(model.Source.ID, catalog.Operations[0].ID)]
	if operationSemantic != crosswalk.OperationSemanticKey {
		t.Fatalf("operation semantic=%q want %q", operationSemantic, crosswalk.OperationSemanticKey)
	}
	for claim := range context.RelationshipLabels {
		if !claims[claim] {
			t.Fatalf("strict relationship claim %q was not emitted", claim)
		}
	}
	bad := context
	bad.OperationCrosswalks = map[string]CloudNativeOperationCrosswalk{}
	for key, value := range context.OperationCrosswalks {
		value.OperationSemanticKey = "wrong"
		bad.OperationCrosswalks[key] = value
	}
	if _, err := BuildCloudNativeGraphCandidateJSONL(bad, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "does not equal canonical") {
		t.Fatalf("bad strict crosswalk=%v", err)
	}
	wrongBinding := context
	wrongBinding.SymbolDerivationBindings = map[string]json.RawMessage{}
	for key, value := range context.SymbolDerivationBindings {
		wrongBinding.SymbolDerivationBindings[key] = value
	}
	wrongBinding.SymbolDerivationBindings[CloudNativeSymbolBindingKey("operation", crosswalk.OperationSemanticKey)] = nativeStrictBinding(t, apiSymbol{ID: crosswalk.OperationSymbolID, Role: "operation", SemanticKey: crosswalk.OperationSemanticKey}, "wrong.source_symbol", "operation", context.Manifest.EvidenceSelectionRosterSHA256)
	if _, err := BuildCloudNativeGraphCandidateJSONL(wrongBinding, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "sealed source/surface/roster") {
		t.Fatalf("wrong strict source binding=%v", err)
	}
	resourceClaim := stableID("capi_rel", lengthPrefixedIdentityKey("resource_has_operation", crosswalk.ResourceAccesses[0].TargetSymbolID, crosswalk.OperationSymbolID))
	authSemantic := cloudNativeSemanticKey(catalog, "auth", catalog.Authentication[0].ID)
	authID := stableID("capi_sym", lengthPrefixedIdentityKey("auth_scheme", authSemantic))
	providerID := stableID("capi_sym", lengthPrefixedIdentityKey("provider", cloudNativeProviderSemanticKey(catalog.ProviderID)))
	authClaim := stableID("capi_rel", lengthPrefixedIdentityKey("provider_supports_auth_scheme", providerID, authID))
	for name, missingClaim := range map[string]string{"resource hierarchy": resourceClaim, "provider auth": authClaim} {
		missingHierarchy := context
		missingHierarchy.RelationshipLabels = map[string]string{}
		for key, value := range context.RelationshipLabels {
			missingHierarchy.RelationshipLabels[key] = value
		}
		delete(missingHierarchy.RelationshipLabels, missingClaim)
		if _, err := BuildCloudNativeGraphCandidateJSONL(missingHierarchy, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "lacks sealed canonical selection") {
			t.Fatalf("missing strict %s selection=%v", name, err)
		}
	}
	extra := context
	extra.OperationCrosswalks = map[string]CloudNativeOperationCrosswalk{}
	for key, value := range context.OperationCrosswalks {
		extra.OperationCrosswalks[key] = value
	}
	extra.OperationCrosswalks[CloudNativeOperationBindingKey(model.Source.ID, "absent")] = crosswalk
	if _, err := BuildCloudNativeGraphCandidateJSONL(extra, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "unknown or unselected") {
		t.Fatalf("extra operation crosswalk=%v", err)
	}
	extraResource := context
	extraResource.ResourceCrosswalks = map[string]CloudNativeResourceCrosswalk{}
	for key, value := range context.ResourceCrosswalks {
		extraResource.ResourceCrosswalks[key] = value
	}
	for _, value := range context.ResourceCrosswalks {
		extraResource.ResourceCrosswalks[CloudNativeResourceBindingKey(model.Source.ID, "absent")] = value
	}
	if _, err := BuildCloudNativeGraphCandidateJSONL(extraResource, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "unknown or unselected") {
		t.Fatalf("extra resource crosswalk=%v", err)
	}
	duplicate := context
	duplicate.OperationCrosswalks = map[string]CloudNativeOperationCrosswalk{}
	for key, value := range context.OperationCrosswalks {
		value.ResourceAccesses = append(value.ResourceAccesses, value.ResourceAccesses[0])
		duplicate.OperationCrosswalks[key] = value
	}
	if _, err := BuildCloudNativeGraphCandidateJSONL(duplicate, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "repeats sealed") {
		t.Fatalf("duplicate access=%v", err)
	}
}

func TestBuildCloudNativeGraphCandidateJSONLStrictSummaryCountsPropagateAndRefuseInvalid(t *testing.T) {
	model := nativeGraphTestModel(t)
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	context := nativeGraphStrictTestContext(t, model, catalog)
	context.Summary = &CloudNativeSummaryContext{ExactSourceDocumentCount: 7, ExactDocumentedFieldOccurrenceCount: 2, SampleJSONBlockCount: 3, ProtocolAssertionCount: 4, PreservedContradictionCount: 5}
	raw, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model})
	if err != nil {
		t.Fatal(err)
	}
	var found validationSummary
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		var row struct {
			RowKind string `json:"row_kind"`
		}
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		if row.RowKind == "validation_summary" {
			if err := strictUnmarshal(line, &found); err != nil {
				t.Fatal(err)
			}
		}
	}
	if found.ExactSourceDocumentCount != 7 || found.ExactDocumentedFieldOccurrenceCount != 2 || found.SampleJSONBlockCount != 3 || found.ProtocolAssertionCount != 4 || found.PreservedContradictionCount != 5 {
		t.Fatalf("strict summary propagation=%#v", found)
	}
	missing := context
	missing.Summary = nil
	if _, err := BuildCloudNativeGraphCandidateJSONL(missing, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "requires sealed dependency summary") {
		t.Fatalf("missing summary=%v", err)
	}
	for _, mutate := range []func(*CloudNativeSummaryContext){func(v *CloudNativeSummaryContext) { v.ExactSourceDocumentCount = -1 }, func(v *CloudNativeSummaryContext) { v.ExactDocumentedFieldOccurrenceCount = -1 }, func(v *CloudNativeSummaryContext) { v.SampleJSONBlockCount = -1 }, func(v *CloudNativeSummaryContext) { v.ProtocolAssertionCount = -1 }, func(v *CloudNativeSummaryContext) { v.PreservedContradictionCount = -1 }} {
		bad := context
		copy := *context.Summary
		mutate(&copy)
		bad.Summary = &copy
		if _, err := BuildCloudNativeGraphCandidateJSONL(bad, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), "summary counts must be nonnegative") {
			t.Fatalf("negative summary=%v", err)
		}
	}
}

func nativeGraphStrictTestContext(t *testing.T, model PinnedCloudModel, catalog CloudCatalog) CloudNativeGraphContext {
	t.Helper()
	context := nativeGraphTestContext(t, model, catalog)
	operation := catalog.Operations[0]
	identity := map[string]interface{}{"identity_kind": "source_contract_operation", "identity_components": map[string]interface{}{"operation_name": "list"}}
	semantic, err := sourceOperationSemanticKey("fixture.operation", identity)
	if err != nil {
		t.Fatal(err)
	}
	operationID := stableID("capi_sym", lengthPrefixedIdentityKey("operation", semantic))
	old := cloudNativeSemanticKey(catalog, "operation", operation.ID)
	binding := context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("operation", old)]
	delete(context.SymbolDerivationBindings, CloudNativeSymbolBindingKey("operation", old))
	context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("operation", semantic)] = binding
	oldResourceSemantic := cloudNativeSemanticKey(catalog, "resource", catalog.Resources[0].ID)
	resourceSemantic := "fixture.resource"
	resourceID := stableID("capi_sym", lengthPrefixedIdentityKey("resource", resourceSemantic))
	resourceBinding := context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("resource", oldResourceSemantic)]
	delete(context.SymbolDerivationBindings, CloudNativeSymbolBindingKey("resource", oldResourceSemantic))
	context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("resource", resourceSemantic)] = resourceBinding
	apiID := stableID("capi_sym", lengthPrefixedIdentityKey("vendor_api", cloudNativeSemanticKey(catalog, "api", catalog.APISurfaceID)))
	providerSemantic := cloudNativeProviderSemanticKey(catalog.ProviderID)
	providerID := stableID("capi_sym", lengthPrefixedIdentityKey("provider", providerSemantic))
	serviceID := stableID("capi_sym", lengthPrefixedIdentityKey("service", cloudNativeServiceSemanticKey(catalog.ProviderID, catalog.ServiceID)))
	if len(catalog.Authentication) != 1 {
		t.Fatalf("strict fixture authentication=%#v", catalog.Authentication)
	}
	authID := stableID("capi_sym", lengthPrefixedIdentityKey("auth_scheme", cloudNativeSemanticKey(catalog, "auth", catalog.Authentication[0].ID)))
	context.OperationCrosswalks = map[string]CloudNativeOperationCrosswalk{CloudNativeOperationBindingKey(model.Source.ID, operation.ID): {SourceSymbol: "fixture.operation", CanonicalSourceOperationIdentity: mustNativeTestJSON(t, identity), OperationSemanticKey: semantic, OperationSymbolID: operationID, ResourceAccesses: []CloudNativeRelationshipCrosswalk{{Label: "operation_reads_resource", SourceSymbolID: operationID, TargetSymbolID: resourceID, RelationshipID: stableID("capi_rel", lengthPrefixedIdentityKey("operation_reads_resource", operationID, resourceID))}}}}
	context.ResourceCrosswalks = map[string]CloudNativeResourceCrosswalk{CloudNativeResourceBindingKey(model.Source.ID, catalog.Resources[0].ID): {SourceSymbol: "fixture.resource", ResourceSemanticKey: resourceSemantic, ResourceSymbolID: resourceID}}
	context.Summary = &CloudNativeSummaryContext{}
	context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("resource", resourceSemantic)] = nativeStrictBinding(t, apiSymbol{ID: resourceID, Role: "resource", SemanticKey: resourceSemantic}, "fixture.resource", "resource", context.Manifest.EvidenceSelectionRosterSHA256)
	context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("operation", semantic)] = nativeStrictBinding(t, apiSymbol{ID: operationID, Role: "operation", SemanticKey: semantic}, "fixture.operation", "operation", context.Manifest.EvidenceSelectionRosterSHA256)
	context.RelationshipLabels = map[string]string{}
	context.GapContexts = map[string]CloudNativeGapContext{}
	for _, edge := range []struct{ label, source, target string }{{"provider_has_service", providerID, serviceID}, {"provider_supports_auth_scheme", providerID, authID}, {"service_has_api", serviceID, apiID}, {"api_has_resource", apiID, resourceID}, {"api_has_operation", apiID, operationID}, {"operation_reads_resource", operationID, resourceID}, {"resource_has_operation", resourceID, operationID}} {
		claim := stableID("capi_rel", lengthPrefixedIdentityKey(edge.label, edge.source, edge.target))
		context.RelationshipLabels[claim] = edge.label
		context.GapContexts[CloudNativeGapBindingKey(edge.source, claim)] = CloudNativeGapContext{GapClass: "unqualified_catalog_association", BlockedSubjectKind: "api_symbol_object", BlockedClaimKind: "api_relationship", BlockedClaimID: claim, ApplicabilityProfileID: "test_profile", ApplicabilityProfileVersion: "1", ApplicabilityProfileSHA256: strings.Repeat("a", 64), ApplicabilityRuleID: "test_rule", GapProofBinding: json.RawMessage(`{"candidate_only":true}`), DerivationBinding: json.RawMessage(`{"candidate_only":true}`)}
	}
	return context
}

func mustNativeTestJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := canonicalFactoryJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func nativeStrictBinding(t *testing.T, symbol apiSymbol, source, surface, roster string) json.RawMessage {
	t.Helper()
	binding := candidateAPISymbolDerivationBinding{Kind: apiSymbolDerivationBindingKind, EvidenceSelectionRosterSHA256: roster, ClassificationArtifactID: "fixture_classification", ClassificationArtifactVersion: "1", ClassificationArtifactSHA256: strings.Repeat("b", 64), SourceSymbol: source, SurfaceKind: surface, ClassificationOccurrenceLocatorIDs: []string{"fixture_locator"}}
	binding.ID = candidateAPISymbolDerivationBindingID(symbol.ID, binding)
	raw, err := canonicalFactoryJSON(binding)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBuildCloudNativeGraphCandidateJSONLRefusesInvalidSelectedOperationSets(t *testing.T) {
	model := nativeGraphTestModel(t)
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		selected map[string][]string
		want     string
	}{
		{"unknown_model", map[string][]string{"not-retained": {catalog.Operations[0].ID}}, "unknown retained model source"},
		{"empty", map[string][]string{model.Source.ID: {}}, "is empty"},
		{"duplicate", map[string][]string{model.Source.ID: {catalog.Operations[0].ID, catalog.Operations[0].ID}}, "duplicates"},
		{"unknown_operation", map[string][]string{model.Source.ID: {"not-an-operation"}}, "unknown operation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			context := nativeGraphTestContext(t, model, catalog)
			context.SelectedOperationIDs = tc.selected
			if _, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("selection error = %v, want %q", err, tc.want)
			}
		})
	}
}

func nativeGraphTestModel(t *testing.T) PinnedCloudModel {
	t.Helper()
	raw := []byte(`{"kind":"discovery#restDescription","name":"example","version":"v1","protocol":"rest","auth":{"oauth2":{"scopes":{"https://example.invalid/auth/read":{"description":"read"}}}},"resources":{"things":{"methods":{"list":{"id":"example.things.list"}}}}}`)
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
		context.GapContexts[CloudNativeGapBindingKey(subject, claim)] = CloudNativeGapContext{GapClass: "unqualified_catalog_association", BlockedSubjectKind: "api_symbol_object", BlockedClaimKind: "api_relationship", BlockedClaimID: claim, ApplicabilityProfileID: "test_profile", ApplicabilityProfileVersion: "1", ApplicabilityProfileSHA256: digest, ApplicabilityRuleID: "test_rule", GapProofBinding: json.RawMessage(`{"candidate_only":true}`), DerivationBinding: json.RawMessage(`{"candidate_only":true}`)}
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
	for _, requirement := range catalog.Authentication {
		authID := stableID("capi_sym", lengthPrefixedIdentityKey("auth_scheme", cloudNativeSemanticKey(catalog, "auth", requirement.ID)))
		gap(providerID, "provider_supports_auth_scheme:"+authID)
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
