package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestCloudNativeGCSBucketsListCandidatePassesVerify is deliberately a
// conformance-only proof.  The GCS discovery snapshot is retained evidence,
// while all classification, applicability, and source-contract authority is
// supplied by the sealed test fixture.  It neither selects a production
// source owner nor makes the catalog admissible.
func TestCloudNativeGCSBucketsListCandidatePassesVerify(t *testing.T) {
	testCloudNativeServiceCandidate(t, "gcp-storage-model", "storage.buckets.list", "gcs_buckets_list")
}

func TestCloudNativeComputeInstancesAggregatedListCandidatePassesVerify(t *testing.T) {
	testCloudNativeServiceCandidate(t, "gcp-compute-model", "compute.instances.aggregatedList", "gce_instances_aggregated_list")
}

func TestCloudNativeS3ListBucketsCandidatePassesVerify(t *testing.T) {
	testCloudNativeServiceCandidate(t, "aws-s3-model", "com.amazonaws.s3#ListBuckets", "s3_list_buckets")
}

func TestCloudNativeEC2DescribeInstancesCandidatePassesVerify(t *testing.T) {
	testCloudNativeServiceCandidate(t, "aws-ec2-model", "com.amazonaws.ec2#DescribeInstances", "ec2_describe_instances")
}

func testCloudNativeServiceCandidate(t *testing.T, modelID, operationID, prefix string) {
	model := cloudNativeSnapshotModelByID(t, loadPinnedCloudModelsForCompilerProof(t), modelID)
	model.Source = cloudNativeSnapshotSource(t, model.Source.ID)
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	operation := cloudNativeOperationByID(t, catalog, operationID)
	selected := map[string]bool{operation.ID: true}
	selectedEvidenceIDs := map[string]struct{}{}
	for _, locator := range cloudNativeSelectedCatalogLocators(catalog, selected) {
		if locator.EvidenceID != "model" {
			selectedEvidenceIDs[locator.EvidenceID] = struct{}{}
		}
	}
	for index := range model.SupplementalEvidence {
		if _, used := selectedEvidenceIDs[model.SupplementalEvidence[index].ID]; used {
			model.SupplementalEvidence[index].Source = cloudNativeSnapshotSupplementalSource(t, modelID, model.SupplementalEvidence[index].ID)
		}
	}
	var selectedResource CloudCatalogResource
	for _, resource := range catalog.Resources {
		if cloudNativeResourceSelected(resource, selected) {
			selectedResource = resource
		}
	}
	if selectedResource.ID == "" {
		t.Fatal("buckets.list has no selected resource")
	}

	aws := len(model.SupplementalEvidence) != 0
	primary := testPrimaryEvidenceFixture{
		body: model.Raw, derivationPattern: regexp.QuoteMeta(string(model.Raw[operation.Locator.StartByte:operation.Locator.EndByte])),
		fieldDerivationPattern:      regexp.QuoteMeta(string(model.Raw[selectedResource.Locator.StartByte : selectedResource.Locator.StartByte+min(256, selectedResource.Locator.EndByte-selectedResource.Locator.StartByte)])),
		nativeSelectedOperationOnly: true,
		providerDescription:         "Test-only native cloud fixture over pinned model bytes.",
		provider:                    model.ProviderID, sourceRef: model.Source.StableCoordinate, sourceURL: model.Source.URI,
		representation: "source_declared_machine_export", representationCoord: model.Source.StableCoordinate,
		artifactPrefix: prefix, sourceSymbolPrefix: prefix, operationName: operationID, sectionRoot: "Cloud",
		singleDocument: !aws, protocolLiteralA: "type", protocolLiteralB: "description",
		sampleRange:                   &officialProviderEvidenceRange{Name: "resource_sample", SourceSymbol: prefix + "_resource", SurfaceKind: "resource", ByteStartOffset: int64(selectedResource.Locator.StartByte), ByteEndOffsetExclusive: int64(selectedResource.Locator.EndByte), SelectedRangeSHA256: sha256Hex(model.Raw[selectedResource.Locator.StartByte:selectedResource.Locator.EndByte])},
		exactRoleClassificationRanges: true,
		extraRoles:                    []string{"provider", "service"},
		extraConstraints: []relationshipConstraint{
			{EdgeLabel: "provider_has_service", SourceRole: "provider", TargetRole: "service"},
			{EdgeLabel: "service_has_api", SourceRole: "service", TargetRole: "vendor_api"},
			{EdgeLabel: "api_has_resource", SourceRole: "vendor_api", TargetRole: "resource"},
			{EdgeLabel: "resource_has_operation", SourceRole: "resource", TargetRole: "operation"},
			{EdgeLabel: "provider_supports_auth_scheme", SourceRole: "provider", TargetRole: "auth_scheme"},
		},
		relationshipSubjectEndpoints: map[string]string{"api_has_operation": "source", "resource_has_operation": "source"},
		relationshipDefaultDispositions: map[string]string{
			"provider_has_service": "required", "service_has_api": "required", "api_has_resource": "required", "api_has_operation": "required", "resource_has_operation": "required", "provider_supports_auth_scheme": "required",
		},
		additionalRangeBuilder: func(_, _ string) []officialProviderEvidenceRange {
			ranges := []officialProviderEvidenceRange{}
			add := func(source, surface string, locators []CloudCatalogEvidenceLocator) {
				for index, locator := range locators {
					if locator.EvidenceID != "model" {
						continue
					}
					ranges = append(ranges, officialProviderEvidenceRange{Name: source + "_" + string(rune('a'+index)), SourceSymbol: source, SurfaceKind: surface, ByteStartOffset: int64(locator.StartByte), ByteEndOffsetExclusive: int64(locator.EndByte), SelectedRangeSHA256: sha256Hex(model.Raw[locator.StartByte:locator.EndByte])})
				}
			}
			add(prefix+"_provider", "provider", []CloudCatalogEvidenceLocator{operation.Locator})
			add(prefix+"_service", "service", []CloudCatalogEvidenceLocator{operation.Locator})
			add(prefix+"_api", "vendor_api", cloudNativeSelectedCatalogLocators(catalog, selected))
			for _, resource := range catalog.Resources {
				if !cloudNativeResourceSelected(resource, selected) {
					continue
				}
				locators := []CloudCatalogEvidenceLocator{resource.Locator}
				if resource.DeclarationEvidenceLocator != nil {
					locators = append(locators, *resource.DeclarationEvidenceLocator)
				}
				add(prefix+"_resource", "resource", locators)
			}
			add(prefix+"_read_operation", "operation", []CloudCatalogEvidenceLocator{operation.Locator})
			for _, auth := range catalog.Authentication {
				add(prefix+"_auth_"+auth.ID, "auth_scheme", []CloudCatalogEvidenceLocator{auth.Locator})
			}
			return ranges
		},
	}
	if aws {
		primary.protocolBody = model.SupplementalEvidence[0].Raw
		primary.protocolSourceRef, primary.protocolSourceURL = model.SupplementalEvidence[0].Source.StableCoordinate, model.SupplementalEvidence[0].Source.URI
		primary.protocolLiteralA, primary.protocolLiteralB = "resource_id", "operation_id"
		primary.additionalProtocolRangeBuilder = func(_, _ string) []officialProviderEvidenceRange {
			ranges := []officialProviderEvidenceRange{}
			add := func(source, surface string, locators []CloudCatalogEvidenceLocator) {
				for i, locator := range locators {
					if locator.EvidenceID == model.SupplementalEvidence[0].ID {
						ranges = append(ranges, officialProviderEvidenceRange{Name: source + "_p" + string(rune('a'+i)), SourceSymbol: source, SurfaceKind: surface, ByteStartOffset: int64(locator.StartByte), ByteEndOffsetExclusive: int64(locator.EndByte), SelectedRangeSHA256: sha256Hex(model.SupplementalEvidence[0].Raw[locator.StartByte:locator.EndByte])})
					}
				}
			}
			add(prefix+"_api", "vendor_api", cloudNativeSelectedCatalogLocators(catalog, selected))
			for _, resource := range catalog.Resources {
				if cloudNativeResourceSelected(resource, selected) && resource.DeclarationEvidenceLocator != nil {
					add(prefix+"_resource", "resource", []CloudCatalogEvidenceLocator{*resource.DeclarationEvidenceLocator})
				}
			}
			return ranges
		}
	}
	fixture := newTestFixtureWithPrimaryEvidence(t, primary)

	context := cloudNativeServiceContext(t, fixture, model, catalog, operation, selected, prefix)
	graph, err := BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model})
	if err != nil {
		t.Fatal(err)
	}
	prepareNativeOperationApplicability(t, fixture, graph)
	context = cloudNativeServiceContext(t, fixture, model, catalog, operation, selected, prefix)
	graph, err = BuildCloudNativeGraphCandidateJSONL(context, []PinnedCloudModel{model})
	if err != nil {
		t.Fatal(err)
	}
	packageFixture := newSourcePackageCompilerTestFixtureFromBase(t, model.ProviderID, fixture)
	replaceSourcePackageAPIGraph(t, packageFixture.manifestPath, graph)
	dependencies := defaultDocumentationFactorySourceCompilerDependencies()
	dependencies.RunFactory = func(options FactoryRunOptions) (FactoryRunReceipt, error) {
		return runDocumentationFactory(options, factoryRunnerDependencies{Verify: Verify, ToolIdentity: testFactoryToolIdentity()})
	}
	compiled, err := compileDocumentationFactorySourcePackageWithDependencies(DocumentationFactorySourceCompileOptions{SourcePackagePath: packageFixture.manifestPath, OutputRoot: packageFixture.outputRoot}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	completion := compiled.FactoryReceipt.Completion
	if compiled.FactoryReceipt.PreflightReceipt.Result != "pass" || !completion.DerivationExecuted || !completion.Verified || completion.GraphAdmittable || completion.AdmissionAuthorized || completion.FactoryComplete || compiled.SourceReceipt.AuthoritySelected || compiled.SourceReceipt.AdmissionAuthorized || compiled.SourceReceipt.FactoryComplete {
		t.Fatalf("native cloud candidate overclaimed completion: factory=%+v source=%+v", completion, compiled.SourceReceipt)
	}
}

func prepareNativeOperationApplicability(t *testing.T, fixture *testFixture, graph []byte) {
	t.Helper()
	path := fixture.dependencyByRole["operation_applicability"]
	_, rows := fixtureDependencySemanticArtifact(t, path)
	var operation map[string]interface{}
	for _, row := range rows.byKind["operation_applicability"] {
		id, _ := semanticString(row.data, "operation_candidate_api_symbol_id")
		if id == fixture.sourceOperationID {
			operation = cloneSemanticObjectForTest(t, row.data)
			break
		}
	}
	if operation == nil || len(rows.byKind["artifact_manifest"]) != 1 || len(rows.byKind["validation_summary"]) != 1 {
		t.Fatal("fixture lacks closed source-read operation applicability")
	}
	operation["actual_relationship_ids"], operation["actual_property_claim_ids"] = []interface{}{}, []interface{}{}
	var native validationSummary
	var nativeOperation apiSymbol
	for _, line := range bytes.Split(bytes.TrimSpace(graph), []byte{'\n'}) {
		var envelope struct {
			RowKind string `json:"row_kind"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.RowKind == "validation_summary" {
			if err := strictUnmarshal(line, &native); err != nil {
				t.Fatal(err)
			}
		}
		if envelope.RowKind == "candidate_api_symbol" {
			var symbol apiSymbol
			if err := strictUnmarshal(line, &symbol); err != nil {
				t.Fatal(err)
			}
			if symbol.ID == fixture.sourceOperationID {
				nativeOperation = symbol
			}
		}
	}
	if native.RowKind == "" {
		t.Fatal("native graph lacks validation summary")
	}
	if nativeOperation.ID == "" {
		t.Fatal("native graph lacks selected source operation")
	}
	summary := cloneSemanticObjectForTest(t, rows.byKind["validation_summary"][0].data)
	summary["operation_applicability_count"] = json.Number("1")
	summary["candidate_subject_count"] = json.Number(strconv.Itoa(native.CandidateSubjectCount))
	summary["actual_relationship_fact_count"], summary["actual_property_fact_count"] = json.Number("0"), json.Number("0")
	summary["sparse_required_gap_count"] = json.Number(strconv.Itoa(native.CandidateGraphGapCount))
	summary["captured_operation_kind_counts"] = []interface{}{map[string]interface{}{"operation_kind": "request_response_read_operation", "count": json.Number("1")}}
	summary["subject_set_root_sha256"], summary["fact_set_root_sha256"], summary["gap_set_root_sha256"] = native.SubjectSetRootSHA256, native.FactSetRootSHA256, native.GapSetRootSHA256
	writeJSONL(t, path, []interface{}{cloneSemanticObjectForTest(t, rows.byKind["artifact_manifest"][0].data), operation, summary})
	rebindOperationApplicability(t, fixture)
}

func cloudNativeServiceContext(t *testing.T, fixture *testFixture, model PinnedCloudModel, catalog CloudCatalog, operation CloudCatalogOperation, selected map[string]bool, prefix string) CloudNativeGraphContext {
	t.Helper()
	evidenceManifest := fileSHA256(t, fixture.evidencePath)
	evidenceByID := map[string]string{"model": evidenceManifest}
	selectedEvidenceIDs := map[string]struct{}{}
	for _, locator := range cloudNativeSelectedCatalogLocators(catalog, selected) {
		if locator.EvidenceID != "model" {
			selectedEvidenceIDs[locator.EvidenceID] = struct{}{}
		}
	}
	for evidenceID := range selectedEvidenceIDs {
		path := fixture.evidenceByRole["protocol"]
		if path == "" {
			t.Fatalf("fixture has no sealed supplemental evidence manifest for %q", evidenceID)
		}
		evidenceByID[evidenceID] = fileSHA256(t, path)
	}
	context := CloudNativeGraphContext{
		Provider: model.ProviderID,
		// The candidate has fewer graph rows, but it consumes the same sealed
		// evidence document through every dependency role as the fixture.  Its
		// manifest closure therefore remains byte-for-byte role complete.
		Manifest:                           cloudNativeFixtureManifest(fixture, "gcs_buckets_list_native_graph", "1", append([]evidenceManifestBinding(nil), fixture.manifest().EvidenceManifestBindings...)),
		EvidenceManifestSHA256ByEvidenceID: evidenceByID,
		SelectedOperationIDs:               map[string][]string{model.Source.ID: {operation.ID}},
		Summary:                            cloudNativeFixtureSummaryContext(t, fixture),
		SymbolDerivationBindings:           map[string]json.RawMessage{}, GapContexts: map[string]CloudNativeGapContext{},
		HierarchyEvidence: map[string][]CloudNativeEvidenceReference{}, OperationCrosswalks: map[string]CloudNativeOperationCrosswalk{}, ResourceCrosswalks: map[string]CloudNativeResourceCrosswalk{}, RelationshipLabels: map[string]string{},
	}
	bind := func(role, semantic, source string) {
		context.SymbolDerivationBindings[CloudNativeSymbolBindingKey(role, semantic)] = cloudNativeFixtureSymbolBinding(t, fixture, source, role, semantic)
	}
	providerSemantic := cloudNativeProviderSemanticKey(model.ProviderID)
	serviceSemantic := cloudNativeServiceSemanticKey(model.ProviderID, model.ServiceID)
	bind("provider", providerSemantic, prefix+"_provider")
	bind("service", serviceSemantic, prefix+"_service")
	context.HierarchyEvidence[CloudNativeSymbolBindingKey("provider", providerSemantic)] = []CloudNativeEvidenceReference{{ModelSourceID: model.Source.ID, Locator: operation.Locator}}
	context.HierarchyEvidence[CloudNativeSymbolBindingKey("service", serviceSemantic)] = []CloudNativeEvidenceReference{{ModelSourceID: model.Source.ID, Locator: operation.Locator}}
	apiSemantic := cloudNativeSemanticKey(catalog, "api", catalog.APISurfaceID)
	bind("vendor_api", apiSemantic, prefix+"_api")
	providerID := stableID("capi_sym", lengthPrefixedIdentityKey("provider", providerSemantic))
	serviceID := stableID("capi_sym", lengthPrefixedIdentityKey("service", serviceSemantic))
	apiID := stableID("capi_sym", lengthPrefixedIdentityKey("vendor_api", apiSemantic))
	resourceIDs := map[string]string{}
	for _, resource := range catalog.Resources {
		if !cloudNativeResourceSelected(resource, selected) {
			continue
		}
		semantic := "resource:" + prefix
		bind("resource", semantic, prefix+"_resource")
		resourceIDs[resource.ID] = stableID("capi_sym", lengthPrefixedIdentityKey("resource", semantic))
		context.ResourceCrosswalks[CloudNativeResourceBindingKey(model.Source.ID, resource.ID)] = CloudNativeResourceCrosswalk{SourceSymbol: prefix + "_resource", ResourceSemanticKey: semantic, ResourceSymbolID: resourceIDs[resource.ID]}
	}
	authIDs := map[string]string{}
	for _, auth := range catalog.Authentication {
		bind("auth_scheme", cloudNativeSemanticKey(catalog, "auth", auth.ID), prefix+"_auth_"+auth.ID)
		authIDs[auth.ID] = stableID("capi_sym", lengthPrefixedIdentityKey("auth_scheme", cloudNativeSemanticKey(catalog, "auth", auth.ID)))
	}
	identity := fixture.sourceOperationIdentity
	semantic, err := sourceOperationSemanticKey(fixture.sourceReadOperationSymbol, identity)
	if err != nil {
		t.Fatal(err)
	}
	opID := stableID("capi_sym", lengthPrefixedIdentityKey("operation", semantic))
	bind("operation", semantic, fixture.sourceReadOperationSymbol)
	if len(operation.ResourceIDs) != 1 {
		t.Fatalf("buckets.list resource roster = %v, want one", operation.ResourceIDs)
	}
	resourceID := resourceIDs[operation.ResourceIDs[0]]
	readClaim := stableID("capi_rel", lengthPrefixedIdentityKey("operation_reads_resource", opID, resourceID))
	context.OperationCrosswalks[CloudNativeOperationBindingKey(model.Source.ID, operation.ID)] = CloudNativeOperationCrosswalk{SourceSymbol: fixture.sourceReadOperationSymbol, CanonicalSourceOperationIdentity: mustNativeTestJSON(t, identity), OperationSemanticKey: semantic, OperationSymbolID: opID, ResourceAccesses: []CloudNativeRelationshipCrosswalk{{Label: "operation_reads_resource", SourceSymbolID: opID, TargetSymbolID: resourceID, RelationshipID: readClaim}}}
	addGap := func(label, source, target string, locators []CloudCatalogEvidenceLocator) {
		claim := stableID("capi_rel", lengthPrefixedIdentityKey(label, source, target))
		context.RelationshipLabels[claim] = label
		ids := make([]string, len(locators))
		for i, locator := range locators {
			value, err := cloudNativeEvidenceLocator(context, model, locator)
			if err != nil {
				t.Fatal(err)
			}
			ids[i] = value.ID
		}
		context.GapContexts[CloudNativeGapBindingKey(source, claim)] = cloudNativeFixtureGapContext(t, fixture, source, claim, label, ids)
	}
	apiLocators := cloudNativeSelectedCatalogLocators(catalog, selected)
	addGap("provider_has_service", providerID, serviceID, []CloudCatalogEvidenceLocator{operation.Locator})
	for _, auth := range catalog.Authentication {
		addGap("provider_supports_auth_scheme", providerID, authIDs[auth.ID], []CloudCatalogEvidenceLocator{auth.Locator})
	}
	addGap("service_has_api", serviceID, apiID, apiLocators)
	for _, resource := range catalog.Resources {
		if !cloudNativeResourceSelected(resource, selected) {
			continue
		}
		locators := []CloudCatalogEvidenceLocator{resource.Locator}
		if resource.DeclarationEvidenceLocator != nil {
			locators = append(locators, *resource.DeclarationEvidenceLocator)
		}
		addGap("api_has_resource", apiID, resourceIDs[resource.ID], locators)
	}
	opLocators := append([]CloudCatalogEvidenceLocator{operation.Locator}, cloudNativeAssociationLocators(operation)...)
	addGap("api_has_operation", apiID, opID, opLocators)
	addGap("operation_reads_resource", opID, resourceID, opLocators)
	addGap("resource_has_operation", resourceID, opID, opLocators)
	context.Manifest.EvidenceLocatorManifestSHA256 = cloudNativeLocatorManifestSHA256(t, context, model, cloudNativeSelectedCatalogLocators(catalog, selected))
	return context
}

func cloudNativeFixtureSummaryContext(t *testing.T, fixture *testFixture) *CloudNativeSummaryContext {
	t.Helper()
	count := func(role, kind string) int {
		_, rows := fixtureDependencySemanticArtifact(t, fixtureSemanticArtifactPath(fixture, role))
		return len(rows.byKind[kind])
	}
	return &CloudNativeSummaryContext{
		ExactSourceDocumentCount:            count(dependencySemanticRoleSourceContract, "source_document"),
		ExactDocumentedFieldOccurrenceCount: count(dependencySemanticRoleSourceContract, "field_contract"),
		SampleJSONBlockCount:                count(dependencySemanticRoleSampleShape, "sample_json_block"),
		ProtocolAssertionCount:              count(dependencySemanticRoleProtocolContract, "protocol_assertion_projection"),
		PreservedContradictionCount:         count(dependencySemanticRoleProtocolContract, "provider_contract_contradiction"),
	}
}

func cloudNativeLocatorManifestSHA256(t *testing.T, context CloudNativeGraphContext, model PinnedCloudModel, locators []CloudCatalogEvidenceLocator) string {
	t.Helper()
	byID := map[string]evidenceLocator{}
	for _, locator := range locators {
		value, err := cloudNativeEvidenceLocator(context, model, locator)
		if err != nil {
			t.Fatal(err)
		}
		byID[value.ID] = value
	}
	var raw []byte
	for _, id := range sortedProviderStringMapKeys(byID) {
		line, err := canonicalFactoryJSON(byID[id])
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, line...)
		raw = append(raw, '\n')
	}
	return sha256Hex(raw)
}

func cloudNativeOperationByID(t *testing.T, catalog CloudCatalog, id string) CloudCatalogOperation {
	t.Helper()
	for _, operation := range catalog.Operations {
		if operation.ID == id {
			return operation
		}
	}
	t.Fatalf("catalog has no operation %q", id)
	return CloudCatalogOperation{}
}
func cloudNativeResourceSelected(resource CloudCatalogResource, selected map[string]bool) bool {
	for _, id := range resource.OperationIDs {
		if selected[id] {
			return true
		}
	}
	return false
}

func replaceSourcePackageAPIGraph(t *testing.T, manifestPath string, graph []byte) {
	t.Helper()
	manifest := readSourcePackageCompilerTestManifest(t, manifestPath)
	document := generatedSourcePackageDocumentByRole(t, &manifest, sourcePackageOutputRoleAPIGraphArtifact)
	payload := sourcePackageCoordinate{Role: "source_payload", ID: strings.TrimSuffix(document.Template.ID, "_template") + "_payload", Version: "1"}
	output, payloadRaw, templateRaw := sourcePackageCompilerProjectionTemplate(t, sourcePackageOutputRoleAPIGraphArtifact, payload, graph)
	if !bytes.Equal(output, graph) {
		t.Fatal("native graph source-package projection changed graph bytes")
	}
	replace := func(coordinate sourcePackageCoordinate, raw []byte) {
		for index := range manifest.Resources {
			resource := &manifest.Resources[index]
			if resource.coordinate() != coordinate {
				continue
			}
			if err := os.WriteFile(filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(resource.Path)), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			resource.ExpectedRawSHA256, resource.ExpectedByteCount = sha256Hex(raw), uint64(len(raw))
			return
		}
		t.Fatalf("source package lacks %s", sourcePackageCoordinateLabel(coordinate))
	}
	replace(payload, payloadRaw)
	replace(document.Template, templateRaw)
	document.ExpectedRawSHA256, document.ExpectedByteCount = sha256Hex(output), uint64(len(output))
	profileCoordinate := manifest.FactoryPlan.GraphCompile.StageValidation.Profile.Resource
	for index := range manifest.Resources {
		resource := &manifest.Resources[index]
		if resource.coordinate() != profileCoordinate {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(resource.Path)))
		if err != nil {
			t.Fatal(err)
		}
		var profile stageValidationProfileDocument
		if err := strictUnmarshal(raw, &profile); err != nil {
			t.Fatal(err)
		}
		updated := false
		for bindingIndex := range profile.BoundArtifactSchemas {
			binding := &profile.BoundArtifactSchemas[bindingIndex]
			if binding.Role == document.Role && binding.ArtifactID == document.ID && binding.ArtifactVersion == document.Version {
				binding.ArtifactRawSHA256 = sha256Hex(graph)
				updated = true
			}
		}
		if !updated {
			t.Fatalf("graph validation profile lacks %s", sourcePackageCoordinateLabel(document.coordinate()))
		}
		replace(profileCoordinate, mustStageJSON(t, profile))
		break
	}
	writeSourcePackageCompilerTestManifest(t, manifestPath, manifest)
}
