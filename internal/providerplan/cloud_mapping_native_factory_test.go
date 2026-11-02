package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"testing"
)

// TestCloudMappingFullNativeProgramsCloseEverySelectedField exercises the
// production multi-profile composer with the complete, fixed four-service
// mapping scope.  This is deliberately a single closure: selecting a handy
// field (or one service) is not evidence that the generated program roster is
// complete. TestCloudMappingAllTargetsReachRealFactoryVerify exercises every
// operation through the compiler; this test checks the parent input closure.
func TestCloudMappingFullNativeProgramsCloseEverySelectedField(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	// The snapshot coordinates are the fixture's exact source documents.  Do
	// not concatenate models or re-label a second model as protocol evidence.
	models := loadPinnedCloudModelsForCompilerProof(t)
	request.retainedModels = append([]PinnedCloudModel(nil), models...)
	request.Catalogs = nil
	for i := range request.retainedModels {
		originalID := request.retainedModels[i].Source.ID
		request.retainedModels[i].Source = cloudNativeSnapshotSource(t, originalID)
		for k := range scope.Catalogs {
			if scope.Catalogs[k].ModelSourceID == originalID {
				scope.Catalogs[k].ModelSourceID = request.retainedModels[i].Source.ID
			}
		}
		for j := range request.retainedModels[i].SupplementalEvidence {
			request.retainedModels[i].SupplementalEvidence[j].Source = cloudNativeSnapshotSupplementalSource(t, originalID, request.retainedModels[i].SupplementalEvidence[j].ID)
		}
		catalog, parseErr := ParsePinnedCloudModel(request.retainedModels[i])
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		request.Catalogs = append(request.Catalogs, catalog)
	}
	roster, err := BuildCloudMappingOccurrenceRoster(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(roster.Occurrences), 255; got != want || roster.Totals != (CloudMappingDispositionTotals{Mapped: 31, Private: 24, Unsupported: 200}) {
		t.Fatalf("full native mapping closure = %d/%+v, want %d mapped31 private24 unsupported200", got, roster.Totals, want)
	}

	modelByID := map[string]PinnedCloudModel{}
	bodies := map[string]exactEvidenceBody{}
	for _, model := range request.retainedModels {
		modelByID[model.Source.ID] = model
		bodies[sha256Hex(model.Raw)] = exactEvidenceBody{Bytes: model.Raw, Coordinates: map[evidenceSourceCoordinate]string{{Ref: model.Source.StableCoordinate, URL: model.Source.URI}: sha256Hex([]byte("full-native-manifest|" + model.Source.ID))}}
	}
	occurrences := map[string][]sourceClassificationOccurrence{}
	add := func(symbol, sourceID string, locator CloudCatalogEvidenceLocator) {
		model := modelByID[sourceID]
		bodyDigest := sha256Hex(model.Raw)
		value := evidenceLocator{RowKind: "candidate_evidence_locator", EvidenceManifestSHA256: sha256Hex([]byte("full-native-manifest|" + sourceID)), SourceContentSHA256: bodyDigest, ByteStartOffset: int64(locator.StartByte), ByteEndOffsetExclusive: int64(locator.EndByte), SelectedRangeByteCount: int64(locator.EndByte - locator.StartByte), SelectedRangeSHA256: sha256Hex(model.Raw[locator.StartByte:locator.EndByte]), SourceRefs: []string{model.Source.StableCoordinate}, SourceURLs: []string{model.Source.URI}, LocatorSemantics: exactLocatorSemantics}
		value.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(value))
		occurrences[symbol] = []sourceClassificationOccurrence{{Binding: classificationArtifactBinding{ArtifactID: "full_native_classification", ArtifactVersion: "1", ArtifactSHA256: sha256Hex([]byte("full-native-classification"))}, SourceSymbol: symbol, SurfaceKind: "resource", Locator: value}}
	}
	for _, occurrence := range roster.Occurrences {
		add(occurrence.FieldSourceSymbol, occurrence.ModelSourceID, occurrence.Program.Locator)
		add(occurrence.SourceSchemaOwnerSymbol, occurrence.ModelSourceID, occurrence.SourceSchemaOwnerLocator)
	}
	proof := newSourceClassificationSelectionProof("cloud-full-native", sha256Hex([]byte("full-native-selection-roster")), occurrences)

	for _, provider := range []string{"aws", "gcp"} {
		providerRoster, partErr := CloudMappingOccurrenceRosterForProvider(roster, provider)
		if partErr != nil {
			t.Fatal(partErr)
		}
		bundle, bundleErr := BuildCloudMappingProviderDerivationBundle(providerRoster, proof, bodies)
		if bundleErr != nil {
			t.Fatal(bundleErr)
		}
		if len(bundle.Execution.FieldFacts) != len(providerRoster.Occurrences) || bundle.ProfileExecution.FactCount != int64(len(providerRoster.Occurrences)) {
			t.Fatalf("%s full native execution did not close its roster", provider)
		}
		native := map[string]CloudMappingNativeResourceIdentity{}
		for _, resource := range providerRoster.Resources {
			owners := map[string]string{}
			for _, occurrence := range providerRoster.Occurrences {
				if occurrence.ResourceKey == resource.ResourceKey {
					owners[occurrence.SourceSchemaOwnerSymbol] = occurrences[occurrence.SourceSchemaOwnerSymbol][0].Locator.ID
				}
			}
			native[resource.ResourceKey] = CloudMappingNativeResourceIdentity{APIResourceID: stableID("capi_sym", "full-native|"+resource.ResourceKey), APIResourceSourceSymbol: resource.APIResourceSymbol, SchemaOwnerEvidenceLocatorIDs: owners}
		}
		projection, projectionErr := ComposeCloudMappingSourceContractProjection(providerRoster, native, bundle.Execution.FieldFacts)
		if projectionErr != nil || len(projection.FieldContracts) != len(providerRoster.Occurrences) || len(projection.ResourceSchemaBindings) != len(providerRoster.Resources) {
			t.Fatalf("%s full native source-contract projection = fields:%d bindings:%d err:%v", provider, len(projection.FieldContracts), len(projection.ResourceSchemaBindings), projectionErr)
		}
		// A bridge may not silently accept a substituted schema-owner locator.
		for key, identity := range native {
			identity.SchemaOwnerEvidenceLocatorIDs = map[string]string{}
			native[key] = identity
			break
		}
		if _, err := ComposeCloudMappingSourceContractProjection(providerRoster, native, bundle.Execution.FieldFacts); err == nil {
			t.Fatalf("%s accepted a substituted/missing source-schema bridge locator", provider)
		}
		// A recipe/profile substitution must fail rather than permitting facts
		// from another generated field program to occupy this occurrence.
		facts := append([]exactDocumentationDerivedFact(nil), bundle.Execution.FieldFacts...)
		facts[0].Profile.digest = sha256Hex([]byte("substituted-field-recipe"))
		if _, err := ComposeCloudMappingSourceContractProjection(providerRoster, map[string]CloudMappingNativeResourceIdentity{}, facts); err == nil {
			t.Fatalf("%s accepted a substituted generated field recipe", provider)
		}
	}
}

func cloudMappingNativeFactoryService(t *testing.T, modelID, operationID, prefix string, complete ...CloudMappingOccurrenceRoster) {
	t.Helper()
	model := cloudNativeSnapshotModelByID(t, loadPinnedCloudModelsForCompilerProof(t), modelID)
	model.Source = cloudNativeSnapshotSource(t, model.Source.ID)
	input, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	cloudMappingNativeFactoryServiceWithInputs(t, modelID, operationID, prefix, model, input, complete...)
}

func cloudMappingNativeFactoryServiceWithInputs(t *testing.T, modelID, operationID, prefix string, model PinnedCloudModel, input CloudSourceCandidateRequest, complete ...CloudMappingOccurrenceRoster) {
	t.Helper()
	catalog, err := ParsePinnedCloudModel(model)
	if err != nil {
		t.Fatal(err)
	}
	operation := cloudNativeOperationByID(t, catalog, operationID)
	selected := map[string]bool{operation.ID: true}
	var resource CloudCatalogResource
	for _, value := range catalog.Resources {
		if cloudNativeResourceSelected(value, selected) {
			resource = value
		}
	}
	if resource.ID == "" {
		t.Fatal("selected operation has no resource")
	}
	var target CloudSourceObjectTarget
	for _, value := range input.Targets {
		if value.OperationID == operationID && value.MappingContract != nil {
			target = value
			break
		}
	}
	if target.MappingContract == nil {
		t.Fatalf("%s has no mapping target", operationID)
	}
	fieldSymbol := prefix + "_field"
	roster, err := BuildCloudTargetFieldDerivationRoster(catalog, target, model, fieldSymbol)
	if err != nil {
		t.Fatal(err)
	}
	if len(roster.Candidates) == 0 {
		t.Fatalf("%s has no derivable selected field: %#v", operationID, roster.Unresolved)
	}
	var field CloudFieldDerivationCandidate
	for _, candidate := range roster.Candidates {
		if len(candidate.Program.OrderedRules) == 1 && len(candidate.Program.OrderedRules[0].Pattern) <= maxDocumentationDerivationPatternBytes {
			field = candidate
			break
		}
	}
	if field.FieldPointer == "" {
		t.Fatalf("%s has no derivable field within the exact program bound", operationID)
	}
	var fullFields []CloudFieldDerivationCandidate
	if len(complete) != 0 {
		for _, occurrence := range complete[0].Occurrences {
			ref := dependencyProfileReference{id: occurrence.Program.ProfileID, version: occurrence.Program.ProfileVersion, digest: occurrence.Program.ProgramSHA256}
			program, parseErr := parseExactDocumentationDerivationProgram(occurrence.Program.Program, ref)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			fullFields = append(fullFields, CloudFieldDerivationCandidate{Reference: ref, Program: program, SourceSymbol: occurrence.FieldSourceSymbol, FieldPointer: occurrence.Program.FieldPointer, FieldLocator: occurrence.Program.Locator})
		}
		if len(fullFields) == 0 {
			t.Fatal("empty complete native field roster")
		}
		field, fieldSymbol = fullFields[0], fullFields[0].SourceSymbol
	}

	aws := len(model.SupplementalEvidence) != 0
	selectedEvidence := map[string]struct{}{}
	for _, locator := range cloudNativeSelectedCatalogLocators(catalog, selected) {
		if locator.EvidenceID != "model" {
			selectedEvidence[locator.EvidenceID] = struct{}{}
		}
	}
	for i := range model.SupplementalEvidence {
		if _, used := selectedEvidence[model.SupplementalEvidence[i].ID]; used {
			model.SupplementalEvidence[i].Source = cloudNativeSnapshotSupplementalSource(t, modelID, model.SupplementalEvidence[i].ID)
		}
	}
	primary := cloudMappingNativePrimary(t, model, catalog, operation, selected, resource, prefix)
	// The fixture's legacy fallback program is parsed before the explicit
	// builder runs. It is never executed here; keep its unused pattern bounded
	// while the builder below supplies the retained-model field rule.
	primary.fieldDerivationPattern = "x"
	primary.sampleRange = &officialProviderEvidenceRange{Name: prefix + "_source_field_sample", SourceSymbol: fieldSymbol, SurfaceKind: "resource", ByteStartOffset: int64(field.FieldLocator.StartByte), ByteEndOffsetExclusive: int64(field.FieldLocator.EndByte), SelectedRangeSHA256: sha256Hex(model.Raw[field.FieldLocator.StartByte:field.FieldLocator.EndByte])}
	primary.sampleSourceSymbol = fieldSymbol
	originalRanges := primary.additionalRangeBuilder
	primary.additionalRangeBuilder = func(a, b string) []officialProviderEvidenceRange {
		ranges := originalRanges(a, b)
		if len(complete) == 0 {
			ranges = append(ranges, officialProviderEvidenceRange{Name: prefix + "_source_field", SourceSymbol: fieldSymbol, SurfaceKind: "resource", ByteStartOffset: int64(field.FieldLocator.StartByte), ByteEndOffsetExclusive: int64(field.FieldLocator.EndByte), SelectedRangeSHA256: sha256Hex(model.Raw[field.FieldLocator.StartByte:field.FieldLocator.EndByte])})
		} else {
			seen := map[string]bool{}
			add := func(symbol string, locator CloudCatalogEvidenceLocator) {
				if seen[symbol] {
					return
				}
				seen[symbol] = true
				ranges = append(ranges, officialProviderEvidenceRange{Name: symbol, SourceSymbol: symbol, SurfaceKind: "resource", ByteStartOffset: int64(locator.StartByte), ByteEndOffsetExclusive: int64(locator.EndByte), SelectedRangeSHA256: sha256Hex(model.Raw[locator.StartByte:locator.EndByte])})
			}
			for _, occurrence := range complete[0].Occurrences {
				add(occurrence.FieldSourceSymbol, occurrence.Program.Locator)
				add(occurrence.SourceSchemaOwnerSymbol, occurrence.SourceSchemaOwnerLocator)
			}
		}
		return ranges
	}
	primary.derivationBuilder = func(t *testing.T, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) *testDocumentationDerivationBundle {
		if len(fullFields) != 0 {
			return cloudMappingNativeDerivationBundle(t, field, prefix+"_read_operation", prefix+"_resource", proof, bodies, fullFields[1:]...)
		}
		return cloudMappingNativeDerivationBundle(t, field, prefix+"_read_operation", prefix+"_resource", proof, bodies)
	}
	if aws {
		first := true
		for _, evidence := range model.SupplementalEvidence {
			if _, used := selectedEvidence[evidence.ID]; !used {
				continue
			}
			builder := cloudMappingNativeSupplementalRanges(t, model, catalog, selected, prefix, evidence.ID)
			if first {
				primary.protocolBody = evidence.Raw
				primary.protocolSourceRef, primary.protocolSourceURL = evidence.Source.StableCoordinate, evidence.Source.URI
				primary.protocolLiteralA, primary.protocolLiteralB = "resource_id", "operation_id"
				primary.additionalProtocolRangeBuilder = builder
				first = false
			} else {
				primary.additionalEvidence = append(primary.additionalEvidence, testSupplementalEvidenceFixture{name: evidence.ID, artifactSuffix: "association_" + strconv.Itoa(len(primary.additionalEvidence)), body: evidence.Raw, sourceRef: evidence.Source.StableCoordinate, sourceURL: evidence.Source.URI, ranges: builder("", ""), consumerRoles: []string{"api_graph_projection"}})
			}
		}
	}
	fixture := newTestFixtureWithPrimaryEvidence(t, primary)
	// Preserve the narrow profile-separation assertions for every field in
	// the complete package as well as the representative fixture.
	expectedFields := fullFields
	if len(expectedFields) == 0 {
		expectedFields = []CloudFieldDerivationCandidate{field}
	}
	factProfiles := map[string]dependencyProfileReference{}
	for _, fact := range fixture.documentationDerivation.facts {
		if fact.TargetRowKind == "field_contract" {
			factProfiles[fact.InputSourceSymbol] = fact.Profile
		}
	}
	for _, expectedField := range expectedFields {
		if dependencyProfileReferenceKey(factProfiles[expectedField.SourceSymbol]) != dependencyProfileReferenceKey(expectedField.Reference) {
			t.Fatalf("field %s did not retain its immutable generated profile", expectedField.SourceSymbol)
		}
		if dependencyProfileReferenceKey(fixture.documentationDerivation.accessFact.Profile) == dependencyProfileReferenceKey(expectedField.Reference) {
			t.Fatal("access fact was rebaked into a generated field profile")
		}
	}
	if len(complete) == 0 {
		assertCloudMappingNativeRows(t, fixture, field)
	} else {
		execution := CloudMappingProviderDerivationBundle{Execution: CloudMappingProviderExecution{ProviderID: model.ProviderID, Roster: complete[0]}}
		for _, fact := range fixture.documentationDerivation.facts {
			if fact.TargetRowKind == "field_contract" {
				execution.Execution.FieldFacts = append(execution.Execution.FieldFacts, fact)
			}
		}
		native := map[string]CloudMappingNativeResourceIdentity{}
		for _, resource := range complete[0].Resources {
			owners := map[string]string{}
			for _, occurrence := range complete[0].Occurrences {
				if occurrence.ResourceKey == resource.ResourceKey {
					selected := fixture.classificationSelections[model.ProviderID][occurrence.SourceSchemaOwnerSymbol]
					if len(selected) != 1 {
						t.Fatal("schema owner classification is not singular")
					}
					owners[occurrence.SourceSchemaOwnerSymbol] = selected[0].Locator.ID
				}
			}
			native[resource.ResourceKey] = CloudMappingNativeResourceIdentity{APIResourceID: stableID("capi_sym", lengthPrefixedIdentityKey("resource", "resource:"+prefix)), APIResourceSourceSymbol: prefix + "_resource", SchemaOwnerEvidenceLocatorIDs: owners}
		}
		cloudMappingSpliceFullArtifacts(t, fixture, execution, native)
	}
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
	assertCloudMappingNativeSymbolRosters(t, fixture, graph)
	packageFixture := newSourcePackageCompilerTestFixtureFromBase(t, model.ProviderID, fixture)
	replaceSourcePackageAPIGraph(t, packageFixture.manifestPath, graph)
	deps := defaultDocumentationFactorySourceCompilerDependencies()
	deps.RunFactory = func(options FactoryRunOptions) (FactoryRunReceipt, error) {
		return runDocumentationFactory(options, factoryRunnerDependencies{Verify: Verify, ToolIdentity: testFactoryToolIdentity()})
	}
	compiled, err := compileDocumentationFactorySourcePackageWithDependencies(DocumentationFactorySourceCompileOptions{SourcePackagePath: packageFixture.manifestPath, OutputRoot: packageFixture.outputRoot}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if !compiled.FactoryReceipt.Completion.Verified || compiled.FactoryReceipt.Completion.GraphAdmittable || compiled.SourceReceipt.AuthoritySelected || compiled.SourceReceipt.AdmissionAuthorized {
		t.Fatalf("cloud mapping proof overclaimed or did not verify: %+v / %+v", compiled.FactoryReceipt.Completion, compiled.SourceReceipt)
	}
}

// assertCloudMappingNativeSymbolRosters diagnoses the same exact closure that
// Verify enforces later, while retaining the source-symbol coordinate that the
// generic verifier deliberately does not expose in its final error.
func assertCloudMappingNativeSymbolRosters(t *testing.T, fixture *testFixture, graph []byte) {
	t.Helper()
	selections := cloudNativeFixtureSelections(t, fixture)
	for _, line := range bytes.Split(bytes.TrimSpace(graph), []byte{'\n'}) {
		var row map[string]interface{}
		if err := strictUnmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		if row["row_kind"] != "candidate_api_symbol" {
			continue
		}
		bindingRaw, ok := row["derivation_binding"].(map[string]interface{})
		if !ok {
			t.Fatalf("candidate API symbol %v has no derivation binding", row["candidate_api_symbol_id"])
		}
		sourceSymbol, ok := bindingRaw["source_symbol"].(string)
		if !ok || sourceSymbol == "" {
			t.Fatalf("candidate API symbol %v has no binding source symbol", row["candidate_api_symbol_id"])
		}
		occurrences := selections[sourceSymbol]
		if len(occurrences) == 0 {
			t.Fatalf("candidate API symbol %v names absent classification source symbol %q", row["candidate_api_symbol_id"], sourceSymbol)
		}
		wantSet := map[string]struct{}{}
		for _, occurrence := range occurrences {
			wantSet[occurrence.Locator.ID] = struct{}{}
		}
		want := sortedSetKeys(wantSet)
		gotValues, ok := row["evidence_locator_ids"].([]interface{})
		if !ok {
			t.Fatalf("candidate API symbol %v has malformed evidence locator roster", row["candidate_api_symbol_id"])
		}
		got := make([]string, len(gotValues))
		for i, value := range gotValues {
			var valid bool
			got[i], valid = value.(string)
			if !valid {
				t.Fatalf("candidate API symbol %v has non-string locator", row["candidate_api_symbol_id"])
			}
		}
		if !equalOrderedStrings(got, want) {
			t.Fatalf("native candidate API symbol %v source symbol %q locator roster = %v, want exact classification occurrences %v", row["candidate_api_symbol_id"], sourceSymbol, got, want)
		}
	}
}

func cloudMappingNativePrimary(t *testing.T, model PinnedCloudModel, catalog CloudCatalog, operation CloudCatalogOperation, selected map[string]bool, resource CloudCatalogResource, prefix string) testPrimaryEvidenceFixture {
	t.Helper()
	primary := testPrimaryEvidenceFixture{
		body: model.Raw, derivationPattern: regexp.QuoteMeta(string(model.Raw[operation.Locator.StartByte:operation.Locator.EndByte])), fieldDerivationPattern: regexp.QuoteMeta(string(model.Raw[resource.Locator.StartByte:resource.Locator.EndByte])),
		nativeSelectedOperationOnly: true, providerDescription: "Fixture-only retained cloud model derivation.", provider: model.ProviderID, sourceRef: model.Source.StableCoordinate, sourceURL: model.Source.URI, representation: "source_declared_machine_export", representationCoord: model.Source.StableCoordinate, artifactPrefix: prefix, sourceSymbolPrefix: prefix, operationName: operation.ID, sectionRoot: "Cloud", singleDocument: len(model.SupplementalEvidence) == 0, protocolLiteralA: "type", protocolLiteralB: "description",
		sampleRange: &officialProviderEvidenceRange{Name: "resource_sample", SourceSymbol: prefix + "_resource", SurfaceKind: "resource", ByteStartOffset: int64(resource.Locator.StartByte), ByteEndOffsetExclusive: int64(resource.Locator.EndByte), SelectedRangeSHA256: sha256Hex(model.Raw[resource.Locator.StartByte:resource.Locator.EndByte])}, exactRoleClassificationRanges: true,
		extraRoles: []string{"provider", "service"}, extraConstraints: []relationshipConstraint{{"provider_has_service", "provider", "service"}, {"service_has_api", "service", "vendor_api"}, {"api_has_resource", "vendor_api", "resource"}, {"resource_has_operation", "resource", "operation"}, {"provider_supports_auth_scheme", "provider", "auth_scheme"}},
		relationshipSubjectEndpoints: map[string]string{"api_has_operation": "source", "resource_has_operation": "source"}, relationshipDefaultDispositions: map[string]string{"provider_has_service": "required", "service_has_api": "required", "api_has_resource": "required", "api_has_operation": "required", "resource_has_operation": "required", "provider_supports_auth_scheme": "required"},
	}
	primary.additionalRangeBuilder = func(_, _ string) []officialProviderEvidenceRange {
		var ranges []officialProviderEvidenceRange
		add := func(source, surface string, locators []CloudCatalogEvidenceLocator) {
			for i, locator := range locators {
				if locator.EvidenceID == "model" {
					ranges = append(ranges, officialProviderEvidenceRange{Name: source + "_" + strconv.Itoa(i), SourceSymbol: source, SurfaceKind: surface, ByteStartOffset: int64(locator.StartByte), ByteEndOffsetExclusive: int64(locator.EndByte), SelectedRangeSHA256: sha256Hex(model.Raw[locator.StartByte:locator.EndByte])})
				}
			}
		}
		add(prefix+"_provider", "provider", []CloudCatalogEvidenceLocator{operation.Locator})
		add(prefix+"_service", "service", []CloudCatalogEvidenceLocator{operation.Locator})
		add(prefix+"_api", "vendor_api", cloudNativeSelectedCatalogLocators(catalog, selected))
		resourceLocators := []CloudCatalogEvidenceLocator{resource.Locator}
		if resource.DeclarationEvidenceLocator != nil {
			resourceLocators = append(resourceLocators, *resource.DeclarationEvidenceLocator)
		}
		add(prefix+"_resource", "resource", resourceLocators)
		add(prefix+"_read_operation", "operation", []CloudCatalogEvidenceLocator{operation.Locator})
		for _, auth := range catalog.Authentication {
			add(prefix+"_auth_"+auth.ID, "auth_scheme", []CloudCatalogEvidenceLocator{auth.Locator})
		}
		return ranges
	}
	return primary
}

func cloudMappingNativeSupplementalRanges(t *testing.T, model PinnedCloudModel, catalog CloudCatalog, selected map[string]bool, prefix string, evidenceFilter ...string) func(string, string) []officialProviderEvidenceRange {
	t.Helper()
	return func(_, _ string) []officialProviderEvidenceRange {
		var out []officialProviderEvidenceRange
		evidenceByID := make(map[string]CloudCatalogSupplementalEvidence, len(model.SupplementalEvidence))
		for _, evidence := range model.SupplementalEvidence {
			evidenceByID[evidence.ID] = evidence
		}
		seen := map[string]struct{}{}
		add := func(sourceSymbol, surface string, locator CloudCatalogEvidenceLocator) {
			if len(evidenceFilter) != 0 && locator.EvidenceID != evidenceFilter[0] {
				return
			}
			evidence, ok := evidenceByID[locator.EvidenceID]
			if !ok {
				return
			}
			if locator.StartByte < 0 || locator.EndByte < locator.StartByte || locator.EndByte > len(evidence.Raw) {
				t.Fatalf("supplemental locator %q is outside evidence %q", locator.JSONPointer, locator.EvidenceID)
			}
			key := sourceSymbol + "\x00" + surface + "\x00" + locator.EvidenceID + "\x00" + strconv.Itoa(locator.StartByte) + "\x00" + strconv.Itoa(locator.EndByte)
			if _, duplicate := seen[key]; duplicate {
				return
			}
			seen[key] = struct{}{}
			out = append(out, officialProviderEvidenceRange{Name: prefix + "_supplemental_" + strconv.Itoa(len(out)), SourceSymbol: sourceSymbol, SurfaceKind: surface, ByteStartOffset: int64(locator.StartByte), ByteEndOffsetExclusive: int64(locator.EndByte), SelectedRangeSHA256: sha256Hex(evidence.Raw[locator.StartByte:locator.EndByte])})
		}

		// The API envelope consumes every selected supplemental locator. Symbols
		// that also directly consume supplemental evidence must receive the same
		// exact locator under their own classified source symbol; otherwise the
		// native graph's symbol roster and its classification binding diverge.
		for _, locator := range cloudNativeSelectedCatalogLocators(catalog, selected) {
			add(prefix+"_api", "vendor_api", locator)
		}
		for _, resource := range catalog.Resources {
			if !cloudNativeResourceSelected(resource, selected) {
				continue
			}
			add(prefix+"_resource", "resource", resource.Locator)
			if resource.DeclarationEvidenceLocator != nil {
				add(prefix+"_resource", "resource", *resource.DeclarationEvidenceLocator)
			}
		}
		for _, auth := range catalog.Authentication {
			add(prefix+"_auth_"+auth.ID, "auth_scheme", auth.Locator)
		}
		for _, operation := range catalog.Operations {
			if selected[operation.ID] {
				add(prefix+"_read_operation", "operation", operation.Locator)
			}
		}
		return out
	}
}

func cloudMappingNativeDerivationBundle(t *testing.T, field CloudFieldDerivationCandidate, accessSymbol, accessResourceSymbol string, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody, additionalFields ...CloudFieldDerivationCandidate) *testDocumentationDerivationBundle {
	t.Helper()
	fieldRaw, err := canonicalFactoryJSON(field.Program)
	if err != nil {
		t.Fatal(err)
	}
	if field.Reference.digest != sha256Hex(fieldRaw) {
		t.Fatalf("generated cloud field profile digest drifted: %s", field.Reference.digest)
	}
	fieldProgram, err := parseExactDocumentationDerivationProgram(fieldRaw, field.Reference)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fieldRaw, mustCloudMappingNativeCanonicalProgram(t, fieldProgram)) {
		t.Fatal("generated cloud field program was not byte-identical after parsing")
	}
	occurrences := proof.classificationsBySourceSymbol[accessSymbol]
	if len(occurrences) != 1 {
		t.Fatalf("%s classification occurrences = %d, want one", accessSymbol, len(occurrences))
	}
	locator := occurrences[0].Locator
	body := bodies[locator.SourceContentSHA256].Bytes
	if locator.ByteStartOffset < 0 || locator.ByteEndOffsetExclusive > int64(len(body)) {
		t.Fatal("operation locator outside retained body")
	}
	accessProgram := exactDocumentationDerivationProgram{ProgramKind: exactDocumentationDerivationProgramKind, InputEncoding: exactDocumentationDerivationEncodingUTF8, MaxParseBytes: int64(len(body)), MaxOutputBytesPerFact: 8192, MaxOutputFactsPerPage: 1, MaxOutputBytesPerPage: 8192, MaxOutputFactsPerRun: 1, MaxOutputBytesPerRun: 8192, MaxOutputPagesPerRun: 1, MaxMatcherEvaluationsPerInputUnit: 1, MaxMatcherEvaluationsPerRun: 1, MaxMatcherInputBytesPerInputUnit: int64(len(body)), MaxMatcherInputBytesPerRun: int64(len(body)), MaxOccurrenceOutcomesPerRun: 1, MaxCanonicalOutcomeBytesPerRun: 8192, InputSourceSymbols: []string{accessSymbol}, OrderedRules: []exactDocumentationDerivationRule{{Ordinal: 0, RuleID: "extract_cloud_operation_resource_access", InputSourceSymbol: accessSymbol, TargetArtifactRole: dependencySemanticRoleSourceContract, TargetRowKind: "api_operation", TargetBindingKind: exactDocumentationTargetRowMember, TargetMemberJSONPointer: "/resource_accesses", TargetRowSelector: []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/source_symbol", ExpectedStringTemplate: accessSymbol}}, TargetMemberIdentityJSONPointers: []string{"/source_symbol"}, Pattern: regexp.QuoteMeta(string(body[locator.ByteStartOffset:locator.ByteEndOffsetExclusive])), MaximumMatchBytes: locator.ByteEndOffsetExclusive - locator.ByteStartOffset, MinimumMatches: 1, MaximumMatches: 1, OutputFields: map[string]interface{}{"relationship_label": "operation_reads_resource", "source_symbol": accessResourceSymbol}, ExactOutputFieldNames: []string{"relationship_label", "source_symbol"}}}}
	accessRaw, err := canonicalFactoryJSON(accessProgram)
	if err != nil {
		t.Fatal(err)
	}
	accessReference := dependencyProfileReference{id: "cloud_mapping_native_access_derivation", version: "1", digest: sha256Hex(accessRaw)}
	accessProgram, err = parseExactDocumentationDerivationProgram(accessRaw, accessReference)
	if err != nil {
		t.Fatal(err)
	}
	profileSet := []cloudMappingNativeProfile{{reference: field.Reference, program: fieldProgram, required: []string{"field_name", "provider_requirement", "provider_type"}}, {reference: accessReference, program: accessProgram, required: []string{"relationship_label", "source_symbol"}}}
	for _, additional := range additionalFields {
		raw := mustCloudMappingNativeCanonicalProgram(t, additional.Program)
		if sha256Hex(raw) != additional.Reference.digest {
			t.Fatal("additional generated field program changed")
		}
		profileSet = append(profileSet, cloudMappingNativeProfile{reference: additional.Reference, program: additional.Program, required: []string{"field_name", "provider_requirement", "provider_type"}})
	}
	profileRows := cloudMappingNativeProfileRows(t, profileSet)
	profiles, err := parseExecutableDocumentationDerivationProfiles(profileRows)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(execution.Results) != len(profileSet) || execution.FactCount != int64(len(profileSet)) {
		t.Fatalf("cloud derivation execution = %#v", execution)
	}
	var facts []exactDocumentationDerivedFact
	for _, result := range execution.Results {
		facts = append(facts, result.Facts...)
	}
	var access, fieldFact exactDocumentationDerivedFact
	for _, fact := range facts {
		if fact.TargetRowKind == "field_contract" && fact.Profile == field.Reference {
			fieldFact = fact
		}
		if fact.TargetRowKind == "api_operation" {
			access = fact
		}
	}
	if access.FactID == "" || fieldFact.FactID == "" {
		t.Fatal("cloud derivation has no exact access and field facts")
	}
	authority, artifacts, rows := cloudMappingNativeTarget(t, facts)
	materializations, whole, members, err := validateExactDocumentationTargetMaterializations(profiles, facts, authority, artifacts, rows)
	if err != nil || whole != int64(1+len(additionalFields)) || members != 1 || len(materializations) != len(profileSet) {
		t.Fatalf("cloud target materialization = %d/%d/%d: %v", len(materializations), whole, members, err)
	}
	state, err := parseDocumentationClaimDerivationRows(profileRows)
	if err != nil {
		t.Fatal(err)
	}
	closure, err := executeAndValidateDocumentationDerivationClosure(profileRows, state, authority, artifacts, rows, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDocumentationDerivationClosureProof(closure); err != nil {
		t.Fatal(err)
	}
	fieldOutput, err := decodeExactDocumentationFactOutputFields(fieldFact)
	if err != nil {
		t.Fatal(err)
	}
	numericDisposition, ok := fieldOutput["numeric_disposition"].(map[string]interface{})
	if !ok {
		t.Fatal("generated cloud field lacks numeric disposition")
	}
	numeric := exactValueClassifierOutput{}
	numeric.numericSemantics, _ = numericDisposition["numeric_semantics"].(string)
	numeric.authoritativeCarrier, _ = numericDisposition["authoritative_carrier"].(string)
	numeric.computationPath, _ = numericDisposition["computation_path"].(string)
	if numeric.numericSemantics == "" || numeric.authoritativeCarrier == "" || numeric.computationPath == "" {
		t.Fatalf("generated cloud numeric disposition is incomplete: %#v", numericDisposition)
	}
	return &testDocumentationDerivationBundle{profileRows: profileRows, profiles: profiles, facts: facts, targetAuthority: authority, targetArtifacts: artifacts, targetRows: rows, accessFact: access, fieldFact: fieldFact, numeric: numeric, applicability: "required", ruleCount: execution.RuleCount, outcomeCount: execution.OutcomeCount, factCount: execution.FactCount, wholeRowCount: whole, rowMemberCount: members, pageSetRoot: execution.ProfilePageSetRootSHA256, resultSetRoot: execution.ProfileResultSetRootSHA256, targetRoot: closure.targetMaterializationRootSHA256, targetRosterRoot: closure.targetMaterializationBindingRosterRootSHA256, closureProofRoot: closure.proofSHA256, closure: closure}
}

func mustCloudMappingNativeCanonicalProgram(t *testing.T, program exactDocumentationDerivationProgram) []byte {
	t.Helper()
	raw, err := canonicalFactoryJSON(program)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// cloudMappingFullNativeBindingContext executes the unchanged generated field
// programs through the normal exact-target materialization validator.  The
// returned closure roots are the values the source-package splice must bind;
// callers cannot replace them with row-count assertions.
func cloudMappingFullNativeBindingContext(t *testing.T, execution CloudMappingProviderDerivationBundle, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) documentationDerivationClosureProof {
	t.Helper()
	var facts []exactDocumentationDerivedFact
	for _, result := range execution.ProfileExecution.Results {
		facts = append(facts, result.Facts...)
	}
	if len(facts) != len(execution.Execution.Roster.Occurrences) {
		t.Fatalf("full fact closure=%d want %d", len(facts), len(execution.Execution.Roster.Occurrences))
	}
	authority, artifacts, rows := cloudMappingNativeTarget(t, facts)
	materializations, whole, members, err := validateExactDocumentationTargetMaterializations(execution.Profiles, facts, authority, artifacts, rows)
	if err != nil || whole != int64(len(facts)) || members != 0 || len(materializations) != len(facts) {
		t.Fatalf("full target materialization=%d/%d/%d: %v", len(materializations), whole, members, err)
	}
	state, err := parseDocumentationClaimDerivationRows(execution.ProfileRows)
	if err != nil {
		t.Fatal(err)
	}
	closure, err := executeAndValidateDocumentationDerivationClosure(execution.ProfileRows, state, authority, artifacts, rows, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDocumentationDerivationClosureProof(closure); err != nil {
		t.Fatal(err)
	}
	return closure
}

type cloudMappingNativeProfile struct {
	reference dependencyProfileReference
	program   exactDocumentationDerivationProgram
	required  []string
}

func cloudMappingNativeProfileRows(t *testing.T, profiles []cloudMappingNativeProfile) dependencySemanticRows {
	t.Helper()
	objects := []interface{}{map[string]interface{}{"row_kind": "artifact_manifest", "artifact": "cloud_mapping_native_derivation", "artifact_version": "1", "canonical_admission_authorized": false, "independent_generic_reexecution_required": true}}
	for index, profile := range profiles {
		properties := map[string]interface{}{}
		for name, value := range profile.program.OrderedRules[0].OutputFields {
			properties[name] = cloudMappingNativeClosedSchema(value)
		}
		for _, name := range profile.required {
			if _, exists := properties[name]; !exists {
				properties[name] = map[string]interface{}{"type": "string"}
			}
		}
		schemaID := "urn:fixture:cloud-mapping-native-claim:" + strconv.Itoa(index)
		schema, err := canonicalFactoryJSON(map[string]interface{}{"$schema": validationProfileDraft202012, "$id": schemaID, "type": "object", "additionalProperties": false, "required": profile.required, "properties": properties})
		if err != nil {
			t.Fatal(err)
		}
		schemaRef := dependencyProfileReference{id: schemaID, version: "1", digest: sha256Hex(schema)}
		programObject := map[string]interface{}{}
		if err := strictUnmarshal(mustCloudMappingNativeCanonicalProgram(t, profile.program), &programObject); err != nil {
			t.Fatal(err)
		}
		objects = append(objects, map[string]interface{}{"row_kind": "validation_schema", "validation_schema_id": schemaRef.id, "validation_schema_version": schemaRef.version, "validation_schema_sha256": schemaRef.digest, "claim_kind": "field_contract", "schema_dialect": validationProfileDraft202012, "canonical_schema_json": string(schema)}, map[string]interface{}{"row_kind": "derivation_profile", "derivation_profile_id": profile.reference.id, "derivation_profile_version": profile.reference.version, "derivation_profile_sha256": profile.reference.digest, "claim_kind": "field_contract", "validation_schema_binding": map[string]interface{}{"validation_schema_id": schemaRef.id, "validation_schema_version": schemaRef.version, "validation_schema_sha256": schemaRef.digest}, "program": programObject})
	}
	objects = append(objects, map[string]interface{}{"row_kind": "validation_summary", "validation_schema_count": json.Number(strconv.Itoa(len(profiles))), "derivation_profile_count": json.Number(strconv.Itoa(len(profiles))), "classifier_profile_count": json.Number("0"), "dependency_resolution_profile_count": json.Number("0"), "canonical_admission_authorized": false, "independent_generic_reexecution_required": true, "result": "candidate_closed_source_neutral_derivation_profile"})
	var raw []byte
	for _, object := range objects {
		line, err := canonicalFactoryJSON(object)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, line...)
		raw = append(raw, '\n')
	}
	rows, err := parseDependencySemanticRows(artifactInput{Path: "cloud-mapping-native-profile.jsonl", Raw: raw, SHA256: sha256Hex(raw), Structured: true})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func cloudMappingNativeClosedSchema(value interface{}) map[string]interface{} {
	schema := map[string]interface{}{}
	switch typed := value.(type) {
	case map[string]interface{}:
		properties := map[string]interface{}{}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			properties[key] = cloudMappingNativeClosedSchema(typed[key])
		}
		schema["type"], schema["additionalProperties"], schema["properties"] = "object", false, properties
	case []interface{}:
		schema["type"] = "array"
		if len(typed) != 0 {
			items := make([]interface{}, len(typed))
			for index := range typed {
				items[index] = cloudMappingNativeClosedSchema(typed[index])
			}
			schema["prefixItems"] = items
			schema["items"] = false
		}
	case json.Number:
		schema["type"] = "number"
	case string:
		schema["type"] = "string"
	case bool:
		schema["type"] = "boolean"
	}
	return schema
}

func cloudMappingNativeTarget(t *testing.T, facts []exactDocumentationDerivedFact) (dependencySemanticDerivationTargetSchemaAuthority, map[string]artifactInput, map[string]dependencySemanticRows) {
	t.Helper()
	const role = dependencySemanticRoleSourceContract
	var objects []interface{}
	objects = append(objects, map[string]interface{}{"row_kind": "artifact_manifest", "artifact": "cloud_mapping_native_exact_target", "artifact_version": "1", "canonical_admission_authorized": false, "materialization_authority": "exact_documentation_derivation"})
	for _, fact := range facts {
		output, err := decodeExactDocumentationFactOutputFields(fact)
		if err != nil {
			t.Fatal(err)
		}
		row := map[string]interface{}{"row_kind": fact.TargetRowKind, exactDocumentationDerivedFactIDField: fact.FactID, "source_ref": fact.EvidenceLocator.SourceRefs[0], "source_url": fact.EvidenceLocator.SourceURLs[0], "source_content_sha256": fact.EvidenceLocator.SourceContentSHA256, "evidence_hydration_coordinate": map[string]interface{}{"source_content_sha256": fact.EvidenceLocator.SourceContentSHA256, "byte_start_offset": fact.EvidenceLocator.ByteStartOffset, "byte_end_offset_exclusive": fact.EvidenceLocator.ByteEndOffsetExclusive, "selected_range_byte_count": fact.EvidenceLocator.SelectedRangeByteCount, "selected_range_sha256": fact.EvidenceLocator.SelectedRangeSHA256}}
		if fact.TargetBindingKind == exactDocumentationTargetRowMember {
			row["source_symbol"] = fact.InputSourceSymbol
			member := map[string]interface{}{"documentation_derived_fact_ids": []string{fact.FactID}, "evidence_locator_ids": []string{fact.EvidenceLocatorID}}
			for k, v := range output {
				member[k] = v
			}
			row["resource_accesses"] = []interface{}{member}
		} else {
			for k, v := range output {
				row[k] = v
			}
		}
		objects = append(objects, row)
	}
	objects = append(objects, map[string]interface{}{"row_kind": "validation_summary", "documentation_derived_row_count": len(facts), "canonical_admission_authorized": false, "result": "exact_documentation_target_fixture_complete"})
	dir := t.TempDir()
	path := filepath.Join(dir, "target.jsonl")
	writeJSONL(t, path, objects)
	artifact, err := readArtifactInput(path)
	if err != nil {
		t.Fatal(err)
	}
	schemaPath := filepath.Join(dir, "target.schema.json")
	schemaID := "urn:fixture:cloud-mapping-native-target"
	writeFixtureExactJSONLSchema(t, path, schemaPath, schemaID)
	schema, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := parseDependencySemanticRows(artifact)
	if err != nil {
		t.Fatal(err)
	}
	authority := dependencySemanticDerivationTargetSchemaAuthority{seal: dependencySemanticDerivationTargetSchemaAuthorityIdentity, byRole: map[string]dependencySemanticDerivationTargetSchema{role: {artifactRole: role, artifactSHA256: artifact.SHA256, schemaRole: role + "_schema", schemaID: schemaID, schemaVersion: "1", schemaSHA256: sha256Hex(schema), schemaBytes: schema, discriminatorProperty: "row_kind", discriminatorValues: map[string]struct{}{"artifact_manifest": {}, "api_operation": {}, "field_contract": {}, "validation_summary": {}}}}}
	return authority, map[string]artifactInput{role: artifact}, map[string]dependencySemanticRows{role: rows}
}

func assertCloudMappingNativeRows(t *testing.T, fixture *testFixture, field CloudFieldDerivationCandidate) {
	t.Helper()
	derivation := fixture.documentationDerivation
	if derivation == nil {
		t.Fatal("fixture lacks cloud derivation")
	}
	if dependencyProfileReferenceKey(derivation.fieldFact.Profile) != dependencyProfileReferenceKey(field.Reference) {
		t.Fatalf("source-contract field fact profile = %#v, want immutable generator profile %#v", derivation.fieldFact.Profile, field.Reference)
	}
	if dependencyProfileReferenceKey(derivation.accessFact.Profile) == dependencyProfileReferenceKey(field.Reference) {
		t.Fatal("access fact was rebaked into the generated field profile")
	}
	output, err := decodeExactDocumentationFactOutputFields(derivation.fieldFact)
	if err != nil {
		t.Fatal(err)
	}
	_, source := fixtureDependencySemanticArtifact(t, fixtureSemanticArtifactPath(fixture, dependencySemanticRoleSourceContract))
	if len(source.byKind["field_contract"]) != 1 {
		t.Fatalf("source contract field rows = %d", len(source.byKind["field_contract"]))
	}
	row := source.byKind["field_contract"][0].data
	if row[exactDocumentationDerivedFactIDField] != derivation.fieldFact.FactID || row["field_name"] != output["field_name"] || row["provider_type"] != output["provider_type"] {
		t.Fatalf("source contract did not retain generated cloud field: %#v", row)
	}
	_, mapping := fixtureDependencySemanticArtifact(t, fixtureSemanticArtifactPath(fixture, dependencySemanticRoleFieldMapping))
	occurrences := mapping.byKind["field_occurrence_disposition"]
	if len(occurrences) != 1 {
		t.Fatalf("mapping occurrence rows = %d", len(occurrences))
	}
	binding, _ := occurrences[0].data["derivation_binding"].(map[string]interface{})
	if occurrences[0].data[exactDocumentationDerivedFactIDField] != derivation.fieldFact.FactID || binding["exact_input_documentation_fact_id"] != derivation.fieldFact.FactID {
		t.Fatalf("mapping occurrence did not bind generated fact: %#v", occurrences[0].data)
	}
}
