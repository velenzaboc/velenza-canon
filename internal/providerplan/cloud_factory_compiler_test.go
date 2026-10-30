package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests exercise only repository-local test fixtures. They do not
// select a credential, create a source record, qualify a cloud API, or prove
// that a raw cloud catalog is a native graph plan. The positive case proves
// compiler plumbing only, using existing schema-valid test bodies.
func TestCloudScaffoldClosesSchemaValidFixtureBodiesThroughFourStages(t *testing.T) {
	fixture := newSourcePackageCompilerTestFixture(t, "cloud_candidate")
	bundle := testCloudCandidateBundle(t, fixture.manifestPath)
	sealCloudCandidateBundleIntoTestScaffold(t, fixture.manifestPath, bundle)

	// The production convenience entrypoint intentionally refuses this
	// dirty/offline test checkout at build identity. These existing test
	// dependencies exercise the four-stage runner with its test verifier; they
	// are not evidence of production Verify acceptance.
	result, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err != nil {
		t.Fatalf("compile sealed cloud candidate scaffold: %v", err)
	}
	if err := validateFactoryRunReceipt(result.FactoryReceipt); err != nil {
		t.Fatalf("four-stage factory receipt: %v", err)
	}
	if err := validateDocumentationFactorySourceReceipt(result.SourceReceipt); err != nil {
		t.Fatalf("source compiler receipt: %v", err)
	}
	if len(result.SourceReceipt.GeneratedOutputs) != len(sourcePackageOutputRoleContracts) {
		t.Fatalf("generated output count = %d, want %d", len(result.SourceReceipt.GeneratedOutputs), len(sourcePackageOutputRoleContracts))
	}
	compiledManifest := readSourcePackageCompilerTestManifest(t, fixture.manifestPath)
	for role, want := range bundle.Documents {
		output := generatedSourcePackageDocumentByRole(t, &compiledManifest, role)
		got, readErr := os.ReadFile(filepath.Join(fixture.outputRoot, filepath.FromSlash(output.BundlePath)))
		if readErr != nil {
			t.Fatalf("read compiled %s: %v", role, readErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("compiled %s does not close over the exact candidate body", role)
		}
		if len(bytes.TrimSpace(got)) == 0 || !bytes.Contains(got, []byte(`"`)) {
			t.Fatalf("compiled %s is not a JSON/JSONL candidate body", role)
		}
	}
	if result.SourceReceipt.AuthoritySelected || result.SourceReceipt.AdmissionAuthorized || result.SourceReceipt.FactoryComplete {
		t.Fatal("test-only source package promoted a candidate")
	}
}

func TestCloudCandidateScaffoldRefusesMissingOrMismatchedBodies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(CloudSourceCandidateBundle) CloudSourceCandidateBundle
		want   string
	}{
		{
			name: "missing generated role", want: "unknown generated role",
			mutate: func(bundle CloudSourceCandidateBundle) CloudSourceCandidateBundle {
				delete(bundle.Documents, sourcePackageOutputRoleARCReferenceBlueprint)
				return bundle
			},
		},
		{
			name: "mismatched generated body", want: "does not bind candidate bytes",
			mutate: func(bundle CloudSourceCandidateBundle) CloudSourceCandidateBundle {
				bundle.Documents[sourcePackageOutputRoleSourceMapping] = []byte("{\"candidate_only\":true,\"candidate_kind\":\"mismatch\"}\n")
				return bundle
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newSourcePackageCompilerTestFixture(t, "cloud_candidate_refusal")
			sealed := testCloudCandidateBundle(t, fixture.manifestPath)
			sealCloudCandidateBundleIntoTestScaffold(t, fixture.manifestPath, sealed)
			_, err := CompileCloudSourceCandidateWithScaffold(tc.mutate(sealed), fixture.manifestPath, fixture.outputRoot)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("scaffold refusal = %v, want %q", err, tc.want)
			}
			if _, statErr := os.Stat(fixture.outputRoot); !os.IsNotExist(statErr) {
				t.Fatalf("refused scaffold published output: %v", statErr)
			}
		})
	}
}

func TestCloudCandidateScaffoldRefusesUnprovenNonNativeGraphBodies(t *testing.T) {
	fixture := newSourcePackageCompilerTestFixture(t, "cloud_unproven_candidate")
	bundle := testCloudCandidateBundle(t, fixture.manifestPath)
	// A body-bearing catalog-shaped row is not a nativeGraphPlanJSONL and has
	// neither sealed classification nor typed predecessor derivations.  Keep
	// the failure explicit instead of treating five named files as a proof.
	bundle.Documents[sourcePackageOutputRoleAPIGraphArtifact] = []byte("{\"candidate_only\":true,\"catalogs\":[],\"package_kind\":\"api_graph_artifact\",\"package_version\":\"1\"}\n")
	sealCloudCandidateBundleIntoTestScaffold(t, fixture.manifestPath, bundle)
	_, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err == nil || !strings.Contains(err.Error(), "no exact row_kind") {
		t.Fatalf("unproven native graph candidate failure = %v, want native-plan refusal", err)
	}
}

func TestCloudFourPinnedModelsBuildCandidateOnlyBundleBeforeNativePlanProof(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatalf("load four pinned cloud models: %v", err)
	}
	bundle, err := BuildCloudSourceCandidateBundle(request)
	if err != nil {
		t.Fatalf("build four pinned cloud candidates: %v", err)
	}
	if len(bundle.Documents) != len(sourcePackageOutputRoleContracts) || bundle.Status != cloudSourceCandidateStatus {
		t.Fatalf("four-model candidate bundle = status %q, documents %d", bundle.Status, len(bundle.Documents))
	}
	// This remains explicitly below native graph-plan/Verify proof. The API
	// graph document can only become nativeGraphPlanJSONL with caller-supplied
	// sealed classification, typed predecessors, and manifest commitments.
	if _, err := BuildCloudNativeGraphCandidateJSONL(CloudNativeGraphContext{}, nil); err == nil || !strings.Contains(err.Error(), "requires one provider") {
		t.Fatalf("native graph builder accepted catalog-free context: %v", err)
	}
}

func TestCloudFourPinnedModelsRefuseNativePlanWithoutSealedContext(t *testing.T) {
	models := loadPinnedCloudModelsForCompilerProof(t)
	byProvider := map[string][]PinnedCloudModel{}
	for _, model := range models {
		byProvider[model.ProviderID] = append(byProvider[model.ProviderID], model)
	}
	for _, provider := range []string{"aws", "gcp"} {
		t.Run(provider, func(t *testing.T) {
			_, err := BuildCloudNativeGraphCandidateJSONL(CloudNativeGraphContext{Provider: provider}, byProvider[provider])
			if err == nil || !strings.Contains(err.Error(), "native graph context") {
				t.Fatalf("unsealed %s native plan = %v, want sealed-context refusal", provider, err)
			}
		})
	}
}

func loadPinnedCloudModelsForCompilerProof(t *testing.T) []PinnedCloudModel {
	t.Helper()
	const inputPath = "../../testdata/cloudapi/candidate-input.json"
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input CloudSourceCandidateInput
	if err := strictUnmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	base := filepath.Dir(inputPath)
	models := make([]PinnedCloudModel, len(input.Models))
	for index, item := range input.Models {
		item.Raw, err = os.ReadFile(filepath.Join(base, filepath.FromSlash(item.ModelPath)))
		if err != nil {
			t.Fatalf("read model %d: %v", index, err)
		}
		for evidenceIndex, evidencePath := range item.SupplementalEvidencePaths {
			item.SupplementalEvidence[evidenceIndex].Raw, err = os.ReadFile(filepath.Join(base, filepath.FromSlash(evidencePath)))
			if err != nil {
				t.Fatalf("read model %d supplemental evidence %d: %v", index, evidenceIndex, err)
			}
		}
		models[index] = item.PinnedCloudModel
	}
	return models
}

// testCloudCandidateBundle is intentionally not an authority fixture. It
// reuses real schema-valid candidate body shapes from the test scaffold, so
// this test proves exact body closure rather than merely comparing filenames.
func testCloudCandidateBundle(t *testing.T, manifestPath string) CloudSourceCandidateBundle {
	t.Helper()
	prepared, err := prepareDocumentationFactorySourceCompilation(manifestPath)
	if err != nil {
		t.Fatalf("prepare schema-valid test candidate bodies: %v", err)
	}
	documents := make(map[string][]byte, len(sourcePackageOutputRoleContracts))
	for _, generated := range prepared.manifest.GeneratedDocuments {
		raw := bytes.Clone(prepared.materials[generated.coordinate()].raw)
		// Each fixture body's existing structured content is retained without
		// constructing a new domain body outside the source-package contract.
		documents[generated.PackageRole] = raw
	}
	return CloudSourceCandidateBundle{Status: cloudSourceCandidateStatus, Version: cloudSourcePackageVersion, Documents: documents}
}

// sealCloudCandidateBundleIntoTestScaffold rewrites a test fixture's payload
// and template pins.  It also refreshes every affected validation-profile
// digest, so the real factory stages—not a mock—consume the exact candidates.
func sealCloudCandidateBundleIntoTestScaffold(t *testing.T, manifestPath string, bundle CloudSourceCandidateBundle) {
	t.Helper()
	manifest := readSourcePackageCompilerTestManifest(t, manifestPath)
	base := filepath.Dir(manifestPath)
	resources := make(map[sourcePackageCoordinate]*sourcePackageResourceDeclaration, len(manifest.Resources))
	for index := range manifest.Resources {
		resources[manifest.Resources[index].coordinate()] = &manifest.Resources[index]
	}
	writeResource := func(coordinate sourcePackageCoordinate, raw []byte) {
		declaration := resources[coordinate]
		if declaration == nil {
			t.Fatalf("test scaffold lacks resource %s", sourcePackageCoordinateLabel(coordinate))
		}
		if err := os.WriteFile(filepath.Join(base, filepath.FromSlash(declaration.Path)), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		declaration.ExpectedRawSHA256 = sha256Hex(raw)
		declaration.ExpectedByteCount = uint64(len(raw))
	}
	for index := range manifest.GeneratedDocuments {
		generated := &manifest.GeneratedDocuments[index]
		body, ok := bundle.Documents[generated.PackageRole]
		if !ok {
			t.Fatalf("test bundle lacks generated role %q", generated.PackageRole)
		}
		payload := cloudScaffoldPayloadCoordinate(t, base, resources, generated.Template)
		output, payloadRaw, templateRaw := sourcePackageCompilerProjectionTemplate(t, generated.PackageRole, payload, body)
		if !bytes.Equal(output, body) {
			t.Fatalf("test scaffold template changed %s candidate bytes", generated.PackageRole)
		}
		writeResource(payload, payloadRaw)
		writeResource(generated.Template, templateRaw)
		generated.ExpectedRawSHA256 = sha256Hex(body)
		generated.ExpectedByteCount = uint64(len(body))
	}

	// Profile pins are source-package resources too.  Update only artifact
	// hashes for generated coordinates; schema pins remain their fixture-local
	// canonical assertions and catch a body/profile mismatch in the real runner.
	generatedByCoordinate := map[sourcePackageCoordinate][]byte{}
	for _, generated := range manifest.GeneratedDocuments {
		generatedByCoordinate[generated.coordinate()] = bundle.Documents[generated.PackageRole]
	}
	for _, plan := range []sourcePackageStageValidationPlan{
		manifest.FactoryPlan.EvidenceIntake.StageValidation,
		manifest.FactoryPlan.SemanticExtraction.StageValidation,
		manifest.FactoryPlan.GraphCompile.StageValidation,
		manifest.FactoryPlan.FullFactory.StageValidation,
	} {
		profile := resources[plan.Profile.Resource]
		if profile == nil {
			t.Fatalf("test scaffold lacks validation profile %s", sourcePackageCoordinateLabel(plan.Profile.Resource))
		}
		raw, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(profile.Path)))
		if err != nil {
			t.Fatal(err)
		}
		var value stageValidationProfileDocument
		if err := strictUnmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		changed := false
		for index := range value.BoundArtifactSchemas {
			binding := &value.BoundArtifactSchemas[index]
			coordinate := sourcePackageCoordinate{Role: binding.Role, ID: binding.ArtifactID, Version: binding.ArtifactVersion}
			if body, found := generatedByCoordinate[coordinate]; found {
				binding.ArtifactRawSHA256 = sha256Hex(body)
				changed = true
			}
		}
		if changed {
			writeResource(plan.Profile.Resource, mustStageJSON(t, value))
		}
	}
	writeSourcePackageCompilerTestManifest(t, manifestPath, manifest)
}

func cloudScaffoldPayloadCoordinate(t *testing.T, base string, resources map[sourcePackageCoordinate]*sourcePackageResourceDeclaration, template sourcePackageCoordinate) sourcePackageCoordinate {
	t.Helper()
	declaration := resources[template]
	if declaration == nil {
		t.Fatalf("test scaffold lacks template %s", sourcePackageCoordinateLabel(template))
	}
	raw, err := os.ReadFile(filepath.Join(base, filepath.FromSlash(declaration.Path)))
	if err != nil {
		t.Fatal(err)
	}
	var document sourcePackageTemplateDocument
	if err := strictUnmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	projections := append([]json.RawMessage(nil), document.Rows...)
	if len(document.Document) != 0 && string(document.Document) != "null" {
		projections = append([]json.RawMessage{document.Document}, projections...)
	}
	if len(projections) == 0 {
		t.Fatalf("test scaffold template %s has no projections", sourcePackageCoordinateLabel(template))
	}
	var projection struct {
		Projection struct {
			Resource    sourcePackageCoordinate `json:"resource"`
			Kind        string                  `json:"projection"`
			JSONPointer string                  `json:"json_pointer"`
		} `json:"$resource_projection"`
	}
	if err := strictUnmarshal(projections[0], &projection); err != nil {
		t.Fatal(err)
	}
	for _, rawProjection := range projections[1:] {
		var next struct {
			Projection struct {
				Resource    sourcePackageCoordinate `json:"resource"`
				Kind        string                  `json:"projection"`
				JSONPointer string                  `json:"json_pointer"`
			} `json:"$resource_projection"`
		}
		if err := strictUnmarshal(rawProjection, &next); err != nil {
			t.Fatal(err)
		}
		if next.Projection.Resource != projection.Projection.Resource {
			t.Fatalf("test scaffold template %s projects multiple payloads", sourcePackageCoordinateLabel(template))
		}
	}
	if resources[projection.Projection.Resource] == nil {
		t.Fatalf("test scaffold template %s projects undeclared resource %s", sourcePackageCoordinateLabel(template), sourcePackageCoordinateLabel(projection.Projection.Resource))
	}
	return projection.Projection.Resource
}
