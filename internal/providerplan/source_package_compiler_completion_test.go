package providerplan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourcePackageCompilerShapeRejectsClosedSetViolations(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "completion")
	base := readSourcePackageCompilerTestManifest(t, fixture.manifestPath)
	clone := func(t *testing.T) documentationFactorySourcePackage {
		t.Helper()
		raw, err := canonicalFactoryJSON(base)
		if err != nil {
			t.Fatal(err)
		}
		var copied documentationFactorySourcePackage
		if err := strictUnmarshal(raw, &copied); err != nil {
			t.Fatal(err)
		}
		return copied
	}
	tests := []struct {
		name    string
		mutate  func(*documentationFactorySourcePackage)
		message string
	}{
		{"identity", func(m *documentationFactorySourcePackage) { m.PackageVersion = "2" }, "identity"},
		{"missing roster", func(m *documentationFactorySourcePackage) { m.Resources = nil }, "requires resources"},
		{"padded resource path", func(m *documentationFactorySourcePackage) { m.Resources[0].Path = " source.json" }, "non-relative"},
		{"duplicate resource source path", func(m *documentationFactorySourcePackage) { m.Resources[1].Path = m.Resources[0].Path }, "source path"},
		{"reserved resource bundle", func(m *documentationFactorySourcePackage) {
			m.Resources[0].BundlePath = sourcePackageFactoryReceiptPath
		}, "reserved bundle"},
		{"invalid resource pin", func(m *documentationFactorySourcePackage) { m.Resources[0].ExpectedRawSHA256 = "bad" }, "invalid raw digest"},
		{"padded resource authority", func(m *documentationFactorySourcePackage) { m.Resources[0].ExpectedAuthorityClass = " canonical" }, "expected_authority_class"},
		{"resource bundle dot component", func(m *documentationFactorySourcePackage) { m.Resources[0].BundlePath = ".private/resource.json" }, "dot-prefixed"},
		{"unordered resources", func(m *documentationFactorySourcePackage) {
			m.Resources[0], m.Resources[1] = m.Resources[1], m.Resources[0]
		}, "strictly ordered"},
		{"generated coordinate overlaps resource", func(m *documentationFactorySourcePackage) {
			m.GeneratedDocuments[0].Role, m.GeneratedDocuments[0].ID, m.GeneratedDocuments[0].Version = m.Resources[0].Role, m.Resources[0].ID, m.Resources[0].Version
		}, "duplicates resources"},
		{"generated bundle overlaps resource", func(m *documentationFactorySourcePackage) {
			m.GeneratedDocuments[0].BundlePath = m.Resources[0].BundlePath
		}, "bundle path"},
		{"generated invalid pin", func(m *documentationFactorySourcePackage) { m.GeneratedDocuments[0].ExpectedByteCount = 0 }, "invalid raw digest"},
		{"unknown package role", func(m *documentationFactorySourcePackage) { m.GeneratedDocuments[0].PackageRole = "invented" }, "unregistered package_role"},
		{"duplicate package role", func(m *documentationFactorySourcePackage) {
			m.GeneratedDocuments[1].PackageRole = m.GeneratedDocuments[0].PackageRole
		}, "duplicates package_role"},
		{"missing candidate marker", func(m *documentationFactorySourcePackage) { m.GeneratedDocuments[0].CandidateOnly = false }, "candidate/body-free"},
		{"artifact contract mismatch", func(m *documentationFactorySourcePackage) { m.GeneratedDocuments[0].Role = "wrong" }, "outside its local contract"},
		{"reserved generated bundle", func(m *documentationFactorySourcePackage) {
			m.GeneratedDocuments[0].BundlePath = sourcePackageCompileReceiptPath
		}, "reserved bundle"},
		{"invalid evidence carrier", func(m *documentationFactorySourcePackage) { m.EvidenceBodies[0].CarrierEncoding = "hex" }, "unsupported carrier_encoding"},
		{"invalid evidence pin", func(m *documentationFactorySourcePackage) { m.EvidenceBodies[0].ExpectedBodySHA256 = "bad" }, "invalid body digest"},
		{"unordered evidence", func(m *documentationFactorySourcePackage) {
			m.EvidenceBodies = append(m.EvidenceBodies, m.EvidenceBodies[0])
		}, "strictly ordered"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			manifest := clone(t)
			tc.mutate(&manifest)
			if err := validateDocumentationFactorySourcePackageShape(manifest); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("shape error = %v, want %q", err, tc.message)
			}
		})
	}
}

func TestSourcePackageCompilerCompletionPublicEntryPointSealsCandidateOnlyOutput(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "public-entry")
	options := DocumentationFactorySourceCompileOptions{
		SourcePackagePath: fixture.manifestPath,
		OutputRoot:        fixture.outputRoot,
	}
	if _, err := CompileDocumentationFactorySourcePackage(options); err == nil || !strings.Contains(err.Error(), "build identity") {
		t.Fatalf("public compiler did not fail closed on incomplete build identity: %v", err)
	}
	result, err := compileDocumentationFactorySourcePackageWithDependencies(options, sourcePackageCompilerTestDependencies(t))
	if err != nil {
		t.Fatal(err)
	}
	if result.SourceReceipt.ReceiptKind != documentationFactorySourceReceiptKind || !result.SourceReceipt.BodyFree || result.SourceReceipt.AdmissionAuthorized || result.SourceReceipt.AuthoritySelected {
		t.Fatalf("candidate-only source receipt = %#v", result.SourceReceipt)
	}
	if len(result.SourceReceipt.BundleFiles) == 0 || result.FactoryReceipt.PreflightReceipt.Provider == "" {
		t.Fatalf("sealed compiler result has no bundle or provider receipt: %#v", result)
	}
}

func TestSourcePackageCompilerCompletionPreparationRefusesDetachedInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(*testing.T, sourcePackageCompilerTestFixture, *documentationFactorySourcePackage)
		message string
	}{
		{
			name: "missing resource", message: "resources[0].path",
			mutate: func(_ *testing.T, _ sourcePackageCompilerTestFixture, manifest *documentationFactorySourcePackage) {
				manifest.Resources[0].Path = "source/absent.bin"
			},
		},
		{
			name: "resource digest mismatch", message: "exact source-package pin",
			mutate: func(_ *testing.T, fixture sourcePackageCompilerTestFixture, manifest *documentationFactorySourcePackage) {
				if err := os.WriteFile(filepath.Join(filepath.Dir(fixture.manifestPath), filepath.FromSlash(manifest.Resources[0].Path)), []byte("tampered resource"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "absent generated template", message: "template",
			mutate: func(_ *testing.T, _ sourcePackageCompilerTestFixture, manifest *documentationFactorySourcePackage) {
				manifest.GeneratedDocuments[0].Template = sourcePackageCoordinate{Role: "missing", ID: "template", Version: "1"}
			},
		},
		{
			name: "generated digest mismatch", message: "generated document",
			mutate: func(_ *testing.T, _ sourcePackageCompilerTestFixture, manifest *documentationFactorySourcePackage) {
				manifest.GeneratedDocuments[0].ExpectedRawSHA256 = strings.Repeat("0", 64)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSourcePackageCompilerTestFixture(t, "prepare-"+strings.ReplaceAll(tc.name, " ", "-"))
			manifest := readSourcePackageCompilerTestManifest(t, fixture.manifestPath)
			tc.mutate(t, fixture, &manifest)
			writeSourcePackageCompilerTestManifest(t, fixture.manifestPath, manifest)
			if _, err := prepareDocumentationFactorySourceCompilation(fixture.manifestPath); err == nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("preparation error=%v, want %q", err, tc.message)
			}
		})
	}
}

func TestSourcePackageCompilerCompletionRevalidationRefusesMissingOrChangedAdmission(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "revalidate")
	compilation, err := prepareDocumentationFactorySourceCompilation(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	missing := compilation
	missing.inputAccumulator = nil
	if err := revalidateDocumentationFactorySourceInputs(&missing); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("missing accumulator error=%v", err)
	}
	changedProof := compilation
	changedProof.inputProof.ProofSHA256 = strings.Repeat("0", 64)
	if err := revalidateDocumentationFactorySourceInputs(&changedProof); err == nil || !strings.Contains(err.Error(), "proof changed") {
		t.Fatalf("changed proof error=%v", err)
	}
	changedRoster := compilation
	changedRoster.inputResources = nil
	if err := revalidateDocumentationFactorySourceInputs(&changedRoster); err == nil || !strings.Contains(err.Error(), "roster changed") {
		t.Fatalf("changed roster error=%v", err)
	}
}

func TestSourcePackageCompilerCompletionDoesNotPublishAfterVerificationFailures(t *testing.T) {
	t.Parallel()
	newCompilation := func(t *testing.T) (sourcePackageCompilation, sourcePackageCompilerTestFixture) {
		t.Helper()
		fixture := newSourcePackageCompilerTestFixture(t, "prepared-failure")
		compilation, err := prepareDocumentationFactorySourceCompilation(fixture.manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		return compilation, fixture
	}
	tests := []struct {
		name   string
		mutate func(*documentationFactorySourceCompilerDependencies)
	}{
		{"workspace", func(d *documentationFactorySourceCompilerDependencies) {
			d.WithWorkspace = func([]factorySourceOutputFile, func(string) error) error { return errors.New("workspace denied") }
		}},
		{"receipt", func(d *documentationFactorySourceCompilerDependencies) {
			d.RunFactory = func(FactoryRunOptions) (FactoryRunReceipt, error) { return FactoryRunReceipt{}, nil }
		}},
		{"publish", func(d *documentationFactorySourceCompilerDependencies) {
			d.Publish = func(string, []factorySourceOutputFile) error { return errors.New("publish denied") }
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			compilation, fixture := newCompilation(t)
			dependencies := sourcePackageCompilerTestDependencies(t)
			tc.mutate(&dependencies)
			_, err := compilePreparedDocumentationFactorySourcePackage(DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot}, compilation, dependencies, nil, nil)
			if err == nil {
				t.Fatal("compiler accepted a failed dependency path")
			}
		})
	}
}

func TestSourcePackageCompilerCompletionFactoryPlanRefusesDetachedStages(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "plan-boundaries")
	compilation, err := prepareDocumentationFactorySourceCompilation(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	clonePlan := func(t *testing.T) sourcePackageFactoryPlan {
		t.Helper()
		raw, marshalErr := canonicalFactoryJSON(compilation.manifest.FactoryPlan)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		var plan sourcePackageFactoryPlan
		if unmarshalErr := strictUnmarshal(raw, &plan); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		return plan
	}
	tests := []struct {
		name   string
		mutate func(*sourcePackageFactoryPlan)
	}{
		{"missing evidence schema", func(p *sourcePackageFactoryPlan) {
			p.EvidenceIntake.StageValidation.Schema.Resource = sourcePackageCoordinate{Role: "missing", ID: "schema", Version: "1"}
		}},
		{"missing authority pin", func(p *sourcePackageFactoryPlan) {
			p.EvidenceIntake.AuthorityPins.OODGraph.Resource = sourcePackageCoordinate{Role: "missing", ID: "ood", Version: "1"}
		}},
		{"no evidence manifests", func(p *sourcePackageFactoryPlan) { p.EvidenceIntake.EvidenceManifests = nil }},
		{"no semantic outputs", func(p *sourcePackageFactoryPlan) { p.SemanticExtraction.ArtifactOutputs = nil }},
		{"missing graph plan", func(p *sourcePackageFactoryPlan) {
			p.GraphCompile.Plan = sourcePackageCoordinate{Role: "missing", ID: "plan", Version: "1"}
		}},
		{"missing full validation", func(p *sourcePackageFactoryPlan) {
			p.FullFactory.StageValidation.Schema.Resource = sourcePackageCoordinate{Role: "missing", ID: "schema", Version: "1"}
		}},
		{"missing preflight dependency", func(p *sourcePackageFactoryPlan) {
			p.PreflightDependencies = append(p.PreflightDependencies, sourcePackageCoordinate{Role: "missing", ID: "dependency", Version: "1"})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan := clonePlan(t)
			tc.mutate(&plan)
			if _, _, _, err := buildSourcePackageFactoryRequests(plan, compilation.materials, compilation.evidenceBodies, map[sourcePackageCoordinate]struct{}{}); err == nil {
				t.Fatal("detached factory plan was accepted")
			}
		})
	}
}

func TestSourcePackageCompilerCompletionReceiptRejectsCandidateBoundaryTampering(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "receipt-boundaries")
	result, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot}, sourcePackageCompilerTestDependencies(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*DocumentationFactorySourceCompileReceipt)
	}{
		{"identity posture", func(r *DocumentationFactorySourceCompileReceipt) { r.BodyFree = false }},
		{"digest", func(r *DocumentationFactorySourceCompileReceipt) { r.SourcePackageSHA256 = "bad" }},
		{"completion", func(r *DocumentationFactorySourceCompileReceipt) { r.Completion.Deployed = true }},
		{"empty outputs", func(r *DocumentationFactorySourceCompileReceipt) { r.GeneratedOutputs = nil }},
		{"output candidate flag", func(r *DocumentationFactorySourceCompileReceipt) { r.GeneratedOutputs[0].CandidateOnly = false }},
		{"bundle self reference", func(r *DocumentationFactorySourceCompileReceipt) {
			r.BundleFiles[0].RelativePath = sourcePackageCompileReceiptPath
		}},
		{"bundle missing factory", func(r *DocumentationFactorySourceCompileReceipt) {
			for index := range r.BundleFiles {
				if r.BundleFiles[index].RelativePath == sourcePackageFactoryReceiptPath {
					r.BundleFiles[index].RawSHA256 = strings.Repeat("0", 64)
				}
			}
		}},
		{"receipt digest", func(r *DocumentationFactorySourceCompileReceipt) { r.ReceiptSHA256 = strings.Repeat("0", 64) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receipt := result.SourceReceipt
			receipt.GeneratedOutputs = append([]DocumentationFactorySourceOutputReceipt(nil), receipt.GeneratedOutputs...)
			receipt.BundleFiles = append([]documentationFactorySourceBundleFileReceipt(nil), receipt.BundleFiles...)
			tc.mutate(&receipt)
			if err := validateDocumentationFactorySourceReceipt(receipt); err == nil {
				t.Fatal("tampered receipt was accepted")
			}
		})
	}
}

func TestSourcePackageCompilerTemplateAndEvidenceBoundaries(t *testing.T) {
	coordinate := sourcePackageCoordinate{Role: "payload", ID: "completion", Version: "1"}
	material := sourcePackageMaterial{coordinate: coordinate, raw: []byte(`{"items":[{"name":"one"}],"scalar":true}`)}
	materials := map[sourcePackageCoordinate]sourcePackageMaterial{coordinate: material}
	projection := func(kind, pointer string) map[string]interface{} {
		return map[string]interface{}{"$resource_projection": map[string]interface{}{"resource": coordinate, "projection": kind, "json_pointer": pointer}}
	}
	jsonTemplate := sourcePackageTemplateDocument{
		TemplateKind: documentationFactoryTemplateKind, TemplateVersion: documentationFactoryTemplateVersion,
		OutputFormat: sourcePackageTemplateFormatJSON, Document: mustCanonicalSourcePackageTestJSON(t, map[string]interface{}{"digest": projection(sourcePackageProjectionSHA256, ""), "item": projection(sourcePackageProjectionJSONValue, "/items/0/name")}),
	}
	raw, err := canonicalFactoryJSON(jsonTemplate)
	if err != nil {
		t.Fatal(err)
	}
	used := map[sourcePackageCoordinate]struct{}{}
	rendered, err := renderSourcePackageTemplate(raw, materials, used)
	if err != nil || !bytes.Contains(rendered, []byte(`"item":"one"`)) {
		t.Fatalf("JSON template rendered=%q err=%v", rendered, err)
	}
	if _, ok := used[coordinate]; !ok {
		t.Fatal("projection did not mark its material used")
	}

	jsonlTemplate := sourcePackageTemplateDocument{
		TemplateKind: documentationFactoryTemplateKind, TemplateVersion: documentationFactoryTemplateVersion,
		OutputFormat: sourcePackageTemplateFormatJSONL, Rows: []json.RawMessage{mustCanonicalSourcePackageTestJSONValue(t, projection(sourcePackageProjectionByteCount, "")), mustCanonicalSourcePackageTestJSONValue(t, projection(sourcePackageProjectionJSONValue, "/scalar"))},
	}
	raw, err = canonicalFactoryJSON(jsonlTemplate)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err = renderSourcePackageTemplate(raw, materials, map[sourcePackageCoordinate]struct{}{})
	if err != nil || !strings.HasSuffix(string(rendered), "true\n") {
		t.Fatalf("JSONL template rendered=%q err=%v", rendered, err)
	}

	for _, raw := range [][]byte{
		[]byte(`{"template_kind":"wrong","template_version":"1","output_format":"canonical_json","document":{}}`),
		[]byte(`{"template_kind":"provider_documentation_factory_candidate_template","template_version":"1","output_format":"canonical_json","rows":[{}]}`),
		[]byte(`{"template_kind":"provider_documentation_factory_candidate_template","template_version":"1","output_format":"unknown","document":{}}`),
	} {
		if _, err := renderSourcePackageTemplate(raw, materials, map[sourcePackageCoordinate]struct{}{}); err == nil {
			t.Fatalf("invalid template accepted: %s", raw)
		}
	}
	for _, value := range []interface{}{
		map[string]interface{}{"$resource_projection": projection(sourcePackageProjectionSHA256, ""), "extra": true},
		projection(sourcePackageProjectionSHA256, "/forbidden"),
		projection(sourcePackageProjectionByteCount, "/forbidden"),
		projection("unsupported", ""),
		map[string]interface{}{"$resource_projection": map[string]interface{}{"resource": sourcePackageCoordinate{Role: "missing", ID: "id", Version: "1"}, "projection": sourcePackageProjectionJSONValue, "json_pointer": ""}},
	} {
		if _, err := resolveSourcePackageTemplateValue(value, materials, map[sourcePackageCoordinate]struct{}{}, 0); err == nil {
			t.Fatalf("invalid template projection accepted: %#v", value)
		}
	}
	if _, err := resolveSourcePackageTemplateValue(map[string]interface{}{"$resource_projection": map[string]interface{}{"resource": coordinate, "projection": sourcePackageProjectionJSONValue, "json_pointer": "/scalar/member"}}, materials, map[sourcePackageCoordinate]struct{}{}, 0); err == nil || !strings.Contains(err.Error(), "scalar") {
		t.Fatalf("scalar traversal error=%v", err)
	}
	for _, raw := range [][]byte{[]byte(`{"same":1,"same":2}`), []byte(`{`)} {
		if _, err := decodeSourcePackageTemplateValue(raw); err == nil {
			t.Fatalf("invalid template value accepted: %s", raw)
		}
	}
	for _, pointer := range []string{"/items/9", "/missing"} {
		if _, err := resolveSourcePackageJSONPointer(map[string]interface{}{"items": []interface{}{"one"}}, pointer); err == nil {
			t.Fatalf("unresolvable pointer %q accepted", pointer)
		}
	}

	body := []byte("sealed completion body")
	manifest := sourcePackageCoordinate{Role: "manifest", ID: "completion", Version: "1"}
	carrier := sourcePackageCoordinate{Role: "carrier", ID: "completion", Version: "1"}
	evidenceMaterials := map[sourcePackageCoordinate]sourcePackageMaterial{
		manifest: {coordinate: manifest, raw: []byte(`{"manifest":true}`)},
		carrier:  {coordinate: carrier, raw: []byte(base64.StdEncoding.EncodeToString(body))},
	}
	declaration := sourcePackageEvidenceBodyDeclaration{Manifest: manifest, ComponentOrdinal: 7, Carrier: carrier, CarrierEncoding: sourcePackageCarrierBase64, ExpectedBodySHA256: sha256Hex(body), ExpectedBodyByteCount: uint64(len(body))}
	bodies, err := decodeSourcePackageEvidenceBodies([]sourcePackageEvidenceBodyDeclaration{declaration}, evidenceMaterials, map[sourcePackageCoordinate]struct{}{})
	if err != nil || len(bodies) != 1 || !bytes.Equal(bodies[0].Raw, body) {
		t.Fatalf("base64 evidence decode=%v err=%v", bodies, err)
	}
	declaration.CarrierEncoding = sourcePackageCarrierRaw
	evidenceMaterials[carrier] = sourcePackageMaterial{coordinate: carrier, raw: body}
	bodies, err = decodeSourcePackageEvidenceBodies([]sourcePackageEvidenceBodyDeclaration{declaration}, evidenceMaterials, map[sourcePackageCoordinate]struct{}{})
	if err != nil || len(bodies) != 1 {
		t.Fatalf("raw evidence decode err=%v", err)
	}
	if err := validateSourcePackageOutputBodyFree([]StageEvidenceBody{{Raw: body}}, "candidate.json", mustCanonicalSourcePackageTestJSON(t, map[string]interface{}{"body": string(body)})); err == nil || !strings.Contains(err.Error(), "not body-free") {
		t.Fatalf("embedded body error=%v", err)
	}
	declaration.ExpectedBodyByteCount++
	if _, err := decodeSourcePackageEvidenceBodies([]sourcePackageEvidenceBodyDeclaration{declaration}, evidenceMaterials, map[sourcePackageCoordinate]struct{}{}); err == nil || !strings.Contains(err.Error(), "exact pin") {
		t.Fatalf("mutated evidence pin error=%v", err)
	}
	if _, err := decodeSourcePackageEvidenceBodies([]sourcePackageEvidenceBodyDeclaration{{Manifest: manifest, Carrier: sourcePackageCoordinate{Role: "absent", ID: "carrier", Version: "1"}}}, evidenceMaterials, map[sourcePackageCoordinate]struct{}{}); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("missing evidence carrier error=%v", err)
	}
	evidenceMaterials[carrier] = sourcePackageMaterial{coordinate: carrier, raw: []byte("not base64")}
	declaration.ExpectedBodyByteCount--
	declaration.CarrierEncoding = sourcePackageCarrierBase64
	if _, err := decodeSourcePackageEvidenceBodies([]sourcePackageEvidenceBodyDeclaration{declaration}, evidenceMaterials, map[sourcePackageCoordinate]struct{}{}); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("invalid base64 carrier error=%v", err)
	}
}

func TestSourcePackageCompilerHelpersFailClosed(t *testing.T) {
	coordinate := sourcePackageCoordinate{Role: "role", ID: "id", Version: "1"}
	materials := map[sourcePackageCoordinate]sourcePackageMaterial{coordinate: {coordinate: coordinate, raw: []byte(`{"x":1}`), authorityClass: "canonical"}}
	if _, err := sourcePackagePinForReference(materials, sourcePackagePinReference{Resource: coordinate, AuthorityClass: " canonical"}, map[sourcePackageCoordinate]struct{}{}); err == nil || !strings.Contains(err.Error(), "padded") {
		t.Fatalf("padded authority class error=%v", err)
	}
	if _, err := sourcePackagePinForReference(materials, sourcePackagePinReference{Resource: coordinate, AuthorityClass: "admitted"}, map[sourcePackageCoordinate]struct{}{}); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("mismatched authority class error=%v", err)
	}
	if _, err := sourcePackageMaterialForReference(materials, sourcePackageCoordinate{Role: "missing", ID: "id", Version: "1"}, map[sourcePackageCoordinate]struct{}{}); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("missing material error=%v", err)
	}
	for _, pointer := range []string{"not-a-pointer", "/x/00", "/x/-1"} {
		if _, err := resolveSourcePackageJSONPointer(map[string]interface{}{"x": []interface{}{"one"}}, pointer); err == nil {
			t.Fatalf("invalid pointer %q accepted", pointer)
		}
	}
}

func TestSourcePackageCompilerCompletionFileAndRosterBoundaries(t *testing.T) {
	dependencies := sourcePackageCompilerTestDependencies(t)
	for _, testCase := range []struct {
		name    string
		options DocumentationFactorySourceCompileOptions
		deps    documentationFactorySourceCompilerDependencies
	}{
		{name: "nil runner", options: DocumentationFactorySourceCompileOptions{SourcePackagePath: "source.json", OutputRoot: "output"}, deps: documentationFactorySourceCompilerDependencies{}},
		{name: "padded source", options: DocumentationFactorySourceCompileOptions{SourcePackagePath: " source.json", OutputRoot: "output"}, deps: dependencies},
		{name: "padded output", options: DocumentationFactorySourceCompileOptions{SourcePackagePath: "source.json", OutputRoot: "output "}, deps: dependencies},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if err := validateDocumentationFactorySourceCompilerInputs(testCase.options, testCase.deps); err == nil {
				t.Fatal("invalid compiler inputs accepted")
			}
		})
	}

	files := map[string][]byte{"z.json": []byte("z"), "a.json": []byte("a")}
	outputs := sourcePackageOutputFiles(files)
	if len(outputs) != 2 || outputs[0].RelativePath != "a.json" || outputs[1].RelativePath != "z.json" {
		t.Fatalf("sorted output files = %#v", outputs)
	}
	outputs[0].Raw[0] = 'x'
	if string(files["a.json"]) != "a" {
		t.Fatal("output file bytes alias the input map")
	}
	if paths := sortedSourcePackageFilePaths(files); strings.Join(paths, ",") != "a.json,z.json" {
		t.Fatalf("sorted paths = %v", paths)
	}

	fileSet := map[string][]byte{}
	if err := addSourcePackageCompilationFile(fileSet, "candidate.json", []byte("candidate"), false); err != nil {
		t.Fatal(err)
	}
	if err := addSourcePackageCompilationFile(fileSet, "candidate.json", []byte("second"), false); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("duplicate file error=%v", err)
	}
	if err := addSourcePackageCompilationFile(fileSet, sourcePackageFactoryReceiptPath, []byte("receipt"), false); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved file error=%v", err)
	}
	if err := addSourcePackageCompilationFile(nil, "candidate.json", []byte("candidate"), false); err == nil || !strings.Contains(err.Error(), "nil") {
		t.Fatalf("nil file set error=%v", err)
	}

	resource := sourcePackageResourceDeclaration{Role: "role", ID: "id", Version: "1"}
	if err := requireAllSourcePackageResourcesUsed([]sourcePackageResourceDeclaration{resource}, map[sourcePackageCoordinate]struct{}{}); err == nil || !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("unused resource error=%v", err)
	}
	if err := requireAllSourcePackageResourcesUsed([]sourcePackageResourceDeclaration{resource}, map[sourcePackageCoordinate]struct{}{resource.coordinate(): {}}); err != nil {
		t.Fatalf("used resource error=%v", err)
	}
	document := sourcePackageGeneratedDocument{Role: "role", ID: "generated", Version: "1"}
	if err := requireAllSourcePackageGeneratedDocumentsUsed([]sourcePackageGeneratedDocument{document}, map[sourcePackageCoordinate]struct{}{}); err == nil || !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("unused document error=%v", err)
	}
	if err := requireAllSourcePackageGeneratedDocumentsUsed([]sourcePackageGeneratedDocument{document}, map[sourcePackageCoordinate]struct{}{document.coordinate(): {}}); err != nil {
		t.Fatalf("used document error=%v", err)
	}

	bodies := []StageEvidenceBody{{ManifestRole: "manifest", ManifestID: "id", ManifestVersion: "1", ComponentOrdinal: 2, Raw: []byte("body")}}
	cloned := cloneSourcePackageEvidenceBodies(bodies)
	cloned[0].Raw[0] = 'B'
	if string(bodies[0].Raw) != "body" {
		t.Fatal("evidence body clone aliases original bytes")
	}
	if got := stageRefFromSummary(StageReceiptSummary{StageKind: "stage", ReceiptSHA256: strings.Repeat("a", 64), OutputRootSHA256: strings.Repeat("b", 64)}); got.StageKind != "stage" || got.ReceiptSHA256 == "" || got.OutputRootSHA256 == "" {
		t.Fatalf("stage reference = %#v", got)
	}
}
