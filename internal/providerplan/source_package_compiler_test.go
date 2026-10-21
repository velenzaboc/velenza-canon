package providerplan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type sourcePackageCompilerTestFixture struct {
	manifestPath string
	outputRoot   string
}

type sourcePackageCompilerTestResource struct {
	declaration sourcePackageResourceDeclaration
	raw         []byte
}

func TestDocumentationFactorySourceCompilerRunsClosedSourcePackageThroughIdenticalFactory(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	result, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFactoryRunReceipt(result.FactoryReceipt); err != nil {
		t.Fatalf("nested factory receipt: %v", err)
	}
	if err := validateDocumentationFactorySourceReceipt(result.SourceReceipt); err != nil {
		t.Fatalf("source compiler receipt: %v", err)
	}
	if len(result.SourceReceipt.GeneratedOutputs) != len(sourcePackageOutputRoleContracts) {
		t.Fatalf("generated output count = %d, want %d", len(result.SourceReceipt.GeneratedOutputs), len(sourcePackageOutputRoleContracts))
	}
	for _, relative := range []string{
		sourcePackageManifestBundlePath,
		sourcePackageFactoryReceiptPath,
		sourcePackageCompileReceiptPath,
		"factory-evidence-intake.request.json",
		"factory-semantic-extraction.request.json",
		"factory-graph-compile.request.json",
		"factory-full-factory.request.json",
	} {
		if _, err := os.Stat(filepath.Join(fixture.outputRoot, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("published output %q: %v", relative, err)
		}
	}
	if result.SourceReceipt.AuthoritySelected || result.SourceReceipt.AdmissionAuthorized || result.SourceReceipt.FactoryComplete {
		t.Fatal("source compiler promoted a candidate-only output")
	}
}

func TestDocumentationFactorySourceCompilerDefersARCSourceInvarianceToOwnerChecker(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	_, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, relative := range []string{sourcePackageManifestBundlePath, sourcePackageCompileReceiptPath} {
		raw, readErr := os.ReadFile(filepath.Join(fixture.outputRoot, filepath.FromSlash(relative)))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Contains(raw, []byte(`"source_neutral"`)) {
			t.Fatalf("%s contains an authored source-neutral self-assertion", relative)
		}

		var envelope map[string]interface{}
		if unmarshalErr := json.Unmarshal(raw, &envelope); unmarshalErr != nil {
			t.Fatal(unmarshalErr)
		}
		rosterKey := "generated_documents"
		if relative == sourcePackageCompileReceiptPath {
			rosterKey = "generated_outputs"
		}
		roster, ok := envelope[rosterKey].([]interface{})
		if !ok {
			t.Fatalf("%s lacks %s", relative, rosterKey)
		}
		arcFound := false
		for _, rawItem := range roster {
			item, ok := rawItem.(map[string]interface{})
			if !ok {
				t.Fatalf("%s contains a non-object %s member", relative, rosterKey)
			}
			if item["package_role"] != sourcePackageOutputRoleARCReferenceBlueprint {
				if _, present := item["required_owner_validation"]; present {
					t.Fatalf("%s non-ARC output %v carries an ARC owner gate", relative, item["package_role"])
				}
				continue
			}
			arcFound = true
			ownerValidation, ok := item["required_owner_validation"].(map[string]interface{})
			if !ok {
				t.Fatalf("%s ARC output lacks required_owner_validation", relative)
			}
			if ownerValidation["status"] != "pending_content_derived_package_proof" ||
				ownerValidation["canonical_contract_ref"] != "e799e6ff-7ad0-4c3b-91cb-6c7685f0c7a1#authored_source_package_contract.arc_source_invariance.checkable_form" ||
				ownerValidation["checkable_form_owner_ref"] != "velenza-arc-app-template/contracts/repository_contract.json#source_invariance" {
				t.Fatalf("%s ARC owner-validation boundary = %#v", relative, ownerValidation)
			}
		}
		if !arcFound {
			t.Fatalf("%s lacks ARC reference blueprint output", relative)
		}
	}
}

func TestDocumentationFactorySourceCompilerRejectsAuthoredSourceNeutralAssertion(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	raw, err := os.ReadFile(fixture.manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]interface{}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	roster, ok := envelope["generated_documents"].([]interface{})
	if !ok {
		t.Fatal("fixture lacks generated_documents")
	}
	mutated := false
	for _, rawItem := range roster {
		item, ok := rawItem.(map[string]interface{})
		if ok && item["package_role"] == sourcePackageOutputRoleARCReferenceBlueprint {
			item["source_neutral"] = true
			mutated = true
		}
	}
	if !mutated {
		t.Fatal("fixture lacks ARC reference blueprint output")
	}
	raw, err = canonicalFactoryJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.manifestPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err == nil || !strings.Contains(err.Error(), `unknown field "source_neutral"`) {
		t.Fatalf("authored source-neutral assertion error = %v, want strict unknown-field refusal", err)
	}
	if _, statErr := os.Lstat(fixture.outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("authored source-neutral assertion published an output root: %v", statErr)
	}
}

func TestDocumentationFactorySourceCompilerRejectsExistingOutputWithoutRunningFactory(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "xero")
	retained := []byte("retained\n")
	if err := os.Mkdir(fixture.outputRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.outputRoot, "retained.txt"), retained, 0o600); err != nil {
		t.Fatal(err)
	}
	dependencies := sourcePackageCompilerTestDependencies(t)
	runs := 0
	underlying := dependencies.RunFactory
	dependencies.RunFactory = func(options FactoryRunOptions) (FactoryRunReceipt, error) {
		runs++
		return underlying(options)
	}
	_, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		dependencies,
	)
	if err == nil {
		t.Fatal("existing output root was accepted")
	}
	if runs != 1 {
		t.Fatalf("factory verifier runs = %d, want 1 before no-replace publication refusal", runs)
	}
	got, readErr := os.ReadFile(filepath.Join(fixture.outputRoot, "retained.txt"))
	if readErr != nil || !bytes.Equal(got, retained) {
		t.Fatalf("existing output changed: got=%q err=%v", got, readErr)
	}
}

func TestDocumentationFactorySourceCompilerRejectsTrailingTemplateJSON(t *testing.T) {
	_, err := decodeSourcePackageTemplateValue([]byte(`{"first":true} {"second":true}`))
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("trailing template JSON error = %v", err)
	}
}

func TestSourcePackageGeneratedOutputLineageRejectsNonRunnerUses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*documentationFactorySourcePackage)
	}{
		{
			name: "package role swap",
			mutate: func(manifest *documentationFactorySourcePackage) {
				left := generatedSourcePackageDocumentByRole(t, manifest, sourcePackageOutputRoleResidualCircuitPackage)
				right := generatedSourcePackageDocumentByRole(t, manifest, sourcePackageOutputRoleARCReferenceBlueprint)
				left.Role, right.Role = right.Role, left.Role
				left.ID, right.ID = right.ID, left.ID
				left.Version, right.Version = right.Version, left.Version
			},
		},
		{
			name: "template only",
			mutate: func(manifest *documentationFactorySourcePackage) {
				document := generatedSourcePackageDocumentByRole(t, manifest, sourcePackageOutputRoleResidualCircuitPackage)
				removeSourcePackageSemanticOutput(manifest, document.coordinate())
				generatedSourcePackageDocumentByRole(t, manifest, sourcePackageOutputRoleARCReferenceBlueprint).Template = document.coordinate()
			},
		},
		{
			name: "authority pin only",
			mutate: func(manifest *documentationFactorySourcePackage) {
				document := generatedSourcePackageDocumentByRole(t, manifest, sourcePackageOutputRoleResidualCircuitPackage)
				removeSourcePackageSemanticOutput(manifest, document.coordinate())
				manifest.FactoryPlan.EvidenceIntake.AuthorityPins.OODGraph.Resource = document.coordinate()
			},
		},
		{
			name: "preflight only",
			mutate: func(manifest *documentationFactorySourcePackage) {
				document := generatedSourcePackageDocumentByRole(t, manifest, sourcePackageOutputRoleResidualCircuitPackage)
				removeSourcePackageSemanticOutput(manifest, document.coordinate())
				manifest.FactoryPlan.PreflightDependencies = append(manifest.FactoryPlan.PreflightDependencies, document.coordinate())
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
			manifest := readSourcePackageCompilerTestManifest(t, fixture.manifestPath)
			testCase.mutate(&manifest)
			if _, err := validateSourcePackageGeneratedOutputLineage(manifest); err == nil || !strings.Contains(err.Error(), "runner output lineage") {
				t.Fatalf("non-runner output use error = %v, want runner-lineage refusal", err)
			}
		})
	}
}

func TestDocumentationFactorySourceCompilerRejectsOutputSchemaBindingSwap(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	manifest := readSourcePackageCompilerTestManifest(t, fixture.manifestPath)
	residual := generatedSourcePackageDocumentByRole(t, &manifest, sourcePackageOutputRoleResidualCircuitPackage)
	blueprint := generatedSourcePackageDocumentByRole(t, &manifest, sourcePackageOutputRoleARCReferenceBlueprint)
	var residualOutput, blueprintOutput *sourcePackageSemanticOutputPlan
	for index := range manifest.FactoryPlan.SemanticExtraction.ArtifactOutputs {
		output := &manifest.FactoryPlan.SemanticExtraction.ArtifactOutputs[index]
		switch output.Resource {
		case residual.coordinate():
			residualOutput = output
		case blueprint.coordinate():
			blueprintOutput = output
		}
	}
	if residualOutput == nil || blueprintOutput == nil {
		t.Fatal("fixture lacks residual or blueprint semantic output")
	}
	residualOutput.DerivationBindingIDs, blueprintOutput.DerivationBindingIDs = blueprintOutput.DerivationBindingIDs, residualOutput.DerivationBindingIDs
	writeSourcePackageCompilerTestManifest(t, fixture.manifestPath, manifest)
	_, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err == nil || !strings.Contains(err.Error(), "schema-validated") {
		t.Fatalf("schema-binding swap error = %v, want exact schema-binding refusal", err)
	}
	if _, statErr := os.Lstat(fixture.outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("schema-binding swap published an output root: %v", statErr)
	}
}

func TestDocumentationFactorySourceCompilerRejectsSourceMutationBeforeCompletion(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	dependencies := sourcePackageCompilerTestDependencies(t)
	underlying := dependencies.RunFactory
	dependencies.RunFactory = func(options FactoryRunOptions) (FactoryRunReceipt, error) {
		receipt, err := underlying(options)
		if err != nil {
			return receipt, err
		}
		raw, readErr := os.ReadFile(fixture.manifestPath)
		if readErr != nil {
			return FactoryRunReceipt{}, readErr
		}
		if writeErr := os.WriteFile(fixture.manifestPath, append(raw, '\n'), 0o600); writeErr != nil {
			return FactoryRunReceipt{}, writeErr
		}
		return receipt, nil
	}
	_, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		dependencies,
	)
	if err == nil || !strings.Contains(err.Error(), "revalidate source package input snapshots at completion") {
		t.Fatalf("source mutation error = %v", err)
	}
	if _, statErr := os.Lstat(fixture.outputRoot); !os.IsNotExist(statErr) {
		t.Fatalf("source mutation published an output root: %v", statErr)
	}
}

func TestSourcePackageJSONPointerRejectsInvalidEscape(t *testing.T) {
	_, err := resolveSourcePackageJSONPointer(map[string]interface{}{"bad~2key": true}, "/bad~2key")
	if err == nil || !strings.Contains(err.Error(), "invalid escape") {
		t.Fatalf("invalid JSON pointer escape error = %v", err)
	}
}

func TestDocumentationFactorySourceReceiptRejectsRosterMutation(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	result, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	mutated := result.SourceReceipt
	mutated.GeneratedOutputs = append([]DocumentationFactorySourceOutputReceipt(nil), mutated.GeneratedOutputs...)
	mutated.GeneratedOutputs[0].PackageRole = sourcePackageOutputRoleARCReferenceBlueprint
	mutated.ReceiptSHA256 = ""
	raw, err := canonicalFactoryJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	mutated.ReceiptSHA256 = sha256Hex(raw)
	if err := validateDocumentationFactorySourceReceipt(mutated); err == nil {
		t.Fatal("source receipt accepted a duplicated/mutated package-role roster")
	}
}

func TestDocumentationFactorySourceReceiptRejectsOwnerValidationMutation(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	result, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	mutated := result.SourceReceipt
	mutated.GeneratedOutputs = append([]DocumentationFactorySourceOutputReceipt(nil), mutated.GeneratedOutputs...)
	found := false
	for index := range mutated.GeneratedOutputs {
		if mutated.GeneratedOutputs[index].PackageRole != sourcePackageOutputRoleARCReferenceBlueprint {
			continue
		}
		found = true
		mutated.GeneratedOutputs[index].RequiredOwnerValidation = cloneDocumentationFactorySourceOutputOwnerValidation(mutated.GeneratedOutputs[index].RequiredOwnerValidation)
		mutated.GeneratedOutputs[index].RequiredOwnerValidation.Status = "passed"
	}
	if !found {
		t.Fatal("source receipt lacks ARC output")
	}
	outputRows := make([]string, len(mutated.GeneratedOutputs))
	for index, output := range mutated.GeneratedOutputs {
		rawOutput, marshalErr := canonicalFactoryJSON(output)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		outputRows[index] = string(rawOutput)
	}
	mutated.GeneratedOutputSetRootSHA256 = sha256Hex([]byte(lengthPrefixedIdentityKey(outputRows...)))
	mutated.ReceiptSHA256 = ""
	raw, err := canonicalFactoryJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	mutated.ReceiptSHA256 = sha256Hex(raw)
	if err := validateDocumentationFactorySourceReceipt(mutated); err == nil {
		t.Fatal("source receipt accepted an authored owner-validation success claim")
	}
}

func TestDocumentationFactorySourceReceiptRejectsBundleCrossBindingMutation(t *testing.T) {
	t.Parallel()
	fixture := newSourcePackageCompilerTestFixture(t, "quickbooks")
	result, err := compileDocumentationFactorySourcePackageWithDependencies(
		DocumentationFactorySourceCompileOptions{SourcePackagePath: fixture.manifestPath, OutputRoot: fixture.outputRoot},
		sourcePackageCompilerTestDependencies(t),
	)
	if err != nil {
		t.Fatal(err)
	}
	mutated := result.SourceReceipt
	mutated.BundleFiles = append([]documentationFactorySourceBundleFileReceipt(nil), mutated.BundleFiles...)
	for index := range mutated.BundleFiles {
		if mutated.BundleFiles[index].RelativePath == sourcePackageFactoryReceiptPath {
			mutated.BundleFiles[index].RawSHA256 = strings.Repeat("0", 64)
		}
	}
	fileRows := make([]string, len(mutated.BundleFiles))
	for index, file := range mutated.BundleFiles {
		raw, marshalErr := canonicalFactoryJSON(file)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		fileRows[index] = string(raw)
	}
	mutated.BundleFileSetRootSHA256 = sha256Hex([]byte(lengthPrefixedIdentityKey(fileRows...)))
	mutated.ReceiptSHA256 = ""
	raw, err := canonicalFactoryJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	mutated.ReceiptSHA256 = sha256Hex(raw)
	if err := validateDocumentationFactorySourceReceipt(mutated); err == nil {
		t.Fatal("source receipt accepted a bundle roster detached from the factory receipt file")
	}
}

func sourcePackageCompilerTestDependencies(t *testing.T) documentationFactorySourceCompilerDependencies {
	t.Helper()
	return documentationFactorySourceCompilerDependencies{
		RunFactory: func(options FactoryRunOptions) (FactoryRunReceipt, error) {
			return runDocumentationFactory(options, factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: testFactoryToolIdentity()})
		},
		Publish:       publishFactorySourceOutputDirectoryExclusive,
		WithWorkspace: withPrivateFactorySourceOutputDirectory,
	}
}

func readSourcePackageCompilerTestManifest(t *testing.T, path string) documentationFactorySourcePackage {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest documentationFactorySourcePackage
	if err := strictUnmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func writeSourcePackageCompilerTestManifest(t *testing.T, path string, manifest documentationFactorySourcePackage) {
	t.Helper()
	raw, err := canonicalFactoryJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func generatedSourcePackageDocumentByRole(t *testing.T, manifest *documentationFactorySourcePackage, packageRole string) *sourcePackageGeneratedDocument {
	t.Helper()
	for index := range manifest.GeneratedDocuments {
		if manifest.GeneratedDocuments[index].PackageRole == packageRole {
			return &manifest.GeneratedDocuments[index]
		}
	}
	t.Fatalf("fixture lacks generated package role %q", packageRole)
	return nil
}

func removeSourcePackageSemanticOutput(manifest *documentationFactorySourcePackage, coordinate sourcePackageCoordinate) {
	outputs := manifest.FactoryPlan.SemanticExtraction.ArtifactOutputs[:0]
	for _, output := range manifest.FactoryPlan.SemanticExtraction.ArtifactOutputs {
		if output.Resource != coordinate {
			outputs = append(outputs, output)
		}
	}
	manifest.FactoryPlan.SemanticExtraction.ArtifactOutputs = outputs
}

func newSourcePackageCompilerTestFixture(t *testing.T, provider string) sourcePackageCompilerTestFixture {
	t.Helper()
	root := t.TempDir()
	base := newTestFixture(t)
	lineage := newRealVerifyFactoryLineage(t, base)
	if len(lineage.requests) != 4 || len(lineage.inputs) != 4 {
		t.Fatalf("factory lineage has %d requests/%d inputs", len(lineage.requests), len(lineage.inputs))
	}

	var evidence evidenceIntakeStageRequest
	var semantic semanticExtractionStageRequest
	var graph graphCompileStageRequest
	var full fullFactoryStageRequest
	for index, target := range []interface{}{&evidence, &semantic, &graph, &full} {
		if err := strictUnmarshal(lineage.requests[index], target); err != nil {
			t.Fatalf("decode factory stage request %d: %v", index, err)
		}
	}

	materials := make(map[sourcePackageCoordinate]StageMaterial)
	for _, inputs := range lineage.inputs {
		for _, material := range inputs.Materials {
			coordinate := sourcePackageCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
			if prior, duplicate := materials[coordinate]; duplicate && !bytes.Equal(prior.Raw, material.Raw) {
				t.Fatalf("fixture material %s changes bytes across stages", sourcePackageCoordinateLabel(coordinate))
			}
			materials[coordinate] = StageMaterial{Role: material.Role, ID: material.ID, Version: material.Version, Raw: bytes.Clone(material.Raw)}
		}
	}

	authorityClasses := make(map[sourcePackageCoordinate]string)
	recordPin := func(pin immutableStageArtifactPin) {
		coordinate := sourcePackageCoordinate{Role: pin.Role, ID: pin.ID, Version: pin.Version}
		if prior := authorityClasses[coordinate]; prior != "" && prior != pin.AuthorityClass {
			t.Fatalf("fixture pin %s changes authority class from %q to %q", sourcePackageCoordinateLabel(coordinate), prior, pin.AuthorityClass)
		}
		authorityClasses[coordinate] = pin.AuthorityClass
	}
	for _, validation := range []stageValidationBinding{evidence.StageValidation, semantic.StageValidation, graph.StageValidation, full.StageValidation} {
		recordPin(validation.Schema)
		recordPin(validation.Profile)
	}
	for _, pin := range []immutableStageArtifactPin{
		evidence.AuthorityPins.OODGraph,
		evidence.AuthorityPins.GrandVision,
		evidence.AuthorityPins.SourceRecord,
		evidence.AuthorityPins.ExtensionProtocol,
		semantic.ApplicabilityProfile,
	} {
		recordPin(pin)
	}
	for _, binding := range semantic.DerivationBindings {
		recordPin(binding.Extractor)
		recordPin(binding.Schema)
	}

	planValue := sourcePackageFactoryPlan{
		EvidenceIntake: sourcePackageEvidenceIntakePlan{
			StageValidation: sourcePackageStageValidationFromBinding(evidence.StageValidation),
			AuthorityPins: sourcePackageAuthorityPlan{
				OODGraph:          sourcePackageReferenceFromPin(evidence.AuthorityPins.OODGraph),
				GrandVision:       sourcePackageReferenceFromPin(evidence.AuthorityPins.GrandVision),
				SourceRecord:      sourcePackageReferenceFromPin(evidence.AuthorityPins.SourceRecord),
				ExtensionProtocol: sourcePackageReferenceFromPin(evidence.AuthorityPins.ExtensionProtocol),
			},
			SelectionRoster: sourcePackageCoordinateFromIdentity(evidence.SelectionRoster),
		},
		SemanticExtraction: sourcePackageSemanticExtractionPlan{
			StageValidation:      sourcePackageStageValidationFromBinding(semantic.StageValidation),
			ApplicabilityProfile: sourcePackageReferenceFromPin(semantic.ApplicabilityProfile),
		},
		GraphCompile: sourcePackageGraphCompilePlan{
			StageValidation: sourcePackageStageValidationFromBinding(graph.StageValidation),
			Plan:            sourcePackageCoordinateFromIdentity(graph.Plan),
		},
		FullFactory: sourcePackageFullFactoryPlan{StageValidation: sourcePackageStageValidationFromBinding(full.StageValidation)},
	}
	for _, binding := range evidence.EvidenceManifests {
		planValue.EvidenceIntake.EvidenceManifests = append(planValue.EvidenceIntake.EvidenceManifests, sourcePackageCoordinate{Role: binding.Role, ID: binding.ArtifactID, Version: binding.ArtifactVersion})
	}
	dispositions := make(map[string]string, len(semantic.ArtifactRoleRoster))
	for _, role := range semantic.ArtifactRoleRoster {
		dispositions[role.Role] = role.Disposition
	}
	for _, output := range semantic.ArtifactOutputs {
		planValue.SemanticExtraction.ArtifactOutputs = append(planValue.SemanticExtraction.ArtifactOutputs, sourcePackageSemanticOutputPlan{
			Resource:    sourcePackageCoordinate{Role: output.Role, ID: output.ArtifactID, Version: output.ArtifactVersion},
			Disposition: dispositions[output.Role], DerivationBindingIDs: append([]string(nil), output.DerivationBindingIDs...),
		})
	}
	for _, binding := range semantic.DerivationBindings {
		planValue.SemanticExtraction.DerivationBindings = append(planValue.SemanticExtraction.DerivationBindings, sourcePackageSemanticBindingPlan{
			BindingID: binding.BindingID, Extractor: sourcePackageReferenceFromPin(binding.Extractor), Schema: sourcePackageReferenceFromPin(binding.Schema),
		})
	}
	for _, dependency := range graph.DependencyArtifacts {
		coordinate := sourcePackageCoordinateFromIdentity(dependency)
		planValue.GraphCompile.DependencyArtifacts = append(planValue.GraphCompile.DependencyArtifacts, coordinate)
		planValue.PreflightDependencies = append(planValue.PreflightDependencies, coordinate)
	}

	selected := selectSourcePackageGeneratedCoordinates(t, provider, semantic, graph)
	selectedByCoordinate := make(map[sourcePackageCoordinate]string, len(selected))
	for packageRole, coordinate := range selected {
		selectedByCoordinate[coordinate] = packageRole
	}

	manifestBundles := make(map[sourcePackageCoordinate]string, len(planValue.EvidenceIntake.EvidenceManifests))
	for index, coordinate := range planValue.EvidenceIntake.EvidenceManifests {
		manifestBundles[coordinate] = fmt.Sprintf("evidence/manifest-%02d/manifest.jsonl", index)
	}

	resourceByCoordinate := make(map[sourcePackageCoordinate]sourcePackageCompilerTestResource)
	addResource := func(coordinate sourcePackageCoordinate, raw []byte, bundlePath, authorityClass string) {
		if _, duplicate := resourceByCoordinate[coordinate]; duplicate {
			t.Fatalf("duplicate source fixture resource %s", sourcePackageCoordinateLabel(coordinate))
		}
		resourceByCoordinate[coordinate] = sourcePackageCompilerTestResource{
			declaration: sourcePackageResourceDeclaration{
				Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version, BundlePath: bundlePath,
				ExpectedRawSHA256: sha256Hex(raw), ExpectedByteCount: uint64(len(raw)), ExpectedAuthorityClass: authorityClass,
			},
			raw: bytes.Clone(raw),
		}
	}

	materialCoordinates := make([]sourcePackageCoordinate, 0, len(materials))
	for coordinate := range materials {
		materialCoordinates = append(materialCoordinates, coordinate)
	}
	sort.Slice(materialCoordinates, func(i, j int) bool {
		return sourcePackageCoordinateKey(materialCoordinates[i]) < sourcePackageCoordinateKey(materialCoordinates[j])
	})
	for index, coordinate := range materialCoordinates {
		if _, generated := selectedByCoordinate[coordinate]; generated {
			continue
		}
		bundlePath := fmt.Sprintf("materials/material-%04d.bin", index)
		if evidencePath := manifestBundles[coordinate]; evidencePath != "" {
			bundlePath = evidencePath
		}
		authorityClass := authorityClasses[coordinate]
		if authorityClass == "" {
			authorityClass = "source_package_material"
		}
		addResource(coordinate, materials[coordinate].Raw, bundlePath, authorityClass)
	}

	generated := make([]sourcePackageGeneratedDocument, 0, len(selected))
	extraSemanticBindings := make([]stageValidationProfileArtifactBinding, 0, 2)
	packageRoles := []string{
		sourcePackageOutputRoleAPIGraphArtifact,
		sourcePackageOutputRoleReusableProfile,
		sourcePackageOutputRoleSourceMapping,
		sourcePackageOutputRoleResidualCircuitPackage,
		sourcePackageOutputRoleARCReferenceBlueprint,
	}
	for index, packageRole := range packageRoles {
		coordinate := selected[packageRole]
		material, exists := materials[coordinate]
		if !exists {
			material = StageMaterial{
				Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version,
				Raw: mustCanonicalSourcePackageTestJSON(t, map[string]interface{}{
					"package_kind": packageRole, "package_version": "1", "candidate_only": true,
					"stable_references": []interface{}{},
				}),
			}
			materials[coordinate] = material
		}
		payloadCoordinate := sourcePackageCoordinate{Role: "source_payload", ID: fmt.Sprintf("%s_%s_payload", provider, packageRole), Version: "1"}
		templateCoordinate := sourcePackageCoordinate{Role: "source_template", ID: fmt.Sprintf("%s_%s_template", provider, packageRole), Version: "1"}
		outputRaw, payloadRaw, templateRaw := sourcePackageCompilerProjectionTemplate(t, packageRole, payloadCoordinate, material.Raw)
		material.Raw = outputRaw
		materials[coordinate] = material
		addResource(payloadCoordinate, payloadRaw, fmt.Sprintf("compiler/payload-%02d.json", index), "repository_source_payload")
		addResource(templateCoordinate, templateRaw, fmt.Sprintf("compiler/template-%02d.json", index), "repository_source_template")
		roleContract := sourcePackageOutputRoleContracts[packageRole]
		authorityClass := authorityClasses[coordinate]
		if authorityClass == "" {
			authorityClass = "candidate_preimage"
		}
		generated = append(generated, sourcePackageGeneratedDocument{
			PackageRole: packageRole, Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version,
			BundlePath: fmt.Sprintf("generated/%s.jsonl", packageRole), Template: templateCoordinate,
			ExpectedRawSHA256: sha256Hex(outputRaw), ExpectedByteCount: uint64(len(outputRaw)),
			SubjectClass: packageRole, TargetArtifactType: roleContract.targetArtifactType,
			PayloadContractRef:      "repository_contract.provider_factory_outputs." + packageRole,
			AuthorityClass:          authorityClass,
			RequiredOwnerValidation: cloneDocumentationFactorySourceOutputOwnerValidation(roleContract.requiredOwnerValidation),
			CandidateOnly:           true, BodyFree: true,
		})
		if packageRole == sourcePackageOutputRoleResidualCircuitPackage || packageRole == sourcePackageOutputRoleARCReferenceBlueprint {
			schemaID := fmt.Sprintf("urn:test:source-package:%s:%s:schema", provider, packageRole)
			schemaCoordinate := sourcePackageCoordinate{Role: coordinate.Role + "_schema", ID: schemaID, Version: "1"}
			schemaRaw := exactStageArtifactSchema(t, schemaID, outputRaw)
			extractorCoordinate := sourcePackageCoordinate{Role: "source_package_output_extractor", ID: fmt.Sprintf("%s_%s_extractor", provider, packageRole), Version: "1"}
			extractorRaw := mustCanonicalSourcePackageTestJSON(t, map[string]interface{}{
				"row_kind": "source_package_output_extractor", "package_role": packageRole, "version": "1",
			})
			materials[schemaCoordinate] = StageMaterial{Role: schemaCoordinate.Role, ID: schemaCoordinate.ID, Version: schemaCoordinate.Version, Raw: schemaRaw}
			materials[extractorCoordinate] = StageMaterial{Role: extractorCoordinate.Role, ID: extractorCoordinate.ID, Version: extractorCoordinate.Version, Raw: extractorRaw}
			authorityClasses[schemaCoordinate] = "canonical"
			authorityClasses[extractorCoordinate] = "admitted"
			addResource(schemaCoordinate, schemaRaw, fmt.Sprintf("compiler/schema-%02d.json", index), "canonical")
			addResource(extractorCoordinate, extractorRaw, fmt.Sprintf("compiler/extractor-%02d.json", index), "admitted")
			bindingID := "binding_source_package_" + packageRole
			planValue.SemanticExtraction.ArtifactOutputs = append(planValue.SemanticExtraction.ArtifactOutputs, sourcePackageSemanticOutputPlan{
				Resource: coordinate, Disposition: "required", DerivationBindingIDs: []string{bindingID},
			})
			planValue.SemanticExtraction.DerivationBindings = append(planValue.SemanticExtraction.DerivationBindings, sourcePackageSemanticBindingPlan{
				BindingID: bindingID,
				Extractor: sourcePackagePinReference{Resource: extractorCoordinate, AuthorityClass: "admitted"},
				Schema:    sourcePackagePinReference{Resource: schemaCoordinate, AuthorityClass: "canonical"},
			})
			extraSemanticBindings = append(extraSemanticBindings, stageValidationProfileArtifactBinding{
				Role: coordinate.Role, ArtifactID: coordinate.ID, ArtifactVersion: coordinate.Version, ArtifactRawSHA256: sha256Hex(outputRaw),
				SchemaRole: schemaCoordinate.Role, SchemaID: schemaCoordinate.ID, SchemaVersion: schemaCoordinate.Version, SchemaRawSHA256: sha256Hex(schemaRaw),
			})
		}
	}
	sort.Slice(planValue.SemanticExtraction.ArtifactOutputs, func(i, j int) bool {
		left := planValue.SemanticExtraction.ArtifactOutputs[i].Resource
		right := planValue.SemanticExtraction.ArtifactOutputs[j].Resource
		if left.Role != right.Role {
			return left.Role < right.Role
		}
		if left.ID != right.ID {
			return left.ID < right.ID
		}
		return left.Version < right.Version
	})
	sort.Slice(planValue.SemanticExtraction.DerivationBindings, func(i, j int) bool {
		return planValue.SemanticExtraction.DerivationBindings[i].BindingID < planValue.SemanticExtraction.DerivationBindings[j].BindingID
	})
	sort.Slice(generated, func(i, j int) bool {
		return sourcePackageCoordinateKey(generated[i].coordinate()) < sourcePackageCoordinateKey(generated[j].coordinate())
	})
	for _, validation := range []stageValidationBinding{evidence.StageValidation, semantic.StageValidation, graph.StageValidation, full.StageValidation} {
		profileCoordinate := sourcePackageReferenceFromPin(validation.Profile).Resource
		profileMaterial := materials[profileCoordinate]
		var profile stageValidationProfileDocument
		if err := strictUnmarshal(profileMaterial.Raw, &profile); err != nil {
			t.Fatalf("decode fixture validation profile %s: %v", sourcePackageCoordinateLabel(profileCoordinate), err)
		}
		if profileCoordinate == planValue.SemanticExtraction.StageValidation.Profile.Resource {
			profile.BoundArtifactSchemas = append(profile.BoundArtifactSchemas, extraSemanticBindings...)
			sort.Slice(profile.BoundArtifactSchemas, func(i, j int) bool {
				left := sourcePackageCoordinate{Role: profile.BoundArtifactSchemas[i].Role, ID: profile.BoundArtifactSchemas[i].ArtifactID, Version: profile.BoundArtifactSchemas[i].ArtifactVersion}
				right := sourcePackageCoordinate{Role: profile.BoundArtifactSchemas[j].Role, ID: profile.BoundArtifactSchemas[j].ArtifactID, Version: profile.BoundArtifactSchemas[j].ArtifactVersion}
				return compareStageMaterialCoordinates(
					stageMaterialCoordinate{Role: left.Role, ID: left.ID, Version: left.Version},
					stageMaterialCoordinate{Role: right.Role, ID: right.ID, Version: right.Version},
				) < 0
			})
		}
		for bindingIndex := range profile.BoundArtifactSchemas {
			binding := &profile.BoundArtifactSchemas[bindingIndex]
			artifactCoordinate := sourcePackageCoordinate{Role: binding.Role, ID: binding.ArtifactID, Version: binding.ArtifactVersion}
			schemaCoordinate := sourcePackageCoordinate{Role: binding.SchemaRole, ID: binding.SchemaID, Version: binding.SchemaVersion}
			binding.ArtifactRawSHA256 = sha256Hex(materials[artifactCoordinate].Raw)
			binding.SchemaRawSHA256 = sha256Hex(materials[schemaCoordinate].Raw)
		}
		profileMaterial.Raw = mustStageJSON(t, profile)
		materials[profileCoordinate] = profileMaterial
		resource := resourceByCoordinate[profileCoordinate]
		resource.raw = bytes.Clone(profileMaterial.Raw)
		resource.declaration.ExpectedRawSHA256 = sha256Hex(profileMaterial.Raw)
		resource.declaration.ExpectedByteCount = uint64(len(profileMaterial.Raw))
		resourceByCoordinate[profileCoordinate] = resource
	}

	evidenceDeclarations := make([]sourcePackageEvidenceBodyDeclaration, 0, len(lineage.inputs[0].EvidenceBodies))
	for bodyIndex, body := range lineage.inputs[0].EvidenceBodies {
		manifestCoordinate := sourcePackageCoordinate{Role: body.ManifestRole, ID: body.ManifestID, Version: body.ManifestVersion}
		manifest := materials[manifestCoordinate]
		stagingFile := sourcePackageCompilerEvidenceStagingFile(t, manifest.Raw, body.ComponentOrdinal)
		carrierCoordinate := sourcePackageCoordinate{Role: "evidence_carrier", ID: fmt.Sprintf("%s_carrier_%04d", provider, bodyIndex), Version: "1"}
		carrierRaw := []byte(base64.StdEncoding.EncodeToString(body.Raw) + strings.Repeat("\n", bodyIndex+1))
		carrierBundle := path.Join(path.Dir(manifestBundles[manifestCoordinate]), stagingFile)
		addResource(carrierCoordinate, carrierRaw, carrierBundle, "sealed_evidence_carrier")
		evidenceDeclarations = append(evidenceDeclarations, sourcePackageEvidenceBodyDeclaration{
			Manifest: manifestCoordinate, ComponentOrdinal: body.ComponentOrdinal, Carrier: carrierCoordinate,
			CarrierEncoding: sourcePackageCarrierBase64, ExpectedBodySHA256: sha256Hex(body.Raw), ExpectedBodyByteCount: uint64(len(body.Raw)),
		})
	}
	sort.Slice(evidenceDeclarations, func(i, j int) bool {
		left := lengthPrefixedIdentityKey(sourcePackageCoordinateKey(evidenceDeclarations[i].Manifest), fmt.Sprintf("%d", evidenceDeclarations[i].ComponentOrdinal))
		right := lengthPrefixedIdentityKey(sourcePackageCoordinateKey(evidenceDeclarations[j].Manifest), fmt.Sprintf("%d", evidenceDeclarations[j].ComponentOrdinal))
		return left < right
	})

	resources := make([]sourcePackageCompilerTestResource, 0, len(resourceByCoordinate))
	for _, resource := range resourceByCoordinate {
		resources = append(resources, resource)
	}
	sort.Slice(resources, func(i, j int) bool {
		return sourcePackageCoordinateKey(resources[i].declaration.coordinate()) < sourcePackageCoordinateKey(resources[j].declaration.coordinate())
	})
	manifestResources := make([]sourcePackageResourceDeclaration, len(resources))
	for index := range resources {
		resources[index].declaration.Path = fmt.Sprintf("source/resource-%04d.bin", index)
		manifestResources[index] = resources[index].declaration
		target := filepath.Join(root, filepath.FromSlash(resources[index].declaration.Path))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, resources[index].raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	manifest := documentationFactorySourcePackage{
		PackageKind: documentationFactorySourcePackageKind, PackageVersion: documentationFactorySourcePackageVersion,
		Resources: manifestResources, EvidenceBodies: evidenceDeclarations, GeneratedDocuments: generated, FactoryPlan: planValue,
	}
	manifestRaw, err := canonicalFactoryJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "source-package.json")
	if err := os.WriteFile(manifestPath, append(manifestRaw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return sourcePackageCompilerTestFixture{manifestPath: manifestPath, outputRoot: filepath.Join(root, "compiled-output")}
}

func sourcePackageStageValidationFromBinding(binding stageValidationBinding) sourcePackageStageValidationPlan {
	return sourcePackageStageValidationPlan{Schema: sourcePackageReferenceFromPin(binding.Schema), Profile: sourcePackageReferenceFromPin(binding.Profile)}
}

func sourcePackageReferenceFromPin(pin immutableStageArtifactPin) sourcePackagePinReference {
	return sourcePackagePinReference{Resource: sourcePackageCoordinate{Role: pin.Role, ID: pin.ID, Version: pin.Version}, AuthorityClass: pin.AuthorityClass}
}

func sourcePackageCoordinateFromIdentity(identity stageArtifactIdentity) sourcePackageCoordinate {
	return sourcePackageCoordinate{Role: identity.Role, ID: identity.ID, Version: identity.Version}
}

func selectSourcePackageGeneratedCoordinates(t *testing.T, provider string, semantic semanticExtractionStageRequest, graph graphCompileStageRequest) map[string]sourcePackageCoordinate {
	t.Helper()
	semanticByRole := make(map[string]sourcePackageCoordinate, len(semantic.ArtifactOutputs))
	for _, output := range semantic.ArtifactOutputs {
		semanticByRole[output.Role] = sourcePackageCoordinate{Role: output.Role, ID: output.ArtifactID, Version: output.ArtifactVersion}
	}
	reusable, reusableOK := semanticByRole["provider_neutral_compilation_profile"]
	mapping, mappingOK := semanticByRole["field_mapping_candidate"]
	if !reusableOK || !mappingOK {
		t.Fatalf("factory fixture lacks role-correct reusable-profile or source-mapping semantic output")
	}
	return map[string]sourcePackageCoordinate{
		sourcePackageOutputRoleAPIGraphArtifact:       sourcePackageCoordinateFromIdentity(graph.Plan),
		sourcePackageOutputRoleReusableProfile:        reusable,
		sourcePackageOutputRoleSourceMapping:          mapping,
		sourcePackageOutputRoleResidualCircuitPackage: {Role: sourcePackageOutputRoleResidualCircuitPackage, ID: provider + "_residual_circuit_package", Version: "1"},
		sourcePackageOutputRoleARCReferenceBlueprint:  {Role: sourcePackageOutputRoleARCReferenceBlueprint, ID: provider + "_arc_reference_blueprint", Version: "1"},
	}
}

func sourcePackageCompilerProjectionTemplate(t *testing.T, packageRole string, payloadCoordinate sourcePackageCoordinate, target []byte) ([]byte, []byte, []byte) {
	t.Helper()
	if value, err := decodeSourcePackageTemplateValue(target); err == nil {
		canonical, canonicalErr := canonicalStageValue(value)
		if canonicalErr == nil {
			outputRaw := append(canonical, '\n')
			payloadRaw := mustCanonicalSourcePackageTestJSON(t, map[string]interface{}{"package_role": packageRole, "value": value})
			projection := mustCanonicalSourcePackageTestJSONValue(t, sourcePackageProjectionValue(payloadCoordinate, "/value"))
			templateRaw := mustCanonicalSourcePackageTestJSON(t, sourcePackageTemplateDocument{
				TemplateKind: documentationFactoryTemplateKind, TemplateVersion: documentationFactoryTemplateVersion,
				OutputFormat: sourcePackageTemplateFormatJSON, Document: projection,
			})
			return outputRaw, payloadRaw, templateRaw
		}
	}
	rows := make([]interface{}, 0)
	var outputRaw []byte
	for lineNumber, line := range bytes.Split(target, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		value, err := decodeSourcePackageTemplateValue(line)
		if err != nil {
			t.Fatalf("generated fixture target %q row %d is not canonical JSON: %v", packageRole, lineNumber+1, err)
		}
		rows = append(rows, value)
		canonical, canonicalErr := canonicalStageValue(value)
		if canonicalErr != nil {
			t.Fatal(canonicalErr)
		}
		outputRaw = append(outputRaw, canonical...)
		outputRaw = append(outputRaw, '\n')
	}
	payloadRaw := mustCanonicalSourcePackageTestJSON(t, map[string]interface{}{"package_role": packageRole, "rows": rows})
	templateRows := make([]json.RawMessage, len(rows))
	for index := range rows {
		templateRows[index] = mustCanonicalSourcePackageTestJSONValue(t, sourcePackageProjectionValue(payloadCoordinate, fmt.Sprintf("/rows/%d", index)))
	}
	templateRaw := mustCanonicalSourcePackageTestJSON(t, sourcePackageTemplateDocument{
		TemplateKind: documentationFactoryTemplateKind, TemplateVersion: documentationFactoryTemplateVersion,
		OutputFormat: sourcePackageTemplateFormatJSONL, Rows: templateRows,
	})
	rendered, err := renderSourcePackageTemplate(templateRaw, map[sourcePackageCoordinate]sourcePackageMaterial{
		payloadCoordinate: {coordinate: payloadCoordinate, raw: payloadRaw},
	}, map[sourcePackageCoordinate]struct{}{})
	if err != nil || !bytes.Equal(rendered, outputRaw) {
		mismatch := 0
		for mismatch < len(outputRaw) && mismatch < len(rendered) && outputRaw[mismatch] == rendered[mismatch] {
			mismatch++
		}
		start := max(0, mismatch-40)
		endTarget := min(len(outputRaw), mismatch+80)
		endRendered := min(len(rendered), mismatch+80)
		t.Fatalf("projection template for %q does not reproduce exact target: err=%v target=%d/%s rendered=%d/%s mismatch=%d target_window=%q rendered_window=%q", packageRole, err, len(outputRaw), sha256Hex(outputRaw), len(rendered), sha256Hex(rendered), mismatch, outputRaw[start:endTarget], rendered[start:endRendered])
	}
	return outputRaw, payloadRaw, templateRaw
}

func sourcePackageProjectionValue(resource sourcePackageCoordinate, pointer string) map[string]interface{} {
	return map[string]interface{}{
		"$resource_projection": map[string]interface{}{
			"resource": resource, "projection": sourcePackageProjectionJSONValue, "json_pointer": pointer,
		},
	}
}

func mustCanonicalSourcePackageTestJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := canonicalFactoryJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func mustCanonicalSourcePackageTestJSONValue(t *testing.T, value interface{}) json.RawMessage {
	t.Helper()
	raw, err := canonicalFactoryJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func sourcePackageCompilerEvidenceStagingFile(t *testing.T, manifest []byte, ordinal uint64) string {
	t.Helper()
	for lineNumber, line := range bytes.Split(manifest, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var envelope evidenceManifestEnvelope
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatalf("decode evidence manifest row %d: %v", lineNumber+1, err)
		}
		if envelope.RowKind != "external_evidence_body" {
			continue
		}
		var body externalEvidenceBody
		if err := json.Unmarshal(line, &body); err != nil {
			t.Fatal(err)
		}
		if uint64(body.ComponentOrdinal) == ordinal {
			return body.StagingFile
		}
	}
	t.Fatalf("evidence manifest omits component ordinal %d", ordinal)
	return ""
}
