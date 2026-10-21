package providerplan

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// These are deliberately small, direct contract tests for the runner's
// attestation boundaries.  The end-to-end fixtures exercise the happy path;
// this matrix makes the individual fail-closed checks independently durable.
func TestFactoryRunnerIdentityBoundariesFailClosed(t *testing.T) {
	tool := testFactoryToolIdentity()
	execution := testFactoryExecutionIdentity(tool)

	toolCases := []struct {
		name   string
		mutate func(*FactoryToolIdentity)
	}{
		{"command", func(v *FactoryToolIdentity) { v.CommandPath = "wrong" }},
		{"module", func(v *FactoryToolIdentity) { v.ModuleVersion = "" }},
		{"vcs", func(v *FactoryToolIdentity) { v.VCS = "hg" }},
		{"revision", func(v *FactoryToolIdentity) { v.VCSRevision = "not-a-revision" }},
		{"modified", func(v *FactoryToolIdentity) { v.VCSModified = true }},
		{"not reproducible", func(v *FactoryToolIdentity) { v.ReproducibleSourceTree = false }},
		{"tags", func(v *FactoryToolIdentity) { v.BuildTags = "dev" }},
		{"contract", func(v *FactoryToolIdentity) { v.RunnerContractSHA256 = strings.Repeat("0", 64) }},
		{"time", func(v *FactoryToolIdentity) { v.VCSTime = "never" }},
		{"module graph", func(v *FactoryToolIdentity) { v.ModuleGraphSHA256 = "bad" }},
	}
	for _, test := range toolCases {
		t.Run("tool "+test.name, func(t *testing.T) {
			candidate := tool
			test.mutate(&candidate)
			if _, err := sealFactoryToolIdentity(candidate); err == nil {
				t.Fatalf("%s substitution was accepted", test.name)
			}
		})
	}

	executionCases := []struct {
		name   string
		mutate func(*FactoryExecutionIdentity)
	}{
		{"portable binding", func(v *FactoryExecutionIdentity) { v.PortableBuildIdentitySHA256 = strings.Repeat("0", 64) }},
		{"target", func(v *FactoryExecutionIdentity) { v.TargetOS = "" }},
		{"metadata source", func(v *FactoryExecutionIdentity) { v.BuildMetadataSource = "caller" }},
		{"measurement scope", func(v *FactoryExecutionIdentity) { v.ExecutableMeasurementScope = "mapped-image" }},
		{"duplicate setting", func(v *FactoryExecutionIdentity) { v.BuildSettings = append(v.BuildSettings, v.BuildSettings[0]) }},
		{"unsupported setting", func(v *FactoryExecutionIdentity) {
			v.BuildSettings = append(v.BuildSettings, factoryBuildSetting{Key: "GODEBUG", Value: "x"})
		}},
		{"profile", func(v *FactoryExecutionIdentity) { setFactoryBuildSetting(v.BuildSettings, "CGO_ENABLED", "1") }},
		{"tags contradict tool", func(v *FactoryExecutionIdentity) { setFactoryBuildSetting(v.BuildSettings, "-tags", "different") }},
		{"vcs contradict tool", func(v *FactoryExecutionIdentity) { setFactoryBuildSetting(v.BuildSettings, "vcs", "other") }},
		{"executable", func(v *FactoryExecutionIdentity) { v.ExecutableSHA256 = "bad" }},
		{"byte count", func(v *FactoryExecutionIdentity) { v.ExecutableByteCount = 0 }},
		{"toolchain count", func(v *FactoryExecutionIdentity) { v.GoToolchainFileCount = 0 }},
	}
	for _, test := range executionCases {
		t.Run("execution "+test.name, func(t *testing.T) {
			candidate := execution
			candidate.BuildSettings = append([]FactoryBuildSetting(nil), execution.BuildSettings...)
			test.mutate(&candidate)
			if _, err := sealFactoryExecutionIdentity(candidate, tool); err == nil {
				t.Fatalf("%s substitution was accepted", test.name)
			}
		})
	}
	tamperedExecution := execution
	tamperedExecution.ExecutionIdentitySHA256 = strings.Repeat("0", 64)
	if err := validateFactoryExecutionIdentity(tamperedExecution, tool); err == nil {
		t.Fatal("tampered execution identity digest was accepted")
	}
	tamperedTool := tool
	tamperedTool.BuildIdentitySHA256 = strings.Repeat("0", 64)
	if err := validateFactoryToolIdentity(tamperedTool); err == nil {
		t.Fatal("tampered portable tool identity digest was accepted")
	}

	for _, value := range []string{"", strings.Repeat("a", 39), strings.Repeat("A", 40), strings.Repeat("z", 40), strings.Repeat("b", 64)} {
		want := value == strings.Repeat("b", 64)
		if got := validFactoryVCSRevision(value); got != want {
			t.Fatalf("validFactoryVCSRevision(%q)=%v want %v", value, got, want)
		}
	}
}

func TestFactoryRunnerBuildMetadataAndSettingsBoundaries(t *testing.T) {
	if _, err := canonicalFactoryBuildMetadata(nil); err == nil {
		t.Fatal("nil build metadata was accepted")
	}
	info := &debug.BuildInfo{
		GoVersion: "go1.test",
		Main:      debug.Module{Path: "example/main", Version: "v1.0.0", Sum: "h1:main"},
		Deps: []*debug.Module{
			{Path: "z.example/module", Version: "v1.0.0", Sum: "h1:z"},
			{Path: "a.example/module", Version: "v1.0.0", Sum: "h1:a"},
		},
		Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}, {Key: "-tags", Value: "factory_release"}, {Key: "vcs.revision", Value: "abc"}},
	}
	metadata, err := canonicalFactoryBuildMetadata(info)
	if err != nil || len(metadata.Dependencies) != 2 || metadata.Dependencies[0].Path != "a.example/module" || len(metadata.Settings) != 2 || metadata.Settings[0].Key != "-tags" {
		t.Fatalf("canonical metadata=%+v err=%v", metadata, err)
	}
	badReplacement := *info
	badReplacement.Main = debug.Module{Path: "example/main", Version: "v1", Sum: "h1:main", Replace: &debug.Module{Path: "../local"}}
	if _, err := canonicalFactoryBuildMetadata(&badReplacement); err == nil {
		t.Fatal("unpinned replacement was accepted")
	}
	nilDependency := *info
	nilDependency.Deps = []*debug.Module{nil}
	if _, err := canonicalFactoryBuildMetadata(&nilDependency); err == nil {
		t.Fatal("nil build dependency was accepted")
	}

	for _, key := range []string{"GOOS", "GOAMD64", "-compiler"} {
		if !factoryTargetBuildSetting(key) || !factoryExecutionBuildSettingAllowed(key) {
			t.Fatalf("target setting %q unexpectedly rejected", key)
		}
	}
	if !factoryTargetBuildSetting("CGO_LDFLAGS") || factoryExecutionBuildSettingAllowed("CGO_LDFLAGS") {
		t.Fatal("CGO linker setting crossed the portable/execution boundary")
	}
	for _, key := range []string{"GODEBUG", "random"} {
		if factoryTargetBuildSetting(key) || factoryExecutionBuildSettingAllowed(key) {
			t.Fatalf("non-contract setting %q unexpectedly accepted", key)
		}
	}
	if _, err := exactFactoryBuildSettings([]debug.BuildSetting{{Key: "random", Value: "x"}}); err == nil {
		t.Fatal("unapproved execution setting was accepted")
	}
}

func TestFactoryRunnerBuildInfoAndExecutableOperationsFailClosed(t *testing.T) {
	if _, err := factoryToolIdentityFromBuildInfoWithPins(nil, "linux", "amd64", factoryReleaseBuildPins{}); err == nil {
		t.Fatal("nil build info was accepted")
	}
	base := factoryTestBuildInfo()
	for _, mutate := range []func(*debug.BuildInfo){
		func(v *debug.BuildInfo) {
			v.Settings = append(v.Settings, debug.BuildSetting{Key: "GOOS", Value: "linux"})
		},
		func(v *debug.BuildInfo) { setDebugBuildSetting(v.Settings, "vcs.modified", "maybe") },
		func(v *debug.BuildInfo) { setDebugBuildSetting(v.Settings, "CGO_ENABLED", "1") },
	} {
		candidate := cloneFactoryBuildInfo(base)
		mutate(candidate)
		if _, err := factoryToolIdentityFromBuildInfoWithPins(candidate, "linux", "amd64", factoryReleaseBuildPins{SourceRosterSHA256: strings.Repeat("a", 64)}); err == nil {
			t.Fatal("invalid runtime build information was accepted")
		}
	}
	if _, err := factoryToolIdentityFromBuildInfo(base, "linux", "amd64"); err == nil {
		t.Fatal("ordinary build unexpectedly used release linker pins")
	}
	if _, _, err := currentFactoryRuntimeIdentities(); err == nil {
		t.Fatal("ordinary test binary unexpectedly claimed a pinned factory-release identity")
	}
	if _, err := factoryExecutionIdentityFromBuildInfo(base, "linux", "amd64", testFactoryToolIdentity(), strings.Repeat("d", 64), 1); err == nil {
		t.Fatal("ordinary build unexpectedly used release linker pins for execution identity")
	}
	// This exercises the production wrapper.  A `go test` binary is not a
	// release launcher and may be exposed through a non-openable harness path.
	_, _, _ = currentFactoryExecutableIdentity()
	if _, err := RunDocumentationFactory(FactoryRunOptions{}); err == nil {
		t.Fatal("ordinary test binary unexpectedly ran the production factory launcher")
	}

	path := filepath.Join(t.TempDir(), "factory-executable")
	if err := os.WriteFile(path, []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	operations := factoryExecutableIdentityOperations{
		executable: func() (string, error) { return path, nil }, initialLstat: os.Lstat, initialOpen: os.Open,
		open: os.Open, finalLstat: os.Lstat, finalOpen: os.Open,
	}
	digest, count, err := factoryExecutableIdentityWithOperations(operations)
	if err != nil || count != int64(len("identity")) || !isLowerSHA256(digest) {
		t.Fatalf("stable executable identity=(%q,%d,%v)", digest, count, err)
	}
	operations.executable = func() (string, error) { return "", os.ErrNotExist }
	if _, _, err := factoryExecutableIdentityWithOperations(operations); err == nil {
		t.Fatal("executable lookup failure was accepted")
	}
	operations = factoryExecutableIdentityOperations{executable: func() (string, error) { return path, nil }, initialLstat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }}
	if _, _, err := factoryExecutableIdentityWithOperations(operations); err == nil {
		t.Fatal("initial lstat failure was accepted")
	}
	directory := t.TempDir()
	operations = factoryStableExecutableOperations(path)
	operations.executable = func() (string, error) { return directory, nil }
	if _, _, err := factoryExecutableIdentityWithOperations(operations); err == nil {
		t.Fatal("directory executable was accepted")
	}
	for _, test := range []struct {
		name   string
		mutate func(*factoryExecutableIdentityOperations)
	}{
		{"initial open", func(v *factoryExecutableIdentityOperations) { v.initialOpen = factoryOpenFailure }},
		{"open", func(v *factoryExecutableIdentityOperations) { v.open = factoryOpenFailure }},
		{"final lstat", func(v *factoryExecutableIdentityOperations) {
			v.finalLstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		}},
		{"final open", func(v *factoryExecutableIdentityOperations) { v.finalOpen = factoryOpenFailure }},
		{"initial closed handle", func(v *factoryExecutableIdentityOperations) { v.initialOpen = factoryClosedOpen(t, path) }},
		{"opened closed handle", func(v *factoryExecutableIdentityOperations) { v.open = factoryClosedOpen(t, path) }},
		{"final closed handle", func(v *factoryExecutableIdentityOperations) { v.finalOpen = factoryClosedOpen(t, path) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := factoryStableExecutableOperations(path)
			test.mutate(&candidate)
			if _, _, err := factoryExecutableIdentityWithOperations(candidate); err == nil {
				t.Fatalf("%s failure was accepted", test.name)
			}
		})
	}
	for _, field := range []string{"initial", "final"} {
		candidate := factoryStableExecutableOperations(path)
		if field == "initial" {
			candidate.initialOpen = nil
		} else {
			candidate.finalOpen = nil
		}
		if _, _, err := factoryExecutableIdentityWithOperations(candidate); err != nil {
			t.Fatalf("%s fallback open failed: %v", field, err)
		}
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashFactoryExecutable(file); err == nil {
		t.Fatal("closed executable handle was hashed")
	}
	overLimitPath := filepath.Join(t.TempDir(), "over-limit-executable")
	overLimit, err := os.Create(overLimitPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := overLimit.Truncate(maxFactoryExecutableBytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := hashFactoryExecutable(overLimit); err == nil {
		t.Fatal("oversized executable was hashed")
	}
	if err := overLimit.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFactoryRunnerReceiptAndUtilityBoundaryChecks(t *testing.T) {
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	receipt, err := runDocumentationFactory(options, factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: testFactoryToolIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFactoryPreflightReceipt(receipt.PreflightReceipt, StageReceiptSummary{ReceiptSHA256: receipt.Stages[2].ReceiptSHA256, OutputRootSHA256: receipt.Stages[2].OutputRootSHA256}, receipt.InputAdmissionProof, receipt.InputResources); err != nil {
		t.Fatalf("valid preflight receipt rejected: %v", err)
	}
	stage := StageReceiptSummary{ReceiptSHA256: receipt.Stages[2].ReceiptSHA256, OutputRootSHA256: receipt.Stages[2].OutputRootSHA256}
	for _, test := range []struct {
		name   string
		mutate func(*Receipt)
	}{
		{"result", func(v *Receipt) { v.Result = "fail" }},
		{"graph receipt", func(v *Receipt) { v.GraphCompileStageReceiptSHA256 = strings.Repeat("0", 64) }},
		{"graph root", func(v *Receipt) { v.GraphCompileStageOutputRootSHA256 = strings.Repeat("0", 64) }},
		{"admission proof", func(v *Receipt) { v.ProviderInputAdmissionProofSHA256 = strings.Repeat("0", 64) }},
		{"observed manifest hash", func(v *Receipt) { v.EvidenceManifestSHA256 = []string{strings.Repeat("0", 64)} }},
		{"candidate safety", func(v *Receipt) { v.CredentialMaterialDetected = true }},
	} {
		t.Run("preflight "+test.name, func(t *testing.T) {
			candidate := receipt.PreflightReceipt
			test.mutate(&candidate)
			var sealErr error
			candidate, sealErr = sealReceipt(candidate)
			if sealErr != nil {
				t.Fatal(sealErr)
			}
			if err := validateFactoryPreflightReceipt(candidate, stage, receipt.InputAdmissionProof, receipt.InputResources); err == nil {
				t.Fatal("substituted preflight receipt was accepted")
			}
		})
	}

	if _, err := factoryStageValidationBinding([]byte(`{"stage_kind":"unknown"}`), "unknown"); err == nil {
		t.Fatal("unsupported stage validation binding was accepted")
	}
	if _, err := factoryExpectedStageMaterials([]byte(`{}`)); err == nil {
		t.Fatal("incomplete stage request was accepted")
	}
	for _, stageKind := range []string{stageEvidenceIntake, stageSemanticExtraction, stageGraphCompile, stageFullFactory, "unknown"} {
		raw := []byte(`{"stage_kind":"` + stageKind + `"}`)
		if _, err := factoryExpectedStageMaterials(raw); err == nil {
			t.Fatalf("incomplete %s material request was accepted", stageKind)
		}
	}
	if _, err := factoryPathKey(" padded "); err == nil {
		t.Fatal("padded factory path was accepted")
	}
	key, err := factoryPathKey(filepath.Join(t.TempDir(), "file"))
	if err != nil || key == "" {
		t.Fatalf("factory path key=%q err=%v", key, err)
	}
	inputs := StageCompileInputs{PredecessorReceipts: [][]byte{[]byte("r")}, EvidenceBodies: []StageEvidenceBody{{Raw: []byte("e")}}, Materials: []StageMaterial{{Raw: []byte("m")}}}
	copy := shallowFactoryStageInputs(inputs)
	copy.PredecessorReceipts[0] = []byte("changed")
	if string(inputs.PredecessorReceipts[0]) != "r" {
		t.Fatal("shallow factory inputs did not isolate the receipt slice")
	}
	if equalFactoryStrings([]string{"a"}, []string{"a", "b"}) || !equalFactoryStrings(nil, nil) {
		t.Fatal("factory string equality lost its exact cardinality semantics")
	}
	if !factoryBuildSettingLess(factoryBuildSetting{Key: "a", Value: "a"}, factoryBuildSetting{Key: "a", Value: "b"}) {
		t.Fatal("build-setting tie breaker is not deterministic")
	}
}

func TestFactoryRunnerOrchestrationAndMaterialRequestsRejectSubstitution(t *testing.T) {
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	tool := testFactoryToolIdentity()
	execution := testFactoryExecutionIdentity(tool)
	dependencies := factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: tool}
	for _, test := range []struct {
		name    string
		options FactoryRunOptions
		deps    factoryRunnerDependencies
		exec    FactoryExecutionIdentity
	}{
		{"nil verifier", options, factoryRunnerDependencies{ToolIdentity: tool}, execution},
		{"invalid tool", options, factoryRunnerDependencies{Verify: factoryVerifierStub(t)}, execution},
		{"invalid execution", options, dependencies, FactoryExecutionIdentity{}},
		{"padded stage manifest", func() FactoryRunOptions {
			v := options
			v.EvidenceIntakeInputManifestPath = " " + v.EvidenceIntakeInputManifestPath
			return v
		}(), dependencies, execution},
		{"padded preflight authority", func() FactoryRunOptions {
			v := options
			v.Preflight.OODSpecPath = v.Preflight.OODSpecPath + " "
			return v
		}(), dependencies, execution},
		{"duplicate stage manifest", func() FactoryRunOptions {
			v := options
			v.FullFactoryInputManifestPath = v.GraphCompileInputManifestPath
			return v
		}(), dependencies, execution},
		{"missing stage manifest", func() FactoryRunOptions {
			v := options
			v.SemanticExtractionInputManifestPath = filepath.Join(t.TempDir(), "missing.json")
			return v
		}(), dependencies, execution},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := runDocumentationFactoryWithExecution(test.options, test.deps, test.exec); err == nil {
				t.Fatal("substituted orchestration input was accepted")
			}
		})
	}

	for _, raw := range [][]byte{fixture.evidenceRequest.raw, fixture.semanticRequest.raw, fixture.graphRequest.raw, fixture.fullRequest.raw} {
		if materials, err := factoryExpectedStageMaterials(raw); err != nil || len(materials) == 0 {
			t.Fatalf("valid stage material roster=%v err=%v", materials, err)
		}
	}
	badDigest := fixture.evidenceRequest.request
	badDigest.AuthorityPins.OODGraph.RawSHA256 = "not-a-digest"
	if _, err := factoryExpectedStageMaterials(mustStageJSON(t, badDigest)); err == nil {
		t.Fatal("invalid authority material digest was accepted")
	}
	aliasedAuthority := fixture.evidenceRequest.request
	aliasedAuthority.AuthorityPins.GrandVision = aliasedAuthority.AuthorityPins.OODGraph
	aliasedAuthority.AuthorityPins.GrandVision.RawSHA256 = strings.Repeat("b", 64)
	if _, err := factoryExpectedStageMaterials(mustStageJSON(t, aliasedAuthority)); err == nil {
		t.Fatal("conflicting authority coordinates were accepted")
	}
	aliasedDependency := fixture.graphRequest.request
	second := aliasedDependency.DependencyArtifacts[0]
	second.RawSHA256 = strings.Repeat("c", 64)
	aliasedDependency.DependencyArtifacts = append(aliasedDependency.DependencyArtifacts, second)
	if _, err := factoryExpectedStageMaterials(mustStageJSON(t, aliasedDependency)); err == nil {
		t.Fatal("conflicting dependency coordinates were accepted")
	}

	declared := make([]factoryDeclaredMaterial, len(fixture.evidenceRequest.inputs.Materials))
	for index, material := range fixture.evidenceRequest.inputs.Materials {
		declared[index] = factoryDeclaredMaterial{coordinate: stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}, raw: material.Raw}
	}
	if _, err := completeFactoryStageMaterials(fixture.evidenceRequest.raw, nil, nil); err == nil {
		t.Fatal("factory stage accepted no validation profile material")
	}
	duplicateMaterial := append(append([]factoryDeclaredMaterial(nil), declared...), declared[0])
	if _, err := completeFactoryStageMaterials(fixture.evidenceRequest.raw, duplicateMaterial, nil); err == nil {
		t.Fatal("duplicate whole-run material coordinate was accepted")
	}
	extraMaterial := append(append([]factoryDeclaredMaterial(nil), declared...), factoryDeclaredMaterial{coordinate: stageMaterialCoordinate{Role: "extra", ID: "extra", Version: "v1"}, raw: []byte("extra")})
	if _, err := completeFactoryStageMaterials(fixture.evidenceRequest.raw, extraMaterial, nil); err == nil {
		t.Fatal("unbound factory material was accepted")
	}
	if _, _, err := factoryManifestMaterials(options.EvidenceIntakeInputManifestPath, stageCompileInputAdmissionBinding{}, StageCompileInputs{}); err == nil {
		t.Fatal("empty stage admission binding was accepted")
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	_, loaded, binding, err := loadStageCompileFileManifestWithAdmission(options.EvidenceIntakeInputManifestPath, accumulator)
	if err != nil {
		t.Fatal(err)
	}
	if _, materialRows, err := factoryManifestMaterials(options.EvidenceIntakeInputManifestPath, binding, loaded); err != nil || len(materialRows) == 0 {
		t.Fatalf("valid factory manifest binding=%v err=%v", materialRows, err)
	}
	cloneBinding := func() stageCompileInputAdmissionBinding {
		copy := binding
		copy.Items = append([]stageCompileInputAdmissionItem(nil), binding.Items...)
		return copy
	}
	invalidManifest := cloneBinding()
	invalidManifest.Items[0].Raw = []byte("not-json")
	if _, _, err := factoryManifestMaterials(options.EvidenceIntakeInputManifestPath, invalidManifest, loaded); err == nil {
		t.Fatal("invalid manifest bytes were accepted")
	}
	shortBinding := cloneBinding()
	shortBinding.Items = shortBinding.Items[:len(shortBinding.Items)-1]
	if _, _, err := factoryManifestMaterials(options.EvidenceIntakeInputManifestPath, shortBinding, loaded); err == nil {
		t.Fatal("truncated stage binding was accepted")
	}
	wrongCoordinate := loaded
	wrongCoordinate.Materials = append([]StageMaterial(nil), loaded.Materials...)
	wrongCoordinate.Materials[0].Role = "wrong"
	if _, _, err := factoryManifestMaterials(options.EvidenceIntakeInputManifestPath, cloneBinding(), wrongCoordinate); err == nil {
		t.Fatal("mislabelled loaded material was accepted")
	}
	wrongReceipt := cloneBinding()
	wrongReceipt.Items[2].Resource.ContentSHA256 = strings.Repeat("0", 64)
	if _, _, err := factoryManifestMaterials(options.EvidenceIntakeInputManifestPath, wrongReceipt, loaded); err == nil {
		t.Fatal("material without exact input receipt binding was accepted")
	}
	var manifest stageCompileFileManifest
	if err := strictUnmarshal(binding.Items[0].Raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Materials[0].Path = ""
	badPath := cloneBinding()
	badPath.Items[0].Raw, err = canonicalFactoryJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := factoryManifestMaterials(options.EvidenceIntakeInputManifestPath, badPath, loaded); err == nil {
		t.Fatal("empty material path was accepted")
	}
}

func TestFactoryRunnerReceiptValidatorRejectsCompletionAndStageSubstitution(t *testing.T) {
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	receipt, err := runDocumentationFactory(options, factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: testFactoryToolIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*FactoryRunReceipt)
	}{
		{"identity", func(v *FactoryRunReceipt) { v.ReceiptKind = "wrong" }},
		{"stage cardinality", func(v *FactoryRunReceipt) { v.Stages = v.Stages[:3] }},
		{"stage kind", func(v *FactoryRunReceipt) { v.Stages[0].StageKind = "wrong" }},
		{"stage preflight binding", func(v *FactoryRunReceipt) {
			v.PreflightReceipt.GraphCompileStageReceiptSHA256 = strings.Repeat("0", 64)
		}},
		{"completion overclaim", func(v *FactoryRunReceipt) { v.Completion.Deployed = true }},
		{"portable digest", func(v *FactoryRunReceipt) { v.PortableReceiptSHA256 = strings.Repeat("0", 64) }},
		{"receipt digest", func(v *FactoryRunReceipt) { v.ReceiptSHA256 = strings.Repeat("0", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := receipt
			candidate.Stages = append([]FactoryStageRunReceipt(nil), receipt.Stages...)
			test.mutate(&candidate)
			if err := validateFactoryRunReceipt(candidate); err == nil {
				t.Fatal("receipt substitution was accepted")
			}
		})
	}
	badProof := receipt
	badProof.InputAdmissionProof.ProofSHA256 = ""
	badProof, err = sealFactoryRunReceipt(badProof)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFactoryRunReceipt(badProof); err == nil {
		t.Fatal("invalid whole-run input-admission proof was accepted")
	}
	badPreflight := receipt
	badPreflight.PreflightReceipt.GraphCompileStageReceiptSHA256 = strings.Repeat("0", 64)
	badPreflight.PreflightReceipt, err = sealReceipt(badPreflight.PreflightReceipt)
	if err != nil {
		t.Fatal(err)
	}
	badPreflight, err = sealFactoryRunReceipt(badPreflight)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFactoryRunReceipt(badPreflight); err == nil {
		t.Fatal("cross-bound graph preflight receipt was accepted")
	}
	badStage := receipt
	badStage.Stages = append([]FactoryStageRunReceipt(nil), receipt.Stages...)
	badStage.Stages[0].ReceiptSHA256 = ""
	if err := validateFactoryRunReceipt(badStage); err == nil {
		t.Fatal("incomplete stage receipt identity was accepted")
	}
	badPreflightIdentity := receipt
	badPreflightIdentity.PreflightReceipt.ReceiptKind = "wrong"
	if err := validateFactoryRunReceipt(badPreflightIdentity); err == nil {
		t.Fatal("invalid nested preflight receipt identity was accepted")
	}
}

func setFactoryBuildSetting(settings []FactoryBuildSetting, key, value string) {
	for index := range settings {
		if settings[index].Key == key {
			settings[index].Value = value
			return
		}
	}
}

func factoryStableExecutableOperations(path string) factoryExecutableIdentityOperations {
	return factoryExecutableIdentityOperations{
		executable: func() (string, error) { return path, nil }, initialLstat: os.Lstat, initialOpen: os.Open,
		open: os.Open, finalLstat: os.Lstat, finalOpen: os.Open,
	}
}

func factoryOpenFailure(string) (*os.File, error) { return nil, os.ErrNotExist }

func factoryClosedOpen(t *testing.T, path string) func(string) (*os.File, error) {
	t.Helper()
	return func(string) (*os.File, error) {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		return file, nil
	}
}

func factoryTestBuildInfo() *debug.BuildInfo {
	return &debug.BuildInfo{
		Path: factoryRunnerCommandPath, GoVersion: "go1.test",
		Main: debug.Module{Path: factoryRunnerModulePath, Version: "v1.0.0", Sum: "h1:main"},
		Settings: []debug.BuildSetting{
			{Key: "-buildmode", Value: "exe"}, {Key: "-compiler", Value: "gc"}, {Key: "-tags", Value: factoryReleaseBuildTag},
			{Key: "CGO_ENABLED", Value: "0"}, {Key: "GOOS", Value: "linux"}, {Key: "GOARCH", Value: "amd64"},
			{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: strings.Repeat("a", 40)}, {Key: "vcs.time", Value: "2026-01-01T00:00:00Z"}, {Key: "vcs.modified", Value: "false"},
		},
	}
}

func cloneFactoryBuildInfo(source *debug.BuildInfo) *debug.BuildInfo {
	copy := *source
	copy.Settings = append([]debug.BuildSetting(nil), source.Settings...)
	return &copy
}

func setDebugBuildSetting(settings []debug.BuildSetting, key, value string) {
	for index := range settings {
		if settings[index].Key == key {
			settings[index].Value = value
			return
		}
	}
}
