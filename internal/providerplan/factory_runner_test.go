package providerplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestDocumentationFactoryRunnerIsDeterministicPathIndependentAndBodyFree(t *testing.T) {
	t.Parallel()
	tool := testFactoryToolIdentity()
	run := func(root string, reversePreflightLists bool) FactoryRunReceipt {
		t.Helper()
		fixture := newStageContractFixture(t)
		options := writeFactoryRunnerFixture(t, root, fixture)
		if reversePreflightLists {
			reverseStrings(options.Preflight.EvidenceManifestPath)
			reverseStrings(options.Preflight.DependencyArtifactPath)
		}
		for _, path := range append(append([]string(nil), options.stageManifestPaths()...), options.preflightPaths()...) {
			stamp := time.Unix(1_800_000_000, int64(len(path)))
			if err := os.Chtimes(path, stamp, stamp); err != nil {
				t.Fatal(err)
			}
		}
		receipt, err := runDocumentationFactory(options, factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: tool})
		if err != nil {
			t.Fatal(err)
		}
		return receipt
	}

	first := run(filepath.Join(t.TempDir(), "first"), false)
	second := run(filepath.Join(t.TempDir(), "second"), true)
	firstRaw := mustFactoryReceiptJSON(t, first)
	secondRaw := mustFactoryReceiptJSON(t, second)
	if !bytes.Equal(firstRaw, secondRaw) {
		t.Fatalf("path, argument order, or mtime changed the factory receipt:\nfirst=%s\nsecond=%s", firstRaw, secondRaw)
	}
	if bytes.Contains(firstRaw, []byte("Exact selected documentation")) || bytes.Contains(firstRaw, []byte("source-declared machine export evidence line")) {
		t.Fatal("factory receipt embeds selected evidence body bytes")
	}
	if err := validateFactoryRunReceipt(first); err != nil {
		t.Fatalf("validate factory receipt: %v", err)
	}
	if len(first.Stages) != 4 {
		t.Fatalf("stage count = %d, want 4", len(first.Stages))
	}
	wantOrder := []string{stageEvidenceIntake, stageSemanticExtraction, stageGraphCompile, stageFullFactory}
	for index, want := range wantOrder {
		if first.Stages[index].StageKind != want {
			t.Fatalf("stage %d kind = %q, want %q", index, first.Stages[index].StageKind, want)
		}
	}
	if first.InputAdmissionProof.Actuals.StageInputManifestCount != 4 {
		t.Fatalf("whole-run stage manifest count = %d, want 4", first.InputAdmissionProof.Actuals.StageInputManifestCount)
	}
	if !first.Completion.Compiled || !first.Completion.Verified || !first.Completion.DerivationExecuted ||
		first.Completion.GraphAdmittable || first.Completion.Admitted || first.Completion.CircuitAdmittable ||
		first.Completion.CircuitAdmitted || first.Completion.Configured || first.Completion.CredentialProvisioned ||
		first.Completion.Deployed || first.Completion.LiveTested || first.Completion.TwoTenantProven ||
		first.Completion.SourceSubstitutionProven || first.Completion.AuthoritySelected ||
		first.Completion.AdmissionAuthorized || first.Completion.FactoryComplete {
		t.Fatalf("factory completion classification overclaims: %+v", first.Completion)
	}
}

func TestFactoryReleaseCountsAndExecutableHashRejectInvalidInputs(t *testing.T) {
	for _, test := range []struct {
		value string
		want  int64
	}{{"1", 1}, {"42", 42}, {"0", 0}, {"-1", 0}, {"bad", 0}} {
		if got := parseFactoryReleaseCount(test.value); got != test.want {
			t.Fatalf("parseFactoryReleaseCount(%q) = %d, want %d", test.value, got, test.want)
		}
	}
	path := filepath.Join(t.TempDir(), "factory")
	if err := os.WriteFile(path, []byte("factory-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	digest, count, err := hashFactoryExecutable(file)
	if closeErr := file.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil || count != int64(len("factory-bytes")) || !isLowerSHA256(digest) {
		t.Fatalf("hashFactoryExecutable() = (%q, %d, %v)", digest, count, err)
	}
}

func TestDocumentationFactoryRunnerSharesOneImmutableEvidenceCorpus(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	var firstBody *byte
	locations := map[string]bool{}
	materialLocations := map[string]bool{}
	materialBackings := map[stageMaterialCoordinate]*byte{}
	dependencies := factoryRunnerDependencies{
		Verify:       factoryVerifierStub(t),
		ToolIdentity: testFactoryToolIdentity(),
		ObserveEvidenceBodies: func(location string, bodies []StageEvidenceBody, retainedStageCollections int) {
			locations[location] = true
			if retainedStageCollections != 0 {
				t.Errorf("%s retained %d completed-stage evidence collections, want zero", location, retainedStageCollections)
			}
			if len(bodies) == 0 || len(bodies[0].Raw) == 0 {
				t.Errorf("%s observed no evidence body bytes", location)
				return
			}
			current := &bodies[0].Raw[0]
			if firstBody == nil {
				firstBody = current
			} else if current != firstBody {
				t.Errorf("%s received a cloned evidence body backing store", location)
			}
		},
		ObserveMaterialBodies: func(location string, materials []StageMaterial, retainedStageCollections int) {
			materialLocations[location] = true
			if retainedStageCollections != 0 {
				t.Errorf("%s retained %d completed-stage material collections, want zero", location, retainedStageCollections)
			}
			for _, material := range materials {
				if len(material.Raw) == 0 {
					continue
				}
				coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
				current := &material.Raw[0]
				if prior, exists := materialBackings[coordinate]; exists && prior != current {
					t.Errorf("%s received a cloned material backing store for %+v", location, coordinate)
				} else if !exists {
					materialBackings[coordinate] = current
				}
			}
		},
	}
	if _, err := runDocumentationFactory(options, dependencies); err != nil {
		t.Fatal(err)
	}
	wantLocations := []string{
		"stage:" + stageEvidenceIntake,
		"stage:" + stageSemanticExtraction,
		"stage:" + stageGraphCompile,
		"stage:" + stageFullFactory,
		"verifier:graph_compile_loader",
	}
	for _, location := range wantLocations {
		if !locations[location] {
			t.Errorf("evidence storage observer did not see %s", location)
		}
		if !materialLocations[location] {
			t.Errorf("material storage observer did not see %s", location)
		}
	}
}

func TestDocumentationFactoryRunnerRejectsStageSubstitutionAndDuplicatePreflightPath(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	dependencies := factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: testFactoryToolIdentity()}

	swapped := options
	swapped.EvidenceIntakeInputManifestPath, swapped.SemanticExtractionInputManifestPath = swapped.SemanticExtractionInputManifestPath, swapped.EvidenceIntakeInputManifestPath
	if _, err := runDocumentationFactory(swapped, dependencies); err == nil || !strings.Contains(err.Error(), "stage_kind") {
		t.Fatalf("swapped stage manifests error = %v, want stage_kind refusal", err)
	}

	duplicate := options
	duplicate.Preflight.DependencyArtifactPath = append(append([]string(nil), duplicate.Preflight.DependencyArtifactPath...), duplicate.Preflight.DependencyArtifactPath[0])
	if _, err := runDocumentationFactory(duplicate, dependencies); err == nil || !strings.Contains(err.Error(), "path duplicates dependency_artifact[0]") {
		t.Fatalf("duplicate preflight path error = %v, want duplicate-path refusal", err)
	}
}

func TestDocumentationFactoryRunnerRecordsOneInitialAdmissionTraversalPerInput(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	checked := false
	dependencies := factoryRunnerDependencies{
		Verify:       factoryVerifierStub(t),
		ToolIdentity: testFactoryToolIdentity(),
		BeforeFinalInputCheck: func(accumulator *providerInputAdmissionAccumulator) error {
			checked = true
			if len(accumulator.physicalSnapshots) == 0 {
				return fmt.Errorf("factory retained no physical input snapshots")
			}
			for path, snapshot := range accumulator.physicalSnapshots {
				if snapshot.initialTraversalCount != 1 {
					return fmt.Errorf("physical input %q initial admission traversal count = %d, want 1", path, snapshot.initialTraversalCount)
				}
				if snapshot.initialTraversalBytes != snapshot.size {
					return fmt.Errorf("physical input %q initial admission traversal bytes = %d, want exact size %d", path, snapshot.initialTraversalBytes, snapshot.size)
				}
			}
			return nil
		},
	}
	if _, err := runDocumentationFactory(options, dependencies); err != nil {
		t.Fatal(err)
	}
	if !checked {
		t.Fatal("factory final physical-snapshot observer was not called")
	}
}

func TestDocumentationFactoryRunnerRejectsLateByteIdenticalInputReplacement(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		selectPath func(*testing.T, FactoryRunOptions) string
	}{
		{name: "stage_manifest", selectPath: func(_ *testing.T, options FactoryRunOptions) string { return options.EvidenceIntakeInputManifestPath }},
		{name: "stage_request", selectPath: func(t *testing.T, options FactoryRunOptions) string {
			manifest := readFactoryStageManifestForMutationTest(t, options.SemanticExtractionInputManifestPath)
			return filepath.Join(filepath.Dir(options.SemanticExtractionInputManifestPath), filepath.FromSlash(manifest.RequestPath))
		}},
		{name: "stage_only_material", selectPath: func(t *testing.T, options FactoryRunOptions) string {
			manifest := readFactoryStageManifestForMutationTest(t, options.FullFactoryInputManifestPath)
			if len(manifest.Materials) == 0 {
				t.Fatal("full_factory fixture has no stage-only material")
			}
			return filepath.Join(filepath.Dir(options.FullFactoryInputManifestPath), filepath.FromSlash(manifest.Materials[0].Path))
		}},
		{name: "intake_body", selectPath: func(t *testing.T, options FactoryRunOptions) string {
			manifest := readFactoryStageManifestForMutationTest(t, options.EvidenceIntakeInputManifestPath)
			if len(manifest.EvidenceBodies) == 0 {
				t.Fatal("evidence_intake fixture has no body")
			}
			return filepath.Join(filepath.Dir(options.EvidenceIntakeInputManifestPath), filepath.FromSlash(manifest.EvidenceBodies[0].Path))
		}},
		{name: "ood_authority", selectPath: func(_ *testing.T, options FactoryRunOptions) string { return options.Preflight.OODSpecPath }},
		{name: "evidence_manifest", selectPath: func(_ *testing.T, options FactoryRunOptions) string { return options.Preflight.EvidenceManifestPath[0] }},
		{name: "dependency", selectPath: func(_ *testing.T, options FactoryRunOptions) string {
			return options.Preflight.DependencyArtifactPath[0]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStageContractFixture(t)
			options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
			target := test.selectPath(t, options)
			dependencies := factoryRunnerDependencies{
				Verify:       factoryVerifierStub(t),
				ToolIdentity: testFactoryToolIdentity(),
				BeforeFinalInputCheck: func(*providerInputAdmissionAccumulator) error {
					replaceFactoryInputWithByteIdenticalFile(t, target)
					return nil
				},
			}
			_, err := runDocumentationFactory(options, dependencies)
			if err == nil || !strings.Contains(err.Error(), "changed after its exact physical snapshot") {
				t.Fatalf("late replacement error = %v, want final physical-identity refusal", err)
			}
		})
	}
}

func readFactoryStageManifestForMutationTest(t *testing.T, path string) stageCompileFileManifest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var manifest stageCompileFileManifest
	if err := strictUnmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func replaceFactoryInputWithByteIdenticalFile(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	backup := path + ".original"
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
}

func TestDocumentationFactoryRunnerRejectsPreflightCoordinateAndCorpusSubstitution(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	dependencies := factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: testFactoryToolIdentity()}

	wrongAuthority := options
	wrongAuthority.Preflight.OODSpecPath = options.Preflight.DependencyArtifactPath[0]
	wrongAuthority.Preflight.ExpectedOODSpecSHA256 = factoryPathHashes(t, []string{wrongAuthority.Preflight.OODSpecPath})[0]
	if _, err := runDocumentationFactory(wrongAuthority, dependencies); err == nil || !strings.Contains(err.Error(), "want exact intake coordinate") {
		t.Fatalf("authority-coordinate substitution error = %v, want exact intake-coordinate refusal", err)
	}

	wrongCorpus := options
	wrongCorpus.Preflight.EvidenceManifestPath = []string{options.Preflight.DependencyArtifactPath[0]}
	if _, err := runDocumentationFactory(wrongCorpus, dependencies); err == nil || !strings.Contains(err.Error(), "outside the exact intake roster") {
		t.Fatalf("evidence-corpus substitution error = %v, want exact intake-roster refusal", err)
	}

	omittedCorpus := options
	omittedCorpus.Preflight.EvidenceManifestPath = nil
	if _, err := runDocumentationFactory(omittedCorpus, dependencies); err == nil || !strings.Contains(err.Error(), "differs from exact intake roster") {
		t.Fatalf("evidence-corpus omission error = %v, want set-equality refusal", err)
	}
}

func TestDocumentationFactoryRunnerRejectsLaterStageExternalLineageFiles(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	manifestRaw, err := os.ReadFile(options.SemanticExtractionInputManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest stageCompileFileManifest
	if err := strictUnmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(filepath.Dir(options.SemanticExtractionInputManifestPath), "external-predecessor.json")
	if err := os.WriteFile(receiptPath, fixture.evidenceReceipt, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest.PredecessorReceiptPaths = []string{filepath.Base(receiptPath)}
	writeFactoryJSON(t, options.SemanticExtractionInputManifestPath, manifest)

	_, err = runDocumentationFactory(options, factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: testFactoryToolIdentity()})
	if err == nil || !strings.Contains(err.Error(), "predecessor_receipt_paths must be empty") {
		t.Fatalf("external predecessor error = %v, want runner-owned lineage refusal", err)
	}
}

func TestFactoryToolIdentityBindsPortableBuildRecipeAndRepository(t *testing.T) {
	identity := testFactoryToolIdentity()
	changedRecipe := identity
	changedRecipe.BuildRecipeSHA256 = strings.Repeat("e", 64)
	changedRecipe.BuildIdentitySHA256 = ""
	changedRecipe, err := sealFactoryToolIdentity(changedRecipe)
	if err != nil {
		t.Fatal(err)
	}
	if changedRecipe.BuildIdentitySHA256 == identity.BuildIdentitySHA256 {
		t.Fatal("changed portable build recipe did not change the factory build identity")
	}

	wrongRepository := identity
	wrongRepository.ModulePath = "example.invalid/spec-graph-lookalike"
	wrongRepository.BuildIdentitySHA256 = ""
	if _, err := sealFactoryToolIdentity(wrongRepository); err == nil {
		t.Fatal("foreign module path was accepted as the factory runner")
	}

	wrongCommand := identity
	wrongCommand.CommandPath = factoryRunnerModulePath + "/cmd/provider-plan-verify"
	wrongCommand.BuildIdentitySHA256 = ""
	if _, err := sealFactoryToolIdentity(wrongCommand); err == nil {
		t.Fatal("different same-module command path was accepted as the factory runner")
	}

	missingMetadata := identity
	missingMetadata.ModuleGraphSHA256 = ""
	missingMetadata.BuildIdentitySHA256 = ""
	if _, err := sealFactoryToolIdentity(missingMetadata); err == nil {
		t.Fatal("missing exact module-graph digest was accepted")
	}

	wrongTags := identity
	wrongTags.BuildTags = "factory_release,unapproved"
	wrongTags.BuildIdentitySHA256 = ""
	if _, err := sealFactoryToolIdentity(wrongTags); err == nil || !strings.Contains(err.Error(), "build tags") {
		t.Fatalf("non-release tool build-tag error = %v, want fixed-tag refusal", err)
	}
}

func TestFactoryBuildMetadataRejectsUnpinnedLocalModuleReplacement(t *testing.T) {
	info := &debug.BuildInfo{
		Path:      factoryRunnerCommandPath,
		GoVersion: "go1.27.0",
		Main:      debug.Module{Path: factoryRunnerModulePath, Version: "(devel)"},
		Deps: []*debug.Module{{
			Path:    "example.test/dependency",
			Version: "v1.2.3",
			Sum:     "h1:dependency",
			Replace: &debug.Module{Path: "../outside-source"},
		}},
	}
	if _, err := canonicalFactoryBuildMetadata(info); err == nil || !strings.Contains(err.Error(), "unpinned local replacement") {
		t.Fatalf("local replacement error = %v, want fail-closed unpinned replacement refusal", err)
	}
}

func TestFactoryBuildMetadataAcceptsPinnedVersionedModuleReplacement(t *testing.T) {
	info := &debug.BuildInfo{
		Path:      factoryRunnerCommandPath,
		GoVersion: "go1.27.0",
		Main:      debug.Module{Path: factoryRunnerModulePath, Version: "(devel)"},
		Deps: []*debug.Module{{
			Path:    "example.test/dependency",
			Version: "v1.2.3",
			Sum:     "h1:dependency",
			Replace: &debug.Module{Path: "example.test/replacement", Version: "v1.4.0", Sum: "h1:replacement"},
		}},
	}
	metadata, err := canonicalFactoryBuildMetadata(info)
	if err != nil {
		t.Fatal(err)
	}
	if len(metadata.Dependencies) != 1 {
		t.Fatalf("dependency count = %d, want 1", len(metadata.Dependencies))
	}
	dependency := metadata.Dependencies[0]
	if dependency.ReplacePath != "example.test/replacement" || dependency.ReplaceVersion != "v1.4.0" || dependency.ReplaceSum != "h1:replacement" {
		t.Fatalf("pinned replacement metadata = %+v, want exact versioned replacement identity", dependency)
	}
}

func TestFactoryToolIdentityIsPortableAcrossWindowsAndMacTargets(t *testing.T) {
	portablePins := factoryReleaseBuildPins{SourceRosterSHA256: strings.Repeat("f", 64)}
	windowsPins := portablePins
	windowsPins.GoExecutableSHA256 = strings.Repeat("1", 64)
	windowsPins.GitExecutableSHA256 = strings.Repeat("2", 64)
	windowsPins.GoToolchainSHA256 = strings.Repeat("5", 64)
	windowsPins.GitToolchainSHA256 = strings.Repeat("6", 64)
	windowsPins.GoToolchainFiles, windowsPins.GoToolchainBytes = 10, 100
	windowsPins.GitToolchainFiles, windowsPins.GitToolchainBytes = 20, 200
	macPins := portablePins
	macPins.GoExecutableSHA256 = strings.Repeat("3", 64)
	macPins.GitExecutableSHA256 = strings.Repeat("4", 64)
	macPins.GoToolchainSHA256 = strings.Repeat("7", 64)
	macPins.GitToolchainSHA256 = strings.Repeat("8", 64)
	macPins.GoToolchainFiles, macPins.GoToolchainBytes = 11, 101
	macPins.GitToolchainFiles, macPins.GitToolchainBytes = 21, 201
	buildInfo := func(goos, goarch string, targetSettings ...debug.BuildSetting) *debug.BuildInfo {
		settings := []debug.BuildSetting{
			{Key: "-buildmode", Value: "exe"},
			{Key: "-compiler", Value: "gc"},
			{Key: "-tags", Value: "factory_release"},
			{Key: "-trimpath", Value: "true"},
			{Key: "CGO_ENABLED", Value: "0"},
			{Key: "GOOS", Value: goos},
			{Key: "GOARCH", Value: goarch},
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: strings.Repeat("a", 40)},
			{Key: "vcs.time", Value: "2026-08-25T00:00:00Z"},
			{Key: "vcs.modified", Value: "false"},
		}
		settings = append(settings, targetSettings...)
		return &debug.BuildInfo{
			Path:      factoryRunnerCommandPath,
			GoVersion: "go1.25.0",
			Main:      debug.Module{Path: factoryRunnerModulePath, Version: "v0.0.0-test", Sum: "h1:main"},
			Deps:      []*debug.Module{{Path: "example.test/dependency", Version: "v1.2.3", Sum: "h1:dependency"}},
			Settings:  settings,
		}
	}
	windowsInfo := buildInfo("windows", "amd64", debug.BuildSetting{Key: "GOAMD64", Value: "v1"})
	macInfo := buildInfo("darwin", "arm64", debug.BuildSetting{Key: "GOARM64", Value: "v8.0"})
	uppercaseRevisionInfo := buildInfo("windows", "amd64", debug.BuildSetting{Key: "GOAMD64", Value: "v1"})
	for index := range uppercaseRevisionInfo.Settings {
		if uppercaseRevisionInfo.Settings[index].Key == "vcs.revision" {
			uppercaseRevisionInfo.Settings[index].Value = strings.ToUpper(uppercaseRevisionInfo.Settings[index].Value)
		}
	}
	if _, err := factoryToolIdentityFromBuildInfoWithPins(uppercaseRevisionInfo, "windows", "amd64", windowsPins); err == nil {
		t.Fatal("non-canonical embedded VCS revision was normalized instead of rejected")
	}
	windows, err := factoryToolIdentityFromBuildInfoWithPins(windowsInfo, "windows", "amd64", windowsPins)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := factoryToolIdentityFromBuildInfoWithPins(macInfo, "darwin", "arm64", macPins)
	if err != nil {
		t.Fatal(err)
	}
	if windows != mac {
		t.Fatalf("portable factory identities differ across Windows and macOS targets:\nwindows=%+v\nmac=%+v", windows, mac)
	}
	windowsExecution, err := factoryExecutionIdentityFromBuildInfoWithPins(windowsInfo, "windows", "amd64", windows, strings.Repeat("d", 64), 1024, windowsPins)
	if err != nil {
		t.Fatal(err)
	}
	macExecution, err := factoryExecutionIdentityFromBuildInfoWithPins(macInfo, "darwin", "arm64", mac, strings.Repeat("e", 64), 2048, macPins)
	if err != nil {
		t.Fatal(err)
	}
	if windowsExecution.PortableBuildIdentitySHA256 != macExecution.PortableBuildIdentitySHA256 {
		t.Fatal("target-specific execution identities do not bind the same portable build identity")
	}
	if windowsExecution.ExecutionIdentitySHA256 == macExecution.ExecutionIdentitySHA256 {
		t.Fatal("Windows and macOS exact execution identities unexpectedly match")
	}
}

func TestFactoryRunReceiptRejectsExecutionProfileIdentityAndReportSubstitution(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	receipt, err := runDocumentationFactory(options, factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: testFactoryToolIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	validationRaw, err := canonicalFactoryJSON(receipt.ValidationIdentity)
	if err != nil {
		t.Fatal(err)
	}
	validationResultMember := []byte(`"result":"` + factoryValidationResult + `"`)
	if !bytes.Contains(validationRaw, validationResultMember) || bytes.Contains(validationRaw, []byte(`"result":"pass"`)) {
		t.Fatalf("serialized factory validation identity does not carry only the candidate runtime result: %s", validationRaw)
	}
	reportRaw, err := canonicalFactoryJSON(factoryValidationReportForReceipt(receipt))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(reportRaw, validationResultMember) || bytes.Contains(reportRaw, []byte(`"result":"pass"`)) {
		t.Fatalf("serialized factory validation report does not carry only the candidate runtime result: %s", reportRaw)
	}
	executionIdentityRaw, err := canonicalFactoryJSON(receipt.ExecutionIdentity)
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range [][]byte{
		[]byte(`"build_metadata_source":"` + factoryBuildMetadataSource + `"`),
		[]byte(`"executable_measurement_scope":"` + factoryExecutableScope + `"`),
	} {
		if !bytes.Contains(executionIdentityRaw, member) {
			t.Fatalf("serialized factory execution identity omits %s: %s", member, executionIdentityRaw)
		}
	}

	toolSubstitution := receipt
	toolSubstitution.ToolIdentity.CommandPath = factoryRunnerModulePath + "/cmd/provider-plan-verify"
	resealFactoryFinalDigestForTest(t, &toolSubstitution)
	if err := validateFactoryRunReceipt(toolSubstitution); err == nil || !strings.Contains(err.Error(), "command path") {
		t.Fatalf("tool-identity substitution error = %v, want exact-command refusal", err)
	}

	portableSubstitution := receipt
	portableSubstitution.PortableReceiptSHA256 = strings.Repeat("a", 64)
	resealFactoryFinalDigestForTest(t, &portableSubstitution)
	if err := validateFactoryRunReceipt(portableSubstitution); err == nil || !strings.Contains(err.Error(), "portable receipt digest") {
		t.Fatalf("portable-receipt substitution error = %v, want recomputed-portable-root refusal", err)
	}

	wrongProfile := receipt.ExecutionIdentity
	wrongProfile.BuildSettings = append([]factoryBuildSetting(nil), receipt.ExecutionIdentity.BuildSettings...)
	for index := range wrongProfile.BuildSettings {
		if wrongProfile.BuildSettings[index].Key == "CGO_ENABLED" {
			wrongProfile.BuildSettings[index].Value = "1"
		}
	}
	settingsRaw, err := canonicalFactoryJSON(wrongProfile.BuildSettings)
	if err != nil {
		t.Fatal(err)
	}
	wrongProfile.BuildSettingsSHA256 = sha256Hex(settingsRaw)
	wrongProfile.ExecutionIdentitySHA256 = ""
	if _, err := sealFactoryExecutionIdentity(wrongProfile, receipt.ToolIdentity); err == nil || !strings.Contains(err.Error(), "release build profile") {
		t.Fatalf("CGO-enabled profile substitution error = %v, want release-profile refusal", err)
	}

	reorderedSettings := receipt
	reorderedSettings.ExecutionIdentity.BuildSettings = append([]factoryBuildSetting(nil), receipt.ExecutionIdentity.BuildSettings...)
	reorderedSettings.ExecutionIdentity.BuildSettings[0], reorderedSettings.ExecutionIdentity.BuildSettings[1] = reorderedSettings.ExecutionIdentity.BuildSettings[1], reorderedSettings.ExecutionIdentity.BuildSettings[0]
	settingsRaw, err = canonicalFactoryJSON(reorderedSettings.ExecutionIdentity.BuildSettings)
	if err != nil {
		t.Fatal(err)
	}
	reorderedSettings.ExecutionIdentity.BuildSettingsSHA256 = sha256Hex(settingsRaw)
	reorderedSettings.ExecutionIdentity.ExecutionIdentitySHA256 = ""
	executionRaw, err := canonicalFactoryJSON(reorderedSettings.ExecutionIdentity)
	if err != nil {
		t.Fatal(err)
	}
	reorderedSettings.ExecutionIdentity.ExecutionIdentitySHA256 = sha256Hex(executionRaw)
	resealFactoryFinalDigestForTest(t, &reorderedSettings)
	if err := validateFactoryRunReceipt(reorderedSettings); err == nil || !strings.Contains(err.Error(), "canonical order") {
		t.Fatalf("reordered build-settings substitution error = %v, want canonical-order refusal", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*FactoryExecutionIdentity)
	}{
		{name: "build metadata source", mutate: func(identity *FactoryExecutionIdentity) { identity.BuildMetadataSource = "caller_claim" }},
		{name: "executable measurement scope", mutate: func(identity *FactoryExecutionIdentity) {
			identity.ExecutableMeasurementScope = "mapped_running_image_bytes"
		}},
	} {
		t.Run(test.name+" substitution", func(t *testing.T) {
			candidate := receipt
			test.mutate(&candidate.ExecutionIdentity)
			recomputeFactoryExecutionIdentityDigestForTest(t, &candidate.ExecutionIdentity)
			sealedCandidate, sealErr := sealFactoryRunReceipt(candidate)
			if sealErr != nil {
				t.Fatal(sealErr)
			}
			if err := validateFactoryRunReceipt(sealedCandidate); err == nil || !strings.Contains(err.Error(), "measurement source or scope") {
				t.Fatalf("%s substitution error = %v, want sealed-measurement refusal", test.name, err)
			}
		})
	}

	upperRevision := receipt.ExecutionIdentity
	upperRevision.BuildSettings = append([]factoryBuildSetting(nil), receipt.ExecutionIdentity.BuildSettings...)
	for index := range upperRevision.BuildSettings {
		if upperRevision.BuildSettings[index].Key == "vcs.revision" {
			upperRevision.BuildSettings[index].Value = strings.ToUpper(upperRevision.BuildSettings[index].Value)
		}
	}
	settingsRaw, err = canonicalFactoryJSON(upperRevision.BuildSettings)
	if err != nil {
		t.Fatal(err)
	}
	upperRevision.BuildSettingsSHA256 = sha256Hex(settingsRaw)
	upperRevision.ExecutionIdentitySHA256 = ""
	if _, err := sealFactoryExecutionIdentity(upperRevision, receipt.ToolIdentity); err == nil || !strings.Contains(err.Error(), "exact clean source revision") {
		t.Fatalf("non-canonical VCS revision error = %v, want exact cross-identity refusal", err)
	}

	tagContradiction := receipt
	tagContradiction.ToolIdentity.BuildTags = "factory_release,unapproved"
	recomputeFactoryToolIdentityDigestForTest(t, &tagContradiction.ToolIdentity)
	tagContradiction.ExecutionIdentity.PortableBuildIdentitySHA256 = tagContradiction.ToolIdentity.BuildIdentitySHA256
	recomputeFactoryExecutionIdentityDigestForTest(t, &tagContradiction.ExecutionIdentity)
	if _, err := sealFactoryExecutionIdentity(tagContradiction.ExecutionIdentity, tagContradiction.ToolIdentity); err == nil || !strings.Contains(err.Error(), "contradict") {
		t.Fatalf("tool/execution build-tag contradiction error = %v, want cross-identity refusal", err)
	}
	tagContradiction, err = sealFactoryRunReceipt(tagContradiction)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFactoryRunReceipt(tagContradiction); err == nil || !strings.Contains(err.Error(), "build tags") {
		t.Fatalf("fully resealed tool build-tag substitution error = %v, want fixed-tag refusal", err)
	}

	identitySubstitution := receipt
	identitySubstitution.ExecutionIdentity.ExecutableSHA256 = strings.Repeat("e", 64)
	identitySubstitution.ExecutionIdentity.ExecutionIdentitySHA256 = ""
	identitySubstitution.ExecutionIdentity, err = sealFactoryExecutionIdentity(identitySubstitution.ExecutionIdentity, identitySubstitution.ToolIdentity)
	if err != nil {
		t.Fatal(err)
	}
	resealFactoryFinalDigestForTest(t, &identitySubstitution)
	if err := validateFactoryRunReceipt(identitySubstitution); err == nil || !strings.Contains(err.Error(), "validation identity") {
		t.Fatalf("execution-identity substitution error = %v, want validation cross-binding refusal", err)
	}

	reportSubstitution := receipt
	reportSubstitution.ValidationIdentity.ValidationReportSHA256 = strings.Repeat("f", 64)
	reportSubstitution.ValidationIdentity.ValidationIdentitySHA256 = ""
	reportSubstitution.ValidationIdentity, err = sealFactoryValidationIdentity(reportSubstitution.ValidationIdentity)
	if err != nil {
		t.Fatal(err)
	}
	resealFactoryFinalDigestForTest(t, &reportSubstitution)
	if err := validateFactoryRunReceipt(reportSubstitution); err == nil || !strings.Contains(err.Error(), "validation identity") {
		t.Fatalf("validation-report substitution error = %v, want recomputed-report refusal", err)
	}

	validationProfileSubstitution := receipt.ValidationIdentity
	validationProfileSubstitution.ProfileVersion = "999"
	validationProfileSubstitution.ValidationIdentitySHA256 = ""
	if _, err := sealFactoryValidationIdentity(validationProfileSubstitution); err == nil || !strings.Contains(err.Error(), "profile identity") {
		t.Fatalf("validation-profile substitution error = %v, want fixed-profile refusal", err)
	}

	validationResultSubstitution := receipt
	validationResultSubstitution.ValidationIdentity.Result = "pass"
	recomputeFactoryValidationIdentityDigestForTest(t, &validationResultSubstitution.ValidationIdentity)
	resealFactoryFinalDigestForTest(t, &validationResultSubstitution)
	if err := validateFactoryRunReceipt(validationResultSubstitution); err == nil || !strings.Contains(err.Error(), "validation identity") {
		t.Fatalf("generic validation-result substitution error = %v, want candidate-runtime-result refusal", err)
	}

	orderedBindingFailure := receipt.ValidationIdentity
	orderedBindingFailure.PortableReceiptSHA256 = ""
	orderedBindingFailure.ToolBuildIdentitySHA256 = ""
	orderedBindingFailure.ValidationIdentitySHA256 = ""
	if _, err := sealFactoryValidationIdentity(orderedBindingFailure); err == nil || !strings.Contains(err.Error(), "portable receipt") {
		t.Fatalf("multi-binding validation error = %v, want deterministic first portable-receipt error", err)
	}
}

func TestFactoryExecutableIdentityRejectsPathSwapBeforeOpen(t *testing.T) {
	initialPath := filepath.Join(t.TempDir(), "initial-executable")
	replacementPath := filepath.Join(t.TempDir(), "replacement-executable")
	for path, body := range map[string][]byte{
		initialPath:     []byte("initial-artifact"),
		replacementPath: []byte("replace-artifact"),
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Unix(1_800_000_000, 0)
	for _, path := range []string{initialPath, replacementPath} {
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}

	_, _, err := factoryExecutableIdentityWithOperations(factoryExecutableIdentityOperations{
		executable:   func() (string, error) { return initialPath, nil },
		initialLstat: os.Lstat,
		initialOpen:  os.Open,
		open: func(string) (*os.File, error) {
			return os.Open(replacementPath)
		},
		finalLstat: os.Lstat,
		finalOpen:  os.Open,
	})
	if err == nil || !strings.Contains(err.Error(), "between path inspection and open") {
		t.Fatalf("pre-open executable substitution error = %v, want identity-mismatch refusal", err)
	}
}

func TestFactoryExecutableIdentityRejectsFinalPathSwap(t *testing.T) {
	initialPath := filepath.Join(t.TempDir(), "initial-executable")
	replacementPath := filepath.Join(t.TempDir(), "replacement-executable")
	for path, body := range map[string][]byte{
		initialPath:     []byte("initial-artifact"),
		replacementPath: []byte("replace-artifact"),
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Unix(1_800_000_000, 0)
	for _, path := range []string{initialPath, replacementPath} {
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}

	_, _, err := factoryExecutableIdentityWithOperations(factoryExecutableIdentityOperations{
		executable:   func() (string, error) { return initialPath, nil },
		initialLstat: os.Lstat,
		initialOpen:  os.Open,
		open:         os.Open,
		finalLstat: func(string) (os.FileInfo, error) {
			return os.Lstat(replacementPath)
		},
		finalOpen: func(string) (*os.File, error) {
			return os.Open(replacementPath)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "changed while its identity was measured") {
		t.Fatalf("final executable-path substitution error = %v, want identity-mismatch refusal", err)
	}
}

func TestFactoryPortableReceiptIsByteIdenticalAcrossTargetAttestations(t *testing.T) {
	t.Parallel()
	fixture := newStageContractFixture(t)
	options := writeFactoryRunnerFixture(t, t.TempDir(), fixture)
	windowsReceipt, err := runDocumentationFactory(options, factoryRunnerDependencies{Verify: factoryVerifierStub(t), ToolIdentity: testFactoryToolIdentity()})
	if err != nil {
		t.Fatal(err)
	}
	macReceipt := windowsReceipt
	macReceipt.ExecutionIdentity = testFactoryExecutionIdentityForTarget(
		macReceipt.ToolIdentity, "darwin", "arm64", "GOARM64", "v8.0", strings.Repeat("e", 64), 2048,
	)
	macReceipt, err = sealFactoryRunReceipt(macReceipt)
	if err != nil {
		t.Fatal(err)
	}
	windowsPortable, err := canonicalFactoryPortableReceiptIdentity(windowsReceipt)
	if err != nil {
		t.Fatal(err)
	}
	macPortable, err := canonicalFactoryPortableReceiptIdentity(macReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(windowsPortable, macPortable) || windowsReceipt.PortableReceiptSHA256 != macReceipt.PortableReceiptSHA256 {
		t.Fatal("target attestation changed the byte-identical portable receipt")
	}
	if windowsReceipt.ReceiptSHA256 == macReceipt.ReceiptSHA256 || windowsReceipt.ValidationIdentity.ValidationReportSHA256 == macReceipt.ValidationIdentity.ValidationReportSHA256 {
		t.Fatal("target-specific execution did not change the full receipt and validation report identities")
	}
	if err := validateFactoryRunReceipt(macReceipt); err != nil {
		t.Fatalf("validate synthetic macOS receipt: %v", err)
	}
}

func writeFactoryRunnerFixture(t *testing.T, root string, fixture stageContractFixture) FactoryRunOptions {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	declared := map[stageMaterialCoordinate]factoryFixtureMaterial{}
	writeStage := func(index int, holderRaw []byte, inputs StageCompileInputs) (string, map[stageMaterialCoordinate]string) {
		t.Helper()
		dir := filepath.Join(root, []string{"01-intake", "02-extraction", "03-graph", "04-full"}[index])
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		requestName := "request.json"
		if err := os.WriteFile(filepath.Join(dir, requestName), holderRaw, 0o600); err != nil {
			t.Fatal(err)
		}
		manifest := stageCompileFileManifest{RequestPath: requestName, PredecessorReceiptPaths: []string{}, Materials: []stageCompileFileMaterial{}, EvidenceBodies: []stageCompileFileEvidenceBody{}}
		paths := map[stageMaterialCoordinate]string{}
		for materialIndex, material := range inputs.Materials {
			coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
			if prior, exists := declared[coordinate]; exists {
				if !bytes.Equal(prior.Raw, material.Raw) {
					t.Fatalf("fixture material %v changes bytes across stages", coordinate)
				}
				paths[coordinate] = prior.Path
				continue
			}
			name := "material-" + zeroPadFactoryIndex(materialIndex) + ".json"
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, material.Raw, 0o600); err != nil {
				t.Fatal(err)
			}
			manifest.Materials = append(manifest.Materials, stageCompileFileMaterial{Role: material.Role, ID: material.ID, Version: material.Version, Path: name})
			declared[coordinate] = factoryFixtureMaterial{Path: path, Raw: bytes.Clone(material.Raw)}
			paths[coordinate] = path
		}
		if index == 0 {
			for bodyIndex, body := range inputs.EvidenceBodies {
				name := "evidence-" + zeroPadFactoryIndex(bodyIndex) + ".bin"
				if err := os.WriteFile(filepath.Join(dir, name), body.Raw, 0o600); err != nil {
					t.Fatal(err)
				}
				manifest.EvidenceBodies = append(manifest.EvidenceBodies, stageCompileFileEvidenceBody{
					ManifestRole: body.ManifestRole, ManifestID: body.ManifestID, ManifestVersion: body.ManifestVersion,
					ComponentOrdinal: body.ComponentOrdinal, Path: name,
				})
			}
		}
		manifestPath := filepath.Join(dir, "stage-inputs.json")
		writeFactoryJSON(t, manifestPath, manifest)
		return manifestPath, paths
	}

	intakePath, intakeMaterials := writeStage(0, fixture.evidenceRequest.raw, fixture.evidenceRequest.inputs)
	semanticPath, semanticMaterials := writeStage(1, fixture.semanticRequest.raw, fixture.semanticRequest.inputs)
	graphPath, graphMaterials := writeStage(2, fixture.graphRequest.raw, fixture.graphRequest.inputs)
	fullPath, _ := writeStage(3, fixture.fullRequest.raw, fixture.fullRequest.inputs)
	all := map[stageMaterialCoordinate]string{}
	for _, group := range []map[stageMaterialCoordinate]string{intakeMaterials, semanticMaterials, graphMaterials} {
		for coordinate, path := range group {
			all[coordinate] = path
		}
	}
	authority := fixture.evidenceRequest.request.AuthorityPins
	pathForPin := func(pin immutableStageArtifactPin) string { return all[stageCoordinateForPin(pin)] }
	evidenceManifest := fixture.evidenceRequest.request.EvidenceManifests[0]
	evidencePath := all[stageMaterialCoordinate{Role: evidenceManifest.Role, ID: evidenceManifest.ArtifactID, Version: evidenceManifest.ArtifactVersion}]
	dependency := fixture.graphRequest.request.DependencyArtifacts[0]
	dependencyPath := all[stageCoordinateForIdentity(dependency)]
	return FactoryRunOptions{
		EvidenceIntakeInputManifestPath:     intakePath,
		SemanticExtractionInputManifestPath: semanticPath,
		GraphCompileInputManifestPath:       graphPath,
		FullFactoryInputManifestPath:        fullPath,
		Preflight: Options{
			OODSpecPath: pathForPin(authority.OODGraph), ExpectedOODSpecSHA256: authority.OODGraph.RawSHA256,
			GrandVisionPath: pathForPin(authority.GrandVision), ExpectedGrandVisionSHA256: authority.GrandVision.RawSHA256,
			SourceRecordSpecPath: pathForPin(authority.SourceRecord), ExpectedSourceRecordSHA256: authority.SourceRecord.RawSHA256,
			EvidenceManifestPath: []string{evidencePath}, DependencyArtifactPath: []string{dependencyPath},
		},
	}
}

type factoryFixtureMaterial struct {
	Path string
	Raw  []byte
}

func factoryVerifierStub(t *testing.T) func(Options) (Receipt, error) {
	t.Helper()
	return func(options Options) (Receipt, error) {
		requestRaw, inputs, err := options.graphCompileSelectionLoader()
		if err != nil {
			return Receipt{}, err
		}
		stageRaw, err := CompileStageReceipt(requestRaw, inputs)
		if err != nil {
			return Receipt{}, err
		}
		stage, err := ValidateStageReceipt(stageRaw)
		if err != nil {
			return Receipt{}, err
		}
		accumulator := options.inputAdmissionAccumulator
		if accumulator == nil {
			return Receipt{}, fmt.Errorf("factory verifier stub did not receive the whole-run input admission accumulator")
		}
		if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindAuthority, int(maxVerificationAuthorityCount)); err != nil {
			return Receipt{}, err
		}
		authorities := []struct {
			path string
			role string
		}{
			{path: options.OODSpecPath, role: verificationAuthorityRoleOODGraph},
			{path: options.GrandVisionPath, role: verificationAuthorityRoleGrandVision},
			{path: options.SourceRecordSpecPath, role: verificationAuthorityRoleSourceRecord},
		}
		for _, authority := range authorities {
			if _, err := readVerificationAuthorityWithAdmission(authority.path, authority.role, accumulator); err != nil {
				return Receipt{}, err
			}
		}
		if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindManifest, len(options.EvidenceManifestPath)); err != nil {
			return Receipt{}, err
		}
		for index, path := range options.EvidenceManifestPath {
			if _, err := readBoundedProviderInputFile(path, fmt.Sprintf("factory verifier stub evidence manifest[%d]", index), providerInputAdmissionResourceKindManifest, "", accumulator); err != nil {
				return Receipt{}, err
			}
		}
		if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindArtifact, len(options.DependencyArtifactPath)); err != nil {
			return Receipt{}, err
		}
		for index, path := range options.DependencyArtifactPath {
			if _, err := readBoundedProviderInputFile(path, fmt.Sprintf("factory verifier stub dependency[%d]", index), providerInputAdmissionResourceKindArtifact, "", accumulator); err != nil {
				return Receipt{}, err
			}
		}
		if err := accumulator.revalidatePhysicalSnapshots(); err != nil {
			return Receipt{}, err
		}
		proof, err := accumulator.seal()
		if err != nil {
			return Receipt{}, err
		}
		if options.inputAdmissionObserver != nil {
			resources := append([]providerInputAdmissionResourceReceipt(nil), accumulator.resources...)
			if err := options.inputAdmissionObserver(proof, resources); err != nil {
				return Receipt{}, err
			}
		}
		receipt := Receipt{
			ReceiptKind: receiptKind, ReceiptVersion: receiptVersion, Result: "pass",
			Scope:    "offline_exact_evidence_deterministic_documentation_derivation_and_structural_plan_preflight",
			Provider: "fixture_provider", OODSpecSHA256: options.ExpectedOODSpecSHA256,
			GrandVisionSHA256: options.ExpectedGrandVisionSHA256, SourceRecordSpecSHA256: options.ExpectedSourceRecordSHA256,
			GraphCompileStageReceiptSHA256: stage.ReceiptSHA256, GraphCompileStageOutputRootSHA256: stage.OutputRootSHA256,
			EvidenceManifestSHA256:   factoryPathHashes(t, options.EvidenceManifestPath),
			DependencyArtifactSHA256: factoryPathHashes(t, options.DependencyArtifactPath), DependencyArtifactCount: len(options.DependencyArtifactPath),
			ProviderInputAdmissionProofSHA256: proof.ProofSHA256, ProviderInputAdmissionResourceSetRootSHA256: proof.ResourceSetRootSHA256,
			ProviderInputAdmissionLimits: proof.Limits, ProviderInputAdmissionActuals: proof.Actuals,
			AuthorityHashesMatchExpectedPins: true, BodyFreeSchemaBindingVerified: true,
			AuthoritySelectionCanonicalized: false, BodyFreeSchemaAuthorityVerified: false,
			CredentialMaterialDetected: false, OrganizationIDPresentInPlan: false, BinaryFloatAuthorityPresent: false,
			RawValueEmbeddingAllowed: false, CanonicalAdmissionAuthorized: false,
		}
		return sealReceipt(receipt)
	}
}

func factoryPathHashes(t *testing.T, paths []string) []string {
	t.Helper()
	result := make([]string, len(paths))
	for index, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[index] = sha256Hex(raw)
	}
	sort.Strings(result)
	return result
}

func (options FactoryRunOptions) preflightPaths() []string {
	result := []string{options.Preflight.OODSpecPath, options.Preflight.GrandVisionPath, options.Preflight.SourceRecordSpecPath}
	result = append(result, options.Preflight.EvidenceManifestPath...)
	result = append(result, options.Preflight.DependencyArtifactPath...)
	return result
}

func testFactoryToolIdentity() factoryToolIdentity {
	identity, err := sealFactoryToolIdentity(factoryToolIdentity{
		CommandPath: factoryRunnerCommandPath, ModulePath: factoryRunnerModulePath, ModuleVersion: "test", GoVersion: "go1.25.0",
		VCS: "git", VCSRevision: strings.Repeat("a", 40), VCSTime: "2026-08-25T00:00:00Z",
		BuildTags:         factoryReleaseBuildTag,
		ModuleGraphSHA256: strings.Repeat("b", 64), BuildRecipeSHA256: strings.Repeat("c", 64),
		SourceRosterSHA256:   strings.Repeat("f", 64),
		RunnerContractSHA256: sha256Hex([]byte(factoryRunnerContract)), ReproducibleSourceTree: true,
	})
	if err != nil {
		panic(err)
	}
	return identity
}

// runDocumentationFactory keeps unit fixtures hermetic. Production callers use
// RunDocumentationFactory, which derives and hashes the actual executable.
func runDocumentationFactory(options FactoryRunOptions, dependencies factoryRunnerDependencies) (FactoryRunReceipt, error) {
	return runDocumentationFactoryWithExecution(options, dependencies, testFactoryExecutionIdentity(dependencies.ToolIdentity))
}

func testFactoryExecutionIdentity(toolIdentity FactoryToolIdentity) FactoryExecutionIdentity {
	return testFactoryExecutionIdentityForTarget(toolIdentity, "windows", "amd64", "GOAMD64", "v1", strings.Repeat("d", 64), 1024)
}

func testFactoryExecutionIdentityForTarget(toolIdentity FactoryToolIdentity, targetOS, targetArch, featureKey, featureValue, executableSHA256 string, executableByteCount int64) FactoryExecutionIdentity {
	settings := []factoryBuildSetting{
		{Key: "-buildmode", Value: "exe"},
		{Key: "-compiler", Value: "gc"},
		{Key: "-tags", Value: factoryReleaseBuildTag},
		{Key: "-trimpath", Value: "true"},
		{Key: "CGO_ENABLED", Value: "0"},
		{Key: "GOARCH", Value: targetArch},
		{Key: "GOOS", Value: targetOS},
		{Key: featureKey, Value: featureValue},
		{Key: "vcs", Value: toolIdentity.VCS},
		{Key: "vcs.modified", Value: "false"},
		{Key: "vcs.revision", Value: toolIdentity.VCSRevision},
		{Key: "vcs.time", Value: toolIdentity.VCSTime},
	}
	sort.Slice(settings, func(i, j int) bool { return settings[i].Key < settings[j].Key })
	settingsRaw, err := canonicalFactoryJSON(settings)
	if err != nil {
		panic(err)
	}
	identity, err := sealFactoryExecutionIdentity(FactoryExecutionIdentity{
		PortableBuildIdentitySHA256: toolIdentity.BuildIdentitySHA256,
		BuildMetadataSource:         factoryBuildMetadataSource,
		ExecutableMeasurementScope:  factoryExecutableScope,
		TargetOS:                    targetOS,
		TargetArch:                  targetArch,
		BuildSettings:               settings,
		BuildSettingsSHA256:         sha256Hex(settingsRaw),
		ExecutableSHA256:            executableSHA256,
		ExecutableByteCount:         executableByteCount,
		GoExecutableSHA256:          strings.Repeat("1", 64),
		GitExecutableSHA256:         strings.Repeat("2", 64),
		GoToolchainSHA256:           strings.Repeat("3", 64),
		GitToolchainSHA256:          strings.Repeat("4", 64),
		GoToolchainFileCount:        10,
		GoToolchainByteCount:        100,
		GitToolchainFileCount:       20,
		GitToolchainByteCount:       200,
	}, toolIdentity)
	if err != nil {
		panic(err)
	}
	return identity
}

func resealFactoryFinalDigestForTest(t *testing.T, receipt *FactoryRunReceipt) {
	t.Helper()
	receipt.ReceiptSHA256 = ""
	raw, err := canonicalFactoryReceiptIdentity(*receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.ReceiptSHA256 = sha256Hex(raw)
}

func recomputeFactoryToolIdentityDigestForTest(t *testing.T, identity *FactoryToolIdentity) {
	t.Helper()
	identity.BuildIdentitySHA256 = ""
	raw, err := canonicalFactoryJSON(*identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.BuildIdentitySHA256 = sha256Hex(raw)
}

func recomputeFactoryExecutionIdentityDigestForTest(t *testing.T, identity *FactoryExecutionIdentity) {
	t.Helper()
	identity.ExecutionIdentitySHA256 = ""
	raw, err := canonicalFactoryJSON(*identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.ExecutionIdentitySHA256 = sha256Hex(raw)
}

func recomputeFactoryValidationIdentityDigestForTest(t *testing.T, identity *FactoryValidationIdentity) {
	t.Helper()
	identity.ValidationIdentitySHA256 = ""
	raw, err := canonicalFactoryJSON(*identity)
	if err != nil {
		t.Fatal(err)
	}
	identity.ValidationIdentitySHA256 = sha256Hex(raw)
}

func mustFactoryReceiptJSON(t *testing.T, receipt FactoryRunReceipt) []byte {
	t.Helper()
	raw, err := canonicalFactoryJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func writeFactoryJSON(t *testing.T, path string, value interface{}) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func zeroPadFactoryIndex(index int) string {
	return fmt.Sprintf("%04d", index)
}

func reverseStrings(values []string) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}
