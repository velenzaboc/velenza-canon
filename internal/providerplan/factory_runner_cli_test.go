package providerplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

type factoryPublicReleaseRun struct {
	SourceRoot     string
	CleanRevision  string
	DirectReceipt  FactoryRunReceipt
	DirectRaw      []byte
	ReleaseReceipt FactoryRunReceipt
	ReleaseRaw     []byte
}

func TestDocumentationFactoryPublicCLIWithCleanReleaseBuild(t *testing.T) {
	result := runFactoryPublicReleaseForFixture(t, newTestFixture(t))
	exportFactoryPortabilityEvidence(t, result.SourceRoot, result.CleanRevision, result.DirectReceipt, result.DirectRaw, result.ReleaseReceipt, result.ReleaseRaw)
}

func runFactoryPublicReleaseForFixture(t *testing.T, fixture *testFixture) factoryPublicReleaseRun {
	t.Helper()
	lineage := newRealVerifyFactoryLineage(t, fixture)
	stagePaths := writeRealVerifyFactoryStageManifests(t, fixture, lineage)

	sourceRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	cleanRoot := filepath.Join(t.TempDir(), "clean-source")
	sourceRoster := copyFactoryTrackedAndCandidateSourceRoster(t, sourceRoot, cleanRoot)
	initializeFactoryReleaseRepository(t, cleanRoot)
	revision := commitFactoryReleaseSourceRoster(t, cleanRoot, sourceRoster)

	executableName := "provider-documentation-factory-run"
	if runtime.GOOS == "windows" {
		executableName += ".exe"
	}
	executablePath := filepath.Join(t.TempDir(), executableName)
	releaseEnv := installFactoryAmbientGoWorkspaceTrap(t, cleanRoot)
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	goExecutableRaw, err := os.ReadFile(goPath)
	if err != nil {
		t.Fatal(err)
	}
	gitExecutableRaw, err := os.ReadFile(gitPath)
	if err != nil {
		t.Fatal(err)
	}
	linkerFlags := strings.Join([]string{
		"-X=" + factoryRunnerModulePath + "/internal/providerplan.factoryReleaseSourceRosterSHA256=" + factoryTestSourceRosterSHA256(t, sourceRoster),
		"-X=" + factoryRunnerModulePath + "/internal/providerplan.factoryReleaseGoExecutableSHA256=" + sha256Hex(goExecutableRaw),
		"-X=" + factoryRunnerModulePath + "/internal/providerplan.factoryReleaseGitExecutableSHA256=" + sha256Hex(gitExecutableRaw),
		"-X=" + factoryRunnerModulePath + "/internal/providerplan.factoryReleaseGoToolchainSHA256=" + sha256Hex([]byte("test-go-toolchain")),
		"-X=" + factoryRunnerModulePath + "/internal/providerplan.factoryReleaseGitToolchainSHA256=" + sha256Hex([]byte("test-git-toolchain")),
		"-X=" + factoryRunnerModulePath + "/internal/providerplan.factoryReleaseGoToolchainFiles=1",
		"-X=" + factoryRunnerModulePath + "/internal/providerplan.factoryReleaseGoToolchainBytes=1",
		"-X=" + factoryRunnerModulePath + "/internal/providerplan.factoryReleaseGitToolchainFiles=1",
		"-X=" + factoryRunnerModulePath + "/internal/providerplan.factoryReleaseGitToolchainBytes=1",
	}, " ")
	runFactoryCommand(t, cleanRoot, factoryCommandOptions{name: goPath, args: []string{"mod", "verify"}, env: releaseEnv})
	for _, required := range []string{"main.go"} {
		if _, err := os.Stat(filepath.Join(cleanRoot, "cmd", "provider-documentation-factory-run", required)); err != nil {
			t.Fatalf("clean release snapshot omits %s: %v", required, err)
		}
	}
	runFactoryCommand(t, cleanRoot, factoryCommandOptions{
		name: goPath, args: []string{"build", "-buildvcs=true", "-trimpath", "-tags=" + factoryReleaseBuildTag, "-ldflags=" + linkerFlags, "-o", executablePath, "./cmd/provider-documentation-factory-run"}, env: releaseEnv,
	})

	preflight := fixture.options
	args := []string{
		"--evidence-intake-inputs", stagePaths[0],
		"--semantic-extraction-inputs", stagePaths[1],
		"--graph-compile-inputs", stagePaths[2],
		"--full-factory-inputs", stagePaths[3],
		"--ood", preflight.OODSpecPath,
		"--expected-ood-sha256", preflight.ExpectedOODSpecSHA256,
		"--grand-vision", preflight.GrandVisionPath,
		"--expected-grand-vision-sha256", preflight.ExpectedGrandVisionSHA256,
		"--source-record", preflight.SourceRecordSpecPath,
		"--expected-source-record-sha256", preflight.ExpectedSourceRecordSHA256,
	}
	for _, path := range preflight.EvidenceManifestPath {
		args = append(args, "--evidence-manifest", path)
	}
	for _, path := range preflight.DependencyArtifactPath {
		args = append(args, "--dependency-artifact", path)
	}

	firstMissingStdout, firstMissingStderr := runFactoryCommandFailure(t, cleanRoot, factoryCommandOptions{name: executablePath})
	secondMissingStdout, secondMissingStderr := runFactoryCommandFailure(t, cleanRoot, factoryCommandOptions{name: executablePath})
	if len(firstMissingStdout) != 0 || len(secondMissingStdout) != 0 {
		t.Fatal("missing required flags unexpectedly emitted a receipt")
	}
	wantMissing := "provider-documentation-factory-run: --evidence-intake-inputs is required\n"
	if string(firstMissingStderr) != wantMissing || !bytes.Equal(firstMissingStderr, secondMissingStderr) {
		t.Fatalf("missing-flag diagnostics are not closed and deterministic:\nfirst=%q\nsecond=%q\nwant=%q", firstMissingStderr, secondMissingStderr, wantMissing)
	}

	positionalArgs := append(append([]string(nil), args...), "unexpected-positional")
	positionalStdout, positionalStderr := runFactoryCommandFailure(t, cleanRoot, factoryCommandOptions{name: executablePath, args: positionalArgs})
	if len(positionalStdout) != 0 {
		t.Fatal("positional argument unexpectedly produced a receipt")
	}
	wantPositional := "provider-documentation-factory-run: positional arguments are not accepted\n"
	if string(positionalStderr) != wantPositional {
		t.Fatalf("positional-argument diagnostic = %q, want %q", positionalStderr, wantPositional)
	}

	raw := runFactoryCommand(t, cleanRoot, factoryCommandOptions{name: executablePath, args: args})
	var receipt FactoryRunReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		t.Fatalf("decode public CLI receipt: %v\n%s", err, raw)
	}
	if err := validateFactoryRunReceipt(receipt); err != nil {
		t.Fatalf("validate public CLI receipt: %v", err)
	}
	if receipt.ToolIdentity.VCSRevision != revision || receipt.ToolIdentity.VCSModified || !receipt.ToolIdentity.ReproducibleSourceTree {
		t.Fatalf("public CLI source identity = %+v, want clean revision %s", receipt.ToolIdentity, revision)
	}
	executableRaw, err := os.ReadFile(executablePath)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ExecutionIdentity.ExecutableSHA256 != sha256Hex(executableRaw) || receipt.ExecutionIdentity.ExecutableByteCount != int64(len(executableRaw)) {
		t.Fatal("public CLI receipt does not bind the exact executable bytes")
	}
	if receipt.ExecutionIdentity.TargetOS != runtime.GOOS || receipt.ExecutionIdentity.TargetArch != runtime.GOARCH {
		t.Fatalf("public CLI target = %s/%s, want %s/%s", receipt.ExecutionIdentity.TargetOS, receipt.ExecutionIdentity.TargetArch, runtime.GOOS, runtime.GOARCH)
	}
	if receipt.ValidationIdentity.ValidationReportSHA256 == "" || receipt.ValidationIdentity.PortableReceiptSHA256 != receipt.PortableReceiptSHA256 {
		t.Fatal("public CLI receipt omits its distinct validation-report binding")
	}

	absoluteGoPath, err := filepath.Abs(goPath)
	if err != nil {
		t.Fatal(err)
	}
	absoluteGitPath, err := filepath.Abs(gitPath)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapProgram := "sh"
	bootstrapArgs := []string{
		filepath.Join(cleanRoot, "scripts", "provider-documentation-factory-release.sh"),
		cleanRoot, revision, absoluteGoPath, absoluteGitPath, "--",
	}
	if runtime.GOOS == "windows" {
		bootstrapProgram = "pwsh"
		bootstrapArgs = []string{
			"-NoProfile", "-File", filepath.Join(cleanRoot, "scripts", "provider-documentation-factory-release.ps1"),
			cleanRoot, revision, absoluteGoPath, absoluteGitPath, "--",
		}
	}
	bootstrapRaw := runFactoryCommandWithEmptyStderr(t, cleanRoot, factoryCommandOptions{
		name: bootstrapProgram, args: append(bootstrapArgs, args...),
	})
	var bootstrapReceipt FactoryRunReceipt
	if err := json.Unmarshal(bootstrapRaw, &bootstrapReceipt); err != nil {
		t.Fatalf("decode exact-commit release receipt: %v\n%s", err, bootstrapRaw)
	}
	if err := validateFactoryRunReceipt(bootstrapReceipt); err != nil {
		t.Fatalf("validate exact-commit release receipt: %v", err)
	}
	if bootstrapReceipt.ToolIdentity.VCSRevision != revision || bootstrapReceipt.ToolIdentity.SourceRosterSHA256 != receipt.ToolIdentity.SourceRosterSHA256 {
		t.Fatal("exact-commit release receipt differs from the selected source identity")
	}
	if bootstrapReceipt.PortableReceiptSHA256 != receipt.PortableReceiptSHA256 {
		t.Fatalf("exact-commit and direct candidate portable roots differ: %s != %s", bootstrapReceipt.PortableReceiptSHA256, receipt.PortableReceiptSHA256)
	}
	if bootstrapReceipt.ExecutionIdentity.GoExecutableSHA256 != sha256Hex(goExecutableRaw) || bootstrapReceipt.ExecutionIdentity.GitExecutableSHA256 != sha256Hex(gitExecutableRaw) || bootstrapReceipt.ExecutionIdentity.GoToolchainFileCount <= 0 || bootstrapReceipt.ExecutionIdentity.GoToolchainByteCount <= 0 || bootstrapReceipt.ExecutionIdentity.GitToolchainFileCount <= 0 || bootstrapReceipt.ExecutionIdentity.GitToolchainByteCount <= 0 {
		t.Fatal("exact-commit release receipt omits independently measured tool or complete toolchain identity")
	}

	goRunArgs := []string{"run", "-buildvcs=true", "-trimpath", "-tags=" + factoryReleaseBuildTag, "./cmd/provider-documentation-factory-run"}
	goRunArgs = append(goRunArgs, args...)
	goRunStdout, goRunStderr := runFactoryCommandFailure(t, cleanRoot, factoryCommandOptions{name: goPath, args: goRunArgs, env: releaseEnv})
	if len(goRunStdout) != 0 || string(goRunStderr) != "provider-documentation-factory-run: factory validation failed\nexit status 1\n" {
		t.Fatalf("raw go run bypass was not rejected deterministically:\nstdout=%q\nstderr=%q", goRunStdout, goRunStderr)
	}
	return factoryPublicReleaseRun{
		SourceRoot: sourceRoot, CleanRevision: revision,
		DirectReceipt: receipt, DirectRaw: raw,
		ReleaseReceipt: bootstrapReceipt, ReleaseRaw: bootstrapRaw,
	}
}

type factoryCommandOptions struct {
	name  string
	args  []string
	env   []string
	stdin []byte
}

type factoryPortabilityEvidenceManifest struct {
	EvidenceKind                  string `json:"evidence_kind"`
	EvidenceVersion               string `json:"evidence_version"`
	CandidateCommit               string `json:"candidate_commit"`
	CleanSourceRevision           string `json:"clean_source_revision"`
	SourceRosterSHA256            string `json:"source_roster_sha256"`
	TargetOS                      string `json:"target_os"`
	TargetArch                    string `json:"target_arch"`
	DirectReceiptSHA256           string `json:"direct_receipt_sha256"`
	ReleaseReceiptSHA256          string `json:"release_receipt_sha256"`
	DirectReceiptFileSHA256       string `json:"direct_receipt_file_sha256"`
	ReleaseReceiptFileSHA256      string `json:"release_receipt_file_sha256"`
	DirectPortableReceiptSHA256   string `json:"direct_portable_receipt_sha256"`
	ReleasePortableReceiptSHA256  string `json:"release_portable_receipt_sha256"`
	PreflightReceiptSHA256        string `json:"preflight_receipt_sha256"`
	BodyFree                      bool   `json:"body_free"`
	NonAuthoritativeCandidateOnly bool   `json:"non_authoritative_candidate_only"`
	LiveProviderAcceptanceClaimed bool   `json:"live_provider_acceptance_claimed"`
}

func exportFactoryPortabilityEvidence(t *testing.T, sourceRoot, cleanRevision string, direct FactoryRunReceipt, directRaw []byte, release FactoryRunReceipt, releaseRaw []byte) {
	t.Helper()
	directory := os.Getenv("VELENZA_FACTORY_PORTABILITY_EVIDENCE_DIR")
	if directory == "" {
		return
	}
	if directory != strings.TrimSpace(directory) || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatalf("factory portability evidence directory %q is not an absolute canonical path", directory)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create exclusive factory portability evidence directory: %v", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		t.Fatalf("factory portability evidence directory is not a physical directory: %v", err)
	}
	candidateCommit := strings.TrimSpace(string(runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"rev-parse", "HEAD"},
	})))
	if len(candidateCommit) != 40 {
		t.Fatalf("candidate portability evidence commit = %q, want full SHA-1", candidateCommit)
	}
	if direct.PortableReceiptSHA256 != release.PortableReceiptSHA256 || direct.PreflightReceipt.ReceiptSHA256 != release.PreflightReceipt.ReceiptSHA256 {
		t.Fatal("factory portability evidence inputs do not share portable and preflight roots")
	}
	manifest := factoryPortabilityEvidenceManifest{
		EvidenceKind:                  "provider_documentation_factory_cross_machine_portability_evidence",
		EvidenceVersion:               "1",
		CandidateCommit:               candidateCommit,
		CleanSourceRevision:           cleanRevision,
		SourceRosterSHA256:            direct.ToolIdentity.SourceRosterSHA256,
		TargetOS:                      runtime.GOOS,
		TargetArch:                    runtime.GOARCH,
		DirectReceiptSHA256:           direct.ReceiptSHA256,
		ReleaseReceiptSHA256:          release.ReceiptSHA256,
		DirectReceiptFileSHA256:       sha256Hex(directRaw),
		ReleaseReceiptFileSHA256:      sha256Hex(releaseRaw),
		DirectPortableReceiptSHA256:   direct.PortableReceiptSHA256,
		ReleasePortableReceiptSHA256:  release.PortableReceiptSHA256,
		PreflightReceiptSHA256:        direct.PreflightReceipt.ReceiptSHA256,
		BodyFree:                      direct.BodyFree && release.BodyFree,
		NonAuthoritativeCandidateOnly: true,
		LiveProviderAcceptanceClaimed: false,
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw = append(manifestRaw, '\n')
	for _, artifact := range []struct {
		name string
		raw  []byte
	}{
		{name: "direct-receipt.json", raw: directRaw},
		{name: "release-receipt.json", raw: releaseRaw},
		{name: "manifest.json", raw: manifestRaw},
	} {
		if err := writeFactoryPortabilityEvidenceFile(filepath.Join(directory, artifact.name), artifact.raw); err != nil {
			t.Fatalf("write factory portability evidence %s: %v", artifact.name, err)
		}
	}
}

func writeFactoryPortabilityEvidenceFile(path string, raw []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if written != len(raw) {
		return io.ErrShortWrite
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func runFactoryCommand(t *testing.T, dir string, options factoryCommandOptions) []byte {
	t.Helper()
	command := exec.Command(options.name, options.args...)
	command.Dir = dir
	command.Env = append(filteredFactoryEnvironment(os.Environ(), options.env), options.env...)
	if options.stdin != nil {
		command.Stdin = bytes.NewReader(options.stdin)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s %s: %v\nstderr:\n%s\nstdout:\n%s", options.name, strings.Join(options.args, " "), err, stderr.String(), stdout.String())
	}
	return stdout.Bytes()
}

func runFactoryCommandWithEmptyStderr(t *testing.T, dir string, options factoryCommandOptions) []byte {
	t.Helper()
	command := exec.Command(options.name, options.args...)
	command.Dir = dir
	command.Env = append(filteredFactoryEnvironment(os.Environ(), options.env), options.env...)
	if options.stdin != nil {
		command.Stdin = bytes.NewReader(options.stdin)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("%s %s: %v\nstderr:\n%s\nstdout:\n%s", options.name, strings.Join(options.args, " "), err, stderr.String(), stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("%s %s succeeded with stderr:\n%s", options.name, strings.Join(options.args, " "), stderr.String())
	}
	return stdout.Bytes()
}

func runFactoryCommandFailure(t *testing.T, dir string, options factoryCommandOptions) ([]byte, []byte) {
	t.Helper()
	command := exec.Command(options.name, options.args...)
	command.Dir = dir
	command.Env = append(filteredFactoryEnvironment(os.Environ(), options.env), options.env...)
	if options.stdin != nil {
		command.Stdin = bytes.NewReader(options.stdin)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatalf("%s %s unexpectedly succeeded\nstdout:\n%s", options.name, strings.Join(options.args, " "), stdout.String())
	}
	return stdout.Bytes(), stderr.Bytes()
}

func filteredFactoryEnvironment(current, overrides []string) []string {
	keys := make(map[string]struct{}, len(overrides))
	for _, override := range overrides {
		key, _, _ := strings.Cut(override, "=")
		keys[strings.ToUpper(key)] = struct{}{}
	}
	result := make([]string, 0, len(current))
	for _, value := range current {
		key, _, _ := strings.Cut(value, "=")
		if _, replaced := keys[strings.ToUpper(key)]; !replaced {
			result = append(result, value)
		}
	}
	return result
}

type factorySourceRosterEntry struct {
	mode          string
	blobObjectID  string
	contentBytes  int64
	contentSHA256 string
}

type factorySourceRoster map[string]factorySourceRosterEntry

func factoryTestSourceRosterSHA256(t *testing.T, roster factorySourceRoster) string {
	t.Helper()
	hash := sha256.New()
	for _, path := range sortedFactorySourceRosterPaths(roster) {
		entry := roster[path]
		for _, value := range []string{path, entry.mode} {
			if err := binary.Write(hash, binary.BigEndian, uint64(len(value))); err != nil {
				t.Fatal(err)
			}
			if _, err := hash.Write([]byte(value)); err != nil {
				t.Fatal(err)
			}
		}
		if entry.contentBytes < 0 {
			t.Fatalf("exact source path %q has negative byte count %d", path, entry.contentBytes)
		}
		if err := binary.Write(hash, binary.BigEndian, uint64(entry.contentBytes)); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(hash, binary.BigEndian, uint64(len(entry.contentSHA256))); err != nil {
			t.Fatal(err)
		}
		if _, err := hash.Write([]byte(entry.contentSHA256)); err != nil {
			t.Fatal(err)
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type factorySourceCopyHooks struct {
	afterTargetFileCopy func(relative string) error
}

type factorySourceSnapshot struct {
	path          string
	relative      string
	identity      providerInputStableFileIdentity
	mutationToken providerInputMutationToken
	openedInfo    os.FileInfo
	digest        string
	size          int64
}

func copyFactoryTrackedAndCandidateSource(t *testing.T, sourceRoot, targetRoot string) {
	t.Helper()
	_ = copyFactoryTrackedAndCandidateSourceRoster(t, sourceRoot, targetRoot)
}

func copyFactoryTrackedAndCandidateSourceRoster(t *testing.T, sourceRoot, targetRoot string) factorySourceRoster {
	return copyFactoryTrackedAndCandidateSourceRosterWithHooks(t, sourceRoot, targetRoot, factorySourceCopyHooks{})
}

func copyFactoryTrackedAndCandidateSourceRosterWithHooks(t *testing.T, sourceRoot, targetRoot string, hooks factorySourceCopyHooks) factorySourceRoster {
	t.Helper()
	stagedBefore := runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"ls-files", "--cached", "--stage", "-z"},
	})
	trackedModes := factoryTrackedSourceModes(t, stagedBefore)
	listed := runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: factoryTrackedAndCandidateSourceListArgs(),
	})
	targetWriter, err := newFactoryCleanTargetWriter(targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = targetWriter.release() }()
	listedPaths := make(map[string]struct{}, len(trackedModes))
	nativePaths := make(map[string]string, len(trackedModes))
	physicalFiles := make(map[providerInputStableFileIdentity]string, len(trackedModes))
	copiedRoster := make(factorySourceRoster, len(trackedModes))
	sourceSnapshots := make(map[string]factorySourceSnapshot, len(trackedModes))
	for _, encoded := range bytes.Split(listed, []byte{0}) {
		if len(encoded) == 0 {
			continue
		}
		slashPath := string(encoded)
		if _, duplicate := listedPaths[slashPath]; duplicate {
			t.Fatalf("candidate source roster repeats %q", slashPath)
		}
		listedPaths[slashPath] = struct{}{}
		relative := factoryCandidateSourceRelativePath(t, slashPath)
		nativePathKey := canonicalProviderInputPathKey(relative)
		if prior, collision := nativePaths[nativePathKey]; collision {
			t.Fatalf("candidate source paths %q and %q collapse to one native path", prior, slashPath)
		}
		nativePaths[nativePathKey] = slashPath
		source := filepath.Join(sourceRoot, relative)
		raw, mode, identity, snapshot := readStableFactoryCandidateSource(t, source, relative)
		if prior, collision := physicalFiles[identity]; collision {
			t.Fatalf("candidate source paths %q and %q resolve to one physical file", prior, slashPath)
		}
		physicalFiles[identity] = slashPath
		gitMode := "100644"
		if mode.Perm()&0o111 != 0 {
			gitMode = "100755"
		}
		if trackedMode, tracked := trackedModes[slashPath]; tracked {
			gitMode = trackedMode
			switch trackedMode {
			case "100644":
				mode = 0o644
			case "100755":
				mode = 0o755
			default:
				t.Fatalf("candidate source %q has unsupported Git index mode %q", relative, trackedMode)
			}
		}
		if err := targetWriter.writeFile(relative, raw, mode); err != nil {
			t.Fatal(err)
		}
		if hooks.afterTargetFileCopy != nil {
			if err := hooks.afterTargetFileCopy(relative); err != nil {
				t.Fatal(err)
			}
		}
		copiedRoster[slashPath] = factorySourceRosterEntry{mode: gitMode, contentBytes: int64(len(raw)), contentSHA256: sha256Hex(raw)}
		sourceSnapshots[slashPath] = snapshot
	}
	for slashPath := range trackedModes {
		if _, present := listedPaths[slashPath]; !present {
			t.Fatalf("tracked candidate source %q is absent from the complete source roster", slashPath)
		}
	}
	if stagedAfter := runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"ls-files", "--cached", "--stage", "-z"},
	}); !bytes.Equal(stagedAfter, stagedBefore) {
		t.Fatal("candidate source Git index changed while the clean source was copied")
	}
	if listedAfter := runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: factoryTrackedAndCandidateSourceListArgs(),
	}); !bytes.Equal(listedAfter, listed) {
		t.Fatal("tracked-plus-untracked candidate source roster changed while the clean source was copied")
	}
	revalidateFactoryCandidateSourceSnapshots(t, sourceSnapshots)
	if err := targetWriter.finish(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(targetRoot, "go.mod")); err != nil {
		t.Fatal(fmt.Errorf("copied source omits go.mod: %w", err))
	}
	return copiedRoster
}

func initializeFactoryReleaseRepository(t *testing.T, root string) {
	t.Helper()
	runFactoryCommand(t, root, factoryCommandOptions{
		name: "git", args: []string{"init", "-q", "-b", "main", "--object-format=sha1"},
	})
	runFactoryCommand(t, root, factoryCommandOptions{name: "git", args: []string{"config", "user.name", "Factory Test"}})
	runFactoryCommand(t, root, factoryCommandOptions{name: "git", args: []string{"config", "user.email", "factory-test@example.invalid"}})
	runFactoryCommand(t, root, factoryCommandOptions{name: "git", args: []string{"config", "core.autocrlf", "false"}})
	hooks := filepath.Join(root, ".empty-hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, root, factoryCommandOptions{name: "git", args: []string{"config", "core.hooksPath", hooks}})
	gitAttributes := strings.TrimSpace(string(runFactoryCommand(t, root, factoryCommandOptions{
		name: "git", args: []string{"rev-parse", "--git-path", "info/attributes"},
	})))
	if !filepath.IsAbs(gitAttributes) {
		gitAttributes = filepath.Join(root, filepath.FromSlash(gitAttributes))
	}
	if err := os.MkdirAll(filepath.Dir(gitAttributes), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gitAttributes, []byte("* -text -eol -filter -ident -working-tree-encoding\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func commitFactoryReleaseSourceRoster(t *testing.T, root string, roster factorySourceRoster) string {
	t.Helper()
	stageFactoryReleaseSourceRoster(t, root, roster)
	fixedGitEnv := []string{"GIT_AUTHOR_DATE=2026-08-25T00:00:00Z", "GIT_COMMITTER_DATE=2026-08-25T00:00:00Z"}
	runFactoryCommand(t, root, factoryCommandOptions{name: "git", args: []string{"commit", "-q", "-m", "hermetic factory release snapshot"}, env: fixedGitEnv})
	committed := factoryCommittedSourceRoster(t, runFactoryCommand(t, root, factoryCommandOptions{
		name: "git", args: []string{"ls-tree", "-r", "-z", "--full-tree", "HEAD"},
	}))
	assertFactorySourceRosterEqual(t, "committed factory source", committed, roster)
	if status := runFactoryCommand(t, root, factoryCommandOptions{name: "git", args: []string{"status", "--porcelain=v1", "-z"}}); len(status) != 0 {
		t.Fatalf("exact factory source projection is dirty after commit: %q", status)
	}
	return strings.TrimSpace(string(runFactoryCommand(t, root, factoryCommandOptions{name: "git", args: []string{"rev-parse", "HEAD"}})))
}

func stageFactoryReleaseSourceRoster(t *testing.T, root string, roster factorySourceRoster) {
	t.Helper()
	paths := sortedFactorySourceRosterPaths(roster)
	const maxHashObjectArgumentBytes = 12 << 10
	for first := 0; first < len(paths); {
		args := []string{"hash-object", "-w", "--no-filters", "--"}
		argumentBytes := 0
		last := first
		for last < len(paths) {
			pathBytes := len(paths[last]) + 3
			if last > first && argumentBytes+pathBytes > maxHashObjectArgumentBytes {
				break
			}
			args = append(args, paths[last])
			argumentBytes += pathBytes
			last++
		}
		raw := runFactoryCommand(t, root, factoryCommandOptions{name: "git", args: args})
		objectIDs := strings.Fields(string(raw))
		if len(objectIDs) != last-first {
			t.Fatalf("git hash-object returned %d object IDs for %d exact source paths", len(objectIDs), last-first)
		}
		for index, objectID := range objectIDs {
			if !validFactoryVCSRevision(objectID) || strings.Trim(objectID, "0") == "" {
				t.Fatalf("git hash-object returned invalid blob identity %q", objectID)
			}
			path := paths[first+index]
			entry := roster[path]
			blob := runFactoryCommand(t, root, factoryCommandOptions{name: "git", args: []string{"cat-file", "blob", objectID}})
			if int64(len(blob)) != entry.contentBytes || sha256Hex(blob) != entry.contentSHA256 {
				t.Fatalf("Git blob %s for exact source path %q differs from the copied source byte count or digest", objectID, path)
			}
			entry.blobObjectID = objectID
			roster[path] = entry
		}
		first = last
	}
	var indexInfo bytes.Buffer
	for _, path := range paths {
		entry := roster[path]
		fmt.Fprintf(&indexInfo, "%s %s\t%s", entry.mode, entry.blobObjectID, path)
		indexInfo.WriteByte(0)
	}
	runFactoryCommand(t, root, factoryCommandOptions{
		name: "git", args: []string{"update-index", "-z", "--index-info"}, stdin: indexInfo.Bytes(),
	})
	staged := factoryGitIndexSourceRoster(t, runFactoryCommand(t, root, factoryCommandOptions{
		name: "git", args: []string{"ls-files", "--cached", "--stage", "-z"},
	}))
	assertFactorySourceRosterEqual(t, "staged factory source", staged, roster)
}

func sortedFactorySourceRosterPaths(roster factorySourceRoster) []string {
	paths := make([]string, 0, len(roster))
	for path := range roster {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func factoryGitIndexSourceRoster(t *testing.T, raw []byte) factorySourceRoster {
	t.Helper()
	roster := make(factorySourceRoster)
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, encodedPath, found := bytes.Cut(record, []byte{'\t'})
		fields := bytes.Fields(header)
		if !found || len(encodedPath) == 0 || len(fields) != 3 {
			t.Fatalf("malformed Git index record %q", record)
		}
		mode, objectID, stage := string(fields[0]), string(fields[1]), string(fields[2])
		path := string(encodedPath)
		if stage != "0" || (mode != "100644" && mode != "100755") || !validFactoryVCSRevision(objectID) || strings.Trim(objectID, "0") == "" {
			t.Fatalf("invalid exact Git index entry %q", record)
		}
		if _, duplicate := roster[path]; duplicate {
			t.Fatalf("Git index repeats exact source path %q", path)
		}
		roster[path] = factorySourceRosterEntry{mode: mode, blobObjectID: objectID}
	}
	return roster
}

func factoryCommittedSourceRoster(t *testing.T, raw []byte) factorySourceRoster {
	t.Helper()
	roster := make(factorySourceRoster)
	for _, record := range bytes.Split(raw, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, encodedPath, found := bytes.Cut(record, []byte{'\t'})
		fields := bytes.Fields(header)
		if !found || len(encodedPath) == 0 || len(fields) != 3 || string(fields[1]) != "blob" {
			t.Fatalf("malformed committed Git tree record %q", record)
		}
		mode, objectID, path := string(fields[0]), string(fields[2]), string(encodedPath)
		if (mode != "100644" && mode != "100755") || !validFactoryVCSRevision(objectID) || strings.Trim(objectID, "0") == "" {
			t.Fatalf("invalid committed Git source entry %q", record)
		}
		if _, duplicate := roster[path]; duplicate {
			t.Fatalf("committed Git tree repeats exact source path %q", path)
		}
		roster[path] = factorySourceRosterEntry{mode: mode, blobObjectID: objectID}
	}
	return roster
}

func assertFactorySourceRosterEqual(t *testing.T, label string, got, want factorySourceRoster) {
	t.Helper()
	for _, path := range sortedFactorySourceRosterPaths(want) {
		gotEntry, exists := got[path]
		if !exists {
			t.Fatalf("%s omits exact copied path %q", label, path)
		}
		wantEntry := want[path]
		if gotEntry.mode != wantEntry.mode || gotEntry.blobObjectID != wantEntry.blobObjectID {
			t.Fatalf("%s entry %q = %s/%s, want exact %s/%s", label, path, gotEntry.mode, gotEntry.blobObjectID, wantEntry.mode, wantEntry.blobObjectID)
		}
	}
	for _, path := range sortedFactorySourceRosterPaths(got) {
		if _, exists := want[path]; !exists {
			t.Fatalf("%s contains unsealed path %q", label, path)
		}
	}
}

func factoryReleaseEnvironment() []string {
	return []string{
		"CGO_ENABLED=0",
		"GO111MODULE=on",
		"GOENV=off",
		"GOEXPERIMENT=",
		"GOFLAGS=-mod=readonly",
		"GOTOOLCHAIN=local",
		"GOWORK=off",
	}
}

func installFactoryAmbientGoWorkspaceTrap(t *testing.T, cleanRoot string) []string {
	t.Helper()
	trapRoot := t.TempDir()
	missingReplacement := filepath.Join(trapRoot, "outside-unsealed-replacement")
	if err := os.MkdirAll(missingReplacement, 0o700); err != nil {
		t.Fatal(err)
	}
	workPath := filepath.Join(trapRoot, "go.work")
	workRaw := fmt.Sprintf(
		"go 1.27.0\nuse %s\nreplace github.com/google/uuid => %s\n",
		strconv.Quote(filepath.ToSlash(cleanRoot)), strconv.Quote(filepath.ToSlash(missingReplacement)),
	)
	if err := os.WriteFile(workPath, []byte(workRaw), 0o600); err != nil {
		t.Fatal(err)
	}
	goEnvPath := filepath.Join(trapRoot, "ambient-go-env")
	if err := os.WriteFile(goEnvPath, []byte("GOFLAGS=-mod=mod\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", workPath)
	t.Setenv("GOENV", goEnvPath)
	runFactoryCommandFailure(t, cleanRoot, factoryCommandOptions{
		name: "go", args: []string{"list", "-m", "all"}, env: []string{"GOTOOLCHAIN=local"},
	})
	releaseEnv := factoryReleaseEnvironment()
	goEnvironmentRaw := strings.ReplaceAll(string(runFactoryCommand(t, cleanRoot, factoryCommandOptions{
		name: "go", args: []string{"env", "GOWORK", "GOENV", "GOFLAGS", "GOTOOLCHAIN"}, env: releaseEnv,
	})), "\r\n", "\n")
	goEnvironment := strings.Split(strings.TrimSuffix(goEnvironmentRaw, "\n"), "\n")
	wantEnvironment := []string{"off", "", "-mod=readonly", "local"}
	if !equalStringSlices(goEnvironment, wantEnvironment) {
		t.Fatalf("factory release Go environment = %q, want %q", goEnvironment, wantEnvironment)
	}
	moduleGraph := runFactoryCommand(t, cleanRoot, factoryCommandOptions{name: "go", args: []string{"list", "-m", "all"}, env: releaseEnv})
	if bytes.Contains(moduleGraph, []byte(missingReplacement)) {
		t.Fatal("factory release module graph consumed the ambient workspace replacement")
	}
	return releaseEnv
}

func factoryTrackedSourceModes(t *testing.T, staged []byte) map[string]string {
	t.Helper()
	modes := make(map[string]string)
	for _, record := range bytes.Split(staged, []byte{0}) {
		if len(record) == 0 {
			continue
		}
		header, encodedPath, found := bytes.Cut(record, []byte{'\t'})
		fields := bytes.Fields(header)
		if !found || len(encodedPath) == 0 || len(fields) != 3 {
			t.Fatalf("malformed Git index record %q", record)
		}
		mode := string(fields[0])
		stage := string(fields[2])
		slashPath := string(encodedPath)
		if stage != "0" {
			t.Fatalf("candidate source %q has unresolved Git index stage %q", slashPath, stage)
		}
		if mode != "100644" && mode != "100755" {
			t.Fatalf("candidate source %q has unsupported Git index mode %q", slashPath, mode)
		}
		if _, duplicate := modes[slashPath]; duplicate {
			t.Fatalf("Git index repeats candidate source %q", slashPath)
		}
		modes[slashPath] = mode
	}
	return modes
}

func factoryCandidateSourceRelativePath(t *testing.T, slashPath string) string {
	t.Helper()
	relative := filepath.FromSlash(slashPath)
	cleaned := filepath.Clean(relative)
	if slashPath == "" || filepath.IsAbs(relative) || filepath.VolumeName(relative) != "" || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		t.Fatalf("candidate source roster contains non-relative path %q", slashPath)
	}
	return cleaned
}

func readStableFactoryCandidateSource(t *testing.T, source, relative string) ([]byte, os.FileMode, providerInputStableFileIdentity, factorySourceSnapshot) {
	t.Helper()
	label := fmt.Sprintf("candidate source %q", relative)
	inspectedPath, inspectedInfo, err := inspectPathWithoutLinks(source, label)
	if err != nil {
		t.Fatal(err)
	}
	if !inspectedInfo.Mode().IsRegular() {
		t.Fatalf("candidate source %q is not a regular file", relative)
	}
	file, err := openStableProviderInput(inspectedPath, label)
	if err != nil {
		t.Fatalf("open %s: %v", label, err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		t.Fatalf("inspect opened %s: %v", label, err)
	}
	if !openedInfo.Mode().IsRegular() {
		t.Fatalf("candidate source %q is not a regular file", relative)
	}
	mutationToken, err := currentProviderInputMutationToken(file)
	if err != nil {
		t.Fatalf("capture %s mutation token: %v", label, err)
	}
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		t.Fatalf("derive stable file identity for %s: %v", label, err)
	}
	if inspectedInfo.Size() != openedInfo.Size() || !inspectedInfo.ModTime().Equal(openedInfo.ModTime()) {
		t.Fatalf("%s changed metadata before open", label)
	}
	currentIdentity, currentInfo, err := stableProviderInputPathIdentity(inspectedPath, label)
	if err != nil {
		t.Fatalf("reinspect %s after open: %v", label, err)
	}
	if currentIdentity != identity || openedInfo.Size() != currentInfo.Size() || !openedInfo.ModTime().Equal(currentInfo.ModTime()) {
		t.Fatalf("%s changed identity during validation", label)
	}
	length, err := safeProviderInputAllocationLength(openedInfo.Size())
	if err != nil {
		t.Fatalf("allocate %s: %v", label, err)
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(file, raw); err != nil {
		t.Fatalf("read exact %s: %v", label, err)
	}
	var extra [1]byte
	if count, readErr := file.Read(extra[:]); readErr != io.EOF || count != 0 {
		if readErr == nil {
			readErr = fmt.Errorf("file grew after its size was inspected")
		}
		t.Fatalf("read exact %s: %v", label, readErr)
	}
	if err := validateStableOpenedFile(file, openedInfo, inspectedPath, label); err != nil {
		t.Fatal(err)
	}
	if err := validateProviderInputReadSnapshot(file, mutationToken, label); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close exact %s snapshot: %v", label, err)
	}
	return raw, openedInfo.Mode().Perm(), identity, factorySourceSnapshot{
		path:          inspectedPath,
		relative:      relative,
		identity:      identity,
		mutationToken: mutationToken,
		openedInfo:    openedInfo,
		digest:        sha256Hex(raw),
		size:          int64(len(raw)),
	}
}

func revalidateFactoryCandidateSourceSnapshots(t *testing.T, snapshots map[string]factorySourceSnapshot) {
	t.Helper()
	paths := make([]string, 0, len(snapshots))
	for path := range snapshots {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		snapshot := snapshots[path]
		label := fmt.Sprintf("candidate source %q", snapshot.relative)
		file, err := openStableProviderInput(snapshot.path, label)
		if err != nil {
			t.Fatalf("reopen %s after clean-source copy: %v", label, err)
		}
		openedInfo, statErr := file.Stat()
		identity, identityErr := stableProviderInputFileIdentity(file)
		mutationToken, tokenErr := currentProviderInputMutationToken(file)
		observed := newHashingCountingReader(io.LimitReader(file, snapshot.size+1))
		_, readErr := io.Copy(io.Discard, observed)
		stableErr := validateStableOpenedFile(file, openedInfo, snapshot.path, label)
		closeErr := file.Close()
		if statErr != nil || identityErr != nil || tokenErr != nil || readErr != nil || stableErr != nil || closeErr != nil ||
			identity != snapshot.identity || mutationToken != snapshot.mutationToken ||
			openedInfo.Size() != snapshot.size || !openedInfo.ModTime().Equal(snapshot.openedInfo.ModTime()) || observed.count != snapshot.size || observed.sha256() != snapshot.digest {
			t.Fatalf("%s changed after its exact clean-source copy: stat=%v identity=%v token=%v read=%v stable=%v close=%v count=%d digest=%s", label, statErr, identityErr, tokenErr, readErr, stableErr, closeErr, observed.count, observed.sha256())
		}
	}
}

type factoryCleanTargetDirectory struct {
	logicalPath string
	identity    providerInputStableFileIdentity
	handle      factoryCleanTargetDirectoryHandle
}

type factoryCleanTargetDirectoryHandle interface {
	createDirectory(component, displayPath string) (factoryCleanTargetDirectoryHandle, providerInputStableFileIdentity, error)
	createFile(component, displayPath string, raw []byte, mode os.FileMode) (providerInputStableFileIdentity, error)
	validate() error
	close() error
}

type factoryCleanTargetWriterTestHooks struct {
	beforeFileCreate func(relative string) error
}

type factoryCleanTargetWriter struct {
	root                     string
	directoriesByPath        map[string]factoryCleanTargetDirectory
	directoryPathsByIdentity map[providerInputStableFileIdentity]string
	directoryOrder           []string
	filePathsByPath          map[string]string
	filePathsByIdentity      map[providerInputStableFileIdentity]string
	hooks                    factoryCleanTargetWriterTestHooks
	released                 bool
}

func newFactoryCleanTargetWriter(targetRoot string) (*factoryCleanTargetWriter, error) {
	return newFactoryCleanTargetWriterWithHooks(targetRoot, factoryCleanTargetWriterTestHooks{})
}

func newFactoryCleanTargetWriterWithHooks(targetRoot string, hooks factoryCleanTargetWriterTestHooks) (*factoryCleanTargetWriter, error) {
	if strings.TrimSpace(targetRoot) == "" {
		return nil, fmt.Errorf("clean target root is empty")
	}
	if err := validateProviderInputPathSyntax(targetRoot, "clean target root"); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(targetRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve clean target root %q: %w", targetRoot, err)
	}
	absolute = filepath.Clean(absolute)
	rootHandle, rootIdentity, err := createFactoryCleanTargetRoot(absolute)
	if err != nil {
		return nil, fmt.Errorf("create exclusive clean target root %q: %w", absolute, err)
	}
	rootKey := canonicalProviderInputPathKey(".")
	return &factoryCleanTargetWriter{
		root: absolute,
		directoriesByPath: map[string]factoryCleanTargetDirectory{
			rootKey: {logicalPath: ".", identity: rootIdentity, handle: rootHandle},
		},
		directoryPathsByIdentity: map[providerInputStableFileIdentity]string{rootIdentity: "."},
		directoryOrder:           []string{rootKey},
		filePathsByPath:          map[string]string{},
		filePathsByIdentity:      map[providerInputStableFileIdentity]string{},
		hooks:                    hooks,
	}, nil
}

func (writer *factoryCleanTargetWriter) writeFile(relative string, raw []byte, mode os.FileMode) error {
	if writer == nil || writer.released {
		return fmt.Errorf("clean target writer is nil")
	}
	cleaned := filepath.Clean(relative)
	if relative == "" || filepath.IsAbs(relative) || filepath.VolumeName(relative) != "" || cleaned != relative || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return fmt.Errorf("clean target file path %q is not an exact relative path", relative)
	}
	if err := validateProviderInputPathSyntax(relative, "clean target file"); err != nil {
		return err
	}
	parent, err := writer.ensureParentDirectories(relative)
	if err != nil {
		return err
	}
	pathKey := canonicalProviderInputPathKey(relative)
	if prior, duplicate := writer.filePathsByPath[pathKey]; duplicate {
		return fmt.Errorf("clean target file paths %q and %q collapse to one native path", prior, relative)
	}
	if prior, duplicate := writer.directoriesByPath[pathKey]; duplicate {
		return fmt.Errorf("clean target file %q collides with directory %q", relative, prior.logicalPath)
	}
	if err := parent.handle.validate(); err != nil {
		return err
	}
	if writer.hooks.beforeFileCreate != nil {
		if err := writer.hooks.beforeFileCreate(relative); err != nil {
			return fmt.Errorf("before clean target file creation test hook: %w", err)
		}
	}
	target := filepath.Join(writer.root, relative)
	identity, err := parent.handle.createFile(filepath.Base(relative), target, raw, mode)
	if err != nil {
		return fmt.Errorf("create exclusive clean target file %q: %w", target, err)
	}
	if prior, collision := writer.filePathsByIdentity[identity]; collision {
		return fmt.Errorf("clean target file paths %q and %q resolve to one physical file", prior, relative)
	}
	writer.filePathsByPath[pathKey] = relative
	writer.filePathsByIdentity[identity] = relative
	return nil
}

func (writer *factoryCleanTargetWriter) ensureParentDirectories(relative string) (factoryCleanTargetDirectory, error) {
	relativeDir := filepath.Dir(relative)
	if relativeDir == "." {
		pathKey := canonicalProviderInputPathKey(".")
		registered, exists := writer.directoriesByPath[pathKey]
		if !exists || registered.logicalPath != "." {
			return factoryCleanTargetDirectory{}, fmt.Errorf("clean target root is not registered exactly once")
		}
		if err := registered.handle.validate(); err != nil {
			return factoryCleanTargetDirectory{}, err
		}
		return registered, nil
	}
	currentLogical := ""
	parentKey := canonicalProviderInputPathKey(".")
	for _, component := range strings.Split(relativeDir, string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			return factoryCleanTargetDirectory{}, fmt.Errorf("clean target parent contains invalid component %q", component)
		}
		currentLogical = filepath.Join(currentLogical, component)
		pathKey := canonicalProviderInputPathKey(currentLogical)
		if prior, exists := writer.directoriesByPath[pathKey]; exists {
			if prior.logicalPath != currentLogical {
				return factoryCleanTargetDirectory{}, fmt.Errorf("clean target directory paths %q and %q collapse to one native path", prior.logicalPath, currentLogical)
			}
			if err := prior.handle.validate(); err != nil {
				return factoryCleanTargetDirectory{}, err
			}
			parentKey = pathKey
			continue
		}
		parent, exists := writer.directoriesByPath[parentKey]
		if !exists {
			return factoryCleanTargetDirectory{}, fmt.Errorf("clean target parent for %q is not retained", currentLogical)
		}
		currentPath := filepath.Join(writer.root, currentLogical)
		handle, identity, err := parent.handle.createDirectory(component, currentPath)
		if err != nil {
			return factoryCleanTargetDirectory{}, fmt.Errorf("create exclusive clean target directory %q: %w", currentPath, err)
		}
		if prior, collision := writer.directoryPathsByIdentity[identity]; collision {
			_ = handle.close()
			return factoryCleanTargetDirectory{}, fmt.Errorf("clean target directory paths %q and %q resolve to one physical directory", prior, currentLogical)
		}
		writer.directoriesByPath[pathKey] = factoryCleanTargetDirectory{logicalPath: currentLogical, identity: identity, handle: handle}
		writer.directoryPathsByIdentity[identity] = currentLogical
		writer.directoryOrder = append(writer.directoryOrder, pathKey)
		parentKey = pathKey
	}
	pathKey := canonicalProviderInputPathKey(relativeDir)
	registered, exists := writer.directoriesByPath[pathKey]
	if !exists || registered.logicalPath != relativeDir {
		return factoryCleanTargetDirectory{}, fmt.Errorf("clean target parent directory %q is not registered exactly once", relativeDir)
	}
	if err := registered.handle.validate(); err != nil {
		return factoryCleanTargetDirectory{}, err
	}
	return registered, nil
}

func (writer *factoryCleanTargetWriter) finish() error {
	if writer == nil || writer.released {
		return nil
	}
	var validationErrors []error
	for _, pathKey := range writer.directoryOrder {
		if err := writer.directoriesByPath[pathKey].handle.validate(); err != nil {
			validationErrors = append(validationErrors, err)
		}
	}
	if err := writer.release(); err != nil {
		validationErrors = append(validationErrors, err)
	}
	return errors.Join(validationErrors...)
}

func (writer *factoryCleanTargetWriter) release() error {
	if writer == nil || writer.released {
		return nil
	}
	writer.released = true
	var releaseErrors []error
	for index := len(writer.directoryOrder) - 1; index >= 0; index-- {
		entry := writer.directoriesByPath[writer.directoryOrder[index]]
		if err := entry.handle.close(); err != nil {
			releaseErrors = append(releaseErrors, err)
		}
	}
	return errors.Join(releaseErrors...)
}

func validateFactoryCleanTargetDirectoryHandle(path string, retained *os.File, createdIdentity providerInputStableFileIdentity) error {
	openedInfo, err := retained.Stat()
	if err != nil {
		return fmt.Errorf("inspect retained clean target directory %q: %w", path, err)
	}
	openedIdentity, err := stableProviderInputFileIdentity(retained)
	if err != nil {
		return fmt.Errorf("derive retained clean target directory identity %q: %w", path, err)
	}
	if !openedInfo.IsDir() || fileInfoHasReparsePoint(openedInfo) || openedIdentity != createdIdentity {
		return fmt.Errorf("clean target directory %q changed retained identity", path)
	}
	current, err := openFactoryOutputDirectoryPathNoFollow(path)
	if err != nil {
		return err
	}
	defer current.Close()
	currentInfo, err := current.Stat()
	if err != nil {
		return err
	}
	currentIdentity, err := stableProviderInputFileIdentity(current)
	if err != nil {
		return err
	}
	if !currentInfo.IsDir() || currentIdentity != openedIdentity {
		return fmt.Errorf("clean target directory %q changed path identity", path)
	}
	return nil
}

func writeExactFactoryCleanTargetFile(file *os.File, path string, raw []byte, mode os.FileMode) (providerInputStableFileIdentity, error) {
	if file == nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("retain clean target file %q", path)
	}
	keepOpen := true
	defer func() {
		if keepOpen {
			_ = file.Close()
		}
	}()
	created, err := file.Stat()
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("inspect new clean target file %q: %w", path, err)
	}
	if !created.Mode().IsRegular() || fileInfoHasReparsePoint(created) {
		return providerInputStableFileIdentity{}, fmt.Errorf("clean target file %q is not a stable regular file", path)
	}
	createdIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("derive new clean target file identity %q: %w", path, err)
	}
	if err := file.Chmod(mode.Perm()); err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("set exact clean target file mode %q: %w", path, err)
	}
	written, err := io.Copy(file, bytes.NewReader(raw))
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("write exact clean target file %q: %w", path, err)
	}
	if written != int64(len(raw)) {
		return providerInputStableFileIdentity{}, fmt.Errorf("write exact clean target file %q: wrote %d bytes, want %d", path, written, len(raw))
	}
	afterWrite, err := file.Stat()
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("reinspect clean target file %q: %w", path, err)
	}
	afterWriteIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("rederive clean target file identity %q: %w", path, err)
	}
	if !afterWrite.Mode().IsRegular() || createdIdentity != afterWriteIdentity || afterWrite.Size() != int64(len(raw)) {
		return providerInputStableFileIdentity{}, fmt.Errorf("clean target file %q changed identity or size while writing", path)
	}
	if _, err := file.Seek(0, 0); err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("rewind clean target file %q: %w", path, err)
	}
	persisted, err := io.ReadAll(io.LimitReader(file, int64(len(raw))+1))
	if err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("read back clean target file %q: %w", path, err)
	}
	if !bytes.Equal(persisted, raw) {
		return providerInputStableFileIdentity{}, fmt.Errorf("clean target file %q differs from exact source bytes", path)
	}
	identity := afterWriteIdentity
	currentIdentity, currentInfo, err := stableProviderInputPathIdentity(path, "clean target file")
	if err != nil {
		return providerInputStableFileIdentity{}, err
	}
	if !currentInfo.Mode().IsRegular() || currentIdentity != identity {
		return providerInputStableFileIdentity{}, fmt.Errorf("clean target file %q changed path identity after creation", path)
	}
	if err := file.Close(); err != nil {
		return providerInputStableFileIdentity{}, fmt.Errorf("close exact clean target file %q: %w", path, err)
	}
	keepOpen = false
	return identity, nil
}

func factoryTrackedAndCandidateSourceListArgs() []string {
	return []string{
		"ls-files",
		"--cached",
		"--others",
		"--exclude-standard",
		"-z",
	}
}

func TestFactoryCleanSourceCopiesUntrackedCanonicalPathFiles(t *testing.T) {
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	candidate := filepath.Join(sourceRoot, "_canonical", "specs-repo", "candidate.go")
	candidateBytes := []byte("package candidate\n")
	if err := os.MkdirAll(filepath.Dir(candidate), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(candidate, candidateBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	copyFactoryTrackedAndCandidateSource(t, sourceRoot, targetRoot)
	for _, relative := range []string{
		"go.mod",
		"internal/providerplan/source.go",
		"_canonical/retained.txt",
		"_canonical/specs-repo/candidate.go",
	} {
		if _, err := os.Stat(filepath.Join(targetRoot, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("copied source omits %s: %v", relative, err)
		}
	}
	for relative, want := range map[string][]byte{
		"internal/providerplan/source.go":    []byte("package providerplan\n"),
		"_canonical/specs-repo/candidate.go": candidateBytes,
	} {
		got, err := os.ReadFile(filepath.Join(targetRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("copied source %s bytes = %q, want %q", relative, got, want)
		}
	}
}

func TestFactoryCleanTargetWriterRejectsPreexistingRoot(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	if err := os.Mkdir(targetRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := newFactoryCleanTargetWriter(targetRoot); err == nil || !strings.Contains(err.Error(), "create exclusive clean target root") {
		t.Fatalf("preexisting clean target root error = %v, want exclusive-create refusal", err)
	}
}

func TestFactoryCleanTargetWriterRejectsUnexpectedExistingLeaf(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	writer, err := newFactoryCleanTargetWriter(targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.release() }()
	if err := os.WriteFile(filepath.Join(targetRoot, "candidate.go"), []byte("preexisting bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writer.writeFile("candidate.go", []byte("replacement bytes\n"), 0o600); err == nil || !strings.Contains(err.Error(), "create exclusive clean target file") {
		t.Fatalf("preexisting clean target leaf error = %v, want exclusive-create refusal", err)
	}
}

func TestFactoryCleanTargetWriterRejectsUnexpectedExistingDirectory(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	writer, err := newFactoryCleanTargetWriter(targetRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.release() }()
	if err := os.Mkdir(filepath.Join(targetRoot, "candidate"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writer.writeFile(filepath.Join("candidate", "file.go"), []byte("package candidate\n"), 0o600); err == nil || !strings.Contains(err.Error(), "create exclusive clean target directory") {
		t.Fatalf("preexisting clean target directory error = %v, want exclusive-create refusal", err)
	}
}

func TestFactoryCleanTargetWriterParentReplacementCannotRedirectCreate(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		relative string
		prepare  func(t *testing.T, writer *factoryCleanTargetWriter, targetRoot string) (string, string)
	}{
		{
			name:     "root",
			relative: "candidate.go",
			prepare: func(t *testing.T, _ *factoryCleanTargetWriter, targetRoot string) (string, string) {
				return targetRoot, filepath.Join(filepath.Dir(targetRoot), "retained-clean-source")
			},
		},
		{
			name:     "nested parent",
			relative: filepath.Join("candidate", "candidate.go"),
			prepare: func(t *testing.T, writer *factoryCleanTargetWriter, targetRoot string) (string, string) {
				t.Helper()
				if err := writer.writeFile(filepath.Join("candidate", "bootstrap.go"), []byte("package bootstrap\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				parent := filepath.Join(targetRoot, "candidate")
				return parent, filepath.Join(targetRoot, "retained-candidate")
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			tempRoot := t.TempDir()
			targetRoot := filepath.Join(tempRoot, "clean-source")
			writer, err := newFactoryCleanTargetWriter(targetRoot)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = writer.release() }()
			parent, retainedParent := testCase.prepare(t, writer, targetRoot)
			hookCalled := false
			writer.hooks.beforeFileCreate = func(relative string) error {
				if relative != testCase.relative {
					return fmt.Errorf("mutation hook relative path = %q, want %q", relative, testCase.relative)
				}
				if err := os.Rename(parent, retainedParent); err != nil {
					return err
				}
				if err := os.Mkdir(parent, 0o700); err != nil {
					return err
				}
				hookCalled = true
				return nil
			}
			want := []byte("must stay bound to the retained parent handle\n")
			if err := writer.writeFile(testCase.relative, want, 0o600); err == nil {
				t.Fatal("parent replacement was reported as a successful clean-target write")
			}
			if !hookCalled {
				t.Fatal("parent replacement hook did not run")
			}
			replacementLeaf := filepath.Join(parent, filepath.Base(testCase.relative))
			if _, err := os.Lstat(replacementLeaf); !os.IsNotExist(err) {
				t.Fatalf("replacement parent received copied source bytes: %v", err)
			}
			retainedLeaf := filepath.Join(retainedParent, filepath.Base(testCase.relative))
			got, err := os.ReadFile(retainedLeaf)
			if err != nil {
				t.Fatalf("retained parent did not receive the handle-relative write: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("retained-parent bytes = %q, want %q", got, want)
			}
		})
	}
}

func TestFactoryCleanSourceCopiesTrackedExecutableMode(t *testing.T) {
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	executable := filepath.Join(sourceRoot, "scripts", "candidate.sh")
	executableBytes := []byte("#!/bin/sh\nexit 0\n")
	if err := os.MkdirAll(filepath.Dir(executable), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, executableBytes, 0o700); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"add", "scripts/candidate.sh"}})
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"update-index", "--chmod=+x", "scripts/candidate.sh"}})
	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	copyFactoryTrackedAndCandidateSource(t, sourceRoot, targetRoot)
	info, err := os.Stat(filepath.Join(targetRoot, "scripts", "candidate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		t.Fatalf("copied tracked executable mode = %v, want an executable bit", info.Mode().Perm())
	}
	got, err := os.ReadFile(filepath.Join(targetRoot, "scripts", "candidate.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, executableBytes) {
		t.Fatalf("copied tracked executable bytes = %q, want %q", got, executableBytes)
	}
}

func TestFactoryReleaseCommitPreservesTrackedIgnoredCRLFBytesAndMode(t *testing.T) {
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	for relative, raw := range map[string][]byte{
		".gitignore":     []byte("scripts/ignored.go\n"),
		".gitattributes": []byte("*.go text eol=lf\n"),
	} {
		if err := os.WriteFile(filepath.Join(sourceRoot, relative), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	relative := filepath.FromSlash("scripts/ignored.go")
	path := filepath.Join(sourceRoot, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	want := []byte("package ignored\r\n\r\nconst Exact = \"CRLF\"\r\n")
	if err := os.WriteFile(path, want, 0o700); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"add", ".gitignore", ".gitattributes"}})
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"add", "-f", "scripts/ignored.go"}})
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"update-index", "--chmod=+x", "scripts/ignored.go"}})
	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	roster := copyFactoryTrackedAndCandidateSourceRoster(t, sourceRoot, targetRoot)
	initializeFactoryReleaseRepository(t, targetRoot)
	commitFactoryReleaseSourceRoster(t, targetRoot, roster)
	got := runFactoryCommand(t, targetRoot, factoryCommandOptions{name: "git", args: []string{"show", "HEAD:scripts/ignored.go"}})
	if !bytes.Equal(got, want) {
		t.Fatalf("committed tracked ignored source bytes = %q, want exact CRLF bytes %q", got, want)
	}
	fields := strings.Fields(string(runFactoryCommand(t, targetRoot, factoryCommandOptions{name: "git", args: []string{"ls-tree", "HEAD", "scripts/ignored.go"}})))
	if len(fields) == 0 || fields[0] != "100755" {
		t.Fatalf("committed tracked ignored source tree entry = %q, want mode 100755", fields)
	}
}

func TestFactoryCleanSourceRejectsEarlierSourceMutationAfterTargetCopy(t *testing.T) {
	if os.Getenv("VELENZA_FACTORY_SOURCE_MUTATION_CHILD") == "1" {
		sourceRoot := os.Getenv("VELENZA_FACTORY_CLEAN_SOURCE_COPY_SOURCE")
		targetRoot := os.Getenv("VELENZA_FACTORY_CLEAN_SOURCE_COPY_TARGET")
		victim := filepath.FromSlash("00-victim.go")
		copyFactoryTrackedAndCandidateSourceRosterWithHooks(t, sourceRoot, targetRoot, factorySourceCopyHooks{
			afterTargetFileCopy: func(relative string) error {
				if relative != victim {
					return nil
				}
				return os.WriteFile(filepath.Join(sourceRoot, victim), []byte("package changed\n"), 0o600)
			},
		})
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	victim := filepath.Join(sourceRoot, "00-victim.go")
	if err := os.WriteFile(victim, []byte("package victim1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"add", "00-victim.go"}})
	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	command := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	command.Env = append(os.Environ(),
		"VELENZA_FACTORY_SOURCE_MUTATION_CHILD=1",
		"VELENZA_FACTORY_CLEAN_SOURCE_COPY_SOURCE="+sourceRoot,
		"VELENZA_FACTORY_CLEAN_SOURCE_COPY_TARGET="+targetRoot,
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("source mutation after target copy was accepted:\n%s", output)
	}
	if !bytes.Contains(output, []byte("changed after its exact clean-source copy")) {
		t.Fatalf("source mutation failure omits final full-roster revalidation:\n%s", output)
	}
}

func TestFactoryCleanSourceRejectsTrackedGitSymlinkMode(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	linkPath := filepath.Join(sourceRoot, "candidate-link")
	if err := os.WriteFile(linkPath, []byte("outside-target"), 0o600); err != nil {
		t.Fatal(err)
	}
	objectID := strings.TrimSpace(string(runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"hash-object", "-w", "--", "candidate-link"},
	})))
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"update-index", "--add", "--cacheinfo", "120000," + objectID + ",candidate-link"},
	})
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "unsupported Git index mode \"120000\"")
}

func TestFactoryCleanSourceRejectsTrackedGitlinkMode(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"config", "user.name", "Factory Test"}})
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"config", "user.email", "factory-test@example.invalid"}})
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"commit", "-q", "-m", "fixture base"}})
	commitID := strings.TrimSpace(string(runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"rev-parse", "HEAD"}})))
	gitlinkPath := filepath.Join(sourceRoot, "candidate-gitlink")
	if err := os.WriteFile(gitlinkPath, []byte("ordinary placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"update-index", "--add", "--cacheinfo", "160000," + commitID + ",candidate-gitlink"},
	})
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "unsupported Git index mode \"160000\"")
}

func TestFactoryCleanSourceRejectsPhysicalHardlinkAliases(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	alias := filepath.Join(sourceRoot, "candidate-hardlink.go")
	if err := os.Link(filepath.Join(sourceRoot, "internal", "providerplan", "source.go"), alias); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"add", "candidate-hardlink.go"}})
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "resolve to one physical file")
}

func TestFactoryCleanSourceRejectsCanonicalNestedRepository(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	canonicalCheckout := filepath.Join(sourceRoot, "_canonical", "specs-repo")
	if err := os.MkdirAll(canonicalCheckout, 0o700); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, canonicalCheckout, factoryCommandOptions{
		name: "git", args: []string{"init", "-q", "-b", "main"},
	})
	assertFactoryCleanSourceCopyFails(t, sourceRoot, fmt.Sprintf(
		"candidate source %q is not a regular file",
		filepath.FromSlash("_canonical/specs-repo"),
	))
}

func TestFactoryCleanSourceRejectsUnrelatedNestedRepository(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	nested := filepath.Join(sourceRoot, "candidate", "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, nested, factoryCommandOptions{
		name: "git", args: []string{"init", "-q", "-b", "main"},
	})
	assertFactoryCleanSourceCopyFails(t, sourceRoot, fmt.Sprintf(
		"candidate source %q is not a regular file",
		filepath.FromSlash("candidate/nested"),
	))
}

func newFactoryCleanSourceTestRepository(t *testing.T) string {
	t.Helper()
	sourceRoot := filepath.Join(t.TempDir(), "source")
	for relative, raw := range map[string][]byte{
		"go.mod":                          []byte("module example.invalid/factory-clean-source\n\ngo 1.26\n"),
		"internal/providerplan/source.go": []byte("package providerplan\n"),
		"_canonical/retained.txt":         []byte("tracked canonical neighbor\n"),
	} {
		path := filepath.Join(sourceRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"init", "-q", "-b", "main"},
	})
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{
		name: "git", args: []string{"add", "go.mod", "internal/providerplan/source.go", "_canonical/retained.txt"},
	})
	return sourceRoot
}

func runFactoryCleanSourceCopyFailureChild(t *testing.T) bool {
	t.Helper()
	if os.Getenv("VELENZA_FACTORY_CLEAN_SOURCE_COPY_FAILURE_CHILD") != "1" {
		return false
	}
	sourceRoot := os.Getenv("VELENZA_FACTORY_CLEAN_SOURCE_COPY_SOURCE")
	targetRoot := os.Getenv("VELENZA_FACTORY_CLEAN_SOURCE_COPY_TARGET")
	if sourceRoot == "" || targetRoot == "" {
		t.Fatal("clean-source failure child omits its source or target root")
	}
	copyFactoryTrackedAndCandidateSource(t, sourceRoot, targetRoot)
	return true
}

func assertFactoryCleanSourceCopyFails(t *testing.T, sourceRoot, want string) {
	t.Helper()
	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	command := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
	command.Env = append(os.Environ(),
		"VELENZA_FACTORY_CLEAN_SOURCE_COPY_FAILURE_CHILD=1",
		"VELENZA_FACTORY_CLEAN_SOURCE_COPY_SOURCE="+sourceRoot,
		"VELENZA_FACTORY_CLEAN_SOURCE_COPY_TARGET="+targetRoot,
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatalf("copy unexpectedly accepted nonregular candidate source:\n%s", output)
	}
	if !bytes.Contains(output, []byte(want)) {
		t.Fatalf("copy failure omits %q:\n%s", want, output)
	}
}
