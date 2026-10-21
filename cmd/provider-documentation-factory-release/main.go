package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	releaseCommandName                  = "provider-documentation-factory-release"
	releaseGoVersion                    = "go1.27.1"
	releaseBuildTag                     = "factory_release"
	releaseModulePath                   = "github.com/velenzaboc/velenza-canon"
	releaseRunnerPackage                = "./cmd/provider-documentation-factory-run"
	releaseRunnerImportPath             = releaseModulePath + "/cmd/provider-documentation-factory-run"
	releaseReceiptKind                  = "provider_documentation_factory_offline_run_receipt"
	releaseReceiptVersion               = "2"
	releaseReceiptResult                = "compiled_and_verified_candidate_only"
	releaseReceiptScope                 = "offline_exact_input_four_stage_compilation_and_provider_plan_verification"
	releaseValidationProfileID          = "provider_documentation_factory_runtime_validation"
	releaseValidationVersion            = "3"
	releaseValidationResult             = "candidate_runtime_validation_pass"
	releaseValidationContract           = "result=candidate_runtime_validation_pass;portable_receipt_recomputed;tool_identity_validated;exact_execution_profile_validated;honest_measurement_scope_validated;executable_digest_bound;input_admission_recomputed;four_stage_receipts_validated;preflight_receipt_validated;completion_classification_fail_closed"
	releaseRunnerContract               = "exactly_four_ordered_stage_manifests;runner_owned_predecessor_and_evidence_reuse;one_union_input_roster;intake_authority_and_evidence_cross_binding;verifier_admitted_complete_dependency_closure;no_network_graph_admission_tenant_credential_deployment_or_live_acceptance_claim"
	releaseBuildMetadataSource          = "go_runtime_debug_build_info"
	releaseExecutableScope              = "launch_path_open_regular_file"
	productionSourceRunReceiptKind      = "provider_documentation_factory_production_source_run_receipt"
	productionSourceRunReceiptVersion   = "1"
	productionSourceRunReceiptResult    = "authenticated_source_compiled_and_verified_candidate_only"
	productionSourceRunReceiptScope     = "sealed_source_package_exact_provider_evidence_identity_four_stage_candidate_compilation"
	sourceCompileReceiptKind            = "provider_documentation_factory_source_compile_receipt"
	sourceCompileReceiptVersion         = "1"
	sourceCompileReceiptResult          = "compiled_and_verified_candidate_bundle_only"
	sourceCompileReceiptScope           = "offline_sealed_source_package_candidate_materialization_and_four_stage_factory_verification"
	productionSourceVerificationKind    = "provider_documentation_factory_production_source_verification"
	productionSourceVerificationVersion = "1"
	productionSourceVerificationResult  = "authenticated_current_complete_provider_evidence_identity_set_verified"
	maximumCommandOutput                = 64 << 20
	maximumRosterEntries                = 100_000
	maximumRosterBytes                  = 4 << 30
	maximumReleaseJSONDepth             = 128
)

var errChildExited = errors.New("factory child exited")

type childExitError struct {
	code int
}

func (err childExitError) Error() string { return errChildExited.Error() }
func (err childExitError) Unwrap() error { return errChildExited }

type releaseOptions struct {
	sourceRoot    string
	commit        string
	goExecutable  string
	gitExecutable string
	childArgs     []string
}

type productionSourceChildSelection struct {
	enabled          bool
	expectedProvider string
}

type measuredExecutable struct {
	path   string
	digest string
	size   int64
	mtime  int64
}

type measuredTree struct {
	root   string
	digest string
	files  int
	bytes  int64
}

type childBuildExpectation struct {
	toolIdentitySHA256      string
	moduleGraphSHA256       string
	buildRecipeSHA256       string
	executionIdentitySHA256 string
	buildSettingsSHA256     string
}

type releaseWorkspace struct {
	tempRoot       string
	root           string
	projectionRoot string
	onlineEnv      []string
	offlineEnv     []string
}

type gitHelperEntry struct {
	kind         string
	logicalPath  string
	rawTarget    string
	resolvedPath string
}

type measuredRegularPayload struct {
	digest string
	size   int64
	mtime  int64
}

type sourceRosterEntry struct {
	path          string
	nativePath    string
	mode          string
	objectID      string
	contentSHA256 string
	byteCount     int64
}

type sourceRoster struct {
	entries []sourceRosterEntry
	byPath  map[string]sourceRosterEntry
	root    string
}

type listedModule struct {
	Path    string        `json:"Path"`
	Version string        `json:"Version"`
	Sum     string        `json:"Sum"`
	Main    bool          `json:"Main"`
	Replace *listedModule `json:"Replace"`
}

type listedPackageModule struct {
	Path string `json:"Path"`
	Main bool   `json:"Main"`
}

type listedPackage struct {
	ImportPath string               `json:"ImportPath"`
	Dir        string               `json:"Dir"`
	Module     *listedPackageModule `json:"Module"`
	GoFiles    []string             `json:"GoFiles"`
	CgoFiles   []string             `json:"CgoFiles"`
	SFiles     []string             `json:"SFiles"`
	SysoFiles  []string             `json:"SysoFiles"`
	EmbedFiles []string             `json:"EmbedFiles"`
}

type childReceiptEnvelope struct {
	ReceiptKind    string `json:"receipt_kind"`
	ReceiptVersion string `json:"receipt_version"`
	Result         string `json:"result"`
	Scope          string `json:"scope"`
	ToolIdentity   struct {
		CommandPath            string `json:"command_path"`
		ModulePath             string `json:"module_path"`
		ModuleVersion          string `json:"module_version"`
		GoVersion              string `json:"go_version"`
		VCS                    string `json:"vcs"`
		VCSRevision            string `json:"vcs_revision"`
		VCSTime                string `json:"vcs_time"`
		VCSModified            bool   `json:"vcs_modified"`
		BuildTags              string `json:"build_tags"`
		ModuleGraphSHA256      string `json:"module_graph_sha256"`
		BuildRecipeSHA256      string `json:"build_recipe_sha256"`
		SourceRosterSHA256     string `json:"source_roster_sha256"`
		RunnerContractSHA256   string `json:"runner_contract_sha256"`
		BuildIdentitySHA256    string `json:"build_identity_sha256"`
		ReproducibleSourceTree bool   `json:"reproducible_source_tree"`
	} `json:"tool_identity"`
	ExecutionIdentity struct {
		PortableBuildIdentitySHA256 string          `json:"portable_build_identity_sha256"`
		BuildMetadataSource         string          `json:"build_metadata_source"`
		ExecutableMeasurementScope  string          `json:"executable_measurement_scope"`
		TargetOS                    string          `json:"target_os"`
		TargetArch                  string          `json:"target_arch"`
		BuildSettings               json.RawMessage `json:"build_settings"`
		BuildSettingsSHA256         string          `json:"build_settings_sha256"`
		ExecutableSHA256            string          `json:"executable_sha256"`
		ExecutableByteCount         int64           `json:"executable_byte_count"`
		GoExecutableSHA256          string          `json:"go_executable_sha256"`
		GitExecutableSHA256         string          `json:"git_executable_sha256"`
		GoToolchainSHA256           string          `json:"go_toolchain_sha256"`
		GitToolchainSHA256          string          `json:"git_toolchain_sha256"`
		GoToolchainFileCount        int64           `json:"go_toolchain_file_count"`
		GoToolchainByteCount        int64           `json:"go_toolchain_byte_count"`
		GitToolchainFileCount       int64           `json:"git_toolchain_file_count"`
		GitToolchainByteCount       int64           `json:"git_toolchain_byte_count"`
		ExecutionIdentitySHA256     string          `json:"execution_identity_sha256"`
	} `json:"execution_identity"`
	ValidationIdentity    json.RawMessage `json:"validation_identity"`
	InputAdmissionProof   json.RawMessage `json:"input_admission_proof"`
	InputResources        json.RawMessage `json:"input_resources"`
	Stages                json.RawMessage `json:"stages"`
	PreflightReceipt      json.RawMessage `json:"preflight_receipt"`
	Completion            json.RawMessage `json:"completion"`
	BodyFree              bool            `json:"body_free"`
	PortableReceiptSHA256 string          `json:"portable_receipt_sha256"`
	ReceiptSHA256         string          `json:"receipt_sha256"`
}

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(code)
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithExecutor(args, stdout, stderr, executeRelease)
}

func runWithExecutor(args []string, stdout, stderr io.Writer, execute func(releaseOptions, io.Writer, io.Writer) error) int {
	options, err := parseReleaseOptions(args)
	if err != nil {
		fmt.Fprintln(stderr, releaseCommandName+": invalid release invocation")
		return 2
	}
	err = execute(options, stdout, stderr)
	if err == nil {
		return 0
	}
	var childErr childExitError
	if errors.As(err, &childErr) {
		if childErr.code > 0 {
			return childErr.code
		}
		return 1
	}
	fmt.Fprintln(stderr, releaseCommandName+": release ceremony failed")
	return 1
}

func parseReleaseOptions(args []string) (releaseOptions, error) {
	delimiter := -1
	for index, arg := range args {
		if arg == "--" {
			delimiter = index
			break
		}
	}
	if delimiter < 0 {
		return releaseOptions{}, fmt.Errorf("missing child-argument delimiter")
	}
	flags := flag.NewFlagSet(releaseCommandName, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options releaseOptions
	flags.StringVar(&options.sourceRoot, "source-root", "", "existing Git source repository root")
	flags.StringVar(&options.commit, "commit", "", "full source commit object identity")
	flags.StringVar(&options.goExecutable, "go-executable", "", "absolute Go trust-root executable")
	flags.StringVar(&options.gitExecutable, "git-executable", "", "absolute Git trust-root executable")
	if err := flags.Parse(args[:delimiter]); err != nil || flags.NArg() != 0 {
		return releaseOptions{}, fmt.Errorf("invalid launcher flags")
	}
	if strings.TrimSpace(options.sourceRoot) == "" || strings.TrimSpace(options.commit) == "" || strings.TrimSpace(options.goExecutable) == "" || strings.TrimSpace(options.gitExecutable) == "" {
		return releaseOptions{}, fmt.Errorf("required launcher flag is absent")
	}
	if options.sourceRoot != strings.TrimSpace(options.sourceRoot) || options.commit != strings.TrimSpace(options.commit) || options.goExecutable != strings.TrimSpace(options.goExecutable) || options.gitExecutable != strings.TrimSpace(options.gitExecutable) {
		return releaseOptions{}, fmt.Errorf("launcher flag is padded")
	}
	options.childArgs = append([]string(nil), args[delimiter+1:]...)
	return options, nil
}

func executeRelease(options releaseOptions, stdout, stderr io.Writer) error {
	sourceRoot, err := resolveSourceRoot(options.sourceRoot)
	if err != nil {
		return err
	}
	if !validFullCommitID(options.commit) {
		return fmt.Errorf("commit is not a full lowercase Git object identity")
	}
	goTool, err := measureExecutable(options.goExecutable)
	if err != nil {
		return fmt.Errorf("measure Go trust root: %w", err)
	}
	gitTool, err := measureExecutable(options.gitExecutable)
	if err != nil {
		return fmt.Errorf("measure Git trust root: %w", err)
	}
	workspace, err := newReleaseWorkspace(goTool.path, gitTool.path)
	if err != nil {
		return err
	}
	defer removeReleaseWorkspace(workspace.tempRoot, workspace.root)
	if err := verifyGoVersion(goTool.path, workspace.onlineEnv); err != nil {
		return err
	}
	goRoot, err := resolveGoRoot(goTool.path, workspace.onlineEnv)
	if err != nil {
		return err
	}
	goToolchain, err := measureRegularTree(goRoot)
	if err != nil {
		return fmt.Errorf("measure complete Go toolchain: %w", err)
	}
	gitExecRoot, err := resolveGitExecRoot(gitTool.path, workspace.onlineEnv)
	if err != nil {
		return err
	}
	gitToolchain, err := measureGitHelperTree(gitExecRoot)
	if err != nil {
		return fmt.Errorf("measure complete Git helper toolchain: %w", err)
	}
	gitShim, err := installGitInvocationShim(goTool.path, gitTool.path, workspace)
	if err != nil {
		return err
	}
	if err := verifySourceRepository(gitTool.path, sourceRoot, options.commit, workspace.onlineEnv); err != nil {
		return err
	}
	roster, err := createCommitProjection(gitTool.path, sourceRoot, options.commit, workspace)
	if err != nil {
		return err
	}
	if err := verifyCommitProjection(gitTool.path, options.commit, workspace.projectionRoot, workspace.onlineEnv, roster); err != nil {
		return err
	}
	if err := rejectUnpinnedModuleReplacements(goTool.path, workspace.projectionRoot, workspace.onlineEnv); err != nil {
		return err
	}
	if err := prefetchSelectedModuleGraph(goTool.path, workspace.projectionRoot, workspace.onlineEnv); err != nil {
		return err
	}
	if err := runSilent(goTool.path, []string{"mod", "verify"}, workspace.projectionRoot, workspace.onlineEnv); err != nil {
		return fmt.Errorf("verify exact module graph: %w", err)
	}
	if err := verifyCommitProjection(gitTool.path, options.commit, workspace.projectionRoot, workspace.onlineEnv, roster); err != nil {
		return err
	}
	if err := verifySelectedMainModuleInputs(goTool.path, workspace.projectionRoot, workspace.offlineEnv, roster); err != nil {
		return err
	}
	executableName := "provider-documentation-factory-run"
	if runtime.GOOS == "windows" {
		executableName += ".exe"
	}
	outputDirectory := filepath.Join(workspace.root, "output")
	if err := os.Mkdir(outputDirectory, 0o700); err != nil {
		return fmt.Errorf("create release output directory: %w", err)
	}
	childExecutable := filepath.Join(outputDirectory, executableName)
	linkerFlags := strings.Join([]string{
		"-X=" + releaseModulePath + "/internal/providerplan.factoryReleaseSourceRosterSHA256=" + roster.root,
		"-X=" + releaseModulePath + "/internal/providerplan.factoryReleaseGoExecutableSHA256=" + goTool.digest,
		"-X=" + releaseModulePath + "/internal/providerplan.factoryReleaseGitExecutableSHA256=" + gitTool.digest,
		"-X=" + releaseModulePath + "/internal/providerplan.factoryReleaseGoToolchainSHA256=" + goToolchain.digest,
		"-X=" + releaseModulePath + "/internal/providerplan.factoryReleaseGitToolchainSHA256=" + gitToolchain.digest,
		"-X=" + releaseModulePath + "/internal/providerplan.factoryReleaseGoToolchainFiles=" + strconv.Itoa(goToolchain.files),
		"-X=" + releaseModulePath + "/internal/providerplan.factoryReleaseGoToolchainBytes=" + strconv.FormatInt(goToolchain.bytes, 10),
		"-X=" + releaseModulePath + "/internal/providerplan.factoryReleaseGitToolchainFiles=" + strconv.Itoa(gitToolchain.files),
		"-X=" + releaseModulePath + "/internal/providerplan.factoryReleaseGitToolchainBytes=" + strconv.FormatInt(gitToolchain.bytes, 10),
	}, " ")
	buildArgs := []string{
		"build",
		"-mod=readonly",
		"-buildvcs=true",
		"-trimpath",
		"-tags=" + releaseBuildTag,
		"-pgo=off",
		"-ldflags=" + linkerFlags,
		"-o", childExecutable,
		releaseRunnerPackage,
	}
	if err := runSilent(goTool.path, buildArgs, workspace.projectionRoot, workspace.offlineEnv); err != nil {
		return fmt.Errorf("build exact factory child: %w", err)
	}
	if err := verifyCommitProjection(gitTool.path, options.commit, workspace.projectionRoot, workspace.offlineEnv, roster); err != nil {
		return err
	}
	if err := verifyMeasuredExecutable(goTool); err != nil {
		return fmt.Errorf("Go trust root changed during release: %w", err)
	}
	if err := verifyMeasuredExecutable(gitTool); err != nil {
		return fmt.Errorf("Git trust root changed during release: %w", err)
	}
	if err := verifyMeasuredExecutable(gitShim); err != nil {
		return fmt.Errorf("closed Git invocation shim changed during release: %w", err)
	}
	finalGoToolchain, err := measureRegularTree(goRoot)
	if err != nil || finalGoToolchain != goToolchain {
		return fmt.Errorf("Go toolchain changed during release")
	}
	finalGitToolchain, err := measureGitHelperTree(gitExecRoot)
	if err != nil || finalGitToolchain != gitToolchain {
		return fmt.Errorf("Git helper toolchain changed during release")
	}
	child, err := openRetainedChildExecutable(childExecutable)
	if err != nil || child.measurement.size <= 0 {
		return fmt.Errorf("built factory child is not a regular executable")
	}
	defer child.close()
	childBuild, err := inspectChildBuildIdentity(child.file, roster.root, child.measurement, goTool, gitTool, goToolchain, gitToolchain)
	if err != nil {
		return err
	}
	return executeAndValidateChild(child, childBuild, options, sourceRoot, workspace.offlineEnv, roster.root, goTool, gitTool, goToolchain, gitToolchain, stdout, stderr)
}

func executeAndValidateChild(child *retainedChildExecutable, childBuild childBuildExpectation, options releaseOptions, sourceRoot string, environment []string, rosterRoot string, goTool, gitTool measuredExecutable, goToolchain, gitToolchain measuredTree, stdout, stderr io.Writer) error {
	productionSelection, err := selectProductionSourceChild(options.childArgs)
	if err != nil {
		return err
	}
	outPath, hasOut, childArgs, err := splitChildReceiptPath(options.childArgs, sourceRoot)
	if err != nil {
		return err
	}
	privateReceiptPath := child.measurement.path + ".validated-receipt.json"
	if _, statErr := os.Lstat(privateReceiptPath); statErr == nil || !errors.Is(statErr, fs.ErrNotExist) {
		return fmt.Errorf("private child receipt output is not new")
	}
	childArgs = append(childArgs, "--out", privateReceiptPath)
	command, err := child.command(childArgs)
	if err != nil {
		return err
	}
	command.Dir = sourceRoot
	command.Env = append([]string(nil), environment...)
	command.Stdin = os.Stdin
	var childStdout, childStderr limitedBuffer
	childStdout.limit = maximumCommandOutput
	childStderr.limit = maximumCommandOutput
	command.Stdout = &childStdout
	command.Stderr = &childStderr
	if runErr := command.Run(); runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return childExitError{code: exitErr.ExitCode()}
		}
		return fmt.Errorf("execute exact factory child: %w", runErr)
	}
	if err := child.verify(); err != nil {
		return err
	}
	if len(childStderr.Bytes()) != 0 {
		return fmt.Errorf("successful factory child emitted stderr")
	}
	if len(childStdout.Bytes()) != 0 {
		return fmt.Errorf("child emitted stdout while publishing its private receipt")
	}
	receiptRaw, err := readPrivateChildReceipt(privateReceiptPath)
	if err != nil || validateReleasedChildReceipt(receiptRaw, productionSelection, options.commit, rosterRoot, goTool, gitTool, goToolchain, gitToolchain, child.measurement, childBuild) != nil {
		return fmt.Errorf("child receipt does not match independently selected release identity")
	}
	if hasOut {
		if err := publishValidatedReceipt(outPath, receiptRaw); err != nil {
			return fmt.Errorf("publish independently validated child receipt: %w", err)
		}
		return nil
	}
	count, err := stdout.Write(receiptRaw)
	if err != nil {
		return fmt.Errorf("publish validated child receipt: %w", err)
	}
	if count != len(receiptRaw) {
		return fmt.Errorf("publish validated child receipt: %w", io.ErrShortWrite)
	}
	return nil
}

func selectProductionSourceChild(args []string) (productionSourceChildSelection, error) {
	knownValueFlags := map[string]struct{}{
		"evidence-intake-inputs": {}, "semantic-extraction-inputs": {}, "graph-compile-inputs": {}, "full-factory-inputs": {},
		"ood": {}, "expected-ood-sha256": {}, "grand-vision": {}, "expected-grand-vision-sha256": {},
		"source-record": {}, "expected-source-record-sha256": {}, "source-package": {},
		"source-verification-receipt": {}, "expected-provider": {}, "output-root": {}, "out": {},
		"evidence-manifest": {}, "dependency-artifact": {},
	}
	var selection productionSourceChildSelection
	foundVerificationReceipt := false
	foundProvider := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			continue
		}
		nameValue := strings.TrimLeft(arg, "-")
		name, value, hasEquals := strings.Cut(nameValue, "=")
		if _, known := knownValueFlags[name]; !known {
			continue
		}
		if !hasEquals {
			if index+1 >= len(args) {
				return productionSourceChildSelection{}, fmt.Errorf("child --%s value is absent", name)
			}
			index++
			value = args[index]
		}
		switch name {
		case "source-verification-receipt":
			if foundVerificationReceipt {
				return productionSourceChildSelection{}, fmt.Errorf("child --source-verification-receipt is duplicated")
			}
			if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
				return productionSourceChildSelection{}, fmt.Errorf("child --source-verification-receipt value is empty or padded")
			}
			foundVerificationReceipt = true
		case "expected-provider":
			if foundProvider {
				return productionSourceChildSelection{}, fmt.Errorf("child --expected-provider is duplicated")
			}
			if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
				return productionSourceChildSelection{}, fmt.Errorf("child --expected-provider value is empty or padded")
			}
			foundProvider = true
			selection.expectedProvider = value
		}
	}
	if foundVerificationReceipt != foundProvider {
		return productionSourceChildSelection{}, fmt.Errorf("production source child selection is incomplete")
	}
	selection.enabled = foundVerificationReceipt
	return selection, nil
}

func splitChildReceiptPath(args []string, sourceRoot string) (string, bool, []string, error) {
	var value string
	found := false
	forwarded := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--" {
			forwarded = append(forwarded, args[index:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			forwarded = append(forwarded, arg)
			continue
		}
		nameValue := strings.TrimLeft(arg, "-")
		name, flagValue, hasEquals := strings.Cut(nameValue, "=")
		if name != "out" {
			forwarded = append(forwarded, arg)
			continue
		}
		if found {
			return "", false, nil, fmt.Errorf("child --out is duplicated")
		}
		if !hasEquals {
			if index+1 >= len(args) {
				return "", false, nil, fmt.Errorf("child --out value is absent")
			}
			index++
			flagValue = args[index]
		}
		value = flagValue
		found = true
	}
	if !found {
		return "", false, forwarded, nil
	}
	if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
		return "", false, nil, fmt.Errorf("child --out value is empty or padded")
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(sourceRoot, value)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", false, nil, err
	}
	return filepath.Clean(abs), true, forwarded, nil
}

func validateChildReceipt(raw []byte, commit, rosterRoot string, goTool, gitTool measuredExecutable, goToolchain, gitToolchain measuredTree, child measuredExecutable, childBuild childBuildExpectation) error {
	object, err := decodeReleaseJSONObject(raw)
	if err != nil {
		return err
	}
	if err := requireExactObjectKeys(object, []string{
		"receipt_kind", "receipt_version", "result", "scope", "tool_identity", "execution_identity",
		"validation_identity", "input_admission_proof", "input_resources", "stages", "preflight_receipt",
		"completion", "body_free", "portable_receipt_sha256", "receipt_sha256",
	}); err != nil {
		return fmt.Errorf("child receipt schema: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	var receipt childReceiptEnvelope
	if err := decoder.Decode(&receipt); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("child receipt contains trailing JSON")
	}
	if receipt.ReceiptKind != releaseReceiptKind || receipt.ReceiptVersion != releaseReceiptVersion || receipt.Result != releaseReceiptResult || receipt.Scope != releaseReceiptScope || !receipt.BodyFree || !validSHA256(receipt.PortableReceiptSHA256) || !validSHA256(receipt.ReceiptSHA256) || receipt.ToolIdentity.CommandPath != releaseRunnerImportPath || receipt.ToolIdentity.ModulePath != releaseModulePath || strings.TrimSpace(receipt.ToolIdentity.ModuleVersion) == "" || receipt.ToolIdentity.GoVersion != releaseGoVersion || receipt.ToolIdentity.VCS != "git" || receipt.ToolIdentity.VCSRevision != commit || receipt.ToolIdentity.VCSModified || receipt.ToolIdentity.BuildTags != releaseBuildTag || !receipt.ToolIdentity.ReproducibleSourceTree || receipt.ToolIdentity.SourceRosterSHA256 != rosterRoot || receipt.ToolIdentity.RunnerContractSHA256 != sha256String(releaseRunnerContract) {
		return fmt.Errorf("child tool identity differs from release selection")
	}
	if receipt.ToolIdentity.ModuleGraphSHA256 != childBuild.moduleGraphSHA256 || receipt.ToolIdentity.BuildRecipeSHA256 != childBuild.buildRecipeSHA256 || receipt.ToolIdentity.BuildIdentitySHA256 != childBuild.toolIdentitySHA256 {
		return fmt.Errorf("child portable build identity differs from independently read executable metadata")
	}
	if receipt.ExecutionIdentity.PortableBuildIdentitySHA256 != receipt.ToolIdentity.BuildIdentitySHA256 || receipt.ExecutionIdentity.BuildMetadataSource != releaseBuildMetadataSource || receipt.ExecutionIdentity.ExecutableMeasurementScope != releaseExecutableScope || receipt.ExecutionIdentity.TargetOS != runtime.GOOS || receipt.ExecutionIdentity.TargetArch != runtime.GOARCH || receipt.ExecutionIdentity.ExecutableSHA256 != child.digest || receipt.ExecutionIdentity.ExecutableByteCount != child.size || receipt.ExecutionIdentity.GoExecutableSHA256 != goTool.digest || receipt.ExecutionIdentity.GitExecutableSHA256 != gitTool.digest || receipt.ExecutionIdentity.GoToolchainSHA256 != goToolchain.digest || receipt.ExecutionIdentity.GitToolchainSHA256 != gitToolchain.digest || receipt.ExecutionIdentity.GoToolchainFileCount != int64(goToolchain.files) || receipt.ExecutionIdentity.GoToolchainByteCount != goToolchain.bytes || receipt.ExecutionIdentity.GitToolchainFileCount != int64(gitToolchain.files) || receipt.ExecutionIdentity.GitToolchainByteCount != gitToolchain.bytes {
		return fmt.Errorf("child execution identity differs from release measurement")
	}
	if receipt.ExecutionIdentity.BuildSettingsSHA256 != childBuild.buildSettingsSHA256 || receipt.ExecutionIdentity.ExecutionIdentitySHA256 != childBuild.executionIdentitySHA256 {
		return fmt.Errorf("child execution identity differs from independently read executable build settings")
	}
	toolIdentity, err := requireJSONObject(object["tool_identity"], "tool_identity")
	if err != nil {
		return err
	}
	if err := requireExactObjectKeys(toolIdentity, []string{
		"command_path", "module_path", "module_version", "go_version", "vcs", "vcs_revision", "vcs_time",
		"vcs_modified", "build_tags", "module_graph_sha256", "build_recipe_sha256", "source_roster_sha256",
		"runner_contract_sha256", "build_identity_sha256", "reproducible_source_tree",
	}); err != nil {
		return fmt.Errorf("child tool identity schema: %w", err)
	}
	if err := validateObjectSelfDigest(toolIdentity, "build_identity_sha256", receipt.ToolIdentity.BuildIdentitySHA256); err != nil {
		return fmt.Errorf("child tool identity: %w", err)
	}
	executionIdentity, err := requireJSONObject(object["execution_identity"], "execution_identity")
	if err != nil {
		return err
	}
	if err := requireExactObjectKeys(executionIdentity, []string{
		"portable_build_identity_sha256", "build_metadata_source", "executable_measurement_scope", "target_os",
		"target_arch", "build_settings", "build_settings_sha256", "executable_sha256", "executable_byte_count",
		"go_executable_sha256", "git_executable_sha256", "go_toolchain_sha256", "git_toolchain_sha256",
		"go_toolchain_file_count", "go_toolchain_byte_count", "git_toolchain_file_count", "git_toolchain_byte_count",
		"execution_identity_sha256",
	}); err != nil {
		return fmt.Errorf("child execution identity schema: %w", err)
	}
	settingsDigest, err := canonicalReleaseDigest(executionIdentity["build_settings"])
	if err != nil || settingsDigest != receipt.ExecutionIdentity.BuildSettingsSHA256 {
		return fmt.Errorf("child execution build-settings digest is invalid")
	}
	if err := validateObjectSelfDigest(executionIdentity, "execution_identity_sha256", receipt.ExecutionIdentity.ExecutionIdentitySHA256); err != nil {
		return fmt.Errorf("child execution identity: %w", err)
	}
	if err := validatePortableReceiptDigest(object, receipt.PortableReceiptSHA256); err != nil {
		return err
	}
	if err := validateChildValidationIdentity(object, receipt); err != nil {
		return err
	}
	if err := validateObjectSelfDigest(object, "receipt_sha256", receipt.ReceiptSHA256); err != nil {
		return fmt.Errorf("child receipt: %w", err)
	}
	return nil
}

func validateReleasedChildReceipt(raw []byte, production productionSourceChildSelection, commit, rosterRoot string, goTool, gitTool measuredExecutable, goToolchain, gitToolchain measuredTree, child measuredExecutable, childBuild childBuildExpectation) error {
	if !production.enabled {
		return validateChildReceipt(raw, commit, rosterRoot, goTool, gitTool, goToolchain, gitToolchain, child, childBuild)
	}
	return validateProductionSourceChildReceipt(raw, production.expectedProvider, commit, rosterRoot, goTool, gitTool, goToolchain, gitToolchain, child, childBuild)
}

func validateProductionSourceChildReceipt(raw []byte, expectedProvider, commit, rosterRoot string, goTool, gitTool measuredExecutable, goToolchain, gitToolchain measuredTree, child measuredExecutable, childBuild childBuildExpectation) error {
	object, err := decodeReleaseJSONObject(raw)
	if err != nil {
		return err
	}
	if err := requireExactObjectKeys(object, []string{
		"receipt_kind", "receipt_version", "result", "scope", "source_receipt", "factory_receipt",
		"body_free", "authority_selected", "admission_authorized", "factory_complete", "receipt_sha256",
	}); err != nil {
		return fmt.Errorf("production source child receipt schema: %w", err)
	}
	if !releaseObjectIdentityEquals(object, "receipt_kind", productionSourceRunReceiptKind) || !releaseObjectIdentityEquals(object, "receipt_version", productionSourceRunReceiptVersion) || !releaseObjectIdentityEquals(object, "result", productionSourceRunReceiptResult) || !releaseObjectIdentityEquals(object, "scope", productionSourceRunReceiptScope) || !releaseObjectBoolEquals(object, "body_free", true) || !releaseObjectBoolEquals(object, "authority_selected", false) || !releaseObjectBoolEquals(object, "admission_authorized", false) || !releaseObjectBoolEquals(object, "factory_complete", false) {
		return fmt.Errorf("production source child receipt identity or candidate-only posture is invalid")
	}
	receiptSHA256, err := requireReleaseString(object, "receipt_sha256", "production source child receipt")
	if err != nil || validateObjectSelfDigest(object, "receipt_sha256", receiptSHA256) != nil {
		return fmt.Errorf("production source child receipt digest is invalid")
	}
	sourceReceipt, err := requireJSONObject(object["source_receipt"], "production source child source_receipt")
	if err != nil {
		return err
	}
	factoryReceipt, err := requireJSONObject(object["factory_receipt"], "production source child factory_receipt")
	if err != nil {
		return err
	}
	if err := validateProductionSourceRelay(sourceReceipt, factoryReceipt, expectedProvider); err != nil {
		return err
	}
	factoryRaw, err := canonicalReleaseJSON(factoryReceipt)
	if err != nil {
		return fmt.Errorf("serialize production source child factory receipt: %w", err)
	}
	if err := validateChildReceipt(factoryRaw, commit, rosterRoot, goTool, gitTool, goToolchain, gitToolchain, child, childBuild); err != nil {
		return fmt.Errorf("production source child factory receipt: %w", err)
	}
	return nil
}

func validateProductionSourceRelay(sourceReceipt, factoryReceipt map[string]any, expectedProvider string) error {
	if err := requireExactObjectKeys(sourceReceipt, []string{
		"receipt_kind", "receipt_version", "result", "scope", "compiler_contract_sha256", "source_package_sha256",
		"source_input_admission_proof", "source_input_resources", "generated_outputs", "generated_output_set_root_sha256",
		"bundle_files", "bundle_file_set_root_sha256", "receipt_path", "receipt_excluded_from_bundle_file_set",
		"factory_portable_receipt_sha256", "factory_receipt_sha256", "factory_receipt_file_sha256", "completion",
		"body_free", "authority_selected", "admission_authorized", "factory_complete", "production_source_verification",
		"receipt_sha256",
	}); err != nil {
		return fmt.Errorf("production source child source receipt schema: %w", err)
	}
	if !releaseObjectIdentityEquals(sourceReceipt, "receipt_kind", sourceCompileReceiptKind) || !releaseObjectIdentityEquals(sourceReceipt, "receipt_version", sourceCompileReceiptVersion) || !releaseObjectIdentityEquals(sourceReceipt, "result", sourceCompileReceiptResult) || !releaseObjectIdentityEquals(sourceReceipt, "scope", sourceCompileReceiptScope) || !releaseObjectIdentityEquals(sourceReceipt, "receipt_path", "source-compile-receipt.json") || !releaseObjectBoolEquals(sourceReceipt, "receipt_excluded_from_bundle_file_set", true) || !releaseObjectBoolEquals(sourceReceipt, "body_free", true) || !releaseObjectBoolEquals(sourceReceipt, "authority_selected", false) || !releaseObjectBoolEquals(sourceReceipt, "admission_authorized", false) || !releaseObjectBoolEquals(sourceReceipt, "factory_complete", false) {
		return fmt.Errorf("production source child source receipt identity or candidate-only posture is invalid")
	}
	for _, field := range []string{
		"compiler_contract_sha256", "source_package_sha256", "generated_output_set_root_sha256", "bundle_file_set_root_sha256",
		"factory_portable_receipt_sha256", "factory_receipt_sha256", "factory_receipt_file_sha256", "receipt_sha256",
	} {
		value, err := requireReleaseString(sourceReceipt, field, "production source child source receipt")
		if err != nil || !validSHA256(value) {
			return fmt.Errorf("production source child source receipt %s is invalid", field)
		}
	}
	sourceReceiptSHA256, _ := requireReleaseString(sourceReceipt, "receipt_sha256", "production source child source receipt")
	if err := validateObjectSelfDigest(sourceReceipt, "receipt_sha256", sourceReceiptSHA256); err != nil {
		return fmt.Errorf("production source child source receipt: %w", err)
	}
	sourcePackageSHA256, _ := requireReleaseString(sourceReceipt, "source_package_sha256", "production source child source receipt")
	verification, err := requireJSONObject(sourceReceipt["production_source_verification"], "production_source_verification")
	if err != nil {
		return err
	}
	provider, err := validateProductionSourceVerificationRelay(verification, sourcePackageSHA256)
	if err != nil {
		return err
	}
	if provider != expectedProvider {
		return fmt.Errorf("production source child receipt provider differs from release selection")
	}

	factoryReceiptSHA256, err := requireReleaseString(factoryReceipt, "receipt_sha256", "factory receipt")
	if err != nil {
		return err
	}
	factoryPortableReceiptSHA256, err := requireReleaseString(factoryReceipt, "portable_receipt_sha256", "factory receipt")
	if err != nil {
		return err
	}
	sourceFactoryReceiptSHA256, _ := requireReleaseString(sourceReceipt, "factory_receipt_sha256", "source receipt")
	sourceFactoryPortableReceiptSHA256, _ := requireReleaseString(sourceReceipt, "factory_portable_receipt_sha256", "source receipt")
	if sourceFactoryReceiptSHA256 != factoryReceiptSHA256 || sourceFactoryPortableReceiptSHA256 != factoryPortableReceiptSHA256 {
		return fmt.Errorf("production source child source receipt binds a different factory receipt")
	}
	factoryRaw, err := canonicalReleaseJSON(factoryReceipt)
	if err != nil {
		return err
	}
	factoryFileRaw := append(append([]byte(nil), factoryRaw...), '\n')
	sourceFactoryFileSHA256, _ := requireReleaseString(sourceReceipt, "factory_receipt_file_sha256", "source receipt")
	factoryFileSum := sha256.Sum256(factoryFileRaw)
	if sourceFactoryFileSHA256 != hex.EncodeToString(factoryFileSum[:]) {
		return fmt.Errorf("production source child source receipt binds different factory receipt bytes")
	}
	sourceCompletion, err := requireJSONObject(sourceReceipt["completion"], "source receipt completion")
	if err != nil {
		return err
	}
	factoryCompletion, err := requireJSONObject(factoryReceipt["completion"], "factory receipt completion")
	if err != nil {
		return err
	}
	sourceCompletionSHA256, err := canonicalReleaseDigest(sourceCompletion)
	if err != nil {
		return err
	}
	factoryCompletionSHA256, err := canonicalReleaseDigest(factoryCompletion)
	if err != nil || sourceCompletionSHA256 != factoryCompletionSHA256 {
		return fmt.Errorf("production source child source and factory completion classifications differ")
	}
	preflight, err := requireJSONObject(factoryReceipt["preflight_receipt"], "factory preflight receipt")
	if err != nil {
		return err
	}
	compiledProvider, err := requireReleaseString(preflight, "provider", "factory preflight receipt")
	if err != nil || compiledProvider != provider {
		return fmt.Errorf("production source child verified provider differs from compiled provider")
	}
	return nil
}

func validateProductionSourceVerificationRelay(verification map[string]any, sourcePackageSHA256 string) (string, error) {
	if err := requireExactObjectKeys(verification, []string{
		"verification_kind", "verification_version", "result", "provider", "observed_at", "source_package_sha256",
		"source_package_byte_count", "provider_evidence_identities", "provider_evidence_identity_set_root_sha256",
		"source_owner_verification_receipt_sha256", "source_owner_verification_receipt_byte_count", "producer_authenticated",
		"current_generation_verified", "complete_evidence_identity_set_verified", "test_owned", "binding_sha256",
	}); err != nil {
		return "", fmt.Errorf("production source verification schema: %w", err)
	}
	if !releaseObjectIdentityEquals(verification, "verification_kind", productionSourceVerificationKind) || !releaseObjectIdentityEquals(verification, "verification_version", productionSourceVerificationVersion) || !releaseObjectIdentityEquals(verification, "result", productionSourceVerificationResult) || !releaseObjectBoolEquals(verification, "producer_authenticated", true) || !releaseObjectBoolEquals(verification, "current_generation_verified", true) || !releaseObjectBoolEquals(verification, "complete_evidence_identity_set_verified", true) || !releaseObjectBoolEquals(verification, "test_owned", false) {
		return "", fmt.Errorf("production source verification trust verdict is not production-eligible")
	}
	provider, err := requireReleaseString(verification, "provider", "production source verification")
	if err != nil || provider == "" || provider != strings.TrimSpace(provider) {
		return "", fmt.Errorf("production source verification provider is invalid")
	}
	observedAt, err := requireReleaseString(verification, "observed_at", "production source verification")
	if err != nil {
		return "", err
	}
	parsedObservedAt, err := time.Parse(time.RFC3339Nano, observedAt)
	if err != nil || parsedObservedAt.UTC().Format(time.RFC3339Nano) != observedAt {
		return "", fmt.Errorf("production source verification observed_at is not canonical UTC RFC3339")
	}
	for _, field := range []string{"source_package_sha256", "provider_evidence_identity_set_root_sha256", "source_owner_verification_receipt_sha256", "binding_sha256"} {
		value, err := requireReleaseString(verification, field, "production source verification")
		if err != nil || !validSHA256(value) {
			return "", fmt.Errorf("production source verification %s is invalid", field)
		}
	}
	verificationSourcePackageSHA256, _ := requireReleaseString(verification, "source_package_sha256", "production source verification")
	if verificationSourcePackageSHA256 != sourcePackageSHA256 {
		return "", fmt.Errorf("production source verification binds a different source package")
	}
	for _, field := range []string{"source_package_byte_count", "source_owner_verification_receipt_byte_count"} {
		value, err := requireReleaseInt64(verification, field, "production source verification")
		if err != nil || value <= 0 {
			return "", fmt.Errorf("production source verification %s is invalid", field)
		}
	}
	identities, ok := verification["provider_evidence_identities"].([]any)
	if !ok || len(identities) == 0 {
		return "", fmt.Errorf("production source verification evidence identity set is empty")
	}
	rows := make([]string, len(identities))
	prior := ""
	for index, value := range identities {
		identity, err := requireJSONObject(value, fmt.Sprintf("provider evidence identity[%d]", index))
		if err != nil {
			return "", err
		}
		if err := requireExactObjectKeys(identity, []string{
			"manifest_role", "manifest_id", "manifest_version", "manifest_raw_sha256", "manifest_byte_count",
			"component_ordinal", "source_content_sha256", "source_content_byte_count", "carrier_role", "carrier_id",
			"carrier_version", "carrier_raw_sha256", "carrier_byte_count",
		}); err != nil {
			return "", fmt.Errorf("provider evidence identity[%d] schema: %w", index, err)
		}
		stringsByField := map[string]string{}
		for _, field := range []string{"manifest_role", "manifest_id", "manifest_version", "carrier_role", "carrier_id", "carrier_version"} {
			item, err := requireReleaseString(identity, field, "provider evidence identity")
			if err != nil || item == "" || item != strings.TrimSpace(item) {
				return "", fmt.Errorf("provider evidence identity[%d] %s is invalid", index, field)
			}
			stringsByField[field] = item
		}
		for _, field := range []string{"manifest_raw_sha256", "source_content_sha256", "carrier_raw_sha256"} {
			item, err := requireReleaseString(identity, field, "provider evidence identity")
			if err != nil || !validSHA256(item) {
				return "", fmt.Errorf("provider evidence identity[%d] %s is invalid", index, field)
			}
			stringsByField[field] = item
		}
		for _, field := range []string{"manifest_byte_count", "source_content_byte_count", "carrier_byte_count"} {
			count, err := requireReleaseInt64(identity, field, "provider evidence identity")
			if err != nil || count <= 0 {
				return "", fmt.Errorf("provider evidence identity[%d] %s is invalid", index, field)
			}
		}
		ordinal, err := requireReleaseUint64(identity, "component_ordinal", "provider evidence identity")
		if err != nil {
			return "", fmt.Errorf("provider evidence identity[%d] component_ordinal is invalid", index)
		}
		key := releaseLengthPrefixedIdentityKey(
			stringsByField["manifest_role"], stringsByField["manifest_id"], stringsByField["manifest_version"],
			fmt.Sprintf("%020d", ordinal), stringsByField["source_content_sha256"], stringsByField["carrier_role"],
			stringsByField["carrier_id"], stringsByField["carrier_version"],
		)
		if index != 0 && key <= prior {
			return "", fmt.Errorf("production source verification evidence identity set is unsorted or duplicated")
		}
		prior = key
		raw, err := canonicalReleaseJSON(identity)
		if err != nil {
			return "", err
		}
		rows[index] = string(raw)
	}
	wantRoot := sha256String(releaseLengthPrefixedIdentityKey(rows...))
	root, _ := requireReleaseString(verification, "provider_evidence_identity_set_root_sha256", "production source verification")
	if root != wantRoot {
		return "", fmt.Errorf("production source verification evidence identity root mismatch")
	}
	bindingSHA256, _ := requireReleaseString(verification, "binding_sha256", "production source verification")
	if err := validateObjectSelfDigest(verification, "binding_sha256", bindingSHA256); err != nil {
		return "", fmt.Errorf("production source verification binding: %w", err)
	}
	return provider, nil
}

func releaseObjectIdentityEquals(object map[string]any, field, expected string) bool {
	value, ok := object[field].(string)
	return ok && value == expected
}

func releaseObjectBoolEquals(object map[string]any, field string, expected bool) bool {
	value, ok := object[field].(bool)
	return ok && value == expected
}

func requireReleaseString(object map[string]any, field, label string) (string, error) {
	value, ok := object[field].(string)
	if !ok {
		return "", fmt.Errorf("%s %s is not a string", label, field)
	}
	return value, nil
}

func requireReleaseInt64(object map[string]any, field, label string) (int64, error) {
	value, ok := object[field].(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s %s is not an integer", label, field)
	}
	parsed, err := strconv.ParseInt(value.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s %s is not an integer", label, field)
	}
	return parsed, nil
}

func requireReleaseUint64(object map[string]any, field, label string) (uint64, error) {
	value, ok := object[field].(json.Number)
	if !ok {
		return 0, fmt.Errorf("%s %s is not an unsigned integer", label, field)
	}
	parsed, err := strconv.ParseUint(value.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s %s is not an unsigned integer", label, field)
	}
	return parsed, nil
}

func releaseLengthPrefixedIdentityKey(fields ...string) string {
	var output strings.Builder
	for _, field := range fields {
		fmt.Fprintf(&output, "%d:", len([]byte(field)))
		output.WriteString(field)
	}
	return output.String()
}

func validatePortableReceiptDigest(receipt map[string]any, expected string) error {
	portable := cloneJSONObject(receipt)
	portable["execution_identity"] = map[string]any{
		"portable_build_identity_sha256": "", "build_metadata_source": "", "executable_measurement_scope": "",
		"target_os": "", "target_arch": "", "build_settings": nil, "build_settings_sha256": "",
		"executable_sha256": "", "executable_byte_count": json.Number("0"), "go_executable_sha256": "",
		"git_executable_sha256": "", "go_toolchain_sha256": "", "git_toolchain_sha256": "",
		"go_toolchain_file_count": json.Number("0"), "go_toolchain_byte_count": json.Number("0"),
		"git_toolchain_file_count": json.Number("0"), "git_toolchain_byte_count": json.Number("0"),
		"execution_identity_sha256": "",
	}
	portable["validation_identity"] = map[string]any{
		"profile_id": "", "profile_version": "", "result": "", "validation_contract_sha256": "",
		"portable_receipt_sha256": "", "tool_build_identity_sha256": "", "execution_identity_sha256": "",
		"validation_report_sha256": "", "validation_identity_sha256": "",
	}
	portable["portable_receipt_sha256"] = ""
	portable["receipt_sha256"] = ""
	digest, err := canonicalReleaseDigest(portable)
	if err != nil || digest != expected {
		return fmt.Errorf("child portable receipt digest is invalid")
	}
	return nil
}

func validateChildValidationIdentity(receipt map[string]any, envelope childReceiptEnvelope) error {
	identity, err := requireJSONObject(receipt["validation_identity"], "validation_identity")
	if err != nil {
		return err
	}
	if err := requireExactObjectKeys(identity, []string{
		"profile_id", "profile_version", "result", "validation_contract_sha256", "portable_receipt_sha256",
		"tool_build_identity_sha256", "execution_identity_sha256", "validation_report_sha256", "validation_identity_sha256",
	}); err != nil {
		return fmt.Errorf("child validation identity schema: %w", err)
	}
	wantContract := sha256String(releaseValidationContract)
	if identity["profile_id"] != releaseValidationProfileID || identity["profile_version"] != releaseValidationVersion || identity["result"] != releaseValidationResult || identity["validation_contract_sha256"] != wantContract || identity["portable_receipt_sha256"] != envelope.PortableReceiptSHA256 || identity["tool_build_identity_sha256"] != envelope.ToolIdentity.BuildIdentitySHA256 || identity["execution_identity_sha256"] != envelope.ExecutionIdentity.ExecutionIdentitySHA256 {
		return fmt.Errorf("child validation identity differs from the closed validation profile")
	}
	validationSHA256, ok := identity["validation_identity_sha256"].(string)
	if !ok || !validSHA256(validationSHA256) {
		return fmt.Errorf("child validation identity digest is invalid")
	}
	if err := validateObjectSelfDigest(identity, "validation_identity_sha256", validationSHA256); err != nil {
		return fmt.Errorf("child validation identity: %w", err)
	}
	proof, err := requireJSONObject(receipt["input_admission_proof"], "input_admission_proof")
	if err != nil {
		return err
	}
	proofSHA256, ok := proof["proof_sha256"].(string)
	if !ok || !validSHA256(proofSHA256) {
		return fmt.Errorf("child input-admission proof digest is invalid")
	}
	stages, ok := receipt["stages"].([]any)
	if !ok || len(stages) != 4 {
		return fmt.Errorf("child stage receipt roster is not exactly four entries")
	}
	stageDigests := make([]string, len(stages))
	for index, value := range stages {
		stage, stageErr := requireJSONObject(value, "stage")
		if stageErr != nil {
			return stageErr
		}
		if err := requireExactObjectKeys(stage, []string{"stage_kind", "receipt_sha256", "output_root_sha256", "input_resource_set_root_sha256"}); err != nil {
			return fmt.Errorf("child stage %d schema: %w", index, err)
		}
		stageDigests[index], ok = stage["receipt_sha256"].(string)
		if !ok || !validSHA256(stageDigests[index]) {
			return fmt.Errorf("child stage %d receipt digest is invalid", index)
		}
	}
	preflight, err := requireJSONObject(receipt["preflight_receipt"], "preflight_receipt")
	if err != nil {
		return err
	}
	preflightSHA256, ok := preflight["receipt_sha256"].(string)
	if !ok || !validSHA256(preflightSHA256) {
		return fmt.Errorf("child preflight receipt digest is invalid")
	}
	report := map[string]any{
		"result":                       releaseValidationResult,
		"portable_receipt_sha256":      envelope.PortableReceiptSHA256,
		"tool_build_identity_sha256":   envelope.ToolIdentity.BuildIdentitySHA256,
		"execution_identity_sha256":    envelope.ExecutionIdentity.ExecutionIdentitySHA256,
		"input_admission_proof_sha256": proofSHA256,
		"stage_receipt_sha256":         stageDigests,
		"preflight_receipt_sha256":     preflightSHA256,
		"completion_classification":    receipt["completion"],
	}
	wantReportSHA256, err := canonicalReleaseDigest(report)
	gotReportSHA256, ok := identity["validation_report_sha256"].(string)
	if err != nil || !ok || gotReportSHA256 != wantReportSHA256 {
		return fmt.Errorf("child validation report digest is invalid")
	}
	return nil
}

func validateObjectSelfDigest(object map[string]any, field, expected string) error {
	if !validSHA256(expected) {
		return fmt.Errorf("%s is not a lowercase SHA-256", field)
	}
	identity := cloneJSONObject(object)
	identity[field] = ""
	digest, err := canonicalReleaseDigest(identity)
	if err != nil {
		return err
	}
	if digest != expected {
		return fmt.Errorf("%s does not match the canonical object identity", field)
	}
	return nil
}

func decodeReleaseJSONObject(raw []byte) (map[string]any, error) {
	if err := validateNoDuplicateJSONKeys(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("child receipt contains trailing JSON token %v", token)
		}
		return nil, err
	}
	return requireJSONObject(value, "child receipt")
}

func validateNoDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateJSONTokenValue(decoder, 0); err != nil {
		return err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("JSON contains trailing token %v", token)
		}
		return err
	}
	return nil
}

func validateJSONTokenValue(decoder *json.Decoder, depth int) error {
	if depth > maximumReleaseJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maximumReleaseJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("JSON object duplicates key %q", key)
			}
			seen[key] = struct{}{}
			if err := validateJSONTokenValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONTokenValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("JSON array is not closed")
		}
	default:
		return fmt.Errorf("JSON begins with an unexpected delimiter")
	}
	return nil
}

func requireJSONObject(value any, label string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not an object", label)
	}
	return object, nil
}

func requireExactObjectKeys(object map[string]any, expected []string) error {
	if len(object) != len(expected) {
		return fmt.Errorf("object has %d fields, want %d", len(object), len(expected))
	}
	for _, key := range expected {
		if _, exists := object[key]; !exists {
			return fmt.Errorf("required field %q is absent", key)
		}
	}
	return nil
}

func cloneJSONObject(object map[string]any) map[string]any {
	clone := make(map[string]any, len(object))
	for key, value := range object {
		clone[key] = value
	}
	return clone
}

func canonicalReleaseDigest(value any) (string, error) {
	canonical, err := canonicalReleaseJSON(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalReleaseJSON(value any) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func sha256String(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func resolveSourceRoot(candidate string) (string, error) {
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolve source root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve source root links: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("source root is not an existing directory")
	}
	return filepath.Clean(resolved), nil
}

func resolveExecutable(candidate string) (string, error) {
	if !filepath.IsAbs(candidate) {
		return "", fmt.Errorf("executable trust root is not absolute")
	}
	abs := filepath.Clean(candidate)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("executable trust root is not a regular file")
	}
	return filepath.Clean(resolved), nil
}

func measureExecutable(candidate string) (measuredExecutable, error) {
	resolved, err := resolveExecutable(candidate)
	if err != nil {
		return measuredExecutable{}, err
	}
	first, err := hashExecutablePath(resolved)
	if err != nil {
		return measuredExecutable{}, err
	}
	second, err := hashExecutablePath(resolved)
	if err != nil {
		return measuredExecutable{}, err
	}
	if first.digest != second.digest || first.size != second.size || first.mtime != second.mtime {
		return measuredExecutable{}, fmt.Errorf("executable trust-root path changed while measured")
	}
	return first, nil
}

func hashExecutablePath(resolved string) (measuredExecutable, error) {
	file, err := os.Open(resolved)
	if err != nil {
		return measuredExecutable{}, err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return measuredExecutable{}, fmt.Errorf("inspect executable trust root")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, file)
	if err != nil {
		return measuredExecutable{}, err
	}
	after, err := file.Stat()
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || count != before.Size() {
		return measuredExecutable{}, fmt.Errorf("executable trust root changed while measured")
	}
	pathInfo, err := os.Lstat(resolved)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() || pathInfo.Size() != before.Size() || !pathInfo.ModTime().Equal(before.ModTime()) {
		return measuredExecutable{}, fmt.Errorf("executable trust-root path changed while measured")
	}
	return measuredExecutable{path: resolved, digest: hex.EncodeToString(hash.Sum(nil)), size: count, mtime: before.ModTime().UnixNano()}, nil
}

func measureOpenExecutable(file *os.File, resolved string) (measuredExecutable, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return measuredExecutable{}, fmt.Errorf("inspect retained executable")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return measuredExecutable{}, err
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, (512<<20)+1))
	if err != nil || count > 512<<20 {
		return measuredExecutable{}, fmt.Errorf("measure retained executable")
	}
	after, err := file.Stat()
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || count != before.Size() {
		return measuredExecutable{}, fmt.Errorf("retained executable changed while measured")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return measuredExecutable{}, err
	}
	return measuredExecutable{path: resolved, digest: hex.EncodeToString(hash.Sum(nil)), size: count, mtime: before.ModTime().UnixNano()}, nil
}

func verifyMeasuredExecutable(expected measuredExecutable) error {
	actual, err := measureExecutable(expected.path)
	if err != nil {
		return err
	}
	if actual.digest != expected.digest || actual.size != expected.size || actual.mtime != expected.mtime {
		return fmt.Errorf("executable trust-root identity changed")
	}
	return nil
}

func newReleaseWorkspace(goExecutable, gitExecutable string) (releaseWorkspace, error) {
	tempRoot, err := physicalTempDirectory()
	if err != nil {
		return releaseWorkspace{}, fmt.Errorf("resolve physical temporary directory: %w", err)
	}
	root, err := os.MkdirTemp(tempRoot, "velenza-provider-factory-release-")
	if err != nil {
		return releaseWorkspace{}, fmt.Errorf("create exclusive release workspace: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		removeReleaseWorkspace(tempRoot, root)
		return releaseWorkspace{}, fmt.Errorf("protect release workspace: %w", err)
	}
	workspace := releaseWorkspace{tempRoot: tempRoot, root: root, projectionRoot: filepath.Join(root, "projection")}
	workspace.onlineEnv, err = closedReleaseEnvironment(root, goExecutable, gitExecutable, false)
	if err != nil {
		removeReleaseWorkspace(tempRoot, root)
		return releaseWorkspace{}, err
	}
	workspace.offlineEnv, err = closedReleaseEnvironment(root, goExecutable, gitExecutable, true)
	if err != nil {
		removeReleaseWorkspace(tempRoot, root)
		return releaseWorkspace{}, err
	}
	return workspace, nil
}

func physicalTempDirectory() (string, error) {
	root := os.TempDir()
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("temporary directory is not absolute")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) {
		return "", fmt.Errorf("physical temporary directory is not absolute")
	}
	info, err := os.Lstat(resolved)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("physical temporary directory is not a real directory")
	}
	return resolved, nil
}

func removeReleaseWorkspace(tempRoot, root string) {
	if tempRoot == "" || root == "" || !filepath.IsAbs(tempRoot) || !filepath.IsAbs(root) {
		return
	}
	tempRoot = filepath.Clean(tempRoot)
	root = filepath.Clean(root)
	if sameNativePath(tempRoot, root) || !sameNativePath(filepath.Dir(root), tempRoot) || !strings.HasPrefix(filepath.Base(root), "velenza-provider-factory-release-") {
		return
	}
	tempInfo, tempErr := os.Lstat(tempRoot)
	rootInfo, rootErr := os.Lstat(root)
	if tempErr != nil || rootErr != nil || tempInfo.Mode()&os.ModeSymlink != 0 || !tempInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || !sameNativePath(resolvedRoot, root) {
		return
	}
	_ = makeReleaseWorkspaceWritable(root)
	_ = os.RemoveAll(root)
}

func makeReleaseWorkspaceWritable(root string) error {
	return filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			return os.Chmod(current, 0o700)
		case info.Mode().IsRegular():
			return os.Chmod(current, 0o600)
		default:
			return nil
		}
	})
}

func closedReleaseEnvironment(root, goExecutable, gitExecutable string, offline bool) ([]string, error) {
	directories := []string{
		filepath.Join(root, "home"),
		filepath.Join(root, "cache", "build"),
		filepath.Join(root, "cache", "modules"),
		filepath.Join(root, "gopath"),
		filepath.Join(root, "tmp", "go"),
		filepath.Join(root, "tmp", "process"),
		filepath.Join(root, "config"),
		filepath.Join(root, "bin"),
	}
	for _, directory := range directories {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create closed release environment: %w", err)
		}
	}
	gitConfig := filepath.Join(root, "config", "gitconfig")
	if err := os.WriteFile(gitConfig, nil, 0o600); err != nil {
		return nil, fmt.Errorf("create closed Git configuration: %w", err)
	}
	processTemp := filepath.Join(root, "tmp", "process")
	values := map[string]string{
		"CGO_ENABLED":            "0",
		"GO_EXTLINK_ENABLED":     "0",
		"GIT_ASKPASS":            "",
		"GIT_CONFIG_GLOBAL":      gitConfig,
		"GIT_CONFIG_NOSYSTEM":    "1",
		"GIT_NO_REPLACE_OBJECTS": "1",
		"GIT_PAGER":              "cat",
		"GIT_TERMINAL_PROMPT":    "0",
		"GCM_INTERACTIVE":        "never",
		"GO111MODULE":            "on",
		"GOCACHE":                filepath.Join(root, "cache", "build"),
		"GOENV":                  "off",
		"GOFLAGS":                "-mod=readonly",
		"GOMODCACHE":             filepath.Join(root, "cache", "modules"),
		"GOPATH":                 filepath.Join(root, "gopath"),
		"GOTOOLCHAIN":            "local",
		"GOTMPDIR":               filepath.Join(root, "tmp", "go"),
		"GOWORK":                 "off",
		"HOME":                   filepath.Join(root, "home"),
		"LANG":                   "C",
		"LC_ALL":                 "C",
		"PAGER":                  "cat",
		"PATH":                   filepath.Join(root, "bin"),
		"SOURCE_DATE_EPOCH":      "0",
		"SSH_ASKPASS":            "",
		"TEMP":                   processTemp,
		"TMP":                    processTemp,
		"TMPDIR":                 processTemp,
		"TZ":                     "UTC",
		"USERPROFILE":            filepath.Join(root, "home"),
		"XDG_CACHE_HOME":         filepath.Join(root, "cache"),
		"XDG_CONFIG_HOME":        filepath.Join(root, "config"),
	}
	if offline {
		values["GOPROXY"] = "off"
		values["GOSUMDB"] = "off"
	} else {
		values["GOPROXY"] = "https://proxy.golang.org"
		values["GOSUMDB"] = "sum.golang.org"
	}
	if runtime.GOOS == "windows" {
		for _, key := range []string{"SYSTEMROOT", "WINDIR"} {
			if value := os.Getenv(key); value != "" {
				values[key] = value
			}
		}
		values["PATHEXT"] = ".EXE"
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment, nil
}

func installGitInvocationShim(goExecutable, gitExecutable string, workspace releaseWorkspace) (measuredExecutable, error) {
	shimName := "git"
	if runtime.GOOS == "windows" {
		shimName += ".exe"
	}
	shimPath := filepath.Join(workspace.root, "bin", shimName)
	sourcePath := filepath.Join(workspace.root, "config", "git-invocation-shim.go")
	source := fmt.Sprintf(`package main

import (
	"errors"
	"os"
	"os/exec"
)

const selectedGit = %q

func main() {
	command := exec.Command(selectedGit, os.Args[1:]...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			os.Exit(exitError.ExitCode())
		}
		os.Exit(127)
	}
}
`, gitExecutable)
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		return measuredExecutable{}, fmt.Errorf("write closed Git invocation shim: %w", err)
	}
	shimEnvironment := replaceEnvironmentValue(workspace.offlineEnv, "GO111MODULE", "off")
	if err := runSilent(goExecutable, []string{"build", "-buildvcs=false", "-trimpath", "-o", shimPath, sourcePath}, workspace.root, shimEnvironment); err != nil {
		return measuredExecutable{}, fmt.Errorf("build closed Git invocation shim: %w", err)
	}
	shim, err := measureExecutable(shimPath)
	if err != nil {
		return measuredExecutable{}, fmt.Errorf("measure closed Git invocation shim: %w", err)
	}
	directVersion, err := runCaptured(gitExecutable, []string{"--version"}, "", workspace.offlineEnv)
	if err != nil {
		return measuredExecutable{}, fmt.Errorf("run selected Git trust root: %w", err)
	}
	shimVersion, err := runCaptured(shim.path, []string{"--version"}, "", workspace.offlineEnv)
	if err != nil || !bytes.Equal(directVersion, shimVersion) {
		return measuredExecutable{}, fmt.Errorf("closed Git invocation shim does not resolve the selected Git trust root")
	}
	return shim, nil
}

func replaceEnvironmentValue(environment []string, key, value string) []string {
	prefix := key + "="
	result := append([]string(nil), environment...)
	for index, entry := range result {
		if strings.HasPrefix(entry, prefix) {
			result[index] = prefix + value
			return result
		}
	}
	return append(result, prefix+value)
}

func verifyGoVersion(goExecutable string, environment []string) error {
	raw, err := runCaptured(goExecutable, []string{"env", "GOVERSION"}, "", environment)
	if err != nil {
		return fmt.Errorf("read Go trust-root version: %w", err)
	}
	if strings.TrimSpace(string(raw)) != releaseGoVersion {
		return fmt.Errorf("Go trust-root version is not %s", releaseGoVersion)
	}
	return nil
}

func resolveGoRoot(goExecutable string, environment []string) (string, error) {
	raw, err := runCaptured(goExecutable, []string{"env", "GOROOT"}, "", environment)
	if err != nil {
		return "", fmt.Errorf("resolve Go trust-root toolchain: %w", err)
	}
	root := strings.TrimSpace(string(raw))
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("Go trust-root toolchain path is not absolute")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("Go trust-root toolchain is not a directory")
	}
	return filepath.Clean(resolved), nil
}

func resolveGitExecRoot(gitExecutable string, environment []string) (string, error) {
	raw, err := runCaptured(gitExecutable, []string{"--exec-path"}, "", environment)
	if err != nil {
		return "", fmt.Errorf("resolve Git helper trust root: %w", err)
	}
	root := strings.TrimSpace(string(raw))
	if root == "" || !filepath.IsAbs(root) {
		return "", fmt.Errorf("Git helper trust-root path is not absolute")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("Git helper trust root is not a directory")
	}
	return filepath.Clean(resolved), nil
}

func measureRegularTree(root string) (measuredTree, error) {
	hash := sha256.New()
	result := measuredTree{root: root}
	var paths []string
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == root {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("toolchain contains a symbolic link")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("toolchain contains a non-regular file")
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return measuredTree{}, err
	}
	sort.Strings(paths)
	for _, relative := range paths {
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return measuredTree{}, err
		}
		before, err := file.Stat()
		if err != nil || !before.Mode().IsRegular() {
			file.Close()
			return measuredTree{}, fmt.Errorf("toolchain file changed before measurement")
		}
		fileHash := sha256.New()
		count, copyErr := io.Copy(fileHash, file)
		after, statErr := file.Stat()
		closeErr := file.Close()
		if copyErr != nil || statErr != nil || closeErr != nil || count != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			return measuredTree{}, fmt.Errorf("toolchain file changed during measurement")
		}
		contentDigest := hex.EncodeToString(fileHash.Sum(nil))
		for _, value := range []string{relative, contentDigest} {
			if err := binary.Write(hash, binary.BigEndian, uint64(len(value))); err != nil {
				return measuredTree{}, err
			}
			_, _ = io.WriteString(hash, value)
		}
		if err := binary.Write(hash, binary.BigEndian, uint64(count)); err != nil {
			return measuredTree{}, err
		}
		result.files++
		result.bytes += count
	}
	if result.files == 0 || result.bytes <= 0 {
		return measuredTree{}, fmt.Errorf("toolchain tree is empty")
	}
	result.digest = hex.EncodeToString(hash.Sum(nil))
	return result, nil
}

func measureGitHelperTree(root string) (measuredTree, error) {
	root = filepath.Clean(root)
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return measuredTree{}, fmt.Errorf("Git helper trust root is not a physical directory")
	}
	entries, err := scanGitHelperEntries(root)
	if err != nil {
		return measuredTree{}, err
	}
	hash := sha256.New()
	payloads := make(map[string]measuredRegularPayload)
	payloadPaths := make(map[string]string)
	for _, entry := range entries {
		measurement, err := measureStableRegularPayload(entry.resolvedPath)
		if err != nil {
			return measuredTree{}, fmt.Errorf("measure Git helper payload %q: %w", entry.logicalPath, err)
		}
		key := nativePathKey(entry.resolvedPath)
		if existing, ok := payloads[key]; ok && existing != measurement {
			return measuredTree{}, fmt.Errorf("Git helper payload changed across aliases")
		}
		payloads[key] = measurement
		payloadPaths[key] = entry.resolvedPath
		for _, value := range []string{entry.kind, entry.logicalPath} {
			if err := writeMeasuredTreeString(hash, value); err != nil {
				return measuredTree{}, err
			}
		}
		if entry.kind == "symlink" {
			for _, value := range []string{entry.rawTarget, filepath.ToSlash(entry.resolvedPath)} {
				if err := writeMeasuredTreeString(hash, value); err != nil {
					return measuredTree{}, err
				}
			}
		}
		if err := writeMeasuredTreeString(hash, measurement.digest); err != nil {
			return measuredTree{}, err
		}
		if err := binary.Write(hash, binary.BigEndian, uint64(measurement.size)); err != nil {
			return measuredTree{}, err
		}
	}
	keys := make([]string, 0, len(payloads))
	for key := range payloads {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := measuredTree{root: root, digest: hex.EncodeToString(hash.Sum(nil))}
	for _, key := range keys {
		final, err := measureStableRegularPayload(payloadPaths[key])
		if err != nil || final != payloads[key] {
			return measuredTree{}, fmt.Errorf("Git helper payload changed during tree measurement")
		}
		result.files++
		result.bytes += final.size
	}
	finalEntries, err := scanGitHelperEntries(root)
	if err != nil || len(finalEntries) != len(entries) {
		return measuredTree{}, fmt.Errorf("Git helper tree changed during measurement")
	}
	for index := range entries {
		if entries[index] != finalEntries[index] {
			return measuredTree{}, fmt.Errorf("Git helper tree changed during measurement")
		}
	}
	if len(entries) == 0 || result.files == 0 || result.bytes <= 0 {
		return measuredTree{}, fmt.Errorf("Git helper tree is empty")
	}
	return result, nil
}

func scanGitHelperEntries(root string) ([]gitHelperEntry, error) {
	var entries []gitHelperEntry
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if sameNativePath(current, root) {
			return nil
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		logicalPath := filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			rawTarget, err := os.Readlink(current)
			if err != nil || rawTarget == "" || filepath.IsAbs(rawTarget) || filepath.VolumeName(rawTarget) != "" {
				return fmt.Errorf("Git helper symbolic link %q has an invalid target", logicalPath)
			}
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil || !filepath.IsAbs(resolved) {
				return fmt.Errorf("Git helper symbolic link %q is dangling or cyclic", logicalPath)
			}
			resolved = filepath.Clean(resolved)
			info, err := os.Lstat(resolved)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !regularFileExecutable(resolved, info.Mode()) {
				return fmt.Errorf("Git helper symbolic link %q does not resolve to a regular executable", logicalPath)
			}
			entries = append(entries, gitHelperEntry{kind: "symlink", logicalPath: logicalPath, rawTarget: rawTarget, resolvedPath: resolved})
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("Git helper tree contains a non-regular file")
		}
		entries = append(entries, gitHelperEntry{kind: "regular", logicalPath: logicalPath, resolvedPath: filepath.Clean(current)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(left, right int) bool {
		return entries[left].logicalPath < entries[right].logicalPath
	})
	return entries, nil
}

func measureStableRegularPayload(path string) (measuredRegularPayload, error) {
	path = filepath.Clean(path)
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return measuredRegularPayload{}, fmt.Errorf("payload path is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return measuredRegularPayload{}, err
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		file.Close()
		return measuredRegularPayload{}, fmt.Errorf("payload changed before measurement")
	}
	hash := sha256.New()
	count, copyErr := io.Copy(hash, file)
	after, statErr := file.Stat()
	closeErr := file.Close()
	finalPathInfo, lstatErr := os.Lstat(path)
	if copyErr != nil || statErr != nil || closeErr != nil || lstatErr != nil || finalPathInfo.Mode()&os.ModeSymlink != 0 || !finalPathInfo.Mode().IsRegular() || count != before.Size() || before.Size() != after.Size() || finalPathInfo.Size() != before.Size() || !before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(finalPathInfo.ModTime()) {
		return measuredRegularPayload{}, fmt.Errorf("payload changed during measurement")
	}
	return measuredRegularPayload{digest: hex.EncodeToString(hash.Sum(nil)), size: count, mtime: before.ModTime().UnixNano()}, nil
}

func writeMeasuredTreeString(writer io.Writer, value string) error {
	if err := binary.Write(writer, binary.BigEndian, uint64(len(value))); err != nil {
		return err
	}
	_, err := io.WriteString(writer, value)
	return err
}

func nativePathKey(value string) string {
	value = filepath.Clean(value)
	if runtime.GOOS == "windows" {
		return strings.ToLower(value)
	}
	return value
}

func regularFileExecutable(path string, mode fs.FileMode) bool {
	if runtime.GOOS != "windows" {
		return mode.Perm()&0o111 != 0
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".bat", ".cmd", ".com", ".exe":
		return true
	default:
		return false
	}
}

func inspectChildBuildIdentity(executable *os.File, rosterRoot string, child measuredExecutable, goTool, gitTool measuredExecutable, goToolchain, gitToolchain measuredTree) (childBuildExpectation, error) {
	info, err := buildinfo.Read(executable)
	if err != nil {
		return childBuildExpectation{}, fmt.Errorf("read built child Go metadata independently: %w", err)
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return childBuildExpectation{}, fmt.Errorf("built child duplicates Go build setting %q", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH || settings["-compiler"] != "gc" || settings["-buildmode"] != "exe" || settings["CGO_ENABLED"] != "0" || settings["-tags"] != releaseBuildTag || settings["-trimpath"] != "true" || settings["vcs"] != "git" || settings["vcs.modified"] != "false" {
		return childBuildExpectation{}, fmt.Errorf("built child metadata does not satisfy the closed release profile")
	}
	if info.Path != releaseRunnerImportPath || info.Main.Path != releaseModulePath || strings.TrimSpace(info.Main.Version) == "" {
		return childBuildExpectation{}, fmt.Errorf("built child metadata identifies a different command or module")
	}
	mainModule, err := releaseBuildModule(info.Main)
	if err != nil {
		return childBuildExpectation{}, err
	}
	dependencies := make([]any, len(info.Deps))
	for index, dependency := range info.Deps {
		if dependency == nil {
			return childBuildExpectation{}, fmt.Errorf("built child metadata contains a nil dependency")
		}
		dependencies[index], err = releaseBuildModule(*dependency)
		if err != nil {
			return childBuildExpectation{}, err
		}
	}
	sort.Slice(dependencies, func(i, j int) bool {
		return releaseBuildModuleLess(dependencies[i].(map[string]any), dependencies[j].(map[string]any))
	})
	portableSettings := make([]any, 0, len(info.Settings))
	executionSettings := make([]any, 0, len(info.Settings))
	for _, setting := range info.Settings {
		entry := map[string]any{"key": setting.Key, "value": setting.Value}
		if !releaseTargetBuildSetting(setting.Key) {
			portableSettings = append(portableSettings, entry)
		}
		if !releaseExecutionBuildSettingAllowed(setting.Key) {
			return childBuildExpectation{}, fmt.Errorf("built child metadata contains unsupported setting %q", setting.Key)
		}
		executionSettings = append(executionSettings, entry)
	}
	lessSetting := func(values []any, i, j int) bool {
		left := values[i].(map[string]any)
		right := values[j].(map[string]any)
		if left["key"] != right["key"] {
			return left["key"].(string) < right["key"].(string)
		}
		return left["value"].(string) < right["value"].(string)
	}
	sort.Slice(portableSettings, func(i, j int) bool { return lessSetting(portableSettings, i, j) })
	sort.Slice(executionSettings, func(i, j int) bool { return lessSetting(executionSettings, i, j) })
	metadata := map[string]any{
		"go_version": info.GoVersion, "main": mainModule, "dependencies": dependencies,
		"portable_settings": portableSettings,
	}
	moduleGraphSHA256, err := canonicalReleaseDigest(map[string]any{"main": mainModule, "dependencies": dependencies})
	if err != nil {
		return childBuildExpectation{}, err
	}
	buildRecipeSHA256, err := canonicalReleaseDigest(metadata)
	if err != nil {
		return childBuildExpectation{}, err
	}
	toolIdentity := map[string]any{
		"command_path": info.Path, "module_path": info.Main.Path, "module_version": info.Main.Version,
		"go_version": info.GoVersion, "vcs": settings["vcs"], "vcs_revision": settings["vcs.revision"],
		"vcs_time": settings["vcs.time"], "vcs_modified": false, "build_tags": settings["-tags"],
		"module_graph_sha256": moduleGraphSHA256, "build_recipe_sha256": buildRecipeSHA256,
		"source_roster_sha256": rosterRoot, "runner_contract_sha256": sha256String(releaseRunnerContract),
		"build_identity_sha256": "", "reproducible_source_tree": true,
	}
	toolIdentitySHA256, err := canonicalReleaseDigest(toolIdentity)
	if err != nil {
		return childBuildExpectation{}, err
	}
	buildSettingsSHA256, err := canonicalReleaseDigest(executionSettings)
	if err != nil {
		return childBuildExpectation{}, err
	}
	executionIdentity := map[string]any{
		"portable_build_identity_sha256": toolIdentitySHA256, "build_metadata_source": releaseBuildMetadataSource,
		"executable_measurement_scope": releaseExecutableScope, "target_os": runtime.GOOS, "target_arch": runtime.GOARCH,
		"build_settings": executionSettings, "build_settings_sha256": buildSettingsSHA256,
		"executable_sha256": child.digest, "executable_byte_count": child.size,
		"go_executable_sha256": goTool.digest, "git_executable_sha256": gitTool.digest,
		"go_toolchain_sha256": goToolchain.digest, "git_toolchain_sha256": gitToolchain.digest,
		"go_toolchain_file_count": int64(goToolchain.files), "go_toolchain_byte_count": goToolchain.bytes,
		"git_toolchain_file_count": int64(gitToolchain.files), "git_toolchain_byte_count": gitToolchain.bytes,
		"execution_identity_sha256": "",
	}
	executionIdentitySHA256, err := canonicalReleaseDigest(executionIdentity)
	if err != nil {
		return childBuildExpectation{}, err
	}
	return childBuildExpectation{
		toolIdentitySHA256: toolIdentitySHA256, moduleGraphSHA256: moduleGraphSHA256,
		buildRecipeSHA256: buildRecipeSHA256, executionIdentitySHA256: executionIdentitySHA256,
		buildSettingsSHA256: buildSettingsSHA256,
	}, nil
}

func releaseBuildModuleLess(left, right map[string]any) bool {
	for _, key := range []string{"path", "version", "sum", "replace_path", "replace_version", "replace_sum"} {
		leftValue, _ := left[key].(string)
		rightValue, _ := right[key].(string)
		if leftValue != rightValue {
			return leftValue < rightValue
		}
	}
	return false
}

func releaseBuildModule(module debug.Module) (map[string]any, error) {
	result := map[string]any{"path": module.Path, "version": module.Version, "sum": module.Sum}
	if module.Replace != nil {
		if strings.TrimSpace(module.Replace.Path) == "" || strings.TrimSpace(module.Replace.Version) == "" || strings.TrimSpace(module.Replace.Sum) == "" {
			return nil, fmt.Errorf("built child metadata contains an unpinned module replacement")
		}
		result["replace_path"] = module.Replace.Path
		result["replace_version"] = module.Replace.Version
		result["replace_sum"] = module.Replace.Sum
	}
	return result, nil
}

func releaseTargetBuildSetting(key string) bool {
	switch key {
	case "-buildmode", "-compiler", "-ldflags", "CGO_ENABLED", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS",
		"GOOS", "GOARCH", "GO386", "GOAMD64", "GOARM", "GOARM64", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOWASM":
		return true
	default:
		return false
	}
}

func releaseExecutionBuildSettingAllowed(key string) bool {
	switch key {
	case "-buildmode", "-compiler", "-ldflags", "-tags", "-trimpath", "CGO_ENABLED", "GOOS", "GOARCH",
		"GO386", "GOAMD64", "GOARM", "GOARM64", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOWASM",
		"vcs", "vcs.revision", "vcs.time", "vcs.modified", "DefaultGODEBUG":
		return true
	default:
		return false
	}
}

func verifySourceRepository(gitExecutable, sourceRoot, commit string, environment []string) error {
	top, err := runCaptured(gitExecutable, []string{"-C", sourceRoot, "rev-parse", "--show-toplevel"}, "", environment)
	if err != nil {
		return fmt.Errorf("resolve source Git repository: %w", err)
	}
	resolvedTop, err := resolveSourceRoot(strings.TrimSpace(string(top)))
	if err != nil || !sameNativePath(resolvedTop, sourceRoot) {
		return fmt.Errorf("source root is not the exact Git repository root")
	}
	if _, err := runCaptured(gitExecutable, []string{"-C", sourceRoot, "cat-file", "-e", commit + "^{commit}"}, "", environment); err != nil {
		return fmt.Errorf("source commit does not exist as a commit object")
	}
	resolved, err := runCaptured(gitExecutable, []string{"-C", sourceRoot, "rev-parse", "--verify", commit + "^{commit}"}, "", environment)
	if err != nil || strings.TrimSpace(string(resolved)) != commit {
		return fmt.Errorf("source commit does not resolve exactly")
	}
	if replacements, err := runCaptured(gitExecutable, []string{"-C", sourceRoot, "for-each-ref", "--format=%(refname)", "refs/replace"}, "", environment); err != nil || len(bytes.TrimSpace(replacements)) != 0 {
		return fmt.Errorf("source repository carries replacement refs")
	}
	return nil
}

func createCommitProjection(gitExecutable, sourceRoot, commit string, workspace releaseWorkspace) (sourceRoster, error) {
	if err := os.Mkdir(workspace.projectionRoot, 0o700); err != nil {
		return sourceRoster{}, fmt.Errorf("create source projection: %w", err)
	}
	if err := runSilent(gitExecutable, []string{"init", "--quiet", "--object-format=sha1"}, workspace.projectionRoot, workspace.onlineEnv); err != nil {
		return sourceRoster{}, fmt.Errorf("initialize source projection: %w", err)
	}
	for _, setting := range [][2]string{
		{"core.autocrlf", "false"},
		{"core.filemode", strconv.FormatBool(runtime.GOOS != "windows")},
		{"core.hooksPath", filepath.Join(workspace.root, "empty-hooks")},
		{"core.symlinks", "false"},
	} {
		if err := runSilent(gitExecutable, []string{"config", "--local", setting[0], setting[1]}, workspace.projectionRoot, workspace.onlineEnv); err != nil {
			return sourceRoster{}, fmt.Errorf("configure source projection: %w", err)
		}
	}
	if err := os.Mkdir(filepath.Join(workspace.root, "empty-hooks"), 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return sourceRoster{}, err
	}
	attributesPath := filepath.Join(workspace.projectionRoot, ".git", "info", "attributes")
	if err := os.MkdirAll(filepath.Dir(attributesPath), 0o700); err != nil {
		return sourceRoster{}, err
	}
	if err := os.WriteFile(attributesPath, []byte("* -text -eol -filter -ident -working-tree-encoding\n"), 0o600); err != nil {
		return sourceRoster{}, err
	}
	fetchRef := "refs/heads/factory-release"
	fetchArgs := []string{"-c", "protocol.file.allow=always", "fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--depth=1", sourceRoot, commit + ":" + fetchRef}
	if err := runSilent(gitExecutable, fetchArgs, workspace.projectionRoot, workspace.onlineEnv); err != nil {
		return sourceRoster{}, fmt.Errorf("fetch exact source commit: %w", err)
	}
	resolved, err := runCaptured(gitExecutable, []string{"rev-parse", "--verify", fetchRef + "^{commit}"}, workspace.projectionRoot, workspace.onlineEnv)
	if err != nil || strings.TrimSpace(string(resolved)) != commit {
		return sourceRoster{}, fmt.Errorf("fetched source commit differs from request")
	}
	if err := runSilent(gitExecutable, []string{"symbolic-ref", "HEAD", fetchRef}, workspace.projectionRoot, workspace.onlineEnv); err != nil {
		return sourceRoster{}, err
	}
	if err := runSilent(gitExecutable, []string{"read-tree", commit}, workspace.projectionRoot, workspace.onlineEnv); err != nil {
		return sourceRoster{}, fmt.Errorf("load exact source index: %w", err)
	}
	treeRaw, err := runCaptured(gitExecutable, []string{"ls-tree", "-r", "-z", "--full-tree", commit}, workspace.projectionRoot, workspace.onlineEnv)
	if err != nil {
		return sourceRoster{}, fmt.Errorf("enumerate exact source tree: %w", err)
	}
	roster, err := parseSourceTree(treeRaw)
	if err != nil {
		return sourceRoster{}, err
	}
	if err := materializeSourceRoster(gitExecutable, workspace.projectionRoot, workspace.onlineEnv, &roster); err != nil {
		return sourceRoster{}, err
	}
	roster.root, err = sourceRosterRoot(roster.entries)
	if err != nil {
		return sourceRoster{}, err
	}
	roster.byPath = make(map[string]sourceRosterEntry, len(roster.entries))
	for _, entry := range roster.entries {
		roster.byPath[entry.path] = entry
	}
	if err := verifyProjectionGitTrustLayout(gitExecutable, workspace.projectionRoot, workspace.onlineEnv); err != nil {
		return sourceRoster{}, err
	}
	return roster, nil
}

func parseSourceTree(raw []byte) (sourceRoster, error) {
	if len(raw) == 0 {
		return sourceRoster{}, fmt.Errorf("source commit tree is empty")
	}
	parts := bytes.Split(raw, []byte{0})
	entries := make([]sourceRosterEntry, 0, len(parts)-1)
	nativePaths := map[string]string{}
	for _, encoded := range parts {
		if len(encoded) == 0 {
			continue
		}
		if len(entries) >= maximumRosterEntries {
			return sourceRoster{}, fmt.Errorf("source roster exceeds entry bound")
		}
		tab := bytes.IndexByte(encoded, '\t')
		if tab <= 0 || tab == len(encoded)-1 {
			return sourceRoster{}, fmt.Errorf("source tree entry is malformed")
		}
		metadata := strings.Fields(string(encoded[:tab]))
		if len(metadata) != 3 || metadata[1] != "blob" || (metadata[0] != "100644" && metadata[0] != "100755") || !validFullObjectID(metadata[2]) {
			return sourceRoster{}, fmt.Errorf("source tree contains unsupported object kind or mode")
		}
		gitPath := string(encoded[tab+1:])
		nativePath, collisionKey, err := safeRosterPath(gitPath)
		if err != nil {
			return sourceRoster{}, err
		}
		if prior, duplicate := nativePaths[collisionKey]; duplicate {
			return sourceRoster{}, fmt.Errorf("source paths %q and %q collapse to one native path", prior, gitPath)
		}
		nativePaths[collisionKey] = gitPath
		entries = append(entries, sourceRosterEntry{path: gitPath, nativePath: nativePath, mode: metadata[0], objectID: metadata[2]})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].path < entries[j].path })
	return sourceRoster{entries: entries}, nil
}

func safeRosterPath(gitPath string) (string, string, error) {
	if gitPath == "" || !utf8.ValidString(gitPath) || strings.ContainsRune(gitPath, '\x00') || strings.ContainsRune(gitPath, '\\') || strings.HasPrefix(gitPath, "/") || path.Clean(gitPath) != gitPath || gitPath == "." || gitPath == ".." || strings.HasPrefix(gitPath, "../") {
		return "", "", fmt.Errorf("source tree path is not a portable relative path")
	}
	segments := strings.Split(gitPath, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || strings.EqualFold(segment, ".git") || strings.HasSuffix(segment, " ") || strings.HasSuffix(segment, ".") {
			return "", "", fmt.Errorf("source tree path has an unsafe native segment")
		}
		for _, character := range segment {
			if character < 0x20 || character >= 0x7f || strings.ContainsRune(`<>:"|?*`, character) {
				return "", "", fmt.Errorf("source tree path contains an unsupported native character")
			}
		}
		stem := strings.ToUpper(strings.SplitN(segment, ".", 2)[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || stem == "CONIN$" || stem == "CONOUT$" || strings.HasPrefix(stem, "COM") && validReservedSuffix(stem[3:]) || strings.HasPrefix(stem, "LPT") && validReservedSuffix(stem[3:]) {
			return "", "", fmt.Errorf("source tree path contains a reserved native segment")
		}
	}
	native := filepath.Clean(filepath.FromSlash(gitPath))
	if filepath.IsAbs(native) || native == "." || native == ".." || strings.HasPrefix(native, ".."+string(os.PathSeparator)) {
		return "", "", fmt.Errorf("source tree path escapes the projection")
	}
	// The release must be buildable on both supported families. Case-only names
	// are therefore rejected even on a case-sensitive host.
	return native, strings.ToLower(filepath.ToSlash(native)), nil
}

func validReservedSuffix(value string) bool {
	return len(value) == 1 && value[0] >= '1' && value[0] <= '9'
}

func materializeSourceRoster(gitExecutable, projectionRoot string, environment []string, roster *sourceRoster) error {
	command := exec.Command(gitExecutable, "cat-file", "--batch")
	command.Dir = projectionRoot
	command.Env = append([]string(nil), environment...)
	stdin, err := command.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr limitedBuffer
	stderr.limit = maximumCommandOutput
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start exact blob projection: %w", err)
	}
	go func() {
		writer := bufio.NewWriter(stdin)
		for _, entry := range roster.entries {
			_, _ = fmt.Fprintln(writer, entry.objectID)
		}
		_ = writer.Flush()
		_ = stdin.Close()
	}()
	reader := bufio.NewReader(stdout)
	var total int64
	for index := range roster.entries {
		entry := &roster.entries[index]
		header, readErr := reader.ReadString('\n')
		if readErr != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return fmt.Errorf("read exact blob header: %w", readErr)
		}
		fields := strings.Fields(header)
		if len(fields) != 3 || fields[0] != entry.objectID || fields[1] != "blob" {
			_ = command.Process.Kill()
			_ = command.Wait()
			return fmt.Errorf("Git returned an unexpected source object")
		}
		size, parseErr := strconv.ParseInt(fields[2], 10, 64)
		if parseErr != nil || size < 0 || size > maximumRosterBytes-total {
			_ = command.Process.Kill()
			_ = command.Wait()
			return fmt.Errorf("source roster exceeds byte bound")
		}
		target := filepath.Join(projectionRoot, entry.nativePath)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return err
		}
		mode := fs.FileMode(0o644)
		if entry.mode == "100755" {
			mode = 0o755
		}
		file, openErr := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if openErr != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return fmt.Errorf("create exact source projection: %w", openErr)
		}
		hash := sha256.New()
		written, copyErr := io.CopyN(io.MultiWriter(file, hash), reader, size)
		closeErr := file.Close()
		separator, separatorErr := reader.ReadByte()
		if copyErr != nil || closeErr != nil || separatorErr != nil || separator != '\n' || written != size {
			_ = command.Process.Kill()
			_ = command.Wait()
			return fmt.Errorf("materialize exact source blob")
		}
		if err := os.Chmod(target, mode); err != nil {
			_ = command.Process.Kill()
			_ = command.Wait()
			return err
		}
		entry.contentSHA256 = hex.EncodeToString(hash.Sum(nil))
		entry.byteCount = size
		total += size
	}
	if err := command.Wait(); err != nil {
		return fmt.Errorf("materialize exact source blobs: %w", err)
	}
	return nil
}

func sourceRosterRoot(entries []sourceRosterEntry) (string, error) {
	hash := sha256.New()
	if err := writeSourceRosterIdentity(hash, entries); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeSourceRosterIdentity(writer io.Writer, entries []sourceRosterEntry) error {
	for _, entry := range entries {
		for _, value := range []string{entry.path, entry.mode} {
			if err := binary.Write(writer, binary.BigEndian, uint64(len(value))); err != nil {
				return err
			}
			if _, err := io.WriteString(writer, value); err != nil {
				return err
			}
		}
		if err := binary.Write(writer, binary.BigEndian, uint64(entry.byteCount)); err != nil {
			return err
		}
		if err := binary.Write(writer, binary.BigEndian, uint64(len(entry.contentSHA256))); err != nil {
			return err
		}
		if _, err := io.WriteString(writer, entry.contentSHA256); err != nil {
			return err
		}
	}
	return nil
}

func verifyCommitProjection(gitExecutable, commit, projectionRoot string, environment []string, expected sourceRoster) error {
	if err := verifyProjectionGitTrustLayout(gitExecutable, projectionRoot, environment); err != nil {
		return err
	}
	resolved, err := runCaptured(gitExecutable, []string{"rev-parse", "--verify", "HEAD^{commit}"}, projectionRoot, environment)
	if err != nil || strings.TrimSpace(string(resolved)) != commit {
		return fmt.Errorf("projection HEAD differs from exact source commit")
	}
	treeRaw, err := runCaptured(gitExecutable, []string{"ls-tree", "-r", "-z", "--full-tree", "HEAD"}, projectionRoot, environment)
	if err != nil {
		return err
	}
	treeRoster, err := parseSourceTree(treeRaw)
	if err != nil || len(treeRoster.entries) != len(expected.entries) {
		return fmt.Errorf("projection commit roster changed")
	}
	for index, want := range expected.entries {
		got := treeRoster.entries[index]
		if got.path != want.path || got.mode != want.mode || got.objectID != want.objectID {
			return fmt.Errorf("projection commit roster changed")
		}
	}
	indexRaw, err := runCaptured(gitExecutable, []string{"ls-files", "--cached", "--stage", "-z"}, projectionRoot, environment)
	if err != nil {
		return err
	}
	if err := verifyProjectionIndex(indexRaw, expected); err != nil {
		return err
	}
	flagRaw, err := runCaptured(gitExecutable, []string{"ls-files", "-v", "-z"}, projectionRoot, environment)
	if err != nil {
		return err
	}
	for _, encoded := range bytes.Split(flagRaw, []byte{0}) {
		if len(encoded) == 0 {
			continue
		}
		if len(encoded) < 3 || encoded[0] != 'H' || encoded[1] != ' ' {
			return fmt.Errorf("projection index contains skip-worktree, assume-unchanged, or fsmonitor state")
		}
	}
	seen := make(map[string]struct{}, len(expected.entries))
	err = filepath.WalkDir(projectionRoot, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == projectionRoot {
			return nil
		}
		relative, relErr := filepath.Rel(projectionRoot, current)
		if relErr != nil {
			return relErr
		}
		if strings.EqualFold(strings.Split(filepath.ToSlash(relative), "/")[0], ".git") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		gitPath := filepath.ToSlash(relative)
		want, exists := expected.byPath[gitPath]
		if !exists {
			return fmt.Errorf("projection contains an extra source path")
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("inspect projection source %q: %w", gitPath, infoErr)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != want.byteCount {
			return fmt.Errorf("projection source %q has mode %s and %d bytes, want a regular non-link file with %d bytes", gitPath, info.Mode(), info.Size(), want.byteCount)
		}
		if runtime.GOOS != "windows" {
			wantExecutable := want.mode == "100755"
			if (info.Mode().Perm()&0o111 != 0) != wantExecutable {
				return fmt.Errorf("projection source mode differs from commit")
			}
		}
		file, openErr := os.Open(current)
		if openErr != nil {
			return openErr
		}
		hash := sha256.New()
		count, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || count != want.byteCount || hex.EncodeToString(hash.Sum(nil)) != want.contentSHA256 {
			return fmt.Errorf("projection source bytes differ from commit")
		}
		seen[gitPath] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(expected.entries) {
		return fmt.Errorf("projection omits a committed source path")
	}
	status, err := runCaptured(gitExecutable, []string{"status", "--porcelain=v1", "-z", "--untracked-files=all"}, projectionRoot, environment)
	if err != nil || len(status) != 0 {
		return fmt.Errorf("projection is not exactly clean")
	}
	return nil
}

func verifyProjectionGitTrustLayout(gitExecutable, projectionRoot string, environment []string) error {
	wantGitDir := filepath.Join(projectionRoot, ".git")
	for _, query := range []struct {
		args []string
		want string
	}{
		{args: []string{"rev-parse", "--absolute-git-dir"}, want: wantGitDir},
		{args: []string{"rev-parse", "--path-format=absolute", "--git-common-dir"}, want: wantGitDir},
		{args: []string{"rev-parse", "--path-format=absolute", "--git-path", "objects"}, want: filepath.Join(wantGitDir, "objects")},
	} {
		raw, err := runCaptured(gitExecutable, query.args, projectionRoot, environment)
		if err != nil || !sameNativePath(strings.TrimSpace(string(raw)), query.want) {
			return fmt.Errorf("projection Git storage is redirected")
		}
	}
	for _, forbidden := range []string{
		filepath.Join(wantGitDir, "info", "grafts"),
		filepath.Join(wantGitDir, "objects", "info", "alternates"),
	} {
		if _, err := os.Lstat(forbidden); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("projection Git object graph is redirected")
		}
	}
	replacements, err := runCaptured(gitExecutable, []string{"replace", "-l"}, projectionRoot, environment)
	if err != nil || len(bytes.TrimSpace(replacements)) != 0 {
		return fmt.Errorf("projection contains replacement refs")
	}
	for _, key := range []string{"core.sparseCheckout", "core.sparseCheckoutCone", "extensions.worktreeConfig"} {
		raw, err := runCapturedAllowExitOne(gitExecutable, []string{"config", "--local", "--get", key}, projectionRoot, environment)
		if err != nil || len(bytes.TrimSpace(raw)) != 0 {
			return fmt.Errorf("projection enables unsupported Git workspace state")
		}
	}
	return nil
}

func verifyProjectionIndex(raw []byte, expected sourceRoster) error {
	seen := make(map[string]struct{}, len(expected.entries))
	for _, encoded := range bytes.Split(raw, []byte{0}) {
		if len(encoded) == 0 {
			continue
		}
		tab := bytes.IndexByte(encoded, '\t')
		if tab <= 0 || tab == len(encoded)-1 {
			return fmt.Errorf("projection index entry is malformed")
		}
		fields := strings.Fields(string(encoded[:tab]))
		gitPath := string(encoded[tab+1:])
		want, exists := expected.byPath[gitPath]
		if !exists || len(fields) != 3 || fields[0] != want.mode || fields[1] != want.objectID || fields[2] != "0" {
			return fmt.Errorf("projection index differs from commit roster")
		}
		if _, duplicate := seen[gitPath]; duplicate {
			return fmt.Errorf("projection index repeats a source path")
		}
		seen[gitPath] = struct{}{}
	}
	if len(seen) != len(expected.entries) {
		return fmt.Errorf("projection index omits a source path")
	}
	return nil
}

func rejectUnpinnedModuleReplacements(goExecutable, projectionRoot string, environment []string) error {
	raw, err := runCaptured(goExecutable, []string{"list", "-mod=readonly", "-m", "-json", "all"}, projectionRoot, environment)
	if err != nil {
		return fmt.Errorf("inspect module graph before build: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	count := 0
	for {
		var module listedModule
		err := decoder.Decode(&module)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("decode module graph: %w", err)
		}
		count++
		if strings.TrimSpace(module.Path) == "" {
			return fmt.Errorf("module graph contains an unnamed module")
		}
		if module.Replace != nil && (strings.TrimSpace(module.Replace.Path) == "" || strings.TrimSpace(module.Replace.Version) == "" || strings.TrimSpace(module.Replace.Sum) == "") {
			return fmt.Errorf("module graph contains an unpinned local replacement")
		}
	}
	if count == 0 {
		return fmt.Errorf("module graph is empty")
	}
	return nil
}

func prefetchSelectedModuleGraph(goExecutable, projectionRoot string, environment []string) error {
	args := []string{"list", "-mod=readonly", "-deps", "-tags=" + releaseBuildTag, releaseRunnerPackage}
	if err := runSilent(goExecutable, args, projectionRoot, environment); err != nil {
		return fmt.Errorf("download selected factory module graph: %w", err)
	}
	return nil
}

func verifySelectedMainModuleInputs(goExecutable, projectionRoot string, environment []string, roster sourceRoster) error {
	raw, err := runCaptured(goExecutable, []string{"list", "-mod=readonly", "-deps", "-json", "-tags=" + releaseBuildTag, releaseRunnerPackage}, projectionRoot, environment)
	if err != nil {
		return fmt.Errorf("enumerate selected factory build inputs: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	selected := map[string]struct{}{}
	foundRunner := false
	for {
		var pkg listedPackage
		err := decoder.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("decode selected factory build inputs: %w", err)
		}
		if pkg.Module == nil || (!pkg.Module.Main && pkg.Module.Path != releaseModulePath) {
			continue
		}
		if pkg.ImportPath == releaseRunnerImportPath {
			foundRunner = true
		}
		files := append([]string(nil), pkg.GoFiles...)
		files = append(files, pkg.CgoFiles...)
		files = append(files, pkg.SFiles...)
		files = append(files, pkg.SysoFiles...)
		files = append(files, pkg.EmbedFiles...)
		for _, file := range files {
			candidate := file
			if !filepath.IsAbs(candidate) {
				candidate = filepath.Join(pkg.Dir, filepath.FromSlash(candidate))
			}
			abs, absErr := filepath.Abs(candidate)
			if absErr != nil {
				return absErr
			}
			relative, relErr := filepath.Rel(projectionRoot, abs)
			if relErr != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
				return fmt.Errorf("selected main-module input escapes exact commit projection")
			}
			gitPath := filepath.ToSlash(filepath.Clean(relative))
			if _, exists := roster.byPath[gitPath]; !exists {
				return fmt.Errorf("selected main-module input is absent from exact commit roster")
			}
			selected[gitPath] = struct{}{}
		}
	}
	if !foundRunner || len(selected) == 0 {
		return fmt.Errorf("factory runner package or selected source roster is absent")
	}
	return nil
}

type limitedBuffer struct {
	buffer bytes.Buffer
	limit  int64
}

func (writer *limitedBuffer) Write(value []byte) (int, error) {
	if int64(writer.buffer.Len())+int64(len(value)) > writer.limit {
		return 0, fmt.Errorf("command output exceeds bound")
	}
	return writer.buffer.Write(value)
}

func (writer *limitedBuffer) Bytes() []byte { return writer.buffer.Bytes() }

func runCaptured(executable string, args []string, directory string, environment []string) ([]byte, error) {
	command := exec.Command(executable, args...)
	command.Dir = directory
	command.Env = append([]string(nil), environment...)
	var stdout, stderr limitedBuffer
	stdout.limit = maximumCommandOutput
	stderr.limit = maximumCommandOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("command failed: %w: %s", err, strings.TrimSpace(string(stderr.Bytes())))
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func runCapturedAllowExitOne(executable string, args []string, directory string, environment []string) ([]byte, error) {
	command := exec.Command(executable, args...)
	command.Dir = directory
	command.Env = append([]string(nil), environment...)
	var stdout, stderr limitedBuffer
	stdout.limit = maximumCommandOutput
	stderr.limit = maximumCommandOutput
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("command failed: %w", err)
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

func runSilent(executable string, args []string, directory string, environment []string) error {
	_, err := runCaptured(executable, args, directory, environment)
	return err
}

func validFullObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	if strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.Trim(value, "0") != ""
}

func validFullCommitID(value string) bool {
	return len(value) == 40 && validFullObjectID(value)
}

func validSHA256(value string) bool {
	return len(value) == 64 && validFullObjectID(value)
}

func sameNativePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
