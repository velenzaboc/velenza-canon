package providerplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	factoryRunnerReceiptKind    = "provider_documentation_factory_offline_run_receipt"
	factoryRunnerReceiptVersion = "2"
	factoryRunnerResult         = "compiled_and_verified_candidate_only"
	factoryRunnerScope          = "offline_exact_input_four_stage_compilation_and_provider_plan_verification"
	factoryRunnerContract       = "exactly_four_ordered_stage_manifests;runner_owned_predecessor_and_evidence_reuse;one_union_input_roster;intake_authority_and_evidence_cross_binding;verifier_admitted_complete_dependency_closure;no_network_graph_admission_tenant_credential_deployment_or_live_acceptance_claim"
	factoryRunnerModulePath     = "github.com/velenzaboc/velenza-canon"
	factoryRunnerCommandPath    = factoryRunnerModulePath + "/cmd/provider-documentation-factory-run"
	factoryReleaseBuildTag      = "factory_release"
	factoryBuildMetadataSource  = "go_runtime_debug_build_info"
	factoryExecutableScope      = "launch_path_open_regular_file"
	factoryValidationProfileID  = "provider_documentation_factory_runtime_validation"
	factoryValidationVersion    = "3"
	factoryValidationResult     = "candidate_runtime_validation_pass"
	factoryValidationContract   = "result=candidate_runtime_validation_pass;portable_receipt_recomputed;tool_identity_validated;exact_execution_profile_validated;honest_measurement_scope_validated;executable_digest_bound;input_admission_recomputed;four_stage_receipts_validated;preflight_receipt_validated;completion_classification_fail_closed"
	maxFactoryExecutableBytes   = 512 << 20
)

// The exact-commit release launcher sets these nine values at link time. They
// are evidence, not authority: the launcher independently verifies each digest
// before build and then checks the child receipt after execution.
var (
	factoryReleaseSourceRosterSHA256  string
	factoryReleaseGoExecutableSHA256  string
	factoryReleaseGitExecutableSHA256 string
	factoryReleaseGoToolchainSHA256   string
	factoryReleaseGitToolchainSHA256  string
	factoryReleaseGoToolchainFiles    string
	factoryReleaseGoToolchainBytes    string
	factoryReleaseGitToolchainFiles   string
	factoryReleaseGitToolchainBytes   string
)

type factoryReleaseBuildPins struct {
	SourceRosterSHA256  string
	GoExecutableSHA256  string
	GitExecutableSHA256 string
	GoToolchainSHA256   string
	GitToolchainSHA256  string
	GoToolchainFiles    int64
	GoToolchainBytes    int64
	GitToolchainFiles   int64
	GitToolchainBytes   int64
}

func currentFactoryReleaseBuildPins() factoryReleaseBuildPins {
	return factoryReleaseBuildPins{
		SourceRosterSHA256:  factoryReleaseSourceRosterSHA256,
		GoExecutableSHA256:  factoryReleaseGoExecutableSHA256,
		GitExecutableSHA256: factoryReleaseGitExecutableSHA256,
		GoToolchainSHA256:   factoryReleaseGoToolchainSHA256,
		GitToolchainSHA256:  factoryReleaseGitToolchainSHA256,
		GoToolchainFiles:    parseFactoryReleaseCount(factoryReleaseGoToolchainFiles),
		GoToolchainBytes:    parseFactoryReleaseCount(factoryReleaseGoToolchainBytes),
		GitToolchainFiles:   parseFactoryReleaseCount(factoryReleaseGitToolchainFiles),
		GitToolchainBytes:   parseFactoryReleaseCount(factoryReleaseGitToolchainBytes),
	}
}

func parseFactoryReleaseCount(value string) int64 {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

// FactoryRunOptions names the four exact stage manifests and the separately
// pinned offline preflight inputs. Preflight graph selection is always replaced
// with the graph stage compiled in this run; callers cannot supply a second
// graph plan path or in-memory selection.
type FactoryRunOptions struct {
	EvidenceIntakeInputManifestPath     string
	SemanticExtractionInputManifestPath string
	GraphCompileInputManifestPath       string
	FullFactoryInputManifestPath        string
	Preflight                           Options
}

// FactoryToolIdentity is derived from Go's embedded VCS build metadata. The
// runner refuses a modified or unidentifiable source tree instead of trusting a
// caller-provided source/build attestation.
type FactoryToolIdentity struct {
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
}

// FactoryExecutionIdentity is the exact local execution attestation. Unlike
// FactoryToolIdentity, it is deliberately target-specific: it binds the native
// build settings, a stable digest of the launch-resolved executable artifact,
// and the complete selected Go and Git helper trees measured by the release
// launcher. FactoryToolIdentity supplies the executing build's in-memory Go
// build identity; the artifact digest does not claim that every host exposes
// the loader's mapped image bytes as a file. The identity is excluded from
// PortableReceiptSHA256 and included in ReceiptSHA256.
type FactoryExecutionIdentity struct {
	PortableBuildIdentitySHA256 string                `json:"portable_build_identity_sha256"`
	BuildMetadataSource         string                `json:"build_metadata_source"`
	ExecutableMeasurementScope  string                `json:"executable_measurement_scope"`
	TargetOS                    string                `json:"target_os"`
	TargetArch                  string                `json:"target_arch"`
	BuildSettings               []FactoryBuildSetting `json:"build_settings"`
	BuildSettingsSHA256         string                `json:"build_settings_sha256"`
	ExecutableSHA256            string                `json:"executable_sha256"`
	ExecutableByteCount         int64                 `json:"executable_byte_count"`
	GoExecutableSHA256          string                `json:"go_executable_sha256"`
	GitExecutableSHA256         string                `json:"git_executable_sha256"`
	GoToolchainSHA256           string                `json:"go_toolchain_sha256"`
	GitToolchainSHA256          string                `json:"git_toolchain_sha256"`
	GoToolchainFileCount        int64                 `json:"go_toolchain_file_count"`
	GoToolchainByteCount        int64                 `json:"go_toolchain_byte_count"`
	GitToolchainFileCount       int64                 `json:"git_toolchain_file_count"`
	GitToolchainByteCount       int64                 `json:"git_toolchain_byte_count"`
	ExecutionIdentitySHA256     string                `json:"execution_identity_sha256"`
}

// FactoryValidationIdentity identifies the exact built-in runtime validation
// profile and the report deterministically produced from this candidate run.
// It is not an independent validator or test-suite PASS. Callers do not supply
// either value.
type FactoryValidationIdentity struct {
	ProfileID                string `json:"profile_id"`
	ProfileVersion           string `json:"profile_version"`
	Result                   string `json:"result"`
	ValidationContractSHA256 string `json:"validation_contract_sha256"`
	PortableReceiptSHA256    string `json:"portable_receipt_sha256"`
	ToolBuildIdentitySHA256  string `json:"tool_build_identity_sha256"`
	ExecutionIdentitySHA256  string `json:"execution_identity_sha256"`
	ValidationReportSHA256   string `json:"validation_report_sha256"`
	ValidationIdentitySHA256 string `json:"validation_identity_sha256"`
}

type factoryToolIdentity = FactoryToolIdentity

type FactoryBuildSetting struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type factoryBuildSetting = FactoryBuildSetting

type factoryBuildModule struct {
	Path           string `json:"path"`
	Version        string `json:"version"`
	Sum            string `json:"sum"`
	ReplacePath    string `json:"replace_path,omitempty"`
	ReplaceVersion string `json:"replace_version,omitempty"`
	ReplaceSum     string `json:"replace_sum,omitempty"`
}

type factoryBuildMetadata struct {
	GoVersion    string                `json:"go_version"`
	Main         factoryBuildModule    `json:"main"`
	Dependencies []factoryBuildModule  `json:"dependencies"`
	Settings     []factoryBuildSetting `json:"portable_settings"`
}

type factoryValidationReport struct {
	Result                    string                          `json:"result"`
	PortableReceiptSHA256     string                          `json:"portable_receipt_sha256"`
	ToolBuildIdentitySHA256   string                          `json:"tool_build_identity_sha256"`
	ExecutionIdentitySHA256   string                          `json:"execution_identity_sha256"`
	InputAdmissionProofSHA256 string                          `json:"input_admission_proof_sha256"`
	StageReceiptSHA256        []string                        `json:"stage_receipt_sha256"`
	PreflightReceiptSHA256    string                          `json:"preflight_receipt_sha256"`
	CompletionClassification  FactoryCompletionClassification `json:"completion_classification"`
}

type factoryModuleGraph struct {
	Main         factoryBuildModule   `json:"main"`
	Dependencies []factoryBuildModule `json:"dependencies"`
}

type FactoryStageRunReceipt struct {
	StageKind                  string `json:"stage_kind"`
	ReceiptSHA256              string `json:"receipt_sha256"`
	OutputRootSHA256           string `json:"output_root_sha256"`
	InputResourceSetRootSHA256 string `json:"input_resource_set_root_sha256"`
}

type FactoryCompletionClassification struct {
	Compiled                 bool `json:"compiled"`
	Verified                 bool `json:"verified"`
	DerivationExecuted       bool `json:"derivation_executed"`
	GraphAdmittable          bool `json:"graph_admittable"`
	Admitted                 bool `json:"admitted"`
	CircuitAdmittable        bool `json:"circuit_admittable"`
	CircuitAdmitted          bool `json:"circuit_admitted"`
	Configured               bool `json:"configured"`
	CredentialProvisioned    bool `json:"credential_provisioned"`
	Deployed                 bool `json:"deployed"`
	LiveTested               bool `json:"live_tested"`
	TwoTenantProven          bool `json:"two_tenant_proven"`
	SourceSubstitutionProven bool `json:"source_substitution_proven"`
	AuthoritySelected        bool `json:"authority_selected"`
	AdmissionAuthorized      bool `json:"admission_authorized"`
	FactoryComplete          bool `json:"factory_complete"`
}

// FactoryRunReceipt is body-free and secret-free. It binds the exact union of
// stage and verifier input receipts, all four stage commitments, the executable
// preflight receipt, and a closed completion classification. It never upgrades
// an offline candidate into graph, circuit, configuration, credential, tenant,
// deployment, or live-acceptance state.
type FactoryRunReceipt struct {
	ReceiptKind           string                                  `json:"receipt_kind"`
	ReceiptVersion        string                                  `json:"receipt_version"`
	Result                string                                  `json:"result"`
	Scope                 string                                  `json:"scope"`
	ToolIdentity          FactoryToolIdentity                     `json:"tool_identity"`
	ExecutionIdentity     FactoryExecutionIdentity                `json:"execution_identity"`
	ValidationIdentity    FactoryValidationIdentity               `json:"validation_identity"`
	InputAdmissionProof   providerInputAdmissionProof             `json:"input_admission_proof"`
	InputResources        []providerInputAdmissionResourceReceipt `json:"input_resources"`
	Stages                []FactoryStageRunReceipt                `json:"stages"`
	PreflightReceipt      Receipt                                 `json:"preflight_receipt"`
	Completion            FactoryCompletionClassification         `json:"completion"`
	BodyFree              bool                                    `json:"body_free"`
	PortableReceiptSHA256 string                                  `json:"portable_receipt_sha256"`
	ReceiptSHA256         string                                  `json:"receipt_sha256"`
}

type factoryRunnerDependencies struct {
	Verify                func(Options) (Receipt, error)
	ToolIdentity          FactoryToolIdentity
	ObserveEvidenceBodies func(location string, bodies []StageEvidenceBody, retainedStageCollections int)
	ObserveMaterialBodies func(location string, materials []StageMaterial, retainedStageCollections int)
	BeforeFinalInputCheck func(*providerInputAdmissionAccumulator) error
}

type factoryLoadedStage struct {
	requestRaw []byte
	inputs     StageCompileInputs
	binding    stageCompileInputAdmissionBinding
	manifest   stageCompileFileManifest
	materials  []factoryDeclaredMaterial
	summary    StageReceiptSummary
}

type factoryDeclaredMaterial struct {
	coordinate stageMaterialCoordinate
	path       string
	raw        []byte
	resource   providerInputAdmissionResourceReceipt
}

func (options FactoryRunOptions) stageManifestPaths() []string {
	return []string{
		options.EvidenceIntakeInputManifestPath,
		options.SemanticExtractionInputManifestPath,
		options.GraphCompileInputManifestPath,
		options.FullFactoryInputManifestPath,
	}
}

// RunDocumentationFactory compiles one prepared four-stage offline bundle and
// executes the existing provider-plan verifier in the same bounded process. It
// does not generate the stage requests or their provider artifacts from raw
// source inputs.
func RunDocumentationFactory(options FactoryRunOptions) (FactoryRunReceipt, error) {
	toolIdentity, executionIdentity, err := currentFactoryRuntimeIdentities()
	if err != nil {
		return FactoryRunReceipt{}, err
	}
	return runDocumentationFactoryWithExecution(options, factoryRunnerDependencies{Verify: Verify, ToolIdentity: toolIdentity}, executionIdentity)
}

func runDocumentationFactoryWithExecution(options FactoryRunOptions, dependencies factoryRunnerDependencies, executionIdentity FactoryExecutionIdentity) (FactoryRunReceipt, error) {
	if dependencies.Verify == nil {
		return FactoryRunReceipt{}, fmt.Errorf("factory verifier is nil")
	}
	if err := validateFactoryToolIdentity(dependencies.ToolIdentity); err != nil {
		return FactoryRunReceipt{}, err
	}
	if err := validateFactoryExecutionIdentity(executionIdentity, dependencies.ToolIdentity); err != nil {
		return FactoryRunReceipt{}, err
	}
	manifestPaths := options.stageManifestPaths()
	wantKinds := []string{stageEvidenceIntake, stageSemanticExtraction, stageGraphCompile, stageFullFactory}
	for index, path := range manifestPaths {
		if err := validateProviderInputPathSyntax(path, wantKinds[index]+" stage manifest"); err != nil {
			return FactoryRunReceipt{}, err
		}
	}
	if err := validateProviderVerificationTopLevelPathSyntax(options.Preflight); err != nil {
		return FactoryRunReceipt{}, fmt.Errorf("factory preflight input path: %w", err)
	}
	seenManifestPaths := map[string]struct{}{}
	for index, path := range manifestPaths {
		key, err := factoryPathKey(path)
		if err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("%s stage manifest: %w", wantKinds[index], err)
		}
		if _, duplicate := seenManifestPaths[key]; duplicate {
			return FactoryRunReceipt{}, fmt.Errorf("factory stage manifests duplicate path %q", path)
		}
		seenManifestPaths[key] = struct{}{}
	}

	stageAccumulator := newCanonicalProviderInputAdmissionAccumulator()
	materialCache := map[stageMaterialCoordinate]factoryDeclaredMaterial{}
	materialByPath := map[string]factoryDeclaredMaterial{}
	stages := make([]factoryLoadedStage, 0, len(wantKinds))
	var selectedEvidence []StageEvidenceBody
	var compiledReceipts [][]byte
	var graphPreflightInputs StageCompileInputs

	for index, wantKind := range wantKinds {
		requestRaw, loadedInputs, binding, err := loadStageCompileFileManifestWithAdmission(manifestPaths[index], stageAccumulator)
		if err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("load %s stage inputs: %w", wantKind, err)
		}
		header, err := decodeStageRequestHeader(requestRaw)
		if err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("decode %s stage request: %w", wantKind, err)
		}
		if header.StageKind != wantKind {
			return FactoryRunReceipt{}, fmt.Errorf("factory position %d stage_kind is %q, want %q", index, header.StageKind, wantKind)
		}
		manifest, declaredMaterials, err := factoryManifestMaterials(manifestPaths[index], binding, loadedInputs)
		if err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("bind %s stage manifest: %w", wantKind, err)
		}
		if len(manifest.PredecessorReceiptPaths) != 0 {
			return FactoryRunReceipt{}, fmt.Errorf("%s predecessor_receipt_paths must be empty; the runner owns exact in-run lineage", wantKind)
		}
		if index == 0 {
			if len(loadedInputs.EvidenceBodies) == 0 {
				return FactoryRunReceipt{}, fmt.Errorf("evidence_intake stage has no exact selected evidence bodies")
			}
			// The intake loader owns these bytes. Seal one immutable in-process
			// corpus and share it across all four compilers and the verifier; a
			// valid maximum corpus must not be cloned once per stage/loader call.
			selectedEvidence = loadedInputs.EvidenceBodies
		} else {
			if len(manifest.EvidenceBodies) != 0 || len(loadedInputs.EvidenceBodies) != 0 {
				return FactoryRunReceipt{}, fmt.Errorf("%s evidence_bodies must be empty; the runner reuses the exact intake bodies", wantKind)
			}
			loadedInputs.EvidenceBodies = selectedEvidence
		}
		if dependencies.ObserveEvidenceBodies != nil {
			dependencies.ObserveEvidenceBodies("stage:"+wantKind, loadedInputs.EvidenceBodies, retainedFactoryEvidenceCollections(stages))
		}
		if len(loadedInputs.PredecessorReceipts) != 0 {
			return FactoryRunReceipt{}, fmt.Errorf("%s has externally loaded predecessor receipt bytes", wantKind)
		}
		switch wantKind {
		case stageSemanticExtraction:
			loadedInputs.PredecessorReceipts = append([][]byte(nil), compiledReceipts[0:1]...)
		case stageGraphCompile:
			loadedInputs.PredecessorReceipts = append([][]byte(nil), compiledReceipts[1:2]...)
		case stageFullFactory:
			loadedInputs.PredecessorReceipts = append([][]byte(nil), compiledReceipts...)
		}
		loadedInputs.Materials, err = completeFactoryStageMaterials(requestRaw, declaredMaterials, materialCache)
		if err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("complete %s material roster: %w", wantKind, err)
		}
		if dependencies.ObserveMaterialBodies != nil {
			dependencies.ObserveMaterialBodies("stage:"+wantKind, loadedInputs.Materials, retainedFactoryMaterialCollections(stages))
		}
		for _, material := range declaredMaterials {
			if _, duplicate := materialCache[material.coordinate]; duplicate {
				return FactoryRunReceipt{}, fmt.Errorf("stage manifests redeclare material coordinate %s/%s/%s", material.coordinate.Role, material.coordinate.ID, material.coordinate.Version)
			}
			pathKey, keyErr := factoryPathKey(material.path)
			if keyErr != nil {
				return FactoryRunReceipt{}, keyErr
			}
			if prior, duplicate := materialByPath[pathKey]; duplicate {
				return FactoryRunReceipt{}, fmt.Errorf("stage material path %q duplicates %s/%s/%s", material.path, prior.coordinate.Role, prior.coordinate.ID, prior.coordinate.Version)
			}
			materialCache[material.coordinate] = material
			materialByPath[pathKey] = material
		}
		receiptRaw, err := CompileStageReceipt(requestRaw, loadedInputs)
		if err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("compile %s stage: %w", wantKind, err)
		}
		summary, err := ValidateStageReceipt(receiptRaw)
		if err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("validate generated %s receipt: %w", wantKind, err)
		}
		if summary.StageKind != wantKind {
			return FactoryRunReceipt{}, fmt.Errorf("generated stage receipt kind %q differs from %q", summary.StageKind, wantKind)
		}
		compiledReceipts = append(compiledReceipts, receiptRaw)
		if wantKind == stageGraphCompile {
			graphPreflightInputs = shallowFactoryStageInputs(loadedInputs)
		}
		if err := compactStageCompileInputAdmissionBinding(&binding); err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("compact %s stage admission bytes: %w", wantKind, err)
		}
		retainedInputs := loadedInputs
		retainedInputs.EvidenceBodies = nil
		retainedInputs.Materials = nil
		retainedInputs.PredecessorReceipts = nil
		stages = append(stages, factoryLoadedStage{requestRaw: requestRaw, inputs: retainedInputs, binding: binding, manifest: manifest, materials: declaredMaterials, summary: summary})
	}

	preflight, err := prepareFactoryPreflight(options.Preflight, materialByPath, stages[0], stages[2], graphPreflightInputs, selectedEvidence, dependencies.ObserveEvidenceBodies, dependencies.ObserveMaterialBodies)
	if err != nil {
		return FactoryRunReceipt{}, err
	}
	stageAccumulator.enableFactorySnapshotAliases()
	if err := authorizeFactoryPreflightSnapshotAliases(preflight, stageAccumulator); err != nil {
		return FactoryRunReceipt{}, err
	}
	var (
		observerCalled     bool
		preflightProof     providerInputAdmissionProof
		preflightResources []providerInputAdmissionResourceReceipt
	)
	preflight.inputAdmissionObserver = func(proof providerInputAdmissionProof, resources []providerInputAdmissionResourceReceipt) error {
		if observerCalled {
			return fmt.Errorf("provider verifier emitted more than one input-admission observation")
		}
		if err := validateProviderInputAdmissionProof(proof, resources); err != nil {
			return fmt.Errorf("validate verifier input-admission observation: %w", err)
		}
		observerCalled = true
		preflightProof = proof
		preflightResources = append([]providerInputAdmissionResourceReceipt(nil), resources...)
		return nil
	}
	preflight.inputAdmissionAccumulator = stageAccumulator
	preflightReceipt, err := dependencies.Verify(preflight)
	if err != nil {
		return FactoryRunReceipt{}, fmt.Errorf("verify provider documentation plan: %w", err)
	}
	if !observerCalled {
		return FactoryRunReceipt{}, fmt.Errorf("provider verifier did not expose its exact input-admission proof")
	}
	if err := validateFactoryPreflightReceipt(preflightReceipt, stages[2].summary, preflightProof, preflightResources); err != nil {
		return FactoryRunReceipt{}, err
	}

	if err := stageAccumulator.revalidatePhysicalSnapshots(); err != nil {
		return FactoryRunReceipt{}, fmt.Errorf("revalidate whole-run provider input physical snapshots: %w", err)
	}
	proof, err := stageAccumulator.seal()
	if err != nil {
		return FactoryRunReceipt{}, fmt.Errorf("seal whole-run provider input roster: %w", err)
	}
	if proof != preflightProof {
		return FactoryRunReceipt{}, fmt.Errorf("whole-run provider input proof changed after verifier observation")
	}
	orderedResources := stageAccumulator.orderedResources()
	stageRows := make([]FactoryStageRunReceipt, len(stages))
	for index := range stages {
		if err := bindAndValidateStageCompileInputAdmission(&stages[index].binding, proof, orderedResources); err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("bind %s inputs to whole-run roster: %w", stages[index].summary.StageKind, err)
		}
		stageRows[index] = FactoryStageRunReceipt{
			StageKind: stages[index].summary.StageKind, ReceiptSHA256: stages[index].summary.ReceiptSHA256,
			OutputRootSHA256:           stages[index].summary.OutputRootSHA256,
			InputResourceSetRootSHA256: stages[index].binding.ResourceSetRootSHA256,
		}
	}

	receipt := FactoryRunReceipt{
		ReceiptKind: factoryRunnerReceiptKind, ReceiptVersion: factoryRunnerReceiptVersion,
		Result: factoryRunnerResult, Scope: factoryRunnerScope, ToolIdentity: dependencies.ToolIdentity, ExecutionIdentity: executionIdentity,
		InputAdmissionProof: proof, InputResources: orderedResources, Stages: stageRows,
		PreflightReceipt: preflightReceipt,
		Completion:       FactoryCompletionClassification{Compiled: true, Verified: true, DerivationExecuted: true},
		BodyFree:         true,
	}
	sealed, err := sealFactoryRunReceipt(receipt)
	if err != nil {
		return FactoryRunReceipt{}, err
	}
	raw, err := canonicalFactoryJSON(sealed)
	if err != nil {
		return FactoryRunReceipt{}, err
	}
	bodies := make(map[string]exactEvidenceBody, len(selectedEvidence))
	for _, body := range selectedEvidence {
		bodies[sha256Hex(body.Raw)] = exactEvidenceBody{Bytes: body.Raw}
	}
	if err := validateNoEmbeddedEvidenceBodies("factory run receipt", raw, bodies, 1); err != nil {
		return FactoryRunReceipt{}, fmt.Errorf("factory receipt is not body-free: %w", err)
	}
	if err := validateFactoryRunReceipt(sealed); err != nil {
		return FactoryRunReceipt{}, err
	}
	if dependencies.BeforeFinalInputCheck != nil {
		if err := dependencies.BeforeFinalInputCheck(stageAccumulator); err != nil {
			return FactoryRunReceipt{}, fmt.Errorf("factory input completion hook: %w", err)
		}
	}
	if err := stageAccumulator.revalidatePhysicalSnapshots(); err != nil {
		return FactoryRunReceipt{}, fmt.Errorf("revalidate whole-run provider input physical snapshots at completion: %w", err)
	}
	completionProof, err := stageAccumulator.seal()
	if err != nil {
		return FactoryRunReceipt{}, fmt.Errorf("reseal whole-run provider input roster at completion: %w", err)
	}
	if completionProof != proof {
		return FactoryRunReceipt{}, fmt.Errorf("whole-run provider input proof changed before completion")
	}
	return sealed, nil
}

func completeFactoryStageMaterials(requestRaw []byte, declared []factoryDeclaredMaterial, cache map[stageMaterialCoordinate]factoryDeclaredMaterial) ([]StageMaterial, error) {
	expected, err := factoryExpectedStageMaterials(requestRaw)
	if err != nil {
		return nil, err
	}
	available := make(map[stageMaterialCoordinate]factoryDeclaredMaterial, len(cache)+len(declared))
	for coordinate, material := range cache {
		available[coordinate] = material
	}
	for _, material := range declared {
		if _, duplicate := available[material.coordinate]; duplicate {
			return nil, fmt.Errorf("material coordinate %s/%s/%s is declared more than once in the whole run", material.coordinate.Role, material.coordinate.ID, material.coordinate.Version)
		}
		available[material.coordinate] = material
	}
	header, err := decodeStageRequestHeader(requestRaw)
	if err != nil {
		return nil, err
	}
	stageValidation, err := factoryStageValidationBinding(requestRaw, header.StageKind)
	if err != nil {
		return nil, err
	}
	profileCoordinate := stageCoordinateForPin(stageValidation.Profile)
	profileMaterial, ok := available[profileCoordinate]
	if !ok {
		return nil, fmt.Errorf("stage validation profile material %s/%s/%s is absent", profileCoordinate.Role, profileCoordinate.ID, profileCoordinate.Version)
	}
	profile, err := decodeStageValidationProfile(profileMaterial.raw, header.StageKind, stageValidation.Profile)
	if err != nil {
		return nil, err
	}
	for _, binding := range profile.BoundArtifactSchemas {
		coordinate := stageMaterialCoordinate{Role: binding.SchemaRole, ID: binding.SchemaID, Version: binding.SchemaVersion}
		if prior, duplicate := expected[coordinate]; duplicate && prior != binding.SchemaRawSHA256 {
			return nil, fmt.Errorf("stage validation schema coordinate %s/%s/%s aliases two digests", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		expected[coordinate] = binding.SchemaRawSHA256
	}
	for _, material := range declared {
		if _, ok := expected[material.coordinate]; !ok {
			return nil, fmt.Errorf("stage manifest declares unbound material %s/%s/%s", material.coordinate.Role, material.coordinate.ID, material.coordinate.Version)
		}
	}
	coordinates := make([]stageMaterialCoordinate, 0, len(expected))
	for coordinate := range expected {
		coordinates = append(coordinates, coordinate)
	}
	sort.Slice(coordinates, func(i, j int) bool { return compareStageMaterialCoordinates(coordinates[i], coordinates[j]) < 0 })
	result := make([]StageMaterial, 0, len(coordinates))
	for _, coordinate := range coordinates {
		material, ok := available[coordinate]
		if !ok {
			return nil, fmt.Errorf("stage omits material %s/%s/%s and no earlier admitted material supplies it", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		if got, want := sha256Hex(material.raw), expected[coordinate]; got != want {
			return nil, fmt.Errorf("material %s/%s/%s digest %s differs from request digest %s", coordinate.Role, coordinate.ID, coordinate.Version, got, want)
		}
		result = append(result, StageMaterial{Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version, Raw: material.raw})
	}
	return result, nil
}

func factoryStageValidationBinding(requestRaw []byte, stageKind string) (stageValidationBinding, error) {
	switch stageKind {
	case stageEvidenceIntake:
		var request evidenceIntakeStageRequest
		if err := strictUnmarshal(requestRaw, &request); err != nil {
			return stageValidationBinding{}, err
		}
		return request.StageValidation, nil
	case stageSemanticExtraction:
		var request semanticExtractionStageRequest
		if err := strictUnmarshal(requestRaw, &request); err != nil {
			return stageValidationBinding{}, err
		}
		return request.StageValidation, nil
	case stageGraphCompile:
		var request graphCompileStageRequest
		if err := strictUnmarshal(requestRaw, &request); err != nil {
			return stageValidationBinding{}, err
		}
		return request.StageValidation, nil
	case stageFullFactory:
		var request fullFactoryStageRequest
		if err := strictUnmarshal(requestRaw, &request); err != nil {
			return stageValidationBinding{}, err
		}
		return request.StageValidation, nil
	default:
		return stageValidationBinding{}, fmt.Errorf("unsupported factory stage_kind %q", stageKind)
	}
}

func factoryExpectedStageMaterials(requestRaw []byte) (map[stageMaterialCoordinate]string, error) {
	header, err := decodeStageRequestHeader(requestRaw)
	if err != nil {
		return nil, err
	}
	expected := map[stageMaterialCoordinate]string{}
	add := func(coordinate stageMaterialCoordinate, digest string) error {
		if err := validateStageMaterialCoordinate(coordinate); err != nil {
			return err
		}
		if !isLowerSHA256(digest) {
			return fmt.Errorf("material %s/%s/%s has an invalid digest", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		if prior, duplicate := expected[coordinate]; duplicate && prior != digest {
			return fmt.Errorf("material coordinate %s/%s/%s aliases two digests", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		expected[coordinate] = digest
		return nil
	}
	addPin := func(pin immutableStageArtifactPin) error { return add(stageCoordinateForPin(pin), pin.RawSHA256) }
	addIdentity := func(identity stageArtifactIdentity) error {
		return add(stageCoordinateForIdentity(identity), identity.RawSHA256)
	}
	addValidation := func(binding stageValidationBinding) error {
		if err := addPin(binding.Schema); err != nil {
			return err
		}
		return addPin(binding.Profile)
	}
	switch header.StageKind {
	case stageEvidenceIntake:
		var request evidenceIntakeStageRequest
		if err := strictUnmarshal(requestRaw, &request); err != nil {
			return nil, err
		}
		if err := addValidation(request.StageValidation); err != nil {
			return nil, err
		}
		for _, pin := range []immutableStageArtifactPin{request.AuthorityPins.OODGraph, request.AuthorityPins.GrandVision, request.AuthorityPins.SourceRecord, request.AuthorityPins.ExtensionProtocol} {
			if err := addPin(pin); err != nil {
				return nil, err
			}
		}
		if err := addIdentity(request.SelectionRoster); err != nil {
			return nil, err
		}
		for _, manifest := range request.EvidenceManifests {
			if err := addIdentity(stageArtifactIdentity{Role: manifest.Role, ID: manifest.ArtifactID, Version: manifest.ArtifactVersion, RawSHA256: manifest.ArtifactRawSHA256}); err != nil {
				return nil, err
			}
		}
	case stageSemanticExtraction:
		var request semanticExtractionStageRequest
		if err := strictUnmarshal(requestRaw, &request); err != nil {
			return nil, err
		}
		if err := addValidation(request.StageValidation); err != nil {
			return nil, err
		}
		if err := addPin(request.ApplicabilityProfile); err != nil {
			return nil, err
		}
		for _, binding := range request.DerivationBindings {
			if err := addPin(binding.Extractor); err != nil {
				return nil, err
			}
			if err := addPin(binding.Schema); err != nil {
				return nil, err
			}
		}
		for _, output := range request.ArtifactOutputs {
			if err := addIdentity(stageArtifactIdentity{Role: output.Role, ID: output.ArtifactID, Version: output.ArtifactVersion, RawSHA256: output.ArtifactRawSHA256}); err != nil {
				return nil, err
			}
		}
	case stageGraphCompile:
		var request graphCompileStageRequest
		if err := strictUnmarshal(requestRaw, &request); err != nil {
			return nil, err
		}
		if err := addValidation(request.StageValidation); err != nil {
			return nil, err
		}
		for _, identity := range request.DependencyArtifacts {
			if err := addIdentity(identity); err != nil {
				return nil, err
			}
		}
		if err := addIdentity(request.Plan); err != nil {
			return nil, err
		}
	case stageFullFactory:
		var request fullFactoryStageRequest
		if err := strictUnmarshal(requestRaw, &request); err != nil {
			return nil, err
		}
		if err := addValidation(request.StageValidation); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported factory stage_kind %q", header.StageKind)
	}
	return expected, nil
}

func factoryManifestMaterials(manifestPath string, binding stageCompileInputAdmissionBinding, inputs StageCompileInputs) (stageCompileFileManifest, []factoryDeclaredMaterial, error) {
	if len(binding.Items) == 0 {
		return stageCompileFileManifest{}, nil, fmt.Errorf("stage input binding is empty")
	}
	var manifest stageCompileFileManifest
	if err := strictUnmarshal(binding.Items[0].Raw, &manifest); err != nil {
		return stageCompileFileManifest{}, nil, err
	}
	wantItems := 2 + len(manifest.PredecessorReceiptPaths) + len(manifest.Materials) + len(manifest.EvidenceBodies)
	if len(binding.Items) != wantItems || len(inputs.Materials) != len(manifest.Materials) {
		return stageCompileFileManifest{}, nil, fmt.Errorf("stage input binding item count %d does not match manifest closure %d", len(binding.Items), wantItems)
	}
	baseDir, err := filepath.Abs(filepath.Dir(manifestPath))
	if err != nil {
		return stageCompileFileManifest{}, nil, err
	}
	materialOffset := 2 + len(manifest.PredecessorReceiptPaths)
	result := make([]factoryDeclaredMaterial, len(manifest.Materials))
	for index, declared := range manifest.Materials {
		path, err := resolveRelativeStageManifestPath(baseDir, declared.Path, fmt.Sprintf("materials[%d].path", index))
		if err != nil {
			return stageCompileFileManifest{}, nil, err
		}
		loaded := inputs.Materials[index]
		coordinate := stageMaterialCoordinate{Role: loaded.Role, ID: loaded.ID, Version: loaded.Version}
		if coordinate != (stageMaterialCoordinate{Role: declared.Role, ID: declared.ID, Version: declared.Version}) {
			return stageCompileFileManifest{}, nil, fmt.Errorf("material %d loaded coordinate differs from its manifest", index)
		}
		resource := binding.Items[materialOffset+index].Resource
		if resource.ContentSHA256 != sha256Hex(loaded.Raw) || resource.ContentBytes != int64(len(loaded.Raw)) {
			return stageCompileFileManifest{}, nil, fmt.Errorf("material %d is not exact-bound to its stage input receipt", index)
		}
		result[index] = factoryDeclaredMaterial{coordinate: coordinate, path: path, raw: loaded.Raw, resource: resource}
	}
	return manifest, result, nil
}

func prepareFactoryPreflight(options Options, materialByPath map[string]factoryDeclaredMaterial, intake, graph factoryLoadedStage, graphPreflightInputs StageCompileInputs, sharedEvidence []StageEvidenceBody, evidenceObserver func(string, []StageEvidenceBody, int), materialObserver func(string, []StageMaterial, int)) (Options, error) {
	if strings.TrimSpace(options.GraphCompileInputManifestPath) != "" || len(options.graphCompileRequestRaw) != 0 || len(options.graphCompileInputs.Materials) != 0 || len(options.graphCompileInputs.PredecessorReceipts) != 0 || len(options.graphCompileInputs.EvidenceBodies) != 0 || options.graphCompileSelectionLoader != nil || options.inputAdmissionObserver != nil || options.inputAdmissionAfterOpenStat != nil || options.inputAdmissionAccumulator != nil || options.inputAdmissionBeforeFinish != nil {
		return Options{}, fmt.Errorf("factory preflight must not supply an independent graph_compile selection or input observer")
	}
	var intakeRequest evidenceIntakeStageRequest
	if err := strictUnmarshal(intake.requestRaw, &intakeRequest); err != nil {
		return Options{}, fmt.Errorf("decode exact evidence_intake request for preflight binding: %w", err)
	}
	var graphRequestBinding graphCompileStageRequest
	if err := strictUnmarshal(graph.requestRaw, &graphRequestBinding); err != nil {
		return Options{}, fmt.Errorf("decode exact graph_compile request for preflight binding: %w", err)
	}
	seen := map[string]string{}
	bindOne := func(label, path string, want *stageMaterialCoordinate) (factoryDeclaredMaterial, error) {
		key, err := factoryPathKey(path)
		if err != nil {
			return factoryDeclaredMaterial{}, fmt.Errorf("%s: %w", label, err)
		}
		if prior, duplicate := seen[key]; duplicate {
			return factoryDeclaredMaterial{}, fmt.Errorf("%s path duplicates %s", label, prior)
		}
		material, ok := materialByPath[key]
		if !ok {
			return factoryDeclaredMaterial{}, fmt.Errorf("%s path %q is not an admitted stage material", label, path)
		}
		if want != nil && material.coordinate != *want {
			return factoryDeclaredMaterial{}, fmt.Errorf("%s path selects material %s/%s/%s, want exact intake coordinate %s/%s/%s", label, material.coordinate.Role, material.coordinate.ID, material.coordinate.Version, want.Role, want.ID, want.Version)
		}
		seen[key] = label
		return material, nil
	}
	authorities := []struct {
		label    string
		path     string
		expected string
		pin      immutableStageArtifactPin
	}{
		{"OOD authority", options.OODSpecPath, options.ExpectedOODSpecSHA256, intakeRequest.AuthorityPins.OODGraph},
		{"Grand Vision authority", options.GrandVisionPath, options.ExpectedGrandVisionSHA256, intakeRequest.AuthorityPins.GrandVision},
		{"Source Record authority", options.SourceRecordSpecPath, options.ExpectedSourceRecordSHA256, intakeRequest.AuthorityPins.SourceRecord},
	}
	for _, authority := range authorities {
		coordinate := stageCoordinateForPin(authority.pin)
		material, err := bindOne(authority.label, authority.path, &coordinate)
		if err != nil {
			return Options{}, err
		}
		if material.resource.ContentSHA256 != authority.expected || material.resource.ContentSHA256 != authority.pin.RawSHA256 {
			return Options{}, fmt.Errorf("%s admitted digest %s differs from independently expected pin %s or intake pin %s", authority.label, material.resource.ContentSHA256, authority.expected, authority.pin.RawSHA256)
		}
	}
	canonicalizeExactStageRoster := func(label string, paths []string, expected map[stageMaterialCoordinate]string) ([]string, error) {
		type boundPath struct {
			path     string
			material factoryDeclaredMaterial
		}
		if len(paths) != len(expected) {
			return nil, fmt.Errorf("%s path count %d differs from exact intake roster %d", label, len(paths), len(expected))
		}
		remaining := make(map[stageMaterialCoordinate]string, len(expected))
		for coordinate, digest := range expected {
			remaining[coordinate] = digest
		}
		bound := make([]boundPath, len(paths))
		for index, path := range paths {
			material, err := bindOne(fmt.Sprintf("%s[%d]", label, index), path, nil)
			if err != nil {
				return nil, err
			}
			digest, ok := remaining[material.coordinate]
			if !ok {
				return nil, fmt.Errorf("%s[%d] selects material %s/%s/%s outside the exact intake roster", label, index, material.coordinate.Role, material.coordinate.ID, material.coordinate.Version)
			}
			if material.resource.ContentSHA256 != digest {
				return nil, fmt.Errorf("%s[%d] material digest %s differs from exact intake digest %s", label, index, material.resource.ContentSHA256, digest)
			}
			delete(remaining, material.coordinate)
			bound[index] = boundPath{path: path, material: material}
		}
		if len(remaining) != 0 {
			return nil, fmt.Errorf("%s paths omit %d exact intake materials", label, len(remaining))
		}
		sort.Slice(bound, func(i, j int) bool {
			return bound[i].material.resource.ResourceReceiptSHA256 < bound[j].material.resource.ResourceReceiptSHA256
		})
		orderedPaths := make([]string, len(bound))
		for index := range bound {
			orderedPaths[index] = bound[index].path
		}
		return orderedPaths, nil
	}
	intakeEvidence := make(map[stageMaterialCoordinate]string, len(intakeRequest.EvidenceManifests))
	for _, manifest := range intakeRequest.EvidenceManifests {
		coordinate := stageMaterialCoordinate{Role: manifest.Role, ID: manifest.ArtifactID, Version: manifest.ArtifactVersion}
		if prior, duplicate := intakeEvidence[coordinate]; duplicate && prior != manifest.ArtifactRawSHA256 {
			return Options{}, fmt.Errorf("evidence_intake aliases manifest coordinate %s/%s/%s", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		intakeEvidence[coordinate] = manifest.ArtifactRawSHA256
	}
	var err error
	options.EvidenceManifestPath, err = canonicalizeExactStageRoster("evidence_manifest", options.EvidenceManifestPath, intakeEvidence)
	if err != nil {
		return Options{}, err
	}

	graphDependencies := make(map[stageMaterialCoordinate]string, len(graphRequestBinding.DependencyArtifacts))
	for _, dependency := range graphRequestBinding.DependencyArtifacts {
		coordinate := stageCoordinateForIdentity(dependency)
		if prior, duplicate := graphDependencies[coordinate]; duplicate && prior != dependency.RawSHA256 {
			return Options{}, fmt.Errorf("graph_compile aliases dependency coordinate %s/%s/%s", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		graphDependencies[coordinate] = dependency.RawSHA256
	}
	stageMaterialByCoordinate := make(map[stageMaterialCoordinate]factoryDeclaredMaterial, len(materialByPath))
	for _, pathKey := range sortedProviderStringMapKeys(materialByPath) {
		material := materialByPath[pathKey]
		if _, duplicate := stageMaterialByCoordinate[material.coordinate]; duplicate {
			return Options{}, fmt.Errorf("factory stage material coordinate %s/%s/%s has more than one physical path", material.coordinate.Role, material.coordinate.ID, material.coordinate.Version)
		}
		stageMaterialByCoordinate[material.coordinate] = material
	}
	for _, coordinate := range sortedStageMaterialCoordinateKeys(graphDependencies) {
		material, exists := stageMaterialByCoordinate[coordinate]
		if !exists {
			return Options{}, fmt.Errorf("graph_compile direct dependency %s/%s/%s has no admitted stage material", coordinate.Role, coordinate.ID, coordinate.Version)
		}
		if material.resource.ContentSHA256 != graphDependencies[coordinate] {
			return Options{}, fmt.Errorf("graph_compile direct dependency %s/%s/%s stage digest %s differs from request digest %s", coordinate.Role, coordinate.ID, coordinate.Version, material.resource.ContentSHA256, graphDependencies[coordinate])
		}
	}
	type dependencyPathBinding struct {
		path         string
		pathKey      string
		stageBacked  bool
		stageReceipt string
		coordinate   stageMaterialCoordinate
	}
	dependencyBindings := make([]dependencyPathBinding, len(options.DependencyArtifactPath))
	providedDirect := make(map[stageMaterialCoordinate]struct{}, len(graphDependencies))
	for index, path := range options.DependencyArtifactPath {
		key, keyErr := factoryPathKey(path)
		if keyErr != nil {
			return Options{}, fmt.Errorf("dependency_artifact[%d]: %w", index, keyErr)
		}
		if prior, duplicate := seen[key]; duplicate {
			return Options{}, fmt.Errorf("dependency_artifact[%d] path duplicates %s", index, prior)
		}
		seen[key] = fmt.Sprintf("dependency_artifact[%d]", index)
		binding := dependencyPathBinding{path: path, pathKey: key}
		if material, stageBacked := materialByPath[key]; stageBacked {
			binding.stageBacked = true
			binding.stageReceipt = material.resource.ResourceReceiptSHA256
			binding.coordinate = material.coordinate
			if wantDigest, direct := graphDependencies[material.coordinate]; direct {
				if material.resource.ContentSHA256 != wantDigest {
					return Options{}, fmt.Errorf("dependency_artifact[%d] direct stage material digest %s differs from graph_compile digest %s", index, material.resource.ContentSHA256, wantDigest)
				}
				providedDirect[material.coordinate] = struct{}{}
			}
		}
		dependencyBindings[index] = binding
	}
	for _, coordinate := range sortedStageMaterialCoordinateKeys(graphDependencies) {
		if _, supplied := providedDirect[coordinate]; !supplied {
			return Options{}, fmt.Errorf("dependency_artifact paths omit exact graph_compile direct stage material %s/%s/%s", coordinate.Role, coordinate.ID, coordinate.Version)
		}
	}
	sort.Slice(dependencyBindings, func(i, j int) bool {
		left, right := dependencyBindings[i], dependencyBindings[j]
		if left.stageBacked != right.stageBacked {
			return left.stageBacked
		}
		if left.stageBacked && left.stageReceipt != right.stageReceipt {
			return left.stageReceipt < right.stageReceipt
		}
		return left.pathKey < right.pathKey
	})
	options.DependencyArtifactPath = make([]string, len(dependencyBindings))
	for index, binding := range dependencyBindings {
		options.DependencyArtifactPath[index] = binding.path
	}

	graphInputs := shallowFactoryStageInputs(graphPreflightInputs)
	options.graphCompileSelectionLoader = func() ([]byte, StageCompileInputs, error) {
		inputs := shallowFactoryStageInputs(graphInputs)
		inputs.EvidenceBodies = sharedEvidence
		if evidenceObserver != nil {
			evidenceObserver("verifier:graph_compile_loader", inputs.EvidenceBodies, 0)
		}
		if materialObserver != nil {
			materialObserver("verifier:graph_compile_loader", inputs.Materials, 0)
		}
		return graph.requestRaw, inputs, nil
	}
	return options, nil
}

func retainedFactoryEvidenceCollections(stages []factoryLoadedStage) int {
	count := 0
	for _, stage := range stages {
		if len(stage.inputs.EvidenceBodies) != 0 {
			count++
		}
	}
	return count
}

func retainedFactoryMaterialCollections(stages []factoryLoadedStage) int {
	count := 0
	for _, stage := range stages {
		if len(stage.inputs.Materials) != 0 {
			count++
		}
	}
	return count
}

func authorizeFactoryPreflightSnapshotAliases(options Options, accumulator *providerInputAdmissionAccumulator) error {
	aliases := []struct {
		label        string
		path         string
		resourceKind string
	}{
		{label: "OOD authority", path: options.OODSpecPath, resourceKind: providerInputAdmissionResourceKindAuthority},
		{label: "Grand Vision authority", path: options.GrandVisionPath, resourceKind: providerInputAdmissionResourceKindAuthority},
		{label: "Source Record authority", path: options.SourceRecordSpecPath, resourceKind: providerInputAdmissionResourceKindAuthority},
	}
	for index, path := range options.EvidenceManifestPath {
		aliases = append(aliases, struct {
			label        string
			path         string
			resourceKind string
		}{label: fmt.Sprintf("evidence manifest[%d]", index), path: path, resourceKind: providerInputAdmissionResourceKindManifest})
	}
	for index, path := range options.DependencyArtifactPath {
		aliases = append(aliases, struct {
			label        string
			path         string
			resourceKind string
		}{label: fmt.Sprintf("dependency artifact[%d]", index), path: path, resourceKind: providerInputAdmissionResourceKindArtifact})
	}
	for _, alias := range aliases {
		key, err := factoryPathKey(alias.path)
		if err != nil {
			return fmt.Errorf("inspect exact factory preflight snapshot alias: %w", err)
		}
		if accumulator.physicalSnapshots[key] == nil {
			// A recursively required auxiliary dependency may not be a stage
			// material. Verify admits that fresh physical input exactly once.
			continue
		}
		if err := accumulator.authorizeFactorySnapshotAlias(alias.path, alias.label, alias.resourceKind); err != nil {
			return fmt.Errorf("authorize exact factory preflight snapshot alias: %w", err)
		}
	}
	return nil
}

func validateFactoryPreflightReceipt(receipt Receipt, graph StageReceiptSummary, proof providerInputAdmissionProof, resources []providerInputAdmissionResourceReceipt) error {
	if err := validateReceiptIdentity(receipt); err != nil {
		return fmt.Errorf("validate executable preflight receipt identity: %w", err)
	}
	if receipt.Result != "pass" {
		return fmt.Errorf("executable preflight result %q is not pass", receipt.Result)
	}
	if receipt.GraphCompileStageReceiptSHA256 != graph.ReceiptSHA256 {
		return fmt.Errorf("executable preflight graph_compile receipt %s differs from the factory stage receipt %s", receipt.GraphCompileStageReceiptSHA256, graph.ReceiptSHA256)
	}
	if receipt.GraphCompileStageOutputRootSHA256 != graph.OutputRootSHA256 {
		return fmt.Errorf("executable preflight graph_compile output root %s differs from the factory stage output root %s", receipt.GraphCompileStageOutputRootSHA256, graph.OutputRootSHA256)
	}
	if receipt.ProviderInputAdmissionProofSHA256 != proof.ProofSHA256 || receipt.ProviderInputAdmissionResourceSetRootSHA256 != proof.ResourceSetRootSHA256 || receipt.ProviderInputAdmissionLimits != proof.Limits || receipt.ProviderInputAdmissionActuals != proof.Actuals {
		return fmt.Errorf("executable preflight receipt does not bind its observed exact input-admission proof")
	}
	if err := validateProviderInputAdmissionProof(proof, resources); err != nil {
		return fmt.Errorf("executable preflight observed input-admission proof: %w", err)
	}
	wantEvidence := factoryObservedResourceHashes(resources, providerInputAdmissionResourceKindManifest)
	wantDependencies := factoryObservedResourceHashes(resources, providerInputAdmissionResourceKindArtifact)
	gotEvidence := append([]string(nil), receipt.EvidenceManifestSHA256...)
	gotDependencies := append([]string(nil), receipt.DependencyArtifactSHA256...)
	sort.Strings(gotEvidence)
	sort.Strings(gotDependencies)
	if !equalFactoryStrings(gotEvidence, wantEvidence) || !equalFactoryStrings(gotDependencies, wantDependencies) || receipt.DependencyArtifactCount != len(wantDependencies) || len(gotEvidence) != int(proof.Actuals.EvidenceManifestCount) || len(gotDependencies) != int(proof.Actuals.DependencyArtifactCount) {
		return fmt.Errorf("executable preflight receipt input hashes differ from the exact observed logical input resources")
	}
	if !receipt.AuthorityHashesMatchExpectedPins || receipt.AuthoritySelectionCanonicalized || !receipt.BodyFreeSchemaBindingVerified || receipt.BodyFreeSchemaAuthorityVerified || receipt.CredentialMaterialDetected || receipt.OrganizationIDPresentInPlan || receipt.BinaryFloatAuthorityPresent || receipt.RawValueEmbeddingAllowed || receipt.CanonicalAdmissionAuthorized {
		return fmt.Errorf("executable preflight receipt weakens the candidate-only body-free safety posture")
	}
	return nil
}

func factoryObservedResourceHashes(resources []providerInputAdmissionResourceReceipt, resourceKind string) []string {
	hashes := make([]string, 0)
	for _, resource := range resources {
		if resource.ResourceKind == resourceKind {
			hashes = append(hashes, resource.ContentSHA256)
		}
	}
	sort.Strings(hashes)
	return hashes
}

func sealFactoryRunReceipt(receipt FactoryRunReceipt) (FactoryRunReceipt, error) {
	receipt.PortableReceiptSHA256 = ""
	receipt.ValidationIdentity = FactoryValidationIdentity{}
	receipt.ReceiptSHA256 = ""
	portableIdentity, err := canonicalFactoryPortableReceiptIdentity(receipt)
	if err != nil {
		return FactoryRunReceipt{}, err
	}
	receipt.PortableReceiptSHA256 = sha256Hex(portableIdentity)
	validationIdentity, err := newFactoryValidationIdentity(receipt)
	if err != nil {
		return FactoryRunReceipt{}, err
	}
	receipt.ValidationIdentity = validationIdentity
	identity, err := canonicalFactoryReceiptIdentity(receipt)
	if err != nil {
		return FactoryRunReceipt{}, err
	}
	receipt.ReceiptSHA256 = sha256Hex(identity)
	return receipt, nil
}

func validateFactoryRunReceipt(receipt FactoryRunReceipt) error {
	if receipt.ReceiptKind != factoryRunnerReceiptKind || receipt.ReceiptVersion != factoryRunnerReceiptVersion || receipt.Result != factoryRunnerResult || receipt.Scope != factoryRunnerScope || !receipt.BodyFree || !isLowerSHA256(receipt.PortableReceiptSHA256) || !isLowerSHA256(receipt.ReceiptSHA256) {
		return fmt.Errorf("factory run receipt identity or body-free posture is incomplete")
	}
	if err := validateFactoryToolIdentity(receipt.ToolIdentity); err != nil {
		return err
	}
	if err := validateFactoryExecutionIdentity(receipt.ExecutionIdentity, receipt.ToolIdentity); err != nil {
		return err
	}
	if err := validateProviderInputAdmissionProof(receipt.InputAdmissionProof, receipt.InputResources); err != nil {
		return fmt.Errorf("factory input-admission proof: %w", err)
	}
	if len(receipt.Stages) != 4 {
		return fmt.Errorf("factory receipt has %d stages, want 4", len(receipt.Stages))
	}
	wantKinds := []string{stageEvidenceIntake, stageSemanticExtraction, stageGraphCompile, stageFullFactory}
	for index, stage := range receipt.Stages {
		if stage.StageKind != wantKinds[index] || !isLowerSHA256(stage.ReceiptSHA256) || !isLowerSHA256(stage.OutputRootSHA256) || !isLowerSHA256(stage.InputResourceSetRootSHA256) {
			return fmt.Errorf("factory stage %d receipt identity is invalid", index)
		}
	}
	if err := validateReceiptIdentity(receipt.PreflightReceipt); err != nil {
		return fmt.Errorf("factory preflight receipt: %w", err)
	}
	graph := receipt.Stages[2]
	if receipt.PreflightReceipt.GraphCompileStageReceiptSHA256 != graph.ReceiptSHA256 || receipt.PreflightReceipt.GraphCompileStageOutputRootSHA256 != graph.OutputRootSHA256 {
		return fmt.Errorf("factory preflight receipt differs from the graph stage receipt")
	}
	completion := receipt.Completion
	if !completion.Compiled || !completion.Verified || !completion.DerivationExecuted || completion.GraphAdmittable || completion.Admitted || completion.CircuitAdmittable || completion.CircuitAdmitted || completion.Configured || completion.CredentialProvisioned || completion.Deployed || completion.LiveTested || completion.TwoTenantProven || completion.SourceSubstitutionProven || completion.AuthoritySelected || completion.AdmissionAuthorized || completion.FactoryComplete {
		return fmt.Errorf("factory receipt overclaims completion state")
	}
	portableIdentity, err := canonicalFactoryPortableReceiptIdentity(receipt)
	if err != nil {
		return err
	}
	if sha256Hex(portableIdentity) != receipt.PortableReceiptSHA256 {
		return fmt.Errorf("factory portable receipt digest is invalid")
	}
	expectedValidationIdentity, err := newFactoryValidationIdentity(receipt)
	if err != nil {
		return err
	}
	if expectedValidationIdentity != receipt.ValidationIdentity {
		return fmt.Errorf("factory validation identity or report digest is invalid")
	}
	identity, err := canonicalFactoryReceiptIdentity(receipt)
	if err != nil {
		return err
	}
	if sha256Hex(identity) != receipt.ReceiptSHA256 {
		return fmt.Errorf("factory receipt self digest is invalid")
	}
	return nil
}

func canonicalFactoryReceiptIdentity(receipt FactoryRunReceipt) ([]byte, error) {
	receipt.ReceiptSHA256 = ""
	return canonicalFactoryJSON(receipt)
}

func canonicalFactoryPortableReceiptIdentity(receipt FactoryRunReceipt) ([]byte, error) {
	receipt.ExecutionIdentity = FactoryExecutionIdentity{}
	receipt.ValidationIdentity = FactoryValidationIdentity{}
	receipt.PortableReceiptSHA256 = ""
	receipt.ReceiptSHA256 = ""
	return canonicalFactoryJSON(receipt)
}

func newFactoryValidationIdentity(receipt FactoryRunReceipt) (FactoryValidationIdentity, error) {
	reportSHA256, err := factoryValidationReportSHA256(receipt)
	if err != nil {
		return FactoryValidationIdentity{}, err
	}
	return sealFactoryValidationIdentity(FactoryValidationIdentity{
		ProfileID:                factoryValidationProfileID,
		ProfileVersion:           factoryValidationVersion,
		Result:                   factoryValidationResult,
		ValidationContractSHA256: sha256Hex([]byte(factoryValidationContract)),
		PortableReceiptSHA256:    receipt.PortableReceiptSHA256,
		ToolBuildIdentitySHA256:  receipt.ToolIdentity.BuildIdentitySHA256,
		ExecutionIdentitySHA256:  receipt.ExecutionIdentity.ExecutionIdentitySHA256,
		ValidationReportSHA256:   reportSHA256,
	})
}

func factoryValidationReportSHA256(receipt FactoryRunReceipt) (string, error) {
	report := factoryValidationReportForReceipt(receipt)
	raw, err := canonicalFactoryJSON(report)
	if err != nil {
		return "", err
	}
	return sha256Hex(raw), nil
}

func factoryValidationReportForReceipt(receipt FactoryRunReceipt) factoryValidationReport {
	stages := make([]string, len(receipt.Stages))
	for index, stage := range receipt.Stages {
		stages[index] = stage.ReceiptSHA256
	}
	return factoryValidationReport{
		Result:                    factoryValidationResult,
		PortableReceiptSHA256:     receipt.PortableReceiptSHA256,
		ToolBuildIdentitySHA256:   receipt.ToolIdentity.BuildIdentitySHA256,
		ExecutionIdentitySHA256:   receipt.ExecutionIdentity.ExecutionIdentitySHA256,
		InputAdmissionProofSHA256: receipt.InputAdmissionProof.ProofSHA256,
		StageReceiptSHA256:        stages,
		PreflightReceiptSHA256:    receipt.PreflightReceipt.ReceiptSHA256,
		CompletionClassification:  receipt.Completion,
	}
}

func sealFactoryValidationIdentity(identity FactoryValidationIdentity) (FactoryValidationIdentity, error) {
	identity.ValidationIdentitySHA256 = ""
	if identity.ProfileID != factoryValidationProfileID || identity.ProfileVersion != factoryValidationVersion || identity.Result != factoryValidationResult || identity.ValidationContractSHA256 != sha256Hex([]byte(factoryValidationContract)) {
		return FactoryValidationIdentity{}, fmt.Errorf("factory validation profile identity is invalid")
	}
	bindings := []struct {
		name  string
		value string
	}{
		{name: "portable receipt", value: identity.PortableReceiptSHA256},
		{name: "tool build", value: identity.ToolBuildIdentitySHA256},
		{name: "execution", value: identity.ExecutionIdentitySHA256},
		{name: "validation report", value: identity.ValidationReportSHA256},
	}
	for _, binding := range bindings {
		if !isLowerSHA256(binding.value) {
			return FactoryValidationIdentity{}, fmt.Errorf("factory %s validation binding is invalid", binding.name)
		}
	}
	raw, err := canonicalFactoryJSON(identity)
	if err != nil {
		return FactoryValidationIdentity{}, err
	}
	identity.ValidationIdentitySHA256 = sha256Hex(raw)
	return identity, nil
}

func canonicalFactoryJSON(value interface{}) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return canonicalizeCandidateJSON(raw)
}

func currentFactoryRuntimeIdentities() (FactoryToolIdentity, FactoryExecutionIdentity, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return FactoryToolIdentity{}, FactoryExecutionIdentity{}, fmt.Errorf("factory runner has no embedded Go build identity")
	}
	pins := currentFactoryReleaseBuildPins()
	toolIdentity, err := factoryToolIdentityFromBuildInfoWithPins(info, runtime.GOOS, runtime.GOARCH, pins)
	if err != nil {
		return FactoryToolIdentity{}, FactoryExecutionIdentity{}, err
	}
	executableSHA256, executableByteCount, err := currentFactoryExecutableIdentity()
	if err != nil {
		return FactoryToolIdentity{}, FactoryExecutionIdentity{}, err
	}
	executionIdentity, err := factoryExecutionIdentityFromBuildInfoWithPins(info, runtime.GOOS, runtime.GOARCH, toolIdentity, executableSHA256, executableByteCount, pins)
	if err != nil {
		return FactoryToolIdentity{}, FactoryExecutionIdentity{}, err
	}
	return toolIdentity, executionIdentity, nil
}

func factoryToolIdentityFromBuildInfo(info *debug.BuildInfo, nativeOS, nativeArch string) (FactoryToolIdentity, error) {
	return factoryToolIdentityFromBuildInfoWithPins(info, nativeOS, nativeArch, currentFactoryReleaseBuildPins())
}

func factoryToolIdentityFromBuildInfoWithPins(info *debug.BuildInfo, nativeOS, nativeArch string, pins factoryReleaseBuildPins) (FactoryToolIdentity, error) {
	if info == nil {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner build metadata is nil")
	}
	settings := make(map[string]string, len(info.Settings))
	for _, setting := range info.Settings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return FactoryToolIdentity{}, fmt.Errorf("factory runner build identity duplicates setting %q", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	modifiedValue, hasModified := settings["vcs.modified"]
	if !hasModified || (modifiedValue != "true" && modifiedValue != "false") {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner build identity omits an exact vcs.modified setting")
	}
	if settings["GOOS"] != nativeOS || settings["GOARCH"] != nativeArch || settings["-compiler"] != "gc" || settings["-buildmode"] != "exe" || settings["CGO_ENABLED"] != "0" {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner requires the native pure-Go gc/exe build profile")
	}
	metadata, err := canonicalFactoryBuildMetadata(info)
	if err != nil {
		return FactoryToolIdentity{}, err
	}
	moduleGraphRaw, err := canonicalFactoryJSON(factoryModuleGraph{Main: metadata.Main, Dependencies: metadata.Dependencies})
	if err != nil {
		return FactoryToolIdentity{}, err
	}
	buildRecipeRaw, err := canonicalFactoryJSON(metadata)
	if err != nil {
		return FactoryToolIdentity{}, err
	}
	identity := FactoryToolIdentity{
		CommandPath: info.Path, ModulePath: info.Main.Path, ModuleVersion: info.Main.Version, GoVersion: info.GoVersion,
		VCS: settings["vcs"], VCSRevision: settings["vcs.revision"], VCSTime: settings["vcs.time"], VCSModified: modifiedValue == "true",
		BuildTags: settings["-tags"], ModuleGraphSHA256: sha256Hex(moduleGraphRaw), BuildRecipeSHA256: sha256Hex(buildRecipeRaw), SourceRosterSHA256: pins.SourceRosterSHA256,
		RunnerContractSHA256: sha256Hex([]byte(factoryRunnerContract)), ReproducibleSourceTree: modifiedValue == "false",
	}
	return sealFactoryToolIdentity(identity)
}

func factoryExecutionIdentityFromBuildInfo(info *debug.BuildInfo, nativeOS, nativeArch string, toolIdentity FactoryToolIdentity, executableSHA256 string, executableByteCount int64) (FactoryExecutionIdentity, error) {
	return factoryExecutionIdentityFromBuildInfoWithPins(info, nativeOS, nativeArch, toolIdentity, executableSHA256, executableByteCount, currentFactoryReleaseBuildPins())
}

func factoryExecutionIdentityFromBuildInfoWithPins(info *debug.BuildInfo, nativeOS, nativeArch string, toolIdentity FactoryToolIdentity, executableSHA256 string, executableByteCount int64, pins factoryReleaseBuildPins) (FactoryExecutionIdentity, error) {
	if info == nil {
		return FactoryExecutionIdentity{}, fmt.Errorf("factory runner execution build metadata is nil")
	}
	settings, err := exactFactoryBuildSettings(info.Settings)
	if err != nil {
		return FactoryExecutionIdentity{}, err
	}
	settingsRaw, err := canonicalFactoryJSON(settings)
	if err != nil {
		return FactoryExecutionIdentity{}, err
	}
	identity := FactoryExecutionIdentity{
		PortableBuildIdentitySHA256: toolIdentity.BuildIdentitySHA256,
		BuildMetadataSource:         factoryBuildMetadataSource,
		ExecutableMeasurementScope:  factoryExecutableScope,
		TargetOS:                    nativeOS,
		TargetArch:                  nativeArch,
		BuildSettings:               settings,
		BuildSettingsSHA256:         sha256Hex(settingsRaw),
		ExecutableSHA256:            executableSHA256,
		ExecutableByteCount:         executableByteCount,
		GoExecutableSHA256:          pins.GoExecutableSHA256,
		GitExecutableSHA256:         pins.GitExecutableSHA256,
		GoToolchainSHA256:           pins.GoToolchainSHA256,
		GitToolchainSHA256:          pins.GitToolchainSHA256,
		GoToolchainFileCount:        pins.GoToolchainFiles,
		GoToolchainByteCount:        pins.GoToolchainBytes,
		GitToolchainFileCount:       pins.GitToolchainFiles,
		GitToolchainByteCount:       pins.GitToolchainBytes,
	}
	return sealFactoryExecutionIdentity(identity, toolIdentity)
}

func exactFactoryBuildSettings(settings []debug.BuildSetting) ([]factoryBuildSetting, error) {
	result := make([]factoryBuildSetting, len(settings))
	seen := make(map[string]struct{}, len(settings))
	for index, setting := range settings {
		if _, duplicate := seen[setting.Key]; duplicate {
			return nil, fmt.Errorf("factory runner execution identity duplicates setting %q", setting.Key)
		}
		if !factoryExecutionBuildSettingAllowed(setting.Key) {
			return nil, fmt.Errorf("factory runner execution profile contains unsupported setting %q", setting.Key)
		}
		seen[setting.Key] = struct{}{}
		result[index] = factoryBuildSetting{Key: setting.Key, Value: setting.Value}
	}
	sort.Slice(result, func(i, j int) bool {
		return factoryBuildSettingLess(result[i], result[j])
	})
	return result, nil
}

func factoryBuildSettingLess(left, right factoryBuildSetting) bool {
	if left.Key != right.Key {
		return left.Key < right.Key
	}
	return left.Value < right.Value
}

func factoryExecutionBuildSettingAllowed(key string) bool {
	switch key {
	case "-buildmode", "-compiler", "-ldflags", "-tags", "-trimpath", "CGO_ENABLED", "GOOS", "GOARCH",
		"GO386", "GOAMD64", "GOARM", "GOARM64", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOWASM",
		"vcs", "vcs.revision", "vcs.time", "vcs.modified", "DefaultGODEBUG":
		return true
	default:
		return false
	}
}

func sealFactoryExecutionIdentity(identity FactoryExecutionIdentity, toolIdentity FactoryToolIdentity) (FactoryExecutionIdentity, error) {
	identity.ExecutionIdentitySHA256 = ""
	if identity.PortableBuildIdentitySHA256 != toolIdentity.BuildIdentitySHA256 || strings.TrimSpace(identity.TargetOS) == "" || strings.TrimSpace(identity.TargetArch) == "" {
		return FactoryExecutionIdentity{}, fmt.Errorf("factory execution identity is not bound to the portable tool build")
	}
	if identity.BuildMetadataSource != factoryBuildMetadataSource || identity.ExecutableMeasurementScope != factoryExecutableScope {
		return FactoryExecutionIdentity{}, fmt.Errorf("factory execution measurement source or scope is invalid")
	}
	settings := make(map[string]string, len(identity.BuildSettings))
	for _, setting := range identity.BuildSettings {
		if _, duplicate := settings[setting.Key]; duplicate {
			return FactoryExecutionIdentity{}, fmt.Errorf("factory execution identity duplicates setting %q", setting.Key)
		}
		if !factoryExecutionBuildSettingAllowed(setting.Key) {
			return FactoryExecutionIdentity{}, fmt.Errorf("factory execution identity contains unsupported setting %q", setting.Key)
		}
		settings[setting.Key] = setting.Value
	}
	if !sort.SliceIsSorted(identity.BuildSettings, func(i, j int) bool {
		return factoryBuildSettingLess(identity.BuildSettings[i], identity.BuildSettings[j])
	}) {
		return FactoryExecutionIdentity{}, fmt.Errorf("factory execution build settings are not in canonical order")
	}
	if settings["GOOS"] != identity.TargetOS || settings["GOARCH"] != identity.TargetArch || settings["-compiler"] != "gc" || settings["-buildmode"] != "exe" || settings["CGO_ENABLED"] != "0" || settings["-tags"] != factoryReleaseBuildTag || settings["-trimpath"] != "true" {
		return FactoryExecutionIdentity{}, fmt.Errorf("factory execution identity does not satisfy the exact native pure-Go release build profile")
	}
	if settings["-tags"] != toolIdentity.BuildTags {
		return FactoryExecutionIdentity{}, fmt.Errorf("factory execution build tags contradict the portable tool identity")
	}
	if settings["vcs"] != toolIdentity.VCS || settings["vcs.revision"] != toolIdentity.VCSRevision || settings["vcs.time"] != toolIdentity.VCSTime || settings["vcs.modified"] != "false" {
		return FactoryExecutionIdentity{}, fmt.Errorf("factory execution identity differs from the exact clean source revision")
	}
	settingsRaw, err := canonicalFactoryJSON(identity.BuildSettings)
	if err != nil {
		return FactoryExecutionIdentity{}, err
	}
	if sha256Hex(settingsRaw) != identity.BuildSettingsSHA256 {
		return FactoryExecutionIdentity{}, fmt.Errorf("factory execution build-settings digest is invalid")
	}
	if !isLowerSHA256(identity.ExecutableSHA256) || identity.ExecutableByteCount <= 0 || identity.ExecutableByteCount > maxFactoryExecutableBytes || !isLowerSHA256(identity.GoExecutableSHA256) || !isLowerSHA256(identity.GitExecutableSHA256) || !isLowerSHA256(identity.GoToolchainSHA256) || !isLowerSHA256(identity.GitToolchainSHA256) || identity.GoToolchainFileCount <= 0 || identity.GoToolchainByteCount <= 0 || identity.GitToolchainFileCount <= 0 || identity.GitToolchainByteCount <= 0 {
		return FactoryExecutionIdentity{}, fmt.Errorf("factory execution executable identity is invalid")
	}
	raw, err := canonicalFactoryJSON(identity)
	if err != nil {
		return FactoryExecutionIdentity{}, err
	}
	identity.ExecutionIdentitySHA256 = sha256Hex(raw)
	return identity, nil
}

func validateFactoryExecutionIdentity(identity FactoryExecutionIdentity, toolIdentity FactoryToolIdentity) error {
	sealed, err := sealFactoryExecutionIdentity(identity, toolIdentity)
	if err != nil {
		return err
	}
	actual, err := canonicalFactoryJSON(identity)
	if err != nil {
		return err
	}
	expected, err := canonicalFactoryJSON(sealed)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return fmt.Errorf("factory execution identity digest is invalid")
	}
	return nil
}

func currentFactoryExecutableIdentity() (string, int64, error) {
	return factoryExecutableIdentityWithOperations(factoryExecutableIdentityOperations{
		executable:   os.Executable,
		initialLstat: os.Lstat,
		initialOpen:  openProviderInputPathNoFollow,
		open:         openProviderInputPathNoFollow,
		finalLstat:   os.Lstat,
		finalOpen:    openProviderInputPathNoFollow,
	})
}

type factoryExecutableIdentityOperations struct {
	executable   func() (string, error)
	initialLstat func(string) (os.FileInfo, error)
	initialOpen  func(string) (*os.File, error)
	open         func(string) (*os.File, error)
	finalLstat   func(string) (os.FileInfo, error)
	finalOpen    func(string) (*os.File, error)
}

func factoryExecutableIdentityWithOperations(operations factoryExecutableIdentityOperations) (string, int64, error) {
	path, err := operations.executable()
	if err != nil {
		return "", 0, fmt.Errorf("resolve factory runner executable: %w", err)
	}
	pathInfo, err := operations.initialLstat(path)
	if err != nil {
		return "", 0, fmt.Errorf("inspect factory runner executable: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return "", 0, fmt.Errorf("factory runner executable is not a stable regular file")
	}
	if operations.initialOpen == nil {
		operations.initialOpen = operations.open
	}
	if operations.finalOpen == nil {
		operations.finalOpen = operations.open
	}
	initialFile, err := operations.initialOpen(path)
	if err != nil {
		return "", 0, fmt.Errorf("open initial factory runner executable identity: %w", err)
	}
	initialInfo, err := initialFile.Stat()
	if err != nil {
		_ = initialFile.Close()
		return "", 0, fmt.Errorf("stat initial factory runner executable identity: %w", err)
	}
	initialIdentity, err := stableProviderInputFileIdentity(initialFile)
	closeInitialErr := initialFile.Close()
	if err != nil {
		return "", 0, fmt.Errorf("derive initial factory runner executable identity: %w", err)
	}
	if closeInitialErr != nil {
		return "", 0, fmt.Errorf("close initial factory runner executable identity handle: %w", closeInitialErr)
	}
	file, err := operations.open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open factory runner executable: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat factory runner executable: %w", err)
	}
	beforeIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return "", 0, fmt.Errorf("derive opened factory runner executable identity: %w", err)
	}
	if !initialInfo.Mode().IsRegular() || !before.Mode().IsRegular() || initialIdentity != beforeIdentity || pathInfo.Size() != initialInfo.Size() || pathInfo.Size() != before.Size() || !pathInfo.ModTime().Equal(initialInfo.ModTime()) || !pathInfo.ModTime().Equal(before.ModTime()) {
		return "", 0, fmt.Errorf("factory runner executable changed between path inspection and open")
	}
	firstSHA256, firstBytes, err := hashFactoryExecutable(file)
	if err != nil {
		return "", 0, err
	}
	middle, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("restat factory runner executable: %w", err)
	}
	middleIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return "", 0, fmt.Errorf("rederive factory runner executable identity: %w", err)
	}
	secondSHA256, secondBytes, err := hashFactoryExecutable(file)
	if err != nil {
		return "", 0, err
	}
	after, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("final stat factory runner executable: %w", err)
	}
	afterIdentity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		return "", 0, fmt.Errorf("final rederive factory runner executable identity: %w", err)
	}
	finalPathInfo, err := operations.finalLstat(path)
	if err != nil {
		return "", 0, fmt.Errorf("final inspect factory runner executable: %w", err)
	}
	finalFile, err := operations.finalOpen(path)
	if err != nil {
		return "", 0, fmt.Errorf("final open factory runner executable identity: %w", err)
	}
	finalOpenedInfo, err := finalFile.Stat()
	if err != nil {
		_ = finalFile.Close()
		return "", 0, fmt.Errorf("final stat factory runner executable identity: %w", err)
	}
	finalIdentity, err := stableProviderInputFileIdentity(finalFile)
	closeFinalErr := finalFile.Close()
	if err != nil {
		return "", 0, fmt.Errorf("derive final factory runner executable identity: %w", err)
	}
	if closeFinalErr != nil {
		return "", 0, fmt.Errorf("close final factory runner executable identity handle: %w", closeFinalErr)
	}
	if finalPathInfo.Mode()&os.ModeSymlink != 0 || !finalPathInfo.Mode().IsRegular() || !finalOpenedInfo.Mode().IsRegular() || beforeIdentity != middleIdentity || beforeIdentity != afterIdentity || beforeIdentity != finalIdentity || before.Size() != middle.Size() || before.Size() != after.Size() || before.Size() != finalPathInfo.Size() || before.Size() != finalOpenedInfo.Size() || !before.ModTime().Equal(middle.ModTime()) || !before.ModTime().Equal(after.ModTime()) || !before.ModTime().Equal(finalPathInfo.ModTime()) || !before.ModTime().Equal(finalOpenedInfo.ModTime()) || firstBytes != before.Size() || firstBytes != secondBytes || firstSHA256 != secondSHA256 {
		return "", 0, fmt.Errorf("factory runner executable changed while its identity was measured")
	}
	return firstSHA256, firstBytes, nil
}

func hashFactoryExecutable(file *os.File) (string, int64, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", 0, fmt.Errorf("rewind factory runner executable: %w", err)
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, maxFactoryExecutableBytes+1))
	if err != nil {
		return "", 0, fmt.Errorf("hash factory runner executable: %w", err)
	}
	if count > maxFactoryExecutableBytes {
		return "", 0, fmt.Errorf("factory runner executable exceeds %d bytes", maxFactoryExecutableBytes)
	}
	return hex.EncodeToString(hash.Sum(nil)), count, nil
}

func canonicalFactoryBuildMetadata(info *debug.BuildInfo) (factoryBuildMetadata, error) {
	if info == nil {
		return factoryBuildMetadata{}, fmt.Errorf("factory runner build metadata is nil")
	}
	toModule := func(module debug.Module) (factoryBuildModule, error) {
		result := factoryBuildModule{Path: module.Path, Version: module.Version, Sum: module.Sum}
		if module.Replace != nil {
			if strings.TrimSpace(module.Replace.Path) == "" || strings.TrimSpace(module.Replace.Version) == "" || strings.TrimSpace(module.Replace.Sum) == "" {
				return factoryBuildModule{}, fmt.Errorf("factory runner build metadata contains an unpinned local replacement for module %q", module.Path)
			}
			result.ReplacePath = module.Replace.Path
			result.ReplaceVersion = module.Replace.Version
			result.ReplaceSum = module.Replace.Sum
		}
		return result, nil
	}
	mainModule, err := toModule(info.Main)
	if err != nil {
		return factoryBuildMetadata{}, err
	}
	metadata := factoryBuildMetadata{GoVersion: info.GoVersion, Main: mainModule}
	metadata.Dependencies = make([]factoryBuildModule, len(info.Deps))
	for index, dependency := range info.Deps {
		if dependency == nil {
			return factoryBuildMetadata{}, fmt.Errorf("factory runner build metadata contains a nil dependency")
		}
		metadata.Dependencies[index], err = toModule(*dependency)
		if err != nil {
			return factoryBuildMetadata{}, err
		}
	}
	sort.Slice(metadata.Dependencies, func(i, j int) bool {
		left, right := metadata.Dependencies[i], metadata.Dependencies[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.Sum < right.Sum
	})
	for _, setting := range info.Settings {
		if factoryTargetBuildSetting(setting.Key) {
			continue
		}
		metadata.Settings = append(metadata.Settings, factoryBuildSetting{Key: setting.Key, Value: setting.Value})
	}
	sort.Slice(metadata.Settings, func(i, j int) bool {
		if metadata.Settings[i].Key != metadata.Settings[j].Key {
			return metadata.Settings[i].Key < metadata.Settings[j].Key
		}
		return metadata.Settings[i].Value < metadata.Settings[j].Value
	})
	return metadata, nil
}

func factoryTargetBuildSetting(key string) bool {
	switch key {
	case "-buildmode", "-compiler", "-ldflags", "CGO_ENABLED", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS",
		"GOOS", "GOARCH", "GO386", "GOAMD64", "GOARM", "GOARM64", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOWASM":
		return true
	default:
		return false
	}
}

func sealFactoryToolIdentity(identity FactoryToolIdentity) (FactoryToolIdentity, error) {
	identity.BuildIdentitySHA256 = ""
	if identity.CommandPath != factoryRunnerCommandPath {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner command path is %q, want %q", identity.CommandPath, factoryRunnerCommandPath)
	}
	if identity.ModulePath != factoryRunnerModulePath || strings.TrimSpace(identity.ModuleVersion) == "" || strings.TrimSpace(identity.GoVersion) == "" {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner module or Go toolchain identity is incomplete")
	}
	if identity.VCS != "git" || !validFactoryVCSRevision(identity.VCSRevision) || identity.VCSModified || !identity.ReproducibleSourceTree {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner requires an unmodified, VCS-identified source tree")
	}
	if identity.BuildTags != factoryReleaseBuildTag {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner build tags are %q, want %q", identity.BuildTags, factoryReleaseBuildTag)
	}
	if identity.RunnerContractSHA256 != sha256Hex([]byte(factoryRunnerContract)) {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner contract identity is invalid")
	}
	if _, err := time.Parse(time.RFC3339, identity.VCSTime); err != nil {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner vcs_time is invalid: %w", err)
	}
	if !isLowerSHA256(identity.ModuleGraphSHA256) || !isLowerSHA256(identity.BuildRecipeSHA256) || !isLowerSHA256(identity.SourceRosterSHA256) {
		return FactoryToolIdentity{}, fmt.Errorf("factory runner portable module graph or build recipe identity is incomplete")
	}
	raw, err := canonicalFactoryJSON(identity)
	if err != nil {
		return FactoryToolIdentity{}, err
	}
	identity.BuildIdentitySHA256 = sha256Hex(raw)
	return identity, nil
}

func validateFactoryToolIdentity(identity FactoryToolIdentity) error {
	sealed, err := sealFactoryToolIdentity(identity)
	if err != nil {
		return err
	}
	if sealed != identity {
		return fmt.Errorf("factory tool build identity digest is invalid")
	}
	return nil
}

func validFactoryVCSRevision(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func factoryPathKey(path string) (string, error) {
	if strings.TrimSpace(path) == "" || path != strings.TrimSpace(path) {
		return "", fmt.Errorf("path is empty or padded")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	key := filepath.Clean(abs)
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key, nil
}

func shallowFactoryStageInputs(input StageCompileInputs) StageCompileInputs {
	return StageCompileInputs{
		PredecessorReceipts: append([][]byte(nil), input.PredecessorReceipts...),
		EvidenceBodies:      append([]StageEvidenceBody(nil), input.EvidenceBodies...),
		Materials:           append([]StageMaterial(nil), input.Materials...),
	}
}

func equalFactoryStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
