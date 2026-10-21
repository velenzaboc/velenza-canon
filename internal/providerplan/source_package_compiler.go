package providerplan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const (
	documentationFactorySourcePackageKind    = "provider_documentation_factory_source_package"
	documentationFactorySourcePackageVersion = "1"
	documentationFactoryTemplateKind         = "provider_documentation_factory_candidate_template"
	documentationFactoryTemplateVersion      = "1"
	documentationFactorySourceReceiptKind    = "provider_documentation_factory_source_compile_receipt"
	documentationFactorySourceReceiptVersion = "1"
	documentationFactorySourceResult         = "compiled_and_verified_candidate_bundle_only"
	documentationFactorySourceScope          = "offline_sealed_source_package_candidate_materialization_and_four_stage_factory_verification"
	documentationFactorySourceContract       = "strict_source_package;exact_input_hash_and_size_pins;declarative_json_templates;closed_package_local_output_roles=api_graph_artifact,reusable_profile,source_mapping,residual_circuit_package,arc_reference_blueprint;runner_owned_stage_lineage;arc_source_invariance=pending_content_derived_package_proof_at_template_owner_checker;complete_private_tree_before_no_replace_publication;body_free_candidate_receipts;no_authority_selection_admission_configuration_credentials_tenants_deployment_or_live_acceptance"

	sourcePackageTemplateFormatJSON  = "canonical_json"
	sourcePackageTemplateFormatJSONL = "canonical_jsonl"

	sourcePackageProjectionSHA256    = "raw_sha256"
	sourcePackageProjectionByteCount = "byte_count"
	sourcePackageProjectionJSONValue = "json_value"

	sourcePackageCarrierRaw    = "raw"
	sourcePackageCarrierBase64 = "base64_rfc4648"

	sourcePackageOutputRoleAPIGraphArtifact       = "api_graph_artifact"
	sourcePackageOutputRoleReusableProfile        = "reusable_profile"
	sourcePackageOutputRoleSourceMapping          = "source_mapping"
	sourcePackageOutputRoleResidualCircuitPackage = "residual_circuit_package"
	sourcePackageOutputRoleARCReferenceBlueprint  = "arc_reference_blueprint"

	sourcePackageOwnerValidationPendingContentDerivedPackageProof = "pending_content_derived_package_proof"
	sourcePackageARCSourceInvarianceCanonicalContractRef          = "e799e6ff-7ad0-4c3b-91cb-6c7685f0c7a1#authored_source_package_contract.arc_source_invariance.checkable_form"
	sourcePackageARCSourceInvarianceCheckableFormOwnerRef         = "velenza-arc-app-template/contracts/repository_contract.json#source_invariance"

	sourcePackageFactoryReceiptPath = "factory-run-receipt.json"
	sourcePackageCompileReceiptPath = "source-compile-receipt.json"
	sourcePackageManifestBundlePath = "source-package.manifest.json"
)

type sourcePackageOutputRoleContract struct {
	targetArtifactType      string
	requiredOwnerValidation *DocumentationFactorySourceOutputOwnerValidation
	runnerStage             string
	runnerSlot              string
	artifactRole            string
}

var sourcePackageOutputRoleContracts = map[string]sourcePackageOutputRoleContract{
	sourcePackageOutputRoleAPIGraphArtifact: {
		runnerStage: stageGraphCompile, runnerSlot: "plan", artifactRole: "api_graph_plan",
	},
	sourcePackageOutputRoleReusableProfile: {
		runnerStage: stageSemanticExtraction, runnerSlot: "artifact_outputs", artifactRole: "provider_neutral_compilation_profile",
	},
	sourcePackageOutputRoleSourceMapping: {
		runnerStage: stageSemanticExtraction, runnerSlot: "artifact_outputs", artifactRole: "field_mapping_candidate",
	},
	sourcePackageOutputRoleResidualCircuitPackage: {
		targetArtifactType: "circuit", runnerStage: stageSemanticExtraction, runnerSlot: "artifact_outputs", artifactRole: sourcePackageOutputRoleResidualCircuitPackage,
	},
	sourcePackageOutputRoleARCReferenceBlueprint: {
		targetArtifactType: "app_blueprint",
		requiredOwnerValidation: &DocumentationFactorySourceOutputOwnerValidation{
			Status:                sourcePackageOwnerValidationPendingContentDerivedPackageProof,
			CanonicalContractRef:  sourcePackageARCSourceInvarianceCanonicalContractRef,
			CheckableFormOwnerRef: sourcePackageARCSourceInvarianceCheckableFormOwnerRef,
		},
		runnerStage: stageSemanticExtraction, runnerSlot: "artifact_outputs", artifactRole: sourcePackageOutputRoleARCReferenceBlueprint,
	},
}

func cloneDocumentationFactorySourceOutputOwnerValidation(value *DocumentationFactorySourceOutputOwnerValidation) *DocumentationFactorySourceOutputOwnerValidation {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func equalDocumentationFactorySourceOutputOwnerValidation(left, right *DocumentationFactorySourceOutputOwnerValidation) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

var sourcePackageReservedOutputPaths = map[string]struct{}{
	canonicalProviderInputPathKey(sourcePackageFactoryReceiptPath):            {},
	canonicalProviderInputPathKey(sourcePackageCompileReceiptPath):            {},
	canonicalProviderInputPathKey(sourcePackageManifestBundlePath):            {},
	canonicalProviderInputPathKey("factory-evidence-intake.request.json"):     {},
	canonicalProviderInputPathKey("factory-evidence-intake.inputs.json"):      {},
	canonicalProviderInputPathKey("factory-semantic-extraction.request.json"): {},
	canonicalProviderInputPathKey("factory-semantic-extraction.inputs.json"):  {},
	canonicalProviderInputPathKey("factory-graph-compile.request.json"):       {},
	canonicalProviderInputPathKey("factory-graph-compile.inputs.json"):        {},
	canonicalProviderInputPathKey("factory-full-factory.request.json"):        {},
	canonicalProviderInputPathKey("factory-full-factory.inputs.json"):         {},
}

// DocumentationFactorySourceCompileOptions names one exact source-package
// manifest and an absent destination directory. The source package is a
// repository-local candidate pre-image, not artifact or admission authority.
type DocumentationFactorySourceCompileOptions struct {
	SourcePackagePath string
	OutputRoot        string
}

// DocumentationFactorySourceCompileResult returns both receipts. FactoryReceipt
// remains the exact receipt consumed by the existing exact-commit release
// wrapper. SourceReceipt additionally binds the original source package and the
// privately materialized candidate tree.
type DocumentationFactorySourceCompileResult struct {
	FactoryReceipt FactoryRunReceipt
	SourceReceipt  DocumentationFactorySourceCompileReceipt
}

// DocumentationFactorySourceOutputOwnerValidation records a validation that a
// downstream owner must still derive from its complete subject bytes. It is a
// pending gate coordinate, never a verdict or an authored safety assertion.
type DocumentationFactorySourceOutputOwnerValidation struct {
	Status                string `json:"status"`
	CanonicalContractRef  string `json:"canonical_contract_ref"`
	CheckableFormOwnerRef string `json:"checkable_form_owner_ref"`
}

type DocumentationFactorySourceOutputReceipt struct {
	PackageRole             string                                           `json:"package_role"`
	ArtifactRole            string                                           `json:"artifact_role"`
	ArtifactID              string                                           `json:"artifact_id"`
	ArtifactVersion         string                                           `json:"artifact_version"`
	RelativePath            string                                           `json:"relative_path"`
	RawSHA256               string                                           `json:"raw_sha256"`
	ByteCount               int64                                            `json:"byte_count"`
	SubjectClass            string                                           `json:"subject_class"`
	TargetArtifactType      string                                           `json:"target_artifact_type,omitempty"`
	PayloadContractRef      string                                           `json:"payload_contract_ref"`
	AuthorityClass          string                                           `json:"expected_authority_class"`
	RequiredOwnerValidation *DocumentationFactorySourceOutputOwnerValidation `json:"required_owner_validation,omitempty"`
	CandidateOnly           bool                                             `json:"candidate_only"`
	BodyFree                bool                                             `json:"body_free"`
}

type documentationFactorySourceBundleFileReceipt struct {
	RelativePath string `json:"relative_path"`
	RawSHA256    string `json:"raw_sha256"`
	ByteCount    int64  `json:"byte_count"`
}

// DocumentationFactorySourceCompileReceipt is intentionally body-free and
// candidate-only. It records what exact source inputs were consumed and what
// exact files were privately materialized, but claims no platform artifact
// validity, admission, configuration, credential, tenant, deployment, or live
// provider state.
type DocumentationFactorySourceCompileReceipt struct {
	ReceiptKind                  string                                                   `json:"receipt_kind"`
	ReceiptVersion               string                                                   `json:"receipt_version"`
	Result                       string                                                   `json:"result"`
	Scope                        string                                                   `json:"scope"`
	CompilerContractSHA256       string                                                   `json:"compiler_contract_sha256"`
	SourcePackageSHA256          string                                                   `json:"source_package_sha256"`
	SourceInputAdmissionProof    providerInputAdmissionProof                              `json:"source_input_admission_proof"`
	SourceInputResources         []providerInputAdmissionResourceReceipt                  `json:"source_input_resources"`
	GeneratedOutputs             []DocumentationFactorySourceOutputReceipt                `json:"generated_outputs"`
	GeneratedOutputSetRootSHA256 string                                                   `json:"generated_output_set_root_sha256"`
	BundleFiles                  []documentationFactorySourceBundleFileReceipt            `json:"bundle_files"`
	BundleFileSetRootSHA256      string                                                   `json:"bundle_file_set_root_sha256"`
	ReceiptPath                  string                                                   `json:"receipt_path"`
	ReceiptExcludedFromBundleSet bool                                                     `json:"receipt_excluded_from_bundle_file_set"`
	FactoryPortableReceiptSHA256 string                                                   `json:"factory_portable_receipt_sha256"`
	FactoryReceiptSHA256         string                                                   `json:"factory_receipt_sha256"`
	FactoryReceiptFileSHA256     string                                                   `json:"factory_receipt_file_sha256"`
	Completion                   FactoryCompletionClassification                          `json:"completion"`
	BodyFree                     bool                                                     `json:"body_free"`
	AuthoritySelected            bool                                                     `json:"authority_selected"`
	AdmissionAuthorized          bool                                                     `json:"admission_authorized"`
	FactoryComplete              bool                                                     `json:"factory_complete"`
	ProductionSourceVerification *DocumentationFactoryProductionSourceVerificationReceipt `json:"production_source_verification,omitempty"`
	ReceiptSHA256                string                                                   `json:"receipt_sha256"`
}

type documentationFactorySourcePackage struct {
	PackageKind        string                                 `json:"package_kind"`
	PackageVersion     string                                 `json:"package_version"`
	Resources          []sourcePackageResourceDeclaration     `json:"resources"`
	EvidenceBodies     []sourcePackageEvidenceBodyDeclaration `json:"evidence_bodies"`
	GeneratedDocuments []sourcePackageGeneratedDocument       `json:"generated_documents"`
	FactoryPlan        sourcePackageFactoryPlan               `json:"factory_plan"`
}

type sourcePackageCoordinate struct {
	Role    string `json:"role"`
	ID      string `json:"id"`
	Version string `json:"version"`
}

type sourcePackageResourceDeclaration struct {
	Role                   string `json:"role"`
	ID                     string `json:"id"`
	Version                string `json:"version"`
	Path                   string `json:"path"`
	BundlePath             string `json:"bundle_path"`
	ExpectedRawSHA256      string `json:"expected_raw_sha256"`
	ExpectedByteCount      uint64 `json:"expected_byte_count"`
	ExpectedAuthorityClass string `json:"expected_authority_class"`
}

func (item sourcePackageResourceDeclaration) coordinate() sourcePackageCoordinate {
	return sourcePackageCoordinate{Role: item.Role, ID: item.ID, Version: item.Version}
}

type sourcePackageEvidenceBodyDeclaration struct {
	Manifest              sourcePackageCoordinate `json:"manifest"`
	ComponentOrdinal      uint64                  `json:"component_ordinal"`
	Carrier               sourcePackageCoordinate `json:"carrier"`
	CarrierEncoding       string                  `json:"carrier_encoding"`
	ExpectedBodySHA256    string                  `json:"expected_body_sha256"`
	ExpectedBodyByteCount uint64                  `json:"expected_body_byte_count"`
}

type sourcePackageGeneratedDocument struct {
	PackageRole             string                                           `json:"package_role"`
	Role                    string                                           `json:"artifact_role"`
	ID                      string                                           `json:"id"`
	Version                 string                                           `json:"version"`
	BundlePath              string                                           `json:"bundle_path"`
	Template                sourcePackageCoordinate                          `json:"template"`
	ExpectedRawSHA256       string                                           `json:"expected_raw_sha256"`
	ExpectedByteCount       uint64                                           `json:"expected_byte_count"`
	SubjectClass            string                                           `json:"subject_class"`
	TargetArtifactType      string                                           `json:"target_artifact_type"`
	PayloadContractRef      string                                           `json:"payload_contract_ref"`
	AuthorityClass          string                                           `json:"expected_authority_class"`
	RequiredOwnerValidation *DocumentationFactorySourceOutputOwnerValidation `json:"required_owner_validation,omitempty"`
	CandidateOnly           bool                                             `json:"candidate_only"`
	BodyFree                bool                                             `json:"body_free"`
}

func (item sourcePackageGeneratedDocument) coordinate() sourcePackageCoordinate {
	return sourcePackageCoordinate{Role: item.Role, ID: item.ID, Version: item.Version}
}

type sourcePackagePinReference struct {
	Resource       sourcePackageCoordinate `json:"resource"`
	AuthorityClass string                  `json:"authority_class"`
}

type sourcePackageStageValidationPlan struct {
	Schema  sourcePackagePinReference `json:"schema"`
	Profile sourcePackagePinReference `json:"profile"`
}

type sourcePackageAuthorityPlan struct {
	OODGraph          sourcePackagePinReference `json:"ood_graph"`
	GrandVision       sourcePackagePinReference `json:"grand_vision"`
	SourceRecord      sourcePackagePinReference `json:"source_record"`
	ExtensionProtocol sourcePackagePinReference `json:"extension_protocol"`
}

type sourcePackageEvidenceIntakePlan struct {
	StageValidation   sourcePackageStageValidationPlan `json:"stage_validation"`
	AuthorityPins     sourcePackageAuthorityPlan       `json:"authority_pins"`
	SelectionRoster   sourcePackageCoordinate          `json:"selection_roster"`
	EvidenceManifests []sourcePackageCoordinate        `json:"evidence_manifests"`
}

type sourcePackageSemanticOutputPlan struct {
	Resource             sourcePackageCoordinate `json:"resource"`
	Disposition          string                  `json:"disposition"`
	DerivationBindingIDs []string                `json:"derivation_binding_ids"`
}

type sourcePackageSemanticBindingPlan struct {
	BindingID string                    `json:"binding_id"`
	Extractor sourcePackagePinReference `json:"extractor"`
	Schema    sourcePackagePinReference `json:"schema"`
}

type sourcePackageSemanticExtractionPlan struct {
	StageValidation      sourcePackageStageValidationPlan   `json:"stage_validation"`
	ApplicabilityProfile sourcePackagePinReference          `json:"applicability_profile"`
	ArtifactOutputs      []sourcePackageSemanticOutputPlan  `json:"artifact_outputs"`
	DerivationBindings   []sourcePackageSemanticBindingPlan `json:"derivation_bindings"`
}

type sourcePackageGraphCompilePlan struct {
	StageValidation     sourcePackageStageValidationPlan `json:"stage_validation"`
	DependencyArtifacts []sourcePackageCoordinate        `json:"dependency_artifacts"`
	Plan                sourcePackageCoordinate          `json:"plan"`
}

type sourcePackageFullFactoryPlan struct {
	StageValidation sourcePackageStageValidationPlan `json:"stage_validation"`
}

type sourcePackageFactoryPlan struct {
	EvidenceIntake        sourcePackageEvidenceIntakePlan     `json:"evidence_intake"`
	SemanticExtraction    sourcePackageSemanticExtractionPlan `json:"semantic_extraction"`
	GraphCompile          sourcePackageGraphCompilePlan       `json:"graph_compile"`
	FullFactory           sourcePackageFullFactoryPlan        `json:"full_factory"`
	PreflightDependencies []sourcePackageCoordinate           `json:"preflight_dependencies"`
}

type sourcePackageTemplateDocument struct {
	TemplateKind    string            `json:"template_kind"`
	TemplateVersion string            `json:"template_version"`
	OutputFormat    string            `json:"output_format"`
	Document        json.RawMessage   `json:"document"`
	Rows            []json.RawMessage `json:"rows"`
}

type sourcePackageProjection struct {
	Resource    sourcePackageCoordinate `json:"resource"`
	Projection  string                  `json:"projection"`
	JSONPointer string                  `json:"json_pointer"`
}

type sourcePackageMaterial struct {
	coordinate     sourcePackageCoordinate
	raw            []byte
	bundlePath     string
	authorityClass string
	inputResource  *providerInputAdmissionResourceReceipt
}

type sourcePackageCompilation struct {
	manifest           documentationFactorySourcePackage
	packageRaw         []byte
	inputProof         providerInputAdmissionProof
	inputResources     []providerInputAdmissionResourceReceipt
	materials          map[sourcePackageCoordinate]sourcePackageMaterial
	evidenceBodies     []StageEvidenceBody
	generatedOutputs   []DocumentationFactorySourceOutputReceipt
	files              map[string][]byte
	stageManifestPaths [4]string
	preflight          Options
	inputAccumulator   *providerInputAdmissionAccumulator
}

type documentationFactorySourceCompilerDependencies struct {
	RunFactory    func(FactoryRunOptions) (FactoryRunReceipt, error)
	Publish       func(string, []factorySourceOutputFile) error
	WithWorkspace func([]factorySourceOutputFile, func(string) error) error
}

func defaultDocumentationFactorySourceCompilerDependencies() documentationFactorySourceCompilerDependencies {
	return documentationFactorySourceCompilerDependencies{
		RunFactory:    RunDocumentationFactory,
		Publish:       publishFactorySourceOutputDirectoryExclusive,
		WithWorkspace: withPrivateFactorySourceOutputDirectory,
	}
}

// CompileDocumentationFactorySourcePackage compiles a closed repository-local
// source package to a complete candidate tree, verifies the generated four
// stages with the existing factory runner, and publishes the tree once. The
// function performs no admission, graph write, configuration, credential,
// tenant, deployment, or live-provider operation.
func CompileDocumentationFactorySourcePackage(options DocumentationFactorySourceCompileOptions) (DocumentationFactorySourceCompileResult, error) {
	return compileDocumentationFactorySourcePackageWithDependencies(options, defaultDocumentationFactorySourceCompilerDependencies())
}

func compileDocumentationFactorySourcePackageWithDependencies(options DocumentationFactorySourceCompileOptions, dependencies documentationFactorySourceCompilerDependencies) (DocumentationFactorySourceCompileResult, error) {
	if err := validateDocumentationFactorySourceCompilerInputs(options, dependencies); err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	compilation, err := prepareDocumentationFactorySourceCompilation(options.SourcePackagePath)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	return compilePreparedDocumentationFactorySourcePackage(options, compilation, dependencies, nil, nil)
}

func validateDocumentationFactorySourceCompilerInputs(options DocumentationFactorySourceCompileOptions, dependencies documentationFactorySourceCompilerDependencies) error {
	if dependencies.RunFactory == nil || dependencies.Publish == nil || dependencies.WithWorkspace == nil {
		return fmt.Errorf("source compiler dependency is nil")
	}
	if strings.TrimSpace(options.SourcePackagePath) == "" || options.SourcePackagePath != strings.TrimSpace(options.SourcePackagePath) {
		return fmt.Errorf("source package path is empty or padded")
	}
	if strings.TrimSpace(options.OutputRoot) == "" || options.OutputRoot != strings.TrimSpace(options.OutputRoot) {
		return fmt.Errorf("source compiler output root is empty or padded")
	}
	return nil
}

func compilePreparedDocumentationFactorySourcePackage(options DocumentationFactorySourceCompileOptions, compilation sourcePackageCompilation, dependencies documentationFactorySourceCompilerDependencies, productionVerification *DocumentationFactoryProductionSourceVerificationReceipt, revalidateProductionVerification func() error) (DocumentationFactorySourceCompileResult, error) {
	workspaceFiles := sourcePackageOutputFiles(compilation.files)
	var factoryReceipt FactoryRunReceipt
	err := dependencies.WithWorkspace(workspaceFiles, func(workspace string) error {
		options := sourcePackageFactoryRunOptionsForWorkspace(compilation, workspace)
		var runErr error
		factoryReceipt, runErr = dependencies.RunFactory(options)
		return runErr
	})
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("verify generated source package factory: %w", err)
	}
	if err := validateFactoryRunReceipt(factoryReceipt); err != nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("validate generated source package factory receipt: %w", err)
	}
	if productionVerification != nil && factoryReceipt.PreflightReceipt.Provider != productionVerification.Provider {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("verified production source-package provider %q does not match compiled provider %q", productionVerification.Provider, factoryReceipt.PreflightReceipt.Provider)
	}
	if err := revalidateDocumentationFactorySourceInputs(&compilation); err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	if revalidateProductionVerification != nil {
		if err := revalidateProductionVerification(); err != nil {
			return DocumentationFactorySourceCompileResult{}, fmt.Errorf("revalidate production source-package verification receipt at completion: %w", err)
		}
	}
	factoryRaw, err := canonicalFactoryJSON(factoryReceipt)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("serialize generated factory receipt: %w", err)
	}
	factoryRaw = append(factoryRaw, '\n')
	if err := addSourcePackageCompilationFile(compilation.files, sourcePackageFactoryReceiptPath, factoryRaw, true); err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}

	sourceReceipt, err := sealDocumentationFactorySourceReceipt(compilation, factoryReceipt, productionVerification)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	sourceRaw, err := canonicalFactoryJSON(sourceReceipt)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("serialize source compiler receipt: %w", err)
	}
	sourceRaw = append(sourceRaw, '\n')
	if err := validateSourcePackageOutputBodyFree(compilation.evidenceBodies, sourcePackageCompileReceiptPath, sourceRaw); err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	if err := addSourcePackageCompilationFile(compilation.files, sourcePackageCompileReceiptPath, sourceRaw, true); err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}

	outputFiles := sourcePackageOutputFiles(compilation.files)
	if err := dependencies.Publish(options.OutputRoot, outputFiles); err != nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("publish complete source compiler output tree: %w", err)
	}
	return DocumentationFactorySourceCompileResult{FactoryReceipt: factoryReceipt, SourceReceipt: sourceReceipt}, nil
}

func sourcePackageOutputFiles(files map[string][]byte) []factorySourceOutputFile {
	result := make([]factorySourceOutputFile, 0, len(files))
	for _, relative := range sortedSourcePackageFilePaths(files) {
		result = append(result, factorySourceOutputFile{RelativePath: relative, Raw: bytes.Clone(files[relative])})
	}
	return result
}

func sourcePackageFactoryRunOptionsForWorkspace(compilation sourcePackageCompilation, workspace string) FactoryRunOptions {
	preflight := compilation.preflight
	preflight.EvidenceManifestPath = append([]string(nil), compilation.preflight.EvidenceManifestPath...)
	preflight.DependencyArtifactPath = append([]string(nil), compilation.preflight.DependencyArtifactPath...)
	for index, relative := range preflight.EvidenceManifestPath {
		preflight.EvidenceManifestPath[index] = filepath.Join(workspace, filepath.FromSlash(relative))
	}
	for index, relative := range preflight.DependencyArtifactPath {
		preflight.DependencyArtifactPath[index] = filepath.Join(workspace, filepath.FromSlash(relative))
	}
	preflight.OODSpecPath = filepath.Join(workspace, filepath.FromSlash(preflight.OODSpecPath))
	preflight.GrandVisionPath = filepath.Join(workspace, filepath.FromSlash(preflight.GrandVisionPath))
	preflight.SourceRecordSpecPath = filepath.Join(workspace, filepath.FromSlash(preflight.SourceRecordSpecPath))
	return FactoryRunOptions{
		EvidenceIntakeInputManifestPath:     filepath.Join(workspace, filepath.FromSlash(compilation.stageManifestPaths[0])),
		SemanticExtractionInputManifestPath: filepath.Join(workspace, filepath.FromSlash(compilation.stageManifestPaths[1])),
		GraphCompileInputManifestPath:       filepath.Join(workspace, filepath.FromSlash(compilation.stageManifestPaths[2])),
		FullFactoryInputManifestPath:        filepath.Join(workspace, filepath.FromSlash(compilation.stageManifestPaths[3])),
		Preflight:                           preflight,
	}
}

func prepareDocumentationFactorySourceCompilation(manifestPath string) (sourcePackageCompilation, error) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	manifestFile, err := readBoundedProviderInputFile(manifestPath, "factory source package", providerInputAdmissionResourceKindStageManifest, "factory_source_package_v1", accumulator)
	if err != nil {
		return sourcePackageCompilation{}, err
	}
	if err := accumulator.admitStructuredJSONDocument(manifestPath, "factory source package", providerInputAdmissionResourceKindStageManifest, manifestFile.Bytes); err != nil {
		return sourcePackageCompilation{}, err
	}
	var manifest documentationFactorySourcePackage
	if err := strictUnmarshal(manifestFile.Bytes, &manifest); err != nil {
		return sourcePackageCompilation{}, fmt.Errorf("decode factory source package: %w", err)
	}
	if err := validateDocumentationFactorySourcePackageShape(manifest); err != nil {
		return sourcePackageCompilation{}, err
	}
	baseDir, err := filepath.Abs(filepath.Dir(manifestPath))
	if err != nil {
		return sourcePackageCompilation{}, fmt.Errorf("resolve factory source package directory: %w", err)
	}

	compilation := sourcePackageCompilation{
		manifest:   manifest,
		packageRaw: manifestFile.Bytes,
		materials:  make(map[sourcePackageCoordinate]sourcePackageMaterial, len(manifest.Resources)+len(manifest.GeneratedDocuments)),
		files:      make(map[string][]byte, len(manifest.Resources)+len(manifest.GeneratedDocuments)+12),
	}
	if err := addSourcePackageCompilationFile(compilation.files, sourcePackageManifestBundlePath, manifestFile.Bytes, true); err != nil {
		return sourcePackageCompilation{}, err
	}
	used := make(map[sourcePackageCoordinate]struct{}, len(manifest.Resources))
	contentOwners := make(map[string]sourcePackageCoordinate, len(manifest.Resources))
	for index, declaration := range manifest.Resources {
		file, readErr := readExactStageManifestFileWithAdmission(baseDir, declaration.Path, fmt.Sprintf("resources[%d].path", index), "factory_source_resource_v1|"+sourcePackageCoordinateKey(declaration.coordinate()), accumulator)
		if readErr != nil {
			return sourcePackageCompilation{}, readErr
		}
		if file.SHA256 != declaration.ExpectedRawSHA256 || uint64(file.Size) != declaration.ExpectedByteCount {
			return sourcePackageCompilation{}, fmt.Errorf("resource %s digest/size differs from its exact source-package pin", sourcePackageCoordinateLabel(declaration.coordinate()))
		}
		if owner, aliased := contentOwners[file.SHA256]; aliased {
			return sourcePackageCompilation{}, fmt.Errorf("resource %s aliases the exact content of %s", sourcePackageCoordinateLabel(declaration.coordinate()), sourcePackageCoordinateLabel(owner))
		}
		contentOwners[file.SHA256] = declaration.coordinate()
		resolved, resolveErr := resolveRelativeStageManifestPath(baseDir, declaration.Path, fmt.Sprintf("resources[%d].path", index))
		if resolveErr != nil {
			return sourcePackageCompilation{}, resolveErr
		}
		if err := accumulator.admitStructuredJSONAuto(resolved, fmt.Sprintf("factory source resource[%d]", index), providerInputAdmissionResourceKindStageFile, file.Bytes); err != nil {
			return sourcePackageCompilation{}, err
		}
		resource := file.Resource
		compilation.materials[declaration.coordinate()] = sourcePackageMaterial{
			coordinate: declaration.coordinate(), raw: bytes.Clone(file.Bytes), bundlePath: declaration.BundlePath,
			authorityClass: declaration.ExpectedAuthorityClass, inputResource: &resource,
		}
		if err := addSourcePackageCompilationFile(compilation.files, declaration.BundlePath, file.Bytes, false); err != nil {
			return sourcePackageCompilation{}, err
		}
	}

	decodedBodies, err := decodeSourcePackageEvidenceBodies(manifest.EvidenceBodies, compilation.materials, used)
	if err != nil {
		return sourcePackageCompilation{}, err
	}
	compilation.evidenceBodies = decodedBodies

	for index, declaration := range manifest.GeneratedDocuments {
		template, ok := compilation.materials[declaration.Template]
		if !ok {
			return sourcePackageCompilation{}, fmt.Errorf("generated_documents[%d] template %s is absent", index, sourcePackageCoordinateLabel(declaration.Template))
		}
		used[declaration.Template] = struct{}{}
		raw, renderErr := renderSourcePackageTemplate(template.raw, compilation.materials, used)
		if renderErr != nil {
			return sourcePackageCompilation{}, fmt.Errorf("render generated document %s: %w", sourcePackageCoordinateLabel(declaration.coordinate()), renderErr)
		}
		if sha256Hex(raw) != declaration.ExpectedRawSHA256 || uint64(len(raw)) != declaration.ExpectedByteCount {
			return sourcePackageCompilation{}, fmt.Errorf("generated document %s digest/size differs from its exact source-package pin", sourcePackageCoordinateLabel(declaration.coordinate()))
		}
		if err := validateSourcePackageOutputBodyFree(decodedBodies, declaration.BundlePath, raw); err != nil {
			return sourcePackageCompilation{}, err
		}
		if err := validateStructuredDependencySecurity(artifactInput{Path: declaration.BundlePath, Raw: raw, Structured: true}); err != nil {
			return sourcePackageCompilation{}, fmt.Errorf("generated document %s metadata security: %w", declaration.BundlePath, err)
		}
		compilation.materials[declaration.coordinate()] = sourcePackageMaterial{
			coordinate: declaration.coordinate(), raw: raw, bundlePath: declaration.BundlePath, authorityClass: declaration.AuthorityClass,
		}
		if err := addSourcePackageCompilationFile(compilation.files, declaration.BundlePath, raw, false); err != nil {
			return sourcePackageCompilation{}, err
		}
		compilation.generatedOutputs = append(compilation.generatedOutputs, DocumentationFactorySourceOutputReceipt{
			PackageRole: declaration.PackageRole, ArtifactRole: declaration.Role, ArtifactID: declaration.ID, ArtifactVersion: declaration.Version,
			RelativePath: declaration.BundlePath, RawSHA256: sha256Hex(raw), ByteCount: int64(len(raw)),
			SubjectClass: declaration.SubjectClass, TargetArtifactType: declaration.TargetArtifactType,
			PayloadContractRef: declaration.PayloadContractRef, AuthorityClass: declaration.AuthorityClass,
			RequiredOwnerValidation: cloneDocumentationFactorySourceOutputOwnerValidation(declaration.RequiredOwnerValidation),
			CandidateOnly:           true, BodyFree: true,
		})
	}

	runnerBoundGenerated, err := validateSourcePackageGeneratedOutputLineage(manifest)
	if err != nil {
		return sourcePackageCompilation{}, err
	}
	requests, stageMaterials, preflight, err := buildSourcePackageFactoryRequests(manifest.FactoryPlan, compilation.materials, decodedBodies, used)
	if err != nil {
		return sourcePackageCompilation{}, err
	}
	compilation.preflight = preflight
	for _, materials := range stageMaterials {
		for _, material := range materials {
			used[sourcePackageCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}] = struct{}{}
		}
	}
	if err := assembleSourcePackageFactoryFiles(&compilation, requests, stageMaterials, decodedBodies); err != nil {
		return sourcePackageCompilation{}, err
	}
	if err := requireAllSourcePackageResourcesUsed(manifest.Resources, used); err != nil {
		return sourcePackageCompilation{}, err
	}
	if err := requireAllSourcePackageGeneratedDocumentsUsed(manifest.GeneratedDocuments, runnerBoundGenerated); err != nil {
		return sourcePackageCompilation{}, err
	}
	if err := accumulator.revalidatePhysicalSnapshots(); err != nil {
		return sourcePackageCompilation{}, fmt.Errorf("revalidate source package input snapshots: %w", err)
	}
	proof, err := accumulator.seal()
	if err != nil {
		return sourcePackageCompilation{}, fmt.Errorf("seal source package input admission: %w", err)
	}
	compilation.inputProof = proof
	compilation.inputResources = accumulator.orderedResources()
	compilation.inputAccumulator = accumulator
	return compilation, nil
}

func revalidateDocumentationFactorySourceInputs(compilation *sourcePackageCompilation) error {
	if compilation == nil || compilation.inputAccumulator == nil {
		return fmt.Errorf("source package input accumulator is unavailable at completion")
	}
	if err := compilation.inputAccumulator.revalidatePhysicalSnapshots(); err != nil {
		return fmt.Errorf("revalidate source package input snapshots at completion: %w", err)
	}
	proof, err := compilation.inputAccumulator.seal()
	if err != nil {
		return fmt.Errorf("reseal source package input admission at completion: %w", err)
	}
	if proof != compilation.inputProof {
		return fmt.Errorf("source package input admission proof changed before completion")
	}
	resources := compilation.inputAccumulator.orderedResources()
	wantRaw, wantErr := canonicalFactoryJSON(compilation.inputResources)
	gotRaw, gotErr := canonicalFactoryJSON(resources)
	if wantErr != nil || gotErr != nil || !bytes.Equal(wantRaw, gotRaw) {
		return fmt.Errorf("source package input resource roster changed before completion")
	}
	return nil
}

func validateDocumentationFactorySourcePackageShape(manifest documentationFactorySourcePackage) error {
	if manifest.PackageKind != documentationFactorySourcePackageKind || manifest.PackageVersion != documentationFactorySourcePackageVersion {
		return fmt.Errorf("factory source package identity is not %s v%s", documentationFactorySourcePackageKind, documentationFactorySourcePackageVersion)
	}
	if len(manifest.Resources) == 0 || len(manifest.EvidenceBodies) == 0 || len(manifest.GeneratedDocuments) == 0 {
		return fmt.Errorf("factory source package requires resources, evidence_bodies, and generated_documents")
	}
	coordinates := map[sourcePackageCoordinate]string{}
	paths := map[string]string{}
	sourcePaths := map[string]string{}
	priorCoordinate := ""
	for index, item := range manifest.Resources {
		coordinate := item.coordinate()
		if err := validateSourcePackageCoordinate(coordinate); err != nil {
			return fmt.Errorf("resources[%d]: %w", index, err)
		}
		key := sourcePackageCoordinateKey(coordinate)
		if key <= priorCoordinate {
			return fmt.Errorf("resources are not unique and strictly ordered by role/id/version")
		}
		priorCoordinate = key
		if err := validateSourcePackageDeclaredPath(item.Path, fmt.Sprintf("resources[%d].path", index)); err != nil {
			return err
		}
		sourcePathKey := canonicalProviderInputPathKey(filepath.FromSlash(item.Path))
		if prior, duplicate := sourcePaths[sourcePathKey]; duplicate {
			return fmt.Errorf("source path %q is duplicated by %s and resources[%d]", item.Path, prior, index)
		}
		sourcePaths[sourcePathKey] = fmt.Sprintf("resources[%d]", index)
		if err := validateSourcePackageBundlePath(item.BundlePath, fmt.Sprintf("resources[%d].bundle_path", index)); err != nil {
			return err
		}
		if !isLowerSHA256(item.ExpectedRawSHA256) || item.ExpectedByteCount == 0 || item.ExpectedByteCount > uint64(maxExactStageCount) {
			return fmt.Errorf("resources[%d] has an invalid raw digest or byte count", index)
		}
		if strings.TrimSpace(item.ExpectedAuthorityClass) == "" || item.ExpectedAuthorityClass != strings.TrimSpace(item.ExpectedAuthorityClass) {
			return fmt.Errorf("resources[%d] has an empty or padded expected_authority_class", index)
		}
		coordinates[coordinate] = fmt.Sprintf("resources[%d]", index)
		pathKey := canonicalProviderInputPathKey(filepath.FromSlash(item.BundlePath))
		if _, reserved := sourcePackageReservedOutputPaths[pathKey]; reserved || strings.HasPrefix(filepath.Base(filepath.FromSlash(item.BundlePath)), "factory-evidence-body-") {
			return fmt.Errorf("resources[%d] uses reserved bundle path %q", index, item.BundlePath)
		}
		if prior, duplicate := paths[pathKey]; duplicate {
			return fmt.Errorf("bundle path %q is duplicated by %s and resources[%d]", item.BundlePath, prior, index)
		}
		paths[pathKey] = fmt.Sprintf("resources[%d]", index)
	}
	priorCoordinate = ""
	packageRoles := make(map[string]struct{}, len(manifest.GeneratedDocuments))
	for index, item := range manifest.GeneratedDocuments {
		coordinate := item.coordinate()
		if err := validateSourcePackageCoordinate(coordinate); err != nil {
			return fmt.Errorf("generated_documents[%d]: %w", index, err)
		}
		key := sourcePackageCoordinateKey(coordinate)
		if key <= priorCoordinate {
			return fmt.Errorf("generated_documents are not unique and strictly ordered by role/id/version")
		}
		priorCoordinate = key
		if prior, duplicate := coordinates[coordinate]; duplicate {
			return fmt.Errorf("generated document coordinate %s duplicates %s", sourcePackageCoordinateLabel(coordinate), prior)
		}
		if err := validateSourcePackageBundlePath(item.BundlePath, fmt.Sprintf("generated_documents[%d].bundle_path", index)); err != nil {
			return err
		}
		pathKey := canonicalProviderInputPathKey(filepath.FromSlash(item.BundlePath))
		if prior, duplicate := paths[pathKey]; duplicate {
			return fmt.Errorf("bundle path %q is duplicated by %s and generated_documents[%d]", item.BundlePath, prior, index)
		}
		if _, reserved := sourcePackageReservedOutputPaths[pathKey]; reserved || strings.HasPrefix(filepath.Base(filepath.FromSlash(item.BundlePath)), "factory-evidence-body-") {
			return fmt.Errorf("generated_documents[%d] uses reserved bundle path %q", index, item.BundlePath)
		}
		paths[pathKey] = fmt.Sprintf("generated_documents[%d]", index)
		coordinates[coordinate] = fmt.Sprintf("generated_documents[%d]", index)
		if !isLowerSHA256(item.ExpectedRawSHA256) || item.ExpectedByteCount == 0 || item.ExpectedByteCount > uint64(maxExactStageCount) {
			return fmt.Errorf("generated_documents[%d] has an invalid raw digest or byte count", index)
		}
		if strings.TrimSpace(item.SubjectClass) == "" || item.SubjectClass != strings.TrimSpace(item.SubjectClass) || strings.TrimSpace(item.PayloadContractRef) == "" || item.PayloadContractRef != strings.TrimSpace(item.PayloadContractRef) || strings.TrimSpace(item.AuthorityClass) == "" || item.AuthorityClass != strings.TrimSpace(item.AuthorityClass) || !item.CandidateOnly || !item.BodyFree {
			return fmt.Errorf("generated_documents[%d] lacks candidate/body-free package metadata", index)
		}
		roleContract, registered := sourcePackageOutputRoleContracts[item.PackageRole]
		if !registered {
			return fmt.Errorf("generated_documents[%d] has unregistered package_role %q", index, item.PackageRole)
		}
		if _, duplicate := packageRoles[item.PackageRole]; duplicate {
			return fmt.Errorf("generated_documents[%d] duplicates package_role %q", index, item.PackageRole)
		}
		if item.TargetArtifactType != roleContract.targetArtifactType || item.Role != roleContract.artifactRole || !equalDocumentationFactorySourceOutputOwnerValidation(item.RequiredOwnerValidation, roleContract.requiredOwnerValidation) {
			return fmt.Errorf("generated_documents[%d] package_role %q has artifact role, target artifact type, or required owner-validation boundary outside its local contract", index, item.PackageRole)
		}
		packageRoles[item.PackageRole] = struct{}{}
	}
	if len(packageRoles) != len(sourcePackageOutputRoleContracts) {
		return fmt.Errorf("generated_documents package_role roster has %d members, want exact closed set of %d", len(packageRoles), len(sourcePackageOutputRoleContracts))
	}
	priorBody := ""
	for index, body := range manifest.EvidenceBodies {
		if err := validateSourcePackageCoordinate(body.Manifest); err != nil {
			return fmt.Errorf("evidence_bodies[%d].manifest: %w", index, err)
		}
		if err := validateSourcePackageCoordinate(body.Carrier); err != nil {
			return fmt.Errorf("evidence_bodies[%d].carrier: %w", index, err)
		}
		key := lengthPrefixedIdentityKey(sourcePackageCoordinateKey(body.Manifest), strconv.FormatUint(body.ComponentOrdinal, 10))
		if key <= priorBody {
			return fmt.Errorf("evidence_bodies are not unique and strictly ordered by manifest coordinate and component_ordinal")
		}
		priorBody = key
		if body.CarrierEncoding != sourcePackageCarrierRaw && body.CarrierEncoding != sourcePackageCarrierBase64 {
			return fmt.Errorf("evidence_bodies[%d] has unsupported carrier_encoding %q", index, body.CarrierEncoding)
		}
		if !isLowerSHA256(body.ExpectedBodySHA256) || body.ExpectedBodyByteCount == 0 || body.ExpectedBodyByteCount > uint64(maxExactStageCount) {
			return fmt.Errorf("evidence_bodies[%d] has an invalid body digest or byte count", index)
		}
	}
	return nil
}

func validateSourcePackageCoordinate(coordinate sourcePackageCoordinate) error {
	return validateStageMaterialCoordinate(stageMaterialCoordinate{Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version})
}

func sourcePackageCoordinateKey(coordinate sourcePackageCoordinate) string {
	return lengthPrefixedIdentityKey(coordinate.Role, coordinate.ID, coordinate.Version)
}

func sourcePackageCoordinateLabel(coordinate sourcePackageCoordinate) string {
	return coordinate.Role + "/" + coordinate.ID + "/" + coordinate.Version
}

func validateSourcePackageDeclaredPath(path, label string) error {
	native := filepath.FromSlash(path)
	if path == "" || path != strings.TrimSpace(path) || !filepath.IsLocal(native) || filepath.IsAbs(native) || filepath.VolumeName(native) != "" || !validEvidenceStagingPathComponents(native) {
		return fmt.Errorf("%s is empty, padded, or non-relative", label)
	}
	return nil
}

func validateSourcePackageBundlePath(path, label string) error {
	if err := validateSourcePackageDeclaredPath(path, label); err != nil {
		return err
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean != path || strings.HasPrefix(clean, ".") {
		return fmt.Errorf("%s must be canonical slash-separated relative path without a dot-prefixed component", label)
	}
	return nil
}

func decodeSourcePackageEvidenceBodies(declarations []sourcePackageEvidenceBodyDeclaration, materials map[sourcePackageCoordinate]sourcePackageMaterial, used map[sourcePackageCoordinate]struct{}) ([]StageEvidenceBody, error) {
	result := make([]StageEvidenceBody, len(declarations))
	for index, declaration := range declarations {
		_, manifestOK := materials[declaration.Manifest]
		carrier, carrierOK := materials[declaration.Carrier]
		if !manifestOK || !carrierOK {
			return nil, fmt.Errorf("evidence_bodies[%d] references an absent manifest or carrier", index)
		}
		used[declaration.Manifest] = struct{}{}
		used[declaration.Carrier] = struct{}{}
		var body []byte
		switch declaration.CarrierEncoding {
		case sourcePackageCarrierRaw:
			body = bytes.Clone(carrier.raw)
		case sourcePackageCarrierBase64:
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(carrier.raw)))
			if err != nil {
				return nil, fmt.Errorf("decode evidence_bodies[%d] base64 carrier: %w", index, err)
			}
			body = decoded
		default:
			return nil, fmt.Errorf("evidence_bodies[%d] has unsupported carrier encoding", index)
		}
		if sha256Hex(body) != declaration.ExpectedBodySHA256 || uint64(len(body)) != declaration.ExpectedBodyByteCount {
			return nil, fmt.Errorf("evidence_bodies[%d] decoded bytes differ from their exact pin", index)
		}
		result[index] = StageEvidenceBody{
			ManifestRole: declaration.Manifest.Role, ManifestID: declaration.Manifest.ID, ManifestVersion: declaration.Manifest.Version,
			ComponentOrdinal: declaration.ComponentOrdinal, Raw: body,
		}
	}
	return result, nil
}

func renderSourcePackageTemplate(raw []byte, materials map[sourcePackageCoordinate]sourcePackageMaterial, used map[sourcePackageCoordinate]struct{}) ([]byte, error) {
	var template sourcePackageTemplateDocument
	if err := strictUnmarshal(raw, &template); err != nil {
		return nil, fmt.Errorf("decode source-package template: %w", err)
	}
	if template.TemplateKind != documentationFactoryTemplateKind || template.TemplateVersion != documentationFactoryTemplateVersion {
		return nil, fmt.Errorf("source-package template identity is invalid")
	}
	hasDocument := len(bytes.TrimSpace(template.Document)) != 0 && !bytes.Equal(bytes.TrimSpace(template.Document), []byte("null"))
	switch template.OutputFormat {
	case sourcePackageTemplateFormatJSON:
		if !hasDocument || len(template.Rows) != 0 {
			return nil, fmt.Errorf("canonical_json template requires document and forbids rows")
		}
		value, err := decodeSourcePackageTemplateValue(template.Document)
		if err != nil {
			return nil, err
		}
		resolved, err := resolveSourcePackageTemplateValue(value, materials, used, 0)
		if err != nil {
			return nil, err
		}
		canonical, err := canonicalStageValue(resolved)
		if err != nil {
			return nil, err
		}
		return append(canonical, '\n'), nil
	case sourcePackageTemplateFormatJSONL:
		if hasDocument || len(template.Rows) == 0 {
			return nil, fmt.Errorf("canonical_jsonl template requires rows and forbids document")
		}
		var output []byte
		for index, rawRow := range template.Rows {
			value, err := decodeSourcePackageTemplateValue(rawRow)
			if err != nil {
				return nil, fmt.Errorf("template row %d: %w", index, err)
			}
			resolved, err := resolveSourcePackageTemplateValue(value, materials, used, 0)
			if err != nil {
				return nil, fmt.Errorf("template row %d: %w", index, err)
			}
			canonical, err := canonicalStageValue(resolved)
			if err != nil {
				return nil, fmt.Errorf("template row %d: %w", index, err)
			}
			output = append(output, canonical...)
			output = append(output, '\n')
		}
		return output, nil
	default:
		return nil, fmt.Errorf("source-package template output_format %q is unsupported", template.OutputFormat)
	}
}

func decodeSourcePackageTemplateValue(raw []byte) (interface{}, error) {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return nil, fmt.Errorf("template value has duplicate keys: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("template value has trailing JSON")
		}
		return nil, fmt.Errorf("decode trailing template value: %w", err)
	}
	return value, nil
}

func resolveSourcePackageTemplateValue(value interface{}, materials map[sourcePackageCoordinate]sourcePackageMaterial, used map[sourcePackageCoordinate]struct{}, depth int) (interface{}, error) {
	if depth > int(canonicalProviderInputAdmissionLimits.StructuredJSONNestingDepth) {
		return nil, fmt.Errorf("template resolution exceeds the deterministic nesting bound")
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		projectionValue, projection := typed["$resource_projection"]
		if projection {
			if len(typed) != 1 {
				return nil, fmt.Errorf("$resource_projection must be the sole member of its object")
			}
			rawProjection, err := canonicalStageValue(projectionValue)
			if err != nil {
				return nil, err
			}
			var declaration sourcePackageProjection
			if err := strictUnmarshal(rawProjection, &declaration); err != nil {
				return nil, fmt.Errorf("decode $resource_projection: %w", err)
			}
			material, ok := materials[declaration.Resource]
			if !ok {
				return nil, fmt.Errorf("$resource_projection references absent %s", sourcePackageCoordinateLabel(declaration.Resource))
			}
			used[declaration.Resource] = struct{}{}
			switch declaration.Projection {
			case sourcePackageProjectionSHA256:
				if declaration.JSONPointer != "" {
					return nil, fmt.Errorf("raw_sha256 projection forbids json_pointer")
				}
				return sha256Hex(material.raw), nil
			case sourcePackageProjectionByteCount:
				if declaration.JSONPointer != "" {
					return nil, fmt.Errorf("byte_count projection forbids json_pointer")
				}
				return json.Number(strconv.Itoa(len(material.raw))), nil
			case sourcePackageProjectionJSONValue:
				root, err := decodeSourcePackageTemplateValue(material.raw)
				if err != nil {
					return nil, fmt.Errorf("decode projected JSON resource %s: %w", sourcePackageCoordinateLabel(declaration.Resource), err)
				}
				return resolveSourcePackageJSONPointer(root, declaration.JSONPointer)
			default:
				return nil, fmt.Errorf("unsupported resource projection %q", declaration.Projection)
			}
		}
		result := make(map[string]interface{}, len(typed))
		for key, member := range typed {
			resolved, err := resolveSourcePackageTemplateValue(member, materials, used, depth+1)
			if err != nil {
				return nil, err
			}
			result[key] = resolved
		}
		return result, nil
	case []interface{}:
		result := make([]interface{}, len(typed))
		for index, member := range typed {
			resolved, err := resolveSourcePackageTemplateValue(member, materials, used, depth+1)
			if err != nil {
				return nil, err
			}
			result[index] = resolved
		}
		return result, nil
	default:
		return value, nil
	}
}

func resolveSourcePackageJSONPointer(root interface{}, pointer string) (interface{}, error) {
	if pointer == "" {
		return root, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("json_pointer %q is not empty or slash-prefixed", pointer)
	}
	current := root
	for _, encoded := range strings.Split(pointer[1:], "/") {
		for index := 0; index < len(encoded); index++ {
			if encoded[index] != '~' {
				continue
			}
			if index+1 >= len(encoded) || (encoded[index+1] != '0' && encoded[index+1] != '1') {
				return nil, fmt.Errorf("json_pointer %q contains an invalid escape in token %q", pointer, encoded)
			}
			index++
		}
		token := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch typed := current.(type) {
		case map[string]interface{}:
			next, ok := typed[token]
			if !ok {
				return nil, fmt.Errorf("json_pointer %q does not resolve member %q", pointer, token)
			}
			current = next
		case []interface{}:
			if token == "" || (len(token) > 1 && token[0] == '0') {
				return nil, fmt.Errorf("json_pointer %q has non-canonical array index %q", pointer, token)
			}
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, fmt.Errorf("json_pointer %q has out-of-range array index %q", pointer, token)
			}
			current = typed[index]
		default:
			return nil, fmt.Errorf("json_pointer %q traverses a scalar at %q", pointer, token)
		}
	}
	return current, nil
}

func validateSourcePackageOutputBodyFree(bodies []StageEvidenceBody, label string, raw []byte) error {
	exact := make(map[string]exactEvidenceBody, len(bodies))
	for _, body := range bodies {
		exact[sha256Hex(body.Raw)] = exactEvidenceBody{Bytes: body.Raw}
	}
	if err := validateNoEmbeddedEvidenceBodies(label, raw, exact, 1); err != nil {
		return fmt.Errorf("%s is not body-free: %w", label, err)
	}
	return nil
}

func sourcePackageMaterialForReference(materials map[sourcePackageCoordinate]sourcePackageMaterial, reference sourcePackageCoordinate, used map[sourcePackageCoordinate]struct{}) (sourcePackageMaterial, error) {
	material, ok := materials[reference]
	if !ok {
		return sourcePackageMaterial{}, fmt.Errorf("source package reference %s is absent", sourcePackageCoordinateLabel(reference))
	}
	used[reference] = struct{}{}
	return material, nil
}

func sourcePackageIdentityForReference(materials map[sourcePackageCoordinate]sourcePackageMaterial, reference sourcePackageCoordinate, used map[sourcePackageCoordinate]struct{}) (stageArtifactIdentity, error) {
	material, err := sourcePackageMaterialForReference(materials, reference, used)
	if err != nil {
		return stageArtifactIdentity{}, err
	}
	return stageArtifactIdentity{Role: reference.Role, ID: reference.ID, Version: reference.Version, RawSHA256: sha256Hex(material.raw)}, nil
}

func sourcePackagePinForReference(materials map[sourcePackageCoordinate]sourcePackageMaterial, reference sourcePackagePinReference, used map[sourcePackageCoordinate]struct{}) (immutableStageArtifactPin, error) {
	material, err := sourcePackageMaterialForReference(materials, reference.Resource, used)
	if err != nil {
		return immutableStageArtifactPin{}, err
	}
	if reference.AuthorityClass == "" || reference.AuthorityClass != strings.TrimSpace(reference.AuthorityClass) {
		return immutableStageArtifactPin{}, fmt.Errorf("source package pin %s has empty or padded authority_class", sourcePackageCoordinateLabel(reference.Resource))
	}
	if material.authorityClass != reference.AuthorityClass {
		return immutableStageArtifactPin{}, fmt.Errorf("source package pin %s authority_class %q differs from resource declaration %q", sourcePackageCoordinateLabel(reference.Resource), reference.AuthorityClass, material.authorityClass)
	}
	return immutableStageArtifactPin{
		Role: reference.Resource.Role, ID: reference.Resource.ID, Version: reference.Resource.Version,
		RawSHA256: sha256Hex(material.raw), AuthorityClass: reference.AuthorityClass,
	}, nil
}

func sourcePackageStageValidation(materials map[sourcePackageCoordinate]sourcePackageMaterial, plan sourcePackageStageValidationPlan, used map[sourcePackageCoordinate]struct{}) (stageValidationBinding, error) {
	schema, err := sourcePackagePinForReference(materials, plan.Schema, used)
	if err != nil {
		return stageValidationBinding{}, err
	}
	profile, err := sourcePackagePinForReference(materials, plan.Profile, used)
	if err != nil {
		return stageValidationBinding{}, err
	}
	return stageValidationBinding{Schema: schema, Profile: profile}, nil
}

func buildSourcePackageFactoryRequests(plan sourcePackageFactoryPlan, materials map[sourcePackageCoordinate]sourcePackageMaterial, bodies []StageEvidenceBody, used map[sourcePackageCoordinate]struct{}) ([4][]byte, [4][]StageMaterial, Options, error) {
	var requests [4][]byte
	var stageMaterials [4][]StageMaterial

	evidenceValidation, err := sourcePackageStageValidation(materials, plan.EvidenceIntake.StageValidation, used)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	pinAuthority := func(reference sourcePackagePinReference) (immutableStageArtifactPin, error) {
		return sourcePackagePinForReference(materials, reference, used)
	}
	oodPin, err := pinAuthority(plan.EvidenceIntake.AuthorityPins.OODGraph)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	visionPin, err := pinAuthority(plan.EvidenceIntake.AuthorityPins.GrandVision)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	sourcePin, err := pinAuthority(plan.EvidenceIntake.AuthorityPins.SourceRecord)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	extensionPin, err := pinAuthority(plan.EvidenceIntake.AuthorityPins.ExtensionProtocol)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	selection, err := sourcePackageIdentityForReference(materials, plan.EvidenceIntake.SelectionRoster, used)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	if len(plan.EvidenceIntake.EvidenceManifests) == 0 {
		return requests, stageMaterials, Options{}, fmt.Errorf("source package evidence_intake has no evidence manifests")
	}
	bodyStats := map[sourcePackageCoordinate]struct{ count, bytes uint64 }{}
	for _, body := range bodies {
		coordinate := sourcePackageCoordinate{Role: body.ManifestRole, ID: body.ManifestID, Version: body.ManifestVersion}
		stats := bodyStats[coordinate]
		stats.count++
		stats.bytes += uint64(len(body.Raw))
		bodyStats[coordinate] = stats
	}
	evidenceBindings := make([]evidenceManifestStageBinding, len(plan.EvidenceIntake.EvidenceManifests))
	for index, reference := range plan.EvidenceIntake.EvidenceManifests {
		identity, identityErr := sourcePackageIdentityForReference(materials, reference, used)
		if identityErr != nil {
			return requests, stageMaterials, Options{}, identityErr
		}
		stats := bodyStats[reference]
		if stats.count == 0 {
			return requests, stageMaterials, Options{}, fmt.Errorf("evidence manifest %s has no exact bodies", sourcePackageCoordinateLabel(reference))
		}
		evidenceBindings[index] = evidenceManifestStageBinding{
			Role: identity.Role, ArtifactID: identity.ID, ArtifactVersion: identity.Version, ArtifactRawSHA256: identity.RawSHA256,
			BodyCount: stats.count, ByteCount: stats.bytes,
		}
	}
	evidenceRequest := evidenceIntakeStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageEvidenceIntake,
		StageValidation: evidenceValidation,
		AuthorityPins:   stageAuthorityPins{OODGraph: oodPin, GrandVision: visionPin, SourceRecord: sourcePin, ExtensionProtocol: extensionPin},
		SelectionRoster: selection, EvidenceManifests: evidenceBindings,
	}
	requests[0], err = canonicalStageValue(evidenceRequest)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	stageMaterials[0], err = sourcePackageMaterialsForRequest(requests[0], materials)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	evidenceReceipt, err := CompileStageReceipt(requests[0], StageCompileInputs{Materials: stageMaterials[0], EvidenceBodies: cloneSourcePackageEvidenceBodies(bodies)})
	if err != nil {
		return requests, stageMaterials, Options{}, fmt.Errorf("precompile generated evidence_intake request: %w", err)
	}
	evidenceSummary, err := ValidateStageReceipt(evidenceReceipt)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}

	semanticValidation, err := sourcePackageStageValidation(materials, plan.SemanticExtraction.StageValidation, used)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	applicability, err := sourcePackagePinForReference(materials, plan.SemanticExtraction.ApplicabilityProfile, used)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	if len(plan.SemanticExtraction.ArtifactOutputs) == 0 || len(plan.SemanticExtraction.DerivationBindings) == 0 {
		return requests, stageMaterials, Options{}, fmt.Errorf("source package semantic_extraction has no outputs or derivation bindings")
	}
	semanticRoles := make([]semanticArtifactRole, len(plan.SemanticExtraction.ArtifactOutputs))
	semanticOutputs := make([]semanticArtifactOutput, len(plan.SemanticExtraction.ArtifactOutputs))
	for index, output := range plan.SemanticExtraction.ArtifactOutputs {
		identity, identityErr := sourcePackageIdentityForReference(materials, output.Resource, used)
		if identityErr != nil {
			return requests, stageMaterials, Options{}, identityErr
		}
		semanticRoles[index] = semanticArtifactRole{Role: identity.Role, Disposition: output.Disposition}
		semanticOutputs[index] = semanticArtifactOutput{
			Role: identity.Role, ArtifactID: identity.ID, ArtifactVersion: identity.Version,
			ArtifactRawSHA256: identity.RawSHA256, DerivationBindingIDs: append([]string(nil), output.DerivationBindingIDs...),
		}
	}
	semanticBindings := make([]semanticDerivationBinding, len(plan.SemanticExtraction.DerivationBindings))
	for index, binding := range plan.SemanticExtraction.DerivationBindings {
		extractor, extractorErr := sourcePackagePinForReference(materials, binding.Extractor, used)
		if extractorErr != nil {
			return requests, stageMaterials, Options{}, extractorErr
		}
		schema, schemaErr := sourcePackagePinForReference(materials, binding.Schema, used)
		if schemaErr != nil {
			return requests, stageMaterials, Options{}, schemaErr
		}
		semanticBindings[index] = semanticDerivationBinding{BindingID: binding.BindingID, Extractor: extractor, Schema: schema}
	}
	semanticRequest := semanticExtractionStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageSemanticExtraction,
		IntakeReceipt: stageRefFromSummary(evidenceSummary), StageValidation: semanticValidation, ApplicabilityProfile: applicability,
		ArtifactRoleRoster: semanticRoles, ArtifactOutputs: semanticOutputs, DerivationBindings: semanticBindings,
	}
	requests[1], err = canonicalStageValue(semanticRequest)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	stageMaterials[1], err = sourcePackageMaterialsForRequest(requests[1], materials)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	semanticReceipt, err := CompileStageReceipt(requests[1], StageCompileInputs{PredecessorReceipts: [][]byte{evidenceReceipt}, Materials: stageMaterials[1], EvidenceBodies: cloneSourcePackageEvidenceBodies(bodies)})
	if err != nil {
		return requests, stageMaterials, Options{}, fmt.Errorf("precompile generated semantic_extraction request: %w", err)
	}
	semanticSummary, err := ValidateStageReceipt(semanticReceipt)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}

	graphValidation, err := sourcePackageStageValidation(materials, plan.GraphCompile.StageValidation, used)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	graphDependencies := make([]stageArtifactIdentity, len(plan.GraphCompile.DependencyArtifacts))
	for index, reference := range plan.GraphCompile.DependencyArtifacts {
		identity, identityErr := sourcePackageIdentityForReference(materials, reference, used)
		if identityErr != nil {
			return requests, stageMaterials, Options{}, identityErr
		}
		graphDependencies[index] = identity
	}
	graphPlan, err := sourcePackageIdentityForReference(materials, plan.GraphCompile.Plan, used)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	graphProfileMaterial, err := sourcePackageMaterialForReference(materials, plan.GraphCompile.StageValidation.Profile.Resource, used)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	graphProfile, err := decodeStageValidationProfile(graphProfileMaterial.raw, stageGraphCompile, graphValidation.Profile)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	sets, err := deriveStageGraphSets(materials[plan.GraphCompile.Plan].raw, graphProfile.GraphRowDispositions)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	graphRequest := graphCompileStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageGraphCompile,
		ExtractionReceipts: []StageReceiptReference{stageRefFromSummary(semanticSummary)}, StageValidation: graphValidation,
		DependencyArtifacts: graphDependencies, Plan: graphPlan, Subjects: sets["subject"], Facts: sets["fact"], Gaps: sets["gap"],
	}
	requests[2], err = canonicalStageValue(graphRequest)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	stageMaterials[2], err = sourcePackageMaterialsForRequest(requests[2], materials)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	graphReceipt, err := CompileStageReceipt(requests[2], StageCompileInputs{PredecessorReceipts: [][]byte{semanticReceipt}, Materials: stageMaterials[2], EvidenceBodies: cloneSourcePackageEvidenceBodies(bodies)})
	if err != nil {
		return requests, stageMaterials, Options{}, fmt.Errorf("precompile generated graph_compile request: %w", err)
	}
	graphSummary, err := ValidateStageReceipt(graphReceipt)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}

	fullValidation, err := sourcePackageStageValidation(materials, plan.FullFactory.StageValidation, used)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	fullRequest := fullFactoryStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageFullFactory,
		StageValidation: fullValidation,
		PriorReceipts:   []StageReceiptReference{stageRefFromSummary(evidenceSummary), stageRefFromSummary(semanticSummary), stageRefFromSummary(graphSummary)},
	}
	requests[3], err = canonicalStageValue(fullRequest)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	stageMaterials[3], err = sourcePackageMaterialsForRequest(requests[3], materials)
	if err != nil {
		return requests, stageMaterials, Options{}, err
	}
	if _, err := CompileStageReceipt(requests[3], StageCompileInputs{PredecessorReceipts: [][]byte{evidenceReceipt, semanticReceipt, graphReceipt}, Materials: stageMaterials[3], EvidenceBodies: cloneSourcePackageEvidenceBodies(bodies)}); err != nil {
		return requests, stageMaterials, Options{}, fmt.Errorf("precompile generated full_factory request: %w", err)
	}

	preflightDependencies := make([]string, len(plan.PreflightDependencies))
	for index, reference := range plan.PreflightDependencies {
		material, materialErr := sourcePackageMaterialForReference(materials, reference, used)
		if materialErr != nil {
			return requests, stageMaterials, Options{}, materialErr
		}
		preflightDependencies[index] = material.bundlePath
	}
	evidenceManifestPaths := make([]string, len(plan.EvidenceIntake.EvidenceManifests))
	for index, reference := range plan.EvidenceIntake.EvidenceManifests {
		evidenceManifestPaths[index] = materials[reference].bundlePath
	}
	preflight := Options{
		OODSpecPath:                materials[plan.EvidenceIntake.AuthorityPins.OODGraph.Resource].bundlePath,
		ExpectedOODSpecSHA256:      oodPin.RawSHA256,
		GrandVisionPath:            materials[plan.EvidenceIntake.AuthorityPins.GrandVision.Resource].bundlePath,
		ExpectedGrandVisionSHA256:  visionPin.RawSHA256,
		SourceRecordSpecPath:       materials[plan.EvidenceIntake.AuthorityPins.SourceRecord.Resource].bundlePath,
		ExpectedSourceRecordSHA256: sourcePin.RawSHA256,
		EvidenceManifestPath:       evidenceManifestPaths,
		DependencyArtifactPath:     preflightDependencies,
	}
	return requests, stageMaterials, preflight, nil
}

func cloneSourcePackageEvidenceBodies(bodies []StageEvidenceBody) []StageEvidenceBody {
	cloned := make([]StageEvidenceBody, len(bodies))
	for index, body := range bodies {
		cloned[index] = body
		cloned[index].Raw = bytes.Clone(body.Raw)
	}
	return cloned
}

func stageRefFromSummary(summary StageReceiptSummary) StageReceiptReference {
	return StageReceiptReference{StageKind: summary.StageKind, ReceiptSHA256: summary.ReceiptSHA256, OutputRootSHA256: summary.OutputRootSHA256}
}

func sourcePackageMaterialsForRequest(requestRaw []byte, materials map[sourcePackageCoordinate]sourcePackageMaterial) ([]StageMaterial, error) {
	available := make(map[stageMaterialCoordinate]factoryDeclaredMaterial, len(materials))
	for coordinate, material := range materials {
		stageCoordinate := stageMaterialCoordinate{Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version}
		available[stageCoordinate] = factoryDeclaredMaterial{coordinate: stageCoordinate, path: material.bundlePath, raw: material.raw}
	}
	complete, err := completeFactoryStageMaterials(requestRaw, nil, available)
	if err != nil {
		return nil, err
	}
	for index := range complete {
		complete[index].Raw = bytes.Clone(complete[index].Raw)
	}
	return complete, nil
}

func assembleSourcePackageFactoryFiles(compilation *sourcePackageCompilation, requests [4][]byte, stageMaterials [4][]StageMaterial, bodies []StageEvidenceBody) error {
	if compilation == nil {
		return fmt.Errorf("source package compilation is nil")
	}
	declared := map[stageMaterialCoordinate]struct{}{}
	stageNames := []string{"evidence-intake", "semantic-extraction", "graph-compile", "full-factory"}
	for stageIndex, stageName := range stageNames {
		requestName := "factory-" + stageName + ".request.json"
		manifestName := "factory-" + stageName + ".inputs.json"
		if err := addSourcePackageCompilationFile(compilation.files, requestName, append(bytes.Clone(requests[stageIndex]), '\n'), true); err != nil {
			return err
		}
		manifest := stageCompileFileManifest{RequestPath: requestName, PredecessorReceiptPaths: []string{}, Materials: []stageCompileFileMaterial{}, EvidenceBodies: []stageCompileFileEvidenceBody{}}
		for _, material := range stageMaterials[stageIndex] {
			coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
			if _, alreadyDeclared := declared[coordinate]; alreadyDeclared {
				continue
			}
			source := compilation.materials[sourcePackageCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}]
			manifest.Materials = append(manifest.Materials, stageCompileFileMaterial{Role: material.Role, ID: material.ID, Version: material.Version, Path: source.bundlePath})
			declared[coordinate] = struct{}{}
		}
		if stageIndex == 0 {
			for bodyIndex, body := range bodies {
				bodyPath := fmt.Sprintf("factory-evidence-body-%06d.bin", bodyIndex)
				if err := addSourcePackageCompilationFile(compilation.files, bodyPath, body.Raw, true); err != nil {
					return err
				}
				manifest.EvidenceBodies = append(manifest.EvidenceBodies, stageCompileFileEvidenceBody{
					ManifestRole: body.ManifestRole, ManifestID: body.ManifestID, ManifestVersion: body.ManifestVersion,
					ComponentOrdinal: body.ComponentOrdinal, Path: bodyPath,
				})
			}
		}
		manifestRaw, err := canonicalStageValue(manifest)
		if err != nil {
			return err
		}
		if err := addSourcePackageCompilationFile(compilation.files, manifestName, append(manifestRaw, '\n'), true); err != nil {
			return err
		}
		compilation.stageManifestPaths[stageIndex] = manifestName
	}
	return nil
}

func addSourcePackageCompilationFile(files map[string][]byte, relative string, raw []byte, allowReserved bool) error {
	if files == nil {
		return fmt.Errorf("source package compilation file set is nil")
	}
	if err := validateSourcePackageBundlePath(relative, "source package compilation file"); err != nil {
		return err
	}
	key := canonicalProviderInputPathKey(filepath.FromSlash(relative))
	if !allowReserved {
		_, reserved := sourcePackageReservedOutputPaths[key]
		baseKey := strings.ToLower(filepath.Base(filepath.FromSlash(relative)))
		if reserved || strings.HasPrefix(baseKey, "factory-evidence-body-") {
			return fmt.Errorf("source package compilation file %q uses a reserved path", relative)
		}
	}
	for existing := range files {
		if canonicalProviderInputPathKey(filepath.FromSlash(existing)) == key {
			return fmt.Errorf("source package compilation file %q collides with %q", relative, existing)
		}
	}
	files[relative] = bytes.Clone(raw)
	return nil
}

func requireAllSourcePackageResourcesUsed(resources []sourcePackageResourceDeclaration, used map[sourcePackageCoordinate]struct{}) error {
	var unused []string
	for _, resource := range resources {
		if _, ok := used[resource.coordinate()]; !ok {
			unused = append(unused, sourcePackageCoordinateLabel(resource.coordinate()))
		}
	}
	if len(unused) != 0 {
		return fmt.Errorf("factory source package has unbound resources: %s", strings.Join(unused, ", "))
	}
	return nil
}

func requireAllSourcePackageGeneratedDocumentsUsed(documents []sourcePackageGeneratedDocument, used map[sourcePackageCoordinate]struct{}) error {
	var unused []string
	for _, document := range documents {
		if _, ok := used[document.coordinate()]; !ok {
			unused = append(unused, sourcePackageCoordinateLabel(document.coordinate()))
		}
	}
	if len(unused) != 0 {
		return fmt.Errorf("factory source package has unbound generated documents: %s", strings.Join(unused, ", "))
	}
	return nil
}

func validateSourcePackageGeneratedOutputLineage(manifest documentationFactorySourcePackage) (map[sourcePackageCoordinate]struct{}, error) {
	generatedByRole := make(map[string]sourcePackageGeneratedDocument, len(manifest.GeneratedDocuments))
	for _, document := range manifest.GeneratedDocuments {
		generatedByRole[document.PackageRole] = document
	}
	semanticOutputs := make(map[sourcePackageCoordinate]sourcePackageSemanticOutputPlan, len(manifest.FactoryPlan.SemanticExtraction.ArtifactOutputs))
	for _, output := range manifest.FactoryPlan.SemanticExtraction.ArtifactOutputs {
		semanticOutputs[output.Resource] = output
	}
	bound := make(map[sourcePackageCoordinate]struct{}, len(sourcePackageOutputRoleContracts))
	for _, packageRole := range []string{
		sourcePackageOutputRoleAPIGraphArtifact,
		sourcePackageOutputRoleReusableProfile,
		sourcePackageOutputRoleSourceMapping,
		sourcePackageOutputRoleResidualCircuitPackage,
		sourcePackageOutputRoleARCReferenceBlueprint,
	} {
		document, ok := generatedByRole[packageRole]
		if !ok {
			return nil, fmt.Errorf("runner output lineage omits package_role %q", packageRole)
		}
		contract := sourcePackageOutputRoleContracts[packageRole]
		coordinate := document.coordinate()
		if coordinate.Role != contract.artifactRole {
			return nil, fmt.Errorf("runner output lineage package_role %q binds artifact role %q, want %q", packageRole, coordinate.Role, contract.artifactRole)
		}
		switch {
		case contract.runnerStage == stageGraphCompile && contract.runnerSlot == "plan":
			if coordinate != manifest.FactoryPlan.GraphCompile.Plan {
				return nil, fmt.Errorf("runner output lineage package_role %q must set-equal graph_compile.plan", packageRole)
			}
		case contract.runnerStage == stageSemanticExtraction && contract.runnerSlot == "artifact_outputs":
			output, present := semanticOutputs[coordinate]
			if !present || len(output.DerivationBindingIDs) == 0 {
				return nil, fmt.Errorf("runner output lineage package_role %q must set-equal one schema-bound semantic_extraction.artifact_outputs member", packageRole)
			}
		default:
			return nil, fmt.Errorf("runner output lineage package_role %q has unsupported stage slot %s.%s", packageRole, contract.runnerStage, contract.runnerSlot)
		}
		bound[coordinate] = struct{}{}
	}
	if len(bound) != len(sourcePackageOutputRoleContracts) {
		return nil, fmt.Errorf("runner output lineage aliases package-role coordinates")
	}
	return bound, nil
}

func sealDocumentationFactorySourceReceipt(compilation sourcePackageCompilation, factory FactoryRunReceipt, productionVerification *DocumentationFactoryProductionSourceVerificationReceipt) (DocumentationFactorySourceCompileReceipt, error) {
	outputs := append([]DocumentationFactorySourceOutputReceipt(nil), compilation.generatedOutputs...)
	sort.Slice(outputs, func(i, j int) bool {
		return lengthPrefixedIdentityKey(outputs[i].PackageRole, outputs[i].ArtifactRole, outputs[i].ArtifactID, outputs[i].ArtifactVersion) < lengthPrefixedIdentityKey(outputs[j].PackageRole, outputs[j].ArtifactRole, outputs[j].ArtifactID, outputs[j].ArtifactVersion)
	})
	outputRows := make([]string, len(outputs))
	for index, output := range outputs {
		raw, err := canonicalFactoryJSON(output)
		if err != nil {
			return DocumentationFactorySourceCompileReceipt{}, err
		}
		outputRows[index] = string(raw)
	}
	files := sourcePackageBundleFileReceipts(compilation.files)
	fileRows := make([]string, len(files))
	for index, file := range files {
		raw, err := canonicalFactoryJSON(file)
		if err != nil {
			return DocumentationFactorySourceCompileReceipt{}, err
		}
		fileRows[index] = string(raw)
	}
	receipt := DocumentationFactorySourceCompileReceipt{
		ReceiptKind: documentationFactorySourceReceiptKind, ReceiptVersion: documentationFactorySourceReceiptVersion,
		Result: documentationFactorySourceResult, Scope: documentationFactorySourceScope,
		CompilerContractSHA256: sha256Hex([]byte(documentationFactorySourceContract)), SourcePackageSHA256: sha256Hex(compilation.packageRaw),
		SourceInputAdmissionProof: compilation.inputProof, SourceInputResources: compilation.inputResources,
		GeneratedOutputs: outputs, GeneratedOutputSetRootSHA256: sha256Hex([]byte(lengthPrefixedIdentityKey(outputRows...))),
		BundleFiles: files, BundleFileSetRootSHA256: sha256Hex([]byte(lengthPrefixedIdentityKey(fileRows...))),
		ReceiptPath: sourcePackageCompileReceiptPath, ReceiptExcludedFromBundleSet: true,
		FactoryPortableReceiptSHA256: factory.PortableReceiptSHA256, FactoryReceiptSHA256: factory.ReceiptSHA256,
		FactoryReceiptFileSHA256: sha256Hex(compilation.files[sourcePackageFactoryReceiptPath]),
		Completion:               factory.Completion, BodyFree: true,
	}
	if productionVerification != nil {
		verification := *productionVerification
		verification.EvidenceIdentities = cloneDocumentationFactoryProviderEvidenceIdentities(productionVerification.EvidenceIdentities)
		receipt.ProductionSourceVerification = &verification
	}
	if !receipt.Completion.Compiled || !receipt.Completion.Verified || !receipt.Completion.DerivationExecuted || receipt.Completion.GraphAdmittable || receipt.Completion.Admitted || receipt.Completion.CircuitAdmittable || receipt.Completion.CircuitAdmitted || receipt.Completion.Configured || receipt.Completion.CredentialProvisioned || receipt.Completion.Deployed || receipt.Completion.LiveTested || receipt.Completion.TwoTenantProven || receipt.Completion.SourceSubstitutionProven || receipt.Completion.AuthoritySelected || receipt.Completion.AdmissionAuthorized || receipt.Completion.FactoryComplete {
		return DocumentationFactorySourceCompileReceipt{}, fmt.Errorf("factory completion classification is not candidate-only")
	}
	identity := receipt
	identity.ReceiptSHA256 = ""
	raw, err := canonicalFactoryJSON(identity)
	if err != nil {
		return DocumentationFactorySourceCompileReceipt{}, err
	}
	receipt.ReceiptSHA256 = sha256Hex(raw)
	if err := validateDocumentationFactorySourceReceipt(receipt); err != nil {
		return DocumentationFactorySourceCompileReceipt{}, err
	}
	return receipt, nil
}

func validateDocumentationFactorySourceReceipt(receipt DocumentationFactorySourceCompileReceipt) error {
	if receipt.ReceiptKind != documentationFactorySourceReceiptKind || receipt.ReceiptVersion != documentationFactorySourceReceiptVersion || receipt.Result != documentationFactorySourceResult || receipt.Scope != documentationFactorySourceScope || receipt.CompilerContractSHA256 != sha256Hex([]byte(documentationFactorySourceContract)) || receipt.ReceiptPath != sourcePackageCompileReceiptPath || !receipt.ReceiptExcludedFromBundleSet || !receipt.BodyFree || receipt.AuthoritySelected || receipt.AdmissionAuthorized || receipt.FactoryComplete {
		return fmt.Errorf("source compiler receipt identity or candidate-only posture is invalid")
	}
	if !isLowerSHA256(receipt.SourcePackageSHA256) || !isLowerSHA256(receipt.GeneratedOutputSetRootSHA256) || !isLowerSHA256(receipt.BundleFileSetRootSHA256) || !isLowerSHA256(receipt.FactoryPortableReceiptSHA256) || !isLowerSHA256(receipt.FactoryReceiptSHA256) || !isLowerSHA256(receipt.FactoryReceiptFileSHA256) || !isLowerSHA256(receipt.ReceiptSHA256) {
		return fmt.Errorf("source compiler receipt has invalid digest fields")
	}
	if err := validateProviderInputAdmissionProof(receipt.SourceInputAdmissionProof, receipt.SourceInputResources); err != nil {
		return fmt.Errorf("source compiler receipt input admission: %w", err)
	}
	manifestBound := false
	for _, resource := range receipt.SourceInputResources {
		if resource.ResourceKind == providerInputAdmissionResourceKindStageManifest && resource.ContentSHA256 == receipt.SourcePackageSHA256 {
			manifestBound = true
			break
		}
	}
	if !manifestBound {
		return fmt.Errorf("source compiler receipt does not bind its source-package manifest in the input admission proof")
	}
	if receipt.ProductionSourceVerification != nil {
		verification := receipt.ProductionSourceVerification
		if err := validateDocumentationFactoryProductionSourceVerificationReceipt(*verification); err != nil {
			return fmt.Errorf("source compiler receipt production verification: %w", err)
		}
		if verification.SourcePackageSHA256 != receipt.SourcePackageSHA256 {
			return fmt.Errorf("source compiler receipt production verification binds a different source package")
		}
		inputIdentity := make(map[string]struct{}, len(receipt.SourceInputResources))
		for _, resource := range receipt.SourceInputResources {
			inputIdentity[lengthPrefixedIdentityKey(resource.ContentSHA256, fmt.Sprintf("%d", resource.ContentBytes))] = struct{}{}
		}
		if _, ok := inputIdentity[lengthPrefixedIdentityKey(verification.SourcePackageSHA256, fmt.Sprintf("%d", verification.SourcePackageByteCount))]; !ok {
			return fmt.Errorf("source compiler receipt production verification source package is absent from input admission")
		}
		for _, identity := range verification.EvidenceIdentities {
			for label, item := range map[string]struct {
				digest string
				count  int64
			}{
				"manifest": {digest: identity.ManifestRawSHA256, count: identity.ManifestByteCount},
				"carrier":  {digest: identity.CarrierRawSHA256, count: identity.CarrierByteCount},
			} {
				if _, ok := inputIdentity[lengthPrefixedIdentityKey(item.digest, fmt.Sprintf("%d", item.count))]; !ok {
					return fmt.Errorf("source compiler receipt production verification %s identity is absent from input admission", label)
				}
			}
		}
	}
	if !receipt.Completion.Compiled || !receipt.Completion.Verified || !receipt.Completion.DerivationExecuted || receipt.Completion.GraphAdmittable || receipt.Completion.Admitted || receipt.Completion.CircuitAdmittable || receipt.Completion.CircuitAdmitted || receipt.Completion.Configured || receipt.Completion.CredentialProvisioned || receipt.Completion.Deployed || receipt.Completion.LiveTested || receipt.Completion.TwoTenantProven || receipt.Completion.SourceSubstitutionProven || receipt.Completion.AuthoritySelected || receipt.Completion.AdmissionAuthorized || receipt.Completion.FactoryComplete {
		return fmt.Errorf("source compiler receipt completion classification is not candidate-only")
	}
	if len(receipt.GeneratedOutputs) == 0 || len(receipt.BundleFiles) == 0 {
		return fmt.Errorf("source compiler receipt has an empty generated-output or bundle-file roster")
	}
	outputRows := make([]string, len(receipt.GeneratedOutputs))
	priorOutput := ""
	seenPackageRoles := make(map[string]struct{}, len(receipt.GeneratedOutputs))
	seenOutputPaths := make(map[string]struct{}, len(receipt.GeneratedOutputs))
	seenOutputCoordinates := make(map[sourcePackageCoordinate]struct{}, len(receipt.GeneratedOutputs))
	for index, output := range receipt.GeneratedOutputs {
		key := lengthPrefixedIdentityKey(output.PackageRole, output.ArtifactRole, output.ArtifactID, output.ArtifactVersion)
		roleContract, registered := sourcePackageOutputRoleContracts[output.PackageRole]
		_, duplicateRole := seenPackageRoles[output.PackageRole]
		coordinate := sourcePackageCoordinate{Role: output.ArtifactRole, ID: output.ArtifactID, Version: output.ArtifactVersion}
		_, duplicateCoordinate := seenOutputCoordinates[coordinate]
		pathKey := canonicalProviderInputPathKey(filepath.FromSlash(output.RelativePath))
		_, duplicatePath := seenOutputPaths[pathKey]
		if key <= priorOutput || !registered || duplicateRole || duplicateCoordinate || duplicatePath || validateSourcePackageCoordinate(coordinate) != nil || output.SubjectClass == "" || output.PayloadContractRef == "" || output.AuthorityClass == "" || !isLowerSHA256(output.RawSHA256) || output.ByteCount <= 0 || output.TargetArtifactType != roleContract.targetArtifactType || !equalDocumentationFactorySourceOutputOwnerValidation(output.RequiredOwnerValidation, roleContract.requiredOwnerValidation) || !output.CandidateOnly || !output.BodyFree {
			return fmt.Errorf("source compiler receipt generated output %d is invalid or not strictly ordered", index)
		}
		seenPackageRoles[output.PackageRole] = struct{}{}
		seenOutputCoordinates[coordinate] = struct{}{}
		seenOutputPaths[pathKey] = struct{}{}
		if err := validateSourcePackageBundlePath(output.RelativePath, fmt.Sprintf("generated_outputs[%d].relative_path", index)); err != nil {
			return err
		}
		priorOutput = key
		rawOutput, err := canonicalFactoryJSON(output)
		if err != nil {
			return err
		}
		outputRows[index] = string(rawOutput)
	}
	if len(seenPackageRoles) != len(sourcePackageOutputRoleContracts) {
		return fmt.Errorf("source compiler receipt generated-output package-role roster is incomplete")
	}
	if sha256Hex([]byte(lengthPrefixedIdentityKey(outputRows...))) != receipt.GeneratedOutputSetRootSHA256 {
		return fmt.Errorf("source compiler receipt generated-output set root mismatch")
	}
	fileRows := make([]string, len(receipt.BundleFiles))
	priorPath := ""
	factoryReceiptBound := false
	sourceManifestBound := false
	bundleByPath := make(map[string]documentationFactorySourceBundleFileReceipt, len(receipt.BundleFiles))
	seenBundlePathKeys := make(map[string]struct{}, len(receipt.BundleFiles))
	for index, file := range receipt.BundleFiles {
		if err := validateSourcePackageBundlePath(file.RelativePath, fmt.Sprintf("bundle_files[%d].relative_path", index)); err != nil {
			return err
		}
		pathKey := canonicalProviderInputPathKey(filepath.FromSlash(file.RelativePath))
		_, duplicatePathKey := seenBundlePathKeys[pathKey]
		if file.RelativePath <= priorPath || duplicatePathKey || !isLowerSHA256(file.RawSHA256) || file.ByteCount < 0 || file.RelativePath == receipt.ReceiptPath {
			return fmt.Errorf("source compiler receipt bundle file %d is invalid, duplicated, unordered, or self-referential", index)
		}
		priorPath = file.RelativePath
		seenBundlePathKeys[pathKey] = struct{}{}
		bundleByPath[file.RelativePath] = file
		if file.RelativePath == sourcePackageFactoryReceiptPath {
			factoryReceiptBound = file.RawSHA256 == receipt.FactoryReceiptFileSHA256
		}
		if file.RelativePath == sourcePackageManifestBundlePath {
			sourceManifestBound = file.RawSHA256 == receipt.SourcePackageSHA256
		}
		rawFile, err := canonicalFactoryJSON(file)
		if err != nil {
			return err
		}
		fileRows[index] = string(rawFile)
	}
	if !factoryReceiptBound || !sourceManifestBound {
		return fmt.Errorf("source compiler receipt bundle roster omits or misbinds the factory receipt or source package manifest")
	}
	for _, output := range receipt.GeneratedOutputs {
		file, ok := bundleByPath[output.RelativePath]
		if !ok || file.RawSHA256 != output.RawSHA256 || file.ByteCount != output.ByteCount {
			return fmt.Errorf("source compiler generated output %q is absent from or differs from the bundle roster", output.PackageRole)
		}
	}
	if sha256Hex([]byte(lengthPrefixedIdentityKey(fileRows...))) != receipt.BundleFileSetRootSHA256 {
		return fmt.Errorf("source compiler receipt bundle-file set root mismatch")
	}
	identity := receipt
	identity.ReceiptSHA256 = ""
	raw, err := canonicalFactoryJSON(identity)
	if err != nil {
		return err
	}
	if sha256Hex(raw) != receipt.ReceiptSHA256 {
		return fmt.Errorf("source compiler receipt digest mismatch")
	}
	return nil
}

func sourcePackageBundleFileReceipts(files map[string][]byte) []documentationFactorySourceBundleFileReceipt {
	paths := sortedSourcePackageFilePaths(files)
	result := make([]documentationFactorySourceBundleFileReceipt, len(paths))
	for index, path := range paths {
		result[index] = documentationFactorySourceBundleFileReceipt{RelativePath: path, RawSHA256: sha256Hex(files[path]), ByteCount: int64(len(files[path]))}
	}
	return result
}

func sortedSourcePackageFilePaths(files map[string][]byte) []string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}
