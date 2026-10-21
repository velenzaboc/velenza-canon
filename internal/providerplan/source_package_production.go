package providerplan

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	documentationFactoryProductionSourceVerificationKind    = "provider_documentation_factory_production_source_verification"
	documentationFactoryProductionSourceVerificationVersion = "1"
	documentationFactoryProductionSourceVerificationResult  = "authenticated_current_complete_provider_evidence_identity_set_verified"
)

// DocumentationFactoryProductionSourceCompileOptions names the same sealed
// source package and absent output root used by the candidate compiler, plus
// one opaque receipt owned and authenticated by the source-evidence producer.
// The provider compiler never interprets that receipt as authority.
type DocumentationFactoryProductionSourceCompileOptions struct {
	SourcePackagePath       string
	VerificationReceiptPath string
	ExpectedProvider        string
	OutputRoot              string
}

// DocumentationFactoryProviderEvidenceIdentity is the complete body-free
// identity that the provider compiler derives from one declared evidence-body
// occurrence. The source owner authenticates and resolves these identities;
// the provider compiler neither authors source identity nor selects authority.
type DocumentationFactoryProviderEvidenceIdentity struct {
	ManifestRole           string `json:"manifest_role"`
	ManifestID             string `json:"manifest_id"`
	ManifestVersion        string `json:"manifest_version"`
	ManifestRawSHA256      string `json:"manifest_raw_sha256"`
	ManifestByteCount      int64  `json:"manifest_byte_count"`
	ComponentOrdinal       uint64 `json:"component_ordinal"`
	SourceContentSHA256    string `json:"source_content_sha256"`
	SourceContentByteCount int64  `json:"source_content_byte_count"`
	CarrierRole            string `json:"carrier_role"`
	CarrierID              string `json:"carrier_id"`
	CarrierVersion         string `json:"carrier_version"`
	CarrierRawSHA256       string `json:"carrier_raw_sha256"`
	CarrierByteCount       int64  `json:"carrier_byte_count"`
}

// DocumentationFactoryProductionSourceVerificationRequest is an exact,
// body-free request to the source-owner verifier. VerificationReceiptRaw is
// opaque input to that verifier and is never decoded into trusted booleans by
// this package or serialized into a factory receipt.
type DocumentationFactoryProductionSourceVerificationRequest struct {
	ExpectedProvider              string
	SourcePackageSHA256           string
	SourcePackageByteCount        int64
	EvidenceIdentities            []DocumentationFactoryProviderEvidenceIdentity
	EvidenceIdentitySetRootSHA256 string
	VerificationReceiptRaw        []byte
	VerificationReceiptSHA256     string
	VerificationReceiptByteCount  int64
	ObservedAt                    string
}

// DocumentationFactoryProductionSourceVerification is process-returned
// verifier evidence, never caller-authored package data. The selected verifier
// owns producer authentication, current-generation resolution, and complete
// identity-set equality. This package independently checks every returned
// coordinate against its measured request before the factory may run.
type DocumentationFactoryProductionSourceVerification struct {
	Provider                            string
	SourcePackageSHA256                 string
	EvidenceIdentitySetRootSHA256       string
	VerificationReceiptSHA256           string
	VerifiedAt                          string
	ProducerAuthenticated               bool
	CurrentGenerationVerified           bool
	CompleteEvidenceIdentitySetVerified bool
	TestOwned                           bool
}

// DocumentationFactoryProductionSourceVerifier is the only production trust
// seam. Implementations must be selected by production boot from the admitted
// source-evidence producer; a package, command flag, or receipt cannot select
// an implementation.
type DocumentationFactoryProductionSourceVerifier interface {
	VerifyDocumentationFactoryProductionSourcePackage(context.Context, DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error)
}

// DocumentationFactoryProductionSourceVerificationReceipt is the body-free
// binding embedded into the ordinary source-compile receipt. It attests only
// that the separately owned verifier accepted the exact source package and
// evidence identity set at one observed instant. All factory outputs remain
// candidate-only and receive no admission, configuration, deployment, tenant,
// credential, source-materialization, or live-provider authority.
type DocumentationFactoryProductionSourceVerificationReceipt struct {
	VerificationKind                    string                                         `json:"verification_kind"`
	VerificationVersion                 string                                         `json:"verification_version"`
	Result                              string                                         `json:"result"`
	Provider                            string                                         `json:"provider"`
	ObservedAt                          string                                         `json:"observed_at"`
	SourcePackageSHA256                 string                                         `json:"source_package_sha256"`
	SourcePackageByteCount              int64                                          `json:"source_package_byte_count"`
	EvidenceIdentities                  []DocumentationFactoryProviderEvidenceIdentity `json:"provider_evidence_identities"`
	EvidenceIdentitySetRootSHA256       string                                         `json:"provider_evidence_identity_set_root_sha256"`
	VerificationReceiptSHA256           string                                         `json:"source_owner_verification_receipt_sha256"`
	VerificationReceiptByteCount        int64                                          `json:"source_owner_verification_receipt_byte_count"`
	ProducerAuthenticated               bool                                           `json:"producer_authenticated"`
	CurrentGenerationVerified           bool                                           `json:"current_generation_verified"`
	CompleteEvidenceIdentitySetVerified bool                                           `json:"complete_evidence_identity_set_verified"`
	TestOwned                           bool                                           `json:"test_owned"`
	BindingSHA256                       string                                         `json:"binding_sha256"`
}

type documentationFactoryProductionSourceCompilerDependencies struct {
	SourceCompiler documentationFactorySourceCompilerDependencies
	Now            func() time.Time
}

// CompileDocumentationFactoryProductionSourcePackage runs the identical
// sealed-package compiler only after the selected source-owner verifier accepts
// the exact package and provider-evidence identity set. No verifier is inferred
// from caller data; a nil verifier refuses before the factory runs.
func CompileDocumentationFactoryProductionSourcePackage(ctx context.Context, options DocumentationFactoryProductionSourceCompileOptions, verifier DocumentationFactoryProductionSourceVerifier) (DocumentationFactorySourceCompileResult, error) {
	return compileDocumentationFactoryProductionSourcePackageWithDependencies(ctx, options, verifier, documentationFactoryProductionSourceCompilerDependencies{
		SourceCompiler: defaultDocumentationFactorySourceCompilerDependencies(),
		Now:            time.Now,
	})
}

func compileDocumentationFactoryProductionSourcePackageWithDependencies(ctx context.Context, options DocumentationFactoryProductionSourceCompileOptions, verifier DocumentationFactoryProductionSourceVerifier, dependencies documentationFactoryProductionSourceCompilerDependencies) (DocumentationFactorySourceCompileResult, error) {
	if ctx == nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("production source-package context is required")
	}
	if verifier == nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("production source-package verifier is required")
	}
	if dependencies.Now == nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("production source-package clock is required")
	}
	sourceOptions := DocumentationFactorySourceCompileOptions{SourcePackagePath: options.SourcePackagePath, OutputRoot: options.OutputRoot}
	if err := validateDocumentationFactorySourceCompilerInputs(sourceOptions, dependencies.SourceCompiler); err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	if strings.TrimSpace(options.VerificationReceiptPath) == "" || options.VerificationReceiptPath != strings.TrimSpace(options.VerificationReceiptPath) {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("production source-package verification receipt path is empty or padded")
	}
	if strings.TrimSpace(options.ExpectedProvider) == "" || options.ExpectedProvider != strings.TrimSpace(options.ExpectedProvider) || !stageIdentifierPattern.MatchString(options.ExpectedProvider) {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("production source-package expected provider is empty or noncanonical")
	}

	compilation, err := prepareDocumentationFactorySourceCompilation(options.SourcePackagePath)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	identities, identityRoot, err := deriveDocumentationFactoryProviderEvidenceIdentities(compilation)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	verificationAccumulator := newCanonicalProviderInputAdmissionAccumulator()
	verificationFile, err := readBoundedProviderInputFile(options.VerificationReceiptPath, "production source-package verification receipt", providerInputAdmissionResourceKindArtifact, "production_source_package_verification_receipt_v1", verificationAccumulator)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	if err := validateSourcePackageOutputBodyFree(compilation.evidenceBodies, "production source-package verification receipt", verificationFile.Bytes); err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	now := dependencies.Now()
	if now.IsZero() {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("production source-package clock returned zero time")
	}
	observedAt := now.UTC().Format(time.RFC3339Nano)
	request := DocumentationFactoryProductionSourceVerificationRequest{
		ExpectedProvider:              options.ExpectedProvider,
		SourcePackageSHA256:           sha256Hex(compilation.packageRaw),
		SourcePackageByteCount:        int64(len(compilation.packageRaw)),
		EvidenceIdentities:            cloneDocumentationFactoryProviderEvidenceIdentities(identities),
		EvidenceIdentitySetRootSHA256: identityRoot,
		VerificationReceiptRaw:        bytes.Clone(verificationFile.Bytes),
		VerificationReceiptSHA256:     verificationFile.SHA256,
		VerificationReceiptByteCount:  verificationFile.Size,
		ObservedAt:                    observedAt,
	}
	answer, err := verifier.VerifyDocumentationFactoryProductionSourcePackage(ctx, request)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("production source-package verification refused: %w", err)
	}
	verification, err := sealDocumentationFactoryProductionSourceVerification(request, answer)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	revalidateVerification := func() error {
		if err := verificationAccumulator.revalidatePhysicalSnapshots(); err != nil {
			return err
		}
		return nil
	}
	result, err := compilePreparedDocumentationFactorySourcePackage(sourceOptions, compilation, dependencies.SourceCompiler, &verification, revalidateVerification)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, err
	}
	if result.FactoryReceipt.PreflightReceipt.Provider != options.ExpectedProvider {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("verified production source-package provider %q does not match compiled provider %q", options.ExpectedProvider, result.FactoryReceipt.PreflightReceipt.Provider)
	}
	return result, nil
}

func deriveDocumentationFactoryProviderEvidenceIdentities(compilation sourcePackageCompilation) ([]DocumentationFactoryProviderEvidenceIdentity, string, error) {
	identities := make([]DocumentationFactoryProviderEvidenceIdentity, 0, len(compilation.manifest.EvidenceBodies))
	for index, declaration := range compilation.manifest.EvidenceBodies {
		manifest, manifestOK := compilation.materials[declaration.Manifest]
		carrier, carrierOK := compilation.materials[declaration.Carrier]
		if !manifestOK || !carrierOK {
			return nil, "", fmt.Errorf("production provider evidence identity[%d] has unresolved manifest or carrier", index)
		}
		identities = append(identities, DocumentationFactoryProviderEvidenceIdentity{
			ManifestRole: declaration.Manifest.Role, ManifestID: declaration.Manifest.ID, ManifestVersion: declaration.Manifest.Version,
			ManifestRawSHA256: sha256Hex(manifest.raw), ManifestByteCount: int64(len(manifest.raw)),
			ComponentOrdinal: declaration.ComponentOrdinal, SourceContentSHA256: declaration.ExpectedBodySHA256, SourceContentByteCount: int64(declaration.ExpectedBodyByteCount),
			CarrierRole: declaration.Carrier.Role, CarrierID: declaration.Carrier.ID, CarrierVersion: declaration.Carrier.Version,
			CarrierRawSHA256: sha256Hex(carrier.raw), CarrierByteCount: int64(len(carrier.raw)),
		})
	}
	sort.Slice(identities, func(i, j int) bool {
		return documentationFactoryProviderEvidenceIdentityKey(identities[i]) < documentationFactoryProviderEvidenceIdentityKey(identities[j])
	})
	root, err := documentationFactoryProviderEvidenceIdentitySetRoot(identities)
	if err != nil {
		return nil, "", err
	}
	return identities, root, nil
}

func sealDocumentationFactoryProductionSourceVerification(request DocumentationFactoryProductionSourceVerificationRequest, answer DocumentationFactoryProductionSourceVerification) (DocumentationFactoryProductionSourceVerificationReceipt, error) {
	if answer.TestOwned {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("production source-package verifier returned test-owned evidence")
	}
	if !answer.ProducerAuthenticated {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("production source-package verification lacks an authenticated producer")
	}
	if !answer.CurrentGenerationVerified {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("production source-package verification does not establish the current generation")
	}
	if !answer.CompleteEvidenceIdentitySetVerified {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("production source-package verification does not establish the complete evidence identity set")
	}
	if answer.Provider != request.ExpectedProvider {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("production source-package verification provider %q does not match expected provider %q", answer.Provider, request.ExpectedProvider)
	}
	if answer.SourcePackageSHA256 != request.SourcePackageSHA256 {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("production source-package verification does not bind the exact source package")
	}
	if answer.EvidenceIdentitySetRootSHA256 != request.EvidenceIdentitySetRootSHA256 {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("production source-package verification does not bind the exact provider evidence identity set")
	}
	if answer.VerificationReceiptSHA256 != request.VerificationReceiptSHA256 {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("production source-package verification does not bind the exact verification receipt")
	}
	if answer.VerifiedAt != request.ObservedAt {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("production source-package verification is stale or bound to a different observation instant")
	}
	receipt := DocumentationFactoryProductionSourceVerificationReceipt{
		VerificationKind: documentationFactoryProductionSourceVerificationKind, VerificationVersion: documentationFactoryProductionSourceVerificationVersion,
		Result: documentationFactoryProductionSourceVerificationResult, Provider: answer.Provider, ObservedAt: answer.VerifiedAt,
		SourcePackageSHA256: request.SourcePackageSHA256, SourcePackageByteCount: request.SourcePackageByteCount,
		EvidenceIdentities: cloneDocumentationFactoryProviderEvidenceIdentities(request.EvidenceIdentities), EvidenceIdentitySetRootSHA256: request.EvidenceIdentitySetRootSHA256,
		VerificationReceiptSHA256: request.VerificationReceiptSHA256, VerificationReceiptByteCount: request.VerificationReceiptByteCount,
		ProducerAuthenticated: answer.ProducerAuthenticated, CurrentGenerationVerified: answer.CurrentGenerationVerified,
		CompleteEvidenceIdentitySetVerified: answer.CompleteEvidenceIdentitySetVerified, TestOwned: answer.TestOwned,
	}
	raw, err := canonicalFactoryJSON(receipt)
	if err != nil {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, fmt.Errorf("serialize production source-package verification binding: %w", err)
	}
	receipt.BindingSHA256 = sha256Hex(raw)
	if err := validateDocumentationFactoryProductionSourceVerificationReceipt(receipt); err != nil {
		return DocumentationFactoryProductionSourceVerificationReceipt{}, err
	}
	return receipt, nil
}

func validateDocumentationFactoryProductionSourceVerificationReceipt(receipt DocumentationFactoryProductionSourceVerificationReceipt) error {
	if receipt.VerificationKind != documentationFactoryProductionSourceVerificationKind || receipt.VerificationVersion != documentationFactoryProductionSourceVerificationVersion || receipt.Result != documentationFactoryProductionSourceVerificationResult {
		return fmt.Errorf("production source-package verification receipt kind/version/result is invalid")
	}
	if !stageIdentifierPattern.MatchString(receipt.Provider) {
		return fmt.Errorf("production source-package verification receipt provider is invalid")
	}
	observedAt, err := time.Parse(time.RFC3339Nano, receipt.ObservedAt)
	if err != nil || observedAt.UTC().Format(time.RFC3339Nano) != receipt.ObservedAt {
		return fmt.Errorf("production source-package verification receipt observed_at is not canonical UTC RFC3339")
	}
	if receipt.SourcePackageByteCount <= 0 || receipt.VerificationReceiptByteCount <= 0 {
		return fmt.Errorf("production source-package verification receipt byte counts are invalid")
	}
	for name, digest := range map[string]string{
		"source_package_sha256":                      receipt.SourcePackageSHA256,
		"provider_evidence_identity_set_root_sha256": receipt.EvidenceIdentitySetRootSHA256,
		"source_owner_verification_receipt_sha256":   receipt.VerificationReceiptSHA256,
		"binding_sha256":                             receipt.BindingSHA256,
	} {
		if !isLowerSHA256(digest) {
			return fmt.Errorf("production source-package verification receipt %s is invalid", name)
		}
	}
	if receipt.TestOwned || !receipt.ProducerAuthenticated || !receipt.CurrentGenerationVerified || !receipt.CompleteEvidenceIdentitySetVerified {
		return fmt.Errorf("production source-package verification receipt trust verdict is not production-eligible")
	}
	wantRoot, err := documentationFactoryProviderEvidenceIdentitySetRoot(receipt.EvidenceIdentities)
	if err != nil {
		return err
	}
	if wantRoot != receipt.EvidenceIdentitySetRootSHA256 {
		return fmt.Errorf("production source-package verification receipt evidence identity root mismatch")
	}
	copyReceipt := receipt
	copyReceipt.BindingSHA256 = ""
	raw, err := canonicalFactoryJSON(copyReceipt)
	if err != nil {
		return err
	}
	if sha256Hex(raw) != receipt.BindingSHA256 {
		return fmt.Errorf("production source-package verification receipt binding hash mismatch")
	}
	return nil
}

func documentationFactoryProviderEvidenceIdentitySetRoot(identities []DocumentationFactoryProviderEvidenceIdentity) (string, error) {
	if len(identities) == 0 {
		return "", fmt.Errorf("production source-package evidence identity set is empty")
	}
	rows := make([]string, len(identities))
	prior := ""
	for index, identity := range identities {
		if err := validateDocumentationFactoryProviderEvidenceIdentity(identity); err != nil {
			return "", fmt.Errorf("production source-package evidence identity[%d]: %w", index, err)
		}
		key := documentationFactoryProviderEvidenceIdentityKey(identity)
		if index != 0 && key <= prior {
			return "", fmt.Errorf("production source-package evidence identity set is unsorted or duplicated")
		}
		prior = key
		raw, err := canonicalFactoryJSON(identity)
		if err != nil {
			return "", err
		}
		rows[index] = string(raw)
	}
	return sha256Hex([]byte(lengthPrefixedIdentityKey(rows...))), nil
}

func validateDocumentationFactoryProviderEvidenceIdentity(identity DocumentationFactoryProviderEvidenceIdentity) error {
	if err := validateSourcePackageCoordinate(sourcePackageCoordinate{Role: identity.ManifestRole, ID: identity.ManifestID, Version: identity.ManifestVersion}); err != nil {
		return fmt.Errorf("manifest coordinate: %w", err)
	}
	if err := validateSourcePackageCoordinate(sourcePackageCoordinate{Role: identity.CarrierRole, ID: identity.CarrierID, Version: identity.CarrierVersion}); err != nil {
		return fmt.Errorf("carrier coordinate: %w", err)
	}
	for name, value := range map[string]string{
		"manifest_role": identity.ManifestRole, "manifest_id": identity.ManifestID, "manifest_version": identity.ManifestVersion,
		"carrier_role": identity.CarrierRole, "carrier_id": identity.CarrierID, "carrier_version": identity.CarrierVersion,
	} {
		if value == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("%s is empty or padded", name)
		}
	}
	for name, digest := range map[string]string{
		"manifest_raw_sha256":   identity.ManifestRawSHA256,
		"source_content_sha256": identity.SourceContentSHA256,
		"carrier_raw_sha256":    identity.CarrierRawSHA256,
	} {
		if !isLowerSHA256(digest) {
			return fmt.Errorf("%s is invalid", name)
		}
	}
	if identity.ManifestByteCount <= 0 || identity.SourceContentByteCount <= 0 || identity.CarrierByteCount <= 0 {
		return fmt.Errorf("byte count is invalid")
	}
	return nil
}

func documentationFactoryProviderEvidenceIdentityKey(identity DocumentationFactoryProviderEvidenceIdentity) string {
	return lengthPrefixedIdentityKey(
		identity.ManifestRole, identity.ManifestID, identity.ManifestVersion,
		fmt.Sprintf("%020d", identity.ComponentOrdinal), identity.SourceContentSHA256,
		identity.CarrierRole, identity.CarrierID, identity.CarrierVersion,
	)
}

func cloneDocumentationFactoryProviderEvidenceIdentities(values []DocumentationFactoryProviderEvidenceIdentity) []DocumentationFactoryProviderEvidenceIdentity {
	return append([]DocumentationFactoryProviderEvidenceIdentity(nil), values...)
}
