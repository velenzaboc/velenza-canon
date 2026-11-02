package providerplan

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DocumentationFactoryProductionSourceOwnerAuthorityReader is selected by the
// production boot, not by a source package, receipt, or command argument. It
// owns authentication of the opaque receipt bytes and resolution of one
// producer's current immutable evidence generation.
//
// The reader's result is deliberately a typed authority observation rather
// than a caller-authored verdict. The adapter below independently checks every
// measured package, receipt, time, and complete identity-set coordinate before
// returning the compiler's much smaller verification verdict.
type DocumentationFactoryProductionSourceOwnerAuthorityReader interface {
	ReadCurrentAuthenticatedProviderEvidence(context.Context, DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceOwnerCurrentGeneration, error)
}

// DocumentationFactoryProductionSourceOwnerCurrentGeneration is the complete
// body-free observation the independently-owned source authority must return.
// No field is taken from the source package as authoritative: each is exact
// compared to compiler-measured inputs below. Authentication and currentness
// are represented by non-empty, owner-issued binding coordinates rather than
// caller-supplied boolean claims.
type DocumentationFactoryProductionSourceOwnerCurrentGeneration struct {
	Provider                            string
	OrganizationID                      string
	SourceOwnerID                       string
	AuthenticatedProducerID             string
	ProducerAuthenticationBindingRef    string
	ProducerAuthenticationBindingSHA256 string
	CurrentGeneration                   uint64
	CurrentGenerationBindingSHA256      string
	SourcePackageSHA256                 string
	SourcePackageByteCount              int64
	VerificationReceiptSHA256           string
	VerificationReceiptByteCount        int64
	EvidenceIdentities                  []DocumentationFactoryProviderEvidenceIdentity
	EvidenceIdentitySetRootSHA256       string
	VerifiedAt                          string
	TestOwned                           bool
}

// DocumentationFactoryProductionSourceOwnerBindingExpectation is selected by
// production boot from the independently admitted owner binding. None of its
// fields are accepted from a package, receipt, or command-line argument.
// CurrentGeneration is intentionally absent: it is resolved fresh by the
// source-owner reader and cannot be frozen in a binary.
type DocumentationFactoryProductionSourceOwnerBindingExpectation struct {
	Provider                            string
	OrganizationID                      string
	SourceOwnerID                       string
	AuthenticatedProducerID             string
	ProducerAuthenticationBindingRef    string
	ProducerAuthenticationBindingSHA256 string
}

type documentationFactoryProductionSourceOwnerVerifier struct {
	expected DocumentationFactoryProductionSourceOwnerBindingExpectation
	reader   DocumentationFactoryProductionSourceOwnerAuthorityReader
}

// DocumentationFactoryProductionSourceBootResolver is supplied by the
// protected process bootstrap.  It is deliberately separate from all source
// package and command options: those inputs can name evidence, but cannot
// choose an organization, provider binding, Spanner client, or verifier.
type DocumentationFactoryProductionSourceBootResolver interface {
	ResolveDocumentationFactoryProductionSourceVerifier(context.Context) (DocumentationFactoryProductionSourceVerifier, error)
}

// DocumentationFactoryProductionSourceBootComposition is the concrete boot
// composition used by protected launchers after they have selected their
// existing authorized client and OOD proof authority.  No credentials are
// created here.
type DocumentationFactoryProductionSourceBootComposition struct {
	Expected DocumentationFactoryProductionSourceOwnerBindingExpectation
	Reader   DocumentationFactoryProductionSourceOODStrongReader
}

func (c DocumentationFactoryProductionSourceBootComposition) ResolveDocumentationFactoryProductionSourceVerifier(ctx context.Context) (DocumentationFactoryProductionSourceVerifier, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return NewDocumentationFactoryProductionSourceOODCurrentVerifier(c.Expected, c.Reader)
}

func (v documentationFactoryProductionSourceOwnerVerifier) VerifyDocumentationFactoryProductionSourcePackage(ctx context.Context, request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceVerification, error) {
	if err := ctx.Err(); err != nil {
		return DocumentationFactoryProductionSourceVerification{}, err
	}
	if v.reader == nil {
		return DocumentationFactoryProductionSourceVerification{}, fmt.Errorf("production source-owner authority reader is not boot configured")
	}
	if err := validateDocumentationFactoryProductionSourceVerificationRequest(request); err != nil {
		return DocumentationFactoryProductionSourceVerification{}, err
	}
	if request.ExpectedProvider != v.expected.Provider {
		return DocumentationFactoryProductionSourceVerification{}, fmt.Errorf("source package provider does not equal the boot-selected provider")
	}
	observed, err := v.reader.ReadCurrentAuthenticatedProviderEvidence(ctx, cloneDocumentationFactoryProductionSourceVerificationRequest(request))
	if err != nil {
		return DocumentationFactoryProductionSourceVerification{}, fmt.Errorf("source-owner authority refused verification: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return DocumentationFactoryProductionSourceVerification{}, err
	}
	if err := validateDocumentationFactoryProductionSourceOwnerCurrentGeneration(request, v.expected, observed); err != nil {
		return DocumentationFactoryProductionSourceVerification{}, err
	}
	return DocumentationFactoryProductionSourceVerification{
		Provider:                            observed.Provider,
		SourcePackageSHA256:                 observed.SourcePackageSHA256,
		EvidenceIdentitySetRootSHA256:       observed.EvidenceIdentitySetRootSHA256,
		VerificationReceiptSHA256:           observed.VerificationReceiptSHA256,
		VerifiedAt:                          observed.VerifiedAt,
		ProducerAuthenticated:               true,
		CurrentGenerationVerified:           true,
		CompleteEvidenceIdentitySetVerified: true,
		TestOwned:                           false,
	}, nil
}

// NewDocumentationFactoryProductionSourceOwnerVerifier is for boot
// composition only. The factory's source-package and CLI inputs cannot call
// this constructor or select the reader; production wiring must supply the
// independently admitted source-owner adapter.
func NewDocumentationFactoryProductionSourceOwnerVerifier(expected DocumentationFactoryProductionSourceOwnerBindingExpectation, reader DocumentationFactoryProductionSourceOwnerAuthorityReader) (DocumentationFactoryProductionSourceVerifier, error) {
	if err := validateDocumentationFactoryProductionSourceOwnerBindingExpectation(expected); err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("production source-owner authority reader is required")
	}
	return documentationFactoryProductionSourceOwnerVerifier{expected: expected, reader: reader}, nil
}

// BootSelectedDocumentationFactoryProductionSourceVerifier exposes the
// process's fixed production selection. This source tree has no admitted
// producer-authority reader or provisioned production owner binding, so it is
// intentionally unavailable. A deployment must bind the typed reader at boot;
// receipt bytes remain only owner-authenticated lookup input.
// BootSelectedDocumentationFactoryProductionSourceVerifier remains for older
// in-process callers. New command composition calls the error-returning
// resolver below so an unavailable protected boot cannot masquerade as a
// selected verifier.
func BootSelectedDocumentationFactoryProductionSourceVerifier() DocumentationFactoryProductionSourceVerifier {
	return documentationFactoryProductionSourceOwnerVerifier{}
}

// ResolveDocumentationFactoryProductionSourceVerifier obtains the verifier
// from the process bootstrap. The ordinary source tree intentionally has no
// ambient credential or mutable configuration fallback; a protected launcher
// provides the resolver through its operations composition.
func ResolveDocumentationFactoryProductionSourceVerifier(ctx context.Context, resolver DocumentationFactoryProductionSourceBootResolver) (DocumentationFactoryProductionSourceVerifier, error) {
	if resolver == nil {
		return nil, fmt.Errorf("production source verifier boot resolver is required")
	}
	verifier, err := resolver.ResolveDocumentationFactoryProductionSourceVerifier(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve protected production source verifier: %w", err)
	}
	if verifier == nil {
		return nil, fmt.Errorf("protected production source verifier is unavailable")
	}
	return verifier, nil
}

func validateDocumentationFactoryProductionSourceVerificationRequest(request DocumentationFactoryProductionSourceVerificationRequest) error {
	if !stageIdentifierPattern.MatchString(request.ExpectedProvider) || request.SourcePackageByteCount <= 0 || request.VerificationReceiptByteCount <= 0 || len(request.VerificationReceiptRaw) == 0 {
		return fmt.Errorf("production source-owner verification request is incomplete")
	}
	for name, digest := range map[string]string{
		"source_package_sha256": request.SourcePackageSHA256, "verification_receipt_sha256": request.VerificationReceiptSHA256,
		"evidence_identity_set_root_sha256": request.EvidenceIdentitySetRootSHA256,
	} {
		if !isLowerSHA256(digest) {
			return fmt.Errorf("production source-owner verification request %s is invalid", name)
		}
	}
	if sha256Hex(request.VerificationReceiptRaw) != request.VerificationReceiptSHA256 || int64(len(request.VerificationReceiptRaw)) != request.VerificationReceiptByteCount {
		return fmt.Errorf("production source-owner verification request receipt bytes do not equal their measured identity")
	}
	if _, err := parseDocumentationFactoryProductionVerificationTime(request.ObservedAt); err != nil {
		return err
	}
	root, err := documentationFactoryProviderEvidenceIdentitySetRoot(request.EvidenceIdentities)
	if err != nil {
		return err
	}
	if root != request.EvidenceIdentitySetRootSHA256 {
		return fmt.Errorf("production source-owner verification request evidence identity root mismatch")
	}
	return nil
}

func validateDocumentationFactoryProductionSourceOwnerBindingExpectation(expected DocumentationFactoryProductionSourceOwnerBindingExpectation) error {
	for name, value := range map[string]string{
		"provider": expected.Provider, "source_owner_id": expected.SourceOwnerID, "authenticated_producer_id": expected.AuthenticatedProducerID,
		"producer_authentication_binding_ref": expected.ProducerAuthenticationBindingRef,
	} {
		if !stageIdentifierPattern.MatchString(value) {
			return fmt.Errorf("production source-owner binding expectation %s is invalid", name)
		}
	}
	organizationID, err := uuid.Parse(expected.OrganizationID)
	if err != nil || organizationID.String() != expected.OrganizationID {
		return fmt.Errorf("production source-owner binding expectation organization_id is not a canonical lowercase UUID")
	}
	if !isLowerSHA256(expected.ProducerAuthenticationBindingSHA256) {
		return fmt.Errorf("production source-owner binding expectation producer_authentication_binding_sha256 is invalid")
	}
	return nil
}

func validateDocumentationFactoryProductionSourceOwnerCurrentGeneration(request DocumentationFactoryProductionSourceVerificationRequest, expected DocumentationFactoryProductionSourceOwnerBindingExpectation, observed DocumentationFactoryProductionSourceOwnerCurrentGeneration) error {
	if observed.TestOwned {
		return fmt.Errorf("source-owner authority returned test-owned evidence")
	}
	for name, value := range map[string]string{
		"provider": observed.Provider, "source_owner_id": observed.SourceOwnerID, "authenticated_producer_id": observed.AuthenticatedProducerID,
		"producer_authentication_binding_ref": observed.ProducerAuthenticationBindingRef,
	} {
		if !stageIdentifierPattern.MatchString(value) {
			return fmt.Errorf("source-owner authority %s is invalid", name)
		}
	}
	if observed.CurrentGeneration == 0 {
		return fmt.Errorf("source-owner authority current generation is invalid")
	}
	for name, digest := range map[string]string{
		"producer_authentication_binding_sha256": observed.ProducerAuthenticationBindingSHA256,
		"current_generation_binding_sha256":      observed.CurrentGenerationBindingSHA256,
		"source_package_sha256":                  observed.SourcePackageSHA256,
		"verification_receipt_sha256":            observed.VerificationReceiptSHA256,
		"evidence_identity_set_root_sha256":      observed.EvidenceIdentitySetRootSHA256,
	} {
		if !isLowerSHA256(digest) {
			return fmt.Errorf("source-owner authority %s is invalid", name)
		}
	}
	if observed.SourcePackageByteCount <= 0 || observed.VerificationReceiptByteCount <= 0 {
		return fmt.Errorf("source-owner authority byte counts are invalid")
	}
	if _, err := parseDocumentationFactoryProductionVerificationTime(observed.VerifiedAt); err != nil {
		return err
	}
	if observed.Provider != expected.Provider || observed.Provider != request.ExpectedProvider || observed.OrganizationID != expected.OrganizationID || observed.SourceOwnerID != expected.SourceOwnerID || observed.AuthenticatedProducerID != expected.AuthenticatedProducerID || observed.ProducerAuthenticationBindingRef != expected.ProducerAuthenticationBindingRef || observed.ProducerAuthenticationBindingSHA256 != expected.ProducerAuthenticationBindingSHA256 {
		return fmt.Errorf("source-owner authority observation does not equal the boot-selected owner binding")
	}
	if observed.SourcePackageSHA256 != request.SourcePackageSHA256 || observed.SourcePackageByteCount != request.SourcePackageByteCount || observed.VerificationReceiptSHA256 != request.VerificationReceiptSHA256 || observed.VerificationReceiptByteCount != request.VerificationReceiptByteCount || observed.VerifiedAt != request.ObservedAt {
		return fmt.Errorf("source-owner authority observation does not bind the exact current verification request")
	}
	root, err := documentationFactoryProviderEvidenceIdentitySetRoot(observed.EvidenceIdentities)
	if err != nil {
		return fmt.Errorf("source-owner authority does not bind the complete exact evidence identity set: %w", err)
	}
	if root != observed.EvidenceIdentitySetRootSHA256 || root != request.EvidenceIdentitySetRootSHA256 || !equalDocumentationFactoryProviderEvidenceIdentitySets(observed.EvidenceIdentities, request.EvidenceIdentities) {
		return fmt.Errorf("source-owner authority does not bind the complete exact evidence identity set")
	}
	return nil
}

func parseDocumentationFactoryProductionVerificationTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("source-owner authority verification time is not canonical UTC RFC3339")
	}
	return parsed, nil
}

func equalDocumentationFactoryProviderEvidenceIdentitySets(left, right []DocumentationFactoryProviderEvidenceIdentity) bool {
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

func cloneDocumentationFactoryProductionSourceVerificationRequest(request DocumentationFactoryProductionSourceVerificationRequest) DocumentationFactoryProductionSourceVerificationRequest {
	request.EvidenceIdentities = cloneDocumentationFactoryProviderEvidenceIdentities(request.EvidenceIdentities)
	request.VerificationReceiptRaw = append([]byte(nil), request.VerificationReceiptRaw...)
	return request
}

var _ DocumentationFactoryProductionSourceVerifier = documentationFactoryProductionSourceOwnerVerifier{}
