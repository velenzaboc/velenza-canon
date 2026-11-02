package providerplan

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// DocumentationFactoryProductionSourceOODAuthority is the protected OOD
// retrieval boundary used by the documentation-factory production verifier.
// Implementations authenticate their caller and resolve the current eligible
// OOD snapshot, receipt/batch/archive closure, and exact hydrated claim. A
// source package, receipt file, or command-line flag never selects this
// authority.
//
// This deliberately models the OOD s9/s10 selection result rather than a
// local registry. The implementation belongs with the OOD owner; this package
// only validates the returned typed coordinates before handing the result to
// the source compiler.
type DocumentationFactoryProductionSourceOODAuthority interface {
	ReadCurrentEligibleProviderEvidence(context.Context, DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODReadObservation, error)
}

// DocumentationFactoryProductionSourceOODReadRequest is built only from the
// independently selected boot binding and compiler-measured request. It is a
// body-free lookup request: provider documentation bytes remain under OOD
// archive custody and are not copied into this adapter.
type DocumentationFactoryProductionSourceOODReadRequest struct {
	Expected DocumentationFactoryProductionSourceOwnerBindingExpectation
	Request  DocumentationFactoryProductionSourceVerificationRequest
}

// DocumentationFactoryProductionSourceOODEligibilityProof binds a current OOD
// snapshot to all authority-bearing closure coordinates needed for source
// qualification. It contains no caller-authored success boolean: eligibility
// is established by the protected OOD authority and rechecked here through
// exact identities, sealed state and canonical digests.
//
// The fields correspond to OOD s9 active selection and s10 snapshot
// eligibility: a sealed snapshot/head, source-set and closure/certificate
// bindings, plus complete receipt/fetch-batch/archive and external-currentness
// closure. The reader does not publish a new graph snapshot.
type DocumentationFactoryProductionSourceOODEligibilityProof struct {
	OrganizationID                    string
	Provider                          string
	SnapshotID                        string
	SnapshotKind                      string
	SnapshotHeadGeneration            uint64
	SnapshotState                     string
	SnapshotStatus                    string
	SourceSetSHA256                   string
	ClosureSHA256                     string
	VerificationCertificateID         string
	VerificationCertificateSHA256     string
	MaterializationProfileID          string
	MaterializationProfileVersion     string
	MaterializationProfileSHA256      string
	ExternalReceiptManifestRootSHA256 string
	// FetchBatchManifestRootSHA256 is the OOD snapshot receipt-closure
	// manifest, whose members include every selected receipt and every
	// governing fetch-batch certificate. It is not a single batch certificate.
	FetchBatchManifestRootSHA256           string
	FetchBatchCount                        int64
	ArchiveBindingManifestRootSHA256       string
	ExternalCurrentValidityResultReference string
	ExternalCurrentValidityResultSHA256    string
}

// DocumentationFactoryProductionSourceOODReadObservation is returned by the
// protected OOD authority. CurrentGeneration retains the typed source-owner
// observation already consumed by the generic verifier; Eligibility proves
// that it came from one currently eligible OOD evidence closure.
type DocumentationFactoryProductionSourceOODReadObservation struct {
	CurrentGeneration DocumentationFactoryProductionSourceOwnerCurrentGeneration
	Eligibility       DocumentationFactoryProductionSourceOODEligibilityProof
}

type documentationFactoryProductionSourceOODReader struct {
	expected  DocumentationFactoryProductionSourceOwnerBindingExpectation
	authority DocumentationFactoryProductionSourceOODAuthority
}

// NewDocumentationFactoryProductionSourceOODAuthorityReader composes the
// source-owner reader from a boot-owned binding and protected OOD authority.
// It is the only supported path for an OOD-backed production reader; callers
// cannot substitute local receipt parsing for OOD snapshot selection.
func NewDocumentationFactoryProductionSourceOODAuthorityReader(expected DocumentationFactoryProductionSourceOwnerBindingExpectation, authority DocumentationFactoryProductionSourceOODAuthority) (DocumentationFactoryProductionSourceOwnerAuthorityReader, error) {
	if err := validateDocumentationFactoryProductionSourceOwnerBindingExpectation(expected); err != nil {
		return nil, err
	}
	if authority == nil {
		return nil, fmt.Errorf("production OOD evidence authority is required")
	}
	return documentationFactoryProductionSourceOODReader{expected: expected, authority: authority}, nil
}

// NewDocumentationFactoryProductionSourceOODVerifier is the boot-composition
// entry point used by a runtime that already selected its protected OOD
// authority and admitted owner binding. It creates no admission or binding and
// remains unavailable to CLI/source-package inputs.
func NewDocumentationFactoryProductionSourceOODVerifier(expected DocumentationFactoryProductionSourceOwnerBindingExpectation, authority DocumentationFactoryProductionSourceOODAuthority) (DocumentationFactoryProductionSourceVerifier, error) {
	reader, err := NewDocumentationFactoryProductionSourceOODAuthorityReader(expected, authority)
	if err != nil {
		return nil, err
	}
	return NewDocumentationFactoryProductionSourceOwnerVerifier(expected, reader)
}

func (r documentationFactoryProductionSourceOODReader) ReadCurrentAuthenticatedProviderEvidence(ctx context.Context, request DocumentationFactoryProductionSourceVerificationRequest) (DocumentationFactoryProductionSourceOwnerCurrentGeneration, error) {
	if err := ctx.Err(); err != nil {
		return DocumentationFactoryProductionSourceOwnerCurrentGeneration{}, err
	}
	if err := validateDocumentationFactoryProductionSourceVerificationRequest(request); err != nil {
		return DocumentationFactoryProductionSourceOwnerCurrentGeneration{}, err
	}
	if request.ExpectedProvider != r.expected.Provider {
		return DocumentationFactoryProductionSourceOwnerCurrentGeneration{}, fmt.Errorf("OOD source evidence request provider does not equal the boot-selected provider")
	}
	observation, err := r.authority.ReadCurrentEligibleProviderEvidence(ctx, DocumentationFactoryProductionSourceOODReadRequest{
		Expected: r.expected,
		Request:  cloneDocumentationFactoryProductionSourceVerificationRequest(request),
	})
	if err != nil {
		return DocumentationFactoryProductionSourceOwnerCurrentGeneration{}, fmt.Errorf("OOD source evidence authority refused current evidence: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return DocumentationFactoryProductionSourceOwnerCurrentGeneration{}, err
	}
	if err := validateDocumentationFactoryProductionSourceOODObservation(r.expected, request, observation); err != nil {
		return DocumentationFactoryProductionSourceOwnerCurrentGeneration{}, err
	}
	return observation.CurrentGeneration, nil
}

func validateDocumentationFactoryProductionSourceOODObservation(expected DocumentationFactoryProductionSourceOwnerBindingExpectation, request DocumentationFactoryProductionSourceVerificationRequest, observation DocumentationFactoryProductionSourceOODReadObservation) error {
	if err := validateDocumentationFactoryProductionSourceOwnerCurrentGeneration(request, expected, observation.CurrentGeneration); err != nil {
		return fmt.Errorf("OOD source evidence observation: %w", err)
	}
	proof := observation.Eligibility
	if proof.OrganizationID != expected.OrganizationID || proof.Provider != expected.Provider {
		return fmt.Errorf("OOD eligibility proof does not equal the boot-selected organization and provider")
	}
	for name, value := range map[string]string{
		"snapshot_kind":                              proof.SnapshotKind,
		"materialization_profile_version":            proof.MaterializationProfileVersion,
		"external_current_validity_result_reference": proof.ExternalCurrentValidityResultReference,
	} {
		if !stageIdentifierPattern.MatchString(value) {
			return fmt.Errorf("OOD eligibility proof %s is invalid", name)
		}
	}
	for name, value := range map[string]string{
		"snapshot_id":                 proof.SnapshotID,
		"verification_certificate_id": proof.VerificationCertificateID,
		"materialization_profile_id":  proof.MaterializationProfileID,
	} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed.String() != value {
			return fmt.Errorf("OOD eligibility proof %s is not a canonical lowercase UUID", name)
		}
	}
	for name, value := range map[string]string{
		"source_set_sha256":                       proof.SourceSetSHA256,
		"closure_sha256":                          proof.ClosureSHA256,
		"verification_certificate_sha256":         proof.VerificationCertificateSHA256,
		"materialization_profile_sha256":          proof.MaterializationProfileSHA256,
		"external_receipt_manifest_root_sha256":   proof.ExternalReceiptManifestRootSHA256,
		"fetch_batch_manifest_root_sha256":        proof.FetchBatchManifestRootSHA256,
		"archive_binding_manifest_root_sha256":    proof.ArchiveBindingManifestRootSHA256,
		"external_current_validity_result_sha256": proof.ExternalCurrentValidityResultSHA256,
	} {
		if !isLowerSHA256(value) {
			return fmt.Errorf("OOD eligibility proof %s is invalid", name)
		}
	}
	if proof.SnapshotHeadGeneration == 0 {
		return fmt.Errorf("OOD eligibility proof snapshot head generation is invalid")
	}
	if proof.FetchBatchCount < 1 {
		return fmt.Errorf("OOD eligibility proof fetch batch count is invalid")
	}
	if proof.SnapshotState != "sealed" {
		return fmt.Errorf("OOD eligibility proof snapshot is not sealed")
	}
	// OOD permits superseded and archived snapshots for separately authorized
	// historical reads. This adapter performs current producer qualification,
	// so the selected compact-head lifecycle must be exactly active. A generic
	// identifier check would accidentally accept a historical or invalid state.
	if proof.SnapshotStatus != "active" {
		return fmt.Errorf("OOD eligibility proof snapshot status is not active")
	}
	return nil
}

var _ DocumentationFactoryProductionSourceOwnerAuthorityReader = documentationFactoryProductionSourceOODReader{}
