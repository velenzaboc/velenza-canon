package providerplan

import (
	"context"
	"fmt"
	"sort"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

// DocumentationFactoryProductionSourceOODStrongReader is the protected OOD
// row-read boundary. Implementations authenticate the caller and make one
// coherent strong read of the OOD-owned current selection. In particular this
// is not a file reader: package bytes, a receipt JSON document, CLI flags, and
// factory fixtures cannot select either the reader or its authority.
//
// The returned rows are deliberately bounded projections. The OOD owner keeps
// raw archive bytes, current-selection policy, credentials, and persistence.
type DocumentationFactoryProductionSourceOODStrongReader interface {
	ReadCurrentEligibleProviderEvidenceRows(context.Context, DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error)
}

// DocumentationFactoryProductionSourceOODSnapshotRow is the exact current
// snapshot coordinate selected by OOD s9/s10. Current qualification accepts
// only a sealed, active provider-documentation snapshot.
type DocumentationFactoryProductionSourceOODSnapshotRow struct {
	OrganizationID                string
	SnapshotID                    string
	SnapshotKind                  string
	HeadGeneration                uint64
	State                         string
	Status                        string
	SourceSetSHA256               string
	ClosureSHA256                 string
	VerificationCertificateID     string
	VerificationCertificateSHA256 string
	MaterializationRunID          string
	MaterializationProfileID      string
	MaterializationProfileVersion string
	MaterializationProfileSHA256  string
	ReceiptManifestRootSHA256     string
	ReceiptCount                  int64
}

// DocumentationFactoryProductionSourceOODMaterializationRunRow binds the
// selected snapshot to its sealed run and admitted profile. It prevents a
// valid snapshot proof from being substituted with a certificate/profile from
// another run.
type DocumentationFactoryProductionSourceOODMaterializationRunRow struct {
	OrganizationID                string
	MaterializationRunID          string
	TargetSnapshotID              string
	State                         string
	SourceSetSHA256               string
	ClosureSHA256                 string
	VerificationCertificateID     string
	VerificationCertificateSHA256 string
	MaterializationProfileID      string
	MaterializationProfileVersion string
	MaterializationProfileSHA256  string
}

// DocumentationFactoryProductionSourceOODEvidenceBindingRow is one selected
// compiler evidence identity joined to its OOD receipt, fetch-batch and archive
// binding coordinates. Each row is body-free. The OOD evidence verifier checks
// the receipt, batch, relationship and locator closure before this reader
// returns a source-owner observation.
type DocumentationFactoryProductionSourceOODEvidenceBindingRow struct {
	Identity                         DocumentationFactoryProviderEvidenceIdentity
	EvidenceIdentitySHA256           string
	ReceiptID                        string
	ReceiptSHA256                    string
	FetchBatchID                     string
	FetchBatchCertificateID          string
	FetchBatchCertificateSHA256      string
	ArchiveBindingSHA256             string
	RelationshipEvidenceSHA256       string
	LocatorManifestSHA256            string
	ExternalCurrentValidityReference string
	ExternalCurrentValiditySHA256    string
}

// DocumentationFactoryProductionSourceOODCurrentEvidenceRows is the complete
// bounded result consumed by the source reader. All relationships below must
// exactly agree; a valid individual digest is never treated as proof that it
// belongs to the current selected closure.
type DocumentationFactoryProductionSourceOODCurrentEvidenceRows struct {
	CurrentGeneration DocumentationFactoryProductionSourceOwnerCurrentGeneration
	Snapshot          DocumentationFactoryProductionSourceOODSnapshotRow
	Run               DocumentationFactoryProductionSourceOODMaterializationRunRow
	Eligibility       DocumentationFactoryProductionSourceOODEligibilityProof
	VerifiedClosure   oodevidence.VerifiedClosureV8
	VerifiedRoster    oodevidence.VerifiedPublicationRosterV8
	VerifiedBatches   []oodevidence.VerifiedBatchV8
	Bindings          []DocumentationFactoryProductionSourceOODEvidenceBindingRow
	preparation       *documentationFactoryProductionSourceOODPreparationEvidence
}

type documentationFactoryProductionSourceOODPreparationEvidence struct {
	closure     DocumentationFactoryOODManifestClosure
	certificate oodevidence.ClosureCertificateV8
	attestation DocumentationFactoryProductionSourceOODProofAttestationAuthority
	issuer      DocumentationFactoryOODSuccessorCertificateIssuer
}

func cloneDocumentationFactoryProductionSourceOODCurrentEvidenceRows(in DocumentationFactoryProductionSourceOODCurrentEvidenceRows) DocumentationFactoryProductionSourceOODCurrentEvidenceRows {
	out := in
	out.CurrentGeneration.EvidenceIdentities = append([]DocumentationFactoryProviderEvidenceIdentity(nil), in.CurrentGeneration.EvidenceIdentities...)
	out.Bindings = append([]DocumentationFactoryProductionSourceOODEvidenceBindingRow(nil), in.Bindings...)
	for i := range out.Bindings {
		out.Bindings[i].Identity = in.Bindings[i].Identity
	}
	out.VerifiedBatches = append([]oodevidence.VerifiedBatchV8(nil), in.VerifiedBatches...)
	if in.preparation != nil {
		p := *in.preparation
		p.certificate = oodevidence.CloneClosureCertificateV8(in.preparation.certificate)
		p.closure.Input = oodpublication.CloneManifestClosureInput(in.preparation.closure.Input)
		p.closure.Reconciler = oodpublication.ManifestClosureReconciler{Input: p.closure.Input}
		out.preparation = &p
	}
	return out
}

type documentationFactoryProductionSourceOODCurrentReader struct {
	expected DocumentationFactoryProductionSourceOwnerBindingExpectation
	reader   DocumentationFactoryProductionSourceOODStrongReader
}

// documentationFactoryProductionSourceOODValidatedObserver is deliberately
// private: a capture may be promoted only after this reader has performed all
// exact owner/request/current-closure validation.
type documentationFactoryProductionSourceOODValidatedObserver interface {
	observeValidatedPreparation(DocumentationFactoryProductionSourceOwnerBindingExpectation, DocumentationFactoryProductionSourceVerificationRequest, DocumentationFactoryProductionSourceOODCurrentEvidenceRows) error
}

// NewDocumentationFactoryProductionSourceOODCurrentReader makes a concrete
// OOD authority adapter from the protected strong-read owner. It is intended
// for boot composition only. A deployment still needs an admitted protected
// reader/binding; this constructor deliberately does not manufacture one.
func NewDocumentationFactoryProductionSourceOODCurrentReader(expected DocumentationFactoryProductionSourceOwnerBindingExpectation, reader DocumentationFactoryProductionSourceOODStrongReader) (DocumentationFactoryProductionSourceOODAuthority, error) {
	if err := validateDocumentationFactoryProductionSourceOwnerBindingExpectation(expected); err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, fmt.Errorf("protected OOD strong reader is required")
	}
	return documentationFactoryProductionSourceOODCurrentReader{expected: expected, reader: reader}, nil
}

// NewDocumentationFactoryProductionSourceOODCurrentVerifier composes the
// strong current reader with both OOD and source-owner verification layers.
// It has no CLI or package-selected authority path.
func NewDocumentationFactoryProductionSourceOODCurrentVerifier(expected DocumentationFactoryProductionSourceOwnerBindingExpectation, reader DocumentationFactoryProductionSourceOODStrongReader) (DocumentationFactoryProductionSourceVerifier, error) {
	authority, err := NewDocumentationFactoryProductionSourceOODCurrentReader(expected, reader)
	if err != nil {
		return nil, err
	}
	return NewDocumentationFactoryProductionSourceOODVerifier(expected, authority)
}

func (r documentationFactoryProductionSourceOODCurrentReader) ReadCurrentEligibleProviderEvidence(ctx context.Context, request DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODReadObservation, error) {
	if err := ctx.Err(); err != nil {
		return DocumentationFactoryProductionSourceOODReadObservation{}, err
	}
	if err := validateDocumentationFactoryProductionSourceOwnerBindingExpectation(request.Expected); err != nil {
		return DocumentationFactoryProductionSourceOODReadObservation{}, fmt.Errorf("OOD strong read expectation: %w", err)
	}
	if request.Expected != r.expected {
		return DocumentationFactoryProductionSourceOODReadObservation{}, fmt.Errorf("OOD strong read expectation does not equal the boot-selected owner binding")
	}
	if err := validateDocumentationFactoryProductionSourceVerificationRequest(request.Request); err != nil {
		return DocumentationFactoryProductionSourceOODReadObservation{}, err
	}
	if request.Request.ExpectedProvider != r.expected.Provider {
		return DocumentationFactoryProductionSourceOODReadObservation{}, fmt.Errorf("OOD strong read provider does not equal the boot-selected provider")
	}
	rows, err := r.reader.ReadCurrentEligibleProviderEvidenceRows(ctx, DocumentationFactoryProductionSourceOODReadRequest{
		Expected: r.expected, Request: cloneDocumentationFactoryProductionSourceVerificationRequest(request.Request),
	})
	if err != nil {
		return DocumentationFactoryProductionSourceOODReadObservation{}, fmt.Errorf("protected OOD strong reader refused current evidence: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return DocumentationFactoryProductionSourceOODReadObservation{}, err
	}
	if err := validateDocumentationFactoryProductionSourceOODCurrentEvidenceRows(r.expected, request.Request, rows); err != nil {
		return DocumentationFactoryProductionSourceOODReadObservation{}, err
	}
	if observer, ok := r.reader.(documentationFactoryProductionSourceOODValidatedObserver); ok {
		if err := observer.observeValidatedPreparation(r.expected, request.Request, rows); err != nil {
			return DocumentationFactoryProductionSourceOODReadObservation{}, err
		}
	}
	return DocumentationFactoryProductionSourceOODReadObservation{CurrentGeneration: rows.CurrentGeneration, Eligibility: rows.Eligibility}, nil
}

func validateDocumentationFactoryProductionSourceOODCurrentEvidenceRows(expected DocumentationFactoryProductionSourceOwnerBindingExpectation, request DocumentationFactoryProductionSourceVerificationRequest, rows DocumentationFactoryProductionSourceOODCurrentEvidenceRows) error {
	if err := validateDocumentationFactoryProductionSourceOODObservation(expected, request, DocumentationFactoryProductionSourceOODReadObservation{CurrentGeneration: rows.CurrentGeneration, Eligibility: rows.Eligibility}); err != nil {
		return err
	}
	if err := oodevidence.ValidateVerifiedClosureV8(rows.VerifiedClosure); err != nil {
		return fmt.Errorf("OOD current selection has no verified closure: %w", err)
	}
	p := rows.Eligibility
	s := rows.Snapshot
	if rows.VerifiedClosure.OrganizationID() != expected.OrganizationID || rows.VerifiedClosure.CertificateID() != p.VerificationCertificateID || rows.VerifiedClosure.CertificateHash() != p.VerificationCertificateSHA256 {
		return fmt.Errorf("OOD verified closure does not equal the selected organization/certificate")
	}
	if s.OrganizationID != expected.OrganizationID || s.SnapshotID != p.SnapshotID || s.SnapshotKind != p.SnapshotKind || s.HeadGeneration != p.SnapshotHeadGeneration || s.State != p.SnapshotState || s.Status != p.SnapshotStatus || s.SourceSetSHA256 != p.SourceSetSHA256 || s.ClosureSHA256 != p.ClosureSHA256 || s.VerificationCertificateID != p.VerificationCertificateID || s.VerificationCertificateSHA256 != p.VerificationCertificateSHA256 || s.MaterializationProfileID != p.MaterializationProfileID || s.MaterializationProfileVersion != p.MaterializationProfileVersion || s.MaterializationProfileSHA256 != p.MaterializationProfileSHA256 || s.ReceiptManifestRootSHA256 != p.ExternalReceiptManifestRootSHA256 {
		return fmt.Errorf("OOD snapshot row does not equal the current eligibility proof")
	}
	if s.MaterializationRunID == "" || s.ReceiptCount < 1 || s.State != "sealed" || s.Status != "active" {
		return fmt.Errorf("OOD snapshot row is not the sealed active current selection")
	}
	run := rows.Run
	if run.OrganizationID != expected.OrganizationID || run.MaterializationRunID != s.MaterializationRunID || run.TargetSnapshotID != s.SnapshotID || run.State != "sealed" || run.SourceSetSHA256 != s.SourceSetSHA256 || run.ClosureSHA256 != s.ClosureSHA256 || run.VerificationCertificateID != s.VerificationCertificateID || run.VerificationCertificateSHA256 != s.VerificationCertificateSHA256 || run.MaterializationProfileID != s.MaterializationProfileID || run.MaterializationProfileVersion != s.MaterializationProfileVersion || run.MaterializationProfileSHA256 != s.MaterializationProfileSHA256 {
		return fmt.Errorf("OOD materialization run does not close over the selected snapshot/profile/certificate")
	}
	// OOD's snapshot receipt_count covers the complete receipt-closure tree,
	// including governing fetch-batch certificate members. The compiler asks
	// for a selected evidence subset, so equality here would reject a complete
	// closure whenever the selected package does not contain every receipt.
	if s.ReceiptCount < 1 || len(rows.Bindings) < 1 {
		return fmt.Errorf("OOD snapshot or selected evidence bindings are empty")
	}
	return validateDocumentationFactoryProductionSourceOODEvidenceBindings(request, p, rows.VerifiedBatches, rows.Bindings)
}

func validateDocumentationFactoryProductionSourceOODEvidenceBindings(request DocumentationFactoryProductionSourceVerificationRequest, proof DocumentationFactoryProductionSourceOODEligibilityProof, verifiedBatches []oodevidence.VerifiedBatchV8, bindings []DocumentationFactoryProductionSourceOODEvidenceBindingRow) error {
	want := make(map[string]DocumentationFactoryProviderEvidenceIdentity, len(request.EvidenceIdentities))
	for _, identity := range request.EvidenceIdentities {
		want[documentationFactoryProviderEvidenceIdentityKey(identity)] = identity
	}
	seen := make(map[string]struct{}, len(bindings))
	batches := make(map[string]struct{}, len(bindings))
	batchProofs := make(map[string]oodevidence.VerifiedBatchV8, len(verifiedBatches))
	for index, batch := range verifiedBatches {
		if err := oodevidence.ValidateVerifiedBatchV8(batch); err != nil {
			return fmt.Errorf("OOD verified batch[%d]: %w", index, err)
		}
		if batch.OrganizationID() != proof.OrganizationID {
			return fmt.Errorf("OOD verified batch[%d] has a foreign organization", index)
		}
		if _, duplicate := batchProofs[batch.FetchBatchID()]; duplicate {
			return fmt.Errorf("OOD verified batches duplicate a fetch batch")
		}
		batchProofs[batch.FetchBatchID()] = batch
	}
	archiveRows := make([]string, 0, len(bindings))
	for index, binding := range bindings {
		key := documentationFactoryProviderEvidenceIdentityKey(binding.Identity)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("OOD evidence binding[%d] duplicates a compiler evidence identity", index)
		}
		seen[key] = struct{}{}
		if _, exists := want[key]; !exists {
			return fmt.Errorf("OOD evidence binding[%d] substitutes an unrequested compiler evidence identity", index)
		}
		for name, digest := range map[string]string{
			"evidence_identity_sha256": binding.EvidenceIdentitySHA256, "receipt_sha256": binding.ReceiptSHA256,
			"fetch_batch_certificate_sha256": binding.FetchBatchCertificateSHA256, "archive_binding_sha256": binding.ArchiveBindingSHA256,
			"relationship_evidence_sha256": binding.RelationshipEvidenceSHA256, "locator_manifest_sha256": binding.LocatorManifestSHA256,
			"external_current_validity_sha256": binding.ExternalCurrentValiditySHA256,
		} {
			if !isLowerSHA256(digest) {
				return fmt.Errorf("OOD evidence binding[%d] %s is invalid", index, name)
			}
		}
		if binding.ReceiptID == "" || binding.FetchBatchID == "" || binding.FetchBatchCertificateID == "" || !isLowerSHA256(binding.FetchBatchCertificateSHA256) || binding.ExternalCurrentValidityReference != proof.ExternalCurrentValidityResultReference || binding.ExternalCurrentValiditySHA256 != proof.ExternalCurrentValidityResultSHA256 {
			return fmt.Errorf("OOD evidence binding[%d] does not equal the selected receipt/batch/current-validity closure", index)
		}
		batches[binding.FetchBatchID] = struct{}{}
		batch, verified := batchProofs[binding.FetchBatchID]
		if !verified {
			return fmt.Errorf("OOD evidence binding[%d] has no opaque verified fetch batch", index)
		}
		receipt, present := batch.Receipt(binding.ReceiptID)
		if !present || receipt.EvidenceIdentityHash != binding.EvidenceIdentitySHA256 {
			return fmt.Errorf("OOD evidence binding[%d] does not belong to its verified receipt/batch roster", index)
		}
		archiveRows = append(archiveRows, binding.ArchiveBindingSHA256)
	}
	if len(seen) != len(want) {
		return fmt.Errorf("OOD evidence bindings do not contain the complete exact compiler identity set")
	}
	if int64(len(batches)) != proof.FetchBatchCount {
		return fmt.Errorf("OOD evidence bindings do not equal the selected fetch batch count")
	}
	if int64(len(batchProofs)) != proof.FetchBatchCount {
		return fmt.Errorf("OOD verified batches do not equal the selected fetch batch count")
	}
	// These are exact references to OOD-owned manifest rows. The source reader
	// verifies the complete identity roster above, while the OOD evidence brick
	// verifies each referenced receipt/batch/archive closure before the strong
	// reader exposes this projection.
	sort.Strings(archiveRows)
	if len(archiveRows) == 0 {
		return fmt.Errorf("OOD evidence bindings have no archive closure")
	}
	return nil
}

var _ DocumentationFactoryProductionSourceOODAuthority = documentationFactoryProductionSourceOODCurrentReader{}
