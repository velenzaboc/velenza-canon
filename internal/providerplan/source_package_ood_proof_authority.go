package providerplan

import (
	"context"
	"fmt"
	"sort"

	"cloud.google.com/go/spanner"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

// DocumentationFactoryProductionSourceOODProofAttestation is an admitted
// owner result, not a caller-authored verdict. Local code supplies the opaque
// verified closure/batch proofs before this service can attest currentness.
type DocumentationFactoryProductionSourceOODProofAttestation struct {
	CurrentGeneration                DocumentationFactoryProductionSourceOwnerCurrentGeneration
	ExternalCurrentValidityReference string
	ExternalCurrentValiditySHA256    string
	Bindings                         []DocumentationFactoryProductionSourceOODEvidenceBindingRow
}

// DocumentationFactoryProductionSourceOODProofAttestationAuthority owns only
// external owner binding and cryptographic/currentness decisions. The row
// reads, closure traversal and OOD verifier calls below remain local.
type DocumentationFactoryProductionSourceOODProofAttestationAuthority interface {
	oodpublication.ClosureAttestor
	oodpublication.APIPropertyPayloadSchemaResolver
	// These two admitted policy decisions remain external owner authority. All
	// receipt-manifest node verification and all closure traversal are local,
	// typed and transaction-bound.
	AdmittedNoncomponentRoleCounts(context.Context, oodevidence.BatchV8) (map[string]int64, error)
	ResolveCanonicalComponentManifest(context.Context, oodevidence.BatchV8) ([]oodevidence.ComponentManifestTuple, error)
	AttestCurrentProviderDocumentationEvidence(context.Context, oodpublication.CurrentSealedClosure, DocumentationFactoryProductionSourceOODReadRequest, oodevidence.VerifiedClosureV8, []oodevidence.VerifiedBatchV8, []DocumentationFactoryProductionSourceOODSpannerMembershipRow) (DocumentationFactoryProductionSourceOODProofAttestation, error)
}

type documentationFactoryOODBatchManifestAuthority struct {
	owner DocumentationFactoryProductionSourceOODProofAttestationAuthority
}

func (a documentationFactoryOODBatchManifestAuthority) VerifySealedManifestNode(_ context.Context, n oodevidence.ReceiptManifestNode) error {
	if !n.Sealed || n.ManifestKind != "fetch_batch_receipt" {
		return fmt.Errorf("unsealed or wrong batch receipt manifest node")
	}
	hash, err := oodevidence.ReceiptManifestNodeHashV8(n)
	if err != nil {
		return fmt.Errorf("canonical batch receipt manifest node: %w", err)
	}
	if hash != n.NodeHash {
		return fmt.Errorf("batch receipt manifest node hash mismatch")
	}
	return nil
}
func (a documentationFactoryOODBatchManifestAuthority) AdmittedNoncomponentRoleCounts(ctx context.Context, b oodevidence.BatchV8) (map[string]int64, error) {
	return a.owner.AdmittedNoncomponentRoleCounts(ctx, b)
}
func (a documentationFactoryOODBatchManifestAuthority) ResolveCanonicalComponentManifest(ctx context.Context, b oodevidence.BatchV8) ([]oodevidence.ComponentManifestTuple, error) {
	return a.owner.ResolveCanonicalComponentManifest(ctx, b)
}

type DocumentationFactoryProductionSourceOODProofAuthority struct {
	Attestation DocumentationFactoryProductionSourceOODProofAttestationAuthority
}

func NewDocumentationFactoryProductionSourceOODProofAuthority(a DocumentationFactoryProductionSourceOODProofAttestationAuthority) (DocumentationFactoryProductionSourceOODSpannerProofAuthority, error) {
	if a == nil {
		return nil, fmt.Errorf("OOD proof attestation authority is required")
	}
	return DocumentationFactoryProductionSourceOODProofAuthority{Attestation: a}, nil
}

func (a DocumentationFactoryProductionSourceOODProofAuthority) VerifyCurrentProviderDocumentationClosure(ctx context.Context, tx *spanner.ReadOnlyTransaction, closure oodpublication.CurrentSealedClosure, request DocumentationFactoryProductionSourceOODReadRequest, members []DocumentationFactoryProductionSourceOODSpannerMembershipRow) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error) {
	if tx == nil || a.Attestation == nil || closure.OrganizationID != request.Expected.OrganizationID || closure.SnapshotKind != "provider_documentation" || len(members) != len(request.Request.EvidenceIdentities) {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("OOD proof authority input is incomplete")
	}
	certificate, err := readDocumentationFactoryOODClosureCertificate(ctx, tx, closure.OrganizationID, closure.CertificateID)
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("hydrate closure certificate: %w", err)
	}
	if certificate.OrganizationID != closure.OrganizationID || certificate.VerificationCertificateID != closure.CertificateID || certificate.VerificationCertificateHash != closure.CertificateHash || certificate.ClosureHash != closure.ClosureHash {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("closure certificate does not equal current head")
	}
	// Reconcile every physical row reachable from all nine roots in this same
	// read-only transaction before admitting the opaque closure proof.  The
	// external authority is consequently limited to its attestation signature;
	// it cannot bless a caller-selected traversal.
	manifestClosure, err := readDocumentationFactoryOODManifestClosure(ctx, tx, certificate)
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("hydrate manifest closure: %w", err)
	}
	verifier := oodpublication.ManifestMemberVerifier{PropertyPayloadSchemas: a.Attestation}
	manifestClosure.Input.MemberVerifier = &verifier
	manifestClosure.Reconciler.Input.MemberVerifier = &verifier
	closureAuthority := oodpublication.AttestedManifestClosureAuthority{ManifestClosureReconciler: manifestClosure.Reconciler, Attestor: a.Attestation}
	verifiedClosure, err := oodevidence.VerifyClosureV8(ctx, certificate, closureAuthority)
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("verify closure: %w", err)
	}
	rosterBytes, err := oodpublication.CanonicalImmutableRosterBytes(manifestClosure.Input.ImmutableRows)
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("canonical closure roster: %w", err)
	}
	verifiedRoster, err := oodevidence.VerifyPublicationRosterV8(ctx, verifiedClosure, rosterBytes, manifestClosure.Reconciler)
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("verify closure roster: %w", err)
	}
	ids := map[string]struct{}{}
	for _, m := range members {
		if m.ReceiptID == "" || m.FetchBatchID == "" || !isLowerSHA256(m.ReceiptSHA256) || !isLowerSHA256(m.EvidenceIdentitySHA256) || !isLowerSHA256(m.ArchiveBindingSHA256) {
			return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("invalid selected receipt membership")
		}
		ids[m.FetchBatchID] = struct{}{}
	}
	batchIDs := make([]string, 0, len(ids))
	for id := range ids {
		batchIDs = append(batchIDs, id)
	}
	sort.Strings(batchIDs)
	batches := make([]oodevidence.VerifiedBatchV8, 0, len(batchIDs))
	for _, id := range batchIDs {
		batch, e := readDocumentationFactoryOODBatch(ctx, tx, closure.OrganizationID, id)
		if e != nil {
			return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, e
		}
		root, e := readDocumentationFactoryOODReceiptManifestNode(ctx, tx, closure.OrganizationID, batch.BatchReceiptManifestRootHash)
		if e != nil {
			return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, e
		}
		receipts, e := documentationFactoryOODManifestReceipts(ctx, tx, closure.OrganizationID, root)
		if e != nil {
			return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, e
		}
		batchAuthority := documentationFactoryOODBatchManifestAuthority{owner: a.Attestation}
		verified, e := oodevidence.VerifyBatchV8(ctx, batch, receipts, root, batchAuthority)
		if e != nil {
			return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("verify batch %q: %w", id, e)
		}
		batches = append(batches, verified)
	}
	attested, err := a.Attestation.AttestCurrentProviderDocumentationEvidence(ctx, closure, request, verifiedClosure, batches, append([]DocumentationFactoryProductionSourceOODSpannerMembershipRow(nil), members...))
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("attest current evidence: %w", err)
	}
	rows, err := documentationFactoryOODProofRows(closure, certificate, verifiedClosure, verifiedRoster, batches, attested, request)
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, err
	}
	issuer, _ := a.Attestation.(DocumentationFactoryOODSuccessorCertificateIssuer)
	rows.preparation = &documentationFactoryProductionSourceOODPreparationEvidence{closure: manifestClosure, certificate: certificate, attestation: a.Attestation, issuer: issuer}
	return rows, nil
}

func documentationFactoryOODManifestReceipts(ctx context.Context, tx *spanner.ReadOnlyTransaction, org string, root oodevidence.ReceiptManifestNode) ([]oodevidence.ReceiptV8, error) {
	stack := []oodevidence.ReceiptManifestNode{root}
	seen := map[string]struct{}{}
	ids := []string{}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := seen[n.NodeHash]; ok {
			return nil, fmt.Errorf("receipt manifest cycle")
		}
		seen[n.NodeHash] = struct{}{}
		for _, e := range n.Entries {
			if e.Member != nil {
				ids = append(ids, e.Member.ReceiptID)
			} else if e.Child != nil {
				stack = append(stack, *e.Child)
			}
		}
	}
	receipts := make([]oodevidence.ReceiptV8, 0, len(ids))
	for _, id := range ids {
		r, e := readDocumentationFactoryOODReceipt(ctx, tx, org, id)
		if e != nil {
			return nil, e
		}
		receipts = append(receipts, r)
	}
	return receipts, nil
}

func documentationFactoryOODProofRows(c oodpublication.CurrentSealedClosure, cert oodevidence.ClosureCertificateV8, verified oodevidence.VerifiedClosureV8, roster oodevidence.VerifiedPublicationRosterV8, batches []oodevidence.VerifiedBatchV8, a DocumentationFactoryProductionSourceOODProofAttestation, req DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error) {
	if len(a.Bindings) != len(req.Request.EvidenceIdentities) || a.ExternalCurrentValidityReference == "" || !isLowerSHA256(a.ExternalCurrentValiditySHA256) {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("incomplete current evidence attestation")
	}
	receiptRoot := cert.Roots["receipt"]
	p := DocumentationFactoryProductionSourceOODEligibilityProof{OrganizationID: c.OrganizationID, Provider: req.Expected.Provider, SnapshotID: c.SnapshotID, SnapshotKind: c.SnapshotKind, SnapshotHeadGeneration: uint64(c.HeadGeneration), SnapshotState: "sealed", SnapshotStatus: "active", SourceSetSHA256: cert.SourceSetHash, ClosureSHA256: c.ClosureHash, VerificationCertificateID: c.CertificateID, VerificationCertificateSHA256: c.CertificateHash, MaterializationProfileID: c.MaterializationProfileID, MaterializationProfileVersion: c.MaterializationProfileVersion, MaterializationProfileSHA256: c.MaterializationProfileDigest, ExternalReceiptManifestRootSHA256: receiptRoot.Hash, FetchBatchManifestRootSHA256: receiptRoot.Hash, FetchBatchCount: int64(len(batches)), ArchiveBindingManifestRootSHA256: cert.ArchiveBindingIdentitySetHash, ExternalCurrentValidityResultReference: a.ExternalCurrentValidityReference, ExternalCurrentValidityResultSHA256: a.ExternalCurrentValiditySHA256}
	return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{CurrentGeneration: a.CurrentGeneration, Eligibility: p, VerifiedClosure: verified, VerifiedRoster: roster, VerifiedBatches: batches, Bindings: append([]DocumentationFactoryProductionSourceOODEvidenceBindingRow(nil), a.Bindings...), Snapshot: DocumentationFactoryProductionSourceOODSnapshotRow{OrganizationID: c.OrganizationID, SnapshotID: c.SnapshotID, SnapshotKind: c.SnapshotKind, HeadGeneration: uint64(c.HeadGeneration), State: "sealed", Status: "active", SourceSetSHA256: cert.SourceSetHash, ClosureSHA256: c.ClosureHash, VerificationCertificateID: c.CertificateID, VerificationCertificateSHA256: c.CertificateHash, MaterializationRunID: c.MaterializationRunID, MaterializationProfileID: c.MaterializationProfileID, MaterializationProfileVersion: c.MaterializationProfileVersion, MaterializationProfileSHA256: c.MaterializationProfileDigest, ReceiptManifestRootSHA256: receiptRoot.Hash, ReceiptCount: receiptRoot.Count}, Run: DocumentationFactoryProductionSourceOODMaterializationRunRow{OrganizationID: c.OrganizationID, MaterializationRunID: c.MaterializationRunID, TargetSnapshotID: c.SnapshotID, State: "sealed", SourceSetSHA256: cert.SourceSetHash, ClosureSHA256: c.ClosureHash, VerificationCertificateID: c.CertificateID, VerificationCertificateSHA256: c.CertificateHash, MaterializationProfileID: c.MaterializationProfileID, MaterializationProfileVersion: c.MaterializationProfileVersion, MaterializationProfileSHA256: c.MaterializationProfileDigest}}, nil
}

var _ DocumentationFactoryProductionSourceOODSpannerProofAuthority = DocumentationFactoryProductionSourceOODProofAuthority{}
