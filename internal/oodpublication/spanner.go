package oodpublication

// This adapter is intentionally constructed with an already-authorized
// Spanner client. It never creates a client or selects credentials; that is a
// protected boot concern. Its reads are the concrete OOD v8 strong-read shape
// shared by publication and source qualification.

import (
	"context"
	"fmt"

	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
)

type SpannerClosureReader struct{ Client *spanner.Client }

type CurrentSealedClosure struct {
	OrganizationID, SnapshotKind, SnapshotID                                                                    string
	GraphVersion, HeadGeneration                                                                                int64
	ClosureHash, CertificateID, CertificateHash, EnvelopeHash                                                   string
	MaterializationRunID, MaterializationProfileID, MaterializationProfileVersion, MaterializationProfileDigest string
}

// CurrentClosureVisitor runs while the same strong read-only transaction that
// resolved the head remains open. Consumers use it to traverse receipt, batch,
// archive, locator and manifest membership without split-read races.
type CurrentClosureVisitor func(context.Context, *spanner.ReadOnlyTransaction, CurrentSealedClosure) error

func (r SpannerClosureReader) WithCurrentSealedClosure(ctx context.Context, organizationID, snapshotKind string, visit CurrentClosureVisitor) error {
	if visit == nil {
		return fmt.Errorf("OOD8 closure visitor is nil")
	}
	if r.Client == nil || organizationID == "" || snapshotKind == "" {
		return fmt.Errorf("OOD8 strong reader requires client, organization, and snapshot kind")
	}
	tx := r.Client.ReadOnlyTransaction()
	defer tx.Close()
	x, err := readCurrentSealedClosure(ctx, tx, organizationID, snapshotKind)
	if err != nil {
		return err
	}
	return visit(ctx, tx, x)
}

// ReadCurrentSealedClosure reads the kind head, snapshot, run and certificate
// in one strong read-only transaction. Callers must still traverse immutable
// manifest/evidence membership through the OOD evidence authority; current
// aliases alone are deliberately insufficient proof.
func (r SpannerClosureReader) ReadCurrentSealedClosure(ctx context.Context, organizationID, snapshotKind string) (CurrentSealedClosure, error) {
	if r.Client == nil || organizationID == "" || snapshotKind == "" {
		return CurrentSealedClosure{}, fmt.Errorf("OOD8 strong reader requires client, organization, and snapshot kind")
	}
	tx := r.Client.ReadOnlyTransaction()
	defer tx.Close()
	return readCurrentSealedClosure(ctx, tx, organizationID, snapshotKind)
}

func readCurrentSealedClosure(ctx context.Context, tx *spanner.ReadOnlyTransaction, organizationID, snapshotKind string) (CurrentSealedClosure, error) {
	stmt := spanner.Statement{SQL: `SELECT h.graph_snapshot_id,h.graph_version,h.head_generation,h.closure_hash,h.verification_certificate_id,h.verification_certificate_hash,h.snapshot_envelope_hash,s.materialization_run_id,s.materialization_profile_id,s.materialization_profile_version,s.materialization_profile_digest,s.snapshot_state,s.status,run.state,cert.verification_certificate_hash
FROM OODGraphSnapshotHeads h
JOIN OODGraphSnapshots s ON s.organization_id=h.organization_id AND s.graph_snapshot_id=h.graph_snapshot_id
JOIN OODGraphMaterializationRuns run ON run.organization_id=s.organization_id AND run.materialization_run_id=s.materialization_run_id
JOIN OODGraphClosureVerificationCertificates cert ON cert.organization_id=s.organization_id AND cert.verification_certificate_id=s.verification_certificate_id
WHERE h.organization_id=@org AND h.snapshot_kind=@kind`, Params: map[string]interface{}{"org": organizationID, "kind": snapshotKind}}
	it := tx.Query(ctx, stmt)
	defer it.Stop()
	row, err := it.Next()
	if err == iterator.Done {
		return CurrentSealedClosure{}, fmt.Errorf("OOD8 current head absent")
	}
	if err != nil {
		return CurrentSealedClosure{}, err
	}
	var x CurrentSealedClosure
	x.OrganizationID, x.SnapshotKind = organizationID, snapshotKind
	var snapshotState, status, runState, certificateHash string
	if err := row.Columns(&x.SnapshotID, &x.GraphVersion, &x.HeadGeneration, &x.ClosureHash, &x.CertificateID, &x.CertificateHash, &x.EnvelopeHash, &x.MaterializationRunID, &x.MaterializationProfileID, &x.MaterializationProfileVersion, &x.MaterializationProfileDigest, &snapshotState, &status, &runState, &certificateHash); err != nil {
		return CurrentSealedClosure{}, err
	}
	if snapshotState != "sealed" || status != "active" || runState != "sealed" || certificateHash != x.CertificateHash {
		return CurrentSealedClosure{}, fmt.Errorf("OOD8 head does not resolve to an eligible sealed closure")
	}
	if _, nextErr := it.Next(); nextErr != iterator.Done {
		return CurrentSealedClosure{}, fmt.Errorf("OOD8 current head is non-unique")
	}
	return x, nil
}
