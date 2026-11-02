package providerplan

// This file is the production-shaped OOD read adapter.  It intentionally
// receives an already-authorized Spanner client and a protected proof owner:
// source-package input never supplies a database, credential, query, or proof
// implementation.

import (
	"context"
	"fmt"

	"cloud.google.com/go/spanner"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"google.golang.org/api/iterator"
)

// DocumentationFactoryProductionSourceOODSpannerProofAuthority owns the
// typed OOD evidence verification (receipts, batches, archives, locators and
// closure).  It runs inside the same read-only transaction as the compact
// current-head resolution.  Its opaque proof results can therefore only be
// made by the oodevidence verification APIs, not by this adapter or a caller.
type DocumentationFactoryProductionSourceOODSpannerProofAuthority interface {
	VerifyCurrentProviderDocumentationClosure(context.Context, *spanner.ReadOnlyTransaction, oodpublication.CurrentSealedClosure, DocumentationFactoryProductionSourceOODReadRequest, []DocumentationFactoryProductionSourceOODSpannerMembershipRow) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error)
}

// DocumentationFactoryProductionSourceOODSpannerMembershipRow is the exact
// protected projection used to bind a compiler evidence body to its OOD
// receipt/batch/archive membership.  It deliberately excludes archive bytes
// and every credential or provider locator.
type DocumentationFactoryProductionSourceOODSpannerMembershipRow struct {
	SourceContentSHA256    string
	SourceContentBytes     int64
	ReceiptID              string
	ReceiptSHA256          string
	FetchBatchID           string
	EvidenceIdentitySHA256 string
	ArchiveBindingSHA256   string
}

// DocumentationFactoryProductionSourceOODSpannerReader maps selected source
// identities to protected OOD rows.  All reads, including membership and the
// current head, use one strong read-only transaction via
// SpannerClosureReader.WithCurrentSealedClosure.
type DocumentationFactoryProductionSourceOODSpannerReader struct {
	ClosureReader  oodpublication.SpannerClosureReader
	ProofAuthority DocumentationFactoryProductionSourceOODSpannerProofAuthority
}

func NewDocumentationFactoryProductionSourceOODSpannerReader(client *spanner.Client, proof DocumentationFactoryProductionSourceOODSpannerProofAuthority) (DocumentationFactoryProductionSourceOODStrongReader, error) {
	if client == nil || proof == nil {
		return nil, fmt.Errorf("protected OOD Spanner client and proof authority are required")
	}
	return DocumentationFactoryProductionSourceOODSpannerReader{ClosureReader: oodpublication.SpannerClosureReader{Client: client}, ProofAuthority: proof}, nil
}

func (r DocumentationFactoryProductionSourceOODSpannerReader) ReadCurrentEligibleProviderEvidenceRows(ctx context.Context, request DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error) {
	if err := ctx.Err(); err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, err
	}
	if r.ClosureReader.Client == nil || r.ProofAuthority == nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("protected OOD Spanner reader is not boot configured")
	}
	var result DocumentationFactoryProductionSourceOODCurrentEvidenceRows
	err := r.ClosureReader.WithCurrentSealedClosure(ctx, request.Expected.OrganizationID, "provider_documentation", func(ctx context.Context, tx *spanner.ReadOnlyTransaction, closure oodpublication.CurrentSealedClosure) error {
		members, err := readDocumentationFactoryOODMembership(ctx, tx, closure, request.Request.EvidenceIdentities)
		if err != nil {
			return err
		}
		result, err = r.ProofAuthority.VerifyCurrentProviderDocumentationClosure(ctx, tx, closure, request, members)
		return err
	})
	if err != nil {
		return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, fmt.Errorf("read protected OOD provider-documentation closure: %w", err)
	}
	return result, nil
}

func readDocumentationFactoryOODMembership(ctx context.Context, tx *spanner.ReadOnlyTransaction, closure oodpublication.CurrentSealedClosure, identities []DocumentationFactoryProviderEvidenceIdentity) ([]DocumentationFactoryProductionSourceOODSpannerMembershipRow, error) {
	if tx == nil || closure.OrganizationID == "" || closure.CertificateID == "" || len(identities) == 0 {
		return nil, fmt.Errorf("OOD membership query is incomplete")
	}
	// Content digest and byte count are the source-package's body-free bridge
	// to the OOD receipt.  They are deliberately *not* a global receipt
	// selector: a body can be re-captured in a historical batch.  Restrict the
	// candidates to receipt leaves reachable from the active closure
	// certificate's receipt-manifest root.  This is both the selection fence
	// and the reason a historical re-capture is not an ambiguity.
	hashes := make([]string, len(identities))
	for i, identity := range identities {
		hashes[i] = identity.SourceContentSHA256
	}
	receiptIDs, err := readDocumentationFactoryOODActiveReceiptIDs(ctx, tx, closure.OrganizationID, closure.CertificateID)
	if err != nil {
		return nil, err
	}
	if len(receiptIDs) == 0 {
		return nil, fmt.Errorf("active OOD receipt manifest has no receipt members")
	}
	stmt := spanner.Statement{SQL: `SELECT source_content_hash, evidence_archive_byte_count, receipt_id, redacted_transport_evidence_digest, fetch_batch_id, evidence_identity_hash, evidence_archive_record_digest
FROM OODGraphExternalFetchReceipts
WHERE organization_id=@org AND receipt_id IN UNNEST(@receipt_ids) AND source_content_hash IN UNNEST(@hashes)`, Params: map[string]interface{}{"org": closure.OrganizationID, "receipt_ids": receiptIDs, "hashes": hashes}}
	it := tx.Query(ctx, stmt)
	defer it.Stop()
	byContent := make(map[string][]DocumentationFactoryProductionSourceOODSpannerMembershipRow)
	for {
		row, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		var member DocumentationFactoryProductionSourceOODSpannerMembershipRow
		if err := row.Columns(&member.SourceContentSHA256, &member.SourceContentBytes, &member.ReceiptID, &member.ReceiptSHA256, &member.FetchBatchID, &member.EvidenceIdentitySHA256, &member.ArchiveBindingSHA256); err != nil {
			return nil, err
		}
		byContent[member.SourceContentSHA256] = append(byContent[member.SourceContentSHA256], member)
	}
	result := make([]DocumentationFactoryProductionSourceOODSpannerMembershipRow, 0, len(identities))
	for _, identity := range identities {
		candidates := byContent[identity.SourceContentSHA256]
		var matched *DocumentationFactoryProductionSourceOODSpannerMembershipRow
		for i := range candidates {
			if candidates[i].SourceContentBytes == identity.SourceContentByteCount {
				if matched != nil {
					return nil, fmt.Errorf("OOD membership is ambiguous for selected evidence identity")
				}
				matched = &candidates[i]
			}
		}
		if matched == nil {
			return nil, fmt.Errorf("OOD membership is absent for selected evidence identity")
		}
		result = append(result, *matched)
	}
	return result, nil
}

// readDocumentationFactoryOODActiveReceiptIDs is intentionally iterative:
// Spanner GoogleSQL does not permit a self-referential CTE.  Every read is
// tenant-scoped and shares the current-head read-only transaction.
func readDocumentationFactoryOODActiveReceiptIDs(ctx context.Context, tx *spanner.ReadOnlyTransaction, org, certificateID string) ([]string, error) {
	certificate, err := tx.ReadRow(ctx, "OODGraphClosureVerificationCertificates", spanner.Key{org, certificateID}, []string{"receipt_manifest_root_hash"})
	if err != nil {
		return nil, fmt.Errorf("read active receipt manifest root: %w", err)
	}
	var root string
	if err := certificate.Columns(&root); err != nil || root == "" {
		return nil, fmt.Errorf("active receipt manifest root is invalid")
	}
	seenNodes, seenReceipts := map[string]struct{}{}, map[string]struct{}{}
	var walk func(string, int) error
	walk = func(nodeHash string, depth int) error {
		if depth > 64 {
			return fmt.Errorf("active receipt manifest exceeds maximum depth")
		}
		if _, duplicate := seenNodes[nodeHash]; duplicate {
			return fmt.Errorf("active receipt manifest has a cycle or duplicate node")
		}
		seenNodes[nodeHash] = struct{}{}
		node, err := tx.ReadRow(ctx, "OODGraphManifestNodes", spanner.Key{org, nodeHash}, []string{"manifest_kind", "node_kind", "node_level", "entry_count", "transitive_member_count", "sealed"})
		if err != nil {
			return fmt.Errorf("read active receipt manifest node: %w", err)
		}
		var kind, nodeKind string
		var level, entryCount, transitiveCount int64
		var sealed bool
		if err := node.Columns(&kind, &nodeKind, &level, &entryCount, &transitiveCount, &sealed); err != nil || kind != "receipt" || !sealed || entryCount < 0 || transitiveCount < 0 || (nodeKind != "leaf" && nodeKind != "internal") || (nodeKind == "leaf" && level != 0) || (nodeKind == "internal" && level < 1) {
			return fmt.Errorf("active receipt manifest node is invalid")
		}
		it := tx.Query(ctx, spanner.Statement{SQL: `SELECT entry_ordinal,entry_kind,member_id,child_manifest_node_hash FROM OODGraphManifestEntries WHERE organization_id=@org AND manifest_node_hash=@node ORDER BY entry_ordinal`, Params: map[string]interface{}{"org": org, "node": nodeHash}})
		defer it.Stop()
		var entries int64
		for {
			r, next := it.Next()
			if next == iterator.Done {
				break
			}
			if next != nil {
				return next
			}
			var ordinal int64
			var entryKind string
			var memberID, child spanner.NullString
			if err := r.Columns(&ordinal, &entryKind, &memberID, &child); err != nil || ordinal != entries {
				return fmt.Errorf("active receipt manifest entry is invalid")
			}
			entries++
			switch entryKind {
			case "receipt":
				if nodeKind != "leaf" || !memberID.Valid || memberID.String() == "" || child.Valid {
					return fmt.Errorf("active receipt manifest member is invalid")
				}
				if _, duplicate := seenReceipts[memberID.String()]; duplicate {
					return fmt.Errorf("active receipt manifest duplicates a receipt")
				}
				seenReceipts[memberID.String()] = struct{}{}
			case "fetch_batch_certificate":
				// The snapshot receipt closure deliberately includes governing
				// batch certificates. They are not receipt candidates, but their
				// presence is retained by the full closure reconciler.
				if nodeKind != "leaf" || !memberID.Valid || memberID.String() == "" || child.Valid {
					return fmt.Errorf("active receipt manifest batch certificate is invalid")
				}
			case "child_manifest":
				if nodeKind != "internal" || !child.Valid || child.String() == "" || memberID.Valid {
					return fmt.Errorf("active receipt manifest child is invalid")
				}
				if err := walk(child.String(), depth+1); err != nil {
					return err
				}
			default:
				return fmt.Errorf("active receipt manifest entry kind is invalid")
			}
		}
		if entries != entryCount {
			return fmt.Errorf("active receipt manifest entry count mismatch")
		}
		return nil
	}
	if err := walk(root, 0); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(seenReceipts))
	for id := range seenReceipts {
		ids = append(ids, id)
	}
	return ids, nil
}

var _ DocumentationFactoryProductionSourceOODStrongReader = DocumentationFactoryProductionSourceOODSpannerReader{}
