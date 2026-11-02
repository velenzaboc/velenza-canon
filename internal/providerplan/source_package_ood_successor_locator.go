package providerplan

import (
	"context"
	"fmt"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

// DocumentationFactoryOODCanonicalRepresentationResolver is a narrow
// boot-owned profile selection seam. Native JSONL supplies neither a profile
// name nor its digest, so the mapper cannot manufacture one from source bytes.
type DocumentationFactoryOODCanonicalRepresentationResolver interface {
	ResolveCanonicalRepresentationProfile(context.Context, oodevidence.ReceiptV8) (string, string, error)
}

// DocumentationFactoryOODEvidenceManifestBindingVerifier binds the compiler's
// evidence-manifest digest to the selected qualified receipt/representation.
// The OOD locator schema has no spare manifest column, so this protected
// verification is required before its range can become a physical locator.
type DocumentationFactoryOODEvidenceManifestBindingVerifier interface {
	VerifyEvidenceManifestBinding(context.Context, oodevidence.ReceiptV8, string) error
}

// DocumentationFactorySourcePackageOODLocatorBinding is the typed bridge to
// the graph-row builder. All fields are locally derived from sealed native
// bytes and strict same-read physical evidence.
type DocumentationFactorySourcePackageOODLocatorBinding struct {
	NativeLocatorID, SourceArtifactHash string
	Receipt, Batch                      oodpublication.SpannerRow
	Locator                             oodproof.GraphFactLocator
	LocatorRow                          oodpublication.SpannerRow
}

func buildDocumentationFactorySourcePackageOODLocatorBindings(ctx context.Context, p DocumentationFactorySourcePackageOODNativeProjection, rows []oodpublication.SpannerRow, authority interface{}, createdAt time.Time) ([]DocumentationFactorySourcePackageOODLocatorBinding, []oodpublication.ManifestMemberV8, error) {
	archive, ok := authority.(DocumentationFactoryOODArchivedCanonicalBytes)
	if !ok {
		return nil, nil, fmt.Errorf("admitted archive-byte resolver absent")
	}
	profiles, ok := authority.(DocumentationFactoryOODCanonicalRepresentationResolver)
	if !ok {
		return nil, nil, fmt.Errorf("admitted canonical representation resolver absent")
	}
	manifests, ok := authority.(DocumentationFactoryOODEvidenceManifestBindingVerifier)
	if !ok {
		return nil, nil, fmt.Errorf("admitted evidence-manifest binding verifier absent")
	}
	receipts := map[string]oodpublication.SpannerRow{}
	batches := map[string]oodpublication.SpannerRow{}
	for _, r := range rows {
		if r.Table == "OODGraphExternalFetchReceipts" {
			receipts[r.Columns["receipt_id"].(string)] = r
		}
		if r.Table == "OODGraphExternalFetchBatches" {
			batches[r.Columns["fetch_batch_id"].(string)] = r
		}
	}
	out := make([]DocumentationFactorySourcePackageOODLocatorBinding, 0, len(p.Locators))
	members := make([]oodpublication.ManifestMemberV8, 0, len(p.Locators))
	for _, native := range p.Locators {
		var receiptRow oodpublication.SpannerRow
		matches := 0
		for _, r := range receipts {
			if r.Columns["source_content_hash"] != native.SourceContentSHA256 {
				continue
			}
			stable, _ := r.Columns["source_stable_reference"].(string)
			if nativeLocatorRef(native.SourceRefs, stable) {
				receiptRow = r
				matches++
			}
		}
		if receiptRow.Table == "" || matches == 0 {
			return nil, nil, fmt.Errorf("native locator %q has no exact qualified receipt", native.ID)
		}
		if matches != 1 {
			return nil, nil, fmt.Errorf("native locator %q has ambiguous qualified receipts: %d", native.ID, matches)
		}
		batchRow := batches[receiptRow.Columns["fetch_batch_id"].(string)]
		if batchRow.Table == "" {
			return nil, nil, fmt.Errorf("native locator %q has no qualified batch", native.ID)
		}
		receipt, e := oodpublication.ReceiptV8FromPhysicalRow(receiptRow)
		if e != nil {
			return nil, nil, e
		}
		if e = manifests.VerifyEvidenceManifestBinding(ctx, receipt, native.EvidenceManifestSHA256); e != nil {
			return nil, nil, fmt.Errorf("native locator %q evidence manifest: %w", native.ID, e)
		}
		batch, e := oodpublication.BatchV8FromPhysicalRow(batchRow)
		if e != nil {
			return nil, nil, e
		}
		body, e := archive.ReadArchivedCanonicalBytes(ctx, receipt)
		if e != nil {
			return nil, nil, fmt.Errorf("native locator %q archive: %w", native.ID, e)
		}
		artifact, e := oodpublication.SourceArtifactExternalEvidenceDigest([]oodpublication.SpannerRow{receiptRow, batchRow})
		if e != nil {
			return nil, nil, e
		}
		ref, digest, e := profiles.ResolveCanonicalRepresentationProfile(ctx, receipt)
		if e != nil || ref == "" || digest == "" {
			return nil, nil, fmt.Errorf("native locator %q representation profile: %w", native.ID, e)
		}
		l := oodproof.GraphFactLocator{OrganizationID: receipt.OrganizationID, EvidenceIdentityHash: receipt.EvidenceIdentityHash, SourceArtifactMemberHash: artifact, EligibleReceiptID: receipt.ReceiptID, EligibleReceiptDigest: receipt.RedactedTransportEvidenceDigest, SealedCompletenessCertificateHash: batch.CompletenessEvidenceDigest, EvidenceArchiveAuthorityID: receipt.EvidenceArchiveAuthorityID, EvidenceArchiveRecordID: receipt.EvidenceArchiveRecordID, EvidenceArchiveRecordDigest: receipt.EvidenceArchiveRecordDigest, SourceContentHashAlgorithm: receipt.SourceContentHashAlgorithm, SourceContentHashProfile: receipt.SourceContentHashProfile, SourceContentHash: receipt.SourceContentHash, SourceContentByteLength: receipt.EvidenceArchiveByteCount, CanonicalRepresentationProfileRef: ref, CanonicalRepresentationProfileDigest: digest, ByteStartOffset: native.ByteStartOffset, ByteEndOffsetExclusive: native.ByteEndOffsetExclusive, SelectedRangeContentHash: native.SelectedRangeSHA256, SelectedRangeByteCount: native.SelectedRangeByteCount, EvidenceArchiveDeletionDomainID: receipt.EvidenceArchiveDeletionDomainID, EvidenceArchiveCryptoShredDomainID: receipt.EvidenceArchiveCryptoShredDomainID}
		l.LocatorHash, e = l.ComputedHash()
		if e != nil {
			return nil, nil, e
		}
		if _, e = oodproof.VerifyGraphFactLocator(ctx, l, body); e != nil {
			return nil, nil, fmt.Errorf("native locator %q: %w", native.ID, e)
		}
		m := map[string]interface{}{"organization_id": l.OrganizationID, "graph_fact_locator_hash": l.LocatorHash, "evidence_identity_hash": l.EvidenceIdentityHash, "source_artifact_member_hash": l.SourceArtifactMemberHash, "eligible_receipt_id": l.EligibleReceiptID, "eligible_receipt_digest": l.EligibleReceiptDigest, "sealed_completeness_certificate_hash": l.SealedCompletenessCertificateHash, "evidence_archive_authority_id": l.EvidenceArchiveAuthorityID, "evidence_archive_record_id": l.EvidenceArchiveRecordID, "evidence_archive_record_digest": l.EvidenceArchiveRecordDigest, "source_content_hash_algorithm": l.SourceContentHashAlgorithm, "source_content_hash_profile": l.SourceContentHashProfile, "source_content_hash": l.SourceContentHash, "source_content_byte_length": l.SourceContentByteLength, "canonical_representation_profile_ref": l.CanonicalRepresentationProfileRef, "canonical_representation_profile_digest": l.CanonicalRepresentationProfileDigest, "byte_start_offset": l.ByteStartOffset, "byte_end_offset_exclusive": l.ByteEndOffsetExclusive, "selected_range_content_hash": l.SelectedRangeContentHash, "selected_range_byte_count": l.SelectedRangeByteCount, "evidence_archive_deletion_domain_id": l.EvidenceArchiveDeletionDomainID, "evidence_archive_crypto_shred_domain_id": l.EvidenceArchiveCryptoShredDomainID, "created_at": createdAt}
		x, e := oodpublication.BuildImmutableRow("OODGraphGraphFactEvidenceLocators", m)
		if e != nil {
			return nil, nil, e
		}
		row := x.Row()
		out = append(out, DocumentationFactorySourcePackageOODLocatorBinding{NativeLocatorID: native.ID, SourceArtifactHash: artifact, Receipt: receiptRow, Batch: batchRow, Locator: l, LocatorRow: row})
		members = append(members, oodpublication.ManifestMemberV8{ManifestKind: "graph_fact_locator", EntryKind: "graph_fact_locator", MemberID: l.LocatorHash, ClaimedHash: l.LocatorHash, Row: &row})
	}
	return out, members, nil
}
func nativeLocatorRef(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
