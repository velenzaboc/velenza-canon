package oodpublication

// Row-derived member hashing.  This is intentionally a small closed router:
// a table with no pinned owner profile is rejected rather than accepting a
// caller preimage or a convenient JSON SHA-256 substitute.

import (
	"errors"
	"fmt"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
)

// CanonicalMemberDigestFromPhysicalRow derives a member digest entirely from
// a strict immutable row.  It is the only admissible route for profiles whose
// owner tuple is pinned in oodcanon.
func CanonicalMemberDigestFromPhysicalRow(row SpannerRow) (string, error) {
	if _, err := BuildImmutableRow(row.Table, row.Columns); err != nil {
		return "", err
	}
	if p, err := oodcanon.GraphFactProfileForPhysicalTable(row.Table); err == nil {
		r, err := recordFromPhysical(p, row)
		if err != nil {
			return "", err
		}
		return oodcanon.DigestHexOf(p, r)
	}
	switch row.Table {
	case "OODGraphExternalFetchReceipts":
		r, err := ReceiptV8FromPhysicalRow(row)
		if err != nil {
			return "", err
		}
		return oodevidence.ReceiptDigestV8(r)
	case "OODGraphRelationshipEvidence":
		r, err := recordFromPhysical(oodcanon.RelationshipEvidenceV1(), row)
		if err != nil {
			return "", err
		}
		return oodcanon.DigestHexOf(oodcanon.RelationshipEvidenceV1(), r)
	case "OODGraphGraphFactEvidenceLocators":
		return graphFactLocatorDigest(row)
	case "OODGraphViolations":
		return CanonicalViolationMemberDigest(row)
	case "OODGraphProjectionArtifacts":
		return structuralProjectionDigest(row)
	case "OODGraphAPIPropertyFacts":
		// property_payload_hash has a schema-selected closed encoding.  The
		// selected schema validator is an authority input, not JSON formatting;
		// accepting this row without that validator would trust its stored hash.
		return "", errors.New("API property member requires admitted payload-schema validator")
	default:
		return "", fmt.Errorf("no pinned physical member profile for %s", row.Table)
	}
}

func graphFactLocatorDigest(row SpannerRow) (string, error) {
	v := row.Columns
	l := oodproof.GraphFactLocator{LocatorHash: v["graph_fact_locator_hash"].(string), OrganizationID: v["organization_id"].(string), EvidenceIdentityHash: v["evidence_identity_hash"].(string), SourceArtifactMemberHash: v["source_artifact_member_hash"].(string), EligibleReceiptID: v["eligible_receipt_id"].(string), EligibleReceiptDigest: v["eligible_receipt_digest"].(string), SealedCompletenessCertificateHash: v["sealed_completeness_certificate_hash"].(string), EvidenceArchiveAuthorityID: v["evidence_archive_authority_id"].(string), EvidenceArchiveRecordID: v["evidence_archive_record_id"].(string), EvidenceArchiveRecordDigest: v["evidence_archive_record_digest"].(string), SourceContentHashAlgorithm: v["source_content_hash_algorithm"].(string), SourceContentHashProfile: v["source_content_hash_profile"].(string), SourceContentHash: v["source_content_hash"].(string), SourceContentByteLength: v["source_content_byte_length"].(int64), CanonicalRepresentationProfileRef: v["canonical_representation_profile_ref"].(string), CanonicalRepresentationProfileDigest: v["canonical_representation_profile_digest"].(string), ByteStartOffset: v["byte_start_offset"].(int64), ByteEndOffsetExclusive: v["byte_end_offset_exclusive"].(int64), SelectedRangeContentHash: v["selected_range_content_hash"].(string), SelectedRangeByteCount: v["selected_range_byte_count"].(int64), EvidenceArchiveDeletionDomainID: v["evidence_archive_deletion_domain_id"].(string), EvidenceArchiveCryptoShredDomainID: v["evidence_archive_crypto_shred_domain_id"].(string)}
	d, e := l.ComputedHash()
	if e != nil {
		return "", e
	}
	if d != l.LocatorHash {
		return "", errors.New("physical graph fact locator hash mismatch")
	}
	return d, nil
}

// SourceArtifactExternalEvidenceDigest derives the virtual source-manifest
// member from its protected receipt and governing batch rows. No synthetic
// source-artifact physical row is accepted.
func SourceArtifactExternalEvidenceDigest(rows []SpannerRow) (string, error) {
	// This exported helper is safe for direct use: it verifies the complete
	// strict physical pair and their canonical evidence digests itself, rather
	// than relying on ManifestClosureReconciler having run first.
	if err := verifyVirtualSourceEvidence(rows); err != nil {
		return "", err
	}
	var receipt, batch *SpannerRow
	if len(rows) != 2 {
		return "", errors.New("source artifact requires exactly receipt and batch evidence rows")
	}
	for i := range rows {
		switch rows[i].Table {
		case "OODGraphExternalFetchReceipts":
			if receipt != nil {
				return "", errors.New("duplicate source artifact receipt evidence row")
			}
			receipt = &rows[i]
		case "OODGraphExternalFetchBatches":
			if batch != nil {
				return "", errors.New("duplicate source artifact batch evidence row")
			}
			batch = &rows[i]
		default:
			return "", errors.New("ineligible source artifact evidence row")
		}
	}
	if receipt == nil || batch == nil {
		return "", errors.New("source artifact requires receipt and batch evidence rows")
	}
	if receipt.Columns["organization_id"] != batch.Columns["organization_id"] || receipt.Columns["fetch_batch_id"] != batch.Columns["fetch_batch_id"] {
		return "", errors.New("source artifact receipt/batch coordinate mismatch")
	}
	p := oodcanon.SourceArtifactExternalEvidenceV2()
	r := oodcanon.RecordValue{}
	put := func(name string, typ oodcanon.Type, x interface{}) error {
		v, e := physicalOwnerValue(oodcanon.Field{Name: name, Type: typ, Policy: oodcanon.Required}, x)
		if e != nil {
			return e
		}
		r[name] = v
		return nil
	}
	for _, x := range []struct {
		name  string
		typ   oodcanon.Type
		value interface{}
	}{{"organization_id", oodcanon.UTF8, receipt.Columns["organization_id"]}, {"source_authority_id", oodcanon.UUID, receipt.Columns["source_authority_id"]}, {"source_ref_kind", oodcanon.UTF8, receipt.Columns["source_ref_kind"]}, {"canonical_source_stable_reference", oodcanon.UTF8, receipt.Columns["source_stable_reference"]}, {"selected_version_coordinate", oodcanon.UTF8, receipt.Columns["version_coordinate"]}, {"content_hash_algorithm", oodcanon.UTF8, receipt.Columns["source_content_hash_algorithm"]}, {"content_hash_profile", oodcanon.UTF8, receipt.Columns["source_content_hash_profile"]}, {"authoritative_content_digest", oodcanon.SHA256, receipt.Columns["source_content_hash"]}, {"evidence_identity_hash", oodcanon.SHA256, receipt.Columns["evidence_identity_hash"]}, {"canonical_content_byte_length", oodcanon.Int64, receipt.Columns["evidence_archive_byte_count"]}, {"source_declared_completeness_relationship_hash", oodcanon.SHA256, batch.Columns["verified_completeness_claim_digest"]}} {
		if e := put(x.name, x.typ, x.value); e != nil {
			return "", e
		}
	}
	return oodcanon.DigestHexOf(p, r)
}

func verifyVirtualSourceEvidence(rows []SpannerRow) error {
	if len(rows) != 2 {
		return errors.New("virtual source evidence row count")
	}
	var receiptRow, batchRow *SpannerRow
	for i := range rows {
		switch rows[i].Table {
		case "OODGraphExternalFetchReceipts":
			if receiptRow != nil {
				return errors.New("duplicate virtual receipt row")
			}
			receiptRow = &rows[i]
		case "OODGraphExternalFetchBatches":
			if batchRow != nil {
				return errors.New("duplicate virtual batch row")
			}
			batchRow = &rows[i]
		default:
			return errors.New("ineligible virtual evidence row")
		}
	}
	if receiptRow == nil || batchRow == nil {
		return errors.New("virtual source receipt/batch rows absent")
	}
	receipt, e := ReceiptV8FromPhysicalRow(*receiptRow)
	if e != nil {
		return e
	}
	batch, e := BatchV8FromPhysicalRow(*batchRow)
	if e != nil {
		return e
	}
	if receipt.OrganizationID != batch.OrganizationID || receipt.FetchBatchID != batch.FetchBatchID {
		return errors.New("typed virtual receipt/batch coordinate mismatch")
	}
	rd, e := oodevidence.ReceiptDigestV8(receipt)
	if e != nil {
		return fmt.Errorf("recompute virtual receipt: %w", e)
	}
	bd, e := oodevidence.CompletenessEvidenceDigestV8(batch)
	if e != nil {
		return fmt.Errorf("recompute virtual batch: %w", e)
	}
	for _, row := range rows {
		switch row.Table {
		case "OODGraphExternalFetchReceipts":
			if row.Columns["organization_id"] != receipt.OrganizationID || row.Columns["fetch_batch_id"] != receipt.FetchBatchID || row.Columns["receipt_id"] != receipt.ReceiptID || row.Columns["redacted_transport_evidence_digest"] != rd {
				return errors.New("physical virtual receipt digest binding mismatch")
			}
		case "OODGraphExternalFetchBatches":
			if row.Columns["organization_id"] != batch.OrganizationID || row.Columns["fetch_batch_id"] != batch.FetchBatchID || row.Columns["completeness_evidence_digest"] != bd {
				return errors.New("physical virtual batch digest binding mismatch")
			}
		}
	}
	return nil
}

func structuralProjectionDigest(row SpannerRow) (string, error) {
	p := oodcanon.StructuralProjectionArtifactV1()
	payload, ok := row.Columns["projection_payload"].(CanonicalJSON)
	if !ok {
		return "", errors.New("projection payload is not canonical JSON bytes")
	}
	// Build the complete record from strict typed columns.  In particular the
	// payload bytes themselves (not projection_hash) enter the owner tuple.
	r := oodcanon.RecordValue{
		"organization_id":                    oodcanon.String(row.Columns["organization_id"].(string)),
		"projection_kind":                    oodcanon.String(row.Columns["projection_kind"].(string)),
		"projection_target_kind":             oodcanon.String(row.Columns["projection_target_kind"].(string)),
		"projection_format":                  oodcanon.String(row.Columns["projection_format"].(string)),
		"canonical_projection_payload_bytes": oodcanon.Bytes(payload),
		"round_trip_state":                   oodcanon.String(row.Columns["round_trip_state"].(string)),
	}
	if x := row.Columns["projection_target_id"]; x == nil {
		r["projection_target_id"] = oodcanon.NullValue(oodcanon.UUID)
	} else {
		s, ok := x.(string)
		if !ok {
			return "", errors.New("projection target id is not UUID text")
		}
		v, e := oodcanon.UUIDText(s)
		if e != nil {
			return "", e
		}
		r["projection_target_id"] = v
	}
	return oodcanon.DigestHexOf(p, r)
}
