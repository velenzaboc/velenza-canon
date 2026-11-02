package oodevidence

import (
	"context"
	"errors"
	"fmt"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
)

// RelationshipV8 is the closed OODGraphRelationshipEvidence canonical tuple.
// Its output hash is deliberately separate from evidence acquisition rows.
type RelationshipV8 struct {
	OrganizationID, RelationshipEvidenceHash                                                                               string
	EvidenceSourceKind, PatchAction, SourceObjectClass                                                                     string
	SourceAuthorityID, SourceRefKind, SourceStableReference, SourceVersionCoordinate, SourceSectionPath                    string
	TargetObjectClass, TargetAuthorityID, TargetRefKind, TargetStableReference, TargetVersionCoordinate, TargetSectionPath string
	EdgeLabel, AuthoringSourcePath                                                                                         string
	EvidenceAuthorityID, EvidenceStableReference, EvidenceVersionCoordinate                                                string
	EvidenceContentHashAlgorithm, EvidenceContentHashProfile, EvidenceContentHash                                          string
	EvidenceIdentityHash, EligibleReceiptID, EligibleReceiptDigest, SealedCompletenessCertificateHash                      *string
	EvidenceArchiveAuthorityID, EvidenceArchiveRecordID, EvidenceArchiveRecordDigest                                       *string
	GraphFactLocatorManifestHash                                                                                           *string
	ExtractorProfileID, ExtractorProfileVersion, ExtractorProfileDigest                                                    *string
	EvidenceAuthorityClass, ParentGraphSnapshotID                                                                          *string
}

// ProfileEligibilityAuthority resolves profile/current eligibility from the
// protected owner. It is intentionally richer than a bool: implementations
// must reject stale, revoked, tenant-mismatched, or unknown profile bindings.
type ProfileEligibilityAuthority interface {
	VerifyCurrentRelationshipEligibility(context.Context, RelationshipV8, ReceiptV8, BatchV8) error
}

// VerifyRelationshipLocator binds one classified relationship to a receipt
// selected from an opaque complete batch, its exact archive body, and an OOD
// graph fact locator. No graph publication authority is granted here.
func VerifyRelationshipLocator(ctx context.Context, relationship RelationshipV8, batch VerifiedBatchV8, locator oodproof.GraphFactLocator, archivedBody []byte, eligibility ProfileEligibilityAuthority) error {
	if eligibility == nil {
		return errors.New("current profile eligibility authority unavailable")
	}
	receipt, err := verifyGraphFactLocatorReceipt(ctx, batch, locator, archivedBody)
	if err != nil {
		return err
	}
	computed, err := RelationshipEvidenceDigestV8(relationship)
	if err != nil {
		return err
	}
	if computed != relationship.RelationshipEvidenceHash {
		return errors.New("relationship evidence hash mismatch")
	}
	if relationship.OrganizationID != receipt.OrganizationID || relationship.EvidenceIdentityHash == nil || *relationship.EvidenceIdentityHash != receipt.EvidenceIdentityHash || relationship.EligibleReceiptID == nil || *relationship.EligibleReceiptID != receipt.ReceiptID || relationship.EligibleReceiptDigest == nil || *relationship.EligibleReceiptDigest != receipt.RedactedTransportEvidenceDigest || relationship.SealedCompletenessCertificateHash == nil || *relationship.SealedCompletenessCertificateHash != batch.CompletenessEvidenceDigest() || relationship.EvidenceArchiveAuthorityID == nil || *relationship.EvidenceArchiveAuthorityID != receipt.EvidenceArchiveAuthorityID || relationship.EvidenceArchiveRecordID == nil || *relationship.EvidenceArchiveRecordID != receipt.EvidenceArchiveRecordID || relationship.EvidenceArchiveRecordDigest == nil || *relationship.EvidenceArchiveRecordDigest != receipt.EvidenceArchiveRecordDigest {
		return errors.New("relationship receipt/archive closure mismatch")
	}
	if relationship.EvidenceContentHashAlgorithm != receipt.SourceContentHashAlgorithm || relationship.EvidenceContentHashProfile != receipt.SourceContentHashProfile || relationship.EvidenceContentHash != receipt.SourceContentHash {
		return errors.New("relationship content binding mismatch")
	}
	if err := eligibility.VerifyCurrentRelationshipEligibility(ctx, relationship, receipt, batch.batch); err != nil {
		return fmt.Errorf("current relationship eligibility: %w", err)
	}
	return nil
}

func RelationshipEvidenceDigestV8(r RelationshipV8) (string, error) {
	p, e := oodcanon.ProfileFor("ood_graph_relationship_evidence_v1")
	if e != nil {
		return "", e
	}
	v, e := relationshipRecord(r)
	if e != nil {
		return "", e
	}
	return oodcanon.DigestHexOf(p, v)
}
func relationshipRecord(r RelationshipV8) (oodcanon.RecordValue, error) {
	v := oodcanon.RecordValue{}
	if e := addStrings(v, map[string]string{"organization_id": r.OrganizationID, "evidence_source_kind": r.EvidenceSourceKind, "patch_action": r.PatchAction, "source_object_class": r.SourceObjectClass, "source_ref_kind": r.SourceRefKind, "source_stable_reference": r.SourceStableReference, "source_version_coordinate": r.SourceVersionCoordinate, "source_section_path": r.SourceSectionPath, "target_object_class": r.TargetObjectClass, "target_ref_kind": r.TargetRefKind, "target_stable_reference": r.TargetStableReference, "target_version_coordinate": r.TargetVersionCoordinate, "target_section_path": r.TargetSectionPath, "edge_label": r.EdgeLabel, "authoring_source_path": r.AuthoringSourcePath, "evidence_stable_reference": r.EvidenceStableReference, "evidence_version_coordinate": r.EvidenceVersionCoordinate, "evidence_content_hash_algorithm": r.EvidenceContentHashAlgorithm, "evidence_content_hash_profile": r.EvidenceContentHashProfile}); e != nil {
		return nil, e
	}
	if e := addUUIDs(v, map[string]string{"source_authority_id": r.SourceAuthorityID, "target_authority_id": r.TargetAuthorityID, "evidence_authority_id": r.EvidenceAuthorityID}); e != nil {
		return nil, e
	}
	if e := addDigests(v, map[string]string{"evidence_content_hash": r.EvidenceContentHash}); e != nil {
		return nil, e
	}
	v["evidence_identity_hash"], v["eligible_receipt_digest"], v["sealed_completeness_certificate_hash"], v["evidence_archive_record_digest"], v["graph_fact_locator_manifest_hash"], v["extractor_profile_digest"] = nullableDigest(r.EvidenceIdentityHash), nullableDigest(r.EligibleReceiptDigest), nullableDigest(r.SealedCompletenessCertificateHash), nullableDigest(r.EvidenceArchiveRecordDigest), nullableDigest(r.GraphFactLocatorManifestHash), nullableDigest(r.ExtractorProfileDigest)
	v["eligible_receipt_id"], v["evidence_archive_authority_id"], v["evidence_archive_record_id"], v["extractor_profile_id"], v["parent_graph_snapshot_id"] = nullableUUID(r.EligibleReceiptID), nullableUUID(r.EvidenceArchiveAuthorityID), nullableUUID(r.EvidenceArchiveRecordID), nullableUUID(r.ExtractorProfileID), nullableUUID(r.ParentGraphSnapshotID)
	v["extractor_profile_version"], v["evidence_authority_class"] = nullableString(r.ExtractorProfileVersion), nullableString(r.EvidenceAuthorityClass)
	return v, nil
}
func nullableDigest(x *string) oodcanon.Value {
	if x == nil {
		return oodcanon.NullValue(oodcanon.SHA256)
	}
	v, e := oodcanon.DigestHex(*x)
	if e != nil {
		return oodcanon.Value{}
	}
	return v
}
func nullableUUID(x *string) oodcanon.Value {
	if x == nil {
		return oodcanon.NullValue(oodcanon.UUID)
	}
	v, e := oodcanon.UUIDText(*x)
	if e != nil {
		return oodcanon.Value{}
	}
	return v
}
