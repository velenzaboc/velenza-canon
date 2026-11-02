package oodevidence

import (
	"fmt"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

// ReceiptDigestV8 replays OOD8's complete 65-field receipt preimage. It does
// not accept a caller-selected profile and therefore cannot silently hash a
// convenient projection of a receipt row.
func ReceiptDigestV8(r ReceiptV8) (string, error) {
	return receiptDigestV8(r, nil)
}
func receiptDigestV8(r ReceiptV8, admittedNoncomponent map[string]int64) (string, error) {
	p, err := oodcanon.ProfileFor("external_fetch_receipt_v1")
	if err != nil {
		return "", err
	}
	v, err := receiptRecord(r, admittedNoncomponent)
	if err != nil {
		return "", err
	}
	return oodcanon.DigestHexOf(p, v)
}

// CompletenessEvidenceDigestV8 replays the sealed batch certificate digest.
// Manifest membership and parsed claim validation are intentionally separate:
// their inputs are not trusted merely because this hash can be recomputed.
func CompletenessEvidenceDigestV8(b BatchV8) (string, error) {
	p, err := oodcanon.ProfileFor("external_fetch_completeness_evidence_v3")
	if err != nil {
		return "", err
	}
	v, err := batchRecord(b)
	if err != nil {
		return "", err
	}
	return oodcanon.DigestHexOf(p, v)
}

func receiptRecord(r ReceiptV8, admittedNoncomponent map[string]int64) (oodcanon.RecordValue, error) {
	if err := ValidateReceiptRoles(r.ReceiptRoles, admittedNoncomponent); err != nil {
		return nil, err
	}
	hasComponent := false
	for _, role := range r.ReceiptRoles {
		if role == "component" {
			hasComponent = true
		}
	}
	if hasComponent && (r.FetchComponentOrdinal == nil || *r.FetchComponentOrdinal < 0) {
		return nil, fmt.Errorf("component receipt requires nonnegative component ordinal")
	}
	if !hasComponent && r.FetchComponentOrdinal != nil {
		return nil, fmt.Errorf("noncomponent receipt requires null component ordinal")
	}
	if r.TransportRawByteCount < 0 || r.TransportDecodedByteCount < 0 || r.EvidenceArchiveByteCount < 0 || r.TransportDecodedByteCount != r.EvidenceArchiveByteCount {
		return nil, fmt.Errorf("invalid transport/archive byte counts")
	}
	expected := 0
	for _, value := range []*string{r.PermissionExpectedContentHashAlgorithm, r.PermissionExpectedContentHashProfile, r.PermissionExpectedContentHash} {
		if value != nil {
			expected++
		}
	}
	if expected != 0 && expected != 3 {
		return nil, fmt.Errorf("expected content hash tuple must be all-null or all-present")
	}
	v := oodcanon.RecordValue{}
	if err := addStrings(v, map[string]string{
		"organization_id": r.OrganizationID, "fetch_batch_id": r.FetchBatchID, "fetch_occurrence_id": r.FetchOccurrenceID, "object_class": r.ObjectClass, "source_ref_kind": r.SourceRefKind, "source_stable_reference": r.SourceStableReference, "source_representation_kind": r.SourceRepresentationKind, "evidence_content_class": r.EvidenceContentClass, "version_coordinate": r.VersionCoordinate, "source_content_hash_algorithm": r.SourceContentHashAlgorithm, "source_content_hash_profile": r.SourceContentHashProfile, "external_fetch_profile_ref": r.ExternalFetchProfileRef, "permission_operation": r.PermissionOperation, "permission_method": r.PermissionMethod, "permission_content_class": r.PermissionContentClass, "permission_trust_class": r.PermissionTrustClass, "permission_status": r.PermissionStatus, "permission_policy_version_ref": r.PermissionPolicyVersionRef, "fetch_authorization_decision_ref": r.FetchAuthorizationDecisionRef, "transport_status": r.TransportStatus, "transport_raw_content_hash_algorithm": r.TransportRawContentHashAlgorithm,
	}); err != nil {
		return nil, err
	}
	if err := addUUIDs(v, map[string]string{"receipt_id": r.ReceiptID, "graph_object_id": r.GraphObjectID, "source_authority_id": r.SourceAuthorityID, "source_authority_binding_id": r.SourceAuthorityBindingID, "representation_declaration_id": r.RepresentationDeclarationID, "permission_grant_id": r.PermissionGrantID, "permission_authority_id": r.PermissionAuthorityID, "permission_principal_id": r.PermissionPrincipalID, "evidence_archive_authority_id": r.EvidenceArchiveAuthorityID, "evidence_archive_record_id": r.EvidenceArchiveRecordID, "evidence_archive_deletion_domain_id": r.EvidenceArchiveDeletionDomainID, "evidence_archive_crypto_shred_domain_id": r.EvidenceArchiveCryptoShredDomainID, "receipt_deletion_domain_id": r.ReceiptDeletionDomainID, "receipt_crypto_shred_domain_id": r.ReceiptCryptoShredDomainID}); err != nil {
		return nil, err
	}
	if err := addDigests(v, map[string]string{"evidence_identity_hash": r.EvidenceIdentityHash, "source_authority_binding_digest": r.SourceAuthorityBindingDigest, "representation_declaration_digest": r.RepresentationDeclarationDigest, "source_content_hash": r.SourceContentHash, "external_fetch_profile_digest": r.ExternalFetchProfileDigest, "permission_grant_digest": r.PermissionGrantDigest, "permission_scope_digest": r.PermissionScopeDigest, "permission_redirect_policy_digest": r.PermissionRedirectPolicyDigest, "permission_policy_version_digest": r.PermissionPolicyVersionDigest, "fetch_authorization_decision_digest": r.FetchAuthorizationDecisionDigest, "transport_raw_content_hash": r.TransportRawContentHash, "transport_response_metadata_digest": r.TransportResponseMetadataDigest, "evidence_archive_record_digest": r.EvidenceArchiveRecordDigest}); err != nil {
		return nil, err
	}
	v["receipt_roles"] = roleArray(r.ReceiptRoles)
	v["fetch_component_ordinal"] = nullableI64(r.FetchComponentOrdinal)
	v["source_representation_media_type"] = nullableString(r.SourceRepresentationMediaType)
	v["permission_byte_ceiling"], v["permission_depth_ceiling"] = oodcanon.I64(r.PermissionByteCeiling), oodcanon.I64(r.PermissionDepthCeiling)
	v["permission_expected_content_hash_algorithm"], v["permission_expected_content_hash_profile"] = nullableString(r.PermissionExpectedContentHashAlgorithm), nullableString(r.PermissionExpectedContentHashProfile)
	if r.PermissionExpectedContentHash == nil {
		v["permission_expected_content_hash"] = oodcanon.NullValue(oodcanon.SHA256)
	} else {
		x, e := oodcanon.DigestHex(*r.PermissionExpectedContentHash)
		if e != nil {
			return nil, e
		}
		v["permission_expected_content_hash"] = x
	}
	var err error
	if v["permission_effective_at"], err = timestamp(r.PermissionEffectiveAt); err != nil {
		return nil, err
	}
	if r.PermissionExpiresAt == nil {
		v["permission_expires_at"] = oodcanon.NullValue(oodcanon.TimestampMicroseconds)
	} else if v["permission_expires_at"], err = timestamp(*r.PermissionExpiresAt); err != nil {
		return nil, err
	}
	if v["observed_at"], err = timestamp(r.ObservedAt); err != nil {
		return nil, err
	}
	v["transport_raw_byte_count"], v["transport_decoded_byte_count"], v["evidence_archive_byte_count"] = oodcanon.I64(r.TransportRawByteCount), oodcanon.I64(r.TransportDecodedByteCount), oodcanon.I64(r.EvidenceArchiveByteCount)
	v["transport_content_encoding"], v["transport_charset"] = nullableString(r.TransportContentEncoding), nullableString(r.TransportCharset)
	return v, nil
}

func batchRecord(b BatchV8) (oodcanon.RecordValue, error) {
	v := oodcanon.RecordValue{}
	if err := addStrings(v, map[string]string{"organization_id": b.OrganizationID, "fetch_batch_id": b.FetchBatchID, "completeness_basis_kind": b.CompletenessBasisKind, "completeness_evidence_ref": b.CompletenessEvidenceRef, "completeness_evidence_content_hash_algorithm": b.CompletenessEvidenceContentHashAlgorithm, "completeness_evidence_content_hash_profile": b.CompletenessEvidenceContentHashProfile, "completeness_evidence_selector_kind": b.CompletenessEvidenceSelectorKind, "completeness_evidence_selector_value": b.CompletenessEvidenceSelectorValue, "completeness_profile_ref": b.CompletenessProfileRef}); err != nil {
		return nil, err
	}
	if err := addUUIDs(v, map[string]string{"source_authority_binding_id": b.SourceAuthorityBindingID, "representation_declaration_id": b.RepresentationDeclarationID, "completeness_evidence_receipt_id": b.CompletenessEvidenceReceiptID, "completeness_evidence_archive_authority_id": b.CompletenessEvidenceArchiveAuthorityID, "completeness_evidence_archive_record_id": b.CompletenessEvidenceArchiveRecordID}); err != nil {
		return nil, err
	}
	if err := addDigests(v, map[string]string{"source_authority_binding_digest": b.SourceAuthorityBindingDigest, "representation_declaration_digest": b.RepresentationDeclarationDigest, "batch_receipt_manifest_root_hash": b.BatchReceiptManifestRootHash, "completeness_evidence_identity_hash": b.CompletenessEvidenceIdentityHash, "completeness_evidence_content_hash": b.CompletenessEvidenceContentHash, "completeness_evidence_archive_record_digest": b.CompletenessEvidenceArchiveRecordDigest, "verified_completeness_claim_digest": b.VerifiedCompletenessClaimDigest, "completeness_profile_digest": b.CompletenessProfileDigest}); err != nil {
		return nil, err
	}
	v["total_receipt_count"], v["component_receipt_count"], v["completeness_evidence_receipt_count"], v["noncomponent_receipt_count"] = oodcanon.I64(b.TotalReceiptCount), oodcanon.I64(b.ComponentReceiptCount), oodcanon.I64(b.CompletenessEvidenceReceiptCount), oodcanon.I64(b.NoncomponentReceiptCount)
	v["expected_component_count"] = nullableI64(b.ExpectedComponentCount)
	return v, nil
}

func addStrings(v oodcanon.RecordValue, in map[string]string) error {
	for k, x := range in {
		if x == "" {
			return fmt.Errorf("%s empty", k)
		}
		v[k] = oodcanon.String(x)
	}
	return nil
}
func addUUIDs(v oodcanon.RecordValue, in map[string]string) error {
	for k, x := range in {
		y, e := oodcanon.UUIDText(x)
		if e != nil {
			return fmt.Errorf("%s: %w", k, e)
		}
		v[k] = y
	}
	return nil
}
func addDigests(v oodcanon.RecordValue, in map[string]string) error {
	for k, x := range in {
		y, e := oodcanon.DigestHex(x)
		if e != nil {
			return fmt.Errorf("%s: %w", k, e)
		}
		v[k] = y
	}
	return nil
}
func nullableString(x *string) oodcanon.Value {
	if x == nil {
		return oodcanon.NullValue(oodcanon.UTF8)
	}
	return oodcanon.String(*x)
}
func nullableI64(x *int64) oodcanon.Value {
	if x == nil {
		return oodcanon.NullValue(oodcanon.Int64)
	}
	return oodcanon.I64(*x)
}
func roleArray(xs []string) oodcanon.Value {
	a := make([]oodcanon.Value, len(xs))
	for i, x := range xs {
		a[i] = oodcanon.String(x)
	}
	return oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present, Elements: a}
}
func timestamp(x time.Time) (oodcanon.Value, error) {
	if x.IsZero() || x.Location() != time.UTC || x.Nanosecond()%1000 != 0 {
		return oodcanon.Value{}, fmt.Errorf("timestamp must be nonzero UTC microseconds")
	}
	return oodcanon.Value{Type: oodcanon.TimestampMicroseconds, Presence: oodcanon.Present, Bytes: i64bytes(x.UnixMicro())}, nil
}
func i64bytes(x int64) []byte {
	return []byte{byte(uint64(x) >> 56), byte(uint64(x) >> 48), byte(uint64(x) >> 40), byte(uint64(x) >> 32), byte(uint64(x) >> 24), byte(uint64(x) >> 16), byte(uint64(x) >> 8), byte(x)}
}
