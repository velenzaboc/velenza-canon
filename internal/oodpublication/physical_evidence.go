package oodpublication

// Typed hydration of the two physical source-evidence rows.  This deliberately
// follows BuildImmutableRow first: a map is permitted at the Spanner boundary,
// but it is not permitted to become evidence until its table roster, types, and
// nullability have been closed by the immutable physical codec.

import (
	"fmt"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

// ReceiptV8FromPhysicalRow reconstructs every proof-relevant receipt field
// from its complete, strictly admitted physical row.
func ReceiptV8FromPhysicalRow(input SpannerRow) (oodevidence.ReceiptV8, error) {
	row, err := evidencePhysicalRow(input, "OODGraphExternalFetchReceipts")
	if err != nil {
		return oodevidence.ReceiptV8{}, err
	}
	v := row.Columns
	r := oodevidence.ReceiptV8{
		OrganizationID: text(v, "organization_id"), ReceiptID: text(v, "receipt_id"), FetchBatchID: text(v, "fetch_batch_id"), ReceiptRoles: stringSlice(v, "receipt_roles"),
		FetchComponentOrdinal: optionalInt64(v, "fetch_component_ordinal"), FetchOccurrenceID: text(v, "fetch_occurrence_id"), EvidenceIdentityHash: text(v, "evidence_identity_hash"),
		GraphObjectID: text(v, "graph_object_id"), ObjectClass: text(v, "object_class"), SourceAuthorityID: text(v, "source_authority_id"), SourceAuthorityBindingID: text(v, "source_authority_binding_id"), SourceAuthorityBindingDigest: text(v, "source_authority_binding_digest"),
		SourceRefKind: text(v, "source_ref_kind"), SourceStableReference: text(v, "source_stable_reference"), SourceRepresentationKind: text(v, "source_representation_kind"), EvidenceContentClass: text(v, "evidence_content_class"), SourceRepresentationMediaType: optionalText(v, "source_representation_media_type"),
		RepresentationDeclarationID: text(v, "representation_declaration_id"), RepresentationDeclarationDigest: text(v, "representation_declaration_digest"), VersionCoordinate: text(v, "version_coordinate"), SourceContentHashAlgorithm: text(v, "source_content_hash_algorithm"), SourceContentHashProfile: text(v, "source_content_hash_profile"), SourceContentHash: text(v, "source_content_hash"),
		ExternalFetchProfileRef: text(v, "external_fetch_profile_ref"), ExternalFetchProfileDigest: text(v, "external_fetch_profile_digest"), PermissionGrantID: text(v, "permission_grant_id"), PermissionGrantDigest: text(v, "permission_grant_digest"), PermissionAuthorityID: text(v, "permission_authority_id"), PermissionPrincipalID: text(v, "permission_principal_id"), PermissionScopeDigest: text(v, "permission_scope_digest"),
		PermissionOperation: text(v, "permission_operation"), PermissionMethod: text(v, "permission_method"), PermissionRedirectPolicyDigest: text(v, "permission_redirect_policy_digest"), PermissionContentClass: text(v, "permission_content_class"), PermissionTrustClass: text(v, "permission_trust_class"), PermissionByteCeiling: int64Value(v, "permission_byte_ceiling"), PermissionDepthCeiling: int64Value(v, "permission_depth_ceiling"),
		PermissionExpectedContentHashAlgorithm: optionalText(v, "permission_expected_content_hash_algorithm"), PermissionExpectedContentHashProfile: optionalText(v, "permission_expected_content_hash_profile"), PermissionExpectedContentHash: optionalText(v, "permission_expected_content_hash"), PermissionEffectiveAt: timestamp(v, "permission_effective_at"), PermissionExpiresAt: optionalTimestamp(v, "permission_expires_at"),
		PermissionStatus: text(v, "permission_status"), PermissionPolicyVersionRef: text(v, "permission_policy_version_ref"), PermissionPolicyVersionDigest: text(v, "permission_policy_version_digest"), FetchAuthorizationDecisionRef: text(v, "fetch_authorization_decision_ref"), FetchAuthorizationDecisionDigest: text(v, "fetch_authorization_decision_digest"), ObservedAt: timestamp(v, "observed_at"),
		TransportStatus: text(v, "transport_status"), TransportRawContentHashAlgorithm: text(v, "transport_raw_content_hash_algorithm"), TransportRawContentHash: text(v, "transport_raw_content_hash"), TransportRawByteCount: int64Value(v, "transport_raw_byte_count"), TransportDecodedByteCount: int64Value(v, "transport_decoded_byte_count"), TransportContentEncoding: optionalText(v, "transport_content_encoding"), TransportCharset: optionalText(v, "transport_charset"), TransportResponseMetadataDigest: text(v, "transport_response_metadata_digest"),
		EvidenceArchiveAuthorityID: text(v, "evidence_archive_authority_id"), EvidenceArchiveRecordID: text(v, "evidence_archive_record_id"), EvidenceArchiveRecordDigest: text(v, "evidence_archive_record_digest"), EvidenceArchiveByteCount: int64Value(v, "evidence_archive_byte_count"), EvidenceArchiveDeletionDomainID: text(v, "evidence_archive_deletion_domain_id"), EvidenceArchiveCryptoShredDomainID: text(v, "evidence_archive_crypto_shred_domain_id"), ReceiptDeletionDomainID: text(v, "receipt_deletion_domain_id"), ReceiptCryptoShredDomainID: text(v, "receipt_crypto_shred_domain_id"), RedactedTransportEvidenceDigest: text(v, "redacted_transport_evidence_digest"),
	}
	return r, nil
}

// BatchV8FromPhysicalRow reconstructs every proof-relevant batch field from
// its complete, strictly admitted physical row.
func BatchV8FromPhysicalRow(input SpannerRow) (oodevidence.BatchV8, error) {
	row, err := evidencePhysicalRow(input, "OODGraphExternalFetchBatches")
	if err != nil {
		return oodevidence.BatchV8{}, err
	}
	v := row.Columns
	return oodevidence.BatchV8{
		OrganizationID: text(v, "organization_id"), FetchBatchID: text(v, "fetch_batch_id"), SourceAuthorityBindingID: text(v, "source_authority_binding_id"), SourceAuthorityBindingDigest: text(v, "source_authority_binding_digest"), RepresentationDeclarationID: text(v, "representation_declaration_id"), RepresentationDeclarationDigest: text(v, "representation_declaration_digest"), BatchReceiptManifestRootHash: text(v, "batch_receipt_manifest_root_hash"),
		TotalReceiptCount: int64Value(v, "total_receipt_count"), ComponentReceiptCount: int64Value(v, "component_receipt_count"), CompletenessEvidenceReceiptCount: int64Value(v, "completeness_evidence_receipt_count"), NoncomponentReceiptCount: int64Value(v, "noncomponent_receipt_count"), ExpectedComponentCount: optionalInt64(v, "expected_component_count"),
		CompletenessBasisKind: text(v, "completeness_basis_kind"), CompletenessEvidenceRef: text(v, "completeness_evidence_ref"), CompletenessEvidenceIdentityHash: text(v, "completeness_evidence_identity_hash"), CompletenessEvidenceContentHashAlgorithm: text(v, "completeness_evidence_content_hash_algorithm"), CompletenessEvidenceContentHashProfile: text(v, "completeness_evidence_content_hash_profile"), CompletenessEvidenceContentHash: text(v, "completeness_evidence_content_hash"), CompletenessEvidenceReceiptID: text(v, "completeness_evidence_receipt_id"), CompletenessEvidenceArchiveAuthorityID: text(v, "completeness_evidence_archive_authority_id"), CompletenessEvidenceArchiveRecordID: text(v, "completeness_evidence_archive_record_id"), CompletenessEvidenceArchiveRecordDigest: text(v, "completeness_evidence_archive_record_digest"), CompletenessEvidenceSelectorKind: text(v, "completeness_evidence_selector_kind"), CompletenessEvidenceSelectorValue: text(v, "completeness_evidence_selector_value"), VerifiedCompletenessClaimDigest: text(v, "verified_completeness_claim_digest"), CompletenessEvidenceDigest: text(v, "completeness_evidence_digest"), CompletenessProfileRef: text(v, "completeness_profile_ref"), CompletenessProfileDigest: text(v, "completeness_profile_digest"), SealedAt: timestamp(v, "sealed_at"),
	}, nil
}

func evidencePhysicalRow(input SpannerRow, table string) (SpannerRow, error) {
	if input.Table != table {
		return SpannerRow{}, fmt.Errorf("%w: expected %s, got %s", ErrImmutablePhysicalRow, table, input.Table)
	}
	immutable, err := BuildImmutableRow(input.Table, input.Columns)
	if err != nil {
		return SpannerRow{}, err
	}
	return immutable.Row(), nil
}

// These conversions are safe only after evidencePhysicalRow has called the
// closed physical codec. Keeping them small and typed makes every field map
// above explicit without reflection or dynamic coercion.
func text(v map[string]interface{}, name string) string { return v[name].(string) }
func stringSlice(v map[string]interface{}, name string) []string {
	return append([]string(nil), v[name].([]string)...)
}
func int64Value(v map[string]interface{}, name string) int64    { return v[name].(int64) }
func timestamp(v map[string]interface{}, name string) time.Time { return v[name].(time.Time) }
func optionalText(v map[string]interface{}, name string) *string {
	if v[name] == nil {
		return nil
	}
	x := v[name].(string)
	return &x
}
func optionalInt64(v map[string]interface{}, name string) *int64 {
	if v[name] == nil {
		return nil
	}
	x := v[name].(int64)
	return &x
}
func optionalTimestamp(v map[string]interface{}, name string) *time.Time {
	if v[name] == nil {
		return nil
	}
	x := v[name].(time.Time)
	return &x
}
