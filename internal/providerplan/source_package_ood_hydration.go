package providerplan

// Typed OOD8 hydration deliberately has no generic row or JSON path.  These
// readers are used only from an already pinned strong read transaction.

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"google.golang.org/api/iterator"
)

var oodReceiptColumns = []string{"organization_id", "receipt_id", "fetch_batch_id", "receipt_roles", "fetch_component_ordinal", "fetch_occurrence_id", "evidence_identity_hash", "graph_object_id", "object_class", "source_authority_id", "source_authority_binding_id", "source_authority_binding_digest", "source_ref_kind", "source_stable_reference", "source_representation_kind", "evidence_content_class", "source_representation_media_type", "representation_declaration_id", "representation_declaration_digest", "version_coordinate", "source_content_hash_algorithm", "source_content_hash_profile", "source_content_hash", "external_fetch_profile_ref", "external_fetch_profile_digest", "permission_grant_id", "permission_grant_digest", "permission_authority_id", "permission_principal_id", "permission_scope_digest", "permission_operation", "permission_method", "permission_redirect_policy_digest", "permission_content_class", "permission_trust_class", "permission_byte_ceiling", "permission_depth_ceiling", "permission_expected_content_hash_algorithm", "permission_expected_content_hash_profile", "permission_expected_content_hash", "permission_effective_at", "permission_expires_at", "permission_status", "permission_policy_version_ref", "permission_policy_version_digest", "fetch_authorization_decision_ref", "fetch_authorization_decision_digest", "observed_at", "transport_status", "transport_raw_content_hash_algorithm", "transport_raw_content_hash", "transport_raw_byte_count", "transport_decoded_byte_count", "transport_content_encoding", "transport_charset", "transport_response_metadata_digest", "evidence_archive_authority_id", "evidence_archive_record_id", "evidence_archive_record_digest", "evidence_archive_byte_count", "evidence_archive_deletion_domain_id", "evidence_archive_crypto_shred_domain_id", "receipt_deletion_domain_id", "receipt_crypto_shred_domain_id", "redacted_transport_evidence_digest"}
var oodBatchColumns = []string{"organization_id", "fetch_batch_id", "source_authority_binding_id", "source_authority_binding_digest", "representation_declaration_id", "representation_declaration_digest", "batch_receipt_manifest_root_hash", "total_receipt_count", "component_receipt_count", "completeness_evidence_receipt_count", "noncomponent_receipt_count", "expected_component_count", "completeness_basis_kind", "completeness_evidence_ref", "completeness_evidence_identity_hash", "completeness_evidence_content_hash_algorithm", "completeness_evidence_content_hash_profile", "completeness_evidence_content_hash", "completeness_evidence_receipt_id", "completeness_evidence_archive_authority_id", "completeness_evidence_archive_record_id", "completeness_evidence_archive_record_digest", "completeness_evidence_selector_kind", "completeness_evidence_selector_value", "verified_completeness_claim_digest", "completeness_evidence_digest", "completeness_profile_ref", "completeness_profile_digest", "sealed_at"}
var oodCertificateColumns = []string{"organization_id", "verification_certificate_id", "verification_certificate_hash", "materialization_run_id", "snapshot_kind", "source_set_hash", "source_manifest_root_hash", "source_artifact_count", "relationship_evidence_count", "object_manifest_root_hash", "object_count", "symbol_manifest_root_hash", "symbol_count", "edge_manifest_root_hash", "edge_count", "api_property_manifest_root_hash", "api_property_count", "graph_fact_locator_manifest_root_hash", "graph_fact_locator_count", "receipt_manifest_root_hash", "receipt_count", "structural_projection_manifest_root_hash", "structural_projection_count", "violation_manifest_root_hash", "violation_count", "closure_hash", "relationship_identity_set_hash", "source_authority_identity_set_hash", "source_authority_identity_count", "completeness_identity_set_hash", "completeness_identity_count", "permission_policy_identity_set_hash", "permission_policy_identity_count", "archive_binding_identity_set_hash", "archive_binding_identity_count", "profile_identity_set_hash", "profile_identity_count", "external_source_receipt_eligibility_set_hash", "external_source_receipt_eligibility_count", "materialization_profile_id", "materialization_profile_version", "materialization_profile_digest", "publication_budget_profile_ref", "publication_budget_profile_digest", "manifest_hash_algorithm", "manifest_hash_profile", "manifest_hash_contract_digest", "closure_hash_algorithm", "closure_hash_profile", "closure_hash_contract_digest", "verifier_capability_name", "verifier_capability_version", "verifier_capability_digest", "verification_policy_ref", "verification_policy_digest", "verification_attestation_authority_id", "verification_attestation_ref", "verification_attestation_digest", "verification_attestation_profile"}

func readDocumentationFactoryOODReceipt(ctx context.Context, tx *spanner.ReadOnlyTransaction, org, receiptID string) (oodevidence.ReceiptV8, error) {
	if err := oodReadInputs(ctx, tx, org, receiptID); err != nil {
		return oodevidence.ReceiptV8{}, err
	}
	row, err := tx.ReadRow(ctx, "OODGraphExternalFetchReceipts", spanner.Key{org, receiptID}, oodReceiptColumns)
	if err != nil {
		return oodevidence.ReceiptV8{}, fmt.Errorf("read OOD receipt: %w", err)
	}
	var r oodevidence.ReceiptV8
	var ordinal spanner.NullInt64
	var media, expectedAlg, expectedProfile, expectedHash, encoding, charset spanner.NullString
	var expires spanner.NullTime
	err = row.Columns(&r.OrganizationID, &r.ReceiptID, &r.FetchBatchID, &r.ReceiptRoles, &ordinal, &r.FetchOccurrenceID, &r.EvidenceIdentityHash, &r.GraphObjectID, &r.ObjectClass, &r.SourceAuthorityID, &r.SourceAuthorityBindingID, &r.SourceAuthorityBindingDigest, &r.SourceRefKind, &r.SourceStableReference, &r.SourceRepresentationKind, &r.EvidenceContentClass, &media, &r.RepresentationDeclarationID, &r.RepresentationDeclarationDigest, &r.VersionCoordinate, &r.SourceContentHashAlgorithm, &r.SourceContentHashProfile, &r.SourceContentHash, &r.ExternalFetchProfileRef, &r.ExternalFetchProfileDigest, &r.PermissionGrantID, &r.PermissionGrantDigest, &r.PermissionAuthorityID, &r.PermissionPrincipalID, &r.PermissionScopeDigest, &r.PermissionOperation, &r.PermissionMethod, &r.PermissionRedirectPolicyDigest, &r.PermissionContentClass, &r.PermissionTrustClass, &r.PermissionByteCeiling, &r.PermissionDepthCeiling, &expectedAlg, &expectedProfile, &expectedHash, &r.PermissionEffectiveAt, &expires, &r.PermissionStatus, &r.PermissionPolicyVersionRef, &r.PermissionPolicyVersionDigest, &r.FetchAuthorizationDecisionRef, &r.FetchAuthorizationDecisionDigest, &r.ObservedAt, &r.TransportStatus, &r.TransportRawContentHashAlgorithm, &r.TransportRawContentHash, &r.TransportRawByteCount, &r.TransportDecodedByteCount, &encoding, &charset, &r.TransportResponseMetadataDigest, &r.EvidenceArchiveAuthorityID, &r.EvidenceArchiveRecordID, &r.EvidenceArchiveRecordDigest, &r.EvidenceArchiveByteCount, &r.EvidenceArchiveDeletionDomainID, &r.EvidenceArchiveCryptoShredDomainID, &r.ReceiptDeletionDomainID, &r.ReceiptCryptoShredDomainID, &r.RedactedTransportEvidenceDigest)
	if err != nil {
		return r, fmt.Errorf("decode OOD receipt: %w", err)
	}
	r.FetchComponentOrdinal = int64Ptr(ordinal)
	r.SourceRepresentationMediaType = stringPtr(media)
	r.PermissionExpectedContentHashAlgorithm = stringPtr(expectedAlg)
	r.PermissionExpectedContentHashProfile = stringPtr(expectedProfile)
	r.PermissionExpectedContentHash = stringPtr(expectedHash)
	r.PermissionExpiresAt = timePtr(expires)
	r.TransportContentEncoding = stringPtr(encoding)
	r.TransportCharset = stringPtr(charset)
	if !sameNullBinding(expectedAlg, expectedProfile, expectedHash) {
		return r, fmt.Errorf("OOD receipt expected-content binding has partial nulls")
	}
	if r.OrganizationID != org || r.ReceiptID != receiptID {
		return r, fmt.Errorf("OOD receipt tenant or key mismatch")
	}
	return r, nil
}

func readDocumentationFactoryOODBatch(ctx context.Context, tx *spanner.ReadOnlyTransaction, org, batchID string) (oodevidence.BatchV8, error) {
	if err := oodReadInputs(ctx, tx, org, batchID); err != nil {
		return oodevidence.BatchV8{}, err
	}
	row, err := tx.ReadRow(ctx, "OODGraphExternalFetchBatches", spanner.Key{org, batchID}, oodBatchColumns)
	if err != nil {
		return oodevidence.BatchV8{}, fmt.Errorf("read OOD batch: %w", err)
	}
	var b oodevidence.BatchV8
	var expected spanner.NullInt64
	err = row.Columns(&b.OrganizationID, &b.FetchBatchID, &b.SourceAuthorityBindingID, &b.SourceAuthorityBindingDigest, &b.RepresentationDeclarationID, &b.RepresentationDeclarationDigest, &b.BatchReceiptManifestRootHash, &b.TotalReceiptCount, &b.ComponentReceiptCount, &b.CompletenessEvidenceReceiptCount, &b.NoncomponentReceiptCount, &expected, &b.CompletenessBasisKind, &b.CompletenessEvidenceRef, &b.CompletenessEvidenceIdentityHash, &b.CompletenessEvidenceContentHashAlgorithm, &b.CompletenessEvidenceContentHashProfile, &b.CompletenessEvidenceContentHash, &b.CompletenessEvidenceReceiptID, &b.CompletenessEvidenceArchiveAuthorityID, &b.CompletenessEvidenceArchiveRecordID, &b.CompletenessEvidenceArchiveRecordDigest, &b.CompletenessEvidenceSelectorKind, &b.CompletenessEvidenceSelectorValue, &b.VerifiedCompletenessClaimDigest, &b.CompletenessEvidenceDigest, &b.CompletenessProfileRef, &b.CompletenessProfileDigest, &b.SealedAt)
	if err != nil {
		return b, fmt.Errorf("decode OOD batch: %w", err)
	}
	b.ExpectedComponentCount = int64Ptr(expected)
	if b.OrganizationID != org || b.FetchBatchID != batchID {
		return b, fmt.Errorf("OOD batch tenant or key mismatch")
	}
	return b, nil
}

func readDocumentationFactoryOODClosureCertificate(ctx context.Context, tx *spanner.ReadOnlyTransaction, org, certificateID string) (oodevidence.ClosureCertificateV8, error) {
	if err := oodReadInputs(ctx, tx, org, certificateID); err != nil {
		return oodevidence.ClosureCertificateV8{}, err
	}
	row, err := tx.ReadRow(ctx, "OODGraphClosureVerificationCertificates", spanner.Key{org, certificateID}, oodCertificateColumns)
	if err != nil {
		return oodevidence.ClosureCertificateV8{}, fmt.Errorf("read OOD closure certificate: %w", err)
	}
	var c oodevidence.ClosureCertificateV8
	var cert string
	var sourceHash, objectHash, symbolHash, edgeHash, apiHash, locatorHash, receiptHash, projectionHash, violationHash string
	var objectCount, symbolCount, edgeCount, apiCount, locatorCount, receiptCount, projectionCount, violationCount int64
	// Scan fixed roots separately to make the canonical root roster visible and closed.
	err = row.Columns(&c.OrganizationID, &cert, &c.VerificationCertificateHash, &c.MaterializationRunID, &c.SnapshotKind, &c.SourceSetHash, &sourceHash, &c.SourceArtifactCount, &c.RelationshipEvidenceCount, &objectHash, &objectCount, &symbolHash, &symbolCount, &edgeHash, &edgeCount, &apiHash, &apiCount, &locatorHash, &locatorCount, &receiptHash, &receiptCount, &projectionHash, &projectionCount, &violationHash, &violationCount, &c.ClosureHash, &c.RelationshipIdentitySetHash, &c.SourceAuthorityIdentitySetHash, &c.SourceAuthorityIdentityCount, &c.CompletenessIdentitySetHash, &c.CompletenessIdentityCount, &c.PermissionPolicyIdentitySetHash, &c.PermissionPolicyIdentityCount, &c.ArchiveBindingIdentitySetHash, &c.ArchiveBindingIdentityCount, &c.ProfileIdentitySetHash, &c.ProfileIdentityCount, &c.ExternalSourceReceiptEligibilitySetHash, &c.ExternalSourceReceiptEligibilityCount, &c.MaterializationProfileID, &c.MaterializationProfileVersion, &c.MaterializationProfileDigest, &c.PublicationBudgetProfileRef, &c.PublicationBudgetProfileDigest, &c.ManifestHashAlgorithm, &c.ManifestHashProfile, &c.ManifestHashContractDigest, &c.ClosureHashAlgorithm, &c.ClosureHashProfile, &c.ClosureHashContractDigest, &c.VerifierCapabilityName, &c.VerifierCapabilityVersion, &c.VerifierCapabilityDigest, &c.VerificationPolicyRef, &c.VerificationPolicyDigest, &c.AttestationAuthorityID, &c.AttestationRef, &c.AttestationDigest, &c.AttestationProfile)
	if err != nil {
		return c, fmt.Errorf("decode OOD closure certificate: %w", err)
	}
	c.VerificationCertificateID = cert
	c.Roots = map[string]oodevidence.ClosureRoot{"source": {Hash: sourceHash, Count: c.SourceArtifactCount + c.RelationshipEvidenceCount}, "object": {Hash: objectHash, Count: objectCount}, "symbol": {Hash: symbolHash, Count: symbolCount}, "edge": {Hash: edgeHash, Count: edgeCount}, "api_property": {Hash: apiHash, Count: apiCount}, "graph_fact_locator": {Hash: locatorHash, Count: locatorCount}, "receipt": {Hash: receiptHash, Count: receiptCount}, "structural_projection": {Hash: projectionHash, Count: projectionCount}, "violation": {Hash: violationHash, Count: violationCount}}
	if c.OrganizationID != org || cert != certificateID {
		return c, fmt.Errorf("OOD closure certificate tenant or key mismatch")
	}
	return c, nil
}

func readDocumentationFactoryOODReceiptManifestNode(ctx context.Context, tx *spanner.ReadOnlyTransaction, org, nodeHash string) (oodevidence.ReceiptManifestNode, error) {
	if err := oodReadInputs(ctx, tx, org, nodeHash); err != nil {
		return oodevidence.ReceiptManifestNode{}, err
	}
	return readOODReceiptManifestNode(ctx, tx, org, nodeHash, map[string]bool{}, 0)
}
func readOODReceiptManifestNode(ctx context.Context, tx *spanner.ReadOnlyTransaction, org, nodeHash string, seen map[string]bool, depth int) (oodevidence.ReceiptManifestNode, error) {
	if depth > 64 || seen[nodeHash] {
		return oodevidence.ReceiptManifestNode{}, fmt.Errorf("OOD receipt manifest cycle or depth")
	}
	seen[nodeHash] = true
	defer delete(seen, nodeHash)
	row, err := tx.ReadRow(ctx, "OODGraphManifestNodes", spanner.Key{org, nodeHash}, []string{"organization_id", "manifest_node_hash", "manifest_kind", "node_kind", "node_level", "entry_count", "transitive_member_count", "canonical_byte_count", "sealed"})
	if err != nil {
		return oodevidence.ReceiptManifestNode{}, fmt.Errorf("read OOD manifest node: %w", err)
	}
	var n oodevidence.ReceiptManifestNode
	if err = row.Columns(&n.OrganizationID, &n.NodeHash, &n.ManifestKind, &n.NodeKind, &n.NodeLevel, &n.EntryCount, &n.TransitiveMemberCount, &n.CanonicalByteCount, &n.Sealed); err != nil {
		return n, fmt.Errorf("decode OOD manifest node: %w", err)
	}
	if n.OrganizationID != org || n.NodeHash != nodeHash {
		return n, fmt.Errorf("OOD manifest node tenant or key mismatch")
	}
	// This typed projection is specifically the per-batch receipt tree used by
	// BatchV8. Snapshot receipt-closure trees additionally admit
	// fetch_batch_certificate entries and must be hydrated by their own typed
	// projection; never coerce those certificates into receipt members.
	if n.ManifestKind != "fetch_batch_receipt" || (n.NodeKind != "leaf" && n.NodeKind != "internal") {
		return n, fmt.Errorf("OOD batch receipt manifest node kind is invalid")
	}
	it := tx.Query(ctx, spanner.Statement{SQL: "SELECT entry_ordinal, entry_kind, member_id, member_hash, child_manifest_node_hash, canonical_entry_byte_count FROM OODGraphManifestEntries WHERE organization_id=@org AND manifest_node_hash=@node ORDER BY entry_ordinal", Params: map[string]interface{}{"org": org, "node": nodeHash}})
	defer it.Stop()
	for ordinal := int64(0); ; ordinal++ {
		r, e := it.Next()
		if e == iterator.Done {
			break
		}
		if e != nil {
			return n, fmt.Errorf("read OOD manifest entry: %w", e)
		}
		var got, canonicalByteCount int64
		var kind string
		var id, hash, child spanner.NullString
		if e = r.Columns(&got, &kind, &id, &hash, &child, &canonicalByteCount); e != nil {
			return n, fmt.Errorf("decode OOD manifest entry: %w", e)
		}
		if got != ordinal {
			return n, fmt.Errorf("OOD manifest entry ordinal invalid")
		}
		if canonicalByteCount <= 0 {
			return n, fmt.Errorf("OOD manifest entry canonical byte count invalid")
		}
		entry := oodevidence.ReceiptManifestEntry{EntryOrdinal: got, CanonicalEntryByteCount: canonicalByteCount}
		switch kind {
		case "receipt":
			if !id.Valid || !hash.Valid || child.Valid {
				return n, fmt.Errorf("OOD manifest member entry invalid")
			}
			m := oodevidence.ReceiptManifestMember{EntryOrdinal: got, ReceiptID: id.String(), MemberHash: hash.String()}
			entry.Member = &m
			n.Members = append(n.Members, m)
		case "child_manifest":
			if id.Valid || hash.Valid || !child.Valid {
				return n, fmt.Errorf("OOD manifest child entry invalid")
			}
			c, e := readOODReceiptManifestNode(ctx, tx, org, child.String(), seen, depth+1)
			if e != nil {
				return n, e
			}
			entry.Child = &c
			n.Children = append(n.Children, c)
		default:
			return n, fmt.Errorf("OOD manifest entry kind invalid")
		}
		n.Entries = append(n.Entries, entry)
	}
	if int64(len(n.Entries)) != n.EntryCount {
		return n, fmt.Errorf("OOD manifest entry count mismatch")
	}
	return n, nil
}

func oodReadInputs(ctx context.Context, tx *spanner.ReadOnlyTransaction, org, key string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tx == nil || org == "" || key == "" {
		return fmt.Errorf("OOD typed hydration requires transaction, organization and key")
	}
	return nil
}
func int64Ptr(x spanner.NullInt64) *int64 {
	if !x.Valid {
		return nil
	}
	v := x.Int64
	return &v
}
func stringPtr(x spanner.NullString) *string {
	if !x.Valid {
		return nil
	}
	v := x.String()
	return &v
}
func timePtr(x spanner.NullTime) *time.Time {
	if !x.Valid {
		return nil
	}
	v := x.Time
	return &v
}

func sameNullBinding(values ...spanner.NullString) bool {
	valid := values[0].Valid
	for _, value := range values[1:] {
		if value.Valid != valid {
			return false
		}
	}
	return true
}
