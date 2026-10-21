package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	externalEvidenceHashProfile = "transport_decoded_representation_bytes_v1"

	externalFetchPermissionOperation = "external_document_fetch"
	externalPermissionStatus         = "affirmative"

	externalBodyCustodyNone = "no_local_body_custody"
	externalBodyCustodyAGFS = "exact_agfs_body_custody"
)

// externalSourceAuthorizationResolver is the pre-I/O authority seam. Its
// implementation resolves admitted source-authority, representation,
// principal/grant, policy-version, and Gate Policy evidence. The fetcher
// receives only the resulting immutable coordinates and never credentials or
// grant bodies.
type externalSourceAuthorizationResolver interface {
	AuthorizeExternalSource(context.Context, externalSourceAuthorizationRequest) (externalSourceAuthorization, error)
}

type externalSourceAuthorizationRequest struct {
	OrganizationID        string
	ObjectClass           string
	SourceRegistryID      string
	SourceArtifactClass   string
	SourceAuthorityID     string
	SourceRefKind         string
	SourceStableReference string
	PermissionOperation   string
	PermissionMethod      string
	ObservedAt            time.Time
}

// externalSourceAuthorization is body-free, secret-free evidence that one
// exact representation may be fetched. It also states, independently,
// whether the selected bytes may be retained in AGFS. The latter is never
// inferred from retrieval permission.
type externalSourceAuthorization struct {
	OrganizationID                    string `json:"organization_id"`
	ObjectClass                       string `json:"object_class"`
	SourceRegistryID                  string `json:"source_registry_id"`
	SourceArtifactClass               string `json:"source_artifact_class"`
	SourceAuthorityID                 string `json:"source_authority_id"`
	SourceAuthorityBindingID          string `json:"source_authority_binding_id"`
	SourceAuthorityBindingDigest      string `json:"source_authority_binding_digest"`
	SourceRefKind                     string `json:"source_ref_kind"`
	SourceStableReference             string `json:"source_stable_reference"`
	SourceRepresentationKind          string `json:"source_representation_kind"`
	SourceRepresentationMediaType     string `json:"source_representation_media_type,omitempty"`
	RepresentationDeclarationID       string `json:"representation_declaration_id"`
	RepresentationDeclarationDigest   string `json:"representation_declaration_digest"`
	SourceContentHashProfile          string `json:"source_content_hash_profile"`
	ExternalFetchProfileRef           string `json:"external_fetch_profile_ref"`
	ExternalFetchProfileDigest        string `json:"external_fetch_profile_digest"`
	PermissionGrantID                 string `json:"permission_grant_id"`
	PermissionGrantDigest             string `json:"permission_grant_digest"`
	PermissionAuthorityID             string `json:"permission_authority_id"`
	PermissionPrincipalID             string `json:"permission_principal_id"`
	PermissionScopeDigest             string `json:"permission_scope_digest"`
	PermissionOperation               string `json:"permission_operation"`
	PermissionMethod                  string `json:"permission_method"`
	PermissionRedirectPolicyDigest    string `json:"permission_redirect_policy_digest"`
	PermissionContentClass            string `json:"permission_content_class"`
	PermissionTrustClass              string `json:"permission_trust_class"`
	PermissionByteCeiling             int64  `json:"permission_byte_ceiling"`
	PermissionDepthCeiling            int64  `json:"permission_depth_ceiling"`
	PermissionExpectedHashAlgorithm   string `json:"permission_expected_content_hash_algorithm,omitempty"`
	PermissionExpectedHashProfile     string `json:"permission_expected_content_hash_profile,omitempty"`
	PermissionExpectedHash            string `json:"permission_expected_content_hash,omitempty"`
	PermissionEffectiveAt             string `json:"permission_effective_at"`
	PermissionExpiresAt               string `json:"permission_expires_at,omitempty"`
	PermissionStatus                  string `json:"permission_status"`
	PermissionPolicyVersionRef        string `json:"permission_policy_version_ref"`
	PermissionPolicyVersionDigest     string `json:"permission_policy_version_digest"`
	FetchAuthorizationDecisionRef     string `json:"fetch_authorization_decision_ref"`
	FetchAuthorizationDecisionDigest  string `json:"fetch_authorization_decision_digest"`
	BodyCustodyDisposition            string `json:"body_custody_disposition"`
	BodyStorageAuthorizationReference string `json:"body_storage_authorization_reference,omitempty"`
	BodyRetentionHoldReference        string `json:"body_retention_hold_reference,omitempty"`
	ArchiveDeletionDomainID           string `json:"archive_deletion_domain_id,omitempty"`
	ArchiveCryptoShredDomainID        string `json:"archive_crypto_shred_domain_id,omitempty"`
	ReceiptDeletionDomainID           string `json:"receipt_deletion_domain_id"`
	ReceiptCryptoShredDomainID        string `json:"receipt_crypto_shred_domain_id"`
}

func resolveExternalSourceAuthorization(ctx context.Context, env *Env, request externalSourceAuthorizationRequest) (externalSourceAuthorization, error) {
	if env == nil || env.ExternalAuthorize == nil {
		return externalSourceAuthorization{}, fmt.Errorf("%w: admitted external-source authorization resolver required before external I/O", ErrOODGraphExternalRetrievalPermissionProofUnavailable)
	}
	answer, err := env.ExternalAuthorize.AuthorizeExternalSource(ctx, request)
	if err != nil {
		return externalSourceAuthorization{}, fmt.Errorf("%w: %v", ErrOODGraphExternalRetrievalPermissionProofUnavailable, err)
	}
	if err := validateExternalSourceAuthorization(request, answer); err != nil {
		return externalSourceAuthorization{}, fmt.Errorf("%w: %v", ErrOODGraphExternalRetrievalPermissionProofUnavailable, err)
	}
	return answer, nil
}

func validateExternalSourceAuthorization(request externalSourceAuthorizationRequest, answer externalSourceAuthorization) error {
	if request.OrganizationID == "" || request.ObjectClass == "" || request.SourceRegistryID == "" || request.SourceArtifactClass == "" || request.SourceAuthorityID == "" || request.SourceRefKind == "" || request.SourceStableReference == "" || request.PermissionOperation == "" || request.PermissionMethod == "" || request.ObservedAt.IsZero() {
		return fmt.Errorf("external authorization request is incomplete")
	}
	if answer.OrganizationID != request.OrganizationID || answer.ObjectClass != request.ObjectClass || answer.SourceRegistryID != request.SourceRegistryID || answer.SourceArtifactClass != request.SourceArtifactClass || answer.SourceAuthorityID != request.SourceAuthorityID || answer.SourceRefKind != request.SourceRefKind || answer.SourceStableReference != request.SourceStableReference || answer.PermissionOperation != request.PermissionOperation || answer.PermissionMethod != request.PermissionMethod {
		return fmt.Errorf("external authorization does not bind the exact tenant, source, representation locator, operation, and method requested")
	}
	for name, value := range map[string]string{
		"organization_id":                  answer.OrganizationID,
		"source_registry_id":               answer.SourceRegistryID,
		"source_artifact_class":            answer.SourceArtifactClass,
		"source_ref_kind":                  answer.SourceRefKind,
		"source_stable_reference":          answer.SourceStableReference,
		"source_representation_kind":       answer.SourceRepresentationKind,
		"representation_declaration_id":    answer.RepresentationDeclarationID,
		"external_fetch_profile_ref":       answer.ExternalFetchProfileRef,
		"permission_policy_version_ref":    answer.PermissionPolicyVersionRef,
		"fetch_authorization_decision_ref": answer.FetchAuthorizationDecisionRef,
		"permission_content_class":         answer.PermissionContentClass,
		"permission_trust_class":           answer.PermissionTrustClass,
		"receipt_deletion_domain_id":       answer.ReceiptDeletionDomainID,
		"receipt_crypto_shred_domain_id":   answer.ReceiptCryptoShredDomainID,
	} {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("external authorization %s is empty or noncanonical", name)
		}
	}
	for name, value := range map[string]string{
		"source_authority_id":            answer.SourceAuthorityID,
		"source_authority_binding_id":    answer.SourceAuthorityBindingID,
		"representation_declaration_id":  answer.RepresentationDeclarationID,
		"permission_grant_id":            answer.PermissionGrantID,
		"permission_authority_id":        answer.PermissionAuthorityID,
		"permission_principal_id":        answer.PermissionPrincipalID,
		"receipt_deletion_domain_id":     answer.ReceiptDeletionDomainID,
		"receipt_crypto_shred_domain_id": answer.ReceiptCryptoShredDomainID,
	} {
		parsed, err := uuid.Parse(value)
		if err != nil {
			return fmt.Errorf("external authorization %s is not a UUID: %w", name, err)
		}
		if parsed.String() != value {
			return fmt.Errorf("external authorization %s is not a canonical lowercase UUID", name)
		}
	}
	for name, value := range map[string]string{
		"source_authority_binding_digest":     answer.SourceAuthorityBindingDigest,
		"representation_declaration_digest":   answer.RepresentationDeclarationDigest,
		"external_fetch_profile_digest":       answer.ExternalFetchProfileDigest,
		"permission_grant_digest":             answer.PermissionGrantDigest,
		"permission_scope_digest":             answer.PermissionScopeDigest,
		"permission_redirect_policy_digest":   answer.PermissionRedirectPolicyDigest,
		"permission_policy_version_digest":    answer.PermissionPolicyVersionDigest,
		"fetch_authorization_decision_digest": answer.FetchAuthorizationDecisionDigest,
	} {
		if err := validateExternalContentHash("sha256", value); err != nil {
			return fmt.Errorf("external authorization %s: %w", name, err)
		}
	}
	if answer.SourceContentHashProfile != externalEvidenceHashProfile {
		return fmt.Errorf("external authorization source_content_hash_profile=%q, want %q", answer.SourceContentHashProfile, externalEvidenceHashProfile)
	}
	switch answer.SourceRepresentationKind {
	case "source_declared_machine_export", "source_origin_representation", "source_declared_component_manifest":
	default:
		return fmt.Errorf("external authorization source_representation_kind %q is outside the closed contract", answer.SourceRepresentationKind)
	}
	if answer.SourceRepresentationMediaType != "" {
		mediaType, charset, err := canonicalExternalResponseMediaType(answer.SourceRepresentationMediaType)
		if err != nil || charset != "" || mediaType != answer.SourceRepresentationMediaType {
			return fmt.Errorf("external authorization source_representation_media_type must be one canonical lowercase media type without parameters")
		}
	}
	if answer.PermissionStatus != externalPermissionStatus {
		return fmt.Errorf("external authorization permission_status=%q is not affirmative", answer.PermissionStatus)
	}
	if answer.PermissionByteCeiling <= 0 || answer.PermissionByteCeiling > maxExternalReferenceBytes || answer.PermissionDepthCeiling < 0 {
		return fmt.Errorf("external authorization byte/depth ceiling is invalid")
	}
	effectiveAt, err := parseCanonicalAuthorizationTime("permission_effective_at", answer.PermissionEffectiveAt, true)
	if err != nil {
		return err
	}
	if effectiveAt.After(request.ObservedAt) {
		return fmt.Errorf("external authorization is not yet effective at observed_at")
	}
	if answer.PermissionExpiresAt != "" {
		expiresAt, err := parseCanonicalAuthorizationTime("permission_expires_at", answer.PermissionExpiresAt, true)
		if err != nil {
			return err
		}
		if !expiresAt.After(request.ObservedAt) {
			return fmt.Errorf("external authorization is expired at observed_at")
		}
	}
	expectedParts := 0
	for _, value := range []string{answer.PermissionExpectedHashAlgorithm, answer.PermissionExpectedHashProfile, answer.PermissionExpectedHash} {
		if value != "" {
			expectedParts++
		}
	}
	if expectedParts != 0 && expectedParts != 3 {
		return fmt.Errorf("external authorization expected content hash triple must be all present or all absent")
	}
	if expectedParts == 3 {
		if answer.PermissionExpectedHashAlgorithm != "sha256" || answer.PermissionExpectedHashProfile != answer.SourceContentHashProfile {
			return fmt.Errorf("external authorization expected content hash uses a different algorithm or canonical byte profile")
		}
		if err := validateExternalContentHash("sha256", answer.PermissionExpectedHash); err != nil {
			return fmt.Errorf("external authorization expected content hash: %w", err)
		}
	}
	switch answer.BodyCustodyDisposition {
	case externalBodyCustodyNone:
		if answer.BodyStorageAuthorizationReference != "" || answer.BodyRetentionHoldReference != "" || answer.ArchiveDeletionDomainID != "" || answer.ArchiveCryptoShredDomainID != "" {
			return fmt.Errorf("no_local_body_custody authorization must not carry AGFS archive coordinates")
		}
	case externalBodyCustodyAGFS:
		for name, value := range map[string]string{
			"body_storage_authorization_reference": answer.BodyStorageAuthorizationReference,
			"body_retention_hold_reference":        answer.BodyRetentionHoldReference,
			"archive_deletion_domain_id":           answer.ArchiveDeletionDomainID,
			"archive_crypto_shred_domain_id":       answer.ArchiveCryptoShredDomainID,
		} {
			if value == "" || strings.TrimSpace(value) != value {
				return fmt.Errorf("exact_agfs_body_custody requires %s", name)
			}
		}
		for name, value := range map[string]string{
			"archive_deletion_domain_id":     answer.ArchiveDeletionDomainID,
			"archive_crypto_shred_domain_id": answer.ArchiveCryptoShredDomainID,
		} {
			parsed, err := uuid.Parse(value)
			if err != nil {
				return fmt.Errorf("exact_agfs_body_custody %s is not a canonical UUID: %w", name, err)
			}
			if parsed.String() != value {
				return fmt.Errorf("exact_agfs_body_custody %s is not a canonical lowercase UUID", name)
			}
		}
	default:
		return fmt.Errorf("external authorization body_custody_disposition %q is outside the closed contract", answer.BodyCustodyDisposition)
	}
	return nil
}

func parseCanonicalAuthorizationTime(name, value string, required bool) (time.Time, error) {
	if value == "" {
		if required {
			return time.Time{}, fmt.Errorf("external authorization %s is required", name)
		}
		return time.Time{}, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.UTC().Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("external authorization %s is not canonical UTC RFC3339: %w", name, err)
	}
	return parsed, nil
}
