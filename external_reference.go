package main

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const stagedExternalReceiptVersion = "external_source_receipt_v4"

// stagedExternalVerificationReceipt is the durable, process-minted evidence
// that staging_load verified one external coordinate against exact fetched
// bytes and its configured locator policy. It deliberately excludes the
// fetched body. staging_promote consumes this receipt without a second GET,
// preventing a moving vendor resource from changing between load and graph
// identity materialization.
type stagedExternalVerificationReceipt struct {
	ReceiptVersion                  string                          `json:"receipt_version"`
	CanonicalReference              string                          `json:"canonical_reference"`
	VerifiedSourceStableReference   string                          `json:"verified_source_stable_reference"`
	RetrievedAt                     string                          `json:"observed_at"`
	ByteLength                      int64                           `json:"transport_raw_byte_count"`
	SHA256                          string                          `json:"transport_raw_content_hash"`
	TransportStatus                 string                          `json:"transport_status"`
	TransportRawHashAlgorithm       string                          `json:"transport_raw_content_hash_algorithm"`
	ContentCoding                   string                          `json:"transport_content_encoding"`
	TransportCharset                string                          `json:"transport_charset,omitempty"`
	TransportResponseMetadataDigest string                          `json:"transport_response_metadata_digest"`
	DecodedByteLength               int64                           `json:"transport_decoded_byte_count"`
	DecodedSHA256                   string                          `json:"source_content_hash"`
	SourceRepresentationMediaType   string                          `json:"source_representation_media_type,omitempty"`
	SourceContentHashAlgorithm      string                          `json:"source_content_hash_algorithm"`
	SourceContentHashProfile        string                          `json:"source_content_hash_profile"`
	UpstreamVersionEvidenceKind     string                          `json:"upstream_version_evidence_kind,omitempty"`
	UpstreamVersionEvidence         string                          `json:"upstream_version_evidence,omitempty"`
	UpstreamVersionToken            string                          `json:"upstream_version_token,omitempty"`
	LicenseEvidence                 string                          `json:"license_evidence_when_available"`
	SourceRegistryID                string                          `json:"source_registry_id"`
	SourceAuthorityID               string                          `json:"source_authority_id"`
	PolicyFingerprint               string                          `json:"policy_fingerprint"`
	ObjectClass                     string                          `json:"object_class"`
	CanonicalName                   string                          `json:"canonical_name"`
	LocatorKind                     string                          `json:"locator_kind"`
	FinalVersionCoordinate          string                          `json:"final_version_coordinate"`
	Authorization                   externalSourceAuthorization     `json:"authorization"`
	Archive                         *externalEvidenceArchiveReceipt `json:"archive,omitempty"`
}

// validateExternalReferenceSubmission applies the source-registry,
// stable-reference-only, freshness, and embedding gates before any substrate
// client is opened. A zero descriptor means the node kind is not external.
func validateExternalReferenceSubmission(ctx context.Context, env *Env, sub ArtifactSubmission, canonicalName string, kindDescriptor NodeKindDescriptor, coord ArtifactSourceCoordinate) (ArtifactSourceCoordinate, ExternalSourceDescriptor, error) {
	verified, policy, _, err := validateExternalReferenceSubmissionForStaging(ctx, env, sub, canonicalName, kindDescriptor, coord)
	return verified, policy, err
}

func validateExternalReferenceSubmissionForStaging(ctx context.Context, env *Env, sub ArtifactSubmission, canonicalName string, kindDescriptor NodeKindDescriptor, coord ArtifactSourceCoordinate) (ArtifactSourceCoordinate, ExternalSourceDescriptor, *stagedExternalVerificationReceipt, error) {
	policy, err := preflightExternalReferenceSubmission(env, sub, canonicalName, kindDescriptor, coord)
	if err != nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, nil, err
	}
	if !kindDescriptor.ExternalReferenceRequired() {
		return coord, ExternalSourceDescriptor{}, nil, nil
	}
	if err := preflightExternalLocatorAdmission(sub.NodeKind, coord, policy); err != nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, nil, err
	}

	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, nil, err
	}
	var receipt verifiedExternalSourceReceipt
	coord, receipt, err = verifyExternalSourceCoordinateWithReceipt(ctx, env, orgID, sub.NodeKind, coord, policy)
	if err != nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, nil, err
	}
	coord, durable, err := finalizeVerifiedExternalReferenceSubmission(env, sub, canonicalName, coord, policy, receipt)
	if err != nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, nil, err
	}
	return coord, policy, durable, nil
}

// finalizeVerifiedExternalReferenceSubmission consumes a receipt only after
// the caller has independently passed the retrieval-permission gate and the
// trusted fetch boundary. It deliberately performs no network I/O. Keeping
// final identity/locator derivation pure keeps those invariants independently
// testable after the admitted authorization, fetch, and archive boundaries.
func finalizeVerifiedExternalReferenceSubmission(env *Env, sub ArtifactSubmission, canonicalName string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor, receipt verifiedExternalSourceReceipt) (ArtifactSourceCoordinate, *stagedExternalVerificationReceipt, error) {
	if policy.VersionCoordinateMode == externalVersionModeContentDigest {
		coord.VersionCoordinate = VersionCoordinate{
			Kind: VersionSourceNamed, SourceAuthorityID: coord.SourceAuthorityID,
			StableName: canonicalName, SourceVersionToken: "sha256_" + receipt.DecodedSHA256,
		}.String()
	} else {
		if err := validateTrustedUpstreamVersionReceipt(policy, receipt); err != nil {
			return ArtifactSourceCoordinate{}, nil, fmt.Errorf("external source %q: %w", policy.ID, err)
		}
		coord.VersionCoordinate = VersionCoordinate{
			Kind: VersionSourceNamed, SourceAuthorityID: coord.SourceAuthorityID,
			StableName: canonicalName, SourceVersionToken: receipt.UpstreamVersionToken,
		}.String()
	}
	if err := verifyExternalObjectLocator(sub.NodeKind, canonicalName, coord, policy, receipt); err != nil {
		return ArtifactSourceCoordinate{}, nil, err
	}
	if err := validateFinalExternalCoordinate(env, sub.NodeKind, canonicalName, coord, policy); err != nil {
		return ArtifactSourceCoordinate{}, nil, err
	}
	fingerprint, err := externalPolicyFingerprint(policy)
	if err != nil {
		return ArtifactSourceCoordinate{}, nil, err
	}
	locatorKind := policy.LocatorKinds[sub.NodeKind]
	durable := &stagedExternalVerificationReceipt{
		ReceiptVersion: stagedExternalReceiptVersion, CanonicalReference: receipt.CanonicalReference,
		VerifiedSourceStableReference: coord.SourceStableReference,
		RetrievedAt:                   coord.RetrievedAt, ByteLength: receipt.ByteLength, SHA256: receipt.SHA256,
		TransportStatus: receipt.TransportStatus, TransportRawHashAlgorithm: receipt.TransportRawHashAlgorithm,
		ContentCoding: receipt.ContentCoding, TransportCharset: receipt.TransportCharset,
		TransportResponseMetadataDigest: receipt.TransportResponseMetadataDigest,
		DecodedByteLength:               receipt.DecodedByteLength, DecodedSHA256: receipt.DecodedSHA256,
		SourceRepresentationMediaType: receipt.SourceRepresentationMediaType,
		SourceContentHashAlgorithm:    policy.ContentHashAlgorithm,
		SourceContentHashProfile:      receipt.Authorization.SourceContentHashProfile,
		LicenseEvidence:               coord.LicenseEvidence,
		SourceRegistryID:              policy.ID, SourceAuthorityID: coord.SourceAuthorityID,
		PolicyFingerprint: fingerprint, ObjectClass: sub.NodeKind, CanonicalName: canonicalName,
		LocatorKind: locatorKind, FinalVersionCoordinate: coord.VersionCoordinate,
		Authorization: receipt.Authorization, Archive: receipt.Archive,
	}
	if policy.VersionCoordinateMode == externalVersionModeUpstreamPinned {
		durable.UpstreamVersionEvidenceKind = receipt.UpstreamVersionEvidenceKind
		durable.UpstreamVersionEvidence = receipt.UpstreamVersionEvidence
		durable.UpstreamVersionToken = receipt.UpstreamVersionToken
	}
	return coord, durable, nil
}

// preflightExternalReferenceSubmission validates every static caller and
// descriptor property needed before an external request can be justified.
// It deliberately performs no organization lookup, network I/O, embedding,
// or substrate access so a batch-level planner can reject topology and
// unsupported locator dependencies first.
func preflightExternalReferenceSubmission(env *Env, sub ArtifactSubmission, canonicalName string, kindDescriptor NodeKindDescriptor, coord ArtifactSourceCoordinate) (ExternalSourceDescriptor, error) {
	policy, err := preflightExternalReferenceSubmissionShape(env, sub, canonicalName, kindDescriptor, coord)
	if err != nil || !kindDescriptor.ExternalReferenceRequired() {
		return policy, err
	}
	// Permission-evidence coordinate shape is checked here, but executable
	// authorization is resolved separately immediately before network I/O.
	// Retrieval, AGFS custody, and graph publication remain independent.
	if err := validateExternalRetrievalPermissionEvidence(policy, coord); err != nil {
		return ExternalSourceDescriptor{}, err
	}
	return policy, nil
}

// preflightExternalReferenceSubmissionShape resolves caller-controlled
// identity and descriptor policy without yet adjudicating permission. The
// batch handler uses this narrower pass so malformed relationships/topology
// and unsupported locators are reported before any per-source evidence gate;
// the full preflight still runs before the first network request.
func preflightExternalReferenceSubmissionShape(env *Env, sub ArtifactSubmission, canonicalName string, kindDescriptor NodeKindDescriptor, coord ArtifactSourceCoordinate) (ExternalSourceDescriptor, error) {
	if !kindDescriptor.ExternalReferenceRequired() {
		return ExternalSourceDescriptor{}, nil
	}
	policy, err := resolveExternalSourcePolicy(env.Config, sub.NodeKind, canonicalName, coord)
	if err != nil {
		return ExternalSourceDescriptor{}, err
	}
	if len(sub.Contract) != 0 || len(sub.Payload) != 0 {
		return ExternalSourceDescriptor{}, fmt.Errorf("external-reference submissions are stable-reference-only: contract and payload must be empty; upstream content, summaries, examples, and rendered excerpts are forbidden")
	}
	// These values are trusted-fetch outputs. A caller may provide only an
	// optional expected digest; accepting caller-authored owner/time/final
	// digest version would confuse an assertion with a process receipt.
	if coord.SourceContentHashOwner != "" || coord.RetrievedAt != "" {
		return ExternalSourceDescriptor{}, fmt.Errorf("source_coordinate.source_content_hash_owner and retrieved_at are trusted-fetch outputs and must be omitted by callers")
	}
	switch policy.VersionCoordinateMode {
	case externalVersionModeContentDigest:
		if coord.VersionCoordinate != "" {
			return ExternalSourceDescriptor{}, fmt.Errorf("source_coordinate.version_coordinate must be omitted for content_digest external source %q; the trusted receipt derives it before graph identity", policy.ID)
		}
	case externalVersionModeUpstreamPinned:
		if coord.VersionCoordinate != "" {
			return ExternalSourceDescriptor{}, fmt.Errorf("source_coordinate.version_coordinate must be omitted for upstream_pinned external source %q; trusted upstream response or adapter evidence derives it before graph identity", policy.ID)
		}
	default:
		return ExternalSourceDescriptor{}, fmt.Errorf("external source %q has unsupported version_coordinate_mode %q", policy.ID, policy.VersionCoordinateMode)
	}
	if err := validateUpstreamPinnedReference(policy, coord.SourceStableReference); err != nil {
		return ExternalSourceDescriptor{}, err
	}
	return policy, nil
}

func validateFinalExternalCoordinate(env *Env, objectClass, canonicalName string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor) error {
	if coord.RetrievedAt == "" {
		return fmt.Errorf("source_coordinate.retrieved_at required for external-reference class %q", objectClass)
	}
	retrievedAt, err := time.Parse(time.RFC3339Nano, coord.RetrievedAt)
	if err != nil {
		return fmt.Errorf("source_coordinate.retrieved_at: %w", err)
	}
	now := time.Now().UTC()
	if env != nil && env.Now != nil {
		now = env.Now().UTC()
	}
	if retrievedAt.After(now.Add(5 * time.Minute)) {
		return fmt.Errorf("source_coordinate.retrieved_at %q is in the future", coord.RetrievedAt)
	}
	if now.Sub(retrievedAt) > time.Duration(policy.FreshnessWindowSeconds)*time.Second {
		return fmt.Errorf("source_coordinate.retrieved_at %q is stale for external source %q freshness window %ds", coord.RetrievedAt, policy.ID, policy.FreshnessWindowSeconds)
	}
	if policy.LicenseEvidenceRequired && coord.LicenseEvidence == "" {
		return fmt.Errorf("source_coordinate.license_evidence_when_available required by external source %q", policy.ID)
	}
	if err := validateExternalContentHash(policy.ContentHashAlgorithm, coord.SourceContentHash); err != nil {
		return fmt.Errorf("source_coordinate.source_content_hash for external source %q: %w", policy.ID, err)
	}
	if coord.SourceContentHashOwner != coord.SourceAuthorityID {
		return fmt.Errorf("source_coordinate.source_content_hash_owner must equal source_authority_id for external source %q", policy.ID)
	}
	if env == nil || env.Config.Embedding == nil || env.Embed == nil {
		return fmt.Errorf("external-reference ingestion requires a configured embedding client")
	}
	if env.Config.Embedding.Model == "" || env.Config.Embedding.Dimensions != externalReferenceEmbeddingDimensions {
		return fmt.Errorf("external-reference ingestion requires a configured embedding model with %d dimensions", externalReferenceEmbeddingDimensions)
	}
	if canonicalName == "" || !utf8.ValidString(canonicalName) || len(canonicalName) > 1024 || !snakeCaseKeyPattern.MatchString(canonicalName) {
		return fmt.Errorf("external-reference canonical name must be lowercase snake_case UTF-8 within OODGraphSymbols STRING(1024)")
	}
	vc, err := ParseVersionCoordinate(coord.VersionCoordinate)
	if err != nil {
		return err
	}
	if vc.Kind != VersionSourceNamed || vc.SourceAuthorityID != coord.SourceAuthorityID || vc.StableName != canonicalName {
		return fmt.Errorf("external-reference final version coordinate is not source-named for %q", canonicalName)
	}
	if policy.VersionCoordinateMode == externalVersionModeContentDigest {
		digest, ok := canonicalSHA256VersionTokenDigest(vc.SourceVersionToken)
		if !ok || digest != coord.SourceContentHash {
			return fmt.Errorf("external source %q requires final version_coordinate token sha256_<trusted receipt digest>", policy.ID)
		}
	} else if vc.SourceVersionToken == "" {
		return fmt.Errorf("external source %q requires a trusted upstream version token", policy.ID)
	}
	address := GraphAddress{
		ObjectClass: objectClass, SourceAuthorityID: coord.SourceAuthorityID,
		SourceRefKind: coord.SourceRefKind, SourceRef: coord.SourceStableReference,
		VersionCoordinate: coord.VersionCoordinate, SectionPath: coord.SectionPath,
	}.String()
	if len(address) > 4096 {
		return fmt.Errorf("source_coordinate graph_address exceeds OODGraphObjects STRING(4096) after canonical percent encoding")
	}
	parsed, err := ParseGraphAddress(address)
	if err != nil || parsed.String() != address {
		return fmt.Errorf("source_coordinate cannot form canonical graph_address after trusted version finalization: %w", err)
	}
	return nil
}

// validateStagedExternalReferenceSubmission consumes only the durable
// load-time receipt. It performs no fetch and therefore cannot rebind graph
// identity to different bytes if the upstream resource changes between load
// and promotion.
func validateStagedExternalReferenceSubmission(env *Env, sub ArtifactSubmission, canonicalName string, kindDescriptor NodeKindDescriptor, coord ArtifactSourceCoordinate, receipt *stagedExternalVerificationReceipt) (ArtifactSourceCoordinate, ExternalSourceDescriptor, error) {
	if !kindDescriptor.ExternalReferenceRequired() {
		if receipt != nil {
			return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, fmt.Errorf("ordinary staging row cannot carry an external verification receipt")
		}
		return coord, ExternalSourceDescriptor{}, nil
	}
	if receipt == nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, fmt.Errorf("external staging row requires a trusted load-time verification receipt")
	}
	policy, err := resolveExternalSourcePolicy(env.Config, sub.NodeKind, canonicalName, coord)
	if err != nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, err
	}
	if len(sub.Contract) != 0 || len(sub.Payload) != 0 {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, fmt.Errorf("external-reference submissions are stable-reference-only: contract and payload must be empty")
	}
	if err := validateStagedExternalReceiptBinding(policy, sub.NodeKind, canonicalName, coord, receipt); err != nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, err
	}
	if err := requireArchivedExternalEvidence(receipt); err != nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, err
	}
	if err := validateFinalExternalCoordinate(env, sub.NodeKind, canonicalName, coord, policy); err != nil {
		return ArtifactSourceCoordinate{}, ExternalSourceDescriptor{}, err
	}
	return coord, policy, nil
}

func requireArchivedExternalEvidence(receipt *stagedExternalVerificationReceipt) error {
	if receipt == nil {
		return fmt.Errorf("external evidence archive check requires a verification receipt")
	}
	switch receipt.Authorization.BodyCustodyDisposition {
	case externalBodyCustodyNone:
		if receipt.Archive != nil {
			return fmt.Errorf("no_local_body_custody receipt cannot carry an archive reference")
		}
		return fmt.Errorf("external evidence cannot be promoted without exact authorized body custody and a durable archive binding")
	case externalBodyCustodyAGFS:
		if receipt.Archive == nil {
			return fmt.Errorf("exact_agfs_body_custody receipt lacks a durable archive binding")
		}
		if err := validateExternalEvidenceArchiveReceipt(*receipt.Archive); err != nil {
			return err
		}
		if receipt.Archive.OrganizationID != receipt.Authorization.OrganizationID ||
			receipt.Archive.SourceContentHashAlgorithm != receipt.SourceContentHashAlgorithm ||
			receipt.Archive.SourceContentHashProfile != receipt.SourceContentHashProfile ||
			receipt.Archive.SourceContentHash != receipt.DecodedSHA256 ||
			receipt.Archive.SourceByteLength != receipt.DecodedByteLength ||
			receipt.Archive.BodyStorageAuthorizationReference != receipt.Authorization.BodyStorageAuthorizationReference ||
			receipt.Archive.BodyRetentionHoldReference != receipt.Authorization.BodyRetentionHoldReference ||
			receipt.Archive.DeletionDomainID != receipt.Authorization.ArchiveDeletionDomainID ||
			receipt.Archive.CryptoShredDomainID != receipt.Authorization.ArchiveCryptoShredDomainID {
			return fmt.Errorf("external evidence archive binding does not match the canonical source bytes and admitted custody decision")
		}
		return nil
	default:
		return fmt.Errorf("external evidence receipt has unknown body custody disposition %q", receipt.Authorization.BodyCustodyDisposition)
	}
}

// validateStagedExternalReceiptBinding proves that one body-free process
// receipt belongs to one finalized semantic coordinate and the currently
// admitted descriptor. Freshness relative to "now" is deliberately outside
// this helper: a sealed historical occurrence remains valid audit evidence
// after its freshness window expires.
func validateStagedExternalReceiptBinding(policy ExternalSourceDescriptor, objectClass, canonicalName string, coord ArtifactSourceCoordinate, receipt *stagedExternalVerificationReceipt) error {
	if receipt == nil {
		return fmt.Errorf("external source coordinate requires a verification receipt")
	}
	if err := validateUpstreamPinnedReference(policy, coord.SourceStableReference); err != nil {
		return err
	}
	fingerprint, err := externalPolicyFingerprint(policy)
	if err != nil {
		return err
	}
	resource, err := externalResourceReference(coord.SourceStableReference, policy)
	if err != nil {
		return err
	}
	wantLocator := policy.LocatorKinds[objectClass]
	if receipt.ReceiptVersion != stagedExternalReceiptVersion ||
		receipt.CanonicalReference != resource ||
		receipt.VerifiedSourceStableReference != coord.SourceStableReference ||
		receipt.SourceRegistryID != policy.ID ||
		receipt.SourceAuthorityID != coord.SourceAuthorityID ||
		receipt.PolicyFingerprint != fingerprint ||
		receipt.ObjectClass != objectClass ||
		receipt.CanonicalName != canonicalName ||
		receipt.LocatorKind != wantLocator ||
		receipt.FinalVersionCoordinate != coord.VersionCoordinate ||
		receipt.DecodedSHA256 != coord.SourceContentHash ||
		receipt.RetrievedAt != coord.RetrievedAt ||
		receipt.LicenseEvidence != coord.LicenseEvidence ||
		receipt.ByteLength < 0 ||
		receipt.DecodedByteLength < 0 {
		return fmt.Errorf("staged external verification receipt does not match the preserved final source coordinate and current trust policy")
	}
	requestAtOccurrence := externalSourceAuthorizationRequest{
		OrganizationID:        receipt.Authorization.OrganizationID,
		ObjectClass:           objectClass,
		SourceRegistryID:      policy.ID,
		SourceArtifactClass:   policy.SourceArtifactClass,
		SourceAuthorityID:     coord.SourceAuthorityID,
		SourceRefKind:         coord.SourceRefKind,
		SourceStableReference: coord.SourceStableReference,
		PermissionOperation:   externalFetchPermissionOperation,
		PermissionMethod:      "GET",
	}
	observedAt, err := time.Parse(time.RFC3339Nano, receipt.RetrievedAt)
	if err != nil {
		return fmt.Errorf("staged external verification receipt observed_at: %w", err)
	}
	requestAtOccurrence.ObservedAt = observedAt
	if err := validateExternalSourceAuthorization(requestAtOccurrence, receipt.Authorization); err != nil {
		return fmt.Errorf("staged external authorization: %w", err)
	}
	if receipt.SourceContentHashAlgorithm != policy.ContentHashAlgorithm || receipt.SourceContentHashProfile != receipt.Authorization.SourceContentHashProfile {
		return fmt.Errorf("staged external verification receipt does not bind the admitted canonical source hash contract")
	}
	if receipt.TransportStatus != "success" || receipt.TransportRawHashAlgorithm != "sha256" {
		return fmt.Errorf("staged external verification receipt lacks successful transport status or the closed raw hash algorithm")
	}
	if err := validateExternalContentHash("sha256", receipt.TransportResponseMetadataDigest); err != nil {
		return fmt.Errorf("staged external verification receipt response metadata digest: %w", err)
	}
	if receipt.Authorization.SourceRepresentationMediaType != "" && receipt.SourceRepresentationMediaType != receipt.Authorization.SourceRepresentationMediaType {
		return fmt.Errorf("staged external verification receipt media type does not match the admitted representation declaration")
	}
	// Check semantic receipt identity before the independent permission gate,
	// so a locator-switched or otherwise tampered staged row is diagnosed as
	// such while still remaining unable to proceed without an executable
	// admitted permission decision.
	if err := validateExternalRetrievalPermissionEvidence(policy, coord); err != nil {
		return err
	}
	if err := validateExternalContentHash(policy.ContentHashAlgorithm, receipt.SHA256); err != nil {
		return fmt.Errorf("staged external verification receipt digest: %w", err)
	}
	if receipt.ContentCoding != "identity" && receipt.ContentCoding != "gzip" {
		return fmt.Errorf("staged external verification receipt content_coding %q is outside the closed identity|gzip set", receipt.ContentCoding)
	}
	if err := validateExternalContentHash("sha256", receipt.DecodedSHA256); err != nil {
		return fmt.Errorf("staged external verification receipt decoded locator digest: %w", err)
	}
	if receipt.ContentCoding == "identity" && (receipt.DecodedByteLength != receipt.ByteLength || receipt.DecodedSHA256 != receipt.SHA256) {
		return fmt.Errorf("identity-coded staged external verification receipt has divergent raw and locator evidence")
	}
	vc, err := ParseVersionCoordinate(coord.VersionCoordinate)
	if err != nil {
		return err
	}
	if policy.VersionCoordinateMode == externalVersionModeUpstreamPinned {
		if tokenErr := validateTrustedUpstreamVersionMaterial(policy, receipt.CanonicalReference, receipt.DecodedSHA256, receipt.UpstreamVersionEvidenceKind, receipt.UpstreamVersionEvidence, receipt.UpstreamVersionToken); tokenErr != nil || vc.SourceVersionToken != receipt.UpstreamVersionToken {
			return fmt.Errorf("staged external verification receipt does not bind trusted upstream version evidence to the final source coordinate")
		}
	} else if receipt.UpstreamVersionEvidenceKind != "" || receipt.UpstreamVersionEvidence != "" || receipt.UpstreamVersionToken != "" {
		return fmt.Errorf("content_digest staged external verification receipt must not carry upstream-pinned version evidence")
	}
	return nil
}

func validateTrustedUpstreamVersionReceipt(policy ExternalSourceDescriptor, receipt verifiedExternalSourceReceipt) error {
	return validateTrustedUpstreamVersionMaterial(policy, receipt.CanonicalReference, receipt.DecodedSHA256, receipt.UpstreamVersionEvidenceKind, receipt.UpstreamVersionEvidence, receipt.UpstreamVersionToken)
}

func validateTrustedUpstreamVersionMaterial(policy ExternalSourceDescriptor, canonicalReference, contentDigest, evidenceKind, evidence, token string) error {
	if evidenceKind == "" || evidence == "" || token == "" {
		return fmt.Errorf("upstream_pinned identity requires trusted upstream version evidence; caller assertions are forbidden")
	}
	switch policy.UpstreamIdentityPolicy {
	case upstreamIdentityHTTPResponseWithContentDigest:
		switch evidenceKind {
		case "http_x_amz_version_id":
			if _, err := canonicalSingleHTTPVersionEvidence("x-amz-version-id", []string{evidence}); err != nil {
				return err
			}
		case "http_etag", "http_weak_etag":
			if !canonicalHTTPETag(evidence) {
				return fmt.Errorf("trusted upstream ETag evidence is not a canonical HTTP entity-tag")
			}
			if (evidenceKind == "http_weak_etag") != strings.HasPrefix(evidence, "W/") {
				return fmt.Errorf("trusted upstream ETag evidence kind does not match weak/strong syntax")
			}
		default:
			return fmt.Errorf("HTTP-response upstream identity policy cannot consume evidence kind %q", evidenceKind)
		}
	case upstreamIdentityImmutableRefWithContentDigest:
		if evidenceKind != "immutable_reference_coordinate" || evidence != canonicalReference {
			return fmt.Errorf("immutable-reference upstream identity must bind the exact fragment-free canonical resource coordinate")
		}
		if err := validateUpstreamPinnedReference(policy, evidence); err != nil {
			return err
		}
	default:
		return fmt.Errorf("external source %q has no executable upstream identity policy", policy.ID)
	}
	wantToken, err := trustedUpstreamVersionToken(evidenceKind, evidence, contentDigest)
	if err != nil {
		return err
	}
	if token != wantToken {
		return fmt.Errorf("trusted upstream version token does not derive from the receipt evidence")
	}
	return nil
}

func validateExternalContentHash(algorithm, digest string) error {
	if algorithm != "sha256" {
		return fmt.Errorf("unsupported configured content hash algorithm %q", algorithm)
	}
	if len(digest) != 64 {
		return fmt.Errorf("must be a 64-character lowercase hexadecimal SHA-256 digest")
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("must be a 64-character lowercase hexadecimal SHA-256 digest")
		}
	}
	return nil
}

// externalReferenceSearchPayload is deliberately closed. Every top-level
// member is listed by OOD_GRAPH_PROTOCOL_v1's property_leak_gate; the nested
// values are graph-owned parser classification tokens. Upstream title,
// summary, body, snippet, rendered prose, status, and runtime secrets have no
// input slot and therefore cannot leak into the graph.
func externalReferenceSearchPayload(kind, graphAddress string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor) map[string]interface{} {
	tokens := map[string]interface{}{
		"source_registry_id":           policy.ID,
		"source_trust_class":           coord.SourceArtifactClass,
		"content_hash_algorithm":       policy.ContentHashAlgorithm,
		"version_coordinate_mode":      policy.VersionCoordinateMode,
		"freshness_window_seconds":     policy.FreshnessWindowSeconds,
		"query_coordinates_allowed":    policy.AllowQuery,
		"fragment_coordinates_allowed": policy.AllowFragment,
	}
	return map[string]interface{}{
		"object_class":                             kind,
		"graph_address":                            graphAddress,
		"section_path":                             coord.SectionPath,
		"version_coordinate":                       coord.VersionCoordinate,
		"source_authority_id":                      coord.SourceAuthorityID,
		"source_stable_reference":                  coord.SourceStableReference,
		"graph_owned_parser_classification_tokens": tokens,
	}
}

func externalReferenceSearchText(kind string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor) string {
	return strings.Join([]string{
		kind,
		coord.SourceStableReference,
		coord.VersionCoordinate,
		coord.SourceArtifactClass,
		policy.ID,
	}, " ")
}

// externalReferenceSymbol emits one metadata-only symbol for the stable
// external coordinate. It reuses the already-validated object embedding so a
// second remote call cannot partially succeed and leave an unembedded symbol.
func externalReferenceSymbol(obj GraphObject, canonicalName string, source ArtifactSourceCoordinate, idNS uuid.UUID) (GraphSymbol, error) {
	const symbolKind = "external_reference"
	sectionPath := source.SectionPath
	if err := ValidateSectionPath(sectionPath); err != nil {
		return GraphSymbol{}, err
	}
	ga := GraphAddress{
		ObjectClass:       "symbol",
		SourceAuthorityID: source.SourceAuthorityID,
		SourceRefKind:     source.SourceRefKind,
		SourceRef:         source.SourceStableReference,
		VersionCoordinate: source.VersionCoordinate,
		SectionPath:       sectionPath,
	}
	address := ga.String()
	if len(address) > 4096 {
		return GraphSymbol{}, fmt.Errorf("external symbol graph_address exceeds OODGraphSymbols STRING(4096)")
	}
	parsed, err := ParseGraphAddress(address)
	if err != nil || parsed.String() != address {
		return GraphSymbol{}, fmt.Errorf("external symbol graph_address is not canonical: %w", err)
	}
	idInput := fmt.Sprintf("symbol|%s|%s|%s|%s|%s|%s|%s|%s:%s",
		obj.OrganizationID, obj.ObjectClass, source.SourceAuthorityID, source.SourceRefKind,
		source.SourceStableReference, source.VersionCoordinate, sectionPath, symbolKind, canonicalName)
	symbol := GraphSymbol{
		OrganizationID:        obj.OrganizationID,
		GraphSnapshotID:       obj.GraphSnapshotID,
		SymbolID:              uuid.NewSHA1(idNS, []byte(idInput)).String(),
		GraphObjectID:         obj.GraphObjectID,
		ObjectClass:           obj.ObjectClass,
		SymbolKind:            symbolKind,
		SymbolName:            canonicalName,
		SourceAuthorityID:     source.SourceAuthorityID,
		SourceStableReference: source.SourceStableReference,
		VersionCoordinate:     source.VersionCoordinate,
		SectionPath:           sectionPath,
		GraphAddress:          address,
		MaterializationRunID:  obj.MaterializationRunID,
		ValidationState:       obj.ValidationState,
		Status:                obj.Status,
		VisibilityScope:       obj.VisibilityScope,
		SearchText:            obj.SearchText,
		SearchPayload:         obj.SearchPayload,
		Embedding:             append([]float32(nil), obj.Embedding...),
		EmbeddingModel:        obj.EmbeddingModel,
	}
	// Keep the authority receipt tokens from the owner while adding the
	// symbol-specific graph-owned coordinates permitted by §6. No upstream
	// title, body, example, or rendered excerpt is copied.
	symbol.SearchPayload = graphOwnedSymbolSearchPayload(symbol)
	if tokens, ok := obj.SearchPayload["graph_owned_parser_classification_tokens"].(map[string]interface{}); ok {
		symbol.SearchPayload["graph_owned_parser_classification_tokens"] = tokens
	}
	return symbol, nil
}
