package oodevidence

import "time"

// ReceiptV8 is the complete immutable OODGraphExternalFetchReceipts row
// relevant to proof.  It intentionally does not contain ciphertext or the
// self-referential redacted_transport_evidence_digest; those are excluded by
// OOD8's receipt preimage.
type ReceiptV8 struct {
	OrganizationID, ReceiptID, FetchBatchID                                                                             string
	ReceiptRoles                                                                                                        []string
	FetchComponentOrdinal                                                                                               *int64
	FetchOccurrenceID, EvidenceIdentityHash                                                                             string
	GraphObjectID, ObjectClass, SourceAuthorityID                                                                       string
	SourceAuthorityBindingID, SourceAuthorityBindingDigest                                                              string
	SourceRefKind, SourceStableReference, SourceRepresentationKind, EvidenceContentClass                                string
	SourceRepresentationMediaType                                                                                       *string
	RepresentationDeclarationID, RepresentationDeclarationDigest, VersionCoordinate                                     string
	SourceContentHashAlgorithm, SourceContentHashProfile, SourceContentHash                                             string
	ExternalFetchProfileRef, ExternalFetchProfileDigest                                                                 string
	PermissionGrantID, PermissionGrantDigest, PermissionAuthorityID, PermissionPrincipalID, PermissionScopeDigest       string
	PermissionOperation, PermissionMethod, PermissionRedirectPolicyDigest, PermissionContentClass, PermissionTrustClass string
	PermissionByteCeiling, PermissionDepthCeiling                                                                       int64
	PermissionExpectedContentHashAlgorithm, PermissionExpectedContentHashProfile, PermissionExpectedContentHash         *string
	PermissionEffectiveAt                                                                                               time.Time
	PermissionExpiresAt                                                                                                 *time.Time
	PermissionStatus, PermissionPolicyVersionRef, PermissionPolicyVersionDigest                                         string
	FetchAuthorizationDecisionRef, FetchAuthorizationDecisionDigest                                                     string
	ObservedAt                                                                                                          time.Time
	TransportStatus, TransportRawContentHashAlgorithm, TransportRawContentHash                                          string
	TransportRawByteCount, TransportDecodedByteCount                                                                    int64
	TransportContentEncoding, TransportCharset                                                                          *string
	TransportResponseMetadataDigest                                                                                     string
	EvidenceArchiveAuthorityID, EvidenceArchiveRecordID, EvidenceArchiveRecordDigest                                    string
	EvidenceArchiveByteCount                                                                                            int64
	EvidenceArchiveDeletionDomainID, EvidenceArchiveCryptoShredDomainID                                                 string
	ReceiptDeletionDomainID, ReceiptCryptoShredDomainID                                                                 string
	RedactedTransportEvidenceDigest                                                                                     string // output/member hash; excluded from receipt digest preimage.
}

// BatchV8 is the complete OODGraphExternalFetchBatches certificate. Counts
// are separate role-set cardinalities: they may overlap and must never be
// summed to manufacture total receipt count.
type BatchV8 struct {
	OrganizationID, FetchBatchID                                                                                         string
	SourceAuthorityBindingID, SourceAuthorityBindingDigest                                                               string
	RepresentationDeclarationID, RepresentationDeclarationDigest                                                         string
	BatchReceiptManifestRootHash                                                                                         string
	TotalReceiptCount, ComponentReceiptCount, CompletenessEvidenceReceiptCount, NoncomponentReceiptCount                 int64
	ExpectedComponentCount                                                                                               *int64
	CompletenessBasisKind, CompletenessEvidenceRef, CompletenessEvidenceIdentityHash                                     string
	CompletenessEvidenceContentHashAlgorithm, CompletenessEvidenceContentHashProfile, CompletenessEvidenceContentHash    string
	CompletenessEvidenceReceiptID                                                                                        string
	CompletenessEvidenceArchiveAuthorityID, CompletenessEvidenceArchiveRecordID, CompletenessEvidenceArchiveRecordDigest string
	CompletenessEvidenceSelectorKind, CompletenessEvidenceSelectorValue                                                  string
	VerifiedCompletenessClaimDigest, CompletenessEvidenceDigest, CompletenessProfileRef, CompletenessProfileDigest       string
	SealedAt                                                                                                             time.Time
}

// ReceiptManifestMember is an exact normalized manifest leaf. The member hash
// is the immutable receipt output digest, not a re-hash of a convenient
// projection. Child links form a bounded tree and are validated separately.
type ReceiptManifestMember struct {
	EntryOrdinal int64
	ReceiptID    string
	MemberHash   string
	Roles        []string
}

// ReceiptManifestNode is an ordinary bounded OOD manifest node. A node has
// exactly one entry kind per child: member or child node; generic traversal
// validates contiguous ordinal ordering and counts before a batch is sealed.
type ReceiptManifestNode struct {
	NodeHash, OrganizationID, ManifestKind, NodeKind                 string
	NodeLevel, EntryCount, TransitiveMemberCount, CanonicalByteCount int64
	Sealed                                                           bool
	Entries                                                          []ReceiptManifestEntry
	Members                                                          []ReceiptManifestMember
	Children                                                         []ReceiptManifestNode
}

// ReceiptManifestEntry preserves the one normalized entry ordinal shared by
// member and child links. Exactly one target is present.
type ReceiptManifestEntry struct {
	EntryOrdinal            int64
	CanonicalEntryByteCount int64
	Member                  *ReceiptManifestMember
	Child                   *ReceiptManifestNode
}

// ComponentManifestTuple is the protected parser's normalized
// canonical_component_manifest_v1 output. It is intentionally typed instead
// of accepting a provider JSON fragment or a caller-selected ordinal.
type ComponentManifestTuple struct {
	Ordinal                   int64
	StableReference           string
	EvidenceIdentityHash      string
	ContentHashAlgorithm      string
	ContentHashProfile        string
	ContentHash               string
	CanonicalContentByteCount int64
}
