package oodevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
)

type manifestTestAuthority struct{}

func (manifestTestAuthority) VerifySealedManifestNode(context.Context, ReceiptManifestNode) error {
	return nil
}
func (manifestTestAuthority) AdmittedNoncomponentRoleCounts(context.Context, BatchV8) (map[string]int64, error) {
	return map[string]int64{}, nil
}
func (manifestTestAuthority) ResolveCanonicalComponentManifest(context.Context, BatchV8) ([]ComponentManifestTuple, error) {
	return nil, nil
}

func testDigest(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }
func testID() string             { return uuid.NewString() }
func testReceiptV8() ReceiptV8 {
	now := time.Unix(1, 0).UTC()
	ordinal := int64(0)
	return ReceiptV8{OrganizationID: testID(), ReceiptID: testID(), FetchBatchID: "batch", ReceiptRoles: []string{"completeness_evidence", "component"}, FetchComponentOrdinal: &ordinal, FetchOccurrenceID: "occurrence", EvidenceIdentityHash: testDigest("identity"), GraphObjectID: testID(), ObjectClass: "object", SourceAuthorityID: testID(), SourceAuthorityBindingID: testID(), SourceAuthorityBindingDigest: testDigest("binding"), SourceRefKind: "url", SourceStableReference: "https://example.test/doc", SourceRepresentationKind: "api", EvidenceContentClass: "docs", RepresentationDeclarationID: testID(), RepresentationDeclarationDigest: testDigest("representation"), VersionCoordinate: "v1", SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: "canonical", SourceContentHash: testDigest("body"), ExternalFetchProfileRef: "profile/v1", ExternalFetchProfileDigest: testDigest("fetch-profile"), PermissionGrantID: testID(), PermissionGrantDigest: testDigest("grant"), PermissionAuthorityID: testID(), PermissionPrincipalID: testID(), PermissionScopeDigest: testDigest("scope"), PermissionOperation: "read", PermissionMethod: "GET", PermissionRedirectPolicyDigest: testDigest("redirect"), PermissionContentClass: "docs", PermissionTrustClass: "official", PermissionByteCeiling: 100, PermissionDepthCeiling: 1, PermissionEffectiveAt: now, PermissionStatus: "affirmative", PermissionPolicyVersionRef: "policy/v1", PermissionPolicyVersionDigest: testDigest("policy"), FetchAuthorizationDecisionRef: "decision/v1", FetchAuthorizationDecisionDigest: testDigest("decision"), ObservedAt: now, TransportStatus: "success", TransportRawContentHashAlgorithm: "sha256", TransportRawContentHash: testDigest("raw"), TransportRawByteCount: 4, TransportDecodedByteCount: 4, TransportResponseMetadataDigest: testDigest("metadata"), EvidenceArchiveAuthorityID: testID(), EvidenceArchiveRecordID: testID(), EvidenceArchiveRecordDigest: testDigest("archive"), EvidenceArchiveByteCount: 4, EvidenceArchiveDeletionDomainID: testID(), EvidenceArchiveCryptoShredDomainID: testID(), ReceiptDeletionDomainID: testID(), ReceiptCryptoShredDomainID: testID(), RedactedTransportEvidenceDigest: ""}
}
func TestReceiptDigestV8RejectsNullRoleAndExpectedHashViolations(t *testing.T) {
	r := testReceiptV8()
	if _, e := ReceiptDigestV8(r); e != nil {
		t.Fatal(e)
	}
	r.FetchComponentOrdinal = nil
	if _, e := ReceiptDigestV8(r); e == nil {
		t.Fatal("component null ordinal accepted")
	}
	r = testReceiptV8()
	r.ReceiptRoles = []string{"completeness_evidence"}
	if _, e := ReceiptDigestV8(r); e == nil {
		t.Fatal("noncomponent ordinal accepted")
	}
	r = testReceiptV8()
	x := "sha256"
	r.PermissionExpectedContentHashAlgorithm = &x
	if _, e := ReceiptDigestV8(r); e == nil {
		t.Fatal("partial optional content tuple accepted")
	}
}
func TestReceiptDigestV8ChangesWhenTypedFieldChanges(t *testing.T) {
	r := testReceiptV8()
	a, e := ReceiptDigestV8(r)
	if e != nil {
		t.Fatal(e)
	}
	r.PermissionOperation = "list"
	b, e := ReceiptDigestV8(r)
	if e != nil {
		t.Fatal(e)
	}
	if a == b {
		t.Fatal("field identity mutation preserved receipt digest")
	}
}

func TestComponentManifestBijectionRejectsSubstitutionAndDuplicateOrdinal(t *testing.T) {
	r := testReceiptV8()
	tuple := ComponentManifestTuple{Ordinal: 0, StableReference: r.SourceStableReference, EvidenceIdentityHash: r.EvidenceIdentityHash, ContentHashAlgorithm: r.SourceContentHashAlgorithm, ContentHashProfile: r.SourceContentHashProfile, ContentHash: r.SourceContentHash, CanonicalContentByteCount: r.EvidenceArchiveByteCount}
	if err := verifyComponentManifestBijection([]ComponentManifestTuple{tuple}, []ReceiptV8{r}, 1); err != nil {
		t.Fatal(err)
	}
	tuple.ContentHash = testDigest("substituted")
	if err := verifyComponentManifestBijection([]ComponentManifestTuple{tuple}, []ReceiptV8{r}, 1); err == nil {
		t.Fatal("substituted component content accepted")
	}
	tuple.ContentHash = r.SourceContentHash
	if err := verifyComponentManifestBijection([]ComponentManifestTuple{tuple, tuple}, []ReceiptV8{r}, 2); err == nil {
		t.Fatal("duplicate component tuple ordinal accepted")
	}
}

func TestManifestTraversalRejectsInflatedAndDeflatedSubtreeCounts(t *testing.T) {
	n := ReceiptManifestNode{NodeHash: testDigest("node"), OrganizationID: testID(), ManifestKind: "fetch_batch_receipt", NodeKind: "leaf", NodeLevel: 0, Sealed: true, EntryCount: 1, TransitiveMemberCount: 1, Members: []ReceiptManifestMember{{ReceiptID: testID(), MemberHash: testDigest("member")}}}
	if count, err := walkReceiptManifest(context.Background(), n, manifestTestAuthority{}, map[string]ReceiptManifestMember{}, map[string]struct{}{}); err != nil || count != 1 {
		t.Fatalf("valid leaf: %d %v", count, err)
	}
	n.TransitiveMemberCount = 2
	if _, err := walkReceiptManifest(context.Background(), n, manifestTestAuthority{}, map[string]ReceiptManifestMember{}, map[string]struct{}{}); err == nil {
		t.Fatal("inflated subtree count accepted")
	}
	n.TransitiveMemberCount = 0
	if _, err := walkReceiptManifest(context.Background(), n, manifestTestAuthority{}, map[string]ReceiptManifestMember{}, map[string]struct{}{}); err == nil {
		t.Fatal("deflated subtree count accepted")
	}
}
