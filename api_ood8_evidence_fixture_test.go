package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
)

// This fixture intentionally mints no opaque proof directly.  The production
// verifier is exercised from canonical archived bytes all the way through the
// complete receipt-batch traversal and native API role derivation.
type apiOOD8FixtureAuthority struct{}

func (apiOOD8FixtureAuthority) VerifySealedManifestNode(context.Context, oodevidence.ReceiptManifestNode) error {
	return nil
}
func (apiOOD8FixtureAuthority) AdmittedNoncomponentRoleCounts(context.Context, oodevidence.BatchV8) (map[string]int64, error) {
	return map[string]int64{}, nil
}
func (apiOOD8FixtureAuthority) ResolveCanonicalComponentManifest(context.Context, oodevidence.BatchV8) ([]oodevidence.ComponentManifestTuple, error) {
	return nil, nil
}
func (apiOOD8FixtureAuthority) VerifyNativeAPIElementRoles(_ context.Context, r oodevidence.RelationshipV8, _ oodevidence.VerifiedBatchV8, l oodproof.GraphFactLocator, source, target string) error {
	if r.SourceStableReference != "api://fixture/source" || r.TargetStableReference != "api://fixture/target" ||
		l.EligibleReceiptID == "" || source != "operation" || target != "resource" {
		return errors.New("fixture native role binding mismatch")
	}
	return nil
}
func (apiOOD8FixtureAuthority) VerifyCurrentRelationshipEligibility(_ context.Context, r oodevidence.RelationshipV8, receipt oodevidence.ReceiptV8, batch oodevidence.BatchV8) error {
	if r.OrganizationID != receipt.OrganizationID || receipt.FetchBatchID != batch.FetchBatchID {
		return errors.New("fixture currentness binding mismatch")
	}
	return nil
}

func apiOOD8Digest(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }
func apiOOD8ID(s string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("api-ood8-fixture/"+s)).String()
}
func apiOOD8String(v string) *string { return &v }
func apiOOD8I64(v int64) *int64      { return &v }

func apiOOD8Receipt(body []byte) oodevidence.ReceiptV8 {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	ordinal := int64(0)
	bodyDigest := sha256.Sum256(body)
	return oodevidence.ReceiptV8{
		OrganizationID: apiOOD8ID("org"), ReceiptID: apiOOD8ID("receipt"), FetchBatchID: "batch-1",
		ReceiptRoles: []string{"completeness_evidence", "component"}, FetchComponentOrdinal: &ordinal, FetchOccurrenceID: "occurrence-1",
		EvidenceIdentityHash: apiOOD8Digest("identity"), GraphObjectID: apiOOD8ID("graph-object"), ObjectClass: "api_symbol",
		SourceAuthorityID: apiOOD8ID("source-authority"), SourceAuthorityBindingID: apiOOD8ID("binding"), SourceAuthorityBindingDigest: apiOOD8Digest("binding"),
		SourceRefKind: "url", SourceStableReference: "https://example.test/api", SourceRepresentationKind: "api", EvidenceContentClass: "documentation",
		RepresentationDeclarationID: apiOOD8ID("representation"), RepresentationDeclarationDigest: apiOOD8Digest("representation"), VersionCoordinate: "v1",
		SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: "canonical", SourceContentHash: hex.EncodeToString(bodyDigest[:]),
		ExternalFetchProfileRef: "profile/v1", ExternalFetchProfileDigest: apiOOD8Digest("fetch-profile"),
		PermissionGrantID: apiOOD8ID("grant"), PermissionGrantDigest: apiOOD8Digest("grant"), PermissionAuthorityID: apiOOD8ID("permission-authority"), PermissionPrincipalID: apiOOD8ID("principal"), PermissionScopeDigest: apiOOD8Digest("scope"), PermissionOperation: "read", PermissionMethod: "GET", PermissionRedirectPolicyDigest: apiOOD8Digest("redirect"), PermissionContentClass: "documentation", PermissionTrustClass: "official", PermissionByteCeiling: 1 << 20, PermissionDepthCeiling: 1, PermissionEffectiveAt: now, PermissionStatus: "affirmative", PermissionPolicyVersionRef: "policy/v1", PermissionPolicyVersionDigest: apiOOD8Digest("policy"),
		FetchAuthorizationDecisionRef: "decision/v1", FetchAuthorizationDecisionDigest: apiOOD8Digest("decision"), ObservedAt: now, TransportStatus: "success", TransportRawContentHashAlgorithm: "sha256", TransportRawContentHash: apiOOD8Digest("raw"), TransportRawByteCount: int64(len(body)), TransportDecodedByteCount: int64(len(body)), TransportResponseMetadataDigest: apiOOD8Digest("metadata"),
		EvidenceArchiveAuthorityID: apiOOD8ID("archive-authority"), EvidenceArchiveRecordID: apiOOD8ID("archive-record"), EvidenceArchiveRecordDigest: apiOOD8Digest("archive-record"), EvidenceArchiveByteCount: int64(len(body)), EvidenceArchiveDeletionDomainID: apiOOD8ID("archive-deletion"), EvidenceArchiveCryptoShredDomainID: apiOOD8ID("archive-shred"), ReceiptDeletionDomainID: apiOOD8ID("receipt-deletion"), ReceiptCryptoShredDomainID: apiOOD8ID("receipt-shred"),
	}
}

func apiOOD8VerifiedBatch(t *testing.T, body []byte) (oodevidence.ReceiptV8, oodevidence.VerifiedBatchV8) {
	t.Helper()
	r := apiOOD8Receipt(body)
	digest, err := oodevidence.ReceiptDigestV8(r)
	if err != nil {
		t.Fatal(err)
	}
	r.RedactedTransportEvidenceDigest = digest
	b := oodevidence.BatchV8{OrganizationID: r.OrganizationID, FetchBatchID: r.FetchBatchID, SourceAuthorityBindingID: r.SourceAuthorityBindingID, SourceAuthorityBindingDigest: r.SourceAuthorityBindingDigest, RepresentationDeclarationID: r.RepresentationDeclarationID, RepresentationDeclarationDigest: r.RepresentationDeclarationDigest, BatchReceiptManifestRootHash: apiOOD8Digest("receipt-manifest"), TotalReceiptCount: 1, ComponentReceiptCount: 1, CompletenessEvidenceReceiptCount: 1, ExpectedComponentCount: apiOOD8I64(1), CompletenessBasisKind: "source_declared_total", CompletenessEvidenceRef: "https://example.test/api", CompletenessEvidenceIdentityHash: r.EvidenceIdentityHash, CompletenessEvidenceContentHashAlgorithm: r.SourceContentHashAlgorithm, CompletenessEvidenceContentHashProfile: r.SourceContentHashProfile, CompletenessEvidenceContentHash: r.SourceContentHash, CompletenessEvidenceReceiptID: r.ReceiptID, CompletenessEvidenceArchiveAuthorityID: r.EvidenceArchiveAuthorityID, CompletenessEvidenceArchiveRecordID: r.EvidenceArchiveRecordID, CompletenessEvidenceArchiveRecordDigest: r.EvidenceArchiveRecordDigest, CompletenessEvidenceSelectorKind: "whole_evidence_body", CompletenessEvidenceSelectorValue: "$", VerifiedCompletenessClaimDigest: apiOOD8Digest("claim"), CompletenessProfileRef: "profile/v1", CompletenessProfileDigest: apiOOD8Digest("profile"), SealedAt: time.Date(2026, 11, 2, 12, 1, 0, 0, time.UTC)}
	b.CompletenessEvidenceDigest, err = oodevidence.CompletenessEvidenceDigestV8(b)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := oodevidence.VerifyBatchV8(context.Background(), b, []oodevidence.ReceiptV8{r}, oodevidence.ReceiptManifestNode{NodeHash: b.BatchReceiptManifestRootHash, OrganizationID: r.OrganizationID, ManifestKind: "fetch_batch_receipt", NodeKind: "leaf", Sealed: true, EntryCount: 1, TransitiveMemberCount: 1, Members: []oodevidence.ReceiptManifestMember{{ReceiptID: r.ReceiptID, MemberHash: digest}}}, apiOOD8FixtureAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	return r, batch
}

func apiOOD8RelationshipAndLocator(t *testing.T, body []byte, receipt oodevidence.ReceiptV8, batch oodevidence.VerifiedBatchV8) (oodevidence.RelationshipV8, oodproof.GraphFactLocator) {
	t.Helper()
	selected := body[0:len(body)]
	selectedSum := sha256.Sum256(selected)
	l := oodproof.GraphFactLocator{OrganizationID: receipt.OrganizationID, EvidenceIdentityHash: receipt.EvidenceIdentityHash, SourceArtifactMemberHash: apiOOD8Digest("virtual-source-artifact"), EligibleReceiptID: receipt.ReceiptID, EligibleReceiptDigest: receipt.RedactedTransportEvidenceDigest, SealedCompletenessCertificateHash: batch.CompletenessEvidenceDigest(), EvidenceArchiveAuthorityID: receipt.EvidenceArchiveAuthorityID, EvidenceArchiveRecordID: receipt.EvidenceArchiveRecordID, EvidenceArchiveRecordDigest: receipt.EvidenceArchiveRecordDigest, SourceContentHashAlgorithm: receipt.SourceContentHashAlgorithm, SourceContentHashProfile: receipt.SourceContentHashProfile, SourceContentHash: receipt.SourceContentHash, SourceContentByteLength: int64(len(body)), CanonicalRepresentationProfileRef: "canonical/v1", CanonicalRepresentationProfileDigest: apiOOD8Digest("canonical-profile"), ByteStartOffset: 0, ByteEndOffsetExclusive: int64(len(body)), SelectedRangeContentHash: hex.EncodeToString(selectedSum[:]), SelectedRangeByteCount: int64(len(body)), EvidenceArchiveDeletionDomainID: receipt.EvidenceArchiveDeletionDomainID, EvidenceArchiveCryptoShredDomainID: receipt.EvidenceArchiveCryptoShredDomainID}
	var err error
	l.LocatorHash, err = l.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	r := oodevidence.RelationshipV8{OrganizationID: receipt.OrganizationID, EvidenceSourceKind: "external_fetch", PatchAction: "add", SourceObjectClass: "api_symbol", SourceAuthorityID: receipt.SourceAuthorityID, SourceRefKind: "url", SourceStableReference: "api://fixture/source", SourceVersionCoordinate: "v1", SourceSectionPath: "/source", TargetObjectClass: "api_symbol", TargetAuthorityID: receipt.SourceAuthorityID, TargetRefKind: "url", TargetStableReference: "api://fixture/target", TargetVersionCoordinate: "v1", TargetSectionPath: "/target", EdgeLabel: "operation_reads_resource", AuthoringSourcePath: "/relationships/0", EvidenceAuthorityID: receipt.SourceAuthorityID, EvidenceStableReference: receipt.SourceStableReference, EvidenceVersionCoordinate: receipt.VersionCoordinate, EvidenceContentHashAlgorithm: receipt.SourceContentHashAlgorithm, EvidenceContentHashProfile: receipt.SourceContentHashProfile, EvidenceContentHash: receipt.SourceContentHash, EvidenceIdentityHash: apiOOD8String(receipt.EvidenceIdentityHash), EligibleReceiptID: apiOOD8String(receipt.ReceiptID), EligibleReceiptDigest: apiOOD8String(receipt.RedactedTransportEvidenceDigest), SealedCompletenessCertificateHash: apiOOD8String(batch.CompletenessEvidenceDigest()), EvidenceArchiveAuthorityID: apiOOD8String(receipt.EvidenceArchiveAuthorityID), EvidenceArchiveRecordID: apiOOD8String(receipt.EvidenceArchiveRecordID), EvidenceArchiveRecordDigest: apiOOD8String(receipt.EvidenceArchiveRecordDigest), GraphFactLocatorManifestHash: apiOOD8String(l.LocatorHash)}
	r.RelationshipEvidenceHash, err = oodevidence.RelationshipEvidenceDigestV8(r)
	if err != nil {
		t.Fatal(err)
	}
	return r, l
}

func TestOOD8LegacyRoleLocatorProofCannotAuthorizeAPIMaterialization(t *testing.T) {
	body := []byte("canonical archived API evidence")
	receipt, batch := apiOOD8VerifiedBatch(t, body)
	relationship, locator := apiOOD8RelationshipAndLocator(t, body, receipt, batch)
	proof, err := oodevidence.VerifyRelationshipLocatorWithAPIRolesV8(context.Background(), relationship, batch, locator, body, "operation", "resource", apiOOD8FixtureAuthority{}, apiOOD8FixtureAuthority{})
	if err != nil {
		t.Fatalf("real locator proof: %v", err)
	}
	if err := oodevidence.ValidateVerifiedAPIRoleLocatorV8(proof); err == nil {
		t.Fatal("legacy role-only proof lacks independently verified role manifests")
	}
	if proof.SourceAPIElementRole() != "operation" || proof.TargetAPIElementRole() != "resource" {
		t.Fatal("native roles not retained in opaque proof")
	}
	for name, mutate := range map[string]func(*oodevidence.RelationshipV8, *oodproof.GraphFactLocator){
		"role substitution": func(_ *oodevidence.RelationshipV8, l *oodproof.GraphFactLocator) {
			l.EligibleReceiptDigest = apiOOD8Digest("other-receipt")
		},
		"receipt substitution": func(r *oodevidence.RelationshipV8, _ *oodproof.GraphFactLocator) {
			*r.EligibleReceiptID = apiOOD8ID("other-receipt")
		},
		"certificate substitution": func(r *oodevidence.RelationshipV8, _ *oodproof.GraphFactLocator) {
			*r.SealedCompletenessCertificateHash = apiOOD8Digest("other-certificate")
		},
		"cross organization": func(r *oodevidence.RelationshipV8, _ *oodproof.GraphFactLocator) {
			r.OrganizationID = apiOOD8ID("other-org")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, l := apiOOD8RelationshipAndLocator(t, body, receipt, batch)
			mutate(&r, &l)
			if _, err := oodevidence.VerifyRelationshipLocatorWithAPIRolesV8(context.Background(), r, batch, l, body, "operation", "resource", apiOOD8FixtureAuthority{}, apiOOD8FixtureAuthority{}); err == nil {
				t.Fatal("correlated substitution accepted")
			}
		})
	}
}
