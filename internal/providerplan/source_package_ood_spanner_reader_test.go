package providerplan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

type productionSourceOODSpannerProofStub struct{}

func (productionSourceOODSpannerProofStub) VerifyCurrentProviderDocumentationClosure(context.Context, *spanner.ReadOnlyTransaction, oodpublication.CurrentSealedClosure, DocumentationFactoryProductionSourceOODReadRequest, []DocumentationFactoryProductionSourceOODSpannerMembershipRow) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error) {
	return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}, nil
}

func TestProductionSourceOODSpannerReaderRequiresProtectedClientAndProofAuthority(t *testing.T) {
	proof := productionSourceOODSpannerProofStub{}
	for _, tc := range []struct {
		name   string
		client *spanner.Client
		proof  DocumentationFactoryProductionSourceOODSpannerProofAuthority
	}{
		{name: "nil client", proof: proof},
		{name: "nil proof", client: &spanner.Client{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, err := NewDocumentationFactoryProductionSourceOODSpannerReader(tc.client, tc.proof)
			if err == nil || reader != nil || !strings.Contains(err.Error(), "required") {
				t.Fatalf("reader=%v err=%v", reader, err)
			}
		})
	}
}

func TestProductionSourceOODSpannerReaderRejectsUseWithoutBootConfiguration(t *testing.T) {
	reader := DocumentationFactoryProductionSourceOODSpannerReader{}
	_, err := reader.ReadCurrentEligibleProviderEvidenceRows(context.Background(), DocumentationFactoryProductionSourceOODReadRequest{})
	if err == nil || !strings.Contains(err.Error(), "not boot configured") {
		t.Fatalf("unconfigured Spanner reader error=%v", err)
	}
}

// This fixture deliberately goes through the public typed OOD verification
// APIs. It cannot mint a VerifiedBatchV8 or VerifiedClosureV8 directly: both
// proof values have opaque state in oodevidence.
type productionSourceOODFixtureAuthority struct{}

func (productionSourceOODFixtureAuthority) VerifySealedManifestNode(context.Context, oodevidence.ReceiptManifestNode) error {
	return nil
}
func (productionSourceOODFixtureAuthority) AdmittedNoncomponentRoleCounts(context.Context, oodevidence.BatchV8) (map[string]int64, error) {
	return map[string]int64{}, nil
}
func (productionSourceOODFixtureAuthority) ResolveCanonicalComponentManifest(context.Context, oodevidence.BatchV8) ([]oodevidence.ComponentManifestTuple, error) {
	return nil, nil
}
func (productionSourceOODFixtureAuthority) VerifyCompleteManifestClosure(context.Context, oodevidence.ClosureCertificateV8) error {
	return nil
}
func (productionSourceOODFixtureAuthority) VerifyClosureAttestation(context.Context, oodevidence.ClosureCertificateV8) error {
	return nil
}

func productionSourceOODDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
func productionSourceOODID() string { return uuid.NewString() }

func productionSourceOODReceipt() oodevidence.ReceiptV8 {
	now := time.Unix(1, 0).UTC()
	ordinal := int64(0)
	return oodevidence.ReceiptV8{OrganizationID: productionSourceOODID(), ReceiptID: productionSourceOODID(), FetchBatchID: "batch", ReceiptRoles: []string{"completeness_evidence", "component"}, FetchComponentOrdinal: &ordinal, FetchOccurrenceID: "occurrence", EvidenceIdentityHash: productionSourceOODDigest("identity"), GraphObjectID: productionSourceOODID(), ObjectClass: "object", SourceAuthorityID: productionSourceOODID(), SourceAuthorityBindingID: productionSourceOODID(), SourceAuthorityBindingDigest: productionSourceOODDigest("binding"), SourceRefKind: "url", SourceStableReference: "https://example.test/doc", SourceRepresentationKind: "api", EvidenceContentClass: "docs", RepresentationDeclarationID: productionSourceOODID(), RepresentationDeclarationDigest: productionSourceOODDigest("representation"), VersionCoordinate: "v1", SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: "canonical", SourceContentHash: productionSourceOODDigest("body"), ExternalFetchProfileRef: "profile/v1", ExternalFetchProfileDigest: productionSourceOODDigest("fetch-profile"), PermissionGrantID: productionSourceOODID(), PermissionGrantDigest: productionSourceOODDigest("grant"), PermissionAuthorityID: productionSourceOODID(), PermissionPrincipalID: productionSourceOODID(), PermissionScopeDigest: productionSourceOODDigest("scope"), PermissionOperation: "read", PermissionMethod: "GET", PermissionRedirectPolicyDigest: productionSourceOODDigest("redirect"), PermissionContentClass: "docs", PermissionTrustClass: "official", PermissionByteCeiling: 100, PermissionDepthCeiling: 1, PermissionEffectiveAt: now, PermissionStatus: "affirmative", PermissionPolicyVersionRef: "policy/v1", PermissionPolicyVersionDigest: productionSourceOODDigest("policy"), FetchAuthorizationDecisionRef: "decision/v1", FetchAuthorizationDecisionDigest: productionSourceOODDigest("decision"), ObservedAt: now, TransportStatus: "success", TransportRawContentHashAlgorithm: "sha256", TransportRawContentHash: productionSourceOODDigest("raw"), TransportRawByteCount: 4, TransportDecodedByteCount: 4, TransportResponseMetadataDigest: productionSourceOODDigest("metadata"), EvidenceArchiveAuthorityID: productionSourceOODID(), EvidenceArchiveRecordID: productionSourceOODID(), EvidenceArchiveRecordDigest: productionSourceOODDigest("archive"), EvidenceArchiveByteCount: 4, EvidenceArchiveDeletionDomainID: productionSourceOODID(), EvidenceArchiveCryptoShredDomainID: productionSourceOODID(), ReceiptDeletionDomainID: productionSourceOODID(), ReceiptCryptoShredDomainID: productionSourceOODID()}
}

func TestProductionSourceOODFixtureUsesOpaqueBatchAndClosureProofAPIs(t *testing.T) {
	r := productionSourceOODReceipt()
	rawReceipt, err := oodevidence.ReceiptDigestV8(r)
	if err != nil {
		t.Fatal(err)
	}
	r.RedactedTransportEvidenceDigest = rawReceipt
	b := oodevidence.BatchV8{OrganizationID: r.OrganizationID, FetchBatchID: r.FetchBatchID, SourceAuthorityBindingID: r.SourceAuthorityBindingID, SourceAuthorityBindingDigest: r.SourceAuthorityBindingDigest, RepresentationDeclarationID: r.RepresentationDeclarationID, RepresentationDeclarationDigest: r.RepresentationDeclarationDigest, BatchReceiptManifestRootHash: productionSourceOODDigest("receipt-manifest"), TotalReceiptCount: 1, ComponentReceiptCount: 1, CompletenessEvidenceReceiptCount: 1, ExpectedComponentCount: ptrInt64(1), CompletenessBasisKind: "source_declared_total", CompletenessEvidenceRef: "https://example.test/doc", CompletenessEvidenceIdentityHash: r.EvidenceIdentityHash, CompletenessEvidenceContentHashAlgorithm: r.SourceContentHashAlgorithm, CompletenessEvidenceContentHashProfile: r.SourceContentHashProfile, CompletenessEvidenceContentHash: r.SourceContentHash, CompletenessEvidenceReceiptID: r.ReceiptID, CompletenessEvidenceArchiveAuthorityID: r.EvidenceArchiveAuthorityID, CompletenessEvidenceArchiveRecordID: r.EvidenceArchiveRecordID, CompletenessEvidenceArchiveRecordDigest: r.EvidenceArchiveRecordDigest, CompletenessEvidenceSelectorKind: "whole_evidence_body", CompletenessEvidenceSelectorValue: "$", VerifiedCompletenessClaimDigest: productionSourceOODDigest("claim"), CompletenessProfileRef: "profile/v1", CompletenessProfileDigest: productionSourceOODDigest("profile"), SealedAt: time.Unix(2, 0).UTC()}
	var errDigest error
	b.CompletenessEvidenceDigest, errDigest = oodevidence.CompletenessEvidenceDigestV8(b)
	if errDigest != nil {
		t.Fatal(errDigest)
	}
	batch, err := oodevidence.VerifyBatchV8(context.Background(), b, []oodevidence.ReceiptV8{r}, oodevidence.ReceiptManifestNode{NodeHash: b.BatchReceiptManifestRootHash, OrganizationID: r.OrganizationID, ManifestKind: "fetch_batch_receipt", NodeKind: "leaf", Sealed: true, EntryCount: 1, TransitiveMemberCount: 1, Members: []oodevidence.ReceiptManifestMember{{ReceiptID: r.ReceiptID, MemberHash: rawReceipt}}}, productionSourceOODFixtureAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	if err := oodevidence.ValidateVerifiedBatchV8(batch); err != nil {
		t.Fatal(err)
	}
	roots := map[string]oodevidence.ClosureRoot{}
	for _, name := range []string{"source", "object", "symbol", "edge", "api_property", "graph_fact_locator", "receipt", "structural_projection", "violation"} {
		roots[name] = oodevidence.ClosureRoot{Hash: productionSourceOODDigest(name), Count: 0}
	}
	roots["receipt"] = oodevidence.ClosureRoot{Hash: productionSourceOODDigest("receipt-root"), Count: 1}
	c := oodevidence.ClosureCertificateV8{OrganizationID: r.OrganizationID, MaterializationRunID: productionSourceOODID(), SnapshotKind: "provider_documentation", SourceSetHash: productionSourceOODDigest("source-set"), Roots: roots, SourceArtifactCount: 0, RelationshipEvidenceCount: 0, RelationshipIdentitySetHash: productionSourceOODDigest("relationships"), SourceAuthorityIdentitySetHash: productionSourceOODDigest("authorities"), CompletenessIdentitySetHash: productionSourceOODDigest("complete"), PermissionPolicyIdentitySetHash: productionSourceOODDigest("permission"), ArchiveBindingIdentitySetHash: productionSourceOODDigest("archive-bindings"), ProfileIdentitySetHash: productionSourceOODDigest("profiles"), ExternalSourceReceiptEligibilitySetHash: productionSourceOODDigest("eligible"), MaterializationProfileID: productionSourceOODID(), MaterializationProfileVersion: "v1", MaterializationProfileDigest: productionSourceOODDigest("materialization"), PublicationBudgetProfileRef: "budget/v1", PublicationBudgetProfileDigest: productionSourceOODDigest("budget"), ManifestHashAlgorithm: "sha256", ManifestHashProfile: "manifest", ManifestHashContractDigest: productionSourceOODDigest("manifest-contract"), ClosureHashAlgorithm: "sha256", ClosureHashProfile: "closure", ClosureHashContractDigest: productionSourceOODDigest("closure-contract"), VerifierCapabilityName: "verifier", VerifierCapabilityVersion: "v1", VerifierCapabilityDigest: productionSourceOODDigest("verifier"), VerificationPolicyRef: "policy/v1", VerificationPolicyDigest: productionSourceOODDigest("verify-policy"), VerificationCertificateID: productionSourceOODID(), AttestationAuthorityID: productionSourceOODID(), AttestationRef: "attestation/v1", AttestationDigest: productionSourceOODDigest("attestation"), AttestationProfile: "profile/v1"}
	c.ClosureHash, err = oodevidence.ClosureHashV8(c)
	if err != nil {
		t.Fatal(err)
	}
	c.VerificationCertificateHash, err = oodevidence.CertificateHashV8(c)
	if err != nil {
		t.Fatal(err)
	}
	closure, err := oodevidence.VerifyClosureV8(context.Background(), c, productionSourceOODFixtureAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	if err := oodevidence.ValidateVerifiedClosureV8(closure); err != nil {
		t.Fatal(err)
	}
}

func ptrInt64(v int64) *int64 { return &v }
