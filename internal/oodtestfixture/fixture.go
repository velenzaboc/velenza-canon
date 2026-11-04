// Package oodtestfixture contains shared test support. It must only be imported by test files.
package oodtestfixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodproof"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"strings"
	"testing"
	"time"
)

type Fixture struct {
	Certificate           oodevidence.ClosureCertificateV8
	Closure               oodpublication.ManifestClosureInput
	Proof                 oodevidence.VerifiedClosureV8
	ImmutableRows         []oodpublication.SpannerRow
	Snapshot, Run, Head   oodpublication.SpannerRow
	PropertySchema        oodpublication.AdmittedAPIPropertyPayloadSchema
	LocatorProofs         []oodevidence.VerifiedLocatorV8
	EvidenceLocatorProofs []oodevidence.VerifiedGraphFactLocatorV8
	Plan                  oodpublication.SpannerWritePlan
	Attestor              oodpublication.ClosureAttestor
	Receipt               oodevidence.ReceiptV8
	Batch                 oodevidence.VerifiedBatchV8
	Relationship          oodevidence.RelationshipV8
	Locator               oodproof.GraphFactLocator
}

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

func (a apiOOD8FixtureAuthority) VerifyNativeAPIElementRoleManifests(ctx context.Context, r oodevidence.RelationshipV8, batch oodevidence.VerifiedBatchV8, locator oodproof.GraphFactLocator, source, target oodevidence.APIElementRoleBinding) error {
	// This fixture's single canonical evidence range independently establishes
	// both endpoint roles and their relationship. Equal hashes are intentional;
	// each purpose is explicitly bound by this test-owned authority.
	if r.GraphFactLocatorManifestHash == nil || source.LocatorManifestHash != *r.GraphFactLocatorManifestHash || target.LocatorManifestHash != *r.GraphFactLocatorManifestHash {
		return errors.New("fixture role manifest binding mismatch")
	}
	return a.VerifyNativeAPIElementRoles(ctx, r, batch, locator, source.Role, target.Role)
}

func apiOOD8RoleManifestProof(ctx context.Context, r oodevidence.RelationshipV8, batch oodevidence.VerifiedBatchV8, locator oodproof.GraphFactLocator, body []byte) (oodevidence.VerifiedLocatorV8, error) {
	if r.GraphFactLocatorManifestHash == nil {
		return oodevidence.VerifiedLocatorV8{}, errors.New("fixture role manifest absent")
	}
	return oodevidence.VerifyRelationshipLocatorWithAPIRoleManifestsV8(ctx, r, batch, locator, body, oodevidence.APIElementRoleBinding{Role: "operation", LocatorManifestHash: *r.GraphFactLocatorManifestHash}, oodevidence.APIElementRoleBinding{Role: "resource", LocatorManifestHash: *r.GraphFactLocatorManifestHash}, apiOOD8FixtureAuthority{}, apiOOD8FixtureAuthority{})
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
	return apiOOD8ReceiptForEvidence(body, apiOOD8Digest("identity"))
}

// apiOOD8ReceiptForEvidence retains the fixture's complete physical shape
// while allowing an integration test to bind it to a compiler-measured source
// evidence identity. It is test support only; all receipt, batch, manifest
// and closure values are subsequently recomputed and verified normally.
func apiOOD8ReceiptForEvidence(body []byte, evidenceIdentityHash string) oodevidence.ReceiptV8 {
	return apiOOD8ReceiptForEvidenceCoordinate(body, evidenceIdentityHash, "one")
}

func apiOOD8ReceiptForEvidenceCoordinate(body []byte, evidenceIdentityHash, coordinate string) oodevidence.ReceiptV8 {
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	ordinal := int64(0)
	bodyDigest := sha256.Sum256(body)
	return oodevidence.ReceiptV8{
		OrganizationID: apiOOD8ID("org"), ReceiptID: apiOOD8ID("receipt/" + coordinate), FetchBatchID: "batch-" + coordinate,
		ReceiptRoles: []string{"completeness_evidence", "component"}, FetchComponentOrdinal: &ordinal, FetchOccurrenceID: "occurrence-" + coordinate,
		EvidenceIdentityHash: evidenceIdentityHash, GraphObjectID: apiOOD8ID("graph-object"), ObjectClass: "api_symbol",
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
	return apiOOD8VerifiedBatchForEvidence(t, body, apiOOD8Digest("identity"))
}

func apiOOD8VerifiedBatchForEvidence(t *testing.T, body []byte, evidenceIdentityHash string) (oodevidence.ReceiptV8, oodevidence.VerifiedBatchV8) {
	return apiOOD8VerifiedBatchForEvidenceCoordinate(t, body, evidenceIdentityHash, "one")
}

func apiOOD8VerifiedBatchForEvidenceCoordinate(t *testing.T, body []byte, evidenceIdentityHash, coordinate string, sourceReference ...string) (oodevidence.ReceiptV8, oodevidence.VerifiedBatchV8) {
	t.Helper()
	r := apiOOD8ReceiptForEvidenceCoordinate(body, evidenceIdentityHash, coordinate)
	if len(sourceReference) > 0 {
		r.SourceStableReference = sourceReference[0]
	}
	digest, err := oodevidence.ReceiptDigestV8(r)
	if err != nil {
		t.Fatal(err)
	}
	r.RedactedTransportEvidenceDigest = digest
	manifest, err := apiOOD8BatchReceiptManifest(r)
	if err != nil {
		t.Fatal(err)
	}
	b := oodevidence.BatchV8{OrganizationID: r.OrganizationID, FetchBatchID: r.FetchBatchID, SourceAuthorityBindingID: r.SourceAuthorityBindingID, SourceAuthorityBindingDigest: r.SourceAuthorityBindingDigest, RepresentationDeclarationID: r.RepresentationDeclarationID, RepresentationDeclarationDigest: r.RepresentationDeclarationDigest, BatchReceiptManifestRootHash: manifest.NodeHash, TotalReceiptCount: 1, ComponentReceiptCount: 1, CompletenessEvidenceReceiptCount: 1, ExpectedComponentCount: apiOOD8I64(1), CompletenessBasisKind: "source_declared_total", CompletenessEvidenceRef: r.SourceStableReference, CompletenessEvidenceIdentityHash: r.EvidenceIdentityHash, CompletenessEvidenceContentHashAlgorithm: r.SourceContentHashAlgorithm, CompletenessEvidenceContentHashProfile: r.SourceContentHashProfile, CompletenessEvidenceContentHash: r.SourceContentHash, CompletenessEvidenceReceiptID: r.ReceiptID, CompletenessEvidenceArchiveAuthorityID: r.EvidenceArchiveAuthorityID, CompletenessEvidenceArchiveRecordID: r.EvidenceArchiveRecordID, CompletenessEvidenceArchiveRecordDigest: r.EvidenceArchiveRecordDigest, CompletenessEvidenceSelectorKind: "whole_evidence_body", CompletenessEvidenceSelectorValue: "$", VerifiedCompletenessClaimDigest: apiOOD8Digest("claim"), CompletenessProfileRef: "profile/v1", CompletenessProfileDigest: apiOOD8Digest("profile"), SealedAt: time.Date(2026, 11, 2, 12, 1, 0, 0, time.UTC)}
	b.CompletenessEvidenceDigest, err = oodevidence.CompletenessEvidenceDigestV8(b)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := oodevidence.VerifyBatchV8(context.Background(), b, []oodevidence.ReceiptV8{r}, manifest, apiOOD8FixtureAuthority{})
	if err != nil {
		t.Fatal(err)
	}
	return r, batch
}

func apiOOD8BatchReceiptManifest(r oodevidence.ReceiptV8) (oodevidence.ReceiptManifestNode, error) {
	member := &oodevidence.ReceiptManifestMember{EntryOrdinal: 0, ReceiptID: r.ReceiptID, MemberHash: r.RedactedTransportEvidenceDigest}
	d, err := oodcanon.DigestHex(member.MemberHash)
	if err != nil {
		return oodevidence.ReceiptManifestNode{}, err
	}
	fields := []oodcanon.NamedValue{{Name: "entry_ordinal", Value: oodcanon.I64(0)}, {Name: "entry_kind", Value: oodcanon.String("receipt")}, {Name: "member_id", Value: oodcanon.String(member.ReceiptID)}, {Name: "member_hash", Value: d}, {Name: "child_manifest_node_hash", Value: oodcanon.NullValue(oodcanon.SHA256)}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(0)}}
	b, err := oodcanon.EncodeNestedRecord(oodcanon.ManifestLeafV1().Fields[7].Element.Nested, fields)
	if err != nil {
		return oodevidence.ReceiptManifestNode{}, err
	}
	entry := oodevidence.ReceiptManifestEntry{EntryOrdinal: 0, CanonicalEntryByteCount: int64(len(b)), Member: member}
	value := oodcanon.Value{Type: oodcanon.Record, Presence: oodcanon.Present, Fields: append([]oodcanon.NamedValue(nil), fields...)}
	value.Fields[len(value.Fields)-1].Value = oodcanon.I64(entry.CanonicalEntryByteCount)
	record := oodcanon.RecordValue{"manifest_kind": oodcanon.String("fetch_batch_receipt"), "entry_count": oodcanon.I64(1), "transitive_member_count": oodcanon.I64(1), "canonical_byte_count": oodcanon.I64(0), "ordered_entry_tuples": oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present, Elements: []oodcanon.Value{value}}}
	nb, err := oodcanon.Encode(oodcanon.ManifestLeafV1(), record)
	if err != nil {
		return oodevidence.ReceiptManifestNode{}, err
	}
	manifest := oodevidence.ReceiptManifestNode{OrganizationID: r.OrganizationID, ManifestKind: "fetch_batch_receipt", NodeKind: "leaf", NodeLevel: 0, Sealed: true, EntryCount: 1, TransitiveMemberCount: 1, CanonicalByteCount: int64(len(nb)), Entries: []oodevidence.ReceiptManifestEntry{entry}}
	manifest.NodeHash, err = oodEvidenceReceiptManifestHash(manifest)
	return manifest, err
}

func oodEvidenceReceiptManifestHash(n oodevidence.ReceiptManifestNode) (string, error) {
	return oodevidence.ReceiptManifestNodeHashV8(n)
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

type apiOOD8ClosureAttestor struct{}

func (apiOOD8ClosureAttestor) VerifyClosureAttestation(context.Context, oodevidence.ClosureCertificateV8) error {
	return nil
}

type apiOOD8PropertySchemas struct {
	schema oodpublication.AdmittedAPIPropertyPayloadSchema
}

func (x apiOOD8PropertySchemas) ResolveAPIPropertyPayloadSchema(_ context.Context, id, version, digest, profile string) (oodpublication.AdmittedAPIPropertyPayloadSchema, error) {
	if x.schema.ArtifactID != id || x.schema.Version != version || x.schema.Digest != digest || x.schema.Profile != profile {
		return oodpublication.AdmittedAPIPropertyPayloadSchema{}, fmt.Errorf("fixture property schema coordinate mismatch")
	}
	return x.schema, nil
}

// Build constructs a complete fixture through the real closure and evidence verifiers.
func Build(ctx context.Context, t *testing.T) Fixture {
	return BuildForEvidence(ctx, t, []byte("canonical archived API evidence"), apiOOD8Digest("identity"))
}

// BuildForEvidence creates the same full nine-root fixture as Build, but
// binds it to the exact archived evidence bytes and identity selected by an
// integration test's protected compiler. No prior physical rows, manifests or
// opaque proofs are reused across the changed evidence.
func BuildForEvidence(ctx context.Context, t *testing.T, body []byte, evidenceIdentityHash string) Fixture {
	return BuildForEvidenceSet(ctx, t, [][]byte{body}, []string{evidenceIdentityHash})
}

// BuildForEvidenceSet constructs one full closure around an exact compiler
// evidence roster. Each body is independently receipt/batch verified before
// its physical rows are admitted to the rebuilt source and receipt roots.
func BuildForEvidenceSet(ctx context.Context, t *testing.T, bodies [][]byte, evidenceIdentityHashes []string) Fixture {
	refs := make([]string, len(bodies))
	for i := range refs {
		refs[i] = "https://example.test/api"
	}
	return BuildForEvidenceSetWithReferences(ctx, t, bodies, evidenceIdentityHashes, refs)
}

// BuildForEvidenceSetWithReferences additionally binds each receipt to the
// exact stable source reference retained by the sealed compiler locator.
func BuildForEvidenceSetWithReferences(ctx context.Context, t *testing.T, bodies [][]byte, evidenceIdentityHashes, sourceReferences []string) Fixture {
	t.Helper()
	if len(bodies) == 0 || len(bodies) != len(evidenceIdentityHashes) || len(bodies) != len(sourceReferences) {
		t.Fatal("fixture evidence roster is incomplete")
	}
	receipts := make([]oodevidence.ReceiptV8, len(bodies))
	batches := make([]oodevidence.VerifiedBatchV8, len(bodies))
	for i := range bodies {
		if len(bodies[i]) == 0 || len(evidenceIdentityHashes[i]) != 64 {
			t.Fatal("fixture evidence body or identity hash is incomplete")
		}
		receipt, batch := apiOOD8VerifiedBatchForEvidenceCoordinate(t, bodies[i], evidenceIdentityHashes[i], fmt.Sprintf("%d", i), sourceReferences[i])
		receipts[i], batches[i] = receipt, batch
	}
	receipt, batch, body := receipts[0], batches[0], bodies[0]
	rel, locator := apiOOD8RelationshipAndLocator(t, body, receipt, batch)
	locatorProof, err := apiOOD8RoleManifestProof(context.Background(), rel, batch, locator, body)
	if err != nil {
		t.Fatal(err)
	}
	org := receipt.OrganizationID
	// These are the exact proof-chain values: no parallel receipt/batch is
	// permitted to enter the virtual source artifact or locator roster.
	rrs := make([]oodpublication.SpannerRow, len(receipts))
	brs := make([]oodpublication.SpannerRow, len(batches))
	for i := range receipts {
		rrs[i] = apiOOD8PhysicalReceipt(t, receipts[i])
		brs[i] = apiOOD8PhysicalBatch(t, receipts[i], batches[i])
	}
	rr, br := rrs[0], brs[0]
	// The locator cites the source member actually derived from these exact
	// closure evidence rows; a convenient fixture digest is not admissible.
	sourceMember, e := oodpublication.SourceArtifactExternalEvidenceDigest([]oodpublication.SpannerRow{rr, br})
	if e != nil {
		t.Fatal(e)
	}
	locator.SourceArtifactMemberHash = sourceMember
	locator.LocatorHash, e = locator.ComputedHash()
	if e != nil {
		t.Fatal(e)
	}

	// Graph rows are made complete before their owner hashes are recomputed.
	objA := apiOOD8GraphRow(t, "OODGraphObjects", org)
	objB := apiOOD8GraphRow(t, "OODGraphObjects", org)
	objA.Columns["graph_object_id"], objB.Columns["graph_object_id"] = apiOOD8ID("operation"), apiOOD8ID("resource")
	objA.Columns["object_class"], objB.Columns["object_class"] = "api_symbol", "api_symbol"
	objA.Columns["api_element_role"], objB.Columns["api_element_role"] = "operation", "resource"
	objA.Columns["api_element_role_locator_manifest_hash"], objB.Columns["api_element_role_locator_manifest_hash"] = locator.LocatorHash, locator.LocatorHash
	objA.Columns["source_stable_reference"], objB.Columns["source_stable_reference"] = rel.SourceStableReference, rel.TargetStableReference
	objA.Columns["source_authority_id"], objA.Columns["source_ref_kind"], objA.Columns["version_coordinate"], objA.Columns["section_path"] = rel.SourceAuthorityID, rel.SourceRefKind, rel.SourceVersionCoordinate, rel.SourceSectionPath
	objB.Columns["source_authority_id"], objB.Columns["source_ref_kind"], objB.Columns["version_coordinate"], objB.Columns["section_path"] = rel.TargetAuthorityID, rel.TargetRefKind, rel.TargetVersionCoordinate, rel.TargetSectionPath
	// The physical API symbols must retain the exact archived content tuple
	// of the locator admitted by their role manifest; a placeholder fixture
	// digest cannot stand in for the sealed receipt evidence.
	objA.Columns["source_content_hash_algorithm"], objA.Columns["source_content_hash_profile"], objA.Columns["source_content_hash"] = locator.SourceContentHashAlgorithm, locator.SourceContentHashProfile, locator.SourceContentHash
	objB.Columns["source_content_hash_algorithm"], objB.Columns["source_content_hash_profile"], objB.Columns["source_content_hash"] = locator.SourceContentHashAlgorithm, locator.SourceContentHashProfile, locator.SourceContentHash
	for _, r := range []*oodpublication.SpannerRow{&objA, &objB} {
		h, e := oodpublication.CanonicalMemberDigestFromPhysicalRow(*r)
		if e != nil {
			t.Fatal(e)
		}
		r.Columns["graph_row_hash"] = h
	}
	edge := apiOOD8GraphRow(t, "OODGraphEdges", org)
	edge.Columns["source_endpoint_id"], edge.Columns["target_endpoint_id"] = objA.Columns["graph_object_id"], objB.Columns["graph_object_id"]
	edge.Columns["source_endpoint_class"], edge.Columns["target_endpoint_class"] = objA.Columns["object_class"], objB.Columns["object_class"]
	edge.Columns["edge_family"], edge.Columns["edge_label"] = "api_relationship", rel.EdgeLabel
	edge.Columns["authoring_source_path"], edge.Columns["source_authority_id"], edge.Columns["source_stable_reference"] = rel.AuthoringSourcePath, rel.EvidenceAuthorityID, rel.EvidenceStableReference
	edge.Columns["source_content_hash_algorithm"], edge.Columns["source_content_hash_profile"], edge.Columns["source_content_hash"] = rel.EvidenceContentHashAlgorithm, rel.EvidenceContentHashProfile, rel.EvidenceContentHash
	eh, err := oodpublication.CanonicalMemberDigestFromPhysicalRow(edge)
	if err != nil {
		t.Fatal(err)
	}
	edge.Columns["graph_row_hash"] = eh

	locrow := apiOOD8FullRow(t, "OODGraphGraphFactEvidenceLocators", org)
	apiOOD8CopyLocator(locrow.Columns, locator)
	locrow.Columns["graph_fact_locator_hash"] = locator.LocatorHash
	claimManifest, err := oodpublication.BuildNativeLocatorManifest(oodpublication.NativeLocatorManifestInput{OrganizationID: org, Locators: []oodpublication.SpannerRow{locrow}, CreatedAt: time.Date(2026, 11, 2, 12, 2, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	// Documentation provenance is a distinct external-reference lane.  It has
	// its own exact locator range and two-member claim root; it must never be
	// silently represented by the API role's locator root.
	docLocator := locator
	docLocator.ByteStartOffset, docLocator.ByteEndOffsetExclusive = 0, 1
	docLocator.SelectedRangeByteCount = 1
	docSelected := sha256.Sum256(body[:1])
	docLocator.SelectedRangeContentHash = hex.EncodeToString(docSelected[:])
	docLocator.CanonicalRepresentationProfileRef = "canonical/documentation/v1"
	docLocator.CanonicalRepresentationProfileDigest = apiOOD8Digest("canonical-documentation-profile")
	docLocator.LocatorHash, err = docLocator.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	doclocrow := apiOOD8FullRow(t, "OODGraphGraphFactEvidenceLocators", org)
	apiOOD8CopyLocator(doclocrow.Columns, docLocator)
	doclocrow.Columns["graph_fact_locator_hash"] = docLocator.LocatorHash
	docLocatorDigest, err := oodpublication.CanonicalMemberDigestFromPhysicalRow(doclocrow)
	if err != nil {
		t.Fatal(err)
	}
	docNode, docNodeRow, docEntryRows := apiOOD8ManifestNode(t, org, "graph_fact_locator", []oodpublication.ManifestMemberV8{{ManifestKind: "graph_fact_locator", EntryKind: "graph_fact_locator", MemberID: docLocator.LocatorHash, ClaimedHash: docLocatorDigest, Row: &doclocrow}})
	*rel.GraphFactLocatorManifestHash = claimManifest.RootHash
	rel.RelationshipEvidenceHash, e = oodevidence.RelationshipEvidenceDigestV8(rel)
	if e != nil {
		t.Fatal(e)
	}
	objA.Columns["api_element_role_locator_manifest_hash"], objB.Columns["api_element_role_locator_manifest_hash"] = claimManifest.RootHash, claimManifest.RootHash
	for _, r := range []*oodpublication.SpannerRow{&objA, &objB} {
		h, e := oodpublication.CanonicalMemberDigestFromPhysicalRow(*r)
		if e != nil {
			t.Fatal(e)
		}
		r.Columns["graph_row_hash"] = h
	}
	edge.Columns["source_endpoint_id"], edge.Columns["target_endpoint_id"] = objA.Columns["graph_object_id"], objB.Columns["graph_object_id"]
	eh, err = oodpublication.CanonicalMemberDigestFromPhysicalRow(edge)
	if err != nil {
		t.Fatal(err)
	}
	edge.Columns["graph_row_hash"] = eh
	locatorProof, e = apiOOD8RoleManifestProof(context.Background(), rel, batch, locator, body)
	if e != nil {
		t.Fatal(e)
	}
	relrow := apiOOD8PhysicalRelationship(t, rel)
	doc := apiOOD8GraphRow(t, "OODGraphObjects", org)
	doc.Columns["graph_object_id"], doc.Columns["object_class"] = apiOOD8ID("documentation"), "external_reference_doc"
	doc.Columns["api_element_role"], doc.Columns["api_element_role_locator_manifest_hash"] = nil, nil
	doc.Columns["source_authority_id"], doc.Columns["source_ref_kind"], doc.Columns["source_stable_reference"], doc.Columns["version_coordinate"], doc.Columns["section_path"], doc.Columns["graph_address"] = receipt.SourceAuthorityID, receipt.SourceRefKind, receipt.SourceStableReference, receipt.VersionCoordinate, "/documentation", "documentation://fixture"
	doc.Columns["source_content_hash_algorithm"], doc.Columns["source_content_hash_profile"], doc.Columns["source_content_hash"] = docLocator.SourceContentHashAlgorithm, docLocator.SourceContentHashProfile, docLocator.SourceContentHash
	dh, err := oodpublication.CanonicalMemberDigestFromPhysicalRow(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.Columns["graph_row_hash"] = dh
	docEdge := apiOOD8GraphRow(t, "OODGraphEdges", org)
	docEdge.Columns["graph_edge_id"] = apiOOD8ID("documents-edge")
	docEdge.Columns["source_endpoint_kind"], docEdge.Columns["source_endpoint_id"], docEdge.Columns["source_endpoint_class"] = "graph_object", doc.Columns["graph_object_id"], doc.Columns["object_class"]
	docEdge.Columns["target_endpoint_kind"], docEdge.Columns["target_endpoint_id"], docEdge.Columns["target_endpoint_class"] = "graph_object", objA.Columns["graph_object_id"], "api_symbol"
	docEdge.Columns["edge_label"], docEdge.Columns["edge_family"], docEdge.Columns["authoring_source_path"] = "documents", "external_reference", "documentation/operation"
	docEdge.Columns["source_authority_id"], docEdge.Columns["source_stable_reference"] = receipt.SourceAuthorityID, receipt.SourceStableReference
	docEdge.Columns["source_content_hash_algorithm"], docEdge.Columns["source_content_hash_profile"], docEdge.Columns["source_content_hash"] = docLocator.SourceContentHashAlgorithm, docLocator.SourceContentHashProfile, docLocator.SourceContentHash
	docEdgeHash, err := oodpublication.CanonicalMemberDigestFromPhysicalRow(docEdge)
	if err != nil {
		t.Fatal(err)
	}
	docEdge.Columns["graph_row_hash"] = docEdgeHash
	docEvidence := apiOOD8FullRow(t, "OODGraphRelationshipEvidence", org)
	docEvidence.Columns["evidence_source_kind"], docEvidence.Columns["patch_action"], docEvidence.Columns["source_object_class"] = "external_document_evidence", "add", "external_reference_doc"
	docEvidence.Columns["source_authority_id"], docEvidence.Columns["source_ref_kind"], docEvidence.Columns["source_stable_reference"], docEvidence.Columns["source_version_coordinate"], docEvidence.Columns["source_section_path"] = receipt.SourceAuthorityID, receipt.SourceRefKind, receipt.SourceStableReference, receipt.VersionCoordinate, "/documentation"
	docEvidence.Columns["target_object_class"], docEvidence.Columns["target_authority_id"], docEvidence.Columns["target_ref_kind"], docEvidence.Columns["target_stable_reference"], docEvidence.Columns["target_version_coordinate"], docEvidence.Columns["target_section_path"] = "api_symbol", objA.Columns["source_authority_id"], objA.Columns["source_ref_kind"], objA.Columns["source_stable_reference"], objA.Columns["version_coordinate"], objA.Columns["section_path"]
	docEvidence.Columns["edge_label"], docEvidence.Columns["authoring_source_path"] = "documents", "documentation/operation"
	docEvidence.Columns["evidence_authority_id"], docEvidence.Columns["evidence_stable_reference"], docEvidence.Columns["evidence_version_coordinate"] = receipt.SourceAuthorityID, receipt.SourceStableReference, receipt.VersionCoordinate
	docEvidence.Columns["evidence_content_hash_algorithm"], docEvidence.Columns["evidence_content_hash_profile"], docEvidence.Columns["evidence_content_hash"] = docLocator.SourceContentHashAlgorithm, docLocator.SourceContentHashProfile, docLocator.SourceContentHash
	docEvidence.Columns["evidence_identity_hash"], docEvidence.Columns["eligible_receipt_id"], docEvidence.Columns["eligible_receipt_digest"], docEvidence.Columns["sealed_completeness_certificate_hash"] = receipt.EvidenceIdentityHash, receipt.ReceiptID, receipt.RedactedTransportEvidenceDigest, batch.CompletenessEvidenceDigest()
	docEvidence.Columns["evidence_archive_authority_id"], docEvidence.Columns["evidence_archive_record_id"], docEvidence.Columns["evidence_archive_record_digest"], docEvidence.Columns["graph_fact_locator_manifest_hash"] = receipt.EvidenceArchiveAuthorityID, receipt.EvidenceArchiveRecordID, receipt.EvidenceArchiveRecordDigest, docNode.Hash
	docEvidenceHash, err := oodpublication.CanonicalMemberDigestFromPhysicalRow(docEvidence)
	if err != nil {
		t.Fatal(err)
	}
	docEvidence.Columns["relationship_evidence_hash"] = docEvidenceHash
	cloneGraphRow := func(row oodpublication.SpannerRow) oodpublication.SpannerRow {
		copy := row
		copy.Columns = make(map[string]interface{}, len(row.Columns))
		for key, value := range row.Columns {
			copy.Columns[key] = value
		}
		return copy
	}
	// Both typed API symbols require a documents relation. The one immutable
	// reference document is intentionally reused only because its source tuple
	// and physical bytes are identical for both claims.
	docEdgeB := cloneGraphRow(docEdge)
	docEdgeB.Columns["graph_edge_id"], docEdgeB.Columns["target_endpoint_id"], docEdgeB.Columns["authoring_source_path"], docEdgeB.Columns["graph_row_hash"] = apiOOD8ID("documents-resource-edge"), objB.Columns["graph_object_id"], "documentation/resource", apiOOD8Digest("documents-resource-edge/pending")
	docEdgeBHash, err := oodpublication.CanonicalMemberDigestFromPhysicalRow(docEdgeB)
	if err != nil {
		t.Fatal(err)
	}
	docEdgeB.Columns["graph_row_hash"] = docEdgeBHash
	docEvidenceB := cloneGraphRow(docEvidence)
	docEvidenceB.Columns["target_authority_id"], docEvidenceB.Columns["target_ref_kind"], docEvidenceB.Columns["target_stable_reference"], docEvidenceB.Columns["target_version_coordinate"], docEvidenceB.Columns["target_section_path"] = objB.Columns["source_authority_id"], objB.Columns["source_ref_kind"], objB.Columns["source_stable_reference"], objB.Columns["version_coordinate"], objB.Columns["section_path"]
	docEvidenceB.Columns["authoring_source_path"], docEvidenceB.Columns["relationship_evidence_hash"] = "documentation/resource", apiOOD8Digest("documents-resource-evidence/pending")
	docEvidenceBHash, err := oodpublication.CanonicalMemberDigestFromPhysicalRow(docEvidenceB)
	if err != nil {
		t.Fatal(err)
	}
	docEvidenceB.Columns["relationship_evidence_hash"] = docEvidenceBHash
	schema := oodpublication.AdmittedAPIPropertyPayloadSchema{ArtifactID: apiOOD8ID("property-schema"), Version: "v1", Digest: apiOOD8Digest("property-schema"), Profile: "fixture_api_property_v1", Fields: []oodpublication.APIPropertyPayloadField{{Name: "name", Type: oodcanon.UTF8}}}
	prop := apiOOD8FullRow(t, "OODGraphAPIPropertyFacts", org)
	prop.Columns["graph_object_id"], prop.Columns["graph_edge_id"] = objA.Columns["graph_object_id"], nil
	prop.Columns["subject_kind"], prop.Columns["subject_graph_row_hash"], prop.Columns["property_family"] = "object", objA.Columns["graph_row_hash"], "api_fixture"
	prop.Columns["graph_fact_locator_manifest_hash"] = claimManifest.RootHash
	prop.Columns["property_schema_artifact_id"], prop.Columns["property_schema_version"], prop.Columns["property_schema_digest"], prop.Columns["property_payload_profile"] = schema.ArtifactID, schema.Version, schema.Digest, schema.Profile
	prop.Columns["property_payload"] = oodpublication.CanonicalJSON(`{"name":"fixture"}`)
	ph, err := oodpublication.CanonicalAPIPropertyPayloadHash(schema, prop.Columns["property_payload"].(oodpublication.CanonicalJSON))
	if err != nil {
		t.Fatal(err)
	}
	prop.Columns["property_payload_hash"] = ph
	verifier := &oodpublication.ManifestMemberVerifier{PropertyPayloadSchemas: apiOOD8PropertySchemas{schema}}
	pfh, err := verifier.CanonicalMemberDigestFromPhysicalRow(context.Background(), prop)
	if err != nil {
		t.Fatal(err)
	}
	prop.Columns["api_property_fact_hash"] = pfh

	// The physical violation table is admitted by the OOD v9 closure codec.
	// Until a concrete violation mapper is needed, its pinned row is still
	// closure-bound as an owner-profile member by apiOOD8Member below.
	rows := append([]oodpublication.SpannerRow{}, rrs...)
	rows = append(rows, brs...)
	rows = append(rows, relrow, docEvidence, docEvidenceB, objA, objB, doc, edge, docEdge, docEdgeB, locrow, doclocrow, prop)
	sourceRows := append([]oodpublication.SpannerRow{}, rrs...)
	sourceRows = append(sourceRows, brs...)
	sourceRows = append(sourceRows, relrow, docEvidence, docEvidenceB)
	memberRows := map[string][]oodpublication.SpannerRow{"source": sourceRows, "object": {objA, objB, doc}, "symbol": {apiOOD8GraphRow(t, "OODGraphSymbols", org)}, "edge": {edge, docEdge, docEdgeB}, "api_property": {prop}, "graph_fact_locator": {locrow, doclocrow}, "receipt": rrs}
	// bind the symbol to its owning object and compute its pinned graph hash.
	sym := memberRows["symbol"][0]
	sym.Columns["graph_object_id"] = objA.Columns["graph_object_id"]
	sym.Columns["object_class"] = objA.Columns["object_class"]
	h, err := oodpublication.CanonicalMemberDigestFromPhysicalRow(sym)
	if err != nil {
		t.Fatal(err)
	}
	sym.Columns["graph_row_hash"] = h
	memberRows["symbol"][0] = sym
	rows = append(rows, sym)
	cert, closure := apiOOD8Manifests(t, org, memberRows, verifier)
	// The API-role claim is intentionally narrower than the global locator
	// root. Preserve its content-addressed auxiliary manifest so role and
	// property bindings can resolve it from the same immutable closure.
	closure.Nodes = append(closure.Nodes, claimManifest.Nodes...)
	closure.ImmutableRows = append(closure.ImmutableRows, claimManifest.ImmutableRows...)
	closure.Nodes = append(closure.Nodes, docNode)
	closure.ImmutableRows = append(closure.ImmutableRows, docNodeRow)
	closure.ImmutableRows = append(closure.ImmutableRows, docEntryRows...)
	if _, err := oodpublication.ResolveGraphFactLocatorManifestMembers(closure.ImmutableRows, org, claimManifest.RootHash); err != nil {
		t.Fatalf("fixture role claim manifest is not closure-resolvable: %v", err)
	}
	if _, err := oodpublication.ResolveGraphFactLocatorManifestMembers(closure.ImmutableRows, org, docNode.Hash); err != nil {
		t.Fatalf("fixture documentation claim manifest is not closure-resolvable: %v", err)
	}
	// With one locator the claim tree is byte-identical to the global locator
	// root already retained by apiOOD8Manifests. Content-addressed rows appear
	// once; the claim refers to that same sealed root.
	// The reconciler's roster includes all member rows, manifest rows, and its
	// certificate.  Do not append an independently assembled parallel roster.
	rows = closure.ImmutableRows
	plan := apiOOD8Plan(org, cert, rows)
	attestor := apiOOD8ClosureAttestor{}
	proof, err := oodevidence.VerifyClosureV8(context.Background(), cert, oodpublication.AttestedManifestClosureAuthority{ManifestClosureReconciler: oodpublication.ManifestClosureReconciler{Input: closure}, Attestor: attestor})
	if err != nil {
		t.Fatalf("fixture closure: %v", err)
	}
	roleEvidence, err := oodevidence.VerifyGraphFactLocatorV8(context.Background(), batch, locator, body)
	if err != nil {
		t.Fatal(err)
	}
	documentationEvidence, err := oodevidence.VerifyGraphFactLocatorV8(context.Background(), batch, docLocator, body)
	if err != nil {
		t.Fatal(err)
	}
	return Fixture{Certificate: cert, Closure: closure, Proof: proof, ImmutableRows: rows, Snapshot: plan.Snapshot, Run: plan.Run, Head: plan.Head, PropertySchema: schema, LocatorProofs: []oodevidence.VerifiedLocatorV8{locatorProof}, EvidenceLocatorProofs: []oodevidence.VerifiedGraphFactLocatorV8{roleEvidence, documentationEvidence}, Plan: plan, Attestor: attestor, Receipt: receipt, Batch: batch, Relationship: rel, Locator: locator}
}

func apiOOD8FullRow(t *testing.T, table, org string) oodpublication.SpannerRow {
	t.Helper()
	keys, cols, err := oodpublication.ImmutablePhysicalColumnNames(table)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]interface{}{}
	now := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for _, n := range cols {
		switch {
		case n == "organization_id":
			m[n] = org
		case strings.HasSuffix(n, "_id") && n != "fetch_batch_id":
			m[n] = apiOOD8ID(table + "/" + n)
		case strings.HasSuffix(n, "_hash") || strings.HasSuffix(n, "_digest"):
			m[n] = apiOOD8Digest(table + "/" + n)
		case strings.Contains(n, "count") || strings.HasSuffix(n, "ordinal") || strings.HasSuffix(n, "offset") || n == "permission_byte_ceiling" || n == "permission_depth_ceiling":
			m[n] = int64(1)
		case n == "sealed":
			m[n] = true
		case n == "diagnostic_only":
			m[n] = false
		case n == "receipt_roles":
			m[n] = []string{"component"}
		case strings.HasSuffix(n, "_at"):
			m[n] = now
		case n == "route_prefix_bytes" || n == "redacted_transport_evidence_ciphertext" || n == "valid_from" || n == "valid_until":
			m[n] = nil
		case n == "property_payload" || n == "projection_payload" || n == "evidence":
			m[n] = oodpublication.CanonicalJSON(`{}`)
		default:
			m[n] = "fixture"
		}
	}
	return oodpublication.SpannerRow{Table: table, KeyColumns: keys, Columns: m}
}

func apiOOD8PhysicalReceipt(t *testing.T, r oodevidence.ReceiptV8) oodpublication.SpannerRow {
	t.Helper()
	x := apiOOD8FullRow(t, "OODGraphExternalFetchReceipts", r.OrganizationID)
	m := x.Columns
	m["receipt_id"], m["fetch_batch_id"], m["receipt_roles"], m["fetch_component_ordinal"], m["fetch_occurrence_id"], m["evidence_identity_hash"], m["graph_object_id"], m["object_class"] = r.ReceiptID, r.FetchBatchID, r.ReceiptRoles, apiOOD8OptionalI64(r.FetchComponentOrdinal), r.FetchOccurrenceID, r.EvidenceIdentityHash, r.GraphObjectID, r.ObjectClass
	m["source_authority_id"], m["source_authority_binding_id"], m["source_authority_binding_digest"], m["source_ref_kind"], m["source_stable_reference"], m["source_representation_kind"], m["evidence_content_class"], m["source_representation_media_type"] = r.SourceAuthorityID, r.SourceAuthorityBindingID, r.SourceAuthorityBindingDigest, r.SourceRefKind, r.SourceStableReference, r.SourceRepresentationKind, r.EvidenceContentClass, apiOOD8OptionalString(r.SourceRepresentationMediaType)
	m["representation_declaration_id"], m["representation_declaration_digest"], m["version_coordinate"], m["source_content_hash_algorithm"], m["source_content_hash_profile"], m["source_content_hash"], m["external_fetch_profile_ref"], m["external_fetch_profile_digest"] = r.RepresentationDeclarationID, r.RepresentationDeclarationDigest, r.VersionCoordinate, r.SourceContentHashAlgorithm, r.SourceContentHashProfile, r.SourceContentHash, r.ExternalFetchProfileRef, r.ExternalFetchProfileDigest
	m["permission_grant_id"], m["permission_grant_digest"], m["permission_authority_id"], m["permission_principal_id"], m["permission_scope_digest"], m["permission_operation"], m["permission_method"], m["permission_redirect_policy_digest"] = r.PermissionGrantID, r.PermissionGrantDigest, r.PermissionAuthorityID, r.PermissionPrincipalID, r.PermissionScopeDigest, r.PermissionOperation, r.PermissionMethod, r.PermissionRedirectPolicyDigest
	m["permission_content_class"], m["permission_trust_class"], m["permission_byte_ceiling"], m["permission_depth_ceiling"], m["permission_expected_content_hash_algorithm"], m["permission_expected_content_hash_profile"], m["permission_expected_content_hash"], m["permission_effective_at"], m["permission_expires_at"] = r.PermissionContentClass, r.PermissionTrustClass, r.PermissionByteCeiling, r.PermissionDepthCeiling, apiOOD8OptionalString(r.PermissionExpectedContentHashAlgorithm), apiOOD8OptionalString(r.PermissionExpectedContentHashProfile), apiOOD8OptionalString(r.PermissionExpectedContentHash), r.PermissionEffectiveAt, apiOOD8OptionalTime(r.PermissionExpiresAt)
	m["permission_status"], m["permission_policy_version_ref"], m["permission_policy_version_digest"], m["fetch_authorization_decision_ref"], m["fetch_authorization_decision_digest"], m["observed_at"] = r.PermissionStatus, r.PermissionPolicyVersionRef, r.PermissionPolicyVersionDigest, r.FetchAuthorizationDecisionRef, r.FetchAuthorizationDecisionDigest, r.ObservedAt
	m["transport_status"], m["transport_raw_content_hash_algorithm"], m["transport_raw_content_hash"], m["transport_raw_byte_count"], m["transport_decoded_byte_count"], m["transport_content_encoding"], m["transport_charset"], m["transport_response_metadata_digest"] = r.TransportStatus, r.TransportRawContentHashAlgorithm, r.TransportRawContentHash, r.TransportRawByteCount, r.TransportDecodedByteCount, apiOOD8OptionalString(r.TransportContentEncoding), apiOOD8OptionalString(r.TransportCharset), r.TransportResponseMetadataDigest
	m["evidence_archive_authority_id"], m["evidence_archive_record_id"], m["evidence_archive_record_digest"], m["evidence_archive_byte_count"], m["evidence_archive_deletion_domain_id"], m["evidence_archive_crypto_shred_domain_id"], m["receipt_deletion_domain_id"], m["receipt_crypto_shred_domain_id"], m["redacted_transport_evidence_digest"] = r.EvidenceArchiveAuthorityID, r.EvidenceArchiveRecordID, r.EvidenceArchiveRecordDigest, r.EvidenceArchiveByteCount, r.EvidenceArchiveDeletionDomainID, r.EvidenceArchiveCryptoShredDomainID, r.ReceiptDeletionDomainID, r.ReceiptCryptoShredDomainID, r.RedactedTransportEvidenceDigest
	return x
}

func apiOOD8PhysicalBatch(t *testing.T, r oodevidence.ReceiptV8, verified oodevidence.VerifiedBatchV8) oodpublication.SpannerRow {
	t.Helper()
	manifest, err := apiOOD8BatchReceiptManifest(r)
	if err != nil {
		t.Fatal(err)
	}
	x := apiOOD8FullRow(t, "OODGraphExternalFetchBatches", r.OrganizationID)
	m := x.Columns
	m["fetch_batch_id"], m["source_authority_binding_id"], m["source_authority_binding_digest"], m["representation_declaration_id"], m["representation_declaration_digest"], m["batch_receipt_manifest_root_hash"] = verified.FetchBatchID(), r.SourceAuthorityBindingID, r.SourceAuthorityBindingDigest, r.RepresentationDeclarationID, r.RepresentationDeclarationDigest, manifest.NodeHash
	m["total_receipt_count"], m["component_receipt_count"], m["completeness_evidence_receipt_count"], m["noncomponent_receipt_count"], m["expected_component_count"] = int64(1), int64(1), int64(1), int64(0), int64(1)
	m["completeness_basis_kind"], m["completeness_evidence_ref"], m["completeness_evidence_identity_hash"], m["completeness_evidence_content_hash_algorithm"], m["completeness_evidence_content_hash_profile"], m["completeness_evidence_content_hash"], m["completeness_evidence_receipt_id"] = "source_declared_total", r.SourceStableReference, r.EvidenceIdentityHash, r.SourceContentHashAlgorithm, r.SourceContentHashProfile, r.SourceContentHash, r.ReceiptID
	m["completeness_evidence_archive_authority_id"], m["completeness_evidence_archive_record_id"], m["completeness_evidence_archive_record_digest"], m["completeness_evidence_selector_kind"], m["completeness_evidence_selector_value"], m["verified_completeness_claim_digest"], m["completeness_evidence_digest"], m["completeness_profile_ref"], m["completeness_profile_digest"] = r.EvidenceArchiveAuthorityID, r.EvidenceArchiveRecordID, r.EvidenceArchiveRecordDigest, "whole_evidence_body", "$", apiOOD8Digest("claim"), verified.CompletenessEvidenceDigest(), "profile/v1", apiOOD8Digest("profile")
	m["sealed_at"] = time.Date(2026, 11, 2, 12, 1, 0, 0, time.UTC)
	decoded, err := oodpublication.BatchV8FromPhysicalRow(x)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := oodevidence.CompletenessEvidenceDigestV8(decoded)
	if err != nil || digest != verified.CompletenessEvidenceDigest() {
		t.Fatalf("fixture physical batch digest does not round trip: got=%q want=%q err=%v", digest, verified.CompletenessEvidenceDigest(), err)
	}
	return x
}

func apiOOD8OptionalI64(x *int64) interface{} {
	if x == nil {
		return nil
	}
	return *x
}
func apiOOD8OptionalString(x *string) interface{} {
	if x == nil {
		return nil
	}
	return *x
}
func apiOOD8OptionalTime(x *time.Time) interface{} {
	if x == nil {
		return nil
	}
	return *x
}

func apiOOD8GraphRow(t *testing.T, table, org string) oodpublication.SpannerRow {
	return apiOOD8FullRow(t, table, org)
}

func apiOOD8PhysicalRelationship(t *testing.T, r oodevidence.RelationshipV8) oodpublication.SpannerRow {
	t.Helper()
	x := apiOOD8FullRow(t, "OODGraphRelationshipEvidence", r.OrganizationID)
	m := x.Columns
	m["relationship_evidence_hash"], m["evidence_source_kind"], m["patch_action"] = r.RelationshipEvidenceHash, r.EvidenceSourceKind, r.PatchAction
	m["source_object_class"], m["source_authority_id"], m["source_ref_kind"], m["source_stable_reference"], m["source_version_coordinate"], m["source_section_path"] = r.SourceObjectClass, r.SourceAuthorityID, r.SourceRefKind, r.SourceStableReference, r.SourceVersionCoordinate, r.SourceSectionPath
	m["target_object_class"], m["target_authority_id"], m["target_ref_kind"], m["target_stable_reference"], m["target_version_coordinate"], m["target_section_path"] = r.TargetObjectClass, r.TargetAuthorityID, r.TargetRefKind, r.TargetStableReference, r.TargetVersionCoordinate, r.TargetSectionPath
	m["edge_label"], m["authoring_source_path"], m["evidence_authority_id"], m["evidence_stable_reference"], m["evidence_version_coordinate"] = r.EdgeLabel, r.AuthoringSourcePath, r.EvidenceAuthorityID, r.EvidenceStableReference, r.EvidenceVersionCoordinate
	m["evidence_content_hash_algorithm"], m["evidence_content_hash_profile"], m["evidence_content_hash"], m["evidence_identity_hash"] = r.EvidenceContentHashAlgorithm, r.EvidenceContentHashProfile, r.EvidenceContentHash, apiOOD8OptionalString(r.EvidenceIdentityHash)
	m["eligible_receipt_id"], m["eligible_receipt_digest"], m["sealed_completeness_certificate_hash"] = apiOOD8OptionalString(r.EligibleReceiptID), apiOOD8OptionalString(r.EligibleReceiptDigest), apiOOD8OptionalString(r.SealedCompletenessCertificateHash)
	m["evidence_archive_authority_id"], m["evidence_archive_record_id"], m["evidence_archive_record_digest"] = apiOOD8OptionalString(r.EvidenceArchiveAuthorityID), apiOOD8OptionalString(r.EvidenceArchiveRecordID), apiOOD8OptionalString(r.EvidenceArchiveRecordDigest)
	m["graph_fact_locator_manifest_hash"], m["extractor_profile_id"], m["extractor_profile_version"], m["extractor_profile_digest"], m["evidence_authority_class"], m["parent_graph_snapshot_id"] = apiOOD8OptionalString(r.GraphFactLocatorManifestHash), apiOOD8OptionalString(r.ExtractorProfileID), apiOOD8OptionalString(r.ExtractorProfileVersion), apiOOD8OptionalString(r.ExtractorProfileDigest), apiOOD8OptionalString(r.EvidenceAuthorityClass), apiOOD8OptionalString(r.ParentGraphSnapshotID)
	return x
}

func apiOOD8CopyLocator(m map[string]interface{}, l oodproof.GraphFactLocator) {
	m["evidence_identity_hash"], m["source_artifact_member_hash"], m["eligible_receipt_id"], m["eligible_receipt_digest"] = l.EvidenceIdentityHash, l.SourceArtifactMemberHash, l.EligibleReceiptID, l.EligibleReceiptDigest
	m["sealed_completeness_certificate_hash"], m["evidence_archive_authority_id"], m["evidence_archive_record_id"], m["evidence_archive_record_digest"] = l.SealedCompletenessCertificateHash, l.EvidenceArchiveAuthorityID, l.EvidenceArchiveRecordID, l.EvidenceArchiveRecordDigest
	m["source_content_hash_algorithm"], m["source_content_hash_profile"], m["source_content_hash"], m["source_content_byte_length"] = l.SourceContentHashAlgorithm, l.SourceContentHashProfile, l.SourceContentHash, l.SourceContentByteLength
	m["canonical_representation_profile_ref"], m["canonical_representation_profile_digest"], m["byte_start_offset"], m["byte_end_offset_exclusive"] = l.CanonicalRepresentationProfileRef, l.CanonicalRepresentationProfileDigest, l.ByteStartOffset, l.ByteEndOffsetExclusive
	m["selected_range_content_hash"], m["selected_range_byte_count"], m["evidence_archive_deletion_domain_id"], m["evidence_archive_crypto_shred_domain_id"] = l.SelectedRangeContentHash, l.SelectedRangeByteCount, l.EvidenceArchiveDeletionDomainID, l.EvidenceArchiveCryptoShredDomainID
}

func apiOOD8Manifests(t *testing.T, org string, rows map[string][]oodpublication.SpannerRow, verifier *oodpublication.ManifestMemberVerifier) (oodevidence.ClosureCertificateV8, oodpublication.ManifestClosureInput) {
	t.Helper()
	kinds := []string{"source", "object", "symbol", "edge", "api_property", "graph_fact_locator", "receipt", "structural_projection", "violation"}
	in := oodpublication.ManifestClosureInput{OrganizationID: org, MemberVerifier: verifier}
	cert := apiOOD8Certificate(org)
	cert.Roots = map[string]oodevidence.ClosureRoot{}
	for _, kind := range kinds {
		members := []oodpublication.ManifestMemberV8{}
		if kind == "source" {
			// The virtual artifact is exactly the receipt/batch pair. Relationship
			// evidence (including the documents lane) is a distinct typed
			// source-manifest member.
			pairCount := 0
			for pairCount < len(rows[kind]) && rows[kind][pairCount].Table == "OODGraphExternalFetchReceipts" {
				pairCount++
			}
			if pairCount == 0 || len(rows[kind]) < pairCount*2+1 {
				t.Fatalf("source fixture wants receipt/batch pairs and relationship evidence")
			}
			for i := 0; i < pairCount; i++ {
				if rows[kind][pairCount+i].Table != "OODGraphExternalFetchBatches" {
					t.Fatalf("source fixture batch %d is not paired to its receipt", i)
				}
			}
			for i := 0; i < pairCount; i++ {
				pair := []oodpublication.SpannerRow{rows[kind][i], rows[kind][pairCount+i]}
				d, err := oodpublication.SourceArtifactExternalEvidenceDigest(pair)
				if err != nil {
					t.Fatal(err)
				}
				members = append(members, oodpublication.ManifestMemberV8{ManifestKind: kind, EntryKind: "source_artifact", MemberID: d, ClaimedHash: d, EvidenceRows: pair})
			}
			for _, relationship := range rows[kind][pairCount*2:] {
				if relationship.Table != "OODGraphRelationshipEvidence" {
					t.Fatalf("source fixture has non-relationship source member %q", relationship.Table)
				}
				rd := relationship.Columns["relationship_evidence_hash"].(string)
				members = append(members, oodpublication.ManifestMemberV8{ManifestKind: kind, EntryKind: "relationship_evidence", MemberID: rd, ClaimedHash: rd, Row: &relationship})
			}
			in.ImmutableRows = append(in.ImmutableRows, rows[kind]...)
		} else {
			for i, row := range rows[kind] {
				var d string
				var err error
				if kind == "receipt" {
					d = row.Columns["redacted_transport_evidence_digest"].(string)
				} else if kind == "api_property" {
					d, err = verifier.CanonicalMemberDigestFromPhysicalRow(context.Background(), row)
				} else {
					d, err = oodpublication.CanonicalMemberDigestFromPhysicalRow(row)
				}
				if err != nil {
					t.Fatal(err)
				}
				entry := kind
				if kind == "graph_fact_locator" {
					entry = "graph_fact_locator"
				}
				memberID := fmt.Sprintf("%s-%d", kind, i)
				switch kind {
				case "object":
					memberID = row.Columns["graph_object_id"].(string)
				case "symbol":
					memberID = row.Columns["symbol_id"].(string)
				case "edge":
					memberID = row.Columns["graph_edge_id"].(string)
				case "api_property":
					memberID = row.Columns["api_property_fact_hash"].(string)
				case "graph_fact_locator":
					memberID = row.Columns["graph_fact_locator_hash"].(string)
				case "receipt":
					memberID = row.Columns["receipt_id"].(string)
				}
				members = append(members, oodpublication.ManifestMemberV8{ManifestKind: kind, EntryKind: entry, MemberID: memberID, ClaimedHash: d, Row: &row})
				// The receipt is already present as the exact evidence backing its
				// virtual source artifact; the receipt root binds that same physical
				// row, never a duplicate roster copy.
				if kind != "receipt" {
					in.ImmutableRows = append(in.ImmutableRows, row)
				}
			}
		}
		n, mr, ers := apiOOD8ManifestNode(t, org, kind, members)
		in.Nodes = append(in.Nodes, n)
		in.Members = append(in.Members, members...)
		in.ImmutableRows = append(in.ImmutableRows, mr)
		in.ImmutableRows = append(in.ImmutableRows, ers...)
		cert.Roots[kind] = oodevidence.ClosureRoot{Hash: n.Hash, Count: int64(len(members))}
	}
	pairCount := 0
	for pairCount < len(rows["source"]) && rows["source"][pairCount].Table == "OODGraphExternalFetchReceipts" {
		pairCount++
	}
	cert.SourceArtifactCount, cert.RelationshipEvidenceCount = int64(pairCount), int64(len(rows["source"])-pairCount*2)
	closureHash, err := oodevidence.ClosureHashV8(cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.ClosureHash = closureHash
	certificateHash, err := oodevidence.CertificateHashV8(cert)
	if err != nil {
		t.Fatal(err)
	}
	cert.VerificationCertificateHash = certificateHash
	cr := apiOOD8CertificateRow(t, cert)
	// A receipt is both the backing evidence for the virtual source artifact
	// and a leaf of the receipt root. Keep that one immutable physical row in
	// the roster once; the two manifest references are what express the
	// relationship, not a duplicate stored row.
	seenRows := map[string]bool{}
	uniqueRows := make([]oodpublication.SpannerRow, 0, len(in.ImmutableRows)+1)
	for _, row := range in.ImmutableRows {
		key := row.Table
		for _, column := range row.KeyColumns {
			key += "\\x00" + fmt.Sprint(row.Columns[column])
		}
		if !seenRows[key] {
			seenRows[key] = true
			uniqueRows = append(uniqueRows, row)
		}
	}
	in.ImmutableRows = uniqueRows
	in.CertificateRow = &cr
	in.ImmutableRows = append(in.ImmutableRows, cr)
	return cert, in
}

func apiOOD8ManifestNode(t *testing.T, org, kind string, members []oodpublication.ManifestMemberV8) (oodpublication.ManifestNodeV8, oodpublication.SpannerRow, []oodpublication.SpannerRow) {
	t.Helper()
	entries := make([]oodpublication.ManifestEntryV8, len(members))
	vals := make([]oodcanon.Value, len(members))
	for i, m := range members {
		d, e := oodcanon.DigestHex(m.ClaimedHash)
		if e != nil {
			t.Fatal(e)
		}
		fields := []oodcanon.NamedValue{{Name: "entry_ordinal", Value: oodcanon.I64(int64(i))}, {Name: "entry_kind", Value: oodcanon.String(m.EntryKind)}, {Name: "member_id", Value: oodcanon.String(m.MemberID)}, {Name: "member_hash", Value: d}, {Name: "child_manifest_node_hash", Value: oodcanon.NullValue(oodcanon.SHA256)}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(0)}}
		measured, e := oodcanon.EncodeNestedRecord(oodcanon.ManifestLeafV1().Fields[7].Element.Nested, fields)
		if e != nil {
			t.Fatal(e)
		}
		entries[i] = oodpublication.ManifestEntryV8{Ordinal: int64(i), EntryKind: m.EntryKind, MemberID: m.MemberID, MemberHash: m.ClaimedHash, CanonicalByteCount: int64(len(measured))}
		fields[len(fields)-1].Value = oodcanon.I64(entries[i].CanonicalByteCount)
		vals[i] = oodcanon.Value{Type: oodcanon.Record, Presence: oodcanon.Present, Fields: fields}
	}
	record := oodcanon.RecordValue{"manifest_kind": oodcanon.String(kind), "entry_count": oodcanon.I64(int64(len(entries))), "transitive_member_count": oodcanon.I64(int64(len(entries))), "canonical_byte_count": oodcanon.I64(0), "ordered_entry_tuples": oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present, Elements: vals}}
	measuredNode, err := oodcanon.Encode(oodcanon.ManifestLeafV1(), record)
	if err != nil {
		t.Fatal(err)
	}
	record["canonical_byte_count"] = oodcanon.I64(int64(len(measuredNode)))
	h, err := oodcanon.DigestHexOf(oodcanon.ManifestLeafV1(), record)
	if err != nil {
		t.Fatal(err)
	}
	n := oodpublication.ManifestNodeV8{Hash: h, OrganizationID: org, Kind: kind, NodeKind: "leaf", HashAlgorithm: "SHA-256", CanonicalizationProfile: "ood_graph_manifest_node_v1", EntryCount: int64(len(entries)), TransitiveMemberCount: int64(len(entries)), CanonicalByteCount: int64(len(measuredNode)), Sealed: true, Entries: entries}
	r := apiOOD8FullRow(t, "OODGraphManifestNodes", org)
	r.Columns["manifest_node_hash"], r.Columns["manifest_kind"], r.Columns["node_kind"], r.Columns["node_level"], r.Columns["route_prefix_bytes"], r.Columns["route_prefix_nibble_length"], r.Columns["entry_count"], r.Columns["transitive_member_count"], r.Columns["canonical_byte_count"], r.Columns["hash_algorithm"], r.Columns["canonicalization_profile"], r.Columns["sealed"] = h, kind, "leaf", int64(0), nil, nil, int64(len(entries)), int64(len(entries)), n.CanonicalByteCount, "SHA-256", "ood_graph_manifest_node_v1", true
	n.Row = &r
	erows := make([]oodpublication.SpannerRow, len(entries))
	for i := range entries {
		e := apiOOD8FullRow(t, "OODGraphManifestEntries", org)
		e.Columns["manifest_node_hash"], e.Columns["entry_ordinal"], e.Columns["branch_nibble"], e.Columns["entry_kind"], e.Columns["member_id"], e.Columns["member_hash"], e.Columns["child_manifest_node_hash"], e.Columns["canonical_entry_byte_count"] = h, int64(i), nil, entries[i].EntryKind, entries[i].MemberID, entries[i].MemberHash, nil, entries[i].CanonicalByteCount
		erows[i] = e
		n.Entries[i].Row = &erows[i]
	}
	return n, r, erows
}

func apiOOD8Certificate(org string) oodevidence.ClosureCertificateV8 {
	d := apiOOD8Digest
	return oodevidence.ClosureCertificateV8{OrganizationID: org, MaterializationRunID: apiOOD8ID("run"), SnapshotKind: "provider_documentation", SourceSetHash: d("source-set"), RelationshipIdentitySetHash: d("relationship-identities"), SourceAuthorityIdentitySetHash: d("authority-identities"), CompletenessIdentitySetHash: d("completeness-identities"), PermissionPolicyIdentitySetHash: d("policy-identities"), ArchiveBindingIdentitySetHash: d("archive-identities"), ProfileIdentitySetHash: d("profile-identities"), ExternalSourceReceiptEligibilitySetHash: d("eligibility-identities"), MaterializationProfileID: apiOOD8ID("profile"), MaterializationProfileVersion: "v1", MaterializationProfileDigest: d("profile"), PublicationBudgetProfileRef: "budget/v1", PublicationBudgetProfileDigest: d("budget"), ManifestHashAlgorithm: "SHA-256", ManifestHashProfile: "ood_graph_manifest_node_v1", ManifestHashContractDigest: d("manifest-contract"), ClosureHashAlgorithm: "SHA-256", ClosureHashProfile: "ood_graph_content_closure_v1", ClosureHashContractDigest: d("closure-contract"), VerifierCapabilityName: "fixture", VerifierCapabilityVersion: "v1", VerifierCapabilityDigest: d("capability"), VerificationPolicyRef: "policy/v1", VerificationPolicyDigest: d("verification-policy"), VerificationCertificateID: apiOOD8ID("certificate"), AttestationAuthorityID: apiOOD8ID("attestor"), AttestationRef: "fixture/attestation", AttestationDigest: d("attestation"), AttestationProfile: "fixture/v1"}
}

func apiOOD8CertificateRow(t *testing.T, c oodevidence.ClosureCertificateV8) oodpublication.SpannerRow {
	t.Helper()
	r := apiOOD8FullRow(t, "OODGraphClosureVerificationCertificates", c.OrganizationID)
	m := r.Columns
	m["verification_certificate_id"], m["verification_certificate_hash"], m["materialization_run_id"], m["snapshot_kind"], m["source_set_hash"], m["closure_hash"] = c.VerificationCertificateID, c.VerificationCertificateHash, c.MaterializationRunID, c.SnapshotKind, c.SourceSetHash, c.ClosureHash
	m["source_manifest_root_hash"] = c.Roots["source"].Hash
	for _, k := range []string{"object", "symbol", "edge", "api_property", "graph_fact_locator", "receipt", "structural_projection", "violation"} {
		m[k+"_manifest_root_hash"], m[k+"_count"] = c.Roots[k].Hash, c.Roots[k].Count
	}
	m["source_artifact_count"], m["relationship_evidence_count"] = c.SourceArtifactCount, c.RelationshipEvidenceCount
	for _, k := range []string{"source_authority_identity_count", "completeness_identity_count", "permission_policy_identity_count", "archive_binding_identity_count", "profile_identity_count", "external_source_receipt_eligibility_count"} {
		m[k] = int64(0)
	}
	for k, v := range map[string]interface{}{"relationship_identity_set_hash": c.RelationshipIdentitySetHash, "source_authority_identity_set_hash": c.SourceAuthorityIdentitySetHash, "completeness_identity_set_hash": c.CompletenessIdentitySetHash, "permission_policy_identity_set_hash": c.PermissionPolicyIdentitySetHash, "archive_binding_identity_set_hash": c.ArchiveBindingIdentitySetHash, "profile_identity_set_hash": c.ProfileIdentitySetHash, "external_source_receipt_eligibility_set_hash": c.ExternalSourceReceiptEligibilitySetHash, "materialization_profile_id": c.MaterializationProfileID, "materialization_profile_version": c.MaterializationProfileVersion, "materialization_profile_digest": c.MaterializationProfileDigest, "publication_budget_profile_ref": c.PublicationBudgetProfileRef, "publication_budget_profile_digest": c.PublicationBudgetProfileDigest, "manifest_hash_algorithm": c.ManifestHashAlgorithm, "manifest_hash_profile": c.ManifestHashProfile, "manifest_hash_contract_digest": c.ManifestHashContractDigest, "closure_hash_algorithm": c.ClosureHashAlgorithm, "closure_hash_profile": c.ClosureHashProfile, "closure_hash_contract_digest": c.ClosureHashContractDigest, "verifier_capability_name": c.VerifierCapabilityName, "verifier_capability_version": c.VerifierCapabilityVersion, "verifier_capability_digest": c.VerifierCapabilityDigest, "verification_policy_ref": c.VerificationPolicyRef, "verification_policy_digest": c.VerificationPolicyDigest, "verification_attestation_authority_id": c.AttestationAuthorityID, "verification_attestation_ref": c.AttestationRef, "verification_attestation_digest": c.AttestationDigest, "verification_attestation_profile": c.AttestationProfile} {
		m[k] = v
	}
	return r
}

func apiOOD8Plan(org string, c oodevidence.ClosureCertificateV8, rows []oodpublication.SpannerRow) oodpublication.SpannerWritePlan {
	snapshotID, kind := apiOOD8ID("snapshot"), "provider_documentation"
	p := oodpublication.SpannerWritePlan{OrganizationID: org, SnapshotKind: kind, SnapshotID: snapshotID, RunID: c.MaterializationRunID, ClosureHash: c.ClosureHash, ImmutableRows: rows}
	p.Snapshot = apiOOD8MutableRow(oodpublication.TableSnapshots, []string{"organization_id", "graph_snapshot_id"}, oodpublication.SnapshotColumns())
	p.Run = apiOOD8MutableRow(oodpublication.TableRuns, []string{"organization_id", "materialization_run_id"}, oodpublication.MaterializationRunColumns())
	p.Head = apiOOD8MutableRow(oodpublication.TableSnapshotHeads, []string{"organization_id", "snapshot_kind"}, oodpublication.SnapshotHeadColumns())
	p.Publication = apiOOD8MutableRow(oodpublication.TablePublicationState, []string{"organization_id"}, oodpublication.PublicationStateColumns())
	for _, row := range []*oodpublication.SpannerRow{&p.Snapshot, &p.Run, &p.Head, &p.Publication} {
		row.Columns["organization_id"] = org
	}
	p.Snapshot.Columns["graph_snapshot_id"], p.Snapshot.Columns["snapshot_kind"], p.Snapshot.Columns["materialization_run_id"], p.Snapshot.Columns["closure_hash"], p.Snapshot.Columns["verification_certificate_id"], p.Snapshot.Columns["verification_certificate_hash"] = snapshotID, kind, c.MaterializationRunID, c.ClosureHash, c.VerificationCertificateID, c.VerificationCertificateHash
	p.Run.Columns["materialization_run_id"], p.Run.Columns["target_graph_snapshot_id"], p.Run.Columns["candidate_closure_hash"], p.Run.Columns["candidate_verification_certificate_id"], p.Run.Columns["candidate_verification_certificate_hash"] = c.MaterializationRunID, snapshotID, c.ClosureHash, c.VerificationCertificateID, c.VerificationCertificateHash
	p.Head.Columns["snapshot_kind"], p.Head.Columns["graph_snapshot_id"], p.Head.Columns["closure_hash"], p.Head.Columns["verification_certificate_id"], p.Head.Columns["verification_certificate_hash"] = kind, snapshotID, c.ClosureHash, c.VerificationCertificateID, c.VerificationCertificateHash
	p.Publication.Columns["last_graph_snapshot_id"], p.Publication.Columns["last_snapshot_kind"] = snapshotID, kind
	return p
}

func apiOOD8MutableRow(table string, keys, columns []string) oodpublication.SpannerRow {
	m := make(map[string]interface{}, len(columns))
	for _, k := range columns {
		if strings.Contains(k, "count") || strings.Contains(k, "generation") || k == "graph_version" || k == "predecessor_head_generation" {
			m[k] = int64(1)
		} else {
			m[k] = "fixture"
		}
	}
	return oodpublication.SpannerRow{Table: table, KeyColumns: keys, Columns: m}
}
