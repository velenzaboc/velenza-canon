package oodproof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func h(s string) string { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }
func locator(t *testing.T) (GraphFactLocator, []byte) {
	t.Helper()
	body := []byte("0123456789")
	l := GraphFactLocator{OrganizationID: uuid.NewString(), EvidenceIdentityHash: h("identity"), SourceArtifactMemberHash: h("member"), EligibleReceiptID: uuid.NewString(), EligibleReceiptDigest: h("receipt"), SealedCompletenessCertificateHash: h("complete"), EvidenceArchiveAuthorityID: uuid.NewString(), EvidenceArchiveRecordID: uuid.NewString(), EvidenceArchiveRecordDigest: h("archive"), SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: "canonical-v1", SourceContentHash: h(string(body)), SourceContentByteLength: int64(len(body)), CanonicalRepresentationProfileRef: "representation/v1", CanonicalRepresentationProfileDigest: h("representation"), ByteStartOffset: 2, ByteEndOffsetExclusive: 7, SelectedRangeContentHash: h(string(body[2:7])), SelectedRangeByteCount: 5, EvidenceArchiveDeletionDomainID: uuid.NewString(), EvidenceArchiveCryptoShredDomainID: uuid.NewString()}
	var err error
	l.LocatorHash, err = l.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	return l, body
}
func TestGraphFactLocatorExactBytesAndMutations(t *testing.T) {
	l, body := locator(t)
	p, err := l.CanonicalPreimage()
	if err != nil {
		t.Fatal(err)
	}
	if string(p[:8]) != "OODGCFE1" {
		t.Fatal("missing exact OODGCFE1 prefix")
	}
	if _, err := VerifyGraphFactLocator(context.Background(), l, body); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*GraphFactLocator){func(x *GraphFactLocator) { x.OrganizationID = uuid.NewString() }, func(x *GraphFactLocator) { x.EvidenceIdentityHash = h("x") }, func(x *GraphFactLocator) { x.SourceArtifactMemberHash = h("x") }, func(x *GraphFactLocator) { x.EligibleReceiptID = uuid.NewString() }, func(x *GraphFactLocator) { x.EligibleReceiptDigest = h("x") }, func(x *GraphFactLocator) { x.SealedCompletenessCertificateHash = h("x") }, func(x *GraphFactLocator) { x.EvidenceArchiveAuthorityID = uuid.NewString() }, func(x *GraphFactLocator) { x.EvidenceArchiveRecordID = uuid.NewString() }, func(x *GraphFactLocator) { x.EvidenceArchiveRecordDigest = h("x") }, func(x *GraphFactLocator) { x.SourceContentHashProfile = "other" }, func(x *GraphFactLocator) { x.SourceContentHash = h("x") }, func(x *GraphFactLocator) { x.SourceContentByteLength++ }, func(x *GraphFactLocator) { x.CanonicalRepresentationProfileRef = "other" }, func(x *GraphFactLocator) { x.CanonicalRepresentationProfileDigest = h("x") }, func(x *GraphFactLocator) { x.ByteStartOffset++ }, func(x *GraphFactLocator) { x.ByteEndOffsetExclusive-- }, func(x *GraphFactLocator) { x.SelectedRangeContentHash = h("x") }, func(x *GraphFactLocator) { x.SelectedRangeByteCount++ }, func(x *GraphFactLocator) { x.EvidenceArchiveDeletionDomainID = uuid.NewString() }, func(x *GraphFactLocator) { x.EvidenceArchiveCryptoShredDomainID = uuid.NewString() }}
	for i, m := range mutations {
		x := l
		m(&x)
		if _, err := VerifyGraphFactLocator(context.Background(), x, body); err == nil {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}

func TestGraphFactLocatorOrganizationStorageWidth(t *testing.T) {
	l, _ := locator(t)
	for _, value := range []string{strings.Repeat("a", 37), strings.Repeat("é", 37)} {
		l.OrganizationID = value
		if _, err := l.CanonicalPreimage(); err == nil {
			t.Fatal("organization exceeding STRING(36) accepted")
		}
	}
	l.OrganizationID = strings.Repeat("é", 36)
	if _, err := l.CanonicalPreimage(); err != nil {
		t.Fatal(err)
	}
}
func TestGraphFactLocatorRejectsBodyRangeAndCancellation(t *testing.T) {
	l, body := locator(t)
	if _, err := VerifyGraphFactLocator(context.Background(), l, append([]byte(nil), body[:9]...)); err == nil {
		t.Fatal("changed body accepted")
	}
	changed := append([]byte(nil), body...)
	changed[3] = 'x'
	if _, err := VerifyGraphFactLocator(context.Background(), l, changed); err == nil {
		t.Fatal("changed range accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyGraphFactLocator(ctx, l, body); err == nil {
		t.Fatal("cancelled context accepted")
	}
	e := l
	e.ByteEndOffsetExclusive = e.ByteStartOffset
	e.SelectedRangeByteCount = 0
	e.SelectedRangeContentHash = h("")
	var err error
	e.LocatorHash, err = e.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyGraphFactLocator(context.Background(), e, body); err == nil {
		t.Fatal("empty half-open range accepted")
	}
	bom := l
	bom.SourceContentHashProfile = "\ufeffcanonical-v1"
	if _, err := bom.ComputedHash(); err == nil {
		t.Fatal("UTF-8 BOM string accepted")
	}
	badVersion := l
	badVersion.EligibleReceiptID = "22222222-2222-9222-8222-222222222222"
	if _, err := badVersion.ComputedHash(); err == nil {
		t.Fatal("UUID version 9 accepted")
	}
}

func TestGraphFactLocatorCanonicalContractAndGoldenVector(t *testing.T) {
	body := []byte("0123456789")
	l := GraphFactLocator{OrganizationID: "11111111-1111-4111-8111-111111111111", EvidenceIdentityHash: h("identity"), SourceArtifactMemberHash: h("member"), EligibleReceiptID: "22222222-2222-4222-8222-222222222222", EligibleReceiptDigest: h("receipt"), SealedCompletenessCertificateHash: h("complete"), EvidenceArchiveAuthorityID: "33333333-3333-4333-8333-333333333333", EvidenceArchiveRecordID: "44444444-4444-4444-8444-444444444444", EvidenceArchiveRecordDigest: h("archive"), SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: "canonical-v1", SourceContentHash: h(string(body)), SourceContentByteLength: 10, CanonicalRepresentationProfileRef: "representation/v1", CanonicalRepresentationProfileDigest: h("representation"), ByteStartOffset: 2, ByteEndOffsetExclusive: 7, SelectedRangeContentHash: h(string(body[2:7])), SelectedRangeByteCount: 5, EvidenceArchiveDeletionDomainID: "55555555-5555-4555-8555-555555555555", EvidenceArchiveCryptoShredDomainID: "66666666-6666-4666-8666-666666666666"}
	fields, err := l.fields()
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"canonicalization_profile", "organization_id", "evidence_identity_hash", "source_artifact_member_hash", "eligible_receipt_id", "eligible_receipt_digest", "sealed_completeness_certificate_hash", "evidence_archive_authority_id", "evidence_archive_record_id", "evidence_archive_record_digest", "source_content_hash_algorithm", "source_content_hash_profile", "source_content_hash", "source_content_byte_length", "canonical_representation_profile_ref", "canonical_representation_profile_digest", "byte_start_offset", "byte_end_offset_exclusive", "selected_range_content_hash", "selected_range_byte_count", "evidence_archive_deletion_domain_id", "evidence_archive_crypto_shred_domain_id"}
	wantTags := []byte{tagUTF8, tagUTF8, tagSHA256, tagSHA256, tagUUID, tagSHA256, tagSHA256, tagUUID, tagUUID, tagSHA256, tagUTF8, tagUTF8, tagSHA256, tagInt64, tagUTF8, tagSHA256, tagInt64, tagInt64, tagSHA256, tagInt64, tagUUID, tagUUID}
	if len(fields) != 22 {
		t.Fatalf("field count=%d", len(fields))
	}
	for i := range fields {
		if fields[i].name != wantNames[i] || fields[i].tag != wantTags[i] {
			t.Fatalf("field %d = %s/%x", i, fields[i].name, fields[i].tag)
		}
	}
	p, err := l.CanonicalPreimage()
	if err != nil {
		t.Fatal(err)
	}
	// This is the complete independently fixed OODGCFE1 preimage vector:
	// the expected bytes are reconstructed here from the protocol envelope,
	// not by calling CanonicalPreimage a second time.
	if got, want := hex.EncodeToString(p), manualGoldenLocatorPreimageHex(l); got != want {
		t.Fatalf("full canonical preimage mismatch\n got=%s\nwant=%s", got, want)
	}
	got, err := l.ComputedHash()
	if err != nil {
		t.Fatal(err)
	}
	if got != "558d5e93677e0ba50b01115364e4c3b15cc2b8cc5d592511b7df5aa83ed21a1e" {
		t.Fatalf("golden hash=%s", got)
	}
}

// manualGoldenLocatorPreimageHex is intentionally test-only and does not use
// production field assembly. It writes fixed protocol envelopes from the
// golden tuple, making the whole preimage—not merely its digest—an oracle.
func manualGoldenLocatorPreimageHex(l GraphFactLocator) string {
	fs := []struct {
		name  string
		tag   byte
		value []byte
	}{
		{"canonicalization_profile", 1, []byte(GraphFactLocatorCanonicalizationProfile)}, {"organization_id", 1, []byte(l.OrganizationID)},
		{"evidence_identity_hash", 8, mustHex(l.EvidenceIdentityHash)}, {"source_artifact_member_hash", 8, mustHex(l.SourceArtifactMemberHash)}, {"eligible_receipt_id", 9, mustUUID(l.EligibleReceiptID)}, {"eligible_receipt_digest", 8, mustHex(l.EligibleReceiptDigest)}, {"sealed_completeness_certificate_hash", 8, mustHex(l.SealedCompletenessCertificateHash)}, {"evidence_archive_authority_id", 9, mustUUID(l.EvidenceArchiveAuthorityID)}, {"evidence_archive_record_id", 9, mustUUID(l.EvidenceArchiveRecordID)}, {"evidence_archive_record_digest", 8, mustHex(l.EvidenceArchiveRecordDigest)}, {"source_content_hash_algorithm", 1, []byte("sha256")}, {"source_content_hash_profile", 1, []byte("canonical-v1")}, {"source_content_hash", 8, mustHex(l.SourceContentHash)}, {"source_content_byte_length", 3, be64(10)}, {"canonical_representation_profile_ref", 1, []byte("representation/v1")}, {"canonical_representation_profile_digest", 8, mustHex(l.CanonicalRepresentationProfileDigest)}, {"byte_start_offset", 3, be64(2)}, {"byte_end_offset_exclusive", 3, be64(7)}, {"selected_range_content_hash", 8, mustHex(l.SelectedRangeContentHash)}, {"selected_range_byte_count", 3, be64(5)}, {"evidence_archive_deletion_domain_id", 9, mustUUID(l.EvidenceArchiveDeletionDomainID)}, {"evidence_archive_crypto_shred_domain_id", 9, mustUUID(l.EvidenceArchiveCryptoShredDomainID)},
	}
	out := append([]byte("OODGCFE1"), 0, 0, 0, 22)
	for _, f := range fs {
		out = append(out, byte(len(f.name)>>24), byte(len(f.name)>>16), byte(len(f.name)>>8), byte(len(f.name)))
		out = append(out, []byte(f.name)...)
		out = append(out, f.tag, 1, 0, 0, 0, 0, 0, 0, 0, byte(len(f.value)))
		out = append(out, f.value...)
	}
	return hex.EncodeToString(out)
}
func mustHex(s string) []byte  { b, _ := hex.DecodeString(s); return b }
func mustUUID(s string) []byte { u := uuid.MustParse(s); return u[:] }
func be64(n uint64) []byte {
	return []byte{byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}
