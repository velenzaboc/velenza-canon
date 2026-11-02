// Package oodproof verifies byte-level OOD Graph proof prerequisites.  It
// deliberately has no materialization or authority-admission API.
package oodproof

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/google/uuid"
)

const GraphFactLocatorCanonicalizationProfile = "ood_graph_graph_fact_evidence_locator_v1"

// GraphFactLocator is the exact s6 OODGraphGraphFactEvidenceLocators hash
// tuple. LocatorHash is excluded from its own preimage.
type GraphFactLocator struct {
	LocatorHash                          string
	OrganizationID                       string
	EvidenceIdentityHash                 string
	SourceArtifactMemberHash             string
	EligibleReceiptID                    string
	EligibleReceiptDigest                string
	SealedCompletenessCertificateHash    string
	EvidenceArchiveAuthorityID           string
	EvidenceArchiveRecordID              string
	EvidenceArchiveRecordDigest          string
	SourceContentHashAlgorithm           string
	SourceContentHashProfile             string
	SourceContentHash                    string
	SourceContentByteLength              int64
	CanonicalRepresentationProfileRef    string
	CanonicalRepresentationProfileDigest string
	ByteStartOffset                      int64
	ByteEndOffsetExclusive               int64
	SelectedRangeContentHash             string
	SelectedRangeByteCount               int64
	EvidenceArchiveDeletionDomainID      string
	EvidenceArchiveCryptoShredDomainID   string
}

// VerifiedByteBinding is a purely local assertion about supplied bytes. It
// does not claim that a receipt, archive or certificate is authoritative.
type VerifiedByteBinding struct {
	LocatorHash              string
	SourceContentHash        string
	SourceContentByteLength  int64
	ByteStartOffset          int64
	ByteEndOffsetExclusive   int64
	SelectedRangeContentHash string
	SelectedRangeByteCount   int64
}

const (
	tagUTF8   byte = 0x01
	tagInt64  byte = 0x03
	tagSHA256 byte = 0x08
	tagUUID   byte = 0x09
	present   byte = 0x01
)

type field struct {
	name  string
	tag   byte
	value []byte
}

func appendU32(dst []byte, n uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return append(dst, b[:]...)
}
func appendU64(dst []byte, n uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], n)
	return append(dst, b[:]...)
}
func int64Bytes(n int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return b[:]
}
func digest(name, s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, fmt.Errorf("%s must be 64 lowercase hex characters", name)
	}
	if s != stringLowerHex(s) {
		return nil, fmt.Errorf("%s must be lowercase hex", name)
	}
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 {
		return nil, fmt.Errorf("%s invalid SHA-256", name)
	}
	return b, nil
}
func stringLowerHex(s string) string {
	for i := range s {
		if s[i] >= 'A' && s[i] <= 'F' {
			b := []byte(s)
			b[i] += 32
			return stringLowerHex(string(b))
		}
	}
	return s
}
func canonicalUUID(name, s string) ([]byte, error) {
	if len(s) != 36 || s != stringLowerHex(s) {
		return nil, fmt.Errorf("%s must be canonical lowercase UUID", name)
	}
	u, e := uuid.Parse(s)
	if e != nil || u.String() != s || u.Variant() != uuid.RFC4122 || u.Version() == 0 || u.Version() > 8 {
		return nil, fmt.Errorf("%s invalid canonical RFC UUID", name)
	}
	return u[:], nil
}
func requiredString(name, s string) ([]byte, error) {
	if s == "" || !utf8.ValidString(s) || (len(s) >= 3 && s[0] == 0xef && s[1] == 0xbb && s[2] == 0xbf) {
		return nil, fmt.Errorf("%s must be nonempty valid UTF-8", name)
	}
	return []byte(s), nil
}
func addString(fs *[]field, n, v string) error {
	b, e := requiredString(n, v)
	if e == nil {
		*fs = append(*fs, field{n, tagUTF8, b})
	}
	return e
}
func addDigest(fs *[]field, n, v string) error {
	b, e := digest(n, v)
	if e == nil {
		*fs = append(*fs, field{n, tagSHA256, b})
	}
	return e
}
func addUUID(fs *[]field, n, v string) error {
	b, e := canonicalUUID(n, v)
	if e == nil {
		*fs = append(*fs, field{n, tagUUID, b})
	}
	return e
}

func (l GraphFactLocator) fields() ([]field, error) {
	fs := make([]field, 0, 22)
	if err := addString(&fs, "canonicalization_profile", GraphFactLocatorCanonicalizationProfile); err != nil {
		return nil, err
	}
	// The closed tuple explicitly declares organization_id as utf8_string.
	// Storage width is not an identity grammar; do not infer UUID semantics
	// without the separate owner contract.
	// OOD's locator table uses STRING(36); Spanner bounds STRING by Unicode
	// characters. The hash tuple still declares UTF-8, not the UUID type.
	if utf8.RuneCountInString(l.OrganizationID) > 36 {
		return nil, errors.New("organization_id exceeds STRING(36)")
	}
	if err := addString(&fs, "organization_id", l.OrganizationID); err != nil {
		return nil, err
	}
	for _, x := range []struct{ n, v string }{{"evidence_identity_hash", l.EvidenceIdentityHash}, {"source_artifact_member_hash", l.SourceArtifactMemberHash}} {
		if err := addDigest(&fs, x.n, x.v); err != nil {
			return nil, err
		}
	}
	if err := addUUID(&fs, "eligible_receipt_id", l.EligibleReceiptID); err != nil {
		return nil, err
	}
	for _, x := range []struct{ n, v string }{{"eligible_receipt_digest", l.EligibleReceiptDigest}, {"sealed_completeness_certificate_hash", l.SealedCompletenessCertificateHash}} {
		if err := addDigest(&fs, x.n, x.v); err != nil {
			return nil, err
		}
	}
	if err := addUUID(&fs, "evidence_archive_authority_id", l.EvidenceArchiveAuthorityID); err != nil {
		return nil, err
	}
	if err := addUUID(&fs, "evidence_archive_record_id", l.EvidenceArchiveRecordID); err != nil {
		return nil, err
	}
	if err := addDigest(&fs, "evidence_archive_record_digest", l.EvidenceArchiveRecordDigest); err != nil {
		return nil, err
	}
	for _, x := range []struct{ n, v string }{{"source_content_hash_algorithm", l.SourceContentHashAlgorithm}, {"source_content_hash_profile", l.SourceContentHashProfile}} {
		if err := addString(&fs, x.n, x.v); err != nil {
			return nil, err
		}
	}
	if l.SourceContentHashAlgorithm != "sha256" {
		return nil, errors.New("source_content_hash_algorithm must be sha256")
	}
	if err := addDigest(&fs, "source_content_hash", l.SourceContentHash); err != nil {
		return nil, err
	}
	fs = append(fs, field{"source_content_byte_length", tagInt64, int64Bytes(l.SourceContentByteLength)})
	if err := addString(&fs, "canonical_representation_profile_ref", l.CanonicalRepresentationProfileRef); err != nil {
		return nil, err
	}
	if err := addDigest(&fs, "canonical_representation_profile_digest", l.CanonicalRepresentationProfileDigest); err != nil {
		return nil, err
	}
	fs = append(fs, field{"byte_start_offset", tagInt64, int64Bytes(l.ByteStartOffset)}, field{"byte_end_offset_exclusive", tagInt64, int64Bytes(l.ByteEndOffsetExclusive)})
	if err := addDigest(&fs, "selected_range_content_hash", l.SelectedRangeContentHash); err != nil {
		return nil, err
	}
	fs = append(fs, field{"selected_range_byte_count", tagInt64, int64Bytes(l.SelectedRangeByteCount)})
	if err := addUUID(&fs, "evidence_archive_deletion_domain_id", l.EvidenceArchiveDeletionDomainID); err != nil {
		return nil, err
	}
	if err := addUUID(&fs, "evidence_archive_crypto_shred_domain_id", l.EvidenceArchiveCryptoShredDomainID); err != nil {
		return nil, err
	}
	return fs, nil
}

// CanonicalPreimage returns the exact OODGCFE1 s6 preimage, not a JSON or
// delimiter encoding.
func (l GraphFactLocator) CanonicalPreimage() ([]byte, error) {
	fs, e := l.fields()
	if e != nil {
		return nil, e
	}
	out := []byte("OODGCFE1")
	out = appendU32(out, uint32(len(fs)))
	for _, f := range fs {
		out = appendU32(out, uint32(len(f.name)))
		out = append(out, []byte(f.name)...)
		out = append(out, f.tag, present)
		out = appendU64(out, uint64(len(f.value)))
		out = append(out, f.value...)
	}
	return out, nil
}
func (l GraphFactLocator) ComputedHash() (string, error) {
	p, e := l.CanonicalPreimage()
	if e != nil {
		return "", e
	}
	s := sha256.Sum256(p)
	return hex.EncodeToString(s[:]), nil
}

func VerifyGraphFactLocator(ctx context.Context, l GraphFactLocator, body []byte) (VerifiedByteBinding, error) {
	if err := ctx.Err(); err != nil {
		return VerifiedByteBinding{}, err
	}
	if l.SourceContentByteLength < 0 || l.ByteStartOffset < 0 || l.ByteEndOffsetExclusive <= l.ByteStartOffset || l.ByteEndOffsetExclusive > l.SourceContentByteLength || l.SelectedRangeByteCount != l.ByteEndOffsetExclusive-l.ByteStartOffset {
		return VerifiedByteBinding{}, errors.New("invalid half-open range binding")
	}
	if int64(len(body)) != l.SourceContentByteLength {
		return VerifiedByteBinding{}, errors.New("supplied body length does not match locator")
	}
	full := sha256.Sum256(body)
	if hex.EncodeToString(full[:]) != l.SourceContentHash {
		return VerifiedByteBinding{}, errors.New("supplied body digest does not match locator")
	}
	if err := ctx.Err(); err != nil {
		return VerifiedByteBinding{}, err
	}
	r := body[int(l.ByteStartOffset):int(l.ByteEndOffsetExclusive)]
	rs := sha256.Sum256(r)
	if hex.EncodeToString(rs[:]) != l.SelectedRangeContentHash {
		return VerifiedByteBinding{}, errors.New("selected range digest does not match locator")
	}
	if int64(len(r)) != l.SelectedRangeByteCount {
		return VerifiedByteBinding{}, errors.New("selected range length does not match locator")
	}
	want, e := l.ComputedHash()
	if e != nil {
		return VerifiedByteBinding{}, e
	}
	if l.LocatorHash != want {
		return VerifiedByteBinding{}, errors.New("locator hash does not match exact canonical preimage")
	}
	return VerifiedByteBinding{l.LocatorHash, l.SourceContentHash, l.SourceContentByteLength, l.ByteStartOffset, l.ByteEndOffsetExclusive, l.SelectedRangeContentHash, l.SelectedRangeByteCount}, nil
}
