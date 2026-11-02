package oodcanon

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// OOD v8 canonical_field_encoding_scalar_null_golden, independently checked
// against its owner-published SHA-256 vector.
func TestOwnerScalarGolden(t *testing.T) {
	d, _ := DigestHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	p := Profile{Name: "fixture", Fields: []Field{f("domain_separator", UTF8, Required, String("golden_scalar_v1")), f("enabled", Bool, Required), f("count", Int64, Required), f("digest", SHA256, Required), f("optional_note", UTF8, Nullable)}}
	r := RecordValue{"enabled": {Type: Bool, Presence: Present, Bytes: []byte{1}}, "count": I64(-2), "digest": d, "optional_note": NullValue(UTF8)}
	b, err := Encode(p, r)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("4f4f4447434645310000000500000010646f6d61696e5f736570617261746f7201010000000000000010676f6c64656e5f7363616c61725f763100000007656e61626c6564020100000000000000010100000005636f756e7403010000000000000008fffffffffffffffe0000000664696765737408010000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000d6f7074696f6e616c5f6e6f746501000000000000000000")
	if string(b) != string(want) {
		t.Fatalf("owner golden preimage mismatch: %x", b)
	}
	h := sha256.Sum256(b)
	if got := hex.EncodeToString(h[:]); got != "fd7ae8c8dbb92a2702afaedc6e13522507103ff1b433d8ed66a3fce5c6e73381" {
		t.Fatal(got)
	}
	r["enabled"], r["count"] = r["count"], r["enabled"]
	if _, err := Encode(p, r); err == nil {
		t.Fatal("type swap accepted")
	}
}

func TestClosedRecordRejectsMissingExtraAndInvalidUUID(t *testing.T) {
	p, err := ProfileFor("external_fetch_receipt_v1")
	if err != nil || len(p.Fields) != 65 {
		t.Fatalf("receipt owner roster: %v %d", err, len(p.Fields))
	}
	if _, err := Encode(p, RecordValue{}); err == nil {
		t.Fatal("missing closed fields accepted")
	}
	if _, err := UUIDText(strings.ToUpper("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")); err == nil {
		t.Fatal("noncanonical UUID accepted")
	}
	if _, err := ProfileFor("unowned_profile"); err != ErrUnsupportedProfile {
		t.Fatal(err)
	}
}

// OOD v8 canonical_encoder_unit_golden prescribes these values for every
// bound field.  This test exercises the complete copied receipt/batch rosters,
// rather than merely counting their fields.
func TestReceiptAndCompletenessOwnerGoldenVectors(t *testing.T) {
	for name, want := range map[string]string{
		"external_fetch_receipt_v1":               "a91f02d8f09655bd7dde566e5da7ace5c1286a61237bd7239e914356e300f394",
		"external_fetch_completeness_evidence_v3": "1b381aa1572ed63d975fbb421e292395ccb0725a2878e8d0f27139c256b9d6f6",
	} {
		p, err := ProfileFor(name)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DigestHexOf(p, ownerUnitFixture(p))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got != want {
			t.Fatalf("%s owner vector: got %s want %s", name, got, want)
		}
	}
}

func ownerUnitFixture(p Profile) RecordValue {
	digest, _ := DigestHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	uuid, _ := UUIDText("11111111-1111-4111-8111-111111111111")
	r := RecordValue{}
	for _, f := range p.Fields {
		if f.Literal != nil {
			continue
		}
		if f.Policy == Nullable || f.Policy == NullOnly {
			r[f.Name] = NullValue(f.Type)
			continue
		}
		switch f.Type {
		case UTF8:
			r[f.Name] = String("g:" + f.Name)
		case UUID:
			r[f.Name] = uuid
		case SHA256:
			r[f.Name] = digest
		case Int64:
			r[f.Name] = I64(1)
		case TimestampMicroseconds:
			r[f.Name] = Value{Type: TimestampMicroseconds, Presence: Present, Bytes: []byte{0, 0, 0, 0, 0, 0, 0, 1}}
		case Array:
			r[f.Name] = Value{Type: Array, Presence: Present}
		default:
			panic("fixture type")
		}
	}
	return r
}
