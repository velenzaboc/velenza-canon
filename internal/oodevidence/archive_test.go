package oodevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestVerifyArchivedCanonicalBytesRejectsCrossBoundBody(t *testing.T) {
	r := ReceiptV8{}
	body := []byte("canonical")
	sum := sha256.Sum256(body)
	r.SourceContentHash = hex.EncodeToString(sum[:])
	r.EvidenceArchiveByteCount = int64(len(body))
	if err := VerifyArchivedCanonicalBytes(r, body); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArchivedCanonicalBytes(r, []byte("canonical!")); err == nil {
		t.Fatal("different archive body accepted")
	}
}

func TestValidateReceiptRolesRequiresClosedCanonicalSet(t *testing.T) {
	if err := ValidateReceiptRoles([]string{"completeness_evidence", "component", "profile_noncomponent:metadata"}, map[string]int64{"metadata": 1}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReceiptRoles([]string{"component", "completeness_evidence"}, nil); err == nil {
		t.Fatal("noncanonical order accepted")
	}
	if err := ValidateReceiptRoles([]string{"component", "component"}, nil); err == nil {
		t.Fatal("duplicate role accepted")
	}
	if err := ValidateReceiptRoles([]string{"profile_noncomponent:metadata"}, nil); err == nil {
		t.Fatal("unadmitted role accepted")
	}
}
