package main

import (
	"strings"
	"testing"
	"time"
)

func TestMaterializerBoundsExternalReceiptStorageIsCanonicalAndClosed(t *testing.T) {
	first := testExternalVerificationReceipt(time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC))
	values, err := canonicalExternalVerificationReceiptValues([]*stagedExternalVerificationReceipt{first})
	if err != nil || len(values) != 1 {
		t.Fatalf("canonical receipt values=%#v err=%v", values, err)
	}
	if _, err := canonicalExternalVerificationReceiptValues([]*stagedExternalVerificationReceipt{first, first}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate receipt coordinate error=%v", err)
	}
	invalid := *first
	invalid.TransportStatus = "pending"
	if err := validateStoredExternalVerificationReceiptShape(&invalid); err == nil || !strings.Contains(err.Error(), "transport status") {
		t.Fatalf("invalid receipt status error=%v", err)
	}
	compacted := compactExternalVerificationReceipts([]*stagedExternalVerificationReceipt{first, nil})
	if len(compacted) != 1 || compacted[0] == first || compacted[0].DecodedSHA256 != first.DecodedSHA256 {
		t.Fatalf("compacted receipts=%#v", compacted)
	}
}

func TestMaterializerBoundsStoredSourceSetAndReceiptTamperRefuse(t *testing.T) {
	receipt := testExternalVerificationReceipt(time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC))
	coordinate := SourceCoordinate{
		OrganizationID: "org-test", SourceAuthorityID: receipt.SourceAuthorityID,
		SourceArtifactClass: "official_vendor_documentation", SourceRefKind: "coordinate",
		SourceStableReference: receipt.VerifiedSourceStableReference, VersionCoordinate: receipt.FinalVersionCoordinate,
		SectionPath: SectionPathRoot, SourceContentHash: receipt.DecodedSHA256,
	}
	set, err := BuildSourceSetWithExternalReceipts(coordinate.OrganizationID, []SourceCoordinate{coordinate}, []*stagedExternalVerificationReceipt{receipt})
	if err != nil {
		t.Fatal(err)
	}
	coordinates, err := SourceCoordinatesFromStoredSet(coordinate.OrganizationID, set)
	if err != nil || len(coordinates) != 1 || coordinates[0] != coordinate {
		t.Fatalf("stored coordinates=%#v err=%v", coordinates, err)
	}
	receipts, err := ExternalVerificationReceiptsFromStoredSet(set)
	if err != nil || len(receipts) != 1 || receipts[0].DecodedSHA256 != receipt.DecodedSHA256 {
		t.Fatalf("stored receipts=%#v err=%v", receipts, err)
	}
	hash, err := ComputeSourceSetHash(coordinate.OrganizationID, []SourceCoordinate{coordinate})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateMaterializationSourceSet(coordinate.OrganizationID, hash, set); err != nil {
		t.Fatalf("closed stored source set: %v", err)
	}
	tampered := make(map[string]interface{}, len(set))
	for key, value := range set {
		tampered[key] = value
	}
	tampered[externalVerificationReceiptsSourceSetKey] = "not-an-array"
	if _, err := ExternalVerificationReceiptsFromStoredSet(tampered); err == nil || !strings.Contains(err.Error(), "want array") {
		t.Fatalf("receipt array type error=%v", err)
	}
	if _, err := SourceCoordinatesFromStoredSet("other-org", set); err == nil || !strings.Contains(err.Error(), "organization") {
		t.Fatalf("organization substitution error=%v", err)
	}
	if err := ValidateMaterializationSourceSet(coordinate.OrganizationID, strings.Repeat("a", 64), set); err == nil || !strings.Contains(err.Error(), "does not attest") {
		t.Fatalf("source-set hash substitution error=%v", err)
	}
}

func TestMaterializerBoundsCoordinateMergesAndStorageLimitAreDeterministic(t *testing.T) {
	first := testCoord("11111111-1111-4111-8111-111111111111", "https://example.com/a", "v1")
	second := testCoord("11111111-1111-4111-8111-111111111111", "https://example.com/b", "v1")
	merged := MergeSourceCoordinates([]SourceCoordinate{second, first}, []SourceCoordinate{first})
	if len(merged) != 2 || compareSourceCoordinates(merged[0], merged[1]) >= 0 {
		t.Fatalf("merged coordinates=%#v", merged)
	}
	if err := validateMaterializationSourceSetStorageBound(map[string]interface{}{"payload": strings.Repeat("x", maxMaterializationSourceSetCanonicalBytes+1)}); err == nil || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("storage ceiling error=%v", err)
	}
}
