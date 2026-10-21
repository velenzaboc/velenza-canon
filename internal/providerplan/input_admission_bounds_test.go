package providerplan

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestInputAdmissionBoundsLimitsReservationsAndReceiptsFailClosed(t *testing.T) {
	limits := canonicalProviderInputAdmissionLimits
	if err := validateProviderInputAdmissionLimits(limits); err != nil {
		t.Fatalf("canonical limits: %v", err)
	}
	bad := limits
	bad.EvidenceManifestBytesPerFile = bad.EvidenceManifestBytesPerCorpus + 1
	if err := validateProviderInputAdmissionLimits(bad); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("inconsistent limit error=%v", err)
	}
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := accumulator.reserve(providerInputAdmissionResourceKindManifest, -1); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative reservation error=%v", err)
	}
	if err := accumulator.reserve("invented", 1); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown reservation kind error=%v", err)
	}
	if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindManifest, -1); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative path count error=%v", err)
	}
	digest := strings.Repeat("a", 64)
	resource, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{ResourceKind: providerInputAdmissionResourceKindManifest, StableCoordinate: "manifest/a", ContentSHA256: digest, ContentBytes: 1})
	if err != nil || !isLowerSHA256(resource.ResourceReceiptSHA256) {
		t.Fatalf("seal manifest receipt=%#v err=%v", resource, err)
	}
	if _, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{ResourceKind: providerInputAdmissionResourceKindManifest, StableCoordinate: "manifest/a", ContentSHA256: digest, ContentBytes: 1, DecodedContentSHA256: digest, DecodedContentBytes: 1}); err == nil || !strings.Contains(err.Error(), "non-carrier") {
		t.Fatalf("manifest decoded tuple error=%v", err)
	}
	if _, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{ResourceKind: providerInputAdmissionResourceKindCarrier, StableCoordinate: "carrier/a", ContentSHA256: digest, ContentBytes: 4}); err == nil || !strings.Contains(err.Error(), "decoded") {
		t.Fatalf("incomplete carrier tuple error=%v", err)
	}
	if err := accumulator.addResource(resource); err != nil {
		t.Fatalf("add sealed resource: %v", err)
	}
	if err := accumulator.addResource(resource); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate resource error=%v", err)
	}
}

func TestInputAdmissionBoundsStrictBase64AndHashingAreExact(t *testing.T) {
	readAll := func(raw string) ([]byte, error) {
		return io.ReadAll(newStrictTrimmedBase64Reader(strings.NewReader(raw)))
	}
	if value, err := readAll(" \n YWJjZA==\t"); err != nil || string(value) != "YWJjZA==" {
		t.Fatalf("trimmed base64=%q err=%v", value, err)
	}
	if _, err := readAll("YWJj ZA=="); err == nil || !strings.Contains(err.Error(), "internal") {
		t.Fatalf("internal base64 whitespace error=%v", err)
	}
	if _, err := readAll("YWJj$A=="); err == nil || !strings.Contains(err.Error(), "noncanonical") {
		t.Fatalf("invalid base64 byte error=%v", err)
	}
	reader := newHashingCountingReader(bytes.NewBufferString("exact bytes"))
	value, err := io.ReadAll(reader)
	if err != nil || string(value) != "exact bytes" || reader.count != int64(len(value)) || reader.passes != 1 || reader.sha256() != sha256Hex(value) {
		t.Fatalf("hashing reader value=%q count=%d passes=%d hash=%q err=%v", value, reader.count, reader.passes, reader.sha256(), err)
	}
	if length, err := safeProviderInputAllocationLength(-1); err == nil || length != 0 {
		t.Fatalf("negative allocation length=%d err=%v", length, err)
	}
	if encoded, err := expectedPaddedBase64Bytes(4); err != nil || encoded != 8 {
		t.Fatalf("padded base64 length=%d err=%v", encoded, err)
	}
}

func TestInputAdmissionBoundsEvidencePairingAndResourceRootsAreDeterministic(t *testing.T) {
	digestA, digestB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	resources := []providerInputAdmissionResourceReceipt{
		{ResourceKind: providerInputAdmissionResourceKindBody, StableCoordinate: "source/a", ContentSHA256: digestA, ContentBytes: 4},
		{ResourceKind: providerInputAdmissionResourceKindCarrier, StableCoordinate: "source/a", ContentSHA256: digestB, ContentBytes: 8, DecodedContentSHA256: digestA, DecodedContentBytes: 4},
	}
	for index := range resources {
		sealed, err := sealProviderInputAdmissionResource(resources[index])
		if err != nil {
			t.Fatal(err)
		}
		resources[index] = sealed
	}
	if err := validateProviderInputAdmissionEvidenceResourcePairs(resources); err != nil {
		t.Fatalf("matched evidence pair: %v", err)
	}
	root, err := providerInputAdmissionResourceSetRoot(resources)
	if err != nil || !isLowerSHA256(root) {
		t.Fatalf("resource root=%q err=%v", root, err)
	}
	reversed := []providerInputAdmissionResourceReceipt{resources[1], resources[0]}
	otherRoot, err := providerInputAdmissionResourceSetRoot(reversed)
	if err != nil || otherRoot != root {
		t.Fatalf("order-independent root=%q want %q err=%v", otherRoot, root, err)
	}
	reversed[1].StableCoordinate = "source/other"
	if err := validateProviderInputAdmissionEvidenceResourcePairs(reversed); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("unpaired evidence coordinate error=%v", err)
	}
}
