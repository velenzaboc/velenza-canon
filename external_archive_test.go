package main

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

func TestProtectedExternalArchiveRequestRejectsInvalidControlsBeforeAdapterCall(t *testing.T) {
	source := []byte("exact")
	sum := sha256.Sum256(source)
	request := externalEvidenceArchiveRequest{
		OrganizationID: "org-test", SourceBytes: source,
		SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: externalEvidenceHashProfile,
		SourceContentHash:                 hex.EncodeToString(sum[:]),
		BodyStorageAuthorizationReference: "storage-auth", BodyRetentionHoldReference: "hold",
		DeletionDomainID: "not-a-uuid", CryptoShredDomainID: "99999999-9999-4999-8999-999999999999",
	}
	if err := validateExternalEvidenceArchiveRequest(request, 1024); err == nil || !strings.Contains(err.Error(), "canonical lowercase UUID") {
		t.Fatalf("invalid deletion-domain error=%v", err)
	}
	request.DeletionDomainID = "88888888-8888-4888-8888-888888888888"
	request.SourceContentHashProfile = "alternate-profile"
	if err := validateExternalEvidenceArchiveRequest(request, 1024); err == nil || !strings.Contains(err.Error(), "exact transport-decoded") {
		t.Fatalf("noncanonical source profile error=%v", err)
	}
}

func TestProtectedExternalArchiveRequestExposesNoCallerCredentialOrOrdinaryNamespaceField(t *testing.T) {
	typeOfRequest := reflect.TypeOf(externalEvidenceArchiveRequest{})
	for i := 0; i < typeOfRequest.NumField(); i++ {
		field := typeOfRequest.Field(i).Name
		for _, forbidden := range []string{"Bearer", "UserAssertion", "PrincipalID", "Token", "Credential", "ParentID", "FileName", "RefName"} {
			if strings.Contains(field, forbidden) {
				t.Fatalf("protected archive request exposes forbidden field %q", field)
			}
		}
	}
}

func TestExternalArchiveRecordDigestGoldenCanonicalFieldEncoding(t *testing.T) {
	receipt := externalEvidenceArchiveReceipt{
		OrganizationID: "org-test", ArchiveAuthorityID: "66666666-6666-4666-8666-666666666666",
		FileID: "77777777-7777-4777-8777-777777777777", ExplicitVersion: 3,
		AGFSContentHash: strings.Repeat("a", 64), SourceByteLength: 26,
		SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: externalEvidenceHashProfile, SourceContentHash: strings.Repeat("b", 64),
		BodyStorageAuthorizationReference: "storage-auth", BodyRetentionHoldReference: "hold",
		DeletionDomainID: "88888888-8888-4888-8888-888888888888", CryptoShredDomainID: "99999999-9999-4999-8999-999999999999",
	}
	digest, err := externalEvidenceArchiveRecordDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	const want = "9acf63b6fc23ac4ac0e1985e2fc7a67622bd70f79b338dd3ddea0a586e2c8e05"
	if digest != want {
		t.Fatalf("archive digest=%s, want %s", digest, want)
	}
}
