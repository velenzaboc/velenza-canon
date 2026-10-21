package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func externalAuthorizationBoundsFixture(t *testing.T, custody string) (externalSourceAuthorizationRequest, externalSourceAuthorization) {
	t.Helper()
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	policy := tlsTestExternalPolicy("https://example.com/docs")
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID:     bootstrapSourceAuthority,
		SourceArtifactClass:   policy.SourceArtifactClass,
		SourceRefKind:         "coordinate",
		SourceStableReference: "https://example.com/docs/page",
		SectionPath:           SectionPathRoot,
	}
	request := externalSourceAuthorizationRequest{
		OrganizationID:        "org-test",
		ObjectClass:           "reference_page",
		SourceRegistryID:      policy.ID,
		SourceArtifactClass:   policy.SourceArtifactClass,
		SourceAuthorityID:     coord.SourceAuthorityID,
		SourceRefKind:         coord.SourceRefKind,
		SourceStableReference: coord.SourceStableReference,
		PermissionOperation:   externalFetchPermissionOperation,
		PermissionMethod:      "GET",
		ObservedAt:            now,
	}
	answer := validTestExternalAuthorization(request.OrganizationID, request.ObjectClass, policy, coord, now, custody)
	if err := validateExternalSourceAuthorization(request, answer); err != nil {
		t.Fatalf("canonical authorization fixture: %v", err)
	}
	return request, answer
}

func TestExternalAuthorizationRefusalMatrix(t *testing.T) {
	request, canonical := externalAuthorizationBoundsFixture(t, externalBodyCustodyNone)
	tests := []struct {
		name   string
		want   string
		mutate func(*externalSourceAuthorizationRequest, *externalSourceAuthorization)
	}{
		{"request incomplete", "request is incomplete", func(r *externalSourceAuthorizationRequest, _ *externalSourceAuthorization) {
			r.ObservedAt = time.Time{}
		}},
		{"binding mismatch", "does not bind", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionMethod = "POST"
		}},
		{"noncanonical coordinate", "empty or noncanonical", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.ExternalFetchProfileRef = " padded "
		}},
		{"uuid malformed", "not a UUID", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionGrantID = "bad"
		}},
		{"uuid uppercase", "canonical lowercase UUID", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.ReceiptDeletionDomainID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
		}},
		{"digest malformed", "external_fetch_profile_digest", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.ExternalFetchProfileDigest = "bad"
		}},
		{"hash profile", "source_content_hash_profile", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.SourceContentHashProfile = "other"
		}},
		{"representation kind", "outside the closed contract", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.SourceRepresentationKind = "screen_scrape"
		}},
		{"media type", "canonical lowercase media type", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.SourceRepresentationMediaType = "text/html; charset=utf-8"
		}},
		{"permission status", "not affirmative", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionStatus = "pending"
		}},
		{"byte ceiling", "ceiling is invalid", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionByteCeiling = 0
		}},
		{"effective missing", "permission_effective_at is required", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionEffectiveAt = ""
		}},
		{"effective malformed", "not canonical UTC RFC3339", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionEffectiveAt = "yesterday"
		}},
		{"not effective", "not yet effective", func(r *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionEffectiveAt = r.ObservedAt.Add(time.Minute).Format(time.RFC3339Nano)
		}},
		{"expiry malformed", "not canonical UTC RFC3339", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionExpiresAt = "tomorrow"
		}},
		{"expired", "expired", func(r *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionExpiresAt = r.ObservedAt.Format(time.RFC3339Nano)
		}},
		{"expected tuple partial", "triple", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionExpectedHashAlgorithm = "sha256"
		}},
		{"expected tuple profile", "different algorithm", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionExpectedHashAlgorithm = "sha256"
			a.PermissionExpectedHashProfile = "other"
			a.PermissionExpectedHash = strings.Repeat("a", 64)
		}},
		{"expected digest", "expected content hash", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.PermissionExpectedHashAlgorithm = "sha256"
			a.PermissionExpectedHashProfile = a.SourceContentHashProfile
			a.PermissionExpectedHash = "bad"
		}},
		{"custody none coordinates", "must not carry AGFS", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.BodyStorageAuthorizationReference = "unexpected"
		}},
		{"custody kind", "outside the closed contract", func(_ *externalSourceAuthorizationRequest, a *externalSourceAuthorization) {
			a.BodyCustodyDisposition = "local_file"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := request
			a := canonical
			test.mutate(&r, &a)
			if err := validateExternalSourceAuthorization(r, a); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("authorization error=%v, want substring %q", err, test.want)
			}
		})
	}
	if value, err := parseCanonicalAuthorizationTime("optional", "", false); err != nil || !value.IsZero() {
		t.Fatalf("optional empty time=%v err=%v", value, err)
	}
}

func TestExternalAuthorizationAGFSCustodyRefusals(t *testing.T) {
	request, canonical := externalAuthorizationBoundsFixture(t, externalBodyCustodyAGFS)
	tests := []struct {
		name   string
		want   string
		mutate func(*externalSourceAuthorization)
	}{
		{"missing coordinate", "requires body_storage", func(a *externalSourceAuthorization) { a.BodyStorageAuthorizationReference = "" }},
		{"invalid domain UUID", "not a canonical UUID", func(a *externalSourceAuthorization) { a.ArchiveDeletionDomainID = "bad" }},
		{"uppercase domain UUID", "canonical lowercase UUID", func(a *externalSourceAuthorization) {
			a.ArchiveDeletionDomainID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			answer := canonical
			test.mutate(&answer)
			if err := validateExternalSourceAuthorization(request, answer); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("AGFS authorization error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func externalArchiveBoundsFixture(t *testing.T) (externalEvidenceArchiveRequest, externalEvidenceArchiveReceipt) {
	t.Helper()
	_, authorization := externalAuthorizationBoundsFixture(t, externalBodyCustodyAGFS)
	body := []byte("exact archived source bytes")
	sum := sha256.Sum256(body)
	request := externalEvidenceArchiveRequest{
		OrganizationID:                    authorization.OrganizationID,
		SourceBytes:                       body,
		SourceContentHashAlgorithm:        "sha256",
		SourceContentHashProfile:          externalEvidenceHashProfile,
		SourceContentHash:                 hex.EncodeToString(sum[:]),
		BodyStorageAuthorizationReference: authorization.BodyStorageAuthorizationReference,
		BodyRetentionHoldReference:        authorization.BodyRetentionHoldReference,
		DeletionDomainID:                  authorization.ArchiveDeletionDomainID,
		CryptoShredDomainID:               authorization.ArchiveCryptoShredDomainID,
	}
	if err := validateExternalEvidenceArchiveRequest(request, 1024); err != nil {
		t.Fatalf("canonical archive request: %v", err)
	}
	receipt := *testExternalArchiveReceipt(authorization, int64(len(body)), request.SourceContentHash)
	if err := validateExternalEvidenceArchiveReceiptForRequest(request, receipt); err != nil {
		t.Fatalf("canonical archive receipt: %v", err)
	}
	return request, receipt
}

func TestExternalArchiveRequestAndReceiptRefusalMatrix(t *testing.T) {
	canonicalRequest, canonicalReceipt := externalArchiveBoundsFixture(t)
	requestTests := []struct {
		name   string
		want   string
		limit  int64
		mutate func(*externalEvidenceArchiveRequest)
	}{
		{"organization", "organization coordinate", 1024, func(r *externalEvidenceArchiveRequest) { r.OrganizationID = " padded " }},
		{"empty body", "empty source", 1024, func(r *externalEvidenceArchiveRequest) { r.SourceBytes = nil }},
		{"body ceiling", "archive ceiling", 1, func(*externalEvidenceArchiveRequest) {}},
		{"hash contract", "SHA-256", 1024, func(r *externalEvidenceArchiveRequest) { r.SourceContentHashAlgorithm = "sha1" }},
		{"digest mismatch", "digest does not match", 1024, func(r *externalEvidenceArchiveRequest) { r.SourceContentHash = strings.Repeat("a", 64) }},
		{"control missing", "requires", 1024, func(r *externalEvidenceArchiveRequest) { r.BodyRetentionHoldReference = "" }},
		{"domain malformed", "canonical lowercase UUID", 1024, func(r *externalEvidenceArchiveRequest) { r.DeletionDomainID = "bad"; r.CryptoShredDomainID = "bad" }},
		{"domain uppercase", "canonical lowercase UUID", 1024, func(r *externalEvidenceArchiveRequest) {
			r.DeletionDomainID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
			r.CryptoShredDomainID = "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB"
		}},
	}
	for _, test := range requestTests {
		t.Run("request "+test.name, func(t *testing.T) {
			request := canonicalRequest
			request.SourceBytes = append([]byte(nil), canonicalRequest.SourceBytes...)
			test.mutate(&request)
			if err := validateExternalEvidenceArchiveRequest(request, test.limit); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("archive request error=%v, want substring %q", err, test.want)
			}
		})
	}

	receiptTests := []struct {
		name   string
		want   string
		mutate func(*externalEvidenceArchiveReceipt)
	}{
		{"incomplete", "incomplete", func(r *externalEvidenceArchiveReceipt) { r.FileID = "" }},
		{"hash contract", "canonical source hash", func(r *externalEvidenceArchiveReceipt) { r.SourceContentHashProfile = "other" }},
		{"hash malformed", "agfs_content_hash", func(r *externalEvidenceArchiveReceipt) { r.AGFSContentHash = "bad" }},
		{"control padded", "requires", func(r *externalEvidenceArchiveReceipt) { r.BodyRetentionHoldReference = " padded " }},
		{"body reference", "body reference hash mismatch", func(r *externalEvidenceArchiveReceipt) { r.AGFSBodyReferenceHash = strings.Repeat("a", 64) }},
		{"record digest", "receipt digest mismatch", func(r *externalEvidenceArchiveReceipt) { r.ArchiveRecordDigest = strings.Repeat("a", 64) }},
	}
	for _, test := range receiptTests {
		t.Run("receipt "+test.name, func(t *testing.T) {
			receipt := canonicalReceipt
			test.mutate(&receipt)
			if err := validateExternalEvidenceArchiveReceipt(receipt); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("archive receipt error=%v, want substring %q", err, test.want)
			}
		})
	}

	mismatch := canonicalRequest
	mismatch.BodyStorageAuthorizationReference = "different"
	if err := validateExternalEvidenceArchiveReceiptForRequest(mismatch, canonicalReceipt); err == nil || !strings.Contains(err.Error(), "exact authorized request") {
		t.Fatalf("request binding error=%v", err)
	}
}

func TestExternalArchiveRecordDigestRefusals(t *testing.T) {
	_, canonical := externalArchiveBoundsFixture(t)
	tests := []struct {
		name   string
		want   string
		mutate func(*externalEvidenceArchiveReceipt)
	}{
		{"negative bytes", "nonnegative", func(r *externalEvidenceArchiveReceipt) { r.SourceByteLength = -1 }},
		{"UUID malformed", "not canonical", func(r *externalEvidenceArchiveReceipt) { r.ArchiveAuthorityID = "bad" }},
		{"UUID uppercase", "canonical lowercase text", func(r *externalEvidenceArchiveReceipt) { r.ArchiveAuthorityID = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" }},
		{"digest hex", "decode", func(r *externalEvidenceArchiveReceipt) { r.SourceContentHash = "zz" }},
		{"digest length", "decodes to", func(r *externalEvidenceArchiveReceipt) { r.SourceContentHash = "aa" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := canonical
			test.mutate(&receipt)
			if _, err := externalEvidenceArchiveRecordDigest(receipt); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("archive digest error=%v, want substring %q", err, test.want)
			}
		})
	}
}
