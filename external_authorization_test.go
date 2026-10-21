package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixedExternalAuthorizationResolver struct {
	mu     sync.Mutex
	answer externalSourceAuthorization
	err    error
	calls  []externalSourceAuthorizationRequest
}

func (r *fixedExternalAuthorizationResolver) AuthorizeExternalSource(_ context.Context, in externalSourceAuthorizationRequest) (externalSourceAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, in)
	return r.answer, r.err
}

func (r *fixedExternalAuthorizationResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

func validTestExternalAuthorization(orgID, objectClass string, policy ExternalSourceDescriptor, coord ArtifactSourceCoordinate, observedAt time.Time, custody string) externalSourceAuthorization {
	answer := externalSourceAuthorization{
		OrganizationID: orgID, ObjectClass: objectClass, SourceRegistryID: policy.ID,
		SourceArtifactClass: policy.SourceArtifactClass, SourceAuthorityID: coord.SourceAuthorityID,
		SourceAuthorityBindingID: "11111111-1111-4111-8111-111111111111", SourceAuthorityBindingDigest: strings.Repeat("1", 64),
		SourceRefKind: coord.SourceRefKind, SourceStableReference: coord.SourceStableReference,
		SourceRepresentationKind: "source_declared_machine_export", SourceRepresentationMediaType: "text/html",
		RepresentationDeclarationID: "22222222-2222-4222-8222-222222222222", RepresentationDeclarationDigest: strings.Repeat("2", 64),
		SourceContentHashProfile: externalEvidenceHashProfile,
		ExternalFetchProfileRef:  "external_fetch_profile/test/v1", ExternalFetchProfileDigest: strings.Repeat("3", 64),
		PermissionGrantID: "33333333-3333-4333-8333-333333333333", PermissionGrantDigest: strings.Repeat("4", 64),
		PermissionAuthorityID: "44444444-4444-4444-8444-444444444444", PermissionPrincipalID: "55555555-5555-4555-8555-555555555555",
		PermissionScopeDigest: strings.Repeat("5", 64), PermissionOperation: externalFetchPermissionOperation, PermissionMethod: "GET",
		PermissionRedirectPolicyDigest: strings.Repeat("6", 64), PermissionContentClass: "provider_documentation",
		PermissionTrustClass: policy.SourceArtifactClass, PermissionByteCeiling: maxExternalReferenceBytes, PermissionDepthCeiling: 0,
		PermissionEffectiveAt: observedAt.Add(-time.Hour).UTC().Format(time.RFC3339Nano),
		PermissionExpiresAt:   observedAt.Add(time.Hour).UTC().Format(time.RFC3339Nano), PermissionStatus: externalPermissionStatus,
		PermissionPolicyVersionRef: "permission_policy/test/v1", PermissionPolicyVersionDigest: strings.Repeat("7", 64),
		FetchAuthorizationDecisionRef: "gate_decision/test/v1", FetchAuthorizationDecisionDigest: strings.Repeat("8", 64),
		BodyCustodyDisposition:  custody,
		ReceiptDeletionDomainID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ReceiptCryptoShredDomainID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	}
	if custody == externalBodyCustodyAGFS {
		answer.BodyStorageAuthorizationReference = "storage-authorization/test/v1"
		answer.BodyRetentionHoldReference = "retention-hold/test/v1"
		answer.ArchiveDeletionDomainID = "88888888-8888-4888-8888-888888888888"
		answer.ArchiveCryptoShredDomainID = "99999999-9999-4999-8999-999999999999"
	}
	return answer
}

func testExternalArchiveReceipt(auth externalSourceAuthorization, byteLength int64, sourceDigest string) *externalEvidenceArchiveReceipt {
	receipt := externalEvidenceArchiveReceipt{
		OrganizationID:     auth.OrganizationID,
		ArchiveAuthorityID: "66666666-6666-4666-8666-666666666666", FileID: "77777777-7777-4777-8777-777777777777",
		ExplicitVersion: 1, AGFSContentHash: strings.Repeat("9", 64),
		SourceByteLength: byteLength, SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: auth.SourceContentHashProfile, SourceContentHash: sourceDigest,
		BodyStorageAuthorizationReference: auth.BodyStorageAuthorizationReference, BodyRetentionHoldReference: auth.BodyRetentionHoldReference,
		DeletionDomainID: auth.ArchiveDeletionDomainID, CryptoShredDomainID: auth.ArchiveCryptoShredDomainID,
	}
	bodyReferenceHash, err := externalAGFSBodyReferenceHash(receipt)
	if err != nil {
		panic(err)
	}
	receipt.AGFSBodyReferenceHash = bodyReferenceHash
	digest, err := externalEvidenceArchiveRecordDigest(receipt)
	if err != nil {
		panic(err)
	}
	receipt.ArchiveRecordDigest = digest
	return &receipt
}

type memoryExternalEvidenceArchive struct {
	mu       sync.Mutex
	requests []externalEvidenceArchiveRequest
	bodies   map[string][]byte
	err      error
}

type selectedDigestTamperingArchive struct{ externalEvidenceArchive }

type sourceByteMutatingArchive struct {
	delegate *memoryExternalEvidenceArchive
	mutated  bool
}

type hydrationResultAliasingArchive struct {
	externalEvidenceArchive
	retained []byte
}

func (a *sourceByteMutatingArchive) Archive(ctx context.Context, in externalEvidenceArchiveRequest) (externalEvidenceArchiveReceipt, error) {
	original := append([]byte(nil), in.SourceBytes...)
	for i := range in.SourceBytes {
		in.SourceBytes[i] = 'x'
	}
	a.mutated = true
	in.SourceBytes = original
	return a.delegate.Archive(ctx, in)
}

func (a *sourceByteMutatingArchive) Hydrate(ctx context.Context, in externalEvidenceHydrationRequest) (externalEvidenceHydrationResult, error) {
	return a.delegate.Hydrate(ctx, in)
}

func (a *hydrationResultAliasingArchive) Hydrate(ctx context.Context, in externalEvidenceHydrationRequest) (externalEvidenceHydrationResult, error) {
	result, err := a.externalEvidenceArchive.Hydrate(ctx, in)
	if err == nil {
		a.retained = result.Bytes
	}
	return result, err
}

func (a selectedDigestTamperingArchive) Hydrate(ctx context.Context, in externalEvidenceHydrationRequest) (externalEvidenceHydrationResult, error) {
	result, err := a.externalEvidenceArchive.Hydrate(ctx, in)
	if err == nil {
		result.SelectedRangeSHA256 = strings.Repeat("f", 64)
	}
	return result, err
}

func (a *memoryExternalEvidenceArchive) Archive(_ context.Context, in externalEvidenceArchiveRequest) (externalEvidenceArchiveReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.requests = append(a.requests, in)
	if a.err != nil {
		return externalEvidenceArchiveReceipt{}, a.err
	}
	if a.bodies == nil {
		a.bodies = map[string][]byte{}
	}
	fileID := fmt.Sprintf("77777777-7777-4777-8777-%012d", len(a.requests))
	a.bodies[fileID] = append([]byte(nil), in.SourceBytes...)
	receipt := externalEvidenceArchiveReceipt{
		OrganizationID:     in.OrganizationID,
		ArchiveAuthorityID: "66666666-6666-4666-8666-666666666666", FileID: fileID, ExplicitVersion: 1,
		AGFSContentHash: strings.Repeat("9", 64), SourceByteLength: int64(len(in.SourceBytes)),
		SourceContentHashAlgorithm: in.SourceContentHashAlgorithm, SourceContentHashProfile: in.SourceContentHashProfile, SourceContentHash: in.SourceContentHash,
		BodyStorageAuthorizationReference: in.BodyStorageAuthorizationReference, BodyRetentionHoldReference: in.BodyRetentionHoldReference,
		DeletionDomainID: in.DeletionDomainID, CryptoShredDomainID: in.CryptoShredDomainID,
	}
	bodyReferenceHash, err := externalAGFSBodyReferenceHash(receipt)
	if err != nil {
		return externalEvidenceArchiveReceipt{}, err
	}
	receipt.AGFSBodyReferenceHash = bodyReferenceHash
	recordDigest, err := externalEvidenceArchiveRecordDigest(receipt)
	if err != nil {
		return externalEvidenceArchiveReceipt{}, err
	}
	receipt.ArchiveRecordDigest = recordDigest
	return receipt, nil
}

func (a *memoryExternalEvidenceArchive) Hydrate(_ context.Context, in externalEvidenceHydrationRequest) (externalEvidenceHydrationResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	body := a.bodies[in.Archive.FileID]
	if in.Start < 0 || in.End < in.Start || in.End > int64(len(body)) {
		return externalEvidenceHydrationResult{}, fmt.Errorf("range outside archived bytes")
	}
	selected := append([]byte(nil), body[in.Start:in.End]...)
	sum := sha256.Sum256(selected)
	return externalEvidenceHydrationResult{
		Bytes: selected, SelectedRangeSHA256: hex.EncodeToString(sum[:]), SourceContentHash: in.Archive.SourceContentHash,
		ArchiveRecordDigest: in.Archive.ArchiveRecordDigest, FileID: in.Archive.FileID, ExplicitVersion: in.Archive.ExplicitVersion,
	}, nil
}

func externalAuthorizationFlowFixture(t *testing.T, custody string) (*Env, ArtifactSubmission, ArtifactSourceCoordinate, string, *memoryExternalEvidenceArchive, *fixedExternalAuthorizationResolver) {
	t.Helper()
	env, _ := newSourceCoordinateEnv(t)
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	env.Now = func() time.Time { return now }
	env.ExternalFetch = deterministicExternalFetcher{retrievedAt: now}
	policy := env.Config.ExternalSources[0]
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID: bootstrapSourceAuthority, SourceArtifactClass: policy.SourceArtifactClass,
		SourceRefKind: "coordinate", SourceStableReference: policy.ReferencePrefix + "/api/invoice#symbol=invoice_api_symbol",
		SectionPath: SectionPathRoot, LicenseEvidence: policy.RetrievalPermissionEvidenceCoordinates[0],
	}
	canonicalName, err := canonicalExternalLocatorName("api_symbol", coord, policy, "invoice_api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	authorizer := &fixedExternalAuthorizationResolver{answer: validTestExternalAuthorization("org-test", "api_symbol", policy, coord, now, custody)}
	archive := &memoryExternalEvidenceArchive{}
	env.ExternalAuthorize = authorizer
	env.ExternalArchive = archive
	sub := ArtifactSubmission{NodeKind: "api_symbol", StableID: canonicalName, SourceCoordinate: &coord}
	return env, sub, coord, canonicalName, archive, authorizer
}

func TestExternalAuthorizationRunsBeforeAnySourceNetworkCall(t *testing.T) {
	env, _, coord, _, _, _ := externalAuthorizationFlowFixture(t, externalBodyCustodyAGFS)
	policy := env.Config.ExternalSources[0]
	calls := 0
	env.ExternalFetch = countingRefusingExternalFetcher{calls: &calls}
	env.ExternalAuthorize = nil
	_, err := fetchExternalSourceReceipt(context.Background(), env, "org-test", "api_symbol", coord, policy)
	if !strings.Contains(fmt.Sprint(err), "admitted external-source authorization resolver required") {
		t.Fatalf("missing resolver error=%v", err)
	}
	if calls != 0 {
		t.Fatalf("source network was called %d time(s) before authorization", calls)
	}

	wrongTenant := validTestExternalAuthorization("org-other", "api_symbol", policy, coord, env.Now(), externalBodyCustodyAGFS)
	env.ExternalAuthorize = &fixedExternalAuthorizationResolver{answer: wrongTenant}
	_, err = fetchExternalSourceReceipt(context.Background(), env, "org-test", "api_symbol", coord, policy)
	if !strings.Contains(fmt.Sprint(err), "exact tenant") || calls != 0 {
		t.Fatalf("tenant-mismatched authorization error=%v network_calls=%d", err, calls)
	}
}

func TestExternalAuthorizationRejectsNoncanonicalRepresentationMediaType(t *testing.T) {
	env, _, coord, _, _, authorizer := externalAuthorizationFlowFixture(t, externalBodyCustodyAGFS)
	policy := env.Config.ExternalSources[0]
	authorizer.answer.SourceRepresentationMediaType = "Text/HTML; Charset=UTF-8"
	calls := 0
	env.ExternalFetch = countingRefusingExternalFetcher{calls: &calls}
	_, err := fetchExternalSourceReceipt(context.Background(), env, "org-test", "api_symbol", coord, policy)
	if err == nil || !strings.Contains(err.Error(), "canonical lowercase media type") {
		t.Fatalf("noncanonical media type error=%v", err)
	}
	if calls != 0 {
		t.Fatalf("noncanonical media type performed %d source fetch(es)", calls)
	}
}

func TestAdmittedExpectedHashMismatchPreventsArchive(t *testing.T) {
	env, sub, coord, canonicalName, archive, authorizer := externalAuthorizationFlowFixture(t, externalBodyCustodyAGFS)
	authorizer.answer.PermissionExpectedHashAlgorithm = "sha256"
	authorizer.answer.PermissionExpectedHashProfile = externalEvidenceHashProfile
	authorizer.answer.PermissionExpectedHash = strings.Repeat("f", 64)
	desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	_, _, receipt, err := validateExternalReferenceSubmissionForStaging(context.Background(), env, sub, canonicalName, desc, coord)
	if err == nil || !strings.Contains(err.Error(), "admitted expected source_content_hash") || receipt != nil {
		t.Fatalf("expected-hash mismatch result receipt=%+v error=%v", receipt, err)
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if len(archive.requests) != 0 {
		t.Fatalf("expected-hash mismatch performed %d archive write(s)", len(archive.requests))
	}
}

func TestCanonicalDecodedEvidenceIsArchivedBeforeLocatorParsing(t *testing.T) {
	env, sub, coord, canonicalName, archive, _ := externalAuthorizationFlowFixture(t, externalBodyCustodyAGFS)
	policy := env.Config.ExternalSources[0]
	decoded := []byte(`<html><body><span id="different_symbol">wrong locator</span></body></html>`)
	wire := gzipExternalTestBytes(t, decoded)
	rawSum := sha256.Sum256(wire)
	decodedSum := sha256.Sum256(decoded)
	env.ExternalFetch = externalReferenceFetcherFunc(func(_ context.Context, reference string, selected ExternalSourceDescriptor, authority string) (verifiedExternalSourceReceipt, error) {
		resource, err := externalResourceReference(reference, selected)
		if err != nil {
			return verifiedExternalSourceReceipt{}, err
		}
		metadataDigest, err := externalTransportResponseMetadataDigest(externalTransportResponseMetadata{
			StatusCode: 200, ContentEncoding: "gzip", MediaType: "text/html",
		})
		if err != nil {
			return verifiedExternalSourceReceipt{}, err
		}
		return verifiedExternalSourceReceipt{
			CanonicalReference: resource, RetrievedAt: env.Now(), ByteLength: int64(len(wire)), SHA256: hex.EncodeToString(rawSum[:]),
			TransportStatus: "success", TransportRawHashAlgorithm: "sha256",
			ContentCoding: "gzip", TransportResponseMetadataDigest: metadataDigest,
			DecodedByteLength: int64(len(decoded)), DecodedSHA256: hex.EncodeToString(decodedSum[:]),
			SourceRepresentationMediaType: "text/html",
			SourceRegistryID:              selected.ID, SourceAuthorityID: authority, Body: wire, LocatorBody: decoded,
		}, nil
	})
	desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = validateExternalReferenceSubmissionForStaging(context.Background(), env, sub, canonicalName, desc, coord)
	if err == nil || !strings.Contains(err.Error(), "does not resolve in the exact fetched bytes") {
		t.Fatalf("locator error=%v", err)
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if len(archive.requests) != 1 {
		t.Fatalf("archive calls=%d, want one before locator refusal", len(archive.requests))
	}
	if !bytes.Equal(archive.requests[0].SourceBytes, decoded) {
		t.Fatalf("archived bytes are not the canonical transport-decoded representation")
	}
	if archive.requests[0].SourceContentHash != hex.EncodeToString(decodedSum[:]) || archive.requests[0].SourceContentHash == hex.EncodeToString(rawSum[:]) {
		t.Fatalf("archive source identity did not separate decoded evidence from raw transfer")
	}
	_ = policy
}

func TestArchiveAdapterCannotMutateBytesLaterParsed(t *testing.T) {
	env, sub, coord, canonicalName, _, _ := externalAuthorizationFlowFixture(t, externalBodyCustodyAGFS)
	delegate := &memoryExternalEvidenceArchive{}
	mutating := &sourceByteMutatingArchive{delegate: delegate}
	env.ExternalArchive = mutating
	desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
	if err != nil {
		t.Fatal(err)
	}

	verified, _, receipt, err := validateExternalReferenceSubmissionForStaging(context.Background(), env, sub, canonicalName, desc, coord)
	if err != nil {
		t.Fatalf("archive adapter mutated the canonical bytes later consumed by locator parsing: %v", err)
	}
	if !mutating.mutated {
		t.Fatal("adversarial archive adapter did not exercise its source-byte alias")
	}
	body := trustedExternalTestBody(coord.SourceStableReference)
	sum := sha256.Sum256(body)
	if verified.SourceContentHash != hex.EncodeToString(sum[:]) || receipt == nil || receipt.Archive == nil {
		t.Fatalf("verified coordinate or durable archive binding changed after adapter mutation: coordinate=%+v receipt=%+v", verified, receipt)
	}
	delegate.mu.Lock()
	defer delegate.mu.Unlock()
	if len(delegate.requests) != 1 || !bytes.Equal(delegate.requests[0].SourceBytes, body) {
		t.Fatalf("protected archive did not receive the exact canonical source bytes")
	}
}

func TestNoLocalBodyCustodyCanStageReceiptButCannotPromote(t *testing.T) {
	env, sub, coord, canonicalName, archive, _ := externalAuthorizationFlowFixture(t, externalBodyCustodyNone)
	desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	verified, _, receipt, err := validateExternalReferenceSubmissionForStaging(context.Background(), env, sub, canonicalName, desc, coord)
	if err != nil {
		t.Fatal(err)
	}
	if receipt == nil || receipt.Archive != nil || verified.SourceContentHash != receipt.DecodedSHA256 {
		t.Fatalf("receipt-only staging result=%+v coordinate=%+v", receipt, verified)
	}
	archive.mu.Lock()
	archiveCalls := len(archive.requests)
	archive.mu.Unlock()
	if archiveCalls != 0 {
		t.Fatalf("no_local_body_custody performed %d archive writes", archiveCalls)
	}
	if err := requireArchivedExternalEvidence(receipt); err == nil || !strings.Contains(err.Error(), "cannot be promoted") {
		t.Fatalf("receipt-only promotion error=%v", err)
	}
}

func TestSourceDeclaredMachineExportIsTheResourceRootEvidenceBody(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	env.Now = func() time.Time { return now }
	policy := env.Config.ExternalSources[0]
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID: bootstrapSourceAuthority, SourceArtifactClass: policy.SourceArtifactClass,
		SourceRefKind: "coordinate", SourceStableReference: policy.ReferencePrefix + "/copy-all/export",
		SectionPath: SectionPathRoot, LicenseEvidence: policy.RetrievalPermissionEvidenceCoordinates[0],
	}
	canonicalName, err := canonicalExternalLocatorName("external_reference_doc", coord, policy, policy.ID+"_resource_root")
	if err != nil {
		t.Fatal(err)
	}
	copyAll := []byte("# ProfitAndLossDetail\nexact provider-selected export bytes\n")
	env.ExternalFetch = deterministicExternalFetcher{retrievedAt: now, bodies: map[string][]byte{coord.SourceStableReference: copyAll}}
	authorization := validTestExternalAuthorization("org-test", "external_reference_doc", policy, coord, now, externalBodyCustodyAGFS)
	authorization.SourceRepresentationKind = "source_declared_machine_export"
	authorization.SourceRepresentationMediaType = "text/plain"
	env.ExternalAuthorize = &fixedExternalAuthorizationResolver{answer: authorization}
	archive := &memoryExternalEvidenceArchive{}
	env.ExternalArchive = archive
	desc, err := env.Kinds.Resolve(context.Background(), "external_reference_doc")
	if err != nil {
		t.Fatal(err)
	}
	verified, _, receipt, err := validateExternalReferenceSubmissionForStaging(context.Background(), env, ArtifactSubmission{NodeKind: "external_reference_doc", StableID: canonicalName, SourceCoordinate: &coord}, canonicalName, desc, coord)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(copyAll)
	wantDigest := hex.EncodeToString(sum[:])
	if verified.SourceContentHash != wantDigest || receipt.DecodedSHA256 != wantDigest || receipt.Archive == nil {
		t.Fatalf("machine-export evidence binding coordinate=%+v receipt=%+v", verified, receipt)
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if len(archive.requests) != 1 || !bytes.Equal(archive.requests[0].SourceBytes, copyAll) {
		t.Fatalf("archived body is not the exact source-declared Copy-all export")
	}
}

func TestArchiveFailurePreventsLocatorAndGraphReceiptFinalization(t *testing.T) {
	env, sub, coord, canonicalName, archive, _ := externalAuthorizationFlowFixture(t, externalBodyCustodyAGFS)
	archive.err = fmt.Errorf("archive unavailable")
	desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	_, _, receipt, err := validateExternalReferenceSubmissionForStaging(context.Background(), env, sub, canonicalName, desc, coord)
	if err == nil || !strings.Contains(err.Error(), "archive exact external evidence before parsing") || receipt != nil {
		t.Fatalf("archive failure result receipt=%+v error=%v", receipt, err)
	}
}

func TestOneIngestionRequestArchivesOneExactResourceCustodyTupleOnce(t *testing.T) {
	env, sub, coord, canonicalName, archive, _ := externalAuthorizationFlowFixture(t, externalBodyCustodyAGFS)
	desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	ctx := withExternalVerificationSession(context.Background(), "org-test")
	for i := 0; i < 2; i++ {
		_, _, receipt, err := validateExternalReferenceSubmissionForStaging(ctx, env, sub, canonicalName, desc, coord)
		if err != nil {
			t.Fatal(err)
		}
		if receipt == nil || receipt.Archive == nil {
			t.Fatalf("iteration %d lacks protected archive binding", i)
		}
	}
	archive.mu.Lock()
	defer archive.mu.Unlock()
	if len(archive.requests) != 1 {
		t.Fatalf("same exact resource/custody tuple performed %d archive writes, want one", len(archive.requests))
	}
}

func TestExactByteRangeHydrationUsesOnlyDurableArchiveBinding(t *testing.T) {
	env, sub, coord, canonicalName, archive, _ := externalAuthorizationFlowFixture(t, externalBodyCustodyAGFS)
	desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	_, _, receipt, err := validateExternalReferenceSubmissionForStaging(context.Background(), env, sub, canonicalName, desc, coord)
	if err != nil {
		t.Fatal(err)
	}
	body := trustedExternalTestBody(coord.SourceStableReference)
	start := bytes.Index(body, []byte("invoice_api_symbol"))
	if start < 0 {
		t.Fatal("fixture lacks exact symbol bytes")
	}
	result, err := hydrateExternalEvidenceByteRange(context.Background(), env, receipt, int64(start), int64(start+len("invoice_api_symbol")))
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Bytes) != "invoice_api_symbol" || result.SourceContentHash != receipt.DecodedSHA256 || result.ArchiveRecordDigest != receipt.Archive.ArchiveRecordDigest {
		t.Fatalf("hydrated exact range=%+v", result)
	}
	if _, err := hydrateExternalEvidenceByteRange(context.Background(), env, receipt, int64(start), int64(start)); err == nil || !strings.Contains(err.Error(), "nonempty") {
		t.Fatalf("empty exact hydration range error=%v, want OOD nonempty-range refusal", err)
	}
	aliasing := &hydrationResultAliasingArchive{externalEvidenceArchive: archive}
	env.ExternalArchive = aliasing
	detached, err := hydrateExternalEvidenceByteRange(context.Background(), env, receipt, int64(start), int64(start+len("invoice_api_symbol")))
	if err != nil {
		t.Fatal(err)
	}
	aliasing.retained[0] = 'x'
	if string(detached.Bytes) != "invoice_api_symbol" {
		t.Fatalf("adapter-retained hydration buffer changed verified exact bytes to %q", detached.Bytes)
	}
	env.ExternalArchive = selectedDigestTamperingArchive{externalEvidenceArchive: archive}
	if _, err := hydrateExternalEvidenceByteRange(context.Background(), env, receipt, int64(start), int64(start+1)); err == nil || !strings.Contains(err.Error(), "requested exact range receipt") {
		t.Fatalf("tampered selected-range digest error=%v", err)
	}
	env.ExternalArchive = archive
	tampered := *receipt
	tamperedArchive := *receipt.Archive
	tamperedArchive.SourceContentHash = strings.Repeat("f", 64)
	digest, err := externalEvidenceArchiveRecordDigest(tamperedArchive)
	if err != nil {
		t.Fatal(err)
	}
	tamperedArchive.ArchiveRecordDigest = digest
	tampered.Archive = &tamperedArchive
	if _, err := hydrateExternalEvidenceByteRange(context.Background(), env, &tampered, int64(start), int64(start+1)); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tampered source binding hydration error=%v", err)
	}
}
