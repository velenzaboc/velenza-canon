package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

const quickBooksTestRetrievalPermissionEvidence = "https://permissions.example.test/express-automated-retrieval-grant"

func trustedExternalTestBody(reference string) []byte {
	resource := reference
	if u, err := parseCanonicalHTTPSReference(reference); err == nil {
		u.Fragment = ""
		resource = u.String()
	}
	return []byte(`<html><body><div id="release-2026-08">release</div><span id="invoice_api_symbol">invoice_api_symbol</span><p>` + resource + `</p></body></html>`)
}

func trustedExternalTestDigest(reference string) string {
	sum := sha256.Sum256(trustedExternalTestBody(reference))
	return hex.EncodeToString(sum[:])
}

type deterministicExternalFetcher struct {
	retrievedAt                 time.Time
	bodies                      map[string][]byte
	upstreamVersionEvidenceKind string
	upstreamVersionEvidence     string
	upstreamVersionToken        string
}

type countingRefusingExternalFetcher struct{ calls *int }

func (f countingRefusingExternalFetcher) Fetch(context.Context, string, ExternalSourceDescriptor, string) (verifiedExternalSourceReceipt, error) {
	*f.calls = *f.calls + 1
	return verifiedExternalSourceReceipt{}, fmt.Errorf("network fetch must not run")
}

func (f deterministicExternalFetcher) Fetch(_ context.Context, reference string, policy ExternalSourceDescriptor, authority string) (verifiedExternalSourceReceipt, error) {
	resource, err := externalResourceReference(reference, policy)
	if err != nil {
		return verifiedExternalSourceReceipt{}, err
	}
	body := trustedExternalTestBody(reference)
	if override, ok := f.bodies[reference]; ok {
		body = append([]byte(nil), override...)
	} else if override, ok := f.bodies[resource]; ok {
		body = append([]byte(nil), override...)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	mediaType := "text/plain"
	if strings.HasPrefix(strings.TrimSpace(string(body)), "<") {
		mediaType = "text/html"
	}
	metadataDigest, err := externalTransportResponseMetadataDigest(externalTransportResponseMetadata{
		StatusCode: http.StatusOK, ContentEncoding: "identity", MediaType: mediaType,
	})
	if err != nil {
		return verifiedExternalSourceReceipt{}, err
	}
	retrievedAt := f.retrievedAt
	if retrievedAt.IsZero() {
		retrievedAt = time.Now().UTC()
	}
	return verifiedExternalSourceReceipt{
		CanonicalReference:              resource,
		RetrievedAt:                     retrievedAt.UTC(),
		ByteLength:                      int64(len(body)),
		SHA256:                          digest,
		TransportStatus:                 "success",
		TransportRawHashAlgorithm:       "sha256",
		ContentCoding:                   "identity",
		TransportResponseMetadataDigest: metadataDigest,
		DecodedByteLength:               int64(len(body)),
		DecodedSHA256:                   digest,
		SourceRepresentationMediaType:   mediaType,
		UpstreamVersionEvidenceKind:     f.upstreamVersionEvidenceKind,
		UpstreamVersionEvidence:         f.upstreamVersionEvidence,
		UpstreamVersionToken:            f.upstreamVersionToken,
		SourceRegistryID:                policy.ID,
		SourceAuthorityID:               authority,
		Body:                            body,
		LocatorBody:                     append([]byte(nil), body...),
	}, nil
}

func externalReferenceCoordinate(versionToken string) *ArtifactSourceCoordinate {
	_ = versionToken // digest-scoped callers do not author the final version token
	reference := "https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice"
	return &ArtifactSourceCoordinate{
		SourceAuthorityID:     bootstrapSourceAuthority,
		SourceArtifactClass:   "official_vendor_documentation",
		SourceRefKind:         "coordinate",
		SourceStableReference: reference,
		SectionPath:           "$",
		SourceContentHash:     trustedExternalTestDigest(reference),
		LicenseEvidence:       quickBooksTestRetrievalPermissionEvidence,
	}
}

type fixedEmbeddingClient struct {
	dimensions int
	err        error
}

func finalizeVerifiedExternalTestReference(t *testing.T, env *Env, sub ArtifactSubmission, canonicalName string, desc NodeKindDescriptor, resolved ArtifactSourceCoordinate) (ArtifactSourceCoordinate, ExternalSourceDescriptor, *stagedExternalVerificationReceipt) {
	t.Helper()
	policy, err := preflightExternalReferenceSubmissionShape(env, sub, canonicalName, desc, resolved)
	if err != nil {
		t.Fatalf("preflight external shape: %v", err)
	}
	if env.ExternalFetch == nil {
		t.Fatal("test requires deterministic external fetcher")
	}
	rawReceipt, err := env.ExternalFetch.Fetch(context.Background(), resolved.SourceStableReference, policy, resolved.SourceAuthorityID)
	if err != nil {
		t.Fatalf("build deterministic receipt: %v", err)
	}
	orgID := env.Config.DefaultOrganizationID
	if orgID == "" {
		orgID = "org-test"
	}
	rawReceipt.Authorization = validTestExternalAuthorization(orgID, sub.NodeKind, policy, resolved, rawReceipt.RetrievedAt, externalBodyCustodyAGFS)
	rawReceipt.Archive = testExternalArchiveReceipt(rawReceipt.Authorization, rawReceipt.DecodedByteLength, rawReceipt.DecodedSHA256)
	verified, rawReceipt, err := bindVerifiedExternalSourceReceipt(resolved, policy, rawReceipt)
	if err != nil {
		t.Fatalf("bind deterministic receipt: %v", err)
	}
	verified, durable, err := finalizeVerifiedExternalReferenceSubmission(env, sub, canonicalName, verified, policy, rawReceipt)
	if err != nil {
		t.Fatalf("finalize verified external reference: %v", err)
	}
	return verified, policy, durable
}

func (f fixedEmbeddingClient) Embed(context.Context, string, string) ([]float32, error) {
	if f.err != nil {
		return nil, f.err
	}
	vec := make([]float32, f.dimensions)
	if len(vec) > 0 {
		vec[0] = 1
	}
	return vec, nil
}

func newSourceCoordinateEnv(t *testing.T) (*Env, *recordingAdapter) {
	t.Helper()
	env, ra := newImportKindEnv(t)
	externalKinds := []string{"external_reference_doc", "reference_page", "api_symbol", "code_example", "release_note"}
	kindDescriptors := make([]NodeKindDescriptor, 0, len(externalKinds)+2)
	for _, kind := range externalKinds {
		kindDescriptors = append(kindDescriptors, NewNodeKindDescriptor(map[string]interface{}{
			"name":                     kind,
			"artifact_type":            kind,
			"substrate_id":             "fake",
			"version_scope":            "source_version_scoped",
			"source_authority":         bootstrapSourceAuthority,
			"source_coordinate_policy": sourceCoordinatePolicyExternalReferenceRequired,
		}))
	}
	kindDescriptors = append(kindDescriptors,
		NewNodeKindDescriptor(map[string]interface{}{
			"name":             "section",
			"artifact_type":    "section",
			"substrate_id":     "fake",
			"version_scope":    "stable_id_preserved",
			"source_authority": bootstrapSourceAuthority,
		}),
		NewNodeKindDescriptor(map[string]interface{}{
			"name":             "axiom",
			"artifact_type":    "axiom",
			"substrate_id":     "fake",
			"version_scope":    "stable_id_preserved",
			"source_authority": bootstrapSourceAuthority,
		}),
	)
	env.Kinds = newKindRegistry(kindDescriptors)
	env.Config.Embedding = &EmbeddingConfig{Model: "gemini-embedding-001", Dimensions: externalReferenceEmbeddingDimensions}
	env.Config.ExternalSources = []ExternalSourceDescriptor{
		{
			ID:                      "quickbooks_online_official_docs",
			SourceArtifactClass:     "official_vendor_documentation",
			ReferenceKind:           "https_url_prefix",
			ReferencePrefix:         "https://developer.intuit.com/app/developer/qbo/docs",
			ContentHashAlgorithm:    "sha256",
			VersionCoordinateMode:   externalVersionModeContentDigest,
			VersionStableNamePrefix: "quickbooks_online_",
			AllowedObjectClasses:    []string{"external_reference_doc", "reference_page", "api_symbol", "code_example"},
			LocatorKinds: map[string]string{
				"external_reference_doc": "resource_root", "reference_page": "html_id_or_name",
				"api_symbol": "html_id_or_name", "code_example": "html_id_or_name",
			},
			FreshnessWindowSeconds:  7 * 24 * 60 * 60,
			LicenseEvidenceRequired: true,
			LicenseEvidenceBinding:  licenseEvidenceBindingCoordinate,
			RetrievalPermissionEvidenceCoordinates: []string{
				quickBooksTestRetrievalPermissionEvidence,
			},
			AllowFragment: true,
		},
		{
			ID:                      "quickbooks_online_official_release_notes",
			SourceArtifactClass:     "official_release_notes",
			ReferenceKind:           "https_url_prefix",
			ReferencePrefix:         "https://developer.intuit.com/app/developer/qbo/docs",
			ContentHashAlgorithm:    "sha256",
			VersionCoordinateMode:   externalVersionModeContentDigest,
			VersionStableNamePrefix: "quickbooks_online_release_",
			AllowedObjectClasses:    []string{"release_note"},
			LocatorKinds:            map[string]string{"release_note": "html_id_or_name"},
			FreshnessWindowSeconds:  7 * 24 * 60 * 60,
			LicenseEvidenceRequired: true,
			LicenseEvidenceBinding:  licenseEvidenceBindingCoordinate,
			RetrievalPermissionEvidenceCoordinates: []string{
				quickBooksTestRetrievalPermissionEvidence,
			},
			AllowFragment: true,
		},
	}
	env.Config.EdgeLabels = externalReferenceTestEdgeDescriptors()
	env.Edges = newEdgeRegistry(env.Config.EdgeLabels)
	env.Embed = fixedEmbeddingClient{dimensions: externalReferenceEmbeddingDimensions}
	env.Now = time.Now
	env.ExternalFetch = deterministicExternalFetcher{}
	return env, ra
}

func referencePageSubmission(coord *ArtifactSourceCoordinate) ArtifactSubmission {
	return ArtifactSubmission{
		ArtifactType:     "reference_page",
		OrganizationID:   "org-test",
		NodeKind:         "reference_page",
		StableID:         "quickbooks_online_invoice_reference",
		SourceCoordinate: coord,
	}
}

func referencePageCorpusInput(coord *ArtifactSourceCoordinate) importInput {
	rootCoord := *coord
	rootCoord.SourceStableReference = "https://developer.intuit.com/app/developer/qbo/docs"
	rootCoord.SourceContentHash = trustedExternalTestDigest(rootCoord.SourceStableReference)
	rootCoord.VersionCoordinate = ""
	return importInput{
		Submissions: []ArtifactSubmission{
			{
				ArtifactType:     "external_reference_doc",
				OrganizationID:   "org-test",
				NodeKind:         "external_reference_doc",
				StableID:         "quickbooks_online_corpus",
				SourceCoordinate: &rootCoord,
			},
			referencePageSubmission(coord),
		},
		Relationships: []ExternalRelationship{{
			EdgeLabel:           "official_source_for",
			SourceCanonicalName: "quickbooks_online_corpus",
			TargetCanonicalName: "quickbooks_online_invoice_reference",
		}},
	}
}

func graphObjectByClass(t *testing.T, objects []GraphObject, class string) GraphObject {
	t.Helper()
	for _, object := range objects {
		if object.ObjectClass == class {
			return object
		}
	}
	t.Fatalf("object class %q missing from %+v", class, objects)
	return GraphObject{}
}

func TestHandleImportFailsClosedBeforeMaterializingExternalCoordinate(t *testing.T) {
	env, adapter := newSourceCoordinateEnv(t)
	coord := externalReferenceCoordinate("sha256_20260821")
	_, err := handleImport(context.Background(), env, referencePageCorpusInput(coord))
	if !errors.Is(err, ErrOODGraphExternalNonGranularProofUnavailable) {
		t.Fatalf("external import error=%v, want typed authenticity/identity refusal", err)
	}
	if adapter.schemaChecks != 0 || len(adapter.openedRuns) != 0 || len(adapter.batches) != 0 {
		t.Fatalf("blocked external coordinate reached substrate: schema=%d runs=%d batches=%d", adapter.schemaChecks, len(adapter.openedRuns), len(adapter.batches))
	}
}

func TestExternalVersionCoordinateModeOwnsFinalIdentity(t *testing.T) {
	t.Run("content_digest derives final token from trusted bytes", func(t *testing.T) {
		env, _ := newSourceCoordinateEnv(t)
		desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
		if err != nil {
			t.Fatal(err)
		}
		input := *externalReferenceCoordinate("ignored")
		input.SourceStableReference += "#symbol=invoice_api_symbol"
		input.SourceContentHash = "" // expected digest is optional
		canonicalName, err := canonicalExternalLocatorName("api_symbol", input, env.Config.ExternalSources[0], "invoice_api_symbol")
		if err != nil {
			t.Fatal(err)
		}
		sub := ArtifactSubmission{ArtifactType: "api_symbol", NodeKind: "api_symbol", StableID: canonicalName, SourceCoordinate: &input}
		resolved, err := resolveArtifactSourceCoordinate("api_symbol", canonicalName, desc, &input)
		if err != nil {
			t.Fatal(err)
		}
		verified, policy, receipt := finalizeVerifiedExternalTestReference(t, env, sub, canonicalName, desc, resolved)
		wantDigest := trustedExternalTestDigest(input.SourceStableReference)
		wantVersion := "source:" + bootstrapSourceAuthority + ":" + canonicalName + "@sha256_" + wantDigest
		if policy.VersionCoordinateMode != externalVersionModeContentDigest || verified.VersionCoordinate != wantVersion || verified.SourceContentHash != wantDigest || verified.SourceContentHashOwner != bootstrapSourceAuthority || receipt == nil || receipt.FinalVersionCoordinate != wantVersion {
			t.Fatalf("verified=%+v policy=%+v receipt=%+v, want digest-owned final identity", verified, policy, receipt)
		}
		if input.VersionCoordinate != "" || input.SourceContentHashOwner != "" || input.RetrievedAt != "" {
			t.Fatalf("trusted outputs leaked back into caller input: %+v", input)
		}
	})

	t.Run("upstream pinned derives only trusted fetch evidence", func(t *testing.T) {
		env, _ := newSourceCoordinateEnv(t)
		env.Config.ExternalSources[0].VersionCoordinateMode = externalVersionModeUpstreamPinned
		env.Config.ExternalSources[0].UpstreamIdentityPolicy = upstreamIdentityHTTPResponseWithContentDigest
		digest := trustedExternalTestDigest(externalReferenceCoordinate("ignored").SourceStableReference)
		trustedToken, err := trustedUpstreamVersionToken("http_weak_etag", `W/"release-2026-08"`, digest)
		if err != nil {
			t.Fatal(err)
		}
		env.ExternalFetch = deterministicExternalFetcher{
			upstreamVersionEvidenceKind: "http_weak_etag",
			upstreamVersionEvidence:     `W/"release-2026-08"`,
			upstreamVersionToken:        trustedToken,
		}
		desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
		if err != nil {
			t.Fatal(err)
		}
		input := *externalReferenceCoordinate("ignored")
		input.SourceStableReference += "#symbol=invoice_api_symbol"
		input.SourceContentHash = ""
		canonicalName, err := canonicalExternalLocatorName("api_symbol", input, env.Config.ExternalSources[0], "invoice_api_symbol")
		if err != nil {
			t.Fatal(err)
		}
		sub := ArtifactSubmission{ArtifactType: "api_symbol", NodeKind: "api_symbol", StableID: canonicalName, SourceCoordinate: &input}
		resolved, err := resolveArtifactSourceCoordinate("api_symbol", canonicalName, desc, &input)
		if err != nil {
			t.Fatal(err)
		}
		verified, policy, receipt := finalizeVerifiedExternalTestReference(t, env, sub, canonicalName, desc, resolved)
		wantVersion := "source:" + bootstrapSourceAuthority + ":" + canonicalName + "@" + trustedToken
		if policy.VersionCoordinateMode != externalVersionModeUpstreamPinned || verified.VersionCoordinate != wantVersion || verified.SourceContentHash != trustedExternalTestDigest(input.SourceStableReference) || receipt == nil || receipt.FinalVersionCoordinate != wantVersion || receipt.UpstreamVersionEvidenceKind != "http_weak_etag" || receipt.UpstreamVersionEvidence != `W/"release-2026-08"` || receipt.UpstreamVersionToken != trustedToken {
			t.Fatalf("verified=%+v policy=%+v receipt=%+v, want upstream token plus independent trusted digest", verified, policy, receipt)
		}
		tamperedReceipt := *receipt
		tamperedReceipt.UpstreamVersionEvidence = `W/"release-2026-09"`
		if err := validateTrustedUpstreamVersionMaterial(policy, tamperedReceipt.CanonicalReference, tamperedReceipt.SHA256, tamperedReceipt.UpstreamVersionEvidenceKind, tamperedReceipt.UpstreamVersionEvidence, tamperedReceipt.UpstreamVersionToken); err == nil {
			t.Fatalf("tampered upstream receipt evidence error=%v, want durable evidence/token refusal", err)
		}
		callerShaped := *receipt
		callerShaped.UpstreamVersionEvidenceKind = "caller_release_assertion"
		callerShaped.UpstreamVersionEvidence = "release_2026_08"
		callerShaped.UpstreamVersionToken, err = trustedUpstreamVersionToken(callerShaped.UpstreamVersionEvidenceKind, callerShaped.UpstreamVersionEvidence, callerShaped.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateTrustedUpstreamVersionMaterial(policy, callerShaped.CanonicalReference, callerShaped.SHA256, callerShaped.UpstreamVersionEvidenceKind, callerShaped.UpstreamVersionEvidence, callerShaped.UpstreamVersionToken); err == nil {
			t.Fatalf("caller-shaped but digest-bound evidence error=%v, want descriptor-policy refusal", err)
		}
	})
}

func TestSameRepositoryLicenseEvidenceIsBoundByDescriptorPathKey(t *testing.T) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	policy := ExternalSourceDescriptor{
		ID: "official_source_repository", SourceArtifactClass: "official_source_repository",
		ReferenceKind: "https_url_prefix", ReferencePrefix: "https://code.example/vendor",
		LicenseEvidenceRequired: true, LicenseEvidenceBinding: licenseEvidenceBindingSameRepositoryFile,
		RepositoryPathSegments:                  2,
		ImmutableReferencePattern:               `^https://code\.example/vendor/repository/commit/(?P<immutable_ref>[0-9a-f]{40})$`,
		SameRepositoryPermissionEvidencePattern: `^https://code\.example/vendor/repository/blob/(?P<immutable_ref>[0-9a-f]{40})/(LICENSE|LICENSE\.[A-Za-z0-9._-]+|COPYING|COPYING\.[A-Za-z0-9._-]+)$`,
	}
	coord := ArtifactSourceCoordinate{
		SourceStableReference: "https://code.example/vendor/repository/commit/" + commit,
		LicenseEvidence:       "https://code.example/vendor/repository/blob/" + commit + "/LICENSE",
	}
	if err := validateSameRepositoryLicenseFileEvidence(policy, coord.SourceStableReference, coord.LicenseEvidence); err != nil {
		t.Fatalf("same-repository license evidence rejected: %v", err)
	}
	if err := validateExternalRetrievalPermissionEvidence(policy, coord); err != nil {
		t.Fatalf("valid same-repository evidence coordinate rejected before the independent authorization resolver: %v", err)
	}
	for name, evidence := range map[string]string{
		"unbound service terms": "https://docs.example/legal/terms",
		"different repository":  "https://code.example/vendor/other/blob/main/LICENSE",
		"caller SPDX assertion": "spdx:Apache-2.0",
		"non-license file":      "https://code.example/vendor/repository/blob/main/README.md",
		"mutable evidence":      "https://code.example/vendor/repository/blob/main/LICENSE",
		"cross commit":          "https://code.example/vendor/repository/blob/ffffffffffffffffffffffffffffffffffffffff/LICENSE",
		"nested dependency":     "https://code.example/vendor/repository/blob/" + commit + "/vendor/dependency/LICENSE",
		"query variant":         "https://code.example/vendor/repository/blob/" + commit + "/LICENSE?download=1",
	} {
		t.Run(name, func(t *testing.T) {
			bad := coord
			bad.LicenseEvidence = evidence
			if err := validateSameRepositoryLicenseFileEvidence(policy, bad.SourceStableReference, bad.LicenseEvidence); err == nil {
				t.Fatalf("unbound repository evidence %q accepted", evidence)
			}
		})
	}
	mutableSource := coord
	mutableSource.SourceStableReference = "https://code.example/vendor/repository/tree/main"
	if err := validateSameRepositoryLicenseFileEvidence(policy, mutableSource.SourceStableReference, mutableSource.LicenseEvidence); err == nil || !strings.Contains(err.Error(), "source coordinate is not descriptor-proven immutable") {
		t.Fatalf("mutable repository source error=%v, want immutable-coordinate refusal", err)
	}
}

func TestCoordinateOnlyPermissionEvidenceDoesNotReplaceTypedGrantResolver(t *testing.T) {
	policy := validExternalSourceConfig().ExternalSources[0]
	coord := ArtifactSourceCoordinate{LicenseEvidence: policy.RetrievalPermissionEvidenceCoordinates[0]}
	if err := validateExternalRetrievalPermissionEvidence(policy, coord); err != nil {
		t.Fatalf("descriptor-owned evidence coordinate rejected: %v", err)
	}
	env := &Env{}
	request := externalSourceAuthorizationRequest{OrganizationID: "org-test", ObjectClass: "api_symbol", SourceRegistryID: policy.ID, SourceArtifactClass: policy.SourceArtifactClass, SourceAuthorityID: bootstrapSourceAuthority, SourceRefKind: "coordinate", SourceStableReference: "https://example.com/docs#symbol=x", PermissionOperation: externalFetchPermissionOperation, PermissionMethod: "GET", ObservedAt: time.Now().UTC()}
	if _, err := resolveExternalSourceAuthorization(context.Background(), env, request); !errors.Is(err, ErrOODGraphExternalRetrievalPermissionProofUnavailable) {
		t.Fatalf("missing typed grant resolver error=%v, want fail-closed refusal", err)
	}
}

func TestExternalCallerCannotAuthorTrustedReceiptFieldsOrDigestModeVersion(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ArtifactSourceCoordinate)
		want   string
	}{
		{"digest_mode_version", func(c *ArtifactSourceCoordinate) {
			c.VersionCoordinate = "source:" + bootstrapSourceAuthority + ":quickbooks_online_invoice_reference@sha256_" + c.SourceContentHash
		}, "must be omitted for content_digest"},
		{"digest_owner", func(c *ArtifactSourceCoordinate) { c.SourceContentHashOwner = bootstrapSourceAuthority }, "trusted-fetch outputs"},
		{"retrieved_at", func(c *ArtifactSourceCoordinate) { c.RetrievedAt = time.Now().UTC().Format(time.RFC3339Nano) }, "trusted-fetch outputs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, adapter := newSourceCoordinateEnv(t)
			coord := externalReferenceCoordinate("ignored")
			tc.mutate(coord)
			_, err := handleImport(context.Background(), env, referencePageCorpusInput(coord))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("handleImport error=%v, want %q", err, tc.want)
			}
			if adapter.schemaChecks != 0 || len(adapter.openedRuns) != 0 {
				t.Fatal("caller-authored trusted receipt field reached substrate")
			}
		})
	}
}

func TestExternalUpstreamPinnedIdentityRejectsCallerAssertionAndMissingTrustedEvidence(t *testing.T) {
	t.Run("caller assertion", func(t *testing.T) {
		env, adapter := newSourceCoordinateEnv(t)
		env.Config.ExternalSources[0].VersionCoordinateMode = externalVersionModeUpstreamPinned
		env.Config.ExternalSources[0].UpstreamIdentityPolicy = upstreamIdentityHTTPResponseWithContentDigest
		coord := externalReferenceCoordinate("ignored")
		coord.VersionCoordinate = "source:" + bootstrapSourceAuthority + ":quickbooks_online_invoice_reference@release_2026_08"
		_, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{referencePageSubmission(coord)}})
		if err == nil || !strings.Contains(err.Error(), "must be omitted for upstream_pinned") {
			t.Fatalf("handleImport error=%v, want caller-version refusal", err)
		}
		if adapter.schemaChecks != 0 || len(adapter.openedRuns) != 0 {
			t.Fatal("caller-minted upstream version reached substrate")
		}
	})

	t.Run("trusted evidence absent", func(t *testing.T) {
		policy := validExternalSourceConfig().ExternalSources[0]
		policy.VersionCoordinateMode = externalVersionModeUpstreamPinned
		policy.UpstreamIdentityPolicy = upstreamIdentityHTTPResponseWithContentDigest
		err := validateTrustedUpstreamVersionReceipt(policy, verifiedExternalSourceReceipt{
			CanonicalReference: "https://example.com/docs", SHA256: strings.Repeat("a", 64),
		})
		if err == nil || !strings.Contains(err.Error(), "requires trusted upstream version evidence") {
			t.Fatalf("trusted receipt error=%v, want missing-evidence refusal", err)
		}
	})
}

func TestStagedExternalReceiptBindsExactVerifiedLocatorIncludingFragment(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	alternatePermissionEvidence := "https://developer.intuit.com/app/developer/qbo/docs/legal-agreements/privacy"
	env.Config.ExternalSources[0].RetrievalPermissionEvidenceCoordinates = append(
		env.Config.ExternalSources[0].RetrievalPermissionEvidenceCoordinates,
		alternatePermissionEvidence,
	)
	desc, err := env.Kinds.Resolve(context.Background(), "reference_page")
	if err != nil {
		t.Fatal(err)
	}
	input := *externalReferenceCoordinate("ignored")
	input.SourceStableReference += "#anchor=invoice_api_symbol"
	input.SourceContentHash = trustedExternalTestDigest(input.SourceStableReference)
	canonicalName, err := canonicalExternalLocatorName("reference_page", input, env.Config.ExternalSources[0], "invoice_api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveArtifactSourceCoordinate("reference_page", canonicalName, desc, &input)
	if err != nil {
		t.Fatal(err)
	}
	sub := ArtifactSubmission{ArtifactType: "reference_page", NodeKind: "reference_page", StableID: canonicalName, SourceCoordinate: &input}
	verified, _, receipt := finalizeVerifiedExternalTestReference(t, env, sub, canonicalName, desc, resolved)
	if receipt == nil || receipt.VerifiedSourceStableReference != input.SourceStableReference || receipt.ContentCoding != "identity" || receipt.DecodedSHA256 != receipt.SHA256 || receipt.LicenseEvidence != input.LicenseEvidence {
		t.Fatalf("durable receipt omitted exact locator or decoded evidence: %+v", receipt)
	}
	tampered := verified
	tampered.SourceStableReference = strings.TrimSuffix(input.SourceStableReference, "#anchor=invoice_api_symbol") + "#anchor=release-2026-08"
	if _, _, err := validateStagedExternalReferenceSubmission(env, sub, canonicalName, desc, tampered, receipt); err == nil || !strings.Contains(err.Error(), "does not match the preserved final source coordinate") {
		t.Fatalf("fragment-switched staged coordinate error=%v, want exact locator receipt refusal", err)
	}
	tampered = verified
	tampered.LicenseEvidence = alternatePermissionEvidence
	if _, _, err := validateStagedExternalReferenceSubmission(env, sub, canonicalName, desc, tampered, receipt); err == nil || !strings.Contains(err.Error(), "does not match the preserved final source coordinate") {
		t.Fatalf("permission-evidence-switched staged coordinate error=%v, want receipt refusal", err)
	}
}

func TestVerifiedCoordinateChangesProduceDistinctStableIDs(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	desc, err := env.Kinds.Resolve(context.Background(), "api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	input := *externalReferenceCoordinate("ignored")
	input.SourceStableReference += "#symbol=invoice_api_symbol"
	input.SourceContentHash = ""
	canonicalName, err := canonicalExternalLocatorName("api_symbol", input, env.Config.ExternalSources[0], "invoice_api_symbol")
	if err != nil {
		t.Fatal(err)
	}
	sub := ArtifactSubmission{ArtifactType: "api_symbol", NodeKind: "api_symbol", StableID: canonicalName, SourceCoordinate: &input}
	resolved, err := resolveArtifactSourceCoordinate("api_symbol", canonicalName, desc, &input)
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := finalizeVerifiedExternalTestReference(t, env, sub, canonicalName, desc, resolved)
	env.ExternalFetch = deterministicExternalFetcher{bodies: map[string][]byte{
		input.SourceStableReference: []byte(`<html><body><span id="invoice_api_symbol">changed</span></body></html>`),
	}}
	second, _, _ := finalizeVerifiedExternalTestReference(t, env, sub, canonicalName, desc, resolved)
	objectID := func(coord ArtifactSourceCoordinate) string {
		name := "object|org-test|api_symbol|" + coord.SourceAuthorityID + "|coordinate|" + coord.SourceStableReference + "|" + coord.VersionCoordinate + "|$"
		return uuid.NewSHA1(oodGraphIDNamespace, []byte(name)).String()
	}
	address := func(coord ArtifactSourceCoordinate) string {
		return GraphAddress{ObjectClass: "api_symbol", SourceAuthorityID: coord.SourceAuthorityID, SourceRefKind: coord.SourceRefKind, SourceRef: coord.SourceStableReference, VersionCoordinate: coord.VersionCoordinate, SectionPath: coord.SectionPath}.String()
	}
	if objectID(first) == objectID(second) || address(first) == address(second) {
		t.Fatalf("different verified source bytes collapsed identity: first=%+v second=%+v", first, second)
	}
}

func TestHandleImportAbsentCoordinatePreservesBootstrapIdentity(t *testing.T) {
	env, ra := newSourceCoordinateEnv(t)
	sub := ArtifactSubmission{
		ArtifactType:   "axiom",
		OrganizationID: "org-test",
		NodeKind:       "axiom",
		StableID:       "unchanged_axiom",
		Contract:       map[string]interface{}{"canonical_name": "unchanged_axiom"},
		Payload:        map[string]interface{}{"claim": "unchanged"},
	}
	_, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{sub}})
	if err != nil {
		t.Fatalf("handleImport: %v", err)
	}
	o := ra.batches[0].Objects[0]
	wantIDInput := "object|org-test|axiom|" + bootstrapSourceAuthority + "|name|unchanged_axiom|unversioned|$"
	wantID := uuid.NewSHA1(oodGraphIDNamespace, []byte(wantIDInput)).String()
	if o.GraphObjectID != wantID {
		t.Errorf("backward-compatible graph_object_id=%q, want %q", o.GraphObjectID, wantID)
	}
	if o.SourceAuthorityID != bootstrapSourceAuthority || o.SourceRefKind != "name" || o.SourceStableReference != "unchanged_axiom" || o.VersionCoordinate != "unversioned" || o.SectionPath != "$" {
		t.Errorf("absent coordinate changed bootstrap defaults: %+v", o)
	}
}

func TestHandleImportRejectsMalformedSourceCoordinatesBeforeIO(t *testing.T) {
	valid := externalReferenceCoordinate("sha256_valid")
	cases := []struct {
		name   string
		mutate func(*ArtifactSourceCoordinate)
		want   string
	}{
		{"missing_authority", func(c *ArtifactSourceCoordinate) { c.SourceAuthorityID = "" }, "source_authority_id required"},
		{"uppercase_authority_uuid", func(c *ArtifactSourceCoordinate) { c.SourceAuthorityID = strings.ToUpper(c.SourceAuthorityID) }, "invalid UUID"},
		{"missing_artifact_class", func(c *ArtifactSourceCoordinate) { c.SourceArtifactClass = "" }, "source_artifact_class required"},
		{"noncanonical_artifact_class", func(c *ArtifactSourceCoordinate) { c.SourceArtifactClass = "OfficialDocs" }, "lowercase snake_case"},
		{"unknown_ref_kind", func(c *ArtifactSourceCoordinate) { c.SourceRefKind = "url" }, "source_ref_kind"},
		{"missing_stable_reference", func(c *ArtifactSourceCoordinate) { c.SourceStableReference = "" }, "source_stable_reference required"},
		{"mutable_latest_alias", func(c *ArtifactSourceCoordinate) { c.VersionCoordinate = "latest" }, "current/latest aliases forbidden"},
		{"noncanonical_version_escape", func(c *ArtifactSourceCoordinate) {
			c.VersionCoordinate = "source:" + bootstrapSourceAuthority + ":quickbooks%5fonline@sha256_valid"
		}, "not canonical"},
		{"mismatched_version_authority", func(c *ArtifactSourceCoordinate) {
			c.VersionCoordinate = "source:46954a80-78eb-4351-8be7-6e7d7eba8f5b:quickbooks_online@sha256_valid"
		}, "does not match"},
		{"external_wrong_authority", func(c *ArtifactSourceCoordinate) {
			other := "46954a80-78eb-4351-8be7-6e7d7eba8f5b"
			c.SourceAuthorityID = other
			c.VersionCoordinate = "source:" + other + ":quickbooks_online@sha256_valid"
			c.SourceContentHashOwner = other
		}, "must match registry authority"},
		{"external_name_ref", func(c *ArtifactSourceCoordinate) { c.SourceRefKind = "name" }, "must be coordinate"},
		{"external_untrusted_source_class", func(c *ArtifactSourceCoordinate) { c.SourceArtifactClass = "unofficial_blog" }, "not admitted by external_sources registry"},
		{"external_unpinned", func(c *ArtifactSourceCoordinate) { c.VersionCoordinate = "unversioned" }, "must be a pinned source-named"},
		{"external_nested_section", func(c *ArtifactSourceCoordinate) { c.SectionPath = "$.invoice" }, "must be \"$\""},
		{"external_wrong_hash_owner", func(c *ArtifactSourceCoordinate) {
			c.SourceContentHashOwner = "46954a80-78eb-4351-8be7-6e7d7eba8f5b"
		}, "must match source_authority_id"},
		{"invalid_section_path", func(c *ArtifactSourceCoordinate) { c.SectionPath = "$.BadKey" }, "section_path"},
		{"owner_without_hash", func(c *ArtifactSourceCoordinate) {
			c.SourceContentHash = ""
			c.SourceContentHashOwner = bootstrapSourceAuthority
		}, "cannot be supplied without source_content_hash"},
		{"oversized_hash", func(c *ArtifactSourceCoordinate) { c.SourceContentHash = strings.Repeat("a", 129) }, "STRING(128)"},
		{"non_digest_hash", func(c *ArtifactSourceCoordinate) { c.SourceContentHash = "caller-asserted-content" }, "64-character lowercase hexadecimal SHA-256"},
		{"uppercase_digest_hash", func(c *ArtifactSourceCoordinate) { c.SourceContentHash = strings.Repeat("A", 64) }, "64-character lowercase hexadecimal SHA-256"},
		{"contradictory_digest_version", func(c *ArtifactSourceCoordinate) {
			c.VersionCoordinate = "source:" + bootstrapSourceAuthority + ":quickbooks_online_invoice_reference@sha256_" + strings.Repeat("b", 64)
		}, "SHA-256 token does not match source_content_hash"},
		{"invalid_hash_owner", func(c *ArtifactSourceCoordinate) { c.SourceContentHashOwner = "not-a-uuid" }, "source_content_hash_owner"},
		{"noncanonical_retrieved_at", func(c *ArtifactSourceCoordinate) { c.RetrievedAt = "2026-08-21T00:00:00+00:00" }, "not canonical UTC"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, ra := newSourceCoordinateEnv(t)
			coordCopy := *valid
			tc.mutate(&coordCopy)
			_, err := handleImport(context.Background(), env, importInput{
				Submissions: []ArtifactSubmission{referencePageSubmission(&coordCopy)},
			})
			if err == nil {
				t.Fatal("malformed source_coordinate was admitted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error=%q, want substring %q", err, tc.want)
			}
			if ra.schemaChecks != 0 || len(ra.openedRuns) != 0 || len(ra.batches) != 0 {
				t.Errorf("malformed coordinate reached substrate: schema_checks=%d opened_runs=%d batches=%d", ra.schemaChecks, len(ra.openedRuns), len(ra.batches))
			}
		})
	}
}

func TestExternalReferenceEnforcesFreshnessWindowBeforeIO(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name        string
		retrievedAt time.Time
		want        string
	}{
		{"stale", now.Add(-8 * 24 * time.Hour), "is stale"},
		{"future", now.Add(6 * time.Minute), "is in the future"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := newSourceCoordinateEnv(t)
			env.Now = func() time.Time { return now }
			policy := env.Config.ExternalSources[0]
			coord := *externalReferenceCoordinate("sha256_freshness")
			coord.RetrievedAt = tc.retrievedAt.UTC().Format(time.RFC3339Nano)
			coord.SourceContentHashOwner = coord.SourceAuthorityID
			coord.VersionCoordinate = VersionCoordinate{Kind: VersionSourceNamed, SourceAuthorityID: coord.SourceAuthorityID, StableName: "quickbooks_online_invoice_reference", SourceVersionToken: "sha256_" + coord.SourceContentHash}.String()
			err := validateFinalExternalCoordinate(env, "reference_page", "quickbooks_online_invoice_reference", coord, policy)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestStagingConceptSubmissionPreservesSourceCoordinate(t *testing.T) {
	coord := externalReferenceCoordinate("sha256_staged")
	c := StagingConcept{
		CanonicalName:    "quickbooks_online_invoice_reference",
		NodeKind:         "reference_page",
		Contract:         map[string]interface{}{"canonical_name": "quickbooks_online_invoice_reference"},
		Payload:          map[string]interface{}{"trust_class": "official_vendor_documentation"},
		SourceCoordinate: coord,
	}
	sub := stagingConceptSubmission(c)
	if sub.SourceCoordinate == nil || *sub.SourceCoordinate != *coord {
		t.Fatalf("staging promotion lost source_coordinate: got=%+v want=%+v", sub.SourceCoordinate, coord)
	}
}

func TestDefinitionHashBindsExplicitSourceCoordinate(t *testing.T) {
	c1 := externalReferenceCoordinate("sha256_hash_first")
	c2 := externalReferenceCoordinate("sha256_hash_second")
	c2.SourceContentHash = strings.Repeat("b", 64)
	s1 := referencePageSubmission(c1)
	s2 := referencePageSubmission(c2)
	h1, err := stepDefinitionHash(context.Background(), nil, s1)
	if err != nil {
		t.Fatalf("stepDefinitionHash(first): %v", err)
	}
	h2, err := stepDefinitionHash(context.Background(), nil, s2)
	if err != nil {
		t.Fatalf("stepDefinitionHash(second): %v", err)
	}
	if h1 == h2 {
		t.Fatalf("different explicit source coordinates produced the same definition_hash %q", h1)
	}
	d1, err := computeDefinitionHashForDedup(s1)
	if err != nil {
		t.Fatalf("computeDefinitionHashForDedup(first): %v", err)
	}
	if d1 != h1 {
		t.Errorf("dedup definition_hash=%q, ceremony definition_hash=%q", d1, h1)
	}
}

func TestSourceCoordinateStrictJSONRejectsUnknownFields(t *testing.T) {
	_, err := sourceCoordinateFromJSON(map[string]interface{}{
		"source_authority_id":     bootstrapSourceAuthority,
		"source_artifact_class":   "official_vendor_documentation",
		"source_ref_kind":         "coordinate",
		"source_stable_reference": "https://example.invalid",
		"version_coordinate":      "unversioned",
		"section_path":            "$",
		"source_reference":        "forbidden_legacy_alias",
	})
	if err == nil {
		t.Fatal("unknown source_coordinate field was silently ignored")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error=%v, want unknown field", err)
	}
}

func TestArtifactSubmissionJSONRejectsUnknownSourceCoordinateField(t *testing.T) {
	raw := `{
		"node_kind":"reference_page",
		"source_coordinate":{
			"source_authority_id":"767c2399-87f9-4859-ac64-afb575bdb263",
			"source_artifact_class":"official_vendor_documentation",
			"source_ref_kind":"coordinate",
			"source_stable_reference":"https://example.invalid",
			"version_coordinate":"source:767c2399-87f9-4859-ac64-afb575bdb263:example@sha256_example",
			"section_path":"$",
			"source_content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"source_content_hash_owner":"767c2399-87f9-4859-ac64-afb575bdb263",
			"source_refernece":"misspelled"
		}
	}`
	var sub ArtifactSubmission
	err := json.Unmarshal([]byte(raw), &sub)
	if err == nil {
		t.Fatal("ArtifactSubmission JSON silently discarded an unknown source_coordinate field")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error=%v, want unknown field", err)
	}
}

func TestResolveArtifactSourceCoordinateWrapsCanonicalGraphAddressValidation(t *testing.T) {
	c := externalReferenceCoordinate("sha256_valid")
	c.SourceStableReference = strings.Repeat("x", 2049)
	desc := NewNodeKindDescriptor(map[string]interface{}{
		"source_authority":         bootstrapSourceAuthority,
		"source_coordinate_policy": sourceCoordinatePolicyExternalReferenceRequired,
	})
	_, err := resolveArtifactSourceCoordinate("reference_page", "name", desc, c)
	if err == nil {
		t.Fatal("oversized source_stable_reference accepted")
	}
	if !strings.Contains(err.Error(), "STRING(2048)") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExternalReferenceRequiresExplicitCoordinateBeforeIO(t *testing.T) {
	env, ra := newSourceCoordinateEnv(t)
	sub := referencePageSubmission(nil)
	_, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{sub}})
	if err == nil || !strings.Contains(err.Error(), "source_coordinate required") {
		t.Fatalf("error=%v, want external source_coordinate required", err)
	}
	if ra.schemaChecks != 0 || len(ra.openedRuns) != 0 || len(ra.batches) != 0 {
		t.Fatalf("nil external coordinate reached substrate: %+v", ra)
	}
}

func TestStagingRejectsNilExternalCoordinateAndPayloadBeforeClient(t *testing.T) {
	for _, concept := range []stagingLoadConcept{
		{CanonicalName: "quickbooks_online_invoice_reference", NodeKind: "reference_page"},
		{
			CanonicalName:    "quickbooks_online_invoice_reference",
			NodeKind:         "reference_page",
			SourceCoordinate: externalReferenceCoordinate("sha256_staging_leak"),
			Payload:          map[string]interface{}{"content": "copied upstream body"},
		},
	} {
		env, _ := newSourceCoordinateEnv(t)
		_, err := handleStagingLoad(context.Background(), env, stagingLoadInput{Concepts: []stagingLoadConcept{concept}})
		if err == nil {
			t.Fatal("invalid external staging concept reached client acquisition")
		}
	}
}

func TestExternalReferenceRejectsUnregisteredAuthorityAndPathPrefixConfusion(t *testing.T) {
	for _, reference := range []string{
		"https://evil.example/app/developer/qbo/docs/api/accounting/all-entities/invoice",
		"https://developer.intuit.com/app/developer/qbo/docs-evil/api/accounting/all-entities/invoice",
	} {
		t.Run(reference, func(t *testing.T) {
			env, ra := newSourceCoordinateEnv(t)
			coord := externalReferenceCoordinate("sha256_untrusted")
			coord.SourceStableReference = reference
			_, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{referencePageSubmission(coord)}})
			if err == nil || !strings.Contains(err.Error(), "not admitted by external_sources registry") {
				t.Fatalf("error=%v, want registry refusal", err)
			}
			if ra.schemaChecks != 0 || len(ra.openedRuns) != 0 {
				t.Fatal("unregistered external source reached substrate")
			}
		})
	}
}

func TestExternalReferenceRequiresByteCanonicalHTTPSIdentity(t *testing.T) {
	cases := []string{
		"https://Developer.Intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice",
		"https://developer.intuit.com:443/app/developer/qbo/docs/api/accounting/all-entities/invoice",
		"https://developer.intuit.com:/app/developer/qbo/docs/api/accounting/all-entities/invoice",
		"https://developer.intuit.com/app/developer/qbo/docs/../docs/api/accounting/all-entities/invoice",
		"https://developer.intuit.com/app/developer/qbo/docs/%2e%2e/docs/api/accounting/all-entities/invoice",
		"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/%69nvoice",
		"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/%FF",
		"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice?a=%FF",
		"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice#%FF",
		"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice?b=2&a=1",
		"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice?a=1&a=2",
	}
	for _, reference := range cases {
		t.Run(reference, func(t *testing.T) {
			env, ra := newSourceCoordinateEnv(t)
			coord := externalReferenceCoordinate("sha256_noncanonical_url")
			coord.SourceStableReference = reference
			_, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{referencePageSubmission(coord)}})
			if err == nil {
				t.Fatal("noncanonical URL identity was admitted")
			}
			if ra.schemaChecks != 0 || len(ra.openedRuns) != 0 {
				t.Fatal("noncanonical URL reached substrate")
			}
		})
	}

	for _, reference := range []string{
		"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice?a=1&b=2",
		"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice#anchor=release-2026-08",
	} {
		t.Run("canonical_"+reference, func(t *testing.T) {
			env, _ := newSourceCoordinateEnv(t)
			if strings.Contains(reference, "?") {
				env.Config.ExternalSources[0].AllowQuery = true
			}
			coord := externalReferenceCoordinate("sha256_canonical_url")
			coord.SourceStableReference = reference
			coord.SourceContentHash = trustedExternalTestDigest(reference)
			if _, err := resolveExternalSourcePolicy(env.Config, "reference_page", "quickbooks_online_invoice_reference", *coord); err != nil {
				t.Fatalf("canonical URL rejected: %v", err)
			}
		})
	}
}

func TestExternalReferenceQueryAndFragmentPolicyIsExplicit(t *testing.T) {
	cases := []struct {
		name      string
		reference string
		mutate    func(*ExternalSourceDescriptor)
		wantOK    bool
	}{
		{"query_disallowed_by_default", "https://developer.intuit.com/app/developer/qbo/docs/invoice?a=1", nil, false},
		{"query_allowed_by_registry", "https://developer.intuit.com/app/developer/qbo/docs/invoice?a=1", func(d *ExternalSourceDescriptor) { d.AllowQuery = true }, true},
		{"fragment_allowed_by_registry", "https://developer.intuit.com/app/developer/qbo/docs/invoice#anchor=release-2026-08", nil, true},
		{"fragment_disallowed_by_registry", "https://developer.intuit.com/app/developer/qbo/docs/invoice#request", func(d *ExternalSourceDescriptor) { d.AllowFragment = false }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := newSourceCoordinateEnv(t)
			if tc.mutate != nil {
				tc.mutate(&env.Config.ExternalSources[0])
			}
			coord := externalReferenceCoordinate("sha256_url_component_policy")
			coord.SourceStableReference = tc.reference
			coord.SourceContentHash = trustedExternalTestDigest(tc.reference)
			_, err := resolveExternalSourcePolicy(env.Config, "reference_page", "quickbooks_online_invoice_reference", *coord)
			if tc.wantOK && err != nil {
				t.Fatalf("allowed coordinate rejected: %v", err)
			}
			if !tc.wantOK && (err == nil || !strings.Contains(err.Error(), "not admitted by external_sources")) {
				t.Fatalf("error=%v, want registry component-policy refusal", err)
			}
		})
	}
}

func TestCanonicalHTTPSReferenceRequiresOneRootPathSpelling(t *testing.T) {
	if _, err := parseCanonicalHTTPSReference("https://developer.intuit.com"); err == nil {
		t.Fatal("host-only URL admitted alongside its semantically equivalent slash-root form")
	}
	if _, err := parseCanonicalHTTPSReference("https://developer.intuit.com/"); err != nil {
		t.Fatalf("canonical slash-root URL rejected: %v", err)
	}
	if _, err := parseCanonicalHTTPSReference("https://developer.intuit.com/docs/"); err == nil {
		t.Fatal("non-root trailing-slash URL admitted alongside its canonical no-slash form")
	}
	if _, err := parseCanonicalHTTPSReference("https://developer.intuit.com/docs"); err != nil {
		t.Fatalf("canonical non-root URL rejected: %v", err)
	}
}

func TestCanonicalHTTPSReferenceRejectsPercentEncodedNonUTF8(t *testing.T) {
	for _, raw := range []string{
		"https://developer.intuit.com/docs/%FF",
		"https://developer.intuit.com/docs?a=%FF",
		"https://developer.intuit.com/docs#%FF",
	} {
		if _, err := parseCanonicalHTTPSReference(raw); err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
			t.Errorf("parseCanonicalHTTPSReference(%q) error=%v, want UTF-8 refusal", raw, err)
		}
	}
}

func TestExternalReferenceRejectsAmbiguousRegistryMatch(t *testing.T) {
	env, ra := newSourceCoordinateEnv(t)
	duplicate := env.Config.ExternalSources[0]
	duplicate.ID = "quickbooks_online_official_docs_shadow"
	env.Config.ExternalSources = append(env.Config.ExternalSources, duplicate)
	_, err := handleImport(context.Background(), env, importInput{
		Submissions: []ArtifactSubmission{referencePageSubmission(externalReferenceCoordinate("sha256_ambiguous"))},
	})
	if err == nil || !strings.Contains(err.Error(), "ambiguously matches") {
		t.Fatalf("error=%v, want ambiguous registry refusal", err)
	}
	if ra.schemaChecks != 0 || len(ra.openedRuns) != 0 {
		t.Fatal("ambiguous registry match reached substrate")
	}
}

func TestExternalReferenceRejectsProseLicenseEvidence(t *testing.T) {
	env, ra := newSourceCoordinateEnv(t)
	coord := externalReferenceCoordinate("sha256_license_leak")
	coord.LicenseEvidence = "These upstream terms may be copied into the graph as prose."
	_, err := handleImport(context.Background(), env, importInput{
		Submissions: []ArtifactSubmission{referencePageSubmission(coord)},
	})
	if err == nil || !strings.Contains(err.Error(), "HTTPS evidence URL or spdx") {
		t.Fatalf("error=%v, want non-prose license evidence refusal", err)
	}
	if ra.schemaChecks != 0 || len(ra.openedRuns) != 0 {
		t.Fatal("prose license evidence reached substrate")
	}
}

func TestExternalReferenceEnforcesRegistryLicenseEvidenceRequirement(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	coord := externalReferenceCoordinate("sha256_license_required")
	coord.LicenseEvidence = ""
	err := validateExternalRetrievalPermissionEvidence(env.Config.ExternalSources[0], *coord)
	if err == nil || !strings.Contains(err.Error(), "required by external source") {
		t.Fatalf("error=%v, want required license-evidence refusal", err)
	}
}

func TestAutomatedHTTPSRetrievalRejectsSPDXOnlyEvidenceBeforeNetwork(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	coord := externalReferenceCoordinate("sha256_spdx_assertion")
	coord.LicenseEvidence = "spdx:Apache-2.0"
	err := validateExternalRetrievalPermissionEvidence(env.Config.ExternalSources[0], *coord)
	if err == nil || !strings.Contains(err.Error(), "SPDX-only evidence cannot authorize") {
		t.Fatalf("error=%v, want SPDX-only retrieval-permission refusal", err)
	}
}

func TestExternalReferenceRejectsUpstreamPayloadLeak(t *testing.T) {
	env, ra := newSourceCoordinateEnv(t)
	sub := referencePageSubmission(externalReferenceCoordinate("sha256_leak"))
	sub.Payload = map[string]interface{}{"body": "copied upstream QuickBooks documentation"}
	_, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{sub}})
	if err == nil || !strings.Contains(err.Error(), "stable-reference-only") {
		t.Fatalf("error=%v, want stable-reference-only refusal", err)
	}
	if ra.schemaChecks != 0 || len(ra.openedRuns) != 0 {
		t.Fatal("external payload leak reached substrate")
	}
}

func TestExternalReferenceCanonicalNameIsCoordinateBoundAndNonProse(t *testing.T) {
	for _, stableID := range []string{"different_reference_name", "Copied QuickBooks page title"} {
		t.Run(stableID, func(t *testing.T) {
			env, ra := newSourceCoordinateEnv(t)
			sub := referencePageSubmission(externalReferenceCoordinate("sha256_name_binding"))
			sub.StableID = stableID
			_, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{sub}})
			if err == nil {
				t.Fatal("unbound or prose external canonical name was admitted")
			}
			if ra.schemaChecks != 0 || len(ra.openedRuns) != 0 {
				t.Fatal("invalid external canonical name reached substrate")
			}
		})
	}
}

func TestExternalReferenceRequiresConfigured3072DimensionEmbedding(t *testing.T) {
	makeFinal := func(env *Env) (ArtifactSourceCoordinate, ExternalSourceDescriptor) {
		coord := *externalReferenceCoordinate("sha256_embed")
		coord.SourceContentHashOwner = coord.SourceAuthorityID
		coord.RetrievedAt = env.Now().UTC().Format(time.RFC3339Nano)
		coord.VersionCoordinate = VersionCoordinate{Kind: VersionSourceNamed, SourceAuthorityID: coord.SourceAuthorityID, StableName: "quickbooks_online_invoice_reference", SourceVersionToken: "sha256_" + coord.SourceContentHash}.String()
		return coord, env.Config.ExternalSources[0]
	}
	t.Run("missing_client", func(t *testing.T) {
		env, _ := newSourceCoordinateEnv(t)
		env.Embed = nil
		coord, policy := makeFinal(env)
		if err := validateFinalExternalCoordinate(env, "reference_page", "quickbooks_online_invoice_reference", coord, policy); err == nil || !strings.Contains(err.Error(), "configured embedding client") {
			t.Fatalf("error=%v, want configured embedding client", err)
		}
	})
	t.Run("wrong_config_dimension", func(t *testing.T) {
		env, _ := newSourceCoordinateEnv(t)
		env.Config.Embedding.Dimensions = 768
		coord, policy := makeFinal(env)
		if err := validateFinalExternalCoordinate(env, "reference_page", "quickbooks_online_invoice_reference", coord, policy); err == nil || !strings.Contains(err.Error(), "3072 dimensions") {
			t.Fatalf("error=%v, want 3072 dimensions", err)
		}
	})
	t.Run("wrong_result_dimension", func(t *testing.T) {
		env, _ := newSourceCoordinateEnv(t)
		env.Embed = fixedEmbeddingClient{dimensions: 768}
		_, policy := makeFinal(env)
		objects := []GraphObject{{SearchText: "external reference"}}
		err := embedExternalObjectsBounded(context.Background(), env, objects, []string{"quickbooks_online_invoice_reference"}, []ExternalSourceDescriptor{policy})
		if err == nil || !strings.Contains(err.Error(), "got 768 dimensions") {
			t.Fatalf("error=%v, want malformed embedding refusal", err)
		}
	})
}

func TestExternalReferenceProjectsOnlyAllowlistedSearchMetadata(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	retrievedAt := time.Date(2026, 8, 21, 12, 0, 0, 123456789, time.UTC)
	env.Now = func() time.Time { return retrievedAt.Add(time.Hour) }
	coord := *externalReferenceCoordinate("sha256_metadata")
	coord.LicenseEvidence = quickBooksTestRetrievalPermissionEvidence
	coord.SourceContentHashOwner = coord.SourceAuthorityID
	coord.RetrievedAt = retrievedAt.Format(time.RFC3339Nano)
	coord.VersionCoordinate = VersionCoordinate{Kind: VersionSourceNamed, SourceAuthorityID: coord.SourceAuthorityID, StableName: "quickbooks_online_invoice_reference", SourceVersionToken: "sha256_" + coord.SourceContentHash}.String()
	policy := env.Config.ExternalSources[0]
	address := GraphAddress{ObjectClass: "reference_page", SourceAuthorityID: coord.SourceAuthorityID, SourceRefKind: coord.SourceRefKind, SourceRef: coord.SourceStableReference, VersionCoordinate: coord.VersionCoordinate, SectionPath: coord.SectionPath}.String()
	obj := GraphObject{
		OrganizationID: "org-test", GraphSnapshotID: uuid.NewString(), GraphObjectID: uuid.NewString(), ObjectClass: "reference_page",
		SourceAuthorityID: coord.SourceAuthorityID, SourceStableReference: coord.SourceStableReference,
		VersionCoordinate: coord.VersionCoordinate, SectionPath: coord.SectionPath,
		MaterializationRunID: uuid.NewString(), ValidationState: "valid", Status: "active", VisibilityScope: "organization",
		SearchText: externalReferenceSearchText("reference_page", coord, policy), SearchPayload: externalReferenceSearchPayload("reference_page", address, coord, policy), EmbeddingModel: embeddingModelOrEmpty(env),
	}
	objects := []GraphObject{obj}
	if err := embedExternalObjectsBounded(context.Background(), env, objects, []string{"quickbooks_online_invoice_reference"}, []ExternalSourceDescriptor{policy}); err != nil {
		t.Fatal(err)
	}
	obj = objects[0]
	for _, forbidden := range []string{"contract", "payload", "title", "summary", "content", "body", "snippet"} {
		if _, exists := obj.SearchPayload[forbidden]; exists {
			t.Errorf("forbidden search_payload key %q materialized", forbidden)
		}
	}
	tokens, ok := obj.SearchPayload["graph_owned_parser_classification_tokens"].(map[string]interface{})
	if !ok || tokens["source_registry_id"] != "quickbooks_online_official_docs" || tokens["content_hash_algorithm"] != "sha256" {
		t.Fatalf("required graph-owned source metadata missing: %#v", obj.SearchPayload)
	}
	if _, present := tokens["retrieved_at"]; present {
		t.Fatal("run-occurrence freshness leaked into immutable semantic search payload")
	}
	if len(obj.Embedding) != externalReferenceEmbeddingDimensions || obj.EmbeddingModel != "gemini-embedding-001" {
		t.Fatalf("external object embedding=%d/%q, want 3072/gemini-embedding-001", len(obj.Embedding), obj.EmbeddingModel)
	}
	symbol, err := externalReferenceSymbol(obj, "quickbooks_online_invoice_reference", coord, oodGraphIDNamespace)
	if err != nil || len(symbol.Embedding) != externalReferenceEmbeddingDimensions {
		t.Fatalf("external metadata symbol embedding=%d err=%v", len(symbol.Embedding), err)
	}
}

func TestSourceCoordinateRejectsEncodedGraphAddressOverflow(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	c := *externalReferenceCoordinate("sha256_overflow")
	c.SourceStableReference = "https://developer.intuit.com/app/developer/qbo/docs/" + strings.Repeat(":", 1350)
	c.SourceContentHashOwner = c.SourceAuthorityID
	c.RetrievedAt = env.Now().UTC().Format(time.RFC3339Nano)
	c.VersionCoordinate = VersionCoordinate{Kind: VersionSourceNamed, SourceAuthorityID: c.SourceAuthorityID, StableName: "quickbooks_online_invoice_reference", SourceVersionToken: "sha256_" + c.SourceContentHash}.String()
	err := validateFinalExternalCoordinate(env, "reference_page", "quickbooks_online_invoice_reference", c, env.Config.ExternalSources[0])
	if err == nil || !strings.Contains(err.Error(), "graph_address exceeds") {
		t.Fatalf("error=%v, want encoded graph_address overflow", err)
	}
}

func TestSourceCoordinateJSONRejectsDuplicateKnownFields(t *testing.T) {
	raw := `{
		"source_authority_id":"767c2399-87f9-4859-ac64-afb575bdb263",
		"source_authority_id":"46954a80-78eb-4351-8be7-6e7d7eba8f5b",
		"source_artifact_class":"official_vendor_documentation",
		"source_ref_kind":"coordinate",
		"source_stable_reference":"https://developer.intuit.com/app/developer/qbo/docs/",
		"version_coordinate":"source:767c2399-87f9-4859-ac64-afb575bdb263:quickbooks_online_docs@sha256_x",
		"section_path":"$"
	}`
	var c ArtifactSourceCoordinate
	err := json.Unmarshal([]byte(raw), &c)
	if err == nil || !strings.Contains(err.Error(), "duplicate field") {
		t.Fatalf("error=%v, want duplicate-field refusal", err)
	}
}

func TestArtifactSubmissionJSONRejectsDuplicateCoordinateMembers(t *testing.T) {
	coordinate := `{
		"source_authority_id":"767c2399-87f9-4859-ac64-afb575bdb263",
		"source_artifact_class":"official_vendor_documentation",
		"source_ref_kind":"coordinate",
		"source_stable_reference":"https://developer.intuit.com/app/developer/qbo/docs/",
		"version_coordinate":"source:767c2399-87f9-4859-ac64-afb575bdb263:quickbooks_online_docs@sha256_x",
		"section_path":"$"
	}`
	raw := `{"node_kind":"reference_page","source_coordinate":` + coordinate + `,"source_coordinate":` + coordinate + `}`
	var sub ArtifactSubmission
	err := json.Unmarshal([]byte(raw), &sub)
	if err == nil || !strings.Contains(err.Error(), `duplicate field "source_coordinate"`) {
		t.Fatalf("error=%v, want duplicate submission coordinate refusal", err)
	}
}

func TestStagingConceptJSONRejectsDuplicateCoordinateMembers(t *testing.T) {
	coordinate := `{
		"source_authority_id":"767c2399-87f9-4859-ac64-afb575bdb263",
		"source_artifact_class":"official_vendor_documentation",
		"source_ref_kind":"coordinate",
		"source_stable_reference":"https://developer.intuit.com/app/developer/qbo/docs/",
		"version_coordinate":"source:767c2399-87f9-4859-ac64-afb575bdb263:quickbooks_online_docs@sha256_x",
		"section_path":"$"
	}`
	raw := `{"canonical_name":"quickbooks_online_docs","node_kind":"reference_page","source_coordinate":` + coordinate + `,"source_coordinate":` + coordinate + `}`
	var concept stagingLoadConcept
	err := json.Unmarshal([]byte(raw), &concept)
	if err == nil || !strings.Contains(err.Error(), `duplicate field "source_coordinate"`) {
		t.Fatalf("error=%v, want duplicate staging coordinate refusal", err)
	}
}

func TestExplicitCoordinateRejectedForLegacyClass(t *testing.T) {
	env, ra := newSourceCoordinateEnv(t)
	coord := externalReferenceCoordinate("sha256_wrong_class")
	sub := ArtifactSubmission{NodeKind: "axiom", StableID: "legacy_axiom", SourceCoordinate: coord}
	_, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{sub}})
	if err == nil || !strings.Contains(err.Error(), "supported only for registry-declared external-reference classes") {
		t.Fatalf("error=%v, want per-class coordinate refusal", err)
	}
	if ra.schemaChecks != 0 || len(ra.openedRuns) != 0 {
		t.Fatal("invalid legacy coordinate reached substrate")
	}
}

func TestDerivedSymbolIdentityFailsBeforeRunOpen(t *testing.T) {
	cases := []map[string]interface{}{
		{"BadKey": "invalid section segment"},
		{strings.Repeat("a", 2040): "section/address overflow"},
	}
	for i, payload := range cases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			env, ra := newSourceCoordinateEnv(t)
			sub := ArtifactSubmission{
				NodeKind: "axiom",
				StableID: "derived_symbol_guard",
				Payload:  payload,
			}
			_, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{sub}})
			if err == nil {
				t.Fatal("invalid derived symbol identity was materialized")
			}
			if len(ra.openedRuns) != 0 || len(ra.batches) != 0 {
				t.Fatalf("invalid derived symbol reached run/commit: opened=%d batches=%d", len(ra.openedRuns), len(ra.batches))
			}
		})
	}
}

func TestSourceCoordinatesFromRowsRejectsMalformedSymbolAddress(t *testing.T) {
	_, err := SourceCoordinatesFromRows(nil, []GraphSymbol{{
		SymbolID:     "bad-symbol",
		GraphAddress: "not-an-ood-address",
	}}, nil)
	if err == nil || !strings.Contains(err.Error(), "non-canonical graph_address") {
		t.Fatalf("error=%v, want malformed symbol graph_address refusal", err)
	}
}
