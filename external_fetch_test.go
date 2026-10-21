package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type externalReferenceFetcherFunc func(context.Context, string, ExternalSourceDescriptor, string) (verifiedExternalSourceReceipt, error)

func (f externalReferenceFetcherFunc) Fetch(ctx context.Context, reference string, policy ExternalSourceDescriptor, authority string) (verifiedExternalSourceReceipt, error) {
	return f(ctx, reference, policy, authority)
}

func canonicalTLSTestClient(t *testing.T, handler http.Handler) (*http.Client, string) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	base := server.Client()
	transport, ok := base.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("TLS test transport type=%T", base.Transport)
	}
	transport = transport.Clone()
	transport.Proxy = nil
	serverAddress := server.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}
	client := *base
	client.Transport = transport
	return &client, "https://example.com"
}

func tlsTestExternalPolicy(prefix string) ExternalSourceDescriptor {
	return ExternalSourceDescriptor{
		ID:                      "official_test_docs",
		SourceArtifactClass:     "official_vendor_documentation",
		ReferenceKind:           "https_url_prefix",
		ReferencePrefix:         prefix,
		ContentHashAlgorithm:    "sha256",
		VersionCoordinateMode:   externalVersionModeContentDigest,
		VersionStableNamePrefix: "official_test_",
		AllowedObjectClasses:    []string{"reference_page"},
		LocatorKinds:            map[string]string{"reference_page": "html_id_or_name"},
		FreshnessWindowSeconds:  3600,
		LicenseEvidenceRequired: true,
		LicenseEvidenceBinding:  licenseEvidenceBindingCoordinate,
		RetrievalPermissionEvidenceCoordinates: []string{
			"https://example.com/retrieval-permission",
		},
	}
}

func sameRepositoryTestExternalPolicy() (ExternalSourceDescriptor, ArtifactSourceCoordinate) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	policy := ExternalSourceDescriptor{
		ID:                                      "official_test_repository",
		SourceArtifactClass:                     "official_source_repository",
		ReferenceKind:                           "https_url_prefix",
		ReferencePrefix:                         "https://example.com/vendor",
		ContentHashAlgorithm:                    "sha256",
		VersionCoordinateMode:                   externalVersionModeUpstreamPinned,
		VersionStableNamePrefix:                 "official_test_repository_",
		AllowedObjectClasses:                    []string{"source_repo"},
		LocatorKinds:                            map[string]string{"source_repo": "resource_root"},
		FreshnessWindowSeconds:                  3600,
		LicenseEvidenceRequired:                 true,
		LicenseEvidenceBinding:                  licenseEvidenceBindingSameRepositoryFile,
		RepositoryPathSegments:                  2,
		UpstreamIdentityPolicy:                  upstreamIdentityImmutableRefWithContentDigest,
		ImmutableReferencePattern:               `^https://example\.com/vendor/repository/commit/(?P<immutable_ref>[0-9a-f]{40})$`,
		SameRepositoryPermissionEvidencePattern: `^https://example\.com/vendor/repository/blob/(?P<immutable_ref>[0-9a-f]{40})/(LICENSE|LICENSE\.[A-Za-z0-9._-]+|COPYING|COPYING\.[A-Za-z0-9._-]+)$`,
	}
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID:     bootstrapSourceAuthority,
		SourceStableReference: "https://example.com/vendor/repository/commit/" + commit,
		LicenseEvidence:       "https://example.com/vendor/repository/blob/" + commit + "/LICENSE",
	}
	return policy, coord
}

func TestHTTPExternalReferenceFetcherAttestsExactResponseOctets(t *testing.T) {
	body := []byte("line one\r\nline two\nUnicode: café\n")
	var gotPath, gotEncoding string
	client, prefix := canonicalTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		gotEncoding = r.Header.Get("Accept-Encoding")
		w.Header().Set("ETag", `W/"page-version-1"`)
		_, _ = w.Write(body)
	}))
	now := time.Date(2026, 8, 21, 12, 34, 56, 789, time.UTC)
	fetcher := newHTTPExternalReferenceFetcher(client, int64(len(body))+1, func() time.Time { return now })
	reference := prefix + "/docs/page#request-body"
	receipt, err := fetcher.Fetch(context.Background(), reference, tlsTestExternalPolicy(prefix), bootstrapSourceAuthority)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	want := sha256.Sum256(body)
	if receipt.SHA256 != hex.EncodeToString(want[:]) || receipt.ByteLength != int64(len(body)) || string(receipt.Body) != string(body) {
		t.Fatalf("receipt digest/length/body=%q/%d/%q", receipt.SHA256, receipt.ByteLength, receipt.Body)
	}
	if receipt.CanonicalReference != prefix+"/docs/page" || receipt.RetrievedAt != now || receipt.SourceRegistryID != "official_test_docs" || receipt.SourceAuthorityID != bootstrapSourceAuthority {
		t.Fatalf("receipt bindings=%+v", receipt)
	}
	if receipt.ContentCoding != "identity" || receipt.DecodedByteLength != receipt.ByteLength || receipt.DecodedSHA256 != receipt.SHA256 || !bytes.Equal(receipt.LocatorBody, body) {
		t.Fatalf("identity locator receipt=%+v", receipt)
	}
	if gotPath != "/docs/page" {
		t.Fatalf("HTTP request URI=%q, want fragment-free exact resource path", gotPath)
	}
	if gotEncoding != "identity" {
		t.Fatalf("Accept-Encoding=%q, want identity", gotEncoding)
	}
}

func gzipExternalTestBytes(t *testing.T, decoded []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := writer.Write(decoded); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestHTTPExternalReferenceFetcherBindsRawGzipAndBoundedDecodedLocatorView(t *testing.T) {
	decoded := []byte(`{"Invoice":{"name":"Invoice"}}`)
	wire := gzipExternalTestBytes(t, decoded)
	client, prefix := canonicalTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.Header().Set("ETag", `"encoded-v1"`)
		_, _ = w.Write(wire)
	}))
	policy := tlsTestExternalPolicy(prefix)
	policy.AllowedObjectClasses = []string{"api_symbol"}
	policy.LocatorKinds = map[string]string{"api_symbol": "json_pointer"}
	reference := prefix + "/objects.json#/Invoice"
	receipt, err := newHTTPExternalReferenceFetcher(client, 1024, time.Now).Fetch(context.Background(), reference, policy, bootstrapSourceAuthority)
	if err != nil {
		t.Fatal(err)
	}
	rawSum := sha256.Sum256(wire)
	decodedSum := sha256.Sum256(decoded)
	if receipt.ContentCoding != "gzip" || receipt.SHA256 != hex.EncodeToString(rawSum[:]) || receipt.DecodedSHA256 != hex.EncodeToString(decodedSum[:]) || receipt.ByteLength != int64(len(wire)) || receipt.DecodedByteLength != int64(len(decoded)) || !bytes.Equal(receipt.Body, wire) || !bytes.Equal(receipt.LocatorBody, decoded) {
		t.Fatalf("gzip receipt did not keep raw and locator evidence distinct: %+v", receipt)
	}
	if receipt.TransportStatus != "success" || receipt.TransportRawHashAlgorithm != "sha256" || receipt.SourceRepresentationMediaType != "application/json" || receipt.TransportCharset != "utf-8" {
		t.Fatalf("transport receipt metadata is incomplete or noncanonical: %+v", receipt)
	}
	if err := validateExternalContentHash("sha256", receipt.TransportResponseMetadataDigest); err != nil {
		t.Fatalf("transport response metadata digest: %v", err)
	}
	locatorReceipt := receipt
	locatorReceipt.Body = receipt.LocatorBody
	locatorReceipt.ByteLength = receipt.DecodedByteLength
	coord := ArtifactSourceCoordinate{SourceStableReference: reference}
	canonicalName, err := canonicalExternalLocatorName("api_symbol", coord, policy, "Invoice")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyExternalObjectLocator("api_symbol", canonicalName, coord, policy, locatorReceipt); err != nil {
		t.Fatalf("JSON Pointer did not resolve in bounded decoded gzip view: %v", err)
	}
}

func TestHTTPExternalReferenceFetcherRejectsAmbiguousOrUnboundedGzip(t *testing.T) {
	first := gzipExternalTestBytes(t, []byte(`{"Invoice":{}}`))
	second := gzipExternalTestBytes(t, []byte(`{"Customer":{}}`))
	tests := []struct {
		name     string
		wire     []byte
		maxBytes int64
		want     string
	}{
		{name: "concatenated_members", wire: append(append([]byte(nil), first...), second...), maxBytes: 1024, want: "concatenated members or trailing bytes"},
		{name: "trailing_bytes", wire: append(append([]byte(nil), first...), 0x00), maxBytes: 1024, want: "concatenated members or trailing bytes"},
		{name: "decoded_oversize", wire: gzipExternalTestBytes(t, bytes.Repeat([]byte("x"), 1024)), maxBytes: 64, want: "decoded gzip locator view exceeds 64-byte limit"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, prefix := canonicalTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write(tc.wire)
			}))
			_, err := newHTTPExternalReferenceFetcher(client, tc.maxBytes, time.Now).Fetch(context.Background(), prefix+"/objects.json", tlsTestExternalPolicy(prefix), bootstrapSourceAuthority)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Fetch error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestHTTPExternalReferenceFetcherDerivesUpstreamPinnedVersionFromResponseEvidence(t *testing.T) {
	t.Run("weak etag is bound to exact raw digest", func(t *testing.T) {
		client, prefix := canonicalTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("ETag", `W/"release-2026-08"`)
			_, _ = w.Write([]byte("release"))
		}))
		policy := tlsTestExternalPolicy(prefix)
		policy.VersionCoordinateMode = externalVersionModeUpstreamPinned
		policy.UpstreamIdentityPolicy = upstreamIdentityHTTPResponseWithContentDigest
		receipt, err := newHTTPExternalReferenceFetcher(client, 1024, time.Now).Fetch(context.Background(), prefix+"/repo", policy, bootstrapSourceAuthority)
		if err != nil {
			t.Fatal(err)
		}
		want, err := trustedUpstreamVersionToken("http_weak_etag", `W/"release-2026-08"`, receipt.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.UpstreamVersionEvidenceKind != "http_weak_etag" || receipt.UpstreamVersionEvidence != `W/"release-2026-08"` || receipt.UpstreamVersionToken != want {
			t.Fatalf("upstream response evidence=%q/%q/%q, want http_weak_etag/raw/%q", receipt.UpstreamVersionEvidenceKind, receipt.UpstreamVersionEvidence, receipt.UpstreamVersionToken, want)
		}
		other := sha256.Sum256([]byte("different exact representation"))
		otherToken, err := trustedUpstreamVersionToken("http_weak_etag", `W/"release-2026-08"`, hex.EncodeToString(other[:]))
		if err != nil {
			t.Fatal(err)
		}
		if otherToken == receipt.UpstreamVersionToken {
			t.Fatal("one weak ETag minted the same version token for different exact response bytes")
		}
	})

	for _, tc := range []struct {
		name string
		etag string
		want string
	}{
		{name: "missing", want: "no trusted version evidence"},
		{name: "malformed", etag: "release-2026-08", want: "not a canonical HTTP entity-tag"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, prefix := canonicalTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.etag != "" {
					w.Header().Set("ETag", tc.etag)
				}
				_, _ = w.Write([]byte("release"))
			}))
			policy := tlsTestExternalPolicy(prefix)
			policy.VersionCoordinateMode = externalVersionModeUpstreamPinned
			policy.UpstreamIdentityPolicy = upstreamIdentityHTTPResponseWithContentDigest
			_, err := newHTTPExternalReferenceFetcher(client, 1024, time.Now).Fetch(context.Background(), prefix+"/repo", policy, bootstrapSourceAuthority)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Fetch error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestHTTPExternalReferenceFetcherDerivesUpstreamPinnedVersionFromImmutableCoordinate(t *testing.T) {
	body := []byte("immutable repository snapshot")
	requests := 0
	client, prefix := canonicalTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = w.Write(body)
	}))
	policy := tlsTestExternalPolicy(prefix)
	policy.VersionCoordinateMode = externalVersionModeUpstreamPinned
	policy.UpstreamIdentityPolicy = upstreamIdentityImmutableRefWithContentDigest
	policy.ImmutableReferencePattern = `^https://example\.com/repository/commit/[0-9a-f]{40}$`
	commit := "0123456789abcdef0123456789abcdef01234567"
	resource := prefix + "/repository/commit/" + commit
	receipt, err := newHTTPExternalReferenceFetcher(client, 1024, time.Now).Fetch(context.Background(), resource+"#symbol=Invoice.Id", policy, bootstrapSourceAuthority)
	if err != nil {
		t.Fatal(err)
	}
	want, err := trustedUpstreamVersionToken("immutable_reference_coordinate", resource, receipt.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.CanonicalReference != resource || receipt.UpstreamVersionEvidenceKind != "immutable_reference_coordinate" || receipt.UpstreamVersionEvidence != resource || receipt.UpstreamVersionToken != want {
		t.Fatalf("immutable receipt=%+v, want fragment-free coordinate %q plus raw digest binding", receipt, resource)
	}

	_, err = newHTTPExternalReferenceFetcher(client, 1024, time.Now).Fetch(context.Background(), prefix+"/repository/main", policy, bootstrapSourceAuthority)
	if err == nil || !strings.Contains(err.Error(), "not an immutable coordinate") {
		t.Fatalf("mutable reference error=%v, want fail-closed immutable-coordinate refusal", err)
	}
	if requests != 1 {
		t.Fatalf("mutable reference reached network; requests=%d, want 1 total", requests)
	}
}

func TestHTTPExternalReferenceFetcherDigestChangesForEveryByteChange(t *testing.T) {
	bodies := [][]byte{
		[]byte("line\n"),
		[]byte("line\r\n"),
		[]byte("café"),
		[]byte("cafe"),
	}
	seen := map[string]bool{}
	for i, body := range bodies {
		t.Run(fmt.Sprintf("body_%d", i), func(t *testing.T) {
			client, prefix := canonicalTLSTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
			receipt, err := newHTTPExternalReferenceFetcher(client, 1024, time.Now).Fetch(context.Background(), prefix+"/page", tlsTestExternalPolicy(prefix), bootstrapSourceAuthority)
			if err != nil {
				t.Fatal(err)
			}
			if seen[receipt.SHA256] {
				t.Fatalf("distinct exact byte sequence reused digest %q", receipt.SHA256)
			}
			seen[receipt.SHA256] = true
		})
	}
}

func TestHTTPExternalReferenceFetcherFailsClosedOnUnattestableResponse(t *testing.T) {
	tests := []struct {
		name     string
		maxBytes int64
		handler  http.Handler
		want     string
	}{
		{
			name: "redirect",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "/other")
				w.WriteHeader(http.StatusFound)
			}),
			want: "HTTP status 302",
		},
		{
			name:    "non_2xx",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "no", http.StatusServiceUnavailable) }),
			want:    "HTTP status 503",
		},
		{
			name: "encoded_representation",
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", "br")
				_, _ = w.Write([]byte("encoded"))
			}),
			want: "content-encoding",
		},
		{
			name:     "declared_oversize",
			maxBytes: 3,
			handler:  http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("four")) }),
			want:     "exceeds 3-byte limit",
		},
		{
			name:     "streamed_oversize",
			maxBytes: 3,
			handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.(http.Flusher).Flush()
				_, _ = w.Write([]byte("four"))
			}),
			want: "response exceeds 3-byte limit",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, prefix := canonicalTLSTestClient(t, tc.handler)
			limit := tc.maxBytes
			if limit == 0 {
				limit = 1024
			}
			_, err := newHTTPExternalReferenceFetcher(client, limit, time.Now).Fetch(context.Background(), prefix+"/page", tlsTestExternalPolicy(prefix), bootstrapSourceAuthority)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Fetch error=%v, want %q", err, tc.want)
			}
		})
	}
}

type countingEmbeddingClient struct{ calls int }

func (c *countingEmbeddingClient) Embed(context.Context, string, string) ([]float32, error) {
	c.calls++
	return make([]float32, externalReferenceEmbeddingDimensions), nil
}

type countingExternalFetcher struct {
	delegate externalReferenceFetcher
	calls    int
}

func (f *countingExternalFetcher) Fetch(ctx context.Context, reference string, policy ExternalSourceDescriptor, authority string) (verifiedExternalSourceReceipt, error) {
	f.calls++
	return f.delegate.Fetch(ctx, reference, policy, authority)
}

func TestExternalVerificationMemoizesOneExactResourcePerImport(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	counting := &countingExternalFetcher{delegate: deterministicExternalFetcher{}}
	env.ExternalFetch = counting
	policy := tlsTestExternalPolicy("https://example.com")
	ctx := withExternalVerificationSession(context.Background(), "org-memoized")
	for _, reference := range []string{
		"https://example.com/root",
		"https://example.com/invoice#anchor=page",
		"https://example.com/invoice#anchor=symbol",
		"https://example.com/releases",
	} {
		if _, err := fetchExternalReceiptResource(ctx, env, "org-memoized", reference, policy, bootstrapSourceAuthority); err != nil {
			t.Fatal(err)
		}
	}
	// The page and api_symbol coordinates name different graph fragments of
	// the same exact HTTP resource. Root + page/symbol + release-note are the
	// three byte resources; fetching four times would defeat request-scoped
	// receipt reuse and allow one logical document to race itself.
	if counting.calls != 3 {
		t.Fatalf("external fetch calls=%d, want 3 distinct fragmentless resources", counting.calls)
	}
}

func TestExternalVerificationSessionDoesNotSerializeDistinctResources(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	policy := tlsTestExternalPolicy("https://example.com")
	started := make(chan string, 2)
	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	base := deterministicExternalFetcher{}
	env.ExternalFetch = externalReferenceFetcherFunc(func(ctx context.Context, reference string, policy ExternalSourceDescriptor, authority string) (verifiedExternalSourceReceipt, error) {
		started <- reference
		select {
		case <-release:
			return base.Fetch(ctx, reference, policy, authority)
		case <-ctx.Done():
			return verifiedExternalSourceReceipt{}, ctx.Err()
		}
	})
	ctx := withExternalVerificationSession(context.Background(), "org-concurrent")
	result := make(chan error, 2)
	for _, suffix := range []string{"invoice", "customer"} {
		coord := ArtifactSourceCoordinate{
			SourceAuthorityID:     bootstrapSourceAuthority,
			SourceStableReference: "https://example.com/docs/" + suffix,
			LicenseEvidence:       "https://example.com/retrieval-permission",
		}
		go func() {
			_, err := fetchExternalReceiptResource(ctx, env, "org-concurrent", coord.SourceStableReference, policy, coord.SourceAuthorityID)
			result <- err
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("distinct external resources were serialized behind a session-wide network lock")
		}
	}
	close(release)
	released = true
	for i := 0; i < 2; i++ {
		if err := <-result; err != nil {
			t.Fatalf("concurrent fetch: %v", err)
		}
	}
}

func TestExternalVerificationSessionCoalescesConcurrentDuplicateResource(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	policy := tlsTestExternalPolicy("https://example.com")
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	base := deterministicExternalFetcher{}
	env.ExternalFetch = externalReferenceFetcherFunc(func(ctx context.Context, reference string, policy ExternalSourceDescriptor, authority string) (verifiedExternalSourceReceipt, error) {
		started <- struct{}{}
		select {
		case <-release:
			return base.Fetch(ctx, reference, policy, authority)
		case <-ctx.Done():
			return verifiedExternalSourceReceipt{}, ctx.Err()
		}
	})
	ctx := withExternalVerificationSession(context.Background(), "org-singleflight")
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID:     bootstrapSourceAuthority,
		SourceStableReference: "https://example.com/docs/invoice#anchor=invoice",
		LicenseEvidence:       "https://example.com/retrieval-permission",
	}
	result := make(chan error, 2)
	go func() {
		_, err := fetchExternalReceiptResource(ctx, env, "org-singleflight", coord.SourceStableReference, policy, coord.SourceAuthorityID)
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first external fetch did not start")
	}
	go func() {
		duplicate := coord
		duplicate.SourceStableReference = "https://example.com/docs/invoice#anchor=other"
		_, err := fetchExternalReceiptResource(ctx, env, "org-singleflight", duplicate.SourceStableReference, policy, duplicate.SourceAuthorityID)
		result <- err
	}()
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-result; err != nil {
			t.Fatalf("coalesced fetch: %v", err)
		}
	}
	if got := len(started); got != 0 {
		t.Fatalf("duplicate fragmentless resource started %d additional fetches", got)
	}
}

func TestExternalVerificationSessionCapacityFailuresRetainNoResponseBuffers(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	policy := tlsTestExternalPolicy("https://example.com")
	calls := 0
	base := deterministicExternalFetcher{}
	env.ExternalFetch = externalReferenceFetcherFunc(func(ctx context.Context, reference string, policy ExternalSourceDescriptor, authority string) (verifiedExternalSourceReceipt, error) {
		calls++
		return base.Fetch(ctx, reference, policy, authority)
	})
	ctx := withExternalVerificationSession(context.Background(), "org-capacity")
	session := ctx.Value(externalVerificationSessionContextKey{}).(*externalVerificationSession)
	session.totalBytes = maxExternalVerificationSessionBytes - 1

	const distinctResources = 32
	for i := 0; i < distinctResources; i++ {
		coord := ArtifactSourceCoordinate{
			SourceAuthorityID:     bootstrapSourceAuthority,
			SourceStableReference: fmt.Sprintf("https://example.com/docs/resource-%02d", i),
			LicenseEvidence:       "https://example.com/retrieval-permission",
		}
		receipt, err := fetchExternalReceiptResource(ctx, env, "org-capacity", coord.SourceStableReference, policy, coord.SourceAuthorityID)
		if err == nil || !strings.Contains(err.Error(), "aggregate receipt limit") {
			t.Fatalf("resource %d error=%v, want aggregate receipt limit", i, err)
		}
		if len(receipt.Body) != 0 || len(receipt.LocatorBody) != 0 {
			t.Fatalf("resource %d returned over-limit response buffers", i)
		}
	}
	if calls != distinctResources {
		t.Fatalf("fetch calls=%d, want %d distinct resources", calls, distinctResources)
	}
	session.mu.Lock()
	if session.totalBytes != maxExternalVerificationSessionBytes-1 {
		t.Fatalf("failed reservations changed retained byte count to %d", session.totalBytes)
	}
	if len(session.entries) != distinctResources {
		t.Fatalf("error entries=%d, want %d", len(session.entries), distinctResources)
	}
	for key, entry := range session.entries {
		if len(entry.receipt.Body) != 0 || len(entry.receipt.LocatorBody) != 0 {
			session.mu.Unlock()
			t.Fatalf("over-limit cache entry %q retained response buffers", key.ResourceReference)
		}
	}
	session.mu.Unlock()

	first := ArtifactSourceCoordinate{
		SourceAuthorityID:     bootstrapSourceAuthority,
		SourceStableReference: "https://example.com/docs/resource-00#anchor=same-resource",
		LicenseEvidence:       "https://example.com/retrieval-permission",
	}
	receipt, err := fetchExternalReceiptResource(ctx, env, "org-capacity", first.SourceStableReference, policy, first.SourceAuthorityID)
	if err == nil || len(receipt.Body) != 0 || len(receipt.LocatorBody) != 0 {
		t.Fatalf("cached capacity failure returned receipt=%+v error=%v", receipt, err)
	}
	if calls != distinctResources {
		t.Fatalf("cached bounded error refetched upstream: calls=%d", calls)
	}
}

func TestExternalFetchRejectsMalformedPermissionEvidenceBeforeNetwork(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	calls := 0
	env.ExternalFetch = countingRefusingExternalFetcher{calls: &calls}
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID:     bootstrapSourceAuthority,
		SourceStableReference: "https://example.com/docs/invoice",
		LicenseEvidence:       "caller says retrieval is permitted",
	}
	_, err := fetchExternalSourceReceipt(context.Background(), env, "org-permission", "api_symbol", coord, tlsTestExternalPolicy("https://example.com"))
	if err == nil || !strings.Contains(err.Error(), "HTTPS evidence URL or spdx") {
		t.Fatalf("fetch error=%v, want malformed permission-evidence refusal", err)
	}
	if calls != 0 {
		t.Fatalf("malformed permission evidence triggered %d network fetches", calls)
	}
}

func TestExternalFetchRejectsCallerSelectedPermissionCoordinateBeforeNetwork(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	calls := 0
	env.ExternalFetch = countingRefusingExternalFetcher{calls: &calls}
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID:     bootstrapSourceAuthority,
		SourceStableReference: "https://example.com/docs/invoice",
		LicenseEvidence:       "https://example.com/caller-selected-policy",
	}
	_, err := fetchExternalSourceReceipt(context.Background(), env, "org-permission", "api_symbol", coord, tlsTestExternalPolicy("https://example.com"))
	if err == nil || !strings.Contains(err.Error(), "not an exact retrieval-permission evidence coordinate admitted") {
		t.Fatalf("fetch error=%v, want descriptor-owned evidence refusal", err)
	}
	if calls != 0 {
		t.Fatalf("caller-selected permission coordinate triggered %d network fetches", calls)
	}
}

func TestSameRepositoryPermissionEvidenceMustExistBeforeSourceFetch(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	policy, coord := sameRepositoryTestExternalPolicy()
	var calls []string
	env.ExternalFetch = externalReferenceFetcherFunc(func(ctx context.Context, reference string, policy ExternalSourceDescriptor, authority string) (verifiedExternalSourceReceipt, error) {
		calls = append(calls, reference)
		if reference == coord.LicenseEvidence {
			return verifiedExternalSourceReceipt{}, fmt.Errorf("HTTP status 404 is not successful")
		}
		return deterministicExternalFetcher{}.Fetch(ctx, reference, policy, authority)
	})
	_, err := fetchExternalSourceReceipt(context.Background(), env, "org-repository", "api_symbol", coord, policy)
	if !errors.Is(err, ErrOODGraphExternalRetrievalPermissionProofUnavailable) {
		t.Fatalf("fetch error=%v, want unadjudicated-license refusal", err)
	}
	if len(calls) != 0 {
		t.Fatalf("unadjudicated license evidence triggered network calls: %v", calls)
	}
}

func TestExternalSymbolLocatorMustResolveInAttestedBytes(t *testing.T) {
	policy := ExternalSourceDescriptor{ID: "official_docs", ReferenceKind: "https_url_prefix", ReferencePrefix: "https://example.com/docs", VersionStableNamePrefix: "official_docs_", LocatorKinds: map[string]string{"api_symbol": "html_id_or_name"}}
	coord := ArtifactSourceCoordinate{SourceStableReference: "https://example.com/docs/invoice#symbol=nonexistent_symbol"}
	name, nameErr := canonicalExternalLocatorName("api_symbol", coord, policy, "nonexistent_symbol")
	if nameErr != nil {
		t.Fatal(nameErr)
	}
	err := verifyExternalObjectLocator("api_symbol", name, coord, policy, verifiedExternalSourceReceipt{Body: []byte(`<div id="other_symbol"></div>`)})
	if err == nil || !strings.Contains(err.Error(), "does not resolve in the exact fetched bytes") {
		t.Fatalf("locator error=%v, want exact-byte refusal", err)
	}
}

func TestTrustedDigestMismatchFailsBeforeEmbeddingOrMaterializationRun(t *testing.T) {
	policy := tlsTestExternalPolicy("https://example.com")
	coord := ArtifactSourceCoordinate{SourceAuthorityID: bootstrapSourceAuthority, SourceStableReference: "https://example.com/page", SourceContentHash: strings.Repeat("0", 64)}
	receipt, err := deterministicExternalFetcher{bodies: map[string][]byte{coord.SourceStableReference: []byte("changed official bytes")}}.Fetch(context.Background(), coord.SourceStableReference, policy, coord.SourceAuthorityID)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = bindVerifiedExternalSourceReceipt(coord, policy, receipt)
	if err == nil || !strings.Contains(err.Error(), "canonical fetched evidence hashes") {
		t.Fatalf("receipt bind error=%v, want trusted digest mismatch", err)
	}
}

func TestTrustedReceiptCannotAttestDifferentURL(t *testing.T) {
	policy := tlsTestExternalPolicy("https://example.com")
	coord := ArtifactSourceCoordinate{SourceAuthorityID: bootstrapSourceAuthority, SourceStableReference: "https://example.com/requested"}
	body := trustedExternalTestBody(coord.SourceStableReference)
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	receipt := verifiedExternalSourceReceipt{
		CanonicalReference: "https://example.com/different-resource",
		RetrievedAt:        time.Now().UTC(), ByteLength: int64(len(body)), SHA256: digest,
		ContentCoding: "identity", DecodedByteLength: int64(len(body)), DecodedSHA256: digest,
		SourceRegistryID: policy.ID, SourceAuthorityID: coord.SourceAuthorityID,
		Body: body, LocatorBody: append([]byte(nil), body...),
	}
	_, _, err := bindVerifiedExternalSourceReceipt(coord, policy, receipt)
	if err == nil || !strings.Contains(err.Error(), "does not match requested resource") {
		t.Fatalf("receipt bind error=%v, want URL/receipt mismatch", err)
	}
}

func TestTrustedGzipReceiptCannotSplitRawIdentityFromLocatorProof(t *testing.T) {
	policy := tlsTestExternalPolicy("https://example.com")
	coord := ArtifactSourceCoordinate{SourceAuthorityID: bootstrapSourceAuthority, SourceStableReference: "https://example.com/page"}
	rawDecoded := []byte(`<div id="raw-symbol"></div>`)
	divergentLocator := []byte(`<div id="different-symbol"></div>`)
	wire := gzipExternalTestBytes(t, rawDecoded)
	rawSum := sha256.Sum256(wire)
	decodedSum := sha256.Sum256(divergentLocator)
	receipt := verifiedExternalSourceReceipt{
		CanonicalReference: coord.SourceStableReference,
		RetrievedAt:        time.Now().UTC(), ByteLength: int64(len(wire)), SHA256: hex.EncodeToString(rawSum[:]),
		ContentCoding: "gzip", DecodedByteLength: int64(len(divergentLocator)), DecodedSHA256: hex.EncodeToString(decodedSum[:]),
		SourceRegistryID: policy.ID, SourceAuthorityID: coord.SourceAuthorityID,
		Body: wire, LocatorBody: divergentLocator,
	}
	if err := validateVerifiedExternalReceiptIntegrity(receipt, coord.SourceStableReference, policy.ID, coord.SourceAuthorityID, "sha256", true); err == nil || !strings.Contains(err.Error(), "decoded locator view diverge") {
		t.Fatalf("integrity error=%v, want raw/decoded divergence refusal", err)
	}
	if _, _, err := bindVerifiedExternalSourceReceipt(coord, policy, receipt); err == nil || !strings.Contains(err.Error(), "decoded locator view diverge") {
		t.Fatalf("bind error=%v, want raw/decoded divergence refusal", err)
	}
}

func TestExternalPolicyFingerprintNormalizesSetValuedFields(t *testing.T) {
	policy := tlsTestExternalPolicy("https://example.com")
	policy.AllowedObjectClasses = []string{"reference_page", "api_symbol"}
	policy.RetrievalPermissionEvidenceCoordinates = []string{"https://example.com/policy/b", "https://example.com/policy/a"}
	first, err := externalPolicyFingerprint(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.AllowedObjectClasses[0], policy.AllowedObjectClasses[1] = policy.AllowedObjectClasses[1], policy.AllowedObjectClasses[0]
	policy.RetrievalPermissionEvidenceCoordinates[0], policy.RetrievalPermissionEvidenceCoordinates[1] = policy.RetrievalPermissionEvidenceCoordinates[1], policy.RetrievalPermissionEvidenceCoordinates[0]
	second, err := externalPolicyFingerprint(policy)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("semantically identical set reorder changed policy fingerprint: %s != %s", first, second)
	}
	policy.ReferencePrefix = "https://example.com/other"
	third, err := externalPolicyFingerprint(policy)
	if err != nil {
		t.Fatal(err)
	}
	if third == first {
		t.Fatal("material policy change did not change fingerprint")
	}
}

func TestExternalReferenceRequiresTrustedFetcher(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	env.ExternalFetch = nil
	policy := tlsTestExternalPolicy("https://example.com")
	coord := ArtifactSourceCoordinate{SourceAuthorityID: bootstrapSourceAuthority, SourceStableReference: "https://example.com/page"}
	_, err := verifyExternalSourceCoordinate(context.Background(), env, "api_symbol", coord, policy)
	if err == nil || !strings.Contains(err.Error(), "trusted external reference fetcher required") {
		t.Fatalf("verification error=%v", err)
	}
}

func TestFetchedExternalBytesRemainTransient(t *testing.T) {
	const marker = "SECRET_UPSTREAM_BODY_MUST_NOT_ENTER_GRAPH"
	durable := testExternalVerificationReceipt(time.Now().UTC())
	raw, err := json.Marshal(durable)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), marker) {
		t.Fatalf("exact fetched bytes leaked into body-free durable receipt: %s", raw)
	}
}

func TestVerifyExternalSourceCoordinateCanonicalizesReceiptTime(t *testing.T) {
	policy := tlsTestExternalPolicy("https://example.com")
	coord := ArtifactSourceCoordinate{SourceAuthorityID: bootstrapSourceAuthority, SourceStableReference: "https://example.com/page"}
	loc := time.FixedZone("UTC-equivalent", 0)
	receipt, err := deterministicExternalFetcher{retrievedAt: time.Date(2026, 8, 21, 12, 0, 0, 0, loc)}.Fetch(context.Background(), coord.SourceStableReference, policy, coord.SourceAuthorityID)
	if err != nil {
		t.Fatal(err)
	}
	verified, _, err := bindVerifiedExternalSourceReceipt(coord, policy, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if verified.RetrievedAt != "2026-08-21T12:00:00Z" {
		t.Fatalf("retrieved_at=%q, want canonical UTC", verified.RetrievedAt)
	}
}

var _ embeddingClient = (*countingEmbeddingClient)(nil)
