package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// maxExternalReferenceBytes bounds the trusted bootstrap fetch. External
// publisher bytes are transient parser input, never graph payload; a bounded
// read prevents an official-but-broken endpoint from exhausting the MCP
// process before the graph can fail closed.
const maxExternalReferenceBytes int64 = 16 << 20

// One materialization request may reuse an exact resource for many verified
// fragments/symbols, but it may not retain an unbounded external corpus in
// process memory. Callers can split a larger corpus into deterministic runs.
const maxExternalVerificationSessionBytes int64 = 64 << 20

// verifiedExternalSourceReceipt is minted only by the process-owned fetcher.
// It keeps raw transfer evidence distinct from the canonical source-owned
// representation: transport-decoded bytes are hashed before charset, HTML,
// JSON, or Unicode normalization and become the archive/graph identity.
type verifiedExternalSourceReceipt struct {
	CanonicalReference              string
	RetrievedAt                     time.Time
	ByteLength                      int64
	SHA256                          string
	ContentCoding                   string
	DecodedByteLength               int64
	DecodedSHA256                   string
	TransportStatus                 string
	TransportRawHashAlgorithm       string
	TransportCharset                string
	TransportResponseMetadataDigest string
	SourceRepresentationMediaType   string
	UpstreamVersionEvidenceKind     string
	UpstreamVersionEvidence         string
	UpstreamVersionToken            string
	SourceRegistryID                string
	SourceAuthorityID               string
	Authorization                   externalSourceAuthorization
	Archive                         *externalEvidenceArchiveReceipt
	Body                            []byte
	LocatorBody                     []byte
}

type externalReferenceFetcher interface {
	Fetch(context.Context, string, ExternalSourceDescriptor, string) (verifiedExternalSourceReceipt, error)
}

type externalVerificationSessionContextKey struct{}

type externalReceiptCacheKey struct {
	OrganizationID    string
	SourceAuthority   string
	PolicyFingerprint string
	ResourceReference string
}

type externalReceiptCacheEntry struct {
	ready   chan struct{}
	receipt verifiedExternalSourceReceipt
	err     error
}

type externalArchiveCacheKey struct {
	OrganizationID                    string
	SourceAuthorityID                 string
	ResourceReference                 string
	SourceContentHash                 string
	BodyStorageAuthorizationReference string
	BodyRetentionHoldReference        string
	DeletionDomainID                  string
	CryptoShredDomainID               string
}

type externalArchiveCacheEntry struct {
	ready   chan struct{}
	receipt externalEvidenceArchiveReceipt
	err     error
}

// externalVerificationSession is request-scoped. It is never attached to
// Env or the process-global fetcher: a later MCP request must re-fetch and
// re-attest freshness. One pending entry supplies per-resource singleflight
// semantics without serializing independent resources behind a network call.
type externalVerificationSession struct {
	mu             sync.Mutex
	entries        map[externalReceiptCacheKey]*externalReceiptCacheEntry
	archiveEntries map[externalArchiveCacheKey]*externalArchiveCacheEntry
	totalBytes     int64
}

func withExternalVerificationSession(ctx context.Context, organizationID string) context.Context {
	if existing, ok := ctx.Value(externalVerificationSessionContextKey{}).(*externalVerificationSession); ok && existing != nil {
		return ctx
	}
	return context.WithValue(ctx, externalVerificationSessionContextKey{}, &externalVerificationSession{
		entries:        make(map[externalReceiptCacheKey]*externalReceiptCacheEntry),
		archiveEntries: make(map[externalArchiveCacheKey]*externalArchiveCacheEntry),
	})
}

type httpExternalReferenceFetcher struct {
	client   *http.Client
	maxBytes int64
	now      func() time.Time
}

func newHTTPExternalReferenceFetcher(client *http.Client, maxBytes int64, now func() time.Time) *httpExternalReferenceFetcher {
	if client == nil {
		client = &http.Client{}
	}
	copyClient := *client
	// A redirect changes the resource whose bytes are being attested. The durable
	// receipt has no requested/effective URL or redirect-chain fields, so it
	// must refuse rather than silently attest a different resource.
	copyClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if copyClient.Timeout == 0 {
		copyClient.Timeout = 30 * time.Second
	}
	if maxBytes <= 0 {
		maxBytes = maxExternalReferenceBytes
	}
	if now == nil {
		now = time.Now
	}
	return &httpExternalReferenceFetcher{client: &copyClient, maxBytes: maxBytes, now: now}
}

func (f *httpExternalReferenceFetcher) Fetch(ctx context.Context, canonicalReference string, policy ExternalSourceDescriptor, authorityID string) (verifiedExternalSourceReceipt, error) {
	if f == nil || f.client == nil || f.now == nil || f.maxBytes <= 0 {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("external reference fetcher is not configured")
	}
	if policy.ReferenceKind != "https_url_prefix" {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("external source %q uses %q and requires a trusted non-HTTP fetch adapter", policy.ID, policy.ReferenceKind)
	}
	u, err := parseCanonicalHTTPSReference(canonicalReference)
	if err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch canonical external reference: %w", err)
	}
	if u.String() != canonicalReference {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch reference is not byte-canonical")
	}
	if err := validateUpstreamPinnedReference(policy, canonicalReference); err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch upstream-pinned reference: %w", err)
	}
	fetchURL := *u
	fetchURL.Fragment = "" // fragments identify graph coordinates, not HTTP resources
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL.String(), nil)
	if err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("build external reference request: %w", err)
	}
	// Explicit identity disables Go's transparent gzip negotiation and keeps
	// the hashed bytes equal to the response representation being attested.
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "velenza-spec-graph/1")
	resp, err := f.client.Do(req)
	if err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: %w", canonicalReference, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: HTTP status %d is not successful", canonicalReference, resp.StatusCode)
	}
	if resp.Uncompressed {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: HTTP transport transparently decoded the response, so raw wire identity is unavailable", canonicalReference)
	}
	contentCoding, err := canonicalExternalContentCoding(resp.Header.Values("Content-Encoding"))
	if err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: %w", canonicalReference, err)
	}
	if resp.ContentLength > f.maxBytes {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: content length %d exceeds %d-byte limit", canonicalReference, resp.ContentLength, f.maxBytes)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("read external reference %q: %w", canonicalReference, err)
	}
	if int64(len(body)) > f.maxBytes {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: response exceeds %d-byte limit", canonicalReference, f.maxBytes)
	}
	locatorBody, err := decodeExternalLocatorBody(contentCoding, body, f.maxBytes)
	if err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: %w", canonicalReference, err)
	}
	sum := sha256.Sum256(body)
	rawDigest := hex.EncodeToString(sum[:])
	decodedSum := sha256.Sum256(locatorBody)
	decodedDigest := hex.EncodeToString(decodedSum[:])
	mediaType, charset, err := canonicalExternalResponseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: %w", canonicalReference, err)
	}
	responseMetadataDigest, err := externalTransportResponseMetadataDigest(externalTransportResponseMetadata{
		StatusCode: resp.StatusCode, ContentEncoding: contentCoding, MediaType: mediaType, Charset: charset,
		ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified"), UpstreamVersionID: resp.Header.Get("X-Amz-Version-Id"),
	})
	if err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q response metadata: %w", canonicalReference, err)
	}
	evidenceKind, evidence, upstreamVersionToken := "", "", ""
	if policy.VersionCoordinateMode == externalVersionModeUpstreamPinned {
		switch policy.UpstreamIdentityPolicy {
		case upstreamIdentityHTTPResponseWithContentDigest:
			evidenceKind, evidence, upstreamVersionToken, err = deriveHTTPUpstreamVersionEvidence(resp.Header, decodedDigest)
		case upstreamIdentityImmutableRefWithContentDigest:
			evidenceKind = "immutable_reference_coordinate"
			evidence = fetchURL.String()
			upstreamVersionToken, err = trustedUpstreamVersionToken(evidenceKind, evidence, decodedDigest)
		default:
			err = fmt.Errorf("external source %q has no executable upstream identity policy", policy.ID)
		}
		if err != nil {
			return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: %w", canonicalReference, err)
		}
		if upstreamVersionToken == "" {
			return verifiedExternalSourceReceipt{}, fmt.Errorf("fetch external reference %q: upstream_pinned source %q returned no trusted version evidence", canonicalReference, policy.ID)
		}
	}
	return verifiedExternalSourceReceipt{
		CanonicalReference:              fetchURL.String(),
		RetrievedAt:                     f.now().UTC(),
		ByteLength:                      int64(len(body)),
		SHA256:                          rawDigest,
		ContentCoding:                   contentCoding,
		DecodedByteLength:               int64(len(locatorBody)),
		DecodedSHA256:                   decodedDigest,
		TransportStatus:                 "success",
		TransportRawHashAlgorithm:       "sha256",
		TransportCharset:                charset,
		TransportResponseMetadataDigest: responseMetadataDigest,
		SourceRepresentationMediaType:   mediaType,
		UpstreamVersionEvidenceKind:     evidenceKind,
		UpstreamVersionEvidence:         evidence,
		UpstreamVersionToken:            upstreamVersionToken,
		SourceRegistryID:                policy.ID,
		SourceAuthorityID:               authorityID,
		Body:                            body,
		LocatorBody:                     locatorBody,
	}, nil
}

type externalTransportResponseMetadata struct {
	StatusCode        int    `json:"status_code"`
	ContentEncoding   string `json:"content_encoding"`
	MediaType         string `json:"media_type,omitempty"`
	Charset           string `json:"charset,omitempty"`
	ETag              string `json:"etag,omitempty"`
	LastModified      string `json:"last_modified,omitempty"`
	UpstreamVersionID string `json:"upstream_version_id,omitempty"`
}

func externalTransportResponseMetadataDigest(metadata externalTransportResponseMetadata) (string, error) {
	canonical, err := canonicalJSON(metadata)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func canonicalExternalResponseMediaType(value string) (string, string, error) {
	if value == "" {
		return "", "", nil
	}
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil {
		return "", "", fmt.Errorf("invalid Content-Type %q: %w", value, err)
	}
	mediaType = strings.ToLower(mediaType)
	charset := strings.ToLower(params["charset"])
	if len(mediaType) > 256 || len(charset) > 64 {
		return "", "", fmt.Errorf("Content-Type media type or charset exceeds the receipt boundary")
	}
	return mediaType, charset, nil
}

func canonicalExternalContentCoding(values []string) (string, error) {
	if len(values) == 0 {
		return "identity", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf("multiple content-encoding header fields are forbidden")
	}
	raw := strings.TrimSpace(values[0])
	if raw == "" {
		return "identity", nil
	}
	if strings.Contains(raw, ",") {
		return "", fmt.Errorf("content-encoding chain %q is unsupported", raw)
	}
	switch strings.ToLower(raw) {
	case "identity":
		return "identity", nil
	case "gzip":
		return "gzip", nil
	default:
		return "", fmt.Errorf("content-encoding %q is outside the closed identity|gzip set", raw)
	}
}

func decodeExternalLocatorBody(contentCoding string, body []byte, maxBytes int64) ([]byte, error) {
	switch contentCoding {
	case "identity":
		return append([]byte(nil), body...), nil
	case "gzip":
		source := bytes.NewReader(body)
		buffered := bufio.NewReader(source)
		reader, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, fmt.Errorf("decode gzip locator view: %w", err)
		}
		// One HTTP representation is one gzip member. Multistream(false), plus
		// the trailing-byte check below, refuses concatenated members and any
		// bytes that are not covered by the first member's checksum.
		reader.Multistream(false)
		decoded, readErr := io.ReadAll(io.LimitReader(reader, maxBytes+1))
		closeErr := reader.Close()
		if readErr != nil {
			return nil, fmt.Errorf("decode gzip locator view: %w", readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close gzip locator view: %w", closeErr)
		}
		if int64(len(decoded)) > maxBytes {
			return nil, fmt.Errorf("decoded gzip locator view exceeds %d-byte limit", maxBytes)
		}
		if buffered.Buffered() != 0 || source.Len() != 0 {
			return nil, fmt.Errorf("gzip locator view contains concatenated members or trailing bytes")
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("content-coding %q has no trusted locator decoder", contentCoding)
	}
}

func deriveHTTPUpstreamVersionEvidence(header http.Header, contentDigest string) (string, string, string, error) {
	if values := header.Values("X-Amz-Version-Id"); len(values) != 0 {
		value, err := canonicalSingleHTTPVersionEvidence("x-amz-version-id", values)
		if err != nil {
			return "", "", "", err
		}
		token, err := trustedUpstreamVersionToken("http_x_amz_version_id", value, contentDigest)
		return "http_x_amz_version_id", value, token, err
	}
	values := header.Values("ETag")
	if len(values) == 0 {
		return "", "", "", nil
	}
	value, err := canonicalSingleHTTPVersionEvidence("etag", values)
	if err != nil {
		return "", "", "", err
	}
	if !canonicalHTTPETag(value) {
		return "", "", "", fmt.Errorf("etag %q is not a canonical HTTP entity-tag", value)
	}
	kind := "http_etag"
	if strings.HasPrefix(value, "W/") {
		kind = "http_weak_etag"
	}
	token, err := trustedUpstreamVersionToken(kind, value, contentDigest)
	return kind, value, token, err
}

func canonicalSingleHTTPVersionEvidence(name string, values []string) (string, error) {
	if len(values) != 1 {
		return "", fmt.Errorf("multiple %s header fields cannot establish one upstream version", name)
	}
	value := strings.TrimSpace(values[0])
	if value == "" || len(value) > 4096 || !utf8.ValidString(value) {
		return "", fmt.Errorf("%s header cannot establish a canonical upstream version", name)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("%s header contains control characters", name)
		}
	}
	return value, nil
}

func canonicalHTTPETag(value string) bool {
	if strings.HasPrefix(value, "W/") {
		value = strings.TrimPrefix(value, "W/")
	}
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	for _, r := range value[1 : len(value)-1] {
		if r == '"' || r < 0x21 || r == 0x7f {
			return false
		}
	}
	return true
}

func trustedUpstreamVersionToken(kind, evidence, contentDigest string) (string, error) {
	if kind == "" || len(kind) > 64 || !snakeCaseKeyPattern.MatchString(kind) {
		return "", fmt.Errorf("trusted upstream version evidence kind is not canonical lowercase snake_case")
	}
	if evidence == "" || len(evidence) > 4096 || !utf8.ValidString(evidence) || strings.TrimSpace(evidence) != evidence {
		return "", fmt.Errorf("trusted upstream version evidence is not canonical UTF-8 within 4096 bytes")
	}
	for _, r := range evidence {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("trusted upstream version evidence contains control characters")
		}
	}
	if err := validateExternalContentHash("sha256", contentDigest); err != nil {
		return "", fmt.Errorf("trusted upstream content digest: %w", err)
	}
	// Upstream metadata identifies the publisher coordinate while the exact
	// raw digest closes representation ambiguity (including weak ETags and
	// mutable server metadata). Neither caller assertions nor metadata alone
	// can mint a graph version token.
	framed := fmt.Sprintf("%d:%s|%d:%s|%d:%s", len(kind), kind, len(evidence), evidence, len(contentDigest), contentDigest)
	sum := sha256.Sum256([]byte(framed))
	return kind + "_sha256_" + hex.EncodeToString(sum[:]), nil
}

func externalResourceReference(reference string, policy ExternalSourceDescriptor) (string, error) {
	if policy.ReferenceKind != "https_url_prefix" {
		return reference, nil
	}
	u, err := parseCanonicalHTTPSReference(reference)
	if err != nil {
		return "", err
	}
	u.Fragment = ""
	return u.String(), nil
}

func externalPolicyFingerprint(policy ExternalSourceDescriptor) (string, error) {
	// These descriptor fields are semantically closed sets: admission uses
	// membership, not caller/config order. Normalize them before hashing so a
	// harmless reorder cannot invalidate durable receipts and block a later
	// complete snapshot.
	normalized := policy
	normalized.AllowedObjectClasses = append([]string(nil), policy.AllowedObjectClasses...)
	sort.Strings(normalized.AllowedObjectClasses)
	normalized.RetrievalPermissionEvidenceCoordinates = append([]string(nil), policy.RetrievalPermissionEvidenceCoordinates...)
	sort.Strings(normalized.RetrievalPermissionEvidenceCoordinates)
	canonical, err := canonicalJSON(normalized)
	if err != nil {
		return "", fmt.Errorf("canonical external source policy: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

func cloneVerifiedExternalSourceReceipt(receipt verifiedExternalSourceReceipt) verifiedExternalSourceReceipt {
	receipt.Body = append([]byte(nil), receipt.Body...)
	receipt.LocatorBody = append([]byte(nil), receipt.LocatorBody...)
	if receipt.Archive != nil {
		archive := *receipt.Archive
		receipt.Archive = &archive
	}
	return receipt
}

func waitForExternalReceipt(ctx context.Context, entry *externalReceiptCacheEntry) (verifiedExternalSourceReceipt, error) {
	select {
	case <-entry.ready:
		return cloneVerifiedExternalSourceReceipt(entry.receipt), entry.err
	case <-ctx.Done():
		return verifiedExternalSourceReceipt{}, ctx.Err()
	}
}

func fetchExternalSourceReceipt(ctx context.Context, env *Env, orgID, objectClass string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor) (verifiedExternalSourceReceipt, error) {
	// This is the sole runtime path into the configured fetch adapter. Repeat
	// both pre-network gates here so future internal callers cannot bypass the
	// admission orchestrator's earlier validation.
	if err := validateExternalRetrievalPermissionEvidence(policy, coord); err != nil {
		return verifiedExternalSourceReceipt{}, err
	}
	if err := validateUpstreamPinnedReference(policy, coord.SourceStableReference); err != nil {
		return verifiedExternalSourceReceipt{}, err
	}
	if env == nil || env.ExternalFetch == nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("trusted external reference fetcher required")
	}
	observedAt := time.Now().UTC()
	if env.Now != nil {
		observedAt = env.Now().UTC()
	}
	authorization, err := resolveExternalSourceAuthorization(ctx, env, externalSourceAuthorizationRequest{
		OrganizationID: orgID, ObjectClass: objectClass, SourceRegistryID: policy.ID,
		SourceArtifactClass: policy.SourceArtifactClass, SourceAuthorityID: coord.SourceAuthorityID,
		SourceRefKind: coord.SourceRefKind, SourceStableReference: coord.SourceStableReference,
		PermissionOperation: externalFetchPermissionOperation, PermissionMethod: http.MethodGet, ObservedAt: observedAt,
	})
	if err != nil {
		return verifiedExternalSourceReceipt{}, err
	}

	receipt, err := fetchExternalReceiptResource(ctx, env, orgID, coord.SourceStableReference, policy, coord.SourceAuthorityID)
	if err != nil {
		return verifiedExternalSourceReceipt{}, err
	}
	requestAtFetch := externalSourceAuthorizationRequest{
		OrganizationID: orgID, ObjectClass: authorization.ObjectClass, SourceRegistryID: policy.ID,
		SourceArtifactClass: policy.SourceArtifactClass, SourceAuthorityID: coord.SourceAuthorityID,
		SourceRefKind: coord.SourceRefKind, SourceStableReference: coord.SourceStableReference,
		PermissionOperation: externalFetchPermissionOperation, PermissionMethod: http.MethodGet, ObservedAt: receipt.RetrievedAt.UTC(),
	}
	if err := validateExternalSourceAuthorization(requestAtFetch, authorization); err != nil {
		return verifiedExternalSourceReceipt{}, fmt.Errorf("external authorization no longer covers the completed fetch: %w", err)
	}
	receipt.Authorization = authorization
	return receipt, nil
}

func fetchExternalReceiptResource(ctx context.Context, env *Env, orgID, reference string, policy ExternalSourceDescriptor, authorityID string) (verifiedExternalSourceReceipt, error) {
	resource, err := externalResourceReference(reference, policy)
	if err != nil {
		return verifiedExternalSourceReceipt{}, err
	}
	fingerprint, err := externalPolicyFingerprint(policy)
	if err != nil {
		return verifiedExternalSourceReceipt{}, err
	}
	session, _ := ctx.Value(externalVerificationSessionContextKey{}).(*externalVerificationSession)
	if session == nil {
		return env.ExternalFetch.Fetch(ctx, reference, policy, authorityID)
	}
	key := externalReceiptCacheKey{
		OrganizationID: orgID, SourceAuthority: authorityID,
		PolicyFingerprint: fingerprint, ResourceReference: resource,
	}
	session.mu.Lock()
	if cached, ok := session.entries[key]; ok {
		session.mu.Unlock()
		return waitForExternalReceipt(ctx, cached)
	}
	pending := &externalReceiptCacheEntry{ready: make(chan struct{})}
	session.entries[key] = pending
	session.mu.Unlock()

	receipt, fetchErr := env.ExternalFetch.Fetch(ctx, reference, policy, authorityID)
	if fetchErr == nil {
		// The session cache retains both exact encoded representation bytes and
		// the independently verified locator view. Count both buffers even for
		// identity coding, where their contents are equal but their backing
		// storage is deliberately not aliased. Use the actual retained buffers,
		// not unverified receipt length claims, for memory accounting.
		receiptBytes := int64(len(receipt.Body)) + int64(len(receipt.LocatorBody))
		session.mu.Lock()
		if receiptBytes > maxExternalVerificationSessionBytes ||
			session.totalBytes < 0 ||
			session.totalBytes > maxExternalVerificationSessionBytes-receiptBytes {
			fetchErr = fmt.Errorf("external verification request exceeds %d-byte aggregate receipt limit", maxExternalVerificationSessionBytes)
		} else {
			session.totalBytes += receiptBytes
		}
		session.mu.Unlock()
	}

	// A failed fetch or capacity reservation publishes only a fixed-size error
	// entry. In particular, over-limit response buffers must not accumulate in
	// the request cache while later distinct coordinates continue to fail.
	published := verifiedExternalSourceReceipt{}
	if fetchErr == nil {
		published = cloneVerifiedExternalSourceReceipt(receipt)
	}
	session.mu.Lock()
	pending.receipt = published
	pending.err = fetchErr
	close(pending.ready)
	session.mu.Unlock()
	if fetchErr != nil {
		return verifiedExternalSourceReceipt{}, fetchErr
	}
	return cloneVerifiedExternalSourceReceipt(published), nil
}

func validateVerifiedExternalReceiptIntegrity(receipt verifiedExternalSourceReceipt, resourceReference, registryID, authorityID, hashAlgorithm string, requireNonempty bool) error {
	if receipt.CanonicalReference != resourceReference {
		return fmt.Errorf("external fetch receipt resource %q does not match requested resource %q", receipt.CanonicalReference, resourceReference)
	}
	if receipt.SourceRegistryID != registryID || receipt.SourceAuthorityID != authorityID {
		return fmt.Errorf("external fetch receipt authority or registry binding mismatch")
	}
	if receipt.RetrievedAt.IsZero() {
		return fmt.Errorf("external fetch receipt retrieved_at must be non-zero")
	}
	if receipt.ByteLength != int64(len(receipt.Body)) || receipt.ByteLength < 0 || (requireNonempty && receipt.ByteLength == 0) {
		return fmt.Errorf("external fetch receipt byte length mismatch or forbidden empty evidence")
	}
	sum := sha256.Sum256(receipt.Body)
	actualDigest := hex.EncodeToString(sum[:])
	if err := validateExternalContentHash(hashAlgorithm, receipt.SHA256); err != nil || receipt.SHA256 != actualDigest {
		return fmt.Errorf("external fetch receipt digest does not match fetched bytes")
	}
	if err := validateVerifiedExternalReceiptLocatorView(receipt); err != nil {
		return err
	}
	return nil
}

// validateVerifiedExternalReceiptLocatorView proves that the locator parser's
// decoded view is exactly the closed decoding of the raw representation bytes
// used for object identity. Checking the two digests independently is not
// sufficient: an alternate fetch adapter could otherwise supply self-
// consistent but unrelated raw and decoded bodies.
func validateVerifiedExternalReceiptLocatorView(receipt verifiedExternalSourceReceipt) error {
	if receipt.ContentCoding != "identity" && receipt.ContentCoding != "gzip" {
		return fmt.Errorf("external fetch receipt content coding is outside the closed identity|gzip set")
	}
	if receipt.ByteLength > maxExternalReferenceBytes || receipt.DecodedByteLength > maxExternalReferenceBytes {
		return fmt.Errorf("external fetch receipt raw or decoded body exceeds %d-byte verification limit", maxExternalReferenceBytes)
	}
	if receipt.DecodedByteLength != int64(len(receipt.LocatorBody)) || receipt.DecodedByteLength < 0 {
		return fmt.Errorf("external fetch receipt decoded byte length mismatch")
	}
	decodedSum := sha256.Sum256(receipt.LocatorBody)
	if err := validateExternalContentHash("sha256", receipt.DecodedSHA256); err != nil || receipt.DecodedSHA256 != hex.EncodeToString(decodedSum[:]) {
		return fmt.Errorf("external fetch receipt decoded locator digest does not match decoded bytes")
	}
	expected, err := decodeExternalLocatorBody(receipt.ContentCoding, receipt.Body, maxExternalReferenceBytes)
	if err != nil {
		return fmt.Errorf("external fetch receipt raw representation cannot produce its locator view: %w", err)
	}
	if !bytes.Equal(expected, receipt.LocatorBody) {
		return fmt.Errorf("external fetch receipt raw representation and decoded locator view diverge")
	}
	return nil
}

// verifyExternalSourceCoordinate replaces caller assertions with a receipt
// from the trusted process dependency. Caller-provided digest evidence is an
// optional expectation only: it must match the bytes fetched from the exact
// registered URL, but it can never mint the stored receipt itself.
func verifyExternalSourceCoordinate(ctx context.Context, env *Env, objectClass string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor) (ArtifactSourceCoordinate, error) {
	verified, _, err := verifyExternalSourceCoordinateWithReceipt(ctx, env, "", objectClass, coord, policy)
	return verified, err
}

func verifyExternalSourceCoordinateWithReceipt(ctx context.Context, env *Env, orgID, objectClass string, coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor) (ArtifactSourceCoordinate, verifiedExternalSourceReceipt, error) {
	if env == nil || env.ExternalFetch == nil {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("trusted external reference fetcher required; production requires the admitted docgraph fetch circuit/driver adapter")
	}
	receipt, err := fetchExternalSourceReceipt(ctx, env, orgID, objectClass, coord, policy)
	if err != nil {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, err
	}
	verified, receipt, err := bindVerifiedExternalSourceReceipt(coord, policy, receipt)
	if err != nil {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, err
	}
	if receipt.Authorization.BodyCustodyDisposition == externalBodyCustodyAGFS {
		if env.ExternalArchive == nil {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external evidence has exact AGFS custody authorization but no trusted archive adapter is configured")
		}
		archiveRequest := externalEvidenceArchiveRequest{
			OrganizationID:                    orgID,
			SourceBytes:                       receipt.LocatorBody,
			SourceContentHashAlgorithm:        policy.ContentHashAlgorithm,
			SourceContentHashProfile:          receipt.Authorization.SourceContentHashProfile,
			SourceContentHash:                 receipt.DecodedSHA256,
			BodyStorageAuthorizationReference: receipt.Authorization.BodyStorageAuthorizationReference,
			BodyRetentionHoldReference:        receipt.Authorization.BodyRetentionHoldReference,
			DeletionDomainID:                  receipt.Authorization.ArchiveDeletionDomainID,
			CryptoShredDomainID:               receipt.Authorization.ArchiveCryptoShredDomainID,
		}
		if err := validateExternalEvidenceArchiveRequest(archiveRequest, maxExternalReferenceBytes); err != nil {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("validate protected external evidence archive request before I/O: %w", err)
		}
		resourceReference, resourceErr := externalResourceReference(coord.SourceStableReference, policy)
		if resourceErr != nil {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, resourceErr
		}
		archive, err := archiveExternalEvidenceOnce(ctx, env, externalArchiveCacheKey{
			OrganizationID: orgID, SourceAuthorityID: coord.SourceAuthorityID, ResourceReference: resourceReference,
			SourceContentHash:                 receipt.DecodedSHA256,
			BodyStorageAuthorizationReference: receipt.Authorization.BodyStorageAuthorizationReference,
			BodyRetentionHoldReference:        receipt.Authorization.BodyRetentionHoldReference,
			DeletionDomainID:                  receipt.Authorization.ArchiveDeletionDomainID,
			CryptoShredDomainID:               receipt.Authorization.ArchiveCryptoShredDomainID,
		}, archiveRequest)
		if err != nil {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("archive exact external evidence before parsing: %w", err)
		}
		if err := validateExternalEvidenceArchiveReceiptForRequest(archiveRequest, archive); err != nil {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("validate protected external evidence archive receipt: %w", err)
		}
		receipt.Archive = &archive
	}
	return verified, receipt, nil
}

func archiveExternalEvidenceOnce(ctx context.Context, env *Env, key externalArchiveCacheKey, request externalEvidenceArchiveRequest) (externalEvidenceArchiveReceipt, error) {
	session, _ := ctx.Value(externalVerificationSessionContextKey{}).(*externalVerificationSession)
	if session == nil {
		return archiveExternalEvidence(ctx, env.ExternalArchive, request)
	}
	session.mu.Lock()
	if cached, ok := session.archiveEntries[key]; ok {
		session.mu.Unlock()
		select {
		case <-cached.ready:
			return cached.receipt, cached.err
		case <-ctx.Done():
			return externalEvidenceArchiveReceipt{}, ctx.Err()
		}
	}
	pending := &externalArchiveCacheEntry{ready: make(chan struct{})}
	session.archiveEntries[key] = pending
	session.mu.Unlock()

	receipt, err := archiveExternalEvidence(ctx, env.ExternalArchive, request)
	session.mu.Lock()
	pending.receipt = receipt
	pending.err = err
	close(pending.ready)
	session.mu.Unlock()
	return receipt, err
}

// bindVerifiedExternalSourceReceipt verifies one already-fetched receipt and
// derives trusted coordinate outputs. Keeping this pure step separate lets
// receipt integrity remain exhaustively testable while the higher permission
// gate correctly disables all automated HTTPS retrieval pending an admitted
// structured permission decision.
func bindVerifiedExternalSourceReceipt(coord ArtifactSourceCoordinate, policy ExternalSourceDescriptor, receipt verifiedExternalSourceReceipt) (ArtifactSourceCoordinate, verifiedExternalSourceReceipt, error) {
	resourceReference, err := externalResourceReference(coord.SourceStableReference, policy)
	if err != nil {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, err
	}
	if receipt.CanonicalReference != resourceReference {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external fetch receipt resource %q does not match requested resource %q", receipt.CanonicalReference, resourceReference)
	}
	if receipt.SourceRegistryID != policy.ID || receipt.SourceAuthorityID != coord.SourceAuthorityID {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external fetch receipt authority or registry binding mismatch")
	}
	if receipt.RetrievedAt.IsZero() {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external fetch receipt retrieved_at must be non-zero")
	}
	receipt.RetrievedAt = receipt.RetrievedAt.UTC()
	if receipt.ByteLength != int64(len(receipt.Body)) || receipt.ByteLength < 0 {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external fetch receipt byte length mismatch")
	}
	sum := sha256.Sum256(receipt.Body)
	actualDigest := hex.EncodeToString(sum[:])
	if err := validateExternalContentHash(policy.ContentHashAlgorithm, receipt.SHA256); err != nil || receipt.SHA256 != actualDigest {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external fetch receipt digest does not match fetched bytes")
	}
	if err := validateVerifiedExternalReceiptLocatorView(receipt); err != nil {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, err
	}
	if receipt.Authorization.PermissionByteCeiling > 0 && (receipt.ByteLength > receipt.Authorization.PermissionByteCeiling || receipt.DecodedByteLength > receipt.Authorization.PermissionByteCeiling) {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external fetch receipt exceeds the admitted permission byte ceiling")
	}
	if receipt.Authorization.PermissionGrantID != "" {
		if receipt.TransportStatus != "success" || receipt.TransportRawHashAlgorithm != "sha256" {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external fetch receipt lacks successful transport status or raw hash algorithm")
		}
		if err := validateExternalContentHash("sha256", receipt.TransportResponseMetadataDigest); err != nil {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external fetch receipt response metadata digest: %w", err)
		}
		if receipt.Authorization.SourceRepresentationMediaType != "" && receipt.SourceRepresentationMediaType != receipt.Authorization.SourceRepresentationMediaType {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("external fetch response media type %q does not match the admitted representation declaration %q", receipt.SourceRepresentationMediaType, receipt.Authorization.SourceRepresentationMediaType)
		}
	}
	if receipt.Authorization.PermissionExpectedHash != "" && receipt.Authorization.PermissionExpectedHash != receipt.DecodedSHA256 {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("admitted expected source_content_hash %q does not match canonical fetched evidence %q", receipt.Authorization.PermissionExpectedHash, receipt.DecodedSHA256)
	}
	if coord.SourceContentHash != "" && coord.SourceContentHash != receipt.DecodedSHA256 {
		return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("caller expected source_content_hash %q but canonical fetched evidence hashes to %q", coord.SourceContentHash, receipt.DecodedSHA256)
	}
	if coord.VersionCoordinate != "" {
		vc, err := ParseVersionCoordinate(coord.VersionCoordinate)
		if err != nil {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, err
		}
		if tokenDigest, ok := canonicalSHA256VersionTokenDigest(vc.SourceVersionToken); ok && tokenDigest != receipt.DecodedSHA256 {
			return ArtifactSourceCoordinate{}, verifiedExternalSourceReceipt{}, fmt.Errorf("source_coordinate.version_coordinate SHA-256 token does not match canonical fetched evidence")
		}
	}
	coord.SourceContentHash = receipt.DecodedSHA256
	coord.SourceContentHashOwner = coord.SourceAuthorityID
	coord.RetrievedAt = receipt.RetrievedAt.Format(time.RFC3339Nano)
	return coord, receipt, nil
}
