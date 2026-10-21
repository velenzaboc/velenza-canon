package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"cloud.google.com/go/spanner"
)

// bootstrapSourceAuthority is the OOD Graph Protocol authority used by the
// original seed-node import shape. Keeping this literal in one place makes
// the no-source_coordinate path exactly backward compatible.
const bootstrapSourceAuthority = "767c2399-87f9-4859-ac64-afb575bdb263"

var sourceRefKinds = map[string]struct{}{
	"id":         {},
	"name":       {},
	"coordinate": {},
	"path":       {},
}

// externalSourceArtifactClasses is the closed source-authority class set in
// OOD_GRAPH_PROTOCOL_v1 §8.external_reference_ingestion_contract.
//
// This is an admission constraint, not a source-selection default: operators
// still declare each trusted source in ExternalSources, but a config entry
// cannot broaden the protocol by inventing a seventh trust class. In
// particular, syntactically-valid values such as "unofficial_blog" used to
// pass config validation and could then make caller-supplied evidence look
// registry-backed.
var externalSourceArtifactClasses = map[string]struct{}{
	"official_vendor_documentation":  {},
	"official_product_documentation": {},
	"official_source_repository":     {},
	"official_release_notes":         {},
	"context7_documentation_package": {},
	"velenza_owned_documentation":    {}, // canonical protocol literal
}

var externalReferenceObjectClasses = map[string]struct{}{
	"external_reference_doc": {},
	"reference_page":         {},
	"api_symbol":             {},
	"code_example":           {},
	"release_note":           {},
	"source_repo":            {},
	"repo_snapshot":          {},
	"code_symbol_ref":        {},
}

const externalReferenceEmbeddingDimensions = 3072

const maxExternalFreshnessWindowSeconds = int64((1<<63)-1) / int64(time.Second)

const sourceCoordinatePolicyExternalReferenceRequired = "external_reference_required"

const (
	externalVersionModeContentDigest  = "content_digest"
	externalVersionModeUpstreamPinned = "upstream_pinned"

	licenseEvidenceBindingCoordinate              = "coordinate"
	licenseEvidenceBindingSameRepositoryFile      = "same_repository_license_file"
	licenseEvidenceBindingNotRequired             = "not_required"
	upstreamIdentityHTTPResponseWithContentDigest = "http_response_evidence_with_content_digest"
	upstreamIdentityImmutableRefWithContentDigest = "immutable_reference_with_content_digest"
)

// ExternalSourceDescriptor is the config-resident trust registry entry for
// one official external source. A caller-provided source_artifact_class is
// evidence to CHECK against this registry, never authority by itself.
//
// reference_kind is closed to https_url_prefix | opaque_prefix. The former
// compares parsed scheme/host plus a segment-bounded path prefix and therefore
// cannot be bypassed by a host such as docs.vendor.example.evil.invalid or a
// /docs-evil sibling. Query and fragment participation are explicit per-entry
// booleans; allowed values must still be byte-canonical. The opaque form
// exists for source authorities such as Context7 whose stable coordinate is
// not an HTTP URL.
type ExternalSourceDescriptor struct {
	ID                   string `json:"id"`
	SourceArtifactClass  string `json:"source_artifact_class"`
	ReferenceKind        string `json:"reference_kind"`
	ReferencePrefix      string `json:"reference_prefix"`
	ContentHashAlgorithm string `json:"content_hash_algorithm"`
	// VersionCoordinateMode is source-registry authority over how the final
	// graph identity is pinned. content_digest derives the source-named token
	// from the trusted process receipt before graph identity exists;
	// upstream_pinned derives its token from a closed process-trusted evidence
	// policy plus the exact fetched-byte digest. Callers omit
	// version_coordinate in both modes.
	VersionCoordinateMode   string   `json:"version_coordinate_mode"`
	VersionStableNamePrefix string   `json:"version_stable_name_prefix"`
	AllowedObjectClasses    []string `json:"allowed_object_classes"`
	// LocatorKinds closes how each allowed object class proves that its
	// coordinate resolves inside the exact fetched resource. External OOD
	// section_path remains "$"; upstream HTML anchors / JSON Pointers live in
	// source_stable_reference's URL fragment and are verified transiently.
	LocatorKinds            map[string]string `json:"locator_kinds"`
	FreshnessWindowSeconds  int64             `json:"freshness_window_seconds"`
	LicenseEvidenceRequired bool              `json:"license_evidence_required"`
	// LicenseEvidenceBinding controls how permission evidence binds to the
	// requested source. coordinate accepts only an exact member of the
	// descriptor-owned retrieval_permission_evidence_coordinates allowlist;
	// same_repository_license_file instead requires an HTTPS LICENSE or COPYING
	// file under the same descriptor-declared repository key. Curating a
	// coordinate is retrieval-policy evidence, not an automatic legal conclusion
	// and never authority to persist the fetched response body.
	LicenseEvidenceBinding string `json:"license_evidence_binding"`
	// RetrievalPermissionEvidenceCoordinates is nonempty only for coordinate
	// binding. Every member is an exact byte-canonical HTTPS evidence coordinate
	// selected by the admitted descriptor policy, never by the requesting caller.
	RetrievalPermissionEvidenceCoordinates []string `json:"retrieval_permission_evidence_coordinates,omitempty"`
	RepositoryPathSegments                 int      `json:"repository_path_segments,omitempty"`
	// SameRepositoryPermissionEvidencePattern is required only for
	// same_repository_license_file. It is an anchored, descriptor-owned regexp
	// over the exact license-file coordinate and carries exactly one named
	// `immutable_ref` capture that must equal the source immutable coordinate's
	// capture before the evidence coordinate is fetched and attested.
	SameRepositoryPermissionEvidencePattern string `json:"same_repository_permission_evidence_pattern,omitempty"`
	// UpstreamIdentityPolicy is required only for upstream_pinned mode. The
	// immutable-reference policy validates the caller coordinate against the
	// descriptor-owned anchored regexp before retrieval; both policies bind
	// the exact fetched content digest into the process-derived token.
	UpstreamIdentityPolicy    string `json:"upstream_identity_policy,omitempty"`
	ImmutableReferencePattern string `json:"immutable_reference_pattern,omitempty"`
	AllowQuery                bool   `json:"allow_query"`
	AllowFragment             bool   `json:"allow_fragment"`
}

// UnmarshalJSON keeps the external-source trust registry fail closed. These
// descriptors decide which authorities, URL prefixes, digest algorithms and
// license policies may mint external graph evidence; silently ignoring a
// misspelled key would weaken policy at process boot (for example,
// license_evidence_requried would otherwise decode as false).
func (d *ExternalSourceDescriptor) UnmarshalJSON(data []byte) error {
	if err := rejectDuplicateJSONObjectKeys(data, "external_source_descriptor"); err != nil {
		return err
	}
	type wire ExternalSourceDescriptor
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var decoded wire
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("decode external_source_descriptor: %w", err)
	}
	// These booleans are policy, not optional conveniences. A Go bool's zero
	// value cannot distinguish an explicit `false` from an omitted key, so
	// check presence in the wire object before accepting the decoded value.
	// Otherwise a truncated config silently changes query, fragment, or
	// license-evidence policy at boot, contrary to the config's no-default
	// contract.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decode external_source_descriptor policy keys: %w", err)
	}
	for _, name := range []string{"version_coordinate_mode", "license_evidence_required", "license_evidence_binding", "allow_query", "allow_fragment"} {
		if _, present := fields[name]; !present {
			return fmt.Errorf("decode external_source_descriptor: required policy field %q is missing (explicit true or false required)", name)
		}
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode external_source_descriptor: multiple JSON values are forbidden")
		}
		return fmt.Errorf("decode external_source_descriptor trailing data: %w", err)
	}
	*d = ExternalSourceDescriptor(decoded)
	return nil
}

func (d ExternalSourceDescriptor) validate(index int) error {
	prefix := fmt.Sprintf("external_sources[%d]", index)
	if !snakeCaseKeyPattern.MatchString(d.ID) {
		return fmt.Errorf("%s.id %q must be lowercase snake_case", prefix, d.ID)
	}
	if !snakeCaseKeyPattern.MatchString(d.SourceArtifactClass) {
		return fmt.Errorf("%s.source_artifact_class %q must be lowercase snake_case", prefix, d.SourceArtifactClass)
	}
	if _, allowed := externalSourceArtifactClasses[d.SourceArtifactClass]; !allowed {
		return fmt.Errorf("%s.source_artifact_class %q is not an allowed OOD external source class", prefix, d.SourceArtifactClass)
	}
	if d.ReferenceKind != "https_url_prefix" && d.ReferenceKind != "opaque_prefix" {
		return fmt.Errorf("%s.reference_kind %q invalid: want https_url_prefix | opaque_prefix", prefix, d.ReferenceKind)
	}
	if strings.TrimSpace(d.ReferencePrefix) != d.ReferencePrefix || d.ReferencePrefix == "" || !utf8.ValidString(d.ReferencePrefix) {
		return fmt.Errorf("%s.reference_prefix must be non-empty canonical UTF-8", prefix)
	}
	if d.ReferenceKind == "https_url_prefix" {
		u, err := parseCanonicalHTTPSReference(d.ReferencePrefix)
		if err != nil {
			return fmt.Errorf("%s.reference_prefix: %w", prefix, err)
		}
		if u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("%s.reference_prefix must not contain query or fragment", prefix)
		}
	}
	if d.ReferenceKind == "https_url_prefix" && !d.LicenseEvidenceRequired {
		return fmt.Errorf("%s.license_evidence_required must be true for automated HTTPS retrieval; retrieval permission is independent of body persistence and graph-coordinate retention", prefix)
	}
	switch d.LicenseEvidenceBinding {
	case licenseEvidenceBindingCoordinate:
		if !d.LicenseEvidenceRequired || d.RepositoryPathSegments != 0 || len(d.RetrievalPermissionEvidenceCoordinates) == 0 || d.SameRepositoryPermissionEvidencePattern != "" {
			return fmt.Errorf("%s license_evidence_binding=%q requires license_evidence_required=true, repository_path_segments=0, nonempty retrieval_permission_evidence_coordinates, and empty same_repository_permission_evidence_pattern", prefix, d.LicenseEvidenceBinding)
		}
		seenEvidence := make(map[string]struct{}, len(d.RetrievalPermissionEvidenceCoordinates))
		for j, evidence := range d.RetrievalPermissionEvidenceCoordinates {
			evidenceURL, err := parseCanonicalHTTPSReference(evidence)
			if err != nil {
				return fmt.Errorf("%s.retrieval_permission_evidence_coordinates[%d]: %w", prefix, j, err)
			}
			if evidenceURL.RawQuery != "" || evidenceURL.Fragment != "" {
				return fmt.Errorf("%s.retrieval_permission_evidence_coordinates[%d] must not carry query or fragment variants", prefix, j)
			}
			if _, duplicate := seenEvidence[evidence]; duplicate {
				return fmt.Errorf("%s.retrieval_permission_evidence_coordinates contains duplicate %q", prefix, evidence)
			}
			seenEvidence[evidence] = struct{}{}
		}
	case licenseEvidenceBindingSameRepositoryFile:
		if d.ReferenceKind != "https_url_prefix" || !d.LicenseEvidenceRequired || d.RepositoryPathSegments <= 0 || len(d.RetrievalPermissionEvidenceCoordinates) != 0 || d.SameRepositoryPermissionEvidencePattern == "" {
			return fmt.Errorf("%s license_evidence_binding=%q requires an HTTPS source, license_evidence_required=true, repository_path_segments>0, empty retrieval_permission_evidence_coordinates, and same_repository_permission_evidence_pattern", prefix, d.LicenseEvidenceBinding)
		}
		if _, err := compileImmutableRefCapturePattern(d.SameRepositoryPermissionEvidencePattern); err != nil {
			return fmt.Errorf("%s.same_repository_permission_evidence_pattern: %w", prefix, err)
		}
		u, err := parseCanonicalHTTPSReference(d.ReferencePrefix)
		if err != nil {
			return fmt.Errorf("%s same-repository reference_prefix: %w", prefix, err)
		}
		if len(splitNonEmptyURLPath(u.EscapedPath())) > d.RepositoryPathSegments {
			return fmt.Errorf("%s.reference_prefix already exceeds repository_path_segments=%d", prefix, d.RepositoryPathSegments)
		}
	case licenseEvidenceBindingNotRequired:
		if d.LicenseEvidenceRequired || d.ReferenceKind == "https_url_prefix" || d.RepositoryPathSegments != 0 || len(d.RetrievalPermissionEvidenceCoordinates) != 0 || d.SameRepositoryPermissionEvidencePattern != "" {
			return fmt.Errorf("%s license_evidence_binding=%q is allowed only for non-HTTPS adapters with license_evidence_required=false and empty retrieval-permission policy fields", prefix, d.LicenseEvidenceBinding)
		}
	default:
		return fmt.Errorf("%s.license_evidence_binding %q invalid: want %s | %s | %s", prefix, d.LicenseEvidenceBinding, licenseEvidenceBindingCoordinate, licenseEvidenceBindingSameRepositoryFile, licenseEvidenceBindingNotRequired)
	}
	if d.ContentHashAlgorithm != "sha256" {
		return fmt.Errorf("%s.content_hash_algorithm %q invalid: want sha256", prefix, d.ContentHashAlgorithm)
	}
	if d.VersionCoordinateMode != externalVersionModeContentDigest && d.VersionCoordinateMode != externalVersionModeUpstreamPinned {
		return fmt.Errorf("%s.version_coordinate_mode %q invalid: want %s | %s", prefix, d.VersionCoordinateMode, externalVersionModeContentDigest, externalVersionModeUpstreamPinned)
	}
	switch d.VersionCoordinateMode {
	case externalVersionModeContentDigest:
		if d.UpstreamIdentityPolicy != "" || d.ImmutableReferencePattern != "" || d.SameRepositoryPermissionEvidencePattern != "" {
			return fmt.Errorf("%s content_digest source must not declare upstream identity policy or immutable-reference patterns", prefix)
		}
	case externalVersionModeUpstreamPinned:
		switch d.UpstreamIdentityPolicy {
		case upstreamIdentityHTTPResponseWithContentDigest:
			if d.ImmutableReferencePattern != "" || d.SameRepositoryPermissionEvidencePattern != "" {
				return fmt.Errorf("%s HTTP-response upstream identity must not declare immutable-reference patterns", prefix)
			}
		case upstreamIdentityImmutableRefWithContentDigest:
			if d.ReferenceKind != "https_url_prefix" || d.ImmutableReferencePattern == "" || strings.TrimSpace(d.ImmutableReferencePattern) != d.ImmutableReferencePattern || !strings.HasPrefix(d.ImmutableReferencePattern, "^") || !strings.HasSuffix(d.ImmutableReferencePattern, "$") {
				return fmt.Errorf("%s immutable-reference upstream identity requires an HTTPS source and a whitespace-free ^...$ immutable_reference_pattern", prefix)
			}
			if len(d.ImmutableReferencePattern) > 4096 || !utf8.ValidString(d.ImmutableReferencePattern) {
				return fmt.Errorf("%s.immutable_reference_pattern must be canonical UTF-8 within 4096 bytes", prefix)
			}
			if _, err := regexp.Compile(d.ImmutableReferencePattern); err != nil {
				return fmt.Errorf("%s.immutable_reference_pattern: %w", prefix, err)
			}
			if d.LicenseEvidenceBinding == licenseEvidenceBindingSameRepositoryFile {
				if _, err := compileImmutableRefCapturePattern(d.ImmutableReferencePattern); err != nil {
					return fmt.Errorf("%s.immutable_reference_pattern for same-repository evidence: %w", prefix, err)
				}
			} else if d.SameRepositoryPermissionEvidencePattern != "" {
				return fmt.Errorf("%s.same_repository_permission_evidence_pattern requires license_evidence_binding=%q", prefix, licenseEvidenceBindingSameRepositoryFile)
			}
		default:
			return fmt.Errorf("%s.upstream_identity_policy %q invalid for upstream_pinned: want %s | %s", prefix, d.UpstreamIdentityPolicy, upstreamIdentityHTTPResponseWithContentDigest, upstreamIdentityImmutableRefWithContentDigest)
		}
	}
	if d.VersionStableNamePrefix == "" || strings.TrimSpace(d.VersionStableNamePrefix) != d.VersionStableNamePrefix || !utf8.ValidString(d.VersionStableNamePrefix) {
		return fmt.Errorf("%s.version_stable_name_prefix required as canonical UTF-8", prefix)
	}
	if !snakeCaseKeyPattern.MatchString(d.VersionStableNamePrefix) || !strings.HasSuffix(d.VersionStableNamePrefix, "_") {
		return fmt.Errorf("%s.version_stable_name_prefix %q must be a lowercase snake_case segment prefix ending in underscore", prefix, d.VersionStableNamePrefix)
	}
	if len(d.AllowedObjectClasses) == 0 {
		return fmt.Errorf("%s.allowed_object_classes must not be empty", prefix)
	}
	seen := map[string]struct{}{}
	for j, class := range d.AllowedObjectClasses {
		if !snakeCaseKeyPattern.MatchString(class) {
			return fmt.Errorf("%s.allowed_object_classes[%d] %q must be lowercase snake_case", prefix, j, class)
		}
		if _, duplicate := seen[class]; duplicate {
			return fmt.Errorf("%s.allowed_object_classes contains duplicate %q", prefix, class)
		}
		seen[class] = struct{}{}
	}
	if len(d.LocatorKinds) != len(d.AllowedObjectClasses) {
		return fmt.Errorf("%s.locator_kinds must contain exactly one policy for every allowed_object_classes member", prefix)
	}
	for class := range seen {
		kind, present := d.LocatorKinds[class]
		if !present {
			return fmt.Errorf("%s.locator_kinds missing object class %q", prefix, class)
		}
		switch kind {
		case "resource_root", "html_id_or_name", "json_pointer", "code_graph_coordinate":
		default:
			return fmt.Errorf("%s.locator_kinds[%q]=%q invalid: want resource_root | html_id_or_name | json_pointer | code_graph_coordinate", prefix, class, kind)
		}
		if class == "api_symbol" && kind != "html_id_or_name" && kind != "json_pointer" {
			return fmt.Errorf("%s.locator_kinds[%q]=%q cannot prove an extracted API symbol", prefix, class, kind)
		}
		if class == "code_symbol_ref" && kind != "code_graph_coordinate" {
			return fmt.Errorf("%s.locator_kinds[%q] must be code_graph_coordinate", prefix, class)
		}
	}
	for class := range d.LocatorKinds {
		if _, allowed := seen[class]; !allowed {
			return fmt.Errorf("%s.locator_kinds contains unbound object class %q", prefix, class)
		}
	}
	if d.FreshnessWindowSeconds <= 0 {
		return fmt.Errorf("%s.freshness_window_seconds must be > 0", prefix)
	}
	if d.FreshnessWindowSeconds > maxExternalFreshnessWindowSeconds {
		return fmt.Errorf("%s.freshness_window_seconds exceeds time.Duration without overflow", prefix)
	}
	return nil
}

// validateExternalRetrievalPermissionEvidence composes the canonical evidence
// coordinate check with the selected descriptor's vendor-neutral coordinate
// or same-repository binding policy. Keeping both checks here makes this sole
// pre-network path safe even for future internal callers that bypass the
// higher-level source-coordinate validator.
//
// This helper validates only the descriptor-owned evidence-coordinate shape.
// It never turns that coordinate (or the bytes at it) into permission. The
// sole executable authorization decision is resolved separately by
// externalSourceAuthorizationResolver immediately before external I/O.
func validateExternalRetrievalPermissionEvidence(policy ExternalSourceDescriptor, coord ArtifactSourceCoordinate) error {
	if !policy.LicenseEvidenceRequired {
		return nil
	}
	if coord.LicenseEvidence == "" {
		return fmt.Errorf("source_coordinate.license_evidence_when_available required by external source %q before automated retrieval", policy.ID)
	}
	if err := validateLicenseEvidence(coord.LicenseEvidence); err != nil {
		return fmt.Errorf("source_coordinate.license_evidence_when_available for external source %q: %w", policy.ID, err)
	}
	switch policy.LicenseEvidenceBinding {
	case licenseEvidenceBindingCoordinate:
		if strings.HasPrefix(coord.LicenseEvidence, "spdx:") {
			return fmt.Errorf("SPDX-only evidence cannot authorize automated HTTPS retrieval; provide a canonical permission-evidence URL")
		}
		for _, admitted := range policy.RetrievalPermissionEvidenceCoordinates {
			if coord.LicenseEvidence == admitted {
				return nil
			}
		}
		return fmt.Errorf("source_coordinate.license_evidence_when_available %q is not an exact retrieval-permission evidence coordinate admitted by external source %q", coord.LicenseEvidence, policy.ID)
	case licenseEvidenceBindingSameRepositoryFile:
		if err := validateSameRepositoryLicenseFileEvidence(policy, coord.SourceStableReference, coord.LicenseEvidence); err != nil {
			return fmt.Errorf("source_coordinate.license_evidence_when_available for external source %q: %w", policy.ID, err)
		}
		return nil
	default:
		return fmt.Errorf("external source %q has no executable retrieval-permission evidence binding", policy.ID)
	}
}

func validateSameRepositoryLicenseFileEvidence(policy ExternalSourceDescriptor, reference, evidence string) error {
	ref, err := parseCanonicalHTTPSReference(reference)
	if err != nil {
		return fmt.Errorf("repository coordinate is not canonical: %w", err)
	}
	refParts := splitNonEmptyURLPath(ref.EscapedPath())
	if policy.RepositoryPathSegments <= 0 || len(refParts) < policy.RepositoryPathSegments {
		return fmt.Errorf("repository coordinate does not contain the configured %d-segment repository key", policy.RepositoryPathSegments)
	}
	if strings.HasPrefix(evidence, "spdx:") {
		return fmt.Errorf("SPDX-only evidence is not bound to the requested repository; provide its canonical license-file URL")
	}
	evidenceURL, err := parseCanonicalHTTPSReference(evidence)
	if err != nil {
		return fmt.Errorf("repository license evidence URL is not canonical: %w", err)
	}
	evidenceParts := splitNonEmptyURLPath(evidenceURL.EscapedPath())
	if evidenceURL.Host != ref.Host || len(evidenceParts) <= policy.RepositoryPathSegments {
		return fmt.Errorf("repository license evidence must resolve beneath the same HTTPS host and repository key")
	}
	for i := 0; i < policy.RepositoryPathSegments; i++ {
		if evidenceParts[i] != refParts[i] {
			return fmt.Errorf("repository license evidence does not match requested repository path segment %d", i)
		}
	}
	filename := evidenceParts[len(evidenceParts)-1]
	base := strings.ToLower(filename)
	if !(base == "copying" || strings.HasPrefix(base, "copying.") || base == "license" || strings.HasPrefix(base, "license.")) {
		return fmt.Errorf("repository evidence terminal %q is not a canonical LICENSE or COPYING file", filename)
	}
	if evidenceURL.RawQuery != "" || evidenceURL.Fragment != "" {
		return fmt.Errorf("repository license evidence must not carry query or fragment variants")
	}
	sourceImmutableRef, err := extractImmutableRefCapture(policy.ImmutableReferencePattern, reference)
	if err != nil {
		return fmt.Errorf("repository source coordinate is not descriptor-proven immutable: %w", err)
	}
	evidenceImmutableRef, err := extractImmutableRefCapture(policy.SameRepositoryPermissionEvidencePattern, evidence)
	if err != nil {
		return fmt.Errorf("repository license evidence coordinate is not descriptor-proven immutable: %w", err)
	}
	if sourceImmutableRef != evidenceImmutableRef {
		return fmt.Errorf("repository license evidence immutable_ref does not match requested source immutable_ref")
	}
	return nil
}

func compileImmutableRefCapturePattern(raw string) (*regexp.Regexp, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || !utf8.ValidString(raw) || len(raw) > 4096 || !strings.HasPrefix(raw, "^") || !strings.HasSuffix(raw, "$") {
		return nil, fmt.Errorf("must be canonical UTF-8 within 4096 bytes and anchored with ^...$")
	}
	compiled, err := regexp.Compile(raw)
	if err != nil {
		return nil, err
	}
	captures := 0
	for _, name := range compiled.SubexpNames() {
		if name == "immutable_ref" {
			captures++
		}
	}
	if captures != 1 {
		return nil, fmt.Errorf("must declare exactly one named immutable_ref capture")
	}
	return compiled, nil
}

func extractImmutableRefCapture(pattern, value string) (string, error) {
	compiled, err := compileImmutableRefCapturePattern(pattern)
	if err != nil {
		return "", err
	}
	match := compiled.FindStringSubmatch(value)
	if match == nil {
		return "", fmt.Errorf("coordinate does not match its anchored descriptor pattern")
	}
	for index, name := range compiled.SubexpNames() {
		if name == "immutable_ref" {
			if index >= len(match) || match[index] == "" {
				return "", fmt.Errorf("immutable_ref capture is empty")
			}
			return match[index], nil
		}
	}
	return "", fmt.Errorf("immutable_ref capture is absent")
}

func validateUpstreamPinnedReference(policy ExternalSourceDescriptor, reference string) error {
	if policy.VersionCoordinateMode != externalVersionModeUpstreamPinned {
		return nil
	}
	switch policy.UpstreamIdentityPolicy {
	case upstreamIdentityHTTPResponseWithContentDigest:
		return nil
	case upstreamIdentityImmutableRefWithContentDigest:
		resourceReference, err := externalResourceReference(reference, policy)
		if err != nil {
			return fmt.Errorf("external source %q immutable reference: %w", policy.ID, err)
		}
		matched, err := regexp.MatchString(policy.ImmutableReferencePattern, resourceReference)
		if err != nil {
			return fmt.Errorf("external source %q immutable-reference policy: %w", policy.ID, err)
		}
		if !matched {
			return fmt.Errorf("source_coordinate.source_stable_reference is not an immutable coordinate admitted by external source %q", policy.ID)
		}
		return nil
	default:
		return fmt.Errorf("external source %q has no executable upstream identity policy", policy.ID)
	}
}

func splitNonEmptyURLPath(path string) []string {
	raw := strings.Split(strings.Trim(path, "/"), "/")
	out := make([]string, 0, len(raw))
	for _, part := range raw {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// UnmarshalJSON keeps source_coordinate fail-closed on every ingress path,
// including the typed MCP decoder and file-backed spec_graph_import. Without
// a field-local decoder, encoding/json would silently discard a misspelled
// identity key and the remaining fields could still form a plausible row.
func (c *ArtifactSourceCoordinate) UnmarshalJSON(data []byte) error {
	if err := rejectDuplicateJSONObjectKeys(data, "source_coordinate"); err != nil {
		return err
	}
	type wire ArtifactSourceCoordinate
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var decoded wire
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("decode source_coordinate: %w", err)
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode source_coordinate: multiple JSON values are forbidden")
		}
		return fmt.Errorf("decode source_coordinate trailing data: %w", err)
	}
	*c = ArtifactSourceCoordinate(decoded)
	return nil
}

// UnmarshalJSON closes the duplicate-key ambiguity one level above the
// coordinate too. Without this guard, two source_coordinate members on one
// submission are each individually valid and encoding/json silently lets the
// last one replace the first.
func (s *ArtifactSubmission) UnmarshalJSON(data []byte) error {
	if err := rejectDuplicateJSONObjectKeys(data, "artifact_submission"); err != nil {
		return err
	}
	type wire ArtifactSubmission
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var decoded wire
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("decode artifact_submission: %w", err)
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode artifact_submission: multiple JSON values are forbidden")
		}
		return fmt.Errorf("decode artifact_submission trailing data: %w", err)
	}
	*s = ArtifactSubmission(decoded)
	return nil
}

// UnmarshalJSON keeps external relationships structural. Unknown or repeated
// keys are refused so a misspelled endpoint cannot silently decode as empty
// and a duplicate key cannot make edge identity parser-dependent.
func (r *ExternalRelationship) UnmarshalJSON(data []byte) error {
	if err := rejectDuplicateJSONObjectKeys(data, "external_relationship"); err != nil {
		return err
	}
	type wire ExternalRelationship
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var decoded wire
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("decode external_relationship: %w", err)
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode external_relationship: multiple JSON values are forbidden")
		}
		return fmt.Errorf("decode external_relationship trailing data: %w", err)
	}
	*r = ExternalRelationship(decoded)
	return nil
}

func (c *stagingLoadConcept) UnmarshalJSON(data []byte) error {
	if err := rejectDuplicateJSONObjectKeys(data, "staging_concept"); err != nil {
		return err
	}
	type wire stagingLoadConcept
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var decoded wire
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("decode staging_concept: %w", err)
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode staging_concept: multiple JSON values are forbidden")
		}
		return fmt.Errorf("decode staging_concept trailing data: %w", err)
	}
	*c = stagingLoadConcept(decoded)
	return nil
}

func (e *stagingLoadEdge) UnmarshalJSON(data []byte) error {
	if err := rejectDuplicateJSONObjectKeys(data, "staging_edge"); err != nil {
		return err
	}
	type wire stagingLoadEdge
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var decoded wire
	if err := dec.Decode(&decoded); err != nil {
		return fmt.Errorf("decode staging_edge: %w", err)
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode staging_edge: multiple JSON values are forbidden")
		}
		return fmt.Errorf("decode staging_edge trailing data: %w", err)
	}
	*e = stagingLoadEdge(decoded)
	return nil
}

func rejectDuplicateJSONObjectKeys(data []byte, label string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	start, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	if delim, ok := start.(json.Delim); !ok || delim != '{' {
		return fmt.Errorf("decode %s: JSON object required", label)
	}
	seen := map[string]struct{}{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("decode %s key: %w", label, err)
		}
		key, ok := tok.(string)
		if !ok {
			return fmt.Errorf("decode %s: object key must be a string", label)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("decode %s: duplicate field %q forbidden", label, key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return fmt.Errorf("decode %s.%s: %w", label, key, err)
		}
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode %s: trailing token %v forbidden", label, tok)
		}
		return fmt.Errorf("decode %s trailing data: %w", label, err)
	}
	return nil
}

// rejectDuplicateJSONKeysRecursive scans the untouched JSON wire value and
// refuses duplicate members at every object depth. It exists in addition to
// the type-local UnmarshalJSON guards because the MCP SDK applies schemas via
// map[string]any and re-marshals before invoking typed handlers, which erases
// duplicate-member evidence unless the original CallToolRequest.Arguments is
// inspected explicitly.
func rejectDuplicateJSONKeysRecursive(data []byte, label string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSONValueRejectingDuplicateKeys(dec, label); err != nil {
		return err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode %s: trailing token %v forbidden", label, tok)
		}
		return fmt.Errorf("decode %s trailing data: %w", label, err)
	}
	return nil
}

func walkJSONValueRejectingDuplicateKeys(dec *json.Decoder, path string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	delim, composite := tok.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return fmt.Errorf("decode %s key: %w", path, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("decode %s: object key must be a string", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("decode %s: duplicate field %q forbidden", path, key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValueRejectingDuplicateKeys(dec, path+"."+key); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return fmt.Errorf("decode %s: malformed JSON object", path)
		}
		return nil
	case '[':
		index := 0
		for dec.More() {
			if err := walkJSONValueRejectingDuplicateKeys(dec, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
			index++
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return fmt.Errorf("decode %s: malformed JSON array", path)
		}
		return nil
	default:
		return fmt.Errorf("decode %s: unexpected JSON delimiter %q", path, delim)
	}
}

// resolveArtifactSourceCoordinate returns the effective coordinate for one
// submission. A nil input preserves the historical bootstrap behavior only
// for kinds without an explicit source_coordinate_policy. External-reference
// kinds require a complete coordinate. A non-nil input is all-or-nothing:
// partial coordinates are rejected rather than silently borrowing bootstrap
// defaults and producing a plausible but false source identity.
func resolveArtifactSourceCoordinate(kind, canonicalName string, kindDescriptor NodeKindDescriptor, in *ArtifactSourceCoordinate) (ArtifactSourceCoordinate, error) {
	external := kindDescriptor.ExternalReferenceRequired()
	externalAuthority := kindDescriptor.SourceAuthority()
	if in == nil {
		if external {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate required for external-reference class %q; bootstrap name/unversioned identity is forbidden", kind)
		}
		return ArtifactSourceCoordinate{
			SourceAuthorityID:     bootstrapSourceAuthority,
			SourceArtifactClass:   kind,
			SourceRefKind:         "name",
			SourceStableReference: canonicalName,
			VersionCoordinate:     "unversioned",
			SectionPath:           SectionPathRoot,
		}, nil
	}
	if !external {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate is supported only for registry-declared external-reference classes; %q retains bootstrap name/unversioned identity", kind)
	}

	c := *in
	required := []struct {
		name  string
		value string
	}{
		{"source_authority_id", c.SourceAuthorityID},
		{"source_artifact_class", c.SourceArtifactClass},
		{"source_ref_kind", c.SourceRefKind},
		{"source_stable_reference", c.SourceStableReference},
		{"section_path", c.SectionPath},
	}
	// External load callers omit version_coordinate because no truthful token
	// exists until the trusted receipt does. This shared decoder also consumes
	// the process-finalized coordinate during no-refetch staging promotion, so
	// the caller-vs-finalized distinction is enforced by the load/promotion
	// validators rather than by this field grammar.
	if !external {
		required = append(required, struct {
			name  string
			value string
		}{"version_coordinate", c.VersionCoordinate})
	}
	for _, f := range required {
		if f.value == "" {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.%s required when source_coordinate is provided", f.name)
		}
		if strings.TrimSpace(f.value) != f.value {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.%s must be canonical without leading or trailing whitespace", f.name)
		}
		if !utf8.ValidString(f.value) {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.%s must be valid UTF-8", f.name)
		}
	}

	if err := ValidateUUID(c.SourceAuthorityID); err != nil {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_authority_id: %w", err)
	}
	if len(c.SourceArtifactClass) > 64 || !snakeCaseKeyPattern.MatchString(c.SourceArtifactClass) {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_artifact_class %q must be lowercase snake_case and at most 64 bytes", c.SourceArtifactClass)
	}
	if _, ok := sourceRefKinds[c.SourceRefKind]; !ok {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_ref_kind %q invalid: want id | name | coordinate | path", c.SourceRefKind)
	}
	if len(c.SourceStableReference) > 2048 {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_stable_reference exceeds OODGraphObjects STRING(2048)")
	}
	if len(c.VersionCoordinate) > 1024 {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.version_coordinate exceeds OODGraphObjects STRING(1024)")
	}
	var vc VersionCoordinate
	if c.VersionCoordinate != "" {
		parsed, err := ParseVersionCoordinate(c.VersionCoordinate)
		if err != nil {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.version_coordinate: %w", err)
		}
		vc = parsed
		if vc.String() != c.VersionCoordinate {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.version_coordinate %q is not canonical; canonical form is %q", c.VersionCoordinate, vc.String())
		}
		if vc.Kind == VersionSourceNamed && vc.SourceAuthorityID != c.SourceAuthorityID {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.version_coordinate authority %q does not match source_authority_id %q", vc.SourceAuthorityID, c.SourceAuthorityID)
		}
	}
	if len(c.SectionPath) > 2048 {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.section_path exceeds OODGraphObjects STRING(2048)")
	}
	if err := ValidateSectionPath(c.SectionPath); err != nil {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.section_path: %w", err)
	}

	if !external && (c.SourceContentHash == "") != (c.SourceContentHashOwner == "") {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_content_hash and source_content_hash_owner must be supplied together")
	}
	if external && c.SourceContentHash == "" && c.SourceContentHashOwner != "" {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_content_hash_owner cannot be supplied without source_content_hash")
	}
	if c.SourceContentHash != "" {
		if strings.TrimSpace(c.SourceContentHash) != c.SourceContentHash {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_content_hash must be canonical without leading or trailing whitespace")
		}
		if !utf8.ValidString(c.SourceContentHash) {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_content_hash must be valid UTF-8")
		}
		if len(c.SourceContentHash) > 128 {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_content_hash exceeds OODGraphObjects STRING(128)")
		}
		if err := validateExternalContentHash("sha256", c.SourceContentHash); err != nil {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_content_hash: %w", err)
		}
		if c.SourceContentHashOwner != "" {
			if err := ValidateUUID(c.SourceContentHashOwner); err != nil {
				return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_content_hash_owner: %w", err)
			}
		}
	}
	if c.RetrievedAt != "" {
		if strings.TrimSpace(c.RetrievedAt) != c.RetrievedAt || !utf8.ValidString(c.RetrievedAt) {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.retrieved_at must be canonical UTF-8 without surrounding whitespace")
		}
		retrievedAt, err := time.Parse(time.RFC3339Nano, c.RetrievedAt)
		if err != nil {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.retrieved_at must be RFC3339: %w", err)
		}
		if retrievedAt.UTC().Format(time.RFC3339Nano) != c.RetrievedAt {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.retrieved_at %q is not canonical UTC RFC3339", c.RetrievedAt)
		}
	}
	if c.LicenseEvidence != "" {
		if strings.TrimSpace(c.LicenseEvidence) != c.LicenseEvidence || !utf8.ValidString(c.LicenseEvidence) {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.license_evidence_when_available must be canonical UTF-8 without surrounding whitespace")
		}
		if len(c.LicenseEvidence) > 2048 {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.license_evidence_when_available exceeds 2048 bytes")
		}
		if err := validateLicenseEvidence(c.LicenseEvidence); err != nil {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.license_evidence_when_available: %w", err)
		}
	}

	// The external-reference family has a closed, stronger identity
	// contract than the generic grammar above. Its rows are OOD-Graph-owned
	// registered coordinates over official sources; accepting an arbitrary
	// authority, name ref, trust class, unpinned version, or unhashed source
	// would make a syntactically valid but semantically false reference.
	if external {
		if c.SourceAuthorityID != externalAuthority {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_authority_id for %s must match registry authority %q", kind, externalAuthority)
		}
		if c.SourceRefKind != "coordinate" {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_ref_kind for %s must be coordinate", kind)
		}
		if c.SectionPath != SectionPathRoot {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.section_path for %s must be %q", kind, SectionPathRoot)
		}
		if c.VersionCoordinate != "" && vc.Kind != VersionSourceNamed {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.version_coordinate for %s must be a pinned source-named version or digest coordinate", kind)
		}
		// External digest evidence is minted by the trusted fetch adapter after
		// registry resolution. A caller may supply only an expected digest;
		// digest owner and retrieval time are trusted process outputs checked by
		// the external-reference validator before any identity is materialized.
		if c.SourceContentHashOwner != "" && c.SourceContentHashOwner != c.SourceAuthorityID {
			return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.source_content_hash_owner for %s must match source_authority_id", kind)
		}
		// A non-empty coordinate here is process-finalized staging state; load
		// callers are rejected before network I/O in both version modes. When a
		// finalized token uses sha256_<digest>, refuse any contradictory digest
		// rather than sealing two content identities for one coordinate.
		if c.VersionCoordinate != "" {
			if tokenDigest, ok := canonicalSHA256VersionTokenDigest(vc.SourceVersionToken); ok && c.SourceContentHash != "" && tokenDigest != c.SourceContentHash {
				return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate.version_coordinate SHA-256 token does not match source_content_hash")
			}
		}
	}
	if external && c.VersionCoordinate == "" {
		return c, nil
	}

	ga := GraphAddress{
		ObjectClass:       kind,
		SourceAuthorityID: c.SourceAuthorityID,
		SourceRefKind:     c.SourceRefKind,
		SourceRef:         c.SourceStableReference,
		VersionCoordinate: c.VersionCoordinate,
		SectionPath:       c.SectionPath,
	}
	address := ga.String()
	if len(address) > 4096 {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate graph_address exceeds OODGraphObjects STRING(4096) after canonical percent encoding")
	}
	parsed, err := ParseGraphAddress(address)
	if err != nil {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate cannot form canonical graph_address: %w", err)
	}
	if parsed.String() != address {
		return ArtifactSourceCoordinate{}, fmt.Errorf("source_coordinate graph_address failed canonical round trip")
	}

	return c, nil
}

func canonicalSHA256VersionTokenDigest(token string) (string, bool) {
	const prefix = "sha256_"
	if !strings.HasPrefix(token, prefix) {
		return "", false
	}
	digest := strings.TrimPrefix(token, prefix)
	if validateExternalContentHash("sha256", digest) != nil {
		return "", false
	}
	return digest, true
}

func resolveExternalSourcePolicy(cfg SpecGraphConfig, kind, canonicalName string, c ArtifactSourceCoordinate) (ExternalSourceDescriptor, error) {
	stableName := canonicalName
	if c.VersionCoordinate != "" {
		vc, err := ParseVersionCoordinate(c.VersionCoordinate)
		if err != nil {
			return ExternalSourceDescriptor{}, err
		}
		if vc.StableName != canonicalName {
			return ExternalSourceDescriptor{}, fmt.Errorf("external-reference canonical name %q must equal version-coordinate stable name %q", canonicalName, vc.StableName)
		}
		stableName = vc.StableName
	}
	matches := make([]ExternalSourceDescriptor, 0, 1)
	for _, d := range cfg.ExternalSources {
		if d.SourceArtifactClass != c.SourceArtifactClass || !containsString(d.AllowedObjectClasses, kind) {
			continue
		}
		if !strings.HasPrefix(stableName, d.VersionStableNamePrefix) {
			continue
		}
		if !externalReferenceMatches(d, c.SourceStableReference) {
			continue
		}
		matches = append(matches, d)
	}
	if len(matches) == 0 {
		return ExternalSourceDescriptor{}, fmt.Errorf("source coordinate is not admitted by external_sources registry: class=%q object_class=%q reference=%q version_stable_name=%q", c.SourceArtifactClass, kind, c.SourceStableReference, stableName)
	}
	if len(matches) != 1 {
		ids := make([]string, 0, len(matches))
		for _, match := range matches {
			ids = append(ids, match.ID)
		}
		return ExternalSourceDescriptor{}, fmt.Errorf("source coordinate ambiguously matches external_sources registry entries %q", ids)
	}
	return matches[0], nil
}

func externalReferenceMatches(d ExternalSourceDescriptor, reference string) bool {
	if d.ReferenceKind == "opaque_prefix" {
		if reference == d.ReferencePrefix {
			return true
		}
		if !strings.HasSuffix(d.ReferencePrefix, "/") && !strings.HasSuffix(d.ReferencePrefix, ":") && !strings.HasSuffix(d.ReferencePrefix, "#") && !strings.HasSuffix(d.ReferencePrefix, "@") {
			return false
		}
		return strings.HasPrefix(reference, d.ReferencePrefix)
	}
	registered, err := parseCanonicalHTTPSReference(d.ReferencePrefix)
	if err != nil {
		return false
	}
	candidate, err := parseCanonicalHTTPSReference(reference)
	if err != nil {
		return false
	}
	if candidate.RawQuery != "" && !d.AllowQuery {
		return false
	}
	if candidate.Fragment != "" && !d.AllowFragment {
		return false
	}
	if registered.Host != candidate.Host {
		return false
	}
	registeredPath := strings.TrimSuffix(registered.EscapedPath(), "/")
	candidatePath := strings.TrimSuffix(candidate.EscapedPath(), "/")
	if registeredPath == "" {
		registeredPath = "/"
	}
	if candidatePath == "" {
		candidatePath = "/"
	}
	return registeredPath == "/" || candidatePath == registeredPath || strings.HasPrefix(candidatePath, registeredPath+"/")
}

func parseCanonicalHTTPSReference(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) != raw || !utf8.ValidString(raw) {
		return nil, fmt.Errorf("must be canonical UTF-8 without surrounding whitespace")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("must be an absolute https URL without userinfo")
	}
	if u.Opaque != "" || u.Port() != "" || strings.HasSuffix(u.Host, ":") || u.Host != strings.ToLower(u.Host) || strings.HasSuffix(u.Hostname(), ".") {
		return nil, fmt.Errorf("URL host must be lowercase, non-opaque, without a trailing dot or explicit port")
	}
	if !utf8.ValidString(u.Path) || !utf8.ValidString(u.Fragment) {
		return nil, fmt.Errorf("URL percent escapes must decode to valid UTF-8")
	}
	for i := 0; i < len(u.Host); i++ {
		if u.Host[i] > 0x7f {
			return nil, fmt.Errorf("URL host must use canonical ASCII/IDNA form")
		}
	}
	if strings.Contains(u.Path, "//") {
		return nil, fmt.Errorf("URL path repeated separators are non-canonical")
	}
	if u.Path != "/" && strings.HasSuffix(u.Path, "/") {
		return nil, fmt.Errorf("URL non-root path must not carry a trailing-slash variant")
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, fmt.Errorf("URL path dot-segments are forbidden")
		}
	}
	canonicalPath := canonicalHTTPPath(u.Path)
	query := ""
	if u.ForceQuery {
		return nil, fmt.Errorf("empty query delimiter is non-canonical")
	}
	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			return nil, fmt.Errorf("invalid URL query: %w", err)
		}
		for key, items := range values {
			if len(items) != 1 {
				return nil, fmt.Errorf("URL query key %q must occur exactly once", key)
			}
			if !utf8.ValidString(key) || !utf8.ValidString(items[0]) {
				return nil, fmt.Errorf("URL query percent escapes must decode to valid UTF-8")
			}
		}
		query = values.Encode()
		if query != u.RawQuery {
			return nil, fmt.Errorf("URL query is not in canonical sorted encoding")
		}
	}
	fragment := ""
	if u.Fragment != "" {
		fragment = percentEncodeFragmentUpper(u.Fragment)
	}
	canonical := "https://" + u.Host + canonicalPath
	if query != "" {
		canonical += "?" + query
	}
	if fragment != "" {
		canonical += "#" + fragment
	}
	if raw != canonical {
		return nil, fmt.Errorf("URL is not byte-canonical; canonical form is %q", canonical)
	}
	return u, nil
}

func validateLicenseEvidence(raw string) error {
	if strings.HasPrefix(raw, "https://") {
		if _, err := parseCanonicalHTTPSReference(raw); err != nil {
			return fmt.Errorf("HTTPS evidence URL is not canonical: %w", err)
		}
		return nil
	}
	if strings.HasPrefix(raw, "spdx:") {
		identifier := strings.TrimPrefix(raw, "spdx:")
		if identifier == "" || len(identifier) > 128 {
			return fmt.Errorf("SPDX evidence identifier must contain 1..128 bytes")
		}
		for _, r := range identifier {
			if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune(".-+", r)) {
				return fmt.Errorf("SPDX evidence identifier %q contains a non-token character", identifier)
			}
		}
		return nil
	}
	return fmt.Errorf("must be a byte-canonical HTTPS evidence URL or spdx:<identifier> token")
}

func canonicalHTTPPath(decoded string) string {
	if decoded == "" {
		return "/"
	}
	var b strings.Builder
	for i := 0; i < len(decoded); i++ {
		c := decoded[i]
		if c == '/' || isUnreserved(c) || strings.ContainsRune("!$&'()*+,;=:@", rune(c)) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// composeSourceSectionPath scopes an extracted contract/payload path under
// the submitted source object's section_path. Bootstrap objects are rooted
// at "$", preserving the old paths byte-for-byte; a versioned source
// fragment at $.foo produces symbols at $.foo.contract..., not at an
// unrelated root.
func composeSourceSectionPath(root, extracted string) (string, error) {
	if err := ValidateSectionPath(root); err != nil {
		return "", err
	}
	if err := ValidateSectionPath(extracted); err != nil {
		return "", err
	}
	if root == SectionPathRoot {
		return extracted, nil
	}
	if extracted == SectionPathRoot {
		return root, nil
	}
	joined := root + strings.TrimPrefix(extracted, SectionPathRoot)
	if err := ValidateSectionPath(joined); err != nil {
		return "", err
	}
	return joined, nil
}

func sourceCoordinateToNullJSON(c *ArtifactSourceCoordinate) (spanner.NullJSON, error) {
	if c == nil {
		return spanner.NullJSON{Valid: false}, nil
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return spanner.NullJSON{Valid: false}, fmt.Errorf("marshal source_coordinate: %w", err)
	}
	return spanner.NullJSON{Value: json.RawMessage(raw), Valid: true}, nil
}

func sourceCoordinateFromJSON(v interface{}) (*ArtifactSourceCoordinate, error) {
	if v == nil {
		return nil, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal staged source_coordinate: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var c ArtifactSourceCoordinate
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode staged source_coordinate: %w", err)
	}
	return &c, nil
}
