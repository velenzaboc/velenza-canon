package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func cloneExternalPolicyForBounds(in ExternalSourceDescriptor) ExternalSourceDescriptor {
	out := in
	out.AllowedObjectClasses = append([]string(nil), in.AllowedObjectClasses...)
	out.RetrievalPermissionEvidenceCoordinates = append([]string(nil), in.RetrievalPermissionEvidenceCoordinates...)
	out.LocatorKinds = make(map[string]string, len(in.LocatorKinds))
	for key, value := range in.LocatorKinds {
		out.LocatorKinds[key] = value
	}
	return out
}

func TestExternalSourceDescriptorValidationRefusalMatrix(t *testing.T) {
	canonical := tlsTestExternalPolicy("https://example.com/docs")
	if err := canonical.validate(0); err != nil {
		t.Fatalf("canonical policy: %v", err)
	}
	tests := []struct {
		name   string
		want   string
		mutate func(*ExternalSourceDescriptor)
	}{
		{"id grammar", "id", func(p *ExternalSourceDescriptor) { p.ID = "Bad-ID" }},
		{"artifact grammar", "source_artifact_class", func(p *ExternalSourceDescriptor) { p.SourceArtifactClass = "Bad" }},
		{"artifact registry", "not an allowed", func(p *ExternalSourceDescriptor) { p.SourceArtifactClass = "invented_source" }},
		{"reference kind", "reference_kind", func(p *ExternalSourceDescriptor) { p.ReferenceKind = "ftp" }},
		{"reference prefix", "reference_prefix", func(p *ExternalSourceDescriptor) { p.ReferencePrefix = " https://example.com/docs" }},
		{"reference query", "query or fragment", func(p *ExternalSourceDescriptor) { p.ReferencePrefix = "https://example.com/docs?q=1" }},
		{"https permission", "must be true", func(p *ExternalSourceDescriptor) { p.LicenseEvidenceRequired = false }},
		{"coordinate shape", "license_evidence_binding", func(p *ExternalSourceDescriptor) { p.RetrievalPermissionEvidenceCoordinates = nil }},
		{"evidence query", "must not carry query", func(p *ExternalSourceDescriptor) {
			p.RetrievalPermissionEvidenceCoordinates = []string{"https://example.com/grant?q=1"}
		}},
		{"evidence duplicate", "duplicate", func(p *ExternalSourceDescriptor) {
			p.RetrievalPermissionEvidenceCoordinates = []string{"https://example.com/grant", "https://example.com/grant"}
		}},
		{"binding registry", "invalid", func(p *ExternalSourceDescriptor) { p.LicenseEvidenceBinding = "invented" }},
		{"hash algorithm", "content_hash_algorithm", func(p *ExternalSourceDescriptor) { p.ContentHashAlgorithm = "sha1" }},
		{"version mode", "version_coordinate_mode", func(p *ExternalSourceDescriptor) { p.VersionCoordinateMode = "latest" }},
		{"digest identity extras", "content_digest", func(p *ExternalSourceDescriptor) {
			p.UpstreamIdentityPolicy = upstreamIdentityHTTPResponseWithContentDigest
		}},
		{"stable prefix empty", "version_stable_name_prefix", func(p *ExternalSourceDescriptor) { p.VersionStableNamePrefix = "" }},
		{"stable prefix grammar", "ending in underscore", func(p *ExternalSourceDescriptor) { p.VersionStableNamePrefix = "official" }},
		{"classes empty", "must not be empty", func(p *ExternalSourceDescriptor) { p.AllowedObjectClasses = nil; p.LocatorKinds = map[string]string{} }},
		{"class grammar", "lowercase snake_case", func(p *ExternalSourceDescriptor) {
			p.AllowedObjectClasses = []string{"Bad"}
			p.LocatorKinds = map[string]string{"Bad": "resource_root"}
		}},
		{"class duplicate", "duplicate", func(p *ExternalSourceDescriptor) {
			p.AllowedObjectClasses = []string{"reference_page", "reference_page"}
			p.LocatorKinds = map[string]string{"reference_page": "html_id_or_name"}
		}},
		{"locator count", "exactly one", func(p *ExternalSourceDescriptor) { p.LocatorKinds = map[string]string{} }},
		{"locator kind", "invalid", func(p *ExternalSourceDescriptor) { p.LocatorKinds["reference_page"] = "xpath" }},
		{"locator extra", "exactly one", func(p *ExternalSourceDescriptor) {
			p.AllowedObjectClasses = append(p.AllowedObjectClasses, "extra_class")
			p.LocatorKinds["extra_class"] = "resource_root"
			p.AllowedObjectClasses = p.AllowedObjectClasses[:1]
		}},
		{"freshness zero", "must be > 0", func(p *ExternalSourceDescriptor) { p.FreshnessWindowSeconds = 0 }},
		{"freshness overflow", "exceeds", func(p *ExternalSourceDescriptor) { p.FreshnessWindowSeconds = maxExternalFreshnessWindowSeconds + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := cloneExternalPolicyForBounds(canonical)
			test.mutate(&policy)
			if err := policy.validate(3); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestExternalSourceDescriptorPinnedAndLocatorPolicyRefusals(t *testing.T) {
	repository, _ := sameRepositoryTestExternalPolicy()
	if err := repository.validate(0); err != nil {
		t.Fatalf("canonical repository policy: %v", err)
	}
	tests := []struct {
		name   string
		want   string
		mutate func(*ExternalSourceDescriptor)
	}{
		{"repository binding shape", "requires an HTTPS source", func(p *ExternalSourceDescriptor) { p.RepositoryPathSegments = 0 }},
		{"repository prefix depth", "already exceeds", func(p *ExternalSourceDescriptor) { p.ReferencePrefix = "https://example.com/vendor/repository/deeper" }},
		{"immutable anchor", "whitespace-free", func(p *ExternalSourceDescriptor) { p.ImmutableReferencePattern = "not-anchored" }},
		{"immutable size", "within 4096", func(p *ExternalSourceDescriptor) { p.ImmutableReferencePattern = "^" + strings.Repeat("a", 4095) + "$" }},
		{"immutable syntax", "error parsing regexp", func(p *ExternalSourceDescriptor) { p.ImmutableReferencePattern = "^([$" }},
		{"immutable capture", "immutable_ref", func(p *ExternalSourceDescriptor) {
			p.ImmutableReferencePattern = `^https://example\\.com/(?P<other>[a-z]+)$`
		}},
		{"upstream policy", "invalid for upstream_pinned", func(p *ExternalSourceDescriptor) { p.UpstreamIdentityPolicy = "invented" }},
		{"source repo locator", "code_graph_coordinate", func(p *ExternalSourceDescriptor) {
			p.AllowedObjectClasses = []string{"code_symbol_ref"}
			p.LocatorKinds = map[string]string{"code_symbol_ref": "resource_root"}
		}},
		{"api locator", "cannot prove", func(p *ExternalSourceDescriptor) {
			p.AllowedObjectClasses = []string{"api_symbol"}
			p.LocatorKinds = map[string]string{"api_symbol": "resource_root"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := cloneExternalPolicyForBounds(repository)
			test.mutate(&policy)
			if err := policy.validate(1); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validation error=%v, want substring %q", err, test.want)
			}
		})
	}

	httpPinned := cloneExternalPolicyForBounds(tlsTestExternalPolicy("https://example.com/docs"))
	httpPinned.VersionCoordinateMode = externalVersionModeUpstreamPinned
	httpPinned.UpstreamIdentityPolicy = upstreamIdentityHTTPResponseWithContentDigest
	if err := httpPinned.validate(0); err != nil {
		t.Fatalf("canonical HTTP response identity: %v", err)
	}
	httpPinned.ImmutableReferencePattern = "^forbidden$"
	if err := httpPinned.validate(0); err == nil || !strings.Contains(err.Error(), "must not declare") {
		t.Fatalf("HTTP response immutable pattern error=%v", err)
	}
}

func TestExternalSourceDescriptorStrictJSONPolicyPresenceAndTrailingData(t *testing.T) {
	raw, err := json.Marshal(tlsTestExternalPolicy("https://example.com/docs"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded ExternalSourceDescriptor
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("canonical decode: %v", err)
	}
	missing := strings.Replace(string(raw), `,"allow_query":false`, "", 1)
	if err := json.Unmarshal([]byte(missing), &decoded); err == nil || !strings.Contains(err.Error(), "required policy field") {
		t.Fatalf("missing explicit boolean error=%v", err)
	}
	if err := decoded.UnmarshalJSON(append(raw, []byte(` {}`)...)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("multiple values error=%v", err)
	}
	if err := decoded.UnmarshalJSON(append(raw, byte('{'))); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("invalid trailing data error=%v", err)
	}
}
