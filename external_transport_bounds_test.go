package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestCanonicalExternalTransportMetadataBounds(t *testing.T) {
	t.Run("media type", func(t *testing.T) {
		for name, value := range map[string]string{
			"empty":            "",
			"invalid":          "text/plain; charset=\"unterminated",
			"media too long":   strings.Repeat("a", 257),
			"charset too long": "text/plain; charset=" + strings.Repeat("a", 65),
		} {
			t.Run(name, func(t *testing.T) {
				mediaType, charset, err := canonicalExternalResponseMediaType(value)
				if name == "empty" {
					if err != nil || mediaType != "" || charset != "" {
						t.Fatalf("empty metadata = %q/%q, %v", mediaType, charset, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("invalid media type %q was accepted", value)
				}
			})
		}
	})

	t.Run("content coding", func(t *testing.T) {
		cases := []struct {
			name   string
			values []string
			want   string
			bad    bool
		}{
			{name: "absent", want: "identity"},
			{name: "blank", values: []string{"  "}, want: "identity"},
			{name: "identity", values: []string{"IDENTITY"}, want: "identity"},
			{name: "gzip", values: []string{"GZip"}, want: "gzip"},
			{name: "multiple fields", values: []string{"gzip", "identity"}, bad: true},
			{name: "chain", values: []string{"gzip, identity"}, bad: true},
			{name: "unknown", values: []string{"br"}, bad: true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := canonicalExternalContentCoding(tc.values)
				if tc.bad {
					if err == nil {
						t.Fatalf("coding %#v was accepted as %q", tc.values, got)
					}
					return
				}
				if err != nil || got != tc.want {
					t.Fatalf("coding %#v = %q, %v; want %q", tc.values, got, err, tc.want)
				}
			})
		}
	})
}

func TestHTTPUpstreamVersionEvidenceBounds(t *testing.T) {
	digest := strings.Repeat("a", 64)

	t.Run("no evidence", func(t *testing.T) {
		kind, evidence, token, err := deriveHTTPUpstreamVersionEvidence(http.Header{}, digest)
		if err != nil || kind != "" || evidence != "" || token != "" {
			t.Fatalf("empty headers = %q/%q/%q, %v", kind, evidence, token, err)
		}
	})

	t.Run("malformed single evidence", func(t *testing.T) {
		for name, values := range map[string][]string{
			"multiple": {"one", "two"},
			"blank":    {"  "},
			"control":  {"release\x7f"},
		} {
			t.Run(name, func(t *testing.T) {
				if _, err := canonicalSingleHTTPVersionEvidence("etag", values); err == nil {
					t.Fatalf("evidence %#v was accepted", values)
				}
			})
		}
	})

	t.Run("untrusted token material", func(t *testing.T) {
		cases := []struct {
			name, kind, evidence, digest string
		}{
			{name: "kind", kind: "HTTP ETag", evidence: "release", digest: digest},
			{name: "evidence whitespace", kind: "http_etag", evidence: " release ", digest: digest},
			{name: "evidence control", kind: "http_etag", evidence: "release\n", digest: digest},
			{name: "digest", kind: "http_etag", evidence: "release", digest: "short"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := trustedUpstreamVersionToken(tc.kind, tc.evidence, tc.digest); err == nil {
					t.Fatal("untrusted version material was accepted")
				}
			})
		}
	})

	t.Run("non-HTTP reference is unchanged", func(t *testing.T) {
		got, err := externalResourceReference("gs://bucket/object", ExternalSourceDescriptor{ReferenceKind: "gcs_uri_prefix"})
		if err != nil || got != "gs://bucket/object" {
			t.Fatalf("reference = %q, %v", got, err)
		}
	})
}
