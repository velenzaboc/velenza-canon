package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
)

// TestTopologicalOrder verifies that spec_graph_import orders submissions so
// that any submission whose payload references another submission's stable_id
// appears AFTER the referent in the result.
func TestTopologicalOrder(t *testing.T) {
	subs := []ArtifactSubmission{
		{StableID: "c", Payload: map[string]interface{}{"links_to": map[string]interface{}{"$ref": "b"}}},
		{StableID: "b", Payload: map[string]interface{}{"links_to": map[string]interface{}{"$ref": "a"}}},
		{StableID: "a", Payload: map[string]interface{}{"value": 1}},
	}
	ordered, err := topologicallyOrder(subs)
	if err != nil {
		t.Fatalf("topologicallyOrder returned %v", err)
	}
	if len(ordered) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(ordered))
	}
	positions := map[string]int{}
	for i, s := range ordered {
		positions[s.StableID] = i
	}
	if positions["a"] > positions["b"] {
		t.Errorf("a (pos %d) must come before b (pos %d)", positions["a"], positions["b"])
	}
	if positions["b"] > positions["c"] {
		t.Errorf("b (pos %d) must come before c (pos %d)", positions["b"], positions["c"])
	}
}

func validExternalSourceConfig() SpecGraphConfig {
	return SpecGraphConfig{
		Mode:                  ModeExperimentalBootstrap,
		ExperimentalAdmitter:  "TEST",
		DefaultOrganizationID: "org-test",
		ListenAddress:         "127.0.0.1:8765",
		GoogleCredentials:     experimentalGoogleCredentials(),
		Embedding: &EmbeddingConfig{
			Provider: "vertex_ai", Project: "project", Location: "us-central1",
			Model: "gemini-embedding-001", Dimensions: externalReferenceEmbeddingDimensions,
			MaxTextBytes: 32768,
		},
		ExternalSources: []ExternalSourceDescriptor{{
			ID:                      "quickbooks_online_official_docs",
			SourceArtifactClass:     "official_vendor_documentation",
			ReferenceKind:           "https_url_prefix",
			ReferencePrefix:         "https://developer.intuit.com/app/developer/qbo/docs",
			ContentHashAlgorithm:    "sha256",
			VersionCoordinateMode:   externalVersionModeContentDigest,
			VersionStableNamePrefix: "quickbooks_online_",
			AllowedObjectClasses:    []string{"reference_page"},
			LocatorKinds:            map[string]string{"reference_page": "html_id_or_name"},
			FreshnessWindowSeconds:  604800,
			LicenseEvidenceRequired: true,
			LicenseEvidenceBinding:  licenseEvidenceBindingCoordinate,
			RetrievalPermissionEvidenceCoordinates: []string{
				quickBooksTestRetrievalPermissionEvidence,
			},
			AllowFragment: true,
		}},
		NodeKinds: []NodeKindDescriptor{NewNodeKindDescriptor(map[string]interface{}{
			"name":                     "reference_page",
			"substrate_id":             "ood_graph",
			"artifact_type":            "reference_page",
			"version_scope":            "page_digest_scope",
			"projection_role":          "retrievable_external_reference_vertex_for_cross_doc_traversal",
			"source_authority":         bootstrapSourceAuthority,
			"source_coordinate_policy": sourceCoordinatePolicyExternalReferenceRequired,
		})},
		EdgeLabels: externalReferenceTestEdgeDescriptors(),
	}
}

func experimentalGoogleCredentials() gcpauth.Selector {
	return gcpauth.Selector{
		CredentialsSource:   gcpauth.CredentialsSourceApplicationDefault,
		CredentialsProfile:  gcpauth.CredentialsProfileImpersonatedServiceAccount,
		CredentialsIdentity: "spec-graph-local@example-gcp-project.iam.gserviceaccount.com",
	}
}

func productionGoogleCredentials() gcpauth.Selector {
	return gcpauth.Selector{
		CredentialsSource:   gcpauth.CredentialsSourceApplicationDefault,
		CredentialsProfile:  gcpauth.CredentialsProfileAttachedServiceAccount,
		CredentialsIdentity: "spec-graph-runtime@example-project.iam.gserviceaccount.com",
	}
}

func externalReferenceTestEdgeDescriptors() []EdgeLabelDescriptor {
	names := make([]string, 0, len(externalReferenceEdgeContracts))
	for name := range externalReferenceEdgeContracts {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]EdgeLabelDescriptor, 0, len(names))
	for _, name := range names {
		contract := externalReferenceEdgeContracts[name]
		sources := make([]interface{}, len(contract.SourceKinds))
		for i, value := range contract.SourceKinds {
			sources[i] = value
		}
		targets := make([]interface{}, len(contract.TargetKinds))
		for i, value := range contract.TargetKinds {
			targets[i] = value
		}
		out = append(out, NewEdgeLabelDescriptor(map[string]interface{}{
			"name":         name,
			"edge_family":  contract.EdgeFamily,
			"source_kinds": sources,
			"target_kinds": targets,
		}))
	}
	return out
}

func TestExternalSourceConfigValidate(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		if err := validExternalSourceConfig().Validate(); err != nil {
			t.Fatalf("valid external source config: %v", err)
		}
	})
	t.Run("external_class_can_remain_dormant_without_source_authority", func(t *testing.T) {
		cfg := validExternalSourceConfig()
		cfg.ExternalSources = nil
		if err := cfg.Validate(); err != nil {
			t.Fatalf("dormant protocol class should not manufacture a source binding: %v", err)
		}
	})
	t.Run("dormant_external_label_still_has_exact_protocol_contract", func(t *testing.T) {
		cfg := validExternalSourceConfig()
		cfg.ExternalSources = nil
		for i := range cfg.EdgeLabels {
			if cfg.EdgeLabels[i].Name() == "documents" {
				cfg.EdgeLabels[i].raw["source_kinds"] = []interface{}{"api_symbol"}
			}
		}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "want exact OOD protocol set") {
			t.Fatalf("dormant documents label widening error=%v, want exact-contract refusal", err)
		}
	})

	cases := []struct {
		name   string
		mutate func(*SpecGraphConfig)
		want   string
	}{
		{"source_registry_class_requires_external_kind", func(c *SpecGraphConfig) {
			c.NodeKinds[0] = NewNodeKindDescriptor(map[string]interface{}{
				"name": "reference_page", "substrate_id": "ood_graph", "artifact_type": "reference_page", "version_scope": "page_digest_scope", "projection_role": "retrievable_external_reference_vertex_for_cross_doc_traversal",
			})
		}, "source_coordinate_policy"},
		{"external_kind_requires_uuid_authority", func(c *SpecGraphConfig) {
			c.NodeKinds[0] = NewNodeKindDescriptor(map[string]interface{}{
				"name": "reference_page", "substrate_id": "ood_graph", "artifact_type": "reference_page", "version_scope": "page_digest_scope", "projection_role": "retrievable_external_reference_vertex_for_cross_doc_traversal",
				"source_coordinate_policy": sourceCoordinatePolicyExternalReferenceRequired,
			})
		}, "source_authority"},
		{"external_kind_requires_3072_embedding", func(c *SpecGraphConfig) { c.Embedding.Dimensions = 768 }, "embedding.dimensions=3072"},
		{"freshness_window_must_not_overflow_duration", func(c *SpecGraphConfig) {
			c.ExternalSources[0].FreshnessWindowSeconds = maxExternalFreshnessWindowSeconds + 1
		}, "exceeds time.Duration without overflow"},
		{"stable_name_prefix_requires_segment_boundary", func(c *SpecGraphConfig) { c.ExternalSources[0].VersionStableNamePrefix = "quickbooks" }, "ending in underscore"},
		{"registry_prefix_requires_canonical_url", func(c *SpecGraphConfig) {
			c.ExternalSources[0].ReferencePrefix = "https://Developer.Intuit.com/app/developer/qbo/docs/"
		}, "URL host must be lowercase"},
		{"source_hash_algorithm_required", func(c *SpecGraphConfig) { c.ExternalSources[0].ContentHashAlgorithm = "" }, "content_hash_algorithm"},
		{"source_hash_algorithm_closed", func(c *SpecGraphConfig) { c.ExternalSources[0].ContentHashAlgorithm = "md5" }, "want sha256"},
		{"version_coordinate_mode_required", func(c *SpecGraphConfig) { c.ExternalSources[0].VersionCoordinateMode = "" }, "version_coordinate_mode"},
		{"version_coordinate_mode_closed", func(c *SpecGraphConfig) { c.ExternalSources[0].VersionCoordinateMode = "caller_selected" }, "content_digest | upstream_pinned"},
		{"retrieval_permission_binding_closed", func(c *SpecGraphConfig) { c.ExternalSources[0].LicenseEvidenceBinding = "provider_default" }, "license_evidence_binding"},
		{"coordinate_binding_requires_descriptor_evidence", func(c *SpecGraphConfig) {
			c.ExternalSources[0].RetrievalPermissionEvidenceCoordinates = nil
		}, "nonempty retrieval_permission_evidence_coordinates"},
		{"permission_evidence_coordinates_must_be_unique", func(c *SpecGraphConfig) {
			c.ExternalSources[0].RetrievalPermissionEvidenceCoordinates = append(c.ExternalSources[0].RetrievalPermissionEvidenceCoordinates, quickBooksTestRetrievalPermissionEvidence)
		}, "contains duplicate"},
		{"permission_evidence_coordinates_must_be_canonical_https", func(c *SpecGraphConfig) {
			c.ExternalSources[0].RetrievalPermissionEvidenceCoordinates = []string{"http://example.com/policy"}
		}, "absolute https URL"},
		{"same_repository_binding_forbids_coordinate_allowlist", func(c *SpecGraphConfig) {
			c.ExternalSources[0].LicenseEvidenceBinding = licenseEvidenceBindingSameRepositoryFile
			c.ExternalSources[0].RepositoryPathSegments = 4
		}, "empty retrieval_permission_evidence_coordinates"},
		{"not_required_binding_forbids_coordinate_allowlist", func(c *SpecGraphConfig) {
			c.ExternalSources[0].LicenseEvidenceBinding = licenseEvidenceBindingNotRequired
			c.ExternalSources[0].LicenseEvidenceRequired = false
			c.ExternalSources[0].ReferenceKind = "opaque_prefix"
			c.ExternalSources[0].ReferencePrefix = "context7:package"
		}, "empty retrieval-permission policy fields"},
		{"content_digest_forbids_upstream_identity_policy", func(c *SpecGraphConfig) {
			c.ExternalSources[0].UpstreamIdentityPolicy = upstreamIdentityHTTPResponseWithContentDigest
		}, "must not declare upstream identity policy"},
		{"upstream_pinned_requires_identity_policy", func(c *SpecGraphConfig) {
			c.ExternalSources[0].VersionCoordinateMode = externalVersionModeUpstreamPinned
		}, "upstream_identity_policy"},
		{"immutable_reference_policy_must_be_anchored", func(c *SpecGraphConfig) {
			c.ExternalSources[0].VersionCoordinateMode = externalVersionModeUpstreamPinned
			c.ExternalSources[0].UpstreamIdentityPolicy = upstreamIdentityImmutableRefWithContentDigest
			c.ExternalSources[0].ImmutableReferencePattern = `https://docs\.example/commit/[0-9a-f]{40}`
		}, "^...$"},
		{"forbidden_source_class_rejected", func(c *SpecGraphConfig) { c.ExternalSources[0].SourceArtifactClass = "unofficial_blog" }, "not an allowed OOD external source class"},
		{"unrecognized_source_class_rejected", func(c *SpecGraphConfig) { c.ExternalSources[0].SourceArtifactClass = "partner_documentation" }, "not an allowed OOD external source class"},
		{"duplicate_registry_id_rejected", func(c *SpecGraphConfig) { c.ExternalSources = append(c.ExternalSources, c.ExternalSources[0]) }, "duplicated"},
		{"overlapping_registry_entries_rejected", func(c *SpecGraphConfig) {
			shadow := c.ExternalSources[0]
			shadow.ID = "quickbooks_online_official_docs_shadow"
			c.ExternalSources = append(c.ExternalSources, shadow)
		}, "overlap"},
		{"cross_source_class_overlap_rejected", func(c *SpecGraphConfig) {
			shadow := c.ExternalSources[0]
			shadow.ID = "quickbooks_online_official_docs_cross_class_shadow"
			shadow.SourceArtifactClass = "official_release_notes"
			c.ExternalSources = append(c.ExternalSources, shadow)
		}, "overlap"},
		{"external_edge_label_required", func(c *SpecGraphConfig) { c.EdgeLabels = c.EdgeLabels[1:] }, "requires edge_label"},
		{"external_edge_family_closed", func(c *SpecGraphConfig) {
			for i := range c.EdgeLabels {
				if c.EdgeLabels[i].Name() == "official_source_for" {
					c.EdgeLabels[i].raw["edge_family"] = "reference"
				}
			}
		}, "want OOD protocol family"},
		{"external_edge_direction_closed", func(c *SpecGraphConfig) {
			for i := range c.EdgeLabels {
				if c.EdgeLabels[i].Name() == "defines_external_symbol" {
					c.EdgeLabels[i].raw["source_kinds"] = []interface{}{"api_symbol"}
				}
			}
		}, "want exact OOD protocol set"},
		{"external_edge_cannot_be_diagnostic_only", func(c *SpecGraphConfig) {
			for i := range c.EdgeLabels {
				if c.EdgeLabels[i].Name() == "technology_relevant_to" {
					c.EdgeLabels[i].raw["diagnostic_only"] = true
				}
			}
		}, "must be authoritative"},
		{"external_edge_boolean_fields_are_typed", func(c *SpecGraphConfig) {
			for i := range c.EdgeLabels {
				if c.EdgeLabels[i].Name() == "technology_relevant_to" {
					c.EdgeLabels[i].raw["diagnostic_only"] = "false"
				}
			}
		}, "diagnostic_only must be a boolean"},
		{"non_external_edge_cannot_wildcard_source_classes", func(c *SpecGraphConfig) {
			c.EdgeLabels = append(c.EdgeLabels, NewEdgeLabelDescriptor(map[string]interface{}{
				"name": "depends_on", "edge_family": "dependency",
				"target_kinds": []interface{}{"section"},
			}))
		}, "source_kinds must be a non-empty closed endpoint set"},
		{"non_external_edge_cannot_admit_external_class", func(c *SpecGraphConfig) {
			c.EdgeLabels = append(c.EdgeLabels, NewEdgeLabelDescriptor(map[string]interface{}{
				"name": "depends_on", "edge_family": "dependency",
				"source_kinds": []interface{}{"api_symbol"}, "target_kinds": []interface{}{"section"},
			}))
		}, "outside the closed OOD external-reference edge-label set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validExternalSourceConfig()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestExternalSourceDescriptorJSONRejectsUnknownAndDuplicatePolicyKeys(t *testing.T) {
	valid := `{
		"id":"quickbooks_online_docs",
		"source_artifact_class":"official_vendor_documentation",
		"reference_kind":"https_url_prefix",
		"reference_prefix":"https://developer.intuit.com/app/developer/qbo/docs",
		"content_hash_algorithm":"sha256",
		"version_coordinate_mode":"content_digest",
		"version_stable_name_prefix":"quickbooks_online_docs_",
		"allowed_object_classes":["reference_page"],
		"freshness_window_seconds":604800,
		"license_evidence_required":true,
		"license_evidence_binding":"coordinate",
		"retrieval_permission_evidence_coordinates":["https://example.com/retrieval-permission"],
		"allow_query":false,
		"allow_fragment":true
	}`
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "version mode must be explicit",
			raw:  strings.Replace(valid, `"version_coordinate_mode":"content_digest",`, ``, 1),
			want: "version_coordinate_mode",
		},
		{
			name: "misspelled license gate",
			raw:  strings.Replace(valid, `"license_evidence_required":true`, `"license_evidence_requried":true`, 1),
			want: "unknown field",
		},
		{
			name: "duplicate authority class",
			raw:  strings.Replace(valid, `"source_artifact_class":"official_vendor_documentation",`, `"source_artifact_class":"official_vendor_documentation","source_artifact_class":"official_release_notes",`, 1),
			want: "duplicate field",
		},
		{
			name: "license policy must be explicit",
			raw:  strings.Replace(valid, `"license_evidence_required":true,`, ``, 1),
			want: "license_evidence_required",
		},
		{
			name: "license evidence binding must be explicit",
			raw:  strings.Replace(valid, `"license_evidence_binding":"coordinate",`, ``, 1),
			want: "license_evidence_binding",
		},
		{
			name: "query policy must be explicit",
			raw:  strings.Replace(valid, `"allow_query":false,`, ``, 1),
			want: "allow_query",
		},
		{
			name: "fragment policy must be explicit",
			raw:  strings.Replace(valid, `"allow_query":false,`+"\n\t\t"+`"allow_fragment":true`, `"allow_query":false`, 1),
			want: "allow_fragment",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var descriptor ExternalSourceDescriptor
			err := json.Unmarshal([]byte(tc.raw), &descriptor)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("json.Unmarshal error=%v, want %q refusal", err, tc.want)
			}
		})
	}

	var roundTrip ExternalSourceDescriptor
	if err := json.Unmarshal([]byte(valid), &roundTrip); err != nil {
		t.Fatalf("explicit policy booleans must decode: %v", err)
	}
	rendered, err := json.Marshal(roundTrip)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	for _, field := range []string{`"version_coordinate_mode":"content_digest"`, `"license_evidence_required":true`, `"license_evidence_binding":"coordinate"`, `"retrieval_permission_evidence_coordinates":["https://example.com/retrieval-permission"]`, `"allow_query":false`, `"allow_fragment":true`} {
		if !strings.Contains(string(rendered), field) {
			t.Errorf("round-trip descriptor %s omitted explicit policy %s", rendered, field)
		}
	}
}

func TestExternalSourceClassRegistryIsExactlyProtocolSet(t *testing.T) {
	allowed := []string{
		"official_vendor_documentation",
		"official_product_documentation",
		"official_source_repository",
		"official_release_notes",
		"context7_documentation_package",
		"velenza_owned_documentation",
	}
	for _, sourceClass := range allowed {
		t.Run(sourceClass, func(t *testing.T) {
			descriptor := validExternalSourceConfig().ExternalSources[0]
			descriptor.SourceArtifactClass = sourceClass
			if err := descriptor.validate(0); err != nil {
				t.Fatalf("protocol source class rejected: %v", err)
			}
		})
	}
	if len(externalSourceArtifactClasses) != len(allowed) {
		t.Fatalf("external source class registry size=%d, want exact six-member protocol set", len(externalSourceArtifactClasses))
	}
}

func TestInvalidExternalSourceClassFailsConfigBoot(t *testing.T) {
	cfg := validExternalSourceConfig()
	cfg.ExternalSources[0].SourceArtifactClass = "unofficial_blog"
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "spec-graph.config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPEC_GRAPH_CONFIG", path)
	if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), "not an allowed OOD external source class") {
		t.Fatalf("loadConfig error=%v, want boot refusal", err)
	}
}

func TestAutomatedHTTPSRegistryCannotDisableRetrievalPermissionEvidence(t *testing.T) {
	docs := validExternalSourceConfig().ExternalSources[0]
	docs.ID = "official_product_docs"
	docs.ReferencePrefix = "https://docs.example/product"
	docs.VersionStableNamePrefix = "official_product_docs_"
	docs.LicenseEvidenceRequired = false
	repo := ExternalSourceDescriptor{
		ID: "official_source_repository", SourceArtifactClass: "official_source_repository",
		ReferenceKind: "https_url_prefix", ReferencePrefix: "https://code.example/vendor",
		ContentHashAlgorithm: "sha256", VersionCoordinateMode: externalVersionModeUpstreamPinned,
		VersionStableNamePrefix: "official_source_", AllowedObjectClasses: []string{"source_repo"},
		LocatorKinds: map[string]string{"source_repo": "resource_root"}, FreshnessWindowSeconds: 604800,
		LicenseEvidenceRequired: false, LicenseEvidenceBinding: licenseEvidenceBindingSameRepositoryFile,
		RepositoryPathSegments: 2, UpstreamIdentityPolicy: upstreamIdentityImmutableRefWithContentDigest,
		ImmutableReferencePattern: `^https://code\.example/vendor/[A-Za-z0-9._-]+/commit/[0-9a-f]{40}$`, AllowFragment: true,
	}
	for name, descriptor := range map[string]ExternalSourceDescriptor{"documentation": docs, "repository": repo} {
		t.Run(name, func(t *testing.T) {
			if err := descriptor.validate(0); err == nil || !strings.Contains(err.Error(), "license_evidence_required must be true") {
				t.Fatalf("descriptor validation error=%v, want generic automated-HTTPS evidence floor", err)
			}
		})
	}
}

func TestSameRepositoryDescriptorRequiresMatchedImmutableEvidencePatterns(t *testing.T) {
	valid, _ := sameRepositoryTestExternalPolicy()
	if err := valid.validate(0); err != nil {
		t.Fatalf("valid same-repository descriptor: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ExternalSourceDescriptor)
		want   string
	}{
		{name: "source capture missing", mutate: func(d *ExternalSourceDescriptor) {
			d.ImmutableReferencePattern = `^https://example\.com/vendor/repository/commit/[0-9a-f]{40}$`
		}, want: "exactly one named immutable_ref capture"},
		{name: "evidence capture missing", mutate: func(d *ExternalSourceDescriptor) {
			d.SameRepositoryPermissionEvidencePattern = `^https://example\.com/vendor/repository/blob/[0-9a-f]{40}/LICENSE$`
		}, want: "exactly one named immutable_ref capture"},
		{name: "evidence pattern missing", mutate: func(d *ExternalSourceDescriptor) {
			d.SameRepositoryPermissionEvidencePattern = ""
		}, want: "same_repository_permission_evidence_pattern"},
		{name: "coordinate allowlist incompatible", mutate: func(d *ExternalSourceDescriptor) {
			d.RetrievalPermissionEvidenceCoordinates = []string{"https://example.com/policy"}
		}, want: "empty retrieval_permission_evidence_coordinates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor := valid
			tc.mutate(&descriptor)
			if err := descriptor.validate(0); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("descriptor validation error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestCommittedExampleConfigsValidate(t *testing.T) {
	for _, path := range []string{"spec-graph.config.bootstrap.example.json", "spec-graph.config.production.example.json"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var cfg SpecGraphConfig
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatalf("decode example: %v", err)
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("example is not boot-valid: %v", err)
			}
			cases := []struct {
				kind, class, reference, stableName, wantPolicy string
			}{
				{"reference_page", "official_product_documentation", "https://docs.cloud.google.com/spanner/docs/ml-tutorial-embeddings", "google_cloud_spanner_docs_ml_embeddings", "google_cloud_spanner_docs_canonical"},
				{"reference_page", "official_product_documentation", "https://docs.cloud.google.com/spanner/docs/vector-search-overview", "google_cloud_spanner_docs_vector_search", "google_cloud_spanner_docs_canonical"},
				{"reference_page", "official_product_documentation", "https://docs.cloud.google.com/spanner/docs/find-approximate-nearest-neighbors", "google_cloud_spanner_docs_ann", "google_cloud_spanner_docs_canonical"},
				{"reference_page", "official_product_documentation", "https://docs.cloud.google.com/spanner/docs/change-streams/manage", "google_cloud_spanner_docs_change_stream_management", "google_cloud_spanner_docs_canonical"},
				{"reference_page", "official_product_documentation", "https://docs.cloud.google.com/spanner/docs/concurrency-control", "google_cloud_spanner_docs_concurrency_control", "google_cloud_spanner_docs_canonical"},
				{"reference_page", "official_product_documentation", "https://docs.cloud.google.com/spanner/docs/transactions", "google_cloud_spanner_docs_transactions", "google_cloud_spanner_docs_canonical"},
				{"reference_page", "official_product_documentation", "https://docs.cloud.google.com/spanner/docs/generated-column/how-to", "google_cloud_spanner_docs_generated_columns", "google_cloud_spanner_docs_canonical"},
				{"reference_page", "official_product_documentation", "https://cloud.google.com/spanner/docs/change-streams/details", "google_cloud_spanner_docs_change_streams", "google_cloud_spanner_docs_legacy_host"},
				{"release_note", "official_release_notes", "https://docs.cloud.google.com/spanner/docs/release-notes", "google_cloud_spanner_release_2026_08", "google_cloud_spanner_release_notes_canonical"},
			}
			if strings.Contains(string(data), "developer.intuit.com/app/developer/qbo/docs/legal-agreements") {
				t.Fatal("example treats the Intuit terms index as automated-retrieval permission")
			}
			qboDocs := ArtifactSourceCoordinate{SourceArtifactClass: "official_vendor_documentation", SourceStableReference: "https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice"}
			if _, err := resolveExternalSourcePolicy(cfg, "reference_page", "quickbooks_online_docs_invoice", qboDocs); err == nil {
				t.Fatal("QuickBooks documentation retrieval is enabled without an applicable admitted permission receipt")
			}
			for _, reference := range []string{
				"https://github.com/intuit/QuickBooks-V3-Java-SDK/commit/0123456789abcdef0123456789abcdef01234567",
				"https://github.com/intuit/unrelated-product/commit/0123456789abcdef0123456789abcdef01234567",
			} {
				coord := ArtifactSourceCoordinate{SourceArtifactClass: "official_source_repository", SourceStableReference: reference}
				if _, err := resolveExternalSourcePolicy(cfg, "source_repo", "quickbooks_online_source_unadmitted", coord); err == nil {
					t.Fatalf("unsettled product-to-repository authority matched production example: %s", reference)
				}
			}
			for _, tc := range cases {
				coord := ArtifactSourceCoordinate{
					SourceArtifactClass:   tc.class,
					SourceStableReference: tc.reference,
					VersionCoordinate:     "source:" + bootstrapSourceAuthority + ":" + tc.stableName + "@sha256_" + strings.Repeat("a", 64),
				}
				policy, err := resolveExternalSourcePolicy(cfg, tc.kind, tc.stableName, coord)
				if err != nil || policy.ID != tc.wantPolicy {
					t.Errorf("resolve %s example policy=%q err=%v, want %q", tc.stableName, policy.ID, err, tc.wantPolicy)
				}
			}
			mismatched := ArtifactSourceCoordinate{
				SourceArtifactClass:   "official_vendor_documentation",
				SourceStableReference: "https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice",
				VersionCoordinate:     "source:" + bootstrapSourceAuthority + ":quickbooks_online_article_invoice@sha256_" + strings.Repeat("a", 64),
			}
			if _, err := resolveExternalSourcePolicy(cfg, "reference_page", "quickbooks_online_article_invoice", mismatched); err == nil {
				t.Fatal("human canonical page URL matched static-article identity policy; digest/source-resource boundary is not disjoint")
			}
			// Protocol classes may remain dormant. A production example must not
			// manufacture product/source authority merely to cover every class.
			for _, source := range cfg.ExternalSources {
				if strings.Contains(source.ReferencePrefix, "github.com/intuit") || strings.Contains(source.ID, "quickbooks") {
					t.Fatalf("example contains unsettled QuickBooks repository authority: %+v", source)
				}
			}
		})
	}
}

func TestExternalReceiptSchemaAndMigrationStayAligned(t *testing.T) {
	schema, err := os.ReadFile(filepath.Join("bootstrap", "schema_v2.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(schema), "source_verification_receipt JSON") {
		t.Fatal("fresh schema lacks staging_concepts.source_verification_receipt")
	}
	migration, err := os.ReadFile(filepath.Join("bootstrap", "migrations", "002_staging_external_verification_receipt.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migration), "ALTER TABLE staging_concepts ADD COLUMN source_verification_receipt JSON") {
		t.Fatal("existing-database migration does not add source_verification_receipt")
	}
}

func TestLinkSuccessorSourceSetPreservesExternalOccurrenceReceipts(t *testing.T) {
	receipt := testExternalVerificationReceipt(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	coordinate := SourceCoordinate{
		OrganizationID: "org-test", SourceAuthorityID: receipt.SourceAuthorityID,
		SourceArtifactClass: "official_vendor_documentation", SourceRefKind: "coordinate",
		SourceStableReference: receipt.VerifiedSourceStableReference,
		VersionCoordinate:     receipt.FinalVersionCoordinate,
		SectionPath:           SectionPathRoot,
		SourceContentHash:     receipt.SHA256,
	}
	// handleLink and handleImport both call this exact publisher helper after
	// complete carry-forward. Protect that common seam so a link successor
	// cannot silently rebuild a body-free source_set without its occurrence
	// receipt.
	set, err := buildCompletePublisherSourceSet("org-test", []SourceCoordinate{coordinate}, MaterializationBatch{
		ExternalVerificationReceipts: []*stagedExternalVerificationReceipt{receipt},
	})
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ExternalVerificationReceiptsFromStoredSet(set)
	if err != nil || len(roundTrip) != 1 || roundTrip[0].RetrievedAt != receipt.RetrievedAt {
		t.Fatalf("link successor receipt round-trip=%+v err=%v", roundTrip, err)
	}
}

type receiptPreservingLinkAdapter struct {
	*recordingAdapter
	prepared MaterializationBatch
}

func (a *receiptPreservingLinkAdapter) PrepareCompleteMaterialization(_ context.Context, delta MaterializationBatch, _ []SourceCoordinate, _ MaterializationValidationAuthority) (MaterializationBatch, []SourceCoordinate, error) {
	batch := a.prepared
	batch.Run = delta.Run
	batch.Snapshot = delta.Snapshot
	batch.Objects = append([]GraphObject(nil), a.prepared.Objects...)
	batch.Symbols = append([]GraphSymbol(nil), a.prepared.Symbols...)
	batch.Edges = append([]GraphEdge(nil), a.prepared.Edges...)
	batch.ExternalVerificationReceipts = append([]*stagedExternalVerificationReceipt(nil), a.prepared.ExternalVerificationReceipts...)
	for i := range batch.Objects {
		batch.Objects[i].GraphSnapshotID = batch.Snapshot.GraphSnapshotID
		batch.Objects[i].MaterializationRunID = batch.Run.MaterializationRunID
	}
	for i := range batch.Symbols {
		batch.Symbols[i].GraphSnapshotID = batch.Snapshot.GraphSnapshotID
		batch.Symbols[i].MaterializationRunID = batch.Run.MaterializationRunID
	}
	for i := range batch.Edges {
		batch.Edges[i].GraphSnapshotID = batch.Snapshot.GraphSnapshotID
		batch.Edges[i].MaterializationRunID = batch.Run.MaterializationRunID
	}
	coords, err := SourceCoordinatesFromRows(batch.Objects, batch.Symbols, batch.Edges)
	return batch, coords, err
}

func TestHandleLinkPreservesHistoricallyValidExternalReceiptWithoutRefetch(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	cfg := validExternalSourceConfig()
	cfg.NodeKinds[0] = NewNodeKindDescriptor(map[string]interface{}{
		"name": "reference_page", "substrate_id": "fake", "artifact_type": "reference_page",
		"version_scope": "page_digest_scope", "projection_role": "retrievable_external_reference_vertex_for_cross_doc_traversal",
		"source_authority": bootstrapSourceAuthority, "source_coordinate_policy": sourceCoordinatePolicyExternalReferenceRequired,
	})
	cfg.NodeKinds = append(cfg.NodeKinds, NewNodeKindDescriptor(map[string]interface{}{
		"name": "section", "substrate_id": "fake", "artifact_type": "section",
		"version_scope": "stable_id_preserved", "projection_role": "subdocument_vertex_for_projection_and_closure",
		"source_authority": bootstrapSourceAuthority,
	}))

	policy := cfg.ExternalSources[0]
	digest := strings.Repeat("a", 64)
	stableReference := policy.ReferencePrefix + "/invoice#anchor=invoice"
	externalCoordinate := ArtifactSourceCoordinate{
		SourceAuthorityID: bootstrapSourceAuthority, SourceArtifactClass: policy.SourceArtifactClass,
		SourceRefKind: "coordinate", SourceStableReference: stableReference, SectionPath: SectionPathRoot,
		SourceContentHash: digest, SourceContentHashOwner: bootstrapSourceAuthority,
		LicenseEvidence: quickBooksTestRetrievalPermissionEvidence,
	}
	canonicalName, err := canonicalExternalLocatorName("reference_page", externalCoordinate, policy, "invoice")
	if err != nil {
		t.Fatal(err)
	}
	externalCoordinate.VersionCoordinate = VersionCoordinate{
		Kind: VersionSourceNamed, SourceAuthorityID: bootstrapSourceAuthority,
		StableName: canonicalName, SourceVersionToken: "sha256_" + digest,
	}.String()
	externalAddress := GraphAddress{
		ObjectClass: "reference_page", SourceAuthorityID: externalCoordinate.SourceAuthorityID,
		SourceRefKind: externalCoordinate.SourceRefKind, SourceRef: externalCoordinate.SourceStableReference,
		VersionCoordinate: externalCoordinate.VersionCoordinate, SectionPath: externalCoordinate.SectionPath,
	}.String()
	externalObject := GraphObject{
		OrganizationID: "org-test", GraphObjectID: uuid.NewSHA1(oodGraphIDNamespace, []byte(fmt.Sprintf("object|%s|%s|%s|%s|%s|%s|%s", "org-test", "reference_page", externalCoordinate.SourceAuthorityID, externalCoordinate.SourceRefKind, externalCoordinate.SourceStableReference, externalCoordinate.VersionCoordinate, externalCoordinate.SectionPath))).String(),
		ObjectClass: "reference_page", SourceAuthorityID: externalCoordinate.SourceAuthorityID,
		SourceArtifactClass: externalCoordinate.SourceArtifactClass, SourceRefKind: externalCoordinate.SourceRefKind,
		SourceStableReference: externalCoordinate.SourceStableReference, VersionCoordinate: externalCoordinate.VersionCoordinate,
		SectionPath: externalCoordinate.SectionPath, GraphAddress: externalAddress, SourceContentHash: digest,
		SourceContentHashOwner: bootstrapSourceAuthority, ProjectionRole: "retrievable_external_reference_vertex_for_cross_doc_traversal",
		ValidationState: "valid", Status: "active", VisibilityScope: "organization",
		SearchText:    externalReferenceSearchText("reference_page", externalCoordinate, policy),
		SearchPayload: externalReferenceSearchPayload("reference_page", externalAddress, externalCoordinate, policy),
		Embedding:     make([]float32, externalReferenceEmbeddingDimensions), EmbeddingModel: "gemini-embedding-001",
	}
	ordinaryCoordinate := ArtifactSourceCoordinate{
		SourceAuthorityID: bootstrapSourceAuthority, SourceArtifactClass: "section", SourceRefKind: "name",
		SourceStableReference: "finance_mapping", VersionCoordinate: "unversioned", SectionPath: SectionPathRoot,
	}
	ordinaryAddress := GraphAddress{
		ObjectClass: "section", SourceAuthorityID: ordinaryCoordinate.SourceAuthorityID,
		SourceRefKind: ordinaryCoordinate.SourceRefKind, SourceRef: ordinaryCoordinate.SourceStableReference,
		VersionCoordinate: ordinaryCoordinate.VersionCoordinate, SectionPath: ordinaryCoordinate.SectionPath,
	}.String()
	ordinaryObject := GraphObject{
		OrganizationID: "org-test", GraphObjectID: uuid.NewSHA1(oodGraphIDNamespace, []byte(fmt.Sprintf("object|%s|%s|%s|%s|%s|%s|%s", "org-test", "section", ordinaryCoordinate.SourceAuthorityID, ordinaryCoordinate.SourceRefKind, ordinaryCoordinate.SourceStableReference, ordinaryCoordinate.VersionCoordinate, ordinaryCoordinate.SectionPath))).String(),
		ObjectClass: "section", SourceAuthorityID: ordinaryCoordinate.SourceAuthorityID,
		SourceArtifactClass: "section", SourceRefKind: ordinaryCoordinate.SourceRefKind,
		SourceStableReference: ordinaryCoordinate.SourceStableReference, VersionCoordinate: ordinaryCoordinate.VersionCoordinate,
		SectionPath: ordinaryCoordinate.SectionPath, GraphAddress: ordinaryAddress,
		ProjectionRole: "subdocument_vertex_for_projection_and_closure", ValidationState: "valid", Status: "active", VisibilityScope: "organization",
		SearchText:    graphOwnedObjectSearchText("section", ordinaryAddress, ordinaryCoordinate),
		SearchPayload: graphOwnedObjectSearchPayload("section", ordinaryAddress, ordinaryCoordinate),
		Embedding:     make([]float32, externalReferenceEmbeddingDimensions), EmbeddingModel: "gemini-embedding-001",
	}
	fingerprint, err := externalPolicyFingerprint(policy)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &stagedExternalVerificationReceipt{
		ReceiptVersion: stagedExternalReceiptVersion, CanonicalReference: strings.Split(stableReference, "#")[0],
		VerifiedSourceStableReference: stableReference, RetrievedAt: now.Format(time.RFC3339Nano), ByteLength: 1,
		SHA256: digest, TransportStatus: "success", TransportRawHashAlgorithm: "sha256",
		ContentCoding: "identity", TransportResponseMetadataDigest: strings.Repeat("c", 64),
		DecodedByteLength: 1, DecodedSHA256: digest, SourceRepresentationMediaType: "text/html",
		SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: externalEvidenceHashProfile,
		LicenseEvidence: quickBooksTestRetrievalPermissionEvidence, SourceRegistryID: policy.ID,
		SourceAuthorityID: bootstrapSourceAuthority, PolicyFingerprint: fingerprint, ObjectClass: "reference_page",
		CanonicalName: canonicalName, LocatorKind: "html_id_or_name", FinalVersionCoordinate: externalCoordinate.VersionCoordinate,
	}
	receipt.Authorization = validTestExternalAuthorization("org-test", "reference_page", policy, externalCoordinate, now, externalBodyCustodyAGFS)
	receipt.Archive = testExternalArchiveReceipt(receipt.Authorization, receipt.DecodedByteLength, receipt.DecodedSHA256)
	recording := &recordingAdapter{fakeAdapter: &fakeAdapter{}}
	adapter := &receiptPreservingLinkAdapter{recordingAdapter: recording, prepared: MaterializationBatch{
		Objects: []GraphObject{externalObject, ordinaryObject}, ExternalVerificationReceipts: []*stagedExternalVerificationReceipt{receipt},
	}}
	env := &Env{
		Config: cfg, Kinds: newKindRegistry(cfg.NodeKinds), Edges: newEdgeRegistry(cfg.EdgeLabels),
		Substrates: &recordingRouter{a: adapter}, Embed: fixedEmbeddingClient{dimensions: externalReferenceEmbeddingDimensions},
		Now: func() time.Time { return now },
	}
	_, err = handleLink(context.Background(), env, linkInput{
		SourceID: externalObject.GraphObjectID, TargetID: ordinaryObject.GraphObjectID, EdgeLabel: "technology_relevant_to",
	})
	if err != nil {
		t.Fatalf("historically valid carried receipt rejected during graph-local link: %v", err)
	}
	if len(recording.batches) != 1 || len(recording.openedRuns) != 1 {
		t.Fatalf("graph-local link did not publish one complete successor: commits=%d opened_runs=%d", len(recording.batches), len(recording.openedRuns))
	}
}

func TestCompleteExternalBootstrapEnvelopeIncludesCarriedRows(t *testing.T) {
	batch := MaterializationBatch{
		Objects: []GraphObject{{ObjectClass: "api_symbol"}},
		Symbols: make([]GraphSymbol, maxCompleteExternalBootstrapVectorRows-1),
	}
	if err := validateCompleteExternalBootstrapPublicationEnvelope(batch); err != nil {
		t.Fatalf("near-cap carried snapshot rejected: %v", err)
	}
	// A one-edge delta looks tiny in isolation, but complete publication must
	// gate the 257-row successor after carry-forward and before run open.
	batch.Edges = append(batch.Edges, GraphEdge{})
	err := validateCompleteExternalBootstrapPublicationEnvelope(batch)
	if !errors.Is(err, ErrOODGraphMaterializationScaleUnrepresentable) {
		t.Fatalf("over-cap complete successor error=%v, want typed refusal", err)
	}
	batch = MaterializationBatch{
		Objects: []GraphObject{{ObjectClass: "api_symbol", SearchText: strings.Repeat("indexed-token ", maxCompleteExternalBootstrapMetadataBytes/8)}},
	}
	if err := validateCompleteExternalBootstrapPublicationEnvelope(batch); !errors.Is(err, ErrOODGraphMaterializationScaleUnrepresentable) {
		t.Fatalf("oversized indexed/tokenized metadata error=%v, want typed refusal", err)
	}
}

func TestExternalBootstrapDeltaEnvelopeCannotExceedCompleteEnvelope(t *testing.T) {
	count := maxExternalObjectsPerBootstrapMaterialization + 1
	submissions := make([]ArtifactSubmission, count)
	policies := make([]ExternalSourceDescriptor, count)
	for i := range policies {
		policies[i].ID = "external"
	}
	err := validateExternalBootstrapPublicationEnvelope(submissions, policies, 0)
	if !errors.Is(err, ErrOODGraphMaterializationScaleUnrepresentable) {
		t.Fatalf("129-object pre-I/O envelope error=%v, want typed refusal", err)
	}

	count = maxExternalObjectsPerBootstrapMaterialization
	submissions = make([]ArtifactSubmission, count)
	policies = make([]ExternalSourceDescriptor, count)
	for i := range policies {
		policies[i].ID = "external"
	}
	if err := validateExternalBootstrapPublicationEnvelope(submissions, policies, 0); err != nil {
		t.Fatalf("exact 256-row pre-I/O envelope rejected: %v", err)
	}
	if err := validateExternalBootstrapPublicationEnvelope(submissions, policies, 1); !errors.Is(err, ErrOODGraphMaterializationScaleUnrepresentable) {
		t.Fatalf("pre-I/O envelope larger than complete ceiling error=%v, want typed refusal", err)
	}
}

func TestCommittedExamplesPreserveOperationalRegistrySemantics(t *testing.T) {
	load := func(path string) SpecGraphConfig {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var cfg SpecGraphConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	bootstrap := load("spec-graph.config.bootstrap.example.json")
	production := load("spec-graph.config.production.example.json")
	if len(bootstrap.NodeKinds) != 29 || len(production.NodeKinds) != 29 || len(bootstrap.EdgeLabels) != 57 || len(production.EdgeLabels) != 57 {
		t.Fatalf("registry narrowing: bootstrap=%d/%d production=%d/%d, want 29 node kinds and 57 edge labels in both", len(bootstrap.NodeKinds), len(bootstrap.EdgeLabels), len(production.NodeKinds), len(production.EdgeLabels))
	}
	semanticDigest := func(cfg SpecGraphConfig) string {
		type nodeRecord struct {
			Name                   string   `json:"name"`
			ArtifactType           string   `json:"artifact_type"`
			VersionScope           string   `json:"version_scope"`
			ProjectionRole         string   `json:"projection_role"`
			SourceAuthority        string   `json:"source_authority"`
			SourceCoordinatePolicy string   `json:"source_coordinate_policy"`
			Projections            []string `json:"projections"`
		}
		type edgeRecord struct {
			Name                string   `json:"name"`
			Direction           string   `json:"direction"`
			CatalogOwner        string   `json:"catalog_owner"`
			Family              string   `json:"family"`
			SourceKinds         []string `json:"source_kinds"`
			TargetKinds         []string `json:"target_kinds"`
			ReciprocalLabel     string   `json:"reciprocal_label"`
			ForbidSelfLoops     bool     `json:"forbid_self_loops"`
			VersionPinned       bool     `json:"version_pinned"`
			DiagnosticOnly      bool     `json:"diagnostic_only"`
			StableReferenceOnly bool     `json:"stable_reference_only"`
		}
		manifest := struct {
			Nodes []nodeRecord `json:"nodes"`
			Edges []edgeRecord `json:"edges"`
		}{}
		for _, d := range cfg.NodeKinds {
			manifest.Nodes = append(manifest.Nodes, nodeRecord{
				Name: d.Name(), ArtifactType: d.ArtifactType(), VersionScope: d.VersionScope(),
				ProjectionRole: d.ProjectionRole(), SourceAuthority: d.SourceAuthority(),
				SourceCoordinatePolicy: d.SourceCoordinatePolicy(), Projections: d.Projections(),
			})
		}
		for _, d := range cfg.EdgeLabels {
			direction, _ := d.Raw()["direction"].(string)
			catalogOwner, _ := d.Raw()["catalog_owner"].(string)
			stableReferenceOnly, _ := d.Raw()["stable_reference_only"].(bool)
			manifest.Edges = append(manifest.Edges, edgeRecord{
				Name: d.Name(), Direction: direction, CatalogOwner: catalogOwner, Family: d.EdgeFamily(),
				SourceKinds: d.SourceKinds(), TargetKinds: d.TargetKinds(), ReciprocalLabel: d.ReciprocalLabel(),
				ForbidSelfLoops: d.ForbidSelfLoops(), VersionPinned: d.VersionPinned(),
				DiagnosticOnly: d.DiagnosticOnly(), StableReferenceOnly: stableReferenceOnly,
			})
		}
		sort.Slice(manifest.Nodes, func(i, j int) bool { return manifest.Nodes[i].Name < manifest.Nodes[j].Name })
		sort.Slice(manifest.Edges, func(i, j int) bool { return manifest.Edges[i].Name < manifest.Edges[j].Name })
		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%x", sha256.Sum256(encoded))
	}
	// Golden value derived from the current 29-kind/57-label operational
	// registry plus only the required projection-role and external-coordinate
	// policy additions. It locks every runtime-consumed endpoint, direction,
	// reciprocal, family, and self-loop field against silent example drift.
	const expectedOperationalRegistrySemanticDigest = "206e9084cd9d86b2f69f70d7dc7e893fc61e9a82d2530beb62d6741320ef4219"
	for name, cfg := range map[string]SpecGraphConfig{"bootstrap": bootstrap, "production": production} {
		if got := semanticDigest(cfg); got != expectedOperationalRegistrySemanticDigest {
			t.Errorf("%s operational registry semantic digest=%s, want %s", name, got, expectedOperationalRegistrySemanticDigest)
		}
	}

	nodeSemantic := func(d NodeKindDescriptor) map[string]interface{} {
		return map[string]interface{}{
			"artifact_type": d.ArtifactType(), "version_scope": d.VersionScope(),
			"projection_role": d.ProjectionRole(), "source_authority": d.SourceAuthority(),
			"source_coordinate_policy": d.SourceCoordinatePolicy(), "projections": d.Projections(),
		}
	}
	edgeSemantic := func(d EdgeLabelDescriptor) map[string]interface{} {
		stableReferenceOnly, _ := d.Raw()["stable_reference_only"].(bool)
		return map[string]interface{}{
			"direction": d.Raw()["direction"], "catalog_owner": d.Raw()["catalog_owner"],
			"edge_family": d.EdgeFamily(), "source_kinds": d.SourceKinds(), "target_kinds": d.TargetKinds(),
			"reciprocal_label": d.ReciprocalLabel(), "forbid_self_loops": d.ForbidSelfLoops(),
			"version_pinned": d.VersionPinned(), "diagnostic_only": d.DiagnosticOnly(),
			"stable_reference_only": stableReferenceOnly,
		}
	}
	productionKinds := map[string]NodeKindDescriptor{}
	for _, d := range production.NodeKinds {
		productionKinds[d.Name()] = d
	}
	for _, d := range bootstrap.NodeKinds {
		other, ok := productionKinds[d.Name()]
		if !ok || !reflect.DeepEqual(nodeSemantic(d), nodeSemantic(other)) {
			t.Errorf("node kind %q semantic drift between operational examples: bootstrap=%#v production=%#v", d.Name(), nodeSemantic(d), nodeSemantic(other))
		}
	}
	productionEdges := map[string]EdgeLabelDescriptor{}
	for _, d := range production.EdgeLabels {
		productionEdges[d.Name()] = d
	}
	bootstrapEdges := map[string]EdgeLabelDescriptor{}
	for _, d := range bootstrap.EdgeLabels {
		bootstrapEdges[d.Name()] = d
		other, ok := productionEdges[d.Name()]
		if !ok || !reflect.DeepEqual(edgeSemantic(d), edgeSemantic(other)) {
			t.Errorf("edge label %q semantic drift between operational examples: bootstrap=%#v production=%#v", d.Name(), edgeSemantic(d), edgeSemantic(other))
		}
	}

	allDependencyKinds := []string{"origin", "axiom", "node_kind_declaration", "edge_label_declaration", "principal_type_declaration", "doc_object", "doc_version", "section", "symbol", "config", "circuit", "schema", "invariant", "assumption"}
	depends := bootstrapEdges["depends_on"]
	if depends.Raw()["direction"] != "source requires target before source is coherent, valid, executable, projectable, or consumable." || depends.EdgeFamily() != "dependency" || depends.ReciprocalLabel() != "load_bearing_for" || !depends.ForbidSelfLoops() || !reflect.DeepEqual(depends.SourceKinds(), allDependencyKinds) || !reflect.DeepEqual(depends.TargetKinds(), allDependencyKinds) {
		t.Errorf("depends_on narrowed or reversed: %#v", edgeSemantic(depends))
	}
	assumes := bootstrapEdges["assumes"]
	if assumes.Raw()["direction"] != "source assumption object constrains target sibling spec, section, object, or symbol." || !reflect.DeepEqual(assumes.SourceKinds(), []string{"assumption"}) || !reflect.DeepEqual(assumes.TargetKinds(), []string{"doc_object", "section", "symbol", "schema", "config", "circuit"}) || assumes.EdgeFamily() != "invariant_assumption" {
		t.Errorf("assumes direction or family drifted: %#v", edgeSemantic(assumes))
	}
	for _, name := range []string{"references", "declares"} {
		if len(bootstrapEdges[name].SourceKinds()) < 10 || len(bootstrapEdges[name].TargetKinds()) < 10 {
			t.Errorf("%s endpoint registry was narrowed: %#v", name, edgeSemantic(bootstrapEdges[name]))
		}
	}
	for name, role := range map[string]string{
		"origin": "substrate_origin_vertex_for_bootstrap_provenance_root", "axiom": "foundational_constraint_vertex_for_bootstrap_grounding",
		"node_kind_declaration": "closed_node_kind_registry_declaration_vertex", "edge_label_declaration": "closed_edge_label_registry_declaration_vertex",
		"principal_type_declaration": "closed_principal_type_registry_declaration_vertex",
	} {
		if got := productionKinds[name].ProjectionRole(); got != role {
			t.Errorf("%s projection_role=%q, want %q", name, got, role)
		}
	}
}

func TestLoadConfigRejectsUnknownAndDuplicateTopLevelKeys(t *testing.T) {
	base, err := os.ReadFile("spec-graph.config.production.example.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{
			name: "unknown",
			raw:  []byte(strings.Replace(string(base), `"mode": "production"`, `"mode": "production", "external_soruces": []`, 1)),
			want: "unknown field",
		},
		{
			name: "duplicate",
			raw:  []byte(strings.Replace(string(base), `"mode": "production"`, `"mode": "production", "mode": "production"`, 1)),
			want: "duplicate field",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "spec-graph.config.json")
			if err := os.WriteFile(path, tc.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SPEC_GRAPH_CONFIG", path)
			if _, err := loadConfig(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loadConfig error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestTopologicalOrderRejectsCycle(t *testing.T) {
	subs := []ArtifactSubmission{
		{StableID: "x", Payload: map[string]interface{}{"r": map[string]interface{}{"$ref": "y"}}},
		{StableID: "y", Payload: map[string]interface{}{"r": map[string]interface{}{"$ref": "x"}}},
	}
	_, err := topologicallyOrder(subs)
	if !errors.Is(err, ErrImportDependencyUnresolved) {
		t.Fatalf("expected ErrImportDependencyUnresolved, got %v", err)
	}
}

func TestTopologicalOrderRejectsDuplicateIDs(t *testing.T) {
	subs := []ArtifactSubmission{
		{StableID: "a"},
		{StableID: "a"},
	}
	_, err := topologicallyOrder(subs)
	if !errors.Is(err, ErrImportDependencyUnresolved) {
		t.Fatalf("expected ErrImportDependencyUnresolved on duplicate, got %v", err)
	}
}

// TestConfigValidate covers every cross-field rule.
func TestConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     SpecGraphConfig
		wantErr bool
		errSub  string
	}{
		{name: "unset_mode_rejected",
			cfg:     SpecGraphConfig{},
			wantErr: true,
			errSub:  "mode is required"},

		{name: "invalid_mode_rejected",
			cfg:     SpecGraphConfig{Mode: "weird"},
			wantErr: true,
			errSub:  "invalid mode"},

		{name: "bootstrap_complete_ok",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				ExperimentalAdmitter:  "MY_ADMITTER_NAME",
				DefaultOrganizationID: "tenant-x",
			},
			wantErr: false},

		{name: "bootstrap_arbitrary_admitter_accepted",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				ExperimentalAdmitter:  "ANYTHING_THE_DEV_WANTS",
				DefaultOrganizationID: "tenant-x",
			},
			wantErr: false},

		{name: "bootstrap_requires_admitter",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				DefaultOrganizationID: "tenant-x",
			},
			wantErr: true,
			errSub:  "experimental_admitter required"},

		{name: "bootstrap_requires_org_id",
			cfg: SpecGraphConfig{
				Mode:                 ModeExperimentalBootstrap,
				ExperimentalAdmitter: "ANY",
			},
			wantErr: true,
			errSub:  "default_organization_id required"},

		{name: "production_clean_ok",
			cfg:     SpecGraphConfig{Mode: ModeProduction, GenesisAdmitter: "GENESIS"},
			wantErr: false},

		{name: "production_requires_genesis_admitter",
			cfg:     SpecGraphConfig{Mode: ModeProduction},
			wantErr: true,
			errSub:  "genesis_admitter required"},

		{name: "production_rejects_experimental_admitter",
			cfg:     SpecGraphConfig{Mode: ModeProduction, GenesisAdmitter: "GENESIS", ExperimentalAdmitter: "X"},
			wantErr: true,
			errSub:  "experimental_admitter must be empty"},

		{name: "production_rejects_default_org_id",
			cfg:     SpecGraphConfig{Mode: ModeProduction, GenesisAdmitter: "GENESIS", DefaultOrganizationID: "X"},
			wantErr: true,
			errSub:  "default_organization_id must be empty"},

		{name: "production_rejects_query_enabled",
			cfg:     SpecGraphConfig{Mode: ModeProduction, GenesisAdmitter: "GENESIS", ExperimentalQueryEnabled: true},
			wantErr: true,
			errSub:  "experimental_query_enabled must be false"},

		{name: "central_credentials_required",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				ExperimentalAdmitter:  "A",
				DefaultOrganizationID: "T",
			},
			wantErr: true,
			errSub:  "credentials_source=application_default is required"},

		{name: "substrate_requires_id",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				ExperimentalAdmitter:  "A",
				DefaultOrganizationID: "T",
				Substrates:            []SubstrateDescriptor{{SpannerDatabase: "x"}},
			},
			wantErr: true,
			errSub:  "id required"},

		{name: "substrate_requires_spanner_database",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				ExperimentalAdmitter:  "A",
				DefaultOrganizationID: "T",
				Substrates:            []SubstrateDescriptor{{ID: "s1"}},
			},
			wantErr: true,
			errSub:  "spanner_database required"},

		{name: "substrate_rejects_legacy_credentials_file",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				ExperimentalAdmitter:  "A",
				DefaultOrganizationID: "T",
				Substrates: []SubstrateDescriptor{{
					ID: "s1", SpannerDatabase: "projects/p/instances/i/databases/d", CredentialsFile: "/k.json", ReadOnly: false,
				}},
			},
			wantErr: true,
			errSub:  "legacy per-client credential selector is forbidden"},

		{name: "writable_substrate_requires_tables",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				ExperimentalAdmitter:  "A",
				DefaultOrganizationID: "T",
				Substrates: []SubstrateDescriptor{{
					ID: "s1", SpannerDatabase: "projects/p/instances/i/databases/d", ReadOnly: false,
				}},
			},
			wantErr: true,
			errSub:  "writable substrate requires"},

		{name: "read_only_substrate_no_tables_needed",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				ExperimentalAdmitter:  "A",
				DefaultOrganizationID: "T",
				Substrates: []SubstrateDescriptor{{
					ID: "s1", SpannerDatabase: "projects/p/instances/i/databases/d", ReadOnly: true,
				}},
			},
			wantErr: false},

		{name: "listen_address_required",
			cfg: SpecGraphConfig{
				Mode:                  ModeExperimentalBootstrap,
				ExperimentalAdmitter:  "A",
				DefaultOrganizationID: "T",
				// ListenAddress deliberately empty
			},
			wantErr: true,
			errSub:  "listen_address is required"},
	}
	// Backfill ListenAddress on every case whose Mode is set, so the existing
	// cases keep testing the same downstream rules. The two mode-error cases
	// (unset_mode_rejected, invalid_mode_rejected) and the new
	// listen_address_required case deliberately omit ListenAddress and are
	// skipped by this fixup.
	for i := range cases {
		c := &cases[i]
		if c.cfg.Mode != "" && c.name != "central_credentials_required" {
			if c.cfg.Mode == ModeProduction {
				c.cfg.GoogleCredentials = productionGoogleCredentials()
			} else {
				c.cfg.GoogleCredentials = experimentalGoogleCredentials()
			}
		}
		switch c.name {
		case "unset_mode_rejected", "invalid_mode_rejected", "listen_address_required":
			// leave ListenAddress empty — these cases test failure modes that
			// fire before the listen_address check would.
		default:
			c.cfg.ListenAddress = "127.0.0.1:8765"
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			if c.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if err != nil && c.errSub != "" && !strings.Contains(err.Error(), c.errSub) {
				t.Errorf("error %q does not contain %q", err.Error(), c.errSub)
			}
		})
	}
}

func TestIsReadOnlySQL(t *testing.T) {
	cases := map[string]bool{
		"SELECT * FROM Nodes":                  true,
		"  select 1":                           true,
		"WITH a AS (SELECT 1) SELECT * FROM a": true,
		"GRAPH CorpusGraph MATCH (n) RETURN n": true,
		"MATCH (n) RETURN n":                   true,
		"INSERT INTO Nodes VALUES (1)":         false,
		"UPDATE Nodes SET x = 1":               false,
		"DELETE FROM Nodes":                    false,
		"DROP TABLE Nodes":                     false,
	}
	for sql, want := range cases {
		t.Run(sql, func(t *testing.T) {
			got := isReadOnlySQL(sql)
			if got != want {
				t.Errorf("isReadOnlySQL(%q) = %v, want %v", sql, got, want)
			}
		})
	}
}

// TestAllowlistCheck covers the config-driven init/reset gate. The allowlist
// patterns live in config; the binary holds no hardcoded patterns.
func TestAllowlistCheck(t *testing.T) {
	// Empty allowlist refuses everything.
	if err := allowlistCheck(SpecGraphConfig{}, "anything"); !errors.Is(err, ErrForbiddenDatabaseTarget) {
		t.Errorf("empty allowlist should refuse all, got %v", err)
	}

	// Matching pattern accepts.
	cfg := SpecGraphConfig{InitDatabaseAllowlist: []string{"corpus-graph-*"}}
	if err := allowlistCheck(cfg, "corpus-graph-iter1"); err != nil {
		t.Errorf("corpus-graph-iter1 should pass under corpus-graph-*, got %v", err)
	}

	// Non-matching pattern refuses. The production-tier database names
	// the user explicitly named as catastrophic-if-touched all refused under
	// the corpus-graph-* allowlist.
	for _, prodDB := range []string{"production-staging", "legacy-production-graph"} {
		if err := allowlistCheck(cfg, prodDB); !errors.Is(err, ErrForbiddenDatabaseTarget) {
			t.Errorf("%q should be refused under corpus-graph-*, got %v", prodDB, err)
		}
	}

	// User can pick any patterns they want — including allowing production-* if
	// that's the developer's choice. The binary doesn't second-guess config.
	cfg2 := SpecGraphConfig{InitDatabaseAllowlist: []string{"test-*", "experimental-*"}}
	if err := allowlistCheck(cfg2, "test-foo"); err != nil {
		t.Errorf("test-foo should pass under test-*, got %v", err)
	}
	if err := allowlistCheck(cfg2, "corpus-graph-iter1"); !errors.Is(err, ErrForbiddenDatabaseTarget) {
		t.Errorf("corpus-graph-iter1 should be refused under test-*|experimental-*, got %v", err)
	}
}

// TestSchemaFingerprintLogic verifies the set-difference logic behind
// VerifyExperimentalSchema without touching Spanner — exercises the
// exclusivity rule for the catastrophic-prevention gate.
func TestSchemaFingerprintLogic(t *testing.T) {
	classify := func(expected, found []string) (missing, extra []string, identical bool) {
		exp := map[string]bool{}
		for _, e := range expected {
			exp[e] = true
		}
		fnd := map[string]bool{}
		for _, f := range found {
			fnd[f] = true
		}
		for e := range exp {
			if !fnd[e] {
				missing = append(missing, e)
			}
		}
		for f := range fnd {
			if !exp[f] {
				extra = append(extra, f)
			}
		}
		identical = len(missing) == 0 && len(extra) == 0
		return
	}

	expected := []string{"Nodes", "Edges", "ArtifactAdmissionLog"}

	cases := []struct {
		name            string
		found           []string
		wantIdentical   bool
		wantMissing     []string
		wantExtraExists bool
	}{
		{name: "exact_match_spec_graph_db",
			found: []string{"Nodes", "Edges", "ArtifactAdmissionLog"}, wantIdentical: true},

		{name: "empty_db_zero_tables",
			found: []string{}, wantIdentical: false, wantMissing: []string{"ArtifactAdmissionLog", "Edges", "Nodes"}},

		{name: "legacy_graph_shape_extras_refuse",
			found:           []string{"ArtifactAdmissionLog", "ASG_Nodes", "DocObjects", "AgentRuns", "ArcLedger"},
			wantIdentical:   false,
			wantMissing:     []string{"Edges", "Nodes"},
			wantExtraExists: true},

		{name: "staging_graph_shape_subset_plus_extras",
			found:           []string{"Nodes", "Circuits", "OODGraphObjects", "Knowledge"},
			wantIdentical:   false,
			wantMissing:     []string{"ArtifactAdmissionLog", "Edges"},
			wantExtraExists: true},

		{name: "extra_only_refuse",
			found:           []string{"Nodes", "Edges", "ArtifactAdmissionLog", "Memories"},
			wantIdentical:   false,
			wantExtraExists: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			missing, extra, identical := classify(expected, c.found)
			if identical != c.wantIdentical {
				t.Errorf("identical = %v, want %v (missing=%v extra=%v)", identical, c.wantIdentical, missing, extra)
			}
			if c.wantExtraExists && len(extra) == 0 {
				t.Errorf("expected extras but got none (missing=%v)", missing)
			}
			if c.wantMissing != nil {
				gotMissing := map[string]bool{}
				for _, m := range missing {
					gotMissing[m] = true
				}
				for _, m := range c.wantMissing {
					if !gotMissing[m] {
						t.Errorf("expected %q in missing set, got missing=%v", m, missing)
					}
				}
			}
		})
	}
}

func TestParseSpannerResource(t *testing.T) {
	p, i, d, err := parseSpannerResource("projects/example-gcp-project/instances/example-spanner-instance/databases/corpus-graph-iter1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p != "example-gcp-project" || i != "example-spanner-instance" || d != "corpus-graph-iter1" {
		t.Errorf("got (%q, %q, %q)", p, i, d)
	}
	if _, _, _, err := parseSpannerResource("not-a-resource"); err == nil {
		t.Error("expected error on malformed resource")
	}
}

func TestCanonicalJSON(t *testing.T) {
	a := map[string]interface{}{"b": 2, "a": 1, "c": map[string]interface{}{"y": "v", "x": "u"}}
	out1, err := canonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	out2, err := canonicalJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	if string(out1) != string(out2) {
		t.Errorf("canonicalJSON not deterministic: %q vs %q", out1, out2)
	}
	want := `{"a":1,"b":2,"c":{"x":"u","y":"v"}}`
	if string(out1) != want {
		t.Errorf("canonicalJSON sort order wrong: got %q, want %q", out1, want)
	}
}

// TestValidateEdgeEndpoints exercises the edge-admission gate that handleLink
// runs against the resolved primary (and, for reciprocal labels, mirror)
// direction before the ceremony is invoked. Three structural defects were
// previously possible because the gate didn't exist:
//
//  1. source_kinds violation (e.g. an `audits` edge whose source is not an
//     audit_record);
//  2. target_kinds violation (e.g. a `raises` edge whose target is not a
//     sentinel);
//  3. self-loop on a label that declares forbid_self_loops=true (e.g. `audits`
//     per 036's audit-record fixed-point assert).
//
// Each subtest constructs an EdgeLabelDescriptor and two Nodes inline so the
// test is hermetic — no Spanner, no config file.
func TestValidateEdgeEndpoints(t *testing.T) {
	auditsDesc := NewEdgeLabelDescriptor(map[string]interface{}{
		"name":              "audits",
		"source_kinds":      []interface{}{"audit_record"},
		"target_kinds":      []interface{}{"axiom", "section", "audit_record"},
		"edge_family":       "audit",
		"forbid_self_loops": true,
	})
	raisesDesc := NewEdgeLabelDescriptor(map[string]interface{}{
		"name":         "raises",
		"source_kinds": []interface{}{"axiom", "section", "decision", "circuit"},
		"target_kinds": []interface{}{"sentinel"},
		"edge_family":  "diag",
	})
	dependsOnDesc := NewEdgeLabelDescriptor(map[string]interface{}{
		"name":         "depends_on",
		"source_kinds": []interface{}{"axiom", "section"},
		"target_kinds": []interface{}{"axiom", "section"},
		"edge_family":  "dep",
		// forbid_self_loops not set → self-loops permitted for this label.
	})
	axiom := func(id string) Node { return Node{NodeID: id, NodeKind: "axiom"} }
	auditRecord := func(id string) Node { return Node{NodeID: id, NodeKind: "audit_record"} }
	section := func(id string) Node { return Node{NodeID: id, NodeKind: "section"} }
	sentinel := func(id string) Node { return Node{NodeID: id, NodeKind: "sentinel"} }

	t.Run("valid_primary_admits", func(t *testing.T) {
		if err := validateEdgeEndpoints(auditsDesc, auditRecord("ar-1"), axiom("ax-1")); err != nil {
			t.Errorf("expected nil; got %v", err)
		}
	})

	t.Run("bad_source_kind_audits_from_axiom_refused", func(t *testing.T) {
		// Defect-1 reproduction: previously admitted ID 4ee317e3...
		err := validateEdgeEndpoints(auditsDesc, axiom("ax-1"), axiom("ax-2"))
		if !errors.Is(err, ErrEdgeKindMismatch) {
			t.Fatalf("expected ErrEdgeKindMismatch; got %v", err)
		}
		if !strings.Contains(err.Error(), "source_id") {
			t.Errorf("error should name source side; got %q", err.Error())
		}
	})

	t.Run("bad_target_kind_raises_to_axiom_refused", func(t *testing.T) {
		// Defect-2 reproduction: previously admitted ID 64f076f5...
		err := validateEdgeEndpoints(raisesDesc, axiom("ax-1"), axiom("ax-2"))
		if !errors.Is(err, ErrEdgeKindMismatch) {
			t.Fatalf("expected ErrEdgeKindMismatch; got %v", err)
		}
		if !strings.Contains(err.Error(), "target_id") {
			t.Errorf("error should name target side; got %q", err.Error())
		}
	})

	t.Run("valid_raises_admits", func(t *testing.T) {
		if err := validateEdgeEndpoints(raisesDesc, section("sec-1"), sentinel("sen-1")); err != nil {
			t.Errorf("expected nil; got %v", err)
		}
	})

	t.Run("self_loop_audits_refused", func(t *testing.T) {
		// Defect-3 reproduction: same-id source+target on a label whose
		// config sets forbid_self_loops=true.
		err := validateEdgeEndpoints(auditsDesc, auditRecord("ar-1"), auditRecord("ar-1"))
		if !errors.Is(err, ErrEdgeSelfLoopForbidden) {
			t.Fatalf("expected ErrEdgeSelfLoopForbidden; got %v", err)
		}
	})

	t.Run("self_loop_depends_on_allowed_when_unset", func(t *testing.T) {
		// depends_on doesn't declare forbid_self_loops in this test desc;
		// the gate must NOT refuse self-loops for labels that didn't opt in.
		// (Per-label policy lives in config; binary carries no global default.)
		if err := validateEdgeEndpoints(dependsOnDesc, axiom("ax-1"), axiom("ax-1")); err != nil {
			t.Errorf("expected nil for unset forbid_self_loops; got %v", err)
		}
	})

	t.Run("empty_source_kinds_fails_closed", func(t *testing.T) {
		desc := NewEdgeLabelDescriptor(map[string]interface{}{
			"name":         "open_src",
			"target_kinds": []interface{}{"axiom"},
			"edge_family":  "ref",
		})
		if err := validateEdgeEndpoints(desc, section("sec-1"), axiom("ax-1")); !errors.Is(err, ErrEdgeKindMismatch) {
			t.Errorf("expected ErrEdgeKindMismatch for unset SourceKinds; got %v", err)
		}
	})

	t.Run("empty_target_kinds_fails_closed", func(t *testing.T) {
		desc := NewEdgeLabelDescriptor(map[string]interface{}{
			"name":         "open_tgt",
			"source_kinds": []interface{}{"axiom"},
			"edge_family":  "ref",
		})
		if err := validateEdgeEndpoints(desc, axiom("ax-1"), sentinel("sen-1")); !errors.Is(err, ErrEdgeKindMismatch) {
			t.Errorf("expected ErrEdgeKindMismatch for unset TargetKinds; got %v", err)
		}
	})
}

// TestCanonicalNameFromFilename verifies the seed_node filename →
// canonical name derivation: strip leading "NNN_" admission-order
// prefix and ".json" suffix. Gates every seed_node admission's identity.
func TestCanonicalNameFromFilename(t *testing.T) {
	cases := []struct{ in, want string }{
		{"001_origin.json", "origin"},
		{"002_node_identity_axiom.json", "node_identity_axiom"},
		{"039_some_long_canonical_name.json", "some_long_canonical_name"},
		{"100_x.json", "x"},
		{"no_prefix.json", "no_prefix"},
		{"a.json", "a"},
		{"_underscore_first.json", "_underscore_first"},
		{"123.json", "123"},
		{"file_with_underscores_only.json", "file_with_underscores_only"},
	}
	for _, c := range cases {
		got := canonicalNameFromFilename(c.in)
		if got != c.want {
			t.Errorf("canonicalNameFromFilename(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestLoadSubmissionsFromPathSkipsUnderscoreFiles verifies that the
// directory scan in loadSubmissionsFromPath ignores leading-underscore JSON
// filenames. _edges.json and _findings.json are authoring/validator
// artifacts that share the directory with submission files; admitting them
// as submissions corrupts the import (they have no node_kind/edge_label and
// trip stepSchemaValidate). AUTHORING_GUIDE.md §11 promises this skip.
func TestLoadSubmissionsFromPathSkipsUnderscoreFiles(t *testing.T) {
	dir := t.TempDir()
	valid := `{"artifact_type":"axiom","organization_id":"test-org","node_kind":"axiom","contract":{"asserts":"u1"},"payload":{"title":"u1"}}`
	if err := os.WriteFile(filepath.Join(dir, "001_node.json"), []byte(valid), 0o644); err != nil {
		t.Fatal(err)
	}
	// Files the scan must skip. Their content is deliberately non-submission
	// shape so a regression that picks them up surfaces as a parse error
	// rather than a silent malformed admission.
	if err := os.WriteFile(filepath.Join(dir, "_edges.json"), []byte(`{"edges":[{"source_canonical_name":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "_findings.json"), []byte(`{"verdict":"pass"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	subs, err := loadSubmissionsFromPath(dir)
	if err != nil {
		t.Fatalf("loadSubmissionsFromPath returned err — scan likely picked up an underscore file: %v", err)
	}
	if len(subs) != 1 {
		t.Errorf("expected 1 submission (underscore files skipped), got %d (subs=%+v)", len(subs), subs)
	}
}

func TestLoadSubmissionsFromPathRejectsNestedDuplicateJSONMembers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		directory bool
	}{
		{
			name: "single_object_payload",
			body: `{"node_kind":"section","stable_id":"duplicate_payload","payload":{"scope":"first","scope":"second"}}`,
		},
		{
			name:      "directory_array_contract",
			body:      `[{"node_kind":"section","stable_id":"duplicate_contract","contract":{"nested":{"name":"first","name":"second"}}}]`,
			directory: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "001_duplicate.json")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			target := path
			if tc.directory {
				target = dir
			}
			_, err := loadSubmissionsFromPath(target)
			if err == nil || !strings.Contains(err.Error(), "duplicate field") {
				t.Fatalf("file ingress duplicate error=%v, want recursive refusal", err)
			}
		})
	}
}

// TestResolveSubmissionCanonicalName covers the OOD_GRAPH_PROTOCOL_v1 §3
// identity-tuple canonical_name resolution rule: stable_id wins, then
// contract.canonical_name, then contract.canonical_err_name (sentinels),
// then error. Regression guard for the collapsed-identity bug where
// omitting stable_id silently fell back to the kind name, producing the
// same UUIDv5 for every same-kind submission.
func TestResolveSubmissionCanonicalName(t *testing.T) {
	cases := []struct {
		name    string
		sub     ArtifactSubmission
		want    string
		wantErr bool
	}{
		{
			name: "stable_id_wins",
			sub: ArtifactSubmission{
				StableID: "explicit_name",
				Contract: map[string]interface{}{"canonical_name": "other_name"},
			},
			want: "explicit_name",
		},
		{
			name: "contract_canonical_name_when_stable_id_empty",
			sub: ArtifactSubmission{
				Contract: map[string]interface{}{"canonical_name": "from_contract"},
			},
			want: "from_contract",
		},
		{
			name: "contract_canonical_err_name_for_sentinels",
			sub: ArtifactSubmission{
				Contract: map[string]interface{}{"canonical_err_name": "ErrSomeFailure"},
			},
			want: "ErrSomeFailure",
		},
		{
			name: "canonical_name_preferred_over_err_name_when_both_present",
			sub: ArtifactSubmission{
				Contract: map[string]interface{}{
					"canonical_name":     "preferred",
					"canonical_err_name": "ErrFallback",
				},
			},
			want: "preferred",
		},
		{
			name:    "error_when_nothing_resolves",
			sub:     ArtifactSubmission{NodeKind: "section"},
			wantErr: true,
		},
		{
			name: "error_when_contract_present_but_empty",
			sub: ArtifactSubmission{
				NodeKind: "section",
				Contract: map[string]interface{}{},
			},
			wantErr: true,
		},
		{
			name: "error_when_contract_canonical_name_is_empty_string",
			sub: ArtifactSubmission{
				Contract: map[string]interface{}{"canonical_name": ""},
			},
			wantErr: true,
		},
		{
			name: "error_when_contract_canonical_name_is_wrong_type",
			sub: ArtifactSubmission{
				Contract: map[string]interface{}{"canonical_name": 42},
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveSubmissionCanonicalName(tc.sub)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil (resolved to %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
