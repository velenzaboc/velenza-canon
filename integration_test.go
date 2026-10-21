//go:build integration

// Integration tests against a local Spanner emulator. Excluded from the
// default `go test ./...` run; enable with `go test -tags=integration`.
// Driven via the Makefile target `make test-integration` which starts the
// emulator, runs these tests, then tears down. The tests create their own
// emulator instance (requireEmulator -> ensureEmulatorInstance) and database,
// so a bare emulator with only SPANNER_EMULATOR_HOST set is sufficient.
//
// Coverage scope: features the Spanner emulator supports as of 2026 —
// DDL apply, mutations, standard SQL queries, the admission-ceremony +
// substrate write path, edge admission with reciprocity, RFC 6902 diff.
//
// NOT covered (emulator gaps; verified on real Spanner via the live MCP
// smoke walks): CREATE PROPERTY GRAPH, APPROX_COSINE_DISTANCE / vector
// indexes, GRAPH_TABLE traversal. The unit tests + manual smoke walks
// against corpus-graph-iter1 cover those paths.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	database "cloud.google.com/go/spanner/admin/database/apiv1"
	adminpb "cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
)

const (
	emulatorProject  = "test-project"
	emulatorInstance = "test-instance"
	emulatorDatabase = "test-corpus-graph"
)

// emulatorResource is the resource path the integration tests target. The
// Spanner Go client honors SPANNER_EMULATOR_HOST and routes to localhost.
var emulatorResource = "projects/" + emulatorProject + "/instances/" + emulatorInstance + "/databases/" + emulatorDatabase

// requireEmulator is the single entry point every emulator-backed test calls
// before any database operation. It also ensures the target instance exists,
// because a bare emulator starts with no instances.
func requireEmulator(t *testing.T) {
	t.Helper()
	host := os.Getenv("SPANNER_EMULATOR_HOST")
	if host == "" {
		t.Fatal("SPANNER_EMULATOR_HOST not set — integration tests require the Spanner emulator running locally; see Makefile test-integration target")
	}
	if err := ensureEmulatorInstance(context.Background(), host); err != nil {
		t.Fatalf("ensure emulator instance: %v", err)
	}
}

// integrationSchema is the subset of bootstrap/schema_v1.sql the Spanner
// emulator supports. The vector index + property graph DDL is omitted
// (emulator gaps); the underlying tables are still created so admission
// ceremony writes succeed.
var integrationSchema = []string{
	`CREATE TABLE Nodes (
		organization_id            STRING(64)  NOT NULL,
		node_id                    STRING(64)  NOT NULL,
		version                    INT64       NOT NULL,
		node_kind                  STRING(128) NOT NULL,
		status                     STRING(32)  NOT NULL,
		contract                   JSON,
		content                    JSON,
		definition_hash            STRING(128),
		manifest_hash              STRING(128),
		signature_chain            ARRAY<STRING(MAX)>,
		admitted_by                STRING(256) NOT NULL,
		admitted_at                TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
		superseded_by_version      INT64,
		governing_spec_ref         STRING(MAX),
		source_spec_lineage_refs   ARRAY<STRING(MAX)>,
		spec_section_ref           STRING(MAX),
		spec_symbol_ref            STRING(MAX),
		node_creation_contract_ref STRING(MAX),
		embedding_v2               ARRAY<FLOAT32>,
		active_marker              STRING(64) AS (IF(status = 'active', node_id, NULL)) STORED,
	) PRIMARY KEY (organization_id, node_id, version)`,
	`CREATE TABLE Edges (
		organization_id    STRING(64)  NOT NULL,
		edge_id            STRING(64)  NOT NULL,
		source_node_id     STRING(64)  NOT NULL,
		source_version     INT64       NOT NULL,
		target_node_id     STRING(64)  NOT NULL,
		target_version     INT64       NOT NULL,
		edge_label         STRING(128) NOT NULL,
		status             STRING(32)  NOT NULL,
		admitted_at        TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
		reciprocal_edge_id STRING(64),
	) PRIMARY KEY (organization_id, edge_id)`,
	`CREATE TABLE ArtifactAdmissionLog (
		organization_id        STRING(64)  NOT NULL,
		admission_id           STRING(64)  NOT NULL,
		artifact_id            STRING(64)  NOT NULL,
		artifact_type          STRING(128) NOT NULL,
		artifact_version       INT64       NOT NULL,
		artifact_hash          STRING(128) NOT NULL,
		manifest_hash          STRING(128) NOT NULL,
		admitted_by            STRING(256) NOT NULL,
		admitted_at            TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
		signature              STRING(MAX) NOT NULL,
		dual_control_approver  STRING(256),
		is_non_genesis         BOOL        NOT NULL,
		pass_report            JSON,
	) PRIMARY KEY (organization_id, admission_id)`,
}

// integrationSourceCoordinateSchema is the schema-v2 subset needed to prove
// that a structured external source coordinate survives the real
// staging_concepts JSON column, promotion, and OODGraph object/symbol writes.
// Search token columns, vector indexes, and CREATE PROPERTY GRAPH are omitted
// because the emulator does not implement them and this test does not use
// those surfaces.
var integrationSourceCoordinateSchema = []string{
	`CREATE TABLE OODGraphSnapshots (
		organization_id STRING(36) NOT NULL,
		graph_snapshot_id STRING(36) NOT NULL,
		graph_version INT64 NOT NULL,
		snapshot_kind STRING(32) NOT NULL,
		source_set_hash STRING(128) NOT NULL,
		source_set JSON NOT NULL,
		materialization_run_id STRING(36),
		snapshot_state STRING(32) NOT NULL,
		status STRING(32) NOT NULL,
		visibility_scope STRING(32) NOT NULL,
		sealed_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
		updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, graph_snapshot_id)`,
	`CREATE UNIQUE INDEX OODGraphSnapshotsByVersion
		ON OODGraphSnapshots(organization_id, graph_version)`,
	`CREATE TABLE OODGraphObjects (
		organization_id STRING(36) NOT NULL,
		graph_snapshot_id STRING(36) NOT NULL,
		graph_object_id STRING(36) NOT NULL,
		object_class STRING(64) NOT NULL,
		source_authority_id STRING(36) NOT NULL,
		source_artifact_class STRING(64) NOT NULL,
		source_ref_kind STRING(32) NOT NULL,
		source_stable_reference STRING(2048) NOT NULL,
		version_coordinate STRING(1024) NOT NULL,
		section_path STRING(2048) NOT NULL,
		graph_address STRING(4096) NOT NULL,
		source_content_hash STRING(128),
		source_content_hash_owner STRING(36),
		materialization_run_id STRING(36) NOT NULL,
		projection_role STRING(64) NOT NULL,
		validation_state STRING(32) NOT NULL,
		status STRING(32) NOT NULL,
		visibility_scope STRING(32) NOT NULL,
		search_text STRING(MAX),
		search_payload JSON,
		embedding ARRAY<FLOAT32>,
		embedding_model STRING(128) NOT NULL,
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
		updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, graph_snapshot_id, graph_object_id)`,
	`CREATE TABLE OODGraphSymbols (
		organization_id STRING(36) NOT NULL,
		graph_snapshot_id STRING(36) NOT NULL,
		symbol_id STRING(36) NOT NULL,
		graph_object_id STRING(36) NOT NULL,
		object_class STRING(64) NOT NULL,
		symbol_kind STRING(64) NOT NULL,
		symbol_name STRING(1024) NOT NULL,
		source_authority_id STRING(36) NOT NULL,
		source_stable_reference STRING(2048) NOT NULL,
		version_coordinate STRING(1024) NOT NULL,
		section_path STRING(2048) NOT NULL,
		graph_address STRING(4096) NOT NULL,
		materialization_run_id STRING(36) NOT NULL,
		validation_state STRING(32) NOT NULL,
		status STRING(32) NOT NULL,
		visibility_scope STRING(32) NOT NULL,
		search_text STRING(MAX),
		search_payload JSON,
		embedding ARRAY<FLOAT32>,
		embedding_model STRING(128) NOT NULL,
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
		updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, graph_snapshot_id, symbol_id)`,
	`CREATE TABLE OODGraphEdges (
		organization_id STRING(36) NOT NULL,
		graph_snapshot_id STRING(36) NOT NULL,
		graph_edge_id STRING(36) NOT NULL,
		source_endpoint_kind STRING(16) NOT NULL,
		source_endpoint_id STRING(36) NOT NULL,
		source_endpoint_class STRING(64) NOT NULL,
		target_endpoint_kind STRING(16) NOT NULL,
		target_endpoint_id STRING(36) NOT NULL,
		target_endpoint_class STRING(64) NOT NULL,
		edge_label STRING(64) NOT NULL,
		edge_family STRING(64) NOT NULL,
		source_version_coordinate STRING(1024) NOT NULL,
		target_version_coordinate STRING(1024) NOT NULL,
		authoring_source_path STRING(2048) NOT NULL,
		source_authority_id STRING(36) NOT NULL,
		source_stable_reference STRING(2048) NOT NULL,
		source_content_hash STRING(128),
		valid_from TIMESTAMP,
		valid_until TIMESTAMP,
		diagnostic_only BOOL NOT NULL,
		reciprocity_state STRING(32) NOT NULL,
		inverse_edge_id STRING(36),
		edge_confidence FLOAT32,
		materialization_run_id STRING(36) NOT NULL,
		validation_state STRING(32) NOT NULL,
		status STRING(32) NOT NULL,
		visibility_scope STRING(32) NOT NULL,
		search_text STRING(MAX),
		search_payload JSON,
		embedding ARRAY<FLOAT32>,
		embedding_model STRING(128) NOT NULL,
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
		updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, graph_snapshot_id, graph_edge_id)`,
	`CREATE TABLE OODGraphMaterializationRuns (
		organization_id STRING(36) NOT NULL,
		materialization_run_id STRING(36) NOT NULL,
		target_graph_snapshot_id STRING(36),
		run_kind STRING(64) NOT NULL,
		input_source_set_hash STRING(128) NOT NULL,
		input_source_set JSON NOT NULL,
		state STRING(32) NOT NULL,
		started_at TIMESTAMP NOT NULL,
		finished_at TIMESTAMP,
		object_count INT64 NOT NULL,
		symbol_count INT64 NOT NULL,
		edge_count INT64 NOT NULL,
		violation_count INT64 NOT NULL,
		status STRING(32) NOT NULL,
		visibility_scope STRING(32) NOT NULL,
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
		updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, materialization_run_id)`,
	`CREATE TABLE OODGraphViolations (
		organization_id STRING(36) NOT NULL,
		violation_id STRING(36) NOT NULL,
		graph_snapshot_id STRING(36),
		materialization_run_id STRING(36),
		violation_code STRING(64) NOT NULL,
		sentinel_candidate STRING(256),
		severity STRING(16) NOT NULL,
		source_authority_id STRING(36),
		source_stable_reference STRING(2048),
		version_coordinate STRING(1024),
		section_path STRING(2048),
		graph_object_id STRING(36),
		symbol_id STRING(36),
		graph_edge_id STRING(36),
		evidence JSON,
		status STRING(32) NOT NULL,
		visibility_scope STRING(32) NOT NULL,
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
		updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, violation_id)`,
	`CREATE TABLE OODGraphProjectionArtifacts (
		organization_id STRING(36) NOT NULL,
		projection_artifact_id STRING(36) NOT NULL,
		graph_snapshot_id STRING(36) NOT NULL,
		projection_kind STRING(64) NOT NULL,
		projection_target_kind STRING(64) NOT NULL,
		projection_target_id STRING(36),
		projection_format STRING(32) NOT NULL,
		projection_hash STRING(128) NOT NULL,
		projection_payload JSON NOT NULL,
		round_trip_state STRING(32) NOT NULL,
		materialization_run_id STRING(36),
		status STRING(32) NOT NULL,
		visibility_scope STRING(32) NOT NULL,
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
		updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, projection_artifact_id)`,
	`CREATE TABLE staging_concepts (
		organization_id STRING(36) NOT NULL,
		ingestion_run_id STRING(36) NOT NULL,
		staging_id STRING(36) NOT NULL,
		canonical_name STRING(2048) NOT NULL,
		node_kind STRING(64) NOT NULL,
		contract JSON,
		payload JSON,
		source_file STRING(1024),
		source_path STRING(2048),
		source_coordinate JSON,
		source_verification_receipt JSON,
		embedding ARRAY<FLOAT32>,
		embedding_model STRING(128),
		cluster_id STRING(36),
		dedup_status STRING(32),
		dedup_decision JSON,
		lint_status STRING(32),
		lint_findings JSON,
		pipeline_state STRING(32) NOT NULL,
		promoted_graph_object_id STRING(36),
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
		updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, ingestion_run_id, staging_id)`,
	`CREATE TABLE staging_symbols (
		organization_id STRING(36) NOT NULL,
		ingestion_run_id STRING(36) NOT NULL,
		staging_symbol_id STRING(36) NOT NULL,
		staging_id STRING(36) NOT NULL,
		canonical_name STRING(2048) NOT NULL,
		node_kind STRING(64) NOT NULL,
		symbol_kind STRING(64) NOT NULL,
		section_path STRING(2048) NOT NULL,
		search_text STRING(MAX),
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, ingestion_run_id, staging_symbol_id)`,
	`CREATE TABLE staging_edges (
		organization_id STRING(36) NOT NULL,
		ingestion_run_id STRING(36) NOT NULL,
		staging_edge_id STRING(36) NOT NULL,
		edge_label STRING(64) NOT NULL,
		source_canonical_name STRING(2048) NOT NULL,
		target_canonical_name STRING(2048) NOT NULL,
		lint_status STRING(32),
		lint_findings JSON,
		pipeline_state STRING(32) NOT NULL,
		promoted_graph_edge_id STRING(36),
		created_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
		updated_at TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
	) PRIMARY KEY (organization_id, ingestion_run_id, staging_edge_id)`,
}

// setupEmulatorDB drops + creates a fresh database, applies the integration
// schema. Returns when ready.
func setupEmulatorDB(ctx context.Context, t *testing.T) {
	t.Helper()
	adminClient, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	defer adminClient.Close()

	// Drop if present.
	_ = adminClient.DropDatabase(ctx, &adminpb.DropDatabaseRequest{Database: emulatorResource})

	// Create.
	op, err := adminClient.CreateDatabase(ctx, &adminpb.CreateDatabaseRequest{
		Parent:          "projects/" + emulatorProject + "/instances/" + emulatorInstance,
		CreateStatement: "CREATE DATABASE `" + emulatorDatabase + "`",
	})
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatalf("create database wait: %v", err)
	}

	// Apply schema.
	op2, err := adminClient.UpdateDatabaseDdl(ctx, &adminpb.UpdateDatabaseDdlRequest{
		Database:   emulatorResource,
		Statements: integrationSchema,
	})
	if err != nil {
		t.Fatalf("update ddl: %v", err)
	}
	if err := op2.Wait(ctx); err != nil {
		t.Fatalf("update ddl wait: %v", err)
	}
}

func applyIntegrationDDL(ctx context.Context, t *testing.T, statements []string) {
	t.Helper()
	adminClient, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		t.Fatalf("admin client: %v", err)
	}
	defer adminClient.Close()
	op, err := adminClient.UpdateDatabaseDdl(ctx, &adminpb.UpdateDatabaseDdlRequest{
		Database:   emulatorResource,
		Statements: statements,
	})
	if err != nil {
		t.Fatalf("update source-coordinate ddl: %v", err)
	}
	if err := op.Wait(ctx); err != nil {
		t.Fatalf("update source-coordinate ddl wait: %v", err)
	}
}

// integrationEnv builds an Env wired to the emulator. The emulator doesn't
// have Vertex AI access; Embed is nil so admission skips embedding.
func integrationEnv(t *testing.T) *Env {
	t.Helper()
	cfg := SpecGraphConfig{
		Mode:                  ModeExperimentalBootstrap,
		GoogleCredentials:     experimentalGoogleCredentials(),
		ExperimentalAdmitter:  "EXPERIMENTAL_BOOTSTRAP",
		DefaultOrganizationID: "test-org",
		ListenAddress:         "127.0.0.1:0",
		AllowSpannerEmulator:  true,
		Substrates: []SubstrateDescriptor{{
			ID:                "test_substrate",
			SpannerDatabase:   emulatorResource,
			NodeTable:         "Nodes",
			EdgeTable:         "Edges",
			AdmissionLogTable: "ArtifactAdmissionLog",
		}},
		NodeKinds: []NodeKindDescriptor{
			NewNodeKindDescriptor(map[string]interface{}{
				"name":            "axiom",
				"substrate_id":    "test_substrate",
				"artifact_type":   "axiom",
				"version_scope":   "stable_id_preserved",
				"projection_role": "foundational_constraint_vertex_for_bootstrap_grounding",
			}),
		},
		EdgeLabels: []EdgeLabelDescriptor{
			NewEdgeLabelDescriptor(map[string]interface{}{
				"name":         "references",
				"source_kinds": []interface{}{"axiom"},
				"target_kinds": []interface{}{"axiom"},
				"edge_family":  "ref",
			}),
			NewEdgeLabelDescriptor(map[string]interface{}{
				"name":             "load_bearing_for",
				"source_kinds":     []interface{}{"axiom"},
				"target_kinds":     []interface{}{"axiom"},
				"reciprocal_label": "depends_on",
				"edge_family":      "dep",
			}),
			NewEdgeLabelDescriptor(map[string]interface{}{
				"name":             "depends_on",
				"source_kinds":     []interface{}{"axiom"},
				"target_kinds":     []interface{}{"axiom"},
				"reciprocal_label": "load_bearing_for",
				"edge_family":      "dep",
			}),
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}
	return &Env{
		Config:     cfg,
		Kinds:      newKindRegistry(cfg.NodeKinds),
		Edges:      newEdgeRegistry(cfg.EdgeLabels),
		Substrates: newRouter(cfg.GoogleCredentials, cfg.AllowSpannerEmulator, cfg.Substrates),
		Now:        time.Now,
	}
}

func integrationOODEnv(t *testing.T) *Env {
	t.Helper()
	edgeLabels := externalReferenceTestEdgeDescriptors()
	edgeLabels = append(edgeLabels,
		resolutionTestLabel("depends_on", "dependency", []string{"section"}, []string{"section"}, "load_bearing_for"),
		resolutionTestLabel("load_bearing_for", "dependency", []string{"section"}, []string{"section"}, "depends_on"),
	)
	cfg := SpecGraphConfig{
		Mode:                  ModeExperimentalBootstrap,
		GoogleCredentials:     experimentalGoogleCredentials(),
		ExperimentalAdmitter:  "EXPERIMENTAL_BOOTSTRAP",
		DefaultOrganizationID: "test-org",
		ListenAddress:         "127.0.0.1:0",
		AllowSpannerEmulator:  true,
		Embedding: &EmbeddingConfig{
			Provider:     "vertex_ai",
			Project:      "test-project",
			Location:     "us-central1",
			Model:        "gemini-embedding-001",
			Dimensions:   externalReferenceEmbeddingDimensions,
			MaxTextBytes: 32768,
		},
		ExternalSources: []ExternalSourceDescriptor{
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
			{
				ID:                      "quickbooks_online_official_source_repository",
				SourceArtifactClass:     "official_source_repository",
				ReferenceKind:           "https_url_prefix",
				ReferencePrefix:         "https://github.com/intuit",
				ContentHashAlgorithm:    "sha256",
				VersionCoordinateMode:   externalVersionModeUpstreamPinned,
				VersionStableNamePrefix: "quickbooks_online_source_",
				AllowedObjectClasses:    []string{"source_repo", "repo_snapshot", "code_symbol_ref"},
				LocatorKinds: map[string]string{
					"source_repo": "resource_root", "repo_snapshot": "resource_root", "code_symbol_ref": "code_graph_coordinate",
				},
				FreshnessWindowSeconds:                  7 * 24 * 60 * 60,
				LicenseEvidenceRequired:                 true,
				LicenseEvidenceBinding:                  licenseEvidenceBindingSameRepositoryFile,
				RepositoryPathSegments:                  2,
				UpstreamIdentityPolicy:                  upstreamIdentityImmutableRefWithContentDigest,
				ImmutableReferencePattern:               `^https://github\.com/intuit/[A-Za-z0-9._-]+/(tree|commit)/(?P<immutable_ref>[0-9a-f]{40})$`,
				SameRepositoryPermissionEvidencePattern: `^https://github\.com/intuit/[A-Za-z0-9._-]+/blob/(?P<immutable_ref>[0-9a-f]{40})/([A-Za-z0-9._-]+/)*(LICENSE|LICENSE\.[A-Za-z0-9._-]+|COPYING|COPYING\.[A-Za-z0-9._-]+)$`,
				AllowFragment:                           true,
			},
		},
		Substrates: []SubstrateDescriptor{{
			ID:                      "test_substrate",
			SpannerDatabase:         emulatorResource,
			NodeTable:               "Nodes",
			EdgeTable:               "Edges",
			AdmissionLogTable:       "ArtifactAdmissionLog",
			SnapshotTable:           "OODGraphSnapshots",
			ObjectTable:             "OODGraphObjects",
			SymbolTable:             "OODGraphSymbols",
			GraphEdgeTable:          "OODGraphEdges",
			MaterializationRunTable: "OODGraphMaterializationRuns",
			ViolationTable:          "OODGraphViolations",
			ProjectionArtifactTable: "OODGraphProjectionArtifacts",
		}},
		NodeKinds:  integrationExternalNodeKinds(),
		EdgeLabels: edgeLabels,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate OOD config: %v", err)
	}
	return &Env{
		Config:        cfg,
		Kinds:         newKindRegistry(cfg.NodeKinds),
		Edges:         newEdgeRegistry(cfg.EdgeLabels),
		Substrates:    newRouter(cfg.GoogleCredentials, cfg.AllowSpannerEmulator, cfg.Substrates),
		Embed:         fixedEmbeddingClient{dimensions: externalReferenceEmbeddingDimensions},
		ExternalFetch: deterministicExternalFetcher{},
		Now:           time.Now,
	}
}

// TestIntegrationConfigurationFixturesValidate is intentionally emulator-free:
// it makes integration-tag compilation execute the same closed node/edge/source
// registries that the emulator tests use, so a stale wildcard or forbidden
// external endpoint cannot hide behind requireEmulator skips.
func TestIntegrationConfigurationFixturesValidate(t *testing.T) {
	env := integrationOODEnv(t)
	if err := env.Substrates.Close(); err != nil {
		t.Fatalf("close integration substrate router: %v", err)
	}
}

func integrationExternalNodeKinds() []NodeKindDescriptor {
	kinds := []string{"external_reference_doc", "reference_page", "api_symbol", "code_example", "release_note", "source_repo", "repo_snapshot", "code_symbol_ref"}
	projectionRoles := map[string]string{
		"external_reference_doc": "root_external_reference_vertex_for_technology_lookup_and_forge_context",
		"reference_page":         "retrievable_external_reference_vertex_for_cross_doc_traversal",
		"api_symbol":             "technology_symbol_vertex_for_retrieval_and_forge_task_context",
		"code_example":           "retrieval_vertex_for_task_examples_without_claiming_source_truth",
		"release_note":           "temporal_external_reference_vertex_for_currentness_and_compatibility_queries",
		"source_repo":            "external_source_authority_vertex_for_docs_and_code_graph_projection",
		"repo_snapshot":          "versioned_bridge_vertex_between_external_docs_and_code_graph_symbols",
		"code_symbol_ref":        "implementation_evidence_vertex_for_traversal_without_copying_code_graph_storage",
	}
	out := make([]NodeKindDescriptor, 0, len(kinds)+1)
	for _, kind := range kinds {
		out = append(out, NewNodeKindDescriptor(map[string]interface{}{
			"name":                     kind,
			"substrate_id":             "test_substrate",
			"artifact_type":            kind,
			"version_scope":            "source_version_scoped",
			"projection_role":          projectionRoles[kind],
			"source_authority":         bootstrapSourceAuthority,
			"source_coordinate_policy": sourceCoordinatePolicyExternalReferenceRequired,
		}))
	}
	out = append(out, NewNodeKindDescriptor(map[string]interface{}{
		"name":             "section",
		"substrate_id":     "test_substrate",
		"artifact_type":    "section",
		"version_scope":    "stable_id_preserved",
		"projection_role":  "subdocument_vertex_for_projection_and_closure",
		"source_authority": bootstrapSourceAuthority,
	}))
	return out
}

func integrationMaterializationBatch(t *testing.T, versionToken, contentHash string) MaterializationBatch {
	t.Helper()
	retrievedAt := time.Now().UTC().Format(time.RFC3339Nano)
	coord := SourceCoordinate{
		OrganizationID:      "test-org",
		SourceAuthorityID:   bootstrapSourceAuthority,
		SourceArtifactClass: "official_vendor_documentation",
		SourceRefKind:       "coordinate",
		// Most integration batches model different source resources rather than
		// different versions of one resource. Keep the resource identity
		// disjoint so complete-snapshot carry-forward is not accidentally a
		// temporal refresh (which is deliberately fail-closed until §6 admits
		// external supersession endpoint classes).
		SourceStableReference: "https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice/" + versionToken,
		VersionCoordinate:     "source:" + bootstrapSourceAuthority + ":quickbooks_online_invoice_reference@sha256_" + contentHash,
		SectionPath:           "$",
		SourceContentHash:     contentHash,
	}
	coords := []SourceCoordinate{coord}
	sourceSetHash, err := ComputeSourceSetHash("test-org", coords)
	if err != nil {
		t.Fatalf("ComputeSourceSetHash: %v", err)
	}
	sourceSet := BuildSourceSet("test-org", coords)
	runID := uuid.NewString()
	snapshotID := uuid.NewString()
	objectIDInput := "object|test-org|reference_page|" + coord.SourceAuthorityID + "|" + coord.SourceRefKind + "|" + coord.SourceStableReference + "|" + coord.VersionCoordinate + "|$"
	objectID := uuid.NewSHA1(oodGraphIDNamespace, []byte(objectIDInput)).String()
	address := GraphAddress{
		ObjectClass:       "reference_page",
		SourceAuthorityID: coord.SourceAuthorityID,
		SourceRefKind:     coord.SourceRefKind,
		SourceRef:         coord.SourceStableReference,
		VersionCoordinate: coord.VersionCoordinate,
		SectionPath:       coord.SectionPath,
	}.String()
	artifactCoordinate := ArtifactSourceCoordinate{
		SourceAuthorityID:      coord.SourceAuthorityID,
		SourceArtifactClass:    coord.SourceArtifactClass,
		SourceRefKind:          coord.SourceRefKind,
		SourceStableReference:  coord.SourceStableReference,
		VersionCoordinate:      coord.VersionCoordinate,
		SectionPath:            coord.SectionPath,
		SourceContentHash:      coord.SourceContentHash,
		SourceContentHashOwner: bootstrapSourceAuthority,
		RetrievedAt:            retrievedAt,
		LicenseEvidence:        quickBooksTestRetrievalPermissionEvidence,
	}
	policy := integrationDocsPolicy(t)
	batch := MaterializationBatch{
		Run: MaterializationRun{
			OrganizationID:       "test-org",
			MaterializationRunID: runID,
			RunKind:              "corpus_refresh",
			InputSourceSetHash:   sourceSetHash,
			InputSourceSet:       sourceSet,
			State:                "running",
			StartedAt:            time.Now().UTC(),
			Status:               "active",
			VisibilityScope:      "organization",
		},
		Snapshot: GraphSnapshot{
			OrganizationID:  "test-org",
			GraphSnapshotID: snapshotID,
			SnapshotKind:    "active_candidate",
			SourceSetHash:   sourceSetHash,
			SourceSet:       sourceSet,
			SnapshotState:   "building",
			Status:          "active",
			VisibilityScope: "organization",
		},
		Objects: []GraphObject{{
			OrganizationID:         "test-org",
			GraphSnapshotID:        snapshotID,
			GraphObjectID:          objectID,
			ObjectClass:            "reference_page",
			SourceAuthorityID:      coord.SourceAuthorityID,
			SourceArtifactClass:    coord.SourceArtifactClass,
			SourceRefKind:          coord.SourceRefKind,
			SourceStableReference:  coord.SourceStableReference,
			VersionCoordinate:      coord.VersionCoordinate,
			SectionPath:            coord.SectionPath,
			GraphAddress:           address,
			SourceContentHash:      coord.SourceContentHash,
			SourceContentHashOwner: bootstrapSourceAuthority,
			MaterializationRunID:   runID,
			ProjectionRole:         "retrievable_external_reference_vertex_for_cross_doc_traversal",
			ValidationState:        "valid",
			Status:                 "active",
			VisibilityScope:        "organization",
			SearchPayload:          externalReferenceSearchPayload("reference_page", address, artifactCoordinate, policy),
			SearchText:             externalReferenceSearchText("reference_page", artifactCoordinate, policy),
			Embedding:              make([]float32, externalReferenceEmbeddingDimensions),
			EmbeddingModel:         "gemini-embedding-001",
		}},
	}
	integrationAttachExternalVerificationReceipts(t, &batch)
	return batch
}

// integrationDocsPolicy obtains the fixture receipt policy from the same
// validated configuration used by the emulator environment. Keeping a second
// hand-written descriptor here made its fingerprint drift while the fields
// still looked superficially equivalent, so carried receipt validation failed
// before the complete-snapshot fixture could exercise its intended path.
func integrationDocsPolicy(t *testing.T) ExternalSourceDescriptor {
	t.Helper()
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	for _, policy := range env.Config.ExternalSources {
		if policy.ID == "quickbooks_online_official_docs" {
			return policy
		}
	}
	t.Fatal("integration config lacks quickbooks_online_official_docs policy")
	return ExternalSourceDescriptor{}
}

// integrationAttachExternalVerificationReceipts models the process-minted,
// run-scoped evidence required for every external row in a complete snapshot.
// The fixture deliberately builds this evidence from the sealed object tuple;
// it does not treat a source coordinate as authorization or as a receipt.
func integrationAttachExternalVerificationReceipts(t *testing.T, batch *MaterializationBatch) {
	t.Helper()
	policy := integrationDocsPolicy(t)
	fingerprint, err := externalPolicyFingerprint(policy)
	if err != nil {
		t.Fatal(err)
	}
	receipts := make([]*stagedExternalVerificationReceipt, 0, len(batch.Objects))
	for _, object := range batch.Objects {
		if _, external := externalReferenceObjectClasses[object.ObjectClass]; !external {
			continue
		}
		version, err := ParseVersionCoordinate(object.VersionCoordinate)
		if err != nil {
			t.Fatal(err)
		}
		observed := time.Now().UTC()
		coordinate := ArtifactSourceCoordinate{
			SourceAuthorityID: object.SourceAuthorityID, SourceArtifactClass: object.SourceArtifactClass,
			SourceRefKind: object.SourceRefKind, SourceStableReference: object.SourceStableReference,
			VersionCoordinate: object.VersionCoordinate, SectionPath: object.SectionPath,
			SourceContentHash: object.SourceContentHash, SourceContentHashOwner: object.SourceContentHashOwner,
			RetrievedAt: observed.Format(time.RFC3339Nano), LicenseEvidence: quickBooksTestRetrievalPermissionEvidence,
		}
		canonicalReference, err := externalResourceReference(object.SourceStableReference, policy)
		if err != nil {
			t.Fatal(err)
		}
		auth := validTestExternalAuthorization(object.OrganizationID, object.ObjectClass, policy, coordinate, observed, externalBodyCustodyAGFS)
		receipt := &stagedExternalVerificationReceipt{
			ReceiptVersion: stagedExternalReceiptVersion, CanonicalReference: canonicalReference,
			VerifiedSourceStableReference: object.SourceStableReference, RetrievedAt: coordinate.RetrievedAt,
			ByteLength: 1, SHA256: object.SourceContentHash, TransportStatus: "success",
			TransportRawHashAlgorithm: "sha256", ContentCoding: "identity", TransportResponseMetadataDigest: strings.Repeat("c", 64),
			DecodedByteLength: 1, DecodedSHA256: object.SourceContentHash, SourceRepresentationMediaType: "text/html",
			SourceContentHashAlgorithm: "sha256", SourceContentHashProfile: externalEvidenceHashProfile,
			LicenseEvidence: coordinate.LicenseEvidence, SourceRegistryID: policy.ID, SourceAuthorityID: object.SourceAuthorityID,
			PolicyFingerprint: fingerprint, ObjectClass: object.ObjectClass, CanonicalName: version.StableName,
			LocatorKind: "html_id_or_name", FinalVersionCoordinate: object.VersionCoordinate, Authorization: auth,
		}
		receipt.Archive = testExternalArchiveReceipt(auth, receipt.DecodedByteLength, receipt.DecodedSHA256)
		receipts = append(receipts, receipt)
	}
	batch.ExternalVerificationReceipts = receipts
	integrationRefreshBatchSourceSet(t, batch)
}

func integrationRebindBatch(t *testing.T, source MaterializationBatch) MaterializationBatch {
	t.Helper()
	batch := source
	batch.Run = source.Run
	batch.Snapshot = source.Snapshot
	batch.Objects = append([]GraphObject(nil), source.Objects...)
	batch.Symbols = append([]GraphSymbol(nil), source.Symbols...)
	batch.Edges = append([]GraphEdge(nil), source.Edges...)
	batch.Violations = append([]Violation(nil), source.Violations...)
	batch.ProjectionArtifacts = append([]ProjectionArtifact(nil), source.ProjectionArtifacts...)
	batch.StagingConceptPromotions = nil
	batch.StagingEdgePromotions = nil
	batch.Run.MaterializationRunID = uuid.NewString()
	batch.Run.State = "running"
	batch.Run.TargetGraphSnapshotID = ""
	batch.Run.FinishedAt = nil
	batch.Run.StartedAt = time.Now().UTC()
	batch.Snapshot.GraphSnapshotID = uuid.NewString()
	batch.Snapshot.MaterializationRunID = ""
	batch.Snapshot.SnapshotState = "building"
	batch.Snapshot.SealedAt = nil
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
	return batch
}

func integrationRefreshBatchSourceSet(t *testing.T, batch *MaterializationBatch) []SourceCoordinate {
	t.Helper()
	coords := make([]SourceCoordinate, 0, len(batch.Objects))
	for _, object := range batch.Objects {
		coords = append(coords, SourceCoordinate{
			OrganizationID:        object.OrganizationID,
			SourceAuthorityID:     object.SourceAuthorityID,
			SourceArtifactClass:   object.SourceArtifactClass,
			SourceRefKind:         object.SourceRefKind,
			SourceStableReference: object.SourceStableReference,
			VersionCoordinate:     object.VersionCoordinate,
			SectionPath:           object.SectionPath,
			SourceContentHash:     object.SourceContentHash,
		})
	}
	hash, err := ComputeSourceSetHash(batch.Run.OrganizationID, coords)
	if err != nil {
		t.Fatalf("ComputeSourceSetHash: %v", err)
	}
	set, err := BuildSourceSetWithExternalReceipts(batch.Run.OrganizationID, coords, batch.ExternalVerificationReceipts)
	if err != nil {
		t.Fatal(err)
	}
	batch.Run.InputSourceSetHash = hash
	batch.Run.InputSourceSet = set
	batch.Snapshot.SourceSetHash = hash
	batch.Snapshot.SourceSet = set
	return coords
}

func integrationRetargetExternalVersion(t *testing.T, batch *MaterializationBatch, stableReference, versionToken, contentHash string) {
	t.Helper()
	if len(batch.Objects) != 1 || len(batch.Symbols) != 0 || len(batch.Edges) != 0 {
		t.Fatal("integrationRetargetExternalVersion requires a one-object batch")
	}
	object := &batch.Objects[0]
	object.SourceStableReference = stableReference
	_ = versionToken // content-digest mode owns the final token
	object.VersionCoordinate = "source:" + bootstrapSourceAuthority + ":quickbooks_online_invoice_reference@sha256_" + contentHash
	object.SourceContentHash = contentHash
	object.SourceContentHashOwner = bootstrapSourceAuthority
	object.GraphObjectID = uuid.NewSHA1(oodGraphIDNamespace, []byte("object|"+object.OrganizationID+"|"+object.ObjectClass+"|"+object.SourceAuthorityID+"|"+object.SourceRefKind+"|"+object.SourceStableReference+"|"+object.VersionCoordinate+"|"+object.SectionPath)).String()
	object.GraphAddress = (GraphAddress{
		ObjectClass: object.ObjectClass, SourceAuthorityID: object.SourceAuthorityID, SourceRefKind: object.SourceRefKind,
		SourceRef: object.SourceStableReference, VersionCoordinate: object.VersionCoordinate, SectionPath: object.SectionPath,
	}).String()
	object.SearchPayload["graph_address"] = object.GraphAddress
	object.SearchPayload["source_stable_reference"] = object.SourceStableReference
	object.SearchPayload["version_coordinate"] = object.VersionCoordinate
	coordinate := ArtifactSourceCoordinate{
		SourceAuthorityID: object.SourceAuthorityID, SourceArtifactClass: object.SourceArtifactClass,
		SourceRefKind: object.SourceRefKind, SourceStableReference: object.SourceStableReference,
		VersionCoordinate: object.VersionCoordinate, SectionPath: object.SectionPath,
		SourceContentHash: object.SourceContentHash, SourceContentHashOwner: object.SourceContentHashOwner,
	}
	policy := ExternalSourceDescriptor{ID: "quickbooks_online_official_docs"}
	object.SearchText = externalReferenceSearchText(object.ObjectClass, coordinate, policy)
	integrationRefreshBatchSourceSet(t, batch)
}

func integrationRebindOrganization(t *testing.T, batch *MaterializationBatch, orgID string) {
	t.Helper()
	if len(batch.Objects) != 1 || len(batch.Symbols) != 0 || len(batch.Edges) != 0 {
		t.Fatal("integrationRebindOrganization requires a one-object batch")
	}
	batch.Run.OrganizationID = orgID
	batch.Snapshot.OrganizationID = orgID
	object := &batch.Objects[0]
	object.OrganizationID = orgID
	object.GraphObjectID = uuid.NewSHA1(oodGraphIDNamespace, []byte("object|"+orgID+"|"+object.ObjectClass+"|"+object.SourceAuthorityID+"|"+object.SourceRefKind+"|"+object.SourceStableReference+"|"+object.VersionCoordinate+"|"+object.SectionPath)).String()
	integrationRefreshBatchSourceSet(t, batch)
}

func integrationSetLegacyProfile(batch *MaterializationBatch) {
	set := map[string]interface{}{}
	for key, value := range batch.Run.InputSourceSet {
		set[key] = value
	}
	set["materialization_profile_version"] = "ood_graph_protocol_v1/materialization/5"
	batch.Run.InputSourceSet = set
	batch.Snapshot.SourceSet = set
}

func integrationAppendObject(t *testing.T, batch *MaterializationBatch, versionToken, contentHash string) GraphObject {
	t.Helper()
	other := integrationMaterializationBatch(t, versionToken, contentHash)
	object := other.Objects[0]
	object.GraphSnapshotID = batch.Snapshot.GraphSnapshotID
	object.MaterializationRunID = batch.Run.MaterializationRunID
	batch.Objects = append(batch.Objects, object)
	integrationAttachExternalVerificationReceipts(t, batch)
	return object
}

func integrationAddReciprocalObjectEdges(t *testing.T, batch *MaterializationBatch) {
	t.Helper()
	if len(batch.Objects) < 2 {
		t.Fatal("integrationAddReciprocalObjectEdges requires two objects")
	}
	// The external-edge registry deliberately forbids generic dependency
	// labels for external reference pages. Make the fixture use two closed
	// external-reference contracts rather than widening that registry.
	target := &batch.Objects[1]
	target.ObjectClass = "api_symbol"
	target.GraphObjectID = uuid.NewSHA1(oodGraphIDNamespace, []byte("object|"+target.OrganizationID+"|api_symbol|"+target.SourceAuthorityID+"|"+target.SourceRefKind+"|"+target.SourceStableReference+"|"+target.VersionCoordinate+"|"+target.SectionPath)).String()
	target.GraphAddress = (GraphAddress{ObjectClass: target.ObjectClass, SourceAuthorityID: target.SourceAuthorityID, SourceRefKind: target.SourceRefKind, SourceRef: target.SourceStableReference, VersionCoordinate: target.VersionCoordinate, SectionPath: target.SectionPath}).String()
	coord := ArtifactSourceCoordinate{SourceAuthorityID: target.SourceAuthorityID, SourceArtifactClass: target.SourceArtifactClass, SourceRefKind: target.SourceRefKind, SourceStableReference: target.SourceStableReference, VersionCoordinate: target.VersionCoordinate, SectionPath: target.SectionPath, SourceContentHash: target.SourceContentHash, SourceContentHashOwner: target.SourceContentHashOwner}
	policy := integrationDocsPolicy(t)
	target.SearchPayload = externalReferenceSearchPayload(target.ObjectClass, target.GraphAddress, coord, policy)
	target.SearchText = externalReferenceSearchText(target.ObjectClass, coord, policy)
	integrationAttachExternalVerificationReceipts(t, batch)

	documents := resolutionTestLabel("documents", "external_reference", []string{"external_reference_doc", "reference_page"}, []string{"doc_object", "doc_version", "section", "symbol", "config", "circuit", "schema", "sentinel", "invariant", "assumption", "api_symbol", "code_example", "release_note", "code_symbol_ref"}, "")
	defines := resolutionTestLabel("defines_external_symbol", "external_reference", []string{"reference_page", "source_repo"}, []string{"api_symbol", "code_symbol_ref"}, "")
	edges, violations := ResolveEdgeEndpointsInBatch(batch.Run.OrganizationID, batch.Run.MaterializationRunID, batch.Snapshot.GraphSnapshotID, batch.Objects, []PendingEdge{
		{SourceEndpointID: batch.Objects[0].GraphObjectID, TargetEndpointID: target.GraphObjectID, Label: documents, AuthoringSourcePath: "$.relationships[0]", SourceAuthorityID: batch.Objects[0].SourceAuthorityID},
		{SourceEndpointID: batch.Objects[0].GraphObjectID, TargetEndpointID: target.GraphObjectID, Label: defines, AuthoringSourcePath: "$.relationships[1]", SourceAuthorityID: batch.Objects[0].SourceAuthorityID},
	})
	if len(violations) != 0 || len(edges) != 2 {
		t.Fatalf("resolve reciprocal fixture edges=%d violations=%+v", len(edges), violations)
	}
	batch.Edges = edges
}

func integrationMarkStagingRunLintPass(ctx context.Context, t *testing.T, client *spanner.Client, runID string) {
	t.Helper()
	_, err := client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		n, err := tx.Update(ctx, spanner.Statement{
			SQL: `UPDATE staging_concepts
SET lint_status='pass', pipeline_state='linted', updated_at=PENDING_COMMIT_TIMESTAMP()
WHERE organization_id=@org AND ingestion_run_id=@run`,
			Params: map[string]interface{}{"org": "test-org", "run": runID},
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("no staged rows for run %s", runID)
		}
		if _, err := tx.Update(ctx, spanner.Statement{
			SQL: `UPDATE staging_edges
SET lint_status='pass', pipeline_state='linted', updated_at=PENDING_COMMIT_TIMESTAMP()
WHERE organization_id=@org AND ingestion_run_id=@run`,
			Params: map[string]interface{}{"org": "test-org", "run": runID},
		}); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("mark staging run %s lint pass: %v", runID, err)
	}
}

func integrationImportOrdinarySections(ctx context.Context, t *testing.T, env *Env, names ...string) ImportResult {
	t.Helper()
	submissions := make([]ArtifactSubmission, 0, len(names))
	for _, name := range names {
		submissions = append(submissions, ArtifactSubmission{
			ArtifactType: "section", OrganizationID: "test-org", NodeKind: "section", StableID: name,
		})
	}
	result, err := handleImport(ctx, env, importInput{Submissions: submissions})
	if err != nil {
		t.Fatalf("import ordinary section fixtures: %v", err)
	}
	if result.Admitted != len(names) || len(result.OrderedIDs) != len(names) || result.GraphSnapshotID == "" {
		t.Fatalf("ordinary section fixture result=%+v", result)
	}
	return result
}

// TestIntegrationAdmitAndRead admits a node via the ceremony, reads it back,
// confirms the contract + payload + admission provenance round-trip.
func TestIntegrationAdmitAndRead(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	env := integrationEnv(t)
	defer env.Substrates.Close()

	sub := ArtifactSubmission{
		ArtifactType:   "axiom",
		OrganizationID: "test-org",
		NodeKind:       "axiom",
		Contract:       map[string]interface{}{"asserts": "test contract"},
		Payload:        map[string]interface{}{"title": "Test Axiom"},
	}
	rec, err := AdmitArtifact(ctx, env, sub)
	if err != nil {
		t.Fatalf("AdmitArtifact: %v", err)
	}
	if rec.ArtifactID == "" {
		t.Fatal("expected ArtifactID minted")
	}
	if rec.ArtifactVersion != 1 {
		t.Errorf("ArtifactVersion = %d, want 1", rec.ArtifactVersion)
	}
	if rec.DefinitionHash == "" || rec.ManifestHash == "" {
		t.Errorf("expected hashes populated, got def=%q man=%q", rec.DefinitionHash, rec.ManifestHash)
	}
	if rec.IsNonGenesis {
		t.Error("expected IsNonGenesis=false for EXPERIMENTAL_BOOTSTRAP")
	}

	got, err := readNodeAcrossSubstrates(ctx, env, rec.ArtifactID, "", "")
	if err != nil {
		t.Fatalf("readNodeAcrossSubstrates: %v", err)
	}
	if got.NodeKind != "axiom" {
		t.Errorf("NodeKind = %q, want axiom", got.NodeKind)
	}
	if got.Status != "active" {
		t.Errorf("Status = %q, want active", got.Status)
	}
	contractMap := got.CurrentVersion.Contract
	if contractMap["asserts"] != "test contract" {
		t.Errorf("Contract.asserts = %v, want 'test contract'", contractMap["asserts"])
	}
}

// TestIntegrationReciprocityAtomic exercises the public OOD link surface.
// A legacy partial predecessor is expanded into a complete immutable
// successor containing both endpoints and the reciprocal edge pair; retrying
// the same link publishes another complete snapshot without duplicate edges.
func TestIntegrationReciprocityAtomic(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter := adapters[0].(*SpannerSubstrateAdapter)
	seed := integrationImportOrdinarySections(ctx, t, env, "finance_link_source", "finance_link_target")

	link := linkInput{SourceID: seed.OrderedIDs[0], TargetID: seed.OrderedIDs[1], EdgeLabel: "depends_on"}
	first, err := handleLink(ctx, env, link)
	if err != nil {
		t.Fatalf("handleLink first: %v", err)
	}
	second, err := handleLink(ctx, env, link)
	if err != nil {
		t.Fatalf("handleLink idempotent retry: %v", err)
	}
	client, err := adapter.getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range []AdmissionRecord{first, second} {
		runRow, err := client.Single().ReadRow(ctx, "OODGraphMaterializationRuns", spanner.Key{"test-org", rec.RunID}, []string{"target_graph_snapshot_id", "state", "object_count", "edge_count", "input_source_set"})
		if err != nil {
			t.Fatal(err)
		}
		var snapshotID, state string
		var objectCount, edgeCount int64
		var sourceSet spanner.NullJSON
		if err := runRow.Columns(&snapshotID, &state, &objectCount, &edgeCount, &sourceSet); err != nil {
			t.Fatal(err)
		}
		if state != "sealed" || objectCount != 2 || edgeCount != 2 {
			t.Errorf("link run=%q snapshot=%q state/counts=%q/%d/%d, want sealed/2/2", rec.RunID, snapshotID, state, objectCount, edgeCount)
		}
		edgeIter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT graph_edge_id, edge_label, inverse_edge_id, reciprocity_state, search_text, search_payload, embedding, embedding_model FROM OODGraphEdges WHERE organization_id=@org AND graph_snapshot_id=@snapshot ORDER BY edge_label`, Params: map[string]interface{}{"org": "test-org", "snapshot": snapshotID}})
		persisted := map[string]struct{ id, inverse, state string }{}
		for {
			row, err := edgeIter.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				edgeIter.Stop()
				t.Fatal(err)
			}
			var id, label, inverseID, reciprocity, searchText, embeddingModel string
			var searchPayload spanner.NullJSON
			var embedding []float32
			if err := row.Columns(&id, &label, &inverseID, &reciprocity, &searchText, &searchPayload, &embedding, &embeddingModel); err != nil {
				edgeIter.Stop()
				t.Fatal(err)
			}
			payload := jsonValueToMap(searchPayload.Value)
			if searchText != fmt.Sprintf("%s section section", label) || !searchPayload.Valid || len(payload) != 4 || payload["edge_label"] != label || payload["edge_family"] != "dependency" || len(embedding) != externalReferenceEmbeddingDimensions || embeddingModel != "gemini-embedding-001" {
				edgeIter.Stop()
				t.Fatalf("link retrieval metadata label=%q text=%q payload=%#v dimensions=%d model=%q", label, searchText, payload, len(embedding), embeddingModel)
			}
			persisted[label] = struct{ id, inverse, state string }{id, inverseID, reciprocity}
		}
		edgeIter.Stop()
		if len(persisted) != 2 || persisted["depends_on"].inverse != persisted["load_bearing_for"].id || persisted["load_bearing_for"].inverse != persisted["depends_on"].id || persisted["depends_on"].state != "complete" || persisted["load_bearing_for"].state != "complete" {
			t.Errorf("reciprocal link rows=%+v", persisted)
		}
		encoded, err := json.Marshal(sourceSet.Value)
		if err != nil || !strings.Contains(string(encoded), `"edge_label":"depends_on"`) || !strings.Contains(string(encoded), `"edge_label":"load_bearing_for"`) {
			t.Errorf("link source_set lacks authoring coordinates: %s err=%v", encoded, err)
		}
	}
	var seedObjects, seedEdges int64
	for table, target := range map[string]*int64{"OODGraphObjects": &seedObjects, "OODGraphEdges": &seedEdges} {
		iter := client.Single().Query(ctx, spanner.Statement{SQL: "SELECT COUNT(*) FROM " + table + " WHERE organization_id=@org AND graph_snapshot_id=@snapshot", Params: map[string]interface{}{"org": "test-org", "snapshot": seed.GraphSnapshotID}})
		row, err := iter.Next()
		if err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		if err := row.Columns(target); err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		iter.Stop()
	}
	if seedObjects != 2 || seedEdges != 0 {
		t.Fatalf("historical seed mutated: objects=%d edges=%d", seedObjects, seedEdges)
	}
}

func TestIntegrationLinkEmbeddingFailureDoesNotOpenRun(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter := adapters[0].(*SpannerSubstrateAdapter)
	seed := integrationImportOrdinarySections(ctx, t, env, "finance_link_failure_source", "finance_link_failure_target")
	client, err := adapter.getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	countRuns := func() int64 {
		iter := client.Single().Query(ctx, spanner.Statement{SQL: "SELECT COUNT(*) FROM OODGraphMaterializationRuns WHERE organization_id=@org", Params: map[string]interface{}{"org": "test-org"}})
		defer iter.Stop()
		r, err := iter.Next()
		if err != nil {
			t.Fatal(err)
		}
		var count int64
		if err := r.Columns(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	before := countRuns()
	env.Embed = fixedEmbeddingClient{dimensions: externalReferenceEmbeddingDimensions, err: errors.New("embedding unavailable")}
	_, err = handleLink(ctx, env, linkInput{SourceID: seed.OrderedIDs[0], TargetID: seed.OrderedIDs[1], EdgeLabel: "depends_on"})
	if err == nil || !strings.Contains(err.Error(), "embedding unavailable") {
		t.Fatalf("handleLink error=%v, want embedding failure", err)
	}
	if after := countRuns(); after != before {
		t.Fatalf("embedding failure opened a run: before=%d after=%d", before, after)
	}
}

// TestIntegrationDiffRFC6902 verifies the RFC 6902 diff shape over two
// versions of one node.
func TestIntegrationDiffRFC6902(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	env := integrationEnv(t)
	defer env.Substrates.Close()

	rec1, err := AdmitArtifact(ctx, env, ArtifactSubmission{
		ArtifactType: "axiom", OrganizationID: "test-org", NodeKind: "axiom",
		Contract: map[string]interface{}{"asserts": "v1"},
		Payload:  map[string]interface{}{"title": "v1"},
	})
	if err != nil {
		t.Fatalf("admit v1: %v", err)
	}

	// Read v1 to seed PriorVersion for v2.
	v1Node, err := readNodeAcrossSubstrates(ctx, env, rec1.ArtifactID, "", "")
	if err != nil {
		t.Fatalf("read v1: %v", err)
	}

	_, err = AdmitArtifact(ctx, env, ArtifactSubmission{
		ArtifactType:   "axiom",
		OrganizationID: "test-org",
		NodeKind:       "axiom",
		StableID:       rec1.ArtifactID,
		Contract:       map[string]interface{}{"asserts": "v2", "added": "new"},
		Payload:        map[string]interface{}{"title": "v2"},
		PriorVersion:   &v1Node.CurrentVersion,
	})
	if err != nil {
		t.Fatalf("admit v2: %v", err)
	}

	diff, err := handleDiff(ctx, env, diffInput{
		NodeID: rec1.ArtifactID, VersionA: "1", VersionB: "2",
	})
	if err != nil {
		t.Fatalf("handleDiff: %v", err)
	}
	if diff.Identical {
		t.Error("expected diff to be non-identical")
	}
	if len(diff.Operations) == 0 {
		t.Fatal("expected RFC 6902 operations")
	}
	// Look for a replace or add op at /contract/asserts.
	foundAssertsChange := false
	for _, op := range diff.Operations {
		if strings.HasPrefix(op.Path, "/contract") && (op.Op == "replace" || op.Op == "add") {
			b, _ := json.Marshal(op.Value)
			if strings.Contains(string(b), "v2") || strings.Contains(string(b), "new") {
				foundAssertsChange = true
				break
			}
		}
	}
	if !foundAssertsChange {
		t.Errorf("expected /contract path change reflecting v1→v2, got operations=%+v", diff.Operations)
	}
}

// TestIntegrationImportAtomicAllOrNone is the regression test for the §3.6
// all-or-none property: when handleImport receives a batch where one
// submission fails ceremony validation (Phase 1 prepare), ZERO rows commit
// to the substrate. Under the pre-fix per-submission AdmitArtifact loop, the
// submissions ordered before the malformed one would have committed
// individually; under the Prepare-then-batch-Commit fix, none do.
func TestIntegrationImportAtomicAllOrNone(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	env := integrationEnv(t)
	defer env.Substrates.Close()

	in := importInput{
		Submissions: []ArtifactSubmission{
			{ArtifactType: "axiom", OrganizationID: "test-org", NodeKind: "axiom",
				Contract: map[string]interface{}{"asserts": "n1"}, Payload: map[string]interface{}{"title": "n1"}},
			{ArtifactType: "axiom", OrganizationID: "test-org", NodeKind: "axiom",
				Contract: map[string]interface{}{"asserts": "n2"}, Payload: map[string]interface{}{"title": "n2"}},
			{ArtifactType: "axiom", OrganizationID: "test-org", NodeKind: "axiom",
				Contract: map[string]interface{}{"asserts": "n3"}, Payload: map[string]interface{}{"title": "n3"}},
			// Malformed: no node_kind, no edge_label. The import boundary
			// refuses it before preparation. The three valid submissions are ordered
			// before this one (no $refs → input-order preserved by Kahn).
			{OrganizationID: "test-org"},
		},
	}
	res, err := handleImport(ctx, env, in)
	if err == nil {
		t.Fatalf("expected handleImport error on malformed submission; got nil; result=%+v", res)
	}
	if !strings.Contains(err.Error(), "node_kind required") {
		t.Errorf("expected node-kind admission refusal; got: %v", err)
	}
	if res.Admitted != 0 {
		t.Errorf("Admitted = %d, want 0 (all-or-none per REQUIREMENTS.md §3.6)", res.Admitted)
	}

	// Confirm zero Nodes rows hit the substrate.
	adapters, err := env.Substrates.All(ctx)
	if err != nil {
		t.Fatalf("substrates.All: %v", err)
	}
	if len(adapters) != 1 {
		t.Fatalf("expected 1 substrate, got %d", len(adapters))
	}
	nodes, err := adapters[0].ListNodes(ctx, ListFilter{
		Status:         "active",
		OrganizationID: "test-org",
		Limit:          100,
	})
	if err != nil {
		t.Fatalf("ListNodes: %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes committed after aborted batch, got %d (rows: %+v)", len(nodes), nodes)
	}
}

// TestIntegrationImportHappyPathBatch verifies the success case of the
// Prepare-then-batch-Commit pattern: a valid N-submission batch yields N
// rows committed and the result struct correctly reports both Total and
// Admitted.
func TestIntegrationImportHappyPathBatch(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()

	in := importInput{
		Submissions: []ArtifactSubmission{
			{ArtifactType: "section", OrganizationID: "test-org", NodeKind: "section", StableID: "import_h1",
				Contract: map[string]interface{}{"asserts": "h1"}, Payload: map[string]interface{}{"title": "h1"}},
			{ArtifactType: "section", OrganizationID: "test-org", NodeKind: "section", StableID: "import_h2",
				Contract: map[string]interface{}{"asserts": "h2"}, Payload: map[string]interface{}{"title": "h2"}},
			{ArtifactType: "section", OrganizationID: "test-org", NodeKind: "section", StableID: "import_h3",
				Contract: map[string]interface{}{"asserts": "h3"}, Payload: map[string]interface{}{"title": "h3"}},
		},
	}
	res, err := handleImport(ctx, env, in)
	if err != nil {
		t.Fatalf("handleImport: %v", err)
	}
	if res.Total != 3 {
		t.Errorf("Total = %d, want 3", res.Total)
	}
	if res.Admitted != 3 {
		t.Errorf("Admitted = %d, want 3", res.Admitted)
	}
	if len(res.OrderedIDs) != 3 {
		t.Errorf("OrderedIDs len = %d, want 3", len(res.OrderedIDs))
	}

	objects, err := handleOODList(ctx, env, oodListInput{ObjectClass: "section", Limit: 100})
	if err != nil {
		t.Fatalf("typed OOD list: %v", err)
	}
	if len(objects.Rows) != 3 {
		t.Errorf("expected 3 OOD graph objects committed, got %d", len(objects.Rows))
	}
}

// TestIntegrationOODGraphMaterializationLifecycle is the schema-v2 safety
// gate. It verifies the real Spanner mutation/query path for the contracts
// that were previously hidden by the legacy three-table integration schema:
// open-run typed NULLs, open→sealed UPDATE, source_set_hash persistence, and
// organization-scoped monotonic graph_version assignment.
func TestIntegrationOODGraphMaterializationLifecycle(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()

	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter, ok := adapters[0].(*SpannerSubstrateAdapter)
	if !ok {
		t.Fatalf("adapter type=%T, want *SpannerSubstrateAdapter", adapters[0])
	}
	client, err := adapter.getClient(ctx)
	if err != nil {
		t.Fatalf("spanner client: %v", err)
	}

	first := integrationMaterializationBatch(t, "sha256_lifecycle_first", strings.Repeat("1", 64))
	if err := adapter.OpenMaterializationRun(ctx, first.Run); err != nil {
		t.Fatalf("OpenMaterializationRun(first): %v", err)
	}

	// Open-run evidence: target snapshot and finished_at must be typed SQL
	// NULL, not wall-clock placeholders. Counts begin at zero.
	openRow, err := client.Single().ReadRow(ctx, "OODGraphMaterializationRuns",
		spanner.Key{"test-org", first.Run.MaterializationRunID},
		[]string{"target_graph_snapshot_id", "state", "started_at", "finished_at", "object_count", "symbol_count", "edge_count", "violation_count", "input_source_set_hash"})
	if err != nil {
		t.Fatalf("read open run: %v", err)
	}
	var openTarget spanner.NullString
	var openState string
	var openStarted time.Time
	var openFinished spanner.NullTime
	var objectCount, symbolCount, edgeCount, violationCount int64
	var openSourceSetHash string
	if err := openRow.Columns(&openTarget, &openState, &openStarted, &openFinished, &objectCount, &symbolCount, &edgeCount, &violationCount, &openSourceSetHash); err != nil {
		t.Fatalf("decode open run: %v", err)
	}
	if openTarget.Valid {
		t.Errorf("open target_graph_snapshot_id=%q, want typed NULL", openTarget.StringVal)
	}
	if openFinished.Valid {
		t.Errorf("open finished_at=%v, want typed NULL", openFinished.Time)
	}
	if openState != "running" || openStarted.IsZero() {
		t.Errorf("open state/started_at = %q/%v, want running/non-zero", openState, openStarted)
	}
	if objectCount != 0 || symbolCount != 0 || edgeCount != 0 || violationCount != 0 {
		t.Errorf("open counts=(%d,%d,%d,%d), want all zero", objectCount, symbolCount, edgeCount, violationCount)
	}
	if openSourceSetHash != first.Run.InputSourceSetHash {
		t.Errorf("open input_source_set_hash=%q, want %q", openSourceSetHash, first.Run.InputSourceSetHash)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(openSourceSetHash) {
		t.Errorf("open input_source_set_hash=%q, want 64-character lowercase SHA-256", openSourceSetHash)
	}

	if err := adapter.CommitMaterializationRun(ctx, first); err != nil {
		t.Fatalf("CommitMaterializationRun(first): %v", err)
	}
	sealedRow, err := client.Single().ReadRow(ctx, "OODGraphMaterializationRuns",
		spanner.Key{"test-org", first.Run.MaterializationRunID},
		[]string{"target_graph_snapshot_id", "state", "started_at", "finished_at", "object_count", "input_source_set_hash", "input_source_set"})
	if err != nil {
		t.Fatalf("read sealed run: %v", err)
	}
	var sealedTarget spanner.NullString
	var sealedState string
	var sealedStarted time.Time
	var sealedFinished spanner.NullTime
	var sealedObjectCount int64
	var sealedSourceSetHash string
	var sealedSourceSet spanner.NullJSON
	if err := sealedRow.Columns(&sealedTarget, &sealedState, &sealedStarted, &sealedFinished, &sealedObjectCount, &sealedSourceSetHash, &sealedSourceSet); err != nil {
		t.Fatalf("decode sealed run: %v", err)
	}
	if !sealedTarget.Valid || sealedTarget.StringVal != first.Snapshot.GraphSnapshotID {
		t.Errorf("sealed target_graph_snapshot_id=%+v, want %q", sealedTarget, first.Snapshot.GraphSnapshotID)
	}
	if sealedState != "sealed" || !sealedFinished.Valid {
		t.Errorf("sealed state/finished_at=%q/%+v, want sealed/non-null", sealedState, sealedFinished)
	}
	if !sealedStarted.Equal(openStarted) {
		t.Errorf("seal rewrote started_at: open=%v sealed=%v", openStarted, sealedStarted)
	}
	if sealedObjectCount != 1 {
		t.Errorf("sealed object_count=%d, want 1", sealedObjectCount)
	}
	if sealedSourceSetHash != first.Run.InputSourceSetHash || !sealedSourceSet.Valid {
		t.Errorf("sealed source-set evidence hash/json=%q/%+v, want %q/valid", sealedSourceSetHash, sealedSourceSet, first.Run.InputSourceSetHash)
	}

	// Reconstruct the source coordinate from the persisted JSON and recompute
	// the digest. This catches writes that bind the run/snapshot to a hash
	// unrelated to their persisted source set.
	persistedMap := jsonValueToMap(sealedSourceSet.Value)
	persistedCoords, ok := persistedMap["coordinates"].([]interface{})
	if !ok || len(persistedCoords) != 1 {
		t.Fatalf("persisted source_set coordinates=%#v, want one", persistedMap["coordinates"])
	}
	coordMap, ok := persistedCoords[0].(map[string]interface{})
	if !ok {
		t.Fatalf("persisted coordinate type=%T, want map", persistedCoords[0])
	}
	reconstructed := SourceCoordinate{
		OrganizationID:        "test-org",
		SourceAuthorityID:     asString(coordMap["source_authority_id"]),
		SourceArtifactClass:   asString(coordMap["source_artifact_class"]),
		SourceRefKind:         asString(coordMap["source_ref_kind"]),
		SourceStableReference: asString(coordMap["source_stable_reference"]),
		VersionCoordinate:     asString(coordMap["version_coordinate"]),
		SectionPath:           asString(coordMap["section_path"]),
		SourceContentHash:     asString(coordMap["source_content_hash"]),
	}
	recomputedHash, err := ComputeSourceSetHash("test-org", []SourceCoordinate{reconstructed})
	if err != nil {
		t.Fatalf("recompute persisted source_set_hash: %v", err)
	}
	if recomputedHash != sealedSourceSetHash {
		t.Errorf("persisted source_set_hash=%q, recomputed=%q", sealedSourceSetHash, recomputedHash)
	}
	snapshotRow, err := client.Single().ReadRow(ctx, "OODGraphSnapshots",
		spanner.Key{"test-org", first.Snapshot.GraphSnapshotID},
		[]string{"graph_version", "source_set_hash", "materialization_run_id", "snapshot_state", "sealed_at"})
	if err != nil {
		t.Fatalf("read first snapshot: %v", err)
	}
	var firstGraphVersion int64
	var snapshotSourceSetHash string
	var snapshotRunID spanner.NullString
	var snapshotState string
	var snapshotSealedAt spanner.NullTime
	if err := snapshotRow.Columns(&firstGraphVersion, &snapshotSourceSetHash, &snapshotRunID, &snapshotState, &snapshotSealedAt); err != nil {
		t.Fatalf("decode first snapshot: %v", err)
	}
	if firstGraphVersion != 1 || snapshotSourceSetHash != recomputedHash || !snapshotRunID.Valid || snapshotRunID.StringVal != first.Run.MaterializationRunID || snapshotState != "sealed" || !snapshotSealedAt.Valid {
		t.Errorf("first snapshot evidence version=%d hash=%q run=%+v state=%q sealed_at=%+v", firstGraphVersion, snapshotSourceSetHash, snapshotRunID, snapshotState, snapshotSealedAt)
	}

	// A failed run remains audit evidence, carries terminal time, and never
	// acquires a target snapshot. This is the failure half of the lifecycle
	// contract that the old three-table harness could not execute.
	failed := integrationMaterializationBatch(t, "sha256_lifecycle_failed", strings.Repeat("f", 64))
	if err := adapter.OpenMaterializationRun(ctx, failed.Run); err != nil {
		t.Fatalf("OpenMaterializationRun(failed): %v", err)
	}
	if err := adapter.FailMaterializationRun(ctx, failed.Run.OrganizationID, failed.Run.MaterializationRunID); err != nil {
		t.Fatalf("FailMaterializationRun: %v", err)
	}
	failedRow, err := client.Single().ReadRow(ctx, "OODGraphMaterializationRuns",
		spanner.Key{"test-org", failed.Run.MaterializationRunID},
		[]string{"target_graph_snapshot_id", "state", "finished_at", "object_count", "symbol_count", "edge_count", "violation_count"})
	if err != nil {
		t.Fatalf("read failed run: %v", err)
	}
	var failedTarget spanner.NullString
	var failedState string
	var failedFinished spanner.NullTime
	var failedObjects, failedSymbols, failedEdges, failedViolations int64
	if err := failedRow.Columns(&failedTarget, &failedState, &failedFinished, &failedObjects, &failedSymbols, &failedEdges, &failedViolations); err != nil {
		t.Fatalf("decode failed run: %v", err)
	}
	if failedTarget.Valid || failedState != "failed" || !failedFinished.Valid {
		t.Errorf("failed run target/state/finished_at=%+v/%q/%+v, want NULL/failed/non-null", failedTarget, failedState, failedFinished)
	}
	if failedObjects != 0 || failedSymbols != 0 || failedEdges != 0 || failedViolations != 0 {
		t.Errorf("failed run counts=(%d,%d,%d,%d), want all zero", failedObjects, failedSymbols, failedEdges, failedViolations)
	}
	// A terminal failed row cannot later be rewritten to sealed. The seal
	// predicate is the last stage of the transaction, so this assertion also
	// proves all graph/snapshot writes buffered earlier are rolled back.
	if err := adapter.CommitMaterializationRun(ctx, failed); err == nil {
		t.Fatal("CommitMaterializationRun sealed an already-failed run")
	}
	for _, check := range []struct {
		table string
		where string
		param string
		value string
	}{
		{"OODGraphSnapshots", "graph_snapshot_id", "snapshot", failed.Snapshot.GraphSnapshotID},
		{"OODGraphObjects", "materialization_run_id", "run", failed.Run.MaterializationRunID},
	} {
		row := client.Single().Query(ctx, spanner.Statement{
			SQL:    fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE organization_id=@org AND %s=@%s", check.table, check.where, check.param),
			Params: map[string]interface{}{"org": "test-org", check.param: check.value},
		})
		countRow, err := row.Next()
		if err != nil {
			row.Stop()
			t.Fatalf("count rolled-back %s rows: %v", check.table, err)
		}
		var count int64
		if err := countRow.Columns(&count); err != nil {
			row.Stop()
			t.Fatalf("decode rolled-back %s count: %v", check.table, err)
		}
		row.Stop()
		if count != 0 {
			t.Errorf("already-failed commit left %d %s rows, want transaction rollback", count, check.table)
		}
	}

	// Commit two already-open runs concurrently. The transaction that reads
	// MAX(graph_version) must make one writer retry, yielding two distinct,
	// consecutive versions rather than two snapshots both claiming v2.
	second := integrationMaterializationBatch(t, "sha256_lifecycle_second", strings.Repeat("2", 64))
	third := integrationMaterializationBatch(t, "sha256_lifecycle_third", strings.Repeat("3", 64))
	for label, batch := range map[string]MaterializationBatch{"second": second, "third": third} {
		if err := adapter.OpenMaterializationRun(ctx, batch.Run); err != nil {
			t.Fatalf("OpenMaterializationRun(%s): %v", label, err)
		}
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, batch := range []MaterializationBatch{second, third} {
		batch := batch
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- adapter.CommitMaterializationRun(ctx, batch)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent CommitMaterializationRun: %v", err)
		}
	}
	versionsIter := client.Single().Query(ctx, spanner.Statement{
		SQL:    `SELECT graph_version FROM OODGraphSnapshots WHERE organization_id=@org ORDER BY graph_version`,
		Params: map[string]interface{}{"org": "test-org"},
	})
	var versions []int64
	for {
		row, err := versionsIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			versionsIter.Stop()
			t.Fatalf("read graph versions: %v", err)
		}
		var version int64
		if err := row.Columns(&version); err != nil {
			versionsIter.Stop()
			t.Fatalf("decode graph version: %v", err)
		}
		versions = append(versions, version)
	}
	versionsIter.Stop()
	if len(versions) != 3 || versions[0] != 1 || versions[1] != 2 || versions[2] != 3 {
		t.Fatalf("graph_version sequence=%v, want [1 2 3] after two concurrent commits", versions)
	}
}

// TestIntegrationOODGraphInBatchReciprocalEdges proves that endpoints carried
// into a complete successor can be resolved before any successor row commits,
// and that the reciprocal pair lands atomically with cross-linked inverse ids.
// It also executes the typed-NULL validity-bound write path for OODGraphEdges.
func TestIntegrationOODGraphInBatchReciprocalEdges(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()

	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter, ok := adapters[0].(*SpannerSubstrateAdapter)
	if !ok {
		t.Fatalf("adapter type=%T, want *SpannerSubstrateAdapter", adapters[0])
	}
	client, err := adapter.getClient(ctx)
	if err != nil {
		t.Fatalf("spanner client: %v", err)
	}

	seed := integrationImportOrdinarySections(ctx, t, env, "finance_in_batch_source", "finance_in_batch_target")
	record, err := handleLink(ctx, env, linkInput{SourceID: seed.OrderedIDs[0], TargetID: seed.OrderedIDs[1], EdgeLabel: "depends_on"})
	if err != nil {
		t.Fatalf("handleLink reciprocal successor: %v", err)
	}

	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT graph_edge_id, source_endpoint_id, target_endpoint_id,
	       edge_label, reciprocity_state, inverse_edge_id, valid_from, valid_until,
	       graph_snapshot_id, materialization_run_id
	FROM OODGraphEdges
	WHERE organization_id=@org AND materialization_run_id=@run
	ORDER BY edge_label`,
		Params: map[string]interface{}{"org": "test-org", "run": record.RunID},
	})
	type persistedEdge struct {
		id, sourceID, targetID, label, reciprocity, inverseID, snapshotID, runID string
		validFrom, validUntil                                                    spanner.NullTime
	}
	var persisted []persistedEdge
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			iter.Stop()
			t.Fatalf("read reciprocal edges: %v", err)
		}
		var e persistedEdge
		if err := row.Columns(&e.id, &e.sourceID, &e.targetID, &e.label, &e.reciprocity, &e.inverseID, &e.validFrom, &e.validUntil, &e.snapshotID, &e.runID); err != nil {
			iter.Stop()
			t.Fatalf("decode reciprocal edge: %v", err)
		}
		persisted = append(persisted, e)
	}
	iter.Stop()
	if len(persisted) != 2 {
		t.Fatalf("persisted reciprocal edges=%d, want 2", len(persisted))
	}
	byID := map[string]persistedEdge{persisted[0].id: persisted[0], persisted[1].id: persisted[1]}
	for _, e := range persisted {
		if e.reciprocity != "complete" || byID[e.inverseID].inverseID != e.id {
			t.Errorf("edge %q reciprocal evidence state=%q inverse=%q peer=%+v", e.id, e.reciprocity, e.inverseID, byID[e.inverseID])
		}
		if e.validFrom.Valid || e.validUntil.Valid {
			t.Errorf("edge %q validity bounds=%+v/%+v, want typed SQL NULLs", e.id, e.validFrom, e.validUntil)
		}
		if e.snapshotID == "" || e.runID != record.RunID {
			t.Errorf("edge %q escaped batch snapshot/run: snapshot=%q run=%q", e.id, e.snapshotID, e.runID)
		}
	}
	if persisted[0].sourceID != persisted[1].targetID || persisted[0].targetID != persisted[1].sourceID {
		t.Errorf("reciprocal endpoints are not reversed: %+v", persisted)
	}
}

// TestIntegrationExternalRelationshipStagingFailsBeforeIO proves that a
// production-shaped relationship manifest cannot launder an otherwise
// unproven external corpus into staging. The root locator is refused before
// network, embedding, or Spanner writes. Relationship planning and receipt
// materialization success remain covered at pure helper boundaries.
func TestIntegrationExternalRelationshipStagingFailsBeforeIO(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	fetcher := &countingExternalFetcher{delegate: deterministicExternalFetcher{}}
	env.ExternalFetch = fetcher
	embeds := &countingEmbeddingClient{}
	env.Embed = embeds

	submissions, relationships := externalRelationshipCorpus()
	concepts := make([]stagingLoadConcept, 0, len(submissions))
	for _, submission := range submissions {
		concepts = append(concepts, stagingLoadConcept{
			CanonicalName: submission.StableID, NodeKind: submission.NodeKind,
			SourceCoordinate: submission.SourceCoordinate,
		})
	}
	edges := make([]stagingLoadEdge, 0, len(relationships))
	for _, relationship := range relationships {
		edges = append(edges, stagingLoadEdge{
			EdgeLabel: relationship.EdgeLabel, SourceCanonicalName: relationship.SourceCanonicalName,
			TargetCanonicalName: relationship.TargetCanonicalName,
		})
	}
	_, err := handleStagingLoad(ctx, env, stagingLoadInput{
		ConceptDomain: "quickbooks_online_external_reference",
		SourceFile:    "official_intuit_machine_sources",
		Concepts:      concepts, Edges: edges,
	})
	if !errors.Is(err, ErrOODGraphExternalRetrievalPermissionProofUnavailable) {
		t.Fatalf("handleStagingLoad error=%v, want typed retrieval-permission refusal", err)
	}
	if fetcher.calls != 0 || embeds.calls != 0 {
		t.Fatalf("refused relationship corpus reached downstream I/O: fetches=%d embeds=%d", fetcher.calls, embeds.calls)
	}

	adapter, err := env.Substrates.ByID("test_substrate")
	if err != nil {
		t.Fatal(err)
	}
	client, err := adapter.(*SpannerSubstrateAdapter).getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"staging_concepts", "staging_edges"} {
		iter := client.Single().Query(ctx, spanner.Statement{
			SQL:    "SELECT COUNT(*) FROM " + table + " WHERE organization_id=@org",
			Params: map[string]interface{}{"org": "test-org"},
		})
		row, err := iter.Next()
		if err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		var rows int64
		if err := row.Columns(&rows); err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		iter.Stop()
		if rows != 0 {
			t.Fatalf("refused relationship corpus wrote %d %s row(s)", rows, table)
		}
	}
}

// TestIntegrationExternalStagingFailsBeforeIO proves the executable public
// posture: a curated coordinate is not itself an admitted retrieval grant,
// and an addressable fragment is not a content-class proof. External staging
// must therefore refuse before network, embedding, or Spanner writes. Pure
// receipt/materialization-boundary tests cover the currently reusable helper
// mechanics without installing a production bypass.
func TestIntegrationExternalStagingFailsBeforeIO(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	loadFetcher := &countingExternalFetcher{delegate: deterministicExternalFetcher{}}
	env.ExternalFetch = loadFetcher
	embeds := &countingEmbeddingClient{}
	env.Embed = embeds

	coord := externalReferenceCoordinate("sha256_emulator_round_trip")
	_, err := handleStagingLoad(ctx, env, stagingLoadInput{
		ConceptDomain: "quickbooks_online_api_reference",
		SourceFile:    "official_intuit_documentation",
		Concepts: []stagingLoadConcept{{
			CanonicalName:    "quickbooks_online_invoice_reference",
			NodeKind:         "reference_page",
			SourceCoordinate: coord,
		}},
	})
	if !errors.Is(err, ErrOODGraphExternalNonGranularProofUnavailable) {
		t.Fatalf("handleStagingLoad error=%v, want typed non-granular proof refusal", err)
	}
	if loadFetcher.calls != 0 || embeds.calls != 0 {
		t.Fatalf("refused external staging reached downstream I/O: fetches=%d embeds=%d", loadFetcher.calls, embeds.calls)
	}

	adapter, err := env.Substrates.ByID("test_substrate")
	if err != nil {
		t.Fatal(err)
	}
	client, err := adapter.(*SpannerSubstrateAdapter).getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	iter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT COUNT(*) FROM staging_concepts WHERE organization_id=@org`, Params: map[string]interface{}{"org": "test-org"}})
	row, err := iter.Next()
	if err != nil {
		iter.Stop()
		t.Fatal(err)
	}
	var staged int64
	if err := row.Columns(&staged); err != nil {
		iter.Stop()
		t.Fatal(err)
	}
	iter.Stop()
	if staged != 0 {
		t.Fatalf("refused external staging wrote %d concept row(s)", staged)
	}
}

func TestIntegrationOrdinaryStagingPromotionRestoresBootstrapCoordinate(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()

	load, err := handleStagingLoad(ctx, env, stagingLoadInput{Concepts: []stagingLoadConcept{{
		CanonicalName: "financial_source_instance_identity",
		NodeKind:      "section",
		Contract:      map[string]interface{}{"canonical_name": "financial_source_instance_identity"},
		Payload:       map[string]interface{}{"scope": "source_neutral_finance_home"},
	}}})
	if err != nil {
		t.Fatalf("stage ordinary concept: %v", err)
	}
	adapter, err := env.Substrates.ByID("test_substrate")
	if err != nil {
		t.Fatal(err)
	}
	client, err := adapter.(*SpannerSubstrateAdapter).getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	integrationMarkStagingRunLintPass(ctx, t, client, load.IngestionRunID)
	promoted, err := handleStagingPromote(ctx, env, stagingPromoteInput{IngestionRunID: load.IngestionRunID})
	if err != nil {
		t.Fatalf("promote ordinary concept: %v", err)
	}
	if promoted.ConceptsPromoted != 1 || promoted.GraphSnapshotID == "" {
		t.Fatalf("promotion=%+v", promoted)
	}
	iter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT object_class, source_authority_id, source_artifact_class, source_ref_kind, source_stable_reference, version_coordinate, section_path FROM OODGraphObjects WHERE organization_id=@org AND graph_snapshot_id=@snapshot AND source_stable_reference=@reference`, Params: map[string]interface{}{"org": "test-org", "snapshot": promoted.GraphSnapshotID, "reference": "financial_source_instance_identity"}})
	row, err := iter.Next()
	if err != nil {
		iter.Stop()
		t.Fatal(err)
	}
	var class, authority, artifactClass, refKind, stableReference, version, section string
	if err := row.Columns(&class, &authority, &artifactClass, &refKind, &stableReference, &version, &section); err != nil {
		iter.Stop()
		t.Fatal(err)
	}
	if _, err := iter.Next(); err != iterator.Done {
		iter.Stop()
		t.Fatalf("ordinary promotion returned trailing row: %v", err)
	}
	iter.Stop()
	if class != "section" || authority != bootstrapSourceAuthority || artifactClass != "section" || refKind != "name" || stableReference != "financial_source_instance_identity" || version != "unversioned" || section != SectionPathRoot {
		t.Fatalf("ordinary promotion source coordinate=%q/%q/%q/%q/%q/%q/%q", class, authority, artifactClass, refKind, stableReference, version, section)
	}
}

func TestIntegrationStagingPromotionRejectsAnyNonDuplicateRowWithoutLintPass(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lintStatus spanner.NullString
		state      string
	}{
		{name: "never_linted", lintStatus: spanner.NullString{}, state: "embedded"},
		{name: "lint_failed", lintStatus: spanner.NullString{StringVal: "fail", Valid: true}, state: "linted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requireEmulator(t)
			ctx := context.Background()
			setupEmulatorDB(ctx, t)
			applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
			env := integrationOODEnv(t)
			defer env.Substrates.Close()
			load, err := handleStagingLoad(ctx, env, stagingLoadInput{Concepts: []stagingLoadConcept{
				{CanonicalName: "finance_mapping_clean", NodeKind: "section", Payload: map[string]interface{}{"state": "clean"}},
				{CanonicalName: "finance_mapping_blocked", NodeKind: "section", Payload: map[string]interface{}{"state": "blocked"}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			adapter, err := env.Substrates.ByID("test_substrate")
			if err != nil {
				t.Fatal(err)
			}
			client, err := adapter.(*SpannerSubstrateAdapter).getClient(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
				if _, err := tx.Update(ctx, spanner.Statement{SQL: `UPDATE staging_concepts SET dedup_status='no_match', lint_status='pass', pipeline_state='linted', updated_at=PENDING_COMMIT_TIMESTAMP() WHERE organization_id=@org AND ingestion_run_id=@run AND canonical_name='finance_mapping_clean'`, Params: map[string]interface{}{"org": "test-org", "run": load.IngestionRunID}}); err != nil {
					return err
				}
				_, err := tx.Update(ctx, spanner.Statement{SQL: `UPDATE staging_concepts SET dedup_status='no_match', lint_status=@lint, pipeline_state=@state, updated_at=PENDING_COMMIT_TIMESTAMP() WHERE organization_id=@org AND ingestion_run_id=@run AND canonical_name='finance_mapping_blocked'`, Params: map[string]interface{}{"org": "test-org", "run": load.IngestionRunID, "lint": tc.lintStatus, "state": tc.state}})
				return err
			})
			if err != nil {
				t.Fatal(err)
			}
			embeds := &countingEmbeddingClient{}
			env.Embed = embeds
			_, err = handleStagingPromote(ctx, env, stagingPromoteInput{IngestionRunID: load.IngestionRunID})
			if err == nil || !strings.Contains(err.Error(), "not clean+linted") {
				t.Fatalf("promotion error=%v, want all-row lint refusal", err)
			}
			if embeds.calls != 0 {
				t.Fatalf("failed promotion performed %d embedding calls", embeds.calls)
			}
			iter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT COUNT(*) FROM OODGraphMaterializationRuns WHERE organization_id=@org`, Params: map[string]interface{}{"org": "test-org"}})
			row, readErr := iter.Next()
			if readErr != nil {
				iter.Stop()
				t.Fatal(readErr)
			}
			var runs int64
			if err := row.Columns(&runs); err != nil {
				iter.Stop()
				t.Fatal(err)
			}
			iter.Stop()
			if runs != 0 {
				t.Fatalf("partial promotion opened %d materialization run(s)", runs)
			}
		})
	}
}

func TestIntegrationStagingPromotionRejectsUnlintedEdgeBeforeMaterialization(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	load, err := handleStagingLoad(ctx, env, stagingLoadInput{
		Concepts: []stagingLoadConcept{
			{CanonicalName: "finance_source_mapping", NodeKind: "section"},
			{CanonicalName: "finance_projection_contract", NodeKind: "section"},
		},
		Edges: []stagingLoadEdge{{EdgeLabel: "depends_on", SourceCanonicalName: "finance_source_mapping", TargetCanonicalName: "finance_projection_contract"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := env.Substrates.ByID("test_substrate")
	if err != nil {
		t.Fatal(err)
	}
	client, err := adapter.(*SpannerSubstrateAdapter).getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		_, err := tx.Update(ctx, spanner.Statement{SQL: `UPDATE staging_concepts SET dedup_status='no_match', lint_status='pass', pipeline_state='linted', updated_at=PENDING_COMMIT_TIMESTAMP() WHERE organization_id=@org AND ingestion_run_id=@run`, Params: map[string]interface{}{"org": "test-org", "run": load.IngestionRunID}})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	embeds := &countingEmbeddingClient{}
	env.Embed = embeds
	fetches := 0
	env.ExternalFetch = externalReferenceFetcherFunc(func(context.Context, string, ExternalSourceDescriptor, string) (verifiedExternalSourceReceipt, error) {
		fetches++
		return verifiedExternalSourceReceipt{}, errors.New("promotion must not fetch")
	})
	_, err = handleStagingPromote(ctx, env, stagingPromoteInput{IngestionRunID: load.IngestionRunID})
	if err == nil || !strings.Contains(err.Error(), "staging_edge_id") || !strings.Contains(err.Error(), "not clean+linted") {
		t.Fatalf("promotion error=%v, want unlinted-edge refusal", err)
	}
	if embeds.calls != 0 || fetches != 0 {
		t.Fatalf("unlinted edge reached downstream I/O: embeds=%d fetches=%d", embeds.calls, fetches)
	}
	iter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT COUNT(*) FROM OODGraphMaterializationRuns WHERE organization_id=@org`, Params: map[string]interface{}{"org": "test-org"}})
	row, readErr := iter.Next()
	if readErr != nil {
		iter.Stop()
		t.Fatal(readErr)
	}
	var runs int64
	if err := row.Columns(&runs); err != nil {
		iter.Stop()
		t.Fatal(err)
	}
	iter.Stop()
	if runs != 0 {
		t.Fatalf("unlinted edge opened %d materialization run(s)", runs)
	}
}

// TestIntegrationOODGraphReplayDeterminism proves the idempotency key is not
// merely indexed: every same-key prior is loaded and compared as a complete
// protocol output set. Equal sequential and concurrent replays may seal;
// divergent output fails the run durably without publishing graph rows.
func TestIntegrationOODGraphReplayDeterminism(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter := adapters[0].(*SpannerSubstrateAdapter)
	client, err := adapter.getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}

	base := integrationMaterializationBatch(t, "sha256_replay", strings.Repeat("8", 64))
	if err := adapter.OpenMaterializationRun(ctx, base.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, base); err != nil {
		t.Fatalf("commit base: %v", err)
	}

	sequential := integrationRebindBatch(t, base)
	if err := adapter.OpenMaterializationRun(ctx, sequential.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, sequential); err != nil {
		t.Fatalf("equal sequential replay: %v", err)
	}

	// Two equal replays starting together exercise both replay comparison
	// and graph_version transaction retry. Both must seal, with no duplicate
	// version and no nondeterminism violation.
	concurrentA := integrationRebindBatch(t, base)
	concurrentB := integrationRebindBatch(t, base)
	for _, candidate := range []MaterializationBatch{concurrentA, concurrentB} {
		if err := adapter.OpenMaterializationRun(ctx, candidate.Run); err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, candidate := range []MaterializationBatch{concurrentA, concurrentB} {
		candidate := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- adapter.CommitMaterializationRun(ctx, candidate)
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("equal concurrent replay: %v", err)
		}
	}

	divergent := integrationRebindBatch(t, base)
	divergent.Objects[0].GraphAddress += "-nondeterministic"
	if err := adapter.OpenMaterializationRun(ctx, divergent.Run); err != nil {
		t.Fatal(err)
	}
	err = adapter.CommitMaterializationRun(ctx, divergent)
	if !errors.Is(err, ErrOODGraphMaterializationReplayNonDeterministic) {
		t.Fatalf("divergent same-key replay err=%v, want ErrOODGraphMaterializationReplayNonDeterministic", err)
	}

	runRow, err := client.Single().ReadRow(ctx, "OODGraphMaterializationRuns", spanner.Key{"test-org", divergent.Run.MaterializationRunID}, []string{"state", "target_graph_snapshot_id", "finished_at"})
	if err != nil {
		t.Fatal(err)
	}
	var state string
	var target spanner.NullString
	var finished spanner.NullTime
	if err := runRow.Columns(&state, &target, &finished); err != nil {
		t.Fatal(err)
	}
	if state != "failed" || target.Valid || !finished.Valid {
		t.Fatalf("divergent replay run=%q target=%+v finished=%+v, want failed/NULL/non-NULL", state, target, finished)
	}

	for _, check := range []struct {
		table string
		where string
		value string
		want  int64
	}{
		{"OODGraphSnapshots", "graph_snapshot_id", divergent.Snapshot.GraphSnapshotID, 0},
		{"OODGraphObjects", "materialization_run_id", divergent.Run.MaterializationRunID, 0},
		{"OODGraphViolations", "materialization_run_id", divergent.Run.MaterializationRunID, 1},
	} {
		iter := client.Single().Query(ctx, spanner.Statement{SQL: fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE organization_id=@org AND %s=@value", check.table, check.where), Params: map[string]interface{}{"org": "test-org", "value": check.value}})
		row, err := iter.Next()
		if err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		var count int64
		if err := row.Columns(&count); err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		iter.Stop()
		if count != check.want {
			t.Errorf("%s divergent-run rows=%d, want %d", check.table, count, check.want)
		}
	}

	versionIter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT graph_version FROM OODGraphSnapshots WHERE organization_id=@org ORDER BY graph_version`, Params: map[string]interface{}{"org": "test-org"}})
	var versions []int64
	for {
		row, err := versionIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			versionIter.Stop()
			t.Fatal(err)
		}
		var version int64
		if err := row.Columns(&version); err != nil {
			versionIter.Stop()
			t.Fatal(err)
		}
		versions = append(versions, version)
	}
	versionIter.Stop()
	if fmt.Sprint(versions) != "[1 2 3 4]" {
		t.Fatalf("equal replay graph versions=%v, want [1 2 3 4] with failed replay publishing none", versions)
	}
}

// TestIntegrationCompleteSnapshotCarriesAllLegacyPartialIdentities proves
// the first corrected complete-profile writer does not mistake the latest legacy partial for
// the whole active corpus. It folds every eligible legacy snapshot, retains
// edge closure, leaves historical rows untouched, then guards a stale
// prepare against a later writer before a retry publishes the complete set.
func TestIntegrationCompleteSnapshotCarriesAllLegacyPartialIdentities(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter := adapters[0].(*SpannerSubstrateAdapter)
	adapter.allowLegacyMaterializationProfilesForTesting = true
	authority := materializationValidationAuthority(env)
	client, err := adapter.getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}

	legacyOne := integrationMaterializationBatch(t, "sha256_legacy_a", strings.Repeat("a", 64))
	integrationAppendObject(t, &legacyOne, "sha256_legacy_b", strings.Repeat("b", 64))
	for i := range legacyOne.Objects {
		legacyOne.Objects[i].ProjectionRole = "bootstrap_admission_vertex"
	}
	integrationAddReciprocalObjectEdges(t, &legacyOne)
	integrationRefreshBatchSourceSet(t, &legacyOne)
	integrationSetLegacyProfile(&legacyOne)
	legacyTwo := integrationMaterializationBatch(t, "sha256_legacy_c", strings.Repeat("c", 64))
	legacyTwo.Objects[0].ProjectionRole = "bootstrap_admission_vertex"
	integrationSetLegacyProfile(&legacyTwo)
	for i, batch := range []MaterializationBatch{legacyOne, legacyTwo} {
		if err := adapter.OpenMaterializationRun(ctx, batch.Run); err != nil {
			t.Fatalf("open legacy[%d]: %v", i, err)
		}
		if err := adapter.CommitMaterializationRun(ctx, batch); err != nil {
			t.Fatalf("commit legacy[%d]: %v", i, err)
		}
	}

	legacyIdentity := map[string]bool{}
	for _, object := range append(append([]GraphObject(nil), legacyOne.Objects...), legacyTwo.Objects...) {
		legacyIdentity[object.GraphObjectID] = true
	}
	legacyEdges := map[string]bool{}
	for _, edge := range legacyOne.Edges {
		legacyEdges[edge.GraphEdgeID] = true
	}

	correctedDelta := integrationMaterializationBatch(t, "sha256_corrected_d", strings.Repeat("d", 64))
	corrected, coords, err := adapter.PrepareCompleteMaterialization(ctx, correctedDelta, nil, authority)
	if err != nil {
		t.Fatalf("prepare first complete: %v", err)
	}
	if !corrected.CompleteSnapshot || corrected.BaselineGraphVersion != 2 || len(corrected.Objects) != 4 || len(corrected.Edges) != 2 {
		t.Fatalf("first complete batch complete=%t baseline=%d objects=%d edges=%d, want true/2/4/2", corrected.CompleteSnapshot, corrected.BaselineGraphVersion, len(corrected.Objects), len(corrected.Edges))
	}
	for _, object := range corrected.Objects {
		desc, descErr := authority.Kinds.Resolve(ctx, object.ObjectClass)
		if descErr != nil || object.ProjectionRole != desc.ProjectionRole() {
			t.Errorf("carried object %q projection_role=%q was not rederived from current registry role=%q err=%v", object.GraphObjectID, object.ProjectionRole, desc.ProjectionRole(), descErr)
		}
	}
	integrationBindPreparedSourceSet(t, &corrected, coords)
	if err := adapter.OpenMaterializationRun(ctx, corrected.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, corrected); err != nil {
		t.Fatalf("commit first complete: %v", err)
	}
	assertIntegrationSnapshotIdentitySet(ctx, t, client, corrected.Snapshot.GraphSnapshotID, 4, legacyIdentity, legacyEdges)
	assertIntegrationHistoricalRowsUnchanged(ctx, t, client, legacyOne, legacyTwo)

	// A subsequent complete materialization starts at the latest complete
	// snapshot, not the full historical union, and adds its delta once.
	secondDelta := integrationMaterializationBatch(t, "sha256_corrected_e", strings.Repeat("e", 64))
	second, secondCoords, err := adapter.PrepareCompleteMaterialization(ctx, secondDelta, nil, authority)
	if err != nil {
		t.Fatal(err)
	}
	if second.BaselineGraphVersion != 3 || len(second.Objects) != 5 || len(second.Edges) != 2 {
		t.Fatalf("second complete baseline=%d objects=%d edges=%d, want 3/5/2", second.BaselineGraphVersion, len(second.Objects), len(second.Edges))
	}
	integrationBindPreparedSourceSet(t, &second, secondCoords)
	if err := adapter.OpenMaterializationRun(ctx, second.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, second); err != nil {
		t.Fatal(err)
	}

	// Prepare F at baseline 4, then let an old profile/5 writer publish G.
	// F must not seal without G; the retry must include both.
	staleDelta := integrationMaterializationBatch(t, "sha256_stale_f", strings.Repeat("f", 64))
	stale, staleCoords, err := adapter.PrepareCompleteMaterialization(ctx, staleDelta, nil, authority)
	if err != nil {
		t.Fatal(err)
	}
	integrationBindPreparedSourceSet(t, &stale, staleCoords)
	laterLegacy := integrationMaterializationBatch(t, "sha256_later_legacy_g", strings.Repeat("7", 64))
	integrationSetLegacyProfile(&laterLegacy)
	if err := adapter.OpenMaterializationRun(ctx, laterLegacy.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, laterLegacy); err != nil {
		t.Fatal(err)
	}
	if err := adapter.OpenMaterializationRun(ctx, stale.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, stale); err == nil || !errors.Is(err, ErrCeremonyAtomicityBroken) {
		t.Fatalf("stale complete commit err=%v, want atomic refusal after baseline advances", err)
	}
	if err := adapter.FailMaterializationRun(ctx, stale.Run.OrganizationID, stale.Run.MaterializationRunID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Single().ReadRow(ctx, "OODGraphSnapshots", spanner.Key{"test-org", stale.Snapshot.GraphSnapshotID}, []string{"graph_snapshot_id"}); spanner.ErrCode(err) != codes.NotFound {
		t.Fatalf("stale snapshot read err=%v, want NotFound", err)
	}

	retryDelta := integrationMaterializationBatch(t, "sha256_stale_f", strings.Repeat("f", 64))
	retry, retryCoords, err := adapter.PrepareCompleteMaterialization(ctx, retryDelta, nil, authority)
	if err != nil {
		t.Fatal(err)
	}
	if retry.BaselineGraphVersion != 5 || len(retry.Objects) != 7 || len(retry.Edges) != 2 {
		t.Fatalf("retried complete baseline=%d objects=%d edges=%d, want 5/7/2", retry.BaselineGraphVersion, len(retry.Objects), len(retry.Edges))
	}
	integrationBindPreparedSourceSet(t, &retry, retryCoords)
	if err := adapter.OpenMaterializationRun(ctx, retry.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, retry); err != nil {
		t.Fatal(err)
	}
	assertIntegrationHistoricalRowsUnchanged(ctx, t, client, legacyOne, legacyTwo)
	assertIntegrationSnapshotIdentitySet(ctx, t, client, retry.Snapshot.GraphSnapshotID, 7, legacyIdentity, legacyEdges)
}

func TestIntegrationCompleteSnapshotNeverDropsCarriedProjectionOrViolationArtifacts(t *testing.T) {
	for _, artifact := range []string{"projection", "violation"} {
		t.Run(artifact, func(t *testing.T) {
			requireEmulator(t)
			ctx := context.Background()
			setupEmulatorDB(ctx, t)
			applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
			env := integrationOODEnv(t)
			defer env.Substrates.Close()
			adapters, err := env.Substrates.All(ctx)
			if err != nil || len(adapters) != 1 {
				t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
			}
			adapter := adapters[0].(*SpannerSubstrateAdapter)
			adapter.allowLegacyMaterializationProfilesForTesting = true
			seed := integrationMaterializationBatch(t, "sha256_artifact_seed_"+artifact, strings.Repeat("a", 64))
			integrationSetLegacyProfile(&seed)
			switch artifact {
			case "projection":
				seed.ProjectionArtifacts = []ProjectionArtifact{{
					OrganizationID: seed.Run.OrganizationID, ProjectionArtifactID: uuid.NewString(), GraphSnapshotID: seed.Snapshot.GraphSnapshotID,
					ProjectionKind: "doc_canonical_json", ProjectionTargetKind: "graph_object", ProjectionTargetID: seed.Objects[0].GraphObjectID,
					ProjectionFormat: "structured_ood_json", ProjectionHash: strings.Repeat("b", 64), ProjectionPayload: map[string]interface{}{"object_class": "reference_page"},
					RoundTripState: "equivalent", MaterializationRunID: seed.Run.MaterializationRunID, Status: "active", VisibilityScope: seed.Snapshot.VisibilityScope,
				}}
			case "violation":
				seed.Violations = []Violation{NewViolation(seed.Run.OrganizationID, seed.Run.MaterializationRunID, seed.Snapshot.GraphSnapshotID, ViolationPropertyOrSearchPayloadLeak, ViolationCoordinate{
					SourceAuthorityID: seed.Objects[0].SourceAuthorityID, SourceStableReference: seed.Objects[0].SourceStableReference,
					VersionCoordinate: seed.Objects[0].VersionCoordinate, SectionPath: seed.Objects[0].SectionPath,
					GraphAddress: seed.Objects[0].GraphAddress, GraphObjectID: seed.Objects[0].GraphObjectID,
					RejectedValueClass: "search_payload", RedactedReason: "legacy_rejected_property_class",
				})}
			}
			if err := adapter.OpenMaterializationRun(ctx, seed.Run); err != nil {
				t.Fatal(err)
			}
			if err := adapter.CommitMaterializationRun(ctx, seed); err != nil {
				t.Fatal(err)
			}
			delta := integrationMaterializationBatch(t, "sha256_artifact_delta_"+artifact, strings.Repeat("c", 64))
			_, _, err = adapter.PrepareCompleteMaterialization(ctx, delta, nil, materializationValidationAuthority(env))
			if !errors.Is(err, ErrOODGraphCompleteArtifactCarryForwardUnavailable) {
				t.Fatalf("prepare error=%v, want %v", err, ErrOODGraphCompleteArtifactCarryForwardUnavailable)
			}
			client, err := adapter.getClient(ctx)
			if err != nil {
				t.Fatal(err)
			}
			iter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT COUNT(*) FROM OODGraphMaterializationRuns WHERE organization_id=@org`, Params: map[string]interface{}{"org": seed.Run.OrganizationID}})
			row, err := iter.Next()
			if err != nil {
				iter.Stop()
				t.Fatal(err)
			}
			var count int64
			if err := row.Columns(&count); err != nil {
				iter.Stop()
				t.Fatal(err)
			}
			iter.Stop()
			if count != 1 {
				t.Fatalf("materialization runs=%d, want only immutable predecessor; refused successor must not open", count)
			}
		})
	}
}

func TestIntegrationCompleteSnapshotRejectsInvalidLegacyRowsBeforeOpeningSuccessor(t *testing.T) {
	for _, corruption := range []string{"unknown_object_class", "unknown_edge_label"} {
		t.Run(corruption, func(t *testing.T) {
			requireEmulator(t)
			ctx := context.Background()
			setupEmulatorDB(ctx, t)
			applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
			env := integrationOODEnv(t)
			defer env.Substrates.Close()
			adapters, err := env.Substrates.All(ctx)
			if err != nil || len(adapters) != 1 {
				t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
			}
			adapter := adapters[0].(*SpannerSubstrateAdapter)
			adapter.allowLegacyMaterializationProfilesForTesting = true
			seed := integrationMaterializationBatch(t, "sha256_invalid_legacy_"+corruption, strings.Repeat("9", 64))
			switch corruption {
			case "unknown_object_class":
				seed.Objects[0].ObjectClass = "legacy_unregistered_class"
			case "unknown_edge_label":
				integrationAppendObject(t, &seed, "sha256_invalid_edge_target", strings.Repeat("a", 64))
				integrationAddReciprocalObjectEdges(t, &seed)
				for i := range seed.Edges {
					seed.Edges[i].EdgeLabel = "legacy_unregistered_label"
				}
			}
			integrationRefreshBatchSourceSet(t, &seed)
			integrationSetLegacyProfile(&seed)
			if err := adapter.OpenMaterializationRun(ctx, seed.Run); err != nil {
				t.Fatal(err)
			}
			if err := adapter.CommitMaterializationRun(ctx, seed); err != nil {
				t.Fatal(err)
			}
			delta := integrationMaterializationBatch(t, "sha256_valid_after_invalid_"+corruption, strings.Repeat("b", 64))
			_, _, err = adapter.PrepareCompleteMaterialization(ctx, delta, nil, materializationValidationAuthority(env))
			if err == nil {
				t.Fatal("invalid legacy row was laundered into a complete successor")
			}
			client, err := adapter.getClient(ctx)
			if err != nil {
				t.Fatal(err)
			}
			iter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT COUNT(*) FROM OODGraphMaterializationRuns WHERE organization_id=@org`, Params: map[string]interface{}{"org": seed.Run.OrganizationID}})
			row, err := iter.Next()
			if err != nil {
				iter.Stop()
				t.Fatal(err)
			}
			var count int64
			if err := row.Columns(&count); err != nil {
				iter.Stop()
				t.Fatal(err)
			}
			iter.Stop()
			if count != 1 {
				t.Fatalf("materialization runs=%d, want invalid predecessor only", count)
			}
		})
	}
}

func TestIntegrationExternalVersionRefreshFailsClosedAndPreservesPinnedPredecessor(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter := adapters[0].(*SpannerSubstrateAdapter)
	first := integrationMaterializationBatch(t, "sha256_external_v1", strings.Repeat("1", 64))
	if err := adapter.OpenMaterializationRun(ctx, first.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, first); err != nil {
		t.Fatal(err)
	}
	refresh := integrationMaterializationBatch(t, "sha256_external_v2", strings.Repeat("2", 64))
	integrationRetargetExternalVersion(t, &refresh, first.Objects[0].SourceStableReference, "sha256_external_v2", strings.Repeat("2", 64))
	_, _, err = adapter.PrepareCompleteMaterialization(ctx, refresh, nil, materializationValidationAuthority(env))
	if !errors.Is(err, ErrOODGraphExternalVersionTransitionUnrepresentable) {
		t.Fatalf("refresh error=%v, want %v", err, ErrOODGraphExternalVersionTransitionUnrepresentable)
	}
	client, err := adapter.getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"OODGraphSnapshots", "OODGraphMaterializationRuns", "OODGraphObjects"} {
		iter := client.Single().Query(ctx, spanner.Statement{SQL: fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE organization_id=@org", table), Params: map[string]interface{}{"org": first.Run.OrganizationID}})
		row, err := iter.Next()
		if err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		var count int64
		if err := row.Columns(&count); err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		iter.Stop()
		if count != 1 {
			t.Errorf("%s rows=%d, want only immutable v1 predecessor", table, count)
		}
	}
	pinned, err := handleOODGet(ctx, env, oodGetInput{GraphObjectID: first.Objects[0].GraphObjectID, GraphSnapshotID: first.Snapshot.GraphSnapshotID})
	if err != nil || len(pinned.Rows) != 1 || pinned.Rows[0]["version_coordinate"] != first.Objects[0].VersionCoordinate {
		t.Fatalf("pinned predecessor changed: rows=%v err=%v", pinned.Rows, err)
	}
}

func integrationBindPreparedSourceSet(t *testing.T, batch *MaterializationBatch, coords []SourceCoordinate) {
	t.Helper()
	hash, err := ComputeSourceSetHash(batch.Run.OrganizationID, coords)
	if err != nil {
		t.Fatal(err)
	}
	set, err := BuildSourceSetWithExternalReceipts(batch.Run.OrganizationID, coords, batch.ExternalVerificationReceipts)
	if err != nil {
		t.Fatal(err)
	}
	batch.Run.InputSourceSetHash, batch.Run.InputSourceSet = hash, set
	batch.Snapshot.SourceSetHash, batch.Snapshot.SourceSet = hash, set
}

func assertIntegrationSnapshotIdentitySet(ctx context.Context, t *testing.T, client *spanner.Client, snapshotID string, wantObjectCount int, requiredObjects, requiredEdges map[string]bool) {
	t.Helper()
	objectIter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT graph_object_id FROM OODGraphObjects WHERE organization_id=@org AND graph_snapshot_id=@snapshot ORDER BY graph_object_id`, Params: map[string]interface{}{"org": "test-org", "snapshot": snapshotID}})
	seenObjects := map[string]int{}
	for {
		row, err := objectIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			objectIter.Stop()
			t.Fatal(err)
		}
		var id string
		if err := row.Columns(&id); err != nil {
			objectIter.Stop()
			t.Fatal(err)
		}
		seenObjects[id]++
	}
	objectIter.Stop()
	if len(seenObjects) != wantObjectCount {
		t.Fatalf("snapshot %q object identities=%d, want %d (%v)", snapshotID, len(seenObjects), wantObjectCount, seenObjects)
	}
	for id := range requiredObjects {
		if seenObjects[id] != 1 {
			t.Errorf("snapshot %q required object %q count=%d, want exactly 1", snapshotID, id, seenObjects[id])
		}
	}
	edgeIter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT graph_edge_id FROM OODGraphEdges WHERE organization_id=@org AND graph_snapshot_id=@snapshot ORDER BY graph_edge_id`, Params: map[string]interface{}{"org": "test-org", "snapshot": snapshotID}})
	seenEdges := map[string]int{}
	for {
		row, err := edgeIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			edgeIter.Stop()
			t.Fatal(err)
		}
		var id string
		if err := row.Columns(&id); err != nil {
			edgeIter.Stop()
			t.Fatal(err)
		}
		seenEdges[id]++
	}
	edgeIter.Stop()
	if len(seenEdges) != len(requiredEdges) {
		t.Errorf("snapshot %q edge identities=%d, want %d (%v)", snapshotID, len(seenEdges), len(requiredEdges), seenEdges)
	}
	for id := range requiredEdges {
		if seenEdges[id] != 1 {
			t.Errorf("snapshot %q required edge %q count=%d, want exactly 1", snapshotID, id, seenEdges[id])
		}
	}
}

func assertIntegrationHistoricalRowsUnchanged(ctx context.Context, t *testing.T, client *spanner.Client, batches ...MaterializationBatch) {
	t.Helper()
	for _, batch := range batches {
		row, err := client.Single().ReadRow(ctx, "OODGraphSnapshots", spanner.Key{"test-org", batch.Snapshot.GraphSnapshotID}, []string{"status", "snapshot_state", "source_set_hash"})
		if err != nil {
			t.Fatal(err)
		}
		var status, state, hash string
		if err := row.Columns(&status, &state, &hash); err != nil {
			t.Fatal(err)
		}
		if status != "active" || state != "sealed" || hash != batch.Snapshot.SourceSetHash {
			t.Errorf("historical snapshot %q mutated: status=%q state=%q hash=%q", batch.Snapshot.GraphSnapshotID, status, state, hash)
		}
		iter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT COUNT(*) FROM OODGraphObjects WHERE organization_id=@org AND graph_snapshot_id=@snapshot AND status='active'`, Params: map[string]interface{}{"org": "test-org", "snapshot": batch.Snapshot.GraphSnapshotID}})
		countRow, err := iter.Next()
		if err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		var count int64
		if err := countRow.Columns(&count); err != nil {
			iter.Stop()
			t.Fatal(err)
		}
		iter.Stop()
		if count != int64(len(batch.Objects)) {
			t.Errorf("historical snapshot %q active object rows=%d, want %d", batch.Snapshot.GraphSnapshotID, count, len(batch.Objects))
		}
	}
}

// TestIntegrationStagingPromotionRollsBackWithGraphSeal injects one valid
// and one nonexistent promotion receipt. The first UPDATE executes before
// the second fails; Spanner must roll both it and every graph write back.
func TestIntegrationStagingPromotionRollsBackWithGraphSeal(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	load, err := handleStagingLoad(ctx, env, stagingLoadInput{ConceptDomain: "atomic_staging", SourceFile: "fixture", Concepts: []stagingLoadConcept{{CanonicalName: "atomic_staging_section", NodeKind: "section"}}})
	if err != nil {
		t.Fatal(err)
	}
	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter := adapters[0].(*SpannerSubstrateAdapter)
	client, err := adapter.getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	integrationMarkStagingRunLintPass(ctx, t, client, load.IngestionRunID)
	iter := client.Single().Query(ctx, spanner.Statement{SQL: `SELECT staging_id FROM staging_concepts WHERE organization_id=@org AND ingestion_run_id=@run`, Params: map[string]interface{}{"org": "test-org", "run": load.IngestionRunID}})
	row, err := iter.Next()
	if err != nil {
		iter.Stop()
		t.Fatal(err)
	}
	var stagingID string
	if err := row.Columns(&stagingID); err != nil {
		iter.Stop()
		t.Fatal(err)
	}
	iter.Stop()

	batch := integrationMaterializationBatch(t, "sha256_atomic_staging", strings.Repeat("9", 64))
	batch.StagingConceptPromotions = []StagingConceptPromotion{
		{IngestionRunID: load.IngestionRunID, StagingID: stagingID, GraphObjectID: batch.Objects[0].GraphObjectID},
		{IngestionRunID: load.IngestionRunID, StagingID: uuid.NewString(), GraphObjectID: batch.Objects[0].GraphObjectID},
	}
	if err := adapter.OpenMaterializationRun(ctx, batch.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, batch); err == nil || !errors.Is(err, ErrCeremonyAtomicityBroken) {
		t.Fatalf("atomic promotion failure err=%v, want ErrCeremonyAtomicityBroken", err)
	}
	stagedRow, err := client.Single().ReadRow(ctx, "staging_concepts", spanner.Key{"test-org", load.IngestionRunID, stagingID}, []string{"pipeline_state", "promoted_graph_object_id"})
	if err != nil {
		t.Fatal(err)
	}
	var pipelineState string
	var promotedID spanner.NullString
	if err := stagedRow.Columns(&pipelineState, &promotedID); err != nil {
		t.Fatal(err)
	}
	if pipelineState != "linted" || promotedID.Valid {
		t.Fatalf("partial staging promotion escaped rollback: state=%q promoted=%+v", pipelineState, promotedID)
	}
	for _, table := range []string{"OODGraphObjects", "OODGraphSnapshots"} {
		countIter := client.Single().Query(ctx, spanner.Statement{SQL: fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE organization_id=@org", table), Params: map[string]interface{}{"org": "test-org"}})
		countRow, err := countIter.Next()
		if err != nil {
			countIter.Stop()
			t.Fatal(err)
		}
		var count int64
		if err := countRow.Columns(&count); err != nil {
			countIter.Stop()
			t.Fatal(err)
		}
		countIter.Stop()
		if count != 0 {
			t.Errorf("%s rows=%d after failed atomic promotion, want 0", table, count)
		}
	}
	if err := adapter.FailMaterializationRun(ctx, batch.Run.OrganizationID, batch.Run.MaterializationRunID); err != nil {
		t.Fatal(err)
	}
}

// TestIntegrationTypedReadsSelectCurrentOrPinnedImmutableSnapshot executes
// the real selected_snapshot CTE. Current reads return only the latest
// eligible complete snapshot; a pin returns the historical snapshot without
// mutating or duplicating either generation.
func TestIntegrationTypedReadsSelectCurrentOrPinnedImmutableSnapshot(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter := adapters[0].(*SpannerSubstrateAdapter)
	authority := materializationValidationAuthority(env)

	first := integrationMaterializationBatch(t, "sha256_typed_a", strings.Repeat("1", 64))
	if err := adapter.OpenMaterializationRun(ctx, first.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, first); err != nil {
		t.Fatal(err)
	}
	secondDelta := integrationMaterializationBatch(t, "sha256_typed_b", strings.Repeat("2", 64))
	second, coords, err := adapter.PrepareCompleteMaterialization(ctx, secondDelta, nil, authority)
	if err != nil {
		t.Fatal(err)
	}
	integrationBindPreparedSourceSet(t, &second, coords)
	if err := adapter.OpenMaterializationRun(ctx, second.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, second); err != nil {
		t.Fatal(err)
	}

	current, err := handleOODList(ctx, env, oodListInput{Limit: 20})
	if err != nil {
		t.Fatalf("current typed list: %v", err)
	}
	if len(current.Rows) != 2 {
		t.Fatalf("current typed rows=%d, want 2 complete-snapshot objects", len(current.Rows))
	}
	for _, row := range current.Rows {
		if row["graph_snapshot_id"] != second.Snapshot.GraphSnapshotID {
			t.Errorf("current row snapshot=%v, want %q", row["graph_snapshot_id"], second.Snapshot.GraphSnapshotID)
		}
	}
	pinned, err := handleOODList(ctx, env, oodListInput{GraphSnapshotID: first.Snapshot.GraphSnapshotID, Limit: 20})
	if err != nil {
		t.Fatalf("pinned typed list: %v", err)
	}
	if len(pinned.Rows) != 1 || pinned.Rows[0]["graph_snapshot_id"] != first.Snapshot.GraphSnapshotID {
		t.Fatalf("pinned rows=%v, want exactly historical snapshot %q", pinned.Rows, first.Snapshot.GraphSnapshotID)
	}
	currentA, err := handleOODGet(ctx, env, oodGetInput{GraphObjectID: first.Objects[0].GraphObjectID})
	if err != nil || len(currentA.Rows) != 1 || currentA.Rows[0]["graph_snapshot_id"] != second.Snapshot.GraphSnapshotID {
		t.Fatalf("current get rows=%v err=%v", currentA.Rows, err)
	}
	pinnedA, err := handleOODGet(ctx, env, oodGetInput{GraphObjectID: first.Objects[0].GraphObjectID, GraphSnapshotID: first.Snapshot.GraphSnapshotID})
	if err != nil || len(pinnedA.Rows) != 1 || pinnedA.Rows[0]["graph_snapshot_id"] != first.Snapshot.GraphSnapshotID {
		t.Fatalf("pinned get rows=%v err=%v", pinnedA.Rows, err)
	}
}

func TestIntegrationRetirementFailsClosedDuringRefreshAndPinnedHistoryIsImmutable(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter := adapters[0].(*SpannerSubstrateAdapter)
	base := integrationMaterializationBatch(t, "sha256_retirement_base", strings.Repeat("3", 64))
	if err := adapter.OpenMaterializationRun(ctx, base.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, base); err != nil {
		t.Fatal(err)
	}
	before, err := handleOODGet(ctx, env, oodGetInput{GraphObjectID: base.Objects[0].GraphObjectID, GraphSnapshotID: base.Snapshot.GraphSnapshotID})
	if err != nil || len(before.Rows) != 1 {
		t.Fatalf("pinned predecessor before retirement: rows=%v err=%v", before.Rows, err)
	}

	delta := integrationMaterializationBatch(t, "sha256_retirement_delta", strings.Repeat("4", 64))
	type preparedResult struct {
		batch  MaterializationBatch
		coords []SourceCoordinate
		err    error
	}
	prepared := make(chan preparedResult, 1)
	archived := make(chan error, 1)
	go func() {
		batch, coords, err := adapter.PrepareCompleteMaterialization(ctx, delta, nil, materializationValidationAuthority(env))
		prepared <- preparedResult{batch: batch, coords: coords, err: err}
	}()
	go func() {
		_, err := adapter.ArchiveNode(ctx, base.Run.OrganizationID, base.Objects[0].GraphObjectID, "integration-admitter")
		archived <- err
	}()
	if err := <-archived; !errors.Is(err, ErrOODGraphImmutableRetirementUnavailable) {
		t.Fatalf("concurrent archive error=%v, want fail-closed sentinel", err)
	}
	result := <-prepared
	if result.err != nil {
		t.Fatalf("concurrent complete prepare: %v", result.err)
	}
	integrationBindPreparedSourceSet(t, &result.batch, result.coords)
	if err := adapter.OpenMaterializationRun(ctx, result.batch.Run); err != nil {
		t.Fatal(err)
	}
	if err := adapter.CommitMaterializationRun(ctx, result.batch); err != nil {
		t.Fatal(err)
	}
	after, err := handleOODGet(ctx, env, oodGetInput{GraphObjectID: base.Objects[0].GraphObjectID, GraphSnapshotID: base.Snapshot.GraphSnapshotID})
	if err != nil || !reflect.DeepEqual(before.Rows, after.Rows) {
		t.Fatalf("pinned predecessor changed across retirement/refresh: before=%v after=%v err=%v", before.Rows, after.Rows, err)
	}
}

func TestIntegrationExplicitSnapshotCoordinatesDoNotCrossTenantsUnderConcurrency(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapters, err := env.Substrates.All(ctx)
	if err != nil || len(adapters) != 1 {
		t.Fatalf("substrates.All: adapters=%d err=%v", len(adapters), err)
	}
	adapter := adapters[0].(*SpannerSubstrateAdapter)
	orgA := integrationMaterializationBatch(t, "sha256_tenant_a", strings.Repeat("5", 64))
	orgB := integrationMaterializationBatch(t, "sha256_tenant_b", strings.Repeat("6", 64))
	integrationRebindOrganization(t, &orgA, "tenant-a")
	integrationRebindOrganization(t, &orgB, "tenant-b")
	for _, batch := range []*MaterializationBatch{&orgA, &orgB} {
		if err := adapter.OpenMaterializationRun(ctx, batch.Run); err != nil {
			t.Fatal(err)
		}
		if err := adapter.CommitMaterializationRun(ctx, *batch); err != nil {
			t.Fatal(err)
		}
	}
	env.Config.Mode = ModeProduction
	env.Config.DefaultOrganizationID = ""
	ctxA := withCallerOrganizationID(context.Background(), "tenant-a")
	ctxB := withCallerOrganizationID(context.Background(), "tenant-b")
	if _, err := handleUse(ctxA, env, useInput{SnapshotID: orgB.Snapshot.GraphSnapshotID}); err == nil {
		t.Fatal("retired implicit-pin tool unexpectedly mutated tenant state")
	}

	type readCase struct {
		ctx      context.Context
		snapshot string
		objectID string
	}
	cases := []readCase{{ctxA, orgA.Snapshot.GraphSnapshotID, orgA.Objects[0].GraphObjectID}, {ctxB, orgB.Snapshot.GraphSnapshotID, orgB.Objects[0].GraphObjectID}}
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for _, tc := range cases {
		tc := tc
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				result, err := handleOODGet(tc.ctx, env, oodGetInput{GraphObjectID: tc.objectID, GraphSnapshotID: tc.snapshot})
				if err != nil {
					errs <- err
					return
				}
				if len(result.Rows) != 1 || result.Rows[0]["graph_snapshot_id"] != tc.snapshot {
					errs <- fmt.Errorf("request-local pin returned rows=%v, want snapshot %q", result.Rows, tc.snapshot)
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	crossTenant, err := handleOODList(ctxA, env, oodListInput{GraphSnapshotID: orgB.Snapshot.GraphSnapshotID, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	if len(crossTenant.Rows) != 0 {
		t.Fatalf("tenant-a read tenant-b snapshot rows=%v", crossTenant.Rows)
	}
}
