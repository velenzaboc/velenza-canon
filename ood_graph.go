package main

import (
	"encoding/json"
	"time"
)

// This file declares the OOD-Graph-owned row struct types matching the
// 7-table schema_v2.sql substrate per OOD_GRAPH_PROTOCOL_v1 §6.
// Phase 3 of the (C) substrate rebuild. New types ADDED here; the legacy
// Node / Edge / NodeVersion / AdmissionRecord / AdmissionPlan types in
// types.go remain load-bearing for handlers.go / ceremony.go / substrate.go
// until Phase 4-5-6 migrate callers to the new types. Phase 6 deletes the
// legacy types from types.go once all callers have switched.
//
// Field naming matches the §6 column names exactly; JSON tags are
// snake_case to round-trip the canonical OOD JSON projection per §5.
// All time fields are time.Time UTC; all UUID-bearing fields are STRING(36)
// canonical lowercase per §3.

// GraphObject mirrors OODGraphObjects (§6.table_surfaces.ood_graph_objects).
// One row per addressable graph-owned object inside one sealed snapshot.
// Identity tuple per §3.object_class_identity_rules; uniqueness enforced by
// OODGraphObjectsByIdentityTuple and OODGraphObjectsByAddress indexes.
type GraphObject struct {
	OrganizationID         string                 `json:"organization_id"`
	GraphSnapshotID        string                 `json:"graph_snapshot_id"`
	GraphObjectID          string                 `json:"graph_object_id"`
	ObjectClass            string                 `json:"object_class"`
	SourceAuthorityID      string                 `json:"source_authority_id"`
	SourceArtifactClass    string                 `json:"source_artifact_class"`
	SourceRefKind          string                 `json:"source_ref_kind"` // id | name | coordinate | path
	SourceStableReference  string                 `json:"source_stable_reference"`
	VersionCoordinate      string                 `json:"version_coordinate"`
	SectionPath            string                 `json:"section_path"`
	GraphAddress           string                 `json:"graph_address"`
	SourceContentHash      string                 `json:"source_content_hash,omitempty"`
	SourceContentHashOwner string                 `json:"source_content_hash_owner,omitempty"`
	MaterializationRunID   string                 `json:"materialization_run_id"`
	ProjectionRole         string                 `json:"projection_role"`
	ValidationState        string                 `json:"validation_state"`
	Status                 string                 `json:"status"`           // active | superseded | invalid | archived
	VisibilityScope        string                 `json:"visibility_scope"` // tenant | organization | platform
	SearchText             string                 `json:"search_text,omitempty"`
	SearchPayload          map[string]interface{} `json:"search_payload,omitempty"`
	Embedding              []float32              `json:"-"`
	EmbeddingModel         string                 `json:"embedding_model"`
	CreatedAt              time.Time              `json:"created_at"`
	UpdatedAt              time.Time              `json:"updated_at"`
}

// GraphSymbol mirrors OODGraphSymbols (§6.table_surfaces.ood_graph_symbols).
// One row per addressable named symbol scoped under a GraphObject inside a
// snapshot. Used by §10 retrieval lookups; production edge endpoints must
// resolve from symbol candidates to OODGraphObjects.graph_object_id before
// active edge insertion (§4.endpoint_model.symbol_endpoint_candidate_rule).
type GraphSymbol struct {
	OrganizationID        string                 `json:"organization_id"`
	GraphSnapshotID       string                 `json:"graph_snapshot_id"`
	SymbolID              string                 `json:"symbol_id"`
	GraphObjectID         string                 `json:"graph_object_id"`
	ObjectClass           string                 `json:"object_class"`
	SymbolKind            string                 `json:"symbol_kind"`
	SymbolName            string                 `json:"symbol_name"`
	SourceAuthorityID     string                 `json:"source_authority_id"`
	SourceStableReference string                 `json:"source_stable_reference"`
	VersionCoordinate     string                 `json:"version_coordinate"`
	SectionPath           string                 `json:"section_path"`
	GraphAddress          string                 `json:"graph_address"`
	MaterializationRunID  string                 `json:"materialization_run_id"`
	ValidationState       string                 `json:"validation_state"`
	Status                string                 `json:"status"`
	VisibilityScope       string                 `json:"visibility_scope"`
	SearchText            string                 `json:"search_text,omitempty"`
	SearchPayload         map[string]interface{} `json:"search_payload,omitempty"`
	Embedding             []float32              `json:"-"`
	EmbeddingModel        string                 `json:"embedding_model"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

// GraphEdge mirrors OODGraphEdges (§6.table_surfaces.ood_graph_edges).
// One row per typed directed edge between two resolved GraphObject endpoints
// inside a snapshot. Identity tuple per §4.edge_identity.identity_tuple;
// uniqueness enforced by OODGraphEdgesByIdentityTuple index. Reciprocity
// state and InverseEdgeID track the same-transaction reciprocal pair per
// §4.dependency_load_bearing_reciprocity and §4.supersession_edges.
type GraphEdge struct {
	OrganizationID          string                 `json:"organization_id"`
	GraphSnapshotID         string                 `json:"graph_snapshot_id"`
	GraphEdgeID             string                 `json:"graph_edge_id"`
	SourceEndpointKind      string                 `json:"source_endpoint_kind"` // always graph_object in v1
	SourceEndpointID        string                 `json:"source_endpoint_id"`
	SourceEndpointClass     string                 `json:"source_endpoint_class"`
	TargetEndpointKind      string                 `json:"target_endpoint_kind"`
	TargetEndpointID        string                 `json:"target_endpoint_id"`
	TargetEndpointClass     string                 `json:"target_endpoint_class"`
	EdgeLabel               string                 `json:"edge_label"`
	EdgeFamily              string                 `json:"edge_family"`
	SourceVersionCoordinate string                 `json:"source_version_coordinate"`
	TargetVersionCoordinate string                 `json:"target_version_coordinate"`
	AuthoringSourcePath     string                 `json:"authoring_source_path"`
	SourceAuthorityID       string                 `json:"source_authority_id"`
	SourceStableReference   string                 `json:"source_stable_reference"`
	SourceContentHash       string                 `json:"source_content_hash,omitempty"`
	ValidFrom               *time.Time             `json:"valid_from,omitempty"`
	ValidUntil              *time.Time             `json:"valid_until,omitempty"`
	DiagnosticOnly          bool                   `json:"diagnostic_only"`
	ReciprocityState        string                 `json:"reciprocity_state"` // complete | mirror_pending | not_required
	InverseEdgeID           string                 `json:"inverse_edge_id,omitempty"`
	EdgeConfidence          *float32               `json:"edge_confidence,omitempty"`
	MaterializationRunID    string                 `json:"materialization_run_id"`
	ValidationState         string                 `json:"validation_state"`
	Status                  string                 `json:"status"`
	VisibilityScope         string                 `json:"visibility_scope"`
	SearchText              string                 `json:"search_text,omitempty"`
	SearchPayload           map[string]interface{} `json:"search_payload,omitempty"`
	Embedding               []float32              `json:"-"`
	EmbeddingModel          string                 `json:"embedding_model"`
	CreatedAt               time.Time              `json:"created_at"`
	UpdatedAt               time.Time              `json:"updated_at"`
}

// GraphSnapshot mirrors OODGraphSnapshots
// (§6.table_surfaces.ood_graph_snapshots). Names one materialized OOD Graph
// version for one organization. SourceSet records the deterministic source
// coordinate set the snapshot was produced from
// (§8.canonical_source_intake.source_set_contract). SnapshotState is
// "building" while the materialization run holds it, "sealed" once the run
// commits successfully.
type GraphSnapshot struct {
	OrganizationID       string                 `json:"organization_id"`
	GraphSnapshotID      string                 `json:"graph_snapshot_id"`
	GraphVersion         int64                  `json:"graph_version"`
	SnapshotKind         string                 `json:"snapshot_kind"` // active_candidate | historical | diagnostic
	SourceSetHash        string                 `json:"source_set_hash"`
	SourceSet            map[string]interface{} `json:"source_set"`
	MaterializationRunID string                 `json:"materialization_run_id,omitempty"`
	SnapshotState        string                 `json:"snapshot_state"` // building | sealed
	Status               string                 `json:"status"`
	VisibilityScope      string                 `json:"visibility_scope"`
	SealedAt             *time.Time             `json:"sealed_at,omitempty"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

// MaterializationRun mirrors OODGraphMaterializationRuns
// (§6.table_surfaces.ood_graph_materialization_runs). One row per execution
// of the §8.materialization_pipeline. State transitions per
// §8.materialization_pipeline.open_materialization_run.initial_state and
// §8.materialization_pipeline.seal_materialization_run.
type MaterializationRun struct {
	OrganizationID        string                 `json:"organization_id"`
	MaterializationRunID  string                 `json:"materialization_run_id"`
	TargetGraphSnapshotID string                 `json:"target_graph_snapshot_id,omitempty"`
	RunKind               string                 `json:"run_kind"` // corpus_refresh | source_change_refresh | replay_verification | projection_recheck
	InputSourceSetHash    string                 `json:"input_source_set_hash"`
	InputSourceSet        map[string]interface{} `json:"input_source_set"`
	State                 string                 `json:"state"` // pending | running | sealed | failed | abandoned
	StartedAt             time.Time              `json:"started_at"`
	FinishedAt            *time.Time             `json:"finished_at,omitempty"`
	ObjectCount           int64                  `json:"object_count"`
	SymbolCount           int64                  `json:"symbol_count"`
	EdgeCount             int64                  `json:"edge_count"`
	ViolationCount        int64                  `json:"violation_count"`
	Status                string                 `json:"status"`
	VisibilityScope       string                 `json:"visibility_scope"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

// Violation mirrors OODGraphViolations
// (§6.table_surfaces.ood_graph_violations). One row per rejected
// materialization fact, projection failure, retrieval boundary breach, or
// corpus-conformance failure. Evidence carries graph-owned coordinates only;
// sibling-owned payload is forbidden per
// §6.encryption_posture.payload_boundary.
type Violation struct {
	OrganizationID        string                 `json:"organization_id"`
	ViolationID           string                 `json:"violation_id"`
	GraphSnapshotID       string                 `json:"graph_snapshot_id,omitempty"`
	MaterializationRunID  string                 `json:"materialization_run_id,omitempty"`
	ViolationCode         string                 `json:"violation_code"`
	SentinelCandidate     string                 `json:"sentinel_candidate,omitempty"`
	Severity              string                 `json:"severity"` // blocker | major | minor | info
	SourceAuthorityID     string                 `json:"source_authority_id,omitempty"`
	SourceStableReference string                 `json:"source_stable_reference,omitempty"`
	VersionCoordinate     string                 `json:"version_coordinate,omitempty"`
	SectionPath           string                 `json:"section_path,omitempty"`
	GraphObjectID         string                 `json:"graph_object_id,omitempty"`
	SymbolID              string                 `json:"symbol_id,omitempty"`
	GraphEdgeID           string                 `json:"graph_edge_id,omitempty"`
	Evidence              map[string]interface{} `json:"evidence"`
	Status                string                 `json:"status"`
	VisibilityScope       string                 `json:"visibility_scope"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
}

// ProjectionArtifact mirrors OODGraphProjectionArtifacts
// (§6.table_surfaces.ood_graph_projection_artifacts). One row per
// deterministic structured_ood_json projection bound to a sealed snapshot.
// ProjectionHash is SHA-256 over canonical JSON projection payload;
// RoundTripState records §5.round_trip_contract verification outcome.
type ProjectionArtifact struct {
	OrganizationID       string                 `json:"organization_id"`
	ProjectionArtifactID string                 `json:"projection_artifact_id"`
	GraphSnapshotID      string                 `json:"graph_snapshot_id"`
	ProjectionKind       string                 `json:"projection_kind"`
	ProjectionTargetKind string                 `json:"projection_target_kind"`
	ProjectionTargetID   string                 `json:"projection_target_id,omitempty"`
	ProjectionFormat     string                 `json:"projection_format"` // structured_ood_json
	ProjectionHash       string                 `json:"projection_hash"`
	ProjectionPayload    map[string]interface{} `json:"projection_payload"`
	RoundTripState       string                 `json:"round_trip_state"` // not_checked | equivalent | loss_detected | invalid
	MaterializationRunID string                 `json:"materialization_run_id,omitempty"`
	Status               string                 `json:"status"`
	VisibilityScope      string                 `json:"visibility_scope"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

// MarshalProjectionPayload renders a ProjectionArtifact.ProjectionPayload
// as canonical sorted-key JSON for projection_hash computation
// (§8.materialization_pipeline.write_projection_artifacts.projection_hash_algorithm).
// The hash binds the artifact to specific payload bytes; any non-canonical
// rendering breaks projection_hash reproducibility.
func MarshalProjectionPayload(payload map[string]interface{}) ([]byte, error) {
	// json.Marshal sorts map keys lexicographically — sufficient for the
	// §8 canonical_json_normalization.object_key_order requirement when the
	// payload was constructed deterministically. The materialization
	// pipeline's stage 16 may layer additional normalization before hash.
	return json.Marshal(payload)
}
