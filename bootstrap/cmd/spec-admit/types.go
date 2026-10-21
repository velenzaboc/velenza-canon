// Package main implements spec-admit, the final stage of the staged
// spec-ingestion pipeline. It takes a validated, deduplicated concept
// table and emits a directory of submission JSON files in the shape
// `spec_graph_import` accepts. The caller then runs `spec_graph_import
// file_path=<dir>` to actually admit the concepts into the graph.
//
// The split between "produce submission files" (spec-admit) and "admit
// them" (spec_graph_import) is deliberate:
//   - spec-admit runs as a deterministic transform (no graph state
//     mutation, no MCP calls) — auditable from inputs alone.
//   - spec_graph_import handles the existing single-admission-path
//     ceremony (10-step pre-sign / sign / post-sign / typed insert)
//     and atomicity — that path is canonical, not duplicated here.
//
// Per Vision Principle 7 (binary is never source of truth), spec-admit
// produces files; spec-graph + Spanner own state.
package main

// ConceptTable is the post-dedup, post-lint, post-rewrite output of
// Stages 2–4. spec-admit consumes it and emits submission files.
type ConceptTable struct {
	ConceptDomain string    `json:"concept_domain"`
	Concepts      []Concept `json:"concepts"`
	Edges         []Edge    `json:"edges,omitempty"`
}

// Concept is one node-to-be. Carries the resolved canonical_name plus
// the kind-specific contract + payload shape. SourceRefs records the
// provenance (multiple .ood.json paths can converge on one concept
// after dedup) — these are metadata, not embedded in contract/payload
// per R13.
type Concept struct {
	CanonicalName string                 `json:"canonical_name"`
	NodeKind      string                 `json:"node_kind"`
	Contract      map[string]interface{} `json:"contract,omitempty"`
	Payload       map[string]interface{} `json:"payload,omitempty"`
	SourceRefs    []string               `json:"source_refs,omitempty"`
}

// Edge is one edge-to-be. References source + target by canonical_name
// (resolved to graph_object_id at admission time by spec_graph_link's
// stable_id lookup).
type Edge struct {
	EdgeLabel    string `json:"edge_label"`
	SourceName   string `json:"source_name"`
	TargetName   string `json:"target_name"`
}

// Submission is the on-disk shape spec_graph_import accepts. Matches
// spec-graph's ArtifactSubmission JSON shape (snake_case per
// REQUIREMENTS.md §12.1).
type Submission struct {
	ArtifactType   string                 `json:"artifact_type"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	NodeKind       string                 `json:"node_kind,omitempty"`
	EdgeLabel      string                 `json:"edge_label,omitempty"`
	StableID       string                 `json:"stable_id,omitempty"`
	Contract       map[string]interface{} `json:"contract,omitempty"`
	Payload        map[string]interface{} `json:"payload,omitempty"`
	SourceID       string                 `json:"source_id,omitempty"`
	TargetID       string                 `json:"target_id,omitempty"`
}
