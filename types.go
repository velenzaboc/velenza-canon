package main

import (
	"time"
)

// Node is the universal corpus-identity primitive (top tier per the three-tier
// framing). A Node owns its stable_id, its version chain, and its contract
// surface. The node_kind is the projection axis: which middle-tier projection
// spec governs the node, and which bottom-tier substrate stores its body.
//
// Field NAMES here are universal-conceptual. Column names in the eventual
// Spanner Nodes table may differ; the mapping is the substrate adapter's job.
type Node struct {
	NodeID         string      `json:"node_id"`
	NodeKind       string      `json:"node_kind"`
	OrganizationID string      `json:"organization_id"`
	Status         string      `json:"status"` // draft | active | superseded | retired
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	CurrentVersion NodeVersion `json:"current_version"`
}

// NodeVersion is one admitted version of a Node. The contract is the stable
// promise; the payload is the version-specific body.
//
// Contract / Payload are typed as map[string]interface{} so the MCP
// outputSchema reflects to {"type":"object","additionalProperties":true} —
// the canonical "any JSON object" form Claude Code accepts. Plain
// interface{} reflects to bare boolean `true`, which strict MCP clients
// reject. Every seed file shape uses JSON objects, so the constraint is
// natural.
type NodeVersion struct {
	NodeID  string `json:"node_id"`
	Version int    `json:"version"`
	Status  string `json:"status"`

	Contract map[string]interface{} `json:"contract,omitempty"`
	Payload  map[string]interface{} `json:"payload,omitempty"`

	// Admission provenance — populated by the ceremony.
	DefinitionHash string    `json:"definition_hash,omitempty"`
	ManifestHash   string    `json:"manifest_hash,omitempty"`
	SignatureChain []string  `json:"signature_chain,omitempty"`
	AdmittedAt     time.Time `json:"admitted_at"`
	AdmittedBy     string    `json:"admitted_by,omitempty"`
	AdmissionRunID string    `json:"admission_run_id,omitempty"`

	// Spec-lineage refs per REQUIREMENTS.md §2 (spec_lineage_admission_surface).
	// Every admitted node carries back-references to the spec node that conforms it.
	GoverningSpecRef        string   `json:"governing_spec_ref,omitempty"`
	SourceSpecLineageRefs   []string `json:"source_spec_lineage_refs,omitempty"`
	SpecSectionRef          string   `json:"spec_section_ref,omitempty"`
	SpecSymbolRef           string   `json:"spec_symbol_ref,omitempty"`
	NodeCreationContractRef string   `json:"node_creation_contract_ref,omitempty"`

	// EmbeddingV2 is the gemini-embedding-001 vector (3072d by default).
	// Populated at admission time when Env.Embed is configured; written into
	// the Nodes.embedding_v2 column. Returned on reads so spec_graph_get and
	// _list callers can see whether a node carries an embedding.
	EmbeddingV2 []float32 `json:"-"`
}

// Edge is a typed directional link between two nodes. Edges are themselves
// admitted artifacts (artifact_type=edge will be one of the registry members
// once the Node Identity & Admission spec lands).
type Edge struct {
	EdgeID         string    `json:"edge_id"`
	OrganizationID string    `json:"organization_id"`
	SourceID       string    `json:"source_id"`
	TargetID       string    `json:"target_id"`
	EdgeLabel      string    `json:"edge_label"`
	Status         string    `json:"status"`
	AdmittedAt     time.Time `json:"admitted_at"`

	// SourceVersion / TargetVersion pin the edge to specific versions of the
	// endpoints when the edge_label semantics require it (e.g. supersedes
	// references both versions explicitly).
	SourceVersion int `json:"source_version,omitempty"`
	TargetVersion int `json:"target_version,omitempty"`

	// ReciprocalEdgeID points to the mirror edge created automatically when
	// the edge_label declares reciprocity (e.g. load_bearing_for ↔ depends_on).
	ReciprocalEdgeID string `json:"reciprocal_edge_id,omitempty"`
}

// AdmissionRecord is the canonical receipt of one admission ceremony. Mirrors
// the ArtifactAdmissionLog row. Returned from every write verb.
//
// The first six fields below (artifact_type, organization_id, artifact_id,
// admitted_at, definition_hash, manifest_hash) ARE the canonical signature
// input vector per REQUIREMENTS.md §2. Every KMS-sign step (ceremony step 6)
// consumes exactly this set; reordering or omitting any of them breaks the
// signature chain contract.
type AdmissionRecord struct {
	RunID           string       `json:"run_id"`
	ArtifactType    string       `json:"artifact_type"`
	OrganizationID  string       `json:"organization_id"`
	ArtifactID      string       `json:"artifact_id"`
	ArtifactVersion int          `json:"artifact_version"`
	AdmittedAt      time.Time    `json:"admitted_at"`
	AdmittedBy      string       `json:"admitted_by"`
	DefinitionHash  string       `json:"definition_hash"`
	ManifestHash    string       `json:"manifest_hash"`
	SignatureChain  []string     `json:"signature_chain"`
	PassReport      []PassResult `json:"pass_report"`

	// IsNonGenesis is TRUE for ceremony-by-real-principal admissions and
	// FALSE for boot-time GENESIS or experimental_bootstrap admissions. Set
	// by the ceremony based on the resolved admitter compared against the
	// configured genesis + experimental admitter literals. Written into
	// ArtifactAdmissionLog.is_non_genesis verbatim.
	IsNonGenesis bool `json:"is_non_genesis"`
}

// PassResult records one compiler-pass outcome inside the ceremony.
type PassResult struct {
	PassName string `json:"pass_name"`
	Outcome  string `json:"outcome"` // passed | failed | skipped
	Evidence string `json:"evidence,omitempty"`
}

// Snapshot is a sealed retrieval coordinate. Stateless HTTP callers pass its
// id explicitly on every historical read; omitted graph_snapshot_id derives
// the current eligible snapshot for that request.
type Snapshot struct {
	SnapshotID     string    `json:"snapshot_id"`
	OrganizationID string    `json:"organization_id"`
	GraphVersion   int       `json:"graph_version"`
	SnapshotKind   string    `json:"snapshot_kind"`
	SealedAt       time.Time `json:"sealed_at"`
	SnapshotState  string    `json:"snapshot_state"` // sealed | …
	Status         string    `json:"status"`         // active | superseded | archived
}

// EdgeArchiveResult is returned by spec_graph_edge_archive. ArchivedEdgeIDs
// lists every graph_edge_id that flipped from status='active' to
// status='archived' in the operation — typically one id, OR two when the
// edge declared a reciprocal mirror (the primary AND its inverse are
// archived atomically so the graph never carries an orphan-pair). When
// the edge was already archived (idempotent re-archive) RowsAffected is 0
// and ArchivedEdgeIDs is empty; this is a successful no-op, not an error.
// AuditRecordID names the audit_record graph_object_id emitted alongside
// the archive (empty when no rows were affected — idempotent no-op
// doesn't emit an audit_record because no event happened).
type EdgeArchiveResult struct {
	ArchivedEdgeIDs []string `json:"archived_edge_ids"`
	RowsAffected    int      `json:"rows_affected"`
	AuditRecordID   string   `json:"audit_record_id,omitempty"`
}

// NodeArchiveResult is returned by spec_graph_node_archive. ArchivedNodeID
// names the graph_object_id that flipped from status='active' to
// status='archived'. AuditRecordID names the audit_record graph_object_id
// emitted in the same Spanner ReadWriteTransaction. DanglingDependents,
// when non-empty, is the list of node ids with active incoming references
// to the archive target — caller MUST archive (or unlink) those first; the
// verb refused. RowsAffected is 0 on idempotent re-archive (target already
// archived).
type NodeArchiveResult struct {
	ArchivedNodeID     string   `json:"archived_node_id"`
	RowsAffected       int      `json:"rows_affected"`
	AuditRecordID      string   `json:"audit_record_id,omitempty"`
	DanglingDependents []string `json:"dangling_dependents,omitempty"`
}

// SimilarNode pairs a Node with its cosine distance from the query embedding.
// Returned by SubstrateAdapter.FindSimilarByEmbedding for Layer-3 pre-admission
// dedup. Cosine distance is in [0, 2]; identical content → 0, opposite → 2.
type SimilarNode struct {
	Node     Node    `json:"node"`
	Distance float64 `json:"cosine_distance"`
}

// -------------------- output wrappers --------------------
//
// MCP SDK requires every tool's structured output to be a JSON object (i.e.,
// a struct), never a bare slice or scalar. These wrappers are the structured
// outputs for verbs that conceptually return collections or byte payloads.

type NodeListResult struct {
	Nodes []Node `json:"nodes"`
}

type EdgeListResult struct {
	Edges []Edge `json:"edges"`
}

type VersionListResult struct {
	Versions []NodeVersion `json:"versions"`
}

// DiffResult is returned from spec_graph_diff. Per REQUIREMENTS.md §12.2 the
// structural diff is RFC 6902 JSON Patch shape over the (contract + payload)
// tree, uniform across all node_kinds. Operations carry both new and old
// values at each path so callers can reconstruct either side.
type DiffResult struct {
	NodeID       string   `json:"node_id"`
	VersionA     int      `json:"version_a"`
	VersionB     int      `json:"version_b"`
	StatusChange string   `json:"status_change,omitempty"`
	KindChange   string   `json:"kind_change,omitempty"`
	Operations   []DiffOp `json:"operations"`
	Identical    bool     `json:"identical"`
}

// DiffOp is one RFC 6902 patch operation augmented with old_value so the
// diff is reversible without a second comparison. Value/OldValue are
// interface{} because RFC 6902 values may be any JSON value (object, array,
// string, number, boolean, null). The jsonschema description tags force the
// SDK reflector to emit `{"description":"..."}` rather than bare boolean
// `true`, which strict MCP clients reject.
type DiffOp struct {
	Op       string      `json:"op" jsonschema:"add | remove | replace"`
	Path     string      `json:"path" jsonschema:"RFC 6901 JSON Pointer"`
	Value    interface{} `json:"value,omitempty" jsonschema:"new value for add/replace operations (any JSON value)"`
	OldValue interface{} `json:"old_value,omitempty" jsonschema:"prior value for replace/remove operations (any JSON value)"`
}

type ProjectResult struct {
	Projection  string `json:"projection,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body"`
}

// QueryResult is returned from spec_graph_query (REQUIREMENTS.md §3.4).
// Each row is a column-name → value map; columns lists the names in
// declared order.
type QueryResult struct {
	Columns []string                 `json:"columns"`
	Rows    []map[string]interface{} `json:"rows"`
}

// ImportResult is returned from spec_graph_import (REQUIREMENTS.md §3.6).
type ImportResult struct {
	Total                 int               `json:"total"`
	Admitted              int               `json:"admitted"`
	RelationshipsAdmitted int               `json:"relationships_admitted,omitempty"`
	Records               []AdmissionRecord `json:"records,omitempty"`
	OrderedIDs            []string          `json:"ordered_ids,omitempty"`
	OrderedEdgeIDs        []string          `json:"ordered_edge_ids,omitempty"`
	GraphSnapshotID       string            `json:"graph_snapshot_id,omitempty"`
}

// HealthResult is returned from spec_graph_health (REQUIREMENTS.md §3.7).
type HealthResult struct {
	Mode              string            `json:"mode"`
	ActiveSnapshotPin string            `json:"active_snapshot_pin,omitempty"`
	RegistrySizes     map[string]int    `json:"registry_sizes"`
	Substrates        []SubstrateHealth `json:"substrates"`
	OverallReady      bool              `json:"overall_ready"`
	BlockingIssues    []string          `json:"blocking_issues,omitempty"`
}

// SubstrateHealth is the per-substrate health probe outcome.
type SubstrateHealth struct {
	ID            string `json:"id"`
	Database      string `json:"database,omitempty"`
	Reachable     bool   `json:"reachable"`
	SchemaApplied bool   `json:"schema_applied"`
	Error         string `json:"error,omitempty"`
}

// ArtifactSubmission is the input to AdmitArtifact — what the caller proposes
// to admit. The ceremony fills in DefinitionHash, ManifestHash, SignatureChain
// and produces an AdmissionRecord.
//
// JSON tags applied per REQUIREMENTS.md §12.1 — snake_case keys throughout so
// seed-file JSON deserializes into this struct correctly. Contract/Payload
// are map[string]interface{} so the MCP schema reflects the canonical
// {"type":"object","additionalProperties":true} form Claude Code accepts
// (interface{} reflects to bare `true` which strict clients reject).
type ArtifactSubmission struct {
	ArtifactType      string                 `json:"artifact_type,omitempty"`
	OrganizationID    string                 `json:"organization_id,omitempty"`
	NodeKind          string                 `json:"node_kind,omitempty"`
	EdgeLabel         string                 `json:"edge_label,omitempty"`
	EdgeSourceID      string                 `json:"edge_source_id,omitempty"`
	EdgeTargetID      string                 `json:"edge_target_id,omitempty"`
	EdgeSourceVersion int                    `json:"edge_source_version,omitempty"`
	EdgeTargetVersion int                    `json:"edge_target_version,omitempty"`
	StableID          string                 `json:"stable_id,omitempty"`
	Contract          map[string]interface{} `json:"contract,omitempty"`
	Payload           map[string]interface{} `json:"payload,omitempty"`
	PriorVersion      *NodeVersion           `json:"prior_version,omitempty"`
	IsRetirement      bool                   `json:"is_retirement,omitempty"`
	Submitter         string                 `json:"submitter,omitempty"`
	GoverningSpec     string                 `json:"governing_spec,omitempty"`
	SpecSection       string                 `json:"spec_section,omitempty"`

	// SourceCoordinate is the source-authority-owned identity consumed by
	// OOD Graph materialization. It is optional only for node kinds that do
	// not declare source_coordinate_policy=external_reference_required, so
	// the bootstrap-spine seed format remains byte-for-byte compatible: when
	// absent there, handleImport derives the existing protocol-owned
	// name/unversioned/$ coordinate.
	//
	// When present, every identity field is required and validated before
	// substrate I/O. This keeps external_reference_doc, reference_page,
	// api_symbol, and other sibling-backed objects from being collapsed into
	// the bootstrap name/unversioned identity family.
	SourceCoordinate *ArtifactSourceCoordinate `json:"source_coordinate,omitempty"`
}

// ExternalRelationship is one typed, directed relationship authored as part
// of an external-reference import. Endpoints are canonical names rather than
// caller-minted graph_object_ids: handleImport resolves both names against
// the objects in the SAME batch, validates their actual registered classes,
// and derives the stable edge identity and authoring path itself.
//
// Only the eight OOD_GRAPH_PROTOCOL_v1 §8 external-ingestion labels are
// accepted. This shape intentionally exposes no endpoint kind/version,
// source authority, graph id, or source path for a caller to forge.
type ExternalRelationship struct {
	EdgeLabel           string `json:"edge_label"`
	SourceCanonicalName string `json:"source_canonical_name"`
	TargetCanonicalName string `json:"target_canonical_name"`
}

// ArtifactSourceCoordinate is the caller-supplied source identity for one
// OOD Graph object. It is metadata, never authored contract/payload content.
// The field set matches OOD_GRAPH_PROTOCOL_v1 §8 parser object_evidence.
// On external-reference input, source_content_hash is only an optional
// expected SHA-256. The trusted fetch process owns the stored digest,
// source_content_hash_owner, retrieved_at, and (for content_digest registry
// mode) final version_coordinate. Non-external rows use only the internal
// bootstrap coordinate and never accept this struct from callers.
type ArtifactSourceCoordinate struct {
	SourceAuthorityID      string `json:"source_authority_id" jsonschema:"required registered source authority UUID"`
	SourceArtifactClass    string `json:"source_artifact_class" jsonschema:"required closed OOD external trust class"`
	SourceRefKind          string `json:"source_ref_kind" jsonschema:"required; external references use coordinate"`
	SourceStableReference  string `json:"source_stable_reference" jsonschema:"required byte-canonical registered resource/locator reference"`
	VersionCoordinate      string `json:"version_coordinate,omitempty" jsonschema:"omit for both content_digest and upstream_pinned policies; trusted runtime evidence derives the final source-named coordinate"`
	SectionPath            string `json:"section_path" jsonschema:"required; external references use $ while URL fragment carries the verified locator"`
	SourceContentHash      string `json:"source_content_hash,omitempty" jsonschema:"optional caller expectation: 64 lowercase hexadecimal SHA-256; trusted fetch owns the stored digest"`
	SourceContentHashOwner string `json:"source_content_hash_owner,omitempty" jsonschema:"trusted-fetch output; callers must omit"`
	RetrievedAt            string `json:"retrieved_at,omitempty" jsonschema:"trusted-fetch output; callers must omit"`
	LicenseEvidence        string `json:"license_evidence_when_available,omitempty"`
}
