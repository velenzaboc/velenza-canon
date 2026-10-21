package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

// Mode names the operating mode of spec-graph. REQUIRED in config; no default.
const (
	ModeExperimentalBootstrap = "experimental_bootstrap"
	ModeProduction            = "production"
)

// SpecGraphConfig is the framework's whole config envelope. Loaded at boot
// from $SPEC_GRAPH_CONFIG (default ./spec-graph.config.json). EVERY behavioral
// value lives here. Per Vision Principle 7 (binary_is_never_sot) and per
// user direction: no defaults, no fallbacks, no hardcoded sentinel literals.
// If a required field is missing, the binary refuses to boot.
type SpecGraphConfig struct {
	// Comment and Pipeline are source-controlled bootstrap/example metadata.
	// The daemon does not execute Pipeline, but declaring it explicitly keeps
	// the top-level config grammar closed without breaking the separate
	// bootstrap CLIs that consume that envelope.
	Comment  string          `json:"_comment,omitempty"`
	Pipeline json.RawMessage `json:"pipeline,omitempty"`

	// Mode REQUIRED. experimental_bootstrap | production.
	Mode string `json:"mode"`

	// GoogleCredentials is the one identity-bound credential selector shared
	// by every Spanner, Spanner Admin, and Vertex AI client in this process.
	// Per-client credential selectors are rejected below so two clients cannot
	// silently resolve different ambient identities.
	GoogleCredentials gcpauth.Selector `json:"google_credentials"`

	// ExperimentalAdmitter REQUIRED in experimental_bootstrap mode; the literal
	// string the developer wants the binary to use as admitted_by during the
	// pre-genesis experimental phase. MUST be empty in production mode.
	ExperimentalAdmitter string `json:"experimental_admitter,omitempty"`

	// ExperimentalQueryEnabled gates the spec_graph_query verb. Honored only
	// in experimental_bootstrap mode; MUST be false in production mode.
	ExperimentalQueryEnabled bool `json:"experimental_query_enabled,omitempty"`

	// DefaultOrganizationID REQUIRED in experimental_bootstrap mode. The
	// tenant scope every bootstrap-phase submission carries. MUST be empty in
	// production mode (CallerContext supplies it per LOEF §2.1).
	DefaultOrganizationID string `json:"default_organization_id,omitempty"`

	// GenesisAdmitter is the literal string the application compares against
	// admitted_by to flag boot-time genesis admissions (is_non_genesis=false).
	// Whatever the dev configures — typically "GENESIS" but never hardcoded
	// in the binary. REQUIRED in production mode. Optional (and effectively
	// dead) in experimental_bootstrap mode, where the experimental admitter
	// is the only literal in play.
	GenesisAdmitter string `json:"genesis_admitter,omitempty"`

	// InitDatabaseAllowlist REQUIRED for spec-graph init and spec-graph reset
	// to operate. List of glob patterns the target database name must match.
	// Empty list (or missing field) causes init/reset to refuse.
	InitDatabaseAllowlist []string `json:"init_database_allowlist,omitempty"`

	// AllowSpannerEmulator is an explicit local-test gate. It is forbidden in
	// production and on non-loopback listeners; an ambient emulator variable
	// can never silently disable authentication for a hosted process.
	AllowSpannerEmulator bool `json:"allow_spanner_emulator,omitempty"`

	// Embedding is optional. When set, spec_graph_create / _update / _import
	// embed the node's canonical text at admission time and write it to
	// Nodes.embedding_v2; spec_graph_search embeds the query and runs
	// APPROX_COSINE_DISTANCE. When unset, both behaviors fail-closed with a
	// "no embedding configured" message.
	Embedding *EmbeddingConfig `json:"embedding,omitempty"`

	// ListenAddress is the host:port the MCP server binds to when serving
	// the Streamable HTTP transport. REQUIRED — there is no default per
	// Vision Principle 7 (binary_is_never_sot). For a single-user local
	// development setup, bind to 127.0.0.1:<port> so the server is
	// reachable only from the host. Network exposure requires the operator
	// to set 0.0.0.0:<port> deliberately and layer transport authentication
	// per StreamableHTTPOptions hooks (not configured here).
	ListenAddress string `json:"listen_address"`

	// Dedup is optional. When set, spec_graph_create runs three pre-admission
	// duplicate-detection layers BEFORE the ceremony writes any row:
	//   Layer 1 — definition_hash exact match  → idempotent return (no-op admit)
	//   Layer 2 — (node_kind, canonical_name)  → ErrDuplicateCanonicalName
	//   Layer 3 — embedding cosine similarity   → ErrPossibleDuplicate(candidates)
	// When unset, no dedup runs and create proceeds straight to admission. Per
	// AUTHORING_GUIDE §2 zero_duplication: dedup is load-bearing; production
	// configs should always set this.
	Dedup *DedupPolicyConfig `json:"dedup_policy,omitempty"`

	// ExternalSources is the config-resident trust registry for official
	// external documentation/repository coordinates. It is optional at boot,
	// but every registry-declared external-reference submission must match one
	// entry before staging or materialization.
	ExternalSources []ExternalSourceDescriptor `json:"external_sources,omitempty"`

	Substrates  []SubstrateDescriptor  `json:"substrates"`
	NodeKinds   []NodeKindDescriptor   `json:"node_kinds"`
	EdgeLabels  []EdgeLabelDescriptor  `json:"edge_labels"`
	Projections []ProjectionDescriptor `json:"projections"`
}

// DedupPolicyConfig governs pre-admission duplicate detection. Every field is
// REQUIRED when Dedup is set — no defaults. Per Vision Principle 7
// (binary_is_never_sot) threshold/limit/exclusion live in config, not the
// binary.
type DedupPolicyConfig struct {
	// EmbeddingSimilarityThreshold is the maximum cosine DISTANCE (not
	// similarity) at which a candidate is considered a possible duplicate.
	// gemini-embedding-001 produces cosine distance in [0, 2]; identical
	// content → 0, opposite → 2. A threshold of 0.08 corresponds to
	// "similarity > 0.92". Caller-tunable per node_kind via overrides if
	// needed in future; today one global threshold applies.
	EmbeddingSimilarityThreshold float64 `json:"embedding_similarity_threshold"`

	// CandidateLimit caps the top-N candidates surfaced when the embedding
	// search finds matches under the threshold. Bounds the size of
	// ErrPossibleDuplicate's detail payload.
	CandidateLimit int `json:"candidate_limit"`

	// SkipKinds disables dedup entirely for the listed node_kinds. Edges
	// are always exempt regardless (parallel edges with the same endpoints
	// are legitimately distinct by label per
	// 010_multi_role_same_target_edges_are_distinct_by_label). Use this
	// list for node_kinds where dedup is structurally inappropriate
	// (e.g. audit_record, snapshot).
	SkipKinds []string `json:"skip_kinds,omitempty"`
}

// EmbeddingConfig carries the per-tenant Vertex AI embedding setup. Every
// field is required when Embedding is set — no defaults. Authentication uses
// the same closed credential selector as the substrate's Spanner client.
type EmbeddingConfig struct {
	Provider     string `json:"provider"`       // "vertex_ai"
	Project      string `json:"project"`        // GCP project id
	Location     string `json:"location"`       // e.g. "us-central1"
	Model        string `json:"model"`          // e.g. "gemini-embedding-001"
	Dimensions   int    `json:"dimensions"`     // e.g. 3072
	MaxTextBytes int    `json:"max_text_bytes"` // truncate input above this
	// Legacy parser sentinels. The process-level selector owns Google
	// credentials; stale per-client fields fail validation below.
	CredentialsFile   string `json:"credentials_file,omitempty"`
	CredentialsSource string `json:"credentials_source,omitempty"`
}

// ProjectionDescriptor is the per-projection config row.
type ProjectionDescriptor struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	OwningSpec  string `json:"owning_spec"`
}

// Validate refuses any config that's incomplete for its declared mode. No
// defaults. No fallbacks. If a value is missing, Validate returns an error
// and loadConfig fails — the binary will not boot.
func (c SpecGraphConfig) Validate() error {
	if c.Mode == "" {
		return fmt.Errorf("mode is required (experimental_bootstrap | production)")
	}
	switch c.Mode {
	case ModeExperimentalBootstrap, ModeProduction:
		// allowed
	default:
		return fmt.Errorf("invalid mode %q: must be %q | %q", c.Mode, ModeExperimentalBootstrap, ModeProduction)
	}
	if err := c.GoogleCredentials.Validate("google_credentials", c.Mode == ModeProduction); err != nil {
		return err
	}
	if c.ListenAddress == "" {
		return fmt.Errorf("listen_address is required (host:port for the Streamable HTTP MCP transport, e.g. \"127.0.0.1:8765\")")
	}
	if c.AllowSpannerEmulator && c.Mode != ModeExperimentalBootstrap {
		return fmt.Errorf("allow_spanner_emulator is forbidden outside experimental_bootstrap mode")
	}
	if c.AllowSpannerEmulator && !strings.HasPrefix(c.ListenAddress, "127.0.0.1:") && !strings.HasPrefix(c.ListenAddress, "localhost:") {
		return fmt.Errorf("allow_spanner_emulator requires a loopback listen_address")
	}

	if c.Mode == ModeExperimentalBootstrap {
		if c.ExperimentalAdmitter == "" {
			return fmt.Errorf("experimental_admitter required in experimental_bootstrap mode (the literal string the binary will use as admitted_by)")
		}
		if c.DefaultOrganizationID == "" {
			return fmt.Errorf("default_organization_id required in experimental_bootstrap mode (no CallerContext envelope to source it from)")
		}
	}

	if c.Mode == ModeProduction {
		if c.ExperimentalAdmitter != "" {
			return fmt.Errorf("experimental_admitter must be empty in production mode (got %q)", c.ExperimentalAdmitter)
		}
		if c.DefaultOrganizationID != "" {
			return fmt.Errorf("default_organization_id must be empty in production mode (org_id resolved from CallerContext)")
		}
		if c.ExperimentalQueryEnabled {
			return fmt.Errorf("experimental_query_enabled must be false in production mode")
		}
		if c.GenesisAdmitter == "" {
			return fmt.Errorf("genesis_admitter required in production mode (the literal string the binary will compare admitted_by against to flag genesis admissions)")
		}
	}

	// Embedding validation. If set, every field must be present — no defaults.
	if c.Embedding != nil {
		e := c.Embedding
		if e.Provider == "" {
			return fmt.Errorf("embedding.provider required when embedding is set")
		}
		if e.Project == "" {
			return fmt.Errorf("embedding.project required when embedding is set")
		}
		if e.Location == "" {
			return fmt.Errorf("embedding.location required when embedding is set")
		}
		if e.Model == "" {
			return fmt.Errorf("embedding.model required when embedding is set")
		}
		if e.Dimensions <= 0 {
			return fmt.Errorf("embedding.dimensions required when embedding is set (>0)")
		}
		if e.MaxTextBytes <= 0 {
			return fmt.Errorf("embedding.max_text_bytes required when embedding is set (>0)")
		}
		if e.Provider != "vertex_ai" {
			return fmt.Errorf("embedding.provider must be vertex_ai")
		}
		if err := vertexai.ValidateEndpointComponents(e.Location, e.Project, e.Model); err != nil {
			return fmt.Errorf("embedding endpoint: %w", err)
		}
		if e.CredentialsFile != "" || e.CredentialsSource != "" {
			return fmt.Errorf("embedding: legacy per-client credential selector is forbidden; use google_credentials")
		}
	}

	seenExternalSourceIDs := map[string]struct{}{}
	for i, source := range c.ExternalSources {
		if err := source.validate(i); err != nil {
			return err
		}
		if _, duplicate := seenExternalSourceIDs[source.ID]; duplicate {
			return fmt.Errorf("external_sources[%d].id %q is duplicated", i, source.ID)
		}
		seenExternalSourceIDs[source.ID] = struct{}{}
	}
	for i := 0; i < len(c.ExternalSources); i++ {
		for j := i + 1; j < len(c.ExternalSources); j++ {
			if externalSourceDescriptorsOverlap(c.ExternalSources[i], c.ExternalSources[j]) {
				return fmt.Errorf("external_sources entries %q and %q overlap for at least one source class/object class/reference/version coordinate", c.ExternalSources[i].ID, c.ExternalSources[j].ID)
			}
		}
	}

	// Dedup policy validation. Every field is required when Dedup is set —
	// no defaults. Per Vision Principle 7: the policy values must come from
	// config, not from the binary.
	if c.Dedup != nil {
		d := c.Dedup
		if d.EmbeddingSimilarityThreshold <= 0 || d.EmbeddingSimilarityThreshold > 2 {
			return fmt.Errorf("dedup_policy.embedding_similarity_threshold required when dedup_policy is set (cosine distance in (0, 2])")
		}
		if d.CandidateLimit <= 0 {
			return fmt.Errorf("dedup_policy.candidate_limit required when dedup_policy is set (>0)")
		}
	}

	// Descriptor validation. Each node_kind and edge_label declares the
	// mechanical fields the binary consumes at runtime; protocol-extra
	// metadata flows through verbatim. See kinds.go / edges.go for the
	// binary_is_never_sot design intent.
	for i, k := range c.NodeKinds {
		if err := k.Validate(i); err != nil {
			return err
		}
	}
	if err := c.validateExternalSourceBindings(); err != nil {
		return err
	}
	for i, l := range c.EdgeLabels {
		if err := l.Validate(i); err != nil {
			return err
		}
	}
	if err := validateExternalReferenceEdgeIsolation(c.EdgeLabels); err != nil {
		return err
	}
	if len(c.ExternalSources) > 0 {
		if err := validateExternalReferenceEdgeRegistry(c.EdgeLabels); err != nil {
			return err
		}
	}

	// Substrate validation. Every substrate must declare its identity and DB.
	// A writable descriptor declares one complete storage generation (legacy
	// three-table admission, OODGraph-v2 seven-table materialization, or both
	// during cutover). Partial generations are rejected at boot.
	for i, s := range c.Substrates {
		if s.ID == "" {
			return fmt.Errorf("substrates[%d].id required", i)
		}
		if s.SpannerDatabase == "" {
			return fmt.Errorf("substrates[%d] (id=%q): spanner_database required", i, s.ID)
		}
		if s.CredentialsFile != "" || s.CredentialsSource != "" {
			return fmt.Errorf("substrates[%d] (id=%q): legacy per-client credential selector is forbidden; use google_credentials", i, s.ID)
		}
		if !s.ReadOnly {
			legacyCount := countNonEmpty(s.NodeTable, s.EdgeTable, s.AdmissionLogTable)
			oodCount := countNonEmpty(s.SnapshotTable, s.ObjectTable, s.SymbolTable, s.GraphEdgeTable, s.MaterializationRunTable, s.ViolationTable, s.ProjectionArtifactTable)
			if legacyCount != 0 && legacyCount != 3 {
				return fmt.Errorf("substrates[%d] (id=%q): node_table / edge_table / admission_log_table must be supplied together", i, s.ID)
			}
			if oodCount != 0 && oodCount != 7 {
				return fmt.Errorf("substrates[%d] (id=%q): all seven OODGraph-v2 table fields must be supplied together", i, s.ID)
			}
			if legacyCount == 0 && oodCount == 0 {
				return fmt.Errorf("substrates[%d] (id=%q): writable substrate requires either node_table / edge_table / admission_log_table or all seven OODGraph-v2 table fields", i, s.ID)
			}
		}
	}

	return nil
}

func externalSourceDescriptorsOverlap(a, b ExternalSourceDescriptor) bool {
	// SourceArtifactClass is caller-supplied evidence, not a policy selector.
	// Two descriptors that admit the same object/name/reference coordinate are
	// therefore ambiguous even when they advertise different source classes or
	// reference-match implementations: otherwise the caller could choose the
	// weaker trust policy by changing only source_artifact_class.
	sharedClass := false
	for _, class := range a.AllowedObjectClasses {
		if containsString(b.AllowedObjectClasses, class) {
			sharedClass = true
			break
		}
	}
	if !sharedClass {
		return false
	}
	if !strings.HasPrefix(a.VersionStableNamePrefix, b.VersionStableNamePrefix) && !strings.HasPrefix(b.VersionStableNamePrefix, a.VersionStableNamePrefix) {
		return false
	}
	return externalReferenceMatches(a, b.ReferencePrefix) || externalReferenceMatches(b, a.ReferencePrefix)
}

func countNonEmpty(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}

// validateExternalSourceBindings validates every configured intake source
// against the closed external node-kind registry. A protocol class may remain
// dormant with no source descriptor: class admissibility does not manufacture
// product/source authority, and imports still require an exact matching
// descriptor. This lets production examples fail closed when no product→repo
// authority has been admitted instead of using an organization-wide prefix.
func (c SpecGraphConfig) validateExternalSourceBindings() error {
	externalKinds := make(map[string]NodeKindDescriptor)
	for _, kind := range c.NodeKinds {
		if kind.ExternalReferenceRequired() {
			if _, allowed := externalReferenceObjectClasses[kind.Name()]; !allowed {
				return fmt.Errorf("node_kind %q cannot use source_coordinate_policy=%q: OOD external-reference object classes are closed", kind.Name(), sourceCoordinatePolicyExternalReferenceRequired)
			}
			if kind.SourceAuthority() != bootstrapSourceAuthority {
				return fmt.Errorf("node_kind %q external-reference source_authority=%q, want OOD Graph authority %q", kind.Name(), kind.SourceAuthority(), bootstrapSourceAuthority)
			}
			externalKinds[kind.Name()] = kind
		}
	}

	for i, source := range c.ExternalSources {
		for j, class := range source.AllowedObjectClasses {
			if _, allowed := externalReferenceObjectClasses[class]; !allowed {
				return fmt.Errorf("external_sources[%d].allowed_object_classes[%d]=%q is not one of the eight OOD external-reference object classes", i, j, class)
			}
			kind, ok := externalKinds[class]
			if !ok {
				return fmt.Errorf("external_sources[%d].allowed_object_classes[%d]=%q must name a node_kind with source_coordinate_policy=%q", i, j, class, sourceCoordinatePolicyExternalReferenceRequired)
			}
			if kind.SourceAuthority() == "" {
				return fmt.Errorf("external_sources[%d].allowed_object_classes[%d]=%q has no node_kind source_authority", i, j, class)
			}
		}
	}
	if len(externalKinds) > 0 {
		if c.Embedding == nil || c.Embedding.Dimensions != externalReferenceEmbeddingDimensions {
			return fmt.Errorf("external-reference node_kinds require embedding.dimensions=%d", externalReferenceEmbeddingDimensions)
		}
	}
	return nil
}

// loadConfig reads the config envelope from $VELENZA_CANON_CONFIG or
// $SPEC_GRAPH_CONFIG (default ./spec-graph.config.json). If the file is
// missing, the binary fails to boot. If the file exists but Validate()
// rejects it, the binary fails to boot. There are no fallbacks.
func loadConfig() (SpecGraphConfig, error) {
	path := resolveConfigPath(os.Getenv)
	data, err := os.ReadFile(path)
	if err != nil {
		return SpecGraphConfig{}, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := rejectDuplicateJSONKeysRecursive(data, "spec_graph_config"); err != nil {
		return SpecGraphConfig{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := gcpauth.ValidateConfigCredentialShape(data); err != nil {
		return SpecGraphConfig{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	var cfg SpecGraphConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return SpecGraphConfig{}, fmt.Errorf("parse config %q: %w", path, err)
	}
	var trailing interface{}
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return SpecGraphConfig{}, fmt.Errorf("parse config %q: multiple JSON values are forbidden", path)
		}
		return SpecGraphConfig{}, fmt.Errorf("parse config %q trailing data: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return SpecGraphConfig{}, fmt.Errorf("validate config %q: %w", path, err)
	}
	return cfg, nil
}
