// Package main implements spec-dedup-verify, Stage 2b of the staged
// spec-ingestion pipeline. It consumes ClusterBuckets produced by
// spec-cluster (Phase F) and uses Vertex AI Gemini Flash to ratify or
// reject each verify_required pair, plus pick canonical names for each
// auto_merge cluster.
//
// Per Vision Principle 1 (trust / auditability): every Flash call writes
// a ledger entry recording prompt template path, raw response, parsed
// verdict, and decision applied. The ledger is the audit trail; without
// it, merges become opaque.
//
// Per Vision Principle 7 (binary_is_never_sot) and explicit user
// directive: every parameter lives in spec-graph.config.json, every
// prompt template is a text file under bootstrap/prompts/, and the
// template files are RE-READ on every Flash invocation (no in-memory
// caching).
package main

// ClusterBuckets is the input shape from spec-cluster. Mirrors the type
// in bootstrap/cmd/spec-cluster/types.go.
type ClusterBuckets struct {
	ConceptDomain    string         `json:"concept_domain"`
	RecordsInspected int            `json:"records_inspected"`
	Thresholds       ThresholdsUsed `json:"thresholds_used"`
	AutoMerge        []Cluster      `json:"auto_merge"`
	VerifyRequired   []Cluster      `json:"verify_required"`
	NoMatch          []ConceptRecord `json:"no_match"`
}

// ThresholdsUsed mirrors the same-named struct from spec-cluster.
type ThresholdsUsed struct {
	AutoMergeDistance float64 `json:"auto_merge_distance"`
	ReviewDistance    float64 `json:"review_distance"`
}

// Cluster mirrors the same-named struct from spec-cluster.
type Cluster struct {
	Representative ConceptRecord   `json:"representative"`
	Members        []ClusterMember `json:"members"`
}

// ClusterMember mirrors the same-named struct from spec-cluster.
type ClusterMember struct {
	Record             ConceptRecord `json:"record"`
	DistanceFromAnchor float64       `json:"distance_from_anchor"`
}

// ConceptRecord mirrors the same-named struct from spec-cluster /
// spec-extract.
type ConceptRecord struct {
	SourceSpecID   string `json:"source_spec_id"`
	SourceSpecName string `json:"source_spec_name"`
	SourceFile     string `json:"source_file"`
	SourcePath     string `json:"source_path"`
	ConceptDomain  string `json:"concept_domain"`
	NodeKind       string `json:"node_kind"`
	LeafName       string `json:"leaf_name"`
	RawValue       string `json:"raw_value"`
}

// DedupDecisions is the primary output: per-cluster ratifications and
// per-pair outcomes for verify_required clusters.
type DedupDecisions struct {
	ConceptDomain string             `json:"concept_domain"`
	AutoMerge     []AutoMergeDecision `json:"auto_merge"`
	Verified      []VerifyDecision    `json:"verified"`
	Escalations   []EscalatedPair     `json:"escalations"`
	NoMatch       []ConceptRecord     `json:"no_match"`
}

// AutoMergeDecision records the canonical_name Flash chose for an
// auto_merge cluster. Members carry forward the cluster's source_refs
// for the eventual ConceptTable.
type AutoMergeDecision struct {
	ChosenName        string          `json:"chosen_name"`
	ChosenNameSource  string          `json:"chosen_name_source"` // "flash_selected" | "flash_proposed"
	RepresentativeRaw string          `json:"representative_raw_value"`
	Members           []ConceptRecord `json:"members"`
}

// VerifyDecision records the outcome of a Flash same-concept check on a
// pair of records inside a verify_required cluster.
type VerifyDecision struct {
	A         ConceptRecord `json:"a"`
	B         ConceptRecord `json:"b"`
	Verdict   string        `json:"verdict"`   // "merge" | "split"
	Rationale string        `json:"rationale"`
}

// EscalatedPair is a verify_required pair where Flash returned
// "uncertain" or where the parsed response was malformed. These go to the
// Stage 2c agent dispatch under the narrowed brief.
type EscalatedPair struct {
	A         ConceptRecord `json:"a"`
	B         ConceptRecord `json:"b"`
	Reason    string        `json:"reason"` // "flash_uncertain" | "flash_unparseable" | "flash_error"
	RawFlash  string        `json:"raw_flash_response,omitempty"`
}

// FlashLedgerEntry records ONE Flash API call. The ledger lets every
// merge or split decision be traced back to the prompt template version,
// the model used, the raw response, and the decision applied. Audit
// trail per Vision Principle 1 trust requirement.
type FlashLedgerEntry struct {
	CallID         string        `json:"call_id"`
	ConceptDomain  string        `json:"concept_domain"`
	PromptTemplate string        `json:"prompt_template_path"`
	Model          string        `json:"model"`
	A              ConceptRecord `json:"a,omitempty"`
	B              ConceptRecord `json:"b,omitempty"`
	Candidates     []string      `json:"candidates,omitempty"`
	Statement      string        `json:"statement,omitempty"`
	RenderedPrompt string        `json:"rendered_prompt"`
	RawResponse    string        `json:"raw_response"`
	ParsedVerdict  string        `json:"parsed_verdict,omitempty"`
	ParsedName     string        `json:"parsed_name,omitempty"`
	Rationale      string        `json:"rationale"`
	DecisionApplied string       `json:"decision_applied"`
	Error          string        `json:"error,omitempty"`
}

// FlashLedger is the persistent audit trail.
type FlashLedger struct {
	ConceptDomain string             `json:"concept_domain"`
	Entries       []FlashLedgerEntry `json:"entries"`
}
