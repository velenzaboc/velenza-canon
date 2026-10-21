// Package main implements spec-cluster, Stage 2a of the staged spec-ingestion
// pipeline. It reads ConceptRecords produced by spec-extract, embeds each via
// Vertex AI, and threshold-clusters them into three buckets that drive the
// downstream pipeline stages (Flash verify in 2b, agent escalation in 2c).
//
// Per Vision Principle 7 (binary_is_never_sot) and explicit user directive,
// every behavioral value lives in spec-graph.config.json — zero hardcoded
// defaults, fail-closed on missing config.
package main

// ConceptRecord is one flat extraction emitted by spec-extract. Shape MUST
// match bootstrap/cmd/spec-extract/types.go.ConceptRecord. Duplicated here so
// spec-cluster is independent of spec-extract's compile state; the JSON tag
// contract is the load-bearing surface.
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

// EmbeddedRecord is a ConceptRecord plus its Vertex AI embedding. Cached to
// disk so re-runs don't re-embed (the input record set evolves slowly across
// pipeline iterations).
type EmbeddedRecord struct {
	Record    ConceptRecord `json:"record"`
	Embedding []float32     `json:"embedding"`
}

// EmbeddingCache is the persisted form of spec-cluster's per-domain
// embedding store. Re-runs read this file; only records whose
// (source_file, source_path, leaf_name) key isn't present get re-embedded.
type EmbeddingCache struct {
	ConceptDomain string           `json:"concept_domain"`
	Embedded      []EmbeddedRecord `json:"embedded"`
}

// ClusterBuckets is the spec-cluster CLI's output shape. Each record from
// the input lands in exactly one bucket per the configured thresholds.
type ClusterBuckets struct {
	ConceptDomain    string         `json:"concept_domain"`
	RecordsInspected int            `json:"records_inspected"`
	Thresholds       ThresholdsUsed `json:"thresholds_used"`
	AutoMerge        []Cluster      `json:"auto_merge"`
	VerifyRequired   []Cluster      `json:"verify_required"`
	NoMatch          []ConceptRecord `json:"no_match"`
}

// ThresholdsUsed records the config values applied to THIS bucketization so
// the downstream stages and audit pass know what cosine-distance discipline
// was in force. Per audit: every classification must be traceable to the
// thresholds that produced it.
type ThresholdsUsed struct {
	AutoMergeDistance float64 `json:"auto_merge_distance"`
	ReviewDistance    float64 `json:"review_distance"`
}

// Cluster groups N records the cosine-distance pass deemed near. The
// representative is the cluster's chosen anchor (lowest mean distance to
// other members); downstream stages may use it for cluster-level naming or
// referencing.
type Cluster struct {
	Representative ConceptRecord   `json:"representative"`
	Members        []ClusterMember `json:"members"`
}

// ClusterMember is one record inside a cluster, annotated with its cosine
// distance from the representative. Distances inform Flash-verify (Stage 2b)
// which pairs to prioritize.
type ClusterMember struct {
	Record            ConceptRecord `json:"record"`
	DistanceFromAnchor float64       `json:"distance_from_anchor"`
}
