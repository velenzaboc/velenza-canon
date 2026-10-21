package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

// Config is the minimal subset of spec-graph.config.json that spec-cluster
// consumes. It is the SAME file the spec-graph daemon reads; this struct
// declares only the fields this CLI needs and ignores the rest.
//
// Per Vision Principle 7 (binary_is_never_sot) and the explicit user
// directive: every value here is REQUIRED. No defaults. No fallbacks. A
// missing or zero value causes spec-cluster to refuse to run.
type Config struct {
	Mode              string           `json:"mode"`
	GoogleCredentials gcpauth.Selector `json:"google_credentials"`
	Embedding         *EmbeddingConfig `json:"embedding"`
	Pipeline          *PipelineConfig  `json:"pipeline"`
}

// EmbeddingConfig mirrors the spec-graph main package's same-named struct
// (intentionally duplicated to keep this CLI buildable independently of the
// main package's compile state). The JSON tag contract is load-bearing.
type EmbeddingConfig struct {
	Provider     string `json:"provider"`
	Project      string `json:"project"`
	Location     string `json:"location"`
	Model        string `json:"model"`
	Dimensions   int    `json:"dimensions"`
	MaxTextBytes int    `json:"max_text_bytes"`
	// Legacy parser sentinels. They remain visible only so a stale shared
	// config fails explicitly; the process-level selector owns credentials.
	CredentialsFile   string `json:"credentials_file,omitempty"`
	CredentialsSource string `json:"credentials_source,omitempty"`
}

// PipelineConfig is the pipeline-stage configuration block in
// spec-graph.config.json. spec-cluster reads Cluster; spec-dedup-verify
// will read Flash (Phase G).
type PipelineConfig struct {
	Cluster *ClusterConfig `json:"cluster"`
}

// ClusterConfig declares the threshold + batch values spec-cluster uses.
// All required. Per the directive: zero defaults; if any field is missing
// or zero, spec-cluster refuses.
type ClusterConfig struct {
	// AutoMergeDistance is the cosine-distance ceiling for auto-merge.
	// Pairs with distance < this go to the auto_merge bucket. gemini-
	// embedding-001 produces cosine distance in [0, 2]; identical
	// content → 0.
	AutoMergeDistance float64 `json:"auto_merge_distance"`

	// ReviewDistance is the cosine-distance ceiling for verify-required.
	// Pairs with AutoMergeDistance <= distance < this go to the
	// verify_required bucket. Pairs above this are not clustered
	// together.
	ReviewDistance float64 `json:"review_distance"`

	// EmbeddingBatchSize caps the number of records embedded in flight at
	// once. The Vertex AI client is per-call serial; this value is the
	// concurrency knob for spec-cluster's outer loop.
	EmbeddingBatchSize int `json:"embedding_batch_size"`
}

// LoadConfig reads spec-graph.config.json at path and validates it.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := gcpauth.ValidateConfigCredentialShape(data); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validate config %q: %w", path, err)
	}
	return &c, nil
}

// Validate refuses any config that doesn't fully populate the fields
// spec-cluster reads. Per directive: zero defaults; fail-closed.
func (c *Config) Validate() error {
	if err := c.ValidateGoogleCredentialTopology(); err != nil {
		return err
	}
	if c.Embedding == nil {
		return fmt.Errorf("embedding section required (spec-cluster needs Vertex AI access)")
	}
	if err := c.Embedding.Validate(); err != nil {
		return fmt.Errorf("embedding: %w", err)
	}
	if c.Pipeline == nil {
		return fmt.Errorf("pipeline section required")
	}
	if c.Pipeline.Cluster == nil {
		return fmt.Errorf("pipeline.cluster section required")
	}
	if err := c.Pipeline.Cluster.Validate(); err != nil {
		return fmt.Errorf("pipeline.cluster: %w", err)
	}
	return nil
}

func (c *Config) ValidateGoogleCredentialTopology() error {
	if c == nil {
		return fmt.Errorf("config required")
	}
	switch c.Mode {
	case "experimental_bootstrap", "production":
		// Closed by the selector below.
	case "":
		return fmt.Errorf("mode required")
	default:
		return fmt.Errorf("mode %q is unsupported", c.Mode)
	}
	return c.GoogleCredentials.Validate("google_credentials", c.Mode == "production")
}

// Validate on EmbeddingConfig. Every field required.
func (e *EmbeddingConfig) Validate() error {
	if e.Provider == "" {
		return fmt.Errorf("provider required (e.g. \"vertex_ai\")")
	}
	if e.Project == "" {
		return fmt.Errorf("project required (GCP project id)")
	}
	if e.Location == "" {
		return fmt.Errorf("location required (e.g. \"us-central1\")")
	}
	if e.Model == "" {
		return fmt.Errorf("model required (e.g. \"gemini-embedding-001\")")
	}
	if e.Dimensions <= 0 {
		return fmt.Errorf("dimensions required (>0)")
	}
	if e.MaxTextBytes <= 0 {
		return fmt.Errorf("max_text_bytes required (>0)")
	}
	if e.Provider != "vertex_ai" {
		return fmt.Errorf("provider must be vertex_ai")
	}
	if e.CredentialsFile != "" || e.CredentialsSource != "" {
		return fmt.Errorf("legacy per-client credential selector is forbidden; use google_credentials")
	}
	if err := vertexai.ValidateEndpointComponents(e.Location, e.Project, e.Model); err != nil {
		return err
	}
	return nil
}

// Validate on ClusterConfig. Every field required and bounded sensibly:
// distances in (0, 2] for cosine, batch size > 0, auto < review.
func (cc *ClusterConfig) Validate() error {
	if cc.AutoMergeDistance <= 0 || cc.AutoMergeDistance > 2 {
		return fmt.Errorf("auto_merge_distance required in (0, 2]")
	}
	if cc.ReviewDistance <= 0 || cc.ReviewDistance > 2 {
		return fmt.Errorf("review_distance required in (0, 2]")
	}
	if cc.AutoMergeDistance >= cc.ReviewDistance {
		return fmt.Errorf("auto_merge_distance (%v) must be < review_distance (%v)",
			cc.AutoMergeDistance, cc.ReviewDistance)
	}
	if cc.EmbeddingBatchSize <= 0 {
		return fmt.Errorf("embedding_batch_size required (>0)")
	}
	return nil
}
