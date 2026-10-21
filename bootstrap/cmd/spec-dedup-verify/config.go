package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

// Config is the minimal subset of spec-graph.config.json that
// spec-dedup-verify consumes. Per directive: every value is REQUIRED;
// zero defaults; fail-closed.
type Config struct {
	Mode              string           `json:"mode"`
	GoogleCredentials gcpauth.Selector `json:"google_credentials"`
	Pipeline          *PipelineConfig  `json:"pipeline"`
}

type PipelineConfig struct {
	Flash *FlashConfig `json:"flash"`
}

// FlashConfig is the Vertex AI Gemini Flash request setup. Functional fields
// are required; credentials belong exclusively to the process-level selector.
type FlashConfig struct {
	// Provider is the model host name. Currently "vertex_ai" is the
	// only supported value; configured explicitly so the binary doesn't
	// hardcode the literal.
	Provider string `json:"provider"`

	// Project is the GCP project id hosting the Vertex AI endpoint.
	Project string `json:"project"`

	// Location is the Vertex AI region (e.g. "us-central1").
	Location string `json:"location"`

	// Model is the Flash model identifier (e.g. "gemini-2.0-flash").
	Model string `json:"model"`

	// Legacy parser sentinels. A stale shared config must fail explicitly
	// instead of being accepted and ignored.
	CredentialsFile   string `json:"credentials_file,omitempty"`
	CredentialsSource string `json:"credentials_source,omitempty"`

	// MaxOutputTokens caps the response length. Single-shot
	// classifications are short; cap protects against runaway responses.
	MaxOutputTokens int `json:"max_output_tokens"`

	// Temperature: 0 for deterministic classification.
	Temperature float64 `json:"temperature"`

	// Prompts lists the per-template file paths. Each prompt template
	// is loaded from disk on EVERY invocation (no in-memory cache) so
	// editing the template file changes future behavior without a
	// binary restart.
	Prompts *FlashPromptsConfig `json:"prompts"`
}

// FlashPromptsConfig declares the file paths to the prompt templates.
// Templates are text files containing Go text/template syntax; the
// caller renders them per call with the relevant context.
type FlashPromptsConfig struct {
	SameConceptQueryPath       string `json:"same_concept_query_path"`
	CanonicalNameSelectionPath string `json:"canonical_name_selection_path"`
}

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

func (c *Config) Validate() error {
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
	if err := c.GoogleCredentials.Validate("google_credentials", c.Mode == "production"); err != nil {
		return err
	}
	if c.Pipeline == nil {
		return fmt.Errorf("pipeline section required")
	}
	if c.Pipeline.Flash == nil {
		return fmt.Errorf("pipeline.flash section required")
	}
	return c.Pipeline.Flash.Validate()
}

func (f *FlashConfig) Validate() error {
	if f.Provider == "" {
		return fmt.Errorf("flash.provider required")
	}
	if f.Project == "" {
		return fmt.Errorf("flash.project required")
	}
	if f.Location == "" {
		return fmt.Errorf("flash.location required")
	}
	if f.Model == "" {
		return fmt.Errorf("flash.model required")
	}
	if f.Provider != "vertex_ai" {
		return fmt.Errorf("flash.provider must be vertex_ai")
	}
	if f.CredentialsFile != "" || f.CredentialsSource != "" {
		return fmt.Errorf("flash legacy per-client credential selector is forbidden; use google_credentials")
	}
	if err := vertexai.ValidateEndpointComponents(f.Location, f.Project, f.Model); err != nil {
		return fmt.Errorf("flash endpoint: %w", err)
	}
	if f.MaxOutputTokens <= 0 {
		return fmt.Errorf("flash.max_output_tokens required (>0)")
	}
	if f.Temperature < 0 || f.Temperature > 2 {
		return fmt.Errorf("flash.temperature required in [0, 2]")
	}
	if f.Prompts == nil {
		return fmt.Errorf("flash.prompts section required")
	}
	if f.Prompts.SameConceptQueryPath == "" {
		return fmt.Errorf("flash.prompts.same_concept_query_path required")
	}
	if f.Prompts.CanonicalNameSelectionPath == "" {
		return fmt.Errorf("flash.prompts.canonical_name_selection_path required")
	}
	return nil
}
