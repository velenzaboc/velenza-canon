package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// CanonArborDescriptor describes Layer 2 (velenza-canon / spec-graph) in the Velenza Arbor Stack.
type CanonArborDescriptor struct {
	Layer            int      `json:"layer"`
	CanonicalName    string   `json:"canonical_name"`
	CompatAlias      string   `json:"compat_alias"`
	ArborSubcommands []string `json:"arbor_subcommands"`
	ConfigEnvVars    []string `json:"config_env_vars"`
	Capabilities     []string `json:"capabilities"`
}

// BuildCanonArborDescriptor returns the canonical Velenza Arbor Layer 2 metadata descriptor.
func BuildCanonArborDescriptor() CanonArborDescriptor {
	return CanonArborDescriptor{
		Layer:            2,
		CanonicalName:    "velenza-canon",
		CompatAlias:      "spec-graph",
		ArborSubcommands: []string{"canon", "spec"},
		ConfigEnvVars: []string{
			"VELENZA_CANON_CONFIG",
			"SPEC_GRAPH_CONFIG",
			"ARBOR_GCP_PROJECT",
			"ARBOR_SPANNER_INSTANCE",
		},
		Capabilities: []string{
			"mcp",
			"init",
			"reset",
			"trace-code",
			"arbor-info",
		},
	}
}

func runArborInfoCLI(args []string, w io.Writer) error {
	_ = args
	desc := BuildCanonArborDescriptor()
	enc, err := json.MarshalIndent(desc, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(enc))
	return err
}
