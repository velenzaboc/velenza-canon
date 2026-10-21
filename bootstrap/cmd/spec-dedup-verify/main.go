package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

var exit = os.Exit
var verifyRuntime = verifyWithVertex
var newVertexAuth = func(ctx context.Context, factory vertexai.TokenSourceFactory) (*vertexai.Auth, error) {
	return vertexai.NewAuth(ctx, factory)
}
var newFlashClient = func(auth *vertexai.Auth, config vertexai.FlashConfig) (*vertexai.FlashClient, error) {
	return vertexai.NewFlashClient(auth, config)
}

// spec-dedup-verify runs Stage 2b of the pipeline. It:
//  1. Loads spec-graph.config.json (REQUIRED, no defaults)
//  2. Reads ClusterBuckets produced by spec-cluster
//  3. For every Flash call: re-reads the prompt template file from
//     disk (no in-memory cache per directive), renders with the
//     pair/cluster context, calls Vertex AI Gemini Flash, parses the
//     response, records a ledger entry
//  4. Writes DedupDecisions JSON and FlashLedger JSON
//
// Usage:
//
//	spec-dedup-verify --config <p> --buckets <p> \
//	                  --output-decisions <p> --output-ledger <p>
//
// Exit codes:
//
//	0  success
//	1  Flash or ledger I/O failure
//	2  invocation error (bad flag, missing file, parse failure, validate)
func main() {
	code, err := run(os.Args[1:], os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "spec-dedup-verify:", err)
		exit(code)
	}
}

func run(args []string, stderr io.Writer) (int, error) {
	flags := flag.NewFlagSet("spec-dedup-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "path to spec-graph.config.json (required)")
	bucketsPath := flags.String("buckets", "", "path to ClusterBuckets JSON from spec-cluster (required)")
	decisionsPath := flags.String("output-decisions", "", "path to write DedupDecisions JSON (required)")
	ledgerPath := flags.String("output-ledger", "", "path to write FlashLedger JSON (required)")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}

	if *configPath == "" || *bucketsPath == "" || *decisionsPath == "" || *ledgerPath == "" {
		return 2, fmt.Errorf("--config, --buckets, --output-decisions, --output-ledger all required")
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return 2, err
	}

	bucketsData, err := os.ReadFile(*bucketsPath)
	if err != nil {
		return 2, fmt.Errorf("read buckets %q: %w", *bucketsPath, err)
	}
	var buckets ClusterBuckets
	if err := json.Unmarshal(bucketsData, &buckets); err != nil {
		return 2, fmt.Errorf("parse buckets %q: %w", *bucketsPath, err)
	}
	decisions, ledger, verifyErr := verifyRuntime(context.Background(), cfg, &buckets)
	if verifyErr != nil {
		fmt.Fprintf(stderr, "spec-dedup-verify: verify: %v\n", verifyErr)
	}
	if err := writeJSON(*decisionsPath, decisions); err != nil {
		return 1, fmt.Errorf("write decisions: %w", err)
	}
	if err := writeJSON(*ledgerPath, ledger); err != nil {
		return 1, fmt.Errorf("write ledger: %w", err)
	}
	fmt.Fprintf(stderr, "spec-dedup-verify: auto_merge=%d verified=%d escalations=%d no_match=%d (ledger entries=%d)\n", len(decisions.AutoMerge), len(decisions.Verified), len(decisions.Escalations), len(decisions.NoMatch), len(ledger.Entries))
	if verifyErr != nil {
		return 1, verifyErr
	}
	return 0, nil
}

func verifyWithVertex(ctx context.Context, cfg *Config, buckets *ClusterBuckets) (*DedupDecisions, *FlashLedger, error) {
	auth, err := newVertexAuth(ctx, cfg.GoogleCredentials.RequestTokenSourceFactory(gcpauth.CloudPlatformScope))
	if err != nil {
		return nil, nil, fmt.Errorf("vertex auth: %w", err)
	}
	gen, err := newFlashClient(auth, vertexai.FlashConfig{
		Project:         cfg.Pipeline.Flash.Project,
		Location:        cfg.Pipeline.Flash.Location,
		Model:           cfg.Pipeline.Flash.Model,
		MaxOutputTokens: cfg.Pipeline.Flash.MaxOutputTokens,
		Temperature:     cfg.Pipeline.Flash.Temperature,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("vertex endpoint: %w", err)
	}

	return VerifyAll(ctx, buckets, gen, cfg.Pipeline.Flash)
}

func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %T: %w", v, err)
	}
	return os.WriteFile(path, data, 0o644)
}
