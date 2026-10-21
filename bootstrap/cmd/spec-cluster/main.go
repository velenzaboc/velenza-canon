package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

var exit = os.Exit
var newVertexAuth = func(ctx context.Context, factory vertexai.TokenSourceFactory) (*vertexai.Auth, error) {
	return vertexai.NewAuth(ctx, factory)
}
var newEmbedClient = func(auth *vertexai.Auth, config vertexai.EmbedConfig) (*vertexai.EmbedClient, error) {
	return vertexai.NewEmbedClient(auth, config)
}
var embedText = func(ctx context.Context, client *vertexai.EmbedClient, text string) ([]float32, error) {
	return client.Embed(ctx, text, vertexai.TaskTypeRetrievalDocument)
}

// spec-cluster runs Stage 2a of the pipeline. It:
//  1. Loads spec-graph.config.json (REQUIRED, no defaults)
//  2. Reads ConceptRecords produced by spec-extract
//  3. Embeds each record via Vertex AI (cached to disk; re-runs reuse)
//  4. Clusters by cosine distance against the two configured thresholds
//  5. Writes ClusterBuckets JSON for downstream Stage 2b (Flash verify)
//
// Per Vision Principle 7 (binary_is_never_sot) and the explicit user
// directive: ZERO hardcoded values. Every threshold, model, project, and
// dimension lives in spec-graph.config.json. If any required field is
// missing or zero, spec-cluster refuses.
//
// Usage:
//
//	spec-cluster --config <p> --records <p> --output <p> --cache <p> \
//	             --concept-domain <name>
//
// Exit codes:
//
//	0  success (buckets written)
//	1  embedding or clustering failure
//	2  invocation error (bad flag, missing file, parse failure, validate)
func main() {
	configPath := flag.String("config", "", "path to spec-graph.config.json (required)")
	recordsPath := flag.String("records", "", "path to ConceptRecords JSON file produced by spec-extract (required)")
	outputPath := flag.String("output", "", "path to write ClusterBuckets JSON (required)")
	cachePath := flag.String("cache", "", "path to embedding cache JSON (required; created if missing)")
	conceptDomain := flag.String("concept-domain", "", "concept_domain stamped on outputs (required)")
	flag.Parse()

	if *configPath == "" || *recordsPath == "" || *outputPath == "" || *cachePath == "" || *conceptDomain == "" {
		fmt.Fprintln(os.Stderr, "spec-cluster: --config, --records, --output, --cache, --concept-domain are all required")
		flag.Usage()
		exit(2)
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: %v\n", err)
		exit(2)
	}

	records, err := loadRecords(*recordsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: %v\n", err)
		exit(2)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "spec-cluster: zero records in input — nothing to cluster")
		// Still emit a well-formed (empty) bucket file for downstream consumers.
	}

	cache, err := loadCache(*cachePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: %v\n", err)
		exit(2)
	}

	ctx := context.Background()
	auth, err := newVertexAuth(ctx, cfg.GoogleCredentials.RequestTokenSourceFactory(gcpauth.CloudPlatformScope))
	if err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: vertex auth: %v\n", err)
		exit(2)
	}
	embedder, err := newEmbedClient(auth, vertexai.EmbedConfig{
		Project:      cfg.Embedding.Project,
		Location:     cfg.Embedding.Location,
		Model:        cfg.Embedding.Model,
		Dimensions:   cfg.Embedding.Dimensions,
		MaxTextBytes: cfg.Embedding.MaxTextBytes,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: vertex endpoint: %v\n", err)
		exit(2)
	}

	embedded, err := embedAllWithCache(ctx, embedder, records, cache)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: embed: %v\n", err)
		exit(1)
	}

	if err := writeCache(*cachePath, &EmbeddingCache{
		ConceptDomain: *conceptDomain,
		Embedded:      embedded,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: cache write: %v\n", err)
		exit(1)
	}

	buckets, err := BucketRecords(embedded, *cfg.Pipeline.Cluster, *conceptDomain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: cluster: %v\n", err)
		exit(1)
	}

	out, err := json.MarshalIndent(buckets, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: marshal: %v\n", err)
		exit(1)
	}
	if err := os.WriteFile(*outputPath, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "spec-cluster: write output: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr,
		"spec-cluster: %d records → auto_merge=%d verify_required=%d no_match=%d\n",
		len(embedded), len(buckets.AutoMerge), len(buckets.VerifyRequired), len(buckets.NoMatch))
}

// loadRecords reads the ConceptRecords JSON file produced by spec-extract.
func loadRecords(path string) ([]ConceptRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read records %q: %w", path, err)
	}
	var records []ConceptRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parse records %q: %w", path, err)
	}
	return records, nil
}

// loadCache reads the embedding cache; missing file is a clean empty cache.
func loadCache(path string) (*EmbeddingCache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &EmbeddingCache{}, nil
		}
		return nil, fmt.Errorf("read cache %q: %w", path, err)
	}
	var c EmbeddingCache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse cache %q: %w", path, err)
	}
	return &c, nil
}

// writeCache persists the embedding cache to disk.
func writeCache(path string, c *EmbeddingCache) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cache: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// cacheKey returns the deterministic identifier under which an embedding
// is stored. The triple uniquely identifies the leaf within a source spec.
func cacheKey(r ConceptRecord) string {
	return r.SourceFile + "#" + r.SourcePath + "#" + r.LeafName
}

// embedAllWithCache embeds every record whose key isn't in the cache. The
// returned slice is index-parallel to records.
func embedAllWithCache(ctx context.Context, embedder *vertexai.EmbedClient, records []ConceptRecord, cache *EmbeddingCache) ([]EmbeddedRecord, error) {
	have := map[string][]float32{}
	for _, e := range cache.Embedded {
		have[cacheKey(e.Record)] = e.Embedding
	}
	out := make([]EmbeddedRecord, 0, len(records))
	for _, r := range records {
		k := cacheKey(r)
		if vec, ok := have[k]; ok {
			out = append(out, EmbeddedRecord{Record: r, Embedding: vec})
			continue
		}
		vec, err := embedText(ctx, embedder, r.RawValue)
		if err != nil {
			return nil, fmt.Errorf("embed %q: %w", k, err)
		}
		out = append(out, EmbeddedRecord{Record: r, Embedding: vec})
	}
	return out, nil
}
