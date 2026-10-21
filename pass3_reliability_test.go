package main

import (
	"os"
	"strings"
	"testing"

	"cloud.google.com/go/spanner"
)

func TestPass3SpecGraphEmbeddingModelSupportAndConfigs(t *testing.T) {
	if !isSupportedSpecEmbeddingModel("gemini-embedding-2-preview") {
		t.Fatalf("expected gemini-embedding-2-preview to be supported by isSupportedSpecEmbeddingModel")
	}
	if !isSupportedSpecEmbeddingModel("gemini-embedding-2") {
		t.Fatalf("expected gemini-embedding-2 to be supported by isSupportedSpecEmbeddingModel")
	}
	if !isSupportedSpecEmbeddingModel("gemini-embedding-001") {
		t.Fatalf("expected legacy gemini-embedding-001 to remain supported during transition")
	}
	if isSupportedSpecEmbeddingModel("unknown-embedding-model") {
		t.Fatalf("expected unknown-embedding-model to be rejected")
	}

	configFiles := []string{
		"spec-graph.config.production.example.json",
		"velenza-canon.config.example.json",
		"spec-graph.config.bootstrap.example.json",
	}
	for _, cfgPath := range configFiles {
		raw, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatalf("read %s: %v", cfgPath, err)
		}
		if !strings.Contains(string(raw), `"gemini-embedding-2-preview"`) {
			t.Fatalf("expected %s to configure model gemini-embedding-2-preview", cfgPath)
		}
	}
}

func TestPass3ChunkStagingMutationsBoundsPerTransaction(t *testing.T) {
	limit := stagingMutationsPerTxLimit()
	if limit <= 0 || limit > 2000 {
		t.Fatalf("expected stagingMutationsPerTxLimit() in (0, 2000], got %d", limit)
	}
	total := 4500
	muts := make([]*spanner.Mutation, total)
	for i := 0; i < total; i++ {
		muts[i] = spanner.Insert("staging_concepts", []string{"staging_id"}, []interface{}{"id"})
	}
	chunks := chunkStagingMutations(muts, limit)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks for %d mutations at limit %d, got %d", total, limit, len(chunks))
	}
	seen := 0
	for i, c := range chunks {
		if len(c) == 0 || len(c) > limit {
			t.Fatalf("chunk %d has invalid length %d (limit %d)", i, len(c), limit)
		}
		seen += len(c)
	}
	if seen != total {
		t.Fatalf("expected %d total mutations across chunks, got %d", total, seen)
	}
}
