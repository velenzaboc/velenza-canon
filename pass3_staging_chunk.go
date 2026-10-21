package main

import (
	"context"

	"cloud.google.com/go/spanner"
)

const maxStagingMutationsPerTx = 2000

func stagingMutationsPerTxLimit() int {
	return maxStagingMutationsPerTx
}

func isSupportedSpecEmbeddingModel(model string) bool {
	switch model {
	case "gemini-embedding-2-preview", "gemini-embedding-2", "gemini-embedding-001":
		return true
	default:
		return false
	}
}

func chunkStagingMutations[T any](muts []T, maxPerChunk int) [][]T {
	if len(muts) == 0 {
		return nil
	}
	if maxPerChunk <= 0 {
		maxPerChunk = maxStagingMutationsPerTx
	}
	chunks := make([][]T, 0, (len(muts)+maxPerChunk-1)/maxPerChunk)
	for i := 0; i < len(muts); i += maxPerChunk {
		end := i + maxPerChunk
		if end > len(muts) {
			end = len(muts)
		}
		chunks = append(chunks, muts[i:end])
	}
	return chunks
}

func applyStagingMutationsChunked(ctx context.Context, client *spanner.Client, muts []*spanner.Mutation) error {
	for _, chunk := range chunkStagingMutations(muts, maxStagingMutationsPerTx) {
		if _, err := client.Apply(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}
