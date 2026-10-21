package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeMCPConfigFixture(t *testing.T, config SpecGraphConfig) string {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "spec-graph.config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCmdMCPBuildsCompleteExperimentalServerAndShutsDown(t *testing.T) {
	config := validIdentityBoundConfig()
	config.ListenAddress = "127.0.0.1:0"
	config.Embedding = nil
	t.Setenv("SPEC_GRAPH_CONFIG", writeMCPConfigFixture(t, config))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- cmdMCP(ctx, nil)
	}()
	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()
	select {
	case err := <-done:
		cancel()
		t.Fatalf("MCP server returned before cancellation: %v", err)
	case <-timer.C:
		cancel()
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("MCP shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("MCP server did not shut down after context cancellation")
	}
}

func TestCmdMCPFailsClosedBeforeServerConstruction(t *testing.T) {
	t.Setenv("SPEC_GRAPH_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	if err := cmdMCP(context.Background(), nil); err == nil {
		t.Fatal("missing configuration was accepted")
	}
}
