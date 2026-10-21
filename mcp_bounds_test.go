package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPTextResultPreservesErrorsAndStructuredResponses(t *testing.T) {
	errResult := textResult(nil, context.DeadlineExceeded)
	if !errResult.IsError || len(errResult.Content) != 1 {
		t.Fatalf("error result=%+v", errResult)
	}
	if text, ok := errResult.Content[0].(*mcp.TextContent); !ok || text.Text != context.DeadlineExceeded.Error() {
		t.Fatalf("error content=%+v", errResult.Content)
	}
	okResult := textResult(map[string]interface{}{"answer": 42}, nil)
	if okResult.IsError || len(okResult.Content) != 1 {
		t.Fatalf("success result=%+v", okResult)
	}
	if text, ok := okResult.Content[0].(*mcp.TextContent); !ok || !strings.Contains(text.Text, "\"answer\": 42") {
		t.Fatalf("success content=%+v", okResult.Content)
	}
	marshalFailure := textResult(map[string]interface{}{"bad": make(chan int)}, nil)
	if !marshalFailure.IsError || len(marshalFailure.Content) != 1 {
		t.Fatalf("marshal failure=%+v", marshalFailure)
	}
	if text, ok := marshalFailure.Content[0].(*mcp.TextContent); !ok || !strings.Contains(text.Text, "unsupported type") {
		t.Fatalf("marshal failure content=%+v", marshalFailure.Content)
	}
}

func TestMCPServerToolBoundariesFailClosedBeforeSubstrateIO(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	config := validIdentityBoundConfig()
	config.ListenAddress = address
	config.Embedding = nil
	t.Setenv("SPEC_GRAPH_CONFIG", writeMCPConfigFixture(t, config))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmdMCP(ctx, nil) }()

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer connectCancel()
	time.Sleep(100 * time.Millisecond)
	client := mcp.NewClient(&mcp.Implementation{Name: "bounds-client", Version: "v0"}, nil)
	session, err := client.Connect(connectCtx, &mcp.StreamableClientTransport{Endpoint: "http://" + address}, nil)
	if err != nil {
		t.Fatalf("connect MCP server: %v", err)
	}
	defer session.Close()

	for _, call := range []struct {
		tool string
		args map[string]interface{}
	}{
		{"spec_graph_use", map[string]interface{}{"snapshot_id": "historical"}},
		{"spec_graph_link", map[string]interface{}{"source_id": "source", "target_id": "target", "edge_label": "unknown"}},
		{"spec_graph_edge_archive", map[string]interface{}{"edge_id": "edge"}},
		{"spec_graph_node_archive", map[string]interface{}{"graph_object_id": "object"}},
		{"spec_graph_get", map[string]interface{}{"graph_object_id": "object"}},
		{"spec_graph_list", map[string]interface{}{}},
		{"spec_graph_search", map[string]interface{}{"query": "query"}},
		{"spec_graph_neighbors", map[string]interface{}{"graph_object_id": "object"}},
		{"spec_graph_closure", map[string]interface{}{"graph_object_id": "object", "closure_profile": "wrong", "max_depth": 1, "result_cap": 1}},
		{"spec_graph_impact", map[string]interface{}{"graph_object_id": "object", "closure_profile": "wrong", "max_depth": 1, "result_cap": 1}},
		{"spec_graph_query", map[string]interface{}{"sql": "DELETE FROM nodes"}},
		{"spec_graph_import", map[string]interface{}{}},
		{"spec_graph_health", map[string]interface{}{}},
		{"spec_graph_list_runs", map[string]interface{}{}},
		{"spec_graph_list_violations", map[string]interface{}{}},
		{"spec_graph_list_snapshots", map[string]interface{}{}},
		{"spec_graph_staging_load", map[string]interface{}{"concepts": []interface{}{}}},
		{"spec_graph_reembed_admitted", map[string]interface{}{}},
		{"spec_graph_staging_extract_ood", map[string]interface{}{"source_file": "relative.json"}},
		{"spec_graph_staging_list", map[string]interface{}{"ingestion_run_id": "run"}},
		{"spec_graph_staging_get", map[string]interface{}{"ingestion_run_id": "run", "staging_id": "id"}},
		{"spec_graph_staging_lint", map[string]interface{}{"ingestion_run_id": "run"}},
		{"spec_graph_staging_cluster", map[string]interface{}{"ingestion_run_id": "run"}},
		{"spec_graph_staging_dedup_verify", map[string]interface{}{"ingestion_run_id": "run"}},
		{"spec_graph_staging_promote", map[string]interface{}{"ingestion_run_id": "run"}},
	} {
		result, err := session.CallTool(connectCtx, &mcp.CallToolParams{Name: call.tool, Arguments: call.args})
		if err != nil {
			t.Fatalf("%s transport error: %v", call.tool, err)
		}
		if len(result.Content) == 0 {
			t.Fatalf("%s result=%+v, want protocol content", call.tool, result)
		}
		if call.tool == "spec_graph_health" {
			if result.IsError || result.StructuredContent == nil {
				t.Fatalf("health result=%+v, want structured degraded readiness", result)
			}
			continue
		}
		if !result.IsError {
			t.Fatalf("%s result=%+v, want typed refusal", call.tool, result)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("MCP shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("MCP server did not stop")
	}
}
