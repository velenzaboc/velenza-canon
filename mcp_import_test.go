package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestMCPImportRejectsWireDuplicateBeforeSDKNormalization exercises the real
// SDK call path. The SDK's schema/default pass decodes Arguments through a Go
// map and would collapse duplicate members before the typed input decoder;
// the handler must therefore inspect CallToolRequest.Params.Arguments itself.
func TestMCPImportRejectsWireDuplicateBeforeSDKNormalization(t *testing.T) {
	env, adapter := newImportKindEnv(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "spec-graph-test", Version: "v0"}, nil)
	addImportTool(server, env)
	client := mcp.NewClient(&mcp.Implementation{Name: "spec-graph-test-client", Version: "v0"}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	raw := json.RawMessage(`{
		"submissions":[{
			"node_kind":"axiom",
			"stable_id":"wire_duplicate",
			"source_coordinate":{
				"source_authority_id":"767c2399-87f9-4859-ac64-afb575bdb263",
				"source_authority_id":"46954a80-78eb-4351-8be7-6e7d7eba8f5b",
				"source_artifact_class":"axiom",
				"source_ref_kind":"name",
				"source_stable_reference":"wire_duplicate",
				"version_coordinate":"unversioned",
				"section_path":"$"
			}
		}]
	}`)
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{
		Name:      "spec_graph_import",
		Arguments: raw,
	})
	if err != nil {
		t.Fatalf("CallTool transport error: %v", err)
	}
	if !result.IsError {
		t.Fatalf("MCP import accepted duplicate identity member: %+v", result)
	}
	var message string
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			message += text.Text
		}
	}
	if !strings.Contains(message, `duplicate field "source_authority_id"`) {
		t.Fatalf("MCP error=%q, want duplicate-field refusal from untouched wire arguments", message)
	}
	if adapter.schemaChecks != 0 || len(adapter.openedRuns) != 0 || len(adapter.batches) != 0 {
		t.Fatalf("wire duplicate reached substrate: schema_checks=%d opened=%d batches=%d", adapter.schemaChecks, len(adapter.openedRuns), len(adapter.batches))
	}
}

func TestMCPStagingLoadRejectsRecursiveWireDuplicateBeforeSDKNormalization(t *testing.T) {
	env, adapter := newImportKindEnv(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "spec-graph-test", Version: "v0"}, nil)
	addStagingLoadTool(server, env)
	client := mcp.NewClient(&mcp.Implementation{Name: "spec-graph-test-client", Version: "v0"}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	raw := json.RawMessage(`{
		"concepts":[{
			"canonical_name":"wire_duplicate",
			"node_kind":"axiom",
			"source_coordinate":{
				"source_authority_id":"767c2399-87f9-4859-ac64-afb575bdb263",
				"source_authority_id":"46954a80-78eb-4351-8be7-6e7d7eba8f5b",
				"source_artifact_class":"axiom",
				"source_ref_kind":"name",
				"source_stable_reference":"wire_duplicate",
				"version_coordinate":"unversioned",
				"section_path":"$"
			}
		}]
	}`)
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "spec_graph_staging_load", Arguments: raw})
	if err != nil {
		t.Fatalf("CallTool transport error: %v", err)
	}
	if !result.IsError {
		t.Fatalf("MCP staging_load accepted duplicate identity member: %+v", result)
	}
	var message string
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			message += text.Text
		}
	}
	if !strings.Contains(message, `duplicate field "source_authority_id"`) {
		t.Fatalf("MCP error=%q, want recursive duplicate-field refusal", message)
	}
	if adapter.schemaChecks != 0 || len(adapter.openedRuns) != 0 || len(adapter.batches) != 0 {
		t.Fatalf("wire duplicate reached substrate: schema_checks=%d opened=%d batches=%d", adapter.schemaChecks, len(adapter.openedRuns), len(adapter.batches))
	}
}

func TestMCPImportAcceptsCallerIdentityShapeButFailsClosedBeforeRetrieval(t *testing.T) {
	env, adapter := newSourceCoordinateEnv(t)
	server := mcp.NewServer(&mcp.Implementation{Name: "spec-graph-test", Version: "v0"}, nil)
	addImportTool(server, env)
	client := mcp.NewClient(&mcp.Implementation{Name: "spec-graph-test-client", Version: "v0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	raw := json.RawMessage(`{
		"submissions":[
			{"node_kind":"external_reference_doc","stable_id":"quickbooks_online_corpus","source_coordinate":{"source_authority_id":"767c2399-87f9-4859-ac64-afb575bdb263","source_artifact_class":"official_vendor_documentation","source_ref_kind":"coordinate","source_stable_reference":"https://developer.intuit.com/app/developer/qbo/docs","section_path":"$","license_evidence_when_available":"https://developer.intuit.com/app/developer/qbo/docs/legal-agreements"}},
			{"node_kind":"reference_page","stable_id":"quickbooks_online_invoice_reference","source_coordinate":{"source_authority_id":"767c2399-87f9-4859-ac64-afb575bdb263","source_artifact_class":"official_vendor_documentation","source_ref_kind":"coordinate","source_stable_reference":"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice","section_path":"$","license_evidence_when_available":"https://developer.intuit.com/app/developer/qbo/docs/legal-agreements"}}
		],
		"relationships":[{"edge_label":"official_source_for","source_canonical_name":"quickbooks_online_corpus","target_canonical_name":"quickbooks_online_invoice_reference"}]
	}`)
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "spec_graph_import", Arguments: raw})
	if err != nil {
		t.Fatalf("CallTool transport error: %v", err)
	}
	if !result.IsError {
		t.Fatalf("MCP import executed automated external retrieval without admitted permission/content-class proof: %+v", result)
	}
	var message string
	for _, content := range result.Content {
		if value, ok := content.(*mcp.TextContent); ok {
			message += value.Text
		}
	}
	if !strings.Contains(message, "ErrOODGraphExternalNonGranularProofUnavailable") {
		t.Fatalf("MCP fail-closed error=%q, want typed non-granular authenticity refusal", message)
	}
	if adapter.schemaChecks != 0 || len(adapter.openedRuns) != 0 || len(adapter.batches) != 0 {
		t.Fatalf("blocked MCP retrieval reached substrate: schema=%d runs=%d batches=%d", adapter.schemaChecks, len(adapter.openedRuns), len(adapter.batches))
	}
}
