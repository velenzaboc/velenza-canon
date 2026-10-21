package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type handlerBoundsEmbedder struct{}

func (handlerBoundsEmbedder) Embed(_ context.Context, text, task string) ([]float32, error) {
	if text == "" || task == "" {
		return nil, nil
	}
	return make([]float32, externalReferenceEmbeddingDimensions), nil
}

func TestHandlerBoundsExtractSymbolsAndReferenceScanning(t *testing.T) {
	ctx := context.Background()
	source := ArtifactSourceCoordinate{
		SourceAuthorityID:     bootstrapSourceAuthority,
		SourceRefKind:         "name",
		SourceStableReference: "test_source",
		VersionCoordinate:     "unversioned",
	}
	var symbols []GraphSymbol
	tree := map[string]interface{}{
		"text":   "hello",
		"number": float64(7),
		"truth":  true,
		"items":  []interface{}{"first", map[string]interface{}{"nested": false}},
	}
	if err := extractSymbolsRecursive(ctx, tree, "$", "root", "object", "section", source, "org", "snapshot", "run", "internal", nil, uuid.Nil, &symbols); err != nil {
		t.Fatalf("extract symbols: %v", err)
	}
	if len(symbols) != 7 {
		t.Fatalf("symbols=%d, want 7: %+v", len(symbols), symbols)
	}
	if symbols[0].SymbolKind != "nested_object" || symbols[1].SymbolName != "items_0" || symbols[1].SearchText == "" {
		t.Fatalf("unexpected deterministic symbol order: %+v", symbols)
	}
	for _, symbol := range symbols {
		if symbol.OrganizationID != "org" || symbol.GraphSnapshotID != "snapshot" || symbol.MaterializationRunID != "run" || symbol.GraphAddress == "" {
			t.Fatalf("incomplete symbol: %+v", symbol)
		}
		if parsed, err := ParseGraphAddress(symbol.GraphAddress); err != nil || parsed.String() != symbol.GraphAddress {
			t.Fatalf("symbol address=%q parsed=%+v err=%v", symbol.GraphAddress, parsed, err)
		}
	}
	if err := emitSymbol(ctx, "", "scalar_string", "", "$.bad", "object", "section", source, "org", "snapshot", "run", "internal", nil, uuid.Nil, &symbols); err == nil || !strings.Contains(err.Error(), "symbol_name") {
		t.Fatalf("empty symbol name error=%v", err)
	}
	refs := scanRefs(
		nil,
		json.RawMessage(`{"nested":["$ref:raw", {"$ref":"key"}]}`),
		[]byte(`{"bytes":"$ref:bytes"}`),
		map[string]interface{}{"plain": "$ref:map", "$ref": 3},
	)
	for _, want := range []string{"raw", "key", "bytes", "map"} {
		found := false
		for _, ref := range refs {
			found = found || ref == want
		}
		if !found {
			t.Fatalf("refs=%v missing %q", refs, want)
		}
	}
}

func TestHandlerBoundsTypedQueryAndAdapterRouting(t *testing.T) {
	ctx := context.Background()
	a := &oodQueryAdapter{handlerAdapter: newHandlerAdapter()}
	a.query = QueryResult{Columns: []string{"id"}, Rows: []map[string]interface{}{{"id": "one"}}}
	env := oodHandlerEnv(a)
	if _, err := handleQueryOnSubstrate(ctx, env, queryInput{}, "fake"); err == nil || !strings.Contains(err.Error(), "sql required") {
		t.Fatalf("empty SQL error=%v", err)
	}
	if _, err := handleQueryOnSubstrate(ctx, env, queryInput{SQL: "DELETE FROM nodes"}, "fake"); err == nil || !strings.Contains(err.Error(), "READ-ONLY") {
		t.Fatalf("write SQL error=%v", err)
	}
	if _, err := handleQueryOnSubstrate(ctx, nil, queryInput{SQL: "SELECT 1"}, "fake"); err == nil || !strings.Contains(err.Error(), "no environment") {
		t.Fatalf("nil environment error=%v", err)
	}
	if _, err := handleQueryOnSubstrate(ctx, env, queryInput{SQL: "SELECT 1"}, ""); err == nil || !strings.Contains(err.Error(), "substrate id required") {
		t.Fatalf("empty substrate error=%v", err)
	}
	if got, err := handleQueryOnSubstrate(ctx, env, queryInput{SQL: "SELECT @id", Params: map[string]interface{}{"id": "one"}}, "fake"); err != nil || len(got.Rows) != 1 || a.sql != "SELECT @id" || a.params["id"] != "one" {
		t.Fatalf("typed query=%+v sql=%q params=%v err=%v", got, a.sql, a.params, err)
	}
	if got, err := resolveAdapterForSubmission(ctx, env, ArtifactSubmission{NodeKind: "section"}); err != nil || got.ID() != "fake" {
		t.Fatalf("node adapter=%v err=%v", got, err)
	}
	if got, err := resolveAdapterForSubmission(ctx, env, ArtifactSubmission{EdgeLabel: "depends_on"}); err != nil || got.ID() != "fake" {
		t.Fatalf("edge adapter=%v err=%v", got, err)
	}
	if _, err := resolveAdapterForSubmission(ctx, env, ArtifactSubmission{}); err == nil || !strings.Contains(err.Error(), "either node_kind or edge_label") {
		t.Fatalf("unroutable submission error=%v", err)
	}
	if err := validateReadOnlyQueryInput(nil, queryInput{SQL: "SELECT 1"}); err == nil || !strings.Contains(err.Error(), "no environment") {
		t.Fatalf("nil query environment error=%v", err)
	}
	disabled := *env
	disabled.Config.ExperimentalQueryEnabled = false
	if err := validateReadOnlyQueryInput(&disabled, queryInput{SQL: "SELECT 1"}); err == nil {
		t.Fatal("disabled query surface accepted SQL")
	}
}

func TestHandlerBoundsArchiveUsesGenesisFallback(t *testing.T) {
	ctx := context.Background()
	a := newHandlerAdapter()
	env := handlerEnv(a)
	env.Config.ExperimentalAdmitter = ""
	env.Config.GenesisAdmitter = "GENESIS"
	if _, err := handleArchiveEdge(ctx, env, archiveEdgeInput{EdgeID: "edge"}); err != nil {
		t.Fatalf("archive edge fallback: %v", err)
	}
	if _, err := handleArchiveNode(ctx, env, archiveNodeInput{GraphObjectID: "object"}); err != nil {
		t.Fatalf("archive node fallback: %v", err)
	}
	withoutAdmitter := *env
	withoutAdmitter.Config.GenesisAdmitter = ""
	if _, err := handleArchiveEdge(ctx, &withoutAdmitter, archiveEdgeInput{EdgeID: "edge"}); err == nil || !strings.Contains(err.Error(), "admitter") {
		t.Fatalf("missing edge admitter error=%v", err)
	}
	if _, err := handleArchiveNode(ctx, &withoutAdmitter, archiveNodeInput{GraphObjectID: "object"}); err == nil || !strings.Contains(err.Error(), "admitter") {
		t.Fatalf("missing node admitter error=%v", err)
	}
}

func TestHandlerBoundsDecodeCountReadAndHealthBoundaries(t *testing.T) {
	if got := estimatedExtractedSymbolCount(nil); got != 0 {
		t.Fatalf("nil count=%d", got)
	}
	if got := estimatedExtractedSymbolCount(map[string]interface{}{"string": "x", "array": []interface{}{float64(1), true}}); got != 4 {
		t.Fatalf("nested count=%d, want 4", got)
	}
	if got := estimatedExtractedSymbolCount(int(1)); got != maxVectorRowsPerExternalBootstrapMaterialization+1 {
		t.Fatalf("unknown count=%d", got)
	}
	if one, err := parseSubmissionsJSON([]byte(`{"stable_id":"one","node_kind":"section"}`), "one.json"); err != nil || len(one) != 1 || one[0].StableID != "one" {
		t.Fatalf("object parse=%+v err=%v", one, err)
	}
	if many, err := parseSubmissionsJSON([]byte(`[{"stable_id":"one"},{"stable_id":"two"}]`), "many.json"); err != nil || len(many) != 2 || many[1].StableID != "two" {
		t.Fatalf("array parse=%+v err=%v", many, err)
	}
	if _, err := parseSubmissionsJSON([]byte(`{"contract":{"dup":1,"dup":2}}`), "duplicate.json"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate parse error=%v", err)
	}
	ctx := context.Background()
	a := newHandlerAdapter()
	a.nodesByVersion["node|"] = handlerNode("node", 1, "active")
	env := handlerEnv(a)
	if got, err := readNodeAcrossSubstrates(ctx, env, "node", "", "snapshot"); err != nil || got.NodeID != "node" {
		t.Fatalf("cross-substrate node=%+v err=%v", got, err)
	}
	if _, err := readNodeAcrossSubstrates(ctx, env, "", "", ""); err == nil || !strings.Contains(err.Error(), "node_id required") {
		t.Fatalf("empty node id error=%v", err)
	}
	empty := *env
	empty.Substrates = handlerRouter{}
	if _, err := readNodeAcrossSubstrates(ctx, &empty, "missing", "", ""); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing node error=%v", err)
	}
	if health, err := handleHealth(ctx, env, healthInput{}); err != nil || !health.OverallReady || len(health.Substrates) != 1 || !health.Substrates[0].SchemaApplied {
		t.Fatalf("healthy result=%+v err=%v", health, err)
	}
}

func TestHandlerBoundsExternalEmbeddingIsBoundedAndFailClosed(t *testing.T) {
	ctx := context.Background()
	objects := []GraphObject{{SearchText: "one"}, {SearchText: "two"}}
	policies := []ExternalSourceDescriptor{{ID: "external-one"}, {ID: "external-two"}}
	if err := embedExternalObjectsBounded(ctx, nil, objects, []string{"one"}, policies); err == nil || !strings.Contains(err.Error(), "cardinality") {
		t.Fatalf("cardinality error=%v", err)
	}
	if err := embedExternalObjectsBounded(ctx, nil, objects[:1], []string{"ordinary"}, []ExternalSourceDescriptor{{}}); err != nil {
		t.Fatalf("ordinary object requested embedding: %v", err)
	}
	if err := embedExternalObjectsBounded(ctx, nil, objects[:1], []string{"one"}, policies[:1]); err == nil || !strings.Contains(err.Error(), "configured embedding") {
		t.Fatalf("missing embedder error=%v", err)
	}
	env := &Env{Embed: handlerBoundsEmbedder{}}
	if err := embedExternalObjectsBounded(ctx, env, objects, []string{"one", "two"}, policies); err != nil {
		t.Fatalf("external embeddings: %v", err)
	}
	for i, object := range objects {
		if len(object.Embedding) != externalReferenceEmbeddingDimensions {
			t.Fatalf("object[%d] embedding dimensions=%d", i, len(object.Embedding))
		}
	}
	wrongDimensions := &Env{Embed: handlerEmbedder{}}
	if err := embedExternalObjectsBounded(ctx, wrongDimensions, objects[:1], []string{"one"}, policies[:1]); err == nil || !strings.Contains(err.Error(), "dimensions") {
		t.Fatalf("wrong dimensions error=%v", err)
	}
}

func TestHandlerBoundsReadSurfaceRefusalsAndConfiguredRoutes(t *testing.T) {
	ctx := context.Background()
	a := newHandlerAdapter()
	a.nodesByVersion["node|"] = handlerNode("node", 1, "active")
	a.listNodes = []Node{handlerNode("listed", 1, "active")}
	env := handlerEnv(a)
	if got, err := handleList(ctx, env, listInput{NodeKind: "section", Limit: 7}, "snapshot"); err != nil || len(got.Nodes) != 1 || a.lastFilter.NodeKind != "section" || a.lastFilter.Limit != 7 {
		t.Fatalf("configured list=%+v filter=%+v err=%v", got, a.lastFilter, err)
	}
	a.listErr = errors.New("list failed")
	if _, err := handleList(ctx, env, listInput{}, ""); err == nil || !strings.Contains(err.Error(), "list failed") {
		t.Fatalf("list failure error=%v", err)
	}
	a.listErr = nil
	if _, err := handleSearch(ctx, env, searchInput{}); err == nil || !strings.Contains(err.Error(), "query required") {
		t.Fatalf("empty search error=%v", err)
	}
	env.Embed = handlerEmbedder{err: errors.New("embed failed")}
	if _, err := handleSearch(ctx, env, searchInput{Query: "query"}); err == nil || !strings.Contains(err.Error(), "embed query") {
		t.Fatalf("embedding search error=%v", err)
	}
	if _, err := handleProject(ctx, env, projectInput{}, ""); err == nil || !strings.Contains(err.Error(), "node_id and projection required") {
		t.Fatalf("empty projection error=%v", err)
	}
	if _, err := handleProject(ctx, env, projectInput{NodeID: "node", Projection: "missing"}, ""); err == nil || !strings.Contains(err.Error(), "unknown projection") {
		t.Fatalf("unknown projection error=%v", err)
	}
	env.Projections = newProjectionRegistry([]ProjectionDescriptor{{Name: "not_ready", OwningSpec: "test"}})
	if _, err := handleProject(ctx, env, projectInput{NodeID: "node", Projection: "not_ready"}, ""); err == nil || !strings.Contains(err.Error(), "projection algorithm") {
		t.Fatalf("unimplemented projection error=%v", err)
	}
}
