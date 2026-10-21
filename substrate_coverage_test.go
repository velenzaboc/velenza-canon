package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestSpannerSubstrateMetadataAndWriteTableGuards(t *testing.T) {
	adapter := &SpannerSubstrateAdapter{Descriptor: SubstrateDescriptor{
		ID: "primary", Description: "primary graph", SpannerDatabase: "projects/p/instances/i/databases/d",
		NodeTable: "Nodes", EdgeTable: "Edges", AdmissionLogTable: "AdmissionLog",
	}}
	if adapter.ID() != "primary" || adapter.Description() != "primary graph" || adapter.Database() != "projects/p/instances/i/databases/d" {
		t.Fatalf("metadata accessors lost descriptor: %q %q %q", adapter.ID(), adapter.Description(), adapter.Database())
	}
	if node, edge, log, err := adapter.requireWriteTables(); err != nil || node != "Nodes" || edge != "Edges" || log != "AdmissionLog" {
		t.Fatalf("write tables = %q %q %q, %v", node, edge, log, err)
	}

	readOnly := &SpannerSubstrateAdapter{Descriptor: adapter.Descriptor}
	readOnly.Descriptor.ReadOnly = true
	if _, _, _, err := readOnly.requireWriteTables(); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only adapter write guard = %v", err)
	}
	missing := &SpannerSubstrateAdapter{Descriptor: adapter.Descriptor}
	missing.Descriptor.EdgeTable = ""
	if _, _, _, err := missing.requireWriteTables(); err == nil || !strings.Contains(err.Error(), "all required") {
		t.Fatalf("missing table guard = %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("close nil client: %v", err)
	}
	if got := condIf(true, "clause"); got != "clause" {
		t.Fatalf("condIf(true) = %q", got)
	}
	if got := condIf(false, "clause"); got != "" {
		t.Fatalf("condIf(false) = %q", got)
	}
}

func TestSpannerSubstrateEarlyRefusalsNeedNoNetwork(t *testing.T) {
	ctx := context.Background()
	empty := &SpannerSubstrateAdapter{Descriptor: SubstrateDescriptor{ID: "empty"}}
	checks := []struct {
		name string
		call func() error
		want string
	}{
		{"check schema", func() error { return empty.CheckSchema(ctx) }, "all required"},
		{"verify fingerprint", func() error { return empty.VerifyExperimentalSchema(ctx) }, "no table fields"},
		{"empty commit", func() error { _, err := empty.CommitAdmission(ctx); return err }, "no plans"},
		{"write tables", func() error { _, err := empty.CommitAdmission(ctx, AdmissionPlan{}); return err }, "all required"},
		{"read node", func() error { _, err := empty.ReadNode(ctx, "n", "", ""); return err }, "node_table"},
		{"read edge", func() error { _, err := empty.ReadEdge(ctx, "e", ""); return err }, "edge_table"},
		{"list", func() error { _, err := empty.ListNodes(ctx, ListFilter{}); return err }, "node_table"},
		{"neighbors", func() error { _, err := empty.Neighbors(ctx, "n", NeighborOpts{}); return err }, "edge_table"},
		{"history", func() error { _, err := empty.History(ctx, "n"); return err }, "node_table"},
		{"search", func() error { _, err := empty.SearchByEmbedding(ctx, []float32{1}, "", 1, "org"); return err }, "node_table"},
		{"definition", func() error { _, _, err := empty.FindByDefinitionHash(ctx, "org", "hash"); return err }, "node_table"},
		{"canonical", func() error { _, _, err := empty.FindByCanonicalName(ctx, "org", "kind", "name"); return err }, "node_table"},
		{"similar", func() error { _, err := empty.FindSimilarByEmbedding(ctx, "org", []float32{1}, .2, 1); return err }, "node_table"},
		{"traverse", func() error { _, err := empty.TraverseClosure(ctx, "n", nil, 2, 5, "forward"); return err }, "node_table"},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}

	configured := &SpannerSubstrateAdapter{Descriptor: SubstrateDescriptor{
		ID: "configured", SpannerDatabase: "projects/p/instances/i/databases/d",
		NodeTable: "Nodes", EdgeTable: "Edges", AdmissionLogTable: "Logs",
	}}
	t.Setenv("SPANNER_EMULATOR_HOST", "127.0.0.1:9010")
	if _, err := configured.getClient(ctx); err == nil || !strings.Contains(err.Error(), "SPANNER_EMULATOR_HOST") {
		t.Fatalf("emulator opt-in refusal = %v", err)
	}
	getClientChecks := []func() error{
		func() error { _, err := configured.ReadNode(ctx, "n", "", ""); return err },
		func() error { _, err := configured.ReadEdge(ctx, "e", ""); return err },
		func() error { _, err := configured.ListNodes(ctx, ListFilter{}); return err },
		func() error { _, err := configured.Neighbors(ctx, "n", NeighborOpts{}); return err },
		func() error { _, err := configured.History(ctx, "n"); return err },
		func() error { _, err := configured.SearchByEmbedding(ctx, nil, "", 1, "org"); return err },
		func() error { _, _, err := configured.FindByDefinitionHash(ctx, "org", "hash"); return err },
		func() error { _, _, err := configured.FindByCanonicalName(ctx, "org", "kind", "name"); return err },
		func() error { _, err := configured.FindSimilarByEmbedding(ctx, "org", nil, .2, 1); return err },
		func() error { _, err := configured.TraverseClosure(ctx, "n", nil, 2, 5, "forward"); return err },
		func() error { _, err := configured.ExecuteReadOnlyQuery(ctx, "SELECT 1", nil); return err },
	}
	for i, call := range getClientChecks {
		if err := call(); err == nil || !strings.Contains(err.Error(), "SPANNER_EMULATOR_HOST") {
			t.Fatalf("configured call[%d] error = %v", i, err)
		}
	}
	if _, _, err := configured.FindByCanonicalName(ctx, "org", "kind", ""); err != nil {
		t.Fatalf("empty canonical name should be a no-hit, got %v", err)
	}
	if _, err := configured.FindSimilarByEmbedding(ctx, "org", nil, .2, 0); err == nil || !strings.Contains(err.Error(), "limit must be") {
		t.Fatalf("invalid similar limit = %v", err)
	}
}

func TestDecodeStructpbValuePreservesNativeShape(t *testing.T) {
	value, err := structpb.NewValue(map[string]interface{}{
		"list":   []interface{}{float64(2), true, nil, "text"},
		"nested": map[string]interface{}{"key": "value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := decodeStructpbValue(value)
	want := map[string]interface{}{
		"list":   []interface{}{float64(2), true, nil, "text"},
		"nested": map[string]interface{}{"key": "value"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded value = %#v, want %#v", got, want)
	}
	if decodeStructpbValue(nil) != nil || decodeStructpbValue(&structpb.Value{}) != nil {
		t.Fatal("nil/unknown protobuf values must decode as nil")
	}
}

func newSubstrateNodeRow(t *testing.T, distance *float64, contract, payload string) *spanner.Row {
	t.Helper()
	columns := []string{"organization_id", "node_id", "version", "node_kind", "status", "contract_json", "content_json", "definition_hash", "manifest_hash", "signature_chain", "admitted_by", "admitted_at"}
	when := time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC)
	values := []interface{}{
		"org", "node", int64(3), "section", "active",
		spanner.NullString{StringVal: contract, Valid: true}, spanner.NullString{StringVal: payload, Valid: true},
		"definition", "manifest", []string{"prior", "current"}, "principal", when,
	}
	if distance != nil {
		columns = append(columns, "distance")
		values = append(values, *distance)
	}
	row, err := spanner.NewRow(columns, values)
	if err != nil {
		t.Fatalf("new row: %v", err)
	}
	return row
}

func TestDecodeSubstrateNodeRows(t *testing.T) {
	row := newSubstrateNodeRow(t, nil, `{"canonical_name":"node"}`, `{"title":"Node"}`)
	node, err := decodeNodeRow(row)
	if err != nil {
		t.Fatalf("decodeNodeRow: %v", err)
	}
	if node.NodeID != "node" || node.NodeKind != "section" || node.OrganizationID != "org" || node.CurrentVersion.Version != 3 {
		t.Fatalf("decoded node identity = %#v", node)
	}
	if node.CurrentVersion.Contract["canonical_name"] != "node" || node.CurrentVersion.Payload["title"] != "Node" || len(node.CurrentVersion.SignatureChain) != 2 {
		t.Fatalf("decoded node material = %#v", node.CurrentVersion)
	}

	distance := 0.125
	searchRow := newSubstrateNodeRow(t, &distance, `{"canonical_name":"node"}`, `{"title":"Node"}`)
	withDistance, gotDistance, err := decodeNodeRowWithDistanceValue(searchRow)
	if err != nil || gotDistance != distance || withDistance.NodeID != "node" {
		t.Fatalf("distance decode = %#v, %v, %v", withDistance, gotDistance, err)
	}
	withoutDistance, err := decodeNodeRowWithDistance(searchRow)
	if err != nil || withoutDistance.CurrentVersion.DefinitionHash != "definition" {
		t.Fatalf("ranked node decode = %#v, %v", withoutDistance, err)
	}

	malformedJSON := newSubstrateNodeRow(t, nil, "{", "[")
	malformed, err := decodeNodeRow(malformedJSON)
	if err != nil {
		t.Fatalf("malformed optional JSON should not corrupt row identity: %v", err)
	}
	if malformed.CurrentVersion.Contract != nil || malformed.CurrentVersion.Payload != nil {
		t.Fatalf("malformed optional JSON decoded as material: %#v", malformed.CurrentVersion)
	}

	short, err := spanner.NewRow([]string{"only"}, []interface{}{"value"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeNodeRow(short); err == nil || !strings.Contains(err.Error(), "decode node row") {
		t.Fatalf("short node row error = %v", err)
	}
	if _, _, err := decodeNodeRowWithDistanceValue(short); err == nil || !strings.Contains(err.Error(), "similar-search") {
		t.Fatalf("short similar row error = %v", err)
	}
	if _, err := decodeNodeRowWithDistance(short); err == nil || !strings.Contains(err.Error(), "search row") {
		t.Fatalf("short ranked row error = %v", err)
	}
}

func TestDecodeSubstrateEdgeRowsAndNullableValues(t *testing.T) {
	when := time.Date(2026, 9, 9, 9, 0, 0, 0, time.UTC)
	row, err := spanner.NewRow(
		[]string{"organization_id", "edge_id", "source_node_id", "source_version", "target_node_id", "target_version", "edge_label", "status", "admitted_at", "reciprocal_edge_id"},
		[]interface{}{"org", "edge", "source", spanner.NullInt64{Int64: 2, Valid: true}, "target", spanner.NullInt64{Int64: 4, Valid: true}, "depends_on", "active", when, spanner.NullString{StringVal: "inverse", Valid: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	edge, err := decodeEdgeRow(row)
	if err != nil {
		t.Fatalf("decodeEdgeRow: %v", err)
	}
	if edge.EdgeID != "edge" || edge.SourceVersion != 2 || edge.TargetVersion != 4 || edge.ReciprocalEdgeID != "inverse" || !edge.AdmittedAt.Equal(when) {
		t.Fatalf("decoded edge = %#v", edge)
	}

	short, err := spanner.NewRow([]string{"only"}, []interface{}{"value"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEdgeRow(short); err == nil || !strings.Contains(err.Error(), "decode edge row") {
		t.Fatalf("short edge row error = %v", err)
	}

	if got := nullableString(""); !reflect.DeepEqual(got, spanner.NullString{Valid: false}) {
		t.Fatalf("nullableString empty = %#v", got)
	}
	if got := nullableString("value"); got != "value" {
		t.Fatalf("nullableString value = %#v", got)
	}
	if got := nullableTime(nil); !reflect.DeepEqual(got, spanner.NullTime{}) {
		t.Fatalf("nullableTime nil = %#v", got)
	}
	if got := nullableTime(&when); got != when {
		t.Fatalf("nullableTime value = %#v", got)
	}
	if got := nullableInt64(0); !reflect.DeepEqual(got, spanner.NullInt64{Valid: false}) {
		t.Fatalf("nullableInt64 zero = %#v", got)
	}
	if got := nullableInt64(7); got != int64(7) {
		t.Fatalf("nullableInt64 value = %#v", got)
	}
}

func TestConfigRouterResolvesOnlyDeclaredSubstrates(t *testing.T) {
	primary := &SpannerSubstrateAdapter{Descriptor: SubstrateDescriptor{ID: "primary"}}
	secondary := &SpannerSubstrateAdapter{Descriptor: SubstrateDescriptor{ID: "secondary"}}
	router := &configRouter{byID: map[string]*SpannerSubstrateAdapter{"primary": primary, "secondary": secondary}}
	kind := NewNodeKindDescriptor(map[string]interface{}{"name": "section", "substrate_id": "primary"})
	got, err := router.Adapter(context.Background(), kind)
	if err != nil || got != primary {
		t.Fatalf("adapter resolution = %#v, %v", got, err)
	}
	missingKind := NewNodeKindDescriptor(map[string]interface{}{"name": "missing_kind", "substrate_id": "missing"})
	if _, err := router.Adapter(context.Background(), missingKind); !errors.Is(err, ErrSubstrateNotProvisioned) {
		t.Fatalf("missing adapter error = %v", err)
	}
	all, err := router.All(context.Background())
	if err != nil || len(all) != 2 {
		t.Fatalf("all adapters = %#v, %v", all, err)
	}
	seen := map[string]bool{}
	for _, adapter := range all {
		seen[adapter.ID()] = true
	}
	if !reflect.DeepEqual(seen, map[string]bool{"primary": true, "secondary": true}) {
		t.Fatalf("adapter roster = %#v", seen)
	}
	if got, err := router.ByID("secondary"); err != nil || got != secondary {
		t.Fatalf("ByID = %#v, %v", got, err)
	}
	if _, err := router.ByID("missing"); err == nil || !strings.Contains(err.Error(), "no substrate") {
		t.Fatalf("missing ByID error = %v", err)
	}
	if err := router.Close(); err != nil {
		t.Fatalf("router close: %v", err)
	}
}
