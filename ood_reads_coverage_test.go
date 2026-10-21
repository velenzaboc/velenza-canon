package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// oodReadCoverageAdapter makes typed OOD handlers observable without a cloud
// database.  It records the exact SQL and bound parameters passed through the
// substrate router, which is the contract these handlers own.
type oodReadCoverageAdapter struct {
	*fakeAdapter
	result QueryResult
	err    error
	sql    string
	params map[string]interface{}
}

func (a *oodReadCoverageAdapter) ID() string { return "ood_graph" }

func (a *oodReadCoverageAdapter) ExecuteReadOnlyQuery(_ context.Context, sql string, params map[string]interface{}) (QueryResult, error) {
	a.sql = sql
	a.params = params
	return a.result, a.err
}

type oodReadCoverageRouter struct{ adapter *oodReadCoverageAdapter }

func (r oodReadCoverageRouter) Adapter(context.Context, NodeKindDescriptor) (SubstrateAdapter, error) {
	return r.adapter, nil
}
func (r oodReadCoverageRouter) All(context.Context) ([]SubstrateAdapter, error) {
	return []SubstrateAdapter{r.adapter}, nil
}
func (r oodReadCoverageRouter) ByID(id string) (SubstrateAdapter, error) {
	if id != "ood_graph" {
		return nil, errors.New("unexpected substrate " + id)
	}
	return r.adapter, nil
}
func (r oodReadCoverageRouter) Close() error { return nil }

func newOODReadCoverageEnv(adapter *oodReadCoverageAdapter) *Env {
	return &Env{
		Config: SpecGraphConfig{
			Mode: ModeExperimentalBootstrap, DefaultOrganizationID: "org-test", ExperimentalQueryEnabled: true,
			Substrates: []SubstrateDescriptor{{
				ID: "ood_graph", ObjectTable: "OODGraphObjects", GraphEdgeTable: "OODGraphEdges",
				SnapshotTable: "OODGraphSnapshots", MaterializationRunTable: "OODGraphMaterializationRuns",
			}},
		},
		Substrates: oodReadCoverageRouter{adapter: adapter},
		Now:        func() time.Time { return time.Unix(0, 0).UTC() },
	}
}

func TestOODReadHandlersBuildAndRouteTypedRequests(t *testing.T) {
	adapter := &oodReadCoverageAdapter{fakeAdapter: &fakeAdapter{}, result: QueryResult{Columns: []string{"graph_object_id"}, Rows: []map[string]interface{}{{"graph_object_id": "object-1"}}}}
	env := newOODReadCoverageEnv(adapter)
	ctx := context.Background()

	if got, err := handleOODGet(ctx, env, oodGetInput{GraphObjectID: "object-1"}); err != nil || len(got.Rows) != 1 {
		t.Fatalf("get result=%+v err=%v", got, err)
	}
	mustContain(t, adapter.sql, "o.graph_object_id = 'object-1'")
	mustContain(t, adapter.sql, "LIMIT 1")

	if _, err := handleOODList(ctx, env, oodListInput{}); err != nil {
		t.Fatalf("list: %v", err)
	}
	mustContain(t, adapter.sql, "o.status = 'active'")
	mustContain(t, adapter.sql, "LIMIT 200")
	if _, err := handleOODList(ctx, env, oodListInput{ObjectClass: "section", Status: "superseded", GraphSnapshotID: "snap", Limit: 7}); err != nil {
		t.Fatalf("historical list: %v", err)
	}
	for _, want := range []string{"o.object_class = 'section'", "o.status = 'superseded'", "s.graph_snapshot_id = 'snap'", "LIMIT 7"} {
		mustContain(t, adapter.sql, want)
	}

	env.Embed = handlerEmbedder{}
	if _, err := handleOODSearch(ctx, env, oodSearchInput{Query: "find contracts", ObjectClass: "axiom"}); err != nil {
		t.Fatalf("search: %v", err)
	}
	mustContain(t, adapter.sql, "APPROX_COSINE_DISTANCE(embedding, @v")
	mustContain(t, adapter.sql, "o.object_class = 'axiom'")
	mustContain(t, adapter.sql, "LIMIT 15")
	if got, ok := adapter.params["v"].([]float32); !ok || len(got) != 2 || got[0] != 1 {
		t.Fatalf("search vector binding=%#v", adapter.params)
	}

	if _, err := handleOODNeighbors(ctx, env, oodNeighborsInput{GraphObjectID: "object-1"}); err != nil {
		t.Fatalf("neighbors: %v", err)
	}
	mustContain(t, adapter.sql, "(e.source_endpoint_id = 'object-1' OR e.target_endpoint_id = 'object-1')")
	mustContain(t, adapter.sql, "LIMIT 200")
	if _, err := handleOODNeighbors(ctx, env, oodNeighborsInput{GraphObjectID: "object-1", Direction: "out", EdgeLabels: []string{"depends_on"}, Limit: 4}); err != nil {
		t.Fatalf("filtered neighbors: %v", err)
	}
	mustContain(t, adapter.sql, "e.source_endpoint_id = 'object-1'")
	mustContain(t, adapter.sql, "e.edge_label IN ('depends_on')")
	mustContain(t, adapter.sql, "LIMIT 4")
}

func TestOODTraversalHandlersShapeRootEvidenceAndRejectUnsafeRequests(t *testing.T) {
	root := traversalTestRow("root", 0, []string{}, []string{"root"}, dependencyClosureProfile, "closure_result", 2, 3)
	adapter := &oodReadCoverageAdapter{fakeAdapter: &fakeAdapter{}, result: QueryResult{Rows: []map[string]interface{}{root}}}
	env := newOODReadCoverageEnv(adapter)

	got, err := handleOODClosure(context.Background(), env, oodClosureInput{GraphObjectID: "root", ClosureProfile: dependencyClosureProfile, MaxDepth: 2, ResultCap: 3})
	if err != nil || got.GraphSnapshotID != "snapshot" || len(got.Rows) != 0 || got.CapState != "complete" {
		t.Fatalf("closure=%+v err=%v", got, err)
	}
	mustContain(t, adapter.sql, "path_edge.edge_label='depends_on'")

	impactRoot := traversalTestRow("root", 0, []string{}, []string{"root"}, loadBearingImpactProfile, "impact_result", 1, 1)
	adapter.result = QueryResult{Rows: []map[string]interface{}{impactRoot}}
	got, err = handleOODImpact(context.Background(), env, oodImpactInput{GraphObjectID: "root", ClosureProfile: loadBearingImpactProfile, MaxDepth: 1, ResultCap: 1})
	if err != nil || got.ResultShape != "impact_result" {
		t.Fatalf("impact=%+v err=%v", got, err)
	}
	mustContain(t, adapter.sql, "path_edge.edge_label='load_bearing_for'")

	for _, tc := range []struct {
		name string
		in   oodClosureInput
		want string
	}{
		{"missing root", oodClosureInput{ClosureProfile: dependencyClosureProfile, ResultCap: 1}, "graph_object_id required"},
		{"negative depth", oodClosureInput{GraphObjectID: "root", ClosureProfile: dependencyClosureProfile, MaxDepth: -1, ResultCap: 1}, "max_depth must be >= 0"},
		{"depth cap", oodClosureInput{GraphObjectID: "root", ClosureProfile: dependencyClosureProfile, MaxDepth: 33, ResultCap: 1}, "max_depth must be <= 32"},
		{"empty cap", oodClosureInput{GraphObjectID: "root", ClosureProfile: dependencyClosureProfile, ResultCap: 0}, "result_cap must be >= 1"},
		{"wrong profile", oodClosureInput{GraphObjectID: "root", ClosureProfile: loadBearingImpactProfile, ResultCap: 1}, "invalid for closure"},
		{"process cap", oodClosureInput{GraphObjectID: "root", ClosureProfile: dependencyClosureProfile, ResultCap: int(^uint(0)>>1) - 1}, "process-safe integer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := handleOODClosure(context.Background(), env, tc.in); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
	adapter.err = errors.New("graph query failed")
	if _, err := handleOODClosure(context.Background(), env, oodClosureInput{GraphObjectID: "root", ClosureProfile: dependencyClosureProfile, MaxDepth: 1, ResultCap: 1}); err == nil || !strings.Contains(err.Error(), "graph query failed") {
		t.Fatalf("closure adapter error=%v", err)
	}
}

func TestOODReadHandlersRefuseInvalidInputsAndAdapterFailures(t *testing.T) {
	adapter := &oodReadCoverageAdapter{fakeAdapter: &fakeAdapter{}, err: errors.New("read failed")}
	env := newOODReadCoverageEnv(adapter)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		run  func() error
		want string
	}{
		{"get id", func() error { _, err := handleOODGet(ctx, env, oodGetInput{}); return err }, "graph_object_id required"},
		{"search query", func() error { _, err := handleOODSearch(ctx, env, oodSearchInput{}); return err }, "query required"},
		{"search embedding", func() error { _, err := handleOODSearch(ctx, env, oodSearchInput{Query: "q"}); return err }, "embedding not configured"},
		{"neighbors id", func() error { _, err := handleOODNeighbors(ctx, env, oodNeighborsInput{}); return err }, "graph_object_id required"},
		{"neighbors direction", func() error {
			_, err := handleOODNeighbors(ctx, env, oodNeighborsInput{GraphObjectID: "x", Direction: "sideways"})
			return err
		}, "direction must be"},
		{"adapter failure", func() error { _, err := handleOODList(ctx, env, oodListInput{}); return err }, "read failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
	env.Embed = handlerEmbedder{err: errors.New("embedding denied")}
	if _, err := handleOODSearch(ctx, env, oodSearchInput{Query: "q"}); err == nil || !strings.Contains(err.Error(), "embed query: embedding denied") {
		t.Fatalf("embedding error=%v", err)
	}
}

func TestOODReadScalarAndEnvelopeRefusals(t *testing.T) {
	for _, tc := range []struct {
		value interface{}
		want  int
	}{
		{int64(2), 2}, {int(3), 3}, {float64(4), 4}, {"5", 5},
	} {
		if got, err := traversalDepth(tc.value); err != nil || got != tc.want {
			t.Fatalf("depth(%#v)=(%d,%v), want %d", tc.value, got, err, tc.want)
		}
	}
	for _, value := range []interface{}{int64(-1), float64(1.5), "05", true} {
		if _, err := traversalDepth(value); err == nil {
			t.Fatalf("invalid depth %#v accepted", value)
		}
	}
	if values, err := traversalStringArray([]interface{}{"a", "b"}, "ids"); err != nil || strings.Join(values, ",") != "a,b" {
		t.Fatalf("array=%v err=%v", values, err)
	}
	for _, value := range []interface{}{[]interface{}{""}, []int{1}, nil} {
		if _, err := traversalStringArray(value, "ids"); err == nil {
			t.Fatalf("invalid array %#v accepted", value)
		}
	}
	for _, tc := range []struct {
		value interface{}
		want  bool
	}{
		{int64(7), true}, {"8", true}, {"08", false}, {float64(7.5), false}, {true, false},
	} {
		_, ok := traversalInt64(tc.value)
		if ok != tc.want {
			t.Fatalf("int64(%#v) ok=%t, want %t", tc.value, ok, tc.want)
		}
	}

	row := traversalTestRow("root", 0, []string{}, []string{"root"}, dependencyClosureProfile, "closure_result", 1, 1)
	row["snapshot_selector_mode"] = "unknown"
	if _, err := traversalEnvelopeFromRow(row, "closure_result"); err == nil || !strings.Contains(err.Error(), "snapshot_selector_mode") {
		t.Fatalf("invalid envelope error=%v", err)
	}
	row = traversalTestRow("root", 0, []string{}, []string{"root"}, dependencyClosureProfile, "closure_result", 1, 1)
	row["path_edge_ids"] = []string{"unexpected"}
	if _, err := validateTraversalPathRow(row, dependencyClosureProfile, 1, 1); err == nil || !strings.Contains(err.Error(), "arrays do not match") {
		t.Fatalf("invalid path error=%v", err)
	}
}

func TestOODReadTableAndTraversalEnvelopeFailClosed(t *testing.T) {
	adapter := &oodReadCoverageAdapter{fakeAdapter: &fakeAdapter{}}
	env := newOODReadCoverageEnv(adapter)
	if got, err := resolveOODReadTables(env); err != nil || got.OwnerID != "ood_graph" || got.Edge != "OODGraphEdges" {
		t.Fatalf("tables=%+v err=%v", got, err)
	}
	for _, tc := range []struct {
		name string
		env  *Env
		want string
	}{
		{"missing table", &Env{Config: SpecGraphConfig{Substrates: []SubstrateDescriptor{{ID: "ood_graph", ObjectTable: "objects"}}}}, "graph_edge_table"},
		{"split owner", &Env{Config: SpecGraphConfig{Substrates: []SubstrateDescriptor{
			{ID: "objects", ObjectTable: "objects", SnapshotTable: "snapshots", MaterializationRunTable: "runs"},
			{ID: "edges", GraphEdgeTable: "edges"},
		}}}, "co-located tables"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := resolveOODReadTables(tc.env); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}

	base := traversalTestRow("root", 0, []string{}, []string{"root"}, dependencyClosureProfile, "closure_result", 1, 1)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]interface{})
		want   string
	}{
		{"bad version", func(r map[string]interface{}) { r["graph_version"] = int64(0) }, "graph_version"},
		{"missing coordinate", func(r map[string]interface{}) { r["materialization_run_id"] = "" }, "materialization_run_id required"},
		{"active nonactive", func(r map[string]interface{}) { r["selected_snapshot_status"] = "archived" }, "non-active"},
		{"bad hash", func(r map[string]interface{}) { r["source_set_hash"] = "not-a-hash" }, "source_set_hash"},
		{"time drift", func(r map[string]interface{}) { r["traversal_time"] = "later" }, "traversal_time"},
		{"wrong shape", func(r map[string]interface{}) { r["result_shape"] = "impact_result" }, "result_shape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := make(map[string]interface{}, len(base))
			for key, value := range base {
				row[key] = value
			}
			tc.mutate(row)
			if _, err := traversalEnvelopeFromRow(row, "closure_result"); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestTraversalPathEvidenceRefusesMalformedClaims(t *testing.T) {
	base := traversalTestRow("child", 1, []string{"edge"}, []string{"root", "child"}, dependencyClosureProfile, "closure_result", 1, 2)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]interface{})
		want   string
	}{
		{"endpoint kind", func(r map[string]interface{}) { r["root_endpoint_kind"] = "symbol" }, "requires graph_object"},
		{"label", func(r map[string]interface{}) { r["path_edge_labels"] = []string{"declares"} }, "does not match"},
		{"cycle type", func(r map[string]interface{}) { r["cycle_detected"] = "false" }, "unexpected type"},
		{"cycle lie", func(r map[string]interface{}) { r["cycle_detected"] = true }, "does not match"},
		{"max depth", func(r map[string]interface{}) { r["max_depth"] = int64(2) }, "max_depth"},
		{"result cap", func(r map[string]interface{}) { r["result_cap"] = int64(3) }, "result_cap"},
		{"profile", func(r map[string]interface{}) { r["selected_closure_profile"] = loadBearingImpactProfile }, "selected_closure_profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := make(map[string]interface{}, len(base))
			for key, value := range base {
				row[key] = value
			}
			tc.mutate(row)
			if _, err := validateTraversalPathRow(row, dependencyClosureProfile, 1, 2); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}
