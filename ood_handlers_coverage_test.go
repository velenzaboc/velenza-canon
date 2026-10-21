package main

import (
	"context"
	"strings"
	"testing"
)

type oodQueryAdapter struct {
	*handlerAdapter
	sql    string
	params map[string]interface{}
}

func (a *oodQueryAdapter) ExecuteReadOnlyQuery(_ context.Context, sql string, params map[string]interface{}) (QueryResult, error) {
	a.sql, a.params = sql, params
	return a.query, a.queryErr
}

func oodHandlerEnv(a *oodQueryAdapter) *Env {
	env := handlerEnv(a.handlerAdapter)
	env.Config.Substrates = []SubstrateDescriptor{{
		ID:                      "fake",
		MaterializationRunTable: "RunLedger",
		ViolationTable:          "ViolationLedger",
		SnapshotTable:           "SnapshotLedger",
	}}
	env.Substrates = handlerRouter{adapters: []SubstrateAdapter{a}}
	return env
}

func TestOODListHandlersUseConfiguredOwnerAndEscapeFilters(t *testing.T) {
	a := &oodQueryAdapter{handlerAdapter: newHandlerAdapter()}
	a.query = QueryResult{Columns: []string{"id"}, Rows: []map[string]interface{}{{"id": "one"}}}
	env := oodHandlerEnv(a)
	ctx := context.Background()

	got, err := handleListRuns(ctx, env, listRunsInput{State: "run'ning", RunKind: "corpus_refresh", Limit: 7})
	if err != nil || len(got.Rows) != 1 {
		t.Fatalf("list runs = %#v, %v", got, err)
	}
	for _, want := range []string{"FROM RunLedger", "state = 'run''ning'", "run_kind = 'corpus_refresh'", "ORDER BY started_at DESC", "LIMIT 7"} {
		if !strings.Contains(a.sql, want) {
			t.Fatalf("run SQL %q lacks %q", a.sql, want)
		}
	}

	got, err = handleListViolations(ctx, env, listViolationsInput{GraphSnapshotID: "snap'1", Severity: "major", ViolationCode: "invalid_edge", Limit: 8})
	if err != nil || len(got.Rows) != 1 {
		t.Fatalf("list violations = %#v, %v", got, err)
	}
	for _, want := range []string{"FROM ViolationLedger", "graph_snapshot_id = 'snap''1'", "severity = 'major'", "violation_code = 'invalid_edge'", "ORDER BY created_at DESC", "LIMIT 8"} {
		if !strings.Contains(a.sql, want) {
			t.Fatalf("violation SQL %q lacks %q", a.sql, want)
		}
	}

	got, err = handleListSnapshots(ctx, env, listSnapshotsInput{SnapshotState: "sealed", SnapshotKind: "historical", Status: "active", Limit: 9})
	if err != nil || len(got.Rows) != 1 {
		t.Fatalf("list snapshots = %#v, %v", got, err)
	}
	for _, want := range []string{"FROM SnapshotLedger", "snapshot_state = 'sealed'", "snapshot_kind = 'historical'", "status = 'active'", "ORDER BY graph_version DESC", "LIMIT 9"} {
		if !strings.Contains(a.sql, want) {
			t.Fatalf("snapshot SQL %q lacks %q", a.sql, want)
		}
	}
	if len(a.params) != 0 {
		t.Fatalf("bootstrap list query unexpectedly carried params: %#v", a.params)
	}
}

func TestOODListHandlersApplyBoundedDefaults(t *testing.T) {
	a := &oodQueryAdapter{handlerAdapter: newHandlerAdapter()}
	env := oodHandlerEnv(a)
	ctx := context.Background()
	for _, call := range []struct {
		name string
		fn   func() error
	}{
		{"runs", func() error { _, err := handleListRuns(ctx, env, listRunsInput{}); return err }},
		{"violations", func() error { _, err := handleListViolations(ctx, env, listViolationsInput{}); return err }},
		{"snapshots", func() error { _, err := handleListSnapshots(ctx, env, listSnapshotsInput{}); return err }},
	} {
		t.Run(call.name, func(t *testing.T) {
			if err := call.fn(); err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(a.sql, "LIMIT 100") {
				t.Fatalf("unbounded default SQL = %q", a.sql)
			}
		})
	}
}

func TestOODTableOwnershipFailsClosed(t *testing.T) {
	pick := func(s SubstrateDescriptor) string { return s.SnapshotTable }
	if _, _, err := substrateTableAndOwner(nil, pick, "snapshot_table"); err == nil || !strings.Contains(err.Error(), "no substrate") {
		t.Fatalf("nil environment error = %v", err)
	}
	empty := &Env{Config: SpecGraphConfig{Substrates: []SubstrateDescriptor{{ID: "other"}}}}
	if _, _, err := substrateTableAndOwner(empty, pick, "snapshot_table"); err == nil || !strings.Contains(err.Error(), "no substrate configures") {
		t.Fatalf("missing table owner error = %v", err)
	}
	ambiguous := &Env{Config: SpecGraphConfig{Substrates: []SubstrateDescriptor{{ID: "a", SnapshotTable: "One"}, {ID: "b", SnapshotTable: "Two"}}}}
	if _, _, err := substrateTableAndOwner(ambiguous, pick, "snapshot_table"); err == nil || !strings.Contains(err.Error(), "ambiguously configured") || !strings.Contains(err.Error(), `"a"`) || !strings.Contains(err.Error(), `"b"`) {
		t.Fatalf("ambiguous owner error = %v", err)
	}
	unique := &Env{Config: SpecGraphConfig{Substrates: []SubstrateDescriptor{{ID: "unused"}, {ID: "owner", SnapshotTable: "Snapshots"}}}}
	table, owner, err := substrateTableAndOwner(unique, pick, "snapshot_table")
	if err != nil || table != "Snapshots" || owner != "owner" {
		t.Fatalf("resolved table owner = %q, %q, %v", table, owner, err)
	}
	if got, err := substrateTable(unique, pick, "snapshot_table"); err != nil || got != table {
		t.Fatalf("substrateTable wrapper = %q, %v", got, err)
	}
	if got := sqlEscape("a'b''c"); got != "a''b''''c" {
		t.Fatalf("sqlEscape = %q", got)
	}
}

func TestOODListHandlersPropagateOwnerAndQueryErrors(t *testing.T) {
	a := &oodQueryAdapter{handlerAdapter: newHandlerAdapter()}
	env := oodHandlerEnv(a)
	env.Config.Substrates[0].MaterializationRunTable = ""
	if _, err := handleListRuns(context.Background(), env, listRunsInput{}); err == nil || !strings.Contains(err.Error(), "materialization_run_table") {
		t.Fatalf("owner resolution error = %v", err)
	}
	a.queryErr = context.Canceled
	env.Config.Substrates[0].MaterializationRunTable = "RunLedger"
	if _, err := handleListRuns(context.Background(), env, listRunsInput{}); err != context.Canceled {
		t.Fatalf("query error = %v", err)
	}
}
