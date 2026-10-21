package main

import (
	"context"
	"fmt"
	"strings"
)

// ood_handlers.go declares MCP verbs that query the schema_v2 OODGraph
// substrate. The whole-spec materialization walker was retired —
// ingestion is per-node admission of the bootstrap/seed_nodes/ files
// only. List verbs here are read-only queries against the 7 OODGraph
// tables; the write verb (spec_graph_import in handlers.go) admits one
// graph object per seed_node file.

// ---------------- inputs ----------------

// listRunsInput filters OODGraphMaterializationRuns rows.
type listRunsInput struct {
	State   string `json:"state,omitempty" jsonschema:"pending | running | sealed | failed | abandoned"`
	RunKind string `json:"run_kind,omitempty"`
	Limit   int    `json:"limit,omitempty"`
}

// listViolationsInput filters OODGraphViolations rows.
type listViolationsInput struct {
	GraphSnapshotID string `json:"graph_snapshot_id,omitempty"`
	Severity        string `json:"severity,omitempty" jsonschema:"blocker | major | minor | info"`
	ViolationCode   string `json:"violation_code,omitempty"`
	Limit           int    `json:"limit,omitempty"`
}

// listSnapshotsInput filters OODGraphSnapshots rows.
type listSnapshotsInput struct {
	SnapshotState string `json:"snapshot_state,omitempty" jsonschema:"building | sealed"`
	SnapshotKind  string `json:"snapshot_kind,omitempty" jsonschema:"active_candidate | historical | diagnostic"`
	Status        string `json:"status,omitempty"`
	Limit         int    `json:"limit,omitempty"`
}

// ---------------- handlers ----------------

// handleListRuns queries the materialization_run table. Table name comes
// from spec-graph.config.json substrate.materialization_run_table per
// binary_is_never_sot — never hardcoded in the binary.
func handleListRuns(ctx context.Context, env *Env, in listRunsInput) (QueryResult, error) {
	table, ownerID, err := substrateTableAndOwner(env, func(s SubstrateDescriptor) string { return s.MaterializationRunTable }, "materialization_run_table")
	if err != nil {
		return QueryResult{}, err
	}
	q := fmt.Sprintf("SELECT * FROM %s WHERE 1=1", table)
	if in.State != "" {
		q += fmt.Sprintf(" AND state = '%s'", sqlEscape(in.State))
	}
	if in.RunKind != "" {
		q += fmt.Sprintf(" AND run_kind = '%s'", sqlEscape(in.RunKind))
	}
	q += " ORDER BY started_at DESC"
	if in.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", in.Limit)
	} else {
		q += " LIMIT 100"
	}
	return handleQueryOnSubstrate(ctx, env, queryInput{SQL: q}, ownerID)
}

// handleListViolations queries the violation table. Table name from config.
func handleListViolations(ctx context.Context, env *Env, in listViolationsInput) (QueryResult, error) {
	table, ownerID, err := substrateTableAndOwner(env, func(s SubstrateDescriptor) string { return s.ViolationTable }, "violation_table")
	if err != nil {
		return QueryResult{}, err
	}
	q := fmt.Sprintf("SELECT * FROM %s WHERE 1=1", table)
	if in.GraphSnapshotID != "" {
		q += fmt.Sprintf(" AND graph_snapshot_id = '%s'", sqlEscape(in.GraphSnapshotID))
	}
	if in.Severity != "" {
		q += fmt.Sprintf(" AND severity = '%s'", sqlEscape(in.Severity))
	}
	if in.ViolationCode != "" {
		q += fmt.Sprintf(" AND violation_code = '%s'", sqlEscape(in.ViolationCode))
	}
	q += " ORDER BY created_at DESC"
	if in.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", in.Limit)
	} else {
		q += " LIMIT 100"
	}
	return handleQueryOnSubstrate(ctx, env, queryInput{SQL: q}, ownerID)
}

// handleListSnapshots queries the snapshot table. Table name from config.
func handleListSnapshots(ctx context.Context, env *Env, in listSnapshotsInput) (QueryResult, error) {
	table, ownerID, err := substrateTableAndOwner(env, func(s SubstrateDescriptor) string { return s.SnapshotTable }, "snapshot_table")
	if err != nil {
		return QueryResult{}, err
	}
	q := fmt.Sprintf("SELECT * FROM %s WHERE 1=1", table)
	if in.SnapshotState != "" {
		q += fmt.Sprintf(" AND snapshot_state = '%s'", sqlEscape(in.SnapshotState))
	}
	if in.SnapshotKind != "" {
		q += fmt.Sprintf(" AND snapshot_kind = '%s'", sqlEscape(in.SnapshotKind))
	}
	if in.Status != "" {
		q += fmt.Sprintf(" AND status = '%s'", sqlEscape(in.Status))
	}
	q += " ORDER BY graph_version DESC"
	if in.Limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", in.Limit)
	} else {
		q += " LIMIT 100"
	}
	return handleQueryOnSubstrate(ctx, env, queryInput{SQL: q}, ownerID)
}

// substrateTable reads a configured table name from the unique substrate
// descriptor that declares it. Substrate ordering is not routing authority:
// production config can list VOLT or ASG before OOD Graph. Zero or multiple
// owners fail closed. The binary holds no table-name defaults; config carries
// the names per binary_is_never_sot, Vision §2 principle 7.
func substrateTable(env *Env, pick func(SubstrateDescriptor) string, fieldName string) (string, error) {
	table, _, err := substrateTableAndOwner(env, pick, fieldName)
	return table, err
}

func substrateTableAndOwner(env *Env, pick func(SubstrateDescriptor) string, fieldName string) (string, string, error) {
	if env == nil {
		return "", "", fmt.Errorf("no substrate registered in spec-graph.config.json")
	}
	var owner *SubstrateDescriptor
	for i := range env.Config.Substrates {
		sub := &env.Config.Substrates[i]
		if pick(*sub) == "" {
			continue
		}
		if owner != nil {
			return "", "", fmt.Errorf("%s is ambiguously configured by substrates %q and %q", fieldName, owner.ID, sub.ID)
		}
		owner = sub
	}
	if owner == nil {
		return "", "", fmt.Errorf("no substrate configures %s in spec-graph.config.json", fieldName)
	}
	return pick(*owner), owner.ID, nil
}

// sqlEscape provides minimal escaping for string literals embedded in
// list-verb query strings. Bootstrap-only — production callers go
// through spec_graph_query with parameterized statements.
func sqlEscape(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
