package main

import (
	"strings"
	"testing"
)

func TestSelectedSnapshotCTEFencesLegacyRetrievalProfiles(t *testing.T) {
	for _, snapshotID := range []string{"", "11111111-1111-4111-8111-111111111111"} {
		sql := selectedSnapshotCTE("OODGraphSnapshots", "OODGraphMaterializationRuns", "org", snapshotID)
		want := "JSON_VALUE(s.source_set, '$.materialization_profile_version') = '" + MaterializationProfileVersion + "'"
		if !strings.Contains(sql, want) {
			t.Fatalf("selected snapshot SQL lacks current-profile retrieval fence: %s", sql)
		}
		for _, envelopeField := range []string{"s.organization_id", "s.graph_version", "s.snapshot_kind", "s.status AS selected_snapshot_status", "s.materialization_run_id", "r.finished_at AS materialization_run_finished_at", "s.source_set_hash", "s.source_set"} {
			mustContain(t, sql, envelopeField)
		}
	}
}

func testOODReadTables() oodReadTables {
	return oodReadTables{
		Object: "OODGraphObjects", Edge: "OODGraphEdges",
		Snapshot: "OODGraphSnapshots", Run: "OODGraphMaterializationRuns",
		OwnerID: "ood_graph",
	}
}

// TestBuildOODGetSQL_ActiveOnly verifies the typed _get verb's SQL builder
// includes the AND status='active' filter that eliminates the
// R-Kernel_TypedReadReturnsNonLatest defect class observed across the Tier
// B C8 validators. Without this filter, _get could return superseded
// version rows whose canonical_name no longer matches the active row's
// canonical_name — the exact failure mode the caller_context C9 dispatch
// caught and worked around via empirical re-query.
func TestBuildOODGetSQL_ActiveOnly(t *testing.T) {
	got := buildOODGetSQL(testOODReadTables(), "org-test", "abc-123", "")
	mustContain(t, got, "o.graph_object_id = 'abc-123'")
	mustContain(t, got, "AND o.status = 'active'")
	mustContain(t, got, "ORDER BY o.updated_at DESC")
	mustContain(t, got, "LIMIT 1")
}

// TestBuildOODGetSQL_EscapesQuoteInID guards against the SQL-quote-escape
// defect by passing an id that contains a single quote and asserting the
// produced SQL escapes it.
func TestBuildOODGetSQL_EscapesQuoteInID(t *testing.T) {
	tables := testOODReadTables()
	tables.Object = "T"
	got := buildOODGetSQL(tables, "org-test", "a'b", "")
	mustContain(t, got, "o.graph_object_id = 'a''b'")
}

// TestBuildOODGetSQL_OmitsEmbedding is the load-bearing guard for the
// Spanner-side-compute discipline. The embedding column is the 3072-
// float vector used by APPROX_COSINE_DISTANCE in spec_graph_search;
// it is Spanner-internal compute substrate, NEVER something a read
// verb should ship back to a client. _get returning embedding shipped
// ~25KB of vector data per call for no consumer. This test catches a
// future SELECT * regression that would re-include it.
func TestBuildOODGetSQL_OmitsEmbedding(t *testing.T) {
	got := buildOODGetSQL(testOODReadTables(), "org-test", "abc-123", "")
	mustNotContain(t, got, "SELECT *")
	mustNotContain(t, got, ", embedding,")
	mustNotContain(t, got, ", embedding ")
	mustNotContain(t, got, " embedding FROM ")
	mustNotContain(t, got, "search_text")
}

// TestBuildOODGetSQL_SharesLeanColumnsWithList verifies _get and _list
// project the SAME lean column set. Both verbs use oodListLeanColumns
// as the single source of truth for "what fields a read verb returns";
// they must not drift apart.
func TestBuildOODGetSQL_SharesLeanColumnsWithList(t *testing.T) {
	tables := testOODReadTables()
	tables.Object = "T"
	got := buildOODGetSQL(tables, "org-test", "x", "")
	for _, col := range oodListLeanColumns {
		mustContain(t, got, col)
	}
}

// TestBuildOODNeighborsSQL_ActiveEdge verifies the edge-status filter
// remains in the new builder. The edge.status='active' filter was already
// present in the legacy implementation; this test guards against
// accidental removal during the endpoint-join refactor.
func TestBuildOODNeighborsSQL_ActiveEdge(t *testing.T) {
	tables := testOODReadTables()
	tables.Edge, tables.Object = "Edges", "Objects"
	got := buildOODNeighborsSQL(tables, "org-test", "node-1", "", "both", nil, 50)
	mustContain(t, got, "e.status = 'active'")
}

// TestBuildOODNeighborsSQL_ActiveEndpoints verifies the endpoint-join
// filter that's the heart of the Phase A fix. The new builder MUST emit
// EXISTS subqueries against both source and target endpoints, each
// constrained to status='active', so the verb returns only edges
// connecting two active objects. This eliminates the "active edges
// pointing at superseded targets" class of R-Kernel findings that
// surfaced 53 times across the four Tier B C8 validators.
func TestBuildOODNeighborsSQL_ActiveEndpoints(t *testing.T) {
	tables := testOODReadTables()
	tables.Edge, tables.Object = "Edges", "Objects"
	got := buildOODNeighborsSQL(tables, "org-test", "node-1", "", "both", nil, 50)
	mustContain(t, got, "src.graph_snapshot_id = e.graph_snapshot_id AND src.graph_object_id = e.source_endpoint_id AND src.status = 'active'")
	mustContain(t, got, "tgt.graph_snapshot_id = e.graph_snapshot_id AND tgt.graph_object_id = e.target_endpoint_id AND tgt.status = 'active'")
}

// TestBuildOODNeighborsSQL_DirectionOut verifies the out-edge clause
// references source_endpoint_id only.
func TestBuildOODNeighborsSQL_DirectionOut(t *testing.T) {
	tables := testOODReadTables()
	tables.Edge, tables.Object = "Edges", "Objects"
	got := buildOODNeighborsSQL(tables, "org-test", "node-1", "", "out", nil, 50)
	mustContain(t, got, "e.source_endpoint_id = 'node-1'")
	mustNotContain(t, got, "OR e.target_endpoint_id")
}

// TestBuildOODNeighborsSQL_DirectionIn verifies the in-edge clause
// references target_endpoint_id only.
func TestBuildOODNeighborsSQL_DirectionIn(t *testing.T) {
	tables := testOODReadTables()
	tables.Edge, tables.Object = "Edges", "Objects"
	got := buildOODNeighborsSQL(tables, "org-test", "node-1", "", "in", nil, 50)
	mustContain(t, got, "e.target_endpoint_id = 'node-1'")
	mustNotContain(t, got, "e.source_endpoint_id = 'node-1'")
}

// TestBuildOODNeighborsSQL_DirectionBoth verifies the both-direction
// clause uses an OR between source and target endpoint matches.
func TestBuildOODNeighborsSQL_DirectionBoth(t *testing.T) {
	tables := testOODReadTables()
	tables.Edge, tables.Object = "Edges", "Objects"
	got := buildOODNeighborsSQL(tables, "org-test", "node-1", "", "both", nil, 50)
	mustContain(t, got, "(e.source_endpoint_id = 'node-1' OR e.target_endpoint_id = 'node-1')")
}

// TestBuildOODNeighborsSQL_EdgeLabelsFilter verifies the edge_label IN
// filter is correctly emitted when labels are supplied.
func TestBuildOODNeighborsSQL_EdgeLabelsFilter(t *testing.T) {
	tables := testOODReadTables()
	tables.Edge, tables.Object = "Edges", "Objects"
	got := buildOODNeighborsSQL(tables, "org-test", "node-1", "", "both", []string{"declares", "depends_on"}, 50)
	mustContain(t, got, "e.edge_label IN ('declares','depends_on')")
}

// TestBuildOODNeighborsSQL_NoEdgeLabelsOmitsFilter verifies the
// edge_label clause is absent when no labels are supplied.
func TestBuildOODNeighborsSQL_NoEdgeLabelsOmitsFilter(t *testing.T) {
	tables := testOODReadTables()
	tables.Edge, tables.Object = "Edges", "Objects"
	got := buildOODNeighborsSQL(tables, "org-test", "node-1", "", "both", nil, 50)
	mustNotContain(t, got, "edge_label IN")
}

// TestBuildOODNeighborsSQL_LimitClause verifies the LIMIT clause is
// emitted at the configured value.
func TestBuildOODNeighborsSQL_LimitClause(t *testing.T) {
	tables := testOODReadTables()
	tables.Edge, tables.Object = "Edges", "Objects"
	got := buildOODNeighborsSQL(tables, "org-test", "node-1", "", "both", nil, 17)
	mustContain(t, got, "LIMIT 17")
}

// ---------------- List builder ----------------

// TestBuildOODListSQL_OmitsEmbedding is the load-bearing test for the
// lean-column projection. The embedding column is ~25KB JSON-encoded
// per row; including it in bulk-enumeration responses burns context
// budget that R-rule validators never read. This test guards against
// a future SELECT *  regression that would re-include it silently.
func TestBuildOODListSQL_OmitsEmbedding(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "", "", "", 200)
	mustNotContain(t, got, "SELECT *")
	mustNotContain(t, got, ", embedding,")
	mustNotContain(t, got, ", embedding ")
	mustNotContain(t, got, "SELECT embedding")
	mustNotContain(t, got, " embedding FROM ")
}

// TestBuildOODListSQL_OmitsSearchText guards that the lean projection
// also drops the search_text duplicate column.
func TestBuildOODListSQL_OmitsSearchText(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "", "", "", 200)
	mustNotContain(t, got, "search_text")
}

// TestBuildOODListSQL_IncludesIdentityAndPayloadColumns verifies the
// fields R-rule validators DO need are present: graph_object_id,
// object_class, source_stable_reference, search_payload, status.
func TestBuildOODListSQL_IncludesIdentityAndPayloadColumns(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "", "", "", 200)
	for _, col := range []string{"graph_object_id", "object_class", "source_stable_reference", "search_payload", "status"} {
		mustContain(t, got, col)
	}
}

// TestBuildOODListSQL_ActiveOnlyByDefault verifies the active-only
// default filter remains in place when no caller-specified status is
// supplied.
func TestBuildOODListSQL_ActiveOnlyByDefault(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "", "", "", 200)
	mustContain(t, got, "status = 'active'")
}

// TestBuildOODListSQL_CallerStatusOverride verifies an explicit
// status value is honored over the active default.
func TestBuildOODListSQL_CallerStatusOverride(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "", "superseded", "", 200)
	mustContain(t, got, "status = 'superseded'")
	mustNotContain(t, got, "AND o.status = 'active'")
}

// TestBuildOODListSQL_ObjectClassFilter verifies the object_class
// filter is appended when supplied.
func TestBuildOODListSQL_ObjectClassFilter(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "invariant", "", "", 200)
	mustContain(t, got, "object_class = 'invariant'")
}

// TestBuildOODListSQL_GraphSnapshotIDFilter verifies the snapshot
// filter is appended when supplied.
func TestBuildOODListSQL_GraphSnapshotIDFilter(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "", "", "snap-uuid-1", 200)
	mustContain(t, got, "graph_snapshot_id = 'snap-uuid-1'")
}

// TestBuildOODListSQL_LimitApplied verifies the configured limit is
// emitted at the end of the query.
func TestBuildOODListSQL_LimitApplied(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "", "", "", 47)
	mustContain(t, got, "LIMIT 47")
}

// TestBuildOODListSQL_DeterministicOrderingPreserved verifies the
// ORDER BY clause is preserved so re-runs produce the same paging.
func TestBuildOODListSQL_DeterministicOrderingPreserved(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "", "", "", 200)
	mustContain(t, got, "ORDER BY o.object_class, o.source_stable_reference")
}

func TestOODCurrentReadSelectsOneEligibleSealedSnapshotAndEnforcesFreshness(t *testing.T) {
	got := buildOODGetSQL(testOODReadTables(), "org-test", "object-1", "")
	for _, want := range []string{
		"s.organization_id = 'org-test'",
		"s.snapshot_state = 'sealed'",
		"s.status = 'active'",
		"s.snapshot_kind = 'active_candidate'",
		"r.target_graph_snapshot_id = s.graph_snapshot_id",
		"r.state = 'sealed'",
		"r.finished_at IS NOT NULL",
		"r.input_source_set_hash = s.source_set_hash",
		"ORDER BY s.graph_version DESC",
		"JOIN selected_snapshot ss ON ss.graph_snapshot_id = o.graph_snapshot_id",
		"TIMESTAMP_DIFF(CURRENT_TIMESTAMP()",
		"freshness_window_seconds",
		"JSON_QUERY_ARRAY(ss.source_set, '$.external_verification_receipts')",
		"$.observed_at",
		"$.source_content_hash",
	} {
		mustContain(t, got, want)
	}
	mustNotContain(t, got, "graph_owned_parser_classification_tokens.retrieved_at")
	// OODGraphObjects.source_content_hash binds the decoded representation.
	// A transport encoding may make the raw transport hash differ, so using
	// transport_raw_content_hash here would hide a fresh, valid object.
	mustNotContain(t, got, "$.transport_raw_content_hash")
}

func TestOODHistoricalReadPinsEligibleSnapshotAndDoesNotApplyCurrentFreshness(t *testing.T) {
	got := buildOODListSQL(testOODReadTables(), "org-test", "", "", "snap-history", 20)
	mustContain(t, got, "s.graph_snapshot_id = 'snap-history'")
	mustContain(t, got, "s.status IN ('active','superseded','archived')")
	mustContain(t, got, "o.status IN ('active','superseded','archived')")
	mustNotContain(t, got, "TIMESTAMP_DIFF(CURRENT_TIMESTAMP()")
}

func TestTypedClosureProfilesAreClosedAndDirectionSpecific(t *testing.T) {
	edge, inverse, shape, err := resolveTypedTraversalProfile(dependencyClosureProfile, "forward")
	if err != nil || edge != "depends_on" || inverse != "load_bearing_for" || shape != "closure_result" {
		t.Fatalf("dependency profile=%q/%q/%q err=%v", edge, inverse, shape, err)
	}
	edge, inverse, shape, err = resolveTypedTraversalProfile(loadBearingImpactProfile, "reverse")
	if err != nil || edge != "load_bearing_for" || inverse != "depends_on" || shape != "impact_result" {
		t.Fatalf("impact profile=%q/%q/%q err=%v", edge, inverse, shape, err)
	}
	for _, tc := range []struct{ profile, direction string }{
		{"dependency", "forward"},
		{loadBearingImpactProfile, "forward"},
		{dependencyClosureProfile, "reverse"},
		{"all_edge_families", "reverse"},
	} {
		if _, _, _, err := resolveTypedTraversalProfile(tc.profile, tc.direction); err == nil {
			t.Fatalf("profile=%q direction=%q escaped the closed traversal contract", tc.profile, tc.direction)
		}
	}
}

func TestTypedTraversalSQLFencesSnapshotEndpointsReciprocityAndImpactLabel(t *testing.T) {
	current := buildOODTraversalSQL(testOODReadTables(), "org-test", "root-object", "", loadBearingImpactProfile, "impact_result", "load_bearing_for", "depends_on", 3, 7)
	for _, want := range []string{
		"JOIN selected_snapshot ss ON ss.graph_snapshot_id=o.graph_snapshot_id",
		"o.status = 'active' AND o.validation_state='valid'",
		"TIMESTAMP_DIFF(CURRENT_TIMESTAMP()",
		"JOIN eligible_objects src ON src.graph_snapshot_id=e.graph_snapshot_id",
		"JOIN eligible_objects tgt ON tgt.graph_snapshot_id=e.graph_snapshot_id",
		"e.status = 'active' AND e.validation_state='valid' AND e.edge_label='load_bearing_for'",
		"e.diagnostic_only=FALSE AND e.reciprocity_state='complete'",
		"inv.graph_snapshot_id=e.graph_snapshot_id",
		"inv.edge_label='depends_on'",
		"inv.status = 'active' AND inv.validation_state='valid'",
		"inv.reciprocity_state='complete'",
		"inv.source_endpoint_id=e.target_endpoint_id AND inv.target_endpoint_id=e.source_endpoint_id",
		"inv.valid_from IS NULL OR inv.valid_from <= ss.sealed_at",
		"inv.valid_until IS NULL OR inv.valid_until > ss.sealed_at",
		"FROM GRAPH_TABLE (", "OODGraph", "MATCH path = WALK",
		"path_edge.edge_label='load_bearing_for'", "->{0,4}(terminal)",
		"root.organization_id='org-test' AND root.graph_object_id='root-object'",
		"ARRAY_TRANSFORM(path_edge, edge -> edge.graph_edge_id) AS path_edge_ids",
		"ARRAY_TRANSFORM(NODES(path), endpoint -> endpoint.graph_object_id) AS path_endpoint_ids",
		"root_endpoint_kind", "root_endpoint_id", "terminal_endpoint_kind", "terminal_endpoint_id",
		"path_edge_labels", "path_endpoint_ids", "cycle_detected", "selected_closure_profile",
		"visited_endpoint_keys", "gp.organization_id AS organization_id", "gp.graph_snapshot_id AS graph_snapshot_id",
		"'graph_object' AS endpoint_kind", "endpoint_id AS endpoint_id",
		"pk.visited_endpoint_keys[OFFSET(ARRAY_LENGTH(pk.visited_endpoint_keys)-1)] IN UNNEST(",
		"'active' AS snapshot_selector_mode", "'impact_result' AS result_shape",
	} {
		mustContain(t, current, want)
	}
	for _, forbidden := range []string{"WITH RECURSIVE", "JOIN closure", "edge_family='dependency'", "e.edge_label='depends_on'", "reciprocity_state='mirror_committed'", "e.graph_edge_id NOT IN UNNEST(c.path_edge_ids)"} {
		mustNotContain(t, current, forbidden)
	}

	historical := buildOODTraversalSQL(testOODReadTables(), "org-test", "root-object", "snapshot-history", dependencyClosureProfile, "closure_result", "depends_on", "load_bearing_for", 3, 7)
	mustContain(t, historical, "s.graph_snapshot_id = 'snapshot-history'")
	mustContain(t, historical, "o.status IN ('active','superseded','archived')")
	mustContain(t, historical, "e.status IN ('active','superseded','archived')")
	mustNotContain(t, historical, "TIMESTAMP_DIFF(CURRENT_TIMESTAMP()")
}

func traversalTestRow(terminal string, depth int64, edgeIDs, endpointIDs []string, profile, shape string, maxDepth, resultCap int) map[string]interface{} {
	label := "depends_on"
	if profile == loadBearingImpactProfile {
		label = "load_bearing_for"
	}
	edgeLabels := make([]string, len(edgeIDs))
	for i := range edgeLabels {
		edgeLabels[i] = label
	}
	cycle := false
	for _, endpointID := range endpointIDs[:len(endpointIDs)-1] {
		if endpointID == terminal {
			cycle = true
		}
	}
	return map[string]interface{}{
		"organization_id": "org", "graph_snapshot_id": "snapshot", "graph_version": int64(7),
		"snapshot_kind": "active_candidate", "snapshot_selector_mode": "active", "selected_snapshot_status": "active",
		"selected_snapshot_sealed_at": "2026-08-22T12:00:00Z", "traversal_time": "2026-08-22T12:00:00Z",
		"materialization_run_id": "run", "materialization_run_finished_at": "2026-08-22T12:00:00Z",
		"source_set_hash": strings.Repeat("a", 64), "result_shape": shape, "diagnostic_policy": "exclude_diagnostic_only",
		"root_endpoint_kind": "graph_object", "root_endpoint_id": "root",
		"terminal_endpoint_kind": "graph_object", "terminal_endpoint_id": terminal,
		"path_edge_ids": edgeIDs, "path_edge_labels": edgeLabels, "path_endpoint_ids": endpointIDs,
		"depth": depth, "cycle_detected": cycle, "selected_closure_profile": profile,
		"max_depth": int64(maxDepth), "result_cap": int64(resultCap),
		"graph_object_id": terminal, "object_class": "section",
	}
}

func TestShapeTraversalResultEmitsTypedEnvelopePathsCyclesAndCapEvidence(t *testing.T) {
	columns := []string{"organization_id", "graph_snapshot_id", "root_endpoint_id", "terminal_endpoint_id", "path_edge_ids", "path_edge_labels", "path_endpoint_ids", "depth", "cycle_detected"}
	raw := QueryResult{Columns: columns, Rows: []map[string]interface{}{
		traversalTestRow("root", 0, []string{}, []string{"root"}, dependencyClosureProfile, "closure_result", 4, 1),
		traversalTestRow("first", 1, []string{"edge-first"}, []string{"root", "first"}, dependencyClosureProfile, "closure_result", 4, 1),
		traversalTestRow("second", 1, []string{"edge-second"}, []string{"root", "second"}, dependencyClosureProfile, "closure_result", 4, 1),
	}}
	partial, err := shapeTraversalResult(raw, dependencyClosureProfile, "closure_result", 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	if partial.OrganizationID != "org" || partial.GraphSnapshotID != "snapshot" || partial.GraphVersion != 7 || partial.SnapshotKind != "active_candidate" || partial.SnapshotSelectorMode != "active" || partial.MaterializationRunID != "run" || partial.SourceSetHash != strings.Repeat("a", 64) || partial.SelectedClosureProfile != dependencyClosureProfile || partial.MaxDepth != 4 || partial.ResultCap != 1 || partial.CapState != "partial_due_to_cap" || partial.ResultCompleteness != "partial_due_to_cap" || partial.AuthoritativeClosureClaimAllowed || len(partial.Rows) != 1 {
		t.Fatalf("partial traversal result=%+v", partial)
	}
	d := partial.CapDiagnostics
	if d.CapKind != "result_cap" || d.RequestedMaxDepth != 4 || d.RequestedResultCap != 1 || d.ReturnedResultCount != 1 || d.SuppressedResultCountKnown || d.FirstSuppressedEndpointKind != "graph_object" || d.FirstSuppressedEndpointID != "second" || d.FirstSuppressedDepth != 1 {
		t.Fatalf("cap diagnostics=%+v", d)
	}
	row := partial.Rows[0]
	for _, required := range []string{"root_endpoint_kind", "root_endpoint_id", "terminal_endpoint_kind", "terminal_endpoint_id", "path_edge_ids", "path_edge_labels", "path_endpoint_ids", "depth", "cycle_detected", "selected_closure_profile", "max_depth", "result_cap", "cap_state", "cap_diagnostics", "authoritative_closure_claim_allowed", "result_completeness"} {
		if _, ok := row[required]; !ok {
			t.Fatalf("typed closure row omitted %q: %#v", required, row)
		}
	}

	depthRaw := QueryResult{Columns: columns, Rows: []map[string]interface{}{
		traversalTestRow("root", 0, []string{}, []string{"root"}, loadBearingImpactProfile, "impact_result", 1, 10),
		traversalTestRow("beyond", 2, []string{"edge-a", "edge-b"}, []string{"root", "middle", "beyond"}, loadBearingImpactProfile, "impact_result", 1, 10),
	}}
	depthPartial, err := shapeTraversalResult(depthRaw, loadBearingImpactProfile, "impact_result", 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if depthPartial.CapDiagnostics.CapKind != "max_depth" || depthPartial.AuthoritativeClosureClaimAllowed || depthPartial.CapDiagnostics.FirstSuppressedEndpointID != "beyond" || !depthPartial.CapDiagnostics.SuppressedResultCountKnown || depthPartial.CapDiagnostics.SuppressedResultCount != 1 {
		t.Fatalf("max-depth diagnostics=%+v", depthPartial)
	}

	completeRows := []map[string]interface{}{
		traversalTestRow("root", 0, []string{}, []string{"root"}, dependencyClosureProfile, "closure_result", 4, 3),
		traversalTestRow("first", 1, []string{"edge-first"}, []string{"root", "first"}, dependencyClosureProfile, "closure_result", 4, 3),
		traversalTestRow("root", 2, []string{"edge-first", "edge-cycle"}, []string{"root", "first", "root"}, dependencyClosureProfile, "closure_result", 4, 3),
	}
	complete, err := shapeTraversalResult(QueryResult{Columns: columns, Rows: completeRows}, dependencyClosureProfile, "closure_result", 4, 3)
	if err != nil || complete.CapState != "complete" || !complete.AuthoritativeClosureClaimAllowed || complete.ResultCompleteness != "complete" || len(complete.Rows) != 2 || complete.Rows[1]["cycle_detected"] != true {
		t.Fatalf("complete traversal=%+v err=%v", complete, err)
	}
	if complete.CapDiagnostics.CapKind != "max_depth_and_result_cap" || !complete.CapDiagnostics.SuppressedResultCountKnown || complete.CapDiagnostics.SuppressedResultCount != 0 {
		t.Fatalf("complete traversal cap diagnostics=%+v, want bounded-but-unsuppressed protocol shape", complete.CapDiagnostics)
	}
	if _, err := shapeTraversalResult(QueryResult{Columns: columns}, dependencyClosureProfile, "closure_result", 4, 3); err == nil || !strings.Contains(err.Error(), "root does not resolve") {
		t.Fatalf("missing root did not fail closed: %v", err)
	}
	malformed := traversalTestRow("root", 0, []string{}, []string{"root"}, dependencyClosureProfile, "closure_result", 4, 3)
	malformed["depth"] = "zero"
	if _, err := shapeTraversalResult(QueryResult{Columns: columns, Rows: []map[string]interface{}{malformed}}, dependencyClosureProfile, "closure_result", 4, 3); err == nil || !strings.Contains(err.Error(), "not a canonical non-negative integer") {
		t.Fatalf("untyped traversal depth did not fail closed: %v", err)
	}
	interiorCycle := traversalTestRow("terminal", 3, []string{"edge-a", "edge-cycle", "edge-b"}, []string{"root", "middle", "middle", "terminal"}, dependencyClosureProfile, "closure_result", 4, 3)
	if _, err := shapeTraversalResult(QueryResult{Columns: columns, Rows: []map[string]interface{}{
		traversalTestRow("root", 0, []string{}, []string{"root"}, dependencyClosureProfile, "closure_result", 4, 3),
		interiorCycle,
	}}, dependencyClosureProfile, "closure_result", 4, 3); err == nil || !strings.Contains(err.Error(), "repeats an endpoint before the terminal") {
		t.Fatalf("interior cycle escaped endpoint-visited suppression: %v", err)
	}
}

func TestSubstrateTableSelectsUniqueConfiguredOwnerNotFirstEntry(t *testing.T) {
	env := &Env{Config: SpecGraphConfig{Substrates: []SubstrateDescriptor{
		{ID: "volt", NodeTable: "Circuits"},
		{ID: "ood_graph", ObjectTable: "OODGraphObjects"},
	}}}
	got, err := substrateTable(env, func(s SubstrateDescriptor) string { return s.ObjectTable }, "object_table")
	if err != nil || got != "OODGraphObjects" {
		t.Fatalf("substrateTable()=%q, %v; want OODGraphObjects from non-first owner", got, err)
	}
}

func TestSubstrateTableRejectsAmbiguousOwners(t *testing.T) {
	env := &Env{Config: SpecGraphConfig{Substrates: []SubstrateDescriptor{
		{ID: "ood_a", ObjectTable: "OODGraphObjectsA"},
		{ID: "ood_b", ObjectTable: "OODGraphObjectsB"},
	}}}
	_, err := substrateTable(env, func(s SubstrateDescriptor) string { return s.ObjectTable }, "object_table")
	if err == nil || !strings.Contains(err.Error(), "ambiguously configured") {
		t.Fatalf("error=%v, want ambiguous owner refusal", err)
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("SQL missing expected substring %q\nfull SQL:\n%s", needle, haystack)
	}
}

func mustNotContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("SQL unexpectedly contains substring %q\nfull SQL:\n%s", needle, haystack)
	}
}
