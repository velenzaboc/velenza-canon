package main

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

// ood_reads.go declares typed read verbs against the OODGraph 7-table
// substrate. Replaces the legacy spec_graph_get/list/search/neighbors/
// closure/impact/history/diff/project handlers that queried schema_v1
// tables. All return QueryResult for consistency with spec_graph_query
// + spec_graph_list_runs/_violations/_snapshots.

// ---------------- inputs ----------------

type oodGetInput struct {
	GraphObjectID   string `json:"graph_object_id"`
	GraphSnapshotID string `json:"graph_snapshot_id,omitempty"`
}

type oodListInput struct {
	ObjectClass     string `json:"object_class,omitempty" jsonschema:"filter by closed-registry class (origin | axiom | section | symbol | ...)"`
	Status          string `json:"status,omitempty" jsonschema:"active | superseded | invalid | archived"`
	GraphSnapshotID string `json:"graph_snapshot_id,omitempty"`
	Limit           int    `json:"limit,omitempty"`
}

type oodSearchInput struct {
	Query           string `json:"query"`
	ObjectClass     string `json:"object_class,omitempty"`
	GraphSnapshotID string `json:"graph_snapshot_id,omitempty"`
	Limit           int    `json:"limit,omitempty"`
}

type oodNeighborsInput struct {
	GraphObjectID   string   `json:"graph_object_id"`
	GraphSnapshotID string   `json:"graph_snapshot_id,omitempty"`
	Direction       string   `json:"direction,omitempty" jsonschema:"out | in | both (default: both)"`
	EdgeLabels      []string `json:"edge_labels,omitempty"`
	Limit           int      `json:"limit,omitempty"`
}

type oodClosureInput struct {
	GraphObjectID   string `json:"graph_object_id"`
	GraphSnapshotID string `json:"graph_snapshot_id,omitempty"`
	ClosureProfile  string `json:"closure_profile" jsonschema:"must be dependency_closure_profile"`
	MaxDepth        int    `json:"max_depth"`
	ResultCap       int    `json:"result_cap"`
}

type oodImpactInput struct {
	GraphObjectID   string `json:"graph_object_id"`
	GraphSnapshotID string `json:"graph_snapshot_id,omitempty"`
	ClosureProfile  string `json:"closure_profile" jsonschema:"must be load_bearing_impact_profile"`
	MaxDepth        int    `json:"max_depth"`
	ResultCap       int    `json:"result_cap"`
}

type traversalCapDiagnostics struct {
	CapKind                     string `json:"cap_kind"`
	RequestedMaxDepth           int    `json:"requested_max_depth"`
	RequestedResultCap          int    `json:"requested_result_cap"`
	ReturnedResultCount         int    `json:"returned_result_count"`
	SuppressedResultCountKnown  bool   `json:"suppressed_result_count_known"`
	SuppressedResultCount       int    `json:"suppressed_result_count"`
	FirstSuppressedEndpointKind string `json:"first_suppressed_endpoint_kind"`
	FirstSuppressedEndpointID   string `json:"first_suppressed_endpoint_id"`
	FirstSuppressedDepth        int    `json:"first_suppressed_depth"`
}

type oodTraversalResult struct {
	OrganizationID                   string                   `json:"organization_id"`
	GraphSnapshotID                  string                   `json:"graph_snapshot_id"`
	GraphVersion                     int64                    `json:"graph_version"`
	SnapshotKind                     string                   `json:"snapshot_kind"`
	SnapshotSelectorMode             string                   `json:"snapshot_selector_mode"`
	SelectedSnapshotStatus           string                   `json:"selected_snapshot_status"`
	SelectedSnapshotSealedAt         string                   `json:"selected_snapshot_sealed_at"`
	TraversalTime                    string                   `json:"traversal_time"`
	MaterializationRunID             string                   `json:"materialization_run_id"`
	MaterializationRunFinishedAt     string                   `json:"materialization_run_finished_at"`
	SourceSetHash                    string                   `json:"source_set_hash"`
	ResultShape                      string                   `json:"result_shape"`
	DiagnosticPolicy                 string                   `json:"diagnostic_policy"`
	SelectedClosureProfile           string                   `json:"selected_closure_profile"`
	MaxDepth                         int                      `json:"max_depth"`
	ResultCap                        int                      `json:"result_cap"`
	CapState                         string                   `json:"cap_state"`
	CapDiagnostics                   traversalCapDiagnostics  `json:"cap_diagnostics"`
	AuthoritativeClosureClaimAllowed bool                     `json:"authoritative_closure_claim_allowed"`
	ResultCompleteness               string                   `json:"result_completeness"`
	Columns                          []string                 `json:"columns"`
	Rows                             []map[string]interface{} `json:"rows"`
}

const (
	dependencyClosureProfile = "dependency_closure_profile"
	loadBearingImpactProfile = "load_bearing_impact_profile"
)

type oodReadTables struct {
	Object   string
	Edge     string
	Snapshot string
	Run      string
	OwnerID  string
}

// resolveOODReadTables binds every table participating in a temporal read to
// one substrate. A query that joins tables owned by different adapters would
// either run against the wrong database or accidentally fall back to router
// order, so mixed ownership fails closed before any adapter is called.
func resolveOODReadTables(env *Env) (oodReadTables, error) {
	object, objectOwner, err := substrateTableAndOwner(env, func(s SubstrateDescriptor) string { return s.ObjectTable }, "object_table")
	if err != nil {
		return oodReadTables{}, err
	}
	edge, edgeOwner, err := substrateTableAndOwner(env, func(s SubstrateDescriptor) string { return s.GraphEdgeTable }, "graph_edge_table")
	if err != nil {
		return oodReadTables{}, err
	}
	snapshot, snapshotOwner, err := substrateTableAndOwner(env, func(s SubstrateDescriptor) string { return s.SnapshotTable }, "snapshot_table")
	if err != nil {
		return oodReadTables{}, err
	}
	run, runOwner, err := substrateTableAndOwner(env, func(s SubstrateDescriptor) string { return s.MaterializationRunTable }, "materialization_run_table")
	if err != nil {
		return oodReadTables{}, err
	}
	for field, owner := range map[string]string{
		"graph_edge_table":          edgeOwner,
		"snapshot_table":            snapshotOwner,
		"materialization_run_table": runOwner,
	} {
		if owner != objectOwner {
			return oodReadTables{}, fmt.Errorf("object_table substrate %q and %s substrate %q differ; temporal OODGraph reads require co-located tables", objectOwner, field, owner)
		}
	}
	return oodReadTables{Object: object, Edge: edge, Snapshot: snapshot, Run: run, OwnerID: objectOwner}, nil
}

func oodReadOrganizationID(ctx context.Context, env *Env) (string, error) {
	return resolveOrganizationID(ctx, env)
}

var externalSourceArtifactClassList = []string{
	"official_vendor_documentation",
	"official_product_documentation",
	"official_source_repository",
	"official_release_notes",
	"context7_documentation_package",
	"velenza_owned_documentation",
}

func qualifiedOODColumns(alias string) string {
	qualified := make([]string, len(oodListLeanColumns))
	for i, col := range oodListLeanColumns {
		qualified[i] = alias + "." + col
	}
	return strings.Join(qualified, ", ")
}

// selectedSnapshotCTE implements the §9 snapshot/run evidence fence. With no
// explicit snapshot id it derives the current active_candidate from the
// highest eligible organization-scoped graph_version. With an id it performs
// a historical selection and accepts the protocol's historical lifecycle
// states. Both paths reject unsealed, unfinished, mismatched, hash-forked, and
// pre-current-profile rows by producing no selected row. Legacy snapshots
// remain internal carry/audit inputs: their historical search columns can
// contain payload shapes forbidden by the current retrieval boundary and may
// not be surfaced by typed reads.
func selectedSnapshotCTE(snapshotTable, runTable, orgID, graphSnapshotID string) string {
	lifecycle := "s.status = 'active' AND s.snapshot_kind = 'active_candidate'"
	selector := ""
	order := " ORDER BY s.graph_version DESC, s.sealed_at DESC, s.graph_snapshot_id DESC"
	if graphSnapshotID != "" {
		lifecycle = "s.status IN ('active','superseded','archived')"
		selector = fmt.Sprintf(" AND s.graph_snapshot_id = '%s'", sqlEscape(graphSnapshotID))
		order = ""
	}
	return fmt.Sprintf(`WITH selected_snapshot AS (
  SELECT s.organization_id, s.graph_snapshot_id, s.graph_version, s.snapshot_kind,
         s.status AS selected_snapshot_status, s.sealed_at, s.materialization_run_id,
		 r.finished_at AS materialization_run_finished_at, s.source_set_hash, s.source_set
  FROM %s s
  JOIN %s r
    ON r.organization_id = s.organization_id
   AND r.materialization_run_id = s.materialization_run_id
   AND r.target_graph_snapshot_id = s.graph_snapshot_id
  WHERE s.organization_id = '%s'
    AND s.snapshot_state = 'sealed'
    AND %s
    AND s.sealed_at IS NOT NULL
    AND r.state = 'sealed'
    AND r.finished_at IS NOT NULL
    AND r.input_source_set_hash = s.source_set_hash
    AND JSON_VALUE(s.source_set, '$.materialization_profile_version') = '%s'%s%s
  LIMIT 1
)`, snapshotTable, runTable, sqlEscape(orgID), lifecycle, sqlEscape(MaterializationProfileVersion), selector, order)
}

func graphRowStatusPredicate(alias, graphSnapshotID string) string {
	if graphSnapshotID == "" {
		return alias + ".status = 'active'"
	}
	return alias + ".status IN ('active','superseded','archived')"
}

// currentExternalFreshnessPredicate excludes stale external-reference rows
// from current-context reads. Historical snapshot-pinned reads deliberately
// skip it: §9 historical replay consumes the freshness metadata sealed into
// that snapshot rather than reinterpreting it as current evidence.
func currentExternalFreshnessPredicate(alias string) string {
	quoted := make([]string, len(externalSourceArtifactClassList))
	for i, class := range externalSourceArtifactClassList {
		quoted[i] = "'" + class + "'"
	}
	retrieved := fmt.Sprintf(`(
	  SELECT MAX(SAFE_CAST(JSON_VALUE(receipt, '$.observed_at') AS TIMESTAMP))
  FROM UNNEST(IFNULL(JSON_QUERY_ARRAY(ss.source_set, '$.%s'), ARRAY<JSON>[])) AS receipt
	  WHERE JSON_VALUE(receipt, '$.object_class')=%s.object_class
    AND JSON_VALUE(receipt, '$.source_authority_id')=%s.source_authority_id
    AND JSON_VALUE(receipt, '$.verified_source_stable_reference')=%s.source_stable_reference
    AND JSON_VALUE(receipt, '$.final_version_coordinate')=%s.version_coordinate
	    AND JSON_VALUE(receipt, '$.source_content_hash')=%s.source_content_hash
)`, externalVerificationReceiptsSourceSetKey, alias, alias, alias, alias, alias)
	window := fmt.Sprintf("SAFE_CAST(JSON_VALUE(%s.search_payload, '$.graph_owned_parser_classification_tokens.freshness_window_seconds') AS INT64)", alias)
	return fmt.Sprintf("(%s.source_artifact_class NOT IN (%s) OR (%s IS NOT NULL AND %s > 0 AND TIMESTAMP_DIFF(CURRENT_TIMESTAMP(), %s, SECOND) BETWEEN -300 AND %s))",
		alias, strings.Join(quoted, ","), retrieved, window, retrieved, window)
}

// ---------------- handlers ----------------

// handleOODGet fetches one OODGraphObjects row by graph_object_id.
//
// Active-only contract: the typed read verb returns the active version row
// for the given graph_object_id. Superseded / invalid / archived version
// rows are intentionally invisible through this verb. Callers needing
// version-history access use spec_graph_history.
//
// This filter eliminates the R-Kernel_TypedReadReturnsNonLatest class of
// validator findings — without the active filter, _get would silently
// surface superseded prose to callers who think they're reading current
// state.
func handleOODGet(ctx context.Context, env *Env, in oodGetInput) (QueryResult, error) {
	if in.GraphObjectID == "" {
		return QueryResult{}, fmt.Errorf("graph_object_id required")
	}
	tables, err := resolveOODReadTables(env)
	if err != nil {
		return QueryResult{}, err
	}
	orgID, err := oodReadOrganizationID(ctx, env)
	if err != nil {
		return QueryResult{}, err
	}
	return handleQueryOnSubstrate(ctx, env, queryInput{SQL: buildOODGetSQL(tables, orgID, in.GraphObjectID, in.GraphSnapshotID)}, tables.OwnerID)
}

// buildOODGetSQL is the pure SQL builder for handleOODGet, extracted for
// unit testing of the active-only filter discipline without requiring a
// live Spanner backend.
//
// Lean-column projection (same set as buildOODListSQL): the embedding
// vector and the search_text duplicate are deliberately omitted. The
// embedding is Spanner-internal compute substrate — vector distance is
// computed server-side via APPROX_COSINE_DISTANCE in spec_graph_search,
// and the raw 3072-float vector has no consumer on the read path.
// Read verbs return DATA, not vector-storage internals; Spanner does
// the vector work.
func buildOODGetSQL(tables oodReadTables, orgID, graphObjectID, graphSnapshotID string) string {
	clauses := []string{
		fmt.Sprintf("o.organization_id = '%s'", sqlEscape(orgID)),
		fmt.Sprintf("o.graph_object_id = '%s'", sqlEscape(graphObjectID)),
		graphRowStatusPredicate("o", graphSnapshotID),
	}
	if graphSnapshotID == "" {
		clauses = append(clauses, currentExternalFreshnessPredicate("o"))
	}
	return fmt.Sprintf("%s\nSELECT %s FROM %s o JOIN selected_snapshot ss ON ss.graph_snapshot_id = o.graph_snapshot_id WHERE %s ORDER BY o.updated_at DESC LIMIT 1",
		selectedSnapshotCTE(tables.Snapshot, tables.Run, orgID, graphSnapshotID), qualifiedOODColumns("o"), tables.Object, strings.Join(clauses, " AND "))
}

// handleOODList lists OODGraphObjects rows with optional class / status /
// snapshot filters.
//
// Lean-column contract: this verb returns the "header" columns +
// search_payload (contract + payload). It deliberately EXCLUDES the
// 3072-float embedding vector (~25KB per row JSON-encoded) and the
// search_text duplicate. A consumer enumerating N rows for R-rule
// validation needs the kind, identity, and payload — never the
// embedding vector. Returning embedding by default made bulk
// enumeration (e.g. validating a 37-node concept_domain) burn ~1MB of
// context per page on data the rule checks never read.
//
// Callers who legitimately need the embedding fetch it row-by-row via
// spec_graph_get (which still returns SELECT *), or use
// spec_graph_search whose distance query needs the column server-side.
// This split keeps bulk enumeration cheap while preserving forensic
// access to the full row for targeted lookups.
func handleOODList(ctx context.Context, env *Env, in oodListInput) (QueryResult, error) {
	tables, err := resolveOODReadTables(env)
	if err != nil {
		return QueryResult{}, err
	}
	orgID, err := oodReadOrganizationID(ctx, env)
	if err != nil {
		return QueryResult{}, err
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 200
	}
	return handleQueryOnSubstrate(ctx, env, queryInput{SQL: buildOODListSQL(tables, orgID, in.ObjectClass, in.Status, in.GraphSnapshotID, limit)}, tables.OwnerID)
}

// oodListLeanColumns enumerates every column handleOODList returns,
// in the order the SQL projects them. Deliberately omits the
// `embedding` column (3072 float32 values, ~25KB JSON-encoded per
// row) and the `search_text` column (a near-duplicate of
// search_payload). See buildOODListSQL for the rationale.
var oodListLeanColumns = []string{
	"graph_object_id", "organization_id", "graph_snapshot_id", "object_class",
	"source_authority_id", "source_artifact_class", "source_ref_kind",
	"source_stable_reference", "version_coordinate", "section_path", "graph_address",
	"source_content_hash", "source_content_hash_owner", "materialization_run_id",
	"projection_role", "validation_state", "status", "visibility_scope", "search_payload",
	"embedding_model", "created_at", "updated_at",
}

// buildOODListSQL is the pure SQL builder for handleOODList, extracted
// for unit testing of the lean-column projection and the active-only
// filter discipline without requiring a live Spanner backend.
//
// The projection is explicit lean — every header field plus
// search_payload, but NOT embedding and NOT search_text. Bulk
// enumeration (37-node concept domains and larger) burns context
// budget that R-rule validators never need; callers wanting the full
// row use spec_graph_get on a specific id.
func buildOODListSQL(tables oodReadTables, orgID, objectClass, status, graphSnapshotID string, limit int) string {
	q := selectedSnapshotCTE(tables.Snapshot, tables.Run, orgID, graphSnapshotID) + "\nSELECT " + qualifiedOODColumns("o") + " FROM " + tables.Object + " o JOIN selected_snapshot ss ON ss.graph_snapshot_id = o.graph_snapshot_id WHERE o.organization_id = '" + sqlEscape(orgID) + "'"
	if objectClass != "" {
		q += fmt.Sprintf(" AND o.object_class = '%s'", sqlEscape(objectClass))
	}
	if status != "" {
		q += fmt.Sprintf(" AND o.status = '%s'", sqlEscape(status))
	} else {
		q += " AND " + graphRowStatusPredicate("o", graphSnapshotID)
	}
	if graphSnapshotID == "" {
		q += " AND " + currentExternalFreshnessPredicate("o")
	}
	q += " ORDER BY o.object_class, o.source_stable_reference"
	q += fmt.Sprintf(" LIMIT %d", limit)
	return q
}

// handleOODSearch runs APPROX_COSINE_DISTANCE against OODGraphObjects.embedding,
// embedding the caller's query string with the same gemini-embedding-001
// model used at admission time.
func handleOODSearch(ctx context.Context, env *Env, in oodSearchInput) (QueryResult, error) {
	if in.Query == "" {
		return QueryResult{}, fmt.Errorf("query required")
	}
	if env.Embed == nil {
		return QueryResult{}, fmt.Errorf("embedding not configured — spec_graph_search requires Config.Embedding")
	}
	tables, err := resolveOODReadTables(env)
	if err != nil {
		return QueryResult{}, err
	}
	orgID, err := oodReadOrganizationID(ctx, env)
	if err != nil {
		return QueryResult{}, err
	}
	vec, err := env.Embed.Embed(ctx, in.Query, vertexai.TaskTypeRetrievalQuery)
	if err != nil {
		return QueryResult{}, fmt.Errorf("embed query: %w", err)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 15
	}
	// Build the vector literal manually — Spanner Go client passes []float32
	// as a query param.
	q := selectedSnapshotCTE(tables.Snapshot, tables.Run, orgID, in.GraphSnapshotID) + "\n" + fmt.Sprintf(
		"SELECT graph_object_id, object_class, source_stable_reference, section_path, search_text, "+
			"APPROX_COSINE_DISTANCE(embedding, @v, options => JSON '{\"num_leaves_to_search\": 10}') AS distance "+
			"FROM %s o JOIN selected_snapshot ss ON ss.graph_snapshot_id = o.graph_snapshot_id WHERE o.organization_id = '%s' AND embedding IS NOT NULL AND %s",
		tables.Object, sqlEscape(orgID), graphRowStatusPredicate("o", in.GraphSnapshotID))
	if in.ObjectClass != "" {
		q += fmt.Sprintf(" AND o.object_class = '%s'", sqlEscape(in.ObjectClass))
	}
	if in.GraphSnapshotID == "" {
		q += " AND " + currentExternalFreshnessPredicate("o")
	}
	q += fmt.Sprintf(" ORDER BY distance LIMIT %d", limit)
	return handleQueryWithParams(ctx, env, tables.OwnerID, q, map[string]interface{}{"v": vec})
}

// handleOODNeighbors lists OODGraphEdges in/out of a graph_object_id with
// optional edge_label + direction filters.
//
// Active-only contract: the typed read verb returns edges that are both
// (a) themselves active and (b) connect two active endpoint nodes. An edge
// pointing at a superseded or archived target is invisible through this
// verb even if the edge row carries status='active', because consumers
// reading the verb expect to walk the active neighborhood.
//
// This endpoint-join filter eliminates the "active edges to superseded
// targets" class of R-Kernel_TypedReadReturnsNonLatest validator findings
// that surfaced across the C8 Tier B validators.
func handleOODNeighbors(ctx context.Context, env *Env, in oodNeighborsInput) (QueryResult, error) {
	if in.GraphObjectID == "" {
		return QueryResult{}, fmt.Errorf("graph_object_id required")
	}
	tables, err := resolveOODReadTables(env)
	if err != nil {
		return QueryResult{}, err
	}
	orgID, err := oodReadOrganizationID(ctx, env)
	if err != nil {
		return QueryResult{}, err
	}
	direction := in.Direction
	if direction == "" {
		direction = "both"
	}
	switch direction {
	case "out", "in", "both":
		// valid
	default:
		return QueryResult{}, fmt.Errorf("direction must be out | in | both (got %q)", direction)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 200
	}
	return handleQueryOnSubstrate(ctx, env, queryInput{SQL: buildOODNeighborsSQL(tables, orgID, in.GraphObjectID, in.GraphSnapshotID, direction, in.EdgeLabels, limit)}, tables.OwnerID)
}

// buildOODNeighborsSQL is the pure SQL builder for handleOODNeighbors,
// extracted for unit testing of the active-endpoint-join discipline
// without requiring a live Spanner backend. Callers MUST pass a validated
// direction ("out" | "in" | "both") and a positive limit; the handler
// enforces both.
func buildOODNeighborsSQL(tables oodReadTables, orgID, graphObjectID, graphSnapshotID, direction string, edgeLabels []string, limit int) string {
	var clauses []string
	switch direction {
	case "out":
		clauses = append(clauses, fmt.Sprintf("e.source_endpoint_id = '%s'", sqlEscape(graphObjectID)))
	case "in":
		clauses = append(clauses, fmt.Sprintf("e.target_endpoint_id = '%s'", sqlEscape(graphObjectID)))
	case "both":
		clauses = append(clauses, fmt.Sprintf("(e.source_endpoint_id = '%s' OR e.target_endpoint_id = '%s')",
			sqlEscape(graphObjectID), sqlEscape(graphObjectID)))
	}
	clauses = append(clauses, fmt.Sprintf("e.organization_id = '%s'", sqlEscape(orgID)))
	clauses = append(clauses, graphRowStatusPredicate("e", graphSnapshotID))
	// Endpoint-active filter: both source and target must resolve to an
	// active object row. EXISTS short-circuits on the first active match
	// per graph_object_id, so multi-version-row tables are handled
	// correctly without producing duplicate edge rows in the result.
	endpointStatus := graphRowStatusPredicate("src", graphSnapshotID)
	endpointFreshness := ""
	if graphSnapshotID == "" {
		endpointFreshness = " AND " + currentExternalFreshnessPredicate("src")
	}
	clauses = append(clauses, fmt.Sprintf(
		"EXISTS (SELECT 1 FROM %s src WHERE src.organization_id = e.organization_id AND src.graph_snapshot_id = e.graph_snapshot_id AND src.graph_object_id = e.source_endpoint_id AND %s%s)", tables.Object, endpointStatus, endpointFreshness))
	endpointStatus = graphRowStatusPredicate("tgt", graphSnapshotID)
	endpointFreshness = ""
	if graphSnapshotID == "" {
		endpointFreshness = " AND " + currentExternalFreshnessPredicate("tgt")
	}
	clauses = append(clauses, fmt.Sprintf(
		"EXISTS (SELECT 1 FROM %s tgt WHERE tgt.organization_id = e.organization_id AND tgt.graph_snapshot_id = e.graph_snapshot_id AND tgt.graph_object_id = e.target_endpoint_id AND %s%s)", tables.Object, endpointStatus, endpointFreshness))
	if len(edgeLabels) > 0 {
		quoted := make([]string, 0, len(edgeLabels))
		for _, l := range edgeLabels {
			quoted = append(quoted, "'"+sqlEscape(l)+"'")
		}
		clauses = append(clauses, "e.edge_label IN ("+strings.Join(quoted, ",")+")")
	}
	return fmt.Sprintf(
		"%s\nSELECT e.graph_edge_id, e.edge_label, e.edge_family, e.source_endpoint_id, e.target_endpoint_id, e.reciprocity_state, e.inverse_edge_id FROM %s e JOIN selected_snapshot ss ON ss.graph_snapshot_id = e.graph_snapshot_id WHERE %s ORDER BY e.edge_label LIMIT %d",
		selectedSnapshotCTE(tables.Snapshot, tables.Run, orgID, graphSnapshotID), tables.Edge, strings.Join(clauses, " AND "), limit)
}

// handleOODClosure runs forward transitive closure from a graph_object_id
// over the closed dependency_closure_profile. The path walk is owned by the
// canonical OODGraph GRAPH_TABLE projection and is bounded by max_depth +
// result_cap.
func handleOODClosure(ctx context.Context, env *Env, in oodClosureInput) (oodTraversalResult, error) {
	return runClosure(ctx, env, in.GraphObjectID, in.GraphSnapshotID, in.ClosureProfile, in.MaxDepth, in.ResultCap, "forward")
}

// handleOODImpact runs reverse transitive closure (impact / blast radius)
// from a graph_object_id over the closed load_bearing_impact_profile.
func handleOODImpact(ctx context.Context, env *Env, in oodImpactInput) (oodTraversalResult, error) {
	return runClosure(ctx, env, in.GraphObjectID, in.GraphSnapshotID, in.ClosureProfile, in.MaxDepth, in.ResultCap, "reverse")
}

func runClosure(ctx context.Context, env *Env, rootID, graphSnapshotID, profile string, maxDepth, resultCap int, direction string) (oodTraversalResult, error) {
	if rootID == "" {
		return oodTraversalResult{}, fmt.Errorf("graph_object_id required")
	}
	if maxDepth < 0 {
		return oodTraversalResult{}, fmt.Errorf("max_depth must be >= 0")
	}
	// The GRAPH_TABLE walk is bounded in the query and in the shaped result.
	// Thirty-two graph hops is already far beyond the intended dependency and
	// impact audit surface and prevents a caller from manufacturing an
	// unbounded query.
	if maxDepth > 32 {
		return oodTraversalResult{}, fmt.Errorf("max_depth must be <= 32 (got %d)", maxDepth)
	}
	if resultCap <= 0 {
		return oodTraversalResult{}, fmt.Errorf("result_cap must be >= 1")
	}
	maxInt := int(^uint(0) >> 1)
	if maxDepth == maxInt || resultCap > maxInt-2 {
		return oodTraversalResult{}, fmt.Errorf("max_depth or result_cap exceeds the process-safe integer boundary")
	}
	edgeLabel, inverseLabel, resultShape, err := resolveTypedTraversalProfile(profile, direction)
	if err != nil {
		return oodTraversalResult{}, err
	}
	tables, err := resolveOODReadTables(env)
	if err != nil {
		return oodTraversalResult{}, err
	}
	orgID, err := oodReadOrganizationID(ctx, env)
	if err != nil {
		return oodTraversalResult{}, err
	}
	q := buildOODTraversalSQL(tables, orgID, rootID, graphSnapshotID, profile, resultShape, edgeLabel, inverseLabel, maxDepth, resultCap)
	raw, err := handleQueryOnSubstrate(ctx, env, queryInput{SQL: q}, tables.OwnerID)
	if err != nil {
		return oodTraversalResult{}, err
	}
	return shapeTraversalResult(raw, profile, resultShape, maxDepth, resultCap)
}

func resolveTypedTraversalProfile(profile, direction string) (edgeLabel, inverseLabel, resultShape string, err error) {
	switch direction {
	case "forward":
		if profile != dependencyClosureProfile {
			return "", "", "", fmt.Errorf("closure_profile %q invalid for closure: the closed v1 profile is %q", profile, dependencyClosureProfile)
		}
		return "depends_on", "load_bearing_for", "closure_result", nil
	case "reverse":
		if profile != loadBearingImpactProfile {
			return "", "", "", fmt.Errorf("closure_profile %q invalid for impact: the closed v1 profile is %q", profile, loadBearingImpactProfile)
		}
		return "load_bearing_for", "depends_on", "impact_result", nil
	default:
		return "", "", "", fmt.Errorf("traversal direction %q invalid", direction)
	}
}

func buildOODTraversalSQL(tables oodReadTables, orgID, rootID, graphSnapshotID, profile, resultShape, edgeLabel, inverseLabel string, maxDepth, resultCap int) string {
	freshness := ""
	if graphSnapshotID == "" {
		freshness = " AND " + currentExternalFreshnessPredicate("o")
	}
	objectStatus := graphRowStatusPredicate("o", graphSnapshotID)
	edgeStatus := graphRowStatusPredicate("e", graphSnapshotID)
	inverseStatus := graphRowStatusPredicate("inv", graphSnapshotID)
	selector := selectedSnapshotCTE(tables.Snapshot, tables.Run, orgID, graphSnapshotID)
	// root depth 0 is returned as an internal evidence row so an empty closure
	// can still prove the selected snapshot and eligible root. The handler
	// removes it from public members.
	selectorMode := "active"
	if graphSnapshotID != "" {
		selectorMode = "graph_snapshot_id"
	}
	return fmt.Sprintf(`%s,
eligible_objects AS (
  SELECT o.organization_id, o.graph_snapshot_id, o.graph_object_id, o.object_class, o.source_stable_reference, o.section_path
  FROM %s o JOIN selected_snapshot ss ON ss.graph_snapshot_id=o.graph_snapshot_id
  WHERE o.organization_id='%s' AND %s AND o.validation_state='valid'%s
),
eligible_edges AS (
  SELECT e.*
  FROM %s e
  JOIN selected_snapshot ss ON ss.graph_snapshot_id=e.graph_snapshot_id
  JOIN eligible_objects src ON src.graph_snapshot_id=e.graph_snapshot_id AND src.graph_object_id=e.source_endpoint_id
  JOIN eligible_objects tgt ON tgt.graph_snapshot_id=e.graph_snapshot_id AND tgt.graph_object_id=e.target_endpoint_id
  WHERE e.organization_id='%s' AND %s AND e.validation_state='valid' AND e.edge_label='%s'
    AND e.diagnostic_only=FALSE AND e.reciprocity_state='complete' AND e.inverse_edge_id IS NOT NULL
    AND (e.valid_from IS NULL OR e.valid_from <= ss.sealed_at)
    AND (e.valid_until IS NULL OR e.valid_until > ss.sealed_at)
    AND EXISTS (
      SELECT 1 FROM %s inv
      WHERE inv.organization_id=e.organization_id AND inv.graph_snapshot_id=e.graph_snapshot_id
        AND inv.graph_edge_id=e.inverse_edge_id AND inv.inverse_edge_id=e.graph_edge_id
        AND inv.edge_label='%s' AND %s AND inv.validation_state='valid' AND inv.diagnostic_only=FALSE
        AND inv.reciprocity_state='complete'
        AND inv.source_endpoint_id=e.target_endpoint_id AND inv.target_endpoint_id=e.source_endpoint_id
        AND (inv.valid_from IS NULL OR inv.valid_from <= ss.sealed_at)
        AND (inv.valid_until IS NULL OR inv.valid_until > ss.sealed_at)
    )
),
graph_paths AS (
  SELECT *
  FROM GRAPH_TABLE (
    OODGraph
    MATCH path = WALK
      (root)-[path_edge WHERE path_edge.edge_label='%s']->{0,%d}(terminal)
    WHERE root.organization_id='%s' AND root.graph_object_id='%s'
    RETURN root.organization_id AS organization_id,
           root.graph_snapshot_id AS graph_snapshot_id,
           root.graph_object_id AS root_endpoint_id,
           terminal.graph_object_id AS terminal_endpoint_id,
           ARRAY_TRANSFORM(path_edge, edge -> edge.graph_edge_id) AS path_edge_ids,
           ARRAY_TRANSFORM(path_edge, edge -> edge.edge_label) AS path_edge_labels,
           ARRAY_TRANSFORM(NODES(path), endpoint -> endpoint.graph_object_id) AS path_endpoint_ids,
           ARRAY_LENGTH(path_edge) AS depth
  )
),
path_keys AS (
  SELECT gp.*,
         ARRAY(
           SELECT AS STRUCT gp.organization_id AS organization_id,
                            gp.graph_snapshot_id AS graph_snapshot_id,
                            'graph_object' AS endpoint_kind,
                            endpoint_id AS endpoint_id
           FROM UNNEST(gp.path_endpoint_ids) AS endpoint_id WITH OFFSET AS endpoint_offset
           ORDER BY endpoint_offset
         ) AS visited_endpoint_keys
  FROM graph_paths gp
  JOIN selected_snapshot ss ON ss.graph_snapshot_id=gp.graph_snapshot_id
  WHERE gp.organization_id=ss.organization_id
    AND ARRAY_LENGTH(gp.path_edge_ids)=gp.depth
    AND ARRAY_LENGTH(gp.path_edge_labels)=gp.depth
    AND ARRAY_LENGTH(gp.path_endpoint_ids)=gp.depth+1
    AND NOT EXISTS (
      SELECT 1 FROM UNNEST(gp.path_endpoint_ids) AS endpoint_id
      WHERE NOT EXISTS (
        SELECT 1 FROM eligible_objects object_endpoint
        WHERE object_endpoint.graph_snapshot_id=gp.graph_snapshot_id
          AND object_endpoint.graph_object_id=endpoint_id
      )
    )
    AND NOT EXISTS (
      SELECT 1 FROM UNNEST(gp.path_edge_ids) AS path_edge_id
      WHERE NOT EXISTS (
        SELECT 1 FROM eligible_edges eligible_edge
        WHERE eligible_edge.graph_snapshot_id=gp.graph_snapshot_id
          AND eligible_edge.graph_edge_id=path_edge_id
      )
    )
),
path_evidence AS (
  SELECT pk.*,
         pk.visited_endpoint_keys[OFFSET(ARRAY_LENGTH(pk.visited_endpoint_keys)-1)] IN UNNEST(
           ARRAY(
             SELECT AS STRUCT endpoint_key.organization_id AS organization_id,
                              endpoint_key.graph_snapshot_id AS graph_snapshot_id,
                              endpoint_key.endpoint_kind AS endpoint_kind,
                              endpoint_key.endpoint_id AS endpoint_id
             FROM UNNEST(pk.visited_endpoint_keys) AS endpoint_key WITH OFFSET AS endpoint_offset
             WHERE endpoint_offset < ARRAY_LENGTH(pk.visited_endpoint_keys)-1
             ORDER BY endpoint_offset
           )
         ) AS cycle_detected
  FROM path_keys pk
  WHERE NOT EXISTS (
    SELECT 1
    FROM UNNEST(pk.visited_endpoint_keys) AS endpoint_key WITH OFFSET AS endpoint_offset
    WHERE endpoint_offset < ARRAY_LENGTH(pk.visited_endpoint_keys)-1
    GROUP BY endpoint_key.organization_id, endpoint_key.graph_snapshot_id,
             endpoint_key.endpoint_kind, endpoint_key.endpoint_id
    HAVING COUNT(*) > 1
  )
),
ranked AS (
  SELECT path_evidence.*,
         ROW_NUMBER() OVER (
           PARTITION BY terminal_endpoint_id, organization_id, graph_snapshot_id, cycle_detected
           ORDER BY depth, TO_JSON_STRING(path_edge_ids), TO_JSON_STRING(path_endpoint_ids)
         ) AS path_rank
  FROM path_evidence
)
SELECT ss.organization_id, r.graph_snapshot_id, ss.graph_version, ss.snapshot_kind,
       '%s' AS snapshot_selector_mode, ss.selected_snapshot_status,
       ss.sealed_at AS selected_snapshot_sealed_at, ss.sealed_at AS traversal_time,
       ss.materialization_run_id, ss.materialization_run_finished_at, ss.source_set_hash,
       '%s' AS result_shape, 'exclude_diagnostic_only' AS diagnostic_policy,
       'graph_object' AS root_endpoint_kind, '%s' AS root_endpoint_id,
       'graph_object' AS terminal_endpoint_kind, r.terminal_endpoint_id,
       r.path_edge_ids, r.path_edge_labels, r.path_endpoint_ids, r.depth, r.cycle_detected,
       '%s' AS selected_closure_profile, %d AS max_depth, %d AS result_cap,
       o.graph_object_id, o.object_class, o.source_stable_reference, o.section_path
FROM ranked r JOIN eligible_objects o
  ON o.graph_snapshot_id=r.graph_snapshot_id AND o.graph_object_id=r.terminal_endpoint_id
JOIN selected_snapshot ss ON ss.graph_snapshot_id=r.graph_snapshot_id
WHERE r.path_rank=1
ORDER BY r.depth, TO_JSON_STRING(r.path_edge_ids), 'graph_object', r.terminal_endpoint_id,
         r.path_edge_ids[SAFE_OFFSET(ARRAY_LENGTH(r.path_edge_ids)-1)]
LIMIT %d`, selector, tables.Object, sqlEscape(orgID), objectStatus, freshness,
		tables.Edge, sqlEscape(orgID), edgeStatus, sqlEscape(edgeLabel), tables.Edge, sqlEscape(inverseLabel), inverseStatus,
		sqlEscape(edgeLabel), maxDepth+1, sqlEscape(orgID), sqlEscape(rootID),
		sqlEscape(selectorMode), sqlEscape(resultShape), sqlEscape(rootID),
		sqlEscape(profile), maxDepth, resultCap, resultCap+2)
}

func shapeTraversalResult(raw QueryResult, profile, resultShape string, maxDepth, resultCap int) (oodTraversalResult, error) {
	out := oodTraversalResult{
		SelectedClosureProfile: profile, ResultShape: resultShape, DiagnosticPolicy: "exclude_diagnostic_only",
		MaxDepth: maxDepth, ResultCap: resultCap, CapState: "complete",
		AuthoritativeClosureClaimAllowed: true, ResultCompleteness: "complete",
		Columns: appendTraversalDerivedColumns(raw.Columns),
		CapDiagnostics: traversalCapDiagnostics{
			// Both bounds are mandatory inputs even when neither truncates the
			// result. cap_state=complete and zero suppressed rows distinguish
			// this from the partial_due_to_cap trigger cases below while keeping
			// cap_kind inside the protocol's closed non-empty value set.
			CapKind:           "max_depth_and_result_cap",
			RequestedMaxDepth: maxDepth, RequestedResultCap: resultCap,
			SuppressedResultCountKnown: true,
		},
	}
	var firstSuppressed map[string]interface{}
	depthSuppressed, resultSuppressed := false, false
	suppressedCount := 0
	rootSeen := false
	var selected traversalResultEnvelope
	for _, row := range raw.Rows {
		envelope, err := traversalEnvelopeFromRow(row, resultShape)
		if err != nil {
			return oodTraversalResult{}, err
		}
		if selected.GraphSnapshotID == "" {
			selected = envelope
		} else if envelope != selected {
			return oodTraversalResult{}, fmt.Errorf("traversal rows cross common-envelope or selected-snapshot boundaries")
		}
		depth, err := validateTraversalPathRow(row, profile, maxDepth, resultCap)
		if err != nil {
			return oodTraversalResult{}, err
		}
		if depth == 0 {
			if rootSeen {
				return oodTraversalResult{}, fmt.Errorf("closure returned more than one depth-zero root evidence row")
			}
			rootSeen = true
			continue
		}
		if depth > maxDepth {
			depthSuppressed = true
			suppressedCount++
			if firstSuppressed == nil {
				firstSuppressed = row
			}
			continue
		}
		if len(out.Rows) >= resultCap {
			resultSuppressed = true
			suppressedCount++
			if firstSuppressed == nil {
				firstSuppressed = row
			}
			continue
		}
		out.Rows = append(out.Rows, row)
	}
	// Apply the envelope before checking GraphSnapshotID so a valid root can
	// prove every common-envelope member in one operation.
	applyTraversalEnvelope(&out, selected)
	if !rootSeen || out.GraphSnapshotID == "" {
		return oodTraversalResult{}, fmt.Errorf("closure root does not resolve as an active, fresh object inside one eligible sealed snapshot")
	}
	out.CapDiagnostics.ReturnedResultCount = len(out.Rows)
	if depthSuppressed || resultSuppressed {
		out.CapState = "partial_due_to_cap"
		out.ResultCompleteness = "partial_due_to_cap"
		out.AuthoritativeClosureClaimAllowed = false
		// The SQL asks for root + result_cap + one evidence row. If fewer
		// rows returned, the result set was exhausted and the exact number
		// suppressed is known. At the limit, the count is an observed lower
		// bound and the explicit false flag prevents it being treated as exact.
		out.CapDiagnostics.SuppressedResultCount = suppressedCount
		out.CapDiagnostics.SuppressedResultCountKnown = len(raw.Rows) < resultCap+2
		switch {
		case depthSuppressed && resultSuppressed:
			out.CapDiagnostics.CapKind = "max_depth_and_result_cap"
		case depthSuppressed:
			out.CapDiagnostics.CapKind = "max_depth"
		default:
			out.CapDiagnostics.CapKind = "result_cap"
		}
		if firstSuppressed != nil {
			out.CapDiagnostics.FirstSuppressedEndpointKind = "graph_object"
			out.CapDiagnostics.FirstSuppressedEndpointID = asString(firstSuppressed["terminal_endpoint_id"])
			depth, err := traversalDepth(firstSuppressed["depth"])
			if err != nil {
				return oodTraversalResult{}, err
			}
			out.CapDiagnostics.FirstSuppressedDepth = depth
		}
	}
	for _, row := range out.Rows {
		row["cap_state"] = out.CapState
		row["cap_diagnostics"] = out.CapDiagnostics
		row["authoritative_closure_claim_allowed"] = out.AuthoritativeClosureClaimAllowed
		row["result_completeness"] = out.ResultCompleteness
	}
	return out, nil
}

func appendTraversalDerivedColumns(columns []string) []string {
	out := append([]string(nil), columns...)
	seen := make(map[string]bool, len(out))
	for _, column := range out {
		seen[column] = true
	}
	for _, column := range []string{"cap_state", "cap_diagnostics", "authoritative_closure_claim_allowed", "result_completeness"} {
		if !seen[column] {
			out = append(out, column)
		}
	}
	return out
}

type traversalResultEnvelope struct {
	OrganizationID               string
	GraphSnapshotID              string
	GraphVersion                 int64
	SnapshotKind                 string
	SnapshotSelectorMode         string
	SelectedSnapshotStatus       string
	SelectedSnapshotSealedAt     string
	TraversalTime                string
	MaterializationRunID         string
	MaterializationRunFinishedAt string
	SourceSetHash                string
	ResultShape                  string
	DiagnosticPolicy             string
}

func traversalEnvelopeFromRow(row map[string]interface{}, expectedResultShape string) (traversalResultEnvelope, error) {
	graphVersion, ok := traversalInt64(row["graph_version"])
	if !ok || graphVersion < 1 {
		return traversalResultEnvelope{}, fmt.Errorf("traversal common envelope graph_version is not a positive integer")
	}
	envelope := traversalResultEnvelope{
		OrganizationID:               asString(row["organization_id"]),
		GraphSnapshotID:              asString(row["graph_snapshot_id"]),
		GraphVersion:                 graphVersion,
		SnapshotKind:                 asString(row["snapshot_kind"]),
		SnapshotSelectorMode:         asString(row["snapshot_selector_mode"]),
		SelectedSnapshotStatus:       asString(row["selected_snapshot_status"]),
		SelectedSnapshotSealedAt:     asString(row["selected_snapshot_sealed_at"]),
		TraversalTime:                asString(row["traversal_time"]),
		MaterializationRunID:         asString(row["materialization_run_id"]),
		MaterializationRunFinishedAt: asString(row["materialization_run_finished_at"]),
		SourceSetHash:                asString(row["source_set_hash"]),
		ResultShape:                  asString(row["result_shape"]),
		DiagnosticPolicy:             asString(row["diagnostic_policy"]),
	}
	for name, value := range map[string]string{
		"organization_id": envelope.OrganizationID, "graph_snapshot_id": envelope.GraphSnapshotID,
		"snapshot_kind": envelope.SnapshotKind, "selected_snapshot_status": envelope.SelectedSnapshotStatus,
		"selected_snapshot_sealed_at": envelope.SelectedSnapshotSealedAt, "traversal_time": envelope.TraversalTime,
		"materialization_run_id": envelope.MaterializationRunID, "materialization_run_finished_at": envelope.MaterializationRunFinishedAt,
		"source_set_hash": envelope.SourceSetHash, "result_shape": envelope.ResultShape, "diagnostic_policy": envelope.DiagnosticPolicy,
	} {
		if value == "" {
			return traversalResultEnvelope{}, fmt.Errorf("traversal common envelope %s required", name)
		}
	}
	if envelope.SnapshotSelectorMode != "active" && envelope.SnapshotSelectorMode != "graph_snapshot_id" {
		return traversalResultEnvelope{}, fmt.Errorf("traversal common envelope snapshot_selector_mode %q invalid", envelope.SnapshotSelectorMode)
	}
	if envelope.SnapshotSelectorMode == "active" && envelope.SelectedSnapshotStatus != "active" {
		return traversalResultEnvelope{}, fmt.Errorf("active traversal selected non-active snapshot status %q", envelope.SelectedSnapshotStatus)
	}
	if envelope.SnapshotSelectorMode == "graph_snapshot_id" && envelope.SelectedSnapshotStatus != "active" && envelope.SelectedSnapshotStatus != "superseded" && envelope.SelectedSnapshotStatus != "archived" {
		return traversalResultEnvelope{}, fmt.Errorf("historical traversal selected ineligible snapshot status %q", envelope.SelectedSnapshotStatus)
	}
	if err := validateExternalContentHash("sha256", envelope.SourceSetHash); err != nil {
		return traversalResultEnvelope{}, fmt.Errorf("traversal common envelope source_set_hash: %w", err)
	}
	if envelope.TraversalTime != envelope.SelectedSnapshotSealedAt {
		return traversalResultEnvelope{}, fmt.Errorf("default traversal_time does not equal selected snapshot sealed_at")
	}
	if envelope.ResultShape != expectedResultShape || envelope.DiagnosticPolicy != "exclude_diagnostic_only" {
		return traversalResultEnvelope{}, fmt.Errorf("traversal common envelope result_shape or diagnostic_policy does not match the typed request")
	}
	return envelope, nil
}

func applyTraversalEnvelope(out *oodTraversalResult, envelope traversalResultEnvelope) {
	if out == nil {
		return
	}
	out.OrganizationID = envelope.OrganizationID
	out.GraphSnapshotID = envelope.GraphSnapshotID
	out.GraphVersion = envelope.GraphVersion
	out.SnapshotKind = envelope.SnapshotKind
	out.SnapshotSelectorMode = envelope.SnapshotSelectorMode
	out.SelectedSnapshotStatus = envelope.SelectedSnapshotStatus
	out.SelectedSnapshotSealedAt = envelope.SelectedSnapshotSealedAt
	out.TraversalTime = envelope.TraversalTime
	out.MaterializationRunID = envelope.MaterializationRunID
	out.MaterializationRunFinishedAt = envelope.MaterializationRunFinishedAt
	out.SourceSetHash = envelope.SourceSetHash
	out.ResultShape = envelope.ResultShape
	out.DiagnosticPolicy = envelope.DiagnosticPolicy
}

func validateTraversalPathRow(row map[string]interface{}, profile string, maxDepth, resultCap int) (int, error) {
	depth, err := traversalDepth(row["depth"])
	if err != nil {
		return 0, err
	}
	rootKind, rootID := asString(row["root_endpoint_kind"]), asString(row["root_endpoint_id"])
	terminalKind, terminalID := asString(row["terminal_endpoint_kind"]), asString(row["terminal_endpoint_id"])
	if rootKind != "graph_object" || terminalKind != "graph_object" || rootID == "" || terminalID == "" {
		return 0, fmt.Errorf("traversal path row requires graph_object root and terminal endpoints")
	}
	edgeIDs, err := traversalStringArray(row["path_edge_ids"], "path_edge_ids")
	if err != nil {
		return 0, err
	}
	edgeLabels, err := traversalStringArray(row["path_edge_labels"], "path_edge_labels")
	if err != nil {
		return 0, err
	}
	endpointIDs, err := traversalStringArray(row["path_endpoint_ids"], "path_endpoint_ids")
	if err != nil {
		return 0, err
	}
	if len(edgeIDs) != depth || len(edgeLabels) != depth || len(endpointIDs) != depth+1 || endpointIDs[0] != rootID || endpointIDs[len(endpointIDs)-1] != terminalID {
		return 0, fmt.Errorf("traversal path arrays do not match depth/root/terminal evidence")
	}
	wantLabel := "depends_on"
	if profile == loadBearingImpactProfile {
		wantLabel = "load_bearing_for"
	}
	for i := range edgeIDs {
		if edgeIDs[i] == "" || edgeLabels[i] != wantLabel {
			return 0, fmt.Errorf("traversal path edge[%d] does not match selected closure profile", i)
		}
	}
	cycle, ok := row["cycle_detected"].(bool)
	if !ok {
		return 0, fmt.Errorf("traversal cycle_detected has unexpected type %T", row["cycle_detected"])
	}
	repeatedTerminal := false
	visited := make(map[string]bool, len(endpointIDs))
	for index, endpointID := range endpointIDs {
		if visited[endpointID] {
			if index != len(endpointIDs)-1 {
				return 0, fmt.Errorf("traversal path repeats an endpoint before the terminal cycle evidence row")
			}
			repeatedTerminal = true
		}
		visited[endpointID] = true
	}
	if cycle != repeatedTerminal {
		return 0, fmt.Errorf("traversal cycle_detected does not match endpoint-visited path evidence")
	}
	selectedDepth, ok := traversalInt64(row["max_depth"])
	if !ok || selectedDepth != int64(maxDepth) {
		return 0, fmt.Errorf("traversal path max_depth does not match typed request")
	}
	selectedCap, ok := traversalInt64(row["result_cap"])
	if !ok || selectedCap != int64(resultCap) {
		return 0, fmt.Errorf("traversal path result_cap does not match typed request")
	}
	if asString(row["selected_closure_profile"]) != profile {
		return 0, fmt.Errorf("traversal path selected_closure_profile does not match typed request")
	}
	return depth, nil
}

func traversalStringArray(value interface{}, field string) ([]string, error) {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...), nil
	case []interface{}:
		out := make([]string, len(values))
		for i, value := range values {
			out[i] = asString(value)
			if out[i] == "" {
				return nil, fmt.Errorf("traversal %s[%d] must be a non-empty string", field, i)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("traversal %s has unexpected type %T", field, value)
	}
}

func traversalDepth(v interface{}) (int, error) {
	switch n := v.(type) {
	case int64:
		if n < 0 || int64(int(n)) != n {
			return 0, fmt.Errorf("traversal depth %d is outside the non-negative int range", n)
		}
		return int(n), nil
	case int:
		if n < 0 {
			return 0, fmt.Errorf("traversal depth %d is negative", n)
		}
		return n, nil
	case float64:
		if n < 0 || n != math.Trunc(n) || n > float64(int(^uint(0)>>1)) {
			return 0, fmt.Errorf("traversal depth %v is not a non-negative integer", n)
		}
		return int(n), nil
	case string:
		parsed, err := strconv.ParseInt(n, 10, 64)
		if err != nil || strconv.FormatInt(parsed, 10) != n || parsed < 0 || int64(int(parsed)) != parsed {
			return 0, fmt.Errorf("traversal depth %q is not a canonical non-negative integer", n)
		}
		return int(parsed), nil
	default:
		return 0, fmt.Errorf("traversal depth has unexpected type %T", v)
	}
}

func traversalInt64(value interface{}) (int64, bool) {
	if parsed, ok := numericInt64(value); ok {
		return parsed, true
	}
	text, ok := value.(string)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil || strconv.FormatInt(parsed, 10) != text {
		return 0, false
	}
	return parsed, true
}

// handleQueryWithParams is a tiny helper because handleQuery's input
// type is awkward to pass through here (Params is map[string]interface{}).
func handleQueryWithParams(ctx context.Context, env *Env, substrateID, sql string, params map[string]interface{}) (QueryResult, error) {
	return handleQueryOnSubstrate(ctx, env, queryInput{SQL: sql, Params: params}, substrateID)
}
