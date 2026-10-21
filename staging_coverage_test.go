package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"cloud.google.com/go/spanner"
)

type stagingQueryAdapter struct {
	*fakeAdapter
	sql    string
	params map[string]interface{}
	result QueryResult
	err    error
}

func (a *stagingQueryAdapter) ExecuteReadOnlyQuery(_ context.Context, sql string, params map[string]interface{}) (QueryResult, error) {
	a.sql, a.params = sql, params
	return a.result, a.err
}

type stagingQueryRouter struct{ adapter *stagingQueryAdapter }

func (r *stagingQueryRouter) Adapter(context.Context, NodeKindDescriptor) (SubstrateAdapter, error) {
	return r.adapter, nil
}
func (r *stagingQueryRouter) All(context.Context) ([]SubstrateAdapter, error) {
	return []SubstrateAdapter{r.adapter}, nil
}
func (r *stagingQueryRouter) ByID(string) (SubstrateAdapter, error) { return r.adapter, nil }
func (r *stagingQueryRouter) Close() error                          { return nil }

func newStagingQueryEnv(adapter *stagingQueryAdapter) *Env {
	return &Env{
		Config: SpecGraphConfig{
			Mode: ModeExperimentalBootstrap, DefaultOrganizationID: "org-test", ExperimentalQueryEnabled: true,
			Substrates: []SubstrateDescriptor{{ID: "ood", ObjectTable: "OODGraphObjects"}},
		},
		Substrates: &stagingQueryRouter{adapter: adapter},
	}
}

func TestStagingWalkClaimsIsDeterministicAndClassifiesLeaves(t *testing.T) {
	input := map[string]interface{}{
		"rule": "This invariant contains enough words to be a graph claim.",
		"a": map[string]interface{}{
			"decision": "This decision is deliberately long enough to be a durable claim.",
			"id":       "short_identifier",
		},
		"items": []interface{}{
			"This array item is also long enough to become a graph claim.",
			17,
		},
	}
	wantNames := []string{"sample__a.decision", "sample__items[0]", "sample__rule"}
	for attempt := 0; attempt < 30; attempt++ {
		var got []stagingLoadConcept
		stagingWalkClaims(input, "", "sample", "section", "/tmp/SAMPLE.ood.json", &got)
		names := make([]string, len(got))
		for i, concept := range got {
			names[i] = concept.CanonicalName
		}
		if !reflect.DeepEqual(names, wantNames) {
			t.Fatalf("claim extraction order must be stable; got %v, want %v", names, wantNames)
		}
		if got[0].NodeKind != "decision" || got[1].NodeKind != "section" || got[2].NodeKind != "invariant" {
			t.Fatalf("leaf kind inference lost semantic classification: %+v", got)
		}
		if got[1].SourcePath != "/tmp/SAMPLE.ood.json#items[0]" {
			t.Fatalf("array claim lost exact provenance: %q", got[1].SourcePath)
		}
	}
}

func TestStagingClaimClassificationAndPrefixBoundaries(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"This sentence is a substantive claim with enough content.", true},
		{"short text", false},
		{"single_token_with_more_than_twenty_characters", false},
		{"/Users/person/a path that otherwise looks like a substantive claim", false},
		{"/home/person/a path that otherwise looks like a substantive claim", false},
	} {
		if got := stagingIsClaimShape(tc.value); got != tc.want {
			t.Errorf("stagingIsClaimShape(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
	for _, tc := range []struct{ field, want string }{
		{"MUST", "invariant"}, {"resolution", "decision"}, {"failure", "sentinel"},
		{"principle", "axiom"}, {"premise", "assumption"}, {"description", "section"},
	} {
		if got := stagingNodeKindForLeaf(tc.field, "section"); got != tc.want {
			t.Errorf("stagingNodeKindForLeaf(%q) = %q, want %q", tc.field, got, tc.want)
		}
	}
	for _, tc := range []struct{ path, want string }{
		{"/tmp/VOLT_SECRET_DETECTION_v1.ood.json", "volt_secret_detection_v1"},
		{"plain.JSON", "plain.json"},
		{"no-extension", "no-extension"},
	} {
		if got := stagingSpecPrefixFromPath(tc.path); got != tc.want {
			t.Errorf("stagingSpecPrefixFromPath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestValidateStagingLoadEdgesRejectsMalformedBatchesBeforeIO(t *testing.T) {
	env := &Env{Edges: newEdgeRegistry([]EdgeLabelDescriptor{NewEdgeLabelDescriptor(map[string]interface{}{"name": "supports"})})}
	valid := stagingLoadEdge{EdgeLabel: "supports", SourceCanonicalName: "source.section", TargetCanonicalName: "target-section"}
	if err := validateStagingLoadEdges(context.Background(), env, []stagingLoadEdge{valid}); err != nil {
		t.Fatalf("valid edge rejected: %v", err)
	}
	for _, tc := range []struct {
		name  string
		env   *Env
		edges []stagingLoadEdge
		want  string
	}{
		{"missing label", env, []stagingLoadEdge{{SourceCanonicalName: "source", TargetCanonicalName: "target"}}, "edge_label required"},
		{"noncanonical endpoint", env, []stagingLoadEdge{{EdgeLabel: "supports", SourceCanonicalName: "has space", TargetCanonicalName: "target"}}, "endpoints must be canonical"},
		{"unregistered label", env, []stagingLoadEdge{{EdgeLabel: "unknown", SourceCanonicalName: "source", TargetCanonicalName: "target"}}, "unknown"},
		{"missing registry", nil, []stagingLoadEdge{valid}, "registry unavailable"},
		{"duplicate relationship", env, []stagingLoadEdge{valid, valid}, "duplicates"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStagingLoadEdges(context.Background(), tc.env, tc.edges)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestStagingReadHandlersBuildBoundedEscapedQueriesAgainstConfiguredOwner(t *testing.T) {
	adapter := &stagingQueryAdapter{fakeAdapter: &fakeAdapter{}, result: QueryResult{Rows: []map[string]interface{}{{"staging_id": "s1"}}}}
	env := newStagingQueryEnv(adapter)
	ctx := context.Background()
	if _, err := handleStagingList(ctx, env, stagingListInput{}); err == nil || !strings.Contains(err.Error(), "ingestion_run_id required") {
		t.Fatalf("missing list run must fail before query, got %v", err)
	}
	result, err := handleStagingList(ctx, env, stagingListInput{IngestionRunID: "run'one", PipelineState: "linted", NodeKind: "section", Limit: -4})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("list result = (%+v, %v)", result, err)
	}
	for _, fragment := range []string{"ingestion_run_id = 'run''one'", "pipeline_state = 'linted'", "node_kind = 'section'", "ORDER BY canonical_name LIMIT 200"} {
		if !strings.Contains(adapter.sql, fragment) {
			t.Errorf("list query missing %q:\n%s", fragment, adapter.sql)
		}
	}
	if _, err := handleStagingGet(ctx, env, stagingGetInput{IngestionRunID: "run", StagingID: "id'one"}); err != nil {
		t.Fatalf("get: %v", err)
	}
	if !strings.Contains(adapter.sql, "staging_id = 'id''one'") {
		t.Fatalf("get query did not escape staging id: %s", adapter.sql)
	}
	if _, err := handleStagingGet(ctx, env, stagingGetInput{IngestionRunID: "run"}); err == nil || !strings.Contains(err.Error(), "ingestion_run_id + staging_id required") {
		t.Fatalf("missing get id must fail before query, got %v", err)
	}
}

func TestStagingStructuralLintRulesShapeFindingsFromTypedRows(t *testing.T) {
	adapter := &stagingQueryAdapter{fakeAdapter: &fakeAdapter{}}
	env := newStagingQueryEnv(adapter)
	label := NewEdgeLabelDescriptor(map[string]interface{}{
		"name": "supports", "source_kinds": []interface{}{"section"}, "target_kinds": []interface{}{"section"}, "forbid_self_loops": true,
	})
	env.Edges = newEdgeRegistry([]EdgeLabelDescriptor{label})
	env.Config.NodeKinds = []NodeKindDescriptor{NewNodeKindDescriptor(map[string]interface{}{"name": "section"})}
	env.Config.EdgeLabels = []EdgeLabelDescriptor{label}
	ctx := context.Background()
	type lintCase struct {
		name string
		rows []map[string]interface{}
		fn   func(context.Context, *Env, string, string) ([]stagingLintFinding, error)
		want string
	}
	for _, tc := range []lintCase{
		{"r3", []map[string]interface{}{{"staging_id": "s", "canonical_name": "name", "node_kind": "unknown"}}, lintR3KindInRegistry, "not in registry"},
		{"r7", []map[string]interface{}{{"staging_id": "s", "canonical_name": "Bad Name", "node_kind": "section"}}, lintR7CanonicalNamePattern, "does not match"},
		{"r8", []map[string]interface{}{{"canonical_name": "duplicate", "n": int64(2)}}, lintR8NoDuplicate, "appears 2 times"},
		{"r10 unresolved", []map[string]interface{}{{"staging_edge_id": "e", "source_canonical_name": "missing", "target_canonical_name": "target"}}, lintR10EdgeEndpointKinds, "endpoint unresolved"},
		{"r12", []map[string]interface{}{{"staging_edge_id": "e", "edge_label": "supports", "source_canonical_name": "same"}}, lintR12SelfLoop, "self-loop"},
		{"r13", []map[string]interface{}{{"staging_id": "s", "canonical_name": "name", "node_kind": "section", "field_path": "payload.source_reference"}}, lintR13NoSourceReference, "source_reference"},
		{"r15", []map[string]interface{}{{"staging_id": "s", "canonical_name": "name", "node_kind": "section"}}, lintR15NoAdmissionArtifacts, "kernel-minted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adapter.result = QueryResult{Rows: tc.rows}
			findings, err := tc.fn(ctx, env, "org'one", "run'one")
			if err != nil || len(findings) != 1 || !strings.Contains(findings[0].Detail, tc.want) {
				t.Fatalf("findings = (%+v, %v), want detail containing %q", findings, err, tc.want)
			}
			if !strings.Contains(adapter.sql, "org''one") || !strings.Contains(adapter.sql, "run''one") {
				t.Fatalf("lint query failed to escape tenant boundary: %s", adapter.sql)
			}
		})
	}
	adapter.result = QueryResult{Rows: []map[string]interface{}{{"staging_id": "s", "canonical_name": "name", "node_kind": "section", "section_path": "$.payload.rule", "value": strings.Repeat("x", 201), "verdict": "prose", "flash_response": "VERDICT: prose"}}}
	findings, err := lintR6NoProse(ctx, env, "org", "run")
	if err != nil || len(findings) != 1 || findings[0].FieldPath != "payload.rule" || len(findings[0].Observed) != 203 {
		t.Fatalf("R6 finding lost normalized field path or bounded evidence: (%+v, %v)", findings, err)
	}
}

func TestStagingJSONAndSubmissionHelpersPreserveBoundaries(t *testing.T) {
	if got := jsonValueToMap(map[string]interface{}{"a": "b"}); got["a"] != "b" {
		t.Fatalf("object JSON lost: %#v", got)
	}
	if got := jsonValueToMap([]interface{}{"not", "an object"}); got != nil {
		t.Fatalf("array JSON must not be represented as an object: %#v", got)
	}
	if got := jsonValueToMap(func() {}); got != nil {
		t.Fatalf("unencodable JSON must fail closed: %#v", got)
	}
	if null, err := toNullableJSON(nil); err != nil || null.Valid {
		t.Fatalf("nil map = (%+v, %v), want invalid JSON", null, err)
	}
	if value, err := toNullableJSON(map[string]interface{}{"a": "b"}); err != nil || !value.Valid || !strings.Contains(string(value.Value.(json.RawMessage)), `"a"`) {
		t.Fatalf("object JSON = (%+v, %v), want valid encoded object", value, err)
	}
	coord := &ArtifactSourceCoordinate{SourceAuthorityID: "authority", SourceRefKind: "id", SourceStableReference: "source", VersionCoordinate: "v1", SectionPath: "$"}
	concept := StagingConcept{CanonicalName: "sample", NodeKind: "section", Contract: map[string]interface{}{"k": "v"}, Payload: map[string]interface{}{"p": true}, SourceCoordinate: coord}
	sub := stagingConceptSubmission(concept)
	if sub.StableID != concept.CanonicalName || sub.NodeKind != concept.NodeKind || sub.SourceCoordinate != coord || sub.Payload["p"] != true {
		t.Fatalf("staging submission changed admission identity: %+v", sub)
	}
	if got := truncate("abcdef", 3); got != "abc…" {
		t.Fatalf("truncate = %q", got)
	}
	if got := truncate("abc", 3); got != "abc" {
		t.Fatalf("in-range truncate = %q", got)
	}
	if got := asString(17); got != "17" {
		t.Fatalf("asString = %q", got)
	}
}

func TestStagedExternalReceiptJSONRejectsUnknownFields(t *testing.T) {
	if encoded, err := stagedExternalReceiptToNullJSON(nil); err != nil || encoded.Valid {
		t.Fatalf("nil receipt = (%+v, %v), want invalid JSON", encoded, err)
	}
	receipt := &stagedExternalVerificationReceipt{ReceiptVersion: stagedExternalReceiptVersion, CanonicalName: "reference"}
	encoded, err := stagedExternalReceiptToNullJSON(receipt)
	if err != nil || !encoded.Valid {
		t.Fatalf("receipt encode = (%+v, %v)", encoded, err)
	}
	decoded, err := stagedExternalReceiptFromJSON(encoded.Value)
	if err != nil || decoded.CanonicalName != receipt.CanonicalName {
		t.Fatalf("receipt round trip = (%+v, %v)", decoded, err)
	}
	if _, err := stagedExternalReceiptFromJSON(map[string]interface{}{"receipt_version": "v", "unexpected": true}); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown receipt field must fail closed, got %v", err)
	}
}

func TestStagingWalkSymbolsEmitsEveryScalarLeaf(t *testing.T) {
	var mutations []*spanner.Mutation
	stagingWalkSymbols(map[string]interface{}{
		"text": "value", "number": float64(2), "flag": true,
		"list":    []interface{}{"nested", map[string]interface{}{"more": false}},
		"ignored": nil,
	}, "$.payload", "org", "run", "stage", "name", "section", &mutations)
	if len(mutations) != 5 {
		t.Fatalf("symbol traversal emitted %d mutations, want one per five scalar leaves", len(mutations))
	}
}
