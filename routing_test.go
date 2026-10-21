package main

import (
	"context"
	"strings"
	"testing"
)

type queryRecordingAdapter struct {
	*fakeAdapter
	id      string
	queries []string
}

func (a *queryRecordingAdapter) ID() string { return a.id }

func (a *queryRecordingAdapter) ExecuteReadOnlyQuery(_ context.Context, sql string, _ map[string]interface{}) (QueryResult, error) {
	a.queries = append(a.queries, sql)
	return QueryResult{}, nil
}

type adversarialReadRouter struct {
	wrong *queryRecordingAdapter
	ood   *queryRecordingAdapter
}

func (r *adversarialReadRouter) Adapter(context.Context, NodeKindDescriptor) (SubstrateAdapter, error) {
	return r.wrong, nil
}

func (r *adversarialReadRouter) All(context.Context) ([]SubstrateAdapter, error) {
	return []SubstrateAdapter{r.wrong, r.ood}, nil
}

func (r *adversarialReadRouter) ByID(id string) (SubstrateAdapter, error) {
	if id == r.ood.id {
		return r.ood, nil
	}
	return r.wrong, nil
}

func (r *adversarialReadRouter) Close() error { return nil }

func routedReadEnv() (*Env, *queryRecordingAdapter, *queryRecordingAdapter) {
	wrong := &queryRecordingAdapter{fakeAdapter: &fakeAdapter{}, id: "wrong-first"}
	ood := &queryRecordingAdapter{fakeAdapter: &fakeAdapter{}, id: "ood_graph"}
	return &Env{
		Config: SpecGraphConfig{
			Mode:                  ModeExperimentalBootstrap,
			DefaultOrganizationID: "org-test",
			Substrates: []SubstrateDescriptor{
				{ID: "wrong-first", NodeTable: "Circuits"},
				{
					ID: "ood_graph", ObjectTable: "OODGraphObjects", GraphEdgeTable: "OODGraphEdges",
					SnapshotTable: "OODGraphSnapshots", MaterializationRunTable: "OODGraphMaterializationRuns",
				},
			},
		},
		Substrates: &adversarialReadRouter{wrong: wrong, ood: ood},
	}, wrong, ood
}

func TestTypedOODReadRoutesToConfiguredTableOwnerNotAllFirst(t *testing.T) {
	env, wrong, ood := routedReadEnv()
	if _, err := handleOODList(context.Background(), env, oodListInput{Limit: 10}); err != nil {
		t.Fatalf("handleOODList: %v", err)
	}
	if len(wrong.queries) != 0 {
		t.Fatalf("typed OOD read executed on first/non-owner substrate: %v", wrong.queries)
	}
	if len(ood.queries) != 1 || !strings.Contains(ood.queries[0], "FROM OODGraphObjects") {
		t.Fatalf("OOD owner queries=%v, want one object-table read", ood.queries)
	}
}

func TestStagingReadRoutesToConfiguredOODOwnerNotAllFirst(t *testing.T) {
	env, wrong, ood := routedReadEnv()
	if _, err := handleStagingList(context.Background(), env, stagingListInput{IngestionRunID: "run-1"}); err != nil {
		t.Fatalf("handleStagingList: %v", err)
	}
	if len(wrong.queries) != 0 {
		t.Fatalf("staging read executed on first/non-owner substrate: %v", wrong.queries)
	}
	if len(ood.queries) != 1 || !strings.Contains(ood.queries[0], "FROM staging_concepts") {
		t.Fatalf("OOD owner queries=%v, want one staging read", ood.queries)
	}
}
