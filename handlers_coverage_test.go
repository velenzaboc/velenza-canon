package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// handlerAdapter is a hermetic, recording substrate for handler boundary
// tests. It deliberately embeds the shared fake so every uninteresting
// interface method remains inert while each read surface can assert its
// concrete request.
type handlerAdapter struct {
	*fakeAdapter
	nodesByVersion map[string]Node
	listNodes      []Node
	edges          []Edge
	history        []NodeVersion
	search         []Node
	closure        []Node
	query          QueryResult
	readErr        error
	listErr        error
	edgeErr        error
	historyErr     error
	queryErr       error
	schemaErr      error
	readEdge       Edge
	readEdgeErr    error
	plans          []AdmissionPlan
	lastFilter     ListFilter
	lastNeighbor   NeighborOpts
	lastClosure    struct {
		id, direction string
		labels        []string
		depth, cap    int
	}
	lastSearch struct {
		vec       []float32
		kind, org string
		limit     int
	}
}

func newHandlerAdapter() *handlerAdapter {
	return &handlerAdapter{fakeAdapter: &fakeAdapter{}, nodesByVersion: map[string]Node{}}
}

func (a *handlerAdapter) ReadNode(_ context.Context, id, version, _ string) (Node, error) {
	if a.readErr != nil {
		return Node{}, a.readErr
	}
	if n, ok := a.nodesByVersion[id+"|"+version]; ok {
		return n, nil
	}
	if n, ok := a.nodesByVersion[id+"|"]; ok {
		return n, nil
	}
	return Node{}, errors.New("not found")
}
func (a *handlerAdapter) ReadEdge(context.Context, string, string) (Edge, error) {
	return a.readEdge, a.readEdgeErr
}
func (a *handlerAdapter) CommitAdmission(_ context.Context, plans ...AdmissionPlan) ([]AdmissionRecord, error) {
	a.plans = append(a.plans, plans...)
	out := make([]AdmissionRecord, len(plans))
	for i := range plans {
		out[i] = plans[i].Record
	}
	return out, nil
}
func (a *handlerAdapter) ListNodes(_ context.Context, f ListFilter) ([]Node, error) {
	a.lastFilter = f
	return a.listNodes, a.listErr
}
func (a *handlerAdapter) Neighbors(_ context.Context, _ string, o NeighborOpts) ([]Edge, error) {
	a.lastNeighbor = o
	return a.edges, a.edgeErr
}
func (a *handlerAdapter) History(context.Context, string) ([]NodeVersion, error) {
	return a.history, a.historyErr
}
func (a *handlerAdapter) SearchByEmbedding(_ context.Context, v []float32, kind string, limit int, org string) ([]Node, error) {
	a.lastSearch.vec, a.lastSearch.kind, a.lastSearch.limit, a.lastSearch.org = v, kind, limit, org
	return a.search, nil
}
func (a *handlerAdapter) TraverseClosure(_ context.Context, id string, labels []string, depth, cap int, direction string) ([]Node, error) {
	a.lastClosure.id, a.lastClosure.labels, a.lastClosure.depth, a.lastClosure.cap, a.lastClosure.direction = id, append([]string(nil), labels...), depth, cap, direction
	return a.closure, nil
}
func (a *handlerAdapter) ExecuteReadOnlyQuery(context.Context, string, map[string]interface{}) (QueryResult, error) {
	return a.query, a.queryErr
}
func (a *handlerAdapter) CheckOODGraphSchema(context.Context) error { return a.schemaErr }

type handlerRouter struct{ adapters []SubstrateAdapter }

func (r handlerRouter) Adapter(context.Context, NodeKindDescriptor) (SubstrateAdapter, error) {
	if len(r.adapters) == 0 {
		return nil, errors.New("no adapter")
	}
	return r.adapters[0], nil
}
func (r handlerRouter) All(context.Context) ([]SubstrateAdapter, error) { return r.adapters, nil }
func (r handlerRouter) ByID(id string) (SubstrateAdapter, error) {
	for _, a := range r.adapters {
		if a.ID() == id {
			return a, nil
		}
	}
	return nil, errors.New("unknown adapter")
}
func (r handlerRouter) Close() error { return nil }

type handlerEmbedder struct{ err error }

func (e handlerEmbedder) Embed(_ context.Context, text, task string) ([]float32, error) {
	if e.err != nil {
		return nil, e.err
	}
	if text == "" || task == "" {
		return nil, errors.New("invalid embed input")
	}
	return []float32{1, 2}, nil
}

func handlerEnv(a *handlerAdapter) *Env {
	kinds := []NodeKindDescriptor{NewNodeKindDescriptor(map[string]interface{}{"name": "section", "artifact_type": "section", "substrate_id": "fake", "version_scope": "stable"})}
	edges := []EdgeLabelDescriptor{NewEdgeLabelDescriptor(map[string]interface{}{"name": "depends_on", "edge_family": "dependency", "source_kinds": []interface{}{"section"}, "target_kinds": []interface{}{"section"}})}
	return &Env{Config: SpecGraphConfig{Mode: ModeExperimentalBootstrap, DefaultOrganizationID: "org-test", ExperimentalAdmitter: "TEST", ExperimentalQueryEnabled: true, NodeKinds: kinds, EdgeLabels: edges}, Kinds: newKindRegistry(kinds), Edges: newEdgeRegistry(edges), Projections: newProjectionRegistry([]ProjectionDescriptor{{Name: "doc_canonical_json", OwningSpec: "test"}}), Substrates: handlerRouter{adapters: []SubstrateAdapter{a}}, Now: func() time.Time { return time.Unix(0, 0).UTC() }}
}

func handlerNode(id string, version int, status string) Node {
	return Node{NodeID: id, NodeKind: "section", OrganizationID: "org-test", Status: status, CurrentVersion: NodeVersion{NodeID: id, Version: version, Contract: map[string]interface{}{"canonical_name": id}, Payload: map[string]interface{}{"value": version}}}
}

func TestHandlersCoverage_ReadSurfacesAndDefaults(t *testing.T) {
	a := newHandlerAdapter()
	a.nodesByVersion["n|"] = handlerNode("n", 1, "active")
	a.listNodes = []Node{handlerNode("listed", 1, "active")}
	a.edges = []Edge{{EdgeID: "e", SourceID: "n", TargetID: "x", Status: "active"}}
	a.history = []NodeVersion{{NodeID: "n", Version: 1}}
	a.search = []Node{handlerNode("search", 1, "active")}
	a.closure = []Node{handlerNode("closure", 1, "active")}
	env := handlerEnv(a)
	env.Embed = handlerEmbedder{}
	ctx := context.Background()

	if got, err := handleGet(ctx, env, getInput{NodeID: "n"}, "snapshot"); err != nil || got.NodeID != "n" {
		t.Fatalf("get=%+v err=%v", got, err)
	}
	if got, err := handleList(ctx, env, listInput{}, "snapshot"); err != nil || len(got.Nodes) != 1 || a.lastFilter.Status != "active" || a.lastFilter.Limit != 50 || a.lastFilter.SnapshotID != "snapshot" {
		t.Fatalf("list=%+v filter=%+v err=%v", got, a.lastFilter, err)
	}
	if _, err := handleList(ctx, env, listInput{NodeKind: "unknown"}, ""); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if got, err := handleSearch(ctx, env, searchInput{Query: "find"}); err != nil || len(got.Nodes) != 1 || a.lastSearch.limit != 15 || a.lastSearch.org != "org-test" {
		t.Fatalf("search=%+v request=%+v err=%v", got, a.lastSearch, err)
	}
	if got, err := handleNeighbors(ctx, env, neighborsInput{NodeID: "n"}, "snap"); err != nil || len(got.Edges) != 1 || a.lastNeighbor.Direction != "both" || a.lastNeighbor.Depth != 1 || a.lastNeighbor.SnapshotID != "snap" {
		t.Fatalf("neighbors=%+v opts=%+v err=%v", got, a.lastNeighbor, err)
	}
	if got, err := handleClosure(ctx, env, closureInput{NodeID: "n", ClosureProfile: "dependency"}); err != nil || len(got.Nodes) != 1 || a.lastClosure.direction != "forward" || a.lastClosure.depth != 3 || a.lastClosure.cap != 100 {
		t.Fatalf("closure=%+v call=%+v err=%v", got, a.lastClosure, err)
	}
	if got, err := handleImpact(ctx, env, impactInput{NodeID: "n"}); err != nil || len(got.Nodes) != 1 || a.lastClosure.direction != "reverse" || len(a.lastClosure.labels) != 1 {
		t.Fatalf("impact=%+v call=%+v err=%v", got, a.lastClosure, err)
	}
	if got, err := handleHistory(ctx, env, historyInput{NodeID: "n"}); err != nil || len(got.Versions) != 1 {
		t.Fatalf("history=%+v err=%v", got, err)
	}
}

func TestHandlersCoverage_DiffProjectQueryHealthAndFailures(t *testing.T) {
	a := newHandlerAdapter()
	a.nodesByVersion["n|one"] = handlerNode("n", 1, "active")
	a.nodesByVersion["n|"] = a.nodesByVersion["n|one"]
	b := handlerNode("n", 2, "retired")
	b.CurrentVersion.Payload = map[string]interface{}{"value": "two"}
	a.nodesByVersion["n|two"] = b
	a.query = QueryResult{Columns: []string{"answer"}, Rows: []map[string]interface{}{{"answer": 42}}}
	env := handlerEnv(a)
	ctx := context.Background()
	if got, err := handleDiff(ctx, env, diffInput{NodeID: "n", VersionA: "one", VersionB: "two"}); err != nil || got.Identical || got.StatusChange != "active->retired" || len(got.Operations) == 0 {
		t.Fatalf("diff=%+v err=%v", got, err)
	}
	if got, err := handleProject(ctx, env, projectInput{NodeID: "n", Projection: "doc_canonical_json"}, ""); err != nil || !strings.Contains(got.Body, "\"node_id\":\"n\"") {
		t.Fatalf("project=%+v err=%v", got, err)
	}
	if got, err := handleQuery(ctx, env, queryInput{SQL: "SELECT 42"}); err != nil || len(got.Rows) != 1 {
		t.Fatalf("query=%+v err=%v", got, err)
	}
	if _, err := handleQuery(ctx, env, queryInput{SQL: "DELETE FROM x"}); err == nil {
		t.Fatal("mutation query accepted")
	}
	if _, err := handleQueryOnSubstrate(ctx, env, queryInput{SQL: "MATCH (n)"}, "fake"); err != nil {
		t.Fatalf("typed query: %v", err)
	}
	if _, err := handleUse(ctx, env, useInput{SnapshotID: "old"}); err == nil {
		t.Fatal("implicit use accepted")
	}
	if _, err := handleCreate(ctx, env, createInput{}); err == nil {
		t.Fatal("empty create accepted")
	}
	if _, err := handleUpdate(ctx, env, updateInput{}); err == nil {
		t.Fatal("empty update accepted")
	}
	if _, err := handleArchive(ctx, env, archiveInput{}); err == nil {
		t.Fatal("empty archive accepted")
	}
	if _, err := handleUnlink(ctx, env, unlinkInput{}); err == nil {
		t.Fatal("empty unlink accepted")
	}
	if _, err := handleSearch(ctx, handlerEnv(a), searchInput{Query: "x"}); err == nil {
		t.Fatal("search without embedder accepted")
	}
	a.schemaErr = errors.New("schema missing")
	if got, err := handleHealth(ctx, env, healthInput{}); err != nil || got.OverallReady || len(got.BlockingIssues) != 1 {
		t.Fatalf("health=%+v err=%v", got, err)
	}
}

func TestHandlersCoverage_AdmissionsUsePriorStateAndRetirementEdges(t *testing.T) {
	a := newHandlerAdapter()
	prior := handlerNode("n", 3, "active")
	a.nodesByVersion["n|"] = prior
	a.readEdge = Edge{EdgeID: "edge", EdgeLabel: "depends_on", SourceID: "n", SourceVersion: 3, TargetID: "target", TargetVersion: 1, Status: "active"}
	env := handlerEnv(a)
	ctx := context.Background()
	if got, err := handleCreate(ctx, env, createInput{NodeKind: "section", StableID: "created", Contract: map[string]interface{}{"canonical_name": "created"}, Payload: map[string]interface{}{"title": "new"}}); err != nil || got.ArtifactID != "created" {
		t.Fatalf("create=%+v err=%v", got, err)
	}
	if got, err := handleUpdate(ctx, env, updateInput{NodeID: "n", Contract: map[string]interface{}{"canonical_name": "n"}, Payload: map[string]interface{}{"title": "changed"}}); err != nil || got.ArtifactVersion != 4 {
		t.Fatalf("update=%+v err=%v", got, err)
	}
	if got, err := handleArchive(ctx, env, archiveInput{NodeID: "n"}); err != nil || got.ArtifactVersion != 4 {
		t.Fatalf("archive=%+v err=%v", got, err)
	}
	if got, err := handleUnlink(ctx, env, unlinkInput{EdgeID: "edge"}); err != nil || got.ArtifactID != "edge" {
		t.Fatalf("unlink=%+v err=%v", got, err)
	}
	if len(a.plans) != 4 || !a.plans[2].IsRetirement || !a.plans[3].IsRetirement {
		t.Fatalf("admission plans=%+v", a.plans)
	}
	// A live incoming edge must block retirement before a new admission plan.
	a.edges = []Edge{{SourceID: "dependent", TargetID: "n", EdgeLabel: "depends_on", Status: "active"}}
	if _, err := handleArchive(ctx, env, archiveInput{NodeID: "n"}); !errors.Is(err, ErrClosureWouldDangle) {
		t.Fatalf("dangling archive error=%v", err)
	}
}

func TestHandleImport_StagingPromotionOrdinarySubmissionNeedsNoExternalReceipt(t *testing.T) {
	a := newHandlerAdapter()
	env := handlerEnv(a)
	result, err := handleImport(context.Background(), env, importInput{
		Submissions: []ArtifactSubmission{{
			NodeKind: "section", StableID: "ordinary_section",
			Contract: map[string]interface{}{"canonical_name": "ordinary_section"},
			Payload:  map[string]interface{}{"scope": "ordinary"},
		}},
		StagingPromotion: &stagingPromotionPlan{
			IngestionRunID: "run", ConceptStagingIDs: []string{"staged-ordinary"},
			ExternalReceipts: []*stagedExternalVerificationReceipt{nil},
		},
	})
	if err != nil {
		t.Fatalf("ordinary staged promotion rejected: %v", err)
	}
	if result.Admitted != 1 || result.GraphSnapshotID == "" {
		t.Fatalf("promotion result=%+v", result)
	}
}

func TestHandlersCoverage_ValidationAndArchiveCompatibility(t *testing.T) {
	a := newHandlerAdapter()
	env := handlerEnv(a)
	ctx := context.Background()
	if err := validateEdgeEndpointClasses(NewEdgeLabelDescriptor(map[string]interface{}{"name": "x", "source_kinds": []interface{}{"section"}, "target_kinds": []interface{}{"section"}, "forbid_self_loops": true}), "a", "section", "a", "section"); !errors.Is(err, ErrEdgeSelfLoopForbidden) {
		t.Fatalf("self loop error=%v", err)
	}
	if err := validateContractMonotonicity(map[string]interface{}{"a": 1}, map[string]interface{}{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if err := validateContractMonotonicity(map[string]interface{}{"a": 1}, map[string]interface{}{"a": 2}); !errors.Is(err, ErrContractDrift) {
		t.Fatalf("drift=%v", err)
	}
	if _, err := handleArchiveEdge(ctx, env, archiveEdgeInput{}); err == nil {
		t.Fatal("empty edge archive accepted")
	}
	if _, err := handleArchiveNode(ctx, env, archiveNodeInput{}); err == nil {
		t.Fatal("empty node archive accepted")
	}
	if _, err := handleArchiveEdge(ctx, &Env{Config: SpecGraphConfig{Mode: ModeExperimentalBootstrap, DefaultOrganizationID: "org-test"}, Substrates: handlerRouter{adapters: []SubstrateAdapter{a}}}, archiveEdgeInput{EdgeID: "e"}); err == nil {
		t.Fatal("archive edge accepted without admitter")
	}
	if _, err := handleArchiveNode(ctx, &Env{Config: SpecGraphConfig{Mode: ModeExperimentalBootstrap, DefaultOrganizationID: "org-test"}, Substrates: handlerRouter{adapters: []SubstrateAdapter{a}}}, archiveNodeInput{GraphObjectID: "n"}); err == nil {
		t.Fatal("archive node accepted without admitter")
	}
	if _, err := handleClosure(ctx, env, closureInput{NodeID: "n"}); err == nil {
		t.Fatal("closure without profile accepted")
	}
	if _, err := handleImpact(ctx, env, impactInput{}); err == nil {
		t.Fatal("impact without node accepted")
	}
	if _, err := handleHistory(ctx, env, historyInput{}); err == nil {
		t.Fatal("history without node accepted")
	}
}
