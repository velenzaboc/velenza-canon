//go:build integration

package main

import (
	"context"
	"strings"
	"testing"
)

func legacyAdmissionPlan(id string, version int, definition string, prior *NodeVersion) AdmissionPlan {
	node := &NodeVersion{
		NodeID: id, Version: version, Status: "active",
		Contract: map[string]interface{}{"canonical_name": id}, Payload: map[string]interface{}{"title": id},
		DefinitionHash: definition, ManifestHash: "manifest-" + id,
	}
	return AdmissionPlan{OrganizationID: "test-org", Node: node, PriorVersion: prior, Record: AdmissionRecord{
		RunID: "run-" + id + "-" + string(rune('0'+version)), ArtifactType: "section", OrganizationID: "test-org",
		ArtifactID: id, ArtifactVersion: version, AdmittedBy: "integration", DefinitionHash: definition,
		ManifestHash: node.ManifestHash, SignatureChain: []string{"sig-" + id}, PassReport: []PassResult{{PassName: "integration", Outcome: "passed"}},
	}}
}

func TestSpannerSubstrateLegacyAdmissionAndReadPaths(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapter, err := env.Substrates.ByID("test_substrate")
	if err != nil {
		t.Fatal(err)
	}
	spannerAdapter := adapter.(*SpannerSubstrateAdapter)
	if err := spannerAdapter.CheckSchema(ctx); err != nil {
		t.Fatalf("CheckSchema: %v", err)
	}
	if err := spannerAdapter.VerifyExperimentalSchema(ctx); err != nil {
		t.Fatalf("VerifyExperimentalSchema: %v", err)
	}

	first := legacyAdmissionPlan("source", 1, "definition-source-v1", nil)
	target := legacyAdmissionPlan("target", 1, "definition-target-v1", nil)
	edge := Edge{EdgeID: "edge-source-target", OrganizationID: "test-org", SourceID: "source", TargetID: "target", SourceVersion: 1, TargetVersion: 1, EdgeLabel: "depends_on", Status: "active"}
	edgePlan := AdmissionPlan{OrganizationID: "test-org", IsEdge: true, Edge: &edge, Record: AdmissionRecord{RunID: "run-edge", ArtifactType: "edge", OrganizationID: "test-org", ArtifactID: edge.EdgeID, ArtifactVersion: 1, AdmittedBy: "integration", DefinitionHash: "edge-definition", ManifestHash: "edge-manifest", SignatureChain: []string{"edge-sig"}}}
	if got, err := spannerAdapter.CommitAdmission(ctx, first, target, edgePlan); err != nil || len(got) != 3 || got[0].AdmittedAt.IsZero() {
		t.Fatalf("initial commit records=%+v err=%v", got, err)
	}
	prior := first.Node
	second := legacyAdmissionPlan("source", 2, "definition-source-v2", prior)
	if got, err := spannerAdapter.CommitAdmission(ctx, second); err != nil || len(got) != 1 || len(got[0].SignatureChain) != 2 {
		t.Fatalf("superseding commit records=%+v err=%v", got, err)
	}

	active, err := spannerAdapter.ReadNode(ctx, "source", "", "")
	if err != nil || active.CurrentVersion.Version != 2 || active.Status != "active" {
		t.Fatalf("active read=%+v err=%v", active, err)
	}
	v1, err := spannerAdapter.ReadNode(ctx, "source", "1", "")
	if err != nil || v1.CurrentVersion.Version != 1 || v1.Status != "superseded" {
		t.Fatalf("v1 read=%+v err=%v", v1, err)
	}
	if _, err := spannerAdapter.ReadNode(ctx, "source", "bad", ""); err == nil || !strings.Contains(err.Error(), "not an integer") {
		t.Fatalf("invalid version error=%v", err)
	}
	if got, err := spannerAdapter.ReadEdge(ctx, edge.EdgeID, ""); err != nil || got.SourceID != "source" || got.TargetVersion != 1 {
		t.Fatalf("edge=%+v err=%v", got, err)
	}
	if got, err := spannerAdapter.ListNodes(ctx, ListFilter{OrganizationID: "test-org", NodeKind: "section", Status: "active", Limit: 10}); err != nil || len(got) != 2 {
		t.Fatalf("list=%+v err=%v", got, err)
	}
	if got, err := spannerAdapter.History(ctx, "source"); err != nil || len(got) != 2 || got[1].Version != 2 {
		t.Fatalf("history=%+v err=%v", got, err)
	}
	for _, direction := range []string{"out", "in", "both"} {
		id := "source"
		if direction == "in" {
			id = "target"
		}
		if got, err := spannerAdapter.Neighbors(ctx, id, NeighborOpts{Direction: direction, EdgeLabels: []string{"depends_on"}}); err != nil || len(got) != 1 {
			t.Fatalf("neighbors %s=%+v err=%v", direction, got, err)
		}
	}
	if got, ok, err := spannerAdapter.FindByDefinitionHash(ctx, "test-org", "definition-source-v2"); err != nil || !ok || got.CurrentVersion.Version != 2 {
		t.Fatalf("definition=%+v ok=%t err=%v", got, ok, err)
	}
	if got, ok, err := spannerAdapter.FindByCanonicalName(ctx, "test-org", "section", "source"); err != nil || !ok || got.NodeID != "source" {
		t.Fatalf("canonical=%+v ok=%t err=%v", got, ok, err)
	}
	if _, ok, err := spannerAdapter.FindByDefinitionHash(ctx, "test-org", "missing"); err != nil || ok {
		t.Fatalf("missing definition ok=%t err=%v", ok, err)
	}
	if _, ok, err := spannerAdapter.FindByCanonicalName(ctx, "test-org", "section", "missing"); err != nil || ok {
		t.Fatalf("missing canonical ok=%t err=%v", ok, err)
	}
	// The emulator intentionally lacks vector-index and property-graph support;
	// assert those substrate paths return their query failures rather than
	// silently manufacturing results. Their successful execution is covered by
	// the production Spanner contract, while this verifies the adapter boundary.
	if _, err := spannerAdapter.SearchByEmbedding(ctx, []float32{1, 0}, "section", 5, "test-org"); err == nil {
		t.Fatal("emulator unexpectedly accepted vector search")
	}
	if _, err := spannerAdapter.FindSimilarByEmbedding(ctx, "test-org", []float32{1, 0}, 0.5, 5); err == nil {
		t.Fatal("emulator unexpectedly accepted similar-vector search")
	}
	if _, err := spannerAdapter.TraverseClosure(ctx, "source", []string{"depends_on"}, 2, 5, "forward"); err == nil {
		t.Fatal("emulator unexpectedly accepted property-graph traversal")
	}
	retirement := AdmissionPlan{OrganizationID: "test-org", IsEdge: true, IsRetirement: true, Edge: &edge, Record: AdmissionRecord{RunID: "run-edge-retire", ArtifactType: "edge", OrganizationID: "test-org", ArtifactID: edge.EdgeID, ArtifactVersion: 1, AdmittedBy: "integration", DefinitionHash: "edge-definition", ManifestHash: "edge-manifest"}}
	if _, err := spannerAdapter.CommitAdmission(ctx, retirement); err != nil {
		t.Fatalf("retire edge: %v", err)
	}
	if got, err := spannerAdapter.ReadEdge(ctx, edge.EdgeID, ""); err != nil || got.Status != "retired" {
		t.Fatalf("retired edge=%+v err=%v", got, err)
	}
	query, err := spannerAdapter.ExecuteReadOnlyQuery(ctx, "SELECT node_id, version FROM Nodes WHERE organization_id=@org ORDER BY node_id, version", map[string]interface{}{"org": "test-org"})
	if err != nil || len(query.Rows) != 3 || query.Rows[0]["node_id"] == nil {
		t.Fatalf("query=%+v err=%v", query, err)
	}
}
