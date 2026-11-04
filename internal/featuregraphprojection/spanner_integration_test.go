//go:build integration

package featuregraphprojection

import (
	"cloud.google.com/go/spanner"
	dbadmin "cloud.google.com/go/spanner/admin/database/apiv1"
	dbpb "cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	instanceadmin "cloud.google.com/go/spanner/admin/instance/apiv1"
	instancepb "cloud.google.com/go/spanner/admin/instance/apiv1/instancepb"
	"context"
	"errors"
	"fmt"
	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"strings"
	"testing"
	"time"
)

var legacyDDL = []string{
	`CREATE TABLE FeatureGraphSnapshots (organization_id STRING(64) NOT NULL,snapshot_id STRING(128) NOT NULL,source_coordinates JSON NOT NULL,scope JSON NOT NULL,sealed BOOL NOT NULL,created_at TIMESTAMP NOT NULL OPTIONS(allow_commit_timestamp=true),sealed_at TIMESTAMP OPTIONS(allow_commit_timestamp=true)) PRIMARY KEY(organization_id,snapshot_id)`,
	`CREATE TABLE FeatureGraphNodes (organization_id STRING(64) NOT NULL,snapshot_id STRING(128) NOT NULL,node_id STRING(1024) NOT NULL,node_kind STRING(64) NOT NULL,title STRING(MAX) NOT NULL,review_state STRING(32) NOT NULL,content_sha256 STRING(64) NOT NULL,body JSON NOT NULL,source_coordinates JSON NOT NULL,search_text STRING(MAX) NOT NULL,created_at TIMESTAMP NOT NULL OPTIONS(allow_commit_timestamp=true)) PRIMARY KEY(organization_id,snapshot_id,node_id)`,
	`CREATE TABLE FeatureGraphEdges (organization_id STRING(64) NOT NULL,snapshot_id STRING(128) NOT NULL,edge_id STRING(1024) NOT NULL,source_id STRING(1024) NOT NULL,target_id STRING(1024) NOT NULL,relation_kind STRING(64) NOT NULL,review_state STRING(32) NOT NULL,support_level STRING(64) NOT NULL,proof JSON NOT NULL,source_coordinates JSON NOT NULL,created_at TIMESTAMP NOT NULL OPTIONS(allow_commit_timestamp=true)) PRIMARY KEY(organization_id,snapshot_id,edge_id)`,
}

func TestSpannerProjectionTransactionAndReadback(t *testing.T) {
	host := os.Getenv("SPANNER_EMULATOR_HOST")
	use, e := gcpauth.ValidateSpannerEmulatorHost(host, true)
	if e != nil || !use {
		t.Fatal("integration requires an explicit loopback Spanner emulator", e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	ia, e := instanceadmin.NewInstanceAdminClient(ctx, option.WithoutAuthentication())
	if e != nil {
		t.Fatal(e)
	}
	defer ia.Close()
	parent := "projects/test-project/instances/fgp-test"
	if _, e = ia.GetInstance(ctx, &instancepb.GetInstanceRequest{Name: parent}); status.Code(e) == codes.NotFound {
		op, err := ia.CreateInstance(ctx, &instancepb.CreateInstanceRequest{Parent: "projects/test-project", InstanceId: "fgp-test", Instance: &instancepb.Instance{Name: parent, Config: "projects/test-project/instanceConfigs/emulator-config", DisplayName: "FeatureGraph projection integration", NodeCount: 1}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = op.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	} else if e != nil {
		t.Fatal(e)
	}
	da, e := dbadmin.NewDatabaseAdminClient(ctx, option.WithoutAuthentication())
	if e != nil {
		t.Fatal(e)
	}
	defer da.Close()
	name := fmt.Sprintf("fgp-%x", time.Now().UnixNano())
	resource := parent + "/databases/" + name
	op, e := da.CreateDatabase(ctx, &dbpb.CreateDatabaseRequest{Parent: parent, CreateStatement: "CREATE DATABASE `" + name + "`", ExtraStatements: legacyDDL})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = op.Wait(ctx); e != nil {
		t.Fatal(e)
	}
	defer da.DropDatabase(context.Background(), &dbpb.DropDatabaseRequest{Database: resource})
	client, e := spanner.NewClient(ctx, resource, option.WithoutAuthentication())
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	f, c, s := fixture()
	c.Database = resource
	c.AllowedDatabases = []string{resource}
	ss := f.source.Snapshot
	n := f.source.Nodes[0]
	ed := f.source.Edges[0]
	created, parseErr := time.Parse(time.RFC3339Nano, testTime)
	if parseErr != nil {
		t.Fatalf("fixture timestamp: %v", parseErr)
	}
	coord, cellErr := jsonCell(ss.CoordinatesJSON)
	if cellErr != nil {
		t.Fatalf("snapshot coordinates JSON: %v", cellErr)
	}
	scope, cellErr := jsonCell(ss.ScopeJSON)
	if cellErr != nil {
		t.Fatalf("snapshot scope JSON: %v", cellErr)
	}
	body, cellErr := jsonCell(n.BodyJSON)
	if cellErr != nil {
		t.Fatalf("node body JSON: %v", cellErr)
	}
	nc, cellErr := jsonCell(n.CoordinatesJSON)
	if cellErr != nil {
		t.Fatalf("node coordinates JSON: %v", cellErr)
	}
	ep, cellErr := jsonCell(ed.ProofJSON)
	if cellErr != nil {
		t.Fatalf("edge proof JSON: %v", cellErr)
	}
	ec, cellErr := jsonCell(ed.CoordinatesJSON)
	if cellErr != nil {
		t.Fatalf("edge coordinates JSON: %v", cellErr)
	}
	_, e = client.Apply(ctx, []*spanner.Mutation{
		spanner.InsertMap("FeatureGraphSnapshots", map[string]any{"organization_id": c.Organization, "snapshot_id": c.SourceSnapshot, "source_coordinates": coord, "scope": scope, "sealed": false, "created_at": created, "sealed_at": spanner.NullTime{}}),
		spanner.InsertMap("FeatureGraphNodes", map[string]any{"organization_id": c.Organization, "snapshot_id": c.SourceSnapshot, "node_id": n.ID, "node_kind": n.Kind, "title": n.Title, "review_state": n.ReviewState, "content_sha256": n.ContentSHA256, "body": body, "source_coordinates": nc, "search_text": n.SearchText, "created_at": created}),
		spanner.InsertMap("FeatureGraphEdges", map[string]any{"organization_id": c.Organization, "snapshot_id": c.SourceSnapshot, "edge_id": ed.ID, "source_id": ed.SourceID, "target_id": ed.TargetID, "relation_kind": ed.RelationKind, "review_state": ed.ReviewState, "support_level": ed.SupportLevel, "proof": ep, "source_coordinates": ec, "created_at": created}),
	})
	if e != nil {
		t.Fatal(e)
	}
	store, e := NewSpannerStore(client, c.MaxBytes)
	if e != nil {
		t.Fatal(e)
	}
	// Observation uses one budget across metadata and selected rows; it must
	// refuse before Plan/Apply can create any target snapshot.
	tiny, e := NewSpannerStore(client, 200)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tiny.ReadSnapshot(ctx, c.Organization, c.SourceSnapshot); e != nil {
		t.Fatal("individual snapshot should fit", e)
	}
	if _, e = tiny.ReadNodes(ctx, c.Organization, c.SourceSnapshot, s.NodeIDs); e != nil {
		t.Fatal("individual nodes should fit", e)
	}
	if _, e = tiny.ReadEdges(ctx, c.Organization, c.SourceSnapshot, s.EdgeIDs); e != nil {
		t.Fatal("individual edges should fit", e)
	}
	if _, e = Plan(ctx, c, tiny, fakeGit{}, s); e == nil || !strings.Contains(e.Error(), "byte budget") {
		t.Fatal("cumulative Plan byte budget accepted", e)
	}
	countRows := client.Single().Query(ctx, spanner.Statement{SQL: "SELECT COUNT(*) FROM FeatureGraphSnapshots"})
	countRow, countErr := countRows.Next()
	if countErr != nil {
		countRows.Stop()
		t.Fatal(countErr)
	}
	var snapshotCount int64
	if countErr = countRow.Columns(&snapshotCount); countErr != nil {
		countRows.Stop()
		t.Fatal(countErr)
	}
	countRows.Stop()
	if snapshotCount != 1 {
		t.Fatal("budget refusal wrote a target", snapshotCount)
	}
	for _, limit := range []int{0, -1, int(^uint(0) >> 1)} {
		if _, _, err := store.ReadAll(ctx, c.Organization, c.SourceSnapshot, limit, 1); err == nil {
			t.Fatalf("unbounded ReadAll limit %d accepted", limit)
		}
	}
	emptySelection := s
	emptySelection.EdgeIDs = nil
	c.ExpectedSelectionSHA256, _ = SelectionSHA256(emptySelection)
	emptyManifest, err := Plan(ctx, c, store, fakeGit{}, emptySelection)
	if err != nil || len(emptyManifest.Edges) != 0 {
		t.Fatal("empty edge selection became an unbounded read", err)
	}
	c.ExpectedSelectionSHA256, _ = SelectionSHA256(s)
	m, e := Plan(ctx, c, store, fakeGit{}, s)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(m.Nodes[0].BodyJSON), "9007199254740993") {
		t.Fatal("large JSON number lost")
	}
	r, e := Apply(ctx, c, store, fakeGit{}, m, m.Digest)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, err := tiny.ReadAll(ctx, c.Organization, r.TargetSnapshot, c.MaxNodes, c.MaxEdges); err == nil {
		t.Fatal("target readback ignored byte budget")
	}
	if r.NodeCount != 2 || r.EdgeCount != 2 || r.CommittedAt == "" || r.Replayed {
		t.Fatalf("bad receipt %+v", r)
	}
	source, e := store.ReadSnapshot(ctx, c.Organization, c.SourceSnapshot)
	if e != nil || source.Sealed || source.SealedAt != "" {
		t.Fatal("source was sealed/changed", e)
	}
	r, e = Apply(ctx, c, store, fakeGit{}, m, m.Digest)
	if e != nil || !r.Replayed {
		t.Fatal("exact replay failed", e)
	}
	// A failure after snapshot+nodes are buffered must expose no target row.
	s.Artifacts[0].Purpose = "different reviewed source reference"
	c.ExpectedSelectionSHA256, _ = SelectionSHA256(s)
	m2, e := Plan(ctx, c, store, fakeGit{}, s)
	if e != nil {
		t.Fatal(e)
	}
	broken := failedEdgeStore{Store: store}
	if _, e = Apply(ctx, c, broken, fakeGit{}, m2, m2.Digest); e == nil {
		t.Fatal("injected write failure accepted")
	}
	id := c.TargetPrefix + stableID("snapshot", m2.Digest)
	if _, e = store.ReadSnapshot(ctx, c.Organization, id); !errors.Is(e, ErrSnapshotNotFound) {
		t.Fatal("partial target visible", e)
	}
	c.ExpectedSelectionSHA256, _ = SelectionSHA256(Selection{NodeIDs: nodeIDs(m.Nodes), EdgeIDs: edgeIDs(m.Edges), Artifacts: m.Artifacts})
	// A manually corrupted sealed target is never silently overwritten by replay.
	_, e = client.Apply(ctx, []*spanner.Mutation{spanner.UpdateMap("FeatureGraphNodes", map[string]any{"organization_id": c.Organization, "snapshot_id": r.TargetSnapshot, "node_id": n.ID, "title": "fault injection"})})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Apply(ctx, c, store, fakeGit{}, m, m.Digest); e == nil {
		t.Fatal("corrupt sealed target accepted")
	}
}

type failedEdgeStore struct{ Store }

func (s failedEdgeStore) Atomic(ctx context.Context, fn func(Tx) error) error {
	return s.Store.Atomic(ctx, func(tx Tx) error { return fn(failedEdgeTx{Tx: tx}) })
}

type failedEdgeTx struct{ Tx }

func (failedEdgeTx) InsertEdges(context.Context, string, string, []Edge) error {
	return fmt.Errorf("injected after buffered node writes")
}
