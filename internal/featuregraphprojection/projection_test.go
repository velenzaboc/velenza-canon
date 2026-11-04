package featuregraphprojection

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const testTime = "2026-01-01T00:00:00Z"
const commitTime = "2026-02-02T00:00:00Z"

type fakeData struct {
	Snapshot Snapshot
	Nodes    []Node
	Edges    []Edge
}
type fakeStore struct {
	source  fakeData
	targets map[string]fakeData
	hook    func()
	fail    string
	commits int
}

func (f *fakeStore) ReadSnapshot(_ context.Context, o, id string) (Snapshot, error) {
	if o != f.source.Snapshot.Organization {
		return Snapshot{}, ErrSnapshotNotFound
	}
	if id == f.source.Snapshot.ID {
		return f.source.Snapshot, nil
	}
	x, ok := f.targets[id]
	if !ok {
		return Snapshot{}, ErrSnapshotNotFound
	}
	return x.Snapshot, nil
}
func (f *fakeStore) ReadNodes(_ context.Context, o, id string, ids []string) ([]Node, error) {
	d := f.source
	if id != d.Snapshot.ID {
		d = f.targets[id]
	}
	out := []Node{}
	for _, n := range d.Nodes {
		for _, want := range ids {
			if n.ID == want {
				out = append(out, n)
			}
		}
	}
	return out, nil
}
func (f *fakeStore) ReadEdges(_ context.Context, o, id string, ids []string) ([]Edge, error) {
	d := f.source
	if id != d.Snapshot.ID {
		d = f.targets[id]
	}
	out := []Edge{}
	for _, n := range d.Edges {
		for _, want := range ids {
			if n.ID == want {
				out = append(out, n)
			}
		}
	}
	return out, nil
}
func (f *fakeStore) ReadAll(_ context.Context, o, id string, n, e int) ([]Node, []Edge, error) {
	d := f.targets[id]
	return append([]Node(nil), d.Nodes...), append([]Edge(nil), d.Edges...), nil
}
func (f *fakeStore) ExistingSnapshot(ctx context.Context, o, id string) (Snapshot, bool, error) {
	x, e := f.ReadSnapshot(ctx, o, id)
	if e == ErrSnapshotNotFound {
		return x, false, nil
	}
	return x, e == nil, e
}
func (f *fakeStore) Atomic(ctx context.Context, fn func(Tx) error) error {
	if f.hook != nil {
		f.hook()
		f.hook = nil
	}
	tmp := *f
	tmp.targets = map[string]fakeData{}
	for id, d := range f.targets {
		tmp.targets[id] = fakeData{Snapshot: d.Snapshot, Nodes: append([]Node(nil), d.Nodes...), Edges: append([]Edge(nil), d.Edges...)}
	}
	if e := fn(&tmp); e != nil {
		return e
	}
	*f = tmp
	return nil
}
func (f *fakeStore) InsertSnapshot(_ context.Context, s Snapshot) error {
	if f.fail == "snapshot" {
		return fmt.Errorf("injected")
	}
	s.CreatedAt = commitTime
	s.SealedAt = commitTime
	f.targets[s.ID] = fakeData{Snapshot: s}
	f.commits++
	return nil
}
func (f *fakeStore) InsertNodes(_ context.Context, o, id string, ns []Node) error {
	if f.fail == "nodes" {
		return fmt.Errorf("injected")
	}
	d := f.targets[id]
	d.Nodes = append([]Node(nil), ns...)
	for i := range d.Nodes {
		if d.Nodes[i].CreatedAt == "" {
			d.Nodes[i].CreatedAt = commitTime
		}
	}
	f.targets[id] = d
	return nil
}
func (f *fakeStore) InsertEdges(_ context.Context, o, id string, es []Edge) error {
	if f.fail == "edges" {
		return fmt.Errorf("injected")
	}
	d := f.targets[id]
	d.Edges = append([]Edge(nil), es...)
	for i := range d.Edges {
		if d.Edges[i].CreatedAt == "" {
			d.Edges[i].CreatedAt = commitTime
		}
	}
	f.targets[id] = d
	return nil
}

type fakeGit struct{}

func (fakeGit) ReadArtifact(_ context.Context, a Artifact, _ Repository, limit int) ([]byte, error) {
	b := []byte(a.Path)
	if len(b) > limit {
		return nil, fmt.Errorf("cap")
	}
	return b, nil
}
func fixture() (*fakeStore, Config, Selection) {
	body := json.RawMessage(`{"n":9007199254740993}`)
	n := Node{ID: "research:feature", Kind: "feature", Title: "research", ReviewState: "pending_review", ContentSHA256: sum(body), BodyJSON: body, CoordinatesJSON: json.RawMessage(`{"authority":"research"}`), SearchText: "research", CreatedAt: testTime}
	e := Edge{ID: "source-edge", SourceID: n.ID, TargetID: n.ID, RelationKind: "cites", ReviewState: "pending_review", SupportLevel: "source_context", ProofJSON: json.RawMessage(`{"runtime_credit":0}`), CoordinatesJSON: json.RawMessage(`{}`), CreatedAt: testTime}
	s := Snapshot{Organization: "tenant-a", ID: "source-v1", Sealed: false, CoordinatesJSON: json.RawMessage(`{"source":"r"}`), ScopeJSON: json.RawMessage(`{"runtime_credit":0}`), CreatedAt: testTime}
	a := Artifact{Repository: "repo", Commit: strings.Repeat("a", 40), Path: "pack/editor.mjs", SHA256: sum([]byte("pack/editor.mjs")), Role: "code", Purpose: "evidence for native editing", References: []string{n.ID}}
	f := &fakeStore{source: fakeData{Snapshot: s, Nodes: []Node{n}, Edges: []Edge{e}}, targets: map[string]fakeData{}}
	c := Config{Mode: "experimental_bootstrap", Database: "projects/p/instances/i/databases/research", Organization: s.Organization, SourceSnapshot: s.ID, TargetPrefix: "evidence-", MaxNodes: 10, MaxEdges: 10, MaxBytes: 100000, MaxMutations: 1000, AllowedDatabases: []string{"projects/p/instances/i/databases/research"}, AllowedRepositories: map[string]Repository{"repo": {GitDir: "/repo.git", PathPrefixes: []string{"pack"}, Roles: []string{"code"}}}, AllowObservedUnsealedSource: true}
	selection := Selection{NodeIDs: []string{n.ID}, EdgeIDs: []string{e.ID}, Artifacts: []Artifact{a}}
	c.ExpectedSelectionSHA256, _ = SelectionSHA256(selection)
	return f, c, selection
}
func plan(t *testing.T, f *fakeStore, c Config, s Selection) Manifest {
	t.Helper()
	m, e := Plan(context.Background(), c, f, fakeGit{}, s)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func TestProjectionPublishesExactClosureAndReplays(t *testing.T) {
	f, c, s := fixture()
	before := f.source
	m := plan(t, f, c, s)
	again := plan(t, f, c, s)
	if m.Digest != again.Digest {
		t.Fatal("same observation is not deterministic")
	}
	r, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest)
	if e != nil {
		t.Fatal(e)
	}
	if r.Replayed || r.NodeCount != 2 || r.EdgeCount != 2 || r.CommittedAt != commitTime {
		t.Fatalf("receipt=%+v", r)
	}
	if !sameJSONValue(before, f.source) || f.source.Snapshot.Sealed {
		t.Fatal("source changed")
	}
	d := f.targets[r.TargetSnapshot]
	if d.Nodes[0].ReviewState == "accepted_research" || !strings.Contains(string(m.Nodes[0].BodyJSON), "9007199254740993") {
		t.Fatal("source facts/review changed")
	}
	if !strings.Contains(string(d.Snapshot.ScopeJSON), `"unsealed_source_observation":true`) {
		t.Fatal("scope lost source state")
	}
	r, e = Apply(context.Background(), c, f, fakeGit{}, m, m.Digest)
	if e != nil || !r.Replayed || f.commits != 1 {
		t.Fatalf("replay %v %+v commits=%d", e, r, f.commits)
	}
	f.source.Nodes[0].Title = "later source revision"
	r, e = Apply(context.Background(), c, f, fakeGit{}, m, m.Digest)
	if e != nil || !r.Replayed {
		t.Fatal("retained target replay incorrectly depends on current source", e)
	}
}
func TestProjectionSourceDriftRefusesBeforeAtomicWrite(t *testing.T) {
	cases := map[string]func(*fakeStore){"review": func(f *fakeStore) { f.source.Nodes[0].ReviewState = "accepted_research" }, "body": func(f *fakeStore) { f.source.Nodes[0].BodyJSON = []byte(`{"n":9007199254740994}`) }, "hash": func(f *fakeStore) { f.source.Nodes[0].ContentSHA256 = strings.Repeat("b", 64) }, "coordinates": func(f *fakeStore) { f.source.Nodes[0].CoordinatesJSON = []byte(`{"authority":"other"}`) }, "scope": func(f *fakeStore) { f.source.Snapshot.ScopeJSON = []byte(`{"runtime_credit":1}`) }, "seal": func(f *fakeStore) { f.source.Snapshot.Sealed = true }, "edge": func(f *fakeStore) { f.source.Edges[0].SupportLevel = "changed" }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f, c, s := fixture()
			m := plan(t, f, c, s)
			f.hook = func() { change(f) }
			if _, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest); e == nil || len(f.targets) != 0 || f.commits != 0 {
				t.Fatalf("source drift wrote data: %v", e)
			}
		})
	}
}
func TestProjectionAtomicRollback(t *testing.T) {
	for _, stage := range []string{"snapshot", "nodes", "edges"} {
		t.Run(stage, func(t *testing.T) {
			f, c, s := fixture()
			m := plan(t, f, c, s)
			f.fail = stage
			if _, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest); e == nil || len(f.targets) != 0 || f.commits != 0 {
				t.Fatal("partial target exposed", e)
			}
		})
	}
}
func TestProjectionRejectsUnsealedWithoutExplicitMode(t *testing.T) {
	f, c, s := fixture()
	c.AllowObservedUnsealedSource = false
	if _, e := Plan(context.Background(), c, f, fakeGit{}, s); e == nil {
		t.Fatal("unsealed accepted")
	}
	f.source.Snapshot.Sealed = true
	f.source.Snapshot.SealedAt = testTime
	m := plan(t, f, c, s)
	if m.ProjectionMode != "sealed_source_projection" {
		t.Fatal("wrong domain")
	}
}
func TestProjectionRejectsSelectionAndScopeTamper(t *testing.T) {
	cases := map[string]func(*Selection){"missing node": func(s *Selection) { s.NodeIDs[0] = "absent" }, "duplicate node": func(s *Selection) { s.NodeIDs = append(s.NodeIDs, s.NodeIDs[0]) }, "foreign reference": func(s *Selection) { s.Artifacts[0].References = []string{"outside"} }, "duplicate artifact": func(s *Selection) { s.Artifacts = append(s.Artifacts, s.Artifacts[0]) }, "unpinned commit": func(s *Selection) { s.Artifacts[0].Commit = "HEAD" }, "wrong artifact hash": func(s *Selection) { s.Artifacts[0].SHA256 = strings.Repeat("b", 64) }}
	for n, edit := range cases {
		t.Run(n, func(t *testing.T) {
			f, c, s := fixture()
			edit(&s)
			if _, e := Plan(context.Background(), c, f, fakeGit{}, s); e == nil {
				t.Fatal("invalid selection accepted")
			}
		})
	}
	f, c, s := fixture()
	m := plan(t, f, c, s)
	m.Nodes[0].Title = "forged"
	if _, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest); e == nil {
		t.Fatal("digest tamper accepted")
	}
	m.Digest, _ = digest(m)
	if _, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest); e == nil || len(f.targets) != 0 {
		t.Fatal("rehashed source forgery accepted")
	}
}
func TestProjectionCapsAndConfigRemainBound(t *testing.T) {
	for _, kind := range []string{"database", "organization", "source", "prefix", "nodes", "edges", "bytes", "mutations"} {
		t.Run(kind, func(t *testing.T) {
			f, c, s := fixture()
			m := plan(t, f, c, s)
			switch kind {
			case "database":
				c.Database = "other"
			case "organization":
				c.Organization = "other"
			case "source":
				c.SourceSnapshot = "other"
			case "prefix":
				c.TargetPrefix = "different-"
			case "nodes":
				c.MaxNodes = 1
			case "edges":
				c.MaxEdges = 1
			case "bytes":
				c.MaxBytes = 1
			case "mutations":
				c.MaxMutations = 1
			}
			if _, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest); e == nil || len(f.targets) != 0 {
				t.Fatal("fence/cap bypass")
			}
		})
	}
}
func TestProjectionReplayRequiresExactRowsAndSeal(t *testing.T) {
	for _, kind := range []string{"seal", "provenance", "node", "extra", "edge"} {
		t.Run(kind, func(t *testing.T) {
			f, c, s := fixture()
			m := plan(t, f, c, s)
			r, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest)
			if e != nil {
				t.Fatal(e)
			}
			d := f.targets[r.TargetSnapshot]
			switch kind {
			case "seal":
				d.Snapshot.Sealed = false
			case "provenance":
				d.Snapshot.CoordinatesJSON = []byte(`{}`)
			case "node":
				d.Nodes[0].Title = "changed"
			case "extra":
				d.Nodes = append(d.Nodes, Node{ID: "unexpected"})
			case "edge":
				d.Edges[0].ReviewState = "accepted_research"
			}
			f.targets[r.TargetSnapshot] = d
			if _, e = Apply(context.Background(), c, f, fakeGit{}, m, m.Digest); e == nil {
				t.Fatal("collision accepted")
			}
		})
	}
}

func TestReviewedSelectionCannotOmitEdgesOrChangeArtifacts(t *testing.T) {
	for _, kind := range []string{"edge", "artifact"} {
		t.Run(kind, func(t *testing.T) {
			f, c, s := fixture()
			m := plan(t, f, c, s)
			if kind == "edge" {
				s.EdgeIDs = nil
				m.Edges = nil
			} else {
				s.Artifacts[0].Purpose = "changed purpose"
				m.Artifacts[0].Purpose = "changed purpose"
			}
			if _, e := Plan(context.Background(), c, f, fakeGit{}, s); e == nil {
				t.Fatal("unreviewed selection accepted")
			}
			m.Digest, _ = digest(m)
			if _, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest); e == nil || len(f.targets) != 0 {
				t.Fatal("unreviewed manifest selection accepted")
			}
		})
	}
}
func TestLegacyDeclaredHashIsQualifiedAndObservedBodyDigestBound(t *testing.T) {
	f, c, s := fixture()
	f.source.Nodes[0].ContentSHA256 = strings.Repeat("b", 64)
	m := plan(t, f, c, s)
	if m.SourceHashPolicy != sourceHashPolicy || m.SourceBodyObservations[0].CanonicalBodySHA256 != sum(canonicalRaw(f.source.Nodes[0].BodyJSON)) || m.SourceBodyObservations[0].DeclaredSHA256 != strings.Repeat("b", 64) {
		t.Fatal("legacy declaration confused with observed body hash")
	}
	r, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(f.targets[r.TargetSnapshot].Snapshot.CoordinatesJSON), sourceHashPolicy) {
		t.Fatal("target lost qualification")
	}
	m.SourceBodyObservations[0].CanonicalBodySHA256 = strings.Repeat("c", 64)
	m.Digest, _ = digest(m)
	if _, e := Apply(context.Background(), c, f, fakeGit{}, m, m.Digest); e == nil {
		t.Fatal("rehashed observed-body forgery accepted")
	}
}
