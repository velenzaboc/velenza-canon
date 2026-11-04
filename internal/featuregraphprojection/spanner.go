package featuregraphprojection

import (
	"cloud.google.com/go/spanner"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"google.golang.org/api/iterator"
	"time"
)

// These three legacy projection tables are the entire write surface. No
// table name or SQL fragment is accepted from operator input.
type SpannerStore struct {
	client       *spanner.Client
	maxReadBytes int
}

func NewSpannerStore(client *spanner.Client, maxReadBytes int) (*SpannerStore, error) {
	if client == nil || maxReadBytes <= 0 || maxReadBytes > 32<<20 {
		return nil, fmt.Errorf("FeatureGraph read budget must be 1..32MiB with a nonnil client")
	}
	return &SpannerStore{client: client, maxReadBytes: maxReadBytes}, nil
}

type queryer interface {
	Query(context.Context, spanner.Statement) *spanner.RowIterator
}
type readBudget struct{ remaining int }

func (b *readBudget) charge(n int) error {
	if n < 0 || n > b.remaining {
		return fmt.Errorf("FeatureGraph read exceeds byte budget")
	}
	b.remaining -= n
	return nil
}
func newReadBudget(n int) *readBudget { return &readBudget{remaining: n} }

var ErrSnapshotNotFound = errors.New("FeatureGraph snapshot not found")

func readSnapshot(ctx context.Context, q queryer, o, id string, budget *readBudget) (Snapshot, error) {
	it := q.Query(ctx, spanner.Statement{SQL: `SELECT organization_id,snapshot_id,TO_JSON_STRING(source_coordinates),TO_JSON_STRING(scope),sealed,created_at,sealed_at FROM FeatureGraphSnapshots WHERE organization_id=@o AND snapshot_id=@s`, Params: map[string]any{"o": o, "s": id}})
	defer it.Stop()
	row, e := it.Next()
	if e == iterator.Done {
		return Snapshot{}, ErrSnapshotNotFound
	}
	if e != nil {
		return Snapshot{}, e
	}
	var x Snapshot
	var c, scope string
	var created time.Time
	var sealed spanner.NullTime
	if e = row.Columns(&x.Organization, &x.ID, &c, &scope, &x.Sealed, &created, &sealed); e != nil {
		return Snapshot{}, e
	}
	if e = budget.charge(len(x.Organization) + len(x.ID) + len(c) + len(scope)); e != nil {
		return Snapshot{}, e
	}
	x.CoordinatesJSON = json.RawMessage(c)
	x.ScopeJSON = json.RawMessage(scope)
	x.CreatedAt = created.UTC().Format(time.RFC3339Nano)
	if sealed.Valid {
		x.SealedAt = sealed.Time.UTC().Format(time.RFC3339Nano)
	}
	return x, nil
}
func readNodes(ctx context.Context, q queryer, o, s string, ids []string, limit int, budget *readBudget) ([]Node, error) {
	if ids != nil && len(ids) > 500000 {
		return nil, fmt.Errorf("selected node IDs exceed cap")
	}
	if ids == nil && (limit <= 0 || limit > 500000) {
		return nil, fmt.Errorf("unbounded FeatureGraph node read refused")
	}
	sql := `SELECT node_id,node_kind,title,review_state,content_sha256,TO_JSON_STRING(body),TO_JSON_STRING(source_coordinates),search_text,created_at FROM FeatureGraphNodes WHERE organization_id=@o AND snapshot_id=@s`
	params := map[string]any{"o": o, "s": s}
	if ids != nil {
		if len(ids) == 0 {
			return []Node{}, nil
		}
		sql += ` AND node_id IN UNNEST(@ids)`
		params["ids"] = ids
	}
	sql += ` ORDER BY node_id`
	if limit > 0 {
		sql += ` LIMIT @lim`
		params["lim"] = int64(limit) + 1
	}
	it := q.Query(ctx, spanner.Statement{SQL: sql, Params: params})
	defer it.Stop()
	out := []Node{}
	for {
		r, e := it.Next()
		if e == iterator.Done {
			return out, nil
		}
		if e != nil {
			return nil, e
		}
		var x Node
		var b, c string
		var created time.Time
		if e = r.Columns(&x.ID, &x.Kind, &x.Title, &x.ReviewState, &x.ContentSHA256, &b, &c, &x.SearchText, &created); e != nil {
			return nil, e
		}
		if e = budget.charge(len(x.ID) + len(x.Kind) + len(x.Title) + len(x.ReviewState) + len(x.ContentSHA256) + len(b) + len(c) + len(x.SearchText)); e != nil {
			return nil, e
		}
		x.BodyJSON = json.RawMessage(b)
		x.CoordinatesJSON = json.RawMessage(c)
		x.CreatedAt = created.UTC().Format(time.RFC3339Nano)
		out = append(out, x)
		if limit > 0 && len(out) > limit {
			return nil, fmt.Errorf("target node count exceeds cap")
		}
	}
}
func readEdges(ctx context.Context, q queryer, o, s string, ids []string, limit int, budget *readBudget) ([]Edge, error) {
	if ids != nil && len(ids) > 500000 {
		return nil, fmt.Errorf("selected edge IDs exceed cap")
	}
	if ids == nil && (limit <= 0 || limit > 500000) {
		return nil, fmt.Errorf("unbounded FeatureGraph edge read refused")
	}
	sql := `SELECT edge_id,source_id,target_id,relation_kind,review_state,support_level,TO_JSON_STRING(proof),TO_JSON_STRING(source_coordinates),created_at FROM FeatureGraphEdges WHERE organization_id=@o AND snapshot_id=@s`
	params := map[string]any{"o": o, "s": s}
	if ids != nil {
		if len(ids) == 0 {
			return []Edge{}, nil
		}
		sql += ` AND edge_id IN UNNEST(@ids)`
		params["ids"] = ids
	}
	sql += ` ORDER BY edge_id`
	if limit > 0 {
		sql += ` LIMIT @lim`
		params["lim"] = int64(limit) + 1
	}
	it := q.Query(ctx, spanner.Statement{SQL: sql, Params: params})
	defer it.Stop()
	out := []Edge{}
	for {
		r, e := it.Next()
		if e == iterator.Done {
			return out, nil
		}
		if e != nil {
			return nil, e
		}
		var x Edge
		var p, c string
		var created time.Time
		if e = r.Columns(&x.ID, &x.SourceID, &x.TargetID, &x.RelationKind, &x.ReviewState, &x.SupportLevel, &p, &c, &created); e != nil {
			return nil, e
		}
		if e = budget.charge(len(x.ID) + len(x.SourceID) + len(x.TargetID) + len(x.RelationKind) + len(x.ReviewState) + len(x.SupportLevel) + len(p) + len(c)); e != nil {
			return nil, e
		}
		x.ProofJSON = json.RawMessage(p)
		x.CoordinatesJSON = json.RawMessage(c)
		x.CreatedAt = created.UTC().Format(time.RFC3339Nano)
		out = append(out, x)
		if limit > 0 && len(out) > limit {
			return nil, fmt.Errorf("target edge count exceeds cap")
		}
	}
}
func (s *SpannerStore) ReadSnapshot(ctx context.Context, o, id string) (Snapshot, error) {
	tx := s.client.Single()
	defer tx.Close()
	return readSnapshot(ctx, tx, o, id, newReadBudget(s.maxReadBytes))
}
func (s *SpannerStore) ReadNodes(ctx context.Context, o, id string, ids []string) ([]Node, error) {
	if len(ids) == 0 {
		return []Node{}, nil
	}
	tx := s.client.Single()
	defer tx.Close()
	return readNodes(ctx, tx, o, id, ids, 0, newReadBudget(s.maxReadBytes))
}
func (s *SpannerStore) ReadEdges(ctx context.Context, o, id string, ids []string) ([]Edge, error) {
	if len(ids) == 0 {
		return []Edge{}, nil
	}
	tx := s.client.Single()
	defer tx.Close()
	return readEdges(ctx, tx, o, id, ids, 0, newReadBudget(s.maxReadBytes))
}
func (s *SpannerStore) ReadAll(ctx context.Context, o, id string, n, e int) ([]Node, []Edge, error) {
	if n <= 0 || e <= 0 {
		return nil, nil, fmt.Errorf("positive bounded node and edge limits required")
	}
	tx := s.client.ReadOnlyTransaction()
	defer tx.Close()
	budget := newReadBudget(s.maxReadBytes)
	ns, err := readNodes(ctx, tx, o, id, nil, n, budget)
	if err != nil {
		return nil, nil, err
	}
	es, err := readEdges(ctx, tx, o, id, nil, e, budget)
	return ns, es, err
}

// Observe pins all caller reads to one read-only transaction and one cumulative
// byte budget. It performs no writes and borrows the caller-owned client.
func (s *SpannerStore) Observe(ctx context.Context, fn func(Reader) error) error {
	tx := s.client.ReadOnlyTransaction()
	defer tx.Close()
	return fn(&readTx{q: tx, ctx: ctx, budget: newReadBudget(s.maxReadBytes)})
}
func (s *SpannerStore) Atomic(ctx context.Context, fn func(Tx) error) error {
	_, e := s.client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		return fn(&spTx{tx: tx, ctx: ctx, budget: newReadBudget(s.maxReadBytes)})
	})
	return e
}

type readTx struct {
	q      queryer
	ctx    context.Context
	budget *readBudget
}

func (t *readTx) ReadSnapshot(_ context.Context, o, id string) (Snapshot, error) {
	return readSnapshot(t.ctx, t.q, o, id, t.budget)
}
func (t *readTx) ReadNodes(_ context.Context, o, id string, ids []string) ([]Node, error) {
	if len(ids) == 0 {
		return []Node{}, nil
	}
	return readNodes(t.ctx, t.q, o, id, ids, 0, t.budget)
}
func (t *readTx) ReadEdges(_ context.Context, o, id string, ids []string) ([]Edge, error) {
	if len(ids) == 0 {
		return []Edge{}, nil
	}
	return readEdges(t.ctx, t.q, o, id, ids, 0, t.budget)
}
func (t *readTx) ReadAll(_ context.Context, o, id string, n, e int) ([]Node, []Edge, error) {
	if n <= 0 || e <= 0 {
		return nil, nil, fmt.Errorf("positive bounded node and edge limits required")
	}
	ns, err := readNodes(t.ctx, t.q, o, id, nil, n, t.budget)
	if err != nil {
		return nil, nil, err
	}
	es, err := readEdges(t.ctx, t.q, o, id, nil, e, t.budget)
	return ns, es, err
}

type spTx struct {
	tx                  *spanner.ReadWriteTransaction
	ctx                 context.Context
	targetOrg, targetID string
	budget              *readBudget
}

func (t *spTx) ReadSnapshot(_ context.Context, o, id string) (Snapshot, error) {
	return readSnapshot(t.ctx, t.tx, o, id, t.budget)
}
func (t *spTx) ReadNodes(_ context.Context, o, id string, ids []string) ([]Node, error) {
	if len(ids) == 0 {
		return []Node{}, nil
	}
	return readNodes(t.ctx, t.tx, o, id, ids, 0, t.budget)
}
func (t *spTx) ReadEdges(_ context.Context, o, id string, ids []string) ([]Edge, error) {
	if len(ids) == 0 {
		return []Edge{}, nil
	}
	return readEdges(t.ctx, t.tx, o, id, ids, 0, t.budget)
}
func (t *spTx) ReadAll(_ context.Context, o, id string, n, e int) ([]Node, []Edge, error) {
	if n <= 0 || e <= 0 {
		return nil, nil, fmt.Errorf("positive bounded node and edge limits required")
	}
	ns, err := readNodes(t.ctx, t.tx, o, id, nil, n, t.budget)
	if err != nil {
		return nil, nil, err
	}
	es, err := readEdges(t.ctx, t.tx, o, id, nil, e, t.budget)
	return ns, es, err
}
func (t *spTx) ExistingSnapshot(_ context.Context, o, id string) (Snapshot, bool, error) {
	x, e := readSnapshot(t.ctx, t.tx, o, id, t.budget)
	if errors.Is(e, ErrSnapshotNotFound) {
		return Snapshot{}, false, nil
	}
	return x, e == nil, e
}
func jsonCell(b []byte) (spanner.NullJSON, error) {
	if !validJSON(b) {
		return spanner.NullJSON{}, fmt.Errorf("invalid JSON cell")
	}
	return spanner.NullJSON{Value: json.RawMessage(b), Valid: true}, nil
}
func rowTime(s string) (time.Time, error) {
	if s == "" {
		return spanner.CommitTimestamp, nil
	}
	return time.Parse(time.RFC3339Nano, s)
}
func (t *spTx) InsertSnapshot(_ context.Context, x Snapshot) error {
	if t.targetID != "" || !x.Sealed || x.CreatedAt != "" || x.SealedAt != "" {
		return fmt.Errorf("only a new atomically sealed target may be inserted")
	}
	c, e := jsonCell(x.CoordinatesJSON)
	if e != nil {
		return e
	}
	scope, e := jsonCell(x.ScopeJSON)
	if e != nil {
		return e
	}
	t.targetOrg, t.targetID = x.Organization, x.ID
	return t.tx.BufferWrite([]*spanner.Mutation{spanner.Insert("FeatureGraphSnapshots", []string{"organization_id", "snapshot_id", "source_coordinates", "scope", "sealed", "created_at", "sealed_at"}, []any{x.Organization, x.ID, c, scope, true, spanner.CommitTimestamp, spanner.CommitTimestamp})})
}
func (t *spTx) InsertNodes(_ context.Context, o, s string, ns []Node) error {
	if t.targetID == "" || t.targetOrg != o || t.targetID != s {
		return fmt.Errorf("node write is outside new target")
	}
	ms := make([]*spanner.Mutation, 0, len(ns))
	for _, x := range ns {
		b, e := jsonCell(x.BodyJSON)
		if e != nil {
			return e
		}
		c, e := jsonCell(x.CoordinatesJSON)
		if e != nil {
			return e
		}
		at, e := rowTime(x.CreatedAt)
		if e != nil {
			return e
		}
		ms = append(ms, spanner.Insert("FeatureGraphNodes", []string{"organization_id", "snapshot_id", "node_id", "node_kind", "title", "review_state", "content_sha256", "body", "source_coordinates", "search_text", "created_at"}, []any{o, s, x.ID, x.Kind, x.Title, x.ReviewState, x.ContentSHA256, b, c, x.SearchText, at}))
	}
	return t.tx.BufferWrite(ms)
}
func (t *spTx) InsertEdges(_ context.Context, o, s string, es []Edge) error {
	if t.targetID == "" || t.targetOrg != o || t.targetID != s {
		return fmt.Errorf("edge write is outside new target")
	}
	ms := make([]*spanner.Mutation, 0, len(es))
	for _, x := range es {
		p, e := jsonCell(x.ProofJSON)
		if e != nil {
			return e
		}
		c, e := jsonCell(x.CoordinatesJSON)
		if e != nil {
			return e
		}
		at, e := rowTime(x.CreatedAt)
		if e != nil {
			return e
		}
		ms = append(ms, spanner.Insert("FeatureGraphEdges", []string{"organization_id", "snapshot_id", "edge_id", "source_id", "target_id", "relation_kind", "review_state", "support_level", "proof", "source_coordinates", "created_at"}, []any{o, s, x.ID, x.SourceID, x.TargetID, x.RelationKind, x.ReviewState, x.SupportLevel, p, c, at}))
	}
	return t.tx.BufferWrite(ms)
}
