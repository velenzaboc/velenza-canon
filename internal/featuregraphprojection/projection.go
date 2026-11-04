// Package featuregraphprojection publishes bounded, source-pinned research
// evidence. It never writes OOD, kernel, admission, or executable state.
package featuregraphprojection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	ArtifactKind     = "artifact_reference"
	ArtifactRelation = "references_artifact"
)

var hex40or64 = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)

type Config struct {
	Mode                        string                `json:"mode"`
	Database                    string                `json:"database"`
	Organization                string                `json:"organization_id"`
	SourceSnapshot              string                `json:"source_snapshot_id"`
	TargetPrefix                string                `json:"target_snapshot_prefix"`
	MaxNodes                    int                   `json:"max_nodes"`
	MaxEdges                    int                   `json:"max_edges"`
	MaxBytes                    int                   `json:"max_bytes"`
	MaxMutations                int                   `json:"max_mutations"`
	AllowedDatabases            []string              `json:"allowed_databases"`
	AllowedRepositories         map[string]Repository `json:"allowed_repositories"`
	ExpectedSelectionSHA256     string                `json:"expected_selection_sha256"`
	AllowObservedUnsealedSource bool                  `json:"allow_observed_unsealed_source"`
}
type Repository struct {
	GitDir       string   `json:"git_dir"`
	PathPrefixes []string `json:"path_prefixes"`
	Roles        []string `json:"roles"`
}

func (c Config) Validate() error {
	allowed := false
	for _, d := range c.AllowedDatabases {
		allowed = allowed || d == c.Database
	}
	if c.Mode != "experimental_bootstrap" || c.Database == "" || !allowed || !cleanID(c.Organization, 64) || !cleanID(c.SourceSnapshot, 128) || !prefixPattern.MatchString(c.TargetPrefix) {
		return fmt.Errorf("explicit experimental database/source/target fences required")
	}
	if !hex64.MatchString(c.ExpectedSelectionSHA256) {
		return fmt.Errorf("reviewed selection digest required")
	}
	if c.MaxNodes <= 0 || c.MaxEdges <= 0 || c.MaxBytes <= 0 || c.MaxMutations <= 0 || len(c.AllowedRepositories) == 0 {
		return fmt.Errorf("positive caps and allowed repositories required")
	}
	for id, r := range c.AllowedRepositories {
		if !cleanID(id, 256) || r.GitDir == "" || len(r.PathPrefixes) == 0 || len(r.Roles) == 0 {
			return fmt.Errorf("incomplete repository fence %q", id)
		}
	}
	return nil
}
func cleanID(s string, max int) bool {
	return s != "" && len(s) <= max && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n\t")
}

type Node struct {
	ID              string          `json:"node_id"`
	Kind            string          `json:"node_kind"`
	Title           string          `json:"title"`
	ReviewState     string          `json:"review_state"`
	ContentSHA256   string          `json:"content_sha256"`
	SearchText      string          `json:"search_text"`
	CreatedAt       string          `json:"created_at"`
	BodyJSON        json.RawMessage `json:"body"`
	CoordinatesJSON json.RawMessage `json:"source_coordinates"`
}
type Edge struct {
	ID              string          `json:"edge_id"`
	SourceID        string          `json:"source_id"`
	TargetID        string          `json:"target_id"`
	RelationKind    string          `json:"relation_kind"`
	ReviewState     string          `json:"review_state"`
	SupportLevel    string          `json:"support_level"`
	CreatedAt       string          `json:"created_at"`
	ProofJSON       json.RawMessage `json:"proof"`
	CoordinatesJSON json.RawMessage `json:"source_coordinates"`
}
type Snapshot struct {
	Organization    string          `json:"organization_id"`
	ID              string          `json:"snapshot_id"`
	CoordinatesJSON json.RawMessage `json:"source_coordinates"`
	ScopeJSON       json.RawMessage `json:"scope"`
	Sealed          bool            `json:"sealed"`
	CreatedAt       string          `json:"created_at"`
	SealedAt        string          `json:"sealed_at"`
}
type Artifact struct {
	Title      string   `json:"title,omitempty"`
	Repository string   `json:"repository"`
	Commit     string   `json:"commit"`
	Path       string   `json:"path"`
	SHA256     string   `json:"sha256"`
	Role       string   `json:"role"`
	Purpose    string   `json:"purpose"`
	References []string `json:"references"`
}
type Selection struct {
	NodeIDs   []string   `json:"node_ids"`
	EdgeIDs   []string   `json:"edge_ids"`
	Artifacts []Artifact `json:"artifacts"`
}

// SourceBodyObservation preserves the legacy declared hash without asserting its
// undocumented algorithm. CanonicalBodySHA256 independently pins observed JSON.
type SourceBodyObservation struct {
	NodeID              string `json:"node_id"`
	DeclaredSHA256      string `json:"legacy_declared_sha256"`
	CanonicalBodySHA256 string `json:"observed_canonical_body_sha256"`
}

const sourceHashPolicy = "legacy_declared_hash_unverified_observed_canonical_body_sha256"

type Manifest struct {
	SourceHashPolicy       string                  `json:"source_hash_policy"`
	SourceBodyObservations []SourceBodyObservation `json:"source_body_observations"`
	Version                int                     `json:"version"`
	Database               string                  `json:"database"`
	TargetPrefix           string                  `json:"target_snapshot_prefix"`
	Organization           string                  `json:"organization_id"`
	SourceSnapshot         string                  `json:"source_snapshot_id"`
	Source                 Snapshot                `json:"source"`
	Nodes                  []Node                  `json:"nodes"`
	Edges                  []Edge                  `json:"edges"`
	Artifacts              []Artifact              `json:"artifacts"`
	Digest                 string                  `json:"digest"`
	ProjectionMode         string                  `json:"projection_mode"`
}
type Receipt struct {
	TargetSnapshot string   `json:"target_snapshot_id"`
	ManifestSHA256 string   `json:"manifest_sha256"`
	NodeIDs        []string `json:"node_ids"`
	EdgeIDs        []string `json:"edge_ids"`
	NodeCount      int      `json:"node_count"`
	EdgeCount      int      `json:"edge_count"`
	CommittedAt    string   `json:"source_observation_commit_time"`
	Replayed       bool     `json:"replayed"`
}
type Reader interface {
	ReadSnapshot(context.Context, string, string) (Snapshot, error)
	ReadNodes(context.Context, string, string, []string) ([]Node, error)
	ReadEdges(context.Context, string, string, []string) ([]Edge, error)
	ReadAll(context.Context, string, string, int, int) ([]Node, []Edge, error)
}
type Store interface {
	Reader
	Atomic(context.Context, func(Tx) error) error
}
type Tx interface {
	Reader
	ExistingSnapshot(context.Context, string, string) (Snapshot, bool, error)
	InsertSnapshot(context.Context, Snapshot) error
	InsertNodes(context.Context, string, string, []Node) error
	InsertEdges(context.Context, string, string, []Edge) error
}
type ArtifactReader interface {
	ReadArtifact(context.Context, Artifact, Repository, int) ([]byte, error)
}

func Plan(ctx context.Context, cfg Config, store Store, reader ArtifactReader, selection Selection) (Manifest, error) {
	if err := cfg.Validate(); err != nil {
		return Manifest{}, err
	}
	if err := validateSelection(selection); err != nil {
		return Manifest{}, err
	}
	if h, e := SelectionSHA256(selection); e != nil || h != cfg.ExpectedSelectionSHA256 {
		return Manifest{}, fmt.Errorf("selection differs from reviewed configuration")
	}
	if len(selection.NodeIDs) > cfg.MaxNodes || len(selection.EdgeIDs) > cfg.MaxEdges {
		return Manifest{}, fmt.Errorf("selection exceeds caps")
	}
	s, err := store.ReadSnapshot(ctx, cfg.Organization, cfg.SourceSnapshot)
	if err != nil {
		return Manifest{}, err
	}
	ns, err := store.ReadNodes(ctx, cfg.Organization, cfg.SourceSnapshot, selection.NodeIDs)
	if err != nil {
		return Manifest{}, err
	}
	es, err := store.ReadEdges(ctx, cfg.Organization, cfg.SourceSnapshot, selection.EdgeIDs)
	if err != nil {
		return Manifest{}, err
	}
	if !reflect.DeepEqual(nodeIDs(ns), sorted(selection.NodeIDs)) || !reflect.DeepEqual(edgeIDs(es), sorted(selection.EdgeIDs)) {
		return Manifest{}, fmt.Errorf("selected IDs do not match exact source closure")
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i].ID < ns[j].ID })
	sort.Slice(es, func(i, j int) bool { return es[i].ID < es[j].ID })
	arts := append([]Artifact(nil), selection.Artifacts...)
	for i := range arts {
		arts[i].References = sorted(arts[i].References)
	}
	sort.Slice(arts, func(i, j int) bool { return artifactKey(arts[i]) < artifactKey(arts[j]) })
	mode := "sealed_source_projection"
	if !s.Sealed {
		mode = "pinned_source_observation"
	}
	m := Manifest{SourceHashPolicy: sourceHashPolicy, SourceBodyObservations: bodyObservations(ns), Version: 1, Database: cfg.Database, TargetPrefix: cfg.TargetPrefix, Organization: cfg.Organization, SourceSnapshot: cfg.SourceSnapshot, Source: s, Nodes: ns, Edges: es, Artifacts: arts, ProjectionMode: mode}
	if err := validateManifest(cfg, m); err != nil {
		return Manifest{}, err
	}
	if err := verifyArtifacts(ctx, cfg, reader, m.Artifacts); err != nil {
		return Manifest{}, err
	}
	m.Digest, err = digest(m)
	return m, err
}
func Apply(ctx context.Context, cfg Config, store Store, reader ArtifactReader, m Manifest, expected string) (Receipt, error) {
	if err := cfg.Validate(); err != nil {
		return Receipt{}, err
	}
	if err := validateManifest(cfg, m); err != nil {
		return Receipt{}, err
	}
	d, err := digest(m)
	if err != nil || !hex64.MatchString(expected) || expected != m.Digest || d != expected {
		return Receipt{}, fmt.Errorf("manifest digest mismatch")
	}
	target, ns, es := projectionRows(cfg, m)
	encoded, err := canonicalMarshal(struct {
		S Snapshot
		N []Node
		E []Edge
	}{target, ns, es})
	if err != nil {
		return Receipt{}, err
	}
	// Count written cells conservatively, including generated token metadata.
	if len(ns) > cfg.MaxNodes || len(es) > cfg.MaxEdges || len(ns)*12+len(es)*12+7 > cfg.MaxMutations || len(encoded) > cfg.MaxBytes {
		return Receipt{}, fmt.Errorf("projection write exceeds configured caps")
	}
	replay := false
	err = store.Atomic(ctx, func(tx Tx) error {
		replay = false
		old, exists, e := tx.ExistingSnapshot(ctx, cfg.Organization, target.ID)
		if e != nil {
			return e
		}
		if exists {
			if e = verifyTarget(ctx, tx, old, target, ns, es, cfg); e != nil {
				return fmt.Errorf("target collision: %w", e)
			}
			replay = true
			return nil
		}
		if e = verifyPinned(ctx, cfg, tx, reader, m); e != nil {
			return e
		}
		if e = tx.InsertSnapshot(ctx, target); e != nil {
			return e
		}
		if e = tx.InsertNodes(ctx, cfg.Organization, target.ID, ns); e != nil {
			return e
		}
		return tx.InsertEdges(ctx, cfg.Organization, target.ID, es)
	})
	if err != nil {
		return Receipt{}, err
	}
	actual, err := store.ReadSnapshot(ctx, cfg.Organization, target.ID)
	if err != nil {
		return Receipt{}, fmt.Errorf("committed projection requires readback: %w", err)
	}
	if err = verifyTarget(ctx, store, actual, target, ns, es, cfg); err != nil {
		return Receipt{}, fmt.Errorf("committed projection readback failed: %w", err)
	}
	return Receipt{TargetSnapshot: target.ID, ManifestSHA256: m.Digest, NodeIDs: nodeIDs(ns), EdgeIDs: edgeIDs(es), NodeCount: len(ns), EdgeCount: len(es), CommittedAt: actual.CreatedAt, Replayed: replay}, nil
}
func verifyPinned(ctx context.Context, cfg Config, r Reader, git ArtifactReader, m Manifest) error {
	s, e := r.ReadSnapshot(ctx, cfg.Organization, cfg.SourceSnapshot)
	if e != nil {
		return e
	}
	if !sameJSONValue(s, m.Source) {
		return fmt.Errorf("source snapshot changed since plan")
	}
	ns, e := r.ReadNodes(ctx, cfg.Organization, cfg.SourceSnapshot, nodeIDs(m.Nodes))
	if e != nil {
		return e
	}
	es, e := r.ReadEdges(ctx, cfg.Organization, cfg.SourceSnapshot, edgeIDs(m.Edges))
	if e != nil {
		return e
	}
	if !sameNodes(ns, m.Nodes) || !sameEdges(es, m.Edges) {
		return fmt.Errorf("selected source closure changed since plan")
	}
	return verifyArtifacts(ctx, cfg, git, m.Artifacts)
}
func verifyArtifacts(ctx context.Context, cfg Config, git ArtifactReader, arts []Artifact) error {
	used := 0
	for _, a := range arts {
		r, ok := cfg.AllowedRepositories[a.Repository]
		if !ok {
			return fmt.Errorf("unapproved repository %q", a.Repository)
		}
		b, e := git.ReadArtifact(ctx, a, r, cfg.MaxBytes-used)
		if e != nil {
			return e
		}
		used += len(b)
		if used > cfg.MaxBytes || sum(b) != a.SHA256 {
			return fmt.Errorf("artifact hash or byte cap mismatch: %s", a.Path)
		}
	}
	return nil
}

// SelectionSHA256 commits to the exact reviewed IDs, artifacts and reference sets.
// Ordering is immaterial; omitted IDs or changed links require a new approval input.
func SelectionSHA256(s Selection) (string, error) {
	if err := validateSelection(s); err != nil {
		return "", err
	}
	normalized := Selection{NodeIDs: sorted(s.NodeIDs), EdgeIDs: sorted(s.EdgeIDs), Artifacts: append([]Artifact(nil), s.Artifacts...)}
	for i := range normalized.Artifacts {
		normalized.Artifacts[i].References = sorted(normalized.Artifacts[i].References)
	}
	sort.Slice(normalized.Artifacts, func(i, j int) bool {
		return artifactKey(normalized.Artifacts[i]) < artifactKey(normalized.Artifacts[j])
	})
	b, err := canonicalMarshal(normalized)
	if err != nil {
		return "", err
	}
	return sum(b), nil
}
func bodyObservations(ns []Node) []SourceBodyObservation {
	out := make([]SourceBodyObservation, 0, len(ns))
	for _, n := range ns {
		out = append(out, SourceBodyObservation{NodeID: n.ID, DeclaredSHA256: n.ContentSHA256, CanonicalBodySHA256: sum(canonicalRaw(n.BodyJSON))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}
func validateSelection(s Selection) error {
	if len(s.NodeIDs) == 0 || len(s.Artifacts) == 0 {
		return fmt.Errorf("explicit source nodes and artifacts required")
	}
	for _, ids := range [][]string{s.NodeIDs, s.EdgeIDs} {
		seen := map[string]bool{}
		for _, id := range ids {
			if !cleanID(id, 1024) || seen[id] {
				return fmt.Errorf("duplicate/invalid selected ID")
			}
			seen[id] = true
		}
	}
	ids := map[string]bool{}
	for _, id := range s.NodeIDs {
		ids[id] = true
	}
	seen := map[string]bool{}
	for _, a := range s.Artifacts {
		if !cleanID(a.Repository, 256) || !hex40or64.MatchString(a.Commit) || !hex64.MatchString(a.SHA256) || a.Path == "" || path.Clean(a.Path) != a.Path || path.IsAbs(a.Path) || strings.HasPrefix(a.Path, "../") || strings.ContainsAny(a.Path, "\\\x00\r\n") || !cleanID(a.Role, 64) || !cleanID(a.Purpose, 2048) || len(a.References) == 0 || seen[artifactKey(a)] {
			return fmt.Errorf("artifact locator, purpose or references invalid")
		}
		seen[artifactKey(a)] = true
		refs := map[string]bool{}
		for _, id := range a.References {
			if !ids[id] || refs[id] {
				return fmt.Errorf("artifact reference leaves selected closure or repeats")
			}
			refs[id] = true
		}
	}
	return nil
}
func validateManifest(c Config, m Manifest) error {
	if m.Version != 1 || m.Database != c.Database || m.TargetPrefix != c.TargetPrefix || m.Organization != c.Organization || m.SourceSnapshot != c.SourceSnapshot || m.Source.Organization != c.Organization || m.Source.ID != c.SourceSnapshot {
		return fmt.Errorf("manifest source/organization/version mismatch")
	}
	want := "sealed_source_projection"
	if !m.Source.Sealed {
		if !c.AllowObservedUnsealedSource {
			return fmt.Errorf("unsealed source requires explicit observation mode")
		}
		want = "pinned_source_observation"
	}
	if m.ProjectionMode != want {
		return fmt.Errorf("source observation mode mismatch")
	}
	if !validTime(m.Source.CreatedAt) || m.Source.Sealed && !validTime(m.Source.SealedAt) || !m.Source.Sealed && m.Source.SealedAt != "" {
		return fmt.Errorf("invalid source timestamps/seal binding")
	}
	if err := validateSelection(Selection{NodeIDs: nodeIDs(m.Nodes), EdgeIDs: edgeIDs(m.Edges), Artifacts: m.Artifacts}); err != nil {
		return err
	}
	if h, e := SelectionSHA256(Selection{NodeIDs: nodeIDs(m.Nodes), EdgeIDs: edgeIDs(m.Edges), Artifacts: m.Artifacts}); e != nil || h != c.ExpectedSelectionSHA256 {
		return fmt.Errorf("manifest selection differs from reviewed configuration")
	}
	if m.SourceHashPolicy != sourceHashPolicy || !reflect.DeepEqual(m.SourceBodyObservations, bodyObservations(m.Nodes)) {
		return fmt.Errorf("source body observations or declared hash qualification mismatch")
	}
	if len(m.Nodes) > c.MaxNodes || len(m.Edges) > c.MaxEdges {
		return fmt.Errorf("manifest source exceeds caps")
	}
	if !validJSON(m.Source.CoordinatesJSON) || !validJSON(m.Source.ScopeJSON) {
		return fmt.Errorf("invalid source metadata JSON")
	}
	kinds := map[string]bool{"use_case": true, "feature": true, "arc_blueprint": true, "presentation_plan": true, "source_evidence": true, "schema_component": true, "artifact_reference": true, "workflow_step": true}
	reviews := map[string]bool{"source_inventory": true, "accepted_research": true, "pending_review": true, "rejected_research": true}
	relations := map[string]bool{"supports_feature": true, "primary_arc": true, "supporting_arc": true, "research_membership": true, "presented_in": true, "uses_component": true, "depends_on": true, "overlaps": true, "contradicts": true, "cites": true, "references_artifact": true}
	ids := map[string]bool{}
	for _, n := range m.Nodes {
		if !kinds[n.Kind] || !reviews[n.ReviewState] || !hex64.MatchString(n.ContentSHA256) || !validJSON(n.BodyJSON) || !validJSON(n.CoordinatesJSON) || !validTime(n.CreatedAt) {
			return fmt.Errorf("invalid selected source node %q", n.ID)
		}
		ids[n.ID] = true
	}
	for _, e := range m.Edges {
		if !ids[e.SourceID] || !ids[e.TargetID] || !relations[e.RelationKind] || !reviews[e.ReviewState] || !validJSON(e.ProofJSON) || !validJSON(e.CoordinatesJSON) || !validTime(e.CreatedAt) {
			return fmt.Errorf("invalid selected source edge %q", e.ID)
		}
	}
	b, e := canonicalMarshal(m)
	if e != nil || len(b) > c.MaxBytes {
		return fmt.Errorf("manifest exceeds byte cap or invalid JSON")
	}
	return nil
}
func projectionRows(c Config, m Manifest) (Snapshot, []Node, []Edge) {
	target := Snapshot{Organization: c.Organization, ID: c.TargetPrefix + stableID("snapshot", m.Digest), Sealed: true}
	target.CoordinatesJSON = mustJSON(map[string]any{"manifest_sha256": m.Digest, "source_organization_id": m.Organization, "source_snapshot_id": m.SourceSnapshot, "source_snapshot_sealed": m.Source.Sealed, "source_coordinates": m.Source.CoordinatesJSON, "source_hash_policy": m.SourceHashPolicy, "source_body_observations": m.SourceBodyObservations, "source_scope_sha256": sum(canonicalRaw(m.Source.ScopeJSON)), "source_observation_time": "target_commit_timestamp", "projection_mode": m.ProjectionMode})
	target.ScopeJSON = scopeFor(m)
	ns := append([]Node(nil), m.Nodes...)
	es := append([]Edge(nil), m.Edges...)
	for _, a := range m.Artifacts {
		body := mustJSON(map[string]any{"repository": a.Repository, "commit": a.Commit, "path": a.Path, "artifact_sha256": a.SHA256, "role": a.Role, "purpose": a.Purpose, "title": a.Title, "runtime_authority": false, "runtime_credit": 0, "effects_enabled": false})
		id := stableID("artifact", m.Digest, artifactKey(a))
		n := Node{ID: id, Kind: ArtifactKind, Title: artifactTitle(a), ReviewState: "source_inventory", ContentSHA256: sum(body), BodyJSON: body, CoordinatesJSON: mustJSON(a), SearchText: artifactTitle(a) + " " + a.Purpose + " " + a.Path}
		ns = append(ns, n)
		for _, ref := range a.References {
			es = append(es, Edge{ID: stableID("reference", m.Digest, id, ref), SourceID: id, TargetID: ref, RelationKind: ArtifactRelation, ReviewState: "source_inventory", SupportLevel: "local_source_evidence", ProofJSON: mustJSON(map[string]any{"purpose": a.Purpose, "title": a.Title, "artifact_sha256": a.SHA256, "runtime_authority": false, "runtime_credit": 0, "effects_enabled": false}), CoordinatesJSON: n.CoordinatesJSON})
		}
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i].ID < ns[j].ID })
	sort.Slice(es, func(i, j int) bool { return es[i].ID < es[j].ID })
	return target, ns, es
}
func scopeFor(m Manifest) json.RawMessage {
	return mustJSON(map[string]any{"manifest_sha256": m.Digest, "source_snapshot_id": m.SourceSnapshot, "source_snapshot_sealed": m.Source.Sealed, "projection_mode": m.ProjectionMode, "unsealed_source_observation": !m.Source.Sealed, "bounded_selected_closure": true, "no_runtime_or_admission_authority": true, "no_full_source_currentness_claim": true, "source_hash_policy": m.SourceHashPolicy, "effects_enabled": false, "source_observation_time": "target_commit_timestamp"})
}
func verifyTarget(ctx context.Context, r Reader, actual, want Snapshot, ns []Node, es []Edge, c Config) error {
	if actual.Organization != want.Organization || actual.ID != want.ID || !actual.Sealed || !validTime(actual.CreatedAt) || actual.SealedAt != actual.CreatedAt || !sameRaw(actual.CoordinatesJSON, want.CoordinatesJSON) || !sameRaw(actual.ScopeJSON, want.ScopeJSON) {
		return fmt.Errorf("target seal/identity/provenance mismatch")
	}
	gotN, gotE, e := r.ReadAll(ctx, c.Organization, want.ID, c.MaxNodes, c.MaxEdges)
	if e != nil {
		return e
	}
	expectedN := append([]Node(nil), ns...)
	for i := range expectedN {
		if expectedN[i].CreatedAt == "" {
			expectedN[i].CreatedAt = actual.CreatedAt
		}
	}
	expectedE := append([]Edge(nil), es...)
	for i := range expectedE {
		if expectedE[i].CreatedAt == "" {
			expectedE[i].CreatedAt = actual.CreatedAt
		}
	}
	if !sameNodes(gotN, expectedN) || !sameEdges(gotE, expectedE) {
		return fmt.Errorf("target rows do not equal pinned complete projection")
	}
	return nil
}
func validTime(s string) bool { _, e := time.Parse(time.RFC3339Nano, s); return s != "" && e == nil }
func validJSON(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	_, e := CanonicalJSON(b)
	return e == nil
}
func canonicalRaw(b []byte) []byte { x, _ := CanonicalJSON(b); return x }
func sameRaw(a, b []byte) bool {
	x, e := CanonicalJSON(a)
	y, f := CanonicalJSON(b)
	return e == nil && f == nil && string(x) == string(y)
}
func canonicalMarshal(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return CanonicalJSON(b)
}
func mustJSON(v any) json.RawMessage {
	b, e := canonicalMarshal(v)
	if e != nil {
		panic(e)
	}
	return b
}
func sameJSONValue(a, b any) bool {
	x, e := canonicalMarshal(a)
	y, f := canonicalMarshal(b)
	return e == nil && f == nil && string(x) == string(y)
}
func sameNodes(a, b []Node) bool {
	x := append([]Node(nil), a...)
	y := append([]Node(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i].ID < x[j].ID })
	sort.Slice(y, func(i, j int) bool { return y[i].ID < y[j].ID })
	return sameJSONValue(x, y)
}
func sameEdges(a, b []Edge) bool {
	x := append([]Edge(nil), a...)
	y := append([]Edge(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i].ID < x[j].ID })
	sort.Slice(y, func(i, j int) bool { return y[i].ID < y[j].ID })
	return sameJSONValue(x, y)
}
func artifactKey(a Artifact) string {
	return strings.Join([]string{a.Repository, a.Commit, a.Path, a.Role}, "\x00")
}
func sum(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }
func stableID(domain string, v ...string) string {
	return domain + "-" + sum([]byte(domain+"\x00"+strings.Join(v, "\x00")))
}
func digest(m Manifest) (string, error) { m.Digest = ""; b, e := canonicalMarshal(m); return sum(b), e }
func sorted(a []string) []string        { x := append([]string{}, a...); sort.Strings(x); return x }
func nodeIDs(ns []Node) []string {
	x := make([]string, len(ns))
	for i, n := range ns {
		x[i] = n.ID
	}
	return sorted(x)
}
func edgeIDs(es []Edge) []string {
	x := make([]string, len(es))
	for i, e := range es {
		x[i] = e.ID
	}
	return sorted(x)
}

func artifactTitle(a Artifact) string {
	if a.Title != "" {
		return a.Title
	}
	return a.Path
}
