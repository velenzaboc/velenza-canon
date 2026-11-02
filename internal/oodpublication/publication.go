// Package oodpublication implements the bounded persistence half of OOD v8
// graph publication.  It deliberately accepts only a closure that a caller
// has already verified: source acquisition, parsing and admission are owned by
// their respective boundaries.
package oodpublication

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

// The v8 closure has nine independently named content-addressed manifests.
// Names, rather than positions, make an omitted member fail closed.
var requiredManifestNames = []string{
	"source_artifacts", "graph_objects", "graph_symbols", "graph_edges",
	"api_properties", "graph_fact_evidence_locators", "eligible_receipts",
	"structural_projections", "violations",
}

// ImmutableRecord is an exact, canonical preimage already validated by its
// owner. Kind and Key form its immutable storage identity. Raw is copied at
// the boundary so a caller cannot mutate a stored value after validation.
type ImmutableRecord struct {
	Kind string
	Key  string
	Raw  []byte
}

// Manifest is an exact canonical manifest record. Digest is verified by the
// evidence/codec owner before this publisher receives it; this package never
// substitutes a home-grown digest encoding.
type Manifest struct {
	Name   string
	Key    string
	Digest string
	Raw    []byte
}

// CanonicalDigestBinding makes a digest independently recomputable with a
// closed OOD v8 profile. It prevents a caller from promoting a string digest
// as evidence without its typed canonical preimage.
type CanonicalDigestBinding struct {
	Profile string
	Record  oodcanon.RecordValue
	Digest  string
}

// VerifiedCandidate is the only graph-publication input. Closure verification
// must establish that CertificateKey/Digest, manifests and immutable records
// are one complete persisted OOD closure. The publisher repeats persistence
// and strong-read checks; it does not invent evidence authority.
type VerifiedCandidate struct {
	OrganizationID                string
	SnapshotKind                  string
	MaterializationProfileID      string
	MaterializationProfileVersion string
	MaterializationProfileDigest  string
	ClosureHash                   string
	CertificateKey                string
	CertificateDigest             string
	Records                       []ImmutableRecord
	Manifests                     []Manifest
	CanonicalDigestBindings       []CanonicalDigestBinding
}

// CandidateVerifier is supplied by the evidence owner. It must reject a
// forged or incomplete candidate before publication starts.
type CandidateVerifier interface {
	VerifyCandidate(context.Context, VerifiedCandidate) error
}

type verifiedClosureVerifier struct{ proof oodevidence.VerifiedClosureV8 }

func (v verifiedClosureVerifier) VerifyCandidate(_ context.Context, c VerifiedCandidate) error {
	if err := oodevidence.ValidateVerifiedClosureV8(v.proof); err != nil {
		return err
	}
	if c.OrganizationID != v.proof.OrganizationID() || c.CertificateKey != v.proof.CertificateID() || c.CertificateDigest != v.proof.CertificateHash() {
		return errors.New("candidate does not match verified closure certificate")
	}
	return nil
}

// PublishVerified is the production publication entry point. Its proof is
// opaque and can only originate with oodevidence.VerifyClosureV8 after the
// protected strong-read traversal and attestation check. Publish remains the
// lower-level mechanism seam for deterministic storage tests.
func PublishVerified(ctx context.Context, store Store, proof oodevidence.VerifiedClosureV8, candidate VerifiedCandidate, snapshotKey, runKey string) (Outcome, error) {
	return Publish(ctx, store, verifiedClosureVerifier{proof: proof}, candidate, snapshotKey, runKey)
}

// Head is the compact mutable organization publication coordinate. All graph
// and evidence facts are immutable; this is the only record advanced by a new
// snapshot.
type Head struct {
	SnapshotKind string
	Generation   int64
	GraphVersion int64
	SnapshotKey  string
	ClosureHash  string
}

type Snapshot struct {
	Key          string
	Generation   int64
	GraphVersion int64
	ClosureHash  string
	State        string
}

type Run struct {
	Key         string
	SnapshotKey string
	ClosureHash string
	State       string
}

type Outcome struct {
	SnapshotKey  string
	RunKey       string
	Generation   int64
	GraphVersion int64
	Replay       bool
}

// PublicationState is the organization-wide allocator fence. Snapshot-head
// generations are per kind; graph version and publication generation are
// organization-wide and cannot be allocated by scanning snapshots.
type PublicationState struct {
	GraphVersion          int64
	PublicationGeneration int64
	LastSnapshotKey       string
	LastSnapshotKind      string
}

// Store separates immutable writes and strong reads from the bounded head
// transaction. An implementation may use Spanner, but cannot turn a callback
// success into a publication: exact re-reads and the transaction state decide
// the result.
type Store interface {
	PutImmutable(ctx context.Context, record ImmutableRecord) error
	ReadImmutable(ctx context.Context, kind, key string) (ImmutableRecord, error)
	ReadHead(ctx context.Context, organizationID, snapshotKind string) (Head, bool, error)
	ReadPublicationState(ctx context.Context, organizationID string) (PublicationState, bool, error)
	ReadSnapshot(ctx context.Context, key string) (Snapshot, bool, error)
	ReadRun(ctx context.Context, key string) (Run, bool, error)
	ReadWrite(ctx context.Context, fn func(Tx) error) error
	ProjectMembership(ctx context.Context, snapshotKey string, manifests []Manifest) error
}

// Tx is intentionally narrow. It has no corpus enumeration operation, keeping
// the CAS transaction bounded to one head, one snapshot and one run.
type Tx interface {
	ReadHead(organizationID, snapshotKind string) (Head, bool, error)
	ReadPublicationState(organizationID string) (PublicationState, bool, error)
	ReadSnapshot(key string) (Snapshot, bool, error)
	PutSnapshot(Snapshot) error
	PutRun(Run) error
	PutHead(organizationID string, value Head) error
	PutPublicationState(organizationID string, value PublicationState) error
}

func validateCandidate(c VerifiedCandidate) error {
	if c.OrganizationID == "" || c.SnapshotKind == "" || c.MaterializationProfileID == "" || c.MaterializationProfileVersion == "" || c.MaterializationProfileDigest == "" || c.ClosureHash == "" || c.CertificateKey == "" || c.CertificateDigest == "" {
		return errors.New("publication candidate is missing required closure or materialization binding")
	}
	if len(c.Records) == 0 || len(c.Manifests) != len(requiredManifestNames) {
		return errors.New("publication candidate does not carry the complete immutable closure")
	}
	seen := map[string]bool{}
	for _, m := range c.Manifests {
		if m.Name == "" || m.Key == "" || m.Digest == "" || len(m.Raw) == 0 || seen[m.Name] {
			return errors.New("publication manifests are incomplete or duplicate")
		}
		seen[m.Name] = true
	}
	for _, name := range requiredManifestNames {
		if !seen[name] {
			return fmt.Errorf("missing required manifest %q", name)
		}
	}
	for _, r := range c.Records {
		if r.Kind == "" || r.Key == "" || len(r.Raw) == 0 {
			return errors.New("publication immutable record is incomplete")
		}
	}
	for _, binding := range c.CanonicalDigestBindings {
		profile, err := oodcanon.ProfileFor(binding.Profile)
		if err != nil {
			return fmt.Errorf("publication canonical profile %q: %w", binding.Profile, err)
		}
		actual, err := oodcanon.DigestHexOf(profile, binding.Record)
		if err != nil || actual != binding.Digest {
			return fmt.Errorf("publication canonical digest %q does not verify", binding.Profile)
		}
	}
	return nil
}

func immutableKey(kind, key string) string { return kind + "\x00" + key }

// Publish carries out OOD v8's immutable-first then bounded-CAS sequence.
// snapshotKey and runKey must be unique candidate identities chosen by the
// verified materializer; this function never synthesizes identity.
func Publish(ctx context.Context, store Store, verifier CandidateVerifier, candidate VerifiedCandidate, snapshotKey, runKey string) (Outcome, error) {
	if ctx == nil || store == nil || verifier == nil || snapshotKey == "" || runKey == "" {
		return Outcome{}, errors.New("publication requires context, store, verifier, snapshot key, and run key")
	}
	if err := validateCandidate(candidate); err != nil {
		return Outcome{}, err
	}
	if err := verifier.VerifyCandidate(ctx, candidate); err != nil {
		return Outcome{}, fmt.Errorf("verify OOD closure: %w", err)
	}
	if err := persistAndStrongRead(ctx, store, candidate); err != nil {
		return Outcome{}, err
	}

	var outcome Outcome
	err := store.ReadWrite(ctx, func(tx Tx) error {
		state, hasState, err := tx.ReadPublicationState(candidate.OrganizationID)
		if err != nil {
			return err
		}
		head, hasHead, err := tx.ReadHead(candidate.OrganizationID, candidate.SnapshotKind)
		if err != nil {
			return err
		}
		if hasHead && head.ClosureHash == candidate.ClosureHash {
			snapshot, ok, err := tx.ReadSnapshot(head.SnapshotKey)
			if err != nil {
				return err
			}
			if !ok || snapshot.State != "sealed" || snapshot.ClosureHash != candidate.ClosureHash {
				return errors.New("head does not resolve to matching sealed snapshot")
			}
			outcome = Outcome{SnapshotKey: snapshot.Key, RunKey: runKey, Generation: head.Generation, GraphVersion: head.GraphVersion, Replay: true}
			return tx.PutRun(Run{Key: runKey, SnapshotKey: snapshot.Key, ClosureHash: candidate.ClosureHash, State: "exact_replay_noop"})
		}
		generation := int64(1)
		if hasHead {
			generation = head.Generation + 1
		}
		graphVersion, publicationGeneration := int64(1), int64(1)
		if hasState {
			graphVersion, publicationGeneration = state.GraphVersion+1, state.PublicationGeneration+1
		}
		existing, exists, err := tx.ReadSnapshot(snapshotKey)
		if err != nil {
			return err
		}
		if exists {
			if existing.State != "sealed" || existing.ClosureHash != candidate.ClosureHash || existing.Generation != generation {
				return errors.New("snapshot identity collision")
			}
			return errors.New("sealed snapshot is not current exact replay")
		}
		snapshot := Snapshot{Key: snapshotKey, Generation: generation, GraphVersion: graphVersion, ClosureHash: candidate.ClosureHash, State: "sealed"}
		if err := tx.PutSnapshot(snapshot); err != nil {
			return err
		}
		if err := tx.PutRun(Run{Key: runKey, SnapshotKey: snapshotKey, ClosureHash: candidate.ClosureHash, State: "sealed"}); err != nil {
			return err
		}
		if err := tx.PutHead(candidate.OrganizationID, Head{SnapshotKind: candidate.SnapshotKind, Generation: generation, GraphVersion: graphVersion, SnapshotKey: snapshotKey, ClosureHash: candidate.ClosureHash}); err != nil {
			return err
		}
		if err := tx.PutPublicationState(candidate.OrganizationID, PublicationState{GraphVersion: graphVersion, PublicationGeneration: publicationGeneration, LastSnapshotKey: snapshotKey, LastSnapshotKind: candidate.SnapshotKind}); err != nil {
			return err
		}
		outcome = Outcome{SnapshotKey: snapshotKey, RunKey: runKey, Generation: generation, GraphVersion: graphVersion}
		return nil
	})
	if err != nil {
		return Outcome{}, fmt.Errorf("seal bounded publication head: %w", err)
	}
	// Projection follows sealing. It cannot influence the immutable closure or
	// head and failure is visible to the caller rather than being hidden.
	if err := store.ProjectMembership(ctx, outcome.SnapshotKey, candidate.Manifests); err != nil {
		return Outcome{}, fmt.Errorf("project sealed snapshot membership: %w", err)
	}
	return outcome, nil
}

func persistAndStrongRead(ctx context.Context, store Store, c VerifiedCandidate) error {
	records := append([]ImmutableRecord(nil), c.Records...)
	for _, m := range c.Manifests {
		records = append(records, ImmutableRecord{Kind: "manifest:" + m.Name, Key: m.Key, Raw: m.Raw})
	}
	records = append(records, ImmutableRecord{Kind: "closure_certificate", Key: c.CertificateKey, Raw: []byte(c.CertificateDigest)})
	sort.Slice(records, func(i, j int) bool {
		return immutableKey(records[i].Kind, records[i].Key) < immutableKey(records[j].Kind, records[j].Key)
	})
	seen := map[string]bool{}
	for _, r := range records {
		k := immutableKey(r.Kind, r.Key)
		if seen[k] {
			return fmt.Errorf("duplicate immutable record %q", k)
		}
		seen[k] = true
		if err := store.PutImmutable(ctx, r); err != nil {
			return fmt.Errorf("put immutable %s: %w", r.Kind, err)
		}
		persisted, err := store.ReadImmutable(ctx, r.Kind, r.Key)
		if err != nil {
			return fmt.Errorf("strong-read immutable %s: %w", r.Kind, err)
		}
		if !bytes.Equal(persisted.Raw, r.Raw) {
			return fmt.Errorf("persisted immutable %s does not match canonical bytes", r.Kind)
		}
	}
	return nil
}

// MemoryStore is a deterministic concrete Store for tests and offline
// preparation. It is deliberately not a production authority adapter.
type MemoryStore struct {
	mu             sync.Mutex
	immutable      map[string]ImmutableRecord
	heads          map[string]Head
	states         map[string]PublicationState
	snapshots      map[string]Snapshot
	runs           map[string]Run
	projected      map[string][]Manifest
	FailProjection error
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{immutable: map[string]ImmutableRecord{}, heads: map[string]Head{}, states: map[string]PublicationState{}, snapshots: map[string]Snapshot{}, runs: map[string]Run{}, projected: map[string][]Manifest{}}
}
func (s *MemoryStore) PutImmutable(_ context.Context, r ImmutableRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := immutableKey(r.Kind, r.Key)
	if old, ok := s.immutable[k]; ok {
		if !bytes.Equal(old.Raw, r.Raw) {
			return errors.New("immutable record collision")
		}
		return nil
	}
	r.Raw = append([]byte(nil), r.Raw...)
	s.immutable[k] = r
	return nil
}
func (s *MemoryStore) ReadImmutable(_ context.Context, kind, key string) (ImmutableRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.immutable[immutableKey(kind, key)]
	if !ok {
		return ImmutableRecord{}, errors.New("immutable record missing")
	}
	r.Raw = append([]byte(nil), r.Raw...)
	return r, nil
}
func headKey(org, kind string) string { return org + "\x00" + kind }
func (s *MemoryStore) ReadHead(_ context.Context, org, kind string) (Head, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.heads[headKey(org, kind)]
	return x, ok, nil
}
func (s *MemoryStore) ReadPublicationState(_ context.Context, org string) (PublicationState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.states[org]
	return x, ok, nil
}
func (s *MemoryStore) ReadSnapshot(_ context.Context, key string) (Snapshot, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.snapshots[key]
	return x, ok, nil
}
func (s *MemoryStore) ReadRun(_ context.Context, key string) (Run, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.runs[key]
	return x, ok, nil
}
func (s *MemoryStore) ReadWrite(_ context.Context, fn func(Tx) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn((*memoryTx)(s))
}
func (s *MemoryStore) ProjectMembership(_ context.Context, snapshot string, manifests []Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailProjection != nil {
		return s.FailProjection
	}
	if _, ok := s.snapshots[snapshot]; !ok {
		return errors.New("cannot project missing snapshot")
	}
	s.projected[snapshot] = append([]Manifest(nil), manifests...)
	return nil
}

type memoryTx MemoryStore

func (t *memoryTx) ReadHead(org, kind string) (Head, bool, error) {
	x, ok := t.heads[headKey(org, kind)]
	return x, ok, nil
}
func (t *memoryTx) ReadPublicationState(org string) (PublicationState, bool, error) {
	x, ok := t.states[org]
	return x, ok, nil
}
func (t *memoryTx) ReadSnapshot(k string) (Snapshot, bool, error) {
	x, ok := t.snapshots[k]
	return x, ok, nil
}
func (t *memoryTx) PutSnapshot(x Snapshot) error {
	if _, ok := t.snapshots[x.Key]; ok {
		return errors.New("snapshot exists")
	}
	t.snapshots[x.Key] = x
	return nil
}
func (t *memoryTx) PutRun(x Run) error {
	if old, ok := t.runs[x.Key]; ok && old != x {
		return errors.New("run collision")
	}
	t.runs[x.Key] = x
	return nil
}
func (t *memoryTx) PutHead(org string, x Head) error {
	if x.SnapshotKind == "" {
		return errors.New("head snapshot kind is empty")
	}
	t.heads[headKey(org, x.SnapshotKind)] = x
	return nil
}
func (t *memoryTx) PutPublicationState(org string, x PublicationState) error {
	if x.GraphVersion < 1 || x.PublicationGeneration < 1 {
		return errors.New("publication generations must be positive")
	}
	t.states[org] = x
	return nil
}

// ManifestNames returns a copy so callers cannot mutate the closure contract.
func ManifestNames() []string { return append([]string(nil), requiredManifestNames...) }
func (c VerifiedCandidate) String() string {
	return strings.Join([]string{c.OrganizationID, c.ClosureHash}, "/")
}
