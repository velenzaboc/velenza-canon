package oodpublication

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

type acceptingVerifier struct{ err error }

func (v acceptingVerifier) VerifyCandidate(context.Context, VerifiedCandidate) error { return v.err }

func candidate() VerifiedCandidate {
	manifests := make([]Manifest, 0, len(ManifestNames()))
	for _, name := range ManifestNames() {
		manifests = append(manifests, Manifest{Name: name, Key: "m/" + name, Digest: "digest/" + name, Raw: []byte("canonical/" + name)})
	}
	return VerifiedCandidate{OrganizationID: "org", SnapshotKind: "provider_documentation", MaterializationProfileID: "profile", MaterializationProfileVersion: "1", MaterializationProfileDigest: "profile-digest", ClosureHash: "closure-a", CertificateKey: "certificate/a", CertificateDigest: "certificate-digest", Records: []ImmutableRecord{{Kind: "receipt", Key: "receipt/a", Raw: []byte("receipt")}, {Kind: "graph_object", Key: "object/a", Raw: []byte("object")}}, Manifests: manifests}
}

func TestPublishSealsThenAdvancesBoundedHead(t *testing.T) {
	store := NewMemoryStore()
	c := candidate()
	got, err := Publish(context.Background(), store, acceptingVerifier{}, c, "snapshot/a", "run/a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Replay || got.Generation != 1 || got.SnapshotKey != "snapshot/a" {
		t.Fatalf("first outcome = %+v", got)
	}
	head, ok, err := store.ReadHead(context.Background(), "org", "provider_documentation")
	if err != nil || !ok || head.Generation != 1 || head.ClosureHash != c.ClosureHash {
		t.Fatalf("head = %+v %t %v", head, ok, err)
	}
	snapshot, ok, err := store.ReadSnapshot(context.Background(), "snapshot/a")
	if err != nil || !ok || snapshot.State != "sealed" {
		t.Fatalf("snapshot = %+v %t %v", snapshot, ok, err)
	}
	run, ok, err := store.ReadRun(context.Background(), "run/a")
	if err != nil || !ok || run.State != "sealed" {
		t.Fatalf("run = %+v %t %v", run, ok, err)
	}
	if got := len(store.projected["snapshot/a"]); got != 9 {
		t.Fatalf("projection manifests = %d", got)
	}
}

func TestPublishExactClosureIsReplayNotNewGeneration(t *testing.T) {
	store := NewMemoryStore()
	c := candidate()
	if _, err := Publish(context.Background(), store, acceptingVerifier{}, c, "snapshot/a", "run/a"); err != nil {
		t.Fatal(err)
	}
	got, err := Publish(context.Background(), store, acceptingVerifier{}, c, "unused-snapshot", "run/replay")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Replay || got.Generation != 1 || got.SnapshotKey != "snapshot/a" {
		t.Fatalf("replay = %+v", got)
	}
	run, ok, err := store.ReadRun(context.Background(), "run/replay")
	if err != nil || !ok || run.State != "exact_replay_noop" {
		t.Fatalf("replay run = %+v %t %v", run, ok, err)
	}
}

func TestPublishDifferentClosureCreatesSuccessor(t *testing.T) {
	store := NewMemoryStore()
	first := candidate()
	if _, err := Publish(context.Background(), store, acceptingVerifier{}, first, "snapshot/a", "run/a"); err != nil {
		t.Fatal(err)
	}
	second := candidate()
	second.ClosureHash = "closure-b"
	second.CertificateKey = "certificate/b"
	second.CertificateDigest = "certificate-digest-b"
	got, err := Publish(context.Background(), store, acceptingVerifier{}, second, "snapshot/b", "run/b")
	if err != nil {
		t.Fatal(err)
	}
	if got.Replay || got.Generation != 2 {
		t.Fatalf("successor = %+v", got)
	}
}

func TestPublishRejectsCandidateHoleForgeryAndCollision(t *testing.T) {
	for name, mutate := range map[string]func(*VerifiedCandidate){
		"missing manifest":        func(c *VerifiedCandidate) { c.Manifests = c.Manifests[:len(c.Manifests)-1] },
		"duplicate manifest":      func(c *VerifiedCandidate) { c.Manifests[1].Name = c.Manifests[0].Name },
		"missing immutable bytes": func(c *VerifiedCandidate) { c.Records[0].Raw = nil },
	} {
		t.Run(name, func(t *testing.T) {
			c := candidate()
			mutate(&c)
			if _, err := Publish(context.Background(), NewMemoryStore(), acceptingVerifier{}, c, "snapshot/a", "run/a"); err == nil {
				t.Fatal("invalid candidate was published")
			}
		})
	}
	store := NewMemoryStore()
	c := candidate()
	if _, err := Publish(context.Background(), store, acceptingVerifier{}, c, "snapshot/a", "run/a"); err != nil {
		t.Fatal(err)
	}
	c.ClosureHash = "changed"
	c.CertificateKey = "certificate/changed"
	if _, err := Publish(context.Background(), store, acceptingVerifier{}, c, "snapshot/a", "run/b"); err == nil {
		t.Fatal("snapshot identity collision accepted")
	}
}

func TestPublishFailsClosedForVerifierImmutableOrProjectionFailure(t *testing.T) {
	c := candidate()
	if _, err := Publish(context.Background(), NewMemoryStore(), acceptingVerifier{err: errors.New("bad certificate")}, c, "snapshot/a", "run/a"); err == nil {
		t.Fatal("unverified closure published")
	}
	store := NewMemoryStore()
	if err := store.PutImmutable(context.Background(), ImmutableRecord{Kind: "receipt", Key: "receipt/a", Raw: []byte("different")}); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(context.Background(), store, acceptingVerifier{}, c, "snapshot/a", "run/a"); err == nil {
		t.Fatal("immutable collision accepted")
	}
	store = NewMemoryStore()
	store.FailProjection = errors.New("projection unavailable")
	if _, err := Publish(context.Background(), store, acceptingVerifier{}, c, "snapshot/a", "run/a"); err == nil {
		t.Fatal("projection failure hidden")
	}
}

func TestPublishVerifiedRejectsAbsentOpaqueClosure(t *testing.T) {
	store := NewMemoryStore()
	if _, err := PublishVerified(context.Background(), store, oodevidence.VerifiedClosureV8{}, candidate(), "snapshot/a", "run/a"); err == nil {
		t.Fatal("publisher accepted a forged zero closure proof")
	}
	if _, ok, _ := store.ReadHead(context.Background(), "org", "provider_documentation"); ok {
		t.Fatal("publisher mutated a head before rejecting absent proof")
	}
}

func TestMemoryStoreConcurrentDifferentClosuresSerializesHead(t *testing.T) {
	store := NewMemoryStore()
	errs := make(chan error, 2)
	for i := range 2 {
		go func(i int) {
			c := candidate()
			c.ClosureHash = fmt.Sprintf("closure-%d", i)
			c.CertificateKey = fmt.Sprintf("certificate-%d", i)
			_, err := Publish(context.Background(), store, acceptingVerifier{}, c, fmt.Sprintf("snapshot-%d", i), fmt.Sprintf("run-%d", i))
			errs <- err
		}(i)
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	head, ok, err := store.ReadHead(context.Background(), "org", "provider_documentation")
	if err != nil || !ok || head.Generation != 2 {
		t.Fatalf("serialized head = %+v %t %v", head, ok, err)
	}
}
