package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRootPureCanonicalEmbeddingAndProjection(t *testing.T) {
	sub := ArtifactSubmission{NodeKind: "concept", StableID: "stable", Contract: map[string]interface{}{"z": "last", "a": "first"}, Payload: map[string]interface{}{"count": float64(2)}}
	got, err := canonicalEmbedText(sub)
	if err != nil {
		t.Fatalf("canonicalEmbedText: %v", err)
	}
	want := `{"contract":{"a":"first","z":"last"},"node_kind":"concept","payload":{"count":2},"stable_id":"stable"}`
	if got != want {
		t.Fatalf("canonical embed text = %s, want %s", got, want)
	}

	when := time.Date(2026, 9, 9, 1, 2, 3, 0, time.UTC)
	node := Node{NodeID: "node-1", NodeKind: "concept", OrganizationID: "org-1", Status: "active", CurrentVersion: NodeVersion{Version: 2, Contract: map[string]interface{}{"b": true}, Payload: map[string]interface{}{"a": "payload"}, DefinitionHash: "definition", ManifestHash: "manifest", AdmittedAt: when, AdmittedBy: "principal"}}
	first, err := renderDocCanonicalJSON(context.Background(), node, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	second, err := renderDocCanonicalJSON(context.Background(), node, []Node{{NodeID: "ignored"}})
	if err != nil {
		t.Fatalf("second render: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("render must be closure-independent: %s != %s", first, second)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("decode render: %v", err)
	}
	if decoded["node_id"] != "node-1" || decoded["version"] != float64(2) {
		t.Fatalf("render lost identity: %#v", decoded)
	}

	registry := newProjectionRegistry([]ProjectionDescriptor{{Name: "doc_canonical_json", OwningSpec: "SPEC"}, {Name: "future", OwningSpec: "FUTURE"}})
	all, err := registry.All(context.Background())
	if err != nil || !reflect.DeepEqual(map[string]bool{all[0]: true, all[1]: true}, map[string]bool{"doc_canonical_json": true, "future": true}) {
		t.Fatalf("all projections = %#v, %v", all, err)
	}
	p, err := registry.Resolve(context.Background(), "doc_canonical_json")
	if err != nil || p.Name() != "doc_canonical_json" || p.OwningSpec() != "SPEC" {
		t.Fatalf("resolve builtin = %#v, %v", p, err)
	}
	if _, err := p.Render(context.Background(), node, nil); err != nil {
		t.Fatalf("builtin render: %v", err)
	}
	future, err := registry.Resolve(context.Background(), "future")
	if err != nil {
		t.Fatalf("resolve future: %v", err)
	}
	if _, err := future.Render(context.Background(), node, nil); !errors.Is(err, ErrSchemaPending) || !strings.Contains(err.Error(), "FUTURE") {
		t.Fatalf("future render = %v", err)
	}
	if _, err := registry.Resolve(context.Background(), "missing"); err == nil {
		t.Fatal("missing projection resolved")
	}
}

func TestRootPureNodeKindRegistryAndErrors(t *testing.T) {
	raw := map[string]interface{}{"name": "external_reference_doc", "substrate_id": "ood", "artifact_type": "document", "version_scope": "source", "projection_role": "structured_ood_json", "source_authority": bootstrapSourceAuthority, "source_coordinate_policy": sourceCoordinatePolicyExternalReferenceRequired, "projections": []interface{}{"doc", 3}, "pre_sign_passes": []interface{}{"lint"}, "post_sign_passes": []interface{}{"sign"}, "dual_control_required": true, "future_protocol_key": map[string]interface{}{"kept": true}}
	d := NewNodeKindDescriptor(raw)
	if err := d.Validate(0); err != nil {
		t.Fatalf("valid descriptor: %v", err)
	}
	if !d.ExternalReferenceRequired() || !d.DualControlRequired() || !reflect.DeepEqual(d.Projections(), []string{"doc"}) || !reflect.DeepEqual(d.PreSignPasses(), []string{"lint"}) || !reflect.DeepEqual(d.PostSignPasses(), []string{"sign"}) {
		t.Fatalf("accessors lost metadata: %#v", d.Raw())
	}
	if d.Raw()["future_protocol_key"].(map[string]interface{})["kept"] != true {
		t.Fatal("raw protocol data was lost")
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal descriptor: %v", err)
	}
	var roundTrip NodeKindDescriptor
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || roundTrip.Name() != d.Name() {
		t.Fatalf("round trip: %v %#v", err, roundTrip.Raw())
	}
	if NewNodeKindDescriptor(nil).Raw() == nil {
		t.Fatal("nil raw must expose empty map")
	}
	if err := NewNodeKindDescriptor(map[string]interface{}{"name": "x"}).Validate(3); err == nil {
		t.Fatal("incomplete descriptor validated")
	}
	if err := NewNodeKindDescriptor(map[string]interface{}{"name": "x", "substrate_id": "s", "artifact_type": "a", "version_scope": "v", "projection_role": "p", "source_coordinate_policy": "wrong"}).Validate(1); err == nil {
		t.Fatal("unknown source policy validated")
	}

	registry := newKindRegistry([]NodeKindDescriptor{d})
	all, err := registry.All(context.Background())
	if err != nil || len(all) != 1 || all[0].Name() != d.Name() {
		t.Fatalf("all kinds: %#v %v", all, err)
	}
	if _, err := registry.Resolve(context.Background(), d.Name()); err != nil {
		t.Fatalf("resolve known: %v", err)
	}
	if _, err := registry.Resolve(context.Background(), "unknown"); !errors.Is(err, ErrUnknownNodeKind) {
		t.Fatalf("resolve unknown = %v", err)
	}

	duplicate := DuplicateCanonicalNameDetail{NodeKind: "concept", CanonicalName: "name", ExistingNodeID: "id", ExistingVersion: 4}
	if !errors.Is(duplicate, ErrDuplicateCanonicalName) || !strings.Contains(duplicate.Error(), "version 4") {
		t.Fatalf("duplicate detail = %v", duplicate)
	}
	possible := PossibleDuplicateDetail{Threshold: .25, Candidates: []PossibleDuplicateCandidate{{NodeID: "a"}, {NodeID: "b"}}}
	if !errors.Is(possible, ErrPossibleDuplicate) || !strings.Contains(possible.Error(), "[a b]") || !reflect.DeepEqual(candidateIDs(possible.Candidates), []string{"a", "b"}) {
		t.Fatalf("possible detail = %v", possible)
	}
	pending := SchemaPendingDetail{Step: "stage", Needs: "DDL", OwnerSpec: "OWNER"}
	missing := SubstrateNotProvisionedDetail{Substrate: "graph", NeededDDL: "CREATE TABLE"}
	if !errors.Is(pending, ErrSchemaPending) || !strings.Contains(pending.Error(), "OWNER") || !errors.Is(missing, ErrSubstrateNotProvisioned) || !strings.Contains(missing.Error(), "graph") {
		t.Fatalf("structured errors not informative: %v / %v", pending, missing)
	}
}

func TestRootPureValidationAndSourceCoordinateHelpers(t *testing.T) {
	if got := framedIdentity("ab", "c"); got != "2:ab1:c" {
		t.Fatalf("framed identity = %q", got)
	}
	if got := framedIdentityMap(map[string]interface{}{"b": float64(2), "a": "one"}); got != `{"a":"one","b":2}` {
		t.Fatalf("framed map = %q", got)
	}
	for _, tc := range []struct {
		in   interface{}
		want int64
		ok   bool
	}{{int64(3), 3, true}, {int(4), 4, true}, {float64(5), 5, true}, {float64(5.5), 0, false}, {math.Inf(1), 0, false}, {"5", 0, false}} {
		got, ok := numericInt64(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("numericInt64(%#v) = %d,%t", tc.in, got, ok)
		}
	}
	if got := sortedMapKeys(map[string]interface{}{"z": nil, "a": nil, "m": nil}); !reflect.DeepEqual(got, []string{"a", "m", "z"}) {
		t.Fatalf("sorted keys = %#v", got)
	}
	if err := validateEmbeddingBinding(make([]float32, externalReferenceEmbeddingDimensions), "model"); err != nil {
		t.Fatalf("valid embedding: %v", err)
	}
	bad := make([]float32, externalReferenceEmbeddingDimensions)
	bad[1] = float32(math.NaN())
	if err := validateEmbeddingBinding(bad, "model"); err == nil {
		t.Fatal("NaN embedding validated")
	}
	if err := validateEmbeddingBinding(nil, ""); err == nil {
		t.Fatal("empty embedding validated")
	}

	validRun := MaterializationBatch{Run: MaterializationRun{OrganizationID: "org", MaterializationRunID: "8d6d3e2b-a3a3-4c36-9cb2-5f56c59406fb", RunKind: "corpus_refresh", State: "running", Status: "active", VisibilityScope: "tenant"}, Snapshot: GraphSnapshot{OrganizationID: "org", GraphSnapshotID: "48b7d3e7-0e35-4916-a7d1-e5b142ec28a5", SnapshotKind: "active_candidate", SnapshotState: "building", Status: "active", VisibilityScope: "tenant"}}
	if err := validateCompleteEnvelope(validRun); err != nil {
		t.Fatalf("valid envelope: %v", err)
	}
	invalid := validRun
	invalid.Snapshot.OrganizationID = "other"
	if err := validateCompleteEnvelope(invalid); err == nil {
		t.Fatal("inconsistent envelope validated")
	}
	if err := validateSourceIdentity(bootstrapSourceAuthority, "official_source_repository", "coordinate", "https://example.test/repo", "unversioned", "$", "", ""); err != nil {
		t.Fatalf("valid source identity: %v", err)
	}
	if err := validateSourceIdentity("bad", "Bad", "unknown", " value ", "bad", "not-path", "hash", ""); err == nil {
		t.Fatal("invalid source identity validated")
	}

	if got, err := composeSourceSectionPath("$", "$.contract"); err != nil || got != "$.contract" {
		t.Fatalf("root compose = %q,%v", got, err)
	}
	if got, err := composeSourceSectionPath("$.source", "$"); err != nil || got != "$.source" {
		t.Fatalf("source root compose = %q,%v", got, err)
	}
	if got, err := composeSourceSectionPath("$.source", "$.contract"); err != nil || got != "$.source.contract" {
		t.Fatalf("joined compose = %q,%v", got, err)
	}
	if _, err := composeSourceSectionPath("bad", "$"); err == nil {
		t.Fatal("invalid root composed")
	}

	c := externalReferenceCoordinate("")
	null, err := sourceCoordinateToNullJSON(c)
	if err != nil || !null.Valid {
		t.Fatalf("to null json: %#v %v", null, err)
	}
	back, err := sourceCoordinateFromJSON(null.Value)
	if err != nil || !reflect.DeepEqual(back, c) {
		t.Fatalf("from null json: %#v %v", back, err)
	}
	nilNull, err := sourceCoordinateToNullJSON(nil)
	if err != nil || nilNull.Valid {
		t.Fatalf("nil coordinate: %#v %v", nilNull, err)
	}
	if absent, err := sourceCoordinateFromJSON(nil); err != nil || absent != nil {
		t.Fatalf("nil decode: %#v %v", absent, err)
	}
	if _, err := sourceCoordinateFromJSON(map[string]interface{}{"unknown": true}); err == nil {
		t.Fatal("unknown source coordinate field accepted")
	}
}
