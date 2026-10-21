package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type ceremonyCommitAdapter struct {
	*fakeAdapter
	plans   []AdmissionPlan
	records []AdmissionRecord
	err     error
}

func (a *ceremonyCommitAdapter) CommitAdmission(_ context.Context, plans ...AdmissionPlan) ([]AdmissionRecord, error) {
	a.plans = append(a.plans, plans...)
	if a.err != nil {
		return nil, a.err
	}
	if a.records != nil {
		return a.records, nil
	}
	records := make([]AdmissionRecord, len(plans))
	for i := range plans {
		records[i] = plans[i].Record
	}
	return records, nil
}

type ceremonyRouter struct {
	adapter SubstrateAdapter
	all     []SubstrateAdapter
	err     error
}

func (r ceremonyRouter) Adapter(context.Context, NodeKindDescriptor) (SubstrateAdapter, error) {
	return r.adapter, r.err
}
func (r ceremonyRouter) All(context.Context) ([]SubstrateAdapter, error) { return r.all, r.err }
func (r ceremonyRouter) ByID(string) (SubstrateAdapter, error)           { return r.adapter, r.err }
func (r ceremonyRouter) Close() error                                    { return r.err }

type ceremonyEmbedder struct {
	calls int
	text  string
	task  string
	vec   []float32
	err   error
}

func (e *ceremonyEmbedder) Embed(_ context.Context, text, task string) ([]float32, error) {
	e.calls++
	e.text = text
	e.task = task
	return e.vec, e.err
}

func newCeremonyEnv(adapter SubstrateAdapter) *Env {
	return &Env{
		Config: SpecGraphConfig{
			Mode:                 ModeExperimentalBootstrap,
			ExperimentalAdmitter: "EXPERIMENTAL",
			GenesisAdmitter:      "GENESIS",
		},
		Kinds:      fakeKinds{},
		Substrates: ceremonyRouter{adapter: adapter, all: []SubstrateAdapter{adapter}},
		Now:        func() time.Time { return time.Date(2026, 9, 9, 12, 30, 0, 123, time.FixedZone("test", -4*60*60)) },
	}
}

func ceremonyNodeSubmission() ArtifactSubmission {
	return ArtifactSubmission{
		ArtifactType:   "section",
		OrganizationID: "org-test",
		NodeKind:       "section",
		Contract:       map[string]interface{}{"canonical_name": "coverage.ceremony"},
		Payload:        map[string]interface{}{"title": "Ceremony coverage"},
		GoverningSpec:  "spec://coverage",
		SpecSection:    "admission",
	}
}

func TestPrepareAdmissionPlanMintsIdentityBeforeHashAndSignature(t *testing.T) {
	env := newCeremonyEnv(nil)
	plan, err := PrepareAdmissionPlan(context.Background(), env, ceremonyNodeSubmission())
	if err != nil {
		t.Fatalf("PrepareAdmissionPlan: %v", err)
	}
	if plan.Record.ArtifactID == "" || plan.Node == nil || plan.Node.NodeID != plan.Record.ArtifactID {
		t.Fatalf("minted identity was not propagated: record=%q node=%#v", plan.Record.ArtifactID, plan.Node)
	}

	sub := ceremonyNodeSubmission()
	sub.StableID = plan.Record.ArtifactID
	wantDefinition, err := stepDefinitionHash(context.Background(), env, sub)
	if err != nil {
		t.Fatalf("stepDefinitionHash: %v", err)
	}
	if plan.Record.DefinitionHash != wantDefinition {
		t.Fatalf("definition hash does not bind minted identity: got %q want %q", plan.Record.DefinitionHash, wantDefinition)
	}
	wantSignature, err := stepSign(context.Background(), env, sub, &plan.Record)
	if err != nil {
		t.Fatalf("stepSign: %v", err)
	}
	if len(plan.Record.SignatureChain) != 1 || plan.Record.SignatureChain[0] != wantSignature {
		t.Fatalf("signature does not bind minted identity: got %#v want %q", plan.Record.SignatureChain, wantSignature)
	}
	if plan.Record.IsNonGenesis {
		t.Fatal("experimental admitter must be classified as genesis")
	}
	if !plan.Record.AdmittedAt.Equal(env.Now().UTC()) {
		t.Fatalf("admitted_at = %v, want %v", plan.Record.AdmittedAt, env.Now().UTC())
	}
}

func TestPrepareAdmissionPlanBuildsVersionedNodeEdgeAndEmbedding(t *testing.T) {
	t.Run("versioned active node embeds", func(t *testing.T) {
		embed := &ceremonyEmbedder{vec: []float32{0.25, 0.75}}
		env := newCeremonyEnv(nil)
		env.Embed = embed
		sub := ceremonyNodeSubmission()
		sub.StableID = "node-1"
		sub.PriorVersion = &NodeVersion{NodeID: "node-1", Version: 4}

		plan, err := PrepareAdmissionPlan(context.Background(), env, sub)
		if err != nil {
			t.Fatalf("PrepareAdmissionPlan: %v", err)
		}
		if plan.IsEdge || plan.Node == nil || plan.Node.Version != 5 || plan.Node.Status != "active" {
			t.Fatalf("unexpected node plan: %#v", plan)
		}
		if embed.calls != 1 || embed.text == "" || embed.task != "RETRIEVAL_DOCUMENT" {
			t.Fatalf("embedding call = (%d, %q, %q)", embed.calls, embed.text, embed.task)
		}
		if len(plan.Node.EmbeddingV2) != 2 || plan.Node.EmbeddingV2[1] != 0.75 {
			t.Fatalf("embedding = %#v", plan.Node.EmbeddingV2)
		}
	})

	t.Run("retired edge preserves endpoints and skips embedding", func(t *testing.T) {
		embed := &ceremonyEmbedder{err: errors.New("must not embed retirement")}
		env := newCeremonyEnv(nil)
		env.Embed = embed
		plan, err := PrepareAdmissionPlan(context.Background(), env, ArtifactSubmission{
			ArtifactType:      "edge",
			OrganizationID:    "org-test",
			EdgeLabel:         "depends_on",
			EdgeSourceID:      "source",
			EdgeTargetID:      "target",
			EdgeSourceVersion: 2,
			EdgeTargetVersion: 3,
			StableID:          "edge-1",
			IsRetirement:      true,
		})
		if err != nil {
			t.Fatalf("PrepareAdmissionPlan: %v", err)
		}
		if !plan.IsEdge || !plan.IsRetirement || plan.Edge == nil || plan.Edge.Status != "retired" {
			t.Fatalf("unexpected edge plan: %#v", plan)
		}
		if plan.Edge.SourceID != "source" || plan.Edge.SourceVersion != 2 || plan.Edge.TargetID != "target" || plan.Edge.TargetVersion != 3 {
			t.Fatalf("edge endpoints were not preserved: %#v", plan.Edge)
		}
		if embed.calls != 0 {
			t.Fatalf("retirement invoked embedder %d times", embed.calls)
		}
	})

	t.Run("retired node skips embedding", func(t *testing.T) {
		embed := &ceremonyEmbedder{err: errors.New("must not embed retirement")}
		env := newCeremonyEnv(nil)
		env.Embed = embed
		sub := ceremonyNodeSubmission()
		sub.StableID = "node-retired"
		sub.IsRetirement = true
		plan, err := PrepareAdmissionPlan(context.Background(), env, sub)
		if err != nil {
			t.Fatalf("PrepareAdmissionPlan: %v", err)
		}
		if plan.Node == nil || plan.Node.Status != "retired" || embed.calls != 0 {
			t.Fatalf("retired node plan = %#v, embed calls = %d", plan.Node, embed.calls)
		}
	})
}

func TestPrepareAdmissionPlanRejectsInvalidCeremonyInputs(t *testing.T) {
	tests := []struct {
		name string
		env  *Env
		sub  ArtifactSubmission
		want string
	}{
		{name: "nil env", sub: ceremonyNodeSubmission(), want: "nil env"},
		{name: "missing shape", env: newCeremonyEnv(nil), sub: ArtifactSubmission{}, want: "neither node_kind nor edge_label"},
		{name: "unsupported contract value", env: newCeremonyEnv(nil), sub: ArtifactSubmission{NodeKind: "section", Contract: map[string]interface{}{"bad": make(chan int)}}, want: "step 4 definition_hash"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PrepareAdmissionPlan(context.Background(), tc.env, tc.sub)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}

	production := newCeremonyEnv(nil)
	production.Config.Mode = ModeProduction
	if _, err := PrepareAdmissionPlan(context.Background(), production, ceremonyNodeSubmission()); err == nil || !strings.Contains(err.Error(), "schema_validate") {
		t.Fatalf("production pending schema error = %v", err)
	}

	withoutAdmitter := newCeremonyEnv(nil)
	withoutAdmitter.Config.ExperimentalAdmitter = ""
	if _, err := PrepareAdmissionPlan(context.Background(), withoutAdmitter, ceremonyNodeSubmission()); err == nil || !strings.Contains(err.Error(), "resolve_admitter") {
		t.Fatalf("missing admitter error = %v", err)
	}

	withSubmitter := newCeremonyEnv(nil)
	withSubmitter.Config.ExperimentalAdmitter = ""
	sub := ceremonyNodeSubmission()
	sub.Submitter = "principal-1"
	plan, err := PrepareAdmissionPlan(context.Background(), withSubmitter, sub)
	if err != nil {
		t.Fatalf("submitter fallback: %v", err)
	}
	if plan.Record.AdmittedBy != "principal-1" || !plan.Record.IsNonGenesis {
		t.Fatalf("submitter admission = %#v", plan.Record)
	}
}

func TestAdmitArtifactCommitsResolvedNodeAndEdgePlans(t *testing.T) {
	t.Run("node success", func(t *testing.T) {
		adapter := &ceremonyCommitAdapter{fakeAdapter: &fakeAdapter{}}
		env := newCeremonyEnv(adapter)
		rec, err := AdmitArtifact(context.Background(), env, ceremonyNodeSubmission())
		if err != nil {
			t.Fatalf("AdmitArtifact: %v", err)
		}
		if rec.ArtifactID == "" || len(adapter.plans) != 1 || adapter.plans[0].Node == nil {
			t.Fatalf("record/commit plan = %#v / %#v", rec, adapter.plans)
		}
		if adapter.plans[0].Node.NodeID != rec.ArtifactID || adapter.plans[0].Record.ArtifactID != rec.ArtifactID {
			t.Fatalf("commit did not carry one identity: %#v", adapter.plans[0])
		}
	})

	t.Run("edge success", func(t *testing.T) {
		adapter := &ceremonyCommitAdapter{fakeAdapter: &fakeAdapter{}}
		env := newCeremonyEnv(adapter)
		rec, err := AdmitArtifact(context.Background(), env, ArtifactSubmission{
			ArtifactType:   "edge",
			OrganizationID: "org-test",
			EdgeLabel:      "depends_on",
			EdgeSourceID:   "source",
			EdgeTargetID:   "target",
			StableID:       "edge-1",
		})
		if err != nil {
			t.Fatalf("AdmitArtifact: %v", err)
		}
		if rec.ArtifactID != "edge-1" || len(adapter.plans) != 1 || !adapter.plans[0].IsEdge {
			t.Fatalf("record/edge plan = %#v / %#v", rec, adapter.plans)
		}
	})
}

func TestAdmitArtifactPropagatesRoutingAndCommitFailures(t *testing.T) {
	tests := []struct {
		name string
		env  *Env
		sub  ArtifactSubmission
		want string
	}{
		{name: "nil env", sub: ceremonyNodeSubmission(), want: "nil env"},
		{name: "adapter resolution", env: func() *Env {
			e := newCeremonyEnv(nil)
			e.Substrates = ceremonyRouter{err: errors.New("route failed")}
			return e
		}(), sub: ceremonyNodeSubmission(), want: "route failed"},
		{name: "edge substrate listing", env: func() *Env {
			e := newCeremonyEnv(nil)
			e.Substrates = ceremonyRouter{err: errors.New("list failed")}
			return e
		}(), sub: ArtifactSubmission{ArtifactType: "edge", OrganizationID: "org-test", EdgeLabel: "depends_on"}, want: "list failed"},
		{name: "no edge substrates", env: func() *Env { e := newCeremonyEnv(nil); e.Substrates = ceremonyRouter{}; return e }(), sub: ArtifactSubmission{ArtifactType: "edge", OrganizationID: "org-test", EdgeLabel: "depends_on"}, want: "no substrates registered"},
		{name: "commit error", env: newCeremonyEnv(&ceremonyCommitAdapter{fakeAdapter: &fakeAdapter{}, err: errors.New("commit failed")}), sub: ceremonyNodeSubmission(), want: "commit failed"},
		{name: "empty records", env: newCeremonyEnv(&ceremonyCommitAdapter{fakeAdapter: &fakeAdapter{}, records: []AdmissionRecord{}}), sub: ceremonyNodeSubmission(), want: "returned no records"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AdmitArtifact(context.Background(), tc.env, tc.sub)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestCeremonyStepContractsAndCanonicalJSON(t *testing.T) {
	env := newCeremonyEnv(nil)
	sub := ceremonyNodeSubmission()
	if err := stepSchemaValidate(context.Background(), env, sub); err != nil {
		t.Fatalf("experimental schema validation: %v", err)
	}
	if admitter, err := stepResolveAdmitter(context.Background(), env, sub); err != nil || admitter != "EXPERIMENTAL" {
		t.Fatalf("resolve admitter = %q, %v", admitter, err)
	}
	passes, err := stepRunPasses(context.Background(), env, sub, "pre_sign")
	if err != nil || len(passes) != 1 || passes[0].Outcome != "skipped" || !strings.Contains(passes[0].PassName, "pre_sign") {
		t.Fatalf("bootstrap passes = %#v, %v", passes, err)
	}

	production := newCeremonyEnv(nil)
	production.Config.Mode = ModeProduction
	if _, err := stepRunPasses(context.Background(), production, sub, "post_sign"); err == nil || !strings.Contains(err.Error(), "post_sign_passes") {
		t.Fatalf("production pass error = %v", err)
	}
	rec := AdmissionRecord{AdmittedAt: env.Now(), DefinitionHash: "definition", ManifestHash: "manifest"}
	if _, err := stepSign(context.Background(), production, sub, &rec); err == nil || !strings.Contains(err.Error(), "kms_sign") {
		t.Fatalf("production signing error = %v", err)
	}

	canonical, err := canonicalJSON(map[string]interface{}{
		"z": []interface{}{map[string]interface{}{"b": 2.0, "a": 1.0}, true},
		"a": "first",
	})
	if err != nil {
		t.Fatalf("canonicalJSON: %v", err)
	}
	if got, want := string(canonical), `{"a":"first","z":[{"a":1,"b":2},true]}`; got != want {
		t.Fatalf("canonical JSON = %s, want %s", got, want)
	}
	if _, err := canonicalJSON(map[string]interface{}{"bad": make(chan int)}); err == nil {
		t.Fatal("canonicalJSON accepted unsupported value")
	}
}
