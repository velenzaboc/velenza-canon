package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Regression suite for the spec_graph_import node_kind gate.
//
// handleImport writes OODGraphObjects.object_class verbatim from a
// submission's node_kind, so the closed NodeKindRegistry is the registry
// that governs object_class. Before this suite existed, ErrUnknownNodeKind
// appeared in ZERO test files: the gate could be deleted outright and the
// whole suite stayed green.
//
// Live-substrate context that motivates the assertions here: 214 of 255
// OODGraphObjects rows carry object_class='concept', a value declared in
// neither the 29-member node_kind registry nor OOD_GRAPH_PROTOCOL_v1
// s2_graph_object_model.object_class_registry_discipline.admissible_classes
// (18 members, registry_is_closed_for_v1=true). Those rows were written by
// an out-of-band ingest tool that never called this code path — but the
// gate that would refuse the same value HERE was itself unpinned, which is
// the defect these tests close.
//
// Every test runs under `go test ./...` with no Spanner emulator.

// recordingAdapter wraps the dedup_test.go fakeAdapter and records the
// substrate interactions handleImport performs, so a test can assert not
// merely "the call returned an error" but "nothing reached the substrate".
type recordingAdapter struct {
	*fakeAdapter
	schemaChecks int
	batches      []MaterializationBatch
	openedRuns   []MaterializationRun
	failedRuns   [][2]string
}

func (r *recordingAdapter) CheckOODGraphSchema(context.Context) error {
	r.schemaChecks++
	return nil
}

func (r *recordingAdapter) CommitMaterializationRun(_ context.Context, b MaterializationBatch) error {
	r.batches = append(r.batches, b)
	return nil
}

// openedRuns / failedRuns record the §8 stage-1 and failure-path calls so a
// test can assert that a run row is opened BEFORE the batch commits and
// marked failed when the commit is refused — the audit evidence
// §8.idempotency_and_replay_safety.abandoned_run_rule presupposes.
func (r *recordingAdapter) OpenMaterializationRun(_ context.Context, run MaterializationRun) error {
	r.openedRuns = append(r.openedRuns, run)
	return nil
}

func (r *recordingAdapter) FailMaterializationRun(_ context.Context, orgID, runID string) error {
	r.failedRuns = append(r.failedRuns, [2]string{orgID, runID})
	return nil
}

// admittedObjectClasses flattens every object_class that actually reached
// the substrate across all committed batches.
func (r *recordingAdapter) admittedObjectClasses() []string {
	var out []string
	for _, b := range r.batches {
		for _, o := range b.Objects {
			out = append(out, o.ObjectClass)
		}
	}
	return out
}

type recordingRouter struct{ a SubstrateAdapter }

func (r *recordingRouter) Adapter(context.Context, NodeKindDescriptor) (SubstrateAdapter, error) {
	return r.a, nil
}
func (r *recordingRouter) All(context.Context) ([]SubstrateAdapter, error) {
	return []SubstrateAdapter{r.a}, nil
}
func (r *recordingRouter) ByID(string) (SubstrateAdapter, error) { return r.a, nil }
func (r *recordingRouter) Close() error                          { return nil }

// importKindTestKinds is the closed set these tests validate against.
var importKindTestKinds = []string{"axiom", "section", "decision"}

// importKindTestRegistry builds a REAL registry via newKindRegistry — the
// production constructor. Deliberately NOT dedup_test.go's fakeKinds, which
// resolves every name to a synthetic descriptor: a permissive registry would
// make every assertion here vacuous, since resolving-everything is exactly
// the behaviour under test.
func importKindTestRegistry() NodeKindRegistry {
	descs := make([]NodeKindDescriptor, 0, len(importKindTestKinds))
	for _, n := range importKindTestKinds {
		descs = append(descs, NewNodeKindDescriptor(map[string]interface{}{
			"name":          n,
			"artifact_type": n,
			"substrate_id":  "fake",
			"version_scope": "stable_id_preserved",
		}))
	}
	return newKindRegistry(descs)
}

func newImportKindEnv(t *testing.T) (*Env, *recordingAdapter) {
	t.Helper()
	ra := &recordingAdapter{fakeAdapter: &fakeAdapter{}}
	env := &Env{
		Config: SpecGraphConfig{
			Mode:                  ModeExperimentalBootstrap,
			ExperimentalAdmitter:  "TEST",
			DefaultOrganizationID: "org-test",
		},
		Kinds:      importKindTestRegistry(),
		Substrates: &recordingRouter{a: ra},
		Now:        func() time.Time { return time.Unix(0, 0).UTC() },
	}
	return env, ra
}

func importSubmission(kind, stableID string) ArtifactSubmission {
	return ArtifactSubmission{
		ArtifactType:   kind,
		NodeKind:       kind,
		OrganizationID: "org-test",
		StableID:       stableID,
		Contract:       map[string]interface{}{"canonical_name": stableID},
		Payload:        map[string]interface{}{"title": stableID},
	}
}

// TestHandleImportRejectsUnregisteredNodeKind is the primary regression: the
// exact value that contaminated the live substrate must be refused, the
// refusal must name it, and NOTHING may reach the substrate — including the
// schema probe, because the gate is required to fail closed before any I/O.
func TestHandleImportRejectsUnregisteredNodeKind(t *testing.T) {
	env, ra := newImportKindEnv(t)

	// A valid submission ordered BEFORE the offender, so the test also pins
	// the all-or-none property: one bad kind voids the whole batch.
	_, err := handleImport(context.Background(), env, importInput{
		Submissions: []ArtifactSubmission{
			importSubmission("axiom", "good_axiom"),
			importSubmission("concept", "bad_concept"),
		},
	})

	if err == nil {
		t.Fatal("handleImport accepted node_kind=\"concept\", which is in neither the node_kind registry nor OGP s2 admissible_classes; want refusal")
	}
	if !errors.Is(err, ErrUnknownNodeKind) {
		t.Errorf("error does not wrap ErrUnknownNodeKind; got: %v", err)
	}
	if !strings.Contains(err.Error(), "concept") {
		t.Errorf("error must name the offending kind so an operator can act on it; got: %v", err)
	}
	if !strings.Contains(err.Error(), "submission[1]") {
		t.Errorf("error must name the offending submission index; got: %v", err)
	}

	// Fail-closed-before-I/O. This is the assertion that goes red if the
	// pre-pass is removed and validation is left downstream of the substrate
	// probe: the batch would still be refused, but only after a live round-trip.
	if ra.schemaChecks != 0 {
		t.Errorf("schema probe ran %d time(s) on a batch that must be refused before any substrate I/O; want 0", ra.schemaChecks)
	}
	// Nothing committed. Goes red if the gate is deleted entirely.
	if len(ra.batches) != 0 {
		t.Errorf("%d materialization batch(es) committed for a rejected import; want 0 (classes: %v)", len(ra.batches), ra.admittedObjectClasses())
	}
}

// TestHandleImportAdmitsEveryRegisteredNodeKind is the non-vacuity control.
// A gate that refuses everything would pass the test above while breaking
// the tool; every declared kind must still admit, and the admitted
// object_class must equal the submitted node_kind.
func TestHandleImportAdmitsEveryRegisteredNodeKind(t *testing.T) {
	for _, kind := range importKindTestKinds {
		t.Run(kind, func(t *testing.T) {
			env, ra := newImportKindEnv(t)

			res, err := handleImport(context.Background(), env, importInput{
				Submissions: []ArtifactSubmission{importSubmission(kind, "node_"+kind)},
			})
			if err != nil {
				t.Fatalf("registered node_kind %q was refused: %v", kind, err)
			}
			if res.Admitted != 1 {
				t.Errorf("Admitted = %d, want 1", res.Admitted)
			}
			if got := ra.admittedObjectClasses(); len(got) != 1 || got[0] != kind {
				t.Errorf("admitted object_class = %v, want [%q] — object_class must be the submitted node_kind verbatim", got, kind)
			}
		})
	}
}

// TestHandleImportRejectsEmptyNodeKind pins the empty case at the same
// pre-substrate boundary. An empty kind would otherwise write an empty
// object_class, which no registry admits.
func TestHandleImportRejectsEmptyNodeKind(t *testing.T) {
	env, ra := newImportKindEnv(t)

	_, err := handleImport(context.Background(), env, importInput{
		Submissions: []ArtifactSubmission{importSubmission("", "no_kind")},
	})
	if err == nil {
		t.Fatal("handleImport accepted an empty node_kind; want refusal")
	}
	if !strings.Contains(err.Error(), "node_kind required") {
		t.Errorf("error should state node_kind is required; got: %v", err)
	}
	if ra.schemaChecks != 0 {
		t.Errorf("schema probe ran %d time(s) before an empty-kind refusal; want 0", ra.schemaChecks)
	}
	if len(ra.batches) != 0 {
		t.Errorf("%d batch(es) committed for an empty-kind import; want 0", len(ra.batches))
	}
}

// TestHandleImportNeverAdmitsAnUnregisteredObjectClass is the invariant
// stated directly over the substrate: whatever mixture of kinds is
// submitted, every object_class that reaches the substrate resolves in the
// closed registry. Asserting the post-state rather than the error keeps the
// property true independent of how the gate is implemented.
func TestHandleImportNeverAdmitsAnUnregisteredObjectClass(t *testing.T) {
	batches := [][]ArtifactSubmission{
		{importSubmission("concept", "c1")},
		{importSubmission("axiom", "a1"), importSubmission("concept", "c2")},
		{importSubmission("concept", "c3"), importSubmission("axiom", "a2")},
		{importSubmission("descriptive", "d1")}, // the ingest tool's other private class
		{importSubmission("axiom", "a3"), importSubmission("section", "s1")},
	}

	registry := importKindTestRegistry()
	for i, subs := range batches {
		env, ra := newImportKindEnv(t)
		_, _ = handleImport(context.Background(), env, importInput{Submissions: subs})

		for _, class := range ra.admittedObjectClasses() {
			if _, err := registry.Resolve(context.Background(), class); err != nil {
				t.Errorf("batch[%d]: object_class %q reached the substrate but does not resolve in the closed registry: %v", i, class, err)
			}
		}
	}
}
