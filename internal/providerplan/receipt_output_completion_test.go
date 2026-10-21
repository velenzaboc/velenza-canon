package providerplan

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assertNoFactoryStageResidue proves an aborted publication left no private
// stage behind. A leaked stage would both leak receipt bytes and let a later
// run observe a partially written object.
func assertNoFactoryStageResidue(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".factory-output-stage-") {
			t.Fatalf("aborted publication leaked private stage %q", entry.Name())
		}
	}
}

// Publication is strictly no-replace: the exported entry point installs the
// receipt exactly once and every later attempt must refuse without disturbing
// the bytes already published.
func TestWriteReceiptExclusivePublishesExactlyOnceAndNeverReplaces(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "receipt.json")
	sealed := []byte(`{"receipt":"sealed-exact-bytes"}`)

	if err := WriteReceiptExclusive(target, sealed); err != nil {
		t.Fatalf("first publication failed: %v", err)
	}
	published, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(published) != string(sealed) {
		t.Fatalf("published bytes = %q, want the exact sealed receipt", published)
	}

	if err := WriteReceiptExclusive(target, []byte(`{"receipt":"replacement"}`)); err == nil {
		t.Fatalf("a second publication replaced an existing receipt")
	}
	retained, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(retained) != string(sealed) {
		t.Fatalf("retained bytes = %q, want the originally published receipt", retained)
	}
	assertNoFactoryStageResidue(t, dir)
}

// A failure anywhere before publish must abort the whole operation: the final
// leaf is never created and the private stage is removed.
func TestWriteFactoryReceiptExclusiveAbortsWithoutPublishingWhenAStageStepFails(t *testing.T) {
	for _, test := range []struct {
		name  string
		hooks func(*factoryOutputTestHooks)
		want  string
	}{
		{
			name: "failure immediately after the private stage is created",
			hooks: func(hooks *factoryOutputTestHooks) {
				hooks.afterStageCreate = func(string) error {
					return fmt.Errorf("staged-object inspection refused")
				}
			},
			want: "after --out stage creation test hook",
		},
		{
			name: "failure after the staged bytes are durable but before publish",
			hooks: func(hooks *factoryOutputTestHooks) {
				hooks.beforePublish = func() error {
					return fmt.Errorf("pre-publish revalidation refused")
				}
			},
			want: "before --out publish test hook",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "receipt.json")
			var hooks factoryOutputTestHooks
			test.hooks(&hooks)

			err := writeFactoryReceiptExclusiveWithHooks(target, []byte(`{"receipt":"staged"}`), hooks)
			if err == nil {
				t.Fatalf("a refused stage step still published the receipt")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
			if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
				t.Fatalf("an aborted publication created the final --out target")
			}
			assertNoFactoryStageResidue(t, dir)
		})
	}
}

// observeFactoryStageNames runs two publications that stop as soon as the stage
// exists, returning the stage name each one reported.
func observeFactoryStageNames(t *testing.T, forceNamed bool) []string {
	t.Helper()
	var observed []string
	hooks := factoryOutputTestHooks{
		forceNamedStage: forceNamed,
		afterStageCreate: func(stagedName string) error {
			observed = append(observed, stagedName)
			return fmt.Errorf("stop after observing the stage name")
		},
	}
	for range 2 {
		dir := t.TempDir()
		_ = writeFactoryReceiptExclusiveWithHooks(filepath.Join(dir, "receipt.json"), []byte(`{"receipt":"staged"}`), hooks)
	}
	if len(observed) != 2 {
		t.Fatalf("observed %d stage names, want one per attempt", len(observed))
	}
	return observed
}

// Nothing a concurrent actor can pre-create or squat may stand between staging
// and publication. A platform that supports an unnamed stage satisfies this
// strictly: the staged object has no directory entry at all. Where a named
// stage is used, the name must instead be private and unpredictable.
func TestWriteFactoryReceiptExclusiveStagesWithNothingToSquat(t *testing.T) {
	for _, name := range observeFactoryStageNames(t, false) {
		if name == "" {
			// An unnamed stage; there is no directory entry to squat.
			continue
		}
		if !strings.HasPrefix(name, ".factory-output-stage-") || !strings.Contains(name, ".tmp") {
			t.Fatalf("stage name %q is neither unnamed nor the private stage form", name)
		}
	}
}

// A forced named stage takes one of two shapes: a private sibling file
// (".factory-output-stage-<entropy>.tmp") or, where publication stages through
// a private directory, a path under it (".factory-output-stage-<entropy>.tmp.d/
// <leaf>"). Both carry the same unguessable prefix and entropy, which is what
// makes the stage impossible to pre-create or squat.
func TestWriteFactoryReceiptExclusiveNamedStageIsPrivateAndUnpredictable(t *testing.T) {
	observed := observeFactoryStageNames(t, true)
	for _, name := range observed {
		if !strings.HasPrefix(name, ".factory-output-stage-") || !strings.Contains(name, ".tmp") {
			t.Fatalf("forced named stage %q is not the private stage form", name)
		}
		if name == "receipt.json" {
			t.Fatalf("stage name collided with the final leaf")
		}
	}
	if observed[0] == observed[1] {
		t.Fatalf("two publications reused stage name %q; it must be unpredictable", observed[0])
	}
}

func TestResolveFactoryOutputPathRefusesPathsThatDoNotNameAFile(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{name: "empty", path: "", want: "empty or padded"},
		{name: "padded", path: "  receipt.json  ", want: "empty or padded"},
		{name: "filesystem root", path: string(filepath.Separator), want: "does not name a file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := resolveFactoryOutputPath(test.path); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}

	resolved, err := resolveFactoryOutputPath(filepath.Join(t.TempDir(), "receipt.json"))
	if err != nil {
		t.Fatalf("an ordinary output path was rejected: %v", err)
	}
	if resolved.leaf != "receipt.json" || !filepath.IsAbs(resolved.absolute) {
		t.Fatalf("resolved = %+v, want an absolute path naming the receipt leaf", resolved)
	}
}

// The post-publish identity check is what proves the object that ended up at
// the final path is the very object that was staged, rather than one swapped in
// by a racing actor.
func TestValidateFactoryOutputIdentityBindsTheFinalLeafToTheStagedObject(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "receipt.json")
	if err := os.WriteFile(target, []byte(`{"receipt":"published"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := openStableProviderInput(target, "--out target")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := stableProviderInputFileIdentity(opened)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	if err := validateFactoryOutputIdentity(target, nil, identity); err != nil {
		t.Fatalf("the exact staged identity was rejected: %v", err)
	}

	// A different identity is exactly the racing-swap case the check exists for.
	var foreign providerInputStableFileIdentity
	if foreign == identity {
		t.Fatalf("the zero identity equals the real one; this control cannot discriminate")
	}
	if err := validateFactoryOutputIdentity(target, nil, foreign); err == nil ||
		!strings.Contains(err.Error(), "changed identity or became a link/reparse point") {
		t.Fatalf("error = %v, want an identity-change refusal", err)
	}

	if err := validateFactoryOutputIdentity(filepath.Join(dir, "absent.json"), nil, identity); err == nil ||
		!strings.Contains(err.Error(), "reinspect --out target") {
		t.Fatalf("error = %v, want an absent-target refusal", err)
	}

	// A parent whose identity cannot be reverified fails the whole check before
	// the leaf is even opened.
	parents := []factoryOutputPathIdentity{{path: filepath.Join(dir, "absent-parent")}}
	if err := validateFactoryOutputIdentity(target, parents, identity); err == nil ||
		!strings.Contains(err.Error(), "--out parent") {
		t.Fatalf("error = %v, want a parent-identity refusal", err)
	}
}

func TestValidateFactoryOutputParentsRefusesUnverifiableParents(t *testing.T) {
	dir := t.TempDir()
	if err := validateFactoryOutputParents(nil); err != nil {
		t.Fatalf("an empty parent chain was rejected: %v", err)
	}

	opened, err := openFactoryOutputDirectoryPathNoFollow(dir)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := stableProviderInputFileIdentity(opened)
	if err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}

	if err := validateFactoryOutputParents([]factoryOutputPathIdentity{{path: dir, identity: identity}}); err != nil {
		t.Fatalf("an unchanged parent was rejected: %v", err)
	}

	var foreign providerInputStableFileIdentity
	if err := validateFactoryOutputParents([]factoryOutputPathIdentity{{path: dir, identity: foreign}}); err == nil ||
		!strings.Contains(err.Error(), "changed identity") {
		t.Fatalf("error = %v, want a changed-parent-identity refusal", err)
	}
}
