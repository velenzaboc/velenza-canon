//go:build !windows

package providerplan

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSourcePackageOutputCompletionRosterPreparationAndPrivateCoordinate(t *testing.T) {
	files := []factorySourceOutputFile{
		{RelativePath: "zeta/last.bin", Raw: []byte("last")},
		{RelativePath: "alpha/first.bin", Raw: []byte("first")},
	}
	prepared, err := prepareSourcePackageOutputRoster(files)
	if err != nil {
		t.Fatal(err)
	}
	if len(prepared) != 2 || prepared[0].relative != "alpha/first.bin" || prepared[1].relative != "zeta/last.bin" {
		t.Fatalf("prepared roster = %#v, want sorted exact paths", prepared)
	}
	files[1].Raw[0] = 'F'
	if !bytes.Equal(prepared[0].raw, []byte("first")) || !reflect.DeepEqual(prepared[0].components, []string{"alpha", "first.bin"}) {
		t.Fatalf("prepared roster did not retain independent exact bytes/components: %#v", prepared[0])
	}
	for _, testCase := range []struct {
		name  string
		files []factorySourceOutputFile
		want  string
	}{
		{"empty", nil, "roster is empty"},
		{"padded", []factorySourceOutputFile{{RelativePath: " x"}}, "empty, padded"},
		{"nul", []factorySourceOutputFile{{RelativePath: "x\x00y"}}, "contains NUL"},
		{"dot component", []factorySourceOutputFile{{RelativePath: "x/./y"}}, "relative file path"},
		{"empty component", []factorySourceOutputFile{{RelativePath: "x//y"}}, "relative file path"},
		{"duplicate", []factorySourceOutputFile{{RelativePath: "same"}, {RelativePath: "same"}}, "duplicate"},
		{"prefix", []factorySourceOutputFile{{RelativePath: "a/b"}, {RelativePath: "a"}}, "treats file"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := prepareSourcePackageOutputRoster(testCase.files)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("prepare roster error = %v, want %q", err, testCase.want)
			}
		})
	}
	if sourcePackageOutputPathIsFoldedPrefix([]string{"a"}, []string{"A", "b"}) == false || sourcePackageOutputPathIsFoldedPrefix([]string{"a"}, []string{"a"}) || sourcePackageOutputPathIsFoldedPrefix([]string{"a"}, []string{"b", "c"}) {
		t.Fatal("folded-prefix predicate did not distinguish prefix, equality, and mismatch")
	}
	if _, err := newPrivateFactorySourceOutputCoordinate(" "); err == nil {
		t.Fatal("padded private root was accepted")
	}
	coordinate, err := newPrivateFactorySourceOutputCoordinate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(coordinate) == "" || !strings.HasSuffix(coordinate, ".private-root") {
		t.Fatalf("private coordinate = %q, want an absent private-root child", coordinate)
	}
}

func TestSourcePackageOutputCompletionExactFileHelpers(t *testing.T) {
	if _, err := inspectNewSourcePackageOutputFile(nil, "nil"); err == nil {
		t.Fatal("nil file was retained")
	}
	if _, err := writeExactSourcePackageOutputFile(nil, "nil", nil, providerInputStableFileIdentity{}, func() error { return nil }); err == nil {
		t.Fatal("nil writer file was accepted")
	}
	if _, err := writeExactSourcePackageOutputFile(&os.File{}, "nil-sync", nil, providerInputStableFileIdentity{}, nil); err == nil {
		t.Fatal("nil sync operation was accepted")
	}

	path := filepath.Join(t.TempDir(), "exact.bin")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	created, err := inspectNewSourcePackageOutputFile(file, "exact.bin")
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("sync refusal")
	if _, err := writeExactSourcePackageOutputFile(file, "exact.bin", []byte("bytes"), created, func() error { return injected }); !errors.Is(err, injected) {
		t.Fatalf("sync failure = %v, want injected error", err)
	}
	if err := file.Truncate(0); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	written, err := writeExactSourcePackageOutputFile(file, "exact.bin", []byte("exact\x00bytes"), created, file.Sync)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyExactSourcePackageOutputFile(file, "exact.bin", []byte("exact\x00bytes"), written); err != nil {
		t.Fatal(err)
	}
	if err := verifyExactSourcePackageOutputFile(file, "exact.bin", []byte("wrong"), written); err == nil {
		t.Fatal("mismatched declared bytes were accepted")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := writeExactSourcePackageOutputFile(file, "closed", []byte("x"), written, func() error { return nil }); err == nil {
		t.Fatal("closed file accepted a write")
	}
	if err := verifyExactSourcePackageOutputFile(file, "closed", nil, written); err == nil {
		t.Fatal("closed file was verified")
	}
	changedPath := filepath.Join(t.TempDir(), "changed.bin")
	changed, err := os.OpenFile(changedPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer changed.Close()
	changedIdentity, err := inspectNewSourcePackageOutputFile(changed, "changed.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writeExactSourcePackageOutputFile(changed, "changed.bin", []byte("declared"), changedIdentity, func() error {
		if err := changed.Truncate(0); err != nil {
			return err
		}
		return changed.Sync()
	}); err == nil || !strings.Contains(err.Error(), "changed identity or size") {
		t.Fatalf("post-write size mutation error = %v", err)
	}
}

func TestSourcePackageOutputCompletionPrivateValidationAndResealFailures(t *testing.T) {
	if err := withPrivateFactorySourceOutputDirectory([]factorySourceOutputFile{{RelativePath: "x", Raw: []byte("x")}}, nil); err == nil {
		t.Fatal("nil private callback was accepted")
	}
	injected := errors.New("private stage refusal")
	if err := withPrivateFactorySourceOutputDirectoryWithHooks(
		[]factorySourceOutputFile{{RelativePath: "x", Raw: []byte("x")}},
		func(string) error { return nil },
		privateFactorySourceOutputHooks{tempRoot: " ", afterStageCreate: func(string) error { return injected }},
	); err == nil {
		t.Fatal("padded private root was accepted before callback")
	}
	parent := t.TempDir()
	root := filepath.Join(parent, "candidate")
	var stagePath string
	err := publishFactorySourceOutputDirectoryExclusiveWithHooks(root, []factorySourceOutputFile{{RelativePath: "exact.txt", Raw: []byte("exact")}}, sourcePackageOutputHooks{
		afterStageCreate: func(path string) error { stagePath = path; return nil },
		afterFileWrite: func(string) error {
			return os.WriteFile(filepath.Join(stagePath, "undeclared.txt"), []byte("attacker"), 0o600)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "contains") {
		t.Fatalf("unsealed roster error = %v", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("unsealed roster reached final root: %v", statErr)
	}
	if err := withPrivateFactorySourceOutputDirectory([]factorySourceOutputFile{{RelativePath: "x/../bad"}}, func(string) error { return nil }); err == nil {
		t.Fatal("invalid private roster was accepted")
	}
	privateTemp := t.TempDir()
	if err := withPrivateFactorySourceOutputDirectoryWithHooks(
		[]factorySourceOutputFile{{RelativePath: "x", Raw: []byte("x")}},
		func(string) error { return nil },
		privateFactorySourceOutputHooks{tempRoot: privateTemp, afterStageCreate: func(string) error { return injected }},
	); !errors.Is(err, injected) {
		t.Fatalf("private stage hook error = %v, want injected refusal", err)
	}
	if err := publishFactorySourceOutputDirectoryExclusive("/", []factorySourceOutputFile{{RelativePath: "x", Raw: []byte("x")}}); err == nil {
		t.Fatal("filesystem root was accepted as a publish leaf")
	}
	if err := publishFactorySourceOutputDirectoryExclusive(" ", []factorySourceOutputFile{{RelativePath: "x", Raw: []byte("x")}}); err == nil {
		t.Fatal("padded publish root was accepted")
	}
	secondParent := t.TempDir()
	secondRoot := filepath.Join(secondParent, "candidate")
	var resealPath string
	err = publishFactorySourceOutputDirectoryExclusiveWithHooks(secondRoot, []factorySourceOutputFile{{RelativePath: "exact.txt", Raw: []byte("exact")}}, sourcePackageOutputHooks{
		afterStageCreate: func(path string) error { resealPath = path; return nil },
		beforePublish: func(string) error {
			return os.WriteFile(filepath.Join(resealPath, "late.txt"), []byte("attacker"), 0o600)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "reseal") {
		t.Fatalf("late roster mutation error = %v", err)
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed-inspect")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectNewSourcePackageOutputFile(closed, "closed"); err == nil {
		t.Fatal("closed file was inspected as stable")
	}
}

func TestSourcePackageOutputCompletionPublisherHookFailuresErasePrivateState(t *testing.T) {
	injected := errors.New("completion hook refusal")
	for _, testCase := range []struct {
		name string
		hook func(*sourcePackageOutputHooks)
	}{
		{"after-stage", func(hooks *sourcePackageOutputHooks) { hooks.afterStageCreate = func(string) error { return injected } }},
		{"before-write", func(hooks *sourcePackageOutputHooks) { hooks.beforeFileWrite = func(string) error { return injected } }},
		{"after-write", func(hooks *sourcePackageOutputHooks) { hooks.afterFileWrite = func(string) error { return injected } }},
		{"before-publish", func(hooks *sourcePackageOutputHooks) { hooks.beforePublish = func(string) error { return injected } }},
		{"after-prepare", func(hooks *sourcePackageOutputHooks) { hooks.afterPrepare = func(string) error { return injected } }},
		{"after-publish", func(hooks *sourcePackageOutputHooks) { hooks.afterPublish = func(string) error { return injected } }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "candidate")
			hooks := sourcePackageOutputHooks{}
			testCase.hook(&hooks)
			err := publishFactorySourceOutputDirectoryExclusiveWithHooks(root, []factorySourceOutputFile{{RelativePath: "nested/exact.txt", Raw: []byte("exact")}}, hooks)
			if !errors.Is(err, injected) {
				t.Fatalf("hook failure = %v, want injected refusal", err)
			}
			if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
				t.Fatalf("hook failure published final root: %v", statErr)
			}
			assertNoSourcePackageOutputStages(t, parent)
		})
	}
}

func TestSourcePackageOutputCompletionNonWindowsStageLedgerAndRelease(t *testing.T) {
	parent := t.TempDir()
	resolved, err := resolveFactoryOutputPath(filepath.Join(parent, "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	stageInterface, parents, err := createSourcePackageOutputStage(resolved, sourcePackageOutputHooks{})
	if err != nil {
		t.Fatal(err)
	}
	stage, ok := stageInterface.(*nonWindowsSourcePackageOutputStage)
	if !ok {
		t.Fatalf("stage type = %T", stageInterface)
	}
	roster, err := prepareSourcePackageOutputRoster([]factorySourceOutputFile{
		{RelativePath: "nested/one.txt", Raw: []byte("one")},
		{RelativePath: "two.txt", Raw: []byte("two")},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range roster {
		if err := stage.writeFile(entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := stage.writeFile(roster[0]); err == nil {
		t.Fatal("duplicate retained file was created")
	}
	if err := stage.validatePrivateRoot(); err != nil {
		t.Fatal(err)
	}
	if err := validateFactoryOutputParents(parents); err != nil {
		t.Fatal(err)
	}
	if same, err := nonWindowsSourcePackageNamedObjectMatches(stage.parentFD, stage.stageName, stage.root.identity, true); err != nil || !same {
		t.Fatalf("retained stage directory identity = %t, %v", same, err)
	}
	if err := stage.seal(roster); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage.stagePath(), "undeclared.txt"), []byte("attacker"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stage.validateClosedRoster(roster); err == nil || !strings.Contains(err.Error(), "contains 3 entries") {
		t.Fatalf("undeclared entry error = %v", err)
	}
	if err := os.Remove(filepath.Join(stage.stagePath(), "undeclared.txt")); err != nil {
		t.Fatal(err)
	}
	if err := stage.validatePrepared(roster); err != nil {
		t.Fatal(err)
	}
	if same, err := nonWindowsSourcePackageNamedObjectMatches(stage.root.fd, "two.txt", stage.files["two.txt"].identity, false); err != nil || !same {
		t.Fatalf("retained file identity = %t, %v", same, err)
	}
	if same, err := nonWindowsSourcePackageNamedObjectMatches(stage.root.fd, "missing", providerInputStableFileIdentity{}, false); err == nil || same {
		t.Fatalf("missing object identity = %t, %v", same, err)
	}
	if err := stage.abort(); err != nil {
		t.Fatal(err)
	}
	if err := stage.release(); err != nil {
		t.Fatal(err)
	}
	if err := stage.release(); err != nil {
		t.Fatalf("second release = %v, want idempotence", err)
	}
	if _, err := os.Lstat(stage.stagePath()); !os.IsNotExist(err) {
		t.Fatalf("aborted stage remains at %q: %v", stage.stagePath(), err)
	}
}

func TestSourcePackageOutputCompletionNonWindowsCreationAndPublicationEdges(t *testing.T) {
	resolved, err := resolveFactoryOutputPath(filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("parent-open refusal")
	if _, _, err := createSourcePackageOutputStage(resolved, sourcePackageOutputHooks{afterParentOpen: func() error { return injected }}); !errors.Is(err, injected) {
		t.Fatalf("after-parent-open error = %v, want injected refusal", err)
	}
	stageInterface, _, err := createSourcePackageOutputStage(resolved, sourcePackageOutputHooks{})
	if err != nil {
		t.Fatal(err)
	}
	stage := stageInterface.(*nonWindowsSourcePackageOutputStage)
	roster, err := prepareSourcePackageOutputRoster([]factorySourceOutputFile{{RelativePath: "exact.txt", Raw: []byte("exact")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.writeFile(roster[0]); err != nil {
		t.Fatal(err)
	}
	if err := stage.seal(roster); err != nil {
		t.Fatal(err)
	}
	if err := stage.publish(); err != nil {
		t.Fatal(err)
	}
	if !stage.published {
		t.Fatal("publish did not record its state")
	}
	if err := stage.validatePublished(roster); err != nil {
		t.Fatal(err)
	}
	if err := stage.abort(); err != nil {
		t.Fatal(err)
	}
	if err := stage.release(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(resolved.absolute); !os.IsNotExist(err) {
		t.Fatalf("aborted published stage remains at final root: %v", err)
	}
}

func TestSourcePackageOutputCompletionNonWindowsLedgerRefusesKindSubstitution(t *testing.T) {
	resolved, err := resolveFactoryOutputPath(filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	stageInterface, _, err := createSourcePackageOutputStage(resolved, sourcePackageOutputHooks{})
	if err != nil {
		t.Fatal(err)
	}
	stage := stageInterface.(*nonWindowsSourcePackageOutputStage)
	roster, err := prepareSourcePackageOutputRoster([]factorySourceOutputFile{{RelativePath: "declared", Raw: []byte("publisher")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.writeFile(roster[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(stage.stagePath(), "declared")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stage.stagePath(), "declared"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := stage.validateClosedRoster(roster); err == nil || (!strings.Contains(err.Error(), "changed identity or kind") && !strings.Contains(err.Error(), "contains 0 entries")) {
		t.Fatalf("kind substitution error = %v", err)
	}
	if err := stage.release(); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePackageOutputCompletionNonWindowsClosedHandlesFailClosed(t *testing.T) {
	resolved, err := resolveFactoryOutputPath(filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	stageInterface, _, err := createSourcePackageOutputStage(resolved, sourcePackageOutputHooks{})
	if err != nil {
		t.Fatal(err)
	}
	stage := stageInterface.(*nonWindowsSourcePackageOutputStage)
	roster, err := prepareSourcePackageOutputRoster([]factorySourceOutputFile{{RelativePath: "nested/declared", Raw: []byte("publisher")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.writeFile(roster[0]); err != nil {
		t.Fatal(err)
	}
	if err := stage.seal(append(roster, preparedSourcePackageOutputFile{relative: "missing"})); err == nil || !strings.Contains(err.Error(), "retained files") {
		t.Fatalf("wrong roster length error = %v", err)
	}
	if err := stage.files["nested/declared"].file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stage.abort(); err == nil {
		t.Fatal("abort accepted a closed retained file")
	}
	if err := stage.release(); err == nil {
		t.Fatal("release accepted an already-closed retained file")
	}
	if err := os.RemoveAll(filepath.Dir(stage.stagePath())); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePackageOutputCompletionNonWindowsDirectoryAndRootSubstitution(t *testing.T) {
	resolved, err := resolveFactoryOutputPath(filepath.Join(t.TempDir(), "candidate"))
	if err != nil {
		t.Fatal(err)
	}
	stageInterface, _, err := createSourcePackageOutputStage(resolved, sourcePackageOutputHooks{})
	if err != nil {
		t.Fatal(err)
	}
	stage := stageInterface.(*nonWindowsSourcePackageOutputStage)
	roster, err := prepareSourcePackageOutputRoster([]factorySourceOutputFile{{RelativePath: "nested/declared", Raw: []byte("publisher")}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stage.stagePath(), "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := stage.writeFile(roster[0]); err == nil || !strings.Contains(err.Error(), "create exclusive source-package directory") {
		t.Fatalf("preexisting private directory error = %v", err)
	}
	if err := os.Remove(filepath.Join(stage.stagePath(), "nested")); err != nil {
		t.Fatal(err)
	}
	if err := stage.abort(); err != nil {
		t.Fatal(err)
	}
	if err := stage.release(); err != nil {
		t.Fatal(err)
	}

	stageInterface, _, err = createSourcePackageOutputStage(resolved, sourcePackageOutputHooks{})
	if err != nil {
		t.Fatal(err)
	}
	stage = stageInterface.(*nonWindowsSourcePackageOutputStage)
	if err := stage.writeFile(roster[0]); err != nil {
		t.Fatal(err)
	}
	retained := filepath.Join(stage.stagePath(), "nested.retained")
	if err := os.Rename(filepath.Join(stage.stagePath(), "nested"), retained); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(stage.stagePath(), "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(retained); err != nil {
		t.Fatal(err)
	}
	// The substituted directory must be refused, but the exact refusal depends
	// on what the retained directory handle still resolves to. Where the handle
	// follows the renamed inode, removing it leaves the handle enumerating a
	// deleted directory; elsewhere the handle observes an empty or
	// identity-changed directory. All three are fail-closed refusals.
	substitutionErr := stage.validateClosedRoster(roster)
	if substitutionErr == nil {
		t.Fatalf("a substituted private directory was accepted")
	}
	if !strings.Contains(substitutionErr.Error(), "changed identity or kind") &&
		!strings.Contains(substitutionErr.Error(), "contains 0 entries") &&
		!strings.Contains(substitutionErr.Error(), "enumerate source-package directory") {
		t.Fatalf("directory substitution error = %v", substitutionErr)
	}
	if err := stage.release(); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePackageOutputCompletionNonWindowsFaultLedgersFailClosed(t *testing.T) {
	newStage := func(t *testing.T, relative string) (*nonWindowsSourcePackageOutputStage, []preparedSourcePackageOutputFile) {
		t.Helper()
		resolved, err := resolveFactoryOutputPath(filepath.Join(t.TempDir(), "candidate"))
		if err != nil {
			t.Fatal(err)
		}
		created, _, err := createSourcePackageOutputStage(resolved, sourcePackageOutputHooks{})
		if err != nil {
			t.Fatal(err)
		}
		roster, err := prepareSourcePackageOutputRoster([]factorySourceOutputFile{{RelativePath: relative, Raw: []byte("publisher")}})
		if err != nil {
			t.Fatal(err)
		}
		return created.(*nonWindowsSourcePackageOutputStage), roster
	}

	t.Run("closed descriptor rejects sync", func(t *testing.T) {
		stage, roster := newStage(t, "declared")
		stage.hooks.beforeFileSync = func(relative string) error { return stage.files[relative].file.Close() }
		if err := stage.writeFile(roster[0]); err == nil || !strings.Contains(err.Error(), "sync source-package file") {
			t.Fatalf("closed-descriptor sync error = %v", err)
		}
		_ = stage.abort()
		_ = stage.release()
	})

	t.Run("closed directory descriptor rejects enumeration", func(t *testing.T) {
		stage, roster := newStage(t, "declared")
		if err := stage.writeFile(roster[0]); err != nil {
			t.Fatal(err)
		}
		if err := stage.root.file.Close(); err != nil {
			t.Fatal(err)
		}
		if err := stage.validateClosedRoster(roster); err == nil {
			t.Fatal("closed root descriptor enumerated roster")
		}
		_ = stage.release()
	})

	t.Run("undeclared entry cannot replace declaration", func(t *testing.T) {
		stage, roster := newStage(t, "declared")
		if err := stage.writeFile(roster[0]); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(stage.stagePath(), "declared")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stage.stagePath(), "undeclared"), []byte("attacker"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := stage.validateClosedRoster(roster); err == nil || !strings.Contains(err.Error(), "undeclared entry") {
			t.Fatalf("undeclared replacement error = %v", err)
		}
		_ = stage.release()
	})

	t.Run("ledger omission cannot hide retained file", func(t *testing.T) {
		stage, roster := newStage(t, "declared")
		if err := stage.writeFile(roster[0]); err != nil {
			t.Fatal(err)
		}
		retained := stage.files["declared"]
		delete(stage.files, "declared")
		stage.files["phantom"] = retained
		if err := stage.validateClosedRoster(roster); err == nil || !strings.Contains(err.Error(), "ledger omits") {
			t.Fatalf("ledger omission error = %v", err)
		}
		_ = stage.release()
	})

	t.Run("link substitution is not a retained file", func(t *testing.T) {
		stage, roster := newStage(t, "declared")
		if err := stage.writeFile(roster[0]); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(stage.stagePath(), "declared")
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("attacker-target", path); err != nil {
			t.Fatal(err)
		}
		if err := stage.validateClosedRoster(roster); err == nil || !strings.Contains(err.Error(), "changed identity or kind") {
			t.Fatalf("link substitution error = %v", err)
		}
		_ = stage.release()
	})

	t.Run("private-root validation rejects closed parent", func(t *testing.T) {
		stage, _ := newStage(t, "declared")
		if err := stage.parentHandles[len(stage.parentHandles)-1].Close(); err != nil {
			t.Fatal(err)
		}
		if err := stage.validatePrivateRoot(); err == nil {
			t.Fatal("closed root descriptor validated as private root")
		}
		_ = stage.release()
	})

	t.Run("seal rejects a missing retained file", func(t *testing.T) {
		stage, roster := newStage(t, "declared")
		if err := stage.writeFile(roster[0]); err != nil {
			t.Fatal(err)
		}
		retained := stage.files["declared"]
		delete(stage.files, "declared")
		stage.files["phantom"] = retained
		if err := stage.seal(roster); err == nil || !strings.Contains(err.Error(), "omits") {
			t.Fatalf("missing retained file seal error = %v", err)
		}
		_ = stage.release()
	})

	t.Run("directory sync rejects invalid retained descriptor", func(t *testing.T) {
		stage, roster := newStage(t, "declared")
		if err := stage.writeFile(roster[0]); err != nil {
			t.Fatal(err)
		}
		stage.root.fd = -1
		if err := stage.seal(roster); err == nil {
			t.Fatalf("invalid directory descriptor seal error = %v", err)
		}
		_ = stage.release()
	})

	t.Run("file presented as directory produces open refusal", func(t *testing.T) {
		stage, roster := newStage(t, "declared")
		if err := stage.writeFile(roster[0]); err != nil {
			t.Fatal(err)
		}
		stage.directories["declared"] = &nonWindowsSourcePackageOutputDirectory{identity: stage.files["declared"].identity}
		if err := stage.validateClosedRoster(roster); err == nil {
			t.Fatal("regular file presented as a retained directory was accepted")
		}
		info, err := os.Lstat(filepath.Join(stage.stagePath(), "declared"))
		if err != nil {
			t.Fatalf("file-as-directory refusal removed the staged file: %v", err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("file-as-directory refusal changed the staged file mode: %v", info.Mode())
		}
		delete(stage.directories, "declared")
		_ = stage.release()
	})

	t.Run("published validation rejects closed parent descriptor", func(t *testing.T) {
		stage, roster := newStage(t, "declared")
		if err := stage.writeFile(roster[0]); err != nil {
			t.Fatal(err)
		}
		if err := stage.parentHandles[len(stage.parentHandles)-1].Close(); err != nil {
			t.Fatal(err)
		}
		if err := stage.validatePublished(roster); err == nil {
			t.Fatal("unpublished stage with closed parent was validated")
		}
		_ = stage.release()
	})
}
