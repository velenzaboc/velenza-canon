package providerplan

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestSourcePackageOutputPublishesExactClosedRoster(t *testing.T) {
	root := filepath.Join(t.TempDir(), "candidate-output")
	roster := []factorySourceOutputFile{
		{RelativePath: "z-last.json", Raw: []byte("{\"z\":true}\n")},
		{RelativePath: "catalog/empty.txt", Raw: nil},
		{RelativePath: "catalog/nested/exact.bin", Raw: []byte{0, 1, 2, '\r', '\n'}},
		{RelativePath: "a-first.json", Raw: []byte("{\"a\":true}\r\n")},
	}
	if err := publishFactorySourceOutputDirectoryExclusive(root, roster); err != nil {
		t.Fatal(err)
	}
	assertExactSourcePackageOutputTree(t, root, roster)
}

func TestSourcePackageOutputRejectsInvalidClosedRosterBeforeCreatingRoot(t *testing.T) {
	tests := []struct {
		name   string
		roster []factorySourceOutputFile
		want   string
	}{
		{name: "empty", want: "roster is empty"},
		{name: "absolute", roster: []factorySourceOutputFile{{RelativePath: "/absolute", Raw: []byte("x")}}, want: "relative file path"},
		{name: "unclean", roster: []factorySourceOutputFile{{RelativePath: "a/../b", Raw: []byte("x")}}, want: "relative file path"},
		{name: "backslash", roster: []factorySourceOutputFile{{RelativePath: `a\b`, Raw: []byte("x")}}, want: "relative file path"},
		{name: "case-fold alias", roster: []factorySourceOutputFile{{RelativePath: "A/file"}, {RelativePath: "a/File"}}, want: "case-fold-alias"},
		{name: "case-fold directory alias", roster: []factorySourceOutputFile{{RelativePath: "A/first"}, {RelativePath: "a/second"}}, want: "case-fold-alias directory"},
		{name: "file-directory collision", roster: []factorySourceOutputFile{{RelativePath: "a"}, {RelativePath: "a/file"}}, want: "treats file"},
		{name: "folded file-directory collision", roster: []factorySourceOutputFile{{RelativePath: "A"}, {RelativePath: "a/file"}}, want: "treats file"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "candidate-output")
			err := publishFactorySourceOutputDirectoryExclusive(root, testCase.roster)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want substring %q", err, testCase.want)
			}
			if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
				t.Fatalf("invalid roster exposed output root: %v", statErr)
			}
		})
	}
}

func TestSourcePackageOutputCleanupDoesNotDeleteSubstitutedStage(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "candidate-output")
	attackerBytes := []byte("attacker stage bytes\n")
	var substitutedStage string
	injected := errors.New("failure after stage substitution")
	err := publishFactorySourceOutputDirectoryExclusiveWithHooks(root, []factorySourceOutputFile{{RelativePath: "candidate.txt", Raw: []byte("candidate\n")}}, sourcePackageOutputHooks{
		afterStageCreate: func(stagePath string) error {
			retainedStage := stagePath + ".retained"
			if err := os.Rename(stagePath, retainedStage); err != nil {
				return err
			}
			if err := os.Mkdir(stagePath, 0o700); err != nil {
				return err
			}
			substitutedStage = stagePath
			if err := os.WriteFile(filepath.Join(stagePath, "attacker.txt"), attackerBytes, 0o600); err != nil {
				return err
			}
			return injected
		},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("stage substitution failure = %v, want injected error", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("stage substitution exposed final root: %v", statErr)
	}
	got, readErr := os.ReadFile(filepath.Join(substitutedStage, "attacker.txt"))
	if readErr != nil || !bytes.Equal(got, attackerBytes) {
		t.Fatalf("cleanup altered attacker-substituted stage: got=%q err=%v", got, readErr)
	}
}

func TestSourcePackageOutputRejectsAttackerReplacementAfterDescendantHandlesClose(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "candidate-output")
	attackerBytes := []byte("attacker replacement after prepare\n")
	var substitutedPath string
	err := publishFactorySourceOutputDirectoryExclusiveWithHooks(root, []factorySourceOutputFile{
		{RelativePath: "declared.txt", Raw: []byte("declared source bytes\n")},
		{RelativePath: "nested/retained.txt", Raw: []byte("retained source bytes\n")},
	}, sourcePackageOutputHooks{
		afterPrepare: func(stagePath string) error {
			substitutedPath = filepath.Join(stagePath, "declared.txt")
			if err := os.Remove(substitutedPath); err != nil {
				return err
			}
			return os.WriteFile(substitutedPath, attackerBytes, 0o600)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "changed identity") {
		t.Fatalf("post-prepare attacker replacement error = %v, want exact identity refusal", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("post-prepare attacker replacement exposed final root: %v", statErr)
	}
	got, readErr := os.ReadFile(substitutedPath)
	if readErr != nil || !bytes.Equal(got, attackerBytes) {
		t.Fatalf("publisher altered or redirected attacker replacement: got=%q err=%v", got, readErr)
	}
}

func TestSourcePackageOutputRejectsExactByteMutationAfterRenameBeforeReturn(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "candidate-output")
	err := publishFactorySourceOutputDirectoryExclusiveWithHooks(root, []factorySourceOutputFile{
		{RelativePath: "declared.txt", Raw: []byte("declared source bytes\n")},
		{RelativePath: "nested/retained.txt", Raw: []byte("retained source bytes\n")},
	}, sourcePackageOutputHooks{
		afterPublish: func(publishedRoot string) error {
			return os.WriteFile(filepath.Join(publishedRoot, "declared.txt"), []byte("mutated after atomic rename\n"), 0o600)
		},
	})
	if err == nil || (!strings.Contains(err.Error(), "differs from declared bytes") && !strings.Contains(err.Error(), "changed identity, kind, size")) {
		t.Fatalf("post-rename exact-byte mutation error = %v, want post-publication exact-tree refusal", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("post-rename exact-byte mutation left a false-success final root: %v", statErr)
	}
	assertNoSourcePackageOutputStages(t, parent)
}

func TestSourcePackageOutputPrivateDirectoryCallbackSeesExactTreeThenErasesIt(t *testing.T) {
	roster := []factorySourceOutputFile{
		{RelativePath: "a.json", Raw: []byte("{\"a\":true}\r\n")},
		{RelativePath: "nested/empty.txt", Raw: nil},
		{RelativePath: "nested/exact.bin", Raw: []byte{0, 1, 2, 3}},
	}
	var privateRoot string
	err := withPrivateFactorySourceOutputDirectory(roster, func(root string) error {
		privateRoot = root
		return verifyExactSourcePackageOutputTree(root, roster)
	})
	if err != nil {
		t.Fatal(err)
	}
	if privateRoot == "" {
		t.Fatal("private callback did not receive its retained root")
	}
	if _, statErr := os.Lstat(privateRoot); !os.IsNotExist(statErr) {
		t.Fatalf("successful private callback left publisher-owned plaintext reachable: %v", statErr)
	}
}

func verifyExactSourcePackageOutputTree(root string, roster []factorySourceOutputFile) error {
	want := make(map[string][]byte, len(roster))
	for _, entry := range roster {
		want[entry.RelativePath] = entry.Raw
	}
	got := make(map[string][]byte, len(roster))
	err := filepath.WalkDir(root, func(current string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == root || entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		got[filepath.ToSlash(relative)] = raw
		return nil
	})
	if err != nil {
		return err
	}
	if len(got) != len(want) {
		return fmt.Errorf("private source-output roster count = %d, want %d", len(got), len(want))
	}
	for relative, expected := range want {
		if !bytes.Equal(got[relative], expected) {
			return fmt.Errorf("private source-output file %q bytes = %q, want %q", relative, got[relative], expected)
		}
	}
	return nil
}

func TestSourcePackageOutputPrivateDirectoryCallbackFailureErasesTree(t *testing.T) {
	injected := errors.New("private callback failure")
	var privateRoot string
	err := withPrivateFactorySourceOutputDirectory([]factorySourceOutputFile{{RelativePath: "secret.txt", Raw: []byte("publisher plaintext\n")}}, func(root string) error {
		privateRoot = root
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("private callback failure = %v, want injected error", err)
	}
	if _, statErr := os.Lstat(privateRoot); !os.IsNotExist(statErr) {
		t.Fatalf("failed private callback left publisher-owned plaintext reachable: %v", statErr)
	}
}

func TestSourcePackageOutputPrivateDirectoryRejectsFileSubstitutionWithoutTouchingAttackerBytes(t *testing.T) {
	publisherBytes := []byte("publisher plaintext\n")
	attackerBytes := []byte("attacker replacement\n")
	var privateRoot string
	var retainedPublisherPath string
	var attackerPath string
	err := withPrivateFactorySourceOutputDirectory([]factorySourceOutputFile{{RelativePath: "declared.txt", Raw: publisherBytes}}, func(root string) error {
		privateRoot = root
		attackerPath = filepath.Join(root, "declared.txt")
		retainedPublisherPath = attackerPath + ".retained"
		if err := os.Rename(attackerPath, retainedPublisherPath); err != nil {
			return err
		}
		return os.WriteFile(attackerPath, attackerBytes, 0o600)
	})
	if err == nil {
		t.Fatal("private callback file substitution was accepted")
	}
	got, readErr := os.ReadFile(attackerPath)
	if readErr != nil || !bytes.Equal(got, attackerBytes) {
		t.Fatalf("private cleanup altered attacker-substituted bytes: got=%q err=%v", got, readErr)
	}
	if retained, retainedErr := os.ReadFile(retainedPublisherPath); retainedErr == nil && bytes.Contains(retained, publisherBytes) {
		t.Fatalf("publisher-owned plaintext remained reachable after substitution at %q", retainedPublisherPath)
	} else if retainedErr != nil && !os.IsNotExist(retainedErr) {
		t.Fatalf("inspect retained publisher identity: %v", retainedErr)
	}
	if privateRoot == "" {
		t.Fatal("private callback root was not captured")
	}
}

func TestSourcePackageOutputPrivateDirectoryRejectsRootSubstitutionWithoutTouchingAttackerBytes(t *testing.T) {
	publisherBytes := []byte("publisher plaintext\n")
	attackerBytes := []byte("attacker root bytes\n")
	var privateRoot string
	var retainedRoot string
	callbackCalled := false
	err := withPrivateFactorySourceOutputDirectoryWithHooks(
		[]factorySourceOutputFile{{RelativePath: "declared.txt", Raw: publisherBytes}},
		func(string) error { callbackCalled = true; return nil },
		privateFactorySourceOutputHooks{afterStageCreate: func(root string) error {
			privateRoot = root
			retainedRoot = root + ".retained"
			if err := os.Rename(root, retainedRoot); err != nil {
				return err
			}
			if err := os.Mkdir(root, 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(root, "attacker.txt"), attackerBytes, 0o600)
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "changed path identity") {
		t.Fatalf("private root substitution error = %v, want identity refusal", err)
	}
	if callbackCalled {
		t.Fatal("private callback ran after its stage root was substituted")
	}
	got, readErr := os.ReadFile(filepath.Join(privateRoot, "attacker.txt"))
	if readErr != nil || !bytes.Equal(got, attackerBytes) {
		t.Fatalf("private cleanup altered attacker root bytes: got=%q err=%v", got, readErr)
	}
	retainedPublisherPath := filepath.Join(retainedRoot, "declared.txt")
	if retained, retainedErr := os.ReadFile(retainedPublisherPath); retainedErr == nil && bytes.Contains(retained, publisherBytes) {
		t.Fatalf("publisher-owned plaintext remained reachable after root substitution at %q", retainedPublisherPath)
	} else if retainedErr != nil && !os.IsNotExist(retainedErr) {
		t.Fatalf("inspect retained publisher root: %v", retainedErr)
	}
}

func TestSourcePackageOutputPrivateDirectoryRejectsLinkOrReparseTempParent(t *testing.T) {
	base := t.TempDir()
	realTemp := filepath.Join(base, "real-temp")
	linkTemp := filepath.Join(base, "link-temp")
	if err := os.Mkdir(realTemp, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realTemp, linkTemp); err != nil {
		t.Fatalf("create link/reparse test fixture: %v", err)
	}
	callbackCalled := false
	err := withPrivateFactorySourceOutputDirectoryWithHooks(
		[]factorySourceOutputFile{{RelativePath: "declared.txt", Raw: []byte("publisher plaintext\n")}},
		func(string) error { callbackCalled = true; return nil },
		privateFactorySourceOutputHooks{tempRoot: linkTemp},
	)
	if err == nil {
		t.Fatal("link/reparse private temp parent was followed")
	}
	if callbackCalled {
		t.Fatal("callback ran through a link/reparse private temp parent")
	}
	entries, readErr := os.ReadDir(realTemp)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("link/reparse target received private publisher objects: %v", entries)
	}
}

func TestSourcePackageOutputExistingRootIsNeverReplaced(t *testing.T) {
	for _, rootKind := range []string{"file", "directory"} {
		t.Run(rootKind, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "candidate-output")
			retained := []byte("attacker-owned bytes\n")
			if rootKind == "file" {
				if err := os.WriteFile(root, retained, 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(root, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "retained.txt"), retained, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			err := publishFactorySourceOutputDirectoryExclusive(root, []factorySourceOutputFile{{RelativePath: "candidate.txt", Raw: []byte("candidate\n")}})
			if err == nil {
				t.Fatal("preexisting output root was replaced")
			}
			path := root
			if rootKind == "directory" {
				path = filepath.Join(root, "retained.txt")
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(got, retained) {
				t.Fatalf("preexisting bytes changed: got=%q err=%v", got, readErr)
			}
			assertNoSourcePackageOutputStages(t, parent)
		})
	}
}

func TestSourcePackageOutputPartialFailureLeavesFinalRootAbsentAndRetryable(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "candidate-output")
	roster := []factorySourceOutputFile{
		{RelativePath: "a/first.txt", Raw: []byte("first\n")},
		{RelativePath: "b/second.txt", Raw: []byte("second\n")},
	}
	injected := errors.New("injected partial-write failure")
	err := publishFactorySourceOutputDirectoryExclusiveWithHooks(root, roster, sourcePackageOutputHooks{
		beforeFileWrite: func(relative string) error {
			if relative == "b/second.txt" {
				return injected
			}
			return nil
		},
	})
	if !errors.Is(err, injected) {
		t.Fatalf("partial failure = %v, want injected error", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("partial failure exposed final root: %v", statErr)
	}
	assertNoSourcePackageOutputStages(t, parent)
	if err := publishFactorySourceOutputDirectoryExclusive(root, roster); err != nil {
		t.Fatalf("retry after private partial failure: %v", err)
	}
	assertExactSourcePackageOutputTree(t, root, roster)
}

func TestSourcePackageOutputParentReplacementCannotRedirectPublication(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	retainedParent := filepath.Join(base, "retained-parent")
	root := filepath.Join(parent, "candidate-output")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	attackerBytes := []byte("attacker replacement\n")
	err := publishFactorySourceOutputDirectoryExclusiveWithHooks(root, []factorySourceOutputFile{{RelativePath: "candidate.txt", Raw: []byte("candidate\n")}}, sourcePackageOutputHooks{
		afterParentOpen: func() error {
			if err := os.Rename(parent, retainedParent); err != nil {
				return err
			}
			if err := os.Mkdir(parent, 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(parent, "attacker.txt"), attackerBytes, 0o600)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "changed identity") {
		t.Fatalf("parent replacement error = %v, want identity refusal", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("replacement parent received final output: %v", statErr)
	}
	got, readErr := os.ReadFile(filepath.Join(parent, "attacker.txt"))
	if readErr != nil || !bytes.Equal(got, attackerBytes) {
		t.Fatalf("attacker replacement bytes changed: got=%q err=%v", got, readErr)
	}
	if _, statErr := os.Lstat(filepath.Join(retainedParent, "candidate-output")); !os.IsNotExist(statErr) {
		t.Fatalf("retained parent exposed final output: %v", statErr)
	}
}

func TestSourcePackageOutputRejectsLinkOrReparseParent(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real")
	linkParent := filepath.Join(base, "link")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatalf("create link/reparse test fixture: %v", err)
	}
	root := filepath.Join(linkParent, "candidate-output")
	err := publishFactorySourceOutputDirectoryExclusive(root, []factorySourceOutputFile{{RelativePath: "candidate.txt", Raw: []byte("candidate\n")}})
	if err == nil {
		t.Fatal("link/reparse parent was followed")
	}
	if _, statErr := os.Lstat(filepath.Join(realParent, "candidate-output")); !os.IsNotExist(statErr) {
		t.Fatalf("link target received final output: %v", statErr)
	}
}

func TestSourcePackageOutputConcurrentNoReplacePublishesOneCompleteTree(t *testing.T) {
	root := filepath.Join(t.TempDir(), "candidate-output")
	rosters := [][]factorySourceOutputFile{
		{{RelativePath: "winner.txt", Raw: []byte("first\n")}, {RelativePath: "nested/first.txt", Raw: []byte("first nested\n")}},
		{{RelativePath: "winner.txt", Raw: []byte("second\n")}, {RelativePath: "nested/second.txt", Raw: []byte("second nested\n")}},
	}
	start := make(chan struct{})
	errorsByRun := make([]error, len(rosters))
	var wait sync.WaitGroup
	for index := range rosters {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			errorsByRun[index] = publishFactorySourceOutputDirectoryExclusive(root, rosters[index])
		}(index)
	}
	close(start)
	wait.Wait()
	successes := 0
	winner := -1
	for index, err := range errorsByRun {
		if err == nil {
			successes++
			winner = index
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent publication successes = %d, want 1; errors=%v", successes, errorsByRun)
	}
	assertExactSourcePackageOutputTree(t, root, rosters[winner])
}

func assertExactSourcePackageOutputTree(t *testing.T, root string, roster []factorySourceOutputFile) {
	t.Helper()
	want := make(map[string][]byte, len(roster))
	for _, entry := range roster {
		want[entry.RelativePath] = entry.Raw
	}
	var gotPaths []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root || entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		gotPaths = append(gotPaths, relative)
		got, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if expected, ok := want[relative]; !ok || !bytes.Equal(got, expected) {
			t.Fatalf("published file %q bytes = %q, want %q (declared=%v)", relative, got, expected, ok)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := make([]string, 0, len(want))
	for relative := range want {
		wantPaths = append(wantPaths, relative)
	}
	sort.Strings(gotPaths)
	sort.Strings(wantPaths)
	if strings.Join(gotPaths, "\n") != strings.Join(wantPaths, "\n") {
		t.Fatalf("published roster = %v, want %v", gotPaths, wantPaths)
	}
}

func assertNoSourcePackageOutputStages(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".factory-output-stage-") {
			t.Fatalf("publisher-owned private stage remained after failure: %s", entry.Name())
		}
	}
}
