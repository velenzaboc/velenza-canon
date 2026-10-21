//go:build !windows

package providerplan

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSourcePackageOutputRejectsWholeStageSubstitutionAfterPrepare(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "candidate-output")
	publisherBytes := []byte("publisher plaintext\n")
	attackerBytes := []byte("attacker replacement\n")
	var substitutedStage string
	var retainedStage string

	err := publishFactorySourceOutputDirectoryExclusiveWithHooks(root, []factorySourceOutputFile{
		{RelativePath: "declared.txt", Raw: publisherBytes},
	}, sourcePackageOutputHooks{
		afterPrepare: func(stagePath string) error {
			substitutedStage = stagePath
			retainedStage = stagePath + ".retained"
			if err := os.Rename(stagePath, retainedStage); err != nil {
				return err
			}
			if err := os.Mkdir(stagePath, 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(stagePath, "attacker.txt"), attackerBytes, 0o600)
		},
	})
	if err == nil || !strings.Contains(err.Error(), "changed path identity") {
		t.Fatalf("whole-stage substitution error = %v, want path-identity refusal", err)
	}
	if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
		t.Fatalf("whole-stage substitution reached final coordinate: %v", statErr)
	}
	got, readErr := os.ReadFile(filepath.Join(substitutedStage, "attacker.txt"))
	if readErr != nil || !bytes.Equal(got, attackerBytes) {
		t.Fatalf("publisher altered attacker-substituted stage: got=%q err=%v", got, readErr)
	}
	if retained, retainedErr := os.ReadFile(filepath.Join(retainedStage, "declared.txt")); retainedErr == nil && bytes.Contains(retained, publisherBytes) {
		t.Fatalf("publisher plaintext remained reachable after whole-stage substitution")
	} else if retainedErr != nil && !os.IsNotExist(retainedErr) {
		t.Fatalf("inspect retained publisher stage: %v", retainedErr)
	}
}

func TestSourcePackageOutputErasesPartialPlaintextOnConstructionFailure(t *testing.T) {
	tests := []struct {
		name  string
		apply func(*sourcePackageOutputHooks, error)
	}{
		{name: "after data write", apply: func(hooks *sourcePackageOutputHooks, injected error) {
			hooks.afterFileDataWrite = func(string) error { return injected }
		}},
		{name: "before sync", apply: func(hooks *sourcePackageOutputHooks, injected error) {
			hooks.beforeFileSync = func(string) error { return injected }
		}},
		{name: "after sync before readback", apply: func(hooks *sourcePackageOutputHooks, injected error) {
			hooks.afterFileSync = func(string) error { return injected }
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			parent := t.TempDir()
			root := filepath.Join(parent, "candidate-output")
			injected := errors.New("injected construction failure")
			hooks := sourcePackageOutputHooks{}
			testCase.apply(&hooks, injected)
			err := publishFactorySourceOutputDirectoryExclusiveWithHooks(root, []factorySourceOutputFile{
				{RelativePath: "nested/declared.txt", Raw: []byte("publisher plaintext\n")},
			}, hooks)
			if !errors.Is(err, injected) {
				t.Fatalf("construction failure = %v, want injected error", err)
			}
			if _, statErr := os.Lstat(root); !os.IsNotExist(statErr) {
				t.Fatalf("construction failure exposed final root: %v", statErr)
			}
			assertNoSourcePackageOutputStages(t, parent)
		})
	}
}
