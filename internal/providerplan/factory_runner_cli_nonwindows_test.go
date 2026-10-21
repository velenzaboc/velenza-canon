//go:build !windows

package providerplan

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFactoryCleanSourceRejectsTrackedFileThroughSymlinkParent(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	trackedRoot := filepath.Join(sourceRoot, "tracked-parent")
	if err := os.MkdirAll(trackedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	trackedPath := filepath.Join(trackedRoot, "tracked.go")
	if err := os.WriteFile(trackedPath, []byte("package tracked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFactoryCommand(t, sourceRoot, factoryCommandOptions{name: "git", args: []string{"add", "tracked-parent/tracked.go"}})
	if err := os.Remove(trackedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(trackedRoot); err != nil {
		t.Fatal(err)
	}
	externalRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(externalRoot, "tracked.go"), []byte("package external\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(externalRoot, trackedRoot); err != nil {
		t.Fatal(err)
	}
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "symbolic link or reparse point")
}

func TestFactoryCleanSourceRejectsCanonicalPathSymlink(t *testing.T) {
	if runFactoryCleanSourceCopyFailureChild(t) {
		return
	}
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	canonicalParent := filepath.Join(sourceRoot, "_canonical")
	if err := os.MkdirAll(canonicalParent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(canonicalParent, "specs-repo")); err != nil {
		t.Fatal(err)
	}
	assertFactoryCleanSourceCopyFails(t, sourceRoot, "symbolic link or reparse point")
}

func TestFactoryCleanSourceCopiesWhitespaceOnlyFilename(t *testing.T) {
	sourceRoot := newFactoryCleanSourceTestRepository(t)
	name := " "
	want := []byte("exact whitespace-name bytes\n")
	if err := os.WriteFile(filepath.Join(sourceRoot, name), want, 0o600); err != nil {
		t.Fatal(err)
	}
	targetRoot := filepath.Join(t.TempDir(), "clean-source")
	copyFactoryTrackedAndCandidateSource(t, sourceRoot, targetRoot)
	got, err := os.ReadFile(filepath.Join(targetRoot, name))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("copied whitespace-only filename bytes = %q, want %q", got, want)
	}
}
