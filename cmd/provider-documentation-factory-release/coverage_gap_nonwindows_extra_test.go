//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenRetainedChildExecutableRejectsInvalidPathAndMissingAncestor(t *testing.T) {
	t.Run("invalid path", func(t *testing.T) {
		if _, err := openRetainedChildExecutable("relative.exe"); err == nil {
			t.Fatal("open of a non-canonical relative path unexpectedly succeeded")
		}
	})
	t.Run("missing ancestor", func(t *testing.T) {
		root := t.TempDir()
		if _, err := openRetainedChildExecutable(filepath.Join(root, "absent-dir", "child")); err == nil {
			t.Fatal("open through a missing ancestor directory unexpectedly succeeded")
		}
	})
}

func createRetainedUnixChildFixture(t *testing.T, content []byte) (root, executable string) {
	t.Helper()
	root = t.TempDir()
	executable = filepath.Join(root, "child")
	if err := os.WriteFile(executable, content, 0o700); err != nil {
		t.Fatal(err)
	}
	return root, executable
}

// verify() re-measures the retained file descriptor's own content on every
// call; overwriting the same inode in place (not replacing it) changes what
// that re-measurement reads without touching identity, exercising the
// "content changed" guard distinctly from the identity guard below.
func TestRetainedUnixChildVerifyDetectsInPlaceContentMutation(t *testing.T) {
	_, executable := createRetainedUnixChildFixture(t, []byte("original executable bytes"))
	child, err := openRetainedChildExecutable(executable)
	if err != nil {
		t.Fatalf("open retained child: %v", err)
	}
	defer child.close()
	if err := child.verify(); err != nil {
		t.Fatalf("verify unchanged retained child: %v", err)
	}
	if err := os.WriteFile(executable, []byte("mutated in place, same inode"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := child.verify(); err == nil {
		t.Fatal("verify did not detect in-place content mutation of the retained executable")
	}
}

// Deleting the leaf out from under a retained child leaves the open
// descriptor itself usable (Unix does not lock files), but the
// caller-visible path re-check inside verify()/verifyVisiblePath must refuse.
func TestRetainedUnixChildVerifyDetectsLeafDeletion(t *testing.T) {
	_, executable := createRetainedUnixChildFixture(t, []byte("executable bytes"))
	child, err := openRetainedChildExecutable(executable)
	if err != nil {
		t.Fatalf("open retained child: %v", err)
	}
	defer child.close()
	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	if err := child.verify(); err == nil {
		t.Fatal("verify did not detect the retained executable's leaf being deleted")
	}
}

// Replacing the leaf with a distinct file (new inode, same name) must be
// caught by the caller-visible identity comparison even though the retained
// descriptor's own fstat identity is unaffected.
func TestRetainedUnixChildVerifyDetectsLeafReplacement(t *testing.T) {
	_, executable := createRetainedUnixChildFixture(t, []byte("executable bytes"))
	child, err := openRetainedChildExecutable(executable)
	if err != nil {
		t.Fatalf("open retained child: %v", err)
	}
	defer child.close()
	if err := os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("executable bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := child.verify(); err == nil {
		t.Fatal("verify did not detect the retained executable's leaf being replaced with a new inode")
	}
}

// Renaming the whole ancestor directory away removes the stable parent path
// the caller-visible recheck depends on, distinct from a leaf-level change.
func TestRetainedUnixChildVerifyDetectsAncestorRenamedAway(t *testing.T) {
	root := t.TempDir()
	ancestor := filepath.Join(root, "locked")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(ancestor, "child")
	if err := os.WriteFile(executable, []byte("executable bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	child, err := openRetainedChildExecutable(executable)
	if err != nil {
		t.Fatalf("open retained child: %v", err)
	}
	defer child.close()
	moved := filepath.Join(root, "moved")
	if err := os.Rename(ancestor, moved); err != nil {
		t.Fatal(err)
	}
	if err := child.verify(); err == nil {
		t.Fatal("verify did not detect the retained executable's ancestor directory vanishing")
	}
}

func TestReadPrivateChildReceiptRejectsMissingAndDirectory(t *testing.T) {
	root := t.TempDir()
	if _, err := readPrivateChildReceipt(filepath.Join(root, "absent.txt")); err == nil {
		t.Fatal("read of a missing private child receipt unexpectedly succeeded")
	}
	if _, err := readPrivateChildReceipt(root); err == nil {
		t.Fatal("read of a directory as a private child receipt unexpectedly succeeded")
	}
}

func TestReadPrivateChildReceiptRoundTrips(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "receipt.txt")
	raw := []byte("private child receipt content")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivateChildReceipt(path)
	if err != nil {
		t.Fatalf("read private child receipt: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("read private child receipt = %q, want %q", got, raw)
	}
}
