//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// resolveReleaseReceiptUnixPath's component validator rejects an empty
// component produced by a doubled path separator, distinct from the
// not-absolute/not-canonical branch already covered elsewhere.
func TestResolveReleaseReceiptUnixPathRejectsEmptyComponent(t *testing.T) {
	if _, err := resolveReleaseReceiptUnixPath("/a//b"); err == nil {
		t.Fatal("path with an empty component from a doubled separator was accepted")
	}
}

// releaseReceiptUnixFileIdentity is a thin Fstat wrapper; a closed file
// descriptor exercises its error return without any filesystem race.
func TestReleaseReceiptUnixFileIdentityRejectsClosedFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "f.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := releaseReceiptUnixFileIdentity(file); err == nil {
		t.Fatal("releaseReceiptUnixFileIdentity accepted a closed file descriptor")
	}
}

// verifyReleaseReceiptBytes seeks then reads; a directory file descriptor
// seeks successfully but fails the subsequent read, exercising the read
// error branch without needing a race.
func TestVerifyReleaseReceiptBytesRejectsDirectoryDescriptor(t *testing.T) {
	root := t.TempDir()
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := verifyReleaseReceiptBytes(dir, []byte("expected")); err == nil {
		t.Fatal("verifyReleaseReceiptBytes accepted a directory file descriptor")
	}
}

// Renaming the whole parent directory away (rather than swapping the final
// leaf, which the existing hook tests already cover) between the durable
// write and the caller-visible reopen must be detected by
// reopenVisibleReleaseReceiptUnixPath's own parent re-resolution.
func TestPublishValidatedReceiptDetectsUnixParentVanishingBeforeVisibleCheck(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	moved := filepath.Join(root, "moved-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "receipt.json")
	raw := []byte("validated receipt")
	vanished := false
	err := publishValidatedReceiptWithHooks(path, raw, publishValidatedReceiptHooks{
		beforeVisibleCheck: func() error {
			if err := os.Rename(parent, moved); err != nil {
				return err
			}
			vanished = true
			return nil
		},
	})
	if err == nil || !vanished {
		t.Fatalf("parent-vanishing result = %v, vanished=%t; want detected vanishing", err, vanished)
	}
	owned, readErr := os.ReadFile(filepath.Join(moved, "receipt.json"))
	if readErr != nil || string(owned) != string(raw) {
		t.Fatalf("owned receipt was not left safely in the moved parent: bytes=%q err=%v", owned, readErr)
	}
}
