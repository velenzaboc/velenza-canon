//go:build windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Deleting (rather than replacing) the final leaf between the durable write
// and the caller-visible reopen exercises the "leaf vanished" branch of
// reopenVisibleReleaseReceiptWindowsPath, distinct from the already-tested
// unknown-replacement branch.
func TestPublishValidatedReceiptDetectsWindowsFinalDeletionBeforeVisibleCheck(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "receipt.json")
	raw := []byte("validated receipt")
	deleted := false
	err := publishValidatedReceiptWithHooks(path, raw, publishValidatedReceiptHooks{
		beforeVisibleCheck: func() error {
			if err := os.Remove(path); err != nil {
				return err
			}
			deleted = true
			return nil
		},
	})
	if err == nil || !deleted {
		t.Fatalf("final deletion result = %v, deleted=%t; want detected deletion", err, deleted)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("deleted receipt path unexpectedly recreated: %v", statErr)
	}
}

// validateReleaseReceiptWindowsOpenedPath's GetFinalPathNameByHandleW call
// fails outright for a closed handle, independent of any alias mismatch.
func TestValidateReleaseReceiptWindowsOpenedPathRejectsClosedHandle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "receipt.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	handle := syscall.Handle(file.Fd())
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validateReleaseReceiptWindowsOpenedPath(handle, path); err == nil {
		t.Fatal("validateReleaseReceiptWindowsOpenedPath accepted a closed handle")
	}
}

// resolveReleaseReceiptWindowsPath's drive-letter volume validator is
// unreachable through a merely malformed drive spelling (which fails the
// earlier absolute/canonical check instead); a UNC path is absolute and
// canonical yet still fails the two-character drive-letter shape.
func TestResolveReleaseReceiptWindowsPathRejectsUNCVolume(t *testing.T) {
	if _, err := resolveReleaseReceiptWindowsPath(`\\server\share\receipt.json`); err == nil {
		t.Fatal("a UNC path was accepted as a canonical drive-letter validated receipt path")
	}
}

func TestPublishValidatedReceiptRejectsEmptyBytesAndNonCanonicalPath(t *testing.T) {
	root := t.TempDir()
	if err := publishValidatedReceipt(filepath.Join(root, "receipt.json"), nil); err == nil {
		t.Fatal("publication of empty receipt bytes unexpectedly succeeded")
	}
	if err := publishValidatedReceipt(`relative\receipt.json`, []byte("receipt")); err == nil {
		t.Fatal("publication to a relative path unexpectedly succeeded")
	}
	if err := publishValidatedReceipt(filepath.Join(root, "missing-parent", "receipt.json"), []byte("receipt")); err == nil {
		t.Fatal("publication through a missing parent directory unexpectedly succeeded")
	}
}
