//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishValidatedReceiptRejectsSymlinkParentAndFinal(t *testing.T) {
	t.Run("parent", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkParent := filepath.Join(root, "link-parent")
		if err := os.Symlink(realParent, linkParent); err != nil {
			t.Fatal(err)
		}
		if err := publishValidatedReceipt(filepath.Join(linkParent, "receipt.json"), []byte("receipt")); err == nil {
			t.Fatal("validated receipt publication followed a symlink parent")
		}
		if _, err := os.Lstat(filepath.Join(realParent, "receipt.json")); !os.IsNotExist(err) {
			t.Fatalf("symlink parent target was modified: %v", err)
		}
	})

	t.Run("final", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target.json")
		if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "receipt.json")
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		if err := publishValidatedReceipt(path, []byte("receipt")); err == nil {
			t.Fatal("validated receipt publication replaced a symlink final target")
		}
		persisted, err := os.ReadFile(target)
		if err != nil || !bytes.Equal(persisted, []byte("target")) {
			t.Fatalf("symlink final target changed: bytes=%q err=%v", persisted, err)
		}
	})
}

func TestPublishValidatedReceiptDetectsParentReplacementAndLeavesUnknownPath(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	moved := filepath.Join(root, "retained-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "receipt.json")
	raw := []byte("validated receipt")
	replaced := false
	err := publishValidatedReceiptWithHooks(path, raw, publishValidatedReceiptHooks{
		afterParentOpen: func() error {
			if err := os.Rename(parent, moved); err != nil {
				return fmt.Errorf("rename retained parent: %w", err)
			}
			if err := os.Mkdir(parent, 0o700); err != nil {
				return fmt.Errorf("create unknown replacement parent: %w", err)
			}
			if err := os.WriteFile(filepath.Join(parent, "unknown.txt"), []byte("unknown"), 0o600); err != nil {
				return err
			}
			replaced = true
			return nil
		},
	})
	if err == nil || !replaced {
		t.Fatalf("parent replacement result = %v, replaced=%t; want detected replacement", err, replaced)
	}
	unknown, readErr := os.ReadFile(filepath.Join(parent, "unknown.txt"))
	if readErr != nil || !bytes.Equal(unknown, []byte("unknown")) {
		t.Fatalf("unknown replacement parent was modified: bytes=%q err=%v", unknown, readErr)
	}
	owned, readErr := os.ReadFile(filepath.Join(moved, "receipt.json"))
	if readErr != nil || !bytes.Equal(owned, raw) {
		t.Fatalf("owned partial receipt was not left safely in place: bytes=%q err=%v", owned, readErr)
	}
}

func TestPublishValidatedReceiptDetectsFinalReplacementWithoutDeletingIt(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "receipt.json")
	moved := filepath.Join(root, "owned-receipt.json")
	raw := []byte("validated receipt")
	unknown := []byte("unknown replacement")
	replaced := false
	err := publishValidatedReceiptWithHooks(path, raw, publishValidatedReceiptHooks{
		beforeVisibleCheck: func() error {
			if err := os.Rename(path, moved); err != nil {
				return err
			}
			if err := os.WriteFile(path, unknown, 0o600); err != nil {
				return err
			}
			replaced = true
			return nil
		},
	})
	if err == nil || !replaced {
		t.Fatalf("final replacement result = %v, replaced=%t; want detected replacement", err, replaced)
	}
	persistedUnknown, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(persistedUnknown, unknown) {
		t.Fatalf("unknown replacement was modified or removed: bytes=%q err=%v", persistedUnknown, readErr)
	}
	persistedOwned, readErr := os.ReadFile(moved)
	if readErr != nil || !bytes.Equal(persistedOwned, raw) {
		t.Fatalf("owned receipt was not left safely in place: bytes=%q err=%v", persistedOwned, readErr)
	}
}

func TestPublishValidatedReceiptRechecksRetainedBytesAfterHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "receipt.json")
	raw := []byte("validated receipt")
	corrupt := []byte("corrupted receipt")
	err := publishValidatedReceiptWithHooks(path, raw, publishValidatedReceiptHooks{
		beforeVisibleCheck: func() error {
			return os.WriteFile(path, corrupt, 0o600)
		},
	})
	if err == nil {
		t.Fatal("same-identity receipt byte replacement was not detected")
	}
	persisted, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(persisted, corrupt) {
		t.Fatalf("owned corrupt partial file was destructively cleaned: bytes=%q err=%v", persisted, readErr)
	}
}
