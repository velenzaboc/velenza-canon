//go:build windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPublishValidatedReceiptRejectsWindowsAliasAndDeviceSyntax(t *testing.T) {
	root := t.TempDir()
	paths := []string{
		filepath.Join(root, "receipt.json:stream"),
		filepath.Join(root, "NUL.json"),
		filepath.Join(root, "receipt.json."),
		filepath.Join(root, "NAME~1", "receipt.json"),
	}
	for _, path := range paths {
		if err := publishValidatedReceipt(path, []byte("receipt")); err == nil {
			t.Fatalf("Windows alias/device path %q unexpectedly succeeded", path)
		}
	}
}

func TestPublishValidatedReceiptRejectsWindowsReparseParentAndFinal(t *testing.T) {
	t.Run("junction parent", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real-junction-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		junctionParent := filepath.Join(root, "junction-parent")
		if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junctionParent, realParent).CombinedOutput(); err != nil {
			t.Fatalf("create Windows junction positive control: %v\n%s", err, output)
		}
		if err := publishValidatedReceipt(filepath.Join(junctionParent, "receipt.json"), []byte("receipt")); err == nil {
			t.Fatal("validated receipt publication followed a junction parent")
		}
		if _, err := os.Lstat(filepath.Join(realParent, "receipt.json")); !os.IsNotExist(err) {
			t.Fatalf("junction parent target was modified: %v", err)
		}
	})

	t.Run("junction final", func(t *testing.T) {
		root := t.TempDir()
		realTarget := filepath.Join(root, "real-junction-target")
		if err := os.Mkdir(realTarget, 0o700); err != nil {
			t.Fatal(err)
		}
		junctionFinal := filepath.Join(root, "receipt.json")
		if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junctionFinal, realTarget).CombinedOutput(); err != nil {
			t.Fatalf("create Windows final-junction positive control: %v\n%s", err, output)
		}
		if err := publishValidatedReceipt(junctionFinal, []byte("receipt")); err == nil {
			t.Fatal("validated receipt publication replaced a junction final target")
		}
		entries, err := os.ReadDir(realTarget)
		if err != nil || len(entries) != 0 {
			t.Fatalf("junction final target was modified: entries=%v err=%v", entries, err)
		}
	})

	t.Run("parent", func(t *testing.T) {
		root := t.TempDir()
		realParent := filepath.Join(root, "real-parent")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkParent := filepath.Join(root, "link-parent")
		if err := os.Symlink(realParent, linkParent); err != nil {
			assertWindowsSymlinkCapabilityFailure(t, linkParent, err)
			return
		}
		if err := publishValidatedReceipt(filepath.Join(linkParent, "receipt.json"), []byte("receipt")); err == nil {
			t.Fatal("validated receipt publication followed a reparse parent")
		}
		if _, err := os.Lstat(filepath.Join(realParent, "receipt.json")); !os.IsNotExist(err) {
			t.Fatalf("reparse parent target was modified: %v", err)
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
			assertWindowsSymlinkCapabilityFailure(t, path, err)
			return
		}
		if err := publishValidatedReceipt(path, []byte("receipt")); err == nil {
			t.Fatal("validated receipt publication replaced a reparse final target")
		}
		persisted, err := os.ReadFile(target)
		if err != nil || !bytes.Equal(persisted, []byte("target")) {
			t.Fatalf("reparse final target changed: bytes=%q err=%v", persisted, err)
		}
	})
}

func assertWindowsSymlinkCapabilityFailure(t *testing.T, path string, err error) {
	t.Helper()
	const errorPrivilegeNotHeld syscall.Errno = 1314
	if !errors.Is(err, errorPrivilegeNotHeld) {
		t.Fatalf("create Windows symlink positive control: %v", err)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("privilege-refused Windows symlink left an unexpected path: %v", statErr)
	}
}

func TestPublishValidatedReceiptDetectsWindowsParentReplacementAndLeavesUnknownPath(t *testing.T) {
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

func TestPublishValidatedReceiptDetectsWindowsFinalReplacementWithoutDeletingIt(t *testing.T) {
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
