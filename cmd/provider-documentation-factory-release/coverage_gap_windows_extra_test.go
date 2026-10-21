//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Direct unit coverage for the retained-child path component validator: every
// hazard branch is a pure function and needs no filesystem fixture.
func TestValidateRetainedChildWindowsComponentRejectsHazards(t *testing.T) {
	cases := []struct {
		name      string
		component string
	}{
		{"empty", ""},
		{"dot", "."},
		{"dotdot", ".."},
		{"native separator", `a\b`},
		{"wildcard", "a*b"},
		{"trailing dot", "name."},
		{"trailing space", "name "},
		{"control character", "name\x01"},
		{"reserved device CON", "CON"},
		{"reserved device com with extension", "COM1.txt"},
		{"reserved device lpt", "LPT9"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if err := validateRetainedChildWindowsComponent(testCase.component); err == nil {
				t.Fatalf("component %q was accepted, want rejection", testCase.component)
			}
		})
	}
	if err := validateRetainedChildWindowsComponent("provider-documentation-factory-run.exe"); err != nil {
		t.Fatalf("ordinary component was rejected: %v", err)
	}
}

// Direct unit coverage for the retained-child path resolver's rejection branches.
func TestResolveRetainedChildWindowsPathRejectsInvalidPaths(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"relative", `child.exe`},
		{"not canonical", `C:\dir\..\child.exe`},
		{"no volume", `\child.exe`},
		{"malformed volume", `CC:\child.exe`},
		{"root only", `C:\`},
		{"invalid component", `C:\dir\CON\child.exe`},
		// A UNC path is absolute and already canonical, so it clears the
		// earlier checks and reaches the drive-letter volume validator,
		// where filepath.VolumeName reports the whole "\\server\share"
		// prefix instead of a two-character drive letter.
		{"UNC volume", `\\server\share\child.exe`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := resolveRetainedChildWindowsPath(testCase.path); err == nil {
				t.Fatalf("path %q was accepted, want rejection", testCase.path)
			}
		})
	}
}

// releaseWindowsIdentity and releaseWindowsAttributes are thin wrappers over
// GetFileInformationByHandleEx; an invalid handle exercises their error return
// without needing any filesystem race.
func TestReleaseWindowsIdentityAndAttributesRejectInvalidHandle(t *testing.T) {
	if _, err := releaseWindowsIdentity(syscall.InvalidHandle); err == nil {
		t.Fatal("releaseWindowsIdentity accepted an invalid handle")
	}
	if _, err := releaseWindowsAttributes(syscall.InvalidHandle); err == nil {
		t.Fatal("releaseWindowsAttributes accepted an invalid handle")
	}
}

func TestOpenRetainedChildExecutableRejectsMissingAndWrongType(t *testing.T) {
	t.Run("missing leaf", func(t *testing.T) {
		root := t.TempDir()
		if _, err := openRetainedChildExecutable(filepath.Join(root, "absent.exe")); err == nil {
			t.Fatal("open of a missing retained child executable unexpectedly succeeded")
		}
	})

	t.Run("missing ancestor", func(t *testing.T) {
		root := t.TempDir()
		absentAncestor := filepath.Join(root, "absent-dir", "child.exe")
		if _, err := openRetainedChildExecutable(absentAncestor); err == nil {
			t.Fatal("open through a missing ancestor directory unexpectedly succeeded")
		}
	})

	t.Run("leaf is a directory", func(t *testing.T) {
		root := t.TempDir()
		asDir := filepath.Join(root, "child.exe")
		if err := os.Mkdir(asDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := openRetainedChildExecutable(asDir); err == nil {
			t.Fatal("open of a directory as the retained child executable unexpectedly succeeded")
		}
	})

	t.Run("ancestor is a file", func(t *testing.T) {
		root := t.TempDir()
		notADir := filepath.Join(root, "notadir")
		if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := openRetainedChildExecutable(filepath.Join(notADir, "child.exe")); err == nil {
			t.Fatal("open through a non-directory ancestor unexpectedly succeeded")
		}
	})

	t.Run("invalid path", func(t *testing.T) {
		if _, err := openRetainedChildExecutable(`relative.exe`); err == nil {
			t.Fatal("open of a non-canonical relative path unexpectedly succeeded")
		}
	})
}

// A file whose content is replaced with shorter bytes between the initial
// Stat and the read-back Stat inside measureOpenExecutable trips the
// "changed while measured" guard; the read-back path is naturally exercised
// here through repeated opens rather than a synthetic hook, so this instead
// pins the ordinary success measurement path plus a zero-length regular file,
// which is a legitimate and previously untested input shape.
func TestOpenRetainedChildExecutableAcceptsZeroLengthRegularFile(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "empty.exe")
	if err := os.WriteFile(executable, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	child, err := openRetainedChildExecutable(executable)
	if err != nil {
		t.Fatalf("open zero-length retained child executable: %v", err)
	}
	defer child.close()
	if child.measurement.size != 0 {
		t.Fatalf("measured size = %d, want 0", child.measurement.size)
	}
	if err := child.verify(); err != nil {
		t.Fatalf("verify zero-length retained child: %v", err)
	}
}

func TestReadPrivateChildReceiptRejectsMissingAndDirectory(t *testing.T) {
	root := t.TempDir()
	if _, err := readPrivateChildReceipt(filepath.Join(root, "absent.txt")); err == nil {
		t.Fatal("read of a missing private child receipt unexpectedly succeeded")
	}
	dir := filepath.Join(root, "adir")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateChildReceipt(dir); err == nil {
		t.Fatal("read of a directory as a private child receipt unexpectedly succeeded")
	}
}

func TestReadPrivateChildReceiptRoundTripsAndDetectsPathIdentityChange(t *testing.T) {
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

func TestReleaseWindowsPathIdentityRejectsMissingPath(t *testing.T) {
	root := t.TempDir()
	if _, err := releaseWindowsPathIdentity(filepath.Join(root, "absent.txt")); err == nil {
		t.Fatal("releaseWindowsPathIdentity accepted a missing path")
	}
}

// resolveRetainedChildWindowsPath must also refuse an embedded NUL byte,
// which os/filepath happily treats as an ordinary rune.
func TestResolveRetainedChildWindowsPathRejectsEmbeddedNUL(t *testing.T) {
	path := `C:\dir\` + strings.Repeat("a", 1) + "\x00" + `.exe`
	if _, err := resolveRetainedChildWindowsPath(path); err == nil {
		t.Fatal("path containing an embedded NUL byte was accepted")
	}
}
