package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// validateNoDuplicateJSONKeys (reached only through decodeReleaseJSONObject,
// which is unexported and called directly here) must reject trailing bytes
// that are themselves invalid JSON syntax, distinct from the
// already-tested case of a second well-formed top-level value.
func TestDecodeReleaseJSONObjectRejectsMalformedTrailingBytes(t *testing.T) {
	if _, err := decodeReleaseJSONObject([]byte(`{}x`)); err == nil {
		t.Fatal("JSON object followed by an invalid trailing byte was accepted")
	}
}

func TestDecodeReleaseJSONObjectRejectsUnclosedObjectAndArray(t *testing.T) {
	t.Run("unclosed object", func(t *testing.T) {
		if _, err := decodeReleaseJSONObject([]byte(`{"a":1`)); err == nil {
			t.Fatal("an unclosed JSON object was accepted")
		}
	})
	t.Run("unclosed nested array", func(t *testing.T) {
		if _, err := decodeReleaseJSONObject([]byte(`{"a":[1,2`)); err == nil {
			t.Fatal("an unclosed JSON array was accepted")
		}
	})
}

// canonicalReleaseDigest fails whenever the object cannot be marshalled as
// JSON; a channel value is a legitimate way to force that without any I/O.
func TestValidateObjectSelfDigestRejectsUnmarshalableObject(t *testing.T) {
	object := map[string]any{
		"digest":    "",
		"unmarshal": make(chan int),
	}
	expected := strings.Repeat("a", 64)
	if err := validateObjectSelfDigest(object, "digest", expected); err == nil {
		t.Fatal("an object containing an unmarshalable value was accepted for self-digest validation")
	}
}

// removeReleaseWorkspace is a pure guard-railed helper; a root whose name
// matches the expected prefix and parent but does not actually exist on disk
// must be refused (a no-op) rather than silently ignored without exercising
// the existence check.
func TestRemoveReleaseWorkspaceRefusesNonexistentRoot(t *testing.T) {
	tempRoot := t.TempDir()
	root := filepath.Join(tempRoot, "velenza-provider-factory-release-absent")
	// removeReleaseWorkspace has no return value to assert on; call it and
	// confirm it neither panics nor creates the absent root, exercising the
	// Lstat-failure guard instead of silently returning earlier.
	removeReleaseWorkspace(tempRoot, root)
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("removeReleaseWorkspace unexpectedly created or left a trace at %q: %v", root, err)
	}
}

// physicalTempDirectory refuses a non-absolute OS temporary directory.
func TestPhysicalTempDirectoryRejectsRelativeEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("TMP", "relative-temp")
		t.Setenv("TEMP", "relative-temp")
	} else {
		t.Setenv("TMPDIR", "relative-temp")
	}
	if _, err := physicalTempDirectory(); err == nil {
		t.Fatal("a relative OS temporary directory was accepted")
	}
}

func TestMeasureGitHelperTreeRejectsMissingRootAndEmptyTree(t *testing.T) {
	t.Run("missing root", func(t *testing.T) {
		root := t.TempDir()
		if _, err := measureGitHelperTree(filepath.Join(root, "absent")); err == nil {
			t.Fatal("a missing Git helper trust root was accepted")
		}
	})
	t.Run("empty tree", func(t *testing.T) {
		root := t.TempDir()
		if _, err := measureGitHelperTree(root); err == nil {
			t.Fatal("an empty Git helper trust root was accepted")
		}
	})
}
