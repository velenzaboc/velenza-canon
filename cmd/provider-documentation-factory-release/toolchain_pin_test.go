package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The release ceremony accepts exactly one Go toolchain patch (releaseGoVersion,
// checked by string equality in verifyGoVersion and against the child receipt's
// build info). Operator release documentation must name that exact patch. Guarded source
// verification independently uses the installed local compiler and never
// installs a toolchain or executes the release ceremony.
func TestReleaseToolchainPinsAgree(t *testing.T) {
	exactPatch := regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)
	if !exactPatch.MatchString(releaseGoVersion) {
		t.Fatalf("releaseGoVersion %q is not one exact Go patch release", releaseGoVersion)
	}
	want := strings.TrimPrefix(releaseGoVersion, "go")

	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	read := func(relative string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		return strings.ReplaceAll(string(raw), "\r\n", "\n")
	}

	// Verification runs under the owner's installed, locally selected compiler.
	// Release remains separately bound to its exact independently selected
	// toolchain; retiring hosted CI must not loosen that release trust root.
	localGate := read("scripts/verify-local.sh")
	if !strings.Contains(localGate, "GOTOOLCHAIN=local") || !strings.Contains(localGate, "go version") {
		t.Fatal("local verification must use and report the installed compiler")
	}
	if _, err := os.Stat(filepath.Join(repositoryRoot, ".github", "workflows", "ci.yml")); !os.IsNotExist(err) {
		t.Fatal("automatic hosted test workflow must remain absent")
	}

	readme := read("README.md")
	for _, pattern := range []string{
		`independently selected absolute Go ([^ ]+) and Git`,
		`<absolute-go-([^>]+)-executable>`,
	} {
		matches := regexp.MustCompile(pattern).FindAllStringSubmatch(readme, -1)
		if len(matches) == 0 {
			t.Fatalf("README.md no longer documents the release Go trust root with %q", pattern)
		}
		for _, match := range matches {
			if match[1] != want {
				t.Fatalf("README.md documents Go %q, want the release trust-root patch %q", match[1], want)
			}
		}
	}
}
