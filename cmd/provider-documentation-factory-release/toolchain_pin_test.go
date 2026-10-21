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
// build info). The repository's own CI jobs and the operator documentation must
// name that same exact patch; otherwise the release tests run under a toolchain
// the trust root refuses, which is how go_version "1.27" (resolving to go1.27.1)
// silently diverged from the go1.27.0 pin.
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

	workflow := read(".github/workflows/ci.yml")
	workflowPins := regexp.MustCompile(`(?m)^\s*go[-_]version:\s*(.*?)\s*$`).FindAllStringSubmatch(workflow, -1)
	if len(workflowPins) != 1 {
		t.Fatalf("ci.yml declares %d Go toolchain selections, want exactly 1", len(workflowPins))
	}
	for _, pin := range workflowPins {
		if got := strings.Trim(pin[1], `"'`); got != want {
			t.Fatalf("ci.yml selects Go %q, want the release trust-root patch %q", pin[1], want)
		}
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
