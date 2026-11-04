package featuregraphprojection

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitReaderReadsPinnedRegularBlob(t *testing.T) {
	repo, commit := testRepository(t)
	reader := GitReader{}
	got, err := reader.ReadArtifact(context.Background(), Artifact{Commit: commit, Path: "docs/readme.txt", Role: "research"}, Repository{GitDir: filepath.Join(repo, ".git"), PathPrefixes: []string{"docs"}, Roles: []string{"research"}}, 1024)
	if err != nil {
		t.Fatalf("ReadArtifact() error = %v", err)
	}
	if string(got) != "evidence\n" {
		t.Fatalf("ReadArtifact() = %q", got)
	}
}

func TestGitReaderRefusesUnsafeInputsAndObjects(t *testing.T) {
	repo, commit := testRepository(t)
	gitDir := filepath.Join(repo, ".git")
	base := Repository{GitDir: gitDir, PathPrefixes: []string{"docs"}, Roles: []string{"research"}}
	reader := GitReader{}
	cases := []struct {
		name     string
		artifact Artifact
		repo     Repository
		limit    int
	}{
		{"path traversal", Artifact{Commit: commit, Path: "docs/../secret", Role: "research"}, base, 100},
		{"unapproved prefix", Artifact{Commit: commit, Path: "other.txt", Role: "research"}, base, 100},
		{"unapproved role", Artifact{Commit: commit, Path: "docs/readme.txt", Role: "other"}, base, 100},
		{"short hash", Artifact{Commit: commit[:39], Path: "docs/readme.txt", Role: "research"}, base, 100},
		{"nonhex hash", Artifact{Commit: strings.Repeat("g", 40), Path: "docs/readme.txt", Role: "research"}, base, 100},
		{"commitish ref", Artifact{Commit: "HEAD", Path: "docs/readme.txt", Role: "research"}, base, 100},
		{"missing blob", Artifact{Commit: commit, Path: "docs/missing.txt", Role: "research"}, base, 100},
		{"byte cap", Artifact{Commit: commit, Path: "docs/readme.txt", Role: "research"}, base, 2},
		{"symlink", Artifact{Commit: commit, Path: "docs/link", Role: "research"}, base, 100},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := reader.ReadArtifact(context.Background(), test.artifact, test.repo, test.limit); err == nil {
				t.Fatal("ReadArtifact() succeeded, want refusal")
			}
		})
	}
}

func testRepository(t *testing.T) (string, string) {
	t.Helper()
	repo := t.TempDir()
	runGit(t, repo, "init", "-q")
	runGit(t, repo, "config", "user.email", "test@example.invalid")
	runGit(t, repo, "config", "user.name", "Test")
	if err := os.Mkdir(filepath.Join(repo, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "docs", "readme.txt"), []byte("evidence\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("readme.txt", filepath.Join(repo, "docs", "link")); err != nil {
		t.Fatal(err)
	}
	runGit(t, repo, "add", ".")
	runGit(t, repo, "commit", "-qm", "fixture")
	return repo, strings.TrimSpace(runGit(t, repo, "rev-parse", "HEAD"))
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}
