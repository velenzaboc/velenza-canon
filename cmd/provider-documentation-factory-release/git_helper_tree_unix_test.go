//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestReleaseWorkspacePhysicalizesLogicalTemporaryRoot(t *testing.T) {
	physicalRoot := t.TempDir()
	aliasParent := t.TempDir()
	logicalRoot := filepath.Join(aliasParent, "logical-temp")
	if err := os.Symlink(physicalRoot, logicalRoot); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", logicalRoot)

	fixture := newReleaseFixture(t, false)
	workspace, err := newReleaseWorkspace(fixture.goPath, fixture.gitPath)
	if err != nil {
		t.Fatal(err)
	}
	defer removeReleaseWorkspace(workspace.tempRoot, workspace.root)
	if !sameNativePath(workspace.tempRoot, physicalRoot) {
		t.Fatalf("release temp root = %q, want physical %q", workspace.tempRoot, physicalRoot)
	}
	if !sameNativePath(filepath.Dir(workspace.root), physicalRoot) {
		t.Fatalf("release workspace = %q, want direct child of %q", workspace.root, physicalRoot)
	}
	if info, err := os.Lstat(workspace.root); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		t.Fatal("release workspace is not a physical directory")
	}

	roster, err := createCommitProjection(fixture.gitPath, fixture.root, fixture.commit, workspace)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCommitProjection(fixture.gitPath, fixture.commit, workspace.projectionRoot, workspace.onlineEnv, roster); err != nil {
		t.Fatalf("physicalized commit projection failed verification: %v", err)
	}
}

func TestMeasureGitHelperTreeBindsRelativeAliasesAndUniquePayloads(t *testing.T) {
	root := t.TempDir()
	externalRoot := t.TempDir()
	internalPayload := filepath.Join(root, "git-internal")
	externalPayload := filepath.Join(externalRoot, "git-external")
	writeTestFile(t, internalPayload, []byte("internal-helper\n"), 0o755)
	writeTestFile(t, externalPayload, []byte("external-helper\n"), 0o755)
	internalAlias := filepath.Join(root, "git-alias-internal")
	externalAlias := filepath.Join(root, "git-alias-external")
	if err := os.Symlink("git-internal", internalAlias); err != nil {
		t.Fatal(err)
	}
	externalRelative, err := filepath.Rel(root, externalPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(externalRelative, externalAlias); err != nil {
		t.Fatal(err)
	}

	first, err := measureGitHelperTree(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := measureGitHelperTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("stable Git helper tree measured differently: first=%+v second=%+v", first, second)
	}
	wantBytes := int64(len("internal-helper\n") + len("external-helper\n"))
	if first.files != 2 || first.bytes != wantBytes {
		t.Fatalf("unique Git helper closure = %d files/%d bytes, want 2/%d", first.files, first.bytes, wantBytes)
	}

	if err := os.Remove(internalAlias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("./git-internal", internalAlias); err != nil {
		t.Fatal(err)
	}
	rawTargetChanged, err := measureGitHelperTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if rawTargetChanged.digest == first.digest {
		t.Fatal("Git helper tree digest did not bind the raw relative alias target")
	}

	writeTestFile(t, externalPayload, []byte("external-change\n"), 0o755)
	payloadChanged, err := measureGitHelperTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if payloadChanged.digest == rawTargetChanged.digest {
		t.Fatal("Git helper tree digest did not bind resolved target bytes")
	}
}

func TestMeasureGitHelperTreeRejectsUnsafeAliases(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T, string)
	}{
		{
			name: "absolute target",
			build: func(t *testing.T, root string) {
				target := filepath.Join(t.TempDir(), "git-target")
				writeTestFile(t, target, []byte("helper\n"), 0o755)
				mustSymlink(t, target, filepath.Join(root, "git-absolute"))
			},
		},
		{
			name: "dangling target",
			build: func(t *testing.T, root string) {
				mustSymlink(t, "missing-helper", filepath.Join(root, "git-dangling"))
			},
		},
		{
			name: "directory target",
			build: func(t *testing.T, root string) {
				directory := filepath.Join(root, "helper-directory")
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, "helper-directory", filepath.Join(root, "git-directory"))
			},
		},
		{
			name: "cycle",
			build: func(t *testing.T, root string) {
				mustSymlink(t, "git-cycle-b", filepath.Join(root, "git-cycle-a"))
				mustSymlink(t, "git-cycle-a", filepath.Join(root, "git-cycle-b"))
			},
		},
		{
			name: "non executable target",
			build: func(t *testing.T, root string) {
				writeTestFile(t, filepath.Join(root, "not-executable"), []byte("helper\n"), 0o644)
				mustSymlink(t, "not-executable", filepath.Join(root, "git-non-executable"))
			},
		},
		{
			name: "non regular target",
			build: func(t *testing.T, root string) {
				fifo := filepath.Join(root, "helper-fifo")
				if err := syscall.Mkfifo(fifo, 0o700); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, "helper-fifo", filepath.Join(root, "git-fifo"))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.build(t, root)
			if _, err := measureGitHelperTree(root); err == nil || !strings.Contains(err.Error(), "Git helper") {
				t.Fatalf("unsafe Git helper alias was accepted: %v", err)
			}
		})
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
