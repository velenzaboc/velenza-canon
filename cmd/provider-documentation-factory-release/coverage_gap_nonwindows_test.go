//go:build !windows

package main

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunCapturedReportsExitAndAllowsExactlyOne(t *testing.T) {
	if _, err := runCaptured("/bin/sh", []string{"-c", "printf failure >&2; exit 2"}, "", nil); err == nil || !strings.Contains(err.Error(), "failure") {
		t.Fatalf("runCaptured error = %v", err)
	}
	if output, err := runCapturedAllowExitOne("/bin/sh", []string{"-c", "exit 1"}, "", nil); err != nil || output != nil {
		t.Fatalf("exit one output=%q err=%v", output, err)
	}
	if _, err := runCapturedAllowExitOne("/bin/sh", []string{"-c", "exit 2"}, "", nil); err == nil {
		t.Fatal("allowed exit status two")
	}
	if output, err := runCaptured("/bin/sh", []string{"-c", "printf success"}, "", nil); err != nil || string(output) != "success" {
		t.Fatalf("success output=%q err=%v", output, err)
	}
}

func writeExecutableScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "child.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExecuteReleaseRejectsEachUntrustedLauncherRoot(t *testing.T) {
	root := t.TempDir()
	validCommit := strings.Repeat("a", 40)
	goExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		options releaseOptions
		want    string
	}{
		{name: "source", options: releaseOptions{sourceRoot: filepath.Join(root, "missing")}, want: "source root"},
		{name: "commit", options: releaseOptions{sourceRoot: root, commit: "short"}, want: "commit is not"},
		{name: "Go", options: releaseOptions{sourceRoot: root, commit: validCommit, goExecutable: "relative"}, want: "measure Go"},
		{name: "Git", options: releaseOptions{sourceRoot: root, commit: validCommit, goExecutable: goExecutable, gitExecutable: "relative"}, want: "measure Git"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			err := executeRelease(test.options, io.Discard, io.Discard)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("executeRelease error = %v, want %q", err, test.want)
			}
		})
	}
	wrongGo := writeExecutableScript(t, "exit 0")
	gitExecutable := exactTestExecutable(t, "git")
	err = executeRelease(releaseOptions{sourceRoot: root, commit: validCommit, goExecutable: wrongGo, gitExecutable: gitExecutable}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "Go trust-root version") {
		t.Fatalf("wrong Go version error = %v", err)
	}
}

func TestExecuteAndValidateChildRejectsRuntimeBoundaryFailures(t *testing.T) {
	type scenario struct {
		name       string
		body       string
		prepare    func(t *testing.T, child *retainedChildExecutable)
		childArgs  []string
		wantExit   int
		wantPhrase string
	}
	cases := []scenario{
		{name: "selection", body: "exit 0", childArgs: []string{"--source-verification-receipt", "only.json"}, wantPhrase: "selection is incomplete"},
		{name: "output value", body: "exit 0", childArgs: []string{"--out"}, wantPhrase: "value is absent"},
		{name: "private exists", body: "exit 0", prepare: func(t *testing.T, child *retainedChildExecutable) {
			if err := os.WriteFile(child.measurement.path+".validated-receipt.json", []byte("occupied"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantPhrase: "private child receipt output is not new"},
		{name: "exit", body: "exit 7", wantExit: 7},
		{name: "stderr", body: "printf child-error >&2", wantPhrase: "emitted stderr"},
		{name: "stdout", body: "printf child-output", wantPhrase: "emitted stdout"},
		{name: "missing receipt", body: "exit 0", wantPhrase: "receipt does not match"},
		{name: "invalid receipt", body: `for last in "$@"; do :; done; printf '{"invalid":true}' > "$last"`, wantPhrase: "receipt does not match"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			path := writeExecutableScript(t, test.body)
			child, err := openRetainedChildExecutable(path)
			if err != nil {
				t.Fatal(err)
			}
			defer child.close()
			if test.prepare != nil {
				test.prepare(t, child)
			}
			options := releaseOptions{commit: strings.Repeat("a", 40), childArgs: append([]string(nil), test.childArgs...)}
			err = executeAndValidateChild(child, childBuildExpectation{}, options, t.TempDir(), os.Environ(), strings.Repeat("b", 64), measuredExecutable{}, measuredExecutable{}, measuredTree{}, measuredTree{}, io.Discard, io.Discard)
			if test.wantExit != 0 {
				var exit childExitError
				if !errors.As(err, &exit) || exit.code != test.wantExit {
					t.Fatalf("child error = %v, want exit %d", err, test.wantExit)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantPhrase) {
				t.Fatalf("child error = %v, want %q", err, test.wantPhrase)
			}
		})
	}

	t.Run("closed retained child", func(t *testing.T) {
		child, err := openRetainedChildExecutable(writeExecutableScript(t, "exit 0"))
		if err != nil {
			t.Fatal(err)
		}
		child.close()
		err = executeAndValidateChild(child, childBuildExpectation{}, releaseOptions{}, t.TempDir(), os.Environ(), "", measuredExecutable{}, measuredExecutable{}, measuredTree{}, measuredTree{}, io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "closed") {
			t.Fatalf("closed child error = %v", err)
		}
	})
}

func TestRetainedChildOpenAndPrivateReceiptBoundaries(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	if _, err := openRetainedChildExecutable(missing); err == nil {
		t.Fatal("opened missing retained child")
	}
	if _, err := openRetainedChildExecutable(root); err == nil {
		t.Fatal("opened directory retained child")
	}
	nonExecutable := filepath.Join(root, "plain")
	if err := os.WriteFile(nonExecutable, []byte("plain"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openRetainedChildExecutable(nonExecutable); err == nil {
		t.Fatal("opened non-executable retained child")
	}
	executable := writeExecutableScript(t, "exit 0")
	link := filepath.Join(root, "linked-child")
	if err := os.Symlink(executable, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openRetainedChildExecutable(link); err == nil {
		t.Fatal("opened symbolic-link retained child")
	}

	receipt := filepath.Join(root, "receipt.json")
	raw := []byte(`{"ok":true}`)
	if err := os.WriteFile(receipt, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readPrivateChildReceipt(receipt)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("receipt=%q err=%v", got, err)
	}
	for _, candidate := range []string{missing, root, link} {
		if _, err := readPrivateChildReceipt(candidate); err == nil {
			t.Errorf("read invalid private receipt %q", candidate)
		}
	}
}

func TestReceiptPublicationHookAndIdentityFailures(t *testing.T) {
	root := t.TempDir()
	raw := []byte(`{"receipt":true}`)
	after := filepath.Join(root, "after.json")
	err := publishValidatedReceiptWithHooks(after, raw, publishValidatedReceiptHooks{afterParentOpen: func() error {
		return errors.New("injected parent hook")
	}})
	if err == nil || !strings.Contains(err.Error(), "injected parent hook") {
		t.Fatalf("after-parent hook error = %v", err)
	}
	if _, err := os.Lstat(after); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("after-parent hook created output: %v", err)
	}

	before := filepath.Join(root, "before.json")
	err = publishValidatedReceiptWithHooks(before, raw, publishValidatedReceiptHooks{beforeVisibleCheck: func() error {
		return errors.New("injected visible hook")
	}})
	if err == nil || !strings.Contains(err.Error(), "injected visible hook") {
		t.Fatalf("before-visible hook error = %v", err)
	}
	persisted, readErr := os.ReadFile(before)
	if readErr != nil || !bytes.Equal(persisted, raw) {
		t.Fatalf("created receipt=%q err=%v", persisted, readErr)
	}

	if _, err := releaseReceiptUnixInfoIdentity(nil); err == nil {
		t.Fatal("accepted absent file identity")
	}
	if _, err := releaseReceiptUnixInfoIdentity(syntheticFileInfo{}); err == nil {
		t.Fatal("accepted unsupported file identity")
	}
}

func TestReopenVisibleReceiptRejectsParentAndLeafIdentityDrift(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "receipt.json")
	raw := []byte("receipt")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveReleaseReceiptUnixPath(path)
	if err != nil {
		t.Fatal(err)
	}
	parents, err := retainReleaseReceiptUnixParents(resolved)
	if err != nil {
		t.Fatal(err)
	}
	defer closeRetainedReleaseReceiptUnixParents(parents)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	created, err := releaseReceiptUnixInfoIdentity(info)
	if err != nil {
		t.Fatal(err)
	}
	if file, err := reopenVisibleReleaseReceiptUnixPath(resolved, parents[:len(parents)-1], created); err == nil {
		file.Close()
		t.Fatal("accepted shortened parent identity chain")
	}
	drifted := append([]retainedReleaseReceiptDirectory(nil), parents...)
	drifted[0].identity.inode++
	if file, err := reopenVisibleReleaseReceiptUnixPath(resolved, drifted, created); err == nil {
		file.Close()
		t.Fatal("accepted changed parent identity")
	}
	wrongCreated := created
	wrongCreated.inode++
	if file, err := reopenVisibleReleaseReceiptUnixPath(resolved, parents, wrongCreated); err == nil {
		file.Close()
		t.Fatal("accepted changed leaf identity")
	}
	missing := resolved
	missing.leaf = "missing.json"
	if file, err := reopenVisibleReleaseReceiptUnixPath(missing, parents, created); err == nil {
		file.Close()
		t.Fatal("reopened missing receipt leaf")
	}
}

type syntheticFileInfo struct{}

func (syntheticFileInfo) Name() string       { return "synthetic" }
func (syntheticFileInfo) Size() int64        { return 0 }
func (syntheticFileInfo) Mode() fs.FileMode  { return 0 }
func (syntheticFileInfo) ModTime() time.Time { return time.Time{} }
func (syntheticFileInfo) IsDir() bool        { return false }
func (syntheticFileInfo) Sys() any           { return "unsupported" }

func TestReleaseReceiptPathAndByteIOBoundaries(t *testing.T) {
	for _, invalid := range []string{"", " padded", "relative", "/", "/tmp/../tmp/out", "/tmp/caf\u00e9"} {
		if _, err := resolveReleaseReceiptUnixPath(invalid); err == nil {
			t.Errorf("accepted receipt path %q", invalid)
		}
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	resolved, err := resolveReleaseReceiptUnixPath(path)
	if err != nil || resolved.absolute != path || resolved.leaf != "receipt.json" || len(resolved.components) == 0 {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	missingParentPath := resolved
	missingParentPath.components = append(missingParentPath.components, "missing")
	if parents, err := retainReleaseReceiptUnixParents(missingParentPath); err == nil {
		closeRetainedReleaseReceiptUnixParents(parents)
		t.Fatal("retained missing receipt parent")
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("exact bytes")
	if err := writeReleaseReceiptBytes(file, raw); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseReceiptBytes(file, raw); err != nil {
		t.Fatal(err)
	}
	if err := verifyReleaseReceiptBytes(file, []byte("different")); err == nil {
		t.Fatal("accepted different persisted bytes")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeReleaseReceiptBytes(file, raw); err == nil {
		t.Fatal("wrote receipt through closed file")
	}
	if err := verifyReleaseReceiptBytes(file, raw); err == nil {
		t.Fatal("verified receipt through closed file")
	}
}

func TestToolTrustRootCommandOutputValidation(t *testing.T) {
	root := t.TempDir()
	environment := append(os.Environ(), "FIXTURE_ROOT="+root)
	tests := []struct {
		name string
		body string
		call func(string) error
		ok   bool
	}{
		{name: "Go version success", body: `printf '` + releaseGoVersion + `\n'`, call: func(path string) error { return verifyGoVersion(path, environment) }, ok: true},
		{name: "Go version mismatch", body: `printf 'go0.0.0\n'`, call: func(path string) error { return verifyGoVersion(path, environment) }},
		{name: "Go version neighbouring patch", body: `printf 'go1.27.0\n'`, call: func(path string) error { return verifyGoVersion(path, environment) }},
		{name: "Go version with suffix after the pin", body: `printf '` + releaseGoVersion + `-devel\n'`, call: func(path string) error { return verifyGoVersion(path, environment) }},
		{name: "Go version line prefix only", body: `printf 'go1.27\n'`, call: func(path string) error { return verifyGoVersion(path, environment) }},
		{name: "Go version command failure", body: `exit 2`, call: func(path string) error { return verifyGoVersion(path, environment) }},
		{name: "Go root success", body: `printf '%s\n' "$FIXTURE_ROOT"`, call: func(path string) error {
			got, err := resolveGoRoot(path, environment)
			if err == nil && !sameNativePath(got, root) {
				return errors.New("resolved a different Go root")
			}
			return err
		}, ok: true},
		{name: "Go root relative", body: `printf 'relative\n'`, call: func(path string) error { _, err := resolveGoRoot(path, environment); return err }},
		{name: "Go root absent", body: `printf '/definitely/missing/velenza-go-root\n'`, call: func(path string) error { _, err := resolveGoRoot(path, environment); return err }},
		{name: "Go root command failure", body: `exit 2`, call: func(path string) error { _, err := resolveGoRoot(path, environment); return err }},
		{name: "Git root success", body: `printf '%s\n' "$FIXTURE_ROOT"`, call: func(path string) error {
			got, err := resolveGitExecRoot(path, environment)
			if err == nil && !sameNativePath(got, root) {
				return errors.New("resolved a different Git root")
			}
			return err
		}, ok: true},
		{name: "Git root relative", body: `printf 'relative\n'`, call: func(path string) error { _, err := resolveGitExecRoot(path, environment); return err }},
		{name: "Git root absent", body: `printf '/definitely/missing/velenza-git-root\n'`, call: func(path string) error { _, err := resolveGitExecRoot(path, environment); return err }},
		{name: "Git root command failure", body: `exit 2`, call: func(path string) error { _, err := resolveGitExecRoot(path, environment); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call(writeExecutableScript(t, test.body))
			if test.ok && err != nil {
				t.Fatal(err)
			}
			if !test.ok && err == nil {
				t.Fatal("invalid trust-root output was accepted")
			}
		})
	}
}

func TestVerifySourceRepositoryRejectsEachGitTrustFailure(t *testing.T) {
	root := t.TempDir()
	commit := strings.Repeat("a", 40)
	environment := append(os.Environ(), "FIXTURE_ROOT="+root, "FIXTURE_COMMIT="+commit)
	base := `
case "$*" in
  *--show-toplevel*) printf '%s\n' "$FIXTURE_ROOT" ;;
  *cat-file*) exit 0 ;;
  *'rev-parse --verify'*) printf '%s\n' "$FIXTURE_COMMIT" ;;
  *for-each-ref*) exit 0 ;;
  *) exit 3 ;;
esac`
	if err := verifySourceRepository(writeExecutableScript(t, base), root, commit, environment); err != nil {
		t.Fatalf("valid source repository relay failed: %v", err)
	}
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "top-level command", body: `exit 2`, want: "resolve source Git repository"},
		{name: "different top-level", body: `case "$*" in *--show-toplevel*) printf '/tmp\n';; *) exit 0;; esac`, want: "exact Git repository root"},
		{name: "missing commit", body: `case "$*" in *--show-toplevel*) printf '%s\n' "$FIXTURE_ROOT";; *cat-file*) exit 2;; *) exit 0;; esac`, want: "does not exist"},
		{name: "different resolved commit", body: `case "$*" in *--show-toplevel*) printf '%s\n' "$FIXTURE_ROOT";; *cat-file*) exit 0;; *'rev-parse --verify'*) printf '%040d\n' 1;; *) exit 0;; esac`, want: "does not resolve exactly"},
		{name: "replacement refs", body: `case "$*" in *--show-toplevel*) printf '%s\n' "$FIXTURE_ROOT";; *cat-file*) exit 0;; *'rev-parse --verify'*) printf '%s\n' "$FIXTURE_COMMIT";; *for-each-ref*) printf 'refs/replace/hostile\n';; *) exit 0;; esac`, want: "replacement refs"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := verifySourceRepository(writeExecutableScript(t, test.body), root, commit, environment)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestMaterializeSourceRosterRejectsMalformedGitBatchStreams(t *testing.T) {
	objectID := strings.Repeat("a", 40)
	tests := []struct {
		name    string
		body    string
		prepare func(t *testing.T, root string)
		want    string
	}{
		{name: "empty response", body: `exit 0`, want: "read exact blob header"},
		{name: "wrong object", body: `printf 'wrong blob 1\nx\n'`, want: "unexpected source object"},
		{name: "invalid size", body: `printf '%s blob invalid\n' "$FIXTURE_OBJECT"`, want: "exceeds byte bound"},
		{name: "truncated payload", body: `printf '%s blob 2\nx' "$FIXTURE_OBJECT"`, want: "materialize exact source blob"},
		{name: "existing target", body: `printf '%s blob 1\nx\n' "$FIXTURE_OBJECT"`, prepare: func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "file.go"), []byte("occupied"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "create exact source projection"},
		{name: "failed batch process", body: `printf '%s blob 1\nx\n' "$FIXTURE_OBJECT"; exit 2`, want: "materialize exact source blobs"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if test.prepare != nil {
				test.prepare(t, root)
			}
			roster := sourceRoster{entries: []sourceRosterEntry{{path: "file.go", nativePath: "file.go", mode: "100644", objectID: objectID}}}
			script := writeExecutableScript(t, test.body)
			environment := append(os.Environ(), "FIXTURE_OBJECT="+objectID)
			err := materializeSourceRoster(script, root, environment, &roster)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	root := t.TempDir()
	roster := sourceRoster{entries: []sourceRosterEntry{{path: "file.go", nativePath: "file.go", mode: "100755", objectID: objectID}}}
	script := writeExecutableScript(t, `printf '%s blob 1\nx\n' "$FIXTURE_OBJECT"`)
	if err := materializeSourceRoster(script, root, append(os.Environ(), "FIXTURE_OBJECT="+objectID), &roster); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(root, "file.go"))
	if err != nil || info.Mode().Perm()&0o111 == 0 || roster.entries[0].byteCount != 1 || roster.entries[0].contentSHA256 != sha256String("x") {
		t.Fatalf("materialized entry=%+v mode=%v err=%v", roster.entries[0], info.Mode(), err)
	}
}

func TestModuleGraphAndSelectedInputCommandFailures(t *testing.T) {
	root := t.TempDir()
	environment := os.Environ()
	outputs := []struct {
		name string
		body string
		want string
	}{
		{name: "command", body: `exit 2`, want: "inspect module graph"},
		{name: "malformed", body: `printf '{'`, want: "decode module graph"},
		{name: "empty", body: `exit 0`, want: "module graph is empty"},
		{name: "unnamed", body: `printf '{"Path":""}\n'`, want: "unnamed module"},
	}
	for _, test := range outputs {
		t.Run("modules "+test.name, func(t *testing.T) {
			err := rejectUnpinnedModuleReplacements(writeExecutableScript(t, test.body), root, environment)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	validModule := writeExecutableScript(t, `printf '{"Path":"example.invalid/main","Version":"v1.0.0"}\n'`)
	if err := rejectUnpinnedModuleReplacements(validModule, root, environment); err != nil {
		t.Fatal(err)
	}
	if err := prefetchSelectedModuleGraph(writeExecutableScript(t, `exit 2`), root, environment); err == nil {
		t.Fatal("ignored module prefetch failure")
	}

	selectedCases := []struct {
		name string
		body string
		want string
	}{
		{name: "command", body: `exit 2`, want: "enumerate selected"},
		{name: "malformed", body: `printf '{'`, want: "decode selected"},
		{name: "empty", body: `exit 0`, want: "runner package"},
		{name: "runner without files", body: `printf '{"ImportPath":"` + releaseRunnerImportPath + `","Module":{"Main":true}}\n'`, want: "runner package"},
		{name: "escaping file", body: `printf '{"ImportPath":"` + releaseRunnerImportPath + `","Dir":"/tmp","GoFiles":["outside.go"],"Module":{"Main":true}}\n'`, want: "escapes exact commit projection"},
		{name: "absent roster file", body: `printf '{"ImportPath":"` + releaseRunnerImportPath + `","Dir":"'"$FIXTURE_ROOT"'","GoFiles":["missing.go"],"Module":{"Main":true}}\n'`, want: "absent from exact commit roster"},
	}
	for _, test := range selectedCases {
		t.Run("selected "+test.name, func(t *testing.T) {
			script := writeExecutableScript(t, test.body)
			err := verifySelectedMainModuleInputs(script, root, append(environment, "FIXTURE_ROOT="+root), sourceRoster{byPath: map[string]sourceRosterEntry{}})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
	file := filepath.Join(root, "main.go")
	if err := os.WriteFile(file, []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := writeExecutableScript(t, `printf '{"ImportPath":"`+releaseRunnerImportPath+`","Dir":"'"$FIXTURE_ROOT"'","GoFiles":["main.go"],"Module":{"Main":true}}\n'`)
	roster := sourceRoster{byPath: map[string]sourceRosterEntry{"main.go": {path: "main.go"}}}
	if err := verifySelectedMainModuleInputs(script, root, append(environment, "FIXTURE_ROOT="+root), roster); err != nil {
		t.Fatal(err)
	}
}

func TestCreateProjectionAndWritableTreeFailures(t *testing.T) {
	missingParent := filepath.Join(t.TempDir(), "missing", "projection")
	workspace := releaseWorkspace{projectionRoot: missingParent}
	if _, err := createCommitProjection("/definitely/missing/git", t.TempDir(), strings.Repeat("a", 40), workspace); err == nil {
		t.Fatal("created projection below missing parent")
	}
	root := t.TempDir()
	workspace = releaseWorkspace{projectionRoot: filepath.Join(root, "projection"), onlineEnv: os.Environ()}
	if _, err := createCommitProjection(writeExecutableScript(t, `exit 2`), root, strings.Repeat("a", 40), workspace); err == nil || !strings.Contains(err.Error(), "initialize source projection") {
		t.Fatalf("projection init error = %v", err)
	}
	if err := makeReleaseWorkspaceWritable(filepath.Join(root, "missing")); err == nil {
		t.Fatal("made missing workspace writable")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink("missing-target", link); err != nil {
		t.Fatal(err)
	}
	if err := makeReleaseWorkspaceWritable(root); err != nil {
		t.Fatal(err)
	}
	if _, err := measureRegularTree(filepath.Join(root, "empty")); err == nil {
		t.Fatal("measured absent regular tree")
	}
	if _, err := measureRegularTree(root); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symbolic-link tree error = %v", err)
	}
}

func TestCreateCommitProjectionReportsGitStageFailures(t *testing.T) {
	source := t.TempDir()
	gitExecutable := exactTestExecutable(t, "git")
	runFixtureCommand(t, source, gitExecutable, "init", "--quiet")
	runFixtureCommand(t, source, gitExecutable, "config", "user.email", "coverage@example.invalid")
	runFixtureCommand(t, source, gitExecutable, "config", "user.name", "Coverage Fixture")
	if err := os.WriteFile(filepath.Join(source, "main.go"), []byte("package fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runFixtureCommand(t, source, gitExecutable, "add", "main.go")
	runFixtureCommand(t, source, gitExecutable, "commit", "--quiet", "-m", "fixture")
	commit := strings.TrimSpace(string(runFixtureCommand(t, source, gitExecutable, "rev-parse", "HEAD")))
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "config", body: `if [ "$1" = config ]; then exit 2; fi; exec "$REAL_GIT" "$@"`, want: "configure source projection"},
		{name: "fetch", body: `case " $* " in *" fetch "*) exit 2;; esac; exec "$REAL_GIT" "$@"`, want: "fetch exact source commit"},
		{name: "resolved commit", body: `if [ "$1" = rev-parse ]; then printf '%040d\n' 1; exit 0; fi; exec "$REAL_GIT" "$@"`, want: "fetched source commit differs"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			workspace := releaseWorkspace{root: root, projectionRoot: filepath.Join(root, "projection"), onlineEnv: append(os.Environ(), "REAL_GIT="+gitExecutable)}
			_, err := createCommitProjection(writeExecutableScript(t, test.body), source, commit, workspace)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}
