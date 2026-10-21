package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func validReleaseArguments() []string {
	return []string{
		"--source-root", "/source",
		"--commit", strings.Repeat("a", 40),
		"--go-executable", "/tools/go",
		"--git-executable", "/tools/git",
		"--", "alpha", "two words",
	}
}

func TestRunMapsInvocationAndCeremonyResults(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		execute  func(releaseOptions, io.Writer, io.Writer) error
		wantCode int
		wantText string
	}{
		{name: "invalid invocation", args: nil, execute: func(releaseOptions, io.Writer, io.Writer) error {
			t.Fatal("executor called for invalid invocation")
			return nil
		}, wantCode: 2, wantText: "invalid release invocation"},
		{name: "success", args: validReleaseArguments(), execute: func(options releaseOptions, stdout, _ io.Writer) error {
			if options.sourceRoot != "/source" || len(options.childArgs) != 2 || options.childArgs[1] != "two words" {
				t.Fatalf("parsed options = %#v", options)
			}
			_, _ = stdout.Write([]byte("receipt"))
			return nil
		}, wantCode: 0},
		{name: "child exit", args: validReleaseArguments(), execute: func(releaseOptions, io.Writer, io.Writer) error {
			return childExitError{code: 9}
		}, wantCode: 9},
		{name: "invalid child exit", args: validReleaseArguments(), execute: func(releaseOptions, io.Writer, io.Writer) error {
			return childExitError{code: 0}
		}, wantCode: 1},
		{name: "ceremony failure", args: validReleaseArguments(), execute: func(releaseOptions, io.Writer, io.Writer) error {
			return errors.New("private release path")
		}, wantCode: 1, wantText: "release ceremony failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := runWithExecutor(test.args, &stdout, &stderr, test.execute); code != test.wantCode {
				t.Fatalf("exit = %d, want %d", code, test.wantCode)
			}
			if test.wantText != "" && !strings.Contains(stderr.String(), test.wantText) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.wantText)
			}
			if strings.Contains(stderr.String(), "private release path") {
				t.Fatalf("private error crossed public boundary: %q", stderr.String())
			}
		})
	}
}

func TestParseReleaseOptionsRejectsMalformedLaunchers(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "missing delimiter", args: []string{"--source-root", "/source"}},
		{name: "unknown flag", args: []string{"--unknown", "value", "--"}},
		{name: "positional launcher argument", args: []string{"position", "--"}},
		{name: "missing required flag", args: []string{"--source-root", "/source", "--"}},
		{name: "padded flag", args: []string{"--source-root", " /source", "--commit", strings.Repeat("a", 40), "--go-executable", "/go", "--git-executable", "/git", "--"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if options, err := parseReleaseOptions(test.args); err == nil {
				t.Fatalf("accepted malformed launcher as %#v", options)
			}
		})
	}
}

func TestChildExitErrorPreservesSentinel(t *testing.T) {
	err := childExitError{code: 7}
	if err.Error() != errChildExited.Error() || !errors.Is(err, errChildExited) {
		t.Fatalf("child exit error lost sentinel identity: %v", err)
	}
}

func TestClosedReleaseEnvironmentDropsAmbientInjection(t *testing.T) {
	goPath := exactTestExecutable(t, "go")
	gitPath := exactTestExecutable(t, "git")
	for key, value := range map[string]string{
		"GIT_INDEX_FILE": "hostile-index",
		"GIT_DIR":        "hostile-git-dir",
		"GOENV":          "hostile-goenv",
		"GOWORK":         "hostile-workspace",
		"GOFLAGS":        "-overlay=hostile.json",
		"GOCACHEPROG":    "hostile-cache-helper",
	} {
		t.Setenv(key, value)
	}
	root := t.TempDir()
	environment, err := closedReleaseEnvironment(root, goPath, gitPath, false)
	if err != nil {
		t.Fatal(err)
	}
	values := environmentMap(environment)
	for _, absent := range []string{"GIT_INDEX_FILE", "GIT_DIR", "GOCACHEPROG"} {
		if _, exists := values[absent]; exists {
			t.Fatalf("closed environment inherited %s", absent)
		}
	}
	for key, want := range map[string]string{
		"CGO_ENABLED":        "0",
		"GO_EXTLINK_ENABLED": "0",
		"GOENV":              "off",
		"GOFLAGS":            "-mod=readonly",
		"GOTOOLCHAIN":        "local",
		"GOWORK":             "off",
		"TZ":                 "UTC",
	} {
		if got := values[key]; got != want {
			t.Fatalf("closed %s = %q, want %q", key, got, want)
		}
	}
	for _, private := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "GOTMPDIR", "TEMP", "TMP"} {
		if value := values[private]; value == "" || !pathWithin(value, root) {
			t.Fatalf("closed %s = %q, want private path under %s", private, value, root)
		}
	}
}

func TestRemoveReleaseWorkspaceHandlesReadOnlyModuleCacheTree(t *testing.T) {
	tempRoot, err := physicalTempDirectory()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(tempRoot, "velenza-provider-factory-release-")
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "cache", "modules", "example.invalid", "module@v1.0.0")
	file := filepath.Join(nested, "go.mod")
	writeTestFile(t, file, []byte("module example.invalid/module\n"), 0o444)
	if err := os.Chmod(nested, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(nested, 0o700)
		_ = os.Chmod(file, 0o600)
		_ = os.RemoveAll(root)
	})
	removeReleaseWorkspace(tempRoot, root)
	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read-only release workspace was not removed: %v", err)
	}
}

func TestSourceRosterRootBindsPathModeByteCountAndDigest(t *testing.T) {
	entries := []sourceRosterEntry{{path: "a.go", mode: "100755", byteCount: 7, contentSHA256: strings.Repeat("a", 64)}}
	got, err := sourceRosterRoot(entries)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	for _, value := range []string{entries[0].path, entries[0].mode} {
		_ = binary.Write(hash, binary.BigEndian, uint64(len(value)))
		_, _ = hash.Write([]byte(value))
	}
	_ = binary.Write(hash, binary.BigEndian, uint64(entries[0].byteCount))
	_ = binary.Write(hash, binary.BigEndian, uint64(len(entries[0].contentSHA256)))
	_, _ = hash.Write([]byte(entries[0].contentSHA256))
	want := hex.EncodeToString(hash.Sum(nil))
	if got != want {
		t.Fatalf("source roster root = %s, want %s", got, want)
	}
	changed := append([]sourceRosterEntry(nil), entries...)
	changed[0].byteCount++
	changedRoot, err := sourceRosterRoot(changed)
	if err != nil {
		t.Fatal(err)
	}
	if changedRoot == got {
		t.Fatal("source roster root did not bind byte_count")
	}
}

func TestSourceTreeRejectsNativePathCollisionAndUnsupportedMode(t *testing.T) {
	oid := strings.Repeat("a", 40)
	caseCollision := []byte("100644 blob " + oid + "\tA.go\x00100644 blob " + oid + "\ta.go\x00")
	if _, err := parseSourceTree(caseCollision); err == nil {
		t.Fatal("case-colliding commit paths were accepted")
	}
	symlink := []byte("120000 blob " + oid + "\tlink\x00")
	if _, err := parseSourceTree(symlink); err == nil {
		t.Fatal("symlink commit mode was accepted")
	}
	for _, unsafePath := range []string{"caf\u00e9.go", "CONIN$.txt", "CONOUT$.txt"} {
		raw := []byte("100644 blob " + oid + "\t" + unsafePath + "\x00")
		if _, err := parseSourceTree(raw); err == nil {
			t.Fatalf("non-portable source path %q was accepted", unsafePath)
		}
	}
}

func TestSplitChildReceiptPathTracksBothGoFlagSpellingsAndPreservesOtherArguments(t *testing.T) {
	root := t.TempDir()
	path, found, forwarded, err := splitChildReceiptPath([]string{"--ood", "authority.json", "-out", "receipt.json"}, root)
	if err != nil {
		t.Fatal(err)
	}
	if !found || path != filepath.Join(root, "receipt.json") {
		t.Fatalf("child receipt path = %q, found=%t", path, found)
	}
	if fmt.Sprint(forwarded) != fmt.Sprint([]string{"--ood", "authority.json"}) {
		t.Fatalf("forwarded args = %v", forwarded)
	}
	path, found, forwarded, err = splitChildReceiptPath([]string{"--out=receipt-two.json"}, root)
	if err != nil {
		t.Fatal(err)
	}
	if !found || path != filepath.Join(root, "receipt-two.json") || len(forwarded) != 0 {
		t.Fatalf("equals child receipt path = %q, found=%t", path, found)
	}
	if _, _, _, err := splitChildReceiptPath([]string{"--out=first.json", "-out", "second.json"}, root); err == nil {
		t.Fatal("duplicated child --out was accepted")
	}
	_, found, forwarded, err = splitChildReceiptPath([]string{"--source-package", "sealed-source.json", "--output-root", "candidate-output"}, root)
	if err != nil || found || fmt.Sprint(forwarded) != fmt.Sprint([]string{"--source-package", "sealed-source.json", "--output-root", "candidate-output"}) {
		t.Fatalf("source compiler child args were not forwarded unchanged: found=%t forwarded=%v err=%v", found, forwarded, err)
	}
}

func TestProductionSourceChildSelectionIsExplicitAndComplete(t *testing.T) {
	selection, err := selectProductionSourceChild([]string{
		"--source-package", "sealed-source.json",
		"--source-verification-receipt=source-owner.receipt.json",
		"--expected-provider", "quickbooks_online",
		"--output-root", "candidate-output",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !selection.enabled || selection.expectedProvider != "quickbooks_online" {
		t.Fatalf("production source selection = %+v", selection)
	}

	selection, err = selectProductionSourceChild([]string{"--source-package", "sealed-source.json", "--output-root", "candidate-output"})
	if err != nil || selection.enabled {
		t.Fatalf("candidate source selection = %+v err=%v", selection, err)
	}

	for _, args := range [][]string{
		{"--source-verification-receipt", "source-owner.receipt.json"},
		{"--expected-provider", "quickbooks_online"},
		{"--source-verification-receipt", "first.json", "--source-verification-receipt", "second.json", "--expected-provider", "quickbooks_online"},
		{"--source-verification-receipt", "source-owner.receipt.json", "--expected-provider", "quickbooks_online", "--expected-provider", "xero"},
	} {
		if _, err := selectProductionSourceChild(args); err == nil {
			t.Fatalf("ambiguous production source selection was accepted: %v", args)
		}
	}
}

func TestProductionSourceReleaseRejectsPlainFactoryReceipt(t *testing.T) {
	fixture := newChildReceiptValidationFixture(t)
	raw, err := json.Marshal(fixture.receipt)
	if err != nil {
		t.Fatal(err)
	}
	production := productionSourceChildSelection{enabled: true, expectedProvider: "quickbooks_online"}
	if err := validateReleasedChildReceipt(raw, production, fixture.commit, fixture.rosterRoot, fixture.goTool, fixture.gitTool, fixture.goToolchain, fixture.gitToolchain, fixture.child, fixture.childBuild); err == nil {
		t.Fatal("production source release accepted a plain factory receipt that dropped source verification")
	}
	if err := validateReleasedChildReceipt(raw, productionSourceChildSelection{}, fixture.commit, fixture.rosterRoot, fixture.goTool, fixture.gitTool, fixture.goToolchain, fixture.gitToolchain, fixture.child, fixture.childBuild); err != nil {
		t.Fatalf("non-production release rejected the existing factory receipt: %v", err)
	}
}

func TestValidateProductionSourceChildReceiptClosesNestedRelay(t *testing.T) {
	fixture := newProductionSourceChildValidationFixture(t)
	if err := fixture.validate(t, fixture.receipt); err != nil {
		t.Fatalf("valid production source child relay was rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "test-owned verification",
			mutate: func(receipt map[string]any) {
				verification := receipt["source_receipt"].(map[string]any)["production_source_verification"].(map[string]any)
				verification["test_owned"] = true
				recloseProductionSourceChildRelayForTest(t, receipt)
			},
		},
		{
			name: "unauthenticated verification",
			mutate: func(receipt map[string]any) {
				verification := receipt["source_receipt"].(map[string]any)["production_source_verification"].(map[string]any)
				verification["producer_authenticated"] = false
				recloseProductionSourceChildRelayForTest(t, receipt)
			},
		},
		{
			name: "stale verification",
			mutate: func(receipt map[string]any) {
				verification := receipt["source_receipt"].(map[string]any)["production_source_verification"].(map[string]any)
				verification["current_generation_verified"] = false
				recloseProductionSourceChildRelayForTest(t, receipt)
			},
		},
		{
			name: "incomplete evidence set",
			mutate: func(receipt map[string]any) {
				verification := receipt["source_receipt"].(map[string]any)["production_source_verification"].(map[string]any)
				verification["complete_evidence_identity_set_verified"] = false
				recloseProductionSourceChildRelayForTest(t, receipt)
			},
		},
		{
			name: "mismatched provider",
			mutate: func(receipt map[string]any) {
				verification := receipt["source_receipt"].(map[string]any)["production_source_verification"].(map[string]any)
				verification["provider"] = "xero"
				recloseProductionSourceChildRelayForTest(t, receipt)
			},
		},
		{
			name: "fabricated evidence root",
			mutate: func(receipt map[string]any) {
				verification := receipt["source_receipt"].(map[string]any)["production_source_verification"].(map[string]any)
				verification["provider_evidence_identity_set_root_sha256"] = testDigest("fabricated-evidence-root")
				recloseProductionSourceChildRelayForTest(t, receipt)
			},
		},
		{
			name: "substituted factory binding",
			mutate: func(receipt map[string]any) {
				source := receipt["source_receipt"].(map[string]any)
				source["factory_receipt_sha256"] = testDigest("different-factory-receipt")
				recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
				recloseObjectSelfDigestForTest(t, receipt, "receipt_sha256")
			},
		},
		{
			name: "mutated envelope digest",
			mutate: func(receipt map[string]any) {
				receipt["receipt_sha256"] = testDigest("mutated-envelope")
			},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			receipt := cloneReceiptForTest(t, fixture.receipt)
			testCase.mutate(receipt)
			if err := fixture.validate(t, receipt); err == nil {
				t.Fatal("hostile production source child relay was accepted")
			}
		})
	}
}

func TestValidateChildReceiptRejectsBrokenIdentityClosures(t *testing.T) {
	fixture := newChildReceiptValidationFixture(t)
	if err := fixture.validate(t, fixture.receipt); err != nil {
		t.Fatalf("valid closed receipt was rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*testing.T, map[string]any)
	}{
		{
			name: "wrong final self digest",
			mutate: func(_ *testing.T, receipt map[string]any) {
				receipt["receipt_sha256"] = testDigest("wrong-final-self")
			},
		},
		{
			name: "unknown top-level field",
			mutate: func(_ *testing.T, receipt map[string]any) {
				receipt["unknown"] = true
			},
		},
		{
			name: "wrong portable digest",
			mutate: func(t *testing.T, receipt map[string]any) {
				receipt["portable_receipt_sha256"] = testDigest("wrong-portable")
				recloseValidationAndReceiptForTest(t, receipt)
			},
		},
		{
			name: "wrong validation report digest",
			mutate: func(t *testing.T, receipt map[string]any) {
				identity := receipt["validation_identity"].(map[string]any)
				identity["validation_report_sha256"] = testDigest("wrong-validation-report")
				recloseObjectSelfDigestForTest(t, identity, "validation_identity_sha256")
				recloseObjectSelfDigestForTest(t, receipt, "receipt_sha256")
			},
		},
		{
			name: "wrong module identity",
			mutate: func(t *testing.T, receipt map[string]any) {
				tool := receipt["tool_identity"].(map[string]any)
				tool["module_path"] = "example.invalid/wrong-module"
				recloseObjectSelfDigestForTest(t, tool, "build_identity_sha256")
				execution := receipt["execution_identity"].(map[string]any)
				execution["portable_build_identity_sha256"] = tool["build_identity_sha256"]
				recloseObjectSelfDigestForTest(t, execution, "execution_identity_sha256")
				reclosePortableReceiptForTest(t, receipt)
				recloseValidationAndReceiptForTest(t, receipt)
			},
		},
		{
			name: "wrong independently selected build identity",
			mutate: func(t *testing.T, receipt map[string]any) {
				tool := receipt["tool_identity"].(map[string]any)
				tool["build_identity_sha256"] = testDigest("foreign-build-identity")
				execution := receipt["execution_identity"].(map[string]any)
				execution["portable_build_identity_sha256"] = tool["build_identity_sha256"]
				recloseObjectSelfDigestForTest(t, execution, "execution_identity_sha256")
				reclosePortableReceiptForTest(t, receipt)
				recloseValidationAndReceiptForTest(t, receipt)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := cloneReceiptForTest(t, fixture.receipt)
			test.mutate(t, receipt)
			if err := fixture.validate(t, receipt); err == nil {
				t.Fatal("invalid child receipt was accepted")
			}
		})
	}
}

func TestReleaseJSONDecoderRejectsDuplicateKeysAndExcessiveNesting(t *testing.T) {
	if _, err := decodeReleaseJSONObject([]byte(`{"receipt_kind":"first","receipt_kind":"second"}`)); err == nil {
		t.Fatal("duplicate JSON object key was accepted")
	}
	nested := strings.Repeat(`{"value":`, maximumReleaseJSONDepth+2) + `true` + strings.Repeat(`}`, maximumReleaseJSONDepth+2)
	if _, err := decodeReleaseJSONObject([]byte(nested)); err == nil {
		t.Fatal("excessively nested child receipt was accepted")
	}
}

func TestCommitProjectionExcludesIgnoredWorkingTreeGoAndEmbedInputs(t *testing.T) {
	fixture := newReleaseFixture(t, false)
	writeTestFile(t, filepath.Join(fixture.root, "cmd", "provider-documentation-factory-run", "ignored-secret.go"), []byte("package main\nfunc init(){ panic(\"working tree injection\") }\n"), 0o644)
	writeTestFile(t, filepath.Join(fixture.root, "cmd", "provider-documentation-factory-run", "ignored-secret.txt"), []byte("working-tree-secret"), 0o644)

	workspace, err := newReleaseWorkspace(fixture.goPath, fixture.gitPath)
	if err != nil {
		t.Fatal(err)
	}
	defer removeReleaseWorkspace(workspace.tempRoot, workspace.root)
	roster, err := createCommitProjection(fixture.gitPath, fixture.root, fixture.commit, workspace)
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{
		"cmd/provider-documentation-factory-run/ignored-secret.go",
		"cmd/provider-documentation-factory-run/ignored-secret.txt",
	} {
		if _, exists := roster.byPath[relative]; exists {
			t.Fatalf("ignored working-tree injection %q entered the commit roster", relative)
		}
		if _, err := os.Lstat(filepath.Join(workspace.projectionRoot, filepath.FromSlash(relative))); !os.IsNotExist(err) {
			t.Fatalf("ignored working-tree injection %q entered the projection", relative)
		}
	}
	if err := verifySelectedMainModuleInputs(fixture.goPath, workspace.projectionRoot, workspace.offlineEnv, roster); err != nil {
		t.Fatalf("selected committed inputs failed: %v", err)
	}
}

func TestCommitProjectionPreservesRawBytesAndExecutableIndexMode(t *testing.T) {
	fixture := newReleaseFixture(t, false)
	relative := "tools/raw-release-probe.sh"
	want := []byte("#!/bin/sh\r\nprintf 'raw-bytes\\r\\n'\r\n")
	writeTestFile(t, filepath.Join(fixture.root, filepath.FromSlash(relative)), want, 0o755)
	runFixtureCommand(t, fixture.root, fixture.gitPath, "add", "--", relative)
	runFixtureCommand(t, fixture.root, fixture.gitPath, "update-index", "--chmod=+x", "--", relative)
	runFixtureCommand(t, fixture.root, fixture.gitPath, "commit", "--quiet", "-m", "add raw executable probe")
	fixture.commit = strings.TrimSpace(string(runFixtureCommand(t, fixture.root, fixture.gitPath, "rev-parse", "HEAD")))
	workspace, err := newReleaseWorkspace(fixture.goPath, fixture.gitPath)
	if err != nil {
		t.Fatal(err)
	}
	defer removeReleaseWorkspace(workspace.tempRoot, workspace.root)
	roster, err := createCommitProjection(fixture.gitPath, fixture.root, fixture.commit, workspace)
	if err != nil {
		t.Fatal(err)
	}
	entry, exists := roster.byPath[relative]
	if !exists || entry.mode != "100755" || entry.byteCount != int64(len(want)) || entry.contentSHA256 != sha256HexForTest(want) {
		t.Fatalf("raw executable roster entry = %+v, exists=%t", entry, exists)
	}
	got, err := os.ReadFile(filepath.Join(workspace.projectionRoot, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("projected bytes = %q, want exact committed bytes %q", got, want)
	}
}

func TestUnpinnedLocalReplacementIsRejectedBeforeBuild(t *testing.T) {
	fixture := newReleaseFixture(t, true)
	workspace, err := newReleaseWorkspace(fixture.goPath, fixture.gitPath)
	if err != nil {
		t.Fatal(err)
	}
	defer removeReleaseWorkspace(workspace.tempRoot, workspace.root)
	_, err = createCommitProjection(fixture.gitPath, fixture.root, fixture.commit, workspace)
	if err != nil {
		t.Fatal(err)
	}
	if err := rejectUnpinnedModuleReplacements(fixture.goPath, workspace.projectionRoot, workspace.onlineEnv); err == nil || !strings.Contains(err.Error(), "unpinned local replacement") {
		t.Fatalf("local replacement result = %v, want explicit rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(workspace.root, "output")); !os.IsNotExist(err) {
		t.Fatal("child output directory exists after pre-build replacement rejection")
	}
}

func TestProjectionMutationIsRejected(t *testing.T) {
	fixture := newReleaseFixture(t, false)
	workspace, err := newReleaseWorkspace(fixture.goPath, fixture.gitPath)
	if err != nil {
		t.Fatal(err)
	}
	defer removeReleaseWorkspace(workspace.tempRoot, workspace.root)
	roster, err := createCommitProjection(fixture.gitPath, fixture.root, fixture.commit, workspace)
	if err != nil {
		t.Fatal(err)
	}
	mainPath := filepath.Join(workspace.projectionRoot, "cmd", "provider-documentation-factory-run", "main.go")
	raw, err := os.ReadFile(mainPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	if err := os.WriteFile(mainPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyCommitProjection(fixture.gitPath, fixture.commit, workspace.projectionRoot, workspace.onlineEnv, roster); err == nil {
		t.Fatal("mutated exact-commit projection was accepted")
	}
}

func TestReleaseIgnoresAmbientGitAndGoStateAndValidatesChildReceipt(t *testing.T) {
	fixture := newReleaseFixture(t, false)
	hostileRoot := t.TempDir()
	writeTestFile(t, filepath.Join(hostileRoot, "go.env"), []byte("GOFLAGS=-overlay=missing-overlay.json\n"), 0o600)
	writeTestFile(t, filepath.Join(hostileRoot, "go.work"), []byte("go 1.27.0\nuse ./missing\n"), 0o600)
	for key, value := range map[string]string{
		"GIT_INDEX_FILE": filepath.Join(hostileRoot, "index"),
		"GOENV":          filepath.Join(hostileRoot, "go.env"),
		"GOWORK":         filepath.Join(hostileRoot, "go.work"),
		"GOFLAGS":        "-overlay=" + filepath.Join(hostileRoot, "overlay.json"),
		"GOCACHEPROG":    filepath.Join(hostileRoot, "cache-helper"),
	} {
		t.Setenv(key, value)
	}
	var stdout, stderr bytes.Buffer
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		bootstrap := filepath.Join(repositoryRoot, "scripts", "provider-documentation-factory-release.ps1")
		command = exec.Command(exactTestExecutable(t, "pwsh"), "-NoProfile", "-File", bootstrap, fixture.root, fixture.commit, fixture.goPath, fixture.gitPath, "--", "alpha", "two words")
	} else {
		bootstrap := filepath.Join(repositoryRoot, "scripts", "provider-documentation-factory-release.sh")
		command = exec.Command("sh", bootstrap, fixture.root, fixture.commit, fixture.goPath, fixture.gitPath, "--", "alpha", "two words")
	}
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		var directStdout, directStderr bytes.Buffer
		directErr := executeRelease(releaseOptions{
			sourceRoot: fixture.root, commit: fixture.commit, goExecutable: fixture.goPath,
			gitExecutable: fixture.gitPath, childArgs: []string{"alpha", "two words"},
		}, &directStdout, &directStderr)
		t.Fatalf("exact release bootstrap failed: %v\nstderr=%s\nstdout=%s\ndirect=%v\ndirect stderr=%s\ndirect stdout=%s", err, stderr.String(), stdout.String(), directErr, directStderr.String(), directStdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("successful child emitted stderr: %q", stderr.String())
	}
	result, err := decodeReleaseJSONObject(stdout.Bytes())
	if err != nil {
		t.Fatalf("decode validated child receipt: %v\n%s", err, stdout.Bytes())
	}
	if result["receipt_kind"] != releaseReceiptKind || result["receipt_version"] != releaseReceiptVersion || result["result"] != releaseReceiptResult || result["scope"] != releaseReceiptScope || result["body_free"] != true {
		t.Fatalf("validated child receipt has the wrong release identity: %v", result)
	}
	for _, forbidden := range []string{"args", "embedded"} {
		if _, exists := result[forbidden]; exists {
			t.Fatalf("validated child receipt retained synthetic top-level field %q", forbidden)
		}
	}

	var directStdout, directStderr bytes.Buffer
	directArgs := []string{
		"--source-root", fixture.root,
		"--commit", fixture.commit,
		"--go-executable", fixture.goPath,
		"--git-executable", fixture.gitPath,
		"--", "alpha", "two words",
	}
	if code := run(directArgs, &directStdout, &directStderr); code != 0 {
		t.Fatalf("direct release exit = %d stderr=%s stdout=%s", code, directStderr.String(), directStdout.String())
	}
	directResult, err := decodeReleaseJSONObject(directStdout.Bytes())
	if err != nil {
		t.Fatalf("decode direct validated child receipt: %v\n%s", err, directStdout.Bytes())
	}
	if directResult["receipt_sha256"] != result["receipt_sha256"] || directResult["receipt_kind"] != releaseReceiptKind {
		t.Fatalf("direct release disagrees with bootstrap: direct=%v bootstrap=%v", directResult["receipt_sha256"], result["receipt_sha256"])
	}
}

func TestBootstrapsRunOnlyTheExactCommittedLauncherSource(t *testing.T) {
	repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []struct {
		relative string
		platform []string
	}{
		{relative: "scripts/provider-documentation-factory-release.ps1", platform: []string{"child_process_windows.go", "receipt_publish_windows.go"}},
		{relative: "scripts/provider-documentation-factory-release.sh", platform: []string{"child_process_nonwindows.go", "receipt_publish_nonwindows.go"}},
	} {
		raw, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(script.relative)))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		requiredFragments := []string{
			"cmd/provider-documentation-factory-release/main.go",
			"GOENV",
			"GOWORK",
			"GOTOOLCHAIN",
			"GO_EXTLINK_ENABLED",
			"GIT_CONFIG_NOSYSTEM",
			"refs/replace",
		}
		requiredFragments = append(requiredFragments, script.platform...)
		for _, required := range requiredFragments {
			if !strings.Contains(text, required) {
				t.Fatalf("%s omits %q", script.relative, required)
			}
		}
		if strings.Contains(text, "go run ./cmd/provider-documentation-factory-release") {
			t.Fatalf("%s runs ambient package source", script.relative)
		}
	}
}

type releaseFixture struct {
	root    string
	commit  string
	goPath  string
	gitPath string
}

type childReceiptValidationFixture struct {
	commit       string
	rosterRoot   string
	goTool       measuredExecutable
	gitTool      measuredExecutable
	goToolchain  measuredTree
	gitToolchain measuredTree
	child        measuredExecutable
	childBuild   childBuildExpectation
	receipt      map[string]any
}

type productionSourceChildValidationFixture struct {
	childReceiptValidationFixture
	expectedProvider string
	receipt          map[string]any
}

func newProductionSourceChildValidationFixture(t *testing.T) productionSourceChildValidationFixture {
	t.Helper()
	child := newChildReceiptValidationFixture(t)
	factory := cloneReceiptForTest(t, child.receipt)
	expectedProvider := "quickbooks_online"
	factory["preflight_receipt"].(map[string]any)["provider"] = expectedProvider
	reclosePortableReceiptForTest(t, factory)
	recloseValidationAndReceiptForTest(t, factory)

	evidenceIdentity := map[string]any{
		"manifest_role": "evidence_manifest", "manifest_id": "quickbooks_manifest", "manifest_version": "1",
		"manifest_raw_sha256": testDigest("manifest"), "manifest_byte_count": int64(101), "component_ordinal": uint64(0),
		"source_content_sha256": testDigest("source-content"), "source_content_byte_count": int64(202),
		"carrier_role": "evidence_carrier", "carrier_id": "quickbooks_carrier", "carrier_version": "1",
		"carrier_raw_sha256": testDigest("carrier"), "carrier_byte_count": int64(303),
	}
	identityRaw, err := canonicalReleaseJSON(evidenceIdentity)
	if err != nil {
		t.Fatal(err)
	}
	evidenceRoot := sha256String(releaseLengthPrefixedIdentityKey(string(identityRaw)))
	sourcePackageSHA256 := testDigest("source-package")
	verification := map[string]any{
		"verification_kind": productionSourceVerificationKind, "verification_version": productionSourceVerificationVersion,
		"result": productionSourceVerificationResult, "provider": expectedProvider, "observed_at": "2026-08-28T22:00:00Z",
		"source_package_sha256": sourcePackageSHA256, "source_package_byte_count": int64(404),
		"provider_evidence_identities": []any{evidenceIdentity}, "provider_evidence_identity_set_root_sha256": evidenceRoot,
		"source_owner_verification_receipt_sha256":     testDigest("source-owner-receipt"),
		"source_owner_verification_receipt_byte_count": int64(505), "producer_authenticated": true,
		"current_generation_verified": true, "complete_evidence_identity_set_verified": true, "test_owned": false,
		"binding_sha256": "",
	}
	recloseObjectSelfDigestForTest(t, verification, "binding_sha256")
	factoryRaw, err := canonicalReleaseJSON(factory)
	if err != nil {
		t.Fatal(err)
	}
	factoryFileRaw := append(append([]byte(nil), factoryRaw...), '\n')
	factoryFileSum := sha256.Sum256(factoryFileRaw)
	source := map[string]any{
		"receipt_kind": sourceCompileReceiptKind, "receipt_version": sourceCompileReceiptVersion,
		"result": sourceCompileReceiptResult, "scope": sourceCompileReceiptScope,
		"compiler_contract_sha256": testDigest("source-compiler-contract"), "source_package_sha256": sourcePackageSHA256,
		"source_input_admission_proof": map[string]any{"proof_sha256": testDigest("source-input-proof")},
		"source_input_resources":       []any{}, "generated_outputs": []any{}, "generated_output_set_root_sha256": testDigest("generated-output-root"),
		"bundle_files": []any{}, "bundle_file_set_root_sha256": testDigest("bundle-root"),
		"receipt_path": "source-compile-receipt.json", "receipt_excluded_from_bundle_file_set": true,
		"factory_portable_receipt_sha256": factory["portable_receipt_sha256"], "factory_receipt_sha256": factory["receipt_sha256"],
		"factory_receipt_file_sha256": hex.EncodeToString(factoryFileSum[:]), "completion": cloneJSONObject(factory["completion"].(map[string]any)),
		"body_free": true, "authority_selected": false, "admission_authorized": false, "factory_complete": false,
		"production_source_verification": verification, "receipt_sha256": "",
	}
	recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
	receipt := map[string]any{
		"receipt_kind": productionSourceRunReceiptKind, "receipt_version": productionSourceRunReceiptVersion,
		"result": productionSourceRunReceiptResult, "scope": productionSourceRunReceiptScope,
		"source_receipt": source, "factory_receipt": factory, "body_free": true,
		"authority_selected": false, "admission_authorized": false, "factory_complete": false, "receipt_sha256": "",
	}
	recloseObjectSelfDigestForTest(t, receipt, "receipt_sha256")
	return productionSourceChildValidationFixture{childReceiptValidationFixture: child, expectedProvider: expectedProvider, receipt: receipt}
}

func (fixture productionSourceChildValidationFixture) validate(t *testing.T, receipt map[string]any) error {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return validateProductionSourceChildReceipt(raw, fixture.expectedProvider, fixture.commit, fixture.rosterRoot, fixture.goTool, fixture.gitTool, fixture.goToolchain, fixture.gitToolchain, fixture.child, fixture.childBuild)
}

func recloseProductionSourceChildRelayForTest(t *testing.T, receipt map[string]any) {
	t.Helper()
	source := receipt["source_receipt"].(map[string]any)
	verification := source["production_source_verification"].(map[string]any)
	recloseObjectSelfDigestForTest(t, verification, "binding_sha256")
	recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
	recloseObjectSelfDigestForTest(t, receipt, "receipt_sha256")
}

func newChildReceiptValidationFixture(t *testing.T) childReceiptValidationFixture {
	t.Helper()
	fixture := childReceiptValidationFixture{
		commit:     strings.Repeat("a", 40),
		rosterRoot: testDigest("source-roster"),
		goTool:     measuredExecutable{digest: testDigest("go-executable")},
		gitTool:    measuredExecutable{digest: testDigest("git-executable")},
		goToolchain: measuredTree{
			digest: testDigest("go-toolchain"), files: 17, bytes: 1700,
		},
		gitToolchain: measuredTree{
			digest: testDigest("git-toolchain"), files: 11, bytes: 1100,
		},
		child: measuredExecutable{digest: testDigest("child-executable"), size: 4096},
	}
	buildSettings := []any{
		map[string]any{"key": "-buildmode", "value": "exe"},
		map[string]any{"key": "GOARCH", "value": runtime.GOARCH},
		map[string]any{"key": "GOOS", "value": runtime.GOOS},
	}
	buildSettingsSHA256, err := canonicalReleaseDigest(buildSettings)
	if err != nil {
		t.Fatal(err)
	}
	fixture.childBuild = childBuildExpectation{
		moduleGraphSHA256:   testDigest("module-graph"),
		buildRecipeSHA256:   testDigest("build-recipe"),
		buildSettingsSHA256: buildSettingsSHA256,
	}
	toolIdentity := map[string]any{
		"command_path": releaseRunnerImportPath, "module_path": releaseModulePath, "module_version": "(devel)",
		"go_version": releaseGoVersion, "vcs": "git", "vcs_revision": fixture.commit,
		"vcs_time": "2026-08-26T00:00:00Z", "vcs_modified": false, "build_tags": releaseBuildTag,
		"module_graph_sha256": fixture.childBuild.moduleGraphSHA256, "build_recipe_sha256": fixture.childBuild.buildRecipeSHA256,
		"source_roster_sha256": fixture.rosterRoot, "runner_contract_sha256": sha256String(releaseRunnerContract),
		"build_identity_sha256": "", "reproducible_source_tree": true,
	}
	recloseObjectSelfDigestForTest(t, toolIdentity, "build_identity_sha256")
	fixture.childBuild.toolIdentitySHA256 = toolIdentity["build_identity_sha256"].(string)
	executionIdentity := map[string]any{
		"portable_build_identity_sha256": fixture.childBuild.toolIdentitySHA256,
		"build_metadata_source":          releaseBuildMetadataSource, "executable_measurement_scope": releaseExecutableScope,
		"target_os": runtime.GOOS, "target_arch": runtime.GOARCH, "build_settings": buildSettings,
		"build_settings_sha256": buildSettingsSHA256, "executable_sha256": fixture.child.digest,
		"executable_byte_count": fixture.child.size, "go_executable_sha256": fixture.goTool.digest,
		"git_executable_sha256": fixture.gitTool.digest, "go_toolchain_sha256": fixture.goToolchain.digest,
		"git_toolchain_sha256":    fixture.gitToolchain.digest,
		"go_toolchain_file_count": int64(fixture.goToolchain.files), "go_toolchain_byte_count": fixture.goToolchain.bytes,
		"git_toolchain_file_count": int64(fixture.gitToolchain.files), "git_toolchain_byte_count": fixture.gitToolchain.bytes,
		"execution_identity_sha256": "",
	}
	recloseObjectSelfDigestForTest(t, executionIdentity, "execution_identity_sha256")
	fixture.childBuild.executionIdentitySHA256 = executionIdentity["execution_identity_sha256"].(string)
	stageKinds := []string{"evidence_intake", "semantic_extraction", "graph_compile", "full_factory"}
	stages := make([]any, len(stageKinds))
	for index, kind := range stageKinds {
		stages[index] = map[string]any{
			"stage_kind":                     kind,
			"receipt_sha256":                 testDigest(fmt.Sprintf("stage-receipt-%d", index)),
			"output_root_sha256":             testDigest(fmt.Sprintf("stage-output-%d", index)),
			"input_resource_set_root_sha256": testDigest(fmt.Sprintf("stage-input-%d", index)),
		}
	}
	fixture.receipt = map[string]any{
		"receipt_kind": releaseReceiptKind, "receipt_version": releaseReceiptVersion,
		"result": releaseReceiptResult, "scope": releaseReceiptScope,
		"tool_identity": toolIdentity, "execution_identity": executionIdentity,
		"validation_identity":   map[string]any{},
		"input_admission_proof": map[string]any{"proof_sha256": testDigest("input-admission-proof")},
		"input_resources":       []any{}, "stages": stages,
		"preflight_receipt": map[string]any{"receipt_sha256": testDigest("preflight")},
		"completion": map[string]any{
			"compiled": true, "verified": true, "derivation_executed": true,
			"graph_admittable": false, "admitted": false, "circuit_admittable": false,
			"circuit_admitted": false, "configured": false, "credential_provisioned": false,
			"deployed": false, "live_tested": false, "two_tenant_proven": false,
			"source_substitution_proven": false, "authority_selected": false,
			"admission_authorized": false, "factory_complete": false,
		},
		"body_free": true, "portable_receipt_sha256": "", "receipt_sha256": "",
	}
	reclosePortableReceiptForTest(t, fixture.receipt)
	recloseValidationAndReceiptForTest(t, fixture.receipt)
	return fixture
}

func (fixture childReceiptValidationFixture) validate(t *testing.T, receipt map[string]any) error {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return validateChildReceipt(raw, fixture.commit, fixture.rosterRoot, fixture.goTool, fixture.gitTool, fixture.goToolchain, fixture.gitToolchain, fixture.child, fixture.childBuild)
}

func reclosePortableReceiptForTest(t *testing.T, receipt map[string]any) {
	t.Helper()
	portable := cloneJSONObject(receipt)
	portable["execution_identity"] = map[string]any{
		"portable_build_identity_sha256": "", "build_metadata_source": "", "executable_measurement_scope": "",
		"target_os": "", "target_arch": "", "build_settings": nil, "build_settings_sha256": "",
		"executable_sha256": "", "executable_byte_count": int64(0), "go_executable_sha256": "",
		"git_executable_sha256": "", "go_toolchain_sha256": "", "git_toolchain_sha256": "",
		"go_toolchain_file_count": int64(0), "go_toolchain_byte_count": int64(0),
		"git_toolchain_file_count": int64(0), "git_toolchain_byte_count": int64(0),
		"execution_identity_sha256": "",
	}
	portable["validation_identity"] = map[string]any{
		"profile_id": "", "profile_version": "", "result": "", "validation_contract_sha256": "",
		"portable_receipt_sha256": "", "tool_build_identity_sha256": "", "execution_identity_sha256": "",
		"validation_report_sha256": "", "validation_identity_sha256": "",
	}
	portable["portable_receipt_sha256"] = ""
	portable["receipt_sha256"] = ""
	digest, err := canonicalReleaseDigest(portable)
	if err != nil {
		t.Fatal(err)
	}
	receipt["portable_receipt_sha256"] = digest
}

func recloseValidationAndReceiptForTest(t *testing.T, receipt map[string]any) {
	t.Helper()
	tool := receipt["tool_identity"].(map[string]any)
	execution := receipt["execution_identity"].(map[string]any)
	proof := receipt["input_admission_proof"].(map[string]any)
	stages := receipt["stages"].([]any)
	stageDigests := make([]string, len(stages))
	for index, value := range stages {
		stageDigests[index] = value.(map[string]any)["receipt_sha256"].(string)
	}
	preflight := receipt["preflight_receipt"].(map[string]any)
	report := map[string]any{
		"result": releaseValidationResult, "portable_receipt_sha256": receipt["portable_receipt_sha256"],
		"tool_build_identity_sha256":   tool["build_identity_sha256"],
		"execution_identity_sha256":    execution["execution_identity_sha256"],
		"input_admission_proof_sha256": proof["proof_sha256"], "stage_receipt_sha256": stageDigests,
		"preflight_receipt_sha256": preflight["receipt_sha256"], "completion_classification": receipt["completion"],
	}
	reportSHA256, err := canonicalReleaseDigest(report)
	if err != nil {
		t.Fatal(err)
	}
	identity := map[string]any{
		"profile_id": releaseValidationProfileID, "profile_version": releaseValidationVersion,
		"result": releaseValidationResult, "validation_contract_sha256": sha256String(releaseValidationContract),
		"portable_receipt_sha256":    receipt["portable_receipt_sha256"],
		"tool_build_identity_sha256": tool["build_identity_sha256"],
		"execution_identity_sha256":  execution["execution_identity_sha256"],
		"validation_report_sha256":   reportSHA256, "validation_identity_sha256": "",
	}
	recloseObjectSelfDigestForTest(t, identity, "validation_identity_sha256")
	receipt["validation_identity"] = identity
	recloseObjectSelfDigestForTest(t, receipt, "receipt_sha256")
}

func recloseObjectSelfDigestForTest(t *testing.T, object map[string]any, field string) {
	t.Helper()
	object[field] = ""
	digest, err := canonicalReleaseDigest(object)
	if err != nil {
		t.Fatal(err)
	}
	object[field] = digest
}

func cloneReceiptForTest(t *testing.T, receipt map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var clone map[string]any
	if err := decoder.Decode(&clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func testDigest(label string) string {
	digest := sha256.Sum256([]byte(label))
	return hex.EncodeToString(digest[:])
}

func newReleaseFixture(t *testing.T, localReplace bool) releaseFixture {
	t.Helper()
	fixture := releaseFixture{root: t.TempDir(), goPath: exactTestExecutable(t, "go"), gitPath: exactTestExecutable(t, "git")}
	goMod := "module " + releaseModulePath + "\n\ngo 1.27.0\n"
	if localReplace {
		goMod += "\nrequire example.invalid/local v0.0.0\nreplace example.invalid/local => ./localdep\n"
		writeTestFile(t, filepath.Join(fixture.root, "localdep", "go.mod"), []byte("module example.invalid/local\n\ngo 1.27.0\n"), 0o644)
		writeTestFile(t, filepath.Join(fixture.root, "localdep", "local.go"), []byte("package local\nconst Value = \"local\"\n"), 0o644)
	}
	writeTestFile(t, filepath.Join(fixture.root, "go.mod"), []byte(goMod), 0o644)
	writeTestFile(t, filepath.Join(fixture.root, ".gitignore"), []byte("ignored-secret.go\nignored-secret.txt\n"), 0o644)
	launcherRaw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(fixture.root, "cmd", "provider-documentation-factory-release", "main.go"), launcherRaw, 0o644)
	for _, name := range []string{
		"child_process_nonwindows.go", "child_process_windows.go",
		"receipt_publish_nonwindows.go", "receipt_publish_windows.go",
	} {
		platformRaw, readErr := os.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		writeTestFile(t, filepath.Join(fixture.root, "cmd", "provider-documentation-factory-release", name), platformRaw, 0o644)
	}
	writeTestFile(t, filepath.Join(fixture.root, "internal", "providerplan", "pins.go"), []byte(fixturePinsSource), 0o644)
	mainSource := fixtureRunnerSource
	if localReplace {
		mainSource = strings.Replace(mainSource, "import (", "import (\n\t_ \"example.invalid/local\"", 1)
	}
	writeTestFile(t, filepath.Join(fixture.root, "cmd", "provider-documentation-factory-run", "main.go"), []byte(mainSource), 0o644)
	writeTestFile(t, filepath.Join(fixture.root, "cmd", "provider-documentation-factory-run", "ignored-base.txt"), []byte("committed-embed"), 0o644)
	runFixtureCommand(t, fixture.root, fixture.gitPath, "init", "--quiet", "--object-format=sha1")
	runFixtureCommand(t, fixture.root, fixture.gitPath, "config", "user.name", "Factory Release Test")
	runFixtureCommand(t, fixture.root, fixture.gitPath, "config", "user.email", "factory-release@example.invalid")
	runFixtureCommand(t, fixture.root, fixture.gitPath, "config", "core.autocrlf", "false")
	runFixtureCommand(t, fixture.root, fixture.gitPath, "add", "--all")
	runFixtureCommand(t, fixture.root, fixture.gitPath, "commit", "--quiet", "-m", "exact release fixture")
	fixture.commit = strings.TrimSpace(string(runFixtureCommand(t, fixture.root, fixture.gitPath, "rev-parse", "HEAD")))
	return fixture
}

const fixturePinsSource = `package providerplan

var (
	factoryReleaseSourceRosterSHA256  string
	factoryReleaseGoExecutableSHA256  string
	factoryReleaseGitExecutableSHA256 string
	factoryReleaseGoToolchainSHA256   string
	factoryReleaseGitToolchainSHA256  string
	factoryReleaseGoToolchainFiles    string
	factoryReleaseGoToolchainBytes    string
	factoryReleaseGitToolchainFiles   string
	factoryReleaseGitToolchainBytes   string
)

type ReleasePins struct {
	SourceRoster, GoExecutable, GitExecutable, GoToolchain, GitToolchain string
	GoToolchainFiles, GoToolchainBytes, GitToolchainFiles, GitToolchainBytes string
}

func Pins() ReleasePins {
	return ReleasePins{
		SourceRoster: factoryReleaseSourceRosterSHA256,
		GoExecutable: factoryReleaseGoExecutableSHA256,
		GitExecutable: factoryReleaseGitExecutableSHA256,
		GoToolchain: factoryReleaseGoToolchainSHA256,
		GitToolchain: factoryReleaseGitToolchainSHA256,
		GoToolchainFiles: factoryReleaseGoToolchainFiles,
		GoToolchainBytes: factoryReleaseGoToolchainBytes,
		GitToolchainFiles: factoryReleaseGitToolchainFiles,
		GitToolchainBytes: factoryReleaseGitToolchainBytes,
	}
}
`

const fixtureRunnerSource = `package main

import (
	_ "embed"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"

	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

//go:embed ignored-*.txt
var embedded string

const (
	receiptKind = "provider_documentation_factory_offline_run_receipt"
	receiptVersion = "2"
	receiptResult = "compiled_and_verified_candidate_only"
	receiptScope = "offline_exact_input_four_stage_compilation_and_provider_plan_verification"
	validationProfileID = "provider_documentation_factory_runtime_validation"
	validationVersion = "3"
	validationResult = "candidate_runtime_validation_pass"
	validationContract = "result=candidate_runtime_validation_pass;portable_receipt_recomputed;tool_identity_validated;exact_execution_profile_validated;honest_measurement_scope_validated;executable_digest_bound;input_admission_recomputed;four_stage_receipts_validated;preflight_receipt_validated;completion_classification_fail_closed"
	runnerContract = "exactly_four_ordered_stage_manifests;runner_owned_predecessor_and_evidence_reuse;one_union_input_roster;intake_authority_and_evidence_cross_binding;verifier_admitted_complete_dependency_closure;no_network_graph_admission_tenant_credential_deployment_or_live_acceptance_claim"
	modulePath = "github.com/velenzaboc/velenza-canon"
	commandPath = modulePath + "/cmd/provider-documentation-factory-run"
)

func main() {
	build, ok := debug.ReadBuildInfo()
	if !ok || build == nil || build.Path != commandPath || build.Main.Path != modulePath { os.Exit(1) }
	settings := map[string]string{}
	for _, setting := range build.Settings { settings[setting.Key] = setting.Value }
	mainModule := buildModule(build.Main)
	dependencies := make([]any, len(build.Deps))
	for index, dependency := range build.Deps {
		if dependency == nil { os.Exit(1) }
		dependencies[index] = buildModule(*dependency)
	}
	sort.Slice(dependencies, func(i, j int) bool {
		left := dependencies[i].(map[string]any)
		right := dependencies[j].(map[string]any)
		for _, key := range []string{"path", "version", "sum", "replace_path", "replace_version", "replace_sum"} {
			leftValue, _ := left[key].(string)
			rightValue, _ := right[key].(string)
			if leftValue != rightValue { return leftValue < rightValue }
		}
		return false
	})
	portableSettings := make([]any, 0, len(build.Settings))
	executionSettings := make([]any, 0, len(build.Settings))
	for _, setting := range build.Settings {
		entry := map[string]any{"key": setting.Key, "value": setting.Value}
		if !targetSetting(setting.Key) { portableSettings = append(portableSettings, entry) }
		executionSettings = append(executionSettings, entry)
	}
	lessSetting := func(values []any, i, j int) bool {
		left := values[i].(map[string]any)
		right := values[j].(map[string]any)
		if left["key"] != right["key"] { return left["key"].(string) < right["key"].(string) }
		return left["value"].(string) < right["value"].(string)
	}
	sort.Slice(portableSettings, func(i, j int) bool { return lessSetting(portableSettings, i, j) })
	sort.Slice(executionSettings, func(i, j int) bool { return lessSetting(executionSettings, i, j) })
	moduleGraphSHA256 := digest(map[string]any{"main": mainModule, "dependencies": dependencies})
	buildRecipeSHA256 := digest(map[string]any{
		"go_version": build.GoVersion, "main": mainModule, "dependencies": dependencies,
		"portable_settings": portableSettings,
	})
	pins := providerplan.Pins()
	toolIdentity := map[string]any{
		"command_path": build.Path, "module_path": build.Main.Path, "module_version": build.Main.Version,
		"go_version": build.GoVersion, "vcs": settings["vcs"], "vcs_revision": settings["vcs.revision"],
		"vcs_time": settings["vcs.time"], "vcs_modified": settings["vcs.modified"] == "true",
		"build_tags": settings["-tags"], "module_graph_sha256": moduleGraphSHA256,
		"build_recipe_sha256": buildRecipeSHA256, "source_roster_sha256": pins.SourceRoster,
		"runner_contract_sha256": shaString(runnerContract), "build_identity_sha256": "",
		"reproducible_source_tree": true,
	}
	closeSelf(toolIdentity, "build_identity_sha256")
	path, err := os.Executable()
	if err != nil { os.Exit(1) }
	raw, err := os.ReadFile(path)
	if err != nil { os.Exit(1) }
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() != int64(len(raw)) { os.Exit(1) }
	goFiles := positiveCount(pins.GoToolchainFiles)
	goBytes := positiveCount(pins.GoToolchainBytes)
	gitFiles := positiveCount(pins.GitToolchainFiles)
	gitBytes := positiveCount(pins.GitToolchainBytes)
	buildSettingsSHA256 := digest(executionSettings)
	executionIdentity := map[string]any{
		"portable_build_identity_sha256": toolIdentity["build_identity_sha256"],
		"build_metadata_source": "go_runtime_debug_build_info",
		"executable_measurement_scope": "launch_path_open_regular_file",
		"target_os": runtime.GOOS, "target_arch": runtime.GOARCH,
		"build_settings": executionSettings, "build_settings_sha256": buildSettingsSHA256,
		"executable_sha256": hexDigest(raw), "executable_byte_count": info.Size(),
		"go_executable_sha256": pins.GoExecutable, "git_executable_sha256": pins.GitExecutable,
		"go_toolchain_sha256": pins.GoToolchain, "git_toolchain_sha256": pins.GitToolchain,
		"go_toolchain_file_count": goFiles, "go_toolchain_byte_count": goBytes,
		"git_toolchain_file_count": gitFiles, "git_toolchain_byte_count": gitBytes,
		"execution_identity_sha256": "",
	}
	closeSelf(executionIdentity, "execution_identity_sha256")
	proof := map[string]any{"proof_sha256": shaString("fixture-input-admission-proof")}
	stageKinds := []string{"evidence_intake", "semantic_extraction", "graph_compile", "full_factory"}
	stages := make([]any, len(stageKinds))
	stageDigests := make([]string, len(stageKinds))
	for index, kind := range stageKinds {
		stageDigests[index] = shaString("fixture-stage-receipt-" + strconv.Itoa(index))
		stages[index] = map[string]any{
			"stage_kind": kind, "receipt_sha256": stageDigests[index],
			"output_root_sha256": shaString("fixture-stage-output-" + strconv.Itoa(index)),
			"input_resource_set_root_sha256": shaString("fixture-stage-input-" + strconv.Itoa(index)),
		}
	}
	preflight := map[string]any{"receipt_sha256": shaString("fixture-preflight")}
	completion := map[string]any{
		"compiled": true, "verified": true, "derivation_executed": true,
		"graph_admittable": false, "admitted": false, "circuit_admittable": false,
		"circuit_admitted": false, "configured": false, "credential_provisioned": false,
		"deployed": false, "live_tested": false, "two_tenant_proven": false,
		"source_substitution_proven": false, "authority_selected": false,
		"admission_authorized": false, "factory_complete": false,
	}
	receipt := map[string]any{
		"receipt_kind": receiptKind, "receipt_version": receiptVersion,
		"result": receiptResult, "scope": receiptScope,
		"tool_identity": toolIdentity, "execution_identity": executionIdentity,
		"validation_identity": map[string]any{}, "input_admission_proof": proof,
		"input_resources": []any{}, "stages": stages, "preflight_receipt": preflight,
		"completion": completion, "body_free": true,
		"portable_receipt_sha256": "", "receipt_sha256": "",
	}
	portable := clone(receipt)
	portable["execution_identity"] = map[string]any{
		"portable_build_identity_sha256": "", "build_metadata_source": "", "executable_measurement_scope": "",
		"target_os": "", "target_arch": "", "build_settings": nil, "build_settings_sha256": "",
		"executable_sha256": "", "executable_byte_count": int64(0), "go_executable_sha256": "",
		"git_executable_sha256": "", "go_toolchain_sha256": "", "git_toolchain_sha256": "",
		"go_toolchain_file_count": int64(0), "go_toolchain_byte_count": int64(0),
		"git_toolchain_file_count": int64(0), "git_toolchain_byte_count": int64(0),
		"execution_identity_sha256": "",
	}
	portable["validation_identity"] = map[string]any{
		"profile_id": "", "profile_version": "", "result": "", "validation_contract_sha256": "",
		"portable_receipt_sha256": "", "tool_build_identity_sha256": "", "execution_identity_sha256": "",
		"validation_report_sha256": "", "validation_identity_sha256": "",
	}
	portable["portable_receipt_sha256"] = ""
	portable["receipt_sha256"] = ""
	receipt["portable_receipt_sha256"] = digest(portable)
	report := map[string]any{
		"result": validationResult, "portable_receipt_sha256": receipt["portable_receipt_sha256"],
		"tool_build_identity_sha256": toolIdentity["build_identity_sha256"],
		"execution_identity_sha256": executionIdentity["execution_identity_sha256"],
		"input_admission_proof_sha256": proof["proof_sha256"], "stage_receipt_sha256": stageDigests,
		"preflight_receipt_sha256": preflight["receipt_sha256"], "completion_classification": completion,
	}
	validationIdentity := map[string]any{
		"profile_id": validationProfileID, "profile_version": validationVersion, "result": validationResult,
		"validation_contract_sha256": shaString(validationContract),
		"portable_receipt_sha256": receipt["portable_receipt_sha256"],
		"tool_build_identity_sha256": toolIdentity["build_identity_sha256"],
		"execution_identity_sha256": executionIdentity["execution_identity_sha256"],
		"validation_report_sha256": digest(report), "validation_identity_sha256": "",
	}
	closeSelf(validationIdentity, "validation_identity_sha256")
	receipt["validation_identity"] = validationIdentity
	closeSelf(receipt, "receipt_sha256")
	out := receiptOutputPath(os.Args[1:])
	if out == "" { os.Exit(1) }
	file, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil { os.Exit(1) }
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(receipt); err != nil || file.Close() != nil { os.Exit(1) }
}

func buildModule(module debug.Module) map[string]any {
	result := map[string]any{"path": module.Path, "version": module.Version, "sum": module.Sum}
	if module.Replace != nil {
		result["replace_path"] = module.Replace.Path
		result["replace_version"] = module.Replace.Version
		result["replace_sum"] = module.Replace.Sum
	}
	return result
}

func targetSetting(key string) bool {
	switch key {
	case "-buildmode", "-compiler", "-ldflags", "CGO_ENABLED", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS",
		"GOOS", "GOARCH", "GO386", "GOAMD64", "GOARM", "GOARM64", "GOMIPS", "GOMIPS64", "GOPPC64", "GORISCV64", "GOWASM":
		return true
	default:
		return false
	}
}

func positiveCount(value string) int64 {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 { os.Exit(1) }
	return parsed
}

func receiptOutputPath(args []string) string {
	var result string
	for index := 0; index < len(args); index++ {
		name, value, equals := strings.Cut(args[index], "=")
		if name != "--out" && name != "-out" { continue }
		if !equals {
			index++
			if index >= len(args) { return "" }
			value = args[index]
		}
		if result != "" { return "" }
		result = value
	}
	return result
}

func clone(object map[string]any) map[string]any {
	result := make(map[string]any, len(object))
	for key, value := range object { result[key] = value }
	return result
}

func closeSelf(object map[string]any, field string) {
	object[field] = ""
	object[field] = digest(object)
}

func digest(value any) string {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil { os.Exit(1) }
	canonical := bytes.TrimSuffix(output.Bytes(), []byte{'\n'})
	return hexDigest(canonical)
}

func shaString(value string) string { return hexDigest([]byte(value)) }

func hexDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
`

func exactTestExecutable(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	if name == "go" {
		command := exec.Command(path, "env", "GOROOT")
		raw, commandErr := command.Output()
		if commandErr != nil {
			t.Fatal(commandErr)
		}
		suffix := "go"
		if runtime.GOOS == "windows" {
			suffix += ".exe"
		}
		path = filepath.Join(strings.TrimSpace(string(raw)), "bin", suffix)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := physicalTestPath(abs)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" && !strings.HasSuffix(strings.ToLower(resolved), ".exe") {
		t.Fatalf("resolved %s trust root is not an executable: %s", name, resolved)
	}
	return resolved
}

func runFixtureCommand(t *testing.T, directory, executable string, args ...string) []byte {
	t.Helper()
	command := exec.Command(executable, args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", executable, strings.Join(args, " "), err, output)
	}
	return output
}

func writeTestFile(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
}

func environmentMap(environment []string) map[string]string {
	result := make(map[string]string, len(environment))
	for _, value := range environment {
		key, value, _ := strings.Cut(value, "=")
		result[key] = value
	}
	return result
}

func pathWithin(candidate, root string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func sha256HexForTest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
