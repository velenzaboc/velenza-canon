package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestGoogleClientConstructionIsIdentityBound(t *testing.T) {
	required := map[string][]string{
		"admin.go":                           {"TokenSource", "WithTokenSource", "WithoutAuthentication", "NewDatabaseAdminClient"},
		"substrate.go":                       {"TokenSource", "WithTokenSource", "WithoutAuthentication", "NewClient"},
		"mcp.go":                             {"RequestTokenSourceFactory", "NewAuth", "NewEmbedClient"},
		"bootstrap/cmd/spec-cluster/main.go": {"RequestTokenSourceFactory", "NewAuth", "NewEmbedClient"},
		"bootstrap/cmd/spec-dedup-verify/main.go": {"RequestTokenSourceFactory", "NewAuth", "NewFlashClient"},
		"bootstrap/cmd/spec-lint/main.go":         {"RequestTokenSourceFactory", "NewAuth", "NewFlashClient"},
	}
	for path, names := range required {
		calls := parsedCallNames(t, path)
		for _, name := range names {
			if calls[name] == 0 {
				t.Errorf("%s: required call %s is absent", path, name)
			}
		}
	}
}

func TestEveryVertexClientConsumesTheValidatedProcessSelector(t *testing.T) {
	for _, path := range []string{
		"mcp.go",
		"bootstrap/cmd/spec-cluster/main.go",
		"bootstrap/cmd/spec-dedup-verify/main.go",
		"bootstrap/cmd/spec-lint/main.go",
	} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Count(string(data), "cfg.GoogleCredentials.RequestTokenSourceFactory("); got != 1 {
			t.Errorf("%s: cfg.GoogleCredentials.RequestTokenSourceFactory call count = %d, want 1", path, got)
		}
	}
}

func TestEveryConfigLoaderRejectsHiddenCredentialSelectors(t *testing.T) {
	for _, path := range []string{
		"config.go",
		"bootstrap/cmd/spec-cluster/config.go",
		"bootstrap/cmd/spec-dedup-verify/config.go",
		"bootstrap/cmd/spec-lint/types.go",
	} {
		if got := parsedCallNames(t, path)["ValidateConfigCredentialShape"]; got != 1 {
			t.Errorf("%s: ValidateConfigCredentialShape call count = %d, want 1", path, got)
		}
	}
}

func TestRuntimeHasNoImplicitOrExportableGoogleCredentialConstructor(t *testing.T) {
	scan, err := scanGoogleCredentialConstructors(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, violation := range scan.violations {
		t.Error(violation)
	}
	if scan.typedImpersonationParserCalls != 1 {
		t.Fatalf("CredentialsFromJSONWithType call count = %d, want exactly 1 in internal/gcpauth/selector.go", scan.typedImpersonationParserCalls)
	}

	// Denominator: the scan must reach every production Go file this
	// repository tracks, so a pruning rule can never silently drop real source.
	tracked := trackedProductionGoFiles(t, ".")
	if len(tracked) == 0 {
		t.Fatal("git reports no tracked production Go files; the credential scan denominator is unmeasured")
	}
	scanned := make(map[string]struct{}, len(scan.files))
	for _, path := range scan.files {
		scanned[path] = struct{}{}
	}
	for _, path := range tracked {
		if _, ok := scanned[path]; !ok {
			t.Errorf("tracked production Go file %s was not scanned for credential constructors", path)
		}
	}
	if len(scan.files) < len(tracked) {
		t.Fatalf("credential scan reached %d production Go files, fewer than the %d tracked", len(scan.files), len(tracked))
	}
}

func TestGoogleCredentialConstructorScanPrunesOnlyNestedCheckouts(t *testing.T) {
	root := t.TempDir()
	writeScanFixture := func(relative, content string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The scanned checkout's own .git never causes its root to be pruned.
	writeScanFixture(".git/HEAD", "ref: refs/heads/main\n")
	writeScanFixture("go.mod", "module example.com/scanfixture\n")
	writeScanFixture("substrate.go", "package main\n\nfunc a() { spanner.NewClient(nil, \"\") }\n")
	writeScanFixture("admin.go", "package main\n\nfunc b() { database.NewDatabaseAdminClient(nil) }\n")
	writeScanFixture("internal/gcpauth/selector.go", "package gcpauth\n\nfunc c() { google.CredentialsFromJSONWithType(nil, nil, \"\") }\n")
	// Planted violations inside this checkout, including under an
	// underscore-prefixed directory that is not a separate checkout.
	writeScanFixture("internal/rogue/rogue.go", "package rogue\n\nfunc d() { spanner.NewClient(nil, \"\") }\n")
	writeScanFixture("_scratch/plain/plain.go", "package plain\n\nfunc e() { google.FindDefaultCredentials(nil) }\n")
	// Test files are outside the runtime boundary.
	writeScanFixture("internal/rogue/rogue_test.go", "package rogue\n\nfunc f() { spanner.NewClient(nil, \"\") }\n")
	// Separate nested checkouts: a .git directory (actions/checkout) and a
	// .git file (git worktree). Neither is this repository's source.
	writeScanFixture("_canonical/specs-repo/.git/HEAD", "ref: refs/heads/main\n")
	writeScanFixture("_canonical/specs-repo/go.mod", "module example.com/canonical\n")
	writeScanFixture("_canonical/specs-repo/cmd/genesis-seed/main.go", "package main\n\nfunc g() { spanner.NewClient(nil, \"\") }\n")
	writeScanFixture("worktreecheckout/.git", "gitdir: ../elsewhere\n")
	writeScanFixture("worktreecheckout/main.go", "package main\n\nfunc h() { google.CredentialsFromJSON(nil, nil) }\n")

	scan, err := scanGoogleCredentialConstructors(root)
	if err != nil {
		t.Fatal(err)
	}
	wantFiles := []string{"_scratch/plain/plain.go", "admin.go", "internal/gcpauth/selector.go", "internal/rogue/rogue.go", "substrate.go"}
	if !equalSortedStrings(scan.files, wantFiles) {
		t.Fatalf("scanned files = %q, want %q", scan.files, wantFiles)
	}
	wantViolations := []string{
		"_scratch/plain/plain.go: forbidden ambient/exportable credential call FindDefaultCredentials",
		"internal/rogue/rogue.go: spanner.NewClient must be centralized in substrate.go",
	}
	if !equalSortedStrings(scan.violations, wantViolations) {
		t.Fatalf("violations = %q, want %q", scan.violations, wantViolations)
	}
	if scan.typedImpersonationParserCalls != 1 {
		t.Fatalf("typed impersonation parser calls = %d, want 1", scan.typedImpersonationParserCalls)
	}
}

type googleCredentialConstructorScan struct {
	files                         []string
	violations                    []string
	typedImpersonationParserCalls int
}

// scanGoogleCredentialConstructors parses every non-test Go file of the
// repository checkout rooted at root. It never enters .git and prunes any
// nested directory that carries its own .git entry, because that directory is
// a separate checkout (for example CI's _canonical/specs-repo), not this
// repository's runtime source. Paths are reported relative to root with
// forward slashes, and files and violations are sorted.
func scanGoogleCredentialConstructors(root string) (googleCredentialConstructorScan, error) {
	forbidden := []string{"CredentialsFromJSON", "FindDefaultCredentials", "JWTConfigFromJSON", "WithCredentialsFile"}
	allowedGoogleConstructors := []struct{ name, path string }{
		{name: "database.NewDatabaseAdminClient", path: "admin.go"},
		{name: "spanner.NewClient", path: "substrate.go"},
	}
	var scan googleCredentialConstructorScan
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.IsDir() {
			if relative == "." {
				return nil
			}
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			if _, err := os.Lstat(filepath.Join(path, ".git")); err == nil {
				return filepath.SkipDir
			} else if !os.IsNotExist(err) {
				return err
			}
			return nil
		}
		if !strings.HasSuffix(relative, ".go") || strings.HasSuffix(relative, "_test.go") {
			return nil
		}
		calls, err := parseCallNames(path)
		if err != nil {
			return err
		}
		scan.files = append(scan.files, relative)
		for _, name := range forbidden {
			if calls[name] > 0 {
				scan.violations = append(scan.violations, fmt.Sprintf("%s: forbidden ambient/exportable credential call %s", relative, name))
			}
		}
		if count := calls["CredentialsFromJSONWithType"]; count > 0 {
			if relative != "internal/gcpauth/selector.go" {
				scan.violations = append(scan.violations, fmt.Sprintf("%s: typed impersonation parsing must be centralized in internal/gcpauth/selector.go", relative))
			}
			scan.typedImpersonationParserCalls += count
		}
		for _, allowed := range allowedGoogleConstructors {
			if calls[allowed.name] > 0 && relative != allowed.path {
				scan.violations = append(scan.violations, fmt.Sprintf("%s: %s must be centralized in %s", relative, allowed.name, allowed.path))
			}
		}
		return nil
	})
	if err != nil {
		return googleCredentialConstructorScan{}, err
	}
	sort.Strings(scan.files)
	sort.Strings(scan.violations)
	return scan, nil
}

// trackedProductionGoFiles lists the non-test Go files recorded in the Git
// index of the checkout at root that are present in its working tree.
func trackedProductionGoFiles(t *testing.T, root string) []string {
	t.Helper()
	command := exec.Command("git", "ls-files", "--cached", "-z", "--", "*.go")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git ls-files for the credential scan denominator: %v", err)
	}
	var tracked []string
	for _, path := range strings.Split(string(output), "\x00") {
		if path == "" || strings.HasSuffix(path, "_test.go") {
			continue
		}
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path))); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		tracked = append(tracked, path)
	}
	sort.Strings(tracked)
	return tracked
}

func equalSortedStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	sortedWant := append([]string(nil), want...)
	sort.Strings(sortedWant)
	for index := range got {
		if got[index] != sortedWant[index] {
			return false
		}
	}
	return true
}

func TestSpannerEmulatorBypassIsExplicitlyExperimental(t *testing.T) {
	descriptor := SubstrateDescriptor{ID: "test", SpannerDatabase: "projects/p/instances/i/databases/d"}

	t.Setenv("SPANNER_EMULATOR_HOST", "localhost:9010")
	production := &SpannerSubstrateAdapter{Descriptor: descriptor, AllowEmulator: false}
	if _, err := production.getClient(context.Background()); err == nil || !strings.Contains(err.Error(), "forbidden outside experimental bootstrap") {
		t.Fatalf("production emulator error = %v", err)
	}

	t.Setenv("SPANNER_EMULATOR_HOST", "127.0.0.1:9010")
	wrongHost := &SpannerSubstrateAdapter{Descriptor: descriptor, AllowEmulator: true}
	if _, err := wrongHost.getClient(context.Background()); err == nil || !strings.Contains(err.Error(), "must equal") {
		t.Fatalf("non-canonical emulator host error = %v", err)
	}

	t.Setenv("SPANNER_EMULATOR_HOST", "localhost:9010")
	experimental := &SpannerSubstrateAdapter{Descriptor: descriptor, AllowEmulator: true}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := experimental.getClient(ctx)
	if err != nil {
		t.Fatalf("experimental emulator client unexpectedly resolved credentials: %v", err)
	}
	if client == nil {
		t.Fatal("experimental emulator client is nil")
	}
	_ = experimental.Close()
}

func parsedCallNames(t *testing.T, path string) map[string]int {
	t.Helper()
	calls, err := parseCallNames(path)
	if err != nil {
		t.Fatal(err)
	}
	return calls
}

func parseCallNames(path string) (map[string]int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
	if err != nil {
		return nil, err
	}
	calls := make(map[string]int)
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			calls[fun.Name]++
		case *ast.SelectorExpr:
			calls[fun.Sel.Name]++
			if qualified := selectorCallName(fun); qualified != fun.Sel.Name {
				calls[qualified]++
			}
		}
		return true
	})
	return calls, nil
}

func selectorCallName(selector *ast.SelectorExpr) string {
	parts := []string{selector.Sel.Name}
	var expression ast.Expr = selector.X
	for {
		switch typed := expression.(type) {
		case *ast.Ident:
			parts = append([]string{typed.Name}, parts...)
			return strings.Join(parts, ".")
		case *ast.SelectorExpr:
			parts = append([]string{typed.Sel.Name}, parts...)
			expression = typed.X
		default:
			return strings.Join(parts, ".")
		}
	}
}
