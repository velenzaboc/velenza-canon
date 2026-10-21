package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type commandTestAdapter struct {
	*fakeAdapter
	schemaResults []error
	verifyErr     error
	checkCalls    int
	verifyCalls   int
}

func (a *commandTestAdapter) nextSchemaResult() error {
	a.checkCalls++
	if len(a.schemaResults) == 0 {
		return nil
	}
	err := a.schemaResults[0]
	a.schemaResults = a.schemaResults[1:]
	return err
}

func (a *commandTestAdapter) CheckSchema(context.Context) error {
	return a.nextSchemaResult()
}
func (a *commandTestAdapter) CheckOODGraphSchema(context.Context) error {
	return a.nextSchemaResult()
}
func (a *commandTestAdapter) VerifyExperimentalSchema(context.Context) error {
	a.verifyCalls++
	return a.verifyErr
}

type commandTestRouter struct {
	adapter SubstrateAdapter
	byIDErr error
	closed  int
}

func (r *commandTestRouter) Adapter(context.Context, NodeKindDescriptor) (SubstrateAdapter, error) {
	return r.adapter, r.byIDErr
}
func (r *commandTestRouter) All(context.Context) ([]SubstrateAdapter, error) {
	return []SubstrateAdapter{r.adapter}, nil
}
func (r *commandTestRouter) ByID(string) (SubstrateAdapter, error) {
	return r.adapter, r.byIDErr
}
func (r *commandTestRouter) Close() error {
	r.closed++
	return nil
}

type commandTestAdmin struct {
	created    []string
	dropped    []string
	appliedDB  string
	statements []string
	createErr  error
	dropErr    error
	applyErr   error
	closed     int
}

func (a *commandTestAdmin) Close() error {
	a.closed++
	return nil
}
func (a *commandTestAdmin) CreateDatabase(_ context.Context, resource string) error {
	a.created = append(a.created, resource)
	return a.createErr
}
func (a *commandTestAdmin) DropDatabase(_ context.Context, resource string) error {
	a.dropped = append(a.dropped, resource)
	return a.dropErr
}
func (a *commandTestAdmin) ApplyDDL(_ context.Context, resource string, statements []string) error {
	a.appliedDB = resource
	a.statements = append([]string(nil), statements...)
	return a.applyErr
}

type commandHarness struct {
	cfg            SpecGraphConfig
	adapter        *commandTestAdapter
	router         *commandTestRouter
	admin          *commandTestAdmin
	stdout         bytes.Buffer
	stderr         bytes.Buffer
	loadErr        error
	adminErr       error
	absErr         error
	readErr        error
	ddl            []byte
	adminCreations int
	routerCreates  int
}

func newCommandHarness() *commandHarness {
	adapter := &commandTestAdapter{fakeAdapter: &fakeAdapter{}}
	h := &commandHarness{
		cfg: SpecGraphConfig{
			Mode:                  ModeExperimentalBootstrap,
			AllowSpannerEmulator:  true,
			InitDatabaseAllowlist: []string{"spec-graph-*"},
			Substrates: []SubstrateDescriptor{{
				ID: "fake", SpannerDatabase: "projects/test/instances/local/databases/spec-graph-test",
				NodeTable: "Nodes", EdgeTable: "Edges", AdmissionLogTable: "AdmissionLog",
				ObjectTable: "OODGraphObjects",
			}},
		},
		adapter: adapter,
		admin:   &commandTestAdmin{},
		ddl:     []byte("-- comment\nCREATE TABLE One (id STRING(10)) PRIMARY KEY (id);\nCREATE TABLE Two (id STRING(10)) PRIMARY KEY (id);"),
	}
	h.router = &commandTestRouter{adapter: adapter}
	return h
}

func (h *commandHarness) dependencies() commandDependencies {
	return commandDependencies{
		loadConfig: func() (SpecGraphConfig, error) { return h.cfg, h.loadErr },
		newRouter: func(SpecGraphConfig) SubstrateRouter {
			h.routerCreates++
			return h.router
		},
		newAdmin: func(context.Context, SpecGraphConfig) (commandAdmin, error) {
			h.adminCreations++
			return h.admin, h.adminErr
		},
		readFile: func(string) ([]byte, error) { return append([]byte(nil), h.ddl...), h.readErr },
		absPath:  func(path string) (string, error) { return "/absolute/" + path, h.absErr },
		stdout:   &h.stdout,
		stderr:   &h.stderr,
	}
}

func TestCmdInitAppliesValidatedDDLAndVerifiesSchema(t *testing.T) {
	h := newCommandHarness()
	h.adapter.schemaResults = []error{ErrSchemaNotApplied, nil}
	err := cmdInitWithDependencies(context.Background(), []string{"--schema", "schema.sql"}, h.dependencies())
	if err != nil {
		t.Fatalf("cmdInitWithDependencies: %v", err)
	}
	if h.adminCreations != 1 || h.admin.closed != 1 || h.router.closed != 1 || h.adapter.checkCalls != 2 {
		t.Fatalf("lifecycle admin=%d/%d router=%d checks=%d", h.adminCreations, h.admin.closed, h.router.closed, h.adapter.checkCalls)
	}
	if h.admin.appliedDB != h.cfg.Substrates[0].SpannerDatabase || len(h.admin.statements) != 2 {
		t.Fatalf("DDL apply = %q %#v", h.admin.appliedDB, h.admin.statements)
	}
	if strings.Contains(h.admin.statements[0], "comment") || !strings.HasPrefix(h.admin.statements[0], "CREATE TABLE One") {
		t.Fatalf("DDL statements not normalized: %#v", h.admin.statements)
	}
	if !strings.Contains(h.stderr.String(), "applying 2 statements") || !strings.Contains(h.stderr.String(), "applied and verified") {
		t.Fatalf("stderr = %q", h.stderr.String())
	}
}

func TestCmdInitIdempotentAndLegacyVerificationPaths(t *testing.T) {
	t.Run("already applied", func(t *testing.T) {
		h := newCommandHarness()
		h.adapter.schemaResults = []error{nil}
		if err := cmdInitWithDependencies(context.Background(), nil, h.dependencies()); err != nil {
			t.Fatal(err)
		}
		if h.adminCreations != 0 || !strings.Contains(h.stderr.String(), "nothing to do") {
			t.Fatalf("idempotent path created admin=%d stderr=%q", h.adminCreations, h.stderr.String())
		}
	})

	t.Run("legacy schema", func(t *testing.T) {
		h := newCommandHarness()
		h.cfg.Substrates[0].ObjectTable = ""
		h.adapter.schemaResults = []error{ErrSchemaNotApplied, nil}
		if err := cmdInitWithDependencies(context.Background(), nil, h.dependencies()); err != nil {
			t.Fatal(err)
		}
		if h.adapter.checkCalls != 2 || len(h.admin.statements) != 2 {
			t.Fatalf("legacy verification checks=%d statements=%#v", h.adapter.checkCalls, h.admin.statements)
		}
	})

	t.Run("write-only descriptor skips post verification", func(t *testing.T) {
		h := newCommandHarness()
		h.cfg.Substrates[0].ObjectTable = ""
		h.cfg.Substrates[0].NodeTable = ""
		h.adapter.schemaResults = []error{ErrSchemaNotApplied}
		if err := cmdInitWithDependencies(context.Background(), nil, h.dependencies()); err != nil {
			t.Fatal(err)
		}
		if h.adapter.checkCalls != 1 {
			t.Fatalf("post verification unexpectedly ran: %d calls", h.adapter.checkCalls)
		}
	})
}

func TestCmdInitRefusesBeforeUnsafeApply(t *testing.T) {
	if err := cmdInitWithDependencies(context.Background(), []string{"--schema"}, newCommandHarness().dependencies()); err == nil || !strings.Contains(err.Error(), "requires a path") {
		t.Fatalf("missing schema argument error = %v", err)
	}
	help := newCommandHarness()
	if err := cmdInitWithDependencies(context.Background(), []string{"--help"}, help.dependencies()); err != nil || !strings.Contains(help.stdout.String(), "apply experimental schema") {
		t.Fatalf("help output=%q err=%v", help.stdout.String(), err)
	}

	tests := []struct {
		name string
		set  func(*commandHarness)
		want string
	}{
		{"config", func(h *commandHarness) { h.loadErr = errors.New("config failed") }, "load config"},
		{"no substrates", func(h *commandHarness) { h.cfg.Substrates = nil }, "no substrates"},
		{"resource", func(h *commandHarness) { h.cfg.Substrates[0].SpannerDatabase = "bad" }, "invalid spanner_database"},
		{"allowlist", func(h *commandHarness) { h.cfg.InitDatabaseAllowlist = nil }, "allowlist empty"},
		{"absolute path", func(h *commandHarness) { h.absErr = errors.New("abs failed") }, "schema path"},
		{"read", func(h *commandHarness) { h.readErr = errors.New("read failed") }, "not readable"},
		{"rendered non-authority", func(h *commandHarness) {
			h.ddl = []byte("-- Rendering is not DDL-apply authorization;\nCREATE TABLE X")
		}, "verification input only"},
		{"empty ddl", func(h *commandHarness) { h.ddl = []byte("-- only a comment") }, "zero DDL"},
		{"router", func(h *commandHarness) {
			h.adapter.schemaResults = []error{ErrSchemaNotApplied}
			h.router.byIDErr = errors.New("route failed")
		}, "resolve substrate"},
		{"admin", func(h *commandHarness) {
			h.adapter.schemaResults = []error{ErrSchemaNotApplied}
			h.adminErr = errors.New("admin failed")
		}, "admin failed"},
		{"apply", func(h *commandHarness) {
			h.adapter.schemaResults = []error{ErrSchemaNotApplied}
			h.admin.applyErr = errors.New("apply failed")
		}, "apply failed"},
		{"post verify", func(h *commandHarness) {
			h.adapter.schemaResults = []error{ErrSchemaNotApplied, errors.New("still missing")}
		}, "post-apply schema_v2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newCommandHarness()
			tc.set(h)
			err := cmdInitWithDependencies(context.Background(), nil, h.dependencies())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestCmdResetDropsRecreatesAndReappliesOnlyAfterFingerprint(t *testing.T) {
	h := newCommandHarness()
	h.adapter.schemaResults = []error{ErrSchemaNotApplied, nil}
	if err := cmdResetWithDependencies(context.Background(), []string{"--confirm"}, h.dependencies()); err != nil {
		t.Fatalf("cmdResetWithDependencies: %v", err)
	}
	resource := h.cfg.Substrates[0].SpannerDatabase
	if len(h.admin.dropped) != 1 || h.admin.dropped[0] != resource || len(h.admin.created) != 1 || h.admin.created[0] != resource {
		t.Fatalf("reset mutations dropped=%#v created=%#v", h.admin.dropped, h.admin.created)
	}
	if len(h.admin.statements) != 2 || h.adapter.verifyCalls != 1 || h.adminCreations != 2 || h.routerCreates != 2 {
		t.Fatalf("reset lifecycle statements=%#v verify=%d admins=%d routers=%d", h.admin.statements, h.adapter.verifyCalls, h.adminCreations, h.routerCreates)
	}
	if !strings.Contains(h.stderr.String(), "dropping") || !strings.Contains(h.stderr.String(), "creating") || !strings.Contains(h.stderr.String(), "empty experimental graph ready") {
		t.Fatalf("stderr = %q", h.stderr.String())
	}
}

func TestCmdResetRefusalAndFailureBoundaries(t *testing.T) {
	h := newCommandHarness()
	if err := cmdResetWithDependencies(context.Background(), nil, h.dependencies()); err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("unconfirmed reset error = %v", err)
	}
	help := newCommandHarness()
	if err := cmdResetWithDependencies(context.Background(), []string{"--help"}, help.dependencies()); err != nil || !strings.Contains(help.stdout.String(), "drop + recreate") {
		t.Fatalf("help output=%q err=%v", help.stdout.String(), err)
	}

	tests := []struct {
		name string
		set  func(*commandHarness)
		want string
	}{
		{"config", func(h *commandHarness) { h.loadErr = errors.New("config failed") }, "load config"},
		{"no substrates", func(h *commandHarness) { h.cfg.Substrates = nil }, "no substrates"},
		{"resource", func(h *commandHarness) { h.cfg.Substrates[0].SpannerDatabase = "bad" }, "invalid spanner_database"},
		{"allowlist", func(h *commandHarness) { h.cfg.InitDatabaseAllowlist = nil }, "allowlist empty"},
		{"route", func(h *commandHarness) { h.router.byIDErr = errors.New("route failed") }, "route failed"},
		{"fingerprint", func(h *commandHarness) { h.adapter.verifyErr = errors.New("wrong schema") }, "refusing to drop"},
		{"admin", func(h *commandHarness) { h.adminErr = errors.New("admin failed") }, "admin failed"},
		{"drop", func(h *commandHarness) { h.admin.dropErr = errors.New("drop failed") }, "drop failed"},
		{"create", func(h *commandHarness) { h.admin.createErr = errors.New("create failed") }, "create failed"},
		{"reapply", func(h *commandHarness) {
			h.adapter.schemaResults = []error{ErrSchemaNotApplied}
			h.readErr = errors.New("schema missing")
		}, "re-apply schema"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newCommandHarness()
			tc.set(h)
			err := cmdResetWithDependencies(context.Background(), []string{"--confirm"}, h.dependencies())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestSchemaCommandParsingAndTargetAllowlist(t *testing.T) {
	statements := splitDDL("-- heading\n CREATE TABLE One (x INT64); ;\nCREATE INDEX I ON One(x); -- tail")
	if len(statements) != 2 || !strings.HasPrefix(statements[0], "CREATE TABLE") || !strings.HasPrefix(statements[1], "CREATE INDEX") {
		t.Fatalf("splitDDL = %#v", statements)
	}
	if err := validateSchemaApplyArtifact([]byte("CREATE TABLE Safe")); err != nil {
		t.Fatalf("safe schema: %v", err)
	}
	if err := validateSchemaApplyArtifact([]byte("-- Rendering is not DDL-apply authorization;")); err == nil {
		t.Fatal("non-authorizing render marker accepted")
	}
	project, instance, database, err := parseSpannerResource("projects/p/instances/i/databases/d")
	if err != nil || project != "p" || instance != "i" || database != "d" {
		t.Fatalf("parse resource = %q %q %q %v", project, instance, database, err)
	}
	if _, _, _, err := parseSpannerResource("projects/p/databases/d"); err == nil {
		t.Fatal("malformed resource accepted")
	}
	cfg := SpecGraphConfig{InitDatabaseAllowlist: []string{"spec-graph-*"}}
	if err := allowlistCheck(cfg, "spec-graph-test"); err != nil {
		t.Fatalf("allowed target: %v", err)
	}
	if err := allowlistCheck(cfg, "production"); !errors.Is(err, ErrForbiddenDatabaseTarget) {
		t.Fatalf("disallowed target error = %v", err)
	}
	if err := allowlistCheck(SpecGraphConfig{InitDatabaseAllowlist: []string{"["}}, "x"); err == nil || !strings.Contains(err.Error(), "invalid pattern") {
		t.Fatalf("invalid glob error = %v", err)
	}
}
