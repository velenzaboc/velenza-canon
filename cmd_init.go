package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
)

// cmdInit applies the configured schema file to the experimental
// Spanner database via the Spanner Admin API using the substrate's
// declared credential selector. No gcloud shell-out. Idempotent: re-running on an
// already-initialized DB reports "already applied" and exits 0. Refuses any
// database not matching the config's init_database_allowlist glob patterns.
func cmdInit(ctx context.Context, args []string) error {
	return cmdInitWithDependencies(ctx, args, productionCommandDependencies())
}

func cmdInitWithDependencies(ctx context.Context, args []string, deps commandDependencies) error {
	// Default is schema_v2.sql post-(C)-substrate-rebuild. The legacy
	// schema_v1.sql remains on disk for reference. Pass --schema to override.
	schemaPath := "bootstrap/schema_v2.sql"
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--schema":
			if i+1 >= len(args) {
				return fmt.Errorf("--schema requires a path")
			}
			schemaPath = args[i+1]
			i++
		case "-h", "--help":
			fmt.Fprintln(deps.stdout, `spec-graph init — apply experimental schema

Reads DDL from bootstrap/schema_v2.sql (override with --schema <path>) and
applies it to the substrate's Spanner database via the Spanner Admin API.
Authenticates using the substrate's declared credential selector (no gcloud shell-out).
Refuses any database whose name does not match init_database_allowlist
patterns from spec-graph.config.json.

Idempotent: re-running on an already-initialized database reports "already
applied" and exits 0.`)
			return nil
		}
	}

	cfg, err := deps.loadConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if len(cfg.Substrates) == 0 {
		return fmt.Errorf("no substrates registered in spec-graph.config.json")
	}
	sub := cfg.Substrates[0]
	_, _, database, err := parseSpannerResource(sub.SpannerDatabase)
	if err != nil {
		return err
	}
	if err := allowlistCheck(cfg, database); err != nil {
		return err
	}

	abs, err := deps.absPath(schemaPath)
	if err != nil {
		return fmt.Errorf("schema path %q: %w", schemaPath, err)
	}
	ddlBytes, err := deps.readFile(abs)
	if err != nil {
		return fmt.Errorf("schema file %q not readable: %w", abs, err)
	}
	if err := validateSchemaApplyArtifact(ddlBytes); err != nil {
		return fmt.Errorf("schema file %q: %w", abs, err)
	}
	statements := splitDDL(string(ddlBytes))
	if len(statements) == 0 {
		return fmt.Errorf("schema file %q produced zero DDL statements", abs)
	}

	fmt.Fprintf(deps.stderr, "spec-graph init: applying %d statements from %s to %s\n", len(statements), abs, sub.SpannerDatabase)

	// Idempotence probe via the data-plane adapter matching the configured
	// storage generation. schema_v2 descriptors do not carry legacy table
	// names, so calling CheckSchema unconditionally would re-apply DDL on
	// every invocation instead of recognizing an already-applied graph.
	router := deps.newRouter(cfg)
	defer router.Close()
	adapter, err := router.ByID(sub.ID)
	if err != nil {
		return fmt.Errorf("resolve substrate %q: %w", sub.ID, err)
	}
	var schemaCheckErr error
	if sub.ObjectTable != "" {
		schemaCheckErr = adapter.CheckOODGraphSchema(ctx)
	} else {
		schemaCheckErr = adapter.CheckSchema(ctx)
	}
	if schemaCheckErr == nil {
		fmt.Fprintln(deps.stderr, "spec-graph init: schema already applied — nothing to do")
		return nil
	}

	admin, err := deps.newAdmin(ctx, cfg)
	if err != nil {
		return err
	}
	defer admin.Close()

	if err := admin.ApplyDDL(ctx, sub.SpannerDatabase, statements); err != nil {
		return err
	}

	// Post-apply verification under (C) substrate rebuild: schema_v2 declares
	// the 7 OODGraph tables; if any of those configured, prefer
	// CheckOODGraphSchema. If the substrate is on legacy schema_v1, fall back
	// to CheckSchema. If neither set of table fields is configured, skip
	// verification — Spanner ApplyDDL above is authoritative.
	if sub.ObjectTable != "" {
		if err := adapter.CheckOODGraphSchema(ctx); err != nil {
			return fmt.Errorf("post-apply schema_v2 verification failed: %w", err)
		}
	} else if sub.NodeTable != "" {
		if err := adapter.CheckSchema(ctx); err != nil {
			return fmt.Errorf("post-apply schema_v1 verification failed: %w", err)
		}
	}
	fmt.Fprintln(deps.stderr, "spec-graph init: schema applied and verified")
	return nil
}

func validateSchemaApplyArtifact(ddl []byte) error {
	const nonAuthorizingMarker = "-- Rendering is not DDL-apply authorization;"
	if strings.Contains(string(ddl), nonAuthorizingMarker) {
		return fmt.Errorf("rendered canonical OOD schema is verification input only; the current seven-table runtime is not compatible and cannot apply it")
	}
	return nil
}

// parseSpannerResource extracts (project, instance, database) from a
// projects/X/instances/Y/databases/Z resource path.
func parseSpannerResource(uri string) (project, instance, database string, err error) {
	parts := strings.Split(uri, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "instances" || parts[4] != "databases" {
		return "", "", "", fmt.Errorf("invalid spanner_database resource %q (want projects/X/instances/Y/databases/Z)", uri)
	}
	return parts[1], parts[3], parts[5], nil
}

// allowlistCheck refuses any database name that doesn't match the config's
// init_database_allowlist glob patterns. Empty allowlist → refuses.
func allowlistCheck(cfg SpecGraphConfig, database string) error {
	if len(cfg.InitDatabaseAllowlist) == 0 {
		return fmt.Errorf("%w: init_database_allowlist empty in spec-graph.config.json — refusing", ErrForbiddenDatabaseTarget)
	}
	for _, pattern := range cfg.InitDatabaseAllowlist {
		matched, err := filepath.Match(pattern, database)
		if err != nil {
			return fmt.Errorf("invalid pattern %q in init_database_allowlist: %w", pattern, err)
		}
		if matched {
			return nil
		}
	}
	return fmt.Errorf("%w: database %q matches none of init_database_allowlist patterns %v", ErrForbiddenDatabaseTarget, database, cfg.InitDatabaseAllowlist)
}
