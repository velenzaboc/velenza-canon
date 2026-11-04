//go:build integration

package main

import (
	"context"
	"os"
	"strings"
	"testing"
)

// TestAPIRoleLocatorDDLParsesOnSpannerEmulator applies the actual index DDL
// from both bootstrap paths. The fresh schema contains emulator-unsupported
// vector and property-graph DDL, so this test isolates the shared index on a
// table with its real key and API-role column shapes.
func TestAPIRoleLocatorDDLParsesOnSpannerEmulator(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()

	migration, err := os.ReadFile("bootstrap/migrations/003_ood_graph_api_role_locator.sql")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := os.ReadFile("bootstrap/schema_v2.sql")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("existing schema migration", func(t *testing.T) {
		setupEmulatorDB(ctx, t)
		applyIntegrationDDL(ctx, t, []string{oodGraphObjectsBaseDDL(false)})
		applyIntegrationDDL(ctx, t, splitDDL(string(migration)))
	})

	t.Run("fresh schema index", func(t *testing.T) {
		setupEmulatorDB(ctx, t)
		applyIntegrationDDL(ctx, t, []string{oodGraphObjectsBaseDDL(true), apiRoleLocatorIndexStatement(t, string(fresh))})
	})
}

func oodGraphObjectsBaseDDL(withAPIRoleColumns bool) string {
	columns := ""
	if withAPIRoleColumns {
		columns = `,
	api_element_role STRING(64),
	api_element_role_locator_manifest_hash STRING(64)`
	}
	return `CREATE TABLE OODGraphObjects (
	organization_id STRING(36) NOT NULL,
	graph_snapshot_id STRING(36) NOT NULL,
	graph_object_id STRING(36) NOT NULL` + columns + `
) PRIMARY KEY (organization_id, graph_snapshot_id, graph_object_id)`
}

func apiRoleLocatorIndexStatement(t *testing.T, ddl string) string {
	t.Helper()
	var statements []string
	for _, statement := range splitDDL(ddl) {
		if strings.Contains(statement, "OODGraphObjectsByApiRoleLocatorManifest") {
			statements = append(statements, statement)
		}
	}
	if len(statements) != 1 {
		t.Fatalf("found %d API-role locator index statements, want 1", len(statements))
	}
	return statements[0]
}
