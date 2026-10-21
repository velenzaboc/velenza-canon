//go:build integration

package main

import (
	"context"
	"strings"
	"testing"
)

func TestAdminClientEmulatorLifecycleAndRefusals(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	resource := "projects/test-project/instances/test-instance/databases/admin-coverage"

	if _, err := newAdminClient(ctx, experimentalGoogleCredentials(), false); err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("emulator without opt-in error=%v", err)
	}
	admin, err := newAdminClient(ctx, experimentalGoogleCredentials(), true)
	if err != nil {
		t.Fatalf("new admin client: %v", err)
	}
	defer func() {
		if err := admin.Close(); err != nil {
			t.Errorf("close admin client: %v", err)
		}
	}()

	if err := admin.DropDatabase(ctx, resource); err != nil {
		t.Fatalf("idempotent initial drop: %v", err)
	}
	if err := admin.CreateDatabase(ctx, "not-a-resource"); err == nil {
		t.Fatal("malformed database resource accepted")
	}
	if err := admin.CreateDatabase(ctx, resource); err != nil {
		t.Fatalf("create database: %v", err)
	}
	if err := admin.ApplyDDL(ctx, resource, []string{
		"CREATE TABLE admin_coverage (id STRING(32) NOT NULL) PRIMARY KEY (id)",
	}); err != nil {
		t.Fatalf("apply ddl: %v", err)
	}
	if err := admin.CreateDatabase(ctx, resource); err == nil || !strings.Contains(err.Error(), "create database") {
		t.Fatalf("duplicate create error=%v", err)
	}
	if err := admin.DropDatabase(ctx, resource); err != nil {
		t.Fatalf("drop database: %v", err)
	}
	if err := admin.DropDatabase(ctx, resource); err != nil {
		t.Fatalf("idempotent repeated drop: %v", err)
	}
	if err := admin.ApplyDDL(ctx, resource, []string{"CREATE TABLE impossible (id INT64 NOT NULL) PRIMARY KEY (id)"}); err == nil || !strings.Contains(err.Error(), "update ddl") {
		t.Fatalf("ddl against absent database error=%v", err)
	}
}
