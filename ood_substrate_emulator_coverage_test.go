//go:build integration

package main

import (
	"context"
	"strings"
	"testing"

	"cloud.google.com/go/spanner"
)

func TestOODSubstrateEmulatorSnapshotVersionQueries(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	adapter, err := env.Substrates.ByID("test_substrate")
	if err != nil {
		t.Fatal(err)
	}
	a := adapter.(*SpannerSubstrateAdapter)
	if err := a.CheckOODGraphSchema(ctx); err != nil {
		t.Fatalf("schema=%v", err)
	}
	first := integrationMaterializationBatch(t, "ood-coverage-first", strings.Repeat("a", 64))
	if err := a.OpenMaterializationRun(ctx, first.Run); err != nil {
		t.Fatal(err)
	}
	if err := a.CommitMaterializationRun(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := integrationMaterializationBatch(t, "ood-coverage-second", strings.Repeat("b", 64))
	if err := a.OpenMaterializationRun(ctx, second.Run); err != nil {
		t.Fatal(err)
	}
	if err := a.CommitMaterializationRun(ctx, second); err != nil {
		t.Fatal(err)
	}
	failed := integrationMaterializationBatch(t, "ood-coverage-failed", strings.Repeat("c", 64))
	if err := a.OpenMaterializationRun(ctx, failed.Run); err != nil {
		t.Fatal(err)
	}
	if err := a.FailMaterializationRun(ctx, failed.Run.OrganizationID, failed.Run.MaterializationRunID); err != nil {
		t.Fatal(err)
	}
	if err := a.FailMaterializationRun(ctx, failed.Run.OrganizationID, failed.Run.MaterializationRunID); err != nil {
		t.Fatalf("idempotent failure=%v", err)
	}
	if err := a.CommitMaterializationRun(ctx, failed); err == nil {
		t.Fatal("commit accepted a failed materialization run")
	}
	client, err := a.getClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		latest, err := latestEligibleActiveCandidateVersionInTx(ctx, tx, a.Descriptor.SnapshotTable, a.Descriptor.MaterializationRunTable, "test-org")
		if err != nil || latest != 2 {
			t.Fatalf("latest=%d err=%v", latest, err)
		}
		newer, err := newerEligibleActiveCandidateSnapshotIDsInTx(ctx, tx, a.Descriptor.SnapshotTable, a.Descriptor.MaterializationRunTable, "test-org", 1)
		if err != nil || len(newer) != 1 || newer[0] != second.Snapshot.GraphSnapshotID {
			t.Fatalf("newer=%v err=%v", newer, err)
		}
		none, err := newerEligibleActiveCandidateSnapshotIDsInTx(ctx, tx, a.Descriptor.SnapshotTable, a.Descriptor.MaterializationRunTable, "test-org", 2)
		if err != nil || len(none) != 0 {
			t.Fatalf("newer after current=%v err=%v", none, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
