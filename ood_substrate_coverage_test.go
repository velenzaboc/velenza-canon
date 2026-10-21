package main

import (
	"context"
	"strings"
	"testing"
)

func TestOODSubstrateTableContractFailsClosed(t *testing.T) {
	full := SubstrateDescriptor{ID: "ood", SnapshotTable: "snapshots", ObjectTable: "objects", SymbolTable: "symbols", GraphEdgeTable: "edges", MaterializationRunTable: "runs", ViolationTable: "violations", ProjectionArtifactTable: "projections"}
	adapter := &SpannerSubstrateAdapter{Descriptor: full}
	if snapshot, object, symbol, edge, run, violation, projection, err := adapter.requireOODGraphTables(); err != nil || snapshot != "snapshots" || object != "objects" || symbol != "symbols" || edge != "edges" || run != "runs" || violation != "violations" || projection != "projections" {
		t.Fatalf("OOD table contract=%q %q %q %q %q %q %q err=%v", snapshot, object, symbol, edge, run, violation, projection, err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*SubstrateDescriptor)
		want   string
	}{
		{"read only", func(d *SubstrateDescriptor) { d.ReadOnly = true }, "read-only"},
		{"missing object", func(d *SubstrateDescriptor) { d.ObjectTable = "" }, "object_table"},
		{"missing run", func(d *SubstrateDescriptor) { d.MaterializationRunTable = "" }, "materialization_run_table"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := full
			tc.mutate(&d)
			if _, _, _, _, _, _, _, err := (&SpannerSubstrateAdapter{Descriptor: d}).requireOODGraphTables(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
	if err := (&SpannerSubstrateAdapter{Descriptor: full}).CheckOODGraphSchema(context.Background()); err == nil {
		t.Fatalf("schema client refusal=%v", err)
	}
}

func TestOODSubstrateRejectsInvalidLifecycleInputsBeforeConnecting(t *testing.T) {
	adapter := &SpannerSubstrateAdapter{Descriptor: SubstrateDescriptor{
		ID:                      "ood",
		SnapshotTable:           "snapshots",
		ObjectTable:             "objects",
		SymbolTable:             "symbols",
		GraphEdgeTable:          "edges",
		MaterializationRunTable: "runs",
		ViolationTable:          "violations",
		ProjectionArtifactTable: "projections",
	}}
	ctx := context.Background()
	run := MaterializationRun{OrganizationID: "org", MaterializationRunID: "run", State: "running", InputSourceSetHash: "hash", InputSourceSet: map[string]interface{}{"materialization_profile_version": "invalid"}}
	if err := adapter.OpenMaterializationRun(ctx, MaterializationRun{State: "pending"}); err == nil || !strings.Contains(err.Error(), "expected \"running\"") {
		t.Fatalf("open state error=%v", err)
	}
	if err := adapter.OpenMaterializationRun(ctx, MaterializationRun{State: "running"}); err == nil || !strings.Contains(err.Error(), "organization_id") {
		t.Fatalf("open identity error=%v", err)
	}
	if err := adapter.OpenMaterializationRun(ctx, MaterializationRun{OrganizationID: "org", MaterializationRunID: "run", State: "running"}); err == nil || !strings.Contains(err.Error(), "input_source_set_hash") {
		t.Fatalf("open source-set error=%v", err)
	}
	if err := adapter.OpenMaterializationRun(ctx, run); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("open profile error=%v", err)
	}
	batch := MaterializationBatch{Run: run, Snapshot: GraphSnapshot{OrganizationID: "org", SnapshotState: "building"}}
	batch.Run.State = "sealed"
	if err := adapter.CommitMaterializationRun(ctx, batch); err == nil || !strings.Contains(err.Error(), "batch.Run.State") {
		t.Fatalf("commit run state error=%v", err)
	}
	batch.Run.State = "running"
	batch.Snapshot.SnapshotState = "sealed"
	if err := adapter.CommitMaterializationRun(ctx, batch); err == nil || !strings.Contains(err.Error(), "batch.Snapshot.SnapshotState") {
		t.Fatalf("commit snapshot state error=%v", err)
	}
	batch.Snapshot.SnapshotState = "building"
	batch.Snapshot.OrganizationID = "other-org"
	if err := adapter.CommitMaterializationRun(ctx, batch); err == nil || !strings.Contains(err.Error(), "snapshot.organization_id") {
		t.Fatalf("commit organization error=%v", err)
	}
	batch.Snapshot.OrganizationID = "org"
	if err := adapter.CommitMaterializationRun(ctx, batch); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("commit profile error=%v", err)
	}
}
