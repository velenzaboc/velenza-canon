//go:build integration

package main

import (
	"context"
	"testing"
)

func TestStagingEmulatorLoadLintListGetAndPromote(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()
	loaded, err := handleStagingLoad(ctx, env, stagingLoadInput{
		IngestionRunID: "staging-emulator-run",
		SourceFile:     "fixture.ood.json",
		Concepts: []stagingLoadConcept{
			{CanonicalName: "staging_alpha", NodeKind: "section", Contract: map[string]interface{}{"canonical_name": "staging_alpha"}, Payload: map[string]interface{}{"title": "Alpha"}, SourcePath: "$.alpha"},
			{CanonicalName: "staging_beta", NodeKind: "section", Contract: map[string]interface{}{"canonical_name": "staging_beta"}, Payload: map[string]interface{}{"title": "Beta"}, SourcePath: "$.beta"},
		},
	})
	if err != nil || loaded.ConceptsLoaded != 2 || loaded.EdgesLoaded != 0 {
		t.Fatalf("load=%+v err=%v", loaded, err)
	}
	listed, err := handleStagingList(ctx, env, stagingListInput{IngestionRunID: loaded.IngestionRunID, Limit: 10})
	if err != nil || len(listed.Rows) != 2 || listed.Rows[0]["canonical_name"] != "staging_alpha" {
		t.Fatalf("list=%+v err=%v", listed, err)
	}
	firstID, _ := listed.Rows[0]["staging_id"].(string)
	got, err := handleStagingGet(ctx, env, stagingGetInput{IngestionRunID: loaded.IngestionRunID, StagingID: firstID})
	if err != nil || len(got.Rows) != 1 || got.Rows[0]["source_path"] != "$.alpha" {
		t.Fatalf("get=%+v err=%v", got, err)
	}
	linted, err := handleStagingLint(ctx, env, stagingLintInput{IngestionRunID: loaded.IngestionRunID})
	if err != nil || linted.ConceptsLinted != 2 || len(linted.Findings) != 0 || len(linted.RulesRun) != 7 {
		t.Fatalf("lint=%+v err=%v", linted, err)
	}
	promoted, err := handleStagingPromote(ctx, env, stagingPromoteInput{IngestionRunID: loaded.IngestionRunID})
	if err != nil || promoted.ConceptsPromoted != 2 || promoted.GraphSnapshotID == "" {
		t.Fatalf("promote=%+v err=%v", promoted, err)
	}
	objects, err := handleOODList(ctx, env, oodListInput{ObjectClass: "section", Limit: 10})
	if err != nil || len(objects.Rows) != 2 {
		t.Fatalf("promoted OOD objects=%+v err=%v", objects, err)
	}
	if _, err := handleStagingLoad(ctx, env, stagingLoadInput{}); err == nil {
		t.Fatal("empty staging load accepted")
	}
}
