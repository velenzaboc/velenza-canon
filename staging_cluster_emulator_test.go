//go:build integration

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloud.google.com/go/spanner"
)

func TestStagingExtractAndExactCoordinateClusterLifecycle(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()

	if _, err := handleStagingCluster(ctx, env, stagingClusterInput{}); err == nil || !strings.Contains(err.Error(), "ingestion_run_id") {
		t.Fatalf("empty cluster input error=%v", err)
	}
	broken := *env
	broken.Config = env.Config
	broken.Config.Substrates = append([]SubstrateDescriptor(nil), env.Config.Substrates...)
	broken.Config.Substrates[0].ObjectTable = ""
	if _, err := handleStagingCluster(ctx, &broken, stagingClusterInput{IngestionRunID: "broken"}); err == nil || !strings.Contains(err.Error(), "object_table") {
		t.Fatalf("missing object table error=%v", err)
	}

	tmp := t.TempDir()
	invalidPath := filepath.Join(tmp, "invalid.ood.json")
	if err := os.WriteFile(invalidPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := handleStagingExtractOOD(ctx, env, stagingExtractOODInput{SourceFile: invalidPath}); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("invalid OOD error=%v", err)
	}
	emptyPath := filepath.Join(tmp, "empty.ood.json")
	if err := os.WriteFile(emptyPath, []byte(`{"id":"short_identifier","enabled":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := handleStagingExtractOOD(ctx, env, stagingExtractOODInput{SourceFile: emptyPath}); err == nil || !strings.Contains(err.Error(), "no claim-shaped") {
		t.Fatalf("claim-free OOD error=%v", err)
	}
	if _, err := handleStagingExtractOOD(ctx, env, stagingExtractOODInput{SourceFile: filepath.Join(tmp, "missing.ood.json")}); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("missing OOD error=%v", err)
	}
	if _, err := handleStagingExtractOOD(ctx, env, stagingExtractOODInput{}); err == nil || !strings.Contains(err.Error(), "source_file") {
		t.Fatalf("empty source path error=%v", err)
	}

	sourcePath := filepath.Join(tmp, "CLUSTER_LIFECYCLE_v1.ood.json")
	if err := os.WriteFile(sourcePath, []byte(`{"contract":{"description":"Every staged claim keeps its exact source coordinate through promotion and replay."}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := handleStagingExtractOOD(ctx, env, stagingExtractOODInput{
		SourceFile:     sourcePath,
		IngestionRunID: "cluster-first",
		NodeKind:       "section",
	})
	if err != nil || first.ConceptsLoaded != 1 || first.SpecPrefix != "cluster_lifecycle_v1" || first.SourceFile != sourcePath {
		t.Fatalf("first extraction=%+v err=%v", first, err)
	}
	clustered, err := handleStagingCluster(ctx, env, stagingClusterInput{IngestionRunID: first.IngestionRunID})
	if err != nil || clustered.ConceptsClustered != 1 || clustered.NoMatch != 1 || clustered.AutoMergeCandidates != 0 {
		t.Fatalf("first cluster=%+v err=%v", clustered, err)
	}
	integrationMarkStagingRunLintPass(ctx, t, stagingClientForTest(t, ctx, env), first.IngestionRunID)
	promoted, err := handleStagingPromote(ctx, env, stagingPromoteInput{IngestionRunID: first.IngestionRunID})
	if err != nil || promoted.ConceptsPromoted != 1 || promoted.GraphSnapshotID == "" {
		t.Fatalf("first promote=%+v err=%v", promoted, err)
	}

	second, err := handleStagingExtractOOD(ctx, env, stagingExtractOODInput{
		SourceFile:     sourcePath,
		IngestionRunID: "cluster-replay",
		NodeKind:       "section",
	})
	if err != nil || second.ConceptsLoaded != 1 {
		t.Fatalf("replay extraction=%+v err=%v", second, err)
	}
	replayed, err := handleStagingCluster(ctx, env, stagingClusterInput{
		IngestionRunID:       second.IngestionRunID,
		AutoMergeMaxDistance: 0.01,
		VerifyMaxDistance:    0.20,
	})
	if err != nil || replayed.ConceptsClustered != 1 || replayed.AutoMergeCandidates != 1 || replayed.NoMatch != 0 {
		t.Fatalf("replay cluster=%+v err=%v", replayed, err)
	}
}

func TestStagingLintPersistsStructuralFindingsAndBlocksPromotion(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	setupEmulatorDB(ctx, t)
	applyIntegrationDDL(ctx, t, integrationSourceCoordinateSchema)
	env := integrationOODEnv(t)
	defer env.Substrates.Close()

	loaded, err := handleStagingLoad(ctx, env, stagingLoadInput{
		IngestionRunID: "lint-structural-findings",
		SourceFile:     "lint-fixture.ood.json",
		Concepts: []stagingLoadConcept{
			{
				CanonicalName: "Bad Canonical Name",
				NodeKind:      "section",
				Contract: map[string]interface{}{
					"canonical_name":  "Bad Canonical Name",
					"definition_hash": strings.Repeat("a", 64),
				},
				Payload:    map[string]interface{}{"source_reference": "forbidden", "statement": "first duplicate"},
				SourcePath: "$.first",
			},
			{
				CanonicalName: "Bad Canonical Name",
				NodeKind:      "section",
				Contract:      map[string]interface{}{"canonical_name": "Bad Canonical Name"},
				Payload:       map[string]interface{}{"statement": "second duplicate"},
				SourcePath:    "$.second",
			},
		},
	})
	if err != nil || loaded.ConceptsLoaded != 2 {
		t.Fatalf("load invalid structural fixture=%+v err=%v", loaded, err)
	}
	linted, err := handleStagingLint(ctx, env, stagingLintInput{IngestionRunID: loaded.IngestionRunID})
	if err != nil {
		t.Fatalf("lint structural fixture: %v", err)
	}
	for rule, minimum := range map[string]int{
		"R7_canonical_name_pattern":  2,
		"R8_no_duplicate":            1,
		"R13_no_source_reference":    1,
		"R15_no_admission_artifacts": 1,
	} {
		if linted.FindingsByRule[rule] < minimum {
			t.Fatalf("%s findings=%d, want at least %d; all=%+v", rule, linted.FindingsByRule[rule], minimum, linted.Findings)
		}
	}
	if linted.ConceptsLinted != 2 || linted.EdgesLinted != 0 || len(linted.RulesRun) != 7 || len(linted.Findings) < 5 {
		t.Fatalf("lint result=%+v", linted)
	}
	rows, err := handleStagingList(ctx, env, stagingListInput{IngestionRunID: loaded.IngestionRunID, Limit: 10})
	if err != nil || len(rows.Rows) != 2 {
		t.Fatalf("list linted rows=%+v err=%v", rows, err)
	}
	for _, row := range rows.Rows {
		if row["lint_status"] != "fail" || row["pipeline_state"] != "linted" {
			t.Fatalf("structural lint was not persisted: %#v", row)
		}
	}
	if _, err := handleStagingPromote(ctx, env, stagingPromoteInput{IngestionRunID: loaded.IngestionRunID}); err == nil || !strings.Contains(err.Error(), "lint_status") {
		t.Fatalf("dirty promotion error=%v", err)
	}
}

func stagingClientForTest(t *testing.T, ctx context.Context, env *Env) *spanner.Client {
	t.Helper()
	client, err := stagingClient(ctx, env)
	if err != nil {
		t.Fatalf("staging client: %v", err)
	}
	return client
}
