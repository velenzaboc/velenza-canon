package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
)

// ood_substrate.go implements the schema_v2 (OODGraph 7-table) substrate
// write surface per OOD_GRAPH_PROTOCOL_v1 §6 + §8.materialization_pipeline.
// Phase 4 of the (C) substrate rebuild.
//
// All writes for one materialization run land in ONE Spanner
// ReadWriteTransaction via CommitMaterializationRun. The 19-stage pipeline
// in ceremony.go (Phase 5) prepares the batch in memory (stages 1-14),
// then hands the prepared MaterializationBatch to this layer for the
// substrate-tier stages (15-19: write_graph_rows → write_projection_artifacts
// → write_snapshot_row → seal_materialization_run).

// MaterializationBatch is the substrate-side input to CommitMaterializationRun.
// Carries everything stage-15 onward needs to write atomically. The Run
// must be in state="running" on entry; CommitMaterializationRun transitions
// it to state="sealed" inside the transaction.
//
// Ordering inside slices is the caller's responsibility (ceremony.go uses
// §8.deterministic_source_ordering). The substrate writes rows in slice
// order; Spanner uniqueness indexes catch any duplicate identity tuple.
type MaterializationBatch struct {
	// Run is the materialization run record. Run.State must be "running" on
	// entry; will be transitioned to "sealed" with FinishedAt + counts set.
	Run MaterializationRun

	// Snapshot is the candidate snapshot to seal. Snapshot.SnapshotState
	// must be "building" on entry; will be transitioned to "sealed" with
	// SealedAt + MaterializationRunID bound to Run.MaterializationRunID.
	Snapshot GraphSnapshot

	Objects             []GraphObject
	Symbols             []GraphSymbol
	Edges               []GraphEdge
	Violations          []Violation
	ProjectionArtifacts []ProjectionArtifact

	// ExternalVerificationReceipts are run-occurrence evidence, not semantic
	// GraphObject material. They are serialized into the snapshot/run
	// source_set so an unchanged-byte re-verification can renew freshness
	// without mutating the stable object row or changing source_set_hash.
	// Bodies are never carried here.
	ExternalVerificationReceipts []*stagedExternalVerificationReceipt

	// CompleteSnapshot is set only after the Spanner preparer has expanded a
	// delta into a complete immutable corpus snapshot. BaselineGraphVersion is
	// the newest eligible active-candidate version observed during that read;
	// CommitMaterializationRun rechecks it inside its RW transaction so a
	// concurrent refresh cannot be silently lost.
	CompleteSnapshot     bool
	BaselineGraphVersion int64

	StagingConceptPromotions []StagingConceptPromotion
	StagingEdgePromotions    []StagingEdgePromotion
}

type StagingConceptPromotion struct {
	IngestionRunID string
	StagingID      string
	GraphObjectID  string
}

type StagingEdgePromotion struct {
	IngestionRunID string
	StagingEdgeID  string
	GraphEdgeID    string
}

// ---------------- table-name plumbing ----------------

// requireOODGraphTables returns the 7 OODGraph table names from the
// descriptor or an error naming the missing field. Called by
// CommitMaterializationRun + CheckOODGraphSchema before any I/O.
func (a *SpannerSubstrateAdapter) requireOODGraphTables() (snapshotT, objectT, symbolT, edgeT, runT, violationT, projectionT string, err error) {
	if a.Descriptor.ReadOnly {
		return "", "", "", "", "", "", "", fmt.Errorf("substrate %q is read-only", a.Descriptor.ID)
	}
	missing := []string{}
	if a.Descriptor.SnapshotTable == "" {
		missing = append(missing, "snapshot_table")
	}
	if a.Descriptor.ObjectTable == "" {
		missing = append(missing, "object_table")
	}
	if a.Descriptor.SymbolTable == "" {
		missing = append(missing, "symbol_table")
	}
	if a.Descriptor.GraphEdgeTable == "" {
		missing = append(missing, "graph_edge_table")
	}
	if a.Descriptor.MaterializationRunTable == "" {
		missing = append(missing, "materialization_run_table")
	}
	if a.Descriptor.ViolationTable == "" {
		missing = append(missing, "violation_table")
	}
	if a.Descriptor.ProjectionArtifactTable == "" {
		missing = append(missing, "projection_artifact_table")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", "", "", "", "", "", "", fmt.Errorf("substrate %q: missing OODGraph table fields in config: %v", a.Descriptor.ID, missing)
	}
	return a.Descriptor.SnapshotTable,
		a.Descriptor.ObjectTable,
		a.Descriptor.SymbolTable,
		a.Descriptor.GraphEdgeTable,
		a.Descriptor.MaterializationRunTable,
		a.Descriptor.ViolationTable,
		a.Descriptor.ProjectionArtifactTable,
		nil
}

// CheckOODGraphSchema verifies the 7 OODGraph tables exist. Per
// §6.dedicated_storage_boundary the substrate's storage state lives only
// in OOD-Graph-owned tables; this check is the substrate-readiness probe
// before CommitMaterializationRun is invoked.
func (a *SpannerSubstrateAdapter) CheckOODGraphSchema(ctx context.Context) error {
	snapshotT, objectT, symbolT, edgeT, runT, violationT, projectionT, err := a.requireOODGraphTables()
	if err != nil {
		return err
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	wanted := []string{snapshotT, objectT, symbolT, edgeT, runT, violationT, projectionT}
	stmt := spanner.Statement{
		SQL: `SELECT table_name FROM information_schema.tables WHERE table_schema = '' AND table_name IN UNNEST(@names)`,
		Params: map[string]interface{}{
			"names": wanted,
		},
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	found := map[string]bool{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("check_ood_graph_schema query: %w", err)
		}
		var name string
		if err := row.Columns(&name); err != nil {
			return fmt.Errorf("check_ood_graph_schema decode: %w", err)
		}
		found[name] = true
	}
	missing := []string{}
	for _, w := range wanted {
		if !found[w] {
			missing = append(missing, w)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("%w: missing tables %v", ErrSchemaNotApplied, missing)
	}
	columnStmt := spanner.Statement{
		SQL: `SELECT column_name FROM information_schema.columns WHERE table_schema = '' AND table_name=@table AND column_name IN UNNEST(@names)`,
		Params: map[string]interface{}{
			"table": objectT,
			"names": []string{"api_element_role", "api_element_role_locator_manifest_hash"},
		},
	}
	columnIter := client.Single().Query(ctx, columnStmt)
	defer columnIter.Stop()
	foundColumns := map[string]bool{}
	for {
		row, err := columnIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("check_ood_graph_schema columns query: %w", err)
		}
		var name string
		if err := row.Columns(&name); err != nil {
			return fmt.Errorf("check_ood_graph_schema columns decode: %w", err)
		}
		foundColumns[name] = true
	}
	missingColumns := []string{}
	for _, name := range []string{"api_element_role", "api_element_role_locator_manifest_hash"} {
		if !foundColumns[name] {
			missingColumns = append(missingColumns, name)
		}
	}
	if len(missingColumns) > 0 {
		return fmt.Errorf("%w: OODGraphObjects missing required columns %v; apply bootstrap/migrations/003_ood_graph_api_role_locator.sql", ErrSchemaNotApplied, missingColumns)
	}
	return nil
}

// ---------------- run lifecycle ----------------

// OpenMaterializationRun performs stage 1 of the §8 pipeline,
// open_materialization_run: it INSERTS the OODGraphMaterializationRuns row
// at state="running", with target_graph_snapshot_id NULL and finished_at
// NULL, BEFORE any parsing, validation or row construction happens.
//
// Why this exists as its own committed write rather than a field set on the
// in-memory batch: until now the run row was inserted only at seal, so a
// run that crashed, was rejected, or was abandoned left NO ROW AT ALL. That
// makes two spec clauses unsatisfiable rather than merely unimplemented —
// §8.idempotency_and_replay_safety.abandoned_run_rule ("Failed or abandoned
// runs remain audit-only state in OODGraphMaterializationRuns") and
// §9.active_snapshot_selection.failed_and_abandoned_run_rule both quantify
// over failed/abandoned rows that could never exist. Combined with the
// absent violation producer, the substrate had no record of anything it had
// ever refused: every rejection was silent.
//
// The insert commits in its OWN transaction, deliberately outside the
// batch's atomic write. §8.snapshot_production_contract's
// partial_projection_allowed=false constrains the GRAPH ROWS — objects,
// symbols, edges, projections, violations and the snapshot must all land or
// none of them — and an open run row is not graph state, it is the audit
// record that the attempt happened. Enrolling it in the same transaction
// would roll it back on failure and reinstate exactly the blindness this
// fixes.
//
// §8.open_materialization_run requires input_source_set_hash and
// input_source_set to be present at open, so the caller must have computed
// the real source-set hash BEFORE calling. That ordering is what makes the
// hash an INPUT to the run rather than a description of its output.
func (a *SpannerSubstrateAdapter) OpenMaterializationRun(ctx context.Context, run MaterializationRun) error {
	_, _, _, _, runT, _, _, err := a.requireOODGraphTables()
	if err != nil {
		return err
	}
	if run.State != "running" {
		return fmt.Errorf("OpenMaterializationRun: run.State=%q, expected %q per §8.open_materialization_run.initial_state", run.State, "running")
	}
	if run.MaterializationRunID == "" || run.OrganizationID == "" {
		return fmt.Errorf("OpenMaterializationRun: organization_id and materialization_run_id required")
	}
	if run.InputSourceSetHash == "" || run.InputSourceSet == nil {
		return fmt.Errorf("OpenMaterializationRun: input_source_set_hash and input_source_set required per §8.open_materialization_run")
	}
	profile, _ := run.InputSourceSet["materialization_profile_version"].(string)
	if profile != MaterializationProfileVersion {
		if !a.allowLegacyMaterializationProfilesForTesting || (profile != "ood_graph_protocol_v1/materialization/5" && profile != "ood_graph_protocol_v1/materialization/6") {
			return fmt.Errorf("OpenMaterializationRun: materialization_profile_version=%q is not writable; want %q", profile, MaterializationProfileVersion)
		}
	} else {
		if err := ValidateMaterializationSourceSet(run.OrganizationID, run.InputSourceSetHash, run.InputSourceSet); err != nil {
			return fmt.Errorf("OpenMaterializationRun: %w", err)
		}
	}
	// target_graph_snapshot_id stays NULL until seal per
	// §8.open_materialization_run.target_graph_snapshot_id_initially_nullable.
	run.TargetGraphSnapshotID = ""
	run.FinishedAt = nil
	client, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		return writeMaterializationRunInTx(ctx, tx, runT, run)
	})
	if err != nil {
		return fmt.Errorf("open materialization run %q: %w", run.MaterializationRunID, err)
	}
	return nil
}

// FailMaterializationRun transitions an open run row to the terminal
// failure state of §8.materialization_pipeline.seal_materialization_run
// (failure_state "failed"), leaving target_graph_snapshot_id NULL.
//
// The failed row is audit evidence and nothing more:
// §9.active_snapshot_selection.failed_and_abandoned_run_rule makes it
// unselectable as active or historical traversal state, and
// §8.seal_materialization_run.failed_run_snapshot_visibility states that no
// failed run is selectable as an active graph snapshot. Because the graph
// rows never committed, there is no snapshot pointing at this run — the
// mismatch case that rule describes cannot arise from this path.
//
// Idempotent by construction: the UPDATE is a no-op once state is already
// terminal, so a caller may invoke it on an error path that also fires
// during retry without corrupting the record. It never rewrites a run that
// already sealed successfully.
func (a *SpannerSubstrateAdapter) FailMaterializationRun(ctx context.Context, orgID, runID string) error {
	_, _, _, _, runT, _, _, err := a.requireOODGraphTables()
	if err != nil {
		return err
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return err
	}
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		stmt := spanner.Statement{
			SQL: fmt.Sprintf(`UPDATE %s
				SET state = 'failed',
				    finished_at = @finished_at,
				    updated_at = PENDING_COMMIT_TIMESTAMP()
				WHERE organization_id = @org
				  AND materialization_run_id = @run
				  AND state = 'running'`, runT),
			Params: map[string]interface{}{
				"finished_at": time.Now().UTC(),
				"org":         orgID,
				"run":         runID,
			},
		}
		_, uErr := tx.Update(ctx, stmt)
		return uErr
	})
	if err != nil {
		return fmt.Errorf("fail materialization run %q: %w", runID, err)
	}
	return nil
}

// ---------------- CommitMaterializationRun ----------------

// CommitMaterializationRun opens one Spanner ReadWriteTransaction and
// writes the entire batch atomically:
//
//  1. write_graph_rows: OODGraphObjects + OODGraphSymbols + OODGraphEdges
//     (idempotent upserts inside the new graph_snapshot_id; identity tuple
//     uniqueness enforced by the UNIQUE INDEX cluster from §6)
//  2. write_projection_artifacts: OODGraphProjectionArtifacts
//  3. write_violations: OODGraphViolations (rejected facts; never
//     authoritative closure members)
//  4. write_snapshot_row: OODGraphSnapshots with snapshot_state=sealed,
//     materialization_run_id bound, sealed_at=commit_timestamp
//  5. seal_materialization_run: OODGraphMaterializationRuns transitioned
//     to state=sealed with finished_at + counts set
//
// On any write failure the entire transaction rolls back; no row reaches
// the substrate per §8.snapshot_production_contract.partial_projection_allowed=false.
//
// The caller (Phase 5 ceremony) is responsible for stages 1-14 of the
// pipeline: parsing, R1-R4 enforcement, identity derivation, class/label
// validation, endpoint resolution, reciprocity validation, retrieval
// metadata preparation. By the time the batch lands here, every row is
// fully formed.
func (a *SpannerSubstrateAdapter) CommitMaterializationRun(ctx context.Context, batch MaterializationBatch) error {
	snapshotT, objectT, symbolT, edgeT, runT, violationT, projectionT, err := a.requireOODGraphTables()
	if err != nil {
		return err
	}
	if batch.Run.State != "running" {
		return fmt.Errorf("CommitMaterializationRun: batch.Run.State=%q, expected %q", batch.Run.State, "running")
	}
	if batch.Snapshot.SnapshotState != "building" {
		return fmt.Errorf("CommitMaterializationRun: batch.Snapshot.SnapshotState=%q, expected %q", batch.Snapshot.SnapshotState, "building")
	}
	if batch.Snapshot.OrganizationID != batch.Run.OrganizationID {
		return fmt.Errorf("CommitMaterializationRun: snapshot.organization_id=%q != run.organization_id=%q", batch.Snapshot.OrganizationID, batch.Run.OrganizationID)
	}
	profile, _ := batch.Run.InputSourceSet["materialization_profile_version"].(string)
	if profile != MaterializationProfileVersion {
		if !a.allowLegacyMaterializationProfilesForTesting || (profile != "ood_graph_protocol_v1/materialization/5" && profile != "ood_graph_protocol_v1/materialization/6") {
			return fmt.Errorf("CommitMaterializationRun: materialization_profile_version=%q is not writable; want %q", profile, MaterializationProfileVersion)
		}
	}
	if batch.CompleteSnapshot && profile != MaterializationProfileVersion {
		return fmt.Errorf("CommitMaterializationRun: complete snapshot requires materialization profile %q", MaterializationProfileVersion)
	}
	if profile == MaterializationProfileVersion {
		if err := ValidateMaterializationSourceSet(batch.Run.OrganizationID, batch.Run.InputSourceSetHash, batch.Run.InputSourceSet); err != nil {
			return fmt.Errorf("CommitMaterializationRun run source set: %w", err)
		}
		if err := ValidateMaterializationSourceSet(batch.Snapshot.OrganizationID, batch.Snapshot.SourceSetHash, batch.Snapshot.SourceSet); err != nil {
			return fmt.Errorf("CommitMaterializationRun snapshot source set: %w", err)
		}
		runSet, err := canonicalJSON(batch.Run.InputSourceSet)
		if err != nil {
			return err
		}
		snapshotSet, err := canonicalJSON(batch.Snapshot.SourceSet)
		if err != nil {
			return err
		}
		if batch.Run.InputSourceSetHash != batch.Snapshot.SourceSetHash || string(runSet) != string(snapshotSet) {
			return fmt.Errorf("CommitMaterializationRun run and snapshot source-set evidence differ")
		}
	}
	if err := validateCompleteExternalBootstrapPublicationEnvelope(batch); err != nil {
		return fmt.Errorf("CommitMaterializationRun publication envelope: %w", err)
	}
	client, err := a.getClient(ctx)
	if err != nil {
		return err
	}

	var replayFailure error
	_, err = client.ReadWriteTransaction(ctx, func(ctx context.Context, tx *spanner.ReadWriteTransaction) error {
		replayFailure = nil
		_, replayErr := verifyReplayOutputsInTx(ctx, tx, snapshotT, objectT, symbolT, edgeT, runT, violationT, projectionT, batch)
		if replayErr != nil {
			if !errors.Is(replayErr, ErrOODGraphMaterializationReplayNonDeterministic) {
				return replayErr
			}
			if err := recordReplayFailureInTx(ctx, tx, runT, violationT, batch, replayErr); err != nil {
				return err
			}
			replayFailure = replayErr
			return nil
		}
		if batch.CompleteSnapshot {
			// Fence the complete carry-forward set against EVERY graph-version
			// mutation for the organization, not merely eligible active-candidate
			// snapshots. A lifecycle/retirement writer consumes the same monotonic
			// graph_version stream; allowing it past this fence could otherwise
			// resurrect a row whose status changed after preparation. Spanner's RW
			// read records a conflict range so a concurrent writer forces retry.
			observed, err := latestOrganizationGraphVersion(ctx, tx, snapshotT, batch.Run.OrganizationID)
			if err != nil {
				return err
			}
			if observed != batch.BaselineGraphVersion {
				return fmt.Errorf("complete snapshot organization-wide baseline advanced from graph_version=%d to %d; retry preparation so no concurrent graph or lifecycle mutation is lost", batch.BaselineGraphVersion, observed)
			}
		}
		// Stage 15: write_graph_rows
		for i, o := range batch.Objects {
			if err := writeGraphObjectInTx(ctx, tx, objectT, o); err != nil {
				return fmt.Errorf("write object[%d] (graph_object_id=%q): %w", i, o.GraphObjectID, err)
			}
		}
		for i, s := range batch.Symbols {
			if err := writeGraphSymbolInTx(ctx, tx, symbolT, s); err != nil {
				return fmt.Errorf("write symbol[%d] (symbol_id=%q): %w", i, s.SymbolID, err)
			}
		}
		for i, e := range batch.Edges {
			if err := writeGraphEdgeInTx(ctx, tx, edgeT, e); err != nil {
				return fmt.Errorf("write edge[%d] (graph_edge_id=%q): %w", i, e.GraphEdgeID, err)
			}
		}

		// Stage 16: write_projection_artifacts
		for i, p := range batch.ProjectionArtifacts {
			if err := writeProjectionArtifactInTx(ctx, tx, projectionT, p); err != nil {
				return fmt.Errorf("write projection_artifact[%d] (id=%q): %w", i, p.ProjectionArtifactID, err)
			}
		}

		// Write violations (§8.violation_emission — graph-owned coordinates only,
		// never sibling payloads). Violations may exist even on a successful
		// seal (severity=minor/info); only blocker-severity rows should have
		// prevented the batch from reaching this stage.
		for i, v := range batch.Violations {
			if err := writeViolationInTx(ctx, tx, violationT, v); err != nil {
				return fmt.Errorf("write violation[%d] (id=%q): %w", i, v.ViolationID, err)
			}
		}

		// Staging is a work buffer, but promotion completion is part of the
		// same durable fact as graph sealing. Updating the staging receipt in
		// this transaction prevents a committed graph snapshot followed by a
		// failed "mark promoted" call from being retried into a duplicate
		// snapshot.
		if err := writeStagingPromotionsInTx(ctx, tx, batch); err != nil {
			return err
		}

		// Stage 18: write_snapshot_row — sealed.
		//
		// graph_version is assigned HERE, not by the caller, and only after
		// every row write above has been buffered without error. That is
		// literally what
		// §8.materialization_pipeline.write_snapshot_row.graph_version_assignment
		// asks for: "monotonic per organization_id AFTER all row validation
		// succeeds". Any value the caller supplied is discarded — a caller
		// cannot know the next version without racing, so accepting one
		// would only make the race look sanctioned.
		snapshot := batch.Snapshot
		nextVersion, err := nextGraphVersionInTx(ctx, tx, snapshotT, batch.Run.OrganizationID)
		if err != nil {
			return err
		}
		snapshot.GraphVersion = nextVersion
		snapshot.SnapshotState = "sealed"
		snapshot.MaterializationRunID = batch.Run.MaterializationRunID
		if snapshot.SealedAt == nil {
			sealedAt := time.Now().UTC()
			snapshot.SealedAt = &sealedAt
		}
		if err := writeGraphSnapshotInTx(ctx, tx, snapshotT, snapshot); err != nil {
			return fmt.Errorf("write snapshot (graph_snapshot_id=%q): %w", snapshot.GraphSnapshotID, err)
		}

		// Stage 19: seal_materialization_run. UPDATEs the row
		// OpenMaterializationRun already inserted, so started_at and
		// created_at survive the seal. finished_at is set explicitly
		// because §8.seal_materialization_run lists it in
		// successful_sealed_run_evidence_required and
		// §9.active_snapshot_selection.eligible_snapshot_predicate gates on
		// finished_at_required_for_selected_run.
		run := batch.Run
		run.State = "sealed"
		run.TargetGraphSnapshotID = snapshot.GraphSnapshotID
		finishedAt := time.Now().UTC()
		run.FinishedAt = &finishedAt
		run.ObjectCount = int64(len(batch.Objects))
		run.SymbolCount = int64(len(batch.Symbols))
		run.EdgeCount = int64(len(batch.Edges))
		run.ViolationCount = int64(len(batch.Violations))
		if err := sealMaterializationRunInTx(ctx, tx, runT, run); err != nil {
			return fmt.Errorf("seal materialization_run (id=%q): %w", run.MaterializationRunID, err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCeremonyAtomicityBroken, err)
	}
	if replayFailure != nil {
		return replayFailure
	}
	return nil
}

func writeStagingPromotionsInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, batch MaterializationBatch) error {
	for i, promotion := range batch.StagingConceptPromotions {
		stmt := stagingConceptPromotionStatement(batch.Run.OrganizationID, promotion)
		count, err := tx.Update(ctx, stmt)
		if err != nil {
			return fmt.Errorf("promote staging concept[%d] %q: %w", i, promotion.StagingID, err)
		}
		if count != 1 {
			return fmt.Errorf("promote staging concept[%d] %q affected %d rows, want one clean+linted row", i, promotion.StagingID, count)
		}
	}
	for i, promotion := range batch.StagingEdgePromotions {
		stmt := stagingEdgePromotionStatement(batch.Run.OrganizationID, promotion)
		count, err := tx.Update(ctx, stmt)
		if err != nil {
			return fmt.Errorf("promote staging edge[%d] %q: %w", i, promotion.StagingEdgeID, err)
		}
		if count != 1 {
			return fmt.Errorf("promote staging edge[%d] %q affected %d rows, want one clean+linted row", i, promotion.StagingEdgeID, count)
		}
	}
	return nil
}

func stagingConceptPromotionStatement(organizationID string, promotion StagingConceptPromotion) spanner.Statement {
	return spanner.Statement{
		SQL: `UPDATE staging_concepts
SET pipeline_state='promoted', promoted_graph_object_id=@graph_object_id,
    updated_at=PENDING_COMMIT_TIMESTAMP()
WHERE organization_id=@org AND ingestion_run_id=@ingestion_run
	  AND staging_id=@staging_id AND pipeline_state='linted' AND lint_status='pass'`,
		Params: map[string]interface{}{
			"graph_object_id": promotion.GraphObjectID,
			"org":             organizationID,
			"ingestion_run":   promotion.IngestionRunID,
			"staging_id":      promotion.StagingID,
		},
	}
}

func stagingEdgePromotionStatement(organizationID string, promotion StagingEdgePromotion) spanner.Statement {
	return spanner.Statement{
		SQL: `UPDATE staging_edges
SET pipeline_state='promoted', promoted_graph_edge_id=@graph_edge_id,
    updated_at=PENDING_COMMIT_TIMESTAMP()
WHERE organization_id=@org AND ingestion_run_id=@ingestion_run
	  AND staging_edge_id=@staging_edge_id AND pipeline_state='linted' AND lint_status='pass'`,
		Params: map[string]interface{}{
			"graph_edge_id":   promotion.GraphEdgeID,
			"org":             organizationID,
			"ingestion_run":   promotion.IngestionRunID,
			"staging_edge_id": promotion.StagingEdgeID,
		},
	}
}

func recordReplayFailureInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, runT, violationT string, batch MaterializationBatch, replayErr error) error {
	finishedAt := time.Now().UTC()
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(`UPDATE %s
SET state='failed', finished_at=@finished_at, updated_at=PENDING_COMMIT_TIMESTAMP()
WHERE organization_id=@org AND materialization_run_id=@run AND state='running'`, runT),
		Params: map[string]interface{}{"finished_at": finishedAt, "org": batch.Run.OrganizationID, "run": batch.Run.MaterializationRunID},
	}
	count, err := tx.Update(ctx, stmt)
	if err != nil {
		return fmt.Errorf("record replay failure run state: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("record replay failure affected %d run rows, want 1", count)
	}
	violation := NewViolation(batch.Run.OrganizationID, batch.Run.MaterializationRunID, "", ViolationReplayNonDeterministic, ViolationCoordinate{
		RejectedValueClass:      "materialization_replay_output",
		IdentityTupleFieldNames: []string{"graph_object_id", "symbol_id", "graph_edge_id", "projection_hash", "violation_coordinate"},
		RedactedReason:          "same_input_key_output_mismatch",
	})
	if err := writeViolationInTx(ctx, tx, violationT, violation); err != nil {
		return fmt.Errorf("record replay nondeterminism violation: %w", err)
	}
	_ = replayErr // the durable row carries the registered redacted classification
	return nil
}

func latestEligibleActiveCandidateVersionInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, snapshotT, runT, orgID string) (int64, error) {
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(`SELECT COALESCE(MAX(s.graph_version), 0)
FROM %s s JOIN %s r
  ON r.organization_id=s.organization_id
 AND r.materialization_run_id=s.materialization_run_id
WHERE s.organization_id=@org
  AND s.snapshot_kind='active_candidate'
  AND s.snapshot_state='sealed'
  AND s.status='active'
  AND s.sealed_at IS NOT NULL
  AND r.target_graph_snapshot_id=s.graph_snapshot_id
  AND r.state='sealed'
  AND r.input_source_set_hash=s.source_set_hash
  AND r.finished_at IS NOT NULL`, snapshotT, runT),
		Params: map[string]interface{}{"org": orgID},
	}
	iter := tx.Query(ctx, stmt)
	defer iter.Stop()
	row, err := iter.Next()
	if err != nil {
		return 0, fmt.Errorf("read complete-snapshot baseline graph version: %w", err)
	}
	var version int64
	if err := row.Columns(&version); err != nil {
		return 0, fmt.Errorf("decode complete-snapshot baseline graph version: %w", err)
	}
	return version, nil
}

func newerEligibleActiveCandidateSnapshotIDsInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, snapshotT, runT, orgID string, afterVersion int64) ([]string, error) {
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(`SELECT s.graph_snapshot_id
FROM %s s JOIN %s r
  ON r.organization_id=s.organization_id
 AND r.materialization_run_id=s.materialization_run_id
WHERE s.organization_id=@org
  AND s.graph_version>@after_version
  AND s.snapshot_kind='active_candidate'
  AND s.snapshot_state='sealed'
  AND s.status='active'
  AND s.sealed_at IS NOT NULL
  AND r.target_graph_snapshot_id=s.graph_snapshot_id
  AND r.state='sealed'
  AND r.input_source_set_hash=s.source_set_hash
  AND r.finished_at IS NOT NULL
ORDER BY s.graph_version, s.graph_snapshot_id`, snapshotT, runT),
		Params: map[string]interface{}{"org": orgID, "after_version": afterVersion},
	}
	iter := tx.Query(ctx, stmt)
	defer iter.Stop()
	var out []string
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read newer complete-snapshot baselines: %w", err)
		}
		var id string
		if err := row.Columns(&id); err != nil {
			return nil, fmt.Errorf("decode newer complete-snapshot baseline: %w", err)
		}
		out = append(out, id)
	}
	return out, nil
}

// ---------------- per-table write helpers ----------------

// writeGraphObjectInTx inserts one OODGraphObjects row. Identity tuple
// uniqueness is enforced by the OODGraphObjectsByIdentityTuple and
// OODGraphObjectsByAddress UNIQUE INDEXes — any duplicate raises a Spanner
// error that fails the enclosing ReadWriteTransaction.
func writeGraphObjectInTx(_ context.Context, tx *spanner.ReadWriteTransaction, table string, o GraphObject) error {
	cols := []string{
		"organization_id", "graph_snapshot_id", "graph_object_id",
		"object_class",
		"api_element_role", "api_element_role_locator_manifest_hash",
		"source_authority_id", "source_artifact_class", "source_ref_kind",
		"source_stable_reference", "version_coordinate", "section_path",
		"graph_address",
		"source_content_hash", "source_content_hash_owner",
		"materialization_run_id", "projection_role",
		"validation_state", "status", "visibility_scope",
		"search_text", "search_payload",
		"embedding", "embedding_model",
		"created_at", "updated_at",
	}
	var embeddingVal interface{} = []float32(nil)
	if len(o.Embedding) > 0 {
		embeddingVal = o.Embedding
	}
	searchPayload := spanner.NullJSON{Valid: false}
	if o.SearchPayload != nil {
		searchPayload = spanner.NullJSON{Value: o.SearchPayload, Valid: true}
	}
	vals := []interface{}{
		o.OrganizationID, o.GraphSnapshotID, o.GraphObjectID,
		o.ObjectClass,
		nullableString(o.APIElementRole), nullableString(o.APIElementRoleLocatorManifestHash),
		o.SourceAuthorityID, o.SourceArtifactClass, o.SourceRefKind,
		o.SourceStableReference, o.VersionCoordinate, o.SectionPath,
		o.GraphAddress,
		nullableString(o.SourceContentHash), nullableString(o.SourceContentHashOwner),
		o.MaterializationRunID, o.ProjectionRole,
		o.ValidationState, o.Status, o.VisibilityScope,
		nullableString(o.SearchText), searchPayload,
		embeddingVal, o.EmbeddingModel,
		spanner.CommitTimestamp, spanner.CommitTimestamp,
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(table, cols, vals)})
}

// writeGraphSymbolInTx inserts one OODGraphSymbols row.
func writeGraphSymbolInTx(_ context.Context, tx *spanner.ReadWriteTransaction, table string, s GraphSymbol) error {
	cols := []string{
		"organization_id", "graph_snapshot_id", "symbol_id", "graph_object_id",
		"object_class", "symbol_kind", "symbol_name",
		"source_authority_id", "source_stable_reference",
		"version_coordinate", "section_path", "graph_address",
		"materialization_run_id",
		"validation_state", "status", "visibility_scope",
		"search_text", "search_payload",
		"embedding", "embedding_model",
		"created_at", "updated_at",
	}
	var embeddingVal interface{} = []float32(nil)
	if len(s.Embedding) > 0 {
		embeddingVal = s.Embedding
	}
	searchPayload := spanner.NullJSON{Valid: false}
	if s.SearchPayload != nil {
		searchPayload = spanner.NullJSON{Value: s.SearchPayload, Valid: true}
	}
	vals := []interface{}{
		s.OrganizationID, s.GraphSnapshotID, s.SymbolID, s.GraphObjectID,
		s.ObjectClass, s.SymbolKind, s.SymbolName,
		s.SourceAuthorityID, s.SourceStableReference,
		s.VersionCoordinate, s.SectionPath, s.GraphAddress,
		s.MaterializationRunID,
		s.ValidationState, s.Status, s.VisibilityScope,
		nullableString(s.SearchText), searchPayload,
		embeddingVal, s.EmbeddingModel,
		spanner.CommitTimestamp, spanner.CommitTimestamp,
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(table, cols, vals)})
}

// writeGraphEdgeInTx inserts one OODGraphEdges row. Endpoint ids MUST
// already resolve to OODGraphObjects.graph_object_id rows in the same
// snapshot per §4.endpoint_model.endpoint_ref_must_resolve_to.
func writeGraphEdgeInTx(_ context.Context, tx *spanner.ReadWriteTransaction, table string, e GraphEdge) error {
	cols := []string{
		"organization_id", "graph_snapshot_id", "graph_edge_id",
		"source_endpoint_kind", "source_endpoint_id", "source_endpoint_class",
		"target_endpoint_kind", "target_endpoint_id", "target_endpoint_class",
		"edge_label", "edge_family",
		"source_version_coordinate", "target_version_coordinate",
		"authoring_source_path",
		"source_authority_id", "source_stable_reference", "source_content_hash",
		"valid_from", "valid_until",
		"diagnostic_only", "reciprocity_state", "inverse_edge_id",
		"edge_confidence",
		"materialization_run_id",
		"validation_state", "status", "visibility_scope",
		"search_text", "search_payload",
		"embedding", "embedding_model",
		"created_at", "updated_at",
	}
	var embeddingVal interface{} = []float32(nil)
	if len(e.Embedding) > 0 {
		embeddingVal = e.Embedding
	}
	searchPayload := spanner.NullJSON{Valid: false}
	if e.SearchPayload != nil {
		searchPayload = spanner.NullJSON{Value: e.SearchPayload, Valid: true}
	}
	// valid_from / valid_until are nullable TIMESTAMPs
	// (§9.temporal_state_model.valid_from / .valid_until, the graph-owned
	// edge validity bounds). Written as TYPED nulls: these lines have never
	// executed against a real Spanner, because OODGraphEdges holds zero
	// rows, so the bare untyped nil they previously carried was untested on
	// a path this change is about to start exercising.
	validFrom := nullableTime(e.ValidFrom)
	validUntil := nullableTime(e.ValidUntil)
	var edgeConfidence interface{} = nil
	if e.EdgeConfidence != nil {
		edgeConfidence = *e.EdgeConfidence
	}
	vals := []interface{}{
		e.OrganizationID, e.GraphSnapshotID, e.GraphEdgeID,
		e.SourceEndpointKind, e.SourceEndpointID, e.SourceEndpointClass,
		e.TargetEndpointKind, e.TargetEndpointID, e.TargetEndpointClass,
		e.EdgeLabel, e.EdgeFamily,
		e.SourceVersionCoordinate, e.TargetVersionCoordinate,
		e.AuthoringSourcePath,
		e.SourceAuthorityID, e.SourceStableReference, nullableString(e.SourceContentHash),
		validFrom, validUntil,
		e.DiagnosticOnly, e.ReciprocityState, nullableString(e.InverseEdgeID),
		edgeConfidence,
		e.MaterializationRunID,
		e.ValidationState, e.Status, e.VisibilityScope,
		nullableString(e.SearchText), searchPayload,
		embeddingVal, e.EmbeddingModel,
		spanner.CommitTimestamp, spanner.CommitTimestamp,
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(table, cols, vals)})
}

// writeGraphSnapshotInTx inserts one OODGraphSnapshots row. Called only
// once per CommitMaterializationRun with snapshot_state="sealed".
func writeGraphSnapshotInTx(_ context.Context, tx *spanner.ReadWriteTransaction, table string, s GraphSnapshot) error {
	cols := []string{
		"organization_id", "graph_snapshot_id", "graph_version",
		"snapshot_kind", "source_set_hash", "source_set",
		"materialization_run_id",
		"snapshot_state", "status", "visibility_scope",
		"sealed_at",
		"created_at", "updated_at",
	}
	sourceSet := spanner.NullJSON{Valid: false}
	if s.SourceSet != nil {
		sourceSet = spanner.NullJSON{Value: s.SourceSet, Valid: true}
	}
	// sealed_at is a plain TIMESTAMP column per §6.table_surfaces (no
	// allow_commit_timestamp option). Use the caller-provided value or
	// the current wall-clock time as a deterministic stand-in.
	var sealedAt interface{} = time.Now().UTC()
	if s.SealedAt != nil {
		sealedAt = *s.SealedAt
	}
	vals := []interface{}{
		s.OrganizationID, s.GraphSnapshotID, s.GraphVersion,
		s.SnapshotKind, s.SourceSetHash, sourceSet,
		nullableString(s.MaterializationRunID),
		s.SnapshotState, s.Status, s.VisibilityScope,
		sealedAt,
		spanner.CommitTimestamp, spanner.CommitTimestamp,
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(table, cols, vals)})
}

// nextGraphVersionInTx returns the next graph_version for an organization:
// MAX(graph_version) + 1 over that organization's snapshot rows, read
// INSIDE the caller's ReadWriteTransaction.
//
// Implements §8.materialization_pipeline.write_snapshot_row
// .graph_version_assignment ("monotonic per organization_id after all row
// validation succeeds") and
// §9.temporal_state_model.graph_version (monotonicity_scope
// [organization_id], uniqueness_scope [organization_id, graph_version]).
//
// Why the read must be inside the transaction: the aggregate takes a
// transactional lock over the organization's version range, so two
// concurrent runs cannot both observe the same MAX. Spanner aborts and
// retries the loser, which then observes the winner's row and takes the
// next version. A version computed OUTSIDE the transaction — or from a wall
// clock, as handlers.go did — is unserialised and races the UNIQUE
// OODGraphSnapshotsByVersion (organization_id, graph_version) index.
//
// The scan is org-scoped and NOT snapshot_kind-scoped, matching
// §9.active_snapshot_selection.uniqueness_rule: "At most one
// OODGraphSnapshots row may exist for the same organization_id and
// graph_version; active selection applies snapshot_kind only as a filter
// over that organization-scoped version stream." Partitioning the counter
// per kind would let an archive_audit snapshot and an active_candidate
// snapshot collide on one version.
func nextGraphVersionInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, snapshotTable, orgID string) (int64, error) {
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(
			`SELECT COALESCE(MAX(graph_version), 0) AS max_version FROM %s WHERE organization_id = @org`,
			snapshotTable),
		Params: map[string]interface{}{"org": orgID},
	}
	iter := tx.Query(ctx, stmt)
	defer iter.Stop()
	row, err := iter.Next()
	if err == iterator.Done {
		// An aggregate over an empty table still yields one row, so this
		// branch is unreachable in practice; treated as "no snapshots yet"
		// rather than as an error so a future non-aggregate rewrite cannot
		// silently mint version 0.
		return 1, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read max graph_version for org %q: %w", orgID, err)
	}
	var maxVersion int64
	if err := row.Columns(&maxVersion); err != nil {
		return 0, fmt.Errorf("decode max graph_version: %w", err)
	}
	return maxVersion + 1, nil
}

// sealMaterializationRunInTx transitions an OPEN run row (state="running",
// written by OpenMaterializationRun) to its terminal state, writing only
// the columns stage 19 owns.
//
// This is an UPDATE, not an upsert, on purpose. The row already exists
// because §8.materialization_pipeline.open_materialization_run requires it
// to be inserted when the run opens; rewriting the whole row at seal would
// clobber created_at and started_at, destroying the very evidence
// §9.audit_and_replay_evidence needs to distinguish a long run from a
// re-run. RowsAffected is asserted so a seal against a run row that was
// never opened fails loudly instead of silently sealing nothing.
func sealMaterializationRunInTx(ctx context.Context, tx *spanner.ReadWriteTransaction, table string, r MaterializationRun) error {
	var finishedAt interface{} = time.Now().UTC()
	if r.FinishedAt != nil {
		finishedAt = *r.FinishedAt
	}
	stmt := spanner.Statement{
		SQL: fmt.Sprintf(`UPDATE %s
			SET target_graph_snapshot_id = @snapshot,
			    state = @state,
			    finished_at = @finished_at,
			    object_count = @object_count,
			    symbol_count = @symbol_count,
			    edge_count = @edge_count,
			    violation_count = @violation_count,
			    updated_at = PENDING_COMMIT_TIMESTAMP()
			WHERE organization_id = @org
			  AND materialization_run_id = @run
			  AND state = 'running'`, table),
		Params: map[string]interface{}{
			"snapshot":        nullableString(r.TargetGraphSnapshotID),
			"state":           r.State,
			"finished_at":     finishedAt,
			"object_count":    r.ObjectCount,
			"symbol_count":    r.SymbolCount,
			"edge_count":      r.EdgeCount,
			"violation_count": r.ViolationCount,
			"org":             r.OrganizationID,
			"run":             r.MaterializationRunID,
		},
	}
	n, err := tx.Update(ctx, stmt)
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("%w: materialization_run_id=%q seal affected %d rows; exactly one state=running row is required (missing and terminal rows cannot be sealed)",
			ErrCeremonyAtomicityBroken, r.MaterializationRunID, n)
	}
	return nil
}

// writeMaterializationRunInTx inserts the OODGraphMaterializationRuns row
// for this run.
//
// finished_at is written as SQL NULL when r.FinishedAt is nil. It used to
// default to the current wall clock, which made every row — including a run
// that had only just opened — look finished. §8's
// open_materialization_run inserts the row at state="running" with no
// terminal evidence yet, and
// §9.active_snapshot_selection.eligible_snapshot_predicate gates on
// finished_at_required_for_selected_run, so a non-null finished_at on an
// open run would make an unfinished run selectable.
func writeMaterializationRunInTx(_ context.Context, tx *spanner.ReadWriteTransaction, table string, r MaterializationRun) error {
	cols := []string{
		"organization_id", "materialization_run_id",
		"target_graph_snapshot_id", "run_kind",
		"input_source_set_hash", "input_source_set",
		"state", "started_at", "finished_at",
		"object_count", "symbol_count", "edge_count", "violation_count",
		"status", "visibility_scope",
		"created_at", "updated_at",
	}
	inputSourceSet := spanner.NullJSON{Valid: false}
	if r.InputSourceSet != nil {
		inputSourceSet = spanner.NullJSON{Value: r.InputSourceSet, Valid: true}
	}
	// finished_at is a plain nullable TIMESTAMP per §6.table_surfaces (no
	// allow_commit_timestamp option). nil means the run has not finished —
	// written as a TYPED null, matching the nullableString/NullJSON
	// convention every other nullable column in this file follows.
	finishedAt := nullableTime(r.FinishedAt)
	vals := []interface{}{
		r.OrganizationID, r.MaterializationRunID,
		nullableString(r.TargetGraphSnapshotID), r.RunKind,
		r.InputSourceSetHash, inputSourceSet,
		r.State, r.StartedAt, finishedAt,
		r.ObjectCount, r.SymbolCount, r.EdgeCount, r.ViolationCount,
		r.Status, r.VisibilityScope,
		spanner.CommitTimestamp, spanner.CommitTimestamp,
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(table, cols, vals)})
}

// writeViolationInTx inserts one OODGraphViolations row. Evidence carries
// graph-owned coordinates only — caller is responsible for redacting any
// sibling payload per §6.encryption_posture.payload_boundary.
func writeViolationInTx(_ context.Context, tx *spanner.ReadWriteTransaction, table string, v Violation) error {
	cols := []string{
		"organization_id", "violation_id",
		"graph_snapshot_id", "materialization_run_id",
		"violation_code", "sentinel_candidate", "severity",
		"source_authority_id", "source_stable_reference",
		"version_coordinate", "section_path",
		"graph_object_id", "symbol_id", "graph_edge_id",
		"evidence",
		"status", "visibility_scope",
		"created_at", "updated_at",
	}
	evidence := spanner.NullJSON{Valid: false}
	if v.Evidence != nil {
		evidence = spanner.NullJSON{Value: v.Evidence, Valid: true}
	}
	vals := []interface{}{
		v.OrganizationID, v.ViolationID,
		nullableString(v.GraphSnapshotID), nullableString(v.MaterializationRunID),
		v.ViolationCode, nullableString(v.SentinelCandidate), v.Severity,
		nullableString(v.SourceAuthorityID), nullableString(v.SourceStableReference),
		nullableString(v.VersionCoordinate), nullableString(v.SectionPath),
		nullableString(v.GraphObjectID), nullableString(v.SymbolID), nullableString(v.GraphEdgeID),
		evidence,
		v.Status, v.VisibilityScope,
		spanner.CommitTimestamp, spanner.CommitTimestamp,
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(table, cols, vals)})
}

// writeProjectionArtifactInTx inserts one OODGraphProjectionArtifacts row.
// Payload is structured_ood_json only per §6.projection_artifact_storage.
func writeProjectionArtifactInTx(_ context.Context, tx *spanner.ReadWriteTransaction, table string, p ProjectionArtifact) error {
	cols := []string{
		"organization_id", "projection_artifact_id",
		"graph_snapshot_id",
		"projection_kind", "projection_target_kind", "projection_target_id",
		"projection_format", "projection_hash",
		"projection_payload",
		"round_trip_state",
		"materialization_run_id",
		"status", "visibility_scope",
		"created_at", "updated_at",
	}
	payload := spanner.NullJSON{Valid: false}
	if p.ProjectionPayload != nil {
		payload = spanner.NullJSON{Value: p.ProjectionPayload, Valid: true}
	}
	vals := []interface{}{
		p.OrganizationID, p.ProjectionArtifactID,
		p.GraphSnapshotID,
		p.ProjectionKind, p.ProjectionTargetKind, nullableString(p.ProjectionTargetID),
		p.ProjectionFormat, p.ProjectionHash,
		payload,
		p.RoundTripState,
		nullableString(p.MaterializationRunID),
		p.Status, p.VisibilityScope,
		spanner.CommitTimestamp, spanner.CommitTimestamp,
	}
	return tx.BufferWrite([]*spanner.Mutation{spanner.Insert(table, cols, vals)})
}
