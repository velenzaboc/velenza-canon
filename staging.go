package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
	"google.golang.org/api/iterator"

	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

// ===========================================================================
// Staging substrate — pre-admission in-Spanner pipeline state
// ===========================================================================
//
// Five MCP tools drive in-flight concepts through their lifecycle in the
// staging_concepts and staging_edges tables (schema_v2.sql STAGING SUBSTRATE
// section):
//
//   spec_graph_staging_load     — bulk INSERT a ConceptTable into staging
//   spec_graph_staging_list     — SELECT with filters (run, state, kind)
//   spec_graph_staging_get      — SELECT one row by (run_id, staging_id)
//   spec_graph_staging_lint     — runs every applicable R-rule, structural
//                                 ones as SQL, R6_no_prose via ML.PREDICT
//                                 against the r6_flash registered model
//   spec_graph_staging_promote  — validate clean staged rows, then route
//                                 them through the shared OODGraph
//                                 materialization path as one snapshot
//
// Architectural shape per VOLT §s1_2 (per bootstrap/audit/README.md):
// push set-oriented lint/query work to data. During bootstrap, load and
// promotion still pass typed rows through the same Go validation,
// source-coordinate and materialization adapter used by direct import; they
// do not create a second durable write shape. The R6 lint reuses the same
// @{remote_udf_max_outstanding_rpcs=64} hint and prompt substitution
// mechanism the bootstrap/audit/r6.sql recipe uses.

// ---------------- staging row types ----------------

// StagingConcept mirrors one staging_concepts row. Carried in tool
// inputs and outputs; not used internally by the adapter (the adapter
// works in spanner.Mutation form directly).
type StagingConcept struct {
	OrganizationID            string                             `json:"organization_id"`
	IngestionRunID            string                             `json:"ingestion_run_id"`
	StagingID                 string                             `json:"staging_id"`
	CanonicalName             string                             `json:"canonical_name"`
	NodeKind                  string                             `json:"node_kind"`
	Contract                  map[string]interface{}             `json:"contract,omitempty"`
	Payload                   map[string]interface{}             `json:"payload,omitempty"`
	SourceFile                string                             `json:"source_file,omitempty"`
	SourcePath                string                             `json:"source_path,omitempty"`
	SourceCoordinate          *ArtifactSourceCoordinate          `json:"source_coordinate,omitempty"`
	SourceVerificationReceipt *stagedExternalVerificationReceipt `json:"source_verification_receipt,omitempty"`
	PipelineState             string                             `json:"pipeline_state"`
	PromotedGraphObjectID     string                             `json:"promoted_graph_object_id,omitempty"`
}

// StagingEdge mirrors one staging_edges row.
type StagingEdge struct {
	OrganizationID      string `json:"organization_id"`
	IngestionRunID      string `json:"ingestion_run_id"`
	StagingEdgeID       string `json:"staging_edge_id"`
	EdgeLabel           string `json:"edge_label"`
	SourceCanonicalName string `json:"source_canonical_name"`
	TargetCanonicalName string `json:"target_canonical_name"`
	PipelineState       string `json:"pipeline_state"`
	PromotedGraphEdgeID string `json:"promoted_graph_edge_id,omitempty"`
}

// ---------------- tool I/O types ----------------

// stagingLoadInput accepts a ConceptTable shape directly (matches
// cmd/spec-lint's loadConceptTable). The IngestionRunID is minted by
// the tool when empty so a caller can stream multiple loads into one
// run by reusing the same id.
type stagingLoadInput struct {
	IngestionRunID string               `json:"ingestion_run_id,omitempty" jsonschema:"reuse to append into an existing run; omit to mint a new run id"`
	ConceptDomain  string               `json:"concept_domain,omitempty"`
	Concepts       []stagingLoadConcept `json:"concepts" jsonschema:"the in-flight concepts to stage"`
	Edges          []stagingLoadEdge    `json:"edges,omitempty" jsonschema:"the in-flight edges to stage"`
	SourceFile     string               `json:"source_file,omitempty" jsonschema:"recorded on every staged row for provenance"`
}

type stagingLoadConcept struct {
	CanonicalName    string                    `json:"canonical_name"`
	NodeKind         string                    `json:"node_kind"`
	Contract         map[string]interface{}    `json:"contract,omitempty"`
	Payload          map[string]interface{}    `json:"payload,omitempty"`
	SourcePath       string                    `json:"source_path,omitempty"`
	SourceCoordinate *ArtifactSourceCoordinate `json:"source_coordinate,omitempty"`
}

type stagingLoadEdge struct {
	EdgeLabel           string `json:"edge_label"`
	SourceCanonicalName string `json:"source_canonical_name"`
	TargetCanonicalName string `json:"target_canonical_name"`
}

type stagingLoadResult struct {
	IngestionRunID string `json:"ingestion_run_id"`
	ConceptsLoaded int    `json:"concepts_loaded"`
	EdgesLoaded    int    `json:"edges_loaded"`
}

type stagingListInput struct {
	IngestionRunID string `json:"ingestion_run_id" jsonschema:"the run to list"`
	PipelineState  string `json:"pipeline_state,omitempty" jsonschema:"filter by state; default no filter"`
	NodeKind       string `json:"node_kind,omitempty" jsonschema:"filter by node_kind; default no filter"`
	Limit          int    `json:"limit,omitempty" jsonschema:"row cap; default 200"`
}

type stagingGetInput struct {
	IngestionRunID string `json:"ingestion_run_id"`
	StagingID      string `json:"staging_id"`
}

type stagingLintInput struct {
	IngestionRunID string `json:"ingestion_run_id" jsonschema:"the run to lint"`
	IncludeR6Flash bool   `json:"include_r6_flash,omitempty" jsonschema:"true: run R6 via ML.PREDICT against r6_flash (≈2 min for 5k rows); false: only structural R-rules"`
}

type stagingLintFinding struct {
	Rule          string `json:"rule"`
	StagingID     string `json:"staging_id,omitempty"`
	StagingEdgeID string `json:"staging_edge_id,omitempty"`
	CanonicalName string `json:"canonical_name,omitempty"`
	NodeKind      string `json:"node_kind,omitempty"`
	FieldPath     string `json:"field_path,omitempty"`
	Observed      string `json:"observed,omitempty"`
	Detail        string `json:"detail"`
}

type stagingLintResult struct {
	IngestionRunID string               `json:"ingestion_run_id"`
	ConceptsLinted int                  `json:"concepts_linted"`
	EdgesLinted    int                  `json:"edges_linted"`
	RulesRun       []string             `json:"rules_run"`
	Findings       []stagingLintFinding `json:"findings"`
	FindingsByRule map[string]int       `json:"findings_by_rule"`
}

type stagingPromoteInput struct {
	IngestionRunID string `json:"ingestion_run_id" jsonschema:"the run whose linted+clean rows to promote"`
}

type stagingPromoteResult struct {
	IngestionRunID     string `json:"ingestion_run_id"`
	ConceptsPromoted   int    `json:"concepts_promoted"`
	EdgesPromoted      int    `json:"edges_promoted"`
	ConceptsSkippedDup int    `json:"concepts_skipped_duplicate_of_admitted"`
	GraphSnapshotID    string `json:"graph_snapshot_id"`
}

type stagingClusterInput struct {
	IngestionRunID       string  `json:"ingestion_run_id" jsonschema:"the run whose embedded rows to cluster against admitted state"`
	AutoMergeMaxDistance float64 `json:"auto_merge_max_distance,omitempty" jsonschema:"distance ≤ this against the nearest admitted node → auto_merge_candidate (skip Flash verify); default 0.05"`
	VerifyMaxDistance    float64 `json:"verify_max_distance,omitempty" jsonschema:"distance ≤ this against the nearest admitted node → verify_needed (Flash decides same-or-different); default 0.30"`
}

type stagingClusterResult struct {
	IngestionRunID      string `json:"ingestion_run_id"`
	ConceptsClustered   int    `json:"concepts_clustered"`
	AutoMergeCandidates int    `json:"auto_merge_candidates"`
	VerifyNeeded        int    `json:"verify_needed"`
	NoMatch             int    `json:"no_match"`
}

type stagingDedupVerifyInput struct {
	IngestionRunID string `json:"ingestion_run_id" jsonschema:"retired compatibility input; semantic verification requires a sanctioned source-authority resolver"`
}

type reembedAdmittedInput struct {
	BatchSize   int `json:"batch_size,omitempty" jsonschema:"rows per batch (default 100)"`
	Concurrency int `json:"concurrency,omitempty" jsonschema:"parallel Vertex AI embed calls (default 16)"`
	MaxRows     int `json:"max_rows,omitempty" jsonschema:"hard cap on rows processed in one call (default 5000, 0 = unbounded)"`
}

type reembedAdmittedResult struct {
	RowsReembedded int `json:"rows_reembedded"`
	RowsFailed     int `json:"rows_failed"`
	RowsSkipped    int `json:"rows_skipped"`
}

type stagingExtractOODInput struct {
	SourceFile     string `json:"source_file" jsonschema:"absolute path to the .ood.json spec to extract"`
	IngestionRunID string `json:"ingestion_run_id,omitempty" jsonschema:"reuse to append into an existing run; omit to mint a new run id"`
	NodeKind       string `json:"node_kind,omitempty" jsonschema:"node_kind to apply to every emitted concept; default 'section' (any value valid in cfg.NodeKinds is accepted)"`
}

type stagingExtractOODResult struct {
	IngestionRunID string `json:"ingestion_run_id"`
	ConceptsLoaded int    `json:"concepts_loaded"`
	SpecPrefix     string `json:"spec_prefix"`
	SourceFile     string `json:"source_file"`
}

type stagingDedupVerifyDecision struct {
	StagingID         string  `json:"staging_id"`
	NearestAdmittedID string  `json:"nearest_admitted_graph_object_id"`
	NearestDistance   float64 `json:"nearest_distance"`
	Verdict           string  `json:"verdict"`
	FlashResponse     string  `json:"flash_response,omitempty"`
}

type stagingDedupVerifyResult struct {
	IngestionRunID    string                       `json:"ingestion_run_id"`
	PairsVerified     int                          `json:"pairs_verified"`
	VerifiedSame      int                          `json:"verified_same"`
	VerifiedDifferent int                          `json:"verified_different"`
	Uncertain         int                          `json:"uncertain"`
	Decisions         []stagingDedupVerifyDecision `json:"decisions"`
}

// ---------------- handlers ----------------

func handleStagingLoad(ctx context.Context, env *Env, in stagingLoadInput) (stagingLoadResult, error) {
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return stagingLoadResult{}, err
	}
	if len(in.Concepts) == 0 && len(in.Edges) == 0 {
		return stagingLoadResult{}, fmt.Errorf("at least one concept or edge required")
	}
	// One load request owns one immutable verification session. Repeated
	// symbols/fragments for the same canonical resource share the exact byte
	// receipt, while a later request must fetch and attest afresh.
	ctx = withExternalVerificationSession(ctx, orgID)
	// Edges are caller-authored batch structure. Reject malformed labels,
	// endpoints, and duplicates before any concept can evaluate permission or
	// fetch upstream evidence; a deterministically invalid batch must consume
	// no vendor request.
	if err := validateStagingLoadEdges(ctx, env, in.Edges); err != nil {
		return stagingLoadResult{}, err
	}
	// Source coordinates are admission identity, not content. Validate the
	// complete batch before opening a Spanner client so partial/malformed
	// external coordinates never enter staging as plausible metadata.
	resolvedCoordinates := make([]ArtifactSourceCoordinate, len(in.Concepts))
	externalPolicies := make([]ExternalSourceDescriptor, len(in.Concepts))
	externalReceipts := make([]*stagedExternalVerificationReceipt, len(in.Concepts))
	for i, c := range in.Concepts {
		if c.CanonicalName == "" || c.NodeKind == "" {
			return stagingLoadResult{}, fmt.Errorf("each concept needs canonical_name + node_kind")
		}
		desc, err := env.Kinds.Resolve(ctx, c.NodeKind)
		if err != nil {
			return stagingLoadResult{}, fmt.Errorf("concept[%d] node_kind=%q: %w", i, c.NodeKind, err)
		}
		coord, err := resolveArtifactSourceCoordinate(c.NodeKind, c.CanonicalName, desc, c.SourceCoordinate)
		if err != nil {
			return stagingLoadResult{}, fmt.Errorf("concept[%d] canonical_name=%q: %w", i, c.CanonicalName, err)
		}
		coord, policy, receipt, err := validateExternalReferenceSubmissionForStaging(ctx, env, ArtifactSubmission{
			NodeKind:         c.NodeKind,
			StableID:         c.CanonicalName,
			Contract:         c.Contract,
			Payload:          c.Payload,
			SourceCoordinate: c.SourceCoordinate,
		}, c.CanonicalName, desc, coord)
		if err != nil {
			return stagingLoadResult{}, fmt.Errorf("concept[%d] canonical_name=%q: %w", i, c.CanonicalName, err)
		}
		resolvedCoordinates[i] = coord
		externalPolicies[i] = policy
		externalReceipts[i] = receipt
	}
	runID := in.IngestionRunID
	if runID == "" {
		runID = uuid.NewString()
	}

	client, err := stagingClient(ctx, env)
	if err != nil {
		return stagingLoadResult{}, err
	}

	conceptMuts := make([]*spanner.Mutation, 0, len(in.Concepts))
	symbolMuts := make([]*spanner.Mutation, 0, len(in.Concepts)*8)
	for i, c := range in.Concepts {
		coord := resolvedCoordinates[i]
		externalPolicy := externalPolicies[i]
		contractJSON, _ := toNullableJSON(c.Contract)
		payloadJSON, _ := toNullableJSON(c.Payload)
		sourceCoordinateJSON, err := sourceCoordinateToNullJSON(&coord)
		if err != nil {
			return stagingLoadResult{}, err
		}
		sourceReceiptJSON, err := stagedExternalReceiptToNullJSON(externalReceipts[i])
		if err != nil {
			return stagingLoadResult{}, err
		}
		stagingID := uuid.NewString()
		// Embed graph-owned identity/classification metadata only, using the
		// same source as handleImport. Source contract/payload bodies remain
		// in staging but are forbidden from OOD retrieval metadata by §6/§8.
		var embedding []float32
		embeddingModel := ""
		if env.Embed != nil {
			address := GraphAddress{
				ObjectClass: c.NodeKind, SourceAuthorityID: coord.SourceAuthorityID,
				SourceRefKind: coord.SourceRefKind, SourceRef: coord.SourceStableReference,
				VersionCoordinate: coord.VersionCoordinate, SectionPath: coord.SectionPath,
			}.String()
			searchText := graphOwnedObjectSearchText(c.NodeKind, address, coord)
			if externalPolicy.ID != "" {
				searchText = externalReferenceSearchText(c.NodeKind, coord, externalPolicy)
			}
			vec, eErr := env.Embed.Embed(ctx, searchText, vertexai.TaskTypeRetrievalDocument)
			if eErr != nil {
				return stagingLoadResult{}, fmt.Errorf("embed concept %q: %w", c.CanonicalName, eErr)
			}
			if externalPolicy.ID != "" && len(vec) != externalReferenceEmbeddingDimensions {
				return stagingLoadResult{}, fmt.Errorf("embed external concept %q: got %d dimensions, want %d", c.CanonicalName, len(vec), externalReferenceEmbeddingDimensions)
			}
			embedding = vec
			embeddingModel = embeddingModelOrEmpty(env)
		}
		conceptMuts = append(conceptMuts, spanner.Insert("staging_concepts",
			[]string{
				"organization_id", "ingestion_run_id", "staging_id",
				"canonical_name", "node_kind", "contract", "payload",
				"source_file", "source_path", "source_coordinate", "source_verification_receipt",
				"embedding", "embedding_model",
				"pipeline_state", "created_at", "updated_at",
			},
			[]interface{}{
				orgID, runID, stagingID,
				c.CanonicalName, c.NodeKind, contractJSON, payloadJSON,
				nullableString(in.SourceFile), nullableString(c.SourcePath), sourceCoordinateJSON, sourceReceiptJSON,
				embedding, nullableString(embeddingModel),
				"embedded", spanner.CommitTimestamp, spanner.CommitTimestamp,
			},
		))
		if externalPolicy.ID == "" {
			stagingWalkSymbols(c.Contract, "$.contract", orgID, runID, stagingID, c.CanonicalName, c.NodeKind, &symbolMuts)
			stagingWalkSymbols(c.Payload, "$.payload", orgID, runID, stagingID, c.CanonicalName, c.NodeKind, &symbolMuts)
		}
	}

	edgeMuts := make([]*spanner.Mutation, 0, len(in.Edges))
	for _, e := range in.Edges {
		edgeMuts = append(edgeMuts, spanner.Insert("staging_edges",
			[]string{
				"organization_id", "ingestion_run_id", "staging_edge_id",
				"edge_label", "source_canonical_name", "target_canonical_name",
				"pipeline_state", "created_at", "updated_at",
			},
			[]interface{}{
				orgID, runID, uuid.NewString(),
				e.EdgeLabel, e.SourceCanonicalName, e.TargetCanonicalName,
				"extracted", spanner.CommitTimestamp, spanner.CommitTimestamp,
			},
		))
	}

	muts := append(conceptMuts, edgeMuts...)
	muts = append(muts, symbolMuts...)
	if err := applyStagingMutationsChunked(ctx, client, muts); err != nil {
		return stagingLoadResult{}, fmt.Errorf("apply staging mutations: %w", err)
	}

	return stagingLoadResult{
		IngestionRunID: runID,
		ConceptsLoaded: len(in.Concepts),
		EdgesLoaded:    len(in.Edges),
	}, nil
}

func validateStagingLoadEdges(ctx context.Context, env *Env, edges []stagingLoadEdge) error {
	seenEdges := map[externalRelationshipIdentity]struct{}{}
	for i, edge := range edges {
		fields := []struct {
			name  string
			value string
			limit int
		}{
			{"edge_label", edge.EdgeLabel, 64},
			{"source_canonical_name", edge.SourceCanonicalName, 2048},
			{"target_canonical_name", edge.TargetCanonicalName, 2048},
		}
		for _, field := range fields {
			if field.value == "" {
				return fmt.Errorf("edge[%d].%s required", i, field.name)
			}
			if strings.TrimSpace(field.value) != field.value || !utf8.ValidString(field.value) || len(field.value) > field.limit {
				return fmt.Errorf("edge[%d].%s must be canonical UTF-8 within STRING(%d)", i, field.name, field.limit)
			}
		}
		if !externalRelationshipCanonicalNamePattern.MatchString(edge.SourceCanonicalName) || !externalRelationshipCanonicalNamePattern.MatchString(edge.TargetCanonicalName) {
			return fmt.Errorf("edge[%d] endpoints must be canonical snake_case, dotted, kebab-case, or UUID names", i)
		}
		if env == nil || env.Edges == nil {
			return fmt.Errorf("edge[%d]: closed edge_label registry unavailable", i)
		}
		if _, err := env.Edges.Resolve(ctx, edge.EdgeLabel); err != nil {
			return fmt.Errorf("edge[%d].edge_label: %w", i, err)
		}
		identity := externalRelationshipIdentity{Source: edge.SourceCanonicalName, Label: edge.EdgeLabel, Target: edge.TargetCanonicalName}
		if _, duplicate := seenEdges[identity]; duplicate {
			return fmt.Errorf("edge[%d] duplicates %q -[%s]-> %q", i, edge.SourceCanonicalName, edge.EdgeLabel, edge.TargetCanonicalName)
		}
		seenEdges[identity] = struct{}{}
	}
	return nil
}

func handleStagingList(ctx context.Context, env *Env, in stagingListInput) (QueryResult, error) {
	if in.IngestionRunID == "" {
		return QueryResult{}, fmt.Errorf("ingestion_run_id required")
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return QueryResult{}, err
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 200
	}
	sql := fmt.Sprintf(`SELECT
  organization_id, ingestion_run_id, staging_id, canonical_name, node_kind,
	contract, payload, source_file, source_path,
	source_coordinate, source_verification_receipt,
  cluster_id, dedup_status, lint_status, pipeline_state,
  promoted_graph_object_id, created_at, updated_at
FROM staging_concepts
WHERE organization_id = '%s' AND ingestion_run_id = '%s'`,
		sqlEscape(orgID), sqlEscape(in.IngestionRunID))
	if in.PipelineState != "" {
		sql += fmt.Sprintf(" AND pipeline_state = '%s'", sqlEscape(in.PipelineState))
	}
	if in.NodeKind != "" {
		sql += fmt.Sprintf(" AND node_kind = '%s'", sqlEscape(in.NodeKind))
	}
	sql += fmt.Sprintf(" ORDER BY canonical_name LIMIT %d", limit)
	return executeStagingReadOnlyQuery(ctx, env, queryInput{SQL: sql})
}

func handleStagingGet(ctx context.Context, env *Env, in stagingGetInput) (QueryResult, error) {
	if in.IngestionRunID == "" || in.StagingID == "" {
		return QueryResult{}, fmt.Errorf("ingestion_run_id + staging_id required")
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return QueryResult{}, err
	}
	sql := fmt.Sprintf(`SELECT * FROM staging_concepts
WHERE organization_id = '%s' AND ingestion_run_id = '%s' AND staging_id = '%s'`,
		sqlEscape(orgID), sqlEscape(in.IngestionRunID), sqlEscape(in.StagingID))
	return executeStagingReadOnlyQuery(ctx, env, queryInput{SQL: sql})
}

func handleStagingLint(ctx context.Context, env *Env, in stagingLintInput) (stagingLintResult, error) {
	if in.IngestionRunID == "" {
		return stagingLintResult{}, fmt.Errorf("ingestion_run_id required")
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return stagingLintResult{}, err
	}

	out := stagingLintResult{
		IngestionRunID: in.IngestionRunID,
		FindingsByRule: map[string]int{},
		RulesRun:       []string{},
	}

	conceptCount, edgeCount, err := stagingRunCounts(ctx, env, orgID, in.IngestionRunID)
	if err != nil {
		return stagingLintResult{}, err
	}
	out.ConceptsLinted = conceptCount
	out.EdgesLinted = edgeCount

	// Structural R-rules — pure SQL against the staging tables. Each
	// helper returns []stagingLintFinding; the rule name is the helper.
	for _, r := range []struct {
		name string
		fn   func(ctx context.Context, env *Env, orgID, runID string) ([]stagingLintFinding, error)
	}{
		{"R3_kind_in_registry", lintR3KindInRegistry},
		{"R7_canonical_name_pattern", lintR7CanonicalNamePattern},
		{"R8_no_duplicate", lintR8NoDuplicate},
		{"R10_edge_endpoint_kinds", lintR10EdgeEndpointKinds},
		{"R12_self_loop", lintR12SelfLoop},
		{"R13_no_source_reference", lintR13NoSourceReference},
		{"R15_no_admission_artifacts", lintR15NoAdmissionArtifacts},
	} {
		findings, err := r.fn(ctx, env, orgID, in.IngestionRunID)
		if err != nil {
			return stagingLintResult{}, fmt.Errorf("%s: %w", r.name, err)
		}
		out.RulesRun = append(out.RulesRun, r.name)
		out.FindingsByRule[r.name] = len(findings)
		out.Findings = append(out.Findings, findings...)
	}

	// R6 via ML.PREDICT — gated by include_r6_flash because it's the
	// only rule that takes minutes-not-seconds.
	if in.IncludeR6Flash {
		findings, err := lintR6NoProse(ctx, env, orgID, in.IngestionRunID)
		if err != nil {
			return stagingLintResult{}, fmt.Errorf("R6_no_prose: %w", err)
		}
		out.RulesRun = append(out.RulesRun, "R6_no_prose")
		out.FindingsByRule["R6_no_prose"] = len(findings)
		out.Findings = append(out.Findings, findings...)
	}

	// Update lint_status on every staging_concepts row in the run.
	if err := stagingUpdateLintStatus(ctx, env, orgID, in.IngestionRunID, out.Findings); err != nil {
		return stagingLintResult{}, fmt.Errorf("update lint_status: %w", err)
	}

	return out, nil
}

func handleStagingPromote(ctx context.Context, env *Env, in stagingPromoteInput) (stagingPromoteResult, error) {
	if in.IngestionRunID == "" {
		return stagingPromoteResult{}, fmt.Errorf("ingestion_run_id required")
	}
	// Promotion routes through handleImport so staged and direct OOD Graph
	// inputs share one source-coordinate validator, identity derivation and
	// CommitMaterializationRun path. Staging remains a work buffer; it is not
	// a second durable graph writer.
	//
	// dedup gate: stagingFetchLintedConcepts excludes rows whose
	// dedup_status indicates a confirmed duplicate of an admitted node
	// (auto_merge_candidate, verified_same). Those rows stay in staging
	// at pipeline_state='linted' so an operator can inspect the
	// dedup_decision and either accept (do nothing) or override
	// (manually flip dedup_status). Rows with no_match / uncertain /
	// verified_different / NULL dedup_status are eligible to promote.
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return stagingPromoteResult{}, err
	}
	// Read the entire promotion candidate at one Spanner timestamp. Every
	// non-duplicate concept and every edge must already be linted+pass; one
	// dirty or unlinted row rejects the whole run before handleImport performs
	// any external, embedding, or materialization I/O.
	concepts, skippedDup, edges, err := stagingFetchPromotionRows(ctx, env, orgID, in.IngestionRunID)
	if err != nil {
		return stagingPromoteResult{}, fmt.Errorf("fetch staged promotion plan: %w", err)
	}
	// An exact replay may have every concept classified as an admitted
	// duplicate. With no staged relationships there is nothing to write and
	// the idempotent result is a successful no-op, not a synthetic empty
	// snapshot. Relationships cannot be replayed without their endpoints in
	// the same snapshot, so that shape remains a fail-closed error.
	if len(concepts) == 0 {
		if len(edges) != 0 {
			return stagingPromoteResult{}, fmt.Errorf("cannot promote %d staged relationship(s): every endpoint concept was skipped as an admitted duplicate", len(edges))
		}
		return stagingPromoteResult{
			IngestionRunID:     in.IngestionRunID,
			ConceptsSkippedDup: skippedDup,
		}, nil
	}
	subs := make([]ArtifactSubmission, 0, len(concepts))
	for _, c := range concepts {
		subs = append(subs, stagingConceptSubmission(c))
	}
	relationships := make([]ExternalRelationship, 0, len(edges))
	for _, edge := range edges {
		relationships = append(relationships, ExternalRelationship{
			EdgeLabel:           edge.EdgeLabel,
			SourceCanonicalName: edge.SourceCanonicalName,
			TargetCanonicalName: edge.TargetCanonicalName,
		})
	}
	conceptStagingIDs := make([]string, len(concepts))
	externalReceipts := make([]*stagedExternalVerificationReceipt, len(concepts))
	for i, concept := range concepts {
		conceptStagingIDs[i] = concept.StagingID
		externalReceipts[i] = concept.SourceVerificationReceipt
	}
	edgeStagingIDs := make([]string, len(edges))
	for i, edge := range edges {
		edgeStagingIDs[i] = edge.StagingEdgeID
	}
	imp, err := handleImport(ctx, env, importInput{
		Submissions:   subs,
		Relationships: relationships,
		StagingPromotion: &stagingPromotionPlan{
			IngestionRunID:    in.IngestionRunID,
			ConceptStagingIDs: conceptStagingIDs,
			EdgeStagingIDs:    edgeStagingIDs,
			ExternalReceipts:  externalReceipts,
		},
	})
	if err != nil {
		return stagingPromoteResult{}, fmt.Errorf("import-promote: %w", err)
	}
	return stagingPromoteResult{
		IngestionRunID:     in.IngestionRunID,
		ConceptsPromoted:   imp.Admitted,
		EdgesPromoted:      imp.RelationshipsAdmitted,
		ConceptsSkippedDup: skippedDup,
		GraphSnapshotID:    imp.GraphSnapshotID,
	}, nil
}

func stagingConceptSubmission(c StagingConcept) ArtifactSubmission {
	return ArtifactSubmission{
		NodeKind:         c.NodeKind,
		StableID:         c.CanonicalName,
		Contract:         c.Contract,
		Payload:          c.Payload,
		SourceCoordinate: c.SourceCoordinate,
	}
}

// handleStagingExtractOOD reads one .ood.json spec from disk and
// recursively decomposes it into ATOMIC concepts — one staging
// concept per scalar-string leaf claim found anywhere in the spec.
// NOT one concept per section — that would just be JSON copy-paste
// into the graph with extra steps. The graph stores finished thought
// (CLAUDE.md ANTI_TRAINING.atomic_single_clause_not_narrative); each
// concept carries ONE claim that can be deduped, referenced, and
// reasoned about independently.
//
// The walk:
//
//   - Recursively descends every map/array node in the spec.
//   - At each scalar string leaf, decides whether the value is a
//     CLAIM (substantive content — a rule, an assertion, a
//     definition) or an IDENTIFIER (a name, version, uuid, doc-id,
//     file path, enum value). Identifiers are skipped (not concepts;
//     they're the structural skeleton).
//   - For each claim leaf, emits one staging concept:
//     canonical_name = "<spec_prefix>__<dotted.path.to.leaf>"
//     e.g. volt_v34__s1_paradigm_principles.s1_2_paradigm_principles
//     .principles.node_first.rule
//     node_kind      = passed-in default (e.g. "section") OR
//     per-leaf-key inference (rule|invariant|
//     sentinel|decision|axiom→matched kind)
//     payload        = { <leaf_field_name>: <leaf_value> }
//     source_path    = "<source_file>#<dotted.path>"
//
// The claim-vs-identifier classifier is deliberately conservative:
// claims have whitespace AND length > 20 AND no obvious identifier
// shape. Borderline values err toward "skip" — better to under-emit
// concepts than to flood the graph with identifier-shaped noise.
//
// Arrays of strings get walked element by element with an index
// segment in the path; arrays of objects recurse normally.
//
// This is the "new version of everything" — replaces the per-spec
// recipe approach with one mechanical walker that produces the same
// atomic shape the recipe-extracted volt_secret_detection concepts
// had (scan_behavior + enforcement + rule + reproducibility each as
// independent concepts, not a single bloated section blob).
func handleStagingExtractOOD(ctx context.Context, env *Env, in stagingExtractOODInput) (stagingExtractOODResult, error) {
	if in.SourceFile == "" {
		return stagingExtractOODResult{}, fmt.Errorf("source_file required")
	}
	defaultKind := in.NodeKind
	if defaultKind == "" {
		defaultKind = "section"
	}

	raw, err := os.ReadFile(in.SourceFile)
	if err != nil {
		return stagingExtractOODResult{}, fmt.Errorf("read %q: %w", in.SourceFile, err)
	}
	var spec map[string]interface{}
	if err := json.Unmarshal(raw, &spec); err != nil {
		return stagingExtractOODResult{}, fmt.Errorf("parse %q as JSON object: %w", in.SourceFile, err)
	}

	specPrefix := stagingSpecPrefixFromPath(in.SourceFile)

	concepts := make([]stagingLoadConcept, 0)
	stagingWalkClaims(spec, "", specPrefix, defaultKind, in.SourceFile, &concepts)

	if len(concepts) == 0 {
		return stagingExtractOODResult{}, fmt.Errorf("spec %q contained no claim-shaped scalar string leaves; nothing to extract", in.SourceFile)
	}

	loadResult, err := handleStagingLoad(ctx, env, stagingLoadInput{
		IngestionRunID: in.IngestionRunID,
		ConceptDomain:  specPrefix,
		Concepts:       concepts,
		SourceFile:     in.SourceFile,
	})
	if err != nil {
		return stagingExtractOODResult{}, fmt.Errorf("load: %w", err)
	}
	return stagingExtractOODResult{
		IngestionRunID: loadResult.IngestionRunID,
		ConceptsLoaded: loadResult.ConceptsLoaded,
		SpecPrefix:     specPrefix,
		SourceFile:     in.SourceFile,
	}, nil
}

// stagingWalkClaims recurses through one JSON subtree, appending one
// stagingLoadConcept per scalar-string leaf that classifies as a
// claim (not an identifier).
//
// pathSoFar uses dotted-path notation for object keys, [N] for array
// indexes (consistent with the OODGraphSymbols section_path
// convention). Empty pathSoFar means we're at the spec root.
func stagingWalkClaims(val interface{}, pathSoFar, specPrefix, defaultKind, sourceFile string, out *[]stagingLoadConcept) {
	switch v := val.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := v[k]
			childPath := k
			if pathSoFar != "" {
				childPath = pathSoFar + "." + k
			}
			stagingWalkClaims(child, childPath, specPrefix, defaultKind, sourceFile, out)
		}
	case []interface{}:
		for i, child := range v {
			childPath := fmt.Sprintf("%s[%d]", pathSoFar, i)
			stagingWalkClaims(child, childPath, specPrefix, defaultKind, sourceFile, out)
		}
	case string:
		if !stagingIsClaimShape(v) {
			return
		}
		// The leaf field name is the last dotted segment of the path
		// (or the path itself if there's no dot). Strip any [N] index
		// suffix so the payload key reads naturally.
		leafField := pathSoFar
		if i := strings.LastIndex(leafField, "."); i >= 0 {
			leafField = leafField[i+1:]
		}
		if i := strings.Index(leafField, "["); i >= 0 {
			leafField = leafField[:i]
		}
		if leafField == "" {
			leafField = "value"
		}
		*out = append(*out, stagingLoadConcept{
			CanonicalName: specPrefix + "__" + pathSoFar,
			NodeKind:      stagingNodeKindForLeaf(leafField, defaultKind),
			Payload:       map[string]interface{}{leafField: v},
			SourcePath:    sourceFile + "#" + pathSoFar,
		})
	}
	// numbers, bools, nil are not claims — skip silently.
}

// stagingIsClaimShape decides whether a scalar string value is a
// CLAIM (substantive content worth a node) or an IDENTIFIER (a
// structural name not worth a node). Conservative: borderline values
// skip. Three signals together — multi-token, length > 20 chars, no
// obvious identifier-shape pattern — must all pass.
func stagingIsClaimShape(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 20 {
		return false
	}
	if !strings.ContainsAny(s, " \t") {
		// No whitespace = single token = identifier shape (UUID,
		// snake_case key, dotted_path, file path, version string,
		// hash, etc.).
		return false
	}
	// File paths under specs-local/ or repos/ are not claims even
	// though they have spaces sometimes — handled by the no-whitespace
	// rule above for the common case. Explicit file-path heuristic:
	if strings.HasPrefix(s, "/Users/") || strings.HasPrefix(s, "/home/") {
		return false
	}
	return true
}

// stagingNodeKindForLeaf maps common leaf-field-name conventions to
// the closed registry of node kinds. Defaults to defaultKind for
// anything that doesn't match a known convention.
//
// The convention is per CLAUDE.md OOD_GRAPH_PROTOCOL — node kinds
// like axiom, invariant, sentinel, decision, section are the closed
// set. Field names like "rule" or "statement" or "assertion" map
// naturally; falling back to default keeps the extractor permissive.
func stagingNodeKindForLeaf(leafField, defaultKind string) string {
	switch strings.ToLower(leafField) {
	case "rule", "invariant", "constraint", "must", "shall":
		return "invariant"
	case "decision", "resolution", "choice":
		return "decision"
	case "sentinel", "error", "failure":
		return "sentinel"
	case "axiom", "principle", "tenet":
		return "axiom"
	case "assumption", "presumption", "premise":
		return "assumption"
	default:
		return defaultKind
	}
}

// stagingSpecPrefixFromPath derives the canonical_name prefix from
// a .ood.json file's basename. Strips the .ood.json suffix and
// lowercases — so VOLT_SECRET_DETECTION_v1.ood.json → volt_secret_detection_v1.
// Falls through cleanly for any name that lacks the .ood.json suffix
// (treats the full basename as the prefix).
func stagingSpecPrefixFromPath(path string) string {
	base := path
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".ood.json")
	base = strings.TrimSuffix(base, ".json")
	return strings.ToLower(base)
}

// handleStagingCluster is an identity replay gate. Every staged concept must
// carry the source coordinate resolved by handleStagingLoad. Ordinary rows
// compare the canonical identity tuple in the one eligible current snapshot;
// external rows additionally bind the authority-owned digest. Semantic source
// comparison is fail-closed until a sanctioned source-authority resolver can
// supply content without misusing OOD retrieval metadata.
func handleStagingCluster(ctx context.Context, env *Env, in stagingClusterInput) (stagingClusterResult, error) {
	if in.IngestionRunID == "" {
		return stagingClusterResult{}, fmt.Errorf("ingestion_run_id required")
	}
	autoMerge := in.AutoMergeMaxDistance
	if autoMerge <= 0 {
		autoMerge = 0.05
	}
	verify := in.VerifyMaxDistance
	if verify <= 0 {
		verify = 0.30
	}
	orgID, err := resolveOrganizationID(ctx, env)
	if err != nil {
		return stagingClusterResult{}, err
	}

	objectTable, err := substrateTable(env, func(s SubstrateDescriptor) string { return s.ObjectTable }, "object_table")
	if err != nil {
		return stagingClusterResult{}, err
	}
	snapshotTable, err := substrateTable(env, func(s SubstrateDescriptor) string { return s.SnapshotTable }, "snapshot_table")
	if err != nil {
		return stagingClusterResult{}, err
	}
	runTable, err := substrateTable(env, func(s SubstrateDescriptor) string { return s.MaterializationRunTable }, "materialization_run_table")
	if err != nil {
		return stagingClusterResult{}, err
	}

	client, err := stagingClient(ctx, env)
	if err != nil {
		return stagingClusterResult{}, err
	}

	// Pull every staged concept of this run with its embedding.
	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT staging_id, canonical_name, node_kind, embedding, source_coordinate
FROM staging_concepts
WHERE organization_id = @org AND ingestion_run_id = @run
  AND embedding IS NOT NULL`,
		Params: map[string]interface{}{"org": orgID, "run": in.IngestionRunID},
	})
	defer iter.Stop()

	type staged struct {
		StagingID        string
		CanonicalName    string
		NodeKind         string
		Embedding        []float32
		SourceCoordinate *ArtifactSourceCoordinate
	}
	var rows []staged
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return stagingClusterResult{}, fmt.Errorf("scan staged: %w", err)
		}
		var s staged
		var sourceCoordinate spanner.NullJSON
		if err := row.Columns(&s.StagingID, &s.CanonicalName, &s.NodeKind, &s.Embedding, &sourceCoordinate); err != nil {
			return stagingClusterResult{}, fmt.Errorf("decode staged row: %w", err)
		}
		if sourceCoordinate.Valid {
			decoded, err := sourceCoordinateFromJSON(sourceCoordinate.Value)
			if err != nil {
				return stagingClusterResult{}, fmt.Errorf("decode staged source_coordinate for %q: %w", s.CanonicalName, err)
			}
			s.SourceCoordinate = decoded
		}
		rows = append(rows, s)
	}

	out := stagingClusterResult{IngestionRunID: in.IngestionRunID}

	// Per-row: the exact identity/digest path is the only lawful path.
	muts := make([]*spanner.Mutation, 0, len(rows))
	for _, s := range rows {
		if s.SourceCoordinate == nil {
			return stagingClusterResult{}, ErrOODGraphSourcePayloadResolutionUnavailable
		}
		identityMatchID, err := stagingExactSourceCoordinateMatch(ctx, client, objectTable, snapshotTable, runTable, orgID, s.NodeKind, *s.SourceCoordinate)
		if err != nil {
			return stagingClusterResult{}, fmt.Errorf("exact source-coordinate lookup for %q: %w", s.CanonicalName, err)
		}
		dedupStatus := "no_match"
		disposition := "changed_or_new_source_coordinate"
		if identityMatchID != "" {
			dedupStatus = "auto_merge_candidate"
			disposition = "exact_coordinate_and_digest_replay"
			out.AutoMergeCandidates++
		} else {
			out.NoMatch++
		}
		decisionJSON, _ := toNullableJSON(map[string]interface{}{
			"nearest_admitted_id":           identityMatchID,
			"nearest_distance":              0,
			"auto_merge_max_distance":       autoMerge,
			"verify_max_distance":           verify,
			"candidates":                    []map[string]interface{}{},
			"source_coordinate_disposition": disposition,
		})
		muts = append(muts, spanner.Update("staging_concepts",
			[]string{
				"organization_id", "ingestion_run_id", "staging_id",
				"dedup_status", "dedup_decision", "pipeline_state", "updated_at",
			},
			[]interface{}{
				orgID, in.IngestionRunID, s.StagingID,
				dedupStatus, decisionJSON, "clustered", spanner.CommitTimestamp,
			},
		))
		out.ConceptsClustered++
	}
	if len(muts) > 0 {
		if err := applyStagingMutationsChunked(ctx, client, muts); err != nil {
			return stagingClusterResult{}, fmt.Errorf("apply cluster updates: %w", err)
		}
	}
	return out, nil
}

func stagingExactSourceCoordinateMatch(ctx context.Context, client *spanner.Client, objectTable, snapshotTable, runTable, orgID, objectClass string, c ArtifactSourceCoordinate) (string, error) {
	stmt, err := stagingExactSourceCoordinateStatement(objectTable, snapshotTable, runTable, orgID, objectClass, c)
	if err != nil {
		return "", err
	}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()
	result, err := iter.Next()
	if err == iterator.Done {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var id string
	if err := result.Columns(&id); err != nil {
		return "", err
	}
	return id, nil
}

func stagingExactSourceCoordinateStatement(objectTable, snapshotTable, runTable, orgID, objectClass string, c ArtifactSourceCoordinate) (spanner.Statement, error) {
	digestPredicate := ""
	params := map[string]interface{}{
		"org": orgID, "class": objectClass, "authority": c.SourceAuthorityID,
		"ref_kind": c.SourceRefKind, "reference": c.SourceStableReference,
		"version": c.VersionCoordinate, "section": c.SectionPath,
	}
	if _, external := externalReferenceObjectClasses[objectClass]; external {
		if c.SourceContentHash == "" {
			return spanner.Statement{}, fmt.Errorf("external exact-coordinate lookup requires source_content_hash")
		}
		digestPredicate = "\n  AND o.source_content_hash=@content_hash"
		params["content_hash"] = c.SourceContentHash
	}
	return spanner.Statement{
		SQL: fmt.Sprintf(`SELECT graph_object_id
FROM %s o
WHERE o.organization_id=@org
  AND o.object_class=@class
  AND o.source_authority_id=@authority
  AND o.source_ref_kind=@ref_kind
  AND o.source_stable_reference=@reference
  AND o.version_coordinate=@version
  AND o.section_path=@section%s
  AND o.status='active'
  AND o.graph_snapshot_id=(
    SELECT s.graph_snapshot_id FROM %s s JOIN %s r
      ON r.organization_id=s.organization_id AND r.materialization_run_id=s.materialization_run_id
    WHERE s.organization_id=@org AND s.snapshot_kind='active_candidate'
      AND s.snapshot_state='sealed' AND s.status='active' AND s.sealed_at IS NOT NULL
      AND r.state='sealed' AND r.finished_at IS NOT NULL
      AND r.target_graph_snapshot_id=s.graph_snapshot_id
      AND r.input_source_set_hash=s.source_set_hash
      AND JSON_VALUE(s.source_set, '$.materialization_profile_version')='%s'
    ORDER BY s.graph_version DESC, s.graph_snapshot_id DESC LIMIT 1)
LIMIT 1`, objectTable, digestPredicate, snapshotTable, runTable, sqlEscape(MaterializationProfileVersion)),
		Params: params,
	}, nil
}

// handleStagingDedupVerify is a fail-closed compatibility endpoint. No OOD
// retrieval column is source content, so semantic comparison needs a future
// sanctioned resolver for the owning source authority.
func handleStagingDedupVerify(context.Context, *Env, stagingDedupVerifyInput) (stagingDedupVerifyResult, error) {
	return stagingDedupVerifyResult{}, ErrOODGraphSourcePayloadResolutionUnavailable
}

// handleReembedAdmitted is retained only as a fail-closed compatibility
// endpoint. Rewriting embeddings on prior sealed rows destroys immutable
// historical snapshots. Profile/7 refreshes changed rows while constructing
// a complete successor and commits them atomically with that new snapshot.
func handleReembedAdmitted(context.Context, *Env, reembedAdmittedInput) (reembedAdmittedResult, error) {
	return reembedAdmittedResult{}, ErrOODGraphImmutableReembeddingUnavailable
}

// ---------------- structural R-rule SQL helpers ----------------

// allowedNodeKinds + allowedEdgeLabels read from cfg.NodeKinds /
// cfg.EdgeLabels — the same closed registry the existing in-process
// spec-lint validates against (VOLT §s1_2 binary_is_never_sot: the
// registry is config, not spec-frozen).

func lintR3KindInRegistry(ctx context.Context, env *Env, orgID, runID string) ([]stagingLintFinding, error) {
	kinds := make([]string, 0, len(env.Config.NodeKinds))
	for _, k := range env.Config.NodeKinds {
		kinds = append(kinds, "'"+sqlEscape(k.Name())+"'")
	}
	if len(kinds) == 0 {
		return nil, nil
	}
	sql := fmt.Sprintf(`SELECT staging_id, canonical_name, node_kind
FROM staging_concepts
WHERE organization_id = '%s' AND ingestion_run_id = '%s' AND node_kind NOT IN (%s)`,
		sqlEscape(orgID), sqlEscape(runID), strings.Join(kinds, ","))
	return runLintQuery(ctx, env, sql, "R3_kind_in_registry", func(row map[string]interface{}) stagingLintFinding {
		return stagingLintFinding{
			Rule:          "R3_kind_in_registry",
			StagingID:     asString(row["staging_id"]),
			CanonicalName: asString(row["canonical_name"]),
			NodeKind:      asString(row["node_kind"]),
			Detail:        fmt.Sprintf("node_kind %q not in registry", asString(row["node_kind"])),
		}
	})
}

func lintR7CanonicalNamePattern(ctx context.Context, env *Env, orgID, runID string) ([]stagingLintFinding, error) {
	// R7: canonical_name MUST match snake_case OR dotted_path OR
	// kebab-case OR UUID. The in-Go check is permissive; the SQL mirror
	// uses a single regex covering the union.
	sql := fmt.Sprintf(`SELECT staging_id, canonical_name, node_kind
FROM staging_concepts
WHERE organization_id = '%s' AND ingestion_run_id = '%s'
  AND NOT REGEXP_CONTAINS(canonical_name, r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$|^[a-z][a-z0-9-]*$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')`,
		sqlEscape(orgID), sqlEscape(runID))
	return runLintQuery(ctx, env, sql, "R7_canonical_name_pattern", func(row map[string]interface{}) stagingLintFinding {
		return stagingLintFinding{
			Rule:          "R7_canonical_name_pattern",
			StagingID:     asString(row["staging_id"]),
			CanonicalName: asString(row["canonical_name"]),
			NodeKind:      asString(row["node_kind"]),
			Detail:        "canonical_name does not match snake_case / dotted_path / kebab-case / uuid",
		}
	})
}

func lintR8NoDuplicate(ctx context.Context, env *Env, orgID, runID string) ([]stagingLintFinding, error) {
	sql := fmt.Sprintf(`SELECT canonical_name, COUNT(*) AS n
FROM staging_concepts
WHERE organization_id = '%s' AND ingestion_run_id = '%s'
GROUP BY canonical_name
HAVING COUNT(*) > 1`, sqlEscape(orgID), sqlEscape(runID))
	return runLintQuery(ctx, env, sql, "R8_no_duplicate", func(row map[string]interface{}) stagingLintFinding {
		return stagingLintFinding{
			Rule:          "R8_no_duplicate",
			CanonicalName: asString(row["canonical_name"]),
			Detail:        fmt.Sprintf("canonical_name appears %v times in this run", row["n"]),
		}
	})
}

func lintR10EdgeEndpointKinds(ctx context.Context, env *Env, orgID, runID string) ([]stagingLintFinding, error) {
	// R10: every edge endpoint must resolve to a staging_concepts row in
	// THIS run. An already-admitted object belongs to a different snapshot
	// and cannot satisfy CommitMaterializationRun's same-snapshot endpoint
	// invariant. Resolve the actual staged node_kind for both endpoints and
	// apply the edge registry's direction constraints here; promotion repeats
	// the same check before substrate I/O.
	sql := fmt.Sprintf(`SELECT e.staging_edge_id, e.edge_label, e.source_canonical_name, e.target_canonical_name,
       s.node_kind AS source_kind, t.node_kind AS target_kind
FROM staging_edges e
LEFT JOIN staging_concepts s
  ON s.organization_id=e.organization_id AND s.ingestion_run_id=e.ingestion_run_id
 AND s.canonical_name=e.source_canonical_name
LEFT JOIN staging_concepts t
  ON t.organization_id=e.organization_id AND t.ingestion_run_id=e.ingestion_run_id
 AND t.canonical_name=e.target_canonical_name
WHERE e.organization_id = '%s' AND e.ingestion_run_id = '%s'`, sqlEscape(orgID), sqlEscape(runID))
	result, err := executeStagingReadOnlyQuery(ctx, env, queryInput{SQL: sql})
	if err != nil {
		return nil, err
	}
	findings := make([]stagingLintFinding, 0)
	for _, row := range result.Rows {
		finding := stagingLintFinding{
			Rule:          "R10_edge_endpoint_kinds",
			StagingEdgeID: asString(row["staging_edge_id"]),
		}
		sourceName := asString(row["source_canonical_name"])
		targetName := asString(row["target_canonical_name"])
		sourceKind := asString(row["source_kind"])
		targetKind := asString(row["target_kind"])
		if sourceKind == "" || targetKind == "" {
			finding.Detail = fmt.Sprintf("edge %q -> %q endpoint unresolved inside this staging/materialization run", sourceName, targetName)
			findings = append(findings, finding)
			continue
		}
		labelName := asString(row["edge_label"])
		label, err := env.Edges.Resolve(ctx, labelName)
		if err != nil {
			finding.Detail = fmt.Sprintf("edge_label %q is not in the closed registry", labelName)
			findings = append(findings, finding)
			continue
		}
		if err := validateEdgeEndpointClasses(label, sourceName, sourceKind, targetName, targetKind); err != nil {
			finding.Detail = err.Error()
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func lintR12SelfLoop(ctx context.Context, env *Env, orgID, runID string) ([]stagingLintFinding, error) {
	// R12: forbid self-loops on edges whose label is in the
	// ForbidSelfLoops set per cfg.EdgeLabels. SQL builds the IN clause
	// from the live registry.
	forbidden := []string{}
	for _, l := range env.Config.EdgeLabels {
		if l.ForbidSelfLoops() {
			forbidden = append(forbidden, "'"+sqlEscape(l.Name())+"'")
		}
	}
	if len(forbidden) == 0 {
		return nil, nil
	}
	sql := fmt.Sprintf(`SELECT staging_edge_id, edge_label, source_canonical_name
FROM staging_edges
WHERE organization_id = '%s' AND ingestion_run_id = '%s'
  AND source_canonical_name = target_canonical_name
  AND edge_label IN (%s)`, sqlEscape(orgID), sqlEscape(runID), strings.Join(forbidden, ","))
	return runLintQuery(ctx, env, sql, "R12_self_loop", func(row map[string]interface{}) stagingLintFinding {
		return stagingLintFinding{
			Rule:          "R12_self_loop",
			StagingEdgeID: asString(row["staging_edge_id"]),
			Detail:        fmt.Sprintf("self-loop on edge_label %q (source = target = %q)", asString(row["edge_label"]), asString(row["source_canonical_name"])),
		}
	})
}

func lintR13NoSourceReference(ctx context.Context, env *Env, orgID, runID string) ([]stagingLintFinding, error) {
	// R13: payload/contract MUST NOT carry a source_reference field.
	sql := fmt.Sprintf(`SELECT staging_id, canonical_name, node_kind,
  CASE
    WHEN JSON_VALUE(contract, '$.source_reference') IS NOT NULL THEN 'contract.source_reference'
    WHEN JSON_VALUE(payload,  '$.source_reference') IS NOT NULL THEN 'payload.source_reference'
  END AS field_path
FROM staging_concepts
WHERE organization_id = '%s' AND ingestion_run_id = '%s'
  AND (
    JSON_VALUE(contract, '$.source_reference') IS NOT NULL
    OR JSON_VALUE(payload, '$.source_reference') IS NOT NULL
  )`, sqlEscape(orgID), sqlEscape(runID))
	return runLintQuery(ctx, env, sql, "R13_no_source_reference", func(row map[string]interface{}) stagingLintFinding {
		return stagingLintFinding{
			Rule:          "R13_no_source_reference",
			StagingID:     asString(row["staging_id"]),
			CanonicalName: asString(row["canonical_name"]),
			NodeKind:      asString(row["node_kind"]),
			FieldPath:     asString(row["field_path"]),
			Detail:        "source_reference field is an admission artifact and must not appear in authored content",
		}
	})
}

func lintR15NoAdmissionArtifacts(ctx context.Context, env *Env, orgID, runID string) ([]stagingLintFinding, error) {
	// R15: payload/contract MUST NOT carry kernel-minted admission
	// artifacts (signature_chain, compilation_certificate,
	// admission_signature, definition_hash, manifest_hash).
	forbiddenFields := []string{"signature_chain", "compilation_certificate", "admission_signature", "definition_hash", "manifest_hash"}
	conditions := []string{}
	for _, f := range forbiddenFields {
		conditions = append(conditions,
			fmt.Sprintf("JSON_VALUE(contract, '$.%s') IS NOT NULL OR JSON_VALUE(payload, '$.%s') IS NOT NULL", f, f))
	}
	sql := fmt.Sprintf(`SELECT staging_id, canonical_name, node_kind
FROM staging_concepts
WHERE organization_id = '%s' AND ingestion_run_id = '%s'
  AND (%s)`, sqlEscape(orgID), sqlEscape(runID), strings.Join(conditions, " OR "))
	return runLintQuery(ctx, env, sql, "R15_no_admission_artifacts", func(row map[string]interface{}) stagingLintFinding {
		return stagingLintFinding{
			Rule:          "R15_no_admission_artifacts",
			StagingID:     asString(row["staging_id"]),
			CanonicalName: asString(row["canonical_name"]),
			NodeKind:      asString(row["node_kind"]),
			Detail:        "payload/contract carries a kernel-minted admission-artifact field",
		}
	})
}

// stagingWalkSymbols recursively walks one contract or payload JSON
// tree and appends one spanner.Insert mutation per scalar string value
// to out. Mirrors the principle of handlers.go's extractSymbolsRecursive
// (which writes OODGraphSymbols for the admitted side); the staging
// shape is lighter (no embedding, no full identity tuple — just the
// per-field-path + value needed by R6 lint).
//
// Why this exists: Spanner's JSON_VALUE rejects a dynamic path argument
// ("Argument 2 to JSON_VALUE must be a constant expression"), so the
// lint query cannot walk arbitrary JSON keys in SQL. Pre-decomposing at
// load time mirrors the admitted-side shape (VOLT §s1_2 fractal_uniformity)
// and lets the lint query SELECT one row per (concept, field, value)
// from a flat table — same shape as bootstrap/audit/r6.sql against
// OODGraphSymbols.
func stagingWalkSymbols(val interface{}, sectionPath, orgID, runID, stagingID, canonicalName, nodeKind string, out *[]*spanner.Mutation) {
	if val == nil {
		return
	}
	switch vv := val.(type) {
	case string:
		*out = append(*out, spanner.Insert("staging_symbols",
			[]string{
				"organization_id", "ingestion_run_id", "staging_symbol_id",
				"staging_id", "canonical_name", "node_kind",
				"symbol_kind", "section_path", "search_text", "created_at",
			},
			[]interface{}{
				orgID, runID, uuid.NewString(),
				stagingID, canonicalName, nodeKind,
				"scalar_string", sectionPath, vv, spanner.CommitTimestamp,
			},
		))
	case float64:
		*out = append(*out, spanner.Insert("staging_symbols",
			[]string{
				"organization_id", "ingestion_run_id", "staging_symbol_id",
				"staging_id", "canonical_name", "node_kind",
				"symbol_kind", "section_path", "search_text", "created_at",
			},
			[]interface{}{
				orgID, runID, uuid.NewString(),
				stagingID, canonicalName, nodeKind,
				"scalar_number", sectionPath, fmt.Sprintf("%v", vv), spanner.CommitTimestamp,
			},
		))
	case bool:
		*out = append(*out, spanner.Insert("staging_symbols",
			[]string{
				"organization_id", "ingestion_run_id", "staging_symbol_id",
				"staging_id", "canonical_name", "node_kind",
				"symbol_kind", "section_path", "search_text", "created_at",
			},
			[]interface{}{
				orgID, runID, uuid.NewString(),
				stagingID, canonicalName, nodeKind,
				"scalar_bool", sectionPath, fmt.Sprintf("%v", vv), spanner.CommitTimestamp,
			},
		))
	case []interface{}:
		for i, elem := range vv {
			childPath := fmt.Sprintf("%s[%d]", sectionPath, i)
			stagingWalkSymbols(elem, childPath, orgID, runID, stagingID, canonicalName, nodeKind, out)
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(vv))
		for k := range vv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := vv[k]
			childPath := sectionPath + "." + k
			stagingWalkSymbols(child, childPath, orgID, runID, stagingID, canonicalName, nodeKind, out)
		}
	}
}

// lintR6NoProse runs R6 via ML.PREDICT against the r6_flash registered
// model — same recipe shape as bootstrap/audit/r6.sql, scoped to the
// staging run instead of the admitted graph. The prompt body is
// substituted in at query-construct time from
// bootstrap/prompts/r6_prose_check.txt (the one canonical source per
// VOLT §s1_2 reuse_by_reference).
//
// The query SELECTs from staging_symbols (the per-field-path table
// populated at load time by stagingWalkSymbols) rather than walking
// staging_concepts.payload dynamically — Spanner's JSON_VALUE path
// argument must be a constant expression, so dynamic JSON walking in
// SQL is structurally impossible. The pre-decomposition mirrors how
// the admitted-side audit recipe queries OODGraphSymbols.
func lintR6NoProse(ctx context.Context, env *Env, orgID, runID string) ([]stagingLintFinding, error) {
	promptBody, err := os.ReadFile("bootstrap/prompts/r6_prose_check.txt")
	if err != nil {
		return nil, fmt.Errorf("read prompt: %w", err)
	}
	// SAFETY: the prompt body MUST NOT contain triple-single-quotes
	// because we wrap it in a Spanner R''' raw string literal. The
	// canonical prompt has none (it uses double-quotes for examples).
	if strings.Contains(string(promptBody), "'''") {
		return nil, fmt.Errorf("prompt body contains triple-single-quote; would break R''' literal")
	}
	sql := fmt.Sprintf(`
SELECT
  staging_id, canonical_name, node_kind, section_path, value, content AS flash_response,
  CASE
    -- Match "prose" or "clean" appearing as a token either at the very
    -- start of the response, after a newline, or after the "verdict:"
    -- prefix (with optional whitespace). Flash occasionally omits the
    -- VERDICT: prefix and emits a bare "prose\nREASON: ..." line — the
    -- prior STRPOS('verdict: prose') check fell through to 'unparseable'
    -- on those, which is a classifier bug not a Flash failure.
    -- (?i) makes the match case-insensitive; \b enforces word-boundary
    -- so "prose" doesn't false-match "prosecution" etc.
    WHEN REGEXP_CONTAINS(content, r'(?im)(^|\n)\s*(verdict:\s*)?prose\b') THEN 'prose'
    WHEN REGEXP_CONTAINS(content, r'(?im)(^|\n)\s*(verdict:\s*)?clean\b') THEN 'clean'
    ELSE 'unparseable'
  END AS verdict
FROM ML.PREDICT(
  MODEL r6_flash,
  (
    SELECT
      s.staging_id, s.canonical_name, s.node_kind, s.section_path,
      s.search_text AS value,
      CONCAT(
        R'''%s''',
        '\n\nVALUE UNDER AUDIT (delimited by <<<>>>):\n<<<',
        s.search_text,
        '>>>\n\n',
        'CONTEXT (informational only):\n',
        '  field_path:     ', s.section_path, '\n',
        '  canonical_name: ', s.canonical_name, '\n',
        '  node_kind:      ', s.node_kind
      ) AS prompt
    FROM staging_symbols s
    WHERE s.organization_id = '%s' AND s.ingestion_run_id = '%s'
      AND s.symbol_kind = 'scalar_string'
      AND s.search_text IS NOT NULL
      AND s.search_text != ''
      AND STRPOS(s.search_text, ' ') > 0
  ),
  STRUCT(256 AS maxOutputTokens, 0.0 AS temperature, 40 AS topK, 0.95 AS topP)
)
WHERE NOT REGEXP_CONTAINS(content, r'(?im)(^|\n)\s*(verdict:\s*)?clean\b')`,
		// NOTE on concurrency: a prior commit of this query carried the
		// hint @{remote_udf_max_outstanding_rpcs=64} sourced from a third-
		// party Medium article. Spanner's runtime recognizes the hint name
		// but rejected the value 64 with "Invalid hint value for: ...".
		// The hint is NOT documented in any official Google Cloud Spanner
		// reference (ml-functions, query-syntax, cloud-run-remote-function
		// — all checked 2026-05-28); the only documented remote-function
		// concurrency knob is `max_batching_rows` on the CREATE MODEL DDL,
		// which is single-row for Gemini's no-batch contract anyway. We
		// rely on Spanner's automatic parallelism here. If throughput
		// becomes a problem on large staging runs, the next move is to
		// search Google's spanner-tools internal channels for the correct
		// hint syntax — not guess values for a hint with no official spec.
		string(promptBody), sqlEscape(orgID), sqlEscape(runID))

	return runLintQuery(ctx, env, sql, "R6_no_prose", func(row map[string]interface{}) stagingLintFinding {
		verdict := asString(row["verdict"])
		detail := "R6 flash verdict: " + verdict
		if reason := asString(row["flash_response"]); reason != "" && len(reason) < 400 {
			detail += " — " + strings.TrimSpace(reason)
		}
		// section_path is stored as the JSONPath form ($.payload.foo) the
		// walker emits. spec-lint's in-process R6 detector emits the
		// dotted form (payload.foo) without the leading $. Trim the
		// prefix here so both surfaces report a consistent field_path
		// to downstream consumers (VOLT §s1_2 fractal_uniformity).
		fieldPath := strings.TrimPrefix(asString(row["section_path"]), "$.")
		return stagingLintFinding{
			Rule:          "R6_no_prose",
			StagingID:     asString(row["staging_id"]),
			CanonicalName: asString(row["canonical_name"]),
			NodeKind:      asString(row["node_kind"]),
			FieldPath:     fieldPath,
			Observed:      truncate(asString(row["value"]), 200),
			Detail:        detail,
		}
	})
}

// ---------------- helpers ----------------

// stagingAdapter resolves the one substrate that owns the OODGraph object
// table. Staging tables are co-located with that substrate, so every staging
// read and write must use this same owner. SubstrateRouter.All has no stable
// ordering (configRouter is map-backed) and therefore cannot safely select a
// staging database by taking element zero.
func stagingAdapter(env *Env) (SubstrateAdapter, error) {
	if env == nil || env.Substrates == nil {
		return nil, fmt.Errorf("no substrates registered")
	}
	_, ownerID, err := substrateTableAndOwner(env, func(s SubstrateDescriptor) string { return s.ObjectTable }, "object_table")
	if err != nil {
		return nil, err
	}
	return env.Substrates.ByID(ownerID)
}

// executeStagingReadOnlyQuery preserves spec_graph_query's experimental-mode
// and read-only gates while routing to the configured OODGraph/staging owner
// instead of an arbitrary first adapter.
func executeStagingReadOnlyQuery(ctx context.Context, env *Env, in queryInput) (QueryResult, error) {
	_, ownerID, err := substrateTableAndOwner(env, func(s SubstrateDescriptor) string { return s.ObjectTable }, "object_table")
	if err != nil {
		return QueryResult{}, err
	}
	return handleQueryOnSubstrate(ctx, env, in, ownerID)
}

func stagingClient(ctx context.Context, env *Env) (*spanner.Client, error) {
	resolved, err := stagingAdapter(env)
	if err != nil {
		return nil, err
	}
	adapter, ok := resolved.(*SpannerSubstrateAdapter)
	if !ok {
		return nil, fmt.Errorf("substrate %q is not a SpannerSubstrateAdapter", resolved.ID())
	}
	return adapter.getClient(ctx)
}

func stagingRunCounts(ctx context.Context, env *Env, orgID, runID string) (int, int, error) {
	client, err := stagingClient(ctx, env)
	if err != nil {
		return 0, 0, err
	}
	// Spanner COUNT(*) returns INT64; reading into a Go `int` via
	// row.Columns silently fails (Columns returns an error that we
	// discard via `_ =`, leaving the destination at its zero value).
	// Read into int64 and cast.
	var cConcepts int64
	var cEdges int64
	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `SELECT
  (SELECT COUNT(*) FROM staging_concepts WHERE organization_id = @org AND ingestion_run_id = @run) AS c,
  (SELECT COUNT(*) FROM staging_edges    WHERE organization_id = @org AND ingestion_run_id = @run) AS e`,
		Params: map[string]interface{}{"org": orgID, "run": runID},
	})
	defer iter.Stop()
	if row, err := iter.Next(); err == nil {
		if err := row.Columns(&cConcepts, &cEdges); err != nil {
			return 0, 0, fmt.Errorf("decode counts: %w", err)
		}
	} else if err != iterator.Done {
		return 0, 0, err
	}
	return int(cConcepts), int(cEdges), nil
}

func runLintQuery(ctx context.Context, env *Env, sql, rule string, build func(map[string]interface{}) stagingLintFinding) ([]stagingLintFinding, error) {
	res, err := executeStagingReadOnlyQuery(ctx, env, queryInput{SQL: sql})
	if err != nil {
		return nil, err
	}
	findings := make([]stagingLintFinding, 0, len(res.Rows))
	for _, row := range res.Rows {
		findings = append(findings, build(row))
	}
	return findings, nil
}

func stagingUpdateLintStatus(ctx context.Context, env *Env, orgID, runID string, findings []stagingLintFinding) error {
	client, err := stagingClient(ctx, env)
	if err != nil {
		return err
	}
	// Rule fail-class split (R6 is advisory, structural rules block):
	//
	// R6_no_prose is a Flash-based semantic check whose prompt has a
	// known false-positive rate on legitimate single-clause invariants
	// (the 4-of-4 prose verdicts on volt_secret_detection's first
	// real ingestion are the working example). Treating R6 as blocking
	// means almost nothing promotes through the substrate, which
	// defeats the substrate's purpose.
	//
	// New posture: lint_findings carries every finding from every
	// rule (including R6) — full audit context is preserved. But
	// lint_status='fail' fires ONLY when at least one STRUCTURAL rule
	// finding exists (R3, R4, R5, R7, R8, R10, R12, R13, R15). R6
	// findings alone leave the row at lint_status='pass'; promote
	// admits the row; an operator (or a future Stage-4 rewrite agent)
	// can inspect lint_findings to decide whether the prose is real.
	//
	// Structural rules are deterministic SQL checks against the closed
	// kind/edge registry; they don't false-positive — when they fire,
	// the row really IS wrong. Those still block.
	advisoryRules := map[string]bool{
		"R6_no_prose": true,
	}

	byID := map[string][]stagingLintFinding{}
	hardFailByID := map[string]bool{}
	byEdgeID := map[string][]stagingLintFinding{}
	hardFailByEdgeID := map[string]bool{}
	for _, f := range findings {
		if f.StagingID != "" {
			byID[f.StagingID] = append(byID[f.StagingID], f)
			if !advisoryRules[f.Rule] {
				hardFailByID[f.StagingID] = true
			}
		}
		if f.StagingEdgeID != "" {
			byEdgeID[f.StagingEdgeID] = append(byEdgeID[f.StagingEdgeID], f)
			if !advisoryRules[f.Rule] {
				hardFailByEdgeID[f.StagingEdgeID] = true
			}
		}
	}
	muts := []*spanner.Mutation{}
	ro := client.ReadOnlyTransaction()
	defer ro.Close()

	iter := ro.Query(ctx, spanner.Statement{
		SQL:    "SELECT staging_id FROM staging_concepts WHERE organization_id = @org AND ingestion_run_id = @run",
		Params: map[string]interface{}{"org": orgID, "run": runID},
	})
	defer iter.Stop()
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		var sid string
		if err := row.Columns(&sid); err != nil {
			return err
		}
		status := "pass"
		if hardFailByID[sid] {
			status = "fail"
		}
		var findingsJSON spanner.NullJSON
		if items, ok := byID[sid]; ok && len(items) > 0 {
			if raw, err := json.Marshal(items); err == nil {
				findingsJSON = spanner.NullJSON{Value: json.RawMessage(raw), Valid: true}
			}
		}
		muts = append(muts, spanner.Update("staging_concepts",
			[]string{"organization_id", "ingestion_run_id", "staging_id", "lint_status", "lint_findings", "pipeline_state", "updated_at"},
			[]interface{}{orgID, runID, sid, status, findingsJSON, "linted", spanner.CommitTimestamp},
		))
	}

	edgeIter := ro.Query(ctx, spanner.Statement{
		SQL:    "SELECT staging_edge_id FROM staging_edges WHERE organization_id = @org AND ingestion_run_id = @run",
		Params: map[string]interface{}{"org": orgID, "run": runID},
	})
	defer edgeIter.Stop()
	for {
		row, err := edgeIter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		var sid string
		if err := row.Columns(&sid); err != nil {
			return err
		}
		status := "pass"
		if hardFailByEdgeID[sid] {
			status = "fail"
		}
		var findingsJSON spanner.NullJSON
		if items, ok := byEdgeID[sid]; ok && len(items) > 0 {
			if raw, err := json.Marshal(items); err == nil {
				findingsJSON = spanner.NullJSON{Value: json.RawMessage(raw), Valid: true}
			}
		}
		muts = append(muts, spanner.Update("staging_edges",
			[]string{"organization_id", "ingestion_run_id", "staging_edge_id", "lint_status", "lint_findings", "pipeline_state", "updated_at"},
			[]interface{}{orgID, runID, sid, status, findingsJSON, "linted", spanner.CommitTimestamp},
		))
	}

	return applyStagingMutationsChunked(ctx, client, muts)
}

func stagingFetchPromotionRows(ctx context.Context, env *Env, orgID, runID string) ([]StagingConcept, int, []StagingEdge, error) {
	client, err := stagingClient(ctx, env)
	if err != nil {
		return nil, 0, nil, err
	}
	reader := client.ReadOnlyTransaction()
	defer reader.Close()
	concepts, skipped, err := stagingFetchLintedConcepts(ctx, reader, env, orgID, runID)
	if err != nil {
		return nil, 0, nil, err
	}
	edges, err := stagingFetchPromotableEdges(ctx, reader, orgID, runID)
	if err != nil {
		return nil, 0, nil, err
	}
	return concepts, skipped, edges, nil
}

func stagingFetchLintedConcepts(ctx context.Context, queryer spannerStatementQueryer, env *Env, orgID, runID string) ([]StagingConcept, int, error) {
	out := []StagingConcept{}
	// SELECTs every non-promoted row of the run (NO lint or dedup
	// filter in the SQL) so the in-Go classifier sees BOTH dedup-skip
	// and lint-fail exclusions and counts them correctly. The prior
	// version put the lint filter in the SQL, which meant rows that
	// were BOTH lint-failing and dedup-duplicate got filtered out by
	// SQL before the skipped-as-duplicate counter incremented —
	// concepts_skipped_duplicate_of_admitted under-reported whenever
	// a duplicate row also happened to fail lint.
	iter := queryer.Query(ctx, spanner.Statement{
		SQL: `SELECT staging_id, canonical_name, node_kind, contract, payload, source_file, source_path, source_coordinate, source_verification_receipt,
	   dedup_status,
	   lint_status, pipeline_state
FROM staging_concepts
WHERE organization_id = @org AND ingestion_run_id = @run
  AND pipeline_state != 'promoted'`,
		Params: map[string]interface{}{"org": orgID, "run": runID},
	})
	defer iter.Stop()
	skipped := 0
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		var c StagingConcept
		var contract, payload spanner.NullJSON
		var sourceFile, sourcePath spanner.NullString
		var sourceCoordinate, sourceReceipt spanner.NullJSON
		var dedupStatus, lintStatus spanner.NullString
		if err := row.Columns(&c.StagingID, &c.CanonicalName, &c.NodeKind, &contract, &payload, &sourceFile, &sourcePath, &sourceCoordinate, &sourceReceipt, &dedupStatus, &lintStatus, &c.PipelineState); err != nil {
			return nil, 0, err
		}
		// Duplicate-of-admitted is counted regardless of lint outcome
		// — a row that is BOTH a duplicate AND lint-failing is
		// counted as one skipped duplicate, not as two skips. The
		// dedup decision is the authoritative reason to skip when it
		// fires; lint failure on a duplicate is moot because the row
		// is held in staging either way.
		isDuplicate := dedupStatus.Valid && (dedupStatus.StringVal == "auto_merge_candidate" || dedupStatus.StringVal == "verified_same")
		// An external exact-coordinate+digest replay is a new verification
		// occurrence even though it is not new semantic object material. Keep
		// it promotable so its v3 receipt can renew the selected snapshot's
		// run-scoped freshness. Other duplicate classes remain skip-only.
		externalExactReplay := dedupStatus.Valid && dedupStatus.StringVal == "auto_merge_candidate" && sourceReceipt.Valid
		if isDuplicate && !externalExactReplay {
			skipped++
			continue
		}
		// Promotion is an all-or-none materialization. A non-duplicate row is
		// eligible only after lint explicitly produced pass and advanced the
		// row to linted; fail, NULL, and every other state reject the run.
		if !lintStatus.Valid || lintStatus.StringVal != "pass" || c.PipelineState != "linted" {
			return nil, 0, fmt.Errorf("staging_id=%q is not clean+linted (lint_status=%q pipeline_state=%q)", c.StagingID, lintStatus.StringVal, c.PipelineState)
		}
		c.OrganizationID = orgID
		c.IngestionRunID = runID
		if contract.Valid {
			c.Contract = jsonValueToMap(contract.Value)
		}
		if payload.Valid {
			c.Payload = jsonValueToMap(payload.Value)
		}
		c.SourceFile = sourceFile.StringVal
		c.SourcePath = sourcePath.StringVal
		if sourceCoordinate.Valid {
			decoded, err := sourceCoordinateFromJSON(sourceCoordinate.Value)
			if err != nil {
				return nil, 0, fmt.Errorf("staging_id=%q: %w", c.StagingID, err)
			}
			desc, err := env.Kinds.Resolve(ctx, c.NodeKind)
			if err != nil {
				return nil, 0, fmt.Errorf("staging_id=%q: resolve node_kind: %w", c.StagingID, err)
			}
			if desc.ExternalReferenceRequired() {
				resolved, err := resolveArtifactSourceCoordinate(c.NodeKind, c.CanonicalName, desc, decoded)
				if err != nil {
					return nil, 0, fmt.Errorf("staging_id=%q: invalid source_coordinate at promotion: %w", c.StagingID, err)
				}
				if !sourceReceipt.Valid {
					return nil, 0, fmt.Errorf("staging_id=%q: external row lacks load-time verification receipt", c.StagingID)
				}
				receipt, receiptErr := stagedExternalReceiptFromJSON(sourceReceipt.Value)
				if receiptErr != nil {
					return nil, 0, fmt.Errorf("staging_id=%q: %w", c.StagingID, receiptErr)
				}
				c.SourceVerificationReceipt = receipt
				c.SourceCoordinate = &resolved
			} else {
				if sourceReceipt.Valid {
					return nil, 0, fmt.Errorf("staging_id=%q: ordinary row carries forbidden external verification receipt", c.StagingID)
				}
				want, wantErr := resolveArtifactSourceCoordinate(c.NodeKind, c.CanonicalName, desc, nil)
				if wantErr != nil || decoded == nil || *decoded != want {
					return nil, 0, fmt.Errorf("staging_id=%q: ordinary row source_coordinate is not the canonical internal bootstrap coordinate", c.StagingID)
				}
				// handleImport owns ordinary-coordinate derivation. Passing the
				// internal persisted coordinate back as caller input would be
				// rejected correctly as an external-only override.
				c.SourceCoordinate = nil
			}
		} else {
			return nil, 0, fmt.Errorf("staging_id=%q: source_coordinate missing", c.StagingID)
		}
		out = append(out, c)
	}
	return out, skipped, nil
}

// stagingFetchPromotableEdges returns every clean, linted edge in canonical
// relationship order. A failed or never-linted edge blocks promotion rather
// than being silently dropped: the graph snapshot must be an all-or-none
// materialization of the staged external corpus and its traversal paths.
func stagingFetchPromotableEdges(ctx context.Context, queryer spannerStatementQueryer, orgID, runID string) ([]StagingEdge, error) {
	iter := queryer.Query(ctx, spanner.Statement{
		SQL: `SELECT staging_edge_id, edge_label, source_canonical_name, target_canonical_name,
       lint_status, pipeline_state
FROM staging_edges
WHERE organization_id = @org AND ingestion_run_id = @run
  AND pipeline_state != 'promoted'
ORDER BY source_canonical_name, edge_label, target_canonical_name`,
		Params: map[string]interface{}{"org": orgID, "run": runID},
	})
	defer iter.Stop()
	out := []StagingEdge{}
	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		var edge StagingEdge
		var lintStatus spanner.NullString
		if err := row.Columns(&edge.StagingEdgeID, &edge.EdgeLabel, &edge.SourceCanonicalName, &edge.TargetCanonicalName, &lintStatus, &edge.PipelineState); err != nil {
			return nil, err
		}
		if !lintStatus.Valid || lintStatus.StringVal != "pass" || edge.PipelineState != "linted" {
			return nil, fmt.Errorf("staging_edge_id=%q is not clean+linted (lint_status=%q pipeline_state=%q)", edge.StagingEdgeID, lintStatus.StringVal, edge.PipelineState)
		}
		edge.OrganizationID = orgID
		edge.IngestionRunID = runID
		out = append(out, edge)
	}
	return out, nil
}

// jsonValueToMap normalizes a spanner.NullJSON.Value into a Go map.
// Spanner's client decodes a JSON column into the parsed Go form
// (map[string]interface{} for objects, []interface{} for arrays, or
// a scalar) — not raw bytes. The fast path is direct type-assertion
// to map. For non-object shapes the fallback marshals then unmarshals
// — never panics, never silently produces wrong data.
func jsonValueToMap(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	return out
}

func toNullableJSON(v map[string]interface{}) (spanner.NullJSON, error) {
	if v == nil || len(v) == 0 {
		return spanner.NullJSON{Valid: false}, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return spanner.NullJSON{Valid: false}, err
	}
	return spanner.NullJSON{Value: json.RawMessage(raw), Valid: true}, nil
}

func stagedExternalReceiptToNullJSON(receipt *stagedExternalVerificationReceipt) (spanner.NullJSON, error) {
	if receipt == nil {
		return spanner.NullJSON{Valid: false}, nil
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return spanner.NullJSON{Valid: false}, fmt.Errorf("encode staged external verification receipt: %w", err)
	}
	return spanner.NullJSON{Value: json.RawMessage(raw), Valid: true}, nil
}

func stagedExternalReceiptFromJSON(v interface{}) (*stagedExternalVerificationReceipt, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("encode staged external verification receipt: %w", err)
	}
	if err := rejectDuplicateJSONKeysRecursive(raw, "source_verification_receipt"); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var receipt stagedExternalVerificationReceipt
	if err := dec.Decode(&receipt); err != nil {
		return nil, fmt.Errorf("decode staged external verification receipt: %w", err)
	}
	return &receipt, nil
}

func asString(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// Avoid unused-import errors when staging.go is built before usage.
var _ = time.Now
