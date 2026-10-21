-- spec-graph schema v2 — OOD_GRAPH_PROTOCOL_v1 alignment
--
-- TRANSCRIBED VERBATIM from OOD_GRAPH_PROTOCOL_v1.ood.json
-- §6.spanner_ddl_model.statements (doc_id 767c2399-87f9-4859-ac64-afb575bdb263).
--
-- Column formatting is reflowed for readability; every column type, every
-- OPTIONS clause, every column name, every PRIMARY KEY ordering, and every
-- index definition is preserved byte-equivalent to the protocol statement.
-- DO NOT improve, simplify, rename, or reorder anything in this file without
-- amending OOD_GRAPH_PROTOCOL_v1 first.
--
-- Applied by `spec-graph init` against the configured experimental Spanner
-- database. REFUSES against production databases by the
-- doc-graph allowlist enforced in cmd_init.go.
--
-- Replaces schema_v1.sql (3-table VOLT-style storage). The protocol mandates
-- 7 dedicated OOD-Graph-owned tables; this file is the storage substrate
-- for the §8 19-stage materialization pipeline. Per spec-graph (C) decision
-- 2026-05-27: the prior doc-graph corpus is dropped, not migrated.
--
-- The §7 CREATE PROPERTY GRAPH OODGraph projection is declared at the foot of
-- this file. The Spanner emulator does not support CREATE PROPERTY GRAPH, but
-- the emulator harness does not read this file — integration_test.go builds its
-- own `integrationSchema` slice — so declaring it here breaks nothing.
--
-- DEFERRED to later phases:
--   - §6.retrieval_index_storage vector indexes over OODGraphObjects.embedding
--     and OODGraphSymbols.embedding (declared MAY in protocol; KNN works
--     without indexes; ANN deferred to retrieval phase)
--   - CREATE SEARCH INDEX over search_text_tokens / search_payload_tokens
--     (§6.retrieval_index_storage.spanner_capability_alignment.search_index_columns)


-- ---------- OODGraphSnapshots ----------
-- §6.table_surfaces.ood_graph_snapshots
-- Names one materialized OOD Graph version for one organization and source set.

CREATE TABLE OODGraphSnapshots (
  organization_id         STRING(36)  NOT NULL,
  graph_snapshot_id       STRING(36)  NOT NULL,
  graph_version           INT64       NOT NULL,
  snapshot_kind           STRING(32)  NOT NULL,
  source_set_hash         STRING(128) NOT NULL,
  source_set              JSON        NOT NULL,
  materialization_run_id  STRING(36),
  snapshot_state          STRING(32)  NOT NULL,
  status                  STRING(32)  NOT NULL,
  visibility_scope        STRING(32)  NOT NULL,
  sealed_at               TIMESTAMP,
  created_at              TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
  updated_at              TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, graph_snapshot_id);


-- ---------- OODGraphObjects ----------
-- §6.table_surfaces.ood_graph_objects
-- Stores graph-owned object vertices from the closed s2 object class set.

CREATE TABLE OODGraphObjects (
  organization_id            STRING(36)   NOT NULL,
  graph_snapshot_id          STRING(36)   NOT NULL,
  graph_object_id            STRING(36)   NOT NULL,
  object_class               STRING(64)   NOT NULL,
  source_authority_id        STRING(36)   NOT NULL,
  source_artifact_class      STRING(64)   NOT NULL,
  source_ref_kind            STRING(32)   NOT NULL,
  source_stable_reference    STRING(2048) NOT NULL,
  version_coordinate         STRING(1024) NOT NULL,
  section_path               STRING(2048) NOT NULL,
  graph_address              STRING(4096) NOT NULL,
  source_content_hash        STRING(128),
  source_content_hash_owner  STRING(36),
  materialization_run_id     STRING(36)   NOT NULL,
  projection_role            STRING(64)   NOT NULL,
  validation_state           STRING(32)   NOT NULL,
  status                     STRING(32)   NOT NULL,
  visibility_scope           STRING(32)   NOT NULL,
  search_text                STRING(MAX),
  search_payload             JSON,
  search_text_tokens         TOKENLIST AS (TOKENIZE_FULLTEXT(search_text)) HIDDEN,
  search_payload_tokens      TOKENLIST AS (TOKENIZE_JSON(search_payload)) HIDDEN,
  embedding                  ARRAY<FLOAT32>(vector_length=>3072),
  embedding_model            STRING(128)  NOT NULL,
  created_at                 TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
  updated_at                 TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, graph_snapshot_id, graph_object_id);


-- ---------- OODGraphSymbols ----------
-- §6.table_surfaces.ood_graph_symbols
-- Stores graph-owned addressable symbols under graph objects and version coordinates.

CREATE TABLE OODGraphSymbols (
  organization_id          STRING(36)   NOT NULL,
  graph_snapshot_id        STRING(36)   NOT NULL,
  symbol_id                STRING(36)   NOT NULL,
  graph_object_id          STRING(36)   NOT NULL,
  object_class             STRING(64)   NOT NULL,
  symbol_kind              STRING(64)   NOT NULL,
  symbol_name              STRING(1024) NOT NULL,
  source_authority_id      STRING(36)   NOT NULL,
  source_stable_reference  STRING(2048) NOT NULL,
  version_coordinate       STRING(1024) NOT NULL,
  section_path             STRING(2048) NOT NULL,
  graph_address            STRING(4096) NOT NULL,
  materialization_run_id   STRING(36)   NOT NULL,
  validation_state         STRING(32)   NOT NULL,
  status                   STRING(32)   NOT NULL,
  visibility_scope         STRING(32)   NOT NULL,
  search_text              STRING(MAX),
  search_payload           JSON,
  search_text_tokens       TOKENLIST AS (TOKENIZE_FULLTEXT(search_text)) HIDDEN,
  search_payload_tokens    TOKENLIST AS (TOKENIZE_JSON(search_payload)) HIDDEN,
  embedding                ARRAY<FLOAT32>(vector_length=>3072),
  embedding_model          STRING(128)  NOT NULL,
  created_at               TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
  updated_at               TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, graph_snapshot_id, symbol_id);


-- ---------- OODGraphEdges ----------
-- §6.table_surfaces.ood_graph_edges
-- Stores graph-owned typed directed edges over resolved OODGraphObjects.graph_object_id endpoints.
-- Symbol candidates must resolve or promote to OODGraphObjects rows before active edge insertion.

CREATE TABLE OODGraphEdges (
  organization_id            STRING(36)   NOT NULL,
  graph_snapshot_id          STRING(36)   NOT NULL,
  graph_edge_id              STRING(36)   NOT NULL,
  source_endpoint_kind       STRING(16)   NOT NULL,
  source_endpoint_id         STRING(36)   NOT NULL,
  source_endpoint_class      STRING(64)   NOT NULL,
  target_endpoint_kind       STRING(16)   NOT NULL,
  target_endpoint_id         STRING(36)   NOT NULL,
  target_endpoint_class      STRING(64)   NOT NULL,
  edge_label                 STRING(64)   NOT NULL,
  edge_family                STRING(64)   NOT NULL,
  source_version_coordinate  STRING(1024) NOT NULL,
  target_version_coordinate  STRING(1024) NOT NULL,
  authoring_source_path      STRING(2048) NOT NULL,
  source_authority_id        STRING(36)   NOT NULL,
  source_stable_reference    STRING(2048) NOT NULL,
  source_content_hash        STRING(128),
  valid_from                 TIMESTAMP,
  valid_until                TIMESTAMP,
  diagnostic_only            BOOL         NOT NULL,
  reciprocity_state          STRING(32)   NOT NULL,
  inverse_edge_id            STRING(36),
  edge_confidence            FLOAT32,
  materialization_run_id     STRING(36)   NOT NULL,
  validation_state           STRING(32)   NOT NULL,
  status                     STRING(32)   NOT NULL,
  visibility_scope           STRING(32)   NOT NULL,
  search_text                STRING(MAX),
  search_payload             JSON,
  search_text_tokens         TOKENLIST AS (TOKENIZE_FULLTEXT(search_text)) HIDDEN,
  search_payload_tokens      TOKENLIST AS (TOKENIZE_JSON(search_payload)) HIDDEN,
  embedding                  ARRAY<FLOAT32>(vector_length=>3072),
  embedding_model            STRING(128)  NOT NULL,
  created_at                 TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
  updated_at                 TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, graph_snapshot_id, graph_edge_id);


-- ---------- OODGraphMaterializationRuns ----------
-- §6.table_surfaces.ood_graph_materialization_runs
-- Stores materialization run state written by s8-owned procedures.

CREATE TABLE OODGraphMaterializationRuns (
  organization_id           STRING(36)  NOT NULL,
  materialization_run_id    STRING(36)  NOT NULL,
  target_graph_snapshot_id  STRING(36),
  run_kind                  STRING(64)  NOT NULL,
  input_source_set_hash     STRING(128) NOT NULL,
  input_source_set          JSON        NOT NULL,
  state                     STRING(32)  NOT NULL,
  started_at                TIMESTAMP   NOT NULL,
  finished_at               TIMESTAMP,
  object_count              INT64       NOT NULL,
  symbol_count              INT64       NOT NULL,
  edge_count                INT64       NOT NULL,
  violation_count           INT64       NOT NULL,
  status                    STRING(32)  NOT NULL,
  visibility_scope          STRING(32)  NOT NULL,
  created_at                TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
  updated_at                TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, materialization_run_id);


-- ---------- OODGraphViolations ----------
-- §6.table_surfaces.ood_graph_violations
-- Stores OOD-Graph-owned conformance and storage violations emitted by
-- materialization, projection, retrieval, and corpus-conformance paths.

CREATE TABLE OODGraphViolations (
  organization_id          STRING(36)   NOT NULL,
  violation_id             STRING(36)   NOT NULL,
  graph_snapshot_id        STRING(36),
  materialization_run_id   STRING(36),
  violation_code           STRING(128)  NOT NULL,
  sentinel_candidate       STRING(128),
  severity                 STRING(32)   NOT NULL,
  source_authority_id      STRING(36),
  source_stable_reference  STRING(2048),
  version_coordinate       STRING(1024),
  section_path             STRING(2048),
  graph_object_id          STRING(36),
  symbol_id                STRING(36),
  graph_edge_id            STRING(36),
  evidence                 JSON         NOT NULL,
  status                   STRING(32)   NOT NULL,
  visibility_scope         STRING(32)   NOT NULL,
  created_at               TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
  updated_at               TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, violation_id);


-- ---------- OODGraphProjectionArtifacts ----------
-- §6.table_surfaces.ood_graph_projection_artifacts
-- Stores deterministic projection artifacts and their bindings to graph snapshots.

CREATE TABLE OODGraphProjectionArtifacts (
  organization_id         STRING(36)  NOT NULL,
  projection_artifact_id  STRING(36)  NOT NULL,
  graph_snapshot_id       STRING(36)  NOT NULL,
  projection_kind         STRING(64)  NOT NULL,
  projection_target_kind  STRING(64)  NOT NULL,
  projection_target_id    STRING(36),
  projection_format       STRING(64)  NOT NULL,
  projection_hash         STRING(128) NOT NULL,
  projection_payload      JSON        NOT NULL,
  round_trip_state        STRING(32)  NOT NULL,
  materialization_run_id  STRING(36),
  status                  STRING(32)  NOT NULL,
  visibility_scope        STRING(32)  NOT NULL,
  created_at              TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
  updated_at              TIMESTAMP   NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, projection_artifact_id);


-- ---------- Indexes ----------
-- §6.spanner_ddl_model.statements: 14 indexes covering uniqueness enforcement
-- (per §6.identity_and_uniqueness_constraints) + lookup paths used by §10
-- retrieval contracts and §9 temporal traversal.

CREATE UNIQUE INDEX OODGraphSnapshotsByVersion
  ON OODGraphSnapshots (organization_id, graph_version);

CREATE INDEX OODGraphSnapshotsByStateVersion
  ON OODGraphSnapshots (organization_id, snapshot_kind, snapshot_state, graph_version);

CREATE UNIQUE INDEX OODGraphObjectsByAddress
  ON OODGraphObjects (organization_id, graph_snapshot_id, graph_address);

CREATE UNIQUE INDEX OODGraphObjectsByIdentityTuple
  ON OODGraphObjects (organization_id, graph_snapshot_id, object_class, source_authority_id, source_ref_kind, source_stable_reference, version_coordinate, section_path);

CREATE UNIQUE INDEX OODGraphSymbolsByAddress
  ON OODGraphSymbols (organization_id, graph_snapshot_id, graph_address);

CREATE UNIQUE INDEX OODGraphSymbolsByIdentityTuple
  ON OODGraphSymbols (organization_id, graph_snapshot_id, object_class, source_authority_id, source_stable_reference, version_coordinate, section_path, symbol_kind, symbol_name);

CREATE UNIQUE INDEX OODGraphEdgesByIdentityTuple
  ON OODGraphEdges (organization_id, graph_snapshot_id, source_endpoint_kind, source_endpoint_id, target_endpoint_kind, target_endpoint_id, edge_label, source_version_coordinate, target_version_coordinate, authoring_source_path, source_authority_id, source_stable_reference);

CREATE INDEX OODGraphEdgesBySource
  ON OODGraphEdges (organization_id, graph_snapshot_id, source_endpoint_kind, source_endpoint_id, edge_label);

CREATE INDEX OODGraphEdgesByTarget
  ON OODGraphEdges (organization_id, graph_snapshot_id, target_endpoint_kind, target_endpoint_id, edge_label);

CREATE INDEX OODGraphEdgesByReciprocity
  ON OODGraphEdges (organization_id, graph_snapshot_id, edge_label, reciprocity_state, inverse_edge_id);

CREATE INDEX OODGraphObjectsBySourceReference
  ON OODGraphObjects (organization_id, source_authority_id, source_ref_kind, source_stable_reference, version_coordinate);

CREATE INDEX OODGraphSymbolsByObject
  ON OODGraphSymbols (organization_id, graph_snapshot_id, graph_object_id, symbol_kind);

CREATE INDEX OODGraphViolationsBySnapshot
  ON OODGraphViolations (organization_id, graph_snapshot_id, severity, violation_code);

CREATE INDEX OODGraphProjectionArtifactsBySnapshot
  ON OODGraphProjectionArtifacts (organization_id, graph_snapshot_id, projection_kind, projection_format);


-- ====================================================================
-- ====================  STAGING SUBSTRATE  ===========================
-- ====================================================================
--
-- Staging tables hold in-flight concepts and edges between the moment
-- spec-extract emits them and the moment spec-admit promotes them into
-- the admitted OODGraph* tables above. Replaces the prior per-stage
-- JSON-file pipeline (spec-cluster → spec-dedup-verify → spec-lint →
-- spec-admit, each a Go binary reading/writing a JSON artifact) with a
-- single in-Spanner state machine that every MCP tool advances via SQL.
--
-- Architectural rationale per VOLT §s1_2:
--   - binary_is_never_sot: behavioral thresholds and registries stay in
--     config. Identity replay reads one eligible current-profile snapshot;
--     OOD retrieval metadata never substitutes for source payload content.
--   - reuse_by_reference: every stage cites the same staging row by
--     (ingestion_run_id, staging_id); no JSON file artifact between
--     stages forks the definition.
--   - fail_closed: every stage's failure populates the row's stage
--     status + findings columns; a row that did not advance is visible
--     in its own state, never silently dropped.
--
-- Lifecycle of one row in staging_concepts (column: pipeline_state):
--   extracted        — spec-extract loaded the concept; embedding NULL
--   embedded         — embedding column populated via ML.PREDICT
--   clustered        — exact source identity/digest replay decided against
--                      one eligible current-profile snapshot
--   dedup_verified   — legacy state only; semantic verification is
--                      fail-closed pending a sanctioned source resolver
--   linted           — lint_status pass|fail; lint_findings populated
--   promoted         — admitted to OODGraphObjects in same Spanner
--                      ReadWriteTransaction that flipped the state
--   rejected         — terminal failure (e.g. lint_status='fail' that
--                      the operator chose not to fix)
--
-- The state column is the single source of truth for what stage a row
-- is in; every MCP tool reads it as a filter and writes the next state
-- in the same transaction that performs the stage's work.

CREATE TABLE staging_concepts (
  organization_id         STRING(36)   NOT NULL,
  ingestion_run_id        STRING(36)   NOT NULL,
  staging_id              STRING(36)   NOT NULL,
  canonical_name          STRING(2048) NOT NULL,
  node_kind               STRING(64)   NOT NULL,
  contract                JSON,
  payload                 JSON,
  source_file             STRING(1024),
  source_path             STRING(2048),
  source_coordinate       JSON,
  -- Process-minted load-time external-byte/locator attestation. Promotion
  -- validates this receipt and freshness without issuing a second GET.
  source_verification_receipt JSON,
  embedding               ARRAY<FLOAT32>(vector_length=>3072),
  embedding_model         STRING(128),
  cluster_id              STRING(36),
  dedup_status            STRING(32),
  dedup_decision          JSON,
  lint_status             STRING(32),
  lint_findings           JSON,
  pipeline_state          STRING(32)   NOT NULL,
  promoted_graph_object_id STRING(36),
  created_at              TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
  updated_at              TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, ingestion_run_id, staging_id);


-- staging_edges: in-flight edges keyed by source/target canonical_name
-- (NOT by graph_object_id, because the source and target may both still
-- be staged rows whose graph_object_id is not yet minted). Resolved to
-- OODGraphEdges-shape ids at promotion time via JOIN with staging_concepts
-- on canonical_name → promoted_graph_object_id, OR against
-- OODGraphObjects.source_stable_reference for edges that target an
-- already-admitted node.

CREATE TABLE staging_edges (
  organization_id         STRING(36)   NOT NULL,
  ingestion_run_id        STRING(36)   NOT NULL,
  staging_edge_id         STRING(36)   NOT NULL,
  edge_label              STRING(64)   NOT NULL,
  source_canonical_name   STRING(2048) NOT NULL,
  target_canonical_name   STRING(2048) NOT NULL,
  lint_status             STRING(32),
  lint_findings           JSON,
  pipeline_state          STRING(32)   NOT NULL,
  promoted_graph_edge_id  STRING(36),
  created_at              TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
  updated_at              TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, ingestion_run_id, staging_edge_id);


-- Indexes drive the per-stage filter patterns (which rows are in state X
-- for run Y) and the duplicate-canonical-name detection R8 uses.

CREATE INDEX StagingConceptsByRunAndState
  ON staging_concepts (organization_id, ingestion_run_id, pipeline_state);

CREATE INDEX StagingConceptsByRunAndName
  ON staging_concepts (organization_id, ingestion_run_id, canonical_name);

CREATE INDEX StagingConceptsByCluster
  ON staging_concepts (organization_id, ingestion_run_id, cluster_id);

CREATE INDEX StagingEdgesByRunAndState
  ON staging_edges (organization_id, ingestion_run_id, pipeline_state);

CREATE INDEX StagingEdgesBySource
  ON staging_edges (organization_id, ingestion_run_id, source_canonical_name);

CREATE INDEX StagingEdgesByTarget
  ON staging_edges (organization_id, ingestion_run_id, target_canonical_name);


-- staging_symbols: per-field-path decomposition of every staged concept's
-- contract + payload. Mirrors OODGraphSymbols' role for admitted state
-- (VOLT §s1_2 fractal_uniformity — same shape both lifecycle stages).
-- Written by spec_graph_staging_load via the recursive JSON walk (one
-- row per scalar value at every section_path under '$.contract' and
-- '$.payload'); read by spec_graph_staging_lint's R6 SQL (and any
-- future per-field-aware rules) so the lint query can SELECT one row
-- per (concept, field, value) without dynamic JSON_VALUE path
-- expressions, which Spanner forbids ("must be a constant expression").

CREATE TABLE staging_symbols (
  organization_id         STRING(36)   NOT NULL,
  ingestion_run_id        STRING(36)   NOT NULL,
  staging_symbol_id       STRING(36)   NOT NULL,
  staging_id              STRING(36)   NOT NULL,
  canonical_name          STRING(2048) NOT NULL,
  node_kind               STRING(64)   NOT NULL,
  symbol_kind             STRING(64)   NOT NULL,
  section_path            STRING(2048) NOT NULL,
  search_text             STRING(MAX),
  created_at              TIMESTAMP    NOT NULL OPTIONS (allow_commit_timestamp=true),
) PRIMARY KEY (organization_id, ingestion_run_id, staging_symbol_id);


CREATE INDEX StagingSymbolsByConcept
  ON staging_symbols (organization_id, ingestion_run_id, staging_id);

CREATE INDEX StagingSymbolsByCanonicalName
  ON staging_symbols (organization_id, ingestion_run_id, canonical_name);


-- ---------- Property Graph ----------
-- §7_spanner_property_graph_schema.create_property_graph_model
--
-- The ONE canonical projection the protocol owns. §7 is emphatic that this is a
-- projection and not a store (§7.property_graph_posture.graph_is_projection_not_store
-- = true): rows stay in the tables above, and OODGraph is a schema object over them.
--
-- Two element definitions, two base tables, ZERO views:
--   - OODGraphObjects, keyed by its PK, DYNAMIC LABEL from object_class
--   - OODGraphEdges,   keyed by its PK, DYNAMIC LABEL from edge_label, with
--     SOURCE/DESTINATION KEY resolving to OODGraphObjects.graph_object_id
--
-- OODGraphSymbols is deliberately NOT an element table. §7.element_key_and_endpoint_
-- strategy.symbol_node_element_key is "compatibility_lookup_only_not_production_
-- property_graph_element_key" and .endpoint_kind_values is the single member
-- ["graph_object"]; a symbol that must be a vertex is promoted to an OODGraphObjects
-- row first. The class-filtered views in §7.view_ddl_model are likewise
-- "compatibility_only_static_view_fallback_not_canonical_property_graph" and are NOT
-- generated here — §7.create_property_graph_model.static_view_generation_status.
--
-- ⛔ CLAUSE ORDER IS SPANNER-ENFORCED AND DIVERGES FROM §7's LITERAL STRING.
-- §7.create_property_graph_model.node_tables / .edge_tables_generation state the order
-- "... DYNAMIC LABEL (x) PROPERTIES ALL COLUMNS". Real Spanner REJECTS that order:
--
--   INVALID_ARGUMENT: Error parsing Spanner DDL statement: ...
--   Syntax error: LABEL or PROPERTIES clause should be moved before
--   DYNAMIC LABEL/PROPERTIES clause; Failed to parse ddl while collecting graph options.
--
-- (measured 2026-08-17 against spec-graph-scratch on instance
-- example-spanner-instance, gcloud exit 1). PROPERTIES must come FIRST. The
-- statement below therefore matches §7 in every table, key, endpoint reference,
-- dynamic-label column and property set, and diverges ONLY in clause order, which
-- §7 does not get to choose. §7 itself sets ddl_apply_instruction=false, so its
-- string is the normative SHAPE rather than the literal text to run — but the stated
-- order is still wrong and an amendment is OWED at four key paths:
--   .sections.s7_spanner_property_graph_schema.create_property_graph_model.node_tables
--   .sections.s7_spanner_property_graph_schema.create_property_graph_model.edge_tables_generation
--   .sections.s7_spanner_property_graph_schema.create_property_graph_model.statement_generation.node_definition_rule
--   .sections.s7_spanner_property_graph_schema.create_property_graph_model.statement_generation.edge_definition_rule
-- Do NOT "fix" the order below to match §7 — that reintroduces a statement that does
-- not parse. bootstrap_property_graph_test.go pins the ordering for exactly this reason.
--
-- PROPERTIES ALL COLUMNS is correct as written: verified 2026-08-17 on real Spanner
-- that it accepts the two HIDDEN generated TOKENLIST columns on each table and lists
-- them among the graph's propertyDefinitions, so no EXCEPT clause is owed.
--
-- ⛔ DECLARING THIS IS NOT APPLYING IT TO THE LIVE CORPUS. spec-graph init is a
-- fresh-init path (it short-circuits on an already-initialized database), so this
-- statement reaches a NEW allowlisted database with zero rows. Projecting the EXISTING
-- spec-graph corpus is separately gated: §7.label_exposure.dynamic_label_rule requires
-- unregistered labels be "rejected before projection" with label_set_validation_owner
-- = s8_graph_materialization_and_ingestion, and as of 2026-08-17 all 255 live
-- OODGraphObjects rows carry object_class values outside §2's closed 18-member set
-- (concept 214, node_kind_declaration 15, axiom 12, edge_label_declaration 9,
-- principal_type_declaration 3, origin 1, decision 1). That reconciliation is owned by
-- task P3-GT-OBJECTCLASS-RULING.

CREATE PROPERTY GRAPH OODGraph
  NODE TABLES (
    OODGraphObjects
      KEY (organization_id, graph_snapshot_id, graph_object_id)
      PROPERTIES ALL COLUMNS
      DYNAMIC LABEL (object_class)
  )
  EDGE TABLES (
    OODGraphEdges
      KEY (organization_id, graph_snapshot_id, graph_edge_id)
      SOURCE KEY (organization_id, graph_snapshot_id, source_endpoint_id)
        REFERENCES OODGraphObjects (organization_id, graph_snapshot_id, graph_object_id)
      DESTINATION KEY (organization_id, graph_snapshot_id, target_endpoint_id)
        REFERENCES OODGraphObjects (organization_id, graph_snapshot_id, graph_object_id)
      PROPERTIES ALL COLUMNS
      DYNAMIC LABEL (edge_label)
  );


-- ---------- Deferred (later phases) ----------
--
-- CREATE VECTOR INDEX over OODGraphObjects.embedding + OODGraphSymbols.embedding
-- per §6.retrieval_index_storage.spanner_capability_alignment.vector_indexes_may_be_declared.
-- Declared MAY (not MUST) in §6; KNN cosine works without indexes; ANN is the
-- enterprise-tier acceleration path. Deferred to retrieval phase.
--
-- CREATE SEARCH INDEX over search_text_tokens + search_payload_tokens columns
-- per §6.retrieval_index_storage.spanner_capability_alignment.search_index_columns.
-- Deferred to retrieval phase.
