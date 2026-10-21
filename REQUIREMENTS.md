# spec-graph — Requirements

The MCP server that is the AI's primary tool for building the Velenza BOC corpus graph organically, node by node, against a throwaway experimental Spanner database, until the bootstrap is perfected and the substrate moves to production.

## 1. Purpose

spec-graph is the **operational arm of the Node Identity & Admission tier**. It exists so the AI can author corpus nodes (sections, circuits, sentinels, invariants, assumptions, configs, doc_objects, …) directly into a real Spanner graph via MCP tool calls during the pre-genesis period when no kernel is deployed.

The corpus is currently a pile of mutually-contradicting on-disk OOD JSON specs. spec-graph is the tool that lets the AI:

1. Author each foundational node from first principles against the on-disk spec corpus as content reference (not as input).
2. Link nodes with typed edges that the graph itself verifies.
3. Iterate destructively — drop and recreate the experimental graph at will until the bootstrap converges.
4. Supersede earlier decisions when a later node reveals an inconsistency, with the graph's own version chain managing audit.
5. Verify linkages with closure/impact/neighbor queries before committing the next node.
6. Eventually flip the substrate config from the experimental database to production-substrate without changing a single verb.

## 2. Current Status — What spec-graph Already Has Right

The framework in this repo is sound. The following are correctly implemented and SHOULD NOT change:

- **Three-tier framing** (top: Node Identity & Admission; middle: projection contracts; bottom: data substrates). Confirmed in `README.md` lines 13-28.
- **15 verb surface** (`spec_graph_use|create|update|archive|link|unlink|get|list|search|neighbors|closure|impact|history|diff|project`). Confirmed in `mcp.go`.
- **10-step admission ceremony** matching VOLT §8.4 step order (schema_validate → resolve_admitter → pre_sign_passes → definition_hash → manifest_hash → kms_sign → signature_chain_append → post_sign_passes → typed_row_insert → admission_log_insert). Confirmed in `ceremony.go` lines 17-26.
- **Closed-registry policy** for node_kinds, edge_labels, projections, and substrates. Binary holds no enum values; registries load from config today, KernelConfig later. Confirmed in `kinds.go`, `edges.go`, `projection.go`, `substrate.go`.
- **ONE generic `SpannerSubstrateAdapter`** parameterized by descriptor — no per-substrate Go. Confirmed in `substrate.go` lines 85-118.
- **Reciprocity rules** declared on edge labels with automatic mirror-edge creation in the same transaction. Confirmed in `edges.go` lines 45-61.
- **Spec-lineage refs** on every `NodeVersion` (governing_spec_ref, source_spec_lineage_refs, spec_section_ref, spec_symbol_ref, node_creation_contract_ref). Matches VOLT §8.2 spec_lineage_admission_surface verbatim. Confirmed in `types.go` lines 45-51.
- **Canonical signature input vector** documented as the six fields (artifact_type, organization_id, artifact_id, admitted_at, definition_hash, manifest_hash). Matches VOLT §8.6 verbatim. Confirmed in `types.go` lines 81-83.
- **Snapshot-pinned reads** via `spec_graph_use` with the pin held per-session. Confirmed in `mcp.go` lines 15-17 and `handlers.go` lines 110-124.
- **Contract monotonicity check** on re-admission (Vision Principle 11). Confirmed in `handlers.go` lines 390-399.
- **Dangling-closure check** on archive. Confirmed in `handlers.go` lines 401-408.
- **Fail-closed posture** throughout. Every pending step returns `SchemaPendingDetail` naming what's missing and which spec owns it. Confirmed in `errors.go` lines 54-77.

The verb surface is reviewable and stable. Schemas conform to verbs, not the other way around (per `README.md` lines 50-55).

## 3. Required New Capabilities

### 3.1 Experimental-Bootstrap Operating Mode

spec-graph MUST support an explicit **experimental-bootstrap mode** distinct from the production VOLT/OOD-Graph/ASG multi-substrate mode the existing config envisions.

In experimental-bootstrap mode:

- **ONE substrate**, not four. Every node_kind routes to the same experimental Spanner database (proposed: `corpus-graph-iter1` in instance `your-spanner-instance`, project `your-gcp-project-id`).
- **Direct admission**, not deferred. The 10-step ceremony runs in full but with relaxed inputs:
  - `admitted_by` accepts the reserved literal `EXPERIMENTAL_BOOTSTRAP` analogous to VOLT §8.8's `GENESIS` marker but for the pre-genesis experimental phase.
  - `signature_chain` carries a placeholder signature derived from a local development key (not Cloud KMS).
  - `manifest_hash` is computed over the actual `pass_results` map, but `pre_sign_passes` and `post_sign_passes` accept an empty pass set when `compiler_pass_registry` is not yet populated.
  - `definition_hash` is computed for real (SHA-256 over canonical JSON of the submission).
- **Cutover discipline**. The moment we switch the substrate config from the experimental DB to production-substrate, the mode flips. `EXPERIMENTAL_BOOTSTRAP` admitted_by becomes invalid; the kernel-internal admission path takes over. The rows authored under `EXPERIMENTAL_BOOTSTRAP` are either preserved as historical lineage or re-admitted under proper ceremony — the decision is captured as a decision-node when we make the cut.

Mode selection is a config field, not a CLI flag. Adding `"mode": "experimental_bootstrap"` to `spec-graph.config.json` enables it. Default is empty → fail-closed.

### 3.2 DDL Bootstrap Subcommand

spec-graph MUST provide a `spec-graph init` subcommand that applies the experimental schema to the configured Spanner database.

- Reads DDL from a declarative SQL file in the repo (`bootstrap/schema_v1.sql`).
- Applies via `gcloud spanner databases ddl update` (the same path CLAUDE.md `APPROVAL_GATES.ddl_apply` authorizes for production-substrate).
- Idempotent: re-running on an already-initialized DB reports "already applied" and exits 0.
- Verifies post-apply: queries `information_schema.tables` and confirms every expected table exists.
- Refuses to run against production-substrate by name (database-name allowlist enforced in code — only allows `corpus-graph-*` patterns during the experimental phase).

The minimum DDL the file must declare:

- `Nodes(organization_id, node_id, node_kind, version, status, content, content_hash, definition_hash, manifest_hash, signature_chain, admitted_by, admitted_at, superseded_by)` with PK `(organization_id, node_id, version)` and the active-version UNIQUE NULL_FILTERED INDEX
- `Edges(organization_id, edge_id, source_node_id, source_version, target_node_id, target_version, edge_label, status, admitted_at, reciprocal_edge_id)` with PK `(organization_id, edge_id)`
- `ArtifactAdmissionLog(organization_id, admission_id, artifact_id, artifact_type, artifact_hash, manifest_hash, admitted_by, admitted_at, signature, dual_control_approver, is_non_genesis)` — the exact shape from VOLT v34 §8.7 lines 2424-2427
- A `CREATE PROPERTY GRAPH CorpusGraph` over Nodes + Edges so `GRAPH_TABLE` / `MATCH` queries work for closure/impact verbs

No per-node_kind typed tables in the experimental schema. All node bodies live in `Nodes.content` (JSON). When we cut to production, per-node_kind tables emerge and the adapter's `table_map` routes them — but during the experimental phase, one Nodes table is correct.

### 3.3 Database Reset Subcommand

spec-graph MUST provide a `spec-graph reset --confirm` subcommand that drops and recreates the experimental database.

- Refuses without `--confirm` flag.
- Refuses against any database not matching the `corpus-graph-*` pattern (defense in depth — production-substrate is unreachable).
- Drops the database, recreates it, applies the schema, verifies. End state: empty graph ready for node-1.

Iteration freedom is the entire point of the experimental phase. Reset is how we use that freedom.

### 3.4 Ad-Hoc GQL Query Verb

spec-graph MUST expose a `spec_graph_query` MCP verb that accepts a GoogleSQL or GQL query string and returns rows.

- READ-ONLY: rejects any query that is not a SELECT or `GRAPH_TABLE` query at the parse level (or by Spanner's read-only transaction).
- Snapshot-pinned per the existing `spec_graph_use` pin.
- Returns rows as a `QueryResult` struct (JSON-encoded for MCP).
- The verb exists so the AI can verify graph state during development without having to learn a custom closure DSL for every check. Production retains the typed closure/impact verbs; the ad-hoc verb is bootstrap-phase-only and gated by config (`"experimental_query_enabled": true`).

### 3.5 Decision-Node Support

The closed `node_kinds` registry MUST include `decision` as a first-class kind during the experimental phase.

- `decision` nodes capture architectural choices made while building the graph (e.g., "Q6 collapsed — Vision §8 ledger framing rejected; principle amendments are concurrent edits, not ledger entries").
- A decision-node carries: the conflict it resolves, the resolution, the reasoning, the affected nodes, the date.
- Future contradiction encounters cite the decision-node rather than re-resolving.
- The on-disk Vision §8 ledger STAYS where it is (we don't edit it); decision-nodes are the going-forward end-state form per the user's correction.

### 3.6 Bulk Import Verb

spec-graph MUST expose a `spec_graph_import` verb that accepts a JSON file path (or inline array) of node submissions and admits them in dependency order.

- Each entry is an `ArtifactSubmission` shape.
- `ArtifactSubmission.source_coordinate` is optional only for non-external bootstrap seed imports, which retain the protocol-owned `name` / `unversioned` / `$` coordinate. A node-kind descriptor opts into external identity with `source_coordinate_policy: "external_reference_required"`; those kinds require caller-authored authority/class/reference/section identity and optional expected digest. `source_content_hash_owner`, `retrieved_at`, and `version_coordinate` are process outputs and callers omit them in both version modes. The closed source-class registry remains the six OOD Graph §8 classes. External submissions are stable-reference-only: `contract` and `payload` are empty, and immutable search metadata contains only graph-owned identity/classification fields.
- The body-free `external_source_receipt_v4` contract separates raw transfer evidence (`transport_raw_content_hash`, raw byte count, content encoding) from canonical source evidence (`transport_decoded_byte_count`, `source_content_hash_algorithm/profile/hash`). The canonical identity profile is `transport_decoded_representation_bytes_v1`: exact bytes after content-encoding decode and before charset decode, Unicode normalization, DOM/JSON parsing, whitespace rewriting, or semantic extraction. `content_digest` and upstream-evidence tokens bind that canonical digest. JSON locator parsing rejects recursive duplicate keys and preserves numeric lexemes; HTML proof accepts one unambiguous `id` or historical `<a name>` target. Locator-owned names bind the full RFC 6901 pointer or resource-relative path plus fragment, preventing repeated-leaf/page-anchor collisions.
- Every external fetch resolves a typed authorization before any source network call. The result binds the kernel-resolved organization, exact source authority/ref/locator, source-owned representation declaration, principal, affirmative grant, scope, method/operation, redirect policy, content/trust classes, byte/depth ceilings, effective/expiry window, immutable policy-version and decision refs/digests, and one closed body-custody disposition. A descriptor-owned evidence URL or immutable same-repository `LICENSE`/`COPYING` coordinate is only evidence-coordinate selection and never authorization. Missing, denied, stale, cross-tenant, scope-mismatched, or incomplete decisions fail with `ErrOODGraphExternalRetrievalPermissionProofUnavailable` before source I/O.
- Retrieval permission, permission to persist the canonical representation, and permission to retain graph-owned coordinates/digests/topology are independent decisions. `no_local_body_custody` permits a body-free audit/staging receipt but cannot promote. `exact_agfs_body_custody` requires storage authorization, an AGFS `external_carrier_hold`, and independent archive/receipt deletion plus crypto-shred domains; the protected SOURCE RECORD custody boundary writes the canonical source bytes before parsing and binds the returned immutable file id, explicit version, AGFS ciphertext content hash, source digest, and byte count. The request carries no ordinary AGFS parent, filename, ref name, bearer material, or principal assertion. Within one ingestion request, source retrieval and protected archive creation are each singleflight: graph elements derived from the same tenant/source/resource/canonical digest and byte-equal storage-authorization/hold/deletion/shred tuple share one occurrence archive binding, while any custody-domain difference creates a distinct archive operation. Two hashes remain distinct: the Source Record `agfs_body_reference_hash` covers tenant/file/version/AGFS hash/storage authorization/hold under RFC 8785, while the OOD `archive_record_digest` uses `external_evidence_archive_binding_v1` canonical field encoding over tenant/archive authority/record/source digest/byte count/deletion/shred. Graph publication stores only those coordinates/digests. Complete publication enforces an exact active-external-object/receipt bijection, preserves receipts through complete successors, bounds bootstrap source-set JSON below Spanner's cell limit, and refuses publication without the archive binding.
- Exact hydration accepts only a durable v4 receipt and a zero-based half-open byte range. It uses AGFS's kernel-internal `external_source_evidence_carrier_resolution`, never ordinary `fs.file.read` or an ordinary caller-visible read claim. The protected resolver rechecks CallerContext, current PIA grants, Gate proceed evidence, the signed hard hold and equal immutable file version, and SOURCE RECORD retention/currentness at issuance and redemption; the adapter then verifies complete source length/digest and the selected-range digest before returning bytes plus provenance. It never re-fetches the provider and never accepts a graph property, embedding, model output, DOM, ordinary AGFS handle, or caller value as an exact field.
- A source-provided machine export is its own evidence representation and is the sole evidence body for its declared locator. Its exact returned bytes and canonical representation coordinate are attested and archived as supplied; the export control, rendered DOM, accessibility tree, static operation metadata, and other navigation aids cannot substitute. Resource-root names are derived from the authority-bound coordinate rather than caller aliases.
- `spec_graph_import.relationships` accepts typed `{edge_label, source_canonical_name, target_canonical_name}` rows. The planner resolves both endpoints only within the batch, validates the closed eight-label external edge registry, derives stable authoring paths/edge IDs, and deduplicates embeddings by relation-class signature. `repo_snapshot` remains rejected because s2 requires a parent `source_repo` edge that s4 cannot currently represent. Caller-authored relationship input is not yet represented in `source_set` identity, so the runtime must not claim that artifact coordinates alone reconstruct an external edge manifest; the canonical relationship-manifest representation is OOD-spec-routed and must not be invented by widening the hash ad hoc. Exhaustive source-set enumeration/page-batch completeness, changed-byte supersession, normalized immutable content rows, partitioned occurrence receipts/membership, and compact manifest/head CAS remain protocol prerequisites; an exact-coordinate submission never claims corpus completeness.
- Promotion requires every non-duplicate concept and edge to be `pipeline_state=linted` with `lint_status=pass` both in preflight and in the final sealing compare-and-set. Clustering deduplicates only exact full-coordinate-plus-canonical-digest replay. Staging promotion reuses the load-time receipt without a second provider fetch and refuses a tenant mismatch, changed authorization binding, missing archive, or changed source/AGFS digest.
- The verb resolves dependencies (a node's `references` to other node ids) and orders the admission topologically.
- Failure on any entry aborts the import (single-admission-path applies to the batch — all or none, per VOLT §8.1). Implementation: every plan is prepared in memory first (ceremony steps 1-8), then plans are grouped by target substrate and each group is committed in ONE Spanner ReadWriteTransaction via the variadic `CommitAdmission`. Any failure in the prepare phase returns before any substrate write; any failure inside a substrate's transaction rolls that substrate's batch back. Cross-substrate atomicity is not Spanner-expressible — §3.6 atomicity is per-substrate by construction.
- Directory scan: when `file_path` points at a directory, every `*.json` file is loaded in filename order EXCEPT files whose name begins with an underscore (`_edges.json`, `_findings.json`, and any other `_*.json` author/validator artifact). The underscore-prefix is the contract; mixing submission files and author/validator artifacts in the same directory is the intended layout (see AUTHORING_GUIDE.md §6 and §11).
- Use case: seeding the first 5-10 axiom nodes in one operation when their content is already designed.

### 3.7 Health-Check Verb

spec-graph MUST expose a `spec_graph_health` verb that reports:

- Substrate database name and reachability (a trivial SELECT).
- Schema state (every expected table present + property graph projection exists).
- Registry sizes (count of node_kinds, edge_labels, projections, substrates loaded).
- Mode (`experimental_bootstrap` | `production` | unset).
- Active snapshot pin (if any).

The verb runs at MCP session start and surfaces immediate readiness or specific blockers.

### 3.8 Admitted-By Identity for Experimental Phase

During experimental-bootstrap mode, the MCP server burns in a single principal at startup, read from config:

```json
{
  "experimental_admitter": "EXPERIMENTAL_BOOTSTRAP"
}
```

Every admission ceremony resolves `admitted_by` to this value when `mode=experimental_bootstrap`. This satisfies the ceremony's step 2 (`resolve_admitter`) without requiring a real CallerContext envelope. The `is_non_genesis` generated column on `ArtifactAdmissionLog` distinguishes EXPERIMENTAL_BOOTSTRAP rows from real principal admissions when we eventually move to production.

In production mode, this field is rejected at config-load and the admitter must come from a real CallerContext.

## 4. Configuration — Single Source of Truth

The framework remains config-driven per Vision Principle 7 `binary_is_never_sot`. The config file at `$SPEC_GRAPH_CONFIG` (default `./spec-graph.config.json`) MUST carry:

```json
{
  "mode": "experimental_bootstrap",
  "experimental_admitter": "EXPERIMENTAL_BOOTSTRAP",
  "experimental_query_enabled": true,
  "substrates": [
    {
      "id": "corpus_graph_iter1",
      "description": "Experimental corpus graph — single substrate during bootstrap iteration",
      "spanner_database": "projects/your-gcp-project-id/instances/your-spanner-instance/databases/corpus-graph-iter1",
      "read_only": false,
      "table_map": {
        "node": "Nodes",
        "edge": "Edges",
        "admission_log": "ArtifactAdmissionLog"
      }
    }
  ],
  "node_kinds": [
    { "name": "node_identity_axiom", "substrate_id": "corpus_graph_iter1", "artifact_type": "axiom", "version_scope": "stable_id_preserved" },
    { "name": "section",             "substrate_id": "corpus_graph_iter1", "artifact_type": "section", "version_scope": "stable_id_preserved" },
    { "name": "sentinel",            "substrate_id": "corpus_graph_iter1", "artifact_type": "sentinel", "version_scope": "stable_id_preserved" },
    { "name": "invariant",           "substrate_id": "corpus_graph_iter1", "artifact_type": "invariant", "version_scope": "stable_id_preserved" },
    { "name": "assumption",          "substrate_id": "corpus_graph_iter1", "artifact_type": "assumption", "version_scope": "stable_id_preserved" },
    { "name": "decision",            "substrate_id": "corpus_graph_iter1", "artifact_type": "decision", "version_scope": "stable_id_preserved" },
    { "name": "doc_object",          "substrate_id": "corpus_graph_iter1", "artifact_type": "doc_object", "version_scope": "stable_id_preserved" },
    { "name": "circuit",             "substrate_id": "corpus_graph_iter1", "artifact_type": "circuit", "version_scope": "stable_id_preserved" }
  ],
  "edge_labels": [ "<<< retain the existing nine-label baseline from spec-graph.config.example.json >>>" ],
  "projections": [ "<<< retain the existing three-projection baseline from spec-graph.config.example.json >>>" ]
}
```

The four-substrate split in the current `spec-graph.config.example.json` is for the production phase. The example file SHOULD remain as `spec-graph.config.production.example.json` and a new `spec-graph.config.bootstrap.example.json` SHOULD be added with the single-substrate shape above.

## 5. Verb Surface — Additions to the Existing 15

The existing 15 verbs stay. Add three:

| Verb | Purpose | Mode |
|---|---|---|
| `spec_graph_query` | Ad-hoc read-only GQL / SQL | bootstrap only |
| `spec_graph_import` | Bulk admission of multiple submissions in topological order | both |
| `spec_graph_health` | Readiness + schema-state + registry sizes | both |

Final count: **18 verbs**.

## 6. CLI Subcommands — Additions to the Existing `mcp`

The existing `spec-graph mcp` stays. Add two:

| Subcommand | Purpose |
|---|---|
| `spec-graph init` | Apply `bootstrap/schema_v1.sql` to the configured experimental database; idempotent; refuses non-`corpus-graph-*` targets |
| `spec-graph reset --confirm` | Drop + recreate the experimental database; refuses without `--confirm`; refuses non-`corpus-graph-*` targets |

## 7. Sentinels — Additions to the Existing Set

The existing 9 sentinels stay. Add four:

| Sentinel | Raised when |
|---|---|
| `ErrModeMismatch` | Verb invoked in a mode that doesn't support it (e.g., `spec_graph_query` outside bootstrap mode with `experimental_query_enabled=false`) |
| `ErrForbiddenDatabaseTarget` | `spec-graph init` or `reset` invoked against a database whose name does not match `corpus-graph-*` |
| `ErrSchemaNotApplied` | Any verb invoked before `spec-graph init` has applied the schema |
| `ErrImportDependencyUnresolved` | `spec_graph_import` cannot topologically order the submissions because of a cycle or a missing referent |

## 8. Out of Scope

spec-graph is NOT:

- A genesis tool. It does not seed canonical production data into production-substrate. Production seeding stays in canonical-specs declarative SQL per CLAUDE.md `feedback_no_committed_genesis_or_oneshot_tooling`.
- A spec editor. It does not modify on-disk OOD JSON files in `/opt/velenza/specs-local/`. Those files are content reference; spec-graph reads them through whatever loader the AI uses, never writes them.
- A migration tool. It does not move rows between databases. When we cut from `corpus-graph-iter1` to production-substrate, that's a separate authorized operation (likely a fresh re-admission against the new substrate via `spec_graph_import` rather than a row-copy).
- A kernel substitute. It does not run circuits, dispatch signals, or admit through real KMS. It runs the ceremony's structural shape against the experimental substrate so the workflow is real; the cryptographic + execution layers wait for the kernel.

## 9. Testing Discipline

Each new capability requires before merge:

- **Unit test** of the orchestration shape with the substrate mocked.
- **Integration test** against a Spanner emulator running locally (the emulator supports DDL + DML + property graphs, suitable for verifying the schema and basic verbs).
- **Manual smoke test** documented in `TESTING.md`: create node, link node, query closure, supersede, archive — the five-verb walk that proves the experimental loop works end-to-end.

No test that uses `t.Skip` per CLAUDE.md `feedback_no_t_skip_in_tests`.

## 10. Open Decisions Requiring User Input

These cannot be resolved without an explicit call:

1. **Database name confirmation.** `corpus-graph-iter1` is a proposal. If the user prefers another name, the entire allowlist in `spec-graph init` shifts accordingly.
2. **Local development key for experimental signing.** The `EXPERIMENTAL_BOOTSTRAP` admitter still produces a signature_chain entry. The signing key for the experimental phase is either (a) a local dev key file, (b) a per-developer GCP service account key, or (c) a placeholder constant. Option (c) is simplest; option (a) closest matches production.
3. **DDL file location.** Proposed: `bootstrap/schema_v1.sql` in this repo. Alternative: a separate canonical-specs subdirectory `experimental-corpus-graph/`. Putting it here keeps the experimental phase self-contained; putting it in canonical-specs aligns with where production DDL eventually lives.
4. **Cutover plan.** What concrete event marks "the bootstrap is perfected and we're moving to production"? Probably: every foundational §5.2 spec has at least one node in the experimental graph + every edge_label has been exercised at least once + the contradiction inventory has been resolved into decision-nodes. The cutover plan itself should become a decision-node when we draft it.

## 11. Triple-Check Verification

This document has been verified against the spec-graph repo source by direct read:

- `README.md` lines 1-130 ✓ — three-tier framing + framework-only status + closed-registry policy + substrate-config pattern
- `main.go` lines 1-56 ✓ — single `mcp` subcommand entry point (additions: `init`, `reset`)
- `mcp.go` lines 19-218 ✓ — 15 verbs registered with typed I/O (additions: `query`, `import`, `health`)
- `types.go` lines 1-167 ✓ — `Node`, `NodeVersion`, `Edge`, `Snapshot`, `AdmissionRecord`, `ArtifactSubmission`, `PassResult` + output wrappers
- `ceremony.go` lines 1-239 ✓ — 10-step ceremony orchestration with `SchemaPendingDetail` returns
- `substrate.go` lines 1-151 ✓ — `SubstrateRouter` + ONE `SpannerSubstrateAdapter` parameterized by descriptor
- `handlers.go` lines 1-408 ✓ — per-verb handlers + cross-substrate read + contract-monotonicity check + dangling-closure check
- `kinds.go` / `edges.go` / `projection.go` ✓ — closed-registry interfaces with file-loaded descriptors
- `errors.go` lines 1-77 ✓ — 9 sentinels + structured `SchemaPendingDetail` + `SubstrateNotProvisionedDetail`
- `config.go` lines 1-59 ✓ — `SpecGraphConfig` loader with empty-default fail-closed posture
- `spec-graph.config.example.json` lines 1-157 ✓ — verified to point at production-substrate (will be split into bootstrap + production variants per §4)

Verified against canonical specs:

- VOLT v34 §8.1-§8.8 — 10-step ceremony, 13 artifact_types, GENESIS exemption mechanism, ArtifactAdmissionLog DDL ✓
- VOLT v34 §8.6 — canonical signature input vector is exactly the six fields listed in §1 ✓
- DocObject Lifecycle v1 §1-§4 — logical-document identity, version model, 9-status enum ✓
- OOD Graph Protocol v1 §1, §10, §11, §12 — graph_native axiom, snapshot pin contract, closure profiles, sibling-authority isolation ✓
- LOEF v13 §3 — 7-category envelope format, caller_context wire location ✓
- Velenza Grand Vision §2 Principle 7 (binary_is_never_sot), Principle 8 (everything-executable-is-a-node — to be amended), Principle 11 (re-admission preserves id), Principle 14 (fractal engineering) ✓

Verified against CLAUDE.md:

- `APPROVAL_GATES.ddl_apply` — `gcloud spanner databases ddl update` is the authorized path; `corpus-graph-iter1` allowlist preserves the production-substrate restriction ✓
- `NEVER.data.never_touch_prod_data_without_explicit_instruction` — experimental database is brand new, no production data risk ✓
- `feedback_no_committed_genesis_or_oneshot_tooling` — spec-graph is an ongoing MCP tool, not a one-shot genesis script; `init` and `reset` operate against the experimental DB only ✓
- `feedback_no_t_skip_in_tests` — test discipline in §9 forbids skip ✓
- `local_working_buffer` — spec-graph never edits files in `specs-local/`; reads them through the loader on demand ✓

---

## 12. Implementation Notes Added Post-Initial-Authoring

> **Added 2026-05-26** — these notes were NOT in the initial REQUIREMENTS.md draft. They were identified during the verification walk-through of `bootstrap/seed_nodes/001_origin.json` and `bootstrap/seed_nodes/002_node_identity_axiom.json` against the framework's existing types. Marked here so the spec-graph dev team can find them easily; this section is the **only** post-initial-draft material in this file.

### 12.1 — `ArtifactSubmission` Go struct is missing JSON tags

**The defect.** `spec-graph/types.go:154-167` defines `ArtifactSubmission` without any `json:"..."` tags. Go's default marshaling uses the Go field names verbatim — CamelCase (`NodeKind`, `OrganizationID`, `StableID`, `Contract`, `Payload`, …) — which does NOT match the snake_case convention used everywhere else in the repo and in the seed files.

**Where this conflicts.**
- `Node` struct (`types.go:15-23`) uses snake_case json tags (`json:"node_id"`, `json:"node_kind"`, …).
- `createInput` (`handlers.go:28-34`) uses snake_case json tags.
- The example config (`spec-graph.config.example.json`) uses snake_case keys throughout.
- The seed files (`bootstrap/seed_nodes/*.json`) use snake_case keys.

`ArtifactSubmission` is the lone exception in the file. Any verb that deserializes JSON directly into `ArtifactSubmission` — most importantly the new `spec_graph_import` verb required by §3.6 — will fail to map seed-file keys to struct fields, or worse, map them silently wrong.

**Required fix.** Before implementing §3.6 (`spec_graph_import`), add explicit `json:"..."` snake_case tags to every field of `ArtifactSubmission`:

```go
type ArtifactSubmission struct {
    ArtifactType   string          `json:"artifact_type"`
    OrganizationID string          `json:"organization_id"`
    NodeKind       string          `json:"node_kind"`
    EdgeLabel      string          `json:"edge_label,omitempty"`
    StableID       string          `json:"stable_id,omitempty"`
    Contract       json.RawMessage `json:"contract,omitempty"`
    Payload        json.RawMessage `json:"payload,omitempty"`
    PriorVersion   *NodeVersion    `json:"prior_version,omitempty"`
    IsRetirement   bool            `json:"is_retirement,omitempty"`
    Submitter      string          `json:"submitter,omitempty"`
    GoverningSpec  string          `json:"governing_spec,omitempty"`
    SpecSection    string          `json:"spec_section,omitempty"`
}
```

**What's unaffected.** `spec_graph_create` (the existing verb) deserializes into the tagged `createInput` struct first, then constructs the submission programmatically — so the current code path works fine. The defect only matters when external JSON files are deserialized directly into `ArtifactSubmission`, which is what `spec_graph_import` will do.

**Where this was caught.** 2026-05-26 verification walk-through of the two seed files against the framework's existing types. The seed files were authored against the project's snake_case convention; the defect was in the framework code, not the seed files.

### 12.2 — `spec_graph_diff` structural-diff semantics

**The design call.** `spec_graph_diff` (defined in `mcp.go:195-204` and stubbed in `handlers.go:335-341`) returns a "structural + content diff between two versions of the same stable id." The shape of the structural diff was not pinned. This subsection pins it.

**Resolution: JSON field-level, uniform across all node_kinds.**

- **Algorithm:** RFC 6902 JSON Patch (or an equivalent canonical-form path/operation representation). Standardized, deterministic, library support in every language.
- **Operates on:** the full content blob of both versions (contract + payload). In practice only payload paths will appear in the diff because `node_version_chain_axiom` (`bootstrap/seed_nodes/003_node_version_chain_axiom.json`) asserts contract byte-equivalence across versions; a diff that surfaces contract-path changes indicates a data-integrity event, not a normal diff.
- **Returns:** a structured `DiffResult` containing the patch operations (`op`, `path`, `value`, optional `from`) plus old-value + new-value at each changed path. Implementation may use any RFC 6902-conforming serialization.
- **Uniform across every node_kind.** No per-kind diff logic. The diff is a property of the content JSON, not of any kind-specific semantic meaning.

**Why not per-kind diff.** Per-kind diff implementations would mean N diff code paths to maintain and validate, and would couple the diff verb to every kind's internal structure — exactly the kind of cross-cutting fragility uniform shape exists to avoid. Per-kind SEMANTIC rendering (e.g., narrative diff of a section's prose, DAG-shape diff of a circuit's invocation graph) is a projection problem handled by `spec_graph_project`: the structural diff is the ground truth, and a projection renders it kind-specifically when needed. Splitting structural-diff (uniform) from semantic-rendering (per-kind, via projections) keeps each layer's contract simple.

**Why not schema-level diff.** Schema/contract is invariant across versions of one stable_id per `node_version_chain_axiom.asserts.contract_immutability_across_versions` (contract is byte-equivalent across versions). A schema-level diff between v_N and v_N+1 of the same stable_id would always be empty by definition; the comparison has no use case at this layer. Schema validation against the contract is what the admission gate does at admission time, not what diff does between versions.

**Closure delta (edges added/removed) is a separate operation.** The existing verb description in `mcp.go:198` mentions "closure delta (edges added/removed)" as part of diff. That conflates two distinct operations: (a) diff between two versions of ONE node's content (this verb), and (b) diff between two snapshots of the GRAPH reachable from one node (a different verb, e.g., a snapshot-diff over edges). When closure delta is implemented, it should be its own verb (`spec_graph_closure_diff` or similar) with inputs `(node_id, snapshot_a, snapshot_b)`, not bundled into `spec_graph_diff`'s `(node_id, version_a, version_b)` input shape. Recommend striking the closure-delta phrase from the existing `spec_graph_diff` description and introducing a separate verb for closure-state comparison if and when that need lands.

**Where this was caught.** 2026-05-26 design conversation during the bootstrap seed-node authoring phase. The question surfaced because the diff verb's description left "structural" undefined and the design call needed pinning before `spec_graph_diff` could be implemented.
