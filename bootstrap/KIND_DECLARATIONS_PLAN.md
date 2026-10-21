# Kind Declarations Plan — The Layer After Axioms

The axiom layer (`seed_nodes/001` through `007`) establishes universal properties: identity, version chains, principals, admission, references, audit. This plan covers the next layer of work — declaring the specific `node_kinds` and `edge_labels` the corpus will admit, so the closed registries the axioms reference become populated.

This is head-start work — drafting can proceed in parallel with the MCP server build. Actual admission of these declarations runs once `spec_graph_import` is online.

---

## Status (as of 2026-05-26)

**Drafting complete for all four phases.** All declaration files are authored and locked in `bootstrap/seed_nodes/`. Awaiting MCP `spec_graph_import` to admit them in the admission order at the bottom of this document.

| Phase | Files | Status |
|---|---|---|
| Phase 1 — Meta-kind declarations (3) | `014_node_kind_declaration_meta_kind.json`, `015_edge_label_declaration_meta_kind.json`, `016_principal_type_declaration_meta_kind.json` | drafted |
| Phase 2 — Foundational back-fill (7) | `017_origin_kind_declaration.json` through `023_snapshot_kind_declaration.json` (origin, axiom, principal, edge, audit_record, grant, snapshot) | drafted |
| Phase 3 — Content kind declarations (5) | `024_section_kind_declaration.json` through `028_decision_kind_declaration.json` (section, sentinel, invariant, assumption, decision) | drafted |
| Phase 4 — Edge label declarations (8) | `029_depends_on_edge_label.json` through `036_audits_edge_label.json` (depends_on, load_bearing_for, references, raises, asserts_invariant, assumes, declares, audits) | drafted |
| Principal type declarations (3) | `037_human_principal_type.json`, `038_system_principal_type.json`, `039_external_system_principal_type.json` | drafted |

**Total drafted artifacts in this layer:** 26 declarations (3 meta-kinds + 7 back-fill + 5 content kinds + 8 edge labels + 3 principal types). The bootstrap principal node itself (between Phase 2 and Phase 3 in admission order) is not yet drafted — it is the operator's first concrete principal admission and depends on the operator's choice of binding material; it will be authored at admission time, not pre-drafted.

**Not yet drafted (deliberately):**
- The bootstrap principal node — depends on operator-chosen keying material.
- Any actual content nodes (sections, axioms-of-application, decisions about the corpus's content) — those wait for the registry to be populated and the cutover to occur.

**Next gate:** MCP `spec_graph_import` operational; then admission run against the experimental corpus database; then operator-controlled cutover to lock the gate against further `EXPERIMENTAL_BOOTSTRAP` admissions.

---

## Purpose

The axiom layer asserts that `node_kind` and `edge_label` are closed registries whose contents are corpus-resident data. The contents currently consist of two implicit entries (`origin` and `axiom`) used during seed-node admission under `EXPERIMENTAL_BOOTSTRAP` mode without registry checks. This layer:

1. Admits **meta-kind declarations** — the kinds whose admission populates the registry itself
2. Admits **back-fill declarations** for the foundational kinds bootstrap already used (`origin`, `axiom`)
3. Admits **first-wave content kind declarations** (`section`, `sentinel`, `invariant`, `assumption`, `decision`)
4. Admits **first-wave edge label declarations** (`depends_on`, `references`, `raises`, `asserts_invariant`, `assumes`, `declares`, `audits`)

After this layer, the corpus's registries are populated, the bootstrap exemption is closed, and steady-state operations begin.

---

## The meta-pattern: declarations are nodes

Per `node_identity_axiom` and `node_reference_axiom`, every closed registry's entries are first-class corpus members. By fractal_engineering applied uniformly:

- A `node_kind_declaration` is a node of `node_kind=node_kind_declaration` that DECLARES one entry in the `node_kind` registry.
- An `edge_label_declaration` is a node of `node_kind=edge_label_declaration` that DECLARES one entry in the `edge_label` registry.
- A `principal_type_declaration` is a node of `node_kind=principal_type_declaration` that DECLARES one entry in the `principal_type` registry (the registry `principal_axiom` claims for type discriminator values).
- All three meta-kinds are themselves declared (meta-recursive admission via `EXPERIMENTAL_BOOTSTRAP` for the meta-kinds, mirroring the axiom layer's self-declaration pattern).

**Decision (applied: origin + first principles + customer-long-term):** Split into separate meta-kinds rather than unifying. The three registries declare different things with different content shapes; tight per-kind schemas beat a discriminated-union schema.

**Convention for all schemas below:** each kind's content carries two surfaces per `node_version_chain_axiom` — **contract** (byte-equivalent across every version of the stable_id, enforced at re-admission) and **payload** (refinable across versions). Schema sketches in this plan name the contract-vs-payload assignment for each field; full schemas are written at authoring time per the discipline (Passes 1-5 of `NODE_QUALITY_DISCIPLINE.md`).

---

## Phase 1: Meta-kind declarations

### `node_kind_declaration`

Content schema sketch (to be expanded when authoring):

| Field | Surface | Type | Required | Description |
|---|---|---|---|---|
| `canonical_name` | contract | string | yes | The name of the declared kind (e.g., `section`) |
| `description` | payload | string | yes | Human-readable description of what this kind represents |
| `content_schema` | contract | JSON Schema | yes | Structural schema the content of nodes-of-this-kind must conform to (in contract because schema change = different kind) |
| `per_kind_lifecycle` | contract | object | yes | Properties specific to this kind: `re_admittable: bool`, `immutable_once_admitted: bool` |
| `bootstrap_kind` | contract | bool | optional | True for foundational kinds (`origin`, `axiom`) that pre-existed the registry |
| `single_instance` | contract | bool | optional | True for kinds where only one node may exist (e.g., `origin`) |

### `edge_label_declaration`

| Field | Surface | Type | Required | Description |
|---|---|---|---|---|
| `canonical_name` | contract | string | yes | The edge_label string (e.g., `depends_on`) |
| `description` | payload | string | yes | What this relationship represents |
| `source_kinds` | contract | array of strings | yes | Allowed `node_kind` values at the edge's source endpoint |
| `target_kinds` | contract | array of strings | yes | Allowed `node_kind` values at the edge's target endpoint |
| `reciprocity` | contract | string | optional | The inverse `edge_label` name, if this label has a defined inverse |
| `edge_family` | contract | string | optional | Grouping for closure profiles (`dependency`, `reference`, `declaration`, etc.) |

### `principal_type_declaration`

Declares one entry in the principal_type registry per `principal_axiom`'s `principal_type_discriminator` claim.

| Field | Surface | Type | Required | Description |
|---|---|---|---|---|
| `canonical_name` | contract | string | yes | The principal type name (e.g., `human`, `system`, `external_system`) |
| `description` | payload | string | yes | What this principal type represents |
| `type_specific_properties` | contract | object | optional | Type-specific schema fragment principals of this type must conform to (e.g., humans require authentication binding fields; system principals don't) |

**Decision (applied: origin + first principles + customer-long-term):** Both schemas use JSON Schema (or directly-equivalent declarative format) for `content_schema` fields. Standardized, deterministic, machine-checkable, library support in every language. Custom rule DSLs would re-implement what exists.

**Decision:** Schemas required complete at declaration time. Discipline: do it right the first time. Refining a schema later is contract drift on the declaration node; under `node_version_chain_axiom`'s contract immutability rule, the schema would have to be part of the declaration's payload (not contract) to permit refinement — which contradicts the schema's structural role. Schemas live in the contract.

---

## Phase 2: Foundational back-fill

These kinds were used during bootstrap or are claimed as foundational kinds by axioms; their declarations are admitted so the registry has entries for what already exists or what the axioms require.

| Kind | Notes |
|---|---|
| `origin` | Single instance per corpus; not re-admittable beyond payload wording refinement; content schema requires `title`, `founder`, `story`, `role_in_conflict_resolution` |
| `axiom` | Re-admittable for wording refinement only (asserts immutable per each axiom's `contract_monotonicity_rule`); content schema requires `title`, `statement`, `rationale_first_principles`, `self_application_proof`, `out_of_scope` |
| `principal` | Re-admittable; content schema follows `principal_axiom` asserts (principal_type, display_identity, authentication_binding per `corpus_authentication_axiom`) |
| `edge` | Re-admittable; content schema is the structural surface from `node_reference_axiom` (`source_stable_id`, `target_stable_id`, `edge_label`) |
| `audit_record` | NOT re-admittable (`immutable_once_admitted: true` per `corpus_audit_axiom`); content schema requires `principal_ref`, `subject_ref`, `wall_clock_instant` |
| `grant` (added) | Re-admittable; content schema from `grant_axiom` (subject, authorization clause with dimension/target/level, granting authority, temporal validity); reason field encrypted per `corpus_encryption_axiom` |
| `snapshot` (added) | NOT re-admittable once sealed (per `corpus_temporal_axiom` sealed-snapshots-immutable); content schema requires `snapshot_kind`, `sealed_at`, monotonic `snapshot_version` per tenant, `materialization_run_ref` |

**Schema enhancements required by axioms 011-013:**

Every kind declaration's content_schema now must include:

- **per_kind_lifecycle** (per `corpus_lifecycle_axiom`): the closed status enum the kind admits, the legal-transition graph over that enum, terminal status values, re-admittable flag, immutable-once-admitted flag, single-instance flag, bootstrap-kind flag
- **per_kind_encryption_posture** (per `corpus_encryption_axiom`): for each field in the content_schema, whether the field is plaintext or carries tenant-comp ciphertext; the kind's default posture; field-level overrides

---

## Phase 3: First wave of content kinds

These are the new kinds that unlock actual content authoring.

| Kind | Purpose | Content schema highlights (as authored in 024-028) |
|---|---|---|
| `section` | Content sections — parts of structured knowledge / specs | `title`, `body` (tenant_comp_encrypted); optional `canonical_name`. Parent-child relationships expressed via `declares` edges per node_reference_axiom (NOT inline parent_section_id). |
| `sentinel` | Failure mode declarations (canonical `Err*` names + raise conditions) | `canonical_err_name`, `description`, `raise_conditions`. Ownership by section/axiom expressed via `declares` edges (NOT inline owning_section_id). |
| `invariant` | System invariant declarations | `canonical_name`, `statement`, `scope_description`. |
| `assumption` | Cross-spec / cross-node assumptions | `assumption_statement`, `target_authority`. Reliance by other corpus members expressed via `assumes` edges (NOT inline relied_on_by). |
| `decision` | Architectural decisions (replaces the Vision §8 ledger pattern with end-state nodes; the corpus captures decisions as nodes, not as a running ledger) | `conflict`, `resolution`, `reasoning`. Affected nodes linked via `references` edges (NOT inline affected_nodes array). |

All Phase 3 kinds: re-admittable per `contract_monotonicity_rule` of their content; immutable contract surfaces across versions.

**Drafting note:** the original Phase 3 table sketched inline reference fields (`parent_section_id`, `owning_section_id`, `relied_on_by`, `affected_nodes`). Final declarations 024-028 instead express these relationships via edges per node_reference_axiom's claim that "inter-node relationships intended for graph traversal are first-class edges — explicit corpus members, not derived from content payloads." The shift from inline fields to edges happened during drafting as a Pass-6 framework call (origin + customer-long-term + first principles all converge on edge-based representation for graph queryability).

---

## Phase 4: First wave of edge labels

Initial set covering the relationships early content needs.

| Edge label | Source kinds | Target kinds | Reciprocity | Family | Notes |
|---|---|---|---|---|---|
| `depends_on` | axiom, section, sentinel, invariant, assumption, decision | axiom, section, sentinel, invariant, assumption, decision | `load_bearing_for` | dependency | — |
| `load_bearing_for` | axiom, section, sentinel, invariant, assumption, decision | axiom, section, sentinel, invariant, assumption, decision | `depends_on` | dependency | Admitted only via reciprocity from depends_on, never standalone |
| `references` | every kind except `origin` (14 kinds) | every kind including `origin` (15 kinds) | — | reference | Origin asymmetry: origin is target-only, never source |
| `raises` | axiom, section, decision | sentinel (only) | — | declaration | — |
| `asserts_invariant` | axiom, section, decision | invariant (only) | — | declaration | — |
| `assumes` | axiom, section, decision | assumption (only) | — | declaration | — |
| `declares` | axiom, section | section, sentinel, invariant, assumption, decision | — | declaration | Enables section hierarchical composition (source=section, target=section) |
| `audits` | audit_record (only) | every kind including `origin` (15 kinds) | — | audit | Default `version_pinning_default: version_pinned` (unique among labels); self-loops (source == target) structurally forbidden per audit_record fixed-point |

**Note:** the table is the FIRST WAVE. Future content authoring may surface needs for additional edge labels (e.g., `implements`, `supersedes`); those get added deliberately as new declarations, not retroactively as schema drift.

**Drafting note on source_kinds widening:** the original Phase 4 table sketched narrower source_kinds (e.g., `raises` source = [section, decision]). Final declarations 029-036 widen `raises`, `asserts_invariant`, `assumes` source_kinds to include `axiom` because axioms structurally describe behaviors including failure conditions, assertions, and assumptions — restricting source to exclude axioms would prevent the foundational layer from authoring its own raises/asserts/assumes relationships. The widening was a Pass-6 framework call during drafting (origin + customer-long-term + first principles all converge on permissive source_kinds for the foundational layer). The original `doc_object` reference in `declares` was also removed — DocObject Lifecycle was absorbed into the node-identity / version-chain axioms during corpus design; sections compose via declares edges without a separate container kind.

---

## Admission order

Strict dependency order — each phase depends on the prior phase being complete. All admissions in steps 1-5 use `EXPERIMENTAL_BOOTSTRAP` as `admitted_by` (no real principal exists yet). The operator triggers cutover at their discretion (step 6); after cutover, the bootstrap principal is the admitter and `EXPERIMENTAL_BOOTSTRAP` is rejected.

1. Phase 1 self-declarations (each meta-kind declares itself):
   - `node_kind_declaration`
   - `edge_label_declaration`
   - `principal_type_declaration`
2. Phase 2 foundational back-fill declarations: `origin`, `axiom`, `principal`, `edge`, `audit_record`
3. Phase 3 content kind declarations: `section`, `sentinel`, `invariant`, `assumption`, `decision`
4. Phase 4 edge label declarations: `depends_on`, `load_bearing_for`, `references`, `raises`, `asserts_invariant`, `assumes`, `declares`, `audits`
5. Bootstrap principal node admitted (a `principal` of an appropriate type from the principal_type registry; this is the last `EXPERIMENTAL_BOOTSTRAP` admission)
6. **Operator-controlled cutover**: the operator triggers cutover at their discretion once they verify the bootstrap layer is correctly admitted. The gate switches from accepting `EXPERIMENTAL_BOOTSTRAP` literal to requiring `admitted_by` to be the stable_id of an admitted principal. Until the operator triggers, `EXPERIMENTAL_BOOTSTRAP` remains accepted — giving the operator time to verify before locking the transition.
7. Begin admitting actual content nodes (admitter: bootstrap principal's stable_id) against the now-populated kind and edge_label registries

**Order correction:** Phase 3 (content kinds) precedes Phase 4 (edge labels) because Phase 4's declarations reference content kinds in their `source_kinds` / `target_kinds` arrays. A Phase 4 declaration admitted before its referenced content kinds exist would name kinds not in the registry, which the admission gate rejects.

---

## Decisions made by applying the framework (not asking)

For traceability — these were resolved during planning without escalation:

- **Split vs unified meta-kinds** (split — tight schemas)
- **Schema format** (JSON Schema or directly-equivalent declarative)
- **Schemas required complete at declaration** (do-it-right-the-first-time discipline)
- **Phase 3 before Phase 4** (edge labels reference content kinds in source/target arrays; kinds must exist first) — corrected from prior draft
- **Edge label registry as bounded-first-wave** (deliberate growth, not retroactive)
- **audit_record kind immutability** (already established by `corpus_audit_axiom`; declaration just surfaces the constraint)
- **`principal_type_declaration` as third meta-kind** (`principal_axiom`'s type discriminator registry needs its own declaration kind; same fractal pattern as node_kind and edge_label registries)
- **Bootstrap cutover trigger** (operator-controlled — per user direction 2026-05-26 overriding the framework's automatic-trigger reading; the operator decides when the bootstrap layer is correctly admitted and triggers cutover at their discretion; `EXPERIMENTAL_BOOTSTRAP` remains accepted until then)
- **No `doc_object` kind** (DocObject Lifecycle absorbed into the node identity / version chain axioms; sections compose into structured knowledge via `declares` edges with no container kind needed)
- **`decision` kind minimal structure** (contract: `canonical_name`; payload: `conflict`, `resolution`, `reasoning`; affected nodes linked via `references` edges rather than inline list — keeps the explicit-edges discipline of `node_reference_axiom` consistent)
- **audit_record subject reference** (via `audits` edge per `node_reference_axiom` traversal-is-edge; principal captured via the audit_record's own admission provenance per `admission_axiom` atomicity — no separate `admitted_by` edge needed in first wave)

---

## Estimated artifact count (updated for expanded foundation)

Approximately 25-27 declaration nodes for this layer (count grew with grant + snapshot back-fill from the expanded axiom layer):

- 3 meta-kind declarations (Phase 1: `node_kind_declaration`, `edge_label_declaration`, `principal_type_declaration`)
- 7 foundational back-fill declarations (Phase 2: `origin`, `axiom`, `principal`, `edge`, `audit_record`, `grant`, `snapshot`)
- 1 bootstrap principal node (between Phase 2 and Phase 3)
- 5 content kind declarations (Phase 3: `section`, `sentinel`, `invariant`, `assumption`, `decision`)
- 2-3 initial `principal_type_declaration` entries (e.g., `human`, `system`, possibly `external_system`)
- 8 edge label declarations (Phase 4: `depends_on`, `load_bearing_for`, `references`, `raises`, `asserts_invariant`, `assumes`, `declares`, `audits`)

Once admitted, the corpus has its full registry populated and is ready for steady-state content authoring against declared kinds and edge labels.

---

## When MCP is online

The drafting of actual declaration JSON files can proceed now (parallel to MCP build). Each declaration's content gets the full discipline (Passes 1-5 per `NODE_QUALITY_DISCIPLINE.md`) before saving. When `spec_graph_import` is live, the declarations are admitted in the order above.

Files would live in `bootstrap/seed_nodes/` numbered `008` onward (or in a parallel subdirectory if the team prefers separation between axiom-layer seeds and kind-layer seeds — that's a file-organization call).
