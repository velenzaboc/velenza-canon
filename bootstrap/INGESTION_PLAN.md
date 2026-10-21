# Corpus Graph Rewrite Plan

This is **NOT** a spec-by-spec copy operation. The job is to **rewrite the Velenza corpus as one unified graph**. The legacy `.ood.json` files under `/opt/velenza/specs-local/` are **reference material** the author cross-reads — not ingestion targets. A concept that appears in N source docs collapses to ONE node referenced by many; a section that exists only because the old file structure had section headings does NOT become its own node unless the section carries a real distinct claim.

## What's already in the graph (the spine — DO NOT re-author)

40 nodes admitted as the corpus's own foundations. Every concept authored from here forward edges into this spine.

- **1 origin** — `origin`
- **12 axioms** — `corpus_audit_axiom`, `corpus_authentication_axiom`, `corpus_authorization_axiom`, `corpus_encryption_axiom`, `corpus_lifecycle_axiom`, `corpus_temporal_axiom`, `grant_axiom`, `node_admission_axiom`, `node_identity_axiom`, `node_reference_axiom`, `node_version_chain_axiom`, `principal_axiom`
- **15 node_kind_declarations** — assumption / audit_record / axiom / decision / edge / edge_label_declaration_meta / grant / invariant / node_kind_declaration_meta / origin / principal / principal_type_declaration_meta / section / sentinel / snapshot
- **9 edge_label_declarations** — asserts_invariant / assumes / audits / declares / depends_on / load_bearing_for / raises / references / resolves
- **3 principal_type_declarations** — external_system_principal / human_principal / system_principal

## Authoring rule — concept-first, dedupe-first

Each dispatch authors **one concept domain**, not one source spec. The brief carries:

1. **Source docs to read as REFERENCE** — may be one file or many; the author cross-reads
2. **The existing graph state** (queryable via `spec_graph_list` / `spec_graph_search`) — every new node must check whether the concept already has a node and edge into it instead of creating a parallel one
3. **Concept boundary** — what's IN this domain, what belongs to a later/earlier tier
4. **Output directory** — `bootstrap/content/<concept_domain>/`

---

## Concept domains in dependency order

Each domain can edge into earlier domains. Domain numbering is dependency order, not size or priority.

### Tier A — Storage protocol content (the graph storing its own protocol)

The 39-axiom spine references OOD_GRAPH_PROTOCOL_v1 by symbol; the protocol's own structural claims aren't yet authored as nodes.

| Domain | Status | What it contains | Source docs (reference) |
|---|---|---|---|
| `storage_identity_grammar` | **admitted + backfilled** (42 nodes / 103 edges; section `077ed261`) — initial 17 + backfill 25 (18 per-class identity rules + 5 canonicalization + 2 mutation) | section_path syntax, version_coordinate forms, graph_address grammar, UUID forms, percent-encoding rules, 18 per-class identity-tuple rules, canonicalization detail | OOD_GRAPH_PROTOCOL_v1 §3 |
| `storage_edge_model` | **admitted + backfilled** (78 nodes / ~184 edges; section `4de287de`) — initial 18 + backfill 60 (34 per-label + 13 per-family + 13 structural) + 1 drift fix (35→34 label count) + 7 raises | edge_label taxonomy with one node per label, edge_family taxonomy with one node per family, edge_identity, per-category property rules, self-edge permission matrix, endpoint promotion rules, identity tuple | OOD_GRAPH_PROTOCOL_v1 §4 |
| `storage_materialization_ceremony` | **admitted + backfilled** (106 nodes / ~239 edges; section `2f77f781`) — initial 40 + backfill 66 (§5 projection + §8 pipeline + §11 forge: 5 closure profiles + 12 fail-closed conditions + per-stage rules + assumptions) + 5 drift fixes + 19 raises | canonical document projection, materialization pipeline (one node per validation gate, per fixture case, per sentinel input), forge consumption contract (one node per closure profile, per fail-closed block condition, per assumption); owns definition_hash / manifest_hash / signature_chain / CommitMaterializationRun / audit_record emission | OOD_GRAPH_PROTOCOL_v1 §5 + §8 + §11 |
| `storage_sentinel_invariant_catalog` | **admitted** (117 nodes / ~305 edges; section `949a16b6` — re-wired from collapsed-identity stub `7a499962` after stable_id-discipline fix) — 100% fidelity at first pass | §15 sentinels (81) + §16 invariants (35); catalog_rules, coverage_matrix, standard_evidence_shapes; raises edges from sentinels to invariants they protect | OOD_GRAPH_PROTOCOL_v1 §15 + §16 |
| `storage_retrieval_surface` | **admitted + backfilled** (68 nodes / ~218 edges; section `bb25832a`) — initial 37 + backfill 31 + 5 references-to-closure-profiles + 2 drift workarounds (authored as new nodes; original drifted nodes remain pending archive verb) | §9 temporal/snapshot model, §10 retrieval contracts (one node per result shape, per diagnostic policy, per source-change rule); owns `snapshot` concept; references the 5 closure profiles owned by §11 | OOD_GRAPH_PROTOCOL_v1 §9 + §10 |

**Tier A LOCKED at 100% fidelity (verified post-R3 across all 5 domains).** 457 nodes in the 5 concept domains + 40-node spine + 1 resolves edge_label_declaration = 519 active graph objects / 1,306 active edges.

Coverage progression by domain:
- storage_identity_grammar: 47% → 100% (R1 closed 18 missing claims via 25 nodes)
- storage_edge_model: 50% → 100% (R1 closed 15 missing + 1 drift fix via 60 nodes)
- storage_sentinel_invariant_catalog: 100% (no backfill — per-row brief produced 100% first pass)
- storage_materialization_ceremony: 32% → 46% → 96.4% → 100% (R1: 66 nodes / R2: 36 nodes + 19 raises / R3: 5 nodes)
- storage_retrieval_surface: 55% → 70-86% → 100% (R1: 31 nodes / R2: 0 nodes (empirical-verification by agent) / R3: 5 nodes + 5 raises)

**Known cosmetic debt (blocked on MCP archive verb — does not affect fidelity %):**
- 3 collapsed-identity orphan stubs (`7a499962` / `58114656` / `31d58d9f`) from pre-stable_id discipline — inert, no incoming concept-domain edges
- 5 duplicate `asserts_invariant` edges on materialization section (cosmetic; same source/target/label admitted twice)
- 23 duplicate `raises` edges in catalog (versioned re-admission of same logical edges)

**Agent definitions enriched post-Tier-A** with three Doc-Graph-Author operational patterns (per-vs-collapse calibration / empirical verification of brief estimates / graph-precedent as tiebreaker) + two new Doc-Graph-Validator rules (R-Granularity / R-StaleRead) encoding the multi-round lessons.

**Known unresolved drift — spec-graph archive verb required (currently absent from MCP)**: 3 collapsed-identity stub nodes from before agents discovered the stable_id requirement remain in the graph with active outbound edges:
- `7a499962` (ex-section): 117 active outbound edges (35 asserts_invariant + 81 declares + 2 depends_on + 1 references) pointing at catalog content. The catalog now has TWO declaring sections — proper `949a16b6` AND the stub. Walks via incoming `declares`/`asserts_invariant` yield both. NOT cosmetic — semantic ambiguity.
- `58114656` (ex-invariant): outbound edges TBD; collapsed identity from 9 dispatch probe attempts (multiple superseded versions).
- `31d58d9f` (ex-sentinel): outbound edges TBD.

MCP currently exposes no archive verb. Cleanup blocked until: (a) `spec_graph_archive` is added to the MCP write surface OR (b) a raw-SQL session with explicit approval marks the stub nodes + edges `status='archived'`. Stubs and their duplicate edges remain queryable until then.

### Tier B — Principal & access model

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `principal_subkinds` | subkinds beyond the 3 admitted types (agent_principal, lobe_principal, tenant_principal, etc.), attestation chain, principal lifecycle | PRINCIPAL_IDENTITY_ACCESS_v6 |
| `grant_model` | grant types, grant scopes, grant lifecycle, grant attestation | PRINCIPAL_IDENTITY_ACCESS_v6, GATE_POLICY_v5 |
| `gate_decision_model` | allow/deny/capability_required taxonomy, gate context, per-effectful-invocation discipline | GATE_POLICY_v5 |
| `caller_context_model` | how principal + grant flow through invocation; the CallerContext shape | PRINCIPAL_IDENTITY_ACCESS_v6 |

### Tier C — Universal node model & ring topology

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `node_universal_model` | the NODE concept (everything executable is a node), implementation_kind ∈ {opcode, circuit}, invocation contract shape | VOLT_v34 §1-§5 |
| `ring_topology` | Ring 0 / Ring 1 / Ring 2 / Ring 3 / Rings 4-7 declarations + boundary rules | VOLT_v34, VELENZA_GRAND_VISION_v1 §3 |
| `node_admission_pipeline` | the kernel-side admission ceremony (extension of `node_admission_axiom` already on spine) | VOLT_v34 admission section, OOD_GRAPH_PROTOCOL_v1 §11 |

### Tier D — Opcode catalog (Ring 0 ISA)

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `opcode_catalog` | one node per locked opcode (SpannerQuery, SpannerMutation, SpannerDDL, InferenceRequest, Embed, HTTPRequest, KMSSign/Verify/Encrypt/Decrypt, HashCompute, DeterministicCompute, Require, SchemaRegistryValidate, TemplateRender, RegexMatch, …); each carries locked invocation contract | VOLT_v34 opcode section |

### Tier E — Invariant catalog

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `kernel_invariants` | every load-bearing structural invariant the kernel enforces; one `invariant` node per claim | VOLT_INVARIANT_CATALOG_v2 |

### Tier F — Sentinel catalog & raise sites

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `sentinel_catalog` | one `sentinel` node per named failure-mode; `raises` edges from circuits/opcodes; `asserts_invariant` edges back to Tier E invariants | VOLT_SENTINEL_CATALOG_v1, SENTINEL_RAISE_SITE_CONVENTION_v4 |

### Tier G — Compiler pipeline

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `compiler_pass_pipeline` | one node per compiler pass, ordered; pass-7-6 receives extra detail; each pass's invariants edge into Tier E | VOLT_COMPILER_PASS_REGISTRY_v1 |

### Tier H — VOLT supporting extracts

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `expression_grammar` | VOLT expression grammar productions, evaluator semantics | VOLT_EXPRESSION_GRAMMAR_v1 |
| `transactional_convergence` | atomic boundaries, multi-mutation coalescing, abort/retry semantics | VOLT_TRANSACTIONAL_CONVERGENCE_v1 |
| `secret_detection` | secret-pattern detection rules, redaction discipline | VOLT_SECRET_DETECTION_v1 |
| `retrieval_model` | corpus retrieval model (embedding routes, retrieval surfaces) | VELENZA_RETRIEVAL_MODEL_v1 |

### Tier I — Runtime transport (LOEF)

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `signal_model` | signal types, envelope shape, ack/nack semantics | LOEF_v13 |
| `lattice_events` | change-stream wake-up model, idempotency window | LOEF_v13 |
| `loef_envelope` | the onion encapsulation format itself | LOEF_v13 |

### Tier J — Metering (LUMEN)

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `cost_model` | cost units, metering events, accounting integers | LUMEN_v3 |
| `economic_protocol` | invoice flow, tenant settlement, currency discipline | LUMEN_v3 |

### Tier K — Lobe / capability / skill hierarchy (rings 4-7)

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `lobe_model` | the lobe concept, lobe boundary, lobe lifecycle | LOBE_HIERARCHY_v9 |
| `capability_model` | capability shape, capability discovery, capability-to-skill binding | LOBE_HIERARCHY_v9, MINDSTATE_CAPABILITY_CONTRACTS_v1 |
| `skill_model` | skill shape, skill catalog | LOBE_HIERARCHY_v9 |
| `interface_layer` | ring-7 interface conventions | LOBE_HIERARCHY_v9 |

### Tier L — Domain infrastructure

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `connector_vault_model` | secret storage shape, vault lifecycle, KMS binding | CONNECTOR_VAULT_v6 |
| `artifact_forge_boundary` | hand-authored vs forged taxonomy, bootstrap substrate definition | ARTIFACT_FORGE_BOUNDARY_PROTOCOL_v1 |
| `app_factory_model` | brick composition, blueprint shape, per-tenant assembly | APP_FACTORY_v2 |
| `docobject_lifecycle` | supersede semantics, version chain, archive policy | DOCOBJECT_LIFECYCLE_VERSIONING_v1 |
| `conformance_model` | conformance gates, validator pipeline | CONFORMANCE_PLAN_v11 |
| `kernel_config_model` | kernel boot config shape, registry loaders | KERNEL_CONFIG_v2 (read v1 only for delta) |
| `encryption_discipline` | per-table encryption rules, KMS key roles, envelope encryption | ENCRYPTION_KMS_DISCIPLINE_v1_SKELETON |
| `canonical_typed_table_schema` | the canonical typed-table schema declarations, per-table contracts, column conventions, supply-chain columns | CANONICAL_TYPED_TABLE_SCHEMA_v1_SKELETON |
| `extension_protocol_model` | how the corpus extends itself, extension authoring rules | EXTENSION_PROTOCOL_v5_SKELETON |
| `external_http_service_model` | per-tenant Cloud Run service contract, OIDC audience rules | EXTERNAL_HTTP_SERVICE_PROTOCOL_v1_SKELETON |
| `fast_path_router` | fast-path routing semantics, hot-cache discipline | FAST_PATH_ROUTER_v4 |
| `file_renderer_model` | file rendering contract, template binding | FILE_RENDERER_v1 |
| `financial_data_storage_and_embeddings` | source-neutral provenance and typed finance homes, source-instance identity, exact values, deterministic entity links, Spanner graph/search/vector projections, asynchronous embedding obligations | VELENZA_GRAND_VISION_v1 §2/§7/§8, VOLT_v34 exact-compute/transaction boundaries, INVOICE_RECORD_v1, CONNECTOR_VAULT_v6, official Spanner embeddings/generated-columns/change-streams/concurrency/vector-index docs and release notes |
| `quickbooks_online_integration_contract` | QBO realm/OAuth/limits/query/CDC/webhook/concurrency/entity schema plus complete Invoice/Line/nested/ref field dispositions into source-neutral finance homes | official Intuit QBO accounting API docs/release notes/static EntityJsonObject_v1 corpus, commit-pinned Intuit QuickBooks-V3-DOTNET-SDK Finance.xsd at `49006edc4678a62aaebae7aec3edd2d8e2f3b9e7`, VELENZA_GRAND_VISION_v1, INVOICE_RECORD_v1 |

### Tier M — Mindstate cluster

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `mindstate_substrate_registry` | substrate registry shape, substrate id model | MINDSTATE_SUBSTRATE_REGISTRY_v1 |
| `mindstate_capability_contracts` | per-mindstate capability contracts | MINDSTATE_CAPABILITY_CONTRACTS_v1 |
| `mindstate_substrate_detail` | substrate-level detail (storage, retrieval, lifecycle per mindstate) | MINDSTATE_SUBSTRATE_DETAIL_v1 |
| `mindstate_overall_model` | mindstate-as-lens model (mindstate is a data partition handle, not an actor) | MINDSTATE_v1_SKELETON, plus operator `feedback_no_actor_language_for_lenses.md` |

### Tier N — Vision & precedence ladder (last; resolves conflicts surfaced by earlier tiers)

| Domain | What it contains | Source docs (reference) |
|---|---|---|
| `vision_precedence_ladder` | the §7 precedence ladder; each rung as a `decision` node that `resolves` conflicts edge-in from earlier tier nodes | VELENZA_GRAND_VISION_v1.md |
| `vision_principles` | §2 principles as `axiom` nodes (or `decision` where they resolve a tension) | VELENZA_GRAND_VISION_v1.md |

---

## Explicit non-domains (NOT authored)

These source docs do **not** become their own domain — their content is absorbed into the domains above:

- `VOLT_v33.ood.json` — historical; read only for context where v34 dropped material
- `VOLT_INVARIANT_CATALOG_v1.ood.json` — superseded by v2
- `KERNEL_CONFIG_v1.ood.json` — read only for delta with v2
- `_*` files (`_corpus_inventory.md`, `_consensus_survey.md`, `_spec_audit_findings.md`, etc.) — scratch / analysis artifacts
- `_SKELETON_TEMPLATE.ood.json` — template
- `_archive_pre_2026_05_25/` — frozen history
- `INDEX.md`, `DOMAINS.md`, `CLUSTERS.md`, `PICK_ONE_REQUIRED.md`, `README.md` — navigation docs, not specs

---

## Per-domain execution loop (graph-native, per-dispatch validation gate)

**HARD GATE: every Doc-Graph-Author dispatch MUST be paired with a Doc-Graph-Validator dispatch BEFORE the orchestrator considers the dispatch complete. A failing validator forces a fix-loop on the same domain; no next-domain dispatch begins until the prior domain's validator returns `verdict=PASS`.**

For parallel dispatch batches: each author dispatch in the batch gets its own paired validator dispatch (also in parallel). All validators must PASS before the orchestrator moves to the next tier. ANY failing validator blocks the tier-advance.

Compound drift accumulates when validators run end-of-batch instead of per-dispatch. The Tier B fan-out (4 parallel authors with no per-dispatch validators) produced 11 wrong-shape sentinels + 50% R6 fail rate + 5 orphan decisions + parent-section orphan declares — all undetected until holistic validation at end-of-batch. The lesson: **use the validator agent after every author dispatch.**

### Mechanical waypoint (forced status-column update)

Orchestrator cannot proceed to next domain dispatch until:
1. Author dispatch returned (notification received)
2. Live-graph query results (node count + edge count + per-kind required-field sample) written into this file's domain row Status column
3. Doc-Graph-Validator dispatch completed against the just-admitted domain
4. Validator verdict written into this file's domain row Status column
5. If `verdict=FAIL`: fix-loop dispatched + re-validate before proceeding

The status column is the mechanical waypoint that prevents implicit-discipline drift.

1. **Parent session pre-check**
   - `spec_graph_search "<domain intent>"` to surface any existing nodes the author should edge into
   - `spec_graph_list object_class=<kind>` for the kinds this domain produces
   - Read the source spec end-to-end via `Read` / `jq` to enumerate the per-subkey source-claim manifest for §5 of the brief template
   - Pre-discover any cross-section reference targets (sibling concept-domain sections) — note in brief

2. **Dispatch `Doc-Graph-Author`** with a tight brief (per §5 manifest + §6 success criteria + §2 framing)
   - One concept domain only; admits DIRECTLY to graph via `spec_graph_import` inline submissions
   - NO files-on-disk pattern (corpus state lives in graph per CLAUDE.md `ANTI_TRAINING.corpus_state_lives_in_the_GRAPH_not_on_disk`)
   - Defined success criterion: every source claim has a graph node OR an edge to an existing node; zero duplicates; cross-section refs queued for parent-session wiring

3. **VERIFICATION GATE — orchestrator queries live graph after author returns, BEFORE marking complete:**
   - `spec_graph_query` for the new section's outbound edge counts vs. brief expectations
   - `spec_graph_query` for per-kind required-field presence on ≥3 sampled new nodes (catches the spec-graph admission gap on wrong-shape canonical_name etc.)
   - `spec_graph_query` for `(node_kind, canonical_name)` collision against existing graph
   - DO NOT trust the agent's structured return as authoritative — it's an INPUT to verification, not the verification itself

4. **Dispatch `Doc-Graph-Validator`** against the just-admitted concept domain
   - Validator queries graph state directly (no files)
   - Applies R3 / R4 / R5 / R6 / R7 / R8 / R10 / R12 / R13 / R15 / R-Boundary / R-OrphanNode / R-Reciprocity / R-Coverage / R-SourceCount-Drift / R-Granularity / R-StaleRead
   - Returns structured findings inline

5. **On validator PASS** — domain LOCKED at 100% fidelity. Proceed to next domain OR next tier.

6. **On validator FAIL** — re-dispatch Author with findings as input. Do NOT proceed to next domain until the failing domain passes.

7. **After validator PASS, wire any deferred cross-section references** as a discrete orchestrator step (spec_graph_link calls). Re-validate the affected sections after wiring.

8. **Tick the row off this file** with admitted counts + verification verdict.

**Recovery from compound drift:** if a tier was admitted under the old end-of-batch validation pattern and drift is discovered late (per Tier B's holistic-validation experience), the recovery sequence is:
- per-domain validator dispatch (one per affected domain)
- per-finding fix (re-admission for drift, new authoring for missing, structured note for false-positive validator findings)
- repeat until each domain validates clean
- only THEN proceed to next tier

---

## Why this order

- **Tier A first** because every later tier's structural edges (`asserts_invariant`, `raises`, `references`) implicitly cite OOD Graph Protocol grammar. Authoring the protocol's own claims as nodes makes those edges resolve.
- **Tier B before C** because every node in C carries a principal contract (who can invoke it under what grant).
- **Tier C before D** because the opcode catalog `declares` ring 0 — the ring concept must exist first.
- **Tiers E + F together-ish** because invariants and sentinels co-define each other (every sentinel `raises` when an invariant is violated). E first so F's edges resolve.
- **Tier N last** because the precedence ladder's `decision` nodes `resolve` conflicts surfaced by claims authored in earlier tiers — those claims must exist as nodes before a decision can edge into them.

---

## Status tracking

Each domain row gains a `Status` column on first activity: `pending` (default) | `authoring` | `validating` | `admitted` | `blocked`. Update this file inline as work progresses.

---

## Dispatch brief template (orchestrator's contract — every dispatch follows this shape)

Every `Doc-Graph-Author` and `Doc-Graph-Validator` dispatch carries the following sections. The brief is FOR the agent; success criteria are the falsifiable end-state the agent must satisfy. No dispatch goes out without all 6 sections filled.

### §1 Concept domain

Name the ONE concept domain from this plan (e.g. `storage_identity_grammar`, `opcode_catalog`). State its boundary: what's IN, what's OUT (belongs to another tier).

### §2 Framing — against training reflex

State the four anti-training claims so the agent can't drift:
- Concept-first, not file-first
- Atomic single-clause claims, not narrative
- Edges carry meaning, not hierarchy
- Dedupe is load-bearing — concepts appearing in N source docs collapse to ONE node

State the CPU mental model so the agent knows what genus the work belongs to.

### §3 Reading list

- `bootstrap/AUTHORING_GUIDE.md` (every dispatch)
- `bootstrap/INGESTION_PLAN.md` (every dispatch; locate this concept domain's row)
- `specs-local/OOD_GRAPH_PROTOCOL_v1.ood.json` (every dispatch — §1, §2, §3, §4 minimum)
- `spec-graph.config.json` (every dispatch — live registry)
- Source docs cross-read for THIS concept (specific paths + sections)

### §4 Existing graph handles (pre-discovered by orchestrator)

Parent runs `spec_graph_list` + `spec_graph_search` before composing the brief. The brief paste the canonical_names of spine nodes + prior-tier nodes the agent will likely edge into. NOT prose — just names + their kinds. Example:

```
Spine axioms relevant to this domain:
  - node_identity_axiom (kind=axiom)
  - node_reference_axiom (kind=axiom)
  - origin (kind=origin)

Kind declarations relevant:
  - section_kind_declaration (kind=node_kind_declaration)
  - invariant_kind_declaration (kind=node_kind_declaration)
```

### §5 Source-claim manifest (orchestrator pre-enumerates — HARD REQUIREMENT, NOT OPTIONAL)

**Every dispatch brief MUST carry §5 — no exceptions, no shortcuts.** Tier B's principal_identity_model validator caught the orchestrator's failure to include this manifest as `R-Coverage_brief_incomplete`. If a dispatch goes out without §5, the validator will fail-grade the orchestrator. The brief is incomplete; the dispatch must be re-composed.

**Standard: 100% coverage. Every structural claim in the source section has a corresponding graph node.** No "≥95%" hedging. No "deviation under target acceptable." The data is right there in the source — read it, enumerate it, admit a node per claim.

**Lesson from Tier A fidelity sweep:** category-level briefs scored 32-55% coverage; the per-row catalog brief scored 100%. The variant-collapse failure mode is structural unless the brief enumerates per-variant. The fix is the manifest, not a coverage tolerance.

Brief MUST carry a structured source-claim manifest, one row per source subkey, with EXACT node count (not minimum). Example:

```
§3 source-claim manifest:
- §3.identity_vocabulary → 7 nodes (one per term: graph_object_id / symbol_id / source_stable_reference / version_coordinate / section_path / graph_address / materialization_identity)
- §3.object_class_identity_rules → 18 nodes (one per declared class)
- §3.graph_address_canonicalization → 5 nodes (per atomic rule)
- §3.id_namespace_rules → 2 nodes (mutation_rule + lifecycle_rule)
- §3.section_path_grammar / version_coordinate_grammar / graph_address_grammar → 3 nodes
Target: EXACTLY 35 nodes. Any missing source claim = dispatch failure.
```

The orchestrator does the source-claim enumeration by reading the source section end-to-end BEFORE dispatching. The agent is held to 100% per-subkey coverage.

### §6 Success criteria — falsifiable end state

The agent's return is successful IFF every checkbox is structurally provable IN THE GRAPH:

**Coverage (from §5 manifest) — 100% standard:**
- [ ] Total node count = manifest target (not "≥" — exact, or with explicit decomposition justification raising the count)
- [ ] Each manifest subkey has its exact stated count of admitted nodes
- [ ] Every structural claim in the source section has a corresponding graph node
- [ ] No subkey collapsed to wrapping-concept (e.g. one `closed_edge_label_registry` decision is NOT a substitute for 34 per-label nodes)
- [ ] Drift = fail. Missing claim = fail. Variant collapse = fail.

**Per-node structure:**
- [ ] Every admitted node has exactly `node_kind` + `contract` + `payload`
- [ ] Every `node_kind` is in config's `node_kinds` registry
- [ ] Every `canonical_name` (or sentinel's `canonical_err_name`) satisfies the kind's pattern
- [ ] Every required contract + payload field present (live-fetched from kind declarations)

**Content discipline:**
- [ ] ZERO prose in payload — no multi-sentence values, no Markdown markers, no paragraph breaks
- [ ] ZERO `source_reference` / `rationale_first_principles` / `self_application_proof` / `statement` (prose) payload keys
- [ ] ZERO duplicates against the live graph at `(node_kind, canonical_name)` granularity
- [ ] ZERO duplicates within the authored directory

**Edge wiring:**
- [ ] Every authored node either (a) edges into ≥1 existing graph node, or (b) is edged into by another authored node in this directory (no orphans)
- [ ] Every edge's endpoint kinds satisfy config's `source_kinds` + `target_kinds`
- [ ] No edge pre-authors a reciprocal mirror (`spec_graph_link` auto-mirrors it per the edge_label's reciprocity rule)
- [ ] No edge endpoint is unresolvable

**Boundary:**
- [ ] Every authored node belongs to THIS concept domain (boundary violations = dispatch failure)

### §6 Return contract

Author returns ONE absolute path: the directory authored. Nothing else.
Validator returns ONE absolute path: the `_findings.json` written. Nothing else.

If the agent returns prose, summary, or a multi-line report instead of one path, the dispatch is malformed and must be re-run.

End of plan.
