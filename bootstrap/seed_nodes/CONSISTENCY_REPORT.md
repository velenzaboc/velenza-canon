# Consistency Report — Seed Nodes 001 through 039

**Date of walk:** 2026-05-26
**Scope:** all 39 seed-node JSON files in `bootstrap/seed_nodes/` plus `NODE_QUALITY_DISCIPLINE.md` and the parent `KIND_DECLARATIONS_PLAN.md`
**Methodology:** end-to-end file reads (per PRIME_DIRECTIVES `read_files_dont_grep`), layer-by-layer walk, cross-reference resolution check, lifecycle/encryption-posture drift check.

---

## Verdict

**2 DEFECTS require resolution before admission run.** Both are surface-level fixes (single-field amendments) with clear resolutions; no deep redesign.

**1 DRIFT is harmless but worth tightening.** Schema vs discipline overlap; resolvable by either tightening the schema or documenting the overlay.

**1 ORDERING NOTE is discretionary** (narrative quality, not operational correctness).

**All other layers are internally consistent and cross-consistent.** 35 of 39 files have no findings.

---

## RESOLUTION STATUS (as of 2026-05-26 — Vision-aligned serial walk)

All findings that required corpus-state changes have been resolved. Each fix was applied serially, validated, and cascade-checked against the rest of the corpus before moving to the next.

| Finding | Status | Resolution applied |
|---|---|---|
| DEFECT #1 (009 ↔ 022 superseded drift) | ✓ RESOLVED | Dropped "superseded" from 009's asserts and statement; added clarifying reference to node_version_chain_axiom for the "old versions aren't consulted" semantic. Lower-tier 022 is unchanged. |
| DEFECT #2 (023 lifecycle contradiction) | ✓ RESOLVED | Flipped 023 to re_admittable=true, immutable_once_admitted=false; renamed assert from `snapshots_are_immutable_once_admitted` to `snapshot_captured_state_is_immutable_across_versions`; reframed rationale + contract_monotonicity_rule + description to clarify that captured-state immutability comes from contract_monotonicity (contract byte-equivalence across versions) while status transitions ARE re-admissions producing new version rows with same contract / advanced status. Matches 022 grant pattern. |
| DRIFT #3 (014 schema vs 018 discipline) | ✓ RESOLVED | Added new rationale `why_payload_fields_optional_at_meta_level` to 014's payload explicitly documenting the per-kind tightening pattern. Each declared kind tightens its own required_payload_fields beyond the meta-kind's optional baseline (verified across all 13 kind declarations — every one varies). |
| ORDERING NOTE (009 ↔ 010 filename order) | ✓ RESOLVED (no change) | Per Vision §7 analysis: bootstrap exemption makes filename order operationally irrelevant; renaming files opens a window for mistakes; the intentional layering is documented in this report. |
| A6 (audits self-loop ban) | ✓ RESOLVED | Added structural assert `audits_forbids_self_loops_per_audit_record_fixed_point` to 036 + paired rationale + description update. The ban implements the per-label self-loop policy 006 axiom defers to and matches the fixed-point design 021 declares. |
| A7 (plan vs final divergence) | ✓ RESOLVED | Updated KIND_DECLARATIONS_PLAN.md Phase 3 AND Phase 4 tables to match final declarations. Phase 3 removed inline reference fields (parent_section_id, owning_section_id, relied_on_by, affected_nodes) — these are now via edges per node_reference_axiom. Phase 4 widened source_kinds where final declarations widened (axiom added to raises/asserts_invariant/assumes sources); removed doc_object reference; added reciprocity for load_bearing_for; documented Pass-6 framework calls for both widenings. |

**Authoring notes A1-A5 status:** documented in the AUTHORING NOTES section below; these are authoring-discipline guidance for downstream content authors. They describe correct interpretation of structurally-encoded behavior — no further corpus changes needed.

**Files edited in this resolution pass:**
- `bootstrap/seed_nodes/009_corpus_authorization_axiom.json`
- `bootstrap/seed_nodes/014_node_kind_declaration_meta_kind.json`
- `bootstrap/seed_nodes/023_snapshot_kind_declaration.json`
- `bootstrap/seed_nodes/036_audits_edge_label.json`
- `bootstrap/KIND_DECLARATIONS_PLAN.md`
- `bootstrap/seed_nodes/CONSISTENCY_REPORT.md` (this file)

**Validation:** all 39 seed-node JSON files parse cleanly after edits; structural spot-checks confirm each fix landed as intended; no cascading drift introduced elsewhere.

**Admission-readiness:** the bootstrap layer is now admission-ready pending the remaining operational gates (MCP `spec_graph_import` operational, bootstrap principal node authored at admission time, operator-controlled cutover).

---

## DEFECT #1 — 009 ↔ 022 drift on "superseded" grant status

**Location:** `009_corpus_authorization_axiom.json` line 8 + `022_grant_kind_declaration.json` line 55

**The drift:**

009 asserts:
> "authorization evaluates active grants — revoked, expired, or **superseded** grants do not authorize"

022 declares:
```json
"status_enum": ["active", "revoked", "expired"]
```

**No `superseded` state exists for grants.** 022's contract_monotonicity_rule explicitly states: *"changing [authorization clause, subject, granting_authority, granted_at] is a different grant requiring a different stable_id."* Content changes produce a NEW grant with a NEW stable_id, not a superseded version of the existing one.

**Resolution (recommended):** amend 009 to drop `superseded` from the enumeration. The corrected wording:
> "authorization evaluates active grants — revoked or expired grants do not authorize"

**Why this direction, not the other:** Adding `superseded` to 022's lifecycle would introduce a second mechanism for grant evolution (in-place supersession AND new-stable-id replacement), making the gate's authorization-decision logic harder to reason about. 022's design (new-stable-id for content changes) is the cleaner pattern; 009's mention of `superseded` is a leftover concept that doesn't apply to grants.

---

## DEFECT #2 — 023 internal contradiction: re_admittable=false + multi-state lifecycle

**Location:** `023_snapshot_kind_declaration.json` lines 43-50 + line 59

**The contradiction:**

Lines 43-48:
```json
"status_enum": ["active", "archived", "invalid"],
"legal_transitions": [
  {"from": "active", "to": "archived"},
  {"from": "active", "to": "invalid"}
],
```

Lines 49-50:
```json
"re_admittable": false,
"immutable_once_admitted": true
```

Line 59 (contract_monotonicity_rule):
> "Status transitions (active→archived, active→invalid) happen via lifecycle operations producing a new version row reflecting the new status"

**These contradict each other.** Per `011_corpus_lifecycle_axiom.json` (line 8), status transitions ARE admissions and produce new version rows. That requires `re_admittable=true`. With `re_admittable=false`, no new version row can ever be created, so the legal_transitions can never fire.

**Compare with 021 (audit_record_kind):** truly immutable — status_enum=[admitted], no transitions, re_admittable=false, immutable_once_admitted=true. Internally consistent.

**Compare with 022 (grant_kind):** re_admittable=true + contract_monotonicity_rule forbids content changes but allows status flips via new version rows. Internally consistent.

**Resolution (recommended):** flip 023 to match the 022 pattern.
```json
"re_admittable": true,
"immutable_once_admitted": false
```

The snapshot's captured content (the rows it includes) stays immutable per the contract_monotonicity_rule's content-change prohibition. Only the lifecycle marker (status) advances via re-admission. This preserves the structural immutability of the snapshot's captured state while permitting the operational lifecycle transitions the kind needs.

**Alternative:** collapse the lifecycle to `status_enum=[active]` only, drop transitions, leave re_admittable=false. This treats archival/invalidation as separate operational concepts outside the corpus lifecycle. Less consistent with corpus_lifecycle_axiom's pattern; not recommended.

---

## DRIFT #3 — schema permissiveness vs authoring-discipline strictness

**Location:** `014_node_kind_declaration_meta_kind.json` lines 71-72 + `018_axiom_kind_declaration.json` lines 17-18 + `NODE_QUALITY_DISCIPLINE.md` Passes 1, 5

**The drift:**

014's content_schema for node_kind_declarations:
```json
"required_payload_fields": ["title", "description"],
"optional_payload_fields": ["rationale_first_principles", "self_application_proof", "out_of_scope"]
```

018's content_schema for axiom instances:
```json
"required_payload_fields": ["title", "statement", "rationale_first_principles", "self_application_proof", "out_of_scope"]
```

NODE_QUALITY_DISCIPLINE.md Pass 1 lists `self_application_proof` as a required check. Pass 5 lists `out_of_scope` completeness as a required check.

**The drift:** a node_kind_declaration that omits rationale_first_principles/self_application_proof/out_of_scope would pass 014's schema (those fields are optional). But an axiom that omits them would fail 018's schema. And the authoring discipline expects every node to have them.

**Resolution options:**

(a) **Tighten 014** — add the three fields to `required_payload_fields`. Pros: structural enforcement at the gate; no relying-on-discipline. Cons: the meta-kind's schema becomes opinionated about node-quality discipline, which might over-constrain future node_kind_declarations that legitimately don't need rationale_first_principles (e.g., a procedurally-generated kind declaration).

(b) **Document the overlay** — keep 014 permissive; document in the discipline doc that each declared kind may tighten its own payload requirements. Pros: 014 stays minimal; per-kind tightening is the established pattern (018 already does it). Cons: discipline is operator policy, not structurally enforced; a node_kind_declaration that omits the fields is structurally admitted but discipline-non-conformant.

**Recommendation: (b) — document the overlay.** The per-kind tightening pattern is already established (018 tightens for axioms, 022 tightens for grants with required `reason` payload field, etc.). 014 being permissive is consistent with its role as the meta-kind; declared kinds tighten as appropriate.

---

## ORDERING NOTE — 009 admits before 010 (narrative discontinuity)

**Location:** filename order `009_corpus_authorization_axiom.json` then `010_grant_axiom.json`

**The observation:** 009 references grants as a concept that 010 axiomizes. The narrative reads: "we have authorization that requires grants" → "now here's what grants are."

The conceptual order would be: "we have grants" → "now here's the authorization discipline that uses them."

**Operational status:** Both orderings work. Bootstrap exemption (EXPERIMENTAL_BOOTSTRAP) means neither axiom's claims are enforced during their own admission, so the chicken-and-egg never executes operationally. Once cutover happens, both axioms exist together and are mutually consistent.

**Discretionary action:** if narrative quality matters for the locked corpus, swap to 009↔010 order (renaming 009→010 and 010→009 in filenames, or inserting a 009.5 placeholder). If narrative doesn't matter for the locked corpus, leave as-is.

**Recommendation:** leave as-is. Renaming opens a window for file-rename mistakes; the operational correctness is unaffected. Document the narrative ordering choice in this report so future readers understand the intentional layering.

---

## CONFIRMED-CONSISTENT — observations that look like drift but aren't

These were investigated and found NOT to be drift:

### Origin (001) contract shape divergence

**Observation:** 001's contract uses prose-named field-keys (`kind_identity`, `single_instance_rule`, `voice_preservation_rule`, `conflict_terminus_role`) instead of the uniform `asserts` block every other axiom carries.

**Verified consistent with 017** (`017_origin_kind_declaration.json` line 16): the origin kind's required_contract_fields are EXACTLY these four prose-named fields plus contract_monotonicity_rule. The shape is intentional — origin is single-instance and doesn't carry the canonical_name+asserts pattern that taxonomy kinds use.

### Identity-field pattern across kinds

**Observation:** different kinds use different identity field names.

**Verified intentional structural distinction:**
| Kind | Identity field on instances |
|---|---|
| origin | `kind_identity` (single-instance, no separate name) |
| axiom | `canonical_name` |
| principal | none (identified by stable_id + display_identity) |
| edge | none (identified by source+target+label) |
| audit_record | none (identified by principal+subject+timestamp) |
| grant | none (identified by subject+authorization+granting_authority) |
| snapshot | none (identified by snapshot_version per tenant) |
| section | `canonical_name` (optional — anonymous sections allowed) |
| sentinel | `canonical_err_name` (CamelCase Err* prefix) |
| invariant / assumption / decision | `canonical_name` |

Each kind's identity field reflects its categorical role. **No drift.**

### Lifecycle variations across content kinds

**Observation:** content kinds have different status_enum compositions (some have `deprecated`, some have `superseded`, some have both).

**Verified intentional per-kind semantic:**
- section: 4-state (full deprecation + supersession)
- sentinel: deprecated only (a new sentinel is a different sentinel; supersession doesn't apply)
- invariant: superseded only (in force or not; deprecation as soft-warn doesn't apply)
- assumption: 4-state (deprecation + supersession both legitimate)
- decision: superseded only (end-state records; don't deprecate)

Each variation reflects the kind's lifecycle semantics. **No drift.**

### 036 audits → audit_record (recursion concern)

**Observation:** 036's target_kinds includes `audit_record`, raising the question of audit-record-of-audit-record infinite recursion.

**Verified resolved by 021's fixed-point design** (`021_audit_record_kind_declaration.json` out_of_scope item): *"the audit-record-of-audit-record (infinite recursion forbidden by construction: audit records are admitted but their admission's audit record is the audit record itself; the chain has a fixed point)."*

An audit_record A documenting audit_record B's admission is legitimate. A's own admission needs no further audit because A IS its own audit. The operational gate must handle this fixed-point at admission. **No structural drift; operational care required.**

### Bootstrap-exempt self-application claims (009, 010, 038, 039)

**Observation:** 009 (authorization), 010 (grant), 038 (system principal), 039 (external_system principal) all carry self_application claims that reference structures (grants, principals) which don't yet exist at the moment of their own admission.

**Verified consistent with bootstrap exemption per 004 (principal_axiom out_of_scope):** *"bootstrap admissions during corpus seeding — these may use a sentinel value as admitted_by before the bootstrap principal node itself exists; this axiom's steady-state claim acknowledges that exception."*

EXPERIMENTAL_BOOTSTRAP admits these layers without enforcing the steady-state claims. The claims hold for the steady state that the operator-controlled cutover establishes. **No drift; bootstrap is the named exception.**

---

## CROSS-REFERENCE RESOLUTION — all dependencies resolve

Verified during the per-layer walks:

### Axiom inter-dependency DAG (acyclic):

| Axiom | Depends on |
|---|---|
| 002 node_identity | (foundation, no dependencies) |
| 003 version_chain | 002 |
| 004 principal | 002, 003 |
| 005 admission | 002, 003, 004 |
| 006 reference | 002, 003, 005 |
| 007 audit | 005 |
| 008 authentication | 004, 005, 007 |
| 009 authorization | 005, 007, 008, 010 |
| 010 grant | 002, 004, 005, 007 |
| 011 lifecycle | 005, 007 |
| 012 temporal | 002, 005, 007 |
| 013 encryption | 002, 007 |

No cycles. Filename order satisfies all dependencies under bootstrap exemption.

### Meta-kind cascade (acyclic):

- 014 (node_kind_declaration meta-kind) → self-recursive, admits under EXPERIMENTAL_BOOTSTRAP
- 015 (edge_label_declaration meta-kind) → admits as node_kind=node_kind_declaration; requires 014 in registry
- 016 (principal_type_declaration meta-kind) → admits as node_kind=node_kind_declaration; requires 014 in registry
- 017-028 (kind declarations) → admit as node_kind=node_kind_declaration; require 014 in registry
- 029-036 (edge label declarations) → admit as node_kind=edge_label_declaration; require 015 in registry
- 037-039 (principal type declarations) → admit as node_kind=principal_type_declaration; require 016 in registry

Filename order satisfies cascade. Each admission's prerequisite is in the registry before it admits.

### Edge label endpoint kinds — all reference admitted kinds:

| Edge label | source_kinds | target_kinds | Verified |
|---|---|---|---|
| 029 depends_on | 6 content+axiom kinds | same 6 | ✓ |
| 030 load_bearing_for | 6 content+axiom kinds | same 6 | ✓ |
| 031 references | 14 kinds (excludes origin from source) | 15 kinds (includes origin) | ✓ (origin asymmetry intentional) |
| 032 raises | [axiom, section, decision] | [sentinel] | ✓ |
| 033 asserts_invariant | [axiom, section, decision] | [invariant] | ✓ |
| 034 assumes | [axiom, section, decision] | [assumption] | ✓ |
| 035 declares | [axiom, section] | [section, sentinel, invariant, assumption, decision] | ✓ |
| 036 audits | [audit_record] | 15 kinds (every registry entry) | ✓ |

Every named kind is in the registry. **No dangling references.**

### Principal type values are admissible per 019:

037 (human), 038 (system), 039 (external_system) canonical_names are the admissible values for principal nodes' `principal_type` field per 019's contract.

---

## AUTHORING NOTES worth surfacing

These are observations from the walk that don't represent drift or defects but warrant explicit authoring guidance so future content authors don't misread the edge labels or kind declarations. None of them block admission; all of them deserve a place in authoring documentation downstream of this layer locking.

### A1. `raises` is a structural-catalog claim, not a runtime claim

`032_raises_edge_label.json` permits source_kinds=[axiom, section, decision]. None of those node kinds execute at runtime — they describe corpus structure or capture choices. The `raises` edge therefore means:

> "this corpus member CATALOGS the failure mode (it describes the conditions under which the named sentinel arises)"

NOT:

> "this corpus member PRODUCES the failure mode at runtime"

Authors authoring `raises` edges should understand that the edge documents structural raise-site inventory. The corpus member at the source isn't asserting it will throw the sentinel — it's asserting that the sentinel is one of the failure modes its semantic surface covers. Misreading `raises` as a runtime claim would lead authors to refuse `raises` edges on axioms (which is structurally fine), or to expect `raises` edges to imply executable behavior (which they don't).

### A2. `references` is the non-load-bearing citation edge — do not substitute for `depends_on`

`031_references_edge_label.json` has the widest endpoint arrays of any edge label (14 sources, 15 targets — everything in the registry except origin as source). This openness invites misuse: a `references` edge between two content nodes might LOOK structurally identical to a `depends_on` edge, but the semantic is fundamentally different:

- `depends_on` (family=dependency) → A's claims rely on B's claims being held; retiring B undermines A; participates in the dependency closure.
- `references` (family=reference) → A cites/mentions B; retiring B does NOT undermine A; does NOT participate in the dependency closure.

Authors should default to `references` for "see also" and "citation" relationships, and reserve `depends_on` for true reliance. Using `references` where `depends_on` belongs would silently break impact-analysis queries (retire a load-bearing target and the dependents wouldn't be flagged). Using `depends_on` where `references` belongs would inflate the dependency closure with non-load-bearing citations.

### A3. `audits` defaults to `version_pinning_default: version_pinned` — UNIQUE among edge labels

Every other edge label (029, 030, 031, 032, 033, 034, 035) defaults `version_pinning_default: current_active`. Only `036_audits_edge_label.json` defaults to `version_pinned`.

This is intentional and structurally necessary per the temporal axiom — audit history must reference the SPECIFIC historical version of the subject at the time of the audited event. An `audits` edge that silently retargeted to a later version when queried would erase historical provenance.

Authors authoring `audits` edges (which in practice the admission gate does automatically per `005`) must populate `target_version_pin` with the subject's version at the moment of audit. Authoring an `audits` edge with `target_version_pin: null` would resolve to the current active version, which defeats the audit chain's claim about a specific historical moment.

### A4. Section hierarchical composition uses `declares` edges, not inline parent references

`024_section_kind_declaration.json` explicitly forbids inline parent_section_id fields. Parent-child relationships between sections are expressed via `declares` edges (`035_declares_edge_label.json` source_kinds=[axiom, section], target_kinds=[section, ...]). A parent section declares each child section.

Authors building section trees should:
- Admit the parent section first.
- Admit each child section.
- Admit one `declares` edge from parent to each child.

Authoring sections with nested-payload child structures (treating section.body as a JSON tree of subsections) would bypass the edge-based hierarchy and break traversal queries like "what sections does this parent contain?" — those queries walk `declares` edges, not section payloads.

### A5. `038 system` vs `039 external_system` authority posture is asymmetric — grant carefully

The two machine principal types have INVERTED default authority postures:

| Type | default_trust_tier | Authority pattern |
|---|---|---|
| 038 system | `core_admin` | High default; restrict via grants |
| 039 external_system | `external` | Low default; **NO structural authority**; every action must trace to an explicit grant |

This asymmetry reflects the trust-boundary asymmetry (internal vs external) but is operationally easy to misuse:

- Granting a `system` principal a permission you don't intend it to have is the default risk — operators must remember to restrict.
- Granting an `external_system` principal a permission inadvertently is harder because the type confers nothing by default — but failing to grant the permissions it legitimately needs will manifest as silent denials.

Authors and operators provisioning new principals should consciously choose the type before admitting, and then think about grants as either "restriction-shaped" (system) or "elevation-shaped" (external_system) depending on which type they chose.

### A6. `audits` edges from audit_record A to audit_record A are NEVER admitted

Per `021_audit_record_kind_declaration.json` (out_of_scope item): *"the audit-record-of-audit-record... the chain has a fixed point."*

An audit_record A documenting some OTHER admission produces an `audits` edge from A to its subject. A's own admission needs no separate audit_record — A IS the audit. Therefore an `audits` edge with source_stable_id == target_stable_id == A's stable_id is structurally wrong-shape and must be refused at the gate.

This is an authoring concern because future content extracted from audit chains or generated by tooling might naively produce such self-loops. The gate should refuse them; authors and tool-builders should know to never emit them.

### A7. Plan-vs-final divergence in source_kinds for raises/asserts_invariant/assumes

`KIND_DECLARATIONS_PLAN.md` Phase 4 table lists narrower source_kinds than the final declarations carry:

| Edge | PLAN source_kinds | FINAL source_kinds |
|---|---|---|
| raises | `[section, decision]` | `[axiom, section, decision]` |
| asserts_invariant | `[section, axiom]` | `[axiom, section, decision]` |
| assumes | `[section, axiom]` | `[axiom, section, decision]` |
| declares | `[section, doc_object]` | `[axiom, section]` (doc_object removed entirely per in-session correction) |

The widening was a Pass-6 framework call during drafting — axioms structurally describe behavior including failure conditions, assertions, and assumptions; restricting source_kinds to exclude axioms would prevent the foundational layer from authoring its own raises/asserts/assumes relationships. Anyone comparing the plan to the final declarations will see the divergence; the final declarations are correct, and the plan table is now an artifact of the pre-drafting design phase.

**Recommendation:** either update KIND_DECLARATIONS_PLAN.md's Phase 4 table to match the final declarations, or add a note in the plan that source_kinds were widened during authoring. The plan currently has a Status section noting drafting complete; the table itself wasn't updated to match the widened arrays.

---

## OPERATIONAL NOTES for the admission run

1. **EXPERIMENTAL_BOOTSTRAP** admits all of 001-039. The bootstrap principal node (not yet drafted — depends on operator-chosen keying material) is the final EXPERIMENTAL_BOOTSTRAP admission.

2. **Operator-controlled cutover** happens at operator discretion after the bootstrap principal admits. Per `KIND_DECLARATIONS_PLAN.md` admission order, cutover locks the gate to require admitted-principal-stable_id as admitter.

3. **036 audits fixed-point handling** must be implemented in the gate so audit_record A's `audits` edge to audit_record B doesn't trigger infinite recursion. A is its own audit; no further audit_record is produced for A's admission specifically.

4. **Reciprocity pairing (029 ↔ 030)** must be admitted atomically per `015` edge_label_declaration meta-kind's reciprocity contract. Admitting depends_on triggers automatic mirror admission of load_bearing_for in the same transaction.

5. **Origin (001) shape divergence is intentional** — the gate validates 001 against 017's content_schema (the kind_identity + 3 rules layout), not against the uniform asserts pattern.

---

## RECOMMENDED PRE-ADMISSION ACTIONS

In order:

1. **Fix DEFECT #2** — edit `023_snapshot_kind_declaration.json` to flip `re_admittable: true` and `immutable_once_admitted: false`. Single field change; preserves all other semantics; resolves the internal contradiction.

2. **Fix DEFECT #1** — edit `009_corpus_authorization_axiom.json` line 8 to remove `"superseded"` from the enumeration of non-authorizing grant states. Single-word amendment.

3. **Document DRIFT #3** — add a clarifying note (either in `014` payload's rationale or in `NODE_QUALITY_DISCIPLINE.md`) that each declared kind may tighten its payload requirements beyond the meta-kind's optional baseline.

4. **Discretionary: act on ORDERING NOTE** — leave 009→010 filename order as-is (recommended); document the intentional layering in this report for future readers.

5. **Validate JSON** after the two edits via `jq empty` to confirm no parse damage.

6. **Re-run the per-layer walk** for 009 and 023 after edits to confirm the fixes resolve the contradictions without introducing new ones.

7. **Proceed with admission run** once 1-6 are clean.

---

## File inventory

39 seed-node JSON files admitted into the bootstrap layer:
- 1 origin (001)
- 12 foundational axioms (002-013)
- 3 meta-kinds (014-016)
- 7 back-fill kind declarations (017-023)
- 5 content kind declarations (024-028)
- 8 edge label declarations (029-036)
- 3 principal type declarations (037-039)

Plus supporting documents:
- `NODE_QUALITY_DISCIPLINE.md` — Pass 1-6 authoring checklist
- `README.md` — file index with one-line per-file summary
- `bootstrap/KIND_DECLARATIONS_PLAN.md` — layer plan with Status section noting all phases drafted

**End of report.**
