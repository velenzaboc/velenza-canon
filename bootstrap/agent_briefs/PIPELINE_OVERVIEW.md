# Staged Spec-Ingestion Pipeline — Overview

This directory holds the canonical brief templates for the agent-driven stages of the spec-graph ingestion pipeline. The pipeline was introduced to eliminate the admit-then-discover-violation churn pattern that produced 5+ rounds of cleanup against the Tier B concept domains (PIA, gate_policy, grant_model, caller_context_model).

## Why a staged pipeline

The previous pattern had agents reason about ~9 distinct things per dispatch — parsing source `.ood.json`, deciding `node_kind`, deriving `canonical_name`, deciding contract-vs-payload field split, dedup against existing graph state, R6 prose reduction, R3/R4/R5/R7/R10/R12/R13/R15 schema checks, edge inference, edge_label selection. Seven of those nine activities are mechanical and were being done by a non-deterministic actor (LLM), producing predictable drift across re-dispatches.

Per Vision Principle 14 (fractal engineering: *AI on the ambiguous parts only*) and Principle 5 (two kernels, separated in code: *cognition judges, operation owns state*), the staged pipeline restores the boundary. Code handles every mechanical step. Agents handle the two genuinely judgment-shaped activities: dedup decisions (Stage 2) and lint-ambiguous R6 rewrites (Stage 4).

## The stages

| Stage | Doer | Deliverable |
|---|---|---|
| 0 | code (spec-graph fix) | Typed read verbs filter to active-latest. Prereq for trustworthy reads downstream. |
| 1 | code (`spec-extract`) | Source `.ood.json` → flat ConceptRecords per extraction recipe. |
| 2a | code (`spec-cluster`) | ConceptRecords → embedding-clustered three buckets (auto_merge / verify_required / no_match) per configured cosine-distance thresholds. |
| 2b | code (`spec-dedup-verify` + Vertex AI Flash) | Flash picks canonical name for auto_merge clusters; Flash classifies verify_required pairs as same-concept yes / no / uncertain. Every Flash call writes a ledger entry (audit trail). |
| 2c | **agent (this directory: `stage2_dedup_judgment.md`)** | Resolve escalations Flash returned uncertain/unparseable on; assemble consolidated ConceptTable. |
| 3 | code (`spec-lint`) | ConceptTable → structured findings per R-rule (R3/R4/R5/R6/R7/R8/R10/R12/R13/R15). Gates Stage 4. |
| 4 | **agent (this directory: `stage4_r6_rewrite.md`)** | R6-ambiguous statements → rewritten single-clause statements. |
| 5 | code (`spec-admit`) | Validated ConceptTable → directory of submission JSON files. |
| 6 | existing `spec_graph_import` | Submission directory → admitted graph state. |

Dedup is a three-tier staircase (2a → 2b → 2c): mechanical clustering catches the obvious; Vertex AI Flash handles cheap binary classification; the full agent only handles genuinely ambiguous escalations. Per Vision Principle 14 (AI on the ambiguous parts only) and Principle 5 (operation owns state; cognition judges).

## Discipline that maps onto every agent-driven stage

These rules apply across Stages 2 and 4:

- **The disk artifact is the workspace; the graph is canonical.** Agents read and write the staging files under `bootstrap/staging/<concept_domain>/`. The graph is consulted only via the typed read verbs (post-Phase-A active-only filtering) when explicit dedup against existing graph state is required.
- **One concept_domain per dispatch.** Cross-domain decisions surface as graph-level concerns, not staging-file concerns.
- **The agent does not run R-rules in its head.** R-rule findings come from `spec-lint`; the agent operates on the linter's output, not on its own interpretation of the rules.
- **Output is structured, not narrative.** Agents update the staging JSON files; they do not write summary prose to the dispatch transcript.
- **File-mediated CAPTURE → EDIT → VERIFY pattern.** Same discipline as the drift-fix workflow encoded in `~/.claude/agents/Doc-Graph-Author.md`: read the staging file, edit on disk, jq-validate, write back.

## Reading list for any pipeline-stage dispatch

1. This file (PIPELINE_OVERVIEW.md).
2. The stage-specific brief template (`stage2_dedup_judgment.md` or `stage4_r6_rewrite.md`).
3. `~/.claude/agents/Doc-Graph-Author.md` — the canonical author-agent definition.
4. `/opt/velenza/CLAUDE.md` — ANTI_TRAINING + PRIME_DIRECTIVES + NEVER + SPEC_GRAPH.
5. `/opt/velenza/specs-local/OOD_GRAPH_PROTOCOL_v1.ood.json` — graph storage protocol.
