# Stage 2c — Agent Escalation Review Brief Template

**Stage purpose.** Stage 2a (`spec-cluster`) and Stage 2b (`spec-dedup-verify`) have already done the bulk of the dedup work. The agent's job at Stage 2c is narrow: review the escalations Flash couldn't resolve, ratify the consolidated ConceptTable.

This brief replaces the earlier all-in-one Stage 2 brief. Dedup is now a three-tier staircase: mechanical (clustering) → Flash (cheap binary classification) → agent (only the genuinely ambiguous cases). Per Vision Principle 14 (AI on the ambiguous parts only) and Principle 5 (operation owns state; cognition judges).

## Reading list

1. `bootstrap/agent_briefs/PIPELINE_OVERVIEW.md` (this directory).
2. `~/.claude/agents/Doc-Graph-Author.md` — author-agent definition; specifically the **STAGED INGESTION WORKFLOW** section.
3. `/opt/velenza/CLAUDE.md` — ANTI_TRAINING + PRIME_DIRECTIVES + SPEC_GRAPH.
4. `/opt/velenza/specs-local/OOD_GRAPH_PROTOCOL_v1.ood.json` — graph storage protocol.

## Inputs

- `bootstrap/staging/<concept_domain>/dedup_decisions.json` — Flash-ratified merges + canonical names + the escalation queue (Phase G output).
- `bootstrap/staging/<concept_domain>/flash_dedup_ledger.json` — audit trail of every Flash call (Phase G output). Useful when an escalation needs the rationale Flash gave when it punted.
- `bootstrap/staging/<concept_domain>/cluster_buckets.json` — original clustering output if needed for context (Phase F output).

## Scope (hard bounds)

- Resolve EVERY entry in `dedup_decisions.json.escalations`. For each:
  - **merge:** both records collapse to one concept; carry both source_refs forward.
  - **split:** they're distinct concepts; emit one concept per record.
  - **decompose:** one or both records are compound (R6-violating) statements that should atomize first; surface for Stage 4 rather than Stage 2.
- Assemble `bootstrap/staging/<concept_domain>/concepts.json` (a ConceptTable) by combining:
  - Every `auto_merge` entry → one concept per cluster, using `chosen_name` as `canonical_name`.
  - Every `verified` entry with `verdict=merge` → one concept (merge A and B).
  - Every `verified` entry with `verdict=split` → one concept per record.
  - Every escalation you resolved → emit per your decision.
  - Every `no_match` → one concept per record.
- Do NOT mutate the graph.
- Do NOT rewrite statements. R6 rewrites are Stage 4.
- Do NOT infer edges. Edge inference is a separate concern.

## ConceptTable output format

`bootstrap/staging/<concept_domain>/concepts.json`:

```json
{
  "concept_domain": "<name>",
  "concepts": [
    {
      "canonical_name": "<snake_case_name>",
      "node_kind": "<section|invariant|...>",
      "contract": { ... per kind requirements ... },
      "payload": { "<leaf_name>": "<raw_value>", ... },
      "source_refs": ["<source_file>#<source_path>", ...]
    }
  ],
  "edges": []
}
```

Edges array stays empty at this stage.

## Workflow

1. **CAPTURE.** Read dedup_decisions.json, flash_dedup_ledger.json. Build a mental map of cluster outcomes.
2. **TRIAGE ESCALATIONS.** For each escalation: look at the pair, the ledger rationale (if Flash gave one before punting), and decide merge / split / decompose.
3. **ASSEMBLE.** Construct the ConceptTable JSON by walking auto_merge + verified + resolved-escalations + no_match.
4. **VERIFY.** `jq empty bootstrap/staging/<concept_domain>/concepts.json` passes.
5. **REPORT.** Single line summary on output count by source bucket.

## Success criteria

- Every escalation entry resolved with an explicit decision.
- ConceptTable JSON is well-formed (passes `jq empty`).
- Every concept has at least one source_ref.
- Every canonical_name is unique within the table.
- No prose narration in the dispatch transcript — staging files ARE the deliverable.

## What this stage does NOT do

- Re-run R-rules in your head. The linter (Stage 3) is the rule engine.
- R6 rewrites (Stage 4).
- Edge inference.
- Graph mutation (Stages 5/6).
- Pull new records the pipeline didn't extract.

## Why the scope shrunk

Earlier dispatches had the agent do all of Stage 2 — record reading, clustering, dedup decisions, name picking. Most of that is mechanical or Flash-tier. The full agent's value is on the genuinely-ambiguous escalations and on the final ratification pass. Restricting scope here reduces context budget, reduces decision drift, and matches Vision Principle 14.
