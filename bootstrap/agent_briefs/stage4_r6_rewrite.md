# Stage 4 — R6 Rewrite Brief Template

**Stage purpose.** Stage 3 (`spec-lint`) has run against the ConceptTable and produced a structured findings file. Most violations the linter caught are mechanical (R3/R4/R5/R7/R8/R10/R12/R13/R15) and the author fixes them directly without judgment. R6 is the exception: the linter flags strings that fail the seven-heuristic prose detector, and rewriting them to single-clause / single-finite-verb form requires preserving semantic meaning — that's the genuinely judgment-shaped activity.

This stage's only job: for each R6-flagged statement, produce a rewritten statement that preserves meaning while passing R6.

## Reading list

1. `bootstrap/agent_briefs/PIPELINE_OVERVIEW.md` (this directory).
2. `~/.claude/agents/Doc-Graph-Author.md` — author-agent definition.
3. `/opt/velenza/CLAUDE.md` — ANTI_TRAINING + PRIME_DIRECTIVES + SPEC_GRAPH.
4. `bootstrap/cmd/spec-lint/r6_no_prose.go` — the seven heuristics, in code form. Read this so the rewrite obeys the same rules the linter applies.

## Inputs

- `bootstrap/staging/<concept_domain>/concepts.json` — the ConceptTable to update.
- `bootstrap/staging/<concept_domain>/lint_findings.json` — the linter output. Filter to `rule == "R6_no_prose"`.

## Scope (hard bounds)

- Rewrite ONLY the values flagged in the findings file. Do NOT touch any other field.
- Preserve the field's KEY untouched. The rewrite changes the VALUE.
- Do NOT rewrite values whose `field_path` resolves to a contract field — contract is byte-equivalence-locked across versions (per `node_version_chain_axiom`). Surface those under `unfixable_contract_field_r6` in the dispatch output and leave the concept unchanged.
- Do NOT add new sentences, examples, or qualifications. The rewrite is a reduction, not an expansion.
- Do NOT change semantics. If a faithful single-clause rewrite is impossible, surface the value under `decompose_proposed` with a proposed decomposition into multiple atomic concepts; the orchestrator decides whether to admit the decomposition or accept the prose.

## Workflow

1. **CAPTURE.** Read the ConceptTable and the findings file.
2. **CLASSIFY each R6 finding.** For each violation:
   - If the value reduces to single-clause / single-finite-verb without semantic loss → `rewrite`.
   - If the value carries two distinct atomic claims joined by a conjunction → `decompose_proposed` (one statement per claim, surfaced for orchestrator review).
   - If the violation is in a contract field → `unfixable_contract_field_r6`.
3. **REWRITE each rewriteable value.** Apply the heuristics:
   - Replace subordinating clauses with participial phrases: `fires when X` → `fires on X` or `fires-X` as canonical_name.
   - Replace coordinating conjunctions with separate concepts (decomposed) or drop redundant predicates.
   - Replace multi-sentence text with the single canonical claim.
   - Trim to under 200 characters.
4. **VERIFY.** Mentally re-run the seven R6 heuristics against each rewrite. If your rewrite still trips any heuristic, the rewrite is not done.
5. **WRITE.** Update the ConceptTable in place with the rewritten values. Emit `bootstrap/staging/<concept_domain>/stage4_outcomes.json` listing per-finding outcome (rewrite | decompose_proposed | unfixable_contract_field_r6).

## Output format

Updated `bootstrap/staging/<concept_domain>/concepts.json` (same shape; only the flagged values change).

`bootstrap/staging/<concept_domain>/stage4_outcomes.json`:

```json
{
  "concept_domain": "<name>",
  "outcomes": [
    {
      "canonical_name": "<name>",
      "field_path": "payload.statement",
      "outcome": "rewrite",
      "before": "<original prose>",
      "after": "<single-clause rewrite>"
    },
    {
      "canonical_name": "<name>",
      "field_path": "payload.statement",
      "outcome": "decompose_proposed",
      "before": "<compound claim>",
      "proposed_decomposition": [
        { "canonical_name": "<new_a>", "statement": "<atom A>" },
        { "canonical_name": "<new_b>", "statement": "<atom B>" }
      ]
    },
    {
      "canonical_name": "<name>",
      "field_path": "contract.monotonicity_rule",
      "outcome": "unfixable_contract_field_r6",
      "before": "<prose>",
      "reason": "contract byte-equivalence invariant per node_version_chain_axiom; cannot edit"
    }
  ]
}
```

## Success criteria

- Every R6 finding in the input is addressed (rewrite | decompose_proposed | unfixable_contract_field_r6).
- Every rewrite, mentally re-linted, passes R6.
- No values outside the flagged set are modified.
- Output files pass `jq empty`.
- No prose narration in the dispatch transcript — the staging files ARE the deliverable.

## What this stage does NOT do

- Validate the rewrite via `spec-lint`. The orchestrator re-runs `spec-lint` after this stage; the rewrite agent operates on a snapshot of findings, not the live linter.
- Resolve `decompose_proposed` outcomes. The orchestrator inspects them and either accepts (which means re-admitting the table with the new atomic concepts) or rejects (which means accepting the prose as an unfixable_contract_field_r6).
- Modify edge submissions.
- Touch the graph.
