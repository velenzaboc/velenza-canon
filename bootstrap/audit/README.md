# Live-graph R-rule audits — Spanner-side compute via ML.PREDICT

R-rule audits against the **admitted graph state** run entirely inside
Spanner via `ML.PREDICT` against the `r6_flash` remote model registered
by `00_create_flash_model.sql`. There is no companion CLI; the recipe IS
the audit.

This replaces the prior local-CLI export-then-loop pattern (the retired
`spec-graph export-concepts` subcommand of [#30](https://github.com/velenzaboc/velenza-canon/pull/30)),
which pulled graph state out to local files and ran a per-file Go binary.
That shape violated VOLT §s1_2 `generic_cpu` + `binary_is_never_sot` +
`discovery_before_creation` (Spanner already does `ML.PREDICT`; pulling
data out to compute on it was building what Spanner already shipped).

## Architectural rule

**Audits run where the data lives.** A new R-rule that needs semantic
reasoning over admitted values lives here as a SQL recipe against the
registered remote model, not as a Go CLI that extracts rows.

The in-process Flash detector in `bootstrap/cmd/spec-lint/r6_no_prose.go`
is a **separate** mechanism: that detector runs at **pre-admission**
time (Stage 4 ConceptTable lint, before any row is written), where the
input is a working-file JSON not yet in the graph. The two mechanisms
share the same prompt template content but operate at different
lifecycle stages over different data.

## Files

| File | Purpose |
|---|---|
| `00_create_flash_model.sql` | One-time DDL registering `gemini-2.5-flash` as a Spanner remote model named `r6_flash`. |
| `r6.sql` | Audit recipe: runs Flash over every active `OODGraphSymbols.search_text` whose value is multi-token, returns one row per Symbol Flash classifies as prose. |

## One-time setup — apply the model DDL

```bash
gcloud spanner databases ddl update doc-graph \
  --instance=your-spanner-instance \
  --project=your-gcp-project-id \
  --ddl-file=bootstrap/audit/00_create_flash_model.sql
```

Same-project (`your-gcp-project-id` → Vertex AI in `your-gcp-project-id`) needs no
extra IAM grants. `default_batch_size = 1` matches Gemini's no-batch
contract.

## Running an audit

The recipe SQL carries a single substitution marker (the literal
token `<<<R6_PROSE_PROMPT_SUBSTITUTE_HERE>>>`) inside a Spanner
triple-quoted raw string literal `R''' ... '''` at the prompt position.
The invocation wrapper substitutes the contents of
[`bootstrap/prompts/r6_prose_check.txt`](../prompts/r6_prose_check.txt)
into that one marker via pure bash parameter expansion (no `sed`, no
external transformer), so the canonical prompt lives in exactly one file
and both this audit recipe AND the in-process spec-lint detector cite it
— VOLT §s1_2 `reuse_by_reference`. A prompt edit propagates to both
surfaces with no recipe edit.

The marker token deliberately does NOT appear anywhere else in `r6.sql`
— not in comments, not in identifiers. Bash `${VAR//pattern/replacement}`
replaces ALL occurrences; if the marker appeared twice, the substituted
multi-line prompt would break out of `--` line-comments at the first
newline and produce a SQL parse error. The wrapper's correctness depends
on single-occurrence; `grep -c '<<<R6_PROSE_PROMPT_SUBSTITUTE_HERE>>>'
bootstrap/audit/r6.sql` MUST return `1`.

```bash
PROMPT="$(cat bootstrap/prompts/r6_prose_check.txt)"
SQL_TEMPLATE="$(cat bootstrap/audit/r6.sql)"
SQL="${SQL_TEMPLATE//<<<R6_PROSE_PROMPT_SUBSTITUTE_HERE>>>/${PROMPT}}"

gcloud spanner databases execute-sql doc-graph \
  --instance=your-spanner-instance \
  --project=your-gcp-project-id \
  --sql="${SQL}" \
  --format=json > r6_findings.json
```

Output: one row per `OODGraphSymbols` row whose value Flash classified as
`prose` OR `unparseable` (VOLT §s1_2 `fail_closed` — an unparseable Flash
response is NOT silently dropped; it is surfaced as a violation, because
Flash did not affirmatively prove the value is clean). Columns:
`(graph_object_id, canonical_name, node_kind, field_path, value,
flash_response, verdict)` where `verdict` ∈ {`prose`, `unparseable`} on
returned rows.

**Concurrency:** the recipe relies on Spanner's automatic parallelism
for `ML.PREDICT`. A prior version of this README claimed an explicit
`@{remote_udf_max_outstanding_rpcs=64}` hint cut wall clock from ~40
min to ~2 min — that claim was wrong on two counts: (a) the hint name
came from a third-party Medium article and is NOT documented in any
official Google Cloud Spanner reference page (ml-functions,
query-syntax, cloud-run-remote-function — all checked 2026-05-28),
(b) when applied with value 64 the Spanner runtime rejected it with
"Invalid hint value for: remote_udf_max_outstanding_rpcs hint: 64."
The recipe carries no concurrency hint as a result. The only
documented remote-function concurrency knob is `max_batching_rows`
set at `CREATE MODEL` time, which for Gemini's no-batch contract is
already `default_batch_size = 1` (see
`00_create_flash_model.sql`). If a future audit hits throughput
problems on a large run, the next move is to locate the correct hint
syntax in official channels rather than guess values for an
undocumented one.

## Prompt source-of-truth (one file, two surfaces)

The canonical R6 prompt body is
[`bootstrap/prompts/r6_prose_check.txt`](../prompts/r6_prose_check.txt).
The file carries ONLY the rule body and the response-format spec — no
value markers, no Go-template syntax. Each surface appends its own
per-call `VALUE UNDER AUDIT` + `CONTEXT` section after the file body:

- the in-process spec-lint detector (`bootstrap/cmd/spec-lint/r6_no_prose.go`)
  appends the section in Go after reading the file on each evaluation;
- this audit recipe substitutes the file into `__R6_PROSE_PROMPT__` and
  appends the section via SQL `CONCAT` (see `r6.sql`'s `prompt` column
  construction).

A change to the rule body is a change to the .txt file alone. Both
surfaces pick it up without any further edit. This is the structural
fulfillment of VOLT §s1_2 `reuse_by_reference` — one definition, every
caller cites it; never a copy-paste fork.

## Adding a new audit

1. Author a new `<rule_id>.sql` next to `r6.sql` following the same
   shape: `ML.PREDICT` over `OODGraphSymbols` filtered by the rule's
   pre-filter, with a prompt that elicits the verdict the rule decides.
2. If the rule needs a different model (longer context, different
   temperature contract), add a sibling `0N_create_<model>_model.sql`
   alongside `00_create_flash_model.sql`.
3. Document the run command in this README.
