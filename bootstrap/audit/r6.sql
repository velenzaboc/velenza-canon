-- bootstrap/audit/r6.sql
--
-- R6_no_prose audit against admitted graph state, executed entirely in
-- Spanner via ML.PREDICT against the r6_flash remote model (registered by
-- bootstrap/audit/00_create_flash_model.sql).
--
-- Architectural shape per VOLT §s1_2 generic_cpu + binary_is_never_sot:
-- push compute to the data. The prior local-CLI export-then-loop pattern
-- pulled rows out of doc-graph into JSON files and ran a per-file Go
-- binary, each spawning its own Vertex AI auth and per-string Flash calls.
-- This recipe replaces all of that: Spanner runs Flash on every prose-
-- candidate Symbol in parallel across its distributed query workers and
-- returns one row per Symbol whose verdict is non-clean.
--
-- VOLT §s1_2 reuse_by_reference compliance: the prompt is NOT inlined.
-- This recipe carries a single substitution marker inside a Spanner
-- triple-quoted raw string literal at the prompt position below. At
-- invocation time the caller substitutes the contents of
-- bootstrap/prompts/r6_prose_check.txt into that one marker via the
-- shell wrapper documented in bootstrap/audit/README.md. The canonical
-- prompt lives in exactly one place (the .txt file); both the
-- in-process spec-lint detector and this audit recipe cite it. A prompt
-- edit propagates to both surfaces with no recipe edit.
--
-- The marker token deliberately does NOT appear anywhere else in this
-- file — not in comments, not in identifiers. A bash parameter-expansion
-- substitution replaces ALL occurrences of its pattern; any second
-- occurrence (e.g. quoted in a comment) would be substituted with the
-- multi-line prompt body and the substituted newlines would escape the
-- `--` line-comment, producing a SQL parse error. Search for the marker
-- to confirm it appears exactly once before editing this file.
--
-- VOLT §s1_2 fail_closed compliance: the output classifies every Flash
-- response into prose / clean / unparseable. The WHERE clause surfaces
-- prose AND unparseable (an unparseable response IS a failure — Flash
-- did not affirmatively prove the value is clean, so the audit treats
-- it as a violation, not a silent pass). Only verdict='clean' is
-- excluded.
--
-- Why OODGraphSymbols, not OODGraphObjects:
-- OODGraphSymbols is the per-field decomposition every admission emits
-- via handleImport's extractSymbolsRecursive. Each Symbol row carries the
-- value at one field path in `search_text`, plus the parent's
-- `source_stable_reference` (canonical_name) and `object_class` (node_kind)
-- stamped in. No JOIN with OODGraphObjects needed.
--
-- Identifier-shape pre-filter: STRPOS(search_text, ' ') > 0 skips single-
-- token values (snake_case, dotted.path, UUID, file path, etc.) — the
-- same free identifier pre-filter the in-Go r6_no_prose.go check uses.
--
-- Run via the wrapper in bootstrap/audit/README.md (which performs the
-- prompt substitution). Direct gcloud execute-sql against THIS file
-- without substitution will fail — the un-substituted marker text is
-- not a valid Spanner identifier.

SELECT
  graph_object_id,
  source_stable_reference AS canonical_name,
  object_class AS node_kind,
  section_path AS field_path,
  value,
  content AS flash_response,
  CASE
    WHEN STRPOS(LOWER(content), 'verdict: prose') > 0 THEN 'prose'
    WHEN STRPOS(LOWER(content), 'verdict: clean') > 0 THEN 'clean'
    ELSE 'unparseable'
  END AS verdict
FROM ML.PREDICT(
  MODEL r6_flash,
  (
    SELECT
      graph_object_id,
      source_stable_reference,
      object_class,
      section_path,
      search_text AS value,
      CONCAT(
        -- The substitution target is a Spanner triple-quoted raw string
        -- literal R''' ... ''' wrapping the marker. The invocation
        -- wrapper substitutes the canonical prompt body (multi-line,
        -- UTF-8) into the marker text below. Triple-quotes admit real
        -- newlines; the raw R prefix means Spanner does not process
        -- backslash escapes inside the substituted prompt body. Single-
        -- quoted single-line literals would reject the multi-line
        -- prompt with a parse error at the first newline. The marker
        -- text uses a deliberately distinctive token form that does not
        -- appear elsewhere in this file.
        R'''<<<R6_PROSE_PROMPT_SUBSTITUTE_HERE>>>''',
        '\n\nVALUE UNDER AUDIT (delimited by <<<>>>):\n<<<', search_text, '>>>\n\n',
        'CONTEXT (informational only):\n',
        '  field_path:     ', section_path, '\n',
        '  canonical_name: ', source_stable_reference, '\n',
        '  node_kind:      ', object_class
      ) AS prompt
    FROM OODGraphSymbols
    WHERE status = 'active'
      AND search_text IS NOT NULL
      AND search_text != ''
      AND STRPOS(search_text, ' ') > 0
  ),
  STRUCT(
    256   AS maxOutputTokens,
    0.0   AS temperature,
    40    AS topK,
    0.95  AS topP
  )
)
WHERE
  STRPOS(LOWER(content), 'verdict: clean') = 0;

-- NOTE on concurrency: a prior version of this recipe carried the hint
-- @{remote_udf_max_outstanding_rpcs=64} sourced from a third-party
-- Medium article. Spanner's runtime recognizes the hint name but
-- rejected the value 64 at execute time with "Invalid hint value for:
-- remote_udf_max_outstanding_rpcs hint: 64." The hint is NOT documented
-- in any official Google Cloud Spanner reference page (ml-functions,
-- query-syntax, cloud-run-remote-function — all checked 2026-05-28); the
-- only documented remote-function concurrency knob is `max_batching_rows`
-- on the CREATE MODEL DDL, which is single-row for Gemini's no-batch
-- contract. We rely on Spanner's automatic parallelism here. If
-- throughput becomes a problem on large audits, the next move is to
-- find the correct hint syntax in official channels — not guess values
-- for a hint with no official spec.
