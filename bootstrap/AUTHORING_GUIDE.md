# Authoring Guide — corpus admission via per-node seed files

The corpus admits content one node per JSON file. Each file in
`/opt/velenza/velenza-canon/bootstrap/seed_nodes/` declares
exactly ONE node with `node_kind` + `contract` + `payload` at the top
level. The `spec_graph_import` verb walks that directory and writes one
OODGraphObjects row per file plus OODGraphSymbols rows for top-level
scalar contract/payload fields.

**There is no whole-spec materialization.** The corpus does not walk
canonical OOD JSON specs (`specs-local/*.ood.json`) into decomposed graph
rows. The seed_nodes are the only ingestion documents.

---

## §1 — Authoring contract

A seed_node JSON file MUST:

1. Be a single JSON object (not an array) at the file root
2. Carry `node_kind` as a top-level string field naming the kind from `spec-graph.config.json` node_kinds
3. Carry `contract` as a top-level object holding the node's immutable rules (single-clause structured claims, no prose)
4. Carry `payload` as a top-level object holding the node's content (structured fields, snake_case keys, full 36-character UUIDs, no truncation)
5. NOT carry shadow-manifest field names (`linked_ood`, `see_also`, `related`, `manifest`, `table_of_contents`, `bibliography`, `footer_registry`, `side_index`) per OOD_GRAPH_PROTOCOL_v1 §4.r3_no_shadow_manifest

The file's canonical name comes from the filename: `001_origin.json` →
`origin`; `002_node_identity_axiom.json` → `node_identity_axiom`. The
leading `NNN_` admission-order prefix and the `.json` suffix are stripped.

---

## §2 — How admission maps to OODGraph rows

`spec_graph_import` against a seed_nodes directory writes, per file:

- **One OODGraphObjects row** with:
  - `object_class` = the file's `node_kind`
  - `source_authority_id` = the ood_graph_protocol UUID (the corpus is its own authority for seed admissions)
  - `source_ref_kind` = `name`
  - `source_stable_reference` = the canonical name (filename-derived)
  - `version_coordinate` = `unversioned`
  - `section_path` = `$`
  - `graph_address` = canonical `oodg://...` form per §3 grammar
  - `search_text` = `<kind>:<canonical_name>` for retrieval
  - `search_payload` = the file's contract + payload as graph-owned JSON
  - `graph_object_id` = UUIDv5 deterministically derived from the identity tuple

- **One OODGraphSymbols row per top-level scalar field** in `contract` and `payload`:
  - `symbol_kind` = `contract_field` or `payload_field`
  - `symbol_name` = the field key
  - `section_path` = `$.contract.<key>` or `$.payload.<key>`
  - `search_text` = the scalar string value (the actual content)
  - `graph_object_id` = the parent Object's id

Nested objects, arrays, numbers, and bools in `contract`/`payload` stay
in the parent Object's `search_payload` JSON column; they remain fully
queryable via `search_payload_tokens` (TOKENIZE_JSON full-text search)
but are not separately addressable as symbol rows.

---

## §3 — Adding a new seed_node

1. Create a new file at `bootstrap/seed_nodes/<NNN>_<canonical_name>.json`. `NNN` is the next zero-padded admission order number.
2. The file body is one JSON object with `node_kind` + `contract` + `payload`.
3. Run `spec_graph_import file_path=bootstrap/seed_nodes/` (or path to the single file). The §6 OODGraph schema must be applied; otherwise the verb refuses.
4. The whole batch admits atomically via `CommitMaterializationRun` — one Spanner ReadWriteTransaction, all-or-nothing.
5. Verify via `spec_graph_query "SELECT object_class, COUNT(*) FROM OODGraphObjects GROUP BY object_class"` and `spec_graph_list_runs`.

---

## §4 — Updating an existing seed_node

1. Edit the file in place.
2. Re-run `spec_graph_import file_path=bootstrap/seed_nodes/<file>`.
3. Stable id derivation is deterministic (UUIDv5 from the identity tuple). The same canonical name produces the same `graph_object_id` across replay, so the new admission supersedes the old per the materialization run pattern.

---

## §5 — Forbidden patterns

- **Multi-object files**. One file = one node.
- **Markdown prose** in `payload` or `contract`. Single-clause structured fields only.
- **Truncated UUIDs / uppercase UUIDs**. All UUID-bearing fields are full 36-character lowercase per §3 identity grammar.
- **Shadow-manifest field names** as edge sources per §4.r3.
- **Cached target metadata** beside stable references per §4.r4_no_cached_target_metadata.

---

## §6 — MCP verbs

**Write:**
- `spec_graph_import` — admit per-node files (the bootstrap admission verb). Each file becomes one OODGraphObjects row + path/classification Symbols for contract+payload structure. OOD retrieval columns and embeddings contain graph-owned identity/classification metadata only; source values remain with their source authority. Every changed row is re-embedded before a complete successor can seal.
- `spec_graph_link` — admit one typed edge between two graph_object_ids. Reciprocity (e.g. depends_on ↔ load_bearing_for) auto-creates the mirror in the same Spanner ReadWriteTransaction with cross-linked inverse_edge_ids. Validates endpoint classes against the label's source_kinds/target_kinds.

**Read (typed):**
- `spec_graph_get` — fetch one OODGraphObjects row by graph_object_id
- `spec_graph_list` — list OODGraphObjects filterable by object_class / status / graph_snapshot_id
- `spec_graph_neighbors` — list OODGraphEdges in/out of a graph_object_id (direction: out|in|both; optional edge_labels filter)
- `spec_graph_search` — vector + retrieval search over OODGraphObjects.embedding via APPROX_COSINE_DISTANCE (query is embedded via gemini-embedding-001)
- `spec_graph_closure` — forward dependency closure using the closed `dependency_closure_profile`; walks only active, valid, non-diagnostic `depends_on` edges whose reciprocal `load_bearing_for` edge is complete in the same eligible snapshot. `max_depth` and `result_cap` are required; capped results are typed non-authoritative partials.
- `spec_graph_impact` — downstream impact using the closed `load_bearing_impact_profile`; walks only active, valid, non-diagnostic `load_bearing_for` edges whose reciprocal `depends_on` edge is complete in the same eligible snapshot. The same typed cap contract applies.

**Substrate operations:**
- `spec_graph_query` — ad-hoc read-only SQL against any OODGraph table
- `spec_graph_list_runs` — list OODGraphMaterializationRuns rows
- `spec_graph_list_violations` — list OODGraphViolations rows
- `spec_graph_list_snapshots` — list OODGraphSnapshots rows
- `spec_graph_health` — substrate readiness probe + registry sizes
- `spec_graph_use` — retired fail-closed compatibility verb; pass `graph_snapshot_id` explicitly on each typed historical read

---

## §7 — End-to-end example: link two admitted seed_nodes

```
# Find two axiom graph_object_ids
spec_graph_list object_class=axiom

# Admit a dependency edge (auto-creates reciprocal load_bearing_for mirror)
spec_graph_link \
  source_id=6cbbb2ce-a7ec-5108-87d8-62bb5bf8a49a \
  target_id=784460eb-f92f-5946-8ae6-8f37ff611d4d \
  edge_label=depends_on

# Inspect the closure
spec_graph_closure \
  graph_object_id=6cbbb2ce-a7ec-5108-87d8-62bb5bf8a49a \
  closure_profile=dependency_closure_profile \
  max_depth=5 \
  result_cap=50
```

---

End of guide. The OOD Graph Protocol v1 (`/opt/velenza/specs-local/OOD_GRAPH_PROTOCOL_v1.ood.json`) is the authority for storage shape (§6), identity grammar (§3), and edge model (§4). This guide is the operational summary for seed_node admission.
