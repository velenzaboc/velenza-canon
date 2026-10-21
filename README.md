# velenza-canon (`spec-graph`)

**Layer 2 of the Velenza Arbor Stack** (`velenza-inarch` → `velenza-cambium` → `velenza-canon` → `velenza-trellis`).

`velenza-canon` (compatible CLI/MCP alias: `spec-graph`, Unified CLI: `inr canon` / `inr spec`) is the Normative Root Canon, OOD Graph, & Node Identity Admission MCP server and CLI. The AI uses it to build and verify the normative corpus graph organically, node by
node, against an experimental Spanner database during the pre-genesis phase, and to audit cross-layer `//spec:` and `//volt:` traceability between `.ood.json` specifications and source code (`trace-code` / `spec_graph_trace_code`).
When the bootstrap converges, flip one config field and the same MCP serves
the production graph — no verb name changes.

## The Velenza Arbor Stack & Cross-Layer Integration

`velenza-canon` is **Layer 2** of the open-source **Velenza Arbor Stack**, a 4-layer neuro-symbolic software engineering stack for concurrent AI coding agents:

| Layer | Repository | Canonical Binary | Compatibility Alias | Umbrella CLI | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Layer 0** | [`velenzaboc/velenza-inarch`](https://github.com/velenzaboc/velenza-inarch) | `velenza-inarch` | `inr` | `inr` | **The Graft Union & Rootstock** — Checkout-free content-addressed VCS (`BonsaiChangeset`, 64-char BLAKE3 changeset IDs, client-side rebase, JIT leases) |
| **Layer 1** | [`velenzaboc/velenza-cambium`](https://github.com/velenzaboc/velenza-cambium) | `velenza-cambium` | `code-graph` | `inr cambium` / `inr code` | **The Living Vascular Code Tissue** — CPG/SSA/VTA semantic code graph and deterministic production hazard analyzer (`code_graph_hazards`) |
| **Layer 2** | [`velenzaboc/velenza-canon`](https://github.com/velenzaboc/velenza-canon) | `velenza-canon` | `spec-graph` | `inr canon` / `inr spec` | **The Normative Root Canon** — Versioned architectural specification graph and requirement-to-symbol governance (`trace-code`) |
| **Layer 3** | [`velenzaboc/velenza-trellis`](https://github.com/velenzaboc/velenza-trellis) | `velenza-trellis` | `task-graph` | `inr trellis` / `inr task` | **The Structural Growth Trellis** — Multi-agent execution DAG, TDD receipts, and cryptographic worklink provenance (`fg-validator-runner`) |

### How `velenza-canon` Integrates Across the Stack

1. **With Layer 0 ([`velenza-inarch`](https://github.com/velenzaboc/velenza-inarch)):**
   - **Umbrella CLI & Config Resolution:** `inr canon <subcommand>` (or `inr spec <subcommand>`) delegates directly to `velenza-canon` (`spec-graph`), propagating `ARBOR_GCP_PROJECT` and `ARBOR_SPANNER_INSTANCE` and resolving `$VELENZA_CANON_CONFIG` / `$SPEC_GRAPH_CONFIG`.
   - **Versioned Spec Snapshots:** Specification files (`.ood.json`) and code trees versioned in `velenza-inarch` changesets can be audited together at any revision.
2. **With Layer 1 ([`velenza-cambium`](https://github.com/velenzaboc/velenza-cambium)):**
   - **Bidirectional Requirement-to-Symbol Traceability (`trace-code` & `code_graph_annotations`):** `velenza-canon trace-code --spec-dir <specs> --code-dir <repo>` (`spec_graph_trace_code`) scans `.ood.json` requirement IDs and cross-checks them against `//spec:<ID>` and `//volt:<ID>` annotations extracted into `velenza-cambium`'s symbol graph, failing closed on dangling code annotations (`--fail-on-dangling`) or uncovered normative requirements (`--fail-on-uncovered`).
3. **With Layer 3 ([`velenza-trellis`](https://github.com/velenzaboc/velenza-trellis)):**
   - **Shared Admission Architecture & Requirement-Bound Tasks:** `velenza-canon` and `velenza-trellis` share the same 10-step node admission ceremony, closed-registry validation discipline (`binary_is_never_sot`), and `SpannerSubstrateAdapter`. Tasks and TDD audit receipts in `velenza-trellis` bind directly to requirement IDs governed by `velenza-canon`.

## Three-tier framing

This binary sits at the **top tier** — Node Identity & Admission. Owns the
`node_id` space, the version chain, the 10-step admission ceremony. Owns
**no** substrate storage; routes by `node_kind` to whichever bottom-tier
substrate owns that kind.

- **TOP — Node Identity & Admission** (this binary)
- **MIDDLE — projection contracts.** VOLT (execution), OOD Graph
  (documentation), ASG (content-store)
- **BOTTOM — data substrates.** Experimental: `corpus-graph-iter1`.
  Production: VOLT-owned tables, OOD-Graph-owned tables, ASG_Nodes,
  code-graph.

## Operating modes (REQUIREMENTS.md §3.1)

Selected by a single `mode` field in `spec-graph.config.json`.

| Bootstrap (`experimental_bootstrap`) | Production (`production`) |
|---|---|
| ONE substrate (`corpus-graph-iter1`) | Many substrates |
| `admitted_by` = `EXPERIMENTAL_BOOTSTRAP` (burned-in literal from config) | Resolved from real CallerContext |
| Placeholder signature (SHA-256 over §8.6 input vector) | Cloud KMS sign |
| Empty `compiler_pass_registry` tolerated | Full pass enforcement |
| Real `definition_hash` / `manifest_hash` (SHA-256, canonical JSON) | Same |
| All bodies in `Nodes.content` JSON | Per-node_kind typed tables |
| `spec_graph_query` allowed (gated by `experimental_query_enabled`) | Refused |
| Iterate destructively via `spec-graph reset --confirm` | Single production substrate; no reset |
| Mode unset = fail-closed | Same |

## Build

```bash
go mod tidy
go build -o bin/velenza-canon .
go build -o bin/spec-graph .
```

## Subcommands

| Subcommand | Purpose |
|---|---|
| `velenza-canon mcp` (`spec-graph mcp`) | Run as MCP Streamable HTTP server |
| `velenza-canon init` (`spec-graph init`) | Apply `bootstrap/schema_v1.sql` to the configured experimental DB via `gcloud spanner databases ddl update`. Idempotent. Refuses any database not matching `corpus-graph-*`. |
| `velenza-canon reset --confirm` (`spec-graph reset --confirm`) | Drop + recreate the experimental DB, then re-apply schema. Refuses without `--confirm`. Refuses non-`corpus-graph-*` targets. |
| `velenza-canon trace-code --spec-dir <dir> --code-dir <dir>` | Audit cross-layer `//spec:` and `//volt:` coverage between `.ood.json` specs and code (`--fail-on-dangling`, `--fail-on-uncovered`). |
| `velenza-canon arbor-info` (`spec-graph arbor-info`) | Emit the canonical Layer 2 Velenza Arbor Stack JSON descriptor (`velenza-canon`). |

## Verbs

**Historical reads:** pass `graph_snapshot_id` explicitly on each typed read.
`spec_graph_use` is a retired fail-closed compatibility verb; stateless HTTP
has no tenant-safe process-global pin.

**Lifecycle (write):** `spec_graph_create`, `spec_graph_update`,
`spec_graph_archive`

**Edges (write):** `spec_graph_link`, `spec_graph_unlink`

**Read:** `spec_graph_get`, `spec_graph_list`, `spec_graph_neighbors`,
`spec_graph_history`, `spec_graph_search`, `spec_graph_closure`,
`spec_graph_impact`, `spec_graph_diff`, `spec_graph_project`

**Bootstrap-phase additions:** `spec_graph_query` (ad-hoc read-only
GoogleSQL/GQL), `spec_graph_import` (bulk topologically-ordered admission),
`spec_graph_health` (readiness probe)

Staging and OODGraph materialization add typed run/snapshot/violation reads,
load/cluster/lint/promote, and fail-closed compatibility verbs. The MCP tool
inventory is generated by the running server; this README does not freeze a
count that can drift from the registered surface.

## Config

The binary reads `$VELENZA_CANON_CONFIG` or `$SPEC_GRAPH_CONFIG` (default `./spec-graph.config.json`).
Every closed registry the framework reasons over is a section of this file.

- `velenza-canon.config.example.json` / `spec-graph.config.bootstrap.example.json` — single-substrate experimental
  config, recommended starting point.
- `spec-graph.config.production.example.json` — four-substrate
  production-target config.

`spec-graph.config.json` is intentionally ignored: it is an environment
artifact and may contain credential paths. On an operator host, store the
durable local config outside the worktree (for example,
`.mcp-local/spec-graph.config.json`). The existing operational
file is the merge base: **do not replace it wholesale with either example**.
Preserve every existing substrate, node-kind, edge-label, projection,
credential, and host value; add only reviewed registry entries whose
permission and authenticity contracts have actually been admitted. The
tracked examples deliberately contain no QuickBooks documentation/static/
release-note descriptor: an Intuit legal-terms index is not express authority
for automated retrieval. They also contain no QuickBooks source-repository
descriptor: an organization-wide GitHub prefix is not product→repository
authority, and no exact QBO repository registry is settled. External object
classes may remain dormant without manufacturing a source binding. The
remaining external-source examples exercise registry shape only. Executable
ingress additionally requires an injected typed authorization resolver, a
trusted acquisition adapter, and the protected source-carrier archive adapter; a URL, descriptor,
or same-repository license file is never a grant. The five pre-existing bootstrap
classes that lacked the now-required `projection_role` (`origin`, `axiom`,
`node_kind_declaration`, `edge_label_declaration`, and
`principal_type_declaration`) must receive the corresponding roles shown in
the example without changing their other fields. Set the daemon's
`SPEC_GRAPH_CONFIG` to the absolute `.mcp-local` path and restart it.

The tracked examples are reviewable convergence references; the `.mcp-local`
file remains the runtime instance. A narrowing replacement is forbidden:
complete-snapshot carry-forward validates old rows against the current
registry, so changing an existing label's family, direction, reciprocity,
self-loop policy, or endpoint sets can reject lawful history. No external
reference is executable merely because its descriptor validates. The typed
resolver must bind the kernel-resolved organization, source authority,
source-owned representation declaration, exact locator, principal, grant,
policy version, authorization decision, method, content/trust classes,
ceilings, validity window, and custody disposition before network I/O. Never
force-add the ignored runtime file to git.

An existing OODGraph-v2 database also needs the additive DDL in
`bootstrap/migrations/002_staging_external_verification_receipt.sql` before
the successor binary starts. Fresh databases created from `schema_v2.sql`
already contain the column; do not apply the migration twice.

Per Vision Principle 7 (`binary_is_never_sot`), operational source selection
and the substrate, node-kind, edge-label, and projection registries live in
config rather than compiled defaults. The binary may reject a configured
entry that widens a protocol-owned closed grammar (for example, OOD Graph
v1's external trust classes or external-edge endpoint contract), but that
conformance guard neither selects a source nor registers a label by itself.
Adding an operator source or enabling a registered kind/label is a config
change and restart, not a compiled default. When KernelConfig Spanner rows
exist for each registry, per-section loaders swap to read from Spanner.

## Sentinels

`ErrSchemaPending`, `ErrSubstrateNotProvisioned`, `ErrRegistryNotLoaded`,
`ErrUnknownNodeKind`, `ErrUnknownEdgeLabel`, `ErrReciprocityViolation`,
`ErrClosureWouldDangle`, `ErrContractDrift`, `ErrCeremonyAtomicityBroken`,
`ErrSnapshotNotPinned`, `ErrModeMismatch`, `ErrForbiddenDatabaseTarget`,
`ErrSchemaNotApplied`, `ErrImportDependencyUnresolved`.

## Cutover discipline

When the experimental bootstrap converges:

1. Edit `spec-graph.config.json`:
   - `mode` → `"production"`
   - `experimental_admitter` → `""`
   - `experimental_query_enabled` → `false`
   - `substrates` → the multi-substrate production set
2. Supply the in-process verified-bearer adapter, admitted external-fetch
   circuit/driver adapter, typed authorization resolver, and protected
   SOURCE RECORD/AGFS source-carrier adapter required by the OOD Graph
   execution boundary.
3. Restart the MCP server. Until every production adapter is wired, the
   process refuses production boot with
   `ErrProductionRuntimeCompositionUnavailable`; the bootstrap HTTP fetcher
   is never used as a production fallback.

`EXPERIMENTAL_BOOTSTRAP` admissions remain in the graph as historical
lineage; the `is_non_genesis` generated column on `ArtifactAdmissionLog`
distinguishes them from real-principal admissions.

## Repo layout

| File | Responsibility |
|---|---|
| `main.go` | CLI entry: `mcp` / `init` / `reset` subcommand dispatch |
| `mcp.go` | MCP server + 18 verb registrations |
| `handlers.go` | One handler per verb |
| `ceremony.go` | The 10-step admission ceremony per VOLT §8.4 |
| `substrate.go` | `SubstrateRouter` + generic `SpannerSubstrateAdapter` |
| `kinds.go` / `edges.go` / `projection.go` | Closed-registry interfaces + file-loaded implementations |
| `config.go` | `SpecGraphConfig` envelope + `Validate()` |
| `cmd_init.go` / `cmd_reset.go` | DDL apply + DB reset subcommands |
| `types.go` | `Node`, `NodeVersion`, `Edge`, `AdmissionRecord`, result wrappers |
| `external_authorization.go` | Pre-I/O admitted grant/representation/custody decision seam |
| `external_archive.go` | Protected SOURCE RECORD/AGFS source-carrier custody and exact byte-range hydration seam |
| `cmd/provider-plan-verify` | Offline, provider-neutral exact-evidence and OOD-contract preflight for documentation graph plans |
| `internal/providerplan` | Body-free plan parser, exact range hydrator, closed-registry validator, and preflight receipt |
| `cmd/ood-schema-render` | Strict renderer for the canonical OOD Graph Spanner DDL; proves table, ordered-column, definition, primary-key, and index-target parity before emitting SQL |
| `internal/oodschema` | OOD schema parser, duplicate-key guard, DDL parity verifier, deterministic renderer, and body-free render receipt |
| `errors.go` | Typed sentinels |
| `bootstrap/schema_v1.sql` | Experimental DDL: Nodes / Edges / ArtifactAdmissionLog / CorpusGraph property graph |
| `TESTING.md` | Manual smoke test — the five-verb walk |
| `REQUIREMENTS.md` | What the MCP needs to do |

## External evidence invariant

The graph never stores provider-document bodies. A successful external
occurrence binds raw transfer evidence separately from the canonical
transport-decoded representation, archives the canonical bytes through the
protected SOURCE RECORD custody boundary before parsing, and stores only
authority-bound coordinates and digests. The resulting AGFS version carries
an `external_carrier_hold` and is invisible to ordinary filesystem reads. The
AGFS ciphertext content hash, Source Record body-reference hash, canonical
source digest, and OOD archive-record digest remain separate identities.
Exact values hydrate from the immutable AGFS file version only through the
kernel-internal protected carrier resolver, which rechecks current CallerContext,
PIA/Gate authority, hold integrity, and SOURCE RECORD currentness at issuance
and redemption for a zero-based half-open byte range; embeddings,
rendered DOM, navigation metadata, and caller-provided values cannot supply an
exact field.

## Provider-documentation plan preflight

The provider-documentation factory is a source-neutral, exact-byte pipeline. A
provider's selected machine export is the documentation evidence body; rendered
DOM, navigation metadata, search snippets, and generated summaries are not
evidence. The same contracts apply to QuickBooks and to every later provider.

`provider-documentation-stage-compile` validates four body-free stage contracts:

1. `evidence_intake` binds independently selected Grand Vision, OOD Graph,
   Source Record, and Extension Protocol authority bytes; the exact selection
   roster; evidence manifests; and every selected evidence component.
2. `semantic_extraction` binds the intake receipt, applicability profile,
   extractor/schema coordinates, closed output-role roster, and exact output
   bytes. It validates commitments and lineage; it does not execute an
   extractor.
3. `graph_compile` binds extraction receipts, the body-free graph plan, its
   compact subject/fact/gap roots, and a generic `dependency_artifacts` roster.
   Every dependency and the plan must have one exact target-schema binding.
4. `full_factory` binds the validated predecessor receipt set. It is a
   composition commitment, not an admission or execution receipt.

Every stage receipt commits to the exact request, predecessor receipts, selected
evidence identities, immutable bindings, and output root. Stage receipts always
state `derivation_executed=false`, `authority_selected=false`,
`admission_authorized=false`, and `factory_complete=false`.

`provider-plan-verify` consumes the exact `graph_compile` selection and reruns
the stage compiler before interpreting a plan. The graph request must select the
plan-bound semantic-validation profile plus all eleven closed semantic artifact
roles. Their role, artifact identity/version/digest, and target-schema
identity/version/digest must be set-equal to the separately loaded plan-bound
semantic closure. Missing, extra, aliased, reordered, substituted, or
schema-mismatched material fails closed. File paths only hydrate already-selected
exact bytes; they do not select authority.

The verifier reads the current OOD contract rather than freezing API element
roles, relationship labels, or property families in Go. It hydrates every
digest-bound zero-based half-open evidence range; recomputes content-derived
candidate identities, endpoint roles, locator roots, and operation
applicability; and requires every required fact to be materialized or represented
by an exact non-materializable fail-closed gap. Optional and inapplicable
absence is never persisted as a fact. All structured candidate artifacts are
validated by exact plan-bound JSON Schemas before their semantics are consumed.
JSON Schema syntax is recognized only at a schema coordinate proven by the
stage profile.

```bash
go run ./cmd/provider-documentation-stage-compile \
  --inputs <graph-compile-stage-input-manifest.json> \
  --out <body-free-graph-stage-receipt.json>

go run ./cmd/provider-plan-verify \
  --ood <path-to-OOD_GRAPH_PROTOCOL_v1.ood.json> \
  --expected-ood-sha256 <independently-selected-sha256> \
  --grand-vision <path-to-VELENZA_GRAND_VISION_v1.md> \
  --expected-grand-vision-sha256 <independently-selected-sha256> \
  --source-record <path-to-SOURCE_RECORD_AND_SEMANTIC_PROJECTION_v1.ood.json> \
  --expected-source-record-sha256 <independently-selected-sha256> \
  --graph-compile-inputs <graph-compile-stage-input-manifest.json> \
  --evidence-manifest <provider-exact-body-manifest.jsonl> \
  --dependency-artifact <each-plan-bound-artifact-profile-schema-or-transitive-input> \
  --out <body-free-preflight-receipt.json>
```

To compile and verify one already-prepared four-stage bundle in a single
bounded process, use the exact-commit release bootstrap. The bootstrap itself
is an operator trust entry point: use its reviewed bytes from the same selected
commit. Supply a repository that contains that commit, the full lowercase
40-character commit SHA, and independently selected absolute Go 1.27.1 and Git
executable paths. On Windows PowerShell:

The local ceremony detects ordinary path, byte, mode, identity, and pre/post
snapshot drift; it is not a sandbox against a hostile process already running
as the same OS account. The selected repository, Go/Git installations, and the
ceremony's private workspace are local trust roots for the duration of the run.
If that same-account boundary is not available, run the reviewed bootstrap in
an isolated account or build service with read-only selected inputs. Toolchain
tree fields attest the stable measured pre/post snapshots; they do not claim an
OS-enforced immutable filesystem against an already-compromised principal.

```powershell
& .\scripts\provider-documentation-factory-release.ps1 `
  '<absolute-spec-graph-repository-root>' `
  '<full-lowercase-commit-sha>' `
  '<absolute-go-1.27.1-executable>' `
  '<absolute-git-executable>' `
  -- `
  --evidence-intake-inputs <evidence-intake-stage-input-manifest.json> `
  --semantic-extraction-inputs <semantic-extraction-stage-input-manifest.json> `
  --graph-compile-inputs <graph-compile-stage-input-manifest.json> `
  --full-factory-inputs <full-factory-stage-input-manifest.json> `
  --ood <path-to-OOD_GRAPH_PROTOCOL_v1.ood.json> `
  --expected-ood-sha256 <independently-selected-sha256> `
  --grand-vision <path-to-VELENZA_GRAND_VISION_v1.md> `
  --expected-grand-vision-sha256 <independently-selected-sha256> `
  --source-record <path-to-SOURCE_RECORD_AND_SEMANTIC_PROJECTION_v1.ood.json> `
  --expected-source-record-sha256 <independently-selected-sha256> `
  --evidence-manifest <exact-manifest-already-declared-by-a-stage> `
  --dependency-artifact <exact-plan-bound-or-transitive-dependency> `
  --out <new-body-free-factory-run-receipt.json>
```

On macOS, use the committed POSIX bootstrap with the same runner arguments:

```bash
./scripts/provider-documentation-factory-release.sh \
  <absolute-spec-graph-repository-root> \
  <full-lowercase-commit-sha> \
  <absolute-go-1.27.1-executable> \
  <absolute-git-executable> \
  -- <the-same-runner-arguments-shown-above>
```

The bootstrap extracts the launcher source from the selected commit rather than
running ambient package source. The launcher projects only that commit into a
private repository, binds every path, Git mode, byte count, and content digest,
uses fresh private Go caches, downloads only the selected runner's dependency
closure under read-only module metadata, verifies that closure, and measures the selected
Git executable, Go executable, complete GOROOT tree, and complete Git helper
tree, then builds with pure Go, external linking disabled, `-buildvcs=true`,
`-trimpath`, `-pgo=off`, and the fixed `factory_release` tag. The target-specific
execution identity binds each toolchain tree's root, unique regular-payload
count, and byte count. GOROOT remains a regular-file-only tree. The Git helper
closure additionally permits only relative symbolic-link aliases that resolve
to regular executables; it binds every alias's logical path, raw target,
physical target path, target digest, and target size while counting shared
payloads once. On Linux the launcher executes the child through its retained
no-follow descriptor path. macOS has no supported pure-Go descriptor-execution
path, so the launcher retains and measures the no-follow file handle, rechecks
that the canonical path still names the same bytes and identity before command
construction, executes that path, and rechecks it afterward. On Windows it
executes the canonical path while no-delete/no-write-sharing handles retain the
executable and every path ancestor, and it revalidates those identities before
and after execution. The
launcher reads the private receipt through a retained no-follow handle,
validates the complete top-level schema, release-critical nested identities,
portable/validation/final roots, and only then publishes the validated bytes by
exclusive no-follow creation.

A child receipt is evidence about the built candidate, not cryptographic proof
that the outer bootstrap and launcher ran. A raw `go run` without the mandatory
link values fails closed, but a caller can mechanically supply link values to a
raw build. Such a child invocation is not the release ceremony. Treat success
as release-path output only when the reviewed bootstrap launched the parent,
the parent independently derived and compared all pinned identities, and the
parent performed the final exclusive publication. The receipt remains
non-authoritative and must not be used as a signature or independent-validator
PASS.

This command is a prepared-bundle compiler/verifier, not the terminal
direct-source push-button factory: it does not generate the four stage manifests,
evidence/classification artifacts, target rows, residual circuits, or ARC
blueprint from a sealed provider corpus. The runner accepts exactly one
preauthored manifest for each stage, in the order shown. The intake manifest
declares the exact evidence bodies; later manifests leave their evidence and
predecessor lists empty because the runner reuses the intake bytes and injects
the receipts it just compiled. Each stage material coordinate and physical path
is declared once, by the first stage that introduces it; later stages reuse that
admitted material by coordinate. Authority and evidence-manifest paths passed to
the executable preflight must name their exact intake-stage materials. The
complete transitive dependency closure is independently verifier-admitted and
may include inputs that are not direct graph-stage materials. The final receipt
binds one union input-admission proof across all four manifests, their files,
and the verifier inputs. `portable_receipt_sha256` binds that platform-neutral
run plus the exact source revision, module graph, portable build recipe, and
runner contract. `receipt_sha256` additionally binds the native build settings,
a stable digest and byte count of the launch-resolved executable artifact
measured by the process, and a distinct internally recomputed runtime-validation
profile/report identity. The embedded Go build metadata is the identity of the
code actually executing. The serialized execution identity seals
`build_metadata_source=go_runtime_debug_build_info` and
`executable_measurement_scope=launch_path_open_regular_file`; the path-artifact
digest does not claim that every host exposes its loader-mapped image bytes as a
file. Compare
`portable_receipt_sha256` across
supported Windows and macOS builds only when their logical inputs and portable
tool/build identity are equal. Compare `receipt_sha256` across repeated runs of
the same native build/artifact and inputs; a different artifact or target is
expected to produce a different execution identity and full receipt root.
Neither execution nor validation attestation is accepted from a command-line
caller. The runtime-validation report proves only the built-in candidate checks
named by its fixed profile and contract and carries the closed result token
`candidate_runtime_validation_pass`; it is not a test-suite receipt or an
independent validator PASS. The fixed `factory_release` tag must agree in both
tool and execution identities. The executable digest does not make the binary a
configuration or artifact authority. The receipt is
deterministic, body-free, and candidate-only:
four-stage compilation, verification, and offline derivation execution are true;
graph/circuit admissibility or admission, authority selection, configuration,
credentials, deployment, live testing, source substitution, two-tenant proof,
and factory completion remain false. When `--out` is supplied, it must name a
new file; existing files, aliases, links, and reparse redirections are refused.

Repeat `--evidence-manifest` when a provider corpus is split across exports,
and repeat `--dependency-artifact` until the complete plan-declared dependency
closure is supplied, including target schemas, validation profiles, and
transitive mapping inputs. Extra inputs are refused. Candidate plans and
receipts contain no source bodies, credential values, or tenant identifier.
Connector credentials remain Connector Vault references; live
`organization_id` is injected later by the kernel and caller-supplied scope is
rejected. Binary-float authority, raw source-value embedding, arbitrary payload
passthrough, and credential material are refused across the complete closure.
Financial values remain exact lexical or typed facts for the admitted owning
finance capability and exact-computation path; neither documentation-graph
material nor provider-specific kernel code is a value-of-record arithmetic
engine.

Receipt version 9 is the final offline executable preflight receipt. It is
distinct from the four structural stage receipts: the verifier reexecutes every
content-addressed, provider-neutral derivation program over the sealed exact
evidence selection; validates every canonical output against its exact
claim-schema generation; records a deterministic outcome for every
rule-by-classified-occurrence pair, including permitted zero matches; seals the
complete bounded page chain; and proves exact-once placement into a
schema-authorized whole row or uniquely selected nested member. Documentation
occurrences remain evidence identities, while operation/resource/member
identity remains source-neutral. The receipt is body-free and non-authorizing:
it performs no network call or graph write and cannot authorize source
selection, admission, tenant access, capability execution, or publication.

## Canonical OOD Graph Spanner schema

`ood-schema-render` reads the authoritative `OOD_GRAPH_PROTOCOL_v1` bytes and
emits the exact s6 DDL statement roster plus the s7 `OODGraph` property-graph
projection. Before rendering, it rejects duplicate
JSON keys, missing or extra table declarations, reordered or mismatched column
definitions, primary-key drift, duplicate indexes, and indexes targeting an
undeclared table, or a property-graph node/edge endpoint absent from the same
physical roster. The generated artifact is pinned to the input spec digest;
its receipt is body-free and explicitly non-authorizing.

```bash
go run ./cmd/ood-schema-render \
  -ood <path-to-OOD_GRAPH_PROTOCOL_v1.ood.json> \
  -out bootstrap/schema_ood_graph_protocol_v1.generated.sql \
  -receipt bootstrap/schema_ood_graph_protocol_v1.render-receipt.json
```

The generated schema is the canonical physical-contract input for the
successor runtime. `spec-graph init` is not silently redirected to it: schema
application remains a separate sanctioned DDL operation, and the existing
seven-table runtime cannot claim compatibility until its row model,
transactions, publication heads, closure certificates, and read paths have
all migrated to the same contract. The current `init --schema` path also
rejects this artifact's non-authorizing marker, preventing a 35-table schema
from being applied underneath a seven-table binary.
