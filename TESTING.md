# spec-graph testing

## Test discipline (REQUIREMENTS.md §9)

Each capability requires before merge:

- **Unit test** of orchestration shape with the substrate mocked. Lives in `*_test.go` alongside the file under test. Run via `make test-unit` (also the default `make test`).
- **Integration test** against a Spanner emulator. Lives in `integration_test.go` behind the `integration` build tag. Run via `make test-integration` — starts the emulator in Docker, creates the test instance, runs the suite (build-tagged), tears the emulator down.
- **Manual smoke test** documented below. Run end-to-end once after every meaningful change against `corpus-graph-iter1`.

`t.Skip` is forbidden per CLAUDE.md `feedback_no_t_skip_in_tests`. Build-tag exclusion (`//go:build integration`) is not a runtime skip — it's a compile-time variant; tests under the tag still run explicitly via `go test -tags=integration` and the Makefile.

## Integration test scope (emulator gaps)

The Spanner emulator supports DDL apply, mutations, standard SQL queries, and the typed-row write path. It does NOT (as of 2026) support:

- `CREATE PROPERTY GRAPH` + DYNAMIC LABEL
- `APPROX_COSINE_DISTANCE` / vector indexes
- `GRAPH CorpusGraph MATCH ...` traversal queries

The integration suite covers the admission ceremony + substrate write/read path + reciprocal-edge atomicity + RFC 6902 diff, plus the seven-table OODGraph-v2 materialization lifecycle: typed SQL NULLs, running→sealed and running→failed terminal transitions, refusal to seal a failed run, deterministic 64-character source-set hashes, consecutive organization-scoped graph versions under concurrent commits, in-batch endpoint resolution, reciprocal OODGraph edges, and structured source-coordinate staging→promotion. External-evidence acceptance is exercised at the generic adapter boundary: typed authorization precedes every source call; cross-tenant and missing authorization make zero source calls; `identity|gzip` raw transfer hashes remain separate from the canonical transport-decoded source digest; authorized canonical bytes archive before locator parsing; archive failure yields no durable graph receipt; malformed archive controls fail before adapter I/O; one request archives a byte-equal tenant/source/resource/custody tuple once; `no_local_body_custody` stages receipt-only and cannot promote; source-declared machine-export bytes are the resource-root evidence body; and exact zero-based half-open ranges hydrate only through a durable protected carrier binding. The archive request surface is structurally checked to expose no credential/principal or ordinary AGFS namespace/ref field. Unit tests also cover per-resource singleflight, bounded cache failure, duplicate JSON-key rejection, unambiguous HTML anchors, full-pointer/path-sensitive names, transport metadata and media-type binding, full range/provenance digest validation, bounded Vertex response/time behavior, conservative complete-publication scale refusal, lint-status compare-and-set, and OOD typed closure/impact traversal evidence. Property-graph execution and vector-index smoke tests remain manual because the local Spanner emulator does not implement those surfaces.

The committed examples define descriptor syntax and closed registries, not executable retrieval authority. They keep external node-kind policies and the eight OOD external-ingestion labels, validate canonical prefixes/version modes/query-fragment rules, and reject arbitrary evidence coordinates. QuickBooks documentation/static/release-note descriptors remain absent until the exact Intuit source-authority, source-owned Copy-all representation declaration, and admitted grant/policy bindings are installed; the available terms index is not express automated-retrieval permission. The QuickBooks source-repository descriptor is likewise absent because an organization-wide GitHub prefix is not product→repository authority. Tests keep descriptor selection, typed authorization, exact-byte custody, and graph retention as separate claims.

## Provider-documentation plan preflight

Run the provider-neutral verifier tests with:

```bash
go test ./internal/providerplan ./cmd/provider-plan-verify ./cmd/provider-documentation-stage-compile ./cmd/provider-documentation-factory-run
```

The synthetic fixture derives its vocabulary from its exact OOD input and
covers all 16 API element roles, all 16 source-neutral API relationship labels,
and all eight property families exposed by that input, plus two operations with
different applicability traits, exact source-resource bindings, and explicit
required-gap behavior. This does not establish the separately governed
factory-required 16-role API-property closure; provider output remains
non-authoritative until that generic 8-to-16 closure is immutably handed off and
independently passes. The fixture executes the same evidence-intake,
semantic-extraction, graph-compile, and final verifier paths used by file-backed
callers.

Negative controls cover exact evidence mutation and hydration failure;
source-coordinate substitution; invalid UTF-8 and duplicate keys; credential,
tenant, raw-body, binary-float, raw-value-embedding, and passthrough carriers;
forged summaries and admissible-status smuggling; missing, extra, aliased,
reordered, or digest-substituted stage materials; target-schema/profile
omission and schema-coordinate substitution; dependency-path bytes that differ
from the graph-stage selection; stale applicability traits, incident rosters,
resource targets, optional absence rows, inapplicable facts, required facts
without an exact gap, and orphan gaps. A JSON object that merely resembles a
schema receives no schema exemption: the exact stage profile must bind its
coordinate as a schema. Even a proven schema coordinate continues to reject
unsafe `const`, `default`, `enum`, and `examples` carriers.

For a real provider corpus, compile each strict stage input manifest with
`cmd/provider-documentation-stage-compile`, then run
`cmd/provider-plan-verify` with independently pinned Grand Vision, OOD Graph,
and Source Record bytes; the exact graph-compile input manifest; every exact
evidence manifest; and the complete plan-bound artifact/profile/schema closure.
Retain the body-free version-9 final executable preflight receipt together with
the exact immutable inputs it names. The suite proves claim-schema execution,
complete bounded paging and resume identity, explicit zero-match outcomes,
unique parent-row selection, source-independent nested-member identity, and
exact-once target materialization. A pass is only an offline preflight; no test
or CLI path writes to OOD Graph, selects current authority, supplies tenant
scope, or represents canonical admission.

The sealed source-package command has a separate production-shaped verifier
mode selected by `--source-verification-receipt` plus
`--expected-provider`. The command never derives trust from those flags or
from fields inside the receipt. Production boot must supply the separately
owned source-evidence verifier; the stock command fails closed while that
upstream implementation is unavailable. Before the identical four-stage
factory may run, the consumer binds the raw source-package hash and size, the
complete manifest/ordinal/body/carrier identity-set root, the opaque receipt's
raw hash and size, the expected provider, and the current observation instant.
It refuses a missing verifier, test-owned or unauthenticated evidence, a stale
generation, an incomplete roster, a substituted receipt or package, and a
provider mismatch. Both the source package and verification receipt are
physically rechecked after the factory and before exclusive publication. The
result remains a body-free candidate-only source receipt; this gate supplies
no artifact validity, admission, configuration, credentials, tenant,
deployment, source materialization, source substitution, or live-provider
claim.

Production source mode publishes a distinct body-free run envelope instead of
dropping back to the nested factory receipt. The envelope binds the complete
production source receipt to the exact factory receipt, its portable identity,
its canonical file bytes, the compiled provider, and the identical
candidate-only completion classification. The exact-commit release wrapper
selects that schema only when both production source flags are present and
rejects a plain factory receipt, test-owned/unauthenticated/stale/incomplete
verification, provider or factory substitution, malformed identity rosters,
and broken nested or envelope hashes. Prepared and candidate source modes keep
their existing factory-receipt wire shape. This relay does not supply the
missing SOURCE-owned verifier: the stock production command and exact release
therefore still refuse before publication until production boot selects that
owner implementation.

The single-command prepared-bundle composition path is covered independently
with:

```bash
go test -count=1 ./cmd/provider-documentation-factory-release ./cmd/provider-documentation-factory-run ./internal/providerplan \
  -run '^(TestDocumentationFactoryRunner|TestDocumentationFactoryPublicCLI|TestFactoryToolIdentity|TestFactoryRunReceipt|TestFactoryPortableReceipt)'
```

Those tests prove the exact four-stage order, runner-owned predecessor and
evidence reuse, one whole-run input roster, path/argument-order/mtime
independence, platform-neutral portable identity, target-specific build and
launch-resolved executable-artifact identity, distinct built-in runtime
validation-report identity, deterministic required-flag diagnostics,
positional-argument rejection, exclusive output creation, body-free receipts,
and fail-closed stage, preflight, build-profile,
execution-identity, or validation-report substitution. Mutation-focused tests
use a receipt-shaped verifier double; a separate composition regression passes
the same bundle through the production `Verify` implementation. The public-CLI
test copies the complete candidate source into a hermetic Git repository,
commits it, builds the actual command with the mandatory release pins, then
runs that binary through the exported `RunDocumentationFactory` path with a
valid four-stage bundle and the production verifier. It compares the embedded
clean source revision, source-roster root, selected Go/Git digests, and receipt
executable digest/byte count against the exact build it ran. The release
launcher additionally binds the complete GOROOT and Git-helper tree roots,
unique regular-payload counts, and byte counts. GOROOT rejects symbolic links;
the Git-helper closure accepts only relative aliases to regular executables and
binds each logical path, raw target, physical target, target digest, and size.
The launcher validates the child's complete top-level schema,
release-critical nested identities, and portable/validation/final roots;
and publishes only bytes read through its retained private receipt handle.
The integration then runs that same real four-stage bundle and production
verifier through the committed exact-commit bootstrap, validates the resulting
receipt, and requires its portable root to equal the direct production run.
That digest is paired with in-memory Go build metadata and is not described as
a cross-platform promise that the loader's mapped image bytes remain
file-addressable. Tests require the serialized metadata-source and executable-
measurement-scope discriminators, reject substitutions of either one, and
reject both pre-open and final-path executable swaps deterministically. The
runtime validation profile/report carries
`candidate_runtime_validation_pass`; tests reject a generic `pass`
substitution, non-canonical validation bindings, and contradictory tool versus
execution build tags. It remains candidate-only, not an independent validator
or test-suite PASS. Raw `go run` without the required link values fails closed,
but caller-supplied `-ldflags` are not launcher provenance and a child receipt is
not a signature proving that the outer ceremony ran. The release-launcher
package separately exercises
the committed PowerShell or POSIX bootstrap, exact-commit projection, closed
Git/Go environment, fresh caches, complete GOROOT and Git-helper measurement,
module and selected-input verification, adversarial ignored/local-replacement
inputs, retained child and receipt handles, strict parent recomputation, and
exclusive no-follow final publication. Linux launches the retained child
through its descriptor. macOS retains and measures the no-follow handle,
revalidates the canonical path and identity before command construction,
executes that path, and revalidates afterward because Darwin provides no
supported pure-Go descriptor-execution path. ARC CI runs the release boundary on
native Linux filesystem/process semantics and compiles the platform-specific
Windows/amd64 and Darwin/arm64 test binaries. Those target compilations are
compile-only evidence: they do not exercise Windows or macOS descriptor,
process, or filesystem semantics. Native release-boundary runs on Windows and
macOS remain required before claiming acceptance on those platforms. This
remains a prepared-bundle runner, not the terminal direct-source compiler.
Pre/post toolchain and source-tree checks prove stable measured snapshots under
the declared local trust boundary; the tests do not claim to sandbox a hostile
writer that already has the same OS-account authority.
Release-boundary CI uses `go test -p 1` so the launcher package and the real
four-stage production integration do not run competing nested Go builds in
parallel; each ceremony retains its own bounded process and resource evidence.

To freeze explicit cross-machine evidence, set
`VELENZA_FACTORY_PORTABILITY_EVIDENCE_DIR` to an absent absolute physical
directory and run
`TestDocumentationFactoryPublicCLIWithCleanReleaseBuild` from the same pushed
commit on each native host. The test creates the directory exclusively and
writes `direct-receipt.json`, `release-receipt.json`, and `manifest.json` by
exclusive file creation. A Windows/macOS portability pass requires equal
candidate commit, clean-source revision, source-roster root, preflight root,
and direct/release portable receipt roots on both hosts. Target OS/architecture,
executable identities, and full receipt roots are intentionally target-specific.
The manifest is body-free, non-authoritative candidate evidence and explicitly
claims no live provider acceptance.

Retained official-provider fixtures are explicit `externalfixture` variants,
not silently skipped tests. Supply the exact pinned bytes and run them directly:

```bash
QBO_COPY_ALL_FIXTURE=/absolute/path/to/intuit-copy-all-body \
XERO_ASSETS_OPENAPI_FIXTURE=/absolute/path/to/xero-assets-openapi.yaml \
  go test -count=1 -tags=externalfixture ./internal/providerplan \
  -run '^TestOfficialProviderPinsRunCompleteDocumentationFactory$' -v
```

The combined test verifies each committed byte length and SHA-256 before
deriving any candidate facts, executes both providers through the same exact
evidence, derivation, materialization, graph, dependency, and production
`Verify` path, then runs each prepared provider bundle through the clean-source
public command and the committed exact-commit release bootstrap. Direct and
release receipts must share their portable and preflight roots. A missing
fixture, changed source body, or changed frozen root is a hard failure;
refreshing a pin requires an independently justified source, semantic,
executor, or target-schema contract change.

To retain comparable native-host evidence, also set
`VELENZA_FACTORY_OFFICIAL_EVIDENCE_DIR` to an absent absolute physical
directory. The test creates one provider-named subdirectory for each pin and
exclusively writes `direct-receipt.json`, `release-receipt.json`, and
`manifest.json`. A Windows/macOS comparison requires equal provider, source
identity, candidate commit, clean-source revision, source-roster root,
preflight root, and direct/release portable roots for each provider. Target
OS/architecture, executable identities, and full receipt roots remain
target-specific.

These retained files are body-free, non-authoritative candidate evidence. The
test-owned prepared manifests do not prove an externally sealed whole-corpus
ceremony, archive custody, graph admission, installation, grants, tenants,
deployment, source substitution, or live acceptance.

## OOD Graph physical-schema rendering

Run the generic renderer tests and the committed artifact/receipt check with:

```bash
go test ./internal/oodschema ./cmd/ood-schema-render .
```

The unit suite includes ordered-column, column-definition, primary-key,
unknown-index-table, duplicate-key, and apply-authority-smuggling failures.
The root artifact test recomputes the generated DDL digest, parses every
generated statement, and verifies the exact statement/table/index/property-
graph counts and physical table roster against the body-free receipt. Rendering
never applies DDL and never authorizes a deployment.

The canonical-source drift gate is a separate build-tagged test because the
authoritative OOD document belongs to `canonical-specs`, not this repository. CI
checks out that repository with the fleet-read installation token on every PR,
main push, and weekly drift run, then executes:

```bash
OOD_GRAPH_PROTOCOL_PATH=/absolute/path/to/canonical-specs/specs-local/OOD_GRAPH_PROTOCOL_v1.ood.json \
  go test -count=1 -tags=canonical -run '^TestGeneratedOODGraphSchemaMatchesCanonicalOOD$' .
```

The test rerenders from those exact bytes and requires byte-equality with the
committed DDL plus field-equality with the committed body-free receipt. The
path is an explicit input, so neither the test nor the renderer assumes a
machine-specific sibling-repository layout.

## Manual smoke test — the five-verb walk

This is the canonical proof that the experimental loop works end-to-end. Run from `/opt/velenza/velenza-canon/` after building (`go build -o bin/spec-graph .`).

### Prereqs

```bash
# gcloud authenticated to operator@example.com and project your-gcp-project-id
gcloud auth list | head -3
gcloud config get-value project   # → your-gcp-project-id

# bootstrap config in place
cp spec-graph.config.bootstrap.example.json spec-graph.config.json
```

### Step 0 — provision the database

```bash
gcloud spanner databases create corpus-graph-iter1 \
  --instance=your-spanner-instance \
  --project=your-gcp-project-id
```

(One-time. `spec-graph init` does NOT create the database — it only applies the schema.)

### Step 1 — apply schema

```bash
./bin/spec-graph init
```

Expected: every table from `bootstrap/schema_v1.sql` exists in `corpus-graph-iter1`. Re-run is idempotent (reports "already applied", exits 0).

### Step 2 — boot the MCP server and call health

```bash
./bin/spec-graph mcp
# in another terminal, via your MCP client:
spec_graph_health
```

Expected: substrate reachable, schema present, registry sizes match the config, mode=experimental_bootstrap.

### Step 3 — create a node

```
spec_graph_create
  node_kind=section
  stable_id=test_section_1
  contract={"name":"smoke test section"}
  payload={"body":"this is a smoke test"}
```

Expected: AdmissionRecord returned with `artifact_version=1`, `admitted_by=EXPERIMENTAL_BOOTSTRAP`, a non-empty definition_hash, a placeholder signature_chain entry.

### Step 4 — link two nodes

```
spec_graph_create
  node_kind=invariant
  stable_id=test_invariant_1
  contract={"name":"test invariant"}
  payload={"statement":"all smoke tests must pass"}

spec_graph_link
  source_id=test_section_1
  target_id=test_invariant_1
  edge_label=asserts_invariant
```

Expected: both AdmissionRecords succeed; the edge exists; reciprocity (if declared on `asserts_invariant`) creates the mirror edge in the same transaction.

### Step 5 — query closure

```
spec_graph_query
  query="GRAPH CorpusGraph MATCH (n:Node {node_id: 'test_section_1'})-[e:Edge]->(m:Node) RETURN m.node_id, m.node_kind, e.edge_label"
```

Expected: one row — `(test_invariant_1, invariant, asserts_invariant)`.

### Step 6 — reset (optional iteration)

```bash
./bin/spec-graph reset --confirm
```

Expected: database dropped and recreated, schema re-applied. Verbs against the now-empty graph fail with `ErrNotFound`-style messages.

### Pass criteria

All six steps complete without error. The graph state matches the expected end-state at each step. The MCP server stays up across calls. Resetting and re-running produces identical state.
