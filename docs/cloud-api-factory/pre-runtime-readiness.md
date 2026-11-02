# Pre-runtime qualification and materialization

This work prepares the selected S3, EC2, Cloud Storage and Compute inventory slice in Canon. It does not make the slice production-qualified or admitted. The boot-owned OOD reader and protected prepare/writer seam are implemented: qualification reads one current immutable generation in one read-only transaction, verifies its complete closure and claim manifests, and hands later stages opaque deep-cloned proofs. Selecting a deploy-time owner binding and accepting a qualified current source generation remain separate. Authoritative materialization, customer acquisition and durable publication remain separate owner-controlled steps.

## Mapping package

The repeatable preparation entrypoint composes the selected mapping package,
shared provider profiles and complete coverage ledger in one checked output
tree:

```sh
cloud-factory-prepare \
  --input /absolute/path/to/candidate-input.json \
  --scope /absolute/path/to/mapping-scope.json \
  --profiles /absolute/path/to/provider-profiles.json \
  --ingestion-policy /absolute/path/to/ingestion-handoff-policy.json \
  --output-root /absolute/path/to/new-preparation
```

Repeat the command with `--verify` to reconstruct the expected outputs from
the pinned inputs and compare every byte and the complete directory roster.
Verification refuses missing, changed or additional files and directories.
Creation uses the source-package publisher's private staging and exclusive
atomic publication; an existing destination is never replaced. The manifest
records exact document digests, provider/service/operation counts and all field
dispositions. The same tree includes the owner-pinned source coordinate and
ingestion handoff, including request-bound S3 detail identity and the
reconciliation/cutover prerequisites. Its status is
`candidate_prepared_unqualified`.

Preparation runs offline against the retained models. It does not fetch a newer
API revision automatically: updating the declared model, its hash or profile
changes the expected package and requires another exact validation. The source
qualification and native factory boundaries below still apply to those
candidates.

### Model revisions and repeatable successors

`cloud-model-audit --old /absolute/path/to/old-model.json --new /absolute/path/to/new-model.json`
compares exact retained JSON documents. Its report pins both complete byte
streams and lists changed JSON pointers with typed before/after values. It
rejects duplicate keys, preserves numeric precision, and distinguishes missing,
null, empty containers and container type. Object key ordering alone does not
become a semantic change; exact byte hashes still change.

`cloud-model-refresh` consumes that comparison and builds a separate successor:

```sh
cloud-model-refresh \
  --input /absolute/path/to/candidate-input.json \
  --scope /absolute/path/to/mapping-scope.json \
  --profiles /absolute/path/to/provider-profiles.json \
  --ingestion-policy /absolute/path/to/ingestion-handoff-policy.json \
  --refresh /absolute/path/to/refresh-request.json \
  --output-root /absolute/path/to/new-refresh
```

The refresh request names the existing model, new retained model path and exact
hash, source provenance, new mapping version, new service-profile version and
capture date. The checked example is
`testdata/cloudapi/refresh-20261102/refresh-request.json`. Both model paths are
resolved relative to the original candidate input. No credentials or network
fetches are involved.

The builder preserves the original package, verifies old evidence ranges,
rebases each selected locator to the same JSON pointer, and requires unchanged
selected values before carrying a binding forward. Changed operations, foreign
evidence identities, ambiguous semantic evidence and changed mapping semantics
refuse. A refused carry-forward requires a newly justified mapping or profile;
the tool cannot approve a new meaning automatically.

The successor includes portable pinned input documents, the revision audit and
the complete ordinary preparation tree. It is published exclusively with a
full digest roster and status `candidate_refresh_prepared_unqualified`.
Repeat the identical command with `--verify` to reconstruct and compare the
whole tree. This verifies reproducibility, not production source authority.

The retained November 2 comparison preserves the selected S3, EC2 and Cloud
Storage model bytes. Compute moves from Discovery revision `20261016` to
`20261026`, with six changed JSON values. The successor preserves the selected
nine operation targets and all 255 dispositions. The historical package and
its evidence remain separately addressable; its prior verification is not
silently reassigned to the new bytes.

`cloud-mapping-package` assembles one parent manifest and two provider packages from an explicit selection document. The same mechanism accepts a different declared selection without adding service branches. Each provider package retains its exact catalog/model versions, service/API coordinates, complete selected target recipes and neutral owner/profile references. The parent binds the exact provider document bytes and the canonical selection digest.

```sh
cloud-mapping-package \
  --input /absolute/path/to/candidate-input.json \
  --scope /absolute/path/to/mapping-scope.json \
  --output-root /absolute/path/to/new-mapping-package
```

The selected scope contains nine operation targets, 31 mapped facts, 24 private dispositions and 200 unsupported dispositions. Those 255 outcomes account for the selected decomposition; unsupported is an explicit gap, not a successful translation. Unknown and not-observed dispositions have separate counters. The publisher checks the parent/provider closure and exclusively creates a new directory. It cannot overwrite an existing package or produce an authority receipt.

This package is reviewable compiler input. It is not a new opaque output role that bypasses the existing source-package compiler. Native composition still requires exact field-contract occurrences, executed derivation facts, classifier/security/transitive profiles, mapping occurrence rows and the full dependency roster. The real compiler and `Verify` remain the acceptance boundary.

Each provider package also carries a proposed exact-byte extraction program for every selected field occurrence, including nested fields. All 255 programs execute through the existing derivation executor in tests against explicitly test-owned evidence selections. Their program identities are content-derived, and the package binds the source model, exact member locator and selected-range hash. This proves extraction mechanics; it does not select a production classifier or approve the neutral meaning. Non-boolean fields retain unclassified numeric semantics, including string-encoded integers. The package never substitutes `not_applicable` merely because the REST value is a string.

## Source qualification

The production source-owner adapter is selected at process boot. Its expected provider, organization, source owner, authenticated producer and authentication binding come from the independent owner binding. It checks the returned observation against the compiler-measured package and receipt digests/counts, canonical observation time and complete ordered evidence identity set. It never treats caller-provided booleans as authentication.

The reader itself must authenticate the producer and resolve the current immutable generation using its owning authority. The canonical Source Record and Semantic Projection contract, section `s1_scope_and_paradigm.integration_manufacturing_boundary.authority_split.provider_documentation_evidence_and_exact_hydration_owner`, assigns receipts, completeness, archive bindings, exact ranges, extractor authority, current validity, disclosure and hydration solely to OOD Graph Protocol. The implementation must consume OOD's sections s6, s9, s10 and s13; it must not introduce a parallel source-evidence authority registry. In particular, s9's active snapshot predicate and s10's snapshot eligibility, API claim retrieval and exact-field hydration contracts govern the current proof selection.

A nonempty binding digest cannot perform those operations. The implemented reader and writer preserve the fixed boot selector: deployment must select the admitted owner/profile binding through its protected authority path, and a current qualified source generation must still be accepted there. Adding a CLI verifier flag, trusting a local JSON claim, or returning success from a test verifier would bypass this boundary.

## Canonical selection and graph evidence

OOD v10 is the accepted canonical owner, pinned at SHA-256 `4c898eff0792fe3647702ff3c3d99af7a87f43c3df13ce851a6ecfaabd0383a2`. Canonical delivery is tracked in PR 3356; repository delivery and its exact merged revision are verified separately from runtime admission. Offline source selection neither changes authored metadata nor performs the signed admission ceremony. V10 closes typed violation-manifest references and the complete claim-root reachability used for graph/property/gap materialization. It does not turn a generated schema or a test fixture into admission.

The generated schema and render receipt match that exact owner. They contain 35 tables, 65 indexes and one property graph. Rendering does not apply DDL. The current seven-table store is not silently upgraded by replacing a generated SQL file.

The graph-fact locator verifier implements the exact 22-field encoding, whole-body/range verification and a fixed golden vector. The opt-in canonical check compares the ordered fields, type tags and presence rules to the independently pinned OOD owner. A successful byte binding proves supplied bytes only. It does not authenticate the receipt, establish archive eligibility/completeness, resolve a source classification, or authorize a graph write.

The source reader traverses the certificate and claim-manifest roots in the same Spanner read-only transaction as current snapshot selection. Strict physical codecs close table columns, nullability, types and primary keys. Manifest verification binds the physical certificate, nodes, entries and member bytes to the complete immutable row roster. External source artifacts derive their virtual identities from complete receipt and batch rows; there is no synthetic source-artifact table. API properties use an independently selected admitted payload schema, with local closed-payload validation and hash recomputation.

The qualification integration test exercises the protected launcher and real
Spanner client against a local protocol fixture, including current-head
selection and the complete nine-root closure in one read-only transaction.
Receipt-batch manifests are recomputed with their physical entry byte counts.
The verifier also checks relationships between members: locators must bind the
exact source artifact, receipt, batch and archive tuple; properties bind their
subject row; symbols bind their owning object; and edges bind both endpoints.
Tests change these bindings and recompute the enclosing hashes to establish
that matching manifest hashes alone cannot authorize contradictory facts.

Preparation retains detached copies of validated rows, certificate roots and
receipt values. Capture becomes available only after complete source
validation, and it binds both compiler-measured byte counts as well as the
digests and observation time. Mutating an input or an accessor result cannot
change a previously verified proof.

The native API adapter consumes opaque closure and row-roster proofs. It reconstructs API roles and relationships from immutable rows, checks their verified evidence locators and claim manifests, and prepares real graph, property and gap rows. The publisher inserts or verifies immutable rows before a bounded transaction compares the expected head and seals the successor. Exact replay has a separate no-advance outcome. A changed immutable row, stale head, wrong tenant or incomplete proof must refuse. The aggregate source-package receipt cannot substitute for these per-fact proofs.

The shared final API validator is implemented. The protected qualified compile → new physical successor → shared final-validator v8 run passed in 15.713 seconds using standalone role proofs and mandatory documentation provenance. Independent review accepted the protected path and its hostile proof-binding checks with zero blockers. Repository delivery follows the protected CI and merge path. `DocumentationFactoryOODSuccessorCoordinateIssuer` issues only non-fact typed graph coordinates. `DocumentationFactoryOODNativeProvenanceAuthority` separately authorizes source-fact provenance, including the boot-primary provenance for a legitimate multi-source claim. Neither role selects a production owner binding, admits an artifact or authorizes live ingestion.

These mechanisms require a protected deployment to supply the admitted archive, schema, attestation and currentness authorities. Local test authorities exercise the deterministic code and never constitute those production bindings. The complete source-reader and API-adapter integration tests remain the acceptance gate for this implementation.

## Verification

Focused unit and integration tests cover package completeness/tampering, boot-binding refusal, exact authority selection and locator bytes. The canonical checks use the owner file supplied separately:

Run the canonical graph-fact locator and authority-selection checks with the independently pinned OOD owner supplied through the deployment-approved test configuration.

These checks require no customer cloud account, kernel changes or database mutation. Runtime admission, credential eligibility, acquisition and durable OHM publication remain separate acceptance steps described in the [completion map](completion-map.md).

The all-four-service/native full nine-target compiler/real-`Verify` v22 run passed in 766.772 seconds with retained evidence and explicit test-only authority. Its accepted JSON SHA-256 is `1ec9a984fdcde5e0b13d9cdc0da020b859762cb82c7938b4083f2f6a4ac6ad03`. Even this observed offline result does not authenticate a production source, qualify a semantic interpretation, admit an artifact or ingest a customer account.
