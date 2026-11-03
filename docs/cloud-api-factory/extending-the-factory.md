# Extending the cloud factory

Add a service by composing retained evidence, reusable provider profiles and
declared mappings. The factory machinery stays shared. A new service needs Go
code only when its model format or wire semantics require a reusable parser or
validator that does not exist yet.

## Smallest reusable units

| Unit | Declares | Reuses |
|---|---|---|
| Provider | Provider identity and common authentication/profile requirements | Authentication and protocol profile definitions |
| Service | API surfaces, model revisions, endpoint and signing residuals | Its provider by exact reference |
| Resource | Documented resource identity, scope and participating operations | Source-neutral record owner and schema |
| Operation | Request/response bindings, permissions, paging and retry policy | Service/API profile and resource references |
| Field occurrence | Exact source locator, disposition and justified recipe | Generic derivation, exact-value and uncertainty validators |

An API surface/version is an explicit coordinate between service and resource.
An operation can touch several resources. Preserve those typed relationships
instead of duplicating an operation or a provider definition in each resource.
Provider reuse does not widen a customer's credential grant.

Repeatability is deliberate: provider → service → API surface/version →
resource ↔ operation → field occurrence is the unit of change. A new revision
or operation gets a new retained coordinate and successor package; it does not
rewrite a prior package, customer source identity or qualification receipt. The
selected package's 255 dispositions (31 mapped, 24 private, 200 unsupported)
are complete accounting for its declared field occurrences only. They are not
a claim of full semantic coverage: only 31 of the 255 dispositions are mapped,
while 24 remain private and 200 are explicitly unsupported.

The historical v2 package remains reproducible as historical input. The normal
four-service successor generator instead binds IRR v3 and has a measured scope
of six resources, nine operations and 255 occurrences: 199 mapped and 56
source-private. It resolves 168 of the original 200 unsupported occurrences
as mapped and retains 32 as intentionally source-private; 55 existing
occurrences are preserved. These counts describe offline package accounting
only. They neither qualify source evidence nor establish runtime acceptance,
admission, acquisition, or OHM publication.

The successor crosswalk is a closure tool, not a semantic acceptance label.
When a package resolves formerly unsupported occurrences, preserve the prior
coverage report and use `cloud-coverage-audit --resolve-from` to account for
each old occurrence exactly once.  A result may be mapped, source-private, or
remain unsupported only with its own field-level reason.  The report proves
offline successor accounting against pinned inputs; it does not qualify source
evidence, admit a package, or publish a customer record.

## Add or extend a service

1. **Retain the source.** Add the exact model bytes and origin, revision and
   SHA-256 to the candidate input. Smithy and Google Discovery already have
   parsers. Retain separate documentary evidence for meanings the model does
   not establish. Supplemental resource/operation associations retain their
   own source coordinates; they cannot masquerade as model declarations.

2. **Reference the provider.** Extend the appropriate service entry in the
   profile document. Reuse compatible provider authentication and protocol
   definitions. Declare service-specific endpoints, signing parameters or
   token scopes, and each selected operation's permissions, pagination and
   retry behavior. The profile validator rejects inconsistent coordinates and
   unjustified widening.

3. **Declare the selected scope.** Extend the catalog and target entries in
   the mapping-scope document. Each resource and operation has an explicit
   parent and canonical identity. The selected response schema determines
   the complete field roster. Declaring a convenient subset cannot produce a
   completeness claim.

4. **Resolve the neutral owner.** A mapped target must exist in the pinned
   owner schema. If its meaning is missing, extend the proper canonical
   record owner and validator, then regenerate its portable export. Until
   that declaration and its evidence exist, retain an explicit unsupported
   disposition. Private source coordinates stay in source identity bindings;
   they do not become neutral identities by renaming them.

5. **Account for every occurrence.** Supply one checked disposition for each
   field, or recursively decompose a parent into its complete declared leaf
   set. Bind a mapped recipe to exact documentary ranges and the target
   schema. Declare absence, null, unknown and inaccessible behavior. Exact
   units, lifecycle meanings and attachment cardinality need their own
   evidence. The same executor runs all generated field programs.

6. **Exercise actual wire shapes.** Add synthetic responses and requests
   matching the retained models, including empty responses and missing,
   inaccessible and malformed values. Test provider-specific lifecycle and
   unit meanings, unknown enums, duplicate identities, ambiguous references
   and partial pagination. Observation gaps never establish deletion.

   For repeated objects, assert that related leaves remain in the same item
   (for example, disk source, boot state and device name).  For scoped
   references, test a same-scope binding and rejection of missing, ambiguous
   and foreign-scope bindings.  Dynamic maps require a closed key/value recipe
   with sorted entries; arbitrary provider JSON is never a fallback value.

7. **Prepare and verify the complete composition.** Run
   `cloud-factory-prepare` with the candidate input, selection, profiles and
   ingestion policy. Run the same command with `--verify`. Both paths rebuild
   the expected package; verification compares every file and the complete
   directory roster. An exclusive new output directory preserves prior
   generations. The manifest binds the source, profile, mapping and coverage
   documents together.

8. **Verify the native factory boundary.** The selected fields must reach
   source-package compilation, all four stages and real `Verify`. Retained
   evidence alone is insufficient: classification, derivation, security,
   applicability and mapping dependencies must close over the exact bytes.
   Production preparation additionally requires the protected source-owner
   qualification path and the complete OOD closure. Test-owned authority
   remains test evidence.

9. **Keep the production handoff separate.** The protected OOD qualification
   seam must read a deploy-time-selected current generation and verified claim
   manifests; the adapter receives opaque deep-cloned proofs and prepares graph,
   property and gap rows. This implemented path is testable without granting a
   local candidate authority. Boot binding, qualified capture, signed admission,
   live acquisition and OHM publication remain owner-controlled events.

10. **Close every exact facet dependency.** Bind the retained model and exact
    evidence ranges; provider, service, API/version, resource, operation and
    field coordinates; field-contract occurrences; classification, derivation,
    applicability and security profiles; mapping rows; relationship/gap
    contexts; claim manifests; and mandatory documentation provenance. Re-run
    the same preparation, verification and protected-successor steps from
    those pinned inputs. `DocumentationFactoryOODSuccessorCoordinateIssuer`
    issues only non-fact typed graph coordinates; it cannot authorize a source
    fact. `DocumentationFactoryOODNativeProvenanceAuthority` separately
    authorizes source-fact provenance, including the boot-primary provenance
    for a legitimate multi-source claim. Do not infer either authority from a
    matching object ID or coordinate.

The checked-in examples are under `testdata/cloudapi`: `candidate-input.json`,
`mapping-package-scope.json`, `provider-profiles-v1.json`,
`ingestion-handoff-policy.json`, the evidence documents and the four service
cases. `cloud-factory-prepare --help` and
[pre-runtime readiness](pre-runtime-readiness.md) describe the commands.

### Extend a versioned service document

`testdata/cloudapi/candidate-input-v3.json` pins each service's target document
under `neutral-v3/`. Each document owns the operations of one provider, service
and API surface. The input resolver checks the complete set of model coordinates,
the exact document digest and every target's parent. A new mapping generation
gets a fresh input and service version. The original package can still be
prepared from its original inputs.

The portable IRR export assigns the target field to a record class and declares
its value shape, unit, cardinality and presence semantics. Bind that descriptor
and the provider evidence to the mapping. `cloud-model-audit --model MODEL
--select SELECTION.json` measures the byte ranges for named JSON pointers.
The selection contains `source_path`, `source_uri`, `expected_sha256` and
`selections` with one `id` and `json_pointer` per range. The mapping loader
reads the pinned bytes again and verifies every individual range.

Use a structured recipe when members belong together. Each interface keeps
its addresses and network reference in the same item. Declare each source
member, any private reason, and the owner member it supplies. Set `on_absent`
and `on_null` when their dispositions differ from the default missing
observation and null refusal. An explicit `unobserved_members` entry handles
an owner member supplied by another service. A scoped relationship requires
an opaque binding in the selected scope. Collection projections preserve item
association, while key/value collections sort keys and reject duplicate keys.

Run the normal four-service preparation from the Canon repository root:

```sh
inputs=testdata/cloudapi
out="$PWD/build/cloud-neutral-v3"
go run ./cmd/cloud-factory-prepare --input "$inputs/candidate-input-v3.json" \
  --scope "$inputs/mapping-package-scope-v3.json" --profiles "$inputs/provider-profiles-refreshed.json" \
  --ingestion-policy "$inputs/ingestion-handoff-policy.json" --output-root "$out"
go run ./cmd/cloud-factory-prepare --input "$inputs/candidate-input-v3.json" \
  --scope "$inputs/mapping-package-scope-v3.json" --profiles "$inputs/provider-profiles-refreshed.json" \
  --ingestion-policy "$inputs/ingestion-handoff-policy.json" --output-root "$out" --verify
```

Use a new output directory for the coverage audit. Its report pairs each
formerly unsupported source occurrence with its successor occurrences, exact
range, disposition and owner. A missing field, changed retained disposition,
foreign source coordinate or unresolved child fails reconciliation.

```sh
go run ./cmd/cloud-coverage-audit --input "$inputs/candidate-input-v3.json" \
  --scope "$inputs/mapping-package-scope-v3.json" --output-root "$PWD/build/cloud-v3-audit" \
  --resolve-from "$inputs/neutral-v3/previous-coverage.json" \
  --resolve-from-sha256 906348b967d473a2fa7aa66fdab891ee8d90c3705a14473b4e74cea540dfae47
```

## Refresh an API revision

Keep the previous model and generation. `cloud-model-audit` reports changed
JSON pointers while retaining both complete byte hashes. `cloud-model-refresh`
can carry a binding forward only when the selected value at its exact pointer
is unchanged; it rebases and rechecks the range against the successor bytes.
A changed semantic assertion requires fresh justification. A successful
refresh produces a separate, reproducible candidate tree and never transfers
an old qualification or admission receipt to new bytes.

The service profile and mapping generation change independently from the
customer source identity. Credential rotation, model refresh and mapping
cutover must not create a new source identity. The ingestion handoff records
the identity, currentness, replay and rollback obligations for eventual OHM
execution.

## Verification and delivery

The ordinary repository suite includes the factory, model refresh, profile,
coverage, mapping and OOD tests:

```sh
go vet ./...
go build ./...
go test -p 1 -count=1 -timeout 30m ./...
```

To run the native four-service verification for the v3 generation on its own:

```sh
go test ./internal/providerplan -run '^TestCloudMappingNeutralSuccessorReachRealFactoryVerify$' -count=1 -timeout 30m
```

Link each successor's exact source and owner versions to its generated package,
implementation revision, tests and independent acceptance. New service work
decomposes into the same provider, service, resource, operation and field units;
the parent closes only when its child evidence composes completely.

Signed admission, eligible customer grants, actual acquisition and durable OHM
publication have their own acceptance boundaries. The refreshed-model CLI,
profile inputs and OHM handoff package prepare repeatable candidate inputs;
they do not choose a production boot binding, qualify capture, admit an
artifact or publish an OHM record. See the
[completion map](completion-map.md) for that handoff.
