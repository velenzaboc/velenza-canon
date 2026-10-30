# Cloud API factory before runtime availability

This path prepares connection candidates and checks their offline conformance in Canon, Arbor's documentation and API-evidence layer. Its acceptance cases are AWS S3, AWS EC2, Google Cloud Storage and Google Compute Engine. It does not require changes to the Velenza kernel. Offline conformance is distinct from qualified evidence verification, admission and customer ingestion.

The goal is reusable machinery: pinned model parsing, evidence-bound API relationships, shared provider and protocol profiles, complete source-field dispositions and owner-bound semantic mappings. Service-specific facts belong in declarative inputs. The four cases exercise the machinery; they are not a claim of complete cloud or CNAPP coverage.

## Owners and boundaries

| Concern | Owner |
|---|---|
| Exact API models, documentation evidence and nested API catalog | Canon / OOD Graph |
| Candidate generation and verification stages | Existing documentation factory in `internal/providerplan` |
| Shared provider authentication requirements and service residuals | Reusable profiles; actual grants and secrets remain Connector Vault responsibilities |
| Source identity, source schemas, mapping generations and publication | OHM |
| Source-neutral infrastructure record meanings | Infrastructure Resource Record, owner `1729172e-44a9-48bb-b833-9591cd105516` version 1, under Business Record Class Contract |
| Implementation references and work evidence | Cambium and Trellis |
| Effective posture, findings and policy/control assessment | Their domain owners and Canopy |

The API hierarchy is provider → service → API surface/version → resource → operation. It is a graph: operations can involve several resources and shared definitions are referenced rather than copied. API/model revisions belong to catalog and mapping lineage; they do not create new customer source identities.

The offline compiler cannot grant customer access, qualify its own evidence, admit an artifact, allocate an OHM semantic identity or publish customer records. Those boundaries remain explicit dependencies. Graph storage compatibility does not itself qualify or publish a candidate graph.

## Four acceptance cases

| Case | Selected acquisition facts | Neutral targets | Required distinctions |
|---|---|---|---|
| S3 | Paginated general-purpose bucket enumeration and documented bucket metadata | Storage container and scope references | Optional ARN; mutable reported creation time; prefix/region scope; no object content |
| EC2 | Instance and volume descriptions | Compute instance, compute volume and attachment references | Account/region scope; exact volume identity; lifecycle ordering; exact capacity units |
| Cloud Storage | Bucket list/detail metadata | Storage container and scope references | Project scope; metageneration is ordering metadata; deletion/soft-deletion is separately evidenced |
| Compute Engine | Aggregated instance and disk descriptions | Compute instance, compute volume and attachment references | Zonal/regional scope; inaccessible aggregate members; forward/reverse attachment references; `TERMINATED` means stopped and restartable |

The AWS pair must reuse the same compatible provider/profile definitions; the Google pair must do likewise. Signing-service parameters, endpoint scope, response envelopes and operation permissions remain explicit residuals. A shared authentication requirement is not a shared grant unless the independently owned eligibility checks permit it.

## Required offline evidence

The retained inputs under `testdata/cloudapi` distinguish exact official model bytes from synthetic response fixtures and supplemental, unqualified assertions. Every input is bound to its bytes and coordinate. Lifecycle and unit recipes resolve explicit evidence bindings containing the source URI, package-local path, full-body hash, byte range and slice hash. Loading verifies those bytes, and later binding mutation refuses. This establishes evidence integrity, not independent qualification of the proposed semantic interpretation. A digest calculated from a file at test time is not an independent expected pin.

Acceptance must establish all of the following:

1. **Evidence integrity:** fixed source hashes, valid bounded UTF-8/JSON, duplicate-field refusal, exact JSON-pointer/byte-range agreement, and selected-operation identity. Unknown constructs or undocumented resource associations remain explicit gaps.
2. **Graph boundaries:** the five-role builder emits a nested cloud catalog candidate with source locators, not the native graph plan accepted by `Verify`. A separate native adapter emits candidate JSONL with typed roles and hierarchy gaps when its explicit context is supplied. Neither output qualifies its own evidence or enters authoritative materialization.
3. **Profile reuse:** shared definitions have stable content references; service-specific parameters and exceptions remain separate. A model change affects only the dependent compositions.
4. **Mapping completeness:** the selected source schema determines the field roster. The caller cannot omit a field and thereby claim completeness. Every field has a checked disposition, and every projected field resolves in the exact neutral schema.
5. **Exact values:** numbers, units, timestamps, enums, lists and references follow the declared type and cardinality rules. Null, absence, not-observed, inaccessible, redacted and unsupported values cannot silently become one another.
6. **Identity and relationships:** source coordinates stay private; neutral identities follow OHM's identity contract. Name similarity, API revision, arrival order, ETag or an ordinary update never proves identity equivalence or recreation. Cross-scope and unresolved references cannot manufacture relationships.
7. **Currentness:** pagination and scope gaps cannot prove deletion. Duplicate, reordered, partial and revoked-access observations exercise the declared refusal or uncertainty outcome. Replay and mapping succession must preserve the prior evidence and identity rules.
8. **Compiler boundaries:** all four retained models feed the candidate builder. Schema-valid fixture bodies separately exercise the existing four-stage compiler with an explicitly test-only verifier. These tests establish file and stage plumbing; they do not establish production `Verify` acceptance of the cloud catalog. Native graph conversion requires separately supplied manifest commitments, classification/derivation bindings and gap contexts. Missing context must refuse.

Storage configuration observations do not establish effective public exposure, encryption assurance or compliance. In particular, S3's reported bucket creation time can change, and its general-purpose `ListBuckets` operation does not establish directory-bucket ARN coverage. The service fixtures retain these distinctions. Lifecycle translation is also evidence-specific: Google Compute Engine's `TERMINATED` can be restarted, while EC2's `terminated` cannot. Neither response alone authorizes deletion of an OHM record.

## Running the path

Run focused offline tests from the repository root:

```sh
go test ./internal/providerplan -run 'Test.*Cloud' -count=1
go test ./cmd/cloud-api-factory -count=1
```

Generate candidates from the checked-in four-case input into a new output directory:

```sh
go run ./cmd/cloud-api-factory \
  --input testdata/cloudapi/candidate-input.json \
  --output-root /absolute/path/to/new-cloud-candidates
```

To use the existing complete source-package materializer, additionally supply its exact scaffold and a separate new output directory:

```sh
go run ./cmd/cloud-api-factory \
  --input testdata/cloudapi/candidate-input.json \
  --output-root /absolute/path/to/new-cloud-candidates \
  --source-package /absolute/path/to/sealed-source-package.json \
  --compiled-output-root /absolute/path/to/new-compiled-candidates
```

The input and output paths are local. Model fetching, customer API calls and credential acquisition are separate operations. Missing or mismatched scaffold/evidence inputs must refuse. Test-only scaffolding demonstrates the compiler boundary; it does not supply production qualification.

## What remains for a running Velenza installation

There are two remaining boundaries. First, before runtime, the native factory needs qualified source evidence and the full classification/derivation context accepted by its production verifier. A catalog and five candidate files do not provide those proofs. The native JSONL adapter accepts explicit candidate commitments and preserves this distinction; it cannot seal its own authority. Graph storage compatibility also refuses authoritative API materialization until the complete evidence verifier exists.

Second, signed admission, eligible customer grants, supported terminal authentication/signing, configured source operation bindings, actual OHM acceptance/publication and live recovery/reconciliation require their owning mechanisms. The kernel boot plan does not complete those service tasks. A later live acceptance must repeat the four cases against authorized cloud accounts and prove durable results, completeness and replay through the real runtime.

See [the completion map](completion-map.md) for the owner-by-owner sequence and the limits of the neutral target contract.

The governing contracts retain the broader research and dependency plan. Work is tracked by `CSP-API-FACTORY-CONTRACT-20261029`; existing broader factory and provider tasks remain separate.
