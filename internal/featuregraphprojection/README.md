# Bounded FeatureGraph evidence publication

`spec-graph featuregraph-publish` plans and atomically publishes a reviewed source selection into a new sealed legacy FeatureGraph snapshot. It writes only FeatureGraphSnapshots, FeatureGraphNodes and FeatureGraphEdges. It neither initializes databases nor writes OOD, runtime, admission or executable state.

The operator config must explicitly fence the experimental database, organization, source snapshot, target prefix, repository paths, artifact roles, caps and the expected selection SHA-256. The selection includes exact source node/edge IDs and immutable Git artifact locators with reviewed references. SelectionSHA256 commits to their normalized sets; omitted edges, changed artifacts and changed references require a new config commitment. Artifact bytes are read from the specified full Git commit, checked as regular blobs and verified against SHA-256.

Source metadata, selected rows and Git bytes are revalidated inside the same read/write transaction before any target insert. The source remains unchanged. The target is inserted and sealed in that single transaction. Readback checks exact rows, counts, provenance, timestamps and seal. Existing matching targets replay without writes; collisions and partial/corrupted targets refuse.

Unsealed sources refuse by default. Explicit allow_observed_unsealed_source records a bounded pinned observation; target seal never asserts that the original source is sealed, complete or current. The target commit timestamp anchors the source observation. Legacy content_sha256 values are preserved as unverified declarations because that schema does not define their hash algorithm. Separately recomputed canonical JSON body digests are bound into the manifest and target provenance. New Git artifact hashes verify exact bytes. Research review states and zero runtime-authority qualifiers are retained.

Plan:

    spec-graph featuregraph-publish --config CONFIG.json --selection SELECTION.json --manifest PLAN.json

Inspect the complete plan and digest before apply:

    spec-graph featuregraph-publish --config CONFIG.json --manifest PLAN.json --apply --expected-manifest-sha256 DIGEST

Reapply the identical manifest to verify exact replay. Config uses the existing gcpauth selector for process-local device credentials and owner-required impersonation; do not copy credentials or change shared authentication. File inputs have an independent 32MiB absolute ceiling; config also caps bytes, node/edge limits and buffered row mutations. max_mutations counts single-row mutation messages (one snapshot plus node/edge rows), not the service quota on cells/index mutations. Spanner independently enforces its commit quotas atomically. Files are strict bounded JSON: duplicate keys, unknown fields and trailing data refuse.

Tests: scoped unit tests cover selection commitments, observed-body qualification, transactional drift, rollback, caps, replay and exact target readback. Integration-tagged tests exercise the real Spanner SDK against an explicitly allowed loopback emulator with only the three legacy tables, including large JSON integers and buffered-write failure. No live credentials are used by tests.
