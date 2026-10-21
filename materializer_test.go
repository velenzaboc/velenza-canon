package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Regression suite for the §8 source-set and run-lifecycle contracts.
//
// What these tests pin, and what each would have caught before this file
// existed:
//
//   - source_set_hash is a SHA-256 over the ORDERED source coordinates
//     (§8.canonical_source_intake.source_set_contract), not a wall clock.
//     Every determinism assertion below goes red against
//     `fmt.Sprintf("seed_nodes_import_%d", now.UnixNano())`, because a
//     wall-clock hash differs on every call by construction.
//   - the eleven-key total order of
//     §8.deterministic_parser_contract.deterministic_source_ordering.
//   - the run row is INSERTED at state="running" before the batch commits,
//     and moved to "failed" when it does not
//     (§8.materialization_pipeline.open_materialization_run,
//     §8.idempotency_and_replay_safety.abandoned_run_rule).
//   - graph_version is not minted by the caller
//     (§8.write_snapshot_row.graph_version_assignment).
//
// Every test runs under `go test ./...` with no Spanner emulator.

func testCoord(authority, ref, version string) SourceCoordinate {
	return SourceCoordinate{
		OrganizationID:        "org-test",
		SourceAuthorityID:     authority,
		SourceArtifactClass:   "axiom",
		SourceRefKind:         "name",
		SourceStableReference: ref,
		VersionCoordinate:     version,
		SectionPath:           "$",
	}
}

// TestComputeSourceSetHashIsIndependentOfArrivalOrder is the load-bearing
// idempotency test. §8.idempotency_and_replay_safety.idempotency_key makes
// input_source_set_hash the field that decides whether two runs are the same
// run; safe_retry_rule then requires "a retried materialization run with the
// same input_source_set_hash" to be recognisable AS a retry. If the hash
// depended on the order submissions happened to arrive in — or on a clock —
// no retry could ever match, and
// §9.active_snapshot_selection.eligible_snapshot_predicate's
// source_set_hash_matches_run_input_source_set_hash would pass only
// vacuously.
func TestComputeSourceSetHashIsIndependentOfArrivalOrder(t *testing.T) {
	a := testCoord("auth-a", "alpha", "v1")
	b := testCoord("auth-b", "beta", "v2")
	c := testCoord("auth-c", "gamma", "v3")

	forward, err := ComputeSourceSetHash("org-test", []SourceCoordinate{a, b, c})
	if err != nil {
		t.Fatalf("ComputeSourceSetHash(forward): %v", err)
	}
	reverse, err := ComputeSourceSetHash("org-test", []SourceCoordinate{c, b, a})
	if err != nil {
		t.Fatalf("ComputeSourceSetHash(reverse): %v", err)
	}
	shuffled, err := ComputeSourceSetHash("org-test", []SourceCoordinate{b, c, a})
	if err != nil {
		t.Fatalf("ComputeSourceSetHash(shuffled): %v", err)
	}

	if forward != reverse || forward != shuffled {
		t.Errorf("source_set_hash depends on arrival order, so no replay can ever be recognised as one:\n  forward  = %s\n  reverse  = %s\n  shuffled = %s", forward, reverse, shuffled)
	}
	// A SHA-256 hex digest is 64 characters. Pins the algorithm clause of
	// source_set_hash_algorithm, and goes red for any stringly-typed
	// stand-in that happens to be stable.
	if len(forward) != 64 {
		t.Errorf("source_set_hash is %d chars (%q); §8.source_set_hash_algorithm requires SHA-256, i.e. 64 hex chars", len(forward), forward)
	}
	if strings.ContainsAny(forward, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_") {
		t.Errorf("source_set_hash %q is not lowercase hex", forward)
	}
}

// TestComputeSourceSetHashIsStableAcrossCalls is the anti-wall-clock
// control. Two invocations with byte-identical input must agree; a
// time-derived hash fails here even though it would pass a single-call
// smoke test.
func TestComputeSourceSetHashIsStableAcrossCalls(t *testing.T) {
	coords := []SourceCoordinate{testCoord("auth-a", "alpha", "v1")}
	first, err := ComputeSourceSetHash("org-test", coords)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := ComputeSourceSetHash("org-test", coords)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first != second {
		t.Errorf("source_set_hash changed between two calls over identical input (%s vs %s) — the hash carries non-source entropy", first, second)
	}
}

// This golden pins the byte-level interpretation of the protocol's closed
// six-input hash contract. A refactor that changes a key name, scalar/array
// shape, canonical-key order, or profile token must fail loudly rather than
// silently minting a second idempotency namespace for the same sources.
func TestComputeSourceSetHashGoldenSixInputContract(t *testing.T) {
	got, err := ComputeSourceSetHash("org-test", []SourceCoordinate{testCoord("auth-a", "alpha", "v1")})
	if err != nil {
		t.Fatal(err)
	}
	const want = "1d6e1094f4da6b61ac9cfefde0caab16a1a921668973814e5a870987c3b17140"
	if got != want {
		t.Fatalf("source_set_hash golden changed: got %s want %s", got, want)
	}
}

func testExternalVerificationReceipt(retrievedAt time.Time) *stagedExternalVerificationReceipt {
	digest := strings.Repeat("a", 64)
	stableName := "official_invoice"
	stableReference := "https://example.com/docs/invoice.json#/models/Invoice"
	policy := ExternalSourceDescriptor{ID: "official_docs", SourceArtifactClass: "official_vendor_documentation"}
	coord := ArtifactSourceCoordinate{SourceAuthorityID: bootstrapSourceAuthority, SourceRefKind: "coordinate", SourceStableReference: stableReference}
	authorization := validTestExternalAuthorization("org-test", "api_symbol", policy, coord, retrievedAt.UTC(), externalBodyCustodyAGFS)
	authorization.PermissionExpiresAt = ""
	receipt := &stagedExternalVerificationReceipt{
		ReceiptVersion:                  stagedExternalReceiptVersion,
		CanonicalReference:              "https://example.com/docs/invoice.json",
		VerifiedSourceStableReference:   stableReference,
		RetrievedAt:                     retrievedAt.UTC().Format(time.RFC3339Nano),
		ByteLength:                      1,
		SHA256:                          digest,
		TransportStatus:                 "success",
		TransportRawHashAlgorithm:       "sha256",
		ContentCoding:                   "identity",
		TransportResponseMetadataDigest: strings.Repeat("c", 64),
		DecodedByteLength:               1,
		DecodedSHA256:                   digest,
		SourceRepresentationMediaType:   "text/html",
		SourceContentHashAlgorithm:      "sha256",
		SourceContentHashProfile:        externalEvidenceHashProfile,
		SourceRegistryID:                "official_docs",
		SourceAuthorityID:               bootstrapSourceAuthority,
		PolicyFingerprint:               strings.Repeat("b", 64),
		ObjectClass:                     "api_symbol",
		CanonicalName:                   stableName,
		LocatorKind:                     "json_pointer",
		FinalVersionCoordinate: VersionCoordinate{
			Kind: VersionSourceNamed, SourceAuthorityID: bootstrapSourceAuthority,
			StableName: stableName, SourceVersionToken: "sha256_" + digest,
		}.String(),
		Authorization: authorization,
	}
	receipt.Archive = testExternalArchiveReceipt(authorization, receipt.DecodedByteLength, receipt.DecodedSHA256)
	return receipt
}

func TestExternalOccurrenceReceiptsDoNotWidenSemanticSourceSetHash(t *testing.T) {
	first := testExternalVerificationReceipt(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	second := *first
	second.RetrievedAt = "2026-08-29T12:00:00Z"
	coordinate := SourceCoordinate{
		OrganizationID: "org-test", SourceAuthorityID: first.SourceAuthorityID,
		SourceArtifactClass: "official_vendor_documentation", SourceRefKind: "coordinate",
		SourceStableReference: first.VerifiedSourceStableReference, VersionCoordinate: first.FinalVersionCoordinate,
		SectionPath: SectionPathRoot, SourceContentHash: first.SHA256,
	}
	hash1, err := ComputeSourceSetHash("org-test", []SourceCoordinate{coordinate})
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := ComputeSourceSetHash("org-test", []SourceCoordinate{coordinate})
	if err != nil {
		t.Fatal(err)
	}
	if hash1 != hash2 {
		t.Fatal("occurrence time widened semantic source_set_hash")
	}
	set1, err := BuildSourceSetWithExternalReceipts("org-test", []SourceCoordinate{coordinate}, []*stagedExternalVerificationReceipt{first})
	if err != nil {
		t.Fatal(err)
	}
	set2, err := BuildSourceSetWithExternalReceipts("org-test", []SourceCoordinate{coordinate}, []*stagedExternalVerificationReceipt{&second})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(set1) == fmt.Sprint(set2) {
		t.Fatal("distinct verification occurrences collapsed in durable source_set evidence")
	}
	roundTrip, err := ExternalVerificationReceiptsFromStoredSet(set2)
	if err != nil || len(roundTrip) != 1 || roundTrip[0].RetrievedAt != second.RetrievedAt {
		t.Fatalf("receipt round trip=%+v err=%v", roundTrip, err)
	}
}

func TestMaterializationSourceSetFailsBelowSpannerJSONCellLimit(t *testing.T) {
	err := validateMaterializationSourceSetStorageBound(map[string]interface{}{
		"oversized": strings.Repeat("x", maxMaterializationSourceSetCanonicalBytes+1),
	})
	if !errors.Is(err, ErrOODGraphMaterializationScaleUnrepresentable) {
		t.Fatalf("oversized source_set error=%v, want typed storage-envelope refusal", err)
	}
}

func TestComputeSourceSetHashExcludesParserAndMaterializerDiscriminators(t *testing.T) {
	base := testCoord("auth-a", "alpha", "v1")
	baseHash, err := ComputeSourceSetHash("org-test", []SourceCoordinate{base})
	if err != nil {
		t.Fatal(err)
	}
	mutations := []struct {
		name   string
		mutate func(*SourceCoordinate)
	}{
		{"source_artifact_class", func(c *SourceCoordinate) { c.SourceArtifactClass = "release_note" }},
		{"source_ref_kind", func(c *SourceCoordinate) { c.SourceRefKind = "coordinate" }},
		{"section_path", func(c *SourceCoordinate) { c.SectionPath = "$.different" }},
		{"symbol_kind", func(c *SourceCoordinate) { c.SymbolKind = "api_symbol" }},
		{"symbol_name", func(c *SourceCoordinate) { c.SymbolName = "Invoice" }},
		{"edge_label", func(c *SourceCoordinate) { c.EdgeLabel = "defines_external_symbol" }},
		{"authoring_source_path", func(c *SourceCoordinate) { c.AuthoringSourcePath = "$.relationships[0]" }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			tc.mutate(&candidate)
			got, err := ComputeSourceSetHash("org-test", []SourceCoordinate{candidate})
			if err != nil {
				t.Fatal(err)
			}
			if got != baseHash {
				t.Fatalf("non-contract discriminator widened source_set_hash: got %s want %s", got, baseHash)
			}
		})
	}
}

// TestComputeSourceSetHashDiscriminates is the non-vacuity control for the
// two tests above. A constant would satisfy every determinism assertion
// while destroying the idempotency key's whole purpose, so each field the
// spec names as a hash input must move the digest, and the organization
// must too.
func TestComputeSourceSetHashDiscriminates(t *testing.T) {
	base := testCoord("auth-a", "alpha", "v1")
	baseHash, err := ComputeSourceSetHash("org-test", []SourceCoordinate{base})
	if err != nil {
		t.Fatalf("base: %v", err)
	}

	withContentHash := base
	withContentHash.SourceContentHash = "deadbeef"

	cases := []struct {
		name   string
		orgID  string
		coords []SourceCoordinate
	}{
		{"different source_authority_id", "org-test", []SourceCoordinate{testCoord("auth-z", "alpha", "v1")}},
		{"different source_stable_reference", "org-test", []SourceCoordinate{testCoord("auth-a", "omega", "v1")}},
		{"different version_coordinate", "org-test", []SourceCoordinate{testCoord("auth-a", "alpha", "v9")}},
		{"exposed source_content_hash", "org-test", []SourceCoordinate{withContentHash}},
		{"different organization_id", "org-other", []SourceCoordinate{base}},
		{"additional coordinate", "org-test", []SourceCoordinate{base, testCoord("auth-b", "beta", "v1")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ComputeSourceSetHash(tc.orgID, tc.coords)
			if err != nil {
				t.Fatalf("ComputeSourceSetHash: %v", err)
			}
			if got == baseHash {
				t.Errorf("%s did not change source_set_hash (%s) — the digest is not covering a §8.source_set_hash_inputs member", tc.name, got)
			}
		})
	}
}

// TestSortSourceCoordinatesAppliesSpecKeyOrder pins that the eleven keys of
// deterministic_source_ordering are applied in the spec's own sequence.
// Each case differs on exactly ONE key while an EARLIER-listed key is held
// equal and a LATER-listed key is set to contradict the expected order — so
// a permutation of the key sequence produces the wrong winner rather than
// merely a different tie-break.
func TestSortSourceCoordinatesAppliesSpecKeyOrder(t *testing.T) {
	// source_authority_id (key 2) outranks source_stable_reference (key 5):
	// "b" wins on authority even though its reference sorts last.
	low := SourceCoordinate{OrganizationID: "org", SourceAuthorityID: "a", SourceStableReference: "zzz"}
	high := SourceCoordinate{OrganizationID: "org", SourceAuthorityID: "b", SourceStableReference: "aaa"}
	got := SortSourceCoordinates([]SourceCoordinate{high, low})
	if got[0].SourceAuthorityID != "a" {
		t.Errorf("source_authority_id must outrank source_stable_reference per deterministic_source_ordering; got first = %+v", got[0])
	}

	// version_coordinate (key 6) outranks section_path (key 7).
	vLow := SourceCoordinate{OrganizationID: "org", VersionCoordinate: "v1", SectionPath: "$.z"}
	vHigh := SourceCoordinate{OrganizationID: "org", VersionCoordinate: "v2", SectionPath: "$.a"}
	got = SortSourceCoordinates([]SourceCoordinate{vHigh, vLow})
	if got[0].VersionCoordinate != "v1" {
		t.Errorf("version_coordinate must outrank section_path; got first = %+v", got[0])
	}

	// symbol_name (key 9) outranks edge_label (key 10).
	sLow := SourceCoordinate{OrganizationID: "org", SymbolName: "aaa", EdgeLabel: "zzz"}
	sHigh := SourceCoordinate{OrganizationID: "org", SymbolName: "bbb", EdgeLabel: "aaa"}
	got = SortSourceCoordinates([]SourceCoordinate{sHigh, sLow})
	if got[0].SymbolName != "aaa" {
		t.Errorf("symbol_name must outrank edge_label; got first = %+v", got[0])
	}
}

// TestSortSourceCoordinatesDoesNotMutateInput pins that a caller may keep
// its arrival-order slice for diagnostics. An in-place sort would silently
// reorder the caller's own view of what it submitted.
func TestSortSourceCoordinatesDoesNotMutateInput(t *testing.T) {
	in := []SourceCoordinate{testCoord("auth-z", "zeta", "v1"), testCoord("auth-a", "alpha", "v1")}
	_ = SortSourceCoordinates(in)
	if in[0].SourceAuthorityID != "auth-z" {
		t.Errorf("SortSourceCoordinates mutated its input; caller's arrival order was destroyed (in[0] = %q)", in[0].SourceAuthorityID)
	}
}

// TestBuildSourceSetCarriesCoordinatesNotCounts pins the stored shape.
// §8.snapshot_production_contract.historical_reproducibility requires a
// sealed snapshot to remain reproducible from its source_set; the prior
// {"object_count":N,"symbol_count":M} shape names no source at all, so a
// snapshot carrying it can never be reproduced. Also pins that the stored
// order is the sorted order, matching the order the hash ran over.
func TestBuildSourceSetCarriesCoordinatesNotCounts(t *testing.T) {
	set := BuildSourceSet("org-test", []SourceCoordinate{
		testCoord("auth-z", "zeta", "v1"),
		testCoord("auth-a", "alpha", "v1"),
	})

	if _, isCount := set["object_count"]; isCount {
		t.Error("source_set carries object_count — a count names no source coordinate and cannot satisfy historical_reproducibility")
	}
	if set["organization_id"] != "org-test" {
		t.Errorf("source_set.organization_id = %v; want org-test (§8.source_set_hash_inputs lists it first)", set["organization_id"])
	}
	if set["materialization_profile_version"] != MaterializationProfileVersion {
		t.Errorf("source_set.materialization_profile_version = %v; want %q", set["materialization_profile_version"], MaterializationProfileVersion)
	}
	items, ok := set["coordinates"].([]interface{})
	if !ok {
		t.Fatalf("source_set.coordinates is %T; want []interface{}", set["coordinates"])
	}
	if len(items) != 2 {
		t.Fatalf("source_set.coordinates has %d entries; want 2", len(items))
	}
	first, ok := items[0].(map[string]interface{})
	if !ok {
		t.Fatalf("coordinate[0] is %T; want map", items[0])
	}
	if first["source_authority_id"] != "auth-a" {
		t.Errorf("stored coordinates are not in deterministic_source_ordering; coordinate[0].source_authority_id = %v, want auth-a", first["source_authority_id"])
	}
	// The stored set must carry identity only. copied_source_payload_allowed
	// is false, so a payload key here would be a storage-boundary breach.
	for _, forbidden := range []string{"payload", "contract", "search_text", "content"} {
		if _, present := first[forbidden]; present {
			t.Errorf("coordinate carries %q — §8.source_set_contract.copied_source_payload_allowed is false", forbidden)
		}
	}
}

func validStoredSourceSet(t *testing.T) (map[string]interface{}, string) {
	t.Helper()
	coordinate := SourceCoordinate{
		OrganizationID:        "org-test",
		SourceAuthorityID:     bootstrapSourceAuthority,
		SourceArtifactClass:   "axiom",
		SourceRefKind:         "name",
		SourceStableReference: "an_axiom",
		VersionCoordinate:     "unversioned",
		SectionPath:           SectionPathRoot,
	}
	set := BuildSourceSet("org-test", []SourceCoordinate{coordinate})
	digest, err := ComputeSourceSetHash("org-test", []SourceCoordinate{coordinate})
	if err != nil {
		t.Fatal(err)
	}
	return set, digest
}

func TestValidateMaterializationSourceSetAcceptsExactCanonicalEvidence(t *testing.T) {
	set, digest := validStoredSourceSet(t)
	if err := ValidateMaterializationSourceSet("org-test", digest, set); err != nil {
		t.Fatalf("ValidateMaterializationSourceSet: %v", err)
	}
}

func TestValidateMaterializationSourceSetRejectsDigestAndShapeDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]interface{}, *string)
		want   string
	}{
		{"uppercase_hash", func(_ map[string]interface{}, digest *string) { *digest = strings.ToUpper(*digest) }, "lowercase hexadecimal"},
		{"nonhex_hash", func(_ map[string]interface{}, digest *string) { *digest = strings.Repeat("z", 64) }, "lowercase hexadecimal"},
		{"wrong_hash", func(_ map[string]interface{}, digest *string) { *digest = strings.Repeat("0", 64) }, "does not attest"},
		{"wrong_profile", func(set map[string]interface{}, _ *string) {
			set["materialization_profile_version"] = "ood_graph_protocol_v1/materialization/6"
		}, "materialization_profile_version"},
		{"wrong_organization", func(set map[string]interface{}, _ *string) { set["organization_id"] = "org-other" }, "organization_id"},
		{"wrong_coordinate_count", func(set map[string]interface{}, _ *string) { set["coordinate_count"] = 2 }, "exact closed canonical rendering"},
		{"widened_top_level", func(set map[string]interface{}, _ *string) { set["payload"] = "forbidden" }, "exact closed canonical rendering"},
		{"widened_coordinate", func(set map[string]interface{}, _ *string) {
			set["coordinates"].([]interface{})[0].(map[string]interface{})["content"] = "forbidden"
		}, "exact closed canonical rendering"},
		{"missing_required_coordinate", func(set map[string]interface{}, _ *string) {
			delete(set["coordinates"].([]interface{})[0].(map[string]interface{}), "source_stable_reference")
		}, "source_stable_reference required"},
		{"arbitrary_content_hash", func(set map[string]interface{}, _ *string) {
			set["coordinates"].([]interface{})[0].(map[string]interface{})["source_content_hash"] = "caller-string"
		}, "source_content_hash"},
		{"half_symbol_coordinate", func(set map[string]interface{}, _ *string) {
			set["coordinates"].([]interface{})[0].(map[string]interface{})["symbol_kind"] = "api_symbol"
		}, "present together"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			set, digest := validStoredSourceSet(t)
			tc.mutate(set, &digest)
			err := ValidateMaterializationSourceSet("org-test", digest, set)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestSpannerMaterializationWriterRejectsLegacyOrMissingProfileBeforeIO(t *testing.T) {
	adapter := &SpannerSubstrateAdapter{Descriptor: SubstrateDescriptor{
		ID: "test", SnapshotTable: "OODGraphSnapshots", ObjectTable: "OODGraphObjects",
		SymbolTable: "OODGraphSymbols", GraphEdgeTable: "OODGraphEdges",
		MaterializationRunTable: "OODGraphMaterializationRuns", ViolationTable: "OODGraphViolations",
		ProjectionArtifactTable: "OODGraphProjectionArtifacts",
	}}
	for _, profile := range []interface{}{nil, "", "ood_graph_protocol_v1/materialization/5", "future/profile"} {
		t.Run(fmt.Sprint(profile), func(t *testing.T) {
			set := map[string]interface{}{
				"organization_id": "org-test", "coordinate_count": 0, "coordinates": []interface{}{},
			}
			if profile != nil {
				set["materialization_profile_version"] = profile
			}
			run := MaterializationRun{
				OrganizationID: "org-test", MaterializationRunID: "00000000-0000-0000-0000-000000000001",
				InputSourceSetHash: strings.Repeat("0", 64), InputSourceSet: set, State: "running",
			}
			err := adapter.OpenMaterializationRun(context.Background(), run)
			if err == nil || !strings.Contains(err.Error(), "is not writable") {
				t.Fatalf("profile=%#v got %v, want fail-closed profile error before credentials/database I/O", profile, err)
			}
		})
	}
}

// TestHandleImportOpensRunBeforeCommitting pins §8 stage 1. Before this,
// `State: "running"` existed only as an in-memory struct field and the run
// row was INSERTed once, already sealed — so a run that failed left no row,
// and abandoned_run_rule / failed_and_abandoned_run_rule quantified over
// rows that could never exist.
func TestHandleImportOpensRunBeforeCommitting(t *testing.T) {
	env, ra := newImportKindEnv(t)

	if _, err := handleImport(context.Background(), env, importInput{
		Submissions: []ArtifactSubmission{importSubmission("axiom", "an_axiom")},
	}); err != nil {
		t.Fatalf("handleImport: %v", err)
	}

	if len(ra.openedRuns) != 1 {
		t.Fatalf("OpenMaterializationRun called %d time(s); want exactly 1 — the run row must exist while the run is running", len(ra.openedRuns))
	}
	opened := ra.openedRuns[0]
	if opened.State != "running" {
		t.Errorf("run opened at state=%q; §8.open_materialization_run.initial_state is \"running\"", opened.State)
	}
	if opened.TargetGraphSnapshotID != "" {
		t.Errorf("run opened with target_graph_snapshot_id=%q; §8.open_materialization_run.target_graph_snapshot_id_initially_nullable is true", opened.TargetGraphSnapshotID)
	}
	if opened.FinishedAt != nil {
		t.Error("run opened with a non-nil finished_at; an unfinished run must not look selectable to §9.eligible_snapshot_predicate.finished_at_required_for_selected_run")
	}
	if opened.InputSourceSetHash == "" || opened.InputSourceSet == nil {
		t.Error("run opened without input_source_set_hash / input_source_set; §8.open_materialization_run requires both at open")
	}
	if len(ra.batches) != 1 {
		t.Fatalf("committed %d batches; want 1", len(ra.batches))
	}
	// The opened run and the committed batch must be the SAME run, or the
	// seal has no row to update and the audit trail forks.
	if ra.batches[0].Run.MaterializationRunID != opened.MaterializationRunID {
		t.Errorf("committed run id %q != opened run id %q", ra.batches[0].Run.MaterializationRunID, opened.MaterializationRunID)
	}
	if len(ra.failedRuns) != 0 {
		t.Errorf("a successful import marked %d run(s) failed; want 0", len(ra.failedRuns))
	}
}

// TestHandleImportSealsRealSourceSetHash pins that the hash reaching the
// substrate is the computed digest, and that snapshot and run agree on it —
// which is the pair §9.eligible_snapshot_predicate's
// source_set_hash_matches_run_input_source_set_hash actually compares.
func TestHandleImportSealsRealSourceSetHash(t *testing.T) {
	env, ra := newImportKindEnv(t)

	if _, err := handleImport(context.Background(), env, importInput{
		Submissions: []ArtifactSubmission{importSubmission("axiom", "an_axiom")},
	}); err != nil {
		t.Fatalf("handleImport: %v", err)
	}
	batch := ra.batches[0]

	if strings.HasPrefix(batch.Snapshot.SourceSetHash, "seed_nodes_import_") {
		t.Errorf("snapshot.source_set_hash is still the wall-clock literal %q", batch.Snapshot.SourceSetHash)
	}
	if len(batch.Snapshot.SourceSetHash) != 64 {
		t.Errorf("snapshot.source_set_hash = %q (%d chars); want a 64-char SHA-256 hex digest", batch.Snapshot.SourceSetHash, len(batch.Snapshot.SourceSetHash))
	}
	if batch.Snapshot.SourceSetHash != batch.Run.InputSourceSetHash {
		t.Errorf("snapshot.source_set_hash (%s) != run.input_source_set_hash (%s); §9.eligible_snapshot_predicate compares exactly this pair",
			batch.Snapshot.SourceSetHash, batch.Run.InputSourceSetHash)
	}
	// graph_version must NOT be minted by the caller: the substrate assigns
	// it monotonically inside the transaction after validation, per
	// §8.write_snapshot_row.graph_version_assignment. A wall-clock value
	// here is the race against UNIQUE (organization_id, graph_version).
	if batch.Snapshot.GraphVersion != 0 {
		t.Errorf("caller minted graph_version=%d; it must be assigned in-transaction after row validation, not by the handler", batch.Snapshot.GraphVersion)
	}
}

// failingCommitAdapter accepts the open, then refuses the commit — the
// crash-mid-run shape that previously left no evidence whatsoever.
type failingCommitAdapter struct {
	*recordingAdapter
	err error
}

func (f *failingCommitAdapter) CommitMaterializationRun(_ context.Context, b MaterializationBatch) error {
	f.batches = append(f.batches, b)
	return f.err
}

// TestHandleImportMarksRunFailedWhenCommitRefused pins the failure path.
// §8.idempotency_and_replay_safety.abandoned_run_rule says failed runs
// "remain audit-only state in OODGraphMaterializationRuns" — which requires
// something to actually write that state.
func TestHandleImportMarksRunFailedWhenCommitRefused(t *testing.T) {
	env, ra := newImportKindEnv(t)
	boom := errors.New("substrate refused the batch")
	fa := &failingCommitAdapter{recordingAdapter: ra, err: boom}
	env.Substrates = &recordingRouter{a: fa}

	_, err := handleImport(context.Background(), env, importInput{
		Submissions: []ArtifactSubmission{importSubmission("axiom", "an_axiom")},
	})
	if err == nil {
		t.Fatal("handleImport succeeded despite a refused commit")
	}
	if !errors.Is(err, boom) {
		t.Errorf("error does not wrap the substrate refusal; got: %v", err)
	}
	if len(ra.openedRuns) != 1 {
		t.Fatalf("OpenMaterializationRun called %d time(s); want 1", len(ra.openedRuns))
	}
	if len(ra.failedRuns) != 1 {
		t.Fatalf("FailMaterializationRun called %d time(s) after a refused commit; want 1 — otherwise the run row is stranded at state=running forever", len(ra.failedRuns))
	}
	if got, want := ra.failedRuns[0][1], ra.openedRuns[0].MaterializationRunID; got != want {
		t.Errorf("marked run %q failed but opened run %q", got, want)
	}
}
