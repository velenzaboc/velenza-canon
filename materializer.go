package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// oodGraphIDNamespace is the UUIDv5 namespace every deterministic OOD-graph
// identifier is minted under — graph_object_id, symbol_id, graph_edge_id,
// violation_id and the archive-audit ids alike.
//
// The literal is the OOD Graph Protocol's own doc_id. Keeping ONE namespace
// across all of them is what makes
// §8.canonical_source_intake.stable_identity_preservation's three
// stability rules composable: the same identity tuple yields the same id
// whichever code path mints it. A second namespace would silently fork
// identity for the same logical row, and because
// §8.idempotency_and_replay_safety.non_determinism_handling forbids random
// UUIDs in stable graph identity, the fork would not surface as a random
// value — it would surface as a stable id that simply never matches.
var oodGraphIDNamespace = uuid.MustParse("767c2399-87f9-4859-ac64-afb575bdb263")

// materializer.go implements the source-set, identity and run-lifecycle
// half of the OOD_GRAPH_PROTOCOL_v1 §8 materialization pipeline — the
// stages that decide WHAT a run is over and WHETHER two runs are the same
// run, as distinct from ood_substrate.go which decides how the resulting
// rows reach Spanner.
//
// The three contracts implemented here, and why each has teeth:
//
//   - §8.canonical_source_intake.source_set_contract — source_set_hash is
//     a SHA-256 over the ORDERED source coordinates. Before this file the
//     hash was a wall clock (`fmt.Sprintf("seed_nodes_import_%d",
//     now.UnixNano())`), which makes
//     §8.idempotency_and_replay_safety.idempotency_key — (organization_id,
//     input_source_set_hash, materialization_profile_version,
//     target_snapshot_kind) — incapable of ever matching across two runs.
//     With a wall clock in the key, safe_retry_rule is not merely
//     unimplemented, it is unimplementABLE: no retry can be recognised as a
//     retry. §9's eligible_snapshot_predicate clause
//     source_set_hash_matches_run_input_source_set_hash then passes only
//     vacuously, because both sides carry the same meaningless literal.
//
//   - §8.deterministic_parser_contract.deterministic_source_ordering — the
//     eleven-key total order. The hash is only reproducible if the sequence
//     it runs over is, and
//     §8.idempotency_and_replay_safety.non_determinism_handling sets
//     unordered_map_iteration_allowed=false.
//
//   - §8.materialization_pipeline.write_snapshot_row.graph_version_assignment
//     — "monotonic per organization_id after all row validation succeeds".
//     A wall-clock graph_version is not monotonic-by-contract, only
//     monotonic-by-luck, and it races the UNIQUE
//     OODGraphSnapshotsByVersion (organization_id, graph_version) index
//     under any concurrency.

// MaterializationProfileVersion names the materialization contract
// implementation that produced a snapshot.
//
// It is BOTH a source_set_hash input
// (§8.canonical_source_intake.source_set_contract.source_set_hash_inputs
// lists materialization_profile_version last) AND a member of the
// idempotency key (§8.idempotency_and_replay_safety.idempotency_key). That
// dual role is deliberate: when the pipeline's own semantics change, runs
// over a byte-identical source set MUST NOT be mistaken for replays of each
// other, because they would not produce equivalent snapshots. Bump this
// literal whenever a change alters what rows a given source set yields.
const MaterializationProfileVersion = "ood_graph_protocol_v1/materialization/9"

const externalVerificationReceiptsSourceSetKey = "external_verification_receipts"

// Spanner's JSON value limit is 10 MiB. Use a lower compact-canonical ceiling
// so normalization/accounting differences cannot turn a locally accepted
// source_set into a late Spanner rejection. This is a bootstrap safety bound,
// not the exhaustive-corpus architecture: large source sets require normalized
// immutable coordinate/receipt rows plus a compact manifest/head.
const maxMaterializationSourceSetCanonicalBytes = 9 * 1024 * 1024

// SourceCoordinate is one element of a run's ordered source set.
//
// It carries source-artifact IDENTITY only — never source payload, per
// §8.canonical_source_intake.source_set_contract.copied_source_payload_allowed
// = false and the parser_must_not clause forbidding copied sibling content.
//
// The field set is the union of two different spec lists, which is why it
// is wider than the hash:
//
//   - the eleven ORDERING keys of
//     §8.deterministic_parser_contract.deterministic_source_ordering, which
//     fix the sequence; and
//   - the five per-element HASH inputs of source_set_hash_inputs, which are
//     the only fields whose VALUES reach the digest.
//
// Fields that order but do not hash (section_path, symbol_kind, symbol_name,
// edge_label, authoring_source_path, source_artifact_class, source_ref_kind)
// are not redundant: they make the order total, and a non-total order makes
// the digest depend on input arrival order.
type SourceCoordinate struct {
	OrganizationID        string `json:"organization_id"`
	SourceAuthorityID     string `json:"source_authority_id"`
	SourceArtifactClass   string `json:"source_artifact_class"`
	SourceRefKind         string `json:"source_ref_kind"`
	SourceStableReference string `json:"source_stable_reference"`
	VersionCoordinate     string `json:"version_coordinate"`
	SectionPath           string `json:"section_path"`
	SymbolKind            string `json:"symbol_kind"`
	SymbolName            string `json:"symbol_name"`
	EdgeLabel             string `json:"edge_label"`
	AuthoringSourcePath   string `json:"authoring_source_path"`

	// SourceContentHash is source-OWNED content identity evidence, carried
	// through verbatim. §8.validation_gates_before_projection
	// .content_hash_binding_gate sets ood_graph_recomputes_docobject_content_hash
	// = false and content_hash_replaces_identity = false — the graph never
	// computes this value and never lets it stand in for identity. Empty
	// means the source authority does not expose one.
	SourceContentHash string `json:"source_content_hash,omitempty"`
}

// compareSourceCoordinates implements the total order of
// §8.deterministic_parser_contract.deterministic_source_ordering, applying
// its eleven keys in the exact sequence the spec lists them. Returns -1, 0
// or +1.
//
// The order is applied as written rather than as a single concatenated sort
// key: concatenation would let a separator character inside one field
// impersonate a field boundary and silently reorder two coordinates.
func compareSourceCoordinates(a, b SourceCoordinate) int {
	pairs := [][2]string{
		{a.OrganizationID, b.OrganizationID},
		{a.SourceAuthorityID, b.SourceAuthorityID},
		{a.SourceArtifactClass, b.SourceArtifactClass},
		{a.SourceRefKind, b.SourceRefKind},
		{a.SourceStableReference, b.SourceStableReference},
		{a.VersionCoordinate, b.VersionCoordinate},
		{a.SectionPath, b.SectionPath},
		{a.SymbolKind, b.SymbolKind},
		{a.SymbolName, b.SymbolName},
		{a.EdgeLabel, b.EdgeLabel},
		{a.AuthoringSourcePath, b.AuthoringSourcePath},
	}
	for _, p := range pairs {
		if p[0] < p[1] {
			return -1
		}
		if p[0] > p[1] {
			return 1
		}
	}
	return 0
}

// SortSourceCoordinates returns a NEW slice ordered per
// §8.deterministic_parser_contract.deterministic_source_ordering. The input
// is not mutated, so a caller may keep its own arrival-order copy for
// diagnostics.
//
// sort.SliceStable is used rather than sort.Slice so that two coordinates
// that compare equal on all eleven keys keep their relative arrival order
// instead of being permuted arbitrarily. Such a pair is a duplicate source
// coordinate and is a caller defect, but a stable sort makes the resulting
// hash reproducible anyway rather than making the bug intermittent.
func SortSourceCoordinates(in []SourceCoordinate) []SourceCoordinate {
	out := make([]SourceCoordinate, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		return compareSourceCoordinates(out[i], out[j]) < 0
	})
	return out
}

// BuildSourceSet renders the ordered source set as the JSON value stored in
// BOTH OODGraphSnapshots.source_set and
// OODGraphMaterializationRuns.input_source_set, per
// §8.canonical_source_intake.source_set_contract.source_set_stored_in.
//
// The two columns take the SAME value so that
// §9.active_snapshot_selection.eligible_snapshot_predicate's
// source_set_hash_matches_run_input_source_set_hash is a real check against
// a real pair, not a tautology over two copies of a wall clock.
//
// The stored shape carries the ordered coordinates themselves, not a
// summary. The prior `{"object_count":N,"symbol_count":M}` shape cannot
// satisfy
// §8.snapshot_production_contract.historical_reproducibility ("A sealed
// snapshot remains reproducible from its source_set_hash, source_set,
// materialization_run_id, projection_hashes, and graph-owned identity
// tuples") because two counts do not name which sources were read.
func BuildSourceSet(orgID string, coords []SourceCoordinate) map[string]interface{} {
	ordered := SortSourceCoordinates(coords)
	items := make([]interface{}, 0, len(ordered))
	for _, c := range ordered {
		item := map[string]interface{}{
			"source_authority_id":     c.SourceAuthorityID,
			"source_artifact_class":   c.SourceArtifactClass,
			"source_ref_kind":         c.SourceRefKind,
			"source_stable_reference": c.SourceStableReference,
			"version_coordinate":      c.VersionCoordinate,
			"section_path":            c.SectionPath,
		}
		// Optional discriminators are omitted rather than emitted empty so
		// an object-only source set does not carry dead symbol/edge keys.
		if c.SymbolKind != "" {
			item["symbol_kind"] = c.SymbolKind
		}
		if c.SymbolName != "" {
			item["symbol_name"] = c.SymbolName
		}
		if c.EdgeLabel != "" {
			item["edge_label"] = c.EdgeLabel
		}
		if c.AuthoringSourcePath != "" {
			item["authoring_source_path"] = c.AuthoringSourcePath
		}
		if c.SourceContentHash != "" {
			item["source_content_hash"] = c.SourceContentHash
		}
		items = append(items, item)
	}
	return map[string]interface{}{
		"organization_id":                 orgID,
		"materialization_profile_version": MaterializationProfileVersion,
		"coordinate_count":                len(items),
		"coordinates":                     items,
	}
}

// BuildSourceSetWithExternalReceipts adds body-free, run-occurrence evidence
// to the stored source set without widening ComputeSourceSetHash. The OOD
// idempotency key is semantic source identity+digest; retrieved_at and HTTP
// representation metadata describe this verification occurrence and may
// legitimately change when the exact bytes are re-attested later.
func BuildSourceSetWithExternalReceipts(orgID string, coords []SourceCoordinate, receipts []*stagedExternalVerificationReceipt) (map[string]interface{}, error) {
	set := BuildSourceSet(orgID, coords)
	if len(receipts) != 0 {
		ordered, err := canonicalExternalVerificationReceiptValues(receipts)
		if err != nil {
			return nil, err
		}
		set[externalVerificationReceiptsSourceSetKey] = ordered
	}
	if err := validateMaterializationSourceSetStorageBound(set); err != nil {
		return nil, err
	}
	return set, nil
}

func validateMaterializationSourceSetStorageBound(sourceSet map[string]interface{}) error {
	canonical, err := canonicalJSON(sourceSet)
	if err != nil {
		return fmt.Errorf("canonical materialization source_set: %w", err)
	}
	if len(canonical) > maxMaterializationSourceSetCanonicalBytes {
		return fmt.Errorf("%w: source_set canonical bytes=%d exceeds bootstrap ceiling=%d below Spanner's 10 MiB JSON-cell limit; use normalized manifest rows", ErrOODGraphMaterializationScaleUnrepresentable, len(canonical), maxMaterializationSourceSetCanonicalBytes)
	}
	return nil
}

func canonicalExternalVerificationReceiptValues(receipts []*stagedExternalVerificationReceipt) ([]interface{}, error) {
	clones := make([]*stagedExternalVerificationReceipt, len(receipts))
	seen := make(map[string]struct{}, len(receipts))
	for i, receipt := range receipts {
		if err := validateStoredExternalVerificationReceiptShape(receipt); err != nil {
			return nil, fmt.Errorf("external verification receipt[%d]: %w", i, err)
		}
		key := externalVerificationReceiptSemanticKey(receipt)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("external verification receipts contain duplicate semantic coordinate %q", receipt.VerifiedSourceStableReference)
		}
		seen[key] = struct{}{}
		clone := *receipt
		clones[i] = &clone
	}
	sort.Slice(clones, func(i, j int) bool {
		left, right := externalVerificationReceiptSemanticKey(clones[i]), externalVerificationReceiptSemanticKey(clones[j])
		if left != right {
			return left < right
		}
		return clones[i].RetrievedAt < clones[j].RetrievedAt
	})
	values := make([]interface{}, 0, len(clones))
	for _, receipt := range clones {
		raw, err := json.Marshal(receipt)
		if err != nil {
			return nil, fmt.Errorf("encode external verification receipt: %w", err)
		}
		var value interface{}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("normalize external verification receipt: %w", err)
		}
		values = append(values, value)
	}
	return values, nil
}

func externalVerificationReceiptSemanticKey(receipt *stagedExternalVerificationReceipt) string {
	if receipt == nil {
		return ""
	}
	return framedIdentity(receipt.ObjectClass, receipt.SourceAuthorityID, receipt.VerifiedSourceStableReference, receipt.FinalVersionCoordinate, receipt.DecodedSHA256)
}

func externalVerificationReceiptObjectKey(object GraphObject) string {
	return framedIdentity(object.ObjectClass, object.SourceAuthorityID, object.SourceStableReference, object.VersionCoordinate, object.SourceContentHash)
}

func compactExternalVerificationReceipts(receipts []*stagedExternalVerificationReceipt) []*stagedExternalVerificationReceipt {
	out := make([]*stagedExternalVerificationReceipt, 0, len(receipts))
	for _, receipt := range receipts {
		if receipt == nil {
			continue
		}
		clone := *receipt
		out = append(out, &clone)
	}
	return out
}

func validateStoredExternalVerificationReceiptShape(receipt *stagedExternalVerificationReceipt) error {
	if receipt == nil {
		return fmt.Errorf("receipt is nil")
	}
	if receipt.ReceiptVersion != stagedExternalReceiptVersion {
		return fmt.Errorf("receipt_version=%q, want %q", receipt.ReceiptVersion, stagedExternalReceiptVersion)
	}
	for name, value := range map[string]string{
		"canonical_reference": receipt.CanonicalReference, "verified_source_stable_reference": receipt.VerifiedSourceStableReference,
		"observed_at": receipt.RetrievedAt, "transport_raw_content_hash": receipt.SHA256,
		"transport_status": receipt.TransportStatus, "transport_raw_content_hash_algorithm": receipt.TransportRawHashAlgorithm,
		"transport_content_encoding": receipt.ContentCoding, "transport_response_metadata_digest": receipt.TransportResponseMetadataDigest,
		"source_content_hash": receipt.DecodedSHA256, "source_content_hash_algorithm": receipt.SourceContentHashAlgorithm,
		"source_content_hash_profile": receipt.SourceContentHashProfile, "source_registry_id": receipt.SourceRegistryID,
		"source_authority_id": receipt.SourceAuthorityID, "policy_fingerprint": receipt.PolicyFingerprint,
		"object_class": receipt.ObjectClass, "canonical_name": receipt.CanonicalName,
		"locator_kind": receipt.LocatorKind, "final_version_coordinate": receipt.FinalVersionCoordinate,
	} {
		if value == "" || strings.TrimSpace(value) != value {
			return fmt.Errorf("%s is empty or non-canonical", name)
		}
	}
	if _, err := parseCanonicalHTTPSReference(receipt.CanonicalReference); err != nil {
		return fmt.Errorf("canonical_reference: %w", err)
	}
	if _, err := parseCanonicalHTTPSReference(receipt.VerifiedSourceStableReference); err != nil {
		return fmt.Errorf("verified_source_stable_reference: %w", err)
	}
	if err := ValidateUUID(receipt.SourceAuthorityID); err != nil {
		return fmt.Errorf("source_authority_id: %w", err)
	}
	if !snakeCaseKeyPattern.MatchString(receipt.CanonicalName) || !snakeCaseKeyPattern.MatchString(receipt.ObjectClass) {
		return fmt.Errorf("object_class or canonical_name is not lowercase snake_case")
	}
	if parsed, err := ParseVersionCoordinate(receipt.FinalVersionCoordinate); err != nil || parsed.String() != receipt.FinalVersionCoordinate {
		return fmt.Errorf("final_version_coordinate is not canonical: %w", err)
	}
	retrievedAt, err := time.Parse(time.RFC3339Nano, receipt.RetrievedAt)
	if err != nil || retrievedAt.UTC().Format(time.RFC3339Nano) != receipt.RetrievedAt {
		return fmt.Errorf("observed_at is not canonical UTC RFC3339: %w", err)
	}
	if receipt.ByteLength < 0 || receipt.DecodedByteLength < 0 {
		return fmt.Errorf("byte lengths must be nonnegative")
	}
	if err := validateExternalContentHash("sha256", receipt.SHA256); err != nil {
		return fmt.Errorf("sha256: %w", err)
	}
	if receipt.TransportStatus != "success" || receipt.TransportRawHashAlgorithm != "sha256" {
		return fmt.Errorf("transport status or raw content hash algorithm is outside the closed receipt contract")
	}
	if err := validateExternalContentHash("sha256", receipt.TransportResponseMetadataDigest); err != nil {
		return fmt.Errorf("transport_response_metadata_digest: %w", err)
	}
	if err := validateExternalContentHash("sha256", receipt.DecodedSHA256); err != nil {
		return fmt.Errorf("decoded_sha256: %w", err)
	}
	if receipt.ContentCoding != "identity" && receipt.ContentCoding != "gzip" {
		return fmt.Errorf("content_coding is outside identity|gzip")
	}
	if receipt.ContentCoding == "identity" && (receipt.ByteLength != receipt.DecodedByteLength || receipt.SHA256 != receipt.DecodedSHA256) {
		return fmt.Errorf("identity-coded raw and decoded evidence diverge")
	}
	request := externalSourceAuthorizationRequest{
		OrganizationID:        receipt.Authorization.OrganizationID,
		ObjectClass:           receipt.ObjectClass,
		SourceRegistryID:      receipt.SourceRegistryID,
		SourceArtifactClass:   receipt.Authorization.SourceArtifactClass,
		SourceAuthorityID:     receipt.SourceAuthorityID,
		SourceRefKind:         receipt.Authorization.SourceRefKind,
		SourceStableReference: receipt.VerifiedSourceStableReference,
		PermissionOperation:   externalFetchPermissionOperation,
		PermissionMethod:      "GET",
		ObservedAt:            retrievedAt,
	}
	if err := validateExternalSourceAuthorization(request, receipt.Authorization); err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if receipt.SourceContentHashAlgorithm != "sha256" || receipt.SourceContentHashProfile != receipt.Authorization.SourceContentHashProfile {
		return fmt.Errorf("canonical source hash contract does not match authorization")
	}
	if receipt.Authorization.SourceRepresentationMediaType != "" && receipt.SourceRepresentationMediaType != receipt.Authorization.SourceRepresentationMediaType {
		return fmt.Errorf("source representation media type does not match authorization")
	}
	if receipt.Archive != nil {
		if err := requireArchivedExternalEvidence(receipt); err != nil {
			return err
		}
	} else if receipt.Authorization.BodyCustodyDisposition == externalBodyCustodyAGFS {
		return fmt.Errorf("exact_agfs_body_custody receipt is missing its archive binding")
	}
	upstreamFields := 0
	for _, value := range []string{receipt.UpstreamVersionEvidenceKind, receipt.UpstreamVersionEvidence, receipt.UpstreamVersionToken} {
		if value != "" {
			upstreamFields++
		}
	}
	if upstreamFields != 0 && upstreamFields != 3 {
		return fmt.Errorf("upstream version evidence fields must be all present or all absent")
	}
	return nil
}

// ExternalVerificationReceiptsFromStoredSet decodes the occurrence receipts
// carried by a current-profile source_set. Full policy/row binding is checked
// by the complete-materialization validator, which has the admitted source
// and node-kind registries.
func ExternalVerificationReceiptsFromStoredSet(sourceSet map[string]interface{}) ([]*stagedExternalVerificationReceipt, error) {
	raw, present := sourceSet[externalVerificationReceiptsSourceSetKey]
	if !present {
		return nil, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("source_set.%s has type %T, want array", externalVerificationReceiptsSourceSetKey, raw)
	}
	receipts := make([]*stagedExternalVerificationReceipt, 0, len(items))
	for i, item := range items {
		receipt, err := stagedExternalReceiptFromJSON(item)
		if err != nil {
			return nil, fmt.Errorf("source_set.%s[%d]: %w", externalVerificationReceiptsSourceSetKey, i, err)
		}
		if err := validateStoredExternalVerificationReceiptShape(receipt); err != nil {
			return nil, fmt.Errorf("source_set.%s[%d]: %w", externalVerificationReceiptsSourceSetKey, i, err)
		}
		receipts = append(receipts, receipt)
	}
	return receipts, nil
}

// MergeSourceCoordinates returns the deterministic set union of source
// coordinates. SourceCoordinate contains strings only and is therefore a
// safe comparable key. Exact duplicate inputs must not multiply the four
// hash projections merely because one came from the carried snapshot and
// one from the current delta.
func MergeSourceCoordinates(groups ...[]SourceCoordinate) []SourceCoordinate {
	seen := make(map[SourceCoordinate]struct{})
	var out []SourceCoordinate
	for _, group := range groups {
		for _, coordinate := range group {
			if _, duplicate := seen[coordinate]; duplicate {
				continue
			}
			seen[coordinate] = struct{}{}
			out = append(out, coordinate)
		}
	}
	return SortSourceCoordinates(out)
}

// SourceCoordinatesFromStoredSet decodes the canonical shape emitted by
// BuildSourceSet. It is used only to preserve non-object materialization
// inputs (for example a public spec_graph_link edge coordinate) across a
// complete successor snapshot. Current-profile source sets are decoded
// strictly; legacy profiles without this shape are reconstructed from rows.
func SourceCoordinatesFromStoredSet(orgID string, sourceSet map[string]interface{}) ([]SourceCoordinate, error) {
	storedOrg, _ := sourceSet["organization_id"].(string)
	if storedOrg != orgID {
		return nil, fmt.Errorf("stored source_set organization_id=%q, want %q", storedOrg, orgID)
	}
	rawCoordinates, ok := sourceSet["coordinates"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("stored source_set.coordinates has type %T, want array", sourceSet["coordinates"])
	}
	coords := make([]SourceCoordinate, 0, len(rawCoordinates))
	for i, raw := range rawCoordinates {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("stored source_set.coordinates[%d] has type %T, want object", i, raw)
		}
		get := func(name string) string {
			value, _ := m[name].(string)
			return value
		}
		coordinate := SourceCoordinate{
			OrganizationID: orgID, SourceAuthorityID: get("source_authority_id"),
			SourceArtifactClass: get("source_artifact_class"), SourceRefKind: get("source_ref_kind"),
			SourceStableReference: get("source_stable_reference"), VersionCoordinate: get("version_coordinate"),
			SectionPath: get("section_path"), SymbolKind: get("symbol_kind"), SymbolName: get("symbol_name"),
			EdgeLabel: get("edge_label"), AuthoringSourcePath: get("authoring_source_path"),
			SourceContentHash: get("source_content_hash"),
		}
		for name, value := range map[string]string{
			"source_authority_id": coordinate.SourceAuthorityID, "source_artifact_class": coordinate.SourceArtifactClass,
			"source_ref_kind": coordinate.SourceRefKind, "source_stable_reference": coordinate.SourceStableReference,
			"version_coordinate": coordinate.VersionCoordinate, "section_path": coordinate.SectionPath,
		} {
			if value == "" {
				return nil, fmt.Errorf("stored source_set.coordinates[%d].%s required", i, name)
			}
		}
		contentHashOwner := ""
		if coordinate.SourceContentHash != "" {
			// The source-set contract intentionally stores the digest but not a
			// second copy of its owner. Graph rows prove the owner; at the source-
			// set boundary a present digest is therefore checked as authority-owned.
			contentHashOwner = coordinate.SourceAuthorityID
		}
		if err := validateSourceIdentity(
			coordinate.SourceAuthorityID,
			coordinate.SourceArtifactClass,
			coordinate.SourceRefKind,
			coordinate.SourceStableReference,
			coordinate.VersionCoordinate,
			coordinate.SectionPath,
			coordinate.SourceContentHash,
			contentHashOwner,
		); err != nil {
			return nil, fmt.Errorf("stored source_set.coordinates[%d]: %w", i, err)
		}
		if (coordinate.SymbolKind == "") != (coordinate.SymbolName == "") {
			return nil, fmt.Errorf("stored source_set.coordinates[%d] symbol_kind and symbol_name must be present together", i)
		}
		if coordinate.SymbolKind != "" && (!snakeCaseKeyPattern.MatchString(coordinate.SymbolKind) || len(coordinate.SymbolKind) > 64 || len(coordinate.SymbolName) > 1024) {
			return nil, fmt.Errorf("stored source_set.coordinates[%d] symbol coordinate is non-canonical or oversized", i)
		}
		if coordinate.EdgeLabel != "" && (!snakeCaseKeyPattern.MatchString(coordinate.EdgeLabel) || len(coordinate.EdgeLabel) > 64) {
			return nil, fmt.Errorf("stored source_set.coordinates[%d].edge_label is non-canonical or oversized", i)
		}
		if coordinate.AuthoringSourcePath != "" {
			if err := ValidateSectionPath(coordinate.AuthoringSourcePath); err != nil || len(coordinate.AuthoringSourcePath) > 2048 {
				return nil, fmt.Errorf("stored source_set.coordinates[%d].authoring_source_path is invalid or oversized: %w", i, err)
			}
		}
		coords = append(coords, coordinate)
	}
	return coords, nil
}

// ValidateMaterializationSourceSet proves that the stored source_set is the
// exact canonical current-profile rendering of its coordinates and that hash is
// the protocol SHA-256 over those inputs. This is a substrate-boundary gate,
// not merely a handler convenience: an alternate caller cannot seal a
// plausible-looking 64-character digest over a different or widened JSON
// shape.
func ValidateMaterializationSourceSet(orgID, sourceSetHash string, sourceSet map[string]interface{}) error {
	if err := validateExternalContentHash("sha256", sourceSetHash); err != nil {
		return fmt.Errorf("source_set_hash: %w", err)
	}
	if sourceSet == nil {
		return fmt.Errorf("source_set is required")
	}
	profile, _ := sourceSet["materialization_profile_version"].(string)
	if profile != MaterializationProfileVersion {
		return fmt.Errorf("source_set materialization_profile_version=%q, want %q", profile, MaterializationProfileVersion)
	}
	coordinates, err := SourceCoordinatesFromStoredSet(orgID, sourceSet)
	if err != nil {
		return err
	}
	receipts, err := ExternalVerificationReceiptsFromStoredSet(sourceSet)
	if err != nil {
		return err
	}
	expectedSet, err := BuildSourceSetWithExternalReceipts(orgID, coordinates, receipts)
	if err != nil {
		return err
	}
	actualCanonical, err := canonicalJSON(sourceSet)
	if err != nil {
		return fmt.Errorf("canonical stored source_set: %w", err)
	}
	expectedCanonical, err := canonicalJSON(expectedSet)
	if err != nil {
		return fmt.Errorf("canonical expected source_set: %w", err)
	}
	if string(actualCanonical) != string(expectedCanonical) {
		return fmt.Errorf("source_set is not the exact closed canonical rendering of its ordered coordinates")
	}
	expectedHash, err := ComputeSourceSetHash(orgID, coordinates)
	if err != nil {
		return err
	}
	if sourceSetHash != expectedHash {
		return fmt.Errorf("source_set_hash=%q does not attest source_set (want %q)", sourceSetHash, expectedHash)
	}
	return nil
}

// ComputeSourceSetHash returns the lowercase-hex SHA-256 required by
// §8.canonical_source_intake.source_set_contract.source_set_hash_algorithm
// ("SHA-256 over canonical JSON serialization with sorted object keys and
// array order defined by deterministic_source_ordering").
//
// The digest input is exactly the closed six-item
// source_set_hash_inputs contract: organization_id, the four ordered source
// projections, and materialization_profile_version. Ordering-only parser
// discriminators remain in the stored source_set but do not widen the digest
// contract. Output drift under an unchanged input key is detected by the
// replay-output comparison at commit; it is never hidden by changing the
// meaning of source_set_hash.
func ComputeSourceSetHash(orgID string, coords []SourceCoordinate) (string, error) {
	ordered := SortSourceCoordinates(coords)
	authorities := make([]interface{}, 0, len(ordered))
	references := make([]interface{}, 0, len(ordered))
	versions := make([]interface{}, 0, len(ordered))
	contentHashes := make([]interface{}, 0, len(ordered))
	for _, c := range ordered {
		authorities = append(authorities, c.SourceAuthorityID)
		references = append(references, c.SourceStableReference)
		versions = append(versions, c.VersionCoordinate)
		contentHashes = append(contentHashes, c.SourceContentHash)
	}
	digestInput := map[string]interface{}{
		"organization_id":                 orgID,
		"source_authority_id":             authorities,
		"source_stable_reference":         references,
		"version_coordinate":              versions,
		"source_content_hash":             contentHashes,
		"materialization_profile_version": MaterializationProfileVersion,
	}
	b, err := canonicalJSON(digestInput)
	if err != nil {
		return "", fmt.Errorf("canonical JSON for source_set_hash: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// SourceCoordinatesFromArtifacts renders the resolved parser inputs used by
// one import. It deliberately emits one coordinate per source artifact
// submission. Symbols and edges are materializer outputs and therefore never
// participate in the idempotency input key.
func SourceCoordinatesFromArtifacts(orgID string, artifacts []ArtifactSourceCoordinate) []SourceCoordinate {
	coords := make([]SourceCoordinate, 0, len(artifacts))
	for _, source := range artifacts {
		coords = append(coords, SourceCoordinate{
			OrganizationID:        orgID,
			SourceAuthorityID:     source.SourceAuthorityID,
			SourceArtifactClass:   source.SourceArtifactClass,
			SourceRefKind:         source.SourceRefKind,
			SourceStableReference: source.SourceStableReference,
			VersionCoordinate:     source.VersionCoordinate,
			SectionPath:           source.SectionPath,
			SourceContentHash:     source.SourceContentHash,
		})
	}
	return coords
}

// SourceCoordinatesFromRows derives the run's source set from the rows the
// run is about to write.
//
// Direction matters and is easy to get backwards: the source set is
// logically the INPUT and the rows the OUTPUT, so deriving one from the
// other looks circular. It is not, because every field consumed here is a
// graph-owned copy of a SOURCE coordinate (source_authority_id,
// source_stable_reference, version_coordinate, section_path,
// source_content_hash) that materialization carried through verbatim rather
// than minted — §9.temporal_state_model.version_coordinate calls
// version_coordinate "source artifact version coordinate copied as
// graph-owned temporal metadata during materialization", and
// content_hash_binding_gate forbids the graph recomputing the content hash.
// Reading them back off the rows recovers the same coordinates the parser
// consumed.
//
// What this does NOT do is stand in for stage 2 resolve_source_set. A real
// resolve_source_set enumerates source artifacts BEFORE parsing and can
// therefore notice a source that yielded no row at all. That stage is not
// implemented; this function makes the hash and the stored source set
// honest for the rows that were produced, and a source that produced
// nothing is invisible to it. That limitation is deliberate and recorded
// rather than hidden behind a name like ResolveSourceSet.
func SourceCoordinatesFromRows(objects []GraphObject, symbols []GraphSymbol, edges []GraphEdge) ([]SourceCoordinate, error) {
	coords := make([]SourceCoordinate, 0, len(objects)+len(symbols)+len(edges))
	objectsByID := make(map[string]GraphObject, len(objects))
	for _, o := range objects {
		if _, duplicate := objectsByID[o.GraphObjectID]; duplicate {
			return nil, fmt.Errorf("duplicate graph_object_id=%q while deriving source set", o.GraphObjectID)
		}
		objectsByID[o.GraphObjectID] = o
		coords = append(coords, SourceCoordinate{
			OrganizationID:        o.OrganizationID,
			SourceAuthorityID:     o.SourceAuthorityID,
			SourceArtifactClass:   o.SourceArtifactClass,
			SourceRefKind:         o.SourceRefKind,
			SourceStableReference: o.SourceStableReference,
			VersionCoordinate:     o.VersionCoordinate,
			SectionPath:           o.SectionPath,
			SourceContentHash:     o.SourceContentHash,
		})
	}
	symbolsByID := make(map[string]GraphSymbol, len(symbols))
	for _, s := range symbols {
		if _, duplicate := symbolsByID[s.SymbolID]; duplicate {
			return nil, fmt.Errorf("duplicate symbol_id=%q while deriving source set", s.SymbolID)
		}
		symbolsByID[s.SymbolID] = s
		// OODGraphSymbols does not physically duplicate source_ref_kind;
		// its canonical graph_address does. Recover the kind from that
		// address so a coordinate-backed external source is not rewritten
		// as the bootstrap "name" family in the sealed source_set. An
		// unparseable address is refused: silently substituting "name" would
		// make the sealed source_set disagree with the row it attests.
		ga, err := ParseGraphAddress(s.GraphAddress)
		if err != nil {
			return nil, fmt.Errorf("symbol_id=%q has non-canonical graph_address: %w", s.SymbolID, err)
		}
		if ga.String() != s.GraphAddress {
			return nil, fmt.Errorf("symbol_id=%q graph_address failed canonical round trip", s.SymbolID)
		}
		refKind := ga.SourceRefKind
		coords = append(coords, SourceCoordinate{
			OrganizationID:        s.OrganizationID,
			SourceAuthorityID:     s.SourceAuthorityID,
			SourceArtifactClass:   s.ObjectClass,
			SourceRefKind:         refKind,
			SourceStableReference: s.SourceStableReference,
			VersionCoordinate:     s.VersionCoordinate,
			SectionPath:           s.SectionPath,
			SymbolKind:            s.SymbolKind,
			SymbolName:            s.SymbolName,
		})
	}
	for _, e := range edges {
		var sourceObject GraphObject
		sourceSectionPath := ""
		switch e.SourceEndpointKind {
		case "graph_object":
			var ok bool
			sourceObject, ok = objectsByID[e.SourceEndpointID]
			if !ok {
				return nil, fmt.Errorf("graph_edge_id=%q source graph_object_id=%q is not present in the materialization batch", e.GraphEdgeID, e.SourceEndpointID)
			}
			sourceSectionPath = sourceObject.SectionPath
		case "symbol":
			sourceSymbol, ok := symbolsByID[e.SourceEndpointID]
			if !ok {
				return nil, fmt.Errorf("graph_edge_id=%q source symbol_id=%q is not present in the materialization batch", e.GraphEdgeID, e.SourceEndpointID)
			}
			var parentFound bool
			sourceObject, parentFound = objectsByID[sourceSymbol.GraphObjectID]
			if !parentFound {
				return nil, fmt.Errorf("graph_edge_id=%q source symbol_id=%q parent graph_object_id=%q is not present in the materialization batch", e.GraphEdgeID, e.SourceEndpointID, sourceSymbol.GraphObjectID)
			}
			sourceSectionPath = sourceSymbol.SectionPath
		default:
			return nil, fmt.Errorf("graph_edge_id=%q source_endpoint_kind=%q is not graph_object or symbol", e.GraphEdgeID, e.SourceEndpointKind)
		}
		if e.SourceAuthorityID != sourceObject.SourceAuthorityID ||
			e.SourceStableReference != sourceObject.SourceStableReference ||
			e.SourceVersionCoordinate != sourceObject.VersionCoordinate ||
			e.SourceContentHash != sourceObject.SourceContentHash {
			return nil, fmt.Errorf("graph_edge_id=%q source evidence does not match its resolved source endpoint", e.GraphEdgeID)
		}
		coords = append(coords, SourceCoordinate{
			OrganizationID:        e.OrganizationID,
			SourceAuthorityID:     sourceObject.SourceAuthorityID,
			SourceArtifactClass:   sourceObject.SourceArtifactClass,
			SourceRefKind:         sourceObject.SourceRefKind,
			SourceStableReference: sourceObject.SourceStableReference,
			VersionCoordinate:     sourceObject.VersionCoordinate,
			SectionPath:           sourceSectionPath,
			EdgeLabel:             e.EdgeLabel,
			AuthoringSourcePath:   e.AuthoringSourcePath,
			SourceContentHash:     sourceObject.SourceContentHash,
		})
	}
	return coords, nil
}
