package oodpublication

// This file owns the physical immutable-row boundary.  It is intentionally
// separate from oodcanon: a graph-row digest has the profile named by its
// owning contract, whereas these bytes bind an already typed physical row to
// the verified publication roster.  In particular, it never falls back to
// map iteration, fmt, JSON marshaling, or a caller supplied encoder.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

var ErrImmutablePhysicalRow = errors.New("oodpublication: invalid immutable physical row")

// ImmutablePhysicalRow is the only builder result.  Its slices and map are
// detached from the input; callers cannot change the row after its roster
// bytes and digest have been bound.
type ImmutablePhysicalRow struct {
	row   SpannerRow
	bytes []byte
	hash  [32]byte
	key   string
}

func (r ImmutablePhysicalRow) Row() SpannerRow  { return cloneImmutableSpannerRow(r.row) }
func (r ImmutablePhysicalRow) Bytes() []byte    { return append([]byte(nil), r.bytes...) }
func (r ImmutablePhysicalRow) SHA256() [32]byte { return r.hash }
func (r ImmutablePhysicalRow) Key() string      { return r.key }

// CanonicalJSON is an already owner-canonical JSON scalar. The codec never
// marshals Go maps, so it cannot create ordering or default authority.
type CanonicalJSON []byte

// CanonicalMemberDigest is deliberately separate from SHA256(): it derives a
// manifest member only through an owner-pinned OOD canonical profile.  The
// physical row codec cannot authorize a replacement graph_row_hash/profile.
func CanonicalMemberDigest(profile string, record oodcanon.RecordValue) (string, error) {
	p, err := oodcanon.ProfileFor(profile)
	if err != nil {
		return "", fmt.Errorf("%w: member profile %q: %v", ErrImmutablePhysicalRow, profile, err)
	}
	return oodcanon.DigestHexOf(p, record)
}

type physicalContract struct{ keys, columns []string }

// ImmutablePhysicalColumnNames exposes the owner-pinned physical read roster
// for same-transaction hydrators. Both results are defensive copies; callers
// cannot alter codec admission by retaining or editing them.
func ImmutablePhysicalColumnNames(table string) (keys, columns []string, err error) {
	c, ok := immutablePhysicalContracts[table]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s is not an admitted immutable table", ErrImmutablePhysicalRow, table)
	}
	return append([]string(nil), c.keys...), append([]string(nil), c.columns...), nil
}

// Physical rosters are owner-v8 field order, not alphabetical order.  The
// compact declaration is deliberately code, not an external schema reader:
// executable publication must not silently follow an unpinned DDL file.
var immutablePhysicalContracts = map[string]physicalContract{
	"OODGraphObjects":                          c("organization_id graph_object_id", "organization_id graph_object_id object_class api_element_role api_element_role_locator_manifest_hash source_authority_id source_artifact_class source_ref_kind source_stable_reference version_coordinate section_path graph_address source_content_hash_algorithm source_content_hash_profile source_content_hash source_stable_reference_index_hash graph_address_index_hash identity_tuple_index_hash graph_row_hash"),
	"OODGraphSymbols":                          c("organization_id symbol_id", "organization_id symbol_id graph_object_id object_class symbol_kind symbol_name source_authority_id source_stable_reference version_coordinate section_path graph_address graph_address_index_hash identity_tuple_index_hash graph_row_hash"),
	"OODGraphEdges":                            c("organization_id graph_edge_id", "organization_id graph_edge_id source_endpoint_kind source_endpoint_id source_endpoint_class target_endpoint_kind target_endpoint_id target_endpoint_class edge_label edge_family source_version_coordinate target_version_coordinate authoring_source_path source_authority_id source_stable_reference source_content_hash_algorithm source_content_hash_profile source_content_hash valid_from valid_until diagnostic_only identity_tuple_index_hash graph_row_hash"),
	"OODGraphExternalFetchReceipts":            c("organization_id receipt_id", "organization_id receipt_id fetch_batch_id receipt_roles fetch_component_ordinal fetch_occurrence_id evidence_identity_hash graph_object_id object_class source_authority_id source_authority_binding_id source_authority_binding_digest source_ref_kind source_stable_reference source_representation_kind evidence_content_class source_representation_media_type representation_declaration_id representation_declaration_digest version_coordinate source_content_hash_algorithm source_content_hash_profile source_content_hash external_fetch_profile_ref external_fetch_profile_digest permission_grant_id permission_grant_digest permission_authority_id permission_principal_id permission_scope_digest permission_operation permission_method permission_redirect_policy_digest permission_content_class permission_trust_class permission_byte_ceiling permission_depth_ceiling permission_expected_content_hash_algorithm permission_expected_content_hash_profile permission_expected_content_hash permission_effective_at permission_expires_at permission_status permission_policy_version_ref permission_policy_version_digest fetch_authorization_decision_ref fetch_authorization_decision_digest observed_at transport_status transport_raw_content_hash_algorithm transport_raw_content_hash transport_raw_byte_count transport_decoded_byte_count transport_content_encoding transport_charset transport_response_metadata_digest evidence_archive_authority_id evidence_archive_record_id evidence_archive_record_digest evidence_archive_byte_count evidence_archive_deletion_domain_id evidence_archive_crypto_shred_domain_id receipt_deletion_domain_id receipt_crypto_shred_domain_id redacted_transport_evidence_ciphertext redacted_transport_evidence_digest created_at"),
	"OODGraphExternalFetchBatches":             c("organization_id fetch_batch_id", "organization_id fetch_batch_id source_authority_binding_id source_authority_binding_digest representation_declaration_id representation_declaration_digest batch_receipt_manifest_root_hash total_receipt_count component_receipt_count completeness_evidence_receipt_count noncomponent_receipt_count expected_component_count completeness_basis_kind completeness_evidence_ref completeness_evidence_identity_hash completeness_evidence_content_hash_algorithm completeness_evidence_content_hash_profile completeness_evidence_content_hash completeness_evidence_receipt_id completeness_evidence_archive_authority_id completeness_evidence_archive_record_id completeness_evidence_archive_record_digest completeness_evidence_selector_kind completeness_evidence_selector_value verified_completeness_claim_digest completeness_evidence_digest completeness_profile_ref completeness_profile_digest sealed_at created_at"),
	"OODGraphRelationshipEvidence":             c("organization_id relationship_evidence_hash", "organization_id relationship_evidence_hash evidence_source_kind patch_action source_object_class source_authority_id source_ref_kind source_stable_reference source_version_coordinate source_section_path target_object_class target_authority_id target_ref_kind target_stable_reference target_version_coordinate target_section_path edge_label authoring_source_path evidence_authority_id evidence_stable_reference evidence_version_coordinate evidence_content_hash_algorithm evidence_content_hash_profile evidence_content_hash evidence_identity_hash eligible_receipt_id eligible_receipt_digest sealed_completeness_certificate_hash evidence_archive_authority_id evidence_archive_record_id evidence_archive_record_digest graph_fact_locator_manifest_hash extractor_profile_id extractor_profile_version extractor_profile_digest evidence_authority_class parent_graph_snapshot_id source_stable_reference_index_hash created_at"),
	"OODGraphAPIPropertyFacts":                 c("organization_id api_property_fact_hash", "organization_id api_property_fact_hash subject_kind graph_object_id graph_edge_id subject_graph_row_hash property_family property_schema_artifact_id property_schema_version property_schema_digest property_payload_profile property_payload property_payload_hash extractor_profile_id extractor_profile_version extractor_profile_digest evidence_authority_class graph_fact_locator_manifest_hash deletion_domain_id created_at"),
	"OODGraphGraphFactEvidenceLocators":        c("organization_id graph_fact_locator_hash", "organization_id graph_fact_locator_hash evidence_identity_hash source_artifact_member_hash eligible_receipt_id eligible_receipt_digest sealed_completeness_certificate_hash evidence_archive_authority_id evidence_archive_record_id evidence_archive_record_digest source_content_hash_algorithm source_content_hash_profile source_content_hash source_content_byte_length canonical_representation_profile_ref canonical_representation_profile_digest byte_start_offset byte_end_offset_exclusive selected_range_content_hash selected_range_byte_count evidence_archive_deletion_domain_id evidence_archive_crypto_shred_domain_id created_at"),
	"OODGraphManifestNodes":                    c("organization_id manifest_node_hash", "organization_id manifest_node_hash manifest_kind node_kind node_level route_prefix_bytes route_prefix_nibble_length entry_count transitive_member_count canonical_byte_count hash_algorithm canonicalization_profile sealed created_at"),
	"OODGraphManifestEntries":                  c("organization_id manifest_node_hash entry_ordinal", "organization_id manifest_node_hash entry_ordinal branch_nibble entry_kind member_id member_hash child_manifest_node_hash canonical_entry_byte_count created_at"),
	"OODGraphSnapshotNodeMembershipProjection": c("organization_id node_membership_entry_hash", "organization_id node_membership_entry_hash graph_object_id object_class api_element_role api_element_role_locator_manifest_hash object_graph_row_hash created_at"),
	"OODGraphSnapshotEdgeMembershipProjection": c("organization_id edge_membership_entry_hash", "organization_id edge_membership_entry_hash graph_edge_id source_node_membership_entry_hash target_node_membership_entry_hash source_endpoint_id target_endpoint_id source_endpoint_class target_endpoint_class edge_label edge_family valid_from valid_until diagnostic_only edge_graph_row_hash created_at"),
	"OODGraphProjectionArtifacts":              c("organization_id projection_artifact_id", "organization_id projection_artifact_id projection_kind projection_target_kind projection_target_id projection_format projection_hash projection_payload round_trip_state created_at"),
	"OODGraphViolations":                       c("organization_id violation_id", "organization_id violation_id graph_snapshot_id materialization_run_id violation_code sentinel_candidate severity source_authority_id source_stable_reference version_coordinate section_path graph_object_id symbol_id graph_edge_id evidence status visibility_scope created_at updated_at"),
	"OODGraphClosureVerificationCertificates":  certificateContract(),
}

func c(keys, columns string) physicalContract {
	return physicalContract{strings.Fields(keys), strings.Fields(columns)}
}
func certificateContract() physicalContract {
	p := oodcanon.ClosureVerificationCertificateV1()
	cols := []string{"organization_id", "verification_certificate_id", "verification_certificate_hash"}
	for _, f := range p.Fields {
		if f.Name == "canonicalization_profile" {
			continue
		} // domain, not a physical column
		cols = append(cols, f.Name)
	}
	cols = append(cols, "verification_attestation_authority_id", "verification_attestation_ref", "verification_attestation_digest", "verification_attestation_profile", "created_at")
	seen := map[string]bool{}
	out := make([]string, 0, len(cols))
	for _, name := range cols {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return physicalContract{[]string{"organization_id", "verification_certificate_id"}, out}
}

// BuildImmutableRow rejects unknown, partial and mutable tables.  The input
// map is accepted only at this boundary, then copied into the immutable result.
func BuildImmutableRow(table string, columns map[string]interface{}) (ImmutablePhysicalRow, error) {
	contract, ok := immutablePhysicalContracts[table]
	if !ok {
		return ImmutablePhysicalRow{}, fmt.Errorf("%w: %s is not an admitted immutable table", ErrImmutablePhysicalRow, table)
	}
	if len(columns) != len(contract.columns) {
		return ImmutablePhysicalRow{}, fmt.Errorf("%w: %s has missing or extra columns", ErrImmutablePhysicalRow, table)
	}
	row := SpannerRow{Table: table, KeyColumns: append([]string(nil), contract.keys...), Columns: make(map[string]interface{}, len(columns))}
	for _, name := range contract.columns {
		v, ok := columns[name]
		if !ok {
			return ImmutablePhysicalRow{}, fmt.Errorf("%w: %s.%s missing", ErrImmutablePhysicalRow, table, name)
		}
		copy, err := immutableValue(table, name, v)
		if err != nil {
			return ImmutablePhysicalRow{}, fmt.Errorf("%w: %s.%s: %v", ErrImmutablePhysicalRow, table, name, err)
		}
		row.Columns[name] = copy
	}
	b, err := encodeImmutablePhysicalRow(row, contract)
	if err != nil {
		return ImmutablePhysicalRow{}, err
	}
	key := table
	for _, k := range contract.keys {
		key += "\x00" + physicalKeyString(row.Columns[k])
	}
	return ImmutablePhysicalRow{row: cloneImmutableSpannerRow(row), bytes: append([]byte(nil), b...), hash: sha256.Sum256(b), key: key}, nil
}

// CanonicalImmutableRowBytes is retained for roster consumers.  It first
// builds the row, so this compatibility API has exactly the same admission
// checks as the typed builder.
func CanonicalImmutableRowBytes(row SpannerRow) ([]byte, error) {
	x, err := BuildImmutableRow(row.Table, row.Columns)
	if err != nil {
		return nil, err
	}
	if !sameStrings(row.KeyColumns, x.row.KeyColumns) {
		return nil, fmt.Errorf("%w: %s primary key roster", ErrImmutablePhysicalRow, row.Table)
	}
	return append([]byte(nil), x.bytes...), nil
}
func CanonicalImmutableRosterBytes(rows []SpannerRow) ([][]byte, error) {
	if len(rows) == 0 {
		return nil, fmt.Errorf("%w: empty roster", ErrImmutablePhysicalRow)
	}
	out := make([][]byte, len(rows))
	seen := map[string]struct{}{}
	for i, r := range rows {
		x, err := BuildImmutableRow(r.Table, r.Columns)
		if err != nil {
			return nil, err
		}
		if !sameStrings(r.KeyColumns, x.row.KeyColumns) {
			return nil, fmt.Errorf("%w: key roster", ErrImmutablePhysicalRow)
		}
		if _, dup := seen[x.key]; dup {
			return nil, fmt.Errorf("%w: duplicate member %d", ErrImmutablePhysicalRow, i)
		}
		seen[x.key] = struct{}{}
		out[i] = append([]byte(nil), x.bytes...)
	}
	return out, nil
}

func encodeImmutablePhysicalRow(row SpannerRow, contract physicalContract) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("OOD8PHR1")
	putText(&b, row.Table)
	putU32(&b, uint32(len(contract.columns)))
	for _, name := range contract.columns {
		putText(&b, name)
		if err := putPhysicalValue(&b, row.Columns[name]); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}
func immutableValue(table, name string, v interface{}) (interface{}, error) {
	if v == nil {
		if nullablePhysicalColumn(table, name) {
			return nil, nil
		}
		return nil, errors.New("required column is null")
	} // null is materially distinct from absent (checked above).
	want := physicalColumnType(table, name)
	switch x := v.(type) {
	case string:
		if want != physicalText {
			return nil, errors.New("string supplied for non-string column")
		}
		if !utf8.ValidString(x) || strings.HasPrefix(x, "\ufeff") {
			return nil, errors.New("noncanonical utf8")
		}
		if physicalUUIDColumn(table, name) {
			u, err := uuid.Parse(x)
			if err != nil || u.String() != x {
				return nil, errors.New("UUID text required")
			}
		}
		if physicalDigestColumn(table, name) && !canonicalHex(x) {
			return nil, errors.New("lowercase SHA-256 digest required")
		}
		return x, nil
	case int64:
		if want != physicalInt64 {
			return nil, errors.New("int64 supplied for non-int64 column")
		}
		return x, nil
	case bool:
		if want != physicalBool {
			return nil, errors.New("bool supplied for non-bool column")
		}
		return x, nil
	case []byte:
		if want != physicalBytes {
			return nil, errors.New("bytes supplied for non-bytes column")
		}
		return append([]byte(nil), x...), nil
	case time.Time:
		if want != physicalTimestamp {
			return nil, errors.New("timestamp supplied for non-timestamp column")
		}
		if x.IsZero() || x.Location() != time.UTC || x.Nanosecond()%1000 != 0 {
			return nil, errors.New("UTC microsecond timestamp required")
		}
		return x, nil
	case []string:
		if want != physicalStringArray {
			return nil, errors.New("array supplied for non-array column")
		}
		out := make([]string, len(x))
		for i, s := range x {
			if !utf8.ValidString(s) || strings.HasPrefix(s, "\ufeff") {
				return nil, errors.New("noncanonical array string")
			}
			out[i] = s
		}
		return out, nil
	case CanonicalJSON:
		if want != physicalJSON {
			return nil, errors.New("JSON supplied for non-JSON column")
		}
		var compact bytes.Buffer
		if !json.Valid(x) || json.Compact(&compact, x) != nil || !bytes.Equal(compact.Bytes(), x) {
			return nil, errors.New("owner-canonical JSON required")
		}
		return CanonicalJSON(append([]byte(nil), x...)), nil
	default:
		return nil, fmt.Errorf("unsupported physical type %T", v)
	}
}

type physicalValueType uint8

const (
	physicalText physicalValueType = iota
	physicalInt64
	physicalBool
	physicalBytes
	physicalTimestamp
	physicalStringArray
	physicalJSON
)

// The sets below are owner-pinned physical bindings. They are deliberately
// explicit field names, rather than suffix/name guessing: every other column
// in an admitted roster is a required STRING physical value.
func physicalColumnType(table, name string) physicalValueType {
	k := table + "." + name
	if _, ok := physicalInt64Columns[k]; ok {
		return physicalInt64
	}
	if _, ok := physicalBoolColumns[k]; ok {
		return physicalBool
	}
	if _, ok := physicalBytesColumns[k]; ok {
		return physicalBytes
	}
	if _, ok := physicalTimestampColumns[k]; ok {
		return physicalTimestamp
	}
	if _, ok := physicalStringArrayColumns[k]; ok {
		return physicalStringArray
	}
	if _, ok := physicalJSONColumns[k]; ok {
		return physicalJSON
	}
	return physicalText
}
func nullablePhysicalColumn(table, name string) bool {
	_, ok := nullablePhysicalColumns[table+"."+name]
	return ok
}
func tableFields(table, fields string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, f := range strings.Fields(fields) {
		m[table+"."+f] = struct{}{}
	}
	return m
}
func mergeFieldSets(sets ...map[string]struct{}) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range sets {
		for k := range s {
			out[k] = struct{}{}
		}
	}
	return out
}

var physicalInt64Columns = mergeFieldSets(
	tableFields("OODGraphEdges", ""), tableFields("OODGraphExternalFetchReceipts", "fetch_component_ordinal permission_byte_ceiling permission_depth_ceiling transport_raw_byte_count transport_decoded_byte_count evidence_archive_byte_count"), tableFields("OODGraphExternalFetchBatches", "total_receipt_count component_receipt_count completeness_evidence_receipt_count noncomponent_receipt_count expected_component_count"), tableFields("OODGraphGraphFactEvidenceLocators", "source_content_byte_length byte_start_offset byte_end_offset_exclusive selected_range_byte_count"), tableFields("OODGraphManifestNodes", "node_level route_prefix_nibble_length entry_count transitive_member_count canonical_byte_count"), tableFields("OODGraphManifestEntries", "entry_ordinal branch_nibble canonical_entry_byte_count"), tableFields("OODGraphClosureVerificationCertificates", "source_artifact_count relationship_evidence_count object_count symbol_count edge_count api_property_count graph_fact_locator_count receipt_count structural_projection_count violation_count source_authority_identity_count completeness_identity_count permission_policy_identity_count archive_binding_identity_count profile_identity_count external_source_receipt_eligibility_count"))
var physicalBoolColumns = mergeFieldSets(tableFields("OODGraphEdges", "diagnostic_only"), tableFields("OODGraphManifestNodes", "sealed"), tableFields("OODGraphSnapshotEdgeMembershipProjection", "diagnostic_only"))
var physicalBytesColumns = mergeFieldSets(tableFields("OODGraphExternalFetchReceipts", "redacted_transport_evidence_ciphertext"), tableFields("OODGraphManifestNodes", "route_prefix_bytes"))
var physicalTimestampColumns = mergeFieldSets(tableFields("OODGraphEdges", "valid_from valid_until"), tableFields("OODGraphExternalFetchReceipts", "permission_effective_at permission_expires_at observed_at created_at"), tableFields("OODGraphExternalFetchBatches", "sealed_at created_at"), tableFields("OODGraphRelationshipEvidence", "created_at"), tableFields("OODGraphGraphFactEvidenceLocators", "created_at"), tableFields("OODGraphAPIPropertyFacts", "created_at"), tableFields("OODGraphManifestNodes", "created_at"), tableFields("OODGraphManifestEntries", "created_at"), tableFields("OODGraphClosureVerificationCertificates", "created_at"), tableFields("OODGraphSnapshotNodeMembershipProjection", "created_at"), tableFields("OODGraphSnapshotEdgeMembershipProjection", "created_at"), tableFields("OODGraphProjectionArtifacts", "created_at"), tableFields("OODGraphViolations", "created_at updated_at"))
var physicalStringArrayColumns = tableFields("OODGraphExternalFetchReceipts", "receipt_roles")
var physicalJSONColumns = mergeFieldSets(tableFields("OODGraphAPIPropertyFacts", "property_payload"), tableFields("OODGraphProjectionArtifacts", "projection_payload"), tableFields("OODGraphViolations", "evidence"))
var nullablePhysicalColumns = mergeFieldSets(
	tableFields("OODGraphObjects", "api_element_role api_element_role_locator_manifest_hash source_content_hash_algorithm source_content_hash_profile source_content_hash"), tableFields("OODGraphEdges", "source_content_hash_algorithm source_content_hash_profile source_content_hash valid_from valid_until"), tableFields("OODGraphExternalFetchReceipts", "fetch_component_ordinal source_representation_media_type permission_expected_content_hash_algorithm permission_expected_content_hash_profile permission_expected_content_hash permission_expires_at transport_content_encoding transport_charset redacted_transport_evidence_ciphertext"), tableFields("OODGraphExternalFetchBatches", "expected_component_count"), tableFields("OODGraphRelationshipEvidence", "evidence_identity_hash eligible_receipt_id eligible_receipt_digest sealed_completeness_certificate_hash evidence_archive_authority_id evidence_archive_record_id evidence_archive_record_digest graph_fact_locator_manifest_hash extractor_profile_id extractor_profile_version extractor_profile_digest evidence_authority_class parent_graph_snapshot_id"), tableFields("OODGraphAPIPropertyFacts", "graph_object_id graph_edge_id"), tableFields("OODGraphManifestNodes", "route_prefix_bytes route_prefix_nibble_length"), tableFields("OODGraphManifestEntries", "branch_nibble member_id member_hash child_manifest_node_hash"), tableFields("OODGraphSnapshotNodeMembershipProjection", "api_element_role api_element_role_locator_manifest_hash"), tableFields("OODGraphSnapshotEdgeMembershipProjection", "valid_from valid_until"), tableFields("OODGraphProjectionArtifacts", "projection_target_id"), tableFields("OODGraphViolations", "graph_snapshot_id materialization_run_id sentinel_candidate source_authority_id source_stable_reference version_coordinate section_path graph_object_id symbol_id graph_edge_id"))

func physicalUUIDColumn(_ string, n string) bool   { _, ok := physicalUUIDFields[n]; return ok }
func physicalDigestColumn(_ string, n string) bool { _, ok := physicalDigestFields[n]; return ok }

var physicalUUIDFields = fieldSet("graph_object_id symbol_id graph_edge_id receipt_id source_authority_id source_authority_binding_id representation_declaration_id permission_grant_id permission_authority_id permission_principal_id evidence_archive_authority_id evidence_archive_record_id evidence_archive_deletion_domain_id evidence_archive_crypto_shred_domain_id receipt_deletion_domain_id receipt_crypto_shred_domain_id eligible_receipt_id completeness_evidence_receipt_id completeness_evidence_archive_authority_id completeness_evidence_archive_record_id evidence_authority_id target_authority_id extractor_profile_id parent_graph_snapshot_id property_schema_artifact_id deletion_domain_id graph_snapshot_id materialization_run_id verification_certificate_id verification_attestation_authority_id projection_artifact_id projection_target_id source_endpoint_id target_endpoint_id violation_id")
var physicalDigestFields = fieldSet("api_element_role_locator_manifest_hash source_content_hash source_stable_reference_index_hash graph_address_index_hash identity_tuple_index_hash graph_row_hash evidence_identity_hash source_authority_binding_digest representation_declaration_digest external_fetch_profile_digest permission_grant_digest permission_scope_digest permission_redirect_policy_digest permission_expected_content_hash permission_policy_version_digest fetch_authorization_decision_digest transport_raw_content_hash transport_response_metadata_digest evidence_archive_record_digest redacted_transport_evidence_digest batch_receipt_manifest_root_hash completeness_evidence_content_hash completeness_evidence_identity_hash completeness_evidence_archive_record_digest verified_completeness_claim_digest completeness_evidence_digest completeness_profile_digest relationship_evidence_hash evidence_content_hash eligible_receipt_digest sealed_completeness_certificate_hash graph_fact_locator_manifest_hash extractor_profile_digest source_artifact_member_hash canonical_representation_profile_digest selected_range_content_hash api_property_fact_hash subject_graph_row_hash property_schema_digest property_payload_hash manifest_node_hash member_hash child_manifest_node_hash verification_certificate_hash source_set_hash source_manifest_root_hash object_manifest_root_hash symbol_manifest_root_hash edge_manifest_root_hash api_property_manifest_root_hash receipt_manifest_root_hash structural_projection_manifest_root_hash violation_manifest_root_hash closure_hash relationship_identity_set_hash source_authority_identity_set_hash completeness_identity_set_hash permission_policy_identity_set_hash archive_binding_identity_set_hash profile_identity_set_hash external_source_receipt_eligibility_set_hash materialization_profile_digest publication_budget_profile_digest manifest_hash_contract_digest closure_hash_contract_digest verifier_capability_digest verification_policy_digest verification_attestation_digest node_membership_entry_hash object_graph_row_hash edge_membership_entry_hash source_node_membership_entry_hash target_node_membership_entry_hash edge_graph_row_hash projection_hash")

func fieldSet(s string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, n := range strings.Fields(s) {
		m[n] = struct{}{}
	}
	return m
}
func canonicalHex(s string) bool {
	if len(s) != 64 && len(s) != 128 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}
func putPhysicalValue(b *bytes.Buffer, v interface{}) error {
	switch x := v.(type) {
	case nil:
		b.WriteByte(0)
	case string:
		b.WriteByte(1)
		putText(b, x)
	case int64:
		b.WriteByte(2)
		putU64(b, uint64(x))
	case bool:
		b.WriteByte(3)
		if x {
			b.WriteByte(1)
		} else {
			b.WriteByte(0)
		}
	case []byte:
		b.WriteByte(4)
		putU32(b, uint32(len(x)))
		b.Write(x)
	case time.Time:
		b.WriteByte(5)
		putU64(b, uint64(x.UnixMicro()))
	case []string:
		b.WriteByte(6)
		putU32(b, uint32(len(x)))
		for _, s := range x {
			putText(b, s)
		}
	case CanonicalJSON:
		b.WriteByte(7)
		putU32(b, uint32(len(x)))
		b.Write(x)
	default:
		return fmt.Errorf("unsupported physical type %T", v)
	}
	return nil
}
func putText(b *bytes.Buffer, s string) { putU32(b, uint32(len(s))); b.WriteString(s) }
func putU32(b *bytes.Buffer, n uint32) {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], n)
	b.Write(x[:])
}
func putU64(b *bytes.Buffer, n uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], n)
	b.Write(x[:])
}
func physicalKeyString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case int64:
		return fmt.Sprintf("%d", x)
	default:
		return fmt.Sprintf("%T:%v", v, v)
	}
}
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func cloneImmutableSpannerRow(in SpannerRow) SpannerRow {
	out := SpannerRow{Table: in.Table, KeyColumns: append([]string(nil), in.KeyColumns...), Columns: make(map[string]interface{}, len(in.Columns))}
	for k, v := range in.Columns {
		switch x := v.(type) {
		case []byte:
			out.Columns[k] = append([]byte(nil), x...)
		case []string:
			out.Columns[k] = append([]string(nil), x...)
		case CanonicalJSON:
			out.Columns[k] = CanonicalJSON(append([]byte(nil), x...))
		default:
			out.Columns[k] = x
		}
	}
	return out
}
