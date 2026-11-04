package oodcanon

import "strings"

// ProfileFor exposes only profiles whose complete field bindings are pinned in
// this package.  Names which the OOD document mentions but which have not been
// copied with their entire binding roster deliberately fail closed.
func ProfileFor(name string) (Profile, error) {
	switch name {
	case "external_fetch_completeness_evidence_v3":
		return ExternalFetchCompletenessEvidenceV3(), nil
	case "external_fetch_receipt_v1":
		return ExternalFetchReceiptV1(), nil
	case "external_evidence_archive_binding_v1":
		return ExternalEvidenceArchiveBindingV1(), nil
	case "ood_graph_relationship_evidence_v1":
		return RelationshipEvidenceV1(), nil
	case "ood_graph_content_closure_v1":
		return ContentClosureV1(), nil
	case "ood_graph_snapshot_envelope_v1":
		return SnapshotEnvelopeV1(), nil
	case "ood_graph_closure_verification_certificate_v1":
		return ClosureVerificationCertificateV1(), nil
	case "ood_graph_manifest_node_v1_leaf":
		return ManifestLeafV1(), nil
	case "ood_graph_manifest_node_v1_internal":
		return ManifestInternalV1(), nil
	case "ood_graph_sparse_patricia_membership_node_v1":
		return SparsePatriciaMembershipNodeV1(), nil
	case "ood_graph_api_property_fact_v1":
		return APIPropertyFactV1(), nil
	case "ood_graph_canonical_source_artifact_identity_v2_admitted_doc_object":
		return SourceArtifactAdmittedDocObjectV2(), nil
	case "ood_graph_canonical_source_artifact_identity_v2_external_evidence":
		return SourceArtifactExternalEvidenceV2(), nil
	case "ood_graph_node_membership_entry_v2":
		return NodeMembershipEntryV2(), nil
	case "ood_graph_edge_membership_entry_v2":
		return EdgeMembershipEntryV2(), nil
	case "ood_graph_structural_projection_artifact_v1":
		return StructuralProjectionArtifactV1(), nil
	case "ood_graph_violation_manifest_member_v1":
		return ViolationManifestMemberV1(), nil
	default:
		return Profile{}, ErrUnsupportedProfile
	}
}

// closed is intentionally a closed, owner-authored roster mini-notation:
// wire-name/type-tag/presence-policy.  It is not an input format.
func closed(name, rows string) Profile {
	parts := strings.Fields(rows)
	fs := make([]Field, 0, len(parts))
	for i, row := range parts {
		p := strings.Split(row, "/")
		if len(p) != 3 {
			panic("bad pinned OOD profile row")
		}
		typ := map[string]Type{"s": UTF8, "u": UUID, "h": SHA256, "i": Int64, "t": TimestampMicroseconds}[p[1]]
		pol := map[string]PresencePolicy{"r": Required, "n": Nullable, "z": NullOnly}[p[2]]
		if typ == 0 {
			panic("unsupported pinned OOD type")
		}
		if i == 0 {
			fs = append(fs, f(p[0], typ, pol, String(name)))
		} else {
			fs = append(fs, f(p[0], typ, pol))
		}
	}
	return Profile{Name: name, Fields: fs}
}

func RelationshipEvidenceV1() Profile {
	return closed("ood_graph_relationship_evidence_v1", `canonical_hash_profile/s/r organization_id/s/r evidence_source_kind/s/r patch_action/s/r source_object_class/s/r source_authority_id/u/r source_ref_kind/s/r source_stable_reference/s/r source_version_coordinate/s/r source_section_path/s/r target_object_class/s/r target_authority_id/u/r target_ref_kind/s/r target_stable_reference/s/r target_version_coordinate/s/r target_section_path/s/r edge_label/s/r authoring_source_path/s/r evidence_authority_id/u/r evidence_stable_reference/s/r evidence_version_coordinate/s/r evidence_content_hash_algorithm/s/r evidence_content_hash_profile/s/r evidence_content_hash/h/r evidence_identity_hash/h/n eligible_receipt_id/u/n eligible_receipt_digest/h/n sealed_completeness_certificate_hash/h/n evidence_archive_authority_id/u/n evidence_archive_record_id/u/n evidence_archive_record_digest/h/n graph_fact_locator_manifest_hash/h/n extractor_profile_id/u/n extractor_profile_version/s/n extractor_profile_digest/h/n evidence_authority_class/s/n parent_graph_snapshot_id/u/n`)
}
func ContentClosureV1() Profile {
	return closed("ood_graph_content_closure_v1", `canonicalization_profile/s/r organization_id/s/r source_set_hash/h/r source_manifest_root_hash/h/r source_artifact_count/i/r relationship_evidence_count/i/r object_manifest_root_hash/h/r object_count/i/r symbol_manifest_root_hash/h/r symbol_count/i/r edge_manifest_root_hash/h/r edge_count/i/r api_property_manifest_root_hash/h/r api_property_count/i/r graph_fact_locator_manifest_root_hash/h/r graph_fact_locator_count/i/r receipt_manifest_root_hash/h/r receipt_count/i/r structural_projection_manifest_root_hash/h/r structural_projection_count/i/r violation_manifest_root_hash/h/r violation_count/i/r materialization_profile_id/u/r materialization_profile_version/s/r materialization_profile_digest/h/r publication_budget_profile_ref/s/r publication_budget_profile_digest/h/r`)
}
func SnapshotEnvelopeV1() Profile {
	return closed("ood_graph_snapshot_envelope_v1", `canonicalization_profile/s/r organization_id/s/r snapshot_kind/s/r graph_snapshot_id/u/r graph_version/i/r materialization_run_id/u/r sealed_at/t/r closure_hash/h/r verification_certificate_id/u/r verification_certificate_hash/h/r predecessor_graph_snapshot_id/u/n predecessor_head_generation/i/n predecessor_snapshot_envelope_hash/h/n published_head_generation/i/r predecessor_org_publication_state_hash/h/n published_org_publication_generation/i/r`)
}
func ClosureVerificationCertificateV1() Profile {
	p := closed("ood_graph_closure_verification_certificate_v1", `canonicalization_profile/s/r organization_id/s/r materialization_run_id/u/r snapshot_kind/s/r source_set_hash/h/r source_manifest_root_hash/h/r source_artifact_count/i/r relationship_evidence_count/i/r object_manifest_root_hash/h/r object_count/i/r symbol_manifest_root_hash/h/r symbol_count/i/r edge_manifest_root_hash/h/r edge_count/i/r api_property_manifest_root_hash/h/r api_property_count/i/r graph_fact_locator_manifest_root_hash/h/r graph_fact_locator_count/i/r receipt_manifest_root_hash/h/r receipt_count/i/r structural_projection_manifest_root_hash/h/r structural_projection_count/i/r violation_manifest_root_hash/h/r violation_count/i/r closure_hash/h/r relationship_identity_set_hash/h/r source_authority_identity_set_hash/h/r source_authority_identity_count/i/r completeness_identity_set_hash/h/r completeness_identity_count/i/r permission_policy_identity_set_hash/h/r permission_policy_identity_count/i/r archive_binding_identity_set_hash/h/r archive_binding_identity_count/i/r profile_identity_set_hash/h/r profile_identity_count/i/r external_source_receipt_eligibility_set_hash/h/r external_source_receipt_eligibility_count/i/r materialization_profile_id/u/r materialization_profile_version/s/r materialization_profile_digest/h/r publication_budget_profile_ref/s/r publication_budget_profile_digest/h/r manifest_hash_algorithm/s/r manifest_hash_profile/s/r manifest_hash_contract_digest/h/r closure_hash_algorithm/s/r closure_hash_profile/s/r closure_hash_contract_digest/h/r verifier_capability_name/s/r verifier_capability_version/s/r verifier_capability_digest/h/r verification_policy_ref/s/r verification_policy_digest/h/r verification_result/s/r`)
	v := String("verified")
	p.Fields[len(p.Fields)-1].Literal = &v
	return p
}

func ManifestLeafV1() Profile {
	entry := Field{Type: Record, Policy: Required, Nested: []Field{f("entry_ordinal", Int64, Required), f("entry_kind", UTF8, Required), f("member_id", UTF8, Required), f("member_hash", SHA256, Required), f("child_manifest_node_hash", SHA256, NullOnly), f("canonical_entry_byte_count", Int64, Required)}}
	return Profile{Name: "ood_graph_manifest_node_v1", Fields: []Field{f("canonicalization_profile", UTF8, Required, String("ood_graph_manifest_node_v1")), f("manifest_kind", UTF8, Required), f("node_kind", UTF8, Required, String("leaf")), f("node_level", Int64, Required, I64(0)), f("entry_count", Int64, Required), f("transitive_member_count", Int64, Required), f("canonical_byte_count", Int64, Required), {Name: "ordered_entry_tuples", Type: Array, Policy: Required, Element: &entry}}}
}
func ManifestInternalV1() Profile {
	child := Field{Type: Record, Policy: Required, Nested: []Field{f("entry_ordinal", Int64, Required), f("entry_kind", UTF8, Required, String("child_manifest")), f("member_id", UTF8, NullOnly), f("member_hash", SHA256, NullOnly), f("child_manifest_node_hash", SHA256, Required), f("child_transitive_member_count", Int64, Required), f("child_canonical_byte_count", Int64, Required), f("canonical_entry_byte_count", Int64, Required)}}
	return Profile{Name: "ood_graph_manifest_node_v1", Fields: []Field{f("canonicalization_profile", UTF8, Required, String("ood_graph_manifest_node_v1")), f("manifest_kind", UTF8, Required), f("node_kind", UTF8, Required, String("internal")), f("node_level", Int64, Required), f("entry_count", Int64, Required), f("transitive_member_count", Int64, Required), f("canonical_byte_count", Int64, Required), {Name: "ordered_child_tuples", Type: Array, Policy: Required, Element: &child}}}
}

// SparsePatriciaMembershipNodeV1 is the only profile eligible for the two
// snapshot membership manifest kinds. Its branch records deliberately retain
// nullable member/child alternatives; shape constraints are verified by the
// membership builder, while this codec owns their exact bytes.
func SparsePatriciaMembershipNodeV1() Profile {
	slot := Field{Type: Record, Policy: Required, Nested: []Field{
		f("branch_nibble", Int64, Required), f("entry_kind", UTF8, Required), f("member_id", UTF8, Nullable), f("member_hash", SHA256, Nullable), f("child_manifest_node_hash", SHA256, Nullable), f("canonical_entry_byte_count", Int64, Required),
	}}
	return Profile{Name: "ood_graph_sparse_patricia_membership_node_v1", Fields: []Field{
		f("canonicalization_profile", UTF8, Required, String("ood_graph_sparse_patricia_membership_node_v1")), f("manifest_kind", UTF8, Required), f("node_kind", UTF8, Required), f("node_level", Int64, Required), f("route_prefix_nibble_length", Int64, Required), f("route_prefix_bytes", RawBytes, Required), f("entry_count", Int64, Required), f("transitive_member_count", Int64, Required), f("canonical_byte_count", Int64, Required), {Name: "ordered_present_slot_tuples", Type: Array, Policy: Required, Element: &slot},
	}}
}

func f(name string, typ Type, policy PresencePolicy, literal ...Value) Field {
	x := Field{Name: name, Type: typ, Policy: policy}
	if typ == Array {
		x.Element = &Field{Type: UTF8, Policy: Required}
	}
	if len(literal) == 1 {
		v := literal[0]
		x.Literal = &v
	}
	return x
}

func ExternalEvidenceArchiveBindingV1() Profile {
	return closed("external_evidence_archive_binding_v1", `canonicalization_profile/s/r organization_id/s/r evidence_archive_authority_id/u/r evidence_archive_record_id/u/r source_content_hash_algorithm/s/r source_content_hash_profile/s/r source_content_hash/h/r evidence_archive_byte_count/i/r evidence_archive_deletion_domain_id/u/r evidence_archive_crypto_shred_domain_id/u/r`)
}

// ExternalFetchReceiptV1 is the complete external receipt digest preimage.
func ExternalFetchReceiptV1() Profile {
	return Profile{Name: "external_fetch_receipt_v1", Fields: []Field{
		f("canonical_hash_profile", UTF8, Required, String("external_fetch_receipt_v1")), f("organization_id", UTF8, Required), f("receipt_id", UUID, Required), f("fetch_batch_id", UTF8, Required), f("receipt_roles", Array, Required), f("fetch_component_ordinal", Int64, Nullable), f("fetch_occurrence_id", UTF8, Required), f("evidence_identity_hash", SHA256, Required), f("graph_object_id", UUID, Required), f("object_class", UTF8, Required),
		f("source_authority_id", UUID, Required), f("source_authority_binding_id", UUID, Required), f("source_authority_binding_digest", SHA256, Required), f("source_ref_kind", UTF8, Required), f("source_stable_reference", UTF8, Required), f("source_representation_kind", UTF8, Required), f("evidence_content_class", UTF8, Required), f("source_representation_media_type", UTF8, Nullable), f("representation_declaration_id", UUID, Required), f("representation_declaration_digest", SHA256, Required),
		f("version_coordinate", UTF8, Required), f("source_content_hash_algorithm", UTF8, Required), f("source_content_hash_profile", UTF8, Required), f("source_content_hash", SHA256, Required), f("external_fetch_profile_ref", UTF8, Required), f("external_fetch_profile_digest", SHA256, Required), f("permission_grant_id", UUID, Required), f("permission_grant_digest", SHA256, Required), f("permission_authority_id", UUID, Required), f("permission_principal_id", UUID, Required),
		f("permission_scope_digest", SHA256, Required), f("permission_operation", UTF8, Required), f("permission_method", UTF8, Required), f("permission_redirect_policy_digest", SHA256, Required), f("permission_content_class", UTF8, Required), f("permission_trust_class", UTF8, Required), f("permission_byte_ceiling", Int64, Required), f("permission_depth_ceiling", Int64, Required), f("permission_expected_content_hash_algorithm", UTF8, Nullable), f("permission_expected_content_hash_profile", UTF8, Nullable), f("permission_expected_content_hash", SHA256, Nullable),
		f("permission_effective_at", TimestampMicroseconds, Required), f("permission_expires_at", TimestampMicroseconds, Nullable), f("permission_status", UTF8, Required), f("permission_policy_version_ref", UTF8, Required), f("permission_policy_version_digest", SHA256, Required), f("fetch_authorization_decision_ref", UTF8, Required), f("fetch_authorization_decision_digest", SHA256, Required), f("observed_at", TimestampMicroseconds, Required), f("transport_status", UTF8, Required), f("transport_raw_content_hash_algorithm", UTF8, Required),
		f("transport_raw_content_hash", SHA256, Required), f("transport_raw_byte_count", Int64, Required), f("transport_decoded_byte_count", Int64, Required), f("transport_content_encoding", UTF8, Nullable), f("transport_charset", UTF8, Nullable), f("transport_response_metadata_digest", SHA256, Required), f("evidence_archive_authority_id", UUID, Required), f("evidence_archive_record_id", UUID, Required), f("evidence_archive_record_digest", SHA256, Required), f("evidence_archive_byte_count", Int64, Required), f("evidence_archive_deletion_domain_id", UUID, Required), f("evidence_archive_crypto_shred_domain_id", UUID, Required), f("receipt_deletion_domain_id", UUID, Required), f("receipt_crypto_shred_domain_id", UUID, Required),
	}}
}

// ExternalFetchCompletenessEvidenceV3 is the complete s6 OOD v8 binding roster.
// The first literal is the hash domain; callers cannot override it.
func ExternalFetchCompletenessEvidenceV3() Profile {
	return Profile{Name: "external_fetch_completeness_evidence_v3", Fields: []Field{
		f("canonicalization_profile", UTF8, Required, String("external_fetch_completeness_evidence_v3")),
		f("organization_id", UTF8, Required), f("fetch_batch_id", UTF8, Required), f("source_authority_binding_id", UUID, Required), f("source_authority_binding_digest", SHA256, Required),
		f("representation_declaration_id", UUID, Required), f("representation_declaration_digest", SHA256, Required), f("batch_receipt_manifest_root_hash", SHA256, Required),
		f("total_receipt_count", Int64, Required), f("component_receipt_count", Int64, Required), f("completeness_evidence_receipt_count", Int64, Required), f("noncomponent_receipt_count", Int64, Required), f("expected_component_count", Int64, Nullable),
		f("completeness_basis_kind", UTF8, Required), f("completeness_evidence_ref", UTF8, Required), f("completeness_evidence_identity_hash", SHA256, Required), f("completeness_evidence_content_hash_algorithm", UTF8, Required), f("completeness_evidence_content_hash_profile", UTF8, Required), f("completeness_evidence_content_hash", SHA256, Required),
		f("completeness_evidence_receipt_id", UUID, Required), f("completeness_evidence_archive_authority_id", UUID, Required), f("completeness_evidence_archive_record_id", UUID, Required), f("completeness_evidence_archive_record_digest", SHA256, Required), f("completeness_evidence_selector_kind", UTF8, Required), f("completeness_evidence_selector_value", UTF8, Required), f("verified_completeness_claim_digest", SHA256, Required), f("completeness_profile_ref", UTF8, Required), f("completeness_profile_digest", SHA256, Required),
	}}
}
