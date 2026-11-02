package oodcanon

// The remaining nine-root member profiles. These are closed owner tuples;
// callers never choose a kind/discriminator or supply output hashes.

func APIPropertyFactV1() Profile {
	return Profile{Name: "ood_graph_api_property_fact_v1", Fields: []Field{
		f("canonicalization_profile", UTF8, Required, String("ood_graph_api_property_fact_v1")), f("organization_id", UTF8, Required), f("subject_kind", UTF8, Required), f("graph_object_id", UUID, Nullable), f("graph_edge_id", UUID, Nullable), f("subject_graph_row_hash", SHA256, Required), f("property_family", UTF8, Required), f("property_schema_artifact_id", UUID, Required), f("property_schema_version", UTF8, Required), f("property_schema_digest", SHA256, Required), f("property_payload_profile", UTF8, Required), f("property_payload_hash", SHA256, Required), f("extractor_profile_id", UUID, Required), f("extractor_profile_version", UTF8, Required), f("extractor_profile_digest", SHA256, Required), f("evidence_authority_class", UTF8, Required), f("graph_fact_locator_manifest_hash", SHA256, Required), f("deletion_domain_id", UUID, Required),
	}}
}

func SourceArtifactAdmittedDocObjectV2() Profile {
	return Profile{Name: "ood_graph_canonical_source_artifact_identity_v2", Fields: append(sourceArtifactCommon("admitted_doc_object"),
		f("admitted_artifact_stable_id", UUID, Required), f("admitted_artifact_version", UTF8, Required), f("admitted_artifact_contract_hash", SHA256, Required), f("admitted_artifact_content_hash", SHA256, Required))}
}
func SourceArtifactExternalEvidenceV2() Profile {
	return Profile{Name: "ood_graph_canonical_source_artifact_identity_v2", Fields: append(sourceArtifactCommon("external_evidence"), f("evidence_identity_hash", SHA256, Required), f("canonical_content_byte_length", Int64, Required), f("source_declared_completeness_relationship_hash", SHA256, Required))}
}
func sourceArtifactCommon(kind string) []Field {
	return []Field{f("canonicalization_profile", UTF8, Required, String("ood_graph_canonical_source_artifact_identity_v2")), f("organization_id", UTF8, Required), f("source_artifact_kind", UTF8, Required, String(kind)), f("source_authority_id", UUID, Required), f("source_ref_kind", UTF8, Required), f("canonical_source_stable_reference", UTF8, Required), f("selected_version_coordinate", UTF8, Required), f("content_hash_algorithm", UTF8, Required), f("content_hash_profile", UTF8, Required), f("authoritative_content_digest", SHA256, Required)}
}

func NodeMembershipEntryV2() Profile {
	return Profile{Name: "ood_graph_node_membership_entry_v2", Fields: []Field{f("canonicalization_profile", UTF8, Required, String("ood_graph_node_membership_entry_v2")), f("organization_id", UTF8, Required), f("graph_object_id", UUID, Required), f("object_class", UTF8, Required), f("api_element_role", UTF8, Nullable), f("api_element_role_locator_manifest_hash", SHA256, Nullable), f("object_graph_row_hash", SHA256, Required)}}
}
func EdgeMembershipEntryV2() Profile {
	return Profile{Name: "ood_graph_edge_membership_entry_v2", Fields: []Field{f("canonicalization_profile", UTF8, Required, String("ood_graph_edge_membership_entry_v2")), f("organization_id", UTF8, Required), f("graph_edge_id", UUID, Required), f("source_node_membership_entry_hash", SHA256, Required), f("target_node_membership_entry_hash", SHA256, Required), f("source_endpoint_id", UUID, Required), f("target_endpoint_id", UUID, Required), f("source_endpoint_class", UTF8, Required), f("target_endpoint_class", UTF8, Required), f("edge_label", UTF8, Required), f("edge_family", UTF8, Required), f("valid_from", TimestampMicroseconds, Nullable), f("valid_until", TimestampMicroseconds, Nullable), f("diagnostic_only", Bool, Required), f("edge_graph_row_hash", SHA256, Required)}}
}

func StructuralProjectionArtifactV1() Profile {
	return Profile{Name: "ood_graph_structural_projection_artifact_v1", Fields: []Field{f("canonicalization_profile", UTF8, Required, String("ood_graph_structural_projection_artifact_v1")), f("organization_id", UTF8, Required), f("projection_kind", UTF8, Required), f("projection_target_kind", UTF8, Required), f("projection_target_id", UUID, Nullable), f("projection_format", UTF8, Required), f("canonical_projection_payload_bytes", RawBytes, Required), f("round_trip_state", UTF8, Required)}}
}
