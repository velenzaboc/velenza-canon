package oodcanon

// Immutable graph fact tuples are three closed variants of the one owner
// profile.  Their table discriminator is a literal: callers select a typed
// getter, never a table/domain string.

// GraphFactProfileForPhysicalTable maps only the three owner-defined graph
// fact homes. The table name is an internal physical discriminator, not a
// caller-selectable hash profile.
func GraphFactProfileForPhysicalTable(table string) (Profile, error) {
	switch table {
	case "OODGraphObjects":
		return ObjectFactTupleV1(), nil
	case "OODGraphSymbols":
		return SymbolFactTupleV1(), nil
	case "OODGraphEdges":
		return EdgeFactTupleV1(), nil
	default:
		return Profile{}, ErrUnsupportedProfile
	}
}

func ObjectFactTupleV1() Profile {
	return Profile{Name: "ood_graph_immutable_fact_tuple_v1", Fields: []Field{
		f("canonicalization_profile", UTF8, Required, String("ood_graph_immutable_fact_tuple_v1")), f("table_discriminator", UTF8, Required, String("object")),
		f("organization_id", UTF8, Required), f("graph_object_id", UUID, Required), f("object_class", UTF8, Required),
		f("api_element_role", UTF8, Nullable), f("api_element_role_locator_manifest_hash", SHA256, Nullable),
		f("source_authority_id", UUID, Required), f("source_artifact_class", UTF8, Required), f("source_ref_kind", UTF8, Required), f("source_stable_reference", UTF8, Required), f("version_coordinate", UTF8, Required), f("section_path", UTF8, Required), f("graph_address", UTF8, Required),
		f("source_content_hash_algorithm", UTF8, Nullable), f("source_content_hash_profile", UTF8, Nullable), f("source_content_hash", SHA256, Nullable),
	}}
}

func SymbolFactTupleV1() Profile {
	return Profile{Name: "ood_graph_immutable_fact_tuple_v1", Fields: []Field{
		f("canonicalization_profile", UTF8, Required, String("ood_graph_immutable_fact_tuple_v1")), f("table_discriminator", UTF8, Required, String("symbol")),
		f("organization_id", UTF8, Required), f("symbol_id", UUID, Required), f("graph_object_id", UUID, Required), f("object_class", UTF8, Required), f("symbol_kind", UTF8, Required), f("symbol_name", UTF8, Required), f("source_authority_id", UUID, Required), f("source_stable_reference", UTF8, Required), f("version_coordinate", UTF8, Required), f("section_path", UTF8, Required), f("graph_address", UTF8, Required),
	}}
}

func EdgeFactTupleV1() Profile {
	return Profile{Name: "ood_graph_immutable_fact_tuple_v1", Fields: []Field{
		f("canonicalization_profile", UTF8, Required, String("ood_graph_immutable_fact_tuple_v1")), f("table_discriminator", UTF8, Required, String("edge")),
		f("organization_id", UTF8, Required), f("graph_edge_id", UUID, Required), f("source_endpoint_kind", UTF8, Required), f("source_endpoint_id", UUID, Required), f("source_endpoint_class", UTF8, Required), f("target_endpoint_kind", UTF8, Required), f("target_endpoint_id", UUID, Required), f("target_endpoint_class", UTF8, Required), f("edge_label", UTF8, Required), f("edge_family", UTF8, Required), f("source_version_coordinate", UTF8, Required), f("target_version_coordinate", UTF8, Required), f("authoring_source_path", UTF8, Required), f("source_authority_id", UUID, Required), f("source_stable_reference", UTF8, Required),
		f("source_content_hash_algorithm", UTF8, Nullable), f("source_content_hash_profile", UTF8, Nullable), f("source_content_hash", SHA256, Nullable), f("valid_from", TimestampMicroseconds, Nullable), f("valid_until", TimestampMicroseconds, Nullable), f("diagnostic_only", Bool, Required),
	}}
}
