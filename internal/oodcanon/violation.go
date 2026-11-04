package oodcanon

// ViolationManifestMemberV1 is the owner-pinned immutable member tuple for a
// selected OODGraphViolations row. Its evidence digest is supplied only after
// the physical owner has validated and RFC-8785-canonicalized the closed JSON
// evidence grammar.
func ViolationManifestMemberV1() Profile {
	return Profile{Name: "ood_graph_violation_manifest_member_v1", Fields: []Field{
		f("canonicalization_profile", UTF8, Required, String("ood_graph_violation_manifest_member_v1")),
		f("organization_id", UTF8, Required), f("violation_id", UUID, Required),
		f("graph_snapshot_id", UUID, Nullable), f("materialization_run_id", UUID, Nullable),
		f("violation_code", UTF8, Required), f("sentinel_candidate", UTF8, Nullable), f("severity", UTF8, Required),
		f("source_authority_id", UUID, Nullable), f("source_stable_reference", UTF8, Nullable), f("version_coordinate", UTF8, Nullable), f("section_path", UTF8, Nullable),
		f("graph_object_id", UUID, Nullable), f("symbol_id", UUID, Nullable), f("graph_edge_id", UUID, Nullable), f("evidence_sha256", SHA256, Required),
	}}
}
