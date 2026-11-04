package oodpublication

// OOD v8 physical contracts used by the production adapter. They are kept as
// closed column rosters so a SQL mapper cannot silently omit a fence/root when
// the generated schema evolves. DDL application is deliberately outside this
// package and its tests.
const (
	TableSnapshots        = "OODGraphSnapshots"
	TableSnapshotHeads    = "OODGraphSnapshotHeads"
	TablePublicationState = "OODGraphPublicationState"
	TableRuns             = "OODGraphMaterializationRuns"
	TableCertificates     = "OODGraphClosureVerificationCertificates"
)

var snapshotColumns = []string{
	"organization_id", "graph_snapshot_id", "graph_version", "snapshot_kind",
	"predecessor_graph_snapshot_id", "predecessor_head_generation", "predecessor_snapshot_envelope_hash",
	"published_head_generation", "predecessor_org_publication_state_hash", "published_org_publication_generation", "published_org_publication_state_hash",
	"source_set_hash", "source_manifest_root_hash", "source_artifact_count", "relationship_evidence_count",
	"materialization_profile_id", "materialization_profile_version", "materialization_profile_digest",
	"object_manifest_root_hash", "symbol_manifest_root_hash", "edge_manifest_root_hash", "api_property_manifest_root_hash",
	"graph_fact_locator_manifest_root_hash", "receipt_manifest_root_hash", "structural_projection_manifest_root_hash", "violation_manifest_root_hash",
	"object_count", "symbol_count", "edge_count", "api_property_count", "graph_fact_locator_count", "receipt_count", "structural_projection_count", "violation_count",
	"closure_hash", "verification_certificate_id", "verification_certificate_hash", "snapshot_envelope_hash", "materialization_run_id", "snapshot_state", "status", "visibility_scope",
}

var snapshotHeadColumns = []string{
	"organization_id", "snapshot_kind", "graph_snapshot_id", "graph_version", "head_generation", "source_set_hash", "source_manifest_root_hash", "source_artifact_count", "relationship_evidence_count",
	"materialization_profile_id", "materialization_profile_version", "materialization_profile_digest", "receipt_manifest_root_hash", "closure_hash", "verification_certificate_id", "verification_certificate_hash", "snapshot_envelope_hash", "kind_head_fence_hash",
}

var publicationStateColumns = []string{
	"organization_id", "current_graph_version", "publication_generation", "last_graph_snapshot_id", "last_snapshot_kind", "last_snapshot_envelope_hash", "predecessor_publication_state_hash", "publication_state_hash",
}

var runColumns = []string{
	"organization_id", "materialization_run_id", "target_graph_snapshot_id", "run_kind", "input_source_set_hash", "input_source_manifest_root_hash", "input_source_count", "input_relationship_evidence_count",
	"materialization_profile_id", "materialization_profile_version", "materialization_profile_digest", "publication_budget_profile_ref", "publication_budget_profile_digest",
	"candidate_closure_hash", "candidate_verification_certificate_id", "candidate_verification_certificate_hash", "compared_predecessor_graph_snapshot_id", "compared_predecessor_head_generation", "compared_predecessor_closure_hash", "closure_comparison_result", "state", "object_count", "symbol_count", "edge_count", "violation_count", "status", "visibility_scope",
}

func copyColumns(in []string) []string    { return append([]string(nil), in...) }
func SnapshotColumns() []string           { return copyColumns(snapshotColumns) }
func SnapshotHeadColumns() []string       { return copyColumns(snapshotHeadColumns) }
func PublicationStateColumns() []string   { return copyColumns(publicationStateColumns) }
func MaterializationRunColumns() []string { return copyColumns(runColumns) }
