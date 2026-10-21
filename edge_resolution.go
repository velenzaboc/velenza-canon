package main

import (
	"fmt"

	"github.com/google/uuid"
)

// edge_resolution.go implements §8 pipeline stages 11 and 12 —
// resolve_edge_endpoints and validate_endpoint_class_constraints — against
// the IN-FLIGHT batch rather than against the live substrate.
//
// The read it replaces is the load-bearing defect. handleLink resolved
// endpoints through lookupObjectClassAndVersion, whose SQL is
//
//	SELECT object_class, version_coordinate FROM <objects>
//	WHERE organization_id=.. AND graph_object_id=.. AND status='active'
//	ORDER BY updated_at DESC LIMIT 1
//
// — no graph_snapshot_id predicate anywhere. That is a cross-snapshot read,
// and it is forbidden twice over:
//
//   - §8.snapshot_production_contract.success_preconditions[2] requires
//     "all active edge endpoints resolve to OODGraphObjects.graph_object_id
//     inside the same graph_snapshot_id". Resolving against whatever row is
//     newest ACROSS snapshots can satisfy the lookup while violating the
//     precondition, which is exactly how an edge-only snapshot with zero
//     objects in it came to look admissible.
//   - §9.historical_snapshot_selection.snapshot_scope_rule scopes every
//     consumed row to one graph_snapshot_id.
//
// Resolving inside the batch also removes an ordering hazard that no amount
// of care at the call site could fix: an edge whose endpoint object is
// being created by the SAME run cannot be resolved by a query against
// committed state, because the object is not committed yet.

// PendingEdge is one authored edge before endpoint resolution: endpoint
// IDENTIFIERS plus the label descriptors, with no endpoint classes or
// version coordinates yet. Those are outputs of resolution, not inputs —
// taking them as inputs is what let a caller assert an endpoint class the
// snapshot did not actually contain.
type PendingEdge struct {
	SourceEndpointID string
	TargetEndpointID string

	// Label is the resolved descriptor for the authored direction.
	Label EdgeLabelDescriptor

	// MirrorLabel is the descriptor for the reciprocal direction when
	// Label.ReciprocalLabel() is non-empty. §4's reciprocity contract
	// requires the mirror to admit in the SAME snapshot
	// (reciprocity_must_be_same_snapshot), so it is resolved and emitted
	// here rather than by a follow-up call.
	MirrorLabel EdgeLabelDescriptor

	// HasMirror discriminates "no reciprocal label declared" from "a
	// zero-valued descriptor", which a bare struct check cannot.
	HasMirror bool

	AuthoringSourcePath string
	SourceAuthorityID   string
	VisibilityScope     string
}

// ResolveEdgeEndpointsInBatch resolves every pending edge against the
// objects being written into THIS snapshot, and returns the edges that
// resolved plus a violation for every fact it refused.
//
// The contract is fail-closed per edge, not per batch: one unresolvable
// edge blocks that edge and emits evidence, and the rest of the run
// proceeds. That is what §8.unresolved_endpoint_handling asks for —
// "emit OODGraphViolations with endpoint_reference_unresolved_or_wrong_key
// and block active edge materialization" — and it is deliberately narrower
// than aborting: successful_authoritative_closure_member_allowed=false
// forbids the bad edge from reaching authoritative closure, not the good
// edges from existing.
//
// Returning violations rather than a bare error is the point. A Go error
// vanishes when the process exits; a violation row is queryable evidence
// bound to the run and snapshot that refused the fact.
func ResolveEdgeEndpointsInBatch(
	orgID, runID, snapshotID string,
	objects []GraphObject,
	pending []PendingEdge,
) ([]GraphEdge, []Violation) {
	// Index the batch's own objects. This index IS the resolution scope —
	// there is no fallback to a live query, deliberately: a fallback would
	// reintroduce the cross-snapshot read under a name that looks safe.
	index := make(map[string]GraphObject, len(objects))
	for _, o := range objects {
		index[o.GraphObjectID] = o
	}

	edges := make([]GraphEdge, 0, len(pending))
	violations := make([]Violation, 0)

	for _, pe := range pending {
		src, srcOK := index[pe.SourceEndpointID]
		tgt, tgtOK := index[pe.TargetEndpointID]

		// Stage 11 resolve_edge_endpoints. Source and target are reported
		// separately because
		// §8.unresolved_endpoint_handling.materialization_behavior names
		// unresolved_source_endpoint and unresolved_target_endpoint as
		// distinct behaviours, and an operator fixing one needs to know
		// which end failed.
		if !srcOK || !tgtOK {
			if !srcOK {
				violations = append(violations, NewViolation(orgID, runID, snapshotID,
					ViolationEndpointReferenceUnresolved, ViolationCoordinate{
						SourceAuthorityID:       pe.SourceAuthorityID,
						GraphObjectID:           pe.SourceEndpointID,
						EdgeLabel:               pe.Label.Name(),
						RejectedValueClass:      "source_endpoint_id",
						IdentityTupleFieldNames: []string{"source_endpoint_id", "graph_snapshot_id"},
						RedactedReason:          "source_endpoint_not_in_snapshot",
					}))
			}
			if !tgtOK {
				violations = append(violations, NewViolation(orgID, runID, snapshotID,
					ViolationEndpointReferenceUnresolved, ViolationCoordinate{
						SourceAuthorityID:       pe.SourceAuthorityID,
						GraphObjectID:           pe.TargetEndpointID,
						EdgeLabel:               pe.Label.Name(),
						RejectedValueClass:      "target_endpoint_id",
						IdentityTupleFieldNames: []string{"target_endpoint_id", "graph_snapshot_id"},
						RedactedReason:          "target_endpoint_not_in_snapshot",
					}))
			}
			continue
		}

		// Stage 12 validate_endpoint_class_constraints, on the classes read
		// off the RESOLVED rows rather than on classes the caller asserted.
		if err := validateEdgeEndpointClasses(pe.Label, pe.SourceEndpointID, src.ObjectClass, pe.TargetEndpointID, tgt.ObjectClass); err != nil {
			violations = append(violations, endpointClassViolation(orgID, runID, snapshotID, pe, src, tgt, pe.Label.Name()))
			continue
		}
		if pe.HasMirror {
			// The mirror runs the SAME gate with the endpoints swapped. A
			// label pair whose inverse forbids the reverse class pair would
			// otherwise commit a half-pair, and
			// §8.validation_gates_before_projection.endpoint_class_constraint_gate
			// .reject_missing_inverse_for_required_reciprocity makes an
			// incomplete required pair a rejection, not a partial success.
			if err := validateEdgeEndpointClasses(pe.MirrorLabel, pe.TargetEndpointID, tgt.ObjectClass, pe.SourceEndpointID, src.ObjectClass); err != nil {
				violations = append(violations, endpointClassViolation(orgID, runID, snapshotID, pe, tgt, src, pe.MirrorLabel.Name()))
				continue
			}
		}

		visibility := pe.VisibilityScope
		if visibility == "" {
			visibility = "organization"
		}

		edge := buildResolvedEdge(orgID, snapshotID, runID, pe, src, tgt, pe.Label, visibility)
		if pe.HasMirror {
			mirror := buildResolvedEdge(orgID, snapshotID, runID, PendingEdge{
				SourceEndpointID:    pe.TargetEndpointID,
				TargetEndpointID:    pe.SourceEndpointID,
				AuthoringSourcePath: pe.AuthoringSourcePath,
				SourceAuthorityID:   pe.SourceAuthorityID,
			}, tgt, src, pe.MirrorLabel, visibility)
			// Cross-link BOTH directions before either is appended, so the
			// pair is complete in one batch and therefore in one snapshot
			// and one transaction, per
			// §4.dependency_load_bearing_reciprocity.
			edge.InverseEdgeID = mirror.GraphEdgeID
			edge.ReciprocityState = "complete"
			mirror.InverseEdgeID = edge.GraphEdgeID
			mirror.ReciprocityState = "complete"
			edges = append(edges, edge, mirror)
			continue
		}
		edges = append(edges, edge)
	}

	return edges, violations
}

// endpointClassViolation renders a stage-12 rejection. Only the endpoint
// CLASSES reach the evidence, never the rejected object's content:
// source_endpoint_class and target_endpoint_class are registered members of
// §8.violation_emission.evidence_allowed_fields, and the sibling
// evidence_forbidden_fields list bars target title, summary and status.
func endpointClassViolation(orgID, runID, snapshotID string, pe PendingEdge, src, tgt GraphObject, label string) Violation {
	return NewViolation(orgID, runID, snapshotID, ViolationEndpointClassPairForbidden, ViolationCoordinate{
		SourceAuthorityID:       pe.SourceAuthorityID,
		GraphObjectID:           src.GraphObjectID,
		EdgeLabel:               label,
		SourceEndpointClass:     src.ObjectClass,
		TargetEndpointClass:     tgt.ObjectClass,
		RejectedValueClass:      "endpoint_class_pair",
		IdentityTupleFieldNames: []string{"source_endpoint_class", "target_endpoint_class", "edge_label"},
		RedactedReason:          "endpoint_class_pair_not_permitted_by_edge_label",
	})
}

// buildResolvedEdge constructs a GraphEdge from RESOLVED endpoint rows.
//
// It differs from handlers.go's buildEdgeRow in what it is allowed to
// believe: every endpoint class and version coordinate here is read off the
// object row that is going into this same snapshot, so
// §8.snapshot_production_contract.success_preconditions[2] holds by
// construction rather than by the caller's assurance.
//
// graph_edge_id is UUIDv5 over the identity tuple
// §8.canonical_source_intake.stable_identity_preservation
// .graph_edge_id_stability_rule names — resolved source endpoint, resolved
// target endpoint, edge_label, both version coordinates,
// authoring_source_path, source_authority_id and source_stable_reference.
// graph_snapshot_id and materialization_run_id are deliberately NOT in the
// tuple: graph_snapshot_id_role and materialization_run_id_role both state
// they never participate in stable identity, which is precisely what lets
// the same logical edge keep one id across snapshots.
func buildResolvedEdge(orgID, snapshotID, runID string, pe PendingEdge, src, tgt GraphObject, label EdgeLabelDescriptor, visibility string) GraphEdge {
	sourceStableRef := src.SourceStableReference
	idInput := fmt.Sprintf("edge|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		orgID,
		src.GraphObjectID, tgt.GraphObjectID,
		label.Name(),
		src.VersionCoordinate, tgt.VersionCoordinate,
		pe.AuthoringSourcePath,
		src.SourceAuthorityID,
		sourceStableRef)
	edgeID := uuid.NewSHA1(oodGraphIDNamespace, []byte(idInput)).String()

	authoringPath := pe.AuthoringSourcePath
	if authoringPath == "" {
		authoringPath = "$"
	}

	edge := GraphEdge{
		OrganizationID:          orgID,
		GraphSnapshotID:         snapshotID,
		GraphEdgeID:             edgeID,
		SourceEndpointKind:      "graph_object",
		SourceEndpointID:        src.GraphObjectID,
		SourceEndpointClass:     src.ObjectClass,
		TargetEndpointKind:      "graph_object",
		TargetEndpointID:        tgt.GraphObjectID,
		TargetEndpointClass:     tgt.ObjectClass,
		EdgeLabel:               label.Name(),
		EdgeFamily:              label.EdgeFamily(),
		SourceVersionCoordinate: src.VersionCoordinate,
		TargetVersionCoordinate: tgt.VersionCoordinate,
		AuthoringSourcePath:     authoringPath,
		SourceAuthorityID:       src.SourceAuthorityID,
		SourceStableReference:   sourceStableRef,
		SourceContentHash:       src.SourceContentHash,
		DiagnosticOnly:          label.DiagnosticOnly(),
		ReciprocityState:        "not_required",
		MaterializationRunID:    runID,
		ValidationState:         "valid",
		Status:                  "active",
		VisibilityScope:         visibility,
		EmbeddingModel:          "",
	}
	// Only registered edge/class metadata enters search columns. Endpoint
	// content, titles, and summaries have no input slot.
	edge.SearchText = graphOwnedEdgeSearchText(edge)
	edge.SearchPayload = graphOwnedEdgeSearchPayload(edge)
	return edge
}
