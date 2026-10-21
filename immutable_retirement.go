package main

import (
	"context"
	"fmt"
)

// ArchiveEdge fails before any database access. OOD Graph v1 requires
// retirement to publish a later, fully validated complete snapshot while
// preserving every prior sealed row. The current class/edge registries do
// not provide a protocol-valid representation for all retirements, so an
// in-place status update or bespoke audit snapshot would corrupt history.
func (a *SpannerSubstrateAdapter) ArchiveEdge(_ context.Context, orgID, edgeID, admitterLiteral string) (EdgeArchiveResult, error) {
	if edgeID == "" {
		return EdgeArchiveResult{}, fmt.Errorf("ArchiveEdge: empty edge_id")
	}
	if orgID == "" {
		return EdgeArchiveResult{}, fmt.Errorf("ArchiveEdge: empty organization_id")
	}
	if admitterLiteral == "" {
		return EdgeArchiveResult{}, fmt.Errorf("ArchiveEdge: empty admitter")
	}
	return EdgeArchiveResult{}, ErrOODGraphImmutableRetirementUnavailable
}

// ArchiveNode has the same fail-closed posture as ArchiveEdge. No prior
// snapshot row is ever UPDATEd, so pinned historical reads remain immutable.
func (a *SpannerSubstrateAdapter) ArchiveNode(_ context.Context, orgID, nodeID, admitterLiteral string) (NodeArchiveResult, error) {
	if nodeID == "" {
		return NodeArchiveResult{}, fmt.Errorf("ArchiveNode: empty graph_object_id")
	}
	if orgID == "" {
		return NodeArchiveResult{}, fmt.Errorf("ArchiveNode: empty organization_id")
	}
	if admitterLiteral == "" {
		return NodeArchiveResult{}, fmt.Errorf("ArchiveNode: empty admitter")
	}
	return NodeArchiveResult{}, ErrOODGraphImmutableRetirementUnavailable
}
