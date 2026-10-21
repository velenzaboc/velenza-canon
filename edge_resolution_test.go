package main

import (
	"strings"
	"testing"
)

// Regression suite for §8 stages 11-12 resolved INSIDE the batch, and for
// the violation producer they feed.
//
// The behaviour under test is the one the live substrate proves was
// missing: OODGraphEdges holds zero rows and OODGraphViolations holds zero
// rows, and the second zero is why the first was never explained. Every
// rejection below must leave evidence, not just an absence.

func resolutionTestLabel(name, family string, sourceKinds, targetKinds []string, reciprocal string) EdgeLabelDescriptor {
	raw := map[string]interface{}{
		"name":        name,
		"edge_family": family,
	}
	if sourceKinds != nil {
		anyKinds := make([]interface{}, len(sourceKinds))
		for i, k := range sourceKinds {
			anyKinds[i] = k
		}
		raw["source_kinds"] = anyKinds
	}
	if targetKinds != nil {
		anyKinds := make([]interface{}, len(targetKinds))
		for i, k := range targetKinds {
			anyKinds[i] = k
		}
		raw["target_kinds"] = anyKinds
	}
	if reciprocal != "" {
		raw["reciprocal_label"] = reciprocal
	}
	return NewEdgeLabelDescriptor(raw)
}

func resolutionTestObject(id, class string) GraphObject {
	return GraphObject{
		OrganizationID:        "org-test",
		GraphSnapshotID:       "snap-new",
		GraphObjectID:         id,
		ObjectClass:           class,
		SourceAuthorityID:     "auth-a",
		SourceStableReference: id + "_ref",
		VersionCoordinate:     "unversioned",
		SectionPath:           "$",
		Status:                "active",
	}
}

// TestResolveEdgeEndpointsResolvesInsideTheBatch is the core R2 assertion:
// an edge whose endpoints are objects being written by the SAME run must
// resolve. Under the old cross-snapshot SELECT this case was unresolvable
// by construction — the objects are not committed yet, so no query against
// committed state can see them.
func TestResolveEdgeEndpointsResolvesInsideTheBatch(t *testing.T) {
	objects := []GraphObject{
		resolutionTestObject("obj-src", "axiom"),
		resolutionTestObject("obj-tgt", "section"),
	}
	label := resolutionTestLabel("references", "reference", []string{"axiom"}, []string{"section"}, "")

	edges, violations := ResolveEdgeEndpointsInBatch("org-test", "run-1", "snap-new", objects, []PendingEdge{{
		SourceEndpointID:  "obj-src",
		TargetEndpointID:  "obj-tgt",
		Label:             label,
		SourceAuthorityID: "auth-a",
	}})

	if len(violations) != 0 {
		t.Fatalf("resolvable edge produced %d violation(s): %+v", len(violations), violations)
	}
	if len(edges) != 1 {
		t.Fatalf("got %d edges; want 1", len(edges))
	}
	e := edges[0]
	if e.GraphSnapshotID != "snap-new" {
		t.Errorf("edge graph_snapshot_id = %q; want snap-new — the edge must land in the snapshot its endpoints do", e.GraphSnapshotID)
	}
	// The classes must be READ from the resolved rows, not asserted by the
	// caller — that is what makes success_preconditions[2] hold by
	// construction.
	if e.SourceEndpointClass != "axiom" || e.TargetEndpointClass != "section" {
		t.Errorf("endpoint classes = (%q,%q); want (axiom,section) read off the resolved object rows", e.SourceEndpointClass, e.TargetEndpointClass)
	}
	if e.SourceVersionCoordinate != "unversioned" || e.TargetVersionCoordinate != "unversioned" {
		t.Errorf("version coordinates = (%q,%q); want both read off the resolved rows", e.SourceVersionCoordinate, e.TargetVersionCoordinate)
	}
	if e.EdgeFamily != "reference" {
		t.Errorf("edge_family = %q; want reference", e.EdgeFamily)
	}
}

// TestResolveEdgeEndpointsEmitsViolationForUnresolvedEndpoint pins
// §8.unresolved_endpoint_handling: the edge is BLOCKED and a violation is
// EMITTED. Before the violation producer existed, this rejection was
// silent — the substrate looked identical to one where the edge had never
// been authored.
func TestResolveEdgeEndpointsEmitsViolationForUnresolvedEndpoint(t *testing.T) {
	objects := []GraphObject{resolutionTestObject("obj-src", "axiom")}
	label := resolutionTestLabel("references", "reference", []string{"axiom"}, []string{"section"}, "")

	edges, violations := ResolveEdgeEndpointsInBatch("org-test", "run-1", "snap-new", objects, []PendingEdge{{
		SourceEndpointID:  "obj-src",
		TargetEndpointID:  "obj-missing",
		Label:             label,
		SourceAuthorityID: "auth-a",
	}})

	if len(edges) != 0 {
		t.Errorf("an edge with an unresolved target materialized; §8.unresolved_endpoint_handling requires it blocked (got %d)", len(edges))
	}
	if len(violations) != 1 {
		t.Fatalf("got %d violations; want exactly 1 for the unresolved target", len(violations))
	}
	v := violations[0]
	if v.ViolationCode != ViolationEndpointReferenceUnresolved {
		t.Errorf("violation_code = %q; want %q", v.ViolationCode, ViolationEndpointReferenceUnresolved)
	}
	if v.Severity != "blocker" {
		t.Errorf("severity = %q; want blocker — the fact did not materialize", v.Severity)
	}
	if v.MaterializationRunID != "run-1" || v.GraphSnapshotID != "snap-new" {
		t.Errorf("violation not bound to its run/snapshot: run=%q snapshot=%q", v.MaterializationRunID, v.GraphSnapshotID)
	}
	if v.SentinelCandidate == "" {
		t.Error("violation carries no sentinel_candidate; §8.violation_emission.candidate_sentinel_mapping registers one for endpoint_reference")
	}
	if v.GraphObjectID != "obj-missing" {
		t.Errorf("violation must name the endpoint that failed to resolve; got graph_object_id=%q", v.GraphObjectID)
	}
}

// TestResolveEdgeEndpointsReportsBothUnresolvedEnds pins that source and
// target are reported separately — materialization_behavior names
// unresolved_source_endpoint and unresolved_target_endpoint as distinct
// behaviours, and collapsing them hides which end an operator must fix.
func TestResolveEdgeEndpointsReportsBothUnresolvedEnds(t *testing.T) {
	label := resolutionTestLabel("references", "reference", []string{"axiom"}, []string{"section"}, "")
	_, violations := ResolveEdgeEndpointsInBatch("org-test", "run-1", "snap-new", nil, []PendingEdge{{
		SourceEndpointID:  "gone-a",
		TargetEndpointID:  "gone-b",
		Label:             label,
		SourceAuthorityID: "auth-a",
	}})
	if len(violations) != 2 {
		t.Fatalf("got %d violations for an edge with BOTH endpoints unresolved; want 2", len(violations))
	}
	classes := map[string]bool{}
	for _, v := range violations {
		classes[v.Evidence["rejected_value_class"].(string)] = true
	}
	if !classes["source_endpoint_id"] || !classes["target_endpoint_id"] {
		t.Errorf("both ends must be named distinctly; got rejected_value_class set %v", classes)
	}
	// Distinct coordinates must yield distinct violation ids, or the two
	// findings collide into one row.
	if violations[0].ViolationID == violations[1].ViolationID {
		t.Error("both violations share a violation_id; the id must discriminate the coordinate")
	}
}

// TestResolveEdgeEndpointsEmitsViolationForForbiddenClassPair pins stage 12
// against the RESOLVED classes. This is the gate that correctly refuses the
// 214 live `concept`-endpoint sidecar edges — a refusal that must now leave
// evidence rather than an unexplained empty table.
func TestResolveEdgeEndpointsEmitsViolationForForbiddenClassPair(t *testing.T) {
	objects := []GraphObject{
		resolutionTestObject("obj-src", "concept"),
		resolutionTestObject("obj-tgt", "section"),
	}
	// `contains` declares no `concept` in its source_kinds, mirroring the
	// live registry.
	label := resolutionTestLabel("contains", "declaration_containment",
		[]string{"doc_object", "section", "symbol"}, []string{"section", "symbol"}, "")

	edges, violations := ResolveEdgeEndpointsInBatch("org-test", "run-1", "snap-new", objects, []PendingEdge{{
		SourceEndpointID:  "obj-src",
		TargetEndpointID:  "obj-tgt",
		Label:             label,
		SourceAuthorityID: "auth-a",
	}})

	if len(edges) != 0 {
		t.Errorf("a forbidden endpoint-class pair materialized; want 0 edges, got %d", len(edges))
	}
	if len(violations) != 1 {
		t.Fatalf("got %d violations; want 1", len(violations))
	}
	v := violations[0]
	if v.ViolationCode != ViolationEndpointClassPairForbidden {
		t.Errorf("violation_code = %q; want %q", v.ViolationCode, ViolationEndpointClassPairForbidden)
	}
	if v.Evidence["source_endpoint_class"] != "concept" {
		t.Errorf("evidence must carry the offending source_endpoint_class; got %v", v.Evidence["source_endpoint_class"])
	}
}

// TestResolveEdgeEndpointsCommitsReciprocalPairTogether pins
// §4.dependency_load_bearing_reciprocity's same-snapshot requirement: the
// mirror is produced in the SAME returned slice with cross-linked
// inverse_edge_ids, so both reach one CommitMaterializationRun.
func TestResolveEdgeEndpointsCommitsReciprocalPairTogether(t *testing.T) {
	objects := []GraphObject{
		resolutionTestObject("obj-src", "section"),
		resolutionTestObject("obj-tgt", "section"),
	}
	label := resolutionTestLabel("depends_on", "dependency", []string{"section"}, []string{"section"}, "load_bearing_for")
	mirror := resolutionTestLabel("load_bearing_for", "dependency", []string{"section"}, []string{"section"}, "depends_on")

	edges, violations := ResolveEdgeEndpointsInBatch("org-test", "run-1", "snap-new", objects, []PendingEdge{{
		SourceEndpointID:  "obj-src",
		TargetEndpointID:  "obj-tgt",
		Label:             label,
		MirrorLabel:       mirror,
		HasMirror:         true,
		SourceAuthorityID: "auth-a",
	}})

	if len(violations) != 0 {
		t.Fatalf("reciprocal pair produced violations: %+v", violations)
	}
	if len(edges) != 2 {
		t.Fatalf("got %d edges; want 2 (the pair must admit together in one snapshot)", len(edges))
	}
	fwd, inv := edges[0], edges[1]
	if fwd.InverseEdgeID != inv.GraphEdgeID || inv.InverseEdgeID != fwd.GraphEdgeID {
		t.Errorf("inverse_edge_ids are not cross-linked: fwd.inverse=%q inv.id=%q / inv.inverse=%q fwd.id=%q",
			fwd.InverseEdgeID, inv.GraphEdgeID, inv.InverseEdgeID, fwd.GraphEdgeID)
	}
	if fwd.ReciprocityState != "complete" || inv.ReciprocityState != "complete" {
		t.Errorf("reciprocity_state = (%q,%q); want both complete — §9.snapshot_scoped_traversal.reciprocity_rule excludes incomplete pairs from authoritative closure",
			fwd.ReciprocityState, inv.ReciprocityState)
	}
	if fwd.GraphSnapshotID != inv.GraphSnapshotID {
		t.Errorf("pair split across snapshots (%q vs %q); reciprocity_must_be_same_snapshot", fwd.GraphSnapshotID, inv.GraphSnapshotID)
	}
	if fwd.EdgeLabel != "depends_on" || inv.EdgeLabel != "load_bearing_for" {
		t.Errorf("pair labels = (%q,%q); want (depends_on,load_bearing_for)", fwd.EdgeLabel, inv.EdgeLabel)
	}
}

// TestResolveEdgeEndpointsBlocksMirrorWhenInverseClassPairForbidden pins
// endpoint_class_constraint_gate.reject_missing_inverse_for_required_reciprocity:
// if the inverse direction is illegal, NEITHER edge admits. A half-pair
// would be silently excluded from dependency closure by
// §9.snapshot_scoped_traversal.reciprocity_rule, so committing one is worse
// than committing none — it looks present and traverses as absent.
func TestResolveEdgeEndpointsBlocksMirrorWhenInverseClassPairForbidden(t *testing.T) {
	objects := []GraphObject{
		resolutionTestObject("obj-src", "axiom"),
		resolutionTestObject("obj-tgt", "section"),
	}
	label := resolutionTestLabel("depends_on", "dependency", []string{"axiom"}, []string{"section"}, "load_bearing_for")
	// The inverse permits only section→section, so the swapped pair
	// (section → axiom) is illegal.
	mirror := resolutionTestLabel("load_bearing_for", "dependency", []string{"section"}, []string{"section"}, "depends_on")

	edges, violations := ResolveEdgeEndpointsInBatch("org-test", "run-1", "snap-new", objects, []PendingEdge{{
		SourceEndpointID:  "obj-src",
		TargetEndpointID:  "obj-tgt",
		Label:             label,
		MirrorLabel:       mirror,
		HasMirror:         true,
		SourceAuthorityID: "auth-a",
	}})

	if len(edges) != 0 {
		t.Errorf("committed %d edge(s) when the required inverse is illegal; want 0 — a half-pair is excluded from closure anyway", len(edges))
	}
	if len(violations) != 1 {
		t.Fatalf("got %d violations; want 1 naming the illegal inverse direction", len(violations))
	}
	if violations[0].Evidence["edge_label"] != "load_bearing_for" {
		t.Errorf("violation must name the MIRROR label that failed; evidence edge_label = %v", violations[0].Evidence["edge_label"])
	}
}

// TestResolveEdgeEndpointsEdgeIDIsSnapshotIndependent pins
// §8.canonical_source_intake.stable_identity_preservation: graph_snapshot_id
// and materialization_run_id "never participate in stable identity". If a
// snapshot id leaked into the id tuple, every complete-snapshot run would
// mint a NEW id for the same logical edge and the graph would grow a
// duplicate per run instead of a new version of one edge.
func TestResolveEdgeEndpointsEdgeIDIsSnapshotIndependent(t *testing.T) {
	label := resolutionTestLabel("references", "reference", []string{"axiom"}, []string{"section"}, "")
	pending := []PendingEdge{{
		SourceEndpointID:  "obj-src",
		TargetEndpointID:  "obj-tgt",
		Label:             label,
		SourceAuthorityID: "auth-a",
	}}

	objectsA := []GraphObject{resolutionTestObject("obj-src", "axiom"), resolutionTestObject("obj-tgt", "section")}
	edgesA, violationsA := ResolveEdgeEndpointsInBatch("org-test", "run-1", "snap-one", objectsA, pending)

	objectsB := make([]GraphObject, len(objectsA))
	copy(objectsB, objectsA)
	for i := range objectsB {
		objectsB[i].GraphSnapshotID = "snap-two"
	}
	edgesB, violationsB := ResolveEdgeEndpointsInBatch("org-test", "run-2", "snap-two", objectsB, pending)

	if len(edgesA) != 1 || len(edgesB) != 1 || len(violationsA) != 0 || len(violationsB) != 0 {
		t.Fatalf("expected one valid edge and zero violations from each run; got edges=%d/%d violations=%d/%d", len(edgesA), len(edgesB), len(violationsA), len(violationsB))
	}
	if edgesA[0].GraphEdgeID != edgesB[0].GraphEdgeID {
		t.Errorf("graph_edge_id changed across snapshots (%s vs %s); snapshot/run ids must not participate in stable identity",
			edgesA[0].GraphEdgeID, edgesB[0].GraphEdgeID)
	}
	if edgesA[0].GraphSnapshotID == edgesB[0].GraphSnapshotID {
		t.Error("non-vacuity control failed: both runs wrote the same graph_snapshot_id, so the test proved nothing")
	}
}

// TestViolationEvidenceRejectsForbiddenFields pins the allowlist in
// §8.violation_emission. The forbidden list names exactly what a raise site
// reaches for when explaining itself — target title, summary, status,
// admission hashes, prose — so the filter must be an allowlist that fails
// closed, not a denylist.
func TestViolationEvidenceRejectsForbiddenFields(t *testing.T) {
	v := NewViolation("org-test", "run-1", "snap-new", ViolationEndpointReferenceUnresolved, ViolationCoordinate{
		SourceAuthorityID:  "auth-a",
		GraphObjectID:      "obj-missing",
		EdgeLabel:          "references",
		RejectedValueClass: "target_endpoint_id",
		RedactedReason:     "target_endpoint_not_in_snapshot",
	})

	forbidden := []string{
		"target_title", "target_summary", "target_status", "target_content",
		"signature_chain", "definition_hash", "manifest_hash",
		"rendered_prose_excerpt", "rejected_value", "payload", "contract",
	}
	for _, f := range forbidden {
		if _, present := v.Evidence[f]; present {
			t.Errorf("evidence carries forbidden field %q", f)
		}
	}
	for k := range v.Evidence {
		if !violationEvidenceAllowedFields[k] {
			t.Errorf("evidence carries %q, which is not in §8.violation_emission.evidence_allowed_fields", k)
		}
	}
	// Non-vacuity: the allowlist must not have filtered the evidence to
	// nothing, or the row would carry no actionable coordinate at all.
	if len(v.Evidence) < 3 {
		t.Errorf("evidence filtered down to %d field(s): %+v — a violation with no coordinate is not evidence", len(v.Evidence), v.Evidence)
	}
	if !strings.Contains(v.ViolationID, "-") || len(v.ViolationID) != 36 {
		t.Errorf("violation_id = %q; want a 36-char UUID", v.ViolationID)
	}
}

// TestViolationIDIsDeterministicPerRun pins
// §8.violation_emission.violation_id_stability. The tuple includes
// materialization_run_id, so the id is stable WITHIN a run and differs
// across runs — the emission is identified, while the finding is identified
// by the code+coordinate pair that same_inputs_same_outputs ranges over.
func TestViolationIDIsDeterministicPerRun(t *testing.T) {
	coord := ViolationCoordinate{
		SourceAuthorityID:  "auth-a",
		GraphObjectID:      "obj-missing",
		RejectedValueClass: "target_endpoint_id",
	}
	a := NewViolation("org-test", "run-1", "snap-new", ViolationEndpointReferenceUnresolved, coord)
	b := NewViolation("org-test", "run-1", "snap-new", ViolationEndpointReferenceUnresolved, coord)
	if a.ViolationID != b.ViolationID {
		t.Errorf("same run + same coordinate produced different ids (%s vs %s)", a.ViolationID, b.ViolationID)
	}
	c := NewViolation("org-test", "run-2", "snap-new", ViolationEndpointReferenceUnresolved, coord)
	if a.ViolationID == c.ViolationID {
		t.Error("different runs produced the same violation_id; materialization_run_id is a member of violation_id_stability")
	}
	d := NewViolation("org-test", "run-1", "snap-new", ViolationEndpointReferenceUnresolved, ViolationCoordinate{
		SourceAuthorityID:  "auth-a",
		GraphObjectID:      "obj-other",
		RejectedValueClass: "target_endpoint_id",
	})
	if a.ViolationID == d.ViolationID {
		t.Error("different coordinates produced the same violation_id")
	}
}
