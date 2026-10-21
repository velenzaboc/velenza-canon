package main

import (
	"testing"
	"time"
)

func replayTestBatch() MaterializationBatch {
	confidence := float32(0.875)
	validFrom := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	return MaterializationBatch{
		Run: MaterializationRun{
			OrganizationID:       "org-replay",
			MaterializationRunID: "run-a",
		},
		Snapshot: GraphSnapshot{GraphSnapshotID: "snapshot-a"},
		Objects: []GraphObject{
			{
				GraphObjectID:         "object-a",
				ObjectClass:           "reference_page",
				SourceAuthorityID:     "authority-a",
				SourceArtifactClass:   "official_vendor_documentation",
				SourceRefKind:         "coordinate",
				SourceStableReference: "https://example.com/docs/a",
				VersionCoordinate:     "source:authority-a:page_a@sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				SectionPath:           "$",
				GraphAddress:          "reference_page://authority-a/coordinate/https%3A%2F%2Fexample.com%2Fdocs%2Fa@source%3Aauthority-a%3Apage_a%40sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa#%24",
				SourceContentHash:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				MaterializationRunID:  "run-a",
				SearchPayload:         map[string]interface{}{"transient_nonidentity": "left"},
			},
			{
				GraphObjectID:         "object-b",
				ObjectClass:           "api_symbol",
				SourceAuthorityID:     "authority-b",
				SourceArtifactClass:   "official_vendor_documentation",
				SourceRefKind:         "coordinate",
				SourceStableReference: "https://example.com/docs/b",
				VersionCoordinate:     "source:authority-b:symbol_b@sha256_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				SectionPath:           "$.symbol",
				GraphAddress:          "api_symbol://authority-b/coordinate/https%3A%2F%2Fexample.com%2Fdocs%2Fb@source%3Aauthority-b%3Asymbol_b%40sha256_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb#%24.symbol",
				SourceContentHash:     "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				MaterializationRunID:  "run-a",
			},
		},
		Symbols: []GraphSymbol{
			{SymbolID: "symbol-a", GraphObjectID: "object-a", ObjectClass: "reference_page", SymbolKind: "external_reference", SymbolName: "page_a", SourceAuthorityID: "authority-a", SourceStableReference: "https://example.com/docs/a", VersionCoordinate: "v-a", SectionPath: "$", GraphAddress: "ga-a", MaterializationRunID: "run-a"},
			{SymbolID: "symbol-b", GraphObjectID: "object-b", ObjectClass: "api_symbol", SymbolKind: "external_reference", SymbolName: "symbol_b", SourceAuthorityID: "authority-b", SourceStableReference: "https://example.com/docs/b", VersionCoordinate: "v-b", SectionPath: "$.symbol", GraphAddress: "ga-b", MaterializationRunID: "run-a"},
		},
		Edges: []GraphEdge{
			{GraphEdgeID: "edge-a", SourceEndpointKind: "graph_object", SourceEndpointID: "object-a", SourceEndpointClass: "reference_page", TargetEndpointKind: "graph_object", TargetEndpointID: "object-b", TargetEndpointClass: "api_symbol", EdgeLabel: "defines_external_symbol", SourceVersionCoordinate: "v-a", TargetVersionCoordinate: "v-b", AuthoringSourcePath: "$.relationships.a", SourceAuthorityID: "authority-a", SourceStableReference: "https://example.com/docs/a", SourceContentHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ValidFrom: &validFrom, EdgeConfidence: &confidence, MaterializationRunID: "run-a"},
			{GraphEdgeID: "edge-b", SourceEndpointKind: "graph_object", SourceEndpointID: "object-b", SourceEndpointClass: "api_symbol", TargetEndpointKind: "graph_object", TargetEndpointID: "object-a", TargetEndpointClass: "reference_page", EdgeLabel: "defined_by_external_source", SourceVersionCoordinate: "v-b", TargetVersionCoordinate: "v-a", AuthoringSourcePath: "$.relationships.b", SourceAuthorityID: "authority-b", SourceStableReference: "https://example.com/docs/b", SourceContentHash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", MaterializationRunID: "run-a"},
		},
		ProjectionArtifacts: []ProjectionArtifact{
			{ProjectionHash: "projection-b"},
			{ProjectionHash: "projection-a"},
		},
		Violations: []Violation{
			NewViolation("org-replay", "run-a", "snapshot-a", "R2", fullViolationCoordinateForTest()),
			NewViolation("org-replay", "run-a", "snapshot-a", "R1", alternateViolationCoordinateForTest()),
		},
	}
}

func TestReplayManifestIsSetOrderedAndRunIndependent(t *testing.T) {
	left := replayTestBatch()
	right := replayTestBatch()
	right.Run.MaterializationRunID = "run-b"
	right.Snapshot.GraphSnapshotID = "snapshot-b"
	for i := range right.Objects {
		right.Objects[i].GraphSnapshotID = "snapshot-b"
		right.Objects[i].MaterializationRunID = "run-b"
		right.Objects[i].SearchPayload = map[string]interface{}{"transient_nonidentity": "right"}
	}
	for i := range right.Symbols {
		right.Symbols[i].GraphSnapshotID = "snapshot-b"
		right.Symbols[i].MaterializationRunID = "run-b"
	}
	for i := range right.Edges {
		right.Edges[i].GraphSnapshotID = "snapshot-b"
		right.Edges[i].MaterializationRunID = "run-b"
	}
	reverseObjects(right.Objects)
	reverseSymbols(right.Symbols)
	reverseEdges(right.Edges)
	reverseProjections(right.ProjectionArtifacts)
	reverseViolations(right.Violations)

	equal, err := replayOutputsEquivalent(left, right)
	if err != nil {
		t.Fatalf("replayOutputsEquivalent: %v", err)
	}
	if !equal {
		t.Fatal("equivalent output sets changed because slice order, run/snapshot ids, or non-contract search payload changed")
	}
	leftDigest, err := replayManifestDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := replayManifestDigest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("equivalent replay digests differ: %s != %s", leftDigest, rightDigest)
	}
}

func TestReplayManifestDetectsEveryProtocolOutputFamily(t *testing.T) {
	base := replayTestBatch()
	tests := []struct {
		name   string
		mutate func(*MaterializationBatch)
	}{
		{"object_identity_or_address", func(b *MaterializationBatch) { b.Objects[0].GraphAddress += "-changed" }},
		{"object_content_hash_evidence", func(b *MaterializationBatch) {
			b.Objects[0].SourceContentHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		}},
		{"symbol", func(b *MaterializationBatch) { b.Symbols[0].SymbolName = "changed" }},
		{"edge", func(b *MaterializationBatch) { b.Edges[0].EdgeLabel = "version_note_for" }},
		{"projection_hash", func(b *MaterializationBatch) { b.ProjectionArtifacts[0].ProjectionHash = "changed" }},
		{"violation_coordinate", func(b *MaterializationBatch) { b.Violations[0].SectionPath = "$.changed" }},
		{"missing_object", func(b *MaterializationBatch) { b.Objects = b.Objects[:1] }},
		{"additional_edge", func(b *MaterializationBatch) { b.Edges = append(b.Edges, b.Edges[0]) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := replayTestBatch()
			tc.mutate(&candidate)
			equal, err := replayOutputsEquivalent(base, candidate)
			if err != nil {
				t.Fatalf("replayOutputsEquivalent: %v", err)
			}
			if equal {
				t.Fatal("mutated replay output was accepted as equivalent")
			}
		})
	}
}

func TestReplayManifestDetectsEveryViolationCoordinateOneAtATime(t *testing.T) {
	base := replayTestBatch()
	changedAddress := GraphAddress{
		ObjectClass:       "api_symbol",
		SourceAuthorityID: "22222222-2222-4222-8222-222222222222",
		SourceRefKind:     "coordinate",
		SourceRef:         "https://example.com/docs/changed",
		VersionCoordinate: "source:22222222-2222-4222-8222-222222222222:changed@sha256_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		SectionPath:       "$.changed",
	}.String()

	tests := []struct {
		name   string
		mutate func(*Violation)
	}{
		{"indexed_source_authority_id", func(v *Violation) { v.SourceAuthorityID += "-changed" }},
		{"indexed_source_stable_reference", func(v *Violation) { v.SourceStableReference += "?changed=1" }},
		{"indexed_version_coordinate", func(v *Violation) { v.VersionCoordinate += "-changed" }},
		{"indexed_section_path", func(v *Violation) { v.SectionPath = "$.changed" }},
		{"indexed_graph_object_id", func(v *Violation) { v.GraphObjectID += "-changed" }},
		{"indexed_symbol_id", func(v *Violation) { v.SymbolID += "-changed" }},
		{"indexed_graph_edge_id", func(v *Violation) { v.GraphEdgeID += "-changed" }},
		{"evidence_source_authority_id", func(v *Violation) { v.Evidence["source_authority_id"] = "changed-authority" }},
		{"evidence_source_stable_reference", func(v *Violation) { v.Evidence["source_stable_reference"] = "https://example.com/changed" }},
		{"evidence_version_coordinate", func(v *Violation) { v.Evidence["version_coordinate"] = "unversioned" }},
		{"evidence_section_path", func(v *Violation) { v.Evidence["section_path"] = "$.changed" }},
		{"graph_address", func(v *Violation) { v.Evidence["graph_address"] = changedAddress }},
		{"evidence_graph_object_id", func(v *Violation) { v.Evidence["graph_object_id"] = "changed-object" }},
		{"evidence_symbol_id", func(v *Violation) { v.Evidence["symbol_id"] = "changed-symbol" }},
		{"evidence_graph_edge_id", func(v *Violation) { v.Evidence["graph_edge_id"] = "changed-edge" }},
		{"edge_label", func(v *Violation) { v.Evidence["edge_label"] = "changed_label" }},
		{"source_endpoint_class", func(v *Violation) { v.Evidence["source_endpoint_class"] = "api_symbol" }},
		{"target_endpoint_class", func(v *Violation) { v.Evidence["target_endpoint_class"] = "reference_page" }},
		{"identity_tuple_field_names", func(v *Violation) {
			v.Evidence["identity_tuple_field_names"] = []interface{}{"graph_address", "new_field"}
		}},
		{"rejected_value_class", func(v *Violation) { v.Evidence["rejected_value_class"] = "changed_value_class" }},
		{"redacted_reason", func(v *Violation) { v.Evidence["redacted_reason"] = "changed_reason" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := replayTestBatch()
			tc.mutate(&candidate.Violations[0])
			equal, err := replayOutputsEquivalent(base, candidate)
			if err != nil {
				t.Fatalf("replayOutputsEquivalent: %v", err)
			}
			if equal {
				t.Fatal("one-coordinate divergence was accepted as replay-equivalent")
			}
		})
	}
}

func TestReplayManifestCanonicalizesViolationIdentityTupleOrder(t *testing.T) {
	left := replayTestBatch()
	right := replayTestBatch()
	left.Violations[0].Evidence["identity_tuple_field_names"] = []interface{}{"symbol_id", "graph_object_id"}
	right.Violations[0].Evidence["identity_tuple_field_names"] = []interface{}{"graph_object_id", "symbol_id"}

	equal, err := replayOutputsEquivalent(left, right)
	if err != nil {
		t.Fatalf("replayOutputsEquivalent: %v", err)
	}
	if !equal {
		t.Fatal("identity_tuple_field_names order changed a set-valued replay coordinate")
	}
}

func TestReplayManifestRejectsMalformedViolationEvidenceCoordinate(t *testing.T) {
	batch := replayTestBatch()
	batch.Violations[0].Evidence["edge_label"] = []interface{}{"not", "a", "string"}
	if _, err := buildReplayManifest(batch); err == nil {
		t.Fatal("non-string edge_label evidence was silently omitted from replay verification")
	}
}

func reverseObjects(v []GraphObject) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}

func reverseSymbols(v []GraphSymbol) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}

func reverseEdges(v []GraphEdge) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}

func reverseProjections(v []ProjectionArtifact) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}

func reverseViolations(v []Violation) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}
