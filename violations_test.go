package main

import (
	"strings"
	"testing"
)

func fullViolationCoordinateForTest() ViolationCoordinate {
	authorityID := "11111111-1111-4111-8111-111111111111"
	version := "source:" + authorityID + ":invoice@sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return ViolationCoordinate{
		SourceAuthorityID:     authorityID,
		SourceStableReference: "https://example.com/docs/invoice#symbol=Invoice",
		VersionCoordinate:     version,
		SectionPath:           "$.invoice",
		GraphAddress: GraphAddress{
			ObjectClass:       "api_symbol",
			SourceAuthorityID: authorityID,
			SourceRefKind:     "coordinate",
			SourceRef:         "https://example.com/docs/invoice#symbol=Invoice",
			VersionCoordinate: version,
			SectionPath:       "$.invoice",
		}.String(),
		GraphObjectID:           "object-invoice",
		SymbolID:                "symbol-invoice",
		GraphEdgeID:             "edge-invoice",
		EdgeLabel:               "defines_external_symbol",
		SourceEndpointClass:     "reference_page",
		TargetEndpointClass:     "api_symbol",
		RejectedValueClass:      "target_endpoint_id",
		IdentityTupleFieldNames: []string{"symbol_id", "graph_object_id"},
		RedactedReason:          "target_endpoint_not_in_snapshot",
	}
}

func alternateViolationCoordinateForTest() ViolationCoordinate {
	coord := fullViolationCoordinateForTest()
	coord.SourceStableReference = "https://example.com/docs/alternate"
	coord.SectionPath = "$.alternate"
	coord.GraphObjectID = "object-alternate"
	coord.SymbolID = "symbol-alternate"
	coord.GraphEdgeID = "edge-alternate"
	coord.GraphAddress = GraphAddress{
		ObjectClass:       "reference_page",
		SourceAuthorityID: coord.SourceAuthorityID,
		SourceRefKind:     "coordinate",
		SourceRef:         coord.SourceStableReference,
		VersionCoordinate: coord.VersionCoordinate,
		SectionPath:       coord.SectionPath,
	}.String()
	return coord
}

func TestViolationIDIncludesEveryRegisteredCoordinateOneAtATime(t *testing.T) {
	baseCoord := fullViolationCoordinateForTest()
	base := NewViolation("org-test", "run-test", "snapshot-test", ViolationEndpointReferenceUnresolved, baseCoord)
	changedAddress := alternateViolationCoordinateForTest().GraphAddress

	tests := []struct {
		name   string
		mutate func(*ViolationCoordinate)
	}{
		{"source_authority_id", func(c *ViolationCoordinate) { c.SourceAuthorityID += "-changed" }},
		{"source_stable_reference", func(c *ViolationCoordinate) { c.SourceStableReference += "?changed=1" }},
		{"version_coordinate", func(c *ViolationCoordinate) { c.VersionCoordinate = "unversioned" }},
		{"section_path", func(c *ViolationCoordinate) { c.SectionPath = "$.changed" }},
		{"graph_address", func(c *ViolationCoordinate) { c.GraphAddress = changedAddress }},
		{"graph_object_id", func(c *ViolationCoordinate) { c.GraphObjectID += "-changed" }},
		{"symbol_id", func(c *ViolationCoordinate) { c.SymbolID += "-changed" }},
		{"graph_edge_id", func(c *ViolationCoordinate) { c.GraphEdgeID += "-changed" }},
		{"edge_label", func(c *ViolationCoordinate) { c.EdgeLabel = "changed_label" }},
		{"source_endpoint_class", func(c *ViolationCoordinate) { c.SourceEndpointClass = "api_symbol" }},
		{"target_endpoint_class", func(c *ViolationCoordinate) { c.TargetEndpointClass = "reference_page" }},
		{"identity_tuple_field_names", func(c *ViolationCoordinate) {
			c.IdentityTupleFieldNames = []string{"graph_object_id", "new_field"}
		}},
		{"rejected_value_class", func(c *ViolationCoordinate) { c.RejectedValueClass = "changed_value_class" }},
		{"redacted_reason", func(c *ViolationCoordinate) { c.RedactedReason = "changed_reason" }},
	}

	seen := map[string]string{base.ViolationID: "base"}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			coord := fullViolationCoordinateForTest()
			tc.mutate(&coord)
			got := NewViolation("org-test", "run-test", "snapshot-test", ViolationEndpointReferenceUnresolved, coord)
			if got.ViolationID == base.ViolationID {
				t.Fatalf("coordinate %s did not participate in violation_id", tc.name)
			}
			if prior, exists := seen[got.ViolationID]; exists {
				t.Fatalf("coordinate %s collided with %s at violation_id=%s", tc.name, prior, got.ViolationID)
			}
			seen[got.ViolationID] = tc.name
		})
	}
}

func TestViolationIDFramesDelimiterBearingCoordinates(t *testing.T) {
	left := fullViolationCoordinateForTest()
	right := fullViolationCoordinateForTest()
	left.SourceAuthorityID = "authority|stable"
	left.SourceStableReference = "reference"
	right.SourceAuthorityID = "authority"
	right.SourceStableReference = "stable|reference"

	a := NewViolation("org-test", "run-test", "snapshot-test", ViolationEndpointReferenceUnresolved, left)
	b := NewViolation("org-test", "run-test", "snapshot-test", ViolationEndpointReferenceUnresolved, right)
	if a.ViolationID == b.ViolationID {
		t.Fatal("distinct delimiter-bearing coordinate tuples collapsed to one violation_id")
	}
}

func TestViolationIDCanonicalizesSetOrderAndGraphAddress(t *testing.T) {
	left := fullViolationCoordinateForTest()
	right := fullViolationCoordinateForTest()
	left.IdentityTupleFieldNames = []string{"symbol_id", "graph_object_id"}
	right.IdentityTupleFieldNames = []string{"graph_object_id", "symbol_id"}
	// Lowercase percent escapes parse to the same address; identity and
	// evidence must use the canonical uppercase serialization.
	right.GraphAddress = strings.ReplaceAll(right.GraphAddress, "%2F", "%2f")
	if right.GraphAddress == left.GraphAddress {
		t.Fatal("test fixture had no percent-encoded slash to de-canonicalize")
	}

	a := NewViolation("org-test", "run-test", "snapshot-test", ViolationEndpointReferenceUnresolved, left)
	b := NewViolation("org-test", "run-test", "snapshot-test", ViolationEndpointReferenceUnresolved, right)
	if a.ViolationID != b.ViolationID {
		t.Fatalf("canonical-equivalent coordinates produced different ids: %s != %s", a.ViolationID, b.ViolationID)
	}
	if a.Evidence["graph_address"] != b.Evidence["graph_address"] {
		t.Fatalf("canonical graph_address evidence differs: %v != %v", a.Evidence["graph_address"], b.Evidence["graph_address"])
	}
}
