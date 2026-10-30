package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func apiRelationshipLabel(name string) EdgeLabelDescriptor {
	return NewEdgeLabelDescriptor(map[string]interface{}{
		"name": name, "edge_family": "api_relationship",
		"source_kinds": []interface{}{"api_symbol"}, "target_kinds": []interface{}{"api_symbol"},
	})
}

func completeAPIRelationshipRegistry() []EdgeLabelDescriptor {
	labels := make([]EdgeLabelDescriptor, 0, len(apiRelationshipEdgeContracts))
	for name := range apiRelationshipEdgeContracts {
		labels = append(labels, apiRelationshipLabel(name))
	}
	return labels
}

func apiTestObject(id, role string) GraphObject {
	return GraphObject{
		OrganizationID: "org-test", GraphSnapshotID: "snap-test", GraphObjectID: id,
		ObjectClass: "api_symbol", APIElementRole: role,
		APIElementRoleLocatorManifestHash: strings.Repeat("a", 64),
		SourceAuthorityID:                 "auth-test", SourceStableReference: id, VersionCoordinate: "unversioned",
	}
}

func TestAPIRelationshipRegistryIsClosedAndComplete(t *testing.T) {
	if err := validateAPIRelationshipEdgeRegistry(completeAPIRelationshipRegistry()); err != nil {
		t.Fatalf("complete OOD API registry rejected: %v", err)
	}
	labels := completeAPIRelationshipRegistry()
	labels[0] = NewEdgeLabelDescriptor(map[string]interface{}{
		"name": "unregistered_provider_link", "edge_family": "api_relationship",
		"source_kinds": []interface{}{"api_symbol"}, "target_kinds": []interface{}{"api_symbol"},
	})
	if err := validateAPIRelationshipEdgeRegistry(labels); err == nil {
		t.Fatal("unknown api_relationship label accepted")
	}
	badPair := completeAPIRelationshipRegistry()
	badPair[0] = NewEdgeLabelDescriptor(map[string]interface{}{
		"name": badPair[0].Name(), "edge_family": "api_relationship",
		"source_kinds": []interface{}{"section"}, "target_kinds": []interface{}{"api_symbol"},
	})
	if err := validateAPIRelationshipEdgeRegistry(badPair); err == nil {
		t.Fatal("non-api_symbol endpoint route accepted")
	}
}

func TestAPIRelationshipNestedChainAndHostileScope(t *testing.T) {
	objects := []GraphObject{
		apiTestObject("provider", "provider"), apiTestObject("service", "service"),
		apiTestObject("api", "vendor_api"), apiTestObject("resource", "resource"),
		apiTestObject("operation", "operation"),
	}
	pending := []PendingEdge{
		{SourceEndpointID: "provider", TargetEndpointID: "service", Label: apiRelationshipLabel("provider_has_service")},
		{SourceEndpointID: "service", TargetEndpointID: "api", Label: apiRelationshipLabel("service_has_api")},
		{SourceEndpointID: "api", TargetEndpointID: "resource", Label: apiRelationshipLabel("api_has_resource")},
		{SourceEndpointID: "resource", TargetEndpointID: "operation", Label: apiRelationshipLabel("resource_has_operation")},
	}
	edges, violations := ResolveEdgeEndpointsInBatch("org-test", "run-test", "snap-test", objects, pending)
	if len(edges) != 0 || len(violations) != len(pending) {
		t.Fatalf("unverified nested chain edges=%d violations=%d, want 0/%d", len(edges), len(violations), len(pending))
	}
	objects[1].APIElementRole = "resource"
	edges, violations = ResolveEdgeEndpointsInBatch("org-test", "run-test", "snap-test", objects, pending[:1])
	if len(edges) != 0 || len(violations) != 1 {
		t.Fatalf("wrong role pair edges=%d violations=%d, want 0/1", len(edges), len(violations))
	}
	objects[1].APIElementRole = "service"
	objects[1].GraphSnapshotID = "foreign-snapshot"
	edges, violations = ResolveEdgeEndpointsInBatch("org-test", "run-test", "snap-test", objects, pending[:1])
	if len(edges) != 0 || len(violations) != 1 {
		t.Fatalf("foreign snapshot edges=%d violations=%d, want 0/1", len(edges), len(violations))
	}
	objects[1].GraphSnapshotID = "snap-test"
	objects[1].OrganizationID = "foreign-org"
	edges, violations = ResolveEdgeEndpointsInBatch("org-test", "run-test", "snap-test", objects, pending[:1])
	if len(edges) != 0 || len(violations) != 1 {
		t.Fatalf("foreign organization edges=%d violations=%d, want 0/1", len(edges), len(violations))
	}
}

func TestAPIElementRoleAndLocatorFailClosed(t *testing.T) {
	object := apiTestObject("resource", "resource")
	if err := validateAPIElementRoleShape(object); err != nil {
		t.Fatalf("valid api row shape rejected: %v", err)
	}
	if err := validateAPIElementRoleObject(object); !errors.Is(err, ErrAPIElementRoleEvidenceVerifierUnavailable) {
		t.Fatalf("unverified api role error=%v, want verifier-unavailable refusal", err)
	}
	object.APIElementRoleLocatorManifestHash = "not-a-hash"
	if err := validateAPIElementRoleObject(object); err == nil {
		t.Fatal("malformed locator hash accepted")
	}
	object = apiTestObject("resource", "unregistered")
	if err := validateAPIElementRoleObject(object); err == nil {
		t.Fatal("unknown role accepted")
	}
	nonAPI := apiTestObject("section", "resource")
	nonAPI.ObjectClass = "section"
	if err := validateAPIElementRoleObject(nonAPI); err == nil {
		t.Fatal("role fields on non-api object accepted")
	}
}

func TestAPIConfiguredRegistryCannotBeAbsent(t *testing.T) {
	cfg := SpecGraphConfig{NodeKinds: []NodeKindDescriptor{NewNodeKindDescriptor(map[string]interface{}{"name": "api_symbol"})}}
	if err := validateAPIRelationshipRegistryForConfig(cfg); err == nil || !strings.Contains(err.Error(), "requires edge_label") {
		t.Fatalf("api_symbol configuration without closed API registry error=%v, want required-label refusal", err)
	}
	if err := validateAPIRelationshipRegistryForConfig(SpecGraphConfig{}); err != nil {
		t.Fatalf("config without api_symbol unexpectedly requires API registry: %v", err)
	}
	edgeOnly := SpecGraphConfig{EdgeLabels: []EdgeLabelDescriptor{apiRelationshipLabel("provider_has_service")}}
	if err := validateAPIRelationshipRegistryForConfig(edgeOnly); err == nil || !strings.Contains(err.Error(), "requires edge_label") {
		t.Fatalf("partial api_relationship-only configuration error=%v, want required-label refusal", err)
	}
}

func TestAPIRoleLocatorMutationChangesCanonicalMaterial(t *testing.T) {
	a := apiTestObject("resource", "resource")
	b := a
	b.APIElementRoleLocatorManifestHash = strings.Repeat("b", 64)
	if _, err := mergeGraphObjectsByID([]GraphObject{a}, []GraphObject{b}); err == nil {
		t.Fatal("role locator mutation was erased from canonical/replay material")
	}
}

func TestAPIRoleLocatorMigrationMatchesFreshSchema(t *testing.T) {
	migration, err := os.ReadFile("bootstrap/migrations/003_ood_graph_api_role_locator.sql")
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := os.ReadFile("bootstrap/schema_v2.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"api_element_role", "api_element_role_locator_manifest_hash", "OODGraphObjectsByApiRoleLocatorManifest",
	} {
		if !strings.Contains(string(migration), required) || !strings.Contains(string(fresh), required) {
			t.Fatalf("migration/fresh schema missing required API role surface %q", required)
		}
	}
}

func TestAPIRelationshipCannotUseExternalRoute(t *testing.T) {
	desc := NewEdgeLabelDescriptor(map[string]interface{}{
		"name": "references", "edge_family": "reference",
		"source_kinds": []interface{}{"api_symbol"}, "target_kinds": []interface{}{"api_symbol"},
	})
	if err := validateExternalReferenceEdgeIsolation([]EdgeLabelDescriptor{desc}); err == nil {
		t.Fatal("api_symbol relationship escaped the closed api_relationship route")
	}
}
