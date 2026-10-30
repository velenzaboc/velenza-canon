package providerplan

import (
	"bytes"
	"encoding/json"
	"testing"
)

// The service cases supply positive acceptance coverage. These adversarial
// tests also use a complete parser-produced catalog and owner-loaded contract.
func TestCloudNeutralProjectionRefusesHostileBindingsAndValues(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	var target CloudSourceObjectTarget
	for _, candidate := range request.Targets {
		if candidate.ProviderID == "gcp" && candidate.ServiceID == "compute" && candidate.SourceObjectType == "Disk" {
			target = candidate
		}
	}
	catalog, ok := findCloudCandidateCatalog(request.Catalogs, target)
	if !ok || target.MappingContract == nil {
		t.Fatal("missing actual Disk contract")
	}
	base := CloudNeutralProjectionRecipe{Catalog: catalog, Target: &target, Contract: *target.MappingContract, ObjectPointer: "/items", IdentitySourcePointer: "/id", IdentitySourceFieldID: "id", ScopeReference: "scope", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RecordTemplate: cloudVolumeTemplate(), Bindings: []CloudNeutralScopedBinding{{ScopeReference: "scope", ScopedNativeKey: "native", OpaqueNeutralID: "opaque-volume"}, {ScopeReference: "scope", ScopedNativeKey: "instance-native", OpaqueNeutralID: "opaque-instance"}}}
	good := []byte(`{"items":[{"id":"native","name":"fixture-disk","sizeGb":"20","users":["instance-native"]}]}`)
	records, err := ProjectCloudNeutralRecords(base, good)
	if err != nil || len(records) != 1 || !bytes.Contains(records[0], []byte("opaque-instance")) || bytes.Contains(records[0], []byte("instance-native")) {
		t.Fatalf("positive binding: %s, %v", records, err)
	}
	for name, replacement := range map[string]string{"bad-type": "true", "overflow": "\"17179869184\"", "null": "null", "negative": "\"-1\""} {
		t.Run(name, func(t *testing.T) {
			raw := bytes.Replace(good, []byte(`"20"`), []byte(replacement), 1)
			if _, err := ProjectCloudNeutralRecords(base, raw); err == nil {
				t.Fatal("invalid exact capacity accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*CloudNeutralProjectionRecipe){
		"missing-target": func(r *CloudNeutralProjectionRecipe) { r.Target = nil },
		"undocumented-identity": func(r *CloudNeutralProjectionRecipe) {
			r.IdentitySourceFieldID = "name"
			r.IdentitySourcePointer = "/name"
		},
		"missing-binding": func(r *CloudNeutralProjectionRecipe) { r.Bindings = r.Bindings[1:] },
		"ambiguous-binding": func(r *CloudNeutralProjectionRecipe) {
			r.Bindings = append(append([]CloudNeutralScopedBinding{}, r.Bindings...), r.Bindings[0])
		},
		"cross-scope": func(r *CloudNeutralProjectionRecipe) {
			r.Bindings = append([]CloudNeutralScopedBinding{}, r.Bindings...)
			r.Bindings[1].ScopeReference = "other"
		},
		"template-fact": func(r *CloudNeutralProjectionRecipe) {
			r.RecordTemplate = cloudVolumeTemplate()
			r.RecordTemplate["storage_class"] = map[string]any{"state": "present", "value": "persistent"}
		},
		"different-target-contract": func(r *CloudNeutralProjectionRecipe) {
			copyTarget := *r.Target
			copyContract := *copyTarget.MappingContract
			copyContract.OperationID = "another"
			copyTarget.MappingContract = &copyContract
			r.Target = &copyTarget
		},
	} {
		t.Run(name, func(t *testing.T) {
			recipe := base
			mutate(&recipe)
			if _, err := ProjectCloudNeutralRecords(recipe, good); err == nil {
				t.Fatal("hostile recipe accepted")
			}
		})
	}
	emptyRecipe := base
	emptyRecipe.Bindings = nil
	empty, err := ProjectCloudNeutralResponse(emptyRecipe, []byte(`{"items":[]}`))
	if err != nil || len(empty.Records) != 0 || empty.DeletionAuthorized {
		t.Fatalf("empty: %#v %v", empty, err)
	}
	continuation := base
	continuation.ContinuationPointer = "/next"
	if _, err := ProjectCloudNeutralResponse(continuation, []byte(`{"items":[],"next":"page-2"}`)); err == nil {
		t.Fatal("complete coverage with continuation accepted")
	}
}

func TestCloudNeutralPointerCollectionPresence(t *testing.T) {
	for _, tc := range []struct {
		raw, pointer, state string
		count               int
	}{
		{`{"items":{"zone":{"disks":[]},"other":{"warning":{}}}}`, "/items/*/disks", "present", 0},
		{`{"items":{"zone":{"warning":{}}}}`, "/items/*/disks", "absent", 0},
		{`{"users":[]}`, "/users/*", "present", 0},
		{`{"users":["a","b"]}`, "/users/*", "present", 2},
	} {
		var root any
		if err := json.Unmarshal([]byte(tc.raw), &root); err != nil {
			t.Fatal(err)
		}
		got, state, err := resolveCloudNeutralProjectionPointer(root, tc.pointer)
		if err != nil || state != tc.state {
			t.Fatalf("%s: %v %s %v", tc.pointer, got, state, err)
		}
		if state == "present" {
			if list, ok := got.([]any); !ok || len(list) != tc.count {
				t.Fatalf("unexpected collection %#v", got)
			}
		}
	}
}
func cloudUnknown() map[string]any { return map[string]any{"state": "unknown"} }
func cloudVolumeTemplate() map[string]any {
	return map[string]any{"record_class": "compute_volume", "display_name": cloudUnknown(), "scope_reference": map[string]any{"state": "present", "value": "scope"}, "location_class": cloudUnknown(), "lifecycle_state": cloudUnknown(), "observation_state": "observed", "capacity_bytes": cloudUnknown(), "storage_class": cloudUnknown(), "encryption_configuration_observation": cloudUnknown(), "attached_compute_instance_reference": cloudUnknown()}
}
func cloudInstanceTemplate() map[string]any {
	return map[string]any{"record_class": "compute_instance", "display_name": cloudUnknown(), "scope_reference": map[string]any{"state": "present", "value": "scope"}, "location_class": cloudUnknown(), "lifecycle_state": cloudUnknown(), "observation_state": "observed", "machine_class": cloudUnknown(), "platform_family": cloudUnknown(), "reported_creation_time": cloudUnknown()}
}
func cloudContainerTemplate() map[string]any {
	return map[string]any{"record_class": "storage_container", "display_name": cloudUnknown(), "scope_reference": map[string]any{"state": "present", "value": "scope"}, "location_class": cloudUnknown(), "lifecycle_state": cloudUnknown(), "observation_state": "observed", "versioning_state": cloudUnknown(), "encryption_configuration_observation": cloudUnknown(), "public_access_configuration_observation": cloudUnknown(), "retention_state": cloudUnknown()}
}
