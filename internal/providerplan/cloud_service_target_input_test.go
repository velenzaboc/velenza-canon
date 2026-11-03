package providerplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedServiceTargetDocuments(t *testing.T) {
	base := t.TempDir()
	model := CloudSourceCandidateModelInput{PinnedCloudModel: PinnedCloudModel{ProviderID: "provider", ServiceID: "inventory", APISurfaceID: "read"}}
	target := CloudSourceObjectTarget{ProviderID: model.ProviderID, ServiceID: model.ServiceID, APISurfaceID: model.APISurfaceID, OperationID: "list"}
	write := func(name string, value any) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	doc := func(targets ...CloudSourceObjectTarget) []byte {
		return write("service.json", map[string]any{"targets": targets})
	}
	ref := CloudServiceTargetReference{ProviderID: model.ProviderID, ServiceID: model.ServiceID, APISurfaceID: model.APISurfaceID, Path: "service.json", SHA256: sha256Hex(doc(target))}
	input := CloudSourceCandidateInput{Models: []CloudSourceCandidateModelInput{model}, TargetDocuments: []CloudServiceTargetReference{ref}}
	load := func(in CloudSourceCandidateInput) (CloudSourceCandidateInput, error) {
		write("input.json", in)
		return readCloudCandidateInput(filepath.Join(base, "input.json"))
	}
	got, err := load(input)
	if err != nil || len(got.Targets) != 1 || got.Targets[0].OperationID != "list" || len(got.TargetDocuments) != 0 {
		t.Fatalf("load pinned targets: %v", err)
	}
	for name, mutate := range map[string]func(*CloudSourceCandidateInput){
		"tampered file":    func(in *CloudSourceCandidateInput) { doc() },
		"duplicate target": func(in *CloudSourceCandidateInput) { in.TargetDocuments[0].SHA256 = sha256Hex(doc(target, target)) },
		"foreign service": func(in *CloudSourceCandidateInput) {
			other := target
			other.ServiceID = "other"
			in.TargetDocuments[0].SHA256 = sha256Hex(doc(other))
		},
		"foreign surface": func(in *CloudSourceCandidateInput) { in.TargetDocuments[0].APISurfaceID = "write" },
		"missing service": func(in *CloudSourceCandidateInput) {
			other := model
			other.ServiceID = "another-service"
			in.Models = append(in.Models, other)
		},
		"mixed representations": func(in *CloudSourceCandidateInput) { in.Targets = []CloudSourceObjectTarget{target} },
		"escape root":           func(in *CloudSourceCandidateInput) { in.TargetDocuments[0].Path = "../service.json" },
		"empty pinned file":     func(in *CloudSourceCandidateInput) { in.TargetDocuments[0].SHA256 = sha256Hex(doc()) },
	} {
		t.Run(name, func(t *testing.T) {
			doc(target)
			in := input
			in.TargetDocuments = []CloudServiceTargetReference{ref}
			mutate(&in)
			if _, err := load(in); err == nil {
				t.Fatal("accepted malformed service composition")
			}
		})
	}
}
