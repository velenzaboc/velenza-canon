package providerplan

import (
	"os"
	"strings"
	"testing"
)

const cloudNativeSnapshotSchema = "velenza.cloud_native_test_source_snapshots.v1"
const cloudNativeSnapshotPosture = "offline_exact_bytes_candidate_only_producer_auth_unavailable"
const cloudNativeSnapshotFormat = "repository_snapshot_exact_bytes_v1"
const cloudNativeSnapshotCommit = "b9e66e343a5482a7925cd9bc1284d20ff46dd5a3"

func TestCloudNativeSnapshotSidecarPreservesPinnedOrigins(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/native-source-snapshots.json")
	if err != nil {
		t.Fatal(err)
	}
	var sidecar struct {
		SchemaVersion    string `json:"schema_version"`
		AuthorityPosture string `json:"authority_posture"`
		RepositoryCommit string `json:"repository_commit"`
		Snapshots        []struct {
			ModelSourceID         string                     `json:"model_source_id"`
			OriginalSource        CloudCatalogSourceIdentity `json:"original_source"`
			SnapshotSource        CloudCatalogSourceIdentity `json:"snapshot_source"`
			ExpectedSHA256        string                     `json:"expected_sha256"`
			SupplementalSnapshots []struct {
				EvidenceID     string `json:"evidence_id"`
				OriginalURI    string `json:"original_uri"`
				SnapshotURI    string `json:"snapshot_uri"`
				ExpectedSHA256 string `json:"expected_sha256"`
			} `json:"supplemental_snapshots"`
		} `json:"snapshots"`
	}
	if err := strictUnmarshal(raw, &sidecar); err != nil {
		t.Fatal(err)
	}
	if sidecar.SchemaVersion != cloudNativeSnapshotSchema || sidecar.AuthorityPosture != cloudNativeSnapshotPosture || sidecar.RepositoryCommit != cloudNativeSnapshotCommit {
		t.Fatal("snapshot sidecar changed its exact schema, candidate-only posture or immutable commit")
	}
	models := loadPinnedCloudModelsForCompilerProof(t)
	if len(sidecar.Snapshots) != 4 || len(sidecar.RepositoryCommit) != 40 {
		t.Fatalf("snapshot sidecar closure is incomplete")
	}
	seen := map[string]bool{}
	for _, entry := range sidecar.Snapshots {
		if seen[entry.ModelSourceID] || entry.SnapshotSource.FormatRevision != cloudNativeSnapshotFormat {
			t.Fatal("snapshot sidecar duplicates a model or changes its format contract")
		}
		seen[entry.ModelSourceID] = true
		model := cloudNativeSnapshotModelByID(t, models, entry.ModelSourceID)
		if entry.OriginalSource != model.Source || entry.ExpectedSHA256 != model.ExpectedSHA256 || sha256Hex(model.Raw) != entry.ExpectedSHA256 {
			t.Fatalf("snapshot %q does not preserve the pinned provider origin and bytes", entry.ModelSourceID)
		}
		if !strings.HasPrefix(entry.SnapshotSource.URI, "https://raw.githubusercontent.com/velenzaboc/velenza-canon/"+sidecar.RepositoryCommit+"/") || strings.Contains(entry.SnapshotSource.URI, "?") {
			t.Fatalf("snapshot %q lacks a canonical immutable HTTPS identity", entry.ModelSourceID)
		}
		for _, supplemental := range entry.SupplementalSnapshots {
			matched := false
			for _, original := range model.SupplementalEvidence {
				if original.ID == supplemental.EvidenceID && original.Source.URI == supplemental.OriginalURI && original.ExpectedSHA256 == supplemental.ExpectedSHA256 && sha256Hex(original.Raw) == supplemental.ExpectedSHA256 {
					matched = true
				}
			}
			if !matched || !strings.HasPrefix(supplemental.SnapshotURI, "https://raw.githubusercontent.com/velenzaboc/velenza-canon/"+sidecar.RepositoryCommit+"/") || strings.Contains(supplemental.SnapshotURI, "?") {
				t.Fatal("supplemental snapshot changed its exact origin, bytes or immutable identity")
			}
		}
	}
}

func cloudNativeSnapshotModelByID(t *testing.T, models []PinnedCloudModel, id string) PinnedCloudModel {
	t.Helper()
	for _, model := range models {
		if model.Source.ID == id {
			return model
		}
	}
	t.Fatalf("missing pinned model %q", id)
	return PinnedCloudModel{}
}
