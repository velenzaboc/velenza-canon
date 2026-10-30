package providerplan

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// This is the first sealed stage of the native proof: the raw provider bytes
// are retained, while the test-only evidence coordinate is the immutable
// repository snapshot recorded in native-source-snapshots.json.
// The authority/profile is explicitly test-only. The exact retained model bytes
// exercise native evidence, range, derivation and four-stage verification. This
// does not qualify provider semantics or admit the generated cloud catalog.
func TestCloudNativeRetainedModelsThroughRealFactoryVerifier(t *testing.T) {
	for _, id := range []string{"aws-s3-model", "aws-ec2-model", "gcp-storage-model", "gcp-compute-model"} {
		t.Run(id, func(t *testing.T) {
			fixture := cloudNativeRetainedModelFixture(t, id)
			packageFixture := newSourcePackageCompilerTestFixtureFromBase(t, fixture.manifest().Provider, fixture)
			dependencies := defaultDocumentationFactorySourceCompilerDependencies()
			dependencies.RunFactory = func(options FactoryRunOptions) (FactoryRunReceipt, error) {
				// go test binaries have no release vcs identity. Only the tool identity
				// is test supplied; every verifier and materializer is the real one.
				return runDocumentationFactory(options, factoryRunnerDependencies{Verify: Verify, ToolIdentity: testFactoryToolIdentity()})
			}
			compiled, err := compileDocumentationFactorySourcePackageWithDependencies(DocumentationFactorySourceCompileOptions{SourcePackagePath: packageFixture.manifestPath, OutputRoot: packageFixture.outputRoot}, dependencies)
			if err != nil {
				t.Fatal(err)
			}
			if compiled.FactoryReceipt.PreflightReceipt.Result != "pass" || !compiled.FactoryReceipt.Completion.DerivationExecuted || !compiled.FactoryReceipt.Completion.Verified || compiled.SourceReceipt.AuthoritySelected || compiled.SourceReceipt.AdmissionAuthorized || compiled.SourceReceipt.FactoryComplete {
				t.Fatalf("source compiler promoted an offline fixture: %+v", compiled.SourceReceipt)
			}

		})
	}
}

func cloudNativeRetainedModelFixture(t *testing.T, id string) *testFixture {
	t.Helper()
	model := cloudNativeSnapshotModelByID(t, loadPinnedCloudModelsForCompilerProof(t), id)
	model.Source = cloudNativeSnapshotSource(t, model.Source.ID)
	pattern, sample := `"kind": "discovery#restDescription"`, `"discovery#restDescription"`
	if model.Format == CloudCatalogFormatSmithyJSON {
		pattern, sample = `"smithy": "2.0"`, `"2.0"`
	}
	start, sampleStart := bytes.Index(model.Raw, []byte(pattern)), bytes.Index(model.Raw, []byte(sample))
	if start < 0 || sampleStart < 0 {
		t.Fatal("retained model marker absent")
	}
	prefix := strings.ReplaceAll(id, "-", "_")
	return newTestFixtureWithPrimaryEvidence(t, testPrimaryEvidenceFixture{
		body: model.Raw, derivationPattern: regexp.QuoteMeta(pattern), providerDescription: "Test-only derivation scaffold over pinned model bytes.",
		provider: model.ProviderID, sourceRef: model.Source.StableCoordinate, sourceURL: model.Source.URI,
		representation: "source_declared_machine_export", representationCoord: model.Source.StableCoordinate,
		artifactPrefix: prefix, sourceSymbolPrefix: prefix, operationName: "cloud_candidate", sectionRoot: "Cloud",
		sampleRange:      &officialProviderEvidenceRange{ByteStartOffset: int64(sampleStart), ByteEndOffsetExclusive: int64(sampleStart + len(sample)), SelectedRangeSHA256: sha256Hex([]byte(sample))},
		additionalRanges: []officialProviderEvidenceRange{{Name: "exact_marker", SourceSymbol: prefix + "_read_operation", SurfaceKind: "operation", ByteStartOffset: int64(start), ByteEndOffsetExclusive: int64(start + len(pattern)), SelectedRangeSHA256: sha256Hex([]byte(pattern))}},
		protocolLiteralA: "type", protocolLiteralB: "description", singleDocument: true,
	})
}

func cloudNativeSnapshotSource(t *testing.T, modelID string) CloudCatalogSourceIdentity {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/cloudapi/native-source-snapshots.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
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
	if err := strictUnmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != cloudNativeSnapshotSchema || doc.AuthorityPosture != cloudNativeSnapshotPosture || doc.RepositoryCommit != cloudNativeSnapshotCommit {
		t.Fatal("native fixture cannot relabel its snapshot authority or version")
	}
	for _, snapshot := range doc.Snapshots {
		if snapshot.ModelSourceID == modelID {
			model := cloudNativeSnapshotModelByID(t, loadPinnedCloudModelsForCompilerProof(t), modelID)
			if snapshot.OriginalSource != model.Source || snapshot.ExpectedSHA256 != model.ExpectedSHA256 || sha256Hex(model.Raw) != snapshot.ExpectedSHA256 || snapshot.SnapshotSource.FormatRevision != cloudNativeSnapshotFormat || !strings.HasPrefix(snapshot.SnapshotSource.URI, "https://raw.githubusercontent.com/velenzaboc/velenza-canon/"+doc.RepositoryCommit+"/") || strings.Contains(snapshot.SnapshotSource.URI, "?") {
				t.Fatal("snapshot is not commit pinned")
			}
			return snapshot.SnapshotSource
		}
	}
	t.Fatalf("snapshot source for %q missing", modelID)
	return CloudCatalogSourceIdentity{}
}

func cloudNativeSnapshotSupplementalSource(t *testing.T, modelID, evidenceID string) CloudCatalogSourceIdentity {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/cloudapi/native-source-snapshots.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
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
	if err := strictUnmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != cloudNativeSnapshotSchema || doc.AuthorityPosture != cloudNativeSnapshotPosture || doc.RepositoryCommit != cloudNativeSnapshotCommit {
		t.Fatal("native supplemental snapshot authority is not closed")
	}
	for _, snapshot := range doc.Snapshots {
		if snapshot.ModelSourceID != modelID {
			continue
		}
		for _, supplemental := range snapshot.SupplementalSnapshots {
			if supplemental.EvidenceID == evidenceID {
				model := cloudNativeSnapshotModelByID(t, loadPinnedCloudModelsForCompilerProof(t), modelID)
				var original *CloudCatalogSupplementalEvidence
				for index := range model.SupplementalEvidence {
					if model.SupplementalEvidence[index].ID == evidenceID {
						original = &model.SupplementalEvidence[index]
						break
					}
				}
				if original == nil || original.Source.URI != supplemental.OriginalURI || original.ExpectedSHA256 != supplemental.ExpectedSHA256 || sha256Hex(original.Raw) != supplemental.ExpectedSHA256 || !strings.HasPrefix(supplemental.SnapshotURI, "https://raw.githubusercontent.com/velenzaboc/velenza-canon/"+doc.RepositoryCommit+"/") || strings.Contains(supplemental.SnapshotURI, "?") {
					t.Fatal("supplemental snapshot metadata does not close over retained evidence")
				}
				path := strings.TrimPrefix(supplemental.SnapshotURI, "https://raw.githubusercontent.com/velenzaboc/velenza-canon/"+doc.RepositoryCommit+"/")
				return CloudCatalogSourceIdentity{ID: "velenza-snapshot-" + modelID + "-" + evidenceID, URI: supplemental.SnapshotURI, StableCoordinate: "velenza-canon@" + doc.RepositoryCommit + "/" + path, FormatRevision: cloudNativeSnapshotFormat}
			}
		}
	}
	t.Fatalf("supplemental snapshot %q/%q missing", modelID, evidenceID)
	return CloudCatalogSourceIdentity{}
}
