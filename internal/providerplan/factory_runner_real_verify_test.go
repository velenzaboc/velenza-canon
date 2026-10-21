package providerplan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This is a production-composition test, not a generic-authority fixture. Its
// OOD input exposes the current eight property families, so every resulting
// state remains candidate-only pending the separately governed 16-role closure.
func TestDocumentationFactoryRunnerComposesRealVerifierCandidateOnly(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	lineage := newRealVerifyFactoryLineage(t, fixture)
	stagePaths := writeRealVerifyFactoryStageManifests(t, fixture, lineage)
	directDependencyPaths := realFactoryGraphDirectDependencyPaths(t, lineage, stagePaths)
	if len(directDependencyPaths) != 12 || len(fixture.options.DependencyArtifactPath) != 31 {
		t.Fatalf("real fixture dependency closure = %d direct/%d closed, want 12/31 (29 semantic closure inputs + one distinct exact target + its schema)", len(directDependencyPaths), len(fixture.options.DependencyArtifactPath))
	}
	preflight := fixture.options
	preflight.graphCompileSelectionLoader = nil
	preflight.graphCompileRequestRaw = nil
	preflight.graphCompileInputs = StageCompileInputs{}
	directKeys := make(map[string]struct{}, len(directDependencyPaths))
	for _, path := range directDependencyPaths {
		directKeys[factoryPathKeyForTest(t, path)] = struct{}{}
	}
	var freshDependencyCount int
	for _, path := range preflight.DependencyArtifactPath {
		if _, direct := directKeys[factoryPathKeyForTest(t, path)]; !direct {
			freshDependencyCount++
		}
	}
	if freshDependencyCount != 19 {
		t.Fatalf("real fixture fresh recursive dependencies = %d, want 19", freshDependencyCount)
	}
	checkedDependencyReads := false

	receipt, err := runDocumentationFactory(FactoryRunOptions{
		EvidenceIntakeInputManifestPath:     stagePaths[0],
		SemanticExtractionInputManifestPath: stagePaths[1],
		GraphCompileInputManifestPath:       stagePaths[2],
		FullFactoryInputManifestPath:        stagePaths[3],
		Preflight:                           preflight,
	}, factoryRunnerDependencies{
		Verify:       Verify,
		ToolIdentity: testFactoryToolIdentity(),
		BeforeFinalInputCheck: func(accumulator *providerInputAdmissionAccumulator) error {
			checkedDependencyReads = true
			for index, path := range preflight.DependencyArtifactPath {
				key, keyErr := factoryPathKey(path)
				if keyErr != nil {
					return keyErr
				}
				snapshot := accumulator.physicalSnapshots[key]
				if snapshot == nil {
					return fmt.Errorf("dependency_artifact[%d] has no retained physical snapshot", index)
				}
				if snapshot.initialTraversalCount != 1 || snapshot.initialTraversalBytes != snapshot.size {
					return fmt.Errorf("dependency_artifact[%d] initial admission traversal = %d/%d, want 1/%d", index, snapshot.initialTraversalCount, snapshot.initialTraversalBytes, snapshot.size)
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !checkedDependencyReads {
		t.Fatal("real verifier factory did not run its final dependency snapshot check")
	}
	if receipt.PreflightReceipt.Result != "pass" {
		t.Fatalf("real verifier result = %q, want pass", receipt.PreflightReceipt.Result)
	}
	actuals := receipt.InputAdmissionProof.Actuals
	if actuals.StageInputManifestCount != exactWholeRunStageManifestCount || actuals.VerificationAuthorityCount != maxVerificationAuthorityCount {
		t.Fatalf("whole-run manifest/authority counts = %d/%d, want %d/%d", actuals.StageInputManifestCount, actuals.VerificationAuthorityCount, exactWholeRunStageManifestCount, maxVerificationAuthorityCount)
	}
	if actuals.EvidenceManifestCount != int64(len(fixture.options.EvidenceManifestPath)) || actuals.EvidenceBodyCount != 2 || actuals.EvidenceCarrierCount != 2 {
		t.Fatalf("whole-run verifier evidence counts = %d/%d/%d, want %d/2/2", actuals.EvidenceManifestCount, actuals.EvidenceBodyCount, actuals.EvidenceCarrierCount, len(fixture.options.EvidenceManifestPath))
	}
	if actuals.DependencyArtifactCount != int64(len(fixture.options.DependencyArtifactPath)) {
		t.Fatalf("whole-run dependency count = %d, want %d", actuals.DependencyArtifactCount, len(fixture.options.DependencyArtifactPath))
	}
	if receipt.PreflightReceipt.ProviderInputAdmissionProofSHA256 == "" || receipt.PreflightReceipt.ProviderInputAdmissionProofSHA256 != receipt.InputAdmissionProof.ProofSHA256 {
		t.Fatal("factory and verifier receipts do not bind the same whole-run physical snapshot proof")
	}
	if !receipt.Completion.Compiled || !receipt.Completion.Verified || !receipt.Completion.DerivationExecuted ||
		receipt.Completion.GraphAdmittable || receipt.Completion.Admitted || receipt.Completion.CircuitAdmittable ||
		receipt.Completion.CircuitAdmitted || receipt.Completion.Configured || receipt.Completion.CredentialProvisioned ||
		receipt.Completion.Deployed || receipt.Completion.LiveTested || receipt.Completion.TwoTenantProven ||
		receipt.Completion.SourceSubstitutionProven || receipt.Completion.AuthoritySelected ||
		receipt.Completion.AdmissionAuthorized || receipt.Completion.FactoryComplete {
		t.Fatalf("real verifier composition overclaims completion: %+v", receipt.Completion)
	}
	raw := mustFactoryReceiptJSON(t, receipt)
	for _, body := range [][]byte{testPrimaryEvidenceBody, testProtocolEvidenceBody} {
		if bytes.Contains(raw, body) {
			t.Fatalf("factory receipt embeds exact evidence body %q", body)
		}
	}
}

func TestDocumentationFactoryRunnerRequiresExactGraphDirectDependencyStagePaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, *Options, string)
	}{
		{
			name: "omitted",
			mutate: func(t *testing.T, options *Options, directPath string) {
				t.Helper()
				directKey := factoryPathKeyForTest(t, directPath)
				kept := make([]string, 0, len(options.DependencyArtifactPath)-1)
				for _, path := range options.DependencyArtifactPath {
					if factoryPathKeyForTest(t, path) != directKey {
						kept = append(kept, path)
					}
				}
				options.DependencyArtifactPath = kept
			},
		},
		{
			name: "alternate_byte_identical_copy",
			mutate: func(t *testing.T, options *Options, directPath string) {
				t.Helper()
				raw, err := os.ReadFile(directPath)
				if err != nil {
					t.Fatal(err)
				}
				alternate := filepath.Join(filepath.Dir(directPath), "alternate-direct-dependency.jsonl")
				if err := os.WriteFile(alternate, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				directKey := factoryPathKeyForTest(t, directPath)
				for index, path := range options.DependencyArtifactPath {
					if factoryPathKeyForTest(t, path) == directKey {
						options.DependencyArtifactPath[index] = alternate
						return
					}
				}
				t.Fatalf("direct dependency path %q is absent from the real closure", directPath)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			lineage := newRealVerifyFactoryLineage(t, fixture)
			stagePaths := writeRealVerifyFactoryStageManifests(t, fixture, lineage)
			directPaths := realFactoryGraphDirectDependencyPaths(t, lineage, stagePaths)
			if len(directPaths) == 0 {
				t.Fatal("real graph_compile fixture has no direct dependency path")
			}
			preflight := fixture.options
			preflight.graphCompileSelectionLoader = nil
			preflight.graphCompileRequestRaw = nil
			preflight.graphCompileInputs = StageCompileInputs{}
			test.mutate(t, &preflight, directPaths[0])
			verifyCalled := false
			_, err := runDocumentationFactory(FactoryRunOptions{
				EvidenceIntakeInputManifestPath:     stagePaths[0],
				SemanticExtractionInputManifestPath: stagePaths[1],
				GraphCompileInputManifestPath:       stagePaths[2],
				FullFactoryInputManifestPath:        stagePaths[3],
				Preflight:                           preflight,
			}, factoryRunnerDependencies{
				Verify: func(Options) (Receipt, error) {
					verifyCalled = true
					return Receipt{}, fmt.Errorf("unexpected verifier invocation")
				},
				ToolIdentity: testFactoryToolIdentity(),
			})
			if err == nil || !strings.Contains(err.Error(), "paths omit exact graph_compile direct stage material") {
				t.Fatalf("direct dependency %s error = %v, want exact stage-path refusal", test.name, err)
			}
			if verifyCalled {
				t.Fatal("factory invoked verifier before rejecting a substituted direct dependency path")
			}
		})
	}
}

func TestDocumentationFactoryRunnerRejectsFreshUnboundDependency(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	lineage := newRealVerifyFactoryLineage(t, fixture)
	stagePaths := writeRealVerifyFactoryStageManifests(t, fixture, lineage)
	preflight := fixture.options
	preflight.graphCompileSelectionLoader = nil
	preflight.graphCompileRequestRaw = nil
	preflight.graphCompileInputs = StageCompileInputs{}
	extraPath := filepath.Join(filepath.Dir(fixture.planPath), "factory-unreferenced-dependency.jsonl")
	writeJSONL(t, extraPath, []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "factory_unreferenced_candidate", "artifact_version": "1", "status": "candidate_not_admissible", "provider": "fixture_provider",
	}})
	preflight.DependencyArtifactPath = append(preflight.DependencyArtifactPath, extraPath)

	_, err := runDocumentationFactory(FactoryRunOptions{
		EvidenceIntakeInputManifestPath:     stagePaths[0],
		SemanticExtractionInputManifestPath: stagePaths[1],
		GraphCompileInputManifestPath:       stagePaths[2],
		FullFactoryInputManifestPath:        stagePaths[3],
		Preflight:                           preflight,
	}, factoryRunnerDependencies{Verify: Verify, ToolIdentity: testFactoryToolIdentity()})
	if err == nil || !strings.Contains(err.Error(), "supplied but not bound") {
		t.Fatalf("fresh unbound dependency error = %v, want exact semantic-closure refusal", err)
	}
}

func TestDocumentationFactoryRunnerRejectsFreshDependencyHardlinkAlias(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	lineage := newRealVerifyFactoryLineage(t, fixture)
	stagePaths := writeRealVerifyFactoryStageManifests(t, fixture, lineage)
	directPaths := realFactoryGraphDirectDependencyPaths(t, lineage, stagePaths)
	directKeys := make(map[string]struct{}, len(directPaths))
	for _, path := range directPaths {
		directKeys[factoryPathKeyForTest(t, path)] = struct{}{}
	}
	var freshPath string
	for _, path := range fixture.options.DependencyArtifactPath {
		if _, direct := directKeys[factoryPathKeyForTest(t, path)]; !direct {
			freshPath = path
			break
		}
	}
	if freshPath == "" {
		t.Fatal("real dependency closure has no fresh recursive dependency")
	}
	aliasPath := filepath.Join(filepath.Dir(freshPath), "fresh-dependency-hardlink-alias.jsonl")
	if err := os.Link(freshPath, aliasPath); err != nil {
		t.Fatalf("create required factory hardlink fixture: %v", err)
	}
	preflight := fixture.options
	preflight.graphCompileSelectionLoader = nil
	preflight.graphCompileRequestRaw = nil
	preflight.graphCompileInputs = StageCompileInputs{}
	preflight.DependencyArtifactPath = append(preflight.DependencyArtifactPath, aliasPath)

	_, err := runDocumentationFactory(FactoryRunOptions{
		EvidenceIntakeInputManifestPath:     stagePaths[0],
		SemanticExtractionInputManifestPath: stagePaths[1],
		GraphCompileInputManifestPath:       stagePaths[2],
		FullFactoryInputManifestPath:        stagePaths[3],
		Preflight:                           preflight,
	}, factoryRunnerDependencies{Verify: Verify, ToolIdentity: testFactoryToolIdentity()})
	if err == nil || !strings.Contains(err.Error(), "duplicate path or file identity") {
		t.Fatalf("fresh dependency hardlink error = %v, want physical-identity refusal", err)
	}
}

func TestDocumentationFactoryRunnerRejectsLateByteIdenticalStreamedCarrierReplacement(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	lineage := newRealVerifyFactoryLineage(t, fixture)
	stagePaths := writeRealVerifyFactoryStageManifests(t, fixture, lineage)
	preflight := fixture.options
	preflight.graphCompileSelectionLoader = nil
	preflight.graphCompileRequestRaw = nil
	preflight.graphCompileInputs = StageCompileInputs{}
	carrierPath := firstRealVerifyEvidenceCarrierPath(t, preflight.EvidenceManifestPath[0])

	_, err := runDocumentationFactory(FactoryRunOptions{
		EvidenceIntakeInputManifestPath:     stagePaths[0],
		SemanticExtractionInputManifestPath: stagePaths[1],
		GraphCompileInputManifestPath:       stagePaths[2],
		FullFactoryInputManifestPath:        stagePaths[3],
		Preflight:                           preflight,
	}, factoryRunnerDependencies{
		Verify:       Verify,
		ToolIdentity: testFactoryToolIdentity(),
		BeforeFinalInputCheck: func(*providerInputAdmissionAccumulator) error {
			replaceFactoryInputWithByteIdenticalFile(t, carrierPath)
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "changed after its exact physical snapshot") {
		t.Fatalf("late streamed-carrier replacement error = %v, want final physical-identity refusal", err)
	}
}

func firstRealVerifyEvidenceCarrierPath(t *testing.T, manifestPath string) string {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	for lineNumber, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var envelope evidenceManifestEnvelope
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatalf("evidence manifest %q line %d: %v", manifestPath, lineNumber+1, err)
		}
		if envelope.RowKind != "external_evidence_body" {
			continue
		}
		var body externalEvidenceBody
		if err := json.Unmarshal(line, &body); err != nil {
			t.Fatalf("evidence body %q line %d: %v", manifestPath, lineNumber+1, err)
		}
		return filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(body.StagingFile))
	}
	t.Fatalf("evidence manifest %q has no external_evidence_body row", manifestPath)
	return ""
}

type realVerifyFactoryLineage struct {
	requests [][]byte
	inputs   []StageCompileInputs
	paths    []string
}

func newRealVerifyFactoryLineage(t *testing.T, fixture *testFixture) realVerifyFactoryLineage {
	t.Helper()
	dir := filepath.Dir(fixture.planPath)
	selectionPath := filepath.Join(dir, "evidence-selection-roster.jsonl")
	selectionTarget := realFactoryFileTarget(t, "selection_roster", selectionPath)

	type manifestFixture struct {
		target  testStageTarget
		binding evidenceManifestStageBinding
		bodies  []StageEvidenceBody
	}
	manifestFixtures := make([]manifestFixture, 0, len(fixture.options.EvidenceManifestPath))
	for _, path := range fixture.options.EvidenceManifestPath {
		target, bodies := realFactoryEvidenceTarget(t, path)
		var byteCount uint64
		for _, body := range bodies {
			byteCount += uint64(len(body.Raw))
		}
		manifestFixtures = append(manifestFixtures, manifestFixture{
			target: target,
			binding: evidenceManifestStageBinding{
				Role: target.identity.Role, ArtifactID: target.identity.ID, ArtifactVersion: target.identity.Version,
				ArtifactRawSHA256: target.identity.RawSHA256, BodyCount: uint64(len(bodies)), ByteCount: byteCount,
			},
			bodies: bodies,
		})
	}
	sort.Slice(manifestFixtures, func(i, j int) bool {
		return compareStageMaterialCoordinates(stageCoordinateForIdentity(manifestFixtures[i].target.identity), stageCoordinateForIdentity(manifestFixtures[j].target.identity)) < 0
	})
	for index := range manifestFixtures {
		role := fmt.Sprintf("selected_evidence_%04d", index)
		manifestFixtures[index].target.identity.Role = role
		manifestFixtures[index].target.schemaPin.Role = role + "_schema"
		manifestFixtures[index].binding.Role = role
		for bodyIndex := range manifestFixtures[index].bodies {
			manifestFixtures[index].bodies[bodyIndex].ManifestRole = role
		}
	}
	evidenceTargets := []testStageTarget{selectionTarget}
	evidenceBindings := make([]evidenceManifestStageBinding, 0, len(manifestFixtures))
	var evidenceBodies []StageEvidenceBody
	for _, manifest := range manifestFixtures {
		evidenceTargets = append(evidenceTargets, manifest.target)
		evidenceBindings = append(evidenceBindings, manifest.binding)
		evidenceBodies = append(evidenceBodies, manifest.bodies...)
	}
	evidenceValidation, evidenceMaterials := newStageValidation(t, stageEvidenceIntake, evidenceTargets, nil)
	extensionPath := filepath.Join(dir, "fixture-extension-protocol.ood.json")
	if err := os.WriteFile(extensionPath, []byte(`{"doc_id":"fixture-extension","version":1,"status":"locked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	authorityPaths := []string{fixture.options.OODSpecPath, fixture.options.GrandVisionPath, fixture.options.SourceRecordSpecPath, extensionPath}
	authorityRoles := []string{"ood_graph", "grand_vision", "source_record", "extension_protocol"}
	authorityMaterials := make([]StageMaterial, len(authorityPaths))
	for index, path := range authorityPaths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		authorityMaterials[index] = StageMaterial{Role: authorityRoles[index], ID: "fixture_" + authorityRoles[index], Version: "1", Raw: raw}
	}
	evidenceRequest := evidenceIntakeStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageEvidenceIntake,
		StageValidation: evidenceValidation,
		AuthorityPins: stageAuthorityPins{
			OODGraph: pinForStageMaterial(authorityMaterials[0], "canonical"), GrandVision: pinForStageMaterial(authorityMaterials[1], "canonical"),
			SourceRecord: pinForStageMaterial(authorityMaterials[2], "canonical"), ExtensionProtocol: pinForStageMaterial(authorityMaterials[3], "canonical"),
		},
		SelectionRoster: selectionTarget.identity, EvidenceManifests: evidenceBindings,
	}
	evidenceInputs := StageCompileInputs{Materials: append(evidenceMaterials, authorityMaterials...), EvidenceBodies: evidenceBodies}
	evidenceRaw := mustStageJSON(t, evidenceRequest)
	evidenceReceipt := mustCompileStage(t, evidenceRaw, evidenceInputs)
	evidenceSummary := mustValidateStage(t, evidenceReceipt)

	previewRaw, previewInputs := newVerifyGraphStageSelection(t, fixture)
	var preview graphCompileStageRequest
	if err := strictUnmarshal(previewRaw, &preview); err != nil {
		t.Fatal(err)
	}
	directTargets := realFactoryGraphDependencyTargets(t, preview, previewInputs)
	applicabilityTarget := newStageTarget(t, "factory_fixture_applicability", "factory_fixture_applicability", []byte("{\"row_kind\":\"applicability_profile\",\"value\":\"closed\"}\n"))
	semanticValidationTargets := append(append([]testStageTarget(nil), directTargets...), applicabilityTarget)
	semanticValidation, semanticMaterials := newStageValidation(t, stageSemanticExtraction, semanticValidationTargets, nil)
	sort.Slice(directTargets, func(i, j int) bool { return directTargets[i].identity.Role < directTargets[j].identity.Role })
	semanticRoster := make([]semanticArtifactRole, len(directTargets))
	semanticOutputs := make([]semanticArtifactOutput, len(directTargets))
	semanticBindings := make([]semanticDerivationBinding, len(directTargets))
	extractorMaterials := make([]StageMaterial, len(directTargets))
	for index, target := range directTargets {
		bindingID := fmt.Sprintf("binding_%04d", index)
		extractor := StageMaterial{
			Role: "factory_fixture_extractor", ID: "factory_fixture_" + target.identity.Role + "_extractor", Version: "1",
			Raw: []byte(fmt.Sprintf("{\"row_kind\":\"fixture_derivation_profile\",\"target_role\":%q}\n", target.identity.Role)),
		}
		extractorMaterials[index] = extractor
		semanticRoster[index] = semanticArtifactRole{Role: target.identity.Role, Disposition: "required"}
		semanticOutputs[index] = semanticArtifactOutput{
			Role: target.identity.Role, ArtifactID: target.identity.ID, ArtifactVersion: target.identity.Version,
			ArtifactRawSHA256: target.identity.RawSHA256, DerivationBindingIDs: []string{bindingID},
		}
		semanticBindings[index] = semanticDerivationBinding{BindingID: bindingID, Extractor: pinForStageMaterial(extractor, "admitted"), Schema: target.schemaPin}
	}
	semanticRequest := semanticExtractionStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageSemanticExtraction,
		IntakeReceipt: stageRef(evidenceSummary), StageValidation: semanticValidation, ApplicabilityProfile: pinForTarget(applicabilityTarget, "canonical"),
		ArtifactRoleRoster: semanticRoster, ArtifactOutputs: semanticOutputs, DerivationBindings: semanticBindings,
	}
	semanticInputs := StageCompileInputs{
		PredecessorReceipts: [][]byte{evidenceReceipt}, Materials: append(semanticMaterials, extractorMaterials...), EvidenceBodies: cloneStageEvidenceBodies(evidenceBodies),
	}
	semanticRaw := mustStageJSON(t, semanticRequest)
	semanticReceipt := mustCompileStage(t, semanticRaw, semanticInputs)
	semanticSummary := mustValidateStage(t, semanticReceipt)

	graphRaw, graphInputs := newVerifyGraphStageSelectionForLineage(t, fixture, semanticSummary, semanticReceipt, evidenceBodies)
	graphReceipt := mustCompileStage(t, graphRaw, graphInputs)
	graphSummary := mustValidateStage(t, graphReceipt)
	fullValidation, fullMaterials := newStageValidation(t, stageFullFactory, nil, nil)
	fullRequest := fullFactoryStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageFullFactory, StageValidation: fullValidation,
		PriorReceipts: []StageReceiptReference{stageRef(evidenceSummary), stageRef(semanticSummary), stageRef(graphSummary)},
	}
	fullInputs := StageCompileInputs{
		PredecessorReceipts: [][]byte{evidenceReceipt, semanticReceipt, graphReceipt}, Materials: fullMaterials, EvidenceBodies: cloneStageEvidenceBodies(evidenceBodies),
	}
	return realVerifyFactoryLineage{
		requests: [][]byte{evidenceRaw, semanticRaw, graphRaw, mustStageJSON(t, fullRequest)},
		inputs:   []StageCompileInputs{evidenceInputs, semanticInputs, graphInputs, fullInputs},
		paths:    append(append(append([]string(nil), authorityPaths...), selectionPath), append(fixture.options.EvidenceManifestPath, append(fixture.options.DependencyArtifactPath, fixture.planPath)...)...),
	}
}

func realFactoryFileTarget(t *testing.T, role, path string) testStageTarget {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	id, version := fixtureStructuredArtifactIdentity(t, path)
	schemaID := "urn:test:factory-real-verify:" + id + ":schema"
	schemaRaw := exactStageArtifactSchema(t, schemaID, raw)
	return testStageTarget{
		identity: stageArtifactIdentity{Role: role, ID: id, Version: version, RawSHA256: sha256Hex(raw)}, raw: raw,
		schemaPin: immutableStageArtifactPin{Role: role + "_schema", ID: schemaID, Version: "1", RawSHA256: sha256Hex(schemaRaw), AuthorityClass: "canonical"}, schemaRaw: schemaRaw,
	}
}

func realFactoryEvidenceTarget(t *testing.T, path string) (testStageTarget, []StageEvidenceBody) {
	t.Helper()
	target := realFactoryFileTarget(t, "selected_evidence", path)
	claims := make(map[uint64]externalEvidenceBody)
	for lineNumber, line := range bytes.Split(target.raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var envelope evidenceManifestEnvelope
		if err := json.Unmarshal(line, &envelope); err != nil {
			t.Fatalf("evidence manifest %q line %d: %v", path, lineNumber+1, err)
		}
		if envelope.RowKind != "external_evidence_body" {
			continue
		}
		var row externalEvidenceBody
		if err := json.Unmarshal(line, &row); err != nil {
			t.Fatal(err)
		}
		claims[uint64(row.ComponentOrdinal)] = row
	}
	bodies := make([]StageEvidenceBody, len(claims))
	for ordinal := range bodies {
		claim, ok := claims[uint64(ordinal)]
		if !ok {
			t.Fatalf("evidence manifest %q omits ordinal %d", path, ordinal)
		}
		carrier, err := os.ReadFile(filepath.Join(filepath.Dir(path), filepath.FromSlash(claim.StagingFile)))
		if err != nil {
			t.Fatal(err)
		}
		body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(carrier)))
		if err != nil {
			t.Fatal(err)
		}
		if sha256Hex(body) != claim.ContentSHA256 || int64(len(body)) != claim.ContentBytes {
			t.Fatalf("evidence manifest %q ordinal %d carrier differs from its exact claim", path, ordinal)
		}
		bodies[ordinal] = StageEvidenceBody{
			ManifestRole: target.identity.Role, ManifestID: target.identity.ID, ManifestVersion: target.identity.Version,
			ComponentOrdinal: uint64(ordinal), Raw: body,
		}
	}
	return target, bodies
}

func realFactoryGraphDependencyTargets(t *testing.T, request graphCompileStageRequest, inputs StageCompileInputs) []testStageTarget {
	t.Helper()
	profile := graphStageValidationProfile(t, request, inputs)
	bindings := make(map[stageMaterialCoordinate]stageValidationProfileArtifactBinding, len(profile.BoundArtifactSchemas))
	for _, binding := range profile.BoundArtifactSchemas {
		bindings[stageMaterialCoordinate{Role: binding.Role, ID: binding.ArtifactID, Version: binding.ArtifactVersion}] = binding
	}
	materials := make(map[stageMaterialCoordinate]StageMaterial, len(inputs.Materials))
	for _, material := range inputs.Materials {
		materials[stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}] = material
	}
	result := make([]testStageTarget, len(request.DependencyArtifacts))
	for index, identity := range request.DependencyArtifacts {
		coordinate := stageCoordinateForIdentity(identity)
		binding, ok := bindings[coordinate]
		if !ok {
			t.Fatalf("graph dependency %v has no exact validation binding", coordinate)
		}
		schemaCoordinate := stageMaterialCoordinate{Role: binding.SchemaRole, ID: binding.SchemaID, Version: binding.SchemaVersion}
		result[index] = testStageTarget{
			identity: identity, raw: bytes.Clone(materials[coordinate].Raw),
			schemaPin: immutableStageArtifactPin{Role: schemaCoordinate.Role, ID: schemaCoordinate.ID, Version: schemaCoordinate.Version, RawSHA256: binding.SchemaRawSHA256, AuthorityClass: "canonical"},
			schemaRaw: bytes.Clone(materials[schemaCoordinate].Raw),
		}
	}
	return result
}

func writeRealVerifyFactoryStageManifests(t *testing.T, fixture *testFixture, lineage realVerifyFactoryLineage) []string {
	t.Helper()
	dir := filepath.Dir(fixture.planPath)
	originalByDigest := map[string]string{}
	for _, path := range lineage.paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256Hex(raw)
		if prior, duplicate := originalByDigest[digest]; duplicate && factoryPathKeyForTest(t, prior) != factoryPathKeyForTest(t, path) {
			t.Fatalf("real factory fixture aliases content digest %s across %q and %q", digest, prior, path)
		}
		originalByDigest[digest] = path
	}
	declared := map[stageMaterialCoordinate][]byte{}
	result := make([]string, len(lineage.requests))
	for stageIndex := range lineage.requests {
		stageName := []string{"evidence", "semantic", "graph", "full"}[stageIndex]
		requestName := fmt.Sprintf("factory-real-%s-request.json", stageName)
		if err := os.WriteFile(filepath.Join(dir, requestName), lineage.requests[stageIndex], 0o600); err != nil {
			t.Fatal(err)
		}
		manifest := stageCompileFileManifest{RequestPath: requestName, PredecessorReceiptPaths: []string{}, Materials: []stageCompileFileMaterial{}, EvidenceBodies: []stageCompileFileEvidenceBody{}}
		materials := append([]StageMaterial(nil), lineage.inputs[stageIndex].Materials...)
		sort.Slice(materials, func(i, j int) bool {
			return compareStageMaterialCoordinates(stageMaterialCoordinate{Role: materials[i].Role, ID: materials[i].ID, Version: materials[i].Version}, stageMaterialCoordinate{Role: materials[j].Role, ID: materials[j].ID, Version: materials[j].Version}) < 0
		})
		for materialIndex, material := range materials {
			coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
			if prior, exists := declared[coordinate]; exists {
				if !bytes.Equal(prior, material.Raw) {
					t.Fatalf("real factory material %v changes bytes across stages", coordinate)
				}
				continue
			}
			path := originalByDigest[sha256Hex(material.Raw)]
			if path == "" {
				path = filepath.Join(dir, fmt.Sprintf("factory-real-%s-material-%04d.json", stageName, materialIndex))
				if err := os.WriteFile(path, material.Raw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			manifest.Materials = append(manifest.Materials, stageCompileFileMaterial{Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version, Path: filepath.Base(path)})
			declared[coordinate] = bytes.Clone(material.Raw)
		}
		if stageIndex == 0 {
			for bodyIndex, body := range lineage.inputs[stageIndex].EvidenceBodies {
				name := fmt.Sprintf("factory-real-evidence-body-%04d.bin", bodyIndex)
				if err := os.WriteFile(filepath.Join(dir, name), body.Raw, 0o600); err != nil {
					t.Fatal(err)
				}
				manifest.EvidenceBodies = append(manifest.EvidenceBodies, stageCompileFileEvidenceBody{
					ManifestRole: body.ManifestRole, ManifestID: body.ManifestID, ManifestVersion: body.ManifestVersion,
					ComponentOrdinal: body.ComponentOrdinal, Path: name,
				})
			}
		}
		manifestName := fmt.Sprintf("factory-real-%s-stage-inputs.json", stageName)
		result[stageIndex] = filepath.Join(dir, manifestName)
		writeFactoryJSON(t, result[stageIndex], manifest)
	}
	return result
}

func realFactoryGraphDirectDependencyPaths(t *testing.T, lineage realVerifyFactoryLineage, stageManifestPaths []string) []string {
	t.Helper()
	if len(lineage.requests) <= 2 {
		t.Fatal("real factory lineage omits graph_compile request")
	}
	var request graphCompileStageRequest
	if err := strictUnmarshal(lineage.requests[2], &request); err != nil {
		t.Fatalf("decode real graph_compile request: %v", err)
	}
	materialPaths := make(map[stageMaterialCoordinate]string)
	for _, manifestPath := range stageManifestPaths {
		manifest := readFactoryStageManifestForMutationTest(t, manifestPath)
		baseDir, err := filepath.Abs(filepath.Dir(manifestPath))
		if err != nil {
			t.Fatal(err)
		}
		for index, material := range manifest.Materials {
			coordinate := stageMaterialCoordinate{Role: material.Role, ID: material.ID, Version: material.Version}
			path, err := resolveRelativeStageManifestPath(baseDir, material.Path, fmt.Sprintf("materials[%d].path", index))
			if err != nil {
				t.Fatal(err)
			}
			if prior, duplicate := materialPaths[coordinate]; duplicate && factoryPathKeyForTest(t, prior) != factoryPathKeyForTest(t, path) {
				t.Fatalf("real factory coordinate %+v has two stage material paths", coordinate)
			}
			materialPaths[coordinate] = path
		}
	}
	result := make([]string, len(request.DependencyArtifacts))
	for index, dependency := range request.DependencyArtifacts {
		coordinate := stageCoordinateForIdentity(dependency)
		path := materialPaths[coordinate]
		if path == "" {
			t.Fatalf("real graph direct dependency %+v has no declared stage material path", coordinate)
		}
		result[index] = path
	}
	return result
}

func factoryPathKeyForTest(t *testing.T, path string) string {
	t.Helper()
	key, err := factoryPathKey(path)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
