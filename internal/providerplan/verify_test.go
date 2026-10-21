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

type testFixture struct {
	options                   Options
	planPath                  string
	oodPath                   string
	evidencePath              string
	evidenceByRole            map[string]string
	planRows                  []interface{}
	roles                     []string
	constraints               []relationshipConstraint
	families                  []string
	locatorID                 string
	symbolByRole              map[string]string
	sourceSymbolByRole        map[string]string
	sourceReadOperationSymbol string
	sourceOperationID         string
	dependencyByRole          map[string]string
	schemaByRole              map[string]string
	artifactCoordinateByRole  map[string]stageMaterialCoordinate
	planStageSchemaRaw        []byte
	applicability             fixtureApplicabilityBinding
	ruleByLabel               map[string]string
	claimRuleID               string
	sourceOperationIdentity   map[string]interface{}
	derivationTargets         map[string]artifactInput
	derivationTargetAuthority dependencySemanticDerivationTargetSchemaAuthority
	derivationTargetPaths     map[string]string
	derivationTargetSchemas   map[string]string
	documentationDerivation   *testDocumentationDerivationBundle
}

type fixtureApplicabilityBinding struct {
	ProfileID      string
	ProfileVersion string
	ProfileSHA256  string
}

func TestVerifyMalformedExpectedPinDiagnosticIsDeterministic(t *testing.T) {
	options := Options{
		OODSpecPath:                "unread-ood",
		ExpectedOODSpecSHA256:      "malformed-ood-pin",
		GrandVisionPath:            "unread-vision",
		ExpectedGrandVisionSHA256:  "malformed-vision-pin",
		SourceRecordSpecPath:       "unread-source",
		ExpectedSourceRecordSHA256: "malformed-source-pin",
		EvidenceManifestPath:       []string{"unread-evidence"},
	}
	want := "expected OOD spec authority digest must be supplied as lowercase SHA-256"
	for iteration := 0; iteration < 256; iteration++ {
		if _, err := Verify(options); err == nil || err.Error() != want {
			t.Fatalf("iteration %d malformed-pin error = %v, want %q", iteration, err, want)
		}
	}
}

func fixtureGapProof(locatorIDs ...string) json.RawMessage {
	ordered := append([]string(nil), locatorIDs...)
	sort.Strings(ordered)
	raw, _ := json.Marshal(map[string]interface{}{"proof_kind": "exact_locator_manifest", "evidence_locator_ids": ordered, "locator_manifest_sha256": strings.Repeat("e", 64)})
	return raw
}

func fixtureClassificationOccurrenceObject(t *testing.T, occurrence sourceClassificationOccurrence) map[string]interface{} {
	t.Helper()
	return map[string]interface{}{
		"artifact_id":      occurrence.Binding.ArtifactID,
		"artifact_version": occurrence.Binding.ArtifactVersion,
		"artifact_sha256":  occurrence.Binding.ArtifactSHA256,
		"row_kind":         "source_classification_occurrence",
		"source_symbol":    occurrence.SourceSymbol,
		"surface_kind":     occurrence.SurfaceKind,
		"evidence_locator": fixtureJSONObject(t, occurrence.Locator),
	}
}

func fixtureSourceOperationIdentity() map[string]interface{} {
	return fixtureSourceOperationIdentityFor("read_records")
}

func fixtureSourceOperationIdentityFor(operationName string) map[string]interface{} {
	return map[string]interface{}{
		"identity_kind": "source_contract_operation",
		"identity_components": map[string]interface{}{
			"operation_name": operationName,
		},
	}
}

func fixtureJSONObject(t *testing.T, value interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	object, err := decodeJSONObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return object
}

func fixtureCanonicalJSONString(t *testing.T, value interface{}) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return string(canonical)
}

func TestVerifyAcceptsExactHydratedProviderPlan(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	receipt, err := Verify(fixture.options)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if receipt.ReceiptKind != receiptKind || receipt.ReceiptVersion != "9" || receipt.Scope != "offline_exact_evidence_deterministic_documentation_derivation_and_structural_plan_preflight" || receipt.Result != "pass" || receipt.CanonicalAdmissionAuthorized || !receipt.BodyFreeSchemaBindingVerified || receipt.BodyFreeSchemaAuthorityVerified {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if err := validateReceiptIdentity(receipt); err != nil {
		t.Fatalf("receipt v9 identity does not cover its complete canonical post-state: %v", err)
	}
	for _, digest := range []struct {
		label string
		value string
	}{
		{"receipt", receipt.ReceiptSHA256},
		{"documentation derivation closure proof", receipt.DocumentationDerivationClosureProofSHA256},
		{"documentation derivation profile artifact", receipt.DocumentationDerivationProfileArtifactSHA256},
		{"source classification proof", receipt.SourceClassificationProofSHA256},
		{"documentation derivation profile page-set root", receipt.DocumentationDerivationProfilePageSetRootSHA256},
		{"documentation derivation profile result root", receipt.DocumentationDerivationProfileResultRootSHA256},
		{"documentation target materialization root", receipt.DocumentationTargetMaterializationRootSHA256},
		{"documentation target binding-roster root", receipt.DocumentationTargetBindingRosterRootSHA256},
	} {
		if !isLowerSHA256(digest.value) {
			t.Fatalf("receipt v9 %s = %q, want lowercase SHA-256", digest.label, digest.value)
		}
	}
	if receipt.DocumentationDerivationProfileArtifactSHA256 != fileSHA256(t, fixture.dependencyByRole[dependencySemanticRoleDocumentationClaimDerivation]) {
		t.Fatalf("receipt derivation profile artifact digest does not bind the exact fixture artifact")
	}
	if receipt.DocumentationDerivationProfileCount != 1 || receipt.DocumentationDerivationOutcomeCount != 2 || receipt.DocumentationDerivedFactCount != 2 || receipt.DocumentationDerivationPageCount != 2 || receipt.DocumentationWholeRowBindingCount != 1 || receipt.DocumentationRowMemberBindingCount != 1 || receipt.DocumentationWholeRowBindingCount+receipt.DocumentationRowMemberBindingCount != receipt.DocumentationDerivedFactCount {
		t.Fatalf("unexpected receipt v9 documentation derivation closure counts: %+v", receipt)
	}
	if receipt.ExactHydratedEvidenceLocatorCount != 2 || receipt.ExactSourceCoordinateBindingCount != 2 || receipt.SourceCoordinateBindingRule == "" || receipt.DependencyArtifactCount != len(fixture.options.DependencyArtifactPath) || receipt.DependencyBindingRule == "" || receipt.APISymbolCount != len(fixture.roles)+1 || receipt.APIRelationshipCount != 1 || receipt.APIPropertyClaimCount != 0 || receipt.ExplicitGraphGapCount != 2 {
		t.Fatalf("unexpected receipt counts: %+v", receipt)
	}
}

func TestEvidenceSelectionRosterRejectsUnknownOrUnconsumedConsumerRoles(t *testing.T) {
	t.Run("unknown role", func(t *testing.T) {
		fixture, roster, loaded, dependencies := loadSelectionValidationFixture(t)
		row := roster.RowsByKind["selected_source_document"][0]
		roles, _ := manifestStringSlice(row, "consumer_roles")
		row["consumer_roles"] = stringInterfaces(append(roles, "unused_sink"))
		err := validateEvidenceSelectionRoster(roster, fixture.manifest().Provider, loaded, dependencies, map[string]struct{}{}, &parsedPlan{Manifest: fixture.manifest(), Locators: fixtureLocators(fixture)})
		if err == nil || !strings.Contains(err.Error(), "unknown factory consumer role") {
			t.Fatalf("error = %v, want unknown consumer-role refusal", err)
		}
	})
	t.Run("graph role removed", func(t *testing.T) {
		fixture, roster, loaded, dependencies := loadSelectionValidationFixture(t)
		for _, row := range roster.RowsByKind["selected_source_document"] {
			roles, _ := manifestStringSlice(row, "consumer_roles")
			filtered := make([]string, 0, len(roles))
			for _, role := range roles {
				if role != "api_graph_projection" {
					filtered = append(filtered, role)
				}
			}
			row["consumer_roles"] = stringInterfaces(filtered)
		}
		delete(roster.ValidationSummary["captured_consumer_role_counts"].(map[string]interface{}), "api_graph_projection")
		bindings := append([]evidenceManifestBinding(nil), fixture.manifest().EvidenceManifestBindings...)
		for index := range bindings {
			bindings[index].ConsumerRoles = append([]string(nil), bindings[index].ConsumerRoles[1:]...)
		}
		manifestCopy := *fixture.manifest()
		manifestCopy.EvidenceManifestBindings = bindings
		err := validateEvidenceSelectionRoster(roster, manifestCopy.Provider, loaded, dependencies, map[string]struct{}{}, &parsedPlan{Manifest: &manifestCopy, Locators: fixtureLocators(fixture)})
		if err == nil || !strings.Contains(err.Error(), "api_graph_projection evidence manifests") {
			t.Fatalf("error = %v, want actual graph-consumer closure refusal", err)
		}
	})
}

func TestEvidenceSelectionRosterRejectsCallerDefinedClassificationShapeAndFalseCount(t *testing.T) {
	t.Run("caller-defined row kind", func(t *testing.T) {
		fixture, roster, loaded, dependencies := loadSelectionValidationFixture(t)
		occurrences := roster.RowsByKind["selected_source_document"][0]["classification_occurrences"].([]interface{})
		occurrences[0].(map[string]interface{})["row_kind"] = "attacker_row"
		err := validateEvidenceSelectionRoster(roster, fixture.manifest().Provider, loaded, dependencies, map[string]struct{}{}, &parsedPlan{Manifest: fixture.manifest(), Locators: fixtureLocators(fixture)})
		if err == nil || !strings.Contains(err.Error(), "classification_occurrences[0]") {
			t.Fatalf("error = %v, want closed source_symbol classification refusal", err)
		}
	})
	t.Run("false manifest count", func(t *testing.T) {
		fixture, roster, loaded, dependencies := loadSelectionValidationFixture(t)
		rawBinding := roster.Manifest["classification_artifact_bindings"].([]interface{})[0].(map[string]interface{})
		digest, _ := manifestString(rawBinding, "artifact_sha256")
		classification := dependencies[digest]
		classification.Manifest["source_symbol_count"] = json.Number("2")
		dependencies[digest] = classification
		err := validateEvidenceSelectionRoster(roster, fixture.manifest().Provider, loaded, dependencies, map[string]struct{}{}, &parsedPlan{Manifest: fixture.manifest(), Locators: fixtureLocators(fixture)})
		if err == nil || !strings.Contains(err.Error(), "manifest-declared source_symbol roster") {
			t.Fatalf("error = %v, want recomputed classification-count refusal", err)
		}
	})
	t.Run("unselected classification row", func(t *testing.T) {
		fixture, roster, loaded, dependencies := loadSelectionValidationFixture(t)
		rawBinding := roster.Manifest["classification_artifact_bindings"].([]interface{})[0].(map[string]interface{})
		digest, _ := manifestString(rawBinding, "artifact_sha256")
		classification := dependencies[digest]
		currentCount := classification.RowKindCounts["source_symbol"]
		classification.Manifest["source_symbol_count"] = json.Number(fmt.Sprint(currentCount + 1))
		classification.RowKindCounts["source_symbol"] = currentCount + 1
		classification.RowsByKind["source_symbol"] = append(classification.RowsByKind["source_symbol"], map[string]interface{}{
			"row_kind":      "source_symbol",
			"source_symbol": "unselected_fixture",
			"surface_kind":  "data_entity",
		})
		dependencies[digest] = classification
		err := validateEvidenceSelectionRoster(roster, fixture.manifest().Provider, loaded, dependencies, map[string]struct{}{}, &parsedPlan{Manifest: fixture.manifest(), Locators: fixtureLocators(fixture)})
		if err == nil || !strings.Contains(err.Error(), "selected classification rows") {
			t.Fatalf("error = %v, want unselected classification-row refusal", err)
		}
	})
}

func TestVerifyRejectsEvidenceManifestMutationWithoutLocatorIdentityChange(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	for _, raw := range fixture.planRows {
		locator, ok := raw.(*evidenceLocator)
		if !ok || locator.SourceRefs[0] != "fixture" {
			continue
		}
		locator.EvidenceManifestSHA256 = fixture.manifest().EvidenceManifestBindings[1].EvidenceManifestSHA256
		break
	}
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "non-content-derived locator id") {
		t.Fatalf("error = %v, want manifest-bound locator identity refusal", err)
	}
}

func TestVerifyRejectsValidationResultThatOnlyContainsCompleteSubstring(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	fixture.summary().Result = "candidate_incomplete"
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "closed result") {
		t.Fatalf("got %v, want closed-result refusal", err)
	}
}

func TestVerifyRejectsNegatedTenantSafetyPhrases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "negated kernel injection", field: "organization_id_source", value: "not_kernel_injected_request_context"},
		{name: "negated exact predicate", field: "predicate_rule", value: "not_exact_organization_id_equality"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			profilePath := fixture.dependencyByRole["profile"]
			mutateJSONLRow(t, profilePath, "tenant_scope_contract", func(row map[string]interface{}) {
				row[test.field] = test.value
			})
			fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
			rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleProfile)
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), "tenant scope") {
				t.Fatalf("got %v, want negated tenant-safety refusal", err)
			}
		})
	}
}

func TestVerifyRejectsNormalConsumerVisibilityForFailClosedSecurityClass(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	securityPath := fixture.dependencyByRole["field_security_policy"]
	oldSecurityDigest := fileSHA256(t, securityPath)
	fieldMappingPath := fixture.dependencyByRole["field_mapping"]
	mutateJSONLMatchingRow(t, securityPath, "security_class_definition", func(row map[string]interface{}) bool {
		class, _ := manifestString(row, "security_class")
		return class == "restricted_no_embed"
	}, func(row map[string]interface{}) {
		row["normal_consumer_visibility"] = true
	})
	newSecurityDigest := fileSHA256(t, securityPath)
	mutateJSONLRow(t, fieldMappingPath, "artifact_manifest", func(row map[string]interface{}) {
		row["field_security_policy_artifact_sha256"] = newSecurityDigest
	})
	mutateJSONLRow(t, fieldMappingPath, "validation_summary", func(row map[string]interface{}) {
		row["security_policy_artifact_sha256"] = newSecurityDigest
	})
	if oldSecurityDigest == newSecurityDigest {
		t.Fatal("field-security test mutation did not change exact artifact bytes")
	}
	fixture.manifest().FieldSecurityPolicySHA256 = newSecurityDigest
	fixture.manifest().FieldMappingCandidateSHA256 = fileSHA256(t, fieldMappingPath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleFieldSecurityPolicy, dependencySemanticRoleFieldMapping)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "permits normal-consumer visibility") {
		t.Fatalf("got %v, want fail-closed security visibility refusal", err)
	}
}

func TestVerifyRejectsOrphanTypedGap(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	gap := &graphGap{RowKind: "candidate_graph_gap", GapClass: "fixture_gap", BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: fixture.symbolByRole["vendor_api"], BlockedClaimKind: "fixture_requirement", BlockedClaimID: "fixture_claim", Disposition: "fail_closed", ApplicabilityProfileID: fixture.applicability.ProfileID, ApplicabilityProfileVersion: fixture.applicability.ProfileVersion, ApplicabilityProfileSHA256: fixture.applicability.ProfileSHA256, ApplicabilityRuleID: fixture.claimRuleID, EvidenceLocatorIDs: []string{fixture.locatorID}, GapProofBinding: fixtureGapProof(fixture.locatorID)}
	gap.DerivationBinding = fixtureGapDerivationBinding(t, fixture.dependencyByRole["api_graph_applicability"], *gap)
	gapIdentity, err := candidateGraphGapIdentityKey(*gap)
	if err != nil {
		t.Fatal(err)
	}
	gap.ID = stableID("capi_gap", gapIdentity)
	fixture.planRows = append(fixture.planRows[:len(fixture.planRows)-1], gap, fixture.summary())
	fixture.summary().CandidateGraphGapCount = 1
	fixture.summary().Result = resultCompleteWithGap
	resealFixtureGraph(t, fixture)
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "optional disposition persists") {
		t.Fatalf("got %v, want orphan typed-gap refusal", err)
	}
}

func TestVerifyRejectsRequiredOperationRelationshipWithoutFactOrGap(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	removeSourceOperationReadWriteCoverage(t, fixture)
	fixture.summary().Result = resultCompleteWithGap
	resealFixtureGraph(t, fixture)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "fact-or-gap coverage 0, want 1") {
		t.Fatalf("got %v, want required operation relationship refusal", err)
	}
}

func TestVerifyAcceptsRequiredOperationRelationshipWithExactIncompleteGap(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	removeSourceOperationReadWriteCoverage(t, fixture)
	missingRelationshipID := stableID("capi_rel", lengthPrefixedIdentityKey("operation_reads_resource", fixture.sourceOperationID, fixture.symbolByRole["resource"]))
	gap := &graphGap{RowKind: "candidate_graph_gap", GapClass: "required_api_relationship_incomplete", BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: fixture.sourceOperationID, BlockedClaimKind: "api_relationship", BlockedClaimID: missingRelationshipID, Disposition: "fail_closed", ApplicabilityProfileID: fixture.applicability.ProfileID, ApplicabilityProfileVersion: fixture.applicability.ProfileVersion, ApplicabilityProfileSHA256: fixture.applicability.ProfileSHA256, ApplicabilityRuleID: fixture.ruleByLabel["operation_reads_resource"], EvidenceLocatorIDs: []string{fixture.locatorID}, GapProofBinding: fixtureGapProof(fixture.locatorID)}
	gap.DerivationBinding = fixtureGapDerivationBinding(t, fixture.dependencyByRole["api_graph_applicability"], *gap)
	gapIdentity, err := candidateGraphGapIdentityKey(*gap)
	if err != nil {
		t.Fatal(err)
	}
	gap.ID = stableID("capi_gap", gapIdentity)
	fixture.planRows = append(fixture.planRows[:len(fixture.planRows)-1], gap, fixture.summary())
	fixture.summary().CandidateGraphGapCount = 1
	fixture.summary().Result = resultCompleteWithGap
	resealFixtureGraph(t, fixture)
	if _, err := Verify(fixture.options); err != nil {
		t.Fatalf("Verify exact required-operation gap: %v", err)
	}
}

func TestVerifyRejectsArbitraryCandidatePropertiesAtClosedGraphSchema(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	writeJSONL(t, fixture.planPath, fixture.planRows)
	mutateJSONLMatchingRow(t, fixture.planPath, "candidate_api_symbol", semanticStringFieldEquals("candidate_api_symbol_id", fixture.symbolByRole["vendor_api"]), func(row map[string]interface{}) {
		row["candidate_properties"] = map[string]interface{}{"documentation_note": "not part of the authoritative typed graph contract"}
	})
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "fails its bound schema") {
		t.Fatalf("got %v, want closed graph-schema refusal", err)
	}
}

func TestRejectReconstructedCredentialMaterialAcrossJSONScalars(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "assignment", raw: `["api_","key=live-","A1b2C3d4E5f6G7h8I9j0"]`},
		{name: "known prefix", raw: `["sk-","live-","A1b2C3d4E5f6G7h8I9j0"]`},
		{name: "jwt", raw: `["eyJhbGciOiJIUzI1NiJ9.","eyJzdWIiOiJmaXh0dXJlIn0.","signature"]`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := rejectReconstructedCredentialMaterial([]byte(test.raw)); err == nil || !strings.Contains(err.Error(), "reconstructed across") {
				t.Fatalf("error = %v, want split credential-material refusal", err)
			}
		})
	}
}

func TestRejectReconstructedCredentialMaterialTreatsExactPlaceholderAsBoundary(t *testing.T) {
	if err := rejectReconstructedCredentialMaterial([]byte(`["api_key=","<API_KEY>","documentation-only"]`)); err != nil {
		t.Fatalf("exact placeholder boundary rejected: %v", err)
	}
}

func TestLoadEvidenceBodiesPreservesCredentialShapedOfficialDocumentationPayload(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	body := []byte("# Official authentication examples\nAuthorization: Basic UHVibGljRXhhbXBsZUNsaWVudDpQdWJsaWNFbmNvZGVkRXhhbXBsZQ==\naccess_token=PublicDocumentationAccessToken123456\nrefresh_token=PublicDocumentationRefreshToken123456\nclient_secret=<CLIENT_SECRET>\n")
	bodyDigest := sha256Hex(body)
	bodyPath := filepath.Join(filepath.Dir(fixture.evidencePath), "body.md.b64")
	if err := os.WriteFile(bodyPath, []byte(base64.StdEncoding.EncodeToString(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	mutateJSONLRow(t, fixture.evidencePath, "external_evidence_body", func(row map[string]interface{}) {
		row["component_byte_length"] = len(body)
		row["component_sha256"] = bodyDigest
		row["content_bytes"] = len(body)
		row["content_sha256"] = bodyDigest
		row["observed_line_delimiter_profile"] = "LF"
	})
	mutateJSONLRow(t, fixture.evidencePath, "validation_summary", func(row map[string]interface{}) {
		row["total_exact_source_bytes"] = len(body)
	})
	loaded, err := loadEvidenceBodies(
		[]string{fixture.evidencePath},
		map[string]struct{}{supportedEvidenceRepresentationKind: {}},
	)
	if err != nil {
		t.Fatalf("official selected documentation payload was rejected: %v", err)
	}
	selected, ok := loaded.Bodies[bodyDigest]
	if !ok || !bytes.Equal(selected.Bytes, body) {
		t.Fatalf("selected evidence payload digest %s was not preserved byte-for-byte", bodyDigest)
	}
}

func TestVerifyRejectsCredentialMaterialInEvidenceManifestMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rowKind string
		mutate  func(map[string]interface{})
	}{
		{name: "artifact", rowKind: "artifact_manifest", mutate: func(row map[string]interface{}) { row["artifact"] = "sk-live-A1b2C3d4E5f6G7h8I9j0" }},
		{name: "provider", rowKind: "artifact_manifest", mutate: func(row map[string]interface{}) { row["provider"] = "api_key=live-A1b2C3d4E5f6G7h8I9j0" }},
		{name: "staging file", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["staging_file"] = "sk-live-A1b2C3d4E5f6G7h8I9j0.b64" }},
		{name: "summary", rowKind: "validation_summary", mutate: func(row map[string]interface{}) { row["result"] = "Bearer A1b2C3d4E5f6G7h8I9j0K1l2" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			mutateJSONLRow(t, fixture.evidencePath, test.rowKind, test.mutate)
			fixture.manifest().EvidenceManifestBindings[0].EvidenceManifestSHA256 = fileSHA256(t, fixture.evidencePath)
			writeJSONL(t, fixture.planPath, fixture.planRows)
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), "credential or secret material") {
				t.Fatalf("got %v, want evidence-manifest metadata credential refusal", err)
			}
		})
	}
}

func TestVerifyRejectsMissingPlanDeclaredDependencyArtifact(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	fixture.options.DependencyArtifactPath = fixture.options.DependencyArtifactPath[1:]
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "dependency semantic role \"provider_neutral_compilation_profile\"") {
		t.Fatalf("got %v, want missing declared dependency refusal", err)
	}
}

func TestVerifyRejectsDependencyBytesChangedAfterGraphSelection(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	request, inputs := newVerifyGraphStageSelection(t, fixture)
	fixture.options.graphCompileSelectionLoader = func() ([]byte, StageCompileInputs, error) {
		return bytes.Clone(request), inputs, nil
	}

	path := fixture.dependencyByRole["operation_applicability"]
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(raw, []byte(`"row_kind":"artifact_manifest"`), []byte(`"row_kind": "artifact_manifest"`), 1)
	if bytes.Equal(mutated, raw) {
		t.Fatal("operation-applicability fixture did not contain the expected manifest encoding")
	}
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), `dependency semantic role "operation_applicability_profile"`) || !strings.Contains(err.Error(), "exact supplied bytes") {
		t.Fatalf("got %v, want fail-closed dependency-path versus graph-selection digest refusal", err)
	}
}

func TestVerifyRejectsMissingEvidenceValidationSummary(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	raw, err := os.ReadFile(fixture.evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) != 3 {
		t.Fatalf("evidence fixture lines=%d, want 3", len(lines))
	}
	if err := os.WriteFile(fixture.evidencePath, append(append([]byte(nil), bytes.Join(lines[:2], []byte{'\n'})...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "evidence validation_summary") {
		t.Fatalf("got %v, want missing evidence-summary refusal", err)
	}
}

func TestVerifyRejectsMarkerOnlyDependencyValidationSummary(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	profilePath := fixture.dependencyByRole["profile"]
	raw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	lines[len(lines)-1] = []byte(`{"row_kind":"validation_summary"}`)
	if err := os.WriteFile(profilePath, append(bytes.Join(lines, []byte{'\n'}), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleProfile)
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "fails its bound schema") {
		t.Fatalf("got %v, want marker-only dependency-summary refusal", err)
	}
}

func TestVerifyRejectsForgedEvidenceManifestStatus(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	mutateJSONLRow(t, fixture.evidencePath, "artifact_manifest", func(row map[string]interface{}) {
		row["status"] = "admitted"
	})
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "status other than candidate_not_admissible") {
		t.Fatalf("got %v, want forged evidence-manifest status refusal", err)
	}
}

func TestVerifyRejectsForgedDependencyManifestStatus(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	mutateJSONLRow(t, fixture.dependencyByRole["source_contract"], "artifact_manifest", func(row map[string]interface{}) {
		row["status"] = "admitted"
	})
	rebindSourceContract(t, fixture)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "status other than candidate_not_admissible") {
		t.Fatalf("got %v, want forged dependency-manifest status refusal", err)
	}
}

func TestVerifyRejectsForgedProfileStatus(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	profilePath := fixture.dependencyByRole["profile"]
	mutateJSONLRow(t, profilePath, "artifact_manifest", func(row map[string]interface{}) {
		row["status"] = "ready_to_execute"
	})
	fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleProfile)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "must have status candidate_not_admissible") {
		t.Fatalf("got %v, want forged profile status refusal", err)
	}
}

func TestVerifyRejectsWrongEvidenceSummaryScalarTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		field string
		value interface{}
		want  string
	}{
		{name: "integer", field: "selected_source_count", value: "1", want: "exact generic selected source-document roster"},
		{name: "boolean", field: "rendered_dom_body_accepted", value: "false", want: "reject rendered DOM"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			mutateJSONLRow(t, fixture.evidencePath, "validation_summary", func(row map[string]interface{}) {
				row[test.field] = test.value
			})
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want strict evidence-summary %s refusal", err, test.name)
			}
		})
	}
}

func TestVerifyRejectsBrokenEvidenceCompletenessTuple(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	baselineEvidence, err := os.ReadFile(fixture.evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		rowKind string
		mutate  func(map[string]interface{})
		want    string
	}{
		{name: "manifest root fabricated", rowKind: "artifact_manifest", mutate: func(row map[string]interface{}) {
			row["canonical_component_manifest_root_hash"] = strings.Repeat("a", 64)
		}, want: "closed manifest key set"},
		{name: "manifest staging encoding", rowKind: "artifact_manifest", mutate: func(row map[string]interface{}) { row["staging_encoding"] = "plain_text" }, want: "closed manifest key set"},
		{name: "manifest evidence authority", rowKind: "artifact_manifest", mutate: func(row map[string]interface{}) { row["evidence_authority"] = "diagnostic_dom" }, want: "closed manifest key set"},
		{name: "manifest unknown key", rowKind: "artifact_manifest", mutate: func(row map[string]interface{}) { row["live_complete"] = true }, want: "closed manifest key set"},
		{name: "ordinal", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["component_ordinal"] = json.Number("1") }, want: "zero-based contiguous ordinal"},
		{name: "stable coordinate", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["component_stable_coordinate"] = "forged" }, want: "source_ref/source_url identity"},
		{name: "component length", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["component_byte_length"] = json.Number("999") }, want: "component byte length/hash tuple"},
		{name: "component digest", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["component_sha256"] = strings.Repeat("0", 64) }, want: "component byte length/hash tuple"},
		{name: "component byte domain", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["component_byte_domain_profile"] = "normalized_text" }, want: "exact-byte contract"},
		{name: "source content hash profile", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["source_content_hash_profile"] = "normalized_text" }, want: "exact-byte contract"},
		{name: "line delimiter", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["observed_line_delimiter_profile"] = "LF" }, want: "does not match exact staged bytes"},
		{name: "representation", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["representation"] = "rendered_dom_text" }, want: "manifest-declared source representation profile and coordinate"},
		{name: "body authority", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["body_authority"] = "diagnostic" }, want: "manifest-declared source representation profile and coordinate"},
		{name: "docgraph status", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["docgraph_status"] = "admitted" }, want: "unknown key"},
		{name: "surface kind", rowKind: "external_evidence_body", mutate: func(row map[string]interface{}) { row["surface_kind"] = "non canonical" }, want: "unknown key \"surface_kind\""},
		{name: "summary surface count", rowKind: "validation_summary", mutate: func(row map[string]interface{}) {
			row["captured_surface_kind_counts"] = map[string]interface{}{"data_entity": json.Number("2")}
		}, want: "does not match its closed key set"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(fixture.evidencePath, baselineEvidence, 0o600); err != nil {
				t.Fatal(err)
			}
			mutateJSONLRow(t, fixture.evidencePath, test.rowKind, test.mutate)
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want %q refusal", err, test.want)
			}
		})
	}
}

func TestVerifyRejectsEvidenceStagingPathEscape(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	mutateJSONLRow(t, fixture.evidencePath, "external_evidence_body", func(row map[string]interface{}) {
		row["staging_file"] = "../body.md.b64"
	})
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "non-relative staging_file") {
		t.Fatalf("got %v, want staging-path escape refusal", err)
	}
}

func TestResolveRelativeEvidenceStagingPathRejectsNonRegularAndWindowsSpecialNames(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "manifest.jsonl")
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "payload")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveRelativeEvidenceStagingPath(manifestPath, "payload"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("got %v, want non-regular staging-file refusal", err)
	}
	if filepath.Separator == '\\' {
		for _, declared := range []string{"body.md:stream", "NUL", "COM1.txt", "nested/LPT9.bin"} {
			if _, err := resolveRelativeEvidenceStagingPath(manifestPath, declared); err == nil || !strings.Contains(err.Error(), "non-relative staging_file") {
				t.Fatalf("got %v for %q, want Windows special-name refusal", err, declared)
			}
		}
	}
}

func TestValidateLocatorAllowsByteExactRangeAcrossUTF8ScalarBoundary(t *testing.T) {
	body := []byte("é")
	coordinate := evidenceSourceCoordinate{Ref: "fixture", URL: "https://example.com/fixture"}
	locator := evidenceLocator{EvidenceManifestSHA256: strings.Repeat("a", 64), SourceContentSHA256: sha256Hex(body), ByteStartOffset: 0, ByteEndOffsetExclusive: 1, SelectedRangeByteCount: 1, SelectedRangeSHA256: sha256Hex(body[:1]), SourceRefs: []string{coordinate.Ref}, SourceURLs: []string{coordinate.URL}, LocatorSemantics: exactLocatorSemantics}
	locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
	if err := validateLocator(locator, map[string]exactEvidenceBody{sha256Hex(body): {Bytes: body, Coordinates: map[evidenceSourceCoordinate]string{coordinate: strings.Repeat("a", 64)}}}); err != nil {
		t.Fatalf("byte-exact locator rejected a representation-neutral byte range: %v", err)
	}
}

func TestVerifyRejectsWrongDependencySummaryScalarTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		field string
		value interface{}
		want  string
	}{
		{name: "integer", field: "field_contract_count", value: "1", want: "fails its bound schema"},
		{name: "boolean", field: "source_neutral_targets_admitted", value: "false", want: "fails its bound schema"},
		{name: "optional integer", field: "issue_count", value: "0", want: "fails its bound schema"},
		{name: "second boolean", field: "diagnostic_line_and_section_coordinates_are_authority", value: "false", want: "fails its bound schema"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			mutateJSONLRow(t, fixture.dependencyByRole["source_contract"], "validation_summary", func(row map[string]interface{}) {
				row[test.field] = test.value
			})
			rebindSourceContract(t, fixture)
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want strict dependency-summary %s refusal", err, test.name)
			}
		})
	}
}

func TestVerifyRejectsForgedDependencyValidationSummaryResult(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	path := fixture.dependencyByRole["source_contract"]
	mutateJSONLRow(t, path, "validation_summary", func(row map[string]interface{}) {
		row["result"] = "candidate_parse_failed"
	})
	rebindSourceContract(t, fixture)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "candidate_parse_complete") {
		t.Fatalf("got %v, want forged dependency-summary result refusal", err)
	}
}

func TestVerifyRejectsUnboundTransitiveProfileAuthorityPin(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	profilePath := fixture.dependencyByRole["profile"]
	mutateJSONLRow(t, profilePath, "artifact_manifest", func(row map[string]interface{}) {
		row["grand_vision"].(map[string]interface{})["raw_sha256"] = strings.Repeat("1", 64)
	})
	fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleProfile)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "does not equal independently selected bytes") {
		t.Fatalf("got %v, want unbound transitive authority refusal", err)
	}
}

func TestVerifyRejectsUnboundAdditionalTransitiveProfileAuthorityPin(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	profilePath := fixture.dependencyByRole["profile"]
	mutateJSONLRow(t, profilePath, "artifact_manifest", func(row map[string]interface{}) {
		row["additional_source_neutral_authority"] = map[string]interface{}{"raw_sha256": strings.Repeat("3", 64)}
	})
	fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleProfile)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "fails its bound schema") {
		t.Fatalf("got %v, want complete transitive authority-closure refusal", err)
	}
}

func TestVerifyRejectsTransitiveAuthorityAliasedToSelectedOOD(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	profilePath := fixture.dependencyByRole["profile"]
	mutateJSONLRow(t, profilePath, "artifact_manifest", func(row map[string]interface{}) {
		row["grand_vision"].(map[string]interface{})["raw_sha256"] = fileSHA256(t, fixture.oodPath)
	})
	fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleProfile)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "does not equal independently selected bytes") {
		t.Fatalf("got %v, want authority-role alias refusal", err)
	}
}

func TestVerifyRejectsProtocolManifestDigestNotBoundToEvidenceInput(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	fixture.manifest().EvidenceManifestBindings[1].EvidenceManifestSHA256 = strings.Repeat("0", 64)
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "evidence_manifest_bindings") {
		t.Fatalf("got %v, want protocol-manifest binding refusal", err)
	}
}

func TestVerifyRejectsProfileWhoseEmbeddedOODDigestDiffersFromSelectedBytes(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	profilePath := fixture.dependencyByRole["profile"]
	mutateJSONLRow(t, profilePath, "artifact_manifest", func(row map[string]interface{}) {
		row["canonical_ood_graph_spec"].(map[string]interface{})["raw_sha256"] = strings.Repeat("0", 64)
	})
	fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleProfile)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "embedded OOD digest") {
		t.Fatalf("got %v, want profile/OOD binding refusal", err)
	}
}

func TestVerifyRejectsSourceIndexWhoseEntityManifestDigestIsUnbound(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	path := fixture.dependencyByRole["source_contract"]
	mutateJSONLRow(t, path, "artifact_manifest", func(row map[string]interface{}) {
		row["derived_from_manifest_sha256s"] = []string{strings.Repeat("0", 64)}
	})
	fixture.manifest().SourceContractIndexSHA256 = fileSHA256(t, path)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleSourceContract)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "derived_from_manifest_sha256s") {
		t.Fatalf("got %v, want entity-manifest binding refusal", err)
	}
}

func TestVerifyRejectsSourceIndexBoundToProtocolEvidenceManifest(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	path := fixture.dependencyByRole["source_contract"]
	mutateJSONLRow(t, path, "artifact_manifest", func(row map[string]interface{}) {
		row["derived_from_manifest_sha256s"] = []string{fileSHA256(t, fixture.evidenceByRole["protocol"])}
	})
	fixture.manifest().SourceContractIndexSHA256 = fileSHA256(t, path)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleSourceContract)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "derived_from_manifest_sha256s is missing") {
		t.Fatalf("got %v, want entity/protocol manifest role refusal", err)
	}
}

func TestVerifyRejectsSampleIndexBoundToDifferentEntityManifest(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	entityRaw, err := os.ReadFile(fixture.evidenceByRole["entity"])
	if err != nil {
		t.Fatal(err)
	}
	entityRaw = bytes.Replace(entityRaw, []byte("fixture_copy_all_for_ai_evidence_manifest"), []byte("alternate_copy_all_for_ai_evidence_manifest"), 1)
	alternatePath := filepath.Join(filepath.Dir(fixture.planPath), "alternate-entity-evidence.jsonl")
	if err := os.WriteFile(alternatePath, entityRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	originalCarrierPath := filepath.Join(filepath.Dir(fixture.evidenceByRole["entity"]), "body.md.b64")
	alternateCarrierRaw, err := os.ReadFile(originalCarrierPath)
	if err != nil {
		t.Fatal(err)
	}
	alternateCarrierPath := filepath.Join(filepath.Dir(alternatePath), "alternate-body.md.b64")
	if err := os.WriteFile(alternateCarrierPath, alternateCarrierRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	mutateJSONLRow(t, alternatePath, "external_evidence_body", func(row map[string]interface{}) {
		row["source_ref"] = "alternate"
		row["source_url"] = "https://example.com/alternate"
		row["component_stable_coordinate"] = "source_ref_url_pair_v1|" + lengthPrefixedIdentityKey("alternate", "https://example.com/alternate")
		row["staging_file"] = filepath.Base(alternateCarrierPath)
	})
	fixture.options.EvidenceManifestPath = append(fixture.options.EvidenceManifestPath, alternatePath)
	samplePath := fixture.dependencyByRole["sample_shape"]
	mutateJSONLRow(t, samplePath, "artifact_manifest", func(row map[string]interface{}) {
		row["derived_from_manifest_sha256s"] = []string{fileSHA256(t, alternatePath)}
	})
	fixture.manifest().SampleShapeIndexSHA256 = fileSHA256(t, samplePath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleSampleShape)
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "supplied evidence closure contains 3 manifests") {
		t.Fatalf("got %v, want mixed entity-manifest refusal", err)
	}
}

func TestVerifyRejectsMissingNestedSurfaceDispositionArtifact(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	dispositionPath := fixture.dependencyByRole["surface_disposition"]
	paths := fixture.options.DependencyArtifactPath[:0]
	for _, path := range fixture.options.DependencyArtifactPath {
		if path != dispositionPath {
			paths = append(paths, path)
		}
	}
	fixture.options.DependencyArtifactPath = paths
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "dependency semantic role \"surface_family_disposition\"") {
		t.Fatalf("got %v, want missing nested dependency refusal", err)
	}
}

func TestVerifyRejectsUnreferencedDependencyArtifact(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	extraPath := filepath.Join(filepath.Dir(fixture.planPath), "unreferenced.jsonl")
	writeJSONL(t, extraPath, []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "unreferenced_candidate", "artifact_version": "1", "status": "candidate_not_admissible", "provider": "fixture_provider",
	}})
	fixture.options.DependencyArtifactPath = append(fixture.options.DependencyArtifactPath, extraPath)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "supplied but not bound") {
		t.Fatalf("got %v, want unreferenced dependency refusal", err)
	}
}

func TestVerifyRejectsAliasedDirectDependencyRoles(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	fixture.manifest().SampleShapeIndexSHA256 = fixture.manifest().SourceContractIndexSHA256
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "aliases roles") {
		t.Fatalf("got %v, want aliased dependency-role refusal", err)
	}
}

func TestVerifyRejectsSurfaceDispositionAliasedToDirectDependency(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	fieldMapPath := fixture.dependencyByRole["field_mapping"]
	raw, err := os.ReadFile(fieldMapPath)
	if err != nil {
		t.Fatal(err)
	}
	dispositionDigest := fileSHA256(t, fixture.dependencyByRole["surface_disposition"])
	raw = bytes.Replace(raw, []byte(dispositionDigest), []byte(fixture.manifest().SourceContractIndexSHA256), 1)
	if err := os.WriteFile(fieldMapPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.manifest().FieldMappingCandidateSHA256 = fileSHA256(t, fieldMapPath)
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "aliases roles") {
		t.Fatalf("got %v, want nested/direct dependency-alias refusal", err)
	}
}

func TestVerifyRejectsFalseDependencyDerivedSummaryCount(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	fixture.summary().ExactSourceDocumentCount++
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "exact_source_document_count") {
		t.Fatalf("got %v, want exact dependency-summary count refusal", err)
	}
}

func TestVerifyRejectsIncompleteProfileRegistryProjection(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	profilePath := fixture.dependencyByRole["profile"]
	removeJSONLMatchingRow(t, profilePath, "api_element_role", func(row map[string]interface{}) bool {
		role, _ := semanticString(row, "api_element_role")
		return role == fixture.roles[0]
	})
	fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleProfile)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "api_element_role_count") {
		t.Fatalf("got %v, want incomplete profile-registry refusal", err)
	}
}

func TestVerifyRejectsProviderNeutralProfileAuthoritySubstitution(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	profilePath := fixture.dependencyByRole["profile"]
	validationProfilePath := fixture.dependencyByRole["dependency_semantic_validation_profile"]
	baselineProfile, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatal(err)
	}
	baselineValidationProfile, err := os.ReadFile(validationProfilePath)
	if err != nil {
		t.Fatal(err)
	}
	baselineProfileDigest := fixture.manifest().ProviderNeutralProfileSHA256
	baselineValidationProfileDigest := fixture.manifest().DependencySemanticValidation.Profile.RawSHA256
	tests := []struct {
		name    string
		rowKind string
		match   func(map[string]interface{}) bool
		mutate  func(map[string]interface{})
		want    string
	}{
		{name: "role authority", rowKind: "api_element_role", match: semanticStringFieldEquals("api_element_role", "vendor_api"), mutate: func(row map[string]interface{}) { row["role_binding_authority"] = "caller_owned" }, want: "authoritative api_symbol role"},
		{name: "role source path", rowKind: "api_element_role", match: semanticStringFieldEquals("api_element_role", "vendor_api"), mutate: func(row map[string]interface{}) { row["source_field_path"] = "provider.roles" }, want: "authoritative api_symbol role"},
		{name: "relationship source path", rowKind: "api_relationship", match: semanticStringFieldEquals("edge_label", "api_has_operation"), mutate: func(row map[string]interface{}) { row["source_field_path"] = "provider.relationships" }, want: "endpoint-role constraint"},
		{name: "property exclusions", rowKind: "api_property_family", match: semanticStringFieldEquals("property_family", "http_method"), mutate: func(row map[string]interface{}) { row["authority_exclusions"] = []string{"search_payload"} }, want: "schema/evidence binding"},
		{name: "capability substitution", rowKind: "capability_stage", match: func(row map[string]interface{}) bool {
			ordinal, _ := semanticInt64(row, "ordinal")
			return ordinal == 1
		}, mutate: func(row map[string]interface{}) { row["capability"] = "provider.fetch" }, want: "want OOD capability"},
		{name: "capability source path", rowKind: "capability_stage", match: func(row map[string]interface{}) bool {
			ordinal, _ := semanticInt64(row, "ordinal")
			return ordinal == 1
		}, mutate: func(row map[string]interface{}) { row["source_field_path"] = "provider.capabilities" }, want: "weakens admitted generic execution"},
		{name: "object class", rowKind: "external_document_object_class", match: semanticStringFieldEquals("object_class", "external_reference_doc"), mutate: func(row map[string]interface{}) { row["object_class"] = "provider_object" }, want: "registry"},
		{name: "edge source path", rowKind: "external_document_edge_label", match: semanticStringFieldEquals("edge_label", "documents"), mutate: func(row map[string]interface{}) { row["source_field_path"] = "provider.edges" }, want: "marker"},
		{name: "authority disposition", rowKind: "source_authority_class", match: semanticStringFieldEquals("source_class", "official_vendor_documentation"), mutate: func(row map[string]interface{}) { row["disposition"] = "forbidden" }, want: "selected OOD authority class"},
		{name: "authority policy", rowKind: "source_authority_class", match: semanticStringFieldEquals("source_class", "official_vendor_documentation"), mutate: func(row map[string]interface{}) { row["policy_rule"] = "caller decides" }, want: "selected OOD authority class"},
		{name: "entry capability", rowKind: "execution_boundary", match: func(map[string]interface{}) bool { return true }, mutate: func(row map[string]interface{}) { row["entry_capability"] = "provider.fetch" }, want: "selected OOD entry capability"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(profilePath, baselineProfile, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(validationProfilePath, baselineValidationProfile, 0o600); err != nil {
				t.Fatal(err)
			}
			fixture.manifest().ProviderNeutralProfileSHA256 = baselineProfileDigest
			fixture.manifest().DependencySemanticValidation.Profile.RawSHA256 = baselineValidationProfileDigest
			writeJSONL(t, fixture.planPath, fixture.planRows)
			mutateJSONLMatchingRow(t, profilePath, test.rowKind, test.match, test.mutate)
			fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
			rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleProfile)
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want profile authority refusal containing %q", err, test.want)
			}
		})
	}
}

func semanticStringFieldEquals(field, want string) func(map[string]interface{}) bool {
	return func(row map[string]interface{}) bool {
		value, _ := semanticString(row, field)
		return value == want
	}
}

func TestVerifyRejectsIncompleteFieldMappingCoverage(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	fieldMapPath := fixture.dependencyByRole["field_mapping"]
	removeJSONLMatchingRow(t, fieldMapPath, "field_occurrence_disposition", func(map[string]interface{}) bool { return true })
	fixture.manifest().FieldMappingCandidateSHA256 = fileSHA256(t, fieldMapPath)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleFieldMapping)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "disposed_field_occurrence_count") {
		t.Fatalf("got %v, want incomplete field-mapping coverage refusal", err)
	}
}

func TestVerifyRejectsBinaryFloatShapedDependencyFact(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	mutateJSONLRow(t, fixture.dependencyByRole["source_contract"], "api_operation", func(row map[string]interface{}) {
		row["candidate_numeric_fact"] = json.Number("1.25")
	})
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "binary-float-shaped JSON number") {
		t.Fatalf("got %v, want binary-float dependency refusal", err)
	}
}

func TestVerifyRejectsEvidenceManifestMutationBeforeProviderSubstitution(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	raw, err := os.ReadFile(fixture.evidenceByRole["protocol"])
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"provider":"fixture_provider"`), []byte(`"provider":"different_provider"`), 1)
	if err := os.WriteFile(fixture.evidenceByRole["protocol"], raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "not locator-bound manifest") {
		t.Fatalf("got %v, want manifest-identity refusal before provider substitution", err)
	}
}

func TestVerifyRejectsFalseLocatorManifestDigest(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	fixture.manifest().EvidenceLocatorManifestSHA256 = strings.Repeat("0", 64)
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "evidence_locator_manifest_sha256") {
		t.Fatalf("got %v, want locator-manifest binding refusal", err)
	}
}

func TestVerifyRejectsUnboundApplicabilityArtifactPins(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		mutate func(*artifactManifest)
		want   string
	}{
		{name: "operation", mutate: func(manifest *artifactManifest) {
			manifest.OperationApplicabilityProfileSHA256 = strings.Repeat("0", 64)
		}, want: dependencySemanticRoleOperationApplicability},
		{name: "api graph", mutate: func(manifest *artifactManifest) {
			manifest.APIGraphApplicabilityProfileSHA256 = strings.Repeat("0", 64)
		}, want: dependencySemanticRoleAPIGraphApplicability},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			test.mutate(fixture.manifest())
			writeJSONL(t, fixture.planPath, fixture.planRows)
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want exact %s pin refusal", err, test.want)
			}
		})
	}
}

func TestVerifyRejectsOperationApplicabilityTraitSubstitution(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	path := fixture.dependencyByRole["operation_applicability"]
	mutateJSONLMatchingRow(t, path, "operation_applicability", semanticStringFieldEquals("operation_candidate_api_symbol_id", fixture.symbolByRole["operation"]), func(row map[string]interface{}) {
		traits := row["subject_traits"].(map[string]interface{})
		traits["emits_change_event"] = false
	})
	rebindOperationApplicability(t, fixture)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "generic classifier reexecution") {
		t.Fatalf("got %v, want data-driven applicability-trait refusal", err)
	}
}

func TestVerifyRejectsOperationApplicabilityIncidentRosterOmission(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	path := fixture.dependencyByRole["operation_applicability"]
	mutateJSONLMatchingRow(t, path, "operation_applicability", semanticStringFieldEquals("operation_candidate_api_symbol_id", fixture.sourceOperationID), func(row map[string]interface{}) {
		roster := row["actual_relationship_ids"].([]interface{})
		row["actual_relationship_ids"] = roster[1:]
	})
	rebindOperationApplicability(t, fixture)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "incident relationship roster") {
		t.Fatalf("got %v, want exact incident-relationship roster refusal", err)
	}
}

func TestVerifyRejectsOperationApplicabilityResourceRetarget(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	path := fixture.dependencyByRole["operation_applicability"]
	mutateJSONLMatchingRow(t, path, "operation_applicability", semanticStringFieldEquals("operation_candidate_api_symbol_id", fixture.sourceOperationID), func(row map[string]interface{}) {
		binding := row["resource_accesses"].([]interface{})[0].(map[string]interface{})
		binding["resource_candidate_api_symbol_id"] = fixture.symbolByRole["auth_scheme"]
	})
	rebindOperationApplicability(t, fixture)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "resource_access_id is not content-derived") {
		t.Fatalf("got %v, want exact operation-resource retarget refusal", err)
	}
}

func TestVerifyLocatorManifestDigestBindsExactEmittedRowBytes(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	raw, err := os.ReadFile(fixture.planPath)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`{"row_kind":"candidate_evidence_locator"`), []byte(` {"row_kind":"candidate_evidence_locator"`), 1)
	if err := os.WriteFile(fixture.planPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "evidence_locator_manifest_sha256") {
		t.Fatalf("got %v, want exact locator-row byte refusal", err)
	}
}

func TestLengthPrefixedIdentityKeyHasUnambiguousUTF8FieldBoundaries(t *testing.T) {
	left := lengthPrefixedIdentityKey("a|b", "c")
	right := lengthPrefixedIdentityKey("a", "b|c")
	if left == right {
		t.Fatalf("ambiguous field boundaries: %q", left)
	}
	if got, want := lengthPrefixedIdentityKey("é"), "2:é"; got != want {
		t.Fatalf("UTF-8 byte length key=%q, want %q", got, want)
	}
}

func TestVerifyRejectsRoleMismatchedRelationship(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	for _, raw := range fixture.planRows {
		relationship, ok := raw.(*apiRelationship)
		if !ok || relationship.Label != "operation_reads_resource" {
			continue
		}
		relationship.TargetID = fixture.symbolByRole["auth_scheme"]
		relationship.ID = stableID("capi_rel", lengthPrefixedIdentityKey(relationship.Label, relationship.SourceID, relationship.TargetID))
		break
	}
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "requires operation->resource") {
		t.Fatalf("got %v, want closed role-registry endpoint refusal", err)
	}
}

func TestVerifyRejectsByteRangeThatDoesNotHydrate(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	for _, raw := range fixture.planRows {
		locator, ok := raw.(*evidenceLocator)
		if !ok {
			continue
		}
		locator.SelectedRangeSHA256 = strings.Repeat("0", 64)
		oldID := locator.ID
		locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(*locator))
		for _, candidate := range fixture.planRows {
			switch row := candidate.(type) {
			case *apiSymbol:
				row.EvidenceLocatorIDs = replaceString(row.EvidenceLocatorIDs, oldID, locator.ID)
			case *apiRelationship:
				row.LocatorIDs = replaceString(row.LocatorIDs, oldID, locator.ID)
			case *apiPropertyClaim:
				row.LocatorIDs = replaceString(row.LocatorIDs, oldID, locator.ID)
			case *graphGap:
				row.EvidenceLocatorIDs = replaceString(row.EvidenceLocatorIDs, oldID, locator.ID)
			}
		}
		break
	}
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "selected bytes do not match") {
		t.Fatalf("got %v, want exact-hydration refusal", err)
	}
}

func TestVerifyRejectsLocatorURLNotBoundToExactEvidenceBody(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	for _, raw := range fixture.planRows {
		locator, ok := raw.(*evidenceLocator)
		if !ok {
			continue
		}
		locator.SourceURLs = []string{"https://example.com/different-page"}
		locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(*locator))
		break
	}
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "is not bound to the exact evidence-manifest body") {
		t.Fatalf("got %v, want source-URL/body binding refusal", err)
	}
}

func TestVerifyRejectsLocatorRefNotBoundToExactEvidenceBody(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	for _, raw := range fixture.planRows {
		locator, ok := raw.(*evidenceLocator)
		if !ok {
			continue
		}
		locator.SourceRefs = []string{"different-source"}
		locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(*locator))
		break
	}
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "is not bound to the exact evidence-manifest body") {
		t.Fatalf("got %v, want source-ref/body binding refusal", err)
	}
}

func TestVerifyRejectsEvidenceBodyWithoutCanonicalSourceCoordinate(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	raw, err := os.ReadFile(fixture.evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"source_url":"https://example.com/fixture",`), nil, 1)
	if err := os.WriteFile(fixture.evidencePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "external_evidence_body is missing required key \"source_url\"") {
		t.Fatalf("got %v, want missing evidence source-coordinate refusal", err)
	}
}

func TestVerifyRejectsCrossPairedSourceCoordinateForSharedBody(t *testing.T) {
	digest := strings.Repeat("a", 64)
	manifestDigest := strings.Repeat("b", 64)
	left := evidenceSourceCoordinate{Ref: "left", URL: "https://example.com/left"}
	right := evidenceSourceCoordinate{Ref: "right", URL: "https://example.com/right"}
	plan := &parsedPlan{
		Manifest: &artifactManifest{EvidenceManifestBindings: []evidenceManifestBinding{{EvidenceManifestSHA256: manifestDigest, EvidenceBodyKind: evidenceBodyKindSourceDocument}}},
		Locators: map[string]evidenceLocator{"cross-paired": {ID: "cross-paired", EvidenceManifestSHA256: manifestDigest, SourceContentSHA256: digest, SourceRefs: []string{left.Ref}, SourceURLs: []string{right.URL}}},
	}
	loaded := loadedEvidence{
		Bodies:             map[string]exactEvidenceBody{digest: {Bytes: []byte("body"), Coordinates: map[evidenceSourceCoordinate]string{left: manifestDigest, right: manifestDigest}}},
		Artifacts:          map[string]artifactInput{manifestDigest: {EvidenceBodyKind: evidenceBodyKindSourceDocument}},
		BodyCoordinateRows: 2,
	}
	err := validateEvidenceClosure(plan, loaded)
	if err == nil || !strings.Contains(err.Error(), "resolves no exact evidence coordinate") {
		t.Fatalf("got %v, want cross-paired source-coordinate refusal", err)
	}
}

func TestVerifyRejectsSourceCoordinateMutationWithoutIdentityChange(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	for _, raw := range fixture.planRows {
		locator, ok := raw.(*evidenceLocator)
		if !ok {
			continue
		}
		locator.SourceRefs = []string{"different-source"}
		break
	}
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "non-content-derived locator id") {
		t.Fatalf("got %v, want source-coordinate identity refusal", err)
	}
}

func TestCanonicalEvidenceSourceURLRejectsEveryQueryString(t *testing.T) {
	t.Parallel()
	for _, candidate := range []string{
		"https://example.com/reference?sig=opaque",
		"https://example.com/reference?code=opaque",
		"https://example.com/reference?X-Amz-Credential=opaque",
		"https://example.com/reference?public=true",
	} {
		if canonicalEvidenceSourceURL(candidate) {
			t.Fatalf("canonicalEvidenceSourceURL(%q) accepted a query-bearing evidence URL", candidate)
		}
	}
	if !canonicalEvidenceSourceURL("https://example.com/reference") {
		t.Fatal("canonicalEvidenceSourceURL rejected a canonical query-free HTTPS URL")
	}
}

func TestVerifyRejectsCallerOrganizationCoordinate(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	for _, raw := range fixture.planRows {
		gap, ok := raw.(*graphGap)
		if !ok {
			continue
		}
		gap.GapProofBinding = json.RawMessage(`{"organization_id":"caller-forged"}`)
		break
	}
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "organization scope key") {
		t.Fatalf("got %v, want caller-tenant refusal", err)
	}
}

func TestVerifyRejectsBinaryFloatShapedCandidateValue(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	for _, raw := range fixture.planRows {
		gap, ok := raw.(*graphGap)
		if !ok {
			continue
		}
		gap.GapProofBinding = json.RawMessage(`{"amount":1.25}`)
		break
	}
	writeJSONL(t, fixture.planPath, fixture.planRows)
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "binary-float-shaped JSON number") {
		t.Fatalf("got %v, want binary-float refusal", err)
	}
}

func TestRejectDuplicateJSONKeys(t *testing.T) {
	err := rejectDuplicateJSONKeys([]byte(`{"row_kind":"x","row_kind":"y"}`))
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("got %v, want duplicate-key refusal", err)
	}
}

func TestRejectInvalidJSONUnicodeScalars(t *testing.T) {
	for _, raw := range []string{`{"value":"\ud800"}`, `{"value":"\udc00"}`, `{"value":"\ud800x"}`} {
		if err := rejectDuplicateJSONKeys([]byte(raw)); err == nil || !strings.Contains(err.Error(), "unpaired") {
			t.Fatalf("got %v for %s, want unpaired-surrogate refusal", err, raw)
		}
	}
	if err := rejectDuplicateJSONKeys([]byte(`{"value":"\ud83d\ude80"}`)); err != nil {
		t.Fatalf("valid surrogate pair rejected: %v", err)
	}
}

func TestVerifyRejectsUnpairedEscapedSurrogatesAcrossJSONInputs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, *testFixture)
	}{
		{name: "plan", mutate: func(t *testing.T, fixture *testFixture) {
			replaceFileBytes(t, fixture.planPath, []byte(`"named_system":"Velenza BOC"`), []byte(`"named_system":"\ud800"`))
		}},
		{name: "evidence", mutate: func(t *testing.T, fixture *testFixture) {
			replaceFileBytes(t, fixture.evidencePath, []byte(`"source_ref":"fixture"`), []byte(`"source_ref":"\ud800"`))
		}},
		{name: "dependency", mutate: func(t *testing.T, fixture *testFixture) {
			path := fixture.dependencyByRole["profile"]
			replaceFileBytes(t, path, []byte(`"named_system":"Velenza BOC"`), []byte(`"named_system":"\ud800"`))
			fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, path)
			writeJSONL(t, fixture.planPath, fixture.planRows)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			test.mutate(t, fixture)
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), "unpaired high surrogate") {
				t.Fatalf("got %v, want escaped non-scalar refusal", err)
			}
		})
	}
}

func TestVerifyRejectsUnmodeledPlanFields(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	raw, err := os.ReadFile(fixture.planPath)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"source_bytes_present":false`), []byte(`"source_bytes_present":false,"source_body":"smuggled"`), 1)
	if err := os.WriteFile(fixture.planPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "embedded provider/document/source body payload is forbidden") {
		t.Fatalf("got %v, want unmodeled-field refusal", err)
	}
}

func TestVerifyRejectsSelectedEvidenceBodyReconstructedAcrossCandidateScalars(t *testing.T) {
	t.Parallel()
	body := bytes.Clone(testPrimaryEvidenceBody)
	encoded := base64.StdEncoding.EncodeToString(body)
	tests := []struct {
		name  string
		value interface{}
	}{
		{name: "decoded fragments", value: []interface{}{string(body[:1]), string(body[1:4]), string(body[4:])}},
		{name: "base64 fragments", value: []interface{}{encoded[:4], encoded[4:8], encoded[8:]}},
		{name: "individually encoded fragments", value: []interface{}{base64.StdEncoding.EncodeToString(body[:1]), base64.StdEncoding.EncodeToString(body[1:4]), base64.StdEncoding.EncodeToString(body[4:])}},
		{name: "object key fragments", value: map[string]interface{}{string(body[:1]): nil, string(body[1:]): nil}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			for _, candidate := range fixture.planRows {
				gap, ok := candidate.(*graphGap)
				if !ok {
					continue
				}
				gap.GapProofBinding = mustJSONRaw(t, map[string]interface{}{
					"fragment_carrier": test.value,
				})
				break
			}
			writeJSONL(t, fixture.planPath, fixture.planRows)
			resealFixturePlanSchemaForReviewedMutation(t, fixture)
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), "reconstructs") {
				t.Fatalf("got %v, want split selected-body reconstruction refusal", err)
			}
		})
	}
}

func TestVerifyRejectsCredentialMaterialInCandidateObjectKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		key  string
	}{
		{name: "jwt key", key: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
		{name: "provider token key", key: "sk-AbCdEfGhIjKlMnOp123456789"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			value, err := json.Marshal(map[string]interface{}{test.key: true})
			if err != nil {
				t.Fatal(err)
			}
			for _, candidate := range fixture.planRows {
				gap, ok := candidate.(*graphGap)
				if ok {
					gap.GapProofBinding = value
					break
				}
			}
			writeJSONL(t, fixture.planPath, fixture.planRows)
			resealFixturePlanSchemaForReviewedMutation(t, fixture)
			_, err = Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), "credential or secret material") {
				t.Fatalf("got %v, want credential-shaped candidate object-key refusal", err)
			}
		})
	}
}

func TestStructuredDependencySecurityRejectsCredentialMaterialInKeysAndVaultLikeSuffixes(t *testing.T) {
	tests := []struct {
		name string
		row  string
	}{
		{name: "jwt key", row: `{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c":true}`},
		{name: "provider token key", row: `{"sk-AbCdEfGhIjKlMnOp123456789":true}`},
		{name: "connector vault with token suffix", row: `{"access_token":"ConnectorVaultAbCdEfGhIjKlMnOp123456789"}`},
		{name: "redacted with token suffix", row: `{"access_token":"redactedAbCdEfGhIjKlMnOp123456789"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateStructuredDependencySecurity(artifactInput{Path: "dependency.jsonl", Raw: []byte(test.row + "\n")})
			if err == nil || !strings.Contains(err.Error(), "credential or secret material") {
				t.Fatalf("got %v, want dependency credential-material refusal", err)
			}
		})
	}
}

func TestVerifyRejectsOmittedSecurityPosture(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	raw, err := os.ReadFile(fixture.planPath)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`,"source_bytes_present":false`), nil, 1)
	if err := os.WriteFile(fixture.planPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "fails its bound schema") {
		t.Fatalf("got %v, want missing-posture refusal", err)
	}
}

func TestVerifyRejectsWrongPlanSummaryScalarTypes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		field string
		value interface{}
	}{
		{name: "integer", field: "candidate_api_symbol_count", value: "17"},
		{name: "boolean", field: "organization_id_present", value: "false"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			mutateJSONLRow(t, fixture.planPath, "validation_summary", func(row map[string]interface{}) {
				row[test.field] = test.value
			})
			_, err := Verify(fixture.options)
			if err == nil || !strings.Contains(err.Error(), "fails its bound schema") {
				t.Fatalf("got %v, want strict plan-summary %s refusal", err, test.name)
			}
		})
	}
}

func TestVerifyRejectsUnknownLegacyPlanManifestMember(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	mutateJSONLRow(t, fixture.planPath, "artifact_manifest", func(row map[string]interface{}) { row["tenant_rule"] = "caller_supplied" })
	_, err := Verify(fixture.options)
	if err == nil || !strings.Contains(err.Error(), "fails its bound schema") {
		t.Fatalf("got %v, want closed graph-plan schema refusal for legacy self-asserted metadata", err)
	}
}

func TestRawInputReadersSeparateStructuredUTF8FromByteNeutralEvidenceBodies(t *testing.T) {
	t.Parallel()
	t.Run("ood", func(t *testing.T) {
		fixture := newTestFixture(t)
		raw, err := os.ReadFile(fixture.oodPath)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, 0xff)
		if err := os.WriteFile(fixture.oodPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = Verify(fixture.options)
		if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
			t.Fatalf("got %v, want invalid OOD UTF-8 refusal", err)
		}
	})

	t.Run("plan", func(t *testing.T) {
		fixture := newTestFixture(t)
		raw, err := os.ReadFile(fixture.planPath)
		if err != nil {
			t.Fatal(err)
		}
		target := []byte("candidate_not_admissible_or_executable")
		if count := bytes.Count(raw, target); count != 1 {
			t.Fatalf("plan contains UTF-8 mutation target %q %d times, want 1", target, count)
		}
		raw = bytes.Replace(raw, target, append(append([]byte(nil), target...), 0xff), 1)
		if err := os.WriteFile(fixture.planPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = Verify(fixture.options)
		if err == nil || !strings.Contains(err.Error(), "UTF-8") {
			t.Fatalf("got %v, want invalid plan UTF-8 refusal", err)
		}
	})

	t.Run("evidence", func(t *testing.T) {
		fixture := newTestFixture(t)
		raw, err := os.ReadFile(fixture.evidencePath)
		if err != nil {
			t.Fatal(err)
		}
		target := []byte(`"artifact":"fixture_evidence_manifest"`)
		if count := bytes.Count(raw, target); count != 1 {
			t.Fatalf("evidence manifest contains UTF-8 mutation target %q %d times, want 1", target, count)
		}
		raw = bytes.Replace(raw, target, append([]byte(`"artifact":"fixture_evidence_manifest","note":"`), append([]byte{0xff}, '"')...), 1)
		if err := os.WriteFile(fixture.evidencePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = Verify(fixture.options)
		if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
			t.Fatalf("got %v, want invalid evidence UTF-8 refusal", err)
		}
	})

	t.Run("dependency", func(t *testing.T) {
		fixture := newTestFixture(t)
		profilePath := fixture.dependencyByRole["profile"]
		raw, err := os.ReadFile(profilePath)
		if err != nil {
			t.Fatal(err)
		}
		raw = bytes.Replace(raw, []byte(`"named_system":"Velenza BOC"`), append([]byte(`"named_system":"Velenza BOC","note":"`), append([]byte{0xff}, []byte(`"`)...)...), 1)
		if err := os.WriteFile(profilePath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.manifest().ProviderNeutralProfileSHA256 = fileSHA256(t, profilePath)
		writeJSONL(t, fixture.planPath, fixture.planRows)
		_, err = Verify(fixture.options)
		if err == nil || !strings.Contains(err.Error(), "UTF-8") {
			t.Fatalf("got %v, want invalid dependency UTF-8 refusal", err)
		}
	})

	t.Run("base64 carrier", func(t *testing.T) {
		fixture := newTestFixture(t)
		carrierPath := filepath.Join(filepath.Dir(fixture.evidencePath), "body.md.b64")
		raw, err := os.ReadFile(carrierPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(carrierPath, append(raw, 0xff), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = Verify(fixture.options)
		if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
			t.Fatalf("got %v, want invalid base64-carrier UTF-8 refusal", err)
		}
	})

	t.Run("decoded evidence body", func(t *testing.T) {
		fixture := newTestFixture(t)
		carrierPath := filepath.Join(filepath.Dir(fixture.evidencePath), "body.md.b64")
		body := []byte{0xff}
		if err := os.WriteFile(carrierPath, []byte(base64.StdEncoding.EncodeToString(body)), 0o600); err != nil {
			t.Fatal(err)
		}
		mutateJSONLRow(t, fixture.evidencePath, "external_evidence_body", func(row map[string]interface{}) {
			row["component_sha256"] = sha256Hex(body)
			row["component_byte_length"] = json.Number("1")
			row["content_sha256"] = sha256Hex(body)
			row["content_bytes"] = json.Number("1")
		})
		mutateJSONLRow(t, fixture.evidencePath, "validation_summary", func(row map[string]interface{}) {
			row["total_exact_source_bytes"] = json.Number("1")
		})
		loaded, err := loadEvidenceBodies([]string{fixture.evidencePath}, map[string]struct{}{supportedEvidenceRepresentationKind: {}})
		if err != nil {
			t.Fatalf("byte-neutral evidence body rejected before typed parsing: %v", err)
		}
		exact, ok := loaded.Bodies[sha256Hex(body)]
		if !ok || !bytes.Equal(exact.Bytes, body) {
			t.Fatalf("loaded evidence body = %x, want exact bytes %x", exact.Bytes, body)
		}
		coordinate := evidenceSourceCoordinate{Ref: "fixture", URL: "https://example.com/fixture"}
		manifestSHA := exact.Coordinates[coordinate]
		locator := evidenceLocator{EvidenceManifestSHA256: manifestSHA, SourceContentSHA256: sha256Hex(body), ByteStartOffset: 0, ByteEndOffsetExclusive: 1, SelectedRangeByteCount: 1, SelectedRangeSHA256: sha256Hex(body), SourceRefs: []string{coordinate.Ref}, SourceURLs: []string{coordinate.URL}, LocatorSemantics: exactLocatorSemantics}
		locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
		if err := validateLocator(locator, loaded.Bodies); err != nil {
			t.Fatalf("byte-neutral exact locator rejected: %v", err)
		}
		profile := sampleParseProfile{reference: dependencyProfileReference{id: "fixture_json_utf8_parse_profile", version: "1", digest: strings.Repeat("a", 64)}, decoderKind: sampleDecoderKindUTF8Strict, parserKind: sampleParserKindJSONRFC8259}
		outcome, failure, _ := executeSampleParseProfile(profile, body)
		if outcome != sampleParseOutcomeFailed || failure == nil || failure.class != "invalid_charset_sequence" || failure.stage != "decoder" {
			t.Fatalf("typed parse result = outcome %q failure %+v, want deterministic decoder failure", outcome, failure)
		}
	})
}

type testPrimaryEvidenceFixture struct {
	body                []byte
	derivationPattern   string
	providerDescription string
	provider            string
	sourceRef           string
	sourceURL           string
	representation      string
	representationCoord string
	artifactPrefix      string
	sourceSymbolPrefix  string
	operationName       string
	readOperationSource string
	sectionRoot         string
	protocolBody        []byte
	protocolLiteralA    string
	protocolLiteralB    string
	singleDocument      bool
	additionalRanges    []officialProviderEvidenceRange
	derivationBuilder   testDocumentationDerivationBuilder
}

type testDocumentationDerivationBuilder func(*testing.T, sourceClassificationSelectionProof, map[string]exactEvidenceBody) *testDocumentationDerivationBundle

type testDocumentationDerivationBundle struct {
	profileRows      dependencySemanticRows
	profiles         map[string]executableDocumentationDerivationProfile
	facts            []exactDocumentationDerivedFact
	targetAuthority  dependencySemanticDerivationTargetSchemaAuthority
	targetArtifacts  map[string]artifactInput
	targetRows       map[string]dependencySemanticRows
	accessFact       exactDocumentationDerivedFact
	fieldFact        exactDocumentationDerivedFact
	numeric          exactValueClassifierOutput
	applicability    string
	ruleCount        int64
	outcomeCount     int64
	factCount        int64
	wholeRowCount    int64
	pageSetRoot      string
	resultSetRoot    string
	targetRoot       string
	targetRosterRoot string
	closureProofRoot string
	closure          documentationDerivationClosureProof
}

type officialProviderEvidenceRange struct {
	Name                   string
	SourceSymbol           string
	SurfaceKind            string
	ByteStartOffset        int64
	ByteEndOffsetExclusive int64
	SelectedRangeSHA256    string
}

func defaultTestPrimaryEvidenceFixture() testPrimaryEvidenceFixture {
	return testPrimaryEvidenceFixture{
		body:                testPrimaryEvidenceBody,
		derivationPattern:   `"12\.34"\t{128}`,
		providerDescription: "Exact amount 12.34.",
		provider:            "fixture_provider",
		sourceRef:           "fixture",
		sourceURL:           "https://example.com/fixture",
		representation:      "source_declared_copy_all_for_ai_markdown",
		representationCoord: "button[aria-label=Copy all for AI]",
		artifactPrefix:      "fixture",
		sourceSymbolPrefix:  "fixture",
		operationName:       "read_records",
		sectionRoot:         "Fixture",
		protocolBody:        testProtocolEvidenceBody,
		protocolLiteralA:    "protocol",
		protocolLiteralB:    "evidence",
	}
}

func newTestFixture(t *testing.T) *testFixture {
	t.Helper()
	return newTestFixtureWithPrimaryEvidence(t, defaultTestPrimaryEvidenceFixture())
}

func newTestFixtureWithPrimaryEvidence(t *testing.T, primary testPrimaryEvidenceFixture) *testFixture {
	t.Helper()
	if len(primary.body) == 0 || primary.derivationPattern == "" || primary.providerDescription == "" || primary.provider == "" || primary.sourceRef == "" || primary.sourceURL == "" || primary.representation == "" || primary.representationCoord == "" || primary.artifactPrefix == "" || primary.sourceSymbolPrefix == "" || primary.operationName == "" || primary.sectionRoot == "" || (!primary.singleDocument && len(primary.protocolBody) == 0) || primary.protocolLiteralA == "" || primary.protocolLiteralB == "" {
		t.Fatal("test primary evidence fixture is incomplete")
	}
	dir := t.TempDir()
	body := bytes.Clone(primary.body)
	bodyDigest := sha256Hex(body)
	bodyLineDelimiterProfile := exactLineDelimiterProfile(body)
	provider := primary.provider
	sourceRef := primary.sourceRef
	sourceURL := primary.sourceURL
	representation := primary.representation
	representationCoordinate := primary.representationCoord
	artifactPrefix := primary.artifactPrefix
	protocolSourceRef := sourceRef + ".protocol-contract"
	protocolSourceURL := strings.TrimSuffix(sourceURL, "/") + "/protocol-contract"
	primaryEvidenceArtifact := artifactPrefix + "_evidence_manifest"
	protocolEvidenceArtifact := artifactPrefix + "_protocol_evidence_manifest"
	classificationArtifact := artifactPrefix + "_source_classification_roster"
	roles := []string{
		"vendor_api", "operation", "resource", "auth_scheme", "webhook_event", "schema_element", "error_shape", "rate_limit_rule",
		"pagination_shape", "request_response_envelope_shape", "lifecycle_shape", "concurrency_and_idempotency_shape",
		"polling_cdc_and_reconciliation_shape", "exact_value_shape", "reference_and_discriminated_union_shape", "batch_and_partial_success_shape",
	}
	constraints := []relationshipConstraint{
		{EdgeLabel: "api_has_operation", SourceRole: "vendor_api", TargetRole: "operation"},
		{EdgeLabel: "operation_reads_resource", SourceRole: "operation", TargetRole: "resource"},
		{EdgeLabel: "operation_writes_resource", SourceRole: "operation", TargetRole: "resource"},
		{EdgeLabel: "operation_requires_auth_scheme", SourceRole: "operation", TargetRole: "auth_scheme"},
		{EdgeLabel: "operation_emits_webhook_event", SourceRole: "operation", TargetRole: "webhook_event"},
		{EdgeLabel: "operation_uses_schema", SourceRole: "operation", TargetRole: "schema_element"},
		{EdgeLabel: "operation_returns_error_shape", SourceRole: "operation", TargetRole: "error_shape"},
		{EdgeLabel: "operation_has_rate_limit_rule", SourceRole: "operation", TargetRole: "rate_limit_rule"},
		{EdgeLabel: "operation_uses_pagination_shape", SourceRole: "operation", TargetRole: "pagination_shape"},
		{EdgeLabel: "operation_uses_request_response_envelope_shape", SourceRole: "operation", TargetRole: "request_response_envelope_shape"},
		{EdgeLabel: "resource_uses_lifecycle_shape", SourceRole: "resource", TargetRole: "lifecycle_shape"},
		{EdgeLabel: "operation_uses_concurrency_and_idempotency_shape", SourceRole: "operation", TargetRole: "concurrency_and_idempotency_shape"},
		{EdgeLabel: "resource_has_polling_cdc_and_reconciliation_shape", SourceRole: "resource", TargetRole: "polling_cdc_and_reconciliation_shape"},
		{EdgeLabel: "schema_uses_exact_numeric_identifier_timestamp_currency_and_string_encoded_numeric_shape", SourceRole: "schema_element", TargetRole: "exact_value_shape"},
		{EdgeLabel: "schema_uses_reference_and_discriminated_union_shape", SourceRole: "schema_element", TargetRole: "reference_and_discriminated_union_shape"},
		{EdgeLabel: "operation_uses_batch_and_partial_success_shape", SourceRole: "operation", TargetRole: "batch_and_partial_success_shape"},
	}
	families := []string{"http_method", "uri_template", "parameter_location_requiredness_and_cardinality", "request_media", "response_media", "error_contract", "pagination_contract", "exact_numeric_identifier_timestamp_currency_and_string_encoded_numeric_lexical_contract"}
	roleCardinalityRule := "fixture api_symbol requires exactly one authoritative role and exact locator manifest"
	roleAuthorityRule := "fixture OODGraphObjects role binding plus exact locator manifest is immutable authority"
	propertySchemaGovernanceRule := "fixture property claims require an admitted exact schema binding"
	propertyEvidenceRule := "fixture property claims require exact digest-bound byte-range evidence"
	propertyAuthorityExclusions := []string{"search_payload", "projection_payload", "embedding", "DOM", "accessibility tree", "static operation metadata", "navigation metadata", "AI summary"}
	capabilities := []string{"docgraph.source.authorize", "docgraph.external.fetch", "docgraph.evidence.archive", "docgraph.fetch.batch.seal", "docgraph.reference.normalize", "docgraph.reference.chunk", "docgraph.reference.symbolize", "docgraph.relationship.plan", "docgraph.plan.validate", "docgraph.snapshot.materialize", "docgraph.snapshot.verify"}
	externalObjectClasses := []string{"external_reference_doc", "reference_page", "api_symbol", "code_example", "release_note", "source_repo", "repo_snapshot", "code_symbol_ref"}
	externalEdgeLabels := []string{"documents", "official_source_for", "defines_external_symbol", "example_of", "version_note_for", "supports_spec_section", "implemented_by_code_symbol", "technology_relevant_to"}
	allowedSourceClasses := []string{"official_vendor_documentation", "official_product_documentation", "official_source_repository", "official_release_notes", "context7_documentation_package", "velenza_owned_documentation"}
	forbiddenSourceClasses := []string{"unofficial_blog", "forum_answer", "scraped_search_result", "AI_summary_without_primary_source", "mirrored_docs_without_admitted_affirmative_authority_and_permission"}
	sourceAuthorityRule := "fixture source authority requires exact typed binding and fails closed"

	ood := map[string]interface{}{"doc_id": "fixture-ood", "version": 1, "status": "locked", "sections": map[string]interface{}{
		"s2_graph_object_model": map[string]interface{}{
			"api_symbol_role_registry": map[string]interface{}{"roles": roles, "cardinality_rule": roleCardinalityRule, "authority_rule": roleAuthorityRule},
			"api_property_claim_model": map[string]interface{}{
				"eligible_subjects":      []string{"api_symbol_object", "api_relationship_edge"},
				"property_families":      families,
				"schema_governance_rule": propertySchemaGovernanceRule,
				"evidence_rule":          propertyEvidenceRule,
				"authority_exclusions":   propertyAuthorityExclusions,
			},
			"external_relationship_authority_boundary": map[string]interface{}{"materialization_rule": "fixture absent explicit required rule means optional"},
		},
		"s4_edge_model": map[string]interface{}{"api_relationship_contract": map[string]interface{}{"family": "api_relationship", "source_class": "api_symbol", "target_class": "api_symbol", "provider_specific_labels_allowed": false, "free_form_subtype_allowed": false, "references_or_depends_on_substitution_allowed": false, "labels_and_role_constraints": constraints}},
		"s6_spanner_storage_model": map[string]interface{}{"table_surfaces": map[string]interface{}{
			"fixture_rows": map[string]interface{}{
				"physical_table_name": "FixtureRows",
				"purpose":             "organization-scoped fixture surface",
				"primary_key":         []string{"organization_id", "fixture_id"},
				"columns":             map[string]interface{}{"organization_id": "STRING", "fixture_id": "STRING"},
			},
		}},
		"s3_symbol_identity_and_addressing": map[string]interface{}{
			"external_canonical_representation_contract": map[string]interface{}{"representation_kind_values": []string{"source_declared_machine_export", "source_origin_representation", "source_declared_component_manifest"}},
			"version_coordinate_grammar": map[string]interface{}{
				"external_evidence_hash_contract": map[string]interface{}{
					"canonical_byte_profiles": map[string]interface{}{
						componentByteDomainProfile:    map[string]interface{}{},
						manifestCanonicalBytesProfile: map[string]interface{}{},
					},
				},
			},
		},
		"s8_graph_materialization_and_ingestion": map[string]interface{}{"external_reference_ingestion_contract": map[string]interface{}{
			"source_authority_policy":             map[string]interface{}{"allowed_source_classes": allowedSourceClasses, "forbidden_source_classes": forbiddenSourceClasses, "rule": sourceAuthorityRule},
			"canonical_ingestion_execution_model": map[string]interface{}{"capability_sequence": capabilities, "entry_capability": capabilities[0]},
			"object_classes_created":              externalObjectClasses,
			"edge_labels_created":                 externalEdgeLabels,
		}},
	}}
	oodRaw, err := json.Marshal(ood)
	if err != nil {
		t.Fatal(err)
	}
	oodPath := filepath.Join(dir, "OOD_GRAPH_PROTOCOL_v1.ood.json")
	if err := os.WriteFile(oodPath, oodRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	bodyPath := filepath.Join(dir, "body.md.b64")
	if err := os.WriteFile(bodyPath, []byte(base64.StdEncoding.EncodeToString(body)), 0o600); err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(dir, "evidence.jsonl")
	writeJSONL(t, evidencePath, []interface{}{
		map[string]interface{}{"row_kind": "artifact_manifest", "artifact": primaryEvidenceArtifact, "artifact_version": "2", "status": "candidate_not_admissible", "provider": provider, "representation": representation, "representation_coordinate": representationCoordinate, "source_representation_kind": supportedEvidenceRepresentationKind, "canonical_bytes": manifestCanonicalBytesProfile},
		map[string]interface{}{"row_kind": "external_evidence_body", "component_ordinal": 0, "component_stable_coordinate": "source_ref_url_pair_v1|" + lengthPrefixedIdentityKey(sourceRef, sourceURL), "component_byte_length": len(body), "component_sha256": bodyDigest, "component_byte_domain_profile": componentByteDomainProfile, "source_ref": sourceRef, "source_url": sourceURL, "representation": representation, "representation_coordinate": representationCoordinate, "source_representation_kind": supportedEvidenceRepresentationKind, "content_sha256": bodyDigest, "content_bytes": len(body), "source_content_hash_profile": sourceContentHashProfile, "observed_line_delimiter_profile": bodyLineDelimiterProfile, "staging_file": filepath.Base(bodyPath), "body_authority": evidenceBodyAuthorityExact},
		map[string]interface{}{"row_kind": "validation_summary", "selected_source_count": 1, "captured_source_count": 1, "total_exact_source_bytes": len(body), "missing_source_refs": []string{}, "unexpected_source_refs": []string{}, "selected_representation_is_only_evidence_body": true, "rendered_dom_body_accepted": false, "result": "structural_candidate_selected_source_document_capture"},
	})
	evidenceManifestDigest := fileSHA256(t, evidencePath)
	protocolBody := bytes.Clone(primary.protocolBody)
	if primary.singleDocument {
		protocolBody = body
		protocolSourceRef = sourceRef
		protocolSourceURL = sourceURL
		protocolEvidenceArtifact = primaryEvidenceArtifact
	}
	protocolBodyDigest := sha256Hex(protocolBody)
	protocolLineDelimiterProfile := exactLineDelimiterProfile(protocolBody)
	protocolEvidencePath := ""
	protocolEvidenceManifestDigest := evidenceManifestDigest
	if !primary.singleDocument {
		protocolBodyPath := filepath.Join(dir, "protocol-body.md.b64")
		if err := os.WriteFile(protocolBodyPath, []byte(base64.StdEncoding.EncodeToString(protocolBody)), 0o600); err != nil {
			t.Fatal(err)
		}
		protocolEvidencePath = filepath.Join(dir, "protocol-evidence.jsonl")
		writeJSONL(t, protocolEvidencePath, []interface{}{
			map[string]interface{}{"row_kind": "artifact_manifest", "artifact": protocolEvidenceArtifact, "artifact_version": "1", "status": "candidate_not_admissible", "provider": provider, "representation": representation, "representation_coordinate": representationCoordinate, "source_representation_kind": supportedEvidenceRepresentationKind, "canonical_bytes": manifestCanonicalBytesProfile},
			map[string]interface{}{"row_kind": "external_evidence_body", "component_ordinal": 0, "component_stable_coordinate": "source_ref_url_pair_v1|" + lengthPrefixedIdentityKey(protocolSourceRef, protocolSourceURL), "component_byte_length": len(protocolBody), "component_sha256": protocolBodyDigest, "component_byte_domain_profile": componentByteDomainProfile, "source_ref": protocolSourceRef, "source_url": protocolSourceURL, "representation": representation, "representation_coordinate": representationCoordinate, "source_representation_kind": supportedEvidenceRepresentationKind, "content_sha256": protocolBodyDigest, "content_bytes": len(protocolBody), "source_content_hash_profile": sourceContentHashProfile, "observed_line_delimiter_profile": protocolLineDelimiterProfile, "staging_file": filepath.Base(protocolBodyPath), "body_authority": evidenceBodyAuthorityExact},
			map[string]interface{}{"row_kind": "validation_summary", "selected_source_count": 1, "captured_source_count": 1, "total_exact_source_bytes": len(protocolBody), "missing_source_refs": []string{}, "unexpected_source_refs": []string{}, "selected_representation_is_only_evidence_body": true, "rendered_dom_body_accepted": false, "result": "structural_candidate_selected_source_document_capture"},
		})
		protocolEvidenceManifestDigest = fileSHA256(t, protocolEvidencePath)
	}

	sourceSymbolByRole := make(map[string]string, len(roles))
	classificationManifest := map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": classificationArtifact, "artifact_version": "2", "status": "candidate_source_selection_input", "provider": provider, "authority_posture": "semantic_source_element_identity_only_not_documentation_evidence",
	}
	classificationRows := []interface{}{classificationManifest}
	declaredClassificationSurfaces := map[string]string{}
	for _, role := range roles {
		sourceSymbol := primary.sourceSymbolPrefix + "_" + role
		if role == "operation" {
			sourceSymbol = primary.sourceSymbolPrefix + "_write_operation"
		}
		sourceSymbolByRole[role] = sourceSymbol
		declaredClassificationSurfaces[sourceSymbol] = role
		classificationRows = append(classificationRows, map[string]interface{}{"row_kind": "source_symbol", "source_symbol": sourceSymbol, "surface_kind": role})
	}
	sourceReadOperationSymbol := primary.readOperationSource
	if sourceReadOperationSymbol == "" {
		sourceReadOperationSymbol = primary.sourceSymbolPrefix + "_read_operation"
	}
	declaredClassificationSurfaces[sourceReadOperationSymbol] = "operation"
	classificationRows = append(classificationRows, map[string]interface{}{"row_kind": "source_symbol", "source_symbol": sourceReadOperationSymbol, "surface_kind": "operation"})
	for _, selected := range primary.additionalRanges {
		if prior, exists := declaredClassificationSurfaces[selected.SourceSymbol]; exists {
			if prior != selected.SurfaceKind {
				t.Fatalf("additional source symbol %q has conflicting surfaces %q and %q", selected.SourceSymbol, prior, selected.SurfaceKind)
			}
			continue
		}
		declaredClassificationSurfaces[selected.SourceSymbol] = selected.SurfaceKind
		classificationRows = append(classificationRows, map[string]interface{}{"row_kind": "source_symbol", "source_symbol": selected.SourceSymbol, "surface_kind": selected.SurfaceKind})
	}
	classificationManifest["source_symbol_count"] = len(classificationRows) - 1
	classificationRosterPath := filepath.Join(dir, "source-classification-roster.jsonl")
	writeJSONL(t, classificationRosterPath, classificationRows)
	classificationRosterDigest := fileSHA256(t, classificationRosterPath)
	classificationLocator := evidenceLocator{RowKind: "candidate_evidence_locator", EvidenceManifestSHA256: evidenceManifestDigest, SourceContentSHA256: bodyDigest, ByteStartOffset: 0, ByteEndOffsetExclusive: int64(len(body)), SelectedRangeByteCount: int64(len(body)), SelectedRangeSHA256: bodyDigest, SourceRefs: []string{sourceRef}, SourceURLs: []string{sourceURL}, LocatorSemantics: exactLocatorSemantics}
	classificationLocator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(classificationLocator))
	protocolEvidenceLocator := evidenceLocator{RowKind: "candidate_evidence_locator", EvidenceManifestSHA256: protocolEvidenceManifestDigest, SourceContentSHA256: protocolBodyDigest, ByteStartOffset: 0, ByteEndOffsetExclusive: int64(len(protocolBody)), SelectedRangeByteCount: int64(len(protocolBody)), SelectedRangeSHA256: protocolBodyDigest, SourceRefs: []string{protocolSourceRef}, SourceURLs: []string{protocolSourceURL}, LocatorSemantics: exactLocatorSemantics}
	protocolEvidenceLocator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(protocolEvidenceLocator))
	classificationBinding := classificationArtifactBinding{ArtifactID: classificationArtifact, ArtifactVersion: "2", ArtifactSHA256: classificationRosterDigest}
	classificationOccurrences := make(map[string][]sourceClassificationOccurrence, len(roles)+1)
	entityOccurrences := make([]interface{}, 0, len(roles)+1)
	protocolOccurrences := make([]interface{}, 0, 2)
	for _, role := range roles {
		sourceSymbol := sourceSymbolByRole[role]
		entityOccurrence := sourceClassificationOccurrence{Binding: classificationBinding, SourceSymbol: sourceSymbol, SurfaceKind: role, Locator: classificationLocator}
		classificationOccurrences[sourceSymbol] = append(classificationOccurrences[sourceSymbol], entityOccurrence)
		entityOccurrences = append(entityOccurrences, fixtureClassificationOccurrenceObject(t, entityOccurrence))
		if !primary.singleDocument && (role == "vendor_api" || role == "operation") {
			protocolOccurrence := sourceClassificationOccurrence{Binding: classificationBinding, SourceSymbol: sourceSymbol, SurfaceKind: role, Locator: protocolEvidenceLocator}
			classificationOccurrences[sourceSymbol] = append(classificationOccurrences[sourceSymbol], protocolOccurrence)
			protocolOccurrences = append(protocolOccurrences, fixtureClassificationOccurrenceObject(t, protocolOccurrence))
		}
	}
	hasExactReadOperationRange := false
	for _, selected := range primary.additionalRanges {
		if selected.SourceSymbol == sourceReadOperationSymbol {
			hasExactReadOperationRange = true
			break
		}
	}
	if !hasExactReadOperationRange {
		readOperationOccurrence := sourceClassificationOccurrence{Binding: classificationBinding, SourceSymbol: sourceReadOperationSymbol, SurfaceKind: "operation", Locator: classificationLocator}
		classificationOccurrences[sourceReadOperationSymbol] = []sourceClassificationOccurrence{readOperationOccurrence}
		entityOccurrences = append(entityOccurrences, fixtureClassificationOccurrenceObject(t, readOperationOccurrence))
	}
	for _, selected := range primary.additionalRanges {
		if selected.ByteStartOffset < 0 || selected.ByteEndOffsetExclusive <= selected.ByteStartOffset || selected.ByteEndOffsetExclusive > int64(len(body)) {
			t.Fatalf("additional source range %q is outside the exact primary body", selected.Name)
		}
		exact := body[selected.ByteStartOffset:selected.ByteEndOffsetExclusive]
		if sha256Hex(exact) != selected.SelectedRangeSHA256 {
			t.Fatalf("additional source range %q differs from its exact SHA-256 pin", selected.Name)
		}
		locator := evidenceLocator{
			RowKind: "candidate_evidence_locator", EvidenceManifestSHA256: evidenceManifestDigest, SourceContentSHA256: bodyDigest,
			ByteStartOffset: selected.ByteStartOffset, ByteEndOffsetExclusive: selected.ByteEndOffsetExclusive,
			SelectedRangeByteCount: selected.ByteEndOffsetExclusive - selected.ByteStartOffset, SelectedRangeSHA256: selected.SelectedRangeSHA256,
			SourceRefs: []string{sourceRef}, SourceURLs: []string{sourceURL}, LocatorSemantics: exactLocatorSemantics,
		}
		locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
		occurrence := sourceClassificationOccurrence{Binding: classificationBinding, SourceSymbol: selected.SourceSymbol, SurfaceKind: selected.SurfaceKind, Locator: locator}
		classificationOccurrences[selected.SourceSymbol] = append(classificationOccurrences[selected.SourceSymbol], occurrence)
		entityOccurrences = append(entityOccurrences, fixtureClassificationOccurrenceObject(t, occurrence))
	}
	for _, occurrences := range [][]interface{}{entityOccurrences, protocolOccurrences} {
		sort.Slice(occurrences, func(i, j int) bool {
			left := occurrences[i].(map[string]interface{})
			right := occurrences[j].(map[string]interface{})
			leftLocator, _ := manifestClassificationEvidenceLocator(left, "evidence_locator")
			rightLocator, _ := manifestClassificationEvidenceLocator(right, "evidence_locator")
			leftKey := fmt.Sprint(left["source_symbol"], "\x00", left["surface_kind"], "\x00", leftLocator.EvidenceManifestSHA256, "\x00", leftLocator.SourceRefs[0], "\x00", leftLocator.SourceURLs[0], "\x00", leftLocator.SourceContentSHA256, "\x00", fmt.Sprintf("%020d", leftLocator.ByteStartOffset), "\x00", fmt.Sprintf("%020d", leftLocator.ByteEndOffsetExclusive), "\x00", leftLocator.SelectedRangeSHA256, "\x00", classificationRosterDigest)
			rightKey := fmt.Sprint(right["source_symbol"], "\x00", right["surface_kind"], "\x00", rightLocator.EvidenceManifestSHA256, "\x00", rightLocator.SourceRefs[0], "\x00", rightLocator.SourceURLs[0], "\x00", rightLocator.SourceContentSHA256, "\x00", fmt.Sprintf("%020d", rightLocator.ByteStartOffset), "\x00", fmt.Sprintf("%020d", rightLocator.ByteEndOffsetExclusive), "\x00", rightLocator.SelectedRangeSHA256, "\x00", classificationRosterDigest)
			return leftKey < rightKey
		})
	}
	selectionRosterPath := filepath.Join(dir, "evidence-selection-roster.jsonl")
	selectionManifest := map[string]interface{}{"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_documentation_evidence_selection_roster", "artifact_version": "4", "status": "candidate_source_selection_input", "provider": provider, "selected_source_count": 2, "classification_artifact_bindings": []interface{}{map[string]interface{}{"artifact_id": classificationArtifact, "artifact_version": "2", "artifact_sha256": classificationRosterDigest}}}
	primarySelectionRow := map[string]interface{}{"row_kind": "selected_source_document", "evidence_manifest_artifact": primaryEvidenceArtifact, "evidence_manifest_artifact_version": "2", "source_ref": sourceRef, "current_reference_url": sourceURL, "representation": representation, "representation_coordinate": representationCoordinate, "source_representation_kind": supportedEvidenceRepresentationKind, "consumer_roles": []string{"api_graph_projection", "field_mapping_candidate", "sample_shape_index", "source_contract_index", "surface_family_disposition"}, "classification_occurrences": entityOccurrences}
	selectionRows := []interface{}{selectionManifest, primarySelectionRow}
	if primary.singleDocument {
		selectionManifest["selected_source_count"] = 1
		primarySelectionRow["consumer_roles"] = []string{"api_graph_projection", "field_mapping_candidate", "protocol_contract_index", "sample_shape_index", "source_contract_index", "surface_family_disposition"}
		selectionRows = append(selectionRows, map[string]interface{}{"row_kind": "validation_summary", "selected_source_count": 1, "evidence_manifest_artifact_count": 1, "classified_source_document_count": 1, "classification_occurrence_count": len(entityOccurrences), "captured_consumer_role_counts": map[string]interface{}{"api_graph_projection": 1, "field_mapping_candidate": 1, "protocol_contract_index": 1, "sample_shape_index": 1, "source_contract_index": 1, "surface_family_disposition": 1}, "result": "structural_candidate_source_selection_roster"})
	} else {
		selectionRows = append(selectionRows,
			map[string]interface{}{"row_kind": "selected_source_document", "evidence_manifest_artifact": protocolEvidenceArtifact, "evidence_manifest_artifact_version": "1", "source_ref": protocolSourceRef, "current_reference_url": protocolSourceURL, "representation": representation, "representation_coordinate": representationCoordinate, "source_representation_kind": supportedEvidenceRepresentationKind, "consumer_roles": []string{"api_graph_projection", "protocol_contract_index"}, "classification_occurrences": protocolOccurrences},
			map[string]interface{}{"row_kind": "validation_summary", "selected_source_count": 2, "evidence_manifest_artifact_count": 2, "classified_source_document_count": 2, "classification_occurrence_count": len(entityOccurrences) + len(protocolOccurrences), "captured_consumer_role_counts": map[string]interface{}{"api_graph_projection": 2, "field_mapping_candidate": 1, "protocol_contract_index": 1, "sample_shape_index": 1, "source_contract_index": 1, "surface_family_disposition": 1}, "result": "structural_candidate_source_selection_roster"},
		)
	}
	writeJSONL(t, selectionRosterPath, selectionRows)
	selectionRosterDigest := fileSHA256(t, selectionRosterPath)
	claimKind := "source_neutral_projection_claim"
	claimSchemaID := "urn:fixture:documentation:claim-schema"
	derivationProfileID := "fixture_documentation_derivation_profile"
	const (
		classifierProfileID    = "fixture_exact_value_classifier_profile"
		resolutionProfileID    = "fixture_exact_computation_resolution_profile"
		semanticProfileVersion = "1"
	)
	fieldFactOutput := map[string]interface{}{
		"cardinality":           "scalar",
		"field_display":         "Amount",
		"field_name":            "Amount",
		"line_number":           1,
		"numeric_disposition":   map[string]interface{}{"numeric_semantics": "exact_decimal", "authoritative_carrier": "source_lexeme", "binary_float_authoritative": false, "computation_path": "unresolved_fail_closed_gap"},
		"official_json_pointer": "/entities/" + primary.sourceSymbolPrefix,
		"provider_description":  primary.providerDescription,
		"provider_requirement":  "Required",
		"provider_type":         "Decimal",
		"section_path":          []string{primary.sectionRoot, "Fields"},
		"source_neutral_target": "candidate",
		"source_symbol":         sourceSymbolByRole["resource"],
		"surface_kind":          "resource",
	}
	accessFactOutput := map[string]interface{}{
		"relationship_label": "operation_reads_resource",
		"source_symbol":      sourceSymbolByRole["resource"],
	}
	derivationInputSourceSymbols := []string{sourceReadOperationSymbol, sourceSymbolByRole["resource"]}
	sort.Strings(derivationInputSourceSymbols)
	derivationProgramObject := map[string]interface{}{
		"program_kind":                           exactDocumentationDerivationProgramKind,
		"input_encoding":                         exactDocumentationDerivationEncodingUTF8,
		"max_parse_bytes":                        65536,
		"max_output_bytes_per_fact":              8192,
		"max_output_facts_per_page":              16,
		"max_output_bytes_per_page":              65536,
		"max_output_facts_per_run":               1024,
		"max_output_bytes_per_run":               1048576,
		"max_output_pages_per_run":               128,
		"max_matcher_evaluations_per_input_unit": 4096,
		"max_matcher_evaluations_per_run":        65536,
		"max_matcher_input_bytes_per_input_unit": 67108864,
		"max_matcher_input_bytes_per_run":        1073741824,
		"max_occurrence_outcomes_per_run":        1024,
		"max_canonical_outcome_bytes_per_run":    1048576,
		"input_source_symbols":                   derivationInputSourceSymbols,
		"ordered_rules": []interface{}{
			map[string]interface{}{
				"ordinal": 0, "rule_id": "extract_operation_resource_access", "input_source_symbol": sourceReadOperationSymbol,
				"target_artifact_role": dependencySemanticRoleSourceContract, "target_row_kind": "api_operation",
				"target_binding_kind": exactDocumentationTargetRowMember, "target_member_json_pointer": "/resource_accesses",
				"target_row_selector":                  []interface{}{map[string]interface{}{"target_row_json_pointer": "/source_symbol", "expected_string_template": sourceReadOperationSymbol}},
				"target_member_identity_json_pointers": []interface{}{"/source_symbol"},
				"pattern":                              primary.derivationPattern, "maximum_match_bytes": 65536, "minimum_matches_per_occurrence": 1, "maximum_matches_per_occurrence": 1,
				"output_fields": accessFactOutput, "exact_output_field_names": sortedSetKeys(stringMapKeysAsSet(accessFactOutput)),
			},
			map[string]interface{}{
				"ordinal": 1, "rule_id": "extract_source_field_contract", "input_source_symbol": sourceSymbolByRole["resource"],
				"target_artifact_role": dependencySemanticRoleSourceContract, "target_row_kind": "field_contract",
				"target_binding_kind": exactDocumentationTargetWholeRow, "target_member_json_pointer": "",
				"target_row_selector": []interface{}{}, "target_member_identity_json_pointers": []interface{}{},
				"pattern": primary.derivationPattern, "maximum_match_bytes": 65536, "minimum_matches_per_occurrence": 1, "maximum_matches_per_occurrence": 1,
				"output_fields": fieldFactOutput, "exact_output_field_names": sortedSetKeys(stringMapKeysAsSet(fieldFactOutput)),
			},
		},
	}
	derivationProgramRaw, err := json.Marshal(derivationProgramObject)
	if err != nil {
		t.Fatal(err)
	}
	derivationProgramCanonical, err := canonicalizeCandidateJSON(derivationProgramRaw)
	if err != nil {
		t.Fatal(err)
	}
	derivationProfileDigest := sha256Hex(derivationProgramCanonical)
	derivationReference := dependencyProfileReference{id: derivationProfileID, version: semanticProfileVersion, digest: derivationProfileDigest}
	derivationProgram, err := parseExactDocumentationDerivationProgram(derivationProgramCanonical, derivationReference)
	if err != nil {
		t.Fatalf("parse fixture exact documentation derivation program: %v", err)
	}
	derivationProof := newSourceClassificationSelectionProof(provider, selectionRosterDigest, classificationOccurrences)
	derivationBodies := map[string]exactEvidenceBody{
		bodyDigest: {
			Bytes: body,
			Coordinates: map[evidenceSourceCoordinate]string{
				{Ref: sourceRef, URL: sourceURL}: evidenceManifestDigest,
			},
		},
	}
	var derivationFacts []exactDocumentationDerivedFact
	var sourceAccessFact, sourceFieldFact exactDocumentationDerivedFact
	var derivationBundle *testDocumentationDerivationBundle
	var officialValidationReference dependencyProfileReference
	var officialClaimSchemaJSON string
	if primary.derivationBuilder != nil {
		derivationBundle = primary.derivationBuilder(t, derivationProof, derivationBodies)
		if derivationBundle == nil || len(derivationBundle.facts) == 0 || derivationBundle.accessFact.FactID == "" || derivationBundle.fieldFact.FactID == "" || len(derivationBundle.targetArtifacts) == 0 || derivationBundle.targetAuthority.seal != dependencySemanticDerivationTargetSchemaAuthorityIdentity {
			t.Fatal("complete documentation derivation fixture is incomplete")
		}
		derivationFacts = append([]exactDocumentationDerivedFact(nil), derivationBundle.facts...)
		sourceAccessFact = derivationBundle.accessFact
		sourceFieldFact = derivationBundle.fieldFact
		if sourceAccessFact.InputSourceSymbol != sourceReadOperationSymbol {
			t.Fatalf("complete documentation access fact source symbol = %q, want exact graph source symbol %q", sourceAccessFact.InputSourceSymbol, sourceReadOperationSymbol)
		}
	} else {
		derivationFacts, err = executeExactDocumentationDerivationProgram(derivationReference, derivationProgram, derivationProof, derivationBodies)
		if err != nil {
			t.Fatalf("execute fixture exact documentation derivation program: %v", err)
		}
		for _, fact := range derivationFacts {
			switch {
			case fact.TargetArtifactRole == dependencySemanticRoleSourceContract && fact.TargetRowKind == "api_operation" && fact.TargetBindingKind == exactDocumentationTargetRowMember && fact.TargetMemberJSONPointer == "/resource_accesses":
				sourceAccessFact = fact
			case fact.TargetArtifactRole == dependencySemanticRoleSourceContract && fact.TargetRowKind == "field_contract" && fact.TargetBindingKind == exactDocumentationTargetWholeRow:
				sourceFieldFact = fact
			default:
				t.Fatalf("fixture documentation derivation emitted unexpected target fact %+v", fact)
			}
		}
		if len(derivationFacts) != 2 || sourceAccessFact.FactID == "" || sourceFieldFact.FactID == "" {
			t.Fatalf("fixture documentation derivation emitted %d facts with access=%q field=%q, want one exact fact per target", len(derivationFacts), sourceAccessFact.FactID, sourceFieldFact.FactID)
		}
	}
	if derivationBundle != nil {
		derivationState, err := parseDocumentationClaimDerivationRows(derivationBundle.profileRows)
		if err != nil {
			t.Fatalf("parse complete documentation derivation fixture: %v", err)
		}
		if dependencyProfileReferenceKey(sourceAccessFact.Profile) != dependencyProfileReferenceKey(sourceFieldFact.Profile) {
			t.Fatal("complete documentation projection facts do not bind one exact derivation profile")
		}
		definition, ok := derivationState.derivations[dependencyProfileReferenceKey(sourceFieldFact.Profile)]
		if !ok {
			t.Fatal("complete documentation projection field fact has no exact derivation definition")
		}
		validation, ok := derivationState.validationSchemas[dependencyProfileReferenceKey(definition.validationSchema)]
		if !ok {
			t.Fatal("complete documentation projection has no exact claim-schema authority")
		}
		claimKind = definition.claimKind
		claimSchemaID = definition.validationSchema.id
		derivationProfileID = sourceFieldFact.Profile.id
		derivationProfileDigest = sourceFieldFact.Profile.digest
		derivationReference = sourceFieldFact.Profile
		officialValidationReference = definition.validationSchema
		officialClaimSchemaJSON = string(validation.authority.canonicalSchemaBytes)
	}
	sourceFieldClaim, err := decodeExactDocumentationFactOutputFields(sourceFieldFact)
	if err != nil {
		t.Fatal(err)
	}
	fieldName := "Amount"
	fieldDisplay := "Amount"
	providerType := "Decimal"
	providerRequirement := "Required"
	providerDescription := primary.providerDescription
	if derivationBundle != nil {
		var ok bool
		fieldName, ok = sourceFieldClaim["field_name"].(string)
		if !ok || fieldName == "" {
			t.Fatal("complete documentation field fact has no exact field_name")
		}
		fieldDisplay = fieldName
		providerType, ok = sourceFieldClaim["provider_type"].(string)
		if !ok || providerType == "" {
			t.Fatal("complete documentation field fact has no exact provider_type")
		}
		if value, ok := sourceFieldClaim["provider_requirement"].(string); ok && value != "" {
			providerRequirement = value
		}
		if value, ok := sourceFieldClaim["provider_description"].(string); ok && value != "" {
			providerDescription = value
		} else if value, ok := sourceFieldClaim["description"].(string); ok && value != "" {
			providerDescription = value
		}
	}
	numericSemantics := "exact_decimal"
	numericCarrier := "source_lexeme"
	computationPath := "unresolved_fail_closed_gap"
	computationApplicability := "required"
	if derivationBundle != nil {
		numericSemantics = derivationBundle.numeric.numericSemantics
		numericCarrier = derivationBundle.numeric.authoritativeCarrier
		computationPath = derivationBundle.numeric.computationPath
		computationApplicability = derivationBundle.applicability
	}

	dependencyByRole := map[string]string{}
	dependencyByRole["selection_roster"] = selectionRosterPath
	visionPath := filepath.Join(dir, "VELENZA_GRAND_VISION_v1.md")
	if err := os.WriteFile(visionPath, []byte("# fixture Grand Vision\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceRecordPath := filepath.Join(dir, "SOURCE_RECORD_AND_SEMANTIC_PROJECTION_v1.ood.json")
	if err := os.WriteFile(sourceRecordPath, []byte(`{"doc_id":"fixture-source-record","version":1,"status":"locked"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.jsonl")
	profileRows := []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "fixture_provider_neutral_compilation_profile", "artifact_version": "2", "schema_version": "provider_documentation_compilation_profile_candidate.v2", "status": "candidate_not_admissible", "named_system": "Velenza BOC", "purpose": "source-neutral test compiler profile", "authority_posture": "derived_candidate_only",
		"canonical_ood_graph_spec":         map[string]interface{}{"doc_id": "fixture-ood", "version": "1", "raw_sha256": sha256Hex(oodRaw), "canonical_ref": "fixture/OOD_GRAPH_PROTOCOL_v1.ood.json"},
		"grand_vision":                     map[string]interface{}{"raw_sha256": fileSHA256(t, visionPath), "canonical_ref": "fixture/VELENZA_GRAND_VISION_v1.md", "governing_principles": []string{"P1", "P2", "P3", "P6", "P7", "P12", "P16"}},
		"source_record_contract":           map[string]interface{}{"doc_id": "fixture-source-record", "version": "1", "raw_sha256": fileSHA256(t, sourceRecordPath), "canonical_ref": "fixture/SOURCE_RECORD_AND_SEMANTIC_PROJECTION_v1.ood.json"},
		"canonical_execution_is_this_file": false, "canonical_execution": "admitted_capability_sequence_only",
	}}
	for _, role := range roles {
		profileRows = append(profileRows, map[string]interface{}{"row_kind": "api_element_role", "object_class": "api_symbol", "api_element_role": role, "role_binding_authority": roleAuthorityRule, "symbol_kind_authority": false, "source_field_path": "sections.s2_graph_object_model.api_symbol_role_registry.roles"})
	}
	for _, constraint := range constraints {
		profileRows = append(profileRows, map[string]interface{}{"row_kind": "api_relationship", "edge_label": constraint.EdgeLabel, "source_object_class": "api_symbol", "source_api_element_role": constraint.SourceRole, "target_object_class": "api_symbol", "target_api_element_role": constraint.TargetRole, "provider_specific_label_allowed": false, "generic_references_or_depends_on_substitution_allowed": false, "source_field_path": "sections.s4_edge_model.api_relationship_contract.labels_and_role_constraints"})
	}
	for _, family := range families {
		profileRows = append(profileRows, map[string]interface{}{"row_kind": "api_property_family", "property_family": family, "eligible_subjects": []string{"api_symbol_object", "api_relationship_edge"}, "property_schema_binding_required": true, "exact_evidence_locator_manifest_required": true, "authority_exclusions": propertyAuthorityExclusions, "source_field_path": "sections.s2_graph_object_model.api_property_claim_model.property_families"})
	}
	for index, capability := range capabilities {
		profileRows = append(profileRows, map[string]interface{}{"row_kind": "capability_stage", "ordinal": index + 1, "capability": capability, "source_field_path": "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.canonical_ingestion_execution_model.capability_sequence", "must_resolve_to_admitted_executable_node": true, "provider_specific_implementation_allowed": false})
	}
	for _, objectClass := range externalObjectClasses {
		profileRows = append(profileRows, map[string]interface{}{"row_kind": "external_document_object_class", "object_class": objectClass, "source_field_path": "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.object_classes_created"})
	}
	for _, edgeLabel := range externalEdgeLabels {
		profileRows = append(profileRows, map[string]interface{}{"row_kind": "external_document_edge_label", "edge_label": edgeLabel, "source_field_path": "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.edge_labels_created"})
	}
	for _, sourceClass := range allowedSourceClasses {
		profileRows = append(profileRows, map[string]interface{}{"row_kind": "source_authority_class", "source_class": sourceClass, "disposition": "requires_exact_binding", "source_field_path": "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.source_authority_policy.allowed_source_classes", "policy_rule": sourceAuthorityRule})
	}
	for _, sourceClass := range forbiddenSourceClasses {
		profileRows = append(profileRows, map[string]interface{}{"row_kind": "source_authority_class", "source_class": sourceClass, "disposition": "forbidden", "source_field_path": "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.source_authority_policy.forbidden_source_classes", "policy_rule": sourceAuthorityRule})
	}
	profileRows = append(profileRows,
		map[string]interface{}{"row_kind": "canonical_table_surface", "logical_name": "fixture_rows", "physical_table_name": "FixtureRows", "purpose": "organization-scoped fixture surface", "primary_key": []string{"organization_id", "fixture_id"}, "organization_scoped": true, "column_count": 2, "source_field_path": "sections.s6_spanner_storage_model.table_surfaces.fixture_rows", "columns_are_loaded_from_canonical_spec_at_execution": true},
		map[string]interface{}{"row_kind": "exact_evidence_locator_profile", "source_field_path": "fixture.locator_profile", "representation_identity_owner": "selected_evidence_metadata", "required_before_fetch": true, "provider_evidence_body": "exact source-declared machine-export bytes selected by an admitted representation declaration", "machine_export_authority_rule": "selected_exact_bytes_only", "source_origin_authority_rule": "typed_binding_required", "source_ui_export_rule": "declared_representation_only", "navigation_aid_rule": "non_authoritative", "contradiction_behavior": "preserve_and_fail_closed", "body_persistence_in_ood_graph_allowed": false, "durable_exact_byte_archive_required": true, "coordinate": map[string]interface{}{"source_content_hash_algorithm": "sha256", "source_content_hash_profile": sourceContentHashProfile, "source_content_sha256": "required", "byte_start_offset": "required", "byte_end_offset_exclusive": "required", "selected_range_byte_count": "required", "selected_range_sha256": "required"}, "line_heading_dom_accessibility_navigation_or_ai_summary_authority": false, "graph_fact_locator_manifest_required": true},
		map[string]interface{}{"row_kind": "execution_boundary", "source_field_path": "sections.s8_graph_materialization_and_ingestion.external_reference_ingestion_contract.canonical_ingestion_execution_model", "entry_capability": capabilities[0], "rule": "admitted_capabilities_only", "external_ingress_executability_rule": "typed_ingress_only", "http_service_boundary": "adapter_only", "ring_contract": "preserve_specified_ring_chokepoints", "graph_source_of_truth_boundary": "derived_graph_only", "semantic_projection_separation": "post_publication_only"},
		map[string]interface{}{"row_kind": "external_evidence_lifecycle", "source_field_path": "fixture.lifecycle", "immutable_evidence_identity": []string{"source_coordinate", "content_digest"}, "fetch_occurrence": "typed_receipt", "same_bytes_new_fetch": "new_receipt", "same_occurrence_retry": "same_receipt", "retrieved_at_or_observed_at_in_evidence_identity": false, "freshness_source": "receipt", "body_persistence_in_ood_graph_allowed": false, "byte_faithful_archive_required": true, "archive_record_is_evidence_identity": false, "pre_parse_completeness": "sealed_selection_roster", "successor_receipt_closure": "exact_deletion_domain_closure", "required_metadata": []string{"source_coordinate", "content_digest", "record_deletion_domain", "archive_crypto_shred_domain"}},
		map[string]interface{}{"row_kind": "provider_fixture_input_contract", "source_neutral": true, "authority_bindings": []string{"fixture.authority"}, "required_inputs": []string{"exact evidence"}, "provider_adapter_may_supply": []string{"representation locator"}, "provider_adapter_must_not_own": []string{"graph identity"}},
		map[string]interface{}{"row_kind": "publication_acceptance_contract", "authority_bindings": []string{"fixture.authority"}, "required_proofs": []string{"exact hydration"}, "acceptance_tenant_count_minimum": 2, "source_substitution_required": true, "zero_findings_required": true},
		map[string]interface{}{"row_kind": "tenant_scope_contract", "source_field_path": "fixture.tenant", "organization_id_source": "kernel_injected_request_context", "caller_supplied_organization_id": "forbidden", "fail_closed_when_missing": []string{"organization_id"}, "predicate_rule": "exact_organization_id_equality", "source_record_authority": map[string]interface{}{"doc_id": "fixture-source-record", "version": "1", "raw_sha256": fileSHA256(t, sourceRecordPath)}, "organization_id_required_everywhere": map[string]interface{}{"ood_graph_rows": true, "property_graph_node_views": true, "property_graph_edge_views": true, "graph_queries": true, "retrieval_outputs": true, "projection_artifacts": true, "validation_evidence_refs": true, "policy_decision_refs": true, "forge_request_envelopes": true, "forge_output_envelopes": true, "violations": true}, "organization_id_join_key_required": true, "cross_tenant_sibling_reference_allowed": false, "cross_tenant_graph_closure_allowed": false},
	)
	profileRows = append(profileRows, map[string]interface{}{
		"row_kind": "validation_summary", "result": "provider_neutral_profile_compiled_from_current_canonical_ood_graph_contract", "canonical_ood_graph_sha256": sha256Hex(oodRaw),
		"api_element_role_count": len(roles), "api_relationship_count": len(constraints), "api_property_family_count": len(families), "canonical_capability_stage_count": len(capabilities), "canonical_table_surface_count": 1, "external_document_object_class_count": len(externalObjectClasses), "external_document_edge_label_count": len(externalEdgeLabels), "source_authority_allowed_class_count": len(allowedSourceClasses), "source_authority_forbidden_class_count": len(forbiddenSourceClasses),
		"organization_id_kernel_injected": true, "provider_specific_go_required": false, "kernel_go_required": false, "canonical_execution_is_admitted_nodes": true, "ready_to_execute": false, "execution_blockers": []string{"fixture remains non-admissible"},
	})
	writeJSONL(t, profilePath, profileRows)
	dependencyByRole["profile"] = profilePath
	entityCoordinate := map[string]interface{}{"source_content_sha256": bodyDigest, "byte_start_offset": 0, "byte_end_offset_exclusive": len(body), "selected_range_byte_count": len(body), "selected_range_sha256": bodyDigest}
	sourceAccessFactID := sourceAccessFact.FactID
	sourceFieldFactID := sourceFieldFact.FactID
	sourceAccessOccurrenceID := stableID("opocc", lengthPrefixedIdentityKey(sourceAccessFactID, sourceAccessFact.EvidenceLocatorID, candidateEvidenceLocatorIdentityKey(sourceAccessFact.EvidenceLocator)))
	sourceAccessCoordinate := map[string]interface{}{
		"source_content_sha256":     sourceAccessFact.EvidenceLocator.SourceContentSHA256,
		"byte_start_offset":         sourceAccessFact.EvidenceLocator.ByteStartOffset,
		"byte_end_offset_exclusive": sourceAccessFact.EvidenceLocator.ByteEndOffsetExclusive,
		"selected_range_byte_count": sourceAccessFact.EvidenceLocator.SelectedRangeByteCount,
		"selected_range_sha256":     sourceAccessFact.EvidenceLocator.SelectedRangeSHA256,
	}
	sourceContractPath := filepath.Join(dir, "source-contract.jsonl")
	writeJSONL(t, sourceContractPath, []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_source_contract_index", "artifact_version": "2", "status": "candidate_not_admissible", "provider": provider, "source_evidence_authority": "selected_machine_export", "derived_from_manifest_sha256s": []string{evidenceManifestDigest}, "evidence_hydration": "exact byte range", "locator_authority": "selected body only", "line_and_section_coordinates": "diagnostic only", "target_home_status": "candidate", "consumer_contract": "source blind", "financial_value_contract": "exact values only",
	}, map[string]interface{}{
		"row_kind": "source_document", "evidence_manifest_sha256": evidenceManifestDigest, "source_ref": sourceRef, "source_url": sourceURL, "content_sha256": bodyDigest, "content_bytes": len(body), "source_content_hash_profile": sourceContentHashProfile, "observed_line_delimiter_profile": bodyLineDelimiterProfile, "representation": representation, "representation_coordinate": representationCoordinate, "source_representation_kind": supportedEvidenceRepresentationKind, "component_byte_domain_profile": componentByteDomainProfile, "evidence_hydration_coordinate": entityCoordinate,
	}, map[string]interface{}{
		"row_kind": "api_operation", "source_symbol": sourceReadOperationSymbol, "surface_kind": "operation", "source_ref": sourceRef, "source_url": sourceURL, "content_sha256": bodyDigest, "line_number": 1, "section_path": []string{primary.sectionRoot, "Operations"}, "source_operation_identity": map[string]interface{}{"identity_kind": "source_contract_operation", "identity_components": map[string]interface{}{"operation_name": primary.operationName}}, "source_neutral_capability": "candidate_read", "operation_evidence_occurrences": []interface{}{map[string]interface{}{"occurrence_id": sourceAccessOccurrenceID, "evidence_locator_id": sourceAccessFact.EvidenceLocatorID, "documentation_derived_fact_id": sourceAccessFactID}}, "resource_accesses": []interface{}{map[string]interface{}{"source_symbol": sourceSymbolByRole["resource"], "relationship_label": "operation_reads_resource", "evidence_locator_ids": []string{sourceAccessFact.EvidenceLocatorID}, "documentation_derived_fact_ids": []string{sourceAccessFactID}}}, "evidence_hydration_coordinate": sourceAccessCoordinate,
	}, map[string]interface{}{
		"row_kind": "field_contract", "documentation_derived_fact_id": sourceFieldFactID, "source_symbol": sourceSymbolByRole["resource"], "surface_kind": "resource", "source_ref": sourceRef, "source_url": sourceURL, "source_content_sha256": bodyDigest, "official_json_pointer": "/entities/" + primary.sourceSymbolPrefix, "line_number": 1, "section_path": []string{primary.sectionRoot, "Fields"}, "field_display": fieldDisplay, "field_name": fieldName, "cardinality": "scalar", "provider_type": providerType, "provider_requirement": providerRequirement, "provider_description": providerDescription, "numeric_disposition": map[string]interface{}{"numeric_semantics": numericSemantics, "authoritative_carrier": numericCarrier, "binary_float_authoritative": false, "computation_path": computationPath}, "source_neutral_target": "candidate", "evidence_hydration_coordinate": entityCoordinate,
	}, map[string]interface{}{
		"row_kind": "validation_summary", "expected_source_documents": 1, "parsed_source_documents": 1, "section_count": 0, "field_contract_count": 1, "documentation_table_row_count": 0, "api_operation_count": 1, "parse_issue_count": 0, "exact_evidence_hydration_coordinates_present": true, "authoritative_locator_form": zeroBasedHalfOpenLocatorForm, "diagnostic_line_and_section_coordinates_are_authority": false, "source_neutral_targets_admitted": false, "result": "candidate_parse_complete",
	}})
	dependencyByRole["source_contract"] = sourceContractPath
	decoderDefinition := map[string]interface{}{
		"decoder_profile_id": "fixture_utf8_strict_decoder", "decoder_profile_version": "1", "program": map[string]interface{}{"kind": sampleDecoderKindUTF8Strict},
	}
	decoderCanonical := fixtureCanonicalJSONString(t, decoderDefinition)
	decoderBinding := map[string]interface{}{
		"decoder_profile_id": "fixture_utf8_strict_decoder", "decoder_profile_version": "1", "decoder_profile_sha256": sha256Hex([]byte(decoderCanonical)), "program": map[string]interface{}{"kind": sampleDecoderKindUTF8Strict},
	}
	parserDefinition := map[string]interface{}{
		"parser_profile_id": "fixture_json_rfc8259_parser", "parser_profile_version": "1", "program": map[string]interface{}{"kind": sampleParserKindJSONRFC8259, "duplicate_key_policy": "reject", "trailing_content_policy": "reject", "number_handling": "preserve_raw_lexeme"},
	}
	parserCanonical := fixtureCanonicalJSONString(t, parserDefinition)
	parserBinding := map[string]interface{}{
		"parser_profile_id": "fixture_json_rfc8259_parser", "parser_profile_version": "1", "parser_profile_sha256": sha256Hex([]byte(parserCanonical)), "program": map[string]interface{}{"kind": sampleParserKindJSONRFC8259, "duplicate_key_policy": "reject", "trailing_content_policy": "reject", "number_handling": "preserve_raw_lexeme"},
	}
	parseProfileDefinition := map[string]interface{}{
		"parse_profile_id": "fixture_json_utf8_parse_profile", "parse_profile_version": "1", "source_representation_media_type": "application/json", "transport_charset": "utf-8", "decoder_profile": decoderBinding, "parser_profile": parserBinding,
	}
	parseProfileCanonical := fixtureCanonicalJSONString(t, parseProfileDefinition)
	parseProfileDigest := sha256Hex([]byte(parseProfileCanonical))
	parseProfileBinding := map[string]interface{}{
		"parse_profile_id": "fixture_json_utf8_parse_profile", "parse_profile_version": "1", "parse_profile_sha256": parseProfileDigest,
	}
	parseReference := dependencyProfileReference{id: "fixture_json_utf8_parse_profile", version: "1", digest: parseProfileDigest}
	parseOutcome, parseFailure, parsedSample := executeSampleParseProfile(sampleParseProfile{
		reference:        parseReference,
		mediaType:        "application/json",
		transportCharset: "utf-8",
		decoderReference: dependencyProfileReference{id: "fixture_utf8_strict_decoder", version: "1", digest: decoderBinding["decoder_profile_sha256"].(string)},
		decoderKind:      sampleDecoderKindUTF8Strict,
		parserReference:  dependencyProfileReference{id: "fixture_json_rfc8259_parser", version: "1", digest: parserBinding["parser_profile_sha256"].(string)},
		parserKind:       sampleParserKindJSONRFC8259,
	}, body)
	var parseFailureValue interface{}
	if parseFailure != nil {
		parseFailureValue = map[string]interface{}{
			"failure_class": parseFailure.class, "failure_stage": parseFailure.stage,
			"parse_profile_id": parseFailure.profile.id, "parse_profile_version": parseFailure.profile.version, "parse_profile_sha256": parseFailure.profile.digest,
		}
	}
	sampleShapePath := filepath.Join(dir, "sample-shape.jsonl")
	sampleShapeRows := []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_json_sample_shape_index", "artifact_version": "2", "status": "candidate_not_admissible", "provider": provider, "source_evidence_authority": "selected_machine_export", "derived_from_manifest_sha256s": []string{evidenceManifestDigest}, "array_index_normalization": "wildcard", "number_handling": "raw lexeme", "sample_value_authority": "example only", "evidence_hydration": "exact byte range", "locator_authority": "selected body only", "line_and_section_coordinates": "diagnostic only",
	}, map[string]interface{}{
		"row_kind": "sample_parse_profile", "parse_profile_id": "fixture_json_utf8_parse_profile", "parse_profile_version": "1", "parse_profile_sha256": parseProfileDigest, "canonical_profile_json": parseProfileCanonical,
	}, map[string]interface{}{
		"row_kind": "sample_json_block", "source_symbol": sourceSymbolByRole["resource"], "surface_kind": "resource", "source_ref": sourceRef, "source_url": sourceURL, "document_content_sha256": bodyDigest, "section_path": []string{primary.sectionRoot, "Sample"}, "start_line_number": 1, "end_line_number": 1, "block_content_sha256": bodyDigest, "block_content_bytes": len(body), "parse_outcome": parseOutcome, "parse_failure": parseFailureValue, "parse_profile_binding": parseProfileBinding, "evidence_hydration_coordinate": entityCoordinate, "diagnostic_navigation_coordinate": map[string]interface{}{"start_line_number": 1, "end_line_number": 1, "section_path": []string{primary.sectionRoot, "Sample"}},
	}}
	sampleShapeCount := 0
	if parseOutcome == sampleParseOutcomeParsed {
		if _, ok := parsedSample.(string); !ok {
			t.Fatalf("test fixture JSON sample has parsed kind %T, want the closed string fixture", parsedSample)
		}
		sampleShapeRows = append(sampleShapeRows, map[string]interface{}{
			"row_kind": "sample_json_shape", "source_symbol": sourceSymbolByRole["resource"], "surface_kind": "resource", "source_ref": sourceRef, "source_url": sourceURL, "block_content_sha256": bodyDigest, "normalized_json_pointer": "", "observed_kinds": []string{"string"}, "occurrences": 1, "observed_raw_number_lexemes": nil, "observed_string_classes": []string{"text"}, "schema_authority": "sample_only_not_schema", "binary_float_authoritative": false, "evidence_hydration_coordinate": entityCoordinate,
		})
		sampleShapeCount = 1
	}
	boolCount := func(value bool) int {
		if value {
			return 1
		}
		return 0
	}
	sampleShapeRows = append(sampleShapeRows, map[string]interface{}{
		"row_kind": "validation_summary", "expected_source_documents": 1, "sample_json_block_count": 1, "sample_parse_profile_count": 1,
		"parsed_sample_json_block_count": boolCount(parseOutcome == sampleParseOutcomeParsed), "unparsed_sample_json_block_count": boolCount(parseOutcome != sampleParseOutcomeParsed),
		"failed_sample_json_block_count": boolCount(parseOutcome == sampleParseOutcomeFailed), "unsupported_sample_json_block_count": boolCount(parseOutcome == sampleParseOutcomeUnsupported), "not_applicable_sample_json_block_count": boolCount(parseOutcome == sampleParseOutcomeNotApplicable),
		"sample_json_shape_row_count": sampleShapeCount, "raw_numeric_lexemes_preserved": true, "source_examples_treated_as_schema": false, "exact_evidence_locator_binding_count": 1 + sampleShapeCount, "exact_evidence_hydration_coordinates_present": true, "authoritative_locator_form": zeroBasedHalfOpenLocatorForm, "diagnostic_line_and_section_coordinates_are_authority": false, "result": "candidate_sample_index_complete_with_explicit_parse_outcomes",
	})
	writeJSONL(t, sampleShapePath, sampleShapeRows)
	dependencyByRole["sample_shape"] = sampleShapePath
	protocolContractPath := filepath.Join(dir, "protocol-contract.jsonl")
	protocolCoordinate := map[string]interface{}{"source_content_sha256": protocolBodyDigest, "byte_start_offset": 0, "byte_end_offset_exclusive": len(protocolBody), "selected_range_byte_count": len(protocolBody), "selected_range_sha256": protocolBodyDigest}
	protocolAssertionA := "fixture_protocol_a"
	protocolAssertionB := "fixture_protocol_b"
	protocolOperationIdentity := map[string]interface{}{"identity_kind": "protocol_assertion_operation", "identity_components": map[string]interface{}{"assertion_set": "fixture_change_event_write"}}
	canonicalProtocolOperationIdentity, err := canonicalSourceOperationIdentity(protocolOperationIdentity)
	if err != nil {
		t.Fatal(err)
	}
	protocolFactID := stableID("opfact", lengthPrefixedIdentityKey(sourceSymbolByRole["operation"], sourceSymbolByRole["resource"], "change_event_write", string(canonicalProtocolOperationIdentity), protocolAssertionA, protocolAssertionB))
	protocolFactLocatorSet := map[string]struct{}{classificationLocator.ID: {}, protocolEvidenceLocator.ID: {}}
	protocolFactLocatorIDs := sortedSetKeys(protocolFactLocatorSet)
	writeJSONL(t, protocolContractPath, []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_protocol_contract_index", "artifact_version": "2", "status": "candidate_not_admissible", "provider": provider, "derived_from_manifest_sha256s": []string{protocolEvidenceManifestDigest}, "evidence_authority": "exact source-declared evidence body", "representation_rule": "selected representation only", "semantic_projection_rule": "source-neutral candidate assertions", "evidence_hydration": "exact byte range", "locator_authority": "selected body only", "line_and_section_coordinates": "diagnostic only", "diagnostic_non_authorities": []string{"line_number", "section_path"}, "blocking_dependencies": []string{"admitted external evidence runtime"},
	}, map[string]interface{}{
		"row_kind": "protocol_assertion_projection", "assertion_id": protocolAssertionA, "assertion_class": "fixture_contract", "candidate_semantics": "first candidate meaning", "required_velenza_boc_consequence": "preserve exact provider assertion", "evidence_match_literal": primary.protocolLiteralA, "source_ref": protocolSourceRef, "source_url": protocolSourceURL, "evidence_body_sha256": protocolBodyDigest, "evidence_hydration_coordinate": protocolCoordinate, "diagnostic_navigation_coordinate": map[string]interface{}{"line_number": 1, "literal_occurrence_selected": 1, "literal_match_count": bytes.Count(protocolBody, []byte(primary.protocolLiteralA))}, "evidence_status": "candidate_exact_hydration", "plan_semantic_disposition": map[string]interface{}{"kind": "preserved_contradiction", "bindings": []string{"fixture_contradiction"}},
	}, map[string]interface{}{
		"row_kind": "protocol_assertion_projection", "assertion_id": protocolAssertionB, "assertion_class": "fixture_contract", "candidate_semantics": "second candidate meaning", "required_velenza_boc_consequence": "preserve exact provider assertion", "evidence_match_literal": primary.protocolLiteralB, "source_ref": protocolSourceRef, "source_url": protocolSourceURL, "evidence_body_sha256": protocolBodyDigest, "evidence_hydration_coordinate": protocolCoordinate, "diagnostic_navigation_coordinate": map[string]interface{}{"line_number": 1, "literal_occurrence_selected": 1, "literal_match_count": bytes.Count(protocolBody, []byte(primary.protocolLiteralB))}, "evidence_status": "candidate_exact_hydration", "plan_semantic_disposition": map[string]interface{}{"kind": "preserved_contradiction", "bindings": []string{"fixture_contradiction"}},
	}, map[string]interface{}{
		"row_kind": "operation_classifier_fact", "operation_classifier_fact_id": protocolFactID, "source_symbol": sourceSymbolByRole["operation"], "resource_source_symbol": sourceSymbolByRole["resource"], "semantic_class": "change_event_write", "source_operation_identity": protocolOperationIdentity, "protocol_assertion_ids": []string{protocolAssertionA, protocolAssertionB}, "evidence_locator_ids": protocolFactLocatorIDs, "source_bytes_present": false,
	}, map[string]interface{}{
		"row_kind": "provider_contract_contradiction", "contradiction_id": "fixture_contradiction", "assertions": []string{protocolAssertionA, protocolAssertionB}, "evidence_hydration_coordinates": []interface{}{map[string]interface{}{"assertion_id": protocolAssertionA, "source_ref": protocolSourceRef, "coordinate": protocolCoordinate}, map[string]interface{}{"assertion_id": protocolAssertionB, "source_ref": protocolSourceRef, "coordinate": protocolCoordinate}}, "disposition": "preserve both exact assertions and fail closed until resolved",
	}, map[string]interface{}{
		"row_kind": "validation_summary", "evidence_body_count": 1, "evidence_exact_source_bytes": len(protocolBody), "protocol_section_projection_count": 0, "protocol_assertion_projection_count": 2, "operation_classifier_fact_count": 1, "preserved_provider_contradiction_count": 1, "source_export_is_only_evidence_body": true, "selected_representation_is_only_evidence_body": true, "exact_hydration_coordinates_present": true, "exact_evidence_locator_binding_count": 6, "authoritative_locator_form": zeroBasedHalfOpenLocatorForm, "diagnostic_line_and_section_coordinates_are_authority": false, "result": "candidate_protocol_contract_index_complete",
	}})
	dependencyByRole["protocol_contract"] = protocolContractPath

	claimSchemaForOutput := func(output map[string]interface{}) map[string]interface{} {
		raw, err := json.Marshal(output)
		if err != nil {
			t.Fatal(err)
		}
		var normalized map[string]interface{}
		if err := decodeOneValidationProfileJSON(raw, &normalized); err != nil {
			t.Fatal(err)
		}
		return fixtureSchemaForObject(t, normalized, false)
	}
	claimSchemaRaw, err := json.Marshal(map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     claimSchemaID,
		"oneOf": []interface{}{
			claimSchemaForOutput(accessFactOutput),
			claimSchemaForOutput(fieldFactOutput),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	claimSchemaCanonical, err := canonicalizeCandidateJSON(claimSchemaRaw)
	if err != nil {
		t.Fatal(err)
	}
	claimSchemaJSON := string(claimSchemaCanonical)
	claimSchemaDigest := sha256Hex(claimSchemaCanonical)
	if derivationBundle != nil {
		claimSchemaJSON = officialClaimSchemaJSON
		claimSchemaDigest = officialValidationReference.digest
	}
	classifierRuleID := "decimal_provider_type"
	if derivationBundle != nil {
		classifierRuleID = "exact_official_provider_type"
	}
	exactValueClassifierProgram := map[string]interface{}{
		"program_kind": exactValueClassifierProgramKind, "input_claim_kind": claimKind,
		"input_validation_schema_binding": map[string]interface{}{
			"validation_schema_id": claimSchemaID, "validation_schema_version": semanticProfileVersion, "validation_schema_sha256": claimSchemaDigest,
		},
		"input_projection_json_pointers": []string{"/provider_type"},
		"match_semantics":                exactValueClassifierMatchExactlyOne,
		"ordered_rules": []interface{}{map[string]interface{}{
			"ordinal": 0, "rule_id": classifierRuleID,
			"predicates": []interface{}{map[string]interface{}{
				"predicate_kind": exactValuePredicateStringEquals, "input_json_pointer": "/provider_type", "expected_string": providerType,
			}},
			"output": map[string]interface{}{
				"numeric_semantics": numericSemantics, "authoritative_carrier": numericCarrier, "computation_path": computationPath,
			},
		}},
		"terminal_default":         exactValueClassifierTerminalFailClosed,
		"numeric_lexeme_preserved": true, "binary_float_authoritative": false,
	}
	exactValueClassifierCanonical, err := canonicalOperationClassifierProgram(exactValueClassifierProgram)
	if err != nil {
		t.Fatal(err)
	}
	classifierProfileDigest := sha256Hex(exactValueClassifierCanonical)
	resolutionProfileDigest := sha256Hex([]byte("fixture source-neutral exact-computation resolution profile v1"))
	operationClassifierProfile, operationClassifierReference := testOperationClassifierProfile(t)
	exactValueClassifierRow := map[string]interface{}{
		"row_kind": "classifier_profile", "classifier_profile_id": classifierProfileID, "classifier_profile_version": semanticProfileVersion, "classifier_profile_sha256": classifierProfileDigest, "input_claim_kind": claimKind, "closed_output_union": []string{numericSemantics}, "authoritative_carrier_union": []string{numericCarrier}, "computation_path_union": []string{computationPath}, "program": exactValueClassifierProgram,
	}
	operationClassifierRow := map[string]interface{}{
		"row_kind": "classifier_profile", "classifier_profile_id": operationClassifierReference.id, "classifier_profile_version": operationClassifierReference.version, "classifier_profile_sha256": operationClassifierReference.digest, "input_claim_kind": operationClassifierProfile.claimKind, "closed_output_union": sortedSetKeys(operationClassifierProfile.semanticClasses), "authoritative_carrier_union": sortedSetKeys(operationClassifierProfile.carriers), "computation_path_union": sortedSetKeys(operationClassifierProfile.computationPaths), "program": operationClassifierProfile.program,
	}
	resolutionProfileRow := map[string]interface{}{
		"row_kind": "dependency_resolution_profile", "resolution_profile_id": resolutionProfileID, "resolution_profile_version": semanticProfileVersion, "resolution_profile_sha256": resolutionProfileDigest, "unresolved_disposition": "fail_closed", "publication_allowed_without_complete_coordinates": false,
	}
	documentationRows := []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_documentation_claim_derivation_profile", "artifact_version": "1", "status": "candidate_not_admissible", "provider": provider, "canonical_admission_authorized": false, "independent_generic_reexecution_required": true,
	}, map[string]interface{}{
		"row_kind": "validation_schema", "validation_schema_id": claimSchemaID, "validation_schema_version": semanticProfileVersion, "validation_schema_sha256": claimSchemaDigest, "claim_kind": claimKind, "schema_dialect": validationProfileDraft202012, "canonical_schema_json": claimSchemaJSON,
	}, map[string]interface{}{
		"row_kind": "derivation_profile", "derivation_profile_id": derivationProfileID, "derivation_profile_version": semanticProfileVersion, "derivation_profile_sha256": derivationProfileDigest, "claim_kind": claimKind, "validation_schema_binding": map[string]interface{}{"validation_schema_id": claimSchemaID, "validation_schema_version": semanticProfileVersion, "validation_schema_sha256": claimSchemaDigest}, "program": derivationProgramObject,
	}, exactValueClassifierRow, operationClassifierRow}
	if computationApplicability == "required" {
		documentationRows = append(documentationRows, resolutionProfileRow)
	}
	if derivationBundle == nil {
		documentationRows = append(documentationRows, map[string]interface{}{
			"row_kind": "validation_summary", "validation_schema_count": 1, "derivation_profile_count": 1, "classifier_profile_count": 2, "dependency_resolution_profile_count": boolCount(computationApplicability == "required"), "canonical_admission_authorized": false, "independent_generic_reexecution_required": true, "result": "candidate_closed_source_neutral_derivation_profile",
		})
	} else {
		documentationRows = documentationRows[:0]
		var summaryRow map[string]interface{}
		for _, line := range bytes.Split(derivationBundle.profileRows.raw, []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var row map[string]interface{}
			if err := decodeOneValidationProfileJSON(line, &row); err != nil {
				t.Fatal(err)
			}
			if kind, _ := row["row_kind"].(string); kind == "validation_summary" {
				summaryRow = row
				continue
			}
			documentationRows = append(documentationRows, row)
		}
		documentationRows = append(documentationRows, exactValueClassifierRow, operationClassifierRow)
		if computationApplicability == "required" {
			documentationRows = append(documentationRows, resolutionProfileRow)
		}
		if summaryRow == nil {
			t.Fatal("complete documentation derivation profile has no validation summary")
		}
		summaryRow["classifier_profile_count"] = 2
		summaryRow["dependency_resolution_profile_count"] = boolCount(computationApplicability == "required")
		documentationRows = append(documentationRows, summaryRow)
	}
	documentationDerivationPath := filepath.Join(dir, "documentation-claim-derivation-profile.jsonl")
	writeJSONL(t, documentationDerivationPath, documentationRows)
	dependencyByRole["documentation_claim_derivation_profile"] = documentationDerivationPath
	documentationDerivationDigest := fileSHA256(t, documentationDerivationPath)
	if derivationBundle != nil {
		preparedRaw, err := os.ReadFile(documentationDerivationPath)
		if err != nil {
			t.Fatal(err)
		}
		preparedRows, err := parseDependencySemanticRows(artifactInput{Path: documentationDerivationPath, Raw: preparedRaw, SHA256: sha256Hex(preparedRaw), Structured: true})
		if err != nil {
			t.Fatalf("parse prepared complete documentation derivation artifact: %v", err)
		}
		preparedState, err := parseDocumentationClaimDerivationRows(preparedRows)
		if err != nil {
			t.Fatalf("parse prepared complete documentation derivation closure: %v", err)
		}
		preparedClosure, err := executeAndValidateDocumentationDerivationClosure(preparedRows, preparedState, derivationBundle.targetAuthority, derivationBundle.targetArtifacts, derivationBundle.targetRows, derivationProof, derivationBodies)
		if err != nil {
			t.Fatalf("execute prepared complete documentation derivation closure: %v", err)
		}
		if preparedClosure.profilePageSetRootSHA256 != derivationBundle.pageSetRoot ||
			preparedClosure.profileResultSetRootSHA256 != derivationBundle.resultSetRoot ||
			preparedClosure.targetMaterializationRootSHA256 != derivationBundle.targetRoot ||
			preparedClosure.targetMaterializationBindingRosterRootSHA256 != derivationBundle.targetRosterRoot ||
			preparedClosure.outcomeCount != derivationBundle.outcomeCount ||
			preparedClosure.factCount != derivationBundle.factCount ||
			preparedClosure.wholeRowBindingCount != derivationBundle.wholeRowCount ||
			preparedClosure.rowMemberBindingCount != 0 {
			t.Fatal("prepared documentation artifact changed the independently executed official derivation/materialization closure")
		}
		derivationBundle.closureProofRoot = preparedClosure.proofSHA256
		derivationBundle.closure = preparedClosure
	}
	profileReference := func(prefix, id, digest string) map[string]interface{} {
		return map[string]interface{}{prefix + "_id": id, prefix + "_version": semanticProfileVersion, prefix + "_sha256": digest}
	}
	surfaceDerivationBinding := map[string]interface{}{}
	for key, value := range profileReference("derivation_profile", derivationProfileID, derivationProfileDigest) {
		surfaceDerivationBinding[key] = value
	}
	for key, value := range profileReference("validation_schema", claimSchemaID, claimSchemaDigest) {
		surfaceDerivationBinding[key] = value
	}
	for key, value := range profileReference("classifier_profile", classifierProfileID, classifierProfileDigest) {
		surfaceDerivationBinding[key] = value
	}
	surfaceDerivationBinding["exact_input_source_content_sha256"] = bodyDigest
	surfaceDerivationBinding["reexecution_status"] = "pending_independent_generic_reexecution"
	numericProfile := map[string]interface{}{numericSemantics + "_occurrences": 1}

	surfaceDispositionPath := filepath.Join(dir, "surface-family-disposition.jsonl")
	writeJSONL(t, surfaceDispositionPath, []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_surface_family_disposition", "artifact_version": "2", "status": "candidate_not_admissible", "provider": provider, "evidence_manifest_sha256s": []string{evidenceManifestDigest}, "source_contract_index_sha256": fileSHA256(t, sourceContractPath), "documentation_claim_derivation_profile_sha256": documentationDerivationDigest, "evidence_hydration": "exact byte range", "mapping_rule": "source-neutral candidate family only", "silent_unknowns_allowed": false, "universal_blob_target_allowed": false, "normal_consumer_contract": "source blind typed projection", "line_section_dom_navigation_or_ai_summary_authority": false,
	}, map[string]interface{}{
		"row_kind": "surface_disposition", "source_symbol": sourceSymbolByRole["resource"], "surface_kind": "resource", "source_ref": sourceRef, "source_url": sourceURL, "official_json_pointer": "/entities/" + primary.sourceSymbolPrefix, "evidence_content_sha256": bodyDigest, "source_neutral_family": "fixture_record", "target_kind": "typed_record", "target_contract_status": "candidate_contract_unlocked", "business_record_projection": true, "typed_home_rule": "canonical typed contract required before admission", "lattice_rule": "source-blind projection only", "exact_numeric_profile": numericProfile, "numeric_ingress": "preserve source lexeme as typed exact candidate", "numeric_computation": "unresolved fail closed exact pipeline", "unsupported_field_disposition": "restricted_no_embed", "derivation_binding": surfaceDerivationBinding, "evidence_hydration_coordinate": entityCoordinate,
	}, map[string]interface{}{
		"row_kind": "validation_summary", "expected_surface_count": 1, "selected_source_count": 1, "disposed_surface_count": 1, "disposed_surface_kind_counts": []interface{}{map[string]interface{}{"surface_kind": "resource", "count": 1}}, "captured_surface_kind_counts": []interface{}{map[string]interface{}{"surface_kind": "resource", "count": 1}}, "silent_unknown_count": 0, "universal_blob_targets": 0, "canonical_contracts_still_unlocked": 1, "exact_evidence_locator_binding_count": 1, "authoritative_locator_form": zeroBasedHalfOpenLocatorForm, "diagnostic_coordinates_are_authority": false, "result": "candidate_exhaustive_surface_family_disposition_complete",
	}})
	dependencyByRole["surface_disposition"] = surfaceDispositionPath

	securityPolicy := map[string]interface{}{
		"policy_id": "fixture_security", "policy_version": "1", "source_neutral": true, "authority_bindings": []string{"fixture.authority"},
		"closed_security_classes":            []string{"restricted_no_embed", "standard_no_raw_value_embedding"},
		"precedence":                         []string{"standard_exact_field_name", "restricted_unclassified_default"},
		"standard_exact_field_name_registry": []string{fieldName}, "unknown_security_class_allowed": false, "unclassified_field_disposition": "restricted_no_embed", "raw_source_value_embedding_allowed": false, "authority_posture": "candidate",
		"ordered_rules": []interface{}{
			map[string]interface{}{"ordinal": 0, "rule_id": "standard_exact_field_name", "input_member": "source_field", "match_kind": "exact_registry_membership", "registry_member": "standard_exact_field_name_registry", "output_security_class": "standard_no_raw_value_embedding"},
			map[string]interface{}{"ordinal": 1, "rule_id": "restricted_unclassified_default", "input_member": "*", "match_kind": "default", "registry_member": nil, "output_security_class": "restricted_no_embed"},
		},
	}
	securityPolicyRaw, err := json.Marshal(securityPolicy)
	if err != nil {
		t.Fatal(err)
	}
	securityPolicyDigest := sha256Hex(securityPolicyRaw)
	fieldSecurityPath := filepath.Join(dir, "field-security-policy.jsonl")
	writeJSONL(t, fieldSecurityPath, []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_field_security_policy", "artifact_version": "1", "status": "candidate_not_admissible", "provider": provider, "policy_id": "fixture_security", "policy_version": "1", "profile_sha256": securityPolicyDigest, "canonical_admission_authorized": false,
	}, map[string]interface{}{
		"row_kind": "security_classification_profile", "profile": securityPolicy, "profile_sha256": securityPolicyDigest,
	}, map[string]interface{}{
		"row_kind": "security_class_definition", "policy_id": "fixture_security", "policy_version": "1", "profile_sha256": securityPolicyDigest, "security_class": "restricted_no_embed", "raw_source_value_embedding_allowed": false, "normal_consumer_visibility": false, "unclassified_default": true,
	}, map[string]interface{}{
		"row_kind": "security_class_definition", "policy_id": "fixture_security", "policy_version": "1", "profile_sha256": securityPolicyDigest, "security_class": "standard_no_raw_value_embedding", "raw_source_value_embedding_allowed": false, "normal_consumer_visibility": true, "unclassified_default": false,
	}, map[string]interface{}{
		"row_kind": "validation_summary", "security_class_definition_count": 2, "profile_count": 1, "raw_source_value_embedding_allowed": false, "canonical_admission_authorized": false, "result": "candidate_closed_source_neutral_field_security_policy",
	}})
	dependencyByRole["field_security_policy"] = fieldSecurityPath

	envelopeSchemaID := "urn:fixture:provider-documentation:artifact-validation-profile-schema"
	envelopeSchemaPath := filepath.Join(dir, "artifact-validation-profile.schema.json")
	writeFixtureArtifactValidationEnvelopeSchema(t, envelopeSchemaPath, envelopeSchemaID)
	mappingArtifactPath := filepath.Join(dir, "mapping-seed.jsonl")
	writeJSONL(t, mappingArtifactPath, []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_source_neutral_mapping_seed", "artifact_version": "1", "status": "candidate_not_admissible", "provider": provider, "canonical_admission_authorized": false,
	}, map[string]interface{}{
		"row_kind": "mapping_candidate", "mapping_id": "fixture_amount_seed", "source_field": fieldName, "target_role": "amount", "authority_posture": "candidate_input_only",
	}, map[string]interface{}{
		"row_kind": "validation_summary", "mapping_count": 1, "canonical_admission_authorized": false, "result": "candidate_closed_mapping_seed",
	}})
	mappingSchemaID := "urn:fixture:provider-documentation:mapping-seed-schema"
	mappingSchemaPath := filepath.Join(dir, "mapping-seed.schema.json")
	writeFixtureExactJSONLSchema(t, mappingArtifactPath, mappingSchemaPath, mappingSchemaID)
	const mappingDependencyRole = "generic_mapping_seed"
	mappingValidationProfileID := "fixture_mapping_seed_validation_profile"
	mappingValidationProfilePath := filepath.Join(dir, "mapping-seed.validation-profile.jsonl")
	writeFixtureArtifactValidationProfile(t, mappingValidationProfilePath, mappingValidationProfileID, []dependencySemanticProfileArtifactBinding{{
		Role: mappingDependencyRole, ArtifactID: "fixture_source_neutral_mapping_seed", ArtifactVersion: "1", ArtifactRawSHA256: fileSHA256(t, mappingArtifactPath), SchemaRole: "generic_mapping_seed_schema", SchemaID: mappingSchemaID, SchemaVersion: "1", SchemaRawSHA256: fileSHA256(t, mappingSchemaPath),
	}})
	mappingBindingID := "fixture_mapping_seed_binding"
	transitiveRosterPath := filepath.Join(dir, "mapping-transitive-dependency-roster.jsonl")
	writeJSONL(t, transitiveRosterPath, []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_mapping_transitive_dependency_roster", "artifact_version": "1", "status": "candidate_not_admissible", "provider": provider, "dependency_count": 1, "closed_dependency_role_roster": []string{mappingDependencyRole}, "canonical_admission_authorized": false,
	}, map[string]interface{}{
		"row_kind": "mapping_transitive_dependency", "dependency_binding_id": mappingBindingID, "precedence_ordinal": 0, "dependency_role": mappingDependencyRole,
		"artifact_identity": map[string]interface{}{"artifact": "fixture_source_neutral_mapping_seed", "artifact_version": "1", "artifact_sha256": fileSHA256(t, mappingArtifactPath)},
		"applicability":     map[string]interface{}{"selector_kind": "all_fields", "selector_values": []string{"*"}}, "authority_posture": "candidate_input_only", "exact_revalidation_required": true,
		"validation_binding": map[string]interface{}{"validation_schema_id": mappingSchemaID, "validation_schema_version": "1", "validation_schema_sha256": fileSHA256(t, mappingSchemaPath), "validation_profile_id": mappingValidationProfileID, "validation_profile_version": "1", "validation_profile_sha256": fileSHA256(t, mappingValidationProfilePath)},
	}, map[string]interface{}{
		"row_kind": "validation_summary", "dependency_count": 1, "canonical_admission_authorized": false, "result": "candidate_closed_mapping_transitive_roster",
	}})
	dependencyByRole["mapping_transitive_dependency_roster"] = transitiveRosterPath

	sourceFieldClaim, err = decodeExactDocumentationFactOutputFields(sourceFieldFact)
	if err != nil {
		t.Fatal(err)
	}
	exactClassifierProjection, err := canonicalExactValueClassifierInputProjection([]string{"/provider_type"}, sourceFieldClaim)
	if err != nil {
		t.Fatal(err)
	}
	exactFieldFactCoordinate := map[string]interface{}{
		"source_content_sha256":     sourceFieldFact.EvidenceLocator.SourceContentSHA256,
		"byte_start_offset":         sourceFieldFact.EvidenceLocator.ByteStartOffset,
		"byte_end_offset_exclusive": sourceFieldFact.EvidenceLocator.ByteEndOffsetExclusive,
		"selected_range_byte_count": sourceFieldFact.EvidenceLocator.SelectedRangeByteCount,
		"selected_range_sha256":     sourceFieldFact.EvidenceLocator.SelectedRangeSHA256,
	}
	fieldDerivationBinding := map[string]interface{}{}
	for key, value := range profileReference("derivation_profile", derivationProfileID, derivationProfileDigest) {
		fieldDerivationBinding[key] = value
	}
	for key, value := range profileReference("validation_schema", claimSchemaID, claimSchemaDigest) {
		fieldDerivationBinding[key] = value
	}
	for key, value := range profileReference("classifier_profile", classifierProfileID, classifierProfileDigest) {
		fieldDerivationBinding[key] = value
	}
	fieldDerivationBinding["exact_input_documentation_fact_id"] = sourceFieldFactID
	fieldDerivationBinding["exact_input_evidence_locator_id"] = sourceFieldFact.EvidenceLocatorID
	fieldDerivationBinding["exact_input_claim_sha256"] = sha256Hex(sourceFieldFact.CanonicalOutputFields)
	fieldDerivationBinding["exact_input_projection_sha256"] = sha256Hex(exactClassifierProjection)
	fieldDerivationBinding["exact_classifier_rule_id"] = classifierRuleID
	fieldDerivationBinding["exact_input_coordinate"] = exactFieldFactCoordinate
	fieldDerivationBinding["reexecution_status"] = "complete_exact_generic_reexecution"
	fieldMappingPath := filepath.Join(dir, "field-mapping.jsonl")
	fieldMappingSummary := map[string]interface{}{
		"row_kind": "validation_summary", "source_document_count": 1, "surface_family_count": 1, "documented_field_occurrence_count": 1, "disposed_field_occurrence_count": 1, "exact_locator_binding_count": 1, "explicit_quarantine_count": 0, "source_only_count": 0, "prior_entity_seed_count": 0, "prior_global_seed_count": 0, "direct_role_count": 1, "typed_reference_count": 0, "exact_integer_count": 0, "silent_unknown_count": 0, "arbitrary_provider_json_passthrough_count": 0, "raw_value_embedding_count": 0, "binary_float_authoritative_count": 0, "restricted_no_embed_count": 0, "standard_no_raw_value_embedding_count": 1, "restricted_unclassified_default_count": 0, "canonical_target_contracts_locked": false, "security_policy_sha256": securityPolicyDigest, "security_policy_artifact_sha256": fileSHA256(t, fieldSecurityPath), "security_policy_profile_sha256": securityPolicyDigest, "admitted_derivation_profile_proof_established": false, "result": "candidate_complete_atomic_field_occurrence_disposition_with_explicit_quarantine_and_no_passthrough",
	}
	fieldMappingSummary[numericSemantics+"_count"] = 1
	writeJSONL(t, fieldMappingPath, []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": artifactPrefix + "_all_field_source_neutral_map", "artifact_version": "2", "status": "candidate_not_admissible", "provider": provider, "evidence_manifest_sha256s": []string{evidenceManifestDigest}, "source_contract_index_sha256": fileSHA256(t, sourceContractPath), "surface_family_disposition_sha256": fileSHA256(t, surfaceDispositionPath), "mapping_transitive_dependency_roster_sha256": fileSHA256(t, transitiveRosterPath), "field_security_policy_artifact_sha256": fileSHA256(t, fieldSecurityPath), "field_security_policy_id": "fixture_security", "field_security_policy_version": "1", "field_security_policy_profile_sha256": securityPolicyDigest, "field_security_policy_sha256": securityPolicyDigest, "documentation_claim_derivation_profile_sha256": documentationDerivationDigest, "provider_documentation_evidence": "exact source field contract", "mapping_rule": "source-neutral target candidate", "unknown_passthrough_allowed": false, "arbitrary_provider_json_allowed": false, "consumer_source_awareness_allowed": false, "canonical_target_contracts_locked": false, "embedding_raw_field_values_allowed": false, "binary_float_authoritative": false,
	}, map[string]interface{}{
		"row_kind": "field_occurrence_disposition", "documentation_derived_fact_id": sourceFieldFactID, "source_symbol": sourceSymbolByRole["resource"], "surface_kind": "resource", "source_ref": sourceRef, "source_url": sourceURL, "target_record_family": "fixture_record", "source_field": fieldName, "source_provider_type": providerType, "source_cardinality": "scalar", "source_requirement": providerRequirement, "source_section_path": []string{primary.sectionRoot, "Fields"}, "target_role": "amount", "target_candidate_path": "fixture_record.amount", "disposition": "typed_field", "mapping_source": "candidate source-neutral compiler", "mapping_is_provider_documentation_fact": false, "provider_field_contract_is_evidence": true, "absence_semantics": "absent remains absent", "exact_numeric_semantics": numericSemantics, "numeric_authoritative_carrier": numericCarrier, "binary_float_authoritative": false, "financial_computation_path": computationPath, "security_class": "standard_no_raw_value_embedding", "security_classification_reason": "standard_exact_field_name", "security_policy_id": "fixture_security", "security_policy_version": "1", "security_policy_profile_sha256": securityPolicyDigest, "raw_source_value_embedding_allowed": false, "normal_consumer_visibility": true, "typed_home_contract_locked": false, "applicable_transitive_dependency_binding_ids": []string{mappingBindingID}, "exact_computation_dependency": map[string]interface{}{"applicability": computationApplicability, "resolution_status": "unresolved_fail_closed_gap", "resolution_profile_id": resolutionProfileID, "resolution_profile_version": semanticProfileVersion, "resolution_profile_sha256": resolutionProfileDigest}, "derivation_binding": fieldDerivationBinding, "evidence_hydration_coordinate": entityCoordinate,
	}, fieldMappingSummary})
	dependencyByRole["field_mapping"] = fieldMappingPath

	semanticArtifactPaths := map[string]string{
		dependencySemanticRoleProfile:                      profilePath,
		dependencySemanticRoleSourceContract:               sourceContractPath,
		dependencySemanticRoleSampleShape:                  sampleShapePath,
		dependencySemanticRoleProtocolContract:             protocolContractPath,
		dependencySemanticRoleFieldMapping:                 fieldMappingPath,
		dependencySemanticRoleSurfaceDisposition:           surfaceDispositionPath,
		dependencySemanticRoleFieldSecurityPolicy:          fieldSecurityPath,
		dependencySemanticRoleMappingTransitiveRoster:      transitiveRosterPath,
		dependencySemanticRoleDocumentationClaimDerivation: documentationDerivationPath,
	}
	semanticValidationProfileID := "fixture_dependency_semantic_validation_profile"
	semanticValidationProfilePath := filepath.Join(dir, "dependency-semantic-validation-profile.jsonl")

	selectedDigest := sha256Hex(body)
	locator := &classificationLocator
	locator.SelectedRangeSHA256 = selectedDigest
	locatorID := locator.ID
	planLocatorByID := map[string]*evidenceLocator{}
	addPlanLocator := func(candidate evidenceLocator) {
		if prior, duplicate := planLocatorByID[candidate.ID]; duplicate {
			if candidateEvidenceLocatorIdentityKey(*prior) != candidateEvidenceLocatorIdentityKey(candidate) {
				t.Fatalf("classification locator ID %q aliases different exact coordinates", candidate.ID)
			}
			return
		}
		copy := candidate
		planLocatorByID[candidate.ID] = &copy
	}
	for _, role := range roles {
		sourceSymbol := sourceSymbolByRole[role]
		for _, occurrence := range classificationOccurrences[sourceSymbol] {
			addPlanLocator(occurrence.Locator)
		}
	}
	for _, occurrence := range classificationOccurrences[sourceReadOperationSymbol] {
		addPlanLocator(occurrence.Locator)
	}
	addPlanLocator(sourceAccessFact.EvidenceLocator)
	planLocatorIDs := sortedProviderStringMapKeys(planLocatorByID)
	planLocators := make([]*evidenceLocator, 0, len(planLocatorIDs))
	for _, planLocatorID := range planLocatorIDs {
		planLocators = append(planLocators, planLocatorByID[planLocatorID])
	}
	var locatorManifestBytes []byte
	for _, planLocator := range planLocators {
		locatorRaw, err := json.Marshal(planLocator)
		if err != nil {
			t.Fatal(err)
		}
		locatorManifestBytes = append(locatorManifestBytes, locatorRaw...)
		locatorManifestBytes = append(locatorManifestBytes, '\n')
	}
	evidenceBindings := []evidenceManifestBinding{{EvidenceManifestSHA256: evidenceManifestDigest, EvidenceBodyKind: evidenceBodyKindSourceDocument, ConsumerRoles: []string{"api_graph_projection", "field_mapping_candidate", "sample_shape_index", "source_contract_index", "surface_family_disposition"}}}
	evidencePaths := []string{evidencePath}
	if primary.singleDocument {
		evidenceBindings[0].ConsumerRoles = append(evidenceBindings[0].ConsumerRoles, "protocol_contract_index")
		sort.Strings(evidenceBindings[0].ConsumerRoles)
	} else {
		evidenceBindings = append(evidenceBindings, evidenceManifestBinding{EvidenceManifestSHA256: protocolEvidenceManifestDigest, EvidenceBodyKind: evidenceBodyKindSourceDocument, ConsumerRoles: []string{"api_graph_projection", "protocol_contract_index"}})
		evidencePaths = append(evidencePaths, protocolEvidencePath)
	}
	planRows := []interface{}{&artifactManifest{
		RowKind: "artifact_manifest", Artifact: artifactPrefix + "_api_graph_plan", ArtifactVersion: "1", Status: "candidate_not_admissible_or_executable", Provider: provider, NamedSystem: "Velenza BOC", CanonicalOODGraphSHA256: sha256Hex(oodRaw),
		ProviderNeutralProfileSHA256: fileSHA256(t, profilePath), SourceContractIndexSHA256: fileSHA256(t, sourceContractPath), SampleShapeIndexSHA256: fileSHA256(t, sampleShapePath), ProtocolContractIndexSHA256: fileSHA256(t, protocolContractPath), EvidenceManifestBindings: evidenceBindings, FieldMappingCandidateSHA256: fileSHA256(t, fieldMappingPath), FieldSecurityPolicySHA256: fileSHA256(t, fieldSecurityPath), MappingTransitiveDependencyRosterSHA256: fileSHA256(t, transitiveRosterPath), DocumentationClaimDerivationProfileSHA256: fileSHA256(t, documentationDerivationPath), OperationApplicabilityProfileSHA256: strings.Repeat("0", 64), APIGraphApplicabilityProfileSHA256: strings.Repeat("1", 64), DependencySemanticValidation: dependencySemanticValidationPlanBinding{Profile: dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile", ID: semanticValidationProfileID, Version: "1", RawSHA256: strings.Repeat("2", 64)}, Schema: dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile_schema", ID: envelopeSchemaID, Version: "1", RawSHA256: fileSHA256(t, envelopeSchemaPath)}}, EvidenceSelectionRosterSHA256: selectionRosterDigest, EvidenceLocatorManifestSHA256: sha256Hex(locatorManifestBytes),
	}}
	for _, planLocator := range planLocators {
		planRows = append(planRows, planLocator)
	}
	symbolByRole := map[string]string{}
	for _, role := range roles {
		sourceSymbol := sourceSymbolByRole[role]
		semanticKey := artifactPrefix + ":" + role
		if role == "resource" {
			semanticKey = "resource:" + artifactPrefix
		} else if role == "operation" {
			semanticKey = artifactPrefix + "_operation_candidate_write_event"
		}
		id := stableID("capi_sym", lengthPrefixedIdentityKey(role, semanticKey))
		symbolByRole[role] = id
		locatorSet := map[string]struct{}{}
		for _, occurrence := range classificationOccurrences[sourceSymbol] {
			locatorSet[occurrence.Locator.ID] = struct{}{}
		}
		symbol := &apiSymbol{RowKind: "candidate_api_symbol", ID: id, Role: role, SemanticKey: semanticKey, DisplayName: role, EvidenceLocatorIDs: sortedSetKeys(locatorSet), AuthorityStatus: symbolAuthorityStatusExact}
		symbol.DerivationBinding, err = candidateAPISymbolDerivationBindingFor(*symbol, selectionRosterDigest, classificationOccurrences[sourceSymbol])
		if err != nil {
			t.Fatal(err)
		}
		planRows = append(planRows, symbol)
	}
	sourceOperationIdentity := fixtureSourceOperationIdentityFor(primary.operationName)
	sourceOperationKey, err := sourceOperationSemanticKey(sourceReadOperationSymbol, sourceOperationIdentity)
	if err != nil {
		t.Fatal(err)
	}
	sourceOperationID := stableID("capi_sym", lengthPrefixedIdentityKey("operation", sourceOperationKey))
	readLocatorSet := map[string]struct{}{}
	for _, occurrence := range classificationOccurrences[sourceReadOperationSymbol] {
		readLocatorSet[occurrence.Locator.ID] = struct{}{}
	}
	sourceOperation := &apiSymbol{RowKind: "candidate_api_symbol", ID: sourceOperationID, Role: "operation", SemanticKey: sourceOperationKey, DisplayName: "fixture source-contract operation", EvidenceLocatorIDs: sortedSetKeys(readLocatorSet), AuthorityStatus: symbolAuthorityStatusExact}
	sourceOperation.DerivationBinding, err = candidateAPISymbolDerivationBindingFor(*sourceOperation, selectionRosterDigest, classificationOccurrences[sourceReadOperationSymbol])
	if err != nil {
		t.Fatal(err)
	}
	planRows = append(planRows, sourceOperation)

	sourceCoverageLabel := "operation_reads_resource"
	sourceCoverageID := stableID("capi_rel", lengthPrefixedIdentityKey(sourceCoverageLabel, sourceOperationID, symbolByRole["resource"]))
	sourceCoverage := &apiRelationship{RowKind: "candidate_api_relationship", ID: sourceCoverageID, Label: sourceCoverageLabel, SourceID: sourceOperationID, TargetID: symbolByRole["resource"], LocatorIDs: []string{sourceAccessFact.EvidenceLocatorID}, AuthorityStatus: relationAuthorityStatusExact}
	sourceInput, sourceRows := fixtureDependencySemanticArtifact(t, sourceContractPath)
	sourceOperationRows := sourceRows.byKind["api_operation"]
	if len(sourceOperationRows) != 1 {
		t.Fatalf("fixture source contract has %d api_operation rows, want 1", len(sourceOperationRows))
	}
	predecessor, err := typedGraphPredecessorFactForRow(typedGraphArtifactRoleSourceContract, sourceInput, sourceOperationRows[0], "source_symbol", sourceReadOperationSymbol, typedGraphFactSourceOperationAccess, 0)
	if err != nil {
		t.Fatal(err)
	}
	sourceCoverage.DerivationBinding, err = typedGraphPredecessorDerivationBindingFor(sourceCoverage.RowKind, sourceCoverage.ID, []typedGraphPredecessorFact{predecessor})
	if err != nil {
		t.Fatal(err)
	}
	planRows = append(planRows, sourceCoverage)
	planRows = append(planRows, &validationSummary{RowKind: "validation_summary", CandidateEvidenceLocatorCount: len(planLocators), CandidateAPISymbolCount: len(roles) + 1, CandidateAPIRelationshipCount: 1, CandidateAPIPropertyClaimCount: 0, CandidateGraphGapCount: 0, APIElementRolesMaterialized: len(roles), APIRelationshipLabelsMaterialized: 1, APIPropertyFamiliesMaterialized: 0, ExactSourceDocumentCount: 1, CandidateOperationCount: 2, CapturedOperationKindCounts: []operationKindCount{{OperationKind: "event_driven_write_operation", Count: 1}, {OperationKind: "request_response_read_operation", Count: 1}}, OperationApplicabilityCount: 2, CandidateSubjectCount: len(roles) + 2, SubjectSetRootSHA256: sha256Hex([]byte("fixture subject set")), FactSetRootSHA256: sha256Hex([]byte("fixture fact set")), GapSetRootSHA256: sha256Hex(nil), ExactDocumentedFieldOccurrenceCount: 1, SampleJSONBlockCount: 1, ProtocolAssertionCount: 2, PreservedContradictionCount: 1, Result: "structural_candidate_only"})
	planPath := filepath.Join(dir, "plan.jsonl")
	writeJSONL(t, planPath, planRows)
	planRaw, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	sets, err := deriveStageGraphSets(planRaw, verifyGraphRowDispositions())
	if err != nil {
		t.Fatal(err)
	}
	summary := planRows[len(planRows)-1].(*validationSummary)
	summary.CandidateSubjectCount = int(sets["subject"].Count)
	summary.SubjectSetRootSHA256 = sets["subject"].RootSHA256
	summary.FactSetRootSHA256 = sets["fact"].RootSHA256
	summary.GapSetRootSHA256 = sets["gap"].RootSHA256
	writeJSONL(t, planPath, planRows)
	protocolEvidenceRolePath := protocolEvidencePath
	if primary.singleDocument {
		protocolEvidenceRolePath = evidencePath
	}
	fixture := &testFixture{planPath: planPath, oodPath: oodPath, evidencePath: evidencePath, evidenceByRole: map[string]string{"entity": evidencePath, "protocol": protocolEvidenceRolePath}, planRows: planRows, roles: roles, constraints: constraints, families: families, locatorID: locatorID, symbolByRole: symbolByRole, sourceSymbolByRole: sourceSymbolByRole, sourceReadOperationSymbol: sourceReadOperationSymbol, sourceOperationID: sourceOperationID, dependencyByRole: dependencyByRole, schemaByRole: map[string]string{}, artifactCoordinateByRole: map[string]stageMaterialCoordinate{}, sourceOperationIdentity: sourceOperationIdentity, derivationTargetPaths: map[string]string{}, derivationTargetSchemas: map[string]string{}}
	if derivationBundle != nil {
		fixture.derivationTargets = derivationBundle.targetArtifacts
		fixture.derivationTargetAuthority = derivationBundle.targetAuthority
		fixture.documentationDerivation = derivationBundle
	} else {
		fixture.derivationTargetAuthority, fixture.derivationTargets = buildDefaultFixtureDocumentationTargets(t, dir, sourceContractPath, sourceAccessFact, sourceFieldFact)
	}
	dependencyPaths := buildFixtureApplicabilityClosure(t, fixture, semanticArtifactPaths, semanticValidationProfilePath, semanticValidationProfileID, envelopeSchemaPath, envelopeSchemaID, operationClassifierReference, mappingArtifactPath, mappingSchemaPath, mappingValidationProfilePath, selectionRosterPath, classificationRosterPath)
	fixture.planStageSchemaRaw = buildFixturePlanStageSchema(t, fixture)
	fixture.options = Options{OODSpecPath: oodPath, ExpectedOODSpecSHA256: fileSHA256(t, oodPath), GrandVisionPath: visionPath, ExpectedGrandVisionSHA256: fileSHA256(t, visionPath), SourceRecordSpecPath: sourceRecordPath, ExpectedSourceRecordSHA256: fileSHA256(t, sourceRecordPath), graphCompileSelectionLoader: func() ([]byte, StageCompileInputs, error) {
		request, inputs := newVerifyGraphStageSelection(t, fixture)
		return request, inputs, nil
	}, EvidenceManifestPath: evidencePaths, DependencyArtifactPath: dependencyPaths}
	return fixture
}

func buildDefaultFixtureDocumentationTargets(
	t *testing.T,
	dir string,
	sourceContractPath string,
	accessFact exactDocumentationDerivedFact,
	fieldFact exactDocumentationDerivedFact,
) (dependencySemanticDerivationTargetSchemaAuthority, map[string]artifactInput) {
	t.Helper()
	_, sourceRows := fixtureDependencySemanticArtifact(t, sourceContractPath)
	var accessRow, fieldRow map[string]interface{}
	for _, row := range sourceRows.byKind["api_operation"] {
		sourceSymbol, _ := semanticString(row.data, "source_symbol")
		if sourceSymbol == accessFact.InputSourceSymbol {
			if accessRow != nil {
				t.Fatalf("default exact documentation target has more than one api_operation for source symbol %q", sourceSymbol)
			}
			accessRow = row.data
		}
	}
	for _, row := range sourceRows.byKind["field_contract"] {
		factID, _ := semanticString(row.data, exactDocumentationDerivedFactIDField)
		if factID == fieldFact.FactID {
			if fieldRow != nil {
				t.Fatalf("default exact documentation target has more than one field_contract for fact %q", factID)
			}
			fieldRow = row.data
		}
	}
	if accessRow == nil || fieldRow == nil {
		t.Fatalf("default exact documentation target rows are incomplete: access=%t field=%t", accessRow != nil, fieldRow != nil)
	}

	const (
		role            = dependencySemanticRoleSourceContract
		artifactID      = "fixture_exact_documentation_source_contract_target"
		artifactVersion = "1"
	)
	artifactPath := filepath.Join(dir, "default-exact-documentation-source-contract-target.jsonl")
	writeJSONL(t, artifactPath, []interface{}{
		map[string]interface{}{
			"row_kind": "artifact_manifest", "artifact": artifactID, "artifact_version": artifactVersion,
			"canonical_admission_authorized": false, "materialization_authority": "exact_documentation_derivation",
		},
		accessRow,
		fieldRow,
		map[string]interface{}{
			"row_kind": "validation_summary", "documentation_derived_row_count": 2,
			"canonical_admission_authorized": false, "result": "exact_documentation_target_fixture_complete",
		},
	})
	artifact, err := readArtifactInput(artifactPath)
	if err != nil {
		t.Fatalf("read default exact documentation target: %v", err)
	}
	if !artifact.Structured || artifact.Manifest == nil {
		t.Fatal("default exact documentation target is not one exact structured artifact")
	}

	schemaID := "urn:fixture:provider-documentation:exact-target:source-contract:v1"
	schemaPath := filepath.Join(dir, "default-exact-documentation-source-contract-target.schema.json")
	writeFixtureExactJSONLSchema(t, artifactPath, schemaPath, schemaID)
	schemaBytes, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	schemaSHA256 := sha256Hex(schemaBytes)
	if err := validateValidationProfileBindings(
		[]validationProfileBinding{{
			Role: role, ArtifactID: artifactID, ArtifactVersion: artifactVersion, ArtifactSHA256: artifact.SHA256,
			SchemaID: schemaID, SchemaVersion: artifactVersion, SchemaSHA256: schemaSHA256,
		}},
		[]validationProfileArtifact{{ID: artifactID, Version: artifactVersion, Bytes: artifact.Raw}},
		[]validationProfileSchema{{ID: schemaID, Version: artifactVersion, Bytes: schemaBytes}},
	); err != nil {
		t.Fatalf("default exact documentation target profile: %v", err)
	}
	authority := dependencySemanticDerivationTargetSchemaAuthority{
		seal: dependencySemanticDerivationTargetSchemaAuthorityIdentity,
		byRole: map[string]dependencySemanticDerivationTargetSchema{
			role: {
				artifactRole: role, artifactSHA256: artifact.SHA256,
				schemaRole: role + "_exact_documentation_target_schema", schemaID: schemaID, schemaVersion: artifactVersion, schemaSHA256: schemaSHA256,
				schemaBytes: schemaBytes, discriminatorProperty: "row_kind",
				discriminatorValues: map[string]struct{}{"artifact_manifest": {}, "api_operation": {}, "field_contract": {}, "validation_summary": {}},
			},
		},
	}
	return authority, map[string]artifactInput{role: artifact}
}

var testProtocolEvidenceBody = func() []byte {
	body := bytes.Repeat([]byte{0xff}, 2048)
	body = append(body, []byte("protocol")...)
	body = append(body, bytes.Repeat([]byte{0xfe}, 2048)...)
	body = append(body, []byte("evidence")...)
	body = append(body, bytes.Repeat([]byte{0xfd}, 2048)...)
	return body
}()

var testPrimaryEvidenceBody = []byte(`"12.34"` + strings.Repeat("\t", 128))

func buildFixtureApplicabilityClosure(t *testing.T, fixture *testFixture, semanticArtifactPaths map[string]string, semanticValidationProfilePath, semanticValidationProfileID, envelopeSchemaPath, envelopeSchemaID string, operationClassifierReference dependencyProfileReference, mappingArtifactPath, mappingSchemaPath, mappingValidationProfilePath, selectionRosterPath, classificationRosterPath string) []string {
	t.Helper()
	manifest := fixture.manifest()
	summary := fixture.summary()
	dir := filepath.Dir(fixture.planPath)
	evaluation := fixtureApplicabilityBinding{ProfileID: "fixture_source_neutral_api_applicability", ProfileVersion: "1", ProfileSHA256: sha256Hex([]byte("fixture source-neutral API applicability evaluation profile v1"))}
	fixture.applicability = evaluation
	fixture.ruleByLabel = map[string]string{}
	fixture.claimRuleID = "fixture_required_claim"

	apiApplicabilityPath := filepath.Join(dir, "api-graph-applicability-profile.jsonl")
	apiRows := []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "fixture_api_graph_applicability_profile", "artifact_version": "1", "status": "candidate_not_admissible", "canonical_ood_graph_sha256": manifest.CanonicalOODGraphSHA256, "source_neutral": true, "transient_expansion_required": true, "candidate_rows_are_authority": false, "closed_dispositions": []string{applicabilityDispositionRequired, applicabilityDispositionOptional, applicabilityDispositionInapplicable},
		"evaluation_profile_binding": map[string]interface{}{"evaluation_profile_id": evaluation.ProfileID, "evaluation_profile_version": evaluation.ProfileVersion, "evaluation_profile_sha256": evaluation.ProfileSHA256},
	}}
	for _, constraint := range fixture.constraints {
		ruleID := "fixture_relationship_" + constraint.EdgeLabel
		fixture.ruleByLabel[constraint.EdgeLabel] = ruleID
		endpoint, subjectRole := "source", constraint.SourceRole
		if constraint.TargetRole == "operation" {
			endpoint, subjectRole = "target", constraint.TargetRole
		}
		defaultDisposition := applicabilityDispositionOptional
		orderedRules := []interface{}{}
		switch constraint.EdgeLabel {
		case "operation_reads_resource":
			defaultDisposition = applicabilityDispositionInapplicable
			orderedRules = []interface{}{map[string]interface{}{"ordinal": 0, "disposition": applicabilityDispositionRequired, "predicate": map[string]interface{}{"predicate_kind": "classifier_output_in", "classifier_profile_id": operationClassifierReference.id, "values": []string{"reads_exact_source_resource"}}}}
		case "operation_writes_resource":
			defaultDisposition = applicabilityDispositionInapplicable
			orderedRules = []interface{}{map[string]interface{}{"ordinal": 0, "disposition": applicabilityDispositionRequired, "predicate": map[string]interface{}{"predicate_kind": "classifier_output_in", "classifier_profile_id": operationClassifierReference.id, "values": []string{"writes_exact_source_resource"}}}}
		case "operation_emits_webhook_event":
			defaultDisposition = applicabilityDispositionInapplicable
			orderedRules = []interface{}{map[string]interface{}{"ordinal": 0, "disposition": applicabilityDispositionRequired, "predicate": map[string]interface{}{"predicate_kind": "subject_trait_equals", "trait": "emits_change_event", "value": true}}}
		}
		apiRows = append(apiRows, map[string]interface{}{
			"row_kind": "relationship_applicability_rule", "applicability_rule_id": ruleID, "relationship_label": constraint.EdgeLabel, "source_api_element_role": constraint.SourceRole, "target_api_element_role": constraint.TargetRole, "applicability_subject_endpoint": endpoint, "applicability_subject_role": subjectRole, "default_disposition": defaultDisposition, "ordered_conditional_rules": orderedRules, "required_cardinality": map[string]interface{}{"minimum": 1, "maximum": 1}, "unmatched_endpoint_disposition": applicabilityDispositionInapplicable,
		})
	}
	labels := make([]string, 0, len(fixture.constraints))
	for _, constraint := range fixture.constraints {
		labels = append(labels, constraint.EdgeLabel)
	}
	sort.Strings(labels)
	roles := append([]string(nil), fixture.roles...)
	sort.Strings(roles)
	for _, family := range fixture.families {
		apiRows = append(apiRows, map[string]interface{}{
			"row_kind": "property_family_applicability_rule", "applicability_rule_id": "fixture_property_" + family, "property_family": family, "eligible_subject_kinds": []string{"api_relationship_edge", "api_symbol_object"}, "allowed_api_symbol_roles": roles, "api_relationship_label_scope": labels, "default_disposition": applicabilityDispositionOptional, "ordered_conditional_rules": []interface{}{}, "disallowed_subject_disposition": applicabilityDispositionInapplicable, "maximum_claims_per_subject": 1,
		})
	}
	apiRows = append(apiRows,
		map[string]interface{}{"row_kind": "claim_applicability_rule", "applicability_rule_id": fixture.claimRuleID, "blocked_claim_kind": "fixture_requirement", "blocked_subject_kind": "api_symbol_object", "default_disposition": applicabilityDispositionOptional, "ordered_conditional_rules": []interface{}{}, "required_cardinality": map[string]interface{}{"minimum": 0, "maximum": 1}},
		map[string]interface{}{"row_kind": "validation_summary", "relationship_applicability_rule_count": len(fixture.constraints), "property_family_applicability_rule_count": len(fixture.families), "claim_applicability_rule_count": 1, "subject_expansion_persisted": false, "optional_absence_rows_persisted": false, "canonical_admission_authorized": false, "result": "candidate_closed_source_neutral_api_applicability_profile"},
	)
	writeJSONL(t, apiApplicabilityPath, apiRows)
	fixture.dependencyByRole["api_graph_applicability"] = apiApplicabilityPath
	semanticArtifactPaths[dependencySemanticRoleAPIGraphApplicability] = apiApplicabilityPath
	manifest.APIGraphApplicabilityProfileSHA256 = fileSHA256(t, apiApplicabilityPath)
	appendFixtureRequiredOperationGaps(t, fixture, apiApplicabilityPath)
	recomputeFixtureGraphMetadata(t, fixture)

	operationApplicabilityPath := filepath.Join(dir, "operation-applicability-profile.jsonl")
	writeFixtureOperationApplicability(t, fixture, operationApplicabilityPath, operationClassifierReference)
	fixture.dependencyByRole["operation_applicability"] = operationApplicabilityPath
	semanticArtifactPaths[dependencySemanticRoleOperationApplicability] = operationApplicabilityPath
	manifest.OperationApplicabilityProfileSHA256 = fileSHA256(t, operationApplicabilityPath)

	targetSchemaPaths := make([]string, 0, len(dependencySemanticRequiredRoles))
	semanticBindings := make([]dependencySemanticProfileArtifactBinding, 0, len(dependencySemanticRequiredRoles))
	for _, role := range dependencySemanticRequiredRoles {
		artifactPath := semanticArtifactPaths[role]
		if artifactPath == "" {
			t.Fatalf("fixture semantic role %q has no artifact", role)
		}
		artifactID, artifactVersion := fixtureStructuredArtifactIdentity(t, artifactPath)
		fixture.artifactCoordinateByRole[role] = stageMaterialCoordinate{Role: role, ID: artifactID, Version: artifactVersion}
		schemaID := "urn:fixture:provider-documentation:" + role + ":schema"
		schemaPath := filepath.Join(dir, role+".schema.json")
		writeFixtureExactJSONLSchema(t, artifactPath, schemaPath, schemaID)
		fixture.schemaByRole[role] = schemaPath
		targetSchemaPaths = append(targetSchemaPaths, schemaPath)
		semanticBindings = append(semanticBindings, dependencySemanticProfileArtifactBinding{Role: role, ArtifactID: artifactID, ArtifactVersion: artifactVersion, ArtifactRawSHA256: fileSHA256(t, artifactPath), SchemaRole: role + "_schema", SchemaID: schemaID, SchemaVersion: "1", SchemaRawSHA256: fileSHA256(t, schemaPath)})
	}
	targetDependencyPaths := make([]string, 0, len(fixture.derivationTargets)*2)
	for _, role := range sortedProviderStringMapKeys(fixture.derivationTargets) {
		artifact := fixture.derivationTargets[role]
		target, ok := fixture.derivationTargetAuthority.byRole[role]
		if !ok || target.artifactSHA256 != sha256Hex(artifact.Raw) || target.schemaSHA256 != sha256Hex(target.schemaBytes) {
			t.Fatalf("complete documentation target role %q has no exact artifact/schema authority", role)
		}
		semanticPath := semanticArtifactPaths[role]
		if semanticPath == "" || fileSHA256(t, semanticPath) == target.artifactSHA256 {
			t.Fatalf("complete documentation target role %q aliases or omits its distinct enriched semantic projection", role)
		}
		artifactID, artifactVersion := fixtureStructuredArtifactIdentityFromInput(t, artifact)
		artifactPath := filepath.Join(dir, role+".exact-documentation-target.jsonl")
		if err := os.WriteFile(artifactPath, artifact.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		schemaRole := target.schemaRole
		schemaPath := filepath.Join(dir, role+".exact-documentation-target.schema.json")
		if err := os.WriteFile(schemaPath, target.schemaBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.derivationTargetPaths[role] = artifactPath
		fixture.derivationTargetSchemas[role] = schemaPath
		semanticBindings = append(semanticBindings, dependencySemanticProfileArtifactBinding{
			Role: role, ArtifactID: artifactID, ArtifactVersion: artifactVersion, ArtifactRawSHA256: target.artifactSHA256,
			SchemaRole: schemaRole, SchemaID: target.schemaID, SchemaVersion: target.schemaVersion, SchemaRawSHA256: target.schemaSHA256,
		})
		targetDependencyPaths = append(targetDependencyPaths, artifactPath, schemaPath)
	}
	writeFixtureArtifactValidationProfile(t, semanticValidationProfilePath, semanticValidationProfileID, semanticBindings)
	fixture.dependencyByRole["dependency_semantic_validation_profile"] = semanticValidationProfilePath
	fixture.dependencyByRole["dependency_semantic_validation_profile_schema"] = envelopeSchemaPath
	manifest.DependencySemanticValidation = dependencySemanticValidationPlanBinding{Profile: dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile", ID: semanticValidationProfileID, Version: "1", RawSHA256: fileSHA256(t, semanticValidationProfilePath)}, Schema: dependencySemanticValidationPin{Role: "dependency_semantic_validation_profile_schema", ID: envelopeSchemaID, Version: "1", RawSHA256: fileSHA256(t, envelopeSchemaPath)}}
	writeJSONL(t, fixture.planPath, fixture.planRows)
	assertFixtureGraphRootsStable(t, fixture, summary.SubjectSetRootSHA256, summary.FactSetRootSHA256, summary.GapSetRootSHA256)

	dependencyPaths := []string{
		semanticArtifactPaths[dependencySemanticRoleProfile], semanticArtifactPaths[dependencySemanticRoleSourceContract], semanticArtifactPaths[dependencySemanticRoleSampleShape], semanticArtifactPaths[dependencySemanticRoleProtocolContract], semanticArtifactPaths[dependencySemanticRoleFieldMapping],
		operationApplicabilityPath, apiApplicabilityPath, semanticArtifactPaths[dependencySemanticRoleSurfaceDisposition], semanticArtifactPaths[dependencySemanticRoleFieldSecurityPolicy], semanticArtifactPaths[dependencySemanticRoleMappingTransitiveRoster], semanticArtifactPaths[dependencySemanticRoleDocumentationClaimDerivation],
		mappingArtifactPath, mappingSchemaPath, mappingValidationProfilePath, semanticValidationProfilePath, envelopeSchemaPath, selectionRosterPath, classificationRosterPath,
	}
	dependencyPaths = append(dependencyPaths, targetSchemaPaths...)
	return append(dependencyPaths, targetDependencyPaths...)
}

func fixtureStructuredArtifactIdentityFromInput(t *testing.T, input artifactInput) (string, string) {
	t.Helper()
	if !input.Structured || sha256Hex(input.Raw) != input.SHA256 {
		t.Fatal("complete documentation target artifact input is not exact structured bytes")
	}
	rows, err := parseDependencySemanticRows(input)
	if err != nil {
		t.Fatal(err)
	}
	manifestRows := rows.byKind["artifact_manifest"]
	if len(manifestRows) != 1 {
		t.Fatal("complete documentation target artifact has no single manifest")
	}
	artifactID, idOK := semanticString(manifestRows[0].data, "artifact")
	artifactVersion, versionOK := semanticString(manifestRows[0].data, "artifact_version")
	if !idOK || !versionOK {
		t.Fatal("complete documentation target artifact has no exact coordinate")
	}
	return artifactID, artifactVersion
}

func appendFixtureRequiredOperationGaps(t *testing.T, fixture *testFixture, applicabilityPath string) {
	t.Helper()
	operationID := fixture.symbolByRole["operation"]
	operation := fixturePlanSymbol(t, fixture, operationID)
	locators := append([]string(nil), operation.EvidenceLocatorIDs...)
	sort.Strings(locators)
	for _, claim := range []struct {
		label      string
		targetRole string
	}{
		{label: "operation_writes_resource", targetRole: "resource"},
		{label: "operation_emits_webhook_event", targetRole: "webhook_event"},
	} {
		blockedRelationshipID := stableID("capi_rel", lengthPrefixedIdentityKey(claim.label, operationID, fixture.symbolByRole[claim.targetRole]))
		gap := &graphGap{
			RowKind:                     "candidate_graph_gap",
			GapClass:                    "required_api_relationship_incomplete",
			BlockedSubjectKind:          "api_symbol_object",
			BlockedSubjectID:            operationID,
			BlockedClaimKind:            "api_relationship",
			BlockedClaimID:              blockedRelationshipID,
			Disposition:                 "fail_closed",
			ApplicabilityProfileID:      fixture.applicability.ProfileID,
			ApplicabilityProfileVersion: fixture.applicability.ProfileVersion,
			ApplicabilityProfileSHA256:  fixture.applicability.ProfileSHA256,
			ApplicabilityRuleID:         fixture.ruleByLabel[claim.label],
			EvidenceLocatorIDs:          locators,
			GapProofBinding:             fixtureGapProof(locators...),
		}
		gap.DerivationBinding = fixtureGapDerivationBinding(t, applicabilityPath, *gap)
		identity, err := candidateGraphGapIdentityKey(*gap)
		if err != nil {
			t.Fatal(err)
		}
		gap.ID = stableID("capi_gap", identity)
		fixture.planRows = append(fixture.planRows[:len(fixture.planRows)-1], gap, fixture.summary())
	}
	fixture.summary().Result = resultCompleteWithGap
}

func writeFixtureOperationApplicability(t *testing.T, fixture *testFixture, path string, classifierReference dependencyProfileReference) {
	t.Helper()
	manifest := fixture.manifest()
	evidenceDigests := make([]string, 0, len(manifest.EvidenceManifestBindings))
	for _, binding := range manifest.EvidenceManifestBindings {
		evidenceDigests = append(evidenceDigests, binding.EvidenceManifestSHA256)
	}
	sort.Strings(evidenceDigests)
	binding := map[string]interface{}{"applicability_profile_id": fixture.applicability.ProfileID, "applicability_profile_version": fixture.applicability.ProfileVersion, "applicability_profile_sha256": fixture.applicability.ProfileSHA256}
	rows := []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": "fixture_provider_operation_applicability_profile", "artifact_version": "1", "status": "candidate_not_admissible", "canonical_ood_graph_sha256": manifest.CanonicalOODGraphSHA256, "source_contract_index_sha256": manifest.SourceContractIndexSHA256, "protocol_contract_index_sha256": manifest.ProtocolContractIndexSHA256, "documentation_claim_derivation_profile_sha256": manifest.DocumentationClaimDerivationProfileSHA256, "api_graph_applicability_profile_sha256": manifest.APIGraphApplicabilityProfileSHA256, "applicability_profile_binding": binding, "evidence_manifest_sha256s": evidenceDigests,
	}}
	sourceRows := fixtureDependencySemanticRows(t, fixture.dependencyByRole["source_contract"])
	protocolRows := fixtureDependencySemanticRows(t, fixture.dependencyByRole["protocol_contract"])
	resourceID := fixture.symbolByRole["resource"]
	resourceSemanticIdentity := fixturePlanSymbol(t, fixture, resourceID).SemanticKey
	operationKinds := map[string]string{fixture.sourceOperationID: "request_response_read_operation", fixture.symbolByRole["operation"]: "event_driven_write_operation"}
	for _, operationID := range []string{fixture.symbolByRole["operation"], fixture.sourceOperationID} {
		symbol := fixturePlanSymbol(t, fixture, operationID)
		relationshipIDs := fixtureIncidentRelationshipIDs(fixture, operationID)
		propertyIDs := fixtureOperationPropertyIDs(fixture, operationID)
		locatorIDs := append([]string(nil), symbol.EvidenceLocatorIDs...)
		accessSemantics := "reads_exact_source_resource"
		relationshipLabel := "operation_reads_resource"
		traits := map[string]interface{}{"emits_change_event": false, "reads_resource": true, "writes_resource": false}
		sourceIdentity := fixtureSourceOperationIdentity()
		if fixture.sourceOperationIdentity != nil {
			sourceIdentity = fixtureJSONObject(t, fixture.sourceOperationIdentity)
		}
		sourceSymbol := fixture.sourceReadOperationSymbol
		var predecessor operationClassifierInputBinding
		if operationID == fixture.symbolByRole["operation"] {
			accessSemantics = "writes_exact_source_resource"
			relationshipLabel = "operation_writes_resource"
			traits = map[string]interface{}{"emits_change_event": true, "reads_resource": false, "writes_resource": true}
			sourceIdentity = map[string]interface{}{"identity_kind": "protocol_assertion_operation", "identity_components": map[string]interface{}{"assertion_set": "fixture_change_event_write"}}
			sourceSymbol = fixture.sourceSymbolByRole["operation"]
			predecessor = fixtureProtocolOperationPredecessorBinding(t, protocolRows, sourceSymbol, fixture.sourceSymbolByRole["resource"], sourceIdentity)
		} else {
			predecessor = fixtureSourceOperationPredecessorBinding(t, sourceRows, symbol.SemanticKey)
		}
		evidenceFactIDs := make([]string, 0)
		if predecessor.artifactRole == operationClassifierSourceArtifactRole {
			for _, row := range sourceRows.byKind["api_operation"] {
				rowSymbol, _ := semanticString(row.data, "source_symbol")
				if rowSymbol != sourceSymbol {
					continue
				}
				accessRows, _ := semanticObjectSlice(row.data, "resource_accesses")
				if predecessor.factOrdinal >= 0 && predecessor.factOrdinal < int64(len(accessRows)) {
					selectedAccess := accessRows[predecessor.factOrdinal]
					evidenceFactIDs, _ = semanticStringSlice(selectedAccess, "documentation_derived_fact_ids")
					locatorIDs, _ = semanticStringSlice(selectedAccess, "evidence_locator_ids")
				}
			}
		} else {
			for _, row := range protocolRows.byKind["operation_classifier_fact"] {
				rowID, _ := semanticString(row.data, "operation_classifier_fact_id")
				if rowID == predecessor.rowIdentity {
					evidenceFactIDs, _ = semanticStringSlice(row.data, "protocol_assertion_ids")
					locatorIDs, _ = semanticStringSlice(row.data, "evidence_locator_ids")
				}
			}
		}
		sort.Strings(locatorIDs)
		sort.Strings(evidenceFactIDs)
		if len(evidenceFactIDs) == 0 {
			t.Fatalf("fixture operation %s has no exact evidence-fact roster", operationID)
		}
		access := fixtureOperationResourceAccess(t, operationID, fixture.sourceSymbolByRole["resource"], resourceID, resourceSemanticIdentity, relationshipLabel, accessSemantics, locatorIDs, evidenceFactIDs, predecessor)
		applicabilityID := stableID("opapp", lengthPrefixedIdentityKey(operationID, symbol.SemanticKey, classifierReference.id, classifierReference.version, classifierReference.digest, access["resource_access_id"].(string)))
		rows = append(rows, map[string]interface{}{
			"row_kind": "operation_applicability", "operation_applicability_id": applicabilityID, "operation_candidate_api_symbol_id": operationID, "operation_semantic_identity": symbol.SemanticKey, "operation_kind": operationKinds[operationID], "source_symbol": sourceSymbol, "source_operation_identity": sourceIdentity, "resource_accesses": []interface{}{access}, "subject_traits": traits, "source_operation_property_claim_ids": []string{}, "actual_relationship_ids": relationshipIDs, "actual_property_claim_ids": propertyIDs, "evidence_locator_ids": locatorIDs, "evidence_fact_ids": evidenceFactIDs, "applicability_profile_binding": binding, "derivation_binding": map[string]interface{}{"classifier_profile_id": classifierReference.id, "classifier_profile_version": classifierReference.version, "classifier_profile_sha256": classifierReference.digest, "exact_input_locator_ids": locatorIDs, "exact_input_fact_ids": evidenceFactIDs}, "source_bytes_present": false,
		})
	}
	rows = append(rows,
		map[string]interface{}{"row_kind": "validation_summary", "operation_applicability_count": 2, "persisted_optional_absence_row_count": 0, "persisted_inapplicable_absence_row_count": 0, "candidate_subject_count": len(fixturePlanSymbols(fixture)) + len(fixturePlanRelationships(fixture)), "actual_relationship_fact_count": len(fixturePlanRelationships(fixture)), "actual_property_fact_count": len(fixturePlanProperties(fixture)), "sparse_required_gap_count": len(fixturePlanGaps(fixture)), "captured_operation_kind_counts": []interface{}{map[string]interface{}{"operation_kind": "event_driven_write_operation", "count": 1}, map[string]interface{}{"operation_kind": "request_response_read_operation", "count": 1}}, "subject_set_root_sha256": fixture.summary().SubjectSetRootSHA256, "fact_set_root_sha256": fixture.summary().FactSetRootSHA256, "gap_set_root_sha256": fixture.summary().GapSetRootSHA256, "source_bytes_present": false, "result": "candidate_complete_operation_applicability"},
	)
	writeJSONL(t, path, rows)
}

func fixtureDependencySemanticRows(t *testing.T, path string) dependencySemanticRows {
	t.Helper()
	_, rows := fixtureDependencySemanticArtifact(t, path)
	return rows
}

func fixtureDependencySemanticArtifact(t *testing.T, path string) (artifactInput, dependencySemanticRows) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	input := artifactInput{Path: path, SHA256: sha256Hex(raw), Raw: raw, Structured: true}
	rows, err := parseDependencySemanticRows(input)
	if err != nil {
		t.Fatal(err)
	}
	manifestRows := rows.byKind["artifact_manifest"]
	if len(manifestRows) != 1 {
		t.Fatalf("fixture dependency %s has %d artifact manifests, want 1", path, len(manifestRows))
	}
	input.Manifest = manifestRows[0].data
	return input, rows
}

func fixtureGapDerivationBinding(t *testing.T, applicabilityPath string, gap graphGap) json.RawMessage {
	t.Helper()
	input, rows := fixtureDependencySemanticArtifact(t, applicabilityPath)
	var match dependencySemanticRow
	matches := 0
	for _, rowKind := range []string{"relationship_applicability_rule", "property_family_applicability_rule", "claim_applicability_rule"} {
		for _, row := range rows.byKind[rowKind] {
			ruleID, ok := semanticString(row.data, "applicability_rule_id")
			if ok && ruleID == gap.ApplicabilityRuleID {
				match = row
				matches++
			}
		}
	}
	if matches != 1 {
		t.Fatalf("fixture applicability rule %q resolved %d rows, want 1", gap.ApplicabilityRuleID, matches)
	}
	fact, err := typedGraphPredecessorFactForRow(typedGraphArtifactRoleAPIApplicability, input, match, "applicability_rule_id", gap.ApplicabilityRuleID, typedGraphFactGraphApplicabilityRule, -1)
	if err != nil {
		t.Fatal(err)
	}
	targetIdentity, err := graphGapDerivationTargetIdentity(gap)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := typedGraphPredecessorDerivationBindingFor(gap.RowKind, targetIdentity, []typedGraphPredecessorFact{fact})
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func fixtureSourceOperationPredecessorBinding(t *testing.T, rows dependencySemanticRows, semanticKey string) operationClassifierInputBinding {
	t.Helper()
	matches := make([]dependencySemanticRow, 0, 1)
	for _, row := range rows.byKind["api_operation"] {
		sourceSymbol, ok := semanticString(row.data, "source_symbol")
		identity, err := parseSourceOperationIdentity(row.data)
		if !ok || err != nil {
			t.Fatalf("fixture source operation predecessor is incomplete: %v", err)
		}
		candidate, err := sourceOperationSemanticKey(sourceSymbol, identity)
		if err != nil {
			t.Fatal(err)
		}
		if candidate == semanticKey {
			matches = append(matches, row)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("fixture source operation predecessor %q resolved %d rows", semanticKey, len(matches))
	}
	return operationClassifierInputBinding{
		artifactRole: operationClassifierSourceArtifactRole, artifactSHA256: sha256Hex(rows.raw), rowKind: "api_operation", rowIdentity: semanticKey, rowSHA256: sha256Hex(matches[0].raw), factLocatorKind: "resource_access_ordinal", factOrdinal: 0,
	}
}

func fixtureProtocolOperationPredecessorBinding(t *testing.T, rows dependencySemanticRows, sourceSymbol, resourceSourceSymbol string, sourceIdentity map[string]interface{}) operationClassifierInputBinding {
	t.Helper()
	matches := make([]dependencySemanticRow, 0, 1)
	for _, row := range rows.byKind["operation_classifier_fact"] {
		fact, err := parseProtocolOperationClassifierPredecessor(rows, row)
		if err != nil {
			t.Fatal(err)
		}
		equal, err := equalCanonicalSourceOperationIdentities(fact.sourceOperationIdentity, sourceIdentity)
		if err != nil {
			t.Fatal(err)
		}
		if equal && fact.sourceSymbol == sourceSymbol && fact.resourceSourceSymbol == resourceSourceSymbol {
			matches = append(matches, row)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("fixture protocol operation predecessor resolved %d rows", len(matches))
	}
	rowIdentity, _ := semanticString(matches[0].data, "operation_classifier_fact_id")
	return operationClassifierInputBinding{
		artifactRole: operationClassifierProtocolArtifactRole, artifactSHA256: sha256Hex(rows.raw), rowKind: "operation_classifier_fact", rowIdentity: rowIdentity, rowSHA256: sha256Hex(matches[0].raw), factLocatorKind: "whole_row", factOrdinal: -1,
	}
}

func fixtureOperationResourceAccess(t *testing.T, operationID, resourceSourceSymbol, resourceID, resourceSemanticIdentity, relationshipLabel, accessSemantics string, locatorIDs, evidenceFactIDs []string, predecessor operationClassifierInputBinding) map[string]interface{} {
	t.Helper()
	orderedLocators := append([]string(nil), locatorIDs...)
	sort.Strings(orderedLocators)
	orderedFacts := append([]string(nil), evidenceFactIDs...)
	sort.Strings(orderedFacts)
	identityParts := []string{
		operationID,
		resourceSourceSymbol,
		resourceID,
		resourceSemanticIdentity,
		relationshipLabel,
		accessSemantics,
		predecessor.artifactRole,
		predecessor.artifactSHA256,
		predecessor.rowKind,
		predecessor.rowIdentity,
		predecessor.rowSHA256,
		predecessor.factLocatorKind,
		fmt.Sprintf("%d", predecessor.factOrdinal),
	}
	identityParts = append(identityParts, orderedLocators...)
	identityParts = append(identityParts, orderedFacts...)
	locator := map[string]interface{}{"locator_kind": predecessor.factLocatorKind}
	if predecessor.factLocatorKind == "resource_access_ordinal" {
		locator["ordinal"] = predecessor.factOrdinal
	}
	return map[string]interface{}{
		"resource_access_id":               stableID("opaccess", lengthPrefixedIdentityKey(identityParts...)),
		"source_symbol":                    resourceSourceSymbol,
		"resource_candidate_api_symbol_id": resourceID,
		"resource_semantic_identity":       resourceSemanticIdentity,
		"relationship_label":               relationshipLabel,
		"access_semantics":                 accessSemantics,
		"evidence_locator_ids":             orderedLocators,
		"evidence_fact_ids":                orderedFacts,
		"predecessor_fact_binding": map[string]interface{}{
			"artifact_role":   predecessor.artifactRole,
			"artifact_sha256": predecessor.artifactSHA256,
			"row_kind":        predecessor.rowKind,
			"row_identity":    predecessor.rowIdentity,
			"row_sha256":      predecessor.rowSHA256,
			"fact_locator":    locator,
		},
	}
}

func buildFixturePlanStageSchema(t *testing.T, fixture *testFixture) []byte {
	t.Helper()
	dir := filepath.Dir(fixture.planPath)
	sourcePath := filepath.Join(dir, "plan-stage-schema-source.jsonl")
	schemaPath := filepath.Join(dir, "plan-stage.schema.json")
	prototypeGap := &graphGap{
		RowKind: "candidate_graph_gap", GapClass: "required_api_relationship_incomplete",
		BlockedSubjectKind: "api_symbol_object", BlockedSubjectID: fixture.sourceOperationID, BlockedClaimKind: "api_relationship", BlockedClaimID: "capi_rel_fixture_schema_prototype",
		Disposition: "fail_closed", ApplicabilityProfileID: fixture.applicability.ProfileID, ApplicabilityProfileVersion: fixture.applicability.ProfileVersion, ApplicabilityProfileSHA256: fixture.applicability.ProfileSHA256, ApplicabilityRuleID: fixture.ruleByLabel["operation_reads_resource"],
		EvidenceLocatorIDs: []string{fixture.locatorID}, GapProofBinding: fixtureGapProof(fixture.locatorID),
	}
	prototypeGap.DerivationBinding = fixtureGapDerivationBinding(t, fixture.dependencyByRole["api_graph_applicability"], *prototypeGap)
	prototypeIdentity, err := candidateGraphGapIdentityKey(*prototypeGap)
	if err != nil {
		t.Fatal(err)
	}
	prototypeGap.ID = stableID("capi_gap", prototypeIdentity)
	rows := append([]interface{}{}, fixture.planRows[:len(fixture.planRows)-1]...)
	rows = append(rows, prototypeGap, fixture.summary())
	writeJSONL(t, sourcePath, rows)
	writeFixtureExactJSONLSchema(t, sourcePath, schemaPath, "urn:test:stage-contract:fixture_api_graph_plan:schema")
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func resealFixturePlanSchemaForReviewedMutation(t *testing.T, fixture *testFixture) {
	t.Helper()
	fixture.planStageSchemaRaw = buildFixturePlanStageSchema(t, fixture)
}

func fixturePlanSymbol(t *testing.T, fixture *testFixture, id string) *apiSymbol {
	t.Helper()
	for _, row := range fixture.planRows {
		if symbol, ok := row.(*apiSymbol); ok && symbol.ID == id {
			return symbol
		}
	}
	t.Fatalf("fixture plan has no API symbol %q", id)
	return nil
}

func fixturePlanSymbols(fixture *testFixture) map[string]*apiSymbol {
	result := map[string]*apiSymbol{}
	for _, row := range fixture.planRows {
		if symbol, ok := row.(*apiSymbol); ok {
			result[symbol.ID] = symbol
		}
	}
	return result
}

func fixturePlanRelationships(fixture *testFixture) map[string]*apiRelationship {
	result := map[string]*apiRelationship{}
	for _, row := range fixture.planRows {
		if relationship, ok := row.(*apiRelationship); ok {
			result[relationship.ID] = relationship
		}
	}
	return result
}

func fixturePlanProperties(fixture *testFixture) map[string]*apiPropertyClaim {
	result := map[string]*apiPropertyClaim{}
	for _, row := range fixture.planRows {
		if property, ok := row.(*apiPropertyClaim); ok {
			result[property.ID] = property
		}
	}
	return result
}

func fixturePlanGaps(fixture *testFixture) map[string]*graphGap {
	result := map[string]*graphGap{}
	for _, row := range fixture.planRows {
		if gap, ok := row.(*graphGap); ok {
			result[gap.ID] = gap
		}
	}
	return result
}

func fixtureIncidentRelationshipIDs(fixture *testFixture, operationID string) []string {
	result := make([]string, 0)
	for id, relationship := range fixturePlanRelationships(fixture) {
		if relationship.SourceID == operationID || relationship.TargetID == operationID {
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result
}

func fixtureOperationPropertyIDs(fixture *testFixture, operationID string) []string {
	result := make([]string, 0)
	for id, property := range fixturePlanProperties(fixture) {
		if property.SubjectKind == "api_symbol_object" && property.SubjectID == operationID {
			result = append(result, id)
		}
	}
	sort.Strings(result)
	return result
}

func resealFixtureGraph(t *testing.T, fixture *testFixture) {
	t.Helper()
	recomputeFixtureGraphMetadata(t, fixture)
	summary := fixture.summary()

	operationPath := fixtureSemanticArtifactPath(fixture, dependencySemanticRoleOperationApplicability)
	_, operationClassifierReference := testOperationClassifierProfile(t)
	writeFixtureOperationApplicability(t, fixture, operationPath, operationClassifierReference)
	operationSchema := fixture.schemaByRole[dependencySemanticRoleOperationApplicability]
	writeFixtureExactJSONLSchema(t, operationPath, operationSchema, "urn:fixture:provider-documentation:"+dependencySemanticRoleOperationApplicability+":schema")
	fixture.manifest().OperationApplicabilityProfileSHA256 = fileSHA256(t, operationPath)
	profilePath := fixture.dependencyByRole["dependency_semantic_validation_profile"]
	mutateJSONLMatchingRow(t, profilePath, "artifact_schema_binding", semanticStringFieldEquals("role", dependencySemanticRoleOperationApplicability), func(row map[string]interface{}) {
		row["artifact_raw_sha256"] = fileSHA256(t, operationPath)
		row["schema_raw_sha256"] = fileSHA256(t, operationSchema)
	})
	fixture.manifest().DependencySemanticValidation.Profile.RawSHA256 = fileSHA256(t, profilePath)
	writeJSONL(t, fixture.planPath, fixture.planRows)
	assertFixtureGraphRootsStable(t, fixture, summary.SubjectSetRootSHA256, summary.FactSetRootSHA256, summary.GapSetRootSHA256)
}

func recomputeFixtureGraphMetadata(t *testing.T, fixture *testFixture) {
	t.Helper()
	writeJSONL(t, fixture.planPath, fixture.planRows)
	raw, err := os.ReadFile(fixture.planPath)
	if err != nil {
		t.Fatal(err)
	}
	sets, err := deriveStageGraphSets(raw, verifyGraphRowDispositions())
	if err != nil {
		t.Fatal(err)
	}
	summary := fixture.summary()
	summary.CandidateEvidenceLocatorCount = len(fixtureLocators(fixture))
	summary.CandidateAPISymbolCount = len(fixturePlanSymbols(fixture))
	summary.CandidateAPIRelationshipCount = len(fixturePlanRelationships(fixture))
	summary.CandidateAPIPropertyClaimCount = len(fixturePlanProperties(fixture))
	summary.CandidateGraphGapCount = len(fixturePlanGaps(fixture))
	materializedRoles := map[string]struct{}{}
	for _, symbol := range fixturePlanSymbols(fixture) {
		materializedRoles[symbol.Role] = struct{}{}
	}
	materializedLabels := map[string]struct{}{}
	for _, relationship := range fixturePlanRelationships(fixture) {
		materializedLabels[relationship.Label] = struct{}{}
	}
	materializedFamilies := map[string]struct{}{}
	for _, property := range fixturePlanProperties(fixture) {
		materializedFamilies[property.Family] = struct{}{}
	}
	summary.APIElementRolesMaterialized = len(materializedRoles)
	summary.APIRelationshipLabelsMaterialized = len(materializedLabels)
	summary.APIPropertyFamiliesMaterialized = len(materializedFamilies)
	summary.CandidateSubjectCount = int(sets["subject"].Count)
	summary.SubjectSetRootSHA256 = sets["subject"].RootSHA256
	summary.FactSetRootSHA256 = sets["fact"].RootSHA256
	summary.GapSetRootSHA256 = sets["gap"].RootSHA256
	writeJSONL(t, fixture.planPath, fixture.planRows)
}

func assertFixtureGraphRootsStable(t *testing.T, fixture *testFixture, subjectRoot, factRoot, gapRoot string) {
	t.Helper()
	raw, err := os.ReadFile(fixture.planPath)
	if err != nil {
		t.Fatal(err)
	}
	sets, err := deriveStageGraphSets(raw, verifyGraphRowDispositions())
	if err != nil {
		t.Fatal(err)
	}
	if sets["subject"].RootSHA256 != subjectRoot || sets["fact"].RootSHA256 != factRoot || sets["gap"].RootSHA256 != gapRoot {
		t.Fatalf("fixture metadata reseal changed graph roots: got subject=%s fact=%s gap=%s; want subject=%s fact=%s gap=%s", sets["subject"].RootSHA256, sets["fact"].RootSHA256, sets["gap"].RootSHA256, subjectRoot, factRoot, gapRoot)
	}
}

func verifyGraphRowDispositions() []stageGraphRowDisposition {
	return []stageGraphRowDisposition{
		{RowKind: "artifact_manifest", SetKinds: []string{"metadata"}},
		{RowKind: "candidate_api_property_claim", SetKinds: []string{"fact"}},
		{RowKind: "candidate_api_relationship", SetKinds: []string{"fact", "subject"}},
		{RowKind: "candidate_api_symbol", SetKinds: []string{"subject"}},
		{RowKind: "candidate_evidence_locator", SetKinds: []string{"metadata"}},
		{RowKind: "candidate_graph_gap", SetKinds: []string{"gap"}},
		{RowKind: "validation_summary", SetKinds: []string{"metadata"}},
	}
}

func newVerifyGraphStageSelection(t *testing.T, fixture *testFixture) ([]byte, StageCompileInputs) {
	t.Helper()
	lineage := newStageContractFixture(t)
	return newVerifyGraphStageSelectionForLineage(t, fixture, lineage.semanticSummary, lineage.semanticReceipt, lineage.semanticRequest.inputs.EvidenceBodies)
}

func newVerifyGraphStageSelectionForLineage(t *testing.T, fixture *testFixture, semanticSummary StageReceiptSummary, semanticReceipt []byte, evidenceBodies []StageEvidenceBody) ([]byte, StageCompileInputs) {
	t.Helper()
	planRaw, err := os.ReadFile(fixture.planPath)
	if err != nil {
		t.Fatal(err)
	}
	planTarget := testStageTarget{
		identity: stageArtifactIdentity{Role: "api_graph_plan", ID: "fixture_api_graph_plan", Version: "1", RawSHA256: sha256Hex(planRaw)}, raw: planRaw,
		schemaPin: immutableStageArtifactPin{Role: "api_graph_plan_schema", ID: "urn:test:stage-contract:fixture_api_graph_plan:schema", Version: "1", RawSHA256: sha256Hex(fixture.planStageSchemaRaw), AuthorityClass: "canonical"}, schemaRaw: fixture.planStageSchemaRaw,
	}
	dependencyTargets := make([]testStageTarget, 0, len(dependencySemanticRequiredRoles)+1)
	semanticProfilePin := fixture.manifest().DependencySemanticValidation.Profile
	semanticProfileRaw, err := os.ReadFile(fixture.dependencyByRole["dependency_semantic_validation_profile"])
	if err != nil {
		t.Fatal(err)
	}
	semanticProfileSchemaPin := fixture.manifest().DependencySemanticValidation.Schema
	semanticProfileSchemaRaw, err := os.ReadFile(fixture.dependencyByRole["dependency_semantic_validation_profile_schema"])
	if err != nil {
		t.Fatal(err)
	}
	dependencyTargets = append(dependencyTargets, testStageTarget{
		identity:  stageArtifactIdentity{Role: semanticProfilePin.Role, ID: semanticProfilePin.ID, Version: semanticProfilePin.Version, RawSHA256: sha256Hex(semanticProfileRaw)},
		raw:       semanticProfileRaw,
		schemaPin: immutableStageArtifactPin{Role: semanticProfileSchemaPin.Role, ID: semanticProfileSchemaPin.ID, Version: semanticProfileSchemaPin.Version, RawSHA256: sha256Hex(semanticProfileSchemaRaw), AuthorityClass: "canonical"},
		schemaRaw: semanticProfileSchemaRaw,
	})
	for _, role := range dependencySemanticRequiredRoles {
		path := fixtureSemanticArtifactPath(fixture, role)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		coordinate, ok := fixture.artifactCoordinateByRole[role]
		if !ok {
			t.Fatalf("fixture has no frozen artifact coordinate for semantic role %q", role)
		}
		schemaID := "urn:fixture:provider-documentation:" + role + ":schema"
		schemaRaw, err := os.ReadFile(fixture.schemaByRole[role])
		if err != nil {
			t.Fatal(err)
		}
		target := testStageTarget{
			identity:  stageArtifactIdentity{Role: coordinate.Role, ID: coordinate.ID, Version: coordinate.Version, RawSHA256: sha256Hex(raw)},
			raw:       raw,
			schemaPin: immutableStageArtifactPin{Role: role + "_schema", ID: schemaID, Version: "1", RawSHA256: sha256Hex(schemaRaw), AuthorityClass: "canonical"},
			schemaRaw: schemaRaw,
		}
		dependencyTargets = append(dependencyTargets, target)
	}
	sort.Slice(dependencyTargets, func(i, j int) bool {
		return compareStageMaterialCoordinates(stageCoordinateForIdentity(dependencyTargets[i].identity), stageCoordinateForIdentity(dependencyTargets[j].identity)) < 0
	})
	dispositions := verifyGraphRowDispositions()
	validationTargets := append([]testStageTarget{planTarget}, dependencyTargets...)
	graphValidation, graphMaterials := newStageValidation(t, stageGraphCompile, validationTargets, dispositions)
	sets, err := deriveStageGraphSets(planRaw, dispositions)
	if err != nil {
		t.Fatal(err)
	}
	request := graphCompileStageRequest{
		RequestKind: stageRequestKind, RequestVersion: stageContractVersion, StageKind: stageGraphCompile,
		ExtractionReceipts: []StageReceiptReference{stageRef(semanticSummary)}, StageValidation: graphValidation,
		DependencyArtifacts: fixtureStageTargetIdentities(dependencyTargets), Plan: planTarget.identity, Subjects: sets["subject"], Facts: sets["fact"], Gaps: sets["gap"],
	}
	inputs := StageCompileInputs{
		PredecessorReceipts: [][]byte{bytes.Clone(semanticReceipt)},
		Materials:           graphMaterials,
		EvidenceBodies:      cloneStageEvidenceBodies(evidenceBodies),
	}
	return mustStageJSON(t, request), inputs
}

func fixtureStageTargetIdentities(targets []testStageTarget) []stageArtifactIdentity {
	identities := make([]stageArtifactIdentity, len(targets))
	for index := range targets {
		identities[index] = targets[index].identity
	}
	return identities
}

func writeFixtureArtifactValidationEnvelopeSchema(t *testing.T, path, schemaID string) {
	t.Helper()
	stringProperty := func() map[string]interface{} { return map[string]interface{}{"type": "string", "minLength": 1} }
	digestProperty := func() map[string]interface{} {
		return map[string]interface{}{"type": "string", "pattern": "^[0-9a-f]{64}$"}
	}
	closedObject := func(required []string, properties map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"type": "object", "required": required, "additionalProperties": false, "properties": properties}
	}
	schema := map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     schemaID,
		"oneOf": []interface{}{
			closedObject(
				[]string{"row_kind", "artifact", "artifact_version", "status", "profile_id", "profile_version", "binding_count", "canonical_admission_authorized"},
				map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "artifact_manifest"}, "artifact": map[string]interface{}{"const": dependencySemanticValidationProfileArtifact}, "artifact_version": stringProperty(), "status": map[string]interface{}{"const": dependencySemanticValidationProfileStatus}, "profile_id": stringProperty(), "profile_version": stringProperty(), "binding_count": map[string]interface{}{"type": "integer", "minimum": 1}, "canonical_admission_authorized": map[string]interface{}{"const": false},
				},
			),
			closedObject(
				[]string{"row_kind", "role", "artifact_id", "artifact_version", "artifact_raw_sha256", "schema_role", "schema_id", "schema_version", "schema_raw_sha256"},
				map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "artifact_schema_binding"}, "role": stringProperty(), "artifact_id": stringProperty(), "artifact_version": stringProperty(), "artifact_raw_sha256": digestProperty(), "schema_role": stringProperty(), "schema_id": stringProperty(), "schema_version": stringProperty(), "schema_raw_sha256": digestProperty(),
				},
			),
			closedObject(
				[]string{"row_kind", "binding_count", "artifact_count", "schema_count", "canonical_admission_authorized", "result"},
				map[string]interface{}{
					"row_kind": map[string]interface{}{"const": "validation_summary"}, "binding_count": map[string]interface{}{"type": "integer", "minimum": 1}, "artifact_count": map[string]interface{}{"type": "integer", "minimum": 1}, "schema_count": map[string]interface{}{"type": "integer", "minimum": 1}, "canonical_admission_authorized": map[string]interface{}{"const": false}, "result": map[string]interface{}{"const": dependencySemanticValidationProfileResult},
				},
			),
		},
	}
	writeFixtureJSONDocument(t, path, schema)
}

func writeFixtureArtifactValidationProfile(t *testing.T, path, profileID string, bindings []dependencySemanticProfileArtifactBinding) {
	t.Helper()
	if len(bindings) == 0 {
		t.Fatal("fixture artifact validation profile requires a nonempty binding roster")
	}
	rows := []interface{}{map[string]interface{}{
		"row_kind": "artifact_manifest", "artifact": dependencySemanticValidationProfileArtifact, "artifact_version": artifactValidationProfileEnvelopeVersion, "status": dependencySemanticValidationProfileStatus, "profile_id": profileID, "profile_version": "1", "binding_count": len(bindings), "canonical_admission_authorized": false,
	}}
	artifactCoordinates := map[string]struct{}{}
	schemaCoordinates := map[string]struct{}{}
	for _, binding := range bindings {
		rows = append(rows, map[string]interface{}{
			"row_kind": "artifact_schema_binding", "role": binding.Role, "artifact_id": binding.ArtifactID, "artifact_version": binding.ArtifactVersion, "artifact_raw_sha256": binding.ArtifactRawSHA256, "schema_role": binding.SchemaRole, "schema_id": binding.SchemaID, "schema_version": binding.SchemaVersion, "schema_raw_sha256": binding.SchemaRawSHA256,
		})
		artifactCoordinates[lengthPrefixedIdentityKey(binding.ArtifactID, binding.ArtifactVersion)] = struct{}{}
		schemaCoordinates[lengthPrefixedIdentityKey(binding.SchemaID, binding.SchemaVersion)] = struct{}{}
	}
	rows = append(rows, map[string]interface{}{
		"row_kind": "validation_summary", "binding_count": len(bindings), "artifact_count": len(artifactCoordinates), "schema_count": len(schemaCoordinates), "canonical_admission_authorized": false, "result": dependencySemanticValidationProfileResult,
	})
	writeJSONL(t, path, rows)
}

func fixtureStructuredArtifactIdentity(t *testing.T, path string) (string, string) {
	t.Helper()
	input, err := readArtifactInput(path)
	if err != nil {
		t.Fatal(err)
	}
	artifact, artifactOK := manifestString(input.Manifest, "artifact")
	version, versionOK := manifestString(input.Manifest, "artifact_version")
	if !input.Structured || !artifactOK || !versionOK {
		t.Fatalf("fixture semantic artifact %q has no exact structured artifact identity", path)
	}
	return artifact, version
}

func writeFixtureExactJSONLSchema(t *testing.T, artifactPath, schemaPath, schemaID string) {
	t.Helper()
	raw, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	rowsByKind := map[string][]interface{}{}
	for lineIndex, rawLine := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			continue
		}
		row, err := decodeJSONObject(line)
		if err != nil {
			t.Fatalf("fixture schema source %q line %d: %v", artifactPath, lineIndex+1, err)
		}
		rowKind, ok := manifestString(row, "row_kind")
		if !ok || rowKind == "" {
			t.Fatalf("fixture schema source %q line %d has no row_kind", artifactPath, lineIndex+1)
		}
		rowsByKind[rowKind] = append(rowsByKind[rowKind], row)
	}
	if len(rowsByKind) == 0 {
		t.Fatalf("fixture schema source %q has no JSONL rows", artifactPath)
	}
	kinds := sortedSetKeys(stringMapKeysAsSet(rowsByKind))
	branches := make([]interface{}, 0, len(kinds))
	for _, rowKind := range kinds {
		branch, ok := fixtureSchemaForValues(t, rowsByKind[rowKind]).(map[string]interface{})
		if !ok {
			t.Fatalf("fixture schema row_kind %q did not produce one closed object branch", rowKind)
		}
		properties := branch["properties"].(map[string]interface{})
		properties["row_kind"] = map[string]interface{}{"const": rowKind}
		required := branch["required"].([]string)
		if _, present := stringSliceSet(required)["row_kind"]; !present {
			required = append(required, "row_kind")
			sort.Strings(required)
			branch["required"] = required
		}
		branches = append(branches, branch)
	}
	writeFixtureJSONDocument(t, schemaPath, map[string]interface{}{"$schema": validationProfileDraft202012, "$id": schemaID, "oneOf": branches})
}

func fixtureSchemaForObject(t *testing.T, object map[string]interface{}, rootRow bool) map[string]interface{} {
	t.Helper()
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	required := make([]string, 0, len(keys))
	properties := make(map[string]interface{}, len(keys))
	for _, key := range keys {
		required = append(required, key)
		if rootRow && key == "row_kind" {
			value, ok := object[key].(string)
			if !ok || value == "" {
				t.Fatalf("fixture row_kind is not a nonempty string")
			}
			properties[key] = map[string]interface{}{"const": value}
			continue
		}
		properties[key] = fixtureSchemaForValue(t, object[key])
	}
	return map[string]interface{}{"type": "object", "required": required, "additionalProperties": false, "properties": properties}
}

func fixtureSchemaForValue(t *testing.T, value interface{}) interface{} {
	t.Helper()
	switch typed := value.(type) {
	case nil:
		return map[string]interface{}{"type": "null"}
	case string:
		return map[string]interface{}{"type": "string"}
	case bool:
		return map[string]interface{}{"type": "boolean"}
	case json.Number:
		if _, err := typed.Int64(); err != nil {
			t.Fatalf("fixture schemas admit exact integer JSON numbers only, got %q", typed.String())
		}
		return map[string]interface{}{"type": "integer"}
	case map[string]interface{}:
		return fixtureSchemaForObject(t, typed, false)
	case []interface{}:
		return fixtureSchemaForArrayValues(t, []interface{}{typed})
	default:
		t.Fatalf("fixture schema generator does not support %T", value)
		return nil
	}
}

// fixtureSchemaForValues produces one closed, non-composed shape for values
// that occupy the same structural position. The production materializer
// intentionally accepts no nested oneOf/anyOf dialect, so heterogeneous object
// arrays use a closed union of named properties with only common fields
// required rather than a composed items schema.
func fixtureSchemaForValues(t *testing.T, values []interface{}) interface{} {
	t.Helper()
	if len(values) == 0 {
		t.Fatal("fixture schema value roster is empty")
	}
	valueKind := func(value interface{}) string {
		switch value.(type) {
		case nil:
			return "null"
		case string:
			return "string"
		case bool:
			return "boolean"
		case json.Number:
			return "number"
		case map[string]interface{}:
			return "object"
		case []interface{}:
			return "array"
		default:
			return "unsupported"
		}
	}
	firstKind := valueKind(values[0])
	mixed := false
	for _, value := range values[1:] {
		if valueKind(value) != firstKind {
			mixed = true
			break
		}
	}
	if mixed {
		enumByCanonical := map[string]interface{}{}
		for _, value := range values {
			kind := valueKind(value)
			if kind == "object" || kind == "array" || kind == "unsupported" {
				t.Fatalf("fixture schema values require unsupported composed %s/%s union", firstKind, kind)
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			enumByCanonical[string(raw)] = value
		}
		keys := sortedSetKeys(stringMapKeysAsSet(enumByCanonical))
		enum := make([]interface{}, len(keys))
		for index, key := range keys {
			enum[index] = enumByCanonical[key]
		}
		return map[string]interface{}{"enum": enum}
	}
	switch values[0].(type) {
	case string:
		for _, value := range values {
			if _, ok := value.(string); !ok {
				t.Fatalf("fixture schema values mix string with %T", value)
			}
		}
		return map[string]interface{}{"type": "string"}
	case bool:
		for _, value := range values {
			if _, ok := value.(bool); !ok {
				t.Fatalf("fixture schema values mix boolean with %T", value)
			}
		}
		return map[string]interface{}{"type": "boolean"}
	case json.Number:
		for _, value := range values {
			number, ok := value.(json.Number)
			if !ok {
				t.Fatalf("fixture schema values mix number with %T", value)
			}
			if _, err := number.Int64(); err != nil {
				t.Fatalf("fixture schemas admit exact integer JSON numbers only, got %q", number.String())
			}
		}
		return map[string]interface{}{"type": "integer"}
	case map[string]interface{}:
		objects := make([]map[string]interface{}, len(values))
		allKeys := map[string]struct{}{}
		presence := map[string]int{}
		fieldValues := map[string][]interface{}{}
		for index, value := range values {
			object, ok := value.(map[string]interface{})
			if !ok {
				t.Fatalf("fixture schema values mix object with %T", value)
			}
			objects[index] = object
			for key, fieldValue := range object {
				allKeys[key] = struct{}{}
				presence[key]++
				fieldValues[key] = append(fieldValues[key], fieldValue)
			}
		}
		keys := sortedSetKeys(allKeys)
		required := make([]string, 0, len(keys))
		properties := make(map[string]interface{}, len(keys))
		for _, key := range keys {
			if presence[key] == len(objects) {
				required = append(required, key)
			}
			properties[key] = fixtureSchemaForValues(t, fieldValues[key])
		}
		return map[string]interface{}{"type": "object", "required": required, "additionalProperties": false, "properties": properties}
	case []interface{}:
		arrays := make([]interface{}, len(values))
		for index, value := range values {
			array, ok := value.([]interface{})
			if !ok {
				t.Fatalf("fixture schema values mix array with %T", value)
			}
			arrays[index] = array
		}
		return fixtureSchemaForArrayValues(t, arrays)
	case nil:
		for _, value := range values {
			if value != nil {
				t.Fatalf("fixture schema values mix null with %T", value)
			}
		}
		return map[string]interface{}{"type": "null"}
	default:
		t.Fatalf("fixture schema generator does not support common value type %T", values[0])
		return nil
	}
}

func fixtureSchemaForArrayValues(t *testing.T, rawArrays []interface{}) map[string]interface{} {
	t.Helper()
	items := make([]interface{}, 0)
	for _, value := range rawArrays {
		array, ok := value.([]interface{})
		if !ok {
			t.Fatalf("fixture array schema received %T", value)
		}
		items = append(items, array...)
	}
	result := map[string]interface{}{"type": "array"}
	if len(items) == 0 {
		result["items"] = false
		result["maxItems"] = 0
		return result
	}
	result["items"] = fixtureSchemaForValues(t, items)
	return result
}

func writeFixtureJSONDocument(t *testing.T, path string, value interface{}) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeJSONL(t *testing.T, path string, rows []interface{}) {
	t.Helper()
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	for _, row := range rows {
		if err := encoder.Encode(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, output.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustJSONRaw(t *testing.T, value interface{}) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutateJSONLRow(t *testing.T, path, rowKind string, mutate func(map[string]interface{})) {
	mutateJSONLMatchingRow(t, path, rowKind, func(map[string]interface{}) bool { return true }, mutate)
}

func mutateJSONLMatchingRow(t *testing.T, path, rowKind string, matches func(map[string]interface{}) bool, mutate func(map[string]interface{})) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	rows := make([]interface{}, 0, len(lines))
	mutated := 0
	for _, line := range lines {
		row, err := decodeJSONObject(line)
		if err != nil {
			t.Fatal(err)
		}
		if value, _ := manifestString(row, "row_kind"); value == rowKind && matches(row) {
			mutate(row)
			mutated++
		}
		rows = append(rows, row)
	}
	if mutated != 1 {
		t.Fatalf("%s has %d %s rows, want exactly 1", path, mutated, rowKind)
	}
	writeJSONL(t, path, rows)
}

func removeJSONLMatchingRow(t *testing.T, path, rowKind string, matches func(map[string]interface{}) bool) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	rows := make([]interface{}, 0, len(lines)-1)
	removed := 0
	for _, line := range lines {
		row, err := decodeJSONObject(line)
		if err != nil {
			t.Fatal(err)
		}
		if value, _ := manifestString(row, "row_kind"); value == rowKind && matches(row) {
			removed++
			continue
		}
		rows = append(rows, row)
	}
	if removed != 1 {
		t.Fatalf("%s removed %d %s rows, want exactly 1", path, removed, rowKind)
	}
	writeJSONL(t, path, rows)
}

func replaceFileBytes(t *testing.T, path string, old, replacement []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, old) {
		t.Fatalf("%q does not contain replacement target %q", path, old)
	}
	raw = bytes.Replace(raw, old, replacement, 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func removeJSONLRowField(t *testing.T, path, rowKind, field string) {
	t.Helper()
	mutateJSONLRow(t, path, rowKind, func(row map[string]interface{}) {
		if _, ok := row[field]; !ok {
			t.Fatalf("%s %s row has no field %s", path, rowKind, field)
		}
		delete(row, field)
	})
}

func replaceString(values []string, old, replacement string) []string {
	out := append([]string(nil), values...)
	for i := range out {
		if out[i] == old {
			out[i] = replacement
		}
	}
	return out
}

func stringInterfaces(values []string) []interface{} {
	result := make([]interface{}, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func removeSourceOperationReadWriteCoverage(t *testing.T, fixture *testFixture) {
	t.Helper()
	filtered := make([]interface{}, 0, len(fixture.planRows)-1)
	removed := 0
	for _, candidate := range fixture.planRows {
		relationship, ok := candidate.(*apiRelationship)
		if ok && relationship.SourceID == fixture.sourceOperationID && (relationship.Label == "operation_reads_resource" || relationship.Label == "operation_writes_resource") {
			removed++
			continue
		}
		filtered = append(filtered, candidate)
	}
	if removed != 1 {
		t.Fatalf("removed source-operation coverage relationships=%d, want 1", removed)
	}
	fixture.planRows = filtered
	fixture.summary().CandidateAPIRelationshipCount--
}

func rebindSourceContract(t *testing.T, fixture *testFixture) {
	t.Helper()
	oldSourceDigest := fixture.manifest().SourceContractIndexSHA256
	newSourceDigest := fileSHA256(t, fixture.dependencyByRole["source_contract"])
	if oldSourceDigest == newSourceDigest {
		t.Fatal("source-contract test mutation did not change its digest")
	}

	surfacePath := fixture.dependencyByRole["surface_disposition"]
	oldSurfaceDigest := fileSHA256(t, surfacePath)
	replaceFileDigest(t, surfacePath, oldSourceDigest, newSourceDigest)
	newSurfaceDigest := fileSHA256(t, surfacePath)

	fieldMapPath := fixture.dependencyByRole["field_mapping"]
	replaceFileDigest(t, fieldMapPath, oldSourceDigest, newSourceDigest)
	replaceFileDigest(t, fieldMapPath, oldSurfaceDigest, newSurfaceDigest)

	fixture.manifest().SourceContractIndexSHA256 = newSourceDigest
	fixture.manifest().FieldMappingCandidateSHA256 = fileSHA256(t, fieldMapPath)
	rebindFixtureSourceRelationship(t, fixture)
	rebindDependencySemanticRoles(t, fixture, dependencySemanticRoleSourceContract, dependencySemanticRoleSurfaceDisposition, dependencySemanticRoleFieldMapping)
	resealFixtureGraph(t, fixture)
}

func rebindFixtureSourceRelationship(t *testing.T, fixture *testFixture) {
	t.Helper()
	input, rows := fixtureDependencySemanticArtifact(t, fixture.dependencyByRole["source_contract"])
	operationRows := rows.byKind["api_operation"]
	if len(operationRows) != 1 {
		t.Fatalf("fixture source-contract mutation leaves %d api_operation rows, want 1", len(operationRows))
	}
	fact, err := typedGraphPredecessorFactForRow(typedGraphArtifactRoleSourceContract, input, operationRows[0], "source_symbol", fixture.sourceReadOperationSymbol, typedGraphFactSourceOperationAccess, 0)
	if err != nil {
		t.Fatal(err)
	}
	updated := 0
	for _, relationship := range fixturePlanRelationships(fixture) {
		if relationship.SourceID != fixture.sourceOperationID || relationship.Label != "operation_reads_resource" {
			continue
		}
		relationship.DerivationBinding, err = typedGraphPredecessorDerivationBindingFor(relationship.RowKind, relationship.ID, []typedGraphPredecessorFact{fact})
		if err != nil {
			t.Fatal(err)
		}
		updated++
	}
	if updated != 1 {
		t.Fatalf("fixture source relationship rebind updated %d rows, want 1", updated)
	}
}

func rebindOperationApplicability(t *testing.T, fixture *testFixture) {
	t.Helper()
	path := fixture.dependencyByRole["operation_applicability"]
	schemaPath := fixture.schemaByRole[dependencySemanticRoleOperationApplicability]
	writeFixtureExactJSONLSchema(t, path, schemaPath, "urn:fixture:provider-documentation:"+dependencySemanticRoleOperationApplicability+":schema")
	fixture.manifest().OperationApplicabilityProfileSHA256 = fileSHA256(t, path)
	profilePath := fixture.dependencyByRole["dependency_semantic_validation_profile"]
	mutateJSONLMatchingRow(t, profilePath, "artifact_schema_binding", semanticStringFieldEquals("role", dependencySemanticRoleOperationApplicability), func(row map[string]interface{}) {
		row["artifact_raw_sha256"] = fileSHA256(t, path)
		row["schema_raw_sha256"] = fileSHA256(t, schemaPath)
	})
	fixture.manifest().DependencySemanticValidation.Profile.RawSHA256 = fileSHA256(t, profilePath)
	writeJSONL(t, fixture.planPath, fixture.planRows)
}

func rebindDependencySemanticRoles(t *testing.T, fixture *testFixture, roles ...string) {
	t.Helper()
	profilePath := fixture.dependencyByRole["dependency_semantic_validation_profile"]
	if profilePath == "" {
		t.Fatal("fixture has no dependency semantic validation profile")
	}
	for _, role := range roles {
		artifactPath := fixtureSemanticArtifactPath(fixture, role)
		artifactDigest := fileSHA256(t, artifactPath)
		coordinate, ok := fixture.artifactCoordinateByRole[role]
		if !ok {
			t.Fatalf("fixture has no frozen artifact coordinate for semantic role %q", role)
		}
		_, profileRows := fixtureDependencySemanticArtifact(t, profilePath)
		priorDigest := ""
		matched := 0
		for _, row := range profileRows.byKind["artifact_schema_binding"] {
			rowRole, _ := semanticString(row.data, "role")
			artifactID, _ := semanticString(row.data, "artifact_id")
			artifactVersion, _ := semanticString(row.data, "artifact_version")
			bindingDigest, _ := semanticString(row.data, "artifact_raw_sha256")
			if rowRole == role && artifactID == coordinate.ID && artifactVersion == coordinate.Version {
				priorDigest = bindingDigest
				matched++
			}
		}
		if matched != 1 || !isLowerSHA256(priorDigest) {
			t.Fatalf("fixture semantic role %q resolves %d exact profile bindings at coordinate %s/%s", role, matched, coordinate.ID, coordinate.Version)
		}
		updated := 0
		mutateJSONLMatchingRow(t, profilePath, "artifact_schema_binding", func(row map[string]interface{}) bool {
			rowRole, _ := semanticString(row, "role")
			bindingDigest, _ := semanticString(row, "artifact_raw_sha256")
			return rowRole == role && bindingDigest == priorDigest
		}, func(row map[string]interface{}) {
			row["artifact_raw_sha256"] = artifactDigest
			updated++
		})
		if updated != 1 {
			t.Fatalf("fixture semantic role %q updated %d exact digest bindings, want 1", role, updated)
		}
	}
	fixture.manifest().DependencySemanticValidation.Profile.RawSHA256 = fileSHA256(t, profilePath)
	writeJSONL(t, fixture.planPath, fixture.planRows)
}

func fixtureSemanticArtifactPath(fixture *testFixture, role string) string {
	switch role {
	case dependencySemanticRoleProfile:
		return fixture.dependencyByRole["profile"]
	case dependencySemanticRoleSourceContract:
		return fixture.dependencyByRole["source_contract"]
	case dependencySemanticRoleSampleShape:
		return fixture.dependencyByRole["sample_shape"]
	case dependencySemanticRoleProtocolContract:
		return fixture.dependencyByRole["protocol_contract"]
	case dependencySemanticRoleFieldMapping:
		return fixture.dependencyByRole["field_mapping"]
	case dependencySemanticRoleOperationApplicability:
		return fixture.dependencyByRole["operation_applicability"]
	case dependencySemanticRoleAPIGraphApplicability:
		return fixture.dependencyByRole["api_graph_applicability"]
	case dependencySemanticRoleSurfaceDisposition:
		return fixture.dependencyByRole["surface_disposition"]
	case dependencySemanticRoleFieldSecurityPolicy:
		return fixture.dependencyByRole["field_security_policy"]
	case dependencySemanticRoleMappingTransitiveRoster:
		return fixture.dependencyByRole["mapping_transitive_dependency_roster"]
	case dependencySemanticRoleDocumentationClaimDerivation:
		return fixture.dependencyByRole["documentation_claim_derivation_profile"]
	default:
		return ""
	}
}

func loadSelectionValidationFixture(t *testing.T) (*testFixture, artifactInput, loadedEvidence, map[string]artifactInput) {
	t.Helper()
	fixture := newTestFixture(t)
	loaded, err := loadEvidenceBodies(
		fixture.options.EvidenceManifestPath,
		map[string]struct{}{supportedEvidenceRepresentationKind: {}},
	)
	if err != nil {
		t.Fatalf("load exact selection evidence: %v", err)
	}
	dependencies, err := loadDependencyArtifacts(fixture.options.DependencyArtifactPath)
	if err != nil {
		t.Fatalf("load selection dependencies: %v", err)
	}
	roster, ok := dependencies[fixture.manifest().EvidenceSelectionRosterSHA256]
	if !ok {
		t.Fatal("selection roster dependency is absent")
	}
	return fixture, roster, loaded, dependencies
}

func fixtureLocators(fixture *testFixture) map[string]evidenceLocator {
	locators := map[string]evidenceLocator{}
	for _, row := range fixture.planRows {
		if locator, ok := row.(*evidenceLocator); ok {
			locators[locator.ID] = *locator
		}
	}
	return locators
}

func replaceFileDigest(t *testing.T, path, oldDigest, newDigest string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if count := bytes.Count(raw, []byte(oldDigest)); count != 1 {
		t.Fatalf("%s contains old digest %s %d times, want 1", path, oldDigest, count)
	}
	raw = bytes.Replace(raw, []byte(oldDigest), []byte(newDigest), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *testFixture) manifest() *artifactManifest {
	return f.planRows[0].(*artifactManifest)
}

func (f *testFixture) summary() *validationSummary {
	return f.planRows[len(f.planRows)-1].(*validationSummary)
}

func (f *testFixture) firstSymbol() *apiSymbol {
	for _, row := range f.planRows {
		if symbol, ok := row.(*apiSymbol); ok {
			return symbol
		}
	}
	panic("fixture has no API symbol")
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256Hex(raw)
}
