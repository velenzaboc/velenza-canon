//go:build externalfixture

package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

type officialProviderFactoryPin struct {
	name                     string
	environment              string
	provider                 string
	sourceRef                string
	sourceURL                string
	representation           string
	representationCoordinate string
	artifactPrefix           string
	sourceSymbolPrefix       string
	operationName            string
	readOperationSource      string
	sectionRoot              string
	protocolLiteralA         string
	protocolLiteralB         string
	ranges                   []officialProviderEvidenceRange
	wantBodyBytes            int
	wantBodySHA256           string
	matchStart               int64
	matchEnd                 int64
	wantRuleCount            int64
	wantOutcomeCount         int64
	wantFactCount            int64
	wantWholeRowCount        int64
}

func officialIntuitFactoryRanges() []officialProviderEvidenceRange {
	ranges := make([]officialProviderEvidenceRange, len(intuitCopyAllEvidenceRanges))
	for index, selected := range intuitCopyAllEvidenceRanges {
		ranges[index] = officialProviderEvidenceRange{
			Name: selected.Name, SourceSymbol: selected.SourceSymbol, SurfaceKind: selected.SurfaceKind,
			ByteStartOffset: selected.ByteStartOffset, ByteEndOffsetExclusive: selected.ByteEndOffsetExclusive, SelectedRangeSHA256: selected.SelectedRangeSHA256,
		}
	}
	return ranges
}

func officialXeroFactoryRanges() []officialProviderEvidenceRange {
	ranges := make([]officialProviderEvidenceRange, len(xeroAssetsEvidenceRanges))
	for index, selected := range xeroAssetsEvidenceRanges {
		ranges[index] = officialProviderEvidenceRange{
			Name: selected.Name, SourceSymbol: selected.SourceSymbol, SurfaceKind: selected.SurfaceKind,
			ByteStartOffset: selected.ByteStartOffset, ByteEndOffsetExclusive: selected.ByteEndOffsetExclusive, SelectedRangeSHA256: selected.SelectedRangeSHA256,
		}
	}
	return ranges
}

func TestOfficialProviderPinsRunCompleteDocumentationFactory(t *testing.T) {
	officialEvidenceRoot := prepareOfficialProviderReleaseEvidenceRoot(t)
	pins := []officialProviderFactoryPin{
		{
			name: "quickbooks_online_copy_all", environment: "QBO_COPY_ALL_FIXTURE",
			provider: "quickbooks_online", sourceRef: intuitProfitAndLossDetailSourceRef, sourceURL: intuitProfitAndLossDetailSourceURL,
			representation: "source_declared_copy_all_for_ai_markdown", representationCoordinate: "button[aria-label=Copy all for AI]",
			artifactPrefix: "intuit_qbo_profit_and_loss_detail_copy_all", sourceSymbolPrefix: "quickbooks_profit_and_loss_detail_semantic_projection", operationName: "query_profit_and_loss_detail", readOperationSource: intuitOperationSource, sectionRoot: "Profit and Loss Detail",
			protocolLiteralA: "ProfitAndLossDetail", protocolLiteralB: "ColData", ranges: officialIntuitFactoryRanges(),
			wantBodyBytes: intuitProfitAndLossDetailCopyAllByteCount, wantBodySHA256: intuitProfitAndLossDetailCopyAllSHA256,
			matchStart: intuitCopyAllEvidenceRanges[2].ByteStartOffset, matchEnd: intuitCopyAllEvidenceRanges[2].ByteEndOffsetExclusive,
			wantRuleCount: 22, wantOutcomeCount: 29, wantFactCount: 100, wantWholeRowCount: 100,
		},
		{
			name: "xero_assets_openapi", environment: "XERO_ASSETS_OPENAPI_FIXTURE",
			provider: "xero", sourceRef: xeroAssetsSourceRef, sourceURL: xeroAssetsSourceURL,
			representation: "openapi_yaml_raw_bytes", representationCoordinate: "git_commit:" + xeroAssetsOpenAPICommit + ":xero_assets.yaml",
			artifactPrefix: "xero_assets_openapi", sourceSymbolPrefix: "xero_assets_semantic_projection", operationName: "get_assets", readOperationSource: xeroOperationSource, sectionRoot: "Xero Assets API",
			protocolLiteralA: "Xero Assets API", protocolLiteralB: "xero-tenant-id", ranges: officialXeroFactoryRanges(),
			wantBodyBytes: xeroAssetsOpenAPIByteCount, wantBodySHA256: xeroAssetsOpenAPISHA256,
			matchStart: xeroAssetsEvidenceRanges[1].ByteStartOffset, matchEnd: xeroAssetsEvidenceRanges[1].ByteEndOffsetExclusive,
			wantRuleCount: 9, wantOutcomeCount: 9, wantFactCount: 21, wantWholeRowCount: 21,
		},
	}
	for _, pin := range pins {
		pin := pin
		t.Run(pin.name, func(t *testing.T) {
			path := os.Getenv(pin.environment)
			if path == "" {
				t.Fatalf("%s must select the exact pinned official source body", pin.environment)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(body) != pin.wantBodyBytes || sha256Hex(body) != pin.wantBodySHA256 {
				t.Fatalf("%s does not equal the exact pinned official source body", pin.environment)
			}

			if pin.matchStart < 0 || pin.matchEnd <= pin.matchStart || pin.matchEnd > int64(len(body)) {
				t.Fatal("official factory match range is outside the exact pinned body")
			}
			selected := body[pin.matchStart:pin.matchEnd]
			if bytes.Count(body, selected) != 1 {
				t.Fatal("official factory match range is not unique in the exact pinned body")
			}
			fixture := newTestFixtureWithPrimaryEvidence(t, testPrimaryEvidenceFixture{
				body: body, derivationPattern: regexp.QuoteMeta(string(selected)), providerDescription: "Exact candidate field derived from the pinned " + pin.provider + " source.",
				provider: pin.provider, sourceRef: pin.sourceRef, sourceURL: pin.sourceURL, representation: pin.representation, representationCoord: pin.representationCoordinate,
				artifactPrefix: pin.artifactPrefix, sourceSymbolPrefix: pin.sourceSymbolPrefix, operationName: pin.operationName, readOperationSource: pin.readOperationSource, sectionRoot: pin.sectionRoot,
				protocolLiteralA: pin.protocolLiteralA, protocolLiteralB: pin.protocolLiteralB, singleDocument: true, additionalRanges: pin.ranges,
				derivationBuilder: func(t *testing.T, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) *testDocumentationDerivationBundle {
					return buildOfficialProviderDocumentationDerivationBundle(t, pin, proof, bodies)
				},
			})
			loaded, err := loadEvidenceBodies(fixture.options.EvidenceManifestPath, map[string]struct{}{supportedEvidenceRepresentationKind: {}})
			if err != nil {
				t.Fatal(err)
			}
			admitted, ok := loaded.Bodies[pin.wantBodySHA256]
			if !ok || !bytes.Equal(admitted.Bytes, body) {
				t.Fatalf("factory fixture does not admit the exact pinned %s source body", pin.provider)
			}
			metadata, ok := loaded.MetadataByCoordinate[evidenceSourceCoordinate{Ref: pin.sourceRef, URL: pin.sourceURL}]
			if !ok || metadata.ContentSHA256 != pin.wantBodySHA256 {
				t.Fatalf("factory fixture does not bind the exact pinned %s source coordinate", pin.provider)
			}
			assertOfficialNonFieldFactCannotSatisfyFieldMapping(t, fixture)

			lineage := newRealVerifyFactoryLineage(t, fixture)
			stagePaths := writeRealVerifyFactoryStageManifests(t, fixture, lineage)
			directDependencyPaths := realFactoryGraphDirectDependencyPaths(t, lineage, stagePaths)
			exactTargetRoles := map[string]struct{}{dependencySemanticRoleSourceContract: {}, dependencySemanticRoleSampleShape: {}, dependencySemanticRoleProtocolContract: {}}
			if err := requireExactSet("official documentation target artifact roles", stringMapKeysAsSet(fixture.derivationTargetPaths), exactTargetRoles); err != nil {
				t.Fatal(err)
			}
			if err := requireExactSet("official documentation target schema roles", stringMapKeysAsSet(fixture.derivationTargetSchemas), exactTargetRoles); err != nil {
				t.Fatal(err)
			}
			dependencyPathSet := stringSet(fixture.options.DependencyArtifactPath)
			targetPathSet := map[string]struct{}{}
			for _, role := range sortedProviderStringMapKeys(exactTargetRoles) {
				targetPath := fixture.derivationTargetPaths[role]
				targetSchemaPath := fixture.derivationTargetSchemas[role]
				targetPathSet[targetPath] = struct{}{}
				targetPathSet[targetSchemaPath] = struct{}{}
				if _, supplied := dependencyPathSet[targetPath]; !supplied {
					t.Fatalf("official %s target role %q artifact is absent from the closed dependency input roster", pin.provider, role)
				}
				if _, supplied := dependencyPathSet[targetSchemaPath]; !supplied {
					t.Fatalf("official %s target role %q schema is absent from the closed dependency input roster", pin.provider, role)
				}
				semanticPath := fixtureSemanticArtifactPath(fixture, role)
				if fileSHA256(t, targetPath) == fileSHA256(t, semanticPath) {
					t.Fatalf("official %s target role %q fell back to its enriched semantic projection", pin.provider, role)
				}
				target := fixture.derivationTargetAuthority.byRole[role]
				if target.artifactSHA256 != fileSHA256(t, targetPath) || target.schemaSHA256 != fileSHA256(t, targetSchemaPath) {
					t.Fatalf("official %s target role %q does not bind its exact distinct artifact/schema bytes", pin.provider, role)
				}
			}
			if len(targetPathSet) != 6 {
				t.Fatalf("official %s target dependency roster has %d distinct paths, want exactly 6", pin.provider, len(targetPathSet))
			}
			wantClosedDependencies := 29 + len(targetPathSet)
			if len(directDependencyPaths) != 12 || len(fixture.options.DependencyArtifactPath) != wantClosedDependencies {
				t.Fatalf("official %s dependency closure = %d direct/%d closed, want 12/%d (29 base + 3 exact targets + 3 schemas)", pin.provider, len(directDependencyPaths), len(fixture.options.DependencyArtifactPath), wantClosedDependencies)
			}
			preflight := fixture.options
			preflight.graphCompileSelectionLoader = nil
			preflight.graphCompileRequestRaw = nil
			preflight.graphCompileInputs = StageCompileInputs{}
			receipt, err := runDocumentationFactory(FactoryRunOptions{
				EvidenceIntakeInputManifestPath:     stagePaths[0],
				SemanticExtractionInputManifestPath: stagePaths[1],
				GraphCompileInputManifestPath:       stagePaths[2],
				FullFactoryInputManifestPath:        stagePaths[3],
				Preflight:                           preflight,
			}, factoryRunnerDependencies{Verify: Verify, ToolIdentity: testFactoryToolIdentity()})
			if err != nil {
				t.Fatal(err)
			}
			if receipt.PreflightReceipt.Provider != pin.provider {
				t.Fatalf("official factory provider = %q, want %q", receipt.PreflightReceipt.Provider, pin.provider)
			}
			derivation := fixture.documentationDerivation
			if derivation == nil {
				t.Fatalf("official %s fixture did not retain its independently executed documentation derivation bundle", pin.provider)
			}
			if derivation.ruleCount != pin.wantRuleCount || derivation.outcomeCount != pin.wantOutcomeCount || derivation.factCount != pin.wantFactCount || derivation.wholeRowCount != pin.wantWholeRowCount {
				t.Fatalf("official %s independently executed derivation = %d rules/%d outcomes/%d facts/%d whole rows, want %d/%d/%d/%d", pin.provider, derivation.ruleCount, derivation.outcomeCount, derivation.factCount, derivation.wholeRowCount, pin.wantRuleCount, pin.wantOutcomeCount, pin.wantFactCount, pin.wantWholeRowCount)
			}
			preflightReceipt := receipt.PreflightReceipt
			if preflightReceipt.DocumentationDerivationProfileCount != 1 ||
				preflightReceipt.DocumentationDerivationOutcomeCount != pin.wantOutcomeCount ||
				preflightReceipt.DocumentationDerivedFactCount != pin.wantFactCount ||
				preflightReceipt.DocumentationWholeRowBindingCount != pin.wantWholeRowCount ||
				preflightReceipt.DocumentationRowMemberBindingCount != 0 {
				t.Fatalf("official %s receipt derivation/materialization closure = %d profiles/%d outcomes/%d facts/%d whole/%d member, want 1/%d/%d/%d/0", pin.provider, preflightReceipt.DocumentationDerivationProfileCount, preflightReceipt.DocumentationDerivationOutcomeCount, preflightReceipt.DocumentationDerivedFactCount, preflightReceipt.DocumentationWholeRowBindingCount, preflightReceipt.DocumentationRowMemberBindingCount, pin.wantOutcomeCount, pin.wantFactCount, pin.wantWholeRowCount)
			}
			if preflightReceipt.DocumentationDerivationProfilePageSetRootSHA256 != derivation.pageSetRoot ||
				preflightReceipt.DocumentationDerivationProfileResultRootSHA256 != derivation.resultSetRoot ||
				preflightReceipt.DocumentationTargetMaterializationRootSHA256 != derivation.targetRoot ||
				preflightReceipt.DocumentationTargetBindingRosterRootSHA256 != derivation.targetRosterRoot ||
				preflightReceipt.DocumentationDerivationClosureProofSHA256 != derivation.closureProofRoot {
				t.Fatalf("official %s receipt roots do not bind the independently executed derivation/materialization bundle: page=%s/%s result=%s/%s materialization=%s/%s roster=%s/%s closure=%s/%s", pin.provider,
					preflightReceipt.DocumentationDerivationProfilePageSetRootSHA256, derivation.pageSetRoot,
					preflightReceipt.DocumentationDerivationProfileResultRootSHA256, derivation.resultSetRoot,
					preflightReceipt.DocumentationTargetMaterializationRootSHA256, derivation.targetRoot,
					preflightReceipt.DocumentationTargetBindingRosterRootSHA256, derivation.targetRosterRoot,
					preflightReceipt.DocumentationDerivationClosureProofSHA256, derivation.closureProofRoot)
			}
			assertOfficialProviderCandidateOnlyReceipt(t, receipt, body)

			publicRun := runFactoryPublicReleaseForFixture(t, fixture)
			assertOfficialProviderPublicRelease(t, pin, publicRun, body)
			exportOfficialProviderReleaseEvidence(t, officialEvidenceRoot, pin, publicRun)
		})
	}
}

type officialProviderReleaseEvidenceManifest struct {
	EvidenceKind                  string `json:"evidence_kind"`
	EvidenceVersion               string `json:"evidence_version"`
	Provider                      string `json:"provider"`
	SourceRef                     string `json:"source_ref"`
	Representation                string `json:"representation"`
	SourceContentSHA256           string `json:"source_content_sha256"`
	SourceContentByteCount        int64  `json:"source_content_byte_count"`
	CandidateCommit               string `json:"candidate_commit"`
	CleanSourceRevision           string `json:"clean_source_revision"`
	SourceRosterSHA256            string `json:"source_roster_sha256"`
	TargetOS                      string `json:"target_os"`
	TargetArch                    string `json:"target_arch"`
	DirectReceiptSHA256           string `json:"direct_receipt_sha256"`
	ReleaseReceiptSHA256          string `json:"release_receipt_sha256"`
	DirectReceiptFileSHA256       string `json:"direct_receipt_file_sha256"`
	ReleaseReceiptFileSHA256      string `json:"release_receipt_file_sha256"`
	DirectPortableReceiptSHA256   string `json:"direct_portable_receipt_sha256"`
	ReleasePortableReceiptSHA256  string `json:"release_portable_receipt_sha256"`
	PreflightReceiptSHA256        string `json:"preflight_receipt_sha256"`
	BodyFree                      bool   `json:"body_free"`
	NonAuthoritativeCandidateOnly bool   `json:"non_authoritative_candidate_only"`
	LiveProviderAcceptanceClaimed bool   `json:"live_provider_acceptance_claimed"`
}

func prepareOfficialProviderReleaseEvidenceRoot(t *testing.T) string {
	t.Helper()
	directory := os.Getenv("VELENZA_FACTORY_OFFICIAL_EVIDENCE_DIR")
	if directory == "" {
		return ""
	}
	if directory != strings.TrimSpace(directory) || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatalf("official provider evidence directory %q is not an absolute canonical path", directory)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create exclusive official provider evidence directory: %v", err)
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		t.Fatalf("official provider evidence directory is not a physical directory: %v", err)
	}
	return directory
}

func assertOfficialProviderPublicRelease(t *testing.T, pin officialProviderFactoryPin, result factoryPublicReleaseRun, body []byte) {
	t.Helper()
	direct, release := result.DirectReceipt, result.ReleaseReceipt
	for name, receipt := range map[string]FactoryRunReceipt{"direct": direct, "release": release} {
		if receipt.PreflightReceipt.Provider != pin.provider {
			t.Fatalf("official %s public %s provider = %q, want %q", pin.provider, name, receipt.PreflightReceipt.Provider, pin.provider)
		}
		assertOfficialProviderCandidateOnlyReceipt(t, receipt, body)
	}
	if direct.PortableReceiptSHA256 != release.PortableReceiptSHA256 || direct.PreflightReceipt.ReceiptSHA256 != release.PreflightReceipt.ReceiptSHA256 {
		t.Fatalf("official %s direct/release roots differ: portable=%s/%s preflight=%s/%s", pin.provider,
			direct.PortableReceiptSHA256, release.PortableReceiptSHA256,
			direct.PreflightReceipt.ReceiptSHA256, release.PreflightReceipt.ReceiptSHA256)
	}
	if bytes.Contains(result.DirectRaw, body) || bytes.Contains(result.ReleaseRaw, body) {
		t.Fatalf("official %s public release evidence contains the exact source body", pin.provider)
	}
}

func exportOfficialProviderReleaseEvidence(t *testing.T, root string, pin officialProviderFactoryPin, result factoryPublicReleaseRun) {
	t.Helper()
	if root == "" {
		return
	}
	directory := filepath.Join(root, pin.name)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("create exclusive official %s evidence directory: %v", pin.provider, err)
	}
	info, err := os.Lstat(directory)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		t.Fatalf("official %s evidence directory is not physical: %v", pin.provider, err)
	}
	candidateCommit := strings.TrimSpace(string(runFactoryCommand(t, result.SourceRoot, factoryCommandOptions{
		name: "git", args: []string{"rev-parse", "HEAD"},
	})))
	if len(candidateCommit) != 40 {
		t.Fatalf("official %s evidence candidate commit = %q, want full SHA-1", pin.provider, candidateCommit)
	}
	direct, release := result.DirectReceipt, result.ReleaseReceipt
	manifest := officialProviderReleaseEvidenceManifest{
		EvidenceKind: "provider_documentation_factory_official_provider_cross_machine_evidence", EvidenceVersion: "1",
		Provider: pin.provider, SourceRef: pin.sourceRef, Representation: pin.representation,
		SourceContentSHA256: pin.wantBodySHA256, SourceContentByteCount: int64(pin.wantBodyBytes),
		CandidateCommit: candidateCommit, CleanSourceRevision: result.CleanRevision,
		SourceRosterSHA256: direct.ToolIdentity.SourceRosterSHA256,
		TargetOS:           direct.ExecutionIdentity.TargetOS, TargetArch: direct.ExecutionIdentity.TargetArch,
		DirectReceiptSHA256: direct.ReceiptSHA256, ReleaseReceiptSHA256: release.ReceiptSHA256,
		DirectReceiptFileSHA256: sha256Hex(result.DirectRaw), ReleaseReceiptFileSHA256: sha256Hex(result.ReleaseRaw),
		DirectPortableReceiptSHA256: direct.PortableReceiptSHA256, ReleasePortableReceiptSHA256: release.PortableReceiptSHA256,
		PreflightReceiptSHA256:        direct.PreflightReceipt.ReceiptSHA256,
		BodyFree:                      direct.BodyFree && release.BodyFree,
		NonAuthoritativeCandidateOnly: true, LiveProviderAcceptanceClaimed: false,
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw = append(manifestRaw, '\n')
	for _, artifact := range []struct {
		name string
		raw  []byte
	}{
		{name: "direct-receipt.json", raw: result.DirectRaw},
		{name: "release-receipt.json", raw: result.ReleaseRaw},
		{name: "manifest.json", raw: manifestRaw},
	} {
		if err := writeFactoryPortabilityEvidenceFile(filepath.Join(directory, artifact.name), artifact.raw); err != nil {
			t.Fatalf("write official %s evidence %s: %v", pin.provider, artifact.name, err)
		}
	}
}

func buildOfficialProviderDocumentationDerivationBundle(t *testing.T, pin officialProviderFactoryPin, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) *testDocumentationDerivationBundle {
	t.Helper()
	var profileRows dependencySemanticRows
	var profiles map[string]executableDocumentationDerivationProfile
	var execution exactDocumentationDerivationProfileExecutionSet
	var targetAuthority dependencySemanticDerivationTargetSchemaAuthority
	var targetArtifacts map[string]artifactInput
	var targetRows map[string]dependencySemanticRows

	switch pin.name {
	case "quickbooks_online_copy_all":
		programValue := intuitCopyAllDerivationProgram()
		programCanonical := intuitMustCanonicalJSON(t, programValue)
		reference := dependencyProfileReference{id: "intuit_qbo_profit_and_loss_detail_copy_all", version: "1", digest: sha256Hex(programCanonical)}
		profileRows = intuitCopyAllExecutableProfileRows(t, reference, programValue)
		var err error
		profiles, err = parseExecutableDocumentationDerivationProfiles(profileRows)
		if err != nil {
			t.Fatal(err)
		}
		execution, err = executeDocumentationDerivationProfileSet(profiles, proof, bodies)
		if err != nil {
			t.Fatal(err)
		}
		targetAuthority, targetArtifacts, targetRows, _ = intuitCopyAllTargetMaterializationFixture(t, profiles, execution.Results[0].Facts)
	case "xero_assets_openapi":
		programValue := xeroAssetsDerivationProgram()
		programCanonical := xeroMustCanonicalJSON(t, programValue)
		reference := dependencyProfileReference{id: "xero_assets_openapi_documentation_derivation", version: "1", digest: sha256Hex(programCanonical)}
		profileRows = xeroExecutableProfileRows(t, reference, programValue)
		var err error
		profiles, err = parseExecutableDocumentationDerivationProfiles(profileRows)
		if err != nil {
			t.Fatal(err)
		}
		execution, err = executeDocumentationDerivationProfileSet(profiles, proof, bodies)
		if err != nil {
			t.Fatal(err)
		}
		targetAuthority, targetArtifacts, targetRows = xeroTargetMaterializationFixture(t, profiles, execution.Results[0].Facts)
	default:
		t.Fatalf("unknown official provider factory pin %q", pin.name)
	}
	if len(execution.Results) != 1 {
		t.Fatalf("official %s documentation execution has %d results, want 1", pin.provider, len(execution.Results))
	}
	facts := execution.Results[0].Facts
	var accessFact, fieldFact exactDocumentationDerivedFact
	for _, fact := range facts {
		if accessFact.FactID == "" && fact.TargetArtifactRole == dependencySemanticRoleSourceContract && fact.TargetRowKind == "api_operation" && fact.TargetBindingKind == exactDocumentationTargetWholeRow {
			accessFact = fact
		}
		if fieldFact.FactID == "" && fact.TargetArtifactRole == dependencySemanticRoleSourceContract && fact.TargetBindingKind == exactDocumentationTargetWholeRow && (fact.TargetRowKind == "field_contract" || fact.TargetRowKind == "money_field_contract") {
			fieldFact = fact
		}
	}
	if accessFact.FactID == "" || fieldFact.FactID == "" {
		t.Fatalf("official %s documentation facts have no exact operation/field projection seam", pin.provider)
	}
	materializations, wholeRows, memberRows, err := validateExactDocumentationTargetMaterializations(profiles, facts, targetAuthority, targetArtifacts, targetRows)
	if err != nil {
		t.Fatal(err)
	}
	if memberRows != 0 || int64(len(materializations)) != int64(len(facts)) || wholeRows != int64(len(facts)) {
		t.Fatalf("official %s target closure = %d materializations/%d whole/%d member for %d facts", pin.provider, len(materializations), wholeRows, memberRows, len(facts))
	}
	derivationState, err := parseDocumentationClaimDerivationRows(profileRows)
	if err != nil {
		t.Fatal(err)
	}
	closure, err := executeAndValidateDocumentationDerivationClosure(profileRows, derivationState, targetAuthority, targetArtifacts, targetRows, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDocumentationDerivationClosureProof(closure); err != nil {
		t.Fatal(err)
	}
	numeric := exactValueClassifierOutput{numericSemantics: "exact_decimal", authoritativeCarrier: "source_lexeme", computationPath: "unresolved_fail_closed_gap"}
	if pin.name == "quickbooks_online_copy_all" {
		numeric.numericSemantics = "exact_string"
	}
	return &testDocumentationDerivationBundle{
		profileRows: profileRows, profiles: profiles, facts: facts, targetAuthority: targetAuthority, targetArtifacts: targetArtifacts, targetRows: targetRows,
		accessFact: accessFact, fieldFact: fieldFact, numeric: numeric, applicability: "required",
		ruleCount: execution.RuleCount, outcomeCount: execution.OutcomeCount, factCount: execution.FactCount, wholeRowCount: wholeRows,
		pageSetRoot: execution.ProfilePageSetRootSHA256, resultSetRoot: execution.ProfileResultSetRootSHA256,
		targetRoot: closure.targetMaterializationRootSHA256, targetRosterRoot: closure.targetMaterializationBindingRosterRootSHA256, closureProofRoot: closure.proofSHA256,
		closure: closure,
	}
}

func assertOfficialNonFieldFactCannotSatisfyFieldMapping(t *testing.T, fixture *testFixture) {
	t.Helper()
	derivation := fixture.documentationDerivation
	if derivation == nil || derivation.closure.seal != documentationDerivationClosureAuthority {
		t.Fatal("official fixture has no sealed prepared documentation derivation closure")
	}
	_, mappingRows := fixtureDependencySemanticArtifact(t, fixtureSemanticArtifactPath(fixture, dependencySemanticRoleFieldMapping))
	if len(mappingRows.byKind["field_occurrence_disposition"]) != 1 {
		t.Fatalf("official field mapping has %d field occurrence rows, want 1", len(mappingRows.byKind["field_occurrence_disposition"]))
	}
	row := mappingRows.byKind["field_occurrence_disposition"][0]
	row.data = cloneSemanticObjectForTest(t, row.data)
	binding, ok := row.data["derivation_binding"].(map[string]interface{})
	if !ok {
		t.Fatal("official field mapping has no derivation binding")
	}
	nonFieldFact := derivation.accessFact
	row.data[exactDocumentationDerivedFactIDField] = nonFieldFact.FactID
	binding["exact_input_documentation_fact_id"] = nonFieldFact.FactID
	binding["exact_input_evidence_locator_id"] = nonFieldFact.EvidenceLocatorID
	binding["exact_input_claim_sha256"] = sha256Hex(nonFieldFact.CanonicalOutputFields)
	binding["exact_input_coordinate"] = map[string]interface{}{
		"source_content_sha256":     nonFieldFact.EvidenceLocator.SourceContentSHA256,
		"byte_start_offset":         json.Number(strconv.FormatInt(nonFieldFact.EvidenceLocator.ByteStartOffset, 10)),
		"byte_end_offset_exclusive": json.Number(strconv.FormatInt(nonFieldFact.EvidenceLocator.ByteEndOffsetExclusive, 10)),
		"selected_range_byte_count": json.Number(strconv.FormatInt(nonFieldFact.EvidenceLocator.SelectedRangeByteCount, 10)),
		"selected_range_sha256":     nonFieldFact.EvidenceLocator.SelectedRangeSHA256,
	}
	_, derivationRows := fixtureDependencySemanticArtifact(t, fixtureSemanticArtifactPath(fixture, dependencySemanticRoleDocumentationClaimDerivation))
	profiles, err := parseDocumentationClaimDerivationRows(derivationRows)
	if err != nil {
		t.Fatal(err)
	}
	semantics, _ := semanticString(row.data, "exact_numeric_semantics")
	carrier, _ := semanticString(row.data, "numeric_authoritative_carrier")
	computationPath, _ := semanticString(row.data, "financial_computation_path")
	coordinate := dependencyHydrationCoordinate{
		digest: nonFieldFact.EvidenceLocator.SourceContentSHA256, start: nonFieldFact.EvidenceLocator.ByteStartOffset,
		end: nonFieldFact.EvidenceLocator.ByteEndOffsetExclusive, count: nonFieldFact.EvidenceLocator.SelectedRangeByteCount,
		rangeSHA: nonFieldFact.EvidenceLocator.SelectedRangeSHA256,
	}
	err = validateFieldDerivationAndExactComputation(mappingRows, row, coordinate, semantics, carrier, computationPath, profiles, derivation.closure)
	if err == nil || !strings.Contains(err.Error(), "exact input fact does not equal the bound field name and provider type") {
		t.Fatalf("non-field-shaped source-contract fact validation error = %v, want exact field-shape refusal", err)
	}
}

func assertOfficialProviderCandidateOnlyReceipt(t *testing.T, receipt FactoryRunReceipt, body []byte) {
	t.Helper()
	completion := receipt.Completion
	if !completion.Compiled || !completion.Verified || !completion.DerivationExecuted ||
		completion.GraphAdmittable || completion.Admitted || completion.CircuitAdmittable || completion.CircuitAdmitted ||
		completion.Configured || completion.CredentialProvisioned || completion.Deployed || completion.LiveTested ||
		completion.TwoTenantProven || completion.SourceSubstitutionProven || completion.AuthoritySelected ||
		completion.AdmissionAuthorized || completion.FactoryComplete {
		t.Fatalf("official provider factory overclaims candidate completion: %+v", completion)
	}
	raw := mustFactoryReceiptJSON(t, receipt)
	if !receipt.BodyFree || bytes.Contains(raw, body) {
		t.Fatal("official provider factory receipt is not body-free")
	}
}
