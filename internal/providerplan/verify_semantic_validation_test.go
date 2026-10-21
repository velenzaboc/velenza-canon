package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func verifyTestDigest(letter string) string { return strings.Repeat(letter, 64) }

// validSemanticPlan is deliberately small, but exercises the same closed
// identity, locator, and summary rules used for a compiled candidate plan.
func validSemanticPlan() (*parsedPlan, map[string]exactEvidenceBody, map[string]compactStageSet) {
	body := []byte("read")
	manifestDigest := verifyTestDigest("a")
	bodyDigest := sha256Hex(body)
	locator := evidenceLocator{
		ID:                     "",
		EvidenceManifestSHA256: manifestDigest,
		SourceContentSHA256:    bodyDigest,
		ByteEndOffsetExclusive: int64(len(body)),
		SelectedRangeByteCount: int64(len(body)),
		SelectedRangeSHA256:    sha256Hex(body),
		SourceRefs:             []string{"provider-doc"},
		SourceURLs:             []string{"https://docs.example.test/read"},
		LocatorSemantics:       exactLocatorSemantics,
	}
	locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
	symbol := apiSymbol{
		Role:               "operation",
		SemanticKey:        "read",
		DisplayName:        "Read",
		EvidenceLocatorIDs: []string{locator.ID},
		DerivationBinding:  json.RawMessage(`{"proof":"derived"}`),
		AuthorityStatus:    symbolAuthorityStatusExact,
	}
	symbol.ID = stableID("capi_sym", lengthPrefixedIdentityKey(symbol.Role, symbol.SemanticKey))
	sets := map[string]compactStageSet{
		"subject": {RootSHA256: verifyTestDigest("b"), Count: 1},
		"fact":    {RootSHA256: verifyTestDigest("c"), Count: 0},
		"gap":     {RootSHA256: verifyTestDigest("d"), Count: 0},
	}
	plan := &parsedPlan{
		Manifest: &artifactManifest{
			Provider:                      "fixture",
			Artifact:                      "provider_graph",
			ArtifactVersion:               "1",
			NamedSystem:                   "Velenza BOC",
			Status:                        "candidate_not_admissible_or_executable",
			ProviderNeutralProfileSHA256:  verifyTestDigest("e"),
			SourceContractIndexSHA256:     verifyTestDigest("f"),
			SampleShapeIndexSHA256:        verifyTestDigest("1"),
			ProtocolContractIndexSHA256:   verifyTestDigest("2"),
			FieldMappingCandidateSHA256:   verifyTestDigest("3"),
			EvidenceSelectionRosterSHA256: verifyTestDigest("4"),
			EvidenceLocatorManifestSHA256: verifyTestDigest("5"),
			EvidenceManifestBindings: []evidenceManifestBinding{{
				EvidenceManifestSHA256: manifestDigest,
				EvidenceBodyKind:       evidenceBodyKindSourceDocument,
				ConsumerRoles:          []string{"api_graph_projection"},
			}},
		},
		Locators:      map[string]evidenceLocator{locator.ID: locator},
		Symbols:       map[string]apiSymbol{symbol.ID: symbol},
		Relationships: map[string]apiRelationship{},
		Properties:    map[string]apiPropertyClaim{},
		Gaps:          map[string]graphGap{},
		Summary: &validationSummary{
			CandidateEvidenceLocatorCount: 1,
			CandidateAPISymbolCount:       1,
			APIElementRolesMaterialized:   1,
			CandidateOperationCount:       1,
			CapturedOperationKindCounts:   []operationKindCount{{OperationKind: "read", Count: 1}},
			OperationApplicabilityCount:   1,
			CandidateSubjectCount:         1,
			SubjectSetRootSHA256:          sets["subject"].RootSHA256,
			FactSetRootSHA256:             sets["fact"].RootSHA256,
			GapSetRootSHA256:              sets["gap"].RootSHA256,
			Result:                        resultComplete,
		},
	}
	bodies := map[string]exactEvidenceBody{bodyDigest: {
		Bytes:       body,
		Coordinates: map[evidenceSourceCoordinate]string{{Ref: locator.SourceRefs[0], URL: locator.SourceURLs[0]}: manifestDigest},
	}}
	return plan, bodies, sets
}

func semanticParseProof(raw []byte) graphPlanParseProof {
	return graphPlanParseProof{
		seal: graphPlanParseAuthority,
		structural: graphPlanSchemaBindingProof{
			seal: graphPlanSchemaBindingAuthority,
			plan: stageArtifactIdentity{RawSHA256: sha256Hex(raw)},
			setKindsByRowKind: map[string][]string{
				"artifact_manifest":            nil,
				"candidate_evidence_locator":   nil,
				"candidate_api_symbol":         nil,
				"candidate_api_relationship":   nil,
				"candidate_api_property_claim": nil,
				"candidate_graph_gap":          nil,
				"validation_summary":           nil,
			},
		},
		bodyFree: graphPlanBodyFreeProof{seal: graphPlanBodyFreeAuthority, planSHA256: sha256Hex(raw)},
	}
}

func semanticPlanRows(t *testing.T) []byte {
	t.Helper()
	rows := []interface{}{
		artifactManifest{RowKind: "artifact_manifest"},
		evidenceLocator{RowKind: "candidate_evidence_locator", ID: "locator"},
		apiSymbol{RowKind: "candidate_api_symbol", ID: "symbol"},
		apiRelationship{RowKind: "candidate_api_relationship", ID: "relationship"},
		apiPropertyClaim{RowKind: "candidate_api_property_claim", ID: "property"},
		graphGap{RowKind: "candidate_graph_gap", ID: "gap"},
		validationSummary{RowKind: "validation_summary"},
	}
	encoded := make([][]byte, 0, len(rows))
	for _, row := range rows {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, raw)
	}
	return bytes.Join(encoded, []byte("\n"))
}

func TestVerifySemanticParserAcceptsClosedRowsAndRejectsAmbiguity(t *testing.T) {
	raw := semanticPlanRows(t)
	plan, err := parsePlan(raw, semanticParseProof(raw))
	if err != nil || len(plan.Locators) != 1 || len(plan.Symbols) != 1 || len(plan.Relationships) != 1 || len(plan.Properties) != 1 || len(plan.Gaps) != 1 {
		t.Fatalf("closed plan parser result=%+v err=%v", plan, err)
	}
	for name, candidate := range map[string][]byte{
		"duplicate key": []byte(`{"row_kind":"artifact_manifest","row_kind":"artifact_manifest"}`),
		"bad JSON":      []byte(`{`),
		"undeclared":    []byte(`{"row_kind":"other"}`),
		"duplicate manifest": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"artifact_manifest"}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"duplicate identifier": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"candidate_api_symbol","candidate_api_symbol_id":"same"}`, `{"row_kind":"candidate_graph_gap","candidate_graph_gap_id":"same"}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"missing summary": []byte(`{"row_kind":"artifact_manifest"}`),
		"strict artifact": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest","unknown":true}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"strict locator": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"candidate_evidence_locator","unknown":true}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"strict symbol": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"candidate_api_symbol","unknown":true}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"strict relationship": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"candidate_api_relationship","unknown":true}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"strict property": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"candidate_api_property_claim","unknown":true}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"strict gap": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"candidate_graph_gap","unknown":true}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"strict summary": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"validation_summary","unknown":true}`,
		}, "\n")),
		"duplicate summary": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"validation_summary"}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"duplicate locator identifier": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"candidate_evidence_locator","evidence_locator_id":"same"}`, `{"row_kind":"candidate_api_symbol","candidate_api_symbol_id":"same"}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
		"duplicate relationship identifier": []byte(strings.Join([]string{
			`{"row_kind":"artifact_manifest"}`, `{"row_kind":"candidate_api_relationship","candidate_api_relationship_id":"same"}`, `{"row_kind":"candidate_api_property_claim","candidate_api_property_claim_id":"same"}`, `{"row_kind":"validation_summary"}`,
		}, "\n")),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePlan(candidate, semanticParseProof(candidate)); err == nil {
				t.Fatal("invalid graph plan parsed successfully")
			}
		})
	}
	unsupported := []byte(`{"row_kind":"other"}`)
	proof := semanticParseProof(unsupported)
	proof.structural.setKindsByRowKind["other"] = nil
	if _, err := parsePlan(unsupported, proof); err == nil {
		t.Fatal("declared but unsupported row kind parsed successfully")
	}
	if _, err := parsePlan([]byte{0xff}, semanticParseProof([]byte{0xff})); err == nil {
		t.Fatal("non-UTF8 graph plan parsed successfully")
	}
	if _, err := parsePlan(raw, graphPlanParseProof{}); err == nil {
		t.Fatal("unsealed graph plan parsed successfully")
	}
}

func TestVerifySemanticPlanValidationRejectsIdentityAndAuthorityViolations(t *testing.T) {
	roles := map[string]struct{}{"operation": {}}
	for name, mutate := range map[string]func(*parsedPlan){
		"wrong system":              func(plan *parsedPlan) { plan.Manifest.NamedSystem = "other" },
		"malformed manifest digest": func(plan *parsedPlan) { plan.Manifest.FieldMappingCandidateSHA256 = "bad" },
		"unknown symbol role": func(plan *parsedPlan) {
			for id, symbol := range plan.Symbols {
				symbol.Role = "unknown"
				plan.Symbols[id] = symbol
			}
		},
		"symbol carries source bytes": func(plan *parsedPlan) {
			for id, symbol := range plan.Symbols {
				symbol.SourceBytesPresent = true
				plan.Symbols[id] = symbol
			}
		},
		"symbol noncontent identity": func(plan *parsedPlan) {
			for id, symbol := range plan.Symbols {
				symbol.ID = "not-derived"
				delete(plan.Symbols, id)
				plan.Symbols[symbol.ID] = symbol
			}
		},
		"symbol missing locator": func(plan *parsedPlan) {
			for id, symbol := range plan.Symbols {
				symbol.EvidenceLocatorIDs = nil
				plan.Symbols[id] = symbol
			}
		},
		"symbol unknown locator": func(plan *parsedPlan) {
			for id, symbol := range plan.Symbols {
				symbol.EvidenceLocatorIDs = []string{"unknown"}
				plan.Symbols[id] = symbol
			}
		},
		"symbol invalid derivation": func(plan *parsedPlan) {
			for id, symbol := range plan.Symbols {
				symbol.DerivationBinding = json.RawMessage(`{`)
				plan.Symbols[id] = symbol
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			plan, bodies, sets := validSemanticPlan()
			mutate(plan)
			if err := validatePlan(plan, roles, nil, nil, nil, bodies, sets); err == nil {
				t.Fatal("invalid candidate plan was accepted")
			}
		})
	}
	plan, bodies, sets := validSemanticPlan()
	if err := validatePlan(plan, roles, nil, nil, nil, bodies, sets); err != nil {
		t.Fatalf("minimal closed candidate plan rejected: %v", err)
	}
}

func TestVerifySemanticLocatorAndSummaryFailureModes(t *testing.T) {
	plan, bodies, sets := validSemanticPlan()
	var locator evidenceLocator
	for _, value := range plan.Locators {
		locator = value
	}
	for name, mutate := range map[string]func(*evidenceLocator){
		"source bytes":           func(value *evidenceLocator) { value.SourceBytesPresent = true },
		"bad digest":             func(value *evidenceLocator) { value.SelectedRangeSHA256 = "bad" },
		"bad range":              func(value *evidenceLocator) { value.ByteStartOffset = 3; value.ByteEndOffsetExclusive = 2 },
		"unknown body":           func(value *evidenceLocator) { value.SourceContentSHA256 = verifyTestDigest("9") },
		"range exceeds body":     func(value *evidenceLocator) { value.ByteEndOffsetExclusive = 99; value.SelectedRangeByteCount = 99 },
		"missing coordinate":     func(value *evidenceLocator) { value.SourceRefs = []string{"other"} },
		"wrong coordinate owner": func(value *evidenceLocator) { value.EvidenceManifestSHA256 = verifyTestDigest("f") },
	} {
		t.Run(name, func(t *testing.T) {
			copy := locator
			mutate(&copy)
			if err := validateLocator(copy, bodies); err == nil {
				t.Fatal("invalid locator was accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*evidenceLocator){
		"coordinate missing after identity":        func(value *evidenceLocator) { value.SourceRefs = []string{"other"} },
		"coordinate owner mismatch after identity": func(value *evidenceLocator) { value.EvidenceManifestSHA256 = verifyTestDigest("f") },
		"range exceeds after identity":             func(value *evidenceLocator) { value.ByteEndOffsetExclusive = 99; value.SelectedRangeByteCount = 99 },
		"range digest mismatch after identity":     func(value *evidenceLocator) { value.SelectedRangeSHA256 = verifyTestDigest("f") },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := locator
			mutate(&candidate)
			candidate.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(candidate))
			if err := validateLocator(candidate, bodies); err == nil {
				t.Fatal("invalid rekeyed locator was accepted")
			}
		})
	}
	roles := map[string]struct{}{"operation": {}}
	for name, mutate := range map[string]func(*validationSummary){
		"row count":  func(value *validationSummary) { value.CandidateAPISymbolCount++ },
		"role count": func(value *validationSummary) { value.APIElementRolesMaterialized++ },
		"operation ordering": func(value *validationSummary) {
			value.CapturedOperationKindCounts = append(value.CapturedOperationKindCounts, operationKindCount{OperationKind: "read", Count: 1})
		},
		"bad root":                 func(value *validationSummary) { value.SubjectSetRootSHA256 = "bad" },
		"source bytes":             func(value *validationSummary) { value.SourceBytesPresent = true },
		"wrong result":             func(value *validationSummary) { value.Result = resultCompleteWithGap },
		"invalid operation kind":   func(value *validationSummary) { value.CapturedOperationKindCounts[0].OperationKind = "Invalid Kind" },
		"operation count mismatch": func(value *validationSummary) { value.OperationApplicabilityCount++ },
		"subject count mismatch":   func(value *validationSummary) { value.CandidateSubjectCount++ },
		"derived set mismatch":     func(value *validationSummary) { value.FactSetRootSHA256 = verifyTestDigest("f") },
	} {
		t.Run(name, func(t *testing.T) {
			candidate, candidateBodies, candidateSets := validSemanticPlan()
			mutate(candidate.Summary)
			if err := validatePlan(candidate, roles, nil, nil, nil, candidateBodies, candidateSets); err == nil {
				t.Fatal("invalid summary was accepted")
			}
		})
	}
	if err := validatePlan(plan, roles, nil, nil, nil, bodies, sets); err != nil {
		t.Fatalf("baseline plan rejected: %v", err)
	}
}

func completeSemanticPlan() (*parsedPlan, map[string]exactEvidenceBody, map[string]compactStageSet, map[string]struct{}, map[string]relationshipConstraint, map[string]struct{}, map[string]struct{}) {
	plan, bodies, sets := validSemanticPlan()
	var locatorID string
	for id := range plan.Locators {
		locatorID = id
	}
	resource := apiSymbol{
		Role:               "resource",
		SemanticKey:        "record",
		DisplayName:        "Record",
		EvidenceLocatorIDs: []string{locatorID},
		DerivationBinding:  json.RawMessage(`{"proof":"resource"}`),
		AuthorityStatus:    symbolAuthorityStatusExact,
	}
	resource.ID = stableID("capi_sym", lengthPrefixedIdentityKey(resource.Role, resource.SemanticKey))
	plan.Symbols[resource.ID] = resource
	var operationID string
	for id, symbol := range plan.Symbols {
		if symbol.Role == "operation" {
			operationID = id
		}
	}
	relationship := apiRelationship{
		Label:             "returns",
		SourceID:          operationID,
		TargetID:          resource.ID,
		LocatorIDs:        []string{locatorID},
		DerivationBinding: json.RawMessage(`{"proof":"relationship"}`),
		AuthorityStatus:   relationAuthorityStatusExact,
	}
	relationship.ID = stableID("capi_rel", lengthPrefixedIdentityKey(relationship.Label, relationship.SourceID, relationship.TargetID))
	plan.Relationships[relationship.ID] = relationship
	property := apiPropertyClaim{
		Family:            "metadata",
		SubjectKind:       "api_symbol_object",
		SubjectID:         resource.ID,
		PropertyName:      "shape",
		CandidateValue:    json.RawMessage(`{"type":"object"}`),
		LocatorIDs:        []string{locatorID},
		DerivationBinding: json.RawMessage(`{"proof":"property"}`),
		AuthorityStatus:   propertyAuthorityStatusExact,
	}
	canonicalValue, _ := canonicalizeCandidateJSON(property.CandidateValue)
	property.ID = stableID("capi_prop", lengthPrefixedIdentityKey(property.Family, property.SubjectID, property.PropertyName, string(canonicalValue)))
	plan.Properties[property.ID] = property
	gap := graphGap{
		GapClass:                    "documentation_gap",
		BlockedSubjectKind:          "api_symbol_object",
		BlockedSubjectID:            resource.ID,
		BlockedClaimKind:            "property_claim",
		BlockedClaimID:              "write_shape",
		Disposition:                 "fail_closed",
		ApplicabilityProfileID:      "profile",
		ApplicabilityProfileVersion: "1",
		ApplicabilityProfileSHA256:  verifyTestDigest("6"),
		ApplicabilityRuleID:         "rule",
		EvidenceLocatorIDs:          []string{locatorID},
		GapProofBinding:             json.RawMessage(`{"proof":"gap"}`),
		DerivationBinding:           json.RawMessage(`{"proof":"derivation"}`),
	}
	gapKey, _ := candidateGraphGapIdentityKey(gap)
	gap.ID = stableID("capi_gap", gapKey)
	plan.Gaps[gap.ID] = gap
	sets["subject"] = compactStageSet{RootSHA256: verifyTestDigest("7"), Count: 3}
	sets["fact"] = compactStageSet{RootSHA256: verifyTestDigest("8"), Count: 2}
	sets["gap"] = compactStageSet{RootSHA256: verifyTestDigest("9"), Count: 1}
	plan.Summary = &validationSummary{
		CandidateEvidenceLocatorCount:     1,
		CandidateAPISymbolCount:           2,
		CandidateAPIRelationshipCount:     1,
		CandidateAPIPropertyClaimCount:    1,
		CandidateGraphGapCount:            1,
		APIElementRolesMaterialized:       2,
		APIRelationshipLabelsMaterialized: 1,
		APIPropertyFamiliesMaterialized:   1,
		CandidateOperationCount:           1,
		CapturedOperationKindCounts:       []operationKindCount{{OperationKind: "read", Count: 1}},
		OperationApplicabilityCount:       1,
		CandidateSubjectCount:             3,
		SubjectSetRootSHA256:              sets["subject"].RootSHA256,
		FactSetRootSHA256:                 sets["fact"].RootSHA256,
		GapSetRootSHA256:                  sets["gap"].RootSHA256,
		Result:                            resultCompleteWithGap,
	}
	return plan, bodies, sets,
		map[string]struct{}{"operation": {}, "resource": {}},
		map[string]relationshipConstraint{"returns": {EdgeLabel: "returns", SourceRole: "operation", TargetRole: "resource"}},
		map[string]struct{}{"metadata": {}},
		map[string]struct{}{"api_symbol_object": {}, "api_relationship_edge": {}}
}

func semanticRekeyRelationship(plan *parsedPlan, mutate func(*apiRelationship)) {
	for oldID, value := range plan.Relationships {
		mutate(&value)
		value.ID = stableID("capi_rel", lengthPrefixedIdentityKey(value.Label, value.SourceID, value.TargetID))
		delete(plan.Relationships, oldID)
		plan.Relationships[value.ID] = value
	}
}

func semanticRekeyProperty(plan *parsedPlan, mutate func(*apiPropertyClaim)) {
	for oldID, value := range plan.Properties {
		mutate(&value)
		canonical, err := canonicalizeCandidateJSON(value.CandidateValue)
		if err == nil {
			value.ID = stableID("capi_prop", lengthPrefixedIdentityKey(value.Family, value.SubjectID, value.PropertyName, string(canonical)))
		}
		delete(plan.Properties, oldID)
		plan.Properties[value.ID] = value
	}
}

func semanticRekeyGap(plan *parsedPlan, mutate func(*graphGap)) {
	for oldID, value := range plan.Gaps {
		mutate(&value)
		if key, err := candidateGraphGapIdentityKey(value); err == nil {
			value.ID = stableID("capi_gap", key)
		}
		delete(plan.Gaps, oldID)
		plan.Gaps[value.ID] = value
	}
}

func TestVerifySemanticCompletePlanTraversesRelationshipPropertyAndGapRules(t *testing.T) {
	plan, bodies, sets, roles, constraints, families, subjects := completeSemanticPlan()
	if err := validatePlan(plan, roles, constraints, families, subjects, bodies, sets); err != nil {
		t.Fatalf("complete closed plan rejected: %v", err)
	}
	for name, mutate := range map[string]func(*parsedPlan){
		"relationship unknown label": func(candidate *parsedPlan) {
			semanticRekeyRelationship(candidate, func(value *apiRelationship) { value.Label = "unknown" })
		},
		"relationship unresolved endpoint": func(candidate *parsedPlan) {
			semanticRekeyRelationship(candidate, func(value *apiRelationship) { value.TargetID = "missing" })
		},
		"relationship wrong roles": func(candidate *parsedPlan) {
			semanticRekeyRelationship(candidate, func(value *apiRelationship) { value.SourceID = value.TargetID })
		},
		"relationship source bytes": func(candidate *parsedPlan) {
			for id, value := range candidate.Relationships {
				value.SourceBytesPresent = true
				candidate.Relationships[id] = value
			}
		},
		"relationship invalid derivation": func(candidate *parsedPlan) {
			for id, value := range candidate.Relationships {
				value.DerivationBinding = json.RawMessage(`{`)
				candidate.Relationships[id] = value
			}
		},
		"relationship missing locator": func(candidate *parsedPlan) {
			for id, value := range candidate.Relationships {
				value.LocatorIDs = nil
				candidate.Relationships[id] = value
			}
		},
		"property unknown family": func(candidate *parsedPlan) {
			semanticRekeyProperty(candidate, func(value *apiPropertyClaim) { value.Family = "unknown" })
		},
		"property unknown subject kind": func(candidate *parsedPlan) {
			for id, value := range candidate.Properties {
				value.SubjectKind = "unknown"
				candidate.Properties[id] = value
			}
		},
		"property unknown symbol": func(candidate *parsedPlan) {
			semanticRekeyProperty(candidate, func(value *apiPropertyClaim) { value.SubjectID = "unknown" })
		},
		"property incomplete contract": func(candidate *parsedPlan) {
			for id, value := range candidate.Properties {
				value.PropertyName = ""
				candidate.Properties[id] = value
			}
		},
		"property invalid derivation": func(candidate *parsedPlan) {
			for id, value := range candidate.Properties {
				value.DerivationBinding = json.RawMessage(`{`)
				candidate.Properties[id] = value
			}
		},
		"property missing locator": func(candidate *parsedPlan) {
			for id, value := range candidate.Properties {
				value.LocatorIDs = nil
				candidate.Properties[id] = value
			}
		},
		"property noninteger value": func(candidate *parsedPlan) {
			semanticRekeyProperty(candidate, func(value *apiPropertyClaim) { value.CandidateValue = json.RawMessage(`1.5`) })
		},
		"gap materialization": func(candidate *parsedPlan) {
			for id, value := range candidate.Gaps {
				value.MaterializationEligible = true
				candidate.Gaps[id] = value
			}
		},
		"gap invalid class": func(candidate *parsedPlan) {
			for id, value := range candidate.Gaps {
				value.GapClass = "Invalid Class"
				candidate.Gaps[id] = value
			}
		},
		"gap invalid proof": func(candidate *parsedPlan) {
			for id, value := range candidate.Gaps {
				value.GapProofBinding = json.RawMessage(`{`)
				candidate.Gaps[id] = value
			}
		},
		"gap invalid derivation": func(candidate *parsedPlan) {
			for id, value := range candidate.Gaps {
				value.DerivationBinding = json.RawMessage(`{`)
				candidate.Gaps[id] = value
			}
		},
		"gap duplicate locator": func(candidate *parsedPlan) {
			semanticRekeyGap(candidate, func(value *graphGap) {
				value.EvidenceLocatorIDs = append(value.EvidenceLocatorIDs, value.EvidenceLocatorIDs[0])
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate, candidateBodies, candidateSets, candidateRoles, candidateConstraints, candidateFamilies, candidateSubjects := completeSemanticPlan()
			mutate(candidate)
			if err := validatePlan(candidate, candidateRoles, candidateConstraints, candidateFamilies, candidateSubjects, candidateBodies, candidateSets); err == nil {
				t.Fatal("invalid complete plan was accepted")
			}
		})
	}
	manifest := map[string]interface{}{}
	for _, key := range evidenceManifestBaseKeys {
		manifest[key] = "value"
	}
	manifest["representation"] = "machine_export"
	manifest["representation_coordinate"] = "coordinate"
	manifest["source_representation_kind"] = supportedEvidenceRepresentationKind
	manifest["canonical_bytes"] = manifestCanonicalBytesProfile
	artifact := artifactInput{Path: "fixture", Manifest: manifest, EvidenceBodyKind: evidenceBodyKindSourceDocument}
	if err := validateEvidenceArtifactManifest(artifact, map[string]struct{}{supportedEvidenceRepresentationKind: {}}); err != nil {
		t.Fatalf("valid evidence artifact manifest rejected: %v", err)
	}
	brokenKeys := artifact
	brokenKeys.Manifest = map[string]interface{}{}
	if err := validateEvidenceArtifactManifest(brokenKeys, map[string]struct{}{supportedEvidenceRepresentationKind: {}}); err == nil {
		t.Fatal("open evidence manifest keys accepted")
	}
	brokenProfile := artifact
	brokenProfile.Manifest = make(map[string]interface{}, len(manifest))
	for key, value := range manifest {
		brokenProfile.Manifest[key] = value
	}
	brokenProfile.Manifest["canonical_bytes"] = "other"
	if err := validateEvidenceArtifactManifest(brokenProfile, map[string]struct{}{supportedEvidenceRepresentationKind: {}}); err == nil {
		t.Fatal("wrong evidence manifest profile accepted")
	}
	wrongKind := artifact
	wrongKind.EvidenceBodyKind = "rendered_dom"
	if err := validateEvidenceArtifactManifest(wrongKind, map[string]struct{}{supportedEvidenceRepresentationKind: {}}); err == nil {
		t.Fatal("wrong evidence body kind accepted")
	}
	if exactObjectKeys(map[string]interface{}{"a": true}, []string{"a", "b"}) || containsExactString([]string{"a"}, "b") {
		t.Fatal("exact helper accepted missing member")
	}
}

func TestVerifySemanticReceiptAndClosedRegistries(t *testing.T) {
	receipt := Receipt{ReceiptKind: receiptKind, ReceiptVersion: receiptVersion, Result: "pass"}
	sealed, err := sealReceipt(receipt)
	if err != nil || validateReceiptIdentity(sealed) != nil {
		t.Fatalf("sealed receipt was not self-consistent: receipt=%+v err=%v", sealed, err)
	}
	sealed.Result = "tampered"
	if err := validateReceiptIdentity(sealed); err == nil {
		t.Fatal("tampered receipt identity accepted")
	}
	valid := []evidenceManifestBinding{{EvidenceManifestSHA256: verifyTestDigest("a"), EvidenceBodyKind: evidenceBodyKindSourceDocument, ConsumerRoles: []string{"api_graph_projection", "sample_shape_index"}}}
	if err := validateEvidenceManifestBindingRoster(valid); err != nil {
		t.Fatalf("valid roster rejected: %v", err)
	}
	for name, bindings := range map[string][]evidenceManifestBinding{
		"empty":           nil,
		"bad digest":      {{EvidenceManifestSHA256: "bad", EvidenceBodyKind: evidenceBodyKindSourceDocument}},
		"wrong body kind": {{EvidenceManifestSHA256: verifyTestDigest("a"), EvidenceBodyKind: "rendered_dom"}},
		"unordered roles": {{EvidenceManifestSHA256: verifyTestDigest("a"), EvidenceBodyKind: evidenceBodyKindSourceDocument, ConsumerRoles: []string{"sample_shape_index", "api_graph_projection"}}},
		"unknown role":    {{EvidenceManifestSHA256: verifyTestDigest("a"), EvidenceBodyKind: evidenceBodyKindSourceDocument, ConsumerRoles: []string{"unknown"}}},
		"duplicate digest": {
			{EvidenceManifestSHA256: verifyTestDigest("a"), EvidenceBodyKind: evidenceBodyKindSourceDocument},
			{EvidenceManifestSHA256: verifyTestDigest("a"), EvidenceBodyKind: evidenceBodyKindSourceDocument},
		},
		"duplicate role": {{EvidenceManifestSHA256: verifyTestDigest("a"), EvidenceBodyKind: evidenceBodyKindSourceDocument, ConsumerRoles: []string{"api_graph_projection", "api_graph_projection"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateEvidenceManifestBindingRoster(bindings); err == nil {
				t.Fatal("invalid evidence binding roster accepted")
			}
		})
	}
	if _, err := candidateGraphGapIdentityKey(graphGap{GapProofBinding: json.RawMessage(`{"proof":true}`), DerivationBinding: json.RawMessage(`{`)}); err == nil {
		t.Fatal("invalid gap derivation identity accepted")
	}
}

func semanticOODContract() oodContract {
	var ood oodContract
	ood.Sections.ObjectModel.Roles.CardinalityRule = "one role"
	ood.Sections.ObjectModel.Roles.AuthorityRule = "immutable"
	ood.Sections.ObjectModel.Roles.Roles = []string{"operation", "resource"}
	ood.Sections.ObjectModel.Properties.SchemaGovernanceRule = "closed"
	ood.Sections.ObjectModel.Properties.EvidenceRule = "exact"
	ood.Sections.ObjectModel.Properties.AuthorityExclusions = []string{"rendered_dom"}
	ood.Sections.ObjectModel.Properties.Families = []string{"metadata"}
	ood.Sections.ObjectModel.Properties.EligibleSubjects = []string{"api_symbol_object", "api_relationship_edge"}
	ood.Sections.ObjectModel.ExternalRelationshipAuthorityBoundary.MaterializationRule = "closed"
	ood.Sections.EdgeModel.Relationships.Family = "api_relationship"
	ood.Sections.EdgeModel.Relationships.SourceClass = "api_symbol"
	ood.Sections.EdgeModel.Relationships.TargetClass = "api_symbol"
	ood.Sections.EdgeModel.Relationships.Constraints = []relationshipConstraint{{EdgeLabel: "returns", SourceRole: "operation", TargetRole: "resource"}}
	ingestion := &ood.Sections.GraphMaterialization.ExternalReferenceIngestion
	ingestion.CanonicalIngestionExecutionModel.CapabilitySequence = []string{"authorize", "fetch"}
	ingestion.CanonicalIngestionExecutionModel.EntryCapability = "authorize"
	ingestion.ObjectClassesCreated = []string{"external_reference_doc"}
	ingestion.EdgeLabelsCreated = []string{"documents"}
	ingestion.SourceAuthorityPolicy.AllowedSourceClasses = []string{"official_documentation"}
	ingestion.SourceAuthorityPolicy.ForbiddenSourceClasses = []string{"unofficial_blog"}
	ingestion.SourceAuthorityPolicy.Rule = "closed"
	ood.Sections.IdentityModel.ExternalRepresentation.Kinds = []string{supportedEvidenceRepresentationKind}
	ood.Sections.IdentityModel.VersionCoordinateGrammar.ExternalEvidenceHashContract.CanonicalByteProfiles = map[string]json.RawMessage{
		componentByteDomainProfile:    json.RawMessage(`true`),
		manifestCanonicalBytesProfile: json.RawMessage(`true`),
	}
	return ood
}

func TestVerifySemanticOODNormalizationClosesEveryRegistry(t *testing.T) {
	ood := semanticOODContract()
	roles, constraints, families, subjects, err := normalizeOODContract(ood)
	if err != nil || len(roles) != 2 || constraints["returns"].TargetRole != "resource" || len(families) != 1 || len(subjects) != 2 {
		t.Fatalf("closed OOD normalization failed: roles=%v constraints=%v families=%v subjects=%v err=%v", roles, constraints, families, subjects, err)
	}
	kinds, err := normalizeExternalRepresentationKinds(ood)
	if err != nil || len(kinds) != 1 {
		t.Fatalf("closed representation registry failed: kinds=%v err=%v", kinds, err)
	}
	for name, mutate := range map[string]func(*oodContract){
		"missing role authority":    func(value *oodContract) { value.Sections.ObjectModel.Roles.AuthorityRule = "" },
		"missing property schema":   func(value *oodContract) { value.Sections.ObjectModel.Properties.SchemaGovernanceRule = "" },
		"missing property evidence": func(value *oodContract) { value.Sections.ObjectModel.Properties.EvidenceRule = "" },
		"duplicate exclusion": func(value *oodContract) {
			value.Sections.ObjectModel.Properties.AuthorityExclusions = []string{"dom", "dom"}
		},
		"missing external boundary": func(value *oodContract) {
			value.Sections.ObjectModel.ExternalRelationshipAuthorityBoundary.MaterializationRule = ""
		},
		"wrong edge family":       func(value *oodContract) { value.Sections.EdgeModel.Relationships.Family = "other" },
		"provider labels allowed": func(value *oodContract) { value.Sections.EdgeModel.Relationships.ProviderSpecificLabelsAllowed = true },
		"empty capability sequence": func(value *oodContract) {
			value.Sections.GraphMaterialization.ExternalReferenceIngestion.CanonicalIngestionExecutionModel.CapabilitySequence = nil
		},
		"empty object registry": func(value *oodContract) {
			value.Sections.GraphMaterialization.ExternalReferenceIngestion.ObjectClassesCreated = nil
		},
		"empty edge registry": func(value *oodContract) {
			value.Sections.GraphMaterialization.ExternalReferenceIngestion.EdgeLabelsCreated = nil
		},
		"empty allowed registry": func(value *oodContract) {
			value.Sections.GraphMaterialization.ExternalReferenceIngestion.SourceAuthorityPolicy.AllowedSourceClasses = nil
		},
		"empty policy rule": func(value *oodContract) {
			value.Sections.GraphMaterialization.ExternalReferenceIngestion.SourceAuthorityPolicy.Rule = ""
		},
		"wrong entry": func(value *oodContract) {
			value.Sections.GraphMaterialization.ExternalReferenceIngestion.CanonicalIngestionExecutionModel.EntryCapability = "fetch"
		},
		"overlapping source class": func(value *oodContract) {
			value.Sections.GraphMaterialization.ExternalReferenceIngestion.SourceAuthorityPolicy.ForbiddenSourceClasses = []string{"official_documentation"}
		},
		"duplicate role":            func(value *oodContract) { value.Sections.ObjectModel.Roles.Roles = []string{"operation", "operation"} },
		"empty role":                func(value *oodContract) { value.Sections.ObjectModel.Roles.Roles = []string{""} },
		"unknown constraint role":   func(value *oodContract) { value.Sections.EdgeModel.Relationships.Constraints[0].TargetRole = "unknown" },
		"unknown constraint source": func(value *oodContract) { value.Sections.EdgeModel.Relationships.Constraints[0].SourceRole = "unknown" },
		"incomplete constraint":     func(value *oodContract) { value.Sections.EdgeModel.Relationships.Constraints[0].EdgeLabel = "" },
		"duplicate constraint": func(value *oodContract) {
			value.Sections.EdgeModel.Relationships.Constraints = append(value.Sections.EdgeModel.Relationships.Constraints, value.Sections.EdgeModel.Relationships.Constraints[0])
		},
		"empty constraints": func(value *oodContract) { value.Sections.EdgeModel.Relationships.Constraints = nil },
		"duplicate property family": func(value *oodContract) {
			value.Sections.ObjectModel.Properties.Families = []string{"metadata", "metadata"}
		},
		"empty property family":  func(value *oodContract) { value.Sections.ObjectModel.Properties.Families = []string{""} },
		"empty eligible subject": func(value *oodContract) { value.Sections.ObjectModel.Properties.EligibleSubjects = []string{""} },
		"duplicate eligible subject": func(value *oodContract) {
			value.Sections.ObjectModel.Properties.EligibleSubjects = []string{"api_symbol_object", "api_symbol_object"}
		},
		"no eligible subjects": func(value *oodContract) { value.Sections.ObjectModel.Properties.EligibleSubjects = nil },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := semanticOODContract()
			mutate(&candidate)
			if _, _, _, _, err := normalizeOODContract(candidate); err == nil {
				t.Fatal("invalid OOD registry accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*oodContract){
		"empty":        func(value *oodContract) { value.Sections.IdentityModel.ExternalRepresentation.Kinds = nil },
		"empty member": func(value *oodContract) { value.Sections.IdentityModel.ExternalRepresentation.Kinds = []string{""} },
		"duplicate": func(value *oodContract) {
			value.Sections.IdentityModel.ExternalRepresentation.Kinds = []string{supportedEvidenceRepresentationKind, supportedEvidenceRepresentationKind}
		},
		"missing supported": func(value *oodContract) {
			value.Sections.IdentityModel.ExternalRepresentation.Kinds = []string{"other"}
		},
		"missing byte profile": func(value *oodContract) {
			value.Sections.IdentityModel.VersionCoordinateGrammar.ExternalEvidenceHashContract.CanonicalByteProfiles = nil
		},
		"missing manifest profile": func(value *oodContract) {
			value.Sections.IdentityModel.VersionCoordinateGrammar.ExternalEvidenceHashContract.CanonicalByteProfiles = map[string]json.RawMessage{componentByteDomainProfile: json.RawMessage(`true`)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := semanticOODContract()
			mutate(&candidate)
			if _, err := normalizeExternalRepresentationKinds(candidate); err == nil {
				t.Fatal("invalid representation registry accepted")
			}
		})
	}
}

func TestVerifySemanticNormalizationHelpersRejectAmbiguousInputs(t *testing.T) {
	if got := exactLineDelimiterProfile([]byte("a\r\nb\r\n")); got != "CRLF" {
		t.Fatalf("CRLF profile=%q", got)
	}
	if got := exactLineDelimiterProfile([]byte("a\nb\n")); got != "LF" {
		t.Fatalf("LF profile=%q", got)
	}
	if got := exactLineDelimiterProfile([]byte("a\rb\n")); got != "mixed" {
		t.Fatalf("mixed profile=%q", got)
	}
	if got := exactLineDelimiterProfile([]byte("plain")); got != "none" {
		t.Fatalf("none profile=%q", got)
	}
	identities := sortedEvidenceBodyIdentityKeys(map[evidenceBodyIdentity]int{
		{ManifestSHA256: "b", SourceRef: "b", ContentSHA256: "b"}: 1,
		{ManifestSHA256: "a", SourceRef: "z", ContentSHA256: "z"}: 1,
		{ManifestSHA256: "a", SourceRef: "a", ContentSHA256: "z"}: 1,
	})
	if len(identities) != 3 || identities[0].SourceRef != "a" || identities[2].ManifestSHA256 != "b" {
		t.Fatalf("identity sort=%v", identities)
	}
	locators := map[string]evidenceLocator{"one": {ID: "one"}}
	if err := validateLocatorRefs("owner", []string{"one"}, locators); err != nil {
		t.Fatalf("valid locator ref rejected: %v", err)
	}
	for name, ids := range map[string][]string{"empty": nil, "duplicate": {"one", "one"}, "unknown": {"unknown"}} {
		t.Run(name, func(t *testing.T) {
			if err := validateLocatorRefs("owner", ids, locators); err == nil {
				t.Fatal("invalid locator refs accepted")
			}
		})
	}
	if err := validateOptionalLocatorRefs("owner", nil, locators); err != nil {
		t.Fatalf("optional empty refs rejected: %v", err)
	}
	gap := graphGap{GapProofBinding: json.RawMessage(`{"proof":true}`), DerivationBinding: json.RawMessage(`{"derived":true}`), EvidenceLocatorIDs: []string{"b", "a"}}
	first, err := candidateGraphGapIdentityKey(gap)
	if err != nil {
		t.Fatal(err)
	}
	gap.EvidenceLocatorIDs = []string{"a", "b"}
	second, err := candidateGraphGapIdentityKey(gap)
	if err != nil || first != second {
		t.Fatalf("gap identity was not locator-order independent: first=%q second=%q err=%v", first, second, err)
	}
	gap.GapProofBinding = json.RawMessage(`{`)
	if _, err := candidateGraphGapIdentityKey(gap); err == nil {
		t.Fatal("invalid gap proof accepted")
	}
	if raw, _, err := loadGraphCompileSelection(Options{graphCompileRequestRaw: []byte(`{"request":true}`)}); err != nil || string(raw) != `{"request":true}` {
		t.Fatalf("in-memory graph selection raw=%q err=%v", raw, err)
	}
	if _, _, err := loadGraphCompileSelection(Options{graphCompileInputs: StageCompileInputs{}}); err == nil {
		t.Fatal("empty in-memory graph request accepted")
	}
	if _, _, err := loadGraphCompileSelection(Options{graphCompileInputs: StageCompileInputs{Materials: []StageMaterial{{Role: "plan"}}}}); err == nil {
		t.Fatal("material-only graph selection accepted without request bytes")
	}
}

func TestVerifySemanticEvidenceClosureAndSummaryBindExactBodies(t *testing.T) {
	plan, bodies, _ := validSemanticPlan()
	manifestDigest := plan.Manifest.EvidenceManifestBindings[0].EvidenceManifestSHA256
	loaded := loadedEvidence{
		Artifacts:          map[string]artifactInput{manifestDigest: {EvidenceBodyKind: evidenceBodyKindSourceDocument}},
		Bodies:             bodies,
		BodyCoordinateRows: 1,
	}
	if err := validateEvidenceClosure(plan, loaded); err != nil {
		t.Fatalf("exact evidence closure rejected: %v", err)
	}
	for name, mutate := range map[string]func(*loadedEvidence, *parsedPlan){
		"missing bound artifact": func(value *loadedEvidence, _ *parsedPlan) { value.Artifacts = map[string]artifactInput{} },
		"wrong body kind": func(value *loadedEvidence, _ *parsedPlan) {
			for digest, artifact := range value.Artifacts {
				artifact.EvidenceBodyKind = "rendered_dom"
				value.Artifacts[digest] = artifact
			}
		},
		"extra artifact": func(value *loadedEvidence, _ *parsedPlan) {
			value.Artifacts[verifyTestDigest("f")] = artifactInput{EvidenceBodyKind: evidenceBodyKindSourceDocument}
		},
		"bad coordinate count": func(value *loadedEvidence, _ *parsedPlan) { value.BodyCoordinateRows = 2 },
		"locator unknown manifest": func(_ *loadedEvidence, candidate *parsedPlan) {
			for id, locator := range candidate.Locators {
				locator.EvidenceManifestSHA256 = verifyTestDigest("f")
				candidate.Locators[id] = locator
			}
		},
		"locator missing body": func(value *loadedEvidence, candidate *parsedPlan) {
			for id, locator := range candidate.Locators {
				delete(value.Bodies, locator.SourceContentSHA256)
				candidate.Locators[id] = locator
			}
		},
		"unbound coordinate owner": func(value *loadedEvidence, _ *parsedPlan) {
			for digest, body := range value.Bodies {
				for coordinate := range body.Coordinates {
					body.Coordinates[coordinate] = verifyTestDigest("f")
				}
				value.Bodies[digest] = body
			}
		},
		"locator coordinate missing": func(value *loadedEvidence, candidate *parsedPlan) {
			for _, locator := range candidate.Locators {
				body := value.Bodies[locator.SourceContentSHA256]
				delete(body.Coordinates, evidenceSourceCoordinate{Ref: locator.SourceRefs[0], URL: locator.SourceURLs[0]})
				value.Bodies[locator.SourceContentSHA256] = body
			}
		},
		"locator coordinate wrong owner": func(value *loadedEvidence, candidate *parsedPlan) {
			for _, locator := range candidate.Locators {
				body := value.Bodies[locator.SourceContentSHA256]
				body.Coordinates[evidenceSourceCoordinate{Ref: locator.SourceRefs[0], URL: locator.SourceURLs[0]}] = verifyTestDigest("f")
				value.Bodies[locator.SourceContentSHA256] = body
			}
		},
		"unreached coordinate": func(_ *loadedEvidence, candidate *parsedPlan) { candidate.Locators = map[string]evidenceLocator{} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate, candidateBodies, _ := validSemanticPlan()
			candidateDigest := candidate.Manifest.EvidenceManifestBindings[0].EvidenceManifestSHA256
			candidateLoaded := loadedEvidence{Artifacts: map[string]artifactInput{candidateDigest: {EvidenceBodyKind: evidenceBodyKindSourceDocument}}, Bodies: candidateBodies, BodyCoordinateRows: 1}
			mutate(&candidateLoaded, candidate)
			if err := validateEvidenceClosure(candidate, candidateLoaded); err == nil {
				t.Fatal("invalid evidence closure accepted")
			}
		})
	}
	input := artifactInput{
		Path:              "fixture",
		EvidenceBodyKind:  evidenceBodyKindSourceDocument,
		EvidenceBodyCount: 1,
		EvidenceByteCount: 4,
		RowKindCounts:     map[string]int{"external_evidence_body": 1},
		ValidationSummary: map[string]interface{}{
			"row_kind": "validation_summary", "captured_source_count": json.Number("1"), "missing_source_refs": []interface{}{}, "rendered_dom_body_accepted": false,
			"result": "structural_candidate_selected_source_document_capture", "selected_representation_is_only_evidence_body": true,
			"selected_source_count": json.Number("1"), "total_exact_source_bytes": json.Number("4"), "unexpected_source_refs": []interface{}{},
		},
	}
	if err := validateEvidenceValidationSummary(input); err != nil {
		t.Fatalf("exact evidence summary rejected: %v", err)
	}
	for name, mutate := range map[string]func(*artifactInput){
		"missing summary":   func(value *artifactInput) { value.ValidationSummary = nil },
		"wrong body kind":   func(value *artifactInput) { value.EvidenceBodyKind = "rendered_dom" },
		"unknown key":       func(value *artifactInput) { value.ValidationSummary["unknown"] = true },
		"wrong row kind":    func(value *artifactInput) { value.ValidationSummary["row_kind"] = "other" },
		"count mismatch":    func(value *artifactInput) { value.EvidenceByteCount++ },
		"body row mismatch": func(value *artifactInput) { value.RowKindCounts["external_evidence_body"] = 0 },
		"selected body false": func(value *artifactInput) {
			value.ValidationSummary["selected_representation_is_only_evidence_body"] = false
		},
		"rendered dom accepted": func(value *artifactInput) { value.ValidationSummary["rendered_dom_body_accepted"] = true },
		"unclosed roster":       func(value *artifactInput) { value.ValidationSummary["missing_source_refs"] = []interface{}{"missing"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := input
			candidate.RowKindCounts = map[string]int{"external_evidence_body": 1}
			candidate.ValidationSummary = make(map[string]interface{}, len(input.ValidationSummary))
			for key, value := range input.ValidationSummary {
				candidate.ValidationSummary[key] = value
			}
			mutate(&candidate)
			if err := validateEvidenceValidationSummary(candidate); err == nil {
				t.Fatal("invalid evidence summary accepted")
			}
		})
	}
}

func TestVerifySemanticStageSelectionAndMaterialAreExact(t *testing.T) {
	raw := []byte(`{"row_kind":"artifact_manifest"}`)
	identity := stageArtifactIdentity{Role: "plan", ID: "graph", Version: "1", RawSHA256: sha256Hex(raw)}
	proof := graphPlanParseProof{seal: graphPlanParseAuthority, structural: graphPlanSchemaBindingProof{seal: graphPlanSchemaBindingAuthority, plan: identity}}
	inputs := StageCompileInputs{Materials: []StageMaterial{{Role: identity.Role, ID: identity.ID, Version: identity.Version, Raw: raw}}}
	selected, err := exactGraphPlanMaterial(proof, inputs)
	if err != nil || !bytes.Equal(selected, raw) {
		t.Fatalf("exact graph material selected=%q err=%v", selected, err)
	}
	for name, candidate := range map[string]graphPlanParseProof{
		"unsealed":     {},
		"wrong digest": {seal: graphPlanParseAuthority, structural: graphPlanSchemaBindingProof{seal: graphPlanSchemaBindingAuthority, plan: stageArtifactIdentity{Role: identity.Role, ID: identity.ID, Version: identity.Version, RawSHA256: verifyTestDigest("a")}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := exactGraphPlanMaterial(candidate, inputs); err == nil {
				t.Fatal("invalid graph proof accepted")
			}
		})
	}
	if _, err := exactGraphPlanMaterial(proof, StageCompileInputs{}); err == nil {
		t.Fatal("missing exact graph material accepted")
	}
	duplicate := inputs
	duplicate.Materials = append(duplicate.Materials, duplicate.Materials[0])
	if _, err := exactGraphPlanMaterial(proof, duplicate); err == nil {
		t.Fatal("duplicate exact graph material accepted")
	}
	roles, labels, families := planMaterializedVocabulary(&parsedPlan{
		Symbols: map[string]apiSymbol{"a": {Role: "operation"}}, Relationships: map[string]apiRelationship{"b": {Label: "returns"}}, Properties: map[string]apiPropertyClaim{"c": {Family: "metadata"}},
	})
	if len(roles) != 1 || len(labels) != 1 || len(families) != 1 {
		t.Fatalf("materialized vocabulary roles=%v labels=%v families=%v", roles, labels, families)
	}
	if err := validateProviderVerificationTopLevelPathSyntax(Options{OODSpecPath: "valid-on-unix"}); err != nil {
		t.Fatalf("portable authority input path rejected: %v", err)
	}
}

func TestVerifySemanticDependencyArtifactReadersFailClosed(t *testing.T) {
	directory := t.TempDir()
	rawPath := filepath.Join(directory, "authority.txt")
	emptyPath := filepath.Join(directory, "empty.txt")
	jsonPath := filepath.Join(directory, "object.json")
	if err := os.WriteFile(rawPath, []byte("immutable authority bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsonPath, []byte(`{"authority":"closed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if input, err := readArtifactInput(rawPath); err != nil || input.Structured || !bytes.Equal(input.Raw, []byte("immutable authority bytes")) {
		t.Fatalf("raw authority input=%+v err=%v", input, err)
	}
	if input, err := readArtifactInput(jsonPath); err != nil || input.Structured || !bytes.Equal(input.Raw, []byte(`{"authority":"closed"}`)) {
		t.Fatalf("JSON authority input=%+v err=%v", input, err)
	}
	for name, paths := range map[string][]string{
		"empty path":      {""},
		"empty file":      {emptyPath},
		"duplicate bytes": {rawPath, rawPath},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadDependencyArtifacts(paths); err == nil {
				t.Fatal("invalid dependency artifact input accepted")
			}
		})
	}
	if _, err := readArtifactInput(""); err == nil {
		t.Fatal("empty artifact path accepted")
	}
}
