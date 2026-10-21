package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExecutableDocumentationDerivationProfileSetReexecutesExactPrograms(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	programRaw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	programObject := map[string]interface{}{}
	if err := decodeOneValidationProfileJSON(programRaw, &programObject); err != nil {
		t.Fatal(err)
	}
	rows := executableDocumentationProfileRows(t, reference, programObject)
	profiles, err := parseExecutableDocumentationDerivationProfiles(rows)
	if err != nil {
		t.Fatal(err)
	}
	first, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	second, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Results) != 1 || len(first.Results[0].Facts) != 1 || first.ProfileResultSetRootSHA256 != second.ProfileResultSetRootSHA256 || first.ProfilePageSetRootSHA256 != second.ProfilePageSetRootSHA256 || first.ExecutionSetRootSHA256 != second.ExecutionSetRootSHA256 || !isLowerSHA256(first.ProfilePageSetRootSHA256) || !isLowerSHA256(first.ExecutionSetRootSHA256) || first.ClassificationProofSHA256 != proof.contentSHA256 || first.FactCount != 1 || first.OutcomeCount != 1 || first.PageCount <= 0 || first.Status != documentationDerivationProfileExecutionSetComplete {
		t.Fatalf("profile execution set did not close deterministically: %#v", first)
	}
}

func TestExecutableDocumentationDerivationProfileSetEnforcesAggregateLimits(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	programRaw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	programObject := map[string]interface{}{}
	if err := decodeOneValidationProfileJSON(programRaw, &programObject); err != nil {
		t.Fatal(err)
	}
	profiles, err := parseExecutableDocumentationDerivationProfiles(executableDocumentationProfileRows(t, reference, programObject))
	if err != nil {
		t.Fatal(err)
	}
	first := profiles[dependencyProfileReferenceKey(reference)]
	second := first
	second.Reference.id = "fixture_second_profile"
	second.SemanticGeneration, err = newDocumentationSemanticGenerationBinding(second.ClaimKind, second.Reference, second.ValidationSchema)
	if err != nil {
		t.Fatal(err)
	}
	profiles[dependencyProfileReferenceKey(second.Reference)] = second

	profileLimited := canonicalDocumentationDerivationProfileSetHardLimits()
	profileLimited.profileCount = 1
	if _, err := executeDocumentationDerivationProfileSetWithLimits(profiles, proof, bodies, profileLimited); err == nil || !strings.Contains(err.Error(), "profile count") {
		t.Fatalf("profile-set count cap error = %v", err)
	}

	factLimited := canonicalDocumentationDerivationProfileSetHardLimits()
	factLimited.factCount = 1
	if _, err := executeDocumentationDerivationProfileSetWithLimits(profiles, proof, bodies, factLimited); err == nil || !strings.Contains(err.Error(), "aggregate reserved facts exceed limit") {
		t.Fatalf("profile-set aggregate fact cap error = %v", err)
	}
	if _, err := executeDocumentationDerivationProfileSetWithLimits(profiles, proof, map[string]exactEvidenceBody{}, factLimited); err == nil || !strings.Contains(err.Error(), "aggregate reserved facts exceed limit") {
		t.Fatalf("profile-set did not refuse aggregate reservation before touching invalid evidence: %v", err)
	}

	ruleLimited := canonicalDocumentationDerivationProfileSetHardLimits()
	ruleLimited.ruleCount = 1
	if _, err := executeDocumentationDerivationProfileSetWithLimits(profiles, proof, bodies, ruleLimited); err == nil || !strings.Contains(err.Error(), "aggregate rules exceed limit") {
		t.Fatalf("profile-set aggregate rule cap error = %v", err)
	}

	programByteLimited := canonicalDocumentationDerivationProfileSetHardLimits()
	programByteLimited.canonicalProgramBytes = 1
	if _, err := executeDocumentationDerivationProfileSetWithLimits(profiles, proof, bodies, programByteLimited); err == nil || !strings.Contains(err.Error(), "canonical program bytes") {
		t.Fatalf("profile-set aggregate program-byte cap error = %v", err)
	}

	schemaByteLimited := canonicalDocumentationDerivationProfileSetHardLimits()
	schemaByteLimited.canonicalSchemaBytes = 1
	if _, err := executeDocumentationDerivationProfileSetWithLimits(profiles, proof, bodies, schemaByteLimited); err == nil || !strings.Contains(err.Error(), "canonical claim schema bytes") {
		t.Fatalf("profile-set aggregate schema-byte cap error = %v", err)
	}
}

func TestExecutableDocumentationDerivationProfileSetSealsSuccessfulRestrictedLimits(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	programRaw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	program, err := parseExactDocumentationDerivationProgram(programRaw, reference)
	if err != nil {
		t.Fatal(err)
	}
	generation := exactDocumentationFieldClaimSchemaFixture(t, reference)
	profile := executableDocumentationDerivationProfile{Reference: reference, ClaimKind: generation.claimKind, ValidationSchema: generation.claimSchema, SemanticGeneration: generation, Program: program}
	limits := canonicalDocumentationDerivationProfileSetHardLimits()
	limits.profileCount = 1
	limits.ruleCount = int64(len(program.OrderedRules))
	limits.canonicalProgramBytes = int64(len(programRaw))
	limits.canonicalSchemaBytes = int64(len(generation.claimSchema.canonicalSchemaBytes))
	limits.factCount = program.MaxOutputFactsPerRun
	limits.canonicalFactBytes = program.MaxOutputBytesPerRun
	limits.outcomeCount = program.MaxOccurrenceOutcomesPerRun
	limits.canonicalOutcomeBytes = program.MaxCanonicalOutcomeBytesPerRun
	limits.retainedCanonicalBytes = program.MaxOutputBytesPerRun + program.MaxCanonicalOutcomeBytesPerRun
	limits.pageCount = program.MaxOutputPagesPerRun
	limits.matcherEvaluations = program.MaxMatcherEvaluationsPerRun
	limits.matcherInputBytes = program.MaxMatcherInputBytesPerRun
	set, err := executeDocumentationDerivationProfileSetWithLimits(map[string]executableDocumentationDerivationProfile{dependencyProfileReferenceKey(reference): profile}, proof, bodies, limits)
	if err != nil {
		t.Fatal(err)
	}
	if set.Limits.profileCount != 1 || set.Limits.ruleCount != int64(len(program.OrderedRules)) {
		t.Fatalf("restricted exact ceilings were not sealed: %#v", set.Limits)
	}
	if err := validateExactDocumentationDerivationProfileExecutionSet(set, proof); err != nil {
		t.Fatalf("sealed restricted execution set did not revalidate: %v", err)
	}
}

func TestExecutableDocumentationDerivationProfileParsingPreflightsRosterBeforePrograms(t *testing.T) {
	rows := dependencySemanticRows{byKind: map[string][]dependencySemanticRow{
		"derivation_profile": make([]dependencySemanticRow, maxDocumentationDerivationProfilesPerSet+1),
		"validation_schema":  {{data: map[string]interface{}{}}},
	}}
	if _, err := parseExecutableDocumentationDerivationProfiles(rows); err == nil || !strings.Contains(err.Error(), "profile count") {
		t.Fatalf("oversized profile roster was not refused before program parsing: %v", err)
	}
}

func TestExecutableDocumentationDerivationProfileSetBudgetIsContentDerived(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	programRaw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	program, err := parseExactDocumentationDerivationProgram(programRaw, reference)
	if err != nil {
		t.Fatal(err)
	}
	generation := exactDocumentationFieldClaimSchemaFixture(t, reference)
	profile := executableDocumentationDerivationProfile{Reference: reference, ClaimKind: generation.claimKind, ValidationSchema: generation.claimSchema, SemanticGeneration: generation, Program: program}
	first, err := executeDocumentationDerivationProfileSet(map[string]executableDocumentationDerivationProfile{dependencyProfileReferenceKey(reference): profile}, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}

	program.MaxOutputFactsPerRun++
	mutatedRaw, err := json.Marshal(program)
	if err != nil {
		t.Fatal(err)
	}
	mutatedCanonical, err := canonicalizeCandidateJSON(mutatedRaw)
	if err != nil {
		t.Fatal(err)
	}
	mutatedReference := reference
	mutatedReference.digest = sha256Hex(mutatedCanonical)
	mutatedProgram, err := parseExactDocumentationDerivationProgram(mutatedCanonical, mutatedReference)
	if err != nil {
		t.Fatal(err)
	}
	mutatedGeneration, err := newDocumentationSemanticGenerationBinding(generation.claimKind, mutatedReference, generation.claimSchema)
	if err != nil {
		t.Fatal(err)
	}
	mutatedProfile := executableDocumentationDerivationProfile{Reference: mutatedReference, ClaimKind: generation.claimKind, ValidationSchema: generation.claimSchema, SemanticGeneration: mutatedGeneration, Program: mutatedProgram}
	second, err := executeDocumentationDerivationProfileSet(map[string]executableDocumentationDerivationProfile{dependencyProfileReferenceKey(mutatedReference): mutatedProfile}, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if first.Limits.factCount == second.Limits.factCount || first.ProfileBudgetRootSHA256 == second.ProfileBudgetRootSHA256 || first.ExecutionSetRootSHA256 == second.ExecutionSetRootSHA256 {
		t.Fatal("admitted program budget change did not change the reserved limit and content-derived roots")
	}
}

func TestExecutableDocumentationDerivationProfileSetRejectsResultAndSetTamper(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	programRaw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	program, err := parseExactDocumentationDerivationProgram(programRaw, reference)
	if err != nil {
		t.Fatal(err)
	}
	generation := exactDocumentationFieldClaimSchemaFixture(t, reference)
	profile := executableDocumentationDerivationProfile{Reference: reference, ClaimKind: generation.claimKind, ValidationSchema: generation.claimSchema, SemanticGeneration: generation, Program: program}
	set, err := executeDocumentationDerivationProfileSet(map[string]executableDocumentationDerivationProfile{dependencyProfileReferenceKey(reference): profile}, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*exactDocumentationDerivationProfileExecutionSet){
		"result root": func(value *exactDocumentationDerivationProfileExecutionSet) {
			value.Results[0].ResultRootSHA256 = sha256Hex([]byte("different result"))
		},
		"page root": func(value *exactDocumentationDerivationProfileExecutionSet) {
			value.Results[0].PageSetRootSHA256 = sha256Hex([]byte("different page set"))
		},
		"outcome bytes":  func(value *exactDocumentationDerivationProfileExecutionSet) { value.Results[0].CanonicalOutcomeBytes++ },
		"matcher actual": func(value *exactDocumentationDerivationProfileExecutionSet) { value.Results[0].MatcherInputByteCount++ },
		"set budget root": func(value *exactDocumentationDerivationProfileExecutionSet) {
			value.ProfileBudgetRootSHA256 = sha256Hex([]byte("different budget"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := set
			tampered.Results = append([]exactDocumentationDerivationExecutionResult(nil), set.Results...)
			mutate(&tampered)
			if err := validateExactDocumentationDerivationProfileExecutionSet(tampered, proof); err == nil {
				t.Fatal("tampered execution-set evidence was accepted")
			}
		})
	}
}

func TestExecutableDocumentationDerivationProfileSetRootsBindExactClaimSchemaGeneration(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	programRaw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	programObject := map[string]interface{}{}
	if err := decodeOneValidationProfileJSON(programRaw, &programObject); err != nil {
		t.Fatal(err)
	}
	profiles, err := parseExecutableDocumentationDerivationProfiles(executableDocumentationProfileRows(t, reference, programObject))
	if err != nil {
		t.Fatal(err)
	}
	first, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	key := dependencyProfileReferenceKey(reference)
	profile := profiles[key]
	var schema map[string]interface{}
	if err := decodeOneValidationProfileJSON(profile.ValidationSchema.canonicalSchemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	schema["title"] = "same accepted outputs, different exact schema generation"
	mutatedBytes := mustValidationProfileJSON(t, schema)
	mutatedReference := profile.ValidationSchema.reference
	mutatedReference.digest = sha256Hex(mutatedBytes)
	mutatedSchema, err := resolveDocumentationClaimSchema(mutatedReference, profile.ClaimKind, string(mutatedBytes))
	if err != nil {
		t.Fatal(err)
	}
	profile.ValidationSchema = mutatedSchema
	profile.SemanticGeneration, err = newDocumentationSemanticGenerationBinding(profile.ClaimKind, profile.Reference, mutatedSchema)
	if err != nil {
		t.Fatal(err)
	}
	profiles[key] = profile
	second, err := executeDocumentationDerivationProfileSet(profiles, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if first.ProfilePageSetRootSHA256 == second.ProfilePageSetRootSHA256 || first.ProfileResultSetRootSHA256 == second.ProfileResultSetRootSHA256 || first.Results[0].ResultRootSHA256 == second.Results[0].ResultRootSHA256 {
		t.Fatal("claim-schema generation change did not change every profile/result root")
	}
}

func TestExecutableDocumentationDerivationProfileRejectsMissingOrDigestMismatchedProgram(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	programRaw, reference, _, _ := exactDocumentationProgramFixture(t, body, 1, 1)
	programObject := map[string]interface{}{}
	if err := decodeOneValidationProfileJSON(programRaw, &programObject); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*dependencySemanticRows){
		"missing": func(rows *dependencySemanticRows) {
			delete(rows.byKind["derivation_profile"][0].data, "program")
		},
		"digest": func(rows *dependencySemanticRows) {
			rows.byKind["derivation_profile"][0].data["derivation_profile_sha256"] = strings.Repeat("0", 64)
		},
		"validation binding": func(rows *dependencySemanticRows) {
			binding := rows.byKind["derivation_profile"][0].data["validation_schema_binding"].(map[string]interface{})
			binding["validation_schema_sha256"] = strings.Repeat("0", 64)
		},
		"claim kind": func(rows *dependencySemanticRows) {
			rows.byKind["derivation_profile"][0].data["claim_kind"] = "different_claim_kind"
		},
	} {
		t.Run(name, func(t *testing.T) {
			rows := executableDocumentationProfileRows(t, reference, programObject)
			mutate(&rows)
			if _, err := parseExecutableDocumentationDerivationProfiles(rows); err == nil {
				t.Fatal("invalid executable profile was accepted")
			}
		})
	}
}

func executableDocumentationProfileRows(t *testing.T, reference dependencyProfileReference, program map[string]interface{}) dependencySemanticRows {
	t.Helper()
	generation := exactDocumentationFieldClaimSchemaFixture(t, reference)
	validation := generation.claimSchema
	objects := []map[string]interface{}{
		{"row_kind": "artifact_manifest", "artifact": "fixture_derivation_profiles", "artifact_version": "1"},
		{
			"row_kind":             "validation_schema",
			"validation_schema_id": validation.reference.id, "validation_schema_version": validation.reference.version,
			"validation_schema_sha256": validation.reference.digest, "claim_kind": validation.claimKind,
			"schema_dialect": validationProfileDraft202012, "canonical_schema_json": string(validation.canonicalSchemaBytes),
		},
		{
			"row_kind": "derivation_profile", "derivation_profile_id": reference.id,
			"derivation_profile_version": reference.version, "derivation_profile_sha256": reference.digest,
			"claim_kind": "field_contract",
			"validation_schema_binding": map[string]interface{}{
				"validation_schema_id": validation.reference.id, "validation_schema_version": validation.reference.version,
				"validation_schema_sha256": validation.reference.digest,
			},
			"program": program,
		},
		{"row_kind": "validation_summary"},
	}
	raw := make([]byte, 0)
	for _, object := range objects {
		encoded, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		raw = append(raw, encoded...)
		raw = append(raw, '\n')
	}
	input := artifactInput{Path: "fixture_derivation_profiles.jsonl", Raw: raw, SHA256: sha256Hex(raw), Structured: true}
	rows, err := parseDependencySemanticRows(input)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
