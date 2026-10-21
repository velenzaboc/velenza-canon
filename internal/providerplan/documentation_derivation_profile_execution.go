package providerplan

import (
	"encoding/json"
	"fmt"
)

const (
	documentationDerivationProfileExecutionSetComplete = "complete"
	documentationDerivationProfileExecutionSetKind     = "exact_documentation_derivation_profile_execution_set_v1"
	maxDocumentationDerivationProfilesPerSet           = int64(1024)
	maxDocumentationDerivationRulesPerSet              = int64(1 << 16)
	maxDocumentationDerivationProgramBytesPerSet       = int64(256 << 20)
	maxDocumentationClaimSchemaBytesPerSet             = int64(128 << 20)
)

type exactDocumentationDerivationProfileSetLimits struct {
	profileCount           int64
	ruleCount              int64
	canonicalProgramBytes  int64
	canonicalSchemaBytes   int64
	factCount              int64
	canonicalFactBytes     int64
	outcomeCount           int64
	canonicalOutcomeBytes  int64
	retainedCanonicalBytes int64
	pageCount              int64
	matcherEvaluations     int64
	matcherInputBytes      int64
}

func canonicalDocumentationDerivationProfileSetHardLimits() exactDocumentationDerivationProfileSetLimits {
	return exactDocumentationDerivationProfileSetLimits{
		profileCount:           maxDocumentationDerivationProfilesPerSet,
		ruleCount:              maxDocumentationDerivationRulesPerSet,
		canonicalProgramBytes:  maxDocumentationDerivationProgramBytesPerSet,
		canonicalSchemaBytes:   maxDocumentationClaimSchemaBytesPerSet,
		factCount:              maxDocumentationFactsPerRun,
		canonicalFactBytes:     maxDocumentationBytesPerRun,
		outcomeCount:           maxDocumentationOccurrenceOutcomesPerRun,
		canonicalOutcomeBytes:  maxDocumentationCanonicalOutcomeBytesPerRun,
		retainedCanonicalBytes: maxDocumentationBytesPerRun + maxDocumentationCanonicalOutcomeBytesPerRun,
		pageCount:              maxDocumentationPagesPerRun,
		matcherEvaluations:     maxDocumentationMatcherEvaluationsPerRun,
		matcherInputBytes:      maxDocumentationMatcherInputBytesPerRun,
	}
}

type executableDocumentationDerivationProfile struct {
	Reference          dependencyProfileReference
	ClaimKind          string
	ValidationSchema   documentationClaimSchemaAuthority
	SemanticGeneration documentationSemanticGenerationBinding
	Program            exactDocumentationDerivationProgram
}

type exactDocumentationDerivationProfileExecutionSet struct {
	seal                       *exactDocumentationDerivationProfileExecutionSetSeal
	Profiles                   []executableDocumentationDerivationProfile
	Results                    []exactDocumentationDerivationExecutionResult
	ClassificationProofSHA256  string
	ProfileBudgetRootSHA256    string
	ProfilePageSetRootSHA256   string
	ProfileResultSetRootSHA256 string
	ExecutionSetRootSHA256     string
	RuleCount                  int64
	CanonicalProgramBytes      int64
	CanonicalClaimSchemaBytes  int64
	FactCount                  int64
	CanonicalFactBytes         int64
	OutcomeCount               int64
	CanonicalOutcomeBytes      int64
	RetainedCanonicalBytes     int64
	PageCount                  int64
	MatcherEvaluationCount     int64
	MatcherInputByteCount      int64
	Limits                     exactDocumentationDerivationProfileSetLimits
	Status                     string
}

type exactDocumentationDerivationProfileExecutionSetSeal struct{}

var exactDocumentationDerivationProfileExecutionSetAuthority = &exactDocumentationDerivationProfileExecutionSetSeal{}

type exactDocumentationDerivationProfileExecutionSetIdentity struct {
	ExecutionSetKind            string `json:"execution_set_kind"`
	ClassificationProofSHA256   string `json:"classification_proof_sha256"`
	ProfileBudgetRootSHA256     string `json:"profile_budget_root_sha256"`
	ProfilePageSetRootSHA256    string `json:"profile_page_set_root_sha256"`
	ProfileResultSetRootSHA256  string `json:"profile_result_set_root_sha256"`
	ProfileCount                int64  `json:"profile_count"`
	ProfileCountLimit           int64  `json:"profile_count_limit"`
	RuleCount                   int64  `json:"rule_count"`
	RuleCountLimit              int64  `json:"rule_count_limit"`
	CanonicalProgramBytes       int64  `json:"canonical_program_bytes"`
	CanonicalProgramByteLimit   int64  `json:"canonical_program_byte_limit"`
	CanonicalClaimSchemaBytes   int64  `json:"canonical_claim_schema_bytes"`
	CanonicalClaimSchemaLimit   int64  `json:"canonical_claim_schema_byte_limit"`
	FactCount                   int64  `json:"fact_count"`
	FactCountLimit              int64  `json:"fact_count_limit"`
	CanonicalFactBytes          int64  `json:"canonical_fact_bytes"`
	CanonicalFactByteLimit      int64  `json:"canonical_fact_byte_limit"`
	OutcomeCount                int64  `json:"outcome_count"`
	OutcomeCountLimit           int64  `json:"outcome_count_limit"`
	CanonicalOutcomeBytes       int64  `json:"canonical_outcome_bytes"`
	CanonicalOutcomeByteLimit   int64  `json:"canonical_outcome_byte_limit"`
	RetainedCanonicalBytes      int64  `json:"retained_canonical_bytes"`
	RetainedCanonicalByteLimit  int64  `json:"retained_canonical_byte_limit"`
	PageCount                   int64  `json:"page_count"`
	PageCountLimit              int64  `json:"page_count_limit"`
	MatcherEvaluationCount      int64  `json:"matcher_evaluation_count"`
	MatcherEvaluationCountLimit int64  `json:"matcher_evaluation_count_limit"`
	MatcherInputByteCount       int64  `json:"matcher_input_byte_count"`
	MatcherInputByteLimit       int64  `json:"matcher_input_byte_limit"`
	Status                      string `json:"status"`
}

// parseExecutableDocumentationDerivationProfiles resolves executable program
// bytes from the already schema-validated derivation-profile artifact. The
// profile digest is the canonical executable program digest; descriptive row
// metadata cannot replace executable authority.
func parseExecutableDocumentationDerivationProfiles(rows dependencySemanticRows) (map[string]executableDocumentationDerivationProfile, error) {
	hard := canonicalDocumentationDerivationProfileSetHardLimits()
	profileRows := rows.byKind["derivation_profile"]
	schemaRows := rows.byKind["validation_schema"]
	if len(profileRows) == 0 || int64(len(profileRows)) > hard.profileCount {
		return nil, fmt.Errorf("documentation derivation profile count %d is outside the closed set ceiling %d", len(profileRows), hard.profileCount)
	}
	if len(schemaRows) == 0 || int64(len(schemaRows)) > hard.profileCount {
		return nil, fmt.Errorf("documentation validation schema count %d is outside the closed set ceiling %d", len(schemaRows), hard.profileCount)
	}
	var schemaBytes int64
	for _, row := range schemaRows {
		canonicalSchema, ok := semanticString(row.data, "canonical_schema_json")
		if !ok || int64(len(canonicalSchema)) > hard.canonicalSchemaBytes-schemaBytes {
			return nil, semanticRowError(rows, row, "documentation validation schema bytes exceed the closed set ceiling %d", hard.canonicalSchemaBytes)
		}
		schemaBytes += int64(len(canonicalSchema))
	}
	var programBytes, ruleCount int64
	for _, row := range profileRows {
		programObject, ok := semanticObject(row.data, "program")
		if !ok {
			return nil, semanticRowError(rows, row, "documentation derivation profile has no executable program")
		}
		programRaw, err := json.Marshal(programObject)
		if err != nil {
			return nil, semanticRowError(rows, row, "marshal documentation derivation program: %v", err)
		}
		canonicalProgram, err := canonicalizeCandidateJSON(programRaw)
		if err != nil {
			return nil, semanticRowError(rows, row, "canonicalize documentation derivation program: %v", err)
		}
		if int64(len(canonicalProgram)) > hard.canonicalProgramBytes-programBytes {
			return nil, semanticRowError(rows, row, "documentation derivation program bytes exceed the closed set ceiling %d", hard.canonicalProgramBytes)
		}
		programBytes += int64(len(canonicalProgram))
		rules, ok := semanticObjectSlice(programObject, "ordered_rules")
		if !ok || int64(len(rules)) > hard.ruleCount-ruleCount {
			return nil, semanticRowError(rows, row, "documentation derivation rule count exceeds the closed set ceiling %d", hard.ruleCount)
		}
		ruleCount += int64(len(rules))
	}
	validationSchemas := make(map[string]documentationClaimSchemaAuthority, len(rows.byKind["validation_schema"]))
	for _, row := range rows.byKind["validation_schema"] {
		reference, referenceOK := dependencyProfileReferenceFromFields(row.data, "validation_schema")
		claimKind, claimOK := semanticString(row.data, "claim_kind")
		dialect, dialectOK := semanticString(row.data, "schema_dialect")
		canonicalSchema, schemaOK := semanticString(row.data, "canonical_schema_json")
		if !referenceOK || !claimOK || !dialectOK || dialect != validationProfileDraft202012 || !schemaOK {
			return nil, semanticRowError(rows, row, "documentation validation schema is incomplete")
		}
		authority, err := resolveDocumentationClaimSchema(reference, claimKind, canonicalSchema)
		if err != nil {
			return nil, semanticRowError(rows, row, "documentation validation schema: %v", err)
		}
		key := dependencyProfileReferenceKey(reference)
		if _, duplicate := validationSchemas[key]; duplicate {
			return nil, semanticRowError(rows, row, "duplicate documentation validation schema coordinate")
		}
		validationSchemas[key] = authority
	}
	if len(validationSchemas) == 0 {
		return nil, fmt.Errorf("documentation derivation artifact has no exact validation schemas")
	}

	profiles := make(map[string]executableDocumentationDerivationProfile, len(rows.byKind["derivation_profile"]))
	usedValidationSchemas := map[string]struct{}{}
	for _, row := range rows.byKind["derivation_profile"] {
		reference, referenceOK := dependencyProfileReferenceFromFields(row.data, "derivation_profile")
		claimKind, claimOK := semanticString(row.data, "claim_kind")
		validationBinding, bindingOK := semanticObject(row.data, "validation_schema_binding")
		validationReference, validationOK := dependencyProfileReferenceFromFields(validationBinding, "validation_schema")
		programObject, programOK := semanticObject(row.data, "program")
		if !referenceOK || !claimOK || !bindingOK || !validationOK || !programOK {
			return nil, semanticRowError(rows, row, "documentation derivation profile has no exact executable program coordinate")
		}
		programRaw, err := json.Marshal(programObject)
		if err != nil {
			return nil, semanticRowError(rows, row, "marshal documentation derivation program: %v", err)
		}
		program, err := parseExactDocumentationDerivationProgram(programRaw, reference)
		if err != nil {
			return nil, semanticRowError(rows, row, "%v", err)
		}
		validationSchema, exists := validationSchemas[dependencyProfileReferenceKey(validationReference)]
		if !exists || validationSchema.claimKind != claimKind {
			return nil, semanticRowError(rows, row, "documentation derivation profile does not bind one exact same-claim validation schema")
		}
		usedValidationSchemas[dependencyProfileReferenceKey(validationReference)] = struct{}{}
		generation, err := newDocumentationSemanticGenerationBinding(claimKind, reference, validationSchema)
		if err != nil {
			return nil, semanticRowError(rows, row, "%v", err)
		}
		key := dependencyProfileReferenceKey(reference)
		if _, duplicate := profiles[key]; duplicate {
			return nil, semanticRowError(rows, row, "duplicate executable documentation derivation profile coordinate")
		}
		profiles[key] = executableDocumentationDerivationProfile{
			Reference: reference, ClaimKind: claimKind, ValidationSchema: validationSchema,
			SemanticGeneration: generation, Program: program,
		}
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("documentation derivation artifact has no executable derivation profiles")
	}
	if err := requireExactSet("documentation derivation executable validation-schema roster", usedValidationSchemas, stringMapKeysAsSet(validationSchemas)); err != nil {
		return nil, err
	}
	return profiles, nil
}

func executeDocumentationDerivationProfileSet(profiles map[string]executableDocumentationDerivationProfile, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody) (exactDocumentationDerivationProfileExecutionSet, error) {
	return executeDocumentationDerivationProfileSetWithLimits(profiles, proof, bodies, canonicalDocumentationDerivationProfileSetHardLimits())
}

func executeDocumentationDerivationProfileSetWithLimits(profiles map[string]executableDocumentationDerivationProfile, proof sourceClassificationSelectionProof, bodies map[string]exactEvidenceBody, hardLimits exactDocumentationDerivationProfileSetLimits) (exactDocumentationDerivationProfileExecutionSet, error) {
	var set exactDocumentationDerivationProfileExecutionSet
	if err := validateDocumentationDerivationProfileSetLimits(hardLimits); err != nil {
		return set, err
	}
	if err := validateSourceClassificationSelectionProof(proof); err != nil {
		return set, fmt.Errorf("documentation derivation profile set requires a sealed exact classification proof: %w", err)
	}
	keys := sortedSetKeys(stringMapKeysAsSet(profiles))
	limits, budgetRoot, ruleCount, programBytes, schemaBytes, err := reserveDocumentationDerivationProfileSet(profiles, keys, hardLimits)
	if err != nil {
		return set, err
	}
	seenFacts := map[string]string{}
	seenOutcomes := map[string]string{}
	rootRows := make([][]byte, 0, len(keys))
	pageRows := make([][]byte, 0, len(keys))
	for _, key := range keys {
		profile := profiles[key]
		result, err := executeExactDocumentationDerivationWithManifest(profile.Reference, profile.Program, profile.SemanticGeneration, proof, bodies)
		if err != nil {
			return set, fmt.Errorf("execute documentation derivation profile %q: %w", key, err)
		}
		if err := validateExactDocumentationDerivationProfileResult(profile, proof, result); err != nil {
			return exactDocumentationDerivationProfileExecutionSet{}, fmt.Errorf("documentation derivation profile %q result: %w", key, err)
		}
		if err := accumulateDocumentationDerivationProfileResult(&set, result, limits); err != nil {
			return exactDocumentationDerivationProfileExecutionSet{}, fmt.Errorf("documentation derivation profile %q aggregate closure: %w", key, err)
		}
		for _, fact := range result.Facts {
			if prior, duplicate := seenFacts[fact.FactID]; duplicate {
				return set, fmt.Errorf("documentation derivation profiles %q and %q duplicate fact %s", prior, key, fact.FactID)
			}
			seenFacts[fact.FactID] = key
		}
		for _, outcome := range result.Outcomes {
			if prior, duplicate := seenOutcomes[outcome.OutcomeID]; duplicate {
				return set, fmt.Errorf("documentation derivation profiles %q and %q duplicate outcome %s", prior, key, outcome.OutcomeID)
			}
			seenOutcomes[outcome.OutcomeID] = key
		}
		set.Profiles = append(set.Profiles, profile)
		set.Results = append(set.Results, result)
		rootRows = append(rootRows, []byte(lengthPrefixedIdentityKey(key, profile.SemanticGeneration.identitySHA256, result.ResultRootSHA256)))
		pageRows = append(pageRows, []byte(lengthPrefixedIdentityKey(key, profile.SemanticGeneration.identitySHA256, result.PageSetRootSHA256)))
	}
	set.ClassificationProofSHA256 = proof.contentSHA256
	set.ProfileBudgetRootSHA256 = budgetRoot
	set.ProfilePageSetRootSHA256 = stageCanonicalSetRoot(pageRows)
	set.ProfileResultSetRootSHA256 = stageCanonicalSetRoot(rootRows)
	set.RuleCount = ruleCount
	set.CanonicalProgramBytes = programBytes
	set.CanonicalClaimSchemaBytes = schemaBytes
	set.Limits = limits
	set.Status = documentationDerivationProfileExecutionSetComplete
	identity := exactDocumentationDerivationProfileExecutionSetIdentityFor(set)
	raw, err := json.Marshal(identity)
	if err != nil {
		return exactDocumentationDerivationProfileExecutionSet{}, err
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		return exactDocumentationDerivationProfileExecutionSet{}, err
	}
	set.ExecutionSetRootSHA256 = sha256Hex(canonical)
	set.seal = exactDocumentationDerivationProfileExecutionSetAuthority
	if err := validateExactDocumentationDerivationProfileExecutionSet(set, proof); err != nil {
		return exactDocumentationDerivationProfileExecutionSet{}, err
	}
	return set, nil
}

func validateDocumentationDerivationProfileSetLimits(limits exactDocumentationDerivationProfileSetLimits) error {
	actual := []int64{limits.profileCount, limits.ruleCount, limits.canonicalProgramBytes, limits.canonicalSchemaBytes, limits.factCount, limits.canonicalFactBytes, limits.outcomeCount, limits.canonicalOutcomeBytes, limits.retainedCanonicalBytes, limits.pageCount, limits.matcherEvaluations, limits.matcherInputBytes}
	canonical := canonicalDocumentationDerivationProfileSetHardLimits()
	maximum := []int64{
		canonical.profileCount,
		canonical.ruleCount,
		canonical.canonicalProgramBytes,
		canonical.canonicalSchemaBytes,
		canonical.factCount,
		canonical.canonicalFactBytes,
		canonical.outcomeCount,
		canonical.canonicalOutcomeBytes,
		canonical.retainedCanonicalBytes,
		canonical.pageCount,
		canonical.matcherEvaluations,
		canonical.matcherInputBytes,
	}
	for index := range actual {
		if actual[index] <= 0 || actual[index] > maximum[index] {
			return fmt.Errorf("documentation derivation profile-set resource limit %d is outside its closed canonical ceiling", index)
		}
	}
	return nil
}

type exactDocumentationDerivationProfileBudgetIdentity struct {
	ProfileID                      string `json:"profile_id"`
	ProfileVersion                 string `json:"profile_version"`
	ProfileSHA256                  string `json:"profile_sha256"`
	SemanticGenerationSHA256       string `json:"semantic_generation_sha256"`
	ValidationSchemaID             string `json:"validation_schema_id"`
	ValidationSchemaVersion        string `json:"validation_schema_version"`
	ValidationSchemaSHA256         string `json:"validation_schema_sha256"`
	CanonicalProgramBytes          int64  `json:"canonical_program_bytes"`
	CanonicalClaimSchemaBytes      int64  `json:"canonical_claim_schema_bytes"`
	RuleCount                      int64  `json:"rule_count"`
	MaxOutputFactsPerRun           int64  `json:"max_output_facts_per_run"`
	MaxOutputBytesPerRun           int64  `json:"max_output_bytes_per_run"`
	MaxOutputPagesPerRun           int64  `json:"max_output_pages_per_run"`
	MaxMatcherEvaluationsPerRun    int64  `json:"max_matcher_evaluations_per_run"`
	MaxMatcherInputBytesPerRun     int64  `json:"max_matcher_input_bytes_per_run"`
	MaxOccurrenceOutcomesPerRun    int64  `json:"max_occurrence_outcomes_per_run"`
	MaxCanonicalOutcomeBytesPerRun int64  `json:"max_canonical_outcome_bytes_per_run"`
}

func reserveDocumentationDerivationProfileSet(profiles map[string]executableDocumentationDerivationProfile, keys []string, hard exactDocumentationDerivationProfileSetLimits) (exactDocumentationDerivationProfileSetLimits, string, int64, int64, int64, error) {
	var reserved exactDocumentationDerivationProfileSetLimits
	if len(keys) == 0 || int64(len(keys)) > hard.profileCount {
		return reserved, "", 0, 0, 0, fmt.Errorf("documentation derivation profile count %d is outside the closed set limit %d", len(keys), hard.profileCount)
	}
	reserved.profileCount = hard.profileCount
	reserved.ruleCount = hard.ruleCount
	reserved.canonicalProgramBytes = hard.canonicalProgramBytes
	reserved.canonicalSchemaBytes = hard.canonicalSchemaBytes
	budgetRows := make([][]byte, 0, len(keys))
	seenSchemas := map[string]struct{}{}
	var ruleCount, programBytes, schemaBytes int64
	for _, key := range keys {
		profile := profiles[key]
		normalized, err := normalizeExecutableDocumentationDerivationProfile(key, profile)
		if err != nil {
			return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, err
		}
		profile = normalized
		profiles[key] = profile
		programRaw, err := json.Marshal(profile.Program)
		if err != nil {
			return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, err
		}
		canonicalProgram, err := canonicalizeCandidateJSON(programRaw)
		if err != nil || sha256Hex(canonicalProgram) != profile.Reference.digest {
			return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, fmt.Errorf("documentation derivation profile %q program bytes differ from its exact coordinate", key)
		}
		if err := addDocumentationProfileSetMetric("canonical program bytes", &programBytes, int64(len(canonicalProgram)), hard.canonicalProgramBytes); err != nil {
			return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, err
		}
		if err := addDocumentationProfileSetMetric("rules", &ruleCount, int64(len(profile.Program.OrderedRules)), hard.ruleCount); err != nil {
			return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, err
		}
		schemaKey := dependencyProfileReferenceKey(profile.ValidationSchema.reference)
		if _, seen := seenSchemas[schemaKey]; !seen {
			if err := addDocumentationProfileSetMetric("canonical claim schema bytes", &schemaBytes, int64(len(profile.ValidationSchema.canonicalSchemaBytes)), hard.canonicalSchemaBytes); err != nil {
				return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, err
			}
			seenSchemas[schemaKey] = struct{}{}
		}
		program := profile.Program
		for _, metric := range []struct {
			label string
			value *int64
			add   int64
			limit int64
		}{
			{"reserved facts", &reserved.factCount, program.MaxOutputFactsPerRun, hard.factCount},
			{"reserved canonical fact bytes", &reserved.canonicalFactBytes, program.MaxOutputBytesPerRun, hard.canonicalFactBytes},
			{"reserved outcomes", &reserved.outcomeCount, program.MaxOccurrenceOutcomesPerRun, hard.outcomeCount},
			{"reserved canonical outcome bytes", &reserved.canonicalOutcomeBytes, program.MaxCanonicalOutcomeBytesPerRun, hard.canonicalOutcomeBytes},
			{"reserved pages", &reserved.pageCount, program.MaxOutputPagesPerRun, hard.pageCount},
			{"reserved matcher evaluations", &reserved.matcherEvaluations, program.MaxMatcherEvaluationsPerRun, hard.matcherEvaluations},
			{"reserved matcher input bytes", &reserved.matcherInputBytes, program.MaxMatcherInputBytesPerRun, hard.matcherInputBytes},
		} {
			if err := addDocumentationProfileSetMetric(metric.label, metric.value, metric.add, metric.limit); err != nil {
				return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, err
			}
		}
		if program.MaxOutputBytesPerRun > hard.retainedCanonicalBytes-program.MaxCanonicalOutcomeBytesPerRun {
			return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, fmt.Errorf("documentation derivation profile %q retained-byte reservation exceeds the closed set ceiling", key)
		}
		if err := addDocumentationProfileSetMetric("reserved retained canonical bytes", &reserved.retainedCanonicalBytes, program.MaxOutputBytesPerRun+program.MaxCanonicalOutcomeBytesPerRun, hard.retainedCanonicalBytes); err != nil {
			return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, err
		}
		budget := exactDocumentationDerivationProfileBudgetIdentity{
			ProfileID: profile.Reference.id, ProfileVersion: profile.Reference.version, ProfileSHA256: profile.Reference.digest,
			SemanticGenerationSHA256: profile.SemanticGeneration.identitySHA256,
			ValidationSchemaID:       profile.ValidationSchema.reference.id, ValidationSchemaVersion: profile.ValidationSchema.reference.version, ValidationSchemaSHA256: profile.ValidationSchema.reference.digest,
			CanonicalProgramBytes: int64(len(canonicalProgram)), CanonicalClaimSchemaBytes: int64(len(profile.ValidationSchema.canonicalSchemaBytes)), RuleCount: int64(len(program.OrderedRules)),
			MaxOutputFactsPerRun: program.MaxOutputFactsPerRun, MaxOutputBytesPerRun: program.MaxOutputBytesPerRun, MaxOutputPagesPerRun: program.MaxOutputPagesPerRun,
			MaxMatcherEvaluationsPerRun: program.MaxMatcherEvaluationsPerRun, MaxMatcherInputBytesPerRun: program.MaxMatcherInputBytesPerRun,
			MaxOccurrenceOutcomesPerRun: program.MaxOccurrenceOutcomesPerRun, MaxCanonicalOutcomeBytesPerRun: program.MaxCanonicalOutcomeBytesPerRun,
		}
		canonicalBudget, err := canonicalDocumentationBytes(budget)
		if err != nil {
			return exactDocumentationDerivationProfileSetLimits{}, "", 0, 0, 0, err
		}
		budgetRows = append(budgetRows, canonicalBudget)
	}
	return reserved, stageCanonicalSetRoot(budgetRows), ruleCount, programBytes, schemaBytes, nil
}

func normalizeExecutableDocumentationDerivationProfile(key string, profile executableDocumentationDerivationProfile) (executableDocumentationDerivationProfile, error) {
	if dependencyProfileReferenceKey(profile.Reference) != key || profile.ClaimKind == "" || profile.ClaimKind != profile.ValidationSchema.claimKind ||
		dependencyProfileReferenceKey(profile.ValidationSchema.reference) != dependencyProfileReferenceKey(profile.SemanticGeneration.claimSchema.reference) ||
		profile.ValidationSchema.resolved == nil || sha256Hex(profile.ValidationSchema.canonicalSchemaBytes) != profile.ValidationSchema.reference.digest {
		return executableDocumentationDerivationProfile{}, fmt.Errorf("documentation derivation profile map key %q does not equal its exact profile and claim-schema coordinate", key)
	}
	if err := validateDocumentationSemanticGenerationBinding(profile.SemanticGeneration); err != nil {
		return executableDocumentationDerivationProfile{}, fmt.Errorf("documentation derivation profile %q semantic generation: %w", key, err)
	}
	raw, err := json.Marshal(profile.Program)
	if err != nil {
		return executableDocumentationDerivationProfile{}, err
	}
	normalized, err := parseExactDocumentationDerivationProgram(raw, profile.Reference)
	if err != nil {
		return executableDocumentationDerivationProfile{}, fmt.Errorf("documentation derivation profile %q executable program: %w", key, err)
	}
	profile.Program = normalized
	return profile, nil
}

func addDocumentationProfileSetMetric(label string, value *int64, add, limit int64) error {
	if add < 0 || *value < 0 || add > limit || *value > limit-add {
		return fmt.Errorf("documentation derivation profile-set aggregate %s exceed limit %d", label, limit)
	}
	*value += add
	return nil
}

func validateExactDocumentationDerivationProfileResult(profile executableDocumentationDerivationProfile, proof sourceClassificationSelectionProof, result exactDocumentationDerivationExecutionResult) error {
	if result.seal != exactDocumentationDerivationExecutionResultAuthority || result.ExecutionKind != exactDocumentationDerivationExecutionKind || result.Status != exactDocumentationDerivationComplete ||
		dependencyProfileReferenceKey(result.Profile) != dependencyProfileReferenceKey(profile.Reference) || result.SemanticGenerationSHA256 != profile.SemanticGeneration.identitySHA256 ||
		result.Provider != proof.provider || result.EvidenceRosterSHA256 != proof.evidenceSelectionRosterSHA256 || result.ClassificationProofSHA256 != proof.contentSHA256 ||
		result.PageCount <= 0 || result.PageCount > profile.Program.MaxOutputPagesPerRun || !isLowerSHA256(result.PageSetRootSHA256) ||
		result.MatcherEvaluationCount < 0 || result.MatcherEvaluationCount > profile.Program.MaxMatcherEvaluationsPerRun ||
		result.MatcherInputByteCount < 0 || result.MatcherInputByteCount > profile.Program.MaxMatcherInputBytesPerRun ||
		result.MatcherInputByteLimitPerInputUnit != profile.Program.MaxMatcherInputBytesPerInputUnit || result.MatcherInputByteLimitPerRun != profile.Program.MaxMatcherInputBytesPerRun {
		return fmt.Errorf("execution result authority, page seal, or run-pinned matcher actuals are invalid")
	}
	factIDs := map[string]struct{}{}
	var factBytes int64
	for index, fact := range result.Facts {
		if index > 0 && result.Facts[index-1].FactID >= fact.FactID {
			return fmt.Errorf("fact roster is not strictly identity-sorted")
		}
		if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil || dependencyProfileReferenceKey(fact.Profile) != dependencyProfileReferenceKey(profile.Reference) || fact.Provider != proof.provider || fact.EvidenceRosterSHA256 != proof.evidenceSelectionRosterSHA256 {
			return fmt.Errorf("fact %q authority or integrity is invalid", fact.FactID)
		}
		canonical, err := canonicalExactDocumentationFactEnvelopeBytes(fact)
		if err != nil || int64(len(canonical)) > profile.Program.MaxOutputBytesPerRun-factBytes {
			return fmt.Errorf("fact %q canonical bytes exceed the run-pinned result budget", fact.FactID)
		}
		factBytes += int64(len(canonical))
		factIDs[fact.FactID] = struct{}{}
	}
	if int64(len(result.Facts)) > profile.Program.MaxOutputFactsPerRun || result.FactSetRootSHA256 != exactDocumentationFactRoot(result.Facts) || result.CanonicalFactBytes != factBytes {
		return fmt.Errorf("fact root, count, or canonical byte actual disagrees")
	}
	outcomeRows := make([][]byte, len(result.Outcomes))
	derivedFactIDs := map[string]struct{}{}
	var outcomeBytes int64
	for index, outcome := range result.Outcomes {
		if index > 0 && result.Outcomes[index-1].OutcomeID >= outcome.OutcomeID {
			return fmt.Errorf("outcome roster is not strictly identity-sorted")
		}
		canonical, err := validateExactDocumentationDerivationOccurrenceOutcome(profile.Reference, proof, outcome)
		if err != nil || int64(len(canonical)) > profile.Program.MaxCanonicalOutcomeBytesPerRun-outcomeBytes {
			return fmt.Errorf("outcome %q authority or canonical bytes are invalid", outcome.OutcomeID)
		}
		outcomeBytes += int64(len(canonical))
		outcomeRows[index] = canonical
		for _, factID := range outcome.DerivedFactIDs {
			if _, exists := factIDs[factID]; !exists {
				return fmt.Errorf("outcome %q names unknown fact %q", outcome.OutcomeID, factID)
			}
			if _, duplicate := derivedFactIDs[factID]; duplicate {
				return fmt.Errorf("fact %q is named by more than one outcome", factID)
			}
			derivedFactIDs[factID] = struct{}{}
		}
	}
	if err := requireExactSet("documentation derivation result outcome/fact roster", derivedFactIDs, factIDs); err != nil {
		return err
	}
	if int64(len(result.Outcomes)) > profile.Program.MaxOccurrenceOutcomesPerRun || result.OutcomeSetRootSHA256 != stageCanonicalSetRoot(outcomeRows) || result.CanonicalOutcomeBytes != outcomeBytes ||
		result.CanonicalFactBytes > result.RetainedCanonicalBytes || result.CanonicalOutcomeBytes != result.RetainedCanonicalBytes-result.CanonicalFactBytes {
		return fmt.Errorf("outcome root, count, canonical bytes, or retained-byte relation disagrees")
	}
	identity := exactDocumentationDerivationResultIdentity{
		ExecutionKind: result.ExecutionKind, ProfileID: result.Profile.id, ProfileVersion: result.Profile.version, ProfileSHA256: result.Profile.digest,
		SemanticGenerationSHA256: result.SemanticGenerationSHA256, Provider: result.Provider, EvidenceRosterSHA256: result.EvidenceRosterSHA256, ClassificationProofSHA256: result.ClassificationProofSHA256,
		OutcomeCount: int64(len(result.Outcomes)), OutcomeSetRootSHA256: result.OutcomeSetRootSHA256, FactCount: int64(len(result.Facts)), FactSetRootSHA256: result.FactSetRootSHA256,
		CanonicalFactBytes: result.CanonicalFactBytes, CanonicalOutcomeBytes: result.CanonicalOutcomeBytes, RetainedCanonicalBytes: result.RetainedCanonicalBytes,
		MatcherEvaluationCount: result.MatcherEvaluationCount, MatcherInputByteCount: result.MatcherInputByteCount, MatcherInputByteLimitPerInputUnit: result.MatcherInputByteLimitPerInputUnit, MatcherInputByteLimitPerRun: result.MatcherInputByteLimitPerRun,
		PageCount: result.PageCount, PageSetRootSHA256: result.PageSetRootSHA256, Status: result.Status,
	}
	canonicalIdentity, err := canonicalDocumentationBytes(identity)
	if err != nil || sha256Hex(canonicalIdentity) != result.ResultRootSHA256 {
		return fmt.Errorf("execution result root differs from its exact evidence")
	}
	return nil
}

func exactDocumentationDerivationProfileExecutionSetIdentityFor(set exactDocumentationDerivationProfileExecutionSet) exactDocumentationDerivationProfileExecutionSetIdentity {
	return exactDocumentationDerivationProfileExecutionSetIdentity{
		ExecutionSetKind: documentationDerivationProfileExecutionSetKind, ClassificationProofSHA256: set.ClassificationProofSHA256,
		ProfileBudgetRootSHA256: set.ProfileBudgetRootSHA256, ProfilePageSetRootSHA256: set.ProfilePageSetRootSHA256, ProfileResultSetRootSHA256: set.ProfileResultSetRootSHA256,
		ProfileCount: int64(len(set.Profiles)), ProfileCountLimit: set.Limits.profileCount,
		RuleCount: set.RuleCount, RuleCountLimit: set.Limits.ruleCount,
		CanonicalProgramBytes: set.CanonicalProgramBytes, CanonicalProgramByteLimit: set.Limits.canonicalProgramBytes,
		CanonicalClaimSchemaBytes: set.CanonicalClaimSchemaBytes, CanonicalClaimSchemaLimit: set.Limits.canonicalSchemaBytes,
		FactCount: set.FactCount, FactCountLimit: set.Limits.factCount, CanonicalFactBytes: set.CanonicalFactBytes, CanonicalFactByteLimit: set.Limits.canonicalFactBytes,
		OutcomeCount: set.OutcomeCount, OutcomeCountLimit: set.Limits.outcomeCount, CanonicalOutcomeBytes: set.CanonicalOutcomeBytes, CanonicalOutcomeByteLimit: set.Limits.canonicalOutcomeBytes,
		RetainedCanonicalBytes: set.RetainedCanonicalBytes, RetainedCanonicalByteLimit: set.Limits.retainedCanonicalBytes,
		PageCount: set.PageCount, PageCountLimit: set.Limits.pageCount, MatcherEvaluationCount: set.MatcherEvaluationCount, MatcherEvaluationCountLimit: set.Limits.matcherEvaluations,
		MatcherInputByteCount: set.MatcherInputByteCount, MatcherInputByteLimit: set.Limits.matcherInputBytes, Status: set.Status,
	}
}

func validateExactDocumentationDerivationProfileExecutionSet(set exactDocumentationDerivationProfileExecutionSet, proof sourceClassificationSelectionProof) error {
	if set.seal != exactDocumentationDerivationProfileExecutionSetAuthority || set.Status != documentationDerivationProfileExecutionSetComplete || set.ClassificationProofSHA256 != proof.contentSHA256 || len(set.Profiles) == 0 || len(set.Profiles) != len(set.Results) {
		return fmt.Errorf("documentation derivation profile execution set is absent or incomplete")
	}
	profiles := make(map[string]executableDocumentationDerivationProfile, len(set.Profiles))
	keys := make([]string, len(set.Profiles))
	rootRows := make([][]byte, len(set.Profiles))
	pageRows := make([][]byte, len(set.Profiles))
	var actual exactDocumentationDerivationProfileExecutionSet
	seenFacts := map[string]struct{}{}
	seenOutcomes := map[string]struct{}{}
	for index, profile := range set.Profiles {
		key := dependencyProfileReferenceKey(profile.Reference)
		if index > 0 && keys[index-1] >= key {
			return fmt.Errorf("documentation derivation profile execution roster is not strictly coordinate-sorted")
		}
		keys[index] = key
		normalized, err := normalizeExecutableDocumentationDerivationProfile(key, profile)
		if err != nil {
			return err
		}
		profile = normalized
		profiles[key] = profile
		result := set.Results[index]
		if err := validateExactDocumentationDerivationProfileResult(profile, proof, result); err != nil {
			return fmt.Errorf("documentation derivation profile %q result: %w", key, err)
		}
		if err := accumulateDocumentationDerivationProfileResult(&actual, result, set.Limits); err != nil {
			return err
		}
		for _, fact := range result.Facts {
			if _, duplicate := seenFacts[fact.FactID]; duplicate {
				return fmt.Errorf("documentation derivation profile set duplicates fact %q", fact.FactID)
			}
			seenFacts[fact.FactID] = struct{}{}
		}
		for _, outcome := range result.Outcomes {
			if _, duplicate := seenOutcomes[outcome.OutcomeID]; duplicate {
				return fmt.Errorf("documentation derivation profile set duplicates outcome %q", outcome.OutcomeID)
			}
			seenOutcomes[outcome.OutcomeID] = struct{}{}
		}
		rootRows[index] = []byte(lengthPrefixedIdentityKey(key, profile.SemanticGeneration.identitySHA256, result.ResultRootSHA256))
		pageRows[index] = []byte(lengthPrefixedIdentityKey(key, profile.SemanticGeneration.identitySHA256, result.PageSetRootSHA256))
	}
	if err := validateDocumentationDerivationProfileSetLimits(set.Limits); err != nil {
		return fmt.Errorf("documentation derivation profile execution set limits: %w", err)
	}
	limits, budgetRoot, ruleCount, programBytes, schemaBytes, err := reserveDocumentationDerivationProfileSet(profiles, keys, set.Limits)
	if err != nil || limits != set.Limits || budgetRoot != set.ProfileBudgetRootSHA256 || ruleCount != set.RuleCount || programBytes != set.CanonicalProgramBytes || schemaBytes != set.CanonicalClaimSchemaBytes {
		return fmt.Errorf("documentation derivation profile execution set budget reservation differs from its exact profile roster")
	}
	if actual.FactCount != set.FactCount || actual.CanonicalFactBytes != set.CanonicalFactBytes || actual.OutcomeCount != set.OutcomeCount || actual.CanonicalOutcomeBytes != set.CanonicalOutcomeBytes || actual.RetainedCanonicalBytes != set.RetainedCanonicalBytes || actual.PageCount != set.PageCount || actual.MatcherEvaluationCount != set.MatcherEvaluationCount || actual.MatcherInputByteCount != set.MatcherInputByteCount || stageCanonicalSetRoot(rootRows) != set.ProfileResultSetRootSHA256 || stageCanonicalSetRoot(pageRows) != set.ProfilePageSetRootSHA256 {
		return fmt.Errorf("documentation derivation profile execution set actuals or roots differ from its exact results")
	}
	canonicalIdentity, err := canonicalDocumentationBytes(exactDocumentationDerivationProfileExecutionSetIdentityFor(set))
	if err != nil || sha256Hex(canonicalIdentity) != set.ExecutionSetRootSHA256 {
		return fmt.Errorf("documentation derivation profile execution set root differs from its exact evidence")
	}
	return nil
}

func accumulateDocumentationDerivationProfileResult(set *exactDocumentationDerivationProfileExecutionSet, result exactDocumentationDerivationExecutionResult, limits exactDocumentationDerivationProfileSetLimits) error {
	if result.Status != exactDocumentationDerivationComplete || result.CanonicalFactBytes < 0 || result.CanonicalOutcomeBytes < 0 || result.RetainedCanonicalBytes < 0 || result.CanonicalFactBytes > result.RetainedCanonicalBytes || result.CanonicalOutcomeBytes != result.RetainedCanonicalBytes-result.CanonicalFactBytes || result.PageCount <= 0 || result.MatcherEvaluationCount < 0 || result.MatcherInputByteCount < 0 {
		return fmt.Errorf("result is incomplete or has invalid resource actuals")
	}
	metrics := []struct {
		label string
		value *int64
		add   int64
		limit int64
	}{
		{"facts", &set.FactCount, int64(len(result.Facts)), limits.factCount},
		{"canonical fact bytes", &set.CanonicalFactBytes, result.CanonicalFactBytes, limits.canonicalFactBytes},
		{"outcomes", &set.OutcomeCount, int64(len(result.Outcomes)), limits.outcomeCount},
		{"canonical outcome bytes", &set.CanonicalOutcomeBytes, result.CanonicalOutcomeBytes, limits.canonicalOutcomeBytes},
		{"retained canonical bytes", &set.RetainedCanonicalBytes, result.RetainedCanonicalBytes, limits.retainedCanonicalBytes},
		{"pages", &set.PageCount, result.PageCount, limits.pageCount},
		{"matcher evaluations", &set.MatcherEvaluationCount, result.MatcherEvaluationCount, limits.matcherEvaluations},
		{"matcher input bytes", &set.MatcherInputByteCount, result.MatcherInputByteCount, limits.matcherInputBytes},
	}
	for _, metric := range metrics {
		if metric.add < 0 || *metric.value > metric.limit-metric.add {
			return fmt.Errorf("aggregate %s exceed limit %d", metric.label, metric.limit)
		}
		*metric.value += metric.add
	}
	return nil
}
