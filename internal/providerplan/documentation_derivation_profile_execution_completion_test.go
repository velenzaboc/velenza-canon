package providerplan

import (
	"strings"
	"testing"
)

func TestDocumentationDerivationProfileExecutionCompletionLimitsAndMetricsFailClosed(t *testing.T) {
	canonical := canonicalDocumentationDerivationProfileSetHardLimits()
	if err := validateDocumentationDerivationProfileSetLimits(canonical); err != nil {
		t.Fatalf("canonical closed limits rejected: %v", err)
	}
	for name, mutate := range map[string]func(*exactDocumentationDerivationProfileSetLimits){
		"zero profile count":   func(limits *exactDocumentationDerivationProfileSetLimits) { limits.profileCount = 0 },
		"oversized rule count": func(limits *exactDocumentationDerivationProfileSetLimits) { limits.ruleCount++ },
		"zero matcher bytes":   func(limits *exactDocumentationDerivationProfileSetLimits) { limits.matcherInputBytes = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			limits := canonical
			mutate(&limits)
			if err := validateDocumentationDerivationProfileSetLimits(limits); err == nil {
				t.Fatal("invalid closed limit was accepted")
			}
		})
	}

	var value int64
	if err := addDocumentationProfileSetMetric("facts", &value, 2, 3); err != nil || value != 2 {
		t.Fatalf("bounded metric did not accumulate: value=%d err=%v", value, err)
	}
	for name, values := range map[string]struct{ current, add, limit int64 }{
		"negative increment":  {0, -1, 3},
		"negative current":    {-1, 1, 3},
		"increment too large": {0, 4, 3},
		"aggregate overflow":  {2, 2, 3},
	} {
		t.Run(name, func(t *testing.T) {
			value := values.current
			if err := addDocumentationProfileSetMetric("facts", &value, values.add, values.limit); err == nil || !strings.Contains(err.Error(), "facts") {
				t.Fatalf("invalid metric accepted: value=%d err=%v", value, err)
			}
		})
	}
}

func TestDocumentationDerivationProfileExecutionCompletionReservesNormalizedProfiles(t *testing.T) {
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, []byte("| amount | Decimal | Required |\n"), 1, 1)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	generation := exactDocumentationFieldClaimSchemaFixture(t, reference)
	profile := executableDocumentationDerivationProfile{Reference: reference, ClaimKind: generation.claimKind, ValidationSchema: generation.claimSchema, SemanticGeneration: generation, Program: program}
	key := dependencyProfileReferenceKey(reference)

	profiles := map[string]executableDocumentationDerivationProfile{key: profile}
	reserved, root, rules, programBytes, schemaBytes, err := reserveDocumentationDerivationProfileSet(profiles, []string{key}, canonicalDocumentationDerivationProfileSetHardLimits())
	if err != nil {
		t.Fatalf("valid normalized profile was not reserved: %v", err)
	}
	if root == "" || rules != int64(len(program.OrderedRules)) || programBytes <= 0 || schemaBytes <= 0 || reserved.factCount != program.MaxOutputFactsPerRun || reserved.pageCount != program.MaxOutputPagesPerRun {
		t.Fatalf("reservation did not preserve exact program accounting: %#v rules=%d bytes=%d/%d root=%q", reserved, rules, programBytes, schemaBytes, root)
	}
	if _, _, _, _, _, err := reserveDocumentationDerivationProfileSet(profiles, nil, canonicalDocumentationDerivationProfileSetHardLimits()); err == nil {
		t.Fatal("empty executable roster was accepted")
	}
	if _, _, _, _, _, err := reserveDocumentationDerivationProfileSet(map[string]executableDocumentationDerivationProfile{"wrong-key": profile}, []string{"wrong-key"}, canonicalDocumentationDerivationProfileSetHardLimits()); err == nil || !strings.Contains(err.Error(), "map key") {
		t.Fatalf("mismatched profile map key was accepted: %v", err)
	}
	retainedLimited := canonicalDocumentationDerivationProfileSetHardLimits()
	retainedLimited.retainedCanonicalBytes = program.MaxCanonicalOutcomeBytesPerRun
	if _, _, _, _, _, err := reserveDocumentationDerivationProfileSet(map[string]executableDocumentationDerivationProfile{key: profile}, []string{key}, retainedLimited); err == nil || !strings.Contains(err.Error(), "retained-byte") {
		t.Fatalf("insufficient retained-byte reservation was accepted: %v", err)
	}

	set, err := executeDocumentationDerivationProfileSet(map[string]executableDocumentationDerivationProfile{key: profile}, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	var actual exactDocumentationDerivationProfileExecutionSet
	if err := accumulateDocumentationDerivationProfileResult(&actual, set.Results[0], set.Limits); err != nil {
		t.Fatalf("valid result did not accumulate: %v", err)
	}
	if actual.FactCount != int64(len(set.Results[0].Facts)) || actual.OutcomeCount != int64(len(set.Results[0].Outcomes)) || actual.PageCount != set.Results[0].PageCount {
		t.Fatalf("result actuals were not accumulated: %#v", actual)
	}
	invalid := set.Results[0]
	invalid.RetainedCanonicalBytes = invalid.CanonicalFactBytes - 1
	if err := accumulateDocumentationDerivationProfileResult(&exactDocumentationDerivationProfileExecutionSet{}, invalid, set.Limits); err == nil {
		t.Fatal("invalid retained-byte relation was accepted")
	}
	limited := set.Limits
	limited.factCount = 0
	if err := accumulateDocumentationDerivationProfileResult(&exactDocumentationDerivationProfileExecutionSet{}, set.Results[0], limited); err == nil || !strings.Contains(err.Error(), "facts") {
		t.Fatalf("fact-limit overflow was accepted: %v", err)
	}
}
