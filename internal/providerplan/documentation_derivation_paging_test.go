package providerplan

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestExactDocumentationDerivationPagingSegmentsAndSealsMultiplePages(t *testing.T) {
	body := []byte(strings.Repeat("| amount | Decimal | Required |\n", 12))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 12, 12, 160, 2, 4096)
	result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pages) < 4 || len(result.Facts) != 12 || result.Seal.Status != exactDocumentationDerivationPagingComplete || !isLowerSHA256(result.Seal.PageSetRootSHA256) {
		t.Fatalf("paged result = pages %d facts %d seal %#v", len(result.Pages), len(result.Facts), result.Seal)
	}
	assertExactDocumentationUnitCoverage(t, result.Pages, int64(len(body)), 160)
	for index, page := range result.Pages {
		if page.Descriptor.OutputPageOrdinal != int64(index) {
			t.Fatalf("page %d ordinal = %d", index, page.Descriptor.OutputPageOrdinal)
		}
		if page.Descriptor.FactCount > 2 || page.Descriptor.CanonicalFactBytes > 4096 {
			t.Fatalf("page %d exceeds pinned output budgets: %#v", index, page.Descriptor)
		}
		if index < len(result.Pages)-1 && (page.Status != exactDocumentationDerivationResumable || page.Continuation == nil) {
			t.Fatalf("page %d is not resumable incomplete", index)
		}
	}
	last := result.Pages[len(result.Pages)-1]
	if last.Status != exactDocumentationDerivationPagingComplete || last.Continuation != nil || !last.Descriptor.TerminalForExecution {
		t.Fatalf("last page is not the sole terminal completion: %#v", last)
	}
}

func TestExactDocumentationFactRootsAndContinuationCursorAreDeterministic(t *testing.T) {
	fact := exactDocumentationDerivedFact{FactID: "fact", RuleID: "rule", Provider: "fixture", CanonicalOutputFields: []byte(`{"field":"value"}`)}
	root := exactDocumentationOrderedFactRoot([]exactDocumentationDerivedFact{fact})
	if !isLowerSHA256(root) || root != exactDocumentationOrderedFactRoot([]exactDocumentationDerivedFact{fact}) {
		t.Fatalf("fact root is not deterministic: %q", root)
	}
	page := exactDocumentationDerivationPage{Continuation: &exactDocumentationDerivationContinuation{CursorKind: "next"}}
	if got := exactDocumentationCursorForPage(page); got.CursorKind != "next" {
		t.Fatalf("cursor = %#v", got)
	}
	if got := exactDocumentationCursorForPage(exactDocumentationDerivationPage{}); got.CursorKind != "" {
		t.Fatalf("nil continuation cursor = %#v", got)
	}
}

func TestExactDocumentationDerivationPagingEmitsBoundaryCrossingLineMatchOnce(t *testing.T) {
	prefix := strings.Repeat("x", 150) + "\n"
	body := []byte(prefix + "| amount | Decimal | Required |\n")
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 1, 1, 160, 8, 4096)
	result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != 1 {
		t.Fatalf("boundary-crossing facts = %d, want exactly one", len(result.Facts))
	}
	wantStart := int64(len(prefix))
	if result.Facts[0].ByteStartOffset != wantStart || result.Facts[0].ByteEndOffsetExclusive <= 160 {
		t.Fatalf("boundary match coordinate = [%d,%d), want start %d and crossing offset 160", result.Facts[0].ByteStartOffset, result.Facts[0].ByteEndOffsetExclusive, wantStart)
	}
}

func TestExactDocumentationDerivationPagingDoesNotInventLineAnchorAtUnitBoundary(t *testing.T) {
	row := "| amount | Decimal | Required |\n"
	body := []byte(strings.Repeat("x", 160) + row + row)
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 1, 1, 160, 8, 4096)
	result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != 1 {
		t.Fatalf("line-anchor facts = %d, want only the real post-newline match", len(result.Facts))
	}
	wantStart := int64(160 + len(row))
	if result.Facts[0].ByteStartOffset != wantStart {
		t.Fatalf("line-anchor match start = %d, want %d", result.Facts[0].ByteStartOffset, wantStart)
	}
}

func TestExactDocumentationDerivationPagingDoesNotInventLineEndAtLookaheadBoundary(t *testing.T) {
	for name, fixture := range map[string]struct {
		body      string
		minimum   int64
		wantFacts int
		wantStart int64
		wantEnd   int64
	}{
		"non-newline following byte": {body: "xxfooz", minimum: 0, wantFacts: 0},
		"non-newline following rune": {body: "xxfoo世", minimum: 0, wantFacts: 0},
		"real following newline":     {body: "xxfoo\nz", minimum: 1, wantFacts: 1, wantStart: 2, wantEnd: 5},
		"real selected end":          {body: "xxfoo", minimum: 1, wantFacts: 1, wantStart: 2, wantEnd: 5},
	} {
		t.Run(name, func(t *testing.T) {
			raw, reference, proof, bodies := exactDocumentationProgramFixture(t, []byte(fixture.body), fixture.minimum, 1)
			var object map[string]interface{}
			if err := decodeOneValidationProfileJSON(raw, &object); err != nil {
				t.Fatal(err)
			}
			object["max_parse_bytes"] = json.Number("3")
			rule := object["ordered_rules"].([]interface{})[0].(map[string]interface{})
			rule["pattern"] = `(?m)foo$`
			rule["maximum_match_bytes"] = json.Number("3")
			rule["output_fields"] = map[string]interface{}{"assertion": "line_end"}
			rule["exact_output_field_names"] = []interface{}{"assertion"}
			encoded, err := json.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := canonicalizeCandidateJSON(encoded)
			if err != nil {
				t.Fatal(err)
			}
			reference.digest = sha256Hex(canonical)
			program, err := parseExactDocumentationDerivationProgram(canonical, reference)
			if err != nil {
				t.Fatal(err)
			}
			result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Facts) != fixture.wantFacts {
				t.Fatalf("facts = %d, want %d; artificial search-window end changed (?m)$ semantics", len(result.Facts), fixture.wantFacts)
			}
			if fixture.wantFacts == 1 && (result.Facts[0].ByteStartOffset != fixture.wantStart || result.Facts[0].ByteEndOffsetExclusive != fixture.wantEnd) {
				t.Fatalf("match = [%d,%d), want [%d,%d)", result.Facts[0].ByteStartOffset, result.Facts[0].ByteEndOffsetExclusive, fixture.wantStart, fixture.wantEnd)
			}
		})
	}
}

func TestExactDocumentationDerivationPagingDoesNotMatchReplacementRuneAtUTF8Boundary(t *testing.T) {
	body := []byte("abcéz")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 0, 1)
	object := decodeDocumentationProgramObject(t, raw)
	object["max_parse_bytes"] = json.Number("4")
	rule := documentationProgramRuleObject(t, object, 0)
	rule["pattern"] = `\p{So}`
	rule["maximum_match_bytes"] = json.Number("4")
	rule["output_fields"] = map[string]interface{}{"assertion": "symbol"}
	rule["exact_output_field_names"] = []interface{}{"assertion"}
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Facts) != 0 {
		t.Fatalf("UTF-8 boundary manufactured %d symbol facts from a split é rune", len(result.Facts))
	}
	if len(result.Pages) != 2 || result.Pages[0].Descriptor.InputEndByteOffsetExclusive != 3 || result.Pages[1].Descriptor.InputStartByteOffset != 3 {
		t.Fatalf("UTF-8 aligned units = %#v", result.Pages)
	}
}

func TestExactDocumentationDerivationPagingPersistsZeroFactUnitOutcomes(t *testing.T) {
	body := []byte(strings.Repeat("not a table row\n", 30))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 0, 1, 160, 4, 4096)
	result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	wantUnits := (len(body) + 159) / 160
	if len(result.Pages) != wantUnits || len(result.Facts) != 0 || result.Seal.FactCount != 0 {
		t.Fatalf("zero-output closure = pages %d/%d facts %d seal facts %d", len(result.Pages), wantUnits, len(result.Facts), result.Seal.FactCount)
	}
	if len(result.Outcomes) != 1 || result.Seal.OutcomeCount != 1 || result.Seal.CanonicalOutcomeBytes <= 0 || !isLowerSHA256(result.Seal.OutcomeSetRootSHA256) {
		t.Fatalf("zero-fact outcome closure = outcomes %d seal %#v", len(result.Outcomes), result.Seal)
	}
	var matcherTotal int64
	for index, page := range result.Pages {
		matcherTotal += page.Descriptor.MatcherEvaluationCount
		if page.Descriptor.FactCount != 0 || page.Descriptor.LastOutputKind != exactDocumentationNoOutputKind || page.Descriptor.LastOutputIdentityHash != sha256Hex(nil) || !page.Descriptor.TerminalForInputUnit {
			t.Fatalf("zero-output page %d is incomplete: %#v", index, page.Descriptor)
		}
	}
	if matcherTotal != result.Seal.MatcherEvaluationCount {
		t.Fatalf("sealed matcher total = %d, page sum %d", result.Seal.MatcherEvaluationCount, matcherTotal)
	}
	assertExactDocumentationUnitCoverage(t, result.Pages, int64(len(body)), 160)
}

func TestExactDocumentationDerivationPagingResumesFromCanonicalCursor(t *testing.T) {
	body := []byte(strings.Repeat("| amount | Decimal | Required |\n", 10))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 10, 10, 160, 1, 4096)
	expected, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	var continuation *exactDocumentationDerivationContinuation
	var resumed []exactDocumentationDerivationPage
	for {
		page, err := executeExactDocumentationDerivationPageTestOnly(reference, program, proof, bodies, continuation)
		if err != nil {
			t.Fatal(err)
		}
		resumed = append(resumed, page)
		if page.Status == exactDocumentationDerivationPagingComplete {
			break
		}
		if page.Continuation == nil {
			t.Fatal("resumable page has no canonical continuation")
		}
		cursor := *page.Continuation
		continuation = &cursor
	}
	if len(resumed) != len(expected.Pages) {
		t.Fatalf("resumed pages = %d, want %d", len(resumed), len(expected.Pages))
	}
	for index := range resumed {
		if resumed[index].Descriptor.PageSHA256 != expected.Pages[index].Descriptor.PageSHA256 {
			t.Fatalf("resumed page %d changed identity", index)
		}
	}
}

func TestExactDocumentationDerivationPagingRejectsCursorTamperAndWrongAuthority(t *testing.T) {
	body := []byte(strings.Repeat("| amount | Decimal | Required |\n", 6))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 6, 6, 160, 1, 4096)
	first, err := executeExactDocumentationDerivationPageTestOnly(reference, program, proof, bodies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Continuation == nil {
		t.Fatal("fixture did not exhaust its first output page")
	}

	t.Run("tuple bytes", func(t *testing.T) {
		tampered := *first.Continuation
		tampered.NextCheckpoint.InputEndByteOffsetExclusive++
		if _, err := executeExactDocumentationDerivationPageTestOnly(reference, program, proof, bodies, &tampered); err == nil || !strings.Contains(err.Error(), "hash") {
			t.Fatalf("error = %v, want canonical cursor-hash refusal", err)
		}
	})
	t.Run("self-consistent skip ahead", func(t *testing.T) {
		tampered := *first.Continuation
		tampered.OutputPageOrdinal++
		var digestErr error
		tampered.ContinuationCursorSHA256, digestErr = canonicalDocumentationDigest(exactDocumentationContinuationIdentityFor(tampered))
		if digestErr != nil {
			t.Fatal(digestErr)
		}
		if _, err := executeExactDocumentationDerivationPageTestOnly(reference, program, proof, bodies, &tampered); err == nil || !strings.Contains(err.Error(), "structurally invalid") {
			t.Fatalf("error = %v, want checkpoint-consistency refusal", err)
		}
	})
	t.Run("wrong profile", func(t *testing.T) {
		wrong := reference
		wrong.version = "different"
		if _, err := executeExactDocumentationDerivationPageTestOnly(wrong, program, proof, bodies, first.Continuation); err == nil || !strings.Contains(err.Error(), "wrong profile") {
			t.Fatalf("error = %v, want wrong-profile refusal", err)
		}
	})
	t.Run("wrong proof", func(t *testing.T) {
		wrongProof := newSourceClassificationSelectionProof("different_provider", proof.evidenceSelectionRosterSHA256, proof.classificationsBySourceSymbol)
		if _, err := executeExactDocumentationDerivationPageTestOnly(reference, program, wrongProof, bodies, first.Continuation); err == nil || !strings.Contains(err.Error(), "wrong sealed classification proof") {
			t.Fatalf("error = %v, want wrong-proof refusal", err)
		}
	})
}

func TestExactDocumentationDerivationPagingRejectsSelfHashedFactSkippingCheckpoint(t *testing.T) {
	row := "| amount | Decimal | Required |\n"
	body := []byte(strings.Repeat(row, 4))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 4, 4, 512, 1, 4096)
	first, err := executeExactDocumentationDerivationPageTestOnly(reference, program, proof, bodies, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first.Continuation == nil || len(first.Continuation.NextCheckpoint.RuleProgress) != 1 {
		t.Fatal("fixture first page has no resumable rule checkpoint")
	}

	forged := *first.Continuation
	forged.NextCheckpoint = cloneExactDocumentationCheckpoint(first.Continuation.NextCheckpoint)
	// Advance over the second exact row without emitting its fact, then make
	// the cursor's self-hash internally consistent. This was accepted before
	// reachability was distinguished from content identity.
	secondMatchEnd := int64(2*len(row) - 1)
	forged.NextCheckpoint.CandidateByteOffset = secondMatchEnd
	forged.NextCheckpoint.RuleProgress[0].MatchCount = 2
	forged.NextCheckpoint.RuleProgress[0].LastAcceptedEndOffset = secondMatchEnd
	forged.ContinuationCursorSHA256, err = canonicalDocumentationDigest(exactDocumentationContinuationIdentityFor(forged))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExactDocumentationContinuation(forged, reference, program, proof); err != nil {
		t.Fatalf("forged cursor is intentionally structurally valid and self-hashed: %v", err)
	}
	if _, err := executeExactDocumentationDerivationPageTestOnly(reference, program, proof, bodies, &forged); err == nil || !strings.Contains(err.Error(), "exact reachable predecessor") {
		t.Fatalf("error = %v, want reachable-prefix refusal of self-hashed fact skip", err)
	}

	expected, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	var continuation *exactDocumentationDerivationContinuation
	for index, want := range expected.Pages {
		got, err := executeExactDocumentationDerivationPageTestOnly(reference, program, proof, bodies, continuation)
		if err != nil {
			t.Fatalf("valid resume page %d: %v", index, err)
		}
		if got.Descriptor.PageSHA256 != want.Descriptor.PageSHA256 {
			t.Fatalf("valid resumed page %d identity changed", index)
		}
		continuation = got.Continuation
	}
}

func TestExactDocumentationDerivationPagingSealRejectsReorderGapOverlapAndDuplicate(t *testing.T) {
	body := []byte(strings.Repeat("| amount | Decimal | Required |\n", 12))
	reference, program, proof, bodies := exactDocumentationPagingFixture(t, body, 12, 12, 160, 2, 4096)
	result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pages) < 3 {
		t.Fatalf("fixture pages = %d, want at least three", len(result.Pages))
	}
	if _, err := sealExactDocumentationDerivationPageSet(reference, program, proof, bodies, cloneExactDocumentationPages(result.Pages)); err != nil {
		t.Fatalf("valid page set: %v", err)
	}

	for name, mutate := range map[string]func([]exactDocumentationDerivationPage) []exactDocumentationDerivationPage{
		"reorder": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			pages[0], pages[1] = pages[1], pages[0]
			return pages
		},
		"gap": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			return append(pages[:1], pages[2:]...)
		},
		"overlap": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := 1; index < len(pages); index++ {
				if pages[index].Descriptor.InputStartByteOffset != pages[index-1].Descriptor.InputStartByteOffset {
					pages[index].Descriptor.InputStartByteOffset = pages[index-1].Descriptor.InputStartByteOffset
					break
				}
			}
			return pages
		},
		"duplicate fact": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := 1; index < len(pages); index++ {
				if len(pages[index].Facts) > 0 && len(pages[0].Facts) > 0 {
					pages[index].Facts[0] = pages[0].Facts[0]
					break
				}
			}
			return pages
		},
		"locator row kind": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := range pages {
				if len(pages[index].Facts) == 0 {
					continue
				}
				pages[index].Facts[0].EvidenceLocator.RowKind = "different_locator_kind"
				break
			}
			return pages
		},
		"target binding": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := range pages {
				if len(pages[index].Facts) == 0 {
					continue
				}
				fact := &pages[index].Facts[0]
				fact.TargetBindingKind = exactDocumentationTargetRowMember
				fact.TargetMemberJSONPointer = "/properties/a~1b~0c"
				fact.FactID = exactDocumentationDerivedFactID(*fact)
				break
			}
			return pages
		},
		"remove terminal outcomes": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			pages[len(pages)-1].Outcomes = nil
			return pages
		},
		"erase cumulative matcher work": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			pages[len(pages)-1].Descriptor.CumulativeMatcherEvaluationCount--
			pages[len(pages)-1].ParserState.CumulativeMatcherEvaluationCount--
			return pages
		},
		"erase canonical outcome bytes": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			pages[len(pages)-1].Descriptor.CanonicalOutcomeBytes = 0
			pages[len(pages)-1].ParserState.CanonicalOutcomeBytes = 0
			return pages
		},
		"foreign profile": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := range pages {
				if len(pages[index].Facts) == 0 {
					continue
				}
				pages[index].Facts[0].Profile.version = "foreign"
				pages[index].Facts[0].FactID = exactDocumentationDerivedFactID(pages[index].Facts[0])
				break
			}
			return pages
		},
		"foreign provider": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := range pages {
				if len(pages[index].Facts) == 0 {
					continue
				}
				pages[index].Facts[0].Provider = "foreign_provider"
				pages[index].Facts[0].FactID = exactDocumentationDerivedFactID(pages[index].Facts[0])
				break
			}
			return pages
		},
		"foreign evidence roster": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := range pages {
				if len(pages[index].Facts) == 0 {
					continue
				}
				pages[index].Facts[0].EvidenceRosterSHA256 = strings.Repeat("a", 64)
				pages[index].Facts[0].FactID = exactDocumentationDerivedFactID(pages[index].Facts[0])
				break
			}
			return pages
		},
		"foreign predecessor locator": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := range pages {
				if len(pages[index].Facts) == 0 {
					continue
				}
				pages[index].Facts[0].PredecessorLocatorID = "foreign_locator"
				pages[index].Facts[0].FactID = exactDocumentationDerivedFactID(pages[index].Facts[0])
				break
			}
			return pages
		},
		"forged selected subrange": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := range pages {
				if len(pages[index].Facts) == 0 {
					continue
				}
				fact := &pages[index].Facts[0]
				locator := fact.EvidenceLocator
				locator.ByteEndOffsetExclusive = locator.ByteStartOffset + 1
				locator.SelectedRangeByteCount = 1
				locator.SelectedRangeSHA256 = sha256Hex(bodies[locator.SourceContentSHA256].Bytes[locator.ByteStartOffset:locator.ByteEndOffsetExclusive])
				locator.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(locator))
				fact.EvidenceLocator = locator
				fact.EvidenceLocatorID = locator.ID
				fact.ByteEndOffsetExclusive = locator.ByteEndOffsetExclusive
				fact.SelectedMatchSHA256 = locator.SelectedRangeSHA256
				fact.FactID = exactDocumentationDerivedFactID(*fact)
				break
			}
			return pages
		},
		"forged rendered output": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := range pages {
				if len(pages[index].Facts) == 0 {
					continue
				}
				fact := &pages[index].Facts[0]
				fact.CanonicalOutputFields = []byte(`{"field_name":"forged","provider_requirement":"Required","provider_type":"Decimal"}`)
				fact.FactID = exactDocumentationDerivedFactID(*fact)
				break
			}
			return pages
		},
		"forged match ordinal": func(pages []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
			for index := range pages {
				if len(pages[index].Facts) == 0 {
					continue
				}
				pages[index].Facts[0].MatchOrdinal++
				pages[index].Facts[0].FactID = exactDocumentationDerivedFactID(pages[index].Facts[0])
				break
			}
			return pages
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := sealExactDocumentationDerivationPageSet(reference, program, proof, bodies, mutate(cloneExactDocumentationPages(result.Pages))); err == nil {
				t.Fatal("tampered page set sealed")
			}
		})
	}
}

func TestExactDocumentationDerivationPagingSealRejectsOutcomeCoordinateSubstitutionAndInventedFact(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	object := decodeDocumentationProgramObject(t, raw)
	rules := object["ordered_rules"].([]interface{})
	cloneBytes, err := json.Marshal(rules[0])
	if err != nil {
		t.Fatal(err)
	}
	var second map[string]interface{}
	if err := decodeOneValidationProfileJSON(cloneBytes, &second); err != nil {
		t.Fatal(err)
	}
	second["ordinal"] = json.Number("1")
	second["rule_id"] = "extract_second_field_rows"
	object["ordered_rules"] = append(rules, second)
	canonical := encodeDocumentationProgramObject(t, object, &reference)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	result, err := executeExactDocumentationDerivationAllPages(reference, program, proof, bodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Pages) != 1 || len(result.Pages[0].Outcomes) != 2 || len(result.Facts) != 2 {
		t.Fatalf("fixture pages/outcomes/facts = %d/%d/%d", len(result.Pages), len(result.Pages[0].Outcomes), len(result.Facts))
	}

	for name, mutate := range map[string]func(*exactDocumentationDerivationOccurrenceOutcome){
		"coordinate substitution": func(outcome *exactDocumentationDerivationOccurrenceOutcome) {
			authority := result.Pages[0].Outcomes[0]
			outcome.RuleID = authority.RuleID
			outcome.InputSourceSymbol = authority.InputSourceSymbol
			outcome.ClassificationArtifactID = authority.ClassificationArtifactID
			outcome.ClassificationVersion = authority.ClassificationVersion
			outcome.ClassificationSHA256 = authority.ClassificationSHA256
			outcome.ClassificationRole = authority.ClassificationRole
			outcome.PredecessorLocatorID = authority.PredecessorLocatorID
		},
		"invented fact identity": func(outcome *exactDocumentationDerivationOccurrenceOutcome) {
			outcome.DerivedFactIDs[0] = stableID("docfact", "invented")
		},
	} {
		t.Run(name, func(t *testing.T) {
			pages := cloneExactDocumentationPages(result.Pages)
			outcome := &pages[0].Outcomes[1]
			mutate(outcome)
			sort.Strings(outcome.DerivedFactIDs)
			factRows := make([][]byte, len(outcome.DerivedFactIDs))
			for index, factID := range outcome.DerivedFactIDs {
				factRows[index] = []byte(factID)
			}
			outcome.DerivedFactSetRootSHA256 = stageCanonicalSetRoot(factRows)
			binding := classificationArtifactBinding{ArtifactID: outcome.ClassificationArtifactID, ArtifactVersion: outcome.ClassificationVersion, ArtifactSHA256: outcome.ClassificationSHA256}
			key := exactDocumentationDerivationOutcomeKey(outcome.RuleID, outcome.InputSourceSymbol, binding, outcome.ClassificationRole, outcome.PredecessorLocatorID)
			outcome.OutcomeID = stableID("docout", lengthPrefixedIdentityKey(reference.id, reference.version, reference.digest, proof.contentSHA256, key, outcome.Disposition, strconv.FormatInt(outcome.MatchCount, 10), outcome.DerivedFactSetRootSHA256))
			resealExactDocumentationTerminalPageForTest(t, &pages[0])
			if _, err := sealExactDocumentationDerivationPageSet(reference, program, proof, bodies, pages); err == nil {
				t.Fatal("self-consistent substituted outcome page set sealed")
			}
		})
	}
}

func TestExactDocumentationDerivationPagingRejectsUnboundedRegex(t *testing.T) {
	body := []byte("aaaa")
	raw, reference, _, _ := exactDocumentationProgramFixture(t, body, 0, 1)
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	rule := object["ordered_rules"].([]interface{})[0].(map[string]interface{})
	rule["pattern"] = `(?P<field_name>a+)(?P<provider_type>b{1,2})(?P<provider_requirement>c{1,2})`
	mutated, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(mutated)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	if _, err := parseExactDocumentationDerivationProgram(canonical, reference); err == nil || !strings.Contains(err.Error(), "unbounded") {
		t.Fatalf("error = %v, want unbounded-width refusal", err)
	}
}

func TestExactDocumentationDerivationPagingSealDistinguishesEmptyRuns(t *testing.T) {
	firstBody := []byte(strings.Repeat("no match\n", 30))
	secondBody := []byte(strings.Repeat("still no match\n", 30))
	firstReference, firstProgram, firstProof, firstBodies := exactDocumentationPagingFixture(t, firstBody, 0, 1, 160, 4, 4096)
	secondReference, secondProgram, secondProof, secondBodies := exactDocumentationPagingFixture(t, secondBody, 0, 1, 160, 4, 4096)
	first, err := executeExactDocumentationDerivationAllPages(firstReference, firstProgram, firstProof, firstBodies)
	if err != nil {
		t.Fatal(err)
	}
	second, err := executeExactDocumentationDerivationAllPages(secondReference, secondProgram, secondProof, secondBodies)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Facts) != 0 || len(second.Facts) != 0 || first.Seal.PageSetRootSHA256 == second.Seal.PageSetRootSHA256 || first.Seal.OrderedPageChainRootSHA256 == second.Seal.OrderedPageChainRootSHA256 {
		t.Fatalf("empty run seals collapsed: first=%#v second=%#v", first.Seal, second.Seal)
	}
}

func exactDocumentationPagingFixture(t *testing.T, body []byte, minimumMatches, maximumMatches, maxParseBytes, maxOutputFacts, maxOutputBytes int64) (dependencyProfileReference, exactDocumentationDerivationProgram, sourceClassificationSelectionProof, map[string]exactEvidenceBody) {
	t.Helper()
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, minimumMatches, maximumMatches)
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["max_parse_bytes"] = json.Number(strconv.FormatInt(maxParseBytes, 10))
	perFactBytes := maxOutputBytes
	if perFactBytes > 3072 {
		perFactBytes = 3072
	}
	object["max_output_bytes_per_fact"] = json.Number(strconv.FormatInt(perFactBytes, 10))
	object["max_output_facts_per_page"] = json.Number(strconv.FormatInt(maxOutputFacts, 10))
	object["max_output_bytes_per_page"] = json.Number(strconv.FormatInt(maxOutputBytes, 10))
	object["max_output_facts_per_run"] = json.Number("65536")
	object["max_output_bytes_per_run"] = json.Number("67108864")
	object["max_output_pages_per_run"] = json.Number("65536")
	object["max_matcher_evaluations_per_input_unit"] = json.Number("65536")
	object["max_matcher_evaluations_per_run"] = json.Number("268435456")
	object["max_matcher_input_bytes_per_input_unit"] = json.Number("268435456")
	object["max_matcher_input_bytes_per_run"] = json.Number("4294967296")
	object["max_occurrence_outcomes_per_run"] = json.Number("1048576")
	object["max_canonical_outcome_bytes_per_run"] = json.Number("1073741824")
	rule := object["ordered_rules"].([]interface{})[0].(map[string]interface{})
	rule["maximum_match_bytes"] = json.Number(strconv.FormatInt(maxParseBytes, 10))
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reference.digest = sha256Hex(canonical)
	program, err := parseExactDocumentationDerivationProgram(canonical, reference)
	if err != nil {
		t.Fatal(err)
	}
	return reference, program, proof, bodies
}

func assertExactDocumentationUnitCoverage(t *testing.T, pages []exactDocumentationDerivationPage, selectedLength, maxParseBytes int64) {
	t.Helper()
	var priorEnd int64
	var observed int64
	for _, page := range pages {
		if !page.Descriptor.TerminalForInputUnit {
			continue
		}
		if page.Descriptor.InputStartByteOffset != priorEnd || page.Descriptor.InputEndByteOffsetExclusive <= page.Descriptor.InputStartByteOffset || page.Descriptor.InputUnitLength != page.Descriptor.InputEndByteOffsetExclusive-page.Descriptor.InputStartByteOffset || page.Descriptor.InputUnitLength > maxParseBytes {
			t.Fatalf("unit coverage breaks at page %d: prior_end=%d descriptor=%#v", page.Descriptor.OutputPageOrdinal, priorEnd, page.Descriptor)
		}
		observed += page.Descriptor.InputUnitLength
		priorEnd = page.Descriptor.InputEndByteOffsetExclusive
	}
	if priorEnd != selectedLength || observed != selectedLength {
		t.Fatalf("unit coverage end/sum = %d/%d, want %d", priorEnd, observed, selectedLength)
	}
}

func cloneExactDocumentationPages(input []exactDocumentationDerivationPage) []exactDocumentationDerivationPage {
	result := make([]exactDocumentationDerivationPage, len(input))
	for index, page := range input {
		result[index] = page
		result[index].Facts = append([]exactDocumentationDerivedFact(nil), page.Facts...)
		result[index].Outcomes = append([]exactDocumentationDerivationOccurrenceOutcome(nil), page.Outcomes...)
		for outcomeIndex := range result[index].Outcomes {
			result[index].Outcomes[outcomeIndex].DerivedFactIDs = append([]string(nil), page.Outcomes[outcomeIndex].DerivedFactIDs...)
		}
		if page.Continuation != nil {
			cursor := *page.Continuation
			cursor.NextCheckpoint = cloneExactDocumentationCheckpoint(page.Continuation.NextCheckpoint)
			result[index].Continuation = &cursor
		}
	}
	return result
}

func resealExactDocumentationTerminalPageForTest(t *testing.T, page *exactDocumentationDerivationPage) {
	t.Helper()
	rows := make([][]byte, len(page.Outcomes))
	var byteCount int64
	for index, outcome := range page.Outcomes {
		canonical, err := canonicalDocumentationBytes(outcome)
		if err != nil {
			t.Fatal(err)
		}
		rows[index] = canonical
		byteCount += int64(len(canonical))
	}
	root := stageCanonicalSetRoot(rows)
	page.Descriptor.OutcomeIdentityRootSHA256 = root
	page.Descriptor.OutcomeCount = int64(len(page.Outcomes))
	page.Descriptor.CanonicalOutcomeBytes = byteCount
	page.Descriptor.CumulativeOutcomeCount = int64(len(page.Outcomes))
	page.Descriptor.CumulativeCanonicalOutcomeBytes = byteCount
	page.ParserState.OutcomeIdentityRootSHA256 = root
	page.ParserState.OutcomeCount = int64(len(page.Outcomes))
	page.ParserState.CanonicalOutcomeBytes = byteCount
	page.ParserState.CumulativeOutcomeCount = int64(len(page.Outcomes))
	page.ParserState.CumulativeCanonicalOutcomeBytes = byteCount
	stateDigest, err := canonicalDocumentationDigest(page.ParserState)
	if err != nil {
		t.Fatal(err)
	}
	page.Descriptor.ParserStateDigest = stateDigest
	page.Descriptor.PageSHA256, err = canonicalDocumentationDigest(exactDocumentationPageIdentityFor(page.Descriptor))
	if err != nil {
		t.Fatal(err)
	}
}
