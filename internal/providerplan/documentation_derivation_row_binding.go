package providerplan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

const exactDocumentationDerivedFactIDField = "documentation_derived_fact_id"

var exactDocumentationDerivedRowEnvelopeFields = map[string]struct{}{
	"row_kind":                           {},
	exactDocumentationDerivedFactIDField: {},
	"source_ref":                         {},
	"source_url":                         {},
	"source_content_sha256":              {},
	"evidence_hydration_coordinate":      {},
}

var forbiddenDocumentationSourceDigestAliases = map[string]struct{}{
	"content_digest":          {},
	"content_sha256":          {},
	"document_content_sha256": {},
	"evidence_body_sha256":    {},
	"evidence_content_sha256": {},
	"sha256":                  {},
	"source_content_digest":   {},
	"source_content_hash":     {},
	"source_digest":           {},
}

// validateExactDocumentationDerivedSemanticRow proves that one dependency
// semantic row is an exact, closed rendering of one fact emitted by the
// provider-neutral documentation derivation executor. The artifact role is
// supplied by the caller because role is an artifact-envelope coordinate, not
// an authoritative field that a semantic row may assert for itself.
func validateExactDocumentationDerivedSemanticRow(targetArtifactRole string, row dependencySemanticRow, fact exactDocumentationDerivedFact) error {
	if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil {
		return fmt.Errorf("documentation-derived fact %q is invalid: %w", fact.FactID, err)
	}
	if targetArtifactRole != fact.TargetArtifactRole {
		return fmt.Errorf("dependency semantic artifact role %q does not equal documentation-derived fact target role %q", targetArtifactRole, fact.TargetArtifactRole)
	}
	if row.kind != fact.TargetRowKind {
		return fmt.Errorf("dependency semantic row kind %q does not equal documentation-derived fact target row kind %q", row.kind, fact.TargetRowKind)
	}
	if len(bytes.TrimSpace(row.raw)) == 0 || row.data == nil {
		return fmt.Errorf("dependency semantic row has no exact JSON bytes or decoded object")
	}
	if err := rejectDuplicateJSONKeys(row.raw); err != nil {
		return fmt.Errorf("dependency semantic row JSON: %w", err)
	}
	rawCanonical, err := canonicalizeCandidateJSON(row.raw)
	if err != nil {
		return fmt.Errorf("canonicalize dependency semantic row: %w", err)
	}
	decodedBytes, err := json.Marshal(row.data)
	if err != nil {
		return fmt.Errorf("marshal decoded dependency semantic row: %w", err)
	}
	decodedCanonical, err := canonicalizeCandidateJSON(decodedBytes)
	if err != nil {
		return fmt.Errorf("canonicalize decoded dependency semantic row: %w", err)
	}
	if !bytes.Equal(rawCanonical, decodedCanonical) {
		return fmt.Errorf("dependency semantic row decoded object does not equal its exact JSON bytes")
	}

	for alias := range forbiddenDocumentationSourceDigestAliases {
		if _, present := row.data[alias]; present {
			return fmt.Errorf("dependency semantic row uses forbidden source-content digest alias %q; source_content_sha256 is the sole digest field", alias)
		}
	}

	expectedKeys := make(map[string]struct{}, len(exactDocumentationDerivedRowEnvelopeFields)+len(fact.ExactOutputFieldNames))
	for key := range exactDocumentationDerivedRowEnvelopeFields {
		expectedKeys[key] = struct{}{}
	}
	for _, key := range fact.ExactOutputFieldNames {
		if _, reserved := exactDocumentationDerivedRowEnvelopeFields[key]; reserved {
			return fmt.Errorf("documentation-derived output field %q collides with the closed executor-owned row envelope", key)
		}
		expectedKeys[key] = struct{}{}
	}
	if err := requireExactSet("documentation-derived dependency semantic row fields", stringMapKeysAsSet(row.data), expectedKeys); err != nil {
		return err
	}

	if err := requireExactCanonicalDocumentationRowMember(row.raw, "row_kind", fact.TargetRowKind); err != nil {
		return err
	}
	if err := requireExactCanonicalDocumentationRowMember(row.raw, exactDocumentationDerivedFactIDField, fact.FactID); err != nil {
		return err
	}
	locator := fact.EvidenceLocator
	if err := requireExactCanonicalDocumentationRowMember(row.raw, "source_ref", locator.SourceRefs[0]); err != nil {
		return err
	}
	if err := requireExactCanonicalDocumentationRowMember(row.raw, "source_url", locator.SourceURLs[0]); err != nil {
		return err
	}
	if err := requireExactCanonicalDocumentationRowMember(row.raw, "source_content_sha256", locator.SourceContentSHA256); err != nil {
		return err
	}
	expectedCoordinate := map[string]interface{}{
		"source_content_sha256":     locator.SourceContentSHA256,
		"byte_start_offset":         locator.ByteStartOffset,
		"byte_end_offset_exclusive": locator.ByteEndOffsetExclusive,
		"selected_range_byte_count": locator.SelectedRangeByteCount,
		"selected_range_sha256":     locator.SelectedRangeSHA256,
	}
	if err := requireExactCanonicalDocumentationRowMember(row.raw, "evidence_hydration_coordinate", expectedCoordinate); err != nil {
		return fmt.Errorf("claim-specific zero-based half-open evidence hydration coordinate: %w", err)
	}

	outputFields, err := decodeExactDocumentationFactOutputFields(fact)
	if err != nil {
		return err
	}
	for _, field := range fact.ExactOutputFieldNames {
		if err := requireExactCanonicalDocumentationRowMember(row.raw, field, outputFields[field]); err != nil {
			return fmt.Errorf("documentation-derived authoritative field %q: %w", field, err)
		}
	}
	return nil
}

// validateExactDocumentationDerivedSemanticRowSet validates a complete target
// artifact role and proves a bijection between candidate rows and executor
// facts. This makes duplicate fact use, unknown additions, and omitted facts
// impossible to hide behind individually valid rows.
func validateExactDocumentationDerivedSemanticRowSet(targetArtifactRole string, rows []dependencySemanticRow, facts []exactDocumentationDerivedFact) error {
	factsByID := make(map[string]exactDocumentationDerivedFact, len(facts))
	for _, fact := range facts {
		if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil {
			return fmt.Errorf("documentation-derived fact %q is invalid: %w", fact.FactID, err)
		}
		if fact.TargetArtifactRole != targetArtifactRole {
			return fmt.Errorf("documentation-derived fact %q targets artifact role %q, not row-set role %q", fact.FactID, fact.TargetArtifactRole, targetArtifactRole)
		}
		if _, duplicate := factsByID[fact.FactID]; duplicate {
			return fmt.Errorf("documentation-derived fact roster duplicates fact ID %q", fact.FactID)
		}
		factsByID[fact.FactID] = fact
	}
	used := make(map[string]struct{}, len(rows))
	for index, row := range rows {
		factID, ok := semanticString(row.data, exactDocumentationDerivedFactIDField)
		if !ok {
			return fmt.Errorf("dependency semantic row %d has no canonical %s", index, exactDocumentationDerivedFactIDField)
		}
		if _, duplicate := used[factID]; duplicate {
			return fmt.Errorf("dependency semantic row set uses documentation-derived fact ID %q more than once", factID)
		}
		fact, exists := factsByID[factID]
		if !exists {
			return fmt.Errorf("dependency semantic row %d references unknown documentation-derived fact ID %q", index, factID)
		}
		if err := validateExactDocumentationDerivedSemanticRow(targetArtifactRole, row, fact); err != nil {
			return fmt.Errorf("dependency semantic row %d: %w", index, err)
		}
		used[factID] = struct{}{}
	}
	return requireExactSet("documentation-derived fact use", used, stringMapKeysAsSet(factsByID))
}

func validateExactDocumentationDerivedFactIntegrity(fact exactDocumentationDerivedFact) error {
	if fact.FactID == "" || fact.Profile.id == "" || fact.Profile.version == "" || fact.TargetArtifactRole == "" || fact.TargetRowKind == "" || fact.Provider == "" || fact.ClassificationBinding.ArtifactID == "" || fact.ClassificationBinding.ArtifactVersion == "" || fact.ClassificationRole == "" || fact.RuleID == "" || fact.InputSourceSymbol == "" || fact.PredecessorLocatorID == "" || fact.EvidenceLocatorID == "" || fact.MatchOrdinal < 0 {
		return fmt.Errorf("identity or target coordinate is incomplete")
	}
	if !canonicalSurfaceKindPattern.MatchString(fact.TargetArtifactRole) || !canonicalSurfaceKindPattern.MatchString(fact.TargetRowKind) || !canonicalSurfaceKindPattern.MatchString(fact.ClassificationRole) || !canonicalSurfaceKindPattern.MatchString(fact.RuleID) {
		return fmt.Errorf("target, classification, or rule coordinate is not canonical")
	}
	if !isLowerSHA256(fact.Profile.digest) || !isLowerSHA256(fact.EvidenceRosterSHA256) || !isLowerSHA256(fact.ClassificationBinding.ArtifactSHA256) {
		return fmt.Errorf("profile, evidence-roster, or classification digest is malformed")
	}
	if len(fact.ExactOutputFieldNames) == 0 || hasEmptyOrDuplicateSemanticStrings(fact.ExactOutputFieldNames) || !sort.StringsAreSorted(fact.ExactOutputFieldNames) {
		return fmt.Errorf("exact output field roster is not nonempty, unique, and sorted")
	}
	outputFields, err := decodeExactDocumentationFactOutputFields(fact)
	if err != nil {
		return err
	}
	if err := requireExactSet("documentation-derived fact output fields", stringMapKeysAsSet(outputFields), stringSet(fact.ExactOutputFieldNames)); err != nil {
		return err
	}
	outputBytes, err := json.Marshal(outputFields)
	if err != nil {
		return fmt.Errorf("marshal output fields: %w", err)
	}
	canonicalOutput, err := canonicalizeCandidateJSON(outputBytes)
	if err != nil {
		return fmt.Errorf("canonicalize output fields: %w", err)
	}
	if !bytes.Equal(canonicalOutput, fact.CanonicalOutputFields) {
		return fmt.Errorf("canonical output bytes do not equal output fields")
	}
	if err := rejectNonIntegerNumbers(canonicalOutput); err != nil {
		return fmt.Errorf("canonical output fields contain a non-integer numeric value: %w", err)
	}

	locator := fact.EvidenceLocator
	if locator.RowKind != "candidate_evidence_locator" {
		return fmt.Errorf("claim locator row_kind %q is outside the exact closed value candidate_evidence_locator", locator.RowKind)
	}
	if len(locator.SourceRefs) != 1 || len(locator.SourceURLs) != 1 {
		return fmt.Errorf("claim locator does not carry exactly one source ref and URL")
	}
	if locator.ID != fact.EvidenceLocatorID || locator.ID != stableID("evloc", candidateEvidenceLocatorIdentityKey(locator)) {
		return fmt.Errorf("claim locator ID is not content-derived from the exact locator")
	}
	if !isLowerSHA256(locator.EvidenceManifestSHA256) || !isLowerSHA256(locator.SourceContentSHA256) || !isLowerSHA256(locator.SelectedRangeSHA256) || locator.ByteStartOffset < 0 || locator.ByteEndOffsetExclusive <= locator.ByteStartOffset || locator.SelectedRangeByteCount != locator.ByteEndOffsetExclusive-locator.ByteStartOffset {
		return fmt.Errorf("claim locator is not a valid zero-based half-open exact-byte coordinate")
	}
	if !canonicalEvidenceSourceRef(locator.SourceRefs[0]) || !canonicalEvidenceSourceURL(locator.SourceURLs[0]) || locator.LocatorSemantics != exactLocatorSemantics || locator.SourceBytesPresent {
		return fmt.Errorf("claim locator has a noncanonical source coordinate, locator semantics, or embedded source bytes")
	}
	if fact.ByteStartOffset != locator.ByteStartOffset || fact.ByteEndOffsetExclusive != locator.ByteEndOffsetExclusive || fact.SelectedMatchSHA256 != locator.SelectedRangeSHA256 {
		return fmt.Errorf("derived match coordinate does not equal the claim locator")
	}
	if err := validateExactDocumentationDerivedFactTargetIdentity(fact); err != nil {
		return err
	}
	if _, err := canonicalExactDocumentationFactEnvelopeBytes(fact); err != nil {
		return fmt.Errorf("canonical fact envelope: %w", err)
	}
	return nil
}

func requireExactCanonicalDocumentationRowMember(rowRaw []byte, field string, expected interface{}) error {
	rawValue, err := semanticRawMember(rowRaw, field)
	if err != nil {
		return fmt.Errorf("field %q: %w", field, err)
	}
	canonicalActual, err := canonicalizeCandidateJSON(rawValue)
	if err != nil {
		return fmt.Errorf("field %q is not valid canonicalizable JSON: %w", field, err)
	}
	if !bytes.Equal(bytes.TrimSpace(rawValue), canonicalActual) {
		return fmt.Errorf("field %q is not encoded as its canonical JSON value", field)
	}
	expectedBytes, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf("field %q expected value cannot be encoded: %w", field, err)
	}
	canonicalExpected, err := canonicalizeCandidateJSON(expectedBytes)
	if err != nil {
		return fmt.Errorf("field %q expected value cannot be canonicalized: %w", field, err)
	}
	if !bytes.Equal(canonicalActual, canonicalExpected) {
		return fmt.Errorf("field %q canonical JSON value does not equal its exact documentation-derived fact value", field)
	}
	return nil
}
