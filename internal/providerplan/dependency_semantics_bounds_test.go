package providerplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func dependencySemanticProofFixture() (map[string]artifactInput, dependencySemanticValidationProof) {
	artifacts := make(map[string]artifactInput, len(dependencySemanticRequiredRoles))
	bindings := make(map[string]dependencySemanticValidatedArtifact, len(dependencySemanticRequiredRoles))
	for _, role := range dependencySemanticRequiredRoles {
		raw := []byte("exact bytes for " + role)
		digest := sha256Hex(raw)
		artifacts[role] = artifactInput{Path: role + ".jsonl", Raw: raw, SHA256: digest}
		bindings[role] = dependencySemanticValidatedArtifact{
			artifactSHA256: digest,
			schemaRole:     role + "_schema",
			schemaID:       "urn:test:dependency-semantics",
			schemaVersion:  "1",
			schemaSHA256:   strings.Repeat("f", 64),
		}
	}
	return artifacts, dependencySemanticValidationProof{seal: dependencySemanticValidationAuthority, byRole: bindings}
}

func cloneDependencySemanticProofFixture() (map[string]artifactInput, dependencySemanticValidationProof) {
	artifacts, proof := dependencySemanticProofFixture()
	artifactCopy := make(map[string]artifactInput, len(artifacts))
	for key, value := range artifacts {
		artifactCopy[key] = value
	}
	proofCopy := dependencySemanticValidationProof{seal: proof.seal, byRole: make(map[string]dependencySemanticValidatedArtifact, len(proof.byRole))}
	for key, value := range proof.byRole {
		proofCopy.byRole[key] = value
	}
	return artifactCopy, proofCopy
}

func TestDependencySemanticProofRejectsEveryBindingDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]artifactInput, *dependencySemanticValidationProof)
	}{
		{"artifact role roster", func(a map[string]artifactInput, _ *dependencySemanticValidationProof) {
			delete(a, dependencySemanticRequiredRoles[0])
		}},
		{"proof role roster", func(_ map[string]artifactInput, p *dependencySemanticValidationProof) {
			delete(p.byRole, dependencySemanticRequiredRoles[0])
		}},
		{"missing expected role", func(_ map[string]artifactInput, p *dependencySemanticValidationProof) {
			delete(p.byRole, dependencySemanticRequiredRoles[0])
			p.byRole["unexpected_role"] = dependencySemanticValidatedArtifact{}
		}},
		{"artifact bytes", func(_ map[string]artifactInput, p *dependencySemanticValidationProof) {
			role := dependencySemanticRequiredRoles[0]
			binding := p.byRole[role]
			binding.artifactSHA256 = strings.Repeat("0", 64)
			p.byRole[role] = binding
		}},
		{"artifact declared digest", func(a map[string]artifactInput, _ *dependencySemanticValidationProof) {
			role := dependencySemanticRequiredRoles[0]
			input := a[role]
			input.SHA256 = strings.Repeat("0", 64)
			a[role] = input
		}},
		{"aliased artifact bytes", func(a map[string]artifactInput, p *dependencySemanticValidationProof) {
			first, second := dependencySemanticRequiredRoles[0], dependencySemanticRequiredRoles[1]
			input := a[first]
			a[second] = artifactInput{Path: second + ".jsonl", Raw: input.Raw, SHA256: input.SHA256}
			binding := p.byRole[second]
			binding.artifactSHA256 = input.SHA256
			p.byRole[second] = binding
		}},
		{"schema coordinate", func(_ map[string]artifactInput, p *dependencySemanticValidationProof) {
			role := dependencySemanticRequiredRoles[0]
			binding := p.byRole[role]
			binding.schemaID = ""
			p.byRole[role] = binding
		}},
		{"schema digest", func(_ map[string]artifactInput, p *dependencySemanticValidationProof) {
			role := dependencySemanticRequiredRoles[0]
			binding := p.byRole[role]
			binding.schemaSHA256 = "short"
			p.byRole[role] = binding
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			artifacts, proof := cloneDependencySemanticProofFixture()
			tc.mutate(artifacts, &proof)
			if err := validateDependencySemanticProof(proof, artifacts); err == nil {
				t.Fatal("drifted dependency semantic proof was accepted")
			}
		})
	}
}

func TestParseDependencySemanticRowsRejectsMalformedCarriers(t *testing.T) {
	validRaw := []byte("{\"row_kind\":\"artifact_manifest\"}\n{\"row_kind\":\"validation_summary\"}\n")
	tests := []struct {
		name  string
		input artifactInput
	}{
		{"empty", artifactInput{Path: "empty.jsonl"}},
		{"invalid utf8", artifactInput{Path: "utf8.jsonl", Raw: []byte{0xff}}},
		{"duplicate keys", artifactInput{Path: "duplicate.jsonl", Raw: []byte("{\"row_kind\":\"artifact_manifest\",\"row_kind\":\"artifact_manifest\"}\n")}},
		{"invalid json", artifactInput{Path: "json.jsonl", Raw: []byte("{\"row_kind\":")}},
		{"missing row kind", artifactInput{Path: "kind.jsonl", Raw: []byte("{}\n")}},
		{"missing summary", artifactInput{Path: "summary.jsonl", Raw: []byte("{\"row_kind\":\"artifact_manifest\"}\n")}},
		{"parsed discriminator", artifactInput{Path: "parsed.jsonl", Raw: validRaw, ParsedRows: []artifactParsedRow{{Line: 1, Discriminator: "kind", Kind: "artifact_manifest", RawStart: 0, RawEnd: 32}}}},
		{"parsed range", artifactInput{Path: "parsed.jsonl", Raw: validRaw, ParsedRows: []artifactParsedRow{{Line: 1, Discriminator: "row_kind", Kind: "artifact_manifest", RawStart: -1, RawEnd: 1}}}},
		{"parsed roster", artifactInput{Path: "parsed.jsonl", Raw: validRaw, ParsedRows: []artifactParsedRow{{Line: 1, Discriminator: "row_kind", Kind: "artifact_manifest", RawStart: 0, RawEnd: 32}}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseDependencySemanticRows(tc.input); err == nil {
				t.Fatal("malformed dependency rows were accepted")
			}
		})
	}

	rows, err := parseDependencySemanticRows(artifactInput{Path: "blank-lines.jsonl", Raw: append([]byte("\n  \n"), validRaw...)})
	if err != nil || len(rows.byKind["artifact_manifest"]) != 1 || len(rows.byKind["validation_summary"]) != 1 {
		t.Fatalf("blank-line carrier parse = %#v, %v", rows.byKind, err)
	}
}

func TestDependencySemanticHydrationAndLocatorBounds(t *testing.T) {
	body := []byte("abcdef")
	digest := sha256Hex(body)
	selected := body[1:4]
	coordinate := dependencyHydrationCoordinate{digest: digest, start: 1, end: 4, count: 3, rangeSHA: sha256Hex(selected)}
	ref, sourceURL := "ref", "https://example.invalid/source"
	loaded := loadedEvidence{Bodies: map[string]exactEvidenceBody{digest: {
		Bytes:       body,
		Coordinates: map[evidenceSourceCoordinate]string{{Ref: ref, URL: sourceURL}: strings.Repeat("a", 64)},
	}}}
	rows := dependencySemanticRows{path: "fixture.jsonl"}
	row := dependencySemanticRow{line: 2, kind: "fact"}

	badCoordinates := []dependencyHydrationCoordinate{
		{},
		{digest: digest, start: 1, end: 9, count: 8, rangeSHA: coordinate.rangeSHA},
		{digest: digest, start: 1, end: 4, count: 3, rangeSHA: strings.Repeat("0", 64)},
	}
	for index, bad := range badCoordinates {
		if err := validateExactHydrationCoordinate(rows, row, bad, ref, sourceURL, loaded); err == nil {
			t.Fatalf("bad coordinate %d was accepted", index)
		}
	}
	missing := coordinate
	missing.digest = strings.Repeat("0", 64)
	if err := validateExactHydrationCoordinate(rows, row, missing, ref, sourceURL, loaded); err == nil {
		t.Fatal("missing evidence body was accepted")
	}
	if err := validateExactHydrationCoordinate(rows, row, coordinate, "", "", loaded); err != nil {
		t.Fatalf("coordinate-only hydration = %v", err)
	}
	if err := validateExactHydrationCoordinate(rows, row, coordinate, "other", sourceURL, loaded); err == nil {
		t.Fatal("non-matching source coordinate was accepted")
	}

	coordinateObject := map[string]interface{}{
		"source_content_sha256": digest, "byte_start_offset": json.Number("1"),
		"byte_end_offset_exclusive": json.Number("4"), "selected_range_byte_count": json.Number("3"),
		"selected_range_sha256": coordinate.rangeSHA,
	}
	if _, err := coordinateFromRow(map[string]interface{}{}); err == nil {
		t.Fatal("missing hydration object was accepted")
	}
	if _, err := parseDependencyHydrationCoordinate(map[string]interface{}{"source_content_sha256": digest}); err == nil {
		t.Fatal("incomplete hydration object was accepted")
	}
	validRow := dependencySemanticRow{line: 3, kind: "fact", data: map[string]interface{}{
		"evidence_hydration_coordinate": coordinateObject,
		"content_sha256":                digest,
		"block_content_sha256":          coordinate.rangeSHA,
	}}
	if _, err := validateRowHydration(rows, validRow, loaded); err != nil {
		t.Fatalf("valid row hydration = %v", err)
	}
	badDigestRow := validRow
	badDigestRow.data = cloneSemanticObject(validRow.data)
	badDigestRow.data["content_sha256"] = "wrong"
	if _, err := validateRowHydration(rows, badDigestRow, loaded); err == nil {
		t.Fatal("mismatched content digest was accepted")
	}
	badBlockRow := validRow
	badBlockRow.data = cloneSemanticObject(validRow.data)
	badBlockRow.data["block_content_sha256"] = "wrong"
	if _, err := validateRowHydration(rows, badBlockRow, loaded); err == nil {
		t.Fatal("mismatched selected-range digest was accepted")
	}

	locator := evidenceLocator{ID: "loc", SourceContentSHA256: digest, ByteStartOffset: 1, ByteEndOffsetExclusive: 4, SelectedRangeByteCount: 3, SelectedRangeSHA256: coordinate.rangeSHA, SourceRefs: []string{ref}, SourceURLs: []string{sourceURL}}
	plan := &parsedPlan{
		Locators:      map[string]evidenceLocator{"loc": locator},
		Symbols:       map[string]apiSymbol{"symbol": {EvidenceLocatorIDs: []string{"missing", "loc"}}},
		Relationships: map[string]apiRelationship{"relation": {LocatorIDs: []string{"loc"}}},
		Properties:    map[string]apiPropertyClaim{"property": {LocatorIDs: []string{"loc"}}},
	}
	for _, id := range []string{"symbol", "relation", "property"} {
		if ids, ok := planGraphElementLocatorIDs(plan, id); !ok || len(ids) != 1 && id != "symbol" {
			t.Fatalf("locator ids for %q = %#v, %t", id, ids, ok)
		}
	}
	if _, ok := planGraphElementLocatorIDs(plan, "absent"); ok {
		t.Fatal("absent graph element resolved locators")
	}
	if !planSymbolHasExactLocator(plan, plan.Symbols["symbol"], coordinate, ref, sourceURL) {
		t.Fatal("exact symbol locator was not found")
	}
	if planSymbolHasExactLocator(plan, apiSymbol{EvidenceLocatorIDs: []string{"loc"}}, coordinate, "other", sourceURL) {
		t.Fatal("mismatched symbol locator was accepted")
	}
}

func cloneSemanticObject(input map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func TestDependencySemanticPrimitiveHelperBounds(t *testing.T) {
	if got, err := semanticStringSet(map[string]interface{}{"values": []interface{}{"a", "b"}}, "values"); err != nil || len(got) != 2 {
		t.Fatalf("semantic string set = %#v, %v", got, err)
	}
	for _, object := range []map[string]interface{}{
		{},
		{"values": []interface{}{"a", "a"}},
		{"values": []interface{}{"a", 1}},
	} {
		if _, err := semanticStringSet(object, "values"); err == nil {
			t.Fatal("invalid semantic string set was accepted")
		}
	}
	if _, err := semanticRawMember([]byte("{"), "x"); err == nil {
		t.Fatal("malformed raw object was accepted")
	}
	if _, err := semanticRawMember([]byte("{}"), "x"); err == nil {
		t.Fatal("absent raw member was accepted")
	}
	if raw, err := semanticRawMember([]byte(`{"x":1}`), "x"); err != nil || string(raw) != "1" {
		t.Fatalf("raw member = %s, %v", raw, err)
	}

	if values, ok := semanticNullableStringSlice(map[string]interface{}{"v": nil}, "v"); !ok || len(values) != 0 {
		t.Fatalf("nullable string slice = %#v, %t", values, ok)
	}
	if _, ok := semanticNullableStringSlice(map[string]interface{}{}, "v"); ok {
		t.Fatal("absent nullable string slice was present")
	}
	if values, ok := semanticObjectSlice(map[string]interface{}{"v": []interface{}{map[string]interface{}{"x": "y"}}}, "v"); !ok || len(values) != 1 {
		t.Fatalf("semantic object slice = %#v, %t", values, ok)
	}
	if _, ok := semanticObjectSlice(map[string]interface{}{"v": []interface{}{1}}, "v"); ok {
		t.Fatal("non-object semantic slice was accepted")
	}

	if err := requireSemanticKeySet("keys", map[string]int{"a": 1}, map[string]string{"a": "x"}); err != nil {
		t.Fatal(err)
	}
	if err := requireSemanticKeySet("keys", map[string]int{}, map[string]string{"a": "x"}); err == nil {
		t.Fatal("count mismatch was accepted")
	}
	if err := requireSemanticKeySet("keys", map[string]int{"b": 1}, map[string]string{"a": "x"}); err == nil {
		t.Fatal("identity mismatch was accepted")
	}

	if !hasEmptyOrDuplicateSemanticStrings([]string{""}) || !hasEmptyOrDuplicateSemanticStrings([]string{"a", "a"}) || hasEmptyOrDuplicateSemanticStrings([]string{"a", "b"}) {
		t.Fatal("empty/duplicate roster classification drifted")
	}
	if !equalStringSlices([]string{"a"}, []string{"a"}) || equalStringSlices([]string{"a"}, nil) || equalStringSlices([]string{"a"}, []string{"b"}) {
		t.Fatal("ordered string equality drifted")
	}
	if !equalStringSet([]string{"a", "b"}, []string{"b", "a"}) || equalStringSet([]string{"a", "a"}, []string{"a", "a"}) || equalStringSet([]string{"a"}, []string{"a", "b"}) {
		t.Fatal("string set equality drifted")
	}
	if !anyStringPrefix("prefix-value", []string{"", "prefix"}) || anyStringPrefix("value", []string{"x"}) {
		t.Fatal("prefix classification drifted")
	}
	if !snakeTokenPresent("one_two", "two") || snakeTokenPresent("one_two", "three") {
		t.Fatal("snake token classification drifted")
	}

	if !semanticTextContainsAll("Alpha beta", "alpha", "beta") || semanticTextContainsAll(7, "a") || semanticTextContainsAll("alpha", "alpha", "beta") {
		t.Fatal("semantic all-fragment classification drifted")
	}
	if !semanticTextContainsAny("Alpha beta", "z", "beta") || semanticTextContainsAny(7, "a") || semanticTextContainsAny("alpha", "z") {
		t.Fatal("semantic any-fragment classification drifted")
	}
	if !semanticRosterContainsToken([]string{"Alpha Beta", "gamma"}, "alpha-beta") || semanticRosterContainsToken([]string{"alpha"}, "beta") {
		t.Fatal("semantic roster token classification drifted")
	}
	if !semanticRosterContainsAnyToken([]string{"alpha"}, "beta", "alpha") || semanticRosterContainsAnyToken([]string{"alpha"}, "beta") {
		t.Fatal("semantic roster any-token classification drifted")
	}
	if !semanticRosterContainsTokenFragment([]string{"alpha-beta"}, "pha b") || semanticRosterContainsTokenFragment([]string{"alpha"}, "beta") {
		t.Fatal("semantic roster fragment classification drifted")
	}

	for _, value := range []string{"IEEE-754", "float32", "double"} {
		if !semanticNumericTextUnsafe(value) {
			t.Fatalf("unsafe numeric text %q was accepted", value)
		}
	}
	if semanticNumericTextUnsafe("decimal string") {
		t.Fatal("exact decimal text was classified unsafe")
	}
	if semanticNumericPolicyTextUnsafe("float64 is forbidden") || !semanticNumericPolicyTextUnsafe("use float64") || semanticNumericPolicyTextUnsafe("decimal") {
		t.Fatal("numeric policy safety classification drifted")
	}
	if err := validateExactNumericDisposition("", "decimal", "exact"); err == nil {
		t.Fatal("empty numeric semantics were accepted")
	}
	if err := validateExactNumericDisposition("float64", "decimal", "exact"); err == nil {
		t.Fatal("unsafe numeric semantics were accepted")
	}
	if err := validateExactNumericDisposition("decimal", "not_applicable", "exact"); err == nil {
		t.Fatal("mismatched numeric applicability was accepted")
	}
	if err := validateExactNumericDisposition("decimal", "decimal_string", "exact_decimal"); err != nil {
		t.Fatalf("exact numeric disposition = %v", err)
	}

	rows := dependencySemanticRows{byKind: map[string][]dependencySemanticRow{"z": nil, "a": nil}}
	if got := strings.Join(sortedSemanticKinds(rows), ","); got != "a,z" {
		t.Fatalf("sorted semantic kinds = %q", got)
	}
	if !equalOrderedStrings([]string{"a", "b"}, []string{"a", "b"}) || equalOrderedStrings([]string{"a"}, nil) || equalOrderedStrings([]string{"a"}, []string{"b"}) {
		t.Fatal("ordered semantic equality drifted")
	}
}

func TestDependencySemanticReferenceAndOccurrenceBounds(t *testing.T) {
	digest := strings.Repeat("a", 64)
	validArtifact := map[string]interface{}{"artifact": "schema", "artifact_version": "1", "artifact_sha256": digest}
	if got, ok := dependencyArtifactIdentityReference(validArtifact); !ok || got.id != "schema" || got.version != "1" || got.digest != digest {
		t.Fatalf("artifact reference = %#v, %t", got, ok)
	}
	for _, object := range []map[string]interface{}{
		nil,
		{"artifact": "schema", "artifact_version": "1", "artifact_sha256": "short"},
		{"artifact": " schema", "artifact_version": "1", "artifact_sha256": digest},
	} {
		if _, ok := dependencyArtifactIdentityReference(object); ok {
			t.Fatalf("invalid artifact reference %#v was accepted", object)
		}
	}

	validProfile := map[string]interface{}{"profile_id": "schema", "profile_version": "1", "profile_sha256": digest}
	if got, ok := dependencyProfileReferenceFromFields(validProfile, "profile"); !ok || got.id != "schema" {
		t.Fatalf("profile reference = %#v, %t", got, ok)
	}
	for _, object := range []map[string]interface{}{
		nil,
		{"profile_id": "schema", "profile_version": "1", "profile_sha256": "short"},
		{"profile_id": " schema", "profile_version": "1", "profile_sha256": digest},
	} {
		if _, ok := dependencyProfileReferenceFromFields(object, "profile"); ok {
			t.Fatalf("invalid profile reference %#v was accepted", object)
		}
	}
	if _, present, bound := nullableDependencyProfileReference(nil, "profile"); present || bound {
		t.Fatal("nil nullable reference was present")
	}
	allNil := map[string]interface{}{"profile_id": nil, "profile_version": nil, "profile_sha256": nil}
	if _, present, bound := nullableDependencyProfileReference(allNil, "profile"); !present || bound {
		t.Fatal("all-null reference did not preserve explicit null")
	}
	partial := map[string]interface{}{"profile_id": "schema", "profile_version": nil, "profile_sha256": nil}
	if _, present, bound := nullableDependencyProfileReference(partial, "profile"); present || bound {
		t.Fatal("partial nullable reference was accepted")
	}
	if got, present, bound := nullableDependencyProfileReference(validProfile, "profile"); !present || !bound || dependencyProfileReferenceKey(got) == "" {
		t.Fatalf("bound nullable reference = %#v, %t/%t", got, present, bound)
	}

	locator := evidenceLocator{
		ID: "loc", EvidenceManifestSHA256: digest, SourceContentSHA256: digest,
		ByteStartOffset: 0, ByteEndOffsetExclusive: 3, SelectedRangeByteCount: 3,
		SelectedRangeSHA256: digest, SourceRefs: []string{"ref"}, SourceURLs: []string{"https://example.invalid"},
	}
	coordinate := dependencyHydrationCoordinate{digest: digest, start: 0, end: 3, count: 3, rangeSHA: digest}
	plan := &parsedPlan{Locators: map[string]evidenceLocator{"loc": locator}}
	if !planLocatorRosterCoversCoordinate(plan, []string{"missing", "loc"}, coordinate, "ref", "https://example.invalid") {
		t.Fatal("exact locator roster coordinate was not covered")
	}
	if planLocatorRosterCoversCoordinate(plan, []string{"loc"}, coordinate, "other", "https://example.invalid") {
		t.Fatal("mismatched locator coordinate was covered")
	}

	access := sourceOperationResourceAccess{resourceSourceSymbol: "resource", relationshipLabel: "reads", evidenceLocatorIDs: []string{"missing", "loc"}, documentationDerivedFactIDs: []string{"fact"}}
	if got := sourceOperationAccessOccurrenceIdentity("operation", access, plan); got == "" {
		t.Fatal("source operation occurrence identity is empty")
	}

	rowData := map[string]interface{}{
		"source_ref": "ref", "source_url": "https://example.invalid", "surface_kind": "resource",
		"evidence_hydration_coordinate": map[string]interface{}{
			"source_content_sha256": digest, "byte_start_offset": json.Number("0"),
			"byte_end_offset_exclusive": json.Number("3"), "selected_range_byte_count": json.Number("3"),
			"selected_range_sha256": digest,
		},
	}
	classification := sourceClassificationOccurrence{SurfaceKind: "resource", Locator: locator}
	if got := sourceClassificationOccurrenceCoverageCount([]sourceClassificationOccurrence{classification}, rowData); got != 1 {
		t.Fatalf("classification coverage = %d", got)
	}
	if got := sourceClassificationOccurrenceCoverageCount(nil, map[string]interface{}{}); got != 0 {
		t.Fatalf("malformed classification coverage = %d", got)
	}
	wrongSurface := cloneSemanticObject(rowData)
	wrongSurface["surface_kind"] = "operation"
	if got := sourceClassificationOccurrenceCoverageCount([]sourceClassificationOccurrence{classification}, wrongSurface); got != 0 {
		t.Fatalf("wrong-surface classification coverage = %d", got)
	}

	contradictions := []dependencySemanticRow{
		{data: map[string]interface{}{"contradiction_id": "other", "assertions": []interface{}{"assertion"}}},
		{data: map[string]interface{}{"contradiction_id": "wanted", "assertions": []interface{}{"other", "assertion"}}},
	}
	if !contradictionContainsAssertion(contradictions, "wanted", "assertion") || contradictionContainsAssertion(contradictions, "wanted", "absent") {
		t.Fatal("contradiction assertion membership drifted")
	}
}

func TestDependencySemanticFieldOccurrenceBounds(t *testing.T) {
	digest := strings.Repeat("a", 64)
	fields := map[string]string{
		"symbol": "symbol", "surface": "surface", "field": "field", "type": "type",
		"cardinality": "cardinality", "requirement": "requirement", "sections": "sections",
	}
	base := map[string]interface{}{
		"symbol": "record", "surface": "resource", "field": "name", "type": "string",
		"cardinality": "one", "requirement": "required", "sections": []interface{}{"$.name"},
		exactDocumentationDerivedFactIDField: "fact-1",
	}
	if identity, err := fieldOccurrenceIdentity(base, fields); err != nil || identity == "" {
		t.Fatalf("field occurrence identity = %q, %v", identity, err)
	}
	for _, mutate := range []func(map[string]interface{}){
		func(row map[string]interface{}) { delete(row, "symbol") },
		func(row map[string]interface{}) { row["surface"] = "" },
		func(row map[string]interface{}) { row["sections"] = "$.name" },
		func(row map[string]interface{}) { row[exactDocumentationDerivedFactIDField] = 7 },
	} {
		row := cloneSemanticObject(base)
		mutate(row)
		if _, err := fieldOccurrenceIdentity(row, fields); err == nil {
			t.Fatalf("invalid field occurrence %#v was accepted", row)
		}
	}

	coordinate := map[string]interface{}{
		"source_content_sha256": digest, "byte_start_offset": json.Number("0"),
		"byte_end_offset_exclusive": json.Number("1"), "selected_range_byte_count": json.Number("1"),
		"selected_range_sha256": digest,
	}
	locatorBound := map[string]interface{}{
		"evidence_manifest_sha256": digest, "source_ref": "ref", "source_url": "https://example.invalid",
		"source_content_sha256": digest, "evidence_locator_id": "loc",
		"evidence_hydration_coordinate": coordinate,
	}
	if identity, err := fieldOccurrenceEvidenceIdentity(locatorBound); err != nil || identity == "" {
		t.Fatalf("locator-bound field identity = %q, %v", identity, err)
	}
	missing := cloneSemanticObject(locatorBound)
	delete(missing, "source_ref")
	if _, err := fieldOccurrenceEvidenceIdentity(missing); err == nil {
		t.Fatal("incomplete locator-bound field identity was accepted")
	}
	mismatch := cloneSemanticObject(locatorBound)
	mismatch["source_content_sha256"] = strings.Repeat("b", 64)
	if _, err := fieldOccurrenceEvidenceIdentity(mismatch); err == nil {
		t.Fatal("mismatched hydration digest was accepted")
	}
}

func TestArtifactHydrationTraversalBounds(t *testing.T) {
	body := []byte("abc")
	digest := sha256Hex(body)
	coordinate := map[string]interface{}{
		"source_content_sha256": digest, "byte_start_offset": json.Number("0"),
		"byte_end_offset_exclusive": json.Number("3"), "selected_range_byte_count": json.Number("3"),
		"selected_range_sha256": digest,
	}
	identity := evidenceBodyIdentity{ManifestSHA256: strings.Repeat("f", 64), SourceRef: "ref", ContentSHA256: digest}
	loaded := loadedEvidence{
		Bodies: map[string]exactEvidenceBody{digest: {Bytes: body}},
		MetadataByIdentity: map[evidenceBodyIdentity]evidenceBodyMetadata{
			identity: {SourceURL: "https://example.invalid"},
		},
	}
	newResult := func() map[string]struct{} { return map[string]struct{}{} }

	if err := collectArtifactHydrationIdentities(nil, "", "", loaded, newResult(), maxProviderJSONNestingDepth+1, &artifactHydrationWalkState{}); err == nil {
		t.Fatal("over-depth hydration traversal was accepted")
	}
	if err := collectArtifactHydrationIdentities(nil, "", "", loaded, newResult(), 1, &artifactHydrationWalkState{nodes: int(maxProviderJSONNodesPerArtifact)}); err == nil {
		t.Fatal("over-node hydration traversal was accepted")
	}
	for name, value := range map[string]interface{}{
		"coordinate not object": map[string]interface{}{"evidence_hydration_coordinate": "bad"},
		"coordinates not array": map[string]interface{}{"evidence_hydration_coordinates": "bad"},
		"binding not object":    map[string]interface{}{"evidence_hydration_coordinates": []interface{}{1}},
		"binding no coordinate": map[string]interface{}{"evidence_hydration_coordinates": []interface{}{map[string]interface{}{}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := collectArtifactHydrationIdentities(value, "ref", "https://example.invalid", loaded, newResult(), 1, &artifactHydrationWalkState{}); err == nil {
				t.Fatal("malformed hydration traversal was accepted")
			}
		})
	}

	single := map[string]interface{}{
		"source_symbol": "ref", "source_url": "https://example.invalid",
		"evidence_hydration_coordinate": coordinate,
		"nested":                        []interface{}{map[string]interface{}{"diagnostic_navigation_coordinate": "ignored"}},
	}
	result := newResult()
	if err := collectArtifactHydrationIdentities(single, "", "", loaded, result, 1, &artifactHydrationWalkState{}); err != nil || len(result) != 1 {
		t.Fatalf("single hydration traversal = %#v, %v", result, err)
	}
	plural := map[string]interface{}{
		"evidence_hydration_coordinates": []interface{}{map[string]interface{}{
			"source_ref": "ref", "source_url": "https://example.invalid", "coordinate": coordinate,
		}},
	}
	result = newResult()
	if err := collectArtifactHydrationIdentities(plural, "", "", loaded, result, 1, &artifactHydrationWalkState{}); err != nil || len(result) != 1 {
		t.Fatalf("plural hydration traversal = %#v, %v", result, err)
	}

	malformed := cloneSemanticObject(coordinate)
	malformed["selected_range_byte_count"] = json.Number("2")
	if err := addHydratedEvidenceIdentity(malformed, "ref", "https://example.invalid", loaded, newResult()); err == nil {
		t.Fatal("malformed hydrated identity was accepted")
	}
	missing := cloneSemanticObject(coordinate)
	missing["source_content_sha256"] = strings.Repeat("0", 64)
	if err := addHydratedEvidenceIdentity(missing, "ref", "https://example.invalid", loaded, newResult()); err == nil {
		t.Fatal("missing hydrated body was accepted")
	}
	badRange := cloneSemanticObject(coordinate)
	badRange["selected_range_sha256"] = strings.Repeat("0", 64)
	if err := addHydratedEvidenceIdentity(badRange, "ref", "https://example.invalid", loaded, newResult()); err == nil {
		t.Fatal("wrong hydrated bytes were accepted")
	}
	if err := addHydratedEvidenceIdentity(coordinate, "other", "https://example.invalid", loaded, newResult()); err == nil {
		t.Fatal("unbound hydrated evidence identity was accepted")
	}
	duplicateLoaded := loaded
	duplicateLoaded.MetadataByIdentity = make(map[evidenceBodyIdentity]evidenceBodyMetadata, 2)
	duplicateLoaded.MetadataByIdentity[identity] = evidenceBodyMetadata{SourceURL: "https://example.invalid"}
	duplicateLoaded.MetadataByIdentity[evidenceBodyIdentity{ManifestSHA256: strings.Repeat("e", 64), SourceRef: "ref", ContentSHA256: digest}] = evidenceBodyMetadata{SourceURL: "https://example.invalid"}
	if err := addHydratedEvidenceIdentity(coordinate, "ref", "https://example.invalid", duplicateLoaded, newResult()); err == nil {
		t.Fatal("ambiguous hydrated evidence identity was accepted")
	}

	input := artifactInput{RowsByKind: map[string][]map[string]interface{}{
		"artifact_manifest":   {{}},
		"validation_summary":  {{}},
		"documentation_claim": {single},
	}}
	if identities, err := artifactHydratedEvidenceIdentities(input, loaded); err != nil || len(identities) != 1 {
		t.Fatalf("artifact hydrated identities = %#v, %v", identities, err)
	}
}

func TestSampleParseProgramClosedSetBounds(t *testing.T) {
	jsonDecoder := map[string]interface{}{"kind": sampleDecoderKindUTF8Strict}
	noDecoder := map[string]interface{}{"kind": sampleDecoderKindNone}
	jsonParser := map[string]interface{}{
		"kind": sampleParserKindJSONRFC8259, "duplicate_key_policy": "reject",
		"trailing_content_policy": "reject", "number_handling": "preserve_raw_lexeme",
	}
	unsupported := map[string]interface{}{"kind": sampleParserKindUnsupported}
	notApplicable := map[string]interface{}{"kind": sampleParserKindNotApplicable}

	if err := validateSampleParseProgram(jsonDecoder, jsonParser, "application/json", "utf-8"); err != nil {
		t.Fatalf("canonical JSON parse program = %v", err)
	}
	if err := validateSampleParseProgram(noDecoder, unsupported, "text/plain", "utf-8"); err != nil {
		t.Fatalf("canonical unsupported program = %v", err)
	}
	if err := validateSampleParseProgram(noDecoder, notApplicable, "application/octet-stream", ""); err != nil {
		t.Fatalf("canonical not-applicable program = %v", err)
	}

	tests := []struct {
		name                 string
		decoder, parser      map[string]interface{}
		mediaType, character string
	}{
		{"decoder kind", map[string]interface{}{"kind": "base64"}, jsonParser, "application/json", "utf-8"},
		{"parser kind", jsonDecoder, map[string]interface{}{"kind": "yaml"}, "application/json", "utf-8"},
		{"decoder shape", map[string]interface{}{"kind": sampleDecoderKindUTF8Strict, "extra": true}, jsonParser, "application/json", "utf-8"},
		{"parser shape", jsonDecoder, map[string]interface{}{"kind": sampleParserKindJSONRFC8259}, "application/json", "utf-8"},
		{"JSON binding", jsonDecoder, jsonParser, "text/plain", "utf-8"},
		{"unsupported shape", noDecoder, map[string]interface{}{"kind": sampleParserKindUnsupported, "extra": true}, "text/plain", "utf-8"},
		{"unsupported JSON", noDecoder, unsupported, "application/json", "utf-8"},
		{"not-applicable shape", noDecoder, map[string]interface{}{"kind": sampleParserKindNotApplicable, "extra": true}, "text/plain", ""},
		{"not-applicable decoder", jsonDecoder, notApplicable, "text/plain", "utf-8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateSampleParseProgram(tc.decoder, tc.parser, tc.mediaType, tc.character); err == nil {
				t.Fatal("invalid parse program was accepted")
			}
		})
	}

	if err := requireExactSemanticObjectKeys(map[string]interface{}{"a": 1}, "object", "a"); err != nil {
		t.Fatal(err)
	}
	if err := requireExactSemanticObjectKeys(map[string]interface{}{"a": 1}, "object", "b"); err == nil {
		t.Fatal("wrong exact object key was accepted")
	}
	if err := requireExactSemanticObjectKeys(map[string]interface{}{}, "object", "a"); err == nil {
		t.Fatal("wrong exact object key count was accepted")
	}
}

func TestDependencyProfileSummaryBounds(t *testing.T) {
	summaryData := map[string]interface{}{
		"api_element_role_count":                 json.Number("0"),
		"api_relationship_count":                 json.Number("0"),
		"api_property_family_count":              json.Number("0"),
		"canonical_capability_stage_count":       json.Number("0"),
		"canonical_table_surface_count":          json.Number("0"),
		"external_document_object_class_count":   json.Number("0"),
		"external_document_edge_label_count":     json.Number("0"),
		"source_authority_allowed_class_count":   json.Number("0"),
		"source_authority_forbidden_class_count": json.Number("0"),
		"organization_id_kernel_injected":        true,
		"provider_specific_go_required":          false,
		"kernel_go_required":                     false,
		"canonical_execution_is_admitted_nodes":  true,
		"ready_to_execute":                       false,
		"execution_blockers":                     []interface{}{"admission_required"},
	}
	rowsFor := func(summary map[string]interface{}, authorities ...dependencySemanticRow) dependencySemanticRows {
		return dependencySemanticRows{path: "profile.jsonl", byKind: map[string][]dependencySemanticRow{
			"validation_summary":     {{line: 1, kind: "validation_summary", data: summary}},
			"source_authority_class": authorities,
		}}
	}
	if err := validateProfileSummaryFromRows(rowsFor(cloneSemanticObject(summaryData))); err != nil {
		t.Fatalf("valid empty profile summary = %v", err)
	}
	badCount := cloneSemanticObject(summaryData)
	badCount["api_element_role_count"] = json.Number("1")
	if err := validateProfileSummaryFromRows(rowsFor(badCount)); err == nil {
		t.Fatal("incorrect profile row count was accepted")
	}
	missingPolicy := dependencySemanticRow{line: 2, kind: "source_authority_class", data: map[string]interface{}{"disposition": "forbidden"}}
	if err := validateProfileSummaryFromRows(rowsFor(cloneSemanticObject(summaryData), missingPolicy)); err == nil {
		t.Fatal("source authority without policy was accepted")
	}
	unknownDisposition := dependencySemanticRow{line: 2, kind: "source_authority_class", data: map[string]interface{}{"disposition": "optional", "policy_rule": "rule"}}
	if err := validateProfileSummaryFromRows(rowsFor(cloneSemanticObject(summaryData), unknownDisposition)); err == nil {
		t.Fatal("unknown source authority disposition was accepted")
	}
	forbidden := dependencySemanticRow{line: 2, kind: "source_authority_class", data: map[string]interface{}{"disposition": "forbidden", "policy_rule": "rule"}}
	wrongAuthorityCount := cloneSemanticObject(summaryData)
	if err := validateProfileSummaryFromRows(rowsFor(wrongAuthorityCount, forbidden)); err == nil {
		t.Fatal("incorrect source-authority count was accepted")
	}
	badPosture := cloneSemanticObject(summaryData)
	badPosture["ready_to_execute"] = true
	if err := validateProfileSummaryFromRows(rowsFor(badPosture)); err == nil {
		t.Fatal("executable candidate posture was accepted")
	}
}

func TestSourceOperationEvidenceOccurrenceBounds(t *testing.T) {
	digest := strings.Repeat("a", 64)
	locator := evidenceLocator{
		ID: "loc", EvidenceManifestSHA256: digest, SourceContentSHA256: digest,
		ByteStartOffset: 0, ByteEndOffsetExclusive: 3, SelectedRangeByteCount: 3,
		SelectedRangeSHA256: digest, SourceRefs: []string{"ref"}, SourceURLs: []string{"https://example.invalid"},
	}
	plan := &parsedPlan{Locators: map[string]evidenceLocator{"loc": locator}}
	factID := "fact"
	occurrenceID := stableID("opocc", lengthPrefixedIdentityKey(factID, "loc", candidateEvidenceLocatorIdentityKey(locator)))
	validOccurrence := map[string]interface{}{"occurrence_id": occurrenceID, "evidence_locator_id": "loc", "documentation_derived_fact_id": factID}
	row := map[string]interface{}{"operation_evidence_occurrences": []interface{}{validOccurrence}}
	classifications := []sourceClassificationOccurrence{{SurfaceKind: "resource", Locator: locator}}
	locators, facts, err := parseSourceOperationEvidenceOccurrences(row, plan, classifications, "resource")
	if err != nil || len(locators) != 1 || facts[factID] != "loc" {
		t.Fatalf("valid source occurrence = %#v/%#v, %v", locators, facts, err)
	}
	if _, _, err := parseSourceOperationEvidenceOccurrences(map[string]interface{}{}, plan, classifications, "resource"); err == nil {
		t.Fatal("missing operation occurrences were accepted")
	}
	for name, occurrence := range map[string]map[string]interface{}{
		"incomplete": {"occurrence_id": occurrenceID},
		"wrong id":   {"occurrence_id": "wrong", "evidence_locator_id": "loc", "documentation_derived_fact_id": factID},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseSourceOperationEvidenceOccurrences(map[string]interface{}{"operation_evidence_occurrences": []interface{}{occurrence}}, plan, classifications, "resource"); err == nil {
				t.Fatal("invalid operation occurrence was accepted")
			}
		})
	}
	malformedPlan := &parsedPlan{Locators: map[string]evidenceLocator{"loc": {ID: "loc"}}}
	if _, _, err := parseSourceOperationEvidenceOccurrences(row, malformedPlan, classifications, "resource"); err == nil {
		t.Fatal("occurrence with malformed locator was accepted")
	}
	if _, _, err := parseSourceOperationEvidenceOccurrences(row, plan, nil, "resource"); err == nil {
		t.Fatal("unclassified operation occurrence was accepted")
	}
}

func TestDependencySemanticResidualHelperBounds(t *testing.T) {
	if _, ok := semanticJSONInt64("42"); ok {
		t.Fatal("non-number semantic integer was accepted")
	}
	if err := requireEqualStringFields(map[string]interface{}{"a": "x"}, map[string]interface{}{"a": "x"}, "a"); err != nil {
		t.Fatal(err)
	}
	if err := requireEqualStringFields(map[string]interface{}{"a": "x"}, map[string]interface{}{}, "a"); err == nil {
		t.Fatal("missing equal string field was accepted")
	}
	if _, present := semanticNullableString(map[string]interface{}{}, "missing"); present {
		t.Fatal("missing nullable string was reported present")
	}
	defaultProfile := fieldSecurityProfile{rules: []fieldSecurityRule{{id: "default", matchKind: "default", outputClass: "public"}}}
	if class, rule, ok := defaultProfile.classify(map[string]interface{}{}); !ok || class != "public" || rule != "default" {
		t.Fatalf("default field classification = %q/%q, %t", class, rule, ok)
	}
	missingInputProfile := fieldSecurityProfile{rules: []fieldSecurityRule{{id: "exact", matchKind: "exact_registry_membership", inputMember: "classification", registryMember: "classes"}}}
	if _, _, ok := missingInputProfile.classify(map[string]interface{}{}); ok {
		t.Fatal("missing field-security input was classified")
	}

	digest := strings.Repeat("a", 64)
	for name, object := range map[string]map[string]interface{}{
		"missing coordinate":    {"profile_id": "id", "profile_version": "1", "profile_sha256": digest},
		"extra key":             {"profile_id": "id", "profile_version": "1", "profile_sha256": digest, "program": map[string]interface{}{"kind": "x"}, "extra": true},
		"unmarshalable program": {"profile_id": "id", "profile_version": "1", "profile_sha256": digest, "program": map[string]interface{}{"bad": make(chan int)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseSampleExecutableProfile(object, "profile"); err == nil {
				t.Fatal("invalid executable profile was accepted")
			}
		})
	}
}
