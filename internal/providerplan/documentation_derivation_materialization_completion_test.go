package providerplan

import (
	"strings"
	"testing"
)

func TestDocumentationMaterializationCompletionParentIdentityFailsClosed(t *testing.T) {
	digest := func(label string) string { return sha256Hex([]byte(label)) }
	valid := documentationTargetParentRegistrationIdentity{
		TargetArtifactRole: "target", TargetArtifactSHA256: digest("artifact"),
		TargetSchemaRole: "target_schema", TargetSchemaID: "urn:test:target", TargetSchemaVersion: "1", TargetSchemaSHA256: digest("schema"),
		TargetRowKind: "operation", TargetBindingKind: exactDocumentationTargetRowMember, TargetMemberJSONPointer: "/members",
		TargetRowSelectorRosterSHA256: digest("roster"), TargetRowSelectorSHA256: digest("selector"), TargetRowCanonicalSHA256: digest("row"),
	}
	canonical, err := canonicalDocumentationTargetParentRegistration(valid)
	if err != nil || len(canonical) == 0 {
		t.Fatalf("valid parent registration canonical=%q err=%v", canonical, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*documentationTargetParentRegistrationIdentity)
		want   string
	}{
		{"empty role", func(identity *documentationTargetParentRegistrationIdentity) { identity.TargetArtifactRole = "" }, "target artifact role"},
		{"whole row", func(identity *documentationTargetParentRegistrationIdentity) {
			identity.TargetBindingKind = exactDocumentationTargetWholeRow
		}, "not a row-member"},
		{"invalid member pointer", func(identity *documentationTargetParentRegistrationIdentity) {
			identity.TargetMemberJSONPointer = "members"
		}, "member pointer"},
		{"invalid digest", func(identity *documentationTargetParentRegistrationIdentity) {
			identity.TargetRowCanonicalSHA256 = "not-a-digest"
		}, "target row digest"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if _, err := canonicalDocumentationTargetParentRegistration(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}

	shape := documentationTargetShape{key: documentationTargetShapeKey{artifactRole: "target", rowKind: "operation", bindingKind: exactDocumentationTargetRowMember}, rowSelectorJSONPointers: []string{"/operation_id"}}
	key, err := documentationTargetParentIndexKeyForShape(shape)
	if err != nil || key.artifactRole != "target" || !isLowerSHA256(key.selectorRosterSHA256) {
		t.Fatalf("valid parent index key=%#v err=%v", key, err)
	}
	shape.key.bindingKind = exactDocumentationTargetWholeRow
	if _, err := documentationTargetParentIndexKeyForShape(shape); err == nil || !strings.Contains(err.Error(), "row-member") {
		t.Fatalf("whole-row parent index error=%v", err)
	}

	canonicalRow := []byte(`{"operation_id":"one","row_kind":"operation"}`)
	if got, err := canonicalDocumentationTargetRowSHA256(dependencySemanticRow{raw: canonicalRow}); err != nil || got != sha256Hex(canonicalRow) {
		t.Fatalf("canonical row digest=%q err=%v", got, err)
	}
	if got, err := canonicalDocumentationTargetRowSHA256(dependencySemanticRow{canonicalSHA256: digest("prevalidated")}); err != nil || got != digest("prevalidated") {
		t.Fatalf("prevalidated digest=%q err=%v", got, err)
	}
	if _, err := canonicalDocumentationTargetRowSHA256(dependencySemanticRow{raw: []byte(`{"row_kind":}`)}); err == nil || !strings.Contains(err.Error(), "canonical JSON") {
		t.Fatalf("noncanonical row error=%v", err)
	}
}

func TestDocumentationMaterializationCompletionSchemaResolutionFailsClosed(t *testing.T) {
	root := map[string]interface{}{
		"definitions": map[string]interface{}{
			"selected": map[string]interface{}{"type": "object", "properties": map[string]interface{}{"row_kind": map[string]interface{}{"const": "operation"}}},
		},
	}
	branches, err := documentationRowKindSchemaBranches(map[string]interface{}{"$ref": "#/definitions/selected"}, root, "row_kind", "operation", "$", map[string]bool{})
	if err != nil || len(branches) != 1 {
		t.Fatalf("resolved reference branches=%#v err=%v", branches, err)
	}
	for _, test := range []struct {
		name string
		node interface{}
		want string
	}{
		{"non-string reference", map[string]interface{}{"$ref": 1}, "not a string"},
		{"malformed branches", map[string]interface{}{"oneOf": []interface{}{}}, "empty or malformed"},
		{"ambiguous all of", map[string]interface{}{"allOf": []interface{}{}}, "ambiguous allOf"},
		{"nonfinite discriminator", map[string]interface{}{"properties": map[string]interface{}{"row_kind": map[string]interface{}{"type": "string"}}}, "not finite"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := documentationRowKindSchemaBranches(test.node, root, "row_kind", "operation", "$", map[string]bool{}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want %q", err, test.want)
			}
		})
	}
	if _, err := documentationResolveSchemaNode(root, map[string]interface{}{"$dynamicRef": 7}); err == nil || !strings.Contains(err.Error(), "not a string") {
		t.Fatalf("dynamic reference type error=%v", err)
	}
	if scalar, err := documentationResolveSchemaNode(root, "scalar"); err != nil || scalar != "scalar" {
		t.Fatalf("scalar resolution=%#v err=%v", scalar, err)
	}

	for _, test := range []struct {
		name   string
		schema map[string]interface{}
		want   bool
	}{
		{"type string", map[string]interface{}{"type": "string"}, true},
		{"string enum", map[string]interface{}{"enum": []interface{}{"a", "b"}}, true},
		{"mixed enum", map[string]interface{}{"enum": []interface{}{"a", 2}}, false},
		{"empty enum", map[string]interface{}{"enum": []interface{}{}}, false},
	} {
		if got := documentationSchemaProvesString(test.schema); got != test.want {
			t.Fatalf("%s proves string=%t, want %t", test.name, got, test.want)
		}
	}
	for _, object := range []map[string]interface{}{
		{}, {"required": "not-a-list"}, {"required": []interface{}{""}}, {"required": []interface{}{1}},
	} {
		if _, err := documentationSchemaRequiredSet(object); err == nil {
			t.Fatalf("malformed required roster accepted: %#v", object)
		}
	}
	if _, err := documentationJSONPointerValue([]interface{}{}, []string{"field"}); err == nil || !strings.Contains(err.Error(), "non-object") {
		t.Fatalf("non-object pointer traversal error=%v", err)
	}
	if _, err := documentationResolveSchemaNode(map[string]interface{}{}, map[string]interface{}{"$ref": "#/missing"}); err == nil {
		t.Fatal("unknown local schema reference was accepted")
	}
}

func TestDocumentationMaterializationCompletionMaterializationRejectsMismatchedAuthority(t *testing.T) {
	_, _, facts, _, _ := documentationClosureExecutionFixture(t)
	fact := facts[0]
	artifact := artifactInput{Raw: []byte("target-artifact:" + fact.FactID)}
	schema := []byte(`{"type":"object"}`)
	resolution := dependencySemanticDerivationTargetResolution{
		artifactRole: fact.TargetArtifactRole, artifactSHA256: sha256Hex(artifact.Raw), targetRowKind: fact.TargetRowKind,
		schemaRole: "completion_schema", schemaID: "urn:test:completion", schemaVersion: "1", schemaSHA256: sha256Hex(schema), schemaBytes: schema,
	}
	memberPointer := ""
	var member []byte
	if fact.TargetBindingKind == exactDocumentationTargetRowMember {
		memberPointer, member = fact.TargetMemberJSONPointer+"/0", fact.CanonicalOutputFields
	}
	rowDigest := sha256Hex([]byte("target-row:" + fact.FactID))
	valid, err := newDocumentationTargetMaterialization(fact, artifact, resolution, rowDigest, memberPointer, member, maxDocumentationTargetMaterializationCanonicalBytes)
	if err != nil || !isLowerSHA256(valid.bindingSHA256) || valid.canonicalBytes <= 0 {
		t.Fatalf("valid materialization=%#v err=%v", valid, err)
	}
	wrongArtifact := artifact
	wrongArtifact.Raw = []byte("different")
	if _, err := newDocumentationTargetMaterialization(fact, wrongArtifact, resolution, rowDigest, memberPointer, member, maxDocumentationTargetMaterializationCanonicalBytes); err == nil || !strings.Contains(err.Error(), "does not equal") {
		t.Fatalf("artifact authority mismatch error=%v", err)
	}
	if _, err := newDocumentationTargetMaterialization(fact, artifact, resolution, "not-a-digest", memberPointer, member, maxDocumentationTargetMaterializationCanonicalBytes); err == nil || !strings.Contains(err.Error(), "prevalidated canonical parent-row digest") {
		t.Fatalf("row digest mismatch error=%v", err)
	}
	if fact.TargetBindingKind == exactDocumentationTargetRowMember {
		if _, err := newDocumentationTargetMaterialization(fact, artifact, resolution, rowDigest, "", member, maxDocumentationTargetMaterializationCanonicalBytes); err == nil || !strings.Contains(err.Error(), "no exact member instance") {
			t.Fatalf("member pointer error=%v", err)
		}
	} else if _, err := newDocumentationTargetMaterialization(fact, artifact, resolution, rowDigest, "/forbidden/0", []byte(`{}`), maxDocumentationTargetMaterializationCanonicalBytes); err == nil || !strings.Contains(err.Error(), "whole-row") {
		t.Fatalf("whole-row member state error=%v", err)
	}
	if _, err := exactDocumentationCanonicalFactByteCount(facts, 0); err == nil || !strings.Contains(err.Error(), "limit is invalid") {
		t.Fatalf("invalid fact-byte limit error=%v", err)
	}
	if total, err := exactDocumentationCanonicalFactByteCount(facts, maxDocumentationTargetMaterializationCanonicalBytes); err != nil || total <= 0 {
		t.Fatalf("canonical fact bytes=%d err=%v", total, err)
	}
}

func TestDocumentationMaterializationCompletionDeclarationsAndSchemaProofs(t *testing.T) {
	profiles, authority, artifacts, rows := zeroMatchDocumentationTargetFixture(t, "operation_alpha")
	groups, shapes, rules, err := registerDocumentationTargetDeclarations(profiles, authority, artifacts, rows)
	if err != nil || len(groups) != 1 || len(shapes) != 1 || len(rules) != 1 {
		t.Fatalf("valid declarations groups/shapes/rules=%d/%d/%d err=%v", len(groups), len(shapes), len(rules), err)
	}
	if _, _, _, err := registerDocumentationTargetDeclarations(nil, authority, artifacts, rows); err == nil || !strings.Contains(err.Error(), "no executable profiles") {
		t.Fatalf("empty declaration roster error=%v", err)
	}
	for profileKey, profile := range profiles {
		wrongKeyProfiles := map[string]executableDocumentationDerivationProfile{"wrong": profile}
		if _, _, _, err := registerDocumentationTargetDeclarations(wrongKeyProfiles, authority, artifacts, rows); err == nil || !strings.Contains(err.Error(), "differs from") {
			t.Fatalf("wrong profile key error=%v", err)
		}
		badArtifact := artifacts[profile.Program.OrderedRules[0].TargetArtifactRole]
		badArtifact.Raw = []byte("different artifact")
		badArtifacts := map[string]artifactInput{profile.Program.OrderedRules[0].TargetArtifactRole: badArtifact}
		if _, _, _, err := registerDocumentationTargetDeclarations(map[string]executableDocumentationDerivationProfile{profileKey: profile}, authority, badArtifacts, rows); err == nil || !strings.Contains(err.Error(), "no exact schema-authorized") {
			t.Fatalf("wrong artifact binding error=%v", err)
		}
		dynamicZero := profile
		dynamicZero.Program.OrderedRules = append([]exactDocumentationDerivationRule(nil), profile.Program.OrderedRules...)
		dynamicZero.Program.OrderedRules[0].TargetRowSelector = []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/operation_id", ExpectedStringTemplate: "${operation_id}"}}
		if _, _, _, err := registerDocumentationTargetDeclarations(map[string]executableDocumentationDerivationProfile{profileKey: dynamicZero}, authority, artifacts, rows); err == nil || !strings.Contains(err.Error(), "permits zero matches") {
			t.Fatalf("dynamic zero-match selector error=%v", err)
		}
		unknownTarget := profile
		unknownTarget.Program.OrderedRules = append([]exactDocumentationDerivationRule(nil), profile.Program.OrderedRules...)
		unknownTarget.Program.OrderedRules[0].TargetArtifactRole = "unknown_role"
		if _, _, _, err := registerDocumentationTargetDeclarations(map[string]executableDocumentationDerivationProfile{profileKey: unknownTarget}, authority, artifacts, rows); err == nil || !strings.Contains(err.Error(), "target") {
			t.Fatalf("unknown target authority error=%v", err)
		}
		break
	}

	valid := documentationMemberSchemaResolutionFixture(t, "resource_accesses", nil)
	var root map[string]interface{}
	if err := decodeOneValidationProfileJSON(valid.schemaBytes, &root); err != nil {
		t.Fatal(err)
	}
	branches, err := documentationRowKindSchemaBranches(root, root, "row_kind", "api_operation", "$", map[string]bool{})
	if err != nil || len(branches) != 1 {
		t.Fatalf("fixture branches=%d err=%v", len(branches), err)
	}
	if err := documentationSchemaProvesRequiredStringAtPointer(root, branches[0], []string{"row_kind"}); err != nil {
		t.Fatalf("required string discriminator proof: %v", err)
	}
	for _, test := range []struct {
		name   string
		start  map[string]interface{}
		tokens []string
		want   string
	}{
		{"non-object", map[string]interface{}{"type": "object", "required": []interface{}{"field"}, "properties": map[string]interface{}{"field": "scalar"}}, []string{"field", "next"}, "non-object"},
		{"missing required", map[string]interface{}{"type": "object", "required": []interface{}{}, "properties": map[string]interface{}{}}, []string{"field"}, "not required"},
		{"missing properties", map[string]interface{}{"type": "object", "required": []interface{}{"field"}}, []string{"field"}, "no finite properties"},
		{"absent property", map[string]interface{}{"type": "object", "required": []interface{}{"field"}, "properties": map[string]interface{}{}}, []string{"field"}, "absent"},
		{"not a string", map[string]interface{}{"type": "object", "required": []interface{}{"field"}, "properties": map[string]interface{}{"field": map[string]interface{}{"type": "integer"}}}, []string{"field"}, "exact string"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := documentationSchemaProvesRequiredStringAtPointer(root, test.start, test.tokens); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestDocumentationMaterializationCompletionUtilityBoundaries(t *testing.T) {
	memberRule := exactDocumentationDerivationRule{TargetBindingKind: exactDocumentationTargetRowMember, TargetRowSelector: []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/id", ExpectedStringTemplate: "literal"}}}
	selectors, digest, literal, err := literalDocumentationTargetRowSelector(memberRule)
	if err != nil || !literal || len(selectors) != 1 || !isLowerSHA256(digest) {
		t.Fatalf("literal selector=%#v digest=%q literal=%t err=%v", selectors, digest, literal, err)
	}
	memberRule.TargetRowSelector[0].ExpectedStringTemplate = "${capture}"
	if selectors, digest, literal, err := literalDocumentationTargetRowSelector(memberRule); err != nil || literal || selectors != nil || digest != "" {
		t.Fatalf("dynamic selector=%#v digest=%q literal=%t err=%v", selectors, digest, literal, err)
	}
	memberRule.TargetRowSelector[0].ExpectedStringTemplate = ""
	if _, _, _, err := literalDocumentationTargetRowSelector(memberRule); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty selector error=%v", err)
	}
	memberRule.TargetBindingKind = exactDocumentationTargetWholeRow
	if selectors, digest, literal, err := literalDocumentationTargetRowSelector(memberRule); err != nil || !literal || selectors != nil || digest != sha256Hex(nil) {
		t.Fatalf("whole-row selector=%#v digest=%q literal=%t err=%v", selectors, digest, literal, err)
	}

	if equalResolvedDocumentationTargetRowSelectors([]exactDocumentationResolvedTargetRowSelector{{TargetRowJSONPointer: "/id", ExpectedString: "a"}}, nil) {
		t.Fatal("different selector lengths compared equal")
	}
	if equalResolvedDocumentationMemberIdentities([]exactDocumentationResolvedMemberIdentity{{OutputJSONPointer: "/id", ExpectedString: "a"}}, []exactDocumentationResolvedMemberIdentity{{OutputJSONPointer: "/id", ExpectedString: "b"}}) {
		t.Fatal("different member identities compared equal")
	}
	if _, err := canonicalDocumentationJSON(map[string]interface{}{"not_json": func() {}}); err == nil {
		t.Fatal("non-JSON value was canonicalized")
	}
	if _, err := exactDocumentationJSONStringByteCount(string([]byte{0xff})); err == nil {
		t.Fatal("invalid UTF-8 string was accepted")
	}
	if documentationTargetMaterializationRoot([]documentationTargetMaterialization{{canonical: []byte("x"), canonicalBytes: 0}}) != "" {
		t.Fatal("invalid root ownership returned a digest")
	}

	invalidClosure := documentationTargetParentRegistrationClosure{}
	if err := validateDocumentationTargetParentRegistrationClosure(invalidClosure); err == nil || !strings.Contains(err.Error(), "invalid resource") {
		t.Fatalf("invalid closure error=%v", err)
	}
	invalidReceipt := documentationTargetParentRegistrationClosure{
		seal: documentationTargetParentRegistrationAuthority, registrations: []documentationTargetParentRegistrationReceipt{{SHA256: "bad", CanonicalBytes: 1}},
		registrationCount: 1, rootSHA256: sha256Hex(nil), canonicalByteCount: 1,
	}
	if err := validateDocumentationTargetParentRegistrationClosure(invalidReceipt); err == nil || !strings.Contains(err.Error(), "receipt") {
		t.Fatalf("invalid closure receipt error=%v", err)
	}
	if _, _, _, err := registerDocumentationTargetParentRowsWithRoot(nil, nil, nil, 0, 1, 1, nil); err == nil || !strings.Contains(err.Error(), "invalid resource limits") {
		t.Fatalf("invalid indexing limits error=%v", err)
	}

	descriptor := documentationMemberSchemaDescriptor{}
	if err := validateDocumentationMemberIdentitySchema(descriptor, nil); err == nil || !strings.Contains(err.Error(), "no exact") {
		t.Fatalf("empty member identity schema error=%v", err)
	}
	if _, _, err := resolveDocumentationMemberIdentity(map[string]interface{}{"id": "present"}, []string{"/missing"}); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("missing member identity error=%v", err)
	}
	if _, err := executeAndValidateDocumentationDerivationClosure(dependencySemanticRows{}, documentationClaimDerivationState{}, dependencySemanticDerivationTargetSchemaAuthority{}, nil, nil, sourceClassificationSelectionProof{}, nil); err == nil || !strings.Contains(err.Error(), "sealed target-schema authority") {
		t.Fatalf("unsealed closure authority error=%v", err)
	}
}

func TestDocumentationMaterializationCompletionParentIndexRefusesAmbiguousRows(t *testing.T) {
	shapeKey := documentationTargetShapeKey{artifactRole: "role", rowKind: "operation", bindingKind: exactDocumentationTargetRowMember, memberJSONPointer: "/members"}
	shape := documentationTargetShape{key: shapeKey, rowSelectorJSONPointers: []string{"/operation_id"}}
	validRow := func(data map[string]interface{}, raw []byte) dependencySemanticRows {
		return dependencySemanticRows{byKind: map[string][]dependencySemanticRow{"operation": {{data: data, raw: raw}}}}
	}
	canonical := []byte(`{"operation_id":"one","row_kind":"operation"}`)
	if _, _, _, err := registerDocumentationTargetParentRowsWithRoot(nil, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: {key: shapeKey}}, nil, 1, 1, 10000, nil); err == nil || !strings.Contains(err.Error(), "no selector roster") {
		t.Fatalf("missing selector roster error=%v", err)
	}
	if _, _, _, err := registerDocumentationTargetParentRowsWithRoot(nil, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape}, nil, 1, 1, 10000, nil); err == nil || !strings.Contains(err.Error(), "no parsed target rows") {
		t.Fatalf("missing target rows error=%v", err)
	}
	badPointer := shape
	badPointer.rowSelectorJSONPointers = []string{"operation_id"}
	if _, _, _, err := registerDocumentationTargetParentRowsWithRoot(nil, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: badPointer}, map[string]dependencySemanticRows{"role": validRow(map[string]interface{}{"operation_id": "one"}, canonical)}, 1, 1, 10000, nil); err == nil || !strings.Contains(err.Error(), "selector") {
		t.Fatalf("invalid selector pointer error=%v", err)
	}
	if _, _, _, err := registerDocumentationTargetParentRowsWithRoot(nil, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape}, map[string]dependencySemanticRows{"role": validRow(map[string]interface{}{}, canonical)}, 1, 1, 10000, nil); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("missing selector value error=%v", err)
	}
	if _, _, _, err := registerDocumentationTargetParentRowsWithRoot(nil, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape}, map[string]dependencySemanticRows{"role": validRow(map[string]interface{}{"operation_id": 1}, canonical)}, 1, 1, 10000, nil); err == nil || !strings.Contains(err.Error(), "nonempty string") {
		t.Fatalf("non-string selector value error=%v", err)
	}
	if _, _, _, err := registerDocumentationTargetParentRowsWithRoot(nil, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape}, map[string]dependencySemanticRows{"role": validRow(map[string]interface{}{"operation_id": "one"}, []byte(`{"operation_id":}`))}, 1, 1, 10000, nil); err == nil || !strings.Contains(err.Error(), "canonical JSON") {
		t.Fatalf("noncanonical row error=%v", err)
	}
	duplicateRows := validRow(map[string]interface{}{"operation_id": "one"}, canonical)
	duplicateRows.byKind["operation"] = append(duplicateRows.byKind["operation"], duplicateRows.byKind["operation"][0])
	if _, _, _, err := registerDocumentationTargetParentRowsWithRoot(nil, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape}, map[string]dependencySemanticRows{"role": duplicateRows}, 2, 2, 10000, nil); err == nil || !strings.Contains(err.Error(), "duplicates parent-row selector") {
		t.Fatalf("duplicate selector identity error=%v", err)
	}
}

func TestDocumentationMaterializationCompletionMemberSchemaRejectsOpenOrPartialShapes(t *testing.T) {
	branchWithMember := func(member interface{}) map[string]interface{} {
		return map[string]interface{}{
			"type": "object", "required": []interface{}{"members"},
			"properties": map[string]interface{}{"members": member},
		}
	}
	closedMember := func() map[string]interface{} {
		fields := map[string]interface{}{
			"access_kind":                    map[string]interface{}{"type": "string"},
			"documentation_derived_fact_ids": map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
			"evidence_locator_ids":           map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "string"}},
			"resource_symbol":                map[string]interface{}{"type": "string"},
		}
		return map[string]interface{}{"type": "object", "additionalProperties": false, "required": []interface{}{"access_kind", "documentation_derived_fact_ids", "evidence_locator_ids", "resource_symbol"}, "properties": fields}
	}
	validArray := func() map[string]interface{} { return map[string]interface{}{"type": "array", "items": closedMember()} }
	for _, test := range []struct {
		name   string
		branch map[string]interface{}
	}{
		{"member absent", map[string]interface{}{"type": "object", "required": []interface{}{"members"}, "properties": map[string]interface{}{}}},
		{"member not required", map[string]interface{}{"type": "object", "required": []interface{}{}, "properties": map[string]interface{}{"members": validArray()}}},
		{"member not array", branchWithMember(map[string]interface{}{"type": "string"})},
		{"array has no items", branchWithMember(map[string]interface{}{"type": "array"})},
		{"items scalar", branchWithMember(map[string]interface{}{"type": "array", "items": "scalar"})},
		{"open item", branchWithMember(map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}})},
		{"item lacks properties", branchWithMember(map[string]interface{}{"type": "array", "items": map[string]interface{}{"type": "object", "additionalProperties": false, "required": []interface{}{}}})},
		{"item partial required", func() map[string]interface{} {
			item := closedMember()
			item["required"] = []interface{}{"access_kind"}
			return branchWithMember(map[string]interface{}{"type": "array", "items": item})
		}()},
		{"missing envelope", func() map[string]interface{} {
			item := closedMember()
			delete(item["properties"].(map[string]interface{}), "documentation_derived_fact_ids")
			item["required"] = []interface{}{"access_kind", "evidence_locator_ids", "resource_symbol"}
			return branchWithMember(map[string]interface{}{"type": "array", "items": item})
		}()},
		{"envelope wrong type", func() map[string]interface{} {
			item := closedMember()
			item["properties"].(map[string]interface{})["documentation_derived_fact_ids"] = map[string]interface{}{"type": "integer"}
			return branchWithMember(map[string]interface{}{"type": "array", "items": item})
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := documentationMemberSchemaAtPointer(map[string]interface{}{}, test.branch, []string{"members"}); err == nil {
				t.Fatal("invalid member schema was accepted")
			}
		})
	}
	member, names, err := documentationMemberSchemaAtPointer(map[string]interface{}{}, branchWithMember(validArray()), []string{"members"})
	if err != nil || len(member) == 0 || len(names) != 4 {
		t.Fatalf("closed member schema bytes/names=%d/%d err=%v", len(member), len(names), err)
	}
}

func TestDocumentationMaterializationCompletionClosureAndAllocationBoundaries(t *testing.T) {
	execution, classification, facts, materializations, parents := documentationClosureExecutionFixture(t)
	fact := cloneExactDocumentationDerivedFactValue(facts[0])
	proof, err := sealDocumentationDerivationClosure(sha256Hex([]byte("completion-profile")), &execution, classification, materializations, parents, int64(len(facts)), 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*documentationDerivationClosureProof)
		want   string
	}{
		{"invalid provider", func(proof *documentationDerivationClosureProof) { proof.provider = "" }, "invalid identity or counts"},
		{"malformed root", func(proof *documentationDerivationClosureProof) { proof.profileBudgetRootSHA256 = "bad" }, "profile budget digest"},
		{"invalid parent cap", func(proof *documentationDerivationClosureProof) { proof.targetParentRegistrationLimit = 1 }, "invalid identity or counts"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneDocumentationClosureProof(proof)
			test.mutate(&candidate)
			if err := validateDocumentationDerivationClosureProof(candidate); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want %q", err, test.want)
			}
		})
	}

	artifact := artifactInput{Raw: []byte("completion-artifact")}
	schema := []byte(`{"type":"object"}`)
	resolution := dependencySemanticDerivationTargetResolution{artifactRole: fact.TargetArtifactRole, artifactSHA256: sha256Hex(artifact.Raw), targetRowKind: fact.TargetRowKind, schemaRole: "schema", schemaID: "urn:test:schema", schemaVersion: "1", schemaSHA256: sha256Hex(schema), schemaBytes: schema}
	row := sha256Hex([]byte("row"))
	if _, err := newDocumentationTargetMaterialization(fact, artifact, resolution, row, "", nil, -1); err == nil || !strings.Contains(err.Error(), "remaining limit") {
		t.Fatalf("negative allocation limit error=%v", err)
	}
	if fact.TargetBindingKind == exactDocumentationTargetWholeRow {
		if _, err := newDocumentationTargetMaterialization(fact, artifact, resolution, row, "/member/0", []byte(`{}`), maxDocumentationTargetMaterializationCanonicalBytes); err == nil || !strings.Contains(err.Error(), "whole-row") {
			t.Fatalf("whole-row member allocation error=%v", err)
		}
	} else {
		if _, err := newDocumentationTargetMaterialization(fact, artifact, resolution, row, "", nil, maxDocumentationTargetMaterializationCanonicalBytes); err == nil || !strings.Contains(err.Error(), "no exact member") {
			t.Fatalf("member allocation error=%v", err)
		}
	}
	identity := documentationMaterializationFixture(t, "docfact_utf8", "evloc_utf8", "/members/0").identity
	identity.TargetSchemaID = string([]byte{0xff})
	if _, err := exactDocumentationTargetMaterializationCanonicalByteCount(identity); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid identity UTF-8 error=%v", err)
	}
}

func TestDocumentationMaterializationCompletionResolutionAuthorityBoundaries(t *testing.T) {
	valid := documentationMemberSchemaResolutionFixture(t, "resource_accesses", nil)
	for _, test := range []struct {
		name    string
		mutate  func(*dependencySemanticDerivationTargetResolution)
		pointer string
		want    string
	}{
		{"wrong discriminator", func(resolution *dependencySemanticDerivationTargetResolution) {
			resolution.discriminatorProperty = "kind"
		}, "/resource_accesses", "not exact"},
		{"invalid pointer", func(_ *dependencySemanticDerivationTargetResolution) {}, "resource_accesses", "nonempty canonical"},
		{"invalid schema bytes", func(resolution *dependencySemanticDerivationTargetResolution) {
			resolution.schemaBytes = []byte(`{`)
			resolution.schemaSHA256 = sha256Hex(resolution.schemaBytes)
		}, "/resource_accesses", "decode documentation target schema"},
		{"missing row kind", func(resolution *dependencySemanticDerivationTargetResolution) { resolution.targetRowKind = "missing" }, "/resource_accesses", "no branch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if _, err := resolveDocumentationMemberSchema(candidate, test.pointer); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want %q", err, test.want)
			}
		})
	}
	cycleRoot := map[string]interface{}{"definitions": map[string]interface{}{"loop": map[string]interface{}{"$ref": "#/definitions/loop"}}}
	if _, err := documentationRowKindSchemaBranches(map[string]interface{}{"$ref": "#/definitions/loop"}, cycleRoot, "row_kind", "operation", "$", map[string]bool{}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("reference cycle error=%v", err)
	}
	for _, pointer := range []string{"", "/", "/bad~2escape", "/trailing~"} {
		if _, err := documentationJSONPointerTokens(pointer); err == nil {
			t.Fatalf("invalid pointer %q was accepted", pointer)
		}
	}
	if count, err := exactDocumentationJSONStringByteCount("\\\"\b\f\n\r\t\u0001\u2028"); err != nil || count <= 2 {
		t.Fatalf("escaped JSON string count=%d err=%v", count, err)
	}
	materialization := documentationMaterializationFixture(t, "docfact_binding", "evloc_binding", "/members/0")
	if err := validateDocumentationTargetMaterializationFactBinding(materialization, exactDocumentationDerivedFact{}); err == nil || !strings.Contains(err.Error(), "differs") {
		t.Fatalf("mismatched materialization fact binding error=%v", err)
	}
	validReceipt := documentationTargetParentRegistrationReceipt{SHA256: sha256Hex([]byte("receipt")), CanonicalBytes: 1}
	invalidRoot := documentationTargetParentRegistrationClosure{seal: documentationTargetParentRegistrationAuthority, registrations: []documentationTargetParentRegistrationReceipt{validReceipt}, registrationCount: 1, canonicalByteCount: 1, rootSHA256: sha256Hex([]byte("wrong"))}
	if err := validateDocumentationTargetParentRegistrationClosure(invalidRoot); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("mismatched parent closure root error=%v", err)
	}
}
