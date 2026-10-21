package providerplan

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func TestResolveDocumentationMemberSchemaAuthorizesExactClosedResourceAccesses(t *testing.T) {
	resolution := documentationMemberSchemaResolutionFixture(t, "resource_accesses", nil)
	descriptor, err := resolveDocumentationMemberSchema(resolution, "/resource_accesses")
	if err != nil {
		t.Fatalf("resolveDocumentationMemberSchema() error = %v", err)
	}
	if descriptor.pointer != "/resource_accesses" || len(descriptor.tokens) != 1 || descriptor.tokens[0] != "resource_accesses" {
		t.Fatalf("resolved pointer = %#v, want exact /resource_accesses token", descriptor)
	}
	wantFields := map[string]struct{}{
		"access_kind":                    {},
		"documentation_derived_fact_ids": {},
		"evidence_locator_ids":           {},
		"resource_symbol":                {},
	}
	if !stringSetsEqual(descriptor.propertyNames, wantFields) {
		t.Fatalf("resolved member fields = %v, want %v", sortedSetKeys(descriptor.propertyNames), sortedSetKeys(wantFields))
	}
}

func TestDocumentationMaterializationBindingComparisonIsLengthPrefixedAndTotal(t *testing.T) {
	if compareDocumentationLengthPrefixedBytes([]byte("a"), []byte("b")) >= 0 {
		t.Fatal("byte comparison lost lexical order")
	}
	if compareDocumentationLengthPrefixedString("aa", "b") <= 0 {
		t.Fatal("length-prefixed comparison did not prioritize canonical length")
	}
	if compareDocumentationMaterializationBinding("a", "binding", 1, "a", "binding", 2) >= 0 {
		t.Fatal("materialization binding comparison did not order canonical byte counts")
	}
}

func TestResolveDocumentationMemberSchemaUsesCanonicalEscapedPointerTokens(t *testing.T) {
	const property = "resource/accesses~primary"
	resolution := documentationMemberSchemaResolutionFixture(t, property, nil)
	descriptor, err := resolveDocumentationMemberSchema(resolution, "/resource~1accesses~0primary")
	if err != nil {
		t.Fatalf("resolve escaped member pointer: %v", err)
	}
	if len(descriptor.tokens) != 1 || descriptor.tokens[0] != property {
		t.Fatalf("escaped pointer tokens = %v, want exact decoded property %q", descriptor.tokens, property)
	}
	if _, err := resolveDocumentationMemberSchema(resolution, "/resource~01accesses~0primary"); err == nil {
		t.Fatal("noncanonical alternate escaping resolved to the same schema property")
	}
}

func TestResolveDocumentationMemberSchemaRejectsUnprovenOrOpenMemberShapes(t *testing.T) {
	for _, test := range []struct {
		name      string
		mutate    func(branch, memberArray, memberItem map[string]interface{})
		wantError string
	}{
		{
			name: "pointer absent",
			mutate: func(branch, _, _ map[string]interface{}) {
				delete(branch["properties"].(map[string]interface{}), "resource_accesses")
			},
			wantError: `property "resource_accesses" is absent`,
		},
		{
			name: "pointer property not required",
			mutate: func(branch, _, _ map[string]interface{}) {
				branch["required"] = []interface{}{"row_kind"}
			},
			wantError: `property "resource_accesses" is not required`,
		},
		{
			name: "pointer does not select array",
			mutate: func(branch, _, _ map[string]interface{}) {
				branch["properties"].(map[string]interface{})["resource_accesses"] = map[string]interface{}{
					"type":                 "object",
					"additionalProperties": false,
					"properties":           map[string]interface{}{},
					"required":             []interface{}{},
				}
			},
			wantError: "is not an array",
		},
		{
			name: "member object is open",
			mutate: func(_, _, memberItem map[string]interface{}) {
				delete(memberItem, "additionalProperties")
			},
			wantError: "not one closed object shape",
		},
		{
			name: "member fields are not all required",
			mutate: func(_, _, memberItem map[string]interface{}) {
				memberItem["required"] = []interface{}{
					"access_kind",
					"documentation_derived_fact_ids",
					"evidence_locator_ids",
				}
			},
			wantError: "properties are not all required",
		},
		{
			name: "fact envelope is not string array",
			mutate: func(_, _, memberItem map[string]interface{}) {
				memberItem["properties"].(map[string]interface{})["documentation_derived_fact_ids"] = map[string]interface{}{
					"type":  "array",
					"items": map[string]interface{}{"type": "integer"},
				}
			},
			wantError: `field "documentation_derived_fact_ids" items are not strings`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolution := documentationMemberSchemaResolutionFixture(t, "resource_accesses", test.mutate)
			if _, err := resolveDocumentationMemberSchema(resolution, "/resource_accesses"); err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestDocumentationTargetSelectorSchemaRequiresEveryBranchToProveRequiredString(t *testing.T) {
	selector := []exactDocumentationTargetRowSelectorTemplate{{
		TargetRowJSONPointer: "/operation_id", ExpectedStringTemplate: "query_profit_and_loss_detail",
	}}
	resolution := documentationMemberSchemaResolutionFixture(t, "resource_accesses", func(branch, _, _ map[string]interface{}) {
		branch["required"] = []interface{}{"operation_id", "resource_accesses", "row_kind"}
		branch["properties"].(map[string]interface{})["operation_id"] = map[string]interface{}{"type": "string"}
	})
	if err := validateDocumentationTargetRowSelectorSchema(resolution, selector); err != nil {
		t.Fatalf("validate exact selector schema: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(branch map[string]interface{})
	}{
		{
			name: "optional",
			mutate: func(branch map[string]interface{}) {
				branch["required"] = []interface{}{"resource_accesses", "row_kind"}
			},
		},
		{
			name: "non-string",
			mutate: func(branch map[string]interface{}) {
				branch["properties"].(map[string]interface{})["operation_id"] = map[string]interface{}{"type": "integer"}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := documentationMemberSchemaResolutionFixture(t, "resource_accesses", func(branch, _, _ map[string]interface{}) {
				branch["required"] = []interface{}{"operation_id", "resource_accesses", "row_kind"}
				branch["properties"].(map[string]interface{})["operation_id"] = map[string]interface{}{"type": "string"}
				test.mutate(branch)
			})
			if err := validateDocumentationTargetRowSelectorSchema(candidate, selector); err == nil {
				t.Fatal("selector schema without one exact required string path was accepted")
			}
		})
	}
}

func TestDocumentationMemberIdentitySchemaAndValueAreSourceIndependent(t *testing.T) {
	resolution := documentationMemberSchemaResolutionFixture(t, "resource_accesses", nil)
	descriptor, err := resolveDocumentationMemberSchema(resolution, "/resource_accesses")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDocumentationMemberIdentitySchema(descriptor, []string{"/resource_symbol"}); err != nil {
		t.Fatalf("validate exact member identity schema: %v", err)
	}
	if err := validateDocumentationMemberIdentitySchema(descriptor, []string{"/documentation_derived_fact_ids"}); err == nil {
		t.Fatal("evidence-sensitive fact roster was accepted as semantic member identity")
	}

	first, firstRoot, err := resolveDocumentationMemberIdentity(map[string]interface{}{
		"access_kind": "reads", "resource_symbol": "profit_and_loss_detail",
	}, []string{"/resource_symbol"})
	if err != nil {
		t.Fatal(err)
	}
	second, secondRoot, err := resolveDocumentationMemberIdentity(map[string]interface{}{
		"access_kind": "writes", "resource_symbol": "profit_and_loss_detail",
	}, []string{"/resource_symbol"})
	if err != nil {
		t.Fatal(err)
	}
	if firstRoot != secondRoot || !equalResolvedDocumentationMemberIdentities(first, second) {
		t.Fatal("non-identity semantic fields changed the declared member identity")
	}
}

func TestDocumentationTargetParentIndexIsExactUniqueAndResourceBounded(t *testing.T) {
	const role = "target_role"
	shapeKey := documentationTargetShapeKey{
		artifactRole: role, rowKind: "api_operation", bindingKind: exactDocumentationTargetRowMember, memberJSONPointer: "/fields",
	}
	shape := documentationTargetShape{
		key: shapeKey, rowSelectorJSONPointers: []string{"/operation_id"},
		resolution: dependencySemanticDerivationTargetResolution{
			artifactSHA256: sha256Hex([]byte("target artifact")), schemaRole: "target_role_schema",
			schemaID: "urn:test:target-role", schemaVersion: "1", schemaSHA256: sha256Hex([]byte("target schema")),
		},
	}
	alpha := exactDocumentationDependencyRowFromObject(t, map[string]interface{}{"operation_id": "op_alpha", "row_kind": "api_operation"})
	beta := exactDocumentationDependencyRowFromObject(t, map[string]interface{}{"operation_id": "op_beta", "row_kind": "api_operation"})
	groups := map[documentationTargetGroupKey]documentationTargetGroup{}
	indexes, registrations, hydrations, err := registerDocumentationTargetParentRows(
		groups,
		map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape},
		map[string]dependencySemanticRows{role: {byKind: map[string][]dependencySemanticRow{"api_operation": {alpha, beta}}}},
		2,
		2,
	)
	if err != nil {
		t.Fatal(err)
	}
	indexKey, err := documentationTargetParentIndexKeyForShape(shape)
	if err != nil {
		t.Fatal(err)
	}
	index := indexes[indexKey]
	alphaSelectors := []exactDocumentationResolvedTargetRowSelector{{TargetRowJSONPointer: "/operation_id", ExpectedString: "op_alpha"}}
	alphaSHA256, err := canonicalDocumentationDigest(alphaSelectors)
	if err != nil {
		t.Fatal(err)
	}
	if registrations != 2 || hydrations != 2 || len(index.bySelectorSHA256) != 2 || index.bySelectorSHA256[alphaSHA256].row.data["operation_id"] != "op_alpha" {
		t.Fatalf("parent index counts/lookup = %d/%d/%d/%v", registrations, hydrations, len(index.bySelectorSHA256), index.bySelectorSHA256[alphaSHA256].row.data["operation_id"])
	}
	if _, _, _, err := registerDocumentationTargetParentRows(map[documentationTargetGroupKey]documentationTargetGroup{}, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape}, map[string]dependencySemanticRows{role: {byKind: map[string][]dependencySemanticRow{"api_operation": {alpha, alpha}}}}, 2, 2); err == nil || !strings.Contains(err.Error(), "duplicates parent-row selector identity") {
		t.Fatalf("duplicate parent identity error = %v", err)
	}
	if _, _, _, err := registerDocumentationTargetParentRows(map[documentationTargetGroupKey]documentationTargetGroup{}, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape}, map[string]dependencySemanticRows{role: {byKind: map[string][]dependencySemanticRow{"api_operation": {alpha, beta}}}}, 1, 2); err == nil || !strings.Contains(err.Error(), "parent registrations exceed limit") {
		t.Fatalf("parent registration cap error = %v", err)
	}
	if _, _, _, err := registerDocumentationTargetParentRows(map[documentationTargetGroupKey]documentationTargetGroup{}, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape}, map[string]dependencySemanticRows{role: {byKind: map[string][]dependencySemanticRow{"api_operation": {alpha, beta}}}}, 2, 1); err == nil || !strings.Contains(err.Error(), "selector hydrations exceed limit") {
		t.Fatalf("selector hydration cap error = %v", err)
	}
	var byteClosure documentationTargetParentRegistrationClosure
	if _, _, _, err := registerDocumentationTargetParentRowsWithRoot(map[documentationTargetGroupKey]documentationTargetGroup{}, map[documentationTargetShapeKey]documentationTargetShape{shapeKey: shape}, map[string]dependencySemanticRows{role: {byKind: map[string][]dependencySemanticRow{"api_operation": {alpha, beta}}}}, 2, 2, 1, &byteClosure); err == nil || !strings.Contains(err.Error(), "canonical registration bytes exceed limit") {
		t.Fatalf("parent canonical-byte cap error = %v", err)
	}
}

func TestZeroMatchRuleStillValidatesAndSelectsItsDeclaredTarget(t *testing.T) {
	profiles, authority, artifacts, rows := zeroMatchDocumentationTargetFixture(t, "op_alpha")
	materializations, whole, members, err := validateExactDocumentationTargetMaterializations(profiles, nil, authority, artifacts, rows)
	if err != nil {
		t.Fatalf("validate zero-match target declaration: %v", err)
	}
	if len(materializations) != 0 || whole != 0 || members != 0 {
		t.Fatalf("zero-match materialization = %d/%d/%d, want 0/0/0", len(materializations), whole, members)
	}

	_, authority, artifacts, rows = zeroMatchDocumentationTargetFixture(t, "op_beta")
	if _, _, _, err := validateExactDocumentationTargetMaterializations(profiles, nil, authority, artifacts, rows); err == nil || !strings.Contains(err.Error(), "want exactly one") {
		t.Fatalf("missing declared zero-match parent target error = %v", err)
	}
}

func TestZeroFactParentRegistrationChangesClosureRoot(t *testing.T) {
	rootFor := func(operationID string) string {
		t.Helper()
		profiles, authority, artifacts, rows := zeroMatchDocumentationTargetFixture(t, operationID)
		var parentClosure documentationTargetParentRegistrationClosure
		materializations, whole, members, registrations, hydrations, err := validateExactDocumentationTargetMaterializationsWithResourceCounts(profiles, nil, authority, artifacts, rows, &parentClosure)
		if err != nil {
			t.Fatalf("validate zero-fact parent %q: %v", operationID, err)
		}
		if len(materializations) != 0 || whole != 0 || members != 0 || registrations != 1 || hydrations != 1 || !isLowerSHA256(parentClosure.rootSHA256) || parentClosure.canonicalByteCount <= 0 {
			t.Fatalf("zero-fact parent closure %q = materializations/counts/root/bytes %d/%d/%d/%d/%d/%q/%d", operationID, len(materializations), whole, members, registrations, hydrations, parentClosure.rootSHA256, parentClosure.canonicalByteCount)
		}
		return parentClosure.rootSHA256
	}
	if first, second := rootFor("op_alpha"), rootFor("op_beta"); first == second {
		t.Fatal("zero-fact parent row and selector identities did not change the sealed parent-registration root")
	}
}

func TestDocumentationTargetParentRegistrationRootBindsPerReceiptByteCounts(t *testing.T) {
	receipts := []documentationTargetParentRegistrationReceipt{
		{SHA256: sha256Hex([]byte("first parent")), CanonicalBytes: 101},
		{SHA256: sha256Hex([]byte("second parent")), CanonicalBytes: 203},
	}
	rows := make([][]byte, len(receipts))
	for index, receipt := range receipts {
		canonical, err := canonicalDocumentationBytes(receipt)
		if err != nil {
			t.Fatal(err)
		}
		rows[index] = canonical
	}
	closure := documentationTargetParentRegistrationClosure{
		seal: documentationTargetParentRegistrationAuthority, registrations: receipts,
		rootSHA256: stageCanonicalSetRoot(rows), registrationCount: int64(len(receipts)),
		canonicalByteCount: receipts[0].CanonicalBytes + receipts[1].CanonicalBytes,
	}
	if err := validateDocumentationTargetParentRegistrationClosure(closure); err != nil {
		t.Fatal(err)
	}
	tampered := cloneDocumentationTargetParentRegistrationClosure(closure)
	tampered.registrations[0].CanonicalBytes++
	tampered.registrations[1].CanonicalBytes--
	if err := validateDocumentationTargetParentRegistrationClosure(tampered); err == nil {
		t.Fatal("per-receipt canonical byte redistribution preserved total but escaped the sealed roster root")
	}
}

func TestZeroMatchWholeRowCannotHideUndocumentedTargetRows(t *testing.T) {
	profiles, authority, artifacts, rows := zeroMatchDocumentationTargetFixture(t, "op_alpha")
	profileKey := sortedSetKeys(stringMapKeysAsSet(profiles))[0]
	profile := profiles[profileKey]
	profile.Program.OrderedRules[0].TargetBindingKind = exactDocumentationTargetWholeRow
	profile.Program.OrderedRules[0].TargetMemberJSONPointer = ""
	profile.Program.OrderedRules[0].TargetRowSelector = nil
	profile.Program.OrderedRules[0].TargetMemberIdentityJSONPointers = nil
	profiles[profileKey] = profile
	if _, _, _, err := validateExactDocumentationTargetMaterializations(profiles, nil, authority, artifacts, rows); err == nil || !strings.Contains(err.Error(), "want exactly 0 executor facts") {
		t.Fatalf("undocumented whole row under zero-match rule error = %v", err)
	}
}

func TestDynamicDocumentationTargetSelectorCannotHideUnaccountedParentMembers(t *testing.T) {
	body := []byte("| amount | Decimal | Required |\r\n")
	raw, _, proof, bodies := exactDocumentationProgramFixture(t, body, 1, 1)
	var programValue map[string]interface{}
	if err := decodeOneValidationProfileJSON(raw, &programValue); err != nil {
		t.Fatal(err)
	}
	rule := programValue["ordered_rules"].([]interface{})[0].(map[string]interface{})
	rule["target_row_kind"] = "api_operation"
	rule["target_binding_kind"] = exactDocumentationTargetRowMember
	rule["target_member_json_pointer"] = "/fields"
	rule["target_row_selector"] = []interface{}{map[string]interface{}{
		"target_row_json_pointer":  "/operation_id",
		"expected_string_template": "${field_name}",
	}}
	rule["target_member_identity_json_pointers"] = []interface{}{"/field_name"}
	programBytes, err := canonicalizeCandidateJSON(mustValidationProfileJSON(t, programValue))
	if err != nil {
		t.Fatal(err)
	}
	reference := dependencyProfileReference{id: "dynamic_parent_target_profile", version: "1", digest: sha256Hex(programBytes)}
	program, err := parseExactDocumentationDerivationProgram(programBytes, reference)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := executeExactDocumentationDerivationProgram(reference, program, proof, bodies)
	if err != nil || len(facts) != 1 {
		t.Fatalf("execute dynamic parent fixture = %d facts, %v", len(facts), err)
	}
	fact := facts[0]
	output, err := decodeExactDocumentationFactOutputFields(fact)
	if err != nil {
		t.Fatal(err)
	}
	amountMember := make(map[string]interface{}, len(output)+2)
	for key, value := range output {
		amountMember[key] = value
	}
	amountMember["documentation_derived_fact_ids"] = []interface{}{fact.FactID}
	amountMember["evidence_locator_ids"] = []interface{}{fact.EvidenceLocatorID}
	memoMember := map[string]interface{}{
		"field_name": "memo", "provider_type": "String", "provider_requirement": "Optional",
		"documentation_derived_fact_ids": []interface{}{"docfact_forged"},
		"evidence_locator_ids":           []interface{}{"evloc_forged"},
	}
	amountRow := exactDocumentationDependencyRowFromObject(t, map[string]interface{}{
		"row_kind": "api_operation", "operation_id": "amount", "fields": []interface{}{amountMember},
	})
	memoRow := exactDocumentationDependencyRowFromObject(t, map[string]interface{}{
		"row_kind": "api_operation", "operation_id": "memo", "fields": []interface{}{memoMember},
	})
	artifactBytes := append(bytes.Clone(amountRow.raw), '\n')
	artifactBytes = append(artifactBytes, memoRow.raw...)
	artifactBytes = append(artifactBytes, '\n')

	resolution := documentationMemberSchemaResolutionFixture(t, "fields", func(branch, _, memberItem map[string]interface{}) {
		branch["required"] = []interface{}{"fields", "operation_id", "row_kind"}
		branch["properties"].(map[string]interface{})["operation_id"] = map[string]interface{}{"type": "string"}
		memberItem["required"] = []interface{}{
			"documentation_derived_fact_ids", "evidence_locator_ids", "field_name", "provider_requirement", "provider_type",
		}
		memberItem["properties"] = map[string]interface{}{
			"documentation_derived_fact_ids": map[string]interface{}{"type": "array", "minItems": json.Number("1"), "uniqueItems": true, "items": map[string]interface{}{"type": "string"}},
			"evidence_locator_ids":           map[string]interface{}{"type": "array", "minItems": json.Number("1"), "uniqueItems": true, "items": map[string]interface{}{"type": "string"}},
			"field_name":                     map[string]interface{}{"type": "string"},
			"provider_requirement":           map[string]interface{}{"type": "string"},
			"provider_type":                  map[string]interface{}{"type": "string"},
		}
	})
	artifactDigest := sha256Hex(artifactBytes)
	authority := dependencySemanticDerivationTargetSchemaAuthority{
		seal: dependencySemanticDerivationTargetSchemaAuthorityIdentity,
		byRole: map[string]dependencySemanticDerivationTargetSchema{fact.TargetArtifactRole: {
			artifactRole: fact.TargetArtifactRole, artifactSHA256: artifactDigest,
			schemaRole: resolution.schemaRole, schemaID: resolution.schemaID,
			schemaVersion: resolution.schemaVersion, schemaSHA256: resolution.schemaSHA256,
			schemaBytes: resolution.schemaBytes, discriminatorProperty: "row_kind",
			discriminatorValues: map[string]struct{}{"api_operation": {}},
		}},
	}
	profiles := map[string]executableDocumentationDerivationProfile{
		dependencyProfileReferenceKey(reference): {Reference: reference, Program: program},
	}
	artifacts := map[string]artifactInput{fact.TargetArtifactRole: {Raw: artifactBytes, SHA256: artifactDigest}}
	rows := map[string]dependencySemanticRows{fact.TargetArtifactRole: {
		path: "dynamic-parent-target.jsonl", raw: artifactBytes,
		byKind: map[string][]dependencySemanticRow{"api_operation": {amountRow, memoRow}},
	}}
	if _, _, _, err := validateExactDocumentationTargetMaterializations(profiles, facts, authority, artifacts, rows); err == nil || !strings.Contains(err.Error(), "unknown or cross-target fact") {
		t.Fatalf("unaccounted dynamic-selector parent member error = %v", err)
	}
}

func TestDocumentationDerivationClosureProofSealsDeterministicMaterializationSet(t *testing.T) {
	execution, classificationProof, facts, materializations, parentRegistrations := documentationClosureExecutionFixture(t)
	transferredFactID := execution.Results[0].Facts[0].FactID
	transferredCanonicalOutput := execution.Results[0].Facts[0].CanonicalOutputFields

	proof, err := sealDocumentationDerivationClosure(sha256Hex([]byte("derivation-profile-artifact")), &execution, classificationProof, materializations, parentRegistrations, int64(len(facts)), 0)
	if err != nil {
		t.Fatalf("sealDocumentationDerivationClosure() error = %v", err)
	}
	if err := validateDocumentationDerivationClosureProof(proof); err != nil {
		t.Fatalf("validateDocumentationDerivationClosureProof() error = %v", err)
	}
	for _, result := range execution.Results {
		if len(result.Facts) != 0 {
			t.Fatal("sealed closure did not consume execution-set fact ownership")
		}
	}
	transferredFact := proof.factsByID[transferredFactID]
	if len(transferredCanonicalOutput) == 0 || len(transferredFact.CanonicalOutputFields) == 0 || &transferredCanonicalOutput[0] != &transferredFact.CanonicalOutputFields[0] {
		t.Fatal("closure sealing cloned canonical fact output instead of transferring its sole production ownership")
	}
	var canonicalMaterializationBytes int64
	for _, materialization := range materializations {
		canonicalMaterializationBytes += materialization.canonicalBytes
	}
	if proof.canonicalTargetMaterializationBytes != canonicalMaterializationBytes || proof.canonicalTargetMaterializationByteLimit != maxDocumentationTargetMaterializationCanonicalBytes {
		t.Fatalf("sealed canonical materialization bytes/limit = %d/%d, want %d/%d", proof.canonicalTargetMaterializationBytes, proof.canonicalTargetMaterializationByteLimit, canonicalMaterializationBytes, maxDocumentationTargetMaterializationCanonicalBytes)
	}

	secondExecution, secondClassificationProof, secondFacts, _, secondParentRegistrations := documentationClosureExecutionFixture(t)
	reversed := []documentationTargetMaterialization{materializations[1], materializations[0]}
	reversedProof, err := sealDocumentationDerivationClosure(sha256Hex([]byte("derivation-profile-artifact")), &secondExecution, secondClassificationProof, reversed, secondParentRegistrations, int64(len(secondFacts)), 0)
	if err != nil {
		t.Fatalf("seal reversed materialization roster: %v", err)
	}
	if proof.targetMaterializationRootSHA256 != reversedProof.targetMaterializationRootSHA256 || proof.proofSHA256 != reversedProof.proofSHA256 {
		t.Fatalf("canonical set identity changed under reorder: first root/proof %s/%s, reversed %s/%s", proof.targetMaterializationRootSHA256, proof.proofSHA256, reversedProof.targetMaterializationRootSHA256, reversedProof.proofSHA256)
	}
}

func TestDocumentationTargetMaterializationCanonicalBudgetAcceptsExactBoundaryAndRejectsNextByteBeforeAllocation(t *testing.T) {
	_, _, facts, _, _ := documentationClosureExecutionFixture(t)
	fact := facts[0]
	artifact := artifactInput{Raw: []byte("target-artifact:" + fact.FactID)}
	schemaBytes := []byte(`{"type":"object"}`)
	resolution := dependencySemanticDerivationTargetResolution{
		artifactRole: fact.TargetArtifactRole, artifactSHA256: sha256Hex(artifact.Raw), targetRowKind: fact.TargetRowKind,
		schemaRole: "fixture_target_schema", schemaID: "urn:test:closure-target", schemaVersion: "1",
		schemaSHA256: sha256Hex(schemaBytes), schemaBytes: schemaBytes,
	}
	memberPointer := ""
	var canonicalMember []byte
	if fact.TargetBindingKind == exactDocumentationTargetRowMember {
		memberPointer = fact.TargetMemberJSONPointer + "/0"
		canonicalMember = fact.CanonicalOutputFields
	}
	probe, err := newDocumentationTargetMaterialization(fact, artifact, resolution, sha256Hex([]byte("target-row:"+fact.FactID)), memberPointer, canonicalMember, maxDocumentationTargetMaterializationCanonicalBytes)
	if err != nil {
		t.Fatal(err)
	}
	exact, err := newDocumentationTargetMaterialization(fact, artifact, resolution, sha256Hex([]byte("target-row:"+fact.FactID)), memberPointer, canonicalMember, probe.canonicalBytes)
	if err != nil || exact.canonicalBytes != probe.canonicalBytes {
		t.Fatalf("exact canonical materialization boundary = %#v, %v", exact, err)
	}
	if _, err := newDocumentationTargetMaterialization(fact, artifact, resolution, sha256Hex([]byte("target-row:"+fact.FactID)), memberPointer, canonicalMember, probe.canonicalBytes-1); err == nil || !strings.Contains(err.Error(), "before allocation") {
		t.Fatalf("one-byte-over canonical materialization error = %v", err)
	}
}

func TestDocumentationTargetMaterializationCanonicalBytePreflightMatchesEscapedEncoding(t *testing.T) {
	materialization := documentationMaterializationFixture(t, "docfact_escape", "evloc_escape", "/resource_accesses/0")
	identity := materialization.identity
	identity.TargetSchemaID = "urn:test:<>&\u2028snowman-☃"
	identity.TargetMemberInstancePointer = "/resource_accesses/quote-\"-slash-\\"
	want, err := canonicalDocumentationBytes(identity)
	if err != nil {
		t.Fatal(err)
	}
	got, err := exactDocumentationTargetMaterializationCanonicalByteCount(identity)
	if err != nil {
		t.Fatal(err)
	}
	if got != int64(len(want)) {
		t.Fatalf("escaped canonical byte preflight = %d, want exact encoded length %d", got, len(want))
	}
}

func TestDocumentationTargetMaterializationRootStreamsWithoutCanonicalRosterCopies(t *testing.T) {
	const materializationCount = 512
	materializations := make([]documentationTargetMaterialization, materializationCount)
	rows := make([][]byte, materializationCount)
	var canonicalBytes int64
	for index := range materializations {
		factID := stableID("docfact", "streaming-root-"+strconv.Itoa(index))
		locatorID := stableID("evloc", "streaming-root-"+strconv.Itoa(index))
		materializations[index] = documentationMaterializationFixture(t, factID, locatorID, "/resource_accesses/"+strconv.Itoa(index))
		rows[index] = materializations[index].canonical
		canonicalBytes += materializations[index].canonicalBytes
	}
	want := stageCanonicalSetRoot(rows)
	got, stats, err := documentationTargetMaterializationRootWithStats(materializations)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || stats.canonicalBytes != canonicalBytes || stats.peakAdditionalCanonicalBytes != 0 || stats.sortIndexBytes != int64(materializationCount)*int64(strconv.IntSize/8) {
		t.Fatalf("streaming root/stats = %s/%#v, want %s canonical=%d additional=0 index=%d", got, stats, want, canonicalBytes, int64(materializationCount)*int64(strconv.IntSize/8))
	}
	smallAllocations := testing.AllocsPerRun(5, func() {
		if documentationTargetMaterializationRoot(materializations[:8]) == "" {
			panic("empty small root")
		}
	})
	largeAllocations := testing.AllocsPerRun(5, func() {
		if documentationTargetMaterializationRoot(materializations) == "" {
			panic("empty large root")
		}
	})
	if largeAllocations > smallAllocations+2 {
		t.Fatalf("streaming root allocations scaled with canonical roster: small %.0f, large %.0f", smallAllocations, largeAllocations)
	}
}

func TestDocumentationDerivationClosureProofRejectsIdentityOrBindingTamper(t *testing.T) {
	execution, classificationProof, facts, materializations, parentRegistrations := documentationClosureExecutionFixture(t)
	firstFactID := facts[0].FactID
	proof, err := sealDocumentationDerivationClosure(sha256Hex([]byte("derivation-profile-artifact")), &execution, classificationProof, materializations, parentRegistrations, int64(len(facts)), 0)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("sealed identity field", func(t *testing.T) {
		tampered := cloneDocumentationClosureProof(proof)
		tampered.pageCount++
		if err := validateDocumentationDerivationClosureProof(tampered); err == nil || !strings.Contains(err.Error(), "execution-set receipt") {
			t.Fatalf("identity tamper error = %v", err)
		}
	})

	t.Run("binding omitted", func(t *testing.T) {
		tampered := cloneDocumentationClosureProof(proof)
		delete(tampered.materializationBindingSHA256ByFact, firstFactID)
		if err := validateDocumentationDerivationClosureProof(tampered); err == nil || !strings.Contains(err.Error(), "absent, malformed, or incomplete") {
			t.Fatalf("omitted binding error = %v", err)
		}
	})

	t.Run("binding digest substituted", func(t *testing.T) {
		tampered := cloneDocumentationClosureProof(proof)
		tampered.materializationBindingSHA256ByFact[firstFactID] = sha256Hex([]byte("different valid materialization binding"))
		if err := validateDocumentationDerivationClosureProof(tampered); err == nil {
			t.Fatal("well-formed but different fact-to-materialization binding was accepted under the sealed proof identity")
		}
	})

	t.Run("materialization canonical byte actual substituted", func(t *testing.T) {
		tampered := cloneDocumentationClosureProof(proof)
		tampered.canonicalTargetMaterializationBytes++
		if err := validateDocumentationDerivationClosureProof(tampered); err == nil {
			t.Fatal("canonical materialization byte-actual mutation escaped the sealed closure identity")
		}
	})

	t.Run("per-fact materialization canonical bytes substituted", func(t *testing.T) {
		tampered := cloneDocumentationClosureProof(proof)
		tampered.materializationCanonicalBytesByFact[firstFactID]++
		if err := validateDocumentationDerivationClosureProof(tampered); err == nil {
			t.Fatal("per-fact canonical materialization byte mutation escaped the binding-roster root")
		}
	})

	t.Run("executed fact roster omitted", func(t *testing.T) {
		tampered := cloneDocumentationClosureProof(proof)
		tampered.factsByID = nil
		if err := validateDocumentationDerivationClosureProof(tampered); err == nil || !strings.Contains(err.Error(), "absent, malformed, or incomplete") {
			t.Fatalf("omitted executed fact roster error = %v", err)
		}
	})

	t.Run("executor receipt omitted", func(t *testing.T) {
		tampered := cloneDocumentationClosureProof(proof)
		tampered.executionSetReceipt = documentationDerivationExecutionSetReceipt{}
		if err := validateDocumentationDerivationClosureProof(tampered); err == nil || !strings.Contains(err.Error(), "execution-set receipt") {
			t.Fatalf("omitted executor receipt error = %v", err)
		}
	})

	t.Run("parent registration receipt substituted", func(t *testing.T) {
		tampered := cloneDocumentationClosureProof(proof)
		tampered.parentRegistrationReceipt.rootSHA256 = sha256Hex([]byte("different parent registration roster"))
		if err := validateDocumentationDerivationClosureProof(tampered); err == nil || !strings.Contains(err.Error(), "parent-registration receipt") {
			t.Fatalf("substituted parent-registration receipt error = %v", err)
		}
	})
}

func documentationMemberSchemaResolutionFixture(
	t *testing.T,
	memberProperty string,
	mutate func(branch, memberArray, memberItem map[string]interface{}),
) dependencySemanticDerivationTargetResolution {
	t.Helper()
	stringRoster := func() map[string]interface{} {
		return map[string]interface{}{
			"type":        "array",
			"minItems":    json.Number("1"),
			"uniqueItems": true,
			"items":       map[string]interface{}{"type": "string"},
		}
	}
	memberItem := map[string]interface{}{
		"type":                 "object",
		"additionalProperties": false,
		"required": []interface{}{
			"access_kind",
			"documentation_derived_fact_ids",
			"evidence_locator_ids",
			"resource_symbol",
		},
		"properties": map[string]interface{}{
			"access_kind":                    map[string]interface{}{"type": "string"},
			"documentation_derived_fact_ids": stringRoster(),
			"evidence_locator_ids":           stringRoster(),
			"resource_symbol":                map[string]interface{}{"type": "string"},
		},
	}
	memberArray := map[string]interface{}{
		"type":  "array",
		"items": memberItem,
	}
	branch := map[string]interface{}{
		"type":                 "object",
		"additionalProperties": false,
		"required":             []interface{}{"row_kind", memberProperty},
		"properties": map[string]interface{}{
			"row_kind":     map[string]interface{}{"const": "api_operation"},
			memberProperty: memberArray,
		},
	}
	if mutate != nil {
		mutate(branch, memberArray, memberItem)
	}
	schemaBytes := mustValidationProfileJSON(t, map[string]interface{}{
		"$schema": validationProfileDraft202012,
		"$id":     "urn:test:documentation-materialization-target",
		"oneOf":   []interface{}{branch},
	})
	return dependencySemanticDerivationTargetResolution{
		artifactRole:          "source_contract_index",
		targetRowKind:         "api_operation",
		schemaRole:            "source_contract_index_schema",
		schemaID:              "urn:test:documentation-materialization-target",
		schemaVersion:         "1",
		schemaSHA256:          sha256Hex(schemaBytes),
		schemaBytes:           schemaBytes,
		discriminatorProperty: "row_kind",
		discriminatorValues:   []string{"api_operation"},
	}
}

func zeroMatchDocumentationTargetFixture(t *testing.T, operationID string) (
	map[string]executableDocumentationDerivationProfile,
	dependencySemanticDerivationTargetSchemaAuthority,
	map[string]artifactInput,
	map[string]dependencySemanticRows,
) {
	t.Helper()
	const role = "source_contract_index"
	resolution := documentationMemberSchemaResolutionFixture(t, "resource_accesses", func(branch, _, _ map[string]interface{}) {
		branch["required"] = []interface{}{"operation_id", "resource_accesses", "row_kind"}
		branch["properties"].(map[string]interface{})["operation_id"] = map[string]interface{}{"type": "string"}
	})
	rowData := map[string]interface{}{
		"operation_id": operationID, "resource_accesses": []interface{}{}, "row_kind": "api_operation",
	}
	rowRaw := mustValidationProfileJSON(t, rowData)
	artifactDigest := sha256Hex(rowRaw)
	artifact := artifactInput{Raw: rowRaw, SHA256: artifactDigest}
	semanticRows := dependencySemanticRows{
		path: "fixture.jsonl", raw: rowRaw,
		byKind: map[string][]dependencySemanticRow{"api_operation": {{raw: rowRaw, kind: "api_operation", data: rowData}}},
	}
	authority := dependencySemanticDerivationTargetSchemaAuthority{
		seal: dependencySemanticDerivationTargetSchemaAuthorityIdentity,
		byRole: map[string]dependencySemanticDerivationTargetSchema{role: {
			artifactRole: role, artifactSHA256: artifactDigest,
			schemaRole: resolution.schemaRole, schemaID: resolution.schemaID,
			schemaVersion: resolution.schemaVersion, schemaSHA256: resolution.schemaSHA256,
			schemaBytes: resolution.schemaBytes, discriminatorProperty: "row_kind",
			discriminatorValues: map[string]struct{}{"api_operation": {}},
		}},
	}
	reference := dependencyProfileReference{id: "zero_match_profile", version: "1", digest: sha256Hex([]byte("zero-match-profile"))}
	profile := executableDocumentationDerivationProfile{
		Reference: reference,
		Program: exactDocumentationDerivationProgram{OrderedRules: []exactDocumentationDerivationRule{{
			RuleID: "optional_resource_access", TargetArtifactRole: role, TargetRowKind: "api_operation",
			TargetBindingKind: exactDocumentationTargetRowMember, TargetMemberJSONPointer: "/resource_accesses",
			TargetRowSelector:                []exactDocumentationTargetRowSelectorTemplate{{TargetRowJSONPointer: "/operation_id", ExpectedStringTemplate: operationID}},
			TargetMemberIdentityJSONPointers: []string{"/resource_symbol"}, MinimumMatches: 0,
		}}},
	}
	return map[string]executableDocumentationDerivationProfile{dependencyProfileReferenceKey(reference): profile}, authority, map[string]artifactInput{role: artifact}, map[string]dependencySemanticRows{role: semanticRows}
}

func documentationClosureExecutionFixture(t *testing.T) (exactDocumentationDerivationProfileExecutionSet, sourceClassificationSelectionProof, []exactDocumentationDerivedFact, []documentationTargetMaterialization, documentationTargetParentRegistrationClosure) {
	t.Helper()
	body := []byte("| amount | Decimal | Required |\n| balance | Decimal | Required |\n")
	raw, reference, proof, bodies := exactDocumentationProgramFixture(t, body, 2, 2)
	program, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		t.Fatal(err)
	}
	generation := exactDocumentationFieldClaimSchemaFixture(t, reference)
	profile := executableDocumentationDerivationProfile{
		Reference: reference, ClaimKind: generation.claimKind, ValidationSchema: generation.claimSchema,
		SemanticGeneration: generation, Program: program,
	}
	execution, err := executeDocumentationDerivationProfileSet(map[string]executableDocumentationDerivationProfile{dependencyProfileReferenceKey(reference): profile}, proof, bodies)
	if err != nil || len(execution.Results) != 1 || len(execution.Results[0].Facts) != 2 {
		t.Fatalf("closure execution fixture = %#v, %v", execution, err)
	}
	facts := execution.Results[0].Facts
	materializations := make([]documentationTargetMaterialization, 0, len(facts))
	for _, fact := range facts {
		artifact := artifactInput{Raw: []byte("target-artifact:" + fact.FactID)}
		schemaBytes := []byte(`{"type":"object"}`)
		resolution := dependencySemanticDerivationTargetResolution{
			artifactRole: fact.TargetArtifactRole, artifactSHA256: sha256Hex(artifact.Raw), targetRowKind: fact.TargetRowKind,
			schemaRole: "fixture_target_schema", schemaID: "urn:test:closure-target", schemaVersion: "1",
			schemaSHA256: sha256Hex(schemaBytes), schemaBytes: schemaBytes,
		}
		memberPointer := ""
		var canonicalMember []byte
		if fact.TargetBindingKind == exactDocumentationTargetRowMember {
			memberPointer = fact.TargetMemberJSONPointer + "/0"
			canonicalMember = fact.CanonicalOutputFields
		}
		materialization, err := newDocumentationTargetMaterialization(fact, artifact, resolution, sha256Hex([]byte("target-row:"+fact.FactID)), memberPointer, canonicalMember, maxDocumentationTargetMaterializationCanonicalBytes)
		if err != nil {
			t.Fatal(err)
		}
		materializations = append(materializations, materialization)
	}
	parentRegistrations := documentationTargetParentRegistrationClosure{
		seal: documentationTargetParentRegistrationAuthority, registrations: []documentationTargetParentRegistrationReceipt{},
		rootSHA256: stageCanonicalSetRoot(nil), registrationCount: 0, selectorHydrations: 0, canonicalByteCount: 0,
	}
	return execution, proof, facts, materializations, parentRegistrations
}

func documentationMaterializationFixture(t *testing.T, factID, locatorID, memberPointer string) documentationTargetMaterialization {
	t.Helper()
	digest := func(label string) string { return sha256Hex([]byte(label)) }
	identity := documentationTargetMaterializationIdentity{
		FactID:                        factID,
		FactOutputSHA256:              digest(factID + ":output"),
		EvidenceLocatorID:             locatorID,
		EvidenceLocatorIdentitySHA256: digest(locatorID + ":identity"),
		TargetArtifactRole:            "source_contract_index",
		TargetArtifactSHA256:          digest("source-contract-artifact"),
		TargetSchemaRole:              "source_contract_index_schema",
		TargetSchemaID:                "urn:test:documentation-materialization-target",
		TargetSchemaVersion:           "1",
		TargetSchemaSHA256:            digest("source-contract-schema"),
		TargetRowKind:                 "api_operation",
		TargetBindingKind:             exactDocumentationTargetRowMember,
		TargetRowSelectorSHA256:       digest(factID + ":row-selector"),
		TargetRowCanonicalSHA256:      digest("source-contract-row"),
		TargetMemberJSONPointer:       "/resource_accesses",
		TargetMemberIdentitySHA256:    digest(factID + ":member-identity"),
		TargetMemberInstancePointer:   memberPointer,
		TargetMemberCanonicalSHA256:   digest(factID + ":member"),
	}
	raw, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := canonicalizeCandidateJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return documentationTargetMaterialization{
		identity:       identity,
		canonical:      canonical,
		bindingSHA256:  sha256Hex(canonical),
		canonicalBytes: int64(len(canonical)),
	}
}

func cloneDocumentationClosureProof(proof documentationDerivationClosureProof) documentationDerivationClosureProof {
	result := proof
	result.materializationBindingSHA256ByFact = make(map[string]string, len(proof.materializationBindingSHA256ByFact))
	for factID, bindingSHA := range proof.materializationBindingSHA256ByFact {
		result.materializationBindingSHA256ByFact[factID] = bindingSHA
	}
	result.materializationCanonicalBytesByFact = make(map[string]int64, len(proof.materializationCanonicalBytesByFact))
	for factID, canonicalBytes := range proof.materializationCanonicalBytesByFact {
		result.materializationCanonicalBytesByFact[factID] = canonicalBytes
	}
	result.factsByID = make(map[string]exactDocumentationDerivedFact, len(proof.factsByID))
	for factID, fact := range proof.factsByID {
		result.factsByID[factID] = cloneExactDocumentationDerivedFactValue(fact)
	}
	result.parentRegistrationReceipt = cloneDocumentationTargetParentRegistrationClosure(proof.parentRegistrationReceipt)
	return result
}

func TestDocumentationTargetMaterializationRootBindsExactCanonicalBytes(t *testing.T) {
	materialization := documentationMaterializationFixture(t, "docfact_alpha", "evloc_alpha", "/resource_accesses/0")
	original := documentationTargetMaterializationRoot([]documentationTargetMaterialization{materialization})
	mutated := materialization
	mutated.canonical = bytes.Replace(bytes.Clone(materialization.canonical), []byte("docfact_alpha"), []byte("docfact_omega"), 1)
	if original == documentationTargetMaterializationRoot([]documentationTargetMaterialization{mutated}) {
		t.Fatal("target materialization set root did not bind exact canonical materialization bytes")
	}
}
