package providerplan

import (
	"encoding/json"
	"fmt"
	"sort"
)

const (
	exactValueClassifierProgramKind          = "exact_value_classifier_program_v1"
	exactValueClassifierMatchExactlyOne      = "exactly_one_rule_required"
	exactValueClassifierTerminalFailClosed   = "fail_closed"
	exactValuePredicateStringEquals          = "exact_string_equals"
	exactValuePredicateStringIn              = "string_in"
	maxExactValueClassifierProgramBytes      = 16 << 20
	maxExactValueClassifierRules             = 4096
	maxExactValueClassifierPredicatesPerRule = 256
)

// This source-neutral registry contains only pre-classification provider-field
// facts. It deliberately excludes numeric_disposition, source-neutral targets,
// mapping choices, and computation assertions, so classifier execution cannot
// re-endorse its desired output.
var exactValueClassifierAllowedInputPointers = map[string]struct{}{
	"/cardinality":           {},
	"/field_display":         {},
	"/field_name":            {},
	"/official_json_pointer": {},
	"/provider_description":  {},
	"/provider_requirement":  {},
	"/provider_type":         {},
}

type exactValueClassifierOutput struct {
	numericSemantics     string
	authoritativeCarrier string
	computationPath      string
}

type exactValueClassifierPredicate struct {
	kind            string
	inputPointer    string
	expectedString  string
	expectedStrings map[string]struct{}
}

type exactValueClassifierRule struct {
	ordinal    int64
	ruleID     string
	predicates []exactValueClassifierPredicate
	output     exactValueClassifierOutput
}

type exactValueClassifierProgram struct {
	reference               dependencyProfileReference
	inputClaimKind          string
	inputValidationSchema   dependencyProfileReference
	inputProjectionPointers []string
	rules                   []exactValueClassifierRule
}

type exactValueClassifierExecution struct {
	output                exactValueClassifierOutput
	ruleID                string
	inputProjectionSHA256 string
}

// parseExactValueClassifierProgram resolves a closed, content-addressed
// predicate grammar. Every executable input pointer is schema-proven and drawn
// from the fixed pre-classification provider-fact registry; ignored fields and
// constant-output programs are not part of v1.
func parseExactValueClassifierProgram(profile documentationClassifierProfile, reference dependencyProfileReference, schemas map[string]documentationValidationSchema) (exactValueClassifierProgram, error) {
	var program exactValueClassifierProgram
	canonicalProgram, err := canonicalOperationClassifierProgram(profile.program)
	if err != nil {
		return program, err
	}
	if len(canonicalProgram) == 0 || len(canonicalProgram) > maxExactValueClassifierProgramBytes || sha256Hex(canonicalProgram) != reference.digest {
		return program, fmt.Errorf("classifier_profile_sha256 does not equal bounded RFC-canonical exact-value program bytes")
	}
	if err := requireExactSet("exact-value classifier program fields", stringMapKeysAsSet(profile.program), map[string]struct{}{
		"program_kind": {}, "input_claim_kind": {}, "input_validation_schema_binding": {},
		"input_projection_json_pointers": {}, "match_semantics": {}, "ordered_rules": {},
		"terminal_default": {}, "numeric_lexeme_preserved": {}, "binary_float_authoritative": {},
	}); err != nil {
		return program, err
	}
	programKind, kindOK := semanticString(profile.program, "program_kind")
	inputClaimKind, claimOK := semanticString(profile.program, "input_claim_kind")
	validationBinding, validationBindingOK := semanticObject(profile.program, "input_validation_schema_binding")
	validationReference, validationReferenceOK := dependencyProfileReferenceFromFields(validationBinding, "validation_schema")
	projectionPointers, projectionOK := semanticStringSlice(profile.program, "input_projection_json_pointers")
	matchSemantics, matchOK := semanticString(profile.program, "match_semantics")
	rawRules, rulesOK := semanticObjectSlice(profile.program, "ordered_rules")
	terminalDefault, terminalOK := semanticString(profile.program, "terminal_default")
	lexemePreserved, lexemeOK := semanticBool(profile.program, "numeric_lexeme_preserved")
	floatAuthority, floatOK := semanticBool(profile.program, "binary_float_authoritative")
	if !kindOK || programKind != exactValueClassifierProgramKind || !claimOK || inputClaimKind != profile.claimKind ||
		!validationBindingOK || !validationReferenceOK || !projectionOK || len(projectionPointers) == 0 || hasEmptyOrDuplicateSemanticStrings(projectionPointers) || !sort.StringsAreSorted(projectionPointers) ||
		!matchOK || matchSemantics != exactValueClassifierMatchExactlyOne || !rulesOK || len(rawRules) == 0 || len(rawRules) > maxExactValueClassifierRules ||
		!terminalOK || terminalDefault != exactValueClassifierTerminalFailClosed || !lexemeOK || !lexemePreserved || !floatOK || floatAuthority {
		return program, fmt.Errorf("exact-value classifier kind, input, rule, fail-closed, lexeme, or float contract is invalid")
	}
	validation, exists := schemas[dependencyProfileReferenceKey(validationReference)]
	if !exists || validation.claimKind != inputClaimKind || validation.authority.claimKind != inputClaimKind {
		return program, fmt.Errorf("exact-value classifier does not bind one exact same-claim validation schema")
	}
	for _, pointer := range projectionPointers {
		if _, allowed := exactValueClassifierAllowedInputPointers[pointer]; !allowed {
			return program, fmt.Errorf("exact-value classifier input pointer %q is outside the closed pre-classification provider-fact registry", pointer)
		}
		if err := exactValueClassifierSchemaProvesInputPointer(validation.authority, pointer); err != nil {
			return program, fmt.Errorf("exact-value classifier input pointer %q: %w", pointer, err)
		}
	}

	seenRuleIDs := map[string]struct{}{}
	usedPointers := map[string]struct{}{}
	semanticOutputs := map[string]struct{}{}
	carrierOutputs := map[string]struct{}{}
	computationOutputs := map[string]struct{}{}
	for ruleIndex, rawRule := range rawRules {
		if err := requireExactSet("exact-value classifier ordered rule fields", stringMapKeysAsSet(rawRule), map[string]struct{}{
			"ordinal": {}, "rule_id": {}, "predicates": {}, "output": {},
		}); err != nil {
			return program, err
		}
		ordinal, ordinalOK := semanticInt64(rawRule, "ordinal")
		ruleID, ruleIDOK := semanticString(rawRule, "rule_id")
		rawPredicates, predicatesOK := semanticObjectSlice(rawRule, "predicates")
		rawOutput, outputOK := semanticObject(rawRule, "output")
		if !ordinalOK || ordinal != int64(ruleIndex) || !ruleIDOK || !isCanonicalValidationProfileIdentity(ruleID) || !predicatesOK || len(rawPredicates) == 0 || len(rawPredicates) > maxExactValueClassifierPredicatesPerRule || !outputOK {
			return program, fmt.Errorf("exact-value classifier ordered rule %d is incomplete, noncanonical, or out of order", ruleIndex)
		}
		if _, duplicate := seenRuleIDs[ruleID]; duplicate {
			return program, fmt.Errorf("exact-value classifier duplicates rule_id %q", ruleID)
		}
		seenRuleIDs[ruleID] = struct{}{}
		rule := exactValueClassifierRule{ordinal: ordinal, ruleID: ruleID}
		seenRulePointers := map[string]struct{}{}
		for predicateIndex, rawPredicate := range rawPredicates {
			predicate, err := parseExactValueClassifierPredicate(rawPredicate)
			if err != nil {
				return program, fmt.Errorf("exact-value classifier rule %q predicate %d: %w", ruleID, predicateIndex, err)
			}
			if _, duplicate := seenRulePointers[predicate.inputPointer]; duplicate {
				return program, fmt.Errorf("exact-value classifier rule %q repeats input pointer %q", ruleID, predicate.inputPointer)
			}
			seenRulePointers[predicate.inputPointer] = struct{}{}
			usedPointers[predicate.inputPointer] = struct{}{}
			rule.predicates = append(rule.predicates, predicate)
		}
		output, err := parseExactValueClassifierOutput(rawOutput)
		if err != nil {
			return program, fmt.Errorf("exact-value classifier rule %q output: %w", ruleID, err)
		}
		rule.output = output
		semanticOutputs[output.numericSemantics] = struct{}{}
		carrierOutputs[output.authoritativeCarrier] = struct{}{}
		computationOutputs[output.computationPath] = struct{}{}
		program.rules = append(program.rules, rule)
	}
	if err := requireExactSet("exact-value classifier executable input projection", usedPointers, stringSliceSet(projectionPointers)); err != nil {
		return program, err
	}
	if !stringSetsEqual(profile.semanticClasses, semanticOutputs) || !stringSetsEqual(profile.carriers, carrierOutputs) || !stringSetsEqual(profile.computationPaths, computationOutputs) {
		return program, fmt.Errorf("exact-value classifier closed unions do not equal its executable rule outputs")
	}
	program.reference = reference
	program.inputClaimKind = inputClaimKind
	program.inputValidationSchema = validationReference
	program.inputProjectionPointers = append([]string(nil), projectionPointers...)
	return program, nil
}

func parseExactValueClassifierPredicate(raw map[string]interface{}) (exactValueClassifierPredicate, error) {
	var predicate exactValueClassifierPredicate
	kind, kindOK := semanticString(raw, "predicate_kind")
	pointer, pointerOK := semanticString(raw, "input_json_pointer")
	if !kindOK || !pointerOK {
		return predicate, fmt.Errorf("predicate kind or input pointer is absent")
	}
	if _, allowed := exactValueClassifierAllowedInputPointers[pointer]; !allowed {
		return predicate, fmt.Errorf("input pointer %q is outside the closed pre-classification provider-fact registry", pointer)
	}
	predicate.kind = kind
	predicate.inputPointer = pointer
	switch kind {
	case exactValuePredicateStringEquals:
		if err := requireExactSet("exact string-equality predicate fields", stringMapKeysAsSet(raw), map[string]struct{}{
			"predicate_kind": {}, "input_json_pointer": {}, "expected_string": {},
		}); err != nil {
			return predicate, err
		}
		expected, ok := semanticString(raw, "expected_string")
		if !ok || !canonicalEvidenceMetadataString(expected, 4096) {
			return predicate, fmt.Errorf("expected_string is empty or noncanonical")
		}
		predicate.expectedString = expected
	case exactValuePredicateStringIn:
		if err := requireExactSet("string-membership predicate fields", stringMapKeysAsSet(raw), map[string]struct{}{
			"predicate_kind": {}, "input_json_pointer": {}, "expected_strings": {},
		}); err != nil {
			return predicate, err
		}
		expected, ok := semanticStringSlice(raw, "expected_strings")
		if !ok || len(expected) == 0 || hasEmptyOrDuplicateSemanticStrings(expected) || !sort.StringsAreSorted(expected) {
			return predicate, fmt.Errorf("expected_strings is not a nonempty canonical sorted set")
		}
		predicate.expectedStrings = stringSet(expected)
	default:
		return predicate, fmt.Errorf("predicate_kind %q is outside the closed executable grammar", kind)
	}
	return predicate, nil
}

func parseExactValueClassifierOutput(raw map[string]interface{}) (exactValueClassifierOutput, error) {
	var output exactValueClassifierOutput
	if err := requireExactSet("exact-value classifier output fields", stringMapKeysAsSet(raw), map[string]struct{}{
		"numeric_semantics": {}, "authoritative_carrier": {}, "computation_path": {},
	}); err != nil {
		return output, err
	}
	var semanticsOK, carrierOK, pathOK bool
	output.numericSemantics, semanticsOK = semanticString(raw, "numeric_semantics")
	output.authoritativeCarrier, carrierOK = semanticString(raw, "authoritative_carrier")
	output.computationPath, pathOK = semanticString(raw, "computation_path")
	if !semanticsOK || !carrierOK || !pathOK || !canonicalEvidenceMetadataString(output.numericSemantics, 512) || !canonicalEvidenceMetadataString(output.authoritativeCarrier, 512) || !canonicalEvidenceMetadataString(output.computationPath, 512) {
		return exactValueClassifierOutput{}, fmt.Errorf("output tuple is incomplete or noncanonical")
	}
	if err := validateExactNumericDisposition(output.numericSemantics, output.authoritativeCarrier, output.computationPath); err != nil {
		return exactValueClassifierOutput{}, err
	}
	return output, nil
}

func executeExactValueClassifier(program exactValueClassifierProgram, fact exactDocumentationDerivedFact, validation documentationValidationSchema) (exactValueClassifierExecution, error) {
	var execution exactValueClassifierExecution
	if dependencyProfileReferenceKey(program.inputValidationSchema) != dependencyProfileReferenceKey(validation.authority.reference) || validation.claimKind != program.inputClaimKind {
		return execution, fmt.Errorf("exact-value classifier execution validation schema differs from its compiled program")
	}
	if err := validateExactDocumentationDerivedFactIntegrity(fact); err != nil {
		return execution, fmt.Errorf("exact input documentation fact: %w", err)
	}
	if err := validateDocumentationClaimOutput(validation.authority, fact.CanonicalOutputFields); err != nil {
		return execution, err
	}
	claim, err := decodeExactDocumentationFactOutputFields(fact)
	if err != nil {
		return execution, err
	}
	canonicalProjection, err := canonicalExactValueClassifierInputProjection(program.inputProjectionPointers, claim)
	if err != nil {
		return execution, err
	}
	var projection map[string]interface{}
	if err := decodeOneValidationProfileJSON(canonicalProjection, &projection); err != nil {
		return execution, err
	}
	execution.inputProjectionSHA256 = sha256Hex(canonicalProjection)
	matched := make([]exactValueClassifierRule, 0, 1)
	for _, rule := range program.rules {
		matches := true
		for _, predicate := range rule.predicates {
			value := projection[predicate.inputPointer].(string)
			switch predicate.kind {
			case exactValuePredicateStringEquals:
				matches = value == predicate.expectedString
			case exactValuePredicateStringIn:
				_, matches = predicate.expectedStrings[value]
			default:
				return exactValueClassifierExecution{}, fmt.Errorf("compiled exact-value classifier contains an unsupported predicate")
			}
			if !matches {
				break
			}
		}
		if matches {
			matched = append(matched, rule)
		}
	}
	if len(matched) != 1 {
		return exactValueClassifierExecution{}, fmt.Errorf("exact-value classifier matched %d rules, want exactly one", len(matched))
	}
	execution.ruleID = matched[0].ruleID
	execution.output = matched[0].output
	return execution, nil
}

func exactValueClassifierSchemaProvesInputPointer(authority documentationClaimSchemaAuthority, pointer string) error {
	if authority.resolved == nil || sha256Hex(authority.canonicalSchemaBytes) != authority.reference.digest {
		return fmt.Errorf("claim schema authority is absent or inexact")
	}
	tokens, err := exactDocumentationJSONPointerTokens(pointer)
	if err != nil {
		return err
	}
	var root map[string]interface{}
	if err := decodeOneValidationProfileJSON(authority.canonicalSchemaBytes, &root); err != nil {
		return err
	}
	branches, err := exactValueClassifierSchemaObjectBranches(root, root, "$", map[string]bool{})
	if err != nil {
		return err
	}
	for _, branch := range branches {
		if documentationSchemaProvesRequiredStringAtPointer(root, branch, tokens) == nil {
			return nil
		}
	}
	return fmt.Errorf("no closed claim-schema branch proves one required string at the pointer")
}

func exactValueClassifierSchemaObjectBranches(node interface{}, root map[string]interface{}, path string, stack map[string]bool) ([]map[string]interface{}, error) {
	object, ok := node.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("claim schema node at %s is not an object", path)
	}
	if rawRef, present := object["$ref"]; present {
		ref, ok := rawRef.(string)
		if !ok {
			return nil, fmt.Errorf("claim schema $ref at %s is not a string", path)
		}
		target, targetPath, err := resolveValidationProfileLocalJSONPointer(root, ref)
		if err != nil {
			return nil, err
		}
		if stack[targetPath] {
			return nil, fmt.Errorf("claim schema reference cycle at %s", targetPath)
		}
		stack[targetPath] = true
		branches, err := exactValueClassifierSchemaObjectBranches(target, root, targetPath, stack)
		delete(stack, targetPath)
		return branches, err
	}
	compositionKind := ""
	var rawBranches []interface{}
	for _, keyword := range []string{"oneOf", "anyOf"} {
		if value, present := object[keyword]; present {
			if compositionKind != "" {
				return nil, fmt.Errorf("claim schema at %s mixes oneOf and anyOf", path)
			}
			var branchesOK bool
			rawBranches, branchesOK = value.([]interface{})
			if !branchesOK || len(rawBranches) == 0 {
				return nil, fmt.Errorf("claim schema %s at %s is empty or malformed", keyword, path)
			}
			compositionKind = keyword
		}
	}
	if _, present := object["allOf"]; present {
		return nil, fmt.Errorf("exact-value classifier does not accept ambiguous allOf claim composition at %s", path)
	}
	if compositionKind != "" {
		result := make([]map[string]interface{}, 0, len(rawBranches))
		for index, branch := range rawBranches {
			selected, err := exactValueClassifierSchemaObjectBranches(branch, root, fmt.Sprintf("%s/%s/%d", path, compositionKind, index), stack)
			if err != nil {
				return nil, err
			}
			result = append(result, selected...)
		}
		return result, nil
	}
	if _, properties := object["properties"].(map[string]interface{}); !properties {
		return nil, fmt.Errorf("claim schema branch at %s has no closed object properties", path)
	}
	return []map[string]interface{}{object}, nil
}

func canonicalExactValueClassifierInputProjection(pointers []string, claim map[string]interface{}) ([]byte, error) {
	projection := make(map[string]interface{}, len(pointers))
	for _, pointer := range pointers {
		tokens, err := exactDocumentationJSONPointerTokens(pointer)
		if err != nil {
			return nil, err
		}
		value, err := documentationJSONPointerValue(claim, tokens)
		if err != nil {
			return nil, err
		}
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("exact-value classifier projection pointer %q is not a string", pointer)
		}
		projection[pointer] = text
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		return nil, err
	}
	return canonicalizeCandidateJSON(raw)
}
