package providerplan

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
)

const (
	validationProfileDraft202012 = "https://json-schema.org/draft/2020-12/schema"
	// Draft 2020-12 permits a relative $id when the schema has an absolute
	// retrieval base. This fixed .invalid URI supplies only that resolver base;
	// it is not fetched, selected by input, or treated as schema authority.
	validationProfileOfflineBaseURI = "https://offline.invalid/velenza/provider-documentation/validation-profile/"
	unknownValidationRowKind        = "unbound_validation_profile_row_shape"
	maxValidationProfileRowBytes    = 32 * 1024 * 1024
)

// validationProfileBinding binds one artifact role to exact artifact and
// validator-schema coordinates. The hashes are over the supplied bytes, not a
// normalized or re-encoded representation.
type validationProfileBinding struct {
	Role            string `json:"role"`
	ArtifactID      string `json:"artifact_id"`
	ArtifactVersion string `json:"artifact_version"`
	ArtifactSHA256  string `json:"artifact_sha256"`
	SchemaID        string `json:"schema_id"`
	SchemaVersion   string `json:"schema_version"`
	SchemaSHA256    string `json:"schema_sha256"`
}

// validationProfileArtifact supplies one exact JSONL artifact under an
// independently typed identity and version coordinate.
type validationProfileArtifact struct {
	ID      string
	Version string
	Bytes   []byte
}

// validationProfileSchema supplies one exact JSON Schema document under an
// independently typed identity and version coordinate.
type validationProfileSchema struct {
	ID      string
	Version string
	Bytes   []byte
}

type validationProfileCoordinate struct {
	ID      string
	Version string
}

type resolvedValidationProfileSchema struct {
	coordinate    validationProfileCoordinate
	sha256        string
	resolved      *jsonschema.Resolved
	discriminator validationProfileDiscriminator
}

// validationProfileDiscriminator is derived from the exact JSON Schema. The
// property name is intentionally not fixed in the binary: exact legacy
// artifacts can use their native finite row discriminator (for example,
// "kind") while newer artifacts can use another schema-owned name.
type validationProfileDiscriminator struct {
	property string
	values   map[string]struct{}
}

// validateValidationProfileBindings validates a closed role-to-artifact-to-
// schema roster. It performs no vocabulary-specific interpretation: artifact
// row semantics and closed row shapes belong entirely to the bound schema. A
// nil result proves only structural validation and exact binding to the bytes
// supplied by the caller; canonical or admitted authority requires separate
// caller-owned pins and is deliberately not inferred here.
func validateValidationProfileBindings(bindings []validationProfileBinding, artifacts []validationProfileArtifact, schemas []validationProfileSchema) error {
	if len(bindings) == 0 {
		return fmt.Errorf("validation-profile binding roster is empty")
	}
	if len(artifacts) == 0 {
		return fmt.Errorf("validation-profile artifact roster is empty")
	}
	if len(schemas) == 0 {
		return fmt.Errorf("validation-profile schema roster is empty")
	}

	artifactByCoordinate := make(map[validationProfileCoordinate]validationProfileArtifact, len(artifacts))
	artifactDigestOwner := make(map[string]validationProfileCoordinate, len(artifacts))
	suppliedDigestOwner := make(map[string]string, len(artifacts)+len(schemas))
	for index, artifact := range artifacts {
		coordinate, err := newValidationProfileCoordinate("artifact", artifact.ID, artifact.Version)
		if err != nil {
			return fmt.Errorf("validation-profile artifact[%d]: %w", index, err)
		}
		if len(artifact.Bytes) == 0 {
			return fmt.Errorf("validation-profile artifact %q version %q has no bytes", coordinate.ID, coordinate.Version)
		}
		if _, duplicate := artifactByCoordinate[coordinate]; duplicate {
			return fmt.Errorf("validation-profile artifact coordinate %q version %q is duplicated", coordinate.ID, coordinate.Version)
		}
		digest := validationProfileSHA256(artifact.Bytes)
		if prior, duplicate := artifactDigestOwner[digest]; duplicate {
			return fmt.Errorf("validation-profile artifact digest %s is duplicated by %q version %q and %q version %q", digest, prior.ID, prior.Version, coordinate.ID, coordinate.Version)
		}
		if prior, duplicate := suppliedDigestOwner[digest]; duplicate {
			return fmt.Errorf("validation-profile digest %s is duplicated across supplied inputs %s and artifact %q version %q", digest, prior, coordinate.ID, coordinate.Version)
		}
		artifactByCoordinate[coordinate] = artifact
		artifactDigestOwner[digest] = coordinate
		suppliedDigestOwner[digest] = fmt.Sprintf("artifact %q version %q", coordinate.ID, coordinate.Version)
	}

	schemaByCoordinate := make(map[validationProfileCoordinate]resolvedValidationProfileSchema, len(schemas))
	schemaDigestOwner := make(map[string]validationProfileCoordinate, len(schemas))
	for index, supplied := range schemas {
		coordinate, err := newValidationProfileCoordinate("schema", supplied.ID, supplied.Version)
		if err != nil {
			return fmt.Errorf("validation-profile schema[%d]: %w", index, err)
		}
		if len(supplied.Bytes) == 0 {
			return fmt.Errorf("validation-profile schema %q version %q has no bytes", coordinate.ID, coordinate.Version)
		}
		if _, duplicate := schemaByCoordinate[coordinate]; duplicate {
			return fmt.Errorf("validation-profile schema coordinate %q version %q is duplicated", coordinate.ID, coordinate.Version)
		}
		digest := validationProfileSHA256(supplied.Bytes)
		if prior, duplicate := schemaDigestOwner[digest]; duplicate {
			return fmt.Errorf("validation-profile schema digest %s is duplicated by %q version %q and %q version %q", digest, prior.ID, prior.Version, coordinate.ID, coordinate.Version)
		}
		if prior, duplicate := suppliedDigestOwner[digest]; duplicate {
			return fmt.Errorf("validation-profile digest %s is duplicated across supplied inputs %s and schema %q version %q", digest, prior, coordinate.ID, coordinate.Version)
		}
		resolved, discriminator, err := resolveValidationProfileSchema(supplied.Bytes, coordinate)
		if err != nil {
			return fmt.Errorf("validation-profile schema %q version %q: %w", coordinate.ID, coordinate.Version, err)
		}
		schemaByCoordinate[coordinate] = resolvedValidationProfileSchema{coordinate: coordinate, sha256: digest, resolved: resolved, discriminator: discriminator}
		schemaDigestOwner[digest] = coordinate
		suppliedDigestOwner[digest] = fmt.Sprintf("schema %q version %q", coordinate.ID, coordinate.Version)
	}

	roles := make(map[string]struct{}, len(bindings))
	boundArtifactDigests := make(map[string]string, len(bindings))
	artifactUses := make(map[validationProfileCoordinate]int, len(bindings))
	schemaUses := make(map[validationProfileCoordinate]int, len(bindings))
	for index, binding := range bindings {
		if err := validateValidationProfileBindingShape(binding); err != nil {
			return fmt.Errorf("validation-profile binding[%d]: %w", index, err)
		}
		if _, duplicate := roles[binding.Role]; duplicate {
			return fmt.Errorf("validation-profile role %q is duplicated", binding.Role)
		}
		roles[binding.Role] = struct{}{}

		artifactCoordinate := validationProfileCoordinate{ID: binding.ArtifactID, Version: binding.ArtifactVersion}
		artifact, found := artifactByCoordinate[artifactCoordinate]
		if !found {
			return fmt.Errorf("validation-profile role %q binds absent artifact %q version %q", binding.Role, binding.ArtifactID, binding.ArtifactVersion)
		}
		artifactDigest := validationProfileSHA256(artifact.Bytes)
		if artifactDigest != binding.ArtifactSHA256 {
			return fmt.Errorf("validation-profile role %q artifact digest mismatch: binding=%s supplied=%s", binding.Role, binding.ArtifactSHA256, artifactDigest)
		}
		if priorRole, duplicate := boundArtifactDigests[binding.ArtifactSHA256]; duplicate {
			return fmt.Errorf("validation-profile artifact digest %s is bound by duplicate roles %q and %q", binding.ArtifactSHA256, priorRole, binding.Role)
		}
		boundArtifactDigests[binding.ArtifactSHA256] = binding.Role
		artifactUses[artifactCoordinate]++

		schemaCoordinate := validationProfileCoordinate{ID: binding.SchemaID, Version: binding.SchemaVersion}
		schema, found := schemaByCoordinate[schemaCoordinate]
		if !found {
			return fmt.Errorf("validation-profile role %q binds absent schema %q version %q", binding.Role, binding.SchemaID, binding.SchemaVersion)
		}
		if schema.sha256 != binding.SchemaSHA256 {
			return fmt.Errorf("validation-profile role %q schema digest mismatch: binding=%s supplied=%s", binding.Role, binding.SchemaSHA256, schema.sha256)
		}
		schemaUses[schemaCoordinate]++

		if err := validateJSONLRowsAgainstSchema(artifact.Bytes, schema); err != nil {
			return fmt.Errorf("validation-profile role %q artifact %q version %q: %w", binding.Role, binding.ArtifactID, binding.ArtifactVersion, err)
		}
	}

	for _, coordinate := range sortedValidationProfileCoordinates(artifactByCoordinate) {
		if artifactUses[coordinate] != 1 {
			return fmt.Errorf("validation-profile artifact %q version %q is unbound", coordinate.ID, coordinate.Version)
		}
	}
	for _, coordinate := range sortedValidationProfileCoordinates(schemaByCoordinate) {
		if schemaUses[coordinate] == 0 {
			return fmt.Errorf("validation-profile schema %q version %q is unbound", coordinate.ID, coordinate.Version)
		}
	}
	return nil
}

func newValidationProfileCoordinate(kind, id, version string) (validationProfileCoordinate, error) {
	if !isCanonicalValidationProfileIdentity(id) {
		return validationProfileCoordinate{}, fmt.Errorf("%s_id %q is empty, padded, or contains a control character", kind, id)
	}
	if !isCanonicalValidationProfileIdentity(version) {
		return validationProfileCoordinate{}, fmt.Errorf("%s_version %q is empty, padded, or contains a control character", kind, version)
	}
	return validationProfileCoordinate{ID: id, Version: version}, nil
}

func validateValidationProfileBindingShape(binding validationProfileBinding) error {
	if !isCanonicalValidationProfileIdentity(binding.Role) {
		return fmt.Errorf("role %q is empty, padded, or contains a control character", binding.Role)
	}
	if _, err := newValidationProfileCoordinate("artifact", binding.ArtifactID, binding.ArtifactVersion); err != nil {
		return err
	}
	if _, err := newValidationProfileCoordinate("schema", binding.SchemaID, binding.SchemaVersion); err != nil {
		return err
	}
	if !isValidationProfileSHA256(binding.ArtifactSHA256) {
		return fmt.Errorf("artifact_sha256 %q is not a lowercase SHA-256 digest", binding.ArtifactSHA256)
	}
	if !isValidationProfileSHA256(binding.SchemaSHA256) {
		return fmt.Errorf("schema_sha256 %q is not a lowercase SHA-256 digest", binding.SchemaSHA256)
	}
	return nil
}

func resolveValidationProfileSchema(schemaBytes []byte, coordinate validationProfileCoordinate) (*jsonschema.Resolved, validationProfileDiscriminator, error) {
	if !utf8.Valid(schemaBytes) {
		return nil, validationProfileDiscriminator{}, fmt.Errorf("schema bytes are not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(schemaBytes); err != nil {
		return nil, validationProfileDiscriminator{}, fmt.Errorf("schema has duplicate JSON keys: %w", err)
	}
	var rawObject map[string]interface{}
	if err := decodeOneValidationProfileJSON(schemaBytes, &rawObject); err != nil {
		return nil, validationProfileDiscriminator{}, fmt.Errorf("decode schema JSON object: %w", err)
	}
	draft, ok := rawObject["$schema"].(string)
	if !ok || draft != validationProfileDraft202012 {
		return nil, validationProfileDiscriminator{}, fmt.Errorf("$schema must equal %q", validationProfileDraft202012)
	}
	if err := validateValidationProfileSchemaNumbers(rawObject, "$"); err != nil {
		return nil, validationProfileDiscriminator{}, err
	}
	if err := validateValidationProfileClosedObjectShapes(rawObject); err != nil {
		return nil, validationProfileDiscriminator{}, err
	}
	discriminator, err := validationProfileSchemaDiscriminator(rawObject)
	if err != nil {
		return nil, validationProfileDiscriminator{}, err
	}
	var schema jsonschema.Schema
	if err := decodeOneValidationProfileJSON(schemaBytes, &schema); err != nil {
		return nil, validationProfileDiscriminator{}, fmt.Errorf("decode JSON Schema: %w", err)
	}
	if schema.ID == "" || schema.ID != coordinate.ID {
		return nil, validationProfileDiscriminator{}, fmt.Errorf("schema $id %q does not equal bound schema_id %q", schema.ID, coordinate.ID)
	}
	resolved, err := schema.Resolve(&jsonschema.ResolveOptions{
		BaseURI: validationProfileOfflineBaseURI,
		Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
			return nil, fmt.Errorf("external JSON Schema reference %q is forbidden", uri.String())
		},
	})
	if err != nil {
		return nil, validationProfileDiscriminator{}, fmt.Errorf("resolve draft 2020-12 schema without external references: %w", err)
	}
	return resolved, discriminator, nil
}

func validateJSONLRowsAgainstSchema(artifactBytes []byte, schema resolvedValidationProfileSchema) error {
	if schema.resolved == nil {
		return fmt.Errorf("resolved schema is nil")
	}
	if !isCanonicalValidationProfileIdentity(schema.discriminator.property) || len(schema.discriminator.values) == 0 {
		return fmt.Errorf("resolved schema has no finite required discriminator proof")
	}
	if !utf8.Valid(artifactBytes) {
		return fmt.Errorf("artifact bytes are not valid UTF-8")
	}
	scanner := bufio.NewScanner(bytes.NewReader(artifactBytes))
	scanner.Buffer(make([]byte, 64*1024), maxValidationProfileRowBytes)
	rowCount := 0
	for scanner.Scan() {
		raw := bytes.TrimSpace(scanner.Bytes())
		if len(raw) == 0 {
			continue
		}
		rowCount++
		if err := rejectDuplicateJSONKeys(raw); err != nil {
			return fmt.Errorf("JSONL row %d has duplicate JSON keys: %w", rowCount, err)
		}
		var instance interface{}
		if err := decodeOneValidationProfileJSON(raw, &instance); err != nil {
			return fmt.Errorf("decode JSONL row %d: %w", rowCount, err)
		}
		instance, err := normalizeValidationProfileNumbers(instance, fmt.Sprintf("JSONL row %d", rowCount))
		if err != nil {
			return err
		}
		object, ok := instance.(map[string]interface{})
		if !ok {
			return fmt.Errorf("JSONL row %d is not an object", rowCount)
		}
		discriminatorValue, ok := object[schema.discriminator.property].(string)
		if !ok || !isCanonicalValidationProfileIdentity(discriminatorValue) {
			return fmt.Errorf("JSONL row %d has no canonical schema-proven discriminator %q", rowCount, schema.discriminator.property)
		}
		if _, declared := schema.discriminator.values[discriminatorValue]; !declared {
			return fmt.Errorf("JSONL row %d discriminator %q value %q is outside the schema-proven finite roster", rowCount, schema.discriminator.property, discriminatorValue)
		}
		if err := schema.resolved.Validate(object); err != nil {
			return fmt.Errorf("JSONL row %d with %s %q fails its bound schema: %w", rowCount, schema.discriminator.property, discriminatorValue, err)
		}
		unknownShape := make(map[string]interface{}, len(object))
		for key, value := range object {
			unknownShape[key] = value
		}
		unknownShape[schema.discriminator.property] = unknownValidationProfileDiscriminatorValue(schema.discriminator.values)
		if err := schema.resolved.Validate(unknownShape); err == nil {
			return fmt.Errorf("bound schema accepts unknown row shape derived from JSONL row %d", rowCount)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan JSONL artifact: %w", err)
	}
	if rowCount == 0 {
		return fmt.Errorf("JSONL artifact has no rows")
	}
	return nil
}

func unknownValidationProfileDiscriminatorValue(values map[string]struct{}) string {
	candidate := unknownValidationRowKind
	for suffix := 0; ; suffix++ {
		if _, exists := values[candidate]; !exists {
			return candidate
		}
		candidate = unknownValidationRowKind + "_" + strconv.Itoa(suffix+1)
	}
}

func decodeOneValidationProfileJSON(raw []byte, target interface{}) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are forbidden")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func validateValidationProfileSchemaNumbers(value interface{}, path string) error {
	nodes := 0
	return validateValidationProfileSchemaNumbersBounded(value, path, 1, &nodes)
}

func validateValidationProfileSchemaNumbersBounded(value interface{}, path string, depth int, nodes *int) error {
	if depth > maxProviderJSONNestingDepth {
		return fmt.Errorf("schema numeric walk at %s exceeds fixed nesting depth %d", path, maxProviderJSONNestingDepth)
	}
	*nodes++
	if *nodes > maxProviderJSONNodesPerValue {
		return fmt.Errorf("schema numeric walk exceeds fixed node limit %d", maxProviderJSONNodesPerValue)
	}
	switch typed := value.(type) {
	case json.Number:
		if _, ok := exactValidationProfileFloat64(typed); !ok {
			return fmt.Errorf("schema numeric literal at %s (%s) is not exactly representable by the validator and would round", path, typed.String())
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			// jsonschema-go evaluates multipleOf through float64 division. That
			// cannot preserve exact large integers, so this validator refuses the
			// keyword until an exact declarative evaluator owns it.
			if key == "multipleOf" {
				return fmt.Errorf("schema keyword multipleOf at %s/%s is unsupported because exact numeric evaluation cannot be guaranteed", path, key)
			}
			if err := validateValidationProfileSchemaNumbersBounded(typed[key], path+"/"+escapeValidationProfileJSONPointerToken(key), depth+1, nodes); err != nil {
				return err
			}
		}
	case []interface{}:
		for index, item := range typed {
			if err := validateValidationProfileSchemaNumbersBounded(item, fmt.Sprintf("%s/%d", path, index), depth+1, nodes); err != nil {
				return err
			}
		}
	}
	return nil
}

func normalizeValidationProfileNumbers(value interface{}, path string) (interface{}, error) {
	nodes := 0
	return normalizeValidationProfileNumbersBounded(value, path, 1, &nodes)
}

func normalizeValidationProfileNumbersBounded(value interface{}, path string, depth int, nodes *int) (interface{}, error) {
	if depth > maxProviderJSONNestingDepth {
		return nil, fmt.Errorf("numeric normalization at %s exceeds fixed nesting depth %d", path, maxProviderJSONNestingDepth)
	}
	*nodes++
	if *nodes > maxProviderJSONNodesPerValue {
		return nil, fmt.Errorf("numeric normalization exceeds fixed node limit %d", maxProviderJSONNodesPerValue)
	}
	switch typed := value.(type) {
	case json.Number:
		normalized, ok := exactValidationProfileRuntimeNumber(typed)
		if !ok {
			return nil, fmt.Errorf("%s numeric literal %s cannot be represented exactly by the validator", path, typed.String())
		}
		return normalized, nil
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			normalized, err := normalizeValidationProfileNumbersBounded(typed[key], path+"/"+escapeValidationProfileJSONPointerToken(key), depth+1, nodes)
			if err != nil {
				return nil, err
			}
			typed[key] = normalized
		}
		return typed, nil
	case []interface{}:
		for index, item := range typed {
			normalized, err := normalizeValidationProfileNumbersBounded(item, fmt.Sprintf("%s/%d", path, index), depth+1, nodes)
			if err != nil {
				return nil, err
			}
			typed[index] = normalized
		}
		return typed, nil
	default:
		return value, nil
	}
}

func exactValidationProfileRuntimeNumber(number json.Number) (interface{}, bool) {
	lexeme := number.String()
	if !strings.ContainsAny(lexeme, ".eE") {
		integer, ok := new(big.Int).SetString(lexeme, 10)
		if ok {
			if integer.IsInt64() {
				return integer.Int64(), true
			}
			if integer.Sign() >= 0 && integer.BitLen() <= 64 {
				return integer.Uint64(), true
			}
		}
	}
	value, ok := exactValidationProfileFloat64(number)
	if !ok {
		return nil, false
	}
	return value, true
}

func exactValidationProfileFloat64(number json.Number) (float64, bool) {
	exact, ok := new(big.Rat).SetString(number.String())
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseFloat(number.String(), 64)
	if err != nil {
		return 0, false
	}
	represented := new(big.Rat)
	if represented.SetFloat64(value) == nil || represented.Cmp(exact) != 0 {
		return 0, false
	}
	return value, true
}

func validateValidationProfileClosedObjectShapes(root map[string]interface{}) error {
	budget := &validationProfileWalkBudget{}
	return validateValidationProfileSchemaNodeClosure(root, root, "$", map[string]bool{}, 1, budget)
}

func validationProfileSchemaDiscriminator(root map[string]interface{}) (validationProfileDiscriminator, error) {
	budget := &validationProfileWalkBudget{}
	candidates, objectApplicable, err := validationProfileDiscriminatorCandidates(root, root, "$", map[string]bool{}, 1, budget)
	if err != nil {
		return validationProfileDiscriminator{}, fmt.Errorf("schema discriminator closure proof: %w", err)
	}
	if !objectApplicable || len(candidates) == 0 {
		return validationProfileDiscriminator{}, fmt.Errorf("schema does not prove one finite required string discriminator in every object-applicable root branch")
	}
	// Prefer the property that distinguishes the most closed row variants. A
	// lexical tie break makes selection deterministic without assigning semantic
	// authority to a binary-owned property name.
	properties := make([]string, 0, len(candidates))
	for property := range candidates {
		properties = append(properties, property)
	}
	sort.Slice(properties, func(i, j int) bool {
		left, right := len(candidates[properties[i]]), len(candidates[properties[j]])
		if left != right {
			return left > right
		}
		return properties[i] < properties[j]
	})
	return validationProfileDiscriminator{property: properties[0], values: candidates[properties[0]]}, nil
}

type validationProfileWalkBudget struct {
	nodes int
}

func (budget *validationProfileWalkBudget) enter(path string, depth int) error {
	if depth > maxProviderJSONNestingDepth {
		return fmt.Errorf("schema walk at %s exceeds fixed nesting depth %d", path, maxProviderJSONNestingDepth)
	}
	budget.nodes++
	if budget.nodes > maxProviderJSONNodesPerValue {
		return fmt.Errorf("schema walk exceeds fixed node limit %d", maxProviderJSONNodesPerValue)
	}
	return nil
}

// validationProfileDiscriminatorCandidates returns finite required string
// properties common to every object-applicable alternative. Candidate values
// are unioned across alternatives, preserving a closed roster while allowing
// each exact row shape to select a different value.
func validationProfileDiscriminatorCandidates(node interface{}, root map[string]interface{}, path string, proofStack map[string]bool, depth int, budget *validationProfileWalkBudget) (map[string]map[string]struct{}, bool, error) {
	if err := budget.enter(path, depth); err != nil {
		return nil, false, err
	}
	switch typed := node.(type) {
	case bool:
		return nil, typed, nil
	case map[string]interface{}:
		if validationProfileSchemaExcludesObjects(typed) {
			return nil, false, nil
		}
		if proofStack[path] {
			return nil, true, fmt.Errorf("reference cycle at %s does not establish a finite discriminator roster", path)
		}
		proofStack[path] = true
		defer delete(proofStack, path)
		for _, keyword := range []string{"$ref", "$dynamicRef"} {
			if ref, present := typed[keyword]; present {
				refString, ok := ref.(string)
				if !ok {
					return nil, true, fmt.Errorf("%s at %s must be a string", keyword, path)
				}
				target, targetPath, err := resolveValidationProfileLocalJSONPointer(root, refString)
				if err != nil {
					return nil, true, err
				}
				return validationProfileDiscriminatorCandidates(target, root, targetPath, proofStack, depth+1, budget)
			}
		}

		var combined map[string]map[string]struct{}
		foundComposition := false
		compositionObjectApplicable := false
		for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
			branches, present := typed[keyword].([]interface{})
			if !present {
				continue
			}
			if len(branches) == 0 {
				return nil, true, fmt.Errorf("%s at %s is empty", keyword, path)
			}
			foundComposition = true
			var compositionCandidates map[string]map[string]struct{}
			objectBranchCount := 0
			for index, branch := range branches {
				branchCandidates, branchObjectApplicable, err := validationProfileDiscriminatorCandidates(branch, root, fmt.Sprintf("%s/%s/%d", path, keyword, index), proofStack, depth+1, budget)
				if err != nil {
					return nil, true, err
				}
				if !branchObjectApplicable {
					continue
				}
				objectBranchCount++
				if compositionCandidates == nil {
					compositionCandidates = cloneValidationProfileDiscriminatorCandidates(branchCandidates)
				} else {
					intersectValidationProfileDiscriminatorCandidates(compositionCandidates, branchCandidates)
				}
			}
			if objectBranchCount == 0 {
				continue
			}
			compositionObjectApplicable = true
			if combined == nil {
				combined = compositionCandidates
			} else {
				intersectValidationProfileDiscriminatorCandidates(combined, compositionCandidates)
			}
		}
		if foundComposition {
			return combined, compositionObjectApplicable, nil
		}

		if !validationProfileSchemaHasLocalObjectClosure(typed) {
			return nil, true, nil
		}
		requiredValues, ok := typed["required"].([]interface{})
		if !ok {
			return nil, true, nil
		}
		properties, ok := typed["properties"].(map[string]interface{})
		if !ok {
			return nil, true, nil
		}
		candidates := map[string]map[string]struct{}{}
		for _, rawProperty := range requiredValues {
			property, ok := rawProperty.(string)
			if !ok || !isCanonicalValidationProfileIdentity(property) {
				continue
			}
			propertySchema, ok := properties[property].(map[string]interface{})
			if !ok {
				continue
			}
			values, ok := finiteValidationProfileStringValues(propertySchema)
			if ok {
				candidates[property] = values
			}
		}
		return candidates, true, nil
	default:
		return nil, false, fmt.Errorf("schema node at %s must be an object or boolean", path)
	}
}

func finiteValidationProfileStringValues(schema map[string]interface{}) (map[string]struct{}, bool) {
	if value, present := schema["const"]; present {
		stringValue, ok := value.(string)
		if !ok || !isCanonicalValidationProfileIdentity(stringValue) {
			return nil, false
		}
		return map[string]struct{}{stringValue: {}}, true
	}
	rawValues, present := schema["enum"].([]interface{})
	if !present || len(rawValues) == 0 {
		return nil, false
	}
	values := make(map[string]struct{}, len(rawValues))
	for _, rawValue := range rawValues {
		stringValue, ok := rawValue.(string)
		if !ok || !isCanonicalValidationProfileIdentity(stringValue) {
			return nil, false
		}
		if _, duplicate := values[stringValue]; duplicate {
			return nil, false
		}
		values[stringValue] = struct{}{}
	}
	return values, true
}

func cloneValidationProfileDiscriminatorCandidates(input map[string]map[string]struct{}) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{}, len(input))
	for property, values := range input {
		result[property] = make(map[string]struct{}, len(values))
		for value := range values {
			result[property][value] = struct{}{}
		}
	}
	return result
}

func intersectValidationProfileDiscriminatorCandidates(left, right map[string]map[string]struct{}) {
	for property, leftValues := range left {
		rightValues, present := right[property]
		if !present {
			delete(left, property)
			continue
		}
		for value := range rightValues {
			leftValues[value] = struct{}{}
		}
	}
}

func validateValidationProfileSchemaNodeClosure(node interface{}, root map[string]interface{}, path string, proofStack map[string]bool, depth int, budget *validationProfileWalkBudget) error {
	if err := budget.enter(path, depth); err != nil {
		return err
	}
	closed, err := validationProfileSchemaProvesClosedObject(node, root, path, proofStack, depth, budget)
	if err != nil {
		return fmt.Errorf("schema object-closure proof at %s: %w", path, err)
	}
	if !closed {
		return fmt.Errorf("schema at %s can accept an object but does not prove a closed object shape with additionalProperties:false or unevaluatedProperties:false across every applicable branch", path)
	}
	object, ok := node.(map[string]interface{})
	if !ok {
		return nil
	}
	if _, present := object["patternProperties"]; present {
		return fmt.Errorf("schema at %s uses patternProperties, which cannot establish the closed named-property authority required for provider-plan artifacts", path)
	}
	for _, keyword := range []string{"additionalProperties", "unevaluatedProperties", "propertyNames", "items", "contains", "not", "if", "then", "else", "contentSchema", "unevaluatedItems"} {
		child, present := object[keyword]
		if !present {
			continue
		}
		if err := validateValidationProfileSchemaNodeClosure(child, root, path+"/"+keyword, map[string]bool{}, depth+1, budget); err != nil {
			return err
		}
	}
	for _, keyword := range []string{"prefixItems", "allOf", "anyOf", "oneOf"} {
		children, present := object[keyword].([]interface{})
		if !present {
			continue
		}
		for index, child := range children {
			if err := validateValidationProfileSchemaNodeClosure(child, root, fmt.Sprintf("%s/%s/%d", path, keyword, index), map[string]bool{}, depth+1, budget); err != nil {
				return err
			}
		}
	}
	for _, keyword := range []string{"$defs", "definitions", "properties", "dependentSchemas"} {
		children, present := object[keyword].(map[string]interface{})
		if !present {
			continue
		}
		keys := make([]string, 0, len(children))
		for key := range children {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := validateValidationProfileSchemaNodeClosure(children[key], root, path+"/"+keyword+"/"+escapeValidationProfileJSONPointerToken(key), map[string]bool{}, depth+1, budget); err != nil {
				return err
			}
		}
	}
	return nil
}

func validationProfileSchemaProvesClosedObject(node interface{}, root map[string]interface{}, path string, proofStack map[string]bool, depth int, budget *validationProfileWalkBudget) (bool, error) {
	if err := budget.enter(path, depth); err != nil {
		return false, err
	}
	switch typed := node.(type) {
	case bool:
		return !typed, nil
	case map[string]interface{}:
		if validationProfileSchemaExcludesObjects(typed) || validationProfileSchemaHasLocalObjectClosure(typed) {
			return true, nil
		}
		if proofStack[path] {
			return false, fmt.Errorf("reference cycle does not establish object closure")
		}
		proofStack[path] = true
		defer delete(proofStack, path)

		for _, keyword := range []string{"$ref", "$dynamicRef"} {
			if ref, present := typed[keyword]; present {
				refString, ok := ref.(string)
				if !ok {
					return false, fmt.Errorf("%s must be a string", keyword)
				}
				target, targetPath, err := resolveValidationProfileLocalJSONPointer(root, refString)
				if err != nil {
					return false, err
				}
				return validationProfileSchemaProvesClosedObject(target, root, targetPath, proofStack, depth+1, budget)
			}
		}
		foundComposition := false
		for _, keyword := range []string{"allOf", "anyOf", "oneOf"} {
			branches, present := typed[keyword].([]interface{})
			if !present {
				continue
			}
			if len(branches) == 0 {
				return false, fmt.Errorf("%s is empty", keyword)
			}
			foundComposition = true
			for index, branch := range branches {
				closed, err := validationProfileSchemaProvesClosedObject(branch, root, fmt.Sprintf("%s/%s/%d", path, keyword, index), proofStack, depth+1, budget)
				if err != nil {
					return false, err
				}
				if !closed {
					return false, nil
				}
			}
		}
		return foundComposition, nil
	default:
		return false, fmt.Errorf("schema node must be an object or boolean")
	}
}

func validationProfileSchemaExcludesObjects(schema map[string]interface{}) bool {
	if value, present := schema["type"]; present {
		switch typed := value.(type) {
		case string:
			return typed != "object"
		case []interface{}:
			for _, item := range typed {
				if item == "object" {
					return false
				}
			}
			return true
		}
	}
	if value, present := schema["const"]; present {
		_, isObject := value.(map[string]interface{})
		return !isObject
	}
	if values, present := schema["enum"].([]interface{}); present {
		for _, value := range values {
			if _, isObject := value.(map[string]interface{}); isObject {
				return false
			}
		}
		return true
	}
	return false
}

func validationProfileSchemaHasLocalObjectClosure(schema map[string]interface{}) bool {
	for _, keyword := range []string{"additionalProperties", "unevaluatedProperties"} {
		if value, present := schema[keyword]; present {
			if boolean, ok := value.(bool); ok && !boolean {
				return true
			}
		}
	}
	return false
}

func resolveValidationProfileLocalJSONPointer(root map[string]interface{}, ref string) (interface{}, string, error) {
	parsed, err := url.Parse(ref)
	if err != nil {
		return nil, "", fmt.Errorf("malformed schema reference %q: %w", ref, err)
	}
	if parsed.Scheme != "" || parsed.Host != "" || parsed.Opaque != "" || !strings.HasPrefix(ref, "#") {
		return nil, "", fmt.Errorf("external schema reference %q cannot establish local object closure", ref)
	}
	if ref == "#" {
		return root, "$", nil
	}
	if !strings.HasPrefix(parsed.Fragment, "/") {
		return nil, "", fmt.Errorf("internal anchor reference %q cannot establish static object closure; use a local JSON Pointer", ref)
	}
	current := interface{}(root)
	path := "$"
	for _, encodedToken := range strings.Split(strings.TrimPrefix(parsed.Fragment, "/"), "/") {
		token, err := unescapeValidationProfileJSONPointerToken(encodedToken)
		if err != nil {
			return nil, "", fmt.Errorf("malformed local JSON Pointer %q: %w", ref, err)
		}
		path += "/" + escapeValidationProfileJSONPointerToken(token)
		switch typed := current.(type) {
		case map[string]interface{}:
			var found bool
			current, found = typed[token]
			if !found {
				return nil, "", fmt.Errorf("local JSON Pointer %q does not resolve", ref)
			}
		case []interface{}:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, "", fmt.Errorf("local JSON Pointer %q has invalid array index %q", ref, token)
			}
			current = typed[index]
		default:
			return nil, "", fmt.Errorf("local JSON Pointer %q traverses a scalar", ref)
		}
	}
	return current, path, nil
}

func escapeValidationProfileJSONPointerToken(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func unescapeValidationProfileJSONPointerToken(value string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '~' {
			result.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) || (value[index+1] != '0' && value[index+1] != '1') {
			return "", fmt.Errorf("invalid escape at byte %d", index)
		}
		index++
		if value[index] == '0' {
			result.WriteByte('~')
		} else {
			result.WriteByte('/')
		}
	}
	return result.String(), nil
}

func isCanonicalValidationProfileIdentity(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validationProfileSHA256(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func isValidationProfileSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func sortedValidationProfileCoordinates[T any](values map[validationProfileCoordinate]T) []validationProfileCoordinate {
	coordinates := make([]validationProfileCoordinate, 0, len(values))
	for coordinate := range values {
		coordinates = append(coordinates, coordinate)
	}
	sort.Slice(coordinates, func(i, j int) bool {
		if coordinates[i].ID != coordinates[j].ID {
			return coordinates[i].ID < coordinates[j].ID
		}
		return coordinates[i].Version < coordinates[j].Version
	})
	return coordinates
}
