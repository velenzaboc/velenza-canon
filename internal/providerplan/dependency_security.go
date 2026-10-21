package providerplan

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"
)

const dependencySecurityMaxRowBytes = 32 * 1024 * 1024

type structuredSecurityAuthority uint8

const (
	structuredSecurityOrdinary structuredSecurityAuthority = iota
	structuredSecuritySchema
	structuredSecurityDescriptiveAuthority
)

// validateStructuredDependencySecurity rejects tenant scope, secret material,
// source bodies, and unsafe numeric-value policy from a structured dependency.
// It validates every nonblank JSONL row independently so one valid row cannot
// hide malformed or unsafe trailing input.
func validateStructuredDependencySecurity(input artifactInput) error {
	return validateStructuredDependencySecurityWithAuthority(input, structuredSecurityOrdinary)
}

// validateStructuredDependencySchemaSecurity applies the same carrier and
// policy scan while allowing JSON Schema declaration syntax. Callers may use
// it only after an independent immutable binding has established that these
// exact bytes occupy a schema coordinate.
func validateStructuredDependencySchemaSecurity(input artifactInput) error {
	return validateStructuredDependencySecurityWithAuthority(input, structuredSecuritySchema)
}

// validateStructuredAuthoritySecurity permits organization-scope vocabulary in
// an exact, independently pinned authority document. Such documents describe
// the kernel-injected scope contract; they are not derived artifacts carrying
// a caller-selected live scope. Credential, raw-body, exact-number, and JSON
// carrier checks remain identical to ordinary structured dependencies.
func validateStructuredAuthoritySecurity(input artifactInput) error {
	return validateStructuredDependencySecurityWithAuthority(input, structuredSecurityDescriptiveAuthority)
}

func validateStructuredDependencySecurityWithAuthority(input artifactInput, authority structuredSecurityAuthority) error {
	label := input.Path
	if label == "" {
		label = "<memory>"
	}

	scanner := bufio.NewScanner(bytes.NewReader(input.Raw))
	scanner.Buffer(make([]byte, 64*1024), dependencySecurityMaxRowBytes)
	lineNumber := 0
	credentialClosures := []*credentialClosureScanner{newCredentialClosureScanner(), newCredentialClosureScanner()}
	credentialOrders := []jsonCarrierTraversal{jsonCarrierSourceOrder, jsonCarrierCanonicalObjectOrder}
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if !utf8.Valid(line) {
			return fmt.Errorf("structured dependency %q row %d contains invalid UTF-8", label, lineNumber)
		}
		if err := rejectDuplicateJSONKeys(line); err != nil {
			return fmt.Errorf("structured dependency %q row %d: %w", label, lineNumber, err)
		}
		if err := rejectNonIntegerNumbers(line); err != nil {
			return fmt.Errorf("structured dependency %q row %d: %w", label, lineNumber, err)
		}

		var value interface{}
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("structured dependency %q row %d: decode JSON: %w", label, lineNumber, err)
		}
		state := dependencySecurityWalkState{
			artifactLabel:              label,
			lineNumber:                 lineNumber,
			schemaDocument:             authority == structuredSecuritySchema && dependencyJSONSchemaDocument(value),
			organizationScopeAuthority: authority == structuredSecurityDescriptiveAuthority,
		}
		if err := state.walk(value, "$", nil, "", 1); err != nil {
			return err
		}
		for index, credentialClosure := range credentialClosures {
			if err := credentialClosure.scanJSONWithOrder(line, credentialOrders[index]); err != nil {
				return state.violation("$", "%v", err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan structured dependency %q after row %d: %w", label, lineNumber, err)
	}
	for _, credentialClosure := range credentialClosures {
		if err := credentialClosure.finish(); err != nil {
			return fmt.Errorf("structured dependency %q: %w", label, err)
		}
	}
	return nil
}

type dependencySecurityWalkState struct {
	artifactLabel              string
	lineNumber                 int
	schemaDocument             bool
	organizationScopeAuthority bool
	nodes                      int
}

func (state *dependencySecurityWalkState) walk(value interface{}, path string, keyPath []string, credentialContextKey string, depth int) error {
	if depth > maxProviderJSONNestingDepth {
		return state.violation(path, "JSON value exceeds fixed nesting depth %d", maxProviderJSONNestingDepth)
	}
	state.nodes++
	if state.nodes > maxProviderJSONNodesPerValue {
		return state.violation(path, "JSON value exceeds fixed node limit %d", maxProviderJSONNodesPerValue)
	}
	switch typed := value.(type) {
	case map[string]interface{}:
		inheritedCredentialContext := credentialContextKey != ""
		mapCredentialContextKey := credentialContextKey
		if mapCredentialContextKey == "" {
			mapCredentialContextKey = dependencyMapDeclaredCredentialField(typed)
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := typed[key]
			childPath := dependencySecurityObjectPath(path, key)
			canonicalKey := canonicalSensitiveKey(key)
			childKeyPath := appendDependencySecurityKey(keyPath, canonicalKey)
			schemaPropertyDeclaration := state.schemaDocument && dependencyJSONSchemaPropertyDeclaration(childKeyPath, child)
			if credentialShapedValue(key) {
				return state.violation(childPath, "credential or secret material in an object key is forbidden")
			}
			if inheritedCredentialContext && !dependencyCredentialMetadataKey(canonicalKey) && dependencyCredentialScalarIsMaterial(key, "", mapCredentialContextKey) {
				return state.violation(childPath, "credential or secret material in an object key is forbidden")
			}
			if dependencyOrganizationScopeKey(canonicalKey) && !state.organizationScopeAuthority && !schemaPropertyDeclaration && !dependencyOrganizationScopePolicyAssertion(canonicalKey, child) {
				return state.violation(childPath, "organization scope key %q is forbidden; live scope is kernel-injected", key)
			}
			if dependencyRawBodySchemaValueCarrier(childKeyPath, child) {
				return state.violation(childPath, "embedded provider/document/source body payload is forbidden")
			}
			if dependencyRawBodyKey(canonicalKey) && !dependencyRawValuePolicy(childKeyPath) && dependencyHasEmbeddedPayload(child) && !dependencyEvidenceBodyDescriptor(canonicalKey, child) && !(state.schemaDocument && dependencyIntegerMetadataPropertySchema(childKeyPath, child)) && !schemaPropertyDeclaration {
				return state.violation(childPath, "embedded provider/document/source body payload is forbidden")
			}
			childCredentialContextKey := mapCredentialContextKey
			if credentialShapedKey(canonicalKey) {
				childCredentialContextKey = canonicalKey
			}
			if err := state.walk(child, childPath, childKeyPath, childCredentialContextKey, depth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		for index, child := range typed {
			if err := state.walk(child, fmt.Sprintf("%s[%d]", path, index), keyPath, credentialContextKey, depth+1); err != nil {
				return err
			}
		}
	case string:
		if credentialShapedValue(typed) {
			return state.violation(path, "credential or secret material is forbidden")
		}
		if dependencyUnsafePolicyString(keyPath, typed) && !(state.schemaDocument && dependencyJSONSchemaTypeDeclaration(keyPath)) {
			return state.violation(path, "unsafe numeric, embedding, or passthrough policy must be encoded as the exact boolean false posture")
		}
		if credentialContextKey != "" && dependencyCredentialScalarIsMaterial(typed, dependencySecurityLastKey(keyPath), credentialContextKey) {
			return state.violation(path, "credential or secret material is forbidden")
		}
	case json.Number:
		if credentialContextKey != "" && !dependencyCredentialMetadataKey(dependencySecurityLastKey(keyPath)) {
			return state.violation(path, "numeric credential or secret material is forbidden")
		}
	case bool:
		if typed && dependencyBinaryFloatAuthorityPolicy(keyPath) {
			return state.violation(path, "binary-float authority must not be enabled")
		}
		if typed && dependencyRawValuePolicy(keyPath) {
			return state.violation(path, "raw provider/source value embedding or passthrough must not be enabled")
		}
	}
	return nil
}

// dependencyJSONSchemaDocument recognizes only an explicit supported JSON
// Schema dialect marker. This prevents an artifact instance from laundering
// unsafe facts merely by containing a member named `properties`.
func dependencyJSONSchemaDocument(value interface{}) bool {
	object, ok := value.(map[string]interface{})
	if !ok {
		return false
	}
	dialect, ok := object["$schema"].(string)
	if !ok {
		return false
	}
	return strings.TrimSuffix(strings.TrimSpace(dialect), "#") == "https://json-schema.org/draft/2020-12/schema"
}

// dependencyJSONSchemaTypeDeclaration identifies the structural `type`
// keyword beneath a schema property declaration. Its string value describes
// the instance shape; it is not itself a binary-float, passthrough, embedding,
// or tenant-scope policy assertion. Value-bearing keywords such as const,
// default, enum, and examples deliberately receive no exemption.
func dependencyJSONSchemaTypeDeclaration(keyPath []string) bool {
	if len(keyPath) < 3 || keyPath[len(keyPath)-1] != "type" {
		return false
	}
	for index := len(keyPath) - 3; index >= 0; index-- {
		if keyPath[index] == "properties" && index+1 < len(keyPath)-1 {
			return true
		}
	}
	return false
}

func (state dependencySecurityWalkState) violation(path, format string, arguments ...interface{}) error {
	detail := fmt.Sprintf(format, arguments...)
	return fmt.Errorf("structured dependency %q row %d path %s: %s", state.artifactLabel, state.lineNumber, path, detail)
}

func dependencySecurityObjectPath(parent, key string) string {
	encoded, _ := json.Marshal(key)
	return parent + "[" + string(encoded) + "]"
}

func appendDependencySecurityKey(keys []string, key string) []string {
	result := make([]string, len(keys)+1)
	copy(result, keys)
	result[len(keys)] = key
	return result
}

func dependencySecurityLastKey(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	return keys[len(keys)-1]
}

func dependencyOrganizationScopeKey(canonicalKey string) bool {
	for _, suffix := range []string{
		"organizationid",
		"organizationidentifier",
		"organisationid",
		"organisationidentifier",
		"orgid",
		"orgidentifier",
		"tenantid",
		"tenantidentifier",
		"tenantscopeid",
		"tenantscopeidentifier",
	} {
		if canonicalKey == suffix || strings.HasSuffix(canonicalKey, suffix) {
			return true
		}
	}
	return false
}

func dependencyOrganizationScopePolicyAssertion(canonicalKey string, value interface{}) bool {
	if !strings.Contains(canonicalKey, "callersupplied") {
		return false
	}
	switch typed := value.(type) {
	case string:
		switch canonicalSensitiveKey(typed) {
		case "forbidden", "notallowed", "rejected", "mustberejected":
			return true
		}
	case bool:
		return !typed
	}
	return false
}

func dependencyRawBodyKey(canonicalKey string) bool {
	if canonicalKey == "" || dependencyBodyMetadataKey(canonicalKey) {
		return false
	}
	scoped := strings.Contains(canonicalKey, "provider") || strings.Contains(canonicalKey, "document") || strings.Contains(canonicalKey, "source")
	raw := strings.Contains(canonicalKey, "raw") || strings.Contains(canonicalKey, "base64") || strings.Contains(canonicalKey, "blob")
	payload := strings.Contains(canonicalKey, "body") || strings.Contains(canonicalKey, "payload") || strings.Contains(canonicalKey, "content") || strings.Contains(canonicalKey, "response") || strings.Contains(canonicalKey, "bytes")
	if scoped && payload {
		return true
	}
	return raw && (scoped || payload || strings.Contains(canonicalKey, "record"))
}

func dependencyBodyMetadataKey(canonicalKey string) bool {
	for _, marker := range []string{
		"sha256",
		"digest",
		"hash",
		"bytecount",
		"bytescount",
		"bytelength",
		"length",
		"size",
		"offset",
	} {
		if strings.Contains(canonicalKey, marker) {
			return true
		}
	}
	switch canonicalKey {
	case "componentbytedomainprofile", "rawsourceref", "sourcebyteprofile", "sourcecontenthashprofile":
		return true
	}
	return false
}

func dependencyHasEmbeddedPayload(value interface{}) bool {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed) != ""
	case []interface{}:
		return len(typed) != 0
	case map[string]interface{}:
		return len(typed) != 0
	default:
		return false
	}
}

func dependencyEvidenceBodyDescriptor(canonicalKey string, value interface{}) bool {
	if !strings.Contains(canonicalKey, "evidencebody") {
		return false
	}
	description, ok := value.(string)
	if !ok {
		return false
	}
	return strings.TrimSpace(description) == "exact source-declared machine-export bytes selected by an admitted representation declaration"
}

// dependencyJSONSchemaPropertyDeclaration distinguishes an object-valued
// schema declaration from an instance payload whose field happens to be named
// like source/body content. The exemption is structural and deliberately
// shallow: only the declaration node immediately beneath `properties` is
// exempted. Its keywords and values are still walked and carrier-scanned.
func dependencyJSONSchemaPropertyDeclaration(keyPath []string, value interface{}) bool {
	if len(keyPath) < 2 || keyPath[len(keyPath)-2] != "properties" {
		return false
	}
	object, ok := value.(map[string]interface{})
	if !ok {
		return false
	}
	if len(object) == 0 {
		return true
	}
	for key := range object {
		if dependencyJSONSchemaKeyword(key) {
			return true
		}
	}
	return false
}

func dependencyJSONSchemaKeyword(key string) bool {
	switch key {
	case "$anchor", "$comment", "$defs", "$dynamicAnchor", "$dynamicRef", "$id", "$ref", "$schema", "$vocabulary",
		"additionalProperties", "allOf", "anyOf", "const", "contains", "contentEncoding", "contentMediaType", "contentSchema",
		"default", "dependentRequired", "dependentSchemas", "deprecated", "description", "else", "enum", "examples",
		"exclusiveMaximum", "exclusiveMinimum", "format", "if", "items", "maxContains", "maxItems", "maxLength",
		"maxProperties", "maximum", "minContains", "minItems", "minLength", "minProperties", "minimum", "multipleOf",
		"not", "oneOf", "pattern", "patternProperties", "prefixItems", "properties", "propertyNames", "readOnly", "required",
		"then", "title", "type", "unevaluatedItems", "unevaluatedProperties", "uniqueItems", "writeOnly":
		return true
	default:
		return false
	}
}

func dependencyRawBodySchemaValueCarrier(keyPath []string, value interface{}) bool {
	if len(keyPath) < 3 || !dependencyJSONSchemaValueKeyword(keyPath[len(keyPath)-1]) {
		return false
	}
	for index := len(keyPath) - 3; index >= 0; index-- {
		if keyPath[index] != "properties" || index+1 >= len(keyPath)-1 || !dependencyRawBodyKey(keyPath[index+1]) {
			continue
		}
		switch typed := value.(type) {
		case string:
			return strings.TrimSpace(typed) != ""
		case []interface{}:
			return len(typed) != 0
		case map[string]interface{}:
			return len(typed) != 0
		case json.Number:
			integer, ok := new(big.Int).SetString(string(typed), 10)
			return ok && integer.BitLen() >= 128
		default:
			return false
		}
	}
	return false
}

func dependencyJSONSchemaValueKeyword(key string) bool {
	switch key {
	case "const", "default", "enum", "examples":
		return true
	default:
		return false
	}
}

// dependencyIntegerMetadataPropertySchema distinguishes a JSON Schema
// declaration for a byte/count metadata field from an instance that embeds
// source bytes. The exemption is deliberately narrow: it applies only under
// an exact `properties` boundary, requires integer type authority, and permits
// only bounded integer-valued range constraints. Value-bearing annotations
// and equality/roster keywords (const, enum, examples, default) are excluded:
// even when their members are integers, they are reversible byte carriers.
// A string, array, object, annotation, reference, or extension remains a
// body-capable carrier and is rejected by the ordinary raw-body rule.
func dependencyIntegerMetadataPropertySchema(keyPath []string, value interface{}) bool {
	if len(keyPath) < 2 || keyPath[len(keyPath)-2] != "properties" {
		return false
	}
	object, ok := value.(map[string]interface{})
	if !ok || len(object) == 0 {
		return false
	}
	typeName, ok := object["type"].(string)
	if !ok || typeName != "integer" {
		return false
	}
	for key, candidate := range object {
		switch key {
		case "type":
			continue
		case "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum":
			if _, ok := dependencyBoundedIntegerSchemaNumber(candidate); !ok {
				return false
			}
		case "multipleOf":
			multiple, ok := dependencyBoundedIntegerSchemaNumber(candidate)
			if !ok || multiple.Sign() <= 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func dependencyBoundedIntegerSchemaNumber(value interface{}) (*big.Int, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return nil, false
	}
	integer, ok := new(big.Int).SetString(string(number), 10)
	if !ok || integer.Sign() < 0 || integer.BitLen() > 63 {
		return nil, false
	}
	return integer, true
}

func dependencyMapDeclaredCredentialField(object map[string]interface{}) string {
	for _, key := range sortedProviderStringMapKeys(object) {
		value := object[key]
		switch canonicalSensitiveKey(key) {
		case "propertyname", "parametername", "fieldname", "sourcefield", "name":
			text, ok := value.(string)
			if ok && credentialShapedKey(canonicalSensitiveKey(text)) {
				return canonicalSensitiveKey(text)
			}
		}
	}
	return ""
}

func dependencyCredentialScalarIsMaterial(value, currentKey, contextKey string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	canonicalValue := canonicalSensitiveKey(trimmed)
	if canonicalValue == currentKey || (contextKey != "" && canonicalValue == contextKey) {
		return false
	}
	if dependencyCredentialMetadataKey(currentKey) && dependencyCredentialMetadataValueAllowed(currentKey, trimmed) {
		return false
	}
	switch canonicalValue {
	case "placeholder", "redacted", "omitted", "masked", "notprovided", "notapplicable", "unavailable", "exampleonly", "vaultbinding", "connectorvault", "connectorvaultbinding", "connectorvaultreference":
		return false
	}
	if dependencySymbolicCredentialPlaceholder(trimmed, currentKey, contextKey) {
		return false
	}
	return true
}

func dependencySymbolicCredentialPlaceholder(value, currentKey, contextKey string) bool {
	var inner string
	switch {
	case strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">"):
		inner = value[1 : len(value)-1]
	case strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}"):
		inner = value[2 : len(value)-1]
	case strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}"):
		inner = value[2 : len(value)-2]
	default:
		return false
	}
	if len(inner) == 0 || len(inner) > 128 || strings.TrimSpace(inner) != inner || credentialShapedValue(inner) {
		return false
	}
	canonicalInner := canonicalSensitiveKey(inner)
	if canonicalInner == "" || canonicalInner == "credential" || canonicalInner == "secret" || canonicalInner == "token" || canonicalInner == "connectorvaultbinding" || canonicalInner == "vaultbinding" {
		return canonicalInner != ""
	}
	return canonicalInner == currentKey || canonicalInner == contextKey
}

func dependencyCredentialMetadataValueAllowed(key, value string) bool {
	canonicalValue := canonicalSensitiveKey(value)
	switch key {
	case "rowkind":
		return canonicalSurfaceKindPattern.MatchString(value)
	case "type":
		switch canonicalValue {
		case "string", "object", "array", "boolean", "integer", "number":
			return true
		}
	case "format":
		switch canonicalValue {
		case "opaque", "password", "byte", "binary", "uuid":
			return true
		}
	case "in", "location":
		switch canonicalValue {
		case "header", "query", "cookie", "body", "connectorvault":
			return true
		}
	case "description":
		return dependencyCredentialDescriptionLooksLikeProse(value)
	}
	return false
}

func dependencyCredentialDescriptionLooksLikeProse(value string) bool {
	if len(value) > 512 || !strings.ContainsAny(value, " \t") || credentialShapedValue(value) {
		return false
	}
	longestToken := 0
	currentToken := 0
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '-' {
			currentToken++
			if currentToken > longestToken {
				longestToken = currentToken
			}
		} else {
			currentToken = 0
		}
	}
	return longestToken < 20
}

func dependencyCredentialMetadataKey(canonicalKey string) bool {
	switch canonicalKey {
	case "rowkind", "type", "format", "name", "parametername", "description", "in", "location", "required", "optional", "deprecated", "nullable", "readonly", "writeonly", "scope", "scopes", "granttype", "minlength", "maxlength", "length", "count", "ordinal":
		return true
	default:
		for _, suffix := range []string{"description", "field", "fieldname", "format", "location", "name", "parameter", "parametername", "required", "scope", "scopes", "type"} {
			if strings.HasSuffix(canonicalKey, suffix) {
				return true
			}
		}
		return false
	}
}

func dependencyUnsafePolicyString(keys []string, value string) bool {
	if !dependencyBinaryFloatAuthorityPolicy(keys) && !dependencyRawValuePolicy(keys) {
		return false
	}
	switch canonicalSensitiveKey(value) {
	case "false", "forbidden", "disabled", "notallowed", "rejected", "never":
		return false
	default:
		return true
	}
}

func dependencyBinaryFloatAuthorityPolicy(keys []string) bool {
	joined := strings.Join(keys, ".")
	return strings.Contains(joined, "binaryfloat") && (strings.Contains(joined, "authority") || strings.Contains(joined, "authoritative"))
}

func dependencyRawValuePolicy(keys []string) bool {
	joined := strings.Join(keys, ".")
	if !strings.Contains(joined, "embedding") && !strings.Contains(joined, "passthrough") {
		return false
	}
	if strings.Contains(joined, "rawvalue") || (strings.Contains(joined, "raw") && strings.Contains(joined, "value")) {
		return true
	}
	providerOrSource := strings.Contains(joined, "provider") || strings.Contains(joined, "source")
	valueOrPayload := strings.Contains(joined, "value") || strings.Contains(joined, "payload") || strings.Contains(joined, "raw")
	unknownOrArbitrary := strings.Contains(joined, "unknown") || strings.Contains(joined, "arbitrary")
	return (providerOrSource && valueOrPayload) || (strings.Contains(joined, "passthrough") && unknownOrArbitrary)
}
