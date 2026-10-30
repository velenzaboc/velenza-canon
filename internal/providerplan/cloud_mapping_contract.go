package providerplan

// This validator is the offline contract boundary between evidence-local cloud
// schemas and a separately owned neutral record schema.  It does not create
// OHM records or allocate semantic identities; it refuses a candidate whose
// declared mapping cannot be proved against both closed inputs.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

type CloudNeutralFieldSchema struct {
	ID             string          `json:"id"`
	ValueType      string          `json:"value_type"`
	Cardinality    string          `json:"cardinality"`
	Unit           string          `json:"unit,omitempty"`
	AllowsNull     bool            `json:"allows_null"`
	AllowedValues  []string        `json:"allowed_values,omitempty"`
	PresenceStates []string        `json:"presence_states,omitempty"`
	WireSchema     json.RawMessage `json:"wire_schema,omitempty"`
}

// CloudNeutralRecordSchema is a pinned projection of the domain owner's
// machine-readable schema.  OwnerRef and OwnerSHA256 prevent a candidate from
// silently binding a same-named field in a successor or unrelated contract.
type CloudNeutralRecordSchema struct {
	OwnerRef               string                    `json:"owner_ref"`
	OwnerSHA256            string                    `json:"owner_sha256"`
	ClassSymbol            string                    `json:"class_symbol"`
	ValidatorProfileRef    string                    `json:"validator_profile_ref"`
	ValidatorProfileSHA256 string                    `json:"validator_profile_sha256"`
	Fields                 []CloudNeutralFieldSchema `json:"fields"`
	definitions            map[string]json.RawMessage
	recordDefinition       json.RawMessage
	loadedFromExactOwner   bool
	sealedFieldsSHA256     string
}

const cloudInfrastructureRecordOwnerID = "1729172e-44a9-48bb-b833-9591cd105516"
const cloudInfrastructureRecordOwnerVersion = 2
const cloudInfrastructureRecordOwnerSHA256 = "8522cfbab364950c782cb4565b3d34f5dc8a0bc44c73afc1d2c9722cd753a4c5"
const cloudInfrastructureSchemaExportSHA256 = "4817cf1fdeb60f8ebf292c28d119bde065a85d7c864d7a85af87009b75620135"
const cloudInfrastructureSchemaFragmentSHA256 = "19646e19bf0bf947a2ce059060b64ee263ac507fe62afc17345aea8fbec4bab2"
const cloudInfrastructureValidatorProfileSymbol = "sections.s3_semantic_schema_and_relationships.type_and_presence_closure.machine_readable_target_schema.required_validator_profile"
const cloudInfrastructureValidatorProfileSHA256 = "7b92a5c6321ed25917c495857a3d3eeabf366611f112179c99bdbba39297ac4c"

// LoadCloudNeutralRecordSchema extracts a class definition from the exact
// machine-readable schema published by the Infrastructure Resource Record
// owner.  This keeps generated candidates tied to that owner's bytes rather
// than a copied list of target fields in Canon.
func LoadCloudNeutralRecordSchema(exportRaw []byte, expectedExportSHA256, classSymbol string) (CloudNeutralRecordSchema, error) {
	if len(exportRaw) == 0 || len(exportRaw) > 4<<20 || requireValidUTF8("neutral schema export", exportRaw) != nil || rejectDuplicateJSONKeys(exportRaw) != nil {
		return CloudNeutralRecordSchema{}, fmt.Errorf("neutral schema export is not bounded strict JSON")
	}
	if expectedExportSHA256 != cloudInfrastructureSchemaExportSHA256 || sha256Hex(exportRaw) != expectedExportSHA256 {
		return CloudNeutralRecordSchema{}, fmt.Errorf("neutral schema export bytes do not equal expected_sha256")
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(exportRaw, &root); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := requireCloudExactKeys(root, "export_kind", "export_version", "source_owner", "machine_readable_target_schema", "mapping_requirements"); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := requireCloudProfileString(root, "export_kind", "infrastructure_resource_record_mapping_schema_export"); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := requireCloudProfileInteger(root, "export_version", 1); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	provenance, err := rawObject(root["source_owner"])
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := requireCloudExactKeys(provenance, "doc_id", "version", "canonical_owner_sha256", "canonical_owner_commit", "machine_schema_json_pointer", "machine_schema_fragment_sha256", "export_not_full_owner_bytes"); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := requireCloudProfileString(provenance, "doc_id", cloudInfrastructureRecordOwnerID); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := requireCloudProfileInteger(provenance, "version", cloudInfrastructureRecordOwnerVersion); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := requireCloudProfileString(provenance, "canonical_owner_sha256", cloudInfrastructureRecordOwnerSHA256); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := requireCloudProfileString(provenance, "machine_schema_json_pointer", "/sections/s3_semantic_schema_and_relationships/type_and_presence_closure/machine_readable_target_schema"); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := requireCloudProfileString(provenance, "machine_schema_fragment_sha256", cloudInfrastructureSchemaFragmentSHA256); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	var notFull bool
	if err := json.Unmarshal(provenance["export_not_full_owner_bytes"], &notFull); err != nil || !notFull {
		return CloudNeutralRecordSchema{}, fmt.Errorf("neutral schema export must declare non-owner bytes")
	}
	schemaRaw, ok := root["machine_readable_target_schema"]
	if !ok {
		return CloudNeutralRecordSchema{}, fmt.Errorf("neutral schema export lacks machine schema")
	}
	canonicalSchema, err := canonicalizeCandidateJSON(schemaRaw)
	if err != nil || sha256Hex(canonicalSchema) != cloudInfrastructureSchemaFragmentSHA256 {
		return CloudNeutralRecordSchema{}, fmt.Errorf("neutral schema export fragment does not equal pinned canonical fragment")
	}
	schema, err := rawObject(schemaRaw)
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	mappingRequirements, err := rawObject(root["mapping_requirements"])
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	binding, err := rawObject(mappingRequirements["validator_profile_binding"])
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := validateCloudNeutralVocabulary(schema["$vocabulary"]); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if err := validateCloudNeutralValidatorProfile(schema, binding); err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	definitions, err := rawObject(schema["record_class_definitions"])
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	definition, ok := definitions[classSymbol]
	if !ok {
		return CloudNeutralRecordSchema{}, fmt.Errorf("neutral owner has no class definition %q", classSymbol)
	}
	class, err := rawObject(definition)
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	properties, err := rawObject(class["properties"])
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	required, err := rawStringSet(class["required"])
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	if len(required) != len(properties) {
		return CloudNeutralRecordSchema{}, fmt.Errorf("neutral class %q must close required/property fields", classSymbol)
	}
	schemaDefinitions, err := rawObject(schema["$defs"])
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	fields := make([]CloudNeutralFieldSchema, 0, len(properties))
	for _, name := range sortedCloudCatalogKeys(properties) {
		if _, required := required[name]; !required {
			return CloudNeutralRecordSchema{}, fmt.Errorf("neutral class %q leaves optional field %q outside closed mapping contract", classSymbol, name)
		}
		fields = append(fields, CloudNeutralFieldSchema{ID: name, ValueType: "json_schema_envelope", Cardinality: "one", WireSchema: bytes.Clone(properties[name])})
	}
	fieldsRaw, err := canonicalFactoryJSON(fields)
	if err != nil {
		return CloudNeutralRecordSchema{}, err
	}
	return CloudNeutralRecordSchema{OwnerRef: cloudInfrastructureRecordOwnerID + "#sections.s3_semantic_schema_and_relationships.type_and_presence_closure.machine_readable_target_schema.record_class_definitions." + classSymbol, OwnerSHA256: cloudInfrastructureRecordOwnerSHA256, ClassSymbol: classSymbol, ValidatorProfileRef: cloudInfrastructureValidatorProfileSymbol, ValidatorProfileSHA256: cloudInfrastructureValidatorProfileSHA256, Fields: fields, definitions: schemaDefinitions, recordDefinition: bytes.Clone(definition), loadedFromExactOwner: true, sealedFieldsSHA256: sha256Hex(fieldsRaw)}, nil
}

// validateCloudNeutralValidatorProfile binds evaluation to the owner's exact
// profile. Declaring a vocabulary alone is not proof that its assertions run.
func validateCloudNeutralValidatorProfile(schema, binding map[string]json.RawMessage) error {
	profileRaw, ok := schema["required_validator_profile"]
	if !ok {
		return fmt.Errorf("neutral schema has no required validator profile")
	}
	canonical, err := canonicalizeCandidateJSON(profileRaw)
	if err != nil || sha256Hex(canonical) != cloudInfrastructureValidatorProfileSHA256 {
		return fmt.Errorf("neutral validator profile does not equal supported exact profile")
	}
	profile, err := rawObject(profileRaw)
	if err != nil {
		return err
	}
	if err := requireCloudProfileString(profile, "owner_doc_id", cloudInfrastructureRecordOwnerID); err != nil {
		return err
	}
	if err := requireCloudProfileInteger(profile, "owner_version", cloudInfrastructureRecordOwnerVersion); err != nil {
		return err
	}
	if err := requireCloudProfileString(profile, "owner_symbol", cloudInfrastructureValidatorProfileSymbol); err != nil {
		return err
	}
	if err := requireCloudProfileString(profile, "required_dialect", "https://json-schema.org/draft/2020-12/schema"); err != nil {
		return err
	}
	if err := requireCloudProfileSet(profile, "required_vocabularies", []string{"https://json-schema.org/draft/2020-12/vocab/core", "https://json-schema.org/draft/2020-12/vocab/applicator", "https://json-schema.org/draft/2020-12/vocab/validation", "https://json-schema.org/draft/2020-12/vocab/format-assertion"}); err != nil {
		return err
	}
	if err := requireCloudProfileSet(profile, "asserted_formats", []string{"date-time"}); err != nil {
		return err
	}
	if err := requireCloudProfileSet(profile, "required_assertion_keywords", []string{"type", "minLength", "maxLength", "pattern", "enum", "const", "required", "additionalProperties", "format", "items", "minItems", "maxItems", "uniqueItems"}); err != nil {
		return err
	}
	var declaredHash string
	if err := json.Unmarshal(schema["required_validator_profile_sha256"], &declaredHash); err != nil || declaredHash != cloudInfrastructureValidatorProfileSHA256 {
		return fmt.Errorf("neutral validator profile hash binding is absent or wrong")
	}
	if err := requireCloudProfileString(binding, "owner_doc_id", cloudInfrastructureRecordOwnerID); err != nil {
		return err
	}
	if err := requireCloudProfileInteger(binding, "owner_version", cloudInfrastructureRecordOwnerVersion); err != nil {
		return err
	}
	if err := requireCloudProfileString(binding, "owner_symbol", cloudInfrastructureValidatorProfileSymbol); err != nil {
		return err
	}
	return requireCloudProfileString(binding, "profile_sha256", cloudInfrastructureValidatorProfileSHA256)
}

func requireCloudProfileString(object map[string]json.RawMessage, key, expected string) error {
	var actual string
	if err := json.Unmarshal(object[key], &actual); err != nil || actual != expected {
		return fmt.Errorf("validator profile %s is unsupported", key)
	}
	return nil
}

func requireCloudProfileInteger(object map[string]json.RawMessage, key string, expected int) error {
	var actual int
	if err := json.Unmarshal(object[key], &actual); err != nil || actual != expected {
		return fmt.Errorf("validator profile %s is unsupported", key)
	}
	return nil
}

func requireCloudProfileSet(object map[string]json.RawMessage, key string, expected []string) error {
	actual, err := rawStringSet(object[key])
	if err != nil || len(actual) != len(expected) {
		return fmt.Errorf("validator profile %s is unsupported", key)
	}
	for _, entry := range expected {
		if _, ok := actual[entry]; !ok {
			return fmt.Errorf("validator profile %s is unsupported", key)
		}
	}
	return nil
}

func requireCloudExactKeys(object map[string]json.RawMessage, keys ...string) error {
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[key] = struct{}{}
	}
	if len(object) != len(allowed) {
		return fmt.Errorf("object has unknown or missing fields")
	}
	for key := range allowed {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("object misses required field %q", key)
		}
	}
	return nil
}

// ValidateCloudNeutralRecordValue evaluates the portable closed vocabulary
// used by the owner's current wire schema. It intentionally refuses unknown
// assertion keywords instead of silently treating them as annotations.
func ValidateCloudNeutralRecordValue(schema CloudNeutralRecordSchema, raw []byte) error {
	if !schema.loadedFromExactOwner || schema.OwnerSHA256 != cloudInfrastructureRecordOwnerSHA256 || schema.ValidatorProfileRef != cloudInfrastructureValidatorProfileSymbol || schema.ValidatorProfileSHA256 != cloudInfrastructureValidatorProfileSHA256 || len(schema.recordDefinition) == 0 || len(schema.definitions) == 0 {
		return fmt.Errorf("neutral schema was not loaded from exact owner bytes")
	}
	fieldsRaw, err := canonicalFactoryJSON(schema.Fields)
	if err != nil || sha256Hex(fieldsRaw) != schema.sealedFieldsSHA256 {
		return fmt.Errorf("neutral schema exported fields were mutated after owner load")
	}
	if err := requireValidUTF8("neutral record", raw); err != nil || rejectDuplicateJSONKeys(raw) != nil {
		return fmt.Errorf("neutral record is not strict JSON")
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	return validateCloudJSONSchema(schema.recordDefinition, schema.definitions, value, map[string]bool{})
}

func validateCloudJSONSchema(raw json.RawMessage, definitions map[string]json.RawMessage, value any, seen map[string]bool) error {
	schema, err := rawObject(raw)
	if err != nil {
		return err
	}
	allowed := map[string]bool{"$ref": true, "oneOf": true, "type": true, "properties": true, "required": true, "additionalProperties": true, "enum": true, "const": true, "minLength": true, "maxLength": true, "pattern": true, "format": true, "description": true, "items": true, "minItems": true, "maxItems": true, "uniqueItems": true}
	for key := range schema {
		if !allowed[key] {
			return fmt.Errorf("unsupported schema assertion keyword %q", key)
		}
	}
	if ref, ok := schema["$ref"]; ok {
		var target string
		if json.Unmarshal(ref, &target) != nil || !strings.HasPrefix(target, "#/$defs/") {
			return fmt.Errorf("unsupported schema reference")
		}
		name := strings.TrimPrefix(target, "#/$defs/")
		if seen[name] {
			return fmt.Errorf("recursive schema reference %q", name)
		}
		body, ok := definitions[name]
		if !ok {
			return fmt.Errorf("missing schema definition %q", name)
		}
		seen[name] = true
		err := validateCloudJSONSchema(body, definitions, value, seen)
		delete(seen, name)
		return err
	}
	if branches, ok := schema["oneOf"]; ok {
		var arms []json.RawMessage
		if json.Unmarshal(branches, &arms) != nil {
			return fmt.Errorf("oneOf is not array")
		}
		matches := 0
		for _, arm := range arms {
			if validateCloudJSONSchema(arm, definitions, value, map[string]bool{}) == nil {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("oneOf matched %d branches", matches)
		}
		return nil
	}
	if typeRaw, ok := schema["type"]; ok {
		var typ string
		if json.Unmarshal(typeRaw, &typ) != nil {
			return fmt.Errorf("schema type invalid")
		}
		switch typ {
		case "object":
			if _, ok := value.(map[string]any); !ok {
				return fmt.Errorf("want object")
			}
		case "string":
			if _, ok := value.(string); !ok {
				return fmt.Errorf("want string")
			}
		case "array":
			if _, ok := value.([]any); !ok {
				return fmt.Errorf("want array")
			}
		default:
			return fmt.Errorf("unsupported schema type %q", typ)
		}
	}
	if constant, ok := schema["const"]; ok {
		var want any
		if json.Unmarshal(constant, &want) != nil || !cloudJSONEquivalent(want, value) {
			return fmt.Errorf("const mismatch")
		}
	}
	if enum, ok := schema["enum"]; ok {
		var values []any
		if json.Unmarshal(enum, &values) != nil {
			return fmt.Errorf("enum invalid")
		}
		match := false
		for _, candidate := range values {
			if cloudJSONEquivalent(candidate, value) {
				match = true
			}
		}
		if !match {
			return fmt.Errorf("enum mismatch")
		}
	}
	if stringValue, ok := value.(string); ok {
		if err := validateCloudStringAssertions(schema, stringValue); err != nil {
			return err
		}
	}
	if array, ok := value.([]any); ok {
		if err := validateCloudArrayAssertions(schema, definitions, array); err != nil {
			return err
		}
	}
	if propertiesRaw, ok := schema["properties"]; ok {
		properties, err := rawObject(propertiesRaw)
		if err != nil {
			return err
		}
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("properties require object")
		}
		required := map[string]struct{}{}
		if requiredRaw, ok := schema["required"]; ok {
			required, err = rawStringSet(requiredRaw)
			if err != nil {
				return err
			}
		}
		for name := range required {
			if _, ok := object[name]; !ok {
				return fmt.Errorf("required field %q missing", name)
			}
		}
		if additional, ok := schema["additionalProperties"]; ok {
			var allowed bool
			if json.Unmarshal(additional, &allowed) != nil {
				return fmt.Errorf("additionalProperties invalid")
			}
			if !allowed {
				for name := range object {
					if _, ok := properties[name]; !ok {
						return fmt.Errorf("additional field %q", name)
					}
				}
			}
		}
		for name, sub := range properties {
			if candidate, exists := object[name]; exists {
				if err := validateCloudJSONSchema(sub, definitions, candidate, map[string]bool{}); err != nil {
					return fmt.Errorf("field %q: %w", name, err)
				}
			}
		}
	}
	return nil
}

func validateCloudStringAssertions(schema map[string]json.RawMessage, value string) error {
	if min, ok := schema["minLength"]; ok {
		var n int
		if json.Unmarshal(min, &n) != nil || len([]rune(value)) < n {
			return fmt.Errorf("minLength violation")
		}
	}
	if max, ok := schema["maxLength"]; ok {
		var n int
		if json.Unmarshal(max, &n) != nil || len([]rune(value)) > n {
			return fmt.Errorf("maxLength violation")
		}
	}
	if pattern, ok := schema["pattern"]; ok {
		var expression string
		if json.Unmarshal(pattern, &expression) != nil {
			return fmt.Errorf("pattern invalid")
		}
		matched, err := regexp.MatchString(expression, value)
		if err != nil || !matched {
			return fmt.Errorf("pattern violation")
		}
	}
	if format, ok := schema["format"]; ok {
		var name string
		if json.Unmarshal(format, &name) != nil {
			return fmt.Errorf("format invalid")
		}
		if name != "date-time" {
			return fmt.Errorf("unsupported asserted format %q", name)
		}
		if err := validateCloudUTCInstant(value); err != nil {
			return err
		}
	}
	return nil
}

var cloudUTCInstantPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$`)

func validateCloudUTCInstant(value string) error {
	if !cloudUTCInstantPattern.MatchString(value) {
		return fmt.Errorf("date-time must use the exact UTC RFC3339 grammar")
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return fmt.Errorf("date-time is not a valid calendar instant")
	}
	return nil
}

func cloudJSONEquivalent(left, right any) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return bytes.Equal(a, b)
}

func rawObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	var value map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil || value == nil {
		return nil, fmt.Errorf("expected closed object")
	}
	return value, nil
}

func rawStringSet(raw json.RawMessage) (map[string]struct{}, error) {
	var values []string
	if len(raw) == 0 || json.Unmarshal(raw, &values) != nil {
		return nil, fmt.Errorf("expected string array")
	}
	set := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			return nil, fmt.Errorf("empty string in closed array")
		}
		if _, duplicate := set[value]; duplicate {
			return nil, fmt.Errorf("duplicate %q in closed array", value)
		}
		set[value] = struct{}{}
	}
	return set, nil
}

func validateCloudNeutralVocabulary(raw json.RawMessage) error {
	vocabulary, err := rawObject(raw)
	if err != nil {
		return err
	}
	required := map[string]struct{}{
		"https://json-schema.org/draft/2020-12/vocab/core":             {},
		"https://json-schema.org/draft/2020-12/vocab/applicator":       {},
		"https://json-schema.org/draft/2020-12/vocab/validation":       {},
		"https://json-schema.org/draft/2020-12/vocab/format-assertion": {},
	}
	if len(vocabulary) != len(required) {
		return fmt.Errorf("neutral schema declares unsupported vocabulary")
	}
	for uri := range required {
		var requiredFlag bool
		value, ok := vocabulary[uri]
		if !ok || json.Unmarshal(value, &requiredFlag) != nil || !requiredFlag {
			return fmt.Errorf("neutral schema does not require vocabulary %q", uri)
		}
	}
	return nil
}

type CloudMappingProjection string

const (
	CloudMappingProjectionExact                            CloudMappingProjection = "exact"
	CloudMappingProjectionRelationship                     CloudMappingProjection = "relationship_reference"
	CloudMappingProjectionGiBToBytes                       CloudMappingProjection = "binary_gib_to_bytes"
	CloudMappingProjectionCheckedPositiveIntegerGiBToBytes CloudMappingProjection = "checked_positive_integer_gib_to_bytes"
	CloudMappingProjectionBoundedZeroOrOneRelationship     CloudMappingProjection = "bounded_zero_or_one_relationship_reference"
	CloudMappingProjectionExactRFC3339                     CloudMappingProjection = "exact_rfc3339"
	CloudMappingProjectionEvidenceClosedScalar             CloudMappingProjection = "evidence_closed_scalar"
	CloudMappingProjectionBoundedOneEvidenceScalar         CloudMappingProjection = "bounded_one_evidence_closed_scalar"
	CloudMappingProjectionManyRelationship                 CloudMappingProjection = "many_relationship_references"
	CloudMappingProjectionPresentPrivateLeaf               CloudMappingProjection = "present_private_leaf_to_neutral_scalar"
)

type CloudExplicitNullDisposition string

const (
	CloudExplicitNullToNeutralNull CloudExplicitNullDisposition = "map_to_neutral_null"
	CloudExplicitNullToAbsent      CloudExplicitNullDisposition = "map_to_absent"
	CloudExplicitNullToUnknown     CloudExplicitNullDisposition = "map_to_unknown"
	CloudExplicitNullToPrivate     CloudExplicitNullDisposition = "source_private_only"
)

type CloudExplicitAbsentDisposition string

const (
	CloudAbsentRefuse    CloudExplicitAbsentDisposition = "refuse"
	CloudAbsentToAbsent  CloudExplicitAbsentDisposition = "map_to_absent"
	CloudAbsentToUnknown CloudExplicitAbsentDisposition = "map_to_unknown"
)

// CloudEvidenceValueRecipe is a closed evidence-bound scalar translation;
// it deliberately cannot evaluate expressions or coerce source types.
type CloudEvidenceValueRecipe struct {
	EvidenceRefs            []string          `json:"evidence_refs"`
	SourceToNeutral         map[string]string `json:"source_to_neutral"`
	UnknownValuePolicy      string            `json:"unknown_value_policy"`
	UnsupportedSourceValues []string          `json:"unsupported_source_values,omitempty"`
}

type CloudMappingContractField struct {
	SourcePointer             string                         `json:"source_pointer"`
	WirePointer               string                         `json:"wire_pointer,omitempty"`
	SourceFieldID             string                         `json:"source_field_id"`
	Disposition               CloudSourceFieldDisposition    `json:"disposition"`
	TargetField               string                         `json:"target_field,omitempty"`
	Projection                CloudMappingProjection         `json:"projection,omitempty"`
	SourceUnit                string                         `json:"source_unit,omitempty"`
	UnitEvidenceRef           string                         `json:"unit_evidence_ref,omitempty"`
	ExplicitNullDisposition   CloudExplicitNullDisposition   `json:"explicit_null_disposition"`
	ExplicitAbsentDisposition CloudExplicitAbsentDisposition `json:"explicit_absent_disposition"`
	LifecycleRecipe           *CloudLifecycleEnumRecipe      `json:"lifecycle_recipe,omitempty"`
	ValueRecipe               *CloudEvidenceValueRecipe      `json:"value_recipe,omitempty"`
}

// CloudLifecycleEnumRecipe is data carried by the same mapping contract the
// projector executes. Unknown provider values always refuse; no string
// similarity or provider-specific fallback is permitted.
type CloudLifecycleEnumRecipe struct {
	EvidenceRefs            []string          `json:"evidence_refs"`
	SourceToNeutral         map[string]string `json:"source_to_neutral"`
	UnknownValuePolicy      string            `json:"unknown_value_policy"`
	UnsupportedSourceValues []string          `json:"unsupported_source_values,omitempty"`
}

type CloudMappingContract struct {
	OperationID      string                        `json:"operation_id"`
	ObjectSchemaID   string                        `json:"object_schema_id"`
	Neutral          CloudNeutralRecordSchema      `json:"neutral"`
	Fields           []CloudMappingContractField   `json:"fields"`
	Nested           []CloudNestedDecomposition    `json:"nested,omitempty"`
	EvidenceBindings []CloudMappingEvidenceBinding `json:"evidence_bindings,omitempty"`
	evidenceStamp    string
}

type CloudMappingEvidenceBinding struct {
	ID             string `json:"id"`
	SourceURI      string `json:"source_uri"`
	SourcePath     string `json:"source_path"`
	ExpectedSHA256 string `json:"expected_sha256"`
	StartByte      int    `json:"start_byte"`
	EndByte        int    `json:"end_byte"`
	SliceSHA256    string `json:"slice_sha256"`
}

type cloudResolvedField struct {
	ID              string
	Pointer         string
	ValueType       string
	Cardinality     string
	Nullable        bool
	ShapeID         string
	WirePointer     string
	InlineSchema    json.RawMessage
	KnownEnumValues []string
}

// ValidateCloudMappingContract validates a complete mapping roster.  Every
// direct property of the selected object is accounted for. Nested object,
// map, and recursive source forms remain opaque unless an explicit bounded
// nested decomposition supplies a complete retained leaf closure. Unexpanded
// complex/list fields must be explicitly private or unsupported.
func ValidateCloudMappingContract(catalog CloudCatalog, contract CloudMappingContract) error {
	if len(contract.EvidenceBindings) > 0 {
		stamp, err := cloudMappingEvidenceStamp(contract.EvidenceBindings)
		if err != nil || contract.evidenceStamp == "" || stamp != contract.evidenceStamp {
			return fmt.Errorf("mapping evidence was not loaded, verified, or remained unchanged")
		}
	}
	if err := validateCloudMappingEvidenceReferences(contract); err != nil {
		return err
	}
	if strings.TrimSpace(contract.OperationID) == "" || strings.TrimSpace(contract.ObjectSchemaID) == "" {
		return fmt.Errorf("operation_id and object_schema_id are required")
	}
	op, ok := findCloudCatalogOperation(catalog, contract.OperationID)
	if !ok || op.AssociationStatus == cloudCatalogAssociationUnresolved {
		return fmt.Errorf("operation %q is absent or has unresolved resource association", contract.OperationID)
	}
	if err := validateCloudOperationObjectReachability(catalog, op, contract.ObjectSchemaID); err != nil {
		return err
	}
	neutral, err := cloudNeutralFieldMap(contract.Neutral)
	if err != nil {
		return err
	}
	source, err := cloudCatalogObjectFields(catalog, contract.ObjectSchemaID)
	if err != nil {
		return err
	}
	decomposed, err := validateCloudNestedDecompositions(catalog, contract, neutral, source)
	if err != nil {
		return err
	}
	wantDirect := len(source) - len(decomposed)
	if len(contract.Fields) != wantDirect {
		return fmt.Errorf("mapping has %d fields, want complete %d-field object roster", len(contract.Fields), wantDirect)
	}
	seen := map[string]struct{}{}
	for _, mapping := range contract.Fields {
		field, ok := source[mapping.SourcePointer]
		if !ok {
			return fmt.Errorf("mapping source pointer %q is not a selected object field", mapping.SourcePointer)
		}
		if mapping.SourceFieldID != field.ID {
			return fmt.Errorf("mapping %q source_field_id = %q, want %q", mapping.SourcePointer, mapping.SourceFieldID, field.ID)
		}
		if _, duplicate := seen[mapping.SourcePointer]; duplicate {
			return fmt.Errorf("duplicate mapping for source pointer %q", mapping.SourcePointer)
		}
		if _, nested := decomposed[mapping.SourcePointer]; nested {
			return fmt.Errorf("decomposed source field %q cannot also have a direct disposition", mapping.SourcePointer)
		}
		seen[mapping.SourcePointer] = struct{}{}
		if err := validateCloudNullDisposition(mapping, field, neutral); err != nil {
			return err
		}
		if err := validateCloudMappingField(mapping, field, neutral); err != nil {
			return err
		}
	}
	for pointer := range source {
		if _, nested := decomposed[pointer]; nested {
			continue
		}
		if _, ok := seen[pointer]; !ok {
			return fmt.Errorf("selected source field %q lacks a disposition", pointer)
		}
	}
	// Every target fact has one writer within an observation. Merging several
	// source facts requires an owned composition rule, never iteration order.
	writers := map[string]string{}
	for _, field := range cloudNeutralProjectionFields(contract) {
		if field.TargetField == "" {
			continue
		}
		if old, duplicate := writers[field.TargetField]; duplicate {
			return fmt.Errorf("neutral field %q has competing source writers %q and %q", field.TargetField, old, field.SourcePointer)
		}
		writers[field.TargetField] = field.SourcePointer
	}
	return nil
}

func validateCloudMappingEvidenceReferences(contract CloudMappingContract) error {
	ids := mappingEvidenceIDs(contract)
	check := func(fields []CloudMappingContractField) error {
		for _, f := range fields {
			if f.UnitEvidenceRef != "" {
				if _, ok := ids[f.UnitEvidenceRef]; !ok {
					return fmt.Errorf("unit evidence ref %q is unbound", f.UnitEvidenceRef)
				}
			}
			if f.LifecycleRecipe != nil {
				for _, ref := range f.LifecycleRecipe.EvidenceRefs {
					if _, ok := ids[ref]; !ok {
						return fmt.Errorf("lifecycle evidence ref %q is unbound", ref)
					}
				}
			}
			if f.ValueRecipe != nil {
				for _, ref := range f.ValueRecipe.EvidenceRefs {
					if _, ok := ids[ref]; !ok {
						return fmt.Errorf("value evidence ref %q is unbound", ref)
					}
				}
			}
		}
		return nil
	}
	if err := check(contract.Fields); err != nil {
		return err
	}
	for _, nested := range contract.Nested {
		if err := check(nested.Fields); err != nil {
			return err
		}
	}
	return nil
}

// validateCloudOperationObjectReachability proves that a mapper is selecting a
// response object actually exposed by its declared operation.  Catalogs retain
// the pinned source operation bytes, so this must not be inferred from a
// caller-supplied schema id or resource label.
func validateCloudOperationObjectReachability(catalog CloudCatalog, operation CloudCatalogOperation, objectID string) error {
	if len(operation.RawJSON) == 0 {
		return fmt.Errorf("operation %q has no pinned response declaration", operation.ID)
	}
	operationRaw, err := rawObject(operation.RawJSON)
	if err != nil {
		return fmt.Errorf("operation %q: %w", operation.ID, err)
	}
	roots := cloudOperationResponseTargets(operationRaw)
	if len(roots) == 0 {
		return fmt.Errorf("operation %q has no supported response declaration", operation.ID)
	}
	queue := append([]string(nil), roots...)
	seen := map[string]bool{}
	for len(queue) > 0 {
		shapeID := queue[0]
		queue = queue[1:]
		if seen[shapeID] {
			continue
		}
		seen[shapeID] = true
		if shapeID == objectID {
			return nil
		}
		shape, ok := cloudCatalogShape(catalog, shapeID)
		if !ok {
			return fmt.Errorf("operation %q response refers to unretained schema %q", operation.ID, shapeID)
		}
		next, err := cloudShapeReferenceTargets(shape.RawJSON)
		if err != nil {
			return fmt.Errorf("operation %q response shape %q: %w", operation.ID, shapeID, err)
		}
		queue = append(queue, next...)
		if len(seen) > len(catalog.SchemaShapes) {
			return fmt.Errorf("operation %q response traversal exceeded retained shapes", operation.ID)
		}
	}
	return fmt.Errorf("object schema %q is not reachable from operation %q response", objectID, operation.ID)
}

func cloudOperationResponseTargets(operation map[string]json.RawMessage) []string {
	if outputRaw, ok := operation["output"]; ok { // Smithy operation.
		var output struct {
			Target string `json:"target"`
		}
		if json.Unmarshal(outputRaw, &output) == nil && output.Target != "" {
			return []string{output.Target}
		}
	}
	if responseRaw, ok := operation["response"]; ok { // Google Discovery method.
		var response struct {
			Ref string `json:"$ref"`
		}
		if json.Unmarshal(responseRaw, &response) == nil && response.Ref != "" {
			return []string{response.Ref}
		}
	}
	return nil
}

func cloudShapeReferenceTargets(raw json.RawMessage) ([]string, error) {
	object, err := rawObject(raw)
	if err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	var walk func(map[string]json.RawMessage) error
	walk = func(current map[string]json.RawMessage) error {
		if refRaw, ok := current["$ref"]; ok {
			var ref string
			if json.Unmarshal(refRaw, &ref) != nil || ref == "" {
				return fmt.Errorf("invalid reference")
			}
			set[ref] = struct{}{}
		}
		if targetRaw, ok := current["target"]; ok {
			var target string
			if json.Unmarshal(targetRaw, &target) != nil || target == "" {
				return fmt.Errorf("invalid target")
			}
			set[target] = struct{}{}
		}
		for _, key := range []string{"members", "properties"} {
			if nestedRaw, ok := current[key]; ok {
				nested, err := rawObject(nestedRaw)
				if err != nil {
					return err
				}
				for _, child := range nested {
					childObject, err := rawObject(child)
					if err != nil {
						return err
					}
					if err := walk(childObject); err != nil {
						return err
					}
				}
			}
		}
		for _, key := range []string{"member", "items", "key", "value", "additionalProperties"} {
			if childRaw, ok := current[key]; ok {
				child, err := rawObject(childRaw)
				if err != nil {
					return err
				}
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(object); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}

func cloudNeutralFieldMap(schema CloudNeutralRecordSchema) (map[string]CloudNeutralFieldSchema, error) {
	if !schema.loadedFromExactOwner || schema.OwnerSHA256 != cloudInfrastructureRecordOwnerSHA256 || schema.ValidatorProfileRef != cloudInfrastructureValidatorProfileSymbol || schema.ValidatorProfileSHA256 != cloudInfrastructureValidatorProfileSHA256 || strings.TrimSpace(schema.ClassSymbol) == "" || len(schema.Fields) == 0 {
		return nil, fmt.Errorf("neutral schema must pin owner ref, hash, class symbol and fields")
	}
	expectedOwnerRef := cloudInfrastructureRecordOwnerID + "#sections.s3_semantic_schema_and_relationships.type_and_presence_closure.machine_readable_target_schema.record_class_definitions." + schema.ClassSymbol
	if schema.OwnerRef != expectedOwnerRef {
		return nil, fmt.Errorf("neutral schema owner ref does not equal exact class coordinate")
	}
	fieldsRaw, err := canonicalFactoryJSON(schema.Fields)
	if err != nil || schema.sealedFieldsSHA256 == "" || sha256Hex(fieldsRaw) != schema.sealedFieldsSHA256 {
		return nil, fmt.Errorf("neutral schema exported fields were mutated after owner load")
	}
	result := make(map[string]CloudNeutralFieldSchema, len(schema.Fields))
	for _, field := range schema.Fields {
		if strings.TrimSpace(field.ID) == "" || strings.TrimSpace(field.ValueType) == "" || !validCloudCardinality(field.Cardinality) {
			return nil, fmt.Errorf("neutral field is incomplete")
		}
		if _, exists := result[field.ID]; exists {
			return nil, fmt.Errorf("duplicate neutral field %q", field.ID)
		}
		if !sortedUniqueCloudValues(field.AllowedValues) {
			return nil, fmt.Errorf("neutral field %q allowed values are not sorted unique", field.ID)
		}
		if field.ValueType == "json_schema_envelope" {
			inferred, err := inferCloudNeutralWireType(field.WireSchema, schema.definitions, map[string]bool{})
			if err != nil {
				return nil, fmt.Errorf("neutral field %q: %w", field.ID, err)
			}
			field.ValueType, field.Cardinality, field.Unit, field.AllowsNull = inferred.ValueType, inferred.Cardinality, inferred.Unit, inferred.AllowsNull
			field.PresenceStates = cloudNeutralPresenceStates(field.WireSchema, schema.definitions, map[string]bool{})
			field.AllowedValues = cloudNeutralEnumValues(field.WireSchema, schema.definitions, map[string]bool{})
		}
		result[field.ID] = field
	}
	return result, nil
}

func cloudNeutralEnumValues(raw json.RawMessage, definitions map[string]json.RawMessage, seen map[string]bool) []string {
	object, err := rawObject(raw)
	if err != nil {
		return nil
	}
	if refRaw, ok := object["$ref"]; ok {
		var ref string
		if json.Unmarshal(refRaw, &ref) == nil && strings.HasPrefix(ref, "#/$defs/") && !seen[ref] {
			seen[ref] = true
			values := cloudNeutralEnumValues(definitions[strings.TrimPrefix(ref, "#/$defs/")], definitions, seen)
			delete(seen, ref)
			return values
		}
	}
	set := map[string]struct{}{}
	var walk func(json.RawMessage)
	walk = func(candidate json.RawMessage) {
		child, e := rawObject(candidate)
		if e != nil {
			return
		}
		if arms, ok := child["oneOf"]; ok {
			var values []json.RawMessage
			if json.Unmarshal(arms, &values) == nil {
				for _, v := range values {
					walk(v)
				}
			}
		}
		if props, ok := child["properties"]; ok {
			if p, e := rawObject(props); e == nil {
				if value, ok := p["value"]; ok {
					if v, e := rawObject(value); e == nil {
						var enums []string
						if json.Unmarshal(v["enum"], &enums) == nil {
							for _, x := range enums {
								set[x] = struct{}{}
							}
						}
					}
				}
			}
		}
		if ref, ok := child["$ref"]; ok {
			var id string
			if json.Unmarshal(ref, &id) == nil && strings.HasPrefix(id, "#/$defs/") && !seen[id] {
				seen[id] = true
				walk(definitions[strings.TrimPrefix(id, "#/$defs/")])
				delete(seen, id)
			}
		}
	}
	walk(raw)
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func cloudNeutralPresenceStates(raw json.RawMessage, definitions map[string]json.RawMessage, seen map[string]bool) []string {
	object, err := rawObject(raw)
	if err != nil {
		return nil
	}
	if refRaw, ok := object["$ref"]; ok {
		var ref string
		if json.Unmarshal(refRaw, &ref) == nil && strings.HasPrefix(ref, "#/$defs/") && !seen[ref] {
			seen[ref] = true
			values := cloudNeutralPresenceStates(definitions[strings.TrimPrefix(ref, "#/$defs/")], definitions, seen)
			delete(seen, ref)
			return values
		}
	}
	set := map[string]struct{}{}
	if armsRaw, ok := object["oneOf"]; ok {
		var arms []json.RawMessage
		if json.Unmarshal(armsRaw, &arms) == nil {
			for _, arm := range arms {
				for _, state := range cloudNeutralPresenceStates(arm, definitions, seen) {
					set[state] = struct{}{}
				}
			}
		}
	}
	if propertiesRaw, ok := object["properties"]; ok {
		if properties, e := rawObject(propertiesRaw); e == nil {
			if stateRaw, found := properties["state"]; found {
				if state, e := rawObject(stateRaw); e == nil {
					var constant string
					if json.Unmarshal(state["const"], &constant) == nil && constant != "" {
						set[constant] = struct{}{}
					}
					var values []string
					if json.Unmarshal(state["enum"], &values) == nil {
						for _, value := range values {
							set[value] = struct{}{}
						}
					}
				}
			}
		}
	}
	result := make([]string, 0, len(set))
	for state := range set {
		result = append(result, state)
	}
	sort.Strings(result)
	return result
}

func inferCloudNeutralWireType(raw json.RawMessage, definitions map[string]json.RawMessage, seen map[string]bool) (CloudNeutralFieldSchema, error) {
	object, err := rawObject(raw)
	if err != nil {
		return CloudNeutralFieldSchema{}, err
	}
	if refRaw, ok := object["$ref"]; ok {
		var ref string
		if err := json.Unmarshal(refRaw, &ref); err != nil || !strings.HasPrefix(ref, "#/$defs/") {
			return CloudNeutralFieldSchema{}, fmt.Errorf("unsupported target reference")
		}
		name := strings.TrimPrefix(ref, "#/$defs/")
		if seen[name] {
			return CloudNeutralFieldSchema{}, fmt.Errorf("recursive target reference %q", name)
		}
		target, ok := definitions[name]
		if !ok {
			return CloudNeutralFieldSchema{}, fmt.Errorf("target definition %q absent", name)
		}
		seen[name] = true
		result, err := inferCloudNeutralWireType(target, definitions, seen)
		delete(seen, name)
		return result, err
	}
	if oneOfRaw, ok := object["oneOf"]; ok {
		var arms []json.RawMessage
		if err := json.Unmarshal(oneOfRaw, &arms); err != nil {
			return CloudNeutralFieldSchema{}, err
		}
		var present *CloudNeutralFieldSchema
		nullable := false
		for _, arm := range arms {
			candidate, err := inferCloudNeutralWireType(arm, definitions, seen)
			if err == nil {
				if candidate.ValueType == "null" {
					nullable = true
					continue
				}
				if present == nil {
					copy := candidate
					present = &copy
				}
			}
		}
		if present == nil {
			return CloudNeutralFieldSchema{}, fmt.Errorf("oneOf has no present target arm")
		}
		present.AllowsNull = present.AllowsNull || nullable
		return *present, nil
	}
	if typeRaw, ok := object["type"]; ok {
		var typ string
		if json.Unmarshal(typeRaw, &typ) == nil && typ == "null" {
			return CloudNeutralFieldSchema{ValueType: "null", Cardinality: "one"}, nil
		}
		if json.Unmarshal(typeRaw, &typ) == nil && typ == "string" {
			// A direct scalar class property (for example the protected semantic
			// identity) is not a source presence envelope and cannot be targeted
			// by provider mapping.
			return CloudNeutralFieldSchema{ValueType: "system_scalar", Cardinality: "one"}, nil
		}
	}
	if _, constant := object["const"]; constant {
		return CloudNeutralFieldSchema{ValueType: "constant", Cardinality: "one"}, nil
	}
	if _, enumerated := object["enum"]; enumerated {
		return CloudNeutralFieldSchema{ValueType: "system_scalar", Cardinality: "one"}, nil
	}
	properties, err := rawObject(object["properties"])
	if err != nil {
		return CloudNeutralFieldSchema{}, fmt.Errorf("target field lacks supported object schema")
	}
	value, hasValue := properties["value"]
	if !hasValue {
		return CloudNeutralFieldSchema{}, fmt.Errorf("target field has no present value")
	}
	valueObject, err := rawObject(value)
	if err != nil {
		return CloudNeutralFieldSchema{}, err
	}
	if valueRef, ok := valueObject["$ref"]; ok {
		var ref string
		_ = json.Unmarshal(valueRef, &ref)
		if strings.HasSuffix(ref, "semantic_record_instance_identity") {
			return CloudNeutralFieldSchema{ValueType: "semantic_reference", Cardinality: "one"}, nil
		}
	}
	var valueType string
	_ = json.Unmarshal(valueObject["type"], &valueType)
	if valueType == "" {
		if _, enumerated := valueObject["enum"]; enumerated {
			valueType = "string"
		}
	}
	if valueType == "array" {
		item, err := rawObject(valueObject["items"])
		var ref string
		if err == nil && json.Unmarshal(item["$ref"], &ref) == nil && ref == "#/$defs/semantic_record_instance_identity" {
			return CloudNeutralFieldSchema{ValueType: "semantic_reference", Cardinality: "many"}, nil
		}
		return CloudNeutralFieldSchema{}, fmt.Errorf("target array requires an exact semantic identity item schema")
	}
	if valueType != "string" {
		return CloudNeutralFieldSchema{}, fmt.Errorf("unsupported target value type %q", valueType)
	}
	if unit, ok := properties["unit"]; ok {
		unitObject, err := rawObject(unit)
		if err == nil {
			var constant string
			_ = json.Unmarshal(unitObject["const"], &constant)
			if constant == "bytes" {
				return CloudNeutralFieldSchema{ValueType: "unsigned_integer", Cardinality: "one", Unit: "bytes"}, nil
			}
		}
	}
	return CloudNeutralFieldSchema{ValueType: "string", Cardinality: "one"}, nil
}

func validateCloudNullDisposition(mapping CloudMappingContractField, field cloudResolvedField, neutral map[string]CloudNeutralFieldSchema) error {
	if mapping.ExplicitNullDisposition == "" {
		return fmt.Errorf("source field %q lacks explicit-null disposition", field.ID)
	}
	switch mapping.ExplicitNullDisposition {
	case CloudExplicitNullToNeutralNull, CloudExplicitNullToAbsent, CloudExplicitNullToUnknown, CloudExplicitNullToPrivate:
	default:
		return fmt.Errorf("source field %q has unknown explicit-null disposition", field.ID)
	}
	if mapping.ExplicitNullDisposition == CloudExplicitNullToNeutralNull && !field.Nullable {
		return fmt.Errorf("source field %q cannot map null to a neutral null because source schema does not permit null", field.ID)
	}
	if mapping.Disposition == CloudSourcePrivateOnly || mapping.Disposition == CloudSourceNotObserved || mapping.Disposition == CloudSourceUnsupported || mapping.Disposition == CloudSourceUnknown {
		return nil
	}
	target, ok := neutral[mapping.TargetField]
	if !ok {
		return fmt.Errorf("source field %q has no declared neutral target for null disposition", field.ID)
	}
	if mapping.ExplicitNullDisposition == CloudExplicitNullToNeutralNull && !cloudHasPresenceState(target, "null") {
		return fmt.Errorf("source field %q maps null to target %q without an explicit null arm", field.ID, target.ID)
	}
	if len(target.WireSchema) > 0 && mapping.ExplicitNullDisposition == CloudExplicitNullToAbsent && !cloudHasPresenceState(target, "absent") {
		return fmt.Errorf("source field %q maps null to target %q without an absent arm", field.ID, target.ID)
	}
	if len(target.WireSchema) > 0 && mapping.ExplicitNullDisposition == CloudExplicitNullToUnknown && !cloudHasPresenceState(target, "unknown") {
		return fmt.Errorf("source field %q maps null to target %q without an unknown arm", field.ID, target.ID)
	}
	return nil
}

func cloudHasPresenceState(target CloudNeutralFieldSchema, state string) bool {
	for _, candidate := range target.PresenceStates {
		if candidate == state {
			return true
		}
	}
	return false
}

func validateCloudMappingField(mapping CloudMappingContractField, source cloudResolvedField, neutral map[string]CloudNeutralFieldSchema) error {
	switch mapping.Disposition {
	case CloudSourceNotObserved, CloudSourceUnsupported, CloudSourceUnknown, CloudSourcePrivateOnly:
		if mapping.TargetField != "" || mapping.Projection != "" || mapping.SourceUnit != "" || mapping.ValueRecipe != nil || mapping.LifecycleRecipe != nil || mapping.ExplicitAbsentDisposition != "" {
			return fmt.Errorf("%s mapping for %q cannot carry a target, projection or unit", mapping.Disposition, source.ID)
		}
		return nil
	case CloudSourceMapsExactSourceFact, CloudSourceMapsExactRelationshipFact:
	case CloudSourceMapsExactLifecycleFact:
	default:
		return fmt.Errorf("source field %q has unsupported disposition %q", source.ID, mapping.Disposition)
	}
	target, ok := neutral[mapping.TargetField]
	if !ok {
		return fmt.Errorf("source field %q targets unknown neutral field %q", source.ID, mapping.TargetField)
	}
	if err := validateCloudAbsentDisposition(mapping, target); err != nil {
		return err
	}
	if mapping.Disposition != CloudSourceMapsExactLifecycleFact && mapping.LifecycleRecipe != nil {
		return fmt.Errorf("lifecycle recipe cannot be attached to another disposition")
	}
	if mapping.ValueRecipe != nil && mapping.Projection != CloudMappingProjectionEvidenceClosedScalar && mapping.Projection != CloudMappingProjectionBoundedOneEvidenceScalar && mapping.Projection != CloudMappingProjectionPresentPrivateLeaf {
		return fmt.Errorf("value recipe cannot be detached from its evidence-bound projection")
	}
	if target.ID == "lifecycle_state" && mapping.Disposition != CloudSourceMapsExactLifecycleFact {
		return fmt.Errorf("lifecycle_state requires lifecycle enum recipe disposition")
	}
	if mapping.Disposition == CloudSourceMapsExactLifecycleFact && target.ID != "lifecycle_state" {
		return fmt.Errorf("lifecycle recipe may only target lifecycle_state")
	}
	if mapping.Disposition == CloudSourceMapsExactLifecycleFact {
		if err := validateCloudLifecycleRecipe(mapping, source, target); err != nil {
			return fmt.Errorf("lifecycle mapping %q: %w", source.ID, err)
		}
	}
	if mapping.Projection == "" {
		mapping.Projection = CloudMappingProjectionExact
	}
	switch mapping.Projection {
	case CloudMappingProjectionExact:
		if target.Unit != "" && mapping.UnitEvidenceRef == "" {
			return fmt.Errorf("exact unit mapping %q lacks unit evidence", source.ID)
		}
		if source.ValueType != target.ValueType || source.Cardinality != target.Cardinality || mapping.SourceUnit != target.Unit {
			return fmt.Errorf("exact mapping %q to %q changes type, cardinality or unit", source.ID, target.ID)
		}
	case CloudMappingProjectionRelationship:
		if mapping.Disposition != CloudSourceMapsExactRelationshipFact || target.ValueType != "semantic_reference" || source.Cardinality != target.Cardinality {
			return fmt.Errorf("relationship mapping %q is incompatible with neutral field %q", source.ID, target.ID)
		}
	case CloudMappingProjectionGiBToBytes:
		if mapping.UnitEvidenceRef == "" {
			return fmt.Errorf("binary_gib_to_bytes mapping %q lacks unit evidence", source.ID)
		}
		if source.ValueType != "unsigned_integer" || source.Cardinality != "one" || mapping.SourceUnit != "gib" || target.ValueType != "unsigned_integer" || target.Cardinality != "one" || target.Unit != "bytes" {
			return fmt.Errorf("binary_gib_to_bytes mapping %q is incompatible", source.ID)
		}
	case CloudMappingProjectionCheckedPositiveIntegerGiBToBytes:
		if mapping.UnitEvidenceRef == "" {
			return fmt.Errorf("checked_positive_integer_gib_to_bytes mapping %q lacks unit evidence", source.ID)
		}
		if (source.ValueType != "signed_integer" && source.ValueType != "integer_string") || source.Cardinality != "one" || mapping.SourceUnit != "gib" || target.ValueType != "unsigned_integer" || target.Cardinality != "one" || target.Unit != "bytes" {
			return fmt.Errorf("checked_positive_integer_gib_to_bytes mapping %q is incompatible", source.ID)
		}
	case CloudMappingProjectionBoundedZeroOrOneRelationship:
		if mapping.Disposition != CloudSourceMapsExactRelationshipFact || source.ValueType != "string" || source.Cardinality != "many" || target.ValueType != "semantic_reference" || target.Cardinality != "one" {
			return fmt.Errorf("bounded_zero_or_one_relationship_reference mapping %q is incompatible", source.ID)
		}
	case CloudMappingProjectionManyRelationship:
		if mapping.Disposition != CloudSourceMapsExactRelationshipFact || source.ValueType != "string" || source.Cardinality != "many" || target.ValueType != "semantic_reference" || target.Cardinality != "many" {
			return fmt.Errorf("many relationship mapping %q is incompatible", source.ID)
		}
	case CloudMappingProjectionExactRFC3339:
		if mapping.Disposition != CloudSourceMapsExactSourceFact || source.ValueType != "string" || source.Cardinality != "one" || target.ValueType != "string" || target.Cardinality != "one" || len(target.AllowedValues) != 0 || target.Unit != "" {
			return fmt.Errorf("exact timestamp mapping %q changes type or cardinality", source.ID)
		}
	case CloudMappingProjectionEvidenceClosedScalar, CloudMappingProjectionBoundedOneEvidenceScalar, CloudMappingProjectionPresentPrivateLeaf:
		if err := validateCloudEvidenceValueRecipe(mapping, source, target); err != nil {
			return err
		}
	default:
		return fmt.Errorf("source field %q uses unknown projection %q", source.ID, mapping.Projection)
	}
	return nil
}

func validateCloudLifecycleRecipe(mapping CloudMappingContractField, source cloudResolvedField, target CloudNeutralFieldSchema) error {
	recipe := mapping.LifecycleRecipe
	if recipe == nil || recipe.UnknownValuePolicy != "refuse" || len(recipe.EvidenceRefs) == 0 || len(recipe.SourceToNeutral) == 0 {
		return fmt.Errorf("requires evidence-bound complete enum recipe with unknown refusal")
	}
	seenEvidence := map[string]struct{}{}
	for _, ref := range recipe.EvidenceRefs {
		if ref == "" {
			return fmt.Errorf("empty evidence ref")
		}
		if _, duplicate := seenEvidence[ref]; duplicate {
			return fmt.Errorf("duplicate evidence ref")
		}
		seenEvidence[ref] = struct{}{}
	}
	for sourceValue, neutralValue := range recipe.SourceToNeutral {
		if sourceValue == "" || neutralValue == "" {
			return fmt.Errorf("empty enum translation")
		}
		if len(target.AllowedValues) == 0 {
			return fmt.Errorf("target has no resolved closed enum")
		}
		found := false
		for _, candidate := range target.AllowedValues {
			if candidate == neutralValue {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("neutral enum value %q is outside closed target", neutralValue)
		}
	}
	unsupported := map[string]struct{}{}
	for _, value := range recipe.UnsupportedSourceValues {
		if value == "" {
			return fmt.Errorf("empty unsupported source value")
		}
		if _, duplicate := unsupported[value]; duplicate {
			return fmt.Errorf("duplicate unsupported source value")
		}
		unsupported[value] = struct{}{}
	}
	for _, value := range source.KnownEnumValues {
		if _, mapped := recipe.SourceToNeutral[value]; !mapped {
			if _, declared := unsupported[value]; !declared {
				return fmt.Errorf("documented source enum value %q lacks mapping or explicit unsupported disposition", value)
			}
		}
	}
	for value := range unsupported {
		found := false
		for _, known := range source.KnownEnumValues {
			if value == known {
				found = true
			}
		}
		if len(source.KnownEnumValues) > 0 && !found {
			return fmt.Errorf("unsupported source value %q is not documented", value)
		}
	}
	return nil
}

func cloudCatalogObjectFields(catalog CloudCatalog, id string) (map[string]cloudResolvedField, error) {
	shape, ok := cloudCatalogShape(catalog, id)
	if !ok {
		return nil, fmt.Errorf("object schema %q is absent", id)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(shape.RawJSON, &raw); err != nil {
		return nil, fmt.Errorf("object schema %q: %w", id, err)
	}
	if members, ok := raw["members"]; ok {
		return cloudSmithyObjectFields(catalog, members)
	}
	if properties, ok := raw["properties"]; ok {
		return cloudDiscoveryObjectFields(properties)
	}
	return nil, fmt.Errorf("object schema %q has unsupported shape form", id)
}

func cloudCatalogShape(catalog CloudCatalog, id string) (CloudCatalogSchemaShape, bool) {
	for _, shape := range catalog.SchemaShapes {
		if shape.ID == id {
			return shape, true
		}
	}
	return CloudCatalogSchemaShape{}, false
}

func cloudSmithyObjectFields(catalog CloudCatalog, members json.RawMessage) (map[string]cloudResolvedField, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(members, &values); err != nil {
		return nil, err
	}
	result := map[string]cloudResolvedField{}
	for _, name := range sortedCloudCatalogKeys(values) {
		var member struct {
			Target   string                     `json:"target"`
			Nullable bool                       `json:"nullable"`
			Traits   map[string]json.RawMessage `json:"traits"`
		}
		if err := json.Unmarshal(values[name], &member); err != nil || member.Target == "" {
			return nil, fmt.Errorf("Smithy member %q has no target", name)
		}
		target, ok := cloudCatalogShape(catalog, member.Target)
		if !ok {
			return nil, fmt.Errorf("Smithy member %q target %q is not retained", name, member.Target)
		}
		valueType, cardinality, err := cloudShapeType(target)
		if err != nil {
			return nil, fmt.Errorf("Smithy member %q: %w", name, err)
		}
		pointer := "/" + cloudCatalogEscapePointer(name)
		result[pointer] = cloudResolvedField{ID: name, Pointer: pointer, WirePointer: "/" + cloudCatalogEscapePointer(cloudSmithyWireMemberName(name, member.Traits)), ValueType: valueType, Cardinality: cardinality, Nullable: member.Nullable, ShapeID: member.Target, KnownEnumValues: cloudSmithyEnumValues(target.RawJSON)}
	}
	return result, nil
}

func cloudSmithyEnumValues(raw json.RawMessage) []string {
	object, err := rawObject(raw)
	if err != nil {
		return nil
	}
	members, ok := object["members"]
	if !ok {
		return nil
	}
	entries, err := rawObject(members)
	if err != nil {
		return nil
	}
	values := []string{}
	for name, rawMember := range entries {
		member, e := rawObject(rawMember)
		if e != nil {
			return nil
		}
		traits, e := rawObject(member["traits"])
		if e != nil {
			return nil
		}
		var value string
		if json.Unmarshal(traits["smithy.api#enumValue"], &value) != nil || value == "" {
			value = name
		}
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func cloudDiscoveryEnumValues(raw json.RawMessage) []string {
	object, err := rawObject(raw)
	if err != nil {
		return nil
	}
	var values []string
	if json.Unmarshal(object["enum"], &values) != nil {
		return nil
	}
	sort.Strings(values)
	return values
}

func cloudDiscoveryObjectFields(properties json.RawMessage) (map[string]cloudResolvedField, error) {
	var values map[string]json.RawMessage
	if err := json.Unmarshal(properties, &values); err != nil {
		return nil, err
	}
	result := map[string]cloudResolvedField{}
	for _, name := range sortedCloudCatalogKeys(values) {
		var property struct {
			Type                 string          `json:"type"`
			Format               string          `json:"format"`
			Nullable             bool            `json:"nullable"`
			Items                json.RawMessage `json:"items"`
			AdditionalProperties json.RawMessage `json:"additionalProperties"`
			Ref                  string          `json:"$ref"`
		}
		if err := json.Unmarshal(values[name], &property); err != nil {
			return nil, err
		}
		valueType, cardinality := "", ""
		var err error
		if property.Ref != "" || len(property.AdditionalProperties) != 0 || property.Type == "object" {
			// Preserve the direct field in the closure so it must be explicitly
			// private/unsupported; a future bounded nested projection may add it.
			valueType, cardinality = "opaque_complex", "one"
		} else {
			valueType, cardinality, err = cloudDiscoveryType(property.Type, property.Format, property.Items)
		}
		if err != nil {
			return nil, fmt.Errorf("Discovery property %q: %w", name, err)
		}
		shapeID := property.Ref
		if shapeID == "" && property.Type == "array" {
			var item struct {
				Ref string `json:"$ref"`
			}
			_ = json.Unmarshal(property.Items, &item)
			shapeID = item.Ref
		}
		pointer := "/" + cloudCatalogEscapePointer(name)
		result[pointer] = cloudResolvedField{ID: name, Pointer: pointer, WirePointer: pointer, ValueType: valueType, Cardinality: cardinality, Nullable: property.Nullable, ShapeID: shapeID, InlineSchema: bytes.Clone(values[name]), KnownEnumValues: cloudDiscoveryEnumValues(values[name])}
	}
	return result, nil
}

func cloudShapeType(shape CloudCatalogSchemaShape) (string, string, error) {
	var raw struct {
		Type   string          `json:"type"`
		Member json.RawMessage `json:"member"`
	}
	if err := json.Unmarshal(shape.RawJSON, &raw); err != nil {
		return "", "", err
	}
	if raw.Type == "list" {
		return "opaque_list", "many", nil
	}
	if raw.Type == "structure" || raw.Type == "map" {
		return "opaque_complex", "one", nil
	}
	return cloudScalarType(raw.Type)
}

func cloudDiscoveryType(kind, format string, items json.RawMessage) (string, string, error) {
	if kind == "array" {
		if len(items) == 0 {
			return "", "", fmt.Errorf("array lacks items")
		}
		return "opaque_list", "many", nil
	}
	return cloudScalarType(strings.TrimSpace(kind + ":" + format))
}

func cloudScalarType(kind string) (string, string, error) {
	switch kind {
	case "string", "string:", "string:date-time", "timestamp", "timestamp:", "enum", "enum:":
		return "string", "one", nil
	case "integer:uint64":
		return "unsigned_integer", "one", nil
	case "integer", "long", "integer:int64", "intEnum", "intEnum:":
		// The retained model did not prove a non-negative range. A capacity or
		// identity mapping must never silently reinterpret signed integers.
		return "signed_integer", "one", nil
	case "string:int64":
		return "integer_string", "one", nil
	case "boolean", "boolean:":
		return "boolean", "one", nil
	default:
		return "opaque_scalar", "one", nil
	}
}

func validCloudCardinality(value string) bool { return value == "one" || value == "many" }
func sortedUniqueCloudValues(values []string) bool {
	return sort.StringsAreSorted(values) && len(values) == len(uniqueCloudCatalogStrings(append([]string(nil), values...)))
}
