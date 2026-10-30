package providerplan

// This file is an offline conformance oracle.  It turns only fixture-bound
// response objects into owner-valid neutral candidates; it neither allocates
// an OHM identity nor writes a source/OHM store.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// CloudNeutralScopedBinding is deliberately explicit: native scoped keys are
// lookup inputs, never a way to derive a neutral identity (and are never
// emitted as a relationship value).
type CloudNeutralScopedBinding struct {
	ScopeReference  string `json:"scope_reference"`
	ScopedNativeKey string `json:"scoped_native_key"`
	OpaqueNeutralID string `json:"opaque_neutral_id"`
}
type cloudNeutralBindingKey struct{ scope, native string }

// CloudNeutralProjectionRecipe is provider-data, not provider behaviour in
// Go. ObjectPointer selects response object(s); all source fields and their
// disposition remain exclusively in the validated mapping contract.
type CloudNeutralProjectionRecipe struct {
	Catalog               CloudCatalog                `json:"-"`
	Target                *CloudSourceObjectTarget    `json:"-"`
	Contract              CloudMappingContract        `json:"-"`
	ObjectPointer         string                      `json:"object_pointer"`
	IdentitySourcePointer string                      `json:"identity_source_pointer"`
	IdentitySourceFieldID string                      `json:"identity_source_field_id"`
	ScopeReference        string                      `json:"scope_reference"`
	ObservationState      string                      `json:"observation_state"`
	Coverage              CloudSyntheticCoverage      `json:"coverage"`
	ContinuationPointer   string                      `json:"continuation_pointer,omitempty"`
	RecordTemplate        map[string]any              `json:"record_template"`
	RelationshipKeyFields map[string]string           `json:"relationship_key_fields,omitempty"`
	Bindings              []CloudNeutralScopedBinding `json:"bindings"`
}

// CloudNeutralProjectionResult deliberately has no deletion operation. A
// continuation or partial coverage remains evidence of incompleteness only.
type CloudNeutralProjectionResult struct {
	Coverage           CloudSyntheticCoverage `json:"coverage"`
	Continuation       string                 `json:"continuation,omitempty"`
	Records            [][]byte               `json:"records"`
	DeletionAuthorized bool                   `json:"deletion_authorized"`
}

// ProjectCloudNeutralRecords evaluates a bounded declarative recipe. The
// caller supplies a fixture template for non-observed/unavailable facts; the
// template must itself be owner-valid after the contract fields are applied.
func ProjectCloudNeutralRecords(recipe CloudNeutralProjectionRecipe, raw []byte) ([][]byte, error) {
	result, err := ProjectCloudNeutralResponse(recipe, raw)
	if err != nil {
		return nil, err
	}
	return result.Records, nil
}

func ProjectCloudNeutralResponse(recipe CloudNeutralProjectionRecipe, raw []byte) (CloudNeutralProjectionResult, error) {
	if err := validateCloudNeutralProjectionRecipe(recipe); err != nil {
		return CloudNeutralProjectionResult{}, err
	}
	root, err := decodeCloudSyntheticProtocol(raw)
	if err != nil {
		return CloudNeutralProjectionResult{}, err
	}
	selected, state, err := cloudNeutralSelect(root, recipe.ObjectPointer)
	if err != nil {
		return CloudNeutralProjectionResult{}, fmt.Errorf("select response objects: %w", err)
	}
	if state != "present" {
		return CloudNeutralProjectionResult{}, fmt.Errorf("selected response objects are %s", state)
	}
	objects, err := cloudNeutralObjects(selected)
	if err != nil {
		return CloudNeutralProjectionResult{}, err
	}
	bindings, err := cloudNeutralBindingIndex(recipe.Bindings)
	if err != nil {
		return CloudNeutralProjectionResult{}, err
	}
	result := make([][]byte, 0, len(objects))
	for index, object := range objects {
		record, projectErr := projectCloudNeutralObject(recipe, object, bindings, bytes.HasPrefix(bytes.TrimSpace(raw), []byte("<")))
		if projectErr != nil {
			return CloudNeutralProjectionResult{}, fmt.Errorf("selected object %d: %w", index, projectErr)
		}
		result = append(result, record)
	}
	continuation := ""
	if recipe.ContinuationPointer != "" {
		value, status, pointerErr := resolveCloudSyntheticPointer(root, recipe.ContinuationPointer)
		if pointerErr != nil || status == "null" {
			return CloudNeutralProjectionResult{}, fmt.Errorf("continuation evidence is malformed")
		}
		if status == "present" {
			var ok bool
			continuation, ok = value.(string)
			if !ok || continuation == "" {
				return CloudNeutralProjectionResult{}, fmt.Errorf("continuation evidence is not a nonempty string")
			}
		}
	}
	if recipe.Coverage == CloudSyntheticCoverageComplete && continuation != "" {
		return CloudNeutralProjectionResult{}, fmt.Errorf("complete coverage cannot carry continuation evidence")
	}
	return CloudNeutralProjectionResult{Coverage: recipe.Coverage, Continuation: continuation, Records: result, DeletionAuthorized: false}, nil
}

func cloudNeutralSelect(root any, pointer string) (any, string, error) {
	if pointer == "/" {
		return root, "present", nil
	}
	return resolveCloudNeutralProjectionPointer(root, pointer)
}

func validateCloudNeutralProjectionRecipe(recipe CloudNeutralProjectionRecipe) error {
	if recipe.ObjectPointer == "" || recipe.IdentitySourcePointer == "" || recipe.IdentitySourceFieldID == "" || recipe.ScopeReference == "" || recipe.RecordTemplate == nil {
		return fmt.Errorf("object pointer, identity selector, scope reference, and record template are required")
	}
	switch recipe.ObservationState {
	case "observed", "incomplete", "inaccessible", "redacted", "unsupported":
	default:
		return fmt.Errorf("observation state must be an owner-defined enum")
	}
	if recipe.Coverage != CloudSyntheticCoveragePartial && recipe.Coverage != CloudSyntheticCoverageComplete {
		return fmt.Errorf("coverage must be partial_page or complete_scope")
	}
	if err := ValidateCloudMappingContract(recipe.Catalog, recipe.Contract); err != nil {
		return fmt.Errorf("mapping contract: %w", err)
	}
	identityField, found := cloudNeutralContractField(recipe.Contract, recipe.IdentitySourceFieldID)
	if !found || identityField.SourcePointer != recipe.IdentitySourcePointer || (identityField.Disposition != CloudSourcePrivateOnly && identityField.TargetField != "display_name") {
		return fmt.Errorf("identity selector must be a validated private field or the mapped display-name scoped key")
	}
	if recipe.Target == nil {
		return fmt.Errorf("projection requires a target-bound documented identity selector")
	}
	if recipe.Target.MappingContract == nil || !reflect.DeepEqual(*recipe.Target.MappingContract, recipe.Contract) {
		return fmt.Errorf("projection target does not bind this mapping contract")
	}
	matched := false
	for _, id := range recipe.Target.StableIdentitySourceFields {
		if id == recipe.IdentitySourceFieldID {
			matched = true
		}
	}
	if !matched {
		return fmt.Errorf("identity selector is not target-documented")
	}
	if err := ValidateCloudSourceIdentityContract(*recipe.Target, recipe.Catalog); err != nil {
		return fmt.Errorf("target identity evidence: %w", err)
	}
	if recipe.Contract.Neutral.ClassSymbol == "" || recipe.RecordTemplate["record_class"] != recipe.Contract.Neutral.ClassSymbol {
		return fmt.Errorf("record template class must equal loaded mapping-contract neutral class")
	}
	for name, value := range recipe.RecordTemplate {
		if name == "record_class" || name == "semantic_record_instance_identity" || name == "scope_reference" || name == "observation_state" {
			continue
		}
		if envelope, ok := value.(map[string]any); ok && envelope["state"] == "present" {
			return fmt.Errorf("record template field %q cannot assert an affirmative source fact", name)
		}
	}
	for fieldID, pointer := range recipe.RelationshipKeyFields {
		field, ok := cloudNeutralContractField(recipe.Contract, fieldID)
		if !ok || field.Disposition != CloudSourceMapsExactRelationshipFact || pointer == "" {
			return fmt.Errorf("relationship recipe field %q is not a relationship contract field", fieldID)
		}
	}
	return nil
}

func cloudNeutralObjects(value any) ([]map[string]any, error) {
	if one, ok := value.(map[string]any); ok {
		return []map[string]any{one}, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("selected response value must be one object or an object array")
	}
	result := make([]map[string]any, len(list))
	for i, item := range list {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("selected response item %d is not an object", i)
		}
		result[i] = object
	}
	return result, nil
}

func cloudNeutralBindingIndex(bindings []CloudNeutralScopedBinding) (map[cloudNeutralBindingKey]string, error) {
	result := make(map[cloudNeutralBindingKey]string, len(bindings))
	for _, binding := range bindings {
		if strings.TrimSpace(binding.ScopeReference) == "" || strings.TrimSpace(binding.ScopedNativeKey) == "" || strings.TrimSpace(binding.OpaqueNeutralID) == "" {
			return nil, fmt.Errorf("scoped fixture binding is incomplete")
		}
		key := cloudNeutralBindingKey{binding.ScopeReference, binding.ScopedNativeKey}
		if _, duplicate := result[key]; duplicate {
			return nil, fmt.Errorf("ambiguous scoped fixture binding")
		}
		result[key] = binding.OpaqueNeutralID
	}
	return result, nil
}

func projectCloudNeutralObject(recipe CloudNeutralProjectionRecipe, object map[string]any, bindings map[cloudNeutralBindingKey]string, xmlWire bool) ([]byte, error) {
	direct, err := cloudCatalogObjectFields(recipe.Catalog, recipe.Contract.ObjectSchemaID)
	if err != nil {
		return nil, err
	}
	identityPointer := recipe.IdentitySourcePointer
	if xmlWire {
		identityPointer = direct[identityPointer].WirePointer
	}
	identityValue, identityState, err := resolveCloudSyntheticPointer(object, identityPointer)
	if err != nil || identityState != "present" {
		return nil, fmt.Errorf("identity source key is %s", identityState)
	}
	identityKey, ok := identityValue.(string)
	if !ok || identityKey == "" {
		return nil, fmt.Errorf("identity source key is not a nonempty string")
	}
	identity, ok := bindings[cloudNeutralBindingKey{recipe.ScopeReference, identityKey}]
	if !ok {
		return nil, fmt.Errorf("identity source key has no scoped fixture binding")
	}
	template, err := canonicalFactoryJSON(recipe.RecordTemplate)
	if err != nil {
		return nil, err
	}
	var record map[string]any
	if err = json.Unmarshal(template, &record); err != nil {
		return nil, err
	}
	record["semantic_record_instance_identity"] = identity
	// The opaque scope is a fixture binding input, not a provider value.  Set
	// it here so relationship lookup and emitted record cannot silently use
	// different scopes.
	record["scope_reference"] = map[string]any{"state": "present", "value": recipe.ScopeReference}
	record["observation_state"] = recipe.ObservationState
	for _, field := range cloudNeutralProjectionFields(recipe.Contract) {
		if field.Disposition != CloudSourceMapsExactSourceFact && field.Disposition != CloudSourceMapsExactRelationshipFact && field.Disposition != CloudSourceMapsExactLifecycleFact {
			continue
		}
		pointer := field.SourcePointer
		if xmlWire {
			if field.WirePointer != "" {
				pointer = field.WirePointer
			} else if retained, ok := direct[field.SourcePointer]; ok {
				pointer = retained.WirePointer
			}
		}
		value, state, fieldErr := resolveCloudNeutralProjectionPointer(object, pointer)
		// Only an explicitly empty XML list wrapper proves zero members.
		if xmlWire && field.Projection == CloudMappingProjectionBoundedZeroOrOneRelationship && state != "present" {
			if at := strings.LastIndex(pointer, "/item/"); at >= 0 {
				parent, parentState, parentErr := resolveCloudSyntheticPointer(object, pointer[:at])
				if empty, ok := parent.(string); ok && empty == "" && parentErr == nil && parentState == "present" {
					value, state, fieldErr = []any{}, "present", nil
				}
			}
		}
		if fieldErr != nil {
			return nil, fmt.Errorf("field %q: %w", field.SourceFieldID, fieldErr)
		}
		if state == "absent" {
			return nil, fmt.Errorf("field %q is absent; recipe cannot retain a template value", field.SourceFieldID)
		}
		if state == "null" {
			if err := cloudNeutralApplyNull(record, field); err != nil {
				return nil, fmt.Errorf("field %q: %w", field.SourceFieldID, err)
			}
			continue
		}
		if field.Disposition == CloudSourceMapsExactRelationshipFact {
			if field.Projection == CloudMappingProjectionBoundedZeroOrOneRelationship {
				values, boundedErr := cloudNeutralZeroOrOneRelationship(value)
				if boundedErr != nil {
					return nil, boundedErr
				}
				if len(values) == 0 {
					record[field.TargetField] = map[string]any{"state": "null"}
					continue
				}
				value = values[0]
			}
			key, ok := value.(string)
			if !ok || key == "" {
				return nil, fmt.Errorf("relationship is not a nonempty native key")
			}
			ref, found := bindings[cloudNeutralBindingKey{recipe.ScopeReference, key}]
			if !found {
				return nil, fmt.Errorf("relationship has no scoped fixture binding")
			}
			record[field.TargetField] = map[string]any{"state": "present", "value": ref}
			continue
		}
		if field.Disposition == CloudSourceMapsExactLifecycleFact {
			source, ok := value.(string)
			if !ok {
				return nil, fmt.Errorf("lifecycle is not a string")
			}
			if field.LifecycleRecipe == nil {
				return nil, fmt.Errorf("lifecycle has no contract-bound enum recipe")
			}
			neutral, found := field.LifecycleRecipe.SourceToNeutral[source]
			if !found {
				return nil, fmt.Errorf("lifecycle value %q has no explicit recipe enum", source)
			}
			record[field.TargetField] = map[string]any{"state": "present", "value": neutral}
			continue
		}
		if field.Projection == CloudMappingProjectionCheckedPositiveIntegerGiBToBytes || field.Projection == CloudMappingProjectionGiBToBytes {
			bytes, convertErr := cloudCheckedPositiveGiBToBytes(value)
			if convertErr != nil {
				return nil, convertErr
			}
			record[field.TargetField] = map[string]any{"state": "present", "value": bytes, "unit": "bytes"}
		} else {
			record[field.TargetField] = map[string]any{"state": "present", "value": value}
		}
	}
	encoded, err := canonicalFactoryJSON(record)
	if err != nil {
		return nil, err
	}
	if err = ValidateCloudNeutralRecordValue(recipe.Contract.Neutral, encoded); err != nil {
		return nil, fmt.Errorf("owner-valid neutral record: %w", err)
	}
	return encoded, nil
}

func cloudNeutralProjectionFields(contract CloudMappingContract) []CloudMappingContractField {
	result := append([]CloudMappingContractField(nil), contract.Fields...)
	for _, nested := range contract.Nested {
		result = append(result, nested.Fields...)
	}
	return result
}

func resolveCloudNeutralProjectionPointer(root any, pointer string) (any, string, error) {
	if pointer == "" || !strings.HasPrefix(pointer, "/") {
		return nil, "", fmt.Errorf("invalid projection pointer")
	}
	parts := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	var walk func(any, int) (any, string, error)
	walk = func(value any, at int) (any, string, error) {
		if at == len(parts) {
			if value == nil {
				return nil, "null", nil
			}
			return value, "present", nil
		}
		collect := func(list []any, next int) (any, string, error) {
			out := []any{}
			present := len(list) == 0
			for _, item := range list {
				v, state, err := walk(item, next)
				if err != nil {
					return nil, "", err
				}
				if state == "absent" {
					continue
				}
				if state == "null" {
					return nil, "", fmt.Errorf("null member in selected collection")
				}
				present = true
				if nested, ok := v.([]any); ok {
					out = append(out, nested...)
				} else {
					out = append(out, v)
				}
			}
			if !present {
				return nil, "absent", nil
			}
			return out, "present", nil
		}
		if parts[at] == "*" {
			switch typed := value.(type) {
			case []any:
				return collect(typed, at+1)
			case map[string]any:
				keys := make([]string, 0, len(typed))
				for k := range typed {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				list := make([]any, 0, len(keys))
				for _, k := range keys {
					list = append(list, typed[k])
				}
				return collect(list, at+1)
			default:
				return nil, "", fmt.Errorf("wildcard descends through non-collection")
			}
		}
		// XML repeated elements are arrays; singleton elements are objects.
		if list, ok := value.([]any); ok {
			if _, err := strconv.Atoi(parts[at]); err != nil {
				return collect(list, at)
			}
		}
		v, state, err := resolveCloudSyntheticPointer(value, "/"+parts[at])
		if err != nil || state != "present" {
			return v, state, err
		}
		return walk(v, at+1)
	}
	return walk(root, 0)
}
func cloudNeutralZeroOrOneRelationship(value any) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	if scalar, ok := value.(string); ok {
		if scalar == "" {
			return nil, fmt.Errorf("relationship is an empty native key")
		}
		return []string{scalar}, nil
	}
	list, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("bounded relationship is not a string or array")
	}
	if len(list) > 1 {
		return nil, fmt.Errorf("bounded relationship has more than one attachment")
	}
	if len(list) == 0 {
		return nil, nil
	}
	key, ok := list[0].(string)
	if !ok || key == "" {
		return nil, fmt.Errorf("bounded relationship has invalid attachment")
	}
	return []string{key}, nil
}

func cloudNeutralApplyNull(record map[string]any, field CloudMappingContractField) error {
	switch field.ExplicitNullDisposition {
	case CloudExplicitNullToNeutralNull:
		record[field.TargetField] = map[string]any{"state": "null"}
	case CloudExplicitNullToAbsent:
		record[field.TargetField] = map[string]any{"state": "absent"}
	case CloudExplicitNullToUnknown:
		record[field.TargetField] = map[string]any{"state": "unknown"}
	case CloudExplicitNullToPrivate:
		return fmt.Errorf("private source field cannot be materialized")
	default:
		return fmt.Errorf("unknown null disposition")
	}
	return nil
}

func cloudNeutralContractField(contract CloudMappingContract, id string) (CloudMappingContractField, bool) {
	for _, field := range contract.Fields {
		if field.SourceFieldID == id {
			return field, true
		}
	}
	return CloudMappingContractField{}, false
}
