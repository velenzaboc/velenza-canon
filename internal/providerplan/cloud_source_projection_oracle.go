package providerplan

// The projection oracle evaluates only declared mapping recipes against
// synthetic response bytes. It is an offline conformance aid, not OHM and not
// a persistent state/deletion engine.

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

type CloudSyntheticCoverage string

const (
	CloudSyntheticCoveragePartial  CloudSyntheticCoverage = "partial_page"
	CloudSyntheticCoverageComplete CloudSyntheticCoverage = "complete_scope"
)

type CloudSyntheticProjectedField struct {
	SourceFieldID string          `json:"source_field_id"`
	State         string          `json:"state"`
	Value         json.RawMessage `json:"value,omitempty"`
}

type CloudSyntheticProjectionResult struct {
	Coverage           CloudSyntheticCoverage         `json:"coverage"`
	Fields             []CloudSyntheticProjectedField `json:"fields"`
	DeletionAuthorized bool                           `json:"deletion_authorized"`
}

func ProjectCloudSyntheticResponse(target CloudSourceObjectTarget, raw []byte, coverage CloudSyntheticCoverage) (CloudSyntheticProjectionResult, error) {
	if coverage != CloudSyntheticCoveragePartial && coverage != CloudSyntheticCoverageComplete {
		return CloudSyntheticProjectionResult{}, fmt.Errorf("unknown synthetic coverage %q", coverage)
	}
	root, err := decodeCloudSyntheticProtocol(raw)
	if err != nil {
		return CloudSyntheticProjectionResult{}, err
	}
	mappings := append([]CloudSourceFieldMapping(nil), target.FieldMappings...)
	sort.Slice(mappings, func(i, j int) bool { return mappings[i].SourceFieldID < mappings[j].SourceFieldID })
	result := CloudSyntheticProjectionResult{Coverage: coverage, Fields: make([]CloudSyntheticProjectedField, 0, len(mappings)), DeletionAuthorized: false}
	for _, mapping := range mappings {
		field := CloudSyntheticProjectedField{SourceFieldID: mapping.SourceFieldID}
		if mapping.Disposition == CloudSourceUnknown {
			result.Fields = append(result.Fields, CloudSyntheticProjectedField{SourceFieldID: mapping.SourceFieldID, State: "unknown"})
			continue
		}
		if mapping.Disposition != CloudSourceMapsExactSourceFact && mapping.Disposition != CloudSourceMapsExactRelationshipFact && mapping.Disposition != CloudSourceMapsExactLifecycleFact {
			continue
		}
		value, state, err := resolveCloudSyntheticPointer(root, mapping.SourcePointer)
		if err != nil {
			return CloudSyntheticProjectionResult{}, fmt.Errorf("field %q: %w", mapping.SourceFieldID, err)
		}
		field.State = state
		if state == "present" {
			if mapping.Projection == CloudMappingProjection("checked_positive_integer_gib_to_bytes") {
				value, err = cloudCheckedPositiveGiBToBytes(value)
				if err != nil {
					return CloudSyntheticProjectionResult{}, fmt.Errorf("field %q: %w", mapping.SourceFieldID, err)
				}
			}
			encoded, encodeErr := canonicalFactoryJSON(value)
			if encodeErr != nil {
				return CloudSyntheticProjectionResult{}, encodeErr
			}
			field.State = "present"
			field.Value = encoded
		}
		result.Fields = append(result.Fields, field)
	}
	return result, nil
}

func cloudCheckedPositiveGiBToBytes(value any) (string, error) {
	var decimal string
	switch typed := value.(type) {
	case json.Number:
		decimal = typed.String()
	case string:
		decimal = typed
	default:
		return "", fmt.Errorf("checked_positive_integer_gib_to_bytes requires an integer string or JSON integer")
	}
	if decimal == "" || strings.HasPrefix(decimal, "+") || strings.ContainsAny(decimal, ".-eE") {
		return "", fmt.Errorf("checked_positive_integer_gib_to_bytes requires a positive decimal integer")
	}
	parsed, err := strconv.ParseUint(decimal, 10, 64)
	if err != nil || parsed == 0 {
		return "", fmt.Errorf("checked_positive_integer_gib_to_bytes refuses non-positive or overflowing value")
	}
	if parsed > math.MaxUint64/(1024*1024*1024) {
		return "", fmt.Errorf("checked_positive_integer_gib_to_bytes multiplication overflows uint64")
	}
	return strconv.FormatUint(parsed*1024*1024*1024, 10), nil
}

func decodeCloudSyntheticProtocol(raw []byte) (any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("synthetic response is empty")
	}
	if trimmed[0] == '<' {
		return decodeCloudSyntheticXML(trimmed)
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return nil, fmt.Errorf("decode synthetic JSON response: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("synthetic JSON response has trailing value")
		}
		return nil, fmt.Errorf("synthetic JSON trailing data: %w", err)
	}
	return root, nil
}

type cloudSyntheticXMLNode struct {
	name     string
	text     string
	children []*cloudSyntheticXMLNode
}

func decodeCloudSyntheticXML(raw []byte) (any, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var stack []*cloudSyntheticXMLNode
	var root *cloudSyntheticXMLNode
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode synthetic XML response: %w", err)
		}
		switch item := token.(type) {
		case xml.StartElement:
			node := &cloudSyntheticXMLNode{name: item.Name.Local}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("synthetic XML has multiple roots")
				}
				root = node
			} else {
				parent := stack[len(stack)-1]
				parent.children = append(parent.children, node)
			}
			stack = append(stack, node)
		case xml.CharData:
			if len(stack) != 0 {
				stack[len(stack)-1].text += string(item)
			}
		case xml.EndElement:
			if len(stack) == 0 || stack[len(stack)-1].name != item.Name.Local {
				return nil, fmt.Errorf("synthetic XML nesting is invalid")
			}
			stack = stack[:len(stack)-1]
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, fmt.Errorf("synthetic XML has no complete root")
	}
	return map[string]any{root.name: cloudSyntheticXMLValue(root)}, nil
}
func cloudSyntheticXMLValue(node *cloudSyntheticXMLNode) any {
	if len(node.children) == 0 {
		return node.text
	}
	result := map[string]any{}
	for _, child := range node.children {
		value := cloudSyntheticXMLValue(child)
		if prior, ok := result[child.name]; !ok {
			result[child.name] = value
		} else if list, ok := prior.([]any); ok {
			result[child.name] = append(list, value)
		} else {
			result[child.name] = []any{prior, value}
		}
	}
	return result
}
func resolveCloudSyntheticPointer(root any, pointer string) (any, string, error) {
	if pointer == "" || !strings.HasPrefix(pointer, "/") {
		return nil, "", fmt.Errorf("pointer %q is not absolute", pointer)
	}
	value := root
	for _, encoded := range strings.Split(pointer[1:], "/") {
		remainder := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", ""), "~0", "")
		if strings.Contains(remainder, "~") {
			return nil, "", fmt.Errorf("pointer %q has invalid escape", pointer)
		}
		part := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch typed := value.(type) {
		case map[string]any:
			next, ok := typed[part]
			if !ok {
				return nil, "absent", nil
			}
			value = next
		case []any:
			var index int
			if _, err := fmt.Sscanf(part, "%d", &index); err != nil || fmt.Sprintf("%d", index) != part || index < 0 {
				return nil, "", fmt.Errorf("pointer %q has invalid array index", pointer)
			}
			if index >= len(typed) {
				return nil, "absent", nil
			}
			value = typed[index]
		default:
			return nil, "", fmt.Errorf("pointer %q descends through scalar", pointer)
		}
	}
	if value == nil {
		return nil, "null", nil
	}
	return value, "present", nil
}
