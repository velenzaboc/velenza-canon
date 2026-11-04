package providerplan

// Candidate field derivation is intentionally limited to producing an
// executable program.  Selection authority is supplied separately at
// execution time; a catalog cannot select or classify itself.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

type CloudFieldDerivationCandidate struct {
	Reference          dependencyProfileReference
	Program            exactDocumentationDerivationProgram
	SourceSymbol       string
	FieldPointer       string
	FieldLocator       CloudCatalogEvidenceLocator
	SourceFieldID      string
	ProviderType       string
	SourceCardinality  string
	NumericDisposition map[string]interface{}
}

// CloudFieldDerivationRoster preserves every requested source field. A caller
// must treat Unresolved as a fail-closed gap; it is never a license to omit a
// field from a later source-contract artifact.
type CloudFieldDerivationRoster struct {
	Candidates []CloudFieldDerivationCandidate
	Unresolved map[string]string
}

type cloudFieldDerivationPreparation struct {
	catalog CloudCatalog
	target  CloudSourceObjectTarget
	model   PinnedCloudModel
	fields  map[string]cloudResolvedField
	spans   map[string]cloudCatalogByteSpan
}

// BuildCloudTargetFieldDerivationRoster creates one candidate program per
// field occurrence in a mapping target, including nested decompositions.
// Programs remain candidate inputs until a selected-classification proof is
// supplied to the existing executor.
func BuildCloudTargetFieldDerivationRoster(catalog CloudCatalog, target CloudSourceObjectTarget, model PinnedCloudModel, sourceSymbol string) (CloudFieldDerivationRoster, error) {
	return buildCloudTargetFieldDerivationRosterWithSymbol(catalog, target, model, func(string) string { return sourceSymbol })
}

// buildCloudTargetFieldDerivationRosterWithSymbol is the composition-safe
// variant used by a package that will execute all of its field recipes in one
// run.  It keeps the public single-symbol builder for narrow callers while
// giving the package an independently classified source occurrence per field.
func buildCloudTargetFieldDerivationRosterWithSymbol(catalog CloudCatalog, target CloudSourceObjectTarget, model PinnedCloudModel, sourceSymbol func(string) string) (CloudFieldDerivationRoster, error) {
	if target.MappingContract == nil {
		return CloudFieldDerivationRoster{}, fmt.Errorf("field derivation target has no mapping contract")
	}
	fields := append([]CloudMappingContractField(nil), target.MappingContract.Fields...)
	for _, nested := range target.MappingContract.Nested {
		fields = append(fields, nested.Fields...)
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].SourcePointer < fields[j].SourcePointer })
	prepared, err := prepareCloudFieldDerivation(catalog, target, model)
	if err != nil {
		return CloudFieldDerivationRoster{}, err
	}
	result := CloudFieldDerivationRoster{Candidates: make([]CloudFieldDerivationCandidate, 0, len(fields)), Unresolved: map[string]string{}}
	for _, field := range fields {
		candidate, err := buildCloudFieldDerivationCandidate(prepared, field.SourcePointer, sourceSymbol(field.SourcePointer))
		if err != nil {
			result.Unresolved[field.SourcePointer] = err.Error()
			continue
		}
		result.Candidates = append(result.Candidates, candidate)
	}
	return result, nil
}

func cloudMappingFieldSourceSymbol(targetKey, pointer string) string {
	return stableID("cloud_field_occurrence", targetKey+"\x00"+pointer)
}

// BuildCloudFieldDerivationCandidate makes one exact whole-row source-contract
// derivation rule over a field member in the retained model. It uses the model
// byte span, never a reconstructed JSON object or a textual field name.
func BuildCloudFieldDerivationCandidate(catalog CloudCatalog, target CloudSourceObjectTarget, model PinnedCloudModel, fieldPointer, sourceSymbol string) (CloudFieldDerivationCandidate, error) {
	prepared, err := prepareCloudFieldDerivation(catalog, target, model)
	if err != nil {
		return CloudFieldDerivationCandidate{}, err
	}
	return buildCloudFieldDerivationCandidate(prepared, fieldPointer, sourceSymbol)
}

func prepareCloudFieldDerivation(catalog CloudCatalog, target CloudSourceObjectTarget, model PinnedCloudModel) (cloudFieldDerivationPreparation, error) {
	if target.MappingContract == nil || model.Source.ID != catalog.Source.ID || model.ExpectedSHA256 != catalog.ModelSHA256 || sha256Hex(model.Raw) != model.ExpectedSHA256 {
		return cloudFieldDerivationPreparation{}, fmt.Errorf("field derivation requires the matching retained catalog, target, and model bytes")
	}
	parsed, err := ParsePinnedCloudModel(model)
	if err != nil || !reflect.DeepEqual(parsed, catalog) {
		return cloudFieldDerivationPreparation{}, fmt.Errorf("field derivation catalog is not the exact parser result for retained model bytes")
	}
	fields, err := cloudProjectionResolvedFields(catalog, *target.MappingContract)
	if err != nil {
		return cloudFieldDerivationPreparation{}, err
	}
	spans, err := cloudCatalogJSONPointerSpans(model.Raw)
	if err != nil {
		return cloudFieldDerivationPreparation{}, err
	}
	return cloudFieldDerivationPreparation{catalog: catalog, target: target, model: model, fields: fields, spans: spans}, nil
}

func buildCloudFieldDerivationCandidate(prepared cloudFieldDerivationPreparation, fieldPointer, sourceSymbol string) (CloudFieldDerivationCandidate, error) {
	catalog, target, model := prepared.catalog, prepared.target, prepared.model
	if sourceSymbol == "" {
		return CloudFieldDerivationCandidate{}, fmt.Errorf("field derivation source symbol is empty")
	}
	fields := prepared.fields
	field, ok := fields[fieldPointer]
	if !ok {
		return CloudFieldDerivationCandidate{}, fmt.Errorf("source field pointer %q is not in target schema", fieldPointer)
	}
	pointer, err := cloudFieldModelMemberPointer(catalog, target.MappingContract.ObjectSchemaID, field.Pointer)
	if err != nil {
		return CloudFieldDerivationCandidate{}, err
	}
	span, ok := prepared.spans[pointer]
	if !ok || span.end <= span.start {
		return CloudFieldDerivationCandidate{}, fmt.Errorf("model has no exact span for %q", pointer)
	}
	selected := model.Raw[span.start:span.end]
	var member map[string]json.RawMessage
	if err := strictUnmarshal(selected, &member); err != nil {
		return CloudFieldDerivationCandidate{}, fmt.Errorf("decode exact field member: %w", err)
	}
	description, requirement := "", "unknown"
	for _, key := range []string{"documentation", "description"} {
		if raw := member[key]; len(raw) != 0 {
			_ = json.Unmarshal(raw, &description)
			if description != "" {
				break
			}
		}
	}
	if traitsRaw := member["traits"]; len(traitsRaw) != 0 {
		var traits map[string]json.RawMessage
		if json.Unmarshal(traitsRaw, &traits) == nil {
			_ = json.Unmarshal(traits["smithy.api#documentation"], &description)
			if _, required := traits["smithy.api#required"]; required {
				requirement = "required"
			}
		}
	}
	numeric := cloudCandidateNumericDisposition(field.ValueType)
	output := map[string]interface{}{
		"cardinality": field.Cardinality, "field_display": field.ID, "field_name": field.ID,
		"line_number": int64(bytesLineNumber(model.Raw, span.start)), "numeric_disposition": numeric,
		"official_json_pointer": pointer, "provider_description": description, "provider_requirement": requirement, "provider_type": field.ValueType,
		"section_path": []string{"Pinned API model", target.MappingContract.ObjectSchemaID}, "source_neutral_target": "candidate", "source_symbol": sourceSymbol, "surface_kind": "resource",
	}
	// Whole-row rules have no selectors. Encode those rosters as empty arrays,
	// so the exact program can share a closed schema with member rules without
	// requiring a null/array type union or later rewriting its pinned bytes.
	rule := exactDocumentationDerivationRule{Ordinal: 0, RuleID: "extract_cloud_field_contract", InputSourceSymbol: sourceSymbol, TargetArtifactRole: dependencySemanticRoleSourceContract, TargetRowKind: "field_contract", TargetBindingKind: exactDocumentationTargetWholeRow, TargetRowSelector: []exactDocumentationTargetRowSelectorTemplate{}, TargetMemberIdentityJSONPointers: []string{}, Pattern: regexp.QuoteMeta(string(selected)), MaximumMatchBytes: int64(len(selected)), MinimumMatches: 1, MaximumMatches: 1, OutputFields: output, ExactOutputFieldNames: sortedSetKeys(stringMapKeysAsSet(output))}
	program := exactDocumentationDerivationProgram{ProgramKind: exactDocumentationDerivationProgramKind, InputEncoding: exactDocumentationDerivationEncodingUTF8, MaxParseBytes: int64(len(model.Raw)), MaxOutputBytesPerFact: 8192, MaxOutputFactsPerPage: 1, MaxOutputBytesPerPage: 8192, MaxOutputFactsPerRun: 1, MaxOutputBytesPerRun: 8192, MaxOutputPagesPerRun: 1, MaxMatcherEvaluationsPerInputUnit: 1, MaxMatcherEvaluationsPerRun: 1, MaxMatcherInputBytesPerInputUnit: int64(len(model.Raw)), MaxMatcherInputBytesPerRun: int64(len(model.Raw)), MaxOccurrenceOutcomesPerRun: 1, MaxCanonicalOutcomeBytesPerRun: 8192, InputSourceSymbols: []string{sourceSymbol}, OrderedRules: []exactDocumentationDerivationRule{rule}}
	raw, err := canonicalFactoryJSON(program)
	if err != nil {
		return CloudFieldDerivationCandidate{}, err
	}
	digest := sha256Hex(raw)
	// Candidate program identities are content-derived. Reusing an ID/version
	// pair for different executable bytes would look like an owner profile
	// revision even though candidate authoring has no such authority.
	reference := dependencyProfileReference{id: "cloud_field_derivation_candidate_" + digest, version: "1", digest: digest}
	exactProgram, err := parseExactDocumentationDerivationProgram(raw, reference)
	if err != nil {
		return CloudFieldDerivationCandidate{}, err
	}
	return CloudFieldDerivationCandidate{Reference: reference, Program: exactProgram, SourceSymbol: sourceSymbol, FieldPointer: fieldPointer, FieldLocator: CloudCatalogEvidenceLocator{EvidenceID: "model", JSONPointer: pointer, StartByte: span.start, EndByte: span.end}, SourceFieldID: field.ID, ProviderType: field.ValueType, SourceCardinality: field.Cardinality, NumericDisposition: numeric}, nil
}

func cloudCandidateNumericDisposition(valueType string) map[string]interface{} {
	// Model primitive labels are not an exact-value classifier: REST APIs may
	// serialize integer quantities as strings. Only booleans are safely outside
	// numeric value-of-record interpretation before external selection.
	if valueType == "boolean" {
		return map[string]interface{}{"numeric_semantics": "not_applicable", "authoritative_carrier": "not_applicable", "binary_float_authoritative": false, "computation_path": "not_applicable"}
	}
	return map[string]interface{}{"numeric_semantics": "unclassified_fail_closed", "authoritative_carrier": "unclassified_fail_closed", "binary_float_authoritative": false, "computation_path": "unresolved_fail_closed_gap"}
}

// cloudFieldModelMemberPointer follows the model's declared type graph.  A
// source pointer is a projection coordinate, not itself a JSON pointer into a
// Smithy/Discovery model, so joining it onto the root shape would lose nested
// member evidence.
func cloudFieldModelMemberPointer(catalog CloudCatalog, schema, pointer string) (string, error) {
	if len(pointer) < 2 || pointer[0] != '/' {
		return "", fmt.Errorf("source field pointer is invalid")
	}
	parts := strings.Split(pointer[1:], "/")
	switch catalog.Format {
	case CloudCatalogFormatSmithyJSON:
		current, last := schema, ""
		for _, encoded := range parts {
			segment := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
			shape, ok := cloudCatalogShape(catalog, current)
			if !ok {
				return "", fmt.Errorf("Smithy shape %q is absent", current)
			}
			var value map[string]json.RawMessage
			if err := json.Unmarshal(shape.RawJSON, &value); err != nil {
				return "", err
			}
			if segment == "*" {
				var member struct {
					Target string `json:"target"`
				}
				raw := value["member"]
				if len(raw) == 0 {
					raw = value["value"]
				}
				if json.Unmarshal(raw, &member) != nil || member.Target == "" {
					return "", fmt.Errorf("Smithy collection %q has no selected member/value target", current)
				}
				current = member.Target
				continue
			}
			members, err := rawObject(value["members"])
			if err != nil {
				return "", fmt.Errorf("Smithy shape %q has no members", current)
			}
			raw, ok := members[segment]
			if !ok {
				return "", fmt.Errorf("Smithy shape %q has no member %q", current, segment)
			}
			var member struct {
				Target string `json:"target"`
			}
			if json.Unmarshal(raw, &member) != nil || member.Target == "" {
				return "", fmt.Errorf("Smithy member %q has no target", encoded)
			}
			last = "/shapes/" + cloudCatalogEscapePointer(current) + "/members/" + cloudCatalogEscapePointer(segment)
			current = member.Target
		}
		if last == "" {
			return "", fmt.Errorf("Smithy field has no member evidence")
		}
		return last, nil
	case CloudCatalogFormatGoogleDiscoveryREST:
		currentPointer := "/schemas/" + cloudCatalogEscapePointer(schema)
		for _, encoded := range parts {
			segment := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
			if segment == "*" {
				currentPointer += "/items"
				continue
			}
			currentPointer += "/properties/" + cloudCatalogEscapePointer(segment)
		}
		return currentPointer, nil
	default:
		return "", fmt.Errorf("unsupported cloud model format %q", catalog.Format)
	}
}

// cloudSchemaModelPointer identifies the declared schema artifact itself, not
// one of its members.  It is used for the source-schema owner classification:
// an API endpoint is an access boundary, while the declared schema is the
// actual source surface that owns its field contract.
func cloudSchemaModelPointer(catalog CloudCatalog, schema string) (string, error) {
	if schema == "" {
		return "", fmt.Errorf("source schema is empty")
	}
	switch catalog.Format {
	case CloudCatalogFormatSmithyJSON:
		if _, ok := cloudCatalogShape(catalog, schema); !ok {
			return "", fmt.Errorf("Smithy source schema %q is absent", schema)
		}
		return "/shapes/" + cloudCatalogEscapePointer(schema), nil
	case CloudCatalogFormatGoogleDiscoveryREST:
		return "/schemas/" + cloudCatalogEscapePointer(schema), nil
	default:
		return "", fmt.Errorf("unsupported cloud model format %q", catalog.Format)
	}
}

func cloudSourceSchemaOwnerLocator(catalog CloudCatalog, target CloudSourceObjectTarget, model PinnedCloudModel) (CloudCatalogEvidenceLocator, error) {
	if target.MappingContract == nil {
		return CloudCatalogEvidenceLocator{}, fmt.Errorf("source schema owner target has no mapping contract")
	}
	pointer, err := cloudSchemaModelPointer(catalog, target.MappingContract.ObjectSchemaID)
	if err != nil {
		return CloudCatalogEvidenceLocator{}, err
	}
	spans, err := cloudCatalogJSONPointerSpans(model.Raw)
	if err != nil {
		return CloudCatalogEvidenceLocator{}, err
	}
	span, ok := spans[pointer]
	if !ok || span.end <= span.start {
		return CloudCatalogEvidenceLocator{}, fmt.Errorf("source schema %q has no exact model span", target.MappingContract.ObjectSchemaID)
	}
	return CloudCatalogEvidenceLocator{EvidenceID: "model", JSONPointer: pointer, StartByte: span.start, EndByte: span.end}, nil
}

func cloudSourceSchemaOwnerSymbol(modelSourceID string, locator CloudCatalogEvidenceLocator) string {
	return stableID("cloud_source_schema_owner", modelSourceID+"\x00"+locator.EvidenceID+"\x00"+locator.JSONPointer)
}

func bytesLineNumber(raw []byte, offset int) int { return 1 + bytes.Count(raw[:offset], []byte{'\n'}) }
