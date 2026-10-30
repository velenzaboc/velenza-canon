package providerplan

// The cloud catalog is an offline, evidence-local inventory of a pinned public
// API model.  It deliberately does not mint source records, credentials,
// canonical neutral fields, or runtime connection behaviour.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type CloudCatalogFormat string

const (
	CloudCatalogFormatSmithyJSON          CloudCatalogFormat = "smithy_json"
	CloudCatalogFormatGoogleDiscoveryREST CloudCatalogFormat = "google_discovery_rest"

	cloudCatalogAssociationAsserted   = "asserted_candidate_unqualified"
	cloudCatalogAssociationDocumented = "documented_model_association_candidate_unqualified"
	cloudCatalogAssociationUnresolved = "unresolved_fail_closed"
)

// CloudCatalogSourceIdentity identifies documentation evidence only. It is
// intentionally distinct from (and never creates) a customer source record.
type CloudCatalogSourceIdentity struct {
	ID               string `json:"id"`
	URI              string `json:"uri"`
	StableCoordinate string `json:"stable_coordinate"`
	FormatRevision   string `json:"format_revision"`
}

type CloudCatalogEvidenceLocator struct {
	EvidenceID  string `json:"evidence_id"`
	JSONPointer string `json:"json_pointer"`
	StartByte   int    `json:"start_byte"`
	EndByte     int    `json:"end_byte"`
}

type CloudCatalogSupplementalEvidence struct {
	ID             string                     `json:"id"`
	Source         CloudCatalogSourceIdentity `json:"source"`
	Raw            []byte                     `json:"-"`
	ExpectedSHA256 string                     `json:"expected_sha256"`
}

type CloudCatalogResourceOperationAssertion struct {
	ResourceID      string                      `json:"resource_id"`
	OperationID     string                      `json:"operation_id"`
	EvidenceLocator CloudCatalogEvidenceLocator `json:"evidence_locator"`
}

// CloudCatalogResourceDeclaration is an evidence-bound, offline candidate
// declaration for APIs whose model does not use a native resource shape.  It
// is not an identity claim and does not infer that every structure is a
// resource: the supplemental evidence must explicitly name the retained
// structure and role.
type CloudCatalogResourceDeclaration struct {
	ResourceID       string                      `json:"resource_id"`
	StructureShapeID string                      `json:"structure_shape_id"`
	Role             string                      `json:"role"`
	StructureLocator CloudCatalogEvidenceLocator `json:"structure_locator"`
	EvidenceLocator  CloudCatalogEvidenceLocator `json:"evidence_locator"`
}

type PinnedCloudModel struct {
	Format                      CloudCatalogFormat                       `json:"format"`
	Source                      CloudCatalogSourceIdentity               `json:"source"`
	ProviderID                  string                                   `json:"provider_id"`
	ServiceID                   string                                   `json:"service_id"`
	APISurfaceID                string                                   `json:"api_surface_id"`
	APIVersion                  string                                   `json:"api_version"`
	Raw                         []byte                                   `json:"-"`
	ExpectedSHA256              string                                   `json:"expected_sha256"`
	SupplementalEvidence        []CloudCatalogSupplementalEvidence       `json:"supplemental_evidence,omitempty"`
	ResourceDeclarations        []CloudCatalogResourceDeclaration        `json:"resource_declarations,omitempty"`
	ResourceOperationAssertions []CloudCatalogResourceOperationAssertion `json:"resource_operation_assertions,omitempty"`
	locatorSpans                map[string]cloudCatalogByteSpan
}

type cloudCatalogByteSpan struct{ start, end int }

type CloudCatalogSchemaShape struct {
	ID                   string                      `json:"id"`
	DeclaredType         string                      `json:"declared_type"`
	Locator              CloudCatalogEvidenceLocator `json:"locator"`
	RawJSON              json.RawMessage             `json:"raw_json"`
	InterpretationStatus string                      `json:"interpretation_status"`
}

type CloudCatalogResource struct {
	ID                         string                       `json:"id"`
	Locator                    CloudCatalogEvidenceLocator  `json:"locator"`
	OperationIDs               []string                     `json:"operation_ids"`
	DeclarationStatus          string                       `json:"declaration_status"`
	DeclarationEvidenceLocator *CloudCatalogEvidenceLocator `json:"declaration_evidence_locator,omitempty"`
}

// CloudCatalogResourceAssociationEvidence keeps the supplemental assertion
// that made a candidate operation/resource pairing available to this offline
// catalog. It is not a qualified semantic relationship.
type CloudCatalogResourceAssociationEvidence struct {
	ResourceID      string                      `json:"resource_id"`
	EvidenceLocator CloudCatalogEvidenceLocator `json:"evidence_locator"`
}

type CloudCatalogOperation struct {
	ID                            string                                    `json:"id"`
	Locator                       CloudCatalogEvidenceLocator               `json:"locator"`
	ResourceIDs                   []string                                  `json:"resource_ids"`
	AssociationStatus             string                                    `json:"association_status"`
	AuthenticationRequirementIDs  []string                                  `json:"authentication_requirement_ids,omitempty"`
	AuthenticationScopeReferences []string                                  `json:"authentication_scope_references,omitempty"`
	ResourceAssociationEvidence   []CloudCatalogResourceAssociationEvidence `json:"resource_association_evidence,omitempty"`
	RawJSON                       json.RawMessage                           `json:"raw_json"`
}

// CloudCatalogAuthenticationRequirement lists public requirements and scopes;
// it cannot carry a credential, secret, grant, or runtime authorization.
type CloudCatalogAuthenticationRequirement struct {
	ID                                  string                      `json:"id"`
	RequirementReferences               []string                    `json:"requirement_references,omitempty"`
	ScopeReferences                     []string                    `json:"scope_references,omitempty"`
	ServiceSigningRequirementReferences []string                    `json:"service_signing_requirement_references,omitempty"`
	Locator                             CloudCatalogEvidenceLocator `json:"locator"`
}

const (
	cloudCatalogProtocolDocumentedSupported   = "documented_supported"
	cloudCatalogProtocolDocumentedUnsupported = "documented_unsupported"
)

// CloudCatalogProtocolBinding retains an exact, model-local wire protocol
// declaration. It does not select a caller codec and an unsupported binding is
// deliberately retained so downstream mapping can fail closed.
type CloudCatalogProtocolBinding struct {
	ID       string                        `json:"id"`
	Status   string                        `json:"status"`
	Locators []CloudCatalogEvidenceLocator `json:"locators"`
}

type CloudCatalog struct {
	Format           CloudCatalogFormat                      `json:"format"`
	Source           CloudCatalogSourceIdentity              `json:"source"`
	ProviderID       string                                  `json:"provider_id"`
	ServiceID        string                                  `json:"service_id"`
	APISurfaceID     string                                  `json:"api_surface_id"`
	APIVersion       string                                  `json:"api_version"`
	ModelSHA256      string                                  `json:"model_sha256"`
	Resources        []CloudCatalogResource                  `json:"resources"`
	Operations       []CloudCatalogOperation                 `json:"operations"`
	Authentication   []CloudCatalogAuthenticationRequirement `json:"authentication_requirements"`
	SchemaShapes     []CloudCatalogSchemaShape               `json:"schema_shapes"`
	ProtocolBindings []CloudCatalogProtocolBinding           `json:"protocol_bindings"`
}

type CloudCatalogParser interface {
	ParsePinnedCloudModel(PinnedCloudModel) (CloudCatalog, error)
}

type strictCloudCatalogParser struct{}

func (strictCloudCatalogParser) ParsePinnedCloudModel(model PinnedCloudModel) (CloudCatalog, error) {
	return ParsePinnedCloudModel(model)
}

// NewCloudCatalogParser returns the one generic, format-selected parser. The
// service configuration is in PinnedCloudModel; callers never select vendor
// adapters or synthesize source identities.
func NewCloudCatalogParser() CloudCatalogParser { return strictCloudCatalogParser{} }

func ParsePinnedCloudModel(model PinnedCloudModel) (CloudCatalog, error) {
	if err := validatePinnedCloudModel(model); err != nil {
		return CloudCatalog{}, err
	}
	spans, err := cloudCatalogJSONPointerSpans(model.Raw)
	if err != nil {
		return CloudCatalog{}, fmt.Errorf("index model JSON evidence locators: %w", err)
	}
	model.locatorSpans = spans
	var catalog CloudCatalog

	if model.Format == CloudCatalogFormatSmithyJSON {
		catalog, err = parseSmithyCloudCatalog(model)
	} else {
		catalog, err = parseDiscoveryCloudCatalog(model)
	}
	if err != nil {
		return CloudCatalog{}, err
	}
	if err := validateProducedCloudCatalogLocators(catalog, model); err != nil {
		return CloudCatalog{}, err
	}
	return catalog, nil
}

func validateProducedCloudCatalogLocators(catalog CloudCatalog, model PinnedCloudModel) error {
	bodies := map[string][]byte{"model": model.Raw}
	for _, evidence := range model.SupplementalEvidence {
		bodies[evidence.ID] = evidence.Raw
	}
	validate := func(locator CloudCatalogEvidenceLocator) error {
		span, ok := model.locatorSpans[locator.JSONPointer]
		if !ok || locator.EvidenceID != "model" || locator.StartByte != span.start || locator.EndByte != span.end {
			return fmt.Errorf("produced locator is not the exact indexed model pointer range")
		}
		return nil
	}
	for _, schema := range catalog.SchemaShapes {
		if err := validate(schema.Locator); err != nil {
			return fmt.Errorf("schema %q locator: %w", schema.ID, err)
		}
	}
	for _, resource := range catalog.Resources {
		if err := validate(resource.Locator); err != nil {
			return fmt.Errorf("resource %q locator: %w", resource.ID, err)
		}
		if resource.DeclarationStatus == cloudCatalogAssociationAsserted {
			if resource.DeclarationEvidenceLocator == nil {
				return fmt.Errorf("asserted resource %q lacks declaration evidence", resource.ID)
			}
			if err := validateCloudCatalogLocator(*resource.DeclarationEvidenceLocator, bodies); err != nil {
				return fmt.Errorf("resource %q declaration evidence: %w", resource.ID, err)
			}
		}
	}
	for _, operation := range catalog.Operations {
		if err := validate(operation.Locator); err != nil {
			return fmt.Errorf("operation %q locator: %w", operation.ID, err)
		}
		for _, association := range operation.ResourceAssociationEvidence {
			if association.ResourceID == "" {
				return fmt.Errorf("operation %q has association evidence without resource id", operation.ID)
			}
			if err := validateCloudCatalogLocator(association.EvidenceLocator, bodies); err != nil {
				return fmt.Errorf("operation %q association evidence: %w", operation.ID, err)
			}
		}
	}
	for _, auth := range catalog.Authentication {
		if err := validate(auth.Locator); err != nil {
			return fmt.Errorf("auth %q locator: %w", auth.ID, err)
		}
	}
	for _, binding := range catalog.ProtocolBindings {
		if binding.ID == "" || (binding.Status != cloudCatalogProtocolDocumentedSupported && binding.Status != cloudCatalogProtocolDocumentedUnsupported) || len(binding.Locators) == 0 {
			return fmt.Errorf("invalid protocol binding")
		}
		for _, locator := range binding.Locators {
			if err := validate(locator); err != nil {
				return fmt.Errorf("protocol %q locator: %w", binding.ID, err)
			}
		}
	}
	return nil
}

func validatePinnedCloudModel(model PinnedCloudModel) error {
	if model.Format != CloudCatalogFormatSmithyJSON && model.Format != CloudCatalogFormatGoogleDiscoveryREST {
		return fmt.Errorf("unsupported cloud catalog format %q", model.Format)
	}
	for label, value := range map[string]string{"provider_id": model.ProviderID, "service_id": model.ServiceID, "api_surface_id": model.APISurfaceID, "api_version": model.APIVersion} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	if err := validateCloudCatalogSourceIdentity("model source", model.Source); err != nil {
		return err
	}
	if len(model.Raw) == 0 || int64(len(model.Raw)) > maxStageInputFileBytesPerFile {
		return fmt.Errorf("model bytes are empty or exceed fixed bound")
	}
	if err := requireValidUTF8("model bytes", model.Raw); err != nil {
		return err
	}
	if !isLowerSHA256(model.ExpectedSHA256) || sha256Hex(model.Raw) != model.ExpectedSHA256 {
		return fmt.Errorf("model bytes do not equal expected_sha256")
	}
	if _, err := validateProviderJSONStructure(model.Raw); err != nil {
		return fmt.Errorf("model JSON: %w", err)
	}
	seen := map[string][]byte{"model": model.Raw}
	for _, evidence := range model.SupplementalEvidence {
		if evidence.ID == "" || evidence.ID == "model" {
			return fmt.Errorf("supplemental evidence id %q is invalid or duplicates model", evidence.ID)
		}
		if _, exists := seen[evidence.ID]; exists {
			return fmt.Errorf("duplicate supplemental evidence id %q", evidence.ID)
		}
		if err := validateCloudCatalogSourceIdentity("supplemental evidence source", evidence.Source); err != nil {
			return err
		}
		if len(evidence.Raw) == 0 || int64(len(evidence.Raw)) > maxStageInputFileBytesPerFile || !isLowerSHA256(evidence.ExpectedSHA256) || sha256Hex(evidence.Raw) != evidence.ExpectedSHA256 {
			return fmt.Errorf("supplemental evidence %q does not bind exact bounded bytes", evidence.ID)
		}
		if err := requireValidUTF8("supplemental evidence "+evidence.ID, evidence.Raw); err != nil {
			return err
		}
		if _, err := validateProviderJSONStructure(evidence.Raw); err != nil {
			return fmt.Errorf("supplemental evidence %q JSON: %w", evidence.ID, err)
		}
		seen[evidence.ID] = evidence.Raw
	}
	for _, declaration := range model.ResourceDeclarations {
		if err := validateCloudCatalogResourceDeclaration(declaration, seen, model); err != nil {
			return fmt.Errorf("resource declaration %q: %w", declaration.ResourceID, err)
		}
	}
	for _, assertion := range model.ResourceOperationAssertions {
		if assertion.ResourceID == "" || assertion.OperationID == "" {
			return fmt.Errorf("resource-operation assertion must name both resource and operation")
		}
		if err := validateCloudCatalogLocator(assertion.EvidenceLocator, seen); err != nil {
			return fmt.Errorf("resource-operation assertion %q/%q: %w", assertion.ResourceID, assertion.OperationID, err)
		}
		if err := validateCloudCatalogAssertionBinding(assertion, seen); err != nil {
			return fmt.Errorf("resource-operation assertion %q/%q: %w", assertion.ResourceID, assertion.OperationID, err)
		}
	}
	return nil
}

func validateCloudCatalogResourceDeclaration(declaration CloudCatalogResourceDeclaration, bodies map[string][]byte, model PinnedCloudModel) error {
	if declaration.ResourceID == "" || declaration.StructureShapeID == "" || declaration.ResourceID != declaration.StructureShapeID {
		return fmt.Errorf("resource_id must exactly name the declared structure_shape_id")
	}
	if declaration.Role != cloudCatalogAssociationAsserted {
		return fmt.Errorf("role must equal %q", cloudCatalogAssociationAsserted)
	}
	if err := validateCloudCatalogLocator(declaration.EvidenceLocator, bodies); err != nil {
		return fmt.Errorf("declaration evidence locator: %w", err)
	}
	if err := validateCloudCatalogResourceDeclarationBinding(declaration, bodies); err != nil {
		return err
	}
	if declaration.StructureLocator.EvidenceID != "model" || declaration.StructureLocator.JSONPointer != "/shapes/"+cloudCatalogEscapePointer(declaration.StructureShapeID) {
		return fmt.Errorf("structure locator must exactly name the retained model shape")
	}
	if err := validateCloudCatalogLocator(declaration.StructureLocator, bodies); err != nil {
		return fmt.Errorf("structure locator: %w", err)
	}
	spans, err := cloudCatalogJSONPointerSpans(model.Raw)
	if err != nil {
		return err
	}
	span, ok := spans[declaration.StructureLocator.JSONPointer]
	if !ok || declaration.StructureLocator.StartByte != span.start || declaration.StructureLocator.EndByte != span.end {
		return fmt.Errorf("structure locator is not the exact retained model pointer range")
	}
	var root any
	if err := json.Unmarshal(model.Raw, &root); err != nil {
		return err
	}
	target, err := resolveCloudCatalogJSONPointer(root, declaration.StructureLocator.JSONPointer)
	if err != nil {
		return err
	}
	shape, ok := target.(map[string]any)
	if !ok || shape["type"] != "structure" {
		return fmt.Errorf("declared structure locator does not identify a Smithy structure shape")
	}
	return nil
}

func validateCloudCatalogResourceDeclarationBinding(declaration CloudCatalogResourceDeclaration, bodies map[string][]byte) error {
	var root any
	if err := json.Unmarshal(bodies[declaration.EvidenceLocator.EvidenceID], &root); err != nil {
		return err
	}
	target, err := resolveCloudCatalogJSONPointer(root, declaration.EvidenceLocator.JSONPointer)
	if err != nil {
		return err
	}
	item, ok := target.(map[string]any)
	if !ok {
		return fmt.Errorf("evidence locator must identify a resource declaration object")
	}
	resource, resourceOK := item["resource_id"].(string)
	structure, structureOK := item["structure_shape_id"].(string)
	role, roleOK := item["role"].(string)
	locatorRaw, locatorOK := item["structure_locator"]
	if !resourceOK || !structureOK || !roleOK || !locatorOK || resource != declaration.ResourceID || structure != declaration.StructureShapeID || role != declaration.Role {
		return fmt.Errorf("evidence locator does not bind declared resource, structure, and role")
	}
	encoded, err := json.Marshal(locatorRaw)
	if err != nil {
		return err
	}
	var locator CloudCatalogEvidenceLocator
	if err := json.Unmarshal(encoded, &locator); err != nil || locator != declaration.StructureLocator {
		return fmt.Errorf("evidence locator does not bind declared structure locator")
	}
	return nil
}

func validateCloudCatalogAssertionBinding(assertion CloudCatalogResourceOperationAssertion, bodies map[string][]byte) error {
	var root any
	if err := json.Unmarshal(bodies[assertion.EvidenceLocator.EvidenceID], &root); err != nil {
		return err
	}
	target, err := resolveCloudCatalogJSONPointer(root, assertion.EvidenceLocator.JSONPointer)
	if err != nil {
		return err
	}
	item, ok := target.(map[string]any)
	if !ok {
		return fmt.Errorf("evidence locator must identify an assertion object")
	}
	resource, resourceOK := item["resource_id"].(string)
	operation, operationOK := item["operation_id"].(string)
	if !resourceOK || !operationOK || resource != assertion.ResourceID || operation != assertion.OperationID {
		return fmt.Errorf("evidence locator does not bind the asserted resource_id and operation_id")
	}
	return nil
}

func validateCloudCatalogSourceIdentity(label string, source CloudCatalogSourceIdentity) error {
	if strings.TrimSpace(source.ID) == "" || strings.TrimSpace(source.URI) == "" || strings.TrimSpace(source.StableCoordinate) == "" || strings.TrimSpace(source.FormatRevision) == "" {
		return fmt.Errorf("%s must carry id, uri, stable_coordinate, and format_revision", label)
	}
	return nil
}

func validateCloudCatalogLocator(locator CloudCatalogEvidenceLocator, bodies map[string][]byte) error {
	raw, ok := bodies[locator.EvidenceID]
	if !ok || locator.JSONPointer == "" || locator.StartByte < 0 || locator.EndByte <= locator.StartByte || locator.EndByte > len(raw) {
		return fmt.Errorf("locator does not bind an existing evidence body, pointer, and byte range")
	}
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return err
	}
	target, err := resolveCloudCatalogJSONPointer(root, locator.JSONPointer)
	if err != nil {
		return err
	}
	var fragment any
	if err := json.Unmarshal(raw[locator.StartByte:locator.EndByte], &fragment); err != nil {
		return fmt.Errorf("locator byte range is not JSON: %w", err)
	}
	targetJSON, targetErr := json.Marshal(target)
	fragmentJSON, fragmentErr := json.Marshal(fragment)
	if targetErr != nil || fragmentErr != nil || !bytes.Equal(targetJSON, fragmentJSON) {
		return fmt.Errorf("locator byte range does not contain its JSON pointer target")
	}
	return nil
}

func resolveCloudCatalogJSONPointer(root any, pointer string) (any, error) {
	if pointer == "" {
		return root, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("JSON pointer %q is not absolute", pointer)
	}
	value := root
	for _, encoded := range strings.Split(pointer[1:], "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(encoded, "~1", "/"), "~0", "~")
		switch typed := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = typed[part]
			if !ok {
				return nil, fmt.Errorf("JSON pointer %q does not resolve", pointer)
			}
		case []any:
			index, err := strconv.Atoi(part)
			if err != nil || strconv.Itoa(index) != part || index < 0 || index >= len(typed) {
				return nil, fmt.Errorf("JSON pointer %q does not resolve", pointer)
			}
			value = typed[index]
		default:
			return nil, fmt.Errorf("JSON pointer %q descends through scalar", pointer)
		}
	}
	return value, nil
}

func cloudCatalogModelLocator(model PinnedCloudModel, pointer string) CloudCatalogEvidenceLocator {
	span, ok := model.locatorSpans[pointer]
	if !ok {
		return CloudCatalogEvidenceLocator{EvidenceID: "model", JSONPointer: pointer, StartByte: -1, EndByte: -1}
	}
	return CloudCatalogEvidenceLocator{EvidenceID: "model", JSONPointer: pointer, StartByte: span.start, EndByte: span.end}
}

func cloudCatalogEscapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func cloudCatalogBase(model PinnedCloudModel) CloudCatalog {
	return CloudCatalog{Format: model.Format, Source: model.Source, ProviderID: model.ProviderID, ServiceID: model.ServiceID, APISurfaceID: model.APISurfaceID, APIVersion: model.APIVersion, ModelSHA256: model.ExpectedSHA256}
}

func decodeCloudCatalogObject(raw json.RawMessage, label string) (map[string]json.RawMessage, error) {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return nil, fmt.Errorf("%s must be an object", label)
	}
	return value, nil
}

func cloudCatalogString(value map[string]json.RawMessage, key, label string) (string, error) {
	raw, ok := value[key]
	if !ok {
		return "", fmt.Errorf("%s.%s is required", label, key)
	}
	var result string
	if err := json.Unmarshal(raw, &result); err != nil || result == "" {
		return "", fmt.Errorf("%s.%s must be a nonempty string", label, key)
	}
	return result, nil
}

func cloudCatalogOptionalString(value map[string]json.RawMessage, key, label string) (string, bool, error) {
	raw, ok := value[key]
	if !ok {
		return "", false, nil
	}
	var result string
	if err := json.Unmarshal(raw, &result); err != nil || result == "" {
		return "", true, fmt.Errorf("%s.%s must be a nonempty string", label, key)
	}
	return result, true, nil
}

func sortedCloudCatalogKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func uniqueCloudCatalogStrings(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func cloneCloudCatalogRaw(raw json.RawMessage) json.RawMessage { return bytes.Clone(raw) }

// cloudCatalogJSONPointerSpan finds the exact token span for a validated JSON
// Pointer. Input was already structurally bounded and duplicate-free. It keeps
// the original bytes (rather than a re-encoding) as evidence locator ranges.
func cloudCatalogJSONPointerSpans(raw []byte) (map[string]cloudCatalogByteSpan, error) {
	spans := map[string]cloudCatalogByteSpan{}
	skip := func(pos int) int {
		for pos < len(raw) && (raw[pos] == ' ' || raw[pos] == '\n' || raw[pos] == '\r' || raw[pos] == '\t') {
			pos++
		}
		return pos
	}
	var stringEnd func(int) (int, error)
	stringEnd = func(pos int) (int, error) {
		if pos >= len(raw) || raw[pos] != '"' {
			return 0, fmt.Errorf("expected JSON string")
		}
		for pos++; pos < len(raw); pos++ {
			if raw[pos] == '\\' {
				pos++
				continue
			}
			if raw[pos] == '"' {
				return pos + 1, nil
			}
		}
		return 0, fmt.Errorf("unterminated JSON string")
	}
	var walk func(int, string) (int, error)
	walk = func(pos int, pointer string) (int, error) {
		pos = skip(pos)
		if pos >= len(raw) {
			return 0, fmt.Errorf("truncated JSON")
		}
		start := pos
		switch raw[pos] {
		case '{':
			pos = skip(pos + 1)
			for raw[pos] != '}' {
				keyStart := pos
				keyEnd, err := stringEnd(pos)
				if err != nil {
					return 0, err
				}
				var key string
				if err = json.Unmarshal(raw[keyStart:keyEnd], &key); err != nil {
					return 0, err
				}
				pos = skip(keyEnd)
				if pos >= len(raw) || raw[pos] != ':' {
					return 0, fmt.Errorf("object missing colon")
				}
				pos = skip(pos + 1)
				end, err := walk(pos, pointer+"/"+cloudCatalogEscapePointer(key))
				if err != nil {
					return 0, err
				}
				pos = skip(end)
				if raw[pos] == ',' {
					pos = skip(pos + 1)
				} else if raw[pos] != '}' {
					return 0, fmt.Errorf("object separator invalid")
				}
			}
			pos++
		case '[':
			pos = skip(pos + 1)
			for current := 0; raw[pos] != ']'; current++ {
				end, err := walk(pos, pointer+"/"+strconv.Itoa(current))
				if err != nil {
					return 0, err
				}
				pos = skip(end)
				if raw[pos] == ',' {
					pos = skip(pos + 1)
				} else if raw[pos] != ']' {
					return 0, fmt.Errorf("array separator invalid")
				}
			}
			pos++
		default:
			end, _, _, err := walkValueEnd(raw, pos, skip, stringEnd)
			if err != nil {
				return 0, err
			}
			pos = end
		}
		if pointer != "" {
			spans[pointer] = cloudCatalogByteSpan{start: start, end: pos}
		}
		return pos, nil
	}
	end, err := walk(0, "")
	if err != nil {
		return nil, err
	}
	if skip(end) != len(raw) {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return spans, nil
}

func cloudCatalogJSONPointerSpan(raw []byte, pointer string) (int, int, error) {
	spans, err := cloudCatalogJSONPointerSpans(raw)
	if err != nil {
		return 0, 0, err
	}
	span, ok := spans[pointer]
	if !ok {
		return 0, 0, fmt.Errorf("JSON pointer %q does not resolve", pointer)
	}
	return span.start, span.end, nil
}

func walkValueEnd(raw []byte, pos int, skip func(int) int, stringEnd func(int) (int, error)) (int, int, int, error) {
	pos = skip(pos)
	start := pos
	if pos >= len(raw) {
		return 0, 0, 0, fmt.Errorf("truncated JSON")
	}
	switch raw[pos] {
	case '"':
		end, err := stringEnd(pos)
		return end, start, end, err
	case '{', '[':
		open := raw[pos]
		close := byte('}')
		if open == '[' {
			close = ']'
		}
		depth := 0
		for i := pos; i < len(raw); {
			switch raw[i] {
			case '"':
				end, err := stringEnd(i)
				if err != nil {
					return 0, 0, 0, err
				}
				i = end
				continue
			case open:
				depth++
			case close:
				depth--
				if depth == 0 {
					return i + 1, start, i + 1, nil
				}
			}
			i++
		}
		return 0, 0, 0, fmt.Errorf("unterminated JSON container")
	default:
		end := pos
		for end < len(raw) && !strings.ContainsRune(" \t\r\n,]}", rune(raw[end])) {
			end++
		}
		return end, start, end, nil
	}
}
