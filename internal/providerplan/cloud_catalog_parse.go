package providerplan

import (
	"encoding/json"
	"fmt"
	"strings"
)

func parseSmithyCloudCatalog(model PinnedCloudModel) (CloudCatalog, error) {
	root, err := decodeCloudCatalogObject(model.Raw, "Smithy model")
	if err != nil {
		return CloudCatalog{}, err
	}
	if smithy, err := cloudCatalogString(root, "smithy", "Smithy model"); err != nil || smithy != "2.0" {
		return CloudCatalog{}, fmt.Errorf("Smithy model.smithy must equal 2.0")
	}
	shapesRaw, ok := root["shapes"]
	if !ok {
		return CloudCatalog{}, fmt.Errorf("Smithy model.shapes is required")
	}
	shapes, err := decodeCloudCatalogObject(shapesRaw, "Smithy model.shapes")
	if err != nil {
		return CloudCatalog{}, err
	}
	catalog := cloudCatalogBase(model)
	operations := map[string]*CloudCatalogOperation{}
	resources := map[string]*CloudCatalogResource{}
	serviceIDs := []string{}
	for _, id := range sortedCloudCatalogKeys(shapes) {
		shape, err := decodeCloudCatalogObject(shapes[id], "Smithy shape "+id)
		if err != nil {
			return CloudCatalog{}, err
		}
		declaredType, err := cloudCatalogString(shape, "type", "Smithy shape "+id)
		if err != nil {
			return CloudCatalog{}, err
		}
		locator := cloudCatalogModelLocator(model, "/shapes/"+cloudCatalogEscapePointer(id))
		catalog.SchemaShapes = append(catalog.SchemaShapes, CloudCatalogSchemaShape{ID: id, DeclaredType: declaredType, Locator: locator, RawJSON: cloneCloudCatalogRaw(shapes[id]), InterpretationStatus: "preserved_uninterpreted"})
		switch declaredType {
		case "service":
			serviceIDs = append(serviceIDs, id)
		case "operation":
			operations[id] = &CloudCatalogOperation{ID: id, Locator: locator, AssociationStatus: cloudCatalogAssociationUnresolved, RawJSON: cloneCloudCatalogRaw(shapes[id])}
		case "resource":
			resources[id] = &CloudCatalogResource{ID: id, Locator: locator, DeclarationStatus: "native_smithy_resource"}
		}
	}
	if len(serviceIDs) != 1 {
		return CloudCatalog{}, fmt.Errorf("Smithy model must carry exactly one service shape, found %d", len(serviceIDs))
	}
	service, err := decodeCloudCatalogObject(shapes[serviceIDs[0]], "Smithy service "+serviceIDs[0])
	if err != nil {
		return CloudCatalog{}, err
	}
	version, err := cloudCatalogString(service, "version", "Smithy service "+serviceIDs[0])
	if err != nil || version != model.APIVersion {
		return CloudCatalog{}, fmt.Errorf("Smithy service version does not equal pinned api_version %q", model.APIVersion)
	}
	catalog.ProtocolBindings, err = smithyProtocolBindings(model, service, serviceIDs[0])
	if err != nil {
		return CloudCatalog{}, err
	}
	serviceOperations, err := smithyOperationTargets(service, serviceIDs[0])
	if err != nil {
		return CloudCatalog{}, err
	}
	for _, operationID := range serviceOperations {
		operation := operations[operationID]
		if operation == nil {
			return CloudCatalog{}, fmt.Errorf("Smithy service operation %q is absent or is not an operation shape", operationID)
		}
		catalog.Operations = append(catalog.Operations, *operation)
	}
	catalog.Authentication, err = smithyAuthentication(model, service, serviceIDs[0])
	if err != nil {
		return CloudCatalog{}, err
	}
	selectedOperations := make(map[string]*CloudCatalogOperation, len(serviceOperations))
	for _, operationID := range serviceOperations {
		selectedOperations[operationID] = operations[operationID]
	}
	if err := applyCloudCatalogResourceDeclarations(model, resources); err != nil {
		return CloudCatalog{}, err
	}
	if err := applyCloudCatalogAssertions(model, resources, selectedOperations); err != nil {
		return CloudCatalog{}, err
	}
	catalog.Operations = catalog.Operations[:0]
	for _, id := range serviceOperations {
		catalog.Operations = append(catalog.Operations, *operations[id])
	}
	for _, id := range sortedCloudCatalogKeys(resources) {
		catalog.Resources = append(catalog.Resources, *resources[id])
	}
	return catalog, nil
}

func smithyProtocolBindings(model PinnedCloudModel, service map[string]json.RawMessage, serviceID string) ([]CloudCatalogProtocolBinding, error) {
	traitsRaw, ok := service["traits"]
	if !ok {
		return nil, nil
	}
	traits, err := decodeCloudCatalogObject(traitsRaw, "Smithy service traits")
	if err != nil {
		return nil, err
	}
	result := []CloudCatalogProtocolBinding{}
	for _, id := range sortedCloudCatalogKeys(traits) {
		if !strings.HasPrefix(id, "aws.protocols#") {
			continue
		}
		status := cloudCatalogProtocolDocumentedUnsupported
		if id == "aws.protocols#restXml" || id == "aws.protocols#ec2Query" {
			status = cloudCatalogProtocolDocumentedSupported
		}
		result = append(result, CloudCatalogProtocolBinding{ID: id, Status: status, Locators: []CloudCatalogEvidenceLocator{cloudCatalogModelLocator(model, "/shapes/"+cloudCatalogEscapePointer(serviceID)+"/traits/"+cloudCatalogEscapePointer(id))}})
	}
	return result, nil
}

func smithyOperationTargets(service map[string]json.RawMessage, label string) ([]string, error) {
	raw, ok := service["operations"]
	if !ok {
		return nil, fmt.Errorf("Smithy service %q has no operations", label)
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
		return nil, fmt.Errorf("Smithy service %q operations must be a nonempty array", label)
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(entries))
	for index, entryRaw := range entries {
		entry, err := decodeCloudCatalogObject(entryRaw, fmt.Sprintf("Smithy service operation %d", index))
		if err != nil {
			return nil, err
		}
		target, err := cloudCatalogString(entry, "target", "Smithy service operation")
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[target]; duplicate {
			return nil, fmt.Errorf("Smithy service repeats operation target %q", target)
		}
		seen[target] = struct{}{}
		result = append(result, target)
	}
	return uniqueCloudCatalogStrings(result), nil
}

func smithyAuthentication(model PinnedCloudModel, service map[string]json.RawMessage, serviceID string) ([]CloudCatalogAuthenticationRequirement, error) {
	traitsRaw, ok := service["traits"]
	if !ok {
		return nil, nil
	}
	traits, err := decodeCloudCatalogObject(traitsRaw, "Smithy service traits")
	if err != nil {
		return nil, err
	}
	result := []CloudCatalogAuthenticationRequirement{}
	if authRaw, exists := traits["smithy.api#auth"]; exists {
		var schemes []string
		if err := json.Unmarshal(authRaw, &schemes); err != nil || len(schemes) == 0 {
			return nil, fmt.Errorf("Smithy smithy.api#auth must be a nonempty scheme array")
		}
		for _, scheme := range uniqueCloudCatalogStrings(schemes) {
			if scheme == "" {
				return nil, fmt.Errorf("Smithy auth scheme is empty")
			}
			result = append(result, CloudCatalogAuthenticationRequirement{ID: scheme, RequirementReferences: []string{"smithy.api#auth"}, Locator: cloudCatalogModelLocator(model, "/shapes/"+cloudCatalogEscapePointer(serviceID)+"/traits/smithy.api#auth")})
		}
	}
	if _, exists := traits["aws.auth#sigv4"]; exists {
		result = append(result, CloudCatalogAuthenticationRequirement{ID: "aws.auth#sigv4", ServiceSigningRequirementReferences: []string{"aws.auth#sigv4"}, Locator: cloudCatalogModelLocator(model, "/shapes/"+cloudCatalogEscapePointer(serviceID)+"/traits/aws.auth#sigv4")})
	}
	return result, nil
}

func parseDiscoveryCloudCatalog(model PinnedCloudModel) (CloudCatalog, error) {
	root, err := decodeCloudCatalogObject(model.Raw, "Discovery document")
	if err != nil {
		return CloudCatalog{}, err
	}
	if kind, err := cloudCatalogString(root, "kind", "Discovery document"); err != nil || kind != "discovery#restDescription" {
		return CloudCatalog{}, fmt.Errorf("Discovery document.kind must equal discovery#restDescription")
	}
	name, err := cloudCatalogString(root, "name", "Discovery document")
	if err != nil || name != model.APISurfaceID {
		return CloudCatalog{}, fmt.Errorf("Discovery document name does not equal pinned api_surface_id %q", model.APISurfaceID)
	}
	version, err := cloudCatalogString(root, "version", "Discovery document")
	if err != nil || version != model.APIVersion {
		return CloudCatalog{}, fmt.Errorf("Discovery document version does not equal pinned api_version %q", model.APIVersion)
	}
	catalog := cloudCatalogBase(model)
	protocol, err := cloudCatalogString(root, "protocol", "Discovery document")
	if err != nil {
		return CloudCatalog{}, err
	}
	protocolStatus := cloudCatalogProtocolDocumentedUnsupported
	protocolID := "discovery#root_protocol"
	if protocol == "rest" {
		protocolStatus = cloudCatalogProtocolDocumentedSupported
		protocolID = "discovery#rest_json"
	}
	catalog.ProtocolBindings = []CloudCatalogProtocolBinding{{ID: protocolID, Status: protocolStatus, Locators: []CloudCatalogEvidenceLocator{cloudCatalogModelLocator(model, "/kind"), cloudCatalogModelLocator(model, "/protocol")}}}
	authentication, err := discoveryAuthentication(model, root)
	if err != nil {
		return CloudCatalog{}, err
	}
	authSchemeIDs := make([]string, 0, len(authentication))
	for _, requirement := range authentication {
		authSchemeIDs = append(authSchemeIDs, requirement.ID)
	}
	if schemasRaw, exists := root["schemas"]; exists {
		schemas, err := decodeCloudCatalogObject(schemasRaw, "Discovery document.schemas")
		if err != nil {
			return CloudCatalog{}, err
		}
		for _, id := range sortedCloudCatalogKeys(schemas) {
			shape, err := decodeCloudCatalogObject(schemas[id], "Discovery schema "+id)
			if err != nil {
				return CloudCatalog{}, err
			}
			declaredType, _, err := cloudCatalogOptionalString(shape, "type", "Discovery schema "+id)
			if err != nil {
				return CloudCatalog{}, err
			}
			if declaredType == "" {
				declaredType = "unspecified"
			}
			catalog.SchemaShapes = append(catalog.SchemaShapes, CloudCatalogSchemaShape{ID: id, DeclaredType: declaredType, Locator: cloudCatalogModelLocator(model, "/schemas/"+cloudCatalogEscapePointer(id)), RawJSON: cloneCloudCatalogRaw(schemas[id]), InterpretationStatus: "preserved_uninterpreted"})
		}
	}
	resources := map[string]*CloudCatalogResource{}
	operations := map[string]*CloudCatalogOperation{}
	if resourcesRaw, exists := root["resources"]; exists {
		entries, err := decodeCloudCatalogObject(resourcesRaw, "Discovery document.resources")
		if err != nil {
			return CloudCatalog{}, err
		}
		if err := walkDiscoveryResources(model, entries, "/resources", "", authSchemeIDs, resources, operations); err != nil {
			return CloudCatalog{}, err
		}
	}
	if methodsRaw, exists := root["methods"]; exists { // top-level methods have no documented resource association.
		methods, err := decodeCloudCatalogObject(methodsRaw, "Discovery document.methods")
		if err != nil {
			return CloudCatalog{}, err
		}
		if err := addDiscoveryMethods(model, methods, "/methods", "", authSchemeIDs, operations); err != nil {
			return CloudCatalog{}, err
		}
	}
	if len(operations) == 0 {
		return CloudCatalog{}, fmt.Errorf("Discovery document has no methods")
	}
	for _, operation := range operations {
		for _, resourceID := range operation.ResourceIDs {
			if resource := resources[resourceID]; resource != nil {
				resource.OperationIDs = uniqueCloudCatalogStrings(append(resource.OperationIDs, operation.ID))
			}
		}
	}
	catalog.Authentication = authentication
	if err := applyCloudCatalogResourceDeclarations(model, resources); err != nil {
		return CloudCatalog{}, err
	}
	if err := applyCloudCatalogAssertions(model, resources, operations); err != nil {
		return CloudCatalog{}, err
	}
	for _, id := range sortedCloudCatalogKeys(resources) {
		catalog.Resources = append(catalog.Resources, *resources[id])
	}
	for _, id := range sortedCloudCatalogKeys(operations) {
		catalog.Operations = append(catalog.Operations, *operations[id])
	}
	return catalog, nil
}

func walkDiscoveryResources(model PinnedCloudModel, entries map[string]json.RawMessage, pointer, prefix string, authSchemeIDs []string, resources map[string]*CloudCatalogResource, operations map[string]*CloudCatalogOperation) error {
	for _, name := range sortedCloudCatalogKeys(entries) {
		id := name
		if prefix != "" {
			id = prefix + "/" + name
		}
		item, err := decodeCloudCatalogObject(entries[name], "Discovery resource "+id)
		if err != nil {
			return err
		}
		resource := &CloudCatalogResource{ID: id, Locator: cloudCatalogModelLocator(model, pointer+"/"+cloudCatalogEscapePointer(name)), DeclarationStatus: "documented_model_resource"}
		resources[id] = resource
		if methodsRaw, exists := item["methods"]; exists {
			methods, err := decodeCloudCatalogObject(methodsRaw, "Discovery resource methods "+id)
			if err != nil {
				return err
			}
			if err := addDiscoveryMethods(model, methods, pointer+"/"+cloudCatalogEscapePointer(name)+"/methods", id, authSchemeIDs, operations); err != nil {
				return err
			}
		}
		if nestedRaw, exists := item["resources"]; exists {
			nested, err := decodeCloudCatalogObject(nestedRaw, "Discovery nested resources "+id)
			if err != nil {
				return err
			}
			if err := walkDiscoveryResources(model, nested, pointer+"/"+cloudCatalogEscapePointer(name)+"/resources", id, authSchemeIDs, resources, operations); err != nil {
				return err
			}
		}
	}
	return nil
}

func addDiscoveryMethods(model PinnedCloudModel, methods map[string]json.RawMessage, pointer, resourceID string, authSchemeIDs []string, operations map[string]*CloudCatalogOperation) error {
	for _, name := range sortedCloudCatalogKeys(methods) {
		method, err := decodeCloudCatalogObject(methods[name], "Discovery method "+name)
		if err != nil {
			return err
		}
		id, err := cloudCatalogString(method, "id", "Discovery method "+name)
		if err != nil {
			return err
		}
		if _, exists := operations[id]; exists {
			return fmt.Errorf("duplicate Discovery operation id %q", id)
		}
		status := cloudCatalogAssociationUnresolved
		resourceIDs := []string(nil)
		if resourceID != "" {
			status = cloudCatalogAssociationDocumented
			resourceIDs = []string{resourceID}
		}
		operation := &CloudCatalogOperation{ID: id, Locator: cloudCatalogModelLocator(model, pointer+"/"+cloudCatalogEscapePointer(name)), ResourceIDs: resourceIDs, AssociationStatus: status, RawJSON: cloneCloudCatalogRaw(methods[name])}
		if scopesRaw, exists := method["scopes"]; exists {
			var scopes []string
			if err := json.Unmarshal(scopesRaw, &scopes); err != nil {
				return fmt.Errorf("Discovery method %q scopes must be string array", id)
			}
			if len(authSchemeIDs) == 0 {
				return fmt.Errorf("Discovery method %q scopes have no documented authentication scheme", id)
			}
			operation.AuthenticationRequirementIDs = append([]string(nil), authSchemeIDs...)
			operation.AuthenticationScopeReferences = uniqueCloudCatalogStrings(scopes)
		}
		operations[id] = operation
	}
	return nil
}

func discoveryAuthentication(model PinnedCloudModel, root map[string]json.RawMessage) ([]CloudCatalogAuthenticationRequirement, error) {
	authRaw, exists := root["auth"]
	if !exists {
		return nil, nil
	}
	auth, err := decodeCloudCatalogObject(authRaw, "Discovery document.auth")
	if err != nil {
		return nil, err
	}
	result := []CloudCatalogAuthenticationRequirement{}
	for _, id := range sortedCloudCatalogKeys(auth) {
		item, err := decodeCloudCatalogObject(auth[id], "Discovery authentication "+id)
		if err != nil {
			return nil, err
		}
		requirement := CloudCatalogAuthenticationRequirement{ID: id, RequirementReferences: []string{id}, Locator: cloudCatalogModelLocator(model, "/auth/"+cloudCatalogEscapePointer(id))}
		if scopesRaw, exists := item["scopes"]; exists {
			scopes, err := decodeCloudCatalogObject(scopesRaw, "Discovery auth scopes "+id)
			if err != nil {
				return nil, err
			}
			requirement.ScopeReferences = sortedCloudCatalogKeys(scopes)
		}
		result = append(result, requirement)
	}
	return result, nil
}

func applyCloudCatalogResourceDeclarations(model PinnedCloudModel, resources map[string]*CloudCatalogResource) error {
	seen := map[string]struct{}{}
	for _, declaration := range model.ResourceDeclarations {
		if _, duplicate := seen[declaration.ResourceID]; duplicate {
			return fmt.Errorf("duplicate resource declaration %q", declaration.ResourceID)
		}
		seen[declaration.ResourceID] = struct{}{}
		if _, exists := resources[declaration.ResourceID]; exists {
			return fmt.Errorf("resource declaration duplicates native or documented model resource %q", declaration.ResourceID)
		}
		resources[declaration.ResourceID] = &CloudCatalogResource{
			ID:                         declaration.ResourceID,
			Locator:                    declaration.StructureLocator,
			DeclarationStatus:          cloudCatalogAssociationAsserted,
			DeclarationEvidenceLocator: cloudCatalogLocatorPointer(declaration.EvidenceLocator),
		}
	}
	return nil
}

func applyCloudCatalogAssertions(model PinnedCloudModel, resources map[string]*CloudCatalogResource, operations map[string]*CloudCatalogOperation) error {
	seen := map[string]struct{}{}
	for _, assertion := range model.ResourceOperationAssertions {
		key := assertion.ResourceID + "\x00" + assertion.OperationID
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate resource-operation assertion %q/%q", assertion.ResourceID, assertion.OperationID)
		}
		seen[key] = struct{}{}
		resource := resources[assertion.ResourceID]
		operation := operations[assertion.OperationID]
		if resource == nil || operation == nil {
			return fmt.Errorf("resource-operation assertion names unknown resource or operation %q/%q", assertion.ResourceID, assertion.OperationID)
		}
		if operation.AssociationStatus == cloudCatalogAssociationDocumented {
			return fmt.Errorf("resource-operation assertion duplicates documented model association %q/%q", assertion.ResourceID, assertion.OperationID)
		}
		resource.OperationIDs = uniqueCloudCatalogStrings(append(resource.OperationIDs, operation.ID))
		operation.ResourceIDs = uniqueCloudCatalogStrings(append(operation.ResourceIDs, resource.ID))
		operation.ResourceAssociationEvidence = append(operation.ResourceAssociationEvidence, CloudCatalogResourceAssociationEvidence{ResourceID: resource.ID, EvidenceLocator: assertion.EvidenceLocator})
		operation.AssociationStatus = cloudCatalogAssociationAsserted
	}
	for _, resource := range resources {
		resource.OperationIDs = uniqueCloudCatalogStrings(resource.OperationIDs)
	}
	return nil
}

func cloudCatalogLocatorPointer(locator CloudCatalogEvidenceLocator) *CloudCatalogEvidenceLocator {
	copy := locator
	return &copy
}
