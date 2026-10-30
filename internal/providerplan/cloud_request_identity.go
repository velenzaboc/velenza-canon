package providerplan

// Request identity is an offline acquisition binding for detail/configuration
// operations whose response omits the resource key. It binds the documented
// request member and selected resource/operation; it is neither a synthesized
// response field nor proof that a live request ran. SOURCE/OHM still owns the
// authenticated acquisition, durable identity, and reconciliation boundaries.

import (
	"encoding/json"
	"fmt"
	"reflect"
)

type CloudRequestIdentityContract struct {
	ResourceID      string                      `json:"resource_id"`
	RequestSchemaID string                      `json:"request_schema_id"`
	SourceFieldID   string                      `json:"source_field_id"`
	SourcePointer   string                      `json:"source_pointer"`
	Locator         CloudCatalogEvidenceLocator `json:"locator"`
}

// CloudNeutralRequestBinding carries only the selected private lookup-key
// parameter, never credentials or an arbitrary request body. Each fixture
// response is explicitly associated with one operation, resource, and scope.
type CloudNeutralRequestBinding struct {
	OperationID    string            `json:"operation_id"`
	ResourceID     string            `json:"resource_id"`
	ScopeReference string            `json:"scope_reference"`
	Parameters     map[string]string `json:"-"`
}

func validateCloudRequestIdentityContract(target CloudSourceObjectTarget, catalog CloudCatalog) error {
	request := target.RequestIdentity
	if request == nil || target.MappingContract == nil || target.MappingContract.OperationID != target.OperationID {
		return fmt.Errorf("request identity requires the selected operation and mapping contract")
	}
	if len(target.StableIdentitySourceFields) != 0 || len(target.StableIdentityEvidence) != 0 || len(target.IncarnationEvidenceFields) != 0 {
		return fmt.Errorf("request identity cannot be mixed with response-key or incarnation claims")
	}
	if request.ResourceID == "" || target.SourceObjectType != request.ResourceID {
		return fmt.Errorf("request identity must retain the source resource type, not its response representation")
	}
	op, ok := findCloudCatalogOperation(catalog, target.OperationID)
	if !ok || op.AssociationStatus == cloudCatalogAssociationUnresolved {
		return fmt.Errorf("request identity operation has no resource association")
	}
	associated := false
	for _, id := range op.ResourceIDs {
		if id == request.ResourceID {
			associated = true
		}
	}
	declared := false
	for _, resource := range catalog.Resources {
		if resource.ID == request.ResourceID {
			declared = true
		}
	}
	if !associated || !declared {
		return fmt.Errorf("request identity resource is not the declared operation resource")
	}
	// Smithy input is explicit model evidence. Discovery path/query parameters
	// need a separately owned parameter selector; a matching field name alone
	// is not permission to reuse this input-shape proof.
	if catalog.Format != CloudCatalogFormatSmithyJSON {
		return fmt.Errorf("request identity requires a documented input-shape model")
	}
	var operation struct {
		Input struct {
			Target string `json:"target"`
		} `json:"input"`
	}
	if err := json.Unmarshal(op.RawJSON, &operation); err != nil || operation.Input.Target == "" || operation.Input.Target != request.RequestSchemaID {
		return fmt.Errorf("request identity schema is not the selected operation input")
	}
	fields, err := cloudCatalogObjectFields(catalog, request.RequestSchemaID)
	if err != nil {
		return err
	}
	field, ok := fields[request.SourcePointer]
	if !ok || field.ID != request.SourceFieldID || field.Cardinality != "one" || field.ValueType != "string" {
		return fmt.Errorf("request identity is not one exact string input member")
	}
	want, err := CloudIdentityMemberEvidenceLocator(catalog, request.RequestSchemaID, request.SourceFieldID)
	if err != nil || request.Locator != want {
		return fmt.Errorf("request identity evidence differs from the exact input member range")
	}
	return nil
}

func cloudValidateProjectionIdentity(recipe CloudNeutralProjectionRecipe) error {
	if recipe.Target == nil || recipe.Target.MappingContract == nil || !reflect.DeepEqual(*recipe.Target.MappingContract, recipe.Contract) {
		return fmt.Errorf("projection requires the exact target-bound mapping contract")
	}
	if err := ValidateCloudSourceIdentityContract(*recipe.Target, recipe.Catalog); err != nil {
		return fmt.Errorf("target identity evidence: %w", err)
	}
	if request := recipe.Target.RequestIdentity; request != nil {
		binding := recipe.RequestIdentity
		if binding == nil || recipe.IdentitySourcePointer != "" || recipe.IdentitySourceFieldID != "" {
			return fmt.Errorf("request identity requires one request binding and no response selector")
		}
		if binding.OperationID != recipe.Contract.OperationID || binding.ResourceID != request.ResourceID || binding.ScopeReference != recipe.ScopeReference {
			return fmt.Errorf("request binding crosses operation, resource, or scope")
		}
		key, ok := binding.Parameters[request.SourceFieldID]
		if !ok || key == "" || len(binding.Parameters) != 1 {
			return fmt.Errorf("request binding must contain exactly its documented nonempty lookup parameter")
		}
		return nil
	}
	if recipe.RequestIdentity != nil {
		return fmt.Errorf("response identity cannot consume an uncontracted request binding")
	}
	identityField, found := cloudNeutralContractField(recipe.Contract, recipe.IdentitySourceFieldID)
	if !found || identityField.SourcePointer != recipe.IdentitySourcePointer || (identityField.Disposition != CloudSourcePrivateOnly && identityField.TargetField != "display_name") {
		return fmt.Errorf("identity selector must be a validated private field or the mapped display-name scoped key")
	}
	for _, id := range recipe.Target.StableIdentitySourceFields {
		if id == recipe.IdentitySourceFieldID {
			return nil
		}
	}
	return fmt.Errorf("identity selector is not target-documented")
}

func cloudValidateRequestObjectCount(recipe CloudNeutralProjectionRecipe, count int) error {
	if recipe.Target != nil && recipe.Target.RequestIdentity != nil && count != 1 {
		return fmt.Errorf("one request-bound resource observation requires exactly one response object")
	}
	return nil
}

func cloudNeutralResolveIdentity(recipe CloudNeutralProjectionRecipe, object map[string]any, xmlWire bool) (string, error) {
	if request := recipe.Target.RequestIdentity; request != nil {
		return recipe.RequestIdentity.Parameters[request.SourceFieldID], nil
	}
	pointer := recipe.IdentitySourcePointer
	if xmlWire {
		fields, err := cloudCatalogObjectFields(recipe.Catalog, recipe.Contract.ObjectSchemaID)
		if err != nil {
			return "", err
		}
		pointer = fields[pointer].WirePointer
	}
	value, state, err := resolveCloudSyntheticPointer(object, pointer)
	if err != nil || state != "present" {
		return "", fmt.Errorf("identity source key is %s", state)
	}
	key, ok := value.(string)
	if !ok || key == "" {
		return "", fmt.Errorf("identity source key is not a nonempty string")
	}
	return key, nil
}
