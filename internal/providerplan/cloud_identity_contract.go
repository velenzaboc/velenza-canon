package providerplan

import (
	"encoding/json"
	"fmt"
)

// CloudIdentityMemberEvidenceLocator returns the exact original-model member
// range for an explicitly proposed private lookup key. It establishes which
// documented field the proposal refers to, not immutable identity, ownership,
// an incarnation, or permission to allocate an OHM identity.
// Precondition: catalog is the unchanged result of ParsePinnedCloudModel.
// A caller-authored catalog is unqualified input; this helper does not seal or
// independently authenticate its shape bytes against an original model body.
func CloudIdentityMemberEvidenceLocator(catalog CloudCatalog, objectID, fieldID string) (CloudCatalogEvidenceLocator, error) {
	shape, ok := cloudCatalogShape(catalog, objectID)
	if !ok || shape.Locator.EvidenceID != "model" || shape.Locator.StartByte < 0 || shape.Locator.EndByte-shape.Locator.StartByte != len(shape.RawJSON) {
		return CloudCatalogEvidenceLocator{}, fmt.Errorf("identity object has no exact retained model range")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(shape.RawJSON, &object); err != nil {
		return CloudCatalogEvidenceLocator{}, fmt.Errorf("identity object is invalid")
	}
	container := "properties"
	if _, smithy := object["members"]; smithy {
		container = "members"
	}
	localPointer := "/" + container + "/" + cloudCatalogEscapePointer(fieldID)
	start, end, err := cloudCatalogJSONPointerSpan(shape.RawJSON, localPointer)
	if err != nil {
		return CloudCatalogEvidenceLocator{}, fmt.Errorf("identity field is not a direct retained object member")
	}
	return CloudCatalogEvidenceLocator{
		EvidenceID: "model", JSONPointer: shape.Locator.JSONPointer + localPointer,
		StartByte: shape.Locator.StartByte + start, EndByte: shape.Locator.StartByte + end,
	}, nil
}

// ValidateCloudSourceIdentityContract binds a candidate's private lookup-key
// proposal to its selected object's exact member evidence. The offline form
// deliberately has no incarnation-proof authority. Later qualification and
// the OHM owner must establish identity and any incarnation separately.
func ValidateCloudSourceIdentityContract(target CloudSourceObjectTarget, catalog CloudCatalog) error {
	if target.MappingContract == nil || target.SourceObjectType != target.MappingContract.ObjectSchemaID {
		return fmt.Errorf("identity object must equal the mapping's selected object schema")
	}
	if len(target.IncarnationEvidenceFields) != 0 {
		return fmt.Errorf("offline lookup-key candidates cannot assert incarnation proof")
	}
	if len(target.StableIdentitySourceFields) == 0 || len(target.StableIdentitySourceFields) != len(target.StableIdentityEvidence) {
		return fmt.Errorf("every private lookup-key field needs exact member evidence")
	}
	byField := map[string]CloudSourceIdentityEvidence{}
	for _, evidence := range target.StableIdentityEvidence {
		if evidence.SemanticRole != "scoped_native_lookup_key" {
			return fmt.Errorf("offline identity evidence must be a scoped lookup-key proposal")
		}
		if _, duplicate := byField[evidence.SourceFieldID]; duplicate {
			return fmt.Errorf("duplicate identity evidence")
		}
		byField[evidence.SourceFieldID] = evidence
	}
	seen := map[string]bool{}
	for _, fieldID := range target.StableIdentitySourceFields {
		if fieldID == "" || seen[fieldID] {
			return fmt.Errorf("private lookup-key fields must be nonempty and unique")
		}
		seen[fieldID] = true
		evidence, exists := byField[fieldID]
		if !exists {
			return fmt.Errorf("private lookup-key member evidence is missing")
		}
		want, err := CloudIdentityMemberEvidenceLocator(catalog, target.SourceObjectType, fieldID)
		if err != nil {
			return err
		}
		if evidence.Locator != want {
			return fmt.Errorf("private lookup-key evidence does not equal its exact model member range")
		}
	}
	return nil
}
