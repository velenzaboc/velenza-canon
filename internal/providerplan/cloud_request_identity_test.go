package providerplan

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func cloudRequestIdentityTestCatalog(t *testing.T) CloudCatalog {
	t.Helper()
	base := "../../testdata/cloudapi"
	raw, err := os.ReadFile(filepath.Join(base, "candidate-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var input CloudSourceCandidateInput
	if err := json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	item := input.Models[0]
	if item.ServiceID != "s3" {
		t.Fatal("expected retained S3 model")
	}
	item.Raw, err = os.ReadFile(filepath.Join(base, item.ModelPath))
	if err != nil {
		t.Fatal(err)
	}
	for i, path := range item.SupplementalEvidencePaths {
		item.SupplementalEvidence[i].Raw, err = os.ReadFile(filepath.Join(base, path))
		if err != nil {
			t.Fatal(err)
		}
	}
	// This fixture is explicitly an unqualified resource/operation assertion;
	// the member selector below is independently bound to the full AWS model.
	const body = `{"assertion":{"resource_id":"com.amazonaws.s3#Bucket","operation_id":"com.amazonaws.s3#GetBucketVersioning"}}`
	start, end, err := cloudCatalogJSONPointerSpan([]byte(body), "/assertion")
	if err != nil {
		t.Fatal(err)
	}
	item.SupplementalEvidence = append(item.SupplementalEvidence, CloudCatalogSupplementalEvidence{ID: "request-test-association", Source: CloudCatalogSourceIdentity{ID: "request-test-association", URI: "urn:test:request-identity-association", StableCoordinate: "request-identity-association", FormatRevision: "1"}, Raw: []byte(body), ExpectedSHA256: sha256Hex([]byte(body))})
	found := false
	for _, a := range item.ResourceOperationAssertions {
		if a.OperationID == "com.amazonaws.s3#GetBucketVersioning" {
			found = true
		}
	}
	if !found {
		item.ResourceOperationAssertions = append(item.ResourceOperationAssertions, CloudCatalogResourceOperationAssertion{ResourceID: "com.amazonaws.s3#Bucket", OperationID: "com.amazonaws.s3#GetBucketVersioning", EvidenceLocator: CloudCatalogEvidenceLocator{EvidenceID: "request-test-association", JSONPointer: "/assertion", StartByte: start, EndByte: end}})
	}
	catalog, err := ParsePinnedCloudModel(item.PinnedCloudModel)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func TestCloudPrivateIdentityBindingsNeverSerialize(t *testing.T) {
	bindings := []CloudNeutralScopedBinding{
		{ScopeReference: "opaque-scope", ScopedNativeKey: "private-bucket-key", OpaqueNeutralID: "opaque-container"},
		{ScopeReference: "opaque-scope", ScopedNativeKey: "private-attachment-instance-key", OpaqueNeutralID: "opaque-instance"},
	}
	recipe := CloudNeutralProjectionRecipe{Bindings: bindings, RequestIdentity: &CloudNeutralRequestBinding{Parameters: map[string]string{"Bucket": "private-request-key"}}}
	for _, value := range []any{recipe, recipe.RequestIdentity, bindings, bindings[0], bindings[1]} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, private := range []string{"private-bucket-key", "private-attachment-instance-key", "private-request-key", "scoped_native_key", "parameters"} {
			if bytes.Contains(raw, []byte(private)) {
				t.Fatalf("private lookup material serialized: %s", private)
			}
		}
	}
}

func TestCloudRequestIdentityBindsActualOperationInputAndScope(t *testing.T) {
	catalog := cloudRequestIdentityTestCatalog(t)
	locator, err := CloudIdentityMemberEvidenceLocator(catalog, "com.amazonaws.s3#GetBucketVersioningRequest", "Bucket")
	if err != nil {
		t.Fatal(err)
	}
	makeTarget := func() CloudSourceObjectTarget {
		return CloudSourceObjectTarget{SourceObjectType: "com.amazonaws.s3#Bucket", OperationID: "com.amazonaws.s3#GetBucketVersioning", MappingContract: &CloudMappingContract{OperationID: "com.amazonaws.s3#GetBucketVersioning", ObjectSchemaID: "com.amazonaws.s3#GetBucketVersioningOutput"}, RequestIdentity: &CloudRequestIdentityContract{ResourceID: "com.amazonaws.s3#Bucket", RequestSchemaID: "com.amazonaws.s3#GetBucketVersioningRequest", SourceFieldID: "Bucket", SourcePointer: "/Bucket", Locator: locator}}
	}
	target := makeTarget()
	if err := ValidateCloudSourceIdentityContract(target, catalog); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CloudSourceObjectTarget){
		"wrong input shape": func(t *CloudSourceObjectTarget) {
			t.RequestIdentity.RequestSchemaID = "com.amazonaws.s3#GetBucketEncryptionRequest"
		},
		"response shape as identity": func(t *CloudSourceObjectTarget) { t.SourceObjectType = t.MappingContract.ObjectSchemaID },
		"wrong resource":             func(t *CloudSourceObjectTarget) { t.RequestIdentity.ResourceID = "com.amazonaws.s3#Object" },
		"wrong operation":            func(t *CloudSourceObjectTarget) { t.OperationID = "com.amazonaws.s3#ListBuckets" },
		"another input field":        func(t *CloudSourceObjectTarget) { t.RequestIdentity.SourcePointer = "/ExpectedBucketOwner" },
		"wrong locator":              func(t *CloudSourceObjectTarget) { t.RequestIdentity.Locator.EndByte++ },
		"mixed response key":         func(t *CloudSourceObjectTarget) { t.StableIdentitySourceFields = []string{"Name"} },
		"incarnation assertion":      func(t *CloudSourceObjectTarget) { t.IncarnationEvidenceFields = []string{"CreationDate"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := makeTarget()
			mutate(&candidate)
			if ValidateCloudSourceIdentityContract(candidate, catalog) == nil {
				t.Fatal("hostile request identity accepted")
			}
		})
	}
	makeRecipe := func() CloudNeutralProjectionRecipe {
		return CloudNeutralProjectionRecipe{Catalog: catalog, Target: &target, Contract: *target.MappingContract, ScopeReference: "opaque-scope", RequestIdentity: &CloudNeutralRequestBinding{OperationID: target.OperationID, ResourceID: target.SourceObjectType, ScopeReference: "opaque-scope", Parameters: map[string]string{"Bucket": "private-customer-bucket"}}}
	}
	if err := cloudValidateProjectionIdentity(makeRecipe()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CloudNeutralProjectionRecipe){
		"wrong scope":         func(r *CloudNeutralProjectionRecipe) { r.RequestIdentity.ScopeReference = "other" },
		"wrong op":            func(r *CloudNeutralProjectionRecipe) { r.RequestIdentity.OperationID = "wrong" },
		"wrong resource":      func(r *CloudNeutralProjectionRecipe) { r.RequestIdentity.ResourceID = "wrong" },
		"extra parameter":     func(r *CloudNeutralProjectionRecipe) { r.RequestIdentity.Parameters["Secret"] = "must-not-be-accepted" },
		"missing parameter":   func(r *CloudNeutralProjectionRecipe) { r.RequestIdentity.Parameters = nil },
		"empty key":           func(r *CloudNeutralProjectionRecipe) { r.RequestIdentity.Parameters["Bucket"] = "" },
		"response selector":   func(r *CloudNeutralProjectionRecipe) { r.IdentitySourcePointer = "/Name" },
		"missing acquisition": func(r *CloudNeutralProjectionRecipe) { r.RequestIdentity = nil },
	} {
		t.Run(name, func(t *testing.T) {
			r := makeRecipe()
			mutate(&r)
			if cloudValidateProjectionIdentity(r) == nil {
				t.Fatal("crossed or ambiguous acquisition binding accepted")
			}
		})
	}
	for _, count := range []int{0, 2} {
		if cloudValidateRequestObjectCount(makeRecipe(), count) == nil {
			t.Fatal("request identity applied to zero/multiple objects")
		}
	}
	if err := cloudValidateRequestObjectCount(makeRecipe(), 1); err != nil {
		t.Fatal(err)
	}
	key, err := cloudNeutralResolveIdentity(makeRecipe(), map[string]any{"Status": "Enabled"}, true)
	if err != nil || key != "private-customer-bucket" {
		t.Fatalf("input-bound key: %q %v", key, err)
	}
	for _, value := range []any{makeRecipe(), makeRecipe().RequestIdentity} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte("private-customer-bucket")) || bytes.Contains(raw, []byte(`"Bucket":`)) {
			t.Fatal("private request parameters serialized")
		}
	}
}
