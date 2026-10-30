package providerplan

import (
	"os"
	"testing"
)

func TestCloudIdentityEvidenceBindsExactOfficialModelMember(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/official/aws/s3-2006-03-01.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ParsePinnedCloudModel(PinnedCloudModel{
		Format:     CloudCatalogFormatSmithyJSON,
		Source:     CloudCatalogSourceIdentity{ID: "official-s3", URI: "https://raw.githubusercontent.com/aws/api-models-aws/d6bbb4d64e2c82927834dfa9791bebc0000f70c0/models/s3/service/2006-03-01/s3-2006-03-01.json", StableCoordinate: "d6bbb4d64e2c82927834dfa9791bebc0000f70c0/s3", FormatRevision: "2.0"},
		ProviderID: "aws", ServiceID: "s3", APISurfaceID: "s3", APIVersion: "2006-03-01", Raw: raw,
		ExpectedSHA256: "73e4f75747396176053a0fcc910261cf670c7e133c1cebcfffefa703fad3ce68",
	})
	if err != nil {
		t.Fatal(err)
	}
	locator, err := CloudIdentityMemberEvidenceLocator(catalog, "com.amazonaws.s3#Bucket", "Name")
	if err != nil {
		t.Fatal(err)
	}
	start, end, err := cloudCatalogJSONPointerSpan(raw, "/shapes/com.amazonaws.s3#Bucket/members/Name")
	if err != nil || locator.StartByte != start || locator.EndByte != end {
		t.Fatalf("derived member range does not equal full original model: %+v %d:%d %v", locator, start, end, err)
	}
	base := CloudSourceObjectTarget{SourceObjectType: "com.amazonaws.s3#Bucket", MappingContract: &CloudMappingContract{ObjectSchemaID: "com.amazonaws.s3#Bucket"}, StableIdentitySourceFields: []string{"Name"}, StableIdentityEvidence: []CloudSourceIdentityEvidence{{SourceFieldID: "Name", SemanticRole: "scoped_native_lookup_key", Locator: locator}}}
	if err := ValidateCloudSourceIdentityContract(base, catalog); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*CloudSourceObjectTarget)
	}{
		{"missing range", func(v *CloudSourceObjectTarget) {
			v.StableIdentityEvidence[0].Locator.StartByte = 0
			v.StableIdentityEvidence[0].Locator.EndByte = 0
		}},
		{"imprecise range", func(v *CloudSourceObjectTarget) { v.StableIdentityEvidence[0].Locator.EndByte++ }},
		{"another member", func(v *CloudSourceObjectTarget) {
			v.StableIdentityEvidence[0].Locator.JSONPointer = "/shapes/com.amazonaws.s3#Bucket/members/CreationDate"
		}},
		{"wrong evidence", func(v *CloudSourceObjectTarget) { v.StableIdentityEvidence[0].Locator.EvidenceID = "unbound" }},
		{"incarnation claim", func(v *CloudSourceObjectTarget) {
			v.StableIdentityEvidence[0].SemanticRole = "immutable_incarnation_proof"
		}},
		{"incarnation roster", func(v *CloudSourceObjectTarget) { v.IncarnationEvidenceFields = []string{"CreationDate"} }},
		{"wrong object", func(v *CloudSourceObjectTarget) { v.SourceObjectType = "com.amazonaws.s3#Object" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			candidate.StableIdentityEvidence = append([]CloudSourceIdentityEvidence(nil), base.StableIdentityEvidence...)
			tc.mutate(&candidate)
			if ValidateCloudSourceIdentityContract(candidate, catalog) == nil {
				t.Fatal("invalid identity proposal accepted")
			}
		})
	}
}
