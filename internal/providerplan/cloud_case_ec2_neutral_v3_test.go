package providerplan

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCloudCaseAWSEC2NeutralV3ClosesPriorUnsupportedRoster(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/aws-ec2.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Targets []CloudSourceObjectTarget `json:"targets"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"com.amazonaws.ec2#DescribeInstances": 62, "com.amazonaws.ec2#DescribeVolumes": 31}
	for _, target := range doc.Targets {
		if target.MappingContract == nil || target.ProviderID != "aws" || target.ServiceID != "ec2" {
			t.Fatalf("bad successor target %#v", target)
		}
		fields := cloudNeutralProjectionFields(*target.MappingContract)
		if len(fields) != want[target.OperationID] {
			t.Fatalf("%s fields = %d", target.OperationID, len(fields))
		}
		for _, field := range fields {
			if field.Disposition == CloudSourceUnsupported {
				t.Fatalf("unsupported successor field %s", field.SourcePointer)
			}
		}
	}
}

func TestCloudCaseAWSEC2NeutralV3TagsUseClosedPairs(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/neutral-v3/aws-ec2.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Targets []CloudSourceObjectTarget `json:"targets"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, target := range doc.Targets {
		var tags CloudMappingContractField
		for _, field := range target.MappingContract.Fields {
			if field.SourcePointer == "/Tags" {
				tags = field
			}
		}
		if tags.TargetField != "labels" || tags.StructuredRecipe == nil || (tags.StructuredRecipe.Kind != "key_value_entries" && tags.StructuredRecipe.Kind != "list") {
			t.Fatalf("%s tag recipe = %#v", target.OperationID, tags)
		}
	}
}
