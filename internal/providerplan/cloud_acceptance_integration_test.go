package providerplan

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The CLI input is the composition of the independently exercised service
// cases, so a later edit cannot silently leave production-shaped input stale.
func TestCloudInputComposesTheFourServiceCases(t *testing.T) {
	readTargets := func(path string) []any {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Targets []any `json:"targets"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		return body.Targets
	}
	var expected []any
	for _, name := range []string{"aws-s3", "aws-ec2", "gcp-storage", "gcp-compute"} {
		expected = append(expected, readTargets("../../testdata/cloudapi/cases/"+name+".json")...)
	}
	if !reflect.DeepEqual(readTargets("../../testdata/cloudapi/candidate-input.json"), expected) {
		t.Fatal("CLI targets differ from the four exercised service cases")
	}
}

// This is deliberately a real-input integration guard. Small synthetic shape
// tests cannot establish that every field in the selected provider objects is
// representable (including enum, map, list and structured fields).
func TestCloudSelectedOperationsCloseAgainstRetainedModels(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"aws/s3/com.amazonaws.s3#ListBuckets":          "storage_container",
		"aws/s3/com.amazonaws.s3#GetBucketVersioning":  "storage_container",
		"aws/s3/com.amazonaws.s3#GetBucketEncryption":  "storage_container",
		"aws/s3/com.amazonaws.s3#GetPublicAccessBlock": "storage_container",
		"aws/ec2/com.amazonaws.ec2#DescribeInstances":  "compute_instance",
		"aws/ec2/com.amazonaws.ec2#DescribeVolumes":    "compute_volume",
		"gcp/storage/storage.buckets.list":             "storage_container",
		"gcp/compute/compute.instances.aggregatedList": "compute_instance",
		"gcp/compute/compute.disks.aggregatedList":     "compute_volume",
	}
	if len(request.Catalogs) != 4 || len(request.Targets) != len(want) {
		t.Fatalf("need four complete pinned models and nine operation targets, got %d/%d", len(request.Catalogs), len(request.Targets))
	}
	for _, target := range request.Targets {
		key := target.ProviderID + "/" + target.ServiceID + "/" + target.OperationID
		class, found := want[key]
		if !found || class != target.RecordClassSymbol {
			t.Fatalf("unexpected or repeated selected object %s -> %s", key, target.RecordClassSymbol)
		}
		delete(want, key)
		catalog, found := findCloudCandidateCatalog(request.Catalogs, target)
		if !found || target.MappingContract == nil {
			t.Fatalf("selected object %s has no catalog/contract", key)
		}
		fields, err := cloudCatalogObjectFields(catalog, target.MappingContract.ObjectSchemaID)
		if err != nil || len(fields) == 0 {
			t.Fatalf("actual source object %s cannot derive its complete field roster: %v", key, err)
		}
		if err := ValidateCloudMappingContract(catalog, *target.MappingContract); err != nil {
			t.Fatalf("actual selected model contract %s: %v", key, err)
		}
		if err := ValidateCloudSourceIdentityContract(target, catalog); err != nil {
			t.Fatalf("identity closure %s: %v", key, err)
		}
		// This test proves complete checked disposition, not that unsupported
		// fields have become mapped capabilities. Record outcomes have their
		// separate wire-fixture conformance tests.
		t.Logf("%s: %d actual direct source fields, class %s", key, len(fields), class)
	}
}
