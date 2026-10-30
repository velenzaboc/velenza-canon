package providerplan

import (
	"bytes"
	"os"
	"testing"
)

// awsEC2AcceptanceCases deliberately carries target contracts separately from
// candidate-input.json.  The test loads the latter first (including its pinned
// models and neutral owner schema), then substitutes only the two EC2 targets.
// That prevents a reduced hand-made catalog from masquerading as acceptance.
type awsEC2AcceptanceCases struct {
	Targets []CloudSourceObjectTarget `json:"targets"`
}

func loadAWSEC2AcceptanceTargets(t *testing.T) []CloudSourceObjectTarget {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/cloudapi/cases/aws-ec2.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases awsEC2AcceptanceCases
	if err := strictUnmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases.Targets) != 2 {
		t.Fatalf("EC2 cases must carry exactly Instance and Volume targets, got %d", len(cases.Targets))
	}
	return cases.Targets
}

func TestCloudCaseAWSEC2OfflineAcceptance(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	ec2Targets := loadAWSEC2AcceptanceTargets(t)
	for _, replacement := range ec2Targets {
		replaced := false
		for i := range request.Targets {
			if request.Targets[i].ProviderID == "aws" && request.Targets[i].ServiceID == "ec2" && request.Targets[i].SourceObjectType == replacement.SourceObjectType {
				// The owner schema is loaded at the real candidate boundary, never
				// copied into a case file.
				replacement.MappingContract.Neutral = request.Targets[i].MappingContract.Neutral
				if err := LoadCloudMappingEvidence("../../testdata/cloudapi", replacement.MappingContract); err != nil {
					t.Fatal(err)
				}
				replacement.RecordClassContractRef = request.Targets[i].RecordClassContractRef
				request.Targets[i] = replacement
				replaced = true
				break
			}
		}
		if !replaced {
			t.Fatalf("case target %s has no candidate target to replace", replacement.SourceObjectType)
		}
	}

	var instance, volume CloudSourceObjectTarget
	var ec2 CloudCatalog
	for _, target := range request.Targets {
		if target.ProviderID == "aws" && target.ServiceID == "ec2" {
			if target.SourceObjectType == "com.amazonaws.ec2#Instance" {
				instance = target
			}
			if target.SourceObjectType == "com.amazonaws.ec2#Volume" {
				volume = target
			}
		}
	}
	for _, catalog := range request.Catalogs {
		if catalog.ProviderID == "aws" && catalog.ServiceID == "ec2" {
			ec2 = catalog
		}
	}
	if instance.MappingContract == nil || volume.MappingContract == nil || ec2.ProviderID == "" {
		t.Fatal("retained EC2 catalog or case targets missing")
	}
	for _, target := range []CloudSourceObjectTarget{instance, volume} {
		if err := ValidateCloudSourceIdentityContract(target, ec2); err != nil {
			t.Fatalf("identity %s: %v", target.SourceObjectType, err)
		}
		if err := ValidateCloudMappingContract(ec2, *target.MappingContract); err != nil {
			t.Fatalf("mapping %s: %v", target.SourceObjectType, err)
		}
	}

	instanceXML := []byte(`<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-ec2-accepted</instanceId><instanceType>m7i.large</instanceType><launchTime>2026-01-02T03:04:05.000Z</launchTime><instanceState><code>48</code><name>terminated</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`)
	volumeXML := []byte(`<DescribeVolumesResponse><volumeSet><item><volumeId>vol-ec2-accepted</volumeId><size>20</size><status>in-use</status><attachmentSet><item><instanceId>i-ec2-accepted</instanceId><volumeId>vol-ec2-accepted</volumeId><device>/dev/xvda</device><status>attached</status><attachTime>2026-01-02T03:04:05.000Z</attachTime><deleteOnTermination>true</deleteOnTermination><associatedResource>arn:aws:ec2:us-east-1:123456789012:instance/i-ec2-accepted</associatedResource><ebsCardIndex>0</ebsCardIndex><instanceOwningService>ec2</instanceOwningService></item></attachmentSet></item></volumeSet></DescribeVolumesResponse>`)

	instanceRecipe := CloudNeutralProjectionRecipe{Catalog: ec2, Target: &instance, Contract: *instance.MappingContract, ObjectPointer: "/DescribeInstancesResponse/reservationSet/item/instancesSet/item", IdentitySourcePointer: "/InstanceId", IdentitySourceFieldID: "InstanceId", ScopeReference: "scope-ec2", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RecordTemplate: cloudEC2InstanceTemplate(), Bindings: []CloudNeutralScopedBinding{{ScopeReference: "scope-ec2", ScopedNativeKey: "i-ec2-accepted", OpaqueNeutralID: "instance-neutral"}}}
	volumeRecipe := CloudNeutralProjectionRecipe{Catalog: ec2, Target: &volume, Contract: *volume.MappingContract, ObjectPointer: "/DescribeVolumesResponse/volumeSet/item", IdentitySourcePointer: "/VolumeId", IdentitySourceFieldID: "VolumeId", ScopeReference: "scope-ec2", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RecordTemplate: cloudEC2VolumeTemplate(), Bindings: []CloudNeutralScopedBinding{{ScopeReference: "scope-ec2", ScopedNativeKey: "vol-ec2-accepted", OpaqueNeutralID: "volume-neutral"}, {ScopeReference: "scope-ec2", ScopedNativeKey: "i-ec2-accepted", OpaqueNeutralID: "instance-neutral"}}}

	instanceResult, err := ProjectCloudNeutralResponse(instanceRecipe, instanceXML)
	if err != nil || len(instanceResult.Records) != 1 || instanceResult.DeletionAuthorized {
		t.Fatalf("terminated EC2 instance projection = %#v, %v", instanceResult, err)
	}
	volumeResult, err := ProjectCloudNeutralResponse(volumeRecipe, volumeXML)
	if err != nil || len(volumeResult.Records) != 1 || volumeResult.DeletionAuthorized {
		t.Fatalf("attached EC2 volume projection = %#v, %v", volumeResult, err)
	}
	if !bytes.Contains(instanceResult.Records[0], []byte(`"terminated"`)) || !bytes.Contains(volumeResult.Records[0], []byte(`"21474836480"`)) || !bytes.Contains(volumeResult.Records[0], []byte(`"instance-neutral"`)) {
		t.Fatalf("EC2 mapped facts missing: %s / %s", instanceResult.Records[0], volumeResult.Records[0])
	}

	unknown := bytes.Replace(instanceXML, []byte(`>terminated<`), []byte(`>future-state<`), 1)
	if _, err := ProjectCloudNeutralResponse(instanceRecipe, unknown); err == nil {
		t.Fatal("unknown EC2 lifecycle enum accepted")
	}
	tooMany := bytes.Replace(volumeXML, []byte(`</attachmentSet>`), []byte(`<item><instanceId>i-other</instanceId></item></attachmentSet>`), 1)
	if _, err := ProjectCloudNeutralResponse(volumeRecipe, tooMany); err == nil {
		t.Fatal("multi-attachment volume accepted")
	}
	empty := bytes.Replace(volumeXML, []byte(`<attachmentSet><item><instanceId>i-ec2-accepted</instanceId><volumeId>vol-ec2-accepted</volumeId><device>/dev/xvda</device><status>attached</status><attachTime>2026-01-02T03:04:05.000Z</attachTime><deleteOnTermination>true</deleteOnTermination><associatedResource>arn:aws:ec2:us-east-1:123456789012:instance/i-ec2-accepted</associatedResource><ebsCardIndex>0</ebsCardIndex><instanceOwningService>ec2</instanceOwningService></item></attachmentSet>`), []byte(`<attachmentSet/>`), 1)
	if _, err := ProjectCloudNeutralResponse(volumeRecipe, empty); err != nil {
		t.Fatalf("empty attachment collection: %v", err)
	}

	retainedInstance, err := os.ReadFile("../../testdata/cloudapi/fixtures/aws/describe-instances-page-1.xml")
	if err != nil {
		t.Fatal(err)
	}
	retainedTerminated, err := os.ReadFile("../../testdata/cloudapi/fixtures/aws/describe-instances-terminated.xml")
	if err != nil {
		t.Fatal(err)
	}
	retainedVolume, err := os.ReadFile("../../testdata/cloudapi/fixtures/aws/describe-volumes-page-1.xml")
	if err != nil {
		t.Fatal(err)
	}
	retainedInstanceRecipe := instanceRecipe
	retainedInstanceRecipe.Coverage = CloudSyntheticCoveragePartial
	retainedInstanceRecipe.Bindings = append(retainedInstanceRecipe.Bindings, CloudNeutralScopedBinding{ScopeReference: "scope-ec2", ScopedNativeKey: "i-0fixture001", OpaqueNeutralID: "fixture-instance"}, CloudNeutralScopedBinding{ScopeReference: "scope-ec2", ScopedNativeKey: "i-0fixtureterminated", OpaqueNeutralID: "fixture-terminated"})
	retainedVolumeRecipe := volumeRecipe
	retainedVolumeRecipe.Coverage = CloudSyntheticCoveragePartial
	retainedVolumeRecipe.Bindings = append(retainedVolumeRecipe.Bindings, CloudNeutralScopedBinding{ScopeReference: "scope-ec2", ScopedNativeKey: "vol-0fixture001", OpaqueNeutralID: "fixture-volume"}, CloudNeutralScopedBinding{ScopeReference: "scope-ec2", ScopedNativeKey: "i-0fixture001", OpaqueNeutralID: "fixture-instance"})
	for name, recipeAndWire := range map[string]struct {
		recipe CloudNeutralProjectionRecipe
		wire   []byte
	}{"retained running instance": {retainedInstanceRecipe, retainedInstance}, "retained terminated instance": {retainedInstanceRecipe, retainedTerminated}, "retained attached volume": {retainedVolumeRecipe, retainedVolume}} {
		result, projectErr := ProjectCloudNeutralResponse(recipeAndWire.recipe, recipeAndWire.wire)
		if projectErr != nil || len(result.Records) != 1 || result.DeletionAuthorized {
			t.Fatalf("%s = %#v, %v", name, result, projectErr)
		}
	}
}

func cloudEC2InstanceTemplate() map[string]any {
	return map[string]any{"record_class": "compute_instance", "display_name": cloudUnknown(), "scope_reference": cloudUnknown(), "location_class": cloudUnknown(), "lifecycle_state": cloudUnknown(), "machine_class": cloudUnknown(), "platform_family": cloudUnknown(), "reported_creation_time": cloudUnknown()}
}

func cloudEC2VolumeTemplate() map[string]any {
	return map[string]any{"record_class": "compute_volume", "display_name": cloudUnknown(), "scope_reference": cloudUnknown(), "location_class": cloudUnknown(), "lifecycle_state": cloudUnknown(), "capacity_bytes": cloudUnknown(), "storage_class": cloudUnknown(), "encryption_configuration_observation": cloudUnknown(), "attached_compute_instance_reference": cloudUnknown()}
}
