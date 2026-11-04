package providerplan

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestEC2NeutralV3ProjectsInstanceAndVolume(t *testing.T) {
	request, err := loadCloudNeutralV3Service(t, "aws", "ec2")
	if err != nil {
		t.Fatal(err)
	}
	var instance, volume CloudSourceObjectTarget
	var catalog CloudCatalog
	for _, target := range request.Targets {
		if target.SourceObjectType == "com.amazonaws.ec2#Instance" {
			instance = target
		}
		if target.SourceObjectType == "com.amazonaws.ec2#Volume" {
			volume = target
		}
		if foundCatalog, ok := findCloudCandidateCatalog(request.Catalogs, target); ok {
			catalog = foundCatalog
		}
	}
	if instance.MappingContract == nil || volume.MappingContract == nil {
		t.Fatal("EC2 v3 instance or volume target missing")
	}
	bindings := []CloudNeutralScopedBinding{}
	for native, opaque := range map[string]string{
		"i-ec2-accepted": "neutral-instance", "vol-ec2-accepted": "neutral-volume",
		"vol-boot-v3": "neutral-boot-volume", "m7i.large": "neutral-compute-type",
		"us-east-1a": "neutral-zone", "111122223333": "neutral-owner", "gp3": "neutral-volume-type",
		"sg-bound": "neutral-group",
	} {
		bindings = append(bindings, CloudNeutralScopedBinding{ScopeReference: "ec2-v3-scope", ScopedNativeKey: native, OpaqueNeutralID: opaque})
	}
	instanceRecipe := ec2V3Recipe(catalog, instance, "/DescribeInstancesResponse/reservationSet/item/instancesSet/item", "/InstanceId", bindings)
	volumeRecipe := ec2V3Recipe(catalog, volume, "/DescribeVolumesResponse/volumeSet/item", "/VolumeId", bindings)
	instanceRaw := []byte(`<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-ec2-accepted</instanceId><architecture>x86_64</architecture><groupSet><item><groupId>sg-bound</groupId><groupName>web</groupName></item></groupSet><bootMode>uefi</bootMode><instanceType>m7i.large</instanceType><launchTime>2026-01-02T03:04:05.000Z</launchTime><instanceState><code>16</code><name>running</name></instanceState><blockDeviceMapping><item><deviceName>/dev/xvda</deviceName><ebs><volumeId>vol-boot-v3</volumeId><status>attached</status><attachTime>2026-01-02T03:04:05.000Z</attachTime><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMapping></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`)
	volumeRaw := []byte(`<DescribeVolumesResponse><volumeSet><item><volumeId>vol-ec2-accepted</volumeId><ownerId>111122223333</ownerId><availabilityZone>us-east-1a</availabilityZone><size>20</size><volumeType>gp3</volumeType><iops>3000</iops><throughput>125</throughput><status>in-use</status><attachmentSet><item><instanceId>i-ec2-accepted</instanceId><volumeId>vol-ec2-accepted</volumeId><device>/dev/xvda</device><status>attached</status><attachTime>2026-01-02T03:04:05.000Z</attachTime><deleteOnTermination>true</deleteOnTermination></item></attachmentSet></item></volumeSet></DescribeVolumesResponse>`)
	instanceResult, err := ProjectCloudNeutralResponse(instanceRecipe, instanceRaw)
	if err != nil || len(instanceResult.Records) != 1 {
		t.Fatalf("EC2 v3 instance=%#v err=%v", instanceResult, err)
	}
	volumeResult, err := ProjectCloudNeutralResponse(volumeRecipe, volumeRaw)
	if err != nil || len(volumeResult.Records) != 1 {
		t.Fatalf("EC2 v3 volume=%#v err=%v", volumeResult, err)
	}
	var instanceRecord, volumeRecord map[string]any
	if err := json.Unmarshal(instanceResult.Records[0], &instanceRecord); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(volumeResult.Records[0], &volumeRecord); err != nil {
		t.Fatal(err)
	}
	if instanceRecord["semantic_record_instance_identity"] != "neutral-instance" || volumeRecord["semantic_record_instance_identity"] != "neutral-volume" {
		t.Fatal("native key substituted for scoped identity")
	}
	for _, want := range []string{"neutral-boot-volume", "neutral-group"} {
		if !bytes.Contains(instanceResult.Records[0], []byte(want)) {
			t.Errorf("missing scoped item %s", want)
		}
	}
	for _, secret := range []string{"sg-bound", "vol-boot-v3", "111122223333"} {
		if bytes.Contains(instanceResult.Records[0], []byte(secret)) || bytes.Contains(volumeResult.Records[0], []byte(secret)) {
			t.Errorf("unresolved relationship key %s", secret)
		}
	}
	assertField := func(field, want string) {
		t.Helper()
		got, err := json.Marshal(volumeRecord[field])
		if err != nil || string(got) != want {
			t.Errorf("%s = %s, want %s", field, got, want)
		}
	}
	assertField("reported_volume_io_rate", `{"state":"present","value":{"amount":"3000","basis":"provisioned","unit":"iops"}}`)
	assertField("provisioned_throughput_bytes_per_second", `{"state":"present","unit":"bytes_per_second","value":"131072000"}`)
	foreign := volumeRecipe
	foreign.Bindings = []CloudNeutralScopedBinding{{ScopeReference: "other", ScopedNativeKey: "vol-ec2-accepted", OpaqueNeutralID: "neutral-volume"}, {ScopeReference: "other", ScopedNativeKey: "i-ec2-accepted", OpaqueNeutralID: "neutral-instance"}}
	if _, err := ProjectCloudNeutralResponse(foreign, volumeRaw); err == nil {
		t.Fatal("foreign EC2 scope bindings accepted")
	}
	badIOPS := bytes.Replace(volumeRaw, []byte(`<iops>3000</iops>`), []byte(`<iops>-1</iops>`), 1)
	if bytes.Equal(badIOPS, volumeRaw) {
		t.Fatal("EC2 IOPS hostile did not change the fixture")
	}
	if _, err := ProjectCloudNeutralResponse(volumeRecipe, badIOPS); err == nil {
		t.Fatal("negative EC2 IOPS accepted")
	}
}

func ec2V3Recipe(catalog CloudCatalog, target CloudSourceObjectTarget, object, identity string, bindings []CloudNeutralScopedBinding) CloudNeutralProjectionRecipe {
	return CloudNeutralProjectionRecipe{Catalog: catalog, Target: &target, Contract: *target.MappingContract, ObjectPointer: object, IdentitySourcePointer: identity, IdentitySourceFieldID: target.StableIdentitySourceFields[0], ScopeReference: "ec2-v3-scope", ObservationState: "observed", Coverage: CloudSyntheticCoverageComplete, RecordTemplate: cloudNeutralV3Template(target.MappingContract.Neutral), Bindings: bindings}
}
