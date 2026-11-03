package providerplan

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestCloudCheckedMiBPerSecondToBytesPerSecond(t *testing.T) {
	if got, err := cloudCheckedMiBPerSecondToBytesPerSecond(json.Number("125")); err != nil || got != "131072000" {
		t.Fatalf("MiB/s conversion got=%q err=%v", got, err)
	}
	for _, value := range []any{json.Number("-1"), json.Number("1.5"), json.Number("18446744073709551615"), true} {
		if _, err := cloudCheckedMiBPerSecondToBytesPerSecond(value); err == nil {
			t.Fatalf("invalid rate %#v accepted", value)
		}
	}
	if _, err := cloudCheckedMiBPerSecondToBytesPerSecondAtMost(json.Number("2147483648"), "2147483647"); err == nil {
		t.Fatal("int32 throughput source value accepted")
	}
}

func TestCloudCanonicalUnsignedDecimalRefusesLossyOrOutOfRangeSourceValues(t *testing.T) {
	for _, value := range []any{json.Number("0"), json.Number("3000"), "9223372036854775807"} {
		if got, err := cloudCanonicalUnsignedDecimal(value); err != nil || got != fmt.Sprint(value) {
			t.Fatalf("canonical integer %#v got=%q err=%v", value, got, err)
		}
	}
	for _, value := range []any{json.Number("01"), json.Number("1.0"), json.Number("1e3"), json.Number("-1"), "18446744073709551616", true} {
		if _, err := cloudCanonicalUnsignedDecimal(value); err == nil {
			t.Fatalf("non-canonical/out-of-range source integer %#v accepted", value)
		}
	}
	if _, err := cloudCanonicalUnsignedDecimalAtMost("9223372036854775808", "9223372036854775807"); err == nil {
		t.Fatal("source int64 upper bound was not enforced")
	}
	if _, err := cloudCanonicalUnsignedDecimalAtMost("2147483648", "2147483647"); err == nil {
		t.Fatal("source int32 upper bound was not enforced")
	}
}

func TestQualifiedIntegerMeasurementClassifiesEC2VolumeIopsWithoutFalseProvisioning(t *testing.T) {
	recipe := &CloudQualifiedIntegerMeasurementRecipe{Unit: "iops", BasisByDiscriminator: map[string]string{"gp2": "baseline", "gp3": "provisioned", "io1": "provisioned", "io2": "provisioned"}}
	for discriminator, wantBasis := range map[string]string{"gp2": "baseline", "gp3": "provisioned"} {
		got, err := cloudQualifiedIntegerMeasurementValue(json.Number("3000"), discriminator, "9223372036854775807", recipe)
		if err != nil || got["basis"] != wantBasis || got["amount"] != "3000" || got["unit"] != "iops" {
			t.Fatalf("%s Iops classification got=%#v err=%v", discriminator, got, err)
		}
	}
	for _, discriminator := range []string{"", "standard", "sc1"} {
		if _, err := cloudQualifiedIntegerMeasurementValue(json.Number("3000"), discriminator, "9223372036854775807", recipe); err == nil {
			t.Fatalf("unclassified Iops discriminator %q accepted", discriminator)
		}
	}
	if _, err := cloudQualifiedIntegerMeasurementValue(json.Number("1e3"), "gp3", "9223372036854775807", recipe); err == nil {
		t.Fatal("malformed Iops amount accepted")
	}
}

func TestQualifiedIntegerMeasurementUsesRetainedXMLDiscriminatorCoordinate(t *testing.T) {
	contract := CloudMappingContract{Fields: []CloudMappingContractField{{SourcePointer: "/VolumeType", WirePointer: "/volumeType"}}}
	if got := cloudProjectionWirePointer(contract, "/VolumeType", true); got != "/volumeType" {
		t.Fatalf("XML discriminator pointer = %q, want retained wire coordinate", got)
	}
	if got := cloudProjectionWirePointer(contract, "/VolumeType", false); got != "/VolumeType" {
		t.Fatalf("JSON discriminator pointer = %q, want source coordinate", got)
	}
}
