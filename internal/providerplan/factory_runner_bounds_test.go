package providerplan

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestFactoryRunnerBoundsBuildPinsSettingsAndCollections(t *testing.T) {
	pins := currentFactoryReleaseBuildPins()
	if pins.SourceRosterSHA256 != factoryReleaseSourceRosterSHA256 || pins.GoToolchainFiles != parseFactoryReleaseCount(factoryReleaseGoToolchainFiles) || pins.GitToolchainBytes != parseFactoryReleaseCount(factoryReleaseGitToolchainBytes) {
		t.Fatalf("release pins do not preserve their exact generated coordinates: %#v", pins)
	}
	for _, test := range []struct {
		value string
		want  int64
	}{{"1", 1}, {"0002", 2}, {"0", 0}, {"-1", 0}, {"bad", 0}} {
		if got := parseFactoryReleaseCount(test.value); got != test.want {
			t.Fatalf("count %q=%d want %d", test.value, got, test.want)
		}
	}
	settings, err := exactFactoryBuildSettings([]debug.BuildSetting{{Key: "GOARCH", Value: "amd64"}, {Key: "GOOS", Value: "windows"}, {Key: "-tags", Value: factoryReleaseBuildTag}})
	if err != nil || len(settings) != 3 || settings[0].Key != "-tags" {
		t.Fatalf("canonical build settings=%#v err=%v", settings, err)
	}
	if _, err := exactFactoryBuildSettings([]debug.BuildSetting{{Key: "GOOS", Value: "windows"}, {Key: "GOOS", Value: "linux"}}); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate build setting error=%v", err)
	}
	if _, err := exactFactoryBuildSettings([]debug.BuildSetting{{Key: "GODEBUG", Value: "x"}}); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported build setting error=%v", err)
	}
	stages := []factoryLoadedStage{{inputs: StageCompileInputs{EvidenceBodies: []StageEvidenceBody{{Raw: []byte("body")}}, Materials: []StageMaterial{{Role: "role", ID: "id", Version: "v1", Raw: []byte("material")}}}}, {inputs: StageCompileInputs{}}}
	if retainedFactoryEvidenceCollections(stages) != 1 || retainedFactoryMaterialCollections(stages) != 1 {
		t.Fatalf("retained collection counts evidence=%d material=%d", retainedFactoryEvidenceCollections(stages), retainedFactoryMaterialCollections(stages))
	}
}

func TestFactoryRunnerBoundsExecutionIdentityAndObservedHashesFailClosed(t *testing.T) {
	tool := testFactoryToolIdentity()
	execution := testFactoryExecutionIdentity(tool)
	if err := validateFactoryExecutionIdentity(execution, tool); err != nil {
		t.Fatalf("valid execution identity: %v", err)
	}
	tampered := execution
	tampered.TargetOS = "linux"
	if err := validateFactoryExecutionIdentity(tampered, tool); err == nil || !strings.Contains(err.Error(), "release build profile") {
		t.Fatalf("target substitution error=%v", err)
	}
	tampered = execution
	tampered.BuildSettings[0].Value = "tampered"
	if err := validateFactoryExecutionIdentity(tampered, tool); err == nil {
		t.Fatal("build-setting tamper accepted")
	}
	resources := []providerInputAdmissionResourceReceipt{
		{ResourceKind: providerInputAdmissionResourceKindArtifact, ContentSHA256: strings.Repeat("b", 64)},
		{ResourceKind: providerInputAdmissionResourceKindManifest, ContentSHA256: strings.Repeat("c", 64)},
		{ResourceKind: providerInputAdmissionResourceKindArtifact, ContentSHA256: strings.Repeat("a", 64)},
	}
	hashes := factoryObservedResourceHashes(resources, providerInputAdmissionResourceKindArtifact)
	if len(hashes) != 2 || hashes[0] != strings.Repeat("a", 64) || hashes[1] != strings.Repeat("b", 64) {
		t.Fatalf("observed artifact hashes=%v", hashes)
	}
	if !equalFactoryStrings([]string{"a", "b"}, []string{"a", "b"}) || equalFactoryStrings([]string{"a"}, []string{"b"}) {
		t.Fatal("exact factory string equality changed")
	}
}
