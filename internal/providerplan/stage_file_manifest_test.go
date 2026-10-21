package providerplan

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadStageCompileFileManifestRejectsDuplicateUnknownAndTrailingMembers(t *testing.T) {
	for _, test := range []struct {
		name   string
		raw    string
		needle string
	}{
		{name: "duplicate", raw: `{"request_path":"one","request_path":"two","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`, needle: "duplicate JSON key"},
		{name: "unknown", raw: `{"request_path":"one","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[],"authority_selected":true}`, needle: "unknown field"},
		{name: "trailing", raw: `{"request_path":"one","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]} {}`, needle: "trailing JSON token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			manifestPath := filepath.Join(dir, "inputs.json")
			if err := os.WriteFile(manifestPath, []byte(test.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := LoadStageCompileFileManifest(manifestPath)
			if err == nil || !strings.Contains(err.Error(), test.needle) {
				t.Fatalf("LoadStageCompileFileManifest() error = %v, want %q", err, test.needle)
			}
		})
	}
}

func TestLoadStageCompileFileManifestResolvesRelativeExactFiles(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request.json")
	want := []byte("exact request bytes\n")
	if err := os.WriteFile(requestPath, want, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "inputs.json")
	manifest := []byte(`{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	got, inputs, err := LoadStageCompileFileManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("request bytes = %q, want %q", got, want)
	}
	if len(inputs.PredecessorReceipts) != 0 || len(inputs.Materials) != 0 || len(inputs.EvidenceBodies) != 0 {
		t.Fatalf("unexpected loaded inputs: %+v", inputs)
	}
}

func TestLoadStageCompileFileManifestRejectsPaddedFilePath(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "inputs.json")
	manifest := []byte(`{"request_path":" request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadStageCompileFileManifest(manifestPath); err == nil || !strings.Contains(err.Error(), "padded") {
		t.Fatalf("LoadStageCompileFileManifest() error = %v, want padded-path refusal", err)
	}
}

func TestStageCompileInputAdmissionRejectsOversizedManifestBeforeRead(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "inputs.json")
	manifest := []byte(`{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := canonicalProviderInputAdmissionLimits
	limits.StageInputManifestBytesPerFile = int64(len(manifest) - 1)
	limits.StageInputManifestBytesPerCorpus = int64(len(manifest))
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	hookCalled := false
	accumulator.afterOpenStat = func(string, string) error { hookCalled = true; return nil }
	_, _, _, err = loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err == nil || !strings.Contains(err.Error(), "exceeds per-file limit") {
		t.Fatalf("error = %v, want pre-read stage-manifest limit refusal", err)
	}
	if hookCalled {
		t.Fatal("stage-manifest limit was enforced only after the pre-allocation hook")
	}
}

func TestStageCompileInputAdmissionRejectsOversizedFileBeforeRead(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request.json")
	if err := os.WriteFile(requestPath, []byte("oversized request"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := writeStageInputManifestFixture(t, dir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	limits := canonicalProviderInputAdmissionLimits
	limits.StageInputFileBytesPerFile = 8
	limits.StageInputFileBytesPerCorpus = 16
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	stageFileHookCalled := false
	accumulator.afterOpenStat = func(resourceKind, _ string) error {
		if resourceKind == providerInputAdmissionResourceKindStageFile {
			stageFileHookCalled = true
		}
		return nil
	}
	_, _, _, err = loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err == nil || !strings.Contains(err.Error(), "exceeds per-file limit 8") {
		t.Fatalf("error = %v, want pre-read graph_compile input limit refusal", err)
	}
	if stageFileHookCalled {
		t.Fatal("graph_compile input limit was enforced only after the pre-allocation hook")
	}
}

func TestStageCompileInputAdmissionEnforcesAggregateCorpusBeforeSecondAllocation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte("aaaaaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "predecessor.json"), []byte("bbbbbb"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := writeStageInputManifestFixture(t, dir, `{"request_path":"request.json","predecessor_receipt_paths":["predecessor.json"],"materials":[],"evidence_bodies":[]}`)
	limits := canonicalProviderInputAdmissionLimits
	limits.StageInputFileBytesPerFile = 8
	limits.StageInputFileBytesPerCorpus = 10
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	stageFileHookCount := 0
	accumulator.afterOpenStat = func(resourceKind, _ string) error {
		if resourceKind == providerInputAdmissionResourceKindStageFile {
			stageFileHookCount++
		}
		return nil
	}
	_, _, _, err = loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err == nil || !strings.Contains(err.Error(), "corpus bytes would exceed limit 10") {
		t.Fatalf("error = %v, want aggregate graph_compile corpus refusal", err)
	}
	if stageFileHookCount != 1 {
		t.Fatalf("stage-file pre-allocation hook count = %d, want only the admitted first file", stageFileHookCount)
	}
}

func TestStageCompileInputAdmissionEnforcesWholeRunCountAcrossKinds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte("exact request"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := writeStageInputManifestFixture(t, dir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	limits := canonicalProviderInputAdmissionLimits
	limits.TotalResourceCount = 1
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	stageFileHookCalled := false
	accumulator.afterOpenStat = func(resourceKind, _ string) error {
		if resourceKind == providerInputAdmissionResourceKindStageFile {
			stageFileHookCalled = true
		}
		return nil
	}
	_, _, _, err = loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err == nil || !strings.Contains(err.Error(), "total resource count limit 1") {
		t.Fatalf("error = %v, want whole-run cross-kind count refusal", err)
	}
	if stageFileHookCalled {
		t.Fatal("whole-run count was enforced only after the stage-file pre-allocation hook")
	}
}

func TestStageCompileInputAdmissionEnforcesWholeRunBytesAcrossKinds(t *testing.T) {
	dir := t.TempDir()
	request := []byte("exact request")
	if err := os.WriteFile(filepath.Join(dir, "request.json"), request, 0o600); err != nil {
		t.Fatal(err)
	}
	manifestRaw := `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`
	manifestPath := writeStageInputManifestFixture(t, dir, manifestRaw)
	limits := canonicalProviderInputAdmissionLimits
	limits.TotalResourceBytes = int64(len(manifestRaw) + len(request) - 1)
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	stageFileHookCalled := false
	accumulator.afterOpenStat = func(resourceKind, _ string) error {
		if resourceKind == providerInputAdmissionResourceKindStageFile {
			stageFileHookCalled = true
		}
		return nil
	}
	_, _, _, err = loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err == nil || !strings.Contains(err.Error(), "total resource bytes would exceed limit") {
		t.Fatalf("error = %v, want whole-run cross-kind byte refusal", err)
	}
	if stageFileHookCalled {
		t.Fatal("whole-run bytes were enforced only after the stage-file pre-allocation hook")
	}
}

func TestStageCompileInputAdmissionRejectsTruncationAfterStat(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request.json")
	if err := os.WriteFile(requestPath, []byte("must not be partially admitted"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := writeStageInputManifestFixture(t, dir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	accumulator.afterOpenStat = func(resourceKind, hookPath string) error {
		if resourceKind == providerInputAdmissionResourceKindStageFile {
			return os.Truncate(hookPath, 1)
		}
		return nil
	}
	_, _, _, err := loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err == nil || (!strings.Contains(err.Error(), "unexpected EOF") && !strings.Contains(err.Error(), "changed while being read")) {
		t.Fatalf("error = %v, want deterministic graph_compile truncation refusal", err)
	}
}

func TestStageCompileInputAdmissionRejectsSameLengthMutationAfterStat(t *testing.T) {
	dir := t.TempDir()
	requestPath := filepath.Join(dir, "request.json")
	if err := os.WriteFile(requestPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifestPath := writeStageInputManifestFixture(t, dir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	accumulator.afterOpenStat = func(resourceKind, hookPath string) error {
		if resourceKind != providerInputAdmissionResourceKindStageFile {
			return nil
		}
		if err := os.WriteFile(hookPath, []byte("mutated!"), 0o600); err != nil {
			return err
		}
		future := time.Now().Add(time.Hour)
		return os.Chtimes(hookPath, future, future)
	}
	_, _, _, err := loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
	if err == nil || !strings.Contains(err.Error(), "changed while being read") {
		t.Fatalf("error = %v, want deterministic same-length mutation refusal", err)
	}
}

func TestWholeRunStageInputAdmissionSealsExactlyFourManifests(t *testing.T) {
	manifestPaths, expectedManifestBytes, expectedFileBytes := writeStageInputManifestSetFixture(t, t.TempDir(), exactWholeRunStageManifestCount)
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	bindings, err := loadStageInputManifestSetWithAdmission(manifestPaths, accumulator)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != exactWholeRunStageManifestCount {
		t.Fatalf("loaded stage count = %d, want %d", len(bindings), exactWholeRunStageManifestCount)
	}
	proof, err := accumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	for index := range bindings {
		if err := bindAndValidateStageCompileInputAdmission(&bindings[index], proof, accumulator.resources); err != nil {
			t.Fatalf("bind stage %d to shared whole-run proof: %v", index, err)
		}
	}
	if proof.Actuals.StageInputManifestCount != exactWholeRunStageManifestCount || proof.Actuals.StageInputFileCount != exactWholeRunStageManifestCount {
		t.Fatalf("whole-run stage input counts = %+v", proof.Actuals)
	}
	if proof.Actuals.StageInputManifestBytes != expectedManifestBytes || proof.Actuals.StageInputFileBytes != expectedFileBytes {
		t.Fatalf("whole-run stage input bytes = %+v, want manifests=%d files=%d", proof.Actuals, expectedManifestBytes, expectedFileBytes)
	}
}

func TestWholeRunStageInputAdmissionRejectsFifthManifestBeforeItsFiles(t *testing.T) {
	paths, _, _ := writeStageInputManifestSetFixture(t, t.TempDir(), exactWholeRunStageManifestCount+1)
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	for index, path := range paths {
		_, _, _, err := loadStageCompileFileManifestWithAdmission(path, accumulator)
		if index < exactWholeRunStageManifestCount {
			if err != nil {
				t.Fatalf("load stage manifest %d: %v", index, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "count would exceed limit 4") {
			t.Fatalf("fifth manifest error = %v, want count refusal", err)
		}
		return
	}
	t.Fatal("fixture did not exercise a fifth stage manifest")
}

func TestWholeRunStageInputAdmissionEnforcesAggregateCountsAndBytes(t *testing.T) {
	manifestPaths, _, expectedFileBytes := writeStageInputManifestSetFixture(t, t.TempDir(), exactWholeRunStageManifestCount)

	t.Run("count", func(t *testing.T) {
		limits := canonicalProviderInputAdmissionLimits
		limits.StageInputFileCount = exactWholeRunStageManifestCount - 1
		accumulator, err := newProviderInputAdmissionAccumulator(limits)
		if err != nil {
			t.Fatal(err)
		}
		_, err = loadStageInputManifestSetWithAdmission(manifestPaths, accumulator)
		if err == nil || !strings.Contains(err.Error(), "path count") {
			t.Fatalf("error = %v, want aggregate stage-input count refusal", err)
		}
	})

	t.Run("bytes", func(t *testing.T) {
		limits := canonicalProviderInputAdmissionLimits
		limits.StageInputFileBytesPerFile = expectedFileBytes - 1
		limits.StageInputFileBytesPerCorpus = expectedFileBytes - 1
		accumulator, err := newProviderInputAdmissionAccumulator(limits)
		if err != nil {
			t.Fatal(err)
		}
		_, err = loadStageInputManifestSetWithAdmission(manifestPaths, accumulator)
		if err == nil || !strings.Contains(err.Error(), "corpus bytes would exceed limit") {
			t.Fatalf("error = %v, want aggregate stage-input byte refusal", err)
		}
	})
}

func TestWholeRunStageInputAdmissionIsOrderPathAndMtimeIndependent(t *testing.T) {
	load := func(root string, reverse bool, modTime time.Time) (providerInputAdmissionProof, string) {
		t.Helper()
		paths, _, _ := writeStageInputManifestSetFixture(t, root, exactWholeRunStageManifestCount)
		for _, path := range paths {
			if err := os.Chtimes(path, modTime, modTime); err != nil {
				t.Fatal(err)
			}
		}
		if reverse {
			for left, right := 0, len(paths)-1; left < right; left, right = left+1, right-1 {
				paths[left], paths[right] = paths[right], paths[left]
			}
		}
		accumulator := newCanonicalProviderInputAdmissionAccumulator()
		bindings, err := loadStageInputManifestSetWithAdmission(paths, accumulator)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := accumulator.seal()
		if err != nil {
			t.Fatal(err)
		}
		bindingResources := make([]providerInputAdmissionResourceReceipt, 0)
		for index := range bindings {
			if err := bindAndValidateStageCompileInputAdmission(&bindings[index], proof, accumulator.resources); err != nil {
				t.Fatal(err)
			}
			bindingResources = append(bindingResources, bindings[index].resources()...)
		}
		bindingRoot, err := providerInputAdmissionResourceSetRoot(bindingResources)
		if err != nil {
			t.Fatal(err)
		}
		return proof, bindingRoot
	}
	firstProof, firstRoot := load(t.TempDir(), false, time.Unix(1_700_000_000, 0))
	secondProof, secondRoot := load(t.TempDir(), true, time.Unix(1_800_000_000, 0))
	if firstProof != secondProof || firstRoot != secondRoot {
		t.Fatalf("path/order/mtime changed whole-run admission identity:\nfirst=%+v/%s\nsecond=%+v/%s", firstProof, firstRoot, secondProof, secondRoot)
	}
}

func TestWholeRunStageInputAdmissionRejectsDuplicatePathAndIdentity(t *testing.T) {
	t.Run("manifest path", func(t *testing.T) {
		paths, _, _ := writeStageInputManifestSetFixture(t, t.TempDir(), exactWholeRunStageManifestCount)
		paths[3] = paths[0]
		_, err := loadStageInputManifestSetWithAdmission(paths, newCanonicalProviderInputAdmissionAccumulator())
		if err == nil || !strings.Contains(err.Error(), "duplicate path or file identity") {
			t.Fatalf("error = %v, want duplicate manifest path refusal", err)
		}
	})

	t.Run("declared file path", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "shared.json"), []byte("one object"), 0o600); err != nil {
			t.Fatal(err)
		}
		manifestPath := writeStageInputManifestFixture(t, dir, `{"request_path":"shared.json","predecessor_receipt_paths":["shared.json"],"materials":[],"evidence_bodies":[]}`)
		_, _, err := LoadStageCompileFileManifest(manifestPath)
		if err == nil || !strings.Contains(err.Error(), "duplicate declared path") {
			t.Fatalf("error = %v, want duplicate declared path refusal", err)
		}
	})

	t.Run("content identity", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "request.json"), []byte("same bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "predecessor.json"), []byte("same bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		manifestPath := writeStageInputManifestFixture(t, dir, `{"request_path":"request.json","predecessor_receipt_paths":["predecessor.json"],"materials":[],"evidence_bodies":[]}`)
		_, _, err := LoadStageCompileFileManifest(manifestPath)
		if err == nil || !strings.Contains(err.Error(), "duplicate resource identity") {
			t.Fatalf("error = %v, want duplicate content identity refusal", err)
		}
	})
}

func TestStageCompileInputAdmissionRootIsDeterministicAndPathIndependent(t *testing.T) {
	load := func(dir string) (providerInputAdmissionProof, stageCompileInputAdmissionBinding, []byte) {
		t.Helper()
		want := []byte("exact request bytes\r\n")
		if err := os.WriteFile(filepath.Join(dir, "request.json"), want, 0o600); err != nil {
			t.Fatal(err)
		}
		manifestPath := writeStageInputManifestFixture(t, dir, `{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)
		accumulator := newCanonicalProviderInputAdmissionAccumulator()
		got, _, binding, err := loadStageCompileFileManifestWithAdmission(manifestPath, accumulator)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := accumulator.seal()
		if err != nil {
			t.Fatal(err)
		}
		if err := bindAndValidateStageCompileInputAdmission(&binding, proof, accumulator.resources); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("request bytes = %q, want exact %q", got, want)
		}
		if proof.Actuals.StageInputManifestCount != 1 || proof.Actuals.StageInputFileCount != 1 ||
			binding.Items[0].Resource.ContentSHA256 != sha256Hex([]byte(`{"request_path":"request.json","predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`)) ||
			binding.Items[1].Resource.ContentSHA256 != sha256Hex(want) {
			t.Fatalf("stage admission does not preserve exact manifest/request hashes: proof=%+v binding=%+v", proof, binding)
		}
		return proof, binding, got
	}
	firstProof, firstBinding, _ := load(t.TempDir())
	secondProof, secondBinding, _ := load(t.TempDir())
	if firstProof != secondProof || firstBinding.ResourceSetRootSHA256 != secondBinding.ResourceSetRootSHA256 {
		t.Fatalf("path-equal stage corpora produced different admission identities:\nfirst=%+v\nsecond=%+v", firstProof, secondProof)
	}
	firstBinding.Items[1].Raw = append(bytes.Clone(firstBinding.Items[1].Raw), '!')
	if err := bindAndValidateStageCompileInputAdmission(&firstBinding, firstProof, firstBinding.resources()); err == nil {
		t.Fatal("stage bytes mutated after admission were accepted")
	}
}

func loadStageInputManifestSetWithAdmission(paths []string, accumulator *providerInputAdmissionAccumulator) ([]stageCompileInputAdmissionBinding, error) {
	bindings := make([]stageCompileInputAdmissionBinding, 0, len(paths))
	for _, path := range paths {
		_, _, binding, err := loadStageCompileFileManifestWithAdmission(path, accumulator)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func writeStageInputManifestSetFixture(t *testing.T, root string, count int) ([]string, int64, int64) {
	t.Helper()
	paths := make([]string, 0, count)
	var manifestBytes int64
	var fileBytes int64
	for index := 0; index < count; index++ {
		dir := filepath.Join(root, fmt.Sprintf("stage-%d", index))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		requestName := fmt.Sprintf("request-%d.json", index)
		request := []byte(fmt.Sprintf("exact stage request %d\n", index))
		if err := os.WriteFile(filepath.Join(dir, requestName), request, 0o600); err != nil {
			t.Fatal(err)
		}
		manifest := fmt.Sprintf(`{"request_path":%q,"predecessor_receipt_paths":[],"materials":[],"evidence_bodies":[]}`, requestName)
		manifestPath := writeStageInputManifestFixture(t, dir, manifest)
		paths = append(paths, manifestPath)
		manifestBytes += int64(len(manifest))
		fileBytes += int64(len(request))
	}
	return paths, manifestBytes, fileBytes
}

func writeStageInputManifestFixture(t *testing.T, dir, raw string) string {
	t.Helper()
	manifestPath := filepath.Join(dir, "inputs.json")
	if err := os.WriteFile(manifestPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath
}
