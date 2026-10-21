package providerplan

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderInputAdmissionResidentBoundPreservesEveryRetainedCorpusCeiling(t *testing.T) {
	want := maxStageInputManifestBytesPerCorpus +
		maxStageInputFileBytesPerCorpus +
		maxEvidenceManifestBytesPerCorpus +
		maxDependencyArtifactBytesPerCorpus +
		maxVerificationAuthorityBytesPerCorpus +
		maxEvidenceBodyBytesPerCorpus
	if maxProviderInputResidentSnapshotBytes != want {
		t.Fatalf("resident snapshot ceiling = %d, want exact retained-corpus sum %d", maxProviderInputResidentSnapshotBytes, want)
	}
	if maxProviderInputResidentSnapshotBytes >= maxProviderInputAdmissionResourceBytes {
		t.Fatalf("resident snapshot ceiling = %d, want structurally below logical resource ceiling %d because carriers stream", maxProviderInputResidentSnapshotBytes, maxProviderInputAdmissionResourceBytes)
	}
	if maxEvidenceCarrierBytesPerCorpus <= 0 || maxProviderInputResidentSnapshotBytes+maxEvidenceCarrierBytesPerCorpus <= maxProviderInputAdmissionResourceBytes {
		t.Fatal("test premise requires a carrier corpus large enough to prove it is excluded from retained heap accounting")
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	accumulator.residentInputBytes = maxProviderInputResidentSnapshotBytes
	if err := accumulator.checkResidentInputBytes(0); err != nil {
		t.Fatalf("exact retained snapshot boundary was rejected: %v", err)
	}
	if err := accumulator.checkResidentInputBytes(1); err == nil || !strings.Contains(err.Error(), "retained snapshot bytes would exceed limit") {
		t.Fatalf("resident snapshot boundary+1 error = %v, want deterministic pre-allocation refusal", err)
	}
}

func TestProviderInputAdmissionRejectsDeclaredEvidenceBodyBeforeAllocation(t *testing.T) {
	fixture := newTestFixture(t)
	mutateJSONLRow(t, fixture.evidencePath, "external_evidence_body", func(row map[string]interface{}) {
		row["component_byte_length"] = json.Number("9")
		row["content_bytes"] = json.Number("9")
	})
	mutateJSONLRow(t, fixture.evidencePath, "validation_summary", func(row map[string]interface{}) {
		row["total_exact_source_bytes"] = json.Number("9")
	})
	limits := canonicalProviderInputAdmissionLimits
	limits.EvidenceBodyBytesPerFile = 8
	limits.EvidenceBodyBytesPerCorpus = 8
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	hookCalled := false
	accumulator.afterOpenStat = func(resourceKind, path string) error {
		if resourceKind == providerInputAdmissionResourceKindCarrier {
			hookCalled = true
		}
		return nil
	}
	_, err = loadEvidenceBodiesWithAdmission([]string{fixture.evidencePath}, map[string]struct{}{supportedEvidenceRepresentationKind: {}}, accumulator)
	if err == nil || !strings.Contains(err.Error(), "evidence_decoded_body byte length 9 exceeds per-file limit 8") {
		t.Fatalf("error = %v, want declared decoded-body limit refusal", err)
	}
	if hookCalled {
		t.Fatal("declared decoded-body limit was enforced only after the pre-allocation hook")
	}
}

func TestProviderInputAdmissionRejectsOversizedManifestAndDependencyBeforeRead(t *testing.T) {
	t.Run("manifest", func(t *testing.T) {
		fixture := newTestFixture(t)
		info, err := os.Stat(fixture.evidencePath)
		if err != nil {
			t.Fatal(err)
		}
		limits := canonicalProviderInputAdmissionLimits
		limits.EvidenceManifestBytesPerFile = info.Size() - 1
		limits.EvidenceManifestBytesPerCorpus = info.Size()
		accumulator, err := newProviderInputAdmissionAccumulator(limits)
		if err != nil {
			t.Fatal(err)
		}
		hookCalled := false
		accumulator.afterOpenStat = func(string, string) error { hookCalled = true; return nil }
		_, err = loadEvidenceBodiesWithAdmission([]string{fixture.evidencePath}, map[string]struct{}{supportedEvidenceRepresentationKind: {}}, accumulator)
		if err == nil || !strings.Contains(err.Error(), "exceeds per-file limit") {
			t.Fatalf("error = %v, want pre-read manifest limit refusal", err)
		}
		if hookCalled {
			t.Fatal("manifest limit was enforced only after the pre-allocation hook")
		}
	})

	t.Run("dependency", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authority.md")
		if err := os.WriteFile(path, []byte("exact dependency bytes"), 0o600); err != nil {
			t.Fatal(err)
		}
		limits := canonicalProviderInputAdmissionLimits
		limits.DependencyArtifactBytesPerFile = 8
		limits.DependencyArtifactBytesPerCorpus = 16
		accumulator, err := newProviderInputAdmissionAccumulator(limits)
		if err != nil {
			t.Fatal(err)
		}
		hookCalled := false
		accumulator.afterOpenStat = func(string, string) error { hookCalled = true; return nil }
		_, err = readArtifactInputWithAdmission(path, accumulator)
		if err == nil || !strings.Contains(err.Error(), "exceeds per-file limit 8") {
			t.Fatalf("error = %v, want pre-read dependency limit refusal", err)
		}
		if hookCalled {
			t.Fatal("dependency limit was enforced only after the pre-allocation hook")
		}
	})
}

func TestProviderInputAdmissionRechecksOpenedSizeBeforeAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.md")
	if err := os.WriteFile(path, []byte("tiny"), 0o600); err != nil {
		t.Fatal(err)
	}
	limits := canonicalProviderInputAdmissionLimits
	limits.DependencyArtifactBytesPerFile = 8
	limits.DependencyArtifactBytesPerCorpus = 8
	limits.TotalResourceBytes = 8
	limits.ResidentSnapshotBytes = 8
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	grewBeforeHandleStat := false
	accumulator.afterOpenBeforeStat = func(resourceKind, hookPath string) error {
		if resourceKind != providerInputAdmissionResourceKindArtifact {
			return fmt.Errorf("hook resource kind = %q, want dependency artifact", resourceKind)
		}
		grewBeforeHandleStat = true
		return os.WriteFile(hookPath, []byte("ninebytes"), 0o600)
	}
	reachedPreallocationHook := false
	accumulator.afterOpenStat = func(string, string) error {
		reachedPreallocationHook = true
		return nil
	}
	_, err = readBoundedProviderInputFile(path, "dependency", providerInputAdmissionResourceKindArtifact, "dependency|growth-race", accumulator)
	if err == nil || !strings.Contains(err.Error(), "exceeds per-file limit 8") {
		t.Fatalf("opened-handle growth error = %v, want authoritative opened-size refusal", err)
	}
	if !grewBeforeHandleStat {
		t.Fatal("same-inode growth hook was not called between open and handle stat")
	}
	if reachedPreallocationHook {
		t.Fatal("opened-handle size was rechecked only after the preallocation hook")
	}
	if accumulator.residentInputBytes != 0 || accumulator.residentInputPeak != 0 || accumulator.actuals.DependencyArtifactBytes != 0 || accumulator.actuals.TotalResourceBytes != 0 {
		t.Fatalf("oversized opened handle changed admission accounting before refusal: %+v", accumulator.actuals)
	}
}

func TestProviderInputAdmissionEnforcesAggregateDependencyCorpus(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.md")
	second := filepath.Join(dir, "second.md")
	if err := os.WriteFile(first, []byte("aaaaaa"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("bbbbbb"), 0o600); err != nil {
		t.Fatal(err)
	}
	limits := canonicalProviderInputAdmissionLimits
	limits.DependencyArtifactBytesPerFile = 8
	limits.DependencyArtifactBytesPerCorpus = 10
	limits.TotalResourceBytes = 10
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadDependencyArtifactsWithAdmission([]string{first, second}, accumulator)
	if err == nil || !strings.Contains(err.Error(), "corpus bytes would exceed limit 10") {
		t.Fatalf("error = %v, want aggregate dependency-corpus refusal", err)
	}
}

func TestProviderInputAdmissionEnforcesCorpusCountBeforeOpeningInputs(t *testing.T) {
	limits := canonicalProviderInputAdmissionLimits
	limits.DependencyArtifactCount = 1
	accumulator, err := newProviderInputAdmissionAccumulator(limits)
	if err != nil {
		t.Fatal(err)
	}
	hookCalled := false
	accumulator.afterOpenStat = func(string, string) error { hookCalled = true; return nil }
	_, err = loadDependencyArtifactsWithAdmission([]string{"does-not-need-to-exist-a", "does-not-need-to-exist-b"}, accumulator)
	if err == nil || !strings.Contains(err.Error(), "path count 2 exceeds limit 1") {
		t.Fatalf("error = %v, want corpus-count refusal", err)
	}
	if hookCalled {
		t.Fatal("corpus count was enforced only after an input was opened")
	}
}

func TestProviderInputAdmissionStrictStreamingBase64AndExactBytes(t *testing.T) {
	body := []byte("Copy-all bytes stay exact.\r\n")
	encoded := base64.StdEncoding.EncodeToString(body)

	t.Run("outer ASCII whitespace accepted without changing body", func(t *testing.T) {
		manifestPath, carrierName := writeProviderInputCarrierFixture(t, []byte(" \t\r\n"+encoded+"\n\f "))
		accumulator := newCanonicalProviderInputAdmissionAccumulator()
		decoded, _, err := decodeBoundedRelativeEvidenceStagingFile(
			manifestPath,
			strings.Repeat("a", 64),
			carrierName,
			evidenceSourceCoordinate{Ref: "fixture", URL: "https://example.com/fixture"},
			int64(len(body)),
			sha256Hex(body),
			accumulator,
		)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(decoded, body) {
			t.Fatalf("decoded bytes = %q, want exact %q", decoded, body)
		}
		proof, err := accumulator.seal()
		if err != nil {
			t.Fatal(err)
		}
		if proof.Actuals.EvidenceBodyBytes != int64(len(body)) || proof.Actuals.EvidenceCarrierBytes != int64(len(encoded)+7) || !isLowerSHA256(proof.ResourceSetRootSHA256) {
			t.Fatalf("unexpected exact resource accounting: %+v", proof)
		}
	})

	t.Run("internal whitespace rejected", func(t *testing.T) {
		carrier := encoded[:4] + "\n" + encoded[4:]
		manifestPath, carrierName := writeProviderInputCarrierFixture(t, []byte(carrier))
		_, _, err := decodeBoundedRelativeEvidenceStagingFile(manifestPath, strings.Repeat("b", 64), carrierName, evidenceSourceCoordinate{Ref: "fixture", URL: "https://example.com/fixture"}, int64(len(body)), sha256Hex(body), newCanonicalProviderInputAdmissionAccumulator())
		if err == nil || !strings.Contains(err.Error(), "internal whitespace") {
			t.Fatalf("error = %v, want strict internal-whitespace refusal", err)
		}
	})

	t.Run("outer whitespace is bounded before decode", func(t *testing.T) {
		manifestPath, carrierName := writeProviderInputCarrierFixture(t, []byte("   "+encoded))
		limits := canonicalProviderInputAdmissionLimits
		limits.EvidenceCarrierOuterWhitespace = 2
		accumulator, err := newProviderInputAdmissionAccumulator(limits)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = decodeBoundedRelativeEvidenceStagingFile(manifestPath, strings.Repeat("c", 64), carrierName, evidenceSourceCoordinate{Ref: "fixture", URL: "https://example.com/fixture"}, int64(len(body)), sha256Hex(body), accumulator)
		if err == nil || !strings.Contains(err.Error(), "outer-whitespace limit 2") {
			t.Fatalf("error = %v, want carrier whitespace limit refusal", err)
		}
	})

	t.Run("non-ASCII carrier byte rejected", func(t *testing.T) {
		manifestPath, carrierName := writeProviderInputCarrierFixture(t, append([]byte(encoded), 0xff))
		_, _, err := decodeBoundedRelativeEvidenceStagingFile(manifestPath, strings.Repeat("d", 64), carrierName, evidenceSourceCoordinate{Ref: "fixture", URL: "https://example.com/fixture"}, int64(len(body)), sha256Hex(body), newCanonicalProviderInputAdmissionAccumulator())
		if err == nil || !strings.Contains(err.Error(), "invalid UTF-8") {
			t.Fatalf("error = %v, want non-ASCII carrier refusal", err)
		}
	})

	t.Run("nonzero padding bits rejected", func(t *testing.T) {
		oneByteBody := []byte("f")
		manifestPath, carrierName := writeProviderInputCarrierFixture(t, []byte("Zh=="))
		_, _, err := decodeBoundedRelativeEvidenceStagingFile(manifestPath, strings.Repeat("e", 64), carrierName, evidenceSourceCoordinate{Ref: "fixture", URL: "https://example.com/fixture"}, int64(len(oneByteBody)), sha256Hex(oneByteBody), newCanonicalProviderInputAdmissionAccumulator())
		if err == nil || !strings.Contains(err.Error(), "illegal base64 data") {
			t.Fatalf("error = %v, want strict nonzero-padding-bit refusal", err)
		}
	})
}

func TestProviderInputAdmissionReusesOneDecodedBodyByContentInConstantLookup(t *testing.T) {
	body := []byte("one decoded body shared by two exact source coordinates")
	encoded := []byte(base64.StdEncoding.EncodeToString(body))
	firstManifest, firstCarrier := writeProviderInputCarrierFixture(t, encoded)
	secondManifest, secondCarrier := writeProviderInputCarrierFixture(t, encoded)
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	first, _, err := decodeBoundedRelativeEvidenceStagingFile(
		firstManifest, strings.Repeat("1", 64), firstCarrier,
		evidenceSourceCoordinate{Ref: "first", URL: "https://example.com/first"},
		int64(len(body)), sha256Hex(body), accumulator,
	)
	if err != nil {
		t.Fatal(err)
	}
	residentAfterFirst := accumulator.residentInputBytes
	second, _, err := decodeBoundedRelativeEvidenceStagingFile(
		secondManifest, strings.Repeat("2", 64), secondCarrier,
		evidenceSourceCoordinate{Ref: "second", URL: "https://example.com/second"},
		int64(len(body)), sha256Hex(body), accumulator,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) == 0 || &first[0] != &second[0] {
		t.Fatal("equal decoded bodies did not reuse one retained backing store")
	}
	if accumulator.residentInputBytes != residentAfterFirst || accumulator.residentInputBytes != int64(len(body)) {
		t.Fatalf("retained bytes after duplicate body = %d, want exactly one body (%d)", accumulator.residentInputBytes, len(body))
	}
	if len(accumulator.residentContent) != 1 {
		t.Fatalf("retained content index entries = %d, want 1", len(accumulator.residentContent))
	}
}

func TestProviderInputAdmissionStreamsCarrierAndRevalidatesItsMetadataSnapshot(t *testing.T) {
	body := []byte("streamed carrier bytes are never retained as a second corpus")
	manifestPath, carrierName := writeProviderInputCarrierFixture(t, []byte(base64.StdEncoding.EncodeToString(body)))
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	decoded, carrierPath, err := decodeBoundedRelativeEvidenceStagingFile(
		manifestPath, strings.Repeat("3", 64), carrierName,
		evidenceSourceCoordinate{Ref: "streamed", URL: "https://example.com/streamed"},
		int64(len(body)), sha256Hex(body), accumulator,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatal("streamed decoded body differs from its exact source bytes")
	}
	key := canonicalProviderInputPathKey(carrierPath)
	snapshot := accumulator.physicalSnapshots[key]
	if snapshot == nil || snapshot.retainsBytes || len(snapshot.bytes) != 0 || snapshot.initialTraversalCount != 1 || snapshot.initialTraversalBytes != snapshot.size {
		t.Fatalf("carrier snapshot retained payload bytes or lost its one initial admission traversal: %+v", snapshot)
	}
	replaceFactoryInputWithByteIdenticalFile(t, carrierPath)
	if err := accumulator.revalidatePhysicalSnapshots(); err == nil || !strings.Contains(err.Error(), "changed after its exact physical snapshot") {
		t.Fatalf("streamed carrier final revalidation error = %v, want identity replacement refusal", err)
	}
}

func TestProviderInputAdmissionBoundsStreamedCarrierGrowthAfterOpenedSize(t *testing.T) {
	body := []byte("bounded streamed carrier")
	manifestPath, carrierName := writeProviderInputCarrierFixture(t, []byte(base64.StdEncoding.EncodeToString(body)))
	carrierPath := filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(carrierName))
	openedSize := int64(len(base64.StdEncoding.EncodeToString(body)))
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	hookCalled := false
	accumulator.afterOpenStat = func(resourceKind, hookPath string) error {
		if resourceKind != providerInputAdmissionResourceKindCarrier || hookPath != carrierPath {
			return nil
		}
		file, err := os.OpenFile(hookPath, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(bytes.Repeat([]byte(" "), 1<<20))
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		hookCalled = true
		return closeErr
	}
	_, _, err := decodeBoundedRelativeEvidenceStagingFile(
		manifestPath, strings.Repeat("4", 64), carrierName,
		evidenceSourceCoordinate{Ref: "growth", URL: "https://example.com/growth"},
		int64(len(body)), sha256Hex(body), accumulator,
	)
	wantCount := fmt.Sprintf("read %d bytes, want exact file size %d", openedSize+1, openedSize)
	if err == nil || !strings.Contains(err.Error(), wantCount) {
		t.Fatalf("streamed growth error = %v, want hard opened-size+1 boundary %q", err, wantCount)
	}
	if !hookCalled {
		t.Fatal("streamed carrier growth hook did not run after opened-size validation")
	}
	if len(accumulator.resources) != 0 || len(accumulator.physicalSnapshots) != 0 {
		t.Fatalf("streamed growth refusal admitted resources or snapshots: resources=%d snapshots=%d", len(accumulator.resources), len(accumulator.physicalSnapshots))
	}
}

func TestProviderInputAdmissionRejectsTruncationAfterStat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dependency.md")
	if err := os.WriteFile(path, []byte("must not be partially admitted"), 0o600); err != nil {
		t.Fatal(err)
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	accumulator.afterOpenStat = func(resourceKind, hookPath string) error {
		if resourceKind == providerInputAdmissionResourceKindArtifact {
			return os.Truncate(hookPath, 1)
		}
		return nil
	}
	_, err := readArtifactInputWithAdmission(path, accumulator)
	if err == nil || (!strings.Contains(err.Error(), "unexpected EOF") && !strings.Contains(err.Error(), "changed while being read")) {
		t.Fatalf("error = %v, want deterministic truncation refusal", err)
	}
}

func TestProviderInputAdmissionSharesOnePhysicalSnapshotAcrossLogicalRoles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-input.json")
	raw := []byte("one immutable physical snapshot\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	initialSnapshotOpens := 0
	accumulator.afterOpenStat = func(string, string) error {
		initialSnapshotOpens++
		return nil
	}
	stage, err := readBoundedProviderInputFile(path, "stage material", providerInputAdmissionResourceKindStageFile, "stage_file_v1|fixture", accumulator)
	if err != nil {
		t.Fatal(err)
	}
	accumulator.enableFactorySnapshotAliases()
	if err := accumulator.authorizeFactorySnapshotAlias(path, "verification authority", providerInputAdmissionResourceKindAuthority); err != nil {
		t.Fatal(err)
	}
	authority, err := readBoundedProviderInputFile(path, "verification authority", providerInputAdmissionResourceKindAuthority, "verification_authority_input_v1|fixture", accumulator)
	if err != nil {
		t.Fatal(err)
	}
	if initialSnapshotOpens != 1 {
		t.Fatalf("initial snapshot opens = %d, want exactly 1", initialSnapshotOpens)
	}
	if len(stage.Bytes) == 0 || &stage.Bytes[0] != &authority.Bytes[0] {
		t.Fatal("logical roles did not alias the exact physical snapshot backing store")
	}
	if len(accumulator.physicalSnapshots) != 1 {
		t.Fatalf("physical snapshot count = %d, want 1", len(accumulator.physicalSnapshots))
	}
	for _, snapshot := range accumulator.physicalSnapshots {
		if snapshot.initialTraversalCount != 1 {
			t.Fatalf("snapshot initial admission traversal count = %d, want 1", snapshot.initialTraversalCount)
		}
		if snapshot.initialTraversalBytes != int64(len(raw)) {
			t.Fatalf("snapshot initial admission traversal bytes = %d, want %d", snapshot.initialTraversalBytes, len(raw))
		}
	}
	if err := accumulator.revalidatePhysicalSnapshots(); err != nil {
		t.Fatal(err)
	}
	proof, err := accumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	if proof.Actuals.StageInputFileCount != 1 || proof.Actuals.VerificationAuthorityCount != 1 || proof.Actuals.TotalResourceCount != 2 {
		t.Fatalf("logical role accounting = %+v, want one stage and one authority receipt", proof.Actuals)
	}
}

func TestProviderInputAdmissionRejectsHardlinkAliasAfterOneInitialSnapshotOpen(t *testing.T) {
	dir := t.TempDir()
	originalPath := filepath.Join(dir, "original.json")
	aliasPath := filepath.Join(dir, "alias.json")
	raw := []byte("one physical file must not enter through two lexical paths\n")
	if err := os.WriteFile(originalPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(originalPath, aliasPath); err != nil {
		t.Fatalf("create required hardlink fixture: %v", err)
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	initialSnapshotOpens := 0
	accumulator.afterOpenStat = func(string, string) error {
		initialSnapshotOpens++
		return nil
	}
	if _, err := readBoundedProviderInputFile(originalPath, "first dependency", providerInputAdmissionResourceKindArtifact, "dependency|first", accumulator); err != nil {
		t.Fatal(err)
	}
	_, err := readBoundedProviderInputFile(aliasPath, "second dependency", providerInputAdmissionResourceKindArtifact, "dependency|second", accumulator)
	if err == nil || !strings.Contains(err.Error(), "duplicate path or file identity") {
		t.Fatalf("hardlink alias error = %v, want stable physical-identity refusal", err)
	}
	if initialSnapshotOpens != 1 {
		t.Fatalf("initial snapshot opens = %d, want only the admitted original open", initialSnapshotOpens)
	}
	for _, snapshot := range accumulator.physicalSnapshots {
		if snapshot.initialTraversalCount != 1 || snapshot.initialTraversalBytes != int64(len(raw)) {
			t.Fatalf("retained snapshot initial admission traversal = %d/%d, want 1/%d", snapshot.initialTraversalCount, snapshot.initialTraversalBytes, len(raw))
		}
	}
}

func TestProviderInputAdmissionCompletionRevalidationRejectsByteIdenticalReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	backup := filepath.Join(dir, "original.json")
	replacement := filepath.Join(dir, "replacement.json")
	raw := []byte("byte-identical replacement still has a new physical identity\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	if _, err := readBoundedProviderInputFile(path, "dependency", providerInputAdmissionResourceKindArtifact, "dependency|fixture", accumulator); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := accumulator.revalidatePhysicalSnapshots(); err == nil || !strings.Contains(err.Error(), "changed after its exact physical snapshot") {
		t.Fatalf("completion revalidation error = %v, want byte-identical identity replacement refusal", err)
	}
}

func TestProviderInputAdmissionCompletionRevalidationRejectsRestoredMtimeRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	original := []byte("AAAAAAAAAAAAAAAAAAAAAAAA")
	rewritten := []byte("BBBBBBBBBBBBBBBBBBBBBBBB")
	if len(original) != len(rewritten) {
		t.Fatal("test fixture lengths differ")
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	if _, err := readBoundedProviderInputFile(path, "dependency", providerInputAdmissionResourceKindArtifact, "dependency|fixture", accumulator); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(rewritten, 0); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := accumulator.revalidatePhysicalSnapshots(); err == nil || !strings.Contains(err.Error(), "changed after its exact physical snapshot") {
		t.Fatalf("completion revalidation error = %v, want restored-mtime rewrite refusal", err)
	}
}

func TestProviderInputAdmissionCompletionRevalidationRehashesWhenMetadataMatches(t *testing.T) {
	assertRehashRejects := func(t *testing.T, path string, rewritten []byte, accumulator *providerInputAdmissionAccumulator, wantRetainsBytes bool) {
		t.Helper()
		if err := os.WriteFile(path, rewritten, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		currentInfo, err := file.Stat()
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		currentIdentity, err := stableProviderInputFileIdentity(file)
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		currentToken, err := currentProviderInputMutationToken(file)
		if err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if len(accumulator.physicalSnapshots) != 1 {
			t.Fatalf("physical snapshot count = %d, want 1", len(accumulator.physicalSnapshots))
		}
		for _, snapshot := range accumulator.physicalSnapshots {
			if snapshot.retainsBytes != wantRetainsBytes || (!wantRetainsBytes && len(snapshot.bytes) != 0) {
				t.Fatalf("physical snapshot retainsBytes = %t with %d resident bytes, want retainsBytes %t", snapshot.retainsBytes, len(snapshot.bytes), wantRetainsBytes)
			}
			// Model a filesystem whose metadata cannot distinguish the rewrite. The
			// original content digest remains the independent completion oracle.
			snapshot.openedInfo = currentInfo
			snapshot.fileIdentity = currentIdentity
			snapshot.mutationToken = currentToken
		}
		if err := accumulator.revalidatePhysicalSnapshots(); err == nil || !strings.Contains(err.Error(), "changed after its exact physical snapshot") {
			t.Fatalf("completion revalidation error = %v, want exact-byte rehash refusal", err)
		}
	}

	t.Run("retained", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "input.json")
		original := []byte("AAAAAAAAAAAAAAAAAAAAAAAA")
		rewritten := []byte("BBBBBBBBBBBBBBBBBBBBBBBB")
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		accumulator := newCanonicalProviderInputAdmissionAccumulator()
		if _, err := readBoundedProviderInputFile(path, "dependency", providerInputAdmissionResourceKindArtifact, "dependency|fixture", accumulator); err != nil {
			t.Fatal(err)
		}
		assertRehashRejects(t, path, rewritten, accumulator, true)
	})

	t.Run("streamed", func(t *testing.T) {
		body := []byte("streamed carrier bytes are not retained in a physical snapshot")
		rewrittenBody := bytes.Repeat([]byte{'Z'}, len(body))
		manifestPath, carrierName := writeProviderInputCarrierFixture(t, []byte(base64.StdEncoding.EncodeToString(body)))
		accumulator := newCanonicalProviderInputAdmissionAccumulator()
		_, carrierPath, err := decodeBoundedRelativeEvidenceStagingFile(
			manifestPath, strings.Repeat("3", 64), carrierName,
			evidenceSourceCoordinate{Ref: "streamed", URL: "https://example.com/streamed"},
			int64(len(body)), sha256Hex(body), accumulator,
		)
		if err != nil {
			t.Fatal(err)
		}
		assertRehashRejects(t, carrierPath, []byte(base64.StdEncoding.EncodeToString(rewrittenBody)), accumulator, false)
	})
}

func TestProviderInputAdmissionRootIsContentDerivedAndPathIndependent(t *testing.T) {
	type admitted struct {
		artifact  artifactInput
		proof     providerInputAdmissionProof
		resources []providerInputAdmissionResourceReceipt
	}
	load := func(dir string) admitted {
		t.Helper()
		path := filepath.Join(dir, "authority.md")
		if err := os.WriteFile(path, []byte("same exact dependency bytes\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		accumulator := newCanonicalProviderInputAdmissionAccumulator()
		artifact, err := readArtifactInputWithAdmission(path, accumulator)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := accumulator.seal()
		if err != nil {
			t.Fatal(err)
		}
		artifact.InputAdmissionProofSHA256 = proof.ProofSHA256
		return admitted{artifact: artifact, proof: proof, resources: append([]providerInputAdmissionResourceReceipt(nil), accumulator.resources...)}
	}
	first := load(t.TempDir())
	second := load(t.TempDir())
	if first.artifact.InputAdmissionResource.StableCoordinate != second.artifact.InputAdmissionResource.StableCoordinate || first.proof.ResourceSetRootSHA256 != second.proof.ResourceSetRootSHA256 || first.proof.ProofSHA256 != second.proof.ProofSHA256 {
		t.Fatalf("content-equal inputs produced path-dependent identities:\nfirst=%+v\nsecond=%+v", first.proof, second.proof)
	}
	tamperedProof := first.proof
	tamperedProof.Actuals.DependencyArtifactBytes++
	if err := validateProviderInputAdmissionProof(tamperedProof, first.resources); err == nil {
		t.Fatal("tampered input-admission actuals were accepted")
	}
	proofMutations := []struct {
		name   string
		mutate func(*providerInputAdmissionProof)
	}{
		{name: "structured JSON limit", mutate: func(proof *providerInputAdmissionProof) { proof.Limits.StructuredJSONRowsPerCorpus-- }},
		{name: "structured JSON actual", mutate: func(proof *providerInputAdmissionProof) { proof.Actuals.StructuredJSONTokenCount++ }},
		{name: "resident snapshot actual", mutate: func(proof *providerInputAdmissionProof) { proof.Actuals.ResidentSnapshotBytes-- }},
		{name: "peak resident snapshot actual", mutate: func(proof *providerInputAdmissionProof) { proof.Actuals.PeakResidentSnapshotBytes++ }},
	}
	for _, mutation := range proofMutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := first.proof
			mutation.mutate(&mutated)
			if err := validateProviderInputAdmissionProof(mutated, first.resources); err == nil {
				t.Fatalf("tampered %s was accepted", mutation.name)
			}
		})
	}
	tamperedArtifact := first.artifact
	tamperedArtifact.Raw = append(bytes.Clone(tamperedArtifact.Raw), '!')
	if err := validateDependencyInputAdmissionBinding(map[string]artifactInput{tamperedArtifact.SHA256: tamperedArtifact}, first.proof, first.resources); err == nil {
		t.Fatal("dependency bytes mutated after admission were accepted")
	}
}

func TestProviderInputAdmissionRootIsInputOrderIndependent(t *testing.T) {
	dir := t.TempDir()
	firstPath := filepath.Join(dir, "first.md")
	secondPath := filepath.Join(dir, "second.md")
	if err := os.WriteFile(firstPath, []byte("first exact dependency\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte("second exact dependency\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	load := func(paths []string) providerInputAdmissionProof {
		t.Helper()
		accumulator := newCanonicalProviderInputAdmissionAccumulator()
		if _, err := loadDependencyArtifactsWithAdmission(paths, accumulator); err != nil {
			t.Fatal(err)
		}
		proof, err := accumulator.seal()
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}
	forward := load([]string{firstPath, secondPath})
	reverse := load([]string{secondPath, firstPath})
	if forward != reverse {
		t.Fatalf("input order changed the sealed admission proof:\nforward=%+v\nreverse=%+v", forward, reverse)
	}
}

func TestProviderInputAdmissionRejectsDuplicateStableIdentityWithDifferentBytes(t *testing.T) {
	first, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{
		ResourceKind:     providerInputAdmissionResourceKindArtifact,
		StableCoordinate: "duplicate_identity",
		ContentSHA256:    sha256Hex([]byte("first")),
		ContentBytes:     5,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{
		ResourceKind:     providerInputAdmissionResourceKindArtifact,
		StableCoordinate: "duplicate_identity",
		ContentSHA256:    sha256Hex([]byte("second")),
		ContentBytes:     6,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := providerInputAdmissionActualsFromResources([]providerInputAdmissionResourceReceipt{first, second}); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("error = %v, want duplicate stable-identity refusal", err)
	}
}

func TestVerificationAuthorityInputAdmissionSealsThreeRoleBoundResources(t *testing.T) {
	dir := t.TempDir()
	fixtures := []struct {
		role string
		name string
		raw  []byte
	}{
		{role: verificationAuthorityRoleOODGraph, name: "ood.json", raw: []byte(`{"doc_id":"ood"}`)},
		{role: verificationAuthorityRoleGrandVision, name: "vision.md", raw: []byte("# exact vision\n")},
		{role: verificationAuthorityRoleSourceRecord, name: "source.json", raw: []byte(`{"doc_id":"source"}`)},
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	binding := verificationAuthorityInputAdmissionBinding{}
	var expectedBytes int64
	for _, fixture := range fixtures {
		path := filepath.Join(dir, fixture.name)
		if err := os.WriteFile(path, fixture.raw, 0o600); err != nil {
			t.Fatal(err)
		}
		item, err := readVerificationAuthorityWithAdmission(path, fixture.role, accumulator)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateVerificationAuthorityExpectedPin(item, sha256Hex(fixture.raw)); err != nil {
			t.Fatal(err)
		}
		binding.Items = append(binding.Items, item)
		expectedBytes += int64(len(fixture.raw))
	}
	proof, err := accumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	if err := bindAndValidateVerificationAuthorityInputAdmission(&binding, proof, accumulator.resources); err != nil {
		t.Fatal(err)
	}
	if proof.Actuals.VerificationAuthorityCount != 3 || proof.Actuals.VerificationAuthorityBytes != expectedBytes {
		t.Fatalf("authority admission actuals = %+v, want count=3 bytes=%d", proof.Actuals, expectedBytes)
	}
	for _, resource := range accumulator.resources {
		if resource.ResourceKind != providerInputAdmissionResourceKindAuthority || !strings.HasPrefix(resource.StableCoordinate, "verification_authority_input_v1|") {
			t.Fatalf("authority resource is mislabeled: %+v", resource)
		}
	}
}

func TestVerificationAuthorityInputAdmissionRejectsMutationOversizeAndWrongPin(t *testing.T) {
	roles := []string{verificationAuthorityRoleOODGraph, verificationAuthorityRoleGrandVision, verificationAuthorityRoleSourceRecord}
	for _, role := range roles {
		t.Run("mutation "+role, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authority")
			raw := []byte("must not be partially admitted")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			accumulator := newCanonicalProviderInputAdmissionAccumulator()
			accumulator.afterOpenStat = func(resourceKind, hookPath string) error {
				if resourceKind == providerInputAdmissionResourceKindAuthority {
					return os.Truncate(hookPath, 1)
				}
				return nil
			}
			_, err := readVerificationAuthorityWithAdmission(path, role, accumulator)
			if err == nil || (!strings.Contains(err.Error(), "unexpected EOF") && !strings.Contains(err.Error(), "changed while being read")) {
				t.Fatalf("error = %v, want authority mutation refusal", err)
			}
		})
	}

	t.Run("oversize", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authority")
		raw := []byte("four")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		limits := canonicalProviderInputAdmissionLimits
		limits.VerificationAuthorityBytesPerFile = 3
		limits.VerificationAuthorityBytesPerCorpus = 9
		accumulator, err := newProviderInputAdmissionAccumulator(limits)
		if err != nil {
			t.Fatal(err)
		}
		hookCalled := false
		accumulator.afterOpenStat = func(string, string) error { hookCalled = true; return nil }
		_, err = readVerificationAuthorityWithAdmission(path, verificationAuthorityRoleOODGraph, accumulator)
		if err == nil || !strings.Contains(err.Error(), "exceeds per-file limit 3") {
			t.Fatalf("error = %v, want pre-read authority byte refusal", err)
		}
		if hookCalled {
			t.Fatal("authority byte limit was enforced only after the pre-allocation hook")
		}
	})

	t.Run("wrong expected pin", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "authority")
		if err := os.WriteFile(path, []byte("exact"), 0o600); err != nil {
			t.Fatal(err)
		}
		item, err := readVerificationAuthorityWithAdmission(path, verificationAuthorityRoleOODGraph, newCanonicalProviderInputAdmissionAccumulator())
		if err != nil {
			t.Fatal(err)
		}
		err = validateVerificationAuthorityExpectedPin(item, strings.Repeat("0", 64))
		if err == nil || !strings.Contains(err.Error(), "does not equal independently expected authority hash") {
			t.Fatalf("error = %v, want wrong authority-pin refusal", err)
		}
	})
}

func TestVerifyRejectsEachAuthorityMutationDuringAdmission(t *testing.T) {
	for _, test := range []struct {
		name       string
		selectPath func(Options) string
	}{
		{name: "ood_graph", selectPath: func(options Options) string { return options.OODSpecPath }},
		{name: "grand_vision", selectPath: func(options Options) string { return options.GrandVisionPath }},
		{name: "source_record", selectPath: func(options Options) string { return options.SourceRecordSpecPath }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newTestFixture(t)
			target := filepath.Clean(test.selectPath(fixture.options))
			hookCalled := false
			fixture.options.inputAdmissionAfterOpenStat = func(resourceKind, hookPath string) error {
				if resourceKind == providerInputAdmissionResourceKindAuthority && strings.EqualFold(filepath.Clean(hookPath), target) {
					hookCalled = true
					return os.Truncate(hookPath, 1)
				}
				return nil
			}
			_, err := Verify(fixture.options)
			if !hookCalled {
				t.Fatal("authority mutation hook was not called")
			}
			if err == nil || (!strings.Contains(err.Error(), "unexpected EOF") && !strings.Contains(err.Error(), "changed while being read")) {
				t.Fatalf("error = %v, want authority mutation refusal", err)
			}
		})
	}
}

func TestVerifyBindsProviderInputAdmissionIntoReceipt(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	observerCalled := false
	fixture.options.inputAdmissionObserver = func(proof providerInputAdmissionProof, resources []providerInputAdmissionResourceReceipt) error {
		observerCalled = true
		if proof.Actuals.VerificationAuthorityCount != 3 {
			return fmt.Errorf("observer authority count = %d, want 3", proof.Actuals.VerificationAuthorityCount)
		}
		count := 0
		for _, resource := range resources {
			if resource.ResourceKind == providerInputAdmissionResourceKindAuthority {
				count++
			}
		}
		if count != 3 {
			return fmt.Errorf("observer authority resource count = %d, want 3", count)
		}
		return nil
	}
	receipt, err := Verify(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	if !observerCalled {
		t.Fatal("provider input admission observer was not called")
	}
	if !isLowerSHA256(receipt.ProviderInputAdmissionProofSHA256) || !isLowerSHA256(receipt.ProviderInputAdmissionResourceSetRootSHA256) {
		t.Fatalf("receipt omits sealed provider input admission identity: %+v", receipt)
	}
	if receipt.ProviderInputAdmissionLimits != canonicalProviderInputAdmissionLimits {
		t.Fatalf("receipt limits = %+v, want canonical %+v", receipt.ProviderInputAdmissionLimits, canonicalProviderInputAdmissionLimits)
	}
	if receipt.ProviderInputAdmissionActuals.VerificationAuthorityCount != 3 || receipt.ProviderInputAdmissionActuals.EvidenceManifestCount != int64(len(receipt.EvidenceManifestSHA256)) || receipt.ProviderInputAdmissionActuals.DependencyArtifactCount != int64(receipt.DependencyArtifactCount) || receipt.ProviderInputAdmissionActuals.EvidenceBodyCount != int64(receipt.EvidenceBodyCount) {
		t.Fatalf("receipt input actuals do not bind the public exact rosters: %+v", receipt.ProviderInputAdmissionActuals)
	}
	if err := validateReceiptIdentity(receipt); err != nil {
		t.Fatalf("receipt self-identity does not bind provider input admission: %v", err)
	}
}

func TestVerifyRejectsLateByteIdenticalDependencyReplacement(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	target := fixture.options.DependencyArtifactPath[0]
	hookCalled := false
	fixture.options.inputAdmissionBeforeFinish = func() error {
		hookCalled = true
		replaceFactoryInputWithByteIdenticalFile(t, target)
		return nil
	}
	_, err := Verify(fixture.options)
	if !hookCalled {
		t.Fatalf("late provider input completion hook was not called; Verify returned %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "changed after its exact physical snapshot") {
		t.Fatalf("late dependency replacement error = %v, want final physical-identity refusal", err)
	}
}

func TestVerifyRejectsLateByteIdenticalStreamedCarrierReplacement(t *testing.T) {
	t.Parallel()
	fixture := newTestFixture(t)
	target := firstRealVerifyEvidenceCarrierPath(t, fixture.options.EvidenceManifestPath[0])
	hookCalled := false
	fixture.options.inputAdmissionBeforeFinish = func() error {
		hookCalled = true
		replaceFactoryInputWithByteIdenticalFile(t, target)
		return nil
	}
	_, err := Verify(fixture.options)
	if !hookCalled {
		t.Fatalf("late streamed-carrier completion hook was not called; Verify returned %v", err)
	}
	if err == nil || !strings.Contains(err.Error(), "changed after its exact physical snapshot") {
		t.Fatalf("late streamed-carrier replacement error = %v, want final physical-identity refusal", err)
	}
}

func writeProviderInputCarrierFixture(t *testing.T, carrier []byte) (string, string) {
	t.Helper()
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.jsonl")
	if err := os.WriteFile(manifestPath, []byte("manifest placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	carrierName := "body.md.b64"
	if err := os.WriteFile(filepath.Join(dir, carrierName), carrier, 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath, carrierName
}
