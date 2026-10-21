package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestReleaseBuildModuleRequiresPinnedReplacement(t *testing.T) {
	plain, err := releaseBuildModule(debug.Module{Path: "example.invalid/main", Version: "v1.2.3", Sum: "h1:main"})
	if err != nil {
		t.Fatal(err)
	}
	if plain["path"] != "example.invalid/main" || plain["version"] != "v1.2.3" || plain["sum"] != "h1:main" {
		t.Fatalf("plain module = %#v", plain)
	}
	if _, exists := plain["replace_path"]; exists {
		t.Fatalf("plain module unexpectedly carries replacement fields: %#v", plain)
	}

	replacement := &debug.Module{Path: "example.invalid/fork", Version: "v1.2.4", Sum: "h1:fork"}
	replaced, err := releaseBuildModule(debug.Module{Path: "example.invalid/original", Version: "v1.2.3", Sum: "h1:original", Replace: replacement})
	if err != nil {
		t.Fatal(err)
	}
	if replaced["replace_path"] != replacement.Path || replaced["replace_version"] != replacement.Version || replaced["replace_sum"] != replacement.Sum {
		t.Fatalf("replacement module = %#v", replaced)
	}

	for _, invalid := range []*debug.Module{
		{Version: "v1.0.0", Sum: "h1:x"},
		{Path: "example.invalid/fork", Sum: "h1:x"},
		{Path: "example.invalid/fork", Version: "v1.0.0"},
		{Path: " ", Version: "v1.0.0", Sum: "h1:x"},
	} {
		if _, err := releaseBuildModule(debug.Module{Path: "example.invalid/original", Replace: invalid}); err == nil {
			t.Fatalf("accepted unpinned replacement %#v", invalid)
		}
	}
}

func TestReleaseBuildModuleOrderingUsesEveryIdentityField(t *testing.T) {
	keys := []string{"path", "version", "sum", "replace_path", "replace_version", "replace_sum"}
	for index, key := range keys {
		left := map[string]any{}
		right := map[string]any{}
		for prior := 0; prior < index; prior++ {
			left[keys[prior]] = "same"
			right[keys[prior]] = "same"
		}
		left[key] = "a"
		right[key] = "b"
		if !releaseBuildModuleLess(left, right) || releaseBuildModuleLess(right, left) {
			t.Fatalf("module ordering did not compare %q", key)
		}
	}
	equal := map[string]any{"path": "same", "version": "same", "sum": "same"}
	if releaseBuildModuleLess(equal, equal) {
		t.Fatal("equal module identities were ordered")
	}
}

func TestReleaseBuildSettingClassificationsAreClosed(t *testing.T) {
	for _, key := range []string{"GOOS", "GOARCH", "-compiler", "-buildmode", "CGO_ENABLED", "GOAMD64"} {
		if !releaseTargetBuildSetting(key) {
			t.Errorf("target setting %q was not classified", key)
		}
		if !releaseExecutionBuildSettingAllowed(key) {
			t.Errorf("execution setting %q was not allowed", key)
		}
	}
	for _, key := range []string{"-tags", "-trimpath", "vcs", "vcs.revision", "DefaultGODEBUG"} {
		if releaseTargetBuildSetting(key) {
			t.Errorf("portable setting %q was classified as target-specific", key)
		}
		if !releaseExecutionBuildSettingAllowed(key) {
			t.Errorf("closed execution setting %q was rejected", key)
		}
	}
	for _, key := range []string{"", "GOFLAGS", "GOWORK", "unexpected"} {
		if releaseTargetBuildSetting(key) || releaseExecutionBuildSettingAllowed(key) {
			t.Errorf("unknown setting %q crossed closed classification", key)
		}
	}
}

func TestPortablePathAndDigestPredicates(t *testing.T) {
	nonzero40 := strings.Repeat("a", 40)
	nonzero64 := strings.Repeat("b", 64)
	if !validFullObjectID(nonzero40) || !validFullObjectID(nonzero64) || !validFullCommitID(nonzero40) || !validSHA256(nonzero64) {
		t.Fatal("valid lowercase object identities were rejected")
	}
	for _, invalid := range []string{"", strings.Repeat("0", 40), strings.Repeat("A", 40), strings.Repeat("z", 40), strings.Repeat("a", 41)} {
		if validFullObjectID(invalid) {
			t.Errorf("invalid object ID %q was accepted", invalid)
		}
	}
	if validFullCommitID(nonzero64) || validSHA256(nonzero40) {
		t.Fatal("typed digest length was not enforced")
	}
	for _, suffix := range []string{"1", "5", "9"} {
		if !validReservedSuffix(suffix) {
			t.Errorf("valid reserved suffix %q rejected", suffix)
		}
	}
	for _, suffix := range []string{"", "0", "10", "a"} {
		if validReservedSuffix(suffix) {
			t.Errorf("invalid reserved suffix %q accepted", suffix)
		}
	}
}

func TestSafeRosterPathAcceptsPortableNamesAndRejectsNativeHazards(t *testing.T) {
	native, collision, err := safeRosterPath("cmd/tool/main.go")
	if err != nil || filepath.ToSlash(native) != "cmd/tool/main.go" || collision != "cmd/tool/main.go" {
		t.Fatalf("portable path = %q collision=%q err=%v", native, collision, err)
	}
	invalid := []string{
		"", ".", "..", "../escape", "/absolute", `back\\slash`, "two//segments", "./local",
		".git/config", "dir/.GIT/file", "trailing ", "trailing.", "bad:name", "bad\x00name",
		"caf\u00e9.go", "CON", "prn.txt", "AUX", "NUL.log", "COM1", "LPT9.txt", "CONIN$.txt", "CONOUT$",
	}
	for _, path := range invalid {
		if _, _, err := safeRosterPath(path); err == nil {
			t.Errorf("unsafe path %q was accepted", path)
		}
	}
}

func TestReleaseJSONPrimitiveHelpers(t *testing.T) {
	object, err := decodeReleaseJSONObject([]byte(`{"string":"value","int":-2,"uint":3,"nested":{"ok":true},"array":[1,false,null]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := requireReleaseString(object, "string", "fixture"); err != nil || got != "value" {
		t.Fatalf("string = %q, err=%v", got, err)
	}
	if got, err := requireReleaseInt64(object, "int", "fixture"); err != nil || got != -2 {
		t.Fatalf("int = %d, err=%v", got, err)
	}
	if got, err := requireReleaseUint64(object, "uint", "fixture"); err != nil || got != 3 {
		t.Fatalf("uint = %d, err=%v", got, err)
	}
	if nested, err := requireJSONObject(object["nested"], "nested"); err != nil || nested["ok"] != true {
		t.Fatalf("nested = %#v, err=%v", nested, err)
	}
	if !releaseObjectIdentityEquals(object, "string", "value") || releaseObjectIdentityEquals(object, "string", "other") {
		t.Fatal("string identity comparison is not exact")
	}
	if !releaseObjectBoolEquals(object["nested"].(map[string]any), "ok", true) || releaseObjectBoolEquals(object, "string", true) {
		t.Fatal("boolean identity comparison is not typed and exact")
	}
	for _, field := range []string{"missing", "nested"} {
		if _, err := requireReleaseString(object, field, "fixture"); err == nil {
			t.Errorf("accepted %q as string", field)
		}
	}
	for _, value := range []any{"1", json.Number("1.5"), json.Number("999999999999999999999999999999")} {
		if _, err := requireReleaseInt64(map[string]any{"x": value}, "x", "fixture"); err == nil {
			t.Errorf("accepted %#v as int64", value)
		}
	}
	for _, value := range []any{"1", json.Number("-1"), json.Number("999999999999999999999999999999")} {
		if _, err := requireReleaseUint64(map[string]any{"x": value}, "x", "fixture"); err == nil {
			t.Errorf("accepted %#v as uint64", value)
		}
	}
	if _, err := requireJSONObject([]any{}, "fixture"); err == nil {
		t.Fatal("accepted an array as object")
	}
	if err := requireExactObjectKeys(object, []string{"string"}); err == nil {
		t.Fatal("accepted wrong object cardinality")
	}
	if err := requireExactObjectKeys(map[string]any{"a": 1}, []string{"b"}); err == nil {
		t.Fatal("accepted missing required key")
	}
	if err := requireExactObjectKeys(map[string]any{"a": 1}, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	clone := cloneJSONObject(object)
	clone["string"] = "changed"
	if object["string"] != "value" {
		t.Fatal("clone mutation changed original object")
	}
	if got := releaseLengthPrefixedIdentityKey("a", "two"); got != "1:a3:two" {
		t.Fatalf("identity key = %q", got)
	}
}

func TestReleaseJSONRejectsTrailingAndInvalidTopLevelValues(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{} {}`),
		[]byte(`[]`),
		[]byte(`{"a":1`),
		[]byte(`[1,2`),
		[]byte(``),
	} {
		if _, err := decodeReleaseJSONObject(raw); err == nil {
			t.Fatalf("accepted malformed receipt %q", raw)
		}
	}
	if err := validateNoDuplicateJSONKeys([]byte(`{"a":[{"b":1}],"c":null}`)); err != nil {
		t.Fatal(err)
	}
	if err := validateNoDuplicateJSONKeys([]byte(`{"a":1} true`)); err == nil {
		t.Fatal("accepted trailing JSON token")
	}
}

func TestCanonicalReleaseJSONAndSelfDigest(t *testing.T) {
	value := map[string]any{"html": "<tag>", "count": json.Number("2")}
	canonical, err := canonicalReleaseJSON(value)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonical), `\u003c`) || bytes.HasSuffix(canonical, []byte{'\n'}) {
		t.Fatalf("canonical JSON = %q", canonical)
	}
	digest, err := canonicalReleaseDigest(value)
	if err != nil || digest != sha256String(string(canonical)) {
		t.Fatalf("digest = %q, err=%v", digest, err)
	}
	identity := map[string]any{"name": "fixture", "sha256": ""}
	want, err := canonicalReleaseDigest(identity)
	if err != nil {
		t.Fatal(err)
	}
	identity["sha256"] = want
	if err := validateObjectSelfDigest(identity, "sha256", want); err != nil {
		t.Fatal(err)
	}
	if err := validateObjectSelfDigest(identity, "sha256", strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted all-zero digest")
	}
	if err := validateObjectSelfDigest(identity, "sha256", strings.Repeat("a", 64)); err == nil {
		t.Fatal("accepted mismatched self digest")
	}
	if _, err := canonicalReleaseJSON(func() {}); err == nil {
		t.Fatal("canonicalized unsupported JSON value")
	}
}

func TestLimitedBufferAndEnvironmentReplacement(t *testing.T) {
	var buffer limitedBuffer
	buffer.limit = 4
	if count, err := buffer.Write([]byte("four")); err != nil || count != 4 || string(buffer.Bytes()) != "four" {
		t.Fatalf("bounded write count=%d bytes=%q err=%v", count, buffer.Bytes(), err)
	}
	if count, err := buffer.Write([]byte("!")); err == nil || count != 0 || string(buffer.Bytes()) != "four" {
		t.Fatalf("overflow count=%d bytes=%q err=%v", count, buffer.Bytes(), err)
	}
	replaced := replaceEnvironmentValue([]string{"A=one", "B=two"}, "A", "changed")
	if strings.Join(replaced, ",") != "A=changed,B=two" {
		t.Fatalf("replaced environment = %v", replaced)
	}
	added := replaceEnvironmentValue(replaced, "C", "three")
	if strings.Join(added, ",") != "A=changed,B=two,C=three" || strings.Join(replaced, ",") != "A=changed,B=two" {
		t.Fatalf("added=%v source=%v", added, replaced)
	}
}

type failAfterWriter struct {
	remaining int
}

func (writer *failAfterWriter) Write(value []byte) (int, error) {
	if writer.remaining <= 0 {
		return 0, errors.New("injected write failure")
	}
	if len(value) > writer.remaining {
		count := writer.remaining
		writer.remaining = 0
		return count, errors.New("injected write failure")
	}
	writer.remaining -= len(value)
	return len(value), nil
}

func TestMeasuredTreeEncodingPropagatesWriterFailures(t *testing.T) {
	var output bytes.Buffer
	if err := writeMeasuredTreeString(&output, "abc"); err != nil {
		t.Fatal(err)
	}
	if output.Len() != 11 || !bytes.HasSuffix(output.Bytes(), []byte("abc")) {
		t.Fatalf("length-prefixed bytes = %x", output.Bytes())
	}
	if err := writeMeasuredTreeString(&failAfterWriter{remaining: 0}, "abc"); err == nil {
		t.Fatal("binary length write failure was ignored")
	}
	if err := writeMeasuredTreeString(&failAfterWriter{remaining: 8}, "abc"); err == nil {
		t.Fatal("payload write failure was ignored")
	}
}

func TestSourceRosterIdentityPropagatesEveryWriteBoundary(t *testing.T) {
	entry := sourceRosterEntry{path: "a.go", mode: "100644", byteCount: 7, contentSHA256: strings.Repeat("a", 64)}
	var encoded bytes.Buffer
	if err := writeSourceRosterIdentity(&encoded, []sourceRosterEntry{entry}); err != nil {
		t.Fatal(err)
	}
	if encoded.Len() == 0 {
		t.Fatal("source roster identity was empty")
	}
	for _, remaining := range []int{0, 8, 8 + len(entry.path), 16 + len(entry.path), 16 + len(entry.path) + len(entry.mode) + 7, 24 + len(entry.path) + len(entry.mode) + 7} {
		if err := writeSourceRosterIdentity(&failAfterWriter{remaining: remaining}, []sourceRosterEntry{entry}); err == nil {
			t.Errorf("write boundary %d did not propagate failure", remaining)
		}
	}
}

func TestResolveAndMeasureTrustRoots(t *testing.T) {
	root := t.TempDir()
	resolvedRoot, err := resolveSourceRoot(root)
	if err != nil || !sameNativePath(resolvedRoot, root) {
		t.Fatalf("source root=%q err=%v", resolvedRoot, err)
	}
	file := filepath.Join(root, "tool")
	if err := os.WriteFile(file, []byte("tool bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSourceRoot(file); err == nil {
		t.Fatal("accepted file as source root")
	}
	if _, err := resolveSourceRoot(filepath.Join(root, "missing")); err == nil {
		t.Fatal("accepted missing source root")
	}
	if _, err := resolveExecutable("relative-tool"); err == nil {
		t.Fatal("accepted relative executable trust root")
	}
	if _, err := resolveExecutable(root); err == nil {
		t.Fatal("accepted directory as executable trust root")
	}
	resolvedTool, err := resolveExecutable(file)
	if err != nil || !sameNativePath(resolvedTool, file) {
		t.Fatalf("resolved tool=%q err=%v", resolvedTool, err)
	}
	measurement, err := measureExecutable(file)
	if err != nil || measurement.size != int64(len("tool bytes")) || measurement.path != file || !validSHA256(measurement.digest) {
		t.Fatalf("measurement=%+v err=%v", measurement, err)
	}
	if err := verifyMeasuredExecutable(measurement); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("changed tool bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyMeasuredExecutable(measurement); err == nil {
		t.Fatal("changed executable matched prior measurement")
	}
	if _, err := measureExecutable(filepath.Join(root, "missing")); err == nil {
		t.Fatal("measured missing executable")
	}
}

func TestMeasureOpenExecutableAndRegularPayload(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payload")
	if err := os.WriteFile(path, []byte("payload"), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	measurement, err := measureOpenExecutable(file, path)
	if err != nil || measurement.size != 7 || measurement.path != path {
		t.Fatalf("open measurement=%+v err=%v", measurement, err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := measureOpenExecutable(file, path); err == nil {
		t.Fatal("measured closed executable")
	}
	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if _, err := measureOpenExecutable(directory, root); err == nil {
		t.Fatal("measured directory as executable")
	}
	payload, err := measureStableRegularPayload(path)
	if err != nil || payload.size != 7 || !validSHA256(payload.digest) {
		t.Fatalf("payload=%+v err=%v", payload, err)
	}
	for _, candidate := range []string{root, filepath.Join(root, "missing")} {
		if _, err := measureStableRegularPayload(candidate); err == nil {
			t.Errorf("measured non-file %q", candidate)
		}
	}
}

func TestMeasureRegularTreeAndExecutableClassification(t *testing.T) {
	root := t.TempDir()
	if _, err := measureRegularTree(root); err == nil {
		t.Fatal("accepted empty toolchain tree")
	}
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "go"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("go1.27.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tree, err := measureRegularTree(root)
	if err != nil || tree.files != 2 || tree.bytes != int64(len("binary")+len("go1.27.1\n")) || !validSHA256(tree.digest) {
		t.Fatalf("tree=%+v err=%v", tree, err)
	}
	if !sameNativePath(filepath.Join(root, "bin", ".."), root) || sameNativePath(root, filepath.Join(root, "other")) {
		t.Fatal("native path comparison did not clean paths")
	}
	mode := fs.FileMode(0o755)
	if runtime.GOOS == "windows" {
		if !regularFileExecutable("tool.EXE", mode) || regularFileExecutable("tool.txt", mode) {
			t.Fatal("Windows executable extension classification failed")
		}
	} else if !regularFileExecutable("tool", mode) || regularFileExecutable("tool", 0o644) {
		t.Fatal("Unix executable mode classification failed")
	}
}

func TestReleaseWorkspaceCreationAndRemovalGuards(t *testing.T) {
	workspace, err := newReleaseWorkspace("/selected/go", "/selected/git")
	if err != nil {
		t.Fatal(err)
	}
	if workspace.root == "" || workspace.projectionRoot != filepath.Join(workspace.root, "projection") || len(workspace.onlineEnv) == 0 || len(workspace.offlineEnv) == 0 {
		t.Fatalf("workspace = %+v", workspace)
	}
	if environmentMap(workspace.onlineEnv)["GOPROXY"] == "off" || environmentMap(workspace.offlineEnv)["GOPROXY"] != "off" {
		t.Fatalf("online/offline environments not separated")
	}
	removeReleaseWorkspace(workspace.tempRoot, workspace.root)
	if _, err := os.Lstat(workspace.root); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("workspace still exists: %v", err)
	}

	guarded := t.TempDir()
	child := filepath.Join(guarded, "ordinary-child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	removeReleaseWorkspace(guarded, child)
	if _, err := os.Stat(child); err != nil {
		t.Fatalf("unguarded name was deleted: %v", err)
	}
	for _, pair := range [][2]string{{"", child}, {guarded, ""}, {"relative", child}, {guarded, "relative"}, {guarded, guarded}} {
		removeReleaseWorkspace(pair[0], pair[1])
	}
}

func TestVerifyProjectionIndexRejectsStructuralDrift(t *testing.T) {
	oid := strings.Repeat("a", 40)
	want := sourceRoster{
		entries: []sourceRosterEntry{{path: "a.go", mode: "100644", objectID: oid}},
		byPath:  map[string]sourceRosterEntry{"a.go": {path: "a.go", mode: "100644", objectID: oid}},
	}
	valid := []byte("100644 " + oid + " 0\ta.go\x00")
	if err := verifyProjectionIndex(valid, want); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{
		[]byte("malformed\x00"),
		[]byte("100755 " + oid + " 0\ta.go\x00"),
		[]byte("100644 " + oid + " 1\ta.go\x00"),
		[]byte("100644 " + oid + " 0\tb.go\x00"),
		append(append([]byte(nil), valid...), valid...),
		nil,
	} {
		if err := verifyProjectionIndex(raw, want); err == nil {
			t.Fatalf("accepted drifted projection index %q", raw)
		}
	}
}

func childEnvelopeForTest(t *testing.T, object map[string]any) childReceiptEnvelope {
	t.Helper()
	raw, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	var envelope childReceiptEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestChildValidationIdentityRejectsEveryUnclosedCarrier(t *testing.T) {
	fixture := newChildReceiptValidationFixture(t)
	envelope := childEnvelopeForTest(t, fixture.receipt)
	if err := validateChildValidationIdentity(fixture.receipt, envelope); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "identity type", mutate: func(receipt map[string]any) { receipt["validation_identity"] = []any{} }, want: "validation_identity"},
		{name: "identity schema", mutate: func(receipt map[string]any) { receipt["validation_identity"].(map[string]any)["extra"] = true }, want: "schema"},
		{name: "closed profile", mutate: func(receipt map[string]any) {
			receipt["validation_identity"].(map[string]any)["profile_id"] = "different"
		}, want: "closed validation profile"},
		{name: "digest type", mutate: func(receipt map[string]any) {
			receipt["validation_identity"].(map[string]any)["validation_identity_sha256"] = false
		}, want: "digest is invalid"},
		{name: "digest mismatch", mutate: func(receipt map[string]any) {
			receipt["validation_identity"].(map[string]any)["validation_identity_sha256"] = testDigest("wrong-validation-identity")
		}, want: "validation identity"},
		{name: "proof type", mutate: func(receipt map[string]any) { receipt["input_admission_proof"] = []any{} }, want: "input_admission_proof"},
		{name: "proof digest", mutate: func(receipt map[string]any) {
			receipt["input_admission_proof"].(map[string]any)["proof_sha256"] = "invalid"
		}, want: "proof digest"},
		{name: "stage count", mutate: func(receipt map[string]any) { receipt["stages"] = []any{} }, want: "exactly four"},
		{name: "stage type", mutate: func(receipt map[string]any) { receipt["stages"].([]any)[0] = "not-object" }, want: "stage"},
		{name: "stage schema", mutate: func(receipt map[string]any) { receipt["stages"].([]any)[0].(map[string]any)["extra"] = true }, want: "schema"},
		{name: "stage digest", mutate: func(receipt map[string]any) {
			receipt["stages"].([]any)[0].(map[string]any)["receipt_sha256"] = "invalid"
		}, want: "receipt digest"},
		{name: "preflight type", mutate: func(receipt map[string]any) { receipt["preflight_receipt"] = []any{} }, want: "preflight_receipt"},
		{name: "preflight digest", mutate: func(receipt map[string]any) {
			receipt["preflight_receipt"].(map[string]any)["receipt_sha256"] = "invalid"
		}, want: "preflight receipt digest"},
		{name: "report digest", mutate: func(receipt map[string]any) { receipt["completion"].(map[string]any)["compiled"] = false }, want: "validation report digest"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := cloneReceiptForTest(t, fixture.receipt)
			test.mutate(receipt)
			err := validateChildValidationIdentity(receipt, envelope)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestValidateChildReceiptRejectsTypedIdentityDrift(t *testing.T) {
	fixture := newChildReceiptValidationFixture(t)
	tests := []struct {
		name   string
		mutate func(receipt map[string]any, build *childBuildExpectation)
		want   string
	}{
		{name: "decode typed envelope", mutate: func(receipt map[string]any, _ *childBuildExpectation) { receipt["body_free"] = "true" }, want: "cannot unmarshal"},
		{name: "execution measurement", mutate: func(receipt map[string]any, _ *childBuildExpectation) {
			receipt["execution_identity"].(map[string]any)["executable_sha256"] = testDigest("different-executable")
		}, want: "release measurement"},
		{name: "execution metadata", mutate: func(receipt map[string]any, build *childBuildExpectation) {
			build.executionIdentitySHA256 = testDigest("different-execution")
		}, want: "build settings"},
		{name: "tool self digest", mutate: func(receipt map[string]any, build *childBuildExpectation) {
			tool := receipt["tool_identity"].(map[string]any)
			tool["build_identity_sha256"] = testDigest("different-tool-self")
			build.toolIdentitySHA256 = tool["build_identity_sha256"].(string)
			receipt["execution_identity"].(map[string]any)["portable_build_identity_sha256"] = tool["build_identity_sha256"]
		}, want: "child tool identity"},
		{name: "build settings digest", mutate: func(receipt map[string]any, _ *childBuildExpectation) {
			receipt["execution_identity"].(map[string]any)["build_settings"] = []any{}
		}, want: "build-settings digest"},
		{name: "execution self digest", mutate: func(receipt map[string]any, build *childBuildExpectation) {
			identity := receipt["execution_identity"].(map[string]any)
			identity["execution_identity_sha256"] = testDigest("different-execution-self")
			build.executionIdentitySHA256 = identity["execution_identity_sha256"].(string)
		}, want: "child execution identity"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := cloneReceiptForTest(t, fixture.receipt)
			build := fixture.childBuild
			test.mutate(receipt, &build)
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			err = validateChildReceipt(raw, fixture.commit, fixture.rosterRoot, fixture.goTool, fixture.gitTool, fixture.goToolchain, fixture.gitToolchain, fixture.child, build)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestProductionVerificationRejectsMalformedEvidenceCarriers(t *testing.T) {
	fixture := newProductionSourceChildValidationFixture(t)
	normalized := cloneReceiptForTest(t, fixture.receipt)
	source := normalized["source_receipt"].(map[string]any)
	base := source["production_source_verification"].(map[string]any)
	sourcePackage := source["source_package_sha256"].(string)
	if provider, err := validateProductionSourceVerificationRelay(base, sourcePackage); err != nil || provider != fixture.expectedProvider {
		t.Fatalf("provider=%q err=%v", provider, err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "schema", mutate: func(value map[string]any) { value["extra"] = true }, want: "schema"},
		{name: "trust verdict", mutate: func(value map[string]any) { value["verification_kind"] = "other" }, want: "trust verdict"},
		{name: "provider type", mutate: func(value map[string]any) { value["provider"] = false }, want: "provider is invalid"},
		{name: "provider padded", mutate: func(value map[string]any) { value["provider"] = " padded" }, want: "provider is invalid"},
		{name: "observed type", mutate: func(value map[string]any) { value["observed_at"] = false }, want: "observed_at"},
		{name: "observed format", mutate: func(value map[string]any) { value["observed_at"] = "2026-03-01T01:00:00+01:00" }, want: "canonical UTC"},
		{name: "digest", mutate: func(value map[string]any) { value["source_owner_verification_receipt_sha256"] = "invalid" }, want: "is invalid"},
		{name: "source package", mutate: func(value map[string]any) { value["source_package_sha256"] = testDigest("other-package") }, want: "different source package"},
		{name: "byte count type", mutate: func(value map[string]any) { value["source_package_byte_count"] = "404" }, want: "byte_count is invalid"},
		{name: "byte count zero", mutate: func(value map[string]any) { value["source_owner_verification_receipt_byte_count"] = int64(0) }, want: "byte_count is invalid"},
		{name: "evidence type", mutate: func(value map[string]any) { value["provider_evidence_identities"] = "none" }, want: "evidence identity set is empty"},
		{name: "evidence empty", mutate: func(value map[string]any) { value["provider_evidence_identities"] = []any{} }, want: "evidence identity set is empty"},
		{name: "evidence object", mutate: func(value map[string]any) { value["provider_evidence_identities"] = []any{"not-object"} }, want: "provider evidence identity"},
		{name: "evidence schema", mutate: func(value map[string]any) {
			value["provider_evidence_identities"].([]any)[0].(map[string]any)["extra"] = true
		}, want: "schema"},
		{name: "evidence string", mutate: func(value map[string]any) {
			value["provider_evidence_identities"].([]any)[0].(map[string]any)["manifest_id"] = ""
		}, want: "manifest_id is invalid"},
		{name: "evidence digest", mutate: func(value map[string]any) {
			value["provider_evidence_identities"].([]any)[0].(map[string]any)["carrier_raw_sha256"] = "invalid"
		}, want: "carrier_raw_sha256 is invalid"},
		{name: "evidence count", mutate: func(value map[string]any) {
			value["provider_evidence_identities"].([]any)[0].(map[string]any)["manifest_byte_count"] = int64(0)
		}, want: "manifest_byte_count is invalid"},
		{name: "evidence ordinal", mutate: func(value map[string]any) {
			value["provider_evidence_identities"].([]any)[0].(map[string]any)["component_ordinal"] = int64(-1)
		}, want: "component_ordinal is invalid"},
		{name: "evidence root", mutate: func(value map[string]any) {
			value["provider_evidence_identity_set_root_sha256"] = testDigest("wrong-root")
		}, want: "root mismatch"},
		{name: "binding", mutate: func(value map[string]any) { value["binding_sha256"] = testDigest("wrong-binding") }, want: "binding"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verification := cloneReceiptForTest(t, base)
			test.mutate(verification)
			_, err := validateProductionSourceVerificationRelay(verification, sourcePackage)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}

	t.Run("evidence ordering", func(t *testing.T) {
		verification := cloneReceiptForTest(t, base)
		identity := verification["provider_evidence_identities"].([]any)[0].(map[string]any)
		verification["provider_evidence_identities"] = []any{cloneJSONObject(identity), cloneJSONObject(identity)}
		_, err := validateProductionSourceVerificationRelay(verification, sourcePackage)
		if err == nil || !strings.Contains(err.Error(), "unsorted or duplicated") {
			t.Fatalf("ordering error = %v", err)
		}
	})
}

func rebindFactoryFileForRelayTest(t *testing.T, source, factory map[string]any) {
	t.Helper()
	raw, err := canonicalReleaseJSON(factory)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append(raw, '\n'))
	source["factory_receipt_file_sha256"] = hex.EncodeToString(sum[:])
	recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
}

func TestProductionSourceRelayRejectsBrokenEnvelopeBindings(t *testing.T) {
	fixture := newProductionSourceChildValidationFixture(t)
	normalized := cloneReceiptForTest(t, fixture.receipt)
	baseSource := normalized["source_receipt"].(map[string]any)
	baseFactory := normalized["factory_receipt"].(map[string]any)
	if err := validateProductionSourceRelay(baseSource, baseFactory, fixture.expectedProvider); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(source, factory map[string]any)
		want   string
	}{
		{name: "source schema", mutate: func(source, _ map[string]any) { source["extra"] = true }, want: "schema"},
		{name: "source identity", mutate: func(source, _ map[string]any) { source["receipt_kind"] = "other" }, want: "candidate-only posture"},
		{name: "source digest type", mutate: func(source, _ map[string]any) { source["compiler_contract_sha256"] = false }, want: "compiler_contract_sha256 is invalid"},
		{name: "source digest", mutate: func(source, _ map[string]any) { source["receipt_sha256"] = testDigest("wrong-source") }, want: "source receipt"},
		{name: "verification type", mutate: func(source, _ map[string]any) {
			source["production_source_verification"] = []any{}
			recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
		}, want: "production_source_verification"},
		{name: "release provider", mutate: func(source, _ map[string]any) {
			verification := source["production_source_verification"].(map[string]any)
			verification["provider"] = "xero"
			recloseObjectSelfDigestForTest(t, verification, "binding_sha256")
			recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
		}, want: "provider differs"},
		{name: "factory digest missing", mutate: func(_, factory map[string]any) { delete(factory, "receipt_sha256") }, want: "receipt_sha256"},
		{name: "factory portable missing", mutate: func(_, factory map[string]any) { delete(factory, "portable_receipt_sha256") }, want: "portable_receipt_sha256"},
		{name: "factory receipt binding", mutate: func(source, _ map[string]any) {
			source["factory_receipt_sha256"] = testDigest("other-factory")
			recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
		}, want: "different factory receipt"},
		{name: "factory file binding", mutate: func(source, _ map[string]any) {
			source["factory_receipt_file_sha256"] = testDigest("other-file")
			recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
		}, want: "different factory receipt bytes"},
		{name: "source completion type", mutate: func(source, _ map[string]any) {
			source["completion"] = []any{}
			recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
		}, want: "source receipt completion"},
		{name: "factory completion type", mutate: func(source, factory map[string]any) {
			factory["completion"] = []any{}
			rebindFactoryFileForRelayTest(t, source, factory)
		}, want: "factory receipt completion"},
		{name: "completion mismatch", mutate: func(source, _ map[string]any) {
			source["completion"].(map[string]any)["compiled"] = false
			recloseObjectSelfDigestForTest(t, source, "receipt_sha256")
		}, want: "completion classifications differ"},
		{name: "preflight type", mutate: func(source, factory map[string]any) {
			factory["preflight_receipt"] = []any{}
			rebindFactoryFileForRelayTest(t, source, factory)
		}, want: "preflight receipt"},
		{name: "compiled provider", mutate: func(source, factory map[string]any) {
			factory["preflight_receipt"].(map[string]any)["provider"] = "xero"
			rebindFactoryFileForRelayTest(t, source, factory)
		}, want: "compiled provider"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := cloneReceiptForTest(t, baseSource)
			factory := cloneReceiptForTest(t, baseFactory)
			test.mutate(source, factory)
			err := validateProductionSourceRelay(source, factory, fixture.expectedProvider)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestProductionSourceChildRejectsOuterCarrierDrift(t *testing.T) {
	fixture := newProductionSourceChildValidationFixture(t)
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{name: "malformed", mutate: nil, want: "EOF"},
		{name: "identity", mutate: func(receipt map[string]any) { receipt["receipt_kind"] = "other" }, want: "candidate-only posture"},
		{name: "digest type", mutate: func(receipt map[string]any) { receipt["receipt_sha256"] = false }, want: "digest is invalid"},
		{name: "digest mismatch", mutate: func(receipt map[string]any) { receipt["receipt_sha256"] = testDigest("wrong-production-envelope") }, want: "digest is invalid"},
		{name: "source type", mutate: func(receipt map[string]any) {
			receipt["source_receipt"] = []any{}
			recloseObjectSelfDigestForTest(t, receipt, "receipt_sha256")
		}, want: "source_receipt"},
		{name: "factory type", mutate: func(receipt map[string]any) {
			receipt["factory_receipt"] = []any{}
			recloseObjectSelfDigestForTest(t, receipt, "receipt_sha256")
		}, want: "factory_receipt"},
		{name: "factory child", mutate: func(receipt map[string]any) {
			factory := receipt["factory_receipt"].(map[string]any)
			factory["receipt_kind"] = "other"
			source := receipt["source_receipt"].(map[string]any)
			rebindFactoryFileForRelayTest(t, source, factory)
			recloseObjectSelfDigestForTest(t, receipt, "receipt_sha256")
		}, want: "factory receipt"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var raw []byte
			if test.mutate == nil {
				raw = []byte(`{"broken":`)
			} else {
				receipt := cloneReceiptForTest(t, fixture.receipt)
				test.mutate(receipt)
				var err error
				raw, err = json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
			}
			err := validateProductionSourceChildReceipt(raw, fixture.expectedProvider, fixture.commit, fixture.rosterRoot, fixture.goTool, fixture.gitTool, fixture.goToolchain, fixture.gitToolchain, fixture.child, fixture.childBuild)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %q", err, test.want)
			}
		})
	}
}

var _ io.Writer = (*failAfterWriter)(nil)

func TestSplitChildReceiptPathStopsAtDelimiterAndRejectsWhitespace(t *testing.T) {
	path, found, forwarded, err := splitChildReceiptPath([]string{"alpha", "--", "--out", "ignored.json"}, t.TempDir())
	if err != nil || found || path != "" || strings.Join(forwarded, ",") != "alpha,--,--out,ignored.json" {
		t.Fatalf("delimiter path=%q found=%t forwarded=%v err=%v", path, found, forwarded, err)
	}
	for _, args := range [][]string{{"--out="}, {"--out", " padded.json"}} {
		if _, _, _, err := splitChildReceiptPath(args, t.TempDir()); err == nil {
			t.Fatalf("accepted whitespace output path %v", args)
		}
	}
	if err := validateChildReceipt([]byte(`{"broken":`), "", "", measuredExecutable{}, measuredExecutable{}, measuredTree{}, measuredTree{}, measuredExecutable{}, childBuildExpectation{}); err == nil {
		t.Fatal("accepted malformed child receipt")
	}
}
