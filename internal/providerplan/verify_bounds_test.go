package providerplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyBoundsRejectsForbiddenKeysNumbersAndCredentialTokens(t *testing.T) {
	for name, raw := range map[string][]byte{
		"forbidden key":     []byte(`{"api_key":"redacted"}`),
		"fractional number": []byte(`{"count":1.5}`),
		"exponent number":   []byte(`{"count":1e3}`),
		"credential token":  []byte(`{"note":"sk-Abcdefghijklmno1234!"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := rejectForbiddenPlanKeysAndNonIntegerNumbers(raw); err == nil {
				t.Fatalf("forbidden candidate %s was accepted", name)
			}
		})
	}
	if err := rejectForbiddenPlanKeysAndNonIntegerNumbers([]byte(`{"count":12,"name":"safe"}`)); err != nil {
		t.Fatalf("safe integer candidate: %v", err)
	}
	if !knownCredentialTokenAnywhere([]byte("prefix sk-Abcdefghijklmno1234!")) || knownCredentialTokenAnywhere([]byte("ordinary documentation sentence")) {
		t.Fatal("credential token scanner did not distinguish credential-bearing text")
	}
	if err := rejectDuplicateJSONKeys([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate JSON keys accepted")
	}
}

func TestVerifyBoundsEvidenceStagingPathsAndObjectDeltasFailClosed(t *testing.T) {
	root := t.TempDir()
	manifestPath := filepath.Join(root, "manifest.jsonl")
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bodyPath := filepath.Join(root, "evidence", "body.txt")
	if err := os.MkdirAll(filepath.Dir(bodyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bodyPath, []byte("exact body"), 0o600); err != nil {
		t.Fatal(err)
	}
	body, resolved, err := readRelativeEvidenceStagingFile(manifestPath, "evidence/body.txt")
	if err != nil || string(body) != "exact body" || resolved != bodyPath {
		t.Fatalf("read relative evidence body=%q path=%q err=%v", body, resolved, err)
	}
	for _, declared := range []string{"../outside", "/absolute", " evidence/body.txt"} {
		if _, err := resolveRelativeEvidenceStagingPath(manifestPath, declared); err == nil {
			t.Fatalf("unsafe declared path %q accepted", declared)
		}
	}
	object := map[string]interface{}{"a": "one", "b": "two"}
	if !exactObjectKeys(object, []string{"a", "b"}) || exactObjectKeys(object, []string{"a"}) {
		t.Fatal("exact object-key matching changed")
	}
	delta := describeObjectKeyDelta(object, []string{"a", "c"})
	if !strings.Contains(delta, "actual=[a,b]") || !strings.Contains(delta, "expected_one_of=[a,c]") {
		t.Fatalf("object key delta=%q", delta)
	}
	if !hasEmptyOrDuplicateStrings([]string{"a", "", "b"}) || !hasEmptyOrDuplicateStrings([]string{"a", "a"}) || !containsExactString([]string{"a", "b"}, "b") {
		t.Fatal("string helper closed-set behavior changed")
	}
}

func TestVerifyBoundsExactSetsAndManifestIntegersRemainDeterministic(t *testing.T) {
	actual := map[string]struct{}{"a": {}, "b": {}}
	expected := map[string]struct{}{"a": {}, "b": {}}
	if err := requireExactSet("fixture", actual, expected); err != nil {
		t.Fatalf("equal exact set: %v", err)
	}
	if err := requireExactSet("fixture", actual, map[string]struct{}{"a": {}}); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("set surplus error=%v", err)
	}
	if err := requireSetWithExplicitGaps("fixture", map[string]struct{}{"a": {}}, []string{"b"}, expected); err != nil {
		t.Fatalf("explicit gap set: %v", err)
	}
	if err := requireSetWithExplicitGaps("fixture", map[string]struct{}{"a": {}, "z": {}}, []string{"b"}, expected); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("unexpected explicit-gap set error=%v", err)
	}
	if value, ok := manifestInteger(map[string]interface{}{"count": jsonNumberForVerifyTest("12")}, "count"); !ok || value != 12 {
		t.Fatalf("manifest integer value=%d ok=%v", value, ok)
	}
	if _, ok := manifestInteger(map[string]interface{}{"count": jsonNumberForVerifyTest("12.5")}, "count"); ok {
		t.Fatal("fractional manifest integer accepted")
	}
	if got := sortedSetKeys(map[string]struct{}{"b": {}, "a": {}}); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("sorted exact set keys=%v", got)
	}
}

func jsonNumberForVerifyTest(value string) json.Number { return json.Number(value) }

func TestVerifyBoundsJSONShapesIdentityAndCompileSelection(t *testing.T) {
	for name, raw := range map[string][]byte{
		"valid unicode pair":        []byte(`{"value":"\uD83D\uDE00"}`),
		"unpaired high surrogate":   []byte(`{"value":"\uD83D"}`),
		"unpaired low surrogate":    []byte(`{"value":"\uDE00"}`),
		"incomplete unicode escape": []byte(`{"value":"\u12"}`),
	} {
		t.Run(name, func(t *testing.T) {
			err := rejectInvalidJSONUnicodeScalars(raw)
			if name == "valid unicode pair" && err != nil {
				t.Fatalf("valid scalar rejected: %v", err)
			}
			if name != "valid unicode pair" && err == nil {
				t.Fatal("invalid scalar accepted")
			}
		})
	}
	if err := requireObjectKeys([]byte(`{"a":1,"b":2}`), "a", "b"); err != nil {
		t.Fatalf("required keys rejected: %v", err)
	}
	if err := requireObjectKeys([]byte(`{"a":1}`), "a", "b"); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("missing required key error=%v", err)
	}
	for _, raw := range []string{
		`{"nested":{"a":1,"b":2}}`,
		`{"nested":{"a":1}}`,
		`{"nested":"not-object"}`,
		`{"other":{}}`,
	} {
		err := requireNestedObjectExactKeys([]byte(raw), "nested", "a", "b")
		if raw == `{"nested":{"a":1,"b":2}}` && err != nil {
			t.Fatalf("exact nested object rejected: %v", err)
		}
		if raw != `{"nested":{"a":1,"b":2}}` && err == nil {
			t.Fatalf("invalid nested object accepted: %s", raw)
		}
	}
	var destination struct {
		Name string `json:"name"`
	}
	if err := strictUnmarshal([]byte(`{"name":"ok"}`), &destination); err != nil || destination.Name != "ok" {
		t.Fatalf("strict unmarshal=%+v err=%v", destination, err)
	}
	for _, raw := range []string{`{"name":"one","name":"two"}`, `{"unknown":true}`, `{"name":"ok"} trailing`} {
		if err := strictUnmarshal([]byte(raw), &destination); err == nil {
			t.Fatalf("invalid strict JSON accepted: %s", raw)
		}
	}
	for _, raw := range []json.RawMessage{nil, []byte(`[]`), []byte(`{}`), []byte(`{"value":true}`)} {
		err := validateNonemptyCandidateObject("symbol", "candidate", raw)
		if string(raw) == `{"value":true}` && err != nil {
			t.Fatalf("valid candidate object rejected: %v", err)
		}
		if string(raw) != `{"value":true}` && err == nil {
			t.Fatalf("invalid candidate object accepted: %s", raw)
		}
	}
	ids := map[string]string{}
	if err := addUniqueID(ids, "id", "symbol"); err != nil || ids["id"] != "symbol" {
		t.Fatalf("unique ID=%v ids=%v", err, ids)
	}
	if err := addUniqueID(ids, "id", "relationship"); err == nil {
		t.Fatal("duplicate ID accepted")
	}
	if err := addUniqueID(ids, "", "symbol"); err == nil {
		t.Fatal("empty ID accepted")
	}
	if stableID("candidate", "same") != stableID("candidate", "same") || stableID("candidate", "same") == stableID("candidate", "other") {
		t.Fatal("stable ID determinism changed")
	}
	if err := requireValidUTF8("fixture", []byte{0xff}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}

	if _, _, err := loadGraphCompileSelection(Options{}); err == nil || !strings.Contains(err.Error(), "select exactly one") {
		t.Fatalf("missing compile selection error=%v", err)
	}
	loader := func() ([]byte, StageCompileInputs, error) {
		return []byte(`{"request":true}`), StageCompileInputs{}, nil
	}
	if raw, _, err := loadGraphCompileSelection(Options{graphCompileSelectionLoader: loader}); err != nil || string(raw) != `{"request":true}` {
		t.Fatalf("loader selection raw=%q err=%v", raw, err)
	}
	if _, _, err := loadGraphCompileSelection(Options{graphCompileRequestRaw: []byte("request"), graphCompileSelectionLoader: loader}); err == nil || !strings.Contains(err.Error(), "select exactly one") {
		t.Fatalf("ambiguous compile selection error=%v", err)
	}
}
