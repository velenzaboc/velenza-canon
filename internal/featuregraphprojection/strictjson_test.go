package featuregraphprojection

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeStrictRefusesDuplicatesTrailingAndUnknownFields(t *testing.T) {
	type payload struct {
		Known json.Number `json:"known"`
	}
	for _, raw := range []string{
		`{"known":1,"known":2}`,
		`{"outer":{"x":1,"x":2},"known":1}`,
		`{"known":1} {"known":2}`,
		`{"known":1,"unexpected":2}`,
	} {
		var got payload
		if err := DecodeStrict([]byte(raw), &got); err == nil {
			t.Fatalf("DecodeStrict(%q) succeeded, want refusal", raw)
		}
	}
}

func TestCanonicalJSONSortsKeysAndPreservesLargeNumber(t *testing.T) {
	got, err := CanonicalJSON([]byte(`{"z":9007199254740993,"a":{"d":2,"c":1}}`))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"a":{"c":1,"d":2},"z":9007199254740993}`
	if string(got) != want {
		t.Fatalf("CanonicalJSON() = %s, want %s", got, want)
	}
	if strings.Contains(string(got), "9007199254740992") {
		t.Fatalf("CanonicalJSON() coerced large number: %s", got)
	}
}
