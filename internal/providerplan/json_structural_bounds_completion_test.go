package providerplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSortedEvidenceSourceCoordinatesOrdersByRefThenURL(t *testing.T) {
	values := map[evidenceSourceCoordinate]struct{}{
		{Ref: "b", URL: "https://example.test/1"}: {},
		{Ref: "a", URL: "https://example.test/2"}: {},
		{Ref: "a", URL: "https://example.test/1"}: {},
	}
	got := sortedEvidenceSourceCoordinates(values)
	want := []evidenceSourceCoordinate{
		{Ref: "a", URL: "https://example.test/1"},
		{Ref: "a", URL: "https://example.test/2"},
		{Ref: "b", URL: "https://example.test/1"},
	}
	if len(got) != len(want) {
		t.Fatalf("ordered coordinates = %d, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("ordered coordinate %d = %+v, want %+v", index, got[index], want[index])
		}
	}
}

func TestStructuredJSONAdmissionRefusesANilAccumulator(t *testing.T) {
	var accumulator *providerInputAdmissionAccumulator
	_, charge, err := accumulator.beginStructuredJSONPhysicalInput("input.json", "provider input", []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "admission state is nil") {
		t.Fatalf("nil accumulator error = %v, want an explicit nil refusal", err)
	}
	if charge {
		t.Fatal("a refused nil accumulator still reported a chargeable input")
	}
}

func TestStructuredJSONAdmissionRequiresARetainedPhysicalSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	raw := []byte(`{"value":1}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// No readBoundedProviderInputFile call, so no retained snapshot binds these
	// bytes. Structured admission must refuse rather than charge unbound input.
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	err := accumulator.admitStructuredJSONDocument(path, "provider input", providerInputAdmissionResourceKindStageFile, raw)
	if err == nil || !strings.Contains(err.Error(), "does not bind one retained physical snapshot") {
		t.Fatalf("unbound structured admission error = %v, want a snapshot-binding refusal", err)
	}
}

func TestStructuredJSONAdmissionRefusesAnAbsentPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	_, charge, err := accumulator.beginStructuredJSONPhysicalInput(missing, "provider input", []byte(`{}`))
	if err == nil {
		t.Fatal("an absent structured input path was accepted")
	}
	if charge {
		t.Fatal("a refused absent path still reported a chargeable input")
	}
}

func TestStructuredJSONAutoIgnoresWhitespaceOnlyInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blank.json")
	raw := []byte("   \n\t\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	if err := accumulator.admitStructuredJSONAuto(path, "provider input", providerInputAdmissionResourceKindStageFile, raw); err != nil {
		t.Fatalf("whitespace-only input error = %v, want it treated as unstructured", err)
	}
	if accumulator.actuals.StructuredJSONRowCount != 0 {
		t.Fatalf("whitespace-only input charged %d structured rows, want 0", accumulator.actuals.StructuredJSONRowCount)
	}
}

func TestValidateProviderJSONStructureRejectsMalformedContainers(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "object terminated awaiting a value", raw: `{"key":}`, want: ""},
		{name: "unbalanced array terminator", raw: `{"key":]}`, want: ""},
		{name: "top level array terminator", raw: `]`, want: ""},
		{name: "trailing token after a complete value", raw: `{} {}`, want: "trailing JSON token"},
		{name: "duplicate object key", raw: `{"key":1,"key":2}`, want: "duplicate JSON key"},
		{name: "unterminated object", raw: `{"key":1`, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateProviderJSONStructure([]byte(test.raw))
			if err == nil {
				t.Fatalf("malformed structure %q was accepted", test.raw)
			}
			if test.want != "" && !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestValidateProviderJSONStructureCountsScalarsAndContainers(t *testing.T) {
	structure, err := validateProviderJSONStructure([]byte(`{"text":"ab","number":12,"flag":true,"nested":[1]}`))
	if err != nil {
		t.Fatalf("well-formed structure was rejected: %v", err)
	}
	if structure.Nodes == 0 || structure.Tokens == 0 {
		t.Fatalf("structure = %+v, want counted nodes and tokens", structure)
	}
	// Object keys are string tokens too and are charged alongside values, so a
	// document cannot evade the string-byte bound by padding its keys.
	const keyAndValueStringBytes = int64(len("text") + len("number") + len("flag") + len("nested") + len("ab"))
	if structure.StringBytes != keyAndValueStringBytes {
		t.Fatalf("string bytes = %d, want %d covering both keys and values", structure.StringBytes, keyAndValueStringBytes)
	}
	// Non-string scalars are charged as decoded bytes but not as string bytes.
	if structure.DecodedBytes <= structure.StringBytes {
		t.Fatalf("decoded bytes = %d, want more than the %d string bytes once numbers and booleans are charged", structure.DecodedBytes, structure.StringBytes)
	}
}
