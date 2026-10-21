package providerplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An input whose stable identity cannot be derived must fail closed at both
// admission entry points. If either returned nil, an object with an unknowable
// identity would bypass the duplicate-identity check entirely and could be
// admitted alongside itself under a second name.
func TestProviderInputAdmissionFailsClosedWhenIdentityCannotBeDerived(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`{"value":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// A closed handle is the reachable form of "identity cannot be derived".
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	if err := accumulator.rejectDuplicateOpenFileIdentity(path, file); err == nil ||
		!strings.Contains(err.Error(), "derive stable provider input file identity") {
		t.Fatalf("error = %v, want an identity-derivation refusal", err)
	}
	if err := accumulator.addPathIdentity(path, file); err == nil ||
		!strings.Contains(err.Error(), "derive stable provider input file identity") {
		t.Fatalf("error = %v, want an identity-derivation refusal", err)
	}
	if len(accumulator.pathIdentities) != 0 {
		t.Fatalf("an input with underivable identity was still recorded in the roster")
	}
}
