package providerplan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnsupportedProviderInputMutationTokenRefusesWithTheZeroToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`{"value":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	token, err := unsupportedProviderInputMutationToken(file)
	if err == nil {
		t.Fatal("a platform with no change-time equivalent reported a usable mutation token")
	}
	if err.Error() != "platform does not expose a trustworthy provider-input mutation token" {
		t.Fatalf("refusal = %q, want the exact unsupported-platform refusal", err.Error())
	}
	if token != (providerInputMutationToken{}) {
		t.Fatalf("refused token = %+v, want the zero token so no caller can treat it as evidence", token)
	}
}
