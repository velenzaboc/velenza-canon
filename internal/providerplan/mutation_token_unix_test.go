//go:build linux || darwin

package providerplan

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCurrentProviderInputMutationTokenIsStableAndWitnessesMetadataMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`{"value":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	first, err := currentProviderInputMutationToken(file)
	if err != nil {
		t.Fatalf("capture mutation token: %v", err)
	}
	if first == (providerInputMutationToken{}) {
		t.Fatal("mutation token is the zero value, so it could never witness a change")
	}
	again, err := currentProviderInputMutationToken(file)
	if err != nil {
		t.Fatalf("recapture mutation token: %v", err)
	}
	if again != first {
		t.Fatalf("token moved with no mutation: %+v then %+v", first, again)
	}

	// chmod moves the change time while leaving mtime alone, which is exactly
	// the class of mutation this token exists to catch and mtime cannot.
	time.Sleep(20 * time.Millisecond)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	afterChmod, err := currentProviderInputMutationToken(file)
	if err != nil {
		t.Fatalf("capture mutation token after chmod: %v", err)
	}
	if afterChmod == first {
		t.Fatalf("mutation token %+v did not move after a metadata-only mutation", afterChmod)
	}
}

func TestCurrentProviderInputMutationTokenReadingDoesNotDetachTheDescriptor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	want := []byte(`{"value":1}`)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	if _, err := currentProviderInputMutationToken(file); err != nil {
		t.Fatalf("capture mutation token: %v", err)
	}
	got := make([]byte, len(want))
	if _, err := file.Read(got); err != nil {
		t.Fatalf("read the same handle after capturing its mutation token: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("read back %q, want %q", got, want)
	}
}

func TestCurrentProviderInputMutationTokenFailsClosedOnAClosedHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`{"value":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	token, err := currentProviderInputMutationToken(file)
	if err == nil {
		t.Fatal("a closed handle produced a mutation token")
	}
	if token != (providerInputMutationToken{}) {
		t.Fatalf("failed token = %+v, want the zero token", token)
	}
}
