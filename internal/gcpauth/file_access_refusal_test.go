package gcpauth

import "testing"

func TestUnsupportedCredentialFileAccessReturnsExactRefusal(t *testing.T) {
	err := unsupportedCredentialFileAccess(nil, nil)
	if err == nil {
		t.Fatal("unsupportedCredentialFileAccess() = nil, want refusal error")
	}
	const want = "credential file access validation is unsupported on this operating system"
	if err.Error() != want {
		t.Fatalf("unsupportedCredentialFileAccess() = %q, want %q", err.Error(), want)
	}
}
