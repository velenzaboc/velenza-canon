package providerplan

import (
	"path/filepath"
	"strings"
	"testing"
)

// Credential scanning has a fast ASCII path and a separate path for byte
// strings that are not pure ASCII. A credential that escaped detection merely
// because the surrounding payload carried one non-ASCII byte would be a real
// disclosure hole, so the two paths must agree on every fixture.
func TestKnownCredentialTokenAnywhereDetectsTokensInNonASCIIPayloads(t *testing.T) {
	const githubToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
	const awsToken = "AKIAIOSFODNN7EXAMPLE"

	for _, test := range []struct {
		name  string
		ascii string
		want  bool
	}{
		{
			name:  "github token surrounded by prose",
			ascii: "token=" + githubToken + " trailing",
			want:  true,
		},
		{
			name:  "aws access key id",
			ascii: "key " + awsToken + " end",
			want:  true,
		},
		{
			name:  "credential prefix too short to be a token",
			ascii: "ghp_abc and nothing else",
			want:  false,
		},
		{
			name:  "no credential material at all",
			ascii: "an ordinary sentence with no secrets",
			want:  false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			asciiValue := []byte(test.ascii)
			if !bytesAreASCII(asciiValue) {
				t.Fatalf("fixture is not ASCII, so it cannot exercise the ASCII path")
			}
			if got := knownCredentialTokenAnywhere(asciiValue); got != test.want {
				t.Fatalf("ASCII path = %v, want %v", got, test.want)
			}

			// The same payload with one non-ASCII byte must reach the same verdict
			// through the non-ASCII path.
			nonASCII := []byte("café " + test.ascii)
			if bytesAreASCII(nonASCII) {
				t.Fatalf("control failed: the non-ASCII fixture is still pure ASCII")
			}
			if got := knownCredentialTokenAnywhere(nonASCII); got != test.want {
				t.Fatalf("non-ASCII path = %v, want %v (the ASCII path's verdict)", got, test.want)
			}
		})
	}
}

// A non-token occurrence of a credential prefix must not stop the scan: a real
// token appearing later in the same payload still has to be found.
func TestKnownCredentialTokenAnywhereContinuesPastNonTokenPrefixMatches(t *testing.T) {
	const githubToken = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
	payload := []byte("café ghp_short then " + githubToken)
	if bytesAreASCII(payload) {
		t.Fatalf("control failed: the fixture is pure ASCII")
	}
	if !knownCredentialTokenAnywhere(payload) {
		t.Fatalf("a real token after a non-token prefix match was missed")
	}
}

func TestValidEvidenceStagingPathComponentsRejectsWindowsDeviceAndStreamNames(t *testing.T) {
	if filepath.Separator != '\\' {
		// The check is a Windows path-syntax guard; elsewhere it admits every
		// path and the surrounding locality checks do the work.
		if !validEvidenceStagingPathComponents("anything:at/all") {
			t.Fatalf("the non-Windows contract must admit every component")
		}
		return
	}
	for _, path := range []string{"evidence:stream", "nested/CON/body.json", "AUX.json", "dir/COM1.txt", "LPT9"} {
		if validEvidenceStagingPathComponents(path) {
			t.Fatalf("path %q was accepted; it names a reserved device or alternate data stream", path)
		}
	}
	if !validEvidenceStagingPathComponents("nested/ordinary/body.json") {
		t.Fatalf("an ordinary relative staging path was rejected")
	}
}

func TestRequirePathWithinRootRefusesIncomparableAndEscapingPaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "manifest-dir")

	// A relative target cannot be made relative to an absolute root, so the
	// comparison itself fails and must surface as a refusal rather than a pass.
	if err := requirePathWithinRoot(root, "relative-target"); err == nil {
		t.Fatalf("an incomparable root/target pair was accepted")
	}

	for _, target := range []string{root, filepath.Dir(root), filepath.Join(filepath.Dir(root), "sibling")} {
		if err := requirePathWithinRoot(root, target); err == nil {
			t.Fatalf("target %q escapes or names the manifest directory but was accepted", target)
		} else if !strings.Contains(err.Error(), "escapes or names the manifest directory") {
			t.Fatalf("target %q error = %v, want the escape refusal", target, err)
		}
	}

	if err := requirePathWithinRoot(root, filepath.Join(root, "nested", "body.json")); err != nil {
		t.Fatalf("a contained target was rejected: %v", err)
	}
}
