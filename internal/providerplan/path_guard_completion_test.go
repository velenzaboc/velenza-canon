package providerplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStableProviderInputPathIdentityRefusesAnAbsentPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	identity, info, err := stableProviderInputPathIdentity(missing, "provider input")
	if err == nil {
		t.Fatal("an absent path produced a stable identity")
	}
	if info != nil {
		t.Fatalf("failed identity returned file info %v, want none", info)
	}
	if identity != (providerInputStableFileIdentity{}) {
		t.Fatalf("failed identity = %+v, want the zero identity", identity)
	}
}

func TestInspectPathWithoutLinksRefusesEmptyAndNonDirectoryParents(t *testing.T) {
	if _, _, err := inspectPathWithoutLinks("   ", "provider input"); err == nil ||
		!strings.Contains(err.Error(), "path is empty") {
		t.Fatalf("blank path error = %v, want an empty-path refusal", err)
	}

	root := t.TempDir()
	regular := filepath.Join(root, "regular.json")
	if err := os.WriteFile(regular, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A regular file standing where a directory component is required is an
	// unstable input boundary, not a traversable parent.
	through := filepath.Join(regular, "child.json")
	if _, _, err := inspectPathWithoutLinks(through, "provider input"); err == nil {
		t.Fatal("a non-directory parent component was accepted")
	}

	absent := filepath.Join(root, "absent", "child.json")
	if _, _, err := inspectPathWithoutLinks(absent, "provider input"); err == nil ||
		!strings.Contains(err.Error(), "inspect provider input path component") {
		t.Fatalf("absent parent error = %v, want a component inspection refusal", err)
	}
}

func TestProviderInputAdmissionRejectsDuplicatePathAndFileIdentity(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input.json")
	if err := os.WriteFile(path, []byte(`{"value":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	if err := accumulator.addPathIdentity(path, file); err != nil {
		t.Fatalf("first admission of a distinct path failed: %v", err)
	}
	if len(accumulator.pathIdentities) != 1 {
		t.Fatalf("retained path identities = %d, want 1", len(accumulator.pathIdentities))
	}

	if err := accumulator.rejectDuplicatePathIdentity(path, nil); err == nil ||
		!strings.Contains(err.Error(), "duplicate path or file identity") {
		t.Fatalf("duplicate path error = %v, want a duplicate refusal", err)
	}
	if err := accumulator.addPathIdentity(path, file); err == nil ||
		!strings.Contains(err.Error(), "duplicate path or file identity") {
		t.Fatalf("re-adding the same path error = %v, want a duplicate refusal", err)
	}
	if len(accumulator.pathIdentities) != 1 {
		t.Fatalf("a refused duplicate still grew the roster to %d", len(accumulator.pathIdentities))
	}

	// The same inode reached through a hard link is a different path key but
	// the same file identity, and must still be refused.
	alias := filepath.Join(root, "alias.json")
	if err := os.Link(path, alias); err != nil {
		t.Fatalf("hard link the retained input to an alias path: %v", err)
	}
	aliasFile, err := os.Open(alias)
	if err != nil {
		t.Fatal(err)
	}
	defer aliasFile.Close()
	if err := accumulator.rejectDuplicateOpenFileIdentity(alias, aliasFile); err == nil ||
		!strings.Contains(err.Error(), "duplicate path or file identity") {
		t.Fatalf("hard-link alias error = %v, want a duplicate file-identity refusal", err)
	}
}

func TestProviderInputAdmissionRejectsDuplicateOnANilAccumulator(t *testing.T) {
	var accumulator *providerInputAdmissionAccumulator
	if err := accumulator.rejectDuplicatePathIdentity("input.json", nil); err == nil ||
		!strings.Contains(err.Error(), "accumulator is nil") {
		t.Fatalf("nil accumulator error = %v, want an explicit nil refusal", err)
	}
}

func TestProviderInputAdmissionRebuildsItsPathIdentityIndexes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input.json")
	if err := os.WriteFile(path, []byte(`{"value":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	identity, err := stableProviderInputFileIdentity(file)
	if err != nil {
		t.Fatal(err)
	}

	// A roster restored without its lookup indexes must rebuild them rather
	// than silently admitting an already-retained path a second time.
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	accumulator.pathIdentities = []providerInputAdmissionPathIdentity{{
		key:      canonicalProviderInputPathKey(path),
		identity: identity,
	}}
	accumulator.pathKeys = nil
	accumulator.fileIdentities = nil

	if err := accumulator.rejectDuplicatePathIdentity(path, nil); err == nil ||
		!strings.Contains(err.Error(), "duplicate path or file identity") {
		t.Fatalf("rebuilt index error = %v, want the retained path to be refused", err)
	}
	if len(accumulator.pathKeys) != 1 || len(accumulator.fileIdentities) != 1 {
		t.Fatalf("rebuilt indexes = %d keys / %d identities, want 1 and 1",
			len(accumulator.pathKeys), len(accumulator.fileIdentities))
	}
	if err := accumulator.rejectDuplicateOpenFileIdentity(path, file); err == nil ||
		!strings.Contains(err.Error(), "duplicate path or file identity") {
		t.Fatalf("rebuilt file-identity index error = %v, want the retained identity to be refused", err)
	}
}
