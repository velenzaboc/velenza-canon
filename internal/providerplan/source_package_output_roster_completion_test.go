package providerplan

import (
	"strings"
	"testing"
)

// The output roster is the closed set of files a source package may publish.
// Every refusal below is a way one entry could collide with, shadow, or escape
// another once the tree is materialized on a case-folding filesystem.
func TestPrepareSourcePackageOutputRosterRefusesUnusableRelativePaths(t *testing.T) {
	for _, test := range []struct {
		name   string
		roster []factorySourceOutputFile
		want   string
	}{
		{
			name:   "empty roster",
			roster: nil,
			want:   "roster is empty",
		},
		{
			name:   "empty relative path",
			roster: []factorySourceOutputFile{{RelativePath: "  ", Raw: []byte("x")}},
			want:   "is empty, padded, or contains NUL",
		},
		{
			name:   "padded relative path",
			roster: []factorySourceOutputFile{{RelativePath: " a.json", Raw: []byte("x")}},
			want:   "is empty, padded, or contains NUL",
		},
		{
			name:   "relative path contains NUL",
			roster: []factorySourceOutputFile{{RelativePath: "a\x00b.json", Raw: []byte("x")}},
			want:   "is empty, padded, or contains NUL",
		},
		{
			name:   "backslash separator",
			roster: []factorySourceOutputFile{{RelativePath: `dir\a.json`, Raw: []byte("x")}},
			want:   "not a clean slash-separated relative file path",
		},
		{
			name:   "absolute path",
			roster: []factorySourceOutputFile{{RelativePath: "/a.json", Raw: []byte("x")}},
			want:   "not a clean slash-separated relative file path",
		},
		{
			name:   "unclean path",
			roster: []factorySourceOutputFile{{RelativePath: "dir/./a.json", Raw: []byte("x")}},
			want:   "not a clean slash-separated relative file path",
		},
		{
			name:   "current directory",
			roster: []factorySourceOutputFile{{RelativePath: ".", Raw: []byte("x")}},
			want:   "not a clean slash-separated relative file path",
		},
		{
			// path.Clean leaves a leading "..", so this survives the cleanliness
			// check and must be caught by the per-component check instead.
			name:   "parent traversal",
			roster: []factorySourceOutputFile{{RelativePath: "../a.json", Raw: []byte("x")}},
			want:   "contains an invalid component",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := prepareSourcePackageOutputRoster(test.roster)
			if err == nil {
				t.Fatalf("an unusable output roster was accepted")
			}
			if prepared != nil {
				t.Fatalf("a refused roster returned %d prepared entries, want none", len(prepared))
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestPrepareSourcePackageOutputRosterRefusesAliasingAndShadowingEntries(t *testing.T) {
	for _, test := range []struct {
		name   string
		roster []factorySourceOutputFile
		want   string
	}{
		{
			name: "identical paths",
			roster: []factorySourceOutputFile{
				{RelativePath: "a.json", Raw: []byte("one")},
				{RelativePath: "a.json", Raw: []byte("two")},
			},
			want: "duplicate or case-fold-alias paths",
		},
		{
			name: "case-fold alias paths",
			roster: []factorySourceOutputFile{
				{RelativePath: "a.json", Raw: []byte("one")},
				{RelativePath: "A.json", Raw: []byte("two")},
			},
			want: "duplicate or case-fold-alias paths",
		},
		{
			name: "a file is also used as a directory",
			roster: []factorySourceOutputFile{
				{RelativePath: "dir", Raw: []byte("one")},
				{RelativePath: "dir/a.json", Raw: []byte("two")},
			},
			want: "treats file",
		},
		{
			name: "a file is used as a directory under a case-fold alias",
			roster: []factorySourceOutputFile{
				{RelativePath: "Dir", Raw: []byte("one")},
				{RelativePath: "dir/a.json", Raw: []byte("two")},
			},
			want: "treats file",
		},
		{
			name: "case-fold alias directory components",
			roster: []factorySourceOutputFile{
				{RelativePath: "Dir/a.json", Raw: []byte("one")},
				{RelativePath: "dir/b.json", Raw: []byte("two")},
			},
			want: "case-fold-alias directory components",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := prepareSourcePackageOutputRoster(test.roster)
			if err == nil {
				t.Fatalf("an aliasing output roster was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want a refusal containing %q", err, test.want)
			}
		})
	}
}

func TestPrepareSourcePackageOutputRosterSortsAndCopiesDeclaredBytes(t *testing.T) {
	raw := []byte("declared bytes")
	prepared, err := prepareSourcePackageOutputRoster([]factorySourceOutputFile{
		{RelativePath: "b/second.json", Raw: raw},
		{RelativePath: "a/first.json", Raw: []byte("other")},
	})
	if err != nil {
		t.Fatalf("a well-formed roster was rejected: %v", err)
	}
	if len(prepared) != 2 || prepared[0].relative != "a/first.json" || prepared[1].relative != "b/second.json" {
		t.Fatalf("prepared roster = %+v, want it sorted by relative path", prepared)
	}
	if len(prepared[1].components) != 2 || prepared[1].components[0] != "b" {
		t.Fatalf("prepared components = %v, want the split relative path", prepared[1].components)
	}
	// The roster copies declared bytes, so a caller mutating its own slice
	// afterwards cannot change what gets published.
	raw[0] = 'X'
	if string(prepared[1].raw) != "declared bytes" {
		t.Fatalf("prepared bytes = %q, want the copy taken at preparation", prepared[1].raw)
	}
}

func TestSourcePackageOutputPathIsFoldedPrefix(t *testing.T) {
	if sourcePackageOutputPathIsFoldedPrefix([]string{"a", "b"}, []string{"a", "b"}) {
		t.Fatal("an equal-length path was treated as a prefix of itself")
	}
	if !sourcePackageOutputPathIsFoldedPrefix([]string{"Dir"}, []string{"dir", "a.json"}) {
		t.Fatal("a case-fold prefix was not detected")
	}
	if sourcePackageOutputPathIsFoldedPrefix([]string{"other"}, []string{"dir", "a.json"}) {
		t.Fatal("an unrelated component was treated as a prefix")
	}
}

func TestSourcePackageOutputRetentionHelpersRefuseAbsentHandles(t *testing.T) {
	if _, err := inspectNewSourcePackageOutputFile(nil, "a.json"); err == nil ||
		!strings.Contains(err.Error(), "retain source-package file") {
		t.Fatalf("nil handle error = %v, want a retention refusal", err)
	}
	if _, err := writeExactSourcePackageOutputFile(nil, "a.json", []byte("x"), providerInputStableFileIdentity{}, func() error { return nil }); err == nil ||
		!strings.Contains(err.Error(), "and its sync operation") {
		t.Fatalf("nil handle write error = %v, want a retention refusal", err)
	}
}

func TestPrivateFactorySourceOutputRefusesNilCallbackAndPaddedTempRoot(t *testing.T) {
	if err := withPrivateFactorySourceOutputDirectory([]factorySourceOutputFile{{RelativePath: "a.json", Raw: []byte("x")}}, nil); err == nil ||
		!strings.Contains(err.Error(), "callback is nil") {
		t.Fatalf("nil callback error = %v, want an explicit nil refusal", err)
	}
	if _, err := newPrivateFactorySourceOutputCoordinate("  "); err == nil ||
		!strings.Contains(err.Error(), "temp root is empty or padded") {
		t.Fatalf("padded temp root error = %v, want an empty-or-padded refusal", err)
	}
}

func TestPublishFactorySourceOutputDirectoryRefusesAnUncleanRoot(t *testing.T) {
	roster := []factorySourceOutputFile{{RelativePath: "a.json", Raw: []byte("x")}}
	for _, root := range []string{"", "   ", " /tmp/out"} {
		if err := publishFactorySourceOutputDirectoryExclusive(root, roster); err == nil ||
			!strings.Contains(err.Error(), "empty, padded, or not clean") {
			t.Fatalf("root %q error = %v, want an unclean-root refusal", root, err)
		}
	}
}
