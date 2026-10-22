package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestAuditBootstrapListenerRequiresLoopback(t *testing.T) {
	t.Parallel()

	for _, address := range []string{
		"127.0.0.1:8765",
		"localhost:8765",
		"[::1]:8765",
	} {
		address := address
		t.Run("accept_"+address, func(t *testing.T) {
			t.Parallel()
			cfg := validIdentityBoundConfig()
			cfg.AllowSpannerEmulator = false
			cfg.ListenAddress = address
			if err := cfg.Validate(); err != nil {
				t.Fatalf("bootstrap loopback listen_address %q rejected: %v", address, err)
			}
		})
	}

	for _, address := range []string{
		"",
		"0.0.0.0:8765",
		"[::]:8765",
		"192.0.2.10:8765",
		"[2001:db8::1]:8765",
		"127.0.0.1",
		":8765",
	} {
		address := address
		t.Run("reject_"+address, func(t *testing.T) {
			t.Parallel()
			cfg := validIdentityBoundConfig()
			cfg.AllowSpannerEmulator = false
			cfg.ListenAddress = address
			if err := cfg.Validate(); err == nil {
				t.Fatalf("bootstrap non-loopback or malformed listen_address %q accepted", address)
			}
		})
	}
}

func TestAuditTraceAnnotationsRequireRealCommentsForSupportedSources(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		ext    string
		source string
	}{
		{name: "go", ext: ".go", source: "package p\nvar example = \"//spec:DOC-COMMENTS#string_only\"\n// //spec:DOC-COMMENTS#comment\n"},
		{name: "rust", ext: ".rs", source: "const EXAMPLE: &str = \"//spec:DOC-COMMENTS#string_only\";\n// //spec:DOC-COMMENTS#comment\n"},
		{name: "typescript", ext: ".ts", source: "const example = \"//spec:DOC-COMMENTS#string_only\";\n// //spec:DOC-COMMENTS#comment\n"},
		{name: "tsx", ext: ".tsx", source: "const example = \"//spec:DOC-COMMENTS#string_only\";\n// //spec:DOC-COMMENTS#comment\n"},
		{name: "javascript", ext: ".js", source: "const example = \"//spec:DOC-COMMENTS#string_only\";\n// //spec:DOC-COMMENTS#comment\n"},
		{name: "mjs", ext: ".mjs", source: "const example = \"//spec:DOC-COMMENTS#string_only\";\n// //spec:DOC-COMMENTS#comment\n"},
		{name: "cjs", ext: ".cjs", source: "const example = \"//spec:DOC-COMMENTS#string_only\";\n// //spec:DOC-COMMENTS#comment\n"},
		{name: "python", ext: ".py", source: "example = \"//spec:DOC-COMMENTS#string_only\"\n# //spec:DOC-COMMENTS#comment\n"},
		{name: "shell", ext: ".sh", source: "example='//spec:DOC-COMMENTS#string_only'\n# //spec:DOC-COMMENTS#comment\n"},
		{name: "sql", ext: ".sql", source: "SELECT '//spec:DOC-COMMENTS#string_only';\n-- //spec:DOC-COMMENTS#comment\n"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "source"+tc.ext)
			if err := os.WriteFile(path, []byte(tc.source), 0o600); err != nil {
				t.Fatal(err)
			}

			annotations, err := extractFileAnnotations(path, filepath.Base(path))
			if err != nil {
				t.Fatalf("extractFileAnnotations(%s): %v", tc.ext, err)
			}
			if len(annotations) != 1 {
				t.Fatalf("annotations for %s = %+v, want only the genuine comment", tc.ext, annotations)
			}
			if annotations[0].Kind != "spec" || annotations[0].Target != "DOC-COMMENTS#comment" {
				t.Fatalf("annotation for %s = %+v, want real comment target", tc.ext, annotations[0])
			}
		})
	}
}

func TestAuditTraceResolutionRequiresExactUnambiguousCoordinate(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	specDir := filepath.Join(root, "specs")
	codeDir := filepath.Join(root, "code")
	if err := os.MkdirAll(specDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	v1 := `{
  "doc_id": "DOC-TRACE-V1",
  "sections": {
    "s1_core": {
      "requirements": {
        "enforcement": {"rule": "Version one enforcement."}
      }
    }
  }
}`
	v2 := `{
  "doc_id": "DOC-TRACE-V2",
  "sections": {
    "s1_core": {
      "requirements": {
        "enforcement": {"rule": "Version two enforcement."}
      }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(specDir, "TRACE_SPEC_v1.ood.json"), []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(specDir, "TRACE_SPEC_v2.ood.json"), []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	source := `package trace

// Qualified v1 root coordinate remains valid.
// //spec:TRACE_SPEC_v1#s1_core
func v1() {}

// Qualified v2 coordinate names an existing nested object.
// //spec:TRACE_SPEC_v2#s1_core.requirements.enforcement
func v2() {}

// A versionless alias shared by v1 and v2 is ambiguous.
// //spec:TRACE_SPEC#s1_core
func ambiguous() {}

// This nested component does not exist in v2.
// //spec:TRACE_SPEC_v2#s1_core.requirements.missing
func missing() {}

// A target without a section delimiter is malformed.
// //spec:TRACE_SPEC_v1
func malformed() {}
`
	if err := os.WriteFile(filepath.Join(codeDir, "trace.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := ScanSpecCodeTraceability(specDir, codeDir)
	if err != nil {
		t.Fatalf("ScanSpecCodeTraceability: %v", err)
	}
	if report.SpecsScanned != 2 || report.TotalSections != 2 || report.CoveredSections != 2 {
		t.Fatalf("trace counts = specs:%d total:%d covered:%d, want 2/2/2", report.SpecsScanned, report.TotalSections, report.CoveredSections)
	}

	wantDangling := []string{
		"TRACE_SPEC#s1_core",
		"TRACE_SPEC_v1",
		"TRACE_SPEC_v2#s1_core.requirements.missing",
	}
	gotDangling := make([]string, 0, len(report.DanglingAnnotations))
	for _, annotation := range report.DanglingAnnotations {
		gotDangling = append(gotDangling, annotation.Target)
	}
	sort.Strings(gotDangling)
	sort.Strings(wantDangling)
	if len(gotDangling) != len(wantDangling) {
		t.Fatalf("dangling targets = %v, want %v", gotDangling, wantDangling)
	}
	for i := range wantDangling {
		if gotDangling[i] != wantDangling[i] {
			t.Fatalf("dangling targets = %v, want %v", gotDangling, wantDangling)
		}
	}

	wantCoverage := map[string]string{
		"TRACE_SPEC_v1.ood.json": "TRACE_SPEC_v1#s1_core",
		"TRACE_SPEC_v2.ood.json": "TRACE_SPEC_v2#s1_core.requirements.enforcement",
	}
	for _, coverage := range report.SectionCoverage {
		wantTarget, ok := wantCoverage[coverage.SourceFile]
		if !ok {
			t.Fatalf("unexpected coverage source %q", coverage.SourceFile)
		}
		if len(coverage.CoveredBy) != 1 || coverage.CoveredBy[0].Target != wantTarget {
			t.Fatalf("coverage for %s = %+v, want exactly %q", coverage.SourceFile, coverage.CoveredBy, wantTarget)
		}
	}
}
