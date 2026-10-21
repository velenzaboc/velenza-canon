package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SpecSectionRef identifies one normative section declared in an .ood.json specification.
type SpecSectionRef struct {
	DocID      string `json:"doc_id"`
	SpecPrefix string `json:"spec_prefix"`
	SectionID  string `json:"section_id"`
	SourceFile string `json:"source_file"`
}

// CodeSpecAnnotation records one //spec: or //volt: annotation discovered in source code.
type CodeSpecAnnotation struct {
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	FilePath string `json:"file_path"`
	Line     int    `json:"line"`
}

// SpecSectionCoverage summarizes code annotations covering a single spec section.
type SpecSectionCoverage struct {
	DocID      string               `json:"doc_id"`
	SpecPrefix string               `json:"spec_prefix"`
	SectionID  string               `json:"section_id"`
	SourceFile string               `json:"source_file"`
	CoveredBy  []CodeSpecAnnotation `json:"covered_by,omitempty"`
}

// SpecCodeTraceabilityReport is the deterministic cross-layer Canon-to-Cambium traceability report.
type SpecCodeTraceabilityReport struct {
	SpecDir             string                `json:"spec_dir"`
	CodeDir             string                `json:"code_dir"`
	SpecsScanned        int                   `json:"specs_scanned"`
	TotalSections       int                   `json:"total_sections"`
	CoveredSections     int                   `json:"covered_sections"`
	UncoveredSections   []SpecSectionRef      `json:"uncovered_sections"`
	DanglingAnnotations []CodeSpecAnnotation  `json:"dangling_annotations"`
	VoltAnnotations     []CodeSpecAnnotation  `json:"volt_annotations"`
	SectionCoverage     []SpecSectionCoverage `json:"section_coverage"`
}

var (
	versionSuffixRe  = regexp.MustCompile(`(?i)_v[0-9]+$`)
	codeAnnotationRe = regexp.MustCompile(`//(spec|volt):([A-Za-z0-9_./:#-]+)`)
)

// resolveConfigPath resolves the configuration file path from VELENZA_CANON_CONFIG,
// falling back to SPEC_GRAPH_CONFIG and then "spec-graph.config.json".
func resolveConfigPath(getenv func(string) string) string {
	if getenv != nil {
		if p := strings.TrimSpace(getenv("VELENZA_CANON_CONFIG")); p != "" {
			return p
		}
		if p := strings.TrimSpace(getenv("SPEC_GRAPH_CONFIG")); p != "" {
			return p
		}
	}
	return "spec-graph.config.json"
}

type parsedOODSpecEnvelope struct {
	DocID    string                     `json:"doc_id"`
	Sections map[string]json.RawMessage `json:"sections"`
}

// ScanSpecCodeTraceability scans all .ood.json specifications in specDir and
// cross-references their declared sections against //spec: and //volt: annotations
// across source files in codeDir.
func ScanSpecCodeTraceability(specDir, codeDir string) (*SpecCodeTraceabilityReport, error) {
	if strings.TrimSpace(specDir) == "" {
		return nil, fmt.Errorf("spec_dir is required")
	}
	if strings.TrimSpace(codeDir) == "" {
		return nil, fmt.Errorf("code_dir is required")
	}

	var specFiles []string
	err := filepath.WalkDir(specDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".inarch" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".ood.json") && !strings.HasPrefix(d.Name(), "_") {
			specFiles = append(specFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk spec_dir %q: %w", specDir, err)
	}
	sort.Strings(specFiles)

	var coverages []SpecSectionCoverage
	// lookup index: lowercase(specAlias) + "#" + lowercase(sectionID) -> index in coverages
	sectionIndex := make(map[string]int)

	for _, sf := range specFiles {
		raw, err := os.ReadFile(sf)
		if err != nil {
			return nil, fmt.Errorf("read spec %q: %w", sf, err)
		}
		var env parsedOODSpecEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, fmt.Errorf("parse spec %q: %w", sf, err)
		}
		base := filepath.Base(sf)
		prefix := strings.ToLower(strings.TrimSuffix(base, ".ood.json"))
		if strings.HasSuffix(base, ".OOD.JSON") {
			prefix = strings.ToLower(strings.TrimSuffix(base, ".OOD.JSON"))
		}
		stem := versionSuffixRe.ReplaceAllString(prefix, "")
		relFile, relErr := filepath.Rel(specDir, sf)
		if relErr != nil {
			relFile = base
		}
		relFile = filepath.ToSlash(relFile)

		secIDs := make([]string, 0, len(env.Sections))
		for secID := range env.Sections {
			secIDs = append(secIDs, secID)
		}
		sort.Strings(secIDs)

		for _, secID := range secIDs {
			idx := len(coverages)
			coverages = append(coverages, SpecSectionCoverage{
				DocID:      env.DocID,
				SpecPrefix: stem,
				SectionID:  secID,
				SourceFile: relFile,
			})
			secLower := strings.ToLower(secID)
			if env.DocID != "" {
				sectionIndex[strings.ToLower(env.DocID)+"#"+secLower] = idx
			}
			sectionIndex[prefix+"#"+secLower] = idx
			if stem != "" {
				sectionIndex[stem+"#"+secLower] = idx
			}
		}
	}

	var codeFiles []string
	err = filepath.WalkDir(codeDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".inarch" || name == "node_modules" || name == "vendor" || name == "target" {
				return filepath.SkipDir
			}
			return nil
		}
		if isTraceableSourceFile(d.Name()) {
			codeFiles = append(codeFiles, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk code_dir %q: %w", codeDir, err)
	}
	sort.Strings(codeFiles)

	dangling := make([]CodeSpecAnnotation, 0)
	voltAnns := make([]CodeSpecAnnotation, 0)

	for _, cf := range codeFiles {
		relCode, relErr := filepath.Rel(codeDir, cf)
		if relErr != nil {
			relCode = filepath.Base(cf)
		}
		relCode = filepath.ToSlash(relCode)

		anns, err := extractFileAnnotations(cf, relCode)
		if err != nil {
			return nil, err
		}
		for _, ann := range anns {
			if ann.Kind == "volt" {
				voltAnns = append(voltAnns, ann)
				continue
			}
			if idx, ok := resolveSpecSectionIndex(ann.Target, sectionIndex); ok {
				coverages[idx].CoveredBy = append(coverages[idx].CoveredBy, ann)
			} else {
				dangling = append(dangling, ann)
			}
		}
	}

	uncovered := make([]SpecSectionRef, 0)
	coveredCount := 0
	for _, cov := range coverages {
		if len(cov.CoveredBy) > 0 {
			coveredCount++
		} else {
			uncovered = append(uncovered, SpecSectionRef{
				DocID:      cov.DocID,
				SpecPrefix: cov.SpecPrefix,
				SectionID:  cov.SectionID,
				SourceFile: cov.SourceFile,
			})
		}
	}
	if coverages == nil {
		coverages = []SpecSectionCoverage{}
	}

	return &SpecCodeTraceabilityReport{
		SpecDir:             specDir,
		CodeDir:             codeDir,
		SpecsScanned:        len(specFiles),
		TotalSections:       len(coverages),
		CoveredSections:     coveredCount,
		UncoveredSections:   uncovered,
		DanglingAnnotations: dangling,
		VoltAnnotations:     voltAnns,
		SectionCoverage:     coverages,
	}, nil
}

func isTraceableSourceFile(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".go", ".rs", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".py", ".sh", ".sql":
		return true
	default:
		return false
	}
}

func extractFileAnnotations(absPath, relPath string) ([]CodeSpecAnnotation, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open source file %q: %w", absPath, err)
	}
	defer f.Close()

	var out []CodeSpecAnnotation
	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		matches := codeAnnotationRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			if len(m) < 3 {
				continue
			}
			target := strings.TrimRight(m[2], ".,;)]}")
			if target == "" {
				continue
			}
			out = append(out, CodeSpecAnnotation{
				Kind:     m[1],
				Target:   target,
				FilePath: relPath,
				Line:     lineNo,
			})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan source file %q: %w", absPath, err)
	}
	return out, nil
}

func resolveSpecSectionIndex(target string, sectionIndex map[string]int) (int, bool) {
	parts := strings.SplitN(target, "#", 2)
	if len(parts) != 2 {
		return 0, false
	}
	specKey := strings.ToLower(strings.TrimSpace(parts[0]))
	secPath := strings.ToLower(strings.TrimSpace(parts[1]))
	if specKey == "" || secPath == "" {
		return 0, false
	}
	if idx, ok := sectionIndex[specKey+"#"+secPath]; ok {
		return idx, true
	}
	if dot := strings.IndexByte(secPath, '.'); dot > 0 {
		secRoot := secPath[:dot]
		if idx, ok := sectionIndex[specKey+"#"+secRoot]; ok {
			return idx, true
		}
	}
	stemKey := versionSuffixRe.ReplaceAllString(specKey, "")
	if stemKey != specKey {
		if idx, ok := sectionIndex[stemKey+"#"+secPath]; ok {
			return idx, true
		}
		if dot := strings.IndexByte(secPath, '.'); dot > 0 {
			secRoot := secPath[:dot]
			if idx, ok := sectionIndex[stemKey+"#"+secRoot]; ok {
				return idx, true
			}
		}
	}
	return 0, false
}

func cmdTraceCode(ctx context.Context, args []string) error {
	return runTraceCodeCLI(ctx, args, os.Stdout)
}

func runTraceCodeCLI(_ context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("trace-code", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	specDir := fs.String("spec-dir", "", "Directory containing canonical .ood.json specifications")
	codeDir := fs.String("code-dir", "", "Directory containing source code with //spec: and //volt: annotations")
	failOnDangling := fs.Bool("fail-on-dangling", false, "Return non-zero error if any //spec: annotation references a missing section")
	failOnUncovered := fs.Bool("fail-on-uncovered", false, "Return non-zero error if any spec section has zero code annotations")
	if err := fs.Parse(args); err != nil {
		return err
	}

	report, err := ScanSpecCodeTraceability(*specDir, *codeDir)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal traceability report: %w", err)
	}
	if _, err := fmt.Fprintln(out, string(encoded)); err != nil {
		return err
	}
	if *failOnDangling && len(report.DanglingAnnotations) > 0 {
		return fmt.Errorf("spec-code traceability failed: found %d dangling //spec: annotation(s)", len(report.DanglingAnnotations))
	}
	if *failOnUncovered && len(report.UncoveredSections) > 0 {
		return fmt.Errorf("spec-code traceability failed: found %d uncovered spec section(s)", len(report.UncoveredSections))
	}
	return nil
}

type traceCodeInput struct {
	SpecDir string `json:"spec_dir" jsonschema:"Path to directory containing .ood.json specification files"`
	CodeDir string `json:"code_dir" jsonschema:"Path to source code directory to scan for //spec: and //volt: annotations"`
}

func addTraceCodeTool(server *mcp.Server) {
	mcp.AddTool(server,
		&mcp.Tool{
			Name:        "spec_graph_trace_code",
			Description: `Cross-layer Canon-to-Cambium traceability scanner. Walks .ood.json specifications in spec_dir and source files in code_dir to compute section-level //spec: coverage, uncovered normative sections, dangling //spec: references, and //volt: circuit annotations.`,
		},
		func(_ context.Context, _ *mcp.CallToolRequest, in traceCodeInput) (*mcp.CallToolResult, SpecCodeTraceabilityReport, error) {
			report, err := ScanSpecCodeTraceability(in.SpecDir, in.CodeDir)
			if err != nil {
				return textResult(SpecCodeTraceabilityReport{}, err), SpecCodeTraceabilityReport{}, err
			}
			return textResult(*report, nil), *report, nil
		},
	)
}
