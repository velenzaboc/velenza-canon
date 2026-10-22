package main

import (
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
	"unicode/utf8"

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

type specSectionIndex struct {
	sections         map[string][]int
	aliasOwners      map[string]string
	ambiguousAliases map[string]bool
}

func newSpecSectionIndex() specSectionIndex {
	return specSectionIndex{
		sections:         make(map[string][]int),
		aliasOwners:      make(map[string]string),
		ambiguousAliases: make(map[string]bool),
	}
}

type sourceComment struct {
	Text string
	Line int
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
	// A coordinate can name multiple sections when versionless aliases collide.
	// Preserve all candidates so resolution can reject ambiguity instead of
	// silently letting the last specification scanned win.
	sectionIndex := newSpecSectionIndex()

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
		prefix := strings.ToLower(base[:len(base)-len(".ood.json")])
		stem := versionSuffixRe.ReplaceAllString(prefix, "")
		relFile, relErr := filepath.Rel(specDir, sf)
		if relErr != nil {
			relFile = base
		}
		relFile = filepath.ToSlash(relFile)
		if env.DocID != "" {
			sectionIndex.addAliasOwner(env.DocID, relFile)
		}
		sectionIndex.addAliasOwner(prefix, relFile)
		if stem != "" {
			sectionIndex.addAliasOwner(stem, relFile)
		}

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
			sectionPaths, err := exactJSONSectionPaths(secID, env.Sections[secID])
			if err != nil {
				return nil, fmt.Errorf("parse section %q in spec %q: %w", secID, sf, err)
			}
			if env.DocID != "" {
				addSpecSectionAliases(sectionIndex, env.DocID, sectionPaths, idx)
			}
			addSpecSectionAliases(sectionIndex, prefix, sectionPaths, idx)
			if stem != "" {
				addSpecSectionAliases(sectionIndex, stem, sectionPaths, idx)
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
	raw, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read source file %q: %w", absPath, err)
	}
	comments := extractSourceComments(string(raw), strings.ToLower(filepath.Ext(absPath)))
	var out []CodeSpecAnnotation
	for _, comment := range comments {
		matches := codeAnnotationRe.FindAllStringSubmatchIndex(comment.Text, -1)
		for _, match := range matches {
			if len(match) < 6 {
				continue
			}
			kind := comment.Text[match[2]:match[3]]
			target := strings.TrimRight(comment.Text[match[4]:match[5]], ".,;)]}")
			if target == "" {
				continue
			}
			line := comment.Line + strings.Count(comment.Text[:match[0]], "\n")
			out = append(out, CodeSpecAnnotation{
				Kind:     kind,
				Target:   target,
				FilePath: relPath,
				Line:     line,
			})
		}
	}
	return out, nil
}

func extractSourceComments(source, ext string) []sourceComment {
	switch ext {
	case ".go":
		return extractCStyleComments(source, cStyleDialect{backtickStrings: true})
	case ".rs":
		return extractCStyleComments(source, cStyleDialect{rustRawStrings: true, nestedBlockComments: true, rustCharLiterals: true})
	case ".ts", ".tsx", ".js", ".mjs", ".cjs":
		return extractJavaScriptComments(source, ext == ".tsx", ext == ".ts" || ext == ".tsx")
	case ".py":
		return extractPythonComments(source)
	case ".sh":
		return extractShellComments(source)
	case ".sql":
		return extractSQLComments(source)
	default:
		return nil
	}
}

type cStyleDialect struct {
	backtickStrings     bool
	rustRawStrings      bool
	nestedBlockComments bool
	rustCharLiterals    bool
}

func extractCStyleComments(source string, dialect cStyleDialect) []sourceComment {
	var comments []sourceComment
	line := 1
	for i := 0; i < len(source); {
		if source[i] == '\n' {
			line++
			i++
			continue
		}
		if dialect.rustRawStrings {
			if closeDelimiter, contentStart, ok := rustRawStringAt(source, i); ok {
				end := strings.Index(source[contentStart:], closeDelimiter)
				if end < 0 {
					line += strings.Count(source[i:], "\n")
					break
				}
				next := contentStart + end + len(closeDelimiter)
				line += strings.Count(source[i:next], "\n")
				i = next
				continue
			}
		}
		if source[i] == '/' && i+1 < len(source) && source[i+1] == '/' {
			start, startLine := i, line
			i += 2
			for i < len(source) && source[i] != '\n' {
				i++
			}
			comments = append(comments, sourceComment{Text: source[start:i], Line: startLine})
			continue
		}
		if source[i] == '/' && i+1 < len(source) && source[i+1] == '*' {
			start, startLine, depth := i, line, 1
			i += 2
			for i < len(source) && depth > 0 {
				if source[i] == '\n' {
					line++
					i++
					continue
				}
				if dialect.nestedBlockComments && i+1 < len(source) && source[i] == '/' && source[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if i+1 < len(source) && source[i] == '*' && source[i+1] == '/' {
					depth--
					i += 2
					continue
				}
				i++
			}
			comments = append(comments, sourceComment{Text: source[start:i], Line: startLine})
			continue
		}
		if source[i] == '"' || (source[i] == '\'' && (!dialect.rustCharLiterals || rustQuotedCharAt(source, i))) {
			next := skipQuoted(source, i, source[i], true)
			line += strings.Count(source[i:next], "\n")
			i = next
			continue
		}
		if dialect.backtickStrings && source[i] == '`' {
			next := skipQuoted(source, i, '`', false)
			line += strings.Count(source[i:next], "\n")
			i = next
			continue
		}
		i++
	}
	return comments
}

func rustRawStringAt(source string, start int) (string, int, bool) {
	i := start
	if i < len(source) && source[i] == 'b' {
		i++
	}
	if i >= len(source) || source[i] != 'r' {
		return "", 0, false
	}
	i++
	hashStart := i
	for i < len(source) && source[i] == '#' {
		i++
	}
	if i >= len(source) || source[i] != '"' {
		return "", 0, false
	}
	hashes := source[hashStart:i]
	return "\"" + hashes, i + 1, true
}

func rustQuotedCharAt(source string, start int) bool {
	i := start + 1
	if i >= len(source) || source[i] == '\n' || source[i] == '\'' {
		return false
	}
	if source[i] == '\\' {
		i++
		if i >= len(source) || source[i] == '\n' {
			return false
		}
		if source[i] == 'u' && i+1 < len(source) && source[i+1] == '{' {
			i += 2
			for i < len(source) && source[i] != '}' && source[i] != '\n' {
				i++
			}
			if i >= len(source) || source[i] != '}' {
				return false
			}
			i++
		} else {
			i++
		}
	} else {
		_, width := utf8.DecodeRuneInString(source[i:])
		if width == 0 {
			return false
		}
		i += width
	}
	return i < len(source) && source[i] == '\''
}

func skipQuoted(source string, start int, quote byte, escapes bool) int {
	for i := start + 1; i < len(source); i++ {
		if quote != '`' && source[i] == '\n' {
			return i
		}
		if escapes && source[i] == '\\' {
			i++
			continue
		}
		if source[i] == quote {
			return i + 1
		}
	}
	return len(source)
}

type javascriptLexMode struct {
	templateText bool
	expression   bool
	braceDepth   int
	jsx          bool
	jsxText      bool
	jsxDepth     int
	closingTag   bool
}

func extractJavaScriptComments(source string, allowJSX, allowTypeScript bool) []sourceComment {
	var comments []sourceComment
	modes := []javascriptLexMode{{}}
	// A regular expression may begin immediately after a control-statement
	// header even though an ordinary closing parenthesis ends an expression.
	var controlParens []bool
	// Keep statement/declaration blocks distinct from object and function
	// expressions so a following slash is interpreted in the right grammar
	// context.
	var statementBraces []bool
	lastIdentifier := ""
	lastIdentifierStartedStatement := false
	regexAfterControlParen := false
	statementStart := true
	functionDeclarationPending := false
	functionDeclarationParamDepth := 0
	functionDeclarationBodyReady := false
	blockDeclarationPending := false
	blockDeclarationParenDepth := 0
	blockDeclarationBracketDepth := 0
	blockDeclarationAngleDepth := 0
	bracketDepth := 0
	line := 1
	for i := 0; i < len(source); {
		mode := &modes[len(modes)-1]
		if mode.jsx {
			if source[i] == '\n' {
				line++
				i++
				continue
			}
			if mode.jsxText {
				if source[i] == '{' {
					modes = append(modes, javascriptLexMode{expression: true, braceDepth: 1})
					i++
					continue
				}
				if source[i] == '<' && i+1 < len(source) {
					if source[i+1] == '/' {
						mode.jsxText = false
						mode.closingTag = true
						i += 2
						continue
					}
					if isJSXTagStart(source[i+1]) {
						mode.jsxText = false
						mode.closingTag = false
						mode.jsxDepth++
						i++
						continue
					}
				}
				i++
				continue
			}
			if source[i] == '\'' || source[i] == '"' {
				next := skipQuoted(source, i, source[i], true)
				line += strings.Count(source[i:next], "\n")
				i = next
				continue
			}
			if source[i] == '{' {
				modes = append(modes, javascriptLexMode{expression: true, braceDepth: 1})
				i++
				continue
			}
			if source[i] == '/' && i+1 < len(source) && source[i+1] == '>' {
				mode.jsxDepth--
				i += 2
				if mode.jsxDepth == 0 {
					modes = modes[:len(modes)-1]
				} else {
					mode.jsxText = true
				}
				continue
			}
			if source[i] == '>' {
				if mode.closingTag {
					mode.jsxDepth--
				}
				i++
				if mode.jsxDepth == 0 {
					modes = modes[:len(modes)-1]
				} else {
					mode.jsxText = true
					mode.closingTag = false
				}
				continue
			}
			i++
			continue
		}
		if mode.templateText {
			if source[i] == '\n' {
				line++
				i++
				continue
			}
			if source[i] == '\\' {
				i++
				if i < len(source) {
					if source[i] == '\n' {
						line++
					}
					i++
				}
				continue
			}
			if source[i] == '`' {
				modes = modes[:len(modes)-1]
				i++
				continue
			}
			if source[i] == '$' && i+1 < len(source) && source[i+1] == '{' {
				modes = append(modes, javascriptLexMode{expression: true, braceDepth: 1})
				i += 2
				continue
			}
			i++
			continue
		}

		if source[i] == '\n' {
			line++
			i++
			continue
		}
		if isJavaScriptHorizontalWhitespace(source[i]) {
			// Whitespace does not separate a control keyword from its opening
			// parenthesis or a statement boundary from a following regex.
			i++
			continue
		}
		if source[i] == '/' && i+1 < len(source) && source[i+1] == '/' {
			start, startLine := i, line
			i += 2
			for i < len(source) && source[i] != '\n' {
				i++
			}
			comments = append(comments, sourceComment{Text: source[start:i], Line: startLine})
			continue
		}
		if source[i] == '/' && i+1 < len(source) && source[i+1] == '*' {
			start, startLine := i, line
			i += 2
			for i < len(source) {
				if source[i] == '\n' {
					line++
					i++
					continue
				}
				if i+1 < len(source) && source[i] == '*' && source[i+1] == '/' {
					i += 2
					break
				}
				i++
			}
			comments = append(comments, sourceComment{Text: source[start:i], Line: startLine})
			continue
		}
		if source[i] == '\'' || source[i] == '"' {
			next := skipQuoted(source, i, source[i], true)
			line += strings.Count(source[i:next], "\n")
			i = next
			lastIdentifier = ""
			lastIdentifierStartedStatement = false
			regexAfterControlParen = false
			statementStart = false
			continue
		}
		if source[i] == '`' {
			modes = append(modes, javascriptLexMode{templateText: true})
			i++
			lastIdentifier = ""
			lastIdentifierStartedStatement = false
			regexAfterControlParen = false
			statementStart = false
			continue
		}
		if allowJSX && source[i] == '<' && i+1 < len(source) && isJSXTagStart(source[i+1]) && javascriptExpressionCanStart(source, i) && !typescriptGenericArrowAt(source, i) {
			modes = append(modes, javascriptLexMode{jsx: true, jsxDepth: 1})
			i++
			lastIdentifier = ""
			lastIdentifierStartedStatement = false
			regexAfterControlParen = false
			statementStart = false
			continue
		}
		if source[i] == '/' && (statementStart || regexAfterControlParen || isJavaScriptRegexPrefixKeyword(lastIdentifier) || javascriptRegexCanStart(source, i)) {
			next := skipJavaScriptRegex(source, i)
			line += strings.Count(source[i:next], "\n")
			i = next
			lastIdentifier = ""
			lastIdentifierStartedStatement = false
			regexAfterControlParen = false
			statementStart = false
			continue
		}
		if isJavaScriptIdentifierStart(source[i]) {
			end := i + 1
			for end < len(source) && isJavaScriptIdentifierPart(source[end]) {
				end++
			}
			identifier := source[i:end]
			startedStatement := statementStart
			lastIdentifier = identifier
			lastIdentifierStartedStatement = startedStatement
			regexAfterControlParen = false
			if identifier == "function" && startedStatement {
				functionDeclarationPending = true
				functionDeclarationParamDepth = 0
				functionDeclarationBodyReady = false
			}
			if isJavaScriptBlockDeclarationKeyword(identifier, allowTypeScript) && startedStatement {
				blockDeclarationPending = true
				blockDeclarationParenDepth = len(controlParens)
				blockDeclarationBracketDepth = bracketDepth
				blockDeclarationAngleDepth = 0
			}
			statementStart = startedStatement && isJavaScriptStatementPrefix(identifier)
			i = end
			continue
		}
		if source[i] == '(' {
			controlParens = append(controlParens, isJavaScriptControlKeyword(lastIdentifier))
			if functionDeclarationPending && functionDeclarationParamDepth == 0 {
				functionDeclarationParamDepth = len(controlParens)
			}
			lastIdentifier = ""
			lastIdentifierStartedStatement = false
			regexAfterControlParen = false
			statementStart = false
			i++
			continue
		}
		if source[i] == ')' {
			closingDepth := len(controlParens)
			control := false
			if len(controlParens) > 0 {
				control = controlParens[len(controlParens)-1]
				controlParens = controlParens[:len(controlParens)-1]
			}
			if functionDeclarationPending && functionDeclarationParamDepth == closingDepth {
				functionDeclarationParamDepth = 0
				functionDeclarationBodyReady = true
			}
			lastIdentifier = ""
			lastIdentifierStartedStatement = false
			regexAfterControlParen = control
			statementStart = false
			i++
			continue
		}
		if !mode.expression && source[i] == '{' {
			declarationBody := blockDeclarationPending && len(controlParens) == blockDeclarationParenDepth && bracketDepth == blockDeclarationBracketDepth && blockDeclarationAngleDepth == 0
			statementBlock := regexAfterControlParen || statementStart || functionDeclarationBodyReady || declarationBody || isJavaScriptDirectBlockKeyword(lastIdentifier)
			statementBraces = append(statementBraces, statementBlock)
			if functionDeclarationBodyReady {
				functionDeclarationPending = false
				functionDeclarationParamDepth = 0
				functionDeclarationBodyReady = false
			}
			if declarationBody {
				blockDeclarationPending = false
			}
			lastIdentifier = ""
			lastIdentifierStartedStatement = false
			regexAfterControlParen = false
			statementStart = statementBlock
			i++
			continue
		}
		if !mode.expression && source[i] == '}' {
			statementBlock := false
			if len(statementBraces) > 0 {
				statementBlock = statementBraces[len(statementBraces)-1]
				statementBraces = statementBraces[:len(statementBraces)-1]
			}
			lastIdentifier = ""
			lastIdentifierStartedStatement = false
			regexAfterControlParen = statementBlock
			statementStart = statementBlock
			i++
			continue
		}
		if mode.expression {
			switch source[i] {
			case '{':
				mode.braceDepth++
			case '}':
				mode.braceDepth--
				if mode.braceDepth == 0 {
					modes = modes[:len(modes)-1]
				}
			}
		}
		if source[i] == ';' {
			functionDeclarationPending = false
			functionDeclarationParamDepth = 0
			functionDeclarationBodyReady = false
			blockDeclarationPending = false
			statementStart = true
		} else if source[i] == ':' && lastIdentifierStartedStatement {
			// A labelled statement begins a fresh statement position. Colons in
			// object literals and conditional expressions do not satisfy this.
			statementStart = true
		} else {
			statementStart = false
		}
		if source[i] == '[' {
			bracketDepth++
		} else if source[i] == ']' && bracketDepth > 0 {
			bracketDepth--
		}
		if blockDeclarationPending {
			if source[i] == '<' {
				blockDeclarationAngleDepth++
			} else if source[i] == '>' && blockDeclarationAngleDepth > 0 && (i == 0 || source[i-1] != '=') {
				blockDeclarationAngleDepth--
			}
		}
		lastIdentifier = ""
		lastIdentifierStartedStatement = false
		regexAfterControlParen = false
		i++
	}
	return comments
}

func isJavaScriptHorizontalWhitespace(char byte) bool {
	switch char {
	case ' ', '\t', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

func isJSXTagStart(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '>'
}

func typescriptGenericArrowAt(source string, start int) bool {
	angleDepth := 0
	parenDepth := 0
	bracketDepth := 0
	braceDepth := 0
	sawTopLevelComma := false
	sawTopLevelConstraint := false
	for i := start + 1; i < len(source) && source[i] != '\n'; i++ {
		if isJavaScriptIdentifierStart(source[i]) {
			end := i + 1
			for end < len(source) && isJavaScriptIdentifierPart(source[end]) {
				end++
			}
			if angleDepth == 0 && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 && source[i:end] == "extends" {
				sawTopLevelConstraint = true
			}
			i = end - 1
			continue
		}
		switch source[i] {
		case '<':
			angleDepth++
		case '>':
			// A function type inside a constraint or default contains =>. Its
			// greater-than token is not the end of the generic parameter list.
			if i > start+1 && source[i-1] == '=' {
				continue
			}
			if angleDepth > 0 {
				angleDepth--
				continue
			}
			if parenDepth > 0 || bracketDepth > 0 || braceDepth > 0 {
				continue
			}
			if !sawTopLevelComma && !sawTopLevelConstraint {
				return false
			}
			// A trailing comma or a top-level constraint disambiguates a TSX
			// generic arrow from JSX. In both forms the parameter list follows.
			i++
			for i < len(source) && (source[i] == ' ' || source[i] == '\t' || source[i] == '\r' || source[i] == '\n') {
				i++
			}
			return i < len(source) && source[i] == '('
		case ',':
			if angleDepth == 0 && parenDepth == 0 && bracketDepth == 0 && braceDepth == 0 {
				sawTopLevelComma = true
			}
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '\'', '"', '`':
			previous := i - 1
			for previous > start && isJavaScriptHorizontalWhitespace(source[previous]) {
				previous--
			}
			if previous > start && source[previous] == '=' {
				// JSX attributes use name="value". A quoted TypeScript
				// literal constraint has no assignment token before the quote.
				return false
			}
			next := skipQuoted(source, i, source[i], true)
			if next <= i || next > len(source) {
				return false
			}
			i = next - 1
		}
	}
	return false
}

func isJavaScriptBlockDeclarationKeyword(identifier string, allowTypeScript bool) bool {
	if identifier == "class" {
		return true
	}
	if !allowTypeScript {
		return false
	}
	switch identifier {
	case "enum", "interface", "namespace":
		return true
	default:
		return false
	}
}

func isJavaScriptStatementPrefix(identifier string) bool {
	switch identifier {
	case "abstract", "async", "declare", "default", "do", "else", "export", "finally", "try":
		return true
	default:
		return false
	}
}

func isJavaScriptDirectBlockKeyword(identifier string) bool {
	switch identifier {
	case "catch", "do", "else", "finally", "try":
		return true
	default:
		return false
	}
}

func javascriptExpressionCanStart(source string, offset int) bool {
	for i := offset - 1; i >= 0; i-- {
		if source[i] == ' ' || source[i] == '\t' || source[i] == '\r' || source[i] == '\n' {
			continue
		}
		return strings.ContainsRune("=(:,![{;?&|+-*%^~<>", rune(source[i]))
	}
	return true
}

func javascriptRegexCanStart(source string, slash int) bool {
	for i := slash - 1; i >= 0; {
		if source[i] == ' ' || source[i] == '\t' || source[i] == '\r' || source[i] == '\n' {
			i--
			continue
		}
		if isJavaScriptIdentifierPart(source[i]) {
			end := i + 1
			for i >= 0 && isJavaScriptIdentifierPart(source[i]) {
				i--
			}
			return isJavaScriptRegexPrefixKeyword(source[i+1 : end])
		}
		return strings.ContainsRune("=(:,![{;?&|+-*%^~<>", rune(source[i]))
	}
	return true
}

func isJavaScriptRegexPrefixKeyword(identifier string) bool {
	switch identifier {
	case "await", "case", "delete", "in", "instanceof", "new", "of", "return", "throw", "typeof", "void", "yield":
		return true
	default:
		return false
	}
}

func isJavaScriptIdentifierPart(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_' || char == '$'
}

func isJavaScriptIdentifierStart(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_' || char == '$'
}

func isJavaScriptControlKeyword(identifier string) bool {
	switch identifier {
	case "catch", "for", "if", "switch", "while", "with":
		return true
	default:
		return false
	}
}

func skipJavaScriptRegex(source string, start int) int {
	inClass := false
	for i := start + 1; i < len(source) && source[i] != '\n'; i++ {
		if source[i] == '\\' {
			i++
			continue
		}
		if source[i] == '[' {
			inClass = true
			continue
		}
		if source[i] == ']' {
			inClass = false
			continue
		}
		if source[i] == '/' && !inClass {
			i++
			for i < len(source) && ((source[i] >= 'a' && source[i] <= 'z') || (source[i] >= 'A' && source[i] <= 'Z')) {
				i++
			}
			return i
		}
	}
	return start + 1
}

func extractPythonComments(source string) []sourceComment {
	var comments []sourceComment
	line := 1
	for i := 0; i < len(source); {
		if source[i] == '\n' {
			line++
			i++
			continue
		}
		if source[i] == '#' {
			start, startLine := i, line
			for i < len(source) && source[i] != '\n' {
				i++
			}
			comments = append(comments, sourceComment{Text: source[start:i], Line: startLine})
			continue
		}
		if source[i] == '\'' || source[i] == '"' {
			quote := source[i]
			triple := i+2 < len(source) && source[i+1] == quote && source[i+2] == quote
			next := skipPythonString(source, i, quote, triple)
			line += strings.Count(source[i:next], "\n")
			i = next
			continue
		}
		i++
	}
	return comments
}

func skipPythonString(source string, start int, quote byte, triple bool) int {
	i := start + 1
	if triple {
		i = start + 3
	}
	for i < len(source) {
		if source[i] == '\\' {
			i += 2
			continue
		}
		if triple {
			if i+2 < len(source) && source[i] == quote && source[i+1] == quote && source[i+2] == quote {
				return i + 3
			}
		} else {
			if source[i] == quote {
				return i + 1
			}
			if source[i] == '\n' {
				return i
			}
		}
		i++
	}
	return len(source)
}

type shellHeredoc struct {
	delimiter string
	stripTabs bool
}

func extractShellComments(source string) []sourceComment {
	var comments []sourceComment
	var heredocs []shellHeredoc
	quote := byte(0)
	lines := strings.SplitAfter(source, "\n")
	for lineIndex, rawLine := range lines {
		line := strings.TrimSuffix(strings.TrimSuffix(rawLine, "\n"), "\r")
		if len(heredocs) > 0 {
			candidate := line
			if heredocs[0].stripTabs {
				candidate = strings.TrimLeft(candidate, "\t")
			}
			if candidate == heredocs[0].delimiter {
				heredocs = heredocs[1:]
			}
			continue
		}

		for i := 0; i < len(line); i++ {
			c := line[i]
			if quote != 0 {
				if c == '\\' && quote != '\'' {
					i++
					continue
				}
				if c == quote {
					quote = 0
				}
				continue
			}
			if c == '\'' || c == '"' || c == '`' {
				quote = c
				continue
			}
			if c == '#' && (i == 0 || strings.ContainsRune(" \t;|&(){}", rune(line[i-1]))) {
				comments = append(comments, sourceComment{Text: line[i:], Line: lineIndex + 1})
				break
			}
			if c == '<' && i+1 < len(line) && line[i+1] == '<' {
				if heredoc, next, ok := parseShellHeredoc(line, i); ok {
					heredocs = append(heredocs, heredoc)
					i = next - 1
				}
			}
		}
	}
	return comments
}

func parseShellHeredoc(line string, start int) (shellHeredoc, int, bool) {
	i := start + 2
	stripTabs := false
	if i < len(line) && line[i] == '-' {
		stripTabs = true
		i++
	}
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) {
		return shellHeredoc{}, start + 1, false
	}
	var delimiter strings.Builder
	quote := byte(0)
	sawCharacter := false
	// Shell compares heredoc terminators after quote removal. Build that
	// effective delimiter while retaining only characters, not quote syntax.
	for i < len(line) {
		if quote != 0 {
			if line[i] == quote {
				quote = 0
				i++
				continue
			}
			if quote == '"' && line[i] == '\\' && i+1 < len(line) && strings.ContainsRune("$`\"\\", rune(line[i+1])) {
				i++
			}
			delimiter.WriteByte(line[i])
			sawCharacter = true
			i++
			continue
		}
		if line[i] == ' ' || line[i] == '\t' || strings.ContainsRune(";|&(){}<>", rune(line[i])) {
			break
		}
		if line[i] == '\'' || line[i] == '"' {
			quote = line[i]
			i++
			continue
		}
		if line[i] == '\\' {
			if i+1 >= len(line) {
				return shellHeredoc{}, start + 1, false
			}
			i++
		}
		delimiter.WriteByte(line[i])
		sawCharacter = true
		i++
	}
	if !sawCharacter || quote != 0 {
		return shellHeredoc{}, start + 1, false
	}
	return shellHeredoc{delimiter: delimiter.String(), stripTabs: stripTabs}, i, true
}

func extractSQLComments(source string) []sourceComment {
	var comments []sourceComment
	line := 1
	for i := 0; i < len(source); {
		if source[i] == '\n' {
			line++
			i++
			continue
		}
		if i+1 < len(source) && source[i] == '-' && source[i+1] == '-' {
			start, startLine := i, line
			for i < len(source) && source[i] != '\n' {
				i++
			}
			comments = append(comments, sourceComment{Text: source[start:i], Line: startLine})
			continue
		}
		if i+1 < len(source) && source[i] == '/' && source[i+1] == '*' {
			start, startLine, depth := i, line, 1
			i += 2
			for i < len(source) && depth > 0 {
				if source[i] == '\n' {
					line++
					i++
					continue
				}
				if i+1 < len(source) && source[i] == '/' && source[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if i+1 < len(source) && source[i] == '*' && source[i+1] == '/' {
					depth--
					i += 2
					continue
				}
				i++
			}
			comments = append(comments, sourceComment{Text: source[start:i], Line: startLine})
			continue
		}
		if source[i] == '\'' || source[i] == '"' || source[i] == '`' {
			next := skipSQLQuoted(source, i, source[i])
			line += strings.Count(source[i:next], "\n")
			i = next
			continue
		}
		if source[i] == '$' {
			if delimiter, ok := sqlDollarDelimiterAt(source, i); ok {
				contentStart := i + len(delimiter)
				end := strings.Index(source[contentStart:], delimiter)
				if end < 0 {
					line += strings.Count(source[i:], "\n")
					break
				}
				next := contentStart + end + len(delimiter)
				line += strings.Count(source[i:next], "\n")
				i = next
				continue
			}
		}
		i++
	}
	return comments
}

func skipSQLQuoted(source string, start int, quote byte) int {
	for i := start + 1; i < len(source); i++ {
		if source[i] == '\\' {
			i++
			continue
		}
		if source[i] == quote {
			if i+1 < len(source) && source[i+1] == quote {
				i++
				continue
			}
			return i + 1
		}
	}
	return len(source)
}

func sqlDollarDelimiterAt(source string, start int) (string, bool) {
	if start+1 >= len(source) {
		return "", false
	}
	if source[start+1] == '$' {
		return "$$", true
	}
	if !((source[start+1] >= 'a' && source[start+1] <= 'z') || (source[start+1] >= 'A' && source[start+1] <= 'Z') || source[start+1] == '_') {
		return "", false
	}
	for i := start + 1; i < len(source); i++ {
		if source[i] == '$' {
			return source[start : i+1], true
		}
		if !((source[i] >= 'a' && source[i] <= 'z') || (source[i] >= 'A' && source[i] <= 'Z') || (source[i] >= '0' && source[i] <= '9') || source[i] == '_') {
			return "", false
		}
	}
	return "", false
}

func exactJSONSectionPaths(sectionID string, raw json.RawMessage) ([]string, error) {
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	paths := []string{strings.ToLower(sectionID)}
	collectJSONPaths(strings.ToLower(sectionID), value, &paths)
	return paths, nil
}

func collectJSONPaths(prefix string, value interface{}, paths *[]string) {
	switch typed := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			path := prefix + "." + strings.ToLower(key)
			*paths = append(*paths, path)
			collectJSONPaths(path, typed[key], paths)
		}
	case []interface{}:
		for index, item := range typed {
			path := fmt.Sprintf("%s.%d", prefix, index)
			*paths = append(*paths, path)
			collectJSONPaths(path, item, paths)
		}
	}
}

func addSpecSectionAliases(index specSectionIndex, specAlias string, sectionPaths []string, coverageIndex int) {
	specAlias = strings.ToLower(specAlias)
	for _, sectionPath := range sectionPaths {
		key := specAlias + "#" + sectionPath
		alreadyPresent := false
		for _, candidate := range index.sections[key] {
			if candidate == coverageIndex {
				alreadyPresent = true
				break
			}
		}
		if !alreadyPresent {
			index.sections[key] = append(index.sections[key], coverageIndex)
		}
	}
}

func (index specSectionIndex) addAliasOwner(specAlias, owner string) {
	specAlias = strings.ToLower(strings.TrimSpace(specAlias))
	if specAlias == "" {
		return
	}
	if existingOwner, ok := index.aliasOwners[specAlias]; ok && existingOwner != owner {
		// Ambiguity belongs to the document alias, independent of whether a
		// requested nested path happens to exist in only one of its owners.
		index.ambiguousAliases[specAlias] = true
		return
	}
	index.aliasOwners[specAlias] = owner
}

func resolveSpecSectionIndex(target string, sectionIndex specSectionIndex) (int, bool) {
	parts := strings.SplitN(target, "#", 2)
	if len(parts) != 2 {
		return 0, false
	}
	specKey := strings.ToLower(strings.TrimSpace(parts[0]))
	sectionPath := strings.ToLower(strings.TrimSpace(parts[1]))
	if specKey == "" || sectionPath == "" {
		return 0, false
	}
	if sectionIndex.ambiguousAliases[specKey] {
		return 0, false
	}
	candidates := sectionIndex.sections[specKey+"#"+sectionPath]
	if len(candidates) != 1 {
		return 0, false
	}
	return candidates[0], true
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
