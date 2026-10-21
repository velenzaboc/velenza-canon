package main

import (
	"bytes"
	"fmt"
	"os"
	"text/template"
)

// LoadAndRender reads the prompt template file fresh on EVERY call
// (no in-memory cache per directive) and renders it with the supplied
// data. The file IS source-of-truth; editing the .txt file changes
// behavior on the next invocation.
//
// Per Vision Principle 7 (binary_is_never_sot): prompt content is
// authored on disk, not embedded in the binary. The binary holds only
// the rendering mechanism.
func LoadAndRender(path string, data interface{}) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read prompt %q: %w", path, err)
	}
	tmpl, err := template.New(path).Parse(string(raw))
	if err != nil {
		return "", fmt.Errorf("parse prompt %q: %w", path, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render prompt %q: %w", path, err)
	}
	return buf.String(), nil
}

// SameConceptQueryData is the template context for
// same_concept_query.txt.
type SameConceptQueryData struct {
	StatementA string
	StatementB string
	SourceA    string
	SourceB    string
}

// CanonicalNameSelectionData is the template context for
// canonical_name_selection.txt.
type CanonicalNameSelectionData struct {
	Statement  string
	Candidates []string
}
