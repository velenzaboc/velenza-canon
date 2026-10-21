// Package main implements spec-extract, the deterministic extraction
// stage of the staged spec-ingestion pipeline. It walks a source
// `.ood.json` spec file according to a per-spec extraction recipe and
// emits flat ConceptRecords for downstream stages (dedup judgment, lint,
// admit).
//
// Per Vision Principle 14 (fractal engineering: AI on the ambiguous
// parts only), the extraction step is mechanical and runs as code, not
// as LLM judgment. The recipe declares which JSON paths in the source
// carry concept-bearing leaves; the walker emits records uniformly.
package main

// ExtractionRecipe declares, for ONE source spec, which JSON paths
// inside that spec carry concept-bearing leaves and how each leaf
// maps to a proposed node_kind + concept_domain.
type ExtractionRecipe struct {
	SourceSpecID   string       `json:"source_spec_id"`
	SourceSpecName string       `json:"source_spec_name"`
	ConceptDomain  string       `json:"concept_domain"`
	Extractions    []Extraction `json:"extractions"`
}

// Extraction is one (path, kind) rule inside a recipe. Path syntax
// supports:
//   - dotted keys: "foo.bar.baz"
//   - array wildcards: "sections[*].invariants[*]"
//   - root marker: "$" (optional; leading "$." or "$" is stripped)
//
// IDField names the key inside each matched object whose value is the
// object's source-local identity (e.g. "section_id", "invariant_id").
// Used to populate the SourcePath of emitted records.
//
// LeafFields names which sub-keys of each matched object are
// concept-bearing leaves. Each leaf becomes ONE ConceptRecord; multiple
// leaves under one matched object produce one ConceptRecord per leaf.
type Extraction struct {
	Path        string            `json:"path"`
	NodeKind    string            `json:"node_kind"`
	IDField     string            `json:"id_field,omitempty"`
	LeafFields  map[string]string `json:"leaf_fields"` // leaf-name → sub-path inside the matched object
}

// ConceptRecord is one flat extraction. The downstream stages cluster
// records for dedup, lint statements against R-rules, and finally admit
// the consolidated concept table into the graph.
type ConceptRecord struct {
	SourceSpecID   string `json:"source_spec_id"`
	SourceSpecName string `json:"source_spec_name"`
	SourceFile     string `json:"source_file"`
	SourcePath     string `json:"source_path"`
	ConceptDomain  string `json:"concept_domain"`
	NodeKind       string `json:"node_kind"`
	LeafName       string `json:"leaf_name"`
	RawValue       string `json:"raw_value"`
}
