package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// LoadRecipe reads and parses an extraction recipe from disk.
func LoadRecipe(path string) (*ExtractionRecipe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read recipe %s: %w", path, err)
	}
	var r ExtractionRecipe
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse recipe %s: %w", path, err)
	}
	return &r, nil
}

// LoadSource reads and parses a source spec JSON file.
func LoadSource(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read source %s: %w", path, err)
	}
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, fmt.Errorf("parse source %s: %w", path, err)
	}
	return v, nil
}

// Extract applies every Extraction in the recipe against the parsed
// source. For each matched object, emits one ConceptRecord per
// LeafField. Matched objects whose declared LeafField sub-path doesn't
// resolve are skipped silently — they're not concept-bearing for that
// leaf.
func Extract(recipe *ExtractionRecipe, source interface{}, sourcePath string) ([]ConceptRecord, error) {
	var records []ConceptRecord
	for _, ex := range recipe.Extractions {
		segments, err := ParsePath(ex.Path)
		if err != nil {
			return nil, fmt.Errorf("recipe extraction %q: %w", ex.Path, err)
		}
		matches := Walk(source, segments)
		for _, m := range matches {
			obj, ok := m.Value.(map[string]interface{})
			if !ok {
				// Path resolved to a non-object; can't extract named
				// leaves from a scalar.
				continue
			}
			localID := ""
			if ex.IDField != "" {
				if v, ok := obj[ex.IDField].(string); ok {
					localID = v
				}
			}
			for leafName, leafPath := range ex.LeafFields {
				raw, ok := ExtractLeaf(obj, leafPath)
				if !ok {
					continue
				}
				rec := ConceptRecord{
					SourceSpecID:   recipe.SourceSpecID,
					SourceSpecName: recipe.SourceSpecName,
					SourceFile:     sourcePath,
					SourcePath:     buildSourcePath(m.SourcePath, ex.IDField, localID),
					ConceptDomain:  recipe.ConceptDomain,
					NodeKind:       ex.NodeKind,
					LeafName:       leafName,
					RawValue:       raw,
				}
				records = append(records, rec)
			}
		}
	}
	return records, nil
}

func buildSourcePath(walkerPath, idField, localID string) string {
	if localID == "" {
		return walkerPath
	}
	return fmt.Sprintf("%s#%s=%s", walkerPath, idField, localID)
}
