package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// ---------------- ParsePath ----------------

func TestParsePath_DottedKeys(t *testing.T) {
	got, err := ParsePath("foo.bar.baz")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 segments, got %d (%+v)", len(got), got)
	}
	for i, name := range []string{"foo", "bar", "baz"} {
		if got[i].Name != name || got[i].Wildcard {
			t.Errorf("segment %d: got %+v, want name=%s", i, got[i], name)
		}
	}
}

func TestParsePath_RootMarker(t *testing.T) {
	a, _ := ParsePath("$.foo.bar")
	b, _ := ParsePath("foo.bar")
	if len(a) != len(b) {
		t.Fatalf("root marker should strip cleanly: a=%d b=%d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("segment %d differs", i)
		}
	}
}

func TestParsePath_ArrayWildcard(t *testing.T) {
	got, err := ParsePath("sections[*].invariants[*]")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 segments, got %+v", got)
	}
	if got[0].Name != "sections" || got[0].Wildcard {
		t.Errorf("segment 0: %+v", got[0])
	}
	if !got[1].Wildcard {
		t.Errorf("segment 1 should be wildcard: %+v", got[1])
	}
	if got[2].Name != "invariants" || got[2].Wildcard {
		t.Errorf("segment 2: %+v", got[2])
	}
	if !got[3].Wildcard {
		t.Errorf("segment 3 should be wildcard: %+v", got[3])
	}
}

func TestParsePath_RejectsNumericIndex(t *testing.T) {
	if _, err := ParsePath("foo[0]"); err == nil {
		t.Error("expected error on numeric index")
	}
}

func TestParsePath_ObjectWildcard(t *testing.T) {
	got, err := ParsePath("sections.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 segments, got %+v", got)
	}
	if got[0].Name != "sections" || got[0].ObjectWildcard {
		t.Errorf("segment 0: %+v", got[0])
	}
	if !got[1].ObjectWildcard || got[1].Wildcard {
		t.Errorf("segment 1 should be object wildcard: %+v", got[1])
	}
}

func TestParsePath_NestedObjectAndArrayWildcards(t *testing.T) {
	got, err := ParsePath("sections.*.invariants[*]")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 segments, got %+v", got)
	}
	if !got[1].ObjectWildcard {
		t.Errorf("segment 1 should be object wildcard")
	}
	if !got[3].Wildcard {
		t.Errorf("segment 3 should be array wildcard")
	}
}

func TestWalk_ObjectWildcardIteratesValues(t *testing.T) {
	root := mustParseJSON(t, `{"sections": {"s1_first": {"title": "A"}, "s2_second": {"title": "B"}}}`)
	segs, _ := ParsePath("sections.*")
	matches := Walk(root, segs)
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matches))
	}
	if matches[0].SourcePath != "sections.s1_first" {
		t.Errorf("first match source_path: %q", matches[0].SourcePath)
	}
	if matches[1].SourcePath != "sections.s2_second" {
		t.Errorf("second match source_path: %q", matches[1].SourcePath)
	}
}

func TestWalk_ObjectWildcardDeterministicOrder(t *testing.T) {
	root := mustParseJSON(t, `{"m": {"z": {"v": "z"}, "a": {"v": "a"}, "m": {"v": "m"}}}`)
	segs, _ := ParsePath("m.*")
	matches := Walk(root, segs)
	want := []string{"m.a", "m.m", "m.z"}
	if len(matches) != len(want) {
		t.Fatalf("expected %d matches, got %d", len(want), len(matches))
	}
	for i, w := range want {
		if matches[i].SourcePath != w {
			t.Errorf("match %d: got %q want %q", i, matches[i].SourcePath, w)
		}
	}
}

func TestWalk_NestedObjectThenArrayWildcard(t *testing.T) {
	root := mustParseJSON(t, `{"sections": {"s1": {"invariants": [{"id": "i1"}, {"id": "i2"}]}, "s2": {"invariants": [{"id": "i3"}]}}}`)
	segs, _ := ParsePath("sections.*.invariants[*]")
	matches := Walk(root, segs)
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches, got %d (%+v)", len(matches), matches)
	}
}

func TestWalk_ObjectWildcardOnNonObjectReturnsNoMatches(t *testing.T) {
	root := mustParseJSON(t, `{"sections": ["array_not_object"]}`)
	segs, _ := ParsePath("sections.*")
	matches := Walk(root, segs)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches on array-not-object, got %d", len(matches))
	}
}

func TestParsePath_RejectsUnmatchedBracket(t *testing.T) {
	if _, err := ParsePath("foo[*"); err == nil {
		t.Error("expected error on unmatched bracket")
	}
}

// ---------------- Walk ----------------

func mustParseJSON(t *testing.T, s string) interface{} {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}
	return v
}

func TestWalk_SimpleDottedKey(t *testing.T) {
	root := mustParseJSON(t, `{"foo": {"bar": "value"}}`)
	segs, _ := ParsePath("foo.bar")
	matches := Walk(root, segs)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Value != "value" {
		t.Errorf("got value %v, want \"value\"", matches[0].Value)
	}
}

func TestWalk_ArrayWildcardExpandsAll(t *testing.T) {
	root := mustParseJSON(t, `{"items": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}`)
	segs, _ := ParsePath("items[*]")
	matches := Walk(root, segs)
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(matches))
	}
	if !strings.Contains(matches[0].SourcePath, "[0]") {
		t.Errorf("source_path should record array index: %q", matches[0].SourcePath)
	}
}

func TestWalk_NestedArrayWildcards(t *testing.T) {
	root := mustParseJSON(t, `{"sections": [{"invariants": [{"id": "i1"}, {"id": "i2"}]}, {"invariants": [{"id": "i3"}]}]}`)
	segs, _ := ParsePath("sections[*].invariants[*]")
	matches := Walk(root, segs)
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches, got %d (%+v)", len(matches), matches)
	}
}

func TestWalk_MissingKeyReturnsNoMatches(t *testing.T) {
	root := mustParseJSON(t, `{"foo": "bar"}`)
	segs, _ := ParsePath("missing.path")
	matches := Walk(root, segs)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches on missing key, got %d", len(matches))
	}
}

// ---------------- ExtractLeaf ----------------

func TestExtractLeaf_TopLevelString(t *testing.T) {
	obj := mustParseJSON(t, `{"statement": "the gate halts execution"}`)
	v, ok := ExtractLeaf(obj, "statement")
	if !ok || v != "the gate halts execution" {
		t.Errorf("got (%q, %v)", v, ok)
	}
}

func TestExtractLeaf_DottedSubpath(t *testing.T) {
	obj := mustParseJSON(t, `{"contract": {"asserts": "y"}}`)
	v, ok := ExtractLeaf(obj, "contract.asserts")
	if !ok || v != "y" {
		t.Errorf("got (%q, %v)", v, ok)
	}
}

func TestExtractLeaf_DollarRoot(t *testing.T) {
	obj := mustParseJSON(t, `{"a": "x"}`)
	v, ok := ExtractLeaf(obj, "$.a")
	if !ok || v != "x" {
		t.Errorf("got (%q, %v)", v, ok)
	}
}

func TestExtractLeaf_MissingPathReturnsFalse(t *testing.T) {
	obj := mustParseJSON(t, `{"a": "x"}`)
	if _, ok := ExtractLeaf(obj, "missing"); ok {
		t.Error("expected ok=false on missing path")
	}
}

func TestExtractLeaf_NonStringReturnsFalse(t *testing.T) {
	obj := mustParseJSON(t, `{"a": 42}`)
	if _, ok := ExtractLeaf(obj, "a"); ok {
		t.Error("expected ok=false on non-string value")
	}
}

// ---------------- Extract ----------------

func TestExtract_EndToEnd(t *testing.T) {
	recipe := &ExtractionRecipe{
		SourceSpecID:   "test-doc-id",
		SourceSpecName: "TEST_SPEC",
		ConceptDomain:  "test_domain",
		Extractions: []Extraction{
			{
				Path:     "sections[*]",
				NodeKind: "section",
				IDField:  "section_id",
				LeafFields: map[string]string{
					"statement": "statement",
				},
			},
			{
				Path:     "sections[*].invariants[*]",
				NodeKind: "invariant",
				IDField:  "invariant_id",
				LeafFields: map[string]string{
					"statement":   "statement",
					"description": "description",
				},
			},
		},
	}
	source := mustParseJSON(t, `{
		"sections": [
			{
				"section_id": "s1",
				"statement": "section one statement",
				"invariants": [
					{"invariant_id": "i1", "statement": "inv one", "description": "inv one desc"},
					{"invariant_id": "i2", "statement": "inv two"}
				]
			},
			{
				"section_id": "s2",
				"statement": "section two statement",
				"invariants": []
			}
		]
	}`)
	records, err := Extract(recipe, source, "/tmp/test.ood.json")
	if err != nil {
		t.Fatal(err)
	}
	// Expected: 2 section statements + 2 inv statements + 1 inv description = 5
	if len(records) != 5 {
		t.Fatalf("expected 5 records, got %d: %+v", len(records), records)
	}
	// Verify each record has the recipe-derived fields populated.
	for _, r := range records {
		if r.SourceSpecID != "test-doc-id" {
			t.Errorf("source_spec_id not propagated: %+v", r)
		}
		if r.ConceptDomain != "test_domain" {
			t.Errorf("concept_domain not propagated: %+v", r)
		}
		if r.SourceFile != "/tmp/test.ood.json" {
			t.Errorf("source_file not set: %+v", r)
		}
		if r.RawValue == "" {
			t.Errorf("raw_value empty: %+v", r)
		}
	}
}

func TestExtract_MissingLeafSkippedSilently(t *testing.T) {
	recipe := &ExtractionRecipe{
		Extractions: []Extraction{
			{
				Path:     "items[*]",
				NodeKind: "thing",
				LeafFields: map[string]string{
					"optional_leaf": "optional",
				},
			},
		},
	}
	source := mustParseJSON(t, `{"items": [{"required": "x"}, {"optional": "present"}]}`)
	records, err := Extract(recipe, source, "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 record (only the one with the optional leaf), got %d", len(records))
	}
}

func TestExtract_SourcePathContainsLocalID(t *testing.T) {
	recipe := &ExtractionRecipe{
		Extractions: []Extraction{
			{
				Path:     "items[*]",
				NodeKind: "thing",
				IDField:  "name",
				LeafFields: map[string]string{
					"value": "value",
				},
			},
		},
	}
	source := mustParseJSON(t, `{"items": [{"name": "alpha", "value": "v1"}]}`)
	records, _ := Extract(recipe, source, "x")
	if len(records) != 1 {
		t.Fatal("expected 1 record")
	}
	if !strings.Contains(records[0].SourcePath, "name=alpha") {
		t.Errorf("source_path should encode local id: %q", records[0].SourcePath)
	}
}
