package main

import (
	"fmt"
	"sort"
	"strings"
)

// sortStrings sorts the slice in place. Wrapper to keep the walker
// import list tight and named at the call site.
func sortStrings(s []string) { sort.Strings(s) }

// PathSegment is one element of a parsed extraction path. One of:
//   - named key (`Name="sections"`, others false): match an object key
//   - array wildcard (`Wildcard=true`, others false): iterate every
//     element of an array
//   - object wildcard (`ObjectWildcard=true`, others false): iterate
//     every value of a map; the key becomes part of the source_path
//     so downstream stages can identify which entry produced a record
//
// Array indexing (numeric) is intentionally unsupported.
type PathSegment struct {
	Name           string
	Wildcard       bool
	ObjectWildcard bool
}

// ParsePath splits an extraction path into segments. The leading "$"
// or "$." root marker is stripped. Empty path returns empty segments.
//
// Examples:
//   "$.sections[*].invariants[*]" → [sections, *array, invariants, *array]
//   "foo.bar"                     → [foo, bar]
//   "sections[*]"                 → [sections, *array]
//   "sections.*"                  → [sections, *object]
//   "sections.*.invariants[*]"    → [sections, *object, invariants, *array]
//
// A bare `*` segment iterates the values of an object (map[string]any);
// `[*]` iterates the elements of an array. The two are kept distinct so
// recipes are explicit about source shape.
func ParsePath(path string) ([]PathSegment, error) {
	path = strings.TrimPrefix(path, "$")
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return nil, nil
	}
	var segments []PathSegment
	parts := strings.Split(path, ".")
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("empty segment in path %q", path)
		}
		// Bare "*" is the object-wildcard segment.
		if part == "*" {
			segments = append(segments, PathSegment{ObjectWildcard: true})
			continue
		}
		// Handle "name[*]" — split into name segment + array wildcard segment.
		for {
			openIdx := strings.Index(part, "[")
			if openIdx < 0 {
				if part != "" {
					segments = append(segments, PathSegment{Name: part})
				}
				break
			}
			if openIdx > 0 {
				segments = append(segments, PathSegment{Name: part[:openIdx]})
			}
			closeIdx := strings.Index(part, "]")
			if closeIdx < 0 || closeIdx <= openIdx {
				return nil, fmt.Errorf("unmatched [ in path segment %q", part)
			}
			inside := part[openIdx+1 : closeIdx]
			if inside != "*" {
				return nil, fmt.Errorf("only [*] wildcard supported, got [%s]", inside)
			}
			segments = append(segments, PathSegment{Wildcard: true})
			part = part[closeIdx+1:]
			part = strings.TrimPrefix(part, ".")
		}
	}
	return segments, nil
}

// Match holds one walker hit: the object that matched the path plus
// the path through the source JSON that reached it.
type Match struct {
	Value      interface{}
	SourcePath string
}

// Walk traverses root according to the parsed path segments and emits
// one Match per terminal hit. Wildcards expand into all array
// elements; named segments must exist as map keys (missing keys yield
// no match — not an error).
func Walk(root interface{}, segments []PathSegment) []Match {
	if len(segments) == 0 {
		return []Match{{Value: root, SourcePath: ""}}
	}
	return walk(root, segments, "")
}

func walk(node interface{}, segments []PathSegment, sourcePath string) []Match {
	if len(segments) == 0 {
		return []Match{{Value: node, SourcePath: sourcePath}}
	}
	head, rest := segments[0], segments[1:]
	if head.Wildcard {
		arr, ok := node.([]interface{})
		if !ok {
			return nil
		}
		var out []Match
		for i, el := range arr {
			childPath := fmt.Sprintf("%s[%d]", sourcePath, i)
			out = append(out, walk(el, rest, childPath)...)
		}
		return out
	}
	if head.ObjectWildcard {
		obj, ok := node.(map[string]interface{})
		if !ok {
			return nil
		}
		// Iterate map values in sorted key order so the walker is
		// deterministic across runs (Go's map iteration is otherwise
		// randomized).
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sortStrings(keys)
		var out []Match
		for _, k := range keys {
			childPath := sourcePath
			if childPath == "" {
				childPath = k
			} else {
				childPath = childPath + "." + k
			}
			out = append(out, walk(obj[k], rest, childPath)...)
		}
		return out
	}
	obj, ok := node.(map[string]interface{})
	if !ok {
		return nil
	}
	child, exists := obj[head.Name]
	if !exists {
		return nil
	}
	childPath := sourcePath
	if childPath == "" {
		childPath = head.Name
	} else {
		childPath = childPath + "." + head.Name
	}
	return walk(child, rest, childPath)
}

// ExtractLeaf reads a single sub-path inside a matched object and
// returns the value at that sub-path. Sub-paths are dotted only — no
// wildcards inside leaves. Returns ("", false) when the sub-path
// doesn't exist.
func ExtractLeaf(obj interface{}, subpath string) (string, bool) {
	if subpath == "" || subpath == "$" {
		if s, ok := obj.(string); ok {
			return s, true
		}
		return "", false
	}
	subpath = strings.TrimPrefix(subpath, "$.")
	subpath = strings.TrimPrefix(subpath, "$")
	subpath = strings.TrimPrefix(subpath, ".")
	parts := strings.Split(subpath, ".")
	cur := obj
	for _, p := range parts {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return "", false
		}
		next, exists := m[p]
		if !exists {
			return "", false
		}
		cur = next
	}
	s, ok := cur.(string)
	if !ok {
		return "", false
	}
	return s, true
}
