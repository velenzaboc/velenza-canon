package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// artifactTypeForKind maps a concept's node_kind to spec_graph's
// artifact_type. The kind/artifact_type split exists in spec-graph
// because admission ceremony classifies by artifact_type while
// closed-registry routing classifies by kind. For the bootstrap-mode
// concept kinds the linter operates on, kind and artifact_type are
// 1:1.
var artifactTypeForKind = map[string]string{
	"axiom":      "axiom",
	"section":    "section",
	"invariant":  "invariant",
	"sentinel":   "sentinel",
	"assumption": "assumption",
	"decision":   "decision",
	"doc_object": "doc_object",
	"circuit":    "circuit",
	"origin":     "origin",
}

// LoadConceptTable reads a concept table JSON file from disk.
func LoadConceptTable(path string) (*ConceptTable, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read concept table %s: %w", path, err)
	}
	var ct ConceptTable
	if err := json.Unmarshal(data, &ct); err != nil {
		return nil, fmt.Errorf("parse concept table %s: %w", path, err)
	}
	return &ct, nil
}

// ToSubmissions converts a ConceptTable to one Submission per concept
// + one per edge. orgID is the organization_id stamped on every
// submission (spec-graph requires it; the linter validates per R3,
// admission per the ceremony).
//
// Topological order: nodes first (so edges can reference them by
// stable_id), then edges. spec_graph_import already topologically
// orders within node submissions; this layer guarantees nodes-then-
// edges so the import sees a coherent dependency graph.
func ToSubmissions(ct *ConceptTable, orgID string) ([]Submission, error) {
	subs := make([]Submission, 0, len(ct.Concepts)+len(ct.Edges))
	// Stable-sort concepts by canonical_name for deterministic output
	// — eases auditability of the produced directory.
	concepts := make([]Concept, len(ct.Concepts))
	copy(concepts, ct.Concepts)
	sort.SliceStable(concepts, func(i, j int) bool {
		return concepts[i].CanonicalName < concepts[j].CanonicalName
	})
	for _, c := range concepts {
		at, ok := artifactTypeForKind[c.NodeKind]
		if !ok {
			return nil, fmt.Errorf("concept %q: no artifact_type mapping for node_kind %q",
				c.CanonicalName, c.NodeKind)
		}
		subs = append(subs, Submission{
			ArtifactType:   at,
			OrganizationID: orgID,
			NodeKind:       c.NodeKind,
			StableID:       c.CanonicalName,
			Contract:       c.Contract,
			Payload:        c.Payload,
		})
	}
	edges := make([]Edge, len(ct.Edges))
	copy(edges, ct.Edges)
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].EdgeLabel != edges[j].EdgeLabel {
			return edges[i].EdgeLabel < edges[j].EdgeLabel
		}
		if edges[i].SourceName != edges[j].SourceName {
			return edges[i].SourceName < edges[j].SourceName
		}
		return edges[i].TargetName < edges[j].TargetName
	})
	for _, e := range edges {
		subs = append(subs, Submission{
			ArtifactType:   "edge",
			OrganizationID: orgID,
			EdgeLabel:      e.EdgeLabel,
			SourceID:       e.SourceName,
			TargetID:       e.TargetName,
		})
	}
	return subs, nil
}

// WriteSubmissionDir writes each Submission to its own file under dir,
// numbered NNN_<canonical_or_label>.json — the convention
// spec_graph_import's directory scan expects (per REQUIREMENTS.md
// §3.6 and the existing seed_nodes/ convention). Leading-underscore
// names are reserved for authoring artifacts and are not used here.
func WriteSubmissionDir(subs []Submission, dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	for i, s := range subs {
		base := s.StableID
		if s.ArtifactType == "edge" {
			base = fmt.Sprintf("%s__%s__%s", s.EdgeLabel, s.SourceID, s.TargetID)
		}
		fname := fmt.Sprintf("%03d_%s.json", i+1, sanitizeFilenameComponent(base))
		path := filepath.Join(dir, fname)
		data, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal submission %d: %w", i, err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

// sanitizeFilenameComponent trims any character that would be unsafe
// in a filename. canonical_name passes through unchanged in well-formed
// inputs (R7 already enforces snake_case); this is defense in depth
// for edge filenames built from labels + names.
func sanitizeFilenameComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z'), (r >= 'A' && r <= 'Z'), (r >= '0' && r <= '9'):
			b.WriteRune(r)
		case r == '_' || r == '.' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
