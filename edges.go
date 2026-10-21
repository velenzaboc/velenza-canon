package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// externalReferenceEdgeContract is the machine-enforced projection of
// OOD_GRAPH_PROTOCOL_v1 §4's endpoint rules for the eight edge labels §8
// external-reference ingestion is allowed to create. Config remains the
// runtime registry, but a config cannot omit a required traversal label or
// widen/narrow its protocol-owned direction and endpoint classes.
type externalReferenceEdgeContract struct {
	EdgeFamily  string
	SourceKinds []string
	TargetKinds []string
}

var externalReferenceEdgeContracts = map[string]externalReferenceEdgeContract{
	"documents": {
		EdgeFamily:  "external_reference",
		SourceKinds: []string{"external_reference_doc", "reference_page"},
		TargetKinds: []string{"doc_object", "doc_version", "section", "symbol", "config", "circuit", "schema", "sentinel", "invariant", "assumption", "api_symbol", "code_example", "release_note", "code_symbol_ref"},
	},
	"official_source_for": {
		EdgeFamily:  "external_reference",
		SourceKinds: []string{"external_reference_doc", "source_repo", "repo_snapshot"},
		TargetKinds: []string{"section", "api_symbol", "code_symbol_ref", "reference_page"},
	},
	"defines_external_symbol": {
		EdgeFamily:  "external_reference",
		SourceKinds: []string{"reference_page", "source_repo"},
		TargetKinds: []string{"api_symbol", "code_symbol_ref"},
	},
	"example_of": {
		EdgeFamily:  "external_reference",
		SourceKinds: []string{"code_example"},
		TargetKinds: []string{"api_symbol", "reference_page", "code_symbol_ref"},
	},
	"version_note_for": {
		EdgeFamily:  "external_reference",
		SourceKinds: []string{"release_note"},
		TargetKinds: []string{"api_symbol", "reference_page", "external_reference_doc", "code_symbol_ref"},
	},
	"supports_spec_section": {
		EdgeFamily:  "evidence_reference",
		SourceKinds: []string{"external_reference_doc", "reference_page", "api_symbol", "code_example", "release_note", "source_repo", "repo_snapshot", "code_symbol_ref"},
		TargetKinds: []string{"section", "invariant", "sentinel", "schema", "config", "circuit"},
	},
	"implemented_by_code_symbol": {
		EdgeFamily:  "code_graph_interop",
		SourceKinds: []string{"doc_object", "doc_version", "section", "symbol", "config", "circuit", "schema", "sentinel", "invariant", "assumption", "api_symbol"},
		TargetKinds: []string{"code_symbol_ref"},
	},
	"technology_relevant_to": {
		EdgeFamily:  "forge_context_reference",
		SourceKinds: []string{"external_reference_doc", "reference_page", "api_symbol", "code_example", "release_note", "source_repo", "repo_snapshot", "code_symbol_ref"},
		TargetKinds: []string{"doc_object", "doc_version", "section", "symbol", "config", "circuit", "schema", "assumption"},
	},
}

// EdgeLabelRegistry is the closed-set authority for edge_label values. The
// registry loads from spec-graph.config.json's edge_labels section today;
// from KernelConfig once the corpus is queryable as graph rows.
type EdgeLabelRegistry interface {
	Resolve(ctx context.Context, label string) (EdgeLabelDescriptor, error)
	All(ctx context.Context) ([]EdgeLabelDescriptor, error)
}

// EdgeLabelDescriptor wraps the raw config map for one edge_label entry.
//
// Same binary_is_never_sot design as NodeKindDescriptor: the binary holds
// field ACCESSORS for the mechanical fields it consumes at admission and
// validation (Name, SourceKinds, TargetKinds, ReciprocalLabel, EdgeFamily,
// VersionPinned, ForbidSelfLoops, DiagnosticOnly) but the underlying map
// carries the protocol's full per-label metadata (direction,
// authored_or_derived, transitive_closure_meaning, consumed_by, etc.) for
// MCP read verbs and downstream agents.
type EdgeLabelDescriptor struct {
	raw map[string]interface{}
}

// NewEdgeLabelDescriptor constructs a descriptor from a raw map.
func NewEdgeLabelDescriptor(raw map[string]interface{}) EdgeLabelDescriptor {
	if raw == nil {
		raw = map[string]interface{}{}
	}
	return EdgeLabelDescriptor{raw: raw}
}

// UnmarshalJSON loads the descriptor verbatim from JSON.
func (d *EdgeLabelDescriptor) UnmarshalJSON(b []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	d.raw = m
	return nil
}

// MarshalJSON renders the descriptor back to JSON verbatim.
func (d EdgeLabelDescriptor) MarshalJSON() ([]byte, error) {
	if d.raw == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(d.raw)
}

// Raw returns the full underlying config map.
func (d EdgeLabelDescriptor) Raw() map[string]interface{} {
	if d.raw == nil {
		return map[string]interface{}{}
	}
	return d.raw
}

// Name is the canonical edge label (required).
func (d EdgeLabelDescriptor) Name() string { return d.optionalString("name") }

// SourceKinds names the legal source endpoint classes. OOD Graph §4 makes
// per-label endpoint membership closed; an empty slice is invalid rather
// than a wildcard.
func (d EdgeLabelDescriptor) SourceKinds() []string { return d.optionalStrings("source_kinds") }

// TargetKinds names the legal target endpoint classes.
func (d EdgeLabelDescriptor) TargetKinds() []string { return d.optionalStrings("target_kinds") }

// ReciprocalLabel names the inverse label (if the protocol declares
// required reciprocity). Edge creation auto-creates the mirror edge in the
// same Spanner ReadWriteTransaction when this is set.
func (d EdgeLabelDescriptor) ReciprocalLabel() string { return d.optionalString("reciprocal_label") }

// EdgeFamily groups labels for closure_profile-driven traversal (required).
// Per §4.edge_label_taxonomy.labels.*.family.
func (d EdgeLabelDescriptor) EdgeFamily() string { return d.optionalString("edge_family") }

// DiagnosticOnly flags edges that record materialization-time observations
// but are excluded from authoritative closure.
func (d EdgeLabelDescriptor) DiagnosticOnly() bool { return d.optionalBool("diagnostic_only") }

// VersionPinned signals that the edge requires explicit source_version and
// target_version coordinates (e.g. supersedes).
func (d EdgeLabelDescriptor) VersionPinned() bool { return d.optionalBool("version_pinned") }

// ForbidSelfLoops refuses any edge whose source_id equals its target_id.
// Per-label policy declared in config; no binary default. Per §4.self_edges,
// the dependency/version/implementation/raise/invariant/assumption families
// all forbid self-loops; declares/contains/references/interop_reference
// permit them.
func (d EdgeLabelDescriptor) ForbidSelfLoops() bool { return d.optionalBool("forbid_self_loops") }

// Validate refuses descriptors missing required mechanical fields or
// carrying type errors.
func (d EdgeLabelDescriptor) Validate(index int) error {
	if _, ok := d.raw["name"].(string); !ok || d.Name() == "" {
		return fmt.Errorf("edge_labels[%d]: name required and must be a non-empty string", index)
	}
	if _, ok := d.raw["edge_family"].(string); !ok || d.EdgeFamily() == "" {
		return fmt.Errorf("edge_labels[%d] (name=%q): edge_family required and must be a non-empty string (per OOD_GRAPH_PROTOCOL_v1 §4.edge_label_taxonomy)", index, d.Name())
	}
	// OOD Graph §4 requires each label family to name its legal endpoint
	// classes. An omitted or empty set would turn the public link surface into
	// a wildcard and let one label silently consume classes its family never
	// admitted.
	if err := validateKindArray(d.raw["source_kinds"], "source_kinds", index, d.Name()); err != nil {
		return err
	}
	if err := validateKindArray(d.raw["target_kinds"], "target_kinds", index, d.Name()); err != nil {
		return err
	}
	if len(d.SourceKinds()) == 0 {
		return fmt.Errorf("edge_labels[%d] (name=%q): source_kinds must be a non-empty closed endpoint set", index, d.Name())
	}
	if len(d.TargetKinds()) == 0 {
		return fmt.Errorf("edge_labels[%d] (name=%q): target_kinds must be a non-empty closed endpoint set", index, d.Name())
	}
	if value, present := d.raw["reciprocal_label"]; present && value != nil {
		if reciprocal, ok := value.(string); !ok || reciprocal == "" {
			return fmt.Errorf("edge_labels[%d] (name=%q): reciprocal_label must be a non-empty string when set", index, d.Name())
		}
	}
	for _, field := range []string{"diagnostic_only", "version_pinned", "forbid_self_loops"} {
		if value, present := d.raw[field]; present && value != nil {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("edge_labels[%d] (name=%q): %s must be a boolean when set", index, d.Name(), field)
			}
		}
	}
	return nil
}

func validateKindArray(value interface{}, field string, index int, label string) error {
	if value == nil {
		return nil
	}
	arr, ok := value.([]interface{})
	if !ok {
		return fmt.Errorf("edge_labels[%d] (name=%q): %s must be a JSON array when set", index, label, field)
	}
	seen := map[string]struct{}{}
	for i, raw := range arr {
		kind, ok := raw.(string)
		if !ok || kind == "" {
			return fmt.Errorf("edge_labels[%d] (name=%q): %s[%d] must be a non-empty string", index, label, field, i)
		}
		if _, duplicate := seen[kind]; duplicate {
			return fmt.Errorf("edge_labels[%d] (name=%q): %s contains duplicate %q", index, label, field, kind)
		}
		seen[kind] = struct{}{}
	}
	return nil
}

// validateExternalReferenceEdgeRegistry makes an external-source-enabled
// process boot only when every §8 traversal edge has its exact §4 family,
// direction and endpoint-class contract. Without this gate a perfectly valid
// external object batch could seal as isolated vertices that no forge/context
// traversal can reach.
func validateExternalReferenceEdgeRegistry(labels []EdgeLabelDescriptor) error {
	byName := make(map[string]EdgeLabelDescriptor, len(labels))
	for i, label := range labels {
		name := label.Name()
		if _, duplicate := byName[name]; duplicate {
			return fmt.Errorf("edge_labels[%d].name %q is duplicated", i, name)
		}
		byName[name] = label
	}

	names := make([]string, 0, len(externalReferenceEdgeContracts))
	for name := range externalReferenceEdgeContracts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		desc, ok := byName[name]
		if !ok {
			return fmt.Errorf("external-reference ingestion requires edge_label %q", name)
		}
		if err := validateExternalReferenceEdgeDescriptor(desc, externalReferenceEdgeContracts[name]); err != nil {
			return err
		}
	}
	return nil
}

func validateExternalReferenceEdgeDescriptor(desc EdgeLabelDescriptor, contract externalReferenceEdgeContract) error {
	name := desc.Name()
	if desc.EdgeFamily() != contract.EdgeFamily {
		return fmt.Errorf("edge_label %q edge_family=%q; want OOD protocol family %q", name, desc.EdgeFamily(), contract.EdgeFamily)
	}
	if desc.ReciprocalLabel() != "" {
		return fmt.Errorf("edge_label %q must not declare reciprocal_label", name)
	}
	if desc.DiagnosticOnly() {
		return fmt.Errorf("edge_label %q must be authoritative, not diagnostic_only", name)
	}
	if !equalStringSets(desc.SourceKinds(), contract.SourceKinds) {
		return fmt.Errorf("edge_label %q source_kinds=%v; want exact OOD protocol set %v", name, desc.SourceKinds(), contract.SourceKinds)
	}
	if !equalStringSets(desc.TargetKinds(), contract.TargetKinds) {
		return fmt.Errorf("edge_label %q target_kinds=%v; want exact OOD protocol set %v", name, desc.TargetKinds(), contract.TargetKinds)
	}
	return nil
}

// validateExternalReferenceEdgeIsolation applies §4's closed endpoint-family
// rule to every configured label, not only the eight labels §8 ingestion may
// emit. Without this gate an unrelated label (or an empty wildcard set) could
// be widened to an external class and spec_graph_link would bypass the exact
// external-reference topology contract.
func validateExternalReferenceEdgeIsolation(labels []EdgeLabelDescriptor) error {
	for _, desc := range labels {
		if contract, externalLabel := externalReferenceEdgeContracts[desc.Name()]; externalLabel {
			if err := validateExternalReferenceEdgeDescriptor(desc, contract); err != nil {
				return err
			}
			continue
		}
		for _, endpoint := range append(append([]string(nil), desc.SourceKinds()...), desc.TargetKinds()...) {
			if _, externalClass := externalReferenceObjectClasses[endpoint]; externalClass {
				return fmt.Errorf("edge_label %q admits external object class %q outside the closed OOD external-reference edge-label set", desc.Name(), endpoint)
			}
		}
	}
	return nil
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for _, value := range a {
		seen[value] = struct{}{}
	}
	for _, value := range b {
		if _, ok := seen[value]; !ok {
			return false
		}
	}
	return true
}

// optionalString returns the string at key, or "".
func (d EdgeLabelDescriptor) optionalString(key string) string {
	if d.raw == nil {
		return ""
	}
	s, _ := d.raw[key].(string)
	return s
}

// optionalStrings returns the string slice at key.
func (d EdgeLabelDescriptor) optionalStrings(key string) []string {
	if d.raw == nil {
		return nil
	}
	v, ok := d.raw[key]
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// optionalBool returns the bool at key, or false.
func (d EdgeLabelDescriptor) optionalBool(key string) bool {
	if d.raw == nil {
		return false
	}
	b, _ := d.raw[key].(bool)
	return b
}

// fileEdgeRegistry holds the labels loaded from config.
type fileEdgeRegistry struct {
	byName map[string]EdgeLabelDescriptor
}

func newEdgeRegistry(labels []EdgeLabelDescriptor) EdgeLabelRegistry {
	r := &fileEdgeRegistry{byName: make(map[string]EdgeLabelDescriptor, len(labels))}
	for _, l := range labels {
		r.byName[l.Name()] = l
	}
	return r
}

func (r *fileEdgeRegistry) Resolve(_ context.Context, label string) (EdgeLabelDescriptor, error) {
	d, ok := r.byName[label]
	if !ok {
		return EdgeLabelDescriptor{}, fmt.Errorf("%w: %q (add to spec-graph.config.json edge_labels)", ErrUnknownEdgeLabel, label)
	}
	return d, nil
}

func (r *fileEdgeRegistry) All(_ context.Context) ([]EdgeLabelDescriptor, error) {
	out := make([]EdgeLabelDescriptor, 0, len(r.byName))
	for _, d := range r.byName {
		out = append(out, d)
	}
	return out, nil
}

// validateEdgeEndpoints refuses an edge admission whose resolved endpoints
// don't satisfy the edge_label descriptor's structural constraints.
//
// Three checks:
//
//  1. src.NodeKind must be in desc.SourceKinds() (when SourceKinds is non-empty).
//  2. tgt.NodeKind must be in desc.TargetKinds() (when TargetKinds is non-empty).
//  3. When desc.ForbidSelfLoops() is true, src.NodeID must differ from tgt.NodeID.
//
// Empty SourceKinds / TargetKinds fails closed. ForbidSelfLoops defaults to
// false; only labels that opt in via config will refuse self-loops.
func validateEdgeEndpoints(desc EdgeLabelDescriptor, src, tgt Node) error {
	if srcKinds := desc.SourceKinds(); len(srcKinds) == 0 || !containsString(srcKinds, src.NodeKind) {
		return fmt.Errorf("%w: edge_label=%q source_id=%q has node_kind=%q, allowed source_kinds=%v",
			ErrEdgeKindMismatch, desc.Name(), src.NodeID, src.NodeKind, srcKinds)
	}
	if tgtKinds := desc.TargetKinds(); len(tgtKinds) == 0 || !containsString(tgtKinds, tgt.NodeKind) {
		return fmt.Errorf("%w: edge_label=%q target_id=%q has node_kind=%q, allowed target_kinds=%v",
			ErrEdgeKindMismatch, desc.Name(), tgt.NodeID, tgt.NodeKind, tgtKinds)
	}
	if desc.ForbidSelfLoops() && src.NodeID == tgt.NodeID {
		return fmt.Errorf("%w: edge_label=%q source_id=target_id=%q",
			ErrEdgeSelfLoopForbidden, desc.Name(), src.NodeID)
	}
	return nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
