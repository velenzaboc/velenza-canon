package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The OOD Graph Protocol §7 (OOD_GRAPH_PROTOCOL_v1.ood.json, doc_id
// 767c2399-87f9-4859-ac64-afb575bdb263) owns exactly one canonical Spanner
// projection over the §6 storage substrate: a property graph named OODGraph,
// dynamic-labelled from OODGraphObjects.object_class and OODGraphEdges.edge_label.
//
//	§7.create_property_graph_model.projection_strategy =
//	  "dynamic_label_canonical_projection_over_ood_graph_objects_and_edges"
//	§7.create_property_graph_model.static_view_generation_status =
//	  "compatibility_only_not_canonical_end_state"
//	§7.downstream_contracts.s10_retrieval_and_query_contracts[0] =
//	  "must consume OODGraph through GQL or GRAPH_TABLE surfaces for graph traversal"
//
// These tests bind bootstrap/schema_v2.sql to that contract so the statement
// cannot silently regress to the deferral comment it replaced, and so the
// clause ordering Spanner actually requires cannot be "tidied" back into the
// order §7 states (which does not parse — see the ⛔ block in schema_v2.sql).
//
// Deliberately NOT asserted here: that the graph exists in any live database.
// Applying it is a separate, gated act; §7.label_exposure.dynamic_label_rule
// requires unregistered labels be rejected by §8 BEFORE projection.

const schemaV2Path = "bootstrap/schema_v2.sql"

// propertyGraphStatement returns the single CREATE PROPERTY GRAPH statement in
// schema_v2.sql, using the same splitDDL the init path uses, so the test sees
// exactly what admin.ApplyDDL would be handed.
func propertyGraphStatement(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(schemaV2Path)
	if err != nil {
		t.Fatalf("read %s: %v", schemaV2Path, err)
	}
	var found []string
	for _, stmt := range splitDDL(string(raw)) {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(stmt)), "CREATE PROPERTY GRAPH") {
			found = append(found, stmt)
		}
	}
	if len(found) == 0 {
		t.Fatalf("%s declares no CREATE PROPERTY GRAPH statement; OOD_GRAPH_PROTOCOL_v1 §7 requires the OODGraph projection", schemaV2Path)
	}
	if len(found) != 1 {
		t.Fatalf("%s declares %d CREATE PROPERTY GRAPH statements, want exactly 1 (§7 owns one graph, OODGraph)", schemaV2Path, len(found))
	}
	return found[0]
}

func TestSchemaV2DeclaresOODGraphPropertyGraph(t *testing.T) {
	stmt := propertyGraphStatement(t)

	// §7.create_property_graph_model.property_graph_name = "OODGraph".
	if !regexp.MustCompile(`(?i)CREATE\s+PROPERTY\s+GRAPH\s+OODGraph\b`).MatchString(stmt) {
		t.Errorf("graph name is not OODGraph; §7.create_property_graph_model.property_graph_name pins it\nstatement:\n%s", stmt)
	}

	// §7 projects over the two §6 base tables and NOTHING else. OODGraphSymbols is
	// lookup-only (§7.element_key_and_endpoint_strategy.symbol_node_element_key =
	// "compatibility_lookup_only_not_production_property_graph_element_key"), and every
	// generated static view carries production_allowed:false.
	for _, want := range []string{"OODGraphObjects", "OODGraphEdges"} {
		if !strings.Contains(stmt, want) {
			t.Errorf("statement does not reference %s", want)
		}
	}
	if strings.Contains(stmt, "OODGraphSymbols") {
		t.Errorf("statement references OODGraphSymbols; §7 makes symbol rows lookup-only, never a production element table\nstatement:\n%s", stmt)
	}
	if regexp.MustCompile(`(?i)OODGraph(DocObject|DocVersion|Section|SymbolObject|Config|Circuit|Schema|Sentinel|Invariant|Assumption)Nodes`).MatchString(stmt) {
		t.Errorf("statement references a class-filtered compatibility view; §7.create_property_graph_model.static_view_generation_status is compatibility_only_not_canonical_end_state\nstatement:\n%s", stmt)
	}
}

func TestOODGraphElementKeysMatchProtocolS7(t *testing.T) {
	stmt := propertyGraphStatement(t)
	norm := regexp.MustCompile(`\s+`).ReplaceAllString(stmt, " ")

	// §7.element_key_and_endpoint_strategy.object_node_element_key and .edge_element_key.
	for _, want := range []string{
		"KEY (organization_id, graph_snapshot_id, graph_object_id)",
		"KEY (organization_id, graph_snapshot_id, graph_edge_id)",
	} {
		if !strings.Contains(norm, want) {
			t.Errorf("missing element key %q (§7.element_key_and_endpoint_strategy)", want)
		}
	}

	// §7.spanner_dynamic_label_projection_contract.required_edge_table.source_key /
	// .destination_key — both resolve to OODGraphObjects.graph_object_id.
	// §7.element_key_and_endpoint_strategy.graph_address_endpoint_key_allowed = false.
	for _, want := range []string{
		"SOURCE KEY (organization_id, graph_snapshot_id, source_endpoint_id) REFERENCES OODGraphObjects (organization_id, graph_snapshot_id, graph_object_id)",
		"DESTINATION KEY (organization_id, graph_snapshot_id, target_endpoint_id) REFERENCES OODGraphObjects (organization_id, graph_snapshot_id, graph_object_id)",
	} {
		if !strings.Contains(norm, want) {
			t.Errorf("missing endpoint clause %q (§7.spanner_dynamic_label_projection_contract.required_edge_table)", want)
		}
	}
}

func TestOODGraphUsesDynamicLabelsAfterProperties(t *testing.T) {
	stmt := propertyGraphStatement(t)
	norm := regexp.MustCompile(`\s+`).ReplaceAllString(stmt, " ")

	// §7.spanner_dynamic_label_projection_contract.dynamic_node_label_source /
	// .dynamic_edge_label_source. §7.label_exposure.node_dynamic_labels_used and
	// .edge_dynamic_labels_used are both true; .spanner_default_labels_allowed is false.
	for _, want := range []string{
		"DYNAMIC LABEL (object_class)",
		"DYNAMIC LABEL (edge_label)",
	} {
		if !strings.Contains(norm, want) {
			t.Errorf("missing %q; §7 mandates dynamic labels for both element kinds", want)
		}
	}

	// §7.required_node_table.properties / .required_edge_table.properties = "ALL COLUMNS".
	// Verified 2026-08-17 on real Spanner: ALL COLUMNS accepts the two HIDDEN generated
	// TOKENLIST columns on both tables, so no EXCEPT clause is owed.
	if n := strings.Count(norm, "PROPERTIES ALL COLUMNS"); n != 2 {
		t.Errorf("found %d PROPERTIES ALL COLUMNS clauses, want 2 (one per element table)", n)
	}

	// ⛔ ORDER IS LOAD-BEARING AND SPANNER-ENFORCED. §7 states
	// "DYNAMIC LABEL (...) PROPERTIES ALL COLUMNS"; real Spanner rejects that order with
	//   "Syntax error: LABEL or PROPERTIES clause should be moved before
	//    DYNAMIC LABEL/PROPERTIES clause"
	// (measured 2026-08-17 against spec-graph-scratch, INVALID_ARGUMENT, exit 1).
	// PROPERTIES must precede DYNAMIC LABEL. Restoring §7's stated order breaks the apply.
	for _, pair := range []struct{ label, props string }{
		{"DYNAMIC LABEL (object_class)", "PROPERTIES ALL COLUMNS"},
		{"DYNAMIC LABEL (edge_label)", "PROPERTIES ALL COLUMNS"},
	} {
		li := strings.Index(norm, pair.label)
		if li < 0 {
			continue // already reported above
		}
		pi := strings.LastIndex(norm[:li], pair.props)
		if pi < 0 {
			t.Errorf("%q is not preceded by %q; Spanner requires PROPERTIES before DYNAMIC LABEL and rejects the order §7 states", pair.label, pair.props)
		}
	}
}
