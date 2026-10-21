package oodschema

import (
	"encoding/json"
	"strings"
	"testing"
)

func minimalOOD(columns string, statement string) []byte {
	return []byte(`{
  "doc_id":"767c2399-87f9-4859-ac64-afb575bdb263",
  "title":"OOD Graph Protocol",
  "version":"1",
  "sections":{"s6_spanner_storage_model":{
    "table_surfaces":{"example":{"physical_table_name":"OODGraphExample","primary_key":["organization_id","example_id"],"columns":` + columns + `}},
    "spanner_ddl_model":{
      "ddl_is_normative_schema_shape":true,
      "ddl_apply_instruction":false,
      "table_surface_column_order_parity":{"required":true},
      "statements":[` + mustJSON(statement) + `,"CREATE INDEX OODGraphExampleByValue ON OODGraphExample (organization_id, value)"]
    }
  },"s7_spanner_property_graph_schema":{"create_property_graph_model":{
    "ddl_is_normative_schema_shape":true,
    "ddl_apply_instruction":false,
    "property_graph_name":"OODGraph",
    "node_tables":"OODGraphExample KEY (organization_id, example_id) LABEL ood_graph_node PROPERTIES (organization_id, example_id, value) DYNAMIC LABEL (value)",
    "edge_tables_generation":"OODGraphExample KEY (organization_id, example_id) SOURCE KEY (organization_id, example_id) REFERENCES OODGraphExample (organization_id, example_id) DESTINATION KEY (organization_id, example_id) REFERENCES OODGraphExample (organization_id, example_id) LABEL ood_graph_edge PROPERTIES (organization_id, example_id, value) DYNAMIC LABEL (value)"
  }}}
}`)
}

func mustJSON(value string) string {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func TestRenderValidSchema(t *testing.T) {
	ood := minimalOOD(
		`{"organization_id":"STRING(36) NOT NULL","example_id":"STRING(36) NOT NULL","value":"STRING(64) NOT NULL","value_filter":"STRING(64) AS (IF(value = 'ready', value, NULL)) STORED"}`,
		"CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL, value_filter STRING(64) AS (IF(value = 'ready', value, NULL)) STORED) PRIMARY KEY (organization_id, example_id)",
	)
	ddl, receipt, err := Render(ood)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if receipt.Result != "pass" || receipt.TableSurfaceCount != 1 || receipt.StorageDDLStatementCount != 2 || receipt.DDLStatementCount != 3 || receipt.PropertyGraphStatementCount != 1 || receipt.CreateTableCount != 1 || receipt.CreateIndexCount != 1 || receipt.DDLApplyAuthorized {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	text := string(ddl)
	if !strings.Contains(text, "OOD spec SHA-256: "+receipt.OODSpecSHA256) || !strings.Contains(text, "CREATE TABLE OODGraphExample") || !strings.Contains(text, "CREATE PROPERTY GRAPH OODGraph") || !strings.HasSuffix(text, ";\n") {
		t.Fatalf("unexpected rendered DDL:\n%s", text)
	}
	if err := VerifyRendered(ddl, receipt); err != nil {
		t.Fatalf("VerifyRendered(valid output): %v", err)
	}
	for _, tt := range []struct {
		name    string
		ddl     []byte
		receipt Receipt
	}{
		{name: "digest", ddl: append(append([]byte(nil), ddl...), 'x'), receipt: receipt},
		{name: "authorizing receipt", ddl: ddl, receipt: func() Receipt { r := receipt; r.DDLApplyAuthorized = true; return r }()},
		{name: "count", ddl: ddl, receipt: func() Receipt { r := receipt; r.DDLStatementCount++; return r }()},
		{name: "roster", ddl: ddl, receipt: func() Receipt { r := receipt; r.PhysicalTableNames = []string{"Other"}; return r }()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyRendered(tt.ddl, tt.receipt); err == nil {
				t.Fatal("VerifyRendered accepted tampered render receipt")
			}
		})
	}
}

func TestParserPrimitivesCloseMalformedDDLAndJSON(t *testing.T) {
	table, err := parseCreateTable("CREATE TABLE Example (id STRING(36) NOT NULL, value STRING(20) AS (IF(id = 'a,b', 'x', 'y')) STORED, CONSTRAINT ignored CHECK (id != '')) PRIMARY KEY (id)")
	if err != nil || table.Name != "Example" || len(table.Columns) != 2 || table.Columns[1].Name != "value" {
		t.Fatalf("parseCreateTable() = %#v, %v", table, err)
	}
	for _, statement := range []string{"ALTER TABLE Example ADD x STRING(1)", "CREATE TABLE Example (id STRING(1))", "CREATE TABLE Example (id) PRIMARY KEY (id)", "CREATE TABLE Example (id STRING(1)) PRIMARY KEY (id"} {
		if _, err := parseCreateTable(statement); err == nil {
			t.Fatalf("parseCreateTable accepted malformed statement %q", statement)
		}
	}
	if _, err := decodeOrderedStringObject([]byte(`[]`)); err == nil {
		t.Fatal("decodeOrderedStringObject accepted array")
	}
	if _, err := decodeOrderedStringObject([]byte(`{"id":1}`)); err == nil {
		t.Fatal("decodeOrderedStringObject accepted non-string definition")
	}
	if _, err := decodeOrderedStringObject([]byte(`{"id":"STRING(1)","id":"STRING(1)"}`)); err == nil {
		t.Fatal("decodeOrderedStringObject accepted duplicate name")
	}
	for _, value := range []string{"(a, 'b)')", "(a", ")"} {
		_, _ = matchingParen(value, 0)
	}
	for _, value := range []string{"a, func('x,y'), b", "a, (b", "a, 'b"} {
		_, _ = splitTopLevel(value)
	}
	for _, value := range []string{`"1"`, `12`, `null`, `true`, `"`} {
		_, _ = scalarString(json.RawMessage(value))
	}
	for _, value := range []string{`{"a":1}{"b":2}`, `{"a":1,"a":2}`, `{`} {
		if err := rejectDuplicateJSONKeys([]byte(value)); err == nil {
			t.Fatalf("rejectDuplicateJSONKeys accepted malformed/ambiguous value %q", value)
		}
	}
}

func TestRenderPropertyGraphClosesIncompleteOrMisdirectedDefinitions(t *testing.T) {
	tables := map[string]parsedTable{"Nodes": {Name: "Nodes"}, "Edges": {Name: "Edges"}}
	for _, model := range []propertyGraphModel{
		{},
		{Name: "bad-name!", NodeTables: "Nodes DYNAMIC LABEL (x)", EdgeTables: "Edges REFERENCES Nodes (id) REFERENCES Nodes (id) DYNAMIC LABEL (x)"},
		{Name: "Graph", NodeTables: "Missing DYNAMIC LABEL (x)", EdgeTables: "Edges REFERENCES Missing (id) REFERENCES Missing (id) DYNAMIC LABEL (x)"},
		{Name: "Graph", NodeTables: "Nodes DYNAMIC LABEL (x)", EdgeTables: "Edges REFERENCES Nodes (id) DYNAMIC LABEL (x)"},
		{Name: "Graph", NodeTables: "Nodes label", EdgeTables: "Edges REFERENCES Nodes (id) REFERENCES Nodes (id) DYNAMIC LABEL (x)"},
	} {
		if _, err := renderPropertyGraph(model, tables); err == nil {
			t.Fatalf("renderPropertyGraph accepted %#v", model)
		}
	}
}

func TestRenderRejectsColumnOrderDrift(t *testing.T) {
	ood := minimalOOD(
		`{"example_id":"STRING(36) NOT NULL","organization_id":"STRING(36) NOT NULL","value":"STRING(64) NOT NULL"}`,
		"CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL) PRIMARY KEY (organization_id, example_id)",
	)
	_, _, err := Render(ood)
	if err == nil || !strings.Contains(err.Error(), "column[0] mismatch") {
		t.Fatalf("got %v, want column-order mismatch", err)
	}
}

func TestRenderRejectsColumnDefinitionDrift(t *testing.T) {
	ood := minimalOOD(
		`{"organization_id":"STRING(36) NOT NULL","example_id":"STRING(36) NOT NULL","value":"STRING(32) NOT NULL"}`,
		"CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL) PRIMARY KEY (organization_id, example_id)",
	)
	_, _, err := Render(ood)
	if err == nil || !strings.Contains(err.Error(), "column[2] mismatch") {
		t.Fatalf("got %v, want definition mismatch", err)
	}
}

func TestRenderRejectsPrimaryKeyDrift(t *testing.T) {
	ood := minimalOOD(
		`{"organization_id":"STRING(36) NOT NULL","example_id":"STRING(36) NOT NULL","value":"STRING(64) NOT NULL"}`,
		"CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL) PRIMARY KEY (example_id, organization_id)",
	)
	_, _, err := Render(ood)
	if err == nil || !strings.Contains(err.Error(), "primary key mismatch") {
		t.Fatalf("got %v, want primary-key mismatch", err)
	}
}

func TestRenderRejectsUnknownIndexTable(t *testing.T) {
	ood := minimalOOD(
		`{"organization_id":"STRING(36) NOT NULL","example_id":"STRING(36) NOT NULL","value":"STRING(64) NOT NULL"}`,
		"CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL) PRIMARY KEY (organization_id, example_id)",
	)
	ood = []byte(strings.Replace(string(ood), "ON OODGraphExample (organization_id, value)", "ON OODGraphMissing (organization_id, value)", 1))
	_, _, err := Render(ood)
	if err == nil || !strings.Contains(err.Error(), "references unknown table") {
		t.Fatalf("got %v, want unknown-index-table rejection", err)
	}
}

func TestRenderRejectsCreateTableWithoutSurface(t *testing.T) {
	ood := minimalOOD(
		`{"organization_id":"STRING(36) NOT NULL","example_id":"STRING(36) NOT NULL","value":"STRING(64) NOT NULL"}`,
		"CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL) PRIMARY KEY (organization_id, example_id)",
	)
	ood = []byte(strings.Replace(string(ood),
		`"CREATE INDEX OODGraphExampleByValue ON OODGraphExample (organization_id, value)"`,
		`"CREATE TABLE OODGraphExtra (organization_id STRING(36) NOT NULL, extra_id STRING(36) NOT NULL) PRIMARY KEY (organization_id, extra_id)"`, 1))
	_, _, err := Render(ood)
	if err == nil || !strings.Contains(err.Error(), "absent from table_surfaces") {
		t.Fatalf("got %v, want extra-table rejection", err)
	}
}

func TestRenderRejectsDuplicateIndex(t *testing.T) {
	ood := minimalOOD(
		`{"organization_id":"STRING(36) NOT NULL","example_id":"STRING(36) NOT NULL","value":"STRING(64) NOT NULL"}`,
		"CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL) PRIMARY KEY (organization_id, example_id)",
	)
	ood = []byte(strings.Replace(string(ood),
		`"CREATE INDEX OODGraphExampleByValue ON OODGraphExample (organization_id, value)"]`,
		`"CREATE INDEX OODGraphExampleByValue ON OODGraphExample (organization_id, value)","CREATE INDEX OODGraphExampleByValue ON OODGraphExample (organization_id, value)"]`, 1))
	_, _, err := Render(ood)
	if err == nil || !strings.Contains(err.Error(), "duplicate CREATE INDEX") {
		t.Fatalf("got %v, want duplicate-index rejection", err)
	}
}

func TestRenderRejectsDuplicateJSONKeys(t *testing.T) {
	ood := minimalOOD(
		`{"organization_id":"STRING(36) NOT NULL","organization_id":"STRING(36) NOT NULL","example_id":"STRING(36) NOT NULL","value":"STRING(64) NOT NULL"}`,
		"CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL) PRIMARY KEY (organization_id, example_id)",
	)
	_, _, err := Render(ood)
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("got %v, want duplicate-key rejection", err)
	}
}

func TestRenderRejectsApplyAuthoritySmuggling(t *testing.T) {
	ood := minimalOOD(
		`{"organization_id":"STRING(36) NOT NULL","example_id":"STRING(36) NOT NULL","value":"STRING(64) NOT NULL"}`,
		"CREATE TABLE OODGraphExample (organization_id STRING(36) NOT NULL, example_id STRING(36) NOT NULL, value STRING(64) NOT NULL) PRIMARY KEY (organization_id, example_id)",
	)
	ood = []byte(strings.Replace(string(ood), `"ddl_apply_instruction":false`, `"ddl_apply_instruction":true`, 1))
	_, _, err := Render(ood)
	if err == nil || !strings.Contains(err.Error(), "not deployment authorization") {
		t.Fatalf("got %v, want apply-authority rejection", err)
	}
}
