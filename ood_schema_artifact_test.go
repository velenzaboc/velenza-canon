package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodschema"
)

func TestGeneratedOODGraphSchemaMatchesReceipt(t *testing.T) {
	ddl, err := os.ReadFile("bootstrap/schema_ood_graph_protocol_v1.generated.sql")
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := os.ReadFile("bootstrap/schema_ood_graph_protocol_v1.render-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt oodschema.Receipt
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatalf("decode render receipt: %v", err)
	}
	if err := oodschema.VerifyRendered(ddl, receipt); err != nil {
		t.Fatalf("verify generated OOD Graph schema: %v", err)
	}
}
