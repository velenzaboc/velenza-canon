//go:build canonical

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodschema"
)

func TestGeneratedOODGraphSchemaMatchesCanonicalOOD(t *testing.T) {
	oodPath := os.Getenv("OOD_GRAPH_PROTOCOL_PATH")
	if oodPath == "" {
		t.Fatal("OOD_GRAPH_PROTOCOL_PATH must name the authoritative OOD_GRAPH_PROTOCOL_v1.ood.json bytes")
	}
	ood, err := os.ReadFile(oodPath)
	if err != nil {
		t.Fatalf("read authoritative OOD Graph protocol: %v", err)
	}
	wantDDL, wantReceipt, err := oodschema.Render(ood)
	if err != nil {
		t.Fatalf("rerender authoritative OOD Graph protocol: %v", err)
	}

	gotDDL, err := os.ReadFile("bootstrap/schema_ood_graph_protocol_v1.generated.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotDDL, wantDDL) {
		t.Fatal("committed OOD Graph DDL is not the exact rendering of the authoritative OOD bytes")
	}
	receiptBytes, err := os.ReadFile("bootstrap/schema_ood_graph_protocol_v1.render-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	var gotReceipt oodschema.Receipt
	if err := json.Unmarshal(receiptBytes, &gotReceipt); err != nil {
		t.Fatalf("decode committed render receipt: %v", err)
	}
	if !reflect.DeepEqual(gotReceipt, wantReceipt) {
		t.Fatalf("committed OOD Graph render receipt is not derived from the authoritative OOD bytes\ngot:  %+v\nwant: %+v", gotReceipt, wantReceipt)
	}
}
