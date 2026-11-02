package oodpublication_test

import (
	"context"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

func TestManifestCloneDetachesValidatedClosure(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	retained := oodpublication.CloneManifestClosureInput(f.Closure)
	for i := range f.Closure.ImmutableRows {
		f.Closure.ImmutableRows[i].Columns["organization_id"] = "foreign"
		f.Closure.ImmutableRows[i].KeyColumns[0] = "foreign"
	}
	for i := range f.Closure.Nodes {
		f.Closure.Nodes[i].Hash = "changed"
		if f.Closure.Nodes[i].Row != nil {
			f.Closure.Nodes[i].Row.Columns["sealed"] = false
		}
		for j := range f.Closure.Nodes[i].Entries {
			f.Closure.Nodes[i].Entries[j].MemberHash = "changed"
		}
	}
	for i := range f.Closure.Members {
		m := &f.Closure.Members[i]
		m.ClaimedHash = "changed"
		for j := range m.EvidenceRows {
			m.EvidenceRows[j].Columns["organization_id"] = "foreign"
		}
		if m.Receipt != nil {
			m.Receipt.ReceiptRoles[0] = "changed"
		}
		if m.Batch != nil && m.Batch.ExpectedComponentCount != nil {
			*m.Batch.ExpectedComponentCount = 999
		}
	}
	if err := oodpublication.VerifyManifestClosureV8(f.Certificate, retained); err != nil {
		t.Fatalf("mutating read buffers altered retained proof inputs: %v", err)
	}
	if err := oodpublication.VerifyManifestClosureV8(f.Certificate, f.Closure); err == nil {
		t.Fatal("hostile source mutation did not alter the original closure")
	}
}
