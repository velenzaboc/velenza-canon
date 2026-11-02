package oodpublication

import (
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

// CloneManifestClosureInput detaches a validated physical closure from its
// read buffer. The selected schema resolver is a capability, so its identity
// is retained; every data slice, map, byte vector and record pointer is copied.
func CloneManifestClosureInput(in ManifestClosureInput) ManifestClosureInput {
	out := in
	out.CertificateRow = cloneManifestRowPointer(in.CertificateRow)
	out.ImmutableRows = cloneManifestRows(in.ImmutableRows)
	if in.MemberVerifier != nil {
		verifier := *in.MemberVerifier
		out.MemberVerifier = &verifier
	}
	out.Nodes = make([]ManifestNodeV8, len(in.Nodes))
	for i, node := range in.Nodes {
		n := node
		n.RoutePrefix = append([]byte(nil), node.RoutePrefix...)
		n.Row = cloneManifestRowPointer(node.Row)
		n.Entries = append([]ManifestEntryV8(nil), node.Entries...)
		for j := range n.Entries {
			n.Entries[j].Row = cloneManifestRowPointer(node.Entries[j].Row)
		}
		out.Nodes[i] = n
	}
	out.Members = make([]ManifestMemberV8, len(in.Members))
	for i, member := range in.Members {
		m := member
		m.Row = cloneManifestRowPointer(member.Row)
		m.EvidenceRows = cloneManifestRows(member.EvidenceRows)
		if member.OwnerRecord != nil {
			m.OwnerRecord = make(oodcanon.RecordValue, len(member.OwnerRecord))
			for key, value := range member.OwnerRecord {
				m.OwnerRecord[key] = cloneManifestCanonicalValue(value)
			}
		}
		if member.Receipt != nil {
			r := oodevidence.CloneReceiptV8(*member.Receipt)
			m.Receipt = &r
		}
		if member.Batch != nil {
			b := oodevidence.CloneBatchV8(*member.Batch)
			m.Batch = &b
		}
		out.Members[i] = m
	}
	return out
}

func cloneManifestRows(in []SpannerRow) []SpannerRow {
	if in == nil {
		return nil
	}
	out := make([]SpannerRow, len(in))
	for i, row := range in {
		out[i] = cloneImmutableSpannerRow(row)
	}
	return out
}

func cloneManifestRowPointer(in *SpannerRow) *SpannerRow {
	if in == nil {
		return nil
	}
	out := cloneImmutableSpannerRow(*in)
	return &out
}

func cloneManifestCanonicalValue(in oodcanon.Value) oodcanon.Value {
	out := in
	out.Bytes = append([]byte(nil), in.Bytes...)
	if in.Elements != nil {
		out.Elements = make([]oodcanon.Value, len(in.Elements))
		for i, value := range in.Elements {
			out.Elements[i] = cloneManifestCanonicalValue(value)
		}
	}
	if in.Entries != nil {
		out.Entries = make(map[string]oodcanon.Value, len(in.Entries))
		for key, value := range in.Entries {
			out.Entries[key] = cloneManifestCanonicalValue(value)
		}
	}
	if in.Fields != nil {
		out.Fields = make([]oodcanon.NamedValue, len(in.Fields))
		for i, field := range in.Fields {
			out.Fields[i] = oodcanon.NamedValue{Name: field.Name, Value: cloneManifestCanonicalValue(field.Value)}
		}
	}
	return out
}
