package oodevidence

import (
	"fmt"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

// ReceiptManifestNodeHashV8 derives the canonical identity of one sealed
// per-batch receipt tree node from its complete typed entries.  The database
// node hash is therefore not an authority claim: callers must compare this
// value to the stored key before using a node to verify a batch.
func ReceiptManifestNodeHashV8(n ReceiptManifestNode) (string, error) {
	if n.ManifestKind != "fetch_batch_receipt" || n.EntryCount < 0 || n.TransitiveMemberCount < 0 || n.CanonicalByteCount < 0 {
		return "", fmt.Errorf("invalid receipt manifest node")
	}
	entries := n.Entries
	if len(entries) == 0 {
		return "", fmt.Errorf("receipt manifest has no physical entries")
	}
	if int64(len(entries)) != n.EntryCount {
		return "", fmt.Errorf("receipt manifest entry count mismatch")
	}
	record := oodcanon.RecordValue{
		"manifest_kind":           oodcanon.String(n.ManifestKind),
		"entry_count":             oodcanon.I64(n.EntryCount),
		"transitive_member_count": oodcanon.I64(n.TransitiveMemberCount),
		"canonical_byte_count":    oodcanon.I64(n.CanonicalByteCount),
	}
	if n.NodeKind == "leaf" {
		if n.NodeLevel != 0 {
			return "", fmt.Errorf("receipt manifest leaf level")
		}
		values := make([]oodcanon.Value, 0, len(entries))
		for i, entry := range entries {
			if entry.EntryOrdinal != int64(i) || entry.CanonicalEntryByteCount <= 0 || entry.Member == nil || entry.Child != nil || entry.Member.ReceiptID == "" {
				return "", fmt.Errorf("receipt manifest leaf entry")
			}
			digest, err := oodcanon.DigestHex(entry.Member.MemberHash)
			if err != nil {
				return "", fmt.Errorf("receipt manifest member hash: %w", err)
			}
			fields := []oodcanon.NamedValue{{Name: "entry_ordinal", Value: oodcanon.I64(entry.EntryOrdinal)}, {Name: "entry_kind", Value: oodcanon.String("receipt")}, {Name: "member_id", Value: oodcanon.String(entry.Member.ReceiptID)}, {Name: "member_hash", Value: digest}, {Name: "child_manifest_node_hash", Value: oodcanon.NullValue(oodcanon.SHA256)}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(0)}}
			measured, e := oodcanon.EncodeNestedRecord(oodcanon.ManifestLeafV1().Fields[7].Element.Nested, fields)
			if e != nil || int64(len(measured)) != entry.CanonicalEntryByteCount {
				return "", fmt.Errorf("receipt manifest entry byte count")
			}
			fields[len(fields)-1].Value = oodcanon.I64(entry.CanonicalEntryByteCount)
			values = append(values, oodcanon.Value{Type: oodcanon.Record, Presence: oodcanon.Present, Fields: fields})
		}
		record["ordered_entry_tuples"] = oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present, Elements: values}
		encoded, e := oodcanon.Encode(oodcanon.ManifestLeafV1(), record)
		if e != nil || int64(len(encoded)) != n.CanonicalByteCount {
			return "", fmt.Errorf("receipt manifest node byte count")
		}
		return oodcanon.DigestHexOf(oodcanon.ManifestLeafV1(), record)
	}
	if n.NodeKind != "internal" || n.NodeLevel < 1 {
		return "", fmt.Errorf("receipt manifest internal level")
	}
	values := make([]oodcanon.Value, 0, len(entries))
	for i, entry := range entries {
		if entry.EntryOrdinal != int64(i) || entry.CanonicalEntryByteCount <= 0 || entry.Member != nil || entry.Child == nil || entry.Child.NodeHash == "" || entry.Child.NodeLevel != n.NodeLevel-1 {
			return "", fmt.Errorf("receipt manifest child entry")
		}
		digest, err := oodcanon.DigestHex(entry.Child.NodeHash)
		if err != nil {
			return "", fmt.Errorf("receipt manifest child hash: %w", err)
		}
		fields := []oodcanon.NamedValue{{Name: "entry_ordinal", Value: oodcanon.I64(entry.EntryOrdinal)}, {Name: "entry_kind", Value: oodcanon.String("child_manifest")}, {Name: "member_id", Value: oodcanon.NullValue(oodcanon.UTF8)}, {Name: "member_hash", Value: oodcanon.NullValue(oodcanon.SHA256)}, {Name: "child_manifest_node_hash", Value: digest}, {Name: "child_transitive_member_count", Value: oodcanon.I64(entry.Child.TransitiveMemberCount)}, {Name: "child_canonical_byte_count", Value: oodcanon.I64(entry.Child.CanonicalByteCount)}, {Name: "canonical_entry_byte_count", Value: oodcanon.I64(0)}}
		measured, e := oodcanon.EncodeNestedRecord(oodcanon.ManifestInternalV1().Fields[8].Element.Nested, fields)
		if e != nil || int64(len(measured)) != entry.CanonicalEntryByteCount {
			return "", fmt.Errorf("receipt manifest entry byte count")
		}
		fields[len(fields)-1].Value = oodcanon.I64(entry.CanonicalEntryByteCount)
		values = append(values, oodcanon.Value{Type: oodcanon.Record, Presence: oodcanon.Present, Fields: fields})
	}
	record["node_level"] = oodcanon.I64(n.NodeLevel)
	record["ordered_child_tuples"] = oodcanon.Value{Type: oodcanon.Array, Presence: oodcanon.Present, Elements: values}
	encoded, e := oodcanon.Encode(oodcanon.ManifestInternalV1(), record)
	if e != nil || int64(len(encoded)) != n.CanonicalByteCount {
		return "", fmt.Errorf("receipt manifest node byte count")
	}
	return oodcanon.DigestHexOf(oodcanon.ManifestInternalV1(), record)
}
