package oodpublication

import (
	"errors"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

// verifyOrdinaryManifestByteCounts independently recomputes the owner-defined
// nested entry and complete node measures. Stored counts are never authority.
func verifyOrdinaryManifestByteCounts(n ManifestNodeV8, nodes map[string]ManifestNodeV8, p oodcanon.Profile, r oodcanon.RecordValue) error {
	for _, e := range n.Entries {
		b, err := oodcanon.EncodeNestedRecord(nativeOrdinaryEntryFields(n.NodeKind), nativeOrdinaryEntryValues(e, nodes))
		if err != nil || int64(len(b)) != e.CanonicalByteCount {
			return errors.New("manifest canonical entry byte count mismatch")
		}
	}
	b, err := oodcanon.Encode(p, r)
	if err != nil || int64(len(b)) != n.CanonicalByteCount {
		return errors.New("manifest canonical node byte count mismatch")
	}
	return nil
}

func verifySparseManifestByteCounts(n ManifestNodeV8, p oodcanon.Profile, r oodcanon.RecordValue) error {
	var slotFields []oodcanon.Field
	for _, field := range p.Fields {
		if field.Name == "ordered_present_slot_tuples" && field.Element != nil {
			slotFields = field.Element.Nested
		}
	}
	slots := r["ordered_present_slot_tuples"].Elements
	if len(slotFields) == 0 || len(slots) != len(n.Entries) {
		return errors.New("sparse manifest slot schema mismatch")
	}
	for i, slot := range slots {
		b, err := oodcanon.EncodeNestedRecord(slotFields, slot.Fields)
		if err != nil || int64(len(b)) != n.Entries[i].CanonicalByteCount {
			return errors.New("sparse manifest canonical entry byte count mismatch")
		}
	}
	b, err := oodcanon.Encode(p, r)
	if err != nil || int64(len(b)) != n.CanonicalByteCount {
		return errors.New("sparse manifest canonical node byte count mismatch")
	}
	return nil
}
