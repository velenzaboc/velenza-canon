//go:build canonical

package oodproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// This opt-in check reads the independently pinned owner without copying the
// full canonical document into the public implementation repository.
func TestGraphFactLocatorMatchesCanonicalOwner(t *testing.T) {
	path, expected := os.Getenv("OOD_GRAPH_PROTOCOL_PATH"), os.Getenv("OOD_GRAPH_PROTOCOL_SHA256")
	if path == "" || expected != "4c898eff0792fe3647702ff3c3d99af7a87f43c3df13ce851a6ecfaabd0383a2" {
		t.Fatal("exact OOD10 path and independent SHA-256 pin are required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != expected {
		t.Fatal("canonical owner byte identity changed")
	}
	var owner map[string]json.RawMessage
	if err := json.Unmarshal(raw, &owner); err != nil {
		t.Fatal(err)
	}
	object := func(raw json.RawMessage) map[string]json.RawMessage {
		var value map[string]json.RawMessage
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	sections := object(owner["sections"])
	storage := object(sections["s6_spanner_storage_model"])
	tables := object(storage["table_surfaces"])
	locatorTable := object(tables["ood_graph_graph_fact_evidence_locators"])
	var contract struct {
		Algorithm string   `json:"algorithm"`
		Profile   string   `json:"canonicalization_profile"`
		Order     []string `json:"ordered_preimage"`
		Bindings  []struct {
			Name     string `json:"field_path"`
			Type     string `json:"field_type"`
			Presence string `json:"presence_policy"`
		} `json:"field_type_bindings"`
	}
	if err := json.Unmarshal(locatorTable["locator_hash_contract"], &contract); err != nil {
		t.Fatal(err)
	}
	hashContract := object(storage["immutable_fact_hash_contract"])
	var encoding struct {
		Profile   string            `json:"profile_name"`
		Prefix    string            `json:"top_level_record_prefix_ascii"`
		ByteOrder string            `json:"integer_byte_order"`
		Tags      map[string]string `json:"type_tag_registry"`
		Presence  map[string]string `json:"presence_marker_registry"`
	}
	if err := json.Unmarshal(hashContract["canonical_encoding"], &encoding); err != nil {
		t.Fatal(err)
	}
	if contract.Algorithm != "SHA-256" || contract.Profile != GraphFactLocatorCanonicalizationProfile || encoding.Profile != "ood_graph_canonical_field_encoding_v1" || encoding.Prefix != "OODGCFE1" || encoding.ByteOrder != "big_endian" || encoding.Presence["present"] != "0x01" {
		t.Fatal("canonical locator domain or framing changed")
	}
	value, _ := locator(t)
	fields, err := value.fields()
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != len(contract.Order) || len(fields) != len(contract.Bindings) {
		t.Fatal("canonical field roster differs")
	}
	for i, field := range fields {
		binding := contract.Bindings[i]
		tag, err := strconv.ParseUint(encoding.Tags[binding.Type], 0, 8)
		if err != nil || field.name != contract.Order[i] || field.name != binding.Name || field.tag != byte(tag) || binding.Presence != "required" {
			t.Fatalf("field %d does not equal canonical ordered name/type/presence", i)
		}
	}
}
