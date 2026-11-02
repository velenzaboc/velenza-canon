//go:build canonical

package oodcanon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The relationship vector is owner data. Keeping it in the exact pinned OOD
// document avoids placing an internal organization identifier in the ordinary
// public test suite while still checking the complete canonical tuple.
func TestRelationshipOwnerGoldenMatchesCanonicalOOD10(t *testing.T) {
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

	var owner any
	if err := json.Unmarshal(raw, &owner); err != nil {
		t.Fatal(err)
	}
	fixture := findRelationshipOwnerGolden(owner)
	if fixture == nil {
		t.Fatal("relationship owner golden absent or ambiguous")
	}
	input, ok := fixture["ordered_input"].(map[string]any)
	if !ok {
		t.Fatal("relationship owner golden ordered input absent")
	}
	want, ok := fixture["expected_relationship_evidence_hash"].(string)
	if !ok {
		if result, valid := fixture["expected_result"].(map[string]any); valid {
			want, ok = result["expected_relationship_evidence_hash"].(string)
		}
	}
	if !ok {
		t.Fatal("relationship owner golden expected hash absent")
	}

	p, err := ProfileFor("ood_graph_relationship_evidence_v1")
	if err != nil {
		t.Fatal(err)
	}
	r := RecordValue{}
	for _, field := range p.Fields {
		if field.Literal != nil {
			continue
		}
		value, exists := input[field.Name]
		if !exists {
			t.Fatalf("owner input missing %s", field.Name)
		}
		if value == nil {
			if field.Policy != Nullable {
				t.Fatalf("owner input null for required %s", field.Name)
			}
			r[field.Name] = NullValue(field.Type)
			continue
		}
		text, ok := value.(string)
		if !ok {
			t.Fatalf("owner input %s is not a scalar string", field.Name)
		}
		switch field.Type {
		case UTF8:
			r[field.Name] = String(text)
		case UUID:
			v, e := UUIDText(text)
			if e != nil {
				t.Fatalf("owner input %s: %v", field.Name, e)
			}
			r[field.Name] = v
		case SHA256:
			v, e := DigestHex(text)
			if e != nil {
				t.Fatalf("owner input %s: %v", field.Name, e)
			}
			r[field.Name] = v
		default:
			t.Fatalf("relationship owner fixture has unsupported %s type %d", field.Name, field.Type)
		}
	}
	got, err := DigestHexOf(p, r)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("relationship owner golden got %s want %s", got, want)
	}
}

func findRelationshipOwnerGolden(value any) map[string]any {
	var found map[string]any
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			if typed["fixture_id"] == "relationship_evidence_canonical_hash_golden" {
				if found != nil {
					found = nil
					return
				}
				found = typed
			}
			for _, child := range typed {
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return found
}
