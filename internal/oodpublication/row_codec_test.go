package oodpublication

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestImmutablePhysicalObjectBuilderIsClosedAndStable(t *testing.T) {
	cols := map[string]interface{}{}
	for _, n := range immutablePhysicalContracts["OODGraphObjects"].columns {
		cols[n] = "value"
	}
	cols["organization_id"] = "org"
	cols["graph_object_id"] = "11111111-1111-4111-8111-111111111111"
	cols["source_authority_id"] = "22222222-2222-4222-8222-222222222222"
	for _, n := range []string{"api_element_role", "api_element_role_locator_manifest_hash", "source_content_hash_algorithm", "source_content_hash_profile", "source_content_hash"} {
		cols[n] = nil
	}
	for _, n := range []string{"source_stable_reference_index_hash", "graph_address_index_hash", "identity_tuple_index_hash", "graph_row_hash"} {
		cols[n] = strings.Repeat("a", 64)
	}
	x, err := BuildImmutableRow("OODGraphObjects", cols)
	if err != nil {
		t.Fatal(err)
	}
	y, err := BuildImmutableRow("OODGraphObjects", cols)
	if err != nil || !bytes.Equal(x.Bytes(), y.Bytes()) {
		t.Fatalf("nonstable row bytes: %v", err)
	}
	before := x.Bytes()
	cols["graph_row_hash"] = strings.Repeat("b", 64)
	if !bytes.Equal(before, x.Bytes()) {
		t.Fatal("builder retained caller mutation")
	}
	delete(cols, "graph_address")
	if _, err := BuildImmutableRow("OODGraphObjects", cols); err == nil {
		t.Fatal("missing column accepted")
	}
}
func TestImmutablePhysicalCodecRejectsTypeAndKeyTampering(t *testing.T) {
	cols := map[string]interface{}{}
	for _, n := range immutablePhysicalContracts["OODGraphManifestNodes"].columns {
		cols[n] = "x"
	}
	cols["organization_id"] = "org"
	cols["manifest_node_hash"] = strings.Repeat("a", 64)
	cols["node_level"], cols["entry_count"], cols["transitive_member_count"], cols["canonical_byte_count"] = int64(0), int64(0), int64(0), int64(0)
	cols["route_prefix_bytes"], cols["route_prefix_nibble_length"] = nil, nil
	cols["sealed"] = true
	cols["created_at"] = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	x, err := BuildImmutableRow("OODGraphManifestNodes", cols)
	if err != nil {
		t.Fatal(err)
	}
	row := x.Row()
	if _, err := CanonicalImmutableRowBytes(SpannerRow{Table: row.Table, KeyColumns: []string{"organization_id"}, Columns: row.Columns}); err == nil {
		t.Fatal("short key accepted")
	}
	cols["node_level"] = 0
	if _, err := BuildImmutableRow("OODGraphManifestNodes", cols); err == nil {
		t.Fatal("int coercion accepted")
	}
	cols["node_level"] = int64(0)
	cols["manifest_node_hash"] = strings.Repeat("A", 64)
	if _, err := BuildImmutableRow("OODGraphManifestNodes", cols); err == nil {
		t.Fatal("digest case accepted")
	}
}

func TestImmutablePhysicalColumnNamesReturnsDefensivePinnedRoster(t *testing.T) {
	keys, cols, err := ImmutablePhysicalColumnNames("OODGraphManifestNodes")
	if err != nil || len(keys) != 2 || len(cols) == 0 {
		t.Fatalf("roster: %v %v %v", keys, cols, err)
	}
	keys[0], cols[0] = "changed", "changed"
	keys2, cols2, err := ImmutablePhysicalColumnNames("OODGraphManifestNodes")
	if err != nil || keys2[0] == "changed" || cols2[0] == "changed" {
		t.Fatal("physical roster was mutable")
	}
	if _, _, err := ImmutablePhysicalColumnNames("not_a_table"); err == nil {
		t.Fatal("unknown physical table accepted")
	}
}

func TestEveryAcceptedImmutableRosterRejectsRequiredNullAndCrossType(t *testing.T) {
	for table, contract := range immutablePhysicalContracts {
		t.Run(table, func(t *testing.T) {
			cols := validPhysicalFixture(table, contract)
			if _, err := BuildImmutableRow(table, cols); err != nil {
				t.Fatalf("valid fixture rejected (%d columns for %d roster fields): %v", len(cols), len(contract.columns), err)
			}
			for _, name := range contract.columns {
				if !nullablePhysicalColumn(table, name) {
					cols[name] = nil
					break
				}
			}
			if _, err := BuildImmutableRow(table, cols); err == nil {
				t.Fatal("required null accepted")
			}
			cols = validPhysicalFixture(table, contract)
			for _, name := range contract.columns {
				if physicalColumnType(table, name) == physicalText {
					cols[name] = int64(1)
					break
				}
			}
			if _, err := BuildImmutableRow(table, cols); err == nil {
				t.Fatal("cross-type value accepted")
			}
		})
	}
}
func validPhysicalFixture(table string, contract physicalContract) map[string]interface{} {
	m := map[string]interface{}{}
	for _, name := range contract.columns {
		switch physicalColumnType(table, name) {
		case physicalInt64:
			m[name] = int64(1)
		case physicalBool:
			m[name] = true
		case physicalBytes:
			m[name] = []byte{1}
		case physicalTimestamp:
			m[name] = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
		case physicalStringArray:
			m[name] = []string{"role"}
		case physicalJSON:
			m[name] = CanonicalJSON(`{"x":1}`)
		default:
			if physicalUUIDColumn(table, name) {
				m[name] = "11111111-1111-4111-8111-111111111111"
			} else if physicalDigestColumn(table, name) {
				m[name] = strings.Repeat("a", 64)
			} else {
				m[name] = "x"
			}
		}
	}
	return m
}
