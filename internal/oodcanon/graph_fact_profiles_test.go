package oodcanon

import (
	"bytes"
	"testing"
)

func TestImmutableGraphFactTupleVariantsAreClosed(t *testing.T) {
	for _, tc := range []struct {
		name, discriminator string
		p                   Profile
		r                   RecordValue
	}{
		{"object", "object", ObjectFactTupleV1(), objectFactFixture(t)},
		{"symbol", "symbol", SymbolFactTupleV1(), symbolFactFixture(t)},
		{"edge", "edge", EdgeFactTupleV1(), edgeFactFixture(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := Encode(tc.p, tc.r)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Encode(tc.p, tc.r)
			if err != nil || !bytes.Equal(b, again) {
				t.Fatalf("non-deterministic: %v", err)
			}
			if _, err := Encode(tc.p, RecordValue{}); err == nil {
				t.Fatal("missing fields accepted")
			}
			bad := RecordValue{}
			for k, v := range tc.r {
				bad[k] = v
			}
			bad["table_discriminator"] = String(tc.discriminator)
			if _, err := Encode(tc.p, bad); err == nil {
				t.Fatal("caller supplied literal accepted")
			}
		})
	}
}

func TestNineRootMemberProfilesMatchOwnerBindingRosters(t *testing.T) {
	for _, tc := range []struct {
		name   string
		p      Profile
		fields []string
	}{
		{"api", APIPropertyFactV1(), []string{"canonicalization_profile", "organization_id", "subject_kind", "graph_object_id", "graph_edge_id", "subject_graph_row_hash", "property_family", "property_schema_artifact_id", "property_schema_version", "property_schema_digest", "property_payload_profile", "property_payload_hash", "extractor_profile_id", "extractor_profile_version", "extractor_profile_digest", "evidence_authority_class", "graph_fact_locator_manifest_hash", "deletion_domain_id"}},
		{"source admitted", SourceArtifactAdmittedDocObjectV2(), []string{"canonicalization_profile", "organization_id", "source_artifact_kind", "source_authority_id", "source_ref_kind", "canonical_source_stable_reference", "selected_version_coordinate", "content_hash_algorithm", "content_hash_profile", "authoritative_content_digest", "admitted_artifact_stable_id", "admitted_artifact_version", "admitted_artifact_contract_hash", "admitted_artifact_content_hash"}},
		{"source external", SourceArtifactExternalEvidenceV2(), []string{"canonicalization_profile", "organization_id", "source_artifact_kind", "source_authority_id", "source_ref_kind", "canonical_source_stable_reference", "selected_version_coordinate", "content_hash_algorithm", "content_hash_profile", "authoritative_content_digest", "evidence_identity_hash", "canonical_content_byte_length", "source_declared_completeness_relationship_hash"}},
		{"node membership", NodeMembershipEntryV2(), []string{"canonicalization_profile", "organization_id", "graph_object_id", "object_class", "api_element_role", "api_element_role_locator_manifest_hash", "object_graph_row_hash"}},
		{"edge membership", EdgeMembershipEntryV2(), []string{"canonicalization_profile", "organization_id", "graph_edge_id", "source_node_membership_entry_hash", "target_node_membership_entry_hash", "source_endpoint_id", "target_endpoint_id", "source_endpoint_class", "target_endpoint_class", "edge_label", "edge_family", "valid_from", "valid_until", "diagnostic_only", "edge_graph_row_hash"}},
		{"structural", StructuralProjectionArtifactV1(), []string{"canonicalization_profile", "organization_id", "projection_kind", "projection_target_kind", "projection_target_id", "projection_format", "canonical_projection_payload_bytes", "round_trip_state"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.p.Fields) != len(tc.fields) {
				t.Fatal("field count")
			}
			for i, n := range tc.fields {
				if tc.p.Fields[i].Name != n {
					t.Fatalf("field %d=%s", i, tc.p.Fields[i].Name)
				}
			}
		})
	}
}
func uuidValue(t *testing.T, s string) Value {
	t.Helper()
	v, e := UUIDText(s)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func digestValue(t *testing.T) Value {
	t.Helper()
	v, e := DigestHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func objectFactFixture(t *testing.T) RecordValue {
	return RecordValue{"organization_id": String("org"), "graph_object_id": uuidValue(t, "11111111-1111-4111-8111-111111111111"), "object_class": String("api_symbol"), "api_element_role": NullValue(UTF8), "api_element_role_locator_manifest_hash": NullValue(SHA256), "source_authority_id": uuidValue(t, "22222222-2222-4222-8222-222222222222"), "source_artifact_class": String("api"), "source_ref_kind": String("ref"), "source_stable_reference": String("stable"), "version_coordinate": String("v1"), "section_path": String("/x"), "graph_address": String("g"), "source_content_hash_algorithm": NullValue(UTF8), "source_content_hash_profile": NullValue(UTF8), "source_content_hash": NullValue(SHA256)}
}
func symbolFactFixture(t *testing.T) RecordValue {
	return RecordValue{"organization_id": String("org"), "symbol_id": uuidValue(t, "33333333-3333-4333-8333-333333333333"), "graph_object_id": uuidValue(t, "11111111-1111-4111-8111-111111111111"), "object_class": String("api_symbol"), "symbol_kind": String("operation"), "symbol_name": String("get"), "source_authority_id": uuidValue(t, "22222222-2222-4222-8222-222222222222"), "source_stable_reference": String("stable"), "version_coordinate": String("v1"), "section_path": String("/x"), "graph_address": String("g")}
}
func edgeFactFixture(t *testing.T) RecordValue {
	return RecordValue{"organization_id": String("org"), "graph_edge_id": uuidValue(t, "44444444-4444-4444-8444-444444444444"), "source_endpoint_kind": String("object"), "source_endpoint_id": uuidValue(t, "11111111-1111-4111-8111-111111111111"), "source_endpoint_class": String("api_symbol"), "target_endpoint_kind": String("object"), "target_endpoint_id": uuidValue(t, "33333333-3333-4333-8333-333333333333"), "target_endpoint_class": String("api_symbol"), "edge_label": String("depends_on"), "edge_family": String("dependency"), "source_version_coordinate": String("v1"), "target_version_coordinate": String("v1"), "authoring_source_path": String("/x"), "source_authority_id": uuidValue(t, "22222222-2222-4222-8222-222222222222"), "source_stable_reference": String("stable"), "source_content_hash_algorithm": NullValue(UTF8), "source_content_hash_profile": NullValue(UTF8), "source_content_hash": NullValue(SHA256), "valid_from": NullValue(TimestampMicroseconds), "valid_until": NullValue(TimestampMicroseconds), "diagnostic_only": Value{Type: Bool, Presence: Present, Bytes: []byte{0}}}
}
