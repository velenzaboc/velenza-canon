package oodcanon

// OOD secondary-index profiles. These hashes are physical accelerators, but
// their exact preimages are still owner-defined and must be recomputed before
// an immutable row is inserted or reused.

import "fmt"

func GraphAddressIndexHashV1(table, organizationID, graphAddress string) (string, error) {
	d, err := indexDiscriminator(table, "object", "symbol")
	if err != nil {
		return "", err
	}
	return indexDigest("graph_address_index_hash_v1", d, []indexField{{"organization_id", UTF8, organizationID}, {"graph_address", UTF8, graphAddress}})
}
func SourceStableReferenceIndexHashV1(table, organizationID, reference string) (string, error) {
	d, err := indexDiscriminator(table, "object", "relationship_evidence")
	if err != nil {
		return "", err
	}
	return indexDigest("source_stable_reference_index_hash_v1", d, []indexField{{"organization_id", UTF8, organizationID}, {"source_stable_reference", UTF8, reference}})
}
func ObjectIdentityTupleIndexHashV1(org, objectClass, authorityID, refKind, reference, version, section string) (string, error) {
	return indexDigest("identity_tuple_index_hash_v1", "object", []indexField{{"organization_id", UTF8, org}, {"object_class", UTF8, objectClass}, {"source_authority_id", UUID, authorityID}, {"source_ref_kind", UTF8, refKind}, {"source_stable_reference", UTF8, reference}, {"version_coordinate", UTF8, version}, {"section_path", UTF8, section}})
}
func SymbolIdentityTupleIndexHashV1(org, objectClass, authorityID, reference, version, section, kind, name string) (string, error) {
	return indexDigest("identity_tuple_index_hash_v1", "symbol", []indexField{{"organization_id", UTF8, org}, {"object_class", UTF8, objectClass}, {"source_authority_id", UUID, authorityID}, {"source_stable_reference", UTF8, reference}, {"version_coordinate", UTF8, version}, {"section_path", UTF8, section}, {"symbol_kind", UTF8, kind}, {"symbol_name", UTF8, name}})
}
func EdgeIdentityTupleIndexHashV1(org, sourceKind, sourceID, targetKind, targetID, label, sourceVersion, targetVersion, path, authorityID, reference string) (string, error) {
	return indexDigest("identity_tuple_index_hash_v1", "edge", []indexField{{"organization_id", UTF8, org}, {"source_endpoint_kind", UTF8, sourceKind}, {"source_endpoint_id", UUID, sourceID}, {"target_endpoint_kind", UTF8, targetKind}, {"target_endpoint_id", UUID, targetID}, {"edge_label", UTF8, label}, {"source_version_coordinate", UTF8, sourceVersion}, {"target_version_coordinate", UTF8, targetVersion}, {"authoring_source_path", UTF8, path}, {"source_authority_id", UUID, authorityID}, {"source_stable_reference", UTF8, reference}})
}

type indexField struct {
	name string
	typ  Type
	raw  string
}

func indexDiscriminator(table string, allowed ...string) (string, error) {
	for _, x := range allowed {
		if table == x {
			return table, nil
		}
	}
	return "", fmt.Errorf("unsupported OOD index table discriminator %q", table)
}
func indexDigest(profile, discriminator string, fields []indexField) (string, error) {
	p := Profile{Name: profile, Fields: []Field{{Name: "profile", Type: UTF8, Policy: Required, Literal: ptr(String(profile))}, {Name: "table_discriminator", Type: UTF8, Policy: Required, Literal: ptr(String(discriminator))}}}
	r := RecordValue{}
	for _, x := range fields {
		p.Fields = append(p.Fields, Field{Name: x.name, Type: x.typ, Policy: Required})
		var v Value
		var e error
		if x.typ == UUID {
			v, e = UUIDText(x.raw)
		} else {
			v = String(x.raw)
		}
		if e != nil {
			return "", e
		}
		r[x.name] = v
	}
	return DigestHexOf(p, r)
}
func ptr(v Value) *Value { return &v }
