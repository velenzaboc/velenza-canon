package oodpublication

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

type testPropertySchemaResolver struct {
	schema AdmittedAPIPropertyPayloadSchema
}

func (r testPropertySchemaResolver) ResolveAPIPropertyPayloadSchema(_ context.Context, id, version, digest, profile string) (AdmittedAPIPropertyPayloadSchema, error) {
	if id != r.schema.ArtifactID || version != r.schema.Version || digest != r.schema.Digest || profile != r.schema.Profile {
		return AdmittedAPIPropertyPayloadSchema{}, errPropertySchema
	}
	return r.schema, nil
}

type propertySchemaError struct{}

func (propertySchemaError) Error() string { return "schema coordinate mismatch" }

var errPropertySchema error = propertySchemaError{}

func TestCanonicalAPIPropertyPayloadHashUsesAdmittedTypedSchema(t *testing.T) {
	schema := AdmittedAPIPropertyPayloadSchema{ArtifactID: "11111111-1111-4111-8111-111111111111", Version: "v1", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Profile: "test_api_property_payload_v1", Fields: []APIPropertyPayloadField{{Name: "name", Type: oodcanon.UTF8}, {Name: "limit", Type: oodcanon.Int64}, {Name: "optional", Type: oodcanon.UTF8, Nullable: true}}}
	a, err := CanonicalAPIPropertyPayloadHash(schema, CanonicalJSON(`{"limit":7,"name":"x","optional":null}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalAPIPropertyPayloadHash(schema, CanonicalJSON(`{"limit":8,"name":"x","optional":null}`))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("typed payload change retained canonical hash")
	}
	for _, bad := range []CanonicalJSON{CanonicalJSON(`{"name":"x","limit":7}`), CanonicalJSON(`{"name":"x","limit":7,"optional":null,"extra":true}`), CanonicalJSON(`{"name":"x","name":"y","limit":7,"optional":null}`), CanonicalJSON(`{"name":"x","limit":7.0,"optional":null}`), CanonicalJSON(` {"name":"x","limit":7,"optional":null}`)} {
		if _, err := CanonicalAPIPropertyPayloadHash(schema, bad); err == nil {
			t.Fatalf("invalid payload accepted: %s", bad)
		}
	}
}

func TestManifestMemberVerifierRecomputesAPIPropertyPayloadAndFact(t *testing.T) {
	schema := AdmittedAPIPropertyPayloadSchema{ArtifactID: "11111111-1111-4111-8111-111111111111", Version: "v1", Digest: strings.Repeat("a", 64), Profile: "test_api_property_payload_v1", Fields: []APIPropertyPayloadField{{Name: "name", Type: oodcanon.UTF8}}}
	row := testAPIPropertyRow(schema, CanonicalJSON(`{"name":"x"}`))
	h, err := CanonicalAPIPropertyPayloadHash(schema, row.Columns["property_payload"].(CanonicalJSON))
	if err != nil {
		t.Fatal(err)
	}
	row.Columns["property_payload_hash"] = h
	v := ManifestMemberVerifier{PropertyPayloadSchemas: testPropertySchemaResolver{schema}}
	if _, err := v.CanonicalMemberDigestFromPhysicalRow(context.Background(), row); err != nil {
		t.Fatal(err)
	}
	row.Columns["property_payload"] = CanonicalJSON(`{"name":"y"}`)
	if _, err := v.CanonicalMemberDigestFromPhysicalRow(context.Background(), row); err == nil {
		t.Fatal("payload substitution retaining stored hash accepted")
	}
}

func TestCanonicalAPIPropertyPayloadHashSupportsBoundedRecursiveBindings(t *testing.T) {
	text := APIPropertyPayloadField{Type: oodcanon.UTF8}
	schema := AdmittedAPIPropertyPayloadSchema{Profile: "nested_v1", Fields: []APIPropertyPayloadField{{Name: "items", Type: oodcanon.Array, Element: &APIPropertyPayloadField{Type: oodcanon.Record, Fields: []APIPropertyPayloadField{{Name: "name", Type: oodcanon.UTF8}, {Name: "tags", Type: oodcanon.Map, Element: &text, MaxItems: 2}}}, MaxItems: 2}}}
	if _, err := CanonicalAPIPropertyPayloadHash(schema, CanonicalJSON(`{"items":[{"name":"x","tags":{"a":"b"}}]}`)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []CanonicalJSON{CanonicalJSON(`{"items":[{"name":"x","tags":{"a":"b","c":"d","e":"f"}}]}`), CanonicalJSON(`{"items":[{"name":"x","name":"y","tags":{}}]}`), CanonicalJSON(`{"items":[{"name":"x","tags":{}},{"name":"y","tags":{}},{"name":"z","tags":{}}]}`)} {
		if _, err := CanonicalAPIPropertyPayloadHash(schema, raw); err == nil {
			t.Fatalf("hostile nested payload accepted: %s", raw)
		}
	}
	bad := schema
	bad.Fields[0].Element = &APIPropertyPayloadField{Type: oodcanon.Record, Fields: []APIPropertyPayloadField{{Name: "x", Type: oodcanon.UTF8}, {Name: "x", Type: oodcanon.UTF8}}}
	if _, err := CanonicalAPIPropertyPayloadHash(bad, CanonicalJSON(`{"items":[{"x":"a"}]}`)); err == nil {
		t.Fatal("duplicate nested schema field accepted")
	}
	nullElement := AdmittedAPIPropertyPayloadSchema{Profile: "null_element_v1", Fields: []APIPropertyPayloadField{{Name: "xs", Type: oodcanon.Array, Element: &APIPropertyPayloadField{Type: oodcanon.UTF8}}}}
	if _, err := CanonicalAPIPropertyPayloadHash(nullElement, CanonicalJSON(`{"xs":[null]}`)); err == nil {
		t.Fatal("required array null element accepted")
	}
}

func TestCanonicalAPIPropertyPayloadHashTimestampMicroseconds(t *testing.T) {
	s := AdmittedAPIPropertyPayloadSchema{Profile: "timestamp_v1", Fields: []APIPropertyPayloadField{{Name: "at", Type: oodcanon.TimestampMicroseconds}}}
	if _, err := CanonicalAPIPropertyPayloadHash(s, CanonicalJSON(`{"at":1700000000123456}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := CanonicalAPIPropertyPayloadHash(s, CanonicalJSON(`{"at":1700000000123456.0}`)); err == nil {
		t.Fatal("noncanonical timestamp accepted")
	}
}

func testAPIPropertyRow(schema AdmittedAPIPropertyPayloadSchema, payload CanonicalJSON) SpannerRow {
	c := immutablePhysicalContracts["OODGraphAPIPropertyFacts"]
	cols := map[string]interface{}{}
	for _, name := range c.columns {
		switch {
		case name == "organization_id":
			cols[name] = "org"
		case name == "property_schema_artifact_id":
			cols[name] = schema.ArtifactID
		case name == "property_schema_version":
			cols[name] = schema.Version
		case name == "property_schema_digest":
			cols[name] = schema.Digest
		case name == "property_payload_profile":
			cols[name] = schema.Profile
		case name == "property_payload":
			cols[name] = payload
		case name == "property_payload_hash":
			cols[name] = strings.Repeat("b", 64)
		case nullablePhysicalColumn("OODGraphAPIPropertyFacts", name):
			cols[name] = nil
		case physicalUUIDColumn("", name):
			cols[name] = "22222222-2222-4222-8222-222222222222"
		case physicalDigestColumn("", name):
			cols[name] = strings.Repeat("a", 64)
		case physicalColumnType("OODGraphAPIPropertyFacts", name) == physicalTimestamp:
			cols[name] = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		default:
			cols[name] = "x"
		}
	}
	return SpannerRow{Table: "OODGraphAPIPropertyFacts", KeyColumns: append([]string(nil), c.keys...), Columns: cols}
}
