package oodpublication

// Canonical API-property payload ownership.  A property row's stored payload
// hash is a claim; the admitted schema resolver selects the closed typed
// encoding and this package recomputes the claim from the exact JSON bytes.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

type APIPropertyPayloadField struct {
	Name             string
	Type             oodcanon.Type
	Nullable         bool
	Element          *APIPropertyPayloadField  // Array element or Map value.
	Fields           []APIPropertyPayloadField // Ordered Record fields.
	MaxItems         int
	RawBytesEncoding string // canonical_base64 or lowercase_hex
}
type AdmittedAPIPropertyPayloadSchema struct {
	ArtifactID, Version, Digest, Profile string
	Fields                               []APIPropertyPayloadField
}

// APIPropertyPayloadSchemaResolver is boot-owned admission/currentness
// authority. It returns the exact schema selected for an already persisted
// row coordinate; it is not a caller boolean or caller-provided digest.
type APIPropertyPayloadSchemaResolver interface {
	ResolveAPIPropertyPayloadSchema(context.Context, string, string, string, string) (AdmittedAPIPropertyPayloadSchema, error)
}

type ManifestMemberVerifier struct {
	PropertyPayloadSchemas APIPropertyPayloadSchemaResolver
}

func (v ManifestMemberVerifier) CanonicalMemberDigestFromPhysicalRow(ctx context.Context, row SpannerRow) (string, error) {
	if row.Table != "OODGraphAPIPropertyFacts" {
		return CanonicalMemberDigestFromPhysicalRow(row)
	}
	if v.PropertyPayloadSchemas == nil {
		return "", errors.New("API property member requires admitted payload-schema validator")
	}
	return apiPropertyMemberDigest(ctx, row, v.PropertyPayloadSchemas)
}

func apiPropertyMemberDigest(ctx context.Context, row SpannerRow, resolver APIPropertyPayloadSchemaResolver) (string, error) {
	if ctx == nil {
		return "", errors.New("property member requires context")
	}
	if _, err := BuildImmutableRow(row.Table, row.Columns); err != nil {
		return "", err
	}
	id, ok := row.Columns["property_schema_artifact_id"].(string)
	if !ok {
		return "", errors.New("property schema artifact id absent")
	}
	version, ok := row.Columns["property_schema_version"].(string)
	if !ok {
		return "", errors.New("property schema version absent")
	}
	digest, ok := row.Columns["property_schema_digest"].(string)
	if !ok {
		return "", errors.New("property schema digest absent")
	}
	profile, ok := row.Columns["property_payload_profile"].(string)
	if !ok {
		return "", errors.New("property payload profile absent")
	}
	schema, err := resolver.ResolveAPIPropertyPayloadSchema(ctx, id, version, digest, profile)
	if err != nil {
		return "", fmt.Errorf("resolve admitted property payload schema: %w", err)
	}
	if schema.ArtifactID != id || schema.Version != version || schema.Digest != digest || schema.Profile != profile || len(schema.Fields) == 0 {
		return "", errors.New("admitted property payload schema identity mismatch")
	}
	payload, ok := row.Columns["property_payload"].(CanonicalJSON)
	if !ok {
		return "", errors.New("property payload is not canonical JSON")
	}
	h, err := CanonicalAPIPropertyPayloadHash(schema, payload)
	if err != nil {
		return "", err
	}
	if h != row.Columns["property_payload_hash"] {
		return "", errors.New("property payload hash mismatch")
	}
	return apiPropertyFactDigest(row)
}

func CanonicalAPIPropertyPayloadHash(schema AdmittedAPIPropertyPayloadSchema, payload CanonicalJSON) (string, error) {
	var compact bytes.Buffer
	if !json.Valid(payload) || json.Compact(&compact, payload) != nil || !bytes.Equal(compact.Bytes(), payload) {
		return "", errors.New("property payload is not compact canonical JSON")
	}
	raw, err := decodeClosedJSONObject(payload)
	if err != nil {
		return "", err
	}
	if len(raw) != len(schema.Fields) {
		return "", errors.New("property payload has missing or extra fields")
	}
	p := oodcanon.Profile{Name: schema.Profile, Fields: []oodcanon.Field{}}
	// The owner-selected profile is pinned as the first literal field, exactly
	// as required by the shared closed encoder.
	p.Fields = append(p.Fields, oodcanon.Field{Name: "canonicalization_profile", Type: oodcanon.UTF8, Policy: oodcanon.Required, Literal: ptrValue(oodcanon.String(schema.Profile))})
	r := oodcanon.RecordValue{}
	seen := map[string]bool{}
	for _, f := range schema.Fields {
		if f.Name == "" || seen[f.Name] {
			return "", errors.New("admitted property schema has duplicate field")
		}
		seen[f.Name] = true
		policy := oodcanon.Required
		if f.Nullable {
			policy = oodcanon.Nullable
		}
		cf, err := canonicalPayloadField(f, policy)
		if err != nil {
			return "", err
		}
		p.Fields = append(p.Fields, cf)
		x, exists := raw[f.Name]
		if !exists {
			return "", fmt.Errorf("property payload missing %s", f.Name)
		}
		v, err := propertyJSONField(f, x, 0)
		if err != nil {
			return "", fmt.Errorf("property payload %s: %w", f.Name, err)
		}
		r[f.Name] = v
	}
	return oodcanon.DigestHexOf(p, r)
}
func canonicalPayloadField(f APIPropertyPayloadField, policy oodcanon.PresencePolicy) (oodcanon.Field, error) {
	x := oodcanon.Field{Name: f.Name, Type: f.Type, Policy: policy}
	if f.Type == oodcanon.Array || f.Type == oodcanon.Map {
		if f.Element == nil {
			return x, errors.New("container element schema absent")
		}
		ep := oodcanon.Required
		if f.Element.Nullable {
			ep = oodcanon.Nullable
		}
		e, er := canonicalPayloadField(*f.Element, ep)
		if er != nil {
			return x, er
		}
		x.Element = &e
	}
	if f.Type == oodcanon.Record {
		seen := map[string]bool{}
		for _, n := range f.Fields {
			if n.Name == "" || seen[n.Name] {
				return x, errors.New("property record schema has duplicate or empty field")
			}
			seen[n.Name] = true
			p := oodcanon.Required
			if n.Nullable {
				p = oodcanon.Nullable
			}
			e, er := canonicalPayloadField(n, p)
			if er != nil {
				return x, er
			}
			x.Nested = append(x.Nested, e)
		}
	}
	return x, nil
}

func decodeClosedJSONObject(payload []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(payload))
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	if t != json.Delim('{') {
		return nil, errors.New("property payload is not an object")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok || name == "" {
			return nil, errors.New("property payload field name invalid")
		}
		if _, duplicate := out[name]; duplicate {
			return nil, errors.New("property payload has duplicate field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		out[name] = value
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return nil, errors.New("property payload object malformed")
	}
	if d.More() {
		return nil, errors.New("property payload has trailing value")
	}
	return out, nil
}
func decodeJSONArray(payload []byte) ([]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(payload))
	t, e := d.Token()
	if e != nil || t != json.Delim('[') {
		return nil, errors.New("property payload is not an array")
	}
	out := []json.RawMessage{}
	for d.More() {
		var x json.RawMessage
		if e := d.Decode(&x); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	if t, e = d.Token(); e != nil || t != json.Delim(']') {
		return nil, errors.New("property array malformed")
	}
	return out, nil
}
func ptrValue(v oodcanon.Value) *oodcanon.Value { return &v }

const maxPropertyPayloadDepth = 32

func propertyJSONField(f APIPropertyPayloadField, raw json.RawMessage, depth int) (oodcanon.Value, error) {
	if depth > maxPropertyPayloadDepth {
		return oodcanon.Value{}, errors.New("property payload nesting exceeds limit")
	}
	t, nullable := f.Type, f.Nullable
	if string(raw) == "null" {
		if nullable {
			return oodcanon.NullValue(t), nil
		}
		return oodcanon.Value{}, errors.New("required value null")
	}
	s := string(raw)
	switch t {
	case oodcanon.UTF8:
		var x string
		if json.Unmarshal(raw, &x) != nil || strings.HasPrefix(x, "\ufeff") {
			return oodcanon.Value{}, errors.New("not canonical string")
		}
		return oodcanon.String(x), nil
	case oodcanon.Bool:
		var x bool
		if json.Unmarshal(raw, &x) != nil {
			return oodcanon.Value{}, errors.New("not bool")
		}
		if x {
			return oodcanon.Value{Type: t, Presence: oodcanon.Present, Bytes: []byte{1}}, nil
		}
		return oodcanon.Value{Type: t, Presence: oodcanon.Present, Bytes: []byte{0}}, nil
	case oodcanon.Int64, oodcanon.TimestampMicroseconds:
		var n json.Number
		if json.Unmarshal(raw, &n) != nil {
			return oodcanon.Value{}, errors.New("not integer")
		}
		x, e := strconv.ParseInt(n.String(), 10, 64)
		if e != nil || strconv.FormatInt(x, 10) != n.String() {
			return oodcanon.Value{}, errors.New("not canonical int64")
		}
		v := oodcanon.I64(x)
		v.Type = t
		return v, nil
	case oodcanon.CanonicalDecimal:
		var n json.Number
		if json.Unmarshal(raw, &n) != nil || n.String() != s {
			return oodcanon.Value{}, errors.New("not decimal")
		}
		return oodcanon.Value{Type: t, Presence: oodcanon.Present, Bytes: []byte(s)}, nil
	case oodcanon.SHA256:
		var x string
		if json.Unmarshal(raw, &x) != nil {
			return oodcanon.Value{}, errors.New("not digest")
		}
		return oodcanon.DigestHex(x)
	case oodcanon.UUID:
		var x string
		if json.Unmarshal(raw, &x) != nil {
			return oodcanon.Value{}, errors.New("not uuid")
		}
		return oodcanon.UUIDText(x)
	case oodcanon.RawBytes:
		var x string
		if json.Unmarshal(raw, &x) != nil {
			return oodcanon.Value{}, errors.New("not encoded bytes")
		}
		var b []byte
		var err error
		switch f.RawBytesEncoding {
		case "canonical_base64":
			b, err = base64.StdEncoding.DecodeString(x)
			if err == nil && base64.StdEncoding.EncodeToString(b) != x {
				err = errors.New("noncanonical base64")
			}
		case "lowercase_hex":
			b, err = hex.DecodeString(x)
			if err == nil && hex.EncodeToString(b) != x {
				err = errors.New("noncanonical hex")
			}
		default:
			err = errors.New("raw bytes encoding unadmitted")
		}
		if err != nil {
			return oodcanon.Value{}, err
		}
		return oodcanon.Bytes(b), nil
	case oodcanon.Array:
		if f.Element == nil {
			return oodcanon.Value{}, errors.New("array element schema absent")
		}
		vals, err := decodeJSONArray(raw)
		if err != nil {
			return oodcanon.Value{}, err
		}
		if f.MaxItems > 0 && len(vals) > f.MaxItems {
			return oodcanon.Value{}, errors.New("array exceeds bound")
		}
		out := make([]oodcanon.Value, len(vals))
		for i := range vals {
			out[i], err = propertyJSONField(*f.Element, vals[i], depth+1)
			if err != nil {
				return oodcanon.Value{}, err
			}
		}
		return oodcanon.Value{Type: t, Presence: oodcanon.Present, Elements: out}, nil
	case oodcanon.Record:
		m, err := decodeClosedJSONObject(raw)
		if err != nil {
			return oodcanon.Value{}, err
		}
		if len(m) != len(f.Fields) {
			return oodcanon.Value{}, errors.New("record has missing or extra fields")
		}
		out := make([]oodcanon.NamedValue, len(f.Fields))
		for i, n := range f.Fields {
			x, ok := m[n.Name]
			if !ok {
				return oodcanon.Value{}, errors.New("record field absent")
			}
			v, e := propertyJSONField(n, x, depth+1)
			if e != nil {
				return oodcanon.Value{}, e
			}
			out[i] = oodcanon.NamedValue{Name: n.Name, Value: v}
		}
		return oodcanon.Value{Type: t, Presence: oodcanon.Present, Fields: out}, nil
	case oodcanon.Map:
		if f.Element == nil {
			return oodcanon.Value{}, errors.New("map value schema absent")
		}
		m, err := decodeClosedJSONObject(raw)
		if err != nil {
			return oodcanon.Value{}, err
		}
		if f.MaxItems > 0 && len(m) > f.MaxItems {
			return oodcanon.Value{}, errors.New("map exceeds bound")
		}
		out := map[string]oodcanon.Value{}
		for k, x := range m {
			v, e := propertyJSONField(*f.Element, x, depth+1)
			if e != nil {
				return oodcanon.Value{}, e
			}
			out[k] = v
		}
		return oodcanon.Value{Type: t, Presence: oodcanon.Present, Entries: out}, nil
	default:
		return oodcanon.Value{}, errors.New("unadmitted property payload type")
	}
}

func apiPropertyFactDigest(row SpannerRow) (string, error) {
	p := oodcanon.APIPropertyFactV1()
	r := oodcanon.RecordValue{}
	for _, f := range p.Fields {
		if f.Literal != nil {
			continue
		}
		v, err := physicalOwnerValue(f, row.Columns[f.Name])
		if err != nil {
			return "", fmt.Errorf("property fact %s: %w", f.Name, err)
		}
		r[f.Name] = v
	}
	return oodcanon.DigestHexOf(p, r)
}
