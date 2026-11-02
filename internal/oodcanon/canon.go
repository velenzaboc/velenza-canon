// Package oodcanon implements the closed OOD v8 canonical field encoding.
//
// It deliberately accepts typed, ordered profiles rather than JSON or maps of
// strings.  A digest is only meaningful when the caller has selected one of
// the owner-pinned profiles (or a profile parsed from the same owner document).
package oodcanon

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	OwnerDocumentID = "767c2399-87f9-4859-ac64-afb575bdb263"
	OwnerVersion    = 10
	OwnerSHA256     = "4c898eff0792fe3647702ff3c3d99af7a87f43c3df13ce851a6ecfaabd0383a2"
)

var (
	ErrUnsupportedProfile = errors.New("oodcanon: unsupported owner profile")
	ErrInvalidRecord      = errors.New("oodcanon: invalid closed record")
)

type Type byte

const (
	UTF8                  Type = 0x01
	Bool                  Type = 0x02
	Int64                 Type = 0x03
	Uint64                Type = 0x04
	CanonicalDecimal      Type = 0x05
	TimestampMicroseconds Type = 0x06
	RawBytes              Type = 0x07
	SHA256                Type = 0x08
	UUID                  Type = 0x09
	Array                 Type = 0x0a
	Map                   Type = 0x0b
	Record                Type = 0x0c
)

type Presence byte

const (
	Null    Presence = 0x00
	Present Presence = 0x01
	Absent  Presence = 0x02
)

type PresencePolicy uint8

const (
	Required PresencePolicy = iota
	Nullable
	NullOnly
	AbsentAllowed
)

// Field is a complete owner binding. Name is the wire field name, not its
// descriptive ordered-preimage alias. Literal fields cannot be supplied.
type Field struct {
	Name    string
	Type    Type
	Policy  PresencePolicy
	Literal *Value
	Element *Field
	Nested  []Field
}
type Profile struct {
	Name   string
	Fields []Field
}
type Value struct {
	Type     Type
	Presence Presence
	Bytes    []byte
	Elements []Value
	Entries  map[string]Value
	Fields   []NamedValue
}
type NamedValue struct {
	Name  string
	Value Value
}
type RecordValue map[string]Value

func String(s string) Value { return Value{Type: UTF8, Presence: Present, Bytes: []byte(s)} }
func Bytes(b []byte) Value {
	return Value{Type: RawBytes, Presence: Present, Bytes: append([]byte(nil), b...)}
}
func DigestHex(s string) (Value, error) {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || strings.ToLower(s) != s {
		return Value{}, fmt.Errorf("%w: digest", ErrInvalidRecord)
	}
	return Value{Type: SHA256, Presence: Present, Bytes: b}, nil
}
func UUIDText(s string) (Value, error) {
	u, e := uuid.Parse(s)
	if e != nil || u.String() != s {
		return Value{}, fmt.Errorf("%w: uuid", ErrInvalidRecord)
	}
	return Value{Type: UUID, Presence: Present, Bytes: u[:]}, nil
}
func I64(n int64) Value {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n))
	return Value{Type: Int64, Presence: Present, Bytes: b}
}
func U64(n uint64) Value {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return Value{Type: Uint64, Presence: Present, Bytes: b}
}
func NullValue(t Type) Value   { return Value{Type: t, Presence: Null} }
func AbsentValue(t Type) Value { return Value{Type: t, Presence: Absent} }

// Encode returns a fresh, immutable-by-convention byte slice. It verifies the
// full closed schema before emitting a byte, including literal and container rules.
func Encode(p Profile, r RecordValue) ([]byte, error) {
	if err := validateProfile(p); err != nil {
		return nil, err
	}
	if len(r) != countSupplied(p.Fields) {
		return nil, fmt.Errorf("%w: missing or extra field", ErrInvalidRecord)
	}
	b := []byte("OODGCFE1")
	b = put32(b, uint32(len(p.Fields)))
	for _, f := range p.Fields {
		v, ok := r[f.Name]
		if f.Literal != nil {
			if ok {
				return nil, fmt.Errorf("%w: literal supplied %s", ErrInvalidRecord, f.Name)
			}
			v = *f.Literal
		} else if !ok {
			return nil, fmt.Errorf("%w: missing %s", ErrInvalidRecord, f.Name)
		}
		x, e := encodeField(f.Name, f, v)
		if e != nil {
			return nil, e
		}
		b = append(b, x...)
	}
	return b, nil
}

// EncodeNestedRecord returns the canonical value bytes for one already
// profile-bound nested record.  It deliberately accepts fields rather than a
// profile so callers cannot accidentally add a second top-level envelope when
// measuring an embedded record (for example a manifest entry).
//
// This is an encoding primitive, not an owner-profile selector: callers still
// have to obtain the ordered fields from an owner-pinned Profile.
func EncodeNestedRecord(fields []Field, values []NamedValue) ([]byte, error) {
	if len(fields) == 0 {
		return nil, fmt.Errorf("%w: empty nested record", ErrInvalidRecord)
	}
	return encodeValue(Field{Type: Record, Policy: Required, Nested: fields}, Value{Type: Record, Presence: Present, Fields: values})
}
func Digest(p Profile, r RecordValue) ([32]byte, error) {
	b, e := Encode(p, r)
	if e != nil {
		return [32]byte{}, e
	}
	return sha256.Sum256(b), nil
}
func DigestHexOf(p Profile, r RecordValue) (string, error) {
	d, e := Digest(p, r)
	if e != nil {
		return "", e
	}
	return hex.EncodeToString(d[:]), nil
}
func countSupplied(fs []Field) int {
	n := 0
	for _, f := range fs {
		if f.Literal == nil {
			n++
		}
	}
	return n
}
func validateProfile(p Profile) error {
	if p.Name == "" || len(p.Fields) == 0 {
		return fmt.Errorf("%w: empty profile", ErrInvalidRecord)
	}
	seen := map[string]bool{}
	for i, f := range p.Fields {
		if f.Name == "" || seen[f.Name] {
			return fmt.Errorf("%w: duplicate/empty profile field", ErrInvalidRecord)
		}
		seen[f.Name] = true
		if i == 0 && (f.Type != UTF8 || f.Policy != Required || f.Literal == nil || len(f.Literal.Bytes) == 0) {
			return fmt.Errorf("%w: profile domain must be first required literal", ErrInvalidRecord)
		}
		if f.Type == Array && f.Element == nil {
			return fmt.Errorf("%w: array element binding", ErrInvalidRecord)
		}
		if f.Type == Record && len(f.Nested) == 0 {
			return fmt.Errorf("%w: record binding", ErrInvalidRecord)
		}
	}
	return nil
}
func encodeField(name string, f Field, v Value) ([]byte, error) {
	if v.Type != f.Type {
		return nil, fmt.Errorf("%w: type %s", ErrInvalidRecord, name)
	}
	if (f.Policy == Required && v.Presence != Present) || (f.Policy == Nullable && v.Presence == Absent) || (f.Policy == NullOnly && v.Presence != Null) || (f.Policy == AbsentAllowed && v.Presence != Absent && v.Presence != Present) {
		return nil, fmt.Errorf("%w: presence %s", ErrInvalidRecord, name)
	}
	x, e := encodeValue(f, v)
	if e != nil {
		return nil, e
	}
	b := put32(nil, uint32(len([]byte(name))))
	b = append(b, []byte(name)...)
	b = append(b, byte(f.Type), byte(v.Presence))
	b = put64(b, uint64(len(x)))
	return append(b, x...), nil
}
func encodeValue(f Field, v Value) ([]byte, error) {
	if v.Presence != Present {
		if len(v.Bytes) > 0 || len(v.Elements) > 0 || len(v.Entries) > 0 || len(v.Fields) > 0 {
			return nil, fmt.Errorf("%w: nonempty nonpresent", ErrInvalidRecord)
		}
		return nil, nil
	}
	switch f.Type {
	case UTF8:
		if !utf8.Valid(v.Bytes) || strings.HasPrefix(string(v.Bytes), "\ufeff") {
			return nil, fmt.Errorf("%w: utf8", ErrInvalidRecord)
		}
	case Bool:
		if len(v.Bytes) != 1 || (v.Bytes[0] != 0 && v.Bytes[0] != 1) {
			return nil, fmt.Errorf("%w: bool", ErrInvalidRecord)
		}
	case Int64, Uint64, TimestampMicroseconds:
		if len(v.Bytes) != 8 {
			return nil, fmt.Errorf("%w: integer", ErrInvalidRecord)
		}
	case SHA256:
		if len(v.Bytes) != 32 {
			return nil, fmt.Errorf("%w: digest", ErrInvalidRecord)
		}
	case UUID:
		if len(v.Bytes) != 16 {
			return nil, fmt.Errorf("%w: uuid", ErrInvalidRecord)
		}
	case RawBytes:
	case CanonicalDecimal:
		if !decimalRE.Match(v.Bytes) {
			return nil, fmt.Errorf("%w: decimal", ErrInvalidRecord)
		}
	case Array:
		b := put32(nil, uint32(len(v.Elements)))
		for _, e := range v.Elements {
			x, er := encodeElement(*f.Element, e)
			if er != nil {
				return nil, er
			}
			b = append(b, x...)
		}
		return b, nil
	case Map:
		if f.Element == nil {
			return nil, fmt.Errorf("%w: map element binding", ErrInvalidRecord)
		}
		keys := make([]string, 0, len(v.Entries))
		for k := range v.Entries {
			if !utf8.ValidString(k) {
				return nil, fmt.Errorf("%w: map key", ErrInvalidRecord)
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		b := put32(nil, uint32(len(keys)))
		for _, k := range keys {
			b = put32(b, uint32(len(k)))
			b = append(b, k...)
			x, e := encodeElement(*f.Element, v.Entries[k])
			if e != nil {
				return nil, e
			}
			b = append(b, x...)
		}
		return b, nil
	case Record:
		b := put32(nil, uint32(len(f.Nested)))
		if len(v.Fields) != len(f.Nested) {
			return nil, fmt.Errorf("%w: nested count", ErrInvalidRecord)
		}
		for i, n := range v.Fields {
			if n.Name != f.Nested[i].Name {
				return nil, fmt.Errorf("%w: nested order", ErrInvalidRecord)
			}
			x, e := encodeField(n.Name, f.Nested[i], n.Value)
			if e != nil {
				return nil, e
			}
			b = append(b, x...)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("%w: unsupported type", ErrInvalidRecord)
	}
	return append([]byte(nil), v.Bytes...), nil
}
func encodeElement(f Field, v Value) ([]byte, error) {
	if v.Type != f.Type {
		return nil, fmt.Errorf("%w: element type", ErrInvalidRecord)
	}
	if (f.Policy == Required && v.Presence != Present) || (f.Policy == Nullable && v.Presence == Absent) || (f.Policy == NullOnly && v.Presence != Null) || (f.Policy == AbsentAllowed && v.Presence != Absent && v.Presence != Present) {
		return nil, fmt.Errorf("%w: element presence", ErrInvalidRecord)
	}
	x, e := encodeValue(f, v)
	if e != nil {
		return nil, e
	}
	b := []byte{byte(v.Type), byte(v.Presence)}
	b = put64(b, uint64(len(x)))
	return append(b, x...), nil
}

var decimalRE = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$`)

func put32(b []byte, n uint32) []byte {
	x := make([]byte, 4)
	binary.BigEndian.PutUint32(x, n)
	return append(b, x...)
}
func put64(b []byte, n uint64) []byte {
	x := make([]byte, 8)
	binary.BigEndian.PutUint64(x, n)
	return append(b, x...)
}
