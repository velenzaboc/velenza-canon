package oodpublication

// Closed OODGraphViolations manifest-member codec. Evidence is deliberately
// parsed from its raw JSON bytes rather than through map[string]any: duplicate
// keys and JSON numbers must be rejected before RFC-8785 canonicalization.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodcanon"
)

// CanonicalViolationMemberDigest recomputes the non-stored manifest hash from
// the exact immutable identity tuple and the closed canonical evidence bytes.
func CanonicalViolationMemberDigest(input SpannerRow) (string, error) {
	if input.Table != "OODGraphViolations" {
		return "", fmt.Errorf("%w: violation table required", ErrImmutablePhysicalRow)
	}
	immutable, err := BuildImmutableRow(input.Table, input.Columns)
	if err != nil {
		return "", err
	}
	v := immutable.Row().Columns
	evidence, err := CanonicalViolationEvidenceBytes(v["evidence"].(CanonicalJSON))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(evidence)
	digest := oodcanon.RecordValue{
		"organization_id": oodcanon.String(v["organization_id"].(string)), "violation_id": mustUUID(v["violation_id"].(string)),
		"graph_snapshot_id": nullableUUID(v["graph_snapshot_id"]), "materialization_run_id": nullableUUID(v["materialization_run_id"]),
		"violation_code": oodcanon.String(v["violation_code"].(string)), "sentinel_candidate": nullableText(v["sentinel_candidate"]), "severity": oodcanon.String(v["severity"].(string)),
		"source_authority_id": nullableUUID(v["source_authority_id"]), "source_stable_reference": nullableText(v["source_stable_reference"]), "version_coordinate": nullableText(v["version_coordinate"]), "section_path": nullableText(v["section_path"]),
		"graph_object_id": nullableUUID(v["graph_object_id"]), "symbol_id": nullableUUID(v["symbol_id"]), "graph_edge_id": nullableUUID(v["graph_edge_id"]),
		"evidence_sha256": oodcanon.Value{Type: oodcanon.SHA256, Presence: oodcanon.Present, Bytes: sum[:]},
	}
	return oodcanon.DigestHexOf(oodcanon.ViolationManifestMemberV1(), digest)
}

func mustUUID(s string) oodcanon.Value {
	v, err := oodcanon.UUIDText(s)
	if err != nil {
		// BuildImmutableRow has already enforced this physical UUID field; a
		// failure here would be an internal invariant violation, never input.
		panic(err)
	}
	return v
}
func nullableUUID(x interface{}) oodcanon.Value {
	if x == nil {
		return oodcanon.NullValue(oodcanon.UUID)
	}
	return mustUUID(x.(string))
}
func nullableText(x interface{}) oodcanon.Value {
	if x == nil {
		return oodcanon.NullValue(oodcanon.UTF8)
	}
	return oodcanon.String(x.(string))
}

// CanonicalViolationEvidenceBytes validates the owner-pinned evidence grammar
// and returns its exact RFC-8785 JSON Canonicalization Scheme UTF-8 bytes.
func CanonicalViolationEvidenceBytes(raw CanonicalJSON) ([]byte, error) {
	if len(raw) == 0 || len(raw) > 1048576 || !utf8.Valid(raw) {
		return nil, errors.New("violation evidence byte length")
	}
	p := jsonParser{b: raw}
	x, err := p.value()
	p.skip()
	if err == nil && p.i != len(p.b) {
		err = errors.New("trailing JSON")
	}
	if err != nil {
		return nil, fmt.Errorf("invalid violation evidence: %w", err)
	}
	if err := validateEvidence(x); err != nil {
		return nil, err
	}
	return x.jcs(nil), nil
}

// ViolationGraphFactLocatorManifestRoots resolves only the owner-declared
// typed references. Digests and redacted diagnostics never imply a graph link.
func ViolationGraphFactLocatorManifestRoots(raw CanonicalJSON) ([]string, error) {
	canonical, err := CanonicalViolationEvidenceBytes(raw)
	if err != nil {
		return nil, err
	}
	p := jsonParser{b: canonical}
	x, err := p.value()
	if err != nil {
		return nil, err
	}
	var roots []string
	for _, member := range x.obj {
		if member.key != "references" {
			continue
		}
		for _, ref := range member.value.arr {
			var kind, value string
			for _, field := range ref.obj {
				if field.key == "ref_kind" {
					kind = field.value.s
				}
				if field.key == "ref_value" {
					value = field.value.s
				}
			}
			if kind == "graph_fact_locator_manifest_ref" {
				roots = append(roots, value)
			}
		}
	}
	return roots, nil
}

type jsonValue struct {
	kind byte
	s    string
	b    bool
	obj  []jsonMember
	arr  []jsonValue
}
type jsonMember struct {
	key   string
	value jsonValue
}
type jsonParser struct {
	b []byte
	i int
}

func (p *jsonParser) skip() {
	for p.i < len(p.b) && (p.b[p.i] == ' ' || p.b[p.i] == '\n' || p.b[p.i] == '\r' || p.b[p.i] == '\t') {
		p.i++
	}
}
func (p *jsonParser) value() (jsonValue, error) {
	p.skip()
	if p.i == len(p.b) {
		return jsonValue{}, errors.New("unexpected EOF")
	}
	switch p.b[p.i] {
	case '{':
		return p.object()
	case '[':
		return p.array()
	case '"':
		s, e := p.string()
		return jsonValue{kind: 's', s: s}, e
	case 't':
		if p.token("true") {
			return jsonValue{kind: 'b', b: true}, nil
		}
	case 'f':
		if p.token("false") {
			return jsonValue{kind: 'b'}, nil
		}
	case 'n':
		return jsonValue{}, errors.New("null forbidden")
	}
	return jsonValue{}, errors.New("numbers and unknown JSON values forbidden")
}
func (p *jsonParser) token(s string) bool {
	if strings.HasPrefix(string(p.b[p.i:]), s) {
		p.i += len(s)
		return true
	}
	return false
}
func (p *jsonParser) string() (string, error) {
	start := p.i
	p.i++
	esc := false
	for p.i < len(p.b) {
		c := p.b[p.i]
		if c < 0x20 {
			return "", errors.New("control in string")
		}
		p.i++
		if esc {
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '"' {
			if !validJSONSurrogates(p.b[start:p.i]) {
				return "", errors.New("unpaired UTF-16 surrogate")
			}
			var s string
			if err := json.Unmarshal(p.b[start:p.i], &s); err != nil || !utf8.ValidString(s) || strings.HasPrefix(s, "\ufeff") {
				return "", errors.New("invalid string")
			}
			return s, nil
		}
	}
	return "", errors.New("unterminated string")
}
func (p *jsonParser) object() (jsonValue, error) {
	p.i++
	x := jsonValue{kind: 'o'}
	seen := map[string]bool{}
	p.skip()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return x, nil
	}
	for {
		p.skip()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return x, errors.New("object key")
		}
		k, e := p.string()
		if e != nil || seen[k] {
			return x, errors.New("duplicate/invalid object key")
		}
		seen[k] = true
		p.skip()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return x, errors.New("object colon")
		}
		p.i++
		v, e := p.value()
		if e != nil {
			return x, e
		}
		x.obj = append(x.obj, jsonMember{k, v})
		p.skip()
		if p.i >= len(p.b) {
			return x, errors.New("object EOF")
		}
		if p.b[p.i] == '}' {
			p.i++
			return x, nil
		}
		if p.b[p.i] != ',' {
			return x, errors.New("object separator")
		}
		p.i++
	}
}
func (p *jsonParser) array() (jsonValue, error) {
	p.i++
	x := jsonValue{kind: 'a'}
	p.skip()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return x, nil
	}
	for {
		v, e := p.value()
		if e != nil {
			return x, e
		}
		x.arr = append(x.arr, v)
		p.skip()
		if p.i >= len(p.b) {
			return x, errors.New("array EOF")
		}
		if p.b[p.i] == ']' {
			p.i++
			return x, nil
		}
		if p.b[p.i] != ',' {
			return x, errors.New("array separator")
		}
		p.i++
	}
}
func (x jsonValue) jcs(out []byte) []byte {
	switch x.kind {
	case 's':
		return appendJSONString(out, x.s)
	case 'b':
		if x.b {
			return append(out, "true"...)
		}
		return append(out, "false"...)
	case 'a':
		out = append(out, '[')
		for i, v := range x.arr {
			if i > 0 {
				out = append(out, ',')
			}
			out = v.jcs(out)
		}
		return append(out, ']')
	case 'o':
		sort.Slice(x.obj, func(i, j int) bool { return utf16Less(x.obj[i].key, x.obj[j].key) })
		out = append(out, '{')
		for i, m := range x.obj {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendJSONString(out, m.key)
			out = append(out, ':')
			out = m.value.jcs(out)
		}
		return append(out, '}')
	}
	panic("unreachable")
}
func utf16Less(a, b string) bool {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return len(x) < len(y)
}
func validJSONSurrogates(b []byte) bool {
	for i := 0; i+1 < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		if b[i+1] != 'u' {
			i++
			continue
		}
		if i+5 >= len(b) {
			return false
		}
		n, ok := hex4(b[i+2 : i+6])
		if !ok {
			return false
		}
		i += 5
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			lo, ok := hex4(b[i+3 : i+7])
			if !ok || lo < 0xdc00 || lo > 0xdfff {
				return false
			}
			i += 6
		} else if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
	}
	return true
}
func hex4(b []byte) (rune, bool) {
	var n rune
	for _, c := range b {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += rune(c - '0')
		case c >= 'a' && c <= 'f':
			n += rune(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += rune(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return n, true
}
func appendJSONString(out []byte, s string) []byte {
	out = append(out, '"')
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		case '\b':
			out = append(out, "\\b"...)
		case '\f':
			out = append(out, "\\f"...)
		case '\n':
			out = append(out, "\\n"...)
		case '\r':
			out = append(out, "\\r"...)
		case '\t':
			out = append(out, "\\t"...)
		default:
			if r < 0x20 {
				out = append(out, "\\u00"...)
				out = append(out, "0123456789abcdef"[r>>4], "0123456789abcdef"[r&15])
			} else {
				out = append(out, string(r)...)
			}
		}
	}
	return append(out, '"')
}

func validateEvidence(x jsonValue) error {
	if x.kind != 'o' || len(x.obj) == 0 {
		return errors.New("evidence root object")
	}
	allowed := map[string]func(jsonValue) error{"graph_coordinates": validateCoordinates, "stable_reference": validateStableReference, "digests": validateDigests, "identity_tuple_field_names": validateNames, "references": validateReferences, "redacted_diagnostics": validateDiagnostics}
	for _, m := range x.obj {
		f, ok := allowed[m.key]
		if !ok {
			return fmt.Errorf("unknown evidence key %q", m.key)
		}
		if e := f(m.value); e != nil {
			return e
		}
	}
	return nil
}
func closedObject(x jsonValue, fields map[string]func(jsonValue) error) error {
	if x.kind != 'o' || len(x.obj) == 0 {
		return errors.New("closed evidence object")
	}
	for _, m := range x.obj {
		f, ok := fields[m.key]
		if !ok {
			return fmt.Errorf("unknown evidence field %q", m.key)
		}
		if e := f(m.value); e != nil {
			return e
		}
	}
	return nil
}
func stringValue(x jsonValue) error {
	if x.kind != 's' || !utf8.ValidString(x.s) || strings.HasPrefix(x.s, "\ufeff") {
		return errors.New("string evidence value")
	}
	return nil
}
func uuidValue(x jsonValue) error {
	if e := stringValue(x); e != nil {
		return e
	}
	u, e := uuid.Parse(x.s)
	if e != nil || u.String() != x.s {
		return errors.New("UUID evidence value")
	}
	return nil
}
func digestValue(x jsonValue) error {
	if e := stringValue(x); e != nil {
		return e
	}
	b, e := hex.DecodeString(x.s)
	if e != nil || len(b) != 32 || strings.ToLower(x.s) != x.s {
		return errors.New("digest evidence value")
	}
	return nil
}
func boolValue(x jsonValue) error {
	if x.kind != 'b' {
		return errors.New("boolean evidence value")
	}
	return nil
}
func validateCoordinates(x jsonValue) error {
	return closedObject(x, map[string]func(jsonValue) error{"graph_snapshot_id": uuidValue, "materialization_run_id": uuidValue, "graph_object_id": uuidValue, "symbol_id": uuidValue, "graph_edge_id": uuidValue, "section_path": stringValue, "graph_address": stringValue, "edge_label": stringValue, "source_endpoint_class": stringValue, "target_endpoint_class": stringValue})
}
func validateStableReference(x jsonValue) error {
	return closedObject(x, map[string]func(jsonValue) error{"source_authority_id": uuidValue, "source_stable_reference": stringValue, "source_version_coordinate": stringValue})
}
func validateDigests(x jsonValue) error {
	return closedObject(x, map[string]func(jsonValue) error{"source_content_hash": digestValue, "evidence_digest": digestValue, "relationship_evidence_hash": digestValue})
}
func validateDiagnostics(x jsonValue) error {
	return closedObject(x, map[string]func(jsonValue) error{"violation_code": stringValue, "sentinel_candidate": stringValue, "equivalent": boolValue, "loss_detected": boolValue, "invalid": boolValue, "rejected_value_class": stringValue, "redacted_reason": stringValue, "redacted_evidence_code": stringValue})
}
func validateNames(x jsonValue) error {
	if x.kind != 'a' || len(x.arr) < 1 || len(x.arr) > 1024 {
		return errors.New("identity tuple names")
	}
	last := ""
	for i, v := range x.arr {
		if e := stringValue(v); e != nil {
			return e
		}
		if i > 0 && v.s <= last {
			return errors.New("identity tuple names order")
		}
		last = v.s
	}
	return nil
}
func validateReferences(x jsonValue) error {
	if x.kind != 'a' || len(x.arr) < 1 || len(x.arr) > 1024 {
		return errors.New("references")
	}
	last := ""
	for _, v := range x.arr {
		if v.kind != 'o' || len(v.obj) != 2 {
			return errors.New("reference shape")
		}
		var k, val string
		for _, m := range v.obj {
			if m.key == "ref_kind" {
				if e := stringValue(m.value); e != nil {
					return e
				}
				k = m.value.s
			} else if m.key == "ref_value" {
				if e := stringValue(m.value); e != nil {
					return e
				}
				val = m.value.s
			} else {
				return errors.New("reference key")
			}
		}
		if k != "policy_decision_ref" && k != "validation_evidence_ref" && k != "projection_artifact_id" && k != "graph_fact_locator_manifest_ref" {
			return errors.New("reference kind")
		}
		if k == "graph_fact_locator_manifest_ref" {
			if err := digestValue(jsonValue{kind: 's', s: val}); err != nil {
				return errors.New("graph-fact locator manifest reference must be lowercase SHA-256")
			}
		}
		pair := k + "\x00" + val
		if last != "" && pair <= last {
			return errors.New("reference order")
		}
		last = pair
	}
	return nil
}
