package providerplan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestClosureScannerJSONLOrderingProvenanceAndBounds(t *testing.T) {
	item := candidateClosureItem{label: "fixture.jsonl", raw: []byte("\n {\"z\":\"last\",\"a\":\"first\",\"bytes\":[65,66]} \n{\"proof\":\"bound\"}\n")}
	collect := func(order jsonCarrierTraversal) ([]orderedJSONCarrier, error) {
		var carriers []orderedJSONCarrier
		err := scanJSONLClosureItemWithOrderBudgetAndProvenance(item, order, &canonicalEvidenceClosureWorkBudget{limit: 10_000}, func(row int, pointer string, value []byte) bool {
			return row == 3 && pointer == "/proof" && bytes.Equal(value, []byte("bound"))
		}, func(carrier orderedJSONCarrier) error {
			carriers = append(carriers, carrier)
			return nil
		})
		return carriers, err
	}
	source, err := collect(jsonCarrierSourceOrder)
	if err != nil {
		t.Fatalf("source-order scan: %v", err)
	}
	canonical, err := collect(jsonCarrierCanonicalObjectOrder)
	if err != nil {
		t.Fatalf("canonical-order scan: %v", err)
	}
	if len(source) == 0 || len(canonical) != len(source) || string(source[0].bytes) != "z" || string(canonical[0].bytes) != "a" {
		t.Fatalf("carrier ordering source=%#v canonical=%#v", source, canonical)
	}
	var proven bool
	var compactByteCarrier bool
	for _, carrier := range source {
		proven = proven || carrier.provenDigestIdentity
		compactByteCarrier = compactByteCarrier || (carrier.kind == orderedJSONByteArray && bytes.Equal(carrier.bytes, []byte("AB")))
	}
	if !proven || !compactByteCarrier {
		t.Fatalf("proven=%v compactByteCarrier=%v carriers=%#v", proven, compactByteCarrier, source)
	}
	if err := scanJSONLClosureItemWithOrderBudget(item, jsonCarrierSourceOrder, &canonicalEvidenceClosureWorkBudget{limit: 1}, func(orderedJSONCarrier) error { return nil }); err == nil || !strings.Contains(err.Error(), "work-unit") {
		t.Fatalf("budget refusal error=%v", err)
	}
	if err := scanJSONLClosureItem(candidateClosureItem{label: "bad.jsonl", raw: []byte("{\"unterminated\":\n")}, func(orderedJSONCarrier) error { return nil }); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("malformed JSONL error=%v", err)
	}
	if err := walkJSONCarriersValidated([]byte(`{"0":65,"2":66}`), jsonCarrierSourceOrder, func(orderedJSONCarrier) error { return nil }); err == nil || !strings.Contains(err.Error(), "not contiguous") {
		t.Fatalf("sparse indexed carrier error=%v", err)
	}
}

func TestClosureScannerReversibleCarriersAndStreamingMatchers(t *testing.T) {
	bits := []json.RawMessage{[]byte("true"), []byte("false"), []byte("false"), []byte("false"), []byte("false"), []byte("false"), []byte("false"), []byte("true")}
	msb, lsb, ok := rawMessageBooleanVectors(bits)
	if !ok || !bytes.Equal(msb, []byte{0x81}) || !bytes.Equal(lsb, []byte{0x81}) {
		t.Fatalf("boolean vectors msb=%x lsb=%x ok=%v", msb, lsb, ok)
	}
	if _, _, ok := rawMessageBooleanVectors(bits[:7]); ok {
		t.Fatal("short boolean vector accepted")
	}
	big, reversed, ok := reversibleBigIntegerBytes(json.Number("340282366920938463463374607431768211455"))
	if !ok || len(big) != 16 || !bytes.Equal(reversedBytes(big), reversed) {
		t.Fatalf("reversible big integer=%x reversed=%x ok=%v", big, reversed, ok)
	}
	if _, _, ok := reversibleBigIntegerBytes(json.Number("not-a-number")); ok {
		t.Fatal("invalid big integer accepted")
	}
	matcher, err := newStreamingExactMatcher([]byte("abcab"), false)
	if err != nil {
		t.Fatal(err)
	}
	if matcher.advance([]byte("xxabca")) || !matcher.advance([]byte("bzz")) {
		t.Fatal("streaming matcher did not retain its exact cross-carrier prefix")
	}
	hexMatcher, err := newStreamingExactMatcher([]byte("deadbeef"), true)
	if err != nil {
		t.Fatal(err)
	}
	if hexMatcher.advance([]byte("DEAD")) || !hexMatcher.advance([]byte("BEEF")) {
		t.Fatal("folded hexadecimal matcher did not normalize case across chunks")
	}
	if _, err := newStreamingExactMatcher([]byte("DEADBEEF"), true); err == nil || !strings.Contains(err.Error(), "lowercase") {
		t.Fatalf("uppercase folded target error=%v", err)
	}
}

func TestClosureScannerDenseNumericCarrierAndEvidenceItemBoundaries(t *testing.T) {
	var builder strings.Builder
	builder.WriteByte('{')
	for index := 0; index < 16; index++ {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(`"byte_`)
		builder.WriteString(string(rune('a' + index)))
		builder.WriteString(`":`)
		builder.WriteString("65")
	}
	builder.WriteByte('}')
	pairs, err := decodeOrderedJSONObjectPairs([]byte(builder.String()))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := denseCanonicalNumericObjectBytes(pairs); ok {
		t.Fatal("non-numeric suffix object was accepted as dense carrier")
	}
	// A zero-padded numeric roster is a canonical reversible byte carrier.
	builder.Reset()
	builder.WriteByte('{')
	for index := 0; index < 16; index++ {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(`"byte_`)
		builder.WriteByte('0')
		builder.WriteString(string(rune('0' + index/10)))
		builder.WriteString(string(rune('0' + index%10)))
		builder.WriteString(`":`)
		builder.WriteString("65")
	}
	builder.WriteByte('}')
	pairs, err = decodeOrderedJSONObjectPairs([]byte(builder.String()))
	if err != nil {
		t.Fatal(err)
	}
	dense, ok := denseCanonicalNumericObjectBytes(pairs)
	if !ok || !bytes.Equal(dense, bytes.Repeat([]byte("A"), 16)) {
		t.Fatalf("dense numeric carrier=%q ok=%v", dense, ok)
	}
	var rawCarriers []orderedJSONCarrier
	if err := scanEvidenceClosureItemWithOrderBudget(evidenceClosureItem{label: "raw", raw: []byte("opaque bytes"), structured: false}, jsonCarrierSourceOrder, nil, func(carrier orderedJSONCarrier) error {
		rawCarriers = append(rawCarriers, carrier)
		return nil
	}); err != nil || len(rawCarriers) != 1 || string(rawCarriers[0].bytes) != "opaque bytes" {
		t.Fatalf("raw evidence scan carriers=%#v err=%v", rawCarriers, err)
	}
}

func TestClosureScannerBatchCursorAndDecodedCarrierRefusals(t *testing.T) {
	targets := []canonicalEvidenceBatchTarget{
		{digest: "later", target: []byte("second"), priority: 5},
		{digest: "first", target: []byte("first"), priority: 1},
	}
	budget := &canonicalEvidenceClosureWorkBudget{limit: 10_000}
	matcher, err := newCanonicalEvidenceBatchMatcher(targets, false, budget)
	if err != nil {
		t.Fatalf("new batch matcher: %v", err)
	}
	if found, err := matcher.advanceCarrier(orderedJSONCarrier{bytes: []byte("fi"), kind: orderedJSONStringValue}, canonicalEvidenceCarrierRawRepresentations, false, budget); err != nil || found >= 0 {
		t.Fatalf("prefix carrier found=%d err=%v", found, err)
	}
	if found, err := matcher.advanceCarrier(orderedJSONCarrier{bytes: []byte("rst"), kind: orderedJSONStringValue}, canonicalEvidenceCarrierRawRepresentations, false, budget); err != nil || found != 1 {
		t.Fatalf("cross-carrier cursor match=%d err=%v", found, err)
	}
	if found, err := matcher.advanceCarrier(orderedJSONCarrier{bytes: []byte("Zg=="), kind: orderedJSONStringValue}, canonicalEvidenceCarrierBase64, false, budget); err != nil || found >= 0 {
		t.Fatalf("nonmatching base64 carrier found=%d err=%v", found, err)
	}
	if _, err := matcher.advanceCarrier(orderedJSONCarrier{bytes: []byte("00"), kind: orderedJSONStringValue}, canonicalEvidenceCarrierMode(99), false, budget); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unknown carrier mode error=%v", err)
	}
	if _, err := newCanonicalEvidenceBatchMatcher(nil, false, budget); err == nil || !strings.Contains(err.Error(), "no targets") {
		t.Fatalf("empty batch target error=%v", err)
	}
	if _, err := newCanonicalEvidenceBatchMatcher([]canonicalEvidenceBatchTarget{{digest: "bad", target: nil}}, false, budget); err == nil || !strings.Contains(err.Error(), "empty closure target") {
		t.Fatalf("empty target error=%v", err)
	}
	if _, err := newCanonicalEvidenceBatchMatcherWithAuxiliaryLimit([]canonicalEvidenceBatchTarget{{digest: "too-large", target: []byte("target")}}, false, &canonicalEvidenceClosureWorkBudget{}, 1); err == nil || !strings.Contains(err.Error(), "auxiliary bytes") {
		t.Fatalf("auxiliary limit error=%v", err)
	}
	if capacity, err := canonicalEvidenceDecodedCarrierCapacity(canonicalEvidenceCarrierHex, 6); err != nil || capacity != 3 {
		t.Fatalf("hex capacity=%d err=%v", capacity, err)
	}
	if _, err := canonicalEvidenceDecodedCarrierCapacity(canonicalEvidenceCarrierBase64, -1); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative capacity error=%v", err)
	}
}
