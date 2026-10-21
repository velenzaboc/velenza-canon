package providerplan

import (
	"strings"
	"testing"
)

func TestDocumentationMaterializationBoundsPointersSchemasAndJSONValues(t *testing.T) {
	tokens, err := documentationJSONPointerTokens("/target~1member/~0identity")
	if err != nil || len(tokens) != 2 || tokens[0] != "target/member" || tokens[1] != "~identity" {
		t.Fatalf("pointer tokens=%v err=%v", tokens, err)
	}
	if _, err := documentationJSONPointerTokens("/bad~2escape"); err == nil || !strings.Contains(err.Error(), "escape") {
		t.Fatalf("noncanonical pointer escape error=%v", err)
	}
	root := map[string]interface{}{"target/member": map[string]interface{}{"~identity": "exact"}}
	value, err := documentationJSONPointerValue(root, tokens)
	if err != nil || value != "exact" {
		t.Fatalf("pointer value=%#v err=%v", value, err)
	}
	if _, err := documentationJSONPointerValue(root, []string{"missing"}); err == nil || !strings.Contains(err.Error(), "absent") {
		t.Fatalf("missing pointer property error=%v", err)
	}
	required, err := documentationSchemaRequiredSet(map[string]interface{}{"required": []interface{}{"id", "name"}})
	if err != nil || len(required) != 2 || !documentationSchemaTypeEquals(map[string]interface{}{"type": "string"}, "string") {
		t.Fatalf("required schema set=%v err=%v", required, err)
	}
	if _, err := documentationSchemaRequiredSet(map[string]interface{}{"required": []interface{}{"id", "id"}}); err == nil || !strings.Contains(err.Error(), "duplicates") {
		t.Fatalf("duplicate required schema field error=%v", err)
	}
}

func TestDocumentationMaterializationBoundsCanonicalBytesAndBindingOrder(t *testing.T) {
	if count, err := exactDocumentationJSONStringByteCount("a\n\u2028é"); err != nil || count != 13 {
		t.Fatalf("canonical JSON string count=%d err=%v", count, err)
	}
	if _, err := exactDocumentationJSONStringByteCount(string([]byte{0xff})); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid UTF-8 count error=%v", err)
	}
	if compareDocumentationMaterializationBinding("a", "bc", 1, "ab", "c", 1) == 0 {
		t.Fatal("length-prefixed materialization binding comparison collided")
	}
	if compareDocumentationLengthPrefixedString("a", "a") != 0 || compareDocumentationLengthPrefixedBytes([]byte("a"), []byte("b")) >= 0 {
		t.Fatal("length-prefixed comparison is not total and deterministic")
	}
	bindings := map[string]string{"fact-b": strings.Repeat("b", 64), "fact-a": strings.Repeat("a", 64)}
	bytesByFact := map[string]int64{"fact-a": 1, "fact-b": 2}
	first := documentationTargetMaterializationBindingMapRoot(bindings, bytesByFact)
	second := documentationTargetMaterializationBindingMapRoot(map[string]string{"fact-a": strings.Repeat("a", 64), "fact-b": strings.Repeat("b", 64)}, map[string]int64{"fact-b": 2, "fact-a": 1})
	if !isLowerSHA256(first) || first != second {
		t.Fatalf("deterministic binding roots=%q/%q", first, second)
	}
	bytesByFact["fact-b"] = 3
	if documentationTargetMaterializationBindingMapRoot(bindings, bytesByFact) == first {
		t.Fatal("binding root ignored exact canonical byte count")
	}
}

func TestDocumentationMaterializationBoundsRootAccountingRejectsInvalidOwnership(t *testing.T) {
	emptyRoot, stats, err := documentationTargetMaterializationRootWithStats(nil)
	if err != nil || emptyRoot != sha256Hex(nil) || stats.canonicalBytes != 0 {
		t.Fatalf("empty materialization root=%q stats=%#v err=%v", emptyRoot, stats, err)
	}
	invalid := documentationTargetMaterialization{canonical: []byte(`{"x":1}`), canonicalBytes: 1}
	if _, _, err := documentationTargetMaterializationRootWithStats([]documentationTargetMaterialization{invalid}); err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("invalid canonical ownership error=%v", err)
	}
	valid := documentationTargetMaterialization{canonical: []byte(`{"x":1}`), canonicalBytes: int64(len(`{"x":1}`))}
	root, rootStats, err := documentationTargetMaterializationRootWithStats([]documentationTargetMaterialization{valid})
	if err != nil || !isLowerSHA256(root) || rootStats.canonicalBytes != valid.canonicalBytes {
		t.Fatalf("valid materialization root=%q stats=%#v err=%v", root, rootStats, err)
	}
	if documentationDecimalByteCount(0) != 1 || documentationDecimalByteCount(12345) != 5 || documentationLengthPrefixedByteCount(3) != 5 {
		t.Fatal("canonical length accounting changed")
	}
}
