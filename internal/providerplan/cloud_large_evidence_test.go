package providerplan

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestLargeEvidenceHexClosureUsesBoundedSingleTargetFallback(t *testing.T) {
	body := make([]byte, 7<<20)
	for i := range body {
		body[i] = byte(i * 31)
	}
	encoded := make([]byte, hex.EncodedLen(len(body)))
	hex.Encode(encoded, body)
	items := []evidenceClosureItem{{label: "hex-leak", raw: []byte(`{"v":"` + string(encoded) + `"}`), structured: true}}
	limit := int64(len(encoded))*32 + int64(len(body))*64
	label, digest, encoding, found, err := detectCanonicalEvidenceBodyClosureWithBudget(items, jsonCarrierSourceOrder, map[string]exactEvidenceBody{"large": {Bytes: body}}, 1, &canonicalEvidenceClosureWorkBudget{limit: limit})
	if err != nil || !found || label != "hex-leak" || digest != "large" || encoding == "" {
		t.Fatalf("large encoded closure: %q %q %q %v %v", label, digest, encoding, found, err)
	}
}

func TestLargeEvidenceCleanClosureUsesBoundedReversibleFallback(t *testing.T) {
	body := make([]byte, 7<<20)
	for i := range body {
		body[i] = byte(i * 31)
	}
	_, _, _, found, err := detectCanonicalEvidenceBodyClosureWithBudget([]evidenceClosureItem{{label: "clean", raw: []byte(`{"status":"candidate"}`), structured: true}}, jsonCarrierSourceOrder, map[string]exactEvidenceBody{"large": {Bytes: body}}, 1, &canonicalEvidenceClosureWorkBudget{})
	if err != nil || found {
		t.Fatalf("clean large evidence: found=%v err=%v", found, err)
	}
}

func TestSingleReversibleFallbackFindsNumericBodyAndPreservesBudget(t *testing.T) {
	body := []byte("reversible exact fixture body")
	numeric := map[string]uint8{}
	for i, b := range reversedBytes(body) {
		numeric[fmt.Sprintf("n%03d", i)] = b
	}
	raw, err := json.Marshal(numeric)
	if err != nil {
		t.Fatal(err)
	}
	label, found, err := scanCanonicalEvidenceSingleReversible([]evidenceClosureItem{{label: "numeric-leak", raw: raw, structured: true}}, jsonCarrierSourceOrder, body, &canonicalEvidenceClosureWorkBudget{})
	if err != nil || !found || label != "numeric-leak" {
		t.Fatalf("numeric fallback=%s %v %v", label, found, err)
	}
	budget := &canonicalEvidenceClosureWorkBudget{limit: int64(len(body) - 1)}
	_, _, err = scanCanonicalEvidenceSingleReversible(nil, jsonCarrierSourceOrder, body, budget)
	if err == nil || !strings.Contains(err.Error(), "work-unit limit") || budget.used != 0 {
		t.Fatalf("budget refusal: %v used=%d", err, budget.used)
	}
}
