package providerplan

import (
	"encoding/json"
	"testing"
)

func TestModelEvidenceMeasuresPointerInExactUTF8Bytes(t *testing.T) {
	body := []byte("{\"label\":\"台\",\"a/b\":{\"~\":[\"x\",9007199254740993]}}")
	sel := map[string]any{"expected_sha256": sha256Hex(body), "source_uri": "https://example.test/model", "source_path": "models/one.json", "selections": []map[string]string{{"id": "n", "json_pointer": "/a~1b/~0/1"}}}
	raw, _ := json.Marshal(sel)
	b, err := MeasureCloudModelEvidence(body, raw)
	if err != nil || len(b) != 1 {
		t.Fatal(b, err)
	}
	x := b[0]
	if string(body[x.StartByte:x.EndByte]) != "9007199254740993" || x.SliceSHA256 != sha256Hex(body[x.StartByte:x.EndByte]) {
		t.Fatal("lost exact number/UTF-8 range", x)
	}
	sel["selections"] = []map[string]string{{"id": "n", "json_pointer": "/label"}, {"id": "n", "json_pointer": "/a~1b"}}
	raw, _ = json.Marshal(sel)
	if _, err := MeasureCloudModelEvidence(body, raw); err == nil {
		t.Fatal("accepted duplicate evidence id")
	}
	if _, err := MeasureCloudModelEvidence(append(body, ' '), raw); err == nil {
		t.Fatal("accepted changed input digest")
	}
}
