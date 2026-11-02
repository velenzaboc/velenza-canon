package providerplan

import (
	"strings"
	"testing"
)

func TestDecodeSealedNativeAPIJSONLClosesReferences(t *testing.T) {
	raw := []byte(`{"row_kind":"artifact_manifest"}
{"row_kind":"candidate_evidence_locator","evidence_locator_id":"l","evidence_manifest_sha256":"a","source_content_sha256":"b","byte_start_offset":0,"byte_end_offset_exclusive":1,"selected_range_byte_count":1,"selected_range_sha256":"c","source_refs":["r"],"source_urls":["u"],"locator_semantics":"exact_selected_range","source_bytes_present":false}
{"row_kind":"candidate_api_symbol","candidate_api_symbol_id":"a","api_element_role":"operation","semantic_key":"a","display_name":"a","evidence_locator_ids":["l"],"derivation_binding":{},"authority_status":"exact","source_bytes_present":false}
{"row_kind":"candidate_api_symbol","candidate_api_symbol_id":"b","api_element_role":"resource","semantic_key":"b","display_name":"b","evidence_locator_ids":["l"],"derivation_binding":{},"authority_status":"exact","source_bytes_present":false}
{"row_kind":"candidate_api_relationship","candidate_api_relationship_id":"r","relationship_label":"operation_reads_resource","source_candidate_api_symbol_id":"a","target_candidate_api_symbol_id":"b","evidence_locator_ids":["l"],"derivation_binding":{},"authority_status":"exact","source_bytes_present":false}
{"row_kind":"validation_summary"}
`)
	raw = []byte(strings.ReplaceAll(string(raw), `\"`, `"`))
	out, err := decodeSealedNativeAPIJSONL(raw, strings.Repeat("a", 64), strings.Repeat("b", 64))
	if err != nil || len(out.Symbols) != 2 || len(out.Relationships) != 1 || len(out.Locators) != 1 {
		t.Fatalf("sealed native decode = %#v, %v", out, err)
	}
	bad := []byte(strings.Replace(string(raw), `"target_candidate_api_symbol_id":"b"`, `"target_candidate_api_symbol_id":"missing"`, 1))
	if _, err := decodeSealedNativeAPIJSONL(bad, strings.Repeat("a", 64), strings.Repeat("b", 64)); err == nil {
		t.Fatal("dangling sealed relationship accepted")
	}
}
