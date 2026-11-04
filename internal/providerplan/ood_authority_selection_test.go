package providerplan

import (
	"testing"
)

func testOODAuthoritySelection(raw string) verificationAuthorityInputAdmissionItem {
	return verificationAuthorityInputAdmissionItem{Role: verificationAuthorityRoleOODGraph, Raw: []byte(raw), Resource: providerInputAdmissionResourceReceipt{ContentSHA256: sha256Hex([]byte(raw))}}
}

func TestOODAuthoritySelectionPreservesAuthoredStatusAndExactPin(t *testing.T) {
	for _, status := range []string{"draft", "locked", "active"} {
		item := testOODAuthoritySelection(`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263","version":8,"status":"` + status + `"}`)
		got, err := decodeSelectedOODAuthority(item, item.Resource.ContentSHA256)
		if err != nil || got.Status != status || got.Version.String() != "8" {
			t.Fatalf("authored %s: %+v, %v", status, got, err)
		}
		// Identity-only input is not a normalized contract or a materialization
		// proof. Removing the editorial-status gate cannot skip these checks.
		if _, _, _, _, err := normalizeOODContract(got); err == nil {
			t.Fatal("identity-only document accepted as complete OOD contract")
		}
	}
	good := testOODAuthoritySelection(`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263","version":8,"status":"draft"}`)
	for _, raw := range []string{
		`{"doc_id":"different-owner","version":8,"status":"draft"}`,
		`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263","version":9,"status":"draft"}`,
		`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263","version":8,"status":"locked"}`,
	} {
		mutated := testOODAuthoritySelection(raw)
		if _, err := decodeSelectedOODAuthority(mutated, good.Resource.ContentSHA256); err == nil {
			t.Fatal("authority metadata mutation accepted under original expected pin")
		}
	}
	for _, pin := range []string{"", "self-selected", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if _, err := decodeSelectedOODAuthority(good, pin); err == nil {
			t.Fatal("missing or wrong independent pin accepted")
		}
	}
}

func TestOODAuthoritySelectionRejectsMalformedIdentity(t *testing.T) {
	for _, raw := range []string{
		`{"doc_id":"", "version":8,"status":"draft"}`,
		`{"doc_id":" ood", "version":8,"status":"draft"}`,
		`{"doc_id":"ood", "version":8,"status":"draft"}`,
		`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263", "version":0,"status":"draft"}`,
		`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263", "version":-1,"status":"draft"}`,
		`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263", "version":8.0,"status":"draft"}`,
		`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263", "version":8e0,"status":"draft"}`,
		`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263", "version":"8","status":"draft"}`,
		`{"doc_id":"767c239987f94859ac64afb575bdb263", "version":8,"status":"draft"}`,
		`{"doc_id":"767C2399-87F9-4859-AC64-AFB575BDB263", "version":8,"status":"draft"}`,
		`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263", "version":8,"status":""}`,
		`{"doc_id":"767c2399-87f9-4859-ac64-afb575bdb263", "version":8,"status":" draft"}`,
		`{"doc_id":"ood", "doc_id":"other","version":8,"status":"draft"}`,
	} {
		item := testOODAuthoritySelection(raw)
		if _, err := decodeSelectedOODAuthority(item, item.Resource.ContentSHA256); err == nil {
			t.Fatalf("malformed metadata accepted: %s", raw)
		}
	}
	item := testOODAuthoritySelection(`{"doc_id":"ood","version":8,"status":"draft"}`)
	item.Role = verificationAuthorityRoleSourceRecord
	if _, err := decodeSelectedOODAuthority(item, item.Resource.ContentSHA256); err == nil {
		t.Fatal("cross-role authority accepted")
	}
}
