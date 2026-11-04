//go:build canonical

package providerplan

import (
	"os"
	"testing"
)

func TestCanonicalOODAuthoritySelection(t *testing.T) {
	path := os.Getenv("OOD_GRAPH_PROTOCOL_PATH")
	expected := os.Getenv("OOD_GRAPH_PROTOCOL_SHA256")
	if path == "" || !isLowerSHA256(expected) {
		t.Fatal("OOD_GRAPH_PROTOCOL_PATH and independently selected OOD_GRAPH_PROTOCOL_SHA256 are required")
	}
	item, err := readVerificationAuthorityWithAdmission(path, verificationAuthorityRoleOODGraph, newCanonicalProviderInputAdmissionAccumulator())
	if err != nil {
		t.Fatal(err)
	}
	contract, err := decodeSelectedOODAuthority(item, expected)
	if err != nil {
		t.Fatal(err)
	}
	if contract.DocID != "767c2399-87f9-4859-ac64-afb575bdb263" || contract.Version.String() != "10" || contract.Status != "draft" {
		t.Fatalf("canonical owner metadata changed: %s v%s %s", contract.DocID, contract.Version, contract.Status)
	}
	if _, _, _, _, err := normalizeOODContract(contract); err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeExternalRepresentationKinds(contract); err != nil {
		t.Fatal(err)
	}
}
