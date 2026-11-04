package providerplan

import (
	"context"
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

type provenanceTestAuthority struct {
	resolve func(DocumentationFactoryOODNativeProvenanceRequest) ([]DocumentationFactoryNativePrimaryProvenance, error)
}

func (a provenanceTestAuthority) ResolveAndVerifyNativePrimaryProvenance(_ context.Context, request DocumentationFactoryOODNativeProvenanceRequest) ([]DocumentationFactoryNativePrimaryProvenance, error) {
	return a.resolve(request)
}

func TestVerifyDocumentationFactoryNativeProvenanceRejectsUnadmittedAndInvalidSelections(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	p, bindings := provenanceTestInput(t, f)
	if _, err := verifyDocumentationFactoryNativeProvenance(context.Background(), f.Receipt.OrganizationID, p, bindings, nil); err == nil || !strings.Contains(err.Error(), "requires protected fact authority") {
		t.Fatalf("absent authority error = %v", err)
	}

	valid := provenanceTestSelections(p, bindings)
	cases := []struct {
		name string
		pick func([]DocumentationFactoryNativePrimaryProvenance) []DocumentationFactoryNativePrimaryProvenance
		want string
	}{
		{
			name: "incomplete", pick: func(s []DocumentationFactoryNativePrimaryProvenance) []DocumentationFactoryNativePrimaryProvenance {
				return s[:len(s)-1]
			},
			want: "not the complete claim roster",
		},
		{
			name: "extra", pick: func(s []DocumentationFactoryNativePrimaryProvenance) []DocumentationFactoryNativePrimaryProvenance {
				out := append([]DocumentationFactoryNativePrimaryProvenance(nil), s...)
				out = append(out, s[0])
				return out
			}, want: "not the complete claim roster",
		},
		{
			name: "duplicate", pick: func(s []DocumentationFactoryNativePrimaryProvenance) []DocumentationFactoryNativePrimaryProvenance {
				out := append([]DocumentationFactoryNativePrimaryProvenance(nil), s...)
				out[len(out)-1] = out[0]
				return out
			}, want: "foreign, duplicated",
		},
		{
			name: "foreign locator", pick: func(s []DocumentationFactoryNativePrimaryProvenance) []DocumentationFactoryNativePrimaryProvenance {
				out := append([]DocumentationFactoryNativePrimaryProvenance(nil), s...)
				out[0].NativeLocatorID = "foreign"
				return out
			}, want: "foreign, duplicated",
		},
		{
			name: "mutated receipt", pick: func(s []DocumentationFactoryNativePrimaryProvenance) []DocumentationFactoryNativePrimaryProvenance {
				out := append([]DocumentationFactoryNativePrimaryProvenance(nil), s...)
				out[0].ReceiptID = "00000000-0000-0000-0000-000000000001"
				return out
			}, want: "does not bind its qualified receipt/locator",
		},
		{
			name: "mutated digest", pick: func(s []DocumentationFactoryNativePrimaryProvenance) []DocumentationFactoryNativePrimaryProvenance {
				out := append([]DocumentationFactoryNativePrimaryProvenance(nil), s...)
				out[0].ReceiptDigest = sha256Hex([]byte("substituted-receipt-digest"))
				return out
			}, want: "does not bind its qualified receipt/locator",
		},
		{
			name: "mutated locator hash", pick: func(s []DocumentationFactoryNativePrimaryProvenance) []DocumentationFactoryNativePrimaryProvenance {
				out := append([]DocumentationFactoryNativePrimaryProvenance(nil), s...)
				out[0].GraphFactLocatorHash = sha256Hex([]byte("substituted-locator-hash"))
				return out
			}, want: "does not bind its qualified receipt/locator",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := provenanceTestAuthority{resolve: func(DocumentationFactoryOODNativeProvenanceRequest) ([]DocumentationFactoryNativePrimaryProvenance, error) {
				return tc.pick(valid), nil
			}}
			if _, err := verifyDocumentationFactoryNativeProvenance(context.Background(), f.Receipt.OrganizationID, p, bindings, a); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestVerifyDocumentationFactoryNativeProvenanceCopiesAuthorityRequestAndBindsExactProjection(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	p, bindings := provenanceTestInput(t, f)
	valid := provenanceTestSelections(p, bindings)
	called := false
	a := provenanceTestAuthority{resolve: func(request DocumentationFactoryOODNativeProvenanceRequest) ([]DocumentationFactoryNativePrimaryProvenance, error) {
		called = true
		// Mutate every slice delivered to the authority. The verifier's expected
		// claim and qualified-locator maps must remain independent.
		request.Claims[0].NativeClaimID = "mutated"
		request.Claims[0].LocatorIDs[0] = "mutated"
		request.Locators[0].ReceiptDigest = sha256Hex([]byte("mutated"))
		return valid, nil
	}}
	v, err := verifyDocumentationFactoryNativeProvenance(context.Background(), f.Receipt.OrganizationID, p, bindings, a)
	if err != nil || !called {
		t.Fatalf("valid provenance after request mutation: value=%+v err=%v called=%v", v, err, called)
	}
	if _, err := v.primary(f.Receipt.OrganizationID, p, "symbol", "source"); err != nil {
		t.Fatalf("exact projection primary: %v", err)
	}
	otherGraph := p
	otherGraph.APIGraphSHA256 = sha256Hex([]byte("other-graph"))
	if _, err := v.primary(f.Receipt.OrganizationID, otherGraph, "symbol", "source"); err == nil || !strings.Contains(err.Error(), "does not bind the exact sealed graph") {
		t.Fatalf("cross-graph reuse error = %v", err)
	}
	otherMapping := p
	otherMapping.SourceMappingSHA256 = sha256Hex([]byte("other-mapping"))
	if _, err := v.primary(f.Receipt.OrganizationID, otherMapping, "symbol", "source"); err == nil || !strings.Contains(err.Error(), "does not bind the exact sealed graph") {
		t.Fatalf("cross-mapping reuse error = %v", err)
	}
	if _, err := v.primary("different-org", p, "symbol", "source"); err == nil || !strings.Contains(err.Error(), "does not bind the exact sealed graph") {
		t.Fatalf("cross-organization reuse error = %v", err)
	}
}

func provenanceTestInput(t *testing.T, f oodtestfixture.Fixture) (DocumentationFactorySourcePackageOODNativeProjection, []DocumentationFactorySourcePackageOODLocatorBinding) {
	t.Helper()
	q := primaryTestQualifiedLocator(t, f)
	binding := q.binding
	binding.SourceArtifactHash = q.sourceArtifactHash
	for _, row := range f.ImmutableRows {
		switch row.Table {
		case "OODGraphExternalFetchReceipts":
			binding.Receipt = row
		case "OODGraphExternalFetchBatches":
			binding.Batch = row
		}
	}
	if binding.Receipt.Table == "" || binding.Batch.Table == "" {
		t.Fatal("fixture lacks physical receipt/batch for qualified locator")
	}
	p := DocumentationFactorySourcePackageOODNativeProjection{
		APIGraphSHA256:      sha256Hex([]byte("provenance-test-graph")),
		SourceMappingSHA256: sha256Hex([]byte("provenance-test-mapping")),
		Locators: []DocumentationFactoryNativeEvidenceLocator{{
			ID: "primary", SourceContentSHA256: q.binding.Locator.SourceContentHash, SelectedRangeSHA256: q.binding.Locator.SelectedRangeContentHash,
			ByteStartOffset: q.binding.Locator.ByteStartOffset, ByteEndOffsetExclusive: q.binding.Locator.ByteEndOffsetExclusive,
			SelectedRangeByteCount: q.binding.Locator.SelectedRangeByteCount, SourceRefs: []string{q.receipt.SourceStableReference},
		}},
		Symbols: []DocumentationFactoryNativeAPISymbol{
			{ID: "source", LocatorIDs: []string{"primary"}},
			{ID: "target", LocatorIDs: []string{"primary"}},
		},
		Relationships: []DocumentationFactoryNativeAPIRelationship{{ID: "relationship", LocatorIDs: []string{"primary"}}},
	}
	return p, []DocumentationFactorySourcePackageOODLocatorBinding{binding}
}

func provenanceTestSelections(p DocumentationFactorySourcePackageOODNativeProjection, locators []DocumentationFactorySourcePackageOODLocatorBinding) []DocumentationFactoryNativePrimaryProvenance {
	byID := map[string]DocumentationFactorySourcePackageOODLocatorBinding{}
	for _, l := range locators {
		byID[l.NativeLocatorID] = l
	}
	selection := func(kind, id, locatorID string) DocumentationFactoryNativePrimaryProvenance {
		l := byID[locatorID].Locator
		x := DocumentationFactoryNativePrimaryProvenance{Kind: kind, NativeClaimID: id, DocumentationFactoryNativeProvenanceLocator: DocumentationFactoryNativeProvenanceLocator{NativeLocatorID: locatorID, GraphFactLocatorHash: l.LocatorHash, EvidenceIdentityHash: l.EvidenceIdentityHash, ReceiptID: l.EligibleReceiptID, ReceiptDigest: l.EligibleReceiptDigest}}
		if kind == "symbol" {
			x.Documentation = DocumentationFactoryNativeDocumentationProvenance{DocumentObjectClass: "external_reference_doc", DocSectionPath: "/source/" + id, DocumentsAuthoringSourcePath: "native.symbol." + id + ".documents"}
		}
		return x
	}
	out := make([]DocumentationFactoryNativePrimaryProvenance, 0, len(p.Symbols)+len(p.Relationships))
	for _, s := range p.Symbols {
		out = append(out, selection("symbol", s.ID, s.LocatorIDs[0]))
	}
	for _, r := range p.Relationships {
		out = append(out, selection("relationship", r.ID, r.LocatorIDs[0]))
	}
	return out
}

func provenanceTestVerified(t *testing.T, org string, p DocumentationFactorySourcePackageOODNativeProjection, locators []DocumentationFactorySourcePackageOODLocatorBinding) DocumentationFactoryVerifiedNativeProvenance {
	t.Helper()
	selections := provenanceTestSelections(p, locators)
	v, err := verifyDocumentationFactoryNativeProvenance(context.Background(), org, p, locators, provenanceTestAuthority{resolve: func(DocumentationFactoryOODNativeProvenanceRequest) ([]DocumentationFactoryNativePrimaryProvenance, error) {
		return selections, nil
	}})
	if err != nil {
		t.Fatalf("valid provenance: %v", err)
	}
	return v
}
