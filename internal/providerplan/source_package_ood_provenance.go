package providerplan

import (
	"context"
	"fmt"
)

// DocumentationFactoryOODNativeProvenanceAuthority is an admitted source-fact
// derivation capability. It must resolve and verify the primary source from
// the exact sealed native classification/derivation artifacts, including
// current source eligibility. Identity allocation cannot supply this authority.
// This capability is selected by protected boot, never by candidate input.
type DocumentationFactoryOODNativeProvenanceAuthority interface {
	ResolveAndVerifyNativePrimaryProvenance(context.Context, DocumentationFactoryOODNativeProvenanceRequest) ([]DocumentationFactoryNativePrimaryProvenance, error)
}

type DocumentationFactoryOODNativeProvenanceRequest struct {
	OrganizationID, APIGraphSHA256, SourceMappingSHA256 string
	Claims                                              []DocumentationFactoryNativeProvenanceClaim
	Locators                                            []DocumentationFactoryNativeProvenanceLocator
}

type DocumentationFactoryNativeProvenanceClaim struct {
	Kind, NativeClaimID string
	LocatorIDs          []string
}

type DocumentationFactoryNativeProvenanceLocator struct {
	NativeLocatorID, GraphFactLocatorHash, EvidenceIdentityHash string
	ReceiptID, ReceiptDigest                                    string
}

type DocumentationFactoryNativePrimaryProvenance struct {
	Kind, NativeClaimID string
	DocumentationFactoryNativeProvenanceLocator
	Documentation DocumentationFactoryNativeDocumentationProvenance
}

type nativeProvenanceClaimKey struct{ kind, id string }

// DocumentationFactoryVerifiedNativeProvenance is minted only by the
// protected successor path after the source-fact authority returns a complete
// exact claim roster. Its fields cannot be supplied by a coordinate allocator.
type DocumentationFactoryVerifiedNativeProvenance struct {
	organizationID, apiGraphSHA256, sourceMappingSHA256 string
	selections                                          map[nativeProvenanceClaimKey]DocumentationFactoryNativePrimaryProvenance
}

func verifyDocumentationFactoryNativeProvenance(ctx context.Context, org string, p DocumentationFactorySourcePackageOODNativeProjection, locators []DocumentationFactorySourcePackageOODLocatorBinding, authority DocumentationFactoryOODNativeProvenanceAuthority) (DocumentationFactoryVerifiedNativeProvenance, error) {
	if ctx == nil || authority == nil || org == "" || !isLowerSHA256(p.APIGraphSHA256) || !isLowerSHA256(p.SourceMappingSHA256) {
		return DocumentationFactoryVerifiedNativeProvenance{}, fmt.Errorf("native provenance requires protected fact authority and exact sealed graph")
	}
	request := DocumentationFactoryOODNativeProvenanceRequest{OrganizationID: org, APIGraphSHA256: p.APIGraphSHA256, SourceMappingSHA256: p.SourceMappingSHA256}
	claims := map[nativeProvenanceClaimKey]map[string]bool{}
	add := func(kind, id string, ids []string) error {
		key := nativeProvenanceClaimKey{kind, id}
		if id == "" || claims[key] != nil || len(ids) == 0 {
			return fmt.Errorf("native provenance claim is empty or duplicated")
		}
		allowed := map[string]bool{}
		for _, locatorID := range ids {
			if locatorID == "" || allowed[locatorID] {
				return fmt.Errorf("native provenance claim locator is empty or duplicated")
			}
			allowed[locatorID] = true
		}
		claims[key] = allowed
		request.Claims = append(request.Claims, DocumentationFactoryNativeProvenanceClaim{Kind: kind, NativeClaimID: id, LocatorIDs: append([]string(nil), ids...)})
		return nil
	}
	for _, s := range p.Symbols {
		if err := add("symbol", s.ID, s.LocatorIDs); err != nil {
			return DocumentationFactoryVerifiedNativeProvenance{}, err
		}
	}
	for _, r := range p.Relationships {
		if err := add("relationship", r.ID, r.LocatorIDs); err != nil {
			return DocumentationFactoryVerifiedNativeProvenance{}, err
		}
	}
	qualified := map[string]DocumentationFactoryNativeProvenanceLocator{}
	for _, l := range locators {
		if l.NativeLocatorID == "" || l.Locator.OrganizationID != org || qualified[l.NativeLocatorID].NativeLocatorID != "" {
			return DocumentationFactoryVerifiedNativeProvenance{}, fmt.Errorf("native provenance locator is foreign or duplicated")
		}
		v := DocumentationFactoryNativeProvenanceLocator{NativeLocatorID: l.NativeLocatorID, GraphFactLocatorHash: l.Locator.LocatorHash, EvidenceIdentityHash: l.Locator.EvidenceIdentityHash, ReceiptID: l.Locator.EligibleReceiptID, ReceiptDigest: l.Locator.EligibleReceiptDigest}
		qualified[l.NativeLocatorID] = v
		request.Locators = append(request.Locators, v)
	}
	for _, allowed := range claims {
		for id := range allowed {
			if qualified[id].NativeLocatorID == "" {
				return DocumentationFactoryVerifiedNativeProvenance{}, fmt.Errorf("native provenance claim has no qualified locator")
			}
		}
	}
	// The request owns its slices. A capability cannot mutate the independent
	// expected claim/locator maps used to validate its result.
	selected, err := authority.ResolveAndVerifyNativePrimaryProvenance(ctx, request)
	if err != nil {
		return DocumentationFactoryVerifiedNativeProvenance{}, fmt.Errorf("admitted native provenance: %w", err)
	}
	if len(selected) != len(claims) {
		return DocumentationFactoryVerifiedNativeProvenance{}, fmt.Errorf("native provenance selection is not the complete claim roster")
	}
	out := DocumentationFactoryVerifiedNativeProvenance{organizationID: org, apiGraphSHA256: p.APIGraphSHA256, sourceMappingSHA256: p.SourceMappingSHA256, selections: map[nativeProvenanceClaimKey]DocumentationFactoryNativePrimaryProvenance{}}
	for _, s := range selected {
		key := nativeProvenanceClaimKey{s.Kind, s.NativeClaimID}
		if !claims[key][s.NativeLocatorID] || out.selections[key].NativeClaimID != "" || s.DocumentationFactoryNativeProvenanceLocator != qualified[s.NativeLocatorID] {
			return DocumentationFactoryVerifiedNativeProvenance{}, fmt.Errorf("native provenance selection is foreign, duplicated, or does not bind its qualified receipt/locator")
		}
		if s.Kind == "symbol" {
			if err := s.Documentation.validate(); err != nil {
				return DocumentationFactoryVerifiedNativeProvenance{}, fmt.Errorf("native symbol %q documentation fact: %w", s.NativeClaimID, err)
			}
		} else if !s.Documentation.zero() {
			return DocumentationFactoryVerifiedNativeProvenance{}, fmt.Errorf("native relationship %q carries a documentation fact", s.NativeClaimID)
		}
		out.selections[key] = s
	}
	return out, nil
}

func (v DocumentationFactoryVerifiedNativeProvenance) primary(org string, p DocumentationFactorySourcePackageOODNativeProjection, kind, id string) (string, error) {
	if v.organizationID != org || v.apiGraphSHA256 != p.APIGraphSHA256 || v.sourceMappingSHA256 != p.SourceMappingSHA256 || v.selections == nil {
		return "", fmt.Errorf("native provenance does not bind the exact sealed graph and organization")
	}
	s, ok := v.selections[nativeProvenanceClaimKey{kind, id}]
	if !ok || s.NativeLocatorID == "" {
		return "", fmt.Errorf("native claim lacks admitted primary provenance")
	}
	return s.NativeLocatorID, nil
}
