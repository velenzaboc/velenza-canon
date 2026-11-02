package providerplan

import (
	"context"
	"fmt"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

func verifySuccessorRoleProofs(ctx context.Context, p DocumentationFactorySourcePackageOODNativeProjection, graph DocumentationFactorySourcePackageOODNativeGraphRows, locators []DocumentationFactorySourcePackageOODLocatorBinding, provenance DocumentationFactoryVerifiedNativeProvenance, batches []oodevidence.VerifiedBatchV8, authority interface{}) ([]oodevidence.VerifiedAPIElementRoleV8, error) {
	roles, ok := authority.(oodevidence.APIElementRoleEvidenceAuthority)
	if !ok {
		return nil, fmt.Errorf("admitted independent API role authority absent")
	}
	archive, ok := authority.(DocumentationFactoryOODArchivedCanonicalBytes)
	if !ok {
		return nil, fmt.Errorf("API role archive authority absent")
	}
	if len(graph.Objects) != len(p.Symbols) {
		return nil, fmt.Errorf("API role physical object roster is incomplete")
	}
	byLocator := map[string]DocumentationFactorySourcePackageOODLocatorBinding{}
	for _, l := range locators {
		byLocator[l.NativeLocatorID] = l
	}
	byBatch := map[string]oodevidence.VerifiedBatchV8{}
	for _, b := range batches {
		byBatch[b.FetchBatchID()] = b
	}
	out := make([]oodevidence.VerifiedAPIElementRoleV8, 0, len(p.Symbols))
	for i, symbol := range p.Symbols {
		row := graph.Objects[i]
		org, _ := row.Columns["organization_id"].(string)
		primary, err := provenance.primary(org, p, "symbol", symbol.ID)
		if err != nil {
			return nil, err
		}
		l, ok := byLocator[primary]
		if !ok || !nativeLocatorRef(symbol.LocatorIDs, primary) {
			return nil, fmt.Errorf("API symbol %q has no exact admitted primary locator", symbol.ID)
		}
		receipt, err := oodpublication.ReceiptV8FromPhysicalRow(l.Receipt)
		if err != nil {
			return nil, err
		}
		batch, ok := byBatch[receipt.FetchBatchID]
		if !ok {
			return nil, fmt.Errorf("API symbol %q has no verified primary batch", symbol.ID)
		}
		body, err := archive.ReadArchivedCanonicalBytes(ctx, receipt)
		if err != nil {
			return nil, err
		}
		value := func(name string) string { s, _ := row.Columns[name].(string); return s }
		coordinate := oodevidence.APIElementSourceCoordinate{ObjectClass: value("object_class"), AuthorityID: value("source_authority_id"), RefKind: value("source_ref_kind"), StableReference: value("source_stable_reference"), VersionCoordinate: value("version_coordinate"), SectionPath: value("section_path")}
		binding := oodevidence.APIElementRoleBinding{Role: value("api_element_role"), LocatorManifestHash: value("api_element_role_locator_manifest_hash")}
		proof, err := oodevidence.VerifyAPIElementRoleV8(ctx, batch, l.Locator, body, coordinate, binding, roles)
		if err != nil {
			return nil, fmt.Errorf("API symbol %q role: %w", symbol.ID, err)
		}
		out = append(out, proof)
	}
	return out, nil
}
