package providerplan

// This file is deliberately an adapter to the existing provider-plan JSONL
// dialect. Cloud catalogs are evidence-local inventories, not an authority to
// manufacture the classification or typed-predecessor proofs required by
// Verify. Consequently every non-inventory binding below is supplied by the
// caller's sealed compilation context and is rejected when absent.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CloudNativeGraphManifest is the exact dependency commitment carried by an
// artifact_manifest row. These hashes must come from the sealed source-package
// compilation inputs; a catalog parser never supplies them.
type CloudNativeGraphManifest struct {
	Artifact                                  string
	ArtifactVersion                           string
	CanonicalOODGraphSHA256                   string
	ProviderNeutralProfileSHA256              string
	SourceContractIndexSHA256                 string
	SampleShapeIndexSHA256                    string
	ProtocolContractIndexSHA256               string
	EvidenceSelectionRosterSHA256             string
	OperationApplicabilityProfileSHA256       string
	FieldMappingCandidateSHA256               string
	FieldSecurityPolicySHA256                 string
	MappingTransitiveDependencyRosterSHA256   string
	DocumentationClaimDerivationProfileSHA256 string
	APIGraphApplicabilityProfileSHA256        string
	DependencySemanticValidation              dependencySemanticValidationPlanBinding
	EvidenceLocatorManifestSHA256             string
	EvidenceManifestBindings                  []evidenceManifestBinding
}

// CloudNativeGapContext carries an already-derived fail-closed gap. In
// particular, it does not turn an association asserted by a catalog into a
// positive API relationship.
type CloudNativeGapContext struct {
	GapClass                    string
	BlockedSubjectKind          string
	BlockedClaimKind            string
	BlockedClaimID              string
	ApplicabilityProfileID      string
	ApplicabilityProfileVersion string
	ApplicabilityProfileSHA256  string
	ApplicabilityRuleID         string
	GapProofBinding             json.RawMessage
	DerivationBinding           json.RawMessage
}

type CloudNativeEvidenceReference struct {
	ModelSourceID string
	Locator       CloudCatalogEvidenceLocator
}

// CloudNativeGraphContext is intentionally proof-heavy. A key is the value
// returned by CloudNativeSymbolBindingKey or CloudNativeGapBindingKey.
// EvidenceManifestSHA256ByEvidenceID binds "model" and each supplemental
// evidence id to the separately retained source-document manifest.
type CloudNativeGraphContext struct {
	Provider                           string
	Manifest                           CloudNativeGraphManifest
	EvidenceManifestSHA256ByEvidenceID map[string]string
	SymbolDerivationBindings           map[string]json.RawMessage
	GapContexts                        map[string]CloudNativeGapContext
	HierarchyEvidence                  map[string][]CloudNativeEvidenceReference
}

func CloudNativeSymbolBindingKey(role, semanticKey string) string {
	return lengthPrefixedIdentityKey(role, semanticKey)
}

func CloudNativeGapBindingKey(blockedSubjectID, blockedClaimID string) string {
	return lengthPrefixedIdentityKey(blockedSubjectID, blockedClaimID)
}

// BuildCloudNativeGraphCandidateJSONL emits only the existing, closed native
// graph-plan rows. It is one-provider-per-plan: mixed AWS/GCP (or any other
// provider) inputs fail before any output is produced. This constructor cannot
// establish the in-process classification-selection or typed-predecessor seals
// that Verify independently obtains from a sealed source package; it produces
// a structurally shaped, candidate-only body and must not be reported as a
// successful Verify/admission result.
func BuildCloudNativeGraphCandidateJSONL(context CloudNativeGraphContext, models []PinnedCloudModel) ([]byte, error) {
	if len(models) == 0 || strings.TrimSpace(context.Provider) == "" {
		return nil, fmt.Errorf("native cloud graph requires one provider and at least one retained model")
	}
	if err := validateCloudNativeGraphContext(context); err != nil {
		return nil, err
	}

	catalogs := make([]CloudCatalog, len(models))
	for i, model := range models {
		if model.ProviderID != context.Provider {
			return nil, fmt.Errorf("native cloud graph is per-provider: model provider %q does not equal context provider %q", model.ProviderID, context.Provider)
		}
		catalog, err := ParsePinnedCloudModel(model)
		if err != nil {
			return nil, fmt.Errorf("parse retained model %q: %w", model.Source.ID, err)
		}
		catalogs[i] = catalog
	}
	sort.Slice(catalogs, func(i, j int) bool {
		return cloudNativeCatalogIdentity(catalogs[i]) < cloudNativeCatalogIdentity(catalogs[j])
	})

	locators := map[string]evidenceLocator{}
	symbols := map[string]apiSymbol{}
	gaps := make([]graphGap, 0)
	addSymbol := func(role, semantic, display string, evidence []CloudCatalogEvidenceLocator, model PinnedCloudModel) (apiSymbol, error) {
		ids := make([]string, 0, len(evidence))
		for _, item := range evidence {
			locator, err := cloudNativeEvidenceLocator(context, model, item)
			if err != nil {
				return apiSymbol{}, err
			}
			locators[locator.ID] = locator
			ids = append(ids, locator.ID)
		}
		ids = sortedCloudNativeStrings(ids)
		if len(ids) == 0 {
			return apiSymbol{}, fmt.Errorf("native symbol %q has no retained evidence locator", semantic)
		}
		id := stableID("capi_sym", lengthPrefixedIdentityKey(role, semantic))
		binding, ok := context.SymbolDerivationBindings[CloudNativeSymbolBindingKey(role, semantic)]
		if !ok || len(bytes.TrimSpace(binding)) == 0 {
			return apiSymbol{}, fmt.Errorf("native symbol %q lacks sealed classification derivation binding", semantic)
		}
		symbol := apiSymbol{RowKind: "candidate_api_symbol", ID: id, Role: role, SemanticKey: semantic, DisplayName: display, EvidenceLocatorIDs: ids, DerivationBinding: binding, AuthorityStatus: symbolAuthorityStatusExact}
		if _, duplicate := symbols[id]; duplicate {
			return apiSymbol{}, fmt.Errorf("native symbol identity collision for %q", semantic)
		}
		symbols[id] = symbol
		return symbol, nil
	}
	addHierarchy := func(role, semantic, display string) (apiSymbol, error) {
		refs := context.HierarchyEvidence[CloudNativeSymbolBindingKey(role, semantic)]
		if len(refs) == 0 {
			return apiSymbol{}, fmt.Errorf("native hierarchy symbol %q lacks separately selected exact evidence", semantic)
		}
		ids := []string{}
		for _, ref := range refs {
			var found *PinnedCloudModel
			for i := range models {
				if models[i].Source.ID == ref.ModelSourceID {
					found = &models[i]
					break
				}
			}
			if found == nil {
				return apiSymbol{}, fmt.Errorf("native hierarchy symbol %q references unretained model source %q", semantic, ref.ModelSourceID)
			}
			loc, err := cloudNativeEvidenceLocator(context, *found, ref.Locator)
			if err != nil {
				return apiSymbol{}, err
			}
			locators[loc.ID] = loc
			ids = append(ids, loc.ID)
		}
		ids = sortedCloudNativeStrings(ids)
		id := stableID("capi_sym", lengthPrefixedIdentityKey(role, semantic))
		binding, ok := context.SymbolDerivationBindings[CloudNativeSymbolBindingKey(role, semantic)]
		if !ok || len(bytes.TrimSpace(binding)) == 0 {
			return apiSymbol{}, fmt.Errorf("native symbol %q lacks sealed classification derivation binding", semantic)
		}
		s := apiSymbol{RowKind: "candidate_api_symbol", ID: id, Role: role, SemanticKey: semantic, DisplayName: display, EvidenceLocatorIDs: ids, DerivationBinding: binding, AuthorityStatus: symbolAuthorityStatusExact}
		symbols[id] = s
		return s, nil
	}
	providerSemantic := cloudNativeProviderSemanticKey(context.Provider)
	provider, err := addHierarchy("provider", providerSemantic, context.Provider)
	if err != nil {
		return nil, err
	}
	services := map[string]apiSymbol{}

	for index, catalog := range catalogs {
		model := findCloudNativeModel(models, catalog)
		if model == nil {
			return nil, fmt.Errorf("retained model for catalog %q disappeared", cloudNativeCatalogIdentity(catalog))
		}
		serviceSemantic := cloudNativeServiceSemanticKey(catalog.ProviderID, catalog.ServiceID)
		service, exists := services[serviceSemantic]
		if !exists {
			service, err = addHierarchy("service", serviceSemantic, catalog.ServiceID)
			if err != nil {
				return nil, err
			}
			services[serviceSemantic] = service
			ev := context.HierarchyEvidence[CloudNativeSymbolBindingKey("service", serviceSemantic)]
			locs := []CloudCatalogEvidenceLocator{}
			for _, v := range ev {
				locs = append(locs, v.Locator)
			}
			if gap, err := cloudNativeGap(context, provider.ID, "provider_has_service:"+service.ID, "api_symbol_object", "api_relationship", locs, *model); err != nil {
				return nil, err
			} else {
				gaps = append(gaps, gap)
			}
		}
		all := cloudNativeCatalogLocators(catalog)
		api, err := addSymbol("vendor_api", cloudNativeSemanticKey(catalog, "api", catalog.APISurfaceID), catalog.APISurfaceID+" "+catalog.APIVersion, all, *model)
		if err != nil {
			return nil, err
		}
		if gap, err := cloudNativeGap(context, service.ID, "service_has_api:"+api.ID, "api_symbol_object", "api_relationship", all, *model); err != nil {
			return nil, err
		} else {
			gaps = append(gaps, gap)
		}
		resources := map[string]apiSymbol{}
		for _, resource := range catalog.Resources {
			evidence := []CloudCatalogEvidenceLocator{resource.Locator}
			if resource.DeclarationEvidenceLocator != nil {
				evidence = append(evidence, *resource.DeclarationEvidenceLocator)
			}
			symbol, err := addSymbol("resource", cloudNativeSemanticKey(catalog, "resource", resource.ID), resource.ID, evidence, *model)
			if err != nil {
				return nil, err
			}
			resources[resource.ID] = symbol
			if gap, err := cloudNativeGap(context, api.ID, "api_has_resource:"+symbol.ID, "api_symbol_object", "api_relationship", evidence, *model); err != nil {
				return nil, err
			} else {
				gaps = append(gaps, gap)
			}
		}
		auth := map[string]apiSymbol{}
		for _, requirement := range catalog.Authentication {
			symbol, err := addSymbol("auth_scheme", cloudNativeSemanticKey(catalog, "auth", requirement.ID), requirement.ID, []CloudCatalogEvidenceLocator{requirement.Locator}, *model)
			if err != nil {
				return nil, err
			}
			auth[requirement.ID] = symbol
		}
		for _, operation := range catalog.Operations {
			evidence := append([]CloudCatalogEvidenceLocator{operation.Locator}, cloudNativeAssociationLocators(operation)...)
			op, err := addSymbol("operation", cloudNativeSemanticKey(catalog, "operation", operation.ID), operation.ID, evidence, *model)
			if err != nil {
				return nil, err
			}
			// The registry has no provider/service/version node roles. The vendor_api
			// semantic key is the evidence-bound Matryoshka envelope for those values.
			if gap, err := cloudNativeGap(context, api.ID, "api_has_operation:"+op.ID, "api_symbol_object", "api_relationship", evidence, *model); err != nil {
				return nil, err
			} else {
				gaps = append(gaps, gap)
			}
			_ = op
			for _, resourceID := range operation.ResourceIDs {
				resource, found := resources[resourceID]
				if !found {
					return nil, fmt.Errorf("operation %q references unknown catalog resource %q", operation.ID, resourceID)
				}
				if gap, err := cloudNativeGap(context, op.ID, "operation_resource_association:"+resource.ID, "api_symbol_object", "api_relationship", evidence, *model); err != nil {
					return nil, err
				} else {
					gaps = append(gaps, gap)
				}
				if gap, err := cloudNativeGap(context, resource.ID, "resource_has_operation:"+op.ID, "api_symbol_object", "api_relationship", evidence, *model); err != nil {
					return nil, err
				} else {
					gaps = append(gaps, gap)
				}
			}
			for _, requirementID := range operation.AuthenticationRequirementIDs {
				requirement, found := auth[requirementID]
				if !found {
					return nil, fmt.Errorf("operation %q references unknown authentication requirement %q", operation.ID, requirementID)
				}
				if gap, err := cloudNativeGap(context, op.ID, "operation_requires_auth_scheme:"+requirement.ID, "api_symbol_object", "api_relationship", evidence, *model); err != nil {
					return nil, err
				} else {
					gaps = append(gaps, gap)
				}
			}
		}
		_ = index
	}

	rows := make([]any, 0, 2+len(locators)+len(symbols)+len(gaps))
	manifest := artifactManifest{RowKind: "artifact_manifest", Artifact: context.Manifest.Artifact, ArtifactVersion: context.Manifest.ArtifactVersion, Status: "candidate_not_admissible_or_executable", Provider: context.Provider, NamedSystem: "Velenza BOC", CanonicalOODGraphSHA256: context.Manifest.CanonicalOODGraphSHA256, ProviderNeutralProfileSHA256: context.Manifest.ProviderNeutralProfileSHA256, SourceContractIndexSHA256: context.Manifest.SourceContractIndexSHA256, SampleShapeIndexSHA256: context.Manifest.SampleShapeIndexSHA256, ProtocolContractIndexSHA256: context.Manifest.ProtocolContractIndexSHA256, EvidenceSelectionRosterSHA256: context.Manifest.EvidenceSelectionRosterSHA256, OperationApplicabilityProfileSHA256: context.Manifest.OperationApplicabilityProfileSHA256, EvidenceManifestBindings: context.Manifest.EvidenceManifestBindings, FieldMappingCandidateSHA256: context.Manifest.FieldMappingCandidateSHA256, FieldSecurityPolicySHA256: context.Manifest.FieldSecurityPolicySHA256, MappingTransitiveDependencyRosterSHA256: context.Manifest.MappingTransitiveDependencyRosterSHA256, DocumentationClaimDerivationProfileSHA256: context.Manifest.DocumentationClaimDerivationProfileSHA256, APIGraphApplicabilityProfileSHA256: context.Manifest.APIGraphApplicabilityProfileSHA256, DependencySemanticValidation: context.Manifest.DependencySemanticValidation, EvidenceLocatorManifestSHA256: context.Manifest.EvidenceLocatorManifestSHA256}
	rows = append(rows, manifest)
	for _, id := range sortedProviderStringMapKeys(locators) {
		rows = append(rows, locators[id])
	}
	for _, id := range sortedProviderStringMapKeys(symbols) {
		rows = append(rows, symbols[id])
	}
	sort.Slice(gaps, func(i, j int) bool { return gaps[i].ID < gaps[j].ID })
	for _, gap := range gaps {
		rows = append(rows, gap)
	}

	// Roots are computed from the same closed dispositions as Verify; the
	// summary itself is metadata and therefore does not recurse into its roots.
	withoutSummary, err := cloudNativeJSONL(rows)
	if err != nil {
		return nil, err
	}
	sets, err := deriveStageGraphSets(withoutSummary, cloudNativeGraphRowDispositions())
	if err != nil {
		return nil, fmt.Errorf("derive native graph commitments: %w", err)
	}
	operationCount := 0
	for _, symbol := range symbols {
		if symbol.Role == "operation" {
			operationCount++
		}
	}
	summary := validationSummary{RowKind: "validation_summary", ExactSourceDocumentCount: len(models), CandidateOperationCount: operationCount, CapturedOperationKindCounts: []operationKindCount{{OperationKind: "request_response_read_operation", Count: operationCount}}, CandidateEvidenceLocatorCount: len(locators), CandidateAPISymbolCount: len(symbols), CandidateGraphGapCount: len(gaps), APIElementRolesMaterialized: cloudNativeRoleCount(symbols), OperationApplicabilityCount: operationCount, CandidateSubjectCount: len(symbols), SubjectSetRootSHA256: sets["subject"].RootSHA256, FactSetRootSHA256: sets["fact"].RootSHA256, GapSetRootSHA256: sets["gap"].RootSHA256, Result: resultCompleteWithGap}
	rows = append(rows, summary)
	return cloudNativeJSONL(rows)
}

func validateCloudNativeGraphContext(c CloudNativeGraphContext) error {
	m := c.Manifest
	for _, pair := range []struct{ name, value string }{{"artifact", m.Artifact}, {"artifact_version", m.ArtifactVersion}, {"canonical_ood_graph_sha256", m.CanonicalOODGraphSHA256}, {"provider_neutral_profile_sha256", m.ProviderNeutralProfileSHA256}, {"source_contract_index_sha256", m.SourceContractIndexSHA256}, {"sample_shape_index_sha256", m.SampleShapeIndexSHA256}, {"protocol_contract_index_sha256", m.ProtocolContractIndexSHA256}, {"evidence_selection_roster_sha256", m.EvidenceSelectionRosterSHA256}, {"operation_applicability_profile_sha256", m.OperationApplicabilityProfileSHA256}, {"field_mapping_candidate_sha256", m.FieldMappingCandidateSHA256}, {"field_security_policy_sha256", m.FieldSecurityPolicySHA256}, {"mapping_transitive_dependency_roster_sha256", m.MappingTransitiveDependencyRosterSHA256}, {"documentation_claim_derivation_profile_sha256", m.DocumentationClaimDerivationProfileSHA256}, {"api_graph_applicability_profile_sha256", m.APIGraphApplicabilityProfileSHA256}, {"evidence_locator_manifest_sha256", m.EvidenceLocatorManifestSHA256}} {
		if pair.name == "artifact" || pair.name == "artifact_version" {
			if strings.TrimSpace(pair.value) == "" {
				return fmt.Errorf("native graph context %s is required", pair.name)
			}
		} else if !isLowerSHA256(pair.value) {
			return fmt.Errorf("native graph context %s must be lowercase SHA-256", pair.name)
		}
	}
	if len(m.EvidenceManifestBindings) == 0 {
		return fmt.Errorf("native graph context has no evidence manifest bindings")
	}
	return nil
}

func cloudNativeGap(c CloudNativeGraphContext, blockedSubjectID, blockedClaimID, blockedSubjectKind, blockedClaimKind string, evidence []CloudCatalogEvidenceLocator, model PinnedCloudModel) (graphGap, error) {
	ctx, ok := c.GapContexts[CloudNativeGapBindingKey(blockedSubjectID, blockedClaimID)]
	if !ok {
		return graphGap{}, fmt.Errorf("native graph gap %s/%s lacks sealed applicability context", blockedSubjectID, blockedClaimID)
	}
	ids := make([]string, 0, len(evidence))
	for _, item := range evidence {
		locator, err := cloudNativeEvidenceLocator(c, model, item)
		if err != nil {
			return graphGap{}, err
		}
		ids = append(ids, locator.ID)
	}
	ids = sortedCloudNativeStrings(ids)
	gap := graphGap{RowKind: "candidate_graph_gap", GapClass: ctx.GapClass, BlockedSubjectKind: blockedSubjectKind, BlockedSubjectID: blockedSubjectID, BlockedClaimKind: blockedClaimKind, BlockedClaimID: blockedClaimID, Disposition: "fail_closed", ApplicabilityProfileID: ctx.ApplicabilityProfileID, ApplicabilityProfileVersion: ctx.ApplicabilityProfileVersion, ApplicabilityProfileSHA256: ctx.ApplicabilityProfileSHA256, ApplicabilityRuleID: ctx.ApplicabilityRuleID, EvidenceLocatorIDs: ids, GapProofBinding: ctx.GapProofBinding, DerivationBinding: ctx.DerivationBinding}
	identity, err := candidateGraphGapIdentityKey(gap)
	if err != nil {
		return graphGap{}, err
	}
	gap.ID = stableID("capi_gap", identity)
	return gap, nil
}

func cloudNativeEvidenceLocator(c CloudNativeGraphContext, model PinnedCloudModel, item CloudCatalogEvidenceLocator) (evidenceLocator, error) {
	var raw []byte
	var source CloudCatalogSourceIdentity
	if item.EvidenceID == "model" {
		raw = model.Raw
		source = model.Source
	} else {
		found := false
		for _, supplemental := range model.SupplementalEvidence {
			if supplemental.ID == item.EvidenceID {
				raw = supplemental.Raw
				source = supplemental.Source
				found = true
				break
			}
		}
		if !found {
			return evidenceLocator{}, fmt.Errorf("locator names unknown retained evidence %q", item.EvidenceID)
		}
	}
	manifest, ok := c.EvidenceManifestSHA256ByEvidenceID[item.EvidenceID]
	if !ok || !isLowerSHA256(manifest) {
		return evidenceLocator{}, fmt.Errorf("retained evidence %q lacks exact evidence-manifest digest", item.EvidenceID)
	}
	if !cloudNativeManifestBindsEvidence(c.Manifest, manifest) {
		return evidenceLocator{}, fmt.Errorf("retained evidence %q names manifest %s absent from artifact manifest bindings", item.EvidenceID, manifest)
	}
	if item.StartByte < 0 || item.EndByte <= item.StartByte || item.EndByte > len(raw) {
		return evidenceLocator{}, fmt.Errorf("retained evidence %q has invalid exact range", item.EvidenceID)
	}
	selected := raw[item.StartByte:item.EndByte]
	l := evidenceLocator{RowKind: "candidate_evidence_locator", EvidenceManifestSHA256: manifest, SourceContentSHA256: sha256Hex(raw), ByteStartOffset: int64(item.StartByte), ByteEndOffsetExclusive: int64(item.EndByte), SelectedRangeByteCount: int64(len(selected)), SelectedRangeSHA256: sha256Hex(selected), SourceRefs: []string{source.StableCoordinate}, SourceURLs: []string{source.URI}, LocatorSemantics: exactLocatorSemantics}
	l.ID = stableID("evloc", candidateEvidenceLocatorIdentityKey(l))
	return l, nil
}

func cloudNativeManifestBindsEvidence(manifest CloudNativeGraphManifest, digest string) bool {
	for _, binding := range manifest.EvidenceManifestBindings {
		if binding.EvidenceManifestSHA256 == digest {
			return true
		}
	}
	return false
}

func cloudNativeCatalogIdentity(c CloudCatalog) string {
	return lengthPrefixedIdentityKey(c.ProviderID, c.ServiceID, c.APISurfaceID, c.APIVersion, c.ModelSHA256)
}
func cloudNativeSemanticKey(c CloudCatalog, kind, id string) string {
	return lengthPrefixedIdentityKey("cloud_catalog_candidate_v1", c.ProviderID, c.ServiceID, c.APISurfaceID, c.APIVersion, c.ModelSHA256, kind, id)
}
func cloudNativeProviderSemanticKey(provider string) string {
	return lengthPrefixedIdentityKey("cloud_catalog_candidate_v1", "provider", provider)
}
func cloudNativeServiceSemanticKey(provider, service string) string {
	return lengthPrefixedIdentityKey("cloud_catalog_candidate_v1", "service", provider, service)
}
func findCloudNativeModel(models []PinnedCloudModel, catalog CloudCatalog) *PinnedCloudModel {
	for i := range models {
		m := &models[i]
		if m.ProviderID == catalog.ProviderID && m.ServiceID == catalog.ServiceID && m.APISurfaceID == catalog.APISurfaceID && m.APIVersion == catalog.APIVersion && m.ExpectedSHA256 == catalog.ModelSHA256 {
			return m
		}
	}
	return nil
}
func cloudNativeAssociationLocators(operation CloudCatalogOperation) []CloudCatalogEvidenceLocator {
	out := make([]CloudCatalogEvidenceLocator, 0, len(operation.ResourceAssociationEvidence))
	for _, e := range operation.ResourceAssociationEvidence {
		out = append(out, e.EvidenceLocator)
	}
	return out
}
func cloudNativeCatalogLocators(c CloudCatalog) []CloudCatalogEvidenceLocator {
	out := make([]CloudCatalogEvidenceLocator, 0)
	for _, v := range c.Resources {
		out = append(out, v.Locator)
		if v.DeclarationEvidenceLocator != nil {
			out = append(out, *v.DeclarationEvidenceLocator)
		}
	}
	for _, v := range c.Operations {
		out = append(out, v.Locator)
		out = append(out, cloudNativeAssociationLocators(v)...)
	}
	for _, v := range c.Authentication {
		out = append(out, v.Locator)
	}
	return out
}
func sortedCloudNativeStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, v := range values {
		set[v] = struct{}{}
	}
	return sortedSetKeys(set)
}
func cloudNativeRoleCount(symbols map[string]apiSymbol) int {
	set := map[string]struct{}{}
	for _, s := range symbols {
		set[s.Role] = struct{}{}
	}
	return len(set)
}
func cloudNativeJSONL(rows []any) ([]byte, error) {
	var out bytes.Buffer
	for _, row := range rows {
		raw, err := canonicalFactoryJSON(row)
		if err != nil {
			return nil, err
		}
		out.Write(raw)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// These are the sealed native parser dispositions, reproduced here only to
// commit the emitted rows. They deliberately contain no catalog-specific row
// kind and match the stage contract's subject/fact/gap separation.
func cloudNativeGraphRowDispositions() []stageGraphRowDisposition {
	return []stageGraphRowDisposition{
		{RowKind: "artifact_manifest", SetKinds: []string{"metadata"}},
		{RowKind: "candidate_evidence_locator", SetKinds: []string{"metadata"}},
		{RowKind: "candidate_api_symbol", SetKinds: []string{"subject"}},
		{RowKind: "candidate_api_relationship", SetKinds: []string{"fact", "subject"}},
		{RowKind: "candidate_api_property_claim", SetKinds: []string{"fact"}},
		{RowKind: "candidate_graph_gap", SetKinds: []string{"gap"}},
		{RowKind: "validation_summary", SetKinds: []string{"metadata"}},
	}
}
