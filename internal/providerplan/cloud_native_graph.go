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

// CloudNativeOperationCrosswalk is supplied by the sealed source-package
// author. It binds a provider catalog operation to the canonical source
// operation identity used by Verify; catalog strings are never treated as
// that identity in strict native mode.
type CloudNativeOperationCrosswalk struct {
	SourceSymbol                     string
	CanonicalSourceOperationIdentity json.RawMessage
	OperationSemanticKey             string
	OperationSymbolID                string
	ResourceAccesses                 []CloudNativeRelationshipCrosswalk
}

type CloudNativeResourceCrosswalk struct {
	SourceSymbol        string
	ResourceSemanticKey string
	ResourceSymbolID    string
}

func CloudNativeResourceBindingKey(modelSourceID, resourceID string) string {
	return lengthPrefixedIdentityKey(modelSourceID, resourceID)
}

// CloudNativeRelationshipCrosswalk carries the canonical relationship identity
// computed by the sealed source-package applicability profile. The catalog is
// evidence only; it may not invent an operation/resource or auth claim.
type CloudNativeRelationshipCrosswalk struct {
	Label          string
	SourceSymbolID string
	TargetSymbolID string
	RelationshipID string
}

func CloudNativeOperationBindingKey(modelSourceID, operationID string) string {
	return lengthPrefixedIdentityKey(modelSourceID, operationID)
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
	// SelectedOperationIDs is an explicit candidate selection, keyed by the
	// retained model source id. When present it prevents a native plan from
	// classifying the whole provider model by accident.
	SelectedOperationIDs map[string][]string
	// OperationCrosswalks enables strict native mode when non-nil. Every
	// selected operation must have a matching canonical source identity.
	OperationCrosswalks map[string]CloudNativeOperationCrosswalk
	ResourceCrosswalks  map[string]CloudNativeResourceCrosswalk
	// RelationshipLabels is the sealed applicability selection for hierarchy
	// and catalog-envelope edges, keyed by canonical capi_rel identity.
	RelationshipLabels map[string]string
}

// CloudNativeOfflineVerificationOptions binds a pre-sealed source-package
// scaffold to one provider's retained offline models. Unlike production source
// verification, it has no source-owner authentication or current-generation
// claim. The existing factory runner still executes its normal Verify path.
type CloudNativeOfflineVerificationOptions struct {
	Context           CloudNativeGraphContext
	Models            []PinnedCloudModel
	SourcePackagePath string
	OutputRoot        string
}

// CompileCloudNativeOfflineVerification is the only native-cloud bridge into
// the source-package compiler. It first makes the candidate JSONL, then
// requires the supplied sealed scaffold's api_graph artifact to contain those
// exact bytes before invoking the normal four-stage compiler and verifier.
// It never selects production authority, credentials, or admission.
func CompileCloudNativeOfflineVerification(options CloudNativeOfflineVerificationOptions) (DocumentationFactorySourceCompileResult, error) {
	graph, err := BuildCloudNativeGraphCandidateJSONL(options.Context, options.Models)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("build native offline graph: %w", err)
	}
	prepared, err := prepareDocumentationFactorySourceCompilation(options.SourcePackagePath)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("prepare sealed native source package: %w", err)
	}
	var matched bool
	for _, generated := range prepared.manifest.GeneratedDocuments {
		if generated.PackageRole != sourcePackageOutputRoleAPIGraphArtifact {
			continue
		}
		material, ok := prepared.materials[generated.coordinate()]
		if !ok || !bytes.Equal(material.raw, graph) {
			return DocumentationFactorySourceCompileResult{}, fmt.Errorf("sealed api_graph_artifact does not bind exact native offline graph bytes")
		}
		matched = true
	}
	if !matched {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("sealed source package has no api_graph_artifact")
	}
	return compilePreparedDocumentationFactorySourcePackage(DocumentationFactorySourceCompileOptions{SourcePackagePath: options.SourcePackagePath, OutputRoot: options.OutputRoot}, prepared, defaultDocumentationFactorySourceCompilerDependencies(), nil, nil)
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
	if err := validateCloudNativeSelectedOperations(context, models, catalogs); err != nil {
		return nil, err
	}
	sort.Slice(catalogs, func(i, j int) bool {
		return cloudNativeCatalogIdentity(catalogs[i]) < cloudNativeCatalogIdentity(catalogs[j])
	})

	locators := map[string]evidenceLocator{}
	symbols := map[string]apiSymbol{}
	gaps := make([]graphGap, 0)
	usedOperationCrosswalks := map[string]bool{}
	usedResourceCrosswalks := map[string]bool{}
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
			if gap, err := cloudNativeRelationshipGap(context, "provider_has_service", provider.ID, service.ID, locs, *model); err != nil {
				return nil, err
			} else {
				gaps = append(gaps, gap)
			}
		}
		selected := cloudNativeSelectedOperations(context, *model)
		all := cloudNativeSelectedCatalogLocators(catalog, selected)
		api, err := addSymbol("vendor_api", cloudNativeSemanticKey(catalog, "api", catalog.APISurfaceID), catalog.APISurfaceID+" "+catalog.APIVersion, all, *model)
		if err != nil {
			return nil, err
		}
		if gap, err := cloudNativeRelationshipGap(context, "service_has_api", service.ID, api.ID, all, *model); err != nil {
			return nil, err
		} else {
			gaps = append(gaps, gap)
		}
		resources := map[string]apiSymbol{}
		for _, resource := range catalog.Resources {
			if len(selected) != 0 {
				found := false
				for _, operation := range resource.OperationIDs {
					if selected[operation] {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			evidence := []CloudCatalogEvidenceLocator{resource.Locator}
			if resource.DeclarationEvidenceLocator != nil {
				evidence = append(evidence, *resource.DeclarationEvidenceLocator)
			}
			semantic := cloudNativeSemanticKey(catalog, "resource", resource.ID)
			var strictResource *CloudNativeResourceCrosswalk
			if context.OperationCrosswalks != nil {
				resourceKey := CloudNativeResourceBindingKey(model.Source.ID, resource.ID)
				binding, exists := context.ResourceCrosswalks[resourceKey]
				if !exists || binding.SourceSymbol == "" || binding.ResourceSemanticKey == "" || binding.ResourceSymbolID != stableID("capi_sym", lengthPrefixedIdentityKey("resource", binding.ResourceSemanticKey)) {
					return nil, fmt.Errorf("selected native resource %q lacks canonical sealed source crosswalk", resource.ID)
				}
				semantic = binding.ResourceSemanticKey
				strictResource = &binding
				usedResourceCrosswalks[resourceKey] = true
			}
			symbol, err := addSymbol("resource", semantic, resource.ID, evidence, *model)
			if err != nil {
				return nil, err
			}
			if strictResource != nil && symbol.ID != strictResource.ResourceSymbolID {
				return nil, fmt.Errorf("resource %q emitted symbol does not equal sealed crosswalk", resource.ID)
			}
			if strictResource != nil {
				if err := cloudNativeStrictBinding(context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("resource", semantic)], symbol, strictResource.SourceSymbol, "resource", context.Manifest.EvidenceSelectionRosterSHA256); err != nil {
					return nil, fmt.Errorf("resource %q strict binding: %w", resource.ID, err)
				}
			}
			resources[resource.ID] = symbol
			if gap, err := cloudNativeRelationshipGap(context, "api_has_resource", api.ID, symbol.ID, evidence, *model); err != nil {
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
			if len(selected) != 0 && !selected[operation.ID] {
				continue
			}
			evidence := append([]CloudCatalogEvidenceLocator{operation.Locator}, cloudNativeAssociationLocators(operation)...)
			semantic := cloudNativeSemanticKey(catalog, "operation", operation.ID)
			var strictCrosswalk *CloudNativeOperationCrosswalk
			if context.OperationCrosswalks != nil {
				operationKey := CloudNativeOperationBindingKey(model.Source.ID, operation.ID)
				binding, exists := context.OperationCrosswalks[operationKey]
				if !exists {
					return nil, fmt.Errorf("selected native operation %q lacks sealed source crosswalk", operation.ID)
				}
				var identity map[string]interface{}
				if err := strictUnmarshal(binding.CanonicalSourceOperationIdentity, &identity); err != nil {
					return nil, fmt.Errorf("operation %q canonical source identity: %w", operation.ID, err)
				}
				computed, err := sourceOperationSemanticKey(binding.SourceSymbol, identity)
				if err != nil {
					return nil, fmt.Errorf("operation %q canonical source identity: %w", operation.ID, err)
				}
				if binding.OperationSemanticKey != computed || binding.OperationSymbolID != stableID("capi_sym", lengthPrefixedIdentityKey("operation", computed)) {
					return nil, fmt.Errorf("operation %q sealed source crosswalk does not equal canonical operation symbol", operation.ID)
				}
				semantic = computed
				strictCrosswalk = &binding
				usedOperationCrosswalks[operationKey] = true
			}
			op, err := addSymbol("operation", semantic, operation.ID, evidence, *model)
			if err != nil {
				return nil, err
			}
			if strictCrosswalk != nil && op.ID != strictCrosswalk.OperationSymbolID {
				return nil, fmt.Errorf("operation %q emitted symbol does not equal sealed crosswalk", operation.ID)
			}
			if strictCrosswalk != nil {
				if err := cloudNativeStrictBinding(context.SymbolDerivationBindings[CloudNativeSymbolBindingKey("operation", semantic)], op, strictCrosswalk.SourceSymbol, "operation", context.Manifest.EvidenceSelectionRosterSHA256); err != nil {
					return nil, fmt.Errorf("operation %q strict binding: %w", operation.ID, err)
				}
			}
			// Provider and service are explicit evidence-bound envelope nodes; the
			// version remains part of the vendor_api's exact semantic identity.
			if gap, err := cloudNativeRelationshipGap(context, "api_has_operation", api.ID, op.ID, evidence, *model); err != nil {
				return nil, err
			} else {
				gaps = append(gaps, gap)
			}
			_ = op
			if strictCrosswalk != nil {
				seenRelationships := map[string]bool{}
				for _, relation := range strictCrosswalk.ResourceAccesses {
					if relation.SourceSymbolID != op.ID || relation.Label == "" || relation.TargetSymbolID == "" || relation.RelationshipID != stableID("capi_rel", lengthPrefixedIdentityKey(relation.Label, relation.SourceSymbolID, relation.TargetSymbolID)) {
						return nil, fmt.Errorf("operation %q has noncanonical sealed relationship crosswalk", operation.ID)
					}
					if seenRelationships[relation.RelationshipID] {
						return nil, fmt.Errorf("operation %q repeats sealed relationship crosswalk %q", operation.ID, relation.RelationshipID)
					}
					seenRelationships[relation.RelationshipID] = true
					if _, exists := resourcesByNativeID(resources)[relation.TargetSymbolID]; !exists {
						if _, authExists := resourcesByNativeID(auth)[relation.TargetSymbolID]; !authExists {
							return nil, fmt.Errorf("operation %q relationship target is not a selected resource/auth symbol", operation.ID)
						}
					}
					if gap, err := cloudNativeGap(context, op.ID, relation.RelationshipID, "api_symbol_object", "api_relationship", evidence, *model); err != nil {
						return nil, err
					} else {
						gaps = append(gaps, gap)
					}
				}
				continue
			}
			for _, resourceID := range operation.ResourceIDs {
				resource, found := resources[resourceID]
				if !found {
					return nil, fmt.Errorf("operation %q references unknown catalog resource %q", operation.ID, resourceID)
				}
				if gap, err := cloudNativeRelationshipGap(context, "operation_reads_resource", op.ID, resource.ID, evidence, *model); err != nil {
					return nil, err
				} else {
					gaps = append(gaps, gap)
				}
				if gap, err := cloudNativeRelationshipGap(context, "resource_has_operation", resource.ID, op.ID, evidence, *model); err != nil {
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
				if gap, err := cloudNativeRelationshipGap(context, "operation_requires_auth_scheme", op.ID, requirement.ID, evidence, *model); err != nil {
					return nil, err
				} else {
					gaps = append(gaps, gap)
				}
			}
		}
		_ = index
	}
	if context.OperationCrosswalks != nil {
		if len(usedOperationCrosswalks) != len(context.OperationCrosswalks) || len(usedResourceCrosswalks) != len(context.ResourceCrosswalks) {
			return nil, fmt.Errorf("strict native crosswalk maps contain unknown or unselected entries")
		}
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

func cloudNativeSelectedOperations(context CloudNativeGraphContext, model PinnedCloudModel) map[string]bool {
	ids := context.SelectedOperationIDs[model.Source.ID]
	selected := make(map[string]bool, len(ids))
	for _, id := range ids {
		selected[id] = true
	}
	return selected
}

func resourcesByNativeID(values map[string]apiSymbol) map[string]apiSymbol {
	result := make(map[string]apiSymbol, len(values))
	for _, value := range values {
		result[value.ID] = value
	}
	return result
}

func cloudNativeStrictBinding(raw json.RawMessage, symbol apiSymbol, sourceSymbol, surfaceKind, roster string) error {
	var binding candidateAPISymbolDerivationBinding
	if err := strictUnmarshal(raw, &binding); err != nil {
		return fmt.Errorf("is not candidate API symbol derivation binding: %w", err)
	}
	if binding.Kind != apiSymbolDerivationBindingKind || binding.SourceSymbol != sourceSymbol || binding.SurfaceKind != surfaceKind || binding.EvidenceSelectionRosterSHA256 != roster {
		return fmt.Errorf("does not equal sealed source/surface/roster binding")
	}
	if binding.ID != candidateAPISymbolDerivationBindingID(symbol.ID, binding) {
		return fmt.Errorf("candidate derivation binding id does not equal symbol binding")
	}
	return nil
}

func validateCloudNativeSelectedOperations(context CloudNativeGraphContext, models []PinnedCloudModel, catalogs []CloudCatalog) error {
	if context.SelectedOperationIDs == nil {
		return nil
	}
	byModel := make(map[string]CloudCatalog, len(models))
	for index, model := range models {
		byModel[model.Source.ID] = catalogs[index]
	}
	for sourceID, operations := range context.SelectedOperationIDs {
		catalog, found := byModel[sourceID]
		if !found {
			return fmt.Errorf("selected operation set names unknown retained model source %q", sourceID)
		}
		if len(operations) == 0 {
			return fmt.Errorf("selected operation set for retained model source %q is empty", sourceID)
		}
		known := map[string]struct{}{}
		for _, operation := range catalog.Operations {
			known[operation.ID] = struct{}{}
		}
		seen := map[string]struct{}{}
		for _, operation := range operations {
			if _, duplicate := seen[operation]; duplicate {
				return fmt.Errorf("selected operation set for retained model source %q duplicates %q", sourceID, operation)
			}
			seen[operation] = struct{}{}
			if _, exists := known[operation]; !exists {
				return fmt.Errorf("selected operation set for retained model source %q names unknown operation %q", sourceID, operation)
			}
		}
	}
	return nil
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
	if ctx.BlockedSubjectKind != blockedSubjectKind || ctx.BlockedClaimKind != blockedClaimKind || ctx.BlockedClaimID != blockedClaimID {
		return graphGap{}, fmt.Errorf("native graph gap %s/%s does not equal sealed subject/claim context", blockedSubjectID, blockedClaimID)
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

func cloudNativeRelationshipGap(c CloudNativeGraphContext, label, sourceID, targetID string, evidence []CloudCatalogEvidenceLocator, model PinnedCloudModel) (graphGap, error) {
	if c.OperationCrosswalks == nil {
		legacy := label + ":" + targetID
		switch label {
		case "operation_reads_resource":
			legacy = "operation_resource_association:" + targetID
		case "operation_requires_auth_scheme":
			legacy = "operation_requires_auth_scheme:" + targetID
		}
		return cloudNativeGap(c, sourceID, legacy, "api_symbol_object", "api_relationship", evidence, model)
	}
	claimID := stableID("capi_rel", lengthPrefixedIdentityKey(label, sourceID, targetID))
	if actual, ok := c.RelationshipLabels[claimID]; !ok || actual != label {
		return graphGap{}, fmt.Errorf("native strict relationship %q lacks sealed canonical selection", claimID)
	}
	return cloudNativeGap(c, sourceID, claimID, "api_symbol_object", "api_relationship", evidence, model)
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

// cloudNativeSelectedCatalogLocators keeps the API envelope bounded by the
// explicit candidate operation selection.  A selected target must never
// silently classify every operation/resource in a retained provider model.
func cloudNativeSelectedCatalogLocators(c CloudCatalog, selected map[string]bool) []CloudCatalogEvidenceLocator {
	if len(selected) == 0 {
		return cloudNativeCatalogLocators(c)
	}
	out := make([]CloudCatalogEvidenceLocator, 0)
	for _, resource := range c.Resources {
		included := false
		for _, operationID := range resource.OperationIDs {
			if selected[operationID] {
				included = true
				break
			}
		}
		if !included {
			continue
		}
		out = append(out, resource.Locator)
		if resource.DeclarationEvidenceLocator != nil {
			out = append(out, *resource.DeclarationEvidenceLocator)
		}
	}
	for _, operation := range c.Operations {
		if selected[operation.ID] {
			out = append(out, operation.Locator)
			out = append(out, cloudNativeAssociationLocators(operation)...)
		}
	}
	for _, authentication := range c.Authentication {
		out = append(out, authentication.Locator)
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
