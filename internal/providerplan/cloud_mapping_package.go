package providerplan

// This file composes the selected four-service cloud mapping closure into
// reviewable, candidate-only provider packages. It is deliberately below
// source qualification and authoritative graph materialization: a catalog
// parser and a mapping contract can prove exact retained bytes and complete
// disposition accounting, but cannot authenticate an evidence producer,
// create a source instance, or admit a graph.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

const (
	cloudMappingPackageVersion = "1"
	cloudMappingPackageStatus  = "candidate_complete_unqualified"
	cloudMappingParentRole     = "cloud_mapping_parent_manifest"
)

// CloudMappingDispositionTotals is the complete selected mapping closure.
// Mapped includes exact source, lifecycle, and relationship facts. Private
// and unsupported fields remain explicit outcomes, never omitted fields.
type CloudMappingDispositionTotals struct {
	Mapped      int `json:"mapped"`
	NotObserved int `json:"not_observed"`
	Private     int `json:"private"`
	Unknown     int `json:"unknown"`
	Unsupported int `json:"unsupported"`
}

func (totals CloudMappingDispositionTotals) total() int {
	return totals.Mapped + totals.NotObserved + totals.Private + totals.Unknown + totals.Unsupported
}

// CloudProviderMappingPackage identifies one provider-local document in the
// four-service parent package. DocumentSHA256 is over exact canonical bytes,
// including the terminating newline.
type CloudProviderMappingPackage struct {
	ProviderID        string                         `json:"provider_id"`
	DocumentRole      string                         `json:"document_role"`
	DocumentSHA256    string                         `json:"document_sha256"`
	Catalogs          []CloudMappingCatalogReference `json:"catalogs"`
	CatalogSourceIDs  []string                       `json:"catalog_source_ids"`
	TargetKeys        []string                       `json:"target_keys"`
	DispositionTotals CloudMappingDispositionTotals  `json:"disposition_totals"`
}

// CloudMappingCatalogReference keeps the complete parsed-catalog identity
// that the provider document exposes. It prevents a writer from accepting a
// body whose source ID happens to match while its model/version lineage differs.
type CloudMappingCatalogReference struct {
	Source       CloudCatalogSourceIdentity `json:"source"`
	Format       CloudCatalogFormat         `json:"format"`
	ProviderID   string                     `json:"provider_id"`
	ServiceID    string                     `json:"service_id"`
	APISurfaceID string                     `json:"api_surface_id"`
	APIVersion   string                     `json:"api_version"`
	ModelSHA256  string                     `json:"model_sha256"`
}

// CloudMappingPackage is a portable deterministic package boundary. The
// parent manifest ties the two provider packages together without asserting
// source qualification, Canon materialization, admission, credentials, or
// customer acquisition.
type CloudMappingPackage struct {
	Status                 string                        `json:"status"`
	Version                string                        `json:"version"`
	ScopeSHA256            string                        `json:"scope_sha256"`
	ProviderPackages       []CloudProviderMappingPackage `json:"provider_packages"`
	DispositionTotals      CloudMappingDispositionTotals `json:"disposition_totals"`
	Documents              map[string][]byte             `json:"-"`
	UnresolvedDependencies []string                      `json:"unresolved_dependencies"`
}

// CloudMappingCatalogSelection seals one catalog identity into a selected
// mapping scope. It keeps the data choice outside the generic package builder.
type CloudMappingCatalogSelection struct {
	ProviderID    string `json:"provider_id"`
	ServiceID     string `json:"service_id"`
	APISurfaceID  string `json:"api_surface_id"`
	ModelSourceID string `json:"model_source_id"`
}

// CloudMappingTargetSelection identifies one selected source-object mapping.
// It deliberately does not encode a model revision: that is retained in the
// exact catalog bytes and source-mapping lineage.
type CloudMappingTargetSelection struct {
	ProviderID        string `json:"provider_id"`
	ServiceID         string `json:"service_id"`
	APISurfaceID      string `json:"api_surface_id"`
	OperationID       string `json:"operation_id"`
	SourceObjectType  string `json:"source_object_type"`
	RecordClassSymbol string `json:"record_class_symbol"`
}

// CloudMappingPackageScope is owned data, not mechanism. It can describe a
// different selected provider set without a Go change; a caller must bind the
// exact scope bytes into its surrounding source-package evidence closure.
type CloudMappingPackageScope struct {
	ScopeID                   string                         `json:"scope_id"`
	Catalogs                  []CloudMappingCatalogSelection `json:"catalogs"`
	Targets                   []CloudMappingTargetSelection  `json:"targets"`
	ExpectedDispositionTotals CloudMappingDispositionTotals  `json:"expected_disposition_totals"`
}

// LoadCloudMappingPackageScope reads a declarative, reviewable selection
// contract. Loading does not qualify the contract; its caller must retain the
// resulting exact bytes in the source-package evidence closure.
func LoadCloudMappingPackageScope(path string) (CloudMappingPackageScope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CloudMappingPackageScope{}, err
	}
	var scope CloudMappingPackageScope
	if err := strictUnmarshal(raw, &scope); err != nil {
		return CloudMappingPackageScope{}, fmt.Errorf("decode cloud mapping package scope: %w", err)
	}
	return scope, nil
}

// BuildCloudMappingPackage composes the exact selected catalog and mapping
// closure described by scope. It deliberately refuses a subset: complete
// refers only to that explicit scope, never to an entire provider estate.
func BuildCloudMappingPackage(request CloudSourceCandidateRequest, scope CloudMappingPackageScope) (CloudMappingPackage, error) {
	if err := validateCloudMappingPackageScope(request, scope); err != nil {
		return CloudMappingPackage{}, err
	}
	scopeRaw, err := canonicalFactoryJSON(scope)
	if err != nil {
		return CloudMappingPackage{}, fmt.Errorf("canonical mapping package scope: %w", err)
	}
	scopeSHA256 := sha256Hex(scopeRaw)
	byProviderCatalogs := map[string][]CloudCatalog{}
	for _, catalog := range request.Catalogs {
		byProviderCatalogs[catalog.ProviderID] = append(byProviderCatalogs[catalog.ProviderID], catalog)
	}
	byProviderTargets := map[string][]CloudSourceObjectTarget{}
	for _, target := range request.Targets {
		byProviderTargets[target.ProviderID] = append(byProviderTargets[target.ProviderID], target)
	}

	documents := make(map[string][]byte, 3)
	providerIDs := make([]string, 0, len(byProviderCatalogs))
	for provider := range byProviderCatalogs {
		providerIDs = append(providerIDs, provider)
	}
	sort.Strings(providerIDs)
	providers := make([]CloudProviderMappingPackage, 0, len(providerIDs))
	allTotals := CloudMappingDispositionTotals{}
	for _, provider := range providerIDs {
		catalogs := append([]CloudCatalog(nil), byProviderCatalogs[provider]...)
		targets := append([]CloudSourceObjectTarget(nil), byProviderTargets[provider]...)
		sort.Slice(catalogs, func(i, j int) bool {
			return cloudCatalogKey(catalogs[i].ProviderID, catalogs[i].ServiceID, catalogs[i].APISurfaceID) < cloudCatalogKey(catalogs[j].ProviderID, catalogs[j].ServiceID, catalogs[j].APISurfaceID)
		})
		sort.Slice(targets, func(i, j int) bool { return cloudTargetKey(targets[i]) < cloudTargetKey(targets[j]) })
		totals, err := cloudMappingDispositionTotals(targets)
		if err != nil {
			return CloudMappingPackage{}, fmt.Errorf("provider %q dispositions: %w", provider, err)
		}
		catalogRefs := make([]CloudMappingCatalogReference, 0, len(catalogs))
		catalogIDs := make([]string, 0, len(catalogs))
		for _, catalog := range catalogs {
			catalogRefs = append(catalogRefs, CloudMappingCatalogReference{Source: catalog.Source, Format: catalog.Format, ProviderID: catalog.ProviderID, ServiceID: catalog.ServiceID, APISurfaceID: catalog.APISurfaceID, APIVersion: catalog.APIVersion, ModelSHA256: catalog.ModelSHA256})
			catalogIDs = append(catalogIDs, catalog.Source.ID)
		}
		keys := make([]string, len(targets))
		for i := range targets {
			keys[i] = cloudTargetKey(targets[i])
		}
		role := "cloud_mapping_provider_" + provider
		fieldDerivations, err := buildCloudMappingFieldPackages(request, targets)
		if err != nil {
			return CloudMappingPackage{}, fmt.Errorf("provider %q field derivation: %w", provider, err)
		}
		body := map[string]any{
			"package_kind": "cloud_mapping_provider_package", "package_version": cloudMappingPackageVersion,
			"candidate_only": true, "source_qualification_status": "pending_source_owner_verification",
			"authoritative_graph_materialization":            false,
			"authoritative_graph_materialization_dependency": "sealed_native_graph_and_source_owner_evidence_verifier",
			"provider_id": provider, "catalogs": catalogRefs, "targets": targets,
			"disposition_totals": totals,
			"field_derivations":  fieldDerivations,
		}
		raw, err := canonicalFactoryJSON(body)
		if err != nil {
			return CloudMappingPackage{}, fmt.Errorf("canonical %s: %w", role, err)
		}
		raw = append(raw, '\n')
		documents[role] = raw
		providers = append(providers, CloudProviderMappingPackage{ProviderID: provider, DocumentRole: role, DocumentSHA256: sha256Hex(raw), Catalogs: catalogRefs, CatalogSourceIDs: catalogIDs, TargetKeys: keys, DispositionTotals: totals})
		allTotals.Mapped += totals.Mapped
		allTotals.NotObserved += totals.NotObserved
		allTotals.Private += totals.Private
		allTotals.Unknown += totals.Unknown
		allTotals.Unsupported += totals.Unsupported
	}
	parent := map[string]any{
		"package_kind": cloudMappingParentRole, "package_version": cloudMappingPackageVersion,
		"candidate_only": true, "status": cloudMappingPackageStatus,
		"source_qualification_status":         "pending_source_owner_verification",
		"authoritative_graph_materialization": false, "provider_packages": providers,
		"disposition_totals": allTotals,
		"selected_scope_id":  scope.ScopeID, "selected_catalog_count": len(scope.Catalogs),
		"selected_operation_target_count": len(scope.Targets),
	}
	parent["selected_scope_sha256"] = scopeSHA256
	parentRaw, err := canonicalFactoryJSON(parent)
	if err != nil {
		return CloudMappingPackage{}, fmt.Errorf("canonical parent mapping manifest: %w", err)
	}
	documents[cloudMappingParentRole] = append(parentRaw, '\n')
	return CloudMappingPackage{Status: cloudMappingPackageStatus, Version: cloudMappingPackageVersion, ScopeSHA256: scopeSHA256, ProviderPackages: providers, DispositionTotals: allTotals, Documents: documents, UnresolvedDependencies: []string{
		"source_owner_evidence_verification_and_complete_source_identity_set",
		"sealed_native_graph_context_and_real_verify_materialization",
		"authoritative_canon_graph_materialization_authority",
		"connector_vault_credential_eligibility_and_admitted_runtime_execution",
	}}, nil
}

func validateCloudMappingPackageScope(request CloudSourceCandidateRequest, scope CloudMappingPackageScope) error {
	if scope.ScopeID == "" || len(scope.Catalogs) == 0 || len(scope.Targets) == 0 {
		return fmt.Errorf("mapping package scope requires id, catalogs, and targets")
	}
	expectedCatalogs := map[string]string{}
	for _, selected := range scope.Catalogs {
		key := cloudCatalogKey(selected.ProviderID, selected.ServiceID, selected.APISurfaceID)
		if key == "" || selected.ModelSourceID == "" {
			return fmt.Errorf("mapping package scope contains incomplete catalog selection")
		}
		if _, duplicate := expectedCatalogs[key]; duplicate {
			return fmt.Errorf("mapping package scope has duplicate catalog %q", key)
		}
		expectedCatalogs[key] = selected.ModelSourceID
	}
	expectedTargets := map[string]struct{}{}
	for _, selected := range scope.Targets {
		key := cloudMappingSelectedTargetKey(selected)
		if key == "" {
			return fmt.Errorf("mapping package scope contains incomplete target selection")
		}
		if _, duplicate := expectedTargets[key]; duplicate {
			return fmt.Errorf("mapping package scope has duplicate target %q", key)
		}
		expectedTargets[key] = struct{}{}
	}
	if len(request.Catalogs) != len(expectedCatalogs) || len(request.Targets) != len(expectedTargets) {
		return fmt.Errorf("mapping package input does not equal the selected catalog and target roster")
	}
	if err := validateCloudMappingRetainedModels(request); err != nil {
		return err
	}
	catalogs := map[string]CloudCatalog{}
	for _, catalog := range request.Catalogs {
		key := cloudCatalogKey(catalog.ProviderID, catalog.ServiceID, catalog.APISurfaceID)
		modelID, ok := expectedCatalogs[key]
		if !ok || catalog.Source.ID != modelID {
			return fmt.Errorf("unexpected or unpinned catalog %q", key)
		}
		if _, duplicate := catalogs[key]; duplicate {
			return fmt.Errorf("duplicate catalog %q", key)
		}
		catalogs[key] = catalog
	}
	seen := map[string]struct{}{}
	for _, target := range request.Targets {
		key := cloudMappingSelectedTargetKey(CloudMappingTargetSelection{ProviderID: target.ProviderID, ServiceID: target.ServiceID, APISurfaceID: target.APISurfaceID, OperationID: target.OperationID, SourceObjectType: target.SourceObjectType, RecordClassSymbol: target.RecordClassSymbol})
		if _, ok := expectedTargets[key]; !ok {
			return fmt.Errorf("unexpected selected mapping target %q", key)
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate selected mapping target %q", key)
		}
		seen[key] = struct{}{}
		catalog, ok := catalogs[cloudCatalogKey(target.ProviderID, target.ServiceID, target.APISurfaceID)]
		if !ok {
			return fmt.Errorf("target %q has no retained catalog", key)
		}
		if err := validateCloudSourceObjectTarget(target, catalog); err != nil {
			return fmt.Errorf("target %q: %w", key, err)
		}
	}
	totals, err := cloudMappingDispositionTotals(request.Targets)
	if err != nil {
		return err
	}
	if totals != scope.ExpectedDispositionTotals {
		return fmt.Errorf("mapping package dispositions = %+v, want %+v", totals, scope.ExpectedDispositionTotals)
	}
	return nil
}

// validateCloudMappingRetainedModels prevents a caller from substituting a
// mutable parsed catalog after the candidate loader has authenticated the
// package-local model bytes. It intentionally reparses the retained inputs;
// a catalog equality check alone would otherwise only compare caller-owned
// structures.
func validateCloudMappingRetainedModels(request CloudSourceCandidateRequest) error {
	if len(request.retainedModels) != len(request.Catalogs) {
		return fmt.Errorf("mapping package requires one retained model for every catalog")
	}
	bySourceID := make(map[string]PinnedCloudModel, len(request.retainedModels))
	for _, model := range request.retainedModels {
		if model.Source.ID == "" {
			return fmt.Errorf("retained mapping model has no source id")
		}
		if _, duplicate := bySourceID[model.Source.ID]; duplicate {
			return fmt.Errorf("duplicate retained mapping model %q", model.Source.ID)
		}
		bySourceID[model.Source.ID] = model
	}
	for _, catalog := range request.Catalogs {
		model, ok := bySourceID[catalog.Source.ID]
		if !ok || model.Source != catalog.Source || model.ExpectedSHA256 != catalog.ModelSHA256 {
			return fmt.Errorf("catalog %q is not linked to a retained model", cloudCatalogKey(catalog.ProviderID, catalog.ServiceID, catalog.APISurfaceID))
		}
		parsed, err := ParsePinnedCloudModel(model)
		if err != nil || !reflect.DeepEqual(parsed, catalog) {
			return fmt.Errorf("catalog %q differs from exact retained model bytes", cloudCatalogKey(catalog.ProviderID, catalog.ServiceID, catalog.APISurfaceID))
		}
	}
	return nil
}

func cloudMappingSelectedTargetKey(target CloudMappingTargetSelection) string {
	values := []string{target.ProviderID, target.ServiceID, target.APISurfaceID, target.OperationID, target.SourceObjectType, target.RecordClassSymbol}
	for _, value := range values {
		if value == "" {
			return ""
		}
	}
	return values[0] + "\x00" + values[1] + "\x00" + values[2] + "\x00" + values[3] + "\x00" + values[4] + "\x00" + values[5]
}

func cloudMappingDispositionTotals(targets []CloudSourceObjectTarget) (CloudMappingDispositionTotals, error) {
	totals := CloudMappingDispositionTotals{}
	for _, target := range targets {
		if target.MappingContract == nil {
			return CloudMappingDispositionTotals{}, fmt.Errorf("target %q has no mapping contract", cloudTargetKey(target))
		}
		fields := append([]CloudMappingContractField(nil), target.MappingContract.Fields...)
		for _, nested := range target.MappingContract.Nested {
			fields = append(fields, nested.Fields...)
		}
		for _, field := range fields {
			switch field.Disposition {
			case CloudSourceMapsExactSourceFact, CloudSourceMapsExactLifecycleFact, CloudSourceMapsExactRelationshipFact:
				totals.Mapped++
			case CloudSourceNotObserved:
				totals.NotObserved++
			case CloudSourcePrivateOnly:
				totals.Private++
			case CloudSourceUnknown:
				totals.Unknown++
			case CloudSourceUnsupported:
				totals.Unsupported++
			default:
				return CloudMappingDispositionTotals{}, fmt.Errorf("target %q field %q has unrecognized disposition %q", cloudTargetKey(target), field.SourcePointer, field.Disposition)
			}
		}
	}
	return totals, nil
}

// WriteCloudMappingPackageExclusive emits the exact provider and parent
// package documents for a later sealed compiler input. It writes no receipt
// and makes no qualification, materialization, or admission claim.
func WriteCloudMappingPackageExclusive(root string, pkg CloudMappingPackage) error {
	roster, err := validateCloudMappingPackageForWrite(root, pkg)
	if err != nil {
		return err
	}
	return publishFactorySourceOutputDirectoryExclusive(root, roster)
}

type cloudMappingProviderDocument struct {
	PackageKind                                 string                               `json:"package_kind"`
	PackageVersion                              string                               `json:"package_version"`
	CandidateOnly                               bool                                 `json:"candidate_only"`
	SourceQualificationStatus                   string                               `json:"source_qualification_status"`
	AuthoritativeGraphMaterialization           bool                                 `json:"authoritative_graph_materialization"`
	AuthoritativeGraphMaterializationDependency string                               `json:"authoritative_graph_materialization_dependency"`
	ProviderID                                  string                               `json:"provider_id"`
	Catalogs                                    []CloudMappingCatalogReference       `json:"catalogs"`
	Targets                                     []CloudSourceObjectTarget            `json:"targets"`
	DispositionTotals                           CloudMappingDispositionTotals        `json:"disposition_totals"`
	FieldDerivations                            []cloudMappingFieldDerivationPackage `json:"field_derivations"`
}

type cloudMappingParentDocument struct {
	PackageKind                       string                        `json:"package_kind"`
	PackageVersion                    string                        `json:"package_version"`
	CandidateOnly                     bool                          `json:"candidate_only"`
	Status                            string                        `json:"status"`
	SourceQualificationStatus         string                        `json:"source_qualification_status"`
	AuthoritativeGraphMaterialization bool                          `json:"authoritative_graph_materialization"`
	ProviderPackages                  []CloudProviderMappingPackage `json:"provider_packages"`
	DispositionTotals                 CloudMappingDispositionTotals `json:"disposition_totals"`
	SelectedScopeID                   string                        `json:"selected_scope_id"`
	SelectedCatalogCount              int                           `json:"selected_catalog_count"`
	SelectedOperationTargetCount      int                           `json:"selected_operation_target_count"`
	SelectedScopeSHA256               string                        `json:"selected_scope_sha256"`
}

func validateCloudMappingPackageForWrite(root string, pkg CloudMappingPackage) ([]factorySourceOutputFile, error) {
	if root == "" || !filepath.IsAbs(root) || pkg.Status != cloudMappingPackageStatus || pkg.Version != cloudMappingPackageVersion || !isLowerSHA256(pkg.ScopeSHA256) || len(pkg.ProviderPackages) == 0 || len(pkg.Documents) != len(pkg.ProviderPackages)+1 {
		return nil, fmt.Errorf("mapping package has invalid root, status, version, or document roster")
	}
	roster := make([]factorySourceOutputFile, 0, len(pkg.Documents))
	seen := map[string]struct{}{}
	allTotals := CloudMappingDispositionTotals{}
	catalogCount, targetCount := 0, 0
	for _, provider := range pkg.ProviderPackages {
		if provider.ProviderID == "" || provider.DocumentRole == "" || provider.DocumentSHA256 == "" {
			return nil, fmt.Errorf("mapping provider package is incomplete")
		}
		if _, duplicate := seen[provider.DocumentRole]; duplicate {
			return nil, fmt.Errorf("duplicate mapping provider document role %q", provider.DocumentRole)
		}
		seen[provider.DocumentRole] = struct{}{}
		raw, ok := pkg.Documents[provider.DocumentRole]
		if !ok || len(raw) == 0 || sha256Hex(raw) != provider.DocumentSHA256 {
			return nil, fmt.Errorf("mapping provider document %q does not bind its declared bytes", provider.DocumentRole)
		}
		var document cloudMappingProviderDocument
		if err := strictUnmarshal(raw, &document); err != nil {
			return nil, fmt.Errorf("mapping provider document %q: %w", provider.DocumentRole, err)
		}
		if document.PackageKind != "cloud_mapping_provider_package" || document.PackageVersion != pkg.Version || !document.CandidateOnly || document.SourceQualificationStatus != "pending_source_owner_verification" || document.AuthoritativeGraphMaterialization || document.AuthoritativeGraphMaterializationDependency != "sealed_native_graph_and_source_owner_evidence_verifier" || document.ProviderID != provider.ProviderID || document.DispositionTotals != provider.DispositionTotals {
			return nil, fmt.Errorf("mapping provider document %q metadata differs from package", provider.DocumentRole)
		}
		catalogIDs := make([]string, len(document.Catalogs))
		for index, catalog := range document.Catalogs {
			catalogIDs[index] = catalog.Source.ID
		}
		keys := make([]string, len(document.Targets))
		for index, target := range document.Targets {
			keys[index] = cloudTargetKey(target)
		}
		documentTotals, err := cloudMappingDispositionTotals(document.Targets)
		if err != nil || documentTotals != provider.DispositionTotals || !equalCloudMappingCatalogReferences(document.Catalogs, provider.Catalogs) || !equalCloudStringSlices(catalogIDs, provider.CatalogSourceIDs) || !equalCloudStringSlices(keys, provider.TargetKeys) {
			return nil, fmt.Errorf("mapping provider document %q closure differs from package metadata", provider.DocumentRole)
		}
		if err := validateCloudMappingFieldPackages(document); err != nil {
			return nil, fmt.Errorf("mapping provider document %q: %w", provider.DocumentRole, err)
		}
		roster = append(roster, factorySourceOutputFile{RelativePath: provider.DocumentRole + ".json", Raw: raw})
		allTotals.Mapped += provider.DispositionTotals.Mapped
		allTotals.NotObserved += provider.DispositionTotals.NotObserved
		allTotals.Private += provider.DispositionTotals.Private
		allTotals.Unknown += provider.DispositionTotals.Unknown
		allTotals.Unsupported += provider.DispositionTotals.Unsupported
		catalogCount += len(provider.CatalogSourceIDs)
		targetCount += len(provider.TargetKeys)
	}
	parent, ok := pkg.Documents[cloudMappingParentRole]
	if !ok || len(parent) == 0 {
		return nil, fmt.Errorf("mapping package lacks parent manifest")
	}
	var parentDocument cloudMappingParentDocument
	if err := strictUnmarshal(parent, &parentDocument); err != nil {
		return nil, fmt.Errorf("mapping parent manifest: %w", err)
	}
	if parentDocument.PackageKind != cloudMappingParentRole || parentDocument.PackageVersion != pkg.Version || !parentDocument.CandidateOnly || parentDocument.Status != pkg.Status || parentDocument.SourceQualificationStatus != "pending_source_owner_verification" || parentDocument.AuthoritativeGraphMaterialization || !equalCloudProviderMappingPackages(parentDocument.ProviderPackages, pkg.ProviderPackages) || parentDocument.DispositionTotals != pkg.DispositionTotals || parentDocument.DispositionTotals != allTotals || parentDocument.SelectedScopeSHA256 != pkg.ScopeSHA256 || parentDocument.SelectedScopeID == "" || parentDocument.SelectedCatalogCount != catalogCount || parentDocument.SelectedOperationTargetCount != targetCount {
		return nil, fmt.Errorf("mapping parent manifest differs from package closure")
	}
	roster = append(roster, factorySourceOutputFile{RelativePath: cloudMappingParentRole + ".json", Raw: parent})
	sort.Slice(roster, func(i, j int) bool { return roster[i].RelativePath < roster[j].RelativePath })
	return roster, nil
}

func equalCloudProviderMappingPackages(left, right []CloudProviderMappingPackage) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		l, r := left[index], right[index]
		if l.ProviderID != r.ProviderID || l.DocumentRole != r.DocumentRole || l.DocumentSHA256 != r.DocumentSHA256 || l.DispositionTotals != r.DispositionTotals || !equalCloudMappingCatalogReferences(l.Catalogs, r.Catalogs) || !equalCloudStringSlices(l.CatalogSourceIDs, r.CatalogSourceIDs) || !equalCloudStringSlices(l.TargetKeys, r.TargetKeys) {
			return false
		}
	}
	return true
}

func equalCloudMappingCatalogReferences(left, right []CloudMappingCatalogReference) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// EqualCloudMappingPackages compares exact emitted candidate documents. It is
// byte-oriented because parent hashes bind canonical bytes, not a decoded Go
// representation.
func EqualCloudMappingPackages(left, right CloudMappingPackage) bool {
	if left.Status != right.Status || left.Version != right.Version || left.ScopeSHA256 != right.ScopeSHA256 || left.DispositionTotals != right.DispositionTotals || len(left.ProviderPackages) != len(right.ProviderPackages) || !equalCloudStringSlices(left.UnresolvedDependencies, right.UnresolvedDependencies) || len(left.Documents) != len(right.Documents) {
		return false
	}
	if !equalCloudProviderMappingPackages(left.ProviderPackages, right.ProviderPackages) {
		return false
	}
	for role, body := range left.Documents {
		if !bytes.Equal(body, right.Documents[role]) {
			return false
		}
	}
	return true
}
