package providerplan

// This file turns a closed set of pinned cloud API catalogs into the five
// body-bearing candidate documents that a source-package scaffold may render.
// It is deliberately not an OHM runtime, a source-record creator, or an
// admission mechanism.  A caller must still provide the separately owned
// authority/scaffold inputs before CompileDocumentationFactorySourcePackage
// can materialize an offline candidate tree.

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

const (
	cloudSourceCandidateStatus = "candidate_generated"
	cloudSourcePackageVersion  = "1"
)

// CloudSourceFieldDisposition is intentionally exhaustive.  It makes a
// source field's treatment reviewable rather than silently dropping an API
// field or treating an unrecognised value as a neutral fact.
type CloudSourceFieldDisposition string

const (
	CloudSourceMapsExactSourceFact       CloudSourceFieldDisposition = "maps_exact_source_fact"
	CloudSourceMapsExactLifecycleFact    CloudSourceFieldDisposition = "maps_exact_lifecycle_fact"
	CloudSourceMapsExactRelationshipFact CloudSourceFieldDisposition = "maps_exact_relationship_fact"
	CloudSourceNotObserved               CloudSourceFieldDisposition = "not_observed"
	CloudSourceUnsupported               CloudSourceFieldDisposition = "unsupported"
	CloudSourceUnknown                   CloudSourceFieldDisposition = "unknown"
	CloudSourcePrivateOnly               CloudSourceFieldDisposition = "source_private_only"
)

// CloudSourceFieldMapping declares the disposition of one catalog schema
// field.  Units, cardinality and source type are declarative facts; generic
// code never normalizes units or guesses a target type.
type CloudSourceFieldMapping struct {
	SourceSchemaID string                      `json:"source_schema_id"`
	SourceFieldID  string                      `json:"source_field_id"`
	SourcePointer  string                      `json:"source_pointer"`
	DeclaredType   string                      `json:"declared_type"`
	Disposition    CloudSourceFieldDisposition `json:"disposition"`
	TargetField    string                      `json:"target_field,omitempty"`
	Projection     CloudMappingProjection      `json:"projection,omitempty"`
	Unit           string                      `json:"unit,omitempty"`
	Cardinality    string                      `json:"cardinality"`
}

// CloudSourceObjectTarget binds one provider object representation to one
// source-neutral record-class coordinate.  Stable source identity excludes
// API/model/mapping revisions and observed ETags.  Those values may be
// carried only in lineage and ordering evidence by the later SOURCE/OHM owner.
type CloudSourceObjectTarget struct {
	ProviderID                 string                        `json:"provider_id"`
	ServiceID                  string                        `json:"service_id"`
	APISurfaceID               string                        `json:"api_surface_id"`
	OperationID                string                        `json:"operation_id"`
	SourceObjectType           string                        `json:"source_object_type"`
	RecordClassSymbol          string                        `json:"record_class_symbol"`
	RecordClassContractRef     string                        `json:"record_class_contract_ref"`
	SourceSchemaVersion        string                        `json:"source_schema_version"`
	SourceMappingVersion       string                        `json:"source_mapping_version"`
	StableIdentitySourceFields []string                      `json:"stable_identity_source_fields"`
	StableIdentityEvidence     []CloudSourceIdentityEvidence `json:"stable_identity_evidence"`
	IncarnationEvidenceFields  []string                      `json:"incarnation_evidence_fields,omitempty"`
	SourceFields               []string                      `json:"source_fields"`
	FieldMappings              []CloudSourceFieldMapping     `json:"field_mappings"`
	MappingContract            *CloudMappingContract         `json:"mapping_contract,omitempty"`
}

type CloudSourceIdentityEvidence struct {
	SourceFieldID string                      `json:"source_field_id"`
	SemanticRole  string                      `json:"semantic_role"`
	Locator       CloudCatalogEvidenceLocator `json:"locator"`
}

// CloudSourceCandidateRequest is data-only.  Parsed catalogs retain the
// evidence-local API model; targets contain the separately owned neutral
// record bindings.  Neither input conveys a credential, customer grant,
// source instance, tenant, or an admission decision.
type CloudSourceCandidateRequest struct {
	Catalogs []CloudCatalog            `json:"catalogs"`
	Targets  []CloudSourceObjectTarget `json:"targets"`
}

// CloudSourceCandidateBundle is suitable as payload input to the existing
// source-package compiler.  The documents are candidates, not a completed
// source package: a sealed scaffold supplies the authority pins, evidence
// manifests and templates required by the compiler.
type CloudSourceCandidateBundle struct {
	Status                 string            `json:"status"`
	Version                string            `json:"version"`
	Documents              map[string][]byte `json:"-"`
	UnresolvedDependencies []string          `json:"unresolved_dependencies"`
}

// CloudSourceCandidateInput is the portable CLI input.  Model and
// supplemental-evidence bytes are read from explicit relative paths, while
// neutral target contracts remain ordinary declarative data.
type CloudSourceCandidateInput struct {
	Models                    []CloudSourceCandidateModelInput `json:"models"`
	NeutralSchemaExportPath   string                           `json:"neutral_schema_export_path"`
	NeutralSchemaExportSHA256 string                           `json:"neutral_schema_export_sha256"`
	Targets                   []CloudSourceObjectTarget        `json:"targets"`
}

type CloudSourceCandidateModelInput struct {
	PinnedCloudModel
	ModelPath                 string   `json:"model_path"`
	SupplementalEvidencePaths []string `json:"supplemental_evidence_paths,omitempty"`
}

// LoadCloudSourceCandidateInput is intentionally offline: it opens only
// package-local exact bytes and validates each through the CloudCatalog parser.
func LoadCloudSourceCandidateInput(path string, parser CloudCatalogParser) (CloudSourceCandidateRequest, error) {
	if parser == nil {
		return CloudSourceCandidateRequest{}, fmt.Errorf("cloud catalog parser is nil")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return CloudSourceCandidateRequest{}, err
	}
	var input CloudSourceCandidateInput
	if err := strictUnmarshal(raw, &input); err != nil {
		return CloudSourceCandidateRequest{}, fmt.Errorf("decode cloud candidate input: %w", err)
	}
	base := filepath.Dir(path)
	// The export is an evidence-local, source-neutral projection.  Its loader
	// independently pins the canonical owner/profile provenance; candidate
	// input cannot smuggle a caller-constructed neutral schema through this
	// boundary.
	exportPath, err := cloudCandidateLocalPath(base, input.NeutralSchemaExportPath)
	if err != nil {
		return CloudSourceCandidateRequest{}, fmt.Errorf("neutral schema export: %w", err)
	}
	exportRaw, err := os.ReadFile(exportPath)
	if err != nil {
		return CloudSourceCandidateRequest{}, fmt.Errorf("read neutral schema export: %w", err)
	}
	catalogs := make([]CloudCatalog, 0, len(input.Models))
	for index, item := range input.Models {
		modelPath, err := cloudCandidateLocalPath(base, item.ModelPath)
		if err != nil {
			return CloudSourceCandidateRequest{}, fmt.Errorf("models[%d]: %w", index, err)
		}
		item.Raw, err = os.ReadFile(modelPath)
		if err != nil {
			return CloudSourceCandidateRequest{}, fmt.Errorf("models[%d] read model: %w", index, err)
		}
		if len(item.SupplementalEvidencePaths) != len(item.SupplementalEvidence) {
			return CloudSourceCandidateRequest{}, fmt.Errorf("models[%d] supplemental evidence paths do not match declarations", index)
		}
		for evidenceIndex, evidencePath := range item.SupplementalEvidencePaths {
			resolved, pathErr := cloudCandidateLocalPath(base, evidencePath)
			if pathErr != nil {
				return CloudSourceCandidateRequest{}, fmt.Errorf("models[%d] evidence[%d]: %w", index, evidenceIndex, pathErr)
			}
			item.SupplementalEvidence[evidenceIndex].Raw, err = os.ReadFile(resolved)
			if err != nil {
				return CloudSourceCandidateRequest{}, err
			}
		}
		catalog, parseErr := parser.ParsePinnedCloudModel(item.PinnedCloudModel)
		if parseErr != nil {
			return CloudSourceCandidateRequest{}, fmt.Errorf("models[%d]: %w", index, parseErr)
		}
		catalogs = append(catalogs, catalog)
	}
	targets := append([]CloudSourceObjectTarget(nil), input.Targets...)
	for i := range targets {
		if targets[i].MappingContract == nil {
			return CloudSourceCandidateRequest{}, fmt.Errorf("targets[%d]: mapping contract is required", i)
		}
		if !cloudNeutralSchemaIsZero(targets[i].MappingContract.Neutral) || len(targets[i].FieldMappings) != 0 || len(targets[i].SourceFields) != 0 {
			return CloudSourceCandidateRequest{}, fmt.Errorf("targets[%d]: neutral schema and field roster are derived from the pinned mapping contract", i)
		}
		neutral, loadErr := LoadCloudNeutralRecordSchema(exportRaw, input.NeutralSchemaExportSHA256, targets[i].RecordClassSymbol)
		if loadErr != nil {
			return CloudSourceCandidateRequest{}, fmt.Errorf("targets[%d] neutral schema: %w", i, loadErr)
		}
		targets[i].MappingContract.Neutral = neutral
		if evidenceErr := LoadCloudMappingEvidence(base, targets[i].MappingContract); evidenceErr != nil {
			return CloudSourceCandidateRequest{}, fmt.Errorf("targets[%d] mapping evidence: %w", i, evidenceErr)
		}
		if len(targets[i].MappingContract.Fields) == 0 {
			catalog, found := findCloudCandidateCatalog(catalogs, targets[i])
			if !found {
				return CloudSourceCandidateRequest{}, fmt.Errorf("targets[%d]: no matching pinned catalog", i)
			}
			fields, fieldErr := cloudCatalogObjectFields(catalog, targets[i].MappingContract.ObjectSchemaID)
			if fieldErr != nil {
				return CloudSourceCandidateRequest{}, fmt.Errorf("targets[%d]: derive source field roster: %w", i, fieldErr)
			}
			pointers := make([]string, 0, len(fields))
			for pointer := range fields {
				pointers = append(pointers, pointer)
			}
			sort.Strings(pointers)
			for _, pointer := range pointers {
				field := fields[pointer]
				targets[i].MappingContract.Fields = append(targets[i].MappingContract.Fields, CloudMappingContractField{SourcePointer: pointer, SourceFieldID: field.ID, Disposition: CloudSourceUnsupported, ExplicitNullDisposition: CloudExplicitNullToPrivate})
			}
		}
		targets[i].RecordClassContractRef = neutral.OwnerRef
		targets[i].SourceFields, targets[i].FieldMappings = cloudDerivedTargetRoster(*targets[i].MappingContract)
	}
	return CloudSourceCandidateRequest{Catalogs: catalogs, Targets: targets}, nil
}

func findCloudCandidateCatalog(catalogs []CloudCatalog, target CloudSourceObjectTarget) (CloudCatalog, bool) {
	for _, catalog := range catalogs {
		if catalog.ProviderID == target.ProviderID && catalog.ServiceID == target.ServiceID && catalog.APISurfaceID == target.APISurfaceID {
			return catalog, true
		}
	}
	return CloudCatalog{}, false
}

func cloudCandidateLocalPath(base, value string) (string, error) {
	// Candidate manifests are portable JSON and therefore always use slash
	// separators, even when this factory runs on Windows.
	if value == "" || strings.Contains(value, "\\") || strings.Contains(value, ":") || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return "", fmt.Errorf("path must be a nonempty package-local relative path")
	}
	physicalBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", fmt.Errorf("resolve package root: %w", err)
	}
	resolved := filepath.Join(physicalBase, filepath.FromSlash(value))
	physicalTarget, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve package-local path: %w", err)
	}
	relative, err := filepath.Rel(physicalBase, physicalTarget)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("path escapes package root")
	}
	return physicalTarget, nil
}

func cloudNeutralSchemaIsZero(schema CloudNeutralRecordSchema) bool {
	return schema.OwnerRef == "" && schema.OwnerSHA256 == "" && schema.ClassSymbol == "" && schema.ValidatorProfileRef == "" && schema.ValidatorProfileSHA256 == "" && len(schema.Fields) == 0
}

func cloudDerivedTargetRoster(contract CloudMappingContract) ([]string, []CloudSourceFieldMapping) {
	fields := append([]CloudMappingContractField(nil), contract.Fields...)
	sort.Slice(fields, func(i, j int) bool { return fields[i].SourceFieldID < fields[j].SourceFieldID })
	roster := make([]string, 0, len(fields))
	mappings := make([]CloudSourceFieldMapping, 0, len(fields))
	for _, field := range fields {
		roster = append(roster, field.SourceFieldID)
		mappings = append(mappings, CloudSourceFieldMapping{SourceSchemaID: contract.ObjectSchemaID, SourceFieldID: field.SourceFieldID, SourcePointer: field.SourcePointer, DeclaredType: "derived_from_mapping_contract", Disposition: field.Disposition, TargetField: field.TargetField, Projection: field.Projection, Unit: field.SourceUnit, Cardinality: "derived_from_mapping_contract"})
	}
	return roster, mappings
}

// WriteCloudSourceCandidateBundleExclusive emits reviewable candidate bytes,
// never a receipt or a claim of compiler/admission success.
func WriteCloudSourceCandidateBundleExclusive(root string, bundle CloudSourceCandidateBundle) error {
	if bundle.Status != cloudSourceCandidateStatus || bundle.Version != cloudSourcePackageVersion || len(bundle.Documents) != len(sourcePackageOutputRoleContracts) {
		return fmt.Errorf("candidate bundle has invalid status, version, or output role count")
	}
	roster := make([]factorySourceOutputFile, 0, len(sourcePackageOutputRoleContracts))
	for role := range sourcePackageOutputRoleContracts {
		raw, ok := bundle.Documents[role]
		if !ok || len(raw) == 0 {
			return fmt.Errorf("candidate bundle lacks exact role %q", role)
		}
		roster = append(roster, factorySourceOutputFile{RelativePath: role + ".json", Raw: raw})
	}
	if root == "" || filepath.IsAbs(root) == false {
		return fmt.Errorf("candidate output root must be absolute")
	}
	return publishFactorySourceOutputDirectoryExclusive(root, roster)
}

// CompileCloudSourceCandidateWithScaffold makes the existing materializer the
// only full-compile path. A supplied sealed scaffold must render byte-identical
// candidate documents; otherwise no output is published.
func CompileCloudSourceCandidateWithScaffold(bundle CloudSourceCandidateBundle, sourcePackagePath, outputRoot string) (DocumentationFactorySourceCompileResult, error) {
	prepared, err := prepareDocumentationFactorySourceCompilation(sourcePackagePath)
	if err != nil {
		return DocumentationFactorySourceCompileResult{}, fmt.Errorf("prepare supplied scaffold: %w", err)
	}
	for _, generated := range prepared.manifest.GeneratedDocuments {
		want, ok := bundle.Documents[generated.PackageRole]
		if !ok {
			return DocumentationFactorySourceCompileResult{}, fmt.Errorf("scaffold has unknown generated role %q", generated.PackageRole)
		}
		actual := prepared.materials[generated.coordinate()].raw
		if !bytes.Equal(actual, want) {
			return DocumentationFactorySourceCompileResult{}, fmt.Errorf("supplied scaffold generated role %q does not bind candidate bytes", generated.PackageRole)
		}
	}
	return compilePreparedDocumentationFactorySourcePackage(DocumentationFactorySourceCompileOptions{SourcePackagePath: sourcePackagePath, OutputRoot: outputRoot}, prepared, defaultDocumentationFactorySourceCompilerDependencies(), nil, nil)
}

// BuildCloudSourceCandidateBundle builds deterministic body-bearing candidate
// documents.  It fails closed on an unresolved resource/operation association,
// missing source-field disposition, ambiguous identity or malformed target.
func BuildCloudSourceCandidateBundle(request CloudSourceCandidateRequest) (CloudSourceCandidateBundle, error) {
	if len(request.Catalogs) == 0 || len(request.Targets) == 0 {
		return CloudSourceCandidateBundle{}, fmt.Errorf("cloud source candidate requires catalogs and targets")
	}
	catalogs := make(map[string]CloudCatalog, len(request.Catalogs))
	for _, catalog := range request.Catalogs {
		key := cloudCatalogKey(catalog.ProviderID, catalog.ServiceID, catalog.APISurfaceID)
		if key == "" || catalog.ModelSHA256 == "" || len(catalog.Resources) == 0 || len(catalog.Operations) == 0 {
			return CloudSourceCandidateBundle{}, fmt.Errorf("cloud catalog is incomplete")
		}
		if _, duplicate := catalogs[key]; duplicate {
			return CloudSourceCandidateBundle{}, fmt.Errorf("duplicate cloud catalog %q", key)
		}
		catalogs[key] = catalog
	}
	targets := append([]CloudSourceObjectTarget(nil), request.Targets...)
	sort.Slice(targets, func(i, j int) bool { return cloudTargetKey(targets[i]) < cloudTargetKey(targets[j]) })
	for i, target := range targets {
		if i != 0 && cloudTargetKey(targets[i-1]) == cloudTargetKey(target) {
			return CloudSourceCandidateBundle{}, fmt.Errorf("duplicate cloud source target %q", cloudTargetKey(target))
		}
		catalog, ok := catalogs[cloudCatalogKey(target.ProviderID, target.ServiceID, target.APISurfaceID)]
		if !ok {
			return CloudSourceCandidateBundle{}, fmt.Errorf("target %q has no pinned catalog", cloudTargetKey(target))
		}
		if err := validateCloudSourceObjectTarget(target, catalog); err != nil {
			return CloudSourceCandidateBundle{}, fmt.Errorf("target %q: %w", cloudTargetKey(target), err)
		}
		derivedFields, derivedMappings := cloudDerivedTargetRoster(*target.MappingContract)
		if len(target.SourceFields) != 0 || len(target.FieldMappings) != 0 {
			if !cloudTargetRosterEquivalent(target.SourceFields, target.FieldMappings, derivedFields, derivedMappings) {
				return CloudSourceCandidateBundle{}, fmt.Errorf("target %q: field roster differs from mapping contract", cloudTargetKey(target))
			}
		}
		target.SourceFields, target.FieldMappings = derivedFields, derivedMappings
		targets[i] = target
	}

	apiGraph := makeCloudAPIGraphCandidate(request.Catalogs, targets)
	profile := makeCloudReusableProfileCandidate(request.Catalogs)
	mapping := makeCloudMappingCandidate(targets)
	residual := makeCloudResidualCandidate(targets)
	arc := makeCloudARCCandidate(targets)
	documents := map[string][]byte{}
	for role, value := range map[string]any{
		sourcePackageOutputRoleAPIGraphArtifact:       apiGraph,
		sourcePackageOutputRoleReusableProfile:        profile,
		sourcePackageOutputRoleSourceMapping:          mapping,
		sourcePackageOutputRoleResidualCircuitPackage: residual,
		sourcePackageOutputRoleARCReferenceBlueprint:  arc,
	} {
		raw, err := canonicalFactoryJSON(value)
		if err != nil {
			return CloudSourceCandidateBundle{}, fmt.Errorf("canonical %s candidate: %w", role, err)
		}
		documents[role] = append(raw, '\n')
	}
	return CloudSourceCandidateBundle{
		Status: cloudSourceCandidateStatus, Version: cloudSourcePackageVersion, Documents: documents,
		UnresolvedDependencies: []string{
			"sealed_source_package_scaffold_with_authority_pins_and_four_stage_manifests",
			"source_owner_evidence_verification_and_source_instance_binding",
			"connector_vault_interface_and_credential_selection",
			"OHM_source_acceptance_and_admitted_execution",
		},
	}, nil
}

func cloudCatalogKey(provider, service, surface string) string {
	if strings.TrimSpace(provider) == "" || strings.TrimSpace(service) == "" || strings.TrimSpace(surface) == "" {
		return ""
	}
	return provider + "\x00" + service + "\x00" + surface
}

func cloudTargetKey(target CloudSourceObjectTarget) string {
	return strings.Join([]string{target.ProviderID, target.ServiceID, target.APISurfaceID, target.OperationID, target.SourceObjectType, target.RecordClassSymbol, target.SourceSchemaVersion, target.SourceMappingVersion}, "\x00")
}

func validateCloudSourceObjectTarget(target CloudSourceObjectTarget, catalog CloudCatalog) error {
	for label, value := range map[string]string{
		"operation_id": target.OperationID, "source_object_type": target.SourceObjectType,
		"record_class_symbol": target.RecordClassSymbol, "record_class_contract_ref": target.RecordClassContractRef,
		"source_schema_version": target.SourceSchemaVersion, "source_mapping_version": target.SourceMappingVersion,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
	}
	operation, found := findCloudCatalogOperation(catalog, target.OperationID)
	if !found {
		return fmt.Errorf("operation %q is absent from catalog", target.OperationID)
	}
	if operation.AssociationStatus == cloudCatalogAssociationUnresolved || len(operation.ResourceIDs) == 0 {
		return fmt.Errorf("operation %q has unresolved resource association", target.OperationID)
	}
	if target.MappingContract == nil {
		return fmt.Errorf("exact IRR/schema mapping contract is required")
	}
	if target.MappingContract.OperationID != target.OperationID {
		return fmt.Errorf("mapping contract operation does not equal target operation")
	}
	if err := ValidateCloudMappingContract(catalog, *target.MappingContract); err != nil {
		return fmt.Errorf("mapping contract: %w", err)
	}
	if target.MappingContract.Neutral.ClassSymbol != target.RecordClassSymbol || target.MappingContract.Neutral.OwnerRef != target.RecordClassContractRef {
		return fmt.Errorf("target record class does not equal pinned mapping contract neutral class")
	}
	if !strictUniqueNonemptyCloudStrings(target.StableIdentitySourceFields) {
		return fmt.Errorf("stable identity field roster must be nonempty unique set")
	}
	if len(target.StableIdentitySourceFields) == 0 {
		return fmt.Errorf("stable source identity requires source fields")
	}
	evidenceByField := map[string]CloudSourceIdentityEvidence{}
	for _, evidence := range target.StableIdentityEvidence {
		if evidence.SourceFieldID == "" || (evidence.SemanticRole != "scoped_native_lookup_key" && evidence.SemanticRole != "immutable_incarnation_proof") || evidence.Locator.EvidenceID == "" || evidence.Locator.JSONPointer == "" {
			return fmt.Errorf("stable identity evidence is incomplete")
		}
		if _, duplicate := evidenceByField[evidence.SourceFieldID]; duplicate {
			return fmt.Errorf("duplicate stable identity evidence for %q", evidence.SourceFieldID)
		}
		evidenceByField[evidence.SourceFieldID] = evidence
	}
	if len(evidenceByField) != len(target.StableIdentitySourceFields) {
		return fmt.Errorf("each stable identity field requires evidence-bound semantic role")
	}
	for _, field := range target.StableIdentitySourceFields {
		lower := strings.ToLower(field)
		if strings.Contains(lower, "etag") || strings.Contains(lower, "generation") || strings.Contains(lower, "version") || strings.Contains(lower, "time") || strings.Contains(lower, "date") || strings.Contains(lower, "token") {
			return fmt.Errorf("stable source identity field %q is revision, observation, or pagination evidence", field)
		}
		if _, ok := evidenceByField[field]; !ok {
			return fmt.Errorf("stable source identity field %q lacks documented selector evidence", field)
		}
	}
	if !strictUniqueNonemptyCloudStrings(target.IncarnationEvidenceFields) {
		return fmt.Errorf("incarnation evidence roster is not unique")
	}
	derivedFields, _ := cloudDerivedTargetRoster(*target.MappingContract)
	fieldSet := make(map[string]struct{}, len(derivedFields))
	for _, field := range derivedFields {
		fieldSet[field] = struct{}{}
	}
	for _, field := range append(append([]string{}, target.StableIdentitySourceFields...), target.IncarnationEvidenceFields...) {
		if _, exists := fieldSet[field]; !exists {
			return fmt.Errorf("identity/incarnation field %q lacks source-field declaration", field)
		}
	}
	if err := ValidateCloudSourceIdentityContract(target, catalog); err != nil {
		return fmt.Errorf("stable identity contract: %w", err)
	}
	return nil
}

func cloudTargetRosterEquivalent(fields []string, mappings []CloudSourceFieldMapping, derivedFields []string, derivedMappings []CloudSourceFieldMapping) bool {
	if len(fields) != len(derivedFields) || len(mappings) != len(derivedMappings) {
		return false
	}
	byID := map[string]CloudSourceFieldMapping{}
	for _, mapping := range mappings {
		if _, exists := byID[mapping.SourceFieldID]; exists {
			return false
		}
		byID[mapping.SourceFieldID] = mapping
	}
	for index, id := range derivedFields {
		if fields[index] != id {
			return false
		}
		actual, ok := byID[id]
		want := derivedMappings[index]
		if !ok || actual.SourceSchemaID != want.SourceSchemaID || actual.SourcePointer != want.SourcePointer || actual.Disposition != want.Disposition || actual.TargetField != want.TargetField || actual.Projection != want.Projection || actual.Unit != want.Unit {
			return false
		}
	}
	return true
}

func findCloudCatalogOperation(catalog CloudCatalog, id string) (CloudCatalogOperation, bool) {
	for _, operation := range catalog.Operations {
		if operation.ID == id {
			return operation, true
		}
	}
	return CloudCatalogOperation{}, false
}

func validateCloudSourceFieldMapping(mapping CloudSourceFieldMapping, catalog CloudCatalog) error {
	if strings.TrimSpace(mapping.SourceSchemaID) == "" || strings.TrimSpace(mapping.SourceFieldID) == "" || strings.TrimSpace(mapping.SourcePointer) == "" || strings.TrimSpace(mapping.DeclaredType) == "" || strings.TrimSpace(mapping.Cardinality) == "" {
		return fmt.Errorf("source mapping is incomplete")
	}
	foundSchema := false
	for _, shape := range catalog.SchemaShapes {
		if shape.ID == mapping.SourceSchemaID {
			foundSchema = true
			break
		}
	}
	if !foundSchema {
		return fmt.Errorf("source schema %q is absent from catalog", mapping.SourceSchemaID)
	}
	switch mapping.Disposition {
	case CloudSourceMapsExactSourceFact, CloudSourceMapsExactLifecycleFact, CloudSourceMapsExactRelationshipFact:
		if strings.TrimSpace(mapping.TargetField) == "" {
			return fmt.Errorf("%s mapping has no target field", mapping.Disposition)
		}
	case CloudSourceNotObserved, CloudSourceUnsupported, CloudSourceUnknown, CloudSourcePrivateOnly:
		if mapping.TargetField != "" || mapping.Unit != "" {
			return fmt.Errorf("%s mapping must not claim a target or unit", mapping.Disposition)
		}
	default:
		return fmt.Errorf("unknown field disposition %q", mapping.Disposition)
	}
	return nil
}

func strictUniqueNonemptyCloudStrings(values []string) bool {
	seen := map[string]struct{}{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func makeCloudAPIGraphCandidate(catalogs []CloudCatalog, targets []CloudSourceObjectTarget) map[string]any {
	items := append([]CloudCatalog(nil), catalogs...)
	sort.Slice(items, func(i, j int) bool {
		return cloudCatalogKey(items[i].ProviderID, items[i].ServiceID, items[i].APISurfaceID) < cloudCatalogKey(items[j].ProviderID, items[j].ServiceID, items[j].APISurfaceID)
	})
	// Do not embed arbitrary parser structs as a pseudo graph.  These rows are
	// the nested candidate inventory contract: provider/service/API,
	// model lineage, operation/resource association, and source schema rows.
	rows := make([]map[string]any, 0)
	for _, catalog := range items {
		selectedOperations := map[string]bool{}
		selectedSchemas := map[string]bool{}
		for _, target := range targets {
			if target.ProviderID == catalog.ProviderID && target.ServiceID == catalog.ServiceID && target.APISurfaceID == catalog.APISurfaceID {
				selectedOperations[target.OperationID] = true
				if target.MappingContract != nil {
					selectedSchemas[target.MappingContract.ObjectSchemaID] = true
				}
			}
		}
		for _, resource := range catalog.Resources {
			selectedResourceOperations := make([]string, 0, len(resource.OperationIDs))
			for _, operation := range resource.OperationIDs {
				if selectedOperations[operation] {
					selectedResourceOperations = append(selectedResourceOperations, operation)
				}
			}
			if len(selectedResourceOperations) == 0 {
				continue
			}
			rows = append(rows, map[string]any{"row_kind": "cloud_api_resource", "format": catalog.Format, "source": catalog.Source, "provider_id": catalog.ProviderID, "service_id": catalog.ServiceID, "api_surface_id": catalog.APISurfaceID, "api_version": catalog.APIVersion, "model_sha256": catalog.ModelSHA256, "protocol_bindings": catalog.ProtocolBindings, "resource_id": resource.ID, "operation_ids": selectedResourceOperations, "declaration_status": resource.DeclarationStatus, "evidence_locator": resource.Locator, "declaration_evidence_locator": resource.DeclarationEvidenceLocator})
		}
		for _, operation := range catalog.Operations {
			if !selectedOperations[operation.ID] {
				continue
			}
			rows = append(rows, map[string]any{"row_kind": "cloud_api_operation", "format": catalog.Format, "source": catalog.Source, "provider_id": catalog.ProviderID, "service_id": catalog.ServiceID, "api_surface_id": catalog.APISurfaceID, "api_version": catalog.APIVersion, "model_sha256": catalog.ModelSHA256, "protocol_bindings": catalog.ProtocolBindings, "operation_id": operation.ID, "resource_ids": operation.ResourceIDs, "association_status": operation.AssociationStatus, "evidence_locator": operation.Locator, "resource_association_evidence": operation.ResourceAssociationEvidence})
		}
		for _, shape := range catalog.SchemaShapes {
			if !selectedSchemas[shape.ID] {
				continue
			}
			rows = append(rows, map[string]any{"row_kind": "cloud_api_schema", "format": catalog.Format, "source": catalog.Source, "provider_id": catalog.ProviderID, "service_id": catalog.ServiceID, "api_surface_id": catalog.APISurfaceID, "api_version": catalog.APIVersion, "model_sha256": catalog.ModelSHA256, "protocol_bindings": catalog.ProtocolBindings, "schema_id": shape.ID, "declared_type": shape.DeclaredType, "interpretation_status": shape.InterpretationStatus, "evidence_locator": shape.Locator})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		left, _ := canonicalFactoryJSON(rows[i])
		right, _ := canonicalFactoryJSON(rows[j])
		return bytes.Compare(left, right) < 0
	})
	return map[string]any{"package_kind": sourcePackageOutputRoleAPIGraphArtifact, "package_version": cloudSourcePackageVersion, "candidate_only": true, "body_free_receipt": false, "jsonl_row_contract": "velenza.cloud_api_graph_row/1", "rows": rows}
}

func makeCloudReusableProfileCandidate(catalogs []CloudCatalog) map[string]any {
	providers := map[string][]CloudCatalog{}
	for _, catalog := range catalogs {
		providers[catalog.ProviderID] = append(providers[catalog.ProviderID], catalog)
	}
	ids := make([]string, 0, len(providers))
	for id := range providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		services := providers[id]
		sort.Slice(services, func(i, j int) bool { return services[i].ServiceID < services[j].ServiceID })
		// Only mechanism IDs common to every retained service belong in the
		// shared profile. Scopes and signing requirements are service/operation
		// residuals and must never be unioned into provider-wide permission.
		common := map[string]bool{}
		for _, requirement := range services[0].Authentication {
			common[requirement.ID] = true
		}
		for _, service := range services[1:] {
			present := map[string]bool{}
			for _, requirement := range service.Authentication {
				present[requirement.ID] = true
			}
			for mechanism := range common {
				if !present[mechanism] {
					delete(common, mechanism)
				}
			}
		}
		mechanisms := make([]string, 0, len(common))
		for mechanism := range common {
			mechanisms = append(mechanisms, mechanism)
		}
		sort.Strings(mechanisms)
		definition := map[string]any{"provider_id": id, "shared_authentication_mechanism_ids": mechanisms}
		profileRaw, _ := canonicalFactoryJSON(definition)
		profileRef := "sha256:" + sha256Hex(profileRaw)
		residuals := make([]map[string]any, 0, len(services))
		for _, service := range services {
			requirements := make([]map[string]any, 0, len(service.Authentication))
			for _, requirement := range service.Authentication {
				requirements = append(requirements, map[string]any{"id": requirement.ID, "requirement_references": requirement.RequirementReferences, "scope_references": requirement.ScopeReferences, "service_signing_requirement_references": requirement.ServiceSigningRequirementReferences})
			}
			residuals = append(residuals, map[string]any{"provider_profile_ref": profileRef, "service_id": service.ServiceID, "api_surface_id": service.APISurfaceID, "api_version": service.APIVersion, "model_sha256": service.ModelSHA256, "authentication_requirements": requirements})
		}
		result = append(result, map[string]any{"provider_id": id, "provider_profile_ref": profileRef, "shared_authentication_requirements_are_not_credentials_or_grants": true, "provider_profile_definition": definition, "service_residuals": residuals})
	}
	return map[string]any{"package_kind": sourcePackageOutputRoleReusableProfile, "package_version": cloudSourcePackageVersion, "candidate_only": true, "body_free_receipt": false, "providers": result}
}

func makeCloudMappingCandidate(targets []CloudSourceObjectTarget) map[string]any {
	return map[string]any{"package_kind": sourcePackageOutputRoleSourceMapping, "package_version": cloudSourcePackageVersion, "candidate_only": true, "body_free_receipt": false, "targets": targets, "source_value_states": []string{"present", "null", "absent", "unknown"}, "partial_pages_never_authorize_deletion": true, "api_model_mapping_revision_is_lineage_not_stable_identity": true}
}
func makeCloudResidualCandidate(targets []CloudSourceObjectTarget) map[string]any {
	return map[string]any{"package_kind": sourcePackageOutputRoleResidualCircuitPackage, "package_version": cloudSourcePackageVersion, "candidate_only": true, "body_free_receipt": false, "operation_targets": targets, "execution_status": "unresolved_pending_admitted_circuit_and_connector_vault_interface"}
}
func makeCloudARCCandidate(targets []CloudSourceObjectTarget) map[string]any {
	classes := map[string]bool{}
	for _, target := range targets {
		classes[target.RecordClassContractRef] = true
	}
	refs := make([]string, 0, len(classes))
	for ref := range classes {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return map[string]any{"package_kind": sourcePackageOutputRoleARCReferenceBlueprint, "package_version": cloudSourcePackageVersion, "candidate_only": true, "body_free_receipt": false, "neutral_record_class_contract_refs": refs, "owner_validation": "pending_content_derived_package_proof", "admission_authorized": false}
}

// EqualCloudSourceCandidateBundles supports deterministic acceptance tests
// without interpreting a candidate as an admitted artifact.
func EqualCloudSourceCandidateBundles(left, right CloudSourceCandidateBundle) bool {
	if left.Status != right.Status || left.Version != right.Version || len(left.Documents) != len(right.Documents) || !equalCloudStringSlices(left.UnresolvedDependencies, right.UnresolvedDependencies) {
		return false
	}
	for role, raw := range left.Documents {
		if !bytes.Equal(raw, right.Documents[role]) {
			return false
		}
	}
	return true
}

func equalCloudStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
