package providerplan

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// CloudModelRefreshOptions names a successor candidate, never an admitted
// source or a credential. The caller retains both old and new model bytes.
type CloudModelRefreshOptions struct {
	ModelID               string                     `json:"model_id"`
	ModelPath             string                     `json:"model_path"`
	ExpectedSHA256        string                     `json:"expected_sha256"`
	Source                CloudCatalogSourceIdentity `json:"source"`
	MappingVersion        string                     `json:"mapping_version"`
	ServiceProfileVersion string                     `json:"service_profile_version"`
	Retrieved             string                     `json:"retrieved"`
}

func LoadCloudModelRefreshOptions(path string) (CloudModelRefreshOptions, error) {
	var options CloudModelRefreshOptions
	raw, err := os.ReadFile(path)
	if err != nil {
		return options, err
	}
	if len(raw) > 1024*1024 {
		return options, fmt.Errorf("refresh options exceed input bound")
	}
	if err := strictUnmarshal(raw, &options); err != nil {
		return CloudModelRefreshOptions{}, err
	}
	return options, nil
}

// BuildCloudModelRefreshBundle validates both generations against their pinned
// local material, then returns a sealed, exclusively publishable successor
// package. It includes source inputs, revision audit and a fully reconstructed
// preparation so callers can rerun the normal prepare --verify command.
func BuildCloudModelRefreshBundle(inputPath, profilesPath string, scope CloudMappingPackageScope, policy CloudIngestionHandoffPolicy, options CloudModelRefreshOptions) (CloudFactoryPreparation, error) {
	var empty CloudFactoryPreparation
	base := filepath.Dir(inputPath)
	input, err := readCloudCandidateInput(inputPath)
	if err != nil {
		return empty, err
	}
	oldRequest, err := loadCloudSourceCandidateInputAt(base, input, NewCloudCatalogParser())
	if err != nil {
		return empty, err
	}
	profiles, err := LoadCloudAPIProfileDocument(profilesPath)
	if err != nil {
		return empty, err
	}
	if err := ValidateCloudAPIProfileDocument(profiles, oldRequest.Catalogs, oldRequest.Targets); err != nil {
		return empty, err
	}
	var oldRaw []byte
	for _, model := range oldRequest.retainedModels {
		if model.Source.ID == options.ModelID {
			oldRaw = model.Raw
		}
	}
	newPath, err := cloudCandidateLocalPath(base, options.ModelPath)
	if err != nil {
		return empty, err
	}
	newRaw, err := os.ReadFile(newPath)
	if err != nil {
		return empty, err
	}
	next, nextProfiles, audit, err := RefreshCloudModelCandidates(input, profiles, oldRaw, newRaw, options)
	if err != nil {
		return empty, err
	}
	request, err := loadCloudSourceCandidateInputAt(base, next, NewCloudCatalogParser())
	if err != nil {
		return empty, err
	}
	prepared, err := BuildCloudFactoryPreparation(request, scope, nextProfiles, policy)
	if err != nil {
		return empty, err
	}
	files := make(map[string][]byte)
	addJSON := func(name string, value any) error {
		b, e := canonicalFactoryJSON(value)
		if e == nil {
			files[name] = b
		}
		return e
	}
	for name, value := range map[string]any{"candidate-input.json": next, "profiles.json": nextProfiles, "scope.json": scope, "ingestion-policy.json": policy, "revision-audit.json": audit} {
		if err := addJSON(name, value); err != nil {
			return empty, err
		}
	}
	addMaterial := func(materialBase, name, pin string) error {
		resolved, err := cloudCandidateLocalPath(materialBase, name)
		if err != nil {
			return err
		}
		raw, err := os.ReadFile(resolved)
		if err != nil {
			return err
		}
		if sha256Hex(raw) != pin {
			return fmt.Errorf("refresh material bytes differ from exact pin")
		}
		if previous, exists := files[name]; exists && !bytes.Equal(previous, raw) {
			return fmt.Errorf("refresh output namespace collision")
		}
		files[name] = raw
		return nil
	}
	if err := addMaterial(base, next.NeutralSchemaExportPath, next.NeutralSchemaExportSHA256); err != nil {
		return empty, err
	}
	for _, model := range next.Models {
		if err := addMaterial(base, model.ModelPath, model.ExpectedSHA256); err != nil {
			return empty, err
		}
		for i, name := range model.SupplementalEvidencePaths {
			if err := addMaterial(base, name, model.SupplementalEvidence[i].ExpectedSHA256); err != nil {
				return empty, err
			}
		}
	}
	for _, target := range next.Targets {
		for _, binding := range target.MappingContract.EvidenceBindings {
			if err := addMaterial(base, binding.SourcePath, binding.ExpectedSHA256); err != nil {
				return empty, err
			}
		}
	}
	addEvidence := func(items []CloudProfileEvidence) error {
		for _, item := range items {
			materialBase := filepath.Dir(profilesPath)
			if item.LocalPath == options.ModelPath {
				materialBase = base
			}
			if err := addMaterial(materialBase, item.LocalPath, item.ExpectedSHA256); err != nil {
				return err
			}
		}
		return nil
	}
	for _, provider := range nextProfiles.Providers {
		if err := addEvidence(provider.Evidence); err != nil {
			return empty, err
		}
		for _, service := range provider.Services {
			if err := addEvidence(service.Evidence); err != nil {
				return empty, err
			}
			for _, operation := range service.Operations {
				if err := addEvidence(operation.Evidence); err != nil {
					return empty, err
				}
			}
		}
	}
	for _, file := range prepared.files {
		name := "prepared/" + file.RelativePath
		if _, exists := files[name]; exists {
			return empty, fmt.Errorf("refresh preparation namespace collision")
		}
		files[name] = file.Raw
	}
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest CloudPreparationManifest
	if err := strictUnmarshal(prepared.ManifestJSON(), &manifest); err != nil {
		return empty, err
	}
	manifest.Status = "candidate_refresh_prepared_unqualified"
	manifest.Documents = nil
	var outputs []factorySourceOutputFile
	for _, name := range names {
		raw := files[name]
		outputs = append(outputs, factorySourceOutputFile{RelativePath: name, Raw: raw})
		manifest.Documents = append(manifest.Documents, CloudPreparationDocument{Path: name, SHA256: sha256Hex(raw), Bytes: len(raw)})
	}
	manifestRaw, err := canonicalFactoryJSON(manifest)
	if err != nil {
		return empty, err
	}
	outputs = append(outputs, factorySourceOutputFile{RelativePath: "refresh-manifest.json", Raw: manifestRaw})
	if _, err := prepareSourcePackageOutputRoster(outputs); err != nil {
		return empty, err
	}
	return CloudFactoryPreparation{files: outputs, manifest: manifestRaw}, nil
}

// RefreshCloudModelCandidates rebinds exact model evidence while preserving
// declarative mappings. Changed semantic evidence refuses: an unchanged byte
// slice may move, but this function cannot approve new meaning. The returned
// candidates still require normal loading, complete mapping/profile validation,
// source qualification and admission.
func RefreshCloudModelCandidates(input CloudSourceCandidateInput, profiles CloudAPIProfileDocument, oldRaw, newRaw []byte, options CloudModelRefreshOptions) (CloudSourceCandidateInput, CloudAPIProfileDocument, CloudModelRevisionAudit, error) {
	fail := func(err error) (CloudSourceCandidateInput, CloudAPIProfileDocument, CloudModelRevisionAudit, error) {
		return CloudSourceCandidateInput{}, CloudAPIProfileDocument{}, CloudModelRevisionAudit{}, err
	}
	if len(input.TargetDocuments) != 0 {
		return fail(fmt.Errorf("refresh requires resolved service target documents"))
	}
	if options.ModelID == "" || options.ModelPath == "" || path.Clean(options.ModelPath) != options.ModelPath || strings.ContainsAny(options.ModelPath, "\\:") || strings.HasPrefix(options.ModelPath, "/") || options.ModelPath == "." || options.ModelPath == ".." || strings.HasPrefix(options.ModelPath, "../") || options.MappingVersion == "" || options.ServiceProfileVersion == "" || options.Retrieved == "" || options.Source.ID != options.ModelID || options.Source.URI == "" || options.Source.StableCoordinate == "" || options.Source.FormatRevision == "" || sha256Hex(newRaw) != options.ExpectedSHA256 {
		return fail(fmt.Errorf("refresh requires exact new model pin and independent successor coordinates"))
	}
	audit, err := AuditCloudModelRevision(oldRaw, newRaw)
	if err != nil {
		return fail(err)
	}
	// Detach all nested slices and maps from the caller before changing bytes.
	inputRaw, err := canonicalFactoryJSON(input)
	if err != nil {
		return fail(err)
	}
	var next CloudSourceCandidateInput
	if err := strictUnmarshal(inputRaw, &next); err != nil {
		return fail(err)
	}
	profileRaw, err := canonicalFactoryJSON(profiles)
	if err != nil {
		return fail(err)
	}
	var nextProfiles CloudAPIProfileDocument
	if err := strictUnmarshal(profileRaw, &nextProfiles); err != nil {
		return fail(err)
	}
	oldSpans, err := cloudCatalogJSONPointerSpans(oldRaw)
	if err != nil {
		return fail(err)
	}
	newSpans, err := cloudCatalogJSONPointerSpans(newRaw)
	if err != nil {
		return fail(err)
	}
	rebase := func(locator *CloudCatalogEvidenceLocator) error {
		if locator.EvidenceID != "model" {
			return fmt.Errorf("selected refresh locator must bind the model evidence")
		}
		old, ok := oldSpans[locator.JSONPointer]
		if !ok || old.start != locator.StartByte || old.end != locator.EndByte {
			return fmt.Errorf("old model locator is not exact")
		}
		fresh, ok := newSpans[locator.JSONPointer]
		if !ok {
			return fmt.Errorf("refreshed model removed selected pointer %q", locator.JSONPointer)
		}
		comparison, err := AuditCloudModelRevision(oldRaw[old.start:old.end], newRaw[fresh.start:fresh.end])
		if err != nil || len(comparison.Changes) != 0 {
			return fmt.Errorf("selected evidence values changed at %q; explicit reassessment required", locator.JSONPointer)
		}
		locator.StartByte, locator.EndByte = fresh.start, fresh.end
		return nil
	}
	modelIndex := -1
	for i := range next.Models {
		if next.Models[i].Source.ID == options.ModelID {
			if modelIndex >= 0 {
				return fail(fmt.Errorf("duplicate selected model"))
			}
			modelIndex = i
		}
	}
	if modelIndex < 0 {
		return fail(fmt.Errorf("selected model absent"))
	}
	model := &next.Models[modelIndex]
	if model.ExpectedSHA256 != audit.OldSHA256 || model.Source.URI != options.Source.URI {
		return fail(fmt.Errorf("refresh changed origin or old content pin"))
	}
	oldPath := model.ModelPath
	for i := range model.ResourceDeclarations {
		if err := rebase(&model.ResourceDeclarations[i].StructureLocator); err != nil {
			return fail(err)
		}
	}
	model.Source, model.ModelPath, model.ExpectedSHA256 = options.Source, options.ModelPath, options.ExpectedSHA256
	matchedTargets := 0
	for i := range next.Targets {
		target := &next.Targets[i]
		if target.ProviderID != model.ProviderID || target.ServiceID != model.ServiceID || target.APISurfaceID != model.APISurfaceID {
			continue
		}
		matchedTargets++
		if target.SourceMappingVersion == options.MappingVersion || target.MappingContract == nil {
			return fail(fmt.Errorf("refresh requires a successor mapping version and mapping contract"))
		}
		target.SourceMappingVersion = options.MappingVersion
		for j := range target.StableIdentityEvidence {
			if err := rebase(&target.StableIdentityEvidence[j].Locator); err != nil {
				return fail(err)
			}
		}
		for j := range target.MappingContract.EvidenceBindings {
			binding := &target.MappingContract.EvidenceBindings[j]
			if binding.SourcePath != oldPath {
				continue
			}
			if binding.ExpectedSHA256 != audit.OldSHA256 || binding.StartByte < 0 || binding.EndByte <= binding.StartByte || binding.EndByte > len(oldRaw) {
				return fail(fmt.Errorf("old semantic evidence binding mismatch"))
			}
			selected := oldRaw[binding.StartByte:binding.EndByte]
			if sha256Hex(selected) != binding.SliceSHA256 {
				return fail(fmt.Errorf("semantic evidence old range digest mismatch"))
			}
			// Prefer the exact old JSON coordinate. Provider exports may reorder
			// object keys without changing any documented value. Such a successor
			// receives a new byte pin; its complete JSON value must be unchanged.
			pointer := ""
			propertyKey := ""
			for key, span := range oldSpans {
				if span.start == binding.StartByte && span.end == binding.EndByte {
					pointer = key
					break
				}
				if span.start > binding.StartByte && span.end == binding.EndByte {
					prefix := bytes.TrimSpace(oldRaw[binding.StartByte:span.start])
					if bytes.HasSuffix(prefix, []byte(":")) {
						var member string
						if strictUnmarshal(bytes.TrimSpace(prefix[:len(prefix)-1]), &member) == nil && strings.HasSuffix(key, "/"+cloudCatalogEscapePointer(member)) {
							pointer = key
							propertyKey = member
							break
						}
					}
				}
			}
			if pointer != "" {
				span, ok := newSpans[pointer]
				if !ok {
					return fail(fmt.Errorf("semantic evidence pointer removed"))
				}
				freshStart := span.start
				oldCompare := selected
				if propertyKey != "" {
					colon := span.start - 1
					for colon >= 0 && strings.ContainsRune(" \r\n\t", rune(newRaw[colon])) {
						colon--
					}
					if colon < 0 || newRaw[colon] != ':' {
						return fail(fmt.Errorf("new semantic member lacks exact property prefix"))
					}
					keyRaw, e := canonicalFactoryJSON(propertyKey)
					if e != nil {
						return fail(e)
					}
					freshStart = bytes.LastIndex(newRaw[:colon], keyRaw)
					if freshStart < 0 || len(bytes.TrimSpace(newRaw[freshStart+len(keyRaw):colon])) != 0 {
						return fail(fmt.Errorf("new semantic member key is ambiguous"))
					}
					oldCompare = append(append([]byte{'{'}, selected...), '}')
				}
				freshSelection := newRaw[freshStart:span.end]
				freshCompare := freshSelection
				if propertyKey != "" {
					freshCompare = append(append([]byte{'{'}, freshSelection...), '}')
				}
				comparison, err := AuditCloudModelRevision(oldCompare, freshCompare)
				if err != nil || len(comparison.Changes) != 0 {
					return fail(fmt.Errorf("semantic evidence values changed; explicit reassessment required"))
				}
				binding.StartByte, binding.EndByte, binding.SliceSHA256 = freshStart, span.end, sha256Hex(freshSelection)
			} else {
				if bytes.Count(newRaw, selected) != 1 {
					return fail(fmt.Errorf("semantic evidence changed or is ambiguous; explicit reassessment required"))
				}
				start := bytes.Index(newRaw, selected)
				binding.StartByte, binding.EndByte = start, start+len(selected)
			}
			binding.SourcePath, binding.ExpectedSHA256 = options.ModelPath, options.ExpectedSHA256
		}
	}
	if matchedTargets == 0 {
		return fail(fmt.Errorf("refresh has no selected targets"))
	}
	refreshEvidence := func(evidence []CloudProfileEvidence) error {
		for i := range evidence {
			item := &evidence[i]
			if item.LocalPath != oldPath {
				continue
			}
			if item.ExpectedSHA256 != audit.OldSHA256 || item.ByteCount != int64(len(oldRaw)) {
				return fmt.Errorf("profile retained-model evidence mismatch")
			}
			item.LocalPath, item.ExpectedSHA256, item.ByteCount = options.ModelPath, options.ExpectedSHA256, int64(len(newRaw))
			item.StableCoordinate, item.Retrieved = options.Source.StableCoordinate, options.Retrieved
		}
		return nil
	}
	matchedServices := 0
	for i := range nextProfiles.Providers {
		provider := &nextProfiles.Providers[i]
		if err := refreshEvidence(provider.Evidence); err != nil {
			return fail(err)
		}
		for j := range provider.Services {
			service := &provider.Services[j]
			if provider.ProviderID != model.ProviderID || service.ServiceID != model.ServiceID || service.APISurfaceID != model.APISurfaceID {
				continue
			}
			matchedServices++
			if service.CatalogModelSHA256 != audit.OldSHA256 || service.ProfileVersion == options.ServiceProfileVersion {
				return fail(fmt.Errorf("service profile needs exact old model and successor version"))
			}
			service.CatalogModelSHA256, service.ProfileVersion = options.ExpectedSHA256, options.ServiceProfileVersion
			if err := refreshEvidence(service.Evidence); err != nil {
				return fail(err)
			}
			for k := range service.Operations {
				operation := &service.Operations[k]
				old := operation.ModelEvidence.Locator
				if old.StartByte < 0 || old.EndByte > len(oldRaw) || old.EndByte <= old.StartByte || sha256Hex(oldRaw[old.StartByte:old.EndByte]) != operation.ModelEvidence.SelectedRangeSHA256 {
					return fail(fmt.Errorf("operation old range digest mismatch"))
				}
				if err := rebase(&operation.ModelEvidence.Locator); err != nil {
					return fail(err)
				}
				fresh := operation.ModelEvidence.Locator
				operation.ModelEvidence.SelectedRangeSHA256 = sha256Hex(newRaw[fresh.StartByte:fresh.EndByte])
				if err := refreshEvidence(operation.Evidence); err != nil {
					return fail(err)
				}
			}
		}
	}
	if matchedServices != 1 {
		return fail(fmt.Errorf("refresh must select one exact service composition"))
	}
	nextProfiles.ProfileSetID = profiles.ProfileSetID + "_" + options.ExpectedSHA256[:16]
	return next, nextProfiles, audit, nil
}
