package providerplan

// Cloud coverage is a deterministic review artifact over an already-validated
// candidate mapping package.  It accounts for every selected source occurrence
// without making a qualification, admission, or source-value claim.

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
)

const (
	cloudCoverageVersion = "1"
	cloudCoverageStatus  = "candidate_coverage_backlog"
)

// CloudCoverageEntry is one selected source occurrence. It contains model and
// extraction-program coordinates only; it never carries observed customer data.
type CloudCoverageEntry struct {
	ProviderID               string                       `json:"provider_id"`
	ServiceID                string                       `json:"service_id"`
	APISurfaceID             string                       `json:"api_surface_id"`
	OperationID              string                       `json:"operation_id"`
	SourceObjectType         string                       `json:"source_object_type"`
	RecordClassSymbol        string                       `json:"record_class_symbol"`
	RecordClassContractRef   string                       `json:"record_class_contract_ref"`
	AccountableOwnerRef      string                       `json:"accountable_owner_ref"`
	AccountableOwnerSHA256   string                       `json:"accountable_owner_sha256"`
	ModelSourceID            string                       `json:"model_source_id"`
	ModelSHA256              string                       `json:"model_sha256"`
	SourceFieldID            string                       `json:"source_field_id"`
	SourcePointer            string                       `json:"source_pointer"`
	Disposition              CloudSourceFieldDisposition  `json:"disposition"`
	DispositionReason        string                       `json:"disposition_reason"`
	NextOwnerAction          string                       `json:"next_owner_action"`
	DerivationProfileID      string                       `json:"derivation_profile_id,omitempty"`
	DerivationProfileVersion string                       `json:"derivation_profile_version,omitempty"`
	DerivationProgramSHA256  string                       `json:"derivation_program_sha256,omitempty"`
	EvidenceLocator          *CloudCatalogEvidenceLocator `json:"evidence_locator,omitempty"`
	SelectedRangeSHA256      string                       `json:"selected_range_sha256,omitempty"`
	DerivationGapReason      string                       `json:"derivation_gap_reason,omitempty"`
}

// CloudCoverageBacklog is a candidate-only, exhaustive field ledger for one
// declared mapping scope. Document is exact canonical JSON with a newline.
type CloudCoverageBacklog struct {
	Status            string                        `json:"status"`
	Version           string                        `json:"version"`
	ScopeID           string                        `json:"scope_id"`
	ScopeSHA256       string                        `json:"scope_sha256"`
	DispositionTotals CloudMappingDispositionTotals `json:"disposition_totals"`
	Entries           []CloudCoverageEntry          `json:"entries"`
	DocumentSHA256    string                        `json:"document_sha256"`
	Document          []byte                        `json:"-"`
	publicationSeal   string
}

// BuildCloudCoverageBacklog derives an exhaustive coverage artifact directly
// from the generic mapping builder.  It is data-driven for any declared scope.
func BuildCloudCoverageBacklog(request CloudSourceCandidateRequest, scope CloudMappingPackageScope) (CloudCoverageBacklog, error) {
	pkg, err := BuildCloudMappingPackage(request, scope)
	if err != nil {
		return CloudCoverageBacklog{}, fmt.Errorf("build mapping package for coverage: %w", err)
	}
	return buildCloudCoverageBacklogFromValidatedPackage(pkg, scope)
}

// buildCloudCoverageBacklogFromValidatedPackage derives the coverage closure
// from a freshly built and validated mapping package. It is intentionally
// package-private: callers that do not hold a package built by
// BuildCloudMappingPackage must use BuildCloudCoverageBacklog instead.
func buildCloudCoverageBacklogFromValidatedPackage(pkg CloudMappingPackage, scope CloudMappingPackageScope) (CloudCoverageBacklog, error) {
	entries := []CloudCoverageEntry{}
	for _, provider := range pkg.ProviderPackages {
		raw := pkg.Documents[provider.DocumentRole]
		var document cloudMappingProviderDocument
		if err := strictUnmarshal(raw, &document); err != nil {
			return CloudCoverageBacklog{}, fmt.Errorf("decode provider coverage source %q: %w", provider.ProviderID, err)
		}
		if err := validateCloudMappingFieldPackages(document); err != nil {
			return CloudCoverageBacklog{}, fmt.Errorf("validate provider coverage source %q: %w", provider.ProviderID, err)
		}
		derivations := map[string]cloudMappingFieldDerivationPackage{}
		for _, item := range document.FieldDerivations {
			derivations[item.TargetKey] = item
		}
		for _, target := range document.Targets {
			item, ok := derivations[cloudTargetKey(target)]
			if !ok {
				return CloudCoverageBacklog{}, fmt.Errorf("coverage has no field derivation package for target %q", cloudTargetKey(target))
			}
			byPointer := map[string]cloudMappingFieldProgram{}
			for _, program := range item.Programs {
				byPointer[program.FieldPointer] = program
			}
			gaps := map[string]string{}
			for _, gap := range item.Gaps {
				gaps[gap.FieldPointer] = gap.Reason
			}
			fields := append([]CloudMappingContractField(nil), target.MappingContract.Fields...)
			for _, nested := range target.MappingContract.Nested {
				fields = append(fields, nested.Fields...)
			}
			for _, field := range fields {
				entry := CloudCoverageEntry{
					ProviderID: target.ProviderID, ServiceID: target.ServiceID, APISurfaceID: target.APISurfaceID,
					OperationID: target.OperationID, SourceObjectType: target.SourceObjectType,
					RecordClassSymbol: target.RecordClassSymbol, RecordClassContractRef: target.RecordClassContractRef,
					AccountableOwnerRef: target.MappingContract.Neutral.OwnerRef, AccountableOwnerSHA256: target.MappingContract.Neutral.OwnerSHA256,
					ModelSourceID: item.ModelSourceID, ModelSHA256: item.ModelSHA256,
					SourceFieldID: field.SourceFieldID, SourcePointer: field.SourcePointer, Disposition: field.Disposition,
				}
				entry.DispositionReason, entry.NextOwnerAction = cloudCoverageDispositionBoundary(field.Disposition)
				if program, ok := byPointer[field.SourcePointer]; ok {
					locator := program.Locator
					entry.DerivationProfileID, entry.DerivationProfileVersion, entry.DerivationProgramSHA256 = program.ProfileID, program.ProfileVersion, program.ProgramSHA256
					entry.EvidenceLocator, entry.SelectedRangeSHA256 = &locator, program.SelectedRangeSHA256
				} else if gap, ok := gaps[field.SourcePointer]; ok {
					entry.DerivationGapReason = gap
				} else {
					return CloudCoverageBacklog{}, fmt.Errorf("coverage occurrence %q has neither derivation program nor gap", field.SourcePointer)
				}
				entries = append(entries, entry)
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return cloudCoverageEntryKey(entries[i]) < cloudCoverageEntryKey(entries[j]) })
	totals, err := cloudCoverageTotals(entries)
	if err != nil {
		return CloudCoverageBacklog{}, err
	}
	if totals != pkg.DispositionTotals || totals != scope.ExpectedDispositionTotals {
		return CloudCoverageBacklog{}, fmt.Errorf("coverage totals do not equal mapping scope")
	}
	scopeRaw, err := canonicalFactoryJSON(scope)
	if err != nil {
		return CloudCoverageBacklog{}, err
	}
	backlog := CloudCoverageBacklog{Status: cloudCoverageStatus, Version: cloudCoverageVersion, ScopeID: scope.ScopeID, ScopeSHA256: sha256Hex(scopeRaw), DispositionTotals: totals, Entries: entries}
	raw, err := canonicalCloudCoverageDocument(backlog)
	if err != nil {
		return CloudCoverageBacklog{}, err
	}
	backlog.DocumentSHA256, backlog.Document = sha256Hex(raw), raw
	backlog.publicationSeal = cloudCoveragePublicationSeal(backlog.DocumentSHA256, backlog.ScopeSHA256)
	return backlog, nil
}

func canonicalCloudCoverageDocument(backlog CloudCoverageBacklog) ([]byte, error) {
	body := struct {
		Status            string                        `json:"status"`
		Version           string                        `json:"version"`
		ScopeID           string                        `json:"scope_id"`
		ScopeSHA256       string                        `json:"scope_sha256"`
		DispositionTotals CloudMappingDispositionTotals `json:"disposition_totals"`
		Entries           []CloudCoverageEntry          `json:"entries"`
	}{backlog.Status, backlog.Version, backlog.ScopeID, backlog.ScopeSHA256, backlog.DispositionTotals, backlog.Entries}
	raw, err := canonicalFactoryJSON(body)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func cloudCoveragePublicationSeal(documentSHA256, scopeSHA256 string) string {
	return sha256Hex([]byte("cloud-coverage-publication-v1\x00" + documentSHA256 + "\x00" + scopeSHA256))
}

func cloudCoverageDispositionBoundary(disposition CloudSourceFieldDisposition) (string, string) {
	switch disposition {
	case CloudSourceMapsExactSourceFact, CloudSourceMapsExactLifecycleFact, CloudSourceMapsExactRelationshipFact:
		return "exact candidate mapping disposition; production semantic and source-owner qualification remain separate", "qualify the mapped recipe with the owning source and neutral contracts"
	case CloudSourcePrivateOnly:
		return "source-private disposition; no source-neutral semantic assertion is authorized", "retain privately or have the source-neutral owner declare an evidence-backed public semantic contract"
	case CloudSourceUnsupported:
		return "explicit unsupported semantic gap; no neutral translation is authorized", "source-neutral semantic owner must decide an evidence-backed mapping, private disposition, or retained unsupported result"
	case CloudSourceNotObserved:
		return "declared not-observed outcome; absence is not a positive fact", "retain the not-observed contract or add an evidence-backed acquisition source"
	case CloudSourceUnknown:
		return "declared unknown outcome; unknown is not inferred", "resolve through the owning semantic contract or retain unknown"
	default:
		return "unrecognized disposition", "refuse until the mapping contract supplies a recognized disposition"
	}
}

func cloudCoverageEntryKey(entry CloudCoverageEntry) string {
	return entry.ProviderID + "\x00" + entry.ServiceID + "\x00" + entry.APISurfaceID + "\x00" + entry.OperationID + "\x00" + entry.SourceObjectType + "\x00" + entry.SourcePointer
}

func cloudCoverageTotals(entries []CloudCoverageEntry) (CloudMappingDispositionTotals, error) {
	totals := CloudMappingDispositionTotals{}
	seen := map[string]bool{}
	for _, entry := range entries {
		key := cloudCoverageEntryKey(entry)
		if key == "" || seen[key] {
			return CloudMappingDispositionTotals{}, fmt.Errorf("coverage has duplicate or incomplete occurrence")
		}
		if entry.RecordClassContractRef == "" || entry.AccountableOwnerRef == "" || !isLowerSHA256(entry.AccountableOwnerSHA256) {
			return CloudMappingDispositionTotals{}, fmt.Errorf("coverage occurrence %q has no pinned accountable neutral owner", key)
		}
		if entry.AccountableOwnerRef != entry.RecordClassContractRef {
			return CloudMappingDispositionTotals{}, fmt.Errorf("coverage occurrence %q accountable owner does not equal selected neutral record owner", key)
		}
		seen[key] = true
		switch entry.Disposition {
		case CloudSourceMapsExactSourceFact, CloudSourceMapsExactLifecycleFact, CloudSourceMapsExactRelationshipFact:
			totals.Mapped++
		case CloudSourcePrivateOnly:
			totals.Private++
		case CloudSourceUnsupported:
			totals.Unsupported++
		case CloudSourceUnknown:
			totals.Unknown++
		case CloudSourceNotObserved:
			totals.NotObserved++
		default:
			return CloudMappingDispositionTotals{}, fmt.Errorf("coverage has unrecognized disposition %q", entry.Disposition)
		}
	}
	return totals, nil
}

// ValidateCloudCoverageBacklog refuses substituted, reordered, partial, or
// stale coverage bytes by rebuilding the exact declared closure.
func ValidateCloudCoverageBacklog(raw []byte, request CloudSourceCandidateRequest, scope CloudMappingPackageScope) error {
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return fmt.Errorf("coverage document requires canonical terminating newline")
	}
	var decoded struct {
		Status            string                        `json:"status"`
		Version           string                        `json:"version"`
		ScopeID           string                        `json:"scope_id"`
		ScopeSHA256       string                        `json:"scope_sha256"`
		DispositionTotals CloudMappingDispositionTotals `json:"disposition_totals"`
		Entries           []CloudCoverageEntry          `json:"entries"`
	}
	if err := strictUnmarshal(raw, &decoded); err != nil {
		return fmt.Errorf("decode coverage document: %w", err)
	}
	expected, err := BuildCloudCoverageBacklog(request, scope)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, expected.Document) {
		return fmt.Errorf("coverage document differs from exact declared mapping closure")
	}
	return nil
}

// WriteCloudCoverageBacklogExclusive writes one reviewable artifact without
// merging with or replacing an existing directory.
func WriteCloudCoverageBacklogExclusive(root string, backlog CloudCoverageBacklog) error {
	if root == "" || !filepath.IsAbs(root) || backlog.Status != cloudCoverageStatus || backlog.Version != cloudCoverageVersion || !isLowerSHA256(backlog.ScopeSHA256) || sha256Hex(backlog.Document) != backlog.DocumentSHA256 || backlog.publicationSeal != cloudCoveragePublicationSeal(backlog.DocumentSHA256, backlog.ScopeSHA256) {
		return fmt.Errorf("coverage backlog has invalid publication boundary")
	}
	if len(backlog.Entries) == 0 {
		return fmt.Errorf("coverage backlog has no occurrences")
	}
	totals, err := cloudCoverageTotals(backlog.Entries)
	if err != nil {
		return err
	}
	if totals != backlog.DispositionTotals {
		return fmt.Errorf("coverage backlog disposition totals do not bind its entries")
	}
	rebuilt, err := canonicalCloudCoverageDocument(backlog)
	if err != nil {
		return err
	}
	if !bytes.Equal(rebuilt, backlog.Document) {
		return fmt.Errorf("coverage backlog public summary does not bind its sealed document")
	}
	return publishFactorySourceOutputDirectoryExclusive(root, []factorySourceOutputFile{{RelativePath: "cloud_mapping_coverage_backlog.json", Raw: backlog.Document}})
}
