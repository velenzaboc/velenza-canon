package providerplan

import "testing"

func TestCloudMappingOccurrenceRosterClosesAllSelectedProgramsAndRecipes(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := BuildCloudMappingOccurrenceRoster(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Occurrences) != 255 || len(r.Resources) != 6 || r.Totals != (CloudMappingDispositionTotals{Mapped: 31, Private: 24, Unsupported: 200}) {
		t.Fatalf("occurrence closure fields=%d resources=%d %+v", len(r.Occurrences), len(r.Resources), r.Totals)
	}
	seen := map[string]bool{}
	fieldSymbols := map[string]bool{}
	owners := map[string]string{}
	mapped := 0
	for _, x := range r.Occurrences {
		k := x.TargetKey + "\x00" + x.Field.SourcePointer
		if seen[k] {
			t.Fatalf("duplicate %q", k)
		}
		seen[k] = true
		if x.SourceSchemaOwnerSymbol == x.APIResourceSymbol || x.FieldSourceSymbol == "" || x.FieldSourceSymbol != x.Program.SourceSymbol || fieldSymbols[x.FieldSourceSymbol] || x.Program.FieldPointer == "" || x.Program.ProfileID == "" || x.Program.Locator.JSONPointer == "" {
			t.Fatalf("unbridged occurrence %#v", x)
		}
		fieldSymbols[x.FieldSourceSymbol] = true
		if owners[x.TargetKey] != "" && owners[x.TargetKey] != x.SourceSchemaOwnerSymbol {
			t.Fatalf("target %q has inconsistent source-schema owner", x.TargetKey)
		}
		owners[x.TargetKey] = x.SourceSchemaOwnerSymbol
		if x.Field.Disposition == CloudSourceMapsExactSourceFact || x.Field.Disposition == CloudSourceMapsExactLifecycleFact || x.Field.Disposition == CloudSourceMapsExactRelationshipFact {
			mapped++
			if x.Field.TargetField == "" {
				t.Fatalf("mapped occurrence lacks neutral target %q", k)
			}
		}
	}
	for target, owner := range owners {
		var schemaPointer string
		for _, occurrence := range r.Occurrences {
			if occurrence.TargetKey == target {
				schemaPointer = occurrence.SourceSchemaOwnerLocator.JSONPointer
				break
			}
		}
		if owner == "" || schemaPointer == "" {
			t.Fatalf("target %q has no declared schema owner evidence", target)
		}
	}
	coveredTargets := 0
	for _, resource := range r.Resources {
		coveredTargets += len(resource.TargetKeys)
	}
	if coveredTargets != 9 {
		t.Fatalf("resource bridge target closure=%d, want nine operations", coveredTargets)
	}
	groups, err := BuildCloudMappingResourceFieldGroups(r)
	if err != nil || len(groups) != 6 {
		t.Fatalf("resource groups=%d err=%v", len(groups), err)
	}
	groupFields := 0
	for _, group := range groups {
		groupFields += len(group.Occurrences)
		if len(group.SchemaSurfaces) == 0 {
			t.Fatalf("resource group has no schema surfaces: %#v", group)
		}
		for _, surface := range group.SchemaSurfaces {
			if surface.SourceSchemaOwnerSymbol == "" || surface.SourceSchemaOwnerLocator.JSONPointer == "" || len(surface.FieldSourceSymbols) == 0 {
				t.Fatalf("schema surface is incomplete: %#v", surface)
			}
		}
	}
	if groupFields != 255 {
		t.Fatalf("resource group occurrence closure=%d", groupFields)
	}
	aws, err := CloudMappingOccurrenceRosterForProvider(r, "aws")
	if err != nil {
		t.Fatal(err)
	}
	gcp, err := CloudMappingOccurrenceRosterForProvider(r, "gcp")
	if err != nil {
		t.Fatal(err)
	}
	partitionTotals := CloudMappingDispositionTotals{Mapped: aws.Totals.Mapped + gcp.Totals.Mapped, NotObserved: aws.Totals.NotObserved + gcp.Totals.NotObserved, Private: aws.Totals.Private + gcp.Totals.Private, Unknown: aws.Totals.Unknown + gcp.Totals.Unknown, Unsupported: aws.Totals.Unsupported + gcp.Totals.Unsupported}
	if len(aws.Occurrences)+len(gcp.Occurrences) != len(r.Occurrences) || partitionTotals != r.Totals {
		t.Fatalf("provider partitions do not close full roster: aws=%+v gcp=%+v all=%+v", aws.Totals, gcp.Totals, r.Totals)
	}
	if mapped != 31 {
		t.Fatalf("mapped recipes=%d", mapped)
	}
}

func TestCloudMappingOccurrenceRosterRefusesProgramTampering(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := BuildCloudMappingOccurrenceRoster(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	r.Occurrences[0].Program.ProgramSHA256 = sha256Hex([]byte("tampered"))
	if err := ValidateCloudMappingOccurrenceRoster(r, scope.ExpectedDispositionTotals); err == nil {
		t.Fatal("tampered program accepted")
	}
}

func TestCloudMappingOccurrenceRosterRejectsForgedClosureAndBridge(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := LoadCloudMappingPackageScope("../../testdata/cloudapi/mapping-package-scope.json")
	if err != nil {
		t.Fatal(err)
	}
	base, err := BuildCloudMappingOccurrenceRoster(request, scope)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*CloudMappingOccurrenceRoster){
		"deleted with forged totals": func(r *CloudMappingOccurrenceRoster) { r.Occurrences = r.Occurrences[1:]; r.Totals.Mapped-- },
		"program rebound and rehashed": func(r *CloudMappingOccurrenceRoster) {
			r.Occurrences[0].Program.Program = []byte(`{"program_kind":"wrong"}`)
			r.Occurrences[0].Program.ProgramSHA256 = sha256Hex(r.Occurrences[0].Program.Program)
		},
		"resource retarget": func(r *CloudMappingOccurrenceRoster) { r.Resources[0].APIResourceSymbol = "other" },
		"resource omitted":  func(r *CloudMappingOccurrenceRoster) { r.Resources = r.Resources[1:] },
	} {
		r := base
		r.Occurrences = append([]CloudMappingOccurrence(nil), base.Occurrences...)
		r.Resources = append([]CloudMappingSelectedResource(nil), base.Resources...)
		mutate(&r)
		if err := ValidateCloudMappingOccurrenceRoster(r, scope.ExpectedDispositionTotals); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
