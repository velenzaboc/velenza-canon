package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func externalRelationshipCorpus() ([]ArtifactSubmission, []ExternalRelationship) {
	makeSubmission := func(kind, canonicalName, sourceClass, reference, _ string) ArtifactSubmission {
		digest := trustedExternalTestDigest(reference)
		if granularExternalClass(kind) {
			policy := ExternalSourceDescriptor{
				ReferenceKind: "https_url_prefix", ReferencePrefix: "https://developer.intuit.com/app/developer/qbo/docs",
				VersionStableNamePrefix: "quickbooks_online_", LocatorKinds: map[string]string{kind: "html_id_or_name"},
			}
			if kind == "release_note" {
				policy.VersionStableNamePrefix = "quickbooks_online_release_"
			}
			fragment := reference[strings.IndexByte(reference, '#')+1:]
			locator := strings.TrimPrefix(strings.TrimPrefix(fragment, "symbol="), "anchor=")
			derived, err := canonicalExternalLocatorName(kind, ArtifactSourceCoordinate{SourceStableReference: reference}, policy, locator)
			if err != nil {
				panic(err)
			}
			canonicalName = derived
		}
		return ArtifactSubmission{
			ArtifactType: kind,
			NodeKind:     kind,
			StableID:     canonicalName,
			SourceCoordinate: &ArtifactSourceCoordinate{
				SourceAuthorityID:     bootstrapSourceAuthority,
				SourceArtifactClass:   sourceClass,
				SourceRefKind:         "coordinate",
				SourceStableReference: reference,
				SectionPath:           "$",
				SourceContentHash:     digest,
				LicenseEvidence:       quickBooksTestRetrievalPermissionEvidence,
			},
		}
	}
	submissions := []ArtifactSubmission{
		makeSubmission(
			"external_reference_doc",
			"quickbooks_online_corpus",
			"official_vendor_documentation",
			"https://developer.intuit.com/app/developer/qbo/docs",
			"1",
		),
		makeSubmission(
			"reference_page",
			"quickbooks_online_invoice_page",
			"official_vendor_documentation",
			"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice",
			"2",
		),
		makeSubmission(
			"api_symbol",
			"quickbooks_online_invoice_api_symbol",
			"official_vendor_documentation",
			"https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice#symbol=invoice_api_symbol",
			"3",
		),
		makeSubmission(
			"release_note",
			"quickbooks_online_release_2026_08",
			"official_release_notes",
			"https://developer.intuit.com/app/developer/qbo/docs/learn/explore-the-quickbooks-online-accounting-api/release-notes#anchor=release-2026-08",
			"4",
		),
		{
			ArtifactType: "section",
			NodeKind:     "section",
			StableID:     "financial_integration_mapping_section",
			Contract:     map[string]interface{}{"canonical_name": "financial_integration_mapping_section"},
			Payload:      map[string]interface{}{"scope": "financial integration mapping"},
		},
	}
	relationships := []ExternalRelationship{
		{
			EdgeLabel:           "official_source_for",
			SourceCanonicalName: "quickbooks_online_corpus",
			TargetCanonicalName: "quickbooks_online_invoice_page",
		},
		{
			EdgeLabel:           "defines_external_symbol",
			SourceCanonicalName: "quickbooks_online_invoice_page",
			TargetCanonicalName: submissions[2].StableID,
		},
		{
			EdgeLabel:           "version_note_for",
			SourceCanonicalName: submissions[3].StableID,
			TargetCanonicalName: submissions[2].StableID,
		},
		{
			EdgeLabel:           "technology_relevant_to",
			SourceCanonicalName: submissions[2].StableID,
			TargetCanonicalName: "financial_integration_mapping_section",
		},
	}
	return submissions, relationships
}

func externalRelationshipPlanFixture(t *testing.T, env *Env, relationships []ExternalRelationship) ([]ArtifactSubmission, []plannedExternalRelationship, []GraphObject) {
	t.Helper()
	submissions, _ := externalRelationshipCorpus()
	canonicalNames := make([]string, len(submissions))
	kinds := make([]NodeKindDescriptor, len(submissions))
	policies := make([]ExternalSourceDescriptor, len(submissions))
	coordinates := make([]ArtifactSourceCoordinate, len(submissions))
	for i, submission := range submissions {
		canonicalNames[i] = submission.StableID
		desc, err := env.Kinds.Resolve(context.Background(), submission.NodeKind)
		if err != nil {
			t.Fatalf("resolve submission[%d] kind: %v", i, err)
		}
		kinds[i] = desc
		coord, err := resolveArtifactSourceCoordinate(submission.NodeKind, submission.StableID, desc, submission.SourceCoordinate)
		if err != nil {
			t.Fatalf("resolve submission[%d] coordinate: %v", i, err)
		}
		coordinates[i] = coord
		policy, err := preflightExternalReferenceSubmissionShape(env, submission, submission.StableID, desc, coord)
		if err != nil {
			t.Fatalf("resolve submission[%d] external shape: %v", i, err)
		}
		policies[i] = policy
	}
	plans, err := planExternalRelationships(context.Background(), env, canonicalNames, kinds, policies, relationships)
	if err != nil {
		t.Fatalf("plan relationships: %v", err)
	}
	objects := make([]GraphObject, len(submissions))
	for i, submission := range submissions {
		coord := coordinates[i]
		objects[i] = GraphObject{
			OrganizationID:        "org-test",
			GraphSnapshotID:       "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			GraphObjectID:         uuid.NewSHA1(oodGraphIDNamespace, []byte("relationship-fixture|"+submission.StableID)).String(),
			ObjectClass:           submission.NodeKind,
			SourceAuthorityID:     coord.SourceAuthorityID,
			SourceArtifactClass:   coord.SourceArtifactClass,
			SourceRefKind:         coord.SourceRefKind,
			SourceStableReference: coord.SourceStableReference,
			VersionCoordinate:     coord.VersionCoordinate,
			SectionPath:           coord.SectionPath,
			SourceContentHash:     coord.SourceContentHash,
			Status:                "active",
			VisibilityScope:       "organization",
		}
	}
	return submissions, plans, objects
}

func TestExternalRelationshipsMaterializeTraversalPathsInOneBatch(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	_, relationships := externalRelationshipCorpus()
	_, plans, objects := externalRelationshipPlanFixture(t, env, relationships)
	edges, err := materializeExternalRelationships(context.Background(), env, "org-test", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "organization", objects, plans)
	if err != nil {
		t.Fatalf("materialize relationships: %v", err)
	}
	if len(edges) != 4 {
		t.Fatalf("edges=%d, want 4", len(edges))
	}

	objectsByID := map[string]GraphObject{}
	for _, object := range objects {
		objectsByID[object.GraphObjectID] = object
	}
	wantPairs := map[string][2]string{
		"official_source_for":     {"external_reference_doc", "reference_page"},
		"defines_external_symbol": {"reference_page", "api_symbol"},
		"version_note_for":        {"release_note", "api_symbol"},
		"technology_relevant_to":  {"api_symbol", "section"},
	}
	for _, edge := range edges {
		pair, ok := wantPairs[edge.EdgeLabel]
		if !ok {
			t.Fatalf("unexpected edge label %q", edge.EdgeLabel)
		}
		if edge.SourceEndpointClass != pair[0] || edge.TargetEndpointClass != pair[1] {
			t.Errorf("edge %q classes=%s->%s, want %s->%s", edge.EdgeLabel, edge.SourceEndpointClass, edge.TargetEndpointClass, pair[0], pair[1])
		}
		if edge.GraphSnapshotID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" || edge.MaterializationRunID != "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" {
			t.Errorf("edge %q escaped materialization snapshot/run", edge.EdgeLabel)
		}
		if edge.SourceContentHash == "" || edge.SourceContentHash != objectsByID[edge.SourceEndpointID].SourceContentHash {
			t.Errorf("edge %q source hash=%q does not bind source object", edge.EdgeLabel, edge.SourceContentHash)
		}
		if len(edge.Embedding) != externalReferenceEmbeddingDimensions || edge.EmbeddingModel != "gemini-embedding-001" {
			t.Errorf("edge %q embedding=%d/%q, want 3072/gemini-embedding-001", edge.EdgeLabel, len(edge.Embedding), edge.EmbeddingModel)
		}
		if edge.AuthoringSourcePath == "" || !strings.HasPrefix(edge.AuthoringSourcePath, "$.relationships.sha256_") {
			t.Errorf("edge %q authoring path=%q is not graph-derived", edge.EdgeLabel, edge.AuthoringSourcePath)
		}
	}
}

func TestExternalRelationshipReplayIsOrderIndependentAndIdempotent(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	submissions, relationships := externalRelationshipCorpus()
	_, firstPlans, objects := externalRelationshipPlanFixture(t, env, relationships)
	first, err := materializeExternalRelationships(context.Background(), env, "org-test", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "organization", objects, firstPlans)
	if err != nil {
		t.Fatalf("first materialization: %v", err)
	}
	reversed := make([]ExternalRelationship, len(relationships))
	for i := range relationships {
		reversed[len(relationships)-1-i] = relationships[i]
	}
	_, secondPlans, _ := externalRelationshipPlanFixture(t, env, reversed)
	second, err := materializeExternalRelationships(context.Background(), env, "org-test", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "organization", objects, secondPlans)
	if err != nil {
		t.Fatalf("replay materialization: %v", err)
	}
	firstIDs, secondIDs := make([]string, len(first)), make([]string, len(second))
	for i := range first {
		firstIDs[i], secondIDs[i] = first[i].GraphEdgeID, second[i].GraphEdgeID
	}
	if strings.Join(firstIDs, ",") != strings.Join(secondIDs, ",") {
		t.Fatalf("edge ids changed across relationship reordering:\nfirst=%v\nsecond=%v", firstIDs, secondIDs)
	}
	expanded := append(append([]ExternalRelationship(nil), relationships...), ExternalRelationship{
		EdgeLabel:           "official_source_for",
		SourceCanonicalName: "quickbooks_online_corpus",
		TargetCanonicalName: submissions[2].StableID,
	})
	_, thirdPlans, _ := externalRelationshipPlanFixture(t, env, expanded)
	third, err := materializeExternalRelationships(context.Background(), env, "org-test", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "organization", objects, thirdPlans)
	if err != nil {
		t.Fatalf("expanded materialization: %v", err)
	}
	expandedIDs := map[string]bool{}
	for _, edge := range third {
		expandedIDs[edge.GraphEdgeID] = true
	}
	for _, stableID := range firstIDs {
		if !expandedIDs[stableID] {
			t.Errorf("adding an unrelated relationship changed existing edge id %q", stableID)
		}
	}
	if len(third) != len(first)+1 {
		t.Fatalf("expanded edge count=%d, want %d", len(third), len(first)+1)
	}
}

func TestExternalRelationshipsFailClosedBeforeSubstrateIO(t *testing.T) {
	submissions, relationships := externalRelationshipCorpus()
	cases := []struct {
		name   string
		mutate func(*Env, *[]ArtifactSubmission, *[]ExternalRelationship)
		want   string
	}{
		{"unknown_external_label", func(_ *Env, _ *[]ArtifactSubmission, rels *[]ExternalRelationship) {
			(*rels)[0].EdgeLabel = "references"
		}, "not an OOD external-ingestion edge label"},
		{"unresolved_target", func(_ *Env, _ *[]ArtifactSubmission, rels *[]ExternalRelationship) {
			(*rels)[0].TargetCanonicalName = "quickbooks_online_missing_page"
		}, "does not resolve inside this materialization batch"},
		{"wrong_direction", func(_ *Env, subs *[]ArtifactSubmission, rels *[]ExternalRelationship) {
			(*rels)[1].SourceCanonicalName = (*subs)[2].StableID
			(*rels)[1].TargetCanonicalName = "quickbooks_online_invoice_page"
		}, "allowed source_kinds"},
		{"duplicate_relationship", func(_ *Env, _ *[]ArtifactSubmission, rels *[]ExternalRelationship) {
			*rels = append(*rels, (*rels)[0])
		}, "duplicates"},
		{"ambiguous_endpoint", func(_ *Env, subs *[]ArtifactSubmission, _ *[]ExternalRelationship) {
			*subs = append(*subs, (*subs)[0])
		}, "ambiguous"},
		{"noncanonical_endpoint", func(_ *Env, _ *[]ArtifactSubmission, rels *[]ExternalRelationship) {
			(*rels)[0].TargetCanonicalName = "quickbooks_online_invoice_page\x00shadow"
		}, "is not a canonical"},
		{"registry_endpoint_drift", func(env *Env, _ *[]ArtifactSubmission, _ *[]ExternalRelationship) {
			descriptors := externalReferenceTestEdgeDescriptors()
			for i := range descriptors {
				if descriptors[i].Name() == "defines_external_symbol" {
					descriptors[i].raw["source_kinds"] = []interface{}{"api_symbol"}
				}
			}
			env.Edges = newEdgeRegistry(descriptors)
		}, "does not match the OOD external edge contract"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, adapter := newSourceCoordinateEnv(t)
			caseSubs := append([]ArtifactSubmission(nil), submissions...)
			caseRelationships := append([]ExternalRelationship(nil), relationships...)
			tc.mutate(env, &caseSubs, &caseRelationships)
			_, err := handleImport(context.Background(), env, importInput{Submissions: caseSubs, Relationships: caseRelationships})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
			if adapter.schemaChecks != 0 || len(adapter.openedRuns) != 0 || len(adapter.batches) != 0 {
				t.Fatalf("invalid relationship reached substrate: schema=%d opened=%d batches=%d", adapter.schemaChecks, len(adapter.openedRuns), len(adapter.batches))
			}
		})
	}
}

func TestRepoSnapshotFailsClosedUntilParentEdgeIsRepresentable(t *testing.T) {
	sourceRepo := NewNodeKindDescriptor(map[string]interface{}{"name": "source_repo"})
	repoSnapshot := NewNodeKindDescriptor(map[string]interface{}{"name": "repo_snapshot"})
	err := validateRequiredExternalTopology(
		[]NodeKindDescriptor{sourceRepo, repoSnapshot},
		[]ExternalSourceDescriptor{{ID: "repo"}, {ID: "repo"}},
		nil,
	)
	if !errors.Is(err, ErrOODGraphExternalTopologyUnrepresentable) || !strings.Contains(err.Error(), "source_repo -> repo_snapshot") {
		t.Fatalf("repo_snapshot topology error=%v, want typed closed-registry refusal", err)
	}
}

func TestExternalRelationshipEmbeddingIsMandatory(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	env.Embed = fixedEmbeddingClient{dimensions: 768}
	_, relationships := externalRelationshipCorpus()
	_, plans, objects := externalRelationshipPlanFixture(t, env, relationships)
	_, err := materializeExternalRelationships(context.Background(), env, "org-test", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "organization", objects, plans)
	if err == nil || !strings.Contains(err.Error(), "embed external relationship") || !strings.Contains(err.Error(), "got 768 dimensions") {
		t.Fatalf("error=%v, want relationship embedding dimension refusal", err)
	}
}

type relationshipCountingEmbeddingClient struct{ calls int }

func (c *relationshipCountingEmbeddingClient) Embed(context.Context, string, string) ([]float32, error) {
	c.calls++
	return make([]float32, externalReferenceEmbeddingDimensions), nil
}

func TestExternalRelationshipEmbeddingDeduplicatesRelationClassSignature(t *testing.T) {
	env, _ := newSourceCoordinateEnv(t)
	counter := &relationshipCountingEmbeddingClient{}
	env.Embed = counter
	_, relationships := externalRelationshipCorpus()
	_, basePlans, baseObjects := externalRelationshipPlanFixture(t, env, relationships)
	var template plannedExternalRelationship
	for _, plan := range basePlans {
		if plan.Relationship.EdgeLabel == "defines_external_symbol" {
			template = plan
			break
		}
	}
	objects := make([]GraphObject, 0, 200)
	plans := make([]plannedExternalRelationship, 0, 100)
	for i := 0; i < 100; i++ {
		source := baseObjects[template.SourceIndex]
		target := baseObjects[template.TargetIndex]
		source.GraphObjectID = uuid.NewSHA1(oodGraphIDNamespace, []byte("dedup-source-"+string(rune(i)))).String()
		target.GraphObjectID = uuid.NewSHA1(oodGraphIDNamespace, []byte("dedup-target-"+string(rune(i)))).String()
		sourceIndex := len(objects)
		objects = append(objects, source, target)
		plan := template
		plan.SourceIndex = sourceIndex
		plan.TargetIndex = sourceIndex + 1
		plan.Relationship.SourceCanonicalName = source.GraphObjectID
		plan.Relationship.TargetCanonicalName = target.GraphObjectID
		plan.AuthoringPath = "$.relationships.sha256_" + strings.Repeat("a", 62) + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[(i/16)%16])
		plans = append(plans, plan)
	}
	edges, err := materializeExternalRelationships(context.Background(), env, "org-test", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "organization", objects, plans)
	if err != nil {
		t.Fatalf("materialize high-cardinality same-signature edges: %v", err)
	}
	if len(edges) != len(plans) || counter.calls != 1 {
		t.Fatalf("edges=%d embed_calls=%d, want %d/1", len(edges), counter.calls, len(plans))
	}
}

func TestExternalRelationshipJSONIsStrict(t *testing.T) {
	cases := []string{
		`{"edge_label":"official_source_for","edge_label":"documents","source_canonical_name":"a","target_canonical_name":"b"}`,
		`{"edge_label":"official_source_for","source_canonical_name":"a","target_canonical_name":"b","source_kind":"external_reference_doc"}`,
	}
	for _, raw := range cases {
		var relationship ExternalRelationship
		if err := json.Unmarshal([]byte(raw), &relationship); err == nil {
			t.Fatalf("strict relationship decoder accepted %s", raw)
		}
	}
	for _, raw := range cases {
		var edge stagingLoadEdge
		if err := json.Unmarshal([]byte(raw), &edge); err == nil {
			t.Fatalf("strict staging-edge decoder accepted %s", raw)
		}
	}
}

func TestStagingExternalRelationshipsFailBeforeClientAcquisition(t *testing.T) {
	submissions, relationships := externalRelationshipCorpus()
	concepts := make([]stagingLoadConcept, 0, len(submissions))
	for _, submission := range submissions {
		concepts = append(concepts, stagingLoadConcept{
			CanonicalName:    submission.StableID,
			NodeKind:         submission.NodeKind,
			Contract:         submission.Contract,
			Payload:          submission.Payload,
			SourceCoordinate: submission.SourceCoordinate,
		})
	}
	validEdges := make([]stagingLoadEdge, 0, len(relationships))
	for _, relationship := range relationships {
		validEdges = append(validEdges, stagingLoadEdge{
			EdgeLabel:           relationship.EdgeLabel,
			SourceCanonicalName: relationship.SourceCanonicalName,
			TargetCanonicalName: relationship.TargetCanonicalName,
		})
	}

	cases := []struct {
		name   string
		mutate func([]stagingLoadEdge) []stagingLoadEdge
		want   string
	}{
		{"unknown_label", func(edges []stagingLoadEdge) []stagingLoadEdge {
			edges[0].EdgeLabel = "external_parent"
			return edges
		}, "unknown edge_label"},
		{"duplicate", func(edges []stagingLoadEdge) []stagingLoadEdge {
			return append(edges, edges[0])
		}, "duplicates"},
		{"noncanonical_endpoint", func(edges []stagingLoadEdge) []stagingLoadEdge {
			edges[0].SourceCanonicalName += "\x00shadow"
			return edges
		}, "endpoints must be canonical"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, adapter := newSourceCoordinateEnv(t)
			edges := append([]stagingLoadEdge(nil), validEdges...)
			edges = tc.mutate(edges)
			_, err := handleStagingLoad(context.Background(), env, stagingLoadInput{
				Concepts: concepts,
				Edges:    edges,
			})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
			if adapter.schemaChecks != 0 || len(adapter.openedRuns) != 0 || len(adapter.batches) != 0 {
				t.Fatal("invalid staged relationship reached substrate")
			}
		})
	}
}
