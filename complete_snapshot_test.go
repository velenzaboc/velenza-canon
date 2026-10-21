package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSelectCarryForwardSeedsConsolidatesEveryLegacyPartialBeforeFirstComplete(t *testing.T) {
	seeds := []eligibleSnapshotSeed{
		{SnapshotID: "legacy-1", GraphVersion: 1, Profile: "ood_graph_protocol_v1/materialization/4"},
		{SnapshotID: "legacy-2", GraphVersion: 2, Profile: "ood_graph_protocol_v1/materialization/5"},
		{SnapshotID: "legacy-3", GraphVersion: 3, Profile: ""},
	}
	want := append([]eligibleSnapshotSeed(nil), seeds...)
	got := selectCarryForwardSeeds(seeds)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("first complete snapshot selected %v, want union seed set %v", got, want)
	}
	got[0].SnapshotID = "mutated"
	if seeds[0].SnapshotID != "legacy-1" {
		t.Fatal("selectCarryForwardSeeds returned an alias that can mutate caller state")
	}
}

func TestSelectCarryForwardSeedsStartsAtLatestCompleteAndFoldsLaterLegacyWriters(t *testing.T) {
	seeds := []eligibleSnapshotSeed{
		{SnapshotID: "legacy-1", GraphVersion: 1, Profile: "ood_graph_protocol_v1/materialization/5"},
		{SnapshotID: "complete-2", GraphVersion: 2, Profile: MaterializationProfileVersion},
		{SnapshotID: "legacy-3", GraphVersion: 3, Profile: "ood_graph_protocol_v1/materialization/5"},
		{SnapshotID: "complete-4", GraphVersion: 4, Profile: MaterializationProfileVersion},
		{SnapshotID: "legacy-5", GraphVersion: 5, Profile: "ood_graph_protocol_v1/materialization/5"},
	}
	want := []eligibleSnapshotSeed{seeds[3], seeds[4]}
	got := selectCarryForwardSeeds(seeds)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("carry-forward selection=%v, want latest complete plus later legacy partials=%v", got, want)
	}
}

func TestKnownLegacyProjectionRoleIsRederivedWithoutAcceptingArbitraryDrift(t *testing.T) {
	kind := NewNodeKindDescriptor(map[string]interface{}{
		"name": "section", "substrate_id": "test", "artifact_type": "section", "version_scope": "document_version_scoped",
		"projection_role": "subdocument_vertex_for_projection_and_closure", "projections": []interface{}{"doc_canonical_json"},
	})
	registry := newKindRegistry([]NodeKindDescriptor{kind})
	objects := []GraphObject{{GraphSnapshotID: "legacy-snapshot", GraphObjectID: "legacy", ObjectClass: "section", ProjectionRole: "doc_canonical_json"}}
	legacy := map[string]bool{"legacy-snapshot": true}
	if err := normalizeKnownLegacyProjectionRoles(context.Background(), objects, legacy, registry); err != nil {
		t.Fatal(err)
	}
	if objects[0].ProjectionRole != kind.ProjectionRole() {
		t.Fatalf("normalized role=%q, want %q", objects[0].ProjectionRole, kind.ProjectionRole())
	}
	objects[0].ProjectionRole = "caller_invented_role"
	if err := normalizeKnownLegacyProjectionRoles(context.Background(), objects, legacy, registry); err == nil || !strings.Contains(err.Error(), "neither current") {
		t.Fatalf("arbitrary role drift accepted: %v", err)
	}
	objects[0].ProjectionRole = "doc_canonical_json"
	if err := normalizeKnownLegacyProjectionRoles(context.Background(), objects, map[string]bool{}, registry); err == nil || !strings.Contains(err.Error(), "current-profile") {
		t.Fatalf("current-profile drift was silently normalized: %v", err)
	}
}

func TestCarryForwardIdentityCollisionsDeduplicateOnlyExactCanonicalMaterial(t *testing.T) {
	now := time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

	object := GraphObject{GraphObjectID: "object-1", GraphSnapshotID: "snapshot-a", MaterializationRunID: "run-a", ObjectClass: "section", SourceStableReference: "source", Status: "active", SearchText: "same", SearchPayload: map[string]interface{}{"freshness_window_seconds": int64(3600)}, CreatedAt: now, UpdatedAt: now}
	objectRebound := object
	// Spanner JSON decoding may represent an exact stored integer as a
	// json.Number even when the in-memory delta used int64. Compare canonical
	// JSON material, not incidental Go decoder types.
	objectRebound.SearchPayload = map[string]interface{}{"freshness_window_seconds": json.Number("3600")}
	objectRebound.GraphSnapshotID = "snapshot-b"
	objectRebound.MaterializationRunID = "run-b"
	objectRebound.CreatedAt = now.Add(time.Hour)
	objectRebound.UpdatedAt = now.Add(time.Hour)
	objects, err := mergeGraphObjectsByID([]GraphObject{object}, []GraphObject{objectRebound})
	if err != nil || len(objects) != 1 {
		t.Fatalf("exact object rebinding did not deduplicate: objects=%v err=%v", objects, err)
	}
	objectDivergent := objectRebound
	objectDivergent.SearchText = "different"
	if _, err := mergeGraphObjectsByID([]GraphObject{object}, []GraphObject{objectDivergent}); err == nil || !strings.Contains(err.Error(), "divergent canonical material") {
		t.Fatalf("divergent object collision accepted: %v", err)
	}

	symbol := GraphSymbol{SymbolID: "symbol-1", GraphSnapshotID: "snapshot-a", MaterializationRunID: "run-a", GraphObjectID: "object-1", SymbolKind: "field", SymbolName: "amount", Status: "active", CreatedAt: now, UpdatedAt: now}
	symbolRebound := symbol
	symbolRebound.GraphSnapshotID = "snapshot-b"
	symbolRebound.MaterializationRunID = "run-b"
	symbolRebound.CreatedAt = now.Add(time.Hour)
	symbolRebound.UpdatedAt = now.Add(time.Hour)
	symbols, err := mergeGraphSymbolsByID([]GraphSymbol{symbol}, []GraphSymbol{symbolRebound})
	if err != nil || len(symbols) != 1 {
		t.Fatalf("exact symbol rebinding did not deduplicate: symbols=%v err=%v", symbols, err)
	}
	symbolDivergent := symbolRebound
	symbolDivergent.SymbolName = "balance"
	if _, err := mergeGraphSymbolsByID([]GraphSymbol{symbol}, []GraphSymbol{symbolDivergent}); err == nil || !strings.Contains(err.Error(), "divergent canonical material") {
		t.Fatalf("divergent symbol collision accepted: %v", err)
	}

	edge := GraphEdge{GraphEdgeID: "edge-1", GraphSnapshotID: "snapshot-a", MaterializationRunID: "run-a", EdgeLabel: "depends_on", ReciprocityState: "complete", Status: "active", CreatedAt: now, UpdatedAt: now}
	edgeRebound := edge
	edgeRebound.GraphSnapshotID = "snapshot-b"
	edgeRebound.MaterializationRunID = "run-b"
	edgeRebound.CreatedAt = now.Add(time.Hour)
	edgeRebound.UpdatedAt = now.Add(time.Hour)
	edges, err := mergeGraphEdgesByID([]GraphEdge{edge}, []GraphEdge{edgeRebound})
	if err != nil || len(edges) != 1 {
		t.Fatalf("exact edge rebinding did not deduplicate: edges=%v err=%v", edges, err)
	}
	edgeDivergent := edgeRebound
	edgeDivergent.ReciprocityState = "mirror_committed"
	if _, err := mergeGraphEdgesByID([]GraphEdge{edge}, []GraphEdge{edgeDivergent}); err == nil || !strings.Contains(err.Error(), "divergent canonical material") {
		t.Fatalf("divergent edge collision accepted: %v", err)
	}
}

func TestCarryForwardCollisionGateRunsBeforeLegacyProjectionNormalization(t *testing.T) {
	carried := GraphObject{
		GraphObjectID: "same-id", GraphSnapshotID: "legacy-snapshot", MaterializationRunID: "legacy-run",
		ObjectClass: "section", ProjectionRole: "doc_canonical_json", Status: "active",
	}
	delta := carried
	delta.GraphSnapshotID = "new-snapshot"
	delta.MaterializationRunID = "new-run"
	delta.ProjectionRole = "retrievable_source_vertex_for_context_and_cross_spec_traversal"
	err := requireExactSealedCarryForwardCollisionMaterial([]GraphObject{carried}, nil, nil, MaterializationBatch{Objects: []GraphObject{delta}})
	if err == nil || !strings.Contains(err.Error(), "divergent canonical material") {
		t.Fatalf("pre-normalization projection-role collision error=%v, want exact sealed-material refusal", err)
	}
}

func TestLegacyReciprocityNormalizationIsProfileScoped(t *testing.T) {
	legacy := []GraphEdge{{GraphEdgeID: "legacy-edge", GraphSnapshotID: "legacy", ReciprocityState: "mirror_committed"}}
	if err := normalizeKnownLegacyReciprocityStates(legacy, map[string]bool{"legacy": true}); err != nil || legacy[0].ReciprocityState != "complete" {
		t.Fatalf("known legacy reciprocity state was not normalized: edge=%+v err=%v", legacy[0], err)
	}
	current := []GraphEdge{{GraphEdgeID: "current-edge", GraphSnapshotID: "current", ReciprocityState: "mirror_committed"}}
	if err := normalizeKnownLegacyReciprocityStates(current, map[string]bool{}); err == nil || !strings.Contains(err.Error(), "retired reciprocity_state") {
		t.Fatalf("current-profile mirror_committed accepted: %v", err)
	}
}

func TestExternalStableIdentityRefreshRejectsEveryVersionEvidenceChange(t *testing.T) {
	prior := GraphObject{
		ObjectClass: "reference_page", SourceAuthorityID: bootstrapSourceAuthority,
		SourceArtifactClass: "official_vendor_documentation", SourceRefKind: "coordinate",
		SourceStableReference: "https://static.developer.intuit.com/JSONObjects/EntityJsonObject_v1.json",
		VersionCoordinate:     "source:" + bootstrapSourceAuthority + ":quickbooks_online_api_invoice@v1",
		SectionPath:           SectionPathRoot, SourceContentHash: strings.Repeat("1", 64),
		SourceContentHashOwner: bootstrapSourceAuthority,
	}
	if err := rejectUnrepresentableExternalVersionRefresh([]GraphObject{prior}, []GraphObject{prior}); err != nil {
		t.Fatalf("byte-identical external replay rejected: %v", err)
	}
	carriedConflict := prior
	carriedConflict.VersionCoordinate = "source:" + bootstrapSourceAuthority + ":quickbooks_online_api_invoice@v2"
	if err := rejectUnrepresentableExternalVersionRefresh([]GraphObject{prior, carriedConflict}, nil); !errors.Is(err, ErrOODGraphExternalVersionTransitionUnrepresentable) {
		t.Fatalf("conflicting carried external versions error=%v, want %v", err, ErrOODGraphExternalVersionTransitionUnrepresentable)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*GraphObject)
	}{
		{"version_coordinate", func(o *GraphObject) {
			o.VersionCoordinate = "source:" + bootstrapSourceAuthority + ":quickbooks_online_api_invoice@v2"
		}},
		{"content_digest", func(o *GraphObject) { o.SourceContentHash = strings.Repeat("2", 64) }},
		{"digest_owner", func(o *GraphObject) { o.SourceContentHashOwner = "22222222-2222-4222-8222-222222222222" }},
		{"trust_class", func(o *GraphObject) { o.SourceArtifactClass = "official_release_notes" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := prior
			tc.mutate(&changed)
			if err := rejectUnrepresentableExternalVersionRefresh([]GraphObject{prior}, []GraphObject{changed}); !errors.Is(err, ErrOODGraphExternalVersionTransitionUnrepresentable) {
				t.Fatalf("refresh error=%v, want %v", err, ErrOODGraphExternalVersionTransitionUnrepresentable)
			}
		})
	}
}

func TestValidateCompleteMaterializationRowsRejectsDanglingOrEvidenceForkedEdges(t *testing.T) {
	object := GraphObject{
		OrganizationID:        "org",
		GraphSnapshotID:       "snapshot",
		GraphObjectID:         "object",
		ObjectClass:           "reference_page",
		SourceAuthorityID:     "authority",
		SourceStableReference: "https://example.com/docs",
		VersionCoordinate:     "v1",
		SourceContentHash:     "hash",
		GraphAddress:          "address",
		MaterializationRunID:  "run",
		Status:                "active",
	}
	base := MaterializationBatch{
		Run:      MaterializationRun{OrganizationID: "org", MaterializationRunID: "run"},
		Snapshot: GraphSnapshot{GraphSnapshotID: "snapshot"},
		Objects:  []GraphObject{object},
	}
	tests := []struct {
		name string
		edge GraphEdge
	}{
		{
			name: "dangling_target",
			edge: GraphEdge{OrganizationID: "org", GraphSnapshotID: "snapshot", GraphEdgeID: "edge", SourceEndpointKind: "graph_object", SourceEndpointID: "object", SourceEndpointClass: "reference_page", TargetEndpointKind: "graph_object", TargetEndpointID: "missing", TargetEndpointClass: "reference_page", SourceVersionCoordinate: "v1", TargetVersionCoordinate: "v1", SourceAuthorityID: "authority", SourceStableReference: "https://example.com/docs", SourceContentHash: "hash", MaterializationRunID: "run", Status: "active"},
		},
		{
			name: "source_evidence_fork",
			edge: GraphEdge{OrganizationID: "org", GraphSnapshotID: "snapshot", GraphEdgeID: "edge", SourceEndpointKind: "graph_object", SourceEndpointID: "object", SourceEndpointClass: "reference_page", TargetEndpointKind: "graph_object", TargetEndpointID: "object", TargetEndpointClass: "reference_page", SourceVersionCoordinate: "v1", TargetVersionCoordinate: "v1", SourceAuthorityID: "authority", SourceStableReference: "https://example.com/different", SourceContentHash: "hash", MaterializationRunID: "run", Status: "active"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			batch := base
			batch.Edges = []GraphEdge{tc.edge}
			if err := validateCompleteMaterializationClosure(batch); err == nil {
				t.Fatal("invalid complete-snapshot edge was accepted")
			}
		})
	}
}

func completeValidationFixture(t *testing.T) (MaterializationBatch, MaterializationValidationAuthority) {
	t.Helper()
	env, adapter := newImportKindEnv(t)
	env.Config.Embedding = &EmbeddingConfig{Model: "gemini-embedding-001", Dimensions: externalReferenceEmbeddingDimensions}
	env.Embed = fixedEmbeddingClient{dimensions: externalReferenceEmbeddingDimensions}
	label := NewEdgeLabelDescriptor(map[string]interface{}{
		"name": "references", "edge_family": "reference",
		"source_kinds": []interface{}{"axiom"}, "target_kinds": []interface{}{"section"},
	})
	env.Config.EdgeLabels = []EdgeLabelDescriptor{label}
	env.Edges = newEdgeRegistry(env.Config.EdgeLabels)
	env.Config.Projections = []ProjectionDescriptor{{Name: "doc_canonical_json", OwningSpec: "OOD_GRAPH_PROTOCOL_v1"}}
	env.Projections = newProjectionRegistry(env.Config.Projections)
	if _, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{
		importSubmission("axiom", "fixture_axiom"),
		importSubmission("section", "fixture_section"),
	}}); err != nil {
		t.Fatalf("build complete-validation fixture: %v", err)
	}
	if len(adapter.batches) != 1 {
		t.Fatalf("fixture commits=%d, want 1", len(adapter.batches))
	}
	batch := adapter.batches[0]
	edges, violations := ResolveEdgeEndpointsInBatch(batch.Run.OrganizationID, batch.Run.MaterializationRunID, batch.Snapshot.GraphSnapshotID, batch.Objects, []PendingEdge{{
		SourceEndpointID: batch.Objects[0].GraphObjectID, TargetEndpointID: batch.Objects[1].GraphObjectID,
		Label: label, AuthoringSourcePath: "$.relationships.fixture", SourceAuthorityID: batch.Objects[0].SourceAuthorityID,
		VisibilityScope: batch.Snapshot.VisibilityScope,
	}})
	if len(violations) != 0 || len(edges) != 1 {
		t.Fatalf("fixture edge resolution edges=%d violations=%+v", len(edges), violations)
	}
	edges[0].SourceContentHash = batch.Objects[0].SourceContentHash
	edges[0].SearchText = graphOwnedEdgeSearchText(edges[0])
	edges[0].SearchPayload = graphOwnedEdgeSearchPayload(edges[0])
	edges[0].Embedding = make([]float32, externalReferenceEmbeddingDimensions)
	edges[0].EmbeddingModel = "gemini-embedding-001"
	batch.Edges = edges
	authority := materializationValidationAuthority(env)
	if err := validateCompleteMaterializationRows(context.Background(), batch, authority); err != nil {
		t.Fatalf("valid fixture rejected: %v", err)
	}
	return batch, authority
}

func cloneMaterializationBatch(t *testing.T, in MaterializationBatch) MaterializationBatch {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out MaterializationBatch
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	for i := range out.Objects {
		out.Objects[i].Embedding = append([]float32(nil), in.Objects[i].Embedding...)
	}
	for i := range out.Symbols {
		out.Symbols[i].Embedding = append([]float32(nil), in.Symbols[i].Embedding...)
	}
	for i := range out.Edges {
		out.Edges[i].Embedding = append([]float32(nil), in.Edges[i].Embedding...)
	}
	return out
}

func TestExactExternalReplaySeparatesSemanticObjectFromRenewableOccurrence(t *testing.T) {
	first := testExternalVerificationReceipt(time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC))
	second := *first
	second.RetrievedAt = "2026-08-29T12:00:00Z"
	object := GraphObject{
		ObjectClass: first.ObjectClass, SourceAuthorityID: first.SourceAuthorityID,
		SourceStableReference: first.VerifiedSourceStableReference,
		VersionCoordinate:     first.FinalVersionCoordinate, SourceContentHash: first.SHA256,
		Status: "active",
	}
	merged, err := mergeExternalVerificationReceiptsForCompleteSnapshot([]*stagedExternalVerificationReceipt{first}, []*stagedExternalVerificationReceipt{&second}, []GraphObject{object})
	if err != nil || len(merged) != 1 || merged[0].RetrievedAt != second.RetrievedAt {
		t.Fatalf("renewed occurrence merge=%+v err=%v", merged, err)
	}
	if _, err := mergeExternalVerificationReceiptsForCompleteSnapshot(nil, nil, []GraphObject{object}); !errors.Is(err, ErrOODGraphExternalVerificationReceiptUnavailable) {
		t.Fatalf("missing active-object receipt error=%v", err)
	}

	policy := validExternalSourceConfig().ExternalSources[0]
	coord1 := ArtifactSourceCoordinate{
		SourceAuthorityID: first.SourceAuthorityID, SourceArtifactClass: policy.SourceArtifactClass,
		SourceRefKind: "coordinate", SourceStableReference: first.VerifiedSourceStableReference,
		VersionCoordinate: first.FinalVersionCoordinate, SectionPath: SectionPathRoot,
		SourceContentHash: first.SHA256, SourceContentHashOwner: first.SourceAuthorityID,
		RetrievedAt: first.RetrievedAt, LicenseEvidence: "https://example.test/first-occurrence",
	}
	coord2 := coord1
	coord2.RetrievedAt = second.RetrievedAt
	coord2.LicenseEvidence = "https://example.test/second-occurrence"
	address := GraphAddress{ObjectClass: object.ObjectClass, SourceAuthorityID: coord1.SourceAuthorityID, SourceRefKind: coord1.SourceRefKind, SourceRef: coord1.SourceStableReference, VersionCoordinate: coord1.VersionCoordinate, SectionPath: coord1.SectionPath}.String()
	semantic1 := GraphObject{SearchPayload: externalReferenceSearchPayload(object.ObjectClass, address, coord1, policy), SearchText: externalReferenceSearchText(object.ObjectClass, coord1, policy)}
	semantic2 := GraphObject{SearchPayload: externalReferenceSearchPayload(object.ObjectClass, address, coord2, policy), SearchText: externalReferenceSearchText(object.ObjectClass, coord2, policy)}
	left := canonicalObjectMaterial(semantic1)
	right := canonicalObjectMaterial(semantic2)
	if !reflect.DeepEqual(left, right) {
		t.Fatal("retrieval occurrence changed immutable semantic object material")
	}
}

func TestCompleteMaterializationRevalidatesEveryCarriedRowSurface(t *testing.T) {
	base, authority := completeValidationFixture(t)
	tests := []struct {
		name   string
		mutate func(*MaterializationBatch)
		want   string
	}{
		{"object_class_registry", func(b *MaterializationBatch) {
			objectID := b.Objects[0].GraphObjectID
			b.Objects[0].ObjectClass = "unregistered_class"
			for i := range b.Symbols {
				if b.Symbols[i].GraphObjectID == objectID {
					b.Symbols[i].ObjectClass = "unregistered_class"
				}
			}
			for i := range b.Edges {
				if b.Edges[i].SourceEndpointID == objectID {
					b.Edges[i].SourceEndpointClass = "unregistered_class"
				}
				if b.Edges[i].TargetEndpointID == objectID {
					b.Edges[i].TargetEndpointClass = "unregistered_class"
				}
			}
		}, "closed registry"},
		{"projection_role", func(b *MaterializationBatch) { b.Objects[0].ProjectionRole = "bootstrap_admission_vertex" }, "projection_role"},
		{"graph_address", func(b *MaterializationBatch) { b.Objects[0].GraphAddress += "/" }, "graph_address"},
		{"deterministic_object_id", func(b *MaterializationBatch) {
			prior := b.Objects[0].GraphObjectID
			next := uuid.NewString()
			b.Objects[0].GraphObjectID = next
			for i := range b.Symbols {
				if b.Symbols[i].GraphObjectID == prior {
					b.Symbols[i].GraphObjectID = next
				}
			}
			for i := range b.Edges {
				if b.Edges[i].SourceEndpointID == prior {
					b.Edges[i].SourceEndpointID = next
				}
				if b.Edges[i].TargetEndpointID == prior {
					b.Edges[i].TargetEndpointID = next
				}
			}
		}, "not deterministic"},
		{"retrieval_property_leak", func(b *MaterializationBatch) { b.Objects[0].SearchPayload["upstream_summary"] = "copied" }, "outside the closed"},
		{"embedding_binding", func(b *MaterializationBatch) { b.Objects[0].Embedding = b.Objects[0].Embedding[:32] }, "embedding"},
		{"edge_label_registry", func(b *MaterializationBatch) { b.Edges[0].EdgeLabel = "invented_label" }, "closed registry"},
		{"edge_family", func(b *MaterializationBatch) { b.Edges[0].EdgeFamily = "invented_family" }, "differs from registry"},
		{"endpoint_class", func(b *MaterializationBatch) { b.Edges[0].TargetEndpointClass = "api_symbol" }, "class/version evidence"},
		{"reciprocity_claim", func(b *MaterializationBatch) { b.Edges[0].InverseEdgeID = uuid.NewString() }, "missing or asymmetric"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneMaterializationBatch(t, base)
			tc.mutate(&candidate)
			err := validateCompleteMaterializationRows(context.Background(), candidate, authority)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestCompleteExternalObjectRevalidatesRegistryOwnedVersionMode(t *testing.T) {
	cfg := validExternalSourceConfig()
	desc := cfg.NodeKinds[0]
	policy := cfg.ExternalSources[0]
	digest := strings.Repeat("a", 64)
	canonicalName := "quickbooks_online_invoice_reference"
	coordinate := ArtifactSourceCoordinate{
		SourceAuthorityID: bootstrapSourceAuthority, SourceArtifactClass: policy.SourceArtifactClass,
		SourceRefKind: "coordinate", SourceStableReference: policy.ReferencePrefix + "/invoice#anchor=invoice",
		VersionCoordinate: VersionCoordinate{Kind: VersionSourceNamed, SourceAuthorityID: bootstrapSourceAuthority, StableName: canonicalName, SourceVersionToken: "sha256_" + digest}.String(),
		SectionPath:       SectionPathRoot, SourceContentHash: digest, SourceContentHashOwner: bootstrapSourceAuthority,
	}
	address := GraphAddress{ObjectClass: "reference_page", SourceAuthorityID: coordinate.SourceAuthorityID, SourceRefKind: coordinate.SourceRefKind, SourceRef: coordinate.SourceStableReference, VersionCoordinate: coordinate.VersionCoordinate, SectionPath: coordinate.SectionPath}.String()
	object := GraphObject{
		ObjectClass: "reference_page", SourceAuthorityID: coordinate.SourceAuthorityID,
		SourceArtifactClass: coordinate.SourceArtifactClass, SourceRefKind: coordinate.SourceRefKind,
		SourceStableReference: coordinate.SourceStableReference, VersionCoordinate: coordinate.VersionCoordinate,
		SectionPath: coordinate.SectionPath, GraphAddress: address, SourceContentHash: digest,
		SourceContentHashOwner: coordinate.SourceContentHashOwner, Embedding: make([]float32, externalReferenceEmbeddingDimensions),
		EmbeddingModel: "gemini-embedding-001", SearchPayload: externalReferenceSearchPayload("reference_page", address, coordinate, policy),
		SearchText: externalReferenceSearchText("reference_page", coordinate, policy),
	}
	tokens := object.SearchPayload["graph_owned_parser_classification_tokens"].(map[string]interface{})
	tokens["version_coordinate_mode"] = externalVersionModeUpstreamPinned
	if err := validateCompleteExternalObject(object, desc, cfg.ExternalSources, nil); err == nil || !strings.Contains(err.Error(), "mode does not match registry") {
		t.Fatalf("version-mode receipt drift accepted: %v", err)
	}

	object.SearchPayload = externalReferenceSearchPayload("reference_page", address, coordinate, policy)
	version, err := ParseVersionCoordinate(object.VersionCoordinate)
	if err != nil {
		t.Fatal(err)
	}
	object.VersionCoordinate = VersionCoordinate{Kind: VersionSourceNamed, SourceAuthorityID: object.SourceAuthorityID, StableName: version.StableName, SourceVersionToken: "release_2026_08"}.String()
	object.SearchPayload["version_coordinate"] = object.VersionCoordinate
	coordinate.VersionCoordinate = object.VersionCoordinate
	object.SearchText = externalReferenceSearchText(object.ObjectClass, coordinate, policy)
	if err := validateCompleteExternalObject(object, desc, cfg.ExternalSources, nil); err == nil || !strings.Contains(err.Error(), "content_digest version coordinate") {
		t.Fatalf("non-digest token accepted under content_digest policy: %v", err)
	}
}

func TestCompleteMaterializationValidatesProjectionAndViolationCeremonies(t *testing.T) {
	base, authority := completeValidationFixture(t)
	payload := map[string]interface{}{"object_class": base.Objects[0].ObjectClass, "graph_address": base.Objects[0].GraphAddress}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	base.ProjectionArtifacts = []ProjectionArtifact{{
		OrganizationID: base.Run.OrganizationID, ProjectionArtifactID: uuid.NewString(), GraphSnapshotID: base.Snapshot.GraphSnapshotID,
		ProjectionKind: "doc_canonical_json", ProjectionTargetKind: "graph_object", ProjectionTargetID: base.Objects[0].GraphObjectID,
		ProjectionFormat: "structured_ood_json", ProjectionHash: hex.EncodeToString(digest[:]), ProjectionPayload: payload,
		RoundTripState: "equivalent", MaterializationRunID: base.Run.MaterializationRunID, Status: "active", VisibilityScope: base.Snapshot.VisibilityScope,
	}}
	if err := validateCompleteMaterializationRows(context.Background(), base, authority); err != nil {
		t.Fatalf("valid projection rejected: %v", err)
	}

	badProjection := cloneMaterializationBatch(t, base)
	badProjection.ProjectionArtifacts[0].ProjectionHash = strings.Repeat("0", 64)
	if err := validateCompleteMaterializationRows(context.Background(), badProjection, authority); err == nil || !strings.Contains(err.Error(), "does not attest") {
		t.Fatalf("projection hash error=%v", err)
	}

	violationBatch := cloneMaterializationBatch(t, base)
	object := violationBatch.Objects[0]
	violation := NewViolation(violationBatch.Run.OrganizationID, violationBatch.Run.MaterializationRunID, violationBatch.Snapshot.GraphSnapshotID, ViolationPropertyOrSearchPayloadLeak, ViolationCoordinate{
		SourceAuthorityID: object.SourceAuthorityID, SourceStableReference: object.SourceStableReference,
		VersionCoordinate: object.VersionCoordinate, SectionPath: object.SectionPath, GraphAddress: object.GraphAddress,
		GraphObjectID: object.GraphObjectID, RejectedValueClass: "search_payload", RedactedReason: "unregistered_property_class",
	})
	violationBatch.Violations = []Violation{violation}
	if err := validateCompleteMaterializationRows(context.Background(), violationBatch, authority); err == nil || !strings.Contains(err.Error(), "active blocker") {
		t.Fatalf("active blocker violation error=%v", err)
	}

	malformed := cloneMaterializationBatch(t, violationBatch)
	malformed.Violations[0].Evidence["copied_upstream_payload"] = "forbidden"
	if err := validateCompleteMaterializationRows(context.Background(), malformed, authority); err == nil || !strings.Contains(err.Error(), "outside the closed boundary") {
		t.Fatalf("violation property-leak error=%v", err)
	}

	divergent := cloneMaterializationBatch(t, violationBatch)
	divergent.Violations[0].Evidence["redacted_reason"] = "different_coordinate"
	if err := validateCompleteMaterializationRows(context.Background(), divergent, authority); err == nil || (!strings.Contains(err.Error(), "not deterministic") && !strings.Contains(err.Error(), "does not exactly match")) {
		t.Fatalf("violation coordinate divergence error=%v", err)
	}
}
