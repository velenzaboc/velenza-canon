package main

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestGraphOwnedRetrievalMetadataNeverCopiesSourcePayload(t *testing.T) {
	env, adapter := newImportKindEnv(t)
	env.Embed = fixedEmbeddingClient{dimensions: externalReferenceEmbeddingDimensions}
	env.Config.Embedding = &EmbeddingConfig{Model: "gemini-embedding-001", Dimensions: externalReferenceEmbeddingDimensions}
	submission := importSubmission("section", "finance_pipeline_boundary")
	submission.Contract["secret_contract_body"] = "must-not-enter-retrieval"
	submission.Payload["rendered_prose_excerpt"] = "must-not-enter-retrieval"
	if _, err := handleImport(context.Background(), env, importInput{Submissions: []ArtifactSubmission{submission}}); err != nil {
		t.Fatal(err)
	}
	if len(adapter.batches) != 1 || len(adapter.batches[0].Objects) != 1 {
		t.Fatalf("materialized batches=%d objects=%d", len(adapter.batches), len(adapter.batches[0].Objects))
	}
	object := adapter.batches[0].Objects[0]
	for _, forbidden := range []string{"contract", "payload", "secret_contract_body", "rendered_prose_excerpt"} {
		if _, exists := object.SearchPayload[forbidden]; exists {
			t.Fatalf("forbidden retrieval payload key %q materialized: %#v", forbidden, object.SearchPayload)
		}
		if strings.Contains(object.SearchText, "must-not-enter-retrieval") {
			t.Fatalf("source payload leaked into search_text: %q", object.SearchText)
		}
	}
	for _, symbol := range adapter.batches[0].Symbols {
		if !canonicalMapsEqual(symbol.SearchPayload, graphOwnedSymbolSearchPayload(symbol)) {
			t.Fatalf("symbol %q retrieval payload is not graph-owned: %#v", symbol.SymbolID, symbol.SearchPayload)
		}
		if strings.Contains(symbol.SearchText, "must-not-enter-retrieval") {
			t.Fatalf("source value leaked into symbol search_text: %q", symbol.SearchText)
		}
	}
}

func TestNormalizeKnownLegacyRetrievalMetadataRederivesAndReembeds(t *testing.T) {
	kinds := newKindRegistry([]NodeKindDescriptor{NewNodeKindDescriptor(map[string]interface{}{
		"name": "section", "substrate_id": "test", "artifact_type": "section",
		"version_scope": "document_version_scoped", "projection_role": "subdocument_vertex_for_projection_and_closure",
	})})
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID: "11111111-1111-4111-8111-111111111111", SourceArtifactClass: "doc_object",
		SourceRefKind: "name", SourceStableReference: "finance_pipeline_boundary",
		VersionCoordinate: "source:11111111-1111-4111-8111-111111111111:finance_pipeline_boundary@v1", SectionPath: "$",
	}
	address := GraphAddress{ObjectClass: "section", SourceAuthorityID: coord.SourceAuthorityID, SourceRefKind: coord.SourceRefKind, SourceRef: coord.SourceStableReference, VersionCoordinate: coord.VersionCoordinate, SectionPath: coord.SectionPath}.String()
	object := GraphObject{
		GraphSnapshotID: "legacy", GraphObjectID: "object", ObjectClass: "section", GraphAddress: address,
		SourceAuthorityID: coord.SourceAuthorityID, SourceArtifactClass: coord.SourceArtifactClass, SourceRefKind: coord.SourceRefKind,
		SourceStableReference: coord.SourceStableReference, VersionCoordinate: coord.VersionCoordinate, SectionPath: coord.SectionPath,
		SearchText: "copied source prose", SearchPayload: map[string]interface{}{"contract": map[string]interface{}{"claim": "copied"}, "payload": map[string]interface{}{"body": "copied"}},
	}
	symbol := GraphSymbol{
		GraphSnapshotID: "legacy", SymbolID: "symbol", GraphObjectID: object.GraphObjectID, ObjectClass: object.ObjectClass,
		SymbolKind: "scalar", SymbolName: "claim", SourceAuthorityID: coord.SourceAuthorityID,
		SourceStableReference: coord.SourceStableReference, VersionCoordinate: coord.VersionCoordinate,
		SectionPath: "$.payload.claim", GraphAddress: GraphAddress{ObjectClass: "symbol", SourceAuthorityID: coord.SourceAuthorityID, SourceRefKind: coord.SourceRefKind, SourceRef: coord.SourceStableReference, VersionCoordinate: coord.VersionCoordinate, SectionPath: "$.payload.claim"}.String(),
		SearchText: "copied source value",
	}
	edge := GraphEdge{GraphSnapshotID: "legacy", GraphEdgeID: "edge", EdgeLabel: "depends_on", EdgeFamily: "dependency", SourceEndpointClass: "section", TargetEndpointClass: "section", SearchText: "depends_on"}
	authority := MaterializationValidationAuthority{
		Kinds: kinds, Embed: fixedEmbeddingClient{dimensions: externalReferenceEmbeddingDimensions},
		EmbeddingModel: "gemini-embedding-001", EmbeddingDims: externalReferenceEmbeddingDimensions,
	}
	objects, symbols, edges := []GraphObject{object}, []GraphSymbol{symbol}, []GraphEdge{edge}
	if err := normalizeKnownLegacyRetrievalMetadata(context.Background(), objects, symbols, edges, map[string]bool{"legacy": true}, authority); err != nil {
		t.Fatal(err)
	}
	if !canonicalMapsEqual(objects[0].SearchPayload, graphOwnedObjectSearchPayload(object.ObjectClass, object.GraphAddress, coord)) || len(objects[0].Embedding) != externalReferenceEmbeddingDimensions {
		t.Fatalf("object was not normalized/re-embedded: %#v dims=%d", objects[0].SearchPayload, len(objects[0].Embedding))
	}
	if !canonicalMapsEqual(symbols[0].SearchPayload, graphOwnedSymbolSearchPayload(symbols[0])) || len(symbols[0].Embedding) != externalReferenceEmbeddingDimensions {
		t.Fatalf("symbol was not normalized/re-embedded: %#v dims=%d", symbols[0].SearchPayload, len(symbols[0].Embedding))
	}
	if !canonicalMapsEqual(edges[0].SearchPayload, graphOwnedEdgeSearchPayload(edges[0])) || len(edges[0].Embedding) != externalReferenceEmbeddingDimensions {
		t.Fatalf("edge was not normalized/re-embedded: %#v dims=%d", edges[0].SearchPayload, len(edges[0].Embedding))
	}

	objects = []GraphObject{object}
	objects[0].SearchPayload["copied_sibling_summary"] = "forbidden"
	if err := normalizeKnownLegacyRetrievalMetadata(context.Background(), objects, nil, nil, map[string]bool{"legacy": true}, authority); err == nil || !strings.Contains(err.Error(), "neither the exact legacy") {
		t.Fatalf("unrecognized legacy payload was accepted: %v", err)
	}
}

func TestChangedRowEmbeddingFailureBlocksBeforeSeal(t *testing.T) {
	edge := GraphEdge{GraphEdgeID: "edge", SearchText: "depends_on section section"}
	batch := MaterializationBatch{Edges: []GraphEdge{edge}}
	authority := MaterializationValidationAuthority{
		Embed:          fixedEmbeddingClient{dimensions: externalReferenceEmbeddingDimensions, err: errors.New("embedding unavailable")},
		EmbeddingModel: "gemini-embedding-001", EmbeddingDims: externalReferenceEmbeddingDimensions,
	}
	err := ensureChangedRowEmbeddings(context.Background(), &batch, MaterializationBatch{Edges: []GraphEdge{edge}}, authority)
	if err == nil || !strings.Contains(err.Error(), "embedding unavailable") {
		t.Fatalf("changed-row embedding failure did not block: %v", err)
	}
	if len(batch.Edges[0].Embedding) != 0 {
		t.Fatal("failed embedding refresh mutated the edge vector")
	}
}

func TestReembedCompatibilitySurfaceFailsClosedWithoutDatabaseAccess(t *testing.T) {
	_, err := handleReembedAdmitted(context.Background(), &Env{}, reembedAdmittedInput{})
	if !errors.Is(err, ErrOODGraphImmutableReembeddingUnavailable) {
		t.Fatalf("reembed error=%v, want %v", err, ErrOODGraphImmutableReembeddingUnavailable)
	}
}

func TestStagingDedupVerifyFailsClosedWithoutDatabaseOrAuthAccess(t *testing.T) {
	_, err := handleStagingDedupVerify(context.Background(), &Env{}, stagingDedupVerifyInput{})
	if !errors.Is(err, ErrOODGraphSourcePayloadResolutionUnavailable) {
		t.Fatalf("dedup verify error=%v, want %v", err, ErrOODGraphSourcePayloadResolutionUnavailable)
	}
}

func TestStagingExactCoordinateSQLUsesCurrentProfileAndExternalDigestOnly(t *testing.T) {
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID: "11111111-1111-4111-8111-111111111111", SourceRefKind: "name",
		SourceStableReference: "finance_pipeline_boundary", VersionCoordinate: "source:11111111-1111-4111-8111-111111111111:finance_pipeline_boundary@v1",
		SectionPath: "$", SourceContentHash: strings.Repeat("a", 64),
	}
	ordinary, err := stagingExactSourceCoordinateStatement("Objects", "Snapshots", "Runs", "org", "section", coord)
	if err != nil {
		t.Fatal(err)
	}
	profileFence := "JSON_VALUE(s.source_set, '$.materialization_profile_version')='" + MaterializationProfileVersion + "'"
	if !strings.Contains(ordinary.SQL, profileFence) || strings.Contains(ordinary.SQL, "source_content_hash=@content_hash") {
		t.Fatalf("ordinary exact-match SQL has wrong profile/digest posture: %s", ordinary.SQL)
	}
	external, err := stagingExactSourceCoordinateStatement("Objects", "Snapshots", "Runs", "org", "reference_page", coord)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(external.SQL, profileFence) || !strings.Contains(external.SQL, "source_content_hash=@content_hash") || external.Params["content_hash"] != coord.SourceContentHash {
		t.Fatalf("external exact-match SQL lacks profile/digest binding: %s params=%#v", external.SQL, external.Params)
	}
	coord.SourceContentHash = ""
	if _, err := stagingExactSourceCoordinateStatement("Objects", "Snapshots", "Runs", "org", "reference_page", coord); err == nil {
		t.Fatal("external exact-match SQL accepted an absent content digest")
	}
}
