package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/velenzaboc/velenza-canon/internal/vertexai"
)

// OOD_GRAPH_PROTOCOL_v1 §6/§8 deliberately makes the retrieval
// columns a graph-owned projection. Source contract/payload bodies and symbol
// values are not retrieval metadata and must never be copied into these
// columns (or into embeddings derived from them).
func graphOwnedObjectSearchPayload(kind, graphAddress string, coord ArtifactSourceCoordinate) map[string]interface{} {
	return map[string]interface{}{
		"object_class":            kind,
		"graph_address":           graphAddress,
		"section_path":            coord.SectionPath,
		"version_coordinate":      coord.VersionCoordinate,
		"source_authority_id":     coord.SourceAuthorityID,
		"source_stable_reference": coord.SourceStableReference,
	}
}

func graphOwnedObjectSearchText(kind, graphAddress string, coord ArtifactSourceCoordinate) string {
	return strings.Join([]string{
		kind,
		graphAddress,
		coord.SectionPath,
		coord.VersionCoordinate,
		coord.SourceAuthorityID,
		coord.SourceStableReference,
	}, " ")
}

func graphOwnedSymbolSearchPayload(symbol GraphSymbol) map[string]interface{} {
	return map[string]interface{}{
		"object_class":            symbol.ObjectClass,
		"graph_address":           symbol.GraphAddress,
		"section_path":            symbol.SectionPath,
		"version_coordinate":      symbol.VersionCoordinate,
		"symbol_kind":             symbol.SymbolKind,
		"symbol_name":             symbol.SymbolName,
		"source_authority_id":     symbol.SourceAuthorityID,
		"source_stable_reference": symbol.SourceStableReference,
	}
}

func graphOwnedSymbolSearchText(symbol GraphSymbol) string {
	return strings.Join([]string{
		symbol.ObjectClass,
		symbol.SymbolKind,
		symbol.SymbolName,
		symbol.GraphAddress,
		symbol.SectionPath,
		symbol.VersionCoordinate,
		symbol.SourceAuthorityID,
		symbol.SourceStableReference,
	}, " ")
}

func graphOwnedEdgeSearchPayload(edge GraphEdge) map[string]interface{} {
	return map[string]interface{}{
		"edge_label":            edge.EdgeLabel,
		"edge_family":           edge.EdgeFamily,
		"source_endpoint_class": edge.SourceEndpointClass,
		"target_endpoint_class": edge.TargetEndpointClass,
	}
}

func graphOwnedEdgeSearchText(edge GraphEdge) string {
	return fmt.Sprintf("%s %s %s", edge.EdgeLabel, edge.SourceEndpointClass, edge.TargetEndpointClass)
}

func canonicalMapsEqual(a, b map[string]interface{}) bool {
	left, leftErr := canonicalJSON(a)
	right, rightErr := canonicalJSON(b)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func isKnownLegacyObjectSearchPayload(payload map[string]interface{}) bool {
	// The pre-current-profile writer emitted exactly {contract?, payload?}. Values
	// were JSON objects because ArtifactSubmission closes both fields to that
	// shape. Anything else is not recognized legacy state and must fail closed.
	for key, value := range payload {
		if key != "contract" && key != "payload" {
			return false
		}
		if value != nil {
			if _, ok := value.(map[string]interface{}); !ok {
				return false
			}
		}
	}
	return true
}

// normalizeKnownLegacyRetrievalMetadata migrates only the exact retrieval
// shapes emitted by pre-current-profile spec-graph writers. It re-derives metadata
// from already-validated row coordinates in the immutable successor and
// clears vectors whose old input contained source payload. Current-profile
// rows are never repaired here: any drift in them must be rejected by the
// complete-row seal validator.
func normalizeKnownLegacyRetrievalMetadata(ctx context.Context, objects []GraphObject, symbols []GraphSymbol, edges []GraphEdge, legacySnapshotIDs map[string]bool, authority MaterializationValidationAuthority) error {
	if authority.Kinds == nil {
		return fmt.Errorf("legacy retrieval normalization requires node-kind authority")
	}
	embeddingCache := make(map[string][]float32)
	embed := func(searchText string) ([]float32, error) {
		if authority.Embed == nil || !isSupportedSpecEmbeddingModel(authority.EmbeddingModel) || authority.EmbeddingDims != externalReferenceEmbeddingDimensions {
			return nil, fmt.Errorf("legacy retrieval normalization requires gemini-embedding-001 at %d dimensions", externalReferenceEmbeddingDimensions)
		}
		if cached, ok := embeddingCache[searchText]; ok {
			return append([]float32(nil), cached...), nil
		}
		vector, err := authority.Embed.Embed(ctx, searchText, vertexai.TaskTypeRetrievalDocument)
		if err != nil {
			return nil, err
		}
		if len(vector) != externalReferenceEmbeddingDimensions {
			return nil, fmt.Errorf("embedding returned %d dimensions, want %d", len(vector), externalReferenceEmbeddingDimensions)
		}
		embeddingCache[searchText] = append([]float32(nil), vector...)
		return vector, nil
	}
	objectByID := make(map[string]GraphObject, len(objects))
	for i := range objects {
		object := &objects[i]
		objectByID[object.GraphObjectID] = *object
		if !legacySnapshotIDs[object.GraphSnapshotID] {
			continue
		}
		desc, err := authority.Kinds.Resolve(ctx, object.ObjectClass)
		if err != nil {
			return fmt.Errorf("carried object %q retrieval class registry: %w", object.GraphObjectID, err)
		}
		if desc.ExternalReferenceRequired() {
			// There was no protocol-sanctioned legacy external writer. External
			// receipts are authority evidence and may never be synthesized.
			continue
		}
		coord := ArtifactSourceCoordinate{
			SourceAuthorityID: object.SourceAuthorityID, SourceArtifactClass: object.SourceArtifactClass,
			SourceRefKind: object.SourceRefKind, SourceStableReference: object.SourceStableReference,
			VersionCoordinate: object.VersionCoordinate, SectionPath: object.SectionPath,
			SourceContentHash: object.SourceContentHash, SourceContentHashOwner: object.SourceContentHashOwner,
		}
		expectedPayload := graphOwnedObjectSearchPayload(object.ObjectClass, object.GraphAddress, coord)
		if !isKnownLegacyObjectSearchPayload(object.SearchPayload) && !canonicalMapsEqual(object.SearchPayload, expectedPayload) {
			return fmt.Errorf("carried object %q search_payload is neither the exact legacy {contract,payload} shape nor current graph-owned metadata", object.GraphObjectID)
		}
		object.SearchPayload = expectedPayload
		object.SearchText = graphOwnedObjectSearchText(object.ObjectClass, object.GraphAddress, coord)
		object.Embedding, err = embed(object.SearchText)
		if err != nil {
			return fmt.Errorf("re-embed carried object %q: %w", object.GraphObjectID, err)
		}
		object.EmbeddingModel = authority.EmbeddingModel
		objectByID[object.GraphObjectID] = *object
	}

	for i := range symbols {
		symbol := &symbols[i]
		if !legacySnapshotIDs[symbol.GraphSnapshotID] {
			continue
		}
		owner, ok := objectByID[symbol.GraphObjectID]
		if !ok {
			return fmt.Errorf("carried symbol %q has no owner while normalizing retrieval metadata", symbol.SymbolID)
		}
		desc, err := authority.Kinds.Resolve(ctx, owner.ObjectClass)
		if err != nil {
			return fmt.Errorf("carried symbol %q retrieval class registry: %w", symbol.SymbolID, err)
		}
		if desc.ExternalReferenceRequired() {
			continue
		}
		expectedPayload := graphOwnedSymbolSearchPayload(*symbol)
		if len(symbol.SearchPayload) != 0 && !canonicalMapsEqual(symbol.SearchPayload, expectedPayload) {
			return fmt.Errorf("carried symbol %q search_payload is not recognized legacy-empty or current graph-owned metadata", symbol.SymbolID)
		}
		symbol.SearchPayload = expectedPayload
		symbol.SearchText = graphOwnedSymbolSearchText(*symbol)
		symbol.Embedding, err = embed(symbol.SearchText)
		if err != nil {
			return fmt.Errorf("re-embed carried symbol %q: %w", symbol.SymbolID, err)
		}
		symbol.EmbeddingModel = authority.EmbeddingModel
	}

	for i := range edges {
		edge := &edges[i]
		if !legacySnapshotIDs[edge.GraphSnapshotID] {
			continue
		}
		expectedPayload := graphOwnedEdgeSearchPayload(*edge)
		if len(edge.SearchPayload) != 0 && !canonicalMapsEqual(edge.SearchPayload, expectedPayload) {
			return fmt.Errorf("carried edge %q search_payload is not recognized legacy-empty or current graph-owned metadata", edge.GraphEdgeID)
		}
		if edge.SearchText != "" && edge.SearchText != edge.EdgeLabel && edge.SearchText != graphOwnedEdgeSearchText(*edge) {
			return fmt.Errorf("carried edge %q search_text is outside recognized graph-owned metadata", edge.GraphEdgeID)
		}
		edge.SearchPayload = expectedPayload
		edge.SearchText = graphOwnedEdgeSearchText(*edge)
		var err error
		edge.Embedding, err = embed(edge.SearchText)
		if err != nil {
			return fmt.Errorf("re-embed carried edge %q: %w", edge.GraphEdgeID, err)
		}
		edge.EmbeddingModel = authority.EmbeddingModel
	}
	return nil
}

// ensureChangedRowEmbeddings completes the §8 refresh stage for the delta.
// Objects/symbols are normally embedded while parsing; graph-native link
// edges are constructed without a remote call and are completed here, before
// the snapshot can seal. A present vector is reusable only when it has the
// configured model/dimensional binding produced by the current parser path.
func ensureChangedRowEmbeddings(ctx context.Context, complete *MaterializationBatch, delta MaterializationBatch, authority MaterializationValidationAuthority) error {
	changedObjects := make(map[string]bool, len(delta.Objects))
	changedSymbols := make(map[string]bool, len(delta.Symbols))
	changedEdges := make(map[string]bool, len(delta.Edges))
	for _, row := range delta.Objects {
		changedObjects[row.GraphObjectID] = true
	}
	for _, row := range delta.Symbols {
		changedSymbols[row.SymbolID] = true
	}
	for _, row := range delta.Edges {
		changedEdges[row.GraphEdgeID] = true
	}
	cache := make(map[string][]float32)
	embed := func(searchText string) ([]float32, error) {
		if authority.Embed == nil || !isSupportedSpecEmbeddingModel(authority.EmbeddingModel) || authority.EmbeddingDims != externalReferenceEmbeddingDimensions {
			return nil, fmt.Errorf("changed-row embedding refresh requires gemini-embedding-001 at %d dimensions", externalReferenceEmbeddingDimensions)
		}
		if cached, ok := cache[searchText]; ok {
			return append([]float32(nil), cached...), nil
		}
		vector, err := authority.Embed.Embed(ctx, searchText, vertexai.TaskTypeRetrievalDocument)
		if err != nil {
			return nil, err
		}
		if len(vector) != externalReferenceEmbeddingDimensions {
			return nil, fmt.Errorf("embedding returned %d dimensions, want %d", len(vector), externalReferenceEmbeddingDimensions)
		}
		cache[searchText] = append([]float32(nil), vector...)
		return vector, nil
	}
	refresh := func(kind, id, searchText string, vector *[]float32, model *string) error {
		// Delta rows are added-or-changed by definition. Vector shape/model
		// cannot attest which input text produced opaque floats, so §8 permits
		// reuse only for unchanged carried rows and requires a fresh call here.
		fresh, err := embed(searchText)
		if err != nil {
			return fmt.Errorf("refresh changed %s %q embedding: %w", kind, id, err)
		}
		*vector = fresh
		*model = authority.EmbeddingModel
		return nil
	}
	for i := range complete.Objects {
		if changedObjects[complete.Objects[i].GraphObjectID] {
			if err := refresh("object", complete.Objects[i].GraphObjectID, complete.Objects[i].SearchText, &complete.Objects[i].Embedding, &complete.Objects[i].EmbeddingModel); err != nil {
				return err
			}
		}
	}
	for i := range complete.Symbols {
		if changedSymbols[complete.Symbols[i].SymbolID] {
			if err := refresh("symbol", complete.Symbols[i].SymbolID, complete.Symbols[i].SearchText, &complete.Symbols[i].Embedding, &complete.Symbols[i].EmbeddingModel); err != nil {
				return err
			}
		}
	}
	for i := range complete.Edges {
		if changedEdges[complete.Edges[i].GraphEdgeID] {
			if err := refresh("edge", complete.Edges[i].GraphEdgeID, complete.Edges[i].SearchText, &complete.Edges[i].Embedding, &complete.Edges[i].EmbeddingModel); err != nil {
				return err
			}
		}
	}
	return nil
}
