package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/google/uuid"
)

const maxCompleteExternalBootstrapVectorRows = 256
const maxCompleteExternalBootstrapMetadataBytes = 2 << 20
const maxCompleteExternalBootstrapEstimatedPhysicalMutationBytes = 64 << 20
const externalBootstrapMetadataAmplification = 16
const externalBootstrapVectorAmplification = 2

// validateCompleteExternalBootstrapPublicationEnvelope applies to the final
// complete successor, not merely its incoming delta. Complete publication
// clones carried rows today, so repeated tiny deltas can otherwise grow past
// Spanner's transaction limit even though every delta passed its own cap.
// The byte estimate includes both source-set copies and all non-vector row
// material; actual float payload bytes are added explicitly because graph-row
// JSON deliberately omits embeddings.
func validateCompleteExternalBootstrapPublicationEnvelope(batch MaterializationBatch) error {
	hasExternal := false
	for _, object := range batch.Objects {
		if _, external := externalReferenceObjectClasses[object.ObjectClass]; external {
			hasExternal = true
			break
		}
	}
	if !hasExternal {
		return nil
	}
	vectorRows := len(batch.Objects) + len(batch.Symbols) + len(batch.Edges)
	if vectorRows > maxCompleteExternalBootstrapVectorRows {
		return fmt.Errorf("%w: complete successor object+symbol+edge rows=%d exceeds external-bootstrap ceiling=%d; immutable normalized rows plus compact membership/head publication are required", ErrOODGraphMaterializationScaleUnrepresentable, vectorRows, maxCompleteExternalBootstrapVectorRows)
	}
	encoded, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("estimate complete external bootstrap publication: %w", err)
	}
	metadataBytes := int64(len(encoded))
	if metadataBytes > maxCompleteExternalBootstrapMetadataBytes {
		return fmt.Errorf("%w: complete successor non-vector row/source-set material=%d bytes exceeds conservative bootstrap ceiling=%d", ErrOODGraphMaterializationScaleUnrepresentable, metadataBytes, maxCompleteExternalBootstrapMetadataBytes)
	}
	vectorBytes := int64(0)
	for _, object := range batch.Objects {
		vectorBytes += int64(len(object.Embedding)) * 4
	}
	for _, symbol := range batch.Symbols {
		vectorBytes += int64(len(symbol.Embedding)) * 4
	}
	for _, edge := range batch.Edges {
		vectorBytes += int64(len(edge.Embedding)) * 4
	}
	// Spanner's commit size includes indexes, generated columns and change
	// streams, none of which appear in the Go batch JSON. Apply deliberately
	// pessimistic bootstrap multipliers to indexed/tokenized metadata and to
	// the otherwise unindexed vector payload. This is a refusal envelope, not
	// a claim that application-row bytes equal physical mutation bytes.
	estimatedPhysicalBytes := metadataBytes*externalBootstrapMetadataAmplification + vectorBytes*externalBootstrapVectorAmplification
	if estimatedPhysicalBytes > maxCompleteExternalBootstrapEstimatedPhysicalMutationBytes {
		return fmt.Errorf("%w: complete successor conservative physical mutation estimate=%d bytes exceeds bootstrap ceiling=%d (metadata=%d vector=%d)", ErrOODGraphMaterializationScaleUnrepresentable, estimatedPhysicalBytes, maxCompleteExternalBootstrapEstimatedPhysicalMutationBytes, metadataBytes, vectorBytes)
	}
	return nil
}

var completeRowStatuses = map[string]bool{"active": true}
var completeVisibilityScopes = map[string]bool{"tenant": true, "organization": true, "platform": true}
var completeRunKinds = map[string]bool{"corpus_refresh": true, "source_change_refresh": true, "replay_verification": true, "projection_recheck": true}
var completeViolationSeverities = map[string]bool{"blocker": true, "major": true, "minor": true, "info": true}
var completeRoundTripStates = map[string]bool{"not_checked": true, "equivalent": true, "loss_detected": true, "invalid": true}
var completeViolationCodes = map[string]bool{
	ViolationObjectClassNotInClosedSet:    true,
	ViolationEdgeLabelNotInClosedSet:      true,
	ViolationEndpointReferenceUnresolved:  true,
	ViolationEndpointClassPairForbidden:   true,
	ViolationPropertyOrSearchPayloadLeak:  true,
	ViolationContentHashBindingInvalid:    true,
	ViolationPropertyGraphBoundaryInvalid: true,
	ViolationObjectIdentityConflict:       true,
	ViolationSymbolIdentityConflict:       true,
	ViolationEdgeIdentityConflict:         true,
	ViolationReplayNonDeterministic:       true,
}

// validateCompleteMaterializationRows is the seal gate for both newly parsed
// and carried-forward rows. A legacy row is input, not trusted state: it must
// pass the same current closed-registry, identity, endpoint, retrieval, and
// projection checks as a row produced by this run.
func validateCompleteMaterializationRows(ctx context.Context, batch MaterializationBatch, authority MaterializationValidationAuthority) error {
	if authority.Kinds == nil || authority.Edges == nil {
		return fmt.Errorf("complete materialization requires node-kind and edge-label validation authorities")
	}
	if err := validateCompleteEnvelope(batch); err != nil {
		return err
	}
	if err := validateCompleteMaterializationClosure(batch); err != nil {
		return err
	}

	objects := make(map[string]GraphObject, len(batch.Objects))
	objectAddresses := make(map[string]string, len(batch.Objects))
	objectTuples := make(map[string]string, len(batch.Objects))
	externalReceipts := make(map[string]*stagedExternalVerificationReceipt, len(batch.ExternalVerificationReceipts))
	for i, receipt := range batch.ExternalVerificationReceipts {
		if err := validateStoredExternalVerificationReceiptShape(receipt); err != nil {
			return fmt.Errorf("complete external receipt[%d]: %w", i, err)
		}
		key := externalVerificationReceiptSemanticKey(receipt)
		if _, duplicate := externalReceipts[key]; duplicate {
			return fmt.Errorf("complete external receipts duplicate semantic coordinate %q", receipt.VerifiedSourceStableReference)
		}
		externalReceipts[key] = receipt
	}
	usedExternalReceipts := make(map[string]bool, len(externalReceipts))
	for i, object := range batch.Objects {
		receiptKey := externalVerificationReceiptObjectKey(object)
		receipt := externalReceipts[receiptKey]
		if err := validateCompleteObject(ctx, object, batch, authority, receipt); err != nil {
			return fmt.Errorf("complete object[%d] %q: %w", i, object.GraphObjectID, err)
		}
		if receipt != nil {
			usedExternalReceipts[receiptKey] = true
		}
		if _, duplicate := objects[object.GraphObjectID]; duplicate {
			return fmt.Errorf("complete snapshot duplicate graph_object_id %q", object.GraphObjectID)
		}
		if prior, duplicate := objectAddresses[object.GraphAddress]; duplicate {
			return fmt.Errorf("complete snapshot graph_address %q is shared by objects %q and %q", object.GraphAddress, prior, object.GraphObjectID)
		}
		tuple := framedIdentity(object.ObjectClass, object.SourceAuthorityID, object.SourceRefKind, object.SourceStableReference, object.VersionCoordinate, object.SectionPath)
		if prior, duplicate := objectTuples[tuple]; duplicate {
			return fmt.Errorf("complete snapshot object identity tuple is shared by %q and %q", prior, object.GraphObjectID)
		}
		objects[object.GraphObjectID] = object
		objectAddresses[object.GraphAddress] = object.GraphObjectID
		objectTuples[tuple] = object.GraphObjectID
	}
	if len(usedExternalReceipts) != len(externalReceipts) {
		return fmt.Errorf("complete materialization carries an external verification receipt with no matching active semantic object")
	}

	symbols := make(map[string]GraphSymbol, len(batch.Symbols))
	symbolAddresses := make(map[string]string, len(batch.Symbols))
	symbolTuples := make(map[string]string, len(batch.Symbols))
	for i, symbol := range batch.Symbols {
		owner, ok := objects[symbol.GraphObjectID]
		if !ok {
			return fmt.Errorf("complete symbol[%d] %q: owner %q is absent from snapshot", i, symbol.SymbolID, symbol.GraphObjectID)
		}
		if err := validateCompleteSymbol(symbol, owner, batch, authority); err != nil {
			return fmt.Errorf("complete symbol[%d] %q: %w", i, symbol.SymbolID, err)
		}
		if _, duplicate := symbols[symbol.SymbolID]; duplicate {
			return fmt.Errorf("complete snapshot duplicate symbol_id %q", symbol.SymbolID)
		}
		if prior, duplicate := symbolAddresses[symbol.GraphAddress]; duplicate {
			return fmt.Errorf("complete snapshot symbol graph_address %q is shared by %q and %q", symbol.GraphAddress, prior, symbol.SymbolID)
		}
		tuple := framedIdentity(symbol.ObjectClass, symbol.SourceAuthorityID, symbol.SourceStableReference, symbol.VersionCoordinate, symbol.SectionPath, symbol.SymbolKind, symbol.SymbolName)
		if prior, duplicate := symbolTuples[tuple]; duplicate {
			return fmt.Errorf("complete snapshot symbol identity tuple is shared by %q and %q", prior, symbol.SymbolID)
		}
		symbols[symbol.SymbolID] = symbol
		symbolAddresses[symbol.GraphAddress] = symbol.SymbolID
		symbolTuples[tuple] = symbol.SymbolID
	}

	edges := make(map[string]GraphEdge, len(batch.Edges))
	edgeTuples := make(map[string]string, len(batch.Edges))
	for i, edge := range batch.Edges {
		if err := validateCompleteEdge(ctx, edge, objects, batch, authority); err != nil {
			return fmt.Errorf("complete edge[%d] %q: %w", i, edge.GraphEdgeID, err)
		}
		if _, duplicate := edges[edge.GraphEdgeID]; duplicate {
			return fmt.Errorf("complete snapshot duplicate graph_edge_id %q", edge.GraphEdgeID)
		}
		tuple := framedIdentity(edge.SourceEndpointKind, edge.SourceEndpointID, edge.TargetEndpointKind, edge.TargetEndpointID, edge.EdgeLabel, edge.SourceVersionCoordinate, edge.TargetVersionCoordinate, edge.AuthoringSourcePath, edge.SourceAuthorityID, edge.SourceStableReference)
		if prior, duplicate := edgeTuples[tuple]; duplicate {
			return fmt.Errorf("complete snapshot edge identity tuple is shared by %q and %q", prior, edge.GraphEdgeID)
		}
		edges[edge.GraphEdgeID] = edge
		edgeTuples[tuple] = edge.GraphEdgeID
	}
	for _, edge := range batch.Edges {
		if err := validateCompleteReciprocity(ctx, edge, edges, authority.Edges); err != nil {
			return err
		}
	}
	if err := validateCompleteProjections(ctx, batch, objects, symbols, authority.Projections); err != nil {
		return err
	}
	if err := validateCompleteViolations(batch); err != nil {
		return err
	}
	return nil
}

func validateCompleteEnvelope(batch MaterializationBatch) error {
	if batch.Run.OrganizationID == "" || batch.Snapshot.OrganizationID != batch.Run.OrganizationID {
		return fmt.Errorf("complete materialization organization_id is missing or inconsistent")
	}
	if err := ValidateUUID(batch.Run.MaterializationRunID); err != nil {
		return fmt.Errorf("complete materialization run id: %w", err)
	}
	if err := ValidateUUID(batch.Snapshot.GraphSnapshotID); err != nil {
		return fmt.Errorf("complete graph snapshot id: %w", err)
	}
	if !completeRunKinds[batch.Run.RunKind] || batch.Run.State != "running" || batch.Run.Status != "active" {
		return fmt.Errorf("complete materialization run kind/state/status is outside the seal contract")
	}
	if batch.Snapshot.SnapshotKind != "active_candidate" || batch.Snapshot.SnapshotState != "building" || batch.Snapshot.Status != "active" {
		return fmt.Errorf("complete snapshot kind/state/status is outside the active-candidate build contract")
	}
	if !completeVisibilityScopes[batch.Run.VisibilityScope] || batch.Snapshot.VisibilityScope != batch.Run.VisibilityScope {
		return fmt.Errorf("complete run/snapshot visibility_scope is invalid or inconsistent")
	}
	return nil
}

func validateCompleteObject(ctx context.Context, object GraphObject, batch MaterializationBatch, authority MaterializationValidationAuthority, receipt *stagedExternalVerificationReceipt) error {
	if err := ValidateUUID(object.GraphObjectID); err != nil {
		return err
	}
	desc, err := authority.Kinds.Resolve(ctx, object.ObjectClass)
	if err != nil {
		return fmt.Errorf("object_class is not in the closed registry: %w", err)
	}
	if object.ProjectionRole != desc.ProjectionRole() {
		return fmt.Errorf("projection_role=%q, want registry value %q", object.ProjectionRole, desc.ProjectionRole())
	}
	if err := validateAPIElementRoleObject(object); err != nil {
		return err
	}
	if object.OrganizationID != batch.Run.OrganizationID || object.GraphSnapshotID != batch.Snapshot.GraphSnapshotID || object.MaterializationRunID != batch.Run.MaterializationRunID {
		return fmt.Errorf("organization/snapshot/run binding mismatch")
	}
	if !completeRowStatuses[object.Status] || object.ValidationState != "valid" || !completeVisibilityScopes[object.VisibilityScope] || object.VisibilityScope != batch.Snapshot.VisibilityScope {
		return fmt.Errorf("status/validation_state/visibility_scope is not sealable")
	}
	if err := validateSourceIdentity(object.SourceAuthorityID, object.SourceArtifactClass, object.SourceRefKind, object.SourceStableReference, object.VersionCoordinate, object.SectionPath, object.SourceContentHash, object.SourceContentHashOwner); err != nil {
		return err
	}
	address, err := ParseGraphAddress(object.GraphAddress)
	if err != nil || address.String() != object.GraphAddress {
		return fmt.Errorf("graph_address is not byte-canonical: %w", err)
	}
	if address.ObjectClass != object.ObjectClass || address.SourceAuthorityID != object.SourceAuthorityID || address.SourceRefKind != object.SourceRefKind || address.SourceRef != object.SourceStableReference || address.VersionCoordinate != object.VersionCoordinate || address.SectionPath != object.SectionPath {
		return fmt.Errorf("graph_address does not equal the object identity tuple")
	}
	wantID := uuid.NewSHA1(oodGraphIDNamespace, []byte(fmt.Sprintf("object|%s|%s|%s|%s|%s|%s|%s", object.OrganizationID, object.ObjectClass, object.SourceAuthorityID, object.SourceRefKind, object.SourceStableReference, object.VersionCoordinate, object.SectionPath))).String()
	if object.GraphObjectID != wantID {
		return fmt.Errorf("graph_object_id is not deterministic for its identity tuple (want %q)", wantID)
	}
	if err := validateEmbeddingBinding(object.Embedding, object.EmbeddingModel); err != nil {
		return err
	}
	if object.EmbeddingModel != authority.EmbeddingModel || !isSupportedSpecEmbeddingModel(authority.EmbeddingModel) || authority.EmbeddingDims != externalReferenceEmbeddingDimensions {
		return fmt.Errorf("embedding model/dimensional authority differs from the materialization profile")
	}
	if desc.ExternalReferenceRequired() {
		if err := validateCompleteExternalObject(object, desc, authority.ExternalSources, receipt); err != nil {
			return err
		}
	} else if receipt != nil {
		return fmt.Errorf("ordinary object carries an external verification receipt")
	} else if _, external := externalReferenceObjectClasses[object.ObjectClass]; external {
		return fmt.Errorf("external object class lacks external_reference_required registry policy")
	} else if err := validateCompleteGraphOwnedObjectRetrieval(object); err != nil {
		return err
	}
	return nil
}

func validateSourceIdentity(authorityID, artifactClass, refKind, stableReference, version, sectionPath, contentHash, contentHashOwner string) error {
	if err := ValidateUUID(authorityID); err != nil {
		return fmt.Errorf("source_authority_id: %w", err)
	}
	if !snakeCaseKeyPattern.MatchString(artifactClass) || len(artifactClass) > 64 {
		return fmt.Errorf("source_artifact_class is not canonical lowercase snake_case")
	}
	if _, ok := sourceRefKinds[refKind]; !ok {
		return fmt.Errorf("source_ref_kind %q is not registered", refKind)
	}
	if stableReference == "" || strings.TrimSpace(stableReference) != stableReference || len(stableReference) > 2048 {
		return fmt.Errorf("source_stable_reference is empty, non-canonical, or oversized")
	}
	parsedVersion, err := ParseVersionCoordinate(version)
	if err != nil || parsedVersion.String() != version {
		return fmt.Errorf("version_coordinate is not byte-canonical: %w", err)
	}
	if parsedVersion.Kind == VersionSourceNamed && parsedVersion.SourceAuthorityID != authorityID {
		return fmt.Errorf("version_coordinate authority does not match source_authority_id")
	}
	if err := ValidateSectionPath(sectionPath); err != nil || len(sectionPath) > 2048 {
		return fmt.Errorf("section_path is invalid or oversized: %w", err)
	}
	if (contentHash == "") != (contentHashOwner == "") {
		return fmt.Errorf("source_content_hash and owner must be present together")
	}
	if contentHash != "" {
		if err := validateExternalContentHash("sha256", contentHash); err != nil {
			return fmt.Errorf("source_content_hash: %w", err)
		}
		if err := ValidateUUID(contentHashOwner); err != nil {
			return fmt.Errorf("source_content_hash_owner: %w", err)
		}
	}
	return nil
}

func validateCompleteExternalObject(object GraphObject, desc NodeKindDescriptor, sources []ExternalSourceDescriptor, receipt *stagedExternalVerificationReceipt) error {
	if object.SourceAuthorityID != desc.SourceAuthority() || object.SourceRefKind != "coordinate" || object.SectionPath != SectionPathRoot {
		return fmt.Errorf("external object source authority/ref kind/section path does not match its class registry")
	}
	if object.SourceContentHash == "" || object.SourceContentHashOwner != object.SourceAuthorityID {
		return fmt.Errorf("external object lacks authority-owned SHA-256 evidence")
	}
	if len(object.Embedding) != externalReferenceEmbeddingDimensions || object.EmbeddingModel == "" {
		return fmt.Errorf("external object requires a %d-dimensional bound embedding", externalReferenceEmbeddingDimensions)
	}
	tokens, ok := object.SearchPayload["graph_owned_parser_classification_tokens"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("external object lacks graph-owned source receipt metadata")
	}
	allowedTop := map[string]bool{"object_class": true, "graph_address": true, "section_path": true, "version_coordinate": true, "source_authority_id": true, "source_stable_reference": true, "graph_owned_parser_classification_tokens": true}
	for key := range object.SearchPayload {
		if !allowedTop[key] {
			return fmt.Errorf("external search_payload key %q is outside the closed graph-owned boundary", key)
		}
	}
	for key, want := range map[string]string{"object_class": object.ObjectClass, "graph_address": object.GraphAddress, "section_path": object.SectionPath, "version_coordinate": object.VersionCoordinate, "source_authority_id": object.SourceAuthorityID, "source_stable_reference": object.SourceStableReference} {
		if got, _ := object.SearchPayload[key].(string); got != want {
			return fmt.Errorf("external search_payload.%s=%q, want row coordinate %q", key, got, want)
		}
	}
	allowedTokens := map[string]bool{"source_registry_id": true, "source_trust_class": true, "content_hash_algorithm": true, "version_coordinate_mode": true, "freshness_window_seconds": true, "query_coordinates_allowed": true, "fragment_coordinates_allowed": true}
	for key := range tokens {
		if !allowedTokens[key] {
			return fmt.Errorf("external receipt token %q is not registered", key)
		}
	}
	registryID, _ := tokens["source_registry_id"].(string)
	var policy *ExternalSourceDescriptor
	for i := range sources {
		if sources[i].ID == registryID {
			policy = &sources[i]
			break
		}
	}
	if policy == nil {
		return fmt.Errorf("external source_registry_id %q is not configured", registryID)
	}
	coordinate := ArtifactSourceCoordinate{SourceAuthorityID: object.SourceAuthorityID, SourceArtifactClass: object.SourceArtifactClass, SourceRefKind: object.SourceRefKind, SourceStableReference: object.SourceStableReference, VersionCoordinate: object.VersionCoordinate, SectionPath: object.SectionPath, SourceContentHash: object.SourceContentHash, SourceContentHashOwner: object.SourceContentHashOwner}
	version, err := ParseVersionCoordinate(object.VersionCoordinate)
	if err != nil {
		return fmt.Errorf("external version coordinate: %w", err)
	}
	resolved, err := resolveExternalSourcePolicy(SpecGraphConfig{ExternalSources: sources}, object.ObjectClass, version.StableName, coordinate)
	if err != nil || resolved.ID != policy.ID {
		return fmt.Errorf("external source receipt no longer resolves uniquely: %w", err)
	}
	if trust, _ := tokens["source_trust_class"].(string); trust != object.SourceArtifactClass || policy.SourceArtifactClass != object.SourceArtifactClass {
		return fmt.Errorf("external source trust class does not match row and registry")
	}
	if algorithm, _ := tokens["content_hash_algorithm"].(string); algorithm != policy.ContentHashAlgorithm {
		return fmt.Errorf("external content hash algorithm does not match registry")
	}
	if mode, _ := tokens["version_coordinate_mode"].(string); mode != policy.VersionCoordinateMode {
		return fmt.Errorf("external version-coordinate mode does not match registry")
	}
	switch policy.VersionCoordinateMode {
	case externalVersionModeContentDigest:
		digest, ok := canonicalSHA256VersionTokenDigest(version.SourceVersionToken)
		if !ok || digest != object.SourceContentHash {
			return fmt.Errorf("external content_digest version coordinate does not bind the authority-owned content digest")
		}
	case externalVersionModeUpstreamPinned:
		// The upstream owner defines this token. It remains independent from
		// the process-attested content digest unless it explicitly uses the
		// canonical sha256_<digest> grammar, which generic coordinate
		// validation already checks for contradiction.
	default:
		return fmt.Errorf("external version-coordinate mode %q is outside the closed registry", policy.VersionCoordinateMode)
	}
	if got, ok := numericInt64(tokens["freshness_window_seconds"]); !ok || got != policy.FreshnessWindowSeconds {
		return fmt.Errorf("external freshness window does not match registry")
	}
	if got, ok := tokens["query_coordinates_allowed"].(bool); !ok || got != policy.AllowQuery {
		return fmt.Errorf("external query policy receipt does not match registry")
	}
	if got, ok := tokens["fragment_coordinates_allowed"].(bool); !ok || got != policy.AllowFragment {
		return fmt.Errorf("external fragment policy receipt does not match registry")
	}
	if receipt == nil {
		return fmt.Errorf("external object lacks run-scoped verification receipt evidence")
	}
	if receipt.Authorization.OrganizationID != object.OrganizationID {
		return fmt.Errorf("external run-scoped verification receipt organization does not match graph object organization")
	}
	coordinate.RetrievedAt = receipt.RetrievedAt
	coordinate.LicenseEvidence = receipt.LicenseEvidence
	if err := validateStagedExternalReceiptBinding(*policy, object.ObjectClass, version.StableName, coordinate, receipt); err != nil {
		return fmt.Errorf("external run-scoped verification receipt: %w", err)
	}
	if err := requireArchivedExternalEvidence(receipt); err != nil {
		return fmt.Errorf("external run-scoped archive evidence: %w", err)
	}
	if object.SearchText != externalReferenceSearchText(object.ObjectClass, coordinate, *policy) {
		return fmt.Errorf("external search_text differs from graph-owned coordinate/trust metadata")
	}
	return nil
}

func validateCompleteGraphOwnedObjectRetrieval(object GraphObject) error {
	coord := ArtifactSourceCoordinate{
		SourceAuthorityID: object.SourceAuthorityID, SourceArtifactClass: object.SourceArtifactClass,
		SourceRefKind: object.SourceRefKind, SourceStableReference: object.SourceStableReference,
		VersionCoordinate: object.VersionCoordinate, SectionPath: object.SectionPath,
		SourceContentHash: object.SourceContentHash, SourceContentHashOwner: object.SourceContentHashOwner,
	}
	wantPayload := graphOwnedObjectSearchPayload(object.ObjectClass, object.GraphAddress, coord)
	if !canonicalMapsEqual(object.SearchPayload, wantPayload) {
		return fmt.Errorf("search_payload is outside the closed graph-owned object metadata boundary")
	}
	if object.SearchText != graphOwnedObjectSearchText(object.ObjectClass, object.GraphAddress, coord) {
		return fmt.Errorf("search_text is outside the closed graph-owned object metadata boundary")
	}
	return nil
}

func validateCompleteSymbol(symbol GraphSymbol, owner GraphObject, batch MaterializationBatch, authority MaterializationValidationAuthority) error {
	if err := ValidateUUID(symbol.SymbolID); err != nil {
		return err
	}
	if symbol.OrganizationID != batch.Run.OrganizationID || symbol.GraphSnapshotID != batch.Snapshot.GraphSnapshotID || symbol.MaterializationRunID != batch.Run.MaterializationRunID || symbol.Status != "active" || symbol.ValidationState != "valid" || symbol.VisibilityScope != batch.Snapshot.VisibilityScope {
		return fmt.Errorf("organization/snapshot/run/lifecycle binding mismatch")
	}
	if symbol.ObjectClass != owner.ObjectClass || symbol.SourceAuthorityID != owner.SourceAuthorityID || symbol.SourceStableReference != owner.SourceStableReference || symbol.VersionCoordinate != owner.VersionCoordinate {
		return fmt.Errorf("owner class/source coordinate mismatch")
	}
	if symbol.SymbolKind == "" || symbol.SymbolName == "" || len(symbol.SymbolKind) > 64 || len(symbol.SymbolName) > 1024 {
		return fmt.Errorf("symbol_kind or symbol_name is empty or oversized")
	}
	if err := ValidateSectionPath(symbol.SectionPath); err != nil || len(symbol.SectionPath) > 2048 {
		return fmt.Errorf("section_path is invalid: %w", err)
	}
	address, err := ParseGraphAddress(symbol.GraphAddress)
	if err != nil || address.String() != symbol.GraphAddress {
		return fmt.Errorf("graph_address is not byte-canonical: %w", err)
	}
	if address.ObjectClass != "symbol" || address.SourceAuthorityID != symbol.SourceAuthorityID || address.SourceRef != symbol.SourceStableReference || address.VersionCoordinate != symbol.VersionCoordinate || address.SectionPath != symbol.SectionPath {
		return fmt.Errorf("graph_address does not equal symbol identity coordinates")
	}
	wantID := uuid.NewSHA1(oodGraphIDNamespace, []byte(fmt.Sprintf("symbol|%s|%s|%s|%s|%s|%s|%s|%s:%s", symbol.OrganizationID, symbol.ObjectClass, symbol.SourceAuthorityID, address.SourceRefKind, symbol.SourceStableReference, symbol.VersionCoordinate, symbol.SectionPath, symbol.SymbolKind, symbol.SymbolName))).String()
	if symbol.SymbolID != wantID {
		return fmt.Errorf("symbol_id is not deterministic for its identity tuple (want %q)", wantID)
	}
	if err := validateEmbeddingBinding(symbol.Embedding, symbol.EmbeddingModel); err != nil {
		return err
	}
	if symbol.EmbeddingModel != authority.EmbeddingModel || !isSupportedSpecEmbeddingModel(authority.EmbeddingModel) || authority.EmbeddingDims != externalReferenceEmbeddingDimensions {
		return fmt.Errorf("embedding model/dimensional authority differs from the materialization profile")
	}
	if _, external := externalReferenceObjectClasses[owner.ObjectClass]; external {
		if symbol.SymbolKind != "external_reference" || len(symbol.Embedding) != externalReferenceEmbeddingDimensions || symbol.EmbeddingModel != owner.EmbeddingModel {
			return fmt.Errorf("external symbol is not a coordinate-bound 3072-dimensional projection")
		}
		wantPayload := graphOwnedSymbolSearchPayload(symbol)
		if tokens, ok := owner.SearchPayload["graph_owned_parser_classification_tokens"].(map[string]interface{}); ok {
			wantPayload["graph_owned_parser_classification_tokens"] = tokens
		}
		if !canonicalMapsEqual(symbol.SearchPayload, wantPayload) || symbol.SearchText != owner.SearchText {
			return fmt.Errorf("external symbol search metadata differs from its graph-owned coordinate/receipt projection")
		}
	} else if !canonicalMapsEqual(symbol.SearchPayload, graphOwnedSymbolSearchPayload(symbol)) || symbol.SearchText != graphOwnedSymbolSearchText(symbol) {
		return fmt.Errorf("symbol retrieval metadata is outside the closed graph-owned boundary")
	}
	return nil
}

func validateCompleteEdge(ctx context.Context, edge GraphEdge, objects map[string]GraphObject, batch MaterializationBatch, authority MaterializationValidationAuthority) error {
	if err := ValidateUUID(edge.GraphEdgeID); err != nil {
		return err
	}
	if edge.OrganizationID != batch.Run.OrganizationID || edge.GraphSnapshotID != batch.Snapshot.GraphSnapshotID || edge.MaterializationRunID != batch.Run.MaterializationRunID || edge.Status != "active" || edge.ValidationState != "valid" || edge.VisibilityScope != batch.Snapshot.VisibilityScope {
		return fmt.Errorf("organization/snapshot/run/lifecycle binding mismatch")
	}
	if edge.SourceEndpointKind != "graph_object" || edge.TargetEndpointKind != "graph_object" {
		return fmt.Errorf("production endpoints must both be graph_object")
	}
	source, sourceOK := objects[edge.SourceEndpointID]
	target, targetOK := objects[edge.TargetEndpointID]
	if !sourceOK || !targetOK {
		return fmt.Errorf("endpoint is absent from this snapshot")
	}
	desc, err := authority.Edges.Resolve(ctx, edge.EdgeLabel)
	if err != nil {
		return fmt.Errorf("edge_label is not in the closed registry: %w", err)
	}
	if edge.EdgeFamily != desc.EdgeFamily() || edge.DiagnosticOnly != desc.DiagnosticOnly() {
		return fmt.Errorf("edge family or diagnostic policy differs from registry")
	}
	if err := validateEdgeEndpointClasses(desc, source.GraphObjectID, source.ObjectClass, target.GraphObjectID, target.ObjectClass); err != nil {
		return err
	}
	if err := validateAPIRelationshipEndpoints(desc, source, target); err != nil {
		return err
	}
	if edge.SourceEndpointClass != source.ObjectClass || edge.TargetEndpointClass != target.ObjectClass || edge.SourceVersionCoordinate != source.VersionCoordinate || edge.TargetVersionCoordinate != target.VersionCoordinate {
		return fmt.Errorf("endpoint class/version evidence mismatch")
	}
	if edge.SourceAuthorityID != source.SourceAuthorityID || edge.SourceStableReference != source.SourceStableReference || edge.SourceContentHash != source.SourceContentHash {
		return fmt.Errorf("authoring source evidence differs from source endpoint")
	}
	if edge.AuthoringSourcePath == "" || ValidateSectionPath(edge.AuthoringSourcePath) != nil {
		return fmt.Errorf("authoring_source_path is not a canonical section_path")
	}
	if edge.ValidFrom != nil && edge.ValidUntil != nil && !edge.ValidFrom.Before(*edge.ValidUntil) {
		return fmt.Errorf("valid_from must precede exclusive valid_until")
	}
	if edge.EdgeConfidence != nil && (math.IsNaN(float64(*edge.EdgeConfidence)) || *edge.EdgeConfidence < 0 || *edge.EdgeConfidence > 1) {
		return fmt.Errorf("edge_confidence must be finite within [0,1]")
	}
	wantID := uuid.NewSHA1(oodGraphIDNamespace, []byte(fmt.Sprintf("edge|%s|%s|%s|%s|%s|%s|%s|%s|%s", edge.OrganizationID, edge.SourceEndpointID, edge.TargetEndpointID, edge.EdgeLabel, edge.SourceVersionCoordinate, edge.TargetVersionCoordinate, edge.AuthoringSourcePath, edge.SourceAuthorityID, edge.SourceStableReference))).String()
	if edge.GraphEdgeID != wantID {
		return fmt.Errorf("graph_edge_id is not deterministic for its identity tuple (want %q)", wantID)
	}
	if edge.SearchText != graphOwnedEdgeSearchText(edge) {
		return fmt.Errorf("edge search_text contains data outside registered edge/class metadata")
	}
	if !canonicalMapsEqual(edge.SearchPayload, graphOwnedEdgeSearchPayload(edge)) {
		return fmt.Errorf("edge search_payload must contain exactly registered edge/class metadata")
	}
	if err := validateEmbeddingBinding(edge.Embedding, edge.EmbeddingModel); err != nil {
		return err
	}
	if edge.EmbeddingModel != authority.EmbeddingModel || !isSupportedSpecEmbeddingModel(authority.EmbeddingModel) || authority.EmbeddingDims != externalReferenceEmbeddingDimensions {
		return fmt.Errorf("embedding model/dimensional authority differs from the materialization profile")
	}
	return nil
}

func validateCompleteReciprocity(ctx context.Context, edge GraphEdge, edges map[string]GraphEdge, registry EdgeLabelRegistry) error {
	desc, err := registry.Resolve(ctx, edge.EdgeLabel)
	if err != nil {
		return err
	}
	reciprocal := desc.ReciprocalLabel()
	if reciprocal == "" || edge.DiagnosticOnly {
		if edge.InverseEdgeID != "" || edge.ReciprocityState != "not_required" {
			return fmt.Errorf("complete edge %q declares an inverse although reciprocity is not required", edge.GraphEdgeID)
		}
		return nil
	}
	if edge.ReciprocityState != "complete" || edge.InverseEdgeID == "" {
		return fmt.Errorf("complete edge %q lacks required committed reciprocal", edge.GraphEdgeID)
	}
	inverse, ok := edges[edge.InverseEdgeID]
	if !ok || inverse.InverseEdgeID != edge.GraphEdgeID || inverse.EdgeLabel != reciprocal || inverse.SourceEndpointID != edge.TargetEndpointID || inverse.TargetEndpointID != edge.SourceEndpointID || inverse.SourceVersionCoordinate != edge.TargetVersionCoordinate || inverse.TargetVersionCoordinate != edge.SourceVersionCoordinate || inverse.ReciprocityState != "complete" {
		return fmt.Errorf("complete edge %q reciprocal %q is absent or asymmetric", edge.GraphEdgeID, edge.InverseEdgeID)
	}
	return nil
}

func validateCompleteProjections(ctx context.Context, batch MaterializationBatch, objects map[string]GraphObject, symbols map[string]GraphSymbol, registry ProjectionRegistry) error {
	seen := map[string]bool{}
	for i, projection := range batch.ProjectionArtifacts {
		if err := ValidateUUID(projection.ProjectionArtifactID); err != nil {
			return fmt.Errorf("projection[%d] id: %w", i, err)
		}
		if seen[projection.ProjectionArtifactID] {
			return fmt.Errorf("duplicate projection_artifact_id %q", projection.ProjectionArtifactID)
		}
		seen[projection.ProjectionArtifactID] = true
		if registry == nil {
			return fmt.Errorf("projection[%d] has no projection registry authority", i)
		}
		if _, err := registry.Resolve(ctx, projection.ProjectionKind); err != nil {
			return fmt.Errorf("projection[%d] kind: %w", i, err)
		}
		if projection.OrganizationID != batch.Run.OrganizationID || projection.GraphSnapshotID != batch.Snapshot.GraphSnapshotID || projection.MaterializationRunID != batch.Run.MaterializationRunID || projection.Status != "active" || projection.VisibilityScope != batch.Snapshot.VisibilityScope {
			return fmt.Errorf("projection[%d] organization/snapshot/run/lifecycle binding mismatch", i)
		}
		if projection.ProjectionFormat != "structured_ood_json" || !completeRoundTripStates[projection.RoundTripState] || projection.ProjectionPayload == nil {
			return fmt.Errorf("projection[%d] format, payload, or round-trip state is invalid", i)
		}
		payload, err := canonicalJSON(projection.ProjectionPayload)
		if err != nil {
			return fmt.Errorf("projection[%d] canonical payload: %w", i, err)
		}
		sum := sha256.Sum256(payload)
		if projection.ProjectionHash != hex.EncodeToString(sum[:]) {
			return fmt.Errorf("projection[%d] hash does not attest canonical payload", i)
		}
		switch projection.ProjectionTargetKind {
		case "graph_object":
			if _, ok := objects[projection.ProjectionTargetID]; !ok {
				return fmt.Errorf("projection[%d] graph_object target is absent", i)
			}
		case "symbol":
			if _, ok := symbols[projection.ProjectionTargetID]; !ok {
				return fmt.Errorf("projection[%d] symbol target is absent", i)
			}
		case "graph_snapshot":
			if projection.ProjectionTargetID != batch.Snapshot.GraphSnapshotID {
				return fmt.Errorf("projection[%d] graph_snapshot target differs from batch", i)
			}
		default:
			return fmt.Errorf("projection[%d] target kind %q is not a supported graph-owned target", i, projection.ProjectionTargetKind)
		}
		if projection.RoundTripState != "equivalent" {
			return fmt.Errorf("projection[%d] cannot seal until round_trip_state=equivalent", i)
		}
	}
	return nil
}

func validateCompleteViolations(batch MaterializationBatch) error {
	seen := map[string]bool{}
	for i, violation := range batch.Violations {
		if err := ValidateUUID(violation.ViolationID); err != nil {
			return fmt.Errorf("violation[%d] id: %w", i, err)
		}
		if seen[violation.ViolationID] {
			return fmt.Errorf("duplicate violation_id %q", violation.ViolationID)
		}
		seen[violation.ViolationID] = true
		if violation.OrganizationID != batch.Run.OrganizationID || violation.GraphSnapshotID != batch.Snapshot.GraphSnapshotID || violation.MaterializationRunID != batch.Run.MaterializationRunID || violation.Status != "active" || violation.VisibilityScope != batch.Snapshot.VisibilityScope || !completeViolationSeverities[violation.Severity] {
			return fmt.Errorf("violation[%d] organization/snapshot/run/lifecycle binding is invalid", i)
		}
		if !completeViolationCodes[violation.ViolationCode] {
			return fmt.Errorf("violation[%d] code %q is outside the closed materialization registry", i, violation.ViolationCode)
		}
		for key := range violation.Evidence {
			if !violationEvidenceAllowedFields[key] {
				return fmt.Errorf("violation[%d] evidence key %q is outside the closed boundary", i, key)
			}
		}
		if violation.SourceAuthorityID != "" {
			if err := ValidateUUID(violation.SourceAuthorityID); err != nil {
				return fmt.Errorf("violation[%d] source_authority_id: %w", i, err)
			}
		}
		if violation.VersionCoordinate != "" {
			version, err := ParseVersionCoordinate(violation.VersionCoordinate)
			if err != nil || version.String() != violation.VersionCoordinate {
				return fmt.Errorf("violation[%d] version_coordinate is not canonical: %w", i, err)
			}
		}
		if violation.SectionPath != "" {
			if err := ValidateSectionPath(violation.SectionPath); err != nil {
				return fmt.Errorf("violation[%d] section_path: %w", i, err)
			}
		}
		for name, value := range map[string]string{
			"graph_object_id": violation.GraphObjectID,
			"symbol_id":       violation.SymbolID,
			"graph_edge_id":   violation.GraphEdgeID,
		} {
			if value != "" {
				if err := ValidateUUID(value); err != nil {
					return fmt.Errorf("violation[%d] %s: %w", i, name, err)
				}
			}
		}
		coordinate, err := completeViolationCoordinate(violation)
		if err != nil {
			return fmt.Errorf("violation[%d] evidence coordinate: %w", i, err)
		}
		expected := NewViolation(violation.OrganizationID, violation.MaterializationRunID, violation.GraphSnapshotID, violation.ViolationCode, coordinate)
		if violation.ViolationID != expected.ViolationID {
			return fmt.Errorf("violation[%d] id is not deterministic for its complete coordinate set (want %q)", i, expected.ViolationID)
		}
		if violation.SentinelCandidate != expected.SentinelCandidate {
			return fmt.Errorf("violation[%d] sentinel_candidate=%q, want closed mapping %q", i, violation.SentinelCandidate, expected.SentinelCandidate)
		}
		actualEvidence, err := canonicalJSON(violation.Evidence)
		if err != nil {
			return fmt.Errorf("violation[%d] canonical evidence: %w", i, err)
		}
		expectedEvidence, err := canonicalJSON(expected.Evidence)
		if err != nil || string(actualEvidence) != string(expectedEvidence) {
			return fmt.Errorf("violation[%d] evidence does not exactly match its indexed and normalized coordinates", i)
		}
		if violation.Severity == "blocker" {
			return fmt.Errorf("violation[%d] is an active blocker and prevents snapshot seal", i)
		}
	}
	return nil
}

func completeViolationCoordinate(violation Violation) (ViolationCoordinate, error) {
	evidence, err := replayViolationEvidenceCoordinates(violation.Evidence)
	if err != nil {
		return ViolationCoordinate{}, err
	}
	stringValue := func(name string) string {
		value, _ := evidence[name].(string)
		return value
	}
	identityNames, _ := evidence["identity_tuple_field_names"].([]string)
	return ViolationCoordinate{
		SourceAuthorityID:       violation.SourceAuthorityID,
		SourceStableReference:   violation.SourceStableReference,
		VersionCoordinate:       violation.VersionCoordinate,
		SectionPath:             violation.SectionPath,
		GraphAddress:            stringValue("graph_address"),
		GraphObjectID:           violation.GraphObjectID,
		SymbolID:                violation.SymbolID,
		GraphEdgeID:             violation.GraphEdgeID,
		EdgeLabel:               stringValue("edge_label"),
		SourceEndpointClass:     stringValue("source_endpoint_class"),
		TargetEndpointClass:     stringValue("target_endpoint_class"),
		RejectedValueClass:      stringValue("rejected_value_class"),
		IdentityTupleFieldNames: identityNames,
		RedactedReason:          stringValue("redacted_reason"),
	}, nil
}

func validateEmbeddingBinding(vector []float32, model string) error {
	if len(vector) != externalReferenceEmbeddingDimensions || model == "" {
		return fmt.Errorf("embedding must be %d dimensions and carry embedding_model", externalReferenceEmbeddingDimensions)
	}
	for _, value := range vector {
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return fmt.Errorf("embedding contains a non-finite value")
		}
	}
	return nil
}

func framedIdentity(values ...string) string {
	var b strings.Builder
	for _, value := range values {
		_, _ = fmt.Fprintf(&b, "%d:%s", len(value), value)
	}
	return b.String()
}

func framedIdentityMap(value map[string]interface{}) string {
	canonical, err := canonicalJSON(value)
	if err != nil {
		return "!invalid!" + err.Error()
	}
	return string(canonical)
}

func numericInt64(value interface{}) (int64, bool) {
	switch n := value.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		if n == math.Trunc(n) && n >= math.MinInt64 && n <= math.MaxInt64 {
			return int64(n), true
		}
	}
	return 0, false
}

func sortedMapKeys(value map[string]interface{}) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
