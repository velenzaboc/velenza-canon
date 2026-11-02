package providerplan

// Typed property and violation materialization for the sealed native API
// projection.  This is deliberately a boot-coordinate mapper: native JSONL
// supplies candidate facts, while schema selection, subject identity, and
// successor coordinates arrive from the protected same-read preparation.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

type DocumentationFactoryNativePropertyIdentity struct {
	NativePropertyID, SubjectKind, NativeSubjectID                                                string
	GraphObjectID, GraphEdgeID                                                                    string
	PropertyFamily                                                                                string
	PropertySchemaArtifactID, PropertySchemaVersion, PropertySchemaDigest, PropertyPayloadProfile string
	ExtractorProfileID, ExtractorProfileVersion, ExtractorProfileDigest, EvidenceAuthorityClass   string
	DeletionDomainID                                                                              string
}

// Violation identity is boot-issued because neither a candidate gap nor a
// source package can allocate a graph identity, select severity, or decide
// lifecycle visibility. Evidence is constructed below from graph coordinates
// and retained locator provenance only.
type DocumentationFactoryNativeGapIdentity struct {
	NativeGapID, ViolationID, ViolationCode, Severity, Status, VisibilityScope, NativeSubjectID   string
	GapClass, BlockedSubjectKind, BlockedSubjectID, BlockedClaimKind, BlockedClaimID, Disposition string
	SentinelCandidate                                                                             *string
	GraphObjectID, SymbolID, GraphEdgeID                                                          string
}

type DocumentationFactorySourcePackageOODNativePropertyRowsContext struct {
	OrganizationID, SnapshotID, RunID string
	CreatedAt                         time.Time
	LocatorBindings                   []DocumentationFactorySourcePackageOODLocatorBinding
	Properties                        []DocumentationFactoryNativePropertyIdentity
	Gaps                              []DocumentationFactoryNativeGapIdentity
	PropertySchemas                   oodpublication.APIPropertyPayloadSchemaResolver
}

type DocumentationFactorySourcePackageOODNativePropertyRows struct {
	Properties, Violations []oodpublication.SpannerRow
	LocatorManifestRows    []oodpublication.SpannerRow
	LocatorManifestNodes   []oodpublication.ManifestNodeV8
	Members                []oodpublication.ManifestMemberV8
}

func BuildDocumentationFactorySourcePackageOODNativePropertyRows(ctx context.Context, p DocumentationFactorySourcePackageOODNativeProjection, graph DocumentationFactorySourcePackageOODNativeGraphRows, in DocumentationFactorySourcePackageOODNativePropertyRowsContext) (DocumentationFactorySourcePackageOODNativePropertyRows, error) {
	if ctx == nil || in.OrganizationID == "" || in.SnapshotID == "" || in.RunID == "" || in.PropertySchemas == nil || in.CreatedAt.IsZero() || in.CreatedAt.Location() != time.UTC || in.CreatedAt.Nanosecond()%1000 != 0 {
		return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("native property rows require complete boot-owned coordinates, schema authority, and UTC microsecond time")
	}
	locatorRows := map[string]oodpublication.SpannerRow{}
	for _, b := range in.LocatorBindings {
		if b.NativeLocatorID == "" || b.LocatorRow.Table != "OODGraphGraphFactEvidenceLocators" || b.LocatorRow.Columns["organization_id"] != in.OrganizationID || b.LocatorRow.Columns["graph_fact_locator_hash"] != b.Locator.LocatorHash {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("native property locator binding is incomplete")
		}
		if _, err := oodpublication.BuildImmutableRow(b.LocatorRow.Table, b.LocatorRow.Columns); err != nil {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("native property locator binding: %w", err)
		}
		if _, exists := locatorRows[b.NativeLocatorID]; exists {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("duplicate native property locator binding %q", b.NativeLocatorID)
		}
		locatorRows[b.NativeLocatorID] = b.LocatorRow
	}
	objects, edges, symbols := map[string]oodpublication.SpannerRow{}, map[string]oodpublication.SpannerRow{}, map[string]oodpublication.SpannerRow{}
	for _, r := range graph.Objects {
		if _, err := oodpublication.BuildImmutableRow(r.Table, r.Columns); err != nil {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("property object subject: %w", err)
		}
		objects[r.Columns["graph_object_id"].(string)] = r
	}
	for _, r := range graph.Edges {
		if _, err := oodpublication.BuildImmutableRow(r.Table, r.Columns); err != nil {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("property edge subject: %w", err)
		}
		edges[r.Columns["graph_edge_id"].(string)] = r
	}
	for _, r := range graph.Symbols {
		if _, err := oodpublication.BuildImmutableRow(r.Table, r.Columns); err != nil {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("gap symbol subject: %w", err)
		}
		symbols[r.Columns["symbol_id"].(string)] = r
	}
	propertyIDs, gapIDs := map[string]DocumentationFactoryNativePropertyIdentity{}, map[string]DocumentationFactoryNativeGapIdentity{}
	for _, x := range in.Properties {
		if x.NativePropertyID == "" || x.SubjectKind == "" || x.NativeSubjectID == "" || x.PropertyFamily == "" || x.PropertySchemaArtifactID == "" || x.PropertySchemaVersion == "" || x.PropertySchemaDigest == "" || x.PropertyPayloadProfile == "" || x.ExtractorProfileID == "" || x.ExtractorProfileVersion == "" || x.ExtractorProfileDigest == "" || x.EvidenceAuthorityClass == "" || x.DeletionDomainID == "" {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("native property identity is incomplete")
		}
		if _, exists := propertyIDs[x.NativePropertyID]; exists {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("duplicate native property identity %q", x.NativePropertyID)
		}
		propertyIDs[x.NativePropertyID] = x
	}
	for _, x := range in.Gaps {
		if x.NativeGapID == "" || x.ViolationID == "" || x.ViolationCode == "" || x.Severity == "" || x.Status == "" || x.VisibilityScope == "" || x.NativeSubjectID == "" || x.GapClass == "" || x.BlockedSubjectKind == "" || x.BlockedSubjectID == "" || x.BlockedClaimKind == "" || x.BlockedClaimID == "" || x.Disposition == "" {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("native gap identity is incomplete")
		}
		if _, exists := gapIDs[x.NativeGapID]; exists {
			return DocumentationFactorySourcePackageOODNativePropertyRows{}, fmt.Errorf("duplicate native gap identity %q", x.NativeGapID)
		}
		gapIDs[x.NativeGapID] = x
	}
	out := DocumentationFactorySourcePackageOODNativePropertyRows{}
	seen := map[string]bool{}
	for _, x := range p.Properties {
		id, ok := propertyIDs[x.ID]
		if !ok || seen[x.ID] {
			return out, fmt.Errorf("property %q has no unique boot identity", x.ID)
		}
		seen[x.ID] = true
		if id.SubjectKind != x.SubjectKind || id.NativeSubjectID != x.SubjectID || id.PropertyFamily != x.Family {
			return out, fmt.Errorf("property %q subject identity mismatch", x.ID)
		}
		locatorManifest, err := nativePropertyLocatorManifest(in.OrganizationID, x.LocatorIDs, locatorRows, in.CreatedAt)
		if err != nil {
			return out, fmt.Errorf("property %q: %w", x.ID, err)
		}
		root := locatorManifest.RootHash
		var appendErr error
		out.LocatorManifestRows, appendErr = appendUniqueNativeRows(out.LocatorManifestRows, locatorManifest.ImmutableRows)
		if appendErr != nil {
			return out, fmt.Errorf("property %q locator manifest roster: %w", x.ID, appendErr)
		}
		out.LocatorManifestNodes, appendErr = appendUniqueNativeManifestNodes(out.LocatorManifestNodes, locatorManifest.Nodes)
		if appendErr != nil {
			return out, fmt.Errorf("property %q locator manifest nodes: %w", x.ID, appendErr)
		}
		var subject oodpublication.SpannerRow
		graphObjectID, graphEdgeID := interface{}(nil), interface{}(nil)
		switch x.SubjectKind {
		case "object":
			if id.GraphObjectID == "" || id.GraphEdgeID != "" {
				return out, fmt.Errorf("property %q object identity invalid", x.ID)
			}
			subject = objects[id.GraphObjectID]
			graphObjectID = id.GraphObjectID
		case "edge":
			if id.GraphEdgeID == "" || id.GraphObjectID != "" {
				return out, fmt.Errorf("property %q edge identity invalid", x.ID)
			}
			subject = edges[id.GraphEdgeID]
			graphEdgeID = id.GraphEdgeID
		default:
			return out, fmt.Errorf("property %q subject kind %q is not admitted", x.ID, x.SubjectKind)
		}
		if subject.Table == "" {
			return out, fmt.Errorf("property %q subject is not a constructed graph row", x.ID)
		}
		payload := oodpublication.CanonicalJSON(bytes.Clone(x.CandidateValue))
		schema, err := in.PropertySchemas.ResolveAPIPropertyPayloadSchema(ctx, id.PropertySchemaArtifactID, id.PropertySchemaVersion, id.PropertySchemaDigest, id.PropertyPayloadProfile)
		if err != nil || schema.ArtifactID != id.PropertySchemaArtifactID || schema.Version != id.PropertySchemaVersion || schema.Digest != id.PropertySchemaDigest || schema.Profile != id.PropertyPayloadProfile {
			return out, fmt.Errorf("property %q admitted schema: %w", x.ID, err)
		}
		payloadHash, err := oodpublication.CanonicalAPIPropertyPayloadHash(schema, payload)
		if err != nil {
			return out, fmt.Errorf("property %q closed payload: %w", x.ID, err)
		}
		row := oodpublication.SpannerRow{Table: "OODGraphAPIPropertyFacts", KeyColumns: []string{"organization_id", "api_property_fact_hash"}, Columns: map[string]interface{}{
			"organization_id": in.OrganizationID, "api_property_fact_hash": zeroDigest(), "subject_kind": x.SubjectKind, "graph_object_id": graphObjectID, "graph_edge_id": graphEdgeID, "subject_graph_row_hash": subject.Columns["graph_row_hash"], "property_family": x.Family, "property_schema_artifact_id": id.PropertySchemaArtifactID, "property_schema_version": id.PropertySchemaVersion, "property_schema_digest": id.PropertySchemaDigest, "property_payload_profile": id.PropertyPayloadProfile, "property_payload": payload, "property_payload_hash": payloadHash, "extractor_profile_id": id.ExtractorProfileID, "extractor_profile_version": id.ExtractorProfileVersion, "extractor_profile_digest": id.ExtractorProfileDigest, "evidence_authority_class": id.EvidenceAuthorityClass, "graph_fact_locator_manifest_hash": root, "deletion_domain_id": id.DeletionDomainID, "created_at": in.CreatedAt,
		}}
		d, err := oodpublication.ManifestMemberVerifier{PropertyPayloadSchemas: in.PropertySchemas}.CanonicalMemberDigestFromPhysicalRow(ctx, row)
		if err != nil {
			return out, fmt.Errorf("property %q canonical digest: %w", x.ID, err)
		}
		row.Columns["api_property_fact_hash"] = d
		d2, err := oodpublication.ManifestMemberVerifier{PropertyPayloadSchemas: in.PropertySchemas}.CanonicalMemberDigestFromPhysicalRow(ctx, row)
		if err != nil || d2 != d {
			return out, fmt.Errorf("property %q self hash binding", x.ID)
		}
		out.Properties = append(out.Properties, row)
		out.Members = append(out.Members, oodpublication.ManifestMemberV8{ManifestKind: "api_property", EntryKind: "api_property", MemberID: d, ClaimedHash: d, Row: &row})
	}
	if len(seen) != len(propertyIDs) {
		return out, fmt.Errorf("boot property identity has no sealed property")
	}
	seen = map[string]bool{}
	for _, x := range p.Gaps {
		id, ok := gapIDs[x.ID]
		if !ok || seen[x.ID] {
			return out, fmt.Errorf("gap %q has no unique boot identity", x.ID)
		}
		seen[x.ID] = true
		if x.MaterializationEligible || id.NativeSubjectID != x.BlockedSubjectID || id.GapClass != x.GapClass || id.BlockedSubjectKind != x.BlockedSubjectKind || id.BlockedSubjectID != x.BlockedSubjectID || id.BlockedClaimKind != x.BlockedClaimKind || id.BlockedClaimID != x.BlockedClaimID || id.Disposition != x.Disposition {
			return out, fmt.Errorf("gap %q is not an eligible redacted violation", x.ID)
		}
		if (id.GraphObjectID == "") == (id.GraphEdgeID == "") {
			return out, fmt.Errorf("gap %q requires exactly one constructed graph subject", x.ID)
		}
		if id.GraphObjectID != "" && objects[id.GraphObjectID].Table == "" {
			return out, fmt.Errorf("gap %q object subject is not constructed", x.ID)
		}
		if id.GraphEdgeID != "" && edges[id.GraphEdgeID].Table == "" {
			return out, fmt.Errorf("gap %q edge subject is not constructed", x.ID)
		}
		if id.SymbolID != "" {
			symbol := symbols[id.SymbolID]
			if symbol.Table == "" || id.GraphObjectID == "" || symbol.Columns["graph_object_id"] != id.GraphObjectID {
				return out, fmt.Errorf("gap %q symbol is not owned by its constructed object", x.ID)
			}
		}
		locatorManifest, err := nativePropertyLocatorManifest(in.OrganizationID, x.LocatorIDs, locatorRows, in.CreatedAt)
		if err != nil {
			return out, fmt.Errorf("gap %q: %w", x.ID, err)
		}
		root := locatorManifest.RootHash
		var appendErr error
		out.LocatorManifestRows, appendErr = appendUniqueNativeRows(out.LocatorManifestRows, locatorManifest.ImmutableRows)
		if appendErr != nil {
			return out, fmt.Errorf("gap %q locator manifest roster: %w", x.ID, appendErr)
		}
		out.LocatorManifestNodes, appendErr = appendUniqueNativeManifestNodes(out.LocatorManifestNodes, locatorManifest.Nodes)
		if appendErr != nil {
			return out, fmt.Errorf("gap %q locator manifest nodes: %w", x.ID, appendErr)
		}
		gapDigest, err := nativeGapCommitment(x, root)
		if err != nil {
			return out, fmt.Errorf("gap %q commitment: %w", x.ID, err)
		}
		// References are lexicographically ordered by kind under the OOD v10
		// grammar. The typed root makes the gap's evidence closure traversable;
		// the validation reference preserves the native candidate coordinate.
		evidenceRaw := fmt.Sprintf(`{"digests":{"evidence_digest":"%s"},"identity_tuple_field_names":["blocked_claim_id","blocked_claim_kind","blocked_subject_id","blocked_subject_kind","disposition","gap_class"],"redacted_diagnostics":{"loss_detected":true,"redacted_reason":%q,"rejected_value_class":%q,"violation_code":%q},"references":[{"ref_kind":"graph_fact_locator_manifest_ref","ref_value":"%s"},{"ref_kind":"validation_evidence_ref","ref_value":%q}]}`, gapDigest, x.GapClass+":"+x.Disposition, x.BlockedClaimKind, id.ViolationCode, root, x.ID)
		evidence, err := oodpublication.CanonicalViolationEvidenceBytes(oodpublication.CanonicalJSON(evidenceRaw))
		if err != nil {
			return out, fmt.Errorf("gap %q evidence: %w", x.ID, err)
		}
		var sentinel interface{}
		if id.SentinelCandidate != nil {
			sentinel = *id.SentinelCandidate
		}
		row := oodpublication.SpannerRow{Table: "OODGraphViolations", KeyColumns: []string{"organization_id", "violation_id"}, Columns: map[string]interface{}{
			"organization_id": in.OrganizationID, "violation_id": id.ViolationID, "graph_snapshot_id": in.SnapshotID, "materialization_run_id": in.RunID, "violation_code": id.ViolationCode, "sentinel_candidate": sentinel, "severity": id.Severity, "source_authority_id": nil, "source_stable_reference": nil, "version_coordinate": nil, "section_path": nil, "graph_object_id": nullableTextID(id.GraphObjectID), "symbol_id": nullableTextID(id.SymbolID), "graph_edge_id": nullableTextID(id.GraphEdgeID), "evidence": oodpublication.CanonicalJSON(evidence), "status": id.Status, "visibility_scope": id.VisibilityScope, "created_at": in.CreatedAt, "updated_at": in.CreatedAt,
		}}
		d, err := oodpublication.CanonicalViolationMemberDigest(row)
		if err != nil {
			return out, fmt.Errorf("gap %q violation digest: %w", x.ID, err)
		}
		out.Violations = append(out.Violations, row)
		out.Members = append(out.Members, oodpublication.ManifestMemberV8{ManifestKind: "violation", EntryKind: "violation", MemberID: id.ViolationID, ClaimedHash: d, Row: &row})
	}
	if len(seen) != len(gapIDs) {
		return out, fmt.Errorf("boot gap identity has no sealed gap")
	}
	sort.Slice(out.Members, func(i, j int) bool {
		return out.Members[i].ManifestKind+out.Members[i].MemberID < out.Members[j].ManifestKind+out.Members[j].MemberID
	})
	return out, nil
}

func nativePropertyLocatorManifest(org string, ids []string, rows map[string]oodpublication.SpannerRow, createdAt time.Time) (oodpublication.NativeLocatorManifestOutput, error) {
	if len(ids) == 0 {
		return oodpublication.NativeLocatorManifestOutput{}, fmt.Errorf("claim has no locator")
	}
	seen := map[string]bool{}
	locators := make([]oodpublication.SpannerRow, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			return oodpublication.NativeLocatorManifestOutput{}, fmt.Errorf("duplicate locator")
		}
		seen[id] = true
		x, ok := rows[id]
		if !ok {
			return oodpublication.NativeLocatorManifestOutput{}, fmt.Errorf("unknown locator %q", id)
		}
		locators = append(locators, x)
	}
	return oodpublication.BuildNativeLocatorManifest(oodpublication.NativeLocatorManifestInput{OrganizationID: org, Locators: locators, CreatedAt: createdAt})
}
func nullableTextID(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// Per-claim manifests commonly share locators. A closure is a set of exact
// physical rows/nodes: retain one byte-identical occurrence and reject any
// same-identity substitution before successor construction.
func appendUniqueNativeRows(dst, src []oodpublication.SpannerRow) ([]oodpublication.SpannerRow, error) {
	seen := map[string]oodpublication.SpannerRow{}
	for _, row := range dst {
		immutable, err := oodpublication.BuildImmutableRow(row.Table, row.Columns)
		if err != nil {
			return nil, err
		}
		seen[row.Table+"\x00"+immutable.Key()] = row
	}
	for _, row := range src {
		immutable, err := oodpublication.BuildImmutableRow(row.Table, row.Columns)
		if err != nil {
			return nil, err
		}
		key := row.Table + "\x00" + immutable.Key()
		if prior, ok := seen[key]; ok {
			left, e1 := oodpublication.CanonicalImmutableRowBytes(prior)
			right, e2 := oodpublication.CanonicalImmutableRowBytes(row)
			if e1 != nil || e2 != nil || !bytes.Equal(left, right) {
				return nil, fmt.Errorf("same locator-manifest row identity has unequal bytes")
			}
			continue
		}
		seen[key] = row
		dst = append(dst, row)
	}
	return dst, nil
}
func appendUniqueNativeManifestNodes(dst, src []oodpublication.ManifestNodeV8) ([]oodpublication.ManifestNodeV8, error) {
	seen := map[string]oodpublication.ManifestNodeV8{}
	for _, node := range dst {
		seen[node.Hash] = node
	}
	for _, node := range src {
		if old, ok := seen[node.Hash]; ok {
			if old.Kind != node.Kind || old.NodeKind != node.NodeKind || old.EntryCount != node.EntryCount || old.TransitiveMemberCount != node.TransitiveMemberCount || old.CanonicalByteCount != node.CanonicalByteCount {
				return nil, fmt.Errorf("same locator-manifest node hash has unequal tuple")
			}
			continue
		}
		seen[node.Hash] = node
		dst = append(dst, node)
	}
	return dst, nil
}

// nativeGapCommitment has an explicit domain/version and JSON member names;
// unlike delimiter joins it cannot make distinct tuples share a preimage when
// a source coordinate contains a control character such as NUL.
func nativeGapCommitment(x DocumentationFactoryNativeGraphGap, locatorManifestRoot string) (string, error) {
	v := struct {
		Domain, Version, GapClass, BlockedSubjectKind, BlockedSubjectID, BlockedClaimKind, BlockedClaimID, Disposition, LocatorManifestRoot string
	}{"velenza.native_gap_commitment", "v1", x.GapClass, x.BlockedSubjectKind, x.BlockedSubjectID, x.BlockedClaimKind, x.BlockedClaimID, x.Disposition, locatorManifestRoot}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// Keep encoding/json linked here: CandidateValue is intentionally a JSON
// scalar and this assertion prevents a future broad map conversion.
var _ json.RawMessage
