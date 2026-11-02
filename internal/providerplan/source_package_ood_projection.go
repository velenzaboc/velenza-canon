package providerplan

// The compiler-to-OOD handoff retains the exact two candidate documents that
// were rendered and factory-verified in the private workspace.  It refuses a
// caller reparse/replacement of files from an output directory.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

type sourcePackageOODProjection struct {
	apiGraph, sourceMapping             []byte
	apiGraphSHA256, sourceMappingSHA256 string
}

// SourcePackageOODProjectionBinding is inspection-only metadata for boot
// diagnostics. It contains no mutable bytes and cannot be used to construct a
// replacement candidate handoff.
type SourcePackageOODProjectionBinding struct{ APIGraphSHA256, SourceMappingSHA256 string }

func (r DocumentationFactorySourceCompileResult) OODProjectionBinding() (SourcePackageOODProjectionBinding, error) {
	if r.oodProjection == nil {
		return SourcePackageOODProjectionBinding{}, errors.New("source compile result has no sealed OOD projection")
	}
	return SourcePackageOODProjectionBinding{APIGraphSHA256: r.oodProjection.apiGraphSHA256, SourceMappingSHA256: r.oodProjection.sourceMappingSHA256}, nil
}

func newSourcePackageOODProjection(c sourcePackageCompilation) (*sourcePackageOODProjection, error) {
	var graph, mapping []byte
	for _, x := range c.manifest.GeneratedDocuments {
		material, ok := c.materials[x.coordinate()]
		if !ok {
			return nil, errors.New("sealed generated OOD projection material absent")
		}
		switch x.PackageRole {
		case sourcePackageOutputRoleAPIGraphArtifact:
			graph = bytes.Clone(material.raw)
		case sourcePackageOutputRoleSourceMapping:
			mapping = bytes.Clone(material.raw)
		}
	}
	if len(graph) == 0 || len(mapping) == 0 {
		return nil, errors.New("source package lacks sealed api_graph_artifact or source_mapping")
	}
	return &sourcePackageOODProjection{apiGraph: graph, sourceMapping: mapping, apiGraphSHA256: sha256Hex(graph), sourceMappingSHA256: sha256Hex(mapping)}, nil
}

// BuildDocumentationFactorySourcePackageOODPlan is the concrete reusable
// pre-runtime construction path. Facts arrive only from boot-owned typed
// archive/schema/currentness resolution; the candidate documents themselves
// are retained privately in result and their hashes must be bound by the
// supplied physical facts before plan construction.
type DocumentationFactorySourcePackageOODNativeProjection struct {
	APIGraphSHA256, SourceMappingSHA256 string
	Manifest                            json.RawMessage
	Summary                             json.RawMessage
	Symbols                             []DocumentationFactoryNativeAPISymbol
	Relationships                       []DocumentationFactoryNativeAPIRelationship
	Locators                            []DocumentationFactoryNativeEvidenceLocator
	Properties                          []DocumentationFactoryNativeAPIProperty
	Gaps                                []DocumentationFactoryNativeGraphGap
}
type DocumentationFactoryNativeAPISymbol struct {
	ID, Role, SemanticKey, DisplayName string
	LocatorIDs                         []string
}
type DocumentationFactoryNativeAPIRelationship struct {
	ID, Label, SourceID, TargetID string
	LocatorIDs                    []string
}
type DocumentationFactoryNativeEvidenceLocator struct {
	ID, EvidenceManifestSHA256, SourceContentSHA256, SelectedRangeSHA256 string
	ByteStartOffset, ByteEndOffsetExclusive, SelectedRangeByteCount      int64
	SourceRefs, SourceURLs                                               []string
}
type DocumentationFactoryNativeAPIProperty struct {
	ID, Family, SubjectKind, SubjectID, PropertyName string
	CandidateValue                                   json.RawMessage
	LocatorIDs                                       []string
}
type DocumentationFactoryNativeGraphGap struct {
	ID, GapClass, BlockedSubjectKind, BlockedSubjectID, BlockedClaimKind, BlockedClaimID, Disposition string
	MaterializationEligible                                                                           bool
	LocatorIDs                                                                                        []string
}

// DocumentationFactoryOODSuccessorCertificateIssuer is the narrow,
// boot-selected dependency permitted to allocate successor coordinates and
// attest a certificate whose roots and closure hash were computed locally.
// It never receives or manufactures graph facts.
type DocumentationFactoryOODSuccessorCertificateIssuer interface {
	IssueSuccessorCertificate(context.Context, DocumentationFactoryOODSuccessorCertificateRequest) (DocumentationFactoryOODSuccessorCertificateIssuance, error)
}

// DocumentationFactoryOODSuccessorCoordinateIssuer allocates only typed,
// non-fact coordinates for one sealed compiler projection. It cannot alter a
// native graph claim, receipt, locator, property payload, or closure root.
type DocumentationFactoryOODSuccessorCoordinateIssuer interface {
	IssueSuccessorCoordinates(context.Context, DocumentationFactoryOODSuccessorCoordinateRequest) (DocumentationFactoryOODSuccessorCoordinates, error)
}
type DocumentationFactoryOODSuccessorCoordinateRequest struct {
	OrganizationID, APIGraphSHA256, SourceMappingSHA256                     string
	SymbolIDs, DocumentationSymbolIDs, RelationshipIDs, PropertyIDs, GapIDs []string
}

// DocumentationFactoryNativeDocumentationIdentity is allocated by the
// coordinate issuer for one sealed native symbol. It is deliberately separate
// from source-fact provenance: these are graph coordinates, not source facts.
type DocumentationFactoryNativeDocumentationIdentity struct {
	NativeSymbolID, DocGraphObjectID, DocGraphAddress, DocumentsGraphEdgeID string
}
type DocumentationFactoryOODSuccessorCoordinates struct {
	SnapshotID, RunID, VerificationCertificateID string
	CreatedAt                                    time.Time
	Symbols                                      []DocumentationFactoryNativeSymbolIdentity
	Documentation                                []DocumentationFactoryNativeDocumentationIdentity
	Relationships                                []DocumentationFactoryNativeRelationshipIdentity
	Properties                                   []DocumentationFactoryNativePropertyIdentity
	Gaps                                         []DocumentationFactoryNativeGapIdentity
}
type DocumentationFactoryOODSuccessorCertificateRequest struct {
	Certificate     oodevidence.ClosureCertificateV8
	ImmutableRoster [][]byte
}
type DocumentationFactoryOODSuccessorCertificateIssuance struct {
	SnapshotID, RunID, VerificationCertificateID                                  string
	AttestationAuthorityID, AttestationRef, AttestationDigest, AttestationProfile string
	Attestor                                                                      oodpublication.ClosureAttestor
	// CreatedAt is boot-owned successor issuance time.  The mapper never mints
	// a publication timestamp from its local clock.
	CreatedAt time.Time
}

func (r DocumentationFactoryOODSuccessorCertificateIssuance) validate() error {
	if r.SnapshotID == "" || r.RunID == "" || r.VerificationCertificateID == "" || r.AttestationAuthorityID == "" || r.AttestationRef == "" || r.AttestationDigest == "" || r.AttestationProfile == "" || r.Attestor == nil {
		return errors.New("successor certificate issuance incomplete")
	}
	if r.CreatedAt.IsZero() || r.CreatedAt.Location() != time.UTC || r.CreatedAt.Nanosecond()%1000 != 0 {
		return errors.New("successor certificate issuance requires UTC microsecond creation time")
	}
	return nil
}

func (r DocumentationFactoryOODSuccessorCertificateRequest) validate() error {
	if r.Certificate.OrganizationID == "" || r.Certificate.ClosureHash == "" || len(r.Certificate.Roots) != 9 || len(r.ImmutableRoster) == 0 {
		return errors.New("successor certificate request incomplete")
	}
	for _, b := range r.ImmutableRoster {
		if len(b) == 0 {
			return errors.New("successor certificate request has empty roster row")
		}
	}
	return nil
}

// ProjectDocumentationFactorySourcePackageOODNative decodes exact private
// compiler bytes. It admits neither caller graph bytes nor caller rows.
func ProjectDocumentationFactorySourcePackageOODNative(ctx context.Context, result DocumentationFactorySourceCompileResult) (DocumentationFactorySourcePackageOODNativeProjection, error) {
	if result.oodProjection == nil {
		return DocumentationFactorySourcePackageOODNativeProjection{}, errors.New("OOD projection requires sealed compiler result")
	}
	if ctx == nil || !sealedJSONOrJSONL(result.oodProjection.sourceMapping) {
		return DocumentationFactorySourcePackageOODNativeProjection{}, errors.New("OOD projection requires context and sealed structured mapping")
	}
	return decodeSealedNativeAPIJSONL(result.oodProjection.apiGraph, result.oodProjection.apiGraphSHA256, result.oodProjection.sourceMappingSHA256)
}

// source_mapping has legacy canonical-JSON and native JSONL forms. The
// compiler already validated its role/schema; the handoff only verifies that
// retained bytes remain a closed structured document, without narrowing the
// established carrier format.
func sealedJSONOrJSONL(raw []byte) bool {
	if json.Valid(raw) {
		return true
	}
	s := bufio.NewScanner(bytes.NewReader(raw))
	seen := false
	for s.Scan() {
		line := bytes.TrimSpace(s.Bytes())
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return false
		}
		seen = true
	}
	return seen && s.Err() == nil
}
func decodeSealedNativeAPIJSONL(raw []byte, graphHash, mappingHash string) (DocumentationFactorySourcePackageOODNativeProjection, error) {
	out := DocumentationFactorySourcePackageOODNativeProjection{APIGraphSHA256: graphHash, SourceMappingSHA256: mappingHash}
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 1024), 32*1024*1024)
	ids := map[string]bool{}
	symbols := map[string]bool{}
	locators := map[string]bool{}
	type envelope struct {
		RowKind string `json:"row_kind"`
	}
	line := 0
	for scan.Scan() {
		line++
		b := bytes.TrimSpace(scan.Bytes())
		if len(b) == 0 {
			continue
		}
		if err := rejectDuplicateJSONKeys(b); err != nil {
			return out, fmt.Errorf("sealed API graph line %d: %w", line, err)
		}
		var e envelope
		if err := json.Unmarshal(b, &e); err != nil {
			return out, err
		}
		switch e.RowKind {
		case "artifact_manifest":
			if out.Manifest != nil {
				return out, errors.New("sealed API graph repeats artifact manifest")
			}
			out.Manifest = append(json.RawMessage(nil), b...)
		case "validation_summary":
			if out.Summary != nil {
				return out, errors.New("sealed API graph repeats validation summary")
			}
			out.Summary = append(json.RawMessage(nil), b...)
		case "candidate_evidence_locator":
			var x evidenceLocator
			if err := strictUnmarshal(b, &x); err != nil {
				return out, err
			}
			if x.ID == "" || ids[x.ID] {
				return out, fmt.Errorf("duplicate/empty sealed native id %q", x.ID)
			}
			ids[x.ID] = true
			locators[x.ID] = true
			out.Locators = append(out.Locators, DocumentationFactoryNativeEvidenceLocator{ID: x.ID, EvidenceManifestSHA256: x.EvidenceManifestSHA256, SourceContentSHA256: x.SourceContentSHA256, SelectedRangeSHA256: x.SelectedRangeSHA256, ByteStartOffset: x.ByteStartOffset, ByteEndOffsetExclusive: x.ByteEndOffsetExclusive, SelectedRangeByteCount: x.SelectedRangeByteCount, SourceRefs: append([]string(nil), x.SourceRefs...), SourceURLs: append([]string(nil), x.SourceURLs...)})
		case "candidate_api_symbol":
			var x apiSymbol
			if err := strictUnmarshal(b, &x); err != nil {
				return out, err
			}
			if x.ID == "" || ids[x.ID] {
				return out, fmt.Errorf("duplicate/empty sealed native id %q", x.ID)
			}
			ids[x.ID] = true
			symbols[x.ID] = true
			out.Symbols = append(out.Symbols, DocumentationFactoryNativeAPISymbol{ID: x.ID, Role: x.Role, SemanticKey: x.SemanticKey, DisplayName: x.DisplayName, LocatorIDs: append([]string(nil), x.EvidenceLocatorIDs...)})
		case "candidate_api_relationship":
			var x apiRelationship
			if err := strictUnmarshal(b, &x); err != nil {
				return out, err
			}
			if x.ID == "" || ids[x.ID] {
				return out, fmt.Errorf("duplicate/empty sealed native id %q", x.ID)
			}
			ids[x.ID] = true
			out.Relationships = append(out.Relationships, DocumentationFactoryNativeAPIRelationship{ID: x.ID, Label: x.Label, SourceID: x.SourceID, TargetID: x.TargetID, LocatorIDs: append([]string(nil), x.LocatorIDs...)})
		case "candidate_api_property_claim":
			var x apiPropertyClaim
			if err := strictUnmarshal(b, &x); err != nil {
				return out, err
			}
			if x.ID == "" || ids[x.ID] {
				return out, fmt.Errorf("duplicate/empty sealed native id %q", x.ID)
			}
			ids[x.ID] = true
			out.Properties = append(out.Properties, DocumentationFactoryNativeAPIProperty{ID: x.ID, Family: x.Family, SubjectKind: x.SubjectKind, SubjectID: x.SubjectID, PropertyName: x.PropertyName, CandidateValue: append(json.RawMessage(nil), x.CandidateValue...), LocatorIDs: append([]string(nil), x.LocatorIDs...)})
		case "candidate_graph_gap":
			var x graphGap
			if err := strictUnmarshal(b, &x); err != nil {
				return out, err
			}
			if x.ID == "" || ids[x.ID] {
				return out, fmt.Errorf("duplicate/empty sealed native id %q", x.ID)
			}
			ids[x.ID] = true
			out.Gaps = append(out.Gaps, DocumentationFactoryNativeGraphGap{ID: x.ID, GapClass: x.GapClass, BlockedSubjectKind: x.BlockedSubjectKind, BlockedSubjectID: x.BlockedSubjectID, BlockedClaimKind: x.BlockedClaimKind, BlockedClaimID: x.BlockedClaimID, Disposition: x.Disposition, MaterializationEligible: x.MaterializationEligible, LocatorIDs: append([]string(nil), x.EvidenceLocatorIDs...)})
		default:
			return out, fmt.Errorf("sealed API graph line %d has unsupported row kind %q", line, e.RowKind)
		}
	}
	if err := scan.Err(); err != nil {
		return out, err
	}
	if out.Manifest == nil || out.Summary == nil || len(out.Symbols) == 0 || len(out.Relationships) == 0 || len(out.Locators) == 0 {
		return out, errors.New("sealed native graph lacks symbols, relationships, or locators")
	}
	for _, s := range out.Symbols {
		if !nativeRefsExist(s.LocatorIDs, locators) {
			return out, fmt.Errorf("symbol %s has dangling locator", s.ID)
		}
	}
	for _, r := range out.Relationships {
		if !symbols[r.SourceID] || !symbols[r.TargetID] || !nativeRefsExist(r.LocatorIDs, locators) {
			return out, fmt.Errorf("relationship %s has dangling endpoint/locator", r.ID)
		}
	}
	for _, p := range out.Properties {
		if !symbols[p.SubjectID] || !nativeRefsExist(p.LocatorIDs, locators) {
			return out, fmt.Errorf("property %s has dangling subject/locator", p.ID)
		}
	}
	for _, g := range out.Gaps {
		if !nativeRefsExist(g.LocatorIDs, locators) {
			return out, fmt.Errorf("gap %s has dangling locator", g.ID)
		}
	}
	sort.Slice(out.Symbols, func(i, j int) bool { return out.Symbols[i].ID < out.Symbols[j].ID })
	sort.Slice(out.Relationships, func(i, j int) bool { return out.Relationships[i].ID < out.Relationships[j].ID })
	sort.Slice(out.Locators, func(i, j int) bool { return out.Locators[i].ID < out.Locators[j].ID })
	sort.Slice(out.Properties, func(i, j int) bool { return out.Properties[i].ID < out.Properties[j].ID })
	sort.Slice(out.Gaps, func(i, j int) bool { return out.Gaps[i].ID < out.Gaps[j].ID })
	return out, nil
}
func nativeRefsExist(ids []string, known map[string]bool) bool {
	if len(ids) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" || seen[id] || !known[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
