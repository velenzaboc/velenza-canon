package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func requireCompleteError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want containing %q", err, want)
	}
}

func TestCompleteEnvelopeRejectsEveryUnsealableCoordinate(t *testing.T) {
	valid := MaterializationBatch{
		Run: MaterializationRun{
			OrganizationID:       "org",
			MaterializationRunID: uuid.NewString(),
			RunKind:              "corpus_refresh",
			State:                "running",
			Status:               "active",
			VisibilityScope:      "tenant",
		},
		Snapshot: GraphSnapshot{
			OrganizationID:  "org",
			GraphSnapshotID: uuid.NewString(),
			SnapshotKind:    "active_candidate",
			SnapshotState:   "building",
			Status:          "active",
			VisibilityScope: "tenant",
		},
	}
	if err := validateCompleteEnvelope(valid); err != nil {
		t.Fatalf("valid envelope: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*MaterializationBatch)
		want   string
	}{
		{"organization", func(b *MaterializationBatch) { b.Snapshot.OrganizationID = "other" }, "organization_id"},
		{"run id", func(b *MaterializationBatch) { b.Run.MaterializationRunID = "bad" }, "run id"},
		{"snapshot id", func(b *MaterializationBatch) { b.Snapshot.GraphSnapshotID = "bad" }, "snapshot id"},
		{"run lifecycle", func(b *MaterializationBatch) { b.Run.RunKind = "invented" }, "run kind/state/status"},
		{"snapshot lifecycle", func(b *MaterializationBatch) { b.Snapshot.SnapshotState = "sealed" }, "snapshot kind/state/status"},
		{"visibility", func(b *MaterializationBatch) { b.Run.VisibilityScope = "global" }, "visibility_scope"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := valid
			tc.mutate(&candidate)
			requireCompleteError(t, validateCompleteEnvelope(candidate), tc.want)
		})
	}
}

func TestValidateSourceIdentityRejectsEachMalformedAxis(t *testing.T) {
	authority := uuid.NewString()
	digest := strings.Repeat("a", 64)
	valid := []string{authority, "official_source_repository", "coordinate", "https://example.test/source", "unversioned", SectionPathRoot, digest, authority}
	call := func(values []string) error {
		return validateSourceIdentity(values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7])
	}
	if err := call(valid); err != nil {
		t.Fatalf("valid source identity: %v", err)
	}
	tests := []struct {
		name  string
		index int
		value string
		want  string
	}{
		{"authority", 0, "bad", "source_authority_id"},
		{"artifact class", 1, "Official Source", "source_artifact_class"},
		{"reference kind", 2, "invented", "not registered"},
		{"stable reference", 3, " padded ", "non-canonical"},
		{"version", 4, "bad version", "version_coordinate"},
		{"section", 5, "not-a-path", "section_path"},
		{"unpaired digest", 7, "", "present together"},
		{"digest", 6, "abcd", "source_content_hash"},
		{"digest owner", 7, "bad", "source_content_hash_owner"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := append([]string(nil), valid...)
			candidate[tc.index] = tc.value
			requireCompleteError(t, call(candidate), tc.want)
		})
	}
	foreign := append([]string(nil), valid...)
	foreign[4] = VersionCoordinate{Kind: VersionSourceNamed, SourceAuthorityID: uuid.NewString(), StableName: "source", SourceVersionToken: "v1"}.String()
	requireCompleteError(t, call(foreign), "authority does not match")

	withoutDigest := append([]string(nil), valid...)
	withoutDigest[6], withoutDigest[7] = "", ""
	if err := call(withoutDigest); err != nil {
		t.Fatalf("optional digest pair rejected: %v", err)
	}
}

func TestCompleteSymbolRefusalMatrix(t *testing.T) {
	batch, authority := completeValidationFixture(t)
	if len(batch.Symbols) == 0 {
		t.Fatal("fixture produced no symbols")
	}
	base := batch.Symbols[0]
	owner := batch.Objects[0]
	for _, object := range batch.Objects {
		if object.GraphObjectID == base.GraphObjectID {
			owner = object
			break
		}
	}
	if err := validateCompleteSymbol(base, owner, batch, authority); err != nil {
		t.Fatalf("valid symbol: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*GraphSymbol)
		want   string
	}{
		{"id", func(s *GraphSymbol) { s.SymbolID = "bad" }, "UUID"},
		{"lifecycle", func(s *GraphSymbol) { s.Status = "archived" }, "lifecycle binding"},
		{"owner coordinate", func(s *GraphSymbol) { s.ObjectClass = "decision" }, "owner class/source"},
		{"empty kind", func(s *GraphSymbol) { s.SymbolKind = "" }, "empty or oversized"},
		{"oversized name", func(s *GraphSymbol) { s.SymbolName = strings.Repeat("x", 1025) }, "empty or oversized"},
		{"section", func(s *GraphSymbol) { s.SectionPath = "bad" }, "section_path"},
		{"address syntax", func(s *GraphSymbol) { s.GraphAddress = "bad" }, "byte-canonical"},
		{"address coordinate", func(s *GraphSymbol) { s.SourceStableReference = "different" }, "owner class/source"},
		{"deterministic id", func(s *GraphSymbol) { s.SymbolID = uuid.NewString() }, "not deterministic"},
		{"embedding", func(s *GraphSymbol) { s.Embedding = nil }, "embedding must"},
		{"model", func(s *GraphSymbol) { s.EmbeddingModel = "other" }, "dimensional authority"},
		{"retrieval", func(s *GraphSymbol) { s.SearchText += " leak" }, "retrieval metadata"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			candidate.Embedding = append([]float32(nil), base.Embedding...)
			candidate.SearchPayload = cloneMap(base.SearchPayload)
			tc.mutate(&candidate)
			requireCompleteError(t, validateCompleteSymbol(candidate, owner, batch, authority), tc.want)
		})
	}
}

func TestCompleteEdgeRefusalMatrix(t *testing.T) {
	batch, authority := completeValidationFixture(t)
	if len(batch.Edges) == 0 {
		t.Fatal("fixture produced no edges")
	}
	base := batch.Edges[0]
	objects := make(map[string]GraphObject, len(batch.Objects))
	for _, object := range batch.Objects {
		objects[object.GraphObjectID] = object
	}
	if err := validateCompleteEdge(context.Background(), base, objects, batch, authority); err != nil {
		t.Fatalf("valid edge: %v", err)
	}
	now := time.Now().UTC()
	earlier := now.Add(-time.Minute)
	nan := float32(math.NaN())
	over := float32(1.1)
	tests := []struct {
		name   string
		mutate func(*GraphEdge)
		want   string
	}{
		{"id", func(e *GraphEdge) { e.GraphEdgeID = "bad" }, "UUID"},
		{"lifecycle", func(e *GraphEdge) { e.ValidationState = "invalid" }, "lifecycle binding"},
		{"endpoint kind", func(e *GraphEdge) { e.TargetEndpointKind = "symbol" }, "both be graph_object"},
		{"absent endpoint", func(e *GraphEdge) { e.TargetEndpointID = uuid.NewString() }, "absent from this snapshot"},
		{"label", func(e *GraphEdge) { e.EdgeLabel = "invented" }, "closed registry"},
		{"family", func(e *GraphEdge) { e.EdgeFamily = "invented" }, "differs from registry"},
		{"class evidence", func(e *GraphEdge) { e.TargetEndpointClass = "axiom" }, "class/version evidence"},
		{"source evidence", func(e *GraphEdge) { e.SourceContentHash = "different" }, "source endpoint"},
		{"author path", func(e *GraphEdge) { e.AuthoringSourcePath = "bad" }, "authoring_source_path"},
		{"time interval", func(e *GraphEdge) { e.ValidFrom, e.ValidUntil = &now, &earlier }, "must precede"},
		{"nan confidence", func(e *GraphEdge) { e.EdgeConfidence = &nan }, "finite within"},
		{"high confidence", func(e *GraphEdge) { e.EdgeConfidence = &over }, "finite within"},
		{"deterministic id", func(e *GraphEdge) { e.GraphEdgeID = uuid.NewString() }, "not deterministic"},
		{"search text", func(e *GraphEdge) { e.SearchText += " leak" }, "search_text"},
		{"search payload", func(e *GraphEdge) { e.SearchPayload["leak"] = true }, "search_payload"},
		{"embedding", func(e *GraphEdge) { e.Embedding = nil }, "embedding must"},
		{"model", func(e *GraphEdge) { e.EmbeddingModel = "other" }, "dimensional authority"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := base
			candidate.Embedding = append([]float32(nil), base.Embedding...)
			candidate.SearchPayload = cloneMap(base.SearchPayload)
			tc.mutate(&candidate)
			requireCompleteError(t, validateCompleteEdge(context.Background(), candidate, objects, batch, authority), tc.want)
		})
	}
}

func TestCompleteProjectionRefusalMatrix(t *testing.T) {
	batch, authority := completeValidationFixture(t)
	objects := make(map[string]GraphObject, len(batch.Objects))
	for _, object := range batch.Objects {
		objects[object.GraphObjectID] = object
	}
	symbols := make(map[string]GraphSymbol, len(batch.Symbols))
	for _, symbol := range batch.Symbols {
		symbols[symbol.SymbolID] = symbol
	}
	payload := map[string]interface{}{"object_class": batch.Objects[0].ObjectClass}
	canonical, err := canonicalJSON(payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	valid := ProjectionArtifact{
		OrganizationID: batch.Run.OrganizationID, ProjectionArtifactID: uuid.NewString(),
		GraphSnapshotID: batch.Snapshot.GraphSnapshotID, ProjectionKind: "doc_canonical_json",
		ProjectionTargetKind: "graph_object", ProjectionTargetID: batch.Objects[0].GraphObjectID,
		ProjectionFormat: "structured_ood_json", ProjectionHash: hex.EncodeToString(digest[:]), ProjectionPayload: payload,
		RoundTripState: "equivalent", MaterializationRunID: batch.Run.MaterializationRunID,
		Status: "active", VisibilityScope: batch.Snapshot.VisibilityScope,
	}
	with := func(p ProjectionArtifact) MaterializationBatch {
		candidate := batch
		candidate.ProjectionArtifacts = []ProjectionArtifact{p}
		return candidate
	}
	if err := validateCompleteProjections(context.Background(), with(valid), objects, symbols, authority.Projections); err != nil {
		t.Fatalf("valid projection: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ProjectionArtifact)
		want   string
	}{
		{"id", func(p *ProjectionArtifact) { p.ProjectionArtifactID = "bad" }, "id"},
		{"kind", func(p *ProjectionArtifact) { p.ProjectionKind = "missing" }, "kind"},
		{"binding", func(p *ProjectionArtifact) { p.Status = "archived" }, "lifecycle binding"},
		{"format", func(p *ProjectionArtifact) { p.ProjectionFormat = "text" }, "format, payload"},
		{"payload", func(p *ProjectionArtifact) { p.ProjectionPayload = nil }, "format, payload"},
		{"canonical payload", func(p *ProjectionArtifact) { p.ProjectionPayload = map[string]interface{}{"bad": make(chan int)} }, "canonical payload"},
		{"hash", func(p *ProjectionArtifact) { p.ProjectionHash = strings.Repeat("0", 64) }, "does not attest"},
		{"object target", func(p *ProjectionArtifact) { p.ProjectionTargetID = uuid.NewString() }, "target is absent"},
		{"snapshot target", func(p *ProjectionArtifact) {
			p.ProjectionTargetKind = "graph_snapshot"
			p.ProjectionTargetID = uuid.NewString()
		}, "differs from batch"},
		{"target kind", func(p *ProjectionArtifact) { p.ProjectionTargetKind = "edge" }, "not a supported"},
		{"round trip", func(p *ProjectionArtifact) { p.RoundTripState = "loss_detected" }, "cannot seal"},
	}
	if len(batch.Symbols) > 0 {
		tests = append(tests, struct {
			name   string
			mutate func(*ProjectionArtifact)
			want   string
		}{"symbol target", func(p *ProjectionArtifact) {
			p.ProjectionTargetKind = "symbol"
			p.ProjectionTargetID = batch.Symbols[0].SymbolID
		}, ""})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := valid
			candidate.ProjectionPayload = cloneMap(valid.ProjectionPayload)
			tc.mutate(&candidate)
			err := validateCompleteProjections(context.Background(), with(candidate), objects, symbols, authority.Projections)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("valid symbol projection: %v", err)
				}
				return
			}
			requireCompleteError(t, err, tc.want)
		})
	}
	requireCompleteError(t, validateCompleteProjections(context.Background(), with(valid), objects, symbols, nil), "no projection registry")
	duplicate := batch
	duplicate.ProjectionArtifacts = []ProjectionArtifact{valid, valid}
	requireCompleteError(t, validateCompleteProjections(context.Background(), duplicate, objects, symbols, authority.Projections), "duplicate projection")
}

func TestCompletePublicationEnvelopeAccountsForMetadataAndVectors(t *testing.T) {
	ordinary := MaterializationBatch{Objects: []GraphObject{{ObjectClass: "section"}}}
	if err := validateCompleteExternalBootstrapPublicationEnvelope(ordinary); err != nil {
		t.Fatalf("ordinary batch should bypass external envelope: %v", err)
	}
	external := MaterializationBatch{Objects: []GraphObject{{ObjectClass: "reference_page", Embedding: []float32{1}}}}
	if err := validateCompleteExternalBootstrapPublicationEnvelope(external); err != nil {
		t.Fatalf("small external batch: %v", err)
	}
	tooMany := external
	tooMany.Symbols = make([]GraphSymbol, maxCompleteExternalBootstrapVectorRows)
	requireCompleteError(t, validateCompleteExternalBootstrapPublicationEnvelope(tooMany), "exceeds external-bootstrap")
	badJSON := MaterializationBatch{Objects: []GraphObject{external.Objects[0]}}
	badJSON.Objects[0].SearchPayload = map[string]interface{}{"bad": make(chan int)}
	requireCompleteError(t, validateCompleteExternalBootstrapPublicationEnvelope(badJSON), "estimate complete")
	tooLarge := MaterializationBatch{Objects: []GraphObject{external.Objects[0]}}
	tooLarge.Objects[0].SearchText = strings.Repeat("x", maxCompleteExternalBootstrapMetadataBytes+1)
	requireCompleteError(t, validateCompleteExternalBootstrapPublicationEnvelope(tooLarge), "non-vector")
}

func cloneMap(in map[string]interface{}) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
