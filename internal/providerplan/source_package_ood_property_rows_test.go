package providerplan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

type nativePropertySchemaResolver struct {
	schema oodpublication.AdmittedAPIPropertyPayloadSchema
}

func (r nativePropertySchemaResolver) ResolveAPIPropertyPayloadSchema(_ context.Context, id, version, digest, profile string) (oodpublication.AdmittedAPIPropertyPayloadSchema, error) {
	if r.schema.ArtifactID != id || r.schema.Version != version || r.schema.Digest != digest || r.schema.Profile != profile {
		return oodpublication.AdmittedAPIPropertyPayloadSchema{}, context.Canceled
	}
	return r.schema, nil
}

func TestBuildDocumentationFactorySourcePackageOODNativePropertyRows(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	var object, locator oodpublication.SpannerRow
	for _, row := range f.ImmutableRows {
		if row.Table == "OODGraphObjects" && object.Table == "" {
			object = row
		}
		if row.Table == "OODGraphGraphFactEvidenceLocators" {
			locator = row
		}
	}
	if object.Table == "" || locator.Table == "" {
		t.Fatal("fixture rows absent")
	}
	objectID := object.Columns["graph_object_id"].(string)
	now := time.Date(2026, 11, 2, 14, 0, 0, 0, time.UTC)
	id := func(s string) string { return uuid.NewSHA1(uuid.NameSpaceURL, []byte("native-property/"+s)).String() }
	p := DocumentationFactorySourcePackageOODNativeProjection{
		Properties: []DocumentationFactoryNativeAPIProperty{{ID: "p", Family: "fixture_property", SubjectKind: "object", SubjectID: "native-object", PropertyName: "name", CandidateValue: []byte(`{"name":"value"}`), LocatorIDs: []string{"l"}}},
		Gaps:       []DocumentationFactoryNativeGraphGap{{ID: "g", GapClass: "unsupported", BlockedSubjectKind: "object", BlockedSubjectID: "native-object", BlockedClaimKind: "property", BlockedClaimID: "missing", Disposition: "unsupported", MaterializationEligible: false, LocatorIDs: []string{"l"}}},
	}
	ctx := DocumentationFactorySourcePackageOODNativePropertyRowsContext{
		OrganizationID: f.Receipt.OrganizationID, SnapshotID: id("snapshot"), RunID: id("run"), CreatedAt: now,
		LocatorBindings: []DocumentationFactorySourcePackageOODLocatorBinding{{NativeLocatorID: "l", Locator: f.Locator, LocatorRow: locator}},
		Properties:      []DocumentationFactoryNativePropertyIdentity{{NativePropertyID: "p", SubjectKind: "object", NativeSubjectID: "native-object", GraphObjectID: objectID, PropertyFamily: "fixture_property", PropertySchemaArtifactID: f.PropertySchema.ArtifactID, PropertySchemaVersion: f.PropertySchema.Version, PropertySchemaDigest: f.PropertySchema.Digest, PropertyPayloadProfile: f.PropertySchema.Profile, ExtractorProfileID: id("extractor"), ExtractorProfileVersion: "v1", ExtractorProfileDigest: sha256Hex([]byte("extractor")), EvidenceAuthorityClass: "documentation", DeletionDomainID: f.Receipt.EvidenceArchiveDeletionDomainID}},
		Gaps:            []DocumentationFactoryNativeGapIdentity{{NativeGapID: "g", ViolationID: id("violation"), ViolationCode: "native_gap_unsupported", Severity: "warning", Status: "active", VisibilityScope: "organization", NativeSubjectID: "native-object", GraphObjectID: objectID, GapClass: "unsupported", BlockedSubjectKind: "object", BlockedSubjectID: "native-object", BlockedClaimKind: "property", BlockedClaimID: "missing", Disposition: "unsupported"}},
		PropertySchemas: nativePropertySchemaResolver{f.PropertySchema},
	}
	got, err := BuildDocumentationFactorySourcePackageOODNativePropertyRows(context.Background(), p, DocumentationFactorySourcePackageOODNativeGraphRows{Objects: []oodpublication.SpannerRow{object}}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Properties) != 1 || len(got.Violations) != 1 || len(got.Members) != 2 {
		t.Fatalf("unexpected output: %+v", got)
	}
	expectedManifest, err := oodpublication.BuildNativeLocatorManifest(oodpublication.NativeLocatorManifestInput{OrganizationID: f.Receipt.OrganizationID, Locators: []oodpublication.SpannerRow{locator}, CreatedAt: now})
	if err != nil || len(got.LocatorManifestRows) != len(expectedManifest.ImmutableRows) || len(got.LocatorManifestNodes) != len(expectedManifest.Nodes) {
		t.Fatalf("shared property/gap locator manifest was not exact-deduplicated: %v %+v", err, got)
	}
	roots, err := oodpublication.ViolationGraphFactLocatorManifestRoots(got.Violations[0].Columns["evidence"].(oodpublication.CanonicalJSON))
	if err != nil || len(roots) != 1 || roots[0] != expectedManifest.RootHash {
		t.Fatalf("gap violation did not retain its typed locator-manifest root: %v %v", roots, err)
	}
	v := oodpublication.ManifestMemberVerifier{PropertyPayloadSchemas: ctx.PropertySchemas}
	if d, err := v.CanonicalMemberDigestFromPhysicalRow(context.Background(), got.Properties[0]); err != nil || d != got.Properties[0].Columns["api_property_fact_hash"] {
		t.Fatalf("property member binding: %s %v", d, err)
	}
	if _, err := oodpublication.CanonicalViolationMemberDigest(got.Violations[0]); err != nil {
		t.Fatal(err)
	}

	p.Properties[0].CandidateValue = []byte(`{"name":"value","raw":"forbidden"}`)
	if _, err := BuildDocumentationFactorySourcePackageOODNativePropertyRows(context.Background(), p, DocumentationFactorySourcePackageOODNativeGraphRows{Objects: []oodpublication.SpannerRow{object}}, ctx); err == nil {
		t.Fatal("accepted property payload outside admitted schema")
	}
	p.Properties[0].CandidateValue = []byte(`{"name":"value"}`)
	ctx.Gaps[0].SymbolID = id("foreign-symbol")
	if _, err := BuildDocumentationFactorySourcePackageOODNativePropertyRows(context.Background(), p, DocumentationFactorySourcePackageOODNativeGraphRows{Objects: []oodpublication.SpannerRow{object}}, ctx); err == nil {
		t.Fatal("accepted nonexistent gap symbol")
	}
	ctx.Gaps[0].SymbolID = ""
	p.Gaps[0].MaterializationEligible = true
	if _, err := BuildDocumentationFactorySourcePackageOODNativePropertyRows(context.Background(), p, DocumentationFactorySourcePackageOODNativeGraphRows{Objects: []oodpublication.SpannerRow{object}}, ctx); err == nil {
		t.Fatal("accepted eligible candidate gap as violation")
	}

	// Distinct source ranges form one canonical sorted locator manifest; input
	// order cannot select a different fact root.
	l2 := f.Locator
	part := []byte("canonical")
	sum := sha256.Sum256(part)
	l2.ByteStartOffset, l2.ByteEndOffsetExclusive, l2.SelectedRangeByteCount, l2.SelectedRangeContentHash = 0, int64(len(part)), int64(len(part)), hex.EncodeToString(sum[:])
	var e error
	l2.LocatorHash, e = l2.ComputedHash()
	if e != nil {
		t.Fatal(e)
	}
	cols := map[string]interface{}{}
	for k, v := range locator.Columns {
		cols[k] = v
	}
	cols["graph_fact_locator_hash"], cols["byte_start_offset"], cols["byte_end_offset_exclusive"], cols["selected_range_content_hash"], cols["selected_range_byte_count"] = l2.LocatorHash, l2.ByteStartOffset, l2.ByteEndOffsetExclusive, l2.SelectedRangeContentHash, l2.SelectedRangeByteCount
	x, e := oodpublication.BuildImmutableRow("OODGraphGraphFactEvidenceLocators", cols)
	if e != nil {
		t.Fatal(e)
	}
	ctx.LocatorBindings = append(ctx.LocatorBindings, DocumentationFactorySourcePackageOODLocatorBinding{NativeLocatorID: "l2", Locator: l2, LocatorRow: x.Row()})
	p.Gaps = nil
	ctx.Gaps = nil
	p.Properties[0].LocatorIDs = []string{"l", "l2"}
	got, err = BuildDocumentationFactorySourcePackageOODNativePropertyRows(context.Background(), p, DocumentationFactorySourcePackageOODNativeGraphRows{Objects: []oodpublication.SpannerRow{object}}, ctx)
	if err != nil || len(got.LocatorManifestRows) < 3 || len(got.LocatorManifestNodes) == 0 {
		t.Fatalf("multi-locator manifest: %v %+v", err, got)
	}
	first := got.Properties[0].Columns["graph_fact_locator_manifest_hash"]
	p.Properties[0].LocatorIDs = []string{"l2", "l"}
	got, err = BuildDocumentationFactorySourcePackageOODNativePropertyRows(context.Background(), p, DocumentationFactorySourcePackageOODNativeGraphRows{Objects: []oodpublication.SpannerRow{object}}, ctx)
	if err != nil || got.Properties[0].Columns["graph_fact_locator_manifest_hash"] != first {
		t.Fatalf("locator order changed root: %v", err)
	}
	p.Properties[0].LocatorIDs = []string{"l", "l"}
	if _, err := BuildDocumentationFactorySourcePackageOODNativePropertyRows(context.Background(), p, DocumentationFactorySourcePackageOODNativeGraphRows{Objects: []oodpublication.SpannerRow{object}}, ctx); err == nil {
		t.Fatal("duplicate locator accepted")
	}
}

func TestNativeGapCommitmentSeparatesEmbeddedNULBoundaries(t *testing.T) {
	a := DocumentationFactoryNativeGraphGap{GapClass: "a\x00b", BlockedSubjectKind: "c", BlockedSubjectID: "d", BlockedClaimKind: "e", BlockedClaimID: "f", Disposition: "g"}
	b := DocumentationFactoryNativeGraphGap{GapClass: "a", BlockedSubjectKind: "b\x00c", BlockedSubjectID: "d", BlockedClaimKind: "e", BlockedClaimID: "f", Disposition: "g"}
	left, err := nativeGapCommitment(a, sha256Hex([]byte("root")))
	if err != nil {
		t.Fatal(err)
	}
	right, err := nativeGapCommitment(b, sha256Hex([]byte("root")))
	if err != nil {
		t.Fatal(err)
	}
	if left == right {
		t.Fatal("NUL boundary shift shares a gap commitment")
	}
}

var _ = oodevidence.ReceiptV8{}
