package oodpublication

import (
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"testing"
	"time"
)

func projectionMemberRow(payload CanonicalJSON) SpannerRow {
	return SpannerRow{Table: "OODGraphProjectionArtifacts", KeyColumns: []string{"organization_id", "projection_artifact_id"}, Columns: map[string]interface{}{
		"organization_id": "org", "projection_artifact_id": "11111111-1111-4111-8111-111111111111", "projection_kind": "structural", "projection_target_kind": "none", "projection_target_id": nil, "projection_format": "structured_ood_json", "projection_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "projection_payload": payload, "round_trip_state": "exact", "created_at": time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}}
}
func TestStructuralProjectionMemberDigestUsesExactCanonicalPayloadBytes(t *testing.T) {
	a, err := CanonicalMemberDigestFromPhysicalRow(projectionMemberRow(CanonicalJSON(`{"a":1}`)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalMemberDigestFromPhysicalRow(projectionMemberRow(CanonicalJSON(`{"a":2}`)))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("projection payload mutation retained member digest")
	}
}
func TestAPIPropertyMemberFailsClosedWithoutSchemaValidator(t *testing.T) {
	row := SpannerRow{Table: "OODGraphAPIPropertyFacts", KeyColumns: []string{"organization_id", "api_property_fact_hash"}, Columns: map[string]interface{}{}}
	if _, err := CanonicalMemberDigestFromPhysicalRow(row); err == nil {
		t.Fatal("unvalidated API payload accepted")
	}
}

func TestSourceArtifactExternalEvidenceRequiresExactReceiptBatchPair(t *testing.T) {
	receipt := SpannerRow{Table: "OODGraphExternalFetchReceipts", Columns: map[string]interface{}{"organization_id": "one", "fetch_batch_id": "batch"}}
	batch := SpannerRow{Table: "OODGraphExternalFetchBatches", Columns: map[string]interface{}{"organization_id": "two", "fetch_batch_id": "batch"}}
	if _, err := SourceArtifactExternalEvidenceDigest([]SpannerRow{receipt, receipt}); err == nil {
		t.Fatal("duplicate receipt accepted")
	}
	if _, err := SourceArtifactExternalEvidenceDigest([]SpannerRow{receipt, batch}); err == nil {
		t.Fatal("cross tenant batch accepted")
	}
	batch.Columns["organization_id"] = "one"
	batch.Columns["fetch_batch_id"] = "other"
	if _, err := SourceArtifactExternalEvidenceDigest([]SpannerRow{receipt, batch}); err == nil {
		t.Fatal("cross batch accepted")
	}
}

func TestVirtualSourceEvidenceRejectsCorrelatedPhysicalPayloadTamper(t *testing.T) {
	receipt := evidenceReceiptRow(t)
	batch := evidenceBatchRow(t)
	r, err := ReceiptV8FromPhysicalRow(receipt)
	if err != nil {
		t.Fatal(err)
	}
	d, err := oodevidence.ReceiptDigestV8(r)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Columns["redacted_transport_evidence_digest"] = d
	b, err := BatchV8FromPhysicalRow(batch)
	if err != nil {
		t.Fatal(err)
	}
	bd, err := oodevidence.CompletenessEvidenceDigestV8(b)
	if err != nil {
		t.Fatal(err)
	}
	batch.Columns["completeness_evidence_digest"] = bd
	if err := verifyVirtualSourceEvidence([]SpannerRow{receipt, batch}); err != nil {
		t.Fatal(err)
	}
	receipt.Columns["transport_status"] = "correlated_changed"
	if err := verifyVirtualSourceEvidence([]SpannerRow{receipt, batch}); err == nil {
		t.Fatal("changed physical receipt with old digest accepted")
	}
}
