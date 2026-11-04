package oodpublication

import (
	"strings"
	"testing"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

func TestReceiptV8FromPhysicalRowHydratesCompleteTypedReceipt(t *testing.T) {
	row := evidenceReceiptRow(t)
	got, err := ReceiptV8FromPhysicalRow(row)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReceiptID != row.Columns["receipt_id"] || got.FetchComponentOrdinal == nil || *got.FetchComponentOrdinal != 1 || got.SourceRepresentationMediaType == nil || *got.SourceRepresentationMediaType != "text/plain" || got.PermissionExpiresAt != nil || got.TransportCharset != nil {
		t.Fatalf("nullable fields not preserved: %#v", got)
	}
	before, err := oodevidence.ReceiptDigestV8(got)
	if err != nil {
		t.Fatal(err)
	}
	row.Columns["redacted_transport_evidence_digest"] = before
	row.Columns["transport_status"] = "changed"
	changed, err := ReceiptV8FromPhysicalRow(row)
	if err != nil {
		t.Fatal(err)
	}
	after, err := oodevidence.ReceiptDigestV8(changed)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("non-key canonical receipt field did not change digest")
	}
	if changed.RedactedTransportEvidenceDigest != before || changed.RedactedTransportEvidenceDigest == after {
		t.Fatal("old receipt hash was accepted after changed physical payload")
	}
}

func TestBatchV8FromPhysicalRowHydratesCompleteTypedBatch(t *testing.T) {
	row := evidenceBatchRow(t)
	got, err := BatchV8FromPhysicalRow(row)
	if err != nil {
		t.Fatal(err)
	}
	if got.FetchBatchID != "batch" || got.ExpectedComponentCount == nil || *got.ExpectedComponentCount != 1 || !got.SealedAt.Equal(time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("batch hydration: %#v", got)
	}
	if _, err := oodevidence.CompletenessEvidenceDigestV8(got); err != nil {
		t.Fatal(err)
	}
}

func TestPhysicalEvidenceHydrationRejectsInvalidPhysicalRows(t *testing.T) {
	row := evidenceReceiptRow(t)
	wrong := row
	wrong.Table = "OODGraphExternalFetchBatches"
	if _, err := ReceiptV8FromPhysicalRow(wrong); err == nil {
		t.Fatal("wrong table accepted")
	}
	missing := evidenceReceiptRow(t)
	delete(missing.Columns, "transport_status")
	if _, err := ReceiptV8FromPhysicalRow(missing); err == nil {
		t.Fatal("missing column accepted")
	}
	typed := evidenceReceiptRow(t)
	typed.Columns["transport_raw_byte_count"] = 1
	if _, err := ReceiptV8FromPhysicalRow(typed); err == nil {
		t.Fatal("wrong type accepted")
	}
	null := evidenceReceiptRow(t)
	null.Columns["transport_status"] = nil
	if _, err := ReceiptV8FromPhysicalRow(null); err == nil {
		t.Fatal("required null accepted")
	}
}

func evidenceReceiptRow(t *testing.T) SpannerRow {
	t.Helper()
	cols := validPhysicalFixture("OODGraphExternalFetchReceipts", immutablePhysicalContracts["OODGraphExternalFetchReceipts"])
	cols["organization_id"], cols["fetch_batch_id"], cols["receipt_id"] = "org", "batch", evidenceUUID(1)
	for _, name := range immutablePhysicalContracts["OODGraphExternalFetchReceipts"].columns {
		if physicalUUIDColumn("OODGraphExternalFetchReceipts", name) {
			cols[name] = evidenceUUID(2)
		}
		if physicalDigestColumn("OODGraphExternalFetchReceipts", name) {
			cols[name] = strings.Repeat("a", 64)
		}
	}
	cols["receipt_id"] = evidenceUUID(1)
	cols["receipt_roles"] = []string{"component"}
	cols["fetch_component_ordinal"] = int64(1)
	cols["source_representation_media_type"] = "text/plain"
	cols["permission_expected_content_hash_algorithm"], cols["permission_expected_content_hash_profile"], cols["permission_expected_content_hash"] = nil, nil, nil
	cols["permission_expires_at"], cols["transport_content_encoding"], cols["transport_charset"] = nil, nil, nil
	cols["permission_effective_at"], cols["observed_at"], cols["created_at"] = evidenceTime(), evidenceTime(), evidenceTime()
	cols["transport_raw_byte_count"], cols["transport_decoded_byte_count"], cols["evidence_archive_byte_count"] = int64(4), int64(4), int64(4)
	row, err := BuildImmutableRow("OODGraphExternalFetchReceipts", cols)
	if err != nil {
		t.Fatal(err)
	}
	return row.Row()
}

func evidenceBatchRow(t *testing.T) SpannerRow {
	t.Helper()
	cols := validPhysicalFixture("OODGraphExternalFetchBatches", immutablePhysicalContracts["OODGraphExternalFetchBatches"])
	cols["organization_id"], cols["fetch_batch_id"] = "org", "batch"
	for _, name := range immutablePhysicalContracts["OODGraphExternalFetchBatches"].columns {
		if physicalUUIDColumn("OODGraphExternalFetchBatches", name) {
			cols[name] = evidenceUUID(2)
		}
		if physicalDigestColumn("OODGraphExternalFetchBatches", name) {
			cols[name] = strings.Repeat("a", 64)
		}
	}
	cols["expected_component_count"], cols["sealed_at"], cols["created_at"] = int64(1), evidenceTime(), evidenceTime()
	row, err := BuildImmutableRow("OODGraphExternalFetchBatches", cols)
	if err != nil {
		t.Fatal(err)
	}
	return row.Row()
}

func evidenceTime() time.Time   { return time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC) }
func evidenceUUID(n int) string { return "11111111-1111-4111-8111-11111111111" + string(rune('0'+n)) }
