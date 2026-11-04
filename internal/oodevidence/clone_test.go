package oodevidence_test

import (
	"context"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodtestfixture"
)

func TestVerifiedBatchReceiptAccessorDoesNotExposeMutableProofState(t *testing.T) {
	f := oodtestfixture.Build(context.Background(), t)
	r, ok := f.Batch.Receipt(f.Receipt.ReceiptID)
	if !ok {
		t.Fatal("verified receipt absent")
	}
	want := r.ReceiptRoles[0]
	r.ReceiptRoles[0] = "forged-role"
	if r.SourceRepresentationMediaType != nil {
		*r.SourceRepresentationMediaType = "forged/type"
	}
	again, ok := f.Batch.Receipt(f.Receipt.ReceiptID)
	if !ok || again.ReceiptRoles[0] != want || (again.SourceRepresentationMediaType != nil && *again.SourceRepresentationMediaType == "forged/type") {
		t.Fatal("returned receipt mutates opaque verified batch")
	}
}

func TestReceiptCloneDetachesAllOptionalPointers(t *testing.T) {
	text, number := "original", int64(1)
	r := oodevidence.ReceiptV8{ReceiptRoles: []string{"role"}, FetchComponentOrdinal: &number, SourceRepresentationMediaType: &text, PermissionExpectedContentHashAlgorithm: &text, PermissionExpectedContentHashProfile: &text, PermissionExpectedContentHash: &text, TransportContentEncoding: &text, TransportCharset: &text}
	clone := oodevidence.CloneReceiptV8(r)
	text, number, r.ReceiptRoles[0] = "changed", 2, "changed"
	for _, value := range []*string{clone.SourceRepresentationMediaType, clone.PermissionExpectedContentHashAlgorithm, clone.PermissionExpectedContentHashProfile, clone.PermissionExpectedContentHash, clone.TransportContentEncoding, clone.TransportCharset} {
		if *value != "original" {
			t.Fatal("receipt nullable field alias survived clone")
		}
	}
	if *clone.FetchComponentOrdinal != 1 || clone.ReceiptRoles[0] != "role" {
		t.Fatal("receipt role or ordinal alias survived clone")
	}
}
