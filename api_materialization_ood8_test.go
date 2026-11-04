package main

import (
	"context"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

func TestOOD8APIMaterializerFailsClosedWithoutProtectedDependencies(t *testing.T) {
	_, err := (OOD8APIMaterializer{}).Publish(context.Background(), oodevidence.VerifiedClosureV8{}, OOD8APIMaterialization{})
	if err == nil {
		t.Fatal("unprotected OOD8 API materialization accepted")
	}
}

func TestBuildVerifiedOOD8APIMaterializationRequiresOpaqueNativeProofs(t *testing.T) {
	if _, err := BuildVerifiedOOD8APIMaterialization(nil, OOD8APINativeMaterializationOutput{}); err == nil {
		t.Fatal("nil context accepted")
	}
	if _, err := BuildVerifiedOOD8APIMaterialization(context.Background(), OOD8APINativeMaterializationOutput{}); err == nil {
		t.Fatal("caller without opaque closure and roster proofs accepted")
	}
}

func TestClonePlanDoesNotRetainMutablePhysicalPayload(t *testing.T) {
	payload := []byte("{}")
	plan := oodpublication.SpannerWritePlan{ImmutableRows: []oodpublication.SpannerRow{{Columns: map[string]interface{}{"payload": payload}}}}
	copy := clonePlan(plan)
	payload[0] = '['
	got := copy.ImmutableRows[0].Columns["payload"].([]byte)
	if string(got) != "{}" {
		t.Fatalf("opaque plan retained mutable caller bytes: %q", got)
	}
}

func TestNativeCurrentEvidenceAdapterCarriesOnlyOpaqueProofs(t *testing.T) {
	current := providerplan.DocumentationFactoryProductionSourceOODCurrentEvidenceRows{}
	factory := OOD8APIFactoryOutput{Plan: oodpublication.SpannerWritePlan{OrganizationID: "org"}}
	got := OOD8APINativeOutputFromCurrentEvidence(current, factory)
	if got.Factory.Plan.OrganizationID != "org" {
		t.Fatal("publisher adapter did not preserve factory output")
	}
	if got.Closure.OrganizationID() != "" || got.Roster.RowCount() != 0 {
		t.Fatal("zero opaque proofs were unexpectedly manufactured")
	}
}
