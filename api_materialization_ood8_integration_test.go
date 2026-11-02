package main

import (
	"context"
	"errors"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
)

// apiOOD8ProtectedWriter is deliberately a protected-publisher seam, not a
// closure minting seam: Publish still receives the opaque value independently
// minted by VerifyClosureV8 in the all-roots fixture.
type apiOOD8ProtectedWriter struct {
	calls int
	proof oodevidence.VerifiedClosureV8
	plan  oodpublication.SpannerWritePlan
}

func (w *apiOOD8ProtectedWriter) PublishVerifiedOutcome(_ context.Context, proof oodevidence.VerifiedClosureV8, plan oodpublication.SpannerWritePlan) (oodpublication.SpannerPublicationOutcome, error) {
	if err := oodevidence.ValidateVerifiedClosureV8(proof); err != nil {
		return oodpublication.SpannerPublicationOutcome{}, err
	}
	if proof.OrganizationID() != plan.OrganizationID || proof.ClosureHash() != plan.ClosureHash {
		return oodpublication.SpannerPublicationOutcome{}, errors.New("protected writer received unbound plan")
	}
	w.calls++
	w.proof, w.plan = proof, plan
	return oodpublication.SpannerPublicationOutcome{SnapshotID: plan.SnapshotID, RunID: plan.RunID}, nil
}

func TestOOD8APIMaterializationCompleteNativeProofToProtectedPublication(t *testing.T) {
	native, proof := buildOOD8AllRootsManifestFixture(t)
	materialization, err := BuildVerifiedOOD8APIMaterializationFromClosureInput(context.Background(), native)
	if err != nil {
		t.Fatalf("complete native OOD8 proof was not materialized: %v", err)
	}
	writer := &apiOOD8ProtectedWriter{}
	out, err := (OOD8APIMaterializer{publisher: writer}).Publish(context.Background(), proof, materialization)
	if err != nil {
		t.Fatalf("protected publication refused verified materialization: %v", err)
	}
	if writer.calls != 1 || out.SnapshotID != native.Factory.Plan.SnapshotID || writer.plan.OrganizationID != proof.OrganizationID() || writer.plan.ClosureHash != proof.ClosureHash() {
		t.Fatalf("protected writer did not receive exactly the closure-bound plan: calls=%d outcome=%+v", writer.calls, out)
	}
}

func TestOOD8APIMaterializationRejectsCorrelatedFixtureSubstitutions(t *testing.T) {
	for name, mutate := range map[string]func(*OOD8APIClosureMaterializationInput){
		"role proof removed": func(n *OOD8APIClosureMaterializationInput) { n.Factory.LocatorProofs = nil },
		"API property payload substituted": func(n *OOD8APIClosureMaterializationInput) {
			for i := range n.Closure.ImmutableRows {
				if n.Closure.ImmutableRows[i].Table == "OODGraphAPIPropertyFacts" {
					n.Closure.ImmutableRows[i].Columns["property_payload"] = oodpublication.CanonicalJSON(`{"name":"substituted"}`)
					return
				}
			}
		},
		"manifest entry substituted": func(n *OOD8APIClosureMaterializationInput) {
			for i := range n.Closure.ImmutableRows {
				if n.Closure.ImmutableRows[i].Table == "OODGraphManifestEntries" {
					n.Closure.ImmutableRows[i].Columns["canonical_entry_byte_count"] = int64(2)
					return
				}
			}
		},
		"certificate cross organization substitution": func(n *OOD8APIClosureMaterializationInput) {
			for i := range n.Closure.ImmutableRows {
				if n.Closure.ImmutableRows[i].Table == "OODGraphClosureVerificationCertificates" {
					n.Closure.ImmutableRows[i].Columns["organization_id"] = apiOOD8ID("foreign-org")
					return
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			native, _ := buildOOD8AllRootsManifestFixture(t)
			mutate(&native)
			if _, err := BuildVerifiedOOD8APIMaterializationFromClosureInput(context.Background(), native); err == nil {
				t.Fatal("correlated substitution reached API materialization")
			}
		})
	}
}
