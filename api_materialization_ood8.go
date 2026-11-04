package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodapi"
	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
	"github.com/velenzaboc/velenza-canon/internal/oodpublication"
	"github.com/velenzaboc/velenza-canon/internal/providerplan"
)

type OOD8APIFactoryOutput struct {
	LocatorProofs         []oodevidence.VerifiedLocatorV8
	EvidenceLocatorProofs []oodevidence.VerifiedGraphFactLocatorV8
	RoleProofs            []oodevidence.VerifiedAPIElementRoleV8
	Plan                  oodpublication.SpannerWritePlan
}
type OOD8APIMaterialization struct {
	plan oodpublication.SpannerWritePlan
}

// OOD8APINativeMaterializationOutput is the sole final bridge from the native
// read-only derivation path to API publication. Both proof values are opaque:
// API callers cannot replace an all-nine-root traversal with asserted hashes,
// a callback, or a partial immutable roster.
type OOD8APINativeMaterializationOutput struct {
	Closure oodevidence.VerifiedClosureV8
	Roster  oodevidence.VerifiedPublicationRosterV8
	Factory OOD8APIFactoryOutput
}

// OOD8APINativeOutputFromCurrentEvidence is the publisher-facing adapter for
// the same-read source proof. The provider-plan reader has already reconciled
// the typed nine-root closure and minted both opaque values from precisely the
// immutable rows it read; this adapter deliberately exposes neither its raw
// closure input nor a callback authority to API callers.
func OOD8APINativeOutputFromCurrentEvidence(current providerplan.DocumentationFactoryProductionSourceOODCurrentEvidenceRows, factory OOD8APIFactoryOutput) OOD8APINativeMaterializationOutput {
	return OOD8APINativeMaterializationOutput{Closure: current.VerifiedClosure, Roster: current.VerifiedRoster, Factory: factory}
}

// BuildVerifiedOOD8APIMaterialization turns protected native proof output into
// an opaque API write plan. It deliberately performs no Spanner mutation.
func BuildVerifiedOOD8APIMaterialization(ctx context.Context, native OOD8APINativeMaterializationOutput) (OOD8APIMaterialization, error) {
	if ctx == nil {
		return OOD8APIMaterialization{}, errors.New("OOD8 API materialization requires context")
	}
	return NewVerifiedOOD8APIMaterialization(native.Closure, native.Roster, native.Factory)
}

// OOD8APIClosureMaterializationInput is confined to the native source-proof
// owner while it mints the opaque result above. It is intentionally not used
// by the API publication entrypoint: accepting it there would let API callers
// provide raw manifest closure rows and an attestation callback.
type OOD8APIClosureMaterializationInput struct {
	Certificate oodevidence.ClosureCertificateV8
	Closure     oodpublication.ManifestClosureInput
	Attestor    oodpublication.ClosureAttestor
	Factory     OOD8APIFactoryOutput
}

// BuildVerifiedOOD8APIMaterializationFromClosureInput is a native-owner
// helper. It runs deterministic reconciliation and mints opaque proofs before
// delegating to the final API entrypoint.
func BuildVerifiedOOD8APIMaterializationFromClosureInput(ctx context.Context, native OOD8APIClosureMaterializationInput) (OOD8APIMaterialization, error) {
	if ctx == nil {
		return OOD8APIMaterialization{}, errors.New("OOD8 API materialization requires context")
	}
	reconciler := oodpublication.ManifestClosureReconciler{Input: native.Closure}
	authority := oodpublication.AttestedManifestClosureAuthority{ManifestClosureReconciler: reconciler, Attestor: native.Attestor}
	proof, err := oodevidence.VerifyClosureV8(ctx, native.Certificate, authority)
	if err != nil {
		return OOD8APIMaterialization{}, fmt.Errorf("verified native OOD8 closure: %w", err)
	}
	if native.Factory.Plan.OrganizationID != proof.OrganizationID() || native.Factory.Plan.ClosureHash != proof.ClosureHash() {
		return OOD8APIMaterialization{}, errors.New("native API plan does not bind verified closure")
	}
	rows, err := oodpublication.CanonicalImmutableRosterBytes(native.Factory.Plan.ImmutableRows)
	if err != nil {
		return OOD8APIMaterialization{}, fmt.Errorf("canonical native API immutable roster: %w", err)
	}
	roster, err := oodevidence.VerifyPublicationRosterV8(ctx, proof, rows, reconciler)
	if err != nil {
		return OOD8APIMaterialization{}, fmt.Errorf("verified native OOD8 immutable roster: %w", err)
	}
	return BuildVerifiedOOD8APIMaterialization(ctx, OOD8APINativeMaterializationOutput{Closure: proof, Roster: roster, Factory: native.Factory})
}

// NewVerifiedOOD8APIMaterialization requires a protected complete-roster
// proof. It binds every immutable byte, including non-API manifest/property
// and certificate rows, to the verified closure before persistence.
func NewVerifiedOOD8APIMaterialization(proof oodevidence.VerifiedClosureV8, roster oodevidence.VerifiedPublicationRosterV8, in OOD8APIFactoryOutput) (OOD8APIMaterialization, error) {
	if err := oodapi.ValidateMaterialization(proof, roster, oodapi.FactoryOutput{Plan: in.Plan, LocatorProofs: in.LocatorProofs, EvidenceLocatorProofs: in.EvidenceLocatorProofs, RoleProofs: in.RoleProofs}); err != nil {
		return OOD8APIMaterialization{}, err
	}
	return OOD8APIMaterialization{plan: clonePlan(in.Plan)}, nil
}

type ood8VerifiedPublisher interface {
	PublishVerifiedOutcome(context.Context, oodevidence.VerifiedClosureV8, oodpublication.SpannerWritePlan) (oodpublication.SpannerPublicationOutcome, error)
}
type OOD8APIMaterializer struct {
	Writer    oodpublication.SpannerPublicationWriter
	publisher ood8VerifiedPublisher
}

func (m OOD8APIMaterializer) Publish(ctx context.Context, proof oodevidence.VerifiedClosureV8, in OOD8APIMaterialization) (oodpublication.SpannerPublicationOutcome, error) {
	if err := oodevidence.ValidateVerifiedClosureV8(proof); err != nil {
		return oodpublication.SpannerPublicationOutcome{}, fmt.Errorf("verified closure required: %w", err)
	}
	if in.plan.OrganizationID != proof.OrganizationID() || in.plan.ClosureHash != proof.ClosureHash() {
		return oodpublication.SpannerPublicationOutcome{}, errors.New("opaque API materialization does not bind closure")
	}
	p := m.publisher
	if p == nil {
		if m.Writer.Client == nil {
			return oodpublication.SpannerPublicationOutcome{}, errors.New("OOD8 API materialization requires protected writer")
		}
		p = m.Writer
	}
	return p.PublishVerifiedOutcome(ctx, proof, clonePlan(in.plan))
}

func clonePlan(p oodpublication.SpannerWritePlan) oodpublication.SpannerWritePlan {
	p.ImmutableRows = append([]oodpublication.SpannerRow(nil), p.ImmutableRows...)
	for i := range p.ImmutableRows {
		p.ImmutableRows[i].KeyColumns = append([]string(nil), p.ImmutableRows[i].KeyColumns...)
		p.ImmutableRows[i].Columns = cloneColumns(p.ImmutableRows[i].Columns)
	}
	p.Snapshot.Columns, p.Run.Columns, p.Head.Columns, p.Publication.Columns = cloneColumns(p.Snapshot.Columns), cloneColumns(p.Run.Columns), cloneColumns(p.Head.Columns), cloneColumns(p.Publication.Columns)
	return p
}
func cloneColumns(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = cloneColumnValue(v)
	}
	return out
}

// Immutable plans must remain immutable after the opaque materialization has
// been minted.  The row codec admits these concrete values only; cloning them
// here prevents a retained caller slice or canonical JSON buffer from changing
// the bytes later handed to the protected writer.
func cloneColumnValue(v interface{}) interface{} {
	switch x := v.(type) {
	case []byte:
		return append([]byte(nil), x...)
	case []string:
		return append([]string(nil), x...)
	case oodpublication.CanonicalJSON:
		return oodpublication.CanonicalJSON(append([]byte(nil), x...))
	case time.Time, string, int64, bool, nil:
		return x
	default:
		// The strict row codec rejects every other value before this plan can
		// be used. Retaining it here lets the codec produce the authoritative
		// error rather than silently coercing an unsupported type.
		return x
	}
}
