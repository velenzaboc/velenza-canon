package providerplan

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/velenzaboc/velenza-canon/internal/oodevidence"
)

type productionSourceOODStrongReaderStub struct {
	rows    DocumentationFactoryProductionSourceOODCurrentEvidenceRows
	request DocumentationFactoryProductionSourceOODReadRequest
	err     error
	calls   int
	after   func()
}

func (s *productionSourceOODStrongReaderStub) ReadCurrentEligibleProviderEvidenceRows(_ context.Context, request DocumentationFactoryProductionSourceOODReadRequest) (DocumentationFactoryProductionSourceOODCurrentEvidenceRows, error) {
	s.calls++
	s.request = request
	if s.after != nil {
		s.after()
	}
	return s.rows, s.err
}

func productionSourceOODCurrentRows(request DocumentationFactoryProductionSourceVerificationRequest) DocumentationFactoryProductionSourceOODCurrentEvidenceRows {
	proof := productionSourceOODEligibilityProof()
	receipt, batch, closure, closureHash, certificateHash := productionSourceOODCurrentOpaqueProofs(proof.OrganizationID, proof.VerificationCertificateID)
	proof.ClosureSHA256 = closureHash
	proof.VerificationCertificateSHA256 = certificateHash
	proof.FetchBatchManifestRootSHA256 = productionSourceOODDigest("receipt-manifest")
	identity := request.EvidenceIdentities[0]
	return DocumentationFactoryProductionSourceOODCurrentEvidenceRows{
		CurrentGeneration: productionSourceOwnerObservation(request),
		Eligibility:       proof,
		Snapshot: DocumentationFactoryProductionSourceOODSnapshotRow{
			OrganizationID: proof.OrganizationID, SnapshotID: proof.SnapshotID, SnapshotKind: proof.SnapshotKind, HeadGeneration: proof.SnapshotHeadGeneration, State: proof.SnapshotState, Status: proof.SnapshotStatus,
			SourceSetSHA256: proof.SourceSetSHA256, ClosureSHA256: proof.ClosureSHA256, VerificationCertificateID: proof.VerificationCertificateID, VerificationCertificateSHA256: proof.VerificationCertificateSHA256,
			MaterializationRunID: "123e4567-e89b-12d3-a456-426614174004", MaterializationProfileID: proof.MaterializationProfileID, MaterializationProfileVersion: proof.MaterializationProfileVersion, MaterializationProfileSHA256: proof.MaterializationProfileSHA256,
			ReceiptManifestRootSHA256: proof.ExternalReceiptManifestRootSHA256, ReceiptCount: 1,
		},
		Run: DocumentationFactoryProductionSourceOODMaterializationRunRow{
			OrganizationID: proof.OrganizationID, MaterializationRunID: "123e4567-e89b-12d3-a456-426614174004", TargetSnapshotID: proof.SnapshotID, State: "sealed",
			SourceSetSHA256: proof.SourceSetSHA256, ClosureSHA256: proof.ClosureSHA256, VerificationCertificateID: proof.VerificationCertificateID, VerificationCertificateSHA256: proof.VerificationCertificateSHA256,
			MaterializationProfileID: proof.MaterializationProfileID, MaterializationProfileVersion: proof.MaterializationProfileVersion, MaterializationProfileSHA256: proof.MaterializationProfileSHA256,
		},
		VerifiedClosure: closure, VerifiedBatches: []oodevidence.VerifiedBatchV8{batch},
		Bindings: []DocumentationFactoryProductionSourceOODEvidenceBindingRow{{
			Identity: identity, EvidenceIdentitySHA256: receipt.EvidenceIdentityHash, ReceiptID: receipt.ReceiptID, ReceiptSHA256: receipt.RedactedTransportEvidenceDigest, FetchBatchID: receipt.FetchBatchID,
			FetchBatchCertificateID: "123e4567-e89b-12d3-a456-426614174003", FetchBatchCertificateSHA256: productionSourceOODDigest("batch-certificate"), ArchiveBindingSHA256: proof.ArchiveBindingManifestRootSHA256,
			RelationshipEvidenceSHA256: strings.Repeat("b", 64), LocatorManifestSHA256: strings.Repeat("c", 64), ExternalCurrentValidityReference: proof.ExternalCurrentValidityResultReference, ExternalCurrentValiditySHA256: proof.ExternalCurrentValidityResultSHA256,
		}},
	}
}

func productionSourceOODCurrentOpaqueProofs(org, certificateID string) (oodevidence.ReceiptV8, oodevidence.VerifiedBatchV8, oodevidence.VerifiedClosureV8, string, string) {
	r := productionSourceOODReceipt()
	r.OrganizationID = org
	digest, err := oodevidence.ReceiptDigestV8(r)
	if err != nil {
		panic(err)
	}
	r.RedactedTransportEvidenceDigest = digest
	b := oodevidence.BatchV8{OrganizationID: r.OrganizationID, FetchBatchID: r.FetchBatchID, SourceAuthorityBindingID: r.SourceAuthorityBindingID, SourceAuthorityBindingDigest: r.SourceAuthorityBindingDigest, RepresentationDeclarationID: r.RepresentationDeclarationID, RepresentationDeclarationDigest: r.RepresentationDeclarationDigest, BatchReceiptManifestRootHash: productionSourceOODDigest("receipt-manifest"), TotalReceiptCount: 1, ComponentReceiptCount: 1, CompletenessEvidenceReceiptCount: 1, ExpectedComponentCount: ptrInt64(1), CompletenessBasisKind: "source_declared_total", CompletenessEvidenceRef: "https://example.test/doc", CompletenessEvidenceIdentityHash: r.EvidenceIdentityHash, CompletenessEvidenceContentHashAlgorithm: r.SourceContentHashAlgorithm, CompletenessEvidenceContentHashProfile: r.SourceContentHashProfile, CompletenessEvidenceContentHash: r.SourceContentHash, CompletenessEvidenceReceiptID: r.ReceiptID, CompletenessEvidenceArchiveAuthorityID: r.EvidenceArchiveAuthorityID, CompletenessEvidenceArchiveRecordID: r.EvidenceArchiveRecordID, CompletenessEvidenceArchiveRecordDigest: r.EvidenceArchiveRecordDigest, CompletenessEvidenceSelectorKind: "whole_evidence_body", CompletenessEvidenceSelectorValue: "$", VerifiedCompletenessClaimDigest: productionSourceOODDigest("claim"), CompletenessProfileRef: "profile/v1", CompletenessProfileDigest: productionSourceOODDigest("profile"), SealedAt: time.Unix(2, 0).UTC()}
	b.CompletenessEvidenceDigest, err = oodevidence.CompletenessEvidenceDigestV8(b)
	if err != nil {
		panic(err)
	}
	batch, err := oodevidence.VerifyBatchV8(context.Background(), b, []oodevidence.ReceiptV8{r}, oodevidence.ReceiptManifestNode{NodeHash: b.BatchReceiptManifestRootHash, OrganizationID: r.OrganizationID, ManifestKind: "fetch_batch_receipt", NodeKind: "leaf", Sealed: true, EntryCount: 1, TransitiveMemberCount: 1, Members: []oodevidence.ReceiptManifestMember{{ReceiptID: r.ReceiptID, MemberHash: digest}}}, productionSourceOODFixtureAuthority{})
	if err != nil {
		panic(err)
	}
	roots := map[string]oodevidence.ClosureRoot{}
	for _, name := range []string{"source", "object", "symbol", "edge", "api_property", "graph_fact_locator", "receipt", "structural_projection", "violation"} {
		roots[name] = oodevidence.ClosureRoot{Hash: productionSourceOODDigest(name), Count: 0}
	}
	roots["receipt"] = oodevidence.ClosureRoot{Hash: productionSourceOODDigest("receipt-root"), Count: 1}
	c := oodevidence.ClosureCertificateV8{OrganizationID: org, MaterializationRunID: productionSourceOODID(), SnapshotKind: "provider_documentation", SourceSetHash: productionSourceOODDigest("source-set"), Roots: roots, RelationshipIdentitySetHash: productionSourceOODDigest("relationships"), SourceAuthorityIdentitySetHash: productionSourceOODDigest("authorities"), CompletenessIdentitySetHash: productionSourceOODDigest("complete"), PermissionPolicyIdentitySetHash: productionSourceOODDigest("permission"), ArchiveBindingIdentitySetHash: productionSourceOODDigest("archive-bindings"), ProfileIdentitySetHash: productionSourceOODDigest("profiles"), ExternalSourceReceiptEligibilitySetHash: productionSourceOODDigest("eligible"), MaterializationProfileID: productionSourceOODID(), MaterializationProfileVersion: "v1", MaterializationProfileDigest: productionSourceOODDigest("materialization"), PublicationBudgetProfileRef: "budget/v1", PublicationBudgetProfileDigest: productionSourceOODDigest("budget"), ManifestHashAlgorithm: "sha256", ManifestHashProfile: "manifest", ManifestHashContractDigest: productionSourceOODDigest("manifest-contract"), ClosureHashAlgorithm: "sha256", ClosureHashProfile: "closure", ClosureHashContractDigest: productionSourceOODDigest("closure-contract"), VerifierCapabilityName: "verifier", VerifierCapabilityVersion: "v1", VerifierCapabilityDigest: productionSourceOODDigest("verifier"), VerificationPolicyRef: "policy/v1", VerificationPolicyDigest: productionSourceOODDigest("verify-policy"), VerificationCertificateID: certificateID, AttestationAuthorityID: productionSourceOODID(), AttestationRef: "attestation/v1", AttestationDigest: productionSourceOODDigest("attestation"), AttestationProfile: "profile/v1"}
	c.ClosureHash, err = oodevidence.ClosureHashV8(c)
	if err != nil {
		panic(err)
	}
	c.VerificationCertificateHash, err = oodevidence.CertificateHashV8(c)
	if err != nil {
		panic(err)
	}
	closure, err := oodevidence.VerifyClosureV8(context.Background(), c, productionSourceOODFixtureAuthority{})
	if err != nil {
		panic(err)
	}
	return r, batch, closure, c.ClosureHash, c.VerificationCertificateHash
}

func TestProductionSourceOODCurrentReaderClosesExactRows(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	strong := &productionSourceOODStrongReaderStub{rows: productionSourceOODCurrentRows(request)}
	authority, err := NewDocumentationFactoryProductionSourceOODCurrentReader(productionSourceOwnerBindingExpectation(), strong)
	if err != nil {
		t.Fatal(err)
	}
	got, err := authority.ReadCurrentEligibleProviderEvidence(context.Background(), DocumentationFactoryProductionSourceOODReadRequest{Expected: productionSourceOwnerBindingExpectation(), Request: request})
	if err != nil {
		t.Fatal(err)
	}
	if strong.calls != 1 || !reflect.DeepEqual(strong.request.Expected, productionSourceOwnerBindingExpectation()) || !reflect.DeepEqual(strong.request.Request, request) || !reflect.DeepEqual(got.CurrentGeneration, strong.rows.CurrentGeneration) {
		t.Fatalf("strong reader did not receive/return exact protected rows: calls=%d request=%+v got=%+v", strong.calls, strong.request, got)
	}
	verifier, err := NewDocumentationFactoryProductionSourceOODCurrentVerifier(productionSourceOwnerBindingExpectation(), strong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyDocumentationFactoryProductionSourcePackage(context.Background(), request); err != nil {
		t.Fatalf("composed strong OOD verifier refused exact rows: %v", err)
	}
}

func TestProductionSourceOODCurrentReaderRefusesCrossRowSubstitution(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	for _, testCase := range []struct {
		name   string
		mutate func(*DocumentationFactoryProductionSourceOODCurrentEvidenceRows)
		want   string
	}{
		{"nonsealed snapshot", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) { v.Snapshot.State = "candidate" }, "snapshot row"},
		{"historical snapshot", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) { v.Snapshot.Status = "superseded" }, "snapshot row"},
		{"wrong snapshot profile", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) {
			v.Snapshot.MaterializationProfileSHA256 = strings.Repeat("0", 64)
		}, "snapshot row"},
		{"wrong run target", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) {
			v.Run.TargetSnapshotID = "123e4567-e89b-12d3-a456-426614174099"
		}, "materialization run"},
		{"wrong run certificate", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) {
			v.Run.VerificationCertificateSHA256 = strings.Repeat("0", 64)
		}, "materialization run"},
		{"missing binding", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) { v.Bindings = nil }, "selected evidence bindings"},
		{"foreign identity", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) {
			v.Bindings[0].Identity.CarrierID = "carrier.other"
		}, "unrequested"},
		{"missing per-batch certificate", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) {
			v.Bindings[0].FetchBatchCertificateSHA256 = ""
		}, "fetch_batch_certificate_sha256"},
		{"valid but substituted currentness", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) {
			v.Bindings[0].ExternalCurrentValiditySHA256 = strings.Repeat("0", 64)
		}, "receipt/batch"},
		{"wrong batch cardinality", func(v *DocumentationFactoryProductionSourceOODCurrentEvidenceRows) { v.Eligibility.FetchBatchCount = 2 }, "batch count"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			rows := productionSourceOODCurrentRows(request)
			testCase.mutate(&rows)
			strong := &productionSourceOODStrongReaderStub{rows: rows}
			authority, err := NewDocumentationFactoryProductionSourceOODCurrentReader(productionSourceOwnerBindingExpectation(), strong)
			if err != nil {
				t.Fatal(err)
			}
			_, err = authority.ReadCurrentEligibleProviderEvidence(context.Background(), DocumentationFactoryProductionSourceOODReadRequest{Expected: productionSourceOwnerBindingExpectation(), Request: request})
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("substituted rows error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestProductionSourceOODCurrentReaderRefusesNilCanceledAndForeignSelectionBeforeStrongRead(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	if reader, err := NewDocumentationFactoryProductionSourceOODCurrentReader(productionSourceOwnerBindingExpectation(), nil); err == nil || reader != nil {
		t.Fatalf("nil protected strong reader=%v err=%v", reader, err)
	}
	strong := &productionSourceOODStrongReaderStub{rows: productionSourceOODCurrentRows(request)}
	authority, err := NewDocumentationFactoryProductionSourceOODCurrentReader(productionSourceOwnerBindingExpectation(), strong)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := authority.ReadCurrentEligibleProviderEvidence(ctx, DocumentationFactoryProductionSourceOODReadRequest{Expected: productionSourceOwnerBindingExpectation(), Request: request}); err == nil {
		t.Fatal("cancelled context accepted")
	}
	foreign := productionSourceOwnerBindingExpectation()
	foreign.Provider = "another_provider"
	if _, err := authority.ReadCurrentEligibleProviderEvidence(context.Background(), DocumentationFactoryProductionSourceOODReadRequest{Expected: foreign, Request: request}); err == nil || !strings.Contains(err.Error(), "boot-selected") {
		t.Fatalf("foreign expectation error = %v", err)
	}
	if strong.calls != 0 {
		t.Fatalf("strong reader invoked before cancellation/foreign boot selection was rejected: %d", strong.calls)
	}
}

func TestProductionSourceOODCurrentReaderRechecksContextAfterProtectedRead(t *testing.T) {
	request := productionSourceOwnerRequestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	strong := &productionSourceOODStrongReaderStub{rows: productionSourceOODCurrentRows(request), after: cancel}
	authority, err := NewDocumentationFactoryProductionSourceOODCurrentReader(productionSourceOwnerBindingExpectation(), strong)
	if err != nil {
		t.Fatal(err)
	}
	_, err = authority.ReadCurrentEligibleProviderEvidence(ctx, DocumentationFactoryProductionSourceOODReadRequest{Expected: productionSourceOwnerBindingExpectation(), Request: request})
	if err == nil || strong.calls != 1 {
		t.Fatalf("post-read cancellation error=%v calls=%d", err, strong.calls)
	}
}
