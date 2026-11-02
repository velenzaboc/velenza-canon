package oodevidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type rosterAuthority struct {
	calls int
	want  [][]byte
}

func (a *rosterAuthority) VerifyCompleteManifestClosure(context.Context, ClosureCertificateV8) error {
	return nil
}
func (a *rosterAuthority) VerifyClosureAttestation(context.Context, ClosureCertificateV8) error {
	return nil
}
func (a *rosterAuthority) VerifyCompletePublicationRoster(_ context.Context, _ VerifiedClosureV8, got [][]byte) error {
	a.calls++
	if len(got) != len(a.want) || string(got[0]) != string(a.want[0]) {
		return errRoster
	}
	return nil
}

var errRoster = &rosterError{}

type rosterError struct{}

func (*rosterError) Error() string { return "roster mismatch" }
func rosterHash(s string) string   { x := sha256.Sum256([]byte(s)); return hex.EncodeToString(x[:]) }

func verifiedRosterClosure(t *testing.T, a *rosterAuthority) VerifiedClosureV8 {
	t.Helper()
	roots := map[string]ClosureRoot{}
	for _, n := range closureRootFields {
		roots[n] = ClosureRoot{Hash: rosterHash(n), Count: 0}
	}
	c := ClosureCertificateV8{OrganizationID: uuid.NewString(), MaterializationRunID: uuid.NewString(), SnapshotKind: "provider_documentation", SourceSetHash: rosterHash("sources"), Roots: roots, RelationshipIdentitySetHash: rosterHash("relationships"), SourceAuthorityIdentitySetHash: rosterHash("authorities"), CompletenessIdentitySetHash: rosterHash("complete"), PermissionPolicyIdentitySetHash: rosterHash("policy"), ArchiveBindingIdentitySetHash: rosterHash("archive"), ProfileIdentitySetHash: rosterHash("profiles"), ExternalSourceReceiptEligibilitySetHash: rosterHash("eligible"), MaterializationProfileID: uuid.NewString(), MaterializationProfileVersion: "v1", MaterializationProfileDigest: rosterHash("materialization"), PublicationBudgetProfileRef: "budget/v1", PublicationBudgetProfileDigest: rosterHash("budget"), ManifestHashAlgorithm: "sha256", ManifestHashProfile: "manifest", ManifestHashContractDigest: rosterHash("manifest-contract"), ClosureHashAlgorithm: "sha256", ClosureHashProfile: "closure", ClosureHashContractDigest: rosterHash("closure-contract"), VerifierCapabilityName: "verifier", VerifierCapabilityVersion: "v1", VerifierCapabilityDigest: rosterHash("verifier"), VerificationPolicyRef: "policy/v1", VerificationPolicyDigest: rosterHash("policy-v"), VerificationCertificateID: uuid.NewString(), AttestationAuthorityID: uuid.NewString(), AttestationRef: "attestation/v1", AttestationDigest: rosterHash("attestation"), AttestationProfile: "profile/v1"}
	var err error
	c.ClosureHash, err = ClosureHashV8(c)
	if err != nil {
		t.Fatal(err)
	}
	c.VerificationCertificateHash, err = CertificateHashV8(c)
	if err != nil {
		t.Fatal(err)
	}
	v, err := VerifyClosureV8(context.Background(), c, a)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifiedPublicationRosterBindsEveryExactRowToClosure(t *testing.T) {
	a := &rosterAuthority{want: [][]byte{[]byte("certificate"), []byte("manifest"), []byte("property")}}
	closure := verifiedRosterClosure(t, a)
	v, err := VerifyPublicationRosterV8(context.Background(), closure, a.want, a)
	if err != nil {
		t.Fatal(err)
	}
	if a.calls != 1 || !v.MatchesCanonicalRows(a.want) {
		t.Fatal("complete roster was not retained as opaque proof")
	}
	for _, changed := range [][][]byte{{[]byte("certificate"), []byte("manifest"), []byte("property-x")}, {[]byte("certificate"), []byte("manifest")}, {[]byte("certificate"), []byte("manifest"), []byte("property"), []byte("extra")}} {
		if v.MatchesCanonicalRows(changed) {
			t.Fatal("row substitution/cardinality mutation accepted")
		}
	}
	if _, err := VerifyPublicationRosterV8(context.Background(), closure, nil, a); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("empty roster err=%v", err)
	}
}
