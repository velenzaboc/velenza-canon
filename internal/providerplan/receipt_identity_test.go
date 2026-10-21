package providerplan

import (
	"bytes"
	"strings"
	"testing"
)

func TestTopLevelReceiptIdentityIsDeterministicAndExcludesOnlySelfHash(t *testing.T) {
	receipt := receiptIdentityFixture()
	first, err := sealReceipt(receipt)
	if err != nil {
		t.Fatalf("seal first receipt: %v", err)
	}
	second, err := sealReceipt(receipt)
	if err != nil {
		t.Fatalf("seal second receipt: %v", err)
	}
	if first.ReceiptSHA256 != second.ReceiptSHA256 || !isLowerSHA256(first.ReceiptSHA256) {
		t.Fatalf("receipt identity is not deterministic lowercase SHA-256: first=%q second=%q", first.ReceiptSHA256, second.ReceiptSHA256)
	}
	if err := validateReceiptIdentity(first); err != nil {
		t.Fatalf("validate sealed receipt: %v", err)
	}

	identityRaw, err := canonicalReceiptIdentity(first)
	if err != nil {
		t.Fatalf("canonical receipt identity: %v", err)
	}
	if bytes.Contains(identityRaw, []byte(`"receipt_sha256"`)) {
		t.Fatalf("canonical receipt identity includes its self-hash field: %s", identityRaw)
	}

	differentSelfHash := first
	differentSelfHash.ReceiptSHA256 = strings.Repeat("f", 64)
	firstIdentity, err := receiptIdentitySHA256(first)
	if err != nil {
		t.Fatalf("hash first receipt identity: %v", err)
	}
	secondIdentity, err := receiptIdentitySHA256(differentSelfHash)
	if err != nil {
		t.Fatalf("hash receipt identity with different self-hash: %v", err)
	}
	if firstIdentity != secondIdentity || firstIdentity != first.ReceiptSHA256 {
		t.Fatalf("self-hash changed receipt identity: sealed=%q first=%q second=%q", first.ReceiptSHA256, firstIdentity, secondIdentity)
	}
}

func TestTopLevelReceiptIdentityRejectsMutationAndMalformedHash(t *testing.T) {
	sealed, err := sealReceipt(receiptIdentityFixture())
	if err != nil {
		t.Fatalf("seal receipt: %v", err)
	}

	mutated := sealed
	mutated.CanonicalAdmissionAuthorizationRule += ";mutated"
	if err := validateReceiptIdentity(mutated); err == nil || !strings.Contains(err.Error(), "does not match canonical receipt identity") {
		t.Fatalf("mutated receipt validation error = %v, want canonical identity mismatch", err)
	}

	malformed := sealed
	malformed.ReceiptSHA256 = strings.Repeat("A", 64)
	if err := validateReceiptIdentity(malformed); err == nil || !strings.Contains(err.Error(), "lowercase SHA-256") {
		t.Fatalf("malformed receipt hash validation error = %v, want lowercase SHA-256 rejection", err)
	}
}

func TestTopLevelReceiptIdentityBindsDocumentationDerivationClosure(t *testing.T) {
	sealed, err := sealReceipt(receiptIdentityFixture())
	if err != nil {
		t.Fatalf("seal receipt: %v", err)
	}
	const derivationScope = "offline_exact_evidence_deterministic_documentation_derivation_and_structural_plan_preflight"
	if sealed.ReceiptVersion != "9" || sealed.Scope != derivationScope {
		t.Fatalf("receipt authority coordinate = version %q scope %q, want version 9 scope %q", sealed.ReceiptVersion, sealed.Scope, derivationScope)
	}
	if err := validateReceiptIdentity(sealed); err != nil {
		t.Fatalf("validate canonical receipt v%s: %v", receiptVersion, err)
	}

	mutations := []struct {
		name   string
		mutate func(*Receipt)
	}{
		{
			name: "documentation derivation closure proof digest",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationDerivationClosureProofSHA256 = sha256Hex([]byte("mutated documentation derivation closure proof"))
			},
		},
		{
			name: "documentation derivation profile artifact digest",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationDerivationProfileArtifactSHA256 = sha256Hex([]byte("mutated documentation derivation profile artifact"))
			},
		},
		{
			name: "source classification proof digest",
			mutate: func(receipt *Receipt) {
				receipt.SourceClassificationProofSHA256 = sha256Hex([]byte("mutated source classification proof"))
			},
		},
		{
			name: "documentation derivation profile page-set root",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationDerivationProfilePageSetRootSHA256 = sha256Hex([]byte("mutated documentation derivation profile page-set root"))
			},
		},
		{
			name: "documentation derivation profile result root",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationDerivationProfileResultRootSHA256 = sha256Hex([]byte("mutated documentation derivation profile result root"))
			},
		},
		{
			name: "documentation target materialization root",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationTargetMaterializationRootSHA256 = sha256Hex([]byte("mutated documentation target materialization root"))
			},
		},
		{
			name: "documentation target binding roster root",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationTargetBindingRosterRootSHA256 = sha256Hex([]byte("mutated documentation target binding roster root"))
			},
		},
		{
			name: "documentation derivation profile count",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationDerivationProfileCount++
			},
		},
		{
			name: "documentation derivation outcome count",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationDerivationOutcomeCount++
			},
		},
		{
			name: "documentation-derived fact count",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationDerivedFactCount++
			},
		},
		{
			name: "documentation derivation page count",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationDerivationPageCount++
			},
		},
		{
			name: "documentation whole-row binding count",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationWholeRowBindingCount++
			},
		},
		{
			name: "documentation row-member binding count",
			mutate: func(receipt *Receipt) {
				receipt.DocumentationRowMemberBindingCount++
			},
		},
		{
			name: "receipt scope",
			mutate: func(receipt *Receipt) {
				receipt.Scope += "_mutated"
			},
		},
		{
			name: "receipt version",
			mutate: func(receipt *Receipt) {
				receipt.ReceiptVersion = "8"
			},
		},
		{
			name: "structured JSON admission limit",
			mutate: func(receipt *Receipt) {
				receipt.ProviderInputAdmissionLimits.StructuredJSONRowsPerCorpus++
			},
		},
		{
			name: "structured JSON admission actual",
			mutate: func(receipt *Receipt) {
				receipt.ProviderInputAdmissionActuals.StructuredJSONNodeCount++
			},
		},
		{
			name: "resident snapshot peak actual",
			mutate: func(receipt *Receipt) {
				receipt.ProviderInputAdmissionActuals.PeakResidentSnapshotBytes++
			},
		},
	}

	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			mutated := sealed
			mutation.mutate(&mutated)
			if err := validateReceiptIdentity(mutated); err == nil || !strings.Contains(err.Error(), "does not match canonical receipt identity") {
				t.Fatalf("mutated receipt validation error = %v, want canonical identity mismatch", err)
			}
		})
	}
}

func receiptIdentityFixture() Receipt {
	return Receipt{
		ReceiptKind:              receiptKind,
		ReceiptVersion:           receiptVersion,
		Result:                   "pass",
		Scope:                    "offline_exact_evidence_deterministic_documentation_derivation_and_structural_plan_preflight",
		Provider:                 "fixture_provider",
		EvidenceManifestSHA256:   []string{sha256Hex([]byte("fixture evidence"))},
		DependencyArtifactSHA256: []string{sha256Hex([]byte("fixture dependency"))},
		DocumentationDerivationClosureProofSHA256:       sha256Hex([]byte("fixture documentation derivation closure proof")),
		DocumentationDerivationProfileArtifactSHA256:    sha256Hex([]byte("fixture documentation derivation profile artifact")),
		SourceClassificationProofSHA256:                 sha256Hex([]byte("fixture source classification proof")),
		DocumentationDerivationProfilePageSetRootSHA256: sha256Hex([]byte("fixture documentation derivation profile page-set root")),
		DocumentationDerivationProfileResultRootSHA256:  sha256Hex([]byte("fixture documentation derivation profile result root")),
		DocumentationTargetMaterializationRootSHA256:    sha256Hex([]byte("fixture documentation target materialization root")),
		DocumentationTargetBindingRosterRootSHA256:      sha256Hex([]byte("fixture documentation target binding roster root")),
		DocumentationDerivationProfileCount:             2,
		DocumentationDerivationOutcomeCount:             7,
		DocumentationDerivedFactCount:                   5,
		DocumentationDerivationPageCount:                4,
		DocumentationWholeRowBindingCount:               3,
		DocumentationRowMemberBindingCount:              2,
		AllowedAPIElementRoleRegistry:                   []string{"operation", "resource"},
		MaterializedAPIElementRoles:                     []string{"operation"},
		CanonicalAdmissionAuthorized:                    false,
		CanonicalAdmissionAuthorizationRule:             "fixture_preflight_never_authorizes_admission",
	}
}
