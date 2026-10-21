package providerplan

import (
	"strings"
	"testing"
)

func sealedInputResourceForTest(t *testing.T, kind, coordinate string, bytes int64) providerInputAdmissionResourceReceipt {
	t.Helper()
	digest := sha256Hex([]byte(coordinate))
	resource := providerInputAdmissionResourceReceipt{
		ResourceKind: kind, StableCoordinate: coordinate, ContentSHA256: digest, ContentBytes: bytes,
	}
	if kind == providerInputAdmissionResourceKindCarrier {
		resource.DecodedContentSHA256 = sha256Hex([]byte("decoded-" + coordinate))
		resource.DecodedContentBytes = 1
	}
	sealed, err := sealProviderInputAdmissionResource(resource)
	if err != nil {
		t.Fatalf("seal %s: %v", kind, err)
	}
	return sealed
}

func TestProviderInputAdmissionLimitRelationshipsFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*providerInputAdmissionLimits)
	}{
		{"fixed parser profile", func(v *providerInputAdmissionLimits) { v.StructuredJSONNestingDepth-- }},
		{"manifest file corpus", func(v *providerInputAdmissionLimits) {
			v.EvidenceManifestBytesPerCorpus = v.EvidenceManifestBytesPerFile - 1
		}},
		{"body file corpus", func(v *providerInputAdmissionLimits) { v.EvidenceBodyBytesPerCorpus = v.EvidenceBodyBytesPerFile - 1 }},
		{"carrier file corpus", func(v *providerInputAdmissionLimits) {
			v.EvidenceCarrierBytesPerCorpus = v.EvidenceCarrierBytesPerFile - 1
		}},
		{"carrier whitespace", func(v *providerInputAdmissionLimits) {
			v.EvidenceCarrierOuterWhitespace = v.EvidenceCarrierBytesPerFile
		}},
		{"artifact file corpus", func(v *providerInputAdmissionLimits) {
			v.DependencyArtifactBytesPerCorpus = v.DependencyArtifactBytesPerFile - 1
		}},
		{"authority file corpus", func(v *providerInputAdmissionLimits) {
			v.VerificationAuthorityBytesPerCorpus = v.VerificationAuthorityBytesPerFile - 1
		}},
		{"stage manifest file corpus", func(v *providerInputAdmissionLimits) {
			v.StageInputManifestBytesPerCorpus = v.StageInputManifestBytesPerFile - 1
		}},
		{"stage file corpus", func(v *providerInputAdmissionLimits) {
			v.StageInputFileBytesPerCorpus = v.StageInputFileBytesPerFile - 1
		}},
		{"structured hierarchy", func(v *providerInputAdmissionLimits) {
			v.StructuredJSONRowsPerCorpus = v.StructuredJSONRowsPerArtifact - 1
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			limits := canonicalProviderInputAdmissionLimits
			tc.mutate(&limits)
			if err := validateProviderInputAdmissionLimits(limits); err == nil {
				t.Fatal("inconsistent input admission limits were accepted")
			}
		})
	}
}

func TestProviderInputAdmissionAccumulatorBoundaryState(t *testing.T) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	for _, kind := range []string{
		providerInputAdmissionResourceKindManifest,
		providerInputAdmissionResourceKindArtifact,
		providerInputAdmissionResourceKindAuthority,
		providerInputAdmissionResourceKindStageManifest,
		providerInputAdmissionResourceKindStageFile,
	} {
		if err := accumulator.preflightPathCount(kind, 0); err != nil {
			t.Fatalf("preflight %s: %v", kind, err)
		}
	}
	if err := accumulator.preflightPathCount("unknown", 0); err == nil {
		t.Fatal("unknown preflight kind was accepted")
	}
	accumulator.actuals.EvidenceManifestCount = 1
	accumulator.limits.EvidenceManifestCount = 1
	if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindManifest, 1); err == nil {
		t.Fatal("preflight ignored already-admitted resources")
	}
	accumulator.actuals = providerInputAdmissionActuals{}
	accumulator.limits.TotalResourceCount = 1
	if err := accumulator.preflightPathCount(providerInputAdmissionResourceKindManifest, 2); err == nil {
		t.Fatal("preflight ignored total resource limit")
	}

	accumulator = &providerInputAdmissionAccumulator{resources: []providerInputAdmissionResourceReceipt{
		{ResourceKind: providerInputAdmissionResourceKindManifest, StableCoordinate: "one", ResourceReceiptSHA256: strings.Repeat("a", 64)},
	}}
	accumulator.ensureDuplicateIndexes()
	if len(accumulator.resourceCoordinates) != 1 || len(accumulator.resourceReceipts) != 1 {
		t.Fatalf("rebuilt duplicate indexes = %d/%d", len(accumulator.resourceCoordinates), len(accumulator.resourceReceipts))
	}
	accumulator.ensureDuplicateIndexes()

	accumulator = newCanonicalProviderInputAdmissionAccumulator()
	accumulator.actuals.TotalResourceCount = 1
	if _, err := accumulator.seal(); err == nil {
		t.Fatal("receipt/accounting mismatch was sealed")
	}
	accumulator = newCanonicalProviderInputAdmissionAccumulator()
	accumulator.residentInputBytes = 1
	if _, err := accumulator.seal(); err == nil {
		t.Fatal("resident accounting mismatch was sealed")
	}
	empty := newCanonicalProviderInputAdmissionAccumulator()
	proof, err := empty.seal()
	if err != nil || !isLowerSHA256(proof.ProofSHA256) || !isLowerSHA256(proof.ResourceSetRootSHA256) {
		t.Fatalf("empty admission proof = %#v, %v", proof, err)
	}
	if err := validateProviderInputAdmissionProof(proof, nil); err != nil {
		t.Fatalf("validate empty admission proof: %v", err)
	}

	if err := empty.checkResidentInputBytes(-1); err == nil {
		t.Fatal("negative resident allocation was accepted")
	}
	if err := empty.retainResidentInputBytes(1); err != nil || empty.residentInputBytes != 1 || empty.residentInputPeak != 1 {
		t.Fatalf("retain resident byte = %d/%d, %v", empty.residentInputBytes, empty.residentInputPeak, err)
	}
	if err := empty.retainResidentInputBytes(0); err != nil {
		t.Fatal(err)
	}
	if !equalProviderInputBytes([]byte("same"), []byte("same")) || equalProviderInputBytes([]byte("a"), []byte("ab")) || equalProviderInputBytes([]byte("a"), []byte("b")) {
		t.Fatal("provider input byte equality drifted")
	}
}

func providerInputAdmissionResourceKindsForTest() []string {
	return []string{
		providerInputAdmissionResourceKindManifest,
		providerInputAdmissionResourceKindBody,
		providerInputAdmissionResourceKindCarrier,
		providerInputAdmissionResourceKindArtifact,
		providerInputAdmissionResourceKindAuthority,
		providerInputAdmissionResourceKindStageManifest,
		providerInputAdmissionResourceKindStageFile,
	}
}

func providerInputAdmissionResourceLimitForTest(limits providerInputAdmissionLimits, kind string) int64 {
	switch kind {
	case providerInputAdmissionResourceKindManifest:
		return limits.EvidenceManifestBytesPerFile
	case providerInputAdmissionResourceKindBody:
		return limits.EvidenceBodyBytesPerFile
	case providerInputAdmissionResourceKindCarrier:
		return limits.EvidenceCarrierBytesPerFile
	case providerInputAdmissionResourceKindArtifact:
		return limits.DependencyArtifactBytesPerFile
	case providerInputAdmissionResourceKindAuthority:
		return limits.VerificationAuthorityBytesPerFile
	case providerInputAdmissionResourceKindStageManifest:
		return limits.StageInputManifestBytesPerFile
	case providerInputAdmissionResourceKindStageFile:
		return limits.StageInputFileBytesPerFile
	default:
		return 0
	}
}

func TestProviderInputAdmissionReceiptAndActualBounds(t *testing.T) {
	digest := strings.Repeat("a", 64)
	if _, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{}); err == nil {
		t.Fatal("incomplete resource was sealed")
	}
	if _, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{ResourceKind: "unknown", StableCoordinate: "x", ContentSHA256: digest}); err == nil {
		t.Fatal("unknown resource kind was sealed")
	}
	carrier, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{
		ResourceKind: providerInputAdmissionResourceKindCarrier, StableCoordinate: "carrier", ContentSHA256: digest,
		ContentBytes: 2, DecodedContentSHA256: digest, DecodedContentBytes: 1,
	})
	if err != nil || !isLowerSHA256(carrier.ResourceReceiptSHA256) {
		t.Fatalf("valid carrier seal = %#v, %v", carrier, err)
	}

	limits := canonicalProviderInputAdmissionLimits
	for _, kind := range providerInputAdmissionResourceKindsForTest() {
		resource := sealedInputResourceForTest(t, kind, "limit-"+kind, 1)
		if err := validateProviderInputAdmissionResourceAgainstLimits(resource, limits); err != nil {
			t.Fatalf("resource %s within limits: %v", kind, err)
		}
		resource.ContentBytes = providerInputAdmissionResourceLimitForTest(limits, kind) + 1
		if err := validateProviderInputAdmissionResourceAgainstLimits(resource, limits); err == nil {
			t.Fatalf("oversized %s resource was accepted", kind)
		}
	}
	if err := validateProviderInputAdmissionResourceAgainstLimits(providerInputAdmissionResourceReceipt{ResourceKind: "unknown"}, limits); err == nil {
		t.Fatal("unknown resource limit kind was accepted")
	}

	for name, actuals := range map[string]providerInputAdmissionActuals{
		"negative":        {EvidenceManifestCount: -1},
		"body pair":       {EvidenceBodyCount: 1},
		"count partition": {TotalResourceCount: 1},
		"byte partition":  {TotalResourceBytes: 1},
		"resident peak":   {ResidentSnapshotBytes: 2, PeakResidentSnapshotBytes: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateProviderInputAdmissionActuals(actuals, limits); err == nil {
				t.Fatal("inconsistent admission actuals were accepted")
			}
		})
	}
	if err := validateProviderInputAdmissionActuals(providerInputAdmissionActuals{}, limits); err != nil {
		t.Fatalf("empty actuals: %v", err)
	}
}

func TestProviderInputAdmissionResourceAccountingClosedSet(t *testing.T) {
	resources := make([]providerInputAdmissionResourceReceipt, 0, 7)
	for index, kind := range providerInputAdmissionResourceKindsForTest() {
		resources = append(resources, sealedInputResourceForTest(t, kind, kind+string(rune('a'+index)), 1))
	}
	actuals, err := providerInputAdmissionActualsFromResources(resources)
	if err != nil || actuals.TotalResourceCount != int64(len(resources)) || actuals.TotalResourceBytes != int64(len(resources)) {
		t.Fatalf("resource actuals = %#v, %v", actuals, err)
	}

	badDigest := append([]providerInputAdmissionResourceReceipt(nil), resources...)
	badDigest[0].ResourceReceiptSHA256 = strings.Repeat("0", 64)
	if _, err := providerInputAdmissionActualsFromResources(badDigest); err == nil {
		t.Fatal("invalid receipt self-digest was accepted")
	}
	duplicateReceipt := append([]providerInputAdmissionResourceReceipt(nil), resources...)
	duplicateReceipt = append(duplicateReceipt, resources[0])
	if _, err := providerInputAdmissionActualsFromResources(duplicateReceipt); err == nil {
		t.Fatal("duplicate receipt was accepted")
	}
	duplicateIdentity := append([]providerInputAdmissionResourceReceipt(nil), resources...)
	other := sealedInputResourceForTest(t, resources[0].ResourceKind, resources[0].StableCoordinate, 2)
	duplicateIdentity = append(duplicateIdentity, other)
	if _, err := providerInputAdmissionActualsFromResources(duplicateIdentity); err == nil {
		t.Fatal("duplicate resource identity was accepted")
	}
	unknown, _ := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{ResourceKind: providerInputAdmissionResourceKindManifest, StableCoordinate: "unknown", ContentSHA256: strings.Repeat("b", 64), ContentBytes: 1})
	unknown.ResourceKind = "unknown"
	if _, err := providerInputAdmissionActualsFromResources([]providerInputAdmissionResourceReceipt{unknown}); err == nil {
		t.Fatal("unknown accounting resource was accepted")
	}
}

func TestProviderInputAdmissionProofTamperBounds(t *testing.T) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	proof, err := accumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*providerInputAdmissionProof)
	}{
		{"identity", func(p *providerInputAdmissionProof) { p.Kind = "unknown" }},
		{"limits", func(p *providerInputAdmissionProof) { p.Limits.TotalResourceBytes = 0 }},
		{"actuals", func(p *providerInputAdmissionProof) { p.Actuals.TotalResourceCount = 1 }},
		{"resource root", func(p *providerInputAdmissionProof) { p.ResourceSetRootSHA256 = strings.Repeat("0", 64) }},
		{"proof digest", func(p *providerInputAdmissionProof) { p.ProofSHA256 = strings.Repeat("0", 64) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := proof
			tc.mutate(&candidate)
			if err := validateProviderInputAdmissionProof(candidate, nil); err == nil {
				t.Fatal("tampered provider input proof was accepted")
			}
		})
	}
	if _, err := canonicalProviderInputAdmissionJSON(make(chan int)); err == nil {
		t.Fatal("non-JSON admission identity was accepted")
	}
}

func TestProviderInputAdmissionEvidencePairDuplicates(t *testing.T) {
	body := sealedInputResourceForTest(t, providerInputAdmissionResourceKindBody, "same", 1)
	carrier := sealedInputResourceForTest(t, providerInputAdmissionResourceKindCarrier, "same", 1)
	carrier.DecodedContentSHA256 = body.ContentSHA256
	carrier.DecodedContentBytes = body.ContentBytes
	carrier, _ = sealProviderInputAdmissionResource(carrier)
	if err := validateProviderInputAdmissionEvidenceResourcePairs([]providerInputAdmissionResourceReceipt{body, carrier}); err != nil {
		t.Fatalf("valid body/carrier pair: %v", err)
	}
	if err := validateProviderInputAdmissionEvidenceResourcePairs([]providerInputAdmissionResourceReceipt{body, body}); err == nil {
		t.Fatal("duplicate evidence body was accepted")
	}
	if err := validateProviderInputAdmissionEvidenceResourcePairs([]providerInputAdmissionResourceReceipt{carrier, carrier}); err == nil {
		t.Fatal("duplicate evidence carrier was accepted")
	}
	if err := validateProviderInputAdmissionEvidenceResourcePairs([]providerInputAdmissionResourceReceipt{body}); err == nil {
		t.Fatal("unpaired evidence body was accepted")
	}
	wrongCarrier := carrier
	wrongCarrier.DecodedContentBytes++
	if err := validateProviderInputAdmissionEvidenceResourcePairs([]providerInputAdmissionResourceReceipt{body, wrongCarrier}); err == nil {
		t.Fatal("wrong decoded carrier tuple was accepted")
	}
}

func TestProviderInputAdmissionIndexAndAliasBounds(t *testing.T) {
	accumulator := &providerInputAdmissionAccumulator{}
	accumulator.ensurePhysicalSnapshotIndex()
	if accumulator.physicalSnapshots == nil || accumulator.residentContent == nil {
		t.Fatal("physical snapshot indexes were not initialized")
	}
	if accumulator.factorySnapshotAliasAuthorized("path", "kind") {
		t.Fatal("alias was authorized before mode enablement")
	}
	if err := accumulator.authorizeFactorySnapshotAlias("missing", "input", "kind"); err == nil {
		t.Fatal("alias authorization succeeded before enablement")
	}
	accumulator.enableFactorySnapshotAliases()
	if accumulator.authorizedAliases == nil {
		t.Fatal("factory alias index was not initialized")
	}
	if err := accumulator.authorizeFactorySnapshotAlias("missing", "input", "kind"); err == nil {
		t.Fatal("alias authorization succeeded without a physical snapshot")
	}
	if err := (*providerInputAdmissionAccumulator)(nil).revalidatePhysicalSnapshots(); err == nil {
		t.Fatal("nil physical snapshot accumulator was accepted")
	}
	if err := accumulator.revalidatePhysicalSnapshots(); err != nil {
		t.Fatalf("empty physical snapshot revalidation: %v", err)
	}
}

func TestVerificationAuthorityAdmissionBindingBounds(t *testing.T) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	roles := []string{verificationAuthorityRoleOODGraph, verificationAuthorityRoleGrandVision, verificationAuthorityRoleSourceRecord}
	items := make([]verificationAuthorityInputAdmissionItem, 0, len(roles))
	for _, role := range roles {
		raw := []byte("authority-" + role)
		resource := providerInputAdmissionResourceReceipt{
			ResourceKind:     providerInputAdmissionResourceKindAuthority,
			StableCoordinate: "verification_authority_input_v1|" + lengthPrefixedIdentityKey(role),
			ContentSHA256:    sha256Hex(raw), ContentBytes: int64(len(raw)),
		}
		if err := accumulator.reserve(resource.ResourceKind, resource.ContentBytes); err != nil {
			t.Fatal(err)
		}
		if err := accumulator.addResource(resource); err != nil {
			t.Fatal(err)
		}
		items = append(items, verificationAuthorityInputAdmissionItem{Role: role, Raw: raw, Resource: accumulator.resources[len(accumulator.resources)-1]})
	}
	proof, err := accumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	binding := verificationAuthorityInputAdmissionBinding{Items: items}
	if err := bindAndValidateVerificationAuthorityInputAdmission(&binding, proof, accumulator.resources); err != nil {
		t.Fatalf("valid authority admission binding: %v", err)
	}
	if binding.ProofSHA256 != proof.ProofSHA256 || !isLowerSHA256(binding.ResourceSetRootSHA256) || len(binding.resources()) != len(items) {
		t.Fatalf("authority binding was not sealed: %#v", binding)
	}
	if err := validateVerificationAuthorityExpectedPin(items[0], items[0].Resource.ContentSHA256); err != nil {
		t.Fatalf("valid authority pin: %v", err)
	}
	if err := validateVerificationAuthorityExpectedPin(items[0], "short"); err == nil {
		t.Fatal("malformed expected authority pin was accepted")
	}
	if err := validateVerificationAuthorityExpectedPin(items[0], strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong expected authority pin was accepted")
	}
	if err := bindAndValidateVerificationAuthorityInputAdmission(nil, proof, accumulator.resources); err == nil {
		t.Fatal("nil authority binding was accepted")
	}
	short := verificationAuthorityInputAdmissionBinding{Items: items[:1]}
	if err := bindAndValidateVerificationAuthorityInputAdmission(&short, proof, accumulator.resources); err == nil {
		t.Fatal("short authority roster was accepted")
	}
	wrongCount := append([]providerInputAdmissionResourceReceipt(nil), accumulator.resources[:2]...)
	if err := bindAndValidateVerificationAuthorityInputAdmission(&verificationAuthorityInputAdmissionBinding{Items: items}, proof, wrongCount); err == nil {
		t.Fatal("authority resource-count mismatch was accepted")
	}
	badRoleItems := append([]verificationAuthorityInputAdmissionItem(nil), items...)
	badRoleItems[0].Role = "unknown"
	if err := bindAndValidateVerificationAuthorityInputAdmission(&verificationAuthorityInputAdmissionBinding{Items: badRoleItems}, proof, accumulator.resources); err == nil {
		t.Fatal("unknown authority role was accepted")
	}
	duplicateItems := append([]verificationAuthorityInputAdmissionItem(nil), items...)
	duplicateItems[1] = duplicateItems[0]
	if err := bindAndValidateVerificationAuthorityInputAdmission(&verificationAuthorityInputAdmissionBinding{Items: duplicateItems}, proof, accumulator.resources); err == nil {
		t.Fatal("duplicate authority role was accepted")
	}
	wrongResourceItems := append([]verificationAuthorityInputAdmissionItem(nil), items...)
	wrongResourceItems[0].Resource.ContentBytes++
	if err := bindAndValidateVerificationAuthorityInputAdmission(&verificationAuthorityInputAdmissionBinding{Items: wrongResourceItems}, proof, accumulator.resources); err == nil {
		t.Fatal("authority/resource mismatch was accepted")
	}
	missingResourceItems := append([]verificationAuthorityInputAdmissionItem(nil), items...)
	missingResourceItems[0].Resource.ResourceReceiptSHA256 = strings.Repeat("0", 64)
	if err := bindAndValidateVerificationAuthorityInputAdmission(&verificationAuthorityInputAdmissionBinding{Items: missingResourceItems}, proof, accumulator.resources); err == nil {
		t.Fatal("authority absent from sealed resources was accepted")
	}
}

func TestProviderInputAdmissionDownstreamEmptyBindingBounds(t *testing.T) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	proof, err := accumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	evidence := loadedEvidence{Artifacts: map[string]artifactInput{}, MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{}}
	dependencies := map[string]artifactInput{}
	if err := bindAndValidateProviderInputAdmission(&evidence, dependencies, nil, nil, nil, proof, nil); err != nil {
		t.Fatalf("valid empty downstream binding: %v", err)
	}
	if err := validateEvidenceInputAdmissionBinding(evidence, proof); err != nil {
		t.Fatalf("valid empty evidence binding: %v", err)
	}
	if err := validateDependencyInputAdmissionBinding(dependencies, proof, nil); err != nil {
		t.Fatalf("valid empty dependency binding: %v", err)
	}
	if err := bindAndValidateProviderInputAdmission(nil, dependencies, nil, nil, nil, proof, nil); err == nil {
		t.Fatal("nil downstream evidence target was accepted")
	}
	wrongProof := proof
	wrongProof.ProofSHA256 = strings.Repeat("0", 64)
	if err := validateEvidenceInputAdmissionBinding(evidence, wrongProof); err == nil {
		t.Fatal("evidence proof mismatch was accepted")
	}
	nonEvidence := evidence
	nonEvidence.InputAdmissionResources = []providerInputAdmissionResourceReceipt{{ResourceKind: providerInputAdmissionResourceKindArtifact}}
	if err := validateEvidenceInputAdmissionBinding(nonEvidence, proof); err == nil {
		t.Fatal("non-evidence input resource was accepted")
	}
	duplicateResource := providerInputAdmissionResourceReceipt{ResourceKind: providerInputAdmissionResourceKindManifest, StableCoordinate: "same"}
	duplicated := evidence
	duplicated.InputAdmissionResources = []providerInputAdmissionResourceReceipt{duplicateResource, duplicateResource}
	if err := validateEvidenceInputAdmissionBinding(duplicated, proof); err == nil {
		t.Fatal("duplicate evidence input coordinate was accepted")
	}
	rosterMismatch := evidence
	rosterMismatch.InputAdmissionResources = []providerInputAdmissionResourceReceipt{{ResourceKind: providerInputAdmissionResourceKindManifest, StableCoordinate: "extra"}}
	if err := validateEvidenceInputAdmissionBinding(rosterMismatch, proof); err == nil {
		t.Fatal("evidence resource roster mismatch was accepted")
	}

	badPriorKind := sealedInputResourceForTest(t, providerInputAdmissionResourceKindManifest, "prior", 1)
	if err := bindAndValidateProviderInputAdmission(&evidence, dependencies, nil, nil, []providerInputAdmissionResourceReceipt{badPriorKind}, proof, nil); err == nil {
		t.Fatal("non-stage prior resource was accepted")
	}
	stagePrior := sealedInputResourceForTest(t, providerInputAdmissionResourceKindStageFile, "prior-stage", 1)
	if err := bindAndValidateProviderInputAdmission(&evidence, dependencies, nil, nil, []providerInputAdmissionResourceReceipt{stagePrior, stagePrior}, proof, nil); err == nil {
		t.Fatal("duplicate prior receipt was accepted")
	}
	if err := bindAndValidateProviderInputAdmission(&evidence, dependencies, nil, nil, []providerInputAdmissionResourceReceipt{stagePrior}, proof, nil); err == nil {
		t.Fatal("prior resource absent from sealed roster was accepted")
	}
}

func TestProviderInputAdmissionAccountingOverflowBranches(t *testing.T) {
	limits := canonicalProviderInputAdmissionLimits
	corpusLimit := func(kind string) int64 {
		switch kind {
		case providerInputAdmissionResourceKindManifest:
			return limits.EvidenceManifestBytesPerCorpus
		case providerInputAdmissionResourceKindBody:
			return limits.EvidenceBodyBytesPerCorpus
		case providerInputAdmissionResourceKindCarrier:
			return limits.EvidenceCarrierBytesPerCorpus
		case providerInputAdmissionResourceKindArtifact:
			return limits.DependencyArtifactBytesPerCorpus
		case providerInputAdmissionResourceKindAuthority:
			return limits.VerificationAuthorityBytesPerCorpus
		case providerInputAdmissionResourceKindStageManifest:
			return limits.StageInputManifestBytesPerCorpus
		case providerInputAdmissionResourceKindStageFile:
			return limits.StageInputFileBytesPerCorpus
		default:
			return 0
		}
	}
	for _, kind := range providerInputAdmissionResourceKindsForTest() {
		resource := sealedInputResourceForTest(t, kind, "overflow-"+kind, corpusLimit(kind)+1)
		if _, err := providerInputAdmissionActualsFromResources([]providerInputAdmissionResourceReceipt{resource}); err == nil {
			t.Fatalf("%s corpus accounting overflow was accepted", kind)
		}
	}
	resource := sealedInputResourceForTest(t, providerInputAdmissionResourceKindManifest, "total-overflow", limits.TotalResourceBytes+1)
	if _, err := providerInputAdmissionActualsFromResources([]providerInputAdmissionResourceReceipt{resource}); err == nil {
		t.Fatal("total accounting-domain overflow was accepted")
	}
	if _, err := expectedPaddedBase64Bytes(-1); err == nil {
		t.Fatal("negative decoded byte count was accepted")
	}
}

func TestProviderInputAdmissionResidualFailureBranches(t *testing.T) {
	limits := canonicalProviderInputAdmissionLimits
	limits.EvidenceCarrierBytesPerFile = limits.EvidenceCarrierOuterWhitespace
	if err := validateProviderInputAdmissionLimits(limits); err == nil {
		t.Fatal("carrier whitespace equal to the per-file limit was accepted")
	}

	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	accumulator.limits.TotalResourceCount = 1
	accumulator.actuals.TotalResourceCount = 1
	if err := accumulator.reserve(providerInputAdmissionResourceKindManifest, 0); err == nil {
		t.Fatal("reservation beyond the total resource count was accepted")
	}

	accumulator = newCanonicalProviderInputAdmissionAccumulator()
	if err := accumulator.addResource(providerInputAdmissionResourceReceipt{}); err == nil {
		t.Fatal("an incomplete resource was added")
	}
	manifest := sealedInputResourceForTest(t, providerInputAdmissionResourceKindManifest, "residual-manifest", 1)
	accumulator.resourceReceipts[manifest.ResourceReceiptSHA256] = struct{}{}
	if err := accumulator.addResource(manifest); err == nil {
		t.Fatal("a receipt already present in the duplicate index was added")
	}

	accumulator = newCanonicalProviderInputAdmissionAccumulator()
	accumulator.actuals.TotalResourceCount = 1
	accumulator.resources = []providerInputAdmissionResourceReceipt{{}}
	if _, err := accumulator.seal(); err == nil {
		t.Fatal("an invalid resource roster was sealed")
	}

	proofShape := providerInputAdmissionProof{
		Kind: providerInputAdmissionKind, Version: providerInputAdmissionVersion,
		Limits: canonicalProviderInputAdmissionLimits, ResourceSetRootSHA256: strings.Repeat("a", 64),
		Status: providerInputAdmissionStatusComplete, ProofSHA256: strings.Repeat("b", 64),
	}
	oversized := sealedInputResourceForTest(t, providerInputAdmissionResourceKindManifest, "oversized", canonicalProviderInputAdmissionLimits.EvidenceManifestBytesPerFile+1)
	if err := validateProviderInputAdmissionProof(proofShape, []providerInputAdmissionResourceReceipt{oversized}); err == nil {
		t.Fatal("a proof with an oversized resource was accepted")
	}
	body := sealedInputResourceForTest(t, providerInputAdmissionResourceKindBody, "unpaired", 1)
	if err := validateProviderInputAdmissionProof(proofShape, []providerInputAdmissionResourceReceipt{body}); err == nil {
		t.Fatal("a proof with an unpaired evidence body was accepted")
	}
	badReceipt := manifest
	badReceipt.ResourceReceiptSHA256 = strings.Repeat("0", 64)
	if err := validateProviderInputAdmissionProof(proofShape, []providerInputAdmissionResourceReceipt{badReceipt}); err == nil {
		t.Fatal("a proof with an invalid resource receipt was accepted")
	}
	badActuals := proofShape
	badActuals.Actuals.StructuredJSONRowCount = -1
	if err := validateProviderInputAdmissionProof(badActuals, nil); err == nil {
		t.Fatal("a proof with invalid structured accounting was accepted")
	}

	if _, err := readVerificationAuthorityWithAdmission("unused", "unknown", newCanonicalProviderInputAdmissionAccumulator()); err == nil {
		t.Fatal("an unregistered verification authority role was accepted")
	}

	emptyAccumulator := newCanonicalProviderInputAdmissionAccumulator()
	emptyProof, err := emptyAccumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	emptyEvidence := loadedEvidence{Artifacts: map[string]artifactInput{}, MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{}}
	invalidProof := emptyProof
	invalidProof.Kind = "unknown"
	if err := bindAndValidateProviderInputAdmission(&emptyEvidence, map[string]artifactInput{}, nil, nil, nil, invalidProof, nil); err == nil {
		t.Fatal("a downstream binding with an invalid proof was accepted")
	}
	nonEvidence := loadedEvidence{
		Artifacts: map[string]artifactInput{}, MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{},
		InputAdmissionResources: []providerInputAdmissionResourceReceipt{{ResourceKind: providerInputAdmissionResourceKindArtifact}},
	}
	if err := bindAndValidateProviderInputAdmission(&nonEvidence, map[string]artifactInput{}, nil, nil, nil, emptyProof, nil); err == nil {
		t.Fatal("a downstream binding with a non-evidence resource was accepted")
	}
	emptyEvidence = loadedEvidence{Artifacts: map[string]artifactInput{}, MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{}}
	if err := bindAndValidateProviderInputAdmission(&emptyEvidence, map[string]artifactInput{"missing": {}}, nil, nil, nil, emptyProof, nil); err == nil {
		t.Fatal("a downstream binding with a missing dependency resource was accepted")
	}
	emptyEvidence = loadedEvidence{Artifacts: map[string]artifactInput{}, MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{}}
	shortAuthority := &verificationAuthorityInputAdmissionBinding{Items: []verificationAuthorityInputAdmissionItem{{Role: verificationAuthorityRoleOODGraph}}}
	if err := bindAndValidateProviderInputAdmission(&emptyEvidence, map[string]artifactInput{}, shortAuthority, nil, nil, emptyProof, nil); err == nil {
		t.Fatal("a downstream binding with a short authority roster was accepted")
	}
	emptyEvidence = loadedEvidence{Artifacts: map[string]artifactInput{}, MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{}}
	shortStage := &stageCompileInputAdmissionBinding{Items: []stageCompileInputAdmissionItem{{}}}
	if err := bindAndValidateProviderInputAdmission(&emptyEvidence, map[string]artifactInput{}, nil, shortStage, nil, emptyProof, nil); err == nil {
		t.Fatal("a downstream binding with a short stage roster was accepted")
	}

	stageAccumulator := newCanonicalProviderInputAdmissionAccumulator()
	stageResource := sealedInputResourceForTest(t, providerInputAdmissionResourceKindStageFile, "unbound-stage", 1)
	if err := stageAccumulator.reserve(stageResource.ResourceKind, stageResource.ContentBytes); err != nil {
		t.Fatal(err)
	}
	if err := stageAccumulator.addResource(stageResource); err != nil {
		t.Fatal(err)
	}
	stageProof, err := stageAccumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	emptyEvidence = loadedEvidence{Artifacts: map[string]artifactInput{}, MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{}}
	if err := bindAndValidateProviderInputAdmission(&emptyEvidence, map[string]artifactInput{}, nil, nil, nil, stageProof, stageAccumulator.resources); err == nil {
		t.Fatal("an incomplete downstream resource roster was accepted")
	}
}

func TestProviderInputAdmissionResidualArtifactBindings(t *testing.T) {
	accumulator := newCanonicalProviderInputAdmissionAccumulator()
	proof, err := accumulator.seal()
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("manifest bytes")
	digest := sha256Hex(raw)
	resource, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{
		ResourceKind: providerInputAdmissionResourceKindManifest, StableCoordinate: "bound-manifest",
		ContentSHA256: digest, ContentBytes: int64(len(raw)),
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := artifactInput{Raw: raw, InputAdmissionProofSHA256: proof.ProofSHA256, InputAdmissionResource: resource}
	evidence := loadedEvidence{
		Artifacts: map[string]artifactInput{digest: artifact}, MetadataByCoordinate: map[evidenceSourceCoordinate]evidenceBodyMetadata{},
		InputAdmissionProof: proof, InputAdmissionResources: []providerInputAdmissionResourceReceipt{resource},
	}
	badArtifactEvidence := evidence
	badArtifact := artifact
	badArtifact.InputAdmissionProofSHA256 = ""
	badArtifactEvidence.Artifacts = map[string]artifactInput{digest: badArtifact}
	if err := validateEvidenceInputAdmissionBinding(badArtifactEvidence, proof); err == nil {
		t.Fatal("an evidence manifest with an invalid proof binding was accepted")
	}
	otherManifest := sealedInputResourceForTest(t, providerInputAdmissionResourceKindManifest, "other-manifest", 1)
	missingManifestEvidence := evidence
	missingManifestEvidence.InputAdmissionResources = []providerInputAdmissionResourceReceipt{otherManifest}
	if err := validateEvidenceInputAdmissionBinding(missingManifestEvidence, proof); err == nil {
		t.Fatal("an evidence manifest absent from its resource roster was accepted")
	}

	dependencyResource, err := sealProviderInputAdmissionResource(providerInputAdmissionResourceReceipt{
		ResourceKind: providerInputAdmissionResourceKindArtifact, StableCoordinate: "bound-dependency",
		ContentSHA256: digest, ContentBytes: int64(len(raw)),
	})
	if err != nil {
		t.Fatal(err)
	}
	dependency := artifactInput{Raw: raw, InputAdmissionProofSHA256: proof.ProofSHA256, InputAdmissionResource: dependencyResource}
	badDependency := dependency
	badDependency.InputAdmissionProofSHA256 = ""
	if err := validateDependencyInputAdmissionBinding(map[string]artifactInput{digest: badDependency}, proof, []providerInputAdmissionResourceReceipt{dependencyResource}); err == nil {
		t.Fatal("a dependency with an invalid proof binding was accepted")
	}
	otherDependency := sealedInputResourceForTest(t, providerInputAdmissionResourceKindArtifact, "other-dependency", 1)
	if err := validateDependencyInputAdmissionBinding(map[string]artifactInput{digest: dependency}, proof, []providerInputAdmissionResourceReceipt{otherDependency}); err == nil {
		t.Fatal("a dependency absent from its resource roster was accepted")
	}
	if _, err := providerInputAdmissionResourceSetRoot([]providerInputAdmissionResourceReceipt{{}}); err == nil {
		t.Fatal("an invalid resource was accepted into a set root")
	}
}

func TestProviderInputAdmissionAggregateByteOverflow(t *testing.T) {
	resources := []providerInputAdmissionResourceReceipt{
		sealedInputResourceForTest(t, providerInputAdmissionResourceKindCarrier, "carrier-corpus", canonicalProviderInputAdmissionLimits.EvidenceCarrierBytesPerCorpus),
		sealedInputResourceForTest(t, providerInputAdmissionResourceKindBody, "body-corpus", canonicalProviderInputAdmissionLimits.EvidenceBodyBytesPerCorpus),
		sealedInputResourceForTest(t, providerInputAdmissionResourceKindStageFile, "stage-corpus", canonicalProviderInputAdmissionLimits.StageInputFileBytesPerCorpus),
		sealedInputResourceForTest(t, providerInputAdmissionResourceKindManifest, "overflow-total", 1),
	}
	if _, err := providerInputAdmissionActualsFromResources(resources); err == nil {
		t.Fatal("a resource roster exceeding the aggregate byte domain was accepted")
	}
}
