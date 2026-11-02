package providerplan

import (
	"bytes"
	"testing"
)

func TestCloudIngestionHandoffFourComponentIdentityAndNoDeletionMatrix(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := LoadCloudAPIProfileDocument("../../testdata/cloudapi/provider-profiles-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadCloudIngestionHandoffPolicy("../../testdata/cloudapi/ingestion-handoff-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := BuildCloudIngestionHandoff(request, profiles, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(handoff.Targets) != 9 || len(handoff.Transitions) != 4 || len(handoff.Scenarios) != 6 {
		t.Fatalf("targets/transitions/scenarios = %d/%d/%d", len(handoff.Targets), len(handoff.Transitions), len(handoff.Scenarios))
	}
	requestBound := 0
	for _, target := range handoff.Targets {
		c := target.Coordinate
		if c.OrganizationID != "required_external_organization_id" || c.SourceInstanceID != "required_existing_source_instance_id" || c.SourceObjectType == "" || c.VendorRecordIDField == "" || c.VendorRecordIDPointer == "" || (c.ExtractorKind != "response_member" && c.ExtractorKind != "request_member") || target.ServiceProfileRef.ProfileID == "" || target.ServiceProfileRef.ProfileVersion == "" || !isLowerSHA256(target.ProfileDocumentSHA256) || !isLowerSHA256(target.CatalogModelSHA256) {
			t.Fatalf("incomplete coordinate %#v", target)
		}
		if c.ExtractorKind == "request_member" {
			requestBound++
			if c.RequestSchemaID == "" {
				t.Fatal("request extractor omitted schema")
			}
		}
		if c.EvidenceLocator.EvidenceID != "model" || c.EvidenceLocator.JSONPointer == "" {
			t.Fatal("coordinate extractor omitted pinned model evidence")
		}
		if c.ExtractorKind == "response_member" && c.VendorRecordIDPointer == c.EvidenceLocator.JSONPointer {
			t.Fatal("response extraction pointer incorrectly reused model JSON pointer")
		}
	}
	if requestBound != 3 {
		t.Fatalf("request-bound detail targets=%d", requestBound)
	}
	for _, transition := range handoff.Transitions {
		if transition.DeletionAuthorized || transition.CutoverDisposition != "refuse_cutover" {
			t.Fatalf("unsafe outcome %#v", transition)
		}
	}
	if err := ValidateCloudIngestionHandoff(handoff, request, profiles); err != nil {
		t.Fatal(err)
	}
}

func TestCloudIngestionHandoffRefusesIdentityAndPolicyTampering(t *testing.T) {
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	profiles, err := LoadCloudAPIProfileDocument("../../testdata/cloudapi/provider-profiles-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadCloudIngestionHandoffPolicy("../../testdata/cloudapi/ingestion-handoff-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := BuildCloudIngestionHandoff(request, profiles, policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CloudIngestionHandoff){func(h *CloudIngestionHandoff) { h.Targets[0].Coordinate.VendorRecordIDPointer = "/forged" }, func(h *CloudIngestionHandoff) { h.Targets[0].ServiceProfileRef.ProfileID = "substituted" }, func(h *CloudIngestionHandoff) { h.Transitions[0].DeletionAuthorized = true }, func(h *CloudIngestionHandoff) { h.Scenarios[0].ReplayDisposition = "forged" }} {
		copy := handoff
		copy.Targets = append([]CloudIngestionHandoffTarget(nil), handoff.Targets...)
		copy.Transitions = append([]CloudIngestionTransition(nil), handoff.Transitions...)
		copy.Scenarios = append([]CloudIngestionScenario(nil), handoff.Scenarios...)
		mutate(&copy)
		if err := ValidateCloudIngestionHandoff(copy, request, profiles); err == nil {
			t.Fatal("accepted handoff mutation")
		}
	}
	bad := policy
	bad.CoordinateComponents = []string{"organization_id", "source_instance_id", "vendor_record_id"}
	if _, err := BuildCloudIngestionHandoff(request, profiles, bad); err == nil {
		t.Fatal("accepted partial source coordinate")
	}
	if !bytes.HasSuffix(handoff.Document, []byte("\n")) {
		t.Fatal("not canonical output")
	}
	for _, mutate := range []func(*CloudIngestionHandoffPolicy){
		func(value *CloudIngestionHandoffPolicy) { value.SourceRecordOwnerRef = "other#s2" },
		func(value *CloudIngestionHandoffPolicy) { value.SourceRecordOwnerVersion = "18" },
		func(value *CloudIngestionHandoffPolicy) {
			value.SourceRecordOwnerSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		},
	} {
		bad = policy
		mutate(&bad)
		if _, err := BuildCloudIngestionHandoff(request, profiles, bad); err == nil {
			t.Fatal("accepted substituted source record owner pin")
		}
	}
	// Credential/interface/model-version rotation is deliberately excluded from
	// the four-component coordinate. The source identity validator stays the
	// authority for the extracted source member; this handoff never mints an
	// incarnation or semantic identity.
	for _, target := range request.Targets {
		if target.RequestIdentity != nil {
			continue
		}
		copy := target
		copy.SourceSchemaVersion = "rotated-interface-version"
		catalog := request.Catalogs[0]
		for _, candidate := range request.Catalogs {
			if candidate.ProviderID == target.ProviderID && candidate.ServiceID == target.ServiceID {
				catalog = candidate
				break
			}
		}
		if err := ValidateCloudSourceIdentityContract(copy, catalog); err != nil {
			t.Fatalf("identity changed by interface version: %v", err)
		}
	}
	rotatedProfiles := profiles
	rotatedProfiles.Providers = append([]CloudProviderAPIProfile(nil), profiles.Providers...)
	rotatedProfiles.Providers[0].Authentication.CredentialCarrier = "connector_vault_rotated_credential"
	rotated, err := BuildCloudIngestionHandoff(request, rotatedProfiles, policy)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.Targets[0].Coordinate != handoff.Targets[0].Coordinate || rotated.Targets[0].ProfileDocumentSHA256 == handoff.Targets[0].ProfileDocumentSHA256 {
		t.Fatal("credential rotation changed coordinate or escaped profile pin")
	}
	staleProfiles := profiles
	staleProfiles.Providers = append([]CloudProviderAPIProfile(nil), profiles.Providers...)
	staleProfiles.Providers[0].Services = append([]CloudServiceAPIResidual(nil), profiles.Providers[0].Services...)
	staleProfiles.Providers[0].Services[0].APIVersion = "stale"
	if _, err := BuildCloudIngestionHandoff(request, staleProfiles, policy); err == nil {
		t.Fatal("accepted API-version/profile drift")
	}
}
