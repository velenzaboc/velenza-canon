package providerplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudAPIProfilesCoverPinnedFourServiceSelection(t *testing.T) {
	profiles, err := LoadCloudAPIProfileDocument("../../testdata/cloudapi/provider-profiles-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCloudAPIProfileDocument(profiles, request.Catalogs, request.Targets); err != nil {
		t.Fatal(err)
	}
	for _, provider := range profiles.Providers {
		if provider.ProviderID != "aws" {
			continue
		}
		for _, service := range provider.Services {
			if service.ServiceID != "s3" {
				continue
			}
			for _, operation := range service.Operations {
				if operation.OperationID == "com.amazonaws.s3#ListBuckets" {
					if !operation.Pagination.Required || operation.Pagination.RequestTokenField != "ContinuationToken" {
						t.Fatal("ListBuckets must retain its operation-local pagination")
					}
					continue
				}
				if operation.Pagination.Required || operation.Pagination.RequestTokenField != "" || operation.Pagination.ResponseTokenField != "" {
					t.Fatalf("non-list S3 operation %q inherited pagination", operation.OperationID)
				}
			}
		}
	}
	raw, err := CanonicalCloudAPIProfileDocument(profiles)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CloudAPIProfileDocument
	if err := strictUnmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCloudAPIProfileDocument(decoded, request.Catalogs, request.Targets); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "access_key") {
		t.Fatal("profile artifact may not carry credential material")
	}
}

func TestCloudAPIProfilesFailClosed(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/provider-profiles-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var profiles CloudAPIProfileDocument
	if err := strictUnmarshal(raw, &profiles); err != nil {
		t.Fatal(err)
	}
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []struct {
		name   string
		change func(*CloudAPIProfileDocument)
	}{
		{"cross-provider-reference", func(d *CloudAPIProfileDocument) { d.Providers[0].Services[0].ProviderProfileRef.ProviderID = "gcp" }},
		{"credential-owner-expansion", func(d *CloudAPIProfileDocument) {
			d.Providers[0].Authentication.EligibleCredentialOwners = append(d.Providers[0].Authentication.EligibleCredentialOwners, "wildcard")
		}},
		{"stale-version", func(d *CloudAPIProfileDocument) { d.Providers[0].Services[0].ProfileVersion = "0" }},
		{"catalog-model-drift", func(d *CloudAPIProfileDocument) {
			d.Providers[0].Services[0].CatalogModelSHA256 = strings.Repeat("0", 64)
		}},
		{"unbound-smithy-authority", func(d *CloudAPIProfileDocument) {
			d.Providers[0].Services[1].Operations[0].Route.AuthorityTemplate = "evil.example"
		}},
		{"missing-operation", func(d *CloudAPIProfileDocument) {
			d.Providers[0].Services[0].Operations = d.Providers[0].Services[0].Operations[:1]
		}},
		{"non-paginated-operation-tokens", func(d *CloudAPIProfileDocument) {
			for providerIndex := range d.Providers {
				for serviceIndex := range d.Providers[providerIndex].Services {
					service := &d.Providers[providerIndex].Services[serviceIndex]
					if service.ServiceID == "s3" {
						service.Operations[0].Pagination = CloudPaginationShape{RequestTokenField: "ContinuationToken", ResponseTokenField: "ContinuationToken"}
					}
				}
			}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			var isolated CloudAPIProfileDocument
			if err := strictUnmarshal(raw, &isolated); err != nil {
				t.Fatal(err)
			}
			mutate.change(&isolated)
			if err := ValidateCloudAPIProfileDocument(isolated, request.Catalogs, request.Targets); err == nil {
				t.Fatal("validation accepted invalid profile")
			}
		})
	}
}

func TestResolveCloudOperationRouteSeparatesGlobalAndRegionalS3(t *testing.T) {
	global, err := ResolveCloudOperationRoute(CloudOperationRoute{Method: "GET", AuthorityTemplate: "s3.amazonaws.com", PathTemplate: "/"}, map[string]string{})
	if err != nil || global != "https://s3.amazonaws.com/" {
		t.Fatalf("global route = %q %v", global, err)
	}
	regional, err := ResolveCloudOperationRoute(CloudOperationRoute{Method: "GET", AuthorityTemplate: "s3.{region}.amazonaws.com", PathTemplate: "/{Bucket}", QueryTemplates: map[string]string{"encryption": ""}, RequiredSelectors: []string{"Bucket", "region"}}, map[string]string{"Bucket": "my.bucket", "region": "us-west-2"})
	if err != nil || regional != "https://s3.us-west-2.amazonaws.com/my.bucket?encryption" {
		t.Fatalf("regional route = %q %v", regional, err)
	}
	if _, err := ResolveCloudOperationRoute(CloudOperationRoute{Method: "GET", AuthorityTemplate: "x", PathTemplate: "/{bucket}", RequiredSelectors: []string{"bucket"}}, map[string]string{}); err == nil {
		t.Fatal("accepted missing selector")
	}
	if _, err := ResolveCloudOperationRoute(CloudOperationRoute{Method: "GET", AuthorityTemplate: "{bucket}.s3.amazonaws.com", PathTemplate: "/", RequiredSelectors: []string{"bucket"}}, map[string]string{"bucket": "x/evil"}); err == nil {
		t.Fatal("accepted authority injection")
	}
}

func TestCloudAPIProfileNineRoutesAndModelTampering(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/provider-profiles-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc CloudAPIProfileDocument
	if err := strictUnmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	request, err := LoadCloudSourceCandidateInput("../../testdata/cloudapi/candidate-input.json", NewCloudCatalogParser())
	if err != nil {
		t.Fatal(err)
	}
	wants := map[string]string{
		"com.amazonaws.ec2#DescribeInstances":   "https://ec2.us-west-2.amazonaws.com/?Action=DescribeInstances&Version=2016-11-15",
		"com.amazonaws.ec2#DescribeVolumes":     "https://ec2.us-west-2.amazonaws.com/?Action=DescribeVolumes&Version=2016-11-15",
		"com.amazonaws.s3#ListBuckets":          "https://s3.amazonaws.com/?x-id=ListBuckets",
		"com.amazonaws.s3#GetBucketEncryption":  "https://s3.us-west-2.amazonaws.com/sample.bucket?encryption",
		"com.amazonaws.s3#GetBucketVersioning":  "https://s3.us-west-2.amazonaws.com/sample.bucket?versioning",
		"com.amazonaws.s3#GetPublicAccessBlock": "https://s3.us-west-2.amazonaws.com/sample.bucket?publicAccessBlock",
		"compute.instances.aggregatedList":      "https://compute.googleapis.com/compute/v1/projects/sample-project/aggregated/instances",
		"compute.disks.aggregatedList":          "https://compute.googleapis.com/compute/v1/projects/sample-project/aggregated/disks",
		"storage.buckets.list":                  "https://storage.googleapis.com/storage/v1/b?project=sample-project",
	}
	seen := 0
	for _, p := range doc.Providers {
		for _, s := range p.Services {
			for _, op := range s.Operations {
				selectors := map[string]string{}
				for _, name := range op.Route.RequiredSelectors {
					selectors[name] = map[string]string{"region": "us-west-2", "Bucket": "sample.bucket", "project": "sample-project"}[name]
				}
				got, err := ResolveCloudOperationRoute(op.Route, selectors)
				if err != nil || got != wants[op.OperationID] {
					t.Fatalf("%s got %q err %v want %q", op.OperationID, got, err, wants[op.OperationID])
				}
				seen++
			}
		}
	}
	if seen != 9 {
		t.Fatal("selected operation routes not complete")
	}
	for _, mutation := range []struct {
		name   string
		change func(*CloudOperationAPIProfile)
	}{
		{"route", func(op *CloudOperationAPIProfile) { op.Route.PathTemplate = "/unrelated" }},
		{"action", func(op *CloudOperationAPIProfile) { op.Route.QueryTemplates["Action"] = "DeleteVolume" }},
		{"missing-route", func(op *CloudOperationAPIProfile) { op.Route = CloudOperationRoute{} }},
		{"wire-name", func(op *CloudOperationAPIProfile) { op.Pagination.RequestTokenWireName = "WrongToken" }},
		{"locator", func(op *CloudOperationAPIProfile) { op.ModelEvidence.Locator.StartByte++ }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			var changed CloudAPIProfileDocument
			if err := strictUnmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			mutation.change(&changed.Providers[0].Services[0].Operations[0])
			if err := ValidateCloudAPIProfileDocument(changed, request.Catalogs, request.Targets); err == nil {
				t.Fatal("accepted changed exact model binding")
			}
		})
	}
}

func TestCloudOperationRouteRejectsURLInjection(t *testing.T) {
	for _, host := range []string{"a.example@evil.test", "evil.test:443", "a.example/evil", "a.example?x", "a.example#x", "a\\evil.test", "a..example", "-a.example", "a.example.", "{region}suffix.example", "{region}.example}"} {
		if _, err := ResolveCloudOperationRoute(CloudOperationRoute{Method: "GET", AuthorityTemplate: host, PathTemplate: "/"}, nil); err == nil {
			t.Fatalf("accepted authority %q", host)
		}
	}
	for _, value := range []string{"a.b", "-a", "a-", "A", "a\\b", "a\nb", "é", "a@evil.test"} {
		if _, err := ResolveCloudOperationRoute(CloudOperationRoute{Method: "GET", AuthorityTemplate: "{region}.example", PathTemplate: "/", RequiredSelectors: []string{"region"}}, map[string]string{"region": value}); err == nil {
			t.Fatalf("accepted host selector %q", value)
		}
	}
	got, err := ResolveCloudOperationRoute(CloudOperationRoute{Method: "GET", AuthorityTemplate: "api.example", PathTemplate: "/v1/{name}", QueryTemplates: map[string]string{"project": "{project}"}, RequiredSelectors: []string{"name", "project"}}, map[string]string{"name": "a/b", "project": "x+y&admin=true"})
	if err != nil || got != "https://api.example/v1/a%2Fb?project=x%2By%26admin%3Dtrue" {
		t.Fatalf("unsafe or wrong escaping: %q %v", got, err)
	}
}

func TestCloudRetryPolicyIsBoundedAndRefusesAuthorityFailures(t *testing.T) {
	p := CloudRetryShape{Classifications: []string{"client_throttling", "server_transient", "transport_transient"}, IdempotentRead: true, MaxAttempts: 4, InitialBackoffMillis: 250, MaxBackoffMillis: 600, Jitter: "full"}
	for _, class := range []string{"authentication_failure", "permission_denied", "invalid_request", "unknown"} {
		if _, retry, err := CloudRetryDelay(p, class, 1, 17); err != nil || retry {
			t.Fatalf("retried %q: %v", class, err)
		}
	}
	for attempt, cap := range map[int]int64{1: 250, 2: 500, 3: 600} {
		got, retry, err := CloudRetryDelay(p, "client_throttling", attempt, ^uint64(0))
		if err != nil || !retry || got < 0 || got > cap {
			t.Fatalf("bad delay %d %v %v", got, retry, err)
		}
	}
	if _, retry, err := CloudRetryDelay(p, "server_transient", 4, 0); err != nil || retry {
		t.Fatal("retry limit ignored")
	}
	p.Classifications = []string{"permission_denied"}
	if _, _, err := CloudRetryDelay(p, "permission_denied", 1, 0); err == nil {
		t.Fatal("unknown retry class admitted")
	}
}

func TestCloudAPIProfileSuccessorReusesSchemaAndExactProviderReference(t *testing.T) {
	doc, err := LoadCloudAPIProfileDocument("../../testdata/cloudapi/provider-profiles-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	doc.Providers[0].ProfileVersion = "2"
	for i := range doc.Providers[0].Services {
		doc.Providers[0].Services[i].ProviderProfileRef.ProfileVersion = "2"
		doc.Providers[0].Services[i].ProfileVersion = "3"
	}
	if err := ValidateCloudAPIProfileDocument(doc, nil, nil); err != nil {
		t.Fatal(err)
	}
	doc.Providers[0].Services[0].ProviderProfileRef.ProfileVersion = "1"
	if err := ValidateCloudAPIProfileDocument(doc, nil, nil); err == nil {
		t.Fatal("successor silently inherited stale provider profile")
	}
}

func TestCloudAPIProfileLoaderRejectsChangedCapturedBytes(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/cloudapi/provider-profiles-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc CloudAPIProfileDocument
	if err := strictUnmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	doc.Providers[0].Evidence[0].LocalPath = "capture.raw"
	if err := os.WriteFile(filepath.Join(root, "capture.raw"), []byte("substituted capture"), 0600); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "profiles.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCloudAPIProfileDocument(path); err == nil || !strings.Contains(err.Error(), "bytes differ") {
		t.Fatalf("changed capture was not refused at exact bytes: %v", err)
	}
}
