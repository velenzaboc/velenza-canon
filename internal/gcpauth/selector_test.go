package gcpauth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type fixedTokenSource struct{ token string }

func (s fixedTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: s.token}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type fakeMetadataClient struct {
	onGCE bool
	email string
	err   error
	get   func(context.Context, string) (string, error)
}

func (f fakeMetadataClient) OnGCEWithContext(context.Context) bool { return f.onGCE }
func (f fakeMetadataClient) EmailWithContext(context.Context, string) (string, error) {
	return f.email, f.err
}
func (f fakeMetadataClient) GetWithContext(ctx context.Context, suffix string) (string, error) {
	if f.get == nil {
		return "", fmt.Errorf("unexpected metadata token request %q", suffix)
	}
	return f.get(ctx, suffix)
}

func TestSelectorValidateClosesADCUnion(t *testing.T) {
	validIdentity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	for _, tt := range []struct {
		name       string
		selector   Selector
		requireADC bool
		wantErr    string
	}{
		{
			name: "impersonated",
			selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault,
				CredentialsProfile: CredentialsProfileImpersonatedServiceAccount, CredentialsIdentity: validIdentity},
		},
		{
			name: "attached",
			selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault,
				CredentialsProfile: CredentialsProfileAttachedServiceAccount, CredentialsIdentity: validIdentity},
		},
		{name: "missing", wantErr: "credentials_source"},
		{name: "unknown_source", selector: Selector{CredentialsSource: "ambient_magic", CredentialsProfile: CredentialsProfileAttachedServiceAccount, CredentialsIdentity: validIdentity}, wantErr: "unsupported credentials_source"},
		{name: "missing_profile", selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsIdentity: validIdentity}, wantErr: "credentials_profile"},
		{name: "unknown_profile", selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: "some_adc", CredentialsIdentity: validIdentity}, wantErr: "unsupported credentials_profile"},
		{name: "missing_identity", selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileAttachedServiceAccount}, wantErr: "credentials_identity"},
		{name: "human_identity", selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileAttachedServiceAccount, CredentialsIdentity: "operator@example.com"}, wantErr: "service-account email"},
		{name: "file_in_production", requireADC: true, selector: Selector{CredentialsFile: "/tmp/adc.json", CredentialsProfile: CredentialsProfileImpersonatedServiceAccount, CredentialsIdentity: validIdentity}, wantErr: "production requires"},
		{name: "ambiguous_carrier", selector: Selector{CredentialsFile: "/tmp/adc.json", CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileImpersonatedServiceAccount, CredentialsIdentity: validIdentity}, wantErr: "mutually exclusive"},
		{name: "attached_file", selector: Selector{CredentialsFile: "/tmp/adc.json", CredentialsProfile: CredentialsProfileAttachedServiceAccount, CredentialsIdentity: validIdentity}, wantErr: "attached_service_account requires"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.selector.Validate("google_credentials", tt.requireADC)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestTokenSourceRefusesPostQuantumTLSDowngradesBeforeCredentialConstruction(t *testing.T) {
	selector := Selector{}
	for _, value := range []string{"tlsmlkem=0", "http2server=1,tlssecpmlkem=0", " tlsmlkem = 0 "} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("GODEBUG", value)
			_, err := selector.TokenSource(context.Background())
			if err == nil || !strings.Contains(err.Error(), "post-quantum TLS") {
				t.Fatalf("TokenSource() error = %v, want post-quantum downgrade refusal", err)
			}
		})
	}
}

func TestSecuritySensitiveGODEBUGLeavesDefaultOrEnabledPostQuantumTLSAvailable(t *testing.T) {
	for _, value := range []string{"", "tlsmlkem=1", "tlssecpmlkem=1,netdns=go"} {
		if err := validateSecuritySensitiveGODEBUG(value); err != nil {
			t.Fatalf("validateSecuritySensitiveGODEBUG(%q) = %v", value, err)
		}
	}
}

func TestImpersonatedTokenSourceValidatesExactCarrierBytes(t *testing.T) {
	identity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	path := writeCredentialFile(t, fmt.Sprintf(`{
  "type": "impersonated_service_account",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
  "delegates": [],
  "source_credentials": {
    "type": "authorized_user",
    "client_id": "fixture.apps.googleusercontent.com",
    "client_secret": "fixture-secret",
    "refresh_token": "fixture-refresh",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}`, identity), 0o600)
	setDefaultADCPath(t, path)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("CLOUDSDK_CONFIG", "")

	selector := Selector{
		CredentialsSource:   CredentialsSourceApplicationDefault,
		CredentialsProfile:  CredentialsProfileImpersonatedServiceAccount,
		CredentialsIdentity: identity,
	}
	ts, err := selector.TokenSource(context.Background(), "scope-a")
	if err != nil {
		t.Fatalf("TokenSource() unexpected error: %v", err)
	}
	if ts == nil {
		t.Fatal("TokenSource() returned nil")
	}
}

func TestImpersonatedTokenSourceOutlivesConstructionContext(t *testing.T) {
	identity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	path := writeCredentialFile(t, fmt.Sprintf(`{
  "type": "impersonated_service_account",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
  "delegates": [],
  "quota_project_id": "fixture-project",
  "source_credentials": {
    "type": "authorized_user",
    "client_id": "fixture.apps.googleusercontent.com",
    "client_secret": "fixture-secret",
    "refresh_token": "fixture-refresh",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}`, identity), 0o600)
	setDefaultADCPath(t, path)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("CLOUDSDK_CONFIG", "")

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := req.Context().Err(); err != nil {
			return nil, fmt.Errorf("credential request inherited canceled construction context: %w", err)
		}
		body := `{"access_token":"source-token","token_type":"Bearer","expires_in":3600}`
		if strings.Contains(req.URL.Path, ":generateAccessToken") {
			if got := req.Header.Get("Authorization"); got != "Bearer source-token" {
				t.Fatalf("IAMCredentials Authorization = %q, want source token", got)
			}
			body = `{"accessToken":"target-token","expireTime":"2099-01-01T00:00:00Z"}`
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})
	constructionCtx, cancel := context.WithCancel(context.WithValue(
		context.Background(),
		oauth2.HTTPClient,
		&http.Client{Transport: transport},
	))
	selector := Selector{
		CredentialsSource:   CredentialsSourceApplicationDefault,
		CredentialsProfile:  CredentialsProfileImpersonatedServiceAccount,
		CredentialsIdentity: identity,
	}
	ts, err := selector.TokenSource(constructionCtx, CloudPlatformScope)
	if err != nil {
		t.Fatalf("TokenSource() unexpected error: %v", err)
	}
	cancel()

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("Token() after construction context cancellation: %v", err)
	}
	if token == nil || token.AccessToken != "target-token" {
		t.Fatalf("Token() = %#v, want target-token", token)
	}
}

func TestImpersonatedRequestTokenSourceConsumesRefreshContext(t *testing.T) {
	identity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	path := writeCredentialFile(t, fmt.Sprintf(`{
  "type": "impersonated_service_account",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken",
  "delegates": [],
  "quota_project_id": "fixture-project",
  "source_credentials": {
    "type": "authorized_user",
    "client_id": "fixture.apps.googleusercontent.com",
    "client_secret": "fixture-secret",
    "refresh_token": "fixture-refresh",
    "token_uri": "https://oauth2.googleapis.com/token"
  }
}`, identity), 0o600)
	setDefaultADCPath(t, path)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("CLOUDSDK_CONFIG", "")

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(100 * time.Millisecond):
			return nil, fmt.Errorf("refresh context was not propagated")
		}
	})
	refreshContext, cancel := context.WithCancel(context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: transport}))
	selector := Selector{
		CredentialsSource:   CredentialsSourceApplicationDefault,
		CredentialsProfile:  CredentialsProfileImpersonatedServiceAccount,
		CredentialsIdentity: identity,
	}
	tokenSource, err := selector.RequestTokenSourceFactory(CloudPlatformScope)(refreshContext)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := tokenSource.Token(); err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("Token() error = %v, want request-context cancellation", err)
	}
}

func TestImpersonatedTokenSourceRejectsHostileCarrier(t *testing.T) {
	identity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	valid := func(target string) string {
		return fmt.Sprintf(`{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken","delegates":[],"quota_project_id":"fixture-project","source_credentials":{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"refresh","token_uri":"https://oauth2.googleapis.com/token"}}`, target)
	}
	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileImpersonatedServiceAccount, CredentialsIdentity: identity}
	// "Accessible to more than the owner" is enforced through different
	// mechanisms per platform (POSIX mode bits vs. DACL entries), so the
	// rejection wording differs even though the security property is the
	// same. See the "group_readable" case below.
	tooPermissiveWantError := "owner-only"
	if runtime.GOOS == "windows" {
		tooPermissiveWantError = "unapproved principal"
	}

	for _, tt := range []struct {
		name      string
		body      string
		mode      os.FileMode
		cloudSDK  string
		cloudRoot string
		wantError string
	}{
		{name: "wrong_target", body: valid("other-local@example-gcp-project.iam.gserviceaccount.com"), mode: 0o600, wantError: "does not match credentials_identity"},
		{name: "wrong_quota_project", body: strings.Replace(valid(identity), `"quota_project_id":"fixture-project"`, `"quota_project_id":"other-project"`, 1), mode: 0o600, wantError: "must match the impersonated service account project"},
		{name: "private_key", body: strings.TrimSuffix(valid(identity), "}") + `,"private_key":"forbidden"}`, mode: 0o600, wantError: "private_key"},
		{name: "nonempty_delegates", body: strings.Replace(valid(identity), `"delegates":[]`, `"delegates":["delegate@example-gcp-project.iam.gserviceaccount.com"]`, 1), mode: 0o600, wantError: "delegates"},
		{name: "case_variant_delegates", body: strings.Replace(valid(identity), `"delegates":[]`, `"delegates":[],"DELEGATES":["delegate@example-gcp-project.iam.gserviceaccount.com"]`, 1), mode: 0o600, wantError: "DELEGATES"},
		{name: "case_variant_impersonation_url", body: strings.Replace(valid(identity), `"delegates":[]`, `"SERVICE_ACCOUNT_IMPERSONATION_URL":"https://attacker.invalid/v1/token","delegates":[]`, 1), mode: 0o600, wantError: "SERVICE_ACCOUNT_IMPERSONATION_URL"},
		{name: "redirecting_source_token_uri", body: strings.Replace(valid(identity), "https://oauth2.googleapis.com/token", "https://attacker.invalid/token", 1), mode: 0o600, wantError: "source_credentials.token_uri"},
		{name: "case_variant_source_token_uri", body: strings.Replace(valid(identity), `"token_uri":"https://oauth2.googleapis.com/token"`, `"token_uri":"https://oauth2.googleapis.com/token","TOKEN_URI":"https://attacker.invalid/token"`, 1), mode: 0o600, wantError: "TOKEN_URI"},
		{name: "unknown_parser_field", body: strings.Replace(valid(identity), `"delegates":[]`, `"token_url":"https://attacker.invalid/token","delegates":[]`, 1), mode: 0o600, wantError: "token_url"},
		{name: "unexpected_target_scopes", body: strings.Replace(valid(identity), `"delegates":[]`, `"delegates":[],"scopes":["https://www.googleapis.com/auth/drive"]`, 1), mode: 0o600, wantError: "scopes must contain only"},
		{name: "multiple_target_scopes", body: strings.Replace(valid(identity), `"delegates":[]`, `"delegates":[],"scopes":["https://www.googleapis.com/auth/cloud-platform","https://www.googleapis.com/auth/drive"]`, 1), mode: 0o600, wantError: "scopes must contain only"},
		{name: "duplicate_key", body: strings.Replace(valid(identity), `"type":"impersonated_service_account"`, `"type":"impersonated_service_account","type":"impersonated_service_account"`, 1), mode: 0o600, wantError: "duplicate JSON key"},
		{name: "group_readable", body: valid(identity), mode: 0o640, wantError: tooPermissiveWantError},
		{name: "cloud_sdk_override", body: valid(identity), mode: 0o600, cloudSDK: "/tmp/human.json", wantError: "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"},
		{name: "cloud_sdk_config_override", body: valid(identity), mode: 0o600, cloudRoot: "/tmp/alternate-gcloud", wantError: "CLOUDSDK_CONFIG"},
		{name: "service_account_key", body: `{"type":"service_account","private_key_id":"x","private_key":"x"}`, mode: 0o600, wantError: "private_key"},
		{name: "incomplete_authorized_user", body: fmt.Sprintf(`{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken","quota_project_id":"fixture-project","source_credentials":{"type":"authorized_user","client_id":"id"}}`, identity), mode: 0o600, wantError: "client_secret"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := writeCredentialFile(t, tt.body, tt.mode)
			if tt.name == "group_readable" && runtime.GOOS == "windows" {
				// Windows has no POSIX permission bits: os.Chmod(0o640)
				// cannot produce a "more than owner-accessible" file there,
				// and validateCredentialFileAccess on Windows checks the
				// DACL, never os.FileMode — writeCredentialFile's own
				// fixture-ownership fix just reset this file to an
				// owner/SYSTEM/Administrators-only DACL. Exercise the actual
				// Windows-native equivalent of "too permissive" instead: grant
				// an extra, unapproved principal explicit read access, the
				// same shape TestValidateCredentialFileAccessWindowsRejectsUnapprovedDACLPrincipal
				// uses directly against the access check.
				if output, err := exec.Command("icacls", path, "/grant", "Everyone:(R)").CombinedOutput(); err != nil {
					t.Fatalf("icacls grant extra principal: %v: %s", err, output)
				}
			}
			setDefaultADCPath(t, path)
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
			t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", tt.cloudSDK)
			t.Setenv("CLOUDSDK_CONFIG", tt.cloudRoot)
			_, err := selector.TokenSource(context.Background(), "scope-a")
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("TokenSource() error = %v, want substring %q", err, tt.wantError)
			}
		})
	}
}

func TestValidateConfigCredentialShapeClosesHiddenSelectorsAndSecrets(t *testing.T) {
	valid := `{"mode":"experimental_bootstrap","google_credentials":{"credentials_source":"application_default","credentials_profile":"impersonated_service_account","credentials_identity":"graph-test-operator@fixture-project.iam.gserviceaccount.com"},"pipeline":{"cluster":{"embedding_batch_size":1}}}`
	for _, tt := range []struct {
		name    string
		body    string
		wantErr string
	}{
		{name: "closed_shape", body: valid},
		{name: "legacy_nested_file", body: strings.Replace(valid, `"embedding_batch_size":1`, `"embedding_batch_size":1,"credentials_file":"/tmp/key.json"`, 1), wantErr: "credentials_file"},
		{name: "case_variant_selector", body: strings.Replace(valid, `"embedding_batch_size":1`, `"embedding_batch_size":1,"CredentialsSource":"ambient"`, 1), wantErr: "CredentialsSource"},
		{name: "nested_second_selector", body: strings.Replace(valid, `"embedding_batch_size":1`, `"embedding_batch_size":1,"google_credentials":{}`, 1), wantErr: "google_credentials"},
		{name: "embedded_private_key", body: strings.Replace(valid, `"embedding_batch_size":1`, `"embedding_batch_size":1,"private_key":"forbidden"`, 1), wantErr: "private_key"},
		{name: "unknown_selector_member", body: strings.Replace(valid, `"credentials_identity":"graph-test-operator@fixture-project.iam.gserviceaccount.com"`, `"credentials_identity":"graph-test-operator@fixture-project.iam.gserviceaccount.com","credential_fallback":"ambient"`, 1), wantErr: "credential_fallback"},
		{name: "nested_quota_project", body: strings.Replace(valid, `"embedding_batch_size":1`, `"embedding_batch_size":1,"quota_project_id":"attacker-project"`, 1), wantErr: "quota_project_id"},
		{name: "nested_client_id", body: strings.Replace(valid, `"embedding_batch_size":1`, `"embedding_batch_size":1,"client_id":"hidden-client"`, 1), wantErr: "client_id"},
		{name: "nested_token_uri", body: strings.Replace(valid, `"embedding_batch_size":1`, `"embedding_batch_size":1,"token_uri":"https://attacker.invalid/token"`, 1), wantErr: "token_uri"},
		{name: "nested_credential_in_array", body: strings.Replace(valid, `"embedding_batch_size":1`, `"embedding_batch_size":1,"items":[{"private_key":"x"}]`, 1), wantErr: "private_key"},
		{name: "duplicate_selector", body: strings.Replace(valid, `"credentials_source":"application_default"`, `"credentials_source":"application_default","credentials_source":"application_default"`, 1), wantErr: "duplicate JSON key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateConfigCredentialShape([]byte(tt.body))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateConfigCredentialShape() unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateConfigCredentialShape() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSpannerEmulatorHostClosesAuthenticationBypass(t *testing.T) {
	for _, tt := range []struct {
		name      string
		allow     bool
		host      string
		wantUse   bool
		wantError string
	}{
		{name: "unset", host: ""},
		{name: "canonical", allow: true, host: "localhost:9010", wantUse: true},
		{name: "not_allowed", host: "localhost:9010", wantError: "forbidden outside experimental bootstrap"},
		{name: "wrong_port", allow: true, host: "localhost:1", wantError: "must equal"},
		{name: "numeric_loopback_alias", allow: true, host: "127.0.0.1:9010", wantError: "must equal"},
		{name: "remote_host", allow: true, host: "attacker.invalid:9010", wantError: "must equal"},
		{name: "surrounding_whitespace", allow: true, host: " localhost:9010 ", wantError: "must equal"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			use, err := ValidateSpannerEmulatorHost(tt.host, tt.allow)
			if tt.wantError == "" {
				if err != nil || use != tt.wantUse {
					t.Fatalf("ValidateSpannerEmulatorHost() = (%v, %v), want (%v, nil)", use, err, tt.wantUse)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("ValidateSpannerEmulatorHost() error = %v, want substring %q", err, tt.wantError)
			}
		})
	}
}

func TestImpersonatedTokenSourceRejectsOverridesSymlinkAndMissingCarrier(t *testing.T) {
	identity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileImpersonatedServiceAccount, CredentialsIdentity: identity}
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("CLOUDSDK_CONFIG", "")

	t.Run("google_application_credentials_override", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/alternate.json")
		if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "must be unset") {
			t.Fatalf("TokenSource() error = %v, want environment override rejection", err)
		}
	})

	t.Run("missing_well_known_carrier", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		setDefaultADCPath(t, filepath.Join(t.TempDir(), "missing-adc.json"))
		if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "read impersonated ADC carrier") {
			t.Fatalf("TokenSource() error = %v, want missing well-known carrier rejection", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		target := writeCredentialFile(t, `{}`, 0o600)
		link := filepath.Join(t.TempDir(), "adc-link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		setDefaultADCPath(t, link)
		if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("TokenSource() error = %v, want symlink rejection", err)
		}
	})
}

func TestAttachedTokenSourceBindsMetadataIdentityAndDirectSource(t *testing.T) {
	identity := "task-graph-runtime@example-gcp-project.iam.gserviceaccount.com"
	originalMetadata := newMetadataClient
	originalCompute := computeTokenSource
	t.Cleanup(func() {
		newMetadataClient = originalMetadata
		computeTokenSource = originalCompute
	})
	newMetadataClient = func() metadataClient {
		return fakeMetadataClient{onGCE: true, email: identity}
	}
	var gotAccount string
	var gotScopes []string
	computeTokenSource = func(account string, scopes ...string) oauth2.TokenSource {
		gotAccount = account
		gotScopes = append([]string(nil), scopes...)
		return fixedTokenSource{token: "metadata-token"}
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("GCE_METADATA_HOST", "")

	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileAttachedServiceAccount, CredentialsIdentity: identity}
	ts, err := selector.TokenSource(context.Background(), "scope-a", "scope-b")
	if err != nil {
		t.Fatal(err)
	}
	if ts == nil || gotAccount != identity || strings.Join(gotScopes, ",") != "scope-a,scope-b" {
		t.Fatalf("direct metadata source = (%v, %q, %v), want nonnil/%s/[scope-a scope-b]", ts, gotAccount, gotScopes, identity)
	}
}

func TestAttachedRequestTokenSourceConsumesRefreshContext(t *testing.T) {
	identity := "graph-test-runtime@fixture-project.iam.gserviceaccount.com"
	originalMetadata := newMetadataClient
	t.Cleanup(func() { newMetadataClient = originalMetadata })
	var suffix string
	newMetadataClient = func() metadataClient {
		return fakeMetadataClient{
			onGCE: true,
			email: identity,
			get: func(ctx context.Context, got string) (string, error) {
				suffix = got
				select {
				case <-ctx.Done():
					return "", ctx.Err()
				default:
					return `{"access_token":"metadata-token","token_type":"Bearer","expires_in":3600}`, nil
				}
			},
		}
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("GCE_METADATA_HOST", "")

	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileAttachedServiceAccount, CredentialsIdentity: identity}
	tokenSource, err := selector.RequestTokenSourceFactory("scope-a", "scope-b")(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	token, err := tokenSource.Token()
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "metadata-token" || !strings.Contains(suffix, "service-accounts/graph-test-runtime@fixture-project.iam.gserviceaccount.com/token") || !strings.Contains(suffix, "scopes=scope-a%2Cscope-b") {
		t.Fatalf("request-bound metadata token = (%q, %q)", token.AccessToken, suffix)
	}
}

func TestAttachedTokenSourceRejectsAmbientOverridesAndWrongMetadataIdentity(t *testing.T) {
	identity := "task-graph-runtime@example-gcp-project.iam.gserviceaccount.com"
	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileAttachedServiceAccount, CredentialsIdentity: identity}
	originalMetadata := newMetadataClient
	t.Cleanup(func() { newMetadataClient = originalMetadata })

	for _, tt := range []struct {
		name         string
		gac          string
		cloudSDK     string
		metadataHost string
		onGCE        bool
		email        string
		wantErr      string
	}{
		{name: "gac_override", gac: "/tmp/human.json", onGCE: true, email: identity, wantErr: "GOOGLE_APPLICATION_CREDENTIALS"},
		{name: "cloud_sdk_override", cloudSDK: "/tmp/human.json", onGCE: true, email: identity, wantErr: "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"},
		{name: "metadata_host_override", metadataHost: "attacker.invalid", onGCE: true, email: identity, wantErr: "GCE_METADATA_HOST"},
		{name: "not_google_hosted", onGCE: false, email: identity, wantErr: "Google-hosted metadata"},
		{name: "wrong_identity", onGCE: true, email: "default-compute@developer.gserviceaccount.com", wantErr: "does not match credentials_identity"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tt.gac)
			t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", tt.cloudSDK)
			t.Setenv("GCE_METADATA_HOST", tt.metadataHost)
			newMetadataClient = func() metadataClient { return fakeMetadataClient{onGCE: tt.onGCE, email: tt.email} }
			if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("TokenSource() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestCredentialValidationPrimitivesRejectAmbiguityAndUnsafeFiles(t *testing.T) {
	identity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	for _, path := range []string{"", "relative.json", t.TempDir()} {
		if _, err := readOwnerOnlyRegularFile(path); err == nil {
			t.Fatalf("readOwnerOnlyRegularFile(%q) accepted unsafe path", path)
		}
	}
	if got := serviceAccountProject(identity); got != "fixture-project" {
		t.Fatalf("serviceAccountProject() = %q", got)
	}
	if got := serviceAccountProject("not-an-email"); got != "" {
		t.Fatalf("serviceAccountProject(invalid) = %q", got)
	}
	for _, rawURL := range []string{
		"http://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + identity + ":generateAccessToken",
		"https://attacker.invalid/v1/projects/-/serviceAccounts/" + identity + ":generateAccessToken",
		"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/other@fixture-project.iam.gserviceaccount.com:generateAccessToken",
	} {
		if err := validateImpersonationURL(rawURL, identity); err == nil {
			t.Fatalf("validateImpersonationURL accepted %q", rawURL)
		}
	}
	if err := validateImpersonationURL("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"+identity+":generateAccessToken", identity); err != nil {
		t.Fatalf("validateImpersonationURL(valid): %v", err)
	}
	for _, value := range []any{
		map[string]any{"nested": []any{map[string]any{"private_key_id": "forbidden"}}},
		[]any{map[string]any{"private_key": "forbidden"}},
	} {
		if err := rejectForbiddenCredentialFields(value); err == nil {
			t.Fatal("rejectForbiddenCredentialFields accepted private key material")
		}
	}
	for _, data := range []string{`{"a":1,}`, `{"a":1} trailing`, `{"a":{"b":1,"b":2}}`} {
		if err := rejectDuplicateJSONKeys([]byte(data)); err == nil {
			t.Fatalf("rejectDuplicateJSONKeys accepted %q", data)
		}
	}
	if err := validateCredentialObjectKeys(map[string]any{"allowed": true}, "fixture", []string{"allowed"}); err != nil {
		t.Fatalf("validateCredentialObjectKeys(valid): %v", err)
	}
	if err := validateCredentialObjectKeys(map[string]any{"unsafe": true}, "fixture", []string{"allowed"}); err == nil {
		t.Fatal("validateCredentialObjectKeys accepted unknown key")
	}
}

func TestRequestMetadataTokenSourceClosesBadResponses(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		err  error
	}{
		{name: "transport", err: fmt.Errorf("unavailable")},
		{name: "malformed", body: "{"},
		{name: "incomplete", body: `{"access_token":"token","expires_in":0}`},
		{name: "complete", body: `{"access_token":"token","token_type":"Bearer","expires_in":60}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			source := requestMetadataTokenSource{account: "graph-test-runtime@fixture-project.iam.gserviceaccount.com", scopes: []string{"scope-a"}, ctx: context.Background(), client: fakeMetadataClient{get: func(context.Context, string) (string, error) { return tt.body, tt.err }}}
			token, err := source.Token()
			if tt.name == "complete" {
				if err != nil || token == nil || token.AccessToken != "token" {
					t.Fatalf("Token() = %#v, %v", token, err)
				}
				return
			}
			if err == nil {
				t.Fatal("Token() accepted invalid metadata response")
			}
		})
	}
}

func TestImpersonatedConfigurationClosesMalformedOptionalAndSourceFields(t *testing.T) {
	identity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	valid := fmt.Sprintf(`{"type":"impersonated_service_account","service_account_impersonation_url":"https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken","delegates":[],"source_credentials":{"type":"authorized_user","client_id":"id","client_secret":"secret","refresh_token":"refresh"}}`, identity)
	if err := validateImpersonatedConfiguration([]byte(valid), identity); err != nil {
		t.Fatalf("validateImpersonatedConfiguration(valid): %v", err)
	}
	for _, body := range []string{
		`not-json`,
		strings.Replace(valid, `"type":"impersonated_service_account"`, `"type":"authorized_user"`, 1),
		strings.Replace(valid, `"delegates":[]`, `"delegates":null`, 1),
		strings.Replace(valid, `"source_credentials":{`, `"source_credentials":null`, 1),
		strings.Replace(valid, `"client_id":"id"`, `"client_id":""`, 1),
		strings.Replace(valid, `"refresh_token":"refresh"`, `"refresh_token":3`, 1),
		strings.Replace(valid, `"delegates":[]`, `"delegates":[],"scopes":"scope"`, 1),
		strings.Replace(valid, `"delegates":[]`, `"delegates":[],"quota_project_id":9`, 1),
		strings.Replace(valid, `"refresh_token":"refresh"`, `"refresh_token":"refresh","universe_domain":"invalid"`, 1),
	} {
		if err := validateImpersonatedConfiguration([]byte(body), identity); err == nil {
			t.Fatalf("validateImpersonatedConfiguration accepted %s", body)
		}
	}
}

func TestSelectorValidateDeviceServiceAccount(t *testing.T) {
	targetIdentity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	baseIdentity := "workstation-caller@example-gcp-project.iam.gserviceaccount.com"
	for _, tt := range []struct {
		name     string
		selector Selector
		wantErr  string
	}{
		{
			name: "valid",
			selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault,
				CredentialsProfile: CredentialsProfileDeviceServiceAccount, CredentialsIdentity: targetIdentity,
				CredentialsBaseIdentity: baseIdentity},
		},
		{
			name: "missing_base_identity",
			selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault,
				CredentialsProfile: CredentialsProfileDeviceServiceAccount, CredentialsIdentity: targetIdentity},
			wantErr: "credentials_base_identity",
		},
		{
			name: "human_base_identity",
			selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault,
				CredentialsProfile: CredentialsProfileDeviceServiceAccount, CredentialsIdentity: targetIdentity,
				CredentialsBaseIdentity: "operator@example.com"},
			wantErr: "service-account email",
		},
		{
			name: "base_equals_target",
			selector: Selector{CredentialsSource: CredentialsSourceApplicationDefault,
				CredentialsProfile: CredentialsProfileDeviceServiceAccount, CredentialsIdentity: targetIdentity,
				CredentialsBaseIdentity: targetIdentity},
			wantErr: "must differ",
		},
		{
			name: "file_carrier_forbidden",
			selector: Selector{CredentialsFile: "/tmp/adc.json",
				CredentialsProfile: CredentialsProfileDeviceServiceAccount, CredentialsIdentity: targetIdentity,
				CredentialsBaseIdentity: baseIdentity},
			wantErr: "device_service_account requires",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.selector.Validate("google_credentials", false)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestDeviceServiceAccountConfigurationClosesMismatchedOrKeylessCarrier(t *testing.T) {
	identity := "workstation-caller@example-gcp-project.iam.gserviceaccount.com"
	valid := fmt.Sprintf(`{"type":"service_account","client_email":%q,"private_key":"fixture-key","private_key_id":"fixture-key-id","token_uri":"https://oauth2.googleapis.com/token"}`, identity)
	if err := validateDeviceServiceAccountConfiguration([]byte(valid), identity); err != nil {
		t.Fatalf("validateDeviceServiceAccountConfiguration(valid): %v", err)
	}
	for _, body := range []string{
		`not-json`,
		`[1,2,3]`,
		strings.Replace(valid, `"type":"service_account"`, `"type":"authorized_user"`, 1),
		strings.Replace(valid, fmt.Sprintf("%q", identity), `"someone-else@fixture-project.iam.gserviceaccount.com"`, 1),
		strings.Replace(valid, `"private_key":"fixture-key"`, `"private_key":""`, 1),
		strings.Replace(valid, `"token_uri":"https://oauth2.googleapis.com/token"`, ``, 1),
	} {
		if err := validateDeviceServiceAccountConfiguration([]byte(body), identity); err == nil {
			t.Fatalf("validateDeviceServiceAccountConfiguration accepted %s", body)
		}
	}
}

func TestDeviceServiceAccountTokenSourceImpersonatesUsingBaseCredential(t *testing.T) {
	targetIdentity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	baseIdentity := "workstation-caller@example-gcp-project.iam.gserviceaccount.com"
	path := writeCredentialFile(t, fmt.Sprintf(`{
  "type": "service_account",
  "client_email": %q,
  "private_key_id": "fixture-key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n",
  "token_uri": "https://oauth2.googleapis.com/token"
}`, baseIdentity), 0o600)
	setLegacyCredentialsPath(t, path)

	sawTargetCall := false
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"access_token":"base-token","token_type":"Bearer","expires_in":3600}`
		if strings.Contains(req.URL.Path, ":generateAccessToken") {
			sawTargetCall = true
			body = `{"accessToken":"target-token","expireTime":"2099-01-01T00:00:00Z"}`
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Transport: transport})

	selector := Selector{
		CredentialsSource:       CredentialsSourceApplicationDefault,
		CredentialsProfile:      CredentialsProfileDeviceServiceAccount,
		CredentialsIdentity:     targetIdentity,
		CredentialsBaseIdentity: baseIdentity,
	}
	ts, err := selector.TokenSource(ctx, CloudPlatformScope)
	if err != nil {
		t.Fatalf("TokenSource() unexpected error: %v", err)
	}
	token, err := ts.Token()
	if err != nil {
		t.Fatalf("Token() unexpected error: %v", err)
	}
	if token == nil || token.AccessToken != "target-token" {
		t.Fatalf("Token() = %#v, want target-token", token)
	}
	if !sawTargetCall {
		t.Fatal("TokenSource() never called IAMCredentials generateAccessToken for the target identity")
	}
}

func TestDeviceServiceAccountTokenSourceRejectsWrongAccountCarrier(t *testing.T) {
	targetIdentity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	baseIdentity := "workstation-caller@example-gcp-project.iam.gserviceaccount.com"
	// The file at the resolved path claims to belong to a different account
	// than the one named in config — must fail closed rather than silently
	// impersonating using the wrong device's credential.
	path := writeCredentialFile(t, `{
  "type": "service_account",
  "client_email": "someone-else@fixture-project.iam.gserviceaccount.com",
  "private_key_id": "fixture-key-id",
  "private_key": "fixture",
  "token_uri": "https://oauth2.googleapis.com/token"
}`, 0o600)
	setLegacyCredentialsPath(t, path)

	selector := Selector{
		CredentialsSource:       CredentialsSourceApplicationDefault,
		CredentialsProfile:      CredentialsProfileDeviceServiceAccount,
		CredentialsIdentity:     targetIdentity,
		CredentialsBaseIdentity: baseIdentity,
	}
	if _, err := selector.TokenSource(context.Background(), CloudPlatformScope); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("TokenSource() error = %v, want client_email mismatch refusal", err)
	}
}

func TestDefaultADCPathResolvesWellKnownLocationForCurrentOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Run("missing_appdata", func(t *testing.T) {
			t.Setenv("APPDATA", "")
			if _, err := defaultADCPath(); err == nil || !strings.Contains(err.Error(), "APPDATA is required") {
				t.Fatalf("defaultADCPath() error = %v, want APPDATA requirement", err)
			}
		})
		t.Run("resolves_from_appdata", func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("APPDATA", root)
			got, err := defaultADCPath()
			if err != nil {
				t.Fatalf("defaultADCPath() unexpected error: %v", err)
			}
			if want := filepath.Join(root, "gcloud", "application_default_credentials.json"); got != want {
				t.Fatalf("defaultADCPath() = %q, want %q", got, want)
			}
		})
		return
	}
	t.Run("missing_home", func(t *testing.T) {
		t.Setenv("HOME", "")
		if _, err := defaultADCPath(); err == nil || !strings.Contains(err.Error(), "HOME is required") {
			t.Fatalf("defaultADCPath() error = %v, want HOME requirement", err)
		}
	})
	t.Run("resolves_from_home", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HOME", root)
		got, err := defaultADCPath()
		if err != nil {
			t.Fatalf("defaultADCPath() unexpected error: %v", err)
		}
		if want := filepath.Join(root, ".config", "gcloud", "application_default_credentials.json"); got != want {
			t.Fatalf("defaultADCPath() = %q, want %q", got, want)
		}
	})
}

func TestLegacyCredentialsPathResolvesWellKnownLocationForCurrentOS(t *testing.T) {
	const account = "workstation-caller@example-gcp-project.iam.gserviceaccount.com"
	if runtime.GOOS == "windows" {
		t.Run("missing_appdata", func(t *testing.T) {
			t.Setenv("APPDATA", "")
			if _, err := legacyCredentialsPath(account); err == nil || !strings.Contains(err.Error(), "APPDATA is required") {
				t.Fatalf("legacyCredentialsPath() error = %v, want APPDATA requirement", err)
			}
		})
		t.Run("resolves_from_appdata", func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("APPDATA", root)
			got, err := legacyCredentialsPath(account)
			if err != nil {
				t.Fatalf("legacyCredentialsPath() unexpected error: %v", err)
			}
			if want := filepath.Join(root, "gcloud", "legacy_credentials", account, "adc.json"); got != want {
				t.Fatalf("legacyCredentialsPath() = %q, want %q", got, want)
			}
		})
		return
	}
	t.Run("missing_home", func(t *testing.T) {
		t.Setenv("HOME", "")
		if _, err := legacyCredentialsPath(account); err == nil || !strings.Contains(err.Error(), "HOME is required") {
			t.Fatalf("legacyCredentialsPath() error = %v, want HOME requirement", err)
		}
	})
	t.Run("resolves_from_home", func(t *testing.T) {
		root := t.TempDir()
		t.Setenv("HOME", root)
		got, err := legacyCredentialsPath(account)
		if err != nil {
			t.Fatalf("legacyCredentialsPath() unexpected error: %v", err)
		}
		if want := filepath.Join(root, ".config", "gcloud", "legacy_credentials", account, "adc.json"); got != want {
			t.Fatalf("legacyCredentialsPath() = %q, want %q", got, want)
		}
	})
}

func TestProductionMetadataClientAndComputeTokenSourceWiringConstructNonNilValues(t *testing.T) {
	// The production defaults are always overridden by fixtures elsewhere in
	// this package's tests; exercise the real closures directly so the
	// default wiring itself — never invoked end-to-end anywhere else — stays
	// proven. Neither call performs network I/O: both libraries construct a
	// lazy token source/client and defer any request until Token() (or an
	// equivalent method) is later invoked, which this test deliberately never
	// does.
	if client := newMetadataClient(); client == nil {
		t.Fatal("newMetadataClient() returned nil")
	}
	if source := computeTokenSource("graph-test-runtime@fixture-project.iam.gserviceaccount.com", CloudPlatformScope); source == nil {
		t.Fatal("computeTokenSource() returned nil")
	}
}

func TestSelectorValidateDefaultsEmptyLabel(t *testing.T) {
	err := Selector{}.Validate("", false)
	if err == nil || !strings.Contains(err.Error(), "google_credentials: credentials_source=application_default is required") {
		t.Fatalf("Validate(empty label) error = %v, want default label in message", err)
	}
}

func TestTokenSourceRejectsNilAndCanceledContextBeforeCredentialConstruction(t *testing.T) {
	t.Setenv("GODEBUG", "")
	selector := Selector{
		CredentialsSource:   CredentialsSourceApplicationDefault,
		CredentialsProfile:  CredentialsProfileAttachedServiceAccount,
		CredentialsIdentity: "graph-test-operator@fixture-project.iam.gserviceaccount.com",
	}

	t.Run("nil_context", func(t *testing.T) {
		var nilCtx context.Context
		if _, err := selector.TokenSource(nilCtx); err == nil || !strings.Contains(err.Error(), "context is required") {
			t.Fatalf("TokenSource(nil) error = %v, want context-required refusal", err)
		}
	})

	t.Run("canceled_context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := selector.TokenSource(ctx); err == nil || !strings.Contains(err.Error(), "google credentials context:") {
			t.Fatalf("TokenSource(canceled) error = %v, want context cancellation refusal", err)
		}
	})
}

func TestTokenSourceSurfacesSelectorValidationFailure(t *testing.T) {
	t.Setenv("GODEBUG", "")
	if _, err := (Selector{}).TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "credentials_source=application_default is required") {
		t.Fatalf("TokenSource(invalid selector) error = %v, want validation failure", err)
	}
}

func TestImpersonatedTokenSourceSurfacesDefaultADCPathResolutionFailure(t *testing.T) {
	identity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	original := defaultADCPath
	defaultADCPath = func() (string, error) {
		return "", fmt.Errorf("fixture: well-known ADC carrier is unavailable")
	}
	t.Cleanup(func() { defaultADCPath = original })
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("CLOUDSDK_CONFIG", "")

	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileImpersonatedServiceAccount, CredentialsIdentity: identity}
	if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "resolve well-known impersonated ADC carrier") {
		t.Fatalf("TokenSource() error = %v, want ADC path resolution failure", err)
	}
}

func TestImpersonatedTokenSourceRejectsAmbientOverrideWithExplicitCredentialsFile(t *testing.T) {
	identity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	path := writeCredentialFile(t, `{}`, 0o600)
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/ambient.json")

	selector := Selector{CredentialsFile: path, CredentialsProfile: CredentialsProfileImpersonatedServiceAccount, CredentialsIdentity: identity}
	if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "GOOGLE_APPLICATION_CREDENTIALS must be unset when credentials_file is selected explicitly") {
		t.Fatalf("TokenSource() error = %v, want explicit-file ambient override refusal", err)
	}
}

func TestAttachedTokenSourceSurfacesMetadataEmailLookupFailure(t *testing.T) {
	identity := "task-graph-runtime@example-gcp-project.iam.gserviceaccount.com"
	originalMetadata := newMetadataClient
	t.Cleanup(func() { newMetadataClient = originalMetadata })
	newMetadataClient = func() metadataClient {
		return fakeMetadataClient{onGCE: true, err: fmt.Errorf("fixture: metadata email lookup failed")}
	}
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("GCE_METADATA_HOST", "")

	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileAttachedServiceAccount, CredentialsIdentity: identity}
	if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "resolve attached metadata identity") {
		t.Fatalf("TokenSource() error = %v, want metadata identity resolution failure", err)
	}
}

func TestAttachedTokenSourceSurfacesUnavailableComputeTokenSource(t *testing.T) {
	identity := "task-graph-runtime@example-gcp-project.iam.gserviceaccount.com"
	originalMetadata := newMetadataClient
	originalCompute := computeTokenSource
	t.Cleanup(func() {
		newMetadataClient = originalMetadata
		computeTokenSource = originalCompute
	})
	newMetadataClient = func() metadataClient { return fakeMetadataClient{onGCE: true, email: identity} }
	computeTokenSource = func(string, ...string) oauth2.TokenSource { return nil }
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "")
	t.Setenv("GCE_METADATA_HOST", "")

	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileAttachedServiceAccount, CredentialsIdentity: identity}
	if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "metadata token source is unavailable") {
		t.Fatalf("TokenSource() error = %v, want unavailable metadata token source refusal", err)
	}
}

func TestDeviceServiceAccountTokenSourceSurfacesLegacyPathResolutionFailure(t *testing.T) {
	targetIdentity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	baseIdentity := "workstation-caller@example-gcp-project.iam.gserviceaccount.com"
	original := legacyCredentialsPath
	legacyCredentialsPath = func(string) (string, error) {
		return "", fmt.Errorf("fixture: device base identity carrier path is unavailable")
	}
	t.Cleanup(func() { legacyCredentialsPath = original })

	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileDeviceServiceAccount, CredentialsIdentity: targetIdentity, CredentialsBaseIdentity: baseIdentity}
	if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "resolve device base identity carrier") {
		t.Fatalf("TokenSource() error = %v, want legacy path resolution failure", err)
	}
}

func TestDeviceServiceAccountTokenSourceSurfacesMissingLegacyCarrier(t *testing.T) {
	targetIdentity := "graph-test-operator@fixture-project.iam.gserviceaccount.com"
	baseIdentity := "workstation-caller@example-gcp-project.iam.gserviceaccount.com"
	setLegacyCredentialsPath(t, filepath.Join(t.TempDir(), "missing-legacy-adc.json"))

	selector := Selector{CredentialsSource: CredentialsSourceApplicationDefault, CredentialsProfile: CredentialsProfileDeviceServiceAccount, CredentialsIdentity: targetIdentity, CredentialsBaseIdentity: baseIdentity}
	if _, err := selector.TokenSource(context.Background()); err == nil || !strings.Contains(err.Error(), "read device base identity carrier") {
		t.Fatalf("TokenSource() error = %v, want missing legacy carrier refusal", err)
	}
}

func setLegacyCredentialsPath(t *testing.T, path string) {
	t.Helper()
	original := legacyCredentialsPath
	legacyCredentialsPath = func(string) (string, error) { return path, nil }
	t.Cleanup(func() { legacyCredentialsPath = original })
}

func writeCredentialFile(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "adc.json")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	ensureCredentialFixtureOwnedByCurrentUser(t, path)
	return path
}

func setDefaultADCPath(t *testing.T, path string) {
	t.Helper()
	original := defaultADCPath
	defaultADCPath = func() (string, error) { return path, nil }
	t.Cleanup(func() { defaultADCPath = original })
}
