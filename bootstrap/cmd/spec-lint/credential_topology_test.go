package main

import (
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
)

func TestGoogleCredentialTopologyIsCentralAndFailClosed(t *testing.T) {
	valid := &Config{
		Mode: "experimental_bootstrap",
		GoogleCredentials: gcpauth.Selector{
			CredentialsSource:   gcpauth.CredentialsSourceApplicationDefault,
			CredentialsProfile:  gcpauth.CredentialsProfileImpersonatedServiceAccount,
			CredentialsIdentity: "spec-graph-local@example-gcp-project.iam.gserviceaccount.com",
		},
	}
	if err := valid.ValidateGoogleCredentialTopology(); err != nil {
		t.Fatalf("valid topology rejected: %v", err)
	}

	missing := *valid
	missing.GoogleCredentials = gcpauth.Selector{}
	if err := missing.ValidateGoogleCredentialTopology(); err == nil || !strings.Contains(err.Error(), "google_credentials") {
		t.Fatalf("missing central selector error = %v", err)
	}

	productionFile := *valid
	productionFile.Mode = "production"
	productionFile.GoogleCredentials = gcpauth.Selector{
		CredentialsFile:     "/tmp/legacy.json",
		CredentialsProfile:  gcpauth.CredentialsProfileImpersonatedServiceAccount,
		CredentialsIdentity: "spec-graph-runtime@example-project.iam.gserviceaccount.com",
	}
	if err := productionFile.ValidateGoogleCredentialTopology(); err == nil || !strings.Contains(err.Error(), "production requires credentials_source=application_default") {
		t.Fatalf("production credential-file error = %v", err)
	}
}

func TestGoogleCredentialTopologyKeepsModeAndProfileOrthogonal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     string
		profile  string
		identity string
	}{
		{name: "hosted bootstrap runtime", mode: "experimental_bootstrap", profile: gcpauth.CredentialsProfileAttachedServiceAccount, identity: "spec-graph-runtime@example-gcp-project.iam.gserviceaccount.com"},
		{name: "local production administration", mode: "production", profile: gcpauth.CredentialsProfileImpersonatedServiceAccount, identity: "spec-graph-local@example-gcp-project.iam.gserviceaccount.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				Mode: tc.mode,
				GoogleCredentials: gcpauth.Selector{
					CredentialsSource:   gcpauth.CredentialsSourceApplicationDefault,
					CredentialsProfile:  tc.profile,
					CredentialsIdentity: tc.identity,
				},
			}
			if err := cfg.ValidateGoogleCredentialTopology(); err != nil {
				t.Fatalf("explicit identity-bound profile rejected: %v", err)
			}
		})
	}
}

func TestFlashRejectsLegacyPerClientCredentialSelector(t *testing.T) {
	cfg := &FlashConfig{
		Provider:          "vertex_ai",
		Project:           "test-project",
		Location:          "us-central1",
		Model:             "gemini-2.0-flash",
		CredentialsSource: gcpauth.CredentialsSourceApplicationDefault,
		MaxOutputTokens:   100,
		Prompts:           &FlashPromptsConfig{R6ProseCheckPath: "/tmp/r6.txt"},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "legacy per-client credential selector") {
		t.Fatalf("legacy flash selector error = %v", err)
	}
}

func TestSpecLintLoadConfigRejectsHiddenCredentialSelector(t *testing.T) {
	data := []byte(`{"mode":"experimental_bootstrap","google_credentials":{"credentials_source":"application_default","credentials_profile":"impersonated_service_account","credentials_identity":"graph-test-operator@fixture-project.iam.gserviceaccount.com"},"pipeline":{"flash":{"credentials_file":"/tmp/hidden.json"}}}`)
	if _, err := LoadConfig(data); err == nil || !strings.Contains(err.Error(), "credentials_file") {
		t.Fatalf("LoadConfig() error = %v, want hidden credential rejection", err)
	}
}
