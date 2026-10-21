package main

import (
	"strings"
	"testing"

	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
)

func TestGoogleCredentialTopologyIsCentralAndFailClosed(t *testing.T) {
	valid := validCredentialConfig()
	if err := valid.Validate(); err == nil || !strings.Contains(err.Error(), "pipeline section required") {
		t.Fatalf("valid credential topology must reach downstream pipeline validation, got %v", err)
	}

	missing := validCredentialConfig()
	missing.GoogleCredentials = gcpauth.Selector{}
	if err := missing.Validate(); err == nil || !strings.Contains(err.Error(), "google_credentials") {
		t.Fatalf("missing central selector error = %v", err)
	}

	productionFile := validCredentialConfig()
	productionFile.Mode = "production"
	productionFile.GoogleCredentials = gcpauth.Selector{
		CredentialsFile:     "/tmp/legacy.json",
		CredentialsProfile:  gcpauth.CredentialsProfileImpersonatedServiceAccount,
		CredentialsIdentity: "spec-graph-runtime@example-project.iam.gserviceaccount.com",
	}
	if err := productionFile.Validate(); err == nil || !strings.Contains(err.Error(), "production requires credentials_source=application_default") {
		t.Fatalf("production credential-file error = %v", err)
	}
}

func TestGoogleCredentialTopologyKeepsModeAndProfileOrthogonal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    string
		profile string
	}{
		{name: "hosted bootstrap runtime", mode: "experimental_bootstrap", profile: gcpauth.CredentialsProfileAttachedServiceAccount},
		{name: "local production administration", mode: "production", profile: gcpauth.CredentialsProfileImpersonatedServiceAccount},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validCredentialConfig()
			cfg.Mode = tc.mode
			cfg.GoogleCredentials.CredentialsProfile = tc.profile
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "pipeline section required") {
				t.Fatalf("explicit identity-bound profile did not reach downstream validation: %v", err)
			}
		})
	}
}

func TestFlashRejectsLegacyPerClientCredentialSelector(t *testing.T) {
	cfg := validFlashConfig()
	cfg.CredentialsSource = gcpauth.CredentialsSourceApplicationDefault
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "legacy per-client credential selector") {
		t.Fatalf("legacy flash selector error = %v", err)
	}
}
