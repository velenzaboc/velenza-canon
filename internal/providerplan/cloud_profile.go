package providerplan

// Cloud API profiles are declarative, reusable connection-shape contracts.
// They intentionally describe neither a customer credential nor a tenant grant.
// The production source-qualification boundary owns those separate authorities.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const cloudAPIProfileVersion = "1"

type CloudAPIProfileDocument struct {
	ProfileSetID string                    `json:"profile_set_id"`
	Version      string                    `json:"version"`
	Providers    []CloudProviderAPIProfile `json:"providers"`
}

// CloudProviderAPIProfile is the reusable outer profile.  Authentication is a
// protocol declaration only; credential selection remains Connector Vault and
// tenant authorization work.
type CloudProviderAPIProfile struct {
	ProviderID     string                    `json:"provider_id"`
	ProfileID      string                    `json:"profile_id"`
	ProfileVersion string                    `json:"profile_version"`
	Authentication CloudAuthenticationShape  `json:"authentication"`
	Services       []CloudServiceAPIResidual `json:"services"`
	Evidence       []CloudProfileEvidence    `json:"evidence"`
}

type CloudAuthenticationShape struct {
	Protocol                 string   `json:"protocol"`
	CredentialCarrier        string   `json:"credential_carrier"`
	AudienceOrSigningScope   string   `json:"audience_or_signing_scope"`
	EligibleCredentialOwners []string `json:"eligible_credential_owners"`
}

// CloudServiceAPIResidual only adds service-local transport requirements.  It
// cannot replace its provider's authentication shape or widen credential
// eligibility.
type CloudServiceAPIResidual struct {
	ServiceID          string                     `json:"service_id"`
	APISurfaceID       string                     `json:"api_surface_id"`
	APIVersion         string                     `json:"api_version"`
	CatalogModelSHA256 string                     `json:"catalog_model_sha256"`
	ProfileID          string                     `json:"profile_id"`
	ProfileVersion     string                     `json:"profile_version"`
	ProviderProfileRef CloudProfileReference      `json:"provider_profile_ref"`
	Endpoint           CloudEndpointShape         `json:"endpoint"`
	Retry              CloudRetryShape            `json:"retry"`
	Operations         []CloudOperationAPIProfile `json:"operations"`
	Evidence           []CloudProfileEvidence     `json:"evidence"`
}

type CloudProfileReference struct {
	ProviderID     string `json:"provider_id"`
	ProfileID      string `json:"profile_id"`
	ProfileVersion string `json:"profile_version"`
}

type CloudEndpointShape struct {
	PartitionMode      string   `json:"partition_mode"`
	RegionMode         string   `json:"region_mode"`
	SigningName        string   `json:"signing_name,omitempty"`
	BaseURL            string   `json:"base_url"`
	AuthorityTemplates []string `json:"authority_templates"`
}

type CloudPaginationShape struct {
	RequestTokenField     string `json:"request_token_field,omitempty"`
	ResponseTokenField    string `json:"response_token_field,omitempty"`
	RequestTokenWireName  string `json:"request_token_wire_name,omitempty"`
	ResponseTokenWireName string `json:"response_token_wire_name,omitempty"`
	Required              bool   `json:"required"`
}

type CloudRetryShape struct {
	Classifications      []string `json:"classifications"`
	IdempotentRead       bool     `json:"idempotent_read"`
	MaxAttempts          int      `json:"max_attempts"`
	InitialBackoffMillis int64    `json:"initial_backoff_millis"`
	MaxBackoffMillis     int64    `json:"max_backoff_millis"`
	Jitter               string   `json:"jitter"`
}

type CloudOperationAPIProfile struct {
	OperationID string               `json:"operation_id"`
	ResourceIDs []string             `json:"resource_ids"`
	Route       CloudOperationRoute  `json:"route"`
	Pagination  CloudPaginationShape `json:"pagination"`
	// AcceptedScopes is an alternative set: one eligible scope is sufficient
	// when the provider documents multiple OAuth authorization options. It is
	// never an instruction to request every listed scope.
	AcceptedScopes      []string                    `json:"accepted_scopes"`
	RequiredPermissions []string                    `json:"required_permissions"`
	Evidence            []CloudProfileEvidence      `json:"evidence"`
	ModelEvidence       CloudOperationModelEvidence `json:"model_evidence"`
}

type CloudOperationModelEvidence struct {
	Locator             CloudCatalogEvidenceLocator `json:"locator"`
	SelectedRangeSHA256 string                      `json:"selected_range_sha256"`
}

type CloudOperationRoute struct {
	Method            string            `json:"method"`
	AuthorityTemplate string            `json:"authority_template"`
	PathTemplate      string            `json:"path_template"`
	RequiredSelectors []string          `json:"required_selectors"`
	QueryTemplates    map[string]string `json:"query_templates"`
}

// CloudProfileEvidence is a documentation coordinate, not an authority
// receipt.  Production qualification must hydrate and verify documentation via
// the OOD-owned evidence path.
type CloudProfileEvidence struct {
	URI              string `json:"uri"`
	StableCoordinate string `json:"stable_coordinate"`
	ExpectedSHA256   string `json:"expected_sha256"`
	Subject          string `json:"subject"`
	Retrieved        string `json:"retrieved,omitempty"`
	LocalPath        string `json:"local_path"`
	ByteCount        int64  `json:"byte_count"`
}

func LoadCloudAPIProfileDocument(path string) (CloudAPIProfileDocument, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CloudAPIProfileDocument{}, err
	}
	var document CloudAPIProfileDocument
	if err := strictUnmarshal(raw, &document); err != nil {
		return CloudAPIProfileDocument{}, fmt.Errorf("decode cloud API profiles: %w", err)
	}
	// Capture bytes are local immutable candidates. Exact byte checks do not
	// authenticate the producer or substitute for OOD source qualification.
	checked := map[string]string{}
	check := func(evidence []CloudProfileEvidence) error {
		if !validateProfileEvidence(evidence) {
			return fmt.Errorf("profile evidence requires exact retained byte pins")
		}
		for _, item := range evidence {
			if previous, ok := checked[item.LocalPath]; ok && previous != item.ExpectedSHA256 {
				return fmt.Errorf("profile evidence path has conflicting pins")
			}
			resolved, err := cloudCandidateLocalPath(filepath.Dir(path), item.LocalPath)
			if err != nil {
				return err
			}
			body, err := os.ReadFile(resolved)
			if err != nil {
				return err
			}
			if int64(len(body)) != item.ByteCount || sha256Hex(body) != item.ExpectedSHA256 {
				return fmt.Errorf("profile evidence bytes differ from exact pin")
			}
			checked[item.LocalPath] = item.ExpectedSHA256
		}
		return nil
	}
	for _, provider := range document.Providers {
		if err := check(provider.Evidence); err != nil {
			return CloudAPIProfileDocument{}, err
		}
		for _, service := range provider.Services {
			if err := check(service.Evidence); err != nil {
				return CloudAPIProfileDocument{}, err
			}
			for _, operation := range service.Operations {
				if err := check(operation.Evidence); err != nil {
					return CloudAPIProfileDocument{}, err
				}
			}
		}
	}
	return document, nil
}

// CanonicalCloudAPIProfileDocument returns a deterministic profile artifact
// suitable for a surrounding evidence manifest.  It deliberately does not
// mint an admission or source-authority receipt.
func CanonicalCloudAPIProfileDocument(document CloudAPIProfileDocument) ([]byte, error) {
	if err := ValidateCloudAPIProfileDocument(document, nil, nil); err != nil {
		return nil, err
	}
	return canonicalFactoryJSON(document)
}

// ValidateCloudAPIProfileDocument verifies generic composition rules. When
// catalogs and targets are supplied, every selected operation must have one,
// and only one, compatible provider/service/operation profile.
func ValidateCloudAPIProfileDocument(document CloudAPIProfileDocument, catalogs []CloudCatalog, targets []CloudSourceObjectTarget) error {
	if !profileText(document.ProfileSetID, 256) || document.Version != cloudAPIProfileVersion || len(document.Providers) == 0 {
		return fmt.Errorf("cloud API profile document has an invalid identity")
	}
	providers := map[string]CloudProviderAPIProfile{}
	services := map[string]CloudServiceAPIResidual{}
	operations := map[string]CloudOperationAPIProfile{}
	for _, provider := range document.Providers {
		if err := validateCloudProviderAPIProfile(provider); err != nil {
			return err
		}
		if _, duplicate := providers[provider.ProviderID]; duplicate {
			return fmt.Errorf("duplicate provider profile %q", provider.ProviderID)
		}
		providers[provider.ProviderID] = provider
		for _, service := range provider.Services {
			serviceKey := cloudCatalogKey(provider.ProviderID, service.ServiceID, service.APISurfaceID)
			if _, duplicate := services[serviceKey]; duplicate {
				return fmt.Errorf("duplicate service residual %q", serviceKey)
			}
			services[serviceKey] = service
			for _, operation := range service.Operations {
				key := cloudProfileOperationKey(provider.ProviderID, service.ServiceID, service.APISurfaceID, operation.OperationID)
				if _, duplicate := operations[key]; duplicate {
					return fmt.Errorf("duplicate operation profile %q", key)
				}
				operations[key] = operation
			}
		}
	}
	if len(catalogs) != 0 {
		if len(catalogs) != len(services) {
			return fmt.Errorf("profile service roster differs from exact catalog roster")
		}
		for _, catalog := range catalogs {
			key := cloudCatalogKey(catalog.ProviderID, catalog.ServiceID, catalog.APISurfaceID)
			service, found := services[key]
			if !found {
				return fmt.Errorf("pinned catalog %q has no profile residual", key)
			}
			if service.APIVersion != catalog.APIVersion || service.CatalogModelSHA256 != catalog.ModelSHA256 {
				return fmt.Errorf("profile residual %q does not match pinned catalog API/model version", key)
			}
			for _, operation := range service.Operations {
				if err := validateCloudOperationModelBinding(operation, service, catalog); err != nil {
					return fmt.Errorf("profile operation %q model binding: %w", operation.OperationID, err)
				}
			}
		}
	}
	seenTargets := map[string]struct{}{}
	for _, target := range targets {
		key := cloudProfileOperationKey(target.ProviderID, target.ServiceID, target.APISurfaceID, target.OperationID)
		operation, found := operations[key]
		if !found {
			return fmt.Errorf("selected operation %q has no API profile", key)
		}
		if _, repeated := seenTargets[key]; repeated {
			return fmt.Errorf("selected operation %q repeats", key)
		}
		seenTargets[key] = struct{}{}
		if !containsCloudProfileString(operation.ResourceIDs, target.SourceObjectType) {
			return fmt.Errorf("operation profile %q does not bind resource %q", key, target.SourceObjectType)
		}
	}
	if len(targets) != 0 && len(operations) != len(seenTargets) {
		return fmt.Errorf("profile operation roster does not exactly equal selected target roster")
	}
	return nil
}

func validateCloudProviderAPIProfile(provider CloudProviderAPIProfile) error {
	if !profileText(provider.ProviderID, 64) || !profileText(provider.ProfileID, 256) || !validCloudProfileRevision(provider.ProfileVersion) || len(provider.Services) == 0 {
		return fmt.Errorf("provider profile identity is invalid")
	}
	auth := provider.Authentication
	if !profileText(auth.Protocol, 128) || !profileText(auth.CredentialCarrier, 128) || !profileText(auth.AudienceOrSigningScope, 1024) || len(auth.EligibleCredentialOwners) == 0 {
		return fmt.Errorf("provider %q authentication shape is invalid", provider.ProviderID)
	}
	if !equalCloudProfileStrings(auth.EligibleCredentialOwners, []string{"connector_vault", "tenant_grant"}) || !validateProfileEvidence(provider.Evidence) {
		return fmt.Errorf("provider %q has invalid credential-owner or evidence references", provider.ProviderID)
	}
	for _, service := range provider.Services {
		if err := validateCloudServiceAPIResidual(provider, service); err != nil {
			return err
		}
	}
	return nil
}

func equalCloudProfileStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return strictSortedUniqueProfileStrings(left, 256)
}

func validateCloudServiceAPIResidual(provider CloudProviderAPIProfile, service CloudServiceAPIResidual) error {
	if !profileText(service.ServiceID, 128) || !profileText(service.APISurfaceID, 128) || !profileText(service.APIVersion, 256) || !isLowerSHA256(service.CatalogModelSHA256) || !profileText(service.ProfileID, 256) || !validCloudProfileRevision(service.ProfileVersion) || len(service.Operations) == 0 {
		return fmt.Errorf("provider %q has invalid service residual", provider.ProviderID)
	}
	if service.ProviderProfileRef != (CloudProfileReference{ProviderID: provider.ProviderID, ProfileID: provider.ProfileID, ProfileVersion: provider.ProfileVersion}) {
		return fmt.Errorf("service %q does not exactly reference provider %q profile", service.ServiceID, provider.ProviderID)
	}
	endpoint := service.Endpoint
	if !profileText(endpoint.PartitionMode, 128) || !profileText(endpoint.RegionMode, 128) || !profileText(endpoint.BaseURL, 2048) || !profileText(endpoint.SigningName, 128) || !strictSortedUniqueProfileStrings(endpoint.AuthorityTemplates, 253) {
		return fmt.Errorf("service %q endpoint shape is invalid", service.ServiceID)
	}
	if validateCloudRetryPolicy(service.Retry) != nil || !validateProfileEvidence(service.Evidence) {
		return fmt.Errorf("service %q retry or evidence shape is invalid", service.ServiceID)
	}
	seen := map[string]struct{}{}
	for _, operation := range service.Operations {
		if !containsCloudProfileString(endpoint.AuthorityTemplates, operation.Route.AuthorityTemplate) {
			return fmt.Errorf("operation authority differs from shared service endpoint contract")
		}
		if err := validateCloudOperationRoute(operation.Route); err != nil {
			return fmt.Errorf("operation %q route: %w", operation.OperationID, err)
		}
		if operation.ModelEvidence.Locator.EvidenceID != "model" || operation.ModelEvidence.Locator.JSONPointer == "" || operation.ModelEvidence.Locator.StartByte < 0 || operation.ModelEvidence.Locator.EndByte <= operation.ModelEvidence.Locator.StartByte || !isLowerSHA256(operation.ModelEvidence.SelectedRangeSHA256) {
			return fmt.Errorf("operation profile requires exact model evidence")
		}
		if !profileText(operation.OperationID, 512) || len(operation.ResourceIDs) == 0 || !strictSortedUniqueProfileStrings(operation.ResourceIDs, 512) || !strictSortedUniqueProfileStrings(operation.AcceptedScopes, 2048) || !strictSortedUniqueProfileStrings(operation.RequiredPermissions, 512) || !validateProfileEvidence(operation.Evidence) {
			return fmt.Errorf("service %q operation profile is invalid", service.ServiceID)
		}
		if operation.Pagination.Required && (!profileText(operation.Pagination.RequestTokenField, 256) || !profileText(operation.Pagination.ResponseTokenField, 256) || !profileText(operation.Pagination.RequestTokenWireName, 256) || !profileText(operation.Pagination.ResponseTokenWireName, 256)) {
			return fmt.Errorf("service %q operation %q has incomplete required pagination", service.ServiceID, operation.OperationID)
		}
		if !operation.Pagination.Required && (operation.Pagination.RequestTokenField != "" || operation.Pagination.ResponseTokenField != "" || operation.Pagination.RequestTokenWireName != "" || operation.Pagination.ResponseTokenWireName != "") {
			return fmt.Errorf("service %q operation %q declares pagination fields without pagination", service.ServiceID, operation.OperationID)
		}
		if _, duplicate := seen[operation.OperationID]; duplicate {
			return fmt.Errorf("service %q duplicates operation %q", service.ServiceID, operation.OperationID)
		}
		seen[operation.OperationID] = struct{}{}
	}
	return nil
}

// Payload schema version and immutable profile revision are different axes.
// A successor profile using this schema must not require a Go code change.
func validCloudProfileRevision(value string) bool {
	if len(value) == 0 || len(value) > 20 || value[0] < '1' || value[0] > '9' {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func validateProfileEvidence(evidence []CloudProfileEvidence) bool {
	if len(evidence) == 0 {
		return false
	}
	for _, item := range evidence {
		if !strings.HasPrefix(item.URI, "https://") || !profileText(item.Subject, 1024) {
			return false
		}
		if !profileText(item.StableCoordinate, 1024) || !isLowerSHA256(item.ExpectedSHA256) || item.LocalPath == "" || item.ByteCount <= 0 {
			return false
		}
	}
	return true
}

func strictSortedUniqueProfileStrings(values []string, max int) bool {
	if len(values) == 0 || !sort.StringsAreSorted(values) {
		return false
	}
	for i, value := range values {
		if !profileText(value, max) || (i != 0 && values[i-1] == value) {
			return false
		}
	}
	return true
}

func profileText(value string, max int) bool {
	return canonicalEvidenceMetadataString(value, max)
}

func containsCloudProfileString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func cloudProfileOperationKey(provider, service, api, operation string) string {
	return cloudCatalogKey(provider, service, api) + "\x00" + operation
}
