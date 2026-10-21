//go:build !windows && !linux && !darwin

package providerplan

type providerInputMutationToken struct{}

var currentProviderInputMutationToken = unsupportedProviderInputMutationToken
