//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package gcpauth

// validateCredentialFileAccess on every other operating system refuses
// outright; see unsupportedCredentialFileAccess in file_access_refusal.go
// for why that refusal lives in its own unconstrained file.
var validateCredentialFileAccess = unsupportedCredentialFileAccess
