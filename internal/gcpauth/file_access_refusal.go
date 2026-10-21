package gcpauth

import (
	"fmt"
	"os"
)

// unsupportedCredentialFileAccess is the credential-file-access refusal for
// any operating system this package has no dedicated ownership/permission
// check for (see file_access_unix.go and file_access_windows.go for the two
// operating systems that do have one). It carries no build constraint so
// every coverage-gated platform compiles and instruments it; only the var
// assignment that wires it in as validateCredentialFileAccess, in
// file_access_unsupported.go, stays build-constrained to the platforms that
// actually use it at runtime.
func unsupportedCredentialFileAccess(_ *os.File, _ os.FileInfo) error {
	return fmt.Errorf("credential file access validation is unsupported on this operating system")
}
