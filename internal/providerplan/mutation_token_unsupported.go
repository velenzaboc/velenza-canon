package providerplan

import (
	"fmt"
	"os"
)

// unsupportedProviderInputMutationToken is the refusal used by every platform
// that exposes no trustworthy change-time equivalent. It carries no build
// constraint so the refusal itself is compiled and measured on a target the
// coverage gate actually runs, rather than living only in an unselected file.
func unsupportedProviderInputMutationToken(*os.File) (providerInputMutationToken, error) {
	return providerInputMutationToken{}, fmt.Errorf("platform does not expose a trustworthy provider-input mutation token")
}
