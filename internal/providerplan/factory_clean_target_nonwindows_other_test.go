//go:build !windows && !linux && !darwin

package providerplan

import (
	"fmt"
	"runtime"
)

func publishNonWindowsFactoryCleanTargetDirectory(int, string, string) error {
	return fmt.Errorf("%s has no configured atomic no-replace directory publication primitive; refusing", runtime.GOOS)
}
