package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
)

// commandAdmin is the narrow Spanner Admin surface used by init/reset. Keeping
// the command boundary behind this interface lets the destructive guards be
// tested without opening a network client or touching a database.
type commandAdmin interface {
	Close() error
	CreateDatabase(context.Context, string) error
	DropDatabase(context.Context, string) error
	ApplyDDL(context.Context, string, []string) error
}

type commandDependencies struct {
	loadConfig func() (SpecGraphConfig, error)
	newRouter  func(SpecGraphConfig) SubstrateRouter
	newAdmin   func(context.Context, SpecGraphConfig) (commandAdmin, error)
	readFile   func(string) ([]byte, error)
	absPath    func(string) (string, error)
	stdout     io.Writer
	stderr     io.Writer
}

func productionCommandDependencies() commandDependencies {
	return commandDependencies{
		loadConfig: loadConfig,
		newRouter: func(cfg SpecGraphConfig) SubstrateRouter {
			return newRouter(cfg.GoogleCredentials, cfg.AllowSpannerEmulator, cfg.Substrates)
		},
		newAdmin: func(ctx context.Context, cfg SpecGraphConfig) (commandAdmin, error) {
			return newAdminClient(ctx, cfg.GoogleCredentials, cfg.AllowSpannerEmulator)
		},
		readFile: os.ReadFile,
		absPath:  filepath.Abs,
		stdout:   os.Stdout,
		stderr:   os.Stderr,
	}
}
