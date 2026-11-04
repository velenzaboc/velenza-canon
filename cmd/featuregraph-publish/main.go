// featuregraph-publish creates and applies an explicit, digest-pinned
// evidence projection. It has no graph-wide discovery mode.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/velenzaboc/velenza-canon/internal/featuregraphprojection"
	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
)

type fileConfig struct {
	featuregraphprojection.Config
	GoogleCredentials    gcpauth.Selector `json:"google_credentials"`
	AllowSpannerEmulator bool             `json:"allow_spanner_emulator"`
}

const configByteCap = 1 << 20

func main() {
	var configPath, selectionPath, manifestPath, expected string
	var apply bool
	flag.StringVar(&configPath, "config", "", "explicit operator config JSON")
	flag.StringVar(&selectionPath, "selection", "", "explicit selected FeatureGraph IDs JSON")
	flag.StringVar(&manifestPath, "manifest", "", "plan output / apply input JSON")
	flag.StringVar(&expected, "expected-manifest-sha256", "", "required for apply")
	flag.BoolVar(&apply, "apply", false, "write exactly the pinned plan")
	flag.Parse()
	if len(flag.Args()) != 0 {
		die(fmt.Errorf("unexpected positional arguments"))
	}
	if configPath == "" || manifestPath == "" || (!apply && selectionPath == "") || (apply && expected == "") {
		die(fmt.Errorf("--config, --manifest, and the mode-specific required flags are required"))
	}
	if (apply && selectionPath != "") || (!apply && expected != "") {
		die(fmt.Errorf("--selection is plan-only and --expected-manifest-sha256 is apply-only"))
	}
	var cfg fileConfig
	decode(configPath, configByteCap, &cfg)
	if err := cfg.Config.Validate(); err != nil {
		die(err)
	}
	if err := cfg.GoogleCredentials.Validate("featuregraph-publish", !cfg.AllowSpannerEmulator); err != nil {
		die(err)
	}
	ctx := context.Background()
	store, err := featuregraphprojection.NewSpannerStore(ctx, cfg.Database, cfg.GoogleCredentials, cfg.AllowSpannerEmulator)
	if err != nil {
		die(err)
	}
	defer store.Close()
	if apply {
		var m featuregraphprojection.Manifest
		decode(manifestPath, cfg.MaxBytes, &m)
		r, e := featuregraphprojection.Apply(ctx, cfg.Config, store, featuregraphprojection.GitReader{}, m, expected)
		if e != nil {
			die(e)
		}
		emit(r)
		return
	}
	var s featuregraphprojection.Selection
	decode(selectionPath, cfg.MaxBytes, &s)
	m, e := featuregraphprojection.Plan(ctx, cfg.Config, store, featuregraphprojection.GitReader{}, s)
	if e != nil {
		die(e)
	}
	writeJSON(manifestPath, m)
}
func decode(path string, limit int, out any) {
	b, e := readFile(path, limit)
	if e != nil {
		die(e)
	}
	if e = featuregraphprojection.DecodeStrict(b, out); e != nil {
		die(e)
	}
}

func readFile(name string, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("byte cap must be positive")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%s exceeds byte cap", name)
	}
	return b, nil
}
func die(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(2) }
func writeJSON(path string, v any) {
	b, e := featuregraphprojection.CanonicalJSON(mustJSON(v))
	if e != nil {
		die(e)
	}
	if e = os.WriteFile(path, append(b, '\n'), 0600); e != nil {
		die(e)
	}
}
func emit(v any) {
	b, e := featuregraphprojection.CanonicalJSON(mustJSON(v))
	if e != nil {
		die(e)
	}
	fmt.Println(string(b))
}

func mustJSON(v any) []byte {
	// Marshal through the standard encoder first; CanonicalJSON then supplies
	// deterministic key ordering and strict validation of its output.
	b, err := json.Marshal(v)
	if err != nil {
		die(err)
	}
	return b
}
