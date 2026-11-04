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

const (
	featureGraphConfigByteCap = 1 << 20
	featureGraphInputByteCap  = 32 << 20
)

type featureGraphPublishConfig struct {
	featuregraphprojection.Config
	GoogleCredentials    gcpauth.Selector `json:"google_credentials"`
	AllowSpannerEmulator bool             `json:"allow_spanner_emulator"`
}

// cmdFeatureGraphPublish creates or applies an explicit, digest-pinned
// evidence projection. It has no graph-wide discovery mode.
func cmdFeatureGraphPublish(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("featuregraph-publish", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "explicit operator config JSON")
	selectionPath := flags.String("selection", "", "explicit selected FeatureGraph IDs JSON")
	manifestPath := flags.String("manifest", "", "plan output / apply input JSON")
	expected := flags.String("expected-manifest-sha256", "", "required for apply")
	apply := flags.Bool("apply", false, "write exactly the pinned plan")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(flags.Args()) != 0 {
		return fmt.Errorf("featuregraph-publish: unexpected positional arguments")
	}
	if *configPath == "" || *manifestPath == "" || (!*apply && *selectionPath == "") || (*apply && *expected == "") {
		return fmt.Errorf("featuregraph-publish: --config, --manifest, and the mode-specific required flags are required")
	}
	if (*apply && *selectionPath != "") || (!*apply && *expected != "") {
		return fmt.Errorf("featuregraph-publish: --selection is plan-only and --expected-manifest-sha256 is apply-only")
	}

	var cfg featureGraphPublishConfig
	if err := featureGraphDecode(*configPath, featureGraphConfigByteCap, &cfg); err != nil {
		return err
	}
	if err := cfg.Config.Validate(); err != nil {
		return err
	}
	if err := cfg.GoogleCredentials.Validate("featuregraph-publish", !cfg.AllowSpannerEmulator); err != nil {
		return err
	}
	adapter := &SpannerSubstrateAdapter{
		Descriptor:    SubstrateDescriptor{ID: "featuregraph-evidence", SpannerDatabase: cfg.Database},
		Credentials:   cfg.GoogleCredentials,
		AllowEmulator: cfg.AllowSpannerEmulator,
	}
	client, err := adapter.getClient(ctx)
	if err != nil {
		return err
	}
	defer adapter.Close()
	store, err := featuregraphprojection.NewSpannerStore(client, cfg.MaxBytes)
	if err != nil {
		return err
	}
	if *apply {
		var manifest featuregraphprojection.Manifest
		if err := featureGraphDecode(*manifestPath, cfg.MaxBytes, &manifest); err != nil {
			return err
		}
		receipt, err := featuregraphprojection.Apply(ctx, cfg.Config, store, featuregraphprojection.GitReader{}, manifest, *expected)
		if err != nil {
			return err
		}
		return featureGraphEmit(receipt)
	}
	var selection featuregraphprojection.Selection
	if err := featureGraphDecode(*selectionPath, cfg.MaxBytes, &selection); err != nil {
		return err
	}
	manifest, err := featuregraphprojection.Plan(ctx, cfg.Config, store, featuregraphprojection.GitReader{}, selection)
	if err != nil {
		return err
	}
	return featureGraphWriteJSON(*manifestPath, manifest)
}

func featureGraphDecode(name string, limit int, out any) error {
	b, err := featureGraphReadFile(name, limit)
	if err != nil {
		return err
	}
	return featuregraphprojection.DecodeStrict(b, out)
}

func featureGraphReadFile(name string, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("featuregraph-publish: byte cap must be positive")
	}
	if limit > featureGraphInputByteCap {
		limit = featureGraphInputByteCap
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > int64(featureGraphInputByteCap) {
		return nil, fmt.Errorf("featuregraph-publish: %s exceeds absolute input byte cap", name)
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("featuregraph-publish: %s exceeds byte cap", name)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("featuregraph-publish: %s exceeds byte cap", name)
	}
	return b, nil
}

func featureGraphWriteJSON(name string, value any) error {
	b, err := featureGraphCanonicalJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(name, append(b, '\n'), 0o600)
}

func featureGraphEmit(value any) error {
	b, err := featureGraphCanonicalJSON(value)
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(b))
	return err
}

func featureGraphCanonicalJSON(value any) ([]byte, error) {
	b, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return featuregraphprojection.CanonicalJSON(b)
}
