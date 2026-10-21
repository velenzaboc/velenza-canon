//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	instance "cloud.google.com/go/spanner/admin/instance/apiv1"
	instancepb "cloud.google.com/go/spanner/admin/instance/apiv1/instancepb"
	"github.com/velenzaboc/velenza-canon/internal/gcpauth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// emulatorInstanceName is the instance every emulator-backed test targets.
var emulatorInstanceName = "projects/" + emulatorProject + "/instances/" + emulatorInstance

// emulatorInstanceConfig is the only instance configuration the pinned Cloud
// Spanner emulator image serves; GET /v1/projects/test-project/instanceConfigs
// on that image returns exactly this name.
var emulatorInstanceConfig = "projects/" + emulatorProject + "/instanceConfigs/emulator-config"

// ensureEmulatorInstance makes the integration tests own their emulator
// prerequisite. A bare emulator (the reusable CI coverage target starts one and
// exports SPANNER_EMULATOR_HOST without creating any instance) has no
// instances, so every database operation would fail with NotFound. The helper
// creates projects/test-project/instances/test-instance when it is absent and
// treats an existing or concurrently created instance as success.
//
// It refuses before constructing any client unless host is the one documented
// emulator authority accepted by gcpauth.ValidateSpannerEmulatorHost, so it can
// never issue an instance mutation against a real Spanner endpoint.
func ensureEmulatorInstance(ctx context.Context, host string) error {
	useEmulator, err := gcpauth.ValidateSpannerEmulatorHost(host, true)
	if err != nil {
		return fmt.Errorf("refusing to create a Spanner instance: %w", err)
	}
	if !useEmulator {
		return errors.New("refusing to create a Spanner instance: SPANNER_EMULATOR_HOST is empty, so the endpoint would not be the emulator")
	}
	if os.Getenv("SPANNER_EMULATOR_HOST") != host {
		return fmt.Errorf("refusing to create a Spanner instance: SPANNER_EMULATOR_HOST=%q does not match the validated emulator host %q", os.Getenv("SPANNER_EMULATOR_HOST"), host)
	}
	client, err := instance.NewInstanceAdminClient(ctx)
	if err != nil {
		return fmt.Errorf("instance admin client: %w", err)
	}
	defer client.Close()

	_, err = client.GetInstance(ctx, &instancepb.GetInstanceRequest{Name: emulatorInstanceName})
	switch status.Code(err) {
	case codes.OK:
		return nil
	case codes.NotFound:
	default:
		return fmt.Errorf("get instance %s: %w", emulatorInstanceName, err)
	}

	op, err := client.CreateInstance(ctx, &instancepb.CreateInstanceRequest{
		Parent:     "projects/" + emulatorProject,
		InstanceId: emulatorInstance,
		Instance: &instancepb.Instance{
			Name:        emulatorInstanceName,
			Config:      emulatorInstanceConfig,
			DisplayName: "spec-graph integration tests",
			NodeCount:   1,
		},
	})
	if status.Code(err) == codes.AlreadyExists {
		return nil
	}
	if err != nil {
		return fmt.Errorf("create instance %s: %w", emulatorInstanceName, err)
	}
	if _, err := op.Wait(ctx); err != nil {
		if status.Code(err) == codes.AlreadyExists {
			return nil
		}
		return fmt.Errorf("create instance %s wait: %w", emulatorInstanceName, err)
	}
	return nil
}

// TestEnsureEmulatorInstanceRefusesNonEmulatorAndIsIdempotent proves the
// helper's endpoint guard and both of its success paths on a live emulator:
// absent instance -> created with the emulator config, present instance ->
// accepted without a second create.
func TestEnsureEmulatorInstanceRefusesNonEmulatorAndIsIdempotent(t *testing.T) {
	requireEmulator(t)
	ctx := context.Background()
	host := os.Getenv("SPANNER_EMULATOR_HOST")

	for _, refused := range []string{"", "spanner.googleapis.com:443", "127.0.0.1:9010"} {
		if err := ensureEmulatorInstance(ctx, refused); err == nil || !strings.Contains(err.Error(), "refusing to create a Spanner instance") {
			t.Fatalf("ensureEmulatorInstance(%q) error=%v, want refusal", refused, err)
		}
	}

	client, err := instance.NewInstanceAdminClient(ctx)
	if err != nil {
		t.Fatalf("instance admin client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("close instance admin client: %v", err)
		}
	}()

	if err := client.DeleteInstance(ctx, &instancepb.DeleteInstanceRequest{Name: emulatorInstanceName}); err != nil && status.Code(err) != codes.NotFound {
		t.Fatalf("delete instance: %v", err)
	}
	if _, err := client.GetInstance(ctx, &instancepb.GetInstanceRequest{Name: emulatorInstanceName}); status.Code(err) != codes.NotFound {
		t.Fatalf("instance still present after delete: err=%v", err)
	}

	if err := ensureEmulatorInstance(ctx, host); err != nil {
		t.Fatalf("create absent instance: %v", err)
	}
	got, err := client.GetInstance(ctx, &instancepb.GetInstanceRequest{Name: emulatorInstanceName})
	if err != nil {
		t.Fatalf("get created instance: %v", err)
	}
	if got.GetConfig() != emulatorInstanceConfig {
		t.Fatalf("created instance config=%q, want %q", got.GetConfig(), emulatorInstanceConfig)
	}

	if err := ensureEmulatorInstance(ctx, host); err != nil {
		t.Fatalf("existing instance not accepted: %v", err)
	}
}
