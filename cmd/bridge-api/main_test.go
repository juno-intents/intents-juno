package main

import (
	"context"
	"errors"
	"testing"
)

func TestBridgeAPIReadinessCheckOmitsBridgeSettingsWhenPaused(t *testing.T) {
	t.Parallel()

	bridgeSettingsCalled := false
	check := bridgeAPIReadinessCheck(
		true,
		func(context.Context) error { return nil },
		func(context.Context) error { return nil },
		func(context.Context) error {
			bridgeSettingsCalled = true
			return errors.New("bridge settings unavailable")
		},
	)

	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if bridgeSettingsCalled {
		t.Fatal("bridge settings check was called while paused")
	}
}

func TestBridgeAPIReadinessCheckRequiresBridgeSettingsWhenActive(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("bridge settings unavailable")
	check := bridgeAPIReadinessCheck(
		false,
		func(context.Context) error { return nil },
		func(context.Context) error { return nil },
		func(context.Context) error { return wantErr },
	)

	if err := check(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("check error: got %v want %v", err, wantErr)
	}
}
