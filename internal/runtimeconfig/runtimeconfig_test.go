package runtimeconfig

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

type stubLoader struct {
	settings Settings
	err      error
}

func (s *stubLoader) Get(context.Context) (Settings, error) {
	if s.err != nil {
		return Settings{}, s.err
	}
	return s.settings, nil
}

func TestSettingsValidate(t *testing.T) {
	if err := (Settings{
		DepositMinConfirmations:         1,
		WithdrawPlannerMinConfirmations: 1,
		WithdrawBatchConfirmations:      1,
	}).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if err := (Settings{}).Validate(); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestCacheReadyAfterInitialLoad(t *testing.T) {
	cache, err := NewCache(&stubLoader{settings: Settings{
		DepositMinConfirmations:         2,
		WithdrawPlannerMinConfirmations: 3,
		WithdrawBatchConfirmations:      4,
	}}, time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	cache.refresh(context.Background())

	if err := cache.Ready(context.Background()); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	got, err := cache.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got.DepositMinConfirmations != 2 || got.WithdrawPlannerMinConfirmations != 3 || got.WithdrawBatchConfirmations != 4 {
		t.Fatalf("unexpected settings: %+v", got)
	}
}

func TestCacheKeepsLastKnownOnRefreshFailure(t *testing.T) {
	loader := &stubLoader{settings: Settings{
		DepositMinConfirmations:         2,
		WithdrawPlannerMinConfirmations: 3,
		WithdrawBatchConfirmations:      4,
	}}
	cache, err := NewCache(loader, time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	cache.refresh(context.Background())
	loader.err = errors.New("boom")
	cache.refresh(context.Background())

	got, err := cache.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got.DepositMinConfirmations != 2 {
		t.Fatalf("unexpected settings after failed refresh: %+v", got)
	}
}

func TestCacheNotReadyBeforeInitialLoad(t *testing.T) {
	cache, err := NewCache(&stubLoader{err: errors.New("boom")}, time.Millisecond, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	cache.refresh(context.Background())

	if err := cache.Ready(context.Background()); err == nil {
		t.Fatal("expected readiness error")
	}
	if _, err := cache.Current(); err == nil {
		t.Fatal("expected current error")
	}
}
