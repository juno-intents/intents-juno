package leases

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStore_TryAcquireRenewReleaseAndSteal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	s := NewMemoryStore(nowFn)

	ctx := context.Background()

	// Acquire new.
	l, ok, err := s.TryAcquire(ctx, "leader", "a", 10*time.Second)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true on first acquire")
	}
	if l.Owner != "a" {
		t.Fatalf("owner: got %q want %q", l.Owner, "a")
	}
	if !l.ExpiresAt.Equal(now.Add(10 * time.Second)) {
		t.Fatalf("expiresAt: got %v want %v", l.ExpiresAt, now.Add(10*time.Second))
	}

	// Another owner cannot acquire before expiry.
	l2, ok, err := s.TryAcquire(ctx, "leader", "b", 10*time.Second)
	if err != nil {
		t.Fatalf("TryAcquire #2: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false when held by someone else")
	}
	if l2.Owner != "a" {
		t.Fatalf("owner: got %q want %q", l2.Owner, "a")
	}

	// Renew by owner extends expiry.
	now = now.Add(5 * time.Second)
	l3, ok, err := s.Renew(ctx, "leader", "a", 10*time.Second)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true on renew by owner")
	}
	if !l3.ExpiresAt.Equal(now.Add(10 * time.Second)) {
		t.Fatalf("renew expiresAt: got %v want %v", l3.ExpiresAt, now.Add(10*time.Second))
	}

	// Renew by non-owner is rejected.
	if _, ok, err := s.Renew(ctx, "leader", "b", 10*time.Second); err == nil || ok {
		t.Fatalf("expected renew rejection for non-owner: ok=%v err=%v", ok, err)
	}
	if _, _, err := s.Renew(ctx, "leader", "b", 10*time.Second); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}

	// Release by non-owner is rejected.
	if err := s.Release(ctx, "leader", "b"); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("expected ErrNotOwner, got %v", err)
	}

	// Release by owner succeeds.
	if err := s.Release(ctx, "leader", "a"); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// Releasing again should be idempotent.
	if err := s.Release(ctx, "leader", "a"); err != nil {
		t.Fatalf("Release #2: %v", err)
	}

	// Acquire after release.
	l4, ok, err := s.TryAcquire(ctx, "leader", "b", 10*time.Second)
	if err != nil {
		t.Fatalf("TryAcquire after release: %v", err)
	}
	if !ok || l4.Owner != "b" {
		t.Fatalf("expected owner b after acquire: ok=%v owner=%q", ok, l4.Owner)
	}

	// Steal after expiry.
	now = now.Add(11 * time.Second)
	l5, ok, err := s.TryAcquire(ctx, "leader", "c", 10*time.Second)
	if err != nil {
		t.Fatalf("TryAcquire steal: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true when expired")
	}
	if l5.Owner != "c" {
		t.Fatalf("owner after steal: got %q want %q", l5.Owner, "c")
	}
}

func TestMemoryStore_Get_NotFound(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore(time.Now)
	_, err := s.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryStore_RejectsInvalidInput(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore(time.Now)

	if _, _, err := s.TryAcquire(context.Background(), "", "a", time.Second); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if _, _, err := s.TryAcquire(context.Background(), "x", "", time.Second); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if _, _, err := s.TryAcquire(context.Background(), "x", "a", 0); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}
