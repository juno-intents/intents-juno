package withdrawcoordinator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/leases"
)

type stubLeaderReadinessChecker struct {
	calls int
	err   error
}

func (s *stubLeaderReadinessChecker) Ready(context.Context) error {
	s.calls++
	return s.err
}

func TestLeaderElector_Tick_AcquireRenewSteal(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	ls := leases.NewMemoryStore(nowFn)

	a, err := NewLeaderElector(ls, "withdraw-coordinator", "a", 10*time.Second)
	if err != nil {
		t.Fatalf("NewLeaderElector(a): %v", err)
	}
	b, err := NewLeaderElector(ls, "withdraw-coordinator", "b", 10*time.Second)
	if err != nil {
		t.Fatalf("NewLeaderElector(b): %v", err)
	}

	ctx := context.Background()

	lease, leader, err := a.Tick(ctx)
	if err != nil {
		t.Fatalf("a.Tick: %v", err)
	}
	if !leader {
		t.Fatalf("expected a to acquire leadership")
	}
	if lease.Version != 1 {
		t.Fatalf("expected version 1, got %d", lease.Version)
	}

	lease, leader, err = b.Tick(ctx)
	if err != nil {
		t.Fatalf("b.Tick: %v", err)
	}
	if leader {
		t.Fatalf("expected b to not be leader while a lease is valid")
	}
	if lease.Version != 1 {
		t.Fatalf("expected observed version 1 while held by a, got %d", lease.Version)
	}

	now = now.Add(5 * time.Second)
	lease, leader, err = a.Tick(ctx)
	if err != nil {
		t.Fatalf("a.Tick renew: %v", err)
	}
	if !leader {
		t.Fatalf("expected a to remain leader")
	}
	if lease.Version != 1 {
		t.Fatalf("expected renewed version 1, got %d", lease.Version)
	}

	// After expiry, b can steal.
	now = now.Add(11 * time.Second)
	lease, leader, err = b.Tick(ctx)
	if err != nil {
		t.Fatalf("b.Tick steal: %v", err)
	}
	if !leader {
		t.Fatalf("expected b to steal leadership after expiry")
	}
	if lease.Version != 2 {
		t.Fatalf("expected stolen version 2, got %d", lease.Version)
	}
}

func TestLeaderElector_Tick_SkipsLeadershipWhenNotReady(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	ls := leases.NewMemoryStore(nowFn)
	readiness := &stubLeaderReadinessChecker{err: errors.New("underfunded")}

	a, err := NewLeaderElector(ls, "withdraw-coordinator", "a", 10*time.Second, WithReadinessChecker(readiness))
	if err != nil {
		t.Fatalf("NewLeaderElector(a): %v", err)
	}
	b, err := NewLeaderElector(ls, "withdraw-coordinator", "b", 10*time.Second)
	if err != nil {
		t.Fatalf("NewLeaderElector(b): %v", err)
	}

	ctx := context.Background()

	_, leader, err := a.Tick(ctx)
	if err != nil {
		t.Fatalf("a.Tick: %v", err)
	}
	if leader {
		t.Fatalf("expected a to stay out of leadership while unready")
	}
	if readiness.calls == 0 {
		t.Fatalf("expected readiness checks")
	}

	lease, leader, err := b.Tick(ctx)
	if err != nil {
		t.Fatalf("b.Tick: %v", err)
	}
	if !leader {
		t.Fatalf("expected ready peer to acquire leadership")
	}
	if lease.Version != 1 {
		t.Fatalf("expected acquired version 1, got %d", lease.Version)
	}
}
