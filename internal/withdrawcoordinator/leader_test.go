package withdrawcoordinator

import (
	"context"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/leases"
)

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

	leader, err := a.Tick(ctx)
	if err != nil {
		t.Fatalf("a.Tick: %v", err)
	}
	if !leader {
		t.Fatalf("expected a to acquire leadership")
	}

	leader, err = b.Tick(ctx)
	if err != nil {
		t.Fatalf("b.Tick: %v", err)
	}
	if leader {
		t.Fatalf("expected b to not be leader while a lease is valid")
	}

	now = now.Add(5 * time.Second)
	leader, err = a.Tick(ctx)
	if err != nil {
		t.Fatalf("a.Tick renew: %v", err)
	}
	if !leader {
		t.Fatalf("expected a to remain leader")
	}

	// After expiry, b can steal.
	now = now.Add(11 * time.Second)
	leader, err = b.Tick(ctx)
	if err != nil {
		t.Fatalf("b.Tick steal: %v", err)
	}
	if !leader {
		t.Fatalf("expected b to steal leadership after expiry")
	}
}
