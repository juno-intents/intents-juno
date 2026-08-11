package withdrawcoordinator

import (
	"context"
	"errors"
	"sync"
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

type observingLeaderStore struct {
	leases.Store

	mu              sync.Mutex
	tryAcquireCalls int
	renewed         chan leases.Lease
}

func (s *observingLeaderStore) TryAcquire(ctx context.Context, name, owner string, ttl time.Duration) (leases.Lease, bool, error) {
	s.mu.Lock()
	s.tryAcquireCalls++
	s.mu.Unlock()
	return s.Store.TryAcquire(ctx, name, owner, ttl)
}

func (s *observingLeaderStore) Renew(ctx context.Context, name, owner string, ttl time.Duration) (leases.Lease, bool, error) {
	lease, ok, err := s.Store.Renew(ctx, name, owner, ttl)
	if ok && err == nil && s.renewed != nil {
		s.renewed <- lease
	}
	return lease, ok, err
}

func (s *observingLeaderStore) TryAcquireCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tryAcquireCalls
}

type heartbeatFault int

const (
	heartbeatRenewError heartbeatFault = iota
	heartbeatRenewNotOwner
	heartbeatRenewOwnerChanged
	heartbeatRenewVersionChanged
)

type faultingLeaderStore struct {
	mu sync.Mutex

	fault           heartbeatFault
	lease           leases.Lease
	tryAcquireCalls int
	renewCalls      int
}

type blockingRenewLeaderStore struct {
	mu sync.Mutex

	lease             leases.Lease
	tryAcquireCalls   int
	renewCalls        int
	activeRenewCalls  int
	heartbeatStarted  chan struct{}
	heartbeatFinished chan struct{}
	startOnce         sync.Once
	finishOnce        sync.Once
}

func (s *blockingRenewLeaderStore) TryAcquire(_ context.Context, name, owner string, ttl time.Duration) (leases.Lease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tryAcquireCalls++
	s.lease = leases.Lease{
		Name:      name,
		Owner:     owner,
		Version:   11,
		ExpiresAt: time.Now().Add(ttl),
	}
	return s.lease, true, nil
}

func (s *blockingRenewLeaderStore) Renew(ctx context.Context, _ string, _ string, _ time.Duration) (leases.Lease, bool, error) {
	s.mu.Lock()
	s.renewCalls++
	if s.tryAcquireCalls == 0 {
		s.mu.Unlock()
		return leases.Lease{}, false, leases.ErrNotFound
	}
	s.activeRenewCalls++
	s.startOnce.Do(func() { close(s.heartbeatStarted) })
	s.mu.Unlock()

	<-ctx.Done()

	s.mu.Lock()
	s.activeRenewCalls--
	s.finishOnce.Do(func() { close(s.heartbeatFinished) })
	s.mu.Unlock()
	return leases.Lease{}, false, ctx.Err()
}

func (s *blockingRenewLeaderStore) Release(context.Context, string, string) error {
	return nil
}

func (s *blockingRenewLeaderStore) Get(context.Context, string) (leases.Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lease, nil
}

func (s *blockingRenewLeaderStore) Counts() (tryAcquire, renew, activeRenew int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tryAcquireCalls, s.renewCalls, s.activeRenewCalls
}

type invalidInitialLeaseStore struct {
	lease leases.Lease
}

func (s invalidInitialLeaseStore) TryAcquire(context.Context, string, string, time.Duration) (leases.Lease, bool, error) {
	return s.lease, true, nil
}

func (invalidInitialLeaseStore) Renew(context.Context, string, string, time.Duration) (leases.Lease, bool, error) {
	return leases.Lease{}, false, leases.ErrNotFound
}

func (invalidInitialLeaseStore) Release(context.Context, string, string) error {
	return nil
}

func (s invalidInitialLeaseStore) Get(context.Context, string) (leases.Lease, error) {
	return s.lease, nil
}

func (s *faultingLeaderStore) TryAcquire(_ context.Context, name, owner string, ttl time.Duration) (leases.Lease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tryAcquireCalls++
	if s.tryAcquireCalls > 1 {
		return leases.Lease{}, false, errors.New("unexpected reacquire")
	}
	s.lease = leases.Lease{
		Name:      name,
		Owner:     owner,
		Version:   7,
		ExpiresAt: time.Now().Add(ttl),
	}
	return s.lease, true, nil
}

func (s *faultingLeaderStore) Renew(_ context.Context, _ string, _ string, _ time.Duration) (leases.Lease, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewCalls++
	if s.tryAcquireCalls == 0 {
		return leases.Lease{}, false, leases.ErrNotFound
	}
	switch s.fault {
	case heartbeatRenewError:
		return leases.Lease{}, false, errors.New("renew unavailable")
	case heartbeatRenewNotOwner:
		return leases.Lease{}, false, nil
	case heartbeatRenewOwnerChanged:
		changed := s.lease
		changed.Owner = "other-owner"
		return changed, true, nil
	case heartbeatRenewVersionChanged:
		changed := s.lease
		changed.Version++
		return changed, true, nil
	default:
		return leases.Lease{}, false, errors.New("unknown fault")
	}
}

func (s *faultingLeaderStore) Release(context.Context, string, string) error {
	return nil
}

func (s *faultingLeaderStore) Get(context.Context, string) (leases.Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lease, nil
}

func (s *faultingLeaderStore) Counts() (tryAcquire, renew int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tryAcquireCalls, s.renewCalls
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

func TestLeaderElector_RunWhileLeader_RenewsDuringBlockingWork(t *testing.T) {
	const ttl = 60 * time.Millisecond
	store := &observingLeaderStore{
		Store:   leases.NewMemoryStore(time.Now),
		renewed: make(chan leases.Lease, 16),
	}
	elector, err := NewLeaderElector(store, "withdraw-coordinator", "a", ttl)
	if err != nil {
		t.Fatalf("NewLeaderElector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	startedAt := time.Now()
	ran, err := elector.RunWhileLeader(ctx, func(_ context.Context, initial leases.Lease) error {
		if initial.Owner != "a" || initial.Version != 1 {
			t.Fatalf("initial lease: %+v", initial)
		}
		for i := 0; i < 4; i++ {
			select {
			case renewed := <-store.renewed:
				if renewed.Owner != initial.Owner || renewed.Version != initial.Version {
					t.Fatalf("renewed lease changed identity: initial=%+v renewed=%+v", initial, renewed)
				}
			case <-ctx.Done():
				t.Fatalf("waiting for heartbeat renewal: %v", ctx.Err())
			}
		}
		if elapsed := time.Since(startedAt); elapsed <= ttl {
			t.Fatalf("work did not run beyond original lease TTL: elapsed=%s ttl=%s", elapsed, ttl)
		}
		if lease, ok, err := store.Store.TryAcquire(ctx, "withdraw-coordinator", "b", ttl); err != nil {
			return err
		} else if ok {
			t.Fatalf("competitor acquired during heartbeat: %+v", lease)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("RunWhileLeader: %v", err)
	}
	if !ran {
		t.Fatalf("expected leader work to run")
	}
	if got := store.TryAcquireCalls(); got != 1 {
		t.Fatalf("leader TryAcquire calls: got %d want 1", got)
	}
}

func TestLeaderElector_RunWhileLeader_CancelsOnHeartbeatLossWithoutReacquire(t *testing.T) {
	tests := []struct {
		name  string
		fault heartbeatFault
	}{
		{name: "renew error", fault: heartbeatRenewError},
		{name: "renew reports not owner", fault: heartbeatRenewNotOwner},
		{name: "renewed owner changed", fault: heartbeatRenewOwnerChanged},
		{name: "renewed version changed", fault: heartbeatRenewVersionChanged},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &faultingLeaderStore{fault: tc.fault}
			elector, err := NewLeaderElector(store, "withdraw-coordinator", "a", 30*time.Millisecond)
			if err != nil {
				t.Fatalf("NewLeaderElector: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			workCanceled := false
			ran, err := elector.RunWhileLeader(ctx, func(workCtx context.Context, _ leases.Lease) error {
				<-workCtx.Done()
				workCanceled = true
				return workCtx.Err()
			})
			if !ran {
				t.Fatalf("expected leader work to start")
			}
			if !errors.Is(err, ErrLeadershipLost) {
				t.Fatalf("expected ErrLeadershipLost, got %v", err)
			}
			if !workCanceled {
				t.Fatalf("expected heartbeat loss to cancel work")
			}
			tryAcquireCalls, renewCalls := store.Counts()
			if tryAcquireCalls != 1 {
				t.Fatalf("TryAcquire calls: got %d want 1", tryAcquireCalls)
			}
			if renewCalls < 2 {
				t.Fatalf("Renew calls: got %d want at least 2", renewCalls)
			}
		})
	}
}

func TestLeaderElector_RunWhileLeader_BoundsBlockedRenewalBeforeLeaseExpiry(t *testing.T) {
	const ttl = 600 * time.Millisecond
	store := &blockingRenewLeaderStore{
		heartbeatStarted:  make(chan struct{}),
		heartbeatFinished: make(chan struct{}),
	}
	elector, err := NewLeaderElector(store, "withdraw-coordinator", "a", ttl)
	if err != nil {
		t.Fatalf("NewLeaderElector: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var initialExpiry time.Time
	ran, err := elector.RunWhileLeader(ctx, func(workCtx context.Context, initial leases.Lease) error {
		initialExpiry = initial.ExpiresAt
		select {
		case <-store.heartbeatStarted:
		case <-ctx.Done():
			return ctx.Err()
		}
		<-workCtx.Done()
		if !time.Now().Before(initial.ExpiresAt) {
			t.Fatalf("work cancellation missed lease expiry: expiry=%s now=%s", initial.ExpiresAt, time.Now())
		}
		return workCtx.Err()
	})
	if !ran {
		t.Fatalf("expected leader work to start")
	}
	if !errors.Is(err, ErrLeadershipLost) {
		t.Fatalf("expected ErrLeadershipLost, got %v", err)
	}
	if initialExpiry.IsZero() {
		t.Fatalf("work did not observe the initial lease")
	}
	select {
	case <-store.heartbeatFinished:
	default:
		t.Fatalf("blocked renewal outlived RunWhileLeader")
	}
	tryAcquireCalls, renewCalls, activeRenewCalls := store.Counts()
	if tryAcquireCalls != 1 {
		t.Fatalf("TryAcquire calls: got %d want 1", tryAcquireCalls)
	}
	if renewCalls != 2 {
		t.Fatalf("Renew calls: got %d want 2", renewCalls)
	}
	if activeRenewCalls != 0 {
		t.Fatalf("active Renew calls: got %d want 0", activeRenewCalls)
	}
}

func TestLeaderElector_RunWhileLeader_RejectsInvalidInitialLeaseWithoutRunning(t *testing.T) {
	tests := []struct {
		name  string
		lease leases.Lease
	}{
		{
			name:  "wrong name",
			lease: leases.Lease{Name: "other", Owner: "a", Version: 1},
		},
		{
			name:  "wrong owner",
			lease: leases.Lease{Name: "withdraw-coordinator", Owner: "b", Version: 1},
		},
		{
			name:  "invalid version",
			lease: leases.Lease{Name: "withdraw-coordinator", Owner: "a", Version: 0},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			elector, err := NewLeaderElector(
				invalidInitialLeaseStore{lease: tc.lease},
				"withdraw-coordinator",
				"a",
				time.Minute,
			)
			if err != nil {
				t.Fatalf("NewLeaderElector: %v", err)
			}

			called := false
			ran, err := elector.RunWhileLeader(context.Background(), func(context.Context, leases.Lease) error {
				called = true
				return nil
			})
			if ran {
				t.Fatalf("invalid initial lease reported work as run")
			}
			if !errors.Is(err, ErrLeadershipLost) {
				t.Fatalf("expected ErrLeadershipLost, got %v", err)
			}
			if called {
				t.Fatalf("work callback ran with invalid initial lease")
			}
		})
	}
}

func TestLeaderElector_RunWhileLeader_SkipsWorkWhenFollower(t *testing.T) {
	store := leases.NewMemoryStore(time.Now)
	ctx := context.Background()
	if _, ok, err := store.TryAcquire(ctx, "withdraw-coordinator", "b", time.Minute); err != nil || !ok {
		t.Fatalf("seed leader lease: ok=%v err=%v", ok, err)
	}
	elector, err := NewLeaderElector(store, "withdraw-coordinator", "a", time.Minute)
	if err != nil {
		t.Fatalf("NewLeaderElector: %v", err)
	}

	called := false
	ran, err := elector.RunWhileLeader(ctx, func(context.Context, leases.Lease) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("RunWhileLeader: %v", err)
	}
	if ran {
		t.Fatalf("expected follower work to be skipped")
	}
	if called {
		t.Fatalf("work callback ran as follower")
	}
}
