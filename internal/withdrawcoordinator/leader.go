package withdrawcoordinator

import (
	"context"
	"fmt"
	"time"

	"github.com/juno-intents/intents-juno/internal/leases"
)

type ReadinessChecker interface {
	Ready(ctx context.Context) error
}

type LeaderElectorOption func(*LeaderElector)

// LeaderElector is a small helper for "single active coordinator" semantics.
//
// It uses a TTL-based lease in the shared DB. Use RunWhileLeader for work that
// can outlive one lease interval; Tick is the single-attempt primitive.
type LeaderElector struct {
	store leases.Store
	name  string
	owner string
	ttl   time.Duration

	readinessChecker ReadinessChecker
}

func WithReadinessChecker(checker ReadinessChecker) LeaderElectorOption {
	return func(l *LeaderElector) {
		l.readinessChecker = checker
	}
}

func NewLeaderElector(store leases.Store, leaseName, owner string, ttl time.Duration, opts ...LeaderElectorOption) (*LeaderElector, error) {
	if store == nil || leaseName == "" || owner == "" || ttl <= 0 {
		return nil, fmt.Errorf("%w: invalid leader elector config", ErrInvalidConfig)
	}
	le := &LeaderElector{
		store: store,
		name:  leaseName,
		owner: owner,
		ttl:   ttl,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(le)
		}
	}
	return le, nil
}

// Tick attempts to renew leadership if already held, otherwise tries to acquire it.
func (l *LeaderElector) Tick(ctx context.Context) (leases.Lease, bool, error) {
	if l == nil || l.store == nil {
		return leases.Lease{}, false, fmt.Errorf("%w: nil leader elector", ErrInvalidConfig)
	}
	if l.readinessChecker != nil {
		if err := l.readinessChecker.Ready(ctx); err != nil {
			return leases.Lease{}, false, nil
		}
	}

	if lease, ok, err := l.store.Renew(ctx, l.name, l.owner, l.ttl); err == nil && ok {
		return lease, true, nil
	}

	lease, ok, err := l.store.TryAcquire(ctx, l.name, l.owner, l.ttl)
	if err != nil {
		return leases.Lease{}, false, err
	}
	return lease, ok, nil
}

// RunWhileLeader acquires leadership once, then keeps that exact lease alive
// while work runs. A heartbeat may renew the current lease, but it must never
// reacquire a lost lease because work is fenced to the initially acquired
// version.
func (l *LeaderElector) RunWhileLeader(ctx context.Context, work func(context.Context, leases.Lease) error) (bool, error) {
	if l == nil || l.store == nil {
		return false, fmt.Errorf("%w: nil leader elector", ErrInvalidConfig)
	}
	if work == nil {
		return false, fmt.Errorf("%w: nil leader work", ErrInvalidConfig)
	}

	lease, leader, err := l.Tick(ctx)
	if err != nil || !leader {
		return false, err
	}
	if lease.Name != l.name || lease.Owner != l.owner || lease.Version <= 0 {
		return false, fmt.Errorf(
			"%w: acquired lease identity mismatch: name=%q owner=%q version=%d",
			ErrLeadershipLost,
			lease.Name,
			lease.Owner,
			lease.Version,
		)
	}

	workCtx, cancelWork := context.WithCancel(ctx)
	defer cancelWork()
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	defer cancelHeartbeat()

	heartbeatDone := make(chan error, 1)
	go func() {
		interval := l.ttl / 3
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-heartbeatCtx.Done():
				heartbeatDone <- nil
				return
			case <-ticker.C:
				renewCtx, cancelRenew := context.WithTimeout(heartbeatCtx, interval)
				renewed, ok, renewErr := l.store.Renew(renewCtx, l.name, l.owner, l.ttl)
				renewCtxErr := renewCtx.Err()
				cancelRenew()
				if heartbeatCtx.Err() != nil {
					heartbeatDone <- nil
					return
				}
				if renewErr != nil {
					err := fmt.Errorf("%w: renew leader lease: %v", ErrLeadershipLost, renewErr)
					cancelWork()
					heartbeatDone <- err
					return
				}
				if renewCtxErr != nil {
					err := fmt.Errorf("%w: renew leader lease context: %v", ErrLeadershipLost, renewCtxErr)
					cancelWork()
					heartbeatDone <- err
					return
				}
				if !ok {
					err := fmt.Errorf("%w: renew leader lease rejected", ErrLeadershipLost)
					cancelWork()
					heartbeatDone <- err
					return
				}
				if renewed.Name != lease.Name || renewed.Owner != lease.Owner || renewed.Version != lease.Version {
					err := fmt.Errorf(
						"%w: renewed lease identity changed: name=%q owner=%q version=%d",
						ErrLeadershipLost,
						renewed.Name,
						renewed.Owner,
						renewed.Version,
					)
					cancelWork()
					heartbeatDone <- err
					return
				}
			}
		}
	}()

	workErr := work(workCtx, lease)
	cancelHeartbeat()
	heartbeatErr := <-heartbeatDone
	if heartbeatErr != nil {
		return true, heartbeatErr
	}
	return true, workErr
}
