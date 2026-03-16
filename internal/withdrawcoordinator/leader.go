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
// It uses a TTL-based lease in the shared DB. Call Tick periodically; it returns
// whether this instance is the current leader.
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
