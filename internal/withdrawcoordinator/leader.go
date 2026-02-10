package withdrawcoordinator

import (
	"context"
	"fmt"
	"time"

	"github.com/juno-intents/intents-juno/internal/leases"
)

// LeaderElector is a small helper for "single active coordinator" semantics.
//
// It uses a TTL-based lease in the shared DB. Call Tick periodically; it returns
// whether this instance is the current leader.
type LeaderElector struct {
	store leases.Store
	name  string
	owner string
	ttl   time.Duration
}

func NewLeaderElector(store leases.Store, leaseName, owner string, ttl time.Duration) (*LeaderElector, error) {
	if store == nil || leaseName == "" || owner == "" || ttl <= 0 {
		return nil, fmt.Errorf("%w: invalid leader elector config", ErrInvalidConfig)
	}
	return &LeaderElector{
		store: store,
		name:  leaseName,
		owner: owner,
		ttl:   ttl,
	}, nil
}

// Tick attempts to renew leadership if already held, otherwise tries to acquire it.
func (l *LeaderElector) Tick(ctx context.Context) (bool, error) {
	if l == nil || l.store == nil {
		return false, fmt.Errorf("%w: nil leader elector", ErrInvalidConfig)
	}

	if _, ok, err := l.store.Renew(ctx, l.name, l.owner, l.ttl); err == nil && ok {
		return true, nil
	}

	_, ok, err := l.store.TryAcquire(ctx, l.name, l.owner, l.ttl)
	if err != nil {
		return false, err
	}
	return ok, nil
}
