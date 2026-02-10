package leases

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidInput = errors.New("leases: invalid input")
	ErrNotFound     = errors.New("leases: not found")
	ErrNotOwner     = errors.New("leases: not owner")
)

// Lease is a named, expiring ownership record.
//
// Leases are used for leader election and single-writer coordination.
type Lease struct {
	Name      string
	Owner     string
	ExpiresAt time.Time
}

// Store provides a compare-and-swap style lease API.
//
// Semantics:
// - TryAcquire succeeds if the lease does not exist or is expired at the store's notion of "now".
// - Renew succeeds only if the lease currently exists and is owned by owner.
// - Release is idempotent if the lease is already absent.
type Store interface {
	TryAcquire(ctx context.Context, name, owner string, ttl time.Duration) (Lease, bool, error)
	Renew(ctx context.Context, name, owner string, ttl time.Duration) (Lease, bool, error)
	Release(ctx context.Context, name, owner string) error
	Get(ctx context.Context, name string) (Lease, error)
}

func validate(name, owner string, ttl time.Duration) error {
	if name == "" || owner == "" || ttl <= 0 {
		return fmt.Errorf("%w: name/owner must be non-empty and ttl must be > 0", ErrInvalidInput)
	}
	return nil
}
