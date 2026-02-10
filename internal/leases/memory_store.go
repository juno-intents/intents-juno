package leases

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory lease store intended for unit tests and single-process usage.
// It is safe for concurrent use.
type MemoryStore struct {
	mu     sync.Mutex
	now    func() time.Time
	leases map[string]Lease
}

func NewMemoryStore(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{
		now:    now,
		leases: make(map[string]Lease),
	}
}

func (s *MemoryStore) TryAcquire(_ context.Context, name, owner string, ttl time.Duration) (Lease, bool, error) {
	if err := validate(name, owner, ttl); err != nil {
		return Lease{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	l, ok := s.leases[name]
	if !ok || !l.ExpiresAt.After(now) {
		out := Lease{
			Name:      name,
			Owner:     owner,
			ExpiresAt: now.Add(ttl),
		}
		s.leases[name] = out
		return out, true, nil
	}
	return l, false, nil
}

func (s *MemoryStore) Renew(_ context.Context, name, owner string, ttl time.Duration) (Lease, bool, error) {
	if err := validate(name, owner, ttl); err != nil {
		return Lease{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.leases[name]
	if !ok {
		return Lease{}, false, ErrNotFound
	}
	if l.Owner != owner {
		return Lease{}, false, ErrNotOwner
	}

	now := s.now()
	// Allow renewing even if already expired; the caller still owns it in memory until stolen.
	out := Lease{
		Name:      name,
		Owner:     owner,
		ExpiresAt: now.Add(ttl),
	}
	s.leases[name] = out
	return out, true, nil
}

func (s *MemoryStore) Release(_ context.Context, name, owner string) error {
	if name == "" || owner == "" {
		return ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.leases[name]
	if !ok {
		return nil
	}
	if l.Owner != owner {
		return ErrNotOwner
	}
	delete(s.leases, name)
	return nil
}

func (s *MemoryStore) Get(_ context.Context, name string) (Lease, error) {
	if name == "" {
		return Lease{}, ErrInvalidInput
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.leases[name]
	if !ok {
		return Lease{}, ErrNotFound
	}
	return l, nil
}
