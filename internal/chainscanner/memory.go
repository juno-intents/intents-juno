package chainscanner

import (
	"context"
	"fmt"
	"sync"
)

// MemoryStateStore is an in-memory implementation of StateStore for testing.
type MemoryStateStore struct {
	mu      sync.Mutex
	heights map[string]int64
}

// NewMemoryStateStore creates a new in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		heights: make(map[string]int64),
	}
}

func (s *MemoryStateStore) EnsureSchema(_ context.Context) error {
	return nil
}

func (s *MemoryStateStore) GetLastHeight(_ context.Context, serviceName string) (int64, error) {
	if serviceName == "" {
		return 0, fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.heights[serviceName], nil
}

func (s *MemoryStateStore) SetLastHeight(_ context.Context, serviceName string, height int64) error {
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heights[serviceName] = height
	return nil
}

var _ StateStore = (*MemoryStateStore)(nil)
