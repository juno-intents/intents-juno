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
	refs    map[string]map[int64]BlockRef
}

// NewMemoryStateStore creates a new in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		heights: make(map[string]int64),
		refs:    make(map[string]map[int64]BlockRef),
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

func (s *MemoryStateStore) GetBlockRef(_ context.Context, serviceName string, height int64) (BlockRef, bool, error) {
	if serviceName == "" {
		return BlockRef{}, false, fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := s.refs[serviceName]
	if refs == nil {
		return BlockRef{}, false, nil
	}
	ref, ok := refs[height]
	return ref, ok, nil
}

func (s *MemoryStateStore) StoreBlockRef(_ context.Context, serviceName string, ref BlockRef) error {
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	if ref.Height <= 0 {
		return fmt.Errorf("%w: invalid block height", ErrInvalidConfig)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refs[serviceName] == nil {
		s.refs[serviceName] = make(map[int64]BlockRef)
	}
	s.refs[serviceName][ref.Height] = ref
	return nil
}

func (s *MemoryStateStore) DeleteBlockRefsFromHeight(_ context.Context, serviceName string, height int64) error {
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := s.refs[serviceName]
	for refHeight := range refs {
		if refHeight >= height {
			delete(refs, refHeight)
		}
	}
	return nil
}

var _ StateStore = (*MemoryStateStore)(nil)
