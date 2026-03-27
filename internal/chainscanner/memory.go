package chainscanner

import (
	"context"
	"fmt"
	"math/big"
	"sort"
	"sync"
)

// MemoryStateStore is an in-memory implementation of StateStore for testing.
type MemoryStateStore struct {
	mu      sync.Mutex
	heights map[string]int64
	refs    map[string]map[int64]BlockRef
	pending map[string]map[string]WithdrawRequestedEvent
}

// NewMemoryStateStore creates a new in-memory state store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{
		heights: make(map[string]int64),
		refs:    make(map[string]map[int64]BlockRef),
		pending: make(map[string]map[string]WithdrawRequestedEvent),
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

func (s *MemoryStateStore) StageScanData(_ context.Context, serviceName string, refs []BlockRef, events []WithdrawRequestedEvent, lastHeight int64) error {
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	if lastHeight < 0 {
		return fmt.Errorf("%w: invalid block height", ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.refs[serviceName] == nil {
		s.refs[serviceName] = make(map[int64]BlockRef)
	}
	for _, ref := range refs {
		if ref.Height <= 0 {
			return fmt.Errorf("%w: invalid block height", ErrInvalidConfig)
		}
		s.refs[serviceName][ref.Height] = ref
	}
	if s.pending[serviceName] == nil {
		s.pending[serviceName] = make(map[string]WithdrawRequestedEvent)
	}
	for _, event := range events {
		s.pending[serviceName][pendingEventKey(event)] = cloneWithdrawRequestedEvent(event)
	}
	s.heights[serviceName] = lastHeight
	return nil
}

func (s *MemoryStateStore) ListPendingWithdrawEvents(_ context.Context, serviceName string, limit int) ([]WithdrawRequestedEvent, error) {
	if serviceName == "" {
		return nil, fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	if limit <= 0 {
		limit = 1000
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pending := s.pending[serviceName]
	if len(pending) == 0 {
		return nil, nil
	}

	out := make([]WithdrawRequestedEvent, 0, len(pending))
	for _, event := range pending {
		out = append(out, cloneWithdrawRequestedEvent(event))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BlockNumber == out[j].BlockNumber {
			return out[i].LogIndex < out[j].LogIndex
		}
		return out[i].BlockNumber < out[j].BlockNumber
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStateStore) DeletePendingWithdrawEvent(_ context.Context, serviceName string, event WithdrawRequestedEvent) error {
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pending[serviceName] != nil {
		delete(s.pending[serviceName], pendingEventKey(event))
	}
	return nil
}

func (s *MemoryStateStore) DeletePendingWithdrawEventsFromHeight(_ context.Context, serviceName string, height int64) error {
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for key, event := range s.pending[serviceName] {
		if int64(event.BlockNumber) >= height {
			delete(s.pending[serviceName], key)
		}
	}
	return nil
}

func pendingEventKey(event WithdrawRequestedEvent) string {
	return event.TxHash.Hex() + ":" + fmt.Sprintf("%d", event.LogIndex)
}

func cloneWithdrawRequestedEvent(event WithdrawRequestedEvent) WithdrawRequestedEvent {
	var amount *big.Int
	if event.Amount != nil {
		amount = new(big.Int).Set(event.Amount)
	}
	return WithdrawRequestedEvent{
		WithdrawalID:   event.WithdrawalID,
		Requester:      event.Requester,
		Amount:         amount,
		RecipientUA:    append([]byte(nil), event.RecipientUA...),
		Expiry:         event.Expiry,
		FeeBps:         event.FeeBps,
		BlockNumber:    event.BlockNumber,
		BlockHash:      event.BlockHash,
		TxHash:         event.TxHash,
		LogIndex:       event.LogIndex,
		FinalitySource: event.FinalitySource,
	}
}

var _ StateStore = (*MemoryStateStore)(nil)
