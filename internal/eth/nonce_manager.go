package eth

import (
	"context"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

type PendingNoncer interface {
	PendingNonceAt(ctx context.Context, account common.Address) (uint64, error)
}

// NonceManager provides process-local, concurrency-safe nonce allocation for a single EVM account.
//
// It must not decrease its notion of "next nonce" on Sync, to avoid nonce reuse when callers have
// already reserved nonces locally but not yet broadcast transactions.
type NonceManager struct {
	backend PendingNoncer
	addr    common.Address

	mu   sync.Mutex
	next uint64
	have bool
}

func NewNonceManager(backend PendingNoncer, addr common.Address) *NonceManager {
	return &NonceManager{
		backend: backend,
		addr:    addr,
	}
}

// Next returns the next nonce and increments the internal counter.
func (m *NonceManager) Next(ctx context.Context) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.have {
		n, err := m.backend.PendingNonceAt(ctx, m.addr)
		if err != nil {
			return 0, err
		}
		m.next = n
		m.have = true
	}

	n := m.next
	m.next++
	return n, nil
}

// Sync refreshes the next nonce from the backend, but never decreases it.
//
// The returned value is the backend's current pending nonce.
func (m *NonceManager) Sync(ctx context.Context) (uint64, error) {
	n, err := m.backend.PendingNonceAt(ctx, m.addr)
	if err != nil {
		return 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.have || n > m.next {
		m.next = n
		m.have = true
	}
	return n, nil
}
