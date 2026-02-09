package eth

import (
	"context"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

type fakeNoncer struct {
	mu    sync.Mutex
	nonce uint64
	calls int
}

func (f *fakeNoncer) PendingNonceAt(_ context.Context, _ common.Address) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.nonce, nil
}

func TestNonceManager_Next_InitializesFromBackendOnce(t *testing.T) {
	ctx := context.Background()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	backend := &fakeNoncer{nonce: 5}

	m := NewNonceManager(backend, addr)

	n0, err := m.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if n0 != 5 {
		t.Fatalf("nonce: got %d want %d", n0, 5)
	}

	n1, err := m.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if n1 != 6 {
		t.Fatalf("nonce: got %d want %d", n1, 6)
	}

	if backend.calls != 1 {
		t.Fatalf("backend calls: got %d want %d", backend.calls, 1)
	}
}

func TestNonceManager_Sync_DoesNotDecreaseNext(t *testing.T) {
	ctx := context.Background()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	backend := &fakeNoncer{nonce: 10}

	m := NewNonceManager(backend, addr)

	_, _ = m.Next(ctx) // 10
	_, _ = m.Next(ctx) // 11

	backend.nonce = 9
	if _, err := m.Sync(ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}

	n, err := m.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if n != 12 {
		t.Fatalf("nonce after Sync: got %d want %d", n, 12)
	}
}

func TestNonceManager_Sync_AdoptsHigherBackendNonce(t *testing.T) {
	ctx := context.Background()
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	backend := &fakeNoncer{nonce: 1}

	m := NewNonceManager(backend, addr)

	_, _ = m.Next(ctx) // 1
	backend.nonce = 20

	got, err := m.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if got != 20 {
		t.Fatalf("Sync nonce: got %d want %d", got, 20)
	}

	n, err := m.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if n != 20 {
		t.Fatalf("nonce after Sync: got %d want %d", n, 20)
	}
}
