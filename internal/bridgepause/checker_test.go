package bridgepause

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type mockCaller struct {
	result []byte
	err    error
	calls  int
}

func (m *mockCaller) CallContract(_ context.Context, _ common.Address, _ []byte) ([]byte, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return m.result, nil
}

func encodeBool(v bool) []byte {
	out := make([]byte, 32)
	if v {
		out[31] = 1
	}
	return out
}

func TestChecker(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	tests := []struct {
		name       string
		result     []byte
		err        error
		wantPaused bool
		wantErr    bool
	}{
		{
			name:       "not paused",
			result:     encodeBool(false),
			wantPaused: false,
			wantErr:    false,
		},
		{
			name:       "paused",
			result:     encodeBool(true),
			wantPaused: true,
			wantErr:    false,
		},
		{
			name:       "rpc error returns true fail-safe",
			err:        errors.New("connection refused"),
			wantPaused: true,
			wantErr:    true,
		},
		{
			name:       "short response returns true fail-safe",
			result:     []byte{0x01},
			wantPaused: true,
			wantErr:    false,
		},
		{
			name:       "empty response returns true fail-safe",
			result:     []byte{},
			wantPaused: true,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			caller := &mockCaller{result: tt.result, err: tt.err}
			c, err := NewChecker(caller, bridge, 100*time.Millisecond)
			if err != nil {
				t.Fatalf("NewChecker: %v", err)
			}

			paused, err := c.IsPaused(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsPaused() error = %v, wantErr %v", err, tt.wantErr)
			}
			if paused != tt.wantPaused {
				t.Fatalf("IsPaused() = %v, want %v", paused, tt.wantPaused)
			}
		})
	}
}

func TestChecker_CachesResult(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{result: encodeBool(false)}

	c, err := NewChecker(caller, bridge, 1*time.Second)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	ctx := context.Background()

	// First call hits the RPC.
	_, _ = c.IsPaused(ctx)
	if caller.calls != 1 {
		t.Fatalf("expected 1 RPC call, got %d", caller.calls)
	}

	// Second call within TTL should use cache.
	_, _ = c.IsPaused(ctx)
	if caller.calls != 1 {
		t.Fatalf("expected 1 RPC call (cached), got %d", caller.calls)
	}
}

func TestChecker_CacheExpiry(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{result: encodeBool(false)}

	c, err := NewChecker(caller, bridge, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	ctx := context.Background()

	_, _ = c.IsPaused(ctx)
	if caller.calls != 1 {
		t.Fatalf("expected 1 RPC call, got %d", caller.calls)
	}

	// Wait for cache to expire.
	time.Sleep(20 * time.Millisecond)

	_, _ = c.IsPaused(ctx)
	if caller.calls != 2 {
		t.Fatalf("expected 2 RPC calls after cache expiry, got %d", caller.calls)
	}
}

func TestChecker_NilCallerReturnsError(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	_, err := NewChecker(nil, bridge, time.Second)
	if err == nil {
		t.Fatal("expected error for nil caller")
	}
}

func TestChecker_ZeroBridgeAddrReturnsError(t *testing.T) {
	t.Parallel()

	caller := &mockCaller{result: encodeBool(false)}
	_, err := NewChecker(caller, common.Address{}, time.Second)
	if err == nil {
		t.Fatal("expected error for zero bridge address")
	}
}

func TestChecker_RPCErrorDoesNotCache(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{err: errors.New("network error")}

	c, err := NewChecker(caller, bridge, 1*time.Second)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	ctx := context.Background()

	paused, err := c.IsPaused(ctx)
	if !paused {
		t.Fatal("expected fail-safe paused=true on error")
	}
	if err == nil {
		t.Fatal("expected error")
	}

	// Now fix the caller and call again; should hit RPC since error wasn't cached.
	caller.err = nil
	caller.result = encodeBool(false)

	paused, err = c.IsPaused(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if paused {
		t.Fatal("expected not paused after fix")
	}
	if caller.calls != 2 {
		t.Fatalf("expected 2 RPC calls, got %d", caller.calls)
	}
}
