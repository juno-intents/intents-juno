package bridgepause

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type mockCaller struct {
	mu     sync.Mutex
	result []byte
	err    error
	delay  time.Duration
	calls  int
}

func (m *mockCaller) CallContract(ctx context.Context, _ common.Address, _ []byte) ([]byte, error) {
	m.mu.Lock()
	m.calls++
	result := append([]byte(nil), m.result...)
	err := m.err
	delay := m.delay
	m.mu.Unlock()

	if delay > 0 {
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (m *mockCaller) setResult(result []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.result = result
}

func (m *mockCaller) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *mockCaller) setDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = delay
}

func (m *mockCaller) callsCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func waitForCalls(t *testing.T, caller *mockCaller, want int) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := caller.callsCount(); got >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d calls, got %d", want, caller.callsCount())
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
			name:       "short response returns true fail-safe error",
			result:     []byte{0x01},
			wantPaused: true,
			wantErr:    true,
		},
		{
			name:       "empty response returns true fail-safe error",
			result:     []byte{},
			wantPaused: true,
			wantErr:    true,
		},
		{
			name:       "invalid bool response returns true fail-safe error",
			result:     append(encodeBool(false)[:31], 0x02),
			wantPaused: true,
			wantErr:    true,
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
	if got := caller.callsCount(); got != 1 {
		t.Fatalf("expected 1 RPC call, got %d", got)
	}

	// Second call within TTL should use cache.
	_, _ = c.IsPaused(ctx)
	if got := caller.callsCount(); got != 1 {
		t.Fatalf("expected 1 RPC call (cached), got %d", got)
	}
}

func TestChecker_IsPausedFreshBypassesCachedFalse(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{result: encodeBool(false)}

	c, err := NewChecker(caller, bridge, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	ctx := context.Background()

	paused, err := c.IsPaused(ctx)
	if err != nil {
		t.Fatalf("IsPaused: %v", err)
	}
	if paused {
		t.Fatal("expected initial unpaused state")
	}
	if got := caller.callsCount(); got != 1 {
		t.Fatalf("expected 1 RPC call, got %d", got)
	}

	caller.setResult(encodeBool(true))
	paused, err = c.IsPausedFresh(ctx)
	if err != nil {
		t.Fatalf("IsPausedFresh: %v", err)
	}
	if !paused {
		t.Fatal("expected fresh paused state")
	}
	if got := caller.callsCount(); got != 2 {
		t.Fatalf("expected fresh call to bypass cache, got %d calls", got)
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
	if got := caller.callsCount(); got != 1 {
		t.Fatalf("expected 1 RPC call, got %d", got)
	}

	// Wait for cache to expire.
	time.Sleep(20 * time.Millisecond)

	_, _ = c.IsPaused(ctx)
	if got := caller.callsCount(); got != 2 {
		t.Fatalf("expected 2 RPC calls after cache expiry, got %d", got)
	}
}

func TestChecker_IsPausedCachedReturnsStaleCachedStateOnRPCError(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{result: encodeBool(false)}

	c, err := NewChecker(caller, bridge, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	ctx := context.Background()

	paused, err := c.IsPaused(ctx)
	if err != nil {
		t.Fatalf("IsPaused: %v", err)
	}
	if paused {
		t.Fatal("expected initial unpaused state")
	}

	time.Sleep(20 * time.Millisecond)
	caller.setErr(errors.New("temporary rpc outage"))
	caller.setResult(encodeBool(true))

	paused, err = c.IsPausedCached(ctx)
	if err != nil {
		t.Fatalf("IsPausedCached: %v", err)
	}
	if paused {
		t.Fatal("expected stale unpaused state on refresh error")
	}
	waitForCalls(t, caller, 2)

	paused, err = c.IsPausedCached(ctx)
	if err != nil {
		t.Fatalf("cached stale IsPaused: %v", err)
	}
	if paused {
		t.Fatal("expected cached stale unpaused state")
	}
	if got := caller.callsCount(); got != 2 {
		t.Fatalf("expected stale error to refresh cache window, got %d RPC calls", got)
	}
}

func TestChecker_IsPausedCachedColdErrorReturnsUnpausedStatus(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{err: errors.New("temporary rpc outage")}

	c, err := NewChecker(caller, bridge, time.Second)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	paused, err := c.IsPausedCached(context.Background())
	if err == nil {
		t.Fatal("expected cold cache refresh error")
	}
	if paused {
		t.Fatal("expected display status to avoid synthetic paused state on cold error")
	}
	if got := caller.callsCount(); got != 1 {
		t.Fatalf("expected 1 RPC call, got %d", got)
	}

	caller.setErr(nil)
	caller.setResult(encodeBool(true))

	paused, err = c.IsPausedCached(context.Background())
	if err != nil {
		t.Fatalf("IsPausedCached after recovery: %v", err)
	}
	if !paused {
		t.Fatal("expected recovered paused state")
	}
	if got := caller.callsCount(); got != 2 {
		t.Fatalf("expected 2 RPC calls, got %d", got)
	}
}

func TestChecker_IsPausedCachedReturnsStaleImmediatelyWhileRefreshInFlight(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{result: encodeBool(false)}

	c, err := NewChecker(caller, bridge, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	ctx := context.Background()

	paused, err := c.IsPaused(ctx)
	if err != nil {
		t.Fatalf("IsPaused: %v", err)
	}
	if paused {
		t.Fatal("expected initial unpaused state")
	}

	time.Sleep(20 * time.Millisecond)
	caller.setDelay(200 * time.Millisecond)
	caller.setResult(encodeBool(true))

	started := time.Now()
	paused, err = c.IsPausedCached(ctx)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("IsPausedCached: %v", err)
	}
	if paused {
		t.Fatal("expected stale unpaused state while refresh is in flight")
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("IsPausedCached took %s, want immediate stale return", elapsed)
	}
	waitForCalls(t, caller, 2)
}

func TestChecker_IsPausedFailsClosedAfterCachedFalseRPCError(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{result: encodeBool(false)}

	c, err := NewChecker(caller, bridge, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	ctx := context.Background()

	paused, err := c.IsPaused(ctx)
	if err != nil {
		t.Fatalf("IsPaused: %v", err)
	}
	if paused {
		t.Fatal("expected initial unpaused state")
	}

	time.Sleep(20 * time.Millisecond)
	caller.setErr(errors.New("temporary rpc outage"))

	paused, err = c.IsPaused(ctx)
	if err == nil {
		t.Fatal("expected pause check error")
	}
	if !paused {
		t.Fatal("expected IsPaused to fail closed")
	}
}

func TestChecker_IsPausedFreshFailsClosedAfterCachedFalseRPCError(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{result: encodeBool(false)}

	c, err := NewChecker(caller, bridge, time.Hour)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	ctx := context.Background()

	paused, err := c.IsPaused(ctx)
	if err != nil {
		t.Fatalf("IsPaused: %v", err)
	}
	if paused {
		t.Fatal("expected initial unpaused state")
	}

	caller.setErr(errors.New("temporary rpc outage"))

	paused, err = c.IsPausedFresh(ctx)
	if err == nil {
		t.Fatal("expected fresh pause check error")
	}
	if !paused {
		t.Fatal("expected fresh check to fail closed")
	}
}

func TestChecker_InvalidResponseDoesNotPoisonCachedDisplayState(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	caller := &mockCaller{result: encodeBool(false)}

	c, err := NewChecker(caller, bridge, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	ctx := context.Background()

	paused, err := c.IsPaused(ctx)
	if err != nil {
		t.Fatalf("IsPaused: %v", err)
	}
	if paused {
		t.Fatal("expected initial unpaused state")
	}

	time.Sleep(20 * time.Millisecond)
	caller.setResult([]byte{0x01})

	paused, err = c.IsPaused(ctx)
	if err == nil {
		t.Fatal("expected invalid response error")
	}
	if !paused {
		t.Fatal("expected strict check to fail closed")
	}

	paused, err = c.IsPausedCached(ctx)
	if err != nil {
		t.Fatalf("IsPausedCached: %v", err)
	}
	if paused {
		t.Fatal("expected display cache to keep stale unpaused state")
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
	caller.setErr(nil)
	caller.setResult(encodeBool(false))

	paused, err = c.IsPaused(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if paused {
		t.Fatal("expected not paused after fix")
	}
	if got := caller.callsCount(); got != 2 {
		t.Fatalf("expected 2 RPC calls, got %d", got)
	}
}
