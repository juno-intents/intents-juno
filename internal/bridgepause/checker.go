package bridgepause

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// ContractCaller abstracts the eth_call RPC needed for checking the paused() view function.
type ContractCaller interface {
	// CallContract executes an eth_call at the latest block.
	// msg.To is the contract address, msg.Data is the ABI-encoded call data.
	// Returns the ABI-encoded return value.
	CallContract(ctx context.Context, to common.Address, data []byte) ([]byte, error)
}

// pausedSelector is the function selector for paused() -> bool (keccak256("paused()") = 0x5c975abb).
var pausedSelector = []byte{0x5c, 0x97, 0x5a, 0xbb}

// Checker provides a cached bridge paused() check.
type Checker struct {
	caller     ContractCaller
	bridgeAddr common.Address
	cacheTTL   time.Duration

	mu         sync.Mutex
	cachedAt   time.Time
	cached     bool
	cacheValid bool
	staleUntil time.Time
	refreshing bool
}

// NewChecker creates a new Checker.
func NewChecker(caller ContractCaller, bridgeAddr common.Address, cacheTTL time.Duration) (*Checker, error) {
	if caller == nil {
		return nil, fmt.Errorf("bridgepause: nil contract caller")
	}
	if (bridgeAddr == common.Address{}) {
		return nil, fmt.Errorf("bridgepause: zero bridge address")
	}
	if cacheTTL <= 0 {
		cacheTTL = 10 * time.Second
	}
	return &Checker{
		caller:     caller,
		bridgeAddr: bridgeAddr,
		cacheTTL:   cacheTTL,
	}, nil
}

// IsPaused returns true if Bridge.paused() returns true. Caches result for cacheTTL.
// On RPC error, returns true (fail-safe: assume paused).
func (c *Checker) IsPaused(ctx context.Context) (bool, error) {
	c.mu.Lock()
	if c.cacheValid && time.Since(c.cachedAt) < c.cacheTTL {
		paused := c.cached
		c.mu.Unlock()
		return paused, nil
	}
	c.mu.Unlock()

	return c.queryAndStore(ctx)
}

// IsPausedCached returns the cached paused() state for read-only status display.
// If a prior successful read exists, expired values are returned immediately while
// a background refresh runs at most once per cacheTTL.
// Use IsPaused or IsPausedFresh for transaction gating.
func (c *Checker) IsPausedCached(ctx context.Context) (bool, error) {
	c.mu.Lock()
	now := time.Now()
	if c.cacheValid && now.Sub(c.cachedAt) < c.cacheTTL {
		paused := c.cached
		c.mu.Unlock()
		return paused, nil
	}
	if c.cacheValid {
		paused := c.cached
		if !c.refreshing && !now.Before(c.staleUntil) {
			c.refreshing = true
			go c.refreshCached()
		}
		c.mu.Unlock()
		return paused, nil
	}
	c.mu.Unlock()

	paused, err := c.queryAndStore(ctx)
	if err != nil {
		return false, err
	}
	return paused, nil
}

// IsPausedFresh returns true if Bridge.paused() returns true without using a cached result.
// On RPC error, returns true (fail-safe: assume paused).
func (c *Checker) IsPausedFresh(ctx context.Context) (bool, error) {
	return c.queryAndStore(ctx)
}

func (c *Checker) queryAndStore(ctx context.Context) (bool, error) {
	started := time.Now()
	paused, err := c.queryPaused(ctx)
	if err != nil {
		return paused, err
	}
	c.mu.Lock()
	if !c.cacheValid || !c.cachedAt.After(started) {
		c.storePausedLocked(paused)
	}
	c.mu.Unlock()
	return paused, nil
}

func (c *Checker) refreshCached() {
	timeout := c.cacheTTL
	if timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	started := time.Now()
	paused, err := c.queryPaused(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		if !c.cacheValid || !c.cachedAt.After(started) {
			c.storePausedLocked(paused)
		}
	} else {
		c.staleUntil = time.Now().Add(c.cacheTTL)
	}
	c.refreshing = false
}

func (c *Checker) queryPaused(ctx context.Context) (bool, error) {
	result, err := c.caller.CallContract(ctx, c.bridgeAddr, pausedSelector)
	if err != nil {
		return true, fmt.Errorf("bridgepause: rpc error checking paused(): %w", err)
	}

	paused, err := decodeBoolResult(result)
	if err != nil {
		return true, err
	}
	return paused, nil
}

func (c *Checker) storePausedLocked(paused bool) {
	c.cached = paused
	c.cachedAt = time.Now()
	c.cacheValid = true
	c.staleUntil = time.Time{}
}

// decodeBoolResult decodes an ABI-encoded bool (32 bytes, last byte is 0 or 1).
func decodeBoolResult(data []byte) (bool, error) {
	if len(data) != 32 {
		return true, fmt.Errorf("bridgepause: invalid paused() response length %d", len(data))
	}
	for i := 0; i < 31; i++ {
		if data[i] != 0 {
			return true, fmt.Errorf("bridgepause: invalid paused() bool padding")
		}
	}
	switch data[31] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return true, fmt.Errorf("bridgepause: invalid paused() bool value %d", data[31])
	}
}
