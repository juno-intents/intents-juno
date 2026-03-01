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
	defer c.mu.Unlock()

	if c.cacheValid && time.Since(c.cachedAt) < c.cacheTTL {
		return c.cached, nil
	}

	result, err := c.caller.CallContract(ctx, c.bridgeAddr, pausedSelector)
	if err != nil {
		// Fail-safe: assume paused on RPC error.
		return true, fmt.Errorf("bridgepause: rpc error (fail-safe: assuming paused): %w", err)
	}

	paused := decodeBoolResult(result)
	c.cached = paused
	c.cachedAt = time.Now()
	c.cacheValid = true

	return paused, nil
}

// decodeBoolResult decodes an ABI-encoded bool (32 bytes, last byte is 0 or 1).
func decodeBoolResult(data []byte) bool {
	if len(data) < 32 {
		// Unexpected response length; fail-safe: assume paused.
		return true
	}
	return data[31] != 0
}
