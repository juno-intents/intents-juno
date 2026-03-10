package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

var errIdempotencyKeyConflict = errors.New("httpapi: idempotency key reused with different request")

type idempotencyCache struct {
	mu sync.Mutex

	ttl     time.Duration
	maxKeys int
	entries map[string]*idempotencyEntry
}

type idempotencyEntry struct {
	requestHash [32]byte
	waitCh      chan struct{}
	status      int
	body        []byte
	lastSeen    time.Time
	expiresAt   time.Time
}

type idempotencyReservation struct {
	cache *idempotencyCache
	key   string
	entry *idempotencyEntry
}

func newIdempotencyCache(ttl time.Duration, maxKeys int) *idempotencyCache {
	if ttl <= 0 || maxKeys <= 0 {
		return nil
	}
	return &idempotencyCache{
		ttl:     ttl,
		maxKeys: maxKeys,
		entries: make(map[string]*idempotencyEntry),
	}
}

func canonicalRequestHash(to common.Address, data []byte, value *big.Int, gasLimit uint64, timeoutSeconds int) [32]byte {
	payload, _ := json.Marshal(struct {
		To             string `json:"to"`
		Data           string `json:"data"`
		ValueWei       string `json:"value_wei"`
		GasLimit       uint64 `json:"gas_limit"`
		TimeoutSeconds int    `json:"timeout_seconds"`
	}{
		To:             to.Hex(),
		Data:           hexutil.Encode(data),
		ValueWei:       value.String(),
		GasLimit:       gasLimit,
		TimeoutSeconds: timeoutSeconds,
	})
	return sha256.Sum256(payload)
}

func (c *idempotencyCache) Start(ctx context.Context, key string, requestHash [32]byte, now time.Time) (int, []byte, *idempotencyReservation, error) {
	if c == nil || key == "" {
		return 0, nil, nil, nil
	}

	for {
		waitCh, status, body, reservation, err := c.startLocked(key, requestHash, now)
		if err != nil || waitCh == nil {
			return status, body, reservation, err
		}

		select {
		case <-ctx.Done():
			return 0, nil, nil, ctx.Err()
		case <-waitCh:
		}
	}
}

func (c *idempotencyCache) startLocked(key string, requestHash [32]byte, now time.Time) (chan struct{}, int, []byte, *idempotencyReservation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictExpiredLocked(now)

	if entry, ok := c.entries[key]; ok {
		entry.lastSeen = now
		entry.expiresAt = now.Add(c.ttl)
		if entry.requestHash != requestHash {
			return nil, 0, nil, nil, errIdempotencyKeyConflict
		}
		if entry.waitCh == nil {
			return nil, entry.status, append([]byte(nil), entry.body...), nil, nil
		}
		return entry.waitCh, 0, nil, nil, nil
	}

	if len(c.entries) >= c.maxKeys {
		c.evictOneLocked()
	}

	entry := &idempotencyEntry{
		requestHash: requestHash,
		waitCh:      make(chan struct{}),
		lastSeen:    now,
		expiresAt:   now.Add(c.ttl),
	}
	c.entries[key] = entry
	return nil, 0, nil, &idempotencyReservation{
		cache: c,
		key:   key,
		entry: entry,
	}, nil
}

func (r *idempotencyReservation) Complete(status int, body []byte, now time.Time) {
	if r == nil || r.cache == nil || r.entry == nil {
		return
	}

	r.cache.mu.Lock()
	defer r.cache.mu.Unlock()

	entry, ok := r.cache.entries[r.key]
	if !ok || entry != r.entry {
		return
	}
	entry.status = status
	entry.body = append([]byte(nil), body...)
	entry.lastSeen = now
	entry.expiresAt = now.Add(r.cache.ttl)
	if entry.waitCh != nil {
		close(entry.waitCh)
		entry.waitCh = nil
	}
}

func (c *idempotencyCache) evictExpiredLocked(now time.Time) {
	for key, entry := range c.entries {
		if (entry.expiresAt.Before(now) || entry.expiresAt.Equal(now)) && entry.waitCh == nil {
			delete(c.entries, key)
		}
	}
}

func (c *idempotencyCache) evictOneLocked() {
	var (
		oldestKey string
		oldestAt  time.Time
		first     = true
	)
	for key, entry := range c.entries {
		if entry.waitCh != nil {
			continue
		}
		if first || entry.lastSeen.Before(oldestAt) {
			oldestKey = key
			oldestAt = entry.lastSeen
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}
