package bridgeconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
)

var (
	ErrInvalidConfig = errors.New("bridgeconfig: invalid config")
	ErrNotReady      = errors.New("bridgeconfig: bridge settings not loaded")
)

type Caller interface {
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

type Snapshot struct {
	MinDepositAmount uint64
	MinDepositAdmin  common.Address
	LoadedAt         time.Time
}

type Reader struct {
	backend Caller
	bridge  common.Address
	now     func() time.Time
}

func NewReader(backend Caller, bridge common.Address) (*Reader, error) {
	if backend == nil {
		return nil, fmt.Errorf("%w: nil backend", ErrInvalidConfig)
	}
	if bridge == (common.Address{}) {
		return nil, fmt.Errorf("%w: nil bridge address", ErrInvalidConfig)
	}
	return &Reader{backend: backend, bridge: bridge, now: time.Now}, nil
}

func (r *Reader) Load(ctx context.Context) (Snapshot, error) {
	if r == nil || r.backend == nil {
		return Snapshot{}, fmt.Errorf("%w: nil reader", ErrInvalidConfig)
	}
	minDepositData, err := bridgeabi.PackMinDepositAmountCalldata()
	if err != nil {
		return Snapshot{}, err
	}
	minDepositRaw, err := r.backend.CallContract(ctx, ethereum.CallMsg{To: &r.bridge, Data: minDepositData}, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("bridgeconfig: read minDepositAmount: %w", err)
	}
	minDeposit, err := bridgeabi.UnpackMinDepositAmountResult(minDepositRaw)
	if err != nil {
		return Snapshot{}, err
	}
	if minDeposit.Sign() < 0 || minDeposit.BitLen() > 64 {
		return Snapshot{}, fmt.Errorf("%w: minDepositAmount overflows uint64", ErrInvalidConfig)
	}

	minAdminData, err := bridgeabi.PackMinDepositAdminCalldata()
	if err != nil {
		return Snapshot{}, err
	}
	minAdminRaw, err := r.backend.CallContract(ctx, ethereum.CallMsg{To: &r.bridge, Data: minAdminData}, nil)
	if err != nil {
		return Snapshot{}, fmt.Errorf("bridgeconfig: read minDepositAdmin: %w", err)
	}
	minAdmin, err := bridgeabi.UnpackMinDepositAdminResult(minAdminRaw)
	if err != nil {
		return Snapshot{}, err
	}

	return Snapshot{
		MinDepositAmount: minDeposit.Uint64(),
		MinDepositAdmin:  minAdmin,
		LoadedAt:         r.now().UTC(),
	}, nil
}

type Loader interface {
	Load(ctx context.Context) (Snapshot, error)
}

type Cache struct {
	loader   Loader
	interval time.Duration
	log      *slog.Logger

	mu       sync.RWMutex
	snapshot Snapshot
	loaded   bool
	lastErr  error
}

func NewCache(loader Loader, interval time.Duration, log *slog.Logger) (*Cache, error) {
	if loader == nil {
		return nil, fmt.Errorf("%w: nil loader", ErrInvalidConfig)
	}
	if interval <= 0 {
		return nil, fmt.Errorf("%w: poll interval must be > 0", ErrInvalidConfig)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Cache{loader: loader, interval: interval, log: log}, nil
}

func (c *Cache) Start(ctx context.Context) {
	c.refresh(ctx)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.refresh(ctx)
		}
	}
}

func (c *Cache) Ready(context.Context) error {
	if c == nil {
		return fmt.Errorf("%w: nil cache", ErrInvalidConfig)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.loaded {
		return nil
	}
	if c.lastErr != nil {
		return c.lastErr
	}
	return ErrNotReady
}

func (c *Cache) Current() (Snapshot, error) {
	if c == nil {
		return Snapshot{}, fmt.Errorf("%w: nil cache", ErrInvalidConfig)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.loaded {
		if c.lastErr != nil {
			return Snapshot{}, c.lastErr
		}
		return Snapshot{}, ErrNotReady
	}
	return c.snapshot, nil
}

func (c *Cache) refresh(ctx context.Context) {
	snapshot, err := c.loader.Load(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.lastErr = err
		if !c.loaded {
			return
		}
		c.log.Warn("bridge settings refresh failed; keeping last known values", "err", err)
		return
	}
	c.snapshot = snapshot
	c.loaded = true
	c.lastErr = nil
}
