package runtimeconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInvalidConfig = errors.New("runtimeconfig: invalid config")
	ErrNotReady      = errors.New("runtimeconfig: settings not loaded")
)

const schemaSQL = `
CREATE TABLE IF NOT EXISTS runtime_settings (
	id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	deposit_min_confirmations BIGINT NOT NULL,
	withdraw_planner_min_confirmations BIGINT NOT NULL,
	withdraw_batch_confirmations BIGINT NOT NULL,
	updated_by TEXT NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT runtime_settings_deposit_min_confirmations_positive CHECK (deposit_min_confirmations > 0),
	CONSTRAINT runtime_settings_withdraw_planner_min_confirmations_positive CHECK (withdraw_planner_min_confirmations > 0),
	CONSTRAINT runtime_settings_withdraw_batch_confirmations_positive CHECK (withdraw_batch_confirmations > 0),
	CONSTRAINT runtime_settings_updated_by_nonempty CHECK (updated_by <> '')
);
`

type Settings struct {
	DepositMinConfirmations         int64
	WithdrawPlannerMinConfirmations int64
	WithdrawBatchConfirmations      int64
	UpdatedBy                       string
	UpdatedAt                       time.Time
}

func (s Settings) Validate() error {
	if s.DepositMinConfirmations <= 0 {
		return fmt.Errorf("%w: deposit confirmations must be > 0", ErrInvalidConfig)
	}
	if s.WithdrawPlannerMinConfirmations <= 0 {
		return fmt.Errorf("%w: withdraw planner confirmations must be > 0", ErrInvalidConfig)
	}
	if s.WithdrawBatchConfirmations <= 0 {
		return fmt.Errorf("%w: withdraw batch confirmations must be > 0", ErrInvalidConfig)
	}
	return nil
}

type Store struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", ErrInvalidConfig)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) EnsureSchema(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if _, err := s.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("runtimeconfig: ensure schema: %w", err)
	}
	return nil
}

func (s *Store) EnsureDefaults(ctx context.Context, defaults Settings, updatedBy string) (Settings, error) {
	if s == nil || s.pool == nil {
		return Settings{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	defaults.UpdatedBy = updatedBy
	if err := defaults.Validate(); err != nil {
		return Settings{}, err
	}
	if defaults.UpdatedBy == "" {
		return Settings{}, fmt.Errorf("%w: updated_by must be non-empty", ErrInvalidConfig)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO runtime_settings (
			id,
			deposit_min_confirmations,
			withdraw_planner_min_confirmations,
			withdraw_batch_confirmations,
			updated_by,
			updated_at
		) VALUES (1, $1, $2, $3, $4, now())
		ON CONFLICT (id) DO NOTHING
	`,
		defaults.DepositMinConfirmations,
		defaults.WithdrawPlannerMinConfirmations,
		defaults.WithdrawBatchConfirmations,
		defaults.UpdatedBy,
	)
	if err != nil {
		return Settings{}, fmt.Errorf("runtimeconfig: ensure defaults: %w", err)
	}
	return s.Get(ctx)
}

func (s *Store) Get(ctx context.Context) (Settings, error) {
	if s == nil || s.pool == nil {
		return Settings{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	var out Settings
	err := s.pool.QueryRow(ctx, `
		SELECT
			deposit_min_confirmations,
			withdraw_planner_min_confirmations,
			withdraw_batch_confirmations,
			updated_by,
			updated_at
		FROM runtime_settings
		WHERE id = 1
	`).Scan(
		&out.DepositMinConfirmations,
		&out.WithdrawPlannerMinConfirmations,
		&out.WithdrawBatchConfirmations,
		&out.UpdatedBy,
		&out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Settings{}, ErrNotReady
		}
		return Settings{}, fmt.Errorf("runtimeconfig: get: %w", err)
	}
	if err := out.Validate(); err != nil {
		return Settings{}, err
	}
	return out, nil
}

func (s *Store) Update(ctx context.Context, settings Settings, updatedBy string) (Settings, error) {
	if s == nil || s.pool == nil {
		return Settings{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	settings.UpdatedBy = updatedBy
	if settings.UpdatedBy == "" {
		return Settings{}, fmt.Errorf("%w: updated_by must be non-empty", ErrInvalidConfig)
	}
	if err := settings.Validate(); err != nil {
		return Settings{}, err
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE runtime_settings
		SET
			deposit_min_confirmations = $1,
			withdraw_planner_min_confirmations = $2,
			withdraw_batch_confirmations = $3,
			updated_by = $4,
			updated_at = now()
		WHERE id = 1
	`,
		settings.DepositMinConfirmations,
		settings.WithdrawPlannerMinConfirmations,
		settings.WithdrawBatchConfirmations,
		settings.UpdatedBy,
	)
	if err != nil {
		return Settings{}, fmt.Errorf("runtimeconfig: update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Settings{}, ErrNotReady
	}
	return s.Get(ctx)
}

type Loader interface {
	Get(ctx context.Context) (Settings, error)
}

type Cache struct {
	loader   Loader
	interval time.Duration
	log      *slog.Logger

	mu       sync.RWMutex
	settings Settings
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
	return &Cache{
		loader:   loader,
		interval: interval,
		log:      log,
	}, nil
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

func (c *Cache) Current() (Settings, error) {
	if c == nil {
		return Settings{}, fmt.Errorf("%w: nil cache", ErrInvalidConfig)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.loaded {
		if c.lastErr != nil {
			return Settings{}, c.lastErr
		}
		return Settings{}, ErrNotReady
	}
	return c.settings, nil
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

func (c *Cache) refresh(ctx context.Context) {
	settings, err := c.loader.Get(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.lastErr = err
		if !c.loaded {
			return
		}
		c.log.Warn("runtime settings refresh failed; keeping last known values", "err", err)
		return
	}
	c.settings = settings
	c.loaded = true
	c.lastErr = nil
}
