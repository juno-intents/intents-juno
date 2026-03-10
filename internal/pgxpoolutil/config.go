package pgxpoolutil

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	DefaultMinConns          = int32(1)
	DefaultMaxConns          = int32(16)
	DefaultMaxConnLifetime   = time.Hour
	DefaultMaxConnIdleTime   = 30 * time.Minute
	DefaultHealthCheckPeriod = time.Minute
	DefaultReadyTimeout      = 2 * time.Second
)

type Settings struct {
	MinConns          int32
	MaxConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ReadyTimeout      time.Duration
}

func ParseConfig(dsn string, settings Settings) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if err := Apply(cfg, settings); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Apply(cfg *pgxpool.Config, settings Settings) error {
	if cfg == nil {
		return fmt.Errorf("pgxpoolutil: nil config")
	}
	if settings.MinConns <= 0 {
		settings.MinConns = DefaultMinConns
	}
	if settings.MaxConns <= 0 {
		settings.MaxConns = DefaultMaxConns
	}
	if settings.HealthCheckPeriod <= 0 {
		settings.HealthCheckPeriod = DefaultHealthCheckPeriod
	}
	if settings.MaxConnLifetime <= 0 {
		settings.MaxConnLifetime = DefaultMaxConnLifetime
	}
	if settings.MaxConnIdleTime <= 0 {
		settings.MaxConnIdleTime = DefaultMaxConnIdleTime
	}
	if settings.ReadyTimeout <= 0 {
		settings.ReadyTimeout = DefaultReadyTimeout
	}
	if settings.MaxConns < settings.MinConns {
		return fmt.Errorf(
			"pgxpoolutil: max conns %d must be >= min conns %d",
			settings.MaxConns,
			settings.MinConns,
		)
	}

	cfg.MinConns = settings.MinConns
	cfg.MaxConns = settings.MaxConns
	cfg.MaxConnLifetime = settings.MaxConnLifetime
	cfg.MaxConnIdleTime = settings.MaxConnIdleTime
	cfg.HealthCheckPeriod = settings.HealthCheckPeriod
	return nil
}

func NewPool(ctx context.Context, dsn string, settings Settings) (*pgxpool.Pool, error) {
	cfg, err := ParseConfig(dsn, settings)
	if err != nil {
		return nil, err
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

func ReadinessCheck(pool *pgxpool.Pool, timeout time.Duration) func(context.Context) error {
	if timeout <= 0 {
		timeout = DefaultReadyTimeout
	}
	return func(ctx context.Context) error {
		if pool == nil {
			return fmt.Errorf("pgxpoolutil: nil pool")
		}
		pingCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return pool.Ping(pingCtx)
	}
}
