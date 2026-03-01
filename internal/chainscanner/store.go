package chainscanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidConfig = errors.New("chainscanner: invalid config")

// StateStore persists the last-processed block height for each scanner service.
type StateStore interface {
	EnsureSchema(ctx context.Context) error
	GetLastHeight(ctx context.Context, serviceName string) (int64, error)
	SetLastHeight(ctx context.Context, serviceName string, height int64) error
}

// PgStateStore implements StateStore backed by Postgres.
type PgStateStore struct {
	pool *pgxpool.Pool
}

// NewPgStateStore creates a new Postgres-backed state store.
func NewPgStateStore(pool *pgxpool.Pool) (*PgStateStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", ErrInvalidConfig)
	}
	return &PgStateStore{pool: pool}, nil
}

func (s *PgStateStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	_, err := s.pool.Exec(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("chainscanner: ensure schema: %w", err)
	}
	return nil
}

// GetLastHeight returns the last processed height for the given service.
// Returns 0 if the service has not been seen before.
func (s *PgStateStore) GetLastHeight(ctx context.Context, serviceName string) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return 0, fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	var height int64
	err := s.pool.QueryRow(ctx, `
		SELECT last_processed_height
		FROM event_scanner_state
		WHERE service_name = $1
	`, serviceName).Scan(&height)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("chainscanner: get last height: %w", err)
	}
	return height, nil
}

// SetLastHeight upserts the last processed height for the given service.
func (s *PgStateStore) SetLastHeight(ctx context.Context, serviceName string, height int64) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO event_scanner_state (service_name, last_processed_height, last_processed_at)
		VALUES ($1, $2, now())
		ON CONFLICT (service_name) DO UPDATE
		SET last_processed_height = EXCLUDED.last_processed_height,
		    last_processed_at = EXCLUDED.last_processed_at
	`, serviceName, height)
	if err != nil {
		return fmt.Errorf("chainscanner: set last height: %w", err)
	}
	return nil
}

var _ StateStore = (*PgStateStore)(nil)
