package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/leases"
)

var ErrInvalidConfig = errors.New("leases/postgres: invalid config")

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
	_, err := s.pool.Exec(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("leases/postgres: ensure schema: %w", err)
	}
	return nil
}

func (s *Store) TryAcquire(ctx context.Context, name, owner string, ttl time.Duration) (leases.Lease, bool, error) {
	if s == nil || s.pool == nil {
		return leases.Lease{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if err := validateInput(name, owner, ttl); err != nil {
		return leases.Lease{}, false, err
	}

	ttlMS := ttlMilliseconds(ttl)

	var (
		gotOwner string
		expires  time.Time
	)

	err := s.pool.QueryRow(ctx, `
		INSERT INTO leases (name, owner, expires_at, created_at, updated_at)
		VALUES ($1,$2, now() + ($3::bigint * interval '1 millisecond'), now(), now())
		ON CONFLICT (name) DO UPDATE
		SET owner = EXCLUDED.owner,
			expires_at = EXCLUDED.expires_at,
			updated_at = now()
		WHERE leases.expires_at <= now()
		RETURNING owner, expires_at
	`, name, owner, ttlMS).Scan(&gotOwner, &expires)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Someone else currently holds it; return the current lease.
			l, gerr := s.Get(ctx, name)
			if gerr != nil {
				return leases.Lease{}, false, gerr
			}
			return l, false, nil
		}
		return leases.Lease{}, false, fmt.Errorf("leases/postgres: try acquire: %w", err)
	}

	return leases.Lease{
		Name:      name,
		Owner:     gotOwner,
		ExpiresAt: expires,
	}, true, nil
}

func (s *Store) Renew(ctx context.Context, name, owner string, ttl time.Duration) (leases.Lease, bool, error) {
	if s == nil || s.pool == nil {
		return leases.Lease{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if err := validateInput(name, owner, ttl); err != nil {
		return leases.Lease{}, false, err
	}

	ttlMS := ttlMilliseconds(ttl)

	var (
		gotOwner string
		expires  time.Time
	)
	err := s.pool.QueryRow(ctx, `
		UPDATE leases
		SET expires_at = now() + ($3::bigint * interval '1 millisecond'),
			updated_at = now()
		WHERE name = $1 AND owner = $2
		RETURNING owner, expires_at
	`, name, owner, ttlMS).Scan(&gotOwner, &expires)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			l, gerr := s.Get(ctx, name)
			if errors.Is(gerr, leases.ErrNotFound) {
				return leases.Lease{}, false, leases.ErrNotFound
			}
			if gerr != nil {
				return leases.Lease{}, false, gerr
			}
			if l.Owner != owner {
				return leases.Lease{}, false, leases.ErrNotOwner
			}
			return leases.Lease{}, false, fmt.Errorf("leases/postgres: renew: unexpected no rows")
		}
		return leases.Lease{}, false, fmt.Errorf("leases/postgres: renew: %w", err)
	}

	return leases.Lease{
		Name:      name,
		Owner:     gotOwner,
		ExpiresAt: expires,
	}, true, nil
}

func (s *Store) Release(ctx context.Context, name, owner string) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if name == "" || owner == "" {
		return leases.ErrInvalidInput
	}

	tag, err := s.pool.Exec(ctx, `DELETE FROM leases WHERE name = $1 AND owner = $2`, name, owner)
	if err != nil {
		return fmt.Errorf("leases/postgres: release: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// Idempotent if already absent; otherwise reject non-owner.
	l, gerr := s.Get(ctx, name)
	if errors.Is(gerr, leases.ErrNotFound) {
		return nil
	}
	if gerr != nil {
		return gerr
	}
	if l.Owner != owner {
		return leases.ErrNotOwner
	}
	return nil
}

func (s *Store) Get(ctx context.Context, name string) (leases.Lease, error) {
	if s == nil || s.pool == nil {
		return leases.Lease{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if name == "" {
		return leases.Lease{}, leases.ErrInvalidInput
	}

	var (
		owner     string
		expiresAt time.Time
	)
	err := s.pool.QueryRow(ctx, `SELECT owner, expires_at FROM leases WHERE name = $1`, name).Scan(&owner, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return leases.Lease{}, leases.ErrNotFound
		}
		return leases.Lease{}, fmt.Errorf("leases/postgres: get: %w", err)
	}

	return leases.Lease{
		Name:      name,
		Owner:     owner,
		ExpiresAt: expiresAt,
	}, nil
}

func ttlMilliseconds(ttl time.Duration) int64 {
	ms := ttl.Milliseconds()
	if ms <= 0 {
		return 1
	}
	return ms
}

func validateInput(name, owner string, ttl time.Duration) error {
	if name == "" || owner == "" || ttl <= 0 {
		return leases.ErrInvalidInput
	}
	return nil
}
