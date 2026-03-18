package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	for attempt := 0; ; attempt++ {
		_, err := s.pool.Exec(ctx, schemaSQL)
		if err == nil {
			return nil
		}
		// Concurrent CREATE TABLE IF NOT EXISTS can race on implicit
		// composite-type creation, producing a unique_violation on
		// pg_type_typname_nsp_index. Retry after a short delay.
		var pgErr *pgconn.PgError
		if attempt < 3 && errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "pg_type_typname_nsp_index" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
				continue
			}
		}
		return fmt.Errorf("leases/postgres: ensure schema: %w", err)
	}
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
		version  int64
		expires  time.Time
	)

	err := s.pool.QueryRow(ctx, `
		INSERT INTO leases (name, owner, version, expires_at, created_at, updated_at)
		VALUES ($1,$2, 1, now() + ($3::bigint * interval '1 millisecond'), now(), now())
		ON CONFLICT (name) DO UPDATE
		SET owner = EXCLUDED.owner,
			version = leases.version + 1,
			expires_at = EXCLUDED.expires_at,
			updated_at = now()
		WHERE leases.expires_at <= now()
		RETURNING owner, version, expires_at
	`, name, owner, ttlMS).Scan(&gotOwner, &version, &expires)
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
		Version:   version,
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
		version  int64
		expires  time.Time
	)
	err := s.pool.QueryRow(ctx, `
		UPDATE leases
		SET expires_at = now() + ($3::bigint * interval '1 millisecond'),
			updated_at = now()
		WHERE name = $1 AND owner = $2 AND expires_at > now()
		RETURNING owner, version, expires_at
	`, name, owner, ttlMS).Scan(&gotOwner, &version, &expires)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			l, dbNow, gerr := s.getWithDBNow(ctx, name)
			if errors.Is(gerr, leases.ErrNotFound) {
				return leases.Lease{}, false, leases.ErrNotFound
			}
			if gerr != nil {
				return leases.Lease{}, false, gerr
			}
			if l.Owner != owner {
				return leases.Lease{}, false, leases.ErrNotOwner
			}
			if !l.ExpiresAt.After(dbNow) {
				return leases.Lease{}, false, leases.ErrExpired
			}
			return leases.Lease{}, false, fmt.Errorf("leases/postgres: renew: unexpected no rows")
		}
		return leases.Lease{}, false, fmt.Errorf("leases/postgres: renew: %w", err)
	}

	return leases.Lease{
		Name:      name,
		Owner:     gotOwner,
		Version:   version,
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

	tag, err := s.pool.Exec(ctx, `
		UPDATE leases
		SET expires_at = now(),
			updated_at = now()
		WHERE name = $1 AND owner = $2 AND expires_at > now()
	`, name, owner)
	if err != nil {
		return fmt.Errorf("leases/postgres: release: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}

	// Idempotent if already absent; otherwise reject non-owner.
	l, dbNow, gerr := s.getWithDBNow(ctx, name)
	if errors.Is(gerr, leases.ErrNotFound) {
		return nil
	}
	if gerr != nil {
		return gerr
	}
	if l.Owner != owner {
		return leases.ErrNotOwner
	}
	if !l.ExpiresAt.After(dbNow) {
		return nil
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
		version   int64
		expiresAt time.Time
	)
	err := s.pool.QueryRow(ctx, `SELECT owner, version, expires_at FROM leases WHERE name = $1`, name).Scan(&owner, &version, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return leases.Lease{}, leases.ErrNotFound
		}
		return leases.Lease{}, fmt.Errorf("leases/postgres: get: %w", err)
	}

	return leases.Lease{
		Name:      name,
		Owner:     owner,
		Version:   version,
		ExpiresAt: expiresAt,
	}, nil
}

func (s *Store) getWithDBNow(ctx context.Context, name string) (leases.Lease, time.Time, error) {
	if s == nil || s.pool == nil {
		return leases.Lease{}, time.Time{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if name == "" {
		return leases.Lease{}, time.Time{}, leases.ErrInvalidInput
	}

	var (
		owner     string
		version   int64
		expiresAt time.Time
		dbNow     time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT owner, version, expires_at, now()
		FROM leases
		WHERE name = $1
	`, name).Scan(&owner, &version, &expiresAt, &dbNow)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return leases.Lease{}, time.Time{}, leases.ErrNotFound
		}
		return leases.Lease{}, time.Time{}, fmt.Errorf("leases/postgres: get with db now: %w", err)
	}

	return leases.Lease{
		Name:      name,
		Owner:     owner,
		Version:   version,
		ExpiresAt: expiresAt,
	}, dbNow, nil
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
