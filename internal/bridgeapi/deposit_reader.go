package bridgeapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/deposit"
)

type PostgresDepositReader struct {
	pool *pgxpool.Pool
}

func NewPostgresDepositReader(pool *pgxpool.Pool) (*PostgresDepositReader, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", ErrInvalidConfig)
	}
	return &PostgresDepositReader{pool: pool}, nil
}

func (r *PostgresDepositReader) Get(ctx context.Context, depositID [32]byte) (DepositStatus, error) {
	if r == nil || r.pool == nil {
		return DepositStatus{}, fmt.Errorf("%w: nil reader", ErrInvalidConfig)
	}

	row := r.pool.QueryRow(ctx,
		depositStatusSelect+`WHERE dj.deposit_id = $1`,
		depositID[:],
	)

	st, err := scanDepositStatusRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DepositStatus{}, deposit.ErrNotFound
		}
		return DepositStatus{}, fmt.Errorf("bridgeapi: query deposit status: %w", err)
	}
	return st, nil
}
