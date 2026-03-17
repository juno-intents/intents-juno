package depositrepair

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("depositrepair: nil pool")
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) ListTxHashes(ctx context.Context, limit int) ([][32]byte, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT tx_hash
		FROM deposit_jobs
		WHERE tx_hash IS NOT NULL
		ORDER BY tx_hash
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("depositrepair/postgres: list tx hashes: %w", err)
	}
	defer rows.Close()

	out := make([][32]byte, 0, limit)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("depositrepair/postgres: scan tx hash: %w", err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("depositrepair/postgres: invalid tx hash length %d", len(raw))
		}
		var txHash [32]byte
		copy(txHash[:], raw)
		out = append(out, txHash)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("depositrepair/postgres: iterate tx hashes: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) ListDepositIDsByTxHash(ctx context.Context, txHash [32]byte) ([][32]byte, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT deposit_id
		FROM deposit_jobs
		WHERE tx_hash = $1
		ORDER BY deposit_id
	`, txHash[:])
	if err != nil {
		return nil, fmt.Errorf("depositrepair/postgres: list deposit ids: %w", err)
	}
	defer rows.Close()

	out := make([][32]byte, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("depositrepair/postgres: scan deposit id: %w", err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("depositrepair/postgres: invalid deposit id length %d", len(raw))
		}
		var depositID [32]byte
		copy(depositID[:], raw)
		out = append(out, depositID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("depositrepair/postgres: iterate deposit ids: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) ApplyTxHashOutcome(
	ctx context.Context,
	txHash [32]byte,
	finalizedIDs [][32]byte,
	rejectedIDs [][32]byte,
	rejectionReason string,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("depositrepair/postgres: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if len(finalizedIDs) > 0 {
		_, err = tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET state = 6, rejection_reason = NULL, updated_at = now()
			WHERE tx_hash = $1 AND deposit_id = ANY($2)
		`, txHash[:], toRawIDs(finalizedIDs))
		if err != nil {
			return fmt.Errorf("depositrepair/postgres: update finalized deposits: %w", err)
		}
	}
	if len(rejectedIDs) > 0 {
		_, err = tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET state = 7, rejection_reason = $3, updated_at = now()
			WHERE tx_hash = $1 AND deposit_id = ANY($2)
		`, txHash[:], toRawIDs(rejectedIDs), rejectionReason)
		if err != nil {
			return fmt.Errorf("depositrepair/postgres: update rejected deposits: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("depositrepair/postgres: commit tx: %w", err)
	}
	return nil
}

func (s *PostgresStore) RepairFinalized(ctx context.Context, depositID [32]byte, txHash [32]byte) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE deposit_jobs
		SET
			state = 6,
			tx_hash = $2,
			rejection_reason = NULL,
			updated_at = now()
		WHERE deposit_id = $1
	`, depositID[:], txHash[:])
	if err != nil {
		return fmt.Errorf("depositrepair/postgres: repair finalized deposit: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("depositrepair/postgres: repair finalized deposit: no rows updated")
	}
	return nil
}

func toRawIDs(ids [][32]byte) [][]byte {
	out := make([][]byte, 0, len(ids))
	for _, id := range ids {
		raw := make([]byte, 32)
		copy(raw, id[:])
		out = append(out, raw)
	}
	return out
}
