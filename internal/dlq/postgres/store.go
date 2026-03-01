package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/dlq"
)

// Store implements dlq.Store backed by PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new DLQ postgres store.
func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", dlq.ErrInvalidConfig)
	}
	return &Store{pool: pool}, nil
}

// EnsureSchema creates the DLQ tables and indexes if they do not exist.
func (s *Store) EnsureSchema(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("dlq/postgres: ensure schema: %w", err)
	}
	return nil
}

// InsertProofDLQ inserts a proof DLQ record. Uses ON CONFLICT DO NOTHING for idempotency.
func (s *Store) InsertProofDLQ(ctx context.Context, rec dlq.ProofDLQRecord) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO proof_dlq (
			job_id, pipeline, image_id, state, error_code, error_message,
			attempt_count, job_payload, created_at, acknowledged
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false)
		ON CONFLICT (job_id) DO NOTHING
	`,
		rec.JobID[:],
		rec.Pipeline,
		rec.ImageID[:],
		rec.State,
		rec.ErrorCode,
		nilIfEmpty(rec.ErrorMessage),
		rec.AttemptCount,
		rec.JobPayload,
		coalesceTime(rec.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("dlq/postgres: insert proof dlq: %w", err)
	}
	return nil
}

// InsertDepositBatchDLQ inserts a deposit batch DLQ record. Uses ON CONFLICT DO NOTHING for idempotency.
func (s *Store) InsertDepositBatchDLQ(ctx context.Context, rec dlq.DepositBatchDLQRecord) error {
	depositIDs := encodeByteaArray(rec.DepositIDs)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO deposit_batch_dlq (
			batch_id, deposit_ids, items_count, state, failure_stage,
			error_code, error_message, attempt_count, created_at, acknowledged
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, false)
		ON CONFLICT (batch_id) DO NOTHING
	`,
		rec.BatchID[:],
		depositIDs,
		rec.ItemsCount,
		rec.State,
		rec.FailureStage,
		nilIfEmpty(rec.ErrorCode),
		nilIfEmpty(rec.ErrorMessage),
		rec.AttemptCount,
		coalesceTime(rec.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("dlq/postgres: insert deposit batch dlq: %w", err)
	}
	return nil
}

// InsertWithdrawalBatchDLQ inserts a withdrawal batch DLQ record. Uses ON CONFLICT DO NOTHING for idempotency.
func (s *Store) InsertWithdrawalBatchDLQ(ctx context.Context, rec dlq.WithdrawalBatchDLQRecord) error {
	withdrawalIDs := encodeByteaArray(rec.WithdrawalIDs)

	_, err := s.pool.Exec(ctx, `
		INSERT INTO withdrawal_batch_dlq (
			batch_id, withdrawal_ids, items_count, state, failure_stage,
			error_code, error_message, rebroadcast_attempts, juno_tx_id,
			created_at, acknowledged
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false)
		ON CONFLICT (batch_id) DO NOTHING
	`,
		rec.BatchID[:],
		withdrawalIDs,
		rec.ItemsCount,
		rec.State,
		rec.FailureStage,
		nilIfEmpty(rec.ErrorCode),
		nilIfEmpty(rec.ErrorMessage),
		rec.RebroadcastAttempts,
		nilIfEmpty(rec.JunoTxID),
		coalesceTime(rec.CreatedAt),
	)
	if err != nil {
		return fmt.Errorf("dlq/postgres: insert withdrawal batch dlq: %w", err)
	}
	return nil
}

// ListProofDLQ lists proof DLQ records with optional filtering.
func (s *Store) ListProofDLQ(ctx context.Context, filter dlq.DLQFilter) ([]dlq.ProofDLQRecord, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	query, args := buildProofListQuery(filter, limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("dlq/postgres: list proof dlq: %w", err)
	}
	defer rows.Close()

	var out []dlq.ProofDLQRecord
	for rows.Next() {
		var (
			jobIDRaw    []byte
			imageIDRaw  []byte
			errMsg      *string
			ackAt       *time.Time
			rec         dlq.ProofDLQRecord
		)
		if err := rows.Scan(
			&jobIDRaw,
			&rec.Pipeline,
			&imageIDRaw,
			&rec.State,
			&rec.ErrorCode,
			&errMsg,
			&rec.AttemptCount,
			&rec.JobPayload,
			&rec.CreatedAt,
			&rec.Acknowledged,
			&ackAt,
		); err != nil {
			return nil, fmt.Errorf("dlq/postgres: scan proof dlq row: %w", err)
		}
		copy(rec.JobID[:], jobIDRaw)
		copy(rec.ImageID[:], imageIDRaw)
		if errMsg != nil {
			rec.ErrorMessage = *errMsg
		}
		rec.AckAt = ackAt
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dlq/postgres: list proof dlq rows: %w", err)
	}
	return out, nil
}

// ListDepositBatchDLQ lists deposit batch DLQ records with optional filtering.
func (s *Store) ListDepositBatchDLQ(ctx context.Context, filter dlq.DLQFilter) ([]dlq.DepositBatchDLQRecord, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	query, args := buildDepositBatchListQuery(filter, limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("dlq/postgres: list deposit batch dlq: %w", err)
	}
	defer rows.Close()

	var out []dlq.DepositBatchDLQRecord
	for rows.Next() {
		var (
			batchIDRaw []byte
			depositIDs [][]byte
			errCode    *string
			errMsg     *string
			ackAt      *time.Time
			rec        dlq.DepositBatchDLQRecord
		)
		if err := rows.Scan(
			&batchIDRaw,
			&depositIDs,
			&rec.ItemsCount,
			&rec.State,
			&rec.FailureStage,
			&errCode,
			&errMsg,
			&rec.AttemptCount,
			&rec.CreatedAt,
			&rec.Acknowledged,
			&ackAt,
		); err != nil {
			return nil, fmt.Errorf("dlq/postgres: scan deposit batch dlq row: %w", err)
		}
		copy(rec.BatchID[:], batchIDRaw)
		rec.DepositIDs = decodeByteaArray(depositIDs)
		if errCode != nil {
			rec.ErrorCode = *errCode
		}
		if errMsg != nil {
			rec.ErrorMessage = *errMsg
		}
		rec.AckAt = ackAt
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dlq/postgres: list deposit batch dlq rows: %w", err)
	}
	return out, nil
}

// ListWithdrawalBatchDLQ lists withdrawal batch DLQ records with optional filtering.
func (s *Store) ListWithdrawalBatchDLQ(ctx context.Context, filter dlq.DLQFilter) ([]dlq.WithdrawalBatchDLQRecord, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	query, args := buildWithdrawalBatchListQuery(filter, limit)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("dlq/postgres: list withdrawal batch dlq: %w", err)
	}
	defer rows.Close()

	var out []dlq.WithdrawalBatchDLQRecord
	for rows.Next() {
		var (
			batchIDRaw    []byte
			withdrawalIDs [][]byte
			errCode       *string
			errMsg        *string
			junoTxID      *string
			ackAt         *time.Time
			rec           dlq.WithdrawalBatchDLQRecord
		)
		if err := rows.Scan(
			&batchIDRaw,
			&withdrawalIDs,
			&rec.ItemsCount,
			&rec.State,
			&rec.FailureStage,
			&errCode,
			&errMsg,
			&rec.RebroadcastAttempts,
			&junoTxID,
			&rec.CreatedAt,
			&rec.Acknowledged,
			&ackAt,
		); err != nil {
			return nil, fmt.Errorf("dlq/postgres: scan withdrawal batch dlq row: %w", err)
		}
		copy(rec.BatchID[:], batchIDRaw)
		rec.WithdrawalIDs = decodeByteaArray(withdrawalIDs)
		if errCode != nil {
			rec.ErrorCode = *errCode
		}
		if errMsg != nil {
			rec.ErrorMessage = *errMsg
		}
		if junoTxID != nil {
			rec.JunoTxID = *junoTxID
		}
		rec.AckAt = ackAt
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("dlq/postgres: list withdrawal batch dlq rows: %w", err)
	}
	return out, nil
}

// CountUnacknowledged returns the count of unacknowledged records in each DLQ table.
func (s *Store) CountUnacknowledged(ctx context.Context) (dlq.DLQCounts, error) {
	var counts dlq.DLQCounts

	row := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM proof_dlq WHERE NOT acknowledged`)
	if err := row.Scan(&counts.Proofs); err != nil {
		return dlq.DLQCounts{}, fmt.Errorf("dlq/postgres: count proof dlq: %w", err)
	}

	row = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM deposit_batch_dlq WHERE NOT acknowledged`)
	if err := row.Scan(&counts.DepositBatches); err != nil {
		return dlq.DLQCounts{}, fmt.Errorf("dlq/postgres: count deposit batch dlq: %w", err)
	}

	row = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM withdrawal_batch_dlq WHERE NOT acknowledged`)
	if err := row.Scan(&counts.WithdrawalBatches); err != nil {
		return dlq.DLQCounts{}, fmt.Errorf("dlq/postgres: count withdrawal batch dlq: %w", err)
	}

	return counts, nil
}

// Acknowledge marks a DLQ record as acknowledged. The table parameter must be one of
// "proof_dlq", "deposit_batch_dlq", or "withdrawal_batch_dlq".
func (s *Store) Acknowledge(ctx context.Context, table string, id []byte) error {
	if !dlq.ValidDLQTables[table] {
		return fmt.Errorf("%w: %q", dlq.ErrInvalidTable, table)
	}
	if len(id) != 32 {
		return fmt.Errorf("%w: id must be 32 bytes", dlq.ErrInvalidConfig)
	}

	pkCol := primaryKeyColumn(table)

	// Use string concatenation for table/column names (validated above) and parameterized
	// query for user-supplied data.
	query := `UPDATE ` + table + ` SET acknowledged = true, ack_at = now() WHERE ` + pkCol + ` = $1 AND NOT acknowledged`
	tag, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("dlq/postgres: acknowledge %s: %w", table, err)
	}
	if tag.RowsAffected() == 0 {
		return dlq.ErrNotFound
	}
	return nil
}

// primaryKeyColumn returns the primary key column name for each DLQ table.
func primaryKeyColumn(table string) string {
	switch table {
	case "proof_dlq":
		return "job_id"
	default:
		return "batch_id"
	}
}

// buildProofListQuery builds the SQL query and args for listing proof DLQ records.
func buildProofListQuery(filter dlq.DLQFilter, limit int) (string, []interface{}) {
	var (
		clauses []string
		args    []interface{}
		idx     = 1
	)

	if filter.ErrorCode != "" {
		clauses = append(clauses, fmt.Sprintf("error_code = $%d", idx))
		args = append(args, filter.ErrorCode)
		idx++
	}
	if filter.Acknowledged != nil {
		clauses = append(clauses, fmt.Sprintf("acknowledged = $%d", idx))
		args = append(args, *filter.Acknowledged)
		idx++
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, filter.Since)
		idx++
	}

	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT job_id, pipeline, image_id, state, error_code, error_message,
		       attempt_count, job_payload, created_at, acknowledged, ack_at
		FROM proof_dlq
		%s
		ORDER BY created_at ASC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)

	args = append(args, limit, filter.Offset)
	return query, args
}

// buildDepositBatchListQuery builds the SQL query and args for listing deposit batch DLQ records.
func buildDepositBatchListQuery(filter dlq.DLQFilter, limit int) (string, []interface{}) {
	var (
		clauses []string
		args    []interface{}
		idx     = 1
	)

	if filter.ErrorCode != "" {
		clauses = append(clauses, fmt.Sprintf("error_code = $%d", idx))
		args = append(args, filter.ErrorCode)
		idx++
	}
	if filter.FailureStage != "" {
		clauses = append(clauses, fmt.Sprintf("failure_stage = $%d", idx))
		args = append(args, filter.FailureStage)
		idx++
	}
	if filter.Acknowledged != nil {
		clauses = append(clauses, fmt.Sprintf("acknowledged = $%d", idx))
		args = append(args, *filter.Acknowledged)
		idx++
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, filter.Since)
		idx++
	}

	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT batch_id, deposit_ids, items_count, state, failure_stage,
		       error_code, error_message, attempt_count, created_at, acknowledged, ack_at
		FROM deposit_batch_dlq
		%s
		ORDER BY created_at ASC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)

	args = append(args, limit, filter.Offset)
	return query, args
}

// buildWithdrawalBatchListQuery builds the SQL query and args for listing withdrawal batch DLQ records.
func buildWithdrawalBatchListQuery(filter dlq.DLQFilter, limit int) (string, []interface{}) {
	var (
		clauses []string
		args    []interface{}
		idx     = 1
	)

	if filter.ErrorCode != "" {
		clauses = append(clauses, fmt.Sprintf("error_code = $%d", idx))
		args = append(args, filter.ErrorCode)
		idx++
	}
	if filter.FailureStage != "" {
		clauses = append(clauses, fmt.Sprintf("failure_stage = $%d", idx))
		args = append(args, filter.FailureStage)
		idx++
	}
	if filter.Acknowledged != nil {
		clauses = append(clauses, fmt.Sprintf("acknowledged = $%d", idx))
		args = append(args, *filter.Acknowledged)
		idx++
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, filter.Since)
		idx++
	}

	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT batch_id, withdrawal_ids, items_count, state, failure_stage,
		       error_code, error_message, rebroadcast_attempts, juno_tx_id,
		       created_at, acknowledged, ack_at
		FROM withdrawal_batch_dlq
		%s
		ORDER BY created_at ASC
		LIMIT $%d OFFSET $%d
	`, where, idx, idx+1)

	args = append(args, limit, filter.Offset)
	return query, args
}

// encodeByteaArray converts [][32]byte to [][]byte for pgx BYTEA[] encoding.
func encodeByteaArray(ids [][32]byte) [][]byte {
	out := make([][]byte, len(ids))
	for i, id := range ids {
		raw := make([]byte, 32)
		copy(raw, id[:])
		out[i] = raw
	}
	return out
}

// decodeByteaArray converts [][]byte from pgx BYTEA[] to [][32]byte.
func decodeByteaArray(raw [][]byte) [][32]byte {
	out := make([][32]byte, len(raw))
	for i, b := range raw {
		if len(b) == 32 {
			copy(out[i][:], b)
		}
	}
	return out
}

// nilIfEmpty returns nil for empty strings, otherwise the string pointer.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// coalesceTime returns time.Now() if t is zero, otherwise t.
func coalesceTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}

// Compile-time interface check.
var _ dlq.Store = (*Store)(nil)
