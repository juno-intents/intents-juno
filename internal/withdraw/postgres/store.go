package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

var ErrInvalidConfig = errors.New("withdraw/postgres: invalid config")

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
		return fmt.Errorf("withdraw/postgres: ensure schema: %w", err)
	}
	return nil
}

func (s *Store) UpsertRequested(ctx context.Context, w withdraw.Withdrawal) (withdraw.Withdrawal, bool, error) {
	if s == nil || s.pool == nil {
		return withdraw.Withdrawal{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if err := w.Validate(); err != nil {
		return withdraw.Withdrawal{}, false, err
	}
	if w.Amount > math.MaxInt64 {
		return withdraw.Withdrawal{}, false, fmt.Errorf("%w: amount too large", withdraw.ErrInvalidConfig)
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO withdrawal_requests (
			withdrawal_id,
			requester,
			amount,
			fee_bps,
			recipient_ua,
			expiry,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,now(),now())
		ON CONFLICT (withdrawal_id) DO NOTHING
	`, w.ID[:], w.Requester[:], int64(w.Amount), int32(w.FeeBps), w.RecipientUA, w.Expiry)
	if err != nil {
		return withdraw.Withdrawal{}, false, fmt.Errorf("withdraw/postgres: insert requested: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return cloneWithdrawal(w), true, nil
	}

	existing, err := s.getWithdrawal(ctx, w.ID)
	if err != nil {
		return withdraw.Withdrawal{}, false, err
	}
	if !withdrawalEqual(existing, w) {
		return withdraw.Withdrawal{}, false, withdraw.ErrWithdrawalMismatch
	}
	return existing, false, nil
}

func (s *Store) ClaimUnbatched(ctx context.Context, owner string, ttl time.Duration, max int) ([]withdraw.Withdrawal, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" || ttl <= 0 || max <= 0 {
		return nil, withdraw.ErrInvalidConfig
	}

	ttlMS := ttlMilliseconds(ttl)

	rows, err := s.pool.Query(ctx, `
		WITH cte AS (
			SELECT wr.withdrawal_id
			FROM withdrawal_requests wr
			WHERE NOT EXISTS (
				SELECT 1 FROM withdrawal_batch_items wbi WHERE wbi.withdrawal_id = wr.withdrawal_id
			)
			AND (wr.claimed_by IS NULL OR wr.claim_expires_at <= now())
			ORDER BY wr.withdrawal_id ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE withdrawal_requests wr
		SET claimed_by = $2,
			claim_expires_at = now() + ($3::bigint * interval '1 millisecond'),
			updated_at = now()
		FROM cte
		WHERE wr.withdrawal_id = cte.withdrawal_id
		RETURNING wr.withdrawal_id, wr.requester, wr.amount, wr.fee_bps, wr.recipient_ua, wr.expiry
	`, max, owner, ttlMS)
	if err != nil {
		return nil, fmt.Errorf("withdraw/postgres: claim unbatched: %w", err)
	}
	defer rows.Close()

	var out []withdraw.Withdrawal
	for rows.Next() {
		var (
			idRaw   []byte
			reqRaw  []byte
			amount  int64
			feeBps  int32
			recipUA []byte
			expiry  time.Time
		)
		if err := rows.Scan(&idRaw, &reqRaw, &amount, &feeBps, &recipUA, &expiry); err != nil {
			return nil, fmt.Errorf("withdraw/postgres: scan claim row: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return nil, err
		}
		req, err := to20(reqRaw)
		if err != nil {
			return nil, err
		}
		if amount < 0 || feeBps < 0 {
			return nil, fmt.Errorf("withdraw/postgres: negative values in db")
		}
		out = append(out, withdraw.Withdrawal{
			ID:          id,
			Requester:   req,
			Amount:      uint64(amount),
			FeeBps:      uint32(feeBps),
			RecipientUA: append([]byte(nil), recipUA...),
			Expiry:      expiry,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("withdraw/postgres: claim rows: %w", err)
	}
	return out, nil
}

func (s *Store) CreatePlannedBatch(ctx context.Context, owner string, b withdraw.Batch) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" {
		return withdraw.ErrInvalidConfig
	}
	if b.ID == ([32]byte{}) || b.State != withdraw.BatchStatePlanned || len(b.WithdrawalIDs) == 0 || len(b.TxPlan) == 0 {
		return withdraw.ErrInvalidConfig
	}

	ids, err := sortedUnique32(b.WithdrawalIDs)
	if err != nil {
		return err
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("withdraw/postgres: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Insert batch row (idempotent).
	_, err = tx.Exec(ctx, `
		INSERT INTO withdrawal_batches (batch_id, state, tx_plan, created_at, updated_at)
		VALUES ($1,$2,$3,now(),now())
		ON CONFLICT (batch_id) DO NOTHING
	`, b.ID[:], int16(withdraw.BatchStatePlanned), b.TxPlan)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: insert batch: %w", err)
	}

	// Ensure each withdrawal is claimed by owner and not expired; clear claims.
	for _, id := range ids {
		tag, err := tx.Exec(ctx, `
			UPDATE withdrawal_requests
			SET claimed_by = NULL,
				claim_expires_at = NULL,
				updated_at = now()
			WHERE withdrawal_id = $1
				AND claimed_by = $2
				AND claim_expires_at > now()
		`, id[:], owner)
		if err != nil {
			return fmt.Errorf("withdraw/postgres: clear claim: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return withdraw.ErrInvalidTransition
		}
	}

	// Insert batch items (unique on withdrawal_id prevents double-batching).
	for i, id := range ids {
		_, err := tx.Exec(ctx, `
			INSERT INTO withdrawal_batch_items (batch_id, withdrawal_id, position)
			VALUES ($1,$2,$3)
		`, b.ID[:], id[:], i)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return withdraw.ErrInvalidTransition
			}
			return fmt.Errorf("withdraw/postgres: insert batch item: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("withdraw/postgres: commit: %w", err)
	}
	return nil
}

func (s *Store) GetBatch(ctx context.Context, batchID [32]byte) (withdraw.Batch, error) {
	if s == nil || s.pool == nil {
		return withdraw.Batch{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	var (
		idRaw    []byte
		state    int16
		txPlan   []byte
		signedTx []byte
		junoTxID *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT batch_id, state, tx_plan, signed_tx, juno_txid
		FROM withdrawal_batches
		WHERE batch_id = $1
	`, batchID[:]).Scan(&idRaw, &state, &txPlan, &signedTx, &junoTxID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return withdraw.Batch{}, withdraw.ErrNotFound
		}
		return withdraw.Batch{}, fmt.Errorf("withdraw/postgres: get batch: %w", err)
	}

	id, err := to32(idRaw)
	if err != nil {
		return withdraw.Batch{}, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT withdrawal_id
		FROM withdrawal_batch_items
		WHERE batch_id = $1
		ORDER BY position ASC
	`, batchID[:])
	if err != nil {
		return withdraw.Batch{}, fmt.Errorf("withdraw/postgres: get batch items: %w", err)
	}
	defer rows.Close()

	var ids [][32]byte
	for rows.Next() {
		var widRaw []byte
		if err := rows.Scan(&widRaw); err != nil {
			return withdraw.Batch{}, fmt.Errorf("withdraw/postgres: scan batch item: %w", err)
		}
		wid, err := to32(widRaw)
		if err != nil {
			return withdraw.Batch{}, err
		}
		ids = append(ids, wid)
	}
	if err := rows.Err(); err != nil {
		return withdraw.Batch{}, fmt.Errorf("withdraw/postgres: batch items rows: %w", err)
	}

	out := withdraw.Batch{
		ID:            id,
		WithdrawalIDs: ids,
		State:         withdraw.BatchState(state),
		TxPlan:        append([]byte(nil), txPlan...),
		SignedTx:      append([]byte(nil), signedTx...),
	}
	if junoTxID != nil {
		out.JunoTxID = *junoTxID
	}
	return out, nil
}

func (s *Store) ListBatchesByState(ctx context.Context, state withdraw.BatchState) ([]withdraw.Batch, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	rows, err := s.pool.Query(ctx, `SELECT batch_id FROM withdrawal_batches WHERE state = $1 ORDER BY batch_id ASC`, int16(state))
	if err != nil {
		return nil, fmt.Errorf("withdraw/postgres: list batches: %w", err)
	}
	defer rows.Close()

	var out []withdraw.Batch
	for rows.Next() {
		var idRaw []byte
		if err := rows.Scan(&idRaw); err != nil {
			return nil, fmt.Errorf("withdraw/postgres: scan list batch id: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return nil, err
		}
		b, err := s.GetBatch(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("withdraw/postgres: list batches rows: %w", err)
	}
	return out, nil
}

func (s *Store) MarkBatchSigning(ctx context.Context, batchID [32]byte) error {
	return s.updateState(ctx, batchID, withdraw.BatchStatePlanned, withdraw.BatchStateSigning)
}

func (s *Store) SetBatchSigned(ctx context.Context, batchID [32]byte, signedTx []byte) error {
	if len(signedTx) == 0 {
		return withdraw.ErrInvalidConfig
	}

	state, existingSigned, _, err := s.getBatchStateFields(ctx, batchID)
	if err != nil {
		return err
	}
	if state < withdraw.BatchStateSigning {
		return withdraw.ErrInvalidTransition
	}
	if state >= withdraw.BatchStateSigned {
		if !bytes.Equal(existingSigned, signedTx) {
			return withdraw.ErrBatchMismatch
		}
		return nil
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $2, signed_tx = $3, updated_at = now()
		WHERE batch_id = $1 AND state = $4
	`, batchID[:], int16(withdraw.BatchStateSigned), signedTx, int16(withdraw.BatchStateSigning))
	if err != nil {
		return fmt.Errorf("withdraw/postgres: set signed: %w", err)
	}
	if tag.RowsAffected() != 1 {
		// Re-check state for idempotency vs races.
		state2, existingSigned2, _, err2 := s.getBatchStateFields(ctx, batchID)
		if err2 != nil {
			return err2
		}
		if state2 >= withdraw.BatchStateSigned && bytes.Equal(existingSigned2, signedTx) {
			return nil
		}
		return withdraw.ErrInvalidTransition
	}
	return nil
}

func (s *Store) SetBatchBroadcasted(ctx context.Context, batchID [32]byte, txid string) error {
	if txid == "" {
		return withdraw.ErrInvalidConfig
	}

	state, _, existingTxID, err := s.getBatchStateFields(ctx, batchID)
	if err != nil {
		return err
	}
	if state < withdraw.BatchStateSigned {
		return withdraw.ErrInvalidTransition
	}
	if state >= withdraw.BatchStateBroadcasted {
		if existingTxID != txid {
			return withdraw.ErrBatchMismatch
		}
		return nil
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $2, juno_txid = $3, updated_at = now()
		WHERE batch_id = $1 AND state = $4
	`, batchID[:], int16(withdraw.BatchStateBroadcasted), txid, int16(withdraw.BatchStateSigned))
	if err != nil {
		return fmt.Errorf("withdraw/postgres: set broadcasted: %w", err)
	}
	if tag.RowsAffected() != 1 {
		state2, _, existingTxID2, err2 := s.getBatchStateFields(ctx, batchID)
		if err2 != nil {
			return err2
		}
		if state2 >= withdraw.BatchStateBroadcasted && existingTxID2 == txid {
			return nil
		}
		return withdraw.ErrInvalidTransition
	}
	return nil
}

func (s *Store) SetBatchConfirmed(ctx context.Context, batchID [32]byte) error {
	state, _, _, err := s.getBatchStateFields(ctx, batchID)
	if err != nil {
		return err
	}
	if state < withdraw.BatchStateBroadcasted {
		return withdraw.ErrInvalidTransition
	}
	if state == withdraw.BatchStateConfirmed {
		return nil
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $2, updated_at = now()
		WHERE batch_id = $1 AND state = $3
	`, batchID[:], int16(withdraw.BatchStateConfirmed), int16(withdraw.BatchStateBroadcasted))
	if err != nil {
		return fmt.Errorf("withdraw/postgres: set confirmed: %w", err)
	}
	if tag.RowsAffected() != 1 {
		// Idempotent if already confirmed.
		state2, _, _, err2 := s.getBatchStateFields(ctx, batchID)
		if err2 != nil {
			return err2
		}
		if state2 == withdraw.BatchStateConfirmed {
			return nil
		}
		return withdraw.ErrInvalidTransition
	}
	return nil
}

func (s *Store) updateState(ctx context.Context, batchID [32]byte, from, to withdraw.BatchState) error {
	state, _, _, err := s.getBatchStateFields(ctx, batchID)
	if err != nil {
		return err
	}
	if state >= to {
		return nil
	}
	if state != from {
		return withdraw.ErrInvalidTransition
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $2, updated_at = now()
		WHERE batch_id = $1 AND state = $3
	`, batchID[:], int16(to), int16(from))
	if err != nil {
		return fmt.Errorf("withdraw/postgres: update state: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return withdraw.ErrInvalidTransition
	}
	return nil
}

func (s *Store) getBatchStateFields(ctx context.Context, batchID [32]byte) (withdraw.BatchState, []byte, string, error) {
	if s == nil || s.pool == nil {
		return 0, nil, "", fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	var (
		state    int16
		signedTx []byte
		junoTxID *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT state, signed_tx, juno_txid
		FROM withdrawal_batches
		WHERE batch_id = $1
	`, batchID[:]).Scan(&state, &signedTx, &junoTxID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil, "", withdraw.ErrNotFound
		}
		return 0, nil, "", fmt.Errorf("withdraw/postgres: get batch state: %w", err)
	}
	txid := ""
	if junoTxID != nil {
		txid = *junoTxID
	}
	return withdraw.BatchState(state), signedTx, txid, nil
}

func (s *Store) getWithdrawal(ctx context.Context, id [32]byte) (withdraw.Withdrawal, error) {
	var (
		idRaw  []byte
		reqRaw []byte
		amount int64
		feeBps int32
		ua     []byte
		expiry time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT withdrawal_id, requester, amount, fee_bps, recipient_ua, expiry
		FROM withdrawal_requests
		WHERE withdrawal_id = $1
	`, id[:]).Scan(&idRaw, &reqRaw, &amount, &feeBps, &ua, &expiry)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return withdraw.Withdrawal{}, withdraw.ErrNotFound
		}
		return withdraw.Withdrawal{}, fmt.Errorf("withdraw/postgres: get withdrawal: %w", err)
	}

	gotID, err := to32(idRaw)
	if err != nil {
		return withdraw.Withdrawal{}, err
	}
	req, err := to20(reqRaw)
	if err != nil {
		return withdraw.Withdrawal{}, err
	}
	if amount < 0 || feeBps < 0 {
		return withdraw.Withdrawal{}, fmt.Errorf("withdraw/postgres: negative values in db")
	}
	return withdraw.Withdrawal{
		ID:          gotID,
		Requester:   req,
		Amount:      uint64(amount),
		FeeBps:      uint32(feeBps),
		RecipientUA: append([]byte(nil), ua...),
		Expiry:      expiry,
	}, nil
}

func cloneWithdrawal(w withdraw.Withdrawal) withdraw.Withdrawal {
	w.RecipientUA = append([]byte(nil), w.RecipientUA...)
	return w
}

func withdrawalEqual(a, b withdraw.Withdrawal) bool {
	if a.ID != b.ID || a.Requester != b.Requester || a.Amount != b.Amount || a.FeeBps != b.FeeBps || !a.Expiry.Equal(b.Expiry) {
		return false
	}
	return bytes.Equal(a.RecipientUA, b.RecipientUA)
}

func sortedUnique32(in [][32]byte) ([][32]byte, error) {
	ids := make([][32]byte, len(in))
	copy(ids, in)
	slices.SortFunc(ids, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return nil, withdraw.ErrDuplicateWithdrawalID
		}
	}
	return ids, nil
}

func to32(b []byte) ([32]byte, error) {
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("withdraw/postgres: expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func to20(b []byte) ([20]byte, error) {
	if len(b) != 20 {
		return [20]byte{}, fmt.Errorf("withdraw/postgres: expected 20 bytes, got %d", len(b))
	}
	var out [20]byte
	copy(out[:], b)
	return out, nil
}

func ttlMilliseconds(ttl time.Duration) int64 {
	ms := ttl.Milliseconds()
	if ms <= 0 {
		return 1
	}
	return ms
}

var _ withdraw.Store = (*Store)(nil)
