package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
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
		return fmt.Errorf("withdraw/postgres: ensure schema: %w", err)
	}
}

func (s *Store) StoreFinalizerCheckpoint(ctx context.Context, cp checkpoint.Checkpoint, operatorSignatures [][]byte) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	checkpointJSON, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: marshal finalizer checkpoint: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO withdraw_finalizer_checkpoint_state (singleton, checkpoint_json, operator_signatures, updated_at)
		VALUES (TRUE, $1, $2, now())
		ON CONFLICT (singleton) DO UPDATE
		SET checkpoint_json = EXCLUDED.checkpoint_json,
			operator_signatures = EXCLUDED.operator_signatures,
			updated_at = now()
	`, checkpointJSON, operatorSignatures)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: store finalizer checkpoint: %w", err)
	}
	return nil
}

func (s *Store) LoadFinalizerCheckpoint(ctx context.Context) (checkpoint.Checkpoint, [][]byte, bool, error) {
	if s == nil || s.pool == nil {
		return checkpoint.Checkpoint{}, nil, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	var (
		checkpointJSON []byte
		operatorSigs   [][]byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT checkpoint_json, operator_signatures
		FROM withdraw_finalizer_checkpoint_state
		WHERE singleton = TRUE
	`).Scan(&checkpointJSON, &operatorSigs)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return checkpoint.Checkpoint{}, nil, false, nil
		}
		return checkpoint.Checkpoint{}, nil, false, fmt.Errorf("withdraw/postgres: load finalizer checkpoint: %w", err)
	}
	var cp checkpoint.Checkpoint
	if err := json.Unmarshal(checkpointJSON, &cp); err != nil {
		return checkpoint.Checkpoint{}, nil, false, fmt.Errorf("withdraw/postgres: unmarshal finalizer checkpoint: %w", err)
	}
	clonedSigs := make([][]byte, len(operatorSigs))
	for i, sig := range operatorSigs {
		clonedSigs[i] = append([]byte(nil), sig...)
	}
	return cp, clonedSigs, true, nil
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

	var baseBlockNumber *int64
	if w.BaseBlockNumber > 0 {
		bn := w.BaseBlockNumber
		baseBlockNumber = &bn
	}
	var baseBlockHash []byte
	if w.BaseBlockHash != ([32]byte{}) {
		baseBlockHash = w.BaseBlockHash[:]
	}
	var baseTxHash []byte
	if w.BaseTxHash != ([32]byte{}) {
		baseTxHash = w.BaseTxHash[:]
	}
	var baseLogIndex *int64
	if w.BaseTxHash != ([32]byte{}) || w.BaseBlockHash != ([32]byte{}) || w.BaseLogIndex > 0 || w.BaseFinalitySource != "" {
		if w.BaseLogIndex > math.MaxInt64 {
			return withdraw.Withdrawal{}, false, fmt.Errorf("%w: base log index too large", withdraw.ErrInvalidConfig)
		}
		v := int64(w.BaseLogIndex)
		baseLogIndex = &v
	}
	var baseFinalitySource *string
	if w.BaseFinalitySource != "" {
		src := w.BaseFinalitySource
		baseFinalitySource = &src
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO withdrawal_requests (
			withdrawal_id,
			requester,
			amount,
			fee_bps,
			recipient_ua,
			proof_witness_item,
			expiry,
			base_block_number,
			base_block_hash,
			base_tx_hash,
			base_log_index,
			base_finality_source,
			status,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,now(),now())
		ON CONFLICT (withdrawal_id) DO NOTHING
	`, w.ID[:], w.Requester[:], int64(w.Amount), int32(w.FeeBps), w.RecipientUA, w.ProofWitnessItem, w.Expiry, baseBlockNumber, baseBlockHash, baseTxHash, baseLogIndex, baseFinalitySource, int16(withdraw.WithdrawalStatusRequested))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "withdrawal_requests_base_event_key_idx" {
			return withdraw.Withdrawal{}, false, withdraw.ErrWithdrawalMismatch
		}
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

func (s *Store) ClaimUnbatched(ctx context.Context, fence withdraw.Fence, ttl time.Duration, max int) ([]withdraw.Withdrawal, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if err := fence.Validate(); err != nil {
		return nil, err
	}
	if ttl <= 0 || max <= 0 {
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
			AND wr.status = $5
			AND (wr.claimed_by IS NULL OR wr.claim_expires_at <= now())
			ORDER BY wr.withdrawal_id ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		UPDATE withdrawal_requests wr
		SET claimed_by = $2,
			claim_lease_version = $3,
			claim_expires_at = now() + ($4::bigint * interval '1 millisecond'),
			updated_at = now()
		FROM cte
		WHERE wr.withdrawal_id = cte.withdrawal_id
		RETURNING wr.withdrawal_id, wr.requester, wr.amount, wr.fee_bps, wr.recipient_ua, wr.proof_witness_item, wr.expiry, wr.base_block_number, wr.base_block_hash, wr.base_tx_hash, wr.base_log_index, wr.base_finality_source
	`, max, fence.Owner, fence.LeaseVersion, ttlMS, int16(withdraw.WithdrawalStatusRequested))
	if err != nil {
		return nil, fmt.Errorf("withdraw/postgres: claim unbatched: %w", err)
	}
	defer rows.Close()

	var out []withdraw.Withdrawal
	for rows.Next() {
		var (
			idRaw           []byte
			reqRaw          []byte
			amount          int64
			feeBps          int32
			recipUA         []byte
			witness         []byte
			expiry          time.Time
			baseBlockNumber *int64
			baseBlockHash   []byte
			baseTxHash      []byte
			baseLogIndex    *int64
			baseFinality    *string
		)
		if err := rows.Scan(&idRaw, &reqRaw, &amount, &feeBps, &recipUA, &witness, &expiry, &baseBlockNumber, &baseBlockHash, &baseTxHash, &baseLogIndex, &baseFinality); err != nil {
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
		var bn int64
		if baseBlockNumber != nil {
			bn = *baseBlockNumber
		}
		bh, err := toOptional32(baseBlockHash)
		if err != nil {
			return nil, err
		}
		txh, err := toOptional32(baseTxHash)
		if err != nil {
			return nil, err
		}
		var li uint64
		if baseLogIndex != nil {
			if *baseLogIndex < 0 {
				return nil, fmt.Errorf("withdraw/postgres: negative base log index in db")
			}
			li = uint64(*baseLogIndex)
		}
		var finality string
		if baseFinality != nil {
			finality = *baseFinality
		}
		out = append(out, withdraw.Withdrawal{
			ID:                 id,
			Requester:          req,
			Amount:             uint64(amount),
			FeeBps:             uint32(feeBps),
			RecipientUA:        append([]byte(nil), recipUA...),
			ProofWitnessItem:   append([]byte(nil), witness...),
			Expiry:             expiry,
			BaseBlockNumber:    bn,
			BaseBlockHash:      bh,
			BaseTxHash:         txh,
			BaseLogIndex:       li,
			BaseFinalitySource: finality,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("withdraw/postgres: claim rows: %w", err)
	}
	return out, nil
}

func (s *Store) ClaimBatches(ctx context.Context, fence withdraw.Fence, states []withdraw.BatchState, olderThan time.Time, max int) ([]withdraw.Batch, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if err := fence.Validate(); err != nil {
		return nil, err
	}
	if olderThan.IsZero() || max <= 0 || len(states) == 0 {
		return nil, withdraw.ErrInvalidConfig
	}

	batches, err := s.ListBatchesByStatesOlderThan(ctx, states, olderThan, max)
	if err != nil {
		return nil, err
	}

	out := make([]withdraw.Batch, 0, len(batches))
	for _, b := range batches {
		if b.LeaseOwner != "" && b.LeaseOwner != fence.Owner {
			continue
		}
		if err := s.AdoptBatch(ctx, b.ID, fence); err != nil {
			continue
		}
		claimed, err := s.GetBatch(ctx, b.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, claimed)
		if len(out) >= max {
			break
		}
	}
	return out, nil
}

func (s *Store) CreatePlannedBatch(ctx context.Context, fence withdraw.Fence, b withdraw.Batch) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if err := fence.Validate(); err != nil {
		return err
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
	tag, err := tx.Exec(ctx, `
		INSERT INTO withdrawal_batches (batch_id, state, lease_owner, lease_version, tx_plan, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,now(),now())
		ON CONFLICT (batch_id) DO NOTHING
	`, b.ID[:], int16(withdraw.BatchStatePlanned), fence.Owner, fence.LeaseVersion, b.TxPlan)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: insert batch: %w", err)
	}
	if tag.RowsAffected() != 1 {
		existing, getErr := s.GetBatch(ctx, b.ID)
		if getErr != nil {
			return getErr
		}
		if existing.State == withdraw.BatchStatePlanned &&
			existing.LeaseOwner == fence.Owner &&
			existing.LeaseVersion == fence.LeaseVersion &&
			bytes.Equal(existing.TxPlan, b.TxPlan) &&
			slices.Equal(existing.WithdrawalIDs, ids) {
			return nil
		}
		return withdraw.ErrBatchMismatch
	}

	// Ensure each withdrawal is claimed by owner and not expired; clear claims.
	for _, id := range ids {
		tag, err := tx.Exec(ctx, `
			UPDATE withdrawal_requests
			SET claimed_by = NULL,
				claim_lease_version = NULL,
				status = $4,
				claim_expires_at = NULL,
				updated_at = now()
			WHERE withdrawal_id = $1
				AND claimed_by = $2
				AND claim_lease_version = $3
		`, id[:], fence.Owner, fence.LeaseVersion, int16(withdraw.WithdrawalStatusBatched))
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

func (s *Store) GetWithdrawal(ctx context.Context, id [32]byte) (withdraw.Withdrawal, error) {
	if s == nil || s.pool == nil {
		return withdraw.Withdrawal{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	return s.getWithdrawal(ctx, id)
}

func (s *Store) UpdateProofWitnessItem(ctx context.Context, id [32]byte, witnessItem []byte) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_requests
		SET proof_witness_item = $2,
			updated_at = now()
		WHERE withdrawal_id = $1
	`, id[:], witnessItem)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: update proof witness item: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	return withdraw.ErrNotFound
}

func (s *Store) GetWithdrawalStatus(ctx context.Context, id [32]byte) (withdraw.WithdrawalStatus, error) {
	if s == nil || s.pool == nil {
		return withdraw.WithdrawalStatusUnknown, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	var status int16
	err := s.pool.QueryRow(ctx, `
		SELECT status
		FROM withdrawal_requests
		WHERE withdrawal_id = $1
	`, id[:]).Scan(&status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return withdraw.WithdrawalStatusUnknown, withdraw.ErrNotFound
		}
		return withdraw.WithdrawalStatusUnknown, fmt.Errorf("withdraw/postgres: get withdrawal status: %w", err)
	}
	return withdraw.WithdrawalStatus(status), nil
}

func (s *Store) GetBatch(ctx context.Context, batchID [32]byte) (withdraw.Batch, error) {
	if s == nil || s.pool == nil {
		return withdraw.Batch{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	var (
		idRaw           []byte
		state           int16
		leaseOwner      *string
		leaseVersion    *int64
		txPlan          []byte
		signedTx        []byte
		broadcastLocked *time.Time
		junoTxID        *string
		junoConfirmed   *time.Time
		baseTxHash      *string
		rebAttempts     int32
		nextRebroadcast *time.Time
		failureCount    int32
		lastFailure     *string
		lastErrorCode   *string
		lastErrorMsg    *string
		lastFailedAt    *time.Time
		dlqAt           *time.Time
		markPaidFails   int32
		lastMarkPaidErr *string
		createdAt       time.Time
		updatedAt       time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT batch_id, state, lease_owner, lease_version, tx_plan, signed_tx, broadcast_locked_at, juno_txid, juno_confirmed_at, base_tx_hash, rebroadcast_attempts, next_rebroadcast_at, failure_count, last_failure_stage, last_error_code, last_error_message, last_failed_at, dlq_at, mark_paid_failures, last_mark_paid_error, created_at, updated_at
		FROM withdrawal_batches
		WHERE batch_id = $1
	`, batchID[:]).Scan(&idRaw, &state, &leaseOwner, &leaseVersion, &txPlan, &signedTx, &broadcastLocked, &junoTxID, &junoConfirmed, &baseTxHash, &rebAttempts, &nextRebroadcast, &failureCount, &lastFailure, &lastErrorCode, &lastErrorMsg, &lastFailedAt, &dlqAt, &markPaidFails, &lastMarkPaidErr, &createdAt, &updatedAt)
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
	if rebAttempts < 0 {
		return withdraw.Batch{}, fmt.Errorf("withdraw/postgres: negative rebroadcast attempts in db")
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
		ID:                  id,
		WithdrawalIDs:       ids,
		State:               withdraw.BatchState(state),
		TxPlan:              append([]byte(nil), txPlan...),
		SignedTx:            append([]byte(nil), signedTx...),
		RebroadcastAttempts: uint32(rebAttempts),
		FailureCount:        int(failureCount),
		MarkPaidFailures:    int(markPaidFails),
		CreatedAt:           createdAt.UTC(),
		UpdatedAt:           updatedAt.UTC(),
	}
	if leaseOwner != nil {
		out.LeaseOwner = *leaseOwner
	}
	if leaseVersion != nil {
		out.LeaseVersion = *leaseVersion
	}
	if broadcastLocked != nil {
		out.BroadcastLockedAt = (*broadcastLocked).UTC()
	}
	if junoTxID != nil {
		out.JunoTxID = *junoTxID
	}
	if junoConfirmed != nil {
		out.JunoConfirmedAt = (*junoConfirmed).UTC()
	}
	if baseTxHash != nil {
		out.BaseTxHash = *baseTxHash
	}
	if nextRebroadcast != nil {
		out.NextRebroadcastAt = (*nextRebroadcast).UTC()
	}
	if lastFailure != nil {
		out.LastFailureStage = *lastFailure
	}
	if lastErrorCode != nil {
		out.LastErrorCode = *lastErrorCode
	}
	if lastErrorMsg != nil {
		out.LastErrorMessage = *lastErrorMsg
	}
	if lastFailedAt != nil {
		out.LastFailedAt = (*lastFailedAt).UTC()
	}
	if dlqAt != nil {
		out.DLQAt = (*dlqAt).UTC()
	}
	if lastMarkPaidErr != nil {
		out.LastMarkPaidError = *lastMarkPaidErr
	}
	return out, nil
}

func (s *Store) ListBatchesByState(ctx context.Context, state withdraw.BatchState) ([]withdraw.Batch, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	rows, err := s.pool.Query(ctx, `SELECT batch_id FROM withdrawal_batches WHERE state = $1 AND dlq_at IS NULL ORDER BY batch_id ASC`, int16(state))
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

func (s *Store) ListBatchesByStatesOlderThan(ctx context.Context, states []withdraw.BatchState, olderThan time.Time, max int) ([]withdraw.Batch, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if olderThan.IsZero() || max <= 0 || len(states) == 0 {
		return nil, withdraw.ErrInvalidConfig
	}

	stateIDs := make([]int16, 0, len(states))
	seen := make(map[withdraw.BatchState]struct{}, len(states))
	for _, state := range states {
		if state == withdraw.BatchStateUnknown {
			continue
		}
		if _, ok := seen[state]; ok {
			continue
		}
		seen[state] = struct{}{}
		stateIDs = append(stateIDs, int16(state))
	}
	if len(stateIDs) == 0 {
		return nil, withdraw.ErrInvalidConfig
	}

	rows, err := s.pool.Query(ctx, `
		SELECT batch_id
		FROM withdrawal_batches
		WHERE dlq_at IS NULL
		  AND updated_at <= $1
		  AND state = ANY($2::smallint[])
		ORDER BY updated_at ASC, batch_id ASC
		LIMIT $3
	`, olderThan.UTC(), stateIDs, max)
	if err != nil {
		return nil, fmt.Errorf("withdraw/postgres: list batches older than: %w", err)
	}
	defer rows.Close()

	var out []withdraw.Batch
	for rows.Next() {
		var idRaw []byte
		if err := rows.Scan(&idRaw); err != nil {
			return nil, fmt.Errorf("withdraw/postgres: scan stale batch id: %w", err)
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
		return nil, fmt.Errorf("withdraw/postgres: list batches older than rows: %w", err)
	}
	return out, nil
}

func (s *Store) GetScanBackfillCursor(ctx context.Context, walletID string) (int64, time.Time, bool, error) {
	if s == nil || s.pool == nil {
		return 0, time.Time{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	walletID = strings.TrimSpace(walletID)
	if walletID == "" {
		return 0, time.Time{}, false, withdraw.ErrInvalidConfig
	}

	var height int64
	var updatedAt time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT cursor_height, updated_at
		FROM withdraw_scan_backfill_cursors
		WHERE wallet_id = $1
	`, walletID).Scan(&height, &updatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, time.Time{}, false, nil
		}
		return 0, time.Time{}, false, fmt.Errorf("withdraw/postgres: get scan backfill cursor: %w", err)
	}
	return height, updatedAt.UTC(), true, nil
}

func (s *Store) SetScanBackfillCursor(ctx context.Context, walletID string, height int64) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	walletID = strings.TrimSpace(walletID)
	if walletID == "" || height < 0 {
		return withdraw.ErrInvalidConfig
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO withdraw_scan_backfill_cursors (wallet_id, cursor_height, created_at, updated_at)
		VALUES ($1, $2, now(), now())
		ON CONFLICT (wallet_id) DO UPDATE
		SET cursor_height = EXCLUDED.cursor_height,
			updated_at = now()
	`, walletID, height)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: set scan backfill cursor: %w", err)
	}
	return nil
}

func (s *Store) CountDLQBatches(ctx context.Context) (int, error) {
	if s == nil || s.pool == nil {
		return 0, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	var count int
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM withdrawal_batches WHERE dlq_at IS NOT NULL`).Scan(&count); err != nil {
		return 0, fmt.Errorf("withdraw/postgres: count dlq batches: %w", err)
	}
	return count, nil
}

func (s *Store) AdoptBatch(ctx context.Context, batchID [32]byte, fence withdraw.Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET lease_owner = $2,
			lease_version = $3,
			updated_at = now()
		WHERE batch_id = $1
		  AND dlq_at IS NULL
		  AND (
			lease_version IS NULL
			OR lease_version < $3
			OR (lease_version = $3 AND (lease_owner IS NULL OR lease_owner = $2))
		  )
	`, batchID[:], fence.Owner, fence.LeaseVersion)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: adopt batch: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	_, err = s.batchForMutation(ctx, batchID, fence)
	return err
}

func (s *Store) MarkBatchSigning(ctx context.Context, batchID [32]byte, fence withdraw.Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = CASE WHEN state = $4 THEN $5 ELSE state END,
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND dlq_at IS NULL
		  AND state IN ($4, $5, $6, $7, $8, $9, $10, $11)
	`, batchID[:], fence.Owner, fence.LeaseVersion,
		int16(withdraw.BatchStatePlanned),
		int16(withdraw.BatchStateSigning),
		int16(withdraw.BatchStateSigned),
		int16(withdraw.BatchStateBroadcasted),
		int16(withdraw.BatchStateJunoConfirmed),
		int16(withdraw.BatchStateConfirmed),
		int16(withdraw.BatchStateFinalizing),
		int16(withdraw.BatchStateFinalized),
	)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: mark signing: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State > withdraw.BatchStateSigning {
		return nil
	}
	return withdraw.ErrInvalidTransition
}

func (s *Store) ResetBatchSigning(ctx context.Context, batchID [32]byte, fence withdraw.Fence, txPlan []byte) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if len(txPlan) == 0 {
		return withdraw.ErrInvalidConfig
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $4,
			tx_plan = $5,
			signed_tx = NULL,
			broadcast_locked_at = NULL,
			juno_txid = NULL,
			juno_confirmed_at = NULL,
			base_tx_hash = NULL,
			rebroadcast_attempts = 0,
			next_rebroadcast_at = NULL,
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND state = $6
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion, int16(withdraw.BatchStatePlanned), txPlan, int16(withdraw.BatchStateSigning))
	if err != nil {
		return fmt.Errorf("withdraw/postgres: reset signing: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State != withdraw.BatchStateSigning {
		return withdraw.ErrInvalidTransition
	}
	return withdraw.ErrInvalidTransition
}

func (s *Store) SetBatchSigned(ctx context.Context, batchID [32]byte, fence withdraw.Fence, signedTx []byte) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if len(signedTx) == 0 {
		return withdraw.ErrInvalidConfig
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $4,
			signed_tx = $5,
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND state = $6
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion, int16(withdraw.BatchStateSigned), signedTx, int16(withdraw.BatchStateSigning))
	if err != nil {
		return fmt.Errorf("withdraw/postgres: set signed: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State < withdraw.BatchStateSigning {
		return withdraw.ErrInvalidTransition
	}
	if b.State >= withdraw.BatchStateSigned {
		if !bytes.Equal(b.SignedTx, signedTx) {
			return withdraw.ErrBatchMismatch
		}
		return nil
	}
	return withdraw.ErrInvalidTransition
}

func (s *Store) MarkBatchBroadcastLocked(ctx context.Context, batchID [32]byte, fence withdraw.Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET broadcast_locked_at = COALESCE(broadcast_locked_at, now()),
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND state IN ($4, $5, $6, $7, $8, $9)
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion,
		int16(withdraw.BatchStateSigned),
		int16(withdraw.BatchStateBroadcasted),
		int16(withdraw.BatchStateJunoConfirmed),
		int16(withdraw.BatchStateConfirmed),
		int16(withdraw.BatchStateFinalizing),
		int16(withdraw.BatchStateFinalized),
	)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: mark broadcast locked: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State < withdraw.BatchStateSigned {
		return withdraw.ErrInvalidTransition
	}
	return nil
}

func (s *Store) SetBatchBroadcasted(ctx context.Context, batchID [32]byte, fence withdraw.Fence, txid string) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if txid == "" {
		return withdraw.ErrInvalidConfig
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = CASE WHEN state = $5 THEN $6 ELSE state END,
			juno_txid = COALESCE(juno_txid, $4),
			next_rebroadcast_at = NULL,
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND broadcast_locked_at IS NOT NULL
		  AND state IN ($5, $6, $7, $8, $9, $10)
		  AND (juno_txid IS NULL OR juno_txid = $4)
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion, txid,
		int16(withdraw.BatchStateSigned),
		int16(withdraw.BatchStateBroadcasted),
		int16(withdraw.BatchStateJunoConfirmed),
		int16(withdraw.BatchStateConfirmed),
		int16(withdraw.BatchStateFinalizing),
		int16(withdraw.BatchStateFinalized),
	)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: set broadcasted: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State < withdraw.BatchStateSigned || b.BroadcastLockedAt.IsZero() {
		return withdraw.ErrInvalidTransition
	}
	if b.State >= withdraw.BatchStateBroadcasted {
		if b.JunoTxID != txid {
			return withdraw.ErrBatchMismatch
		}
		return nil
	}
	return withdraw.ErrInvalidTransition
}

func (s *Store) ResetBatchPlanned(ctx context.Context, batchID [32]byte, fence withdraw.Fence, txPlan []byte) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if len(txPlan) == 0 {
		return withdraw.ErrInvalidConfig
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $4,
			tx_plan = $5,
			signed_tx = NULL,
			broadcast_locked_at = NULL,
			juno_txid = NULL,
			juno_confirmed_at = NULL,
			base_tx_hash = NULL,
			rebroadcast_attempts = 0,
			next_rebroadcast_at = NULL,
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND state IN ($6, $7)
		  AND broadcast_locked_at IS NULL
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion, int16(withdraw.BatchStatePlanned), txPlan,
		int16(withdraw.BatchStateSigned), int16(withdraw.BatchStateBroadcasted))
	if err != nil {
		return fmt.Errorf("withdraw/postgres: reset planned: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State != withdraw.BatchStateSigned && b.State != withdraw.BatchStateBroadcasted {
		return withdraw.ErrInvalidTransition
	}
	if !b.BroadcastLockedAt.IsZero() {
		return withdraw.ErrInvalidTransition
	}
	return withdraw.ErrInvalidTransition
}

func (s *Store) SetBatchRebroadcastBackoff(ctx context.Context, batchID [32]byte, fence withdraw.Fence, attempts uint32, next time.Time) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if next.IsZero() || attempts > math.MaxInt32 {
		return withdraw.ErrInvalidConfig
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET rebroadcast_attempts = $4,
			next_rebroadcast_at = $5,
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND state = $6
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion, int32(attempts), next.UTC(), int16(withdraw.BatchStateBroadcasted))
	if err != nil {
		return fmt.Errorf("withdraw/postgres: set rebroadcast backoff: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State != withdraw.BatchStateBroadcasted {
		return withdraw.ErrInvalidTransition
	}
	return withdraw.ErrInvalidTransition
}

func (s *Store) MarkBatchJunoConfirmed(ctx context.Context, batchID [32]byte, fence withdraw.Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $4,
			juno_confirmed_at = COALESCE(juno_confirmed_at, now()),
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND state IN ($5, $4)
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion,
		int16(withdraw.BatchStateJunoConfirmed),
		int16(withdraw.BatchStateBroadcasted))
	if err != nil {
		return fmt.Errorf("withdraw/postgres: mark juno confirmed: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State != withdraw.BatchStateBroadcasted && b.State != withdraw.BatchStateJunoConfirmed {
		return withdraw.ErrInvalidTransition
	}
	if !b.JunoConfirmedAt.IsZero() {
		return nil
	}
	return withdraw.ErrInvalidTransition
}

func (s *Store) RecordBatchFailure(ctx context.Context, batchID [32]byte, fence withdraw.Fence, stage string, errorCode string, errorMessage string) (withdraw.Batch, error) {
	if err := fence.Validate(); err != nil {
		return withdraw.Batch{}, err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET failure_count = failure_count + 1,
			last_failure_stage = $4,
			last_error_code = $5,
			last_error_message = $6,
			last_failed_at = now(),
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion, stage, errorCode, errorMessage)
	if err != nil {
		return withdraw.Batch{}, fmt.Errorf("withdraw/postgres: record batch failure: %w", err)
	}
	if tag.RowsAffected() != 1 {
		if _, ferr := s.batchForMutation(ctx, batchID, fence); ferr != nil {
			return withdraw.Batch{}, ferr
		}
		return withdraw.Batch{}, withdraw.ErrInvalidTransition
	}
	return s.GetBatch(ctx, batchID)
}

func (s *Store) RecordBatchMarkPaidFailure(ctx context.Context, batchID [32]byte, fence withdraw.Fence, errorMessage string, nextAttempt time.Time) (withdraw.Batch, error) {
	if err := fence.Validate(); err != nil {
		return withdraw.Batch{}, err
	}
	if nextAttempt.IsZero() {
		return withdraw.Batch{}, withdraw.ErrInvalidConfig
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $4,
			juno_confirmed_at = COALESCE(juno_confirmed_at, now()),
			mark_paid_failures = mark_paid_failures + 1,
			last_mark_paid_error = $5,
			next_rebroadcast_at = $6,
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND state IN ($7, $4)
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion,
		int16(withdraw.BatchStateJunoConfirmed),
		errorMessage,
		nextAttempt.UTC(),
		int16(withdraw.BatchStateBroadcasted))
	if err != nil {
		return withdraw.Batch{}, fmt.Errorf("withdraw/postgres: record mark-paid failure: %w", err)
	}
	if tag.RowsAffected() != 1 {
		if _, ferr := s.batchForMutation(ctx, batchID, fence); ferr != nil {
			return withdraw.Batch{}, ferr
		}
		return withdraw.Batch{}, withdraw.ErrInvalidTransition
	}
	return s.GetBatch(ctx, batchID)
}

func (s *Store) ResetBatchMarkPaidFailures(ctx context.Context, batchID [32]byte, fence withdraw.Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET mark_paid_failures = 0,
			last_mark_paid_error = '',
			next_rebroadcast_at = NULL,
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: reset mark-paid failures: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	_, ferr := s.batchForMutation(ctx, batchID, fence)
	return ferr
}

func (s *Store) MarkBatchDLQ(ctx context.Context, batchID [32]byte, fence withdraw.Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET dlq_at = COALESCE(dlq_at, now()),
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
	`, batchID[:], fence.Owner, fence.LeaseVersion)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: mark batch dlq: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	_, ferr := s.batchForMutation(ctx, batchID, fence)
	return ferr
}

func (s *Store) SetBatchConfirmed(ctx context.Context, batchID [32]byte, fence withdraw.Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("withdraw/postgres: begin confirm tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = CASE WHEN state IN ($4, $5) THEN $6 ELSE state END,
			next_rebroadcast_at = NULL,
			mark_paid_failures = 0,
			last_mark_paid_error = '',
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND juno_confirmed_at IS NOT NULL
		  AND state IN ($4, $5, $6, $7, $8)
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion,
		int16(withdraw.BatchStateBroadcasted),
		int16(withdraw.BatchStateJunoConfirmed),
		int16(withdraw.BatchStateConfirmed),
		int16(withdraw.BatchStateFinalizing),
		int16(withdraw.BatchStateFinalized),
	)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: set confirmed: %w", err)
	}
	if tag.RowsAffected() != 1 {
		if _, ferr := s.batchForMutation(ctx, batchID, fence); ferr != nil {
			return ferr
		}
		b, berr := s.GetBatch(ctx, batchID)
		if berr != nil {
			return berr
		}
		if b.State < withdraw.BatchStateBroadcasted || b.JunoConfirmedAt.IsZero() {
			return withdraw.ErrInvalidTransition
		}
		if b.State >= withdraw.BatchStateConfirmed {
			return nil
		}
		return withdraw.ErrInvalidTransition
	}

	if _, err := tx.Exec(ctx, `
		UPDATE withdrawal_requests wr
		SET status = $2, updated_at = now()
		FROM withdrawal_batch_items wbi
		WHERE wbi.batch_id = $1
		  AND wr.withdrawal_id = wbi.withdrawal_id
		  AND wr.status < $2
	`, batchID[:], int16(withdraw.WithdrawalStatusPaid)); err != nil {
		return fmt.Errorf("withdraw/postgres: set withdrawal paid status: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("withdraw/postgres: commit confirm tx: %w", err)
	}
	return nil
}

func (s *Store) MarkBatchFinalizing(ctx context.Context, batchID [32]byte, fence withdraw.Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = CASE WHEN state = $4 THEN $5 ELSE state END,
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND state IN ($4, $5, $6)
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion,
		int16(withdraw.BatchStateConfirmed),
		int16(withdraw.BatchStateFinalizing),
		int16(withdraw.BatchStateFinalized),
	)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: mark finalizing: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State < withdraw.BatchStateConfirmed {
		return withdraw.ErrInvalidTransition
	}
	return nil
}

func (s *Store) SetBatchFinalized(ctx context.Context, batchID [32]byte, fence withdraw.Fence, baseTxHash string) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	var baseTxHashValue any
	if baseTxHash != "" {
		baseTxHashValue = baseTxHash
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE withdrawal_batches
		SET state = $5,
			base_tx_hash = COALESCE(base_tx_hash, $4::text),
			updated_at = now()
		WHERE batch_id = $1
		  AND lease_owner = $2
		  AND lease_version = $3
		  AND state IN ($6, $7, $5)
		  AND ($4::text IS NULL OR base_tx_hash IS NULL OR base_tx_hash = $4::text)
		  AND dlq_at IS NULL
	`, batchID[:], fence.Owner, fence.LeaseVersion, baseTxHashValue,
		int16(withdraw.BatchStateFinalized),
		int16(withdraw.BatchStateConfirmed),
		int16(withdraw.BatchStateFinalizing),
	)
	if err != nil {
		return fmt.Errorf("withdraw/postgres: set finalized: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	b, ferr := s.batchForMutation(ctx, batchID, fence)
	if ferr != nil {
		return ferr
	}
	if b.State < withdraw.BatchStateConfirmed {
		return withdraw.ErrInvalidTransition
	}
	if b.BaseTxHash != "" && baseTxHash != "" && b.BaseTxHash != baseTxHash {
		return withdraw.ErrBatchMismatch
	}
	if b.State >= withdraw.BatchStateFinalized {
		return nil
	}
	return withdraw.ErrInvalidTransition
}

func (s *Store) batchForMutation(ctx context.Context, batchID [32]byte, fence withdraw.Fence) (withdraw.Batch, error) {
	b, err := s.GetBatch(ctx, batchID)
	if err != nil {
		return withdraw.Batch{}, err
	}
	if b.LeaseOwner != fence.Owner || b.LeaseVersion != fence.LeaseVersion {
		return withdraw.Batch{}, withdraw.ErrInvalidTransition
	}
	return b, nil
}

func (s *Store) getWithdrawal(ctx context.Context, id [32]byte) (withdraw.Withdrawal, error) {
	var (
		idRaw           []byte
		reqRaw          []byte
		amount          int64
		feeBps          int32
		ua              []byte
		witness         []byte
		expiry          time.Time
		baseBlockNumber *int64
		baseBlockHash   []byte
		baseTxHash      []byte
		baseLogIndex    *int64
		baseFinality    *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT withdrawal_id, requester, amount, fee_bps, recipient_ua, proof_witness_item, expiry, base_block_number, base_block_hash, base_tx_hash, base_log_index, base_finality_source
		FROM withdrawal_requests
		WHERE withdrawal_id = $1
	`, id[:]).Scan(&idRaw, &reqRaw, &amount, &feeBps, &ua, &witness, &expiry, &baseBlockNumber, &baseBlockHash, &baseTxHash, &baseLogIndex, &baseFinality)
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
	var bn int64
	if baseBlockNumber != nil {
		bn = *baseBlockNumber
	}
	bh, err := toOptional32(baseBlockHash)
	if err != nil {
		return withdraw.Withdrawal{}, err
	}
	txh, err := toOptional32(baseTxHash)
	if err != nil {
		return withdraw.Withdrawal{}, err
	}
	var li uint64
	if baseLogIndex != nil {
		if *baseLogIndex < 0 {
			return withdraw.Withdrawal{}, fmt.Errorf("withdraw/postgres: negative base log index in db")
		}
		li = uint64(*baseLogIndex)
	}
	var finality string
	if baseFinality != nil {
		finality = *baseFinality
	}
	return withdraw.Withdrawal{
		ID:                 gotID,
		Requester:          req,
		Amount:             uint64(amount),
		FeeBps:             uint32(feeBps),
		RecipientUA:        append([]byte(nil), ua...),
		ProofWitnessItem:   append([]byte(nil), witness...),
		Expiry:             expiry,
		BaseBlockNumber:    bn,
		BaseBlockHash:      bh,
		BaseTxHash:         txh,
		BaseLogIndex:       li,
		BaseFinalitySource: finality,
	}, nil
}

func cloneWithdrawal(w withdraw.Withdrawal) withdraw.Withdrawal {
	w.RecipientUA = append([]byte(nil), w.RecipientUA...)
	w.ProofWitnessItem = append([]byte(nil), w.ProofWitnessItem...)
	return w
}

func withdrawalEqual(a, b withdraw.Withdrawal) bool {
	if a.ID != b.ID ||
		a.Requester != b.Requester ||
		a.Amount != b.Amount ||
		a.FeeBps != b.FeeBps ||
		!a.Expiry.Equal(b.Expiry) ||
		a.BaseBlockNumber != b.BaseBlockNumber ||
		a.BaseBlockHash != b.BaseBlockHash ||
		a.BaseTxHash != b.BaseTxHash ||
		a.BaseLogIndex != b.BaseLogIndex ||
		a.BaseFinalitySource != b.BaseFinalitySource {
		return false
	}
	return bytes.Equal(a.RecipientUA, b.RecipientUA) &&
		bytes.Equal(a.ProofWitnessItem, b.ProofWitnessItem)
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

func toOptional32(b []byte) ([32]byte, error) {
	if len(b) == 0 {
		return [32]byte{}, nil
	}
	return to32(b)
}

func ttlMilliseconds(ttl time.Duration) int64 {
	ms := ttl.Milliseconds()
	if ms <= 0 {
		return 1
	}
	return ms
}

var _ withdraw.Store = (*Store)(nil)
