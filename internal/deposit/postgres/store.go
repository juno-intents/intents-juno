package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/deposit"
)

var ErrInvalidConfig = errors.New("deposit/postgres: invalid config")

type Store struct {
	pool *pgxpool.Pool
}

type execQueryer interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type batchReadQueryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
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
		return fmt.Errorf("deposit/postgres: ensure schema: %w", err)
	}
	return nil
}

func (s *Store) UpsertSeen(ctx context.Context, d deposit.Deposit) (deposit.Job, bool, error) {
	if s == nil || s.pool == nil {
		return deposit.Job{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if d.Amount == 0 {
		return deposit.Job{}, false, fmt.Errorf("%w: amount must be > 0", deposit.ErrDepositMismatch)
	}
	if d.LeafIndex > math.MaxInt64 {
		return deposit.Job{}, false, fmt.Errorf("%w: leaf index too large", deposit.ErrDepositMismatch)
	}

	if d.SourceEvent == nil {
		return s.upsertSeenWithQuerier(ctx, s.pool, d)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return deposit.Job{}, false, fmt.Errorf("deposit/postgres: begin upsert seen: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	job, created, err := s.upsertSeenWithQuerier(ctx, tx, d)
	if err != nil {
		return deposit.Job{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return deposit.Job{}, false, fmt.Errorf("deposit/postgres: commit upsert seen: %w", err)
	}
	return job, created, nil
}

func (s *Store) upsertSeenWithQuerier(ctx context.Context, q execQueryer, d deposit.Deposit) (deposit.Job, bool, error) {
	if err := recordSourceEvent(ctx, q, d); err != nil {
		return deposit.Job{}, false, err
	}

	var junoHeight *int64
	if d.JunoHeight > 0 {
		h := d.JunoHeight
		junoHeight = &h
	}

	tag, err := q.Exec(ctx, `
		INSERT INTO deposit_jobs (
			deposit_id,
			commitment,
			leaf_index,
			amount,
			base_recipient,
			proof_witness_item,
			juno_height,
			state,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now(),now())
		ON CONFLICT (deposit_id) DO NOTHING
	`, d.DepositID[:], d.Commitment[:], int64(d.LeafIndex), int64(d.Amount), d.BaseRecipient[:], d.ProofWitnessItem, junoHeight, int16(deposit.StateSeen))
	if err != nil {
		return deposit.Job{}, false, fmt.Errorf("deposit/postgres: insert seen: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return deposit.Job{Deposit: cloneDeposit(d), State: deposit.StateSeen}, true, nil
	}

	job, err := getWithQuerier(ctx, q, d.DepositID)
	if err != nil {
		return deposit.Job{}, false, err
	}
	if !depositIdentityEqual(job.Deposit, d) {
		return deposit.Job{}, false, deposit.ErrDepositMismatch
	}
	if job.State < deposit.StateProofRequested && len(d.ProofWitnessItem) > 0 && !bytes.Equal(job.Deposit.ProofWitnessItem, d.ProofWitnessItem) {
		_, err = q.Exec(ctx, `
			UPDATE deposit_jobs
			SET proof_witness_item = $2, updated_at = now()
			WHERE deposit_id = $1
		`, d.DepositID[:], d.ProofWitnessItem)
		if err != nil {
			return deposit.Job{}, false, fmt.Errorf("deposit/postgres: update seen proof witness item: %w", err)
		}
		job.Deposit.ProofWitnessItem = append([]byte(nil), d.ProofWitnessItem...)
	}
	if d.JunoHeight > 0 && job.Deposit.JunoHeight != d.JunoHeight {
		_, err = q.Exec(ctx, `
			UPDATE deposit_jobs
			SET juno_height = $2, updated_at = now()
			WHERE deposit_id = $1
		`, d.DepositID[:], d.JunoHeight)
		if err != nil {
			return deposit.Job{}, false, fmt.Errorf("deposit/postgres: update seen juno height: %w", err)
		}
		job.Deposit.JunoHeight = d.JunoHeight
	}
	return job, false, nil
}

func (s *Store) UpsertConfirmed(ctx context.Context, d deposit.Deposit) (deposit.Job, bool, error) {
	job, inserted, err := s.UpsertSeen(ctx, d)
	if err != nil {
		return deposit.Job{}, false, err
	}
	if inserted {
		job.State = deposit.StateSeen
	}
	if job.State < deposit.StateConfirmed {
		// Upgrade to confirmed.
		_, err := s.pool.Exec(ctx, `
			UPDATE deposit_jobs
			SET state = $2, rejection_reason = NULL, updated_at = now()
			WHERE deposit_id = $1 AND state < $2
		`, d.DepositID[:], int16(deposit.StateConfirmed))
		if err != nil {
			return deposit.Job{}, false, fmt.Errorf("deposit/postgres: update state: %w", err)
		}
		job.State = deposit.StateConfirmed
		job.RejectionReason = ""
	}

	return job, inserted, nil
}

func (s *Store) PromoteSeenToConfirmed(ctx context.Context, tipHeight int64, minConfirmations int64, limit int) ([]deposit.Job, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if tipHeight <= 0 || minConfirmations <= 0 || limit <= 0 {
		return nil, nil
	}

	rows, err := s.pool.Query(ctx, `
		WITH eligible AS (
			SELECT deposit_id
			FROM deposit_jobs
			WHERE
				state = $1
				AND juno_height IS NOT NULL
				AND juno_height > 0
				AND ($2 - juno_height + 1) >= $3
			ORDER BY created_at ASC, deposit_id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $4
		)
		UPDATE deposit_jobs dj
		SET state = $5, rejection_reason = NULL, updated_at = now()
		FROM eligible
		WHERE dj.deposit_id = eligible.deposit_id
		RETURNING dj.deposit_id
	`, int16(deposit.StateSeen), tipHeight, minConfirmations, limit, int16(deposit.StateConfirmed))
	if err != nil {
		return nil, fmt.Errorf("deposit/postgres: promote seen to confirmed: %w", err)
	}
	defer rows.Close()

	out := make([]deposit.Job, 0, limit)
	for rows.Next() {
		var idRaw []byte
		if err := rows.Scan(&idRaw); err != nil {
			return nil, fmt.Errorf("deposit/postgres: scan promoted row: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return nil, err
		}
		job, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("deposit/postgres: promote seen rows: %w", err)
	}
	return out, nil
}

func (s *Store) Get(ctx context.Context, depositID [32]byte) (deposit.Job, error) {
	if s == nil || s.pool == nil {
		return deposit.Job{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	return getWithQuerier(ctx, s.pool, depositID)
}

func (s *Store) ListByState(ctx context.Context, state deposit.State, limit int) ([]deposit.Job, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if limit <= 0 {
		return nil, nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT deposit_id
		FROM deposit_jobs
		WHERE state = $1
		ORDER BY created_at ASC, deposit_id ASC
		LIMIT $2
	`, int16(state), limit)
	if err != nil {
		return nil, fmt.Errorf("deposit/postgres: list by state: %w", err)
	}
	defer rows.Close()

	out := make([]deposit.Job, 0, limit)
	for rows.Next() {
		var idRaw []byte
		if err := rows.Scan(&idRaw); err != nil {
			return nil, fmt.Errorf("deposit/postgres: scan list row: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return nil, err
		}
		job, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("deposit/postgres: list by state rows: %w", err)
	}
	return out, nil
}

func (s *Store) ClaimConfirmed(ctx context.Context, owner string, ttl time.Duration, limit int) ([]deposit.Job, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" || ttl <= 0 || limit <= 0 {
		return nil, nil
	}

	expiresAt := time.Now().UTC().Add(ttl)
	rows, err := s.pool.Query(ctx, `
		WITH picked AS (
			SELECT deposit_id
			FROM deposit_jobs
			WHERE
				state IN ($1, $2)
				AND (
					claim_expires_at IS NULL
					OR claim_expires_at <= now()
					OR claimed_by = $3
				)
			ORDER BY created_at ASC, deposit_id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $4
		)
		UPDATE deposit_jobs dj
		SET claimed_by = $3, claim_expires_at = $5, updated_at = now()
		FROM picked
		WHERE dj.deposit_id = picked.deposit_id
		RETURNING dj.deposit_id
	`, int16(deposit.StateConfirmed), int16(deposit.StateProofRequested), owner, limit, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("deposit/postgres: claim confirmed: %w", err)
	}
	defer rows.Close()

	ids := make([][32]byte, 0, limit)
	for rows.Next() {
		var idRaw []byte
		if err := rows.Scan(&idRaw); err != nil {
			return nil, fmt.Errorf("deposit/postgres: scan claim row: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("deposit/postgres: claim confirmed rows: %w", err)
	}

	out := make([]deposit.Job, 0, len(ids))
	for _, id := range ids {
		job, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, nil
}

func (s *Store) ClaimSubmittedAttempts(ctx context.Context, owner string, ttl time.Duration, limit int) ([]deposit.SubmittedBatchAttempt, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" || ttl <= 0 || limit <= 0 {
		return nil, nil
	}

	expiresAt := time.Now().UTC().Add(ttl)
	rows, err := s.pool.Query(ctx, `
		WITH picked AS (
			SELECT batch_id
			FROM deposit_batch_attempts
			WHERE
				claim_expires_at IS NULL
				OR claim_expires_at <= now()
				OR claimed_by = $1
			ORDER BY created_at ASC, batch_id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		UPDATE deposit_batch_attempts dba
		SET claimed_by = $1, claim_expires_at = $3, updated_at = now()
		FROM picked
		WHERE dba.batch_id = picked.batch_id
		RETURNING
			dba.batch_id,
			dba.owner,
			dba.epoch,
			dba.deposit_ids_json,
			dba.checkpoint_height,
			dba.checkpoint_block_hash,
			dba.checkpoint_final_orchard_root,
			dba.checkpoint_base_chain_id,
			dba.checkpoint_bridge_contract,
			dba.operator_signatures_json,
			dba.proof_seal,
			dba.tx_hash
	`, owner, limit, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("deposit/postgres: claim submitted attempts: %w", err)
	}
	defer rows.Close()

	out := make([]deposit.SubmittedBatchAttempt, 0, limit)
	for rows.Next() {
		attempt, err := scanSubmittedBatchAttempt(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, attempt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("deposit/postgres: claim submitted attempts rows: %w", err)
	}
	return out, nil
}

func (s *Store) GetBatch(ctx context.Context, batchID [32]byte) (deposit.Batch, error) {
	if s == nil || s.pool == nil {
		return deposit.Batch{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	return getBatchWithQuerier(ctx, s.pool, batchID)
}

func (s *Store) PrepareNextBatch(ctx context.Context, owner string, ttl time.Duration, nextBatchID [32]byte, maxItems int, maxAge time.Duration, limit int, now time.Time) (deposit.Batch, bool, error) {
	if s == nil || s.pool == nil {
		return deposit.Batch{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" || ttl <= 0 || maxItems <= 0 || maxAge <= 0 || limit <= 0 {
		return deposit.Batch{}, false, deposit.ErrInvalidTransition
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return deposit.Batch{}, false, fmt.Errorf("deposit/postgres: begin prepare batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	leaseExpiresAt := now.Add(ttl)
	batch, found, err := loadNextReadyBatchTx(ctx, tx, owner)
	if err != nil {
		return deposit.Batch{}, false, err
	}
	if found {
		if err := updateBatchLeaseAndStateTx(ctx, tx, batch.BatchID, owner, leaseExpiresAt, batch.State, now, batch.ClosedAt); err != nil {
			return deposit.Batch{}, false, err
		}
		out, err := getBatchWithQuerier(ctx, tx, batch.BatchID)
		if err != nil {
			return deposit.Batch{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return deposit.Batch{}, false, fmt.Errorf("deposit/postgres: commit prepare ready batch tx: %w", err)
		}
		return out, true, nil
	}

	batch, found, err = loadAssemblingBatchTx(ctx, tx)
	if err != nil {
		return deposit.Batch{}, false, err
	}
	if found {
		ready := false
		if len(batch.DepositIDs) >= maxItems || now.Sub(batch.StartedAt) >= maxAge {
			if err := updateBatchLeaseAndStateTx(ctx, tx, batch.BatchID, owner, leaseExpiresAt, deposit.BatchStateClosed, now, batch.ClosedAt); err != nil {
				return deposit.Batch{}, false, err
			}
			ready = true
		} else {
			depositID, ok, err := selectNextConfirmedBatchDepositTx(ctx, tx)
			if err != nil {
				return deposit.Batch{}, false, err
			}
			if ok {
				if err := insertActiveBatchItemsTx(ctx, tx, batch.BatchID, [][32]byte{depositID}); err != nil {
					return deposit.Batch{}, false, err
				}
				batch.DepositIDs = append(batch.DepositIDs, depositID)
				nextState := deposit.BatchStateAssembling
				closedAt := batch.ClosedAt
				if len(batch.DepositIDs) >= maxItems {
					nextState = deposit.BatchStateClosed
					closedAt = now
					ready = true
				}
				if err := updateBatchLeaseAndStateTx(ctx, tx, batch.BatchID, owner, leaseExpiresAt, nextState, now, closedAt); err != nil {
					return deposit.Batch{}, false, err
				}
			} else if err := updateBatchLeaseAndStateTx(ctx, tx, batch.BatchID, owner, leaseExpiresAt, deposit.BatchStateAssembling, now, batch.ClosedAt); err != nil {
				return deposit.Batch{}, false, err
			}
		}

		out, err := getBatchWithQuerier(ctx, tx, batch.BatchID)
		if err != nil {
			return deposit.Batch{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return deposit.Batch{}, false, fmt.Errorf("deposit/postgres: commit prepare existing batch tx: %w", err)
		}
		return out, ready, nil
	}

	depositID, ok, err := selectNextConfirmedBatchDepositTx(ctx, tx)
	if err != nil {
		return deposit.Batch{}, false, err
	}
	if !ok {
		if err := tx.Commit(ctx); err != nil {
			return deposit.Batch{}, false, fmt.Errorf("deposit/postgres: commit empty prepare batch tx: %w", err)
		}
		return deposit.Batch{}, false, nil
	}
	if nextBatchID == ([32]byte{}) {
		return deposit.Batch{}, false, deposit.ErrInvalidTransition
	}
	if err := insertBatchTx(ctx, tx, deposit.Batch{
		BatchID:        nextBatchID,
		State:          deposit.BatchStateAssembling,
		Owner:          owner,
		LeaseOwner:     owner,
		StartedAt:      now,
		ClosedAt:       time.Time{},
		FailureReason:  "",
		ProofRequested: false,
	}, leaseExpiresAt); err != nil {
		return deposit.Batch{}, false, err
	}
	if err := insertActiveBatchItemsTx(ctx, tx, nextBatchID, [][32]byte{depositID}); err != nil {
		return deposit.Batch{}, false, err
	}

	ready := false
	state := deposit.BatchStateAssembling
	closedAt := time.Time{}
	if maxItems == 1 {
		state = deposit.BatchStateClosed
		closedAt = now
		ready = true
		if err := updateBatchLeaseAndStateTx(ctx, tx, nextBatchID, owner, leaseExpiresAt, state, now, closedAt); err != nil {
			return deposit.Batch{}, false, err
		}
	}

	out, err := getBatchWithQuerier(ctx, tx, nextBatchID)
	if err != nil {
		return deposit.Batch{}, false, err
	}
	out.State = state
	out.ClosedAt = closedAt
	if err := tx.Commit(ctx); err != nil {
		return deposit.Batch{}, false, fmt.Errorf("deposit/postgres: commit new prepare batch tx: %w", err)
	}
	return out, ready, nil
}

func (s *Store) SplitBatch(ctx context.Context, owner string, batchID [32]byte, nextBatchID [32]byte, movedDepositIDs [][32]byte) (deposit.Batch, deposit.Batch, error) {
	if s == nil || s.pool == nil {
		return deposit.Batch{}, deposit.Batch{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" || nextBatchID == ([32]byte{}) {
		return deposit.Batch{}, deposit.Batch{}, deposit.ErrInvalidTransition
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return deposit.Batch{}, deposit.Batch{}, fmt.Errorf("deposit/postgres: begin split batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	left, found, err := loadBatchTx(ctx, tx, batchID, true)
	if err != nil {
		return deposit.Batch{}, deposit.Batch{}, err
	}
	if !found {
		return deposit.Batch{}, deposit.Batch{}, deposit.ErrNotFound
	}
	if left.State != deposit.BatchStateClosed {
		return deposit.Batch{}, deposit.Batch{}, deposit.ErrInvalidTransition
	}

	moveSet := make(map[[32]byte]struct{}, len(movedDepositIDs))
	for _, id := range uniqueDepositIDs(movedDepositIDs) {
		moveSet[id] = struct{}{}
	}
	if len(moveSet) == 0 || len(moveSet) >= len(left.DepositIDs) {
		return deposit.Batch{}, deposit.Batch{}, deposit.ErrInvalidTransition
	}

	stay := make([][32]byte, 0, len(left.DepositIDs))
	move := make([][32]byte, 0, len(moveSet))
	for _, id := range left.DepositIDs {
		if _, ok := moveSet[id]; ok {
			move = append(move, id)
			continue
		}
		stay = append(stay, id)
	}
	if len(move) != len(moveSet) || len(stay) == 0 {
		return deposit.Batch{}, deposit.Batch{}, deposit.ErrDepositMismatch
	}

	moveRaw := make([][]byte, 0, len(move))
	for _, id := range move {
		rawID := make([]byte, 32)
		copy(rawID, id[:])
		moveRaw = append(moveRaw, rawID)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE deposit_batch_items
		SET active = FALSE, updated_at = now()
		WHERE batch_id = $1 AND active AND deposit_id = ANY($2)
	`, batchID[:], moveRaw); err != nil {
		return deposit.Batch{}, deposit.Batch{}, fmt.Errorf("deposit/postgres: deactivate split batch items: %w", err)
	}

	if err := insertBatchTx(ctx, tx, deposit.Batch{
		BatchID:            nextBatchID,
		State:              deposit.BatchStateClosed,
		Owner:              left.Owner,
		LeaseOwner:         owner,
		StartedAt:          left.StartedAt,
		ClosedAt:           left.ClosedAt,
		FailureReason:      left.FailureReason,
		Checkpoint:         left.Checkpoint,
		ProofRequested:     left.ProofRequested,
		OperatorSignatures: left.OperatorSignatures,
		ProofSeal:          left.ProofSeal,
		TxHash:             left.TxHash,
	}, time.Time{}); err != nil {
		return deposit.Batch{}, deposit.Batch{}, err
	}
	if err := insertActiveBatchItemsTx(ctx, tx, nextBatchID, move); err != nil {
		return deposit.Batch{}, deposit.Batch{}, err
	}
	if err := updateBatchLeaseAndStateTx(ctx, tx, batchID, owner, time.Time{}, deposit.BatchStateClosed, time.Now().UTC(), left.ClosedAt); err != nil {
		return deposit.Batch{}, deposit.Batch{}, err
	}

	leftOut, err := getBatchWithQuerier(ctx, tx, batchID)
	if err != nil {
		return deposit.Batch{}, deposit.Batch{}, err
	}
	rightOut, err := getBatchWithQuerier(ctx, tx, nextBatchID)
	if err != nil {
		return deposit.Batch{}, deposit.Batch{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return deposit.Batch{}, deposit.Batch{}, fmt.Errorf("deposit/postgres: commit split batch tx: %w", err)
	}
	return leftOut, rightOut, nil
}

func (s *Store) MarkProofRequested(ctx context.Context, depositID [32]byte, cp checkpoint.Checkpoint) error {
	job, err := s.Get(ctx, depositID)
	if err != nil {
		return err
	}
	if job.State == deposit.StateRejected {
		return deposit.ErrInvalidTransition
	}
	if job.State < deposit.StateConfirmed {
		return deposit.ErrInvalidTransition
	}
	if job.State >= deposit.StateProofReady {
		return nil
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE deposit_jobs
		SET
			state = $2,
			checkpoint_height = $3,
			checkpoint_block_hash = $4,
			checkpoint_final_orchard_root = $5,
			checkpoint_base_chain_id = $6,
			checkpoint_bridge_contract = $7,
			updated_at = now()
		WHERE deposit_id = $1 AND state < $8
	`, depositID[:],
		int16(deposit.StateProofRequested),
		int64(cp.Height),
		cp.BlockHash[:],
		cp.FinalOrchardRoot[:],
		int64(cp.BaseChainID),
		cp.BridgeContract[:],
		int16(deposit.StateProofReady),
	)
	if err != nil {
		return fmt.Errorf("deposit/postgres: mark proof requested: %w", err)
	}
	return nil
}

func (s *Store) MarkBatchProofRequested(ctx context.Context, owner string, batchID [32]byte, cp checkpoint.Checkpoint) (deposit.Batch, error) {
	if s == nil || s.pool == nil {
		return deposit.Batch{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" {
		return deposit.Batch{}, deposit.ErrInvalidTransition
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return deposit.Batch{}, fmt.Errorf("deposit/postgres: begin mark batch proof requested tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	batch, found, err := loadBatchTx(ctx, tx, batchID, true)
	if err != nil {
		return deposit.Batch{}, err
	}
	if !found {
		return deposit.Batch{}, deposit.ErrNotFound
	}
	if batch.State != deposit.BatchStateClosed && batch.State != deposit.BatchStateProofRequested && batch.State != deposit.BatchStateProofReady && batch.State != deposit.BatchStateSubmitted {
		return deposit.Batch{}, deposit.ErrInvalidTransition
	}

	if err := lockAndValidateBatchJobsTx(ctx, tx, batch.DepositIDs, deposit.StateConfirmed); err != nil {
		return deposit.Batch{}, err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE deposit_batches
		SET
			state = $2,
			lease_owner = $3,
			checkpoint_height = $4,
			checkpoint_block_hash = $5,
			checkpoint_final_orchard_root = $6,
			checkpoint_base_chain_id = $7,
			checkpoint_bridge_contract = $8,
			proof_requested = TRUE,
			updated_at = now()
		WHERE batch_id = $1
	`, batchID[:], int16(deposit.BatchStateProofRequested), owner, int64(cp.Height), cp.BlockHash[:], cp.FinalOrchardRoot[:], int64(cp.BaseChainID), cp.BridgeContract[:]); err != nil {
		return deposit.Batch{}, fmt.Errorf("deposit/postgres: update batch proof requested: %w", err)
	}

	rawIDs := rawIDs(batch.DepositIDs)
	if len(rawIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET
				state = CASE WHEN state < $2 THEN $2 ELSE state END,
				checkpoint_height = $3,
				checkpoint_block_hash = $4,
				checkpoint_final_orchard_root = $5,
				checkpoint_base_chain_id = $6,
				checkpoint_bridge_contract = $7,
				updated_at = now()
			WHERE deposit_id = ANY($1)
		`, rawIDs, int16(deposit.StateProofRequested), int64(cp.Height), cp.BlockHash[:], cp.FinalOrchardRoot[:], int64(cp.BaseChainID), cp.BridgeContract[:]); err != nil {
			return deposit.Batch{}, fmt.Errorf("deposit/postgres: update batch proof requested jobs: %w", err)
		}
	}

	out, err := getBatchWithQuerier(ctx, tx, batchID)
	if err != nil {
		return deposit.Batch{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return deposit.Batch{}, fmt.Errorf("deposit/postgres: commit mark batch proof requested tx: %w", err)
	}
	return out, nil
}

func (s *Store) SetProofReady(ctx context.Context, depositID [32]byte, seal []byte) error {
	job, err := s.Get(ctx, depositID)
	if err != nil {
		return err
	}
	if job.State == deposit.StateRejected {
		return deposit.ErrInvalidTransition
	}
	if job.State < deposit.StateProofRequested {
		return deposit.ErrInvalidTransition
	}
	if job.State >= deposit.StateSubmitted {
		return nil
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE deposit_jobs
		SET
			state = $2,
			proof_seal = $3,
			claimed_by = NULL,
			claim_expires_at = NULL,
			updated_at = now()
		WHERE deposit_id = $1 AND state < $4
	`, depositID[:], int16(deposit.StateProofReady), seal, int16(deposit.StateSubmitted))
	if err != nil {
		return fmt.Errorf("deposit/postgres: set proof ready: %w", err)
	}
	return nil
}

func (s *Store) MarkBatchProofReady(ctx context.Context, owner string, batchID [32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) (deposit.Batch, error) {
	if s == nil || s.pool == nil {
		return deposit.Batch{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" {
		return deposit.Batch{}, deposit.ErrInvalidTransition
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return deposit.Batch{}, fmt.Errorf("deposit/postgres: begin mark batch proof ready tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	batch, found, err := loadBatchTx(ctx, tx, batchID, true)
	if err != nil {
		return deposit.Batch{}, err
	}
	if !found {
		return deposit.Batch{}, deposit.ErrNotFound
	}
	if batch.State != deposit.BatchStateProofRequested && batch.State != deposit.BatchStateProofReady && batch.State != deposit.BatchStateSubmitted {
		return deposit.Batch{}, deposit.ErrInvalidTransition
	}

	if err := lockAndValidateBatchJobsTx(ctx, tx, batch.DepositIDs, deposit.StateProofRequested); err != nil {
		return deposit.Batch{}, err
	}

	operatorSignaturesJSON, err := marshalOperatorSignatures(operatorSignatures)
	if err != nil {
		return deposit.Batch{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE deposit_batches
		SET
			state = $2,
			lease_owner = $3,
			checkpoint_height = $4,
			checkpoint_block_hash = $5,
			checkpoint_final_orchard_root = $6,
			checkpoint_base_chain_id = $7,
			checkpoint_bridge_contract = $8,
			proof_requested = TRUE,
			operator_signatures_json = $9,
			proof_seal = $10,
			updated_at = now()
		WHERE batch_id = $1
	`, batchID[:], int16(deposit.BatchStateProofReady), owner, int64(cp.Height), cp.BlockHash[:], cp.FinalOrchardRoot[:], int64(cp.BaseChainID), cp.BridgeContract[:], operatorSignaturesJSON, seal); err != nil {
		return deposit.Batch{}, fmt.Errorf("deposit/postgres: update batch proof ready: %w", err)
	}

	rawIDs := rawIDs(batch.DepositIDs)
	if len(rawIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET
				state = CASE WHEN state < $2 THEN $2 ELSE state END,
				checkpoint_height = $3,
				checkpoint_block_hash = $4,
				checkpoint_final_orchard_root = $5,
				checkpoint_base_chain_id = $6,
				checkpoint_bridge_contract = $7,
				proof_seal = $8,
				claimed_by = NULL,
				claim_expires_at = NULL,
				updated_at = now()
			WHERE deposit_id = ANY($1)
		`, rawIDs, int16(deposit.StateProofReady), int64(cp.Height), cp.BlockHash[:], cp.FinalOrchardRoot[:], int64(cp.BaseChainID), cp.BridgeContract[:], seal); err != nil {
			return deposit.Batch{}, fmt.Errorf("deposit/postgres: update batch proof ready jobs: %w", err)
		}
	}

	out, err := getBatchWithQuerier(ctx, tx, batchID)
	if err != nil {
		return deposit.Batch{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return deposit.Batch{}, fmt.Errorf("deposit/postgres: commit mark batch proof ready tx: %w", err)
	}
	return out, nil
}

func (s *Store) MarkFinalized(ctx context.Context, depositID [32]byte, txHash [32]byte) error {
	job, err := s.Get(ctx, depositID)
	if err != nil {
		return err
	}
	if job.State == deposit.StateRejected {
		return deposit.ErrInvalidTransition
	}
	if job.State < deposit.StateProofReady {
		return deposit.ErrInvalidTransition
	}
	if job.State == deposit.StateFinalized {
		if job.TxHash != txHash {
			return deposit.ErrDepositMismatch
		}
		return nil
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE deposit_jobs
		SET
			state = $2,
			tx_hash = $3,
			rejection_reason = NULL,
			claimed_by = NULL,
			claim_expires_at = NULL,
			updated_at = now()
		WHERE deposit_id = $1
		  AND state >= $4
		  AND state NOT IN ($2, $5)
	`, depositID[:], int16(deposit.StateFinalized), txHash[:], int16(deposit.StateProofReady), int16(deposit.StateRejected))
	if err != nil {
		return fmt.Errorf("deposit/postgres: mark finalized: %w", err)
	}
	if err := s.ensureTerminalState(ctx, depositID, deposit.StateFinalized, txHash, ""); err != nil {
		return err
	}
	return nil
}

func (s *Store) RepairFinalized(ctx context.Context, depositID [32]byte, txHash [32]byte) error {
	job, err := s.Get(ctx, depositID)
	if err != nil {
		return err
	}
	if job.State < deposit.StateConfirmed {
		return deposit.ErrInvalidTransition
	}
	if job.State == deposit.StateFinalized {
		if job.TxHash != txHash {
			return deposit.ErrDepositMismatch
		}
		return nil
	}

	_, err = s.pool.Exec(ctx, `
		UPDATE deposit_jobs
		SET
			state = $2,
			tx_hash = $3,
			rejection_reason = NULL,
			submit_batch_id = NULL,
			claimed_by = NULL,
			claim_expires_at = NULL,
			updated_at = now()
		WHERE deposit_id = $1
		  AND state <> $2
	`, depositID[:], int16(deposit.StateFinalized), txHash[:])
	if err != nil {
		return fmt.Errorf("deposit/postgres: repair finalized: %w", err)
	}
	if err := s.ensureTerminalState(ctx, depositID, deposit.StateFinalized, txHash, ""); err != nil {
		return err
	}
	return nil
}

func (s *Store) MarkRejected(ctx context.Context, depositID [32]byte, reason string, txHash [32]byte) error {
	job, err := s.Get(ctx, depositID)
	if err != nil {
		return err
	}
	if reason == "" {
		return deposit.ErrInvalidTransition
	}
	if job.State == deposit.StateFinalized {
		return deposit.ErrInvalidTransition
	}
	if job.State == deposit.StateRejected {
		if job.RejectionReason != reason {
			return deposit.ErrDepositMismatch
		}
		if txHash != ([32]byte{}) && job.TxHash != ([32]byte{}) && job.TxHash != txHash {
			return deposit.ErrDepositMismatch
		}
		return nil
	}

	var rawTxHash []byte
	if txHash != ([32]byte{}) {
		rawTxHash = txHash[:]
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE deposit_jobs
		SET
			state = $2,
			tx_hash = $3,
			rejection_reason = $4,
			submit_batch_id = NULL,
			claimed_by = NULL,
			claim_expires_at = NULL,
			updated_at = now()
		WHERE deposit_id = $1
		  AND state NOT IN ($2, $5)
	`, depositID[:], int16(deposit.StateRejected), rawTxHash, reason, int16(deposit.StateFinalized))
	if err != nil {
		return fmt.Errorf("deposit/postgres: mark rejected: %w", err)
	}
	if err := s.ensureTerminalState(ctx, depositID, deposit.StateRejected, txHash, reason); err != nil {
		return err
	}
	return nil
}

func (s *Store) FailBatch(ctx context.Context, owner string, batchID [32]byte, reason string, rejectedIDs [][32]byte) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if owner == "" || reason == "" {
		return deposit.ErrInvalidTransition
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("deposit/postgres: begin fail batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	batch, found, err := loadBatchTx(ctx, tx, batchID, true)
	if err != nil {
		return err
	}
	if !found {
		return deposit.ErrNotFound
	}

	rejectedSet := make(map[[32]byte]struct{}, len(rejectedIDs))
	for _, id := range uniqueDepositIDs(rejectedIDs) {
		rejectedSet[id] = struct{}{}
	}
	for id := range rejectedSet {
		found := false
		for _, batchID := range batch.DepositIDs {
			if batchID == id {
				found = true
				break
			}
		}
		if !found {
			return deposit.ErrDepositMismatch
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE deposit_batches
		SET
			state = $2,
			lease_owner = $3,
			lease_expires_at = NULL,
			failure_reason = $4,
			updated_at = now()
		WHERE batch_id = $1
	`, batchID[:], int16(deposit.BatchStateFailed), owner, reason); err != nil {
		return fmt.Errorf("deposit/postgres: update failed batch: %w", err)
	}

	var requeueIDs [][32]byte
	var rejectedList [][32]byte
	for _, id := range batch.DepositIDs {
		if _, ok := rejectedSet[id]; ok {
			rejectedList = append(rejectedList, id)
			continue
		}
		requeueIDs = append(requeueIDs, id)
	}

	if len(rejectedList) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET
				state = $2,
				tx_hash = NULL,
				rejection_reason = $3,
				submit_batch_id = NULL,
				claimed_by = NULL,
				claim_expires_at = NULL,
				updated_at = now()
			WHERE deposit_id = ANY($1)
				AND state <> $4
		`, rawIDs(rejectedList), int16(deposit.StateRejected), reason, int16(deposit.StateFinalized)); err != nil {
			return fmt.Errorf("deposit/postgres: reject failed batch rows: %w", err)
		}
	}

	if len(requeueIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET
				state = CASE
					WHEN state IN ($2, $3) THEN $1
					ELSE state
				END,
				checkpoint_height = NULL,
				checkpoint_block_hash = NULL,
				checkpoint_final_orchard_root = NULL,
				checkpoint_base_chain_id = NULL,
				checkpoint_bridge_contract = NULL,
				proof_seal = NULL,
				tx_hash = NULL,
				rejection_reason = NULL,
				submit_batch_id = NULL,
				claimed_by = NULL,
				claim_expires_at = NULL,
				updated_at = now()
			WHERE deposit_id = ANY($4)
				AND state NOT IN ($5, $6)
		`, rawIDs(requeueIDs), int16(deposit.StateConfirmed), int16(deposit.StateProofRequested), int16(deposit.StateProofReady), int16(deposit.StateFinalized), int16(deposit.StateRejected)); err != nil {
			return fmt.Errorf("deposit/postgres: requeue failed batch rows: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			UPDATE deposit_batch_items
			SET active = FALSE, updated_at = now()
			WHERE batch_id = $1 AND active AND deposit_id = ANY($2)
		`, batchID[:], rawIDs(requeueIDs)); err != nil {
			return fmt.Errorf("deposit/postgres: deactivate failed batch items: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("deposit/postgres: commit fail batch tx: %w", err)
	}
	return nil
}

func (s *Store) ensureTerminalState(ctx context.Context, depositID [32]byte, wantState deposit.State, wantTxHash [32]byte, wantReason string) error {
	job, err := s.Get(ctx, depositID)
	if err != nil {
		return err
	}
	if job.State != wantState {
		return deposit.ErrInvalidTransition
	}
	if wantTxHash != ([32]byte{}) && job.TxHash != wantTxHash {
		return deposit.ErrDepositMismatch
	}
	if wantState == deposit.StateRejected && job.RejectionReason != wantReason {
		return deposit.ErrDepositMismatch
	}
	return nil
}

func (s *Store) MarkBatchSubmitted(ctx context.Context, owner string, batchID [32]byte, depositIDs [][32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) (deposit.SubmittedBatchAttempt, error) {
	if s == nil || s.pool == nil {
		return deposit.SubmittedBatchAttempt{}, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	ids := uniqueDepositIDs(depositIDs)
	if len(ids) == 0 {
		return deposit.SubmittedBatchAttempt{}, nil
	}
	if owner == "" {
		return deposit.SubmittedBatchAttempt{}, deposit.ErrInvalidTransition
	}

	rawIDs := make([][]byte, 0, len(ids))
	for _, id := range ids {
		rawID := make([]byte, 32)
		copy(rawID, id[:])
		rawIDs = append(rawIDs, rawID)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, fmt.Errorf("deposit/postgres: begin submit batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT deposit_id, state
		FROM deposit_jobs
		WHERE deposit_id = ANY($1)
		FOR UPDATE
	`, rawIDs)
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, fmt.Errorf("deposit/postgres: lock submit batch rows: %w", err)
	}
	defer rows.Close()

	found := make(map[[32]byte]int16, len(ids))
	for rows.Next() {
		var (
			idRaw []byte
			state int16
		)
		if err := rows.Scan(&idRaw, &state); err != nil {
			return deposit.SubmittedBatchAttempt{}, fmt.Errorf("deposit/postgres: scan submit batch row: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return deposit.SubmittedBatchAttempt{}, err
		}
		found[id] = state
	}
	if err := rows.Err(); err != nil {
		return deposit.SubmittedBatchAttempt{}, fmt.Errorf("deposit/postgres: submit batch rows: %w", err)
	}

	for _, id := range ids {
		state, ok := found[id]
		if !ok {
			return deposit.SubmittedBatchAttempt{}, deposit.ErrNotFound
		}
		if deposit.State(state) == deposit.StateRejected {
			return deposit.SubmittedBatchAttempt{}, deposit.ErrInvalidTransition
		}
		if deposit.State(state) < deposit.StateConfirmed {
			return deposit.SubmittedBatchAttempt{}, deposit.ErrInvalidTransition
		}
	}

	attempt, foundExisting, err := loadSubmittedBatchAttemptTx(ctx, tx, batchID)
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}
	if foundExisting {
		if !submittedBatchAttemptMatches(attempt, owner, ids, cp, operatorSignatures, seal) {
			return deposit.SubmittedBatchAttempt{}, deposit.ErrDepositMismatch
		}
	} else {
		attempt = deposit.SubmittedBatchAttempt{
			BatchID:            batchID,
			DepositIDs:         cloneDepositIDs(ids),
			Owner:              owner,
			Epoch:              1,
			Checkpoint:         cp,
			OperatorSignatures: clone2DBytes(operatorSignatures),
			ProofSeal:          append([]byte(nil), seal...),
		}
		if err := insertSubmittedBatchAttemptTx(ctx, tx, attempt); err != nil {
			return deposit.SubmittedBatchAttempt{}, err
		}
	}

	if err := upsertBatchMetadataTx(ctx, tx, deposit.Batch{
		BatchID:            batchID,
		State:              deposit.BatchStateSubmitted,
		Owner:              owner,
		LeaseOwner:         owner,
		StartedAt:          time.Now().UTC(),
		ClosedAt:           time.Now().UTC(),
		Checkpoint:         cp,
		ProofRequested:     true,
		OperatorSignatures: operatorSignatures,
		ProofSeal:          seal,
	}); err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}
	if err := replaceActiveBatchItemsTx(ctx, tx, batchID, ids); err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}

	_, err = tx.Exec(ctx, `
		UPDATE deposit_jobs
		SET
			state = CASE
				WHEN state = $10 THEN state
				WHEN state = $2 THEN state
				ELSE $2
			END,
			checkpoint_height = $3,
			checkpoint_block_hash = $4,
			checkpoint_final_orchard_root = $5,
			checkpoint_base_chain_id = $6,
			checkpoint_bridge_contract = $7,
			proof_seal = $8,
			rejection_reason = NULL,
			submit_batch_id = $9,
			claimed_by = NULL,
			claim_expires_at = NULL,
			updated_at = now()
		WHERE deposit_id = ANY($1)
	`,
		rawIDs,
		int16(deposit.StateSubmitted),
		int64(cp.Height),
		cp.BlockHash[:],
		cp.FinalOrchardRoot[:],
		int64(cp.BaseChainID),
		cp.BridgeContract[:],
		seal,
		batchID[:],
		int16(deposit.StateFinalized),
	)
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, fmt.Errorf("deposit/postgres: update submit batch rows: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return deposit.SubmittedBatchAttempt{}, fmt.Errorf("deposit/postgres: commit submit batch tx: %w", err)
	}
	return cloneSubmittedBatchAttempt(attempt), nil
}

func (s *Store) SetBatchSubmissionTxHash(ctx context.Context, batchID [32]byte, txHash [32]byte) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	var existing []byte
	err := s.pool.QueryRow(ctx, `
		SELECT tx_hash
		FROM deposit_batch_attempts
		WHERE batch_id = $1
	`, batchID[:]).Scan(&existing)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return deposit.ErrNotFound
		}
		return fmt.Errorf("deposit/postgres: read submitted batch tx hash: %w", err)
	}
	if len(existing) > 0 {
		if len(existing) != 32 || !bytes.Equal(existing, txHash[:]) {
			return deposit.ErrDepositMismatch
		}
		return nil
	}

	tag, err := s.pool.Exec(ctx, `
		UPDATE deposit_batch_attempts
		SET tx_hash = $2, updated_at = now()
		WHERE batch_id = $1
	`, batchID[:], txHash[:])
	if err != nil {
		return fmt.Errorf("deposit/postgres: set submitted batch tx hash: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return deposit.ErrNotFound
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE deposit_batches
		SET state = $2, tx_hash = $3, updated_at = now()
		WHERE batch_id = $1
	`, batchID[:], int16(deposit.BatchStateSubmitted), txHash[:])
	if err != nil {
		return fmt.Errorf("deposit/postgres: set batch tx hash metadata: %w", err)
	}
	return nil
}

func (s *Store) RequeueSubmittedBatch(ctx context.Context, batchID [32]byte) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("deposit/postgres: begin requeue submitted batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	attempt, found, err := loadSubmittedBatchAttemptTx(ctx, tx, batchID)
	if err != nil {
		return err
	}
	if !found {
		return deposit.ErrNotFound
	}
	if attempt.TxHash != ([32]byte{}) {
		return deposit.ErrInvalidTransition
	}

	rawIDs := make([][]byte, 0, len(attempt.DepositIDs))
	for _, id := range attempt.DepositIDs {
		rawID := make([]byte, 32)
		copy(rawID, id[:])
		rawIDs = append(rawIDs, rawID)
	}

	if len(rawIDs) > 0 {
		_, err = tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET
				state = CASE
					WHEN state = $2 THEN $1
					ELSE state
				END,
				proof_seal = CASE
					WHEN state = $2 THEN NULL
					ELSE proof_seal
				END,
				submit_batch_id = CASE
					WHEN submit_batch_id = $3 THEN NULL
					ELSE submit_batch_id
				END,
				claimed_by = NULL,
				claim_expires_at = NULL,
				rejection_reason = CASE
					WHEN state = $2 THEN NULL
					ELSE rejection_reason
				END,
				updated_at = now()
			WHERE deposit_id = ANY($4)
		`, int16(deposit.StateConfirmed), int16(deposit.StateSubmitted), batchID[:], rawIDs)
		if err != nil {
			return fmt.Errorf("deposit/postgres: requeue submitted batch rows: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `DELETE FROM deposit_batch_attempts WHERE batch_id = $1`, batchID[:]); err != nil {
		return fmt.Errorf("deposit/postgres: delete submitted batch attempt: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		UPDATE deposit_batches
		SET
			state = $2,
			lease_owner = NULL,
			lease_expires_at = NULL,
			checkpoint_height = NULL,
			checkpoint_block_hash = NULL,
			checkpoint_final_orchard_root = NULL,
			checkpoint_base_chain_id = NULL,
			checkpoint_bridge_contract = NULL,
			operator_signatures_json = '[]'::jsonb,
			proof_seal = NULL,
			tx_hash = NULL,
			updated_at = now()
		WHERE batch_id = $1
	`, batchID[:], int16(deposit.BatchStateClosed)); err != nil {
		return fmt.Errorf("deposit/postgres: requeue submitted batch metadata: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("deposit/postgres: commit requeue submitted batch tx: %w", err)
	}
	return nil
}

func (s *Store) ApplyBatchOutcome(ctx context.Context, batchID [32]byte, txHash [32]byte, finalizedIDs [][32]byte, rejectedIDs [][32]byte, rejectionReason string) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("deposit/postgres: begin apply batch outcome tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	attempt, found, err := loadSubmittedBatchAttemptTx(ctx, tx, batchID)
	if err != nil {
		return err
	}
	if !found {
		return deposit.ErrNotFound
	}
	if attempt.TxHash != ([32]byte{}) && attempt.TxHash != txHash {
		return deposit.ErrDepositMismatch
	}

	expected := make(map[[32]byte]struct{}, len(attempt.DepositIDs))
	for _, id := range attempt.DepositIDs {
		expected[id] = struct{}{}
	}

	finalizedSet := make(map[[32]byte]struct{}, len(finalizedIDs))
	for _, id := range uniqueDepositIDs(finalizedIDs) {
		if _, ok := expected[id]; !ok {
			return deposit.ErrDepositMismatch
		}
		finalizedSet[id] = struct{}{}
	}

	rejectedSet := make(map[[32]byte]struct{}, len(rejectedIDs))
	for _, id := range uniqueDepositIDs(rejectedIDs) {
		if _, ok := expected[id]; !ok {
			return deposit.ErrDepositMismatch
		}
		if _, ok := finalizedSet[id]; ok {
			return deposit.ErrDepositMismatch
		}
		rejectedSet[id] = struct{}{}
	}

	rawIDs := make([][]byte, 0, len(attempt.DepositIDs))
	for _, id := range attempt.DepositIDs {
		rawID := make([]byte, 32)
		copy(rawID, id[:])
		rawIDs = append(rawIDs, rawID)
	}

	rows, err := tx.Query(ctx, `
		SELECT deposit_id
		FROM deposit_jobs
		WHERE deposit_id = ANY($1)
		FOR UPDATE
	`, rawIDs)
	if err != nil {
		return fmt.Errorf("deposit/postgres: lock apply batch outcome rows: %w", err)
	}
	defer rows.Close()

	seen := make(map[[32]byte]struct{}, len(attempt.DepositIDs))
	for rows.Next() {
		var idRaw []byte
		if err := rows.Scan(&idRaw); err != nil {
			return fmt.Errorf("deposit/postgres: scan apply batch outcome row: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return err
		}
		seen[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("deposit/postgres: apply batch outcome rows: %w", err)
	}
	for _, id := range attempt.DepositIDs {
		if _, ok := seen[id]; !ok {
			return deposit.ErrNotFound
		}
	}

	finalizedRaw := make([][]byte, 0, len(finalizedSet))
	for id := range finalizedSet {
		rawID := make([]byte, 32)
		copy(rawID, id[:])
		finalizedRaw = append(finalizedRaw, rawID)
	}
	if len(finalizedRaw) > 0 {
		_, err = tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET
				state = $2,
				tx_hash = $3,
				rejection_reason = NULL,
				submit_batch_id = NULL,
				claimed_by = NULL,
				claim_expires_at = NULL,
				updated_at = now()
			WHERE deposit_id = ANY($1)
				AND state NOT IN ($4, $5)
		`, finalizedRaw, int16(deposit.StateFinalized), txHash[:], int16(deposit.StateFinalized), int16(deposit.StateRejected))
		if err != nil {
			return fmt.Errorf("deposit/postgres: update finalized batch outcome rows: %w", err)
		}
	}

	rejectedRaw := make([][]byte, 0, len(rejectedSet))
	for id := range rejectedSet {
		rawID := make([]byte, 32)
		copy(rawID, id[:])
		rejectedRaw = append(rejectedRaw, rawID)
	}
	if len(rejectedRaw) > 0 {
		_, err = tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET
				state = $2,
				tx_hash = $3,
				rejection_reason = $4,
				submit_batch_id = NULL,
				claimed_by = NULL,
				claim_expires_at = NULL,
				updated_at = now()
			WHERE deposit_id = ANY($1)
				AND state NOT IN ($5, $6)
		`, rejectedRaw, int16(deposit.StateRejected), txHash[:], rejectionReason, int16(deposit.StateFinalized), int16(deposit.StateRejected))
		if err != nil {
			return fmt.Errorf("deposit/postgres: update rejected batch outcome rows: %w", err)
		}
	}

	resolvedStateCount := len(finalizedSet) + len(rejectedSet)
	allResolved := resolvedStateCount == len(attempt.DepositIDs)

	_, err = tx.Exec(ctx, `
		UPDATE deposit_jobs
		SET
			tx_hash = $2,
			claimed_by = NULL,
			claim_expires_at = NULL,
			updated_at = now()
		WHERE deposit_id = ANY($1)
			AND state NOT IN ($3, $4)
	`, rawIDs, txHash[:], int16(deposit.StateFinalized), int16(deposit.StateRejected))
	if err != nil {
		return fmt.Errorf("deposit/postgres: update unresolved batch outcome rows: %w", err)
	}

	if allResolved {
		_, err = tx.Exec(ctx, `
			DELETE FROM deposit_batch_attempts
			WHERE batch_id = $1
		`, batchID[:])
		if err != nil {
			return fmt.Errorf("deposit/postgres: delete batch attempt after outcome: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		UPDATE deposit_batches
		SET
			state = $2,
			tx_hash = $3,
			failure_reason = CASE
				WHEN $4 <> '' AND $2 = $5 THEN $4
				ELSE failure_reason
			END,
			updated_at = now()
		WHERE batch_id = $1
	`, batchID[:], int16(deposit.BatchStateSubmitted), txHash[:], rejectionReason, int16(deposit.BatchStateFailed)); err != nil {
		return fmt.Errorf("deposit/postgres: update batch outcome metadata: %w", err)
	}
	if allResolved {
		if _, err := tx.Exec(ctx, `
			UPDATE deposit_batches
			SET state = $2, tx_hash = $3, updated_at = now()
			WHERE batch_id = $1
		`, batchID[:], int16(deposit.BatchStateFinalized), txHash[:]); err != nil {
			return fmt.Errorf("deposit/postgres: finalize batch metadata: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("deposit/postgres: commit apply batch outcome tx: %w", err)
	}
	return nil
}

func (s *Store) FinalizeBatch(ctx context.Context, depositIDs [][32]byte, cp checkpoint.Checkpoint, seal []byte, txHash [32]byte) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	ids := uniqueDepositIDs(depositIDs)
	if len(ids) == 0 {
		return nil
	}

	rawIDs := make([][]byte, 0, len(ids))
	for _, id := range ids {
		rawID := make([]byte, 32)
		copy(rawID, id[:])
		rawIDs = append(rawIDs, rawID)
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("deposit/postgres: begin finalize batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT deposit_id, state, tx_hash, submit_batch_id
		FROM deposit_jobs
		WHERE deposit_id = ANY($1)
		FOR UPDATE
	`, rawIDs)
	if err != nil {
		return fmt.Errorf("deposit/postgres: lock finalize batch rows: %w", err)
	}
	defer rows.Close()

	type rowState struct {
		state         int16
		txHash        []byte
		submitBatchID []byte
	}
	found := make(map[[32]byte]rowState, len(ids))
	for rows.Next() {
		var (
			idRaw            []byte
			state            int16
			txHashRaw        []byte
			submitBatchIDRaw []byte
		)
		if err := rows.Scan(&idRaw, &state, &txHashRaw, &submitBatchIDRaw); err != nil {
			return fmt.Errorf("deposit/postgres: scan finalize batch row: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return err
		}
		found[id] = rowState{
			state:         state,
			txHash:        append([]byte(nil), txHashRaw...),
			submitBatchID: append([]byte(nil), submitBatchIDRaw...),
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("deposit/postgres: finalize batch rows: %w", err)
	}

	updatable := make([][]byte, 0, len(ids))
	batchIDsToDelete := make([][]byte, 0, len(ids))
	seenBatchIDs := make(map[[32]byte]struct{}, len(ids))
	for _, id := range ids {
		st, ok := found[id]
		if !ok {
			return deposit.ErrNotFound
		}
		if deposit.State(st.state) == deposit.StateFinalized {
			if len(st.txHash) != 32 || !bytes.Equal(st.txHash, txHash[:]) {
				return deposit.ErrDepositMismatch
			}
			continue
		}
		if deposit.State(st.state) < deposit.StateConfirmed {
			return deposit.ErrInvalidTransition
		}
		if len(st.submitBatchID) > 0 {
			submitBatchID, err := to32(st.submitBatchID)
			if err != nil {
				return err
			}
			if _, ok := seenBatchIDs[submitBatchID]; !ok {
				seenBatchIDs[submitBatchID] = struct{}{}
				rawBatchID := make([]byte, 32)
				copy(rawBatchID, submitBatchID[:])
				batchIDsToDelete = append(batchIDsToDelete, rawBatchID)
			}
		}
		rawID := make([]byte, 32)
		copy(rawID, id[:])
		updatable = append(updatable, rawID)
	}

	if len(updatable) > 0 {
		_, err := tx.Exec(ctx, `
			UPDATE deposit_jobs
			SET
				state = $2,
				checkpoint_height = $3,
				checkpoint_block_hash = $4,
				checkpoint_final_orchard_root = $5,
				checkpoint_base_chain_id = $6,
				checkpoint_bridge_contract = $7,
				proof_seal = $8,
				tx_hash = $9,
				rejection_reason = NULL,
				submit_batch_id = NULL,
				claimed_by = NULL,
				claim_expires_at = NULL,
				updated_at = now()
			WHERE deposit_id = ANY($1)
		`,
			updatable,
			int16(deposit.StateFinalized),
			int64(cp.Height),
			cp.BlockHash[:],
			cp.FinalOrchardRoot[:],
			int64(cp.BaseChainID),
			cp.BridgeContract[:],
			seal,
			txHash[:],
		)
		if err != nil {
			return fmt.Errorf("deposit/postgres: update finalize batch rows: %w", err)
		}
	}

	_, err = tx.Exec(ctx, `
		UPDATE deposit_jobs
		SET submit_batch_id = NULL, updated_at = now()
		WHERE deposit_id = ANY($1)
	`, rawIDs)
	if err != nil {
		return fmt.Errorf("deposit/postgres: clear finalize batch ids: %w", err)
	}

	if len(batchIDsToDelete) > 0 {
		_, err = tx.Exec(ctx, `
			DELETE FROM deposit_batch_attempts
			WHERE batch_id = ANY($1)
		`, batchIDsToDelete)
		if err != nil {
			return fmt.Errorf("deposit/postgres: delete finalize batch attempts: %w", err)
		}
	}

	batchRows, err := tx.Query(ctx, `
		SELECT DISTINCT batch_id
		FROM deposit_batch_items
		WHERE active AND deposit_id = ANY($1)
	`, rawIDs)
	if err != nil {
		return fmt.Errorf("deposit/postgres: select finalize batch metadata ids: %w", err)
	}
	defer batchRows.Close()

	activeBatchIDs := make([][]byte, 0, len(ids))
	for batchRows.Next() {
		var rawBatchID []byte
		if err := batchRows.Scan(&rawBatchID); err != nil {
			return fmt.Errorf("deposit/postgres: scan finalize batch metadata id: %w", err)
		}
		activeBatchIDs = append(activeBatchIDs, append([]byte(nil), rawBatchID...))
	}
	if err := batchRows.Err(); err != nil {
		return fmt.Errorf("deposit/postgres: finalize batch metadata id rows: %w", err)
	}
	if len(activeBatchIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			UPDATE deposit_batches
			SET
				state = $2,
				checkpoint_height = $3,
				checkpoint_block_hash = $4,
				checkpoint_final_orchard_root = $5,
				checkpoint_base_chain_id = $6,
				checkpoint_bridge_contract = $7,
				proof_seal = $8,
				tx_hash = $9,
				updated_at = now()
			WHERE batch_id = ANY($1)
		`, activeBatchIDs, int16(deposit.BatchStateFinalized), int64(cp.Height), cp.BlockHash[:], cp.FinalOrchardRoot[:], int64(cp.BaseChainID), cp.BridgeContract[:], seal, txHash[:]); err != nil {
			return fmt.Errorf("deposit/postgres: update finalize batch metadata: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("deposit/postgres: commit finalize batch tx: %w", err)
	}
	return nil
}

func getBatchWithQuerier(ctx context.Context, q batchReadQueryer, batchID [32]byte) (deposit.Batch, error) {
	batch, found, err := loadBatchTx(ctx, q, batchID, false)
	if err != nil {
		return deposit.Batch{}, err
	}
	if !found {
		return deposit.Batch{}, deposit.ErrNotFound
	}
	return batch, nil
}

func loadAssemblingBatchTx(ctx context.Context, q batchReadQueryer) (deposit.Batch, bool, error) {
	row := q.QueryRow(ctx, `
		SELECT
			batch_id,
			state,
			owner,
			lease_owner,
			lease_expires_at,
			started_at,
			closed_at,
			failure_reason,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			proof_requested,
			operator_signatures_json,
			proof_seal,
			tx_hash
		FROM deposit_batches
		WHERE state = $1
		ORDER BY started_at ASC, batch_id ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`, int16(deposit.BatchStateAssembling))
	return scanBatchRow(ctx, q, row)
}

func loadNextReadyBatchTx(ctx context.Context, q batchReadQueryer, owner string) (deposit.Batch, bool, error) {
	row := q.QueryRow(ctx, `
		SELECT
			batch_id,
			state,
			owner,
			lease_owner,
			lease_expires_at,
			started_at,
			closed_at,
			failure_reason,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			proof_requested,
			operator_signatures_json,
			proof_seal,
			tx_hash
		FROM deposit_batches
		WHERE state IN ($1, $2, $3)
			AND (lease_expires_at IS NULL OR lease_expires_at <= now() OR lease_owner = $4)
		ORDER BY started_at ASC, batch_id ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	`, int16(deposit.BatchStateClosed), int16(deposit.BatchStateProofRequested), int16(deposit.BatchStateProofReady), owner)
	return scanBatchRow(ctx, q, row)
}

func loadBatchTx(ctx context.Context, q batchReadQueryer, batchID [32]byte, forUpdate bool) (deposit.Batch, bool, error) {
	sql := `
		SELECT
			batch_id,
			state,
			owner,
			lease_owner,
			lease_expires_at,
			started_at,
			closed_at,
			failure_reason,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			proof_requested,
			operator_signatures_json,
			proof_seal,
			tx_hash
		FROM deposit_batches
		WHERE batch_id = $1
	`
	if forUpdate {
		sql += " FOR UPDATE"
	}
	return scanBatchRow(ctx, q, q.QueryRow(ctx, sql, batchID[:]))
}

func scanBatchRow(ctx context.Context, q batchReadQueryer, row scanRow) (deposit.Batch, bool, error) {
	var (
		batchIDRaw             []byte
		state                  int16
		owner                  string
		leaseOwner             *string
		leaseExpiresAt         *time.Time
		startedAt              time.Time
		closedAt               *time.Time
		failureReason          *string
		checkpointHeight       *int64
		checkpointBlockHashRaw []byte
		checkpointRootRaw      []byte
		checkpointBaseChainID  *int64
		checkpointBridgeRaw    []byte
		proofRequested         bool
		operatorSignaturesJSON []byte
		proofSeal              []byte
		txHashRaw              []byte
	)

	if err := row.Scan(
		&batchIDRaw,
		&state,
		&owner,
		&leaseOwner,
		&leaseExpiresAt,
		&startedAt,
		&closedAt,
		&failureReason,
		&checkpointHeight,
		&checkpointBlockHashRaw,
		&checkpointRootRaw,
		&checkpointBaseChainID,
		&checkpointBridgeRaw,
		&proofRequested,
		&operatorSignaturesJSON,
		&proofSeal,
		&txHashRaw,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return deposit.Batch{}, false, nil
		}
		return deposit.Batch{}, false, fmt.Errorf("deposit/postgres: scan batch row: %w", err)
	}

	batchID, err := to32(batchIDRaw)
	if err != nil {
		return deposit.Batch{}, false, err
	}
	operatorSignatures, err := unmarshalOperatorSignatures(operatorSignaturesJSON)
	if err != nil {
		return deposit.Batch{}, false, err
	}

	batch := deposit.Batch{
		BatchID:            batchID,
		State:              deposit.BatchState(state),
		Owner:              owner,
		StartedAt:          startedAt.UTC(),
		ProofRequested:     proofRequested,
		OperatorSignatures: operatorSignatures,
		ProofSeal:          append([]byte(nil), proofSeal...),
	}
	if leaseOwner != nil {
		batch.LeaseOwner = *leaseOwner
	}
	if leaseExpiresAt != nil {
		batch.LeaseExpiresAt = leaseExpiresAt.UTC()
	}
	if closedAt != nil {
		batch.ClosedAt = closedAt.UTC()
	}
	if failureReason != nil {
		batch.FailureReason = *failureReason
	}
	if checkpointHeight != nil {
		var cp checkpoint.Checkpoint
		cp.Height = uint64(*checkpointHeight)
		if len(checkpointBlockHashRaw) > 0 {
			cp.BlockHash, err = to32(checkpointBlockHashRaw)
			if err != nil {
				return deposit.Batch{}, false, err
			}
		}
		if len(checkpointRootRaw) > 0 {
			cp.FinalOrchardRoot, err = to32(checkpointRootRaw)
			if err != nil {
				return deposit.Batch{}, false, err
			}
		}
		if checkpointBaseChainID != nil && *checkpointBaseChainID >= 0 {
			cp.BaseChainID = uint64(*checkpointBaseChainID)
		}
		if len(checkpointBridgeRaw) > 0 {
			cp.BridgeContract, err = to20(checkpointBridgeRaw)
			if err != nil {
				return deposit.Batch{}, false, err
			}
		}
		batch.Checkpoint = cp
	}
	if len(txHashRaw) > 0 {
		batch.TxHash, err = to32(txHashRaw)
		if err != nil {
			return deposit.Batch{}, false, err
		}
	}

	depositIDs, err := listActiveBatchDepositIDsTx(ctx, q, batch.BatchID)
	if err != nil {
		return deposit.Batch{}, false, err
	}
	batch.DepositIDs = depositIDs
	return batch, true, nil
}

func listActiveBatchDepositIDsTx(ctx context.Context, q batchReadQueryer, batchID [32]byte) ([][32]byte, error) {
	rows, err := q.Query(ctx, `
		SELECT deposit_id
		FROM deposit_batch_items
		WHERE batch_id = $1 AND active
		ORDER BY created_at ASC, deposit_id ASC
	`, batchID[:])
	if err != nil {
		return nil, fmt.Errorf("deposit/postgres: list batch items: %w", err)
	}
	defer rows.Close()

	out := make([][32]byte, 0)
	for rows.Next() {
		var rawID []byte
		if err := rows.Scan(&rawID); err != nil {
			return nil, fmt.Errorf("deposit/postgres: scan batch item: %w", err)
		}
		id, err := to32(rawID)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("deposit/postgres: batch item rows: %w", err)
	}
	return out, nil
}

func selectNextConfirmedBatchDepositTx(ctx context.Context, tx pgx.Tx) ([32]byte, bool, error) {
	var rawID []byte
	err := tx.QueryRow(ctx, `
		SELECT dj.deposit_id
		FROM deposit_jobs dj
		WHERE
			dj.state = $1
			AND dj.submit_batch_id IS NULL
			AND NOT EXISTS (
				SELECT 1
				FROM deposit_batch_items dbi
				WHERE dbi.deposit_id = dj.deposit_id
					AND dbi.active
			)
		ORDER BY dj.created_at ASC, dj.deposit_id ASC
		FOR UPDATE OF dj SKIP LOCKED
		LIMIT 1
	`, int16(deposit.StateConfirmed)).Scan(&rawID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return [32]byte{}, false, nil
		}
		return [32]byte{}, false, fmt.Errorf("deposit/postgres: select next confirmed batch deposit: %w", err)
	}
	id, err := to32(rawID)
	if err != nil {
		return [32]byte{}, false, err
	}
	return id, true, nil
}

func insertBatchTx(ctx context.Context, tx pgx.Tx, batch deposit.Batch, leaseExpiresAt time.Time) error {
	operatorSignaturesJSON, err := marshalOperatorSignatures(batch.OperatorSignatures)
	if err != nil {
		return err
	}

	var (
		leaseOwner      any
		leaseExpiresAny any
		closedAtAny     any
		failureReason   any
		cpHeight        any
		cpBlockHash     any
		cpRoot          any
		cpBaseChainID   any
		cpBridge        any
		txHash          any
	)
	if batch.LeaseOwner != "" {
		leaseOwner = batch.LeaseOwner
	}
	if !leaseExpiresAt.IsZero() {
		leaseExpiresAny = leaseExpiresAt
	}
	if !batch.ClosedAt.IsZero() {
		closedAtAny = batch.ClosedAt
	}
	if batch.FailureReason != "" {
		failureReason = batch.FailureReason
	}
	if batch.Checkpoint.Height > 0 {
		cpHeight = int64(batch.Checkpoint.Height)
		cpBlockHash = batch.Checkpoint.BlockHash[:]
		cpRoot = batch.Checkpoint.FinalOrchardRoot[:]
		cpBaseChainID = int64(batch.Checkpoint.BaseChainID)
		cpBridge = batch.Checkpoint.BridgeContract[:]
	}
	if batch.TxHash != ([32]byte{}) {
		txHash = batch.TxHash[:]
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO deposit_batches (
			batch_id,
			state,
			owner,
			lease_owner,
			lease_expires_at,
			started_at,
			closed_at,
			failure_reason,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			proof_requested,
			operator_signatures_json,
			proof_seal,
			tx_hash,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,now(),now())
	`, batch.BatchID[:], int16(batch.State), batch.Owner, leaseOwner, leaseExpiresAny, batch.StartedAt, closedAtAny, failureReason, cpHeight, cpBlockHash, cpRoot, cpBaseChainID, cpBridge, batch.ProofRequested, operatorSignaturesJSON, batch.ProofSeal, txHash)
	if err != nil {
		return fmt.Errorf("deposit/postgres: insert batch: %w", err)
	}
	return nil
}

func updateBatchLeaseAndStateTx(ctx context.Context, tx pgx.Tx, batchID [32]byte, owner string, leaseExpiresAt time.Time, state deposit.BatchState, now time.Time, closedAt time.Time) error {
	var leaseExpiresAny any
	if !leaseExpiresAt.IsZero() {
		leaseExpiresAny = leaseExpiresAt
	}
	if closedAt.IsZero() {
		_, err := tx.Exec(ctx, `
			UPDATE deposit_batches
			SET
				state = $2,
				lease_owner = $3,
				lease_expires_at = $4,
				updated_at = $5
			WHERE batch_id = $1
		`, batchID[:], int16(state), owner, leaseExpiresAny, now)
		if err != nil {
			return fmt.Errorf("deposit/postgres: update batch lease/state: %w", err)
		}
		return nil
	}
	_, err := tx.Exec(ctx, `
		UPDATE deposit_batches
		SET
			state = $2,
			lease_owner = $3,
			lease_expires_at = $4,
			closed_at = $5,
			updated_at = $6
		WHERE batch_id = $1
	`, batchID[:], int16(state), owner, leaseExpiresAny, closedAt, now)
	if err != nil {
		return fmt.Errorf("deposit/postgres: update batch lease/state: %w", err)
	}
	return nil
}

func insertActiveBatchItemsTx(ctx context.Context, tx pgx.Tx, batchID [32]byte, depositIDs [][32]byte) error {
	if len(depositIDs) == 0 {
		return nil
	}
	_, err := tx.Exec(ctx, `
		UPDATE deposit_batch_items
		SET active = FALSE, updated_at = now()
		WHERE deposit_id = ANY($1)
			AND batch_id <> $2
			AND active
	`, rawIDs(depositIDs), batchID[:])
	if err != nil {
		return fmt.Errorf("deposit/postgres: deactivate conflicting batch items: %w", err)
	}
	for _, depositID := range depositIDs {
		_, err := tx.Exec(ctx, `
			INSERT INTO deposit_batch_items (batch_id, deposit_id, active, created_at, updated_at)
			VALUES ($1, $2, TRUE, now(), now())
			ON CONFLICT (batch_id, deposit_id)
			DO UPDATE SET active = TRUE, updated_at = now()
		`, batchID[:], depositID[:])
		if err != nil {
			return fmt.Errorf("deposit/postgres: insert batch item: %w", err)
		}
	}
	return nil
}

func replaceActiveBatchItemsTx(ctx context.Context, tx pgx.Tx, batchID [32]byte, depositIDs [][32]byte) error {
	if _, err := tx.Exec(ctx, `
		UPDATE deposit_batch_items
		SET active = FALSE, updated_at = now()
		WHERE batch_id = $1
			AND active
	`, batchID[:]); err != nil {
		return fmt.Errorf("deposit/postgres: clear prior batch items: %w", err)
	}
	return insertActiveBatchItemsTx(ctx, tx, batchID, depositIDs)
}

func upsertBatchMetadataTx(ctx context.Context, tx pgx.Tx, batch deposit.Batch) error {
	operatorSignaturesJSON, err := marshalOperatorSignatures(batch.OperatorSignatures)
	if err != nil {
		return err
	}
	if batch.StartedAt.IsZero() {
		batch.StartedAt = time.Now().UTC()
	}
	var closedAtAny any
	if !batch.ClosedAt.IsZero() {
		closedAtAny = batch.ClosedAt
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO deposit_batches (
			batch_id,
			state,
			owner,
			lease_owner,
			started_at,
			closed_at,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			proof_requested,
			operator_signatures_json,
			proof_seal,
			tx_hash,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,now(),now())
		ON CONFLICT (batch_id) DO UPDATE
		SET
			state = EXCLUDED.state,
			owner = EXCLUDED.owner,
			lease_owner = EXCLUDED.lease_owner,
			closed_at = COALESCE(EXCLUDED.closed_at, deposit_batches.closed_at),
			checkpoint_height = EXCLUDED.checkpoint_height,
			checkpoint_block_hash = EXCLUDED.checkpoint_block_hash,
			checkpoint_final_orchard_root = EXCLUDED.checkpoint_final_orchard_root,
			checkpoint_base_chain_id = EXCLUDED.checkpoint_base_chain_id,
			checkpoint_bridge_contract = EXCLUDED.checkpoint_bridge_contract,
			proof_requested = EXCLUDED.proof_requested,
			operator_signatures_json = EXCLUDED.operator_signatures_json,
			proof_seal = EXCLUDED.proof_seal,
			tx_hash = EXCLUDED.tx_hash,
			updated_at = now()
	`, batch.BatchID[:], int16(batch.State), batch.Owner, batch.LeaseOwner, batch.StartedAt, closedAtAny, int64(batch.Checkpoint.Height), batch.Checkpoint.BlockHash[:], batch.Checkpoint.FinalOrchardRoot[:], int64(batch.Checkpoint.BaseChainID), batch.Checkpoint.BridgeContract[:], batch.ProofRequested, operatorSignaturesJSON, batch.ProofSeal, null32(batch.TxHash))
	if err != nil {
		return fmt.Errorf("deposit/postgres: upsert batch metadata: %w", err)
	}
	return nil
}

func lockAndValidateBatchJobsTx(ctx context.Context, tx pgx.Tx, depositIDs [][32]byte, minState deposit.State) error {
	if len(depositIDs) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT deposit_id, state
		FROM deposit_jobs
		WHERE deposit_id = ANY($1)
		FOR UPDATE
	`, rawIDs(depositIDs))
	if err != nil {
		return fmt.Errorf("deposit/postgres: lock batch jobs: %w", err)
	}
	defer rows.Close()

	found := make(map[[32]byte]deposit.State, len(depositIDs))
	for rows.Next() {
		var rawID []byte
		var state int16
		if err := rows.Scan(&rawID, &state); err != nil {
			return fmt.Errorf("deposit/postgres: scan batch job: %w", err)
		}
		id, err := to32(rawID)
		if err != nil {
			return err
		}
		found[id] = deposit.State(state)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("deposit/postgres: batch job rows: %w", err)
	}
	for _, id := range depositIDs {
		state, ok := found[id]
		if !ok {
			return deposit.ErrNotFound
		}
		if state == deposit.StateRejected {
			return deposit.ErrInvalidTransition
		}
		if state < minState {
			return deposit.ErrInvalidTransition
		}
	}
	return nil
}

func rawIDs(ids [][32]byte) [][]byte {
	out := make([][]byte, 0, len(ids))
	for _, id := range ids {
		rawID := make([]byte, 32)
		copy(rawID, id[:])
		out = append(out, rawID)
	}
	return out
}

func null32(value [32]byte) any {
	if value == ([32]byte{}) {
		return nil
	}
	return value[:]
}

func uniqueDepositIDs(ids [][32]byte) [][32]byte {
	out := make([][32]byte, 0, len(ids))
	seen := make(map[[32]byte]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func to32(b []byte) ([32]byte, error) {
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("deposit/postgres: expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func to20(b []byte) ([20]byte, error) {
	if len(b) != 20 {
		return [20]byte{}, fmt.Errorf("deposit/postgres: expected 20 bytes, got %d", len(b))
	}
	var out [20]byte
	copy(out[:], b)
	return out, nil
}

func cloneDeposit(d deposit.Deposit) deposit.Deposit {
	d.ProofWitnessItem = append([]byte(nil), d.ProofWitnessItem...)
	if d.SourceEvent != nil {
		src := *d.SourceEvent
		d.SourceEvent = &src
	}
	return d
}

func cloneSubmittedBatchAttempt(a deposit.SubmittedBatchAttempt) deposit.SubmittedBatchAttempt {
	a.DepositIDs = cloneDepositIDs(a.DepositIDs)
	a.OperatorSignatures = clone2DBytes(a.OperatorSignatures)
	a.ProofSeal = append([]byte(nil), a.ProofSeal...)
	return a
}

func cloneDepositIDs(ids [][32]byte) [][32]byte {
	if len(ids) == 0 {
		return nil
	}
	out := make([][32]byte, len(ids))
	copy(out, ids)
	return out
}

func clone2DBytes(in [][]byte) [][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(in))
	for _, item := range in {
		out = append(out, append([]byte(nil), item...))
	}
	return out
}

func loadSubmittedBatchAttemptTx(ctx context.Context, tx pgx.Tx, batchID [32]byte) (deposit.SubmittedBatchAttempt, bool, error) {
	row := tx.QueryRow(ctx, `
		SELECT
			batch_id,
			owner,
			epoch,
			deposit_ids_json,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			operator_signatures_json,
			proof_seal,
			tx_hash
		FROM deposit_batch_attempts
		WHERE batch_id = $1
		FOR UPDATE
	`, batchID[:])

	attempt, err := scanSubmittedBatchAttempt(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return deposit.SubmittedBatchAttempt{}, false, nil
		}
		return deposit.SubmittedBatchAttempt{}, false, err
	}
	return attempt, true, nil
}

func insertSubmittedBatchAttemptTx(ctx context.Context, tx pgx.Tx, attempt deposit.SubmittedBatchAttempt) error {
	depositIDsJSON, err := marshalDepositIDs(attempt.DepositIDs)
	if err != nil {
		return err
	}
	operatorSignaturesJSON, err := marshalOperatorSignatures(attempt.OperatorSignatures)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO deposit_batch_attempts (
			batch_id,
			owner,
			epoch,
			deposit_ids_json,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			operator_signatures_json,
			proof_seal,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now(),now())
	`,
		attempt.BatchID[:],
		attempt.Owner,
		int64(attempt.Epoch),
		depositIDsJSON,
		int64(attempt.Checkpoint.Height),
		attempt.Checkpoint.BlockHash[:],
		attempt.Checkpoint.FinalOrchardRoot[:],
		int64(attempt.Checkpoint.BaseChainID),
		attempt.Checkpoint.BridgeContract[:],
		operatorSignaturesJSON,
		attempt.ProofSeal,
	)
	if err != nil {
		return fmt.Errorf("deposit/postgres: insert submitted batch attempt: %w", err)
	}
	return nil
}

type scanRow interface {
	Scan(dest ...any) error
}

func scanSubmittedBatchAttempt(row scanRow) (deposit.SubmittedBatchAttempt, error) {
	var (
		batchIDRaw             []byte
		owner                  string
		epoch                  int64
		depositIDsJSON         []byte
		checkpointHeight       int64
		checkpointBlockHashRaw []byte
		checkpointRootRaw      []byte
		checkpointBaseChainID  int64
		checkpointBridgeRaw    []byte
		operatorSignaturesJSON []byte
		proofSeal              []byte
		txHashRaw              []byte
	)

	if err := row.Scan(
		&batchIDRaw,
		&owner,
		&epoch,
		&depositIDsJSON,
		&checkpointHeight,
		&checkpointBlockHashRaw,
		&checkpointRootRaw,
		&checkpointBaseChainID,
		&checkpointBridgeRaw,
		&operatorSignaturesJSON,
		&proofSeal,
		&txHashRaw,
	); err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}

	batchID, err := to32(batchIDRaw)
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}
	blockHash, err := to32(checkpointBlockHashRaw)
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}
	root, err := to32(checkpointRootRaw)
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}
	bridge, err := to20(checkpointBridgeRaw)
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}
	depositIDs, err := unmarshalDepositIDs(depositIDsJSON)
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}
	operatorSignatures, err := unmarshalOperatorSignatures(operatorSignaturesJSON)
	if err != nil {
		return deposit.SubmittedBatchAttempt{}, err
	}

	attempt := deposit.SubmittedBatchAttempt{
		BatchID:            batchID,
		DepositIDs:         depositIDs,
		Owner:              owner,
		Epoch:              uint64(epoch),
		Checkpoint:         checkpoint.Checkpoint{Height: uint64(checkpointHeight), BlockHash: blockHash, FinalOrchardRoot: root, BaseChainID: uint64(checkpointBaseChainID), BridgeContract: bridge},
		OperatorSignatures: operatorSignatures,
		ProofSeal:          append([]byte(nil), proofSeal...),
	}
	if len(txHashRaw) > 0 {
		attempt.TxHash, err = to32(txHashRaw)
		if err != nil {
			return deposit.SubmittedBatchAttempt{}, err
		}
	}
	return attempt, nil
}

func submittedBatchAttemptMatches(attempt deposit.SubmittedBatchAttempt, owner string, depositIDs [][32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) bool {
	if attempt.Owner != owner || attempt.Checkpoint != cp {
		return false
	}
	if !bytes.Equal(attempt.ProofSeal, seal) {
		return false
	}
	if len(attempt.DepositIDs) != len(depositIDs) || len(attempt.OperatorSignatures) != len(operatorSignatures) {
		return false
	}
	for i := range attempt.DepositIDs {
		if attempt.DepositIDs[i] != depositIDs[i] {
			return false
		}
	}
	for i := range attempt.OperatorSignatures {
		if !bytes.Equal(attempt.OperatorSignatures[i], operatorSignatures[i]) {
			return false
		}
	}
	return true
}

func marshalDepositIDs(ids [][32]byte) ([]byte, error) {
	encoded := make([]string, 0, len(ids))
	for _, id := range ids {
		encoded = append(encoded, hex.EncodeToString(id[:]))
	}
	b, err := json.Marshal(encoded)
	if err != nil {
		return nil, fmt.Errorf("deposit/postgres: marshal deposit ids: %w", err)
	}
	return b, nil
}

func unmarshalDepositIDs(b []byte) ([][32]byte, error) {
	var encoded []string
	if err := json.Unmarshal(b, &encoded); err != nil {
		return nil, fmt.Errorf("deposit/postgres: unmarshal deposit ids: %w", err)
	}
	out := make([][32]byte, 0, len(encoded))
	for _, item := range encoded {
		raw, err := hex.DecodeString(item)
		if err != nil {
			return nil, fmt.Errorf("deposit/postgres: decode deposit id: %w", err)
		}
		id, err := to32(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func marshalOperatorSignatures(sigs [][]byte) ([]byte, error) {
	b, err := json.Marshal(sigs)
	if err != nil {
		return nil, fmt.Errorf("deposit/postgres: marshal operator signatures: %w", err)
	}
	return b, nil
}

func unmarshalOperatorSignatures(b []byte) ([][]byte, error) {
	var sigs [][]byte
	if err := json.Unmarshal(b, &sigs); err != nil {
		return nil, fmt.Errorf("deposit/postgres: unmarshal operator signatures: %w", err)
	}
	return clone2DBytes(sigs), nil
}

func depositEqual(a, b deposit.Deposit) bool {
	return depositIdentityEqual(a, b) && a.JunoHeight == b.JunoHeight
}

func depositIdentityEqual(a, b deposit.Deposit) bool {
	return a.DepositID == b.DepositID &&
		a.Commitment == b.Commitment &&
		a.LeafIndex == b.LeafIndex &&
		a.Amount == b.Amount &&
		a.BaseRecipient == b.BaseRecipient
}

func getWithQuerier(ctx context.Context, q execQueryer, depositID [32]byte) (deposit.Job, error) {
	var (
		depositIDRaw     []byte
		commitmentRaw    []byte
		leafIndex        int64
		amount           int64
		baseRecipientRaw []byte
		proofWitnessRaw  []byte
		state            int16

		cpHeight        *int64
		cpBlockHashRaw  []byte
		cpRootRaw       []byte
		cpBaseChainID   *int64
		cpBridgeRaw     []byte
		proofSeal       []byte
		txHashRaw       []byte
		junoHeight      *int64
		rejectionReason *string
	)

	err := q.QueryRow(ctx, `
		SELECT
			deposit_id,
			commitment,
			leaf_index,
			amount,
			base_recipient,
			proof_witness_item,
			state,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			proof_seal,
			tx_hash,
			juno_height,
			rejection_reason
		FROM deposit_jobs
		WHERE deposit_id = $1
	`, depositID[:]).Scan(
		&depositIDRaw,
		&commitmentRaw,
		&leafIndex,
		&amount,
		&baseRecipientRaw,
		&proofWitnessRaw,
		&state,
		&cpHeight,
		&cpBlockHashRaw,
		&cpRootRaw,
		&cpBaseChainID,
		&cpBridgeRaw,
		&proofSeal,
		&txHashRaw,
		&junoHeight,
		&rejectionReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return deposit.Job{}, deposit.ErrNotFound
		}
		return deposit.Job{}, fmt.Errorf("deposit/postgres: get: %w", err)
	}

	id, err := to32(depositIDRaw)
	if err != nil {
		return deposit.Job{}, err
	}
	cm, err := to32(commitmentRaw)
	if err != nil {
		return deposit.Job{}, err
	}
	recip, err := to20(baseRecipientRaw)
	if err != nil {
		return deposit.Job{}, err
	}
	if leafIndex < 0 || amount < 0 {
		return deposit.Job{}, fmt.Errorf("deposit/postgres: negative values in db")
	}

	var jh int64
	if junoHeight != nil {
		jh = *junoHeight
	}
	job := deposit.Job{
		Deposit: deposit.Deposit{
			DepositID:        id,
			Commitment:       cm,
			LeafIndex:        uint64(leafIndex),
			Amount:           uint64(amount),
			BaseRecipient:    recip,
			ProofWitnessItem: append([]byte(nil), proofWitnessRaw...),
			JunoHeight:       jh,
		},
		State: deposit.State(state),
	}

	if cpHeight != nil {
		var (
			bh [32]byte
			rt [32]byte
		)
		if cpBlockHashRaw != nil {
			bh, err = to32(cpBlockHashRaw)
			if err != nil {
				return deposit.Job{}, err
			}
		}
		if cpRootRaw != nil {
			rt, err = to32(cpRootRaw)
			if err != nil {
				return deposit.Job{}, err
			}
		}
		var bridge [20]byte
		if cpBridgeRaw != nil {
			bridge, err = to20(cpBridgeRaw)
			if err != nil {
				return deposit.Job{}, err
			}
		}
		var baseChain uint64
		if cpBaseChainID != nil && *cpBaseChainID >= 0 {
			baseChain = uint64(*cpBaseChainID)
		}
		job.Checkpoint = checkpoint.Checkpoint{
			Height:           uint64(*cpHeight),
			BlockHash:        bh,
			FinalOrchardRoot: rt,
			BaseChainID:      baseChain,
			BridgeContract:   bridge,
		}
	}

	if proofSeal != nil {
		job.ProofSeal = append([]byte(nil), proofSeal...)
	}
	if txHashRaw != nil {
		tx, err := to32(txHashRaw)
		if err != nil {
			return deposit.Job{}, err
		}
		job.TxHash = tx
	}
	if rejectionReason != nil {
		job.RejectionReason = *rejectionReason
	}

	return job, nil
}

func recordSourceEvent(ctx context.Context, q execQueryer, d deposit.Deposit) error {
	if d.SourceEvent == nil {
		return nil
	}
	if d.SourceEvent.ChainID == 0 || d.SourceEvent.ChainID > math.MaxInt64 || d.SourceEvent.LogIndex > math.MaxInt64 {
		return deposit.ErrDepositMismatch
	}

	var existingIDRaw []byte
	if err := q.QueryRow(ctx, `
		INSERT INTO deposit_source_events (chain_id, tx_hash, log_index, deposit_id, created_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (chain_id, tx_hash, log_index)
		DO UPDATE SET deposit_id = deposit_source_events.deposit_id
		RETURNING deposit_id
	`, int64(d.SourceEvent.ChainID), d.SourceEvent.TxHash[:], int64(d.SourceEvent.LogIndex), d.DepositID[:]).Scan(&existingIDRaw); err != nil {
		return fmt.Errorf("deposit/postgres: record source event: %w", err)
	}
	existingID, err := to32(existingIDRaw)
	if err != nil {
		return err
	}
	if existingID != d.DepositID {
		return deposit.ErrDepositMismatch
	}
	return nil
}

var _ deposit.Store = (*Store)(nil)
