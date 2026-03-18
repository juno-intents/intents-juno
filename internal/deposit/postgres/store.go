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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/deposit"
)

var ErrInvalidConfig = errors.New("deposit/postgres: invalid config")

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

	var junoHeight *int64
	if d.JunoHeight > 0 {
		h := d.JunoHeight
		junoHeight = &h
	}

	tag, err := s.pool.Exec(ctx, `
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

	job, err := s.Get(ctx, d.DepositID)
	if err != nil {
		return deposit.Job{}, false, err
	}
	if !depositIdentityEqual(job.Deposit, d) {
		return deposit.Job{}, false, deposit.ErrDepositMismatch
	}
	if job.State < deposit.StateProofRequested && len(d.ProofWitnessItem) > 0 && !bytes.Equal(job.Deposit.ProofWitnessItem, d.ProofWitnessItem) {
		_, err = s.pool.Exec(ctx, `
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
		_, err = s.pool.Exec(ctx, `
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

	err := s.pool.QueryRow(ctx, `
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

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("deposit/postgres: commit finalize batch tx: %w", err)
	}
	return nil
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

var _ deposit.Store = (*Store)(nil)
