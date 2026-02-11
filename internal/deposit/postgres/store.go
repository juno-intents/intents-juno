package postgres

import (
	"bytes"
	"context"
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

func (s *Store) UpsertConfirmed(ctx context.Context, d deposit.Deposit) (deposit.Job, bool, error) {
	if s == nil || s.pool == nil {
		return deposit.Job{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if d.Amount == 0 {
		return deposit.Job{}, false, fmt.Errorf("%w: amount must be > 0", deposit.ErrDepositMismatch)
	}
	if d.LeafIndex > math.MaxInt64 {
		return deposit.Job{}, false, fmt.Errorf("%w: leaf index too large", deposit.ErrDepositMismatch)
	}

	tag, err := s.pool.Exec(ctx, `
		INSERT INTO deposit_jobs (
			deposit_id,
			commitment,
			leaf_index,
			amount,
			base_recipient,
			state,
			created_at,
			updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,now(),now())
		ON CONFLICT (deposit_id) DO NOTHING
	`, d.DepositID[:], d.Commitment[:], int64(d.LeafIndex), int64(d.Amount), d.BaseRecipient[:], int16(deposit.StateConfirmed))
	if err != nil {
		return deposit.Job{}, false, fmt.Errorf("deposit/postgres: insert: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return deposit.Job{Deposit: d, State: deposit.StateConfirmed}, true, nil
	}

	job, err := s.Get(ctx, d.DepositID)
	if err != nil {
		return deposit.Job{}, false, err
	}
	if job.Deposit != d {
		return deposit.Job{}, false, deposit.ErrDepositMismatch
	}

	if job.State < deposit.StateConfirmed {
		// Upgrade to confirmed.
		_, err := s.pool.Exec(ctx, `
			UPDATE deposit_jobs
			SET state = $2, updated_at = now()
			WHERE deposit_id = $1 AND state < $2
		`, d.DepositID[:], int16(deposit.StateConfirmed))
		if err != nil {
			return deposit.Job{}, false, fmt.Errorf("deposit/postgres: update state: %w", err)
		}
		job.State = deposit.StateConfirmed
	}

	return job, false, nil
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
		state            int16

		cpHeight       *int64
		cpBlockHashRaw []byte
		cpRootRaw      []byte
		cpBaseChainID  *int64
		cpBridgeRaw    []byte
		proofSeal      []byte
		txHashRaw      []byte
	)

	err := s.pool.QueryRow(ctx, `
		SELECT
			deposit_id,
			commitment,
			leaf_index,
			amount,
			base_recipient,
			state,
			checkpoint_height,
			checkpoint_block_hash,
			checkpoint_final_orchard_root,
			checkpoint_base_chain_id,
			checkpoint_bridge_contract,
			proof_seal,
			tx_hash
		FROM deposit_jobs
		WHERE deposit_id = $1
	`, depositID[:]).Scan(
		&depositIDRaw,
		&commitmentRaw,
		&leafIndex,
		&amount,
		&baseRecipientRaw,
		&state,
		&cpHeight,
		&cpBlockHashRaw,
		&cpRootRaw,
		&cpBaseChainID,
		&cpBridgeRaw,
		&proofSeal,
		&txHashRaw,
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

	job := deposit.Job{
		Deposit: deposit.Deposit{
			DepositID:     id,
			Commitment:    cm,
			LeafIndex:     uint64(leafIndex),
			Amount:        uint64(amount),
			BaseRecipient: recip,
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
				state = $1
				AND (
					claim_expires_at IS NULL
					OR claim_expires_at <= now()
					OR claimed_by = $2
				)
			ORDER BY created_at ASC, deposit_id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT $3
		)
		UPDATE deposit_jobs dj
		SET claimed_by = $2, claim_expires_at = $4, updated_at = now()
		FROM picked
		WHERE dj.deposit_id = picked.deposit_id
		RETURNING dj.deposit_id
	`, int16(deposit.StateConfirmed), owner, limit, expiresAt)
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

func (s *Store) MarkProofRequested(ctx context.Context, depositID [32]byte, cp checkpoint.Checkpoint) error {
	job, err := s.Get(ctx, depositID)
	if err != nil {
		return err
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
			claimed_by = NULL,
			claim_expires_at = NULL,
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
			claimed_by = NULL,
			claim_expires_at = NULL,
			updated_at = now()
		WHERE deposit_id = $1
	`, depositID[:], int16(deposit.StateFinalized), txHash[:])
	if err != nil {
		return fmt.Errorf("deposit/postgres: mark finalized: %w", err)
	}
	return nil
}

func (s *Store) MarkBatchSubmitted(ctx context.Context, depositIDs [][32]byte, cp checkpoint.Checkpoint, seal []byte) error {
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
		return fmt.Errorf("deposit/postgres: begin submit batch tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT deposit_id, state
		FROM deposit_jobs
		WHERE deposit_id = ANY($1)
		FOR UPDATE
	`, rawIDs)
	if err != nil {
		return fmt.Errorf("deposit/postgres: lock submit batch rows: %w", err)
	}
	defer rows.Close()

	found := make(map[[32]byte]int16, len(ids))
	for rows.Next() {
		var (
			idRaw []byte
			state int16
		)
		if err := rows.Scan(&idRaw, &state); err != nil {
			return fmt.Errorf("deposit/postgres: scan submit batch row: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return err
		}
		found[id] = state
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("deposit/postgres: submit batch rows: %w", err)
	}

	updatable := make([][]byte, 0, len(ids))
	for _, id := range ids {
		state, ok := found[id]
		if !ok {
			return deposit.ErrNotFound
		}
		if deposit.State(state) == deposit.StateFinalized || deposit.State(state) >= deposit.StateSubmitted {
			continue
		}
		if deposit.State(state) < deposit.StateConfirmed {
			return deposit.ErrInvalidTransition
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
				claimed_by = NULL,
				claim_expires_at = NULL,
				updated_at = now()
			WHERE deposit_id = ANY($1)
		`,
			updatable,
			int16(deposit.StateSubmitted),
			int64(cp.Height),
			cp.BlockHash[:],
			cp.FinalOrchardRoot[:],
			int64(cp.BaseChainID),
			cp.BridgeContract[:],
			seal,
		)
		if err != nil {
			return fmt.Errorf("deposit/postgres: update submit batch rows: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("deposit/postgres: commit submit batch tx: %w", err)
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
		SELECT deposit_id, state, tx_hash
		FROM deposit_jobs
		WHERE deposit_id = ANY($1)
		FOR UPDATE
	`, rawIDs)
	if err != nil {
		return fmt.Errorf("deposit/postgres: lock finalize batch rows: %w", err)
	}
	defer rows.Close()

	type rowState struct {
		state  int16
		txHash []byte
	}
	found := make(map[[32]byte]rowState, len(ids))
	for rows.Next() {
		var (
			idRaw     []byte
			state     int16
			txHashRaw []byte
		)
		if err := rows.Scan(&idRaw, &state, &txHashRaw); err != nil {
			return fmt.Errorf("deposit/postgres: scan finalize batch row: %w", err)
		}
		id, err := to32(idRaw)
		if err != nil {
			return err
		}
		found[id] = rowState{
			state:  state,
			txHash: append([]byte(nil), txHashRaw...),
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("deposit/postgres: finalize batch rows: %w", err)
	}

	updatable := make([][]byte, 0, len(ids))
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

var _ deposit.Store = (*Store)(nil)
