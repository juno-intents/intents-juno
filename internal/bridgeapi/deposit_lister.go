package bridgeapi

import (
	"context"
	"fmt"
	"math"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/deposit"
)

type PostgresDepositLister struct {
	pool *pgxpool.Pool
}

func NewPostgresDepositLister(pool *pgxpool.Pool) (*PostgresDepositLister, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", ErrInvalidConfig)
	}
	return &PostgresDepositLister{pool: pool}, nil
}

func (l *PostgresDepositLister) ListByBaseRecipient(ctx context.Context, recipient [20]byte, limit, offset int) ([]deposit.Job, int, error) {
	var total int
	err := l.pool.QueryRow(ctx, `SELECT COUNT(*) FROM deposit_jobs WHERE base_recipient = $1`, recipient[:]).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: count deposits by recipient: %w", err)
	}

	rows, err := l.pool.Query(ctx, `
		SELECT deposit_id, state, commitment, leaf_index, amount, base_recipient,
			   COALESCE(checkpoint_height, 0), checkpoint_block_hash,
			   checkpoint_final_orchard_root, COALESCE(checkpoint_base_chain_id, 0),
			   checkpoint_bridge_contract, proof_seal, tx_hash, rejection_reason
		FROM deposit_jobs
		WHERE base_recipient = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`, recipient[:], limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: list deposits by recipient: %w", err)
	}
	defer rows.Close()

	var jobs []deposit.Job
	for rows.Next() {
		j, err := scanDepositJob(rows)
		if err != nil {
			return nil, 0, err
		}
		jobs = append(jobs, j)
	}
	if rows.Err() != nil {
		return nil, 0, fmt.Errorf("bridgeapi: iterate deposits: %w", rows.Err())
	}
	return jobs, total, nil
}

func (l *PostgresDepositLister) GetByTxHash(ctx context.Context, txHash [32]byte) (*deposit.Job, error) {
	row := l.pool.QueryRow(ctx, `
		SELECT deposit_id, state, commitment, leaf_index, amount, base_recipient,
			   COALESCE(checkpoint_height, 0), checkpoint_block_hash,
			   checkpoint_final_orchard_root, COALESCE(checkpoint_base_chain_id, 0),
			   checkpoint_bridge_contract, proof_seal, tx_hash, rejection_reason
		FROM deposit_jobs
		WHERE tx_hash = $1
	`, txHash[:])

	j, err := scanDepositJobRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("bridgeapi: get deposit by tx hash: %w", err)
	}
	return &j, nil
}

func scanDepositJob(rows pgx.Rows) (deposit.Job, error) {
	var (
		idRaw           []byte
		state           int16
		commitment      []byte
		leafIndex       int64
		amount          int64
		recipientRaw    []byte
		cpHeight        int64
		cpBlockHash     []byte
		cpRoot          []byte
		cpChainID       int64
		cpBridge        []byte
		proofSeal       []byte
		txHash          []byte
		rejectionReason *string
	)
	err := rows.Scan(&idRaw, &state, &commitment, &leafIndex, &amount, &recipientRaw,
		&cpHeight, &cpBlockHash, &cpRoot, &cpChainID, &cpBridge, &proofSeal, &txHash, &rejectionReason)
	if err != nil {
		return deposit.Job{}, fmt.Errorf("bridgeapi: scan deposit: %w", err)
	}
	return buildDepositJob(idRaw, state, commitment, leafIndex, amount, recipientRaw,
		cpHeight, cpBlockHash, cpRoot, cpChainID, cpBridge, proofSeal, txHash, rejectionReason)
}

func scanDepositJobRow(row pgx.Row) (deposit.Job, error) {
	var (
		idRaw           []byte
		state           int16
		commitment      []byte
		leafIndex       int64
		amount          int64
		recipientRaw    []byte
		cpHeight        int64
		cpBlockHash     []byte
		cpRoot          []byte
		cpChainID       int64
		cpBridge        []byte
		proofSeal       []byte
		txHash          []byte
		rejectionReason *string
	)
	err := row.Scan(&idRaw, &state, &commitment, &leafIndex, &amount, &recipientRaw,
		&cpHeight, &cpBlockHash, &cpRoot, &cpChainID, &cpBridge, &proofSeal, &txHash, &rejectionReason)
	if err != nil {
		return deposit.Job{}, err
	}
	return buildDepositJob(idRaw, state, commitment, leafIndex, amount, recipientRaw,
		cpHeight, cpBlockHash, cpRoot, cpChainID, cpBridge, proofSeal, txHash, rejectionReason)
}

func buildDepositJob(idRaw []byte, state int16, commitment []byte, leafIndex, amount int64,
	recipientRaw []byte, cpHeight int64, cpBlockHash, cpRoot []byte, cpChainID int64,
	cpBridge, proofSeal, txHash []byte, rejectionReason *string) (deposit.Job, error) {

	id, err := to32(idRaw)
	if err != nil {
		return deposit.Job{}, err
	}
	recipient, err := to20(recipientRaw)
	if err != nil {
		return deposit.Job{}, err
	}
	if amount < 0 || amount > math.MaxInt64 {
		return deposit.Job{}, fmt.Errorf("bridgeapi: invalid deposit amount in db")
	}

	var commitHash [32]byte
	if len(commitment) == 32 {
		copy(commitHash[:], commitment)
	}

	j := deposit.Job{
		Deposit: deposit.Deposit{
			DepositID:     id,
			Commitment:    commitHash,
			LeafIndex:     uint64(leafIndex),
			Amount:        uint64(amount),
			BaseRecipient: recipient,
		},
		State: deposit.State(state),
		Checkpoint: checkpoint.Checkpoint{
			Height: uint64(cpHeight),
		},
	}

	if len(cpBlockHash) == 32 {
		copy(j.Checkpoint.BlockHash[:], cpBlockHash)
	}
	if len(cpRoot) == 32 {
		copy(j.Checkpoint.FinalOrchardRoot[:], cpRoot)
	}
	j.Checkpoint.BaseChainID = uint64(cpChainID)
	if len(cpBridge) == 20 {
		copy(j.Checkpoint.BridgeContract[:], cpBridge)
	}

	if proofSeal != nil {
		j.ProofSeal = append([]byte(nil), proofSeal...)
	}
	if len(txHash) == 32 {
		copy(j.TxHash[:], txHash)
	}
	if rejectionReason != nil {
		j.RejectionReason = *rejectionReason
	}

	return j, nil
}
