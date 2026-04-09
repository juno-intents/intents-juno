package bridgeapi

import (
	"context"
	"fmt"
	"math"
	"time"

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

const depositStatusSelect = `
	SELECT
		dj.deposit_id,
		dj.state,
		dj.commitment,
		dj.leaf_index,
		dj.amount,
		dj.base_recipient,
		COALESCE(dj.juno_height, 0),
		COALESCE(dj.checkpoint_height, 0),
		dj.checkpoint_block_hash,
		dj.checkpoint_final_orchard_root,
		COALESCE(dj.checkpoint_base_chain_id, 0),
		dj.checkpoint_bridge_contract,
		dj.proof_seal,
		dj.tx_hash,
		dj.rejection_reason,
		db.tx_hash,
		dj.created_at
	FROM deposit_jobs dj
	LEFT JOIN deposit_batches db ON db.batch_id = dj.submit_batch_id
`

func (l *PostgresDepositLister) ListByBaseRecipient(ctx context.Context, recipient [20]byte, limit, offset int) ([]DepositStatus, int, error) {
	var total int
	err := l.pool.QueryRow(ctx, `SELECT COUNT(*) FROM deposit_jobs WHERE base_recipient = $1`, recipient[:]).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: count deposits by recipient: %w", err)
	}

	rows, err := l.pool.Query(ctx,
		depositStatusSelect+`WHERE dj.base_recipient = $1 ORDER BY dj.created_at DESC LIMIT $2 OFFSET $3`,
		recipient[:], limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: list deposits by recipient: %w", err)
	}
	defer rows.Close()

	statuses, err := scanDepositStatusRows(rows)
	if err != nil {
		return nil, 0, err
	}
	return statuses, total, nil
}

func (l *PostgresDepositLister) GetByTxHash(ctx context.Context, txHash [32]byte) (*DepositStatus, error) {
	row := l.pool.QueryRow(ctx,
		depositStatusSelect+`WHERE dj.tx_hash = $1`,
		txHash[:],
	)

	status, err := scanDepositStatusRow(row)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("bridgeapi: get deposit by tx hash: %w", err)
	}
	return &status, nil
}

func (l *PostgresDepositLister) ListRecent(ctx context.Context, limit, offset int) ([]DepositStatus, int, error) {
	var total int
	err := l.pool.QueryRow(ctx, `SELECT COUNT(*) FROM deposit_jobs`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: count recent deposits: %w", err)
	}

	rows, err := l.pool.Query(ctx,
		depositStatusSelect+`ORDER BY dj.created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: list recent deposits: %w", err)
	}
	defer rows.Close()

	statuses, err := scanDepositStatusRows(rows)
	if err != nil {
		return nil, 0, err
	}
	return statuses, total, nil
}

func scanDepositStatusRows(rows pgx.Rows) ([]DepositStatus, error) {
	var statuses []DepositStatus
	for rows.Next() {
		st, err := scanDepositStatus(rows)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, st)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("bridgeapi: iterate deposits: %w", rows.Err())
	}
	return statuses, nil
}

func scanDepositStatusRow(row pgx.Row) (DepositStatus, error) {
	return scanDepositStatus(scannerAdapter{row: row})
}

type depositStatusScanner interface {
	Scan(dest ...any) error
}

type scannerAdapter struct {
	row pgx.Row
}

func (s scannerAdapter) Scan(dest ...any) error {
	return s.row.Scan(dest...)
}

func scanDepositStatus(scanner depositStatusScanner) (DepositStatus, error) {
	var (
		idRaw           []byte
		state           int16
		commitment      []byte
		leafIndex       int64
		amount          int64
		recipientRaw    []byte
		junoHeight      int64
		cpHeight        int64
		cpBlockHash     []byte
		cpRoot          []byte
		cpChainID       int64
		cpBridge        []byte
		proofSeal       []byte
		txHash          []byte
		rejectionReason *string
		baseTxHash      []byte
		createdAt       time.Time
	)
	err := scanner.Scan(
		&idRaw,
		&state,
		&commitment,
		&leafIndex,
		&amount,
		&recipientRaw,
		&junoHeight,
		&cpHeight,
		&cpBlockHash,
		&cpRoot,
		&cpChainID,
		&cpBridge,
		&proofSeal,
		&txHash,
		&rejectionReason,
		&baseTxHash,
		&createdAt,
	)
	if err != nil {
		return DepositStatus{}, err
	}
	return buildDepositStatus(idRaw, state, commitment, leafIndex, amount, recipientRaw, junoHeight,
		cpHeight, cpBlockHash, cpRoot, cpChainID, cpBridge, proofSeal, txHash, rejectionReason, baseTxHash, createdAt)
}

func buildDepositStatus(idRaw []byte, state int16, commitment []byte, leafIndex, amount int64, recipientRaw []byte,
	junoHeight, cpHeight int64, cpBlockHash, cpRoot []byte, cpChainID int64, cpBridge, proofSeal, txHash []byte,
	rejectionReason *string, baseTxHash []byte, createdAt time.Time) (DepositStatus, error) {

	id, err := to32(idRaw)
	if err != nil {
		return DepositStatus{}, err
	}
	recipient, err := to20(recipientRaw)
	if err != nil {
		return DepositStatus{}, err
	}
	if amount < 0 || amount > math.MaxInt64 {
		return DepositStatus{}, fmt.Errorf("bridgeapi: invalid deposit amount in db")
	}

	var commitmentHash [32]byte
	if len(commitment) == 32 {
		copy(commitmentHash[:], commitment)
	}

	st := DepositStatus{
		Job: deposit.Job{
			Deposit: deposit.Deposit{
				DepositID:     id,
				Commitment:    commitmentHash,
				LeafIndex:     uint64(leafIndex),
				Amount:        uint64(amount),
				BaseRecipient: recipient,
				JunoHeight:    junoHeight,
			},
			State: deposit.State(state),
			Checkpoint: checkpoint.Checkpoint{
				Height: uint64(cpHeight),
			},
		},
		CreatedAt: createdAt.UTC(),
	}

	if len(cpBlockHash) == 32 {
		copy(st.Job.Checkpoint.BlockHash[:], cpBlockHash)
	}
	if len(cpRoot) == 32 {
		copy(st.Job.Checkpoint.FinalOrchardRoot[:], cpRoot)
	}
	st.Job.Checkpoint.BaseChainID = uint64(cpChainID)
	if len(cpBridge) == 20 {
		copy(st.Job.Checkpoint.BridgeContract[:], cpBridge)
	}
	if proofSeal != nil {
		st.Job.ProofSeal = append([]byte(nil), proofSeal...)
	}
	if len(txHash) == 32 {
		copy(st.Job.TxHash[:], txHash)
	}
	if rejectionReason != nil {
		st.Job.RejectionReason = *rejectionReason
	}
	if len(baseTxHash) == 32 {
		st.BaseTxHash = "0x" + fmt.Sprintf("%x", baseTxHash)
	}

	return st, nil
}
