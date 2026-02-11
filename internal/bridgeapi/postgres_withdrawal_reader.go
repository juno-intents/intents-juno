package bridgeapi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

type PostgresWithdrawalReader struct {
	pool *pgxpool.Pool
}

func NewPostgresWithdrawalReader(pool *pgxpool.Pool) (*PostgresWithdrawalReader, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", ErrInvalidConfig)
	}
	return &PostgresWithdrawalReader{pool: pool}, nil
}

func (r *PostgresWithdrawalReader) Get(ctx context.Context, withdrawalID [32]byte) (WithdrawalStatus, error) {
	if r == nil || r.pool == nil {
		return WithdrawalStatus{}, fmt.Errorf("%w: nil reader", ErrInvalidConfig)
	}

	var (
		idRaw        []byte
		requesterRaw []byte
		amount       int64
		feeBps       int32
		recipientUA  []byte
		expiry       time.Time
		batchIDRaw   []byte
		batchState   *int16
		junoTxID     *string
		baseTxHash   *string
	)

	err := r.pool.QueryRow(ctx, `
		SELECT
			wr.withdrawal_id,
			wr.requester,
			wr.amount,
			wr.fee_bps,
			wr.recipient_ua,
			wr.expiry,
			wb.batch_id,
			wb.state,
			wb.juno_txid,
			wb.base_tx_hash
		FROM withdrawal_requests wr
		LEFT JOIN withdrawal_batch_items wbi ON wbi.withdrawal_id = wr.withdrawal_id
		LEFT JOIN withdrawal_batches wb ON wb.batch_id = wbi.batch_id
		WHERE wr.withdrawal_id = $1
	`, withdrawalID[:]).Scan(
		&idRaw,
		&requesterRaw,
		&amount,
		&feeBps,
		&recipientUA,
		&expiry,
		&batchIDRaw,
		&batchState,
		&junoTxID,
		&baseTxHash,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return WithdrawalStatus{}, withdraw.ErrNotFound
		}
		return WithdrawalStatus{}, fmt.Errorf("bridgeapi: query withdrawal status: %w", err)
	}

	id, err := to32(idRaw)
	if err != nil {
		return WithdrawalStatus{}, err
	}
	requester, err := to20(requesterRaw)
	if err != nil {
		return WithdrawalStatus{}, err
	}
	if amount <= 0 || amount > math.MaxInt64 || feeBps < 0 {
		return WithdrawalStatus{}, fmt.Errorf("bridgeapi: invalid amount/fee values in db")
	}

	out := WithdrawalStatus{
		Withdrawal: withdraw.Withdrawal{
			ID:          id,
			Requester:   requester,
			Amount:      uint64(amount),
			FeeBps:      uint32(feeBps),
			RecipientUA: append([]byte(nil), recipientUA...),
			Expiry:      expiry.UTC(),
		},
	}

	if batchIDRaw != nil && batchState != nil {
		bid, err := to32(batchIDRaw)
		if err != nil {
			return WithdrawalStatus{}, err
		}
		out.BatchID = &bid
		out.BatchState = withdraw.BatchState(*batchState)
	}
	if junoTxID != nil {
		out.JunoTxID = *junoTxID
	}
	if baseTxHash != nil {
		out.BaseTxHash = *baseTxHash
	}

	return out, nil
}

func to32(b []byte) ([32]byte, error) {
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("bridgeapi: expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func to20(b []byte) ([20]byte, error) {
	if len(b) != 20 {
		return [20]byte{}, fmt.Errorf("bridgeapi: expected 20 bytes, got %d", len(b))
	}
	var out [20]byte
	copy(out[:], b)
	return out, nil
}
