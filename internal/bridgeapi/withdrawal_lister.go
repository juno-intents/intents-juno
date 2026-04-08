package bridgeapi

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

type PostgresWithdrawalLister struct {
	pool *pgxpool.Pool
}

func NewPostgresWithdrawalLister(pool *pgxpool.Pool) (*PostgresWithdrawalLister, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", ErrInvalidConfig)
	}
	return &PostgresWithdrawalLister{pool: pool}, nil
}

const withdrawalListQuery = `
	SELECT
		wr.withdrawal_id, wr.requester, wr.amount, wr.fee_bps, wr.recipient_ua, wr.expiry,
		wb.batch_id, wb.state, wb.juno_txid, wb.base_tx_hash
	FROM withdrawal_requests wr
	LEFT JOIN withdrawal_batch_items wbi ON wbi.withdrawal_id = wr.withdrawal_id
	LEFT JOIN withdrawal_batches wb ON wb.batch_id = wbi.batch_id
`

func (l *PostgresWithdrawalLister) ListByRequester(ctx context.Context, requester [20]byte, limit, offset int) ([]WithdrawalStatus, int, error) {
	var total int
	err := l.pool.QueryRow(ctx, `SELECT COUNT(*) FROM withdrawal_requests WHERE requester = $1`, requester[:]).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: count withdrawals by requester: %w", err)
	}

	rows, err := l.pool.Query(ctx,
		withdrawalListQuery+`WHERE wr.requester = $1 ORDER BY wr.created_at DESC LIMIT $2 OFFSET $3`,
		requester[:], limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: list withdrawals by requester: %w", err)
	}
	defer rows.Close()

	statuses, err := scanWithdrawalRows(rows)
	if err != nil {
		return nil, 0, err
	}
	return statuses, total, nil
}

func (l *PostgresWithdrawalLister) GetByJunoTxID(ctx context.Context, junoTxID string) ([]WithdrawalStatus, error) {
	rows, err := l.pool.Query(ctx,
		withdrawalListQuery+`WHERE wb.juno_txid = $1 ORDER BY wr.created_at DESC`,
		junoTxID)
	if err != nil {
		return nil, fmt.Errorf("bridgeapi: get withdrawals by juno txid: %w", err)
	}
	defer rows.Close()
	return scanWithdrawalRows(rows)
}

func (l *PostgresWithdrawalLister) GetByBaseTxHash(ctx context.Context, baseTxHash string) ([]WithdrawalStatus, error) {
	rows, err := l.pool.Query(ctx,
		withdrawalListQuery+`WHERE wb.base_tx_hash = $1 ORDER BY wr.created_at DESC`,
		baseTxHash)
	if err != nil {
		return nil, fmt.Errorf("bridgeapi: get withdrawals by base tx hash: %w", err)
	}
	defer rows.Close()
	return scanWithdrawalRows(rows)
}

func (l *PostgresWithdrawalLister) ListRecent(ctx context.Context, limit, offset int) ([]WithdrawalStatus, int, error) {
	var total int
	err := l.pool.QueryRow(ctx, `SELECT COUNT(*) FROM withdrawal_requests`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: count recent withdrawals: %w", err)
	}

	rows, err := l.pool.Query(ctx,
		withdrawalListQuery+`ORDER BY wr.created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("bridgeapi: list recent withdrawals: %w", err)
	}
	defer rows.Close()

	statuses, err := scanWithdrawalRows(rows)
	if err != nil {
		return nil, 0, err
	}
	return statuses, total, nil
}

func scanWithdrawalRows(rows pgx.Rows) ([]WithdrawalStatus, error) {
	var statuses []WithdrawalStatus
	for rows.Next() {
		st, err := scanWithdrawalRow(rows)
		if err != nil {
			return nil, err
		}
		statuses = append(statuses, st)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("bridgeapi: iterate withdrawals: %w", rows.Err())
	}
	return statuses, nil
}

func scanWithdrawalRow(rows pgx.Rows) (WithdrawalStatus, error) {
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

	err := rows.Scan(&idRaw, &requesterRaw, &amount, &feeBps, &recipientUA, &expiry,
		&batchIDRaw, &batchState, &junoTxID, &baseTxHash)
	if err != nil {
		return WithdrawalStatus{}, fmt.Errorf("bridgeapi: scan withdrawal: %w", err)
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
