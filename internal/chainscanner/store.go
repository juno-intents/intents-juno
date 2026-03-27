package chainscanner

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrInvalidConfig = errors.New("chainscanner: invalid config")

// BlockRef captures canonical chain continuity for a processed height.
type BlockRef struct {
	Height     int64
	Hash       common.Hash
	ParentHash common.Hash
}

// StateStore persists the last-processed block height for each scanner service.
type StateStore interface {
	EnsureSchema(ctx context.Context) error
	GetLastHeight(ctx context.Context, serviceName string) (int64, error)
	SetLastHeight(ctx context.Context, serviceName string, height int64) error
	GetBlockRef(ctx context.Context, serviceName string, height int64) (BlockRef, bool, error)
	StoreBlockRef(ctx context.Context, serviceName string, ref BlockRef) error
	DeleteBlockRefsFromHeight(ctx context.Context, serviceName string, height int64) error
	StageScanData(ctx context.Context, serviceName string, refs []BlockRef, events []WithdrawRequestedEvent, lastHeight int64) error
	ListPendingWithdrawEvents(ctx context.Context, serviceName string, limit int) ([]WithdrawRequestedEvent, error)
	DeletePendingWithdrawEvent(ctx context.Context, serviceName string, event WithdrawRequestedEvent) error
	DeletePendingWithdrawEventsFromHeight(ctx context.Context, serviceName string, height int64) error
}

// PgStateStore implements StateStore backed by Postgres.
type PgStateStore struct {
	pool *pgxpool.Pool
}

// NewPgStateStore creates a new Postgres-backed state store.
func NewPgStateStore(pool *pgxpool.Pool) (*PgStateStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: nil pool", ErrInvalidConfig)
	}
	return &PgStateStore{pool: pool}, nil
}

func (s *PgStateStore) EnsureSchema(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	_, err := s.pool.Exec(ctx, schemaSQL)
	if err != nil {
		return fmt.Errorf("chainscanner: ensure schema: %w", err)
	}
	return nil
}

// GetLastHeight returns the last processed height for the given service.
// Returns 0 if the service has not been seen before.
func (s *PgStateStore) GetLastHeight(ctx context.Context, serviceName string) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return 0, fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	var height int64
	err := s.pool.QueryRow(ctx, `
		SELECT last_processed_height
		FROM event_scanner_state
		WHERE service_name = $1
	`, serviceName).Scan(&height)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, nil
		}
		return 0, fmt.Errorf("chainscanner: get last height: %w", err)
	}
	return height, nil
}

// SetLastHeight upserts the last processed height for the given service.
func (s *PgStateStore) SetLastHeight(ctx context.Context, serviceName string, height int64) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO event_scanner_state (service_name, last_processed_height, last_processed_at)
		VALUES ($1, $2, now())
		ON CONFLICT (service_name) DO UPDATE
		SET last_processed_height = EXCLUDED.last_processed_height,
		    last_processed_at = EXCLUDED.last_processed_at
	`, serviceName, height)
	if err != nil {
		return fmt.Errorf("chainscanner: set last height: %w", err)
	}
	return nil
}

func (s *PgStateStore) GetBlockRef(ctx context.Context, serviceName string, height int64) (BlockRef, bool, error) {
	if s == nil || s.pool == nil {
		return BlockRef{}, false, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return BlockRef{}, false, fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	var hashBytes, parentBytes []byte
	err := s.pool.QueryRow(ctx, `
		SELECT block_hash, parent_hash
		FROM event_scanner_block_refs
		WHERE service_name = $1 AND height = $2
	`, serviceName, height).Scan(&hashBytes, &parentBytes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BlockRef{}, false, nil
		}
		return BlockRef{}, false, fmt.Errorf("chainscanner: get block ref: %w", err)
	}
	if len(hashBytes) != common.HashLength || len(parentBytes) != common.HashLength {
		return BlockRef{}, false, fmt.Errorf("chainscanner: invalid block ref hash length")
	}

	var ref BlockRef
	ref.Height = height
	copy(ref.Hash[:], hashBytes)
	copy(ref.ParentHash[:], parentBytes)
	return ref, true, nil
}

func (s *PgStateStore) StoreBlockRef(ctx context.Context, serviceName string, ref BlockRef) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	if ref.Height <= 0 {
		return fmt.Errorf("%w: invalid block height", ErrInvalidConfig)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO event_scanner_block_refs (service_name, height, block_hash, parent_hash, processed_at)
		VALUES ($1, $2, $3, $4, now())
		ON CONFLICT (service_name, height) DO UPDATE
		SET block_hash = EXCLUDED.block_hash,
		    parent_hash = EXCLUDED.parent_hash,
		    processed_at = EXCLUDED.processed_at
	`, serviceName, ref.Height, ref.Hash[:], ref.ParentHash[:])
	if err != nil {
		return fmt.Errorf("chainscanner: store block ref: %w", err)
	}
	return nil
}

func (s *PgStateStore) DeleteBlockRefsFromHeight(ctx context.Context, serviceName string, height int64) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	_, err := s.pool.Exec(ctx, `
		DELETE FROM event_scanner_block_refs
		WHERE service_name = $1 AND height >= $2
	`, serviceName, height)
	if err != nil {
		return fmt.Errorf("chainscanner: delete block refs: %w", err)
	}
	return nil
}

func (s *PgStateStore) StageScanData(ctx context.Context, serviceName string, refs []BlockRef, events []WithdrawRequestedEvent, lastHeight int64) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	if lastHeight < 0 {
		return fmt.Errorf("%w: invalid block height", ErrInvalidConfig)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("chainscanner: begin stage scan tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, ref := range refs {
		if ref.Height <= 0 {
			return fmt.Errorf("%w: invalid block height", ErrInvalidConfig)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO event_scanner_block_refs (service_name, height, block_hash, parent_hash, processed_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (service_name, height) DO UPDATE
			SET block_hash = EXCLUDED.block_hash,
			    parent_hash = EXCLUDED.parent_hash,
			    processed_at = EXCLUDED.processed_at
		`, serviceName, ref.Height, ref.Hash[:], ref.ParentHash[:]); err != nil {
			return fmt.Errorf("chainscanner: stage block ref: %w", err)
		}
	}

	for _, event := range events {
		amount := "0"
		if event.Amount != nil {
			amount = event.Amount.String()
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO event_scanner_pending_withdraw_events (
				service_name,
				withdrawal_id,
				requester,
				amount_decimal,
				recipient_ua,
				expiry,
				fee_bps,
				block_number,
				block_hash,
				tx_hash,
				log_index,
				finality_source,
				staged_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
			ON CONFLICT (service_name, tx_hash, log_index) DO NOTHING
		`,
			serviceName,
			event.WithdrawalID[:],
			event.Requester[:],
			amount,
			event.RecipientUA,
			int64(event.Expiry),
			int64(event.FeeBps),
			int64(event.BlockNumber),
			event.BlockHash[:],
			event.TxHash[:],
			int64(event.LogIndex),
			event.FinalitySource,
		); err != nil {
			return fmt.Errorf("chainscanner: stage withdraw event: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO event_scanner_state (service_name, last_processed_height, last_processed_at)
		VALUES ($1, $2, now())
		ON CONFLICT (service_name) DO UPDATE
		SET last_processed_height = EXCLUDED.last_processed_height,
		    last_processed_at = EXCLUDED.last_processed_at
	`, serviceName, lastHeight); err != nil {
		return fmt.Errorf("chainscanner: stage last height: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("chainscanner: commit stage scan tx: %w", err)
	}
	return nil
}

func (s *PgStateStore) ListPendingWithdrawEvents(ctx context.Context, serviceName string, limit int) ([]WithdrawRequestedEvent, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return nil, fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}
	if limit <= 0 {
		limit = 1000
	}

	rows, err := s.pool.Query(ctx, `
		SELECT
			withdrawal_id,
			requester,
			amount_decimal,
			recipient_ua,
			expiry,
			fee_bps,
			block_number,
			block_hash,
			tx_hash,
			log_index,
			finality_source
		FROM event_scanner_pending_withdraw_events
		WHERE service_name = $1
		ORDER BY block_number ASC, log_index ASC
		LIMIT $2
	`, serviceName, limit)
	if err != nil {
		return nil, fmt.Errorf("chainscanner: list pending withdraw events: %w", err)
	}
	defer rows.Close()

	events := make([]WithdrawRequestedEvent, 0)
	for rows.Next() {
		var (
			withdrawalIDBytes []byte
			requesterBytes    []byte
			amountDecimal     string
			recipientUA       []byte
			expiry            int64
			feeBps            int64
			blockNumber       int64
			blockHashBytes    []byte
			txHashBytes       []byte
			logIndex          int64
			finalitySource    string
		)
		if err := rows.Scan(
			&withdrawalIDBytes,
			&requesterBytes,
			&amountDecimal,
			&recipientUA,
			&expiry,
			&feeBps,
			&blockNumber,
			&blockHashBytes,
			&txHashBytes,
			&logIndex,
			&finalitySource,
		); err != nil {
			return nil, fmt.Errorf("chainscanner: scan pending withdraw event: %w", err)
		}

		amount, ok := new(big.Int).SetString(amountDecimal, 10)
		if !ok {
			return nil, fmt.Errorf("chainscanner: invalid staged amount %q", amountDecimal)
		}

		var event WithdrawRequestedEvent
		if len(withdrawalIDBytes) != 32 || len(blockHashBytes) != common.HashLength || len(txHashBytes) != common.HashLength || len(requesterBytes) != common.AddressLength {
			return nil, fmt.Errorf("chainscanner: invalid staged withdraw event lengths")
		}
		copy(event.WithdrawalID[:], withdrawalIDBytes)
		copy(event.Requester[:], requesterBytes)
		event.Amount = amount
		event.RecipientUA = append([]byte(nil), recipientUA...)
		event.Expiry = uint64(expiry)
		event.FeeBps = uint64(feeBps)
		event.BlockNumber = uint64(blockNumber)
		copy(event.BlockHash[:], blockHashBytes)
		copy(event.TxHash[:], txHashBytes)
		event.LogIndex = uint(logIndex)
		event.FinalitySource = finalitySource
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("chainscanner: iterate pending withdraw events: %w", err)
	}
	return events, nil
}

func (s *PgStateStore) DeletePendingWithdrawEvent(ctx context.Context, serviceName string, event WithdrawRequestedEvent) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	if _, err := s.pool.Exec(ctx, `
		DELETE FROM event_scanner_pending_withdraw_events
		WHERE service_name = $1 AND tx_hash = $2 AND log_index = $3
	`, serviceName, event.TxHash[:], int64(event.LogIndex)); err != nil {
		return fmt.Errorf("chainscanner: delete pending withdraw event: %w", err)
	}
	return nil
}

func (s *PgStateStore) DeletePendingWithdrawEventsFromHeight(ctx context.Context, serviceName string, height int64) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("%w: nil store", ErrInvalidConfig)
	}
	if serviceName == "" {
		return fmt.Errorf("%w: empty service name", ErrInvalidConfig)
	}

	if _, err := s.pool.Exec(ctx, `
		DELETE FROM event_scanner_pending_withdraw_events
		WHERE service_name = $1 AND block_number >= $2
	`, serviceName, height); err != nil {
		return fmt.Errorf("chainscanner: delete pending withdraw events: %w", err)
	}
	return nil
}

var _ StateStore = (*PgStateStore)(nil)
