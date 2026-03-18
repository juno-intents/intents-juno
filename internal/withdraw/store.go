package withdraw

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	ErrNotFound           = errors.New("withdraw: not found")
	ErrWithdrawalMismatch = errors.New("withdraw: withdrawal mismatch")
	ErrBatchMismatch      = errors.New("withdraw: batch mismatch")
	ErrInvalidTransition  = errors.New("withdraw: invalid transition")
)

type Fence struct {
	Owner        string
	LeaseVersion int64
}

func (f Fence) Validate() error {
	if f.Owner == "" || f.LeaseVersion <= 0 {
		return ErrInvalidConfig
	}
	return nil
}

type BatchState uint8

const (
	BatchStateUnknown BatchState = iota
	BatchStatePlanned
	BatchStateSigning
	BatchStateSigned
	BatchStateBroadcasted
	BatchStateConfirmed
	BatchStateFinalizing
	BatchStateFinalized
)

func (s BatchState) String() string {
	switch s {
	case BatchStatePlanned:
		return "planned"
	case BatchStateSigning:
		return "signing"
	case BatchStateSigned:
		return "signed"
	case BatchStateBroadcasted:
		return "broadcasted"
	case BatchStateConfirmed:
		return "confirmed"
	case BatchStateFinalizing:
		return "finalizing"
	case BatchStateFinalized:
		return "finalized"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

type WithdrawalStatus uint8

const (
	WithdrawalStatusUnknown WithdrawalStatus = iota
	WithdrawalStatusRequested
	WithdrawalStatusBatched
	WithdrawalStatusPaid
	WithdrawalStatusRefunded
)

func (s WithdrawalStatus) String() string {
	switch s {
	case WithdrawalStatusRequested:
		return "requested"
	case WithdrawalStatusBatched:
		return "batched"
	case WithdrawalStatusPaid:
		return "paid"
	case WithdrawalStatusRefunded:
		return "refunded"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// Batch is the durable coordination unit for grouped withdrawals.
type Batch struct {
	ID            [32]byte
	WithdrawalIDs [][32]byte // sorted ascending, unique

	State BatchState

	LeaseOwner   string
	LeaseVersion int64

	// TxPlan is a versioned JSON blob (juno-txbuild-like boundary).
	TxPlan []byte

	// SignedTx is the raw signed tx bytes (persisted before broadcast).
	SignedTx []byte

	// BroadcastLockedAt records when the coordinator committed to this exact
	// signed transaction. Once set, the batch may only reuse the persisted
	// SignedTx and may not be replanned.
	BroadcastLockedAt time.Time

	// JunoTxID is the network txid (natural idempotency key for broadcast).
	JunoTxID string

	// JunoConfirmedAt records when the Juno tx was observed confirmed, before
	// Base-side mark-paid/finalization succeeds.
	JunoConfirmedAt time.Time

	// BaseTxHash is the Base tx hash for finalizeWithdrawBatch.
	BaseTxHash string

	// RebroadcastAttempts tracks how many broadcast-tx-missing recovery cycles were attempted.
	RebroadcastAttempts uint32
	// NextRebroadcastAt is the earliest instant the coordinator may attempt another rebroadcast cycle.
	NextRebroadcastAt time.Time

	FailureCount     int
	LastFailureStage string
	LastErrorCode    string
	LastErrorMessage string
	LastFailedAt     time.Time
	DLQAt            time.Time

	MarkPaidFailures int
	LastMarkPaidError string
}

type Store interface {
	UpsertRequested(ctx context.Context, w Withdrawal) (Withdrawal, bool, error)
	ClaimUnbatched(ctx context.Context, fence Fence, ttl time.Duration, max int) ([]Withdrawal, error)
	CreatePlannedBatch(ctx context.Context, fence Fence, b Batch) error

	GetWithdrawal(ctx context.Context, id [32]byte) (Withdrawal, error)
	GetWithdrawalStatus(ctx context.Context, id [32]byte) (WithdrawalStatus, error)
	GetBatch(ctx context.Context, batchID [32]byte) (Batch, error)
	ListBatchesByState(ctx context.Context, state BatchState) ([]Batch, error)

	AdoptBatch(ctx context.Context, batchID [32]byte, fence Fence) error
	MarkBatchSigning(ctx context.Context, batchID [32]byte, fence Fence) error
	ResetBatchSigning(ctx context.Context, batchID [32]byte, fence Fence, txPlan []byte) error
	SetBatchSigned(ctx context.Context, batchID [32]byte, fence Fence, signedTx []byte) error
	MarkBatchBroadcastLocked(ctx context.Context, batchID [32]byte, fence Fence) error
	SetBatchBroadcasted(ctx context.Context, batchID [32]byte, fence Fence, txid string) error
	// ResetBatchPlanned discards stale signed/broadcast metadata and returns a batch
	// to planned so it can be re-signed with a fresh tx plan.
	ResetBatchPlanned(ctx context.Context, batchID [32]byte, fence Fence, txPlan []byte) error
	SetBatchRebroadcastBackoff(ctx context.Context, batchID [32]byte, fence Fence, attempts uint32, next time.Time) error
	MarkBatchJunoConfirmed(ctx context.Context, batchID [32]byte, fence Fence) error
	RecordBatchFailure(ctx context.Context, batchID [32]byte, fence Fence, stage string, errorCode string, errorMessage string) (Batch, error)
	RecordBatchMarkPaidFailure(ctx context.Context, batchID [32]byte, fence Fence, errorMessage string) (Batch, error)
	ResetBatchMarkPaidFailures(ctx context.Context, batchID [32]byte, fence Fence) error
	MarkBatchDLQ(ctx context.Context, batchID [32]byte, fence Fence) error
	SetBatchConfirmed(ctx context.Context, batchID [32]byte, fence Fence) error
	MarkBatchFinalizing(ctx context.Context, batchID [32]byte, fence Fence) error
	SetBatchFinalized(ctx context.Context, batchID [32]byte, fence Fence, baseTxHash string) error
}
