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

type BatchState uint8

const (
	BatchStateUnknown BatchState = iota
	BatchStatePlanned
	BatchStateSigning
	BatchStateSigned
	BatchStateBroadcasted
	BatchStateConfirmed
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
	case BatchStateFinalized:
		return "finalized"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// Batch is the durable coordination unit for grouped withdrawals.
type Batch struct {
	ID            [32]byte
	WithdrawalIDs [][32]byte // sorted ascending, unique

	State BatchState

	// TxPlan is a versioned JSON blob (juno-txbuild-like boundary).
	TxPlan []byte

	// SignedTx is the raw signed tx bytes (persisted before broadcast).
	SignedTx []byte

	// JunoTxID is the network txid (natural idempotency key for broadcast).
	JunoTxID string

	// BaseTxHash is the Base tx hash for finalizeWithdrawBatch.
	BaseTxHash string
}

type Store interface {
	UpsertRequested(ctx context.Context, w Withdrawal) (Withdrawal, bool, error)
	ClaimUnbatched(ctx context.Context, owner string, ttl time.Duration, max int) ([]Withdrawal, error)
	CreatePlannedBatch(ctx context.Context, owner string, b Batch) error

	GetWithdrawal(ctx context.Context, id [32]byte) (Withdrawal, error)
	GetBatch(ctx context.Context, batchID [32]byte) (Batch, error)
	ListBatchesByState(ctx context.Context, state BatchState) ([]Batch, error)

	MarkBatchSigning(ctx context.Context, batchID [32]byte) error
	SetBatchSigned(ctx context.Context, batchID [32]byte, signedTx []byte) error
	SetBatchBroadcasted(ctx context.Context, batchID [32]byte, txid string) error
	ResetBatchPlanned(ctx context.Context, batchID [32]byte, txPlan []byte) error
	SetBatchConfirmed(ctx context.Context, batchID [32]byte) error
	SetBatchFinalized(ctx context.Context, batchID [32]byte, baseTxHash string) error
}
