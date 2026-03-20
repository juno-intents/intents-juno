package deposit

import (
	"context"
	"errors"
	"time"

	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

var (
	ErrNotFound          = errors.New("deposit: not found")
	ErrDepositMismatch   = errors.New("deposit: deposit mismatch")
	ErrInvalidTransition = errors.New("deposit: invalid transition")
)

type Store interface {
	UpsertSeen(ctx context.Context, d Deposit) (Job, bool, error)
	UpsertConfirmed(ctx context.Context, d Deposit) (Job, bool, error)
	PromoteSeenToConfirmed(ctx context.Context, tipHeight int64, minConfirmations int64, limit int) ([]Job, error)
	Get(ctx context.Context, depositID [32]byte) (Job, error)
	GetBatch(ctx context.Context, batchID [32]byte) (Batch, error)
	ListByState(ctx context.Context, state State, limit int) ([]Job, error)
	CountByState(ctx context.Context, state State) (int, error)
	ClaimConfirmed(ctx context.Context, owner string, ttl time.Duration, limit int) ([]Job, error)
	ClaimSubmittedAttempts(ctx context.Context, owner string, ttl time.Duration, limit int) ([]SubmittedBatchAttempt, error)
	ClaimBatches(ctx context.Context, owner string, ttl time.Duration, states []BatchState, olderThan time.Time, limit int) ([]Batch, error)
	PrepareNextBatch(
		ctx context.Context,
		owner string,
		ttl time.Duration,
		nextBatchID [32]byte,
		maxItems int,
		maxAge time.Duration,
		limit int,
		now time.Time,
	) (Batch, bool, error)
	SplitBatch(ctx context.Context, owner string, batchID [32]byte, nextBatchID [32]byte, movedDepositIDs [][32]byte) (Batch, Batch, error)

	MarkProofRequested(ctx context.Context, depositID [32]byte, cp checkpoint.Checkpoint) error
	MarkBatchProofRequested(ctx context.Context, owner string, batchID [32]byte, cp checkpoint.Checkpoint) (Batch, error)
	MarkBatchProofReady(ctx context.Context, owner string, batchID [32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) (Batch, error)
	SetProofReady(ctx context.Context, depositID [32]byte, seal []byte) error
	MarkFinalized(ctx context.Context, depositID [32]byte, txHash [32]byte) error
	RepairFinalized(ctx context.Context, depositID [32]byte, txHash [32]byte) error
	MarkRejected(ctx context.Context, depositID [32]byte, reason string, txHash [32]byte) error
	FailBatch(ctx context.Context, owner string, batchID [32]byte, reason string, rejectedIDs [][32]byte) error
	MarkBatchSubmitted(ctx context.Context, owner string, batchID [32]byte, depositIDs [][32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) (SubmittedBatchAttempt, error)
	RequeueSubmittedBatch(ctx context.Context, batchID [32]byte) error
	ResetBatch(ctx context.Context, owner string, batchID [32]byte) (Batch, error)
	SetBatchSubmissionTxHash(ctx context.Context, batchID [32]byte, txHash [32]byte) error
	// FinalizeBatch atomically transitions the provided deposits to finalized.
	// Implementations must ensure all-or-nothing behavior for this batch call.
	FinalizeBatch(ctx context.Context, depositIDs [][32]byte, cp checkpoint.Checkpoint, seal []byte, txHash [32]byte) error
	ApplyBatchOutcome(ctx context.Context, batchID [32]byte, txHash [32]byte, finalizedIDs [][32]byte, rejectedIDs [][32]byte, rejectionReason string) error
}
