package deposit

import (
	"context"
	"errors"

	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

var (
	ErrNotFound          = errors.New("deposit: not found")
	ErrDepositMismatch   = errors.New("deposit: deposit mismatch")
	ErrInvalidTransition = errors.New("deposit: invalid transition")
)

type Store interface {
	UpsertConfirmed(ctx context.Context, d Deposit) (Job, bool, error)
	Get(ctx context.Context, depositID [32]byte) (Job, error)
	ListByState(ctx context.Context, state State, limit int) ([]Job, error)

	MarkProofRequested(ctx context.Context, depositID [32]byte, cp checkpoint.Checkpoint) error
	SetProofReady(ctx context.Context, depositID [32]byte, seal []byte) error
	MarkFinalized(ctx context.Context, depositID [32]byte, txHash [32]byte) error
}
