package tsshost

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/juno-intents/intents-juno/internal/tss"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

var ErrRejected = errors.New("tsshost: rejected sign request")

type withdrawBatchReader interface {
	GetBatch(ctx context.Context, batchID [32]byte) (withdraw.Batch, error)
	GetWithdrawal(ctx context.Context, id [32]byte) (withdraw.Withdrawal, error)
}

type withdrawBatchVerifier struct {
	store withdrawBatchReader
}

func NewWithdrawBatchVerifier(store withdrawBatchReader) Verifier {
	if store == nil {
		return nil
	}
	return &withdrawBatchVerifier{store: store}
}

func (v *withdrawBatchVerifier) VerifySignRequest(ctx context.Context, sessionID [32]byte, batchID [32]byte, txPlan []byte) error {
	if v == nil || v.store == nil {
		return nil
	}
	batch, err := v.store.GetBatch(ctx, batchID)
	if err != nil {
		if errors.Is(err, withdraw.ErrNotFound) {
			return fmt.Errorf("%w: batch not found", ErrRejected)
		}
		return err
	}
	if !isSignableBatchState(batch.State) {
		return fmt.Errorf("%w: batch state %s is not signable", ErrRejected, batch.State)
	}
	if len(batch.WithdrawalIDs) == 0 {
		return fmt.Errorf("%w: batch has no withdrawal ids", ErrRejected)
	}
	if !bytes.Equal(batch.TxPlan, txPlan) {
		return fmt.Errorf("%w: tx plan does not match persisted batch", ErrRejected)
	}
	expectedSessionID := tss.DeriveSigningSessionID(batchID, txPlan)
	if sessionID != expectedSessionID {
		return fmt.Errorf("%w: session id does not match batch binding", ErrRejected)
	}
	for _, withdrawalID := range batch.WithdrawalIDs {
		if _, err := v.store.GetWithdrawal(ctx, withdrawalID); err != nil {
			if errors.Is(err, withdraw.ErrNotFound) {
				return fmt.Errorf("%w: withdrawal %x missing from persisted batch", ErrRejected, withdrawalID[:4])
			}
			return err
		}
	}
	return nil
}

func isSignableBatchState(state withdraw.BatchState) bool {
	switch state {
	case withdraw.BatchStatePlanned, withdraw.BatchStateSigning, withdraw.BatchStateSigned:
		return true
	default:
		return false
	}
}
