package depositrepair

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
)

type ReceiptReader interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
}

type Store interface {
	ListTxHashes(ctx context.Context, limit int) ([][32]byte, error)
	ListDepositIDsByTxHash(ctx context.Context, txHash [32]byte) ([][32]byte, error)
	ApplyTxHashOutcome(ctx context.Context, txHash [32]byte, finalizedIDs [][32]byte, rejectedIDs [][32]byte, rejectionReason string) error
}

type Repairer struct {
	store   Store
	receipts ReceiptReader
	bridge  common.Address
}

type Result struct {
	TxHash          [32]byte
	DepositCount    int
	FinalizedCount  int
	RejectedCount   int
	UnresolvedCount int
}

func New(store Store, receipts ReceiptReader, bridge common.Address) (*Repairer, error) {
	if store == nil || receipts == nil || bridge == (common.Address{}) {
		return nil, fmt.Errorf("depositrepair: invalid config")
	}
	return &Repairer{
		store:   store,
		receipts: receipts,
		bridge:  bridge,
	}, nil
}

func (r *Repairer) RepairAll(ctx context.Context, limit int) ([]Result, error) {
	txHashes, err := r.store.ListTxHashes(ctx, limit)
	if err != nil {
		return nil, err
	}
	results := make([]Result, 0, len(txHashes))
	for _, txHash := range txHashes {
		result, err := r.RepairTxHash(ctx, txHash)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return results, nil
}

func (r *Repairer) RepairTxHash(ctx context.Context, txHash [32]byte) (Result, error) {
	depositIDs, err := r.store.ListDepositIDsByTxHash(ctx, txHash)
	if err != nil {
		return Result{}, err
	}
	result := Result{
		TxHash:       txHash,
		DepositCount: len(depositIDs),
	}
	if len(depositIDs) == 0 {
		return result, nil
	}

	receipt, err := r.receipts.TransactionReceipt(ctx, common.Hash(txHash))
	if err != nil {
		return Result{}, fmt.Errorf("depositrepair: fetch receipt: %w", err)
	}
	if receipt == nil {
		return Result{}, fmt.Errorf("depositrepair: missing receipt")
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return Result{}, fmt.Errorf("depositrepair: receipt reverted")
	}

	finalizedIDs, rejectedIDs, err := bridgeabi.DecodeMintBatchLogOutcomes(receipt.Logs, r.bridge)
	if err != nil {
		return Result{}, fmt.Errorf("depositrepair: decode receipt logs: %w", err)
	}
	if err := r.store.ApplyTxHashOutcome(ctx, txHash, finalizedIDs, rejectedIDs, "deposit skipped by bridge"); err != nil {
		return Result{}, err
	}
	result.FinalizedCount = len(finalizedIDs)
	result.RejectedCount = len(rejectedIDs)
	result.UnresolvedCount = len(unresolvedDepositIDs(depositIDs, finalizedIDs, rejectedIDs))
	return result, nil
}

func unresolvedDepositIDs(expected, finalized, rejected [][32]byte) [][32]byte {
	finalizedSet := make(map[[32]byte]struct{}, len(finalized))
	for _, id := range finalized {
		finalizedSet[id] = struct{}{}
	}
	rejectedSet := make(map[[32]byte]struct{}, len(rejected))
	for _, id := range rejected {
		rejectedSet[id] = struct{}{}
	}
	out := make([][32]byte, 0, len(expected))
	for _, id := range expected {
		if _, ok := finalizedSet[id]; ok {
			continue
		}
		if _, ok := rejectedSet[id]; ok {
			continue
		}
		out = append(out, id)
	}
	return out
}
