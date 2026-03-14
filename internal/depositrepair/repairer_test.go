package depositrepair

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type stubRepairStore struct {
	txHashes   [][32]byte
	depositIDs map[[32]byte][][32]byte

	appliedTxHash    [32]byte
	appliedFinalized [][32]byte
	appliedRejected  [][32]byte
	appliedReason    string
}

func (s *stubRepairStore) ListTxHashes(context.Context, int) ([][32]byte, error) {
	return s.txHashes, nil
}

func (s *stubRepairStore) ListDepositIDsByTxHash(_ context.Context, txHash [32]byte) ([][32]byte, error) {
	return s.depositIDs[txHash], nil
}

func (s *stubRepairStore) ApplyTxHashOutcome(_ context.Context, txHash [32]byte, finalizedIDs [][32]byte, rejectedIDs [][32]byte, rejectionReason string) error {
	s.appliedTxHash = txHash
	s.appliedFinalized = append([][32]byte(nil), finalizedIDs...)
	s.appliedRejected = append([][32]byte(nil), rejectedIDs...)
	s.appliedReason = rejectionReason
	return nil
}

type stubRepairReceiptReader struct {
	receipt *types.Receipt
	err     error
}

func (s *stubRepairReceiptReader) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.receipt, nil
}

func TestRepairer_RepairTxHash_AppliesMixedBatchOutcome(t *testing.T) {
	t.Parallel()

	txHash := seq32Repair(0x10)
	depositA := seq32Repair(0x11)
	depositB := seq32Repair(0x12)
	bridge := common.HexToAddress("0x0000000000000000000000000000000000000abc")

	store := &stubRepairStore{
		txHashes: [][32]byte{txHash},
		depositIDs: map[[32]byte][][32]byte{
			txHash: {depositA, depositB},
		},
	}
	reader := &stubRepairReceiptReader{
		receipt: &types.Receipt{
			Status: types.ReceiptStatusSuccessful,
			Logs: []*types.Log{
				{Address: bridge, Topics: []common.Hash{
					crypto.Keccak256Hash([]byte("Minted(bytes32,address,uint256,uint256,uint256)")),
					common.BytesToHash(depositA[:]),
				}},
				{Address: bridge, Topics: []common.Hash{
					crypto.Keccak256Hash([]byte("DepositSkipped(bytes32)")),
					common.BytesToHash(depositB[:]),
				}},
			},
		},
	}
	repairer, err := New(store, reader, bridge)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := repairer.RepairTxHash(context.Background(), txHash)
	if err != nil {
		t.Fatalf("RepairTxHash: %v", err)
	}
	if result.FinalizedCount != 1 || result.RejectedCount != 1 || result.UnresolvedCount != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(store.appliedFinalized) != 1 || store.appliedFinalized[0] != depositA {
		t.Fatalf("finalized ids = %x, want %x", store.appliedFinalized, depositA)
	}
	if len(store.appliedRejected) != 1 || store.appliedRejected[0] != depositB {
		t.Fatalf("rejected ids = %x, want %x", store.appliedRejected, depositB)
	}
	if store.appliedReason != "deposit skipped by bridge" {
		t.Fatalf("rejection reason = %q", store.appliedReason)
	}
}

func TestRepairer_RepairTxHash_PropagatesReceiptErrors(t *testing.T) {
	t.Parallel()

	txHash := seq32Repair(0x20)
	store := &stubRepairStore{
		depositIDs: map[[32]byte][][32]byte{
			txHash: {seq32Repair(0x21)},
		},
	}
	reader := &stubRepairReceiptReader{err: errors.New("rpc down")}
	repairer, err := New(store, reader, common.HexToAddress("0x0000000000000000000000000000000000000abc"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := repairer.RepairTxHash(context.Background(), txHash); err == nil {
		t.Fatalf("expected error")
	}
}

func seq32Repair(b byte) [32]byte {
	var out [32]byte
	out[31] = b
	return out
}
