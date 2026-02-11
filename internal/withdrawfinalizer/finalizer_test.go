package withdrawfinalizer

import (
	"context"
	"crypto/ecdsa"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/leases"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

type recordingSender struct {
	calls   int
	lastReq httpapi.SendRequest
	res     httpapi.SendResponse
	err     error
}

func (s *recordingSender) Send(_ context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error) {
	s.calls++
	s.lastReq = req
	return s.res, s.err
}

type staticProver struct {
	seal     []byte
	gotInput []byte
}

func (p *staticProver) Prove(_ context.Context, _ common.Hash, _ []byte, privateInput []byte) ([]byte, error) {
	p.gotInput = append([]byte(nil), privateInput...)
	return p.seal, nil
}

func mustOperatorKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	return key
}

func mustSignedCheckpoint(t *testing.T, cp checkpoint.Checkpoint) ([]common.Address, [][]byte) {
	t.Helper()
	key := mustOperatorKey(t)
	sig, err := checkpoint.SignDigest(key, checkpoint.Digest(cp))
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return []common.Address{addr}, [][]byte{sig}
}

func TestFinalizer_NoCheckpoint_NoOp(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	leaseStore := leases.NewMemoryStore(nowFn)

	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, "a", 10*time.Second, 1)
	batchID := seq32(0x10)
	_ = store.CreatePlannedBatch(ctx, "a", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID)
	_ = store.SetBatchSigned(ctx, batchID, []byte{0x01})
	_ = store.SetBatchBroadcasted(ctx, batchID, "tx1")
	_ = store.SetBatchConfirmed(ctx, batchID)

	sender := &recordingSender{}
	operatorKey := mustOperatorKey(t)
	f, err := New(Config{
		Owner:             "f1",
		LeaseTTL:          10 * time.Second,
		MaxBatches:        10,
		BaseChainID:       31337,
		BridgeAddress:     common.HexToAddress("0x0000000000000000000000000000000000000123"),
		WithdrawImageID:   common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
		OperatorAddresses: []common.Address{crypto.PubkeyToAddress(operatorKey.PublicKey)},
		OperatorThreshold: 1,
		GasLimit:          123_000,
	}, store, leaseStore, sender, &staticProver{seal: []byte{0x99}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := f.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("expected no send calls, got %d", sender.calls)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateConfirmed {
		t.Fatalf("expected confirmed, got %s", b.State)
	}
}

func TestFinalizer_TickFinalizesConfirmedBatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	leaseStore := leases.NewMemoryStore(nowFn)

	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1000, FeeBps: 50, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, "a", 10*time.Second, 1)
	batchID := seq32(0x10)
	_ = store.CreatePlannedBatch(ctx, "a", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID)
	_ = store.SetBatchSigned(ctx, batchID, []byte{0x01})
	_ = store.SetBatchBroadcasted(ctx, batchID, "tx1")
	_ = store.SetBatchConfirmed(ctx, batchID)

	bridgeAddr := common.HexToAddress("0x0000000000000000000000000000000000000123")
	withdrawImageID := common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02")
	cp := checkpoint.Checkpoint{
		Height:           1,
		BlockHash:        common.Hash{},
		FinalOrchardRoot: common.Hash{},
		BaseChainID:      31337,
		BridgeContract:   bridgeAddr,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	sender := &recordingSender{
		res: httpapi.SendResponse{
			TxHash: "0xabc",
			Receipt: &httpapi.ReceiptResponse{
				Status: 1,
			},
		},
	}
	prover := &staticProver{seal: []byte{0x99}}

	f, err := New(Config{
		Owner:             "f1",
		LeaseTTL:          10 * time.Second,
		MaxBatches:        10,
		BaseChainID:       31337,
		BridgeAddress:     bridgeAddr,
		WithdrawImageID:   withdrawImageID,
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		GasLimit:          123_000,
	}, store, leaseStore, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := f.IngestCheckpoint(ctx, CheckpointPackage{
		Checkpoint:         cp,
		OperatorSignatures: checkpointSigs,
	}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	if err := f.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if sender.calls != 1 {
		t.Fatalf("expected 1 send call, got %d", sender.calls)
	}
	if sender.lastReq.To != bridgeAddr.Hex() {
		t.Fatalf("to: got %s want %s", sender.lastReq.To, bridgeAddr.Hex())
	}
	if sender.lastReq.GasLimit != 123_000 {
		t.Fatalf("gasLimit: got %d want %d", sender.lastReq.GasLimit, 123_000)
	}
	if !strings.HasPrefix(sender.lastReq.Data, "0x") || len(sender.lastReq.Data) <= 2 {
		t.Fatalf("expected calldata hex, got %q", sender.lastReq.Data)
	}
	if len(prover.gotInput) == 0 {
		t.Fatalf("expected prover private input")
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if b.State != withdraw.BatchStateFinalized {
		t.Fatalf("expected finalized, got %s", b.State)
	}
	if b.BaseTxHash != "0xabc" {
		t.Fatalf("base tx hash: got %q want %q", b.BaseTxHash, "0xabc")
	}

	// Lease should be released on success.
	if _, err := leaseStore.Get(ctx, batchLeaseName(batchID)); err == nil {
		t.Fatalf("expected lease to be released")
	}
}

func TestFinalizer_LeaseSkipsBatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	leaseStore := leases.NewMemoryStore(nowFn)

	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = store.UpsertRequested(ctx, w)
	_, _ = store.ClaimUnbatched(ctx, "a", 10*time.Second, 1)
	batchID := seq32(0x10)
	_ = store.CreatePlannedBatch(ctx, "a", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = store.MarkBatchSigning(ctx, batchID)
	_ = store.SetBatchSigned(ctx, batchID, []byte{0x01})
	_ = store.SetBatchBroadcasted(ctx, batchID, "tx1")
	_ = store.SetBatchConfirmed(ctx, batchID)

	// Hold the lease under another owner.
	_, ok, err := leaseStore.TryAcquire(ctx, batchLeaseName(batchID), "other", 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("TryAcquire: ok=%v err=%v", ok, err)
	}

	bridgeAddr := common.HexToAddress("0x0000000000000000000000000000000000000123")
	cp := checkpoint.Checkpoint{BaseChainID: 31337, BridgeContract: bridgeAddr}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)
	sender := &recordingSender{
		res: httpapi.SendResponse{TxHash: "0xabc", Receipt: &httpapi.ReceiptResponse{Status: 1}},
	}

	f, err := New(Config{
		Owner:             "f1",
		LeaseTTL:          10 * time.Second,
		MaxBatches:        10,
		BaseChainID:       31337,
		BridgeAddress:     bridgeAddr,
		WithdrawImageID:   common.Hash{},
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		GasLimit:          123_000,
	}, store, leaseStore, sender, &staticProver{seal: []byte{0x99}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_ = f.IngestCheckpoint(ctx, CheckpointPackage{
		Checkpoint:         cp,
		OperatorSignatures: checkpointSigs,
	})

	if err := f.Tick(ctx); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("expected no send calls, got %d", sender.calls)
	}
}

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}
