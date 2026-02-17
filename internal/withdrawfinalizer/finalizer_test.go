package withdrawfinalizer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/leases"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/proverinput"
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

type staticProofRequester struct {
	res    proofclient.Result
	gotReq proofclient.Request
}

func (p *staticProofRequester) RequestProof(_ context.Context, req proofclient.Request) (proofclient.Result, error) {
	p.gotReq = req
	p.gotReq.Journal = append([]byte(nil), req.Journal...)
	p.gotReq.PrivateInput = append([]byte(nil), req.PrivateInput...)
	return p.res, nil
}

type recordingBlobPut struct {
	key     string
	payload []byte
	opts    blobstore.PutOptions
}

type recordingBlobStore struct {
	puts   []recordingBlobPut
	putErr error
}

func (s *recordingBlobStore) Put(_ context.Context, key string, payload []byte, opts blobstore.PutOptions) error {
	if s.putErr != nil {
		return s.putErr
	}
	s.puts = append(s.puts, recordingBlobPut{
		key:     key,
		payload: append([]byte(nil), payload...),
		opts:    opts,
	})
	return nil
}

func (s *recordingBlobStore) Get(context.Context, string) (blobstore.Object, error) {
	return blobstore.Object{}, errors.New("unexpected Get")
}

func (s *recordingBlobStore) Delete(context.Context, string) error { return nil }

func (s *recordingBlobStore) Exists(context.Context, string) (bool, error) { return false, nil }

type failSetFinalizedStore struct {
	withdraw.Store
	err error
}

func (s *failSetFinalizedStore) SetBatchFinalized(context.Context, [32]byte, string) error {
	return s.err
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
	}, store, leaseStore, sender, &staticProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}, nil)
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
	prover := &staticProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}
	artifacts := &recordingBlobStore{}

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
	f.WithBlobStore(artifacts)

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
	if len(prover.gotReq.PrivateInput) == 0 {
		t.Fatalf("expected proof requester private input")
	}
	if got, want := prover.gotReq.Pipeline, "withdraw"; got != want {
		t.Fatalf("proof pipeline: got %q want %q", got, want)
	}
	if prover.gotReq.JobID == (common.Hash{}) {
		t.Fatalf("expected non-zero proof job id")
	}
	wantJournalKey := journalArtifactKey(batchID)
	wantPrivateInputKey := privateInputArtifactKey(batchID)
	wantSealKey := sealArtifactKey(batchID)
	var sawJournal, sawPrivateInput, sawSeal bool
	for _, p := range artifacts.puts {
		switch p.key {
		case wantJournalKey:
			sawJournal = true
		case wantPrivateInputKey:
			sawPrivateInput = true
		case wantSealKey:
			sawSeal = true
		}
	}
	if !sawJournal {
		t.Fatalf("expected journal artifact key %q", wantJournalKey)
	}
	if !sawPrivateInput {
		t.Fatalf("expected private input artifact key %q", wantPrivateInputKey)
	}
	if !sawSeal {
		t.Fatalf("expected seal artifact key %q", wantSealKey)
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

func TestFinalizer_FailsWhenProofArtifactPersistenceFails(t *testing.T) {
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
	prover := &staticProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}
	artifacts := &recordingBlobStore{putErr: errors.New("s3 unavailable")}

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
	f.WithBlobStore(artifacts)

	err = f.IngestCheckpoint(ctx, CheckpointPackage{
		Checkpoint:         cp,
		OperatorSignatures: checkpointSigs,
	})
	if err == nil {
		t.Fatalf("expected IngestCheckpoint error")
	}
	if !strings.Contains(err.Error(), "persist proof journal artifact") {
		t.Fatalf("expected artifact error, got %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("expected no submit on artifact failure, got %d calls", sender.calls)
	}
}

func TestFinalizer_SetBatchFinalizedFailureLeavesBatchFinalizing(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	baseStore := withdraw.NewMemoryStore(nowFn)
	store := &failSetFinalizedStore{
		Store: baseStore,
		err:   errors.New("db unavailable"),
	}
	leaseStore := leases.NewMemoryStore(nowFn)

	ctx := context.Background()

	w := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1000, FeeBps: 50, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = baseStore.UpsertRequested(ctx, w)
	_, _ = baseStore.ClaimUnbatched(ctx, "a", 10*time.Second, 1)
	batchID := seq32(0x10)
	_ = baseStore.CreatePlannedBatch(ctx, "a", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	})
	_ = baseStore.MarkBatchSigning(ctx, batchID)
	_ = baseStore.SetBatchSigned(ctx, batchID, []byte{0x01})
	_ = baseStore.SetBatchBroadcasted(ctx, batchID, "tx1")
	_ = baseStore.SetBatchConfirmed(ctx, batchID)

	bridgeAddr := common.HexToAddress("0x0000000000000000000000000000000000000123")
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
	prover := &staticProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	f, err := New(Config{
		Owner:             "f1",
		LeaseTTL:          10 * time.Second,
		MaxBatches:        10,
		BaseChainID:       31337,
		BridgeAddress:     bridgeAddr,
		WithdrawImageID:   common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		GasLimit:          123_000,
	}, store, leaseStore, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = f.IngestCheckpoint(ctx, CheckpointPackage{
		Checkpoint:         cp,
		OperatorSignatures: checkpointSigs,
	})
	if err == nil {
		t.Fatalf("expected IngestCheckpoint error")
	}
	if sender.calls != 1 {
		t.Fatalf("expected one send call, got %d", sender.calls)
	}

	b, err := baseStore.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if got, want := b.State, withdraw.BatchStateFinalizing; got != want {
		t.Fatalf("state: got %s want %s", got, want)
	}
}

func TestFinalizer_TickResumesFinalizingBatch(t *testing.T) {
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
	_ = store.MarkBatchFinalizing(ctx, batchID)

	bridgeAddr := common.HexToAddress("0x0000000000000000000000000000000000000123")
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
	prover := &staticProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	f, err := New(Config{
		Owner:             "f1",
		LeaseTTL:          10 * time.Second,
		MaxBatches:        10,
		BaseChainID:       31337,
		BridgeAddress:     bridgeAddr,
		WithdrawImageID:   common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
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
		t.Fatalf("expected one send call, got %d", sender.calls)
	}

	b, err := store.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if got, want := b.State, withdraw.BatchStateFinalized; got != want {
		t.Fatalf("state: got %s want %s", got, want)
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
	}, store, leaseStore, sender, &staticProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}, nil)
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

func TestFinalizer_UsesBinaryGuestInputWhenConfigured(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	leaseStore := leases.NewMemoryStore(nowFn)
	ctx := context.Background()

	witness := bytes.Repeat([]byte{0x66}, proverinput.WithdrawWitnessItemLen)
	w := withdraw.Withdrawal{
		ID:               seq32(0x00),
		Amount:           1000,
		FeeBps:           50,
		RecipientUA:      []byte{0x01},
		Expiry:           now.Add(24 * time.Hour),
		ProofWitnessItem: witness,
	}
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
	cp := checkpoint.Checkpoint{
		Height:           1,
		BlockHash:        common.Hash{},
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   bridgeAddr,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)
	sender := &recordingSender{
		res: httpapi.SendResponse{TxHash: "0xabc", Receipt: &httpapi.ReceiptResponse{Status: 1}},
	}
	prover := &staticProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	var ovk [32]byte
	for i := range ovk {
		ovk[i] = byte(0x80 + i)
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
		OWalletOVKBytes:   ovk[:],
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

	wantInput, err := proverinput.EncodeWithdrawGuestPrivateInput(cp, ovk, [][]byte{witness})
	if err != nil {
		t.Fatalf("EncodeWithdrawGuestPrivateInput: %v", err)
	}
	if !bytes.Equal(prover.gotReq.PrivateInput, wantInput) {
		t.Fatalf("proof requester private input mismatch")
	}
}

func TestFinalizer_ErrorsWhenGuestInputConfiguredButWitnessMissing(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	store := withdraw.NewMemoryStore(nowFn)
	leaseStore := leases.NewMemoryStore(nowFn)
	ctx := context.Background()

	w := withdraw.Withdrawal{
		ID:          seq32(0x00),
		Amount:      1000,
		FeeBps:      50,
		RecipientUA: []byte{0x01},
		Expiry:      now.Add(24 * time.Hour),
	}
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
	cp := checkpoint.Checkpoint{
		Height:           1,
		BlockHash:        common.Hash{},
		FinalOrchardRoot: common.Hash{},
		BaseChainID:      31337,
		BridgeContract:   bridgeAddr,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var ovk [32]byte
	ovk[0] = 0x01

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
		OWalletOVKBytes:   ovk[:],
	}, store, leaseStore, &recordingSender{}, &staticProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = f.IngestCheckpoint(ctx, CheckpointPackage{
		Checkpoint:         cp,
		OperatorSignatures: checkpointSigs,
	})
	if err == nil {
		t.Fatalf("expected missing witness error")
	}
	if !strings.Contains(err.Error(), "proof witness item") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}
