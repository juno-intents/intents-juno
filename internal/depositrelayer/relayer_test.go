package depositrelayer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/bridgeconfig"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/proof"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/proverinput"
	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
)

type stubSender struct {
	calls int
	got   []httpapi.SendRequest
	res   httpapi.SendResponse
	err   error
}

func (s *stubSender) Send(_ context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error) {
	s.calls++
	s.got = append(s.got, req)
	return s.res, s.err
}

type stubReadinessChecker struct {
	calls int
	err   error
}

func (s *stubReadinessChecker) Ready(context.Context) error {
	s.calls++
	return s.err
}

type scriptedSenderStep struct {
	res httpapi.SendResponse
	err error
}

type scriptedSender struct {
	calls int
	got   []httpapi.SendRequest
	plan  []scriptedSenderStep
}

func (s *scriptedSender) Send(_ context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error) {
	s.calls++
	s.got = append(s.got, req)
	idx := s.calls - 1
	if idx < len(s.plan) {
		return s.plan[idx].res, s.plan[idx].err
	}
	if len(s.plan) == 0 {
		return httpapi.SendResponse{}, nil
	}
	last := s.plan[len(s.plan)-1]
	return last.res, last.err
}

type stubProofRequester struct {
	calls  int
	gotReq proofclient.Request
	res    proofclient.Result
	err    error
}

func (p *stubProofRequester) RequestProof(_ context.Context, req proofclient.Request) (proofclient.Result, error) {
	p.calls++
	p.gotReq = req
	p.gotReq.Journal = append([]byte(nil), req.Journal...)
	p.gotReq.PrivateInput = append([]byte(nil), req.PrivateInput...)
	return p.res, p.err
}

type scriptedProofRequesterStep struct {
	res proofclient.Result
	err error
}

type scriptedProofRequester struct {
	calls int
	got   []proofclient.Request
	plan  []scriptedProofRequesterStep
}

func (p *scriptedProofRequester) RequestProof(_ context.Context, req proofclient.Request) (proofclient.Result, error) {
	p.calls++
	cloned := req
	cloned.Journal = append([]byte(nil), req.Journal...)
	cloned.PrivateInput = append([]byte(nil), req.PrivateInput...)
	p.got = append(p.got, cloned)
	idx := p.calls - 1
	if idx < len(p.plan) {
		return p.plan[idx].res, p.plan[idx].err
	}
	if len(p.plan) == 0 {
		return proofclient.Result{}, nil
	}
	last := p.plan[len(p.plan)-1]
	return last.res, last.err
}

type stubProofStore struct {
	calls int
	rec   proof.JobRecord
	err   error
}

func (s *stubProofStore) GetJob(_ context.Context, _ common.Hash) (proof.JobRecord, error) {
	s.calls++
	if s.err != nil {
		return proof.JobRecord{}, s.err
	}
	return s.rec, nil
}

type stubDepositWitnessRefresher struct {
	gotCalls        int
	gotAnchorHeight int64
	gotWitnessItem  []byte
	root            common.Hash
	item            []byte
	err             error
}

func (s *stubDepositWitnessRefresher) RefreshDepositWitness(_ context.Context, anchorHeight int64, witnessItem []byte) (common.Hash, []byte, error) {
	s.gotCalls++
	s.gotAnchorHeight = anchorHeight
	s.gotWitnessItem = append([]byte(nil), witnessItem...)
	if s.err != nil {
		return common.Hash{}, nil, s.err
	}
	return s.root, append([]byte(nil), s.item...), nil
}

type flakyDLQStore struct {
	inner         dlq.Store
	depositErrs   []error
	withdrawErrs  []error
	depositCalls  int
	withdrawCalls int
}

func newFlakyDLQStore() *flakyDLQStore {
	return &flakyDLQStore{inner: dlq.NewMemoryStore(nil)}
}

func (s *flakyDLQStore) EnsureSchema(ctx context.Context) error {
	return s.inner.EnsureSchema(ctx)
}

func (s *flakyDLQStore) InsertProofDLQ(ctx context.Context, rec dlq.ProofDLQRecord) error {
	return s.inner.InsertProofDLQ(ctx, rec)
}

func (s *flakyDLQStore) InsertDepositBatchDLQ(ctx context.Context, rec dlq.DepositBatchDLQRecord) error {
	s.depositCalls++
	if idx := s.depositCalls - 1; idx < len(s.depositErrs) && s.depositErrs[idx] != nil {
		return s.depositErrs[idx]
	}
	return s.inner.InsertDepositBatchDLQ(ctx, rec)
}

func (s *flakyDLQStore) InsertWithdrawalBatchDLQ(ctx context.Context, rec dlq.WithdrawalBatchDLQRecord) error {
	s.withdrawCalls++
	if idx := s.withdrawCalls - 1; idx < len(s.withdrawErrs) && s.withdrawErrs[idx] != nil {
		return s.withdrawErrs[idx]
	}
	return s.inner.InsertWithdrawalBatchDLQ(ctx, rec)
}

func (s *flakyDLQStore) ListProofDLQ(ctx context.Context, filter dlq.DLQFilter) ([]dlq.ProofDLQRecord, error) {
	return s.inner.ListProofDLQ(ctx, filter)
}

func (s *flakyDLQStore) ListDepositBatchDLQ(ctx context.Context, filter dlq.DLQFilter) ([]dlq.DepositBatchDLQRecord, error) {
	return s.inner.ListDepositBatchDLQ(ctx, filter)
}

func (s *flakyDLQStore) ListWithdrawalBatchDLQ(ctx context.Context, filter dlq.DLQFilter) ([]dlq.WithdrawalBatchDLQRecord, error) {
	return s.inner.ListWithdrawalBatchDLQ(ctx, filter)
}

func (s *flakyDLQStore) CountUnacknowledged(ctx context.Context) (dlq.DLQCounts, error) {
	return s.inner.CountUnacknowledged(ctx)
}

func (s *flakyDLQStore) Acknowledge(ctx context.Context, table string, id []byte) error {
	return s.inner.Acknowledge(ctx, table, id)
}

type blockingProofRequester struct {
	res proofclient.Result

	enterOnce sync.Once
	enterCh   chan struct{}
	releaseCh chan struct{}
}

func newBlockingProofRequester(res proofclient.Result) *blockingProofRequester {
	return &blockingProofRequester{
		res:       res,
		enterCh:   make(chan struct{}),
		releaseCh: make(chan struct{}),
	}
}

func (p *blockingProofRequester) RequestProof(ctx context.Context, _ proofclient.Request) (proofclient.Result, error) {
	p.enterOnce.Do(func() { close(p.enterCh) })
	select {
	case <-ctx.Done():
		return proofclient.Result{}, ctx.Err()
	case <-p.releaseCh:
		return p.res, nil
	}
}

func (p *blockingProofRequester) waitEntered(t *testing.T, timeout time.Duration) {
	t.Helper()
	select {
	case <-p.enterCh:
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for proof requester entry")
	}
}

func (p *blockingProofRequester) release() {
	close(p.releaseCh)
}

type finalizeFailStore struct {
	deposit.Store
	err error
}

func (s *finalizeFailStore) FinalizeBatch(context.Context, [][32]byte, checkpoint.Checkpoint, []byte, [32]byte) error {
	return s.err
}

func testOWalletIVKBytes() []byte {
	ivk := make([]byte, 64)
	for i := range ivk {
		ivk[i] = byte(i + 1)
	}
	return ivk
}

func testDepositWitnessItem() []byte {
	return bytes.Repeat([]byte{0x7a}, proverinput.DepositWitnessItemLen)
}

type stubDepositRuntimeSettingsProvider struct {
	settings runtimeconfig.Settings
	err      error
}

func (s *stubDepositRuntimeSettingsProvider) Current() (runtimeconfig.Settings, error) {
	return s.settings, s.err
}

func (s *stubDepositRuntimeSettingsProvider) Ready(context.Context) error {
	return s.err
}

type stubPauseChecker struct {
	calls  int
	paused bool
	err    error
}

func (s *stubPauseChecker) IsPaused(context.Context) (bool, error) {
	s.calls++
	return s.paused, s.err
}

func TestRelayer_UsesPersistedFulfilledProofBeforeRequestingAgain(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	store := deposit.NewMemoryStore()
	prover := &stubProofRequester{err: errors.New("proof request should not be sent")}
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	proofStore := &stubProofStore{
		rec: proof.JobRecord{
			State: proof.StateFulfilled,
			Seal:  []byte{0x99},
		},
	}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		ProofStore:        proofStore,
		Now:               time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}
	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	if prover.calls != 0 {
		t.Fatalf("expected no proof request, got %d calls", prover.calls)
	}
	if proofStore.calls == 0 {
		t.Fatal("expected persisted proof lookup")
	}
	if sender.calls != 1 {
		t.Fatalf("expected one bridge submission, got %d", sender.calls)
	}

	depositIDBytes, err := idempotency.DepositIDV1([32]byte(cm), 7)
	if err != nil {
		t.Fatalf("DepositIDV1: %v", err)
	}
	job, err := store.Get(ctx, depositIDBytes)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := job.State, deposit.StateFinalized; got != want {
		t.Fatalf("state: got %s want %s", got, want)
	}
}

func TestRelayer_RejectsDepositAfterTerminalProofFailure(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xbb
	store := deposit.NewMemoryStore()
	dlqStore := dlq.NewMemoryStore(nil)
	prover := &stubProofRequester{
		err: &proofclient.FailureError{
			Code:      "sp1_request_unexecutable",
			Retryable: false,
			Message:   "bad witness",
		},
	}
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		DLQStore:          dlqStore,
		Now:               time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}
	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        9,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	if sender.calls != 0 {
		t.Fatalf("expected no bridge submission, got %d calls", sender.calls)
	}
	if len(r.proofAttempts) != 0 {
		t.Fatalf("expected proof attempts cleared, got %d entries", len(r.proofAttempts))
	}

	depositIDBytes, err := idempotency.DepositIDV1([32]byte(cm), 9)
	if err != nil {
		t.Fatalf("DepositIDV1: %v", err)
	}
	job, err := store.Get(ctx, depositIDBytes)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := job.State, deposit.StateRejected; got != want {
		t.Fatalf("state: got %s want %s", got, want)
	}
	if got, want := job.RejectionReason, "proof failed: sp1_request_unexecutable"; got != want {
		t.Fatalf("rejection reason: got %q want %q", got, want)
	}

	counts, err := dlqStore.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if counts.DepositBatches != 1 {
		t.Fatalf("expected one deposit batch DLQ record, got %d", counts.DepositBatches)
	}
}

func TestRelayer_RejectsDepositFromPersistedTerminalProofFailure(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xbc
	store := deposit.NewMemoryStore()
	dlqStore := dlq.NewMemoryStore(nil)
	prover := &stubProofRequester{err: errors.New("proof request should not be sent")}
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	proofStore := &stubProofStore{
		rec: proof.JobRecord{
			State:        proof.StateFailedTerminal,
			ErrorCode:    "sp1_request_unexecutable",
			ErrorMessage: "bad witness",
		},
	}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		DLQStore:          dlqStore,
		ProofStore:        proofStore,
		Now:               time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}
	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        10,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	if prover.calls != 0 {
		t.Fatalf("expected no proof request, got %d calls", prover.calls)
	}
	if proofStore.calls == 0 {
		t.Fatal("expected persisted proof lookup")
	}
	if sender.calls != 0 {
		t.Fatalf("expected no bridge submission, got %d calls", sender.calls)
	}

	depositIDBytes, err := idempotency.DepositIDV1([32]byte(cm), 10)
	if err != nil {
		t.Fatalf("DepositIDV1: %v", err)
	}
	job, err := store.Get(ctx, depositIDBytes)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := job.State, deposit.StateRejected; got != want {
		t.Fatalf("state: got %s want %s", got, want)
	}
	if got, want := job.RejectionReason, "proof failed: sp1_request_unexecutable"; got != want {
		t.Fatalf("rejection reason: got %q want %q", got, want)
	}

	counts, err := dlqStore.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if counts.DepositBatches != 1 {
		t.Fatalf("expected one deposit batch DLQ record, got %d", counts.DepositBatches)
	}
}

func TestRelayer_QuarantinesTerminalProofFailureBySplittingBatch(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	store := deposit.NewMemoryStore()
	prover := &scriptedProofRequester{
		plan: []scriptedProofRequesterStep{
			{
				err: &proofclient.FailureError{
					Code:      "sp1_request_unexecutable",
					Retryable: false,
					Message:   "bad witness",
				},
			},
			{
				err: &proofclient.FailureError{
					Code:      "sp1_request_unexecutable",
					Retryable: false,
					Message:   "bad witness",
				},
			},
			{
				res: proofclient.Result{Seal: []byte{0xab}},
			},
		},
	}
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x02", Receipt: &httpapi.ReceiptResponse{Status: 1}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          2,
		MaxAge:            3 * time.Minute,
		DedupeMax:         1000,
		Owner:             "worker-1",
		Now:               time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	deposits := []DepositEvent{
		{
			Commitment:       common.HexToHash("0xaa"),
			LeafIndex:        7,
			Amount:           1000,
			Memo:             memoBytes[:],
			ProofWitnessItem: testDepositWitnessItem(),
		},
		{
			Commitment:       common.HexToHash("0xbb"),
			LeafIndex:        8,
			Amount:           1100,
			Memo:             memoBytes[:],
			ProofWitnessItem: testDepositWitnessItem(),
		},
	}
	for _, ev := range deposits {
		if err := r.IngestDeposit(ctx, ev); err != nil {
			t.Fatalf("IngestDeposit(%x): %v", ev.Commitment[:4], err)
		}
	}

	for i := 0; i < 6 && sender.calls < 1; i++ {
		if err := r.FlushDue(ctx); err != nil {
			t.Fatalf("FlushDue #%d: %v", i+1, err)
		}
	}

	if got, want := prover.calls, 3; got != want {
		t.Fatalf("proof calls: got %d want %d", got, want)
	}
	if got, want := sender.calls, 1; got != want {
		t.Fatalf("send calls: got %d want %d", got, want)
	}

	rejected := 0
	finalized := 0
	for _, ev := range deposits {
		depositID := idempotency.MustDepositIDV1([32]byte(ev.Commitment), ev.LeafIndex)
		job, err := store.Get(ctx, depositID)
		if err != nil {
			t.Fatalf("Get(%x): %v", depositID[:4], err)
		}
		switch job.State {
		case deposit.StateRejected:
			rejected++
		case deposit.StateFinalized:
			finalized++
		default:
			t.Fatalf("unexpected state for %x: %s", depositID[:4], job.State)
		}
	}
	if rejected != 1 || finalized != 1 {
		t.Fatalf("expected one rejected and one finalized deposit, got rejected=%d finalized=%d", rejected, finalized)
	}
}

func TestRelayer_DefaultClaimTTLTracksProofRequestTimeout(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:         1,
		BaseChainID:    31337,
		BridgeContract: common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	operatorAddrs, _ := mustSignedCheckpoint(t, cp)

	r, err := New(Config{
		BaseChainID:         uint32(cp.BaseChainID),
		BridgeAddress:       cp.BridgeContract,
		DepositImageID:      common.HexToHash("0x01"),
		OWalletIVKBytes:     testOWalletIVKBytes(),
		OperatorAddresses:   operatorAddrs,
		OperatorThreshold:   1,
		MaxItems:            1,
		MaxAge:              time.Minute,
		DedupeMax:           16,
		ProofRequestTimeout: 4 * time.Minute,
	}, deposit.NewMemoryStore(), &stubSender{}, &stubProofRequester{res: proofclient.Result{Seal: []byte{0x01}}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got, want := r.cfg.ClaimTTL, 6*time.Minute; got != want {
		t.Fatalf("ClaimTTL: got %s want %s", got, want)
	}
}

func TestRelayer_MarksProofRequestedBeforeProofRequestAndAllowsRetryAfterLeaseExpiry(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	store := deposit.NewMemoryStore()
	prover := newBlockingProofRequester(proofclient.Result{Seal: []byte{0x99}})
	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Owner:             "worker-1",
		ClaimTTL:          80 * time.Millisecond,
		Now:               time.Now,
	}, store, &stubSender{}, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	var cm common.Hash
	cm[0] = 0xaa
	depositID := idempotency.MustDepositIDV1([32]byte(cm), 7)
	if _, _, err := store.UpsertConfirmed(ctx, deposit.Deposit{
		DepositID:        depositID,
		Commitment:       [32]byte(cm),
		LeafIndex:        7,
		Amount:           1000,
		BaseRecipient:    [20]byte(common.HexToAddress("0x0000000000000000000000000000000000000456")),
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- r.FlushDue(ctx)
	}()

	prover.waitEntered(t, time.Second)

	job, err := store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := job.State, deposit.StateProofRequested; got != want {
		t.Fatalf("state while proof in flight: got %v want %v", got, want)
	}

	other, err := store.ClaimConfirmed(ctx, "worker-2", 80*time.Millisecond, 1)
	if err != nil {
		t.Fatalf("ClaimConfirmed before expiry: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("expected active proof lease to block second worker")
	}

	time.Sleep(100 * time.Millisecond)

	reclaimed, err := store.ClaimConfirmed(ctx, "worker-2", 80*time.Millisecond, 1)
	if err != nil {
		t.Fatalf("ClaimConfirmed after expiry: %v", err)
	}
	if len(reclaimed) != 1 || reclaimed[0].Deposit.DepositID != depositID {
		t.Fatalf("expected second worker to reclaim proof-requested deposit after lease expiry")
	}

	cancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("FlushDue err = %v, want context.Canceled", err)
	}
}

func TestRelayer_PauseCheckErrorFailsClosedBeforeProofRequest(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	store := deposit.NewMemoryStore()
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Owner:             "worker-1",
		ClaimTTL:          time.Minute,
		Now:               time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.WithPauseChecker(&stubPauseChecker{err: errors.New("pause rpc failed")})

	ctx := context.Background()
	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	var cm common.Hash
	cm[0] = 0xaa
	depositID := idempotency.MustDepositIDV1([32]byte(cm), 7)
	if _, _, err := store.UpsertConfirmed(ctx, deposit.Deposit{
		DepositID:        depositID,
		Commitment:       [32]byte(cm),
		LeafIndex:        7,
		Amount:           1000,
		BaseRecipient:    [20]byte(common.HexToAddress("0x0000000000000000000000000000000000000456")),
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	if err := r.FlushDue(ctx); err == nil {
		t.Fatalf("expected pause check to fail closed")
	}
	if prover.calls != 0 {
		t.Fatalf("proof requester calls: got %d want 0", prover.calls)
	}
	if sender.calls != 0 {
		t.Fatalf("sender calls: got %d want 0", sender.calls)
	}

	job, err := store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := job.State, deposit.StateConfirmed; got != want {
		t.Fatalf("state after paused flush: got %v want %v", got, want)
	}
}

type stubDepositBridgeSettingsProvider struct {
	snapshot bridgeconfig.Snapshot
	err      error
}

func (s *stubDepositBridgeSettingsProvider) Current() (bridgeconfig.Snapshot, error) {
	return s.snapshot, s.err
}

func (s *stubDepositBridgeSettingsProvider) Ready(context.Context) error {
	return s.err
}

type stubTipHeightProvider struct {
	height int64
	err    error
}

func (s *stubTipHeightProvider) TipHeight(context.Context) (int64, error) {
	return s.height, s.err
}

type stubReceiptReader struct {
	receipt    *types.Receipt
	err        error
	filterLogs []types.Log
	filterErr  error
}

func (s *stubReceiptReader) TransactionReceipt(context.Context, common.Hash) (*types.Receipt, error) {
	return s.receipt, s.err
}

func (s *stubReceiptReader) FilterLogs(context.Context, ethereum.FilterQuery) ([]types.Log, error) {
	if s.filterErr != nil {
		return nil, s.filterErr
	}
	return append([]types.Log(nil), s.filterLogs...), nil
}

type stubBridgeCaller struct {
	responses map[string][]byte
	err       error
}

func (s *stubBridgeCaller) CallContract(_ context.Context, msg ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if len(msg.Data) < 4 {
		return nil, fmt.Errorf("unexpected calldata length %d", len(msg.Data))
	}
	key := hex.EncodeToString(msg.Data[:4])
	raw, ok := s.responses[key]
	if !ok {
		return nil, fmt.Errorf("unexpected bridge call selector %s", key)
	}
	return append([]byte(nil), raw...), nil
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

func mustType(t *testing.T, typ string, comps []abi.ArgumentMarshaling) abi.Type {
	t.Helper()

	ty, err := abi.NewType(typ, "", comps)
	if err != nil {
		t.Fatalf("abi.NewType(%q): %v", typ, err)
	}
	return ty
}

func seq32ForRelayer(b byte) [32]byte {
	var out [32]byte
	out[31] = b
	return out
}

func to20(addr common.Address) [20]byte {
	var out [20]byte
	copy(out[:], addr[:])
	return out
}

func TestRelayer_IngestDeposit_RejectsLeafIndexOverflow(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	operatorKey := mustOperatorKey(t)
	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{crypto.PubkeyToAddress(operatorKey.PublicKey)},
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = r.IngestDeposit(context.Background(), DepositEvent{
		Commitment: common.HexToHash("0x01"),
		LeafIndex:  math.MaxUint32 + 1,
		Amount:     1000,
		Memo:       memoBytes[:],
	})
	if !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("expected ErrInvalidEvent, got %v", err)
	}
	if !errors.Is(err, idempotency.ErrDepositLeafIndexOverflow) {
		t.Fatalf("expected ErrDepositLeafIndexOverflow, got %v", err)
	}
}

func TestRelayer_NewRejectsInvalidOWalletIVKLength(t *testing.T) {
	t.Parallel()

	operatorKey := mustOperatorKey(t)

	_, err := New(Config{
		BaseChainID:       31337,
		BridgeAddress:     common.HexToAddress("0x0000000000000000000000000000000000000123"),
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   []byte{0x01},
		OperatorAddresses: []common.Address{crypto.PubkeyToAddress(operatorKey.PublicKey)},
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), &stubSender{}, &stubProofRequester{}, nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestRelayer_NewRejectsMissingOWalletIVK(t *testing.T) {
	t.Parallel()

	operatorKey := mustOperatorKey(t)

	_, err := New(Config{
		BaseChainID:       31337,
		BridgeAddress:     common.HexToAddress("0x0000000000000000000000000000000000000123"),
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OperatorAddresses: []common.Address{crypto.PubkeyToAddress(operatorKey.PublicKey)},
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), &stubSender{}, &stubProofRequester{}, nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestRelayer_NewDefaultsClaimTTLToProofTimeoutPlusBuffer(t *testing.T) {
	t.Parallel()

	operatorKey := mustOperatorKey(t)

	r, err := New(Config{
		BaseChainID:       31337,
		BridgeAddress:     common.HexToAddress("0x0000000000000000000000000000000000000123"),
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{crypto.PubkeyToAddress(operatorKey.PublicKey)},
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got, want := r.cfg.ProofRequestTimeout, 15*time.Minute; got != want {
		t.Fatalf("proof request timeout: got %s want %s", got, want)
	}
	if got, want := r.cfg.ClaimTTL, 17*time.Minute; got != want {
		t.Fatalf("claim ttl: got %s want %s", got, want)
	}
}

func TestRelayer_RefillFromStore_PromotesSeenAndRejectsBelowMin(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	depID := seq32ForRelayer(0x01)
	dep := deposit.Deposit{
		DepositID:     depID,
		Commitment:    seq32ForRelayer(0x11),
		LeafIndex:     7,
		Amount:        99,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000123")),
		JunoHeight:    10,
	}
	if _, _, err := store.UpsertSeen(context.Background(), dep); err != nil {
		t.Fatalf("UpsertSeen: %v", err)
	}

	r, err := New(Config{
		BaseChainID:       31337,
		BridgeAddress:     common.HexToAddress("0x0000000000000000000000000000000000000123"),
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
		RuntimeSettings: &stubDepositRuntimeSettingsProvider{settings: runtimeconfig.Settings{
			DepositMinConfirmations:         3,
			WithdrawPlannerMinConfirmations: 1,
			WithdrawBatchConfirmations:      1,
		}},
		BridgeSettings: &stubDepositBridgeSettingsProvider{snapshot: bridgeconfig.Snapshot{
			MinDepositAmount: 100,
		}},
		TipHeightProvider: &stubTipHeightProvider{height: 12},
	}, store, &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.checkpoint = &checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x01"),
		FinalOrchardRoot: common.HexToHash("0x02"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	r.opSigs = [][]byte{[]byte{0x01}}

	if err := r.refillFromStore(context.Background()); err != nil {
		t.Fatalf("refillFromStore: %v", err)
	}

	job, err := store.Get(context.Background(), depID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateRejected {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateRejected)
	}
	wantReason := "deposit amount is below the current minimum deposit (100)"
	if job.RejectionReason != wantReason {
		t.Fatalf("rejection reason: got %q want %q", job.RejectionReason, wantReason)
	}
}

func TestRelayer_RefillFromStore_PromotesSeenWithoutCheckpoint(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	depID := seq32ForRelayer(0x31)
	dep := deposit.Deposit{
		DepositID:     depID,
		Commitment:    seq32ForRelayer(0x41),
		LeafIndex:     9,
		Amount:        250,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
		JunoHeight:    10,
	}
	if _, _, err := store.UpsertSeen(context.Background(), dep); err != nil {
		t.Fatalf("UpsertSeen: %v", err)
	}

	r, err := New(Config{
		BaseChainID:       31337,
		BridgeAddress:     common.HexToAddress("0x0000000000000000000000000000000000000123"),
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
		RuntimeSettings: &stubDepositRuntimeSettingsProvider{settings: runtimeconfig.Settings{
			DepositMinConfirmations:         1,
			WithdrawPlannerMinConfirmations: 1,
			WithdrawBatchConfirmations:      1,
		}},
		TipHeightProvider: &stubTipHeightProvider{height: 12},
	}, store, &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.refillFromStore(context.Background()); err != nil {
		t.Fatalf("refillFromStore: %v", err)
	}

	job, err := store.Get(context.Background(), depID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateConfirmed)
	}
}

func TestRelayer_PersistsOpenBatchAcrossRestartBeforeSubmitting(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	store := deposit.NewMemoryStore()
	firstSender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	firstProver := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r1, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          2,
		MaxAge:            3 * time.Minute,
		DedupeMax:         1000,
		Owner:             "worker-1",
		Now:               time.Now,
	}, store, firstSender, firstProver, nil)
	if err != nil {
		t.Fatalf("New worker 1: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r1.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("r1 IngestCheckpoint: %v", err)
	}

	deposit1 := DepositEvent{
		Commitment:       common.HexToHash("0xaa"),
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}
	if err := r1.IngestDeposit(ctx, deposit1); err != nil {
		t.Fatalf("r1 IngestDeposit: %v", err)
	}
	if firstSender.calls != 0 {
		t.Fatalf("expected no submission before batch closes, got %d sends", firstSender.calls)
	}
	if firstProver.calls != 0 {
		t.Fatalf("expected no proof request before batch closes, got %d calls", firstProver.calls)
	}

	depositID1 := idempotency.MustDepositIDV1([32]byte(deposit1.Commitment), deposit1.LeafIndex)
	confirmed1, err := store.Get(ctx, depositID1)
	if err != nil {
		t.Fatalf("Get deposit 1: %v", err)
	}
	if got, want := confirmed1.State, deposit.StateConfirmed; got != want {
		t.Fatalf("deposit 1 state after first ingest: got %v want %v", got, want)
	}

	secondSender := &stubSender{res: httpapi.SendResponse{TxHash: "0x02", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	secondProver := &stubProofRequester{res: proofclient.Result{Seal: []byte{0xab}}}
	r2, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          2,
		MaxAge:            3 * time.Minute,
		DedupeMax:         1000,
		Owner:             "worker-2",
		Now:               time.Now,
	}, store, secondSender, secondProver, nil)
	if err != nil {
		t.Fatalf("New worker 2: %v", err)
	}

	if err := r2.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("r2 IngestCheckpoint: %v", err)
	}

	deposit2 := DepositEvent{
		Commitment:       common.HexToHash("0xbb"),
		LeafIndex:        8,
		Amount:           1100,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}
	if err := r2.IngestDeposit(ctx, deposit2); err != nil {
		t.Fatalf("r2 IngestDeposit: %v", err)
	}
	if secondSender.calls != 1 {
		t.Fatalf("expected one submission after second deposit, got %d", secondSender.calls)
	}
	if secondProver.calls != 1 {
		t.Fatalf("expected one proof request after second deposit, got %d", secondProver.calls)
	}

	depositID2 := idempotency.MustDepositIDV1([32]byte(deposit2.Commitment), deposit2.LeafIndex)
	for _, depositID := range [][32]byte{depositID1, depositID2} {
		job, err := store.Get(ctx, depositID)
		if err != nil {
			t.Fatalf("Get finalized deposit %x: %v", depositID[:8], err)
		}
		if got, want := job.State, deposit.StateFinalized; got != want {
			t.Fatalf("final state for %x: got %v want %v", depositID[:8], got, want)
		}
	}
}

func TestRelayer_SplitsOversizedClosedBatchBeforeProofRequest(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	store := deposit.NewMemoryStore()
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x02", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0xab}}}
	r, err := New(Config{
		BaseChainID:          baseChainID,
		BridgeAddress:        bridge,
		DepositImageID:       common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:      testOWalletIVKBytes(),
		OperatorAddresses:    operatorAddrs,
		OperatorThreshold:    1,
		MaxItems:             2,
		MaxAge:               3 * time.Minute,
		DedupeMax:            1000,
		MaxBatchWitnessBytes: len(testDepositWitnessItem()) + 1,
		Owner:                "worker-1",
		Now:                  time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	deposits := []DepositEvent{
		{
			Commitment:       common.HexToHash("0xaa"),
			LeafIndex:        7,
			Amount:           1000,
			Memo:             memoBytes[:],
			ProofWitnessItem: testDepositWitnessItem(),
		},
		{
			Commitment:       common.HexToHash("0xbb"),
			LeafIndex:        8,
			Amount:           1100,
			Memo:             memoBytes[:],
			ProofWitnessItem: testDepositWitnessItem(),
		},
	}

	for _, ev := range deposits {
		if err := r.IngestDeposit(ctx, ev); err != nil {
			t.Fatalf("IngestDeposit(%x): %v", ev.Commitment[:4], err)
		}
	}

	for i := 0; i < 4 && sender.calls < 2; i++ {
		if err := r.FlushDue(ctx); err != nil {
			t.Fatalf("FlushDue #%d: %v", i+1, err)
		}
	}

	if got, want := prover.calls, 2; got != want {
		t.Fatalf("proof calls: got %d want %d", got, want)
	}
	if got, want := sender.calls, 2; got != want {
		t.Fatalf("send calls: got %d want %d", got, want)
	}

	for _, ev := range deposits {
		depositID := idempotency.MustDepositIDV1([32]byte(ev.Commitment), ev.LeafIndex)
		job, err := store.Get(ctx, depositID)
		if err != nil {
			t.Fatalf("Get finalized deposit %x: %v", depositID[:8], err)
		}
		if got, want := job.State, deposit.StateFinalized; got != want {
			t.Fatalf("final state for %x: got %v want %v", depositID[:8], got, want)
		}
	}
}

func TestRelayer_RejectsOversizedSingleDepositBatchBeforeProofRequest(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	store := deposit.NewMemoryStore()
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x02", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0xab}}}
	r, err := New(Config{
		BaseChainID:          baseChainID,
		BridgeAddress:        bridge,
		DepositImageID:       common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:      testOWalletIVKBytes(),
		OperatorAddresses:    operatorAddrs,
		OperatorThreshold:    1,
		MaxItems:             1,
		MaxAge:               3 * time.Minute,
		DedupeMax:            1000,
		MaxBatchWitnessBytes: len(testDepositWitnessItem()) - 1,
		Owner:                "worker-1",
		Now:                  time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	ev := DepositEvent{
		Commitment:       common.HexToHash("0xaa"),
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}
	if err := r.IngestDeposit(ctx, ev); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}
	if err := r.FlushDue(ctx); err != nil {
		t.Fatalf("FlushDue: %v", err)
	}

	if got, want := prover.calls, 0; got != want {
		t.Fatalf("proof calls: got %d want %d", got, want)
	}
	if got, want := sender.calls, 0; got != want {
		t.Fatalf("send calls: got %d want %d", got, want)
	}

	depositID := idempotency.MustDepositIDV1([32]byte(ev.Commitment), ev.LeafIndex)
	job, err := store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get rejected deposit: %v", err)
	}
	if got, want := job.State, deposit.StateRejected; got != want {
		t.Fatalf("state: got %v want %v", got, want)
	}
	if !strings.Contains(job.RejectionReason, "proof witness bytes") {
		t.Fatalf("rejection reason = %q, want proof witness bytes detail", job.RejectionReason)
	}
}

func TestRelayer_MetricsSummary(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	ctx := context.Background()

	deposits := []deposit.Deposit{
		{
			DepositID:     seq32ForRelayer(0x41),
			Commitment:    seq32ForRelayer(0x51),
			LeafIndex:     1,
			Amount:        500,
			BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
		},
		{
			DepositID:     seq32ForRelayer(0x42),
			Commitment:    seq32ForRelayer(0x52),
			LeafIndex:     2,
			Amount:        600,
			BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000457")),
		},
		{
			DepositID:     seq32ForRelayer(0x43),
			Commitment:    seq32ForRelayer(0x53),
			LeafIndex:     3,
			Amount:        700,
			BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000458")),
		},
	}
	for _, dep := range deposits {
		if _, _, err := store.UpsertConfirmed(ctx, dep); err != nil {
			t.Fatalf("UpsertConfirmed(%x): %v", dep.DepositID[:4], err)
		}
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if err := store.MarkProofRequested(ctx, deposits[1].DepositID, cp); err != nil {
		t.Fatalf("MarkProofRequested: %v", err)
	}

	submittedBatch, ready, err := store.PrepareNextBatch(
		ctx,
		"worker-1",
		time.Minute,
		seq32ForRelayer(0x62),
		1,
		time.Minute,
		10,
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("PrepareNextBatch submitted: %v", err)
	}
	if !ready {
		t.Fatalf("expected submitted batch to be ready")
	}
	if _, err := store.MarkBatchProofRequested(ctx, "worker-1", submittedBatch.BatchID, cp); err != nil {
		t.Fatalf("MarkBatchProofRequested submitted: %v", err)
	}
	if _, err := store.MarkBatchProofReady(ctx, "worker-1", submittedBatch.BatchID, cp, [][]byte{[]byte{0x01}}, []byte{0x02}); err != nil {
		t.Fatalf("MarkBatchProofReady submitted: %v", err)
	}
	if _, err := store.MarkBatchSubmitted(ctx, "worker-1", submittedBatch.BatchID, submittedBatch.DepositIDs, cp, [][]byte{[]byte{0x01}}, []byte{0x02}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}

	r, err := New(Config{
		BaseChainID:       31337,
		BridgeAddress:     common.HexToAddress("0x0000000000000000000000000000000000000123"),
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
	}, store, &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	summary, err := r.MetricsSummary(ctx)
	if err != nil {
		t.Fatalf("MetricsSummary: %v", err)
	}
	if summary.ConfirmedCount != 1 {
		t.Fatalf("confirmed count: got %d want 1", summary.ConfirmedCount)
	}
	if summary.ProofRequestedCount != 1 {
		t.Fatalf("proof_requested count: got %d want 1", summary.ProofRequestedCount)
	}
	if summary.SubmittedCount != 1 {
		t.Fatalf("submitted count: got %d want 1", summary.SubmittedCount)
	}
}

func TestRelayer_ApplyBatchOutcomeFromHash_ReconcilesMixedMintedAndSkipped(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	depositA := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x21),
		Commitment:    seq32ForRelayer(0x31),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	depositB := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x22),
		Commitment:    seq32ForRelayer(0x32),
		LeafIndex:     2,
		Amount:        700,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000789")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), depositA); err != nil {
		t.Fatalf("UpsertConfirmed(A): %v", err)
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), depositB); err != nil {
		t.Fatalf("UpsertConfirmed(B): %v", err)
	}

	batchID := seq32ForRelayer(0x40)
	txHash := seq32ForRelayer(0x41)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0x42),
		FinalOrchardRoot: seq32ForRelayer(0x43),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(context.Background(), "owner-1", batchID, [][32]byte{depositA.DepositID, depositB.DepositID}, cp, nil, []byte{0x01}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	if err := store.SetBatchSubmissionTxHash(context.Background(), batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	mintedTopic := crypto.Keccak256Hash([]byte("Minted(bytes32,address,uint256,uint256,uint256)"))
	skippedTopic := crypto.Keccak256Hash([]byte("DepositSkipped(bytes32)"))
	bridge := cp.BridgeContract
	r, err := New(Config{
		BaseChainID:       uint32(cp.BaseChainID),
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
		ReceiptReader: &stubReceiptReader{receipt: &types.Receipt{
			Status: types.ReceiptStatusSuccessful,
			Logs: []*types.Log{
				{Address: bridge, Topics: []common.Hash{mintedTopic, common.BytesToHash(depositA.DepositID[:])}},
				{Address: bridge, Topics: []common.Hash{skippedTopic, common.BytesToHash(depositB.DepositID[:])}},
			},
		}},
	}, store, &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.applyBatchOutcomeFromHash(context.Background(), batchID, [][32]byte{depositA.DepositID, depositB.DepositID}, cp, []byte{0x01}, txHash); err != nil {
		t.Fatalf("applyBatchOutcomeFromHash: %v", err)
	}

	jobA, err := store.Get(context.Background(), depositA.DepositID)
	if err != nil {
		t.Fatalf("Get(A): %v", err)
	}
	if jobA.State != deposit.StateFinalized {
		t.Fatalf("jobA state: got %s want %s", jobA.State, deposit.StateFinalized)
	}

	jobB, err := store.Get(context.Background(), depositB.DepositID)
	if err != nil {
		t.Fatalf("Get(B): %v", err)
	}
	if jobB.State != deposit.StateRejected {
		t.Fatalf("jobB state: got %s want %s", jobB.State, deposit.StateRejected)
	}
	if jobB.RejectionReason != "deposit skipped by bridge" {
		t.Fatalf("jobB rejection reason: got %q want %q", jobB.RejectionReason, "deposit skipped by bridge")
	}
}

func TestRelayer_ApplyBatchOutcomeFromHash_RequeuesUnresolvedDeposits(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	depositA := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x23),
		Commitment:    seq32ForRelayer(0x33),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	depositB := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x24),
		Commitment:    seq32ForRelayer(0x34),
		LeafIndex:     2,
		Amount:        700,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000789")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), depositA); err != nil {
		t.Fatalf("UpsertConfirmed(A): %v", err)
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), depositB); err != nil {
		t.Fatalf("UpsertConfirmed(B): %v", err)
	}

	batchID := seq32ForRelayer(0x35)
	txHash := seq32ForRelayer(0x36)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0x37),
		FinalOrchardRoot: seq32ForRelayer(0x38),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(context.Background(), "owner-1", batchID, [][32]byte{depositA.DepositID, depositB.DepositID}, cp, nil, []byte{0x01}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	if err := store.SetBatchSubmissionTxHash(context.Background(), batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	mintedTopic := crypto.Keccak256Hash([]byte("Minted(bytes32,address,uint256,uint256,uint256)"))
	bridge := cp.BridgeContract
	r, err := New(Config{
		BaseChainID:       uint32(cp.BaseChainID),
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
		ReceiptReader: &stubReceiptReader{receipt: &types.Receipt{
			Status: types.ReceiptStatusSuccessful,
			Logs: []*types.Log{
				{Address: bridge, Topics: []common.Hash{mintedTopic, common.BytesToHash(depositA.DepositID[:])}},
			},
		}},
	}, store, &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.applyBatchOutcomeFromHash(context.Background(), batchID, [][32]byte{depositA.DepositID, depositB.DepositID}, cp, []byte{0x01}, txHash); err != nil {
		t.Fatalf("applyBatchOutcomeFromHash: %v", err)
	}

	jobA, err := store.Get(context.Background(), depositA.DepositID)
	if err != nil {
		t.Fatalf("Get(A): %v", err)
	}
	if jobA.State != deposit.StateFinalized {
		t.Fatalf("jobA state: got %s want %s", jobA.State, deposit.StateFinalized)
	}

	jobB, err := store.Get(context.Background(), depositB.DepositID)
	if err != nil {
		t.Fatalf("Get(B): %v", err)
	}
	if jobB.State != deposit.StateConfirmed {
		t.Fatalf("jobB state: got %s want %s", jobB.State, deposit.StateConfirmed)
	}
	if jobB.TxHash != ([32]byte{}) {
		t.Fatalf("jobB tx hash should be cleared, got %x", jobB.TxHash)
	}

	attempts, err := store.ClaimSubmittedAttempts(context.Background(), "worker-2", time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("submitted attempts len: got %d want 0", len(attempts))
	}
}

func TestRelayer_RecoverSubmittedAttempts_RequeuesStaleCheckpointBatch(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	dep := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x81),
		Commitment:    seq32ForRelayer(0x82),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), dep); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	staleCheckpoint := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0x83),
		FinalOrchardRoot: seq32ForRelayer(0x84),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(
		context.Background(),
		"owner-1",
		seq32ForRelayer(0x85),
		[][32]byte{dep.DepositID},
		staleCheckpoint,
		[][]byte{{0xaa}},
		[]byte{0xbb},
	); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}

	sender := &stubSender{err: errors.New("send should not be called")}
	r, err := New(Config{
		BaseChainID:       uint32(staleCheckpoint.BaseChainID),
		BridgeAddress:     staleCheckpoint.BridgeContract,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
	}, store, sender, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	newerCheckpoint := staleCheckpoint
	newerCheckpoint.Height = staleCheckpoint.Height + 10
	newerCheckpoint.BlockHash = seq32ForRelayer(0x86)
	newerCheckpoint.FinalOrchardRoot = seq32ForRelayer(0x87)
	r.checkpoint = &newerCheckpoint
	r.opSigs = [][]byte{{0xcc}}

	if err := r.recoverSubmittedAttempts(context.Background()); err != nil {
		t.Fatalf("recoverSubmittedAttempts: %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("sender called %d times, want 0", sender.calls)
	}

	job, err := store.Get(context.Background(), dep.DepositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateConfirmed)
	}
	if len(job.ProofSeal) != 0 {
		t.Fatalf("proof seal should be cleared, got %x", job.ProofSeal)
	}

	attempts, err := store.ClaimSubmittedAttempts(context.Background(), "worker-2", time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("submitted attempts len: got %d want 0", len(attempts))
	}

	reclaimed, err := store.ClaimConfirmed(context.Background(), "worker-2", time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimConfirmed: %v", err)
	}
	if len(reclaimed) != 1 || reclaimed[0].Deposit.DepositID != dep.DepositID {
		t.Fatalf("unexpected reclaimed jobs: %#v", reclaimed)
	}
}

func TestRelayer_RecoverSubmittedAttempts_ResetsStaleCheckpointWhenReceiptMissing(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	dep := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x87),
		Commitment:    seq32ForRelayer(0x88),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), dep); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	staleCheckpoint := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0x89),
		FinalOrchardRoot: seq32ForRelayer(0x8a),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	batchID := seq32ForRelayer(0x8b)
	txHash := seq32ForRelayer(0x8c)
	if _, err := store.MarkBatchSubmitted(
		context.Background(),
		"owner-1",
		batchID,
		[][32]byte{dep.DepositID},
		staleCheckpoint,
		[][]byte{{0xaa}},
		[]byte{0xbb},
	); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	if err := store.SetBatchSubmissionTxHash(context.Background(), batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	heightCall, err := bridgeabi.PackLastAcceptedCheckpointHeightCalldata()
	if err != nil {
		t.Fatalf("PackLastAcceptedCheckpointHeightCalldata: %v", err)
	}
	blockHashCall, err := bridgeabi.PackLastAcceptedCheckpointBlockHashCalldata()
	if err != nil {
		t.Fatalf("PackLastAcceptedCheckpointBlockHashCalldata: %v", err)
	}
	rootCall, err := bridgeabi.PackLastAcceptedCheckpointFinalOrchardRootCalldata()
	if err != nil {
		t.Fatalf("PackLastAcceptedCheckpointFinalOrchardRootCalldata: %v", err)
	}
	acceptedBlockHash := seq32ForRelayer(0x8d)
	acceptedRoot := seq32ForRelayer(0x8e)

	r, err := New(Config{
		BaseChainID:       uint32(staleCheckpoint.BaseChainID),
		BridgeAddress:     staleCheckpoint.BridgeContract,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
		ReceiptReader:     &stubReceiptReader{err: ethereum.NotFound},
		BridgeCaller: &stubBridgeCaller{responses: map[string][]byte{
			hex.EncodeToString(heightCall[:4]):    common.LeftPadBytes(big.NewInt(124).Bytes(), 32),
			hex.EncodeToString(blockHashCall[:4]): acceptedBlockHash[:],
			hex.EncodeToString(rootCall[:4]):      acceptedRoot[:],
		}},
	}, store, &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.recoverSubmittedAttempts(context.Background()); err != nil {
		t.Fatalf("recoverSubmittedAttempts: %v", err)
	}

	job, err := store.Get(context.Background(), dep.DepositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateConfirmed)
	}
	if job.TxHash != ([32]byte{}) {
		t.Fatalf("job tx hash: got %x want empty", job.TxHash)
	}

	attempts, err := store.ClaimSubmittedAttempts(context.Background(), "worker-2", time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("submitted attempts len: got %d want 0", len(attempts))
	}
}

func TestRelayer_RecoverSubmittedAttempts_ResetsSameHeightCheckpointConflict(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	dep := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x88),
		Commitment:    seq32ForRelayer(0x89),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), dep); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	conflictingCheckpoint := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0x8a),
		FinalOrchardRoot: seq32ForRelayer(0x8b),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(
		context.Background(),
		"owner-1",
		seq32ForRelayer(0x8c),
		[][32]byte{dep.DepositID},
		conflictingCheckpoint,
		[][]byte{{0xaa}},
		[]byte{0xbb},
	); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}

	sender := &stubSender{err: errors.New("send should not be called")}
	r, err := New(Config{
		BaseChainID:       uint32(conflictingCheckpoint.BaseChainID),
		BridgeAddress:     conflictingCheckpoint.BridgeContract,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
	}, store, sender, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sameHeightCheckpoint := conflictingCheckpoint
	sameHeightCheckpoint.BlockHash = seq32ForRelayer(0x8d)
	sameHeightCheckpoint.FinalOrchardRoot = seq32ForRelayer(0x8e)
	r.checkpoint = &sameHeightCheckpoint
	r.opSigs = [][]byte{{0xcc}}

	if err := r.recoverSubmittedAttempts(context.Background()); err != nil {
		t.Fatalf("recoverSubmittedAttempts: %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("sender called %d times, want 0", sender.calls)
	}

	job, err := store.Get(context.Background(), dep.DepositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateConfirmed)
	}
}

func TestRelayer_RecoverSubmittedAttempts_ResetsOnChainStaleCheckpointRevert(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	dep := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x90),
		Commitment:    seq32ForRelayer(0x91),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), dep); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	staleCheckpoint := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0x92),
		FinalOrchardRoot: seq32ForRelayer(0x93),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(
		context.Background(),
		"owner-1",
		seq32ForRelayer(0x94),
		[][32]byte{dep.DepositID},
		staleCheckpoint,
		[][]byte{{0xaa}},
		[]byte{0xbb},
	); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}

	heightCall, err := bridgeabi.PackLastAcceptedCheckpointHeightCalldata()
	if err != nil {
		t.Fatalf("PackLastAcceptedCheckpointHeightCalldata: %v", err)
	}
	blockHashCall, err := bridgeabi.PackLastAcceptedCheckpointBlockHashCalldata()
	if err != nil {
		t.Fatalf("PackLastAcceptedCheckpointBlockHashCalldata: %v", err)
	}
	rootCall, err := bridgeabi.PackLastAcceptedCheckpointFinalOrchardRootCalldata()
	if err != nil {
		t.Fatalf("PackLastAcceptedCheckpointFinalOrchardRootCalldata: %v", err)
	}
	acceptedBlockHash := seq32ForRelayer(0x95)
	acceptedRoot := seq32ForRelayer(0x96)

	sender := &stubSender{res: httpapi.SendResponse{
		TxHash: "0xdeadbeef",
		Receipt: &httpapi.ReceiptResponse{
			Status:       0,
			RevertReason: "CheckpointHeightRegression(123,124)",
		},
	}}
	r, err := New(Config{
		BaseChainID:       uint32(staleCheckpoint.BaseChainID),
		BridgeAddress:     staleCheckpoint.BridgeContract,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
		BridgeCaller: &stubBridgeCaller{responses: map[string][]byte{
			hex.EncodeToString(heightCall[:4]):    common.LeftPadBytes(big.NewInt(124).Bytes(), 32),
			hex.EncodeToString(blockHashCall[:4]): acceptedBlockHash[:],
			hex.EncodeToString(rootCall[:4]):      acceptedRoot[:],
		}},
	}, store, sender, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.checkpoint = &staleCheckpoint
	r.opSigs = [][]byte{{0xcc}}

	if err := r.recoverSubmittedAttempts(context.Background()); err != nil {
		t.Fatalf("recoverSubmittedAttempts: %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("sender calls: got %d want 0", sender.calls)
	}

	job, err := store.Get(context.Background(), dep.DepositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateConfirmed)
	}
}

func TestRelayer_RecoverSubmittedAttempts_RequeuesReceiptMissingBatchAfterLeaseExpiry(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	dep := deposit.Deposit{
		DepositID:     seq32ForRelayer(0xa5),
		Commitment:    seq32ForRelayer(0xa6),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), dep); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	staleCheckpoint := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0xa7),
		FinalOrchardRoot: seq32ForRelayer(0xa8),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(
		context.Background(),
		"owner-1",
		seq32ForRelayer(0xa9),
		[][32]byte{dep.DepositID},
		staleCheckpoint,
		[][]byte{{0xaa}},
		[]byte{0xbb},
	); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	var txHash [32]byte
	txHash[0] = 0xcc
	if err := store.SetBatchSubmissionTxHash(context.Background(), seq32ForRelayer(0xa9), txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	sender := &stubSender{err: errors.New("send should not be called")}
	r, err := New(Config{
		BaseChainID:       uint32(staleCheckpoint.BaseChainID),
		BridgeAddress:     staleCheckpoint.BridgeContract,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		ClaimTTL:          10 * time.Millisecond,
		Now:               time.Now,
		ReceiptReader:     &stubReceiptReader{err: ethereum.NotFound},
	}, store, sender, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	if err := r.recoverSubmittedAttempts(context.Background()); err != nil {
		t.Fatalf("recoverSubmittedAttempts: %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("sender called %d times, want 0", sender.calls)
	}

	job, err := store.Get(context.Background(), dep.DepositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateConfirmed)
	}
	if job.TxHash != ([32]byte{}) {
		t.Fatalf("tx hash should be cleared, got %x", job.TxHash)
	}

	attempts, err := store.ClaimSubmittedAttempts(context.Background(), "worker-2", time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected submitted attempts to be cleared, got %d", len(attempts))
	}
}

func TestRelayer_RecoverSubmittedAttempts_RequeuesNoTxHashBatchAfterStalenessWindow(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	dep := deposit.Deposit{
		DepositID:     seq32ForRelayer(0xb1),
		Commitment:    seq32ForRelayer(0xb2),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), dep); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	staleCheckpoint := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0xb3),
		FinalOrchardRoot: seq32ForRelayer(0xb4),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(
		context.Background(),
		"owner-1",
		seq32ForRelayer(0xb5),
		[][32]byte{dep.DepositID},
		staleCheckpoint,
		[][]byte{{0xaa}},
		[]byte{0xbb},
	); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}

	sender := &stubSender{err: errors.New("send should not be called")}
	r, err := New(Config{
		BaseChainID:       uint32(staleCheckpoint.BaseChainID),
		BridgeAddress:     staleCheckpoint.BridgeContract,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		ClaimTTL:          10 * time.Millisecond,
		Now:               time.Now,
	}, store, sender, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	time.Sleep(25 * time.Millisecond)

	if err := r.recoverSubmittedAttempts(context.Background()); err != nil {
		t.Fatalf("recoverSubmittedAttempts: %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("sender called %d times, want 0", sender.calls)
	}

	job, err := store.Get(context.Background(), dep.DepositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateConfirmed)
	}
	if job.TxHash != ([32]byte{}) {
		t.Fatalf("tx hash should be cleared, got %x", job.TxHash)
	}

	attempts, err := store.ClaimSubmittedAttempts(context.Background(), "worker-2", time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected submitted attempts to be cleared, got %d", len(attempts))
	}
}

func TestRelayer_ApplyBatchOutcomeFromHash_ReconcilesDuplicateSkippedDepositToOriginalMint(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	depositA := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x51),
		Commitment:    seq32ForRelayer(0x61),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	depositB := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x52),
		Commitment:    seq32ForRelayer(0x62),
		LeafIndex:     2,
		Amount:        700,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000789")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), depositA); err != nil {
		t.Fatalf("UpsertConfirmed(A): %v", err)
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), depositB); err != nil {
		t.Fatalf("UpsertConfirmed(B): %v", err)
	}

	batchID := seq32ForRelayer(0x70)
	txHash := seq32ForRelayer(0x71)
	originalMintTxHash := seq32ForRelayer(0x72)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0x73),
		FinalOrchardRoot: seq32ForRelayer(0x74),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(context.Background(), "owner-1", batchID, [][32]byte{depositA.DepositID, depositB.DepositID}, cp, nil, []byte{0x01}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	if err := store.SetBatchSubmissionTxHash(context.Background(), batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	mintedTopic := crypto.Keccak256Hash([]byte("Minted(bytes32,address,uint256,uint256,uint256)"))
	skippedTopic := crypto.Keccak256Hash([]byte("DepositSkipped(bytes32)"))
	bridge := cp.BridgeContract
	r, err := New(Config{
		BaseChainID:       uint32(cp.BaseChainID),
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
		ReceiptReader: &stubReceiptReader{
			receipt: &types.Receipt{
				Status:      types.ReceiptStatusSuccessful,
				BlockNumber: big.NewInt(50),
				Logs: []*types.Log{
					{Address: bridge, Topics: []common.Hash{mintedTopic, common.BytesToHash(depositA.DepositID[:])}},
					{Address: bridge, Topics: []common.Hash{skippedTopic, common.BytesToHash(depositB.DepositID[:])}},
				},
			},
			filterLogs: []types.Log{
				{
					Address:     bridge,
					Topics:      []common.Hash{mintedTopic, common.BytesToHash(depositB.DepositID[:])},
					BlockNumber: 50,
					TxIndex:     1,
					Index:       2,
					TxHash:      common.Hash(originalMintTxHash),
				},
			},
		},
	}, store, &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.applyBatchOutcomeFromHash(context.Background(), batchID, [][32]byte{depositA.DepositID, depositB.DepositID}, cp, []byte{0x01}, txHash); err != nil {
		t.Fatalf("applyBatchOutcomeFromHash: %v", err)
	}

	jobB, err := store.Get(context.Background(), depositB.DepositID)
	if err != nil {
		t.Fatalf("Get(B): %v", err)
	}
	if jobB.State != deposit.StateFinalized {
		t.Fatalf("jobB state: got %s want %s", jobB.State, deposit.StateFinalized)
	}
	if jobB.TxHash != originalMintTxHash {
		t.Fatalf("jobB tx hash: got %x want %x", jobB.TxHash, originalMintTxHash)
	}
	if jobB.RejectionReason != "" {
		t.Fatalf("jobB rejection reason: got %q want empty", jobB.RejectionReason)
	}
}

func TestRelayer_ApplyBatchOutcomeFromHash_RequeuesUnresolvedDepositsAfterPartialReceipt(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	depositA := deposit.Deposit{
		DepositID:     seq32ForRelayer(0xb1),
		Commitment:    seq32ForRelayer(0xc1),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	depositB := deposit.Deposit{
		DepositID:     seq32ForRelayer(0xb2),
		Commitment:    seq32ForRelayer(0xc2),
		LeafIndex:     2,
		Amount:        700,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000789")),
	}
	depositC := deposit.Deposit{
		DepositID:     seq32ForRelayer(0xb3),
		Commitment:    seq32ForRelayer(0xc3),
		LeafIndex:     3,
		Amount:        900,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000999")),
	}
	for _, dep := range []deposit.Deposit{depositA, depositB, depositC} {
		if _, _, err := store.UpsertConfirmed(context.Background(), dep); err != nil {
			t.Fatalf("UpsertConfirmed(%x): %v", dep.DepositID[:4], err)
		}
	}

	batchID := seq32ForRelayer(0xd0)
	txHash := seq32ForRelayer(0xd1)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0xd2),
		FinalOrchardRoot: seq32ForRelayer(0xd3),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(context.Background(), "owner-1", batchID, [][32]byte{depositA.DepositID, depositB.DepositID, depositC.DepositID}, cp, nil, []byte{0x01}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	if err := store.SetBatchSubmissionTxHash(context.Background(), batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	mintedTopic := crypto.Keccak256Hash([]byte("Minted(bytes32,address,uint256,uint256,uint256)"))
	skippedTopic := crypto.Keccak256Hash([]byte("DepositSkipped(bytes32)"))
	bridge := cp.BridgeContract
	r, err := New(Config{
		BaseChainID:       uint32(cp.BaseChainID),
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
		ReceiptReader: &stubReceiptReader{receipt: &types.Receipt{
			Status: types.ReceiptStatusSuccessful,
			Logs: []*types.Log{
				{Address: bridge, Topics: []common.Hash{mintedTopic, common.BytesToHash(depositA.DepositID[:])}},
				{Address: bridge, Topics: []common.Hash{skippedTopic, common.BytesToHash(depositB.DepositID[:])}},
			},
		}},
	}, store, &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.applyBatchOutcomeFromHash(context.Background(), batchID, [][32]byte{depositA.DepositID, depositB.DepositID, depositC.DepositID}, cp, []byte{0x01}, txHash); err != nil {
		t.Fatalf("applyBatchOutcomeFromHash: %v", err)
	}

	jobA, err := store.Get(context.Background(), depositA.DepositID)
	if err != nil {
		t.Fatalf("Get(A): %v", err)
	}
	if jobA.State != deposit.StateFinalized {
		t.Fatalf("jobA state: got %s want %s", jobA.State, deposit.StateFinalized)
	}

	jobB, err := store.Get(context.Background(), depositB.DepositID)
	if err != nil {
		t.Fatalf("Get(B): %v", err)
	}
	if jobB.State != deposit.StateRejected {
		t.Fatalf("jobB state: got %s want %s", jobB.State, deposit.StateRejected)
	}

	jobC, err := store.Get(context.Background(), depositC.DepositID)
	if err != nil {
		t.Fatalf("Get(C): %v", err)
	}
	if jobC.State != deposit.StateConfirmed {
		t.Fatalf("jobC state: got %s want %s", jobC.State, deposit.StateConfirmed)
	}
	if jobC.TxHash != ([32]byte{}) {
		t.Fatalf("jobC tx hash: got %x want empty", jobC.TxHash)
	}

	batch, err := store.GetBatch(context.Background(), batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if batch.State != deposit.BatchStateClosed {
		t.Fatalf("batch state: got %s want %s", batch.State, deposit.BatchStateClosed)
	}
	if len(batch.DepositIDs) != 1 || batch.DepositIDs[0] != depositC.DepositID {
		t.Fatalf("batch deposit ids: got %#v want only depositC", batch.DepositIDs)
	}

	attempts, err := store.ClaimSubmittedAttempts(context.Background(), "worker-2", time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("submitted attempts len: got %d want 0", len(attempts))
	}
}

func TestRelayer_ApplyBatchOutcomeFromHash_RepairsPreviouslyRejectedDuplicateSkippedDeposit(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	depositA := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x81),
		Commitment:    seq32ForRelayer(0x91),
		LeafIndex:     1,
		Amount:        500,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}
	depositB := deposit.Deposit{
		DepositID:     seq32ForRelayer(0x82),
		Commitment:    seq32ForRelayer(0x92),
		LeafIndex:     2,
		Amount:        700,
		BaseRecipient: to20(common.HexToAddress("0x0000000000000000000000000000000000000789")),
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), depositA); err != nil {
		t.Fatalf("UpsertConfirmed(A): %v", err)
	}
	if _, _, err := store.UpsertConfirmed(context.Background(), depositB); err != nil {
		t.Fatalf("UpsertConfirmed(B): %v", err)
	}

	batchID := seq32ForRelayer(0xa0)
	txHash := seq32ForRelayer(0xa1)
	originalMintTxHash := seq32ForRelayer(0xa2)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        seq32ForRelayer(0xa3),
		FinalOrchardRoot: seq32ForRelayer(0xa4),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := store.MarkBatchSubmitted(context.Background(), "owner-1", batchID, [][32]byte{depositA.DepositID, depositB.DepositID}, cp, nil, []byte{0x01}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	if err := store.SetBatchSubmissionTxHash(context.Background(), batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}
	if err := store.MarkRejected(context.Background(), depositB.DepositID, "deposit skipped by bridge", txHash); err != nil {
		t.Fatalf("MarkRejected: %v", err)
	}

	mintedTopic := crypto.Keccak256Hash([]byte("Minted(bytes32,address,uint256,uint256,uint256)"))
	skippedTopic := crypto.Keccak256Hash([]byte("DepositSkipped(bytes32)"))
	bridge := cp.BridgeContract
	r, err := New(Config{
		BaseChainID:       uint32(cp.BaseChainID),
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000999")},
		OperatorThreshold: 1,
		MaxItems:          10,
		MaxAge:            time.Minute,
		DedupeMax:         100,
		Now:               time.Now,
		ReceiptReader: &stubReceiptReader{
			receipt: &types.Receipt{
				Status:      types.ReceiptStatusSuccessful,
				BlockNumber: big.NewInt(50),
				Logs: []*types.Log{
					{Address: bridge, Topics: []common.Hash{mintedTopic, common.BytesToHash(depositA.DepositID[:])}},
					{Address: bridge, Topics: []common.Hash{skippedTopic, common.BytesToHash(depositB.DepositID[:])}},
				},
			},
			filterLogs: []types.Log{
				{
					Address:     bridge,
					Topics:      []common.Hash{mintedTopic, common.BytesToHash(depositB.DepositID[:])},
					BlockNumber: 50,
					TxIndex:     1,
					Index:       2,
					TxHash:      common.Hash(originalMintTxHash),
				},
			},
		},
	}, store, &stubSender{}, &stubProofRequester{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.applyBatchOutcomeFromHash(context.Background(), batchID, [][32]byte{depositA.DepositID, depositB.DepositID}, cp, []byte{0x01}, txHash); err != nil {
		t.Fatalf("applyBatchOutcomeFromHash: %v", err)
	}

	jobB, err := store.Get(context.Background(), depositB.DepositID)
	if err != nil {
		t.Fatalf("Get(B): %v", err)
	}
	if jobB.State != deposit.StateFinalized {
		t.Fatalf("jobB state: got %s want %s", jobB.State, deposit.StateFinalized)
	}
	if jobB.TxHash != originalMintTxHash {
		t.Fatalf("jobB tx hash: got %x want %x", jobB.TxHash, originalMintTxHash)
	}
	if jobB.RejectionReason != "" {
		t.Fatalf("jobB rejection reason: got %q want empty", jobB.RejectionReason)
	}
}

func TestRelayer_SubmitsOnMaxItems(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])

	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])

	m := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}
	memoBytes := m.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		GasLimit:          55555,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	if sender.calls != 1 {
		t.Fatalf("sender calls: got %d want %d", sender.calls, 1)
	}
	if len(prover.gotReq.PrivateInput) == 0 {
		t.Fatalf("expected proof requester private input")
	}
	if got, want := prover.gotReq.Pipeline, "deposit"; got != want {
		t.Fatalf("proof pipeline: got %q want %q", got, want)
	}
	if prover.gotReq.JobID == (common.Hash{}) {
		t.Fatalf("expected non-zero proof job id")
	}
	if len(sender.got) != 1 {
		t.Fatalf("sender got len: got %d", len(sender.got))
	}
	req := sender.got[0]
	if req.To != bridge.Hex() {
		t.Fatalf("To: got %s want %s", req.To, bridge.Hex())
	}
	if !strings.HasPrefix(req.Data, "0x53a58a48") {
		t.Fatalf("Data selector: got %s", req.Data)
	}
	if req.GasLimit != 55555 {
		t.Fatalf("GasLimit: got %d want %d", req.GasLimit, 55555)
	}

	// Decode and sanity-check the deposit journal passed to the prover.
	journalType := mustType(t, "tuple", []abi.ArgumentMarshaling{
		{Name: "finalOrchardRoot", Type: "bytes32"},
		{Name: "baseChainId", Type: "uint256"},
		{Name: "bridgeContract", Type: "address"},
		{Name: "items", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
			{Name: "depositId", Type: "bytes32"},
			{Name: "recipient", Type: "address"},
			{Name: "amount", Type: "uint256"},
		}},
	})
	args := abi.Arguments{{Name: "dj", Type: journalType}}
	vals, err := args.Unpack(prover.gotReq.Journal)
	if err != nil {
		t.Fatalf("unpack journal: %v", err)
	}
	v := reflect.ValueOf(vals[0])
	gotRoot := v.FieldByName("FinalOrchardRoot").Interface().([32]byte)
	if gotRoot != cp.FinalOrchardRoot {
		t.Fatalf("FinalOrchardRoot mismatch")
	}
	gotBridge := v.FieldByName("BridgeContract").Interface().(common.Address)
	if gotBridge != bridge {
		t.Fatalf("BridgeContract mismatch")
	}
	items := v.FieldByName("Items")
	if items.Len() != 1 {
		t.Fatalf("items len: got %d", items.Len())
	}
	it := items.Index(0)
	gotRecipient := it.FieldByName("Recipient").Interface().(common.Address)
	if gotRecipient != recipient {
		t.Fatalf("recipient mismatch")
	}
	gotAmt := it.FieldByName("Amount").Interface().(*big.Int)
	if gotAmt.Cmp(big.NewInt(1000)) != 0 {
		t.Fatalf("amount mismatch: got %s", gotAmt.String())
	}
	gotDepID := it.FieldByName("DepositId").Interface().([32]byte)
	wantDepID := idempotency.MustDepositIDV1(cm, 7)
	if gotDepID != wantDepID {
		t.Fatalf("depositId mismatch: got %x want %x", gotDepID, wantDepID)
	}
}

func TestRelayer_DedupesDeposits(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])

	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])

	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	dep := DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}
	if err := r.IngestDeposit(ctx, dep); err != nil {
		t.Fatalf("IngestDeposit #1: %v", err)
	}
	if err := r.IngestDeposit(ctx, dep); err != nil {
		t.Fatalf("IngestDeposit #2: %v", err)
	}

	if sender.calls != 1 {
		t.Fatalf("sender calls: got %d want %d", sender.calls, 1)
	}
}

func TestRelayer_ProcessesConfirmedDepositsFromStore(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])

	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])

	var cm common.Hash
	cm[0] = 0xaa
	depositID := idempotency.MustDepositIDV1(cm, 7)

	store := deposit.NewMemoryStore()
	if _, _, err := store.UpsertConfirmed(context.Background(), deposit.Deposit{
		DepositID:        depositID,
		Commitment:       [32]byte(cm),
		LeafIndex:        7,
		Amount:           1000,
		BaseRecipient:    [20]byte(recipient),
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	if sender.calls != 1 {
		t.Fatalf("sender calls: got %d want %d", sender.calls, 1)
	}

	got, err := store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got.State != deposit.StateFinalized {
		t.Fatalf("state: got %v want %v", got.State, deposit.StateFinalized)
	}
}

func TestRelayer_DoesNotClaimDepositsWhenBaseRelayerNotReady(t *testing.T) {
	t.Parallel()

	store := deposit.NewMemoryStore()
	ctx := context.Background()

	bridgeAddr := common.HexToAddress("0x0000000000000000000000000000000000000123")
	cp := checkpoint.Checkpoint{
		Height:         1,
		BaseChainID:    31337,
		BridgeContract: bridgeAddr,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)
	sender := &stubSender{
		res: httpapi.SendResponse{TxHash: "0xabc", Receipt: &httpapi.ReceiptResponse{Status: 1}},
	}
	readiness := &stubReadinessChecker{err: errors.New("underfunded")}
	r, err := New(Config{
		BaseChainID:       uint32(cp.BaseChainID),
		BridgeAddress:     bridgeAddr,
		DepositImageID:    common.HexToHash("0x01"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            time.Minute,
		DedupeMax:         16,
		Owner:             "relayer-a",
		ClaimTTL:          10 * time.Second,
		GasLimit:          120_000,
		ReadinessChecker:  readiness,
	}, store, sender, &stubProofRequester{res: proofclient.Result{Seal: []byte{0x01}}}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{
		Checkpoint:         cp,
		OperatorSignatures: checkpointSigs,
	}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	var commitment [32]byte
	commitment[0] = 0x42

	depID, err := idempotency.DepositIDV1(commitment, 7)
	if err != nil {
		t.Fatalf("DepositIDV1: %v", err)
	}
	if _, _, err := store.UpsertConfirmed(ctx, deposit.Deposit{
		DepositID:     depID,
		Commitment:    commitment,
		LeafIndex:     7,
		Amount:        1000,
		BaseRecipient: [20]byte(common.HexToAddress("0x0000000000000000000000000000000000000456")),
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	if err := r.FlushDue(ctx); err != nil {
		t.Fatalf("FlushDue: %v", err)
	}
	if readiness.calls == 0 {
		t.Fatalf("expected readiness checks")
	}
	if sender.calls != 0 {
		t.Fatalf("expected no send calls, got %d", sender.calls)
	}

	jobs, err := store.ClaimConfirmed(ctx, "other", 10*time.Second, 1)
	if err != nil {
		t.Fatalf("ClaimConfirmed: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("expected deposit to remain claimable, got %d jobs", len(jobs))
	}
}

func TestRelayer_SubmitFailsOnRevertedReceipt(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])

	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])

	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	sender := &stubSender{
		res: httpapi.SendResponse{
			TxHash: "0x01",
			Receipt: &httpapi.ReceiptResponse{
				Status: 0,
			},
		},
	}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	err = r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	})
	if err == nil {
		t.Fatalf("expected error")
	}

	if sender.calls != 1 {
		t.Fatalf("sender calls: got %d want %d", sender.calls, 1)
	}
}

func TestRelayer_QueuesUntilCheckpoint(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])

	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])

	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}
	if sender.calls != 0 {
		t.Fatalf("sender calls: got %d want %d", sender.calls, 0)
	}

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	if sender.calls != 1 {
		t.Fatalf("sender calls after checkpoint: got %d want %d", sender.calls, 1)
	}
}

func TestRelayer_RejectsInvalidOperatorSignature(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}
	operatorAddrs, _ := mustSignedCheckpoint(t, cp)

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	// Bad length (must be 65 bytes with v in {27,28}).
	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: [][]byte{[]byte{0x01}}}); err == nil {
		t.Fatalf("expected error")
	}
}

func TestRelayer_FinalizeStoreFailureLeavesDepositSubmitted(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])

	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])

	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	depositID := idempotency.MustDepositIDV1([32]byte(cm), 7)
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	baseStore := deposit.NewMemoryStore()
	store := &finalizeFailStore{
		Store: baseStore,
		err:   errors.New("db unavailable"),
	}

	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	err = r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	})
	if err == nil {
		t.Fatalf("expected ingest error")
	}

	job, err := baseStore.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got, want := job.State, deposit.StateSubmitted; got != want {
		t.Fatalf("state: got %v want %v", got, want)
	}
}

func TestRelayer_ClaimConfirmedPreventsDuplicateWorkerSends(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var cm common.Hash
	cm[0] = 0xaa
	depositID := idempotency.MustDepositIDV1([32]byte(cm), 7)

	store := deposit.NewMemoryStore()

	sender1 := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	sender2 := &stubSender{res: httpapi.SendResponse{TxHash: "0x02", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover1 := newBlockingProofRequester(proofclient.Result{Seal: []byte{0x99}})
	prover2 := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r1, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Owner:             "worker-1",
		Now:               time.Now,
	}, store, sender1, prover1, nil)
	if err != nil {
		t.Fatalf("New worker 1: %v", err)
	}
	r2, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Owner:             "worker-2",
		Now:               time.Now,
	}, store, sender2, prover2, nil)
	if err != nil {
		t.Fatalf("New worker 2: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	if err := r1.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("r1 IngestCheckpoint: %v", err)
	}
	if err := r2.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("r2 IngestCheckpoint: %v", err)
	}

	if _, _, err := store.UpsertConfirmed(context.Background(), deposit.Deposit{
		DepositID:        depositID,
		Commitment:       [32]byte(cm),
		LeafIndex:        7,
		Amount:           1000,
		BaseRecipient:    [20]byte(recipient),
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- r1.Flush(ctx)
	}()

	prover1.waitEntered(t, time.Second)

	job, err := store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get during proof request: %v", err)
	}
	if got, want := job.State, deposit.StateProofRequested; got != want {
		t.Fatalf("state during proof request: got %v want %v", got, want)
	}

	if err := r2.Flush(ctx); err != nil {
		t.Fatalf("r2 Flush: %v", err)
	}
	if sender2.calls != 0 {
		t.Fatalf("worker 2 sent tx: got %d want 0", sender2.calls)
	}

	prover1.release()
	if err := <-errCh; err != nil {
		t.Fatalf("r1 Flush: %v", err)
	}
	if sender1.calls != 1 {
		t.Fatalf("worker 1 sender calls: got %d want 1", sender1.calls)
	}
}

func TestRelayer_RetriesSubmittedDepositsOnLaterFlush(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	depositID := idempotency.MustDepositIDV1([32]byte(cm), 7)
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	store := deposit.NewMemoryStore()
	sender := &scriptedSender{
		plan: []scriptedSenderStep{
			{
				err: errors.New("temporary send error"),
			},
			{
				res: httpapi.SendResponse{
					TxHash:  "0x01",
					Receipt: &httpapi.ReceiptResponse{Status: 1},
				},
			},
		},
	}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	err = r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	})
	if err == nil {
		t.Fatalf("expected initial submit error")
	}
	if sender.calls != 1 {
		t.Fatalf("sender calls after first attempt: got %d want 1", sender.calls)
	}

	job, err := store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get after failed send: %v", err)
	}
	if got, want := job.State, deposit.StateSubmitted; got != want {
		t.Fatalf("state after failed send: got %v want %v", got, want)
	}

	if err := r.Flush(ctx); err != nil {
		t.Fatalf("Flush retry: %v", err)
	}
	if sender.calls != 2 {
		t.Fatalf("sender calls after retry: got %d want 2", sender.calls)
	}

	job, err = store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get after retry: %v", err)
	}
	if got, want := job.State, deposit.StateFinalized; got != want {
		t.Fatalf("state after retry: got %v want %v", got, want)
	}
}

func TestRelayer_ResumesSubmittedAttemptWithoutRequestingNewProof(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	depositID := idempotency.MustDepositIDV1([32]byte(cm), 7)
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	store := deposit.NewMemoryStore()
	initialSender := &scriptedSender{
		plan: []scriptedSenderStep{{err: errors.New("temporary send error")}},
	}
	initialProver := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r1, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Owner:             "worker-1",
		Now:               time.Now,
	}, store, initialSender, initialProver, nil)
	if err != nil {
		t.Fatalf("New worker 1: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r1.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("r1 IngestCheckpoint: %v", err)
	}
	err = r1.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	})
	if err == nil {
		t.Fatalf("expected initial submit error")
	}

	job, err := store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get after first attempt: %v", err)
	}
	if got, want := job.State, deposit.StateSubmitted; got != want {
		t.Fatalf("state after first attempt: got %v want %v", got, want)
	}

	resumeSender := &scriptedSender{
		plan: []scriptedSenderStep{{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}},
	}
	resumeProver := &stubProofRequester{err: errors.New("proof should not be requested on resume")}

	r2, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Owner:             "worker-2",
		Now:               time.Now,
	}, store, resumeSender, resumeProver, nil)
	if err != nil {
		t.Fatalf("New worker 2: %v", err)
	}

	if err := r2.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("r2 IngestCheckpoint: %v", err)
	}
	if err := r2.Flush(ctx); err != nil {
		t.Fatalf("r2 Flush: %v", err)
	}
	if resumeSender.calls != 1 {
		t.Fatalf("resume sender calls: got %d want 1", resumeSender.calls)
	}
	if initialProver.gotReq.JobID == (common.Hash{}) {
		t.Fatalf("expected initial proof request to occur")
	}
	if resumeProver.gotReq.JobID != (common.Hash{}) {
		t.Fatalf("resume relayer should not request a new proof")
	}

	job, err = store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get after resume: %v", err)
	}
	if got, want := job.State, deposit.StateFinalized; got != want {
		t.Fatalf("state after resume: got %v want %v", got, want)
	}
}

func TestRelayer_UsesBinaryGuestInputWhenConfigured(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var ivk [64]byte
	for i := range ivk {
		ivk[i] = byte(i + 1)
	}
	witness := bytes.Repeat([]byte{0x44}, proverinput.DepositWitnessItemLen)

	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		GasLimit:          55555,
		Now:               time.Now,
		OWalletIVKBytes:   ivk[:],
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}
	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: witness,
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	wantInput, err := proverinput.EncodeDepositGuestPrivateInput(cp, ivk, [][]byte{witness})
	if err != nil {
		t.Fatalf("EncodeDepositGuestPrivateInput: %v", err)
	}
	if !bytes.Equal(prover.gotReq.PrivateInput, wantInput) {
		t.Fatalf("proof requester private input mismatch")
	}
}

func TestRelayer_RefreshesGuestWitnessToCheckpointAnchor(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	var ivk [64]byte
	for i := range ivk {
		ivk[i] = byte(i + 1)
	}
	originalWitness := bytes.Repeat([]byte{0x44}, proverinput.DepositWitnessItemLen)
	refreshedWitness := bytes.Repeat([]byte{0x55}, proverinput.DepositWitnessItemLen)
	refresher := &stubDepositWitnessRefresher{
		root: cp.FinalOrchardRoot,
		item: refreshedWitness,
	}

	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:             baseChainID,
		BridgeAddress:           bridge,
		DepositImageID:          common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OperatorAddresses:       operatorAddrs,
		OperatorThreshold:       1,
		MaxItems:                1,
		MaxAge:                  10 * time.Minute,
		DedupeMax:               1000,
		GasLimit:                55555,
		Now:                     time.Now,
		OWalletIVKBytes:         ivk[:],
		DepositWitnessRefresher: refresher,
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}
	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: originalWitness,
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	if refresher.gotAnchorHeight != int64(cp.Height) {
		t.Fatalf("anchor height mismatch: got=%d want=%d", refresher.gotAnchorHeight, cp.Height)
	}
	if !bytes.Equal(refresher.gotWitnessItem, originalWitness) {
		t.Fatalf("refresher witness mismatch")
	}

	wantInput, err := proverinput.EncodeDepositGuestPrivateInput(cp, ivk, [][]byte{refreshedWitness})
	if err != nil {
		t.Fatalf("EncodeDepositGuestPrivateInput: %v", err)
	}
	if !bytes.Equal(prover.gotReq.PrivateInput, wantInput) {
		t.Fatalf("proof requester private input mismatch after refresh")
	}
}

func TestRelayer_DefersGuestWitnessRefreshUntilCheckpointCoversDepositHeight(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	initialCP := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}
	nextCP := checkpoint.Checkpoint{
		Height:           124,
		BlockHash:        common.HexToHash("0x2102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x2112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, initialSigs := mustSignedCheckpoint(t, initialCP)
	_, nextSigs := mustSignedCheckpoint(t, nextCP)

	var ivk [64]byte
	for i := range ivk {
		ivk[i] = byte(i + 1)
	}
	originalWitness := bytes.Repeat([]byte{0x44}, proverinput.DepositWitnessItemLen)
	refreshedWitness := bytes.Repeat([]byte{0x55}, proverinput.DepositWitnessItemLen)
	refresher := &stubDepositWitnessRefresher{
		root: nextCP.FinalOrchardRoot,
		item: refreshedWitness,
	}

	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}
	store := deposit.NewMemoryStore()

	r, err := New(Config{
		BaseChainID:             baseChainID,
		BridgeAddress:           bridge,
		DepositImageID:          common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OperatorAddresses:       operatorAddrs,
		OperatorThreshold:       1,
		MaxItems:                1,
		MaxAge:                  10 * time.Minute,
		DedupeMax:               1000,
		GasLimit:                55555,
		Now:                     time.Now,
		OWalletIVKBytes:         ivk[:],
		DepositWitnessRefresher: refresher,
		RuntimeSettings: &stubDepositRuntimeSettingsProvider{settings: runtimeconfig.Settings{
			DepositMinConfirmations:         1,
			WithdrawPlannerMinConfirmations: 1,
			WithdrawBatchConfirmations:      1,
		}},
		BridgeSettings: &stubDepositBridgeSettingsProvider{snapshot: bridgeconfig.Snapshot{
			MinDepositAmount: 1,
		}},
		TipHeightProvider: &stubTipHeightProvider{height: 124},
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: initialCP, OperatorSignatures: initialSigs}); err != nil {
		t.Fatalf("IngestCheckpoint(initial): %v", err)
	}
	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		JunoHeight:       124,
		Memo:             memoBytes[:],
		ProofWitnessItem: originalWitness,
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	if refresher.gotCalls != 0 {
		t.Fatalf("refresher calls after lagging checkpoint: got=%d want=0", refresher.gotCalls)
	}
	if sender.calls != 0 {
		t.Fatalf("sender calls after lagging checkpoint: got=%d want=0", sender.calls)
	}
	if prover.gotReq.JobID != (common.Hash{}) {
		t.Fatalf("expected no proof request before checkpoint catches up")
	}
	job, err := store.Get(ctx, idempotency.MustDepositIDV1([32]byte(cm), 7))
	if err != nil {
		t.Fatalf("Get before catch-up: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("job state before catch-up: got=%s want=%s", job.State, deposit.StateConfirmed)
	}

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: nextCP, OperatorSignatures: nextSigs}); err != nil {
		t.Fatalf("IngestCheckpoint(next): %v", err)
	}

	if refresher.gotCalls != 1 {
		t.Fatalf("refresher calls after catch-up: got=%d want=1", refresher.gotCalls)
	}
	if refresher.gotAnchorHeight != int64(nextCP.Height) {
		t.Fatalf("anchor height after catch-up: got=%d want=%d", refresher.gotAnchorHeight, nextCP.Height)
	}
	if sender.calls != 1 {
		t.Fatalf("sender calls after catch-up: got=%d want=1", sender.calls)
	}
	wantInput, err := proverinput.EncodeDepositGuestPrivateInput(nextCP, ivk, [][]byte{refreshedWitness})
	if err != nil {
		t.Fatalf("EncodeDepositGuestPrivateInput: %v", err)
	}
	if !bytes.Equal(prover.gotReq.PrivateInput, wantInput) {
		t.Fatalf("proof requester private input mismatch after checkpoint catch-up")
	}
}

func TestRelayer_ErrorsWhenGuestInputConfiguredButWitnessMissing(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()
	var cm common.Hash
	cm[0] = 0xaa

	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)
	var ivk [64]byte
	ivk[0] = 0x01

	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		Now:               time.Now,
		OWalletIVKBytes:   ivk[:],
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	err = r.IngestDeposit(ctx, DepositEvent{
		Commitment: cm,
		LeafIndex:  7,
		Amount:     1000,
		Memo:       memoBytes[:],
	})
	if err == nil {
		t.Fatalf("expected missing witness error")
	}
	if !strings.Contains(err.Error(), "proof witness item") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func mustHexToBytes(t *testing.T, s string) []byte {
	t.Helper()

	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

func TestRelayer_DLQ_ProofAttemptsExhausted(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	// Prover always fails.
	prover := &stubProofRequester{err: errors.New("sp1 unavailable")}
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	dlqStore := dlq.NewMemoryStore(nil)
	store := deposit.NewMemoryStore()

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		MaxProofAttempts:  2,
		DLQStore:          dlqStore,
		Now:               time.Now,
	}, store, sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	// Ingest checkpoint first (no deposits yet, so no submit).
	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	// Ingest deposit -> triggers submit -> proof fails (attempt 1 of 2).
	_ = r.IngestDeposit(ctx, DepositEvent{
		Commitment: cm,
		LeafIndex:  7,
		Amount:     1000,
		Memo:       memoBytes[:],
	})

	// Flush again -> triggers submit -> proof fails (attempt 2 >= MaxProofAttempts=2).
	// Should trigger DLQ insertion.
	_ = r.Flush(ctx)

	counts, cerr := dlqStore.CountUnacknowledged(ctx)
	if cerr != nil {
		t.Fatalf("CountUnacknowledged: %v", cerr)
	}
	if counts.DepositBatches != 1 {
		t.Fatalf("expected 1 deposit batch DLQ entry, got %d", counts.DepositBatches)
	}

	recs, lerr := dlqStore.ListDepositBatchDLQ(ctx, dlq.DLQFilter{})
	if lerr != nil {
		t.Fatalf("ListDepositBatchDLQ: %v", lerr)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 DLQ record, got %d", len(recs))
	}
	if recs[0].FailureStage != "proof" {
		t.Fatalf("failure_stage: got %q want %q", recs[0].FailureStage, "proof")
	}
}

func TestRelayer_DLQInsertFailureKeepsProofAttemptsRetryable(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	prover := &stubProofRequester{err: errors.New("sp1 unavailable")}
	sender := &stubSender{res: httpapi.SendResponse{TxHash: "0x01", Receipt: &httpapi.ReceiptResponse{Status: 1}}}
	dlqStore := newFlakyDLQStore()
	dlqStore.depositErrs = []error{errors.New("deposit dlq unavailable")}

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		MaxProofAttempts:  1,
		DLQStore:          dlqStore,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	err = r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	})
	if err == nil {
		t.Fatal("expected dlq persistence error")
	}
	if errors.Is(err, ErrProofAttemptsExhausted) {
		t.Fatalf("expected retryable DLQ error, got terminal exhaustion: %v", err)
	}
	if !strings.Contains(err.Error(), "deposit batch DLQ") {
		t.Fatalf("expected deposit DLQ error, got %v", err)
	}
	if len(r.proofAttempts) != 1 {
		t.Fatalf("expected proofAttempts to be retained, got %d entries", len(r.proofAttempts))
	}
	for _, attempts := range r.proofAttempts {
		if attempts != 1 {
			t.Fatalf("expected retained attempt count 1, got %d", attempts)
		}
	}

	counts, cerr := dlqStore.CountUnacknowledged(ctx)
	if cerr != nil {
		t.Fatalf("CountUnacknowledged: %v", cerr)
	}
	if counts.DepositBatches != 0 {
		t.Fatalf("expected no DLQ record after failed insert, got %d", counts.DepositBatches)
	}

	dlqStore.depositErrs = nil
	err = r.Flush(ctx)
	if err == nil {
		t.Fatal("expected ErrProofAttemptsExhausted after DLQ recovery")
	}
	if !errors.Is(err, ErrProofAttemptsExhausted) {
		t.Fatalf("expected ErrProofAttemptsExhausted, got %v", err)
	}
	if len(r.proofAttempts) != 0 {
		t.Fatalf("expected proofAttempts cleared after durable DLQ insert, got %d entries", len(r.proofAttempts))
	}

	counts, cerr = dlqStore.CountUnacknowledged(ctx)
	if cerr != nil {
		t.Fatalf("CountUnacknowledged after retry: %v", cerr)
	}
	if counts.DepositBatches != 1 {
		t.Fatalf("expected 1 deposit batch DLQ entry after retry, got %d", counts.DepositBatches)
	}
}

func TestRelayer_DLQ_BridgeTxReverted(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	// Tx reverts (status 0).
	sender := &stubSender{
		res: httpapi.SendResponse{
			TxHash:  "0xdeadbeef",
			Receipt: &httpapi.ReceiptResponse{Status: 0, RevertReason: "bridge paused"},
		},
	}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}
	dlqStore := dlq.NewMemoryStore(nil)

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		DLQStore:          dlqStore,
		Now:               time.Now,
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	err = r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	})
	if err == nil {
		t.Fatalf("expected error from reverted tx")
	}

	counts, cerr := dlqStore.CountUnacknowledged(ctx)
	if cerr != nil {
		t.Fatalf("CountUnacknowledged: %v", cerr)
	}
	if counts.DepositBatches != 1 {
		t.Fatalf("expected 1 deposit batch DLQ entry, got %d", counts.DepositBatches)
	}

	recs, lerr := dlqStore.ListDepositBatchDLQ(ctx, dlq.DLQFilter{})
	if lerr != nil {
		t.Fatalf("ListDepositBatchDLQ: %v", lerr)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 DLQ record, got %d", len(recs))
	}
	if recs[0].FailureStage != "bridge_tx" {
		t.Fatalf("failure_stage: got %q want %q", recs[0].FailureStage, "bridge_tx")
	}
	if !strings.Contains(recs[0].ErrorMessage, "bridge paused") {
		t.Fatalf("expected revert reason in DLQ error message, got %q", recs[0].ErrorMessage)
	}
}

func TestRelayer_StaleCheckpointTxRevertResetsBatchInsteadOfDLQ(t *testing.T) {
	t.Parallel()

	bridge := common.HexToAddress("0x0000000000000000000000000000000000000123")
	baseChainID := uint32(31337)

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      uint64(baseChainID),
		BridgeContract:   bridge,
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	recipient := common.HexToAddress("0x0000000000000000000000000000000000000456")
	var recip20 [20]byte
	copy(recip20[:], recipient[:])
	memoBytes := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recip20,
		Nonce:         1,
		Flags:         0,
	}.Encode()

	heightCall, err := bridgeabi.PackLastAcceptedCheckpointHeightCalldata()
	if err != nil {
		t.Fatalf("PackLastAcceptedCheckpointHeightCalldata: %v", err)
	}
	blockHashCall, err := bridgeabi.PackLastAcceptedCheckpointBlockHashCalldata()
	if err != nil {
		t.Fatalf("PackLastAcceptedCheckpointBlockHashCalldata: %v", err)
	}
	rootCall, err := bridgeabi.PackLastAcceptedCheckpointFinalOrchardRootCalldata()
	if err != nil {
		t.Fatalf("PackLastAcceptedCheckpointFinalOrchardRootCalldata: %v", err)
	}
	acceptedBlockHash := common.HexToHash("0x2202030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
	acceptedRoot := common.HexToHash("0x2212131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30")

	var cm common.Hash
	cm[0] = 0xaa
	operatorAddrs, checkpointSigs := mustSignedCheckpoint(t, cp)

	sender := &stubSender{
		res: httpapi.SendResponse{
			TxHash: "0xdeadbeef",
			Receipt: &httpapi.ReceiptResponse{
				Status:       0,
				RevertReason: "CheckpointHeightRegression(123,124)",
			},
		},
	}
	prover := &stubProofRequester{res: proofclient.Result{Seal: []byte{0x99}}}
	dlqStore := dlq.NewMemoryStore(nil)

	r, err := New(Config{
		BaseChainID:       baseChainID,
		BridgeAddress:     bridge,
		DepositImageID:    common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000d001"),
		OWalletIVKBytes:   testOWalletIVKBytes(),
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: 1,
		MaxItems:          1,
		MaxAge:            10 * time.Minute,
		DedupeMax:         1000,
		DLQStore:          dlqStore,
		Now:               time.Now,
		BridgeCaller: &stubBridgeCaller{responses: map[string][]byte{
			hex.EncodeToString(heightCall[:4]):    common.LeftPadBytes(big.NewInt(124).Bytes(), 32),
			hex.EncodeToString(blockHashCall[:4]): acceptedBlockHash.Bytes(),
			hex.EncodeToString(rootCall[:4]):      acceptedRoot.Bytes(),
		}},
	}, deposit.NewMemoryStore(), sender, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)

	if err := r.IngestCheckpoint(ctx, CheckpointPackage{Checkpoint: cp, OperatorSignatures: checkpointSigs}); err != nil {
		t.Fatalf("IngestCheckpoint: %v", err)
	}

	if err := r.IngestDeposit(ctx, DepositEvent{
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		Memo:             memoBytes[:],
		ProofWitnessItem: testDepositWitnessItem(),
	}); err != nil {
		t.Fatalf("IngestDeposit: %v", err)
	}

	counts, cerr := dlqStore.CountUnacknowledged(ctx)
	if cerr != nil {
		t.Fatalf("CountUnacknowledged: %v", cerr)
	}
	if counts.DepositBatches != 0 {
		t.Fatalf("expected no deposit batch DLQ entries, got %d", counts.DepositBatches)
	}

	depositID, err := idempotency.DepositIDV1([32]byte(cm), 7)
	if err != nil {
		t.Fatalf("DepositIDV1: %v", err)
	}
	job, err := r.store.Get(ctx, depositID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateConfirmed)
	}
}
