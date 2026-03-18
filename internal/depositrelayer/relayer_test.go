package depositrelayer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
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
	"github.com/juno-intents/intents-juno/internal/bridgeconfig"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/dlq"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
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
	gotReq proofclient.Request
	res    proofclient.Result
	err    error
}

func (p *stubProofRequester) RequestProof(_ context.Context, req proofclient.Request) (proofclient.Result, error) {
	p.gotReq = req
	p.gotReq.Journal = append([]byte(nil), req.Journal...)
	p.gotReq.PrivateInput = append([]byte(nil), req.PrivateInput...)
	return p.res, p.err
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
