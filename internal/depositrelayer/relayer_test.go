package depositrelayer

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/proofclient"
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
		Commitment: cm,
		LeafIndex:  7,
		Amount:     1000,
		Memo:       memoBytes[:],
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
	wantDepID := idempotency.DepositIDV1(cm, 7)
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
		Commitment: cm,
		LeafIndex:  7,
		Amount:     1000,
		Memo:       memoBytes[:],
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
	depositID := idempotency.DepositIDV1(cm, 7)

	store := deposit.NewMemoryStore()
	if _, _, err := store.UpsertConfirmed(context.Background(), deposit.Deposit{
		DepositID:     depositID,
		Commitment:    [32]byte(cm),
		LeafIndex:     7,
		Amount:        1000,
		BaseRecipient: [20]byte(recipient),
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
		Commitment: cm,
		LeafIndex:  7,
		Amount:     1000,
		Memo:       memoBytes[:],
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
		Commitment: cm,
		LeafIndex:  7,
		Amount:     1000,
		Memo:       memoBytes[:],
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

func mustHexToBytes(t *testing.T, s string) []byte {
	t.Helper()

	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}
