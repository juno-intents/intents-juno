package withdrawcoordinator

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
)

type stubExtendSender struct {
	reqs []httpapi.SendRequest
	res  httpapi.SendResponse
	err  error
}

func (s *stubExtendSender) Send(_ context.Context, req httpapi.SendRequest) (httpapi.SendResponse, error) {
	s.reqs = append(s.reqs, req)
	return s.res, s.err
}

type stubExtendSigner struct {
	lastDigest common.Hash
	sigs       [][]byte
	err        error
}

func (s *stubExtendSigner) SignExtendDigest(_ context.Context, digest common.Hash) ([][]byte, error) {
	s.lastDigest = digest
	return s.sigs, s.err
}

func TestBaseExpiryExtender_Extend(t *testing.T) {
	t.Parallel()

	cfg := BaseExpiryExtenderConfig{
		BaseChainID:   8453,
		BridgeAddress: common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		GasLimit:      500_000,
	}

	signer := &stubExtendSigner{
		sigs: [][]byte{[]byte{0x01}, []byte{0x02}},
	}
	sender := &stubExtendSender{
		res: httpapi.SendResponse{
			TxHash: "0xabc",
			Receipt: &httpapi.ReceiptResponse{
				Status: 1,
			},
		},
	}

	ext, err := NewBaseExpiryExtender(cfg, sender, signer)
	if err != nil {
		t.Fatalf("NewBaseExpiryExtender: %v", err)
	}

	id0 := [32]byte(common.HexToHash("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	id1 := [32]byte(common.HexToHash("0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
	ids := [][32]byte{id0, id1}
	newExpiry := time.Unix(1730000000, 0).UTC()

	if err := ext.Extend(context.Background(), ids, newExpiry); err != nil {
		t.Fatalf("Extend: %v", err)
	}

	wantDigest, err := checkpoint.ExtendWithdrawDigest(ids, uint64(newExpiry.Unix()), cfg.BaseChainID, cfg.BridgeAddress)
	if err != nil {
		t.Fatalf("ExtendWithdrawDigest: %v", err)
	}
	if signer.lastDigest != wantDigest {
		t.Fatalf("sign digest mismatch: got %s want %s", signer.lastDigest, wantDigest)
	}

	if len(sender.reqs) != 1 {
		t.Fatalf("sender req count: got %d want 1", len(sender.reqs))
	}
	req := sender.reqs[0]
	if req.To != cfg.BridgeAddress.Hex() {
		t.Fatalf("request to mismatch: got %s want %s", req.To, cfg.BridgeAddress.Hex())
	}
	if req.GasLimit != cfg.GasLimit {
		t.Fatalf("gas limit mismatch: got %d want %d", req.GasLimit, cfg.GasLimit)
	}

	wantCalldata, err := bridgeabi.PackExtendWithdrawExpiryBatchCalldata(
		[]common.Hash{common.Hash(id0), common.Hash(id1)},
		uint64(newExpiry.Unix()),
		signer.sigs,
	)
	if err != nil {
		t.Fatalf("PackExtendWithdrawExpiryBatchCalldata: %v", err)
	}
	if req.Data != hexutil.Encode(wantCalldata) {
		t.Fatalf("calldata mismatch")
	}
}

func TestBaseExpiryExtender_Extend_RejectsRevertedReceipt(t *testing.T) {
	t.Parallel()

	cfg := BaseExpiryExtenderConfig{
		BaseChainID:   8453,
		BridgeAddress: common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	ext, err := NewBaseExpiryExtender(cfg, &stubExtendSender{
		res: httpapi.SendResponse{
			TxHash: "0xabc",
			Receipt: &httpapi.ReceiptResponse{
				Status: 0,
			},
		},
	}, &stubExtendSigner{
		sigs: [][]byte{[]byte{0x01}},
	})
	if err != nil {
		t.Fatalf("NewBaseExpiryExtender: %v", err)
	}

	err = ext.Extend(context.Background(), [][32]byte{
		[32]byte(common.HexToHash("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")),
	}, time.Unix(1730000000, 0).UTC())
	if err == nil || err.Error() != "withdrawcoordinator: extend expiry tx reverted" {
		t.Fatalf("expected revert error, got %v", err)
	}
}

func TestLocalExtendSigner_SortsByAddress(t *testing.T) {
	t.Parallel()

	k1, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA k1: %v", err)
	}
	k2, err := crypto.HexToECDSA("6c875d0e7f3d0d840e4f1a400a54c3c4d5ef0e8f55d8aee0b1b1f0c0a8f6c1d1")
	if err != nil {
		t.Fatalf("HexToECDSA k2: %v", err)
	}

	s, err := NewLocalExtendSigner([]*ecdsa.PrivateKey{k2, k1})
	if err != nil {
		t.Fatalf("NewLocalExtendSigner: %v", err)
	}

	digest := common.HexToHash("0x096b6960ecac1de01b1d37dea33c1b774f83c442c9a69e0c84b0f90ef0fbfef8")
	sigs, err := s.SignExtendDigest(context.Background(), digest)
	if err != nil {
		t.Fatalf("SignExtendDigest: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("len(sig): got %d want 2", len(sigs))
	}

	addr0, err := checkpoint.RecoverSigner(digest, sigs[0])
	if err != nil {
		t.Fatalf("recover sig 0: %v", err)
	}
	addr1, err := checkpoint.RecoverSigner(digest, sigs[1])
	if err != nil {
		t.Fatalf("recover sig 1: %v", err)
	}
	if bytes.Compare(addr0[:], addr1[:]) >= 0 {
		t.Fatalf("signatures not sorted by signer address: %s >= %s", addr0.Hex(), addr1.Hex())
	}
}

func TestNewLocalExtendSigner_RejectsEmptyKeys(t *testing.T) {
	t.Parallel()

	_, err := NewLocalExtendSigner(nil)
	if !errors.Is(err, ErrInvalidExpiryExtenderConfig) {
		t.Fatalf("expected ErrInvalidExpiryExtenderConfig, got %v", err)
	}
}
