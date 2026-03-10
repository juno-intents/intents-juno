package withdrawcoordinator

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
)

func TestBasePaidMarker_MarkPaidSortsAndSendsBatch(t *testing.T) {
	t.Parallel()

	cfg := BasePaidMarkerConfig{
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

	marker, err := NewBasePaidMarker(cfg, sender, signer)
	if err != nil {
		t.Fatalf("NewBasePaidMarker: %v", err)
	}

	id0 := [32]byte(common.HexToHash("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	id1 := [32]byte(common.HexToHash("0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
	ids := [][32]byte{id1, id0}

	if err := marker.MarkPaid(context.Background(), ids); err != nil {
		t.Fatalf("MarkPaid: %v", err)
	}

	sortedIDs := [][32]byte{id0, id1}
	wantDigest, err := checkpoint.MarkWithdrawPaidDigest(sortedIDs, cfg.BaseChainID, cfg.BridgeAddress)
	if err != nil {
		t.Fatalf("MarkWithdrawPaidDigest: %v", err)
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

	wantCalldata, err := bridgeabi.PackMarkWithdrawPaidBatchCalldata(
		[]common.Hash{common.Hash(id0), common.Hash(id1)},
		signer.sigs,
	)
	if err != nil {
		t.Fatalf("PackMarkWithdrawPaidBatchCalldata: %v", err)
	}
	if req.Data != hexutil.Encode(wantCalldata) {
		t.Fatalf("calldata mismatch")
	}
}

func TestBasePaidMarker_MarkPaidRejectsRevertedReceipt(t *testing.T) {
	t.Parallel()

	cfg := BasePaidMarkerConfig{
		BaseChainID:   8453,
		BridgeAddress: common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	marker, err := NewBasePaidMarker(cfg, &stubExtendSender{
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
		t.Fatalf("NewBasePaidMarker: %v", err)
	}

	err = marker.MarkPaid(context.Background(), [][32]byte{
		[32]byte(common.HexToHash("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")),
	})
	if err == nil || err.Error() != "withdrawcoordinator: mark paid tx reverted" {
		t.Fatalf("expected revert error, got %v", err)
	}
}
