package proverinput

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

func TestEncodeDepositPrivateInputV1(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           1,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	out, err := EncodeDepositPrivateInputV1(cp, [][]byte{{0x01, 0x02}}, []bridgeabi.MintItem{
		{
			DepositId: common.HexToHash("0x1"),
			Recipient: common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
			Amount:    big.NewInt(123),
		},
	})
	if err != nil {
		t.Fatalf("EncodeDepositPrivateInputV1: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env["version"] != "deposit.private_input.v1" {
		t.Fatalf("version: got %v", env["version"])
	}
}

func TestEncodeWithdrawPrivateInputV1(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           1,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	out, err := EncodeWithdrawPrivateInputV1(cp, [][]byte{{0x01, 0x02}}, []bridgeabi.FinalizeItem{
		{
			WithdrawalId:    common.HexToHash("0x2"),
			RecipientUAHash: common.HexToHash("0x3"),
			NetAmount:       big.NewInt(123),
		},
	})
	if err != nil {
		t.Fatalf("EncodeWithdrawPrivateInputV1: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env["version"] != "withdraw.private_input.v1" {
		t.Fatalf("version: got %v", env["version"])
	}
}
