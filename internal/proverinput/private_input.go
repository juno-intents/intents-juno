package proverinput

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type depositPrivateInputV1 struct {
	Version            string                     `json:"version"`
	Checkpoint         checkpoint.Checkpoint      `json:"checkpoint"`
	OperatorSignatures []string                   `json:"operatorSignatures"`
	Items              []depositPrivateMintItemV1 `json:"items"`
}

type depositPrivateMintItemV1 struct {
	DepositID string `json:"depositId"`
	Recipient string `json:"recipient"`
	AmountZat string `json:"amountZat"`
}

type withdrawPrivateInputV1 struct {
	Version            string                          `json:"version"`
	Checkpoint         checkpoint.Checkpoint           `json:"checkpoint"`
	OperatorSignatures []string                        `json:"operatorSignatures"`
	Items              []withdrawPrivateFinalizeItemV1 `json:"items"`
}

type withdrawPrivateFinalizeItemV1 struct {
	WithdrawalID    string `json:"withdrawalId"`
	RecipientUAHash string `json:"recipientUAHash"`
	NetAmountZat    string `json:"netAmountZat"`
}

func EncodeDepositPrivateInputV1(cp checkpoint.Checkpoint, operatorSigs [][]byte, items []bridgeabi.MintItem) ([]byte, error) {
	out := depositPrivateInputV1{
		Version:            "deposit.private_input.v1",
		Checkpoint:         cp,
		OperatorSignatures: encodeSignaturesHex(operatorSigs),
		Items:              make([]depositPrivateMintItemV1, 0, len(items)),
	}
	for _, it := range items {
		if it.Amount == nil {
			return nil, fmt.Errorf("proverinput: nil deposit amount")
		}
		out.Items = append(out.Items, depositPrivateMintItemV1{
			DepositID: common.Hash(it.DepositId).Hex(),
			Recipient: it.Recipient.Hex(),
			AmountZat: it.Amount.String(),
		})
	}
	return json.Marshal(out)
}

func EncodeWithdrawPrivateInputV1(cp checkpoint.Checkpoint, operatorSigs [][]byte, items []bridgeabi.FinalizeItem) ([]byte, error) {
	out := withdrawPrivateInputV1{
		Version:            "withdraw.private_input.v1",
		Checkpoint:         cp,
		OperatorSignatures: encodeSignaturesHex(operatorSigs),
		Items:              make([]withdrawPrivateFinalizeItemV1, 0, len(items)),
	}
	for _, it := range items {
		if it.NetAmount == nil {
			return nil, fmt.Errorf("proverinput: nil withdraw net amount")
		}
		out.Items = append(out.Items, withdrawPrivateFinalizeItemV1{
			WithdrawalID:    common.Hash(it.WithdrawalId).Hex(),
			RecipientUAHash: it.RecipientUAHash.Hex(),
			NetAmountZat:    it.NetAmount.String(),
		})
	}
	return json.Marshal(out)
}

func encodeSignaturesHex(sigs [][]byte) []string {
	out := make([]string, 0, len(sigs))
	for _, sig := range sigs {
		out = append(out, "0x"+hex.EncodeToString(sig))
	}
	return out
}
