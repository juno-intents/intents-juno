package proverinput

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/bridgeabi"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

const (
	// Matches MAX_DEPOSIT_ITEMS in zk/deposit_guest/core/src/lib.rs.
	MaxDepositWitnessItems = 100
	// Matches MAX_WITHDRAW_ITEMS in zk/withdraw_guest/core/src/lib.rs.
	MaxWithdrawWitnessItems = 100

	// Byte length of one deposit witness item in the exact guest read order:
	// leaf_index(4) + auth_path(32*32) + orchard_action(32*5 + 580 + 80).
	DepositWitnessItemLen = 4 + (32 * 32) + (32*5 + 580 + 80)
	// Byte length of one withdraw witness item in the exact guest read order:
	// withdrawal_id(32) + recipient_raw_address(43) + leaf_index(4)
	// + auth_path(32*32) + orchard_action(32*5 + 580 + 80).
	WithdrawWitnessItemLen = 32 + 43 + 4 + (32 * 32) + (32*5 + 580 + 80)
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

// EncodeDepositGuestPrivateInput builds the raw binary stdin payload expected by
// zk/deposit_guest/guest/src/main.rs.
func EncodeDepositGuestPrivateInput(cp checkpoint.Checkpoint, owalletIVK [64]byte, witnessItems [][]byte) ([]byte, error) {
	if cp.BaseChainID > math.MaxUint32 {
		return nil, fmt.Errorf("proverinput: base chain id %d exceeds uint32", cp.BaseChainID)
	}
	if len(witnessItems) > MaxDepositWitnessItems {
		return nil, fmt.Errorf("proverinput: too many deposit witness items: got %d max %d", len(witnessItems), MaxDepositWitnessItems)
	}

	buf := make([]byte, 0, 32+4+20+64+4+len(witnessItems)*DepositWitnessItemLen)
	buf = append(buf, cp.FinalOrchardRoot[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(cp.BaseChainID))
	buf = append(buf, cp.BridgeContract[:]...)
	buf = append(buf, owalletIVK[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(witnessItems)))

	for i, item := range witnessItems {
		if len(item) != DepositWitnessItemLen {
			return nil, fmt.Errorf("proverinput: deposit witness item %d has len %d, want %d", i, len(item), DepositWitnessItemLen)
		}
		buf = append(buf, item...)
	}
	return buf, nil
}

// EncodeWithdrawGuestPrivateInput builds the raw binary stdin payload expected by
// zk/withdraw_guest/guest/src/main.rs.
func EncodeWithdrawGuestPrivateInput(cp checkpoint.Checkpoint, owalletOVK [32]byte, witnessItems [][]byte) ([]byte, error) {
	if cp.BaseChainID > math.MaxUint32 {
		return nil, fmt.Errorf("proverinput: base chain id %d exceeds uint32", cp.BaseChainID)
	}
	if len(witnessItems) > MaxWithdrawWitnessItems {
		return nil, fmt.Errorf("proverinput: too many withdraw witness items: got %d max %d", len(witnessItems), MaxWithdrawWitnessItems)
	}

	buf := make([]byte, 0, 32+4+20+32+4+len(witnessItems)*WithdrawWitnessItemLen)
	buf = append(buf, cp.FinalOrchardRoot[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(cp.BaseChainID))
	buf = append(buf, cp.BridgeContract[:]...)
	buf = append(buf, owalletOVK[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(witnessItems)))

	for i, item := range witnessItems {
		if len(item) != WithdrawWitnessItemLen {
			return nil, fmt.Errorf("proverinput: withdraw witness item %d has len %d, want %d", i, len(item), WithdrawWitnessItemLen)
		}
		buf = append(buf, item...)
	}
	return buf, nil
}
