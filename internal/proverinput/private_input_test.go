package proverinput

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"math"
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

func TestEncodeDepositGuestPrivateInput(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		FinalOrchardRoot: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		BaseChainID:      84532,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	var ivk [64]byte
	for i := range ivk {
		ivk[i] = byte(i + 1)
	}
	item := bytes.Repeat([]byte{0x7a}, DepositWitnessItemLen)

	got, err := EncodeDepositGuestPrivateInput(cp, ivk, [][]byte{item})
	if err != nil {
		t.Fatalf("EncodeDepositGuestPrivateInput: %v", err)
	}

	const prefixLen = 32 + 4 + 20 + 64 + 4
	if gotLen, want := len(got), prefixLen+DepositWitnessItemLen; gotLen != want {
		t.Fatalf("len: got %d want %d", gotLen, want)
	}
	if !bytes.Equal(got[:32], cp.FinalOrchardRoot[:]) {
		t.Fatalf("final root mismatch")
	}
	if chainID := binary.LittleEndian.Uint32(got[32:36]); chainID != uint32(cp.BaseChainID) {
		t.Fatalf("baseChainID: got %d want %d", chainID, uint32(cp.BaseChainID))
	}
	if !bytes.Equal(got[36:56], cp.BridgeContract[:]) {
		t.Fatalf("bridge contract mismatch")
	}
	if !bytes.Equal(got[56:120], ivk[:]) {
		t.Fatalf("ivk mismatch")
	}
	if n := binary.LittleEndian.Uint32(got[120:124]); n != 1 {
		t.Fatalf("items length: got %d want 1", n)
	}
	if !bytes.Equal(got[prefixLen:], item) {
		t.Fatalf("item bytes mismatch")
	}
}

func TestEncodeDepositGuestPrivateInput_ValidatesInputs(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{BaseChainID: math.MaxUint32 + 1}
	_, err := EncodeDepositGuestPrivateInput(cp, [64]byte{}, nil)
	if err == nil {
		t.Fatalf("expected chain id validation error")
	}

	cp.BaseChainID = 84532
	_, err = EncodeDepositGuestPrivateInput(cp, [64]byte{}, [][]byte{{0x01}})
	if err == nil {
		t.Fatalf("expected witness size validation error")
	}

	items := make([][]byte, MaxDepositWitnessItems+1)
	for i := range items {
		items[i] = bytes.Repeat([]byte{0x11}, DepositWitnessItemLen)
	}
	_, err = EncodeDepositGuestPrivateInput(cp, [64]byte{}, items)
	if err == nil {
		t.Fatalf("expected max items validation error")
	}
}

func TestEncodeWithdrawGuestPrivateInput(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		FinalOrchardRoot: common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
		BaseChainID:      84532,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	var ovk [32]byte
	for i := range ovk {
		ovk[i] = byte(0xa0 + i)
	}
	item := bytes.Repeat([]byte{0x33}, WithdrawWitnessItemLen)

	got, err := EncodeWithdrawGuestPrivateInput(cp, ovk, [][]byte{item})
	if err != nil {
		t.Fatalf("EncodeWithdrawGuestPrivateInput: %v", err)
	}

	const prefixLen = 32 + 4 + 20 + 32 + 4
	if gotLen, want := len(got), prefixLen+WithdrawWitnessItemLen; gotLen != want {
		t.Fatalf("len: got %d want %d", gotLen, want)
	}
	if !bytes.Equal(got[:32], cp.FinalOrchardRoot[:]) {
		t.Fatalf("final root mismatch")
	}
	if chainID := binary.LittleEndian.Uint32(got[32:36]); chainID != uint32(cp.BaseChainID) {
		t.Fatalf("baseChainID: got %d want %d", chainID, uint32(cp.BaseChainID))
	}
	if !bytes.Equal(got[36:56], cp.BridgeContract[:]) {
		t.Fatalf("bridge contract mismatch")
	}
	if !bytes.Equal(got[56:88], ovk[:]) {
		t.Fatalf("ovk mismatch")
	}
	if n := binary.LittleEndian.Uint32(got[88:92]); n != 1 {
		t.Fatalf("items length: got %d want 1", n)
	}
	if !bytes.Equal(got[prefixLen:], item) {
		t.Fatalf("item bytes mismatch")
	}
}

func TestEncodeWithdrawGuestPrivateInput_ValidatesInputs(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{BaseChainID: math.MaxUint32 + 1}
	_, err := EncodeWithdrawGuestPrivateInput(cp, [32]byte{}, nil)
	if err == nil {
		t.Fatalf("expected chain id validation error")
	}

	cp.BaseChainID = 84532
	_, err = EncodeWithdrawGuestPrivateInput(cp, [32]byte{}, [][]byte{{0x01}})
	if err == nil {
		t.Fatalf("expected witness size validation error")
	}

	items := make([][]byte, MaxWithdrawWitnessItems+1)
	for i := range items {
		items[i] = bytes.Repeat([]byte{0x22}, WithdrawWitnessItemLen)
	}
	_, err = EncodeWithdrawGuestPrivateInput(cp, [32]byte{}, items)
	if err == nil {
		t.Fatalf("expected max items validation error")
	}
}
