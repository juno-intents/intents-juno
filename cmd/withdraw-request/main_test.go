package main

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestParseFixedHex(t *testing.T) {
	t.Parallel()

	b, err := parseFixedHex("0x"+strings.Repeat("aa", 43), 43)
	if err != nil {
		t.Fatalf("parseFixedHex: %v", err)
	}
	if len(b) != 43 {
		t.Fatalf("len: got=%d want=43", len(b))
	}
}

func TestParseWithdrawRequestedEvent(t *testing.T) {
	t.Parallel()

	bridgeABI, err := abi.JSON(strings.NewReader(bridgeABIJSON))
	if err != nil {
		t.Fatalf("parse bridge abi: %v", err)
	}
	eventDef := bridgeABI.Events["WithdrawRequested"]

	bridgeAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	withdrawalID := common.HexToHash("0x" + strings.Repeat("22", 32))
	requester := common.HexToAddress("0x3333333333333333333333333333333333333333")
	recipientUA, _ := hex.DecodeString(strings.Repeat("44", 43))

	nonIndexed, err := eventDef.Inputs.NonIndexed().Pack(
		new(big.Int).SetUint64(10000),
		recipientUA,
		uint64(123456),
		new(big.Int).SetUint64(50),
	)
	if err != nil {
		t.Fatalf("pack non-indexed fields: %v", err)
	}

	logEntry := &types.Log{
		Address: bridgeAddr,
		Topics: []common.Hash{
			eventDef.ID,
			withdrawalID,
			common.BytesToHash(common.LeftPadBytes(requester.Bytes(), 32)),
		},
		Data: nonIndexed,
	}

	event, err := parseWithdrawRequestedEvent([]*types.Log{logEntry}, bridgeAddr, bridgeABI)
	if err != nil {
		t.Fatalf("parseWithdrawRequestedEvent: %v", err)
	}
	if event.WithdrawalID != withdrawalID {
		t.Fatalf("withdrawal id mismatch: got=%s want=%s", event.WithdrawalID.Hex(), withdrawalID.Hex())
	}
	if event.Requester != requester {
		t.Fatalf("requester mismatch: got=%s want=%s", event.Requester.Hex(), requester.Hex())
	}
	if event.Amount != 10000 {
		t.Fatalf("amount mismatch: got=%d want=10000", event.Amount)
	}
	if event.Expiry != 123456 {
		t.Fatalf("expiry mismatch: got=%d want=123456", event.Expiry)
	}
	if event.FeeBps != 50 {
		t.Fatalf("feeBps mismatch: got=%d want=50", event.FeeBps)
	}
	if hex.EncodeToString(event.RecipientUA) != hex.EncodeToString(recipientUA) {
		t.Fatalf("recipientUA mismatch")
	}
}
