package withdrawrequest

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type stubHeaderByNumberClient struct {
	header    *types.Header
	err       error
	lastBlock *big.Int
	headers   []*types.Header
	errs      []error
	calls     int
}

func (s *stubHeaderByNumberClient) HeaderByNumber(_ context.Context, number *big.Int) (*types.Header, error) {
	if number != nil {
		s.lastBlock = new(big.Int).Set(number)
	}
	if len(s.headers) > 0 || len(s.errs) > 0 {
		idx := s.calls
		s.calls++
		var header *types.Header
		var err error
		if idx < len(s.headers) {
			header = s.headers[idx]
		} else if len(s.headers) > 0 {
			header = s.headers[len(s.headers)-1]
		}
		if idx < len(s.errs) {
			err = s.errs[idx]
		} else if len(s.errs) > 0 {
			err = s.errs[len(s.errs)-1]
		}
		return header, err
	}
	return s.header, s.err
}

func TestParseFixedHex(t *testing.T) {
	t.Parallel()

	b, err := ParseFixedHex("0x"+strings.Repeat("aa", 43), 43)
	if err != nil {
		t.Fatalf("ParseFixedHex: %v", err)
	}
	if len(b) != 43 {
		t.Fatalf("len: got=%d want=43", len(b))
	}
}

func TestParseWithdrawRequestedEvent(t *testing.T) {
	t.Parallel()

	bridgeABI, err := abi.JSON(strings.NewReader(BridgeABIJSON))
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
		Address:     bridgeAddr,
		BlockNumber: 123,
		BlockHash:   common.HexToHash("0x" + strings.Repeat("55", 32)),
		TxHash:      common.HexToHash("0x" + strings.Repeat("66", 32)),
		Index:       9,
		Topics: []common.Hash{
			eventDef.ID,
			withdrawalID,
			common.BytesToHash(common.LeftPadBytes(requester.Bytes(), 32)),
		},
		Data: nonIndexed,
	}

	event, err := ParseWithdrawRequestedEvent([]*types.Log{logEntry}, bridgeAddr, bridgeABI)
	if err != nil {
		t.Fatalf("ParseWithdrawRequestedEvent: %v", err)
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
	if event.BlockNumber != 123 {
		t.Fatalf("block number mismatch: got=%d want=123", event.BlockNumber)
	}
	if event.BlockHash != logEntry.BlockHash {
		t.Fatalf("block hash mismatch: got=%s want=%s", event.BlockHash.Hex(), logEntry.BlockHash.Hex())
	}
	if event.TxHash != logEntry.TxHash {
		t.Fatalf("tx hash mismatch: got=%s want=%s", event.TxHash.Hex(), logEntry.TxHash.Hex())
	}
	if event.LogIndex != logEntry.Index {
		t.Fatalf("log index mismatch: got=%d want=%d", event.LogIndex, logEntry.Index)
	}
}

func TestCanonicalizeRequestedEvent_UsesReceiptMetadataBeforeHeaderLookup(t *testing.T) {
	t.Parallel()

	wantBlockHash := common.HexToHash("0x" + strings.Repeat("77", 32))
	wantTxHash := common.HexToHash("0x" + strings.Repeat("88", 32))
	receipt := &types.Receipt{
		BlockHash:   wantBlockHash,
		BlockNumber: big.NewInt(456),
		TxHash:      wantTxHash,
	}
	reader := &stubHeaderByNumberClient{}

	got, err := canonicalizeRequestedEvent(context.Background(), reader, receipt, RequestedEvent{})
	if err != nil {
		t.Fatalf("canonicalizeRequestedEvent: %v", err)
	}
	if got.BlockHash != wantBlockHash {
		t.Fatalf("block hash mismatch: got=%s want=%s", got.BlockHash.Hex(), wantBlockHash.Hex())
	}
	if got.BlockNumber != 456 {
		t.Fatalf("block number mismatch: got=%d want=456", got.BlockNumber)
	}
	if got.TxHash != wantTxHash {
		t.Fatalf("tx hash mismatch: got=%s want=%s", got.TxHash.Hex(), wantTxHash.Hex())
	}
	if reader.lastBlock != nil {
		t.Fatalf("expected no header lookup when receipt has canonical block hash")
	}
}

func TestCanonicalizeRequestedEvent_FallsBackToHeaderLookup(t *testing.T) {
	t.Parallel()

	header := &types.Header{Number: big.NewInt(789), Time: 12345}
	receipt := &types.Receipt{BlockNumber: big.NewInt(789)}
	reader := &stubHeaderByNumberClient{header: header}

	got, err := canonicalizeRequestedEvent(context.Background(), reader, receipt, RequestedEvent{})
	if err != nil {
		t.Fatalf("canonicalizeRequestedEvent: %v", err)
	}
	if got.BlockHash != header.Hash() {
		t.Fatalf("block hash mismatch: got=%s want=%s", got.BlockHash.Hex(), header.Hash().Hex())
	}
	if reader.lastBlock == nil || reader.lastBlock.Uint64() != 789 {
		t.Fatalf("expected header lookup for block 789, got %v", reader.lastBlock)
	}
}

func TestCanonicalizeRequestedEvent_RetriesTransientHeaderLookupMiss(t *testing.T) {
	header := &types.Header{Number: big.NewInt(789), Time: 12345}
	receipt := &types.Receipt{BlockNumber: big.NewInt(789)}
	reader := &stubHeaderByNumberClient{
		headers: []*types.Header{nil, header},
		errs:    []error{errors.New("not found"), nil},
	}

	got, err := canonicalizeRequestedEvent(context.Background(), reader, receipt, RequestedEvent{})
	if err != nil {
		t.Fatalf("canonicalizeRequestedEvent: %v", err)
	}
	if got.BlockHash != header.Hash() {
		t.Fatalf("block hash mismatch: got=%s want=%s", got.BlockHash.Hex(), header.Hash().Hex())
	}
	if reader.calls < 2 {
		t.Fatalf("expected retry after transient header miss, got %d calls", reader.calls)
	}
}

func TestToUint64RejectsBigIntOverflow(t *testing.T) {
	t.Parallel()

	_, err := toUint64(new(big.Int).Lsh(big.NewInt(1), 65))
	if err == nil {
		t.Fatalf("expected overflow error")
	}
	if !strings.Contains(err.Error(), "uint64") {
		t.Fatalf("overflow error = %v, want uint64 guidance", err)
	}
}
