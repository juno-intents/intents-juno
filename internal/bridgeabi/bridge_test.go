package bridgeabi

import (
	"bytes"
	"context"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type stubLogFilterer struct {
	t      *testing.T
	logsFn func(q ethereum.FilterQuery) ([]types.Log, error)
	queries []ethereum.FilterQuery
}

func (s *stubLogFilterer) FilterLogs(_ context.Context, q ethereum.FilterQuery) ([]types.Log, error) {
	s.t.Helper()
	s.queries = append(s.queries, q)
	if s.logsFn != nil {
		return s.logsFn(q)
	}
	return nil, nil
}

func mustType(t *testing.T, typ string, comps []abi.ArgumentMarshaling) abi.Type {
	t.Helper()

	ty, err := abi.NewType(typ, "", comps)
	if err != nil {
		t.Fatalf("abi.NewType(%q): %v", typ, err)
	}
	return ty
}

func TestEncodeDepositJournal_RoundTrip(t *testing.T) {
	t.Parallel()

	var root common.Hash
	root[0] = 0x11

	var depID common.Hash
	depID[0] = 0x22

	dj := DepositJournal{
		FinalOrchardRoot: root,
		BaseChainId:      big.NewInt(31337),
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
		Items: []MintItem{
			{
				DepositId: depID,
				Recipient: common.HexToAddress("0x0000000000000000000000000000000000000456"),
				Amount:    big.NewInt(1000),
			},
		},
	}

	b, err := EncodeDepositJournal(dj)
	if err != nil {
		t.Fatalf("EncodeDepositJournal: %v", err)
	}

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

	vals, err := args.Unpack(b)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("unpack len: got %d want %d", len(vals), 1)
	}

	v := reflect.ValueOf(vals[0])
	if v.Kind() != reflect.Struct {
		t.Fatalf("unpack type: got %T want struct", vals[0])
	}

	gotRoot := v.FieldByName("FinalOrchardRoot").Interface().([32]byte)
	if gotRoot != root {
		t.Fatalf("FinalOrchardRoot mismatch")
	}
	gotChain := v.FieldByName("BaseChainId").Interface().(*big.Int)
	if gotChain.Cmp(dj.BaseChainId) != 0 {
		t.Fatalf("BaseChainId: got %s want %s", gotChain.String(), dj.BaseChainId.String())
	}
	gotBridge := v.FieldByName("BridgeContract").Interface().(common.Address)
	if gotBridge != dj.BridgeContract {
		t.Fatalf("BridgeContract: got %s want %s", gotBridge, dj.BridgeContract)
	}

	items := v.FieldByName("Items")
	if items.Kind() != reflect.Slice || items.Len() != 1 {
		t.Fatalf("Items: got kind=%s len=%d", items.Kind(), items.Len())
	}
	it := items.Index(0)
	gotDepID := it.FieldByName("DepositId").Interface().([32]byte)
	if gotDepID != depID {
		t.Fatalf("DepositId mismatch")
	}
	gotRecip := it.FieldByName("Recipient").Interface().(common.Address)
	if gotRecip != dj.Items[0].Recipient {
		t.Fatalf("Recipient: got %s want %s", gotRecip, dj.Items[0].Recipient)
	}
	gotAmt := it.FieldByName("Amount").Interface().(*big.Int)
	if gotAmt.Cmp(dj.Items[0].Amount) != 0 {
		t.Fatalf("Amount: got %s want %s", gotAmt.String(), dj.Items[0].Amount.String())
	}
}

func TestPackMintBatchCalldata_UnpackMatches(t *testing.T) {
	t.Parallel()

	var depID common.Hash
	depID[0] = 0x22

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}

	journal, err := EncodeDepositJournal(DepositJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items: []MintItem{
			{
				DepositId: depID,
				Recipient: common.HexToAddress("0x0000000000000000000000000000000000000456"),
				Amount:    big.NewInt(1000),
			},
		},
	})
	if err != nil {
		t.Fatalf("EncodeDepositJournal: %v", err)
	}

	operatorSigs := [][]byte{[]byte{0x01, 0x02}, []byte{0x03}}
	seal := []byte{0x99}

	calldata, err := PackMintBatchCalldata(cp, operatorSigs, seal, journal)
	if err != nil {
		t.Fatalf("PackMintBatchCalldata: %v", err)
	}
	if len(calldata) < 4 || !bytes.Equal(calldata[:4], []byte{0x53, 0xa5, 0x8a, 0x48}) {
		t.Fatalf("selector mismatch: got %x", calldata[:4])
	}

	a, err := abi.JSON(strings.NewReader(bridgeABIJSON))
	if err != nil {
		t.Fatalf("parse abi json: %v", err)
	}

	vals, err := a.Methods["mintBatch"].Inputs.Unpack(calldata[4:])
	if err != nil {
		t.Fatalf("unpack calldata: %v", err)
	}
	if len(vals) != 4 {
		t.Fatalf("unpack len: got %d want %d", len(vals), 4)
	}

	// Journal is passed verbatim as bytes.
	if got := vals[3].([]byte); !bytes.Equal(got, journal) {
		t.Fatalf("journal bytes mismatch")
	}
}

func TestFindMintedDepositTxHashes_ChunksLargeLookbackAndStopsOnceFound(t *testing.T) {
	t.Parallel()

	if err := initABI(); err != nil {
		t.Fatalf("initABI: %v", err)
	}
	mintedEvent := bridgeABI.Events["Minted"]
	bridge := common.HexToAddress("0x0000000000000000000000000000000000000abc")
	depositID := [32]byte{0x11}
	mintedTxHash := common.HexToHash("0x1234")
	toBlock := big.NewInt(25_000)

	filterer := &stubLogFilterer{t: t}
	filterer.logsFn = func(q ethereum.FilterQuery) ([]types.Log, error) {
		if q.FromBlock == nil || q.ToBlock == nil {
			t.Fatalf("expected bounded block window, got from=%v to=%v", q.FromBlock, q.ToBlock)
		}
		if q.ToBlock.Uint64()-q.FromBlock.Uint64() > 9_999 {
			t.Fatalf("unexpected oversized block window: from=%s to=%s", q.FromBlock.String(), q.ToBlock.String())
		}
		if q.FromBlock.Uint64() == 15_001 && q.ToBlock.Uint64() == 25_000 {
			return []types.Log{{
				Address:     bridge,
				Topics:      []common.Hash{mintedEvent.ID, common.BytesToHash(depositID[:])},
				BlockNumber: 24_999,
				TxHash:      mintedTxHash,
			}}, nil
		}
		return nil, nil
	}

	got, err := FindMintedDepositTxHashes(context.Background(), filterer, bridge, [][32]byte{depositID}, toBlock)
	if err != nil {
		t.Fatalf("FindMintedDepositTxHashes: %v", err)
	}
	if len(filterer.queries) != 1 {
		t.Fatalf("query count: got %d want %d", len(filterer.queries), 1)
	}
	if got[depositID] != [32]byte(mintedTxHash) {
		t.Fatalf("minted tx hash: got %x want %x", got[depositID], [32]byte(mintedTxHash))
	}
}

func TestFindMintedDepositTxHashes_WalksBackMultipleWindows(t *testing.T) {
	t.Parallel()

	if err := initABI(); err != nil {
		t.Fatalf("initABI: %v", err)
	}
	mintedEvent := bridgeABI.Events["Minted"]
	bridge := common.HexToAddress("0x0000000000000000000000000000000000000abc")
	depositID := [32]byte{0x22}
	mintedTxHash := common.HexToHash("0x5678")
	toBlock := big.NewInt(25_000)

	filterer := &stubLogFilterer{t: t}
	filterer.logsFn = func(q ethereum.FilterQuery) ([]types.Log, error) {
		if q.FromBlock == nil || q.ToBlock == nil {
			t.Fatalf("expected bounded block window, got from=%v to=%v", q.FromBlock, q.ToBlock)
		}
		if q.ToBlock.Uint64()-q.FromBlock.Uint64() > 9_999 {
			t.Fatalf("unexpected oversized block window: from=%s to=%s", q.FromBlock.String(), q.ToBlock.String())
		}
		if q.FromBlock.Uint64() == 5_001 && q.ToBlock.Uint64() == 15_000 {
			return []types.Log{{
				Address:     bridge,
				Topics:      []common.Hash{mintedEvent.ID, common.BytesToHash(depositID[:])},
				BlockNumber: 14_999,
				TxHash:      mintedTxHash,
			}}, nil
		}
		return nil, nil
	}

	got, err := FindMintedDepositTxHashes(context.Background(), filterer, bridge, [][32]byte{depositID}, toBlock)
	if err != nil {
		t.Fatalf("FindMintedDepositTxHashes: %v", err)
	}
	if len(filterer.queries) != 2 {
		t.Fatalf("query count: got %d want %d", len(filterer.queries), 2)
	}
	if first := filterer.queries[0]; first.FromBlock.Uint64() != 15_001 || first.ToBlock.Uint64() != 25_000 {
		t.Fatalf("first query: got from=%s to=%s", first.FromBlock.String(), first.ToBlock.String())
	}
	if second := filterer.queries[1]; second.FromBlock.Uint64() != 5_001 || second.ToBlock.Uint64() != 15_000 {
		t.Fatalf("second query: got from=%s to=%s", second.FromBlock.String(), second.ToBlock.String())
	}
	if got[depositID] != [32]byte(mintedTxHash) {
		t.Fatalf("minted tx hash: got %x want %x", got[depositID], [32]byte(mintedTxHash))
	}
}

func TestPackDepositUsedCalldata_UnpackMatches(t *testing.T) {
	t.Parallel()

	depositID := common.HexToHash("0x" + strings.Repeat("11", 32))

	calldata, err := PackDepositUsedCalldata(depositID)
	if err != nil {
		t.Fatalf("PackDepositUsedCalldata: %v", err)
	}

	a, err := abi.JSON(strings.NewReader(bridgeABIJSON))
	if err != nil {
		t.Fatalf("parse abi json: %v", err)
	}
	vals, err := a.Methods["depositUsed"].Inputs.Unpack(calldata[4:])
	if err != nil {
		t.Fatalf("unpack calldata: %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("unpack len: got %d want 1", len(vals))
	}
	if got := vals[0].([32]byte); got != depositID {
		t.Fatalf("deposit id: got %x want %x", got, depositID)
	}

	used, err := UnpackDepositUsedResult(common.LeftPadBytes([]byte{1}, 32))
	if err != nil {
		t.Fatalf("UnpackDepositUsedResult: %v", err)
	}
	if !used {
		t.Fatalf("expected depositUsed result to decode true")
	}
}

func TestPackGetWithdrawalCalldata_UnpackFinalizedResult(t *testing.T) {
	t.Parallel()

	withdrawalID := common.HexToHash("0x" + strings.Repeat("22", 32))

	calldata, err := PackGetWithdrawalCalldata(withdrawalID)
	if err != nil {
		t.Fatalf("PackGetWithdrawalCalldata: %v", err)
	}

	a, err := abi.JSON(strings.NewReader(bridgeABIJSON))
	if err != nil {
		t.Fatalf("parse abi json: %v", err)
	}
	vals, err := a.Methods["getWithdrawal"].Inputs.Unpack(calldata[4:])
	if err != nil {
		t.Fatalf("unpack calldata: %v", err)
	}
	if len(vals) != 1 {
		t.Fatalf("unpack len: got %d want 1", len(vals))
	}
	if got := vals[0].([32]byte); got != withdrawalID {
		t.Fatalf("withdrawal id: got %x want %x", got, withdrawalID)
	}

	raw, err := a.Methods["getWithdrawal"].Outputs.Pack(
		common.HexToAddress("0x00000000000000000000000000000000000000aa"),
		big.NewInt(1000),
		uint64(123),
		big.NewInt(25),
		true,
		[]byte{0x01, 0x02},
	)
	if err != nil {
		t.Fatalf("pack outputs: %v", err)
	}
	result, err := UnpackGetWithdrawalResult(raw)
	if err != nil {
		t.Fatalf("UnpackGetWithdrawalResult: %v", err)
	}
	if !result.Finalized {
		t.Fatalf("expected finalized result to decode true")
	}
}
