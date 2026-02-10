package bridgeabi

import (
	"bytes"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

func TestEncodeWithdrawJournal_RoundTrip(t *testing.T) {
	t.Parallel()

	var root common.Hash
	root[0] = 0x11

	var wid common.Hash
	wid[0] = 0x33

	var uaHash common.Hash
	uaHash[0] = 0x44

	wj := WithdrawJournal{
		FinalOrchardRoot: root,
		BaseChainId:      big.NewInt(31337),
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
		Items: []FinalizeItem{
			{
				WithdrawalId:     wid,
				RecipientUAHash:  uaHash,
				NetAmount:        big.NewInt(999),
			},
		},
	}

	b, err := EncodeWithdrawJournal(wj)
	if err != nil {
		t.Fatalf("EncodeWithdrawJournal: %v", err)
	}

	journalType := mustType(t, "tuple", []abi.ArgumentMarshaling{
		{Name: "finalOrchardRoot", Type: "bytes32"},
		{Name: "baseChainId", Type: "uint256"},
		{Name: "bridgeContract", Type: "address"},
		{Name: "items", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
			{Name: "withdrawalId", Type: "bytes32"},
			{Name: "recipientUAHash", Type: "bytes32"},
			{Name: "netAmount", Type: "uint256"},
		}},
	})
	args := abi.Arguments{{Name: "wj", Type: journalType}}

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
	if gotChain.Cmp(wj.BaseChainId) != 0 {
		t.Fatalf("BaseChainId mismatch")
	}
	gotBridge := v.FieldByName("BridgeContract").Interface().(common.Address)
	if gotBridge != wj.BridgeContract {
		t.Fatalf("BridgeContract mismatch")
	}

	items := v.FieldByName("Items")
	if items.Kind() != reflect.Slice || items.Len() != 1 {
		t.Fatalf("Items: got kind=%s len=%d", items.Kind(), items.Len())
	}
	it := items.Index(0)
	gotWID := it.FieldByName("WithdrawalId").Interface().([32]byte)
	if common.Hash(gotWID) != wid {
		t.Fatalf("WithdrawalId mismatch")
	}
	gotUAHash := it.FieldByName("RecipientUAHash").Interface().([32]byte)
	if common.Hash(gotUAHash) != uaHash {
		t.Fatalf("RecipientUAHash mismatch")
	}
	gotNet := it.FieldByName("NetAmount").Interface().(*big.Int)
	if gotNet.Cmp(wj.Items[0].NetAmount) != 0 {
		t.Fatalf("NetAmount mismatch")
	}
}

func TestPackFinalizeWithdrawBatchCalldata_UnpackMatches(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}

	var wid common.Hash
	wid[0] = 0x33
	var uaHash common.Hash
	uaHash[0] = 0x44

	journal, err := EncodeWithdrawJournal(WithdrawJournal{
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
		Items: []FinalizeItem{
			{WithdrawalId: wid, RecipientUAHash: uaHash, NetAmount: big.NewInt(999)},
		},
	})
	if err != nil {
		t.Fatalf("EncodeWithdrawJournal: %v", err)
	}

	operatorSigs := [][]byte{[]byte{0x01, 0x02}, []byte{0x03}}
	seal := []byte{0x99}

	calldata, err := PackFinalizeWithdrawBatchCalldata(cp, operatorSigs, seal, journal)
	if err != nil {
		t.Fatalf("PackFinalizeWithdrawBatchCalldata: %v", err)
	}
	if len(calldata) < 4 || !bytes.Equal(calldata[:4], []byte{0xec, 0x70, 0xb6, 0x05}) {
		t.Fatalf("selector mismatch: got %x", calldata[:4])
	}

	a, err := abi.JSON(strings.NewReader(bridgeABIJSON))
	if err != nil {
		t.Fatalf("parse abi json: %v", err)
	}

	vals, err := a.Methods["finalizeWithdrawBatch"].Inputs.Unpack(calldata[4:])
	if err != nil {
		t.Fatalf("unpack calldata: %v", err)
	}
	if len(vals) != 4 {
		t.Fatalf("unpack len: got %d want %d", len(vals), 4)
	}
	if got := vals[3].([]byte); !bytes.Equal(got, journal) {
		t.Fatalf("journal bytes mismatch")
	}
}

func TestPackExtendWithdrawExpiryBatchCalldata_UnpackMatches(t *testing.T) {
	t.Parallel()

	ids := []common.Hash{
		common.HexToHash("0x0100000000000000000000000000000000000000000000000000000000000000"),
		common.HexToHash("0x0200000000000000000000000000000000000000000000000000000000000000"),
	}
	newExpiry := uint64(1234567890)
	operatorSigs := [][]byte{[]byte{0x01}, []byte{0x02, 0x03}}

	calldata, err := PackExtendWithdrawExpiryBatchCalldata(ids, newExpiry, operatorSigs)
	if err != nil {
		t.Fatalf("PackExtendWithdrawExpiryBatchCalldata: %v", err)
	}
	if len(calldata) < 4 || !bytes.Equal(calldata[:4], []byte{0xa0, 0xbd, 0x5f, 0x8a}) {
		t.Fatalf("selector mismatch: got %x", calldata[:4])
	}

	a, err := abi.JSON(strings.NewReader(bridgeABIJSON))
	if err != nil {
		t.Fatalf("parse abi json: %v", err)
	}
	vals, err := a.Methods["extendWithdrawExpiryBatch"].Inputs.Unpack(calldata[4:])
	if err != nil {
		t.Fatalf("unpack calldata: %v", err)
	}
	if len(vals) != 3 {
		t.Fatalf("unpack len: got %d want %d", len(vals), 3)
	}

	// ids
	gotIDs := vals[0].([][32]byte)
	if len(gotIDs) != len(ids) {
		t.Fatalf("ids len: got %d want %d", len(gotIDs), len(ids))
	}
	for i := range ids {
		if common.Hash(gotIDs[i]) != ids[i] {
			t.Fatalf("id[%d] mismatch", i)
		}
	}
	// newExpiry
	if got := vals[1].(uint64); got != newExpiry {
		t.Fatalf("newExpiry: got %d want %d", got, newExpiry)
	}
	// sigs
	gotSigs := vals[2].([][]byte)
	if len(gotSigs) != len(operatorSigs) {
		t.Fatalf("sigs len: got %d want %d", len(gotSigs), len(operatorSigs))
	}
}

