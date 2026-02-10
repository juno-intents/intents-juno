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
