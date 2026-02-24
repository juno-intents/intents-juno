package depositevent

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/proverinput"
)

func TestParseWitnessItem(t *testing.T) {
	t.Parallel()

	witness := make([]byte, proverinput.DepositWitnessItemLen)
	binary.LittleEndian.PutUint32(witness[depositWitnessLeafIndexOffset:depositWitnessLeafIndexOffset+4], 42)
	cmBytes, _ := hex.DecodeString(strings.Repeat("ab", 32))
	copy(witness[depositWitnessCMXOffset:depositWitnessCMXOffset+32], cmBytes)

	cm, leafIndex, err := ParseWitnessItem(witness)
	if err != nil {
		t.Fatalf("ParseWitnessItem: %v", err)
	}
	if leafIndex != 42 {
		t.Fatalf("leaf index: got=%d want=42", leafIndex)
	}
	if cm.Hex() != "0x"+strings.Repeat("ab", 32) {
		t.Fatalf("cm: got=%s", cm.Hex())
	}
}

func TestBuildPayload(t *testing.T) {
	t.Parallel()

	witness := make([]byte, proverinput.DepositWitnessItemLen)
	binary.LittleEndian.PutUint32(witness[depositWitnessLeafIndexOffset:depositWitnessLeafIndexOffset+4], 7)
	cmHex := strings.Repeat("cd", 32)
	cmBytes, _ := hex.DecodeString(cmHex)
	copy(witness[depositWitnessCMXOffset:depositWitnessCMXOffset+32], cmBytes)

	bridge := common.HexToAddress("0x1111111111111111111111111111111111111111")
	recipient := common.HexToAddress("0x2222222222222222222222222222222222222222")

	payload, err := BuildPayload(84532, bridge, recipient, 100000, 99, witness)
	if err != nil {
		t.Fatalf("BuildPayload: %v", err)
	}
	if payload.Version != "deposits.event.v1" {
		t.Fatalf("version: got=%q", payload.Version)
	}
	if payload.CM != "0x"+cmHex {
		t.Fatalf("cm: got=%q", payload.CM)
	}
	if payload.LeafIndex != 7 {
		t.Fatalf("leaf index: got=%d want=7", payload.LeafIndex)
	}
	if payload.Amount != 100000 {
		t.Fatalf("amount: got=%d want=100000", payload.Amount)
	}

	memoBytes, err := hex.DecodeString(strings.TrimPrefix(payload.Memo, "0x"))
	if err != nil {
		t.Fatalf("decode memo: %v", err)
	}
	parsedMemo, err := memo.ParseDepositMemoV1(memoBytes, 84532, [20]byte(bridge))
	if err != nil {
		t.Fatalf("parse memo: %v", err)
	}
	if common.Address(parsedMemo.BaseRecipient) != recipient {
		t.Fatalf("memo recipient mismatch: got=%s want=%s", common.Address(parsedMemo.BaseRecipient), recipient)
	}
	if parsedMemo.Nonce != 99 {
		t.Fatalf("memo nonce mismatch: got=%d want=99", parsedMemo.Nonce)
	}

	expectedDepositID := idempotency.DepositIDV1([32]byte(common.HexToHash(payload.CM)), payload.LeafIndex)
	if payload.DepositID != "0x"+hex.EncodeToString(expectedDepositID[:]) {
		t.Fatalf("deposit id mismatch: got=%s", payload.DepositID)
	}
}
