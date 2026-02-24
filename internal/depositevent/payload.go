package depositevent

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/proverinput"
)

const (
	depositWitnessLeafIndexOffset = 0
	depositWitnessAuthPathOffset  = depositWitnessLeafIndexOffset + 4
	depositWitnessAuthPathLen     = 32 * 32
	depositWitnessActionOffset    = depositWitnessAuthPathOffset + depositWitnessAuthPathLen
	depositWitnessCMXOffset       = depositWitnessActionOffset + 32 + 32
)

type Payload struct {
	Version          string `json:"version"`
	CM               string `json:"cm"`
	LeafIndex        uint64 `json:"leafIndex"`
	Amount           uint64 `json:"amount"`
	Memo             string `json:"memo"`
	ProofWitnessItem string `json:"proofWitnessItem"`
	DepositID        string `json:"depositId"`
}

func BuildPayload(baseChainID uint32, bridge, recipient common.Address, amount, nonce uint64, witnessItem []byte) (Payload, error) {
	cm, leafIndex, err := ParseWitnessItem(witnessItem)
	if err != nil {
		return Payload{}, err
	}

	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	var recipient20 [20]byte
	copy(recipient20[:], recipient[:])

	memoValue := memo.DepositMemoV1{
		BaseChainID:   baseChainID,
		BridgeAddr:    bridge20,
		BaseRecipient: recipient20,
		Nonce:         nonce,
		Flags:         0,
	}
	memoBytes := memoValue.Encode()
	depositID := idempotency.DepositIDV1([32]byte(cm), leafIndex)

	return Payload{
		Version:          "deposits.event.v1",
		CM:               cm.Hex(),
		LeafIndex:        leafIndex,
		Amount:           amount,
		Memo:             "0x" + hex.EncodeToString(memoBytes[:]),
		ProofWitnessItem: "0x" + hex.EncodeToString(witnessItem),
		DepositID:        "0x" + hex.EncodeToString(depositID[:]),
	}, nil
}

func ParseWitnessItem(item []byte) (common.Hash, uint64, error) {
	if len(item) != proverinput.DepositWitnessItemLen {
		return common.Hash{}, 0, fmt.Errorf("witness item len mismatch: got=%d want=%d", len(item), proverinput.DepositWitnessItemLen)
	}
	leafIndex := uint64(binary.LittleEndian.Uint32(item[depositWitnessLeafIndexOffset : depositWitnessLeafIndexOffset+4]))
	cm := common.BytesToHash(item[depositWitnessCMXOffset : depositWitnessCMXOffset+32])
	return cm, leafIndex, nil
}
