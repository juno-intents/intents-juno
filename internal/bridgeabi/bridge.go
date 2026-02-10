package bridgeabi

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

var ErrInvalidInput = errors.New("bridgeabi: invalid input")

type MintItem struct {
	DepositId common.Hash
	Recipient common.Address
	Amount    *big.Int
}

// DepositJournal mirrors Bridge.DepositJournal (contracts/src/Bridge.sol).
type DepositJournal struct {
	FinalOrchardRoot common.Hash
	BaseChainId      *big.Int
	BridgeContract   common.Address
	Items            []MintItem
}

var (
	initOnce sync.Once
	initErr  error

	bridgeABI         abi.ABI
	depositJournalABI abi.Arguments
)

func initABI() error {
	initOnce.Do(func() {
		var err error

		bridgeABI, err = abi.JSON(strings.NewReader(mintBatchABIJSON))
		if err != nil {
			initErr = fmt.Errorf("bridgeabi: parse mintBatch ABI: %w", err)
			return
		}

		journalType, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
			{Name: "finalOrchardRoot", Type: "bytes32"},
			{Name: "baseChainId", Type: "uint256"},
			{Name: "bridgeContract", Type: "address"},
			{Name: "items", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
				{Name: "depositId", Type: "bytes32"},
				{Name: "recipient", Type: "address"},
				{Name: "amount", Type: "uint256"},
			}},
		})
		if err != nil {
			initErr = fmt.Errorf("bridgeabi: build DepositJournal ABI type: %w", err)
			return
		}

		depositJournalABI = abi.Arguments{{Name: "dj", Type: journalType}}
	})
	return initErr
}

func EncodeDepositJournal(dj DepositJournal) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	if dj.BaseChainId == nil || dj.BaseChainId.Sign() <= 0 {
		return nil, fmt.Errorf("%w: BaseChainId must be > 0", ErrInvalidInput)
	}
	if (dj.BridgeContract == common.Address{}) {
		return nil, fmt.Errorf("%w: BridgeContract must be non-zero", ErrInvalidInput)
	}
	for i := range dj.Items {
		it := dj.Items[i]
		if it.Amount == nil || it.Amount.Sign() < 0 {
			return nil, fmt.Errorf("%w: item[%d].Amount must be >= 0", ErrInvalidInput, i)
		}
		// Recipient/amount validation happens in the contract too; we allow zero values to preserve batch resilience.
	}

	b, err := depositJournalABI.Pack(dj)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack DepositJournal: %w", err)
	}
	return b, nil
}

func PackMintBatchCalldata(cp checkpoint.Checkpoint, operatorSigs [][]byte, seal []byte, journal []byte) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	if cp.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: checkpoint BaseChainID must be non-zero", ErrInvalidInput)
	}
	if (cp.BridgeContract == common.Address{}) {
		return nil, fmt.Errorf("%w: checkpoint BridgeContract must be non-zero", ErrInvalidInput)
	}

	// Use a struct with fields matching the Solidity tuple names (see mintBatchABIJSON).
	type checkpointABI struct {
		Height           uint64
		BlockHash        common.Hash
		FinalOrchardRoot common.Hash
		BaseChainId      *big.Int
		BridgeContract   common.Address
	}

	cpABI := checkpointABI{
		Height:           cp.Height,
		BlockHash:        cp.BlockHash,
		FinalOrchardRoot: cp.FinalOrchardRoot,
		BaseChainId:      new(big.Int).SetUint64(cp.BaseChainID),
		BridgeContract:   cp.BridgeContract,
	}

	b, err := bridgeABI.Pack("mintBatch", cpABI, operatorSigs, seal, journal)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack mintBatch calldata: %w", err)
	}
	return b, nil
}

const mintBatchABIJSON = `[
  {
    "inputs": [
      {
        "components": [
          {"internalType":"uint64","name":"height","type":"uint64"},
          {"internalType":"bytes32","name":"blockHash","type":"bytes32"},
          {"internalType":"bytes32","name":"finalOrchardRoot","type":"bytes32"},
          {"internalType":"uint256","name":"baseChainId","type":"uint256"},
          {"internalType":"address","name":"bridgeContract","type":"address"}
        ],
        "internalType":"struct Bridge.Checkpoint",
        "name":"checkpoint",
        "type":"tuple"
      },
      {"internalType":"bytes[]","name":"operatorSigs","type":"bytes[]"},
      {"internalType":"bytes","name":"seal","type":"bytes"},
      {"internalType":"bytes","name":"journal","type":"bytes"}
    ],
    "name":"mintBatch",
    "outputs":[],
    "stateMutability":"nonpayable",
    "type":"function"
  }
]`

