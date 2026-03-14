package bridgeabi

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

var ErrInvalidInput = errors.New("bridgeabi: invalid input")

type MintItem struct {
	DepositId common.Hash
	Recipient common.Address
	Amount    *big.Int
}

type FinalizeItem struct {
	WithdrawalId    common.Hash
	RecipientUAHash common.Hash
	NetAmount       *big.Int
}

// DepositJournal mirrors Bridge.DepositJournal (contracts/src/Bridge.sol).
type DepositJournal struct {
	FinalOrchardRoot common.Hash
	BaseChainId      *big.Int
	BridgeContract   common.Address
	Items            []MintItem
}

// WithdrawJournal mirrors Bridge.WithdrawJournal (contracts/src/Bridge.sol).
type WithdrawJournal struct {
	FinalOrchardRoot common.Hash
	BaseChainId      *big.Int
	BridgeContract   common.Address
	Items            []FinalizeItem
}

var (
	initOnce sync.Once
	initErr  error

	bridgeABI          abi.ABI
	depositJournalABI  abi.Arguments
	withdrawJournalABI abi.Arguments
)

func initABI() error {
	initOnce.Do(func() {
		var err error

		bridgeABI, err = abi.JSON(strings.NewReader(bridgeABIJSON))
		if err != nil {
			initErr = fmt.Errorf("bridgeabi: parse Bridge ABI: %w", err)
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

		withdrawJournalType, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
			{Name: "finalOrchardRoot", Type: "bytes32"},
			{Name: "baseChainId", Type: "uint256"},
			{Name: "bridgeContract", Type: "address"},
			{Name: "items", Type: "tuple[]", Components: []abi.ArgumentMarshaling{
				{Name: "withdrawalId", Type: "bytes32"},
				{Name: "recipientUAHash", Type: "bytes32"},
				{Name: "netAmount", Type: "uint256"},
			}},
		})
		if err != nil {
			initErr = fmt.Errorf("bridgeabi: build WithdrawJournal ABI type: %w", err)
			return
		}
		withdrawJournalABI = abi.Arguments{{Name: "wj", Type: withdrawJournalType}}
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

func EncodeWithdrawJournal(wj WithdrawJournal) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	if wj.BaseChainId == nil || wj.BaseChainId.Sign() <= 0 {
		return nil, fmt.Errorf("%w: BaseChainId must be > 0", ErrInvalidInput)
	}
	if (wj.BridgeContract == common.Address{}) {
		return nil, fmt.Errorf("%w: BridgeContract must be non-zero", ErrInvalidInput)
	}
	for i := range wj.Items {
		it := wj.Items[i]
		if it.NetAmount == nil || it.NetAmount.Sign() < 0 {
			return nil, fmt.Errorf("%w: item[%d].NetAmount must be >= 0", ErrInvalidInput, i)
		}
	}

	b, err := withdrawJournalABI.Pack(wj)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack WithdrawJournal: %w", err)
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

	// Use a struct with fields matching the Solidity tuple names (see bridgeABIJSON).
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

func PackFinalizeWithdrawBatchCalldata(cp checkpoint.Checkpoint, operatorSigs [][]byte, seal []byte, journal []byte) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	if cp.BaseChainID == 0 {
		return nil, fmt.Errorf("%w: checkpoint BaseChainID must be non-zero", ErrInvalidInput)
	}
	if (cp.BridgeContract == common.Address{}) {
		return nil, fmt.Errorf("%w: checkpoint BridgeContract must be non-zero", ErrInvalidInput)
	}

	// Use a struct with fields matching the Solidity tuple names (see bridgeABIJSON).
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

	b, err := bridgeABI.Pack("finalizeWithdrawBatch", cpABI, operatorSigs, seal, journal)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack finalizeWithdrawBatch calldata: %w", err)
	}
	return b, nil
}

func PackExtendWithdrawExpiryBatchCalldata(withdrawalIDs []common.Hash, newExpiry uint64, operatorSigs [][]byte) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	if len(withdrawalIDs) == 0 {
		return nil, fmt.Errorf("%w: empty withdrawalIDs", ErrInvalidInput)
	}
	if newExpiry == 0 {
		return nil, fmt.Errorf("%w: newExpiry must be non-zero", ErrInvalidInput)
	}

	b, err := bridgeABI.Pack("extendWithdrawExpiryBatch", withdrawalIDs, newExpiry, operatorSigs)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack extendWithdrawExpiryBatch calldata: %w", err)
	}
	return b, nil
}

func PackMarkWithdrawPaidBatchCalldata(withdrawalIDs []common.Hash, operatorSigs [][]byte) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	if len(withdrawalIDs) == 0 {
		return nil, fmt.Errorf("%w: empty withdrawalIDs", ErrInvalidInput)
	}

	b, err := bridgeABI.Pack("markWithdrawPaidBatch", withdrawalIDs, operatorSigs)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack markWithdrawPaidBatch calldata: %w", err)
	}
	return b, nil
}

func PackMinDepositAmountCalldata() ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	b, err := bridgeABI.Pack("minDepositAmount")
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack minDepositAmount calldata: %w", err)
	}
	return b, nil
}

func UnpackMinDepositAmountResult(raw []byte) (*big.Int, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	values, err := bridgeABI.Methods["minDepositAmount"].Outputs.Unpack(raw)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: unpack minDepositAmount result: %w", err)
	}
	if len(values) != 1 {
		return nil, fmt.Errorf("%w: unexpected minDepositAmount output count", ErrInvalidInput)
	}
	amount, ok := values[0].(*big.Int)
	if !ok || amount == nil {
		return nil, fmt.Errorf("%w: unexpected minDepositAmount output type", ErrInvalidInput)
	}
	return amount, nil
}

func PackMinDepositAdminCalldata() ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	b, err := bridgeABI.Pack("minDepositAdmin")
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack minDepositAdmin calldata: %w", err)
	}
	return b, nil
}

func UnpackMinDepositAdminResult(raw []byte) (common.Address, error) {
	if err := initABI(); err != nil {
		return common.Address{}, err
	}
	values, err := bridgeABI.Methods["minDepositAdmin"].Outputs.Unpack(raw)
	if err != nil {
		return common.Address{}, fmt.Errorf("bridgeabi: unpack minDepositAdmin result: %w", err)
	}
	if len(values) != 1 {
		return common.Address{}, fmt.Errorf("%w: unexpected minDepositAdmin output count", ErrInvalidInput)
	}
	admin, ok := values[0].(common.Address)
	if !ok {
		return common.Address{}, fmt.Errorf("%w: unexpected minDepositAdmin output type", ErrInvalidInput)
	}
	return admin, nil
}

func PackSetMinDepositAmountCalldata(amount uint64) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	b, err := bridgeABI.Pack("setMinDepositAmount", new(big.Int).SetUint64(amount))
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack setMinDepositAmount calldata: %w", err)
	}
	return b, nil
}

func PackSetMinDepositAdminCalldata(admin common.Address) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	if admin == (common.Address{}) {
		return nil, fmt.Errorf("%w: nil minDepositAdmin", ErrInvalidInput)
	}
	b, err := bridgeABI.Pack("setMinDepositAdmin", admin)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack setMinDepositAdmin calldata: %w", err)
	}
	return b, nil
}

func DecodeMintBatchLogOutcomes(logs []*types.Log, bridge common.Address) ([][32]byte, [][32]byte, error) {
	if err := initABI(); err != nil {
		return nil, nil, err
	}
	mintedEvent, ok := bridgeABI.Events["Minted"]
	if !ok {
		return nil, nil, fmt.Errorf("%w: missing Minted event", ErrInvalidInput)
	}
	skippedEvent, ok := bridgeABI.Events["DepositSkipped"]
	if !ok {
		return nil, nil, fmt.Errorf("%w: missing DepositSkipped event", ErrInvalidInput)
	}

	finalized := make([][32]byte, 0)
	rejected := make([][32]byte, 0)
	for _, lg := range logs {
		if lg == nil || lg.Address != bridge || len(lg.Topics) == 0 {
			continue
		}
		switch lg.Topics[0] {
		case mintedEvent.ID:
			if len(lg.Topics) < 2 {
				return nil, nil, fmt.Errorf("%w: Minted log missing indexed deposit id", ErrInvalidInput)
			}
			finalized = append(finalized, [32]byte(lg.Topics[1]))
		case skippedEvent.ID:
			if len(lg.Topics) < 2 {
				return nil, nil, fmt.Errorf("%w: DepositSkipped log missing indexed deposit id", ErrInvalidInput)
			}
			rejected = append(rejected, [32]byte(lg.Topics[1]))
		}
	}
	return finalized, rejected, nil
}

const bridgeABIJSON = `[
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
  },
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
    "name":"finalizeWithdrawBatch",
    "outputs":[],
    "stateMutability":"nonpayable",
    "type":"function"
  },
  {
    "inputs": [
      {"internalType":"bytes32[]","name":"withdrawalIds","type":"bytes32[]"},
      {"internalType":"uint64","name":"newExpiry","type":"uint64"},
      {"internalType":"bytes[]","name":"operatorSigs","type":"bytes[]"}
    ],
    "name":"extendWithdrawExpiryBatch",
    "outputs":[],
    "stateMutability":"nonpayable",
    "type":"function"
  },
  {
    "inputs": [
      {"internalType":"bytes32[]","name":"withdrawalIds","type":"bytes32[]"},
      {"internalType":"bytes[]","name":"operatorSigs","type":"bytes[]"}
    ],
    "name":"markWithdrawPaidBatch",
    "outputs":[],
    "stateMutability":"nonpayable",
    "type":"function"
  },
  {
    "inputs": [],
    "name":"minDepositAmount",
    "outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
    "stateMutability":"view",
    "type":"function"
  },
  {
    "inputs": [],
    "name":"minDepositAdmin",
    "outputs":[{"internalType":"address","name":"","type":"address"}],
    "stateMutability":"view",
    "type":"function"
  },
  {
    "inputs": [{"internalType":"uint256","name":"newMinDepositAmount","type":"uint256"}],
    "name":"setMinDepositAmount",
    "outputs":[],
    "stateMutability":"nonpayable",
    "type":"function"
  },
  {
    "inputs": [{"internalType":"address","name":"newMinDepositAdmin","type":"address"}],
    "name":"setMinDepositAdmin",
    "outputs":[],
    "stateMutability":"nonpayable",
    "type":"function"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed":true,"internalType":"bytes32","name":"depositId","type":"bytes32"},
      {"indexed":true,"internalType":"address","name":"recipient","type":"address"},
      {"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"},
      {"indexed":false,"internalType":"uint256","name":"fee","type":"uint256"},
      {"indexed":false,"internalType":"uint256","name":"relayerTip","type":"uint256"}
    ],
    "name":"Minted",
    "type":"event"
  },
  {
    "anonymous": false,
    "inputs": [
      {"indexed":true,"internalType":"bytes32","name":"depositId","type":"bytes32"}
    ],
    "name":"DepositSkipped",
    "type":"event"
  }
]`
