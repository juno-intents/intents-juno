package bridgeabi

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
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

type LogFilterer interface {
	FilterLogs(ctx context.Context, q ethereum.FilterQuery) ([]types.Log, error)
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

type WithdrawalView struct {
	Requester       common.Address
	Amount          *big.Int
	Expiry          uint64
	FeeBpsAtRequest *big.Int
	Finalized       bool
	RecipientUA     []byte
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

func PackDepositUsedCalldata(depositID common.Hash) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	b, err := bridgeABI.Pack("depositUsed", depositID)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack depositUsed calldata: %w", err)
	}
	return b, nil
}

func UnpackDepositUsedResult(raw []byte) (bool, error) {
	if err := initABI(); err != nil {
		return false, err
	}
	values, err := bridgeABI.Methods["depositUsed"].Outputs.Unpack(raw)
	if err != nil {
		return false, fmt.Errorf("bridgeabi: unpack depositUsed result: %w", err)
	}
	if len(values) != 1 {
		return false, fmt.Errorf("%w: unexpected depositUsed output count", ErrInvalidInput)
	}
	used, ok := values[0].(bool)
	if !ok {
		return false, fmt.Errorf("%w: unexpected depositUsed output type", ErrInvalidInput)
	}
	return used, nil
}

func PackGetWithdrawalCalldata(withdrawalID common.Hash) ([]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	b, err := bridgeABI.Pack("getWithdrawal", withdrawalID)
	if err != nil {
		return nil, fmt.Errorf("bridgeabi: pack getWithdrawal calldata: %w", err)
	}
	return b, nil
}

func UnpackGetWithdrawalResult(raw []byte) (WithdrawalView, error) {
	if err := initABI(); err != nil {
		return WithdrawalView{}, err
	}
	values, err := bridgeABI.Methods["getWithdrawal"].Outputs.Unpack(raw)
	if err != nil {
		return WithdrawalView{}, fmt.Errorf("bridgeabi: unpack getWithdrawal result: %w", err)
	}
	if len(values) != 6 {
		return WithdrawalView{}, fmt.Errorf("%w: unexpected getWithdrawal output count", ErrInvalidInput)
	}
	requester, ok := values[0].(common.Address)
	if !ok {
		return WithdrawalView{}, fmt.Errorf("%w: unexpected getWithdrawal requester output type", ErrInvalidInput)
	}
	amount, ok := values[1].(*big.Int)
	if !ok || amount == nil {
		return WithdrawalView{}, fmt.Errorf("%w: unexpected getWithdrawal amount output type", ErrInvalidInput)
	}
	expiry, ok := values[2].(uint64)
	if !ok {
		return WithdrawalView{}, fmt.Errorf("%w: unexpected getWithdrawal expiry output type", ErrInvalidInput)
	}
	feeBpsAtRequest, ok := values[3].(*big.Int)
	if !ok || feeBpsAtRequest == nil {
		return WithdrawalView{}, fmt.Errorf("%w: unexpected getWithdrawal fee output type", ErrInvalidInput)
	}
	finalized, ok := values[4].(bool)
	if !ok {
		return WithdrawalView{}, fmt.Errorf("%w: unexpected getWithdrawal finalized output type", ErrInvalidInput)
	}
	recipientUA, ok := values[5].([]byte)
	if !ok {
		return WithdrawalView{}, fmt.Errorf("%w: unexpected getWithdrawal recipient output type", ErrInvalidInput)
	}
	return WithdrawalView{
		Requester:       requester,
		Amount:          amount,
		Expiry:          expiry,
		FeeBpsAtRequest: feeBpsAtRequest,
		Finalized:       finalized,
		RecipientUA:     append([]byte(nil), recipientUA...),
	}, nil
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

func PackLastAcceptedCheckpointHeightCalldata() ([]byte, error) {
	return crypto.Keccak256([]byte("lastAcceptedCheckpointHeight()"))[:4], nil
}

func UnpackLastAcceptedCheckpointHeightResult(raw []byte) (uint64, error) {
	if len(raw) < 32 {
		return 0, fmt.Errorf("%w: lastAcceptedCheckpointHeight result too short", ErrInvalidInput)
	}
	height := new(big.Int).SetBytes(raw[len(raw)-32:])
	if height.Sign() < 0 || height.BitLen() > 64 {
		return 0, fmt.Errorf("%w: unexpected lastAcceptedCheckpointHeight output type", ErrInvalidInput)
	}
	return height.Uint64(), nil
}

func PackLastAcceptedCheckpointBlockHashCalldata() ([]byte, error) {
	return crypto.Keccak256([]byte("lastAcceptedCheckpointBlockHash()"))[:4], nil
}

func UnpackLastAcceptedCheckpointBlockHashResult(raw []byte) (common.Hash, error) {
	if len(raw) < 32 {
		return common.Hash{}, fmt.Errorf("%w: lastAcceptedCheckpointBlockHash result too short", ErrInvalidInput)
	}
	return common.BytesToHash(raw[len(raw)-32:]), nil
}

func PackLastAcceptedCheckpointFinalOrchardRootCalldata() ([]byte, error) {
	return crypto.Keccak256([]byte("lastAcceptedCheckpointFinalOrchardRoot()"))[:4], nil
}

func UnpackLastAcceptedCheckpointFinalOrchardRootResult(raw []byte) (common.Hash, error) {
	if len(raw) < 32 {
		return common.Hash{}, fmt.Errorf("%w: lastAcceptedCheckpointFinalOrchardRoot result too short", ErrInvalidInput)
	}
	return common.BytesToHash(raw[len(raw)-32:]), nil
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

func FindMintedDepositTxHashes(
	ctx context.Context,
	filterer LogFilterer,
	bridge common.Address,
	depositIDs [][32]byte,
	toBlock *big.Int,
) (map[[32]byte][32]byte, error) {
	if err := initABI(); err != nil {
		return nil, err
	}
	if filterer == nil {
		return nil, fmt.Errorf("%w: nil log filterer", ErrInvalidInput)
	}
	if bridge == (common.Address{}) {
		return nil, fmt.Errorf("%w: nil bridge address", ErrInvalidInput)
	}
	ids := uniqueDepositIDs(depositIDs)
	if len(ids) == 0 {
		return map[[32]byte][32]byte{}, nil
	}

	mintedEvent, ok := bridgeABI.Events["Minted"]
	if !ok {
		return nil, fmt.Errorf("%w: missing Minted event", ErrInvalidInput)
	}

	topics := make([]common.Hash, 0, len(ids))
	for _, id := range ids {
		topics = append(topics, common.BytesToHash(id[:]))
	}

	byDeposit := make(map[[32]byte]types.Log, len(ids))
	if toBlock == nil {
		logs, err := filterer.FilterLogs(ctx, ethereum.FilterQuery{
			Addresses: []common.Address{bridge},
			Topics:    [][]common.Hash{{mintedEvent.ID}, topics},
		})
		if err != nil {
			return nil, fmt.Errorf("bridgeabi: filter minted deposit logs: %w", err)
		}
		if err := collectMintedDepositLogs(byDeposit, logs, bridge, mintedEvent.ID); err != nil {
			return nil, err
		}
	} else {
		remaining := append([][32]byte(nil), ids...)
		currentTo := new(big.Int).Set(toBlock)
		maxSpan := big.NewInt(9_999)
		one := big.NewInt(1)
		zero := big.NewInt(0)

		// Duplicate-skipped deposits come from near-concurrent submissions.
		// Walk backward in 10k-block windows and stop once every requested
		// deposit id has its Minted log, instead of issuing one genesis-sized
		// query that public Base endpoints reject.
		for currentTo.Cmp(zero) >= 0 && len(remaining) > 0 {
			currentFrom := new(big.Int).Sub(currentTo, maxSpan)
			if currentFrom.Sign() < 0 {
				currentFrom = new(big.Int)
			}
			windowTopics := make([]common.Hash, 0, len(remaining))
			for _, id := range remaining {
				windowTopics = append(windowTopics, common.BytesToHash(id[:]))
			}
			logs, err := filterer.FilterLogs(ctx, ethereum.FilterQuery{
				Addresses: []common.Address{bridge},
				Topics:    [][]common.Hash{{mintedEvent.ID}, windowTopics},
				FromBlock: new(big.Int).Set(currentFrom),
				ToBlock:   new(big.Int).Set(currentTo),
			})
			if err != nil {
				return nil, fmt.Errorf("bridgeabi: filter minted deposit logs: %w", err)
			}
			if err := collectMintedDepositLogs(byDeposit, logs, bridge, mintedEvent.ID); err != nil {
				return nil, err
			}
			nextRemaining := remaining[:0]
			for _, id := range remaining {
				if _, ok := byDeposit[id]; ok {
					continue
				}
				nextRemaining = append(nextRemaining, id)
			}
			remaining = append([][32]byte(nil), nextRemaining...)
			if currentFrom.Sign() == 0 {
				break
			}
			currentTo = new(big.Int).Sub(currentFrom, one)
		}
	}

	out := make(map[[32]byte][32]byte, len(byDeposit))
	for depositID, lg := range byDeposit {
		out[depositID] = [32]byte(lg.TxHash)
	}
	return out, nil
}

func collectMintedDepositLogs(byDeposit map[[32]byte]types.Log, logs []types.Log, bridge common.Address, mintedEventID common.Hash) error {
	for _, lg := range logs {
		if lg.Address != bridge || len(lg.Topics) == 0 || lg.Topics[0] != mintedEventID {
			continue
		}
		if len(lg.Topics) < 2 {
			return fmt.Errorf("%w: Minted log missing indexed deposit id", ErrInvalidInput)
		}
		depositID := [32]byte(lg.Topics[1])
		prev, ok := byDeposit[depositID]
		if !ok || logComesEarlier(lg, prev) {
			byDeposit[depositID] = lg
		}
	}
	return nil
}

func logComesEarlier(a, b types.Log) bool {
	if a.BlockNumber != b.BlockNumber {
		return a.BlockNumber < b.BlockNumber
	}
	if a.TxIndex != b.TxIndex {
		return a.TxIndex < b.TxIndex
	}
	return a.Index < b.Index
}

func uniqueDepositIDs(ids [][32]byte) [][32]byte {
	if len(ids) <= 1 {
		return append([][32]byte(nil), ids...)
	}
	seen := make(map[[32]byte]struct{}, len(ids))
	out := make([][32]byte, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
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
    "inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],
    "name":"depositUsed",
    "outputs":[{"internalType":"bool","name":"","type":"bool"}],
    "stateMutability":"view",
    "type":"function"
  },
  {
    "inputs": [{"internalType":"bytes32","name":"withdrawalId","type":"bytes32"}],
    "name":"getWithdrawal",
    "outputs":[
      {"internalType":"address","name":"requester","type":"address"},
      {"internalType":"uint256","name":"amount","type":"uint256"},
      {"internalType":"uint64","name":"expiry","type":"uint64"},
      {"internalType":"uint96","name":"feeBpsAtRequest","type":"uint96"},
      {"internalType":"bool","name":"finalized","type":"bool"},
      {"internalType":"bytes","name":"recipientUA","type":"bytes"}
    ],
    "stateMutability":"view",
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
