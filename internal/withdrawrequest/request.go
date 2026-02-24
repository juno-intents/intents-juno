package withdrawrequest

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type Config struct {
	RPCURL       string
	ChainID      uint64
	OwnerKeyHex  string
	WJunoAddress common.Address
	BridgeAddr   common.Address
	Timeout      time.Duration
}

type Request struct {
	Amount           uint64
	RecipientUA      []byte
	ProofWitnessItem []byte
}

type RequestedEvent struct {
	WithdrawalID common.Hash
	Requester    common.Address
	Amount       uint64
	RecipientUA  []byte
	Expiry       uint64
	FeeBps       uint32
}

type Payload struct {
	Version          string `json:"version"`
	WithdrawalID     string `json:"withdrawalId"`
	Requester        string `json:"requester"`
	Amount           uint64 `json:"amount"`
	RecipientUA      string `json:"recipientUA"`
	ProofWitnessItem string `json:"proofWitnessItem,omitempty"`
	Expiry           uint64 `json:"expiry"`
	FeeBps           uint32 `json:"feeBps"`
	ApproveTxHash    string `json:"approveTxHash"`
	RequestTxHash    string `json:"requestTxHash"`
}

func RequestWithdrawal(ctx context.Context, cfg Config, req Request) (Payload, error) {
	if strings.TrimSpace(cfg.RPCURL) == "" {
		return Payload{}, errors.New("rpc url is required")
	}
	if cfg.ChainID == 0 {
		return Payload{}, errors.New("chain id is required")
	}
	if cfg.WJunoAddress == (common.Address{}) {
		return Payload{}, errors.New("wjuno address is required")
	}
	if cfg.BridgeAddr == (common.Address{}) {
		return Payload{}, errors.New("bridge address is required")
	}
	if strings.TrimSpace(cfg.OwnerKeyHex) == "" {
		return Payload{}, errors.New("owner key is required")
	}
	if req.Amount == 0 {
		return Payload{}, errors.New("amount must be > 0")
	}
	if len(req.RecipientUA) == 0 {
		return Payload{}, errors.New("recipient ua is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Minute
	}

	privateKey, err := ParsePrivateKeyHex(cfg.OwnerKeyHex)
	if err != nil {
		return Payload{}, err
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client, err := ethclient.DialContext(ctx, cfg.RPCURL)
	if err != nil {
		return Payload{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	chainIDBig := new(big.Int).SetUint64(cfg.ChainID)
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainIDBig)
	if err != nil {
		return Payload{}, fmt.Errorf("new transactor: %w", err)
	}
	auth.Context = ctx

	wjunoABI, err := abi.JSON(strings.NewReader(WJunoABIJSON))
	if err != nil {
		return Payload{}, fmt.Errorf("parse wjuno abi: %w", err)
	}
	bridgeABI, err := abi.JSON(strings.NewReader(BridgeABIJSON))
	if err != nil {
		return Payload{}, fmt.Errorf("parse bridge abi: %w", err)
	}

	wjunoContract := bind.NewBoundContract(cfg.WJunoAddress, wjunoABI, client, client, client)
	bridgeContract := bind.NewBoundContract(cfg.BridgeAddr, bridgeABI, client, client, client)

	approveTx, err := wjunoContract.Transact(auth, "approve", cfg.BridgeAddr, new(big.Int).SetUint64(req.Amount))
	if err != nil {
		return Payload{}, fmt.Errorf("approve wjuno: %w", err)
	}
	approveReceipt, err := bind.WaitMined(ctx, client, approveTx)
	if err != nil {
		return Payload{}, fmt.Errorf("wait approve receipt: %w", err)
	}
	if approveReceipt == nil || approveReceipt.Status != 1 {
		return Payload{}, errors.New("approve transaction failed")
	}

	requestTx, err := bridgeContract.Transact(auth, "requestWithdraw", new(big.Int).SetUint64(req.Amount), req.RecipientUA)
	if err != nil {
		return Payload{}, fmt.Errorf("requestWithdraw: %w", err)
	}
	requestReceipt, err := bind.WaitMined(ctx, client, requestTx)
	if err != nil {
		return Payload{}, fmt.Errorf("wait requestWithdraw receipt: %w", err)
	}
	if requestReceipt == nil || requestReceipt.Status != 1 {
		return Payload{}, errors.New("requestWithdraw transaction failed")
	}

	event, err := ParseWithdrawRequestedEvent(requestReceipt.Logs, cfg.BridgeAddr, bridgeABI)
	if err != nil {
		return Payload{}, err
	}

	payload := Payload{
		Version:       "withdrawals.requested.v1",
		WithdrawalID:  event.WithdrawalID.Hex(),
		Requester:     event.Requester.Hex(),
		Amount:        event.Amount,
		RecipientUA:   "0x" + hex.EncodeToString(event.RecipientUA),
		Expiry:        event.Expiry,
		FeeBps:        event.FeeBps,
		ApproveTxHash: approveTx.Hash().Hex(),
		RequestTxHash: requestTx.Hash().Hex(),
	}
	if len(req.ProofWitnessItem) > 0 {
		payload.ProofWitnessItem = "0x" + hex.EncodeToString(req.ProofWitnessItem)
	}
	return payload, nil
}

func ParsePrivateKeyHex(raw string) (*ecdsa.PrivateKey, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "0x")
	raw = strings.TrimPrefix(raw, "0X")
	if raw == "" {
		return nil, errors.New("private key hex is empty")
	}
	pk, err := crypto.HexToECDSA(raw)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return pk, nil
}

func ParseFixedHex(raw string, wantLen int) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "0x")
	raw = strings.TrimPrefix(raw, "0X")
	if raw == "" {
		return nil, errors.New("hex value is empty")
	}
	b, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("hex length mismatch: got=%d want=%d", len(b), wantLen)
	}
	return b, nil
}

func ParseWithdrawRequestedEvent(logs []*types.Log, bridgeAddress common.Address, bridgeABI abi.ABI) (RequestedEvent, error) {
	event, ok := bridgeABI.Events["WithdrawRequested"]
	if !ok {
		return RequestedEvent{}, errors.New("bridge ABI missing WithdrawRequested event")
	}

	for _, lg := range logs {
		if lg == nil || lg.Address != bridgeAddress {
			continue
		}
		if len(lg.Topics) < 3 || lg.Topics[0] != event.ID {
			continue
		}

		fields, err := event.Inputs.NonIndexed().Unpack(lg.Data)
		if err != nil {
			return RequestedEvent{}, fmt.Errorf("decode WithdrawRequested data: %w", err)
		}
		if len(fields) != 4 {
			return RequestedEvent{}, fmt.Errorf("unexpected WithdrawRequested field count: got=%d want=4", len(fields))
		}

		amount, err := toUint64(fields[0])
		if err != nil {
			return RequestedEvent{}, fmt.Errorf("decode amount: %w", err)
		}
		recipientUA, ok := fields[1].([]byte)
		if !ok {
			return RequestedEvent{}, errors.New("decode recipientUA: expected []byte")
		}
		expiry, err := toUint64(fields[2])
		if err != nil {
			return RequestedEvent{}, fmt.Errorf("decode expiry: %w", err)
		}
		feeBps64, err := toUint64(fields[3])
		if err != nil {
			return RequestedEvent{}, fmt.Errorf("decode feeBps: %w", err)
		}
		if feeBps64 > uint64(^uint32(0)) {
			return RequestedEvent{}, fmt.Errorf("feeBps out of range: %d", feeBps64)
		}

		return RequestedEvent{
			WithdrawalID: common.Hash(lg.Topics[1]),
			Requester:    common.BytesToAddress(lg.Topics[2].Bytes()),
			Amount:       amount,
			RecipientUA:  append([]byte(nil), recipientUA...),
			Expiry:       expiry,
			FeeBps:       uint32(feeBps64),
		}, nil
	}
	return RequestedEvent{}, errors.New("WithdrawRequested event not found in receipt logs")
}

func toUint64(v any) (uint64, error) {
	switch tv := v.(type) {
	case uint8:
		return uint64(tv), nil
	case uint16:
		return uint64(tv), nil
	case uint32:
		return uint64(tv), nil
	case uint64:
		return tv, nil
	case *big.Int:
		if tv.Sign() < 0 || !tv.IsUint64() {
			return 0, fmt.Errorf("value out of range: %s", tv.String())
		}
		return tv.Uint64(), nil
	default:
		return 0, fmt.Errorf("unsupported numeric type %T", v)
	}
}

const WJunoABIJSON = `[
  {
    "inputs": [
      {"internalType": "address", "name": "spender", "type": "address"},
      {"internalType": "uint256", "name": "value", "type": "uint256"}
    ],
    "name": "approve",
    "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]`

const BridgeABIJSON = `[
  {
    "anonymous": false,
    "inputs": [
      {"indexed": true, "internalType": "bytes32", "name": "withdrawalId", "type": "bytes32"},
      {"indexed": true, "internalType": "address", "name": "requester", "type": "address"},
      {"indexed": false, "internalType": "uint256", "name": "amount", "type": "uint256"},
      {"indexed": false, "internalType": "bytes", "name": "recipientUA", "type": "bytes"},
      {"indexed": false, "internalType": "uint64", "name": "expiry", "type": "uint64"},
      {"indexed": false, "internalType": "uint96", "name": "feeBps", "type": "uint96"}
    ],
    "name": "WithdrawRequested",
    "type": "event"
  },
  {
    "inputs": [
      {"internalType": "uint256", "name": "amount", "type": "uint256"},
      {"internalType": "bytes", "name": "junoRecipientUA", "type": "bytes"}
    ],
    "name": "requestWithdraw",
    "outputs": [{"internalType": "bytes32", "name": "withdrawalId", "type": "bytes32"}],
    "stateMutability": "nonpayable",
    "type": "function"
  }
]`
