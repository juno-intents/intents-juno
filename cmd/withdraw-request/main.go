package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type withdrawRequestedEvent struct {
	WithdrawalID common.Hash
	Requester    common.Address
	Amount       uint64
	RecipientUA  []byte
	Expiry       uint64
	FeeBps       uint32
}

type withdrawRequestedPayload struct {
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

func main() {
	if err := runMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("withdraw-request", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	rpcURL := fs.String("rpc-url", "", "Base RPC URL")
	chainID := fs.Uint64("chain-id", 0, "Base chain ID")
	ownerKeyFile := fs.String("owner-key-file", "", "owner private key file")
	ownerKeyHex := fs.String("owner-key-hex", "", "owner private key hex")
	wjunoAddressHex := fs.String("wjuno-address", "", "WJuno contract address")
	bridgeAddressHex := fs.String("bridge-address", "", "Bridge contract address")
	amount := fs.Uint64("amount", 0, "withdraw amount")
	recipientRawHex := fs.String("recipient-raw-address-hex", "", "recipient raw Orchard address (43-byte hex)")
	proofWitnessItemFile := fs.String("proof-witness-item-file", "", "optional withdraw witness item file")
	outputPath := fs.String("output", "-", "output file path or '-' for stdout")
	timeout := fs.Duration("timeout", 3*time.Minute, "request timeout")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*rpcURL) == "" {
		return errors.New("--rpc-url is required")
	}
	if *chainID == 0 {
		return errors.New("--chain-id is required")
	}
	if strings.TrimSpace(*ownerKeyFile) != "" && strings.TrimSpace(*ownerKeyHex) != "" {
		return errors.New("use only one of --owner-key-file or --owner-key-hex")
	}
	if strings.TrimSpace(*ownerKeyFile) == "" && strings.TrimSpace(*ownerKeyHex) == "" {
		return errors.New("owner key is required (--owner-key-file or --owner-key-hex)")
	}
	if !common.IsHexAddress(strings.TrimSpace(*wjunoAddressHex)) {
		return errors.New("--wjuno-address must be a valid hex address")
	}
	if !common.IsHexAddress(strings.TrimSpace(*bridgeAddressHex)) {
		return errors.New("--bridge-address must be a valid hex address")
	}
	if *amount == 0 {
		return errors.New("--amount must be > 0")
	}
	if *timeout <= 0 {
		return errors.New("--timeout must be > 0")
	}

	recipientRaw, err := parseFixedHex(strings.TrimSpace(*recipientRawHex), 43)
	if err != nil {
		return fmt.Errorf("parse --recipient-raw-address-hex: %w", err)
	}

	privateKeyHex := strings.TrimSpace(*ownerKeyHex)
	if strings.TrimSpace(*ownerKeyFile) != "" {
		b, err := os.ReadFile(strings.TrimSpace(*ownerKeyFile))
		if err != nil {
			return fmt.Errorf("read owner key file: %w", err)
		}
		privateKeyHex = strings.TrimSpace(string(b))
	}
	privateKey, err := parsePrivateKeyHex(privateKeyHex)
	if err != nil {
		return err
	}

	var proofWitnessItem []byte
	if strings.TrimSpace(*proofWitnessItemFile) != "" {
		proofWitnessItem, err = os.ReadFile(strings.TrimSpace(*proofWitnessItemFile))
		if err != nil {
			return fmt.Errorf("read proof witness item file: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client, err := ethclient.DialContext(ctx, *rpcURL)
	if err != nil {
		return fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	chainIDBig := new(big.Int).SetUint64(*chainID)
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainIDBig)
	if err != nil {
		return fmt.Errorf("new transactor: %w", err)
	}
	auth.Context = ctx

	wjunoABI, err := abi.JSON(strings.NewReader(wjunoABIJSON))
	if err != nil {
		return fmt.Errorf("parse wjuno abi: %w", err)
	}
	bridgeABI, err := abi.JSON(strings.NewReader(bridgeABIJSON))
	if err != nil {
		return fmt.Errorf("parse bridge abi: %w", err)
	}

	wjunoAddr := common.HexToAddress(strings.TrimSpace(*wjunoAddressHex))
	bridgeAddr := common.HexToAddress(strings.TrimSpace(*bridgeAddressHex))
	wjunoContract := bind.NewBoundContract(wjunoAddr, wjunoABI, client, client, client)
	bridgeContract := bind.NewBoundContract(bridgeAddr, bridgeABI, client, client, client)

	approveTx, err := wjunoContract.Transact(auth, "approve", bridgeAddr, new(big.Int).SetUint64(*amount))
	if err != nil {
		return fmt.Errorf("approve wjuno: %w", err)
	}
	approveReceipt, err := bind.WaitMined(ctx, client, approveTx)
	if err != nil {
		return fmt.Errorf("wait approve receipt: %w", err)
	}
	if approveReceipt == nil || approveReceipt.Status != 1 {
		return errors.New("approve transaction failed")
	}

	requestTx, err := bridgeContract.Transact(auth, "requestWithdraw", new(big.Int).SetUint64(*amount), recipientRaw)
	if err != nil {
		return fmt.Errorf("requestWithdraw: %w", err)
	}
	requestReceipt, err := bind.WaitMined(ctx, client, requestTx)
	if err != nil {
		return fmt.Errorf("wait requestWithdraw receipt: %w", err)
	}
	if requestReceipt == nil || requestReceipt.Status != 1 {
		return errors.New("requestWithdraw transaction failed")
	}

	event, err := parseWithdrawRequestedEvent(requestReceipt.Logs, bridgeAddr, bridgeABI)
	if err != nil {
		return err
	}

	payload := withdrawRequestedPayload{
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
	if len(proofWitnessItem) > 0 {
		payload.ProofWitnessItem = "0x" + hex.EncodeToString(proofWitnessItem)
	}

	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	encoded = append(encoded, '\n')

	if strings.TrimSpace(*outputPath) == "" || *outputPath == "-" {
		_, err := stdout.Write(encoded)
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*outputPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(*outputPath, encoded, 0o644)
}

func parsePrivateKeyHex(raw string) (*ecdsa.PrivateKey, error) {
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

func parseFixedHex(raw string, wantLen int) ([]byte, error) {
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

func parseWithdrawRequestedEvent(logs []*types.Log, bridgeAddress common.Address, bridgeABI abi.ABI) (withdrawRequestedEvent, error) {
	event, ok := bridgeABI.Events["WithdrawRequested"]
	if !ok {
		return withdrawRequestedEvent{}, errors.New("bridge ABI missing WithdrawRequested event")
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
			return withdrawRequestedEvent{}, fmt.Errorf("decode WithdrawRequested data: %w", err)
		}
		if len(fields) != 4 {
			return withdrawRequestedEvent{}, fmt.Errorf("unexpected WithdrawRequested field count: got=%d want=4", len(fields))
		}

		amount, err := toUint64(fields[0])
		if err != nil {
			return withdrawRequestedEvent{}, fmt.Errorf("decode amount: %w", err)
		}
		recipientUA, ok := fields[1].([]byte)
		if !ok {
			return withdrawRequestedEvent{}, errors.New("decode recipientUA: expected []byte")
		}
		expiry, err := toUint64(fields[2])
		if err != nil {
			return withdrawRequestedEvent{}, fmt.Errorf("decode expiry: %w", err)
		}
		feeBps64, err := toUint64(fields[3])
		if err != nil {
			return withdrawRequestedEvent{}, fmt.Errorf("decode feeBps: %w", err)
		}
		if feeBps64 > uint64(^uint32(0)) {
			return withdrawRequestedEvent{}, fmt.Errorf("feeBps out of range: %d", feeBps64)
		}

		return withdrawRequestedEvent{
			WithdrawalID: common.Hash(lg.Topics[1]),
			Requester:    common.BytesToAddress(lg.Topics[2].Bytes()),
			Amount:       amount,
			RecipientUA:  append([]byte(nil), recipientUA...),
			Expiry:       expiry,
			FeeBps:       uint32(feeBps64),
		}, nil
	}
	return withdrawRequestedEvent{}, errors.New("WithdrawRequested event not found in receipt logs")
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

const wjunoABIJSON = `[
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

const bridgeABIJSON = `[
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
