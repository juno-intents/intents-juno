package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/juno-intents/intents-juno/internal/withdrawrequest"
)

type withdrawRequestedEvent = withdrawrequest.RequestedEvent
type withdrawRequestedPayload = withdrawrequest.Payload

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
	if _, err := parsePrivateKeyHex(privateKeyHex); err != nil {
		return err
	}

	var proofWitnessItem []byte
	if strings.TrimSpace(*proofWitnessItemFile) != "" {
		proofWitnessItem, err = os.ReadFile(strings.TrimSpace(*proofWitnessItemFile))
		if err != nil {
			return fmt.Errorf("read proof witness item file: %w", err)
		}
	}

	payload, err := withdrawrequest.RequestWithdrawal(context.Background(), withdrawrequest.Config{
		RPCURL:       *rpcURL,
		ChainID:      *chainID,
		OwnerKeyHex:  privateKeyHex,
		WJunoAddress: common.HexToAddress(strings.TrimSpace(*wjunoAddressHex)),
		BridgeAddr:   common.HexToAddress(strings.TrimSpace(*bridgeAddressHex)),
		Timeout:      *timeout,
	}, withdrawrequest.Request{
		Amount:           *amount,
		RecipientUA:      recipientRaw,
		ProofWitnessItem: proofWitnessItem,
	})
	if err != nil {
		return err
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
	return withdrawrequest.ParsePrivateKeyHex(raw)
}

func parseFixedHex(raw string, wantLen int) ([]byte, error) {
	return withdrawrequest.ParseFixedHex(raw, wantLen)
}

func parseWithdrawRequestedEvent(logs []*types.Log, bridgeAddress common.Address, bridgeABI abi.ABI) (withdrawRequestedEvent, error) {
	return withdrawrequest.ParseWithdrawRequestedEvent(logs, bridgeAddress, bridgeABI)
}

const wjunoABIJSON = withdrawrequest.WJunoABIJSON
const bridgeABIJSON = withdrawrequest.BridgeABIJSON
