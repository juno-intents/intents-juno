package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/depositevent"
)

const (
	depositWitnessLeafIndexOffset = 0
	depositWitnessAuthPathOffset  = depositWitnessLeafIndexOffset + 4
	depositWitnessAuthPathLen     = 32 * 32
	depositWitnessActionOffset    = depositWitnessAuthPathOffset + depositWitnessAuthPathLen
	depositWitnessCMXOffset       = depositWitnessActionOffset + 32 + 32
)

type depositEventPayload = depositevent.Payload

func main() {
	if err := runMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("deposit-event", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	baseChainID := fs.Uint64("base-chain-id", 0, "Base/EVM chain id")
	bridgeAddressHex := fs.String("bridge-address", "", "Bridge contract address")
	recipientHex := fs.String("recipient", "", "Base recipient address")
	amount := fs.Uint64("amount", 0, "deposit amount")
	witnessItemFile := fs.String("witness-item-file", "", "deposit witness item file path")
	nonceRaw := fs.String("nonce", "", "optional memo nonce override")
	outputPath := fs.String("output", "-", "output path or '-' for stdout")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *baseChainID == 0 || *baseChainID > uint64(^uint32(0)) {
		return errors.New("--base-chain-id is required and must fit uint32")
	}
	if !common.IsHexAddress(strings.TrimSpace(*bridgeAddressHex)) {
		return errors.New("--bridge-address must be a valid hex address")
	}
	if !common.IsHexAddress(strings.TrimSpace(*recipientHex)) {
		return errors.New("--recipient must be a valid hex address")
	}
	if *amount == 0 {
		return errors.New("--amount must be > 0")
	}
	if strings.TrimSpace(*witnessItemFile) == "" {
		return errors.New("--witness-item-file is required")
	}

	witnessItem, err := os.ReadFile(*witnessItemFile)
	if err != nil {
		return fmt.Errorf("read witness item file: %w", err)
	}

	nonce, err := parseNonce(*nonceRaw)
	if err != nil {
		return err
	}

	payload, err := buildDepositEventPayload(
		uint32(*baseChainID),
		common.HexToAddress(strings.TrimSpace(*bridgeAddressHex)),
		common.HexToAddress(strings.TrimSpace(*recipientHex)),
		*amount,
		nonce,
		witnessItem,
	)
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

func parseNonce(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		var buf [8]byte
		if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
			return 0, fmt.Errorf("generate nonce: %w", err)
		}
		return binary.BigEndian.Uint64(buf[:]), nil
	}
	nonce, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse --nonce: %w", err)
	}
	return nonce, nil
}

func buildDepositEventPayload(baseChainID uint32, bridge, recipient common.Address, amount, nonce uint64, witnessItem []byte) (depositEventPayload, error) {
	return depositevent.BuildPayload(baseChainID, bridge, recipient, amount, nonce, witnessItem)
}

func parseDepositWitnessItem(item []byte) (common.Hash, uint64, error) {
	return depositevent.ParseWitnessItem(item)
}
