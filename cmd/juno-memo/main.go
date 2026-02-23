package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/memo"
)

func main() {
	if err := runMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("subcommand is required: deposit|withdraw")
	}
	subcommand := strings.TrimSpace(args[0])
	switch subcommand {
	case "deposit":
		return runDeposit(args[1:], stdout)
	case "withdraw":
		return runWithdraw(args[1:], stdout)
	default:
		return fmt.Errorf("unsupported subcommand %q (want deposit|withdraw)", subcommand)
	}
}

func runDeposit(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("juno-memo deposit", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	baseChainID := fs.Uint64("base-chain-id", 0, "Base chain id")
	bridgeAddressHex := fs.String("bridge-address", "", "Bridge contract address")
	recipientHex := fs.String("recipient", "", "Base recipient address")
	nonce := fs.Uint64("nonce", 0, "Memo nonce")
	flags := fs.Uint64("flags", 0, "Memo flags")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *baseChainID == 0 || *baseChainID > math.MaxUint32 {
		return errors.New("--base-chain-id is required and must fit uint32")
	}
	if *flags > math.MaxUint32 {
		return errors.New("--flags must fit uint32")
	}
	if !common.IsHexAddress(strings.TrimSpace(*bridgeAddressHex)) {
		return errors.New("--bridge-address must be a valid hex address")
	}
	if !common.IsHexAddress(strings.TrimSpace(*recipientHex)) {
		return errors.New("--recipient must be a valid hex address")
	}

	bridge := common.HexToAddress(strings.TrimSpace(*bridgeAddressHex))
	recipient := common.HexToAddress(strings.TrimSpace(*recipientHex))
	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	var recipient20 [20]byte
	copy(recipient20[:], recipient[:])

	m := memo.DepositMemoV1{
		BaseChainID:   uint32(*baseChainID),
		BridgeAddr:    bridge20,
		BaseRecipient: recipient20,
		Nonce:         *nonce,
		Flags:         uint32(*flags),
	}
	encoded := m.Encode()
	_, err := fmt.Fprintf(stdout, "0x%s\n", hex.EncodeToString(encoded[:]))
	return err
}

func runWithdraw(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("juno-memo withdraw", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	baseChainID := fs.Uint64("base-chain-id", 0, "Base chain id")
	bridgeAddressHex := fs.String("bridge-address", "", "Bridge contract address")
	withdrawalIDHex := fs.String("withdrawal-id", "", "Withdrawal ID bytes32 hex")
	batchIDHex := fs.String("batch-id", "", "Batch ID bytes32 hex")
	flags := fs.Uint64("flags", 0, "Memo flags")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *baseChainID == 0 || *baseChainID > math.MaxUint32 {
		return errors.New("--base-chain-id is required and must fit uint32")
	}
	if *flags > math.MaxUint32 {
		return errors.New("--flags must fit uint32")
	}
	if !common.IsHexAddress(strings.TrimSpace(*bridgeAddressHex)) {
		return errors.New("--bridge-address must be a valid hex address")
	}

	withdrawalIDBytes, err := parseFixedHex(*withdrawalIDHex, 32)
	if err != nil {
		return fmt.Errorf("--withdrawal-id: %w", err)
	}
	batchIDBytes, err := parseFixedHex(*batchIDHex, 32)
	if err != nil {
		return fmt.Errorf("--batch-id: %w", err)
	}

	bridge := common.HexToAddress(strings.TrimSpace(*bridgeAddressHex))
	var bridge20 [20]byte
	copy(bridge20[:], bridge[:])
	var withdrawalID [32]byte
	copy(withdrawalID[:], withdrawalIDBytes)
	var batchID [32]byte
	copy(batchID[:], batchIDBytes)

	m := memo.WithdrawalMemoV1{
		BaseChainID:  uint32(*baseChainID),
		BridgeAddr:   bridge20,
		WithdrawalID: withdrawalID,
		BatchID:      batchID,
		Flags:        uint32(*flags),
	}
	encoded := m.Encode()
	_, err = fmt.Fprintf(stdout, "0x%s\n", hex.EncodeToString(encoded[:]))
	return err
}

func parseFixedHex(raw string, wantLen int) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "0x")
	raw = strings.TrimPrefix(raw, "0X")
	if raw == "" {
		return nil, errors.New("value is required")
	}
	if len(raw)%2 != 0 {
		return nil, errors.New("hex length must be even")
	}
	out, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(out) != wantLen {
		return nil, fmt.Errorf("must be %d bytes", wantLen)
	}
	return out, nil
}
