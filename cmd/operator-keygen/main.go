package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/juno-intents/intents-juno/internal/operatorkey"
)

type output struct {
	OperatorID        string `json:"operator_id"`
	FeeRecipient      string `json:"fee_recipient"`
	PrivateKeyPath    string `json:"private_key_path"`
	PrivateKeyCreated bool   `json:"private_key_created"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("operator-keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	privateKeyPath := fs.String("private-key-path", "", "path for operator secp256k1 private key (created if missing)")
	feeRecipient := fs.String("fee-recipient", "", "optional fee recipient address; defaults to operator address")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*privateKeyPath) == "" {
		return fmt.Errorf("private-key-path is required")
	}

	key, created, err := operatorkey.EnsurePrivateKeyFile(*privateKeyPath)
	if err != nil {
		return err
	}
	operatorID := operatorkey.OperatorIDFromPrivateKey(key)

	fee := operatorID
	if strings.TrimSpace(*feeRecipient) != "" {
		fee, err = operatorkey.NormalizeAddress(*feeRecipient)
		if err != nil {
			return fmt.Errorf("invalid fee recipient: %w", err)
		}
	}

	payload := output{
		OperatorID:        operatorID,
		FeeRecipient:      fee,
		PrivateKeyPath:    *privateKeyPath,
		PrivateKeyCreated: created,
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}
