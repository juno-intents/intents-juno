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
	StorageFormat     string `json:"storage_format"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	command := "generate"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = strings.TrimSpace(args[0])
		args = args[1:]
	}

	switch command {
	case "generate":
		return runGenerate(args, stdout)
	case "inspect":
		return runInspect(args, stdout)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func runGenerate(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("operator-keygen", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	privateKeyPath := fs.String("private-key-path", "", "path for operator secp256k1 private key")
	feeRecipient := fs.String("fee-recipient", "", "optional fee recipient address; defaults to operator address")
	storageFormat := fs.String("storage-format", string(operatorkey.FormatEncrypted), "key storage format: encrypted")
	passphrase := fs.String("passphrase", "", "encryption passphrase for encrypted key generation")
	passphraseEnv := fs.String("passphrase-env", "", "env var containing encryption passphrase")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*privateKeyPath) == "" {
		return fmt.Errorf("private-key-path is required")
	}

	keyPassphrase, err := resolvePassphrase(*passphrase, *passphraseEnv)
	if err != nil {
		return err
	}
	if format := operatorkey.StorageFormat(strings.TrimSpace(*storageFormat)); format != operatorkey.FormatEncrypted {
		return fmt.Errorf("unsupported storage format %q", strings.TrimSpace(*storageFormat))
	}

	key, created, err := operatorkey.GeneratePrivateKeyFile(*privateKeyPath, operatorkey.GenerateOptions{
		Format:     operatorkey.FormatEncrypted,
		Passphrase: keyPassphrase,
	})
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
		StorageFormat:     strings.TrimSpace(*storageFormat),
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func runInspect(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("operator-keygen inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	privateKeyPath := fs.String("private-key-path", "", "path for operator secp256k1 private key")
	feeRecipient := fs.String("fee-recipient", "", "optional fee recipient address; defaults to operator address")
	passphrase := fs.String("passphrase", "", "decryption passphrase for encrypted key loading")
	passphraseEnv := fs.String("passphrase-env", "", "env var containing decryption passphrase")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*privateKeyPath) == "" {
		return fmt.Errorf("private-key-path is required")
	}

	keyPassphrase, err := resolvePassphrase(*passphrase, *passphraseEnv)
	if err != nil {
		return err
	}
	key, err := operatorkey.LoadPrivateKeyFile(*privateKeyPath, operatorkey.LoadOptions{Passphrase: keyPassphrase})
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
		PrivateKeyCreated: false,
		StorageFormat:     "existing",
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func resolvePassphrase(literal string, envName string) (string, error) {
	if strings.TrimSpace(literal) != "" {
		return literal, nil
	}
	envName = strings.TrimSpace(envName)
	if envName == "" {
		return "", nil
	}
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return "", fmt.Errorf("passphrase env %s is empty", envName)
	}
	return value, nil
}
