package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/junokey"
)

type outputDoc struct {
	Version            string `json:"version"`
	Network            string `json:"network"`
	TransparentAddress string `json:"transparent_address"`
	WIFCompressed      string `json:"wif_compressed"`
	EthereumAddress    string `json:"ethereum_address_hint"`
}

func main() {
	if err := runMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdout io.Writer) error {
	var privateKeyFile string
	var privateKeyHex string
	var network string
	var wifOutput string

	fs := flag.NewFlagSet("juno-keyinfo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&privateKeyFile, "private-key-file", "", "file containing 0x-prefixed private key hex")
	fs.StringVar(&privateKeyHex, "private-key-hex", "", "0x-prefixed private key hex")
	fs.StringVar(&network, "network", "testnet", "network to derive for (supported: testnet)")
	fs.StringVar(&wifOutput, "wif-output", "", "optional output file for derived testnet WIF")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if privateKeyFile == "" && privateKeyHex == "" {
		return errors.New("one of --private-key-file or --private-key-hex is required")
	}
	if privateKeyFile != "" && privateKeyHex != "" {
		return errors.New("use only one of --private-key-file or --private-key-hex")
	}
	if network != "testnet" {
		return errors.New("--network currently supports only testnet")
	}

	if privateKeyFile != "" {
		raw, err := os.ReadFile(privateKeyFile)
		if err != nil {
			return fmt.Errorf("read private key file: %w", err)
		}
		privateKeyHex = strings.TrimSpace(string(raw))
	}

	keyBytes, err := junokey.ParsePrivateKeyHex(privateKeyHex)
	if err != nil {
		return err
	}
	wif, err := junokey.TestnetWIFCompressed(privateKeyHex)
	if err != nil {
		return err
	}
	taddr, err := junokey.TestnetTransparentAddress(privateKeyHex)
	if err != nil {
		return err
	}
	priv, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		return err
	}

	doc := outputDoc{
		Version:            "juno.keyinfo.v1",
		Network:            network,
		TransparentAddress: taddr,
		WIFCompressed:      wif,
		EthereumAddress:    crypto.PubkeyToAddress(priv.PublicKey).Hex(),
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "%s\n", out); err != nil {
		return err
	}

	if strings.TrimSpace(wifOutput) != "" {
		if err := os.MkdirAll(filepath.Dir(wifOutput), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(wifOutput, []byte(wif+"\n"), 0o600); err != nil {
			return err
		}
	}

	return nil
}
