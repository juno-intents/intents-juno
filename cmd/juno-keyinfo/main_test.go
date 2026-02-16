package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMain_OutputsTestnetMetadataAndWIFFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "juno.key")
	wifFile := filepath.Join(tmp, "juno.wif")
	if err := os.WriteFile(keyFile, []byte("0x4c0883a69102937d6231471b5dbb6204fe5129617082794e8a16f3f6c52b7d03\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	var out bytes.Buffer
	if err := runMain([]string{
		"--private-key-file", keyFile,
		"--network", "testnet",
		"--wif-output", wifFile,
	}, &out); err != nil {
		t.Fatalf("runMain: %v", err)
	}

	var doc struct {
		Version            string `json:"version"`
		Network            string `json:"network"`
		TransparentAddress string `json:"transparent_address"`
		WIFCompressed      string `json:"wif_compressed"`
		EthereumAddress    string `json:"ethereum_address_hint"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if doc.Version != "juno.keyinfo.v1" {
		t.Fatalf("version: got %q", doc.Version)
	}
	if doc.Network != "testnet" {
		t.Fatalf("network: got %q", doc.Network)
	}
	if !strings.HasPrefix(doc.TransparentAddress, "tm") {
		t.Fatalf("transparent address prefix: got %q", doc.TransparentAddress)
	}
	if doc.WIFCompressed == "" {
		t.Fatalf("missing wif_compressed")
	}
	if !strings.HasPrefix(doc.EthereumAddress, "0x") {
		t.Fatalf("ethereum address hint: got %q", doc.EthereumAddress)
	}

	wifRaw, err := os.ReadFile(wifFile)
	if err != nil {
		t.Fatalf("read wif file: %v", err)
	}
	if strings.TrimSpace(string(wifRaw)) != doc.WIFCompressed {
		t.Fatalf("wif file mismatch")
	}
}

func TestRunMain_RejectsMissingKey(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := runMain([]string{
		"--private-key-file", "/no/such/file",
	}, &out)
	if err == nil {
		t.Fatalf("expected error")
	}
}
