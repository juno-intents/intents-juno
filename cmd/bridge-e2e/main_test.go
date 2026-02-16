package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseArgs_Valid(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	deployer := filepath.Join(tmp, "deployer.key")
	op1 := filepath.Join(tmp, "op1.key")
	op2 := filepath.Join(tmp, "op2.key")
	op3 := filepath.Join(tmp, "op3.key")

	if err := os.WriteFile(deployer, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("write deployer key: %v", err)
	}
	if err := os.WriteFile(op1, []byte("0x59c6995e998f97a5a0044976f6f8f5f2b0f95f4d4e4d7d75e4f3f7c06f2a3d9a\n"), 0o600); err != nil {
		t.Fatalf("write op1 key: %v", err)
	}
	if err := os.WriteFile(op2, []byte("0x8b3a350cf5c34c9194ca3a545d4f0b3f15f65f8f5e89f7e5e301d5e7bc7d3c0d\n"), 0o600); err != nil {
		t.Fatalf("write op2 key: %v", err)
	}
	if err := os.WriteFile(op3, []byte("0x0f4d64c83f2d2e4f3e96b3b1e9a8d7c6b5a493827161514131211100f0e0d0c0\n"), 0o600); err != nil {
		t.Fatalf("write op3 key: %v", err)
	}

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-file", deployer,
		"--operator-key-file", op1,
		"--operator-key-file", op2,
		"--operator-key-file", op3,
		"--threshold", "3",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.RPCURL != "https://example-rpc.invalid" {
		t.Fatalf("rpc-url: got %q", cfg.RPCURL)
	}
	if cfg.ChainID != 84532 {
		t.Fatalf("chain-id: got %d", cfg.ChainID)
	}
	if len(cfg.OperatorKeyFiles) != 3 {
		t.Fatalf("operator keys: got %d", len(cfg.OperatorKeyFiles))
	}
	if cfg.Threshold != 3 {
		t.Fatalf("threshold: got %d", cfg.Threshold)
	}
}

func TestParseArgs_RequiresEnoughOperatorKeys(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--threshold", "3",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseArgs_RejectsWithdrawLargerThanDeposit(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--deposit-amount", "100",
		"--withdraw-amount", "200",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}
