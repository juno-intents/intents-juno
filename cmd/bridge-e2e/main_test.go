package main

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
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

func TestParseArgs_PrepareOnlyRequiresProofInputsOutput(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--prepare-only",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseArgs_RejectsInvalidVerifierAddress(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--verifier-address", "0x1234",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseArgs_RejectsInvalidSealHex(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--deposit-seal-hex", "xyz",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseArgs_RejectsInvalidImageID(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--deposit-image-id", "0x1234",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseArgs_VerifierRequiresSealsWithoutPrepareOnly(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseArgs_PrepareOnlyAllowsVerifierWithoutSeals(t *testing.T) {
	t.Parallel()

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--prepare-only",
		"--proof-inputs-output", "/tmp/proof-inputs.json",
	})
	if err != nil {
		t.Fatalf("expected parse success, got: %v", err)
	}
	if !cfg.PrepareOnly {
		t.Fatalf("expected prepare-only true")
	}
	if len(cfg.DepositSeal) != 0 || len(cfg.WithdrawSeal) != 0 {
		t.Fatalf("expected empty seals in prepare-only mode")
	}
}

func TestParseArgs_BoundlessAutoRequiresRequestorKeyFile(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--boundless-auto",
		"--boundless-bin", "boundless",
		"--boundless-rpc-url", "https://mainnet.base.org",
		"--boundless-deposit-program-url", "https://example.invalid/deposit.elf",
		"--boundless-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--deposit-seal-hex", "0x99",
		"--withdraw-seal-hex", "0x99",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--boundless-requestor-key-file") {
		t.Fatalf("expected requestor key file error, got: %v", err)
	}
}

func TestParseArgs_BoundlessAutoRejectsPrepareOnly(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0x11\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--prepare-only",
		"--proof-inputs-output", "/tmp/proof-inputs.json",
		"--boundless-auto",
		"--boundless-bin", "boundless",
		"--boundless-rpc-url", "https://mainnet.base.org",
		"--boundless-requestor-key-file", requestorKey,
		"--boundless-deposit-program-url", "https://example.invalid/deposit.elf",
		"--boundless-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "cannot be used with --prepare-only") {
		t.Fatalf("expected prepare-only incompatibility error, got: %v", err)
	}
}

func TestParseArgs_BoundlessAutoValid(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0x0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--boundless-auto",
		"--boundless-bin", "boundless",
		"--boundless-rpc-url", "https://mainnet.base.org",
		"--boundless-input-mode", "journal-bytes-v1",
		"--boundless-market-address", "0xFd152dADc5183870710FE54f939Eae3aB9F0fE82",
		"--boundless-verifier-router-address", "0x0b144e07a0826182b6b59788c34b32bfa86fb711",
		"--boundless-set-verifier-address", "0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104",
		"--boundless-requestor-key-file", requestorKey,
		"--boundless-deposit-program-url", "https://example.invalid/deposit.elf",
		"--boundless-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--boundless-min-price-wei", "100000000000000",
		"--boundless-max-price-wei", "250000000000000",
		"--boundless-lock-stake-wei", "20000000000000000000",
		"--boundless-bidding-delay-seconds", "85",
		"--boundless-ramp-up-period-seconds", "170",
		"--boundless-lock-timeout-seconds", "625",
		"--boundless-timeout-seconds", "1500",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !cfg.Boundless.Auto {
		t.Fatalf("expected boundless auto mode enabled")
	}
	if cfg.Boundless.Bin != "boundless" {
		t.Fatalf("unexpected boundless bin: %q", cfg.Boundless.Bin)
	}
	if cfg.Boundless.InputMode != "journal-bytes-v1" {
		t.Fatalf("unexpected boundless input mode: %q", cfg.Boundless.InputMode)
	}
	if cfg.Boundless.MarketAddress != common.HexToAddress("0xFd152dADc5183870710FE54f939Eae3aB9F0fE82") {
		t.Fatalf("unexpected boundless market address: %s", cfg.Boundless.MarketAddress.Hex())
	}
	if cfg.Boundless.VerifierRouterAddr != common.HexToAddress("0x0b144e07a0826182b6b59788c34b32bfa86fb711") {
		t.Fatalf("unexpected boundless verifier router address: %s", cfg.Boundless.VerifierRouterAddr.Hex())
	}
	if cfg.Boundless.SetVerifierAddr != common.HexToAddress("0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104") {
		t.Fatalf("unexpected boundless set verifier address: %s", cfg.Boundless.SetVerifierAddr.Hex())
	}
	if cfg.Boundless.RequestorKeyHex == "" {
		t.Fatalf("expected requestor key loaded from file")
	}
	if cfg.Boundless.DepositProgramURL != "https://example.invalid/deposit.elf" {
		t.Fatalf("unexpected deposit program url: %q", cfg.Boundless.DepositProgramURL)
	}
	if cfg.Boundless.WithdrawProgramURL != "https://example.invalid/withdraw.elf" {
		t.Fatalf("unexpected withdraw program url: %q", cfg.Boundless.WithdrawProgramURL)
	}
}

func TestParseArgs_BoundlessAutoRejectsInvalidInputMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0x0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--boundless-auto",
		"--boundless-bin", "boundless",
		"--boundless-rpc-url", "https://mainnet.base.org",
		"--boundless-input-mode", "invalid-mode",
		"--boundless-requestor-key-file", requestorKey,
		"--boundless-deposit-program-url", "https://example.invalid/deposit.elf",
		"--boundless-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--boundless-input-mode") {
		t.Fatalf("expected boundless input mode error, got: %v", err)
	}
}

func TestParseArgs_BoundlessAutoRejectsInvalidMarketAddress(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0x0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--boundless-auto",
		"--boundless-bin", "boundless",
		"--boundless-rpc-url", "https://mainnet.base.org",
		"--boundless-market-address", "not-an-address",
		"--boundless-requestor-key-file", requestorKey,
		"--boundless-deposit-program-url", "https://example.invalid/deposit.elf",
		"--boundless-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--boundless-market-address") {
		t.Fatalf("expected boundless market address error, got: %v", err)
	}
}

func TestParseArgs_BoundlessAutoRejectsInvalidVerifierRouterAddress(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0x0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--boundless-auto",
		"--boundless-bin", "boundless",
		"--boundless-rpc-url", "https://mainnet.base.org",
		"--boundless-verifier-router-address", "bad-address",
		"--boundless-requestor-key-file", requestorKey,
		"--boundless-deposit-program-url", "https://example.invalid/deposit.elf",
		"--boundless-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--boundless-verifier-router-address") {
		t.Fatalf("expected boundless verifier router address error, got: %v", err)
	}
}

func TestParseArgs_BoundlessAutoRejectsInvalidSetVerifierAddress(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0x0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--boundless-auto",
		"--boundless-bin", "boundless",
		"--boundless-rpc-url", "https://mainnet.base.org",
		"--boundless-set-verifier-address", "bad-address",
		"--boundless-requestor-key-file", requestorKey,
		"--boundless-deposit-program-url", "https://example.invalid/deposit.elf",
		"--boundless-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--boundless-set-verifier-address") {
		t.Fatalf("expected boundless set verifier address error, got: %v", err)
	}
}

func TestParseBoundlessWaitOutput(t *testing.T) {
	t.Parallel()

	out := strings.Join([]string{
		"2026-02-16T00:00:00Z  INFO Submitted request 0x8fd, bidding starts at 2026-02-16 00:01:25 UTC",
		"2026-02-16T00:10:00Z  INFO Request fulfilled!",
		"2026-02-16T00:10:00Z  INFO Journal: \"0x010203\" - Seal: \"0x99aa\"",
	}, "\n")

	got, err := parseBoundlessWaitOutput([]byte(out))
	if err != nil {
		t.Fatalf("parseBoundlessWaitOutput: %v", err)
	}
	if got.RequestIDHex != "0x8fd" {
		t.Fatalf("request id: got %q", got.RequestIDHex)
	}
	if got.JournalHex != "0x010203" {
		t.Fatalf("journal: got %q", got.JournalHex)
	}
	if got.SealHex != "0x99aa" {
		t.Fatalf("seal: got %q", got.SealHex)
	}
}

func TestParseBoundlessWaitOutput_RequestorSubmitFormat(t *testing.T) {
	t.Parallel()

	out := strings.Join([]string{
		"Submitting Proof Request from YAML [Unknown Network]",
		"  Assigned Request ID: 0x28ae6a6bc48ac3e425df6e5cbce845eb0001ceae5952e986",
		"",
		"✓ Request submitted successfully",
		"",
		"ℹ Waiting for request fulfillment...",
		"",
		"✓ Request fulfilled!",
		"",
		"Fulfillment Data:",
		"{",
		`  "ImageIdAndJournal": [`,
		"    [1,2,3,4,5,6,7,8],",
		`    "0x01020304"`,
		"  ]",
		"}",
		"",
		"Seal:",
		`"0x99aa55"`,
	}, "\n")

	got, err := parseBoundlessWaitOutput([]byte(out))
	if err != nil {
		t.Fatalf("parseBoundlessWaitOutput: %v", err)
	}
	if got.RequestIDHex != "0x28ae6a6bc48ac3e425df6e5cbce845eb0001ceae5952e986" {
		t.Fatalf("request id: got %q", got.RequestIDHex)
	}
	if got.JournalHex != "0x01020304" {
		t.Fatalf("journal: got %q", got.JournalHex)
	}
	if got.SealHex != "0x99aa55" {
		t.Fatalf("seal: got %q", got.SealHex)
	}
}

func TestParseBoundlessWaitOutput_MissingSeal(t *testing.T) {
	t.Parallel()

	out := "2026-02-16T00:00:00Z  INFO Submitted request 0x8fd, bidding starts at 2026-02-16 00:01:25 UTC"
	_, err := parseBoundlessWaitOutput([]byte(out))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "seal") {
		t.Fatalf("expected missing seal error, got: %v", err)
	}
}

func TestBoundlessPrivateInputVersion_DetectsKnownJSONEnvelope(t *testing.T) {
	t.Parallel()

	got := boundlessPrivateInputVersion([]byte(`{"version":"deposit.private_input.v1","items":[]}`))
	if got != "deposit.private_input.v1" {
		t.Fatalf("input version: got %q", got)
	}
}

func TestBoundlessPrivateInputVersion_IgnoresBinaryOrMissingVersion(t *testing.T) {
	t.Parallel()

	if got := boundlessPrivateInputVersion([]byte{0x01, 0x02, 0x03}); got != "" {
		t.Fatalf("expected empty version for binary input, got %q", got)
	}

	if got := boundlessPrivateInputVersion([]byte(`{"items":[]}`)); got != "" {
		t.Fatalf("expected empty version for json without version, got %q", got)
	}
}

func TestEncodeBoundlessJournalInput(t *testing.T) {
	t.Parallel()

	in := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	got, err := encodeBoundlessJournalInput(in)
	if err != nil {
		t.Fatalf("encodeBoundlessJournalInput: %v", err)
	}
	if len(got) != 8 {
		t.Fatalf("encoded len: got %d want 8", len(got))
	}
	if got[0] != 0x04 || got[1] != 0x00 || got[2] != 0x00 || got[3] != 0x00 {
		t.Fatalf("unexpected length prefix: %x", got[:4])
	}
	if string(got[4:]) != string(in) {
		t.Fatalf("unexpected payload: %x", got[4:])
	}
}

func TestProofInputsFile_WithdrawAmountMarshals(t *testing.T) {
	t.Parallel()

	var f proofInputsFile
	f.Withdraw.Amount = "10000"

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal proof inputs: %v", err)
	}
	if !strings.Contains(string(b), `"amount":"10000"`) {
		t.Fatalf("expected withdraw amount in json, got: %s", string(b))
	}
}

func TestComputePredictedWithdrawalID_Deterministic(t *testing.T) {
	t.Parallel()

	chainID := uint64(84532)
	bridge := common.HexToAddress("0x475576d5685465D5bd65E91Cf10053f9d0EFd685")
	requester := common.HexToAddress("0x1eeCC6a02Cb4A990197dC5C18FC481c7841D021B")
	amount := new(big.Int).SetUint64(10_000)
	recipientUA := []byte{0x01, 0x02, 0x03}

	got1, err := computePredictedWithdrawalID(chainID, bridge, 1, requester, amount, recipientUA)
	if err != nil {
		t.Fatalf("computePredictedWithdrawalID: %v", err)
	}
	got2, err := computePredictedWithdrawalID(chainID, bridge, 1, requester, amount, recipientUA)
	if err != nil {
		t.Fatalf("computePredictedWithdrawalID: %v", err)
	}
	if got1 != got2 {
		t.Fatalf("expected deterministic withdrawal id, got %s != %s", got1.Hex(), got2.Hex())
	}

	got3, err := computePredictedWithdrawalID(chainID, bridge, 2, requester, amount, recipientUA)
	if err != nil {
		t.Fatalf("computePredictedWithdrawalID: %v", err)
	}
	if got1 == got3 {
		t.Fatalf("expected nonce to affect withdrawal id")
	}
}

type mockCallResponse struct {
	result any
	err    error
}

type mockDepositUsedCaller struct {
	expectedDepositID common.Hash
	responses         []mockCallResponse
	calls             int
	blockNumbers      []*big.Int
}

func (m *mockDepositUsedCaller) Call(opts *bind.CallOpts, results *[]any, method string, params ...any) error {
	if method != "depositUsed" {
		return errors.New("unexpected method")
	}
	if len(params) != 1 {
		return errors.New("unexpected params")
	}
	depositID, ok := params[0].(common.Hash)
	if !ok {
		return errors.New("unexpected param type")
	}
	if depositID != m.expectedDepositID {
		return errors.New("unexpected deposit id")
	}
	if opts == nil || opts.BlockNumber == nil {
		return errors.New("missing block number")
	}
	m.blockNumbers = append(m.blockNumbers, new(big.Int).Set(opts.BlockNumber))
	m.calls++

	if len(m.responses) == 0 {
		*results = []any{false}
		return nil
	}
	idx := m.calls - 1
	if idx >= len(m.responses) {
		idx = len(m.responses) - 1
	}
	resp := m.responses[idx]
	if resp.err != nil {
		return resp.err
	}
	*results = []any{resp.result}
	return nil
}

func TestWaitDepositUsedAtBlock_RetriesUntilTrue(t *testing.T) {
	t.Parallel()

	depositID := common.HexToHash("0x1234")
	blockNumber := big.NewInt(42)
	bridge := &mockDepositUsedCaller{
		expectedDepositID: depositID,
		responses: []mockCallResponse{
			{result: false},
			{result: false},
			{result: true},
		},
	}

	used, err := waitDepositUsedAtBlock(context.Background(), bridge, depositID, blockNumber, 5, 0)
	if err != nil {
		t.Fatalf("waitDepositUsedAtBlock: %v", err)
	}
	if !used {
		t.Fatalf("expected deposit to be used")
	}
	if bridge.calls != 3 {
		t.Fatalf("expected 3 calls, got %d", bridge.calls)
	}
	for _, got := range bridge.blockNumbers {
		if got.Cmp(blockNumber) != 0 {
			t.Fatalf("expected block number %s, got %s", blockNumber, got)
		}
	}
}

func TestWaitDepositUsedAtBlock_ReturnsFalseAfterAttempts(t *testing.T) {
	t.Parallel()

	depositID := common.HexToHash("0xabcd")
	bridge := &mockDepositUsedCaller{
		expectedDepositID: depositID,
		responses: []mockCallResponse{
			{result: false},
			{result: false},
		},
	}

	used, err := waitDepositUsedAtBlock(context.Background(), bridge, depositID, big.NewInt(7), 2, 0)
	if err != nil {
		t.Fatalf("waitDepositUsedAtBlock: %v", err)
	}
	if used {
		t.Fatalf("expected depositUsed=false")
	}
	if bridge.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", bridge.calls)
	}
}

func TestWaitDepositUsedAtBlock_ReturnsLastError(t *testing.T) {
	t.Parallel()

	depositID := common.HexToHash("0xfeed")
	bridge := &mockDepositUsedCaller{
		expectedDepositID: depositID,
		responses: []mockCallResponse{
			{err: errors.New("missing trie node")},
			{err: errors.New("header not found")},
		},
	}

	used, err := waitDepositUsedAtBlock(context.Background(), bridge, depositID, big.NewInt(99), 2, 0)
	if err == nil {
		t.Fatalf("expected error")
	}
	if used {
		t.Fatalf("expected used=false on error")
	}
	if !strings.Contains(err.Error(), "header not found") {
		t.Fatalf("expected last error in message, got: %v", err)
	}
}

func TestTransactAuthWithDefaults_UsesDefaultGasLimit(t *testing.T) {
	t.Parallel()

	base := &bind.TransactOpts{
		GasLimit: 0,
		Nonce:    big.NewInt(7),
	}

	got := transactAuthWithDefaults(base, 1_000_000)
	if got == base {
		t.Fatalf("expected a cloned transact opts")
	}
	if got.GasLimit != 1_000_000 {
		t.Fatalf("expected default gas limit, got %d", got.GasLimit)
	}
	if base.GasLimit != 0 {
		t.Fatalf("expected original auth gas limit unchanged, got %d", base.GasLimit)
	}
}

func TestTransactAuthWithDefaults_RespectsExistingGasLimit(t *testing.T) {
	t.Parallel()

	base := &bind.TransactOpts{
		GasLimit: 555_000,
	}

	got := transactAuthWithDefaults(base, 1_000_000)
	if got == base {
		t.Fatalf("expected a cloned transact opts")
	}
	if got.GasLimit != 555_000 {
		t.Fatalf("expected existing gas limit preserved, got %d", got.GasLimit)
	}
	if base.GasLimit != 555_000 {
		t.Fatalf("expected original auth gas limit unchanged, got %d", base.GasLimit)
	}
}

func TestIsRetriableNonceError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nonce too low",
			err:  errors.New("nonce too low: next nonce 63, tx nonce 62"),
			want: true,
		},
		{
			name: "replacement underpriced",
			err:  errors.New("replacement transaction underpriced"),
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("execution reverted"),
			want: false,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isRetriableNonceError(tc.err)
			if got != tc.want {
				t.Fatalf("isRetriableNonceError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestComputeFeeBreakdown(t *testing.T) {
	t.Parallel()

	out := computeFeeBreakdown(new(big.Int).SetUint64(100_000), 50, 1000)
	if out.Fee.Cmp(big.NewInt(500)) != 0 {
		t.Fatalf("fee: got %s want 500", out.Fee.String())
	}
	if out.Tip.Cmp(big.NewInt(50)) != 0 {
		t.Fatalf("tip: got %s want 50", out.Tip.String())
	}
	if out.FeeToDistributor.Cmp(big.NewInt(450)) != 0 {
		t.Fatalf("feeToDistributor: got %s want 450", out.FeeToDistributor.String())
	}
	if out.Net.Cmp(big.NewInt(99_500)) != 0 {
		t.Fatalf("net: got %s want 99500", out.Net.String())
	}
}

func TestExpectedBalanceDeltas_RecipientEqualsOwner(t *testing.T) {
	t.Parallel()

	deltas := expectedBalanceDeltas(expectedBalanceDeltaInput{
		DepositAmount:        big.NewInt(100_000),
		WithdrawAmount:       big.NewInt(10_000),
		DepositFeeBps:        50,
		WithdrawFeeBps:       50,
		RelayerTipBps:        1000,
		RecipientEqualsOwner: true,
	})

	if deltas.Owner.Cmp(big.NewInt(89_555)) != 0 {
		t.Fatalf("owner delta: got %s want 89555", deltas.Owner.String())
	}
	if deltas.Recipient.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("recipient delta: got %s want 0", deltas.Recipient.String())
	}
	if deltas.FeeDistributor.Cmp(big.NewInt(495)) != 0 {
		t.Fatalf("fee distributor delta: got %s want 495", deltas.FeeDistributor.String())
	}
}

func TestExpectedBalanceDeltas_RecipientDiffersFromOwner(t *testing.T) {
	t.Parallel()

	deltas := expectedBalanceDeltas(expectedBalanceDeltaInput{
		DepositAmount:        big.NewInt(100_000),
		WithdrawAmount:       big.NewInt(10_000),
		DepositFeeBps:        50,
		WithdrawFeeBps:       50,
		RelayerTipBps:        1000,
		RecipientEqualsOwner: false,
	})

	if deltas.Owner.Cmp(big.NewInt(-9_945)) != 0 {
		t.Fatalf("owner delta: got %s want -9945", deltas.Owner.String())
	}
	if deltas.Recipient.Cmp(big.NewInt(99_500)) != 0 {
		t.Fatalf("recipient delta: got %s want 99500", deltas.Recipient.String())
	}
	if deltas.FeeDistributor.Cmp(big.NewInt(495)) != 0 {
		t.Fatalf("fee distributor delta: got %s want 495", deltas.FeeDistributor.String())
	}
}
