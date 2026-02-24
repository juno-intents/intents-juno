package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/idempotency"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/proverinput"
)

func TestParseArgs_Valid(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	deployer := filepath.Join(tmp, "deployer.key")
	op1 := filepath.Join(tmp, "op1.key")
	op2 := filepath.Join(tmp, "op2.key")
	op3 := filepath.Join(tmp, "op3.key")
	requestor := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")

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
	if err := os.WriteFile(requestor, []byte("0x4d64c83f2d2e4f3e96b3b1e9a8d7c6b5a493827161514131211100f0e0d0c0f4\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deploy-only",
		"--deployer-key-file", deployer,
		"--operator-key-file", op1,
		"--operator-key-file", op2,
		"--operator-key-file", op3,
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-requestor-key-file", requestor,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
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
	if !cfg.DeployOnly {
		t.Fatalf("deploy-only: got %v want true", cfg.DeployOnly)
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

func TestParseArgs_AcceptsExistingContractAddresses(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	deployer := filepath.Join(tmp, "deployer.key")
	op1 := filepath.Join(tmp, "op1.key")
	op2 := filepath.Join(tmp, "op2.key")
	op3 := filepath.Join(tmp, "op3.key")
	requestor := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")

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
	if err := os.WriteFile(requestor, []byte("0x4d64c83f2d2e4f3e96b3b1e9a8d7c6b5a493827161514131211100f0e0d0c0f4\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-file", deployer,
		"--operator-key-file", op1,
		"--operator-key-file", op2,
		"--operator-key-file", op3,
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-requestor-key-file", requestor,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
		"--existing-wjuno-address", "0x00000000000000000000000000000000000000a1",
		"--existing-operator-registry-address", "0x00000000000000000000000000000000000000b2",
		"--existing-fee-distributor-address", "0x00000000000000000000000000000000000000c3",
		"--existing-bridge-address", "0x00000000000000000000000000000000000000d4",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !cfg.ReuseDeployedContracts {
		t.Fatalf("reuse deployed contracts: got %v want true", cfg.ReuseDeployedContracts)
	}
	if cfg.ExistingWJunoAddress != common.HexToAddress("0x00000000000000000000000000000000000000a1") {
		t.Fatalf("existing wjuno address: got %s", cfg.ExistingWJunoAddress.Hex())
	}
	if cfg.ExistingOperatorRegAddress != common.HexToAddress("0x00000000000000000000000000000000000000b2") {
		t.Fatalf("existing operator registry address: got %s", cfg.ExistingOperatorRegAddress.Hex())
	}
	if cfg.ExistingFeeDistributor != common.HexToAddress("0x00000000000000000000000000000000000000c3") {
		t.Fatalf("existing fee distributor address: got %s", cfg.ExistingFeeDistributor.Hex())
	}
	if cfg.ExistingBridgeAddress != common.HexToAddress("0x00000000000000000000000000000000000000d4") {
		t.Fatalf("existing bridge address: got %s", cfg.ExistingBridgeAddress.Hex())
	}
}

func TestParseArgs_RequiresAllExistingContractAddresses(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	deployer := filepath.Join(tmp, "deployer.key")
	op1 := filepath.Join(tmp, "op1.key")
	op2 := filepath.Join(tmp, "op2.key")
	op3 := filepath.Join(tmp, "op3.key")
	requestor := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")

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
	if err := os.WriteFile(requestor, []byte("0x4d64c83f2d2e4f3e96b3b1e9a8d7c6b5a493827161514131211100f0e0d0c0f4\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-file", deployer,
		"--operator-key-file", op1,
		"--operator-key-file", op2,
		"--operator-key-file", op3,
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-requestor-key-file", requestor,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
		"--existing-bridge-address", "0x00000000000000000000000000000000000000d4",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "all existing contract address flags must be set together") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func runtimeSignerParseArgsBase(t *testing.T) []string {
	t.Helper()

	tmp := t.TempDir()
	deployer := filepath.Join(tmp, "deployer.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")

	if err := os.WriteFile(deployer, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("write deployer key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	return []string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-file", deployer,
		"--operator-signer-bin", "dkg-admin",
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-proof-submission-mode", "queue",
		"--sp1-proof-queue-brokers", "127.0.0.1:9092",
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
	}
}

func TestParseArgs_RuntimeSignerValidWithoutOperatorKeys(t *testing.T) {
	t.Parallel()

	args := runtimeSignerParseArgsBase(t)
	args = append(args,
		"--operator-address", "0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F",
		"--operator-address", "0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7",
		"--operator-address", "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"--operator-signer-endpoint", "http://127.0.0.1:18080",
		"--operator-signer-endpoint", "http://127.0.0.1:18081",
	)

	cfg, err := parseArgs(args)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.OperatorSignerBin != "dkg-admin" {
		t.Fatalf("operator signer bin: got %q", cfg.OperatorSignerBin)
	}
	if len(cfg.OperatorKeyFiles) != 0 {
		t.Fatalf("operator key files: got %d, want 0", len(cfg.OperatorKeyFiles))
	}
	if len(cfg.OperatorAddresses) != 3 {
		t.Fatalf("operator addresses: got %d, want 3", len(cfg.OperatorAddresses))
	}
	if len(cfg.OperatorSignerEndpoints) != 2 {
		t.Fatalf("operator signer endpoints: got %d, want 2", len(cfg.OperatorSignerEndpoints))
	}
}

func TestParseArgs_RuntimeSignerRequiresOperatorAddresses(t *testing.T) {
	t.Parallel()

	_, err := parseArgs(runtimeSignerParseArgsBase(t))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--operator-address") {
		t.Fatalf("expected operator address error, got: %v", err)
	}
}

func TestParseArgs_RuntimeSignerRequiresThresholdOperatorAddresses(t *testing.T) {
	t.Parallel()

	args := runtimeSignerParseArgsBase(t)
	args = append(args,
		"--operator-address", "0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F",
		"--operator-address", "0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7",
	)

	_, err := parseArgs(args)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "operator addresses") {
		t.Fatalf("expected operator addresses threshold error, got: %v", err)
	}
}

func TestConsumeOperatorKeyFileFlags(t *testing.T) {
	t.Parallel()

	remaining, keyFiles, err := consumeOperatorKeyFileFlags([]string{
		"--rpc-url", "https://example.invalid",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file=/tmp/op2",
		"--threshold", "3",
	})
	if err != nil {
		t.Fatalf("consumeOperatorKeyFileFlags: %v", err)
	}
	if len(keyFiles) != 2 || keyFiles[0] != "/tmp/op1" || keyFiles[1] != "/tmp/op2" {
		t.Fatalf("unexpected key files: %#v", keyFiles)
	}
	if len(remaining) != 4 {
		t.Fatalf("unexpected remaining args length: got=%d want=4", len(remaining))
	}
	if strings.Contains(strings.Join(remaining, " "), "operator-key-file") {
		t.Fatalf("operator-key-file flag should be removed from remaining args: %#v", remaining)
	}
}

func TestConsumeOperatorKeyFileFlags_MissingValue(t *testing.T) {
	t.Parallel()

	_, _, err := consumeOperatorKeyFileFlags([]string{"--operator-key-file"})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "missing value for --operator-key-file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRun_RequiresOperatorSignerBin(t *testing.T) {
	t.Parallel()

	_, err := run(context.Background(), config{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--operator-signer-bin is required") {
		t.Fatalf("unexpected error: %v", err)
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

func TestParseArgs_RequiresVerifierAddress(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--sp1-auto",
		"--sp1-requestor-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--verifier-address") {
		t.Fatalf("expected verifier required error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoRequiresRequestorKeyFile(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--sp1-requestor-key-file") {
		t.Fatalf("expected requestor key file error, got: %v", err)
	}
}

func TestParseArgs_RequiresSP1Auto(t *testing.T) {
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
	if !strings.Contains(err.Error(), "--sp1-auto") {
		t.Fatalf("expected sp1-auto required error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoValid(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "guest-witness-v1",
		"--sp1-market-address", "0xFd152dADc5183870710FE54f939Eae3aB9F0fE82",
		"--sp1-verifier-router-address", "0x0b144e07a0826182b6b59788c34b32bfa86fb711",
		"--sp1-set-verifier-address", "0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
		"--sp1-max-price-per-pgu", "250000000000000",
		"--sp1-min-auction-period", "85",
		"--sp1-auction-timeout", "625s",
		"--sp1-request-timeout", "1500s",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !cfg.SP1.Auto {
		t.Fatalf("expected sp1 auto mode enabled")
	}
	if cfg.SP1.Bin != "sp1" {
		t.Fatalf("unexpected sp1 bin: %q", cfg.SP1.Bin)
	}
	if cfg.SP1.InputMode != "guest-witness-v1" {
		t.Fatalf("unexpected sp1 input mode: %q", cfg.SP1.InputMode)
	}
	if cfg.SP1.MarketAddress != common.HexToAddress("0xFd152dADc5183870710FE54f939Eae3aB9F0fE82") {
		t.Fatalf("unexpected sp1 market address: %s", cfg.SP1.MarketAddress.Hex())
	}
	if cfg.SP1.VerifierRouterAddr != common.HexToAddress("0x0b144e07a0826182b6b59788c34b32bfa86fb711") {
		t.Fatalf("unexpected sp1 verifier router address: %s", cfg.SP1.VerifierRouterAddr.Hex())
	}
	if cfg.SP1.SetVerifierAddr != common.HexToAddress("0x1Ab08498CfF17b9723ED67143A050c8E8c2e3104") {
		t.Fatalf("unexpected sp1 set verifier address: %s", cfg.SP1.SetVerifierAddr.Hex())
	}
	if cfg.SP1.RequestorKeyHex == "" {
		t.Fatalf("expected requestor key loaded from file")
	}
	if cfg.SP1.DepositProgramURL != "https://example.invalid/deposit.elf" {
		t.Fatalf("unexpected deposit program url: %q", cfg.SP1.DepositProgramURL)
	}
	if cfg.SP1.WithdrawProgramURL != "https://example.invalid/withdraw.elf" {
		t.Fatalf("unexpected withdraw program url: %q", cfg.SP1.WithdrawProgramURL)
	}
}

func TestParseArgs_SP1AutoQueueSubmissionModeValidWithoutRequestorKey(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-proof-submission-mode", "queue",
		"--sp1-proof-queue-brokers", "127.0.0.1:9092",
		"--sp1-proof-request-topic", "proof.requests.v1",
		"--sp1-proof-result-topic", "proof.fulfillments.v1",
		"--sp1-proof-failure-topic", "proof.failures.v1",
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.SP1.ProofSubmissionMode != "queue" {
		t.Fatalf("proof submission mode: got=%q want=queue", cfg.SP1.ProofSubmissionMode)
	}
	if got := len(cfg.SP1.ProofQueueBrokers); got != 1 {
		t.Fatalf("proof queue brokers: got=%d want=1", got)
	}
	if cfg.SP1.ProofQueueBrokers[0] != "127.0.0.1:9092" {
		t.Fatalf("proof queue broker: got=%q", cfg.SP1.ProofQueueBrokers[0])
	}
	if cfg.SP1.RequestorKeyHex != "" {
		t.Fatalf("requestor key should be optional in queue mode")
	}
}

func TestParseArgs_SP1AutoQueueSubmissionModeRequiresQueueBrokers(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-proof-submission-mode", "queue",
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--sp1-proof-queue-brokers") {
		t.Fatalf("expected missing proof queue brokers error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoRejectsUnknownProofSubmissionMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-proof-submission-mode", "bogus",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--sp1-proof-submission-mode") {
		t.Fatalf("expected proof submission mode error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoRejectsJournalInputMode(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
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
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "journal-bytes-v1",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "guest-witness-v1") {
		t.Fatalf("expected sp1 input mode error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoGuestWitnessModeValid(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "guest-witness-v1",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.SP1.InputMode != "guest-witness-v1" {
		t.Fatalf("unexpected sp1 input mode: %q", cfg.SP1.InputMode)
	}
	if len(cfg.SP1.DepositOWalletIVKBytes) != 64 {
		t.Fatalf("deposit ivk len: got=%d want=64", len(cfg.SP1.DepositOWalletIVKBytes))
	}
	if len(cfg.SP1.WithdrawOWalletOVKBytes) != 32 {
		t.Fatalf("withdraw ovk len: got=%d want=32", len(cfg.SP1.WithdrawOWalletOVKBytes))
	}
	if len(cfg.SP1.DepositWitnessItems) != 1 {
		t.Fatalf("deposit witness items: got=%d want=1", len(cfg.SP1.DepositWitnessItems))
	}
	if len(cfg.SP1.WithdrawWitnessItems) != 1 {
		t.Fatalf("withdraw witness items: got=%d want=1", len(cfg.SP1.WithdrawWitnessItems))
	}
}

func TestParseArgs_SP1AutoGuestWitnessModeRequiresExplicitWitnessInputs(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
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
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "guest-witness-v1",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "guest witness auto generation is disabled") {
		t.Fatalf("expected disabled guest witness auto error, got: %v", err)
	}
}

func TestParseArgs_DeployOnlyAllowsMissingGuestWitnessInputs(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	deployer := filepath.Join(tmp, "deployer.key")
	op1 := filepath.Join(tmp, "op1.key")
	op2 := filepath.Join(tmp, "op2.key")
	op3 := filepath.Join(tmp, "op3.key")
	requestor := filepath.Join(tmp, "requestor.key")
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
	if err := os.WriteFile(requestor, []byte("0x4d64c83f2d2e4f3e96b3b1e9a8d7c6b5a493827161514131211100f0e0d0c0f4\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deploy-only",
		"--deployer-key-file", deployer,
		"--operator-key-file", op1,
		"--operator-key-file", op2,
		"--operator-key-file", op3,
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-requestor-key-file", requestor,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !cfg.DeployOnly {
		t.Fatalf("deploy-only: got %v want true", cfg.DeployOnly)
	}
	if len(cfg.SP1.DepositWitnessItems) != 0 {
		t.Fatalf("deposit witness items: got=%d want=0", len(cfg.SP1.DepositWitnessItems))
	}
	if len(cfg.SP1.WithdrawWitnessItems) != 0 {
		t.Fatalf("withdraw witness items: got=%d want=0", len(cfg.SP1.WithdrawWitnessItems))
	}
}

func TestParseArgs_SP1AutoGuestWitnessModeRequiresInputS3Bucket(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
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
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "guest-witness-v1",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--sp1-input-s3-bucket") {
		t.Fatalf("expected missing s3 bucket error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoRejectsBaseChainRPCURL(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://mainnet.base.org",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "Succinct prover network RPC") {
		t.Fatalf("expected sp1 network rpc endpoint class error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoGuestWitnessModeRequiresDepositFinalOrchardRoot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "guest-witness-v1",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--deposit-final-orchard-root") {
		t.Fatalf("expected missing deposit final orchard root error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoGuestWitnessModeRequiresDepositCheckpointHeight(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "guest-witness-v1",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--deposit-checkpoint-height") {
		t.Fatalf("expected missing deposit checkpoint height error, got: %v", err)
	}
}

func TestParseArgs_CheckpointFieldsDefaultWithdrawToDeposit(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "guest-witness-v1",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.DepositCheckpointHeight != 777 {
		t.Fatalf("deposit checkpoint height: got=%d want=777", cfg.DepositCheckpointHeight)
	}
	wantBlockHash := common.HexToHash("0x" + strings.Repeat("44", 32))
	if cfg.DepositCheckpointBlockHash != wantBlockHash {
		t.Fatalf("deposit checkpoint block hash: got=%s want=%s", cfg.DepositCheckpointBlockHash.Hex(), wantBlockHash.Hex())
	}
	if cfg.WithdrawCheckpointHeight != cfg.DepositCheckpointHeight {
		t.Fatalf("withdraw checkpoint height default mismatch: got=%d want=%d", cfg.WithdrawCheckpointHeight, cfg.DepositCheckpointHeight)
	}
	if cfg.WithdrawCheckpointBlockHash != cfg.DepositCheckpointBlockHash {
		t.Fatalf("withdraw checkpoint block hash default mismatch: got=%s want=%s", cfg.WithdrawCheckpointBlockHash.Hex(), cfg.DepositCheckpointBlockHash.Hex())
	}
}

func TestParseArgs_CheckpointFieldsRequireWithdrawPair(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	depositWitness := filepath.Join(tmp, "deposit.witness.bin")
	withdrawWitness := filepath.Join(tmp, "withdraw.witness.bin")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
		t.Fatalf("write requestor key: %v", err)
	}
	if err := os.WriteFile(depositWitness, bytes.Repeat([]byte{0x11}, proverinput.DepositWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write deposit witness: %v", err)
	}
	if err := os.WriteFile(withdrawWitness, bytes.Repeat([]byte{0x22}, proverinput.WithdrawWitnessItemLen), 0o600); err != nil {
		t.Fatalf("write withdraw witness: %v", err)
	}

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "84532",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-key-file", "/tmp/op1",
		"--operator-key-file", "/tmp/op2",
		"--operator-key-file", "/tmp/op3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "guest-witness-v1",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
		"--sp1-withdraw-owallet-ovk-hex", "0x" + strings.Repeat("22", 32),
		"--sp1-deposit-witness-item-file", depositWitness,
		"--sp1-withdraw-witness-item-file", withdrawWitness,
		"--deposit-final-orchard-root", "0x" + strings.Repeat("33", 32),
		"--deposit-checkpoint-height", "777",
		"--deposit-checkpoint-block-hash", "0x" + strings.Repeat("44", 32),
		"--withdraw-checkpoint-height", "778",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--withdraw-checkpoint-height and --withdraw-checkpoint-block-hash") {
		t.Fatalf("expected withdraw checkpoint pair validation error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoGuestWitnessModeRejectsPartialManualInputs(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
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
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-input-mode", "guest-witness-v1",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit-guest.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw-guest.elf",
		"--sp1-input-s3-bucket", "test-bucket",
		"--sp1-deposit-owallet-ivk-hex", "0x" + strings.Repeat("11", 64),
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "all guest witness manual inputs must be set together") {
		t.Fatalf("expected partial guest-witness manual input error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoRejectsInvalidMarketAddress(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
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
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-market-address", "not-an-address",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--sp1-market-address") {
		t.Fatalf("expected sp1 market address error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoRejectsInvalidVerifierRouterAddress(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
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
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-verifier-router-address", "bad-address",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--sp1-verifier-router-address") {
		t.Fatalf("expected sp1 verifier router address error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoRejectsInvalidSetVerifierAddress(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
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
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-set-verifier-address", "bad-address",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--sp1-set-verifier-address") {
		t.Fatalf("expected sp1 set verifier address error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoRejectsZeroMaxPricePerPGU(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
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
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--sp1-max-price-per-pgu", "0",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--sp1-max-price-per-pgu") {
		t.Fatalf("expected sp1 max price per pgu error, got: %v", err)
	}
}

func TestParseArgs_SP1AutoRejectsZeroMinAuctionPeriod(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	requestorKey := filepath.Join(tmp, "requestor.key")
	if err := os.WriteFile(requestorKey, []byte("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n"), 0o600); err != nil {
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
		"--sp1-auto",
		"--sp1-bin", "sp1",
		"--sp1-rpc-url", "https://rpc.mainnet.succinct.xyz",
		"--sp1-requestor-key-file", requestorKey,
		"--sp1-deposit-program-url", "https://example.invalid/deposit.elf",
		"--sp1-withdraw-program-url", "https://example.invalid/withdraw.elf",
		"--sp1-min-auction-period", "0",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--sp1-min-auction-period") {
		t.Fatalf("expected sp1 min auction period error, got: %v", err)
	}
}

func TestParseSP1WaitOutput(t *testing.T) {
	t.Parallel()

	out := strings.Join([]string{
		"2026-02-16T00:00:00Z  INFO Submitted request 0x8fd, bidding starts at 2026-02-16 00:01:25 UTC",
		"2026-02-16T00:10:00Z  INFO Request fulfilled!",
		"2026-02-16T00:10:00Z  INFO Journal: \"0x010203\" - Seal: \"0x99aa\"",
	}, "\n")

	got, err := parseSP1WaitOutput([]byte(out))
	if err != nil {
		t.Fatalf("parseSP1WaitOutput: %v", err)
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

func TestParseSP1WaitOutput_RequestorSubmitFormat(t *testing.T) {
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

	got, err := parseSP1WaitOutput([]byte(out))
	if err != nil {
		t.Fatalf("parseSP1WaitOutput: %v", err)
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

func TestParseSP1WaitOutput_MissingSeal(t *testing.T) {
	t.Parallel()

	out := "2026-02-16T00:00:00Z  INFO Submitted request 0x8fd, bidding starts at 2026-02-16 00:01:25 UTC"
	_, err := parseSP1WaitOutput([]byte(out))
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "seal") {
		t.Fatalf("expected missing seal error, got: %v", err)
	}
}

func TestExtractQueueProofRequestID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		metadata map[string]string
		want     string
	}{
		{
			name:     "missing metadata",
			metadata: nil,
			want:     "",
		},
		{
			name: "hex request id",
			metadata: map[string]string{
				"request_id": "0xABC123",
			},
			want: "0xabc123",
		},
		{
			name: "decimal request id",
			metadata: map[string]string{
				"requestID": "42",
			},
			want: "0x2a",
		},
		{
			name: "opaque request id",
			metadata: map[string]string{
				"requestId": "abc-42",
			},
			want: "abc-42",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := extractQueueProofRequestID(tc.metadata); got != tc.want {
				t.Fatalf("extractQueueProofRequestID() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateQueueProofFulfillment_RejectsMissingJournal(t *testing.T) {
	t.Parallel()

	err := validateQueueProofFulfillment(
		"deposit",
		[]byte{0x01, 0x02},
		proofclient.Result{Seal: []byte{0x99}},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "journal") {
		t.Fatalf("expected journal validation error, got: %v", err)
	}
}

func TestValidateQueueProofFulfillment_RejectsJournalMismatch(t *testing.T) {
	t.Parallel()

	err := validateQueueProofFulfillment(
		"withdraw",
		[]byte{0x01, 0x02},
		proofclient.Result{
			Seal:    []byte{0x99},
			Journal: []byte{0x01, 0x03},
		},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "journal mismatch") {
		t.Fatalf("expected journal mismatch error, got: %v", err)
	}
}

func TestValidateQueueProofFulfillment_AcceptsMatchingJournal(t *testing.T) {
	t.Parallel()

	err := validateQueueProofFulfillment(
		"withdraw",
		[]byte{0x01, 0x02},
		proofclient.Result{
			Seal:    []byte{0x99},
			Journal: []byte{0x01, 0x02},
		},
	)
	if err != nil {
		t.Fatalf("validateQueueProofFulfillment: %v", err)
	}
}

type mockBridgeConfigCaller struct {
	responses map[string]mockCallResponse
	calls     []string
}

func (m *mockBridgeConfigCaller) Call(_ *bind.CallOpts, results *[]any, method string, params ...any) error {
	if len(params) != 0 {
		return errors.New("unexpected params")
	}
	m.calls = append(m.calls, method)
	resp, ok := m.responses[method]
	if !ok {
		return errors.New("unexpected method: " + method)
	}
	if resp.err != nil {
		return resp.err
	}
	*results = []any{resp.result}
	return nil
}

func TestValidateReusedBridgeConfig_RejectsVerifierMismatch(t *testing.T) {
	t.Parallel()

	depositImageID := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	withdrawImageID := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	caller := &mockBridgeConfigCaller{
		responses: map[string]mockCallResponse{
			"verifier":        {result: common.HexToAddress("0x00000000000000000000000000000000000000aa")},
			"depositImageId":  {result: depositImageID},
			"withdrawImageId": {result: withdrawImageID},
		},
	}

	err := validateReusedBridgeConfig(
		context.Background(),
		caller,
		common.HexToAddress("0x00000000000000000000000000000000000000bb"),
		depositImageID,
		withdrawImageID,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "verifier mismatch") {
		t.Fatalf("expected verifier mismatch, got: %v", err)
	}
}

func TestValidateReusedBridgeConfig_RejectsImageIDMismatch(t *testing.T) {
	t.Parallel()

	depositImageID := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	withdrawImageID := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	caller := &mockBridgeConfigCaller{
		responses: map[string]mockCallResponse{
			"verifier":        {result: common.HexToAddress("0x00000000000000000000000000000000000000aa")},
			"depositImageId":  {result: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")},
			"withdrawImageId": {result: withdrawImageID},
		},
	}

	err := validateReusedBridgeConfig(
		context.Background(),
		caller,
		common.HexToAddress("0x00000000000000000000000000000000000000aa"),
		depositImageID,
		withdrawImageID,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "depositImageId mismatch") {
		t.Fatalf("expected deposit image mismatch, got: %v", err)
	}
}

func TestValidateReusedBridgeConfig_AcceptsMatchingConfig(t *testing.T) {
	t.Parallel()

	verifier := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	depositImageID := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	withdrawImageID := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	caller := &mockBridgeConfigCaller{
		responses: map[string]mockCallResponse{
			"verifier":        {result: verifier},
			"depositImageId":  {result: depositImageID},
			"withdrawImageId": {result: withdrawImageID},
		},
	}

	err := validateReusedBridgeConfig(
		context.Background(),
		caller,
		verifier,
		depositImageID,
		withdrawImageID,
	)
	if err != nil {
		t.Fatalf("validateReusedBridgeConfig: %v", err)
	}
	if len(caller.calls) != 3 {
		t.Fatalf("call count: got=%d want=3", len(caller.calls))
	}
}

func TestParseSP1ProofOutput(t *testing.T) {
	t.Parallel()

	out := strings.Join([]string{
		"Submitting Proof Request from YAML [Unknown Network]",
		"  Assigned Request ID: 0x28ae6a6bc48ac3e425df6e5cbce845eb0001ceae5952e986",
		"✓ Request fulfilled!",
		"Fulfillment Data:",
		"{",
		`  "ImageIdAndJournal": [`,
		"    [1,2,3,4,5,6,7,8],",
		`    "0x01020304"`,
		"  ]",
		"}",
		"Seal:",
		`"0x99aa55"`,
	}, "\n")

	seal, requestID, err := parseSP1ProofOutput([]byte(out), "withdraw", []byte{0x01, 0x02, 0x03, 0x04})
	if err != nil {
		t.Fatalf("parseSP1ProofOutput: %v", err)
	}
	if requestID != "0x28ae6a6bc48ac3e425df6e5cbce845eb0001ceae5952e986" {
		t.Fatalf("request id: got %q", requestID)
	}
	if len(seal) == 0 || seal[0] != 0x99 {
		t.Fatalf("unexpected seal bytes: %x", seal)
	}
}

func TestParseSP1ProofOutput_JournalMismatch(t *testing.T) {
	t.Parallel()

	out := strings.Join([]string{
		"2026-02-16T00:00:00Z  INFO Submitted request 0x8fd, bidding starts at 2026-02-16 00:01:25 UTC",
		"2026-02-16T00:10:00Z  INFO Request fulfilled!",
		"2026-02-16T00:10:00Z  INFO Journal: \"0x010203\" - Seal: \"0x99aa\"",
	}, "\n")

	_, _, err := parseSP1ProofOutput([]byte(out), "deposit", []byte{0x09, 0x09, 0x09})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "journal mismatch") {
		t.Fatalf("expected journal mismatch error, got: %v", err)
	}
}

func TestExtractSP1RequestID(t *testing.T) {
	t.Parallel()

	out := strings.Join([]string{
		"Submitted request 0xabc",
		"Assigned Request ID: 0xDEF123",
	}, "\n")
	got := extractSP1RequestID([]byte(out))
	if got != "0xdef123" {
		t.Fatalf("extractSP1RequestID() = %q, want %q", got, "0xdef123")
	}

	if empty := extractSP1RequestID([]byte("no request id here")); empty != "" {
		t.Fatalf("expected empty request id, got %q", empty)
	}
}

func TestIsRetriableSP1GetProofError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		msg  string
		want bool
	}{
		{name: "timeout", msg: "request timed out", want: true},
		{name: "query event", msg: "query_fulfilled_event failed", want: true},
		{name: "decoding", msg: "decoding err: missing field", want: true},
		{name: "not found", msg: "proof not found yet", want: true},
		{name: "missing data", msg: "missing data", want: true},
		{name: "http 429", msg: "HTTP 429 Too Many Requests", want: true},
		{name: "over rate limit", msg: "over rate limit", want: true},
		{name: "non retriable", msg: "unauthorized", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isRetriableSP1GetProofError(tc.msg)
			if got != tc.want {
				t.Fatalf("isRetriableSP1GetProofError(%q) = %v, want %v", tc.msg, got, tc.want)
			}
		})
	}
}

func TestIsRetriableSP1LockFailure(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		msg  string
		want bool
	}{
		{name: "request timed out", msg: "sp1 submit-offer failed for deposit: request timed out", want: true},
		{name: "not fulfilled", msg: "sp1 get-proof failed for withdraw request_id=0xabc: request not fulfilled", want: true},
		{name: "get-proof timeout", msg: "sp1 get-proof timeout for deposit request_id=0xabc: context deadline exceeded", want: true},
		{name: "lock timeout", msg: "primary prover lock timeout reached", want: true},
		{name: "request expired", msg: "request expired before lock", want: true},
		{name: "non lock failure", msg: "sp1 journal mismatch for deposit", want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isRetriableSP1LockFailure(tc.msg)
			if got != tc.want {
				t.Fatalf("isRetriableSP1LockFailure(%q) = %v, want %v", tc.msg, got, tc.want)
			}
		})
	}
}

func TestSP1ProofAttemptTimeout(t *testing.T) {
	t.Parallel()

	cfg := sp1Config{
		RequestTimeout: 1500 * time.Second,
	}
	want := 27 * time.Minute
	if got := sp1ProofAttemptTimeout(cfg); got != want {
		t.Fatalf("sp1ProofAttemptTimeout() = %s, want %s", got, want)
	}
}

func TestNextSP1MaxPriceWei(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		current    string
		multiplier uint64
		cap        string
		want       string
		wantOK     bool
	}{
		{
			name:       "bumps within cap",
			current:    "50000000000000",
			multiplier: 2,
			cap:        "250000000000000",
			want:       "100000000000000",
			wantOK:     true,
		},
		{
			name:       "clamps to cap",
			current:    "200000000000000",
			multiplier: 2,
			cap:        "250000000000000",
			want:       "250000000000000",
			wantOK:     true,
		},
		{
			name:       "cannot bump at cap",
			current:    "250000000000000",
			multiplier: 2,
			cap:        "250000000000000",
			want:       "250000000000000",
			wantOK:     false,
		},
		{
			name:       "invalid multiplier",
			current:    "50000000000000",
			multiplier: 1,
			cap:        "250000000000000",
			want:       "50000000000000",
			wantOK:     false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			current, _ := new(big.Int).SetString(tc.current, 10)
			cap, _ := new(big.Int).SetString(tc.cap, 10)
			got, ok := nextSP1MaxPriceWei(current, tc.multiplier, cap)
			if ok != tc.wantOK {
				t.Fatalf("nextSP1MaxPriceWei ok=%v, want %v", ok, tc.wantOK)
			}
			if got.String() != tc.want {
				t.Fatalf("nextSP1MaxPriceWei got=%s, want %s", got.String(), tc.want)
			}
		})
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

func TestDeriveDepositIDFromWitnessItem(t *testing.T) {
	t.Parallel()

	item := make([]byte, proverinput.DepositWitnessItemLen)
	leafIndex := uint32(7)
	item[0] = byte(leafIndex)
	var cm [32]byte
	for i := range cm {
		cm[i] = byte(0xa0 + i)
	}
	copy(item[depositWitnessCMXOffset:depositWitnessCMXOffset+32], cm[:])

	got, err := deriveDepositIDFromWitnessItem(item)
	if err != nil {
		t.Fatalf("deriveDepositIDFromWitnessItem: %v", err)
	}
	want := idempotency.DepositIDV1(cm, uint64(leafIndex))
	if got != common.Hash(want) {
		t.Fatalf("deposit id mismatch: got=%s want=%s", got.Hex(), common.Hash(want).Hex())
	}
}

func TestDeriveDepositIDFromWitnessItem_RejectsInvalidLength(t *testing.T) {
	t.Parallel()

	_, err := deriveDepositIDFromWitnessItem([]byte{0x01})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "deposit witness item len") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseWithdrawWitnessIdentity(t *testing.T) {
	t.Parallel()

	item := make([]byte, proverinput.WithdrawWitnessItemLen)
	withdrawalID := common.HexToHash("0x7a")
	copy(item[:32], withdrawalID[:])
	for i := 0; i < withdrawWitnessRecipientRawLen; i++ {
		item[withdrawWitnessRecipientOffset+i] = byte(i + 1)
	}

	got, err := parseWithdrawWitnessIdentity(item)
	if err != nil {
		t.Fatalf("parseWithdrawWitnessIdentity: %v", err)
	}
	if got.WithdrawalID != withdrawalID {
		t.Fatalf("withdrawal id mismatch: got=%s want=%s", got.WithdrawalID.Hex(), withdrawalID.Hex())
	}
	if len(got.RecipientUA) != withdrawWitnessRecipientRawLen {
		t.Fatalf("recipient ua len mismatch: got=%d want=%d", len(got.RecipientUA), withdrawWitnessRecipientRawLen)
	}
	for i := range got.RecipientUA {
		if got.RecipientUA[i] != byte(i+1) {
			t.Fatalf("recipient ua byte[%d] mismatch: got=%d want=%d", i, got.RecipientUA[i], byte(i+1))
		}
	}
}

func TestParseWithdrawWitnessIdentity_RejectsInvalidLength(t *testing.T) {
	t.Parallel()

	_, err := parseWithdrawWitnessIdentity([]byte{0x01})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "withdraw witness item len") {
		t.Fatalf("unexpected error: %v", err)
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

type mockGasEstimator struct {
	price    *big.Int
	tip      *big.Int
	priceErr error
	tipErr   error
}

type mockCodeAtResponse struct {
	code []byte
	err  error
}

type mockCodeAtBackend struct {
	responses []mockCodeAtResponse
	calls     int
}

func (m *mockCodeAtBackend) CodeAt(ctx context.Context, _ common.Address, _ *big.Int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.calls++
	if len(m.responses) == 0 {
		return nil, nil
	}
	idx := m.calls - 1
	if idx >= len(m.responses) {
		idx = len(m.responses) - 1
	}
	resp := m.responses[idx]
	if resp.err != nil {
		return nil, resp.err
	}
	return append([]byte(nil), resp.code...), nil
}

func (m mockGasEstimator) SuggestGasPrice(context.Context) (*big.Int, error) {
	if m.priceErr != nil {
		return nil, m.priceErr
	}
	if m.price == nil {
		return nil, nil
	}
	return new(big.Int).Set(m.price), nil
}

func (m mockGasEstimator) SuggestGasTipCap(context.Context) (*big.Int, error) {
	if m.tipErr != nil {
		return nil, m.tipErr
	}
	if m.tip == nil {
		return nil, nil
	}
	return new(big.Int).Set(m.tip), nil
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

func TestWaitUint64AtLeastAttempts_RetriesUntilMatch(t *testing.T) {
	t.Parallel()

	var calls int
	got, err := waitUint64AtLeastAttempts(
		context.Background(),
		"threshold",
		3,
		5,
		0,
		func() (uint64, error) {
			calls++
			if calls < 3 {
				return 0, nil
			}
			return 3, nil
		},
	)
	if err != nil {
		t.Fatalf("waitUint64AtLeastAttempts: %v", err)
	}
	if got != 3 {
		t.Fatalf("unexpected value: got=%d want=3", got)
	}
	if calls != 3 {
		t.Fatalf("unexpected calls: got=%d want=3", calls)
	}
}

func TestWaitUint64AtLeastAttempts_ReturnsLastValueOnMismatch(t *testing.T) {
	t.Parallel()

	var calls int
	got, err := waitUint64AtLeastAttempts(
		context.Background(),
		"operatorCount",
		5,
		3,
		0,
		func() (uint64, error) {
			calls++
			return 4, nil
		},
	)
	if err != nil {
		t.Fatalf("waitUint64AtLeastAttempts: %v", err)
	}
	if got != 4 {
		t.Fatalf("unexpected value: got=%d want=4", got)
	}
	if calls != 3 {
		t.Fatalf("unexpected calls: got=%d want=3", calls)
	}
}

func TestWaitUint64AtLeastAttempts_ReturnsLastError(t *testing.T) {
	t.Parallel()

	got, err := waitUint64AtLeastAttempts(
		context.Background(),
		"threshold",
		3,
		2,
		0,
		func() (uint64, error) {
			return 0, errors.New("rpc unavailable")
		},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if got != 0 {
		t.Fatalf("unexpected value: got=%d want=0", got)
	}
	if !strings.Contains(err.Error(), "rpc unavailable") {
		t.Fatalf("expected wrapped rpc error, got: %v", err)
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

func TestApplyRetryGasBump_AttemptOneUsesLegacyFloor(t *testing.T) {
	t.Parallel()

	auth := &bind.TransactOpts{}
	applyRetryGasBump(context.Background(), struct{}{}, auth, 1)

	want := big.NewInt(defaultRetryGasPriceWei)
	if auth.GasPrice == nil || auth.GasPrice.Cmp(want) != 0 {
		got := "<nil>"
		if auth.GasPrice != nil {
			got = auth.GasPrice.String()
		}
		t.Fatalf("unexpected gas price: got=%s want=%s", got, want.String())
	}
	if auth.GasTipCap != nil || auth.GasFeeCap != nil {
		t.Fatalf("unexpected EIP-1559 fields in legacy attempt one: tip=%v fee=%v", auth.GasTipCap, auth.GasFeeCap)
	}
}

func TestApplyRetryGasBump_BumpsEIP1559Fields(t *testing.T) {
	t.Parallel()

	auth := &bind.TransactOpts{}
	applyRetryGasBump(context.Background(), mockGasEstimator{
		price: big.NewInt(10),
		tip:   big.NewInt(2),
	}, auth, 3)

	if auth.GasPrice != nil {
		t.Fatalf("expected legacy gas price to be cleared for EIP-1559")
	}
	wantTip := big.NewInt(defaultRetryGasTipCapWei * 4)
	if auth.GasTipCap == nil || auth.GasTipCap.Cmp(wantTip) != 0 {
		got := "<nil>"
		if auth.GasTipCap != nil {
			got = auth.GasTipCap.String()
		}
		t.Fatalf("unexpected gas tip cap: got=%s want=%s", got, wantTip.String())
	}
	wantFee := big.NewInt(defaultRetryGasPriceWei * 4)
	if auth.GasFeeCap == nil || auth.GasFeeCap.Cmp(wantFee) != 0 {
		got := "<nil>"
		if auth.GasFeeCap != nil {
			got = auth.GasFeeCap.String()
		}
		t.Fatalf("unexpected gas fee cap: got=%s want=%s", got, wantFee.String())
	}
}

func TestApplyRetryGasBump_FallsBackToLegacyGasPrice(t *testing.T) {
	t.Parallel()

	auth := &bind.TransactOpts{}
	applyRetryGasBump(context.Background(), struct{}{}, auth, 2)

	want := big.NewInt(defaultRetryGasPriceWei * 2)
	if auth.GasPrice == nil || auth.GasPrice.Cmp(want) != 0 {
		got := "<nil>"
		if auth.GasPrice != nil {
			got = auth.GasPrice.String()
		}
		t.Fatalf("unexpected gas price: got=%s want=%s", got, want.String())
	}
	if auth.GasTipCap != nil || auth.GasFeeCap != nil {
		t.Fatalf("unexpected EIP-1559 fields in legacy fallback: tip=%v fee=%v", auth.GasTipCap, auth.GasFeeCap)
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

func TestIsRetriableWaitMinedError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "deadline exceeded",
			err:  context.DeadlineExceeded,
			want: true,
		},
		{
			name: "not found",
			err:  errors.New("transaction not found"),
			want: true,
		},
		{
			name: "not indexed",
			err:  errors.New("header not indexed yet"),
			want: true,
		},
		{
			name: "other error",
			err:  errors.New("execution reverted"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := isRetriableWaitMinedError(tc.err)
			if got != tc.want {
				t.Fatalf("isRetriableWaitMinedError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestWaitForCodeAtAddress_FindsCode(t *testing.T) {
	t.Parallel()

	backend := &mockCodeAtBackend{
		responses: []mockCodeAtResponse{
			{code: nil},
			{code: []byte{0x60, 0x00}},
		},
	}

	found, err := waitForCodeAtAddress(context.Background(), backend, common.HexToAddress("0x1"), 100*time.Millisecond, time.Millisecond)
	if err != nil {
		t.Fatalf("waitForCodeAtAddress: %v", err)
	}
	if !found {
		t.Fatalf("expected contract code to be found")
	}
	if backend.calls < 2 {
		t.Fatalf("expected at least 2 code checks, got %d", backend.calls)
	}
}

func TestWaitForCodeAtAddress_TimeoutReturnsFalse(t *testing.T) {
	t.Parallel()

	backend := &mockCodeAtBackend{
		responses: []mockCodeAtResponse{
			{code: nil},
		},
	}

	found, err := waitForCodeAtAddress(context.Background(), backend, common.HexToAddress("0x1"), 20*time.Millisecond, time.Millisecond)
	if err != nil {
		t.Fatalf("waitForCodeAtAddress: %v", err)
	}
	if found {
		t.Fatalf("expected no contract code")
	}
	if backend.calls == 0 {
		t.Fatalf("expected at least 1 code check")
	}
}

func TestWaitForCodeAtAddress_ContextCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	backend := &mockCodeAtBackend{}
	found, err := waitForCodeAtAddress(ctx, backend, common.HexToAddress("0x1"), 100*time.Millisecond, time.Millisecond)
	if found {
		t.Fatalf("expected no contract code")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestPrependPathEntries(t *testing.T) {
	t.Parallel()

	got := prependPathEntries("/usr/bin:/bin", "/home/ubuntu/.cargo/bin", "/usr/bin")
	want := "/home/ubuntu/.cargo/bin:/usr/bin:/bin"
	if got != want {
		t.Fatalf("prependPathEntries() = %q, want %q", got, want)
	}
}

func TestUpsertEnvVar(t *testing.T) {
	t.Parallel()

	env := []string{"PATH=/usr/bin", "HOME=/tmp/home"}
	got := upsertEnvVar(env, "PATH", "/custom/bin")
	if got[0] != "PATH=/custom/bin" {
		t.Fatalf("expected PATH to be replaced, got %q", got[0])
	}

	got2 := upsertEnvVar([]string{"HOME=/tmp/home"}, "PATH", "/custom/bin")
	if len(got2) != 2 {
		t.Fatalf("expected appended env var, got len=%d", len(got2))
	}
	if got2[1] != "PATH=/custom/bin" {
		t.Fatalf("expected PATH append at end, got %q", got2[1])
	}
}

func TestJunoExecutionProofFromInputTxHash(t *testing.T) {
	t.Parallel()

	inputHash := "0x1234"
	gotHash, gotSource := junoExecutionProofFromInputTxHash(inputHash)
	if gotHash != inputHash {
		t.Fatalf("proof tx hash: got %q want %q", gotHash, inputHash)
	}
	if gotSource != "input.juno_execution_tx_hash" {
		t.Fatalf("proof source: got %q want %q", gotSource, "input.juno_execution_tx_hash")
	}
}

func TestJunoExecutionProofFromInputTxHash_EmptyHash(t *testing.T) {
	t.Parallel()

	gotHash, gotSource := junoExecutionProofFromInputTxHash("")
	if gotHash != "" {
		t.Fatalf("proof tx hash: got %q want empty", gotHash)
	}
	if gotSource != "" {
		t.Fatalf("proof source: got %q want empty", gotSource)
	}
}

func TestParseArgs_JunoExecutionTxHash(t *testing.T) {
	t.Parallel()

	args := runtimeSignerParseArgsBase(t)
	args = append(args,
		"--operator-address", "0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F",
		"--operator-address", "0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7",
		"--operator-address", "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"--juno-execution-tx-hash", "  juno-hash-123  ",
	)

	cfg, err := parseArgs(args)
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.JunoExecutionTxHash != "juno-hash-123" {
		t.Fatalf("juno execution tx hash: got %q want %q", cfg.JunoExecutionTxHash, "juno-hash-123")
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

func TestNormalizeRecipientDeltaActual_RecipientEqualsOwner(t *testing.T) {
	t.Parallel()

	raw := big.NewInt(89_555)
	got := normalizeRecipientDeltaActual(raw, true)
	if got.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("normalized recipient delta: got %s want 0", got.String())
	}
	if raw.Cmp(big.NewInt(89_555)) != 0 {
		t.Fatalf("raw recipient delta mutated: got %s want 89555", raw.String())
	}
}

func TestNormalizeRecipientDeltaActual_RecipientDiffersFromOwner(t *testing.T) {
	t.Parallel()

	raw := big.NewInt(99_500)
	got := normalizeRecipientDeltaActual(raw, false)
	if got.Cmp(big.NewInt(99_500)) != 0 {
		t.Fatalf("normalized recipient delta: got %s want 99500", got.String())
	}

	got.Add(got, big.NewInt(1))
	if raw.Cmp(big.NewInt(99_500)) != 0 {
		t.Fatalf("normalized recipient delta aliases input: got raw %s want 99500", raw.String())
	}
}

func TestCanonicalizeThresholdSignatures_SortsAndTrims(t *testing.T) {
	t.Parallel()

	k1, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(k1): %v", err)
	}
	k2, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(k2): %v", err)
	}
	k3, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(k3): %v", err)
	}

	digest := common.HexToHash("0x1234")
	sig2, err := checkpoint.SignDigest(k2, digest)
	if err != nil {
		t.Fatalf("SignDigest(k2): %v", err)
	}
	sig1, err := checkpoint.SignDigest(k1, digest)
	if err != nil {
		t.Fatalf("SignDigest(k1): %v", err)
	}
	sig3, err := checkpoint.SignDigest(k3, digest)
	if err != nil {
		t.Fatalf("SignDigest(k3): %v", err)
	}

	ops := []common.Address{
		crypto.PubkeyToAddress(k1.PublicKey),
		crypto.PubkeyToAddress(k2.PublicKey),
		crypto.PubkeyToAddress(k3.PublicKey),
	}
	got, err := canonicalizeThresholdSignatures(
		digest,
		[][]byte{sig2, sig1, sig3},
		ops,
		2,
	)
	if err != nil {
		t.Fatalf("canonicalizeThresholdSignatures: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("signature count: got %d want 2", len(got))
	}

	gotSigners := make([]common.Address, 0, len(got))
	for i, sig := range got {
		signer, err := checkpoint.RecoverSigner(digest, sig)
		if err != nil {
			t.Fatalf("RecoverSigner(sig[%d]): %v", i, err)
		}
		gotSigners = append(gotSigners, signer)
	}
	if bytes.Compare(gotSigners[0][:], gotSigners[1][:]) >= 0 {
		t.Fatalf("signatures not sorted ascending: %s then %s", gotSigners[0], gotSigners[1])
	}

	want := append([]common.Address(nil), ops...)
	sort.Slice(want, func(i, j int) bool {
		return bytes.Compare(want[i][:], want[j][:]) < 0
	})
	if gotSigners[0] != want[0] || gotSigners[1] != want[1] {
		t.Fatalf("unexpected signer set: got [%s, %s] want [%s, %s]", gotSigners[0], gotSigners[1], want[0], want[1])
	}
}

func TestCanonicalizeThresholdSignatures_RejectsUnknownSigner(t *testing.T) {
	t.Parallel()

	allowedKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(allowed): %v", err)
	}
	unknownKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey(unknown): %v", err)
	}

	digest := common.HexToHash("0x55")
	unknownSig, err := checkpoint.SignDigest(unknownKey, digest)
	if err != nil {
		t.Fatalf("SignDigest(unknown): %v", err)
	}

	_, err = canonicalizeThresholdSignatures(
		digest,
		[][]byte{unknownSig},
		[]common.Address{crypto.PubkeyToAddress(allowedKey.PublicKey)},
		1,
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unknown operator") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecOperatorDigestSigner_SignDigest(t *testing.T) {
	t.Parallel()

	signer, err := newExecOperatorDigestSigner(
		"/usr/local/bin/operator-runtime-signer",
		[]string{"https://op1.example.invalid:8443", "https://op2.example.invalid:8443"},
		4096,
	)
	if err != nil {
		t.Fatalf("newExecOperatorDigestSigner: %v", err)
	}

	digest := common.HexToHash("0xabcdef")
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sig, err := checkpoint.SignDigest(key, digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	wantArgs := []string{
		"sign-digest",
		"--digest", digest.Hex(),
		"--json",
		"--operator-endpoint", "https://op1.example.invalid:8443",
		"--operator-endpoint", "https://op2.example.invalid:8443",
	}
	signer.execCommand = func(_ context.Context, bin string, args []string) ([]byte, []byte, error) {
		if bin != "/usr/local/bin/operator-runtime-signer" {
			t.Fatalf("bin: got %q", bin)
		}
		if len(args) != len(wantArgs) {
			t.Fatalf("args len: got %d want %d (%v)", len(args), len(wantArgs), args)
		}
		for i := range args {
			if args[i] != wantArgs[i] {
				t.Fatalf("args[%d]: got %q want %q", i, args[i], wantArgs[i])
			}
		}
		resp := []byte(`{"version":"v1","status":"ok","data":{"signatures":["0x` + hex.EncodeToString(sig) + `"]}}`)
		return resp, nil, nil
	}

	got, err := signer.SignDigest(context.Background(), digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("signature count: got %d want 1", len(got))
	}
	if !bytes.Equal(got[0], sig) {
		t.Fatalf("signature mismatch")
	}
}

func TestWaitForWithdrawalFinalized_Immediate(t *testing.T) {
	t.Parallel()

	calls := 0
	got, err := waitForWithdrawalFinalized(
		context.Background(),
		time.Millisecond,
		func() (withdrawalView, error) {
			calls++
			return withdrawalView{Finalized: true}, nil
		},
	)
	if err != nil {
		t.Fatalf("waitForWithdrawalFinalized: %v", err)
	}
	if !got.Finalized {
		t.Fatalf("expected finalized withdrawal")
	}
	if calls != 1 {
		t.Fatalf("expected one call, got %d", calls)
	}
}

func TestWaitForWithdrawalFinalized_RetryThenSuccess(t *testing.T) {
	t.Parallel()

	calls := 0
	got, err := waitForWithdrawalFinalized(
		context.Background(),
		time.Millisecond,
		func() (withdrawalView, error) {
			calls++
			return withdrawalView{Finalized: calls >= 3}, nil
		},
	)
	if err != nil {
		t.Fatalf("waitForWithdrawalFinalized: %v", err)
	}
	if !got.Finalized {
		t.Fatalf("expected finalized withdrawal")
	}
	if calls != 3 {
		t.Fatalf("expected three calls, got %d", calls)
	}
}

func TestWaitForWithdrawalFinalized_TimesOut(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()

	_, err := waitForWithdrawalFinalized(
		ctx,
		5*time.Millisecond,
		func() (withdrawalView, error) {
			return withdrawalView{Finalized: false}, nil
		},
	)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out waiting for finalized withdrawal") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWaitForInvariantConvergence_Immediate(t *testing.T) {
	t.Parallel()

	calls := 0
	err := waitForInvariantConvergence(
		context.Background(),
		25*time.Millisecond,
		time.Millisecond,
		func() error {
			calls++
			return nil
		},
	)
	if err != nil {
		t.Fatalf("waitForInvariantConvergence: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected one call, got %d", calls)
	}
}

func TestWaitForInvariantConvergence_RetryThenSuccess(t *testing.T) {
	t.Parallel()

	calls := 0
	err := waitForInvariantConvergence(
		context.Background(),
		50*time.Millisecond,
		time.Millisecond,
		func() error {
			calls++
			if calls < 3 {
				return errors.New("not yet")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("waitForInvariantConvergence: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected three calls, got %d", calls)
	}
}

func TestWaitForInvariantConvergence_TimesOut(t *testing.T) {
	t.Parallel()

	err := waitForInvariantConvergence(
		context.Background(),
		15*time.Millisecond,
		5*time.Millisecond,
		func() error {
			return errors.New("still stale")
		},
	)
	if err == nil {
		t.Fatalf("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out waiting for invariant convergence") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), "still stale") {
		t.Fatalf("expected wrapped last error, got: %v", err)
	}
}
