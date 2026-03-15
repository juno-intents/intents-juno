package main

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestParseArgs_ValidDirectDeployer(t *testing.T) {
	t.Parallel()

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "8453",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-address", "0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F",
		"--operator-address", "0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7",
		"--operator-address", "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--governance-safe", "0x1111111111111111111111111111111111111111",
		"--pause-guardian", "0x2222222222222222222222222222222222222222",
		"--min-deposit-admin-address", "0x3333333333333333333333333333333333333333",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.UseEphemeralDeployer {
		t.Fatalf("UseEphemeralDeployer = true, want false")
	}
	if cfg.TimelockMinDelaySeconds != 48*60*60 {
		t.Fatalf("TimelockMinDelaySeconds = %d, want %d", cfg.TimelockMinDelaySeconds, 48*60*60)
	}
	if got := cfg.GovernanceSafe.Hex(); got != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("GovernanceSafe = %s", got)
	}
	if got := cfg.PauseGuardian.Hex(); got != "0x2222222222222222222222222222222222222222" {
		t.Fatalf("PauseGuardian = %s", got)
	}
	if got := cfg.MinDepositAdmin.Hex(); got != "0x3333333333333333333333333333333333333333" {
		t.Fatalf("MinDepositAdmin = %s", got)
	}
}

func TestParseArgs_ValidEphemeralDeployer(t *testing.T) {
	t.Parallel()

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "8453",
		"--funder-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--ephemeral-funding-amount-wei", "50000000000000000",
		"--operator-address", "0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F",
		"--operator-address", "0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7",
		"--operator-address", "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--governance-safe", "0x1111111111111111111111111111111111111111",
		"--pause-guardian", "0x2222222222222222222222222222222222222222",
		"--min-deposit-admin-address", "0x3333333333333333333333333333333333333333",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !cfg.UseEphemeralDeployer {
		t.Fatalf("UseEphemeralDeployer = false, want true")
	}
	if cfg.EphemeralFundingAmountWei == nil {
		t.Fatalf("EphemeralFundingAmountWei = nil")
	}
	if cfg.EphemeralFundingAmountWei.Cmp(big.NewInt(50_000_000_000_000_000)) != 0 {
		t.Fatalf("EphemeralFundingAmountWei = %s", cfg.EphemeralFundingAmountWei.String())
	}
}

func TestParseArgs_RejectsMixedDeployerModes(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "8453",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--funder-key-hex", "0x59c6995e998f97a5a0044976f6f8f5f2b0f95f4d4e4d7d75e4f3f7c06f2a3d9a",
		"--ephemeral-funding-amount-wei", "50000000000000000",
		"--operator-address", "0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F",
		"--operator-address", "0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7",
		"--operator-address", "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--governance-safe", "0x1111111111111111111111111111111111111111",
		"--pause-guardian", "0x2222222222222222222222222222222222222222",
		"--min-deposit-admin-address", "0x3333333333333333333333333333333333333333",
	})
	if err == nil {
		t.Fatalf("parseArgs: got nil error, want error")
	}
}

func TestParseArgs_RequiresGovernanceFlags(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "8453",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-address", "0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F",
		"--operator-address", "0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7",
		"--operator-address", "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
	})
	if err == nil {
		t.Fatalf("parseArgs: got nil error, want error")
	}
}

func TestSweepValueWei(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		balance  string
		fee      string
		want     string
		wantOkay bool
	}{
		{name: "has remainder", balance: "100", fee: "21", want: "79", wantOkay: true},
		{name: "exact fee", balance: "21", fee: "21", want: "0", wantOkay: true},
		{name: "insufficient", balance: "20", fee: "21", want: "0", wantOkay: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			balance, ok := new(big.Int).SetString(tt.balance, 10)
			if !ok {
				t.Fatalf("invalid balance test input: %s", tt.balance)
			}
			fee, ok := new(big.Int).SetString(tt.fee, 10)
			if !ok {
				t.Fatalf("invalid fee test input: %s", tt.fee)
			}

			got, ok := sweepValueWei(balance, fee)
			if ok != tt.wantOkay {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOkay)
			}
			if got.String() != tt.want {
				t.Fatalf("value = %s, want %s", got.String(), tt.want)
			}
		})
	}
}

func TestLegacyValueTransferFeeWei(t *testing.T) {
	t.Parallel()

	gasPrice := big.NewInt(7)
	want := big.NewInt(147000)

	got := legacyValueTransferFeeWei(gasPrice)
	if got.Cmp(want) != 0 {
		t.Fatalf("fee = %s, want %s", got.String(), want.String())
	}
}

func TestBuildLegacyValueTransferTx_UsesProvidedGasPrice(t *testing.T) {
	t.Parallel()

	to := common.HexToAddress("0x1111111111111111111111111111111111111111")
	value := big.NewInt(12345)
	gasPrice := big.NewInt(987654321)

	tx := buildLegacyValueTransferTx(9, to, value, gasPrice)

	if tx.Gas() != legacyValueTransferGasLimit {
		t.Fatalf("gas limit = %d, want %d", tx.Gas(), legacyValueTransferGasLimit)
	}
	if tx.GasPrice().Cmp(gasPrice) != 0 {
		t.Fatalf("gas price = %s, want %s", tx.GasPrice().String(), gasPrice.String())
	}
	if tx.Value().Cmp(value) != 0 {
		t.Fatalf("value = %s, want %s", tx.Value().String(), value.String())
	}
}

func TestWaitBigIntAtLeastAttempts(t *testing.T) {
	t.Parallel()

	values := []*big.Int{big.NewInt(0), big.NewInt(5), big.NewInt(10)}
	idx := 0

	got, err := waitBigIntAtLeastAttempts(
		context.Background(),
		"ephemeral balance",
		big.NewInt(10),
		len(values),
		0,
		func() (*big.Int, error) {
			current := new(big.Int).Set(values[idx])
			if idx < len(values)-1 {
				idx++
			}
			return current, nil
		},
	)
	if err != nil {
		t.Fatalf("waitBigIntAtLeastAttempts: %v", err)
	}
	if got.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("balance = %s, want 10", got.String())
	}
}

func TestWaitBigIntAtLeastAttemptsMismatch(t *testing.T) {
	t.Parallel()

	got, err := waitBigIntAtLeastAttempts(
		context.Background(),
		"ephemeral balance",
		big.NewInt(10),
		2,
		0,
		func() (*big.Int, error) {
			return big.NewInt(5), nil
		},
	)
	if err == nil {
		t.Fatalf("waitBigIntAtLeastAttempts: got nil error, want error")
	}
	if got.Cmp(big.NewInt(5)) != 0 {
		t.Fatalf("balance = %s, want 5", got.String())
	}
}
