package main

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type gasSuggestionBackend struct {
	gasPrice *big.Int
	gasTip   *big.Int
}

type legacyGasSuggestionBackend struct {
	gasPrice *big.Int
}

func (b legacyGasSuggestionBackend) SuggestGasPrice(context.Context) (*big.Int, error) {
	if b.gasPrice == nil {
		return nil, errors.New("no gas price")
	}
	return new(big.Int).Set(b.gasPrice), nil
}

func (b gasSuggestionBackend) SuggestGasPrice(context.Context) (*big.Int, error) {
	if b.gasPrice == nil {
		return nil, errors.New("no gas price")
	}
	return new(big.Int).Set(b.gasPrice), nil
}

func (b gasSuggestionBackend) SuggestGasTipCap(context.Context) (*big.Int, error) {
	if b.gasTip == nil {
		return nil, errors.New("no gas tip")
	}
	return new(big.Int).Set(b.gasTip), nil
}

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
	if len(cfg.OperatorFeeRecipients) != len(cfg.OperatorAddresses) {
		t.Fatalf("OperatorFeeRecipients len = %d, want %d", len(cfg.OperatorFeeRecipients), len(cfg.OperatorAddresses))
	}
	for i := range cfg.OperatorAddresses {
		if cfg.OperatorFeeRecipients[i] != cfg.OperatorAddresses[i] {
			t.Fatalf("OperatorFeeRecipients[%d] = %s, want %s", i, cfg.OperatorFeeRecipients[i].Hex(), cfg.OperatorAddresses[i].Hex())
		}
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

func TestParseArgs_AllowsSameGovernanceSafeAndPauseGuardian(t *testing.T) {
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
		"--pause-guardian", "0x1111111111111111111111111111111111111111",
		"--min-deposit-admin-address", "0x3333333333333333333333333333333333333333",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if got := cfg.PauseGuardian.Hex(); got != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("PauseGuardian = %s", got)
	}
}

func TestParseArgs_UsesExplicitOperatorFeeRecipients(t *testing.T) {
	t.Parallel()

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "8453",
		"--funder-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--ephemeral-funding-amount-wei", "50000000000000000",
		"--operator-address", "0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F",
		"--operator-fee-recipient", "0x1111111111111111111111111111111111111111",
		"--operator-address", "0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7",
		"--operator-fee-recipient", "0x2222222222222222222222222222222222222222",
		"--operator-address", "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"--operator-fee-recipient", "0x3333333333333333333333333333333333333333",
		"--threshold", "3",
		"--verifier-address", "0x475576d5685465D5bd65E91Cf10053f9d0EFd685",
		"--governance-safe", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"--pause-guardian", "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"--min-deposit-admin-address", "0xcccccccccccccccccccccccccccccccccccccccc",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}

	want := []common.Address{
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"),
		common.HexToAddress("0x3333333333333333333333333333333333333333"),
	}
	if len(cfg.OperatorFeeRecipients) != len(want) {
		t.Fatalf("OperatorFeeRecipients len = %d, want %d", len(cfg.OperatorFeeRecipients), len(want))
	}
	for i := range want {
		if cfg.OperatorFeeRecipients[i] != want[i] {
			t.Fatalf("OperatorFeeRecipients[%d] = %s, want %s", i, cfg.OperatorFeeRecipients[i].Hex(), want[i].Hex())
		}
	}
}

func TestParseArgs_RejectsOperatorFeeRecipientCountMismatch(t *testing.T) {
	t.Parallel()

	_, err := parseArgs([]string{
		"--rpc-url", "https://example-rpc.invalid",
		"--chain-id", "8453",
		"--deployer-key-hex", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		"--operator-address", "0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F",
		"--operator-fee-recipient", "0x1111111111111111111111111111111111111111",
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

func TestSortedOperatorBindings_PreservesFeeRecipientMapping(t *testing.T) {
	t.Parallel()

	bindings := sortedOperatorBindings(
		[]common.Address{
			common.HexToAddress("0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7"),
			common.HexToAddress("0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F"),
			common.HexToAddress("0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1"),
		},
		[]common.Address{
			common.HexToAddress("0x2222222222222222222222222222222222222222"),
			common.HexToAddress("0x1111111111111111111111111111111111111111"),
			common.HexToAddress("0x3333333333333333333333333333333333333333"),
		},
	)

	if len(bindings) != 3 {
		t.Fatalf("len(bindings) = %d, want 3", len(bindings))
	}
	if bindings[0].Operator != common.HexToAddress("0x4F2a2d66d7f13f3Ac8A9f8E35CAb2B3a1D52A03F") || bindings[0].FeeRecipient != common.HexToAddress("0x1111111111111111111111111111111111111111") {
		t.Fatalf("binding[0] = (%s -> %s)", bindings[0].Operator.Hex(), bindings[0].FeeRecipient.Hex())
	}
	if bindings[1].Operator != common.HexToAddress("0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1") || bindings[1].FeeRecipient != common.HexToAddress("0x3333333333333333333333333333333333333333") {
		t.Fatalf("binding[1] = (%s -> %s)", bindings[1].Operator.Hex(), bindings[1].FeeRecipient.Hex())
	}
	if bindings[2].Operator != common.HexToAddress("0xBf0CB7f2dE3dEdA412fF6A9021fdaBf8B34C10A7") || bindings[2].FeeRecipient != common.HexToAddress("0x2222222222222222222222222222222222222222") {
		t.Fatalf("binding[2] = (%s -> %s)", bindings[2].Operator.Hex(), bindings[2].FeeRecipient.Hex())
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

func TestFundingValueWei(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		requested string
		balance   string
		fee       string
		want      string
		wantOkay  bool
	}{
		{
			name:      "uses requested value when affordable",
			requested: "15000000000000000",
			balance:   "20000000000000000",
			fee:       "126000000000",
			want:      "15000000000000000",
			wantOkay:  true,
		},
		{
			name:      "clamps to affordable balance when requested exceeds headroom",
			requested: "15000000000000000",
			balance:   "10720564897725620",
			fee:       "126000000000",
			want:      "10720438897725620",
			wantOkay:  true,
		},
		{
			name:      "rejects zero affordable value",
			requested: "15000000000000000",
			balance:   "126000000000",
			fee:       "126000000000",
			want:      "0",
			wantOkay:  false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			requested, ok := new(big.Int).SetString(tt.requested, 10)
			if !ok {
				t.Fatalf("invalid requested test input: %s", tt.requested)
			}
			balance, ok := new(big.Int).SetString(tt.balance, 10)
			if !ok {
				t.Fatalf("invalid balance test input: %s", tt.balance)
			}
			fee, ok := new(big.Int).SetString(tt.fee, 10)
			if !ok {
				t.Fatalf("invalid fee test input: %s", tt.fee)
			}

			got, ok := fundingValueWei(requested, balance, fee)
			if ok != tt.wantOkay {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOkay)
			}
			if got.String() != tt.want {
				t.Fatalf("value = %s, want %s", got.String(), tt.want)
			}
		})
	}
}

func TestTransactAuthWithDefaults_SetsDefaultGasLimitWhenUnset(t *testing.T) {
	t.Parallel()

	auth := &bind.TransactOpts{}
	got := transactAuthWithDefaults(auth, 4_000_000)
	if got == auth {
		t.Fatal("transactAuthWithDefaults returned the original auth pointer")
	}
	if got.GasLimit != 4_000_000 {
		t.Fatalf("GasLimit = %d, want %d", got.GasLimit, 4_000_000)
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

func TestTransactAuthWithDefaults_PreservesExplicitGasLimit(t *testing.T) {
	t.Parallel()

	auth := &bind.TransactOpts{GasLimit: 123_456}
	got := transactAuthWithDefaults(auth, 4_000_000)
	if got == auth {
		t.Fatal("transactAuthWithDefaults returned the original auth pointer")
	}
	if got.GasLimit != auth.GasLimit {
		t.Fatalf("GasLimit = %d, want %d", got.GasLimit, auth.GasLimit)
	}
}

func TestApplyRetryGasBump_PrefersSuggestedLegacyGasPrice(t *testing.T) {
	t.Parallel()

	auth := &bind.TransactOpts{}
	backend := legacyGasSuggestionBackend{gasPrice: big.NewInt(6_000_000)}

	applyRetryGasBump(context.Background(), backend, auth, 1)

	if auth.GasPrice == nil {
		t.Fatal("GasPrice = nil, want suggested gas price")
	}
	if auth.GasPrice.Cmp(big.NewInt(6_000_000)) != 0 {
		t.Fatalf("GasPrice = %s, want 6000000", auth.GasPrice.String())
	}
	if auth.GasTipCap != nil {
		t.Fatalf("GasTipCap = %s, want nil", auth.GasTipCap.String())
	}
	if auth.GasFeeCap != nil {
		t.Fatalf("GasFeeCap = %s, want nil", auth.GasFeeCap.String())
	}
}

func TestApplyRetryGasBump_PrefersSuggestedEIP1559Pricing(t *testing.T) {
	t.Parallel()

	auth := &bind.TransactOpts{}
	backend := gasSuggestionBackend{
		gasPrice: big.NewInt(6_000_000),
		gasTip:   big.NewInt(1_000_000),
	}

	applyRetryGasBump(context.Background(), backend, auth, 1)

	if auth.GasPrice != nil {
		t.Fatalf("GasPrice = %s, want nil", auth.GasPrice.String())
	}
	if auth.GasTipCap == nil {
		t.Fatal("GasTipCap = nil, want suggested gas tip")
	}
	if auth.GasTipCap.Cmp(big.NewInt(1_000_000)) != 0 {
		t.Fatalf("GasTipCap = %s, want 1000000", auth.GasTipCap.String())
	}
	if auth.GasFeeCap == nil {
		t.Fatal("GasFeeCap = nil, want suggested gas fee cap")
	}
	if auth.GasFeeCap.Cmp(big.NewInt(6_000_000)) != 0 {
		t.Fatalf("GasFeeCap = %s, want 6000000", auth.GasFeeCap.String())
	}
}

func TestSweepReservedFeeWei_IncludesSafetyBuffer(t *testing.T) {
	t.Parallel()

	gasPrice := big.NewInt(7)
	want := new(big.Int).Add(big.NewInt(147000), big.NewInt(sweepValueSafetyBufferWei))

	got := sweepReservedFeeWei(gasPrice)
	if got.Cmp(want) != 0 {
		t.Fatalf("reserved fee = %s, want %s", got.String(), want.String())
	}
}

func TestSweepReservedFeeWei_LeavesSweepHeadroom(t *testing.T) {
	t.Parallel()

	gasPrice := big.NewInt(7)
	minHeadroom := new(big.Int).Add(big.NewInt(147000), big.NewInt(10_000))

	got := sweepReservedFeeWei(gasPrice)
	if got.Cmp(minHeadroom) < 0 {
		t.Fatalf("reserved fee = %s, want at least %s", got.String(), minHeadroom.String())
	}
}

func TestSweepEphemeralDeployerWithRetry_AdjustsForObservedShortfall(t *testing.T) {
	t.Parallel()

	balance := big.NewInt(1_000_000)
	gasPrice := big.NewInt(7)
	firstValue := new(big.Int).Sub(balance, sweepReservedFeeWei(gasPrice))
	shortage := big.NewInt(10_000)
	secondReserve := new(big.Int).Add(
		sweepReservedFeeWei(gasPrice),
		new(big.Int).Add(shortage, big.NewInt(sweepValueSafetyBufferWei)),
	)
	secondValue := new(big.Int).Sub(balance, secondReserve)
	wantHash := common.HexToHash("0x1")
	attempts := 0

	gotHash, swept, err := sweepEphemeralDeployerWithRetry(
		context.Background(),
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(balance), nil
		},
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(gasPrice), nil
		},
		func(_ context.Context, value, gotGasPrice *big.Int) (common.Hash, error) {
			attempts++
			if gotGasPrice.Cmp(gasPrice) != 0 {
				t.Fatalf("gas price = %s, want %s", gotGasPrice.String(), gasPrice.String())
			}
			switch attempts {
			case 1:
				if value.Cmp(firstValue) != 0 {
					t.Fatalf("first value = %s, want %s", value.String(), firstValue.String())
				}
				return common.Hash{}, errors.New("send tx: insufficient funds for gas * price + value: have 890000 want 900000")
			case 2:
				if value.Cmp(secondValue) != 0 {
					t.Fatalf("second value = %s, want %s", value.String(), secondValue.String())
				}
				return wantHash, nil
			default:
				t.Fatalf("unexpected sweep attempt %d", attempts)
				return common.Hash{}, nil
			}
		},
	)
	if err != nil {
		t.Fatalf("sweepEphemeralDeployerWithRetry: %v", err)
	}
	if !swept {
		t.Fatalf("swept = false, want true")
	}
	if gotHash != wantHash {
		t.Fatalf("hash = %s, want %s", gotHash.Hex(), wantHash.Hex())
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestSweepEphemeralDeployerWithRetry_ToleratesMultipleObservedShortfalls(t *testing.T) {
	t.Parallel()

	balance := big.NewInt(1_000_000)
	gasPrice := big.NewInt(7)
	shortages := []*big.Int{
		big.NewInt(10_000),
		big.NewInt(20_000),
		big.NewInt(30_000),
	}
	wantHash := common.HexToHash("0x4")
	attempts := 0

	gotHash, swept, err := sweepEphemeralDeployerWithRetry(
		context.Background(),
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(balance), nil
		},
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(gasPrice), nil
		},
		func(_ context.Context, value, gotGasPrice *big.Int) (common.Hash, error) {
			attempts++
			if gotGasPrice.Cmp(gasPrice) != 0 {
				t.Fatalf("gas price = %s, want %s", gotGasPrice.String(), gasPrice.String())
			}
			if attempts <= len(shortages) {
				shortage := shortages[attempts-1]
				wantReserve := sweepReservedFeeWei(gasPrice)
				if attempts == 1 {
					wantReserve = sweepReservedFeeWei(gasPrice)
				} else {
					prevShortage := shortages[attempts-2]
					wantReserve = new(big.Int).Add(
						sweepReservedFeeWei(gasPrice),
						new(big.Int).Add(prevShortage, big.NewInt(sweepValueSafetyBufferWei)),
					)
				}
				wantValue := new(big.Int).Sub(balance, wantReserve)
				if value.Cmp(wantValue) != 0 {
					t.Fatalf("attempt %d value = %s, want %s", attempts, value.String(), wantValue.String())
				}
				return common.Hash{}, fmt.Errorf(
					"send tx: insufficient funds for gas * price + value: balance %s, tx cost %s, overshot %s",
					balance.String(),
					new(big.Int).Add(balance, shortage).String(),
					shortage.String(),
				)
			}
			wantReserve := new(big.Int).Add(
				sweepReservedFeeWei(gasPrice),
				new(big.Int).Add(shortages[len(shortages)-1], big.NewInt(sweepValueSafetyBufferWei)),
			)
			wantValue := new(big.Int).Sub(balance, wantReserve)
			if value.Cmp(wantValue) != 0 {
				t.Fatalf("final value = %s, want %s", value.String(), wantValue.String())
			}
			return wantHash, nil
		},
	)
	if err != nil {
		t.Fatalf("sweepEphemeralDeployerWithRetry: %v", err)
	}
	if !swept {
		t.Fatalf("swept = false, want true")
	}
	if gotHash != wantHash {
		t.Fatalf("hash = %s, want %s", gotHash.Hex(), wantHash.Hex())
	}
	if attempts != len(shortages)+1 {
		t.Fatalf("attempts = %d, want %d", attempts, len(shortages)+1)
	}
}

func TestSweepEphemeralDeployerWithRetry_RetriesRetriableNonceErrors(t *testing.T) {
	t.Parallel()

	balance := big.NewInt(1_000_000)
	gasPrice := big.NewInt(7)
	wantValue, ok := sweepValueWei(balance, sweepReservedFeeWei(gasPrice))
	if !ok {
		t.Fatal("expected sweep value")
	}
	wantHash := common.HexToHash("0x2")
	attempts := 0

	gotHash, swept, err := sweepEphemeralDeployerWithRetry(
		context.Background(),
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(balance), nil
		},
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(gasPrice), nil
		},
		func(_ context.Context, value, gotGasPrice *big.Int) (common.Hash, error) {
			attempts++
			if gotGasPrice.Cmp(gasPrice) != 0 {
				t.Fatalf("gas price = %s, want %s", gotGasPrice.String(), gasPrice.String())
			}
			if value.Cmp(wantValue) != 0 {
				t.Fatalf("value = %s, want %s", value.String(), wantValue.String())
			}
			if attempts == 1 {
				return common.Hash{}, errors.New("send tx: nonce too low: next nonce 32, tx nonce 31")
			}
			if attempts == 2 {
				return wantHash, nil
			}
			t.Fatalf("unexpected sweep attempt %d", attempts)
			return common.Hash{}, nil
		},
	)
	if err != nil {
		t.Fatalf("sweepEphemeralDeployerWithRetry: %v", err)
	}
	if !swept {
		t.Fatalf("swept = false, want true")
	}
	if gotHash != wantHash {
		t.Fatalf("hash = %s, want %s", gotHash.Hex(), wantHash.Hex())
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestFundEphemeralDeployerWithRetry_ClampsRequestedFundingToAffordableBalance(t *testing.T) {
	t.Parallel()

	requested := big.NewInt(15_000_000_000_000_000)
	balance := big.NewInt(10_720_564_897_725_620)
	gasPrice := big.NewInt(6_000_000)
	wantValue := big.NewInt(10_720_438_897_725_620)
	wantHash := common.HexToHash("0x5")
	attempts := 0

	gotHash, fundedAmount, err := fundEphemeralDeployerWithRetry(
		context.Background(),
		requested,
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(balance), nil
		},
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(gasPrice), nil
		},
		func(_ context.Context, value, gotGasPrice *big.Int) (common.Hash, error) {
			attempts++
			if gotGasPrice.Cmp(gasPrice) != 0 {
				t.Fatalf("gas price = %s, want %s", gotGasPrice.String(), gasPrice.String())
			}
			if value.Cmp(wantValue) != 0 {
				t.Fatalf("value = %s, want %s", value.String(), wantValue.String())
			}
			return wantHash, nil
		},
	)
	if err != nil {
		t.Fatalf("fundEphemeralDeployerWithRetry: %v", err)
	}
	if gotHash != wantHash {
		t.Fatalf("hash = %s, want %s", gotHash.Hex(), wantHash.Hex())
	}
	if fundedAmount.Cmp(wantValue) != 0 {
		t.Fatalf("fundedAmount = %s, want %s", fundedAmount.String(), wantValue.String())
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestSweepEphemeralDeployerWithRetry_RetriesWaitMinedTimeout(t *testing.T) {
	t.Parallel()

	balance := big.NewInt(1_000_000)
	gasPrice := big.NewInt(7)
	wantValue, ok := sweepValueWei(balance, sweepReservedFeeWei(gasPrice))
	if !ok {
		t.Fatal("expected sweep value")
	}
	wantHash := common.HexToHash("0x3")
	attempts := 0

	gotHash, swept, err := sweepEphemeralDeployerWithRetry(
		context.Background(),
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(balance), nil
		},
		func(context.Context) (*big.Int, error) {
			return new(big.Int).Set(gasPrice), nil
		},
		func(_ context.Context, value, gotGasPrice *big.Int) (common.Hash, error) {
			attempts++
			if gotGasPrice.Cmp(gasPrice) != 0 {
				t.Fatalf("gas price = %s, want %s", gotGasPrice.String(), gasPrice.String())
			}
			if value.Cmp(wantValue) != 0 {
				t.Fatalf("value = %s, want %s", value.String(), wantValue.String())
			}
			if attempts == 1 {
				return common.Hash{}, context.DeadlineExceeded
			}
			if attempts == 2 {
				return wantHash, nil
			}
			t.Fatalf("unexpected sweep attempt %d", attempts)
			return common.Hash{}, nil
		},
	)
	if err != nil {
		t.Fatalf("sweepEphemeralDeployerWithRetry: %v", err)
	}
	if !swept {
		t.Fatalf("swept = false, want true")
	}
	if gotHash != wantHash {
		t.Fatalf("hash = %s, want %s", gotHash.Hex(), wantHash.Hex())
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestInsufficientFundsShortageWei_ParsesOvershotFormat(t *testing.T) {
	t.Parallel()

	shortage, ok := insufficientFundsShortageWei(errors.New(
		"send tx: insufficient funds for gas * price + value: balance 10759993571077681, tx cost 10759994195683386, overshot 624605705",
	))
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if shortage.Cmp(big.NewInt(624605705)) != 0 {
		t.Fatalf("shortage = %s, want 624605705", shortage.String())
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
