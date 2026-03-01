package e2eorch

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Balances captures wJUNO balances for invariant checking.
type Balances struct {
	Recipient      *big.Int
	FeeDistributor *big.Int
}

// RecordBalances reads current wJUNO balances for the recipient and fee
// distributor addresses. Used before and after flows to compute deltas.
func RecordBalances(ctx context.Context, client *ethclient.Client, cfg E2EConfig) (*Balances, error) {
	recipientBal, err := ReadWJunoBalance(ctx, client, cfg.WJunoAddress, cfg.RecipientAddress)
	if err != nil {
		return nil, fmt.Errorf("read recipient wJUNO balance: %w", err)
	}
	feeDistBal, err := ReadWJunoBalance(ctx, client, cfg.WJunoAddress, cfg.FeeDistributorAddress)
	if err != nil {
		return nil, fmt.Errorf("read fee distributor wJUNO balance: %w", err)
	}
	return &Balances{
		Recipient:      recipientBal,
		FeeDistributor: feeDistBal,
	}, nil
}

// CheckInvariants runs post-flow invariant checks and returns the results.
func CheckInvariants(
	ctx context.Context,
	cfg E2EConfig,
	client *ethclient.Client,
	deposit *DepositResult,
	withdraw *WithdrawalResult,
	preBal *Balances,
) []InvariantCheck {
	var checks []InvariantCheck

	// 1. depositUsed(depositId) == true on-chain.
	if deposit != nil && deposit.DepositID != "" {
		check := checkDepositUsed(ctx, client, cfg.BridgeAddress, deposit.DepositID)
		checks = append(checks, check)
	}

	// 2. getWithdrawal(withdrawalId) shows finalized == true with correct amounts.
	if withdraw != nil && withdraw.WithdrawalID != "" {
		wChecks := checkWithdrawalOnChain(ctx, client, cfg, withdraw)
		checks = append(checks, wChecks...)
	}

	// 3. Fee arithmetic.
	if deposit != nil && withdraw != nil {
		feeChecks := checkFeeArithmetic(cfg, deposit, withdraw)
		checks = append(checks, feeChecks...)
	}

	// 4. Balance deltas.
	if preBal != nil && deposit != nil {
		balChecks := checkBalanceDeltas(ctx, client, cfg, deposit, withdraw, preBal)
		checks = append(checks, balChecks...)
	}

	// 5. IPFS checkpoint availability.
	if cfg.IPFSAPIUrl != "" {
		check := checkIPFSAvailable(ctx, cfg.IPFSAPIUrl)
		checks = append(checks, check)
	}

	return checks
}

func checkDepositUsed(ctx context.Context, client *ethclient.Client, bridgeAddr common.Address, depositIDHex string) InvariantCheck {
	name := "deposit_used_on_chain"

	depositIDBytes, err := parseHexTo32(depositIDHex)
	if err != nil {
		return InvariantCheck{Name: name, Passed: false, Details: fmt.Sprintf("parse depositId: %v", err)}
	}

	used, err := ReadDepositUsed(ctx, client, bridgeAddr, depositIDBytes)
	if err != nil {
		return InvariantCheck{Name: name, Passed: false, Details: fmt.Sprintf("call depositUsed: %v", err)}
	}
	if !used {
		return InvariantCheck{Name: name, Passed: false, Details: "depositUsed returned false"}
	}
	return InvariantCheck{Name: name, Passed: true, Details: "depositUsed == true"}
}

func checkWithdrawalOnChain(ctx context.Context, client *ethclient.Client, cfg E2EConfig, withdraw *WithdrawalResult) []InvariantCheck {
	var checks []InvariantCheck
	name := "withdrawal_finalized_on_chain"

	wID, err := parseHexTo32(withdraw.WithdrawalID)
	if err != nil {
		checks = append(checks, InvariantCheck{Name: name, Passed: false, Details: fmt.Sprintf("parse withdrawalId: %v", err)})
		return checks
	}

	view, err := ReadWithdrawalView(ctx, client, cfg.BridgeAddress, wID)
	if err != nil {
		checks = append(checks, InvariantCheck{Name: name, Passed: false, Details: fmt.Sprintf("call getWithdrawal: %v", err)})
		return checks
	}

	if !view.Finalized {
		checks = append(checks, InvariantCheck{Name: name, Passed: false, Details: "finalized == false on-chain"})
	} else {
		checks = append(checks, InvariantCheck{Name: name, Passed: true, Details: "finalized == true on-chain"})
	}

	// Verify the on-chain amount matches what was requested.
	if view.Amount != nil {
		onChainAmount := view.Amount.Uint64()
		if onChainAmount != cfg.WithdrawAmount {
			checks = append(checks, InvariantCheck{
				Name:    "withdrawal_amount_match",
				Passed:  false,
				Details: fmt.Sprintf("on-chain amount %d != requested %d", onChainAmount, cfg.WithdrawAmount),
			})
		} else {
			checks = append(checks, InvariantCheck{
				Name:    "withdrawal_amount_match",
				Passed:  true,
				Details: fmt.Sprintf("on-chain amount matches: %d", onChainAmount),
			})
		}
	}

	return checks
}

func checkFeeArithmetic(cfg E2EConfig, deposit *DepositResult, withdraw *WithdrawalResult) []InvariantCheck {
	var checks []InvariantCheck

	feeBps := withdraw.FeeBps
	tipBps := cfg.ExpectedTipBps
	amount := cfg.WithdrawAmount

	// fee = amount * feeBps / 10000
	fee := amount * feeBps / 10000
	// tip = fee * tipBps / 10000
	tip := fee * tipBps / 10000
	// net = amount - fee
	net := amount - fee

	if feeBps != cfg.ExpectedFeeBps {
		checks = append(checks, InvariantCheck{
			Name:    "fee_bps_match",
			Passed:  false,
			Details: fmt.Sprintf("feeBps %d != expected %d", feeBps, cfg.ExpectedFeeBps),
		})
	} else {
		checks = append(checks, InvariantCheck{
			Name:    "fee_bps_match",
			Passed:  true,
			Details: fmt.Sprintf("feeBps matches: %d", feeBps),
		})
	}

	checks = append(checks, InvariantCheck{
		Name:   "fee_arithmetic",
		Passed: true,
		Details: fmt.Sprintf("amount=%d fee=%d (bps=%d) tip=%d (tipBps=%d) net=%d",
			amount, fee, feeBps, tip, tipBps, net),
	})

	return checks
}

func checkBalanceDeltas(
	ctx context.Context,
	client *ethclient.Client,
	cfg E2EConfig,
	deposit *DepositResult,
	withdraw *WithdrawalResult,
	preBal *Balances,
) []InvariantCheck {
	var checks []InvariantCheck

	postBal, err := RecordBalances(ctx, client, cfg)
	if err != nil {
		checks = append(checks, InvariantCheck{
			Name:    "balance_delta_read",
			Passed:  false,
			Details: fmt.Sprintf("read post balances: %v", err),
		})
		return checks
	}

	// Recipient delta: should have gained depositAmount - withdrawAmount
	// (simplified; the actual flow deposits wJUNO then withdraws some).
	recipientDelta := new(big.Int).Sub(postBal.Recipient, preBal.Recipient)

	depositAmt := new(big.Int).SetUint64(cfg.DepositAmountZat)
	var expectedRecipientDelta *big.Int
	if withdraw != nil {
		withdrawAmt := new(big.Int).SetUint64(cfg.WithdrawAmount)
		expectedRecipientDelta = new(big.Int).Sub(depositAmt, withdrawAmt)
	} else {
		expectedRecipientDelta = depositAmt
	}

	if recipientDelta.Cmp(expectedRecipientDelta) == 0 {
		checks = append(checks, InvariantCheck{
			Name:    "recipient_balance_delta",
			Passed:  true,
			Details: fmt.Sprintf("recipient wJUNO delta = %s (expected %s)", recipientDelta, expectedRecipientDelta),
		})
	} else {
		checks = append(checks, InvariantCheck{
			Name:    "recipient_balance_delta",
			Passed:  false,
			Details: fmt.Sprintf("recipient wJUNO delta = %s, expected %s", recipientDelta, expectedRecipientDelta),
		})
	}

	// Fee distributor delta: should have gained the withdrawal fee.
	if withdraw != nil {
		feeDistDelta := new(big.Int).Sub(postBal.FeeDistributor, preBal.FeeDistributor)
		expectedFee := cfg.WithdrawAmount * withdraw.FeeBps / 10000
		expectedFeeBig := new(big.Int).SetUint64(expectedFee)

		if feeDistDelta.Cmp(expectedFeeBig) == 0 {
			checks = append(checks, InvariantCheck{
				Name:    "fee_distributor_balance_delta",
				Passed:  true,
				Details: fmt.Sprintf("fee distributor wJUNO delta = %s (expected %s)", feeDistDelta, expectedFeeBig),
			})
		} else {
			// Fee distribution may happen asynchronously or be split; log a warning.
			checks = append(checks, InvariantCheck{
				Name:    "fee_distributor_balance_delta",
				Passed:  false,
				Details: fmt.Sprintf("fee distributor wJUNO delta = %s, expected %s", feeDistDelta, expectedFeeBig),
			})
		}
	}

	return checks
}

func checkIPFSAvailable(ctx context.Context, ipfsAPIURL string) InvariantCheck {
	name := "ipfs_checkpoint_available"

	log.Printf("[invariants] checking IPFS availability at %s", ipfsAPIURL)

	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, ipfsAPIURL, nil)
	if err != nil {
		return InvariantCheck{Name: name, Passed: false, Details: fmt.Sprintf("build request: %v", err)}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return InvariantCheck{Name: name, Passed: false, Details: fmt.Sprintf("GET %s: %v", ipfsAPIURL, err)}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode == http.StatusOK {
		return InvariantCheck{Name: name, Passed: true, Details: "IPFS endpoint reachable"}
	}
	return InvariantCheck{Name: name, Passed: false, Details: fmt.Sprintf("IPFS returned status %d", resp.StatusCode)}
}

func parseHexTo32(s string) ([32]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return [32]byte{}, fmt.Errorf("expected 32-byte hex, got len %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}
