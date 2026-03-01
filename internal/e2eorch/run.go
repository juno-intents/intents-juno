package e2eorch

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/ethereum/go-ethereum/ethclient"
)

// Run is the top-level orchestration entrypoint. It drives the full e2e flow:
// 1. Wait for bridge-api health
// 2. Fetch bridge config and validate
// 3. Record pre-flow balances
// 4. Run deposit flow
// 5. Run withdrawal flow
// 6. Run invariant checks
// 7. Assemble and return report
func Run(ctx context.Context, cfg E2EConfig) (*Report, error) {
	report := NewReport()

	api := NewBridgeAPIClient(cfg.BridgeAPIURL)

	// 1. Wait for bridge-api to be healthy.
	log.Printf("[run] waiting for bridge-api at %s", cfg.BridgeAPIURL)
	if err := api.WaitHealthy(ctx); err != nil {
		report.Error = fmt.Sprintf("bridge-api not healthy: %v", err)
		report.Finalize()
		return report, fmt.Errorf("e2eorch: bridge-api health check: %w", err)
	}
	log.Printf("[run] bridge-api is healthy")

	// 2. Fetch bridge config and validate.
	log.Printf("[run] fetching bridge config")
	bridgeCfg, err := api.GetConfig(ctx)
	if err != nil {
		report.Error = fmt.Sprintf("fetch bridge config: %v", err)
		report.Finalize()
		return report, fmt.Errorf("e2eorch: get bridge config: %w", err)
	}

	if err := validateBridgeConfig(cfg, bridgeCfg); err != nil {
		report.Error = fmt.Sprintf("bridge config validation: %v", err)
		report.Finalize()
		return report, fmt.Errorf("e2eorch: validate bridge config: %w", err)
	}
	log.Printf("[run] bridge config validated: chainId=%d bridge=%s", bridgeCfg.BaseChainID, bridgeCfg.BridgeAddress)

	// 3. Connect to Base RPC and record pre-flow balances.
	log.Printf("[run] connecting to Base RPC at %s", cfg.BaseRPCURL)
	ethClient, err := ethclient.DialContext(ctx, cfg.BaseRPCURL)
	if err != nil {
		report.Error = fmt.Sprintf("connect to Base RPC: %v", err)
		report.Finalize()
		return report, fmt.Errorf("e2eorch: dial base rpc: %w", err)
	}
	defer ethClient.Close()

	log.Printf("[run] recording pre-flow balances")
	preBal, err := RecordBalances(ctx, ethClient, cfg)
	if err != nil {
		report.Error = fmt.Sprintf("record pre-flow balances: %v", err)
		report.Finalize()
		return report, fmt.Errorf("e2eorch: record pre balances: %w", err)
	}
	log.Printf("[run] pre-flow balances: recipient=%s feeDistributor=%s",
		preBal.Recipient, preBal.FeeDistributor)

	// 4. Run deposit flow.
	log.Printf("[run] starting deposit flow")
	depositResult, err := RunDeposit(ctx, cfg, api)
	if err != nil {
		report.Deposit = &DepositResult{
			Success: false,
			Error:   err.Error(),
		}
		report.Error = fmt.Sprintf("deposit flow: %v", err)
		report.Finalize()
		return report, fmt.Errorf("e2eorch: deposit flow: %w", err)
	}
	depositResult.DepositUsed = true // will be verified by invariants
	report.Deposit = depositResult
	log.Printf("[run] deposit flow completed: depositId=%s baseTxHash=%s duration=%s",
		depositResult.DepositID, depositResult.BaseTxHash, depositResult.TotalDuration)

	// 5. Run withdrawal flow.
	log.Printf("[run] starting withdrawal flow")
	withdrawResult, err := RunWithdraw(ctx, cfg, api)
	if err != nil {
		report.Withdrawal = &WithdrawalResult{
			Success: false,
			Error:   err.Error(),
		}
		report.Error = fmt.Sprintf("withdrawal flow: %v", err)
		report.Finalize()
		return report, fmt.Errorf("e2eorch: withdrawal flow: %w", err)
	}
	report.Withdrawal = withdrawResult
	log.Printf("[run] withdrawal flow completed: withdrawalId=%s junoTxId=%s baseTxHash=%s duration=%s",
		withdrawResult.WithdrawalID, withdrawResult.JunoTxID, withdrawResult.BaseTxHash, withdrawResult.TotalDuration)

	// 6. Run invariant checks.
	log.Printf("[run] running invariant checks")
	invariants := CheckInvariants(ctx, cfg, ethClient, depositResult, withdrawResult, preBal)
	report.Invariants = invariants

	allPassed := true
	for _, inv := range invariants {
		status := "PASS"
		if !inv.Passed {
			status = "FAIL"
			allPassed = false
		}
		log.Printf("[invariant] %s: %s - %s", status, inv.Name, inv.Details)
	}

	if !allPassed {
		report.Error = "one or more invariant checks failed"
	}

	// 7. Finalize report.
	report.Finalize()
	log.Printf("[run] e2e orchestrator completed success=%v duration=%s", report.Success, report.Duration)

	return report, nil
}

// validateBridgeConfig checks that the bridge-api config matches expectations.
func validateBridgeConfig(cfg E2EConfig, bc *BridgeConfigResponse) error {
	if uint64(bc.BaseChainID) != cfg.BaseChainID {
		return fmt.Errorf("chain id mismatch: bridge=%d expected=%d", bc.BaseChainID, cfg.BaseChainID)
	}

	if bc.MinDepositAmount != "" {
		minDep, err := strconv.ParseUint(bc.MinDepositAmount, 10, 64)
		if err == nil && cfg.DepositAmountZat < minDep {
			return fmt.Errorf("deposit amount %d below minimum %d", cfg.DepositAmountZat, minDep)
		}
	}

	if bc.MinWithdrawAmount != "" {
		minWith, err := strconv.ParseUint(bc.MinWithdrawAmount, 10, 64)
		if err == nil && cfg.WithdrawAmount < minWith {
			return fmt.Errorf("withdraw amount %d below minimum %d", cfg.WithdrawAmount, minWith)
		}
	}

	return nil
}
