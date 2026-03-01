package e2eorch

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"
)

// RunWithdraw executes the end-to-end withdrawal flow:
// 1. Request withdrawal via bridge-api
// 2. Poll until withdrawal is finalized
func RunWithdraw(ctx context.Context, cfg E2EConfig, api *BridgeAPIClient) (*WithdrawalResult, error) {
	result := &WithdrawalResult{}
	started := time.Now().UTC()

	// 1. Request withdrawal.
	log.Printf("[withdraw] requesting withdrawal amount=%d recipientRawHex=%s",
		cfg.WithdrawAmount, cfg.WithdrawRecipientRawHex)

	reqResp, err := api.RequestWithdrawal(ctx, WithdrawalRequestRequest{
		Amount:                 strconv.FormatUint(cfg.WithdrawAmount, 10),
		RecipientRawAddressHex: cfg.WithdrawRecipientRawHex,
	})
	if err != nil {
		return nil, fmt.Errorf("e2eorch: request withdrawal: %w", err)
	}
	if reqResp.WithdrawalID == "" {
		return nil, fmt.Errorf("e2eorch: withdrawal response missing withdrawalId")
	}

	now := time.Now().UTC()
	result.RequestedAt = &now
	result.WithdrawalID = reqResp.WithdrawalID
	result.Amount = strconv.FormatUint(cfg.WithdrawAmount, 10)
	result.FeeBps = reqResp.FeeBps

	log.Printf("[withdraw] withdrawal requested withdrawalId=%s feeBps=%d", reqResp.WithdrawalID, reqResp.FeeBps)

	// 2. Poll until finalized.
	log.Printf("[withdraw] polling withdrawal status withdrawalId=%s timeout=%s", reqResp.WithdrawalID, cfg.WithdrawTimeout)
	var finalStatus *WithdrawalStatusResponse
	err = PollUntil(ctx, cfg.WithdrawTimeout, cfg.PollInterval, func(ctx context.Context) (bool, string, error) {
		status, err := api.GetWithdrawalStatus(ctx, reqResp.WithdrawalID)
		if err != nil {
			return false, "error", fmt.Errorf("get withdrawal status: %w", err)
		}
		if !status.Found {
			return false, "not found", nil
		}

		// Track timing milestones based on state transitions.
		switch status.State {
		case "planned", "signing", "signed":
			if result.BatchedAt == nil {
				t := time.Now().UTC()
				result.BatchedAt = &t
			}
		case "broadcasted":
			if result.BroadcastedAt == nil {
				t := time.Now().UTC()
				result.BroadcastedAt = &t
			}
		case "confirmed":
			if result.ConfirmedAt == nil {
				t := time.Now().UTC()
				result.ConfirmedAt = &t
			}
		}

		if status.State == "finalized" {
			finalStatus = status
			return true, "finalized", nil
		}
		return false, status.State, nil
	})
	if err != nil {
		return nil, fmt.Errorf("e2eorch: poll withdrawal status: %w", err)
	}

	now = time.Now().UTC()
	result.FinalizedAt = &now
	result.Success = true
	result.FinalState = "finalized"
	result.TotalDuration = now.Sub(started).Round(time.Millisecond).String()

	if finalStatus != nil {
		result.JunoTxID = finalStatus.JunoTxID
		result.BaseTxHash = finalStatus.BaseTxHash
		result.BatchID = finalStatus.BatchID
	}

	return result, nil
}
