package e2eorch

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"
	"time"
)

// RunDeposit executes the end-to-end deposit flow:
// 1. Get deposit memo from bridge-api
// 2. Send shielded Juno deposit
// 3. Extract deposit witness
// 4. Submit deposit to bridge-api
// 5. Poll until deposit is finalized
func RunDeposit(ctx context.Context, cfg E2EConfig, api *BridgeAPIClient) (*DepositResult, error) {
	result := &DepositResult{}
	started := time.Now().UTC()

	// 1. Get deposit memo.
	log.Printf("[deposit] getting deposit memo for recipient %s", cfg.RecipientAddress.Hex())
	memoResp, err := api.GetDepositMemo(ctx, cfg.RecipientAddress.Hex())
	if err != nil {
		return nil, fmt.Errorf("e2eorch: get deposit memo: %w", err)
	}
	if memoResp.MemoHex == "" {
		return nil, fmt.Errorf("e2eorch: deposit memo response missing memoHex")
	}
	nonce, err := strconv.ParseUint(memoResp.Nonce, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("e2eorch: parse nonce from memo response: %w", err)
	}

	now := time.Now().UTC()
	result.MemoFetchedAt = &now
	log.Printf("[deposit] memo obtained: memoHex=%s nonce=%d", memoResp.MemoHex, nonce)

	// 2. Send Juno deposit.
	log.Printf("[deposit] sending juno deposit from=%s to=%s amountZat=%d",
		cfg.JunoFunderSourceAddress, cfg.OWalletUA, cfg.DepositAmountZat)
	junoTxHash, err := SendJunoDeposit(ctx, cfg, memoResp.MemoHex)
	if err != nil {
		return nil, fmt.Errorf("e2eorch: send juno deposit: %w", err)
	}
	now = time.Now().UTC()
	result.JunoSentAt = &now
	log.Printf("[deposit] juno deposit sent txid=%s", junoTxHash)

	// 3. Extract witness.
	log.Printf("[deposit] extracting deposit witness txid=%s", junoTxHash)
	witnessItem, err := ExtractDepositWitness(ctx, cfg, junoTxHash)
	if err != nil {
		return nil, fmt.Errorf("e2eorch: extract witness: %w", err)
	}
	log.Printf("[deposit] witness extracted len=%d", len(witnessItem))

	// 4. Submit deposit to bridge-api.
	log.Printf("[deposit] submitting deposit to bridge-api")
	submitResp, err := api.SubmitDeposit(ctx, DepositSubmitRequest{
		BaseRecipient:    cfg.RecipientAddress.Hex(),
		Amount:           strconv.FormatUint(cfg.DepositAmountZat, 10),
		Nonce:            strconv.FormatUint(nonce, 10),
		ProofWitnessItem: hex.EncodeToString(witnessItem),
	})
	if err != nil {
		return nil, fmt.Errorf("e2eorch: submit deposit: %w", err)
	}
	if submitResp.DepositID == "" {
		return nil, fmt.Errorf("e2eorch: submit deposit response missing depositId")
	}
	now = time.Now().UTC()
	result.SubmittedAt = &now
	result.DepositID = submitResp.DepositID
	result.Amount = strconv.FormatUint(cfg.DepositAmountZat, 10)
	log.Printf("[deposit] deposit submitted depositId=%s", submitResp.DepositID)

	// 5. Poll until finalized.
	log.Printf("[deposit] polling deposit status depositId=%s timeout=%s", submitResp.DepositID, cfg.DepositTimeout)
	var finalStatus *DepositStatusResponse
	err = PollUntil(ctx, cfg.DepositTimeout, cfg.PollInterval, func(ctx context.Context) (bool, string, error) {
		status, err := api.GetDepositStatus(ctx, submitResp.DepositID)
		if err != nil {
			return false, "error", fmt.Errorf("get deposit status: %w", err)
		}
		if !status.Found {
			return false, "not found", nil
		}
		if status.State == "finalized" {
			finalStatus = status
			return true, "finalized", nil
		}
		return false, status.State, nil
	})
	if err != nil {
		return nil, fmt.Errorf("e2eorch: poll deposit status: %w", err)
	}

	now = time.Now().UTC()
	result.FinalizedAt = &now
	result.Success = true
	result.FinalState = "finalized"
	result.TotalDuration = now.Sub(started).Round(time.Millisecond).String()

	if finalStatus != nil {
		result.BaseTxHash = finalStatus.TxHash
	}

	return result, nil
}
