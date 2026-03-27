package tsshost

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/memo"
	"github.com/juno-intents/intents-juno/internal/tss"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

func TestWithdrawBatchVerifier_RejectsTamperedTxPlanOutputs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 27, 10, 0, 0, 0, time.UTC)
	store := withdraw.NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	withdrawal := withdraw.Withdrawal{
		ID:          seq32(0x91),
		Requester:   [20]byte{0x01},
		Amount:      500_000_000,
		FeeBps:      50,
		RecipientUA: []byte("jtest1recipient000000000000000000000000000000000000000000000000000"),
		Expiry:      now.Add(24 * time.Hour),
	}
	if _, _, err := store.UpsertRequested(ctx, withdrawal); err != nil {
		t.Fatalf("UpsertRequested: %v", err)
	}
	if _, err := store.ClaimUnbatched(ctx, withdraw.Fence{Owner: "planner", LeaseVersion: 1}, time.Minute, 1); err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}

	batchID := seq32(0x92)
	bridgeAddress := common.HexToAddress("0x00000000000000000000000000000000000000b5")
	validPlan, err := marshalVerifierTxPlan(batchID, withdrawal, 8453, bridgeAddress)
	if err != nil {
		t.Fatalf("marshal valid plan: %v", err)
	}
	if err := store.CreatePlannedBatch(ctx, withdraw.Fence{Owner: "planner", LeaseVersion: 1}, withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{withdrawal.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        validPlan,
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}

	tamperedPlan, err := marshalVerifierTxPlan(batchID, withdrawal, 8453, bridgeAddress, func(plan map[string]any) {
		outputs := plan["outputs"].([]map[string]string)
		outputs[0]["to_address"] = "jtest1malicious0000000000000000000000000000000000000000000000000"
	})
	if err != nil {
		t.Fatalf("marshal tampered plan: %v", err)
	}

	verifier := NewWithdrawBatchVerifier(store, WithdrawBatchVerifierConfig{
		BaseChainID:  8453,
		BridgeAddress: bridgeAddress,
	})
	err = verifier.VerifySignRequest(ctx, tss.DeriveSigningSessionID(batchID, tamperedPlan), batchID, tamperedPlan)
	if err == nil {
		t.Fatalf("expected verifier rejection")
	}
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("expected ErrRejected, got %v", err)
	}
}

func TestWithdrawBatchVerifier_AllowsExpectedTxPlanOutputs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 27, 10, 0, 0, 0, time.UTC)
	store := withdraw.NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	withdrawal := withdraw.Withdrawal{
		ID:          seq32(0xa1),
		Requester:   [20]byte{0x02},
		Amount:      250_000_000,
		FeeBps:      100,
		RecipientUA: []byte("jtest1recipient111111111111111111111111111111111111111111111111111"),
		Expiry:      now.Add(24 * time.Hour),
	}
	if _, _, err := store.UpsertRequested(ctx, withdrawal); err != nil {
		t.Fatalf("UpsertRequested: %v", err)
	}
	if _, err := store.ClaimUnbatched(ctx, withdraw.Fence{Owner: "planner", LeaseVersion: 1}, time.Minute, 1); err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}

	batchID := seq32(0xa2)
	bridgeAddress := common.HexToAddress("0x00000000000000000000000000000000000000b6")
	plan, err := marshalVerifierTxPlan(batchID, withdrawal, 8453, bridgeAddress)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	if err := store.CreatePlannedBatch(ctx, withdraw.Fence{Owner: "planner", LeaseVersion: 1}, withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{withdrawal.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        plan,
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}

	verifier := NewWithdrawBatchVerifier(store, WithdrawBatchVerifierConfig{
		BaseChainID:  8453,
		BridgeAddress: bridgeAddress,
	})
	if err := verifier.VerifySignRequest(ctx, tss.DeriveSigningSessionID(batchID, plan), batchID, plan); err != nil {
		t.Fatalf("VerifySignRequest: %v", err)
	}
}

func marshalVerifierTxPlan(batchID [32]byte, withdrawal withdraw.Withdrawal, baseChainID uint32, bridgeAddress common.Address, mutate ...func(map[string]any)) ([]byte, error) {
	_, net, err := withdraw.ComputeFeeAndNet(withdrawal.Amount, withdrawal.FeeBps)
	if err != nil {
		return nil, err
	}
	var bridge20 [20]byte
	copy(bridge20[:], bridgeAddress[:])
	memoBytes := memo.WithdrawalMemoV1{
		BaseChainID:  baseChainID,
		BridgeAddr:   bridge20,
		WithdrawalID: withdrawal.ID,
		BatchID:      batchID,
	}.Encode()
	memoHex := hex.EncodeToString(memoBytes[:])
	outputs := []map[string]string{{
		"to_address": string(withdrawal.RecipientUA),
		"amount_zat": strconv.FormatUint(net, 10),
		"memo_hex":   memoHex,
	}}
	plan := map[string]any{
		"version":        "v0",
		"kind":           "withdrawal",
		"change_address": "jtest1change000000000000000000000000000000000000000000000000000000",
		"outputs":        outputs,
	}
	for _, fn := range mutate {
		fn(plan)
	}
	return json.Marshal(plan)
}
