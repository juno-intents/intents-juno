package policy

import (
	"errors"
	"testing"
	"time"
)

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func TestIsSafeToBroadcastWithdrawal_RespectsMargin(t *testing.T) {
	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	margin := 6 * time.Hour

	if !IsSafeToBroadcastWithdrawal(now, now.Add(margin), margin) {
		t.Fatalf("expected safe when expiry-now == margin")
	}
	if IsSafeToBroadcastWithdrawal(now, now.Add(margin-time.Second), margin) {
		t.Fatalf("expected unsafe when expiry-now < margin")
	}
	if IsSafeToBroadcastWithdrawal(now, now, margin) {
		t.Fatalf("expected unsafe when already expired")
	}
}

func TestPlanExtendWithdrawExpiryBatches_NoWorkWhenAllSafe(t *testing.T) {
	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	cfg := WithdrawExpiryConfig{
		SafetyMargin: 6 * time.Hour,
		MaxExtension: 12 * time.Hour,
		MaxBatch:     200,
	}

	plans, err := PlanExtendWithdrawExpiryBatches(now, []Withdrawal{
		{ID: seq32(0x00), Expiry: now.Add(7 * time.Hour)},
		{ID: seq32(0x20), Expiry: now.Add(10 * time.Hour)},
	}, cfg)
	if err != nil {
		t.Fatalf("PlanExtendWithdrawExpiryBatches: %v", err)
	}
	if len(plans) != 0 {
		t.Fatalf("expected no plans, got %d", len(plans))
	}
}

func TestPlanExtendWithdrawExpiryBatches_TargetIsNowPlusMarginAndSorted(t *testing.T) {
	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	cfg := WithdrawExpiryConfig{
		SafetyMargin: 6 * time.Hour,
		MaxExtension: 12 * time.Hour,
		MaxBatch:     200,
	}

	// Both need extension since expiry-now < 6h.
	w1 := Withdrawal{ID: seq32(0x20), Expiry: now.Add(5 * time.Hour)}
	w2 := Withdrawal{ID: seq32(0x00), Expiry: now.Add(1 * time.Hour)}

	plans, err := PlanExtendWithdrawExpiryBatches(now, []Withdrawal{w1, w2}, cfg)
	if err != nil {
		t.Fatalf("PlanExtendWithdrawExpiryBatches: %v", err)
	}
	if len(plans) != 1 {
		t.Fatalf("expected 1 plan, got %d", len(plans))
	}
	if !plans[0].NewExpiry.Equal(now.Add(6 * time.Hour)) {
		t.Fatalf("NewExpiry: got %v want %v", plans[0].NewExpiry, now.Add(6*time.Hour))
	}
	if len(plans[0].IDs) != 2 {
		t.Fatalf("IDs: got %d want 2", len(plans[0].IDs))
	}
	if plans[0].IDs[0] != w2.ID || plans[0].IDs[1] != w1.ID {
		t.Fatalf("IDs not sorted: %+v", plans[0].IDs)
	}
}

func TestPlanExtendWithdrawExpiryBatches_ErrOnExpiredWithdrawal(t *testing.T) {
	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	cfg := WithdrawExpiryConfig{
		SafetyMargin: 6 * time.Hour,
		MaxExtension: 12 * time.Hour,
		MaxBatch:     200,
	}

	_, err := PlanExtendWithdrawExpiryBatches(now, []Withdrawal{
		{ID: seq32(0x00), Expiry: now.Add(-1 * time.Second)},
	}, cfg)
	if !errors.Is(err, ErrWithdrawalExpired) {
		t.Fatalf("expected ErrWithdrawalExpired, got %v", err)
	}
}

func TestPlanExtendWithdrawExpiryBatches_ErrIfCannotExtendWithinBounds(t *testing.T) {
	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	cfg := WithdrawExpiryConfig{
		SafetyMargin: 6 * time.Hour,
		MaxExtension: 1 * time.Hour,
		MaxBatch:     200,
	}

	_, err := PlanExtendWithdrawExpiryBatches(now, []Withdrawal{
		{ID: seq32(0x00), Expiry: now.Add(10 * time.Minute)},
	}, cfg)
	if !errors.Is(err, ErrCannotExtendWithinBounds) {
		t.Fatalf("expected ErrCannotExtendWithinBounds, got %v", err)
	}
}

func TestPlanExtendWithdrawExpiryBatches_ChunksToMaxBatch(t *testing.T) {
	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	cfg := WithdrawExpiryConfig{
		SafetyMargin: 6 * time.Hour,
		MaxExtension: 12 * time.Hour,
		MaxBatch:     2,
	}

	withdrawals := []Withdrawal{
		{ID: seq32(0x40), Expiry: now.Add(1 * time.Hour)},
		{ID: seq32(0x00), Expiry: now.Add(1 * time.Hour)},
		{ID: seq32(0x20), Expiry: now.Add(1 * time.Hour)},
		{ID: seq32(0x60), Expiry: now.Add(1 * time.Hour)},
		{ID: seq32(0x80), Expiry: now.Add(1 * time.Hour)},
	}

	plans, err := PlanExtendWithdrawExpiryBatches(now, withdrawals, cfg)
	if err != nil {
		t.Fatalf("PlanExtendWithdrawExpiryBatches: %v", err)
	}
	if len(plans) != 3 {
		t.Fatalf("expected 3 plans, got %d", len(plans))
	}
	if len(plans[0].IDs) != 2 || len(plans[1].IDs) != 2 || len(plans[2].IDs) != 1 {
		t.Fatalf("unexpected chunk sizes: %d, %d, %d", len(plans[0].IDs), len(plans[1].IDs), len(plans[2].IDs))
	}
}

