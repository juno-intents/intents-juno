package policy

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	// DefaultRefundWindow matches the v1 on-chain default (24 hours).
	DefaultRefundWindow = 24 * time.Hour

	// DefaultWithdrawExpirySafetyMargin is the minimum time-to-expiry required to broadcast a Juno payout tx.
	// The goal is to avoid "paid on Juno but refundable on Base" under expected disruptions.
	DefaultWithdrawExpirySafetyMargin = 6 * time.Hour

	// DefaultMaxExtendBatch mirrors Bridge.MAX_EXTEND_BATCH.
	DefaultMaxExtendBatch = 200
)

var (
	ErrInvalidConfig          = errors.New("policy: invalid config")
	ErrWithdrawalExpired      = errors.New("policy: withdrawal expired")
	ErrCannotExtendWithinBounds = errors.New("policy: cannot extend within bounds")
	ErrDuplicateWithdrawalID  = errors.New("policy: duplicate withdrawal id")
)

type WithdrawExpiryConfig struct {
	// SafetyMargin is the minimum duration required between now and a withdrawal's on-chain expiry.
	SafetyMargin time.Duration

	// MaxExtension is the per-call on-chain bound (Bridge.maxExpiryExtensionSeconds).
	MaxExtension time.Duration

	// MaxBatch is the per-tx bound on extendWithdrawExpiryBatch (Bridge.MAX_EXTEND_BATCH).
	MaxBatch int
}

type Withdrawal struct {
	ID     [32]byte
	Expiry time.Time
}

type ExtendPlan struct {
	IDs      [][32]byte // sorted ascending, unique
	NewExpiry time.Time
}

// IsSafeToBroadcastWithdrawal returns true iff the withdrawal's expiry is at least safetyMargin in the future.
func IsSafeToBroadcastWithdrawal(now time.Time, expiry time.Time, safetyMargin time.Duration) bool {
	if safetyMargin <= 0 {
		return false
	}
	return expiry.Sub(now) >= safetyMargin
}

// PlanExtendWithdrawExpiryBatches plans one or more extendWithdrawExpiryBatch calls to restore the configured
// safety margin for withdrawals that are too close to expiry.
//
// Policy:
// - If a withdrawal is already expired, return ErrWithdrawalExpired (it cannot be made safe via extension).
// - Extend to NewExpiry = ceil(now + SafetyMargin) (seconds resolution), if allowed by MaxExtension.
// - Output is deterministic: ids are sorted ascending and chunked into batches of <= MaxBatch.
func PlanExtendWithdrawExpiryBatches(now time.Time, withdrawals []Withdrawal, cfg WithdrawExpiryConfig) ([]ExtendPlan, error) {
	if cfg.SafetyMargin <= 0 || cfg.MaxExtension <= 0 || cfg.MaxBatch <= 0 {
		return nil, fmt.Errorf("%w: SafetyMargin/MaxExtension/MaxBatch must be > 0", ErrInvalidConfig)
	}

	var need []Withdrawal
	for _, w := range withdrawals {
		if !w.Expiry.After(now) {
			// Already refundable on-chain; extending won't help because Bridge skips expired withdrawals.
			return nil, ErrWithdrawalExpired
		}
		if w.Expiry.Sub(now) < cfg.SafetyMargin {
			need = append(need, w)
		}
	}
	if len(need) == 0 {
		return nil, nil
	}

	slices.SortFunc(need, func(a, b Withdrawal) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	for i := 1; i < len(need); i++ {
		if need[i].ID == need[i-1].ID {
			return nil, ErrDuplicateWithdrawalID
		}
	}

	newExpiry := ceilToSecond(now.Add(cfg.SafetyMargin))
	for _, w := range need {
		if newExpiry.Sub(w.Expiry) > cfg.MaxExtension {
			return nil, ErrCannotExtendWithinBounds
		}
	}

	plans := make([]ExtendPlan, 0, (len(need)+cfg.MaxBatch-1)/cfg.MaxBatch)
	for i := 0; i < len(need); i += cfg.MaxBatch {
		j := i + cfg.MaxBatch
		if j > len(need) {
			j = len(need)
		}
		ids := make([][32]byte, 0, j-i)
		for k := i; k < j; k++ {
			ids = append(ids, need[k].ID)
		}
		plans = append(plans, ExtendPlan{
			IDs:      ids,
			NewExpiry: newExpiry,
		})
	}
	return plans, nil
}

func ceilToSecond(t time.Time) time.Time {
	if t.Nanosecond() == 0 {
		return t
	}
	return t.Truncate(time.Second).Add(time.Second)
}

