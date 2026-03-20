package withdrawcoordinator

import (
	"context"
	"time"

	"github.com/juno-intents/intents-juno/internal/withdraw"
)

type MetricsSummary struct {
	DLQDepth               int
	ConfirmedUnmarkedCount int
	MinTimeToExpiry        time.Duration
	HasConfirmedUnmarked   bool
	MarkPaidCircuitOpen    bool
	StaleBatchBacklogCount  int
	OldestStaleBatchAge     time.Duration
	HasStaleBacklog        bool
}

func (c *Coordinator) MetricsSummary(ctx context.Context) (MetricsSummary, error) {
	summary := MetricsSummary{}
	if c == nil {
		return summary, ErrInvalidConfig
	}
	summary.MarkPaidCircuitOpen = c.markPaidCircuitOpen

	dlqDepth, err := c.store.CountDLQBatches(ctx)
	if err != nil {
		return summary, err
	}
	summary.DLQDepth = dlqDepth

	now := c.cfg.Now().UTC()
	var minExpiry time.Time
	for _, state := range []withdraw.BatchState{withdraw.BatchStateBroadcasted, withdraw.BatchStateJunoConfirmed} {
		batches, err := c.store.ListBatchesByState(ctx, state)
		if err != nil {
			return summary, err
		}
		for _, b := range batches {
			if !isJunoConfirmedUnrecorded(b) {
				continue
			}
			summary.ConfirmedUnmarkedCount += len(b.WithdrawalIDs)
			for _, withdrawalID := range b.WithdrawalIDs {
				w, err := c.store.GetWithdrawal(ctx, withdrawalID)
				if err != nil {
					return summary, err
				}
				if !summary.HasConfirmedUnmarked || w.Expiry.Before(minExpiry) {
					minExpiry = w.Expiry
					summary.HasConfirmedUnmarked = true
				}
			}
		}
	}
	if summary.HasConfirmedUnmarked {
		if minExpiry.After(now) {
			summary.MinTimeToExpiry = minExpiry.Sub(now)
		}
	}

	staleCutoff := now.Add(-c.cfg.MaxAge)
	staleStates := []withdraw.BatchState{
		withdraw.BatchStatePlanned,
		withdraw.BatchStateSigning,
		withdraw.BatchStateSigned,
		withdraw.BatchStateBroadcasted,
		withdraw.BatchStateJunoConfirmed,
		withdraw.BatchStateConfirmed,
		withdraw.BatchStateFinalizing,
	}
	staleBatches, err := c.store.ListBatchesByStatesOlderThan(ctx, staleStates, staleCutoff, int(^uint(0)>>1))
	if err != nil {
		return summary, err
	}
	summary.StaleBatchBacklogCount = len(staleBatches)
	for _, b := range staleBatches {
		age := now.Sub(b.UpdatedAt)
		if !summary.HasStaleBacklog || age > summary.OldestStaleBatchAge {
			summary.OldestStaleBatchAge = age
			summary.HasStaleBacklog = true
		}
	}
	return summary, nil
}

func (c *Coordinator) MarkPaidCircuitOpen() bool {
	if c == nil {
		return false
	}
	return c.markPaidCircuitOpen
}
