package withdrawcoordinator

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/batching"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

func TestCoordinatorMetricsSummaryReportsDLQAndConfirmedUnmarked(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	store := withdraw.NewMemoryStore(nowFn)
	fence := withdraw.Fence{Owner: "coordinator-a", LeaseVersion: 1}

	withdrawals := []withdraw.Withdrawal{
		{ID: seq32(0x10), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(45 * time.Minute)},
		{ID: seq32(0x20), Amount: 2, FeeBps: 0, RecipientUA: []byte{0x02}, Expiry: now.Add(30 * time.Minute)},
		{ID: seq32(0x30), Amount: 3, FeeBps: 0, RecipientUA: []byte{0x03}, Expiry: now.Add(2 * time.Hour)},
	}
	for _, w := range withdrawals {
		if _, created, err := store.UpsertRequested(ctx, w); err != nil || !created {
			t.Fatalf("UpsertRequested(%x): created=%v err=%v", w.ID[:4], created, err)
		}
	}

	claimed, err := store.ClaimUnbatched(ctx, fence, time.Minute, 2)
	if err != nil {
		t.Fatalf("ClaimUnbatched confirmed-unmarked: %v", err)
	}
	if len(claimed) != 2 {
		t.Fatalf("claimed len = %d, want 2", len(claimed))
	}
	confirmedBatchID := batching.WithdrawalBatchIDV1([][32]byte{claimed[0].ID, claimed[1].ID})
	if err := store.CreatePlannedBatch(ctx, fence, withdraw.Batch{
		ID:            confirmedBatchID,
		WithdrawalIDs: [][32]byte{claimed[0].ID, claimed[1].ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch confirmed-unmarked: %v", err)
	}
	if err := store.MarkBatchSigning(ctx, confirmedBatchID, fence); err != nil {
		t.Fatalf("MarkBatchSigning: %v", err)
	}
	if err := store.SetBatchSigned(ctx, confirmedBatchID, fence, []byte{0x01}); err != nil {
		t.Fatalf("SetBatchSigned: %v", err)
	}
	if err := store.MarkBatchBroadcastLocked(ctx, confirmedBatchID, fence); err != nil {
		t.Fatalf("MarkBatchBroadcastLocked: %v", err)
	}
	if err := store.SetBatchBroadcasted(ctx, confirmedBatchID, fence, "tx-confirmed"); err != nil {
		t.Fatalf("SetBatchBroadcasted: %v", err)
	}
	if err := store.MarkBatchJunoConfirmed(ctx, confirmedBatchID, fence); err != nil {
		t.Fatalf("MarkBatchJunoConfirmed: %v", err)
	}

	dlqClaimed, err := store.ClaimUnbatched(ctx, fence, time.Minute, 1)
	if err != nil {
		t.Fatalf("ClaimUnbatched dlq: %v", err)
	}
	if len(dlqClaimed) != 1 {
		t.Fatalf("dlq claimed len = %d, want 1", len(dlqClaimed))
	}
	dlqBatchID := batching.WithdrawalBatchIDV1([][32]byte{dlqClaimed[0].ID})
	if err := store.CreatePlannedBatch(ctx, fence, withdraw.Batch{
		ID:            dlqBatchID,
		WithdrawalIDs: [][32]byte{dlqClaimed[0].ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":2}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch dlq: %v", err)
	}
	if err := store.MarkBatchDLQ(ctx, dlqBatchID, fence); err != nil {
		t.Fatalf("MarkBatchDLQ: %v", err)
	}

	coord, err := New(Config{
		Owner:    fence.Owner,
		MaxItems: 10,
		MaxAge:   time.Minute,
		ClaimTTL: time.Minute,
		Now:      nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, &stubBroadcaster{}, &stubConfirmer{}, &stubTxChecker{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord.markPaidCircuitOpen = true

	summary, err := coord.MetricsSummary(ctx)
	if err != nil {
		t.Fatalf("MetricsSummary: %v", err)
	}
	if summary.DLQDepth != 1 {
		t.Fatalf("DLQDepth = %d, want 1", summary.DLQDepth)
	}
	if summary.ConfirmedUnmarkedCount != 2 {
		t.Fatalf("ConfirmedUnmarkedCount = %d, want 2", summary.ConfirmedUnmarkedCount)
	}
	if !summary.HasConfirmedUnmarked {
		t.Fatalf("HasConfirmedUnmarked = false, want true")
	}
	if summary.MinTimeToExpiry != 30*time.Minute {
		t.Fatalf("MinTimeToExpiry = %s, want %s", summary.MinTimeToExpiry, 30*time.Minute)
	}
	if !summary.MarkPaidCircuitOpen {
		t.Fatalf("MarkPaidCircuitOpen = false, want true")
	}
	if !coord.MarkPaidCircuitOpen() {
		t.Fatalf("MarkPaidCircuitOpen accessor = false, want true")
	}
}

func TestCoordinatorMetricsSummaryReportsStaleBatchBacklog(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 3, 18, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	store := withdraw.NewMemoryStore(nowFn)
	fence := withdraw.Fence{Owner: "coordinator-a", LeaseVersion: 1}

	makeSignedBatch := func(seed byte) [32]byte {
		wid := seq32(seed)
		w := withdraw.Withdrawal{ID: wid, Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(45 * time.Minute)}
		if _, created, err := store.UpsertRequested(ctx, w); err != nil || !created {
			t.Fatalf("UpsertRequested(%x): created=%v err=%v", wid[:1], created, err)
		}
		if _, err := store.ClaimUnbatched(ctx, fence, time.Minute, 1); err != nil {
			t.Fatalf("ClaimUnbatched(%x): %v", wid[:1], err)
		}
		batchID := batching.WithdrawalBatchIDV1([][32]byte{wid})
		if err := store.CreatePlannedBatch(ctx, fence, withdraw.Batch{
			ID:            batchID,
			WithdrawalIDs: [][32]byte{wid},
			State:         withdraw.BatchStatePlanned,
			TxPlan:        []byte(`{"v":1}`),
		}); err != nil {
			t.Fatalf("CreatePlannedBatch(%x): %v", wid[:1], err)
		}
		if err := store.MarkBatchSigning(ctx, batchID, fence); err != nil {
			t.Fatalf("MarkBatchSigning(%x): %v", wid[:1], err)
		}
		if err := store.SetBatchSigned(ctx, batchID, fence, []byte{0x01}); err != nil {
			t.Fatalf("SetBatchSigned(%x): %v", wid[:1], err)
		}
		return batchID
	}

	staleBatchID := makeSignedBatch(0x10)
	now = now.Add(20 * time.Minute)
	freshBatchID := makeSignedBatch(0x20)
	now = now.Add(10 * time.Minute)

	coord, err := New(Config{
		Owner:    fence.Owner,
		MaxItems: 10,
		MaxAge:   15 * time.Minute,
		ClaimTTL: time.Minute,
		Now:      nowFn,
	}, store, &stubPlanner{}, &stubSigner{}, &stubBroadcaster{}, &stubConfirmer{}, &stubTxChecker{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	coord.markPaidCircuitOpen = true

	summary, err := coord.MetricsSummary(ctx)
	if err != nil {
		t.Fatalf("MetricsSummary: %v", err)
	}
	if summary.StaleBatchBacklogCount != 1 {
		t.Fatalf("StaleBatchBacklogCount = %d, want 1", summary.StaleBatchBacklogCount)
	}
	if !summary.HasStaleBacklog {
		t.Fatalf("HasStaleBacklog = false, want true")
	}
	if summary.OldestStaleBatchAge != 30*time.Minute {
		t.Fatalf("OldestStaleBatchAge = %s, want %s", summary.OldestStaleBatchAge, 30*time.Minute)
	}
	if summary.StaleBatchBacklogCount == 0 || staleBatchID == freshBatchID {
		t.Fatalf("unexpected test setup")
	}
}
