package withdraw

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestMemoryStore_UpsertRequested_DedupesAndRejectsMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })

	var id [32]byte
	id[0] = 0x01

	w := Withdrawal{
		ID:               id,
		Amount:           1000,
		FeeBps:           50,
		RecipientUA:      []byte{0x01},
		ProofWitnessItem: []byte{0x09, 0x08},
		Expiry:           now.Add(24 * time.Hour),
	}

	got, created, err := s.UpsertRequested(context.Background(), w)
	if err != nil {
		t.Fatalf("UpsertRequested #1: %v", err)
	}
	if !created {
		t.Fatalf("expected created=true")
	}
	if !withdrawalEqual(got, w) {
		t.Fatalf("unexpected withdrawal returned")
	}

	_, created, err = s.UpsertRequested(context.Background(), w)
	if err != nil {
		t.Fatalf("UpsertRequested #2: %v", err)
	}
	if created {
		t.Fatalf("expected created=false")
	}

	w2 := w
	w2.Amount = 2000
	_, _, err = s.UpsertRequested(context.Background(), w2)
	if !errors.Is(err, ErrWithdrawalMismatch) {
		t.Fatalf("expected ErrWithdrawalMismatch, got %v", err)
	}
}

func TestMemoryStore_GetWithdrawal_DefensiveCopy(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })

	id := seq32(0x01)
	w := Withdrawal{
		ID:               id,
		Amount:           1000,
		FeeBps:           0,
		RecipientUA:      []byte{0x01, 0x02, 0x03},
		ProofWitnessItem: []byte{0xaa, 0xbb, 0xcc},
		Expiry:           now.Add(24 * time.Hour),
	}
	_, _, err := s.UpsertRequested(context.Background(), w)
	if err != nil {
		t.Fatalf("UpsertRequested: %v", err)
	}

	got, err := s.GetWithdrawal(context.Background(), id)
	if err != nil {
		t.Fatalf("GetWithdrawal: %v", err)
	}
	if !withdrawalEqual(got, w) {
		t.Fatalf("unexpected withdrawal")
	}

	// Mutate returned slice and ensure store isn't affected.
	got.RecipientUA[0] ^= 0xff
	got.ProofWitnessItem[0] ^= 0xff
	got2, err := s.GetWithdrawal(context.Background(), id)
	if err != nil {
		t.Fatalf("GetWithdrawal #2: %v", err)
	}
	if !withdrawalEqual(got2, w) {
		t.Fatalf("expected store to be immutable to caller mutations")
	}
}

func TestMemoryStore_ClaimAndBatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	s := NewMemoryStore(nowFn)
	ctx := context.Background()

	w0 := Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	w1 := Withdrawal{ID: seq32(0x20), Amount: 2, FeeBps: 0, RecipientUA: []byte{0x02}, Expiry: now.Add(24 * time.Hour)}
	w2 := Withdrawal{ID: seq32(0x40), Amount: 3, FeeBps: 0, RecipientUA: []byte{0x03}, Expiry: now.Add(24 * time.Hour)}

	_, _, _ = s.UpsertRequested(ctx, w1)
	_, _, _ = s.UpsertRequested(ctx, w2)
	_, _, _ = s.UpsertRequested(ctx, w0)

	claimed, err := s.ClaimUnbatched(ctx, "a", 10*time.Second, 2)
	if err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}
	if len(claimed) != 2 || claimed[0].ID != w0.ID || claimed[1].ID != w1.ID {
		t.Fatalf("unexpected claimed set")
	}

	claimed2, err := s.ClaimUnbatched(ctx, "b", 10*time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimUnbatched by b: %v", err)
	}
	if len(claimed2) != 1 || claimed2[0].ID != w2.ID {
		t.Fatalf("expected b to claim only w2")
	}

	batchID := seq32(0x99)
	if err := s.CreatePlannedBatch(ctx, "a", Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w0.ID, w1.ID},
		State:         BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}

	// Batched withdrawals should not be claimable anymore.
	now = now.Add(1 * time.Hour)
	claimed3, err := s.ClaimUnbatched(ctx, "a", 10*time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimUnbatched after batch: %v", err)
	}
	if len(claimed3) != 1 || claimed3[0].ID != w2.ID {
		t.Fatalf("expected only w2 to remain")
	}
}

func TestMemoryStore_CreatePlannedBatch_AllowsExpiredClaimForSameOwner(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	s := NewMemoryStore(nowFn)
	ctx := context.Background()

	w := Withdrawal{
		ID:          seq32(0x70),
		Amount:      10,
		FeeBps:      25,
		RecipientUA: []byte{0x0a},
		Expiry:      now.Add(24 * time.Hour),
	}
	if _, _, err := s.UpsertRequested(ctx, w); err != nil {
		t.Fatalf("UpsertRequested: %v", err)
	}
	if _, err := s.ClaimUnbatched(ctx, "owner-a", 1*time.Second, 1); err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}

	now = now.Add(2 * time.Second)

	if err := s.CreatePlannedBatch(ctx, "owner-a", Batch{
		ID:            seq32(0x71),
		WithdrawalIDs: [][32]byte{w.ID},
		State:         BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch with expired own claim: %v", err)
	}
}

func TestMemoryStore_BatchStateMachine(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }
	s := NewMemoryStore(nowFn)

	ctx := context.Background()

	w := Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	_, _, _ = s.UpsertRequested(ctx, w)
	_, err := s.ClaimUnbatched(ctx, "a", 10*time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}

	batchID := seq32(0x10)
	if err := s.CreatePlannedBatch(ctx, "a", Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}

	if err := s.SetBatchSigned(ctx, batchID, []byte{0x01}); err == nil {
		t.Fatalf("expected error signing before marking signing")
	}

	if err := s.MarkBatchSigning(ctx, batchID); err != nil {
		t.Fatalf("MarkBatchSigning: %v", err)
	}
	if err := s.MarkBatchSigning(ctx, batchID); err != nil {
		t.Fatalf("MarkBatchSigning #2: %v", err)
	}

	if err := s.SetBatchSigned(ctx, batchID, []byte{0x01}); err != nil {
		t.Fatalf("SetBatchSigned: %v", err)
	}
	if err := s.SetBatchSigned(ctx, batchID, []byte{0x01}); err != nil {
		t.Fatalf("SetBatchSigned #2: %v", err)
	}
	if err := s.SetBatchSigned(ctx, batchID, []byte{0x02}); !errors.Is(err, ErrBatchMismatch) {
		t.Fatalf("expected ErrBatchMismatch, got %v", err)
	}

	if err := s.SetBatchBroadcasted(ctx, batchID, "tx1"); err != nil {
		t.Fatalf("SetBatchBroadcasted: %v", err)
	}
	backoffAt := now.Add(1 * time.Minute)
	if err := s.SetBatchRebroadcastBackoff(ctx, batchID, 1, backoffAt); err != nil {
		t.Fatalf("SetBatchRebroadcastBackoff: %v", err)
	}
	b0, err := s.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch after SetBatchRebroadcastBackoff: %v", err)
	}
	if b0.RebroadcastAttempts != 1 {
		t.Fatalf("rebroadcast attempts: got %d want 1", b0.RebroadcastAttempts)
	}
	if !b0.NextRebroadcastAt.Equal(backoffAt) {
		t.Fatalf("next rebroadcast at mismatch")
	}
	if err := s.SetBatchBroadcasted(ctx, batchID, "tx1"); err != nil {
		t.Fatalf("SetBatchBroadcasted #2: %v", err)
	}
	if err := s.SetBatchBroadcasted(ctx, batchID, "tx2"); !errors.Is(err, ErrBatchMismatch) {
		t.Fatalf("expected ErrBatchMismatch, got %v", err)
	}

	if err := s.ResetBatchPlanned(ctx, batchID, []byte(`{"v":2}`)); err != nil {
		t.Fatalf("ResetBatchPlanned: %v", err)
	}
	b, err := s.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch after reset: %v", err)
	}
	if b.State != BatchStatePlanned {
		t.Fatalf("state after reset: got %s want %s", b.State, BatchStatePlanned)
	}
	if len(b.SignedTx) != 0 || b.JunoTxID != "" {
		t.Fatalf("expected signed tx and txid to be cleared after reset")
	}
	if !b.NextRebroadcastAt.IsZero() {
		t.Fatalf("expected next rebroadcast at to clear on reset")
	}
	if err := s.MarkBatchSigning(ctx, batchID); err != nil {
		t.Fatalf("MarkBatchSigning after reset: %v", err)
	}
	if err := s.SetBatchSigned(ctx, batchID, []byte{0x01}); err != nil {
		t.Fatalf("SetBatchSigned after reset: %v", err)
	}
	if err := s.SetBatchBroadcasted(ctx, batchID, "tx3"); err != nil {
		t.Fatalf("SetBatchBroadcasted after reset: %v", err)
	}

	if err := s.SetBatchConfirmed(ctx, batchID); err != nil {
		t.Fatalf("SetBatchConfirmed: %v", err)
	}
	if err := s.SetBatchConfirmed(ctx, batchID); err != nil {
		t.Fatalf("SetBatchConfirmed #2: %v", err)
	}
	if err := s.MarkBatchFinalizing(ctx, batchID); err != nil {
		t.Fatalf("MarkBatchFinalizing: %v", err)
	}
	if err := s.MarkBatchFinalizing(ctx, batchID); err != nil {
		t.Fatalf("MarkBatchFinalizing #2: %v", err)
	}

	if err := s.SetBatchFinalized(ctx, batchID, "0xabc"); err != nil {
		t.Fatalf("SetBatchFinalized: %v", err)
	}
	if err := s.SetBatchFinalized(ctx, batchID, "0xabc"); err != nil {
		t.Fatalf("SetBatchFinalized #2: %v", err)
	}
	if err := s.SetBatchFinalized(ctx, batchID, "0xdef"); !errors.Is(err, ErrBatchMismatch) {
		t.Fatalf("expected ErrBatchMismatch, got %v", err)
	}
}
