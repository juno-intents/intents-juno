package dlq

import (
	"context"
	"testing"
	"time"
)

func seq32(start byte) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func boolPtr(v bool) *bool { return &v }

func TestInsertProofDLQ_IdempotentAndListable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	rec := ProofDLQRecord{
		JobID:        seq32(0x01),
		Pipeline:     "deposit",
		ImageID:      seq32(0xaa),
		State:        5,
		ErrorCode:    "sp1_invalid_input",
		ErrorMessage: "bad witness",
		AttemptCount: 3,
		JobPayload:   []byte(`{"test":true}`),
	}

	if err := s.InsertProofDLQ(ctx, rec); err != nil {
		t.Fatalf("InsertProofDLQ #1: %v", err)
	}

	// Idempotent: second insert should not error.
	if err := s.InsertProofDLQ(ctx, rec); err != nil {
		t.Fatalf("InsertProofDLQ #2 (idempotent): %v", err)
	}

	recs, err := s.ListProofDLQ(ctx, DLQFilter{})
	if err != nil {
		t.Fatalf("ListProofDLQ: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].Pipeline != "deposit" {
		t.Fatalf("pipeline: got %q want %q", recs[0].Pipeline, "deposit")
	}
	if recs[0].ErrorCode != "sp1_invalid_input" {
		t.Fatalf("error_code: got %q want %q", recs[0].ErrorCode, "sp1_invalid_input")
	}
	if recs[0].Acknowledged {
		t.Fatalf("expected acknowledged=false")
	}
}

func TestInsertDepositBatchDLQ_IdempotentAndListable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	rec := DepositBatchDLQRecord{
		BatchID:      seq32(0x10),
		DepositIDs:   [][32]byte{seq32(0x20), seq32(0x30)},
		ItemsCount:   2,
		State:        3,
		FailureStage: "proof",
		ErrorCode:    "proof_timeout",
		ErrorMessage: "proof request timed out",
		AttemptCount: 3,
	}

	if err := s.InsertDepositBatchDLQ(ctx, rec); err != nil {
		t.Fatalf("InsertDepositBatchDLQ #1: %v", err)
	}

	// Idempotent.
	if err := s.InsertDepositBatchDLQ(ctx, rec); err != nil {
		t.Fatalf("InsertDepositBatchDLQ #2 (idempotent): %v", err)
	}

	recs, err := s.ListDepositBatchDLQ(ctx, DLQFilter{})
	if err != nil {
		t.Fatalf("ListDepositBatchDLQ: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].FailureStage != "proof" {
		t.Fatalf("failure_stage: got %q want %q", recs[0].FailureStage, "proof")
	}
	if recs[0].ItemsCount != 2 {
		t.Fatalf("items_count: got %d want %d", recs[0].ItemsCount, 2)
	}
	if len(recs[0].DepositIDs) != 2 {
		t.Fatalf("deposit_ids len: got %d want %d", len(recs[0].DepositIDs), 2)
	}
}

func TestInsertWithdrawalBatchDLQ_IdempotentAndListable(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	rec := WithdrawalBatchDLQRecord{
		BatchID:             seq32(0x40),
		WithdrawalIDs:       [][32]byte{seq32(0x50)},
		ItemsCount:          1,
		State:               4,
		FailureStage:        "confirm",
		ErrorCode:           "rebroadcast_exhausted",
		ErrorMessage:        "max rebroadcast attempts exceeded",
		RebroadcastAttempts: 5,
		JunoTxID:            "tx-abc123",
	}

	if err := s.InsertWithdrawalBatchDLQ(ctx, rec); err != nil {
		t.Fatalf("InsertWithdrawalBatchDLQ #1: %v", err)
	}

	// Idempotent.
	if err := s.InsertWithdrawalBatchDLQ(ctx, rec); err != nil {
		t.Fatalf("InsertWithdrawalBatchDLQ #2 (idempotent): %v", err)
	}

	recs, err := s.ListWithdrawalBatchDLQ(ctx, DLQFilter{})
	if err != nil {
		t.Fatalf("ListWithdrawalBatchDLQ: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].FailureStage != "confirm" {
		t.Fatalf("failure_stage: got %q want %q", recs[0].FailureStage, "confirm")
	}
	if recs[0].JunoTxID != "tx-abc123" {
		t.Fatalf("juno_tx_id: got %q want %q", recs[0].JunoTxID, "tx-abc123")
	}
	if recs[0].RebroadcastAttempts != 5 {
		t.Fatalf("rebroadcast_attempts: got %d want %d", recs[0].RebroadcastAttempts, 5)
	}
}

func TestCountUnacknowledged(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	// Insert one of each type.
	_ = s.InsertProofDLQ(ctx, ProofDLQRecord{
		JobID:     seq32(0x01),
		Pipeline:  "deposit",
		ImageID:   seq32(0xaa),
		State:     5,
		ErrorCode: "err",
	})
	_ = s.InsertDepositBatchDLQ(ctx, DepositBatchDLQRecord{
		BatchID:      seq32(0x10),
		DepositIDs:   [][32]byte{seq32(0x20)},
		ItemsCount:   1,
		State:        3,
		FailureStage: "proof",
	})
	_ = s.InsertWithdrawalBatchDLQ(ctx, WithdrawalBatchDLQRecord{
		BatchID:       seq32(0x40),
		WithdrawalIDs: [][32]byte{seq32(0x50)},
		ItemsCount:    1,
		State:         4,
		FailureStage:  "confirm",
	})

	counts, err := s.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if counts.Proofs != 1 {
		t.Fatalf("proofs: got %d want 1", counts.Proofs)
	}
	if counts.DepositBatches != 1 {
		t.Fatalf("deposit_batches: got %d want 1", counts.DepositBatches)
	}
	if counts.WithdrawalBatches != 1 {
		t.Fatalf("withdrawal_batches: got %d want 1", counts.WithdrawalBatches)
	}
}

func TestAcknowledge_ReducesUnacknowledgedCount(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	jobID := seq32(0x01)
	_ = s.InsertProofDLQ(ctx, ProofDLQRecord{
		JobID:     jobID,
		Pipeline:  "deposit",
		ImageID:   seq32(0xaa),
		State:     5,
		ErrorCode: "err",
	})

	if err := s.Acknowledge(ctx, "proof_dlq", jobID[:]); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}

	counts, err := s.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if counts.Proofs != 0 {
		t.Fatalf("expected 0 unacknowledged proofs, got %d", counts.Proofs)
	}

	// Acknowledging again should return ErrNotFound.
	if err := s.Acknowledge(ctx, "proof_dlq", jobID[:]); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound on re-ack, got %v", err)
	}
}

func TestAcknowledge_InvalidTable(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore(nil)
	ctx := context.Background()

	if err := s.Acknowledge(ctx, "bad_table", make([]byte, 32)); err == nil {
		t.Fatalf("expected error for invalid table")
	}
}

func TestAcknowledge_InvalidIDLength(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore(nil)
	ctx := context.Background()

	if err := s.Acknowledge(ctx, "proof_dlq", make([]byte, 16)); err == nil {
		t.Fatalf("expected error for invalid id length")
	}
}

func TestListProofDLQ_FilterByErrorCode(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	_ = s.InsertProofDLQ(ctx, ProofDLQRecord{
		JobID: seq32(0x01), Pipeline: "deposit", ImageID: seq32(0xaa),
		State: 5, ErrorCode: "sp1_timeout",
	})
	_ = s.InsertProofDLQ(ctx, ProofDLQRecord{
		JobID: seq32(0x02), Pipeline: "withdraw", ImageID: seq32(0xbb),
		State: 5, ErrorCode: "sp1_invalid_input",
	})

	recs, err := s.ListProofDLQ(ctx, DLQFilter{ErrorCode: "sp1_timeout"})
	if err != nil {
		t.Fatalf("ListProofDLQ with filter: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 filtered record, got %d", len(recs))
	}
	if recs[0].ErrorCode != "sp1_timeout" {
		t.Fatalf("error_code: got %q", recs[0].ErrorCode)
	}
}

func TestListDepositBatchDLQ_FilterByFailureStage(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	_ = s.InsertDepositBatchDLQ(ctx, DepositBatchDLQRecord{
		BatchID: seq32(0x10), DepositIDs: [][32]byte{seq32(0x20)},
		ItemsCount: 1, State: 3, FailureStage: "proof",
	})
	_ = s.InsertDepositBatchDLQ(ctx, DepositBatchDLQRecord{
		BatchID: seq32(0x11), DepositIDs: [][32]byte{seq32(0x21)},
		ItemsCount: 1, State: 3, FailureStage: "bridge_tx",
	})

	recs, err := s.ListDepositBatchDLQ(ctx, DLQFilter{FailureStage: "bridge_tx"})
	if err != nil {
		t.Fatalf("ListDepositBatchDLQ with filter: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 filtered record, got %d", len(recs))
	}
	if recs[0].FailureStage != "bridge_tx" {
		t.Fatalf("failure_stage: got %q", recs[0].FailureStage)
	}
}

func TestListProofDLQ_FilterByAcknowledged(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	_ = s.InsertProofDLQ(ctx, ProofDLQRecord{
		JobID: seq32(0x01), Pipeline: "deposit", ImageID: seq32(0xaa),
		State: 5, ErrorCode: "err",
	})
	_ = s.InsertProofDLQ(ctx, ProofDLQRecord{
		JobID: seq32(0x02), Pipeline: "withdraw", ImageID: seq32(0xbb),
		State: 5, ErrorCode: "err2",
	})

	ackID := seq32(0x01)
	_ = s.Acknowledge(ctx, "proof_dlq", ackID[:])

	// List unacknowledged only.
	recs, err := s.ListProofDLQ(ctx, DLQFilter{Acknowledged: boolPtr(false)})
	if err != nil {
		t.Fatalf("ListProofDLQ acknowledged=false: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 unacknowledged record, got %d", len(recs))
	}
	if recs[0].JobID != seq32(0x02) {
		t.Fatalf("expected job 0x02 to be unacknowledged")
	}

	// List acknowledged only.
	recs, err = s.ListProofDLQ(ctx, DLQFilter{Acknowledged: boolPtr(true)})
	if err != nil {
		t.Fatalf("ListProofDLQ acknowledged=true: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 acknowledged record, got %d", len(recs))
	}
	if recs[0].JobID != seq32(0x01) {
		t.Fatalf("expected job 0x01 to be acknowledged")
	}
}

func TestListProofDLQ_LimitAndOffset(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	for i := byte(0); i < 5; i++ {
		_ = s.InsertProofDLQ(ctx, ProofDLQRecord{
			JobID: seq32(i), Pipeline: "deposit", ImageID: seq32(0xaa),
			State: 5, ErrorCode: "err",
		})
	}

	recs, err := s.ListProofDLQ(ctx, DLQFilter{Limit: 2})
	if err != nil {
		t.Fatalf("ListProofDLQ limit=2: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}

	recs, err = s.ListProofDLQ(ctx, DLQFilter{Limit: 2, Offset: 3})
	if err != nil {
		t.Fatalf("ListProofDLQ offset=3: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records from offset 3, got %d", len(recs))
	}
}

func TestListProofDLQ_FilterBySince(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	_ = s.InsertProofDLQ(ctx, ProofDLQRecord{
		JobID: seq32(0x01), Pipeline: "deposit", ImageID: seq32(0xaa),
		State: 5, ErrorCode: "err", CreatedAt: now.Add(-1 * time.Hour),
	})
	_ = s.InsertProofDLQ(ctx, ProofDLQRecord{
		JobID: seq32(0x02), Pipeline: "deposit", ImageID: seq32(0xbb),
		State: 5, ErrorCode: "err", CreatedAt: now.Add(1 * time.Hour),
	})

	recs, err := s.ListProofDLQ(ctx, DLQFilter{Since: now})
	if err != nil {
		t.Fatalf("ListProofDLQ since: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("expected 1 record since now, got %d", len(recs))
	}
	if recs[0].JobID != seq32(0x02) {
		t.Fatalf("expected recent record")
	}
}

func TestAcknowledge_DepositBatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	batchID := seq32(0x10)
	_ = s.InsertDepositBatchDLQ(ctx, DepositBatchDLQRecord{
		BatchID: batchID, DepositIDs: [][32]byte{seq32(0x20)},
		ItemsCount: 1, State: 3, FailureStage: "proof",
	})

	if err := s.Acknowledge(ctx, "deposit_batch_dlq", batchID[:]); err != nil {
		t.Fatalf("Acknowledge deposit_batch_dlq: %v", err)
	}

	counts, err := s.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if counts.DepositBatches != 0 {
		t.Fatalf("expected 0 unacknowledged deposit batches, got %d", counts.DepositBatches)
	}
}

func TestAcknowledge_WithdrawalBatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	s := NewMemoryStore(func() time.Time { return now })
	ctx := context.Background()

	batchID := seq32(0x40)
	_ = s.InsertWithdrawalBatchDLQ(ctx, WithdrawalBatchDLQRecord{
		BatchID: batchID, WithdrawalIDs: [][32]byte{seq32(0x50)},
		ItemsCount: 1, State: 4, FailureStage: "signing",
	})

	if err := s.Acknowledge(ctx, "withdrawal_batch_dlq", batchID[:]); err != nil {
		t.Fatalf("Acknowledge withdrawal_batch_dlq: %v", err)
	}

	counts, err := s.CountUnacknowledged(ctx)
	if err != nil {
		t.Fatalf("CountUnacknowledged: %v", err)
	}
	if counts.WithdrawalBatches != 0 {
		t.Fatalf("expected 0 unacknowledged withdrawal batches, got %d", counts.WithdrawalBatches)
	}
}

func TestAcknowledge_NonExistentRecord(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore(nil)
	ctx := context.Background()

	nonExistent := seq32(0xff)
	if err := s.Acknowledge(ctx, "proof_dlq", nonExistent[:]); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}
