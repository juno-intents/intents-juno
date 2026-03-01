package dlq

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MemoryStore is an in-memory implementation of Store for testing.
type MemoryStore struct {
	mu sync.Mutex

	nowFn func() time.Time

	proofs      map[[32]byte]ProofDLQRecord
	deposits    map[[32]byte]DepositBatchDLQRecord
	withdrawals map[[32]byte]WithdrawalBatchDLQRecord

	// insertOrder tracks insertion order for deterministic listing.
	proofOrder      [][32]byte
	depositOrder    [][32]byte
	withdrawalOrder [][32]byte
}

// NewMemoryStore creates a new in-memory DLQ store for testing.
func NewMemoryStore(nowFn func() time.Time) *MemoryStore {
	if nowFn == nil {
		nowFn = time.Now
	}
	return &MemoryStore{
		nowFn:       nowFn,
		proofs:      make(map[[32]byte]ProofDLQRecord),
		deposits:    make(map[[32]byte]DepositBatchDLQRecord),
		withdrawals: make(map[[32]byte]WithdrawalBatchDLQRecord),
	}
}

func (s *MemoryStore) EnsureSchema(_ context.Context) error {
	return nil
}

func (s *MemoryStore) InsertProofDLQ(_ context.Context, rec ProofDLQRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.proofs[rec.JobID]; exists {
		return nil // ON CONFLICT DO NOTHING
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = s.nowFn().UTC()
	}
	s.proofs[rec.JobID] = rec
	s.proofOrder = append(s.proofOrder, rec.JobID)
	return nil
}

func (s *MemoryStore) InsertDepositBatchDLQ(_ context.Context, rec DepositBatchDLQRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.deposits[rec.BatchID]; exists {
		return nil // ON CONFLICT DO NOTHING
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = s.nowFn().UTC()
	}
	s.deposits[rec.BatchID] = rec
	s.depositOrder = append(s.depositOrder, rec.BatchID)
	return nil
}

func (s *MemoryStore) InsertWithdrawalBatchDLQ(_ context.Context, rec WithdrawalBatchDLQRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.withdrawals[rec.BatchID]; exists {
		return nil // ON CONFLICT DO NOTHING
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = s.nowFn().UTC()
	}
	s.withdrawals[rec.BatchID] = rec
	s.withdrawalOrder = append(s.withdrawalOrder, rec.BatchID)
	return nil
}

func (s *MemoryStore) ListProofDLQ(_ context.Context, filter DLQFilter) ([]ProofDLQRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	var out []ProofDLQRecord
	for _, id := range s.proofOrder {
		rec := s.proofs[id]
		if !matchesProofFilter(rec, filter) {
			continue
		}
		out = append(out, rec)
	}

	// Apply offset and limit.
	if filter.Offset >= len(out) {
		return nil, nil
	}
	out = out[filter.Offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) ListDepositBatchDLQ(_ context.Context, filter DLQFilter) ([]DepositBatchDLQRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	var out []DepositBatchDLQRecord
	for _, id := range s.depositOrder {
		rec := s.deposits[id]
		if !matchesDepositFilter(rec, filter) {
			continue
		}
		out = append(out, rec)
	}

	if filter.Offset >= len(out) {
		return nil, nil
	}
	out = out[filter.Offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) ListWithdrawalBatchDLQ(_ context.Context, filter DLQFilter) ([]WithdrawalBatchDLQRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}

	var out []WithdrawalBatchDLQRecord
	for _, id := range s.withdrawalOrder {
		rec := s.withdrawals[id]
		if !matchesWithdrawalFilter(rec, filter) {
			continue
		}
		out = append(out, rec)
	}

	if filter.Offset >= len(out) {
		return nil, nil
	}
	out = out[filter.Offset:]
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *MemoryStore) CountUnacknowledged(_ context.Context) (DLQCounts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var counts DLQCounts
	for _, rec := range s.proofs {
		if !rec.Acknowledged {
			counts.Proofs++
		}
	}
	for _, rec := range s.deposits {
		if !rec.Acknowledged {
			counts.DepositBatches++
		}
	}
	for _, rec := range s.withdrawals {
		if !rec.Acknowledged {
			counts.WithdrawalBatches++
		}
	}
	return counts, nil
}

func (s *MemoryStore) Acknowledge(_ context.Context, table string, id []byte) error {
	if !ValidDLQTables[table] {
		return fmt.Errorf("%w: %q", ErrInvalidTable, table)
	}
	if len(id) != 32 {
		return fmt.Errorf("%w: id must be 32 bytes", ErrInvalidConfig)
	}

	var key [32]byte
	copy(key[:], id)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.nowFn().UTC()

	switch table {
	case "proof_dlq":
		rec, ok := s.proofs[key]
		if !ok || rec.Acknowledged {
			return ErrNotFound
		}
		rec.Acknowledged = true
		rec.AckAt = &now
		s.proofs[key] = rec
	case "deposit_batch_dlq":
		rec, ok := s.deposits[key]
		if !ok || rec.Acknowledged {
			return ErrNotFound
		}
		rec.Acknowledged = true
		rec.AckAt = &now
		s.deposits[key] = rec
	case "withdrawal_batch_dlq":
		rec, ok := s.withdrawals[key]
		if !ok || rec.Acknowledged {
			return ErrNotFound
		}
		rec.Acknowledged = true
		rec.AckAt = &now
		s.withdrawals[key] = rec
	}
	return nil
}

func matchesProofFilter(rec ProofDLQRecord, f DLQFilter) bool {
	if f.ErrorCode != "" && rec.ErrorCode != f.ErrorCode {
		return false
	}
	if f.Acknowledged != nil && rec.Acknowledged != *f.Acknowledged {
		return false
	}
	if !f.Since.IsZero() && rec.CreatedAt.Before(f.Since) {
		return false
	}
	return true
}

func matchesDepositFilter(rec DepositBatchDLQRecord, f DLQFilter) bool {
	if f.ErrorCode != "" && rec.ErrorCode != f.ErrorCode {
		return false
	}
	if f.FailureStage != "" && rec.FailureStage != f.FailureStage {
		return false
	}
	if f.Acknowledged != nil && rec.Acknowledged != *f.Acknowledged {
		return false
	}
	if !f.Since.IsZero() && rec.CreatedAt.Before(f.Since) {
		return false
	}
	return true
}

func matchesWithdrawalFilter(rec WithdrawalBatchDLQRecord, f DLQFilter) bool {
	if f.ErrorCode != "" && rec.ErrorCode != f.ErrorCode {
		return false
	}
	if f.FailureStage != "" && rec.FailureStage != f.FailureStage {
		return false
	}
	if f.Acknowledged != nil && rec.Acknowledged != *f.Acknowledged {
		return false
	}
	if !f.Since.IsZero() && rec.CreatedAt.Before(f.Since) {
		return false
	}
	return true
}

// Compile-time interface check.
var _ Store = (*MemoryStore)(nil)
