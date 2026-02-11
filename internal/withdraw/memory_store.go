package withdraw

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

type MemoryStore struct {
	mu  sync.Mutex
	now func() time.Time

	withdrawals map[[32]byte]withdrawalRec
	batches     map[[32]byte]Batch
}

type withdrawalRec struct {
	w Withdrawal

	claimedBy      string
	claimExpiresAt time.Time

	batchID [32]byte
}

func NewMemoryStore(now func() time.Time) *MemoryStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryStore{
		now:         now,
		withdrawals: make(map[[32]byte]withdrawalRec),
		batches:     make(map[[32]byte]Batch),
	}
}

func (s *MemoryStore) UpsertRequested(_ context.Context, w Withdrawal) (Withdrawal, bool, error) {
	if err := w.Validate(); err != nil {
		return Withdrawal{}, false, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.withdrawals[w.ID]
	if !ok {
		w.RecipientUA = append([]byte(nil), w.RecipientUA...)
		s.withdrawals[w.ID] = withdrawalRec{w: w}
		return w, true, nil
	}

	if !withdrawalEqual(rec.w, w) {
		return Withdrawal{}, false, ErrWithdrawalMismatch
	}
	return cloneWithdrawal(rec.w), false, nil
}

func (s *MemoryStore) ClaimUnbatched(_ context.Context, owner string, ttl time.Duration, max int) ([]Withdrawal, error) {
	if owner == "" || ttl <= 0 || max <= 0 {
		return nil, ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	ids := make([][32]byte, 0, len(s.withdrawals))
	for id, rec := range s.withdrawals {
		if rec.batchID != ([32]byte{}) {
			continue
		}
		// Skip actively claimed withdrawals.
		if rec.claimedBy != "" && rec.claimExpiresAt.After(now) {
			continue
		}
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })

	if len(ids) > max {
		ids = ids[:max]
	}

	out := make([]Withdrawal, 0, len(ids))
	for _, id := range ids {
		rec := s.withdrawals[id]
		rec.claimedBy = owner
		rec.claimExpiresAt = now.Add(ttl)
		s.withdrawals[id] = rec
		out = append(out, cloneWithdrawal(rec.w))
	}
	return out, nil
}

func (s *MemoryStore) CreatePlannedBatch(_ context.Context, owner string, b Batch) error {
	if owner == "" {
		return ErrInvalidConfig
	}
	if b.ID == ([32]byte{}) {
		return fmt.Errorf("%w: missing batch id", ErrInvalidConfig)
	}
	if b.State != BatchStatePlanned {
		return fmt.Errorf("%w: batch state must be planned", ErrInvalidConfig)
	}
	if len(b.WithdrawalIDs) == 0 {
		return fmt.Errorf("%w: empty withdrawal ids", ErrInvalidConfig)
	}
	if len(b.TxPlan) == 0 {
		return fmt.Errorf("%w: empty tx plan", ErrInvalidConfig)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	ids, err := sortedUnique32(b.WithdrawalIDs)
	if err != nil {
		return err
	}

	// Idempotency: if batch exists, require exact match.
	if existing, ok := s.batches[b.ID]; ok {
		if existing.State < BatchStatePlanned {
			return ErrInvalidTransition
		}
		if !batchEqual(existing, Batch{ID: b.ID, WithdrawalIDs: ids, State: BatchStatePlanned, TxPlan: b.TxPlan}) {
			return ErrBatchMismatch
		}
		return nil
	}

	// Ensure all withdrawals exist, are unbatched, and are claimed by owner.
	for _, id := range ids {
		rec, ok := s.withdrawals[id]
		if !ok {
			return ErrNotFound
		}
		if rec.batchID != ([32]byte{}) {
			return ErrInvalidTransition
		}
		if rec.claimedBy != owner {
			return ErrInvalidTransition
		}
		if !rec.claimExpiresAt.After(now) {
			return ErrInvalidTransition
		}
	}

	// Create the batch and assign withdrawals to it.
	nb := Batch{
		ID:            b.ID,
		WithdrawalIDs: ids,
		State:         BatchStatePlanned,
		TxPlan:        append([]byte(nil), b.TxPlan...),
	}
	s.batches[b.ID] = nb

	for _, id := range ids {
		rec := s.withdrawals[id]
		rec.batchID = b.ID
		rec.claimedBy = ""
		rec.claimExpiresAt = time.Time{}
		s.withdrawals[id] = rec
	}
	return nil
}

func (s *MemoryStore) GetWithdrawal(_ context.Context, id [32]byte) (Withdrawal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.withdrawals[id]
	if !ok {
		return Withdrawal{}, ErrNotFound
	}
	return cloneWithdrawal(rec.w), nil
}

func (s *MemoryStore) GetBatch(_ context.Context, batchID [32]byte) (Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return Batch{}, ErrNotFound
	}
	return cloneBatch(b), nil
}

func (s *MemoryStore) ListBatchesByState(_ context.Context, state BatchState) ([]Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Batch
	for _, b := range s.batches {
		if b.State == state {
			out = append(out, cloneBatch(b))
		}
	}
	slices.SortFunc(out, func(a, b Batch) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return out, nil
}

func (s *MemoryStore) MarkBatchSigning(_ context.Context, batchID [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}

	switch b.State {
	case BatchStatePlanned, BatchStateSigning:
		b.State = BatchStateSigning
		s.batches[batchID] = b
		return nil
	default:
		// Already progressed beyond signing.
		if b.State > BatchStateSigning {
			return nil
		}
		return ErrInvalidTransition
	}
}

func (s *MemoryStore) SetBatchSigned(_ context.Context, batchID [32]byte, signedTx []byte) error {
	if len(signedTx) == 0 {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}

	if b.State < BatchStateSigning {
		return ErrInvalidTransition
	}

	if b.State >= BatchStateSigned {
		if !bytes.Equal(b.SignedTx, signedTx) {
			return ErrBatchMismatch
		}
		return nil
	}

	b.State = BatchStateSigned
	b.SignedTx = append([]byte(nil), signedTx...)
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) SetBatchBroadcasted(_ context.Context, batchID [32]byte, txid string) error {
	if txid == "" {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}

	if b.State < BatchStateSigned {
		return ErrInvalidTransition
	}

	if b.State >= BatchStateBroadcasted {
		if b.JunoTxID != txid {
			return ErrBatchMismatch
		}
		return nil
	}

	b.State = BatchStateBroadcasted
	b.JunoTxID = txid
	b.NextRebroadcastAt = time.Time{}
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) ResetBatchPlanned(_ context.Context, batchID [32]byte, txPlan []byte) error {
	if len(txPlan) == 0 {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}
	if b.State != BatchStateBroadcasted {
		return ErrInvalidTransition
	}

	b.State = BatchStatePlanned
	b.TxPlan = append([]byte(nil), txPlan...)
	b.SignedTx = nil
	b.JunoTxID = ""
	b.NextRebroadcastAt = time.Time{}
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) SetBatchConfirmed(_ context.Context, batchID [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}

	if b.State < BatchStateBroadcasted {
		return ErrInvalidTransition
	}

	if b.State >= BatchStateConfirmed {
		return nil
	}

	b.State = BatchStateConfirmed
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) MarkBatchFinalizing(_ context.Context, batchID [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}
	if b.State < BatchStateConfirmed {
		return ErrInvalidTransition
	}
	if b.State >= BatchStateFinalizing {
		return nil
	}

	b.State = BatchStateFinalizing
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) SetBatchRebroadcastBackoff(_ context.Context, batchID [32]byte, attempts uint32, next time.Time) error {
	if next.IsZero() {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}
	if b.State != BatchStateBroadcasted {
		return ErrInvalidTransition
	}

	b.RebroadcastAttempts = attempts
	b.NextRebroadcastAt = next
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) SetBatchFinalized(_ context.Context, batchID [32]byte, baseTxHash string) error {
	if baseTxHash == "" {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}

	if b.State < BatchStateConfirmed {
		return ErrInvalidTransition
	}

	if b.State >= BatchStateFinalized {
		if b.BaseTxHash != baseTxHash {
			return ErrBatchMismatch
		}
		return nil
	}

	b.State = BatchStateFinalized
	b.BaseTxHash = baseTxHash
	s.batches[batchID] = b
	return nil
}

func cloneWithdrawal(w Withdrawal) Withdrawal {
	w.RecipientUA = append([]byte(nil), w.RecipientUA...)
	return w
}

func withdrawalEqual(a, b Withdrawal) bool {
	if a.ID != b.ID || a.Requester != b.Requester || a.Amount != b.Amount || a.FeeBps != b.FeeBps || !a.Expiry.Equal(b.Expiry) {
		return false
	}
	return bytes.Equal(a.RecipientUA, b.RecipientUA)
}

func sortedUnique32(in [][32]byte) ([][32]byte, error) {
	ids := make([][32]byte, len(in))
	copy(ids, in)
	slices.SortFunc(ids, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return nil, ErrDuplicateWithdrawalID
		}
	}
	return ids, nil
}

func cloneBatch(b Batch) Batch {
	b.WithdrawalIDs = append([][32]byte(nil), b.WithdrawalIDs...)
	b.TxPlan = append([]byte(nil), b.TxPlan...)
	b.SignedTx = append([]byte(nil), b.SignedTx...)
	return b
}

func batchEqual(a, b Batch) bool {
	if a.ID != b.ID || a.State != b.State || a.JunoTxID != b.JunoTxID || a.BaseTxHash != b.BaseTxHash {
		return false
	}
	if a.RebroadcastAttempts != b.RebroadcastAttempts {
		return false
	}
	if !a.NextRebroadcastAt.Equal(b.NextRebroadcastAt) {
		return false
	}
	if len(a.WithdrawalIDs) != len(b.WithdrawalIDs) {
		return false
	}
	for i := range a.WithdrawalIDs {
		if a.WithdrawalIDs[i] != b.WithdrawalIDs[i] {
			return false
		}
	}
	return bytes.Equal(a.TxPlan, b.TxPlan) && bytes.Equal(a.SignedTx, b.SignedTx)
}
