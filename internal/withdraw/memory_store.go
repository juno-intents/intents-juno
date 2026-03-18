package withdraw

import (
	"bytes"
	"context"
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
	w      Withdrawal
	status WithdrawalStatus

	claimedBy        string
	claimLeaseVersion int64
	claimExpiresAt   time.Time

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
		s.withdrawals[w.ID] = withdrawalRec{w: w, status: WithdrawalStatusRequested}
		return w, true, nil
	}

	if !withdrawalEqual(rec.w, w) {
		return Withdrawal{}, false, ErrWithdrawalMismatch
	}
	return cloneWithdrawal(rec.w), false, nil
}

func (s *MemoryStore) ClaimUnbatched(_ context.Context, fence Fence, ttl time.Duration, max int) ([]Withdrawal, error) {
	if err := fence.Validate(); err != nil {
		return nil, err
	}
	if ttl <= 0 || max <= 0 {
		return nil, ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now().UTC()

	ids := make([][32]byte, 0, len(s.withdrawals))
	for id, rec := range s.withdrawals {
		if rec.batchID != ([32]byte{}) || rec.status != WithdrawalStatusRequested {
			continue
		}
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
		rec.claimedBy = fence.Owner
		rec.claimLeaseVersion = fence.LeaseVersion
		rec.claimExpiresAt = now.Add(ttl)
		s.withdrawals[id] = rec
		out = append(out, cloneWithdrawal(rec.w))
	}
	return out, nil
}

func (s *MemoryStore) CreatePlannedBatch(_ context.Context, fence Fence, b Batch) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if b.ID == ([32]byte{}) || b.State != BatchStatePlanned || len(b.WithdrawalIDs) == 0 || len(b.TxPlan) == 0 {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ids, err := sortedUnique32(b.WithdrawalIDs)
	if err != nil {
		return err
	}

	if existing, ok := s.batches[b.ID]; ok {
		want := Batch{
			ID:            b.ID,
			WithdrawalIDs: ids,
			State:         BatchStatePlanned,
			LeaseOwner:    fence.Owner,
			LeaseVersion:  fence.LeaseVersion,
			TxPlan:        b.TxPlan,
		}
		if !batchEqual(existing, want) {
			return ErrBatchMismatch
		}
		return nil
	}

	for _, id := range ids {
		rec, ok := s.withdrawals[id]
		if !ok {
			return ErrNotFound
		}
		if rec.batchID != ([32]byte{}) {
			return ErrInvalidTransition
		}
		if rec.claimedBy != fence.Owner || rec.claimLeaseVersion != fence.LeaseVersion {
			return ErrInvalidTransition
		}
	}

	nb := Batch{
		ID:            b.ID,
		WithdrawalIDs: ids,
		State:         BatchStatePlanned,
		LeaseOwner:    fence.Owner,
		LeaseVersion:  fence.LeaseVersion,
		TxPlan:        append([]byte(nil), b.TxPlan...),
	}
	s.batches[b.ID] = nb

	for _, id := range ids {
		rec := s.withdrawals[id]
		rec.batchID = b.ID
		rec.status = WithdrawalStatusBatched
		rec.claimedBy = ""
		rec.claimLeaseVersion = 0
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

func (s *MemoryStore) GetWithdrawalStatus(_ context.Context, id [32]byte) (WithdrawalStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.withdrawals[id]
	if !ok {
		return WithdrawalStatusUnknown, ErrNotFound
	}
	return rec.status, nil
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
		if b.State == state && b.DLQAt.IsZero() {
			out = append(out, cloneBatch(b))
		}
	}
	slices.SortFunc(out, func(a, b Batch) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	return out, nil
}

func (s *MemoryStore) AdoptBatch(_ context.Context, batchID [32]byte, fence Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, ok := s.batches[batchID]
	if !ok {
		return ErrNotFound
	}
	if b.LeaseVersion > fence.LeaseVersion {
		return ErrInvalidTransition
	}
	if b.LeaseVersion == fence.LeaseVersion {
		if b.LeaseOwner == "" || b.LeaseOwner == fence.Owner {
			b.LeaseOwner = fence.Owner
			s.batches[batchID] = b
			return nil
		}
		return ErrInvalidTransition
	}
	b.LeaseOwner = fence.Owner
	b.LeaseVersion = fence.LeaseVersion
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) MarkBatchSigning(_ context.Context, batchID [32]byte, fence Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
	}
	switch b.State {
	case BatchStatePlanned, BatchStateSigning:
		b.State = BatchStateSigning
		s.batches[batchID] = b
		return nil
	default:
		if b.State > BatchStateSigning {
			return nil
		}
		return ErrInvalidTransition
	}
}

func (s *MemoryStore) ResetBatchSigning(_ context.Context, batchID [32]byte, fence Fence, txPlan []byte) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if len(txPlan) == 0 {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
	}
	if b.State != BatchStateSigning {
		return ErrInvalidTransition
	}

	b.State = BatchStatePlanned
	b.TxPlan = append([]byte(nil), txPlan...)
	b.SignedTx = nil
	b.BroadcastLockedAt = time.Time{}
	b.JunoTxID = ""
	b.BaseTxHash = ""
	b.NextRebroadcastAt = time.Time{}
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) SetBatchSigned(_ context.Context, batchID [32]byte, fence Fence, signedTx []byte) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if len(signedTx) == 0 {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
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

func (s *MemoryStore) MarkBatchBroadcastLocked(_ context.Context, batchID [32]byte, fence Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
	}
	if b.State < BatchStateSigned {
		return ErrInvalidTransition
	}
	if b.State >= BatchStateBroadcasted {
		return nil
	}
	if b.BroadcastLockedAt.IsZero() {
		b.BroadcastLockedAt = s.now().UTC()
		s.batches[batchID] = b
	}
	return nil
}

func (s *MemoryStore) SetBatchBroadcasted(_ context.Context, batchID [32]byte, fence Fence, txid string) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if txid == "" {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
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
	if b.BroadcastLockedAt.IsZero() {
		return ErrInvalidTransition
	}

	b.State = BatchStateBroadcasted
	b.JunoTxID = txid
	b.NextRebroadcastAt = time.Time{}
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) ResetBatchPlanned(_ context.Context, batchID [32]byte, fence Fence, txPlan []byte) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if len(txPlan) == 0 {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
	}
	if b.State != BatchStateSigned && b.State != BatchStateBroadcasted {
		return ErrInvalidTransition
	}
	if !b.BroadcastLockedAt.IsZero() {
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

func (s *MemoryStore) SetBatchRebroadcastBackoff(_ context.Context, batchID [32]byte, fence Fence, attempts uint32, next time.Time) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if next.IsZero() {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
	}
	if b.State != BatchStateBroadcasted {
		return ErrInvalidTransition
	}

	b.RebroadcastAttempts = attempts
	b.NextRebroadcastAt = next.UTC()
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) MarkBatchJunoConfirmed(_ context.Context, batchID [32]byte, fence Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
	}
	if b.State != BatchStateBroadcasted {
		return ErrInvalidTransition
	}
	if b.JunoConfirmedAt.IsZero() {
		b.JunoConfirmedAt = s.now().UTC()
		s.batches[batchID] = b
	}
	return nil
}

func (s *MemoryStore) RecordBatchFailure(_ context.Context, batchID [32]byte, fence Fence, stage string, errorCode string, errorMessage string) (Batch, error) {
	if err := fence.Validate(); err != nil {
		return Batch{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return Batch{}, err
	}
	b.FailureCount++
	b.LastFailureStage = stage
	b.LastErrorCode = errorCode
	b.LastErrorMessage = errorMessage
	b.LastFailedAt = s.now().UTC()
	s.batches[batchID] = b
	return cloneBatch(b), nil
}

func (s *MemoryStore) RecordBatchMarkPaidFailure(_ context.Context, batchID [32]byte, fence Fence, errorMessage string) (Batch, error) {
	if err := fence.Validate(); err != nil {
		return Batch{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return Batch{}, err
	}
	b.MarkPaidFailures++
	b.LastMarkPaidError = errorMessage
	s.batches[batchID] = b
	return cloneBatch(b), nil
}

func (s *MemoryStore) ResetBatchMarkPaidFailures(_ context.Context, batchID [32]byte, fence Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
	}
	b.MarkPaidFailures = 0
	b.LastMarkPaidError = ""
	s.batches[batchID] = b
	return nil
}

func (s *MemoryStore) MarkBatchDLQ(_ context.Context, batchID [32]byte, fence Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
	}
	if b.DLQAt.IsZero() {
		b.DLQAt = s.now().UTC()
		s.batches[batchID] = b
	}
	return nil
}

func (s *MemoryStore) SetBatchConfirmed(_ context.Context, batchID [32]byte, fence Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
	}
	if b.State < BatchStateBroadcasted {
		return ErrInvalidTransition
	}
	if b.State >= BatchStateConfirmed {
		return nil
	}
	if b.JunoConfirmedAt.IsZero() {
		return ErrInvalidTransition
	}

	b.State = BatchStateConfirmed
	b.NextRebroadcastAt = time.Time{}
	b.MarkPaidFailures = 0
	b.LastMarkPaidError = ""
	s.batches[batchID] = b
	for _, id := range b.WithdrawalIDs {
		rec := s.withdrawals[id]
		rec.status = WithdrawalStatusPaid
		s.withdrawals[id] = rec
	}
	return nil
}

func (s *MemoryStore) MarkBatchFinalizing(_ context.Context, batchID [32]byte, fence Fence) error {
	if err := fence.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
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

func (s *MemoryStore) SetBatchFinalized(_ context.Context, batchID [32]byte, fence Fence, baseTxHash string) error {
	if err := fence.Validate(); err != nil {
		return err
	}
	if baseTxHash == "" {
		return ErrInvalidConfig
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := s.batchForMutation(batchID, fence)
	if err != nil {
		return err
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

func (s *MemoryStore) batchForMutation(batchID [32]byte, fence Fence) (Batch, error) {
	b, ok := s.batches[batchID]
	if !ok {
		return Batch{}, ErrNotFound
	}
	if b.LeaseOwner != fence.Owner || b.LeaseVersion != fence.LeaseVersion {
		return Batch{}, ErrInvalidTransition
	}
	return b, nil
}

func cloneWithdrawal(w Withdrawal) Withdrawal {
	w.RecipientUA = append([]byte(nil), w.RecipientUA...)
	w.ProofWitnessItem = append([]byte(nil), w.ProofWitnessItem...)
	return w
}

func withdrawalEqual(a, b Withdrawal) bool {
	if a.ID != b.ID ||
		a.Requester != b.Requester ||
		a.Amount != b.Amount ||
		a.FeeBps != b.FeeBps ||
		!a.Expiry.Equal(b.Expiry) ||
		a.BaseBlockNumber != b.BaseBlockNumber ||
		a.BaseBlockHash != b.BaseBlockHash ||
		a.BaseTxHash != b.BaseTxHash ||
		a.BaseLogIndex != b.BaseLogIndex ||
		a.BaseFinalitySource != b.BaseFinalitySource {
		return false
	}
	return bytes.Equal(a.RecipientUA, b.RecipientUA) &&
		bytes.Equal(a.ProofWitnessItem, b.ProofWitnessItem)
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
	if a.ID != b.ID ||
		a.State != b.State ||
		a.LeaseOwner != b.LeaseOwner ||
		a.LeaseVersion != b.LeaseVersion ||
		a.JunoTxID != b.JunoTxID ||
		a.BaseTxHash != b.BaseTxHash ||
		a.FailureCount != b.FailureCount ||
		a.LastFailureStage != b.LastFailureStage ||
		a.LastErrorCode != b.LastErrorCode ||
		a.LastErrorMessage != b.LastErrorMessage ||
		a.MarkPaidFailures != b.MarkPaidFailures ||
		a.LastMarkPaidError != b.LastMarkPaidError {
		return false
	}
	if !a.BroadcastLockedAt.Equal(b.BroadcastLockedAt) ||
		!a.JunoConfirmedAt.Equal(b.JunoConfirmedAt) ||
		!a.NextRebroadcastAt.Equal(b.NextRebroadcastAt) ||
		!a.LastFailedAt.Equal(b.LastFailedAt) ||
		!a.DLQAt.Equal(b.DLQAt) {
		return false
	}
	if a.RebroadcastAttempts != b.RebroadcastAttempts {
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
