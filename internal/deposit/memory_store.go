package deposit

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type MemoryStore struct {
	mu sync.Mutex

	jobs  map[[32]byte]Job
	order [][32]byte
	claim map[[32]byte]claimLease

	attempts         map[[32]byte]SubmittedBatchAttempt
	attemptOrder     [][32]byte
	attemptClaim     map[[32]byte]claimLease
	attemptByDeposit map[[32]byte][32]byte
}

type claimLease struct {
	owner     string
	expiresAt time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		jobs:             make(map[[32]byte]Job),
		claim:            make(map[[32]byte]claimLease),
		attempts:         make(map[[32]byte]SubmittedBatchAttempt),
		attemptClaim:     make(map[[32]byte]claimLease),
		attemptByDeposit: make(map[[32]byte][32]byte),
	}
}

func (s *MemoryStore) UpsertSeen(_ context.Context, d Deposit) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[d.DepositID]
	if !ok {
		j = Job{
			Deposit: d,
			State:   StateSeen,
		}
		s.jobs[d.DepositID] = j
		s.order = append(s.order, d.DepositID)
		return j, true, nil
	}

	if !depositIdentityEqual(j.Deposit, d) {
		return Job{}, false, ErrDepositMismatch
	}
	if j.State < StateProofRequested && len(d.ProofWitnessItem) > 0 && !bytes.Equal(j.Deposit.ProofWitnessItem, d.ProofWitnessItem) {
		j.Deposit.ProofWitnessItem = append([]byte(nil), d.ProofWitnessItem...)
	}
	if d.JunoHeight > 0 {
		j.Deposit.JunoHeight = d.JunoHeight
	}
	s.jobs[d.DepositID] = j
	return cloneJob(j), false, nil
}

func (s *MemoryStore) UpsertConfirmed(_ context.Context, d Deposit) (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[d.DepositID]
	if !ok {
		j = Job{
			Deposit: d,
			State:   StateConfirmed,
		}
		s.jobs[d.DepositID] = j
		s.order = append(s.order, d.DepositID)
		return j, true, nil
	}

	if !depositIdentityEqual(j.Deposit, d) {
		return Job{}, false, ErrDepositMismatch
	}
	if j.State < StateProofRequested && len(d.ProofWitnessItem) > 0 && !bytes.Equal(j.Deposit.ProofWitnessItem, d.ProofWitnessItem) {
		j.Deposit.ProofWitnessItem = append([]byte(nil), d.ProofWitnessItem...)
	}
	if d.JunoHeight > 0 {
		j.Deposit.JunoHeight = d.JunoHeight
	}

	if j.State < StateConfirmed {
		j.State = StateConfirmed
		j.RejectionReason = ""
		s.jobs[d.DepositID] = j
		delete(s.claim, d.DepositID)
	}
	return cloneJob(j), false, nil
}

func (s *MemoryStore) PromoteSeenToConfirmed(_ context.Context, tipHeight int64, minConfirmations int64, limit int) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if tipHeight <= 0 || minConfirmations <= 0 || limit <= 0 {
		return nil, nil
	}

	out := make([]Job, 0, limit)
	for _, id := range s.order {
		if len(out) >= limit {
			break
		}
		j := s.jobs[id]
		if j.State != StateSeen || j.Deposit.JunoHeight <= 0 {
			continue
		}
		if tipHeight-j.Deposit.JunoHeight+1 < minConfirmations {
			continue
		}
		j.State = StateConfirmed
		j.RejectionReason = ""
		s.jobs[id] = j
		out = append(out, cloneJob(j))
	}
	return out, nil
}

func (s *MemoryStore) Get(_ context.Context, depositID [32]byte) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return Job{}, ErrNotFound
	}

	// Defensive copy of slices.
	j.Deposit = cloneDeposit(j.Deposit)
	if j.ProofSeal != nil {
		j.ProofSeal = append([]byte(nil), j.ProofSeal...)
	}
	return j, nil
}

func (s *MemoryStore) ListByState(_ context.Context, state State, limit int) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if limit <= 0 {
		return nil, nil
	}

	out := make([]Job, 0, limit)
	for _, id := range s.order {
		j := s.jobs[id]
		if j.State != state {
			continue
		}
		j.Deposit = cloneDeposit(j.Deposit)
		if j.ProofSeal != nil {
			j.ProofSeal = append([]byte(nil), j.ProofSeal...)
		}
		out = append(out, j)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *MemoryStore) ClaimConfirmed(_ context.Context, owner string, ttl time.Duration, limit int) ([]Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner == "" || ttl <= 0 || limit <= 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	out := make([]Job, 0, limit)
	for _, id := range s.order {
		j := s.jobs[id]
		if j.State != StateConfirmed {
			continue
		}
		lease, claimed := s.claim[id]
		if claimed && lease.owner != owner && lease.expiresAt.After(now) {
			continue
		}
		s.claim[id] = claimLease{
			owner:     owner,
			expiresAt: expiresAt,
		}
		j.Deposit = cloneDeposit(j.Deposit)
		if j.ProofSeal != nil {
			j.ProofSeal = append([]byte(nil), j.ProofSeal...)
		}
		out = append(out, j)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *MemoryStore) ClaimSubmittedAttempts(_ context.Context, owner string, ttl time.Duration, limit int) ([]SubmittedBatchAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if owner == "" || ttl <= 0 || limit <= 0 {
		return nil, nil
	}

	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	out := make([]SubmittedBatchAttempt, 0, limit)
	for _, batchID := range s.attemptOrder {
		attempt, ok := s.attempts[batchID]
		if !ok {
			continue
		}
		lease, claimed := s.attemptClaim[batchID]
		if claimed && lease.owner != owner && lease.expiresAt.After(now) {
			continue
		}
		s.attemptClaim[batchID] = claimLease{
			owner:     owner,
			expiresAt: expiresAt,
		}
		out = append(out, cloneSubmittedBatchAttempt(attempt))
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *MemoryStore) MarkProofRequested(_ context.Context, depositID [32]byte, cp checkpoint.Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
	}

	if j.State == StateRejected {
		return ErrInvalidTransition
	}
	if j.State < StateConfirmed {
		return ErrInvalidTransition
	}

	// Do not allow downgrades.
	if j.State < StateProofRequested {
		j.State = StateProofRequested
		delete(s.claim, depositID)
	}
	j.Checkpoint = cp
	s.jobs[depositID] = j
	return nil
}

func (s *MemoryStore) SetProofReady(_ context.Context, depositID [32]byte, seal []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
	}

	if j.State == StateRejected {
		return ErrInvalidTransition
	}
	if j.State < StateProofRequested {
		return ErrInvalidTransition
	}

	if j.State < StateProofReady {
		j.State = StateProofReady
		delete(s.claim, depositID)
	}
	j.ProofSeal = append([]byte(nil), seal...)
	s.jobs[depositID] = j
	return nil
}

func (s *MemoryStore) MarkFinalized(_ context.Context, depositID [32]byte, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
	}

	if j.State == StateRejected {
		return ErrInvalidTransition
	}
	if j.State < StateProofReady {
		return ErrInvalidTransition
	}

	if j.State == StateFinalized {
		if j.TxHash != txHash {
			return ErrDepositMismatch
		}
		return nil
	}

	j.State = StateFinalized
	j.TxHash = txHash
	j.RejectionReason = ""
	s.jobs[depositID] = j
	delete(s.claim, depositID)
	return nil
}

func (s *MemoryStore) MarkRejected(_ context.Context, depositID [32]byte, reason string, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
	}
	if j.State == StateFinalized {
		return ErrInvalidTransition
	}
	if j.State == StateRejected {
		if j.RejectionReason != reason {
			return ErrDepositMismatch
		}
		if txHash != ([32]byte{}) && j.TxHash != ([32]byte{}) && j.TxHash != txHash {
			return ErrDepositMismatch
		}
		return nil
	}
	if j.State < StateSeen {
		return ErrInvalidTransition
	}

	j.State = StateRejected
	j.RejectionReason = reason
	if txHash != ([32]byte{}) {
		j.TxHash = txHash
	}
	s.jobs[depositID] = j
	delete(s.claim, depositID)
	delete(s.attemptByDeposit, depositID)
	return nil
}

func (s *MemoryStore) MarkBatchSubmitted(_ context.Context, owner string, batchID [32]byte, depositIDs [][32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) (SubmittedBatchAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(depositIDs) == 0 {
		return SubmittedBatchAttempt{}, nil
	}
	if owner == "" {
		return SubmittedBatchAttempt{}, ErrInvalidTransition
	}

	ids := uniqueDepositIDs(depositIDs)

	for _, id := range ids {
		j, ok := s.jobs[id]
		if !ok {
			return SubmittedBatchAttempt{}, ErrNotFound
		}
		if j.State == StateRejected {
			return SubmittedBatchAttempt{}, ErrInvalidTransition
		}
		if j.State < StateConfirmed {
			return SubmittedBatchAttempt{}, ErrInvalidTransition
		}
	}

	if existing, ok := s.attempts[batchID]; ok {
		if !submittedBatchAttemptEqual(existing, owner, ids, cp, operatorSignatures, seal) {
			return SubmittedBatchAttempt{}, ErrDepositMismatch
		}
		for _, id := range ids {
			s.attemptByDeposit[id] = batchID
		}
		return cloneSubmittedBatchAttempt(existing), nil
	}

	attempt := SubmittedBatchAttempt{
		BatchID:            batchID,
		DepositIDs:         cloneDepositIDs(ids),
		Owner:              owner,
		Epoch:              1,
		Checkpoint:         cp,
		OperatorSignatures: clone2DBytes(operatorSignatures),
		ProofSeal:          append([]byte(nil), seal...),
	}
	s.attempts[batchID] = attempt
	s.attemptOrder = append(s.attemptOrder, batchID)

	for _, id := range ids {
		j := s.jobs[id]
		j.Checkpoint = cp
		j.ProofSeal = append([]byte(nil), seal...)
		if j.State != StateFinalized && j.State != StateRejected {
			j.State = StateSubmitted
		}
		j.RejectionReason = ""
		s.jobs[id] = j
		delete(s.claim, id)
		s.attemptByDeposit[id] = batchID
	}
	return cloneSubmittedBatchAttempt(attempt), nil
}

func (s *MemoryStore) SetBatchSubmissionTxHash(_ context.Context, batchID [32]byte, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempt, ok := s.attempts[batchID]
	if !ok {
		return ErrNotFound
	}
	if attempt.TxHash != ([32]byte{}) && attempt.TxHash != txHash {
		return ErrDepositMismatch
	}
	attempt.TxHash = txHash
	s.attempts[batchID] = attempt
	return nil
}

func (s *MemoryStore) FinalizeBatch(_ context.Context, depositIDs [][32]byte, cp checkpoint.Checkpoint, seal []byte, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(depositIDs) == 0 {
		return nil
	}

	ids := uniqueDepositIDs(depositIDs)
	batchIDs := make(map[[32]byte]struct{}, len(ids))

	// Validate first so the operation is all-or-nothing.
	for _, id := range ids {
		j, ok := s.jobs[id]
		if !ok {
			return ErrNotFound
		}
		if j.State == StateFinalized {
			if j.TxHash != txHash {
				return ErrDepositMismatch
			}
			continue
		}
		if j.State < StateConfirmed {
			return ErrInvalidTransition
		}
		if batchID, ok := s.attemptByDeposit[id]; ok {
			batchIDs[batchID] = struct{}{}
		}
	}

	for _, id := range ids {
		j := s.jobs[id]
		if j.State == StateFinalized {
			delete(s.claim, id)
			delete(s.attemptByDeposit, id)
			continue
		}
		j.State = StateFinalized
		j.Checkpoint = cp
		j.ProofSeal = append([]byte(nil), seal...)
		j.TxHash = txHash
		j.RejectionReason = ""
		s.jobs[id] = j
		delete(s.claim, id)
		delete(s.attemptByDeposit, id)
	}
	for batchID := range batchIDs {
		delete(s.attempts, batchID)
		delete(s.attemptClaim, batchID)
	}
	return nil
}

func (s *MemoryStore) ApplyBatchOutcome(_ context.Context, batchID [32]byte, txHash [32]byte, finalizedIDs [][32]byte, rejectedIDs [][32]byte, rejectionReason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	attempt, ok := s.attempts[batchID]
	if !ok {
		return ErrNotFound
	}

	expected := make(map[[32]byte]struct{}, len(attempt.DepositIDs))
	for _, id := range attempt.DepositIDs {
		expected[id] = struct{}{}
	}
	finalizedSet := make(map[[32]byte]struct{}, len(finalizedIDs))
	rejectedSet := make(map[[32]byte]struct{}, len(rejectedIDs))
	for _, id := range uniqueDepositIDs(finalizedIDs) {
		if _, ok := expected[id]; !ok {
			return ErrDepositMismatch
		}
		finalizedSet[id] = struct{}{}
	}
	for _, id := range uniqueDepositIDs(rejectedIDs) {
		if _, ok := expected[id]; !ok {
			return ErrDepositMismatch
		}
		if _, ok := finalizedSet[id]; ok {
			return ErrDepositMismatch
		}
		rejectedSet[id] = struct{}{}
	}

	allResolved := true
	for _, id := range attempt.DepositIDs {
		j, ok := s.jobs[id]
		if !ok {
			return ErrNotFound
		}
		if j.State == StateFinalized || j.State == StateRejected {
			delete(s.claim, id)
			delete(s.attemptByDeposit, id)
			s.jobs[id] = j
			continue
		}
		switch {
		case hasID(finalizedSet, id):
			j.State = StateFinalized
			j.RejectionReason = ""
			j.TxHash = txHash
			delete(s.attemptByDeposit, id)
		case hasID(rejectedSet, id):
			j.State = StateRejected
			j.RejectionReason = rejectionReason
			j.TxHash = txHash
			delete(s.attemptByDeposit, id)
		default:
			allResolved = false
			if j.State != StateFinalized && j.State != StateRejected {
				j.State = StateSubmitted
				j.TxHash = txHash
			}
			s.attemptByDeposit[id] = batchID
		}
		delete(s.claim, id)
		s.jobs[id] = j
	}
	if allResolved {
		delete(s.attempts, batchID)
		delete(s.attemptClaim, batchID)
	}
	return nil
}

func uniqueDepositIDs(ids [][32]byte) [][32]byte {
	out := make([][32]byte, 0, len(ids))
	seen := make(map[[32]byte]struct{}, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func cloneDeposit(d Deposit) Deposit {
	d.ProofWitnessItem = append([]byte(nil), d.ProofWitnessItem...)
	return d
}

func cloneJob(j Job) Job {
	j.Deposit = cloneDeposit(j.Deposit)
	j.ProofSeal = append([]byte(nil), j.ProofSeal...)
	return j
}

func cloneSubmittedBatchAttempt(a SubmittedBatchAttempt) SubmittedBatchAttempt {
	a.DepositIDs = cloneDepositIDs(a.DepositIDs)
	a.OperatorSignatures = clone2DBytes(a.OperatorSignatures)
	a.ProofSeal = append([]byte(nil), a.ProofSeal...)
	return a
}

func cloneDepositIDs(ids [][32]byte) [][32]byte {
	if len(ids) == 0 {
		return nil
	}
	out := make([][32]byte, len(ids))
	copy(out, ids)
	return out
}

func clone2DBytes(in [][]byte) [][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make([][]byte, 0, len(in))
	for _, item := range in {
		out = append(out, append([]byte(nil), item...))
	}
	return out
}

func submittedBatchAttemptEqual(existing SubmittedBatchAttempt, owner string, depositIDs [][32]byte, cp checkpoint.Checkpoint, operatorSignatures [][]byte, seal []byte) bool {
	if existing.Owner != owner || existing.Checkpoint != cp {
		return false
	}
	if !bytes.Equal(existing.ProofSeal, seal) {
		return false
	}
	if len(existing.DepositIDs) != len(depositIDs) || len(existing.OperatorSignatures) != len(operatorSignatures) {
		return false
	}
	for i := range existing.DepositIDs {
		if existing.DepositIDs[i] != depositIDs[i] {
			return false
		}
	}
	for i := range existing.OperatorSignatures {
		if !bytes.Equal(existing.OperatorSignatures[i], operatorSignatures[i]) {
			return false
		}
	}
	return true
}

func depositIdentityEqual(a, b Deposit) bool {
	return a.DepositID == b.DepositID &&
		a.Commitment == b.Commitment &&
		a.LeafIndex == b.LeafIndex &&
		a.Amount == b.Amount &&
		a.BaseRecipient == b.BaseRecipient
}

func depositEqual(a, b Deposit) bool {
	return depositIdentityEqual(a, b) && a.JunoHeight == b.JunoHeight
}

func hasID(ids map[[32]byte]struct{}, id [32]byte) bool {
	_, ok := ids[id]
	return ok
}
