package deposit

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type MemoryStore struct {
	mu    sync.Mutex
	jobs  map[[32]byte]Job
	order [][32]byte
	claim map[[32]byte]claimLease
}

type claimLease struct {
	owner     string
	expiresAt time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		jobs:  make(map[[32]byte]Job),
		claim: make(map[[32]byte]claimLease),
	}
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

	if !depositEqual(j.Deposit, d) {
		return Job{}, false, ErrDepositMismatch
	}

	if j.State < StateConfirmed {
		j.State = StateConfirmed
		s.jobs[d.DepositID] = j
		delete(s.claim, d.DepositID)
	}
	return j, false, nil
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
		if j.State != StateConfirmed && j.State != StateSubmitted {
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

func (s *MemoryStore) MarkProofRequested(_ context.Context, depositID [32]byte, cp checkpoint.Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	j, ok := s.jobs[depositID]
	if !ok {
		return ErrNotFound
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
	s.jobs[depositID] = j
	delete(s.claim, depositID)
	return nil
}

func (s *MemoryStore) MarkBatchSubmitted(_ context.Context, depositIDs [][32]byte, cp checkpoint.Checkpoint, seal []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(depositIDs) == 0 {
		return nil
	}

	ids := uniqueDepositIDs(depositIDs)

	for _, id := range ids {
		j, ok := s.jobs[id]
		if !ok {
			return ErrNotFound
		}
		if j.State == StateFinalized {
			continue
		}
		if j.State < StateConfirmed {
			return ErrInvalidTransition
		}
	}

	for _, id := range ids {
		j := s.jobs[id]
		if j.State >= StateSubmitted {
			continue
		}
		j.State = StateSubmitted
		j.Checkpoint = cp
		j.ProofSeal = append([]byte(nil), seal...)
		s.jobs[id] = j
		delete(s.claim, id)
	}
	return nil
}

func (s *MemoryStore) FinalizeBatch(_ context.Context, depositIDs [][32]byte, cp checkpoint.Checkpoint, seal []byte, txHash [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(depositIDs) == 0 {
		return nil
	}

	ids := uniqueDepositIDs(depositIDs)

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
	}

	for _, id := range ids {
		j := s.jobs[id]
		if j.State == StateFinalized {
			continue
		}
		j.State = StateFinalized
		j.Checkpoint = cp
		j.ProofSeal = append([]byte(nil), seal...)
		j.TxHash = txHash
		s.jobs[id] = j
		delete(s.claim, id)
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

func depositEqual(a, b Deposit) bool {
	return a.DepositID == b.DepositID &&
		a.Commitment == b.Commitment &&
		a.LeafIndex == b.LeafIndex &&
		a.Amount == b.Amount &&
		a.BaseRecipient == b.BaseRecipient &&
		bytes.Equal(a.ProofWitnessItem, b.ProofWitnessItem)
}
