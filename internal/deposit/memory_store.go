package deposit

import (
	"context"
	"sync"

	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type MemoryStore struct {
	mu   sync.Mutex
	jobs map[[32]byte]Job
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		jobs: make(map[[32]byte]Job),
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
		return j, true, nil
	}

	if j.Deposit != d {
		return Job{}, false, ErrDepositMismatch
	}

	if j.State < StateConfirmed {
		j.State = StateConfirmed
		s.jobs[d.DepositID] = j
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
	if j.ProofSeal != nil {
		j.ProofSeal = append([]byte(nil), j.ProofSeal...)
	}
	return j, nil
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
	return nil
}

