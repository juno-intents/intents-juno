package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

var ErrCheckpointEquivocation = errors.New("checkpoint: conflicting digest already recorded for height")

type SignerCommitment struct {
	BaseChainID    uint64
	BridgeContract common.Address
	Operator       common.Address
	Height         uint64
	Digest         common.Hash
	SignedAt       time.Time
}

type SignerCommitmentStore interface {
	RecordCommitment(ctx context.Context, commitment SignerCommitment) error
}

type signerCommitmentKey struct {
	baseChainID    uint64
	bridgeContract common.Address
	operator       common.Address
	height         uint64
}

type MemorySignerCommitmentStore struct {
	mu          sync.Mutex
	commitments map[signerCommitmentKey]SignerCommitment
}

func NewMemorySignerCommitmentStore() *MemorySignerCommitmentStore {
	return &MemorySignerCommitmentStore{
		commitments: make(map[signerCommitmentKey]SignerCommitment),
	}
}

func (s *MemorySignerCommitmentStore) RecordCommitment(_ context.Context, commitment SignerCommitment) error {
	if commitment.BaseChainID == 0 {
		return fmt.Errorf("%w: base chain id must be non-zero", ErrInvalidCheckpointCommitment)
	}
	if commitment.BridgeContract == (common.Address{}) {
		return fmt.Errorf("%w: bridge contract must be non-zero", ErrInvalidCheckpointCommitment)
	}
	if commitment.Operator == (common.Address{}) {
		return fmt.Errorf("%w: operator must be non-zero", ErrInvalidCheckpointCommitment)
	}
	if commitment.Digest == (common.Hash{}) {
		return fmt.Errorf("%w: digest must be non-zero", ErrInvalidCheckpointCommitment)
	}

	key := signerCommitmentKey{
		baseChainID:    commitment.BaseChainID,
		bridgeContract: commitment.BridgeContract,
		operator:       commitment.Operator,
		height:         commitment.Height,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.commitments[key]; ok {
		if existing.Digest == commitment.Digest {
			return nil
		}
		return ErrCheckpointEquivocation
	}
	s.commitments[key] = commitment
	return nil
}

var ErrInvalidCheckpointCommitment = errors.New("checkpoint: invalid checkpoint commitment")

var _ SignerCommitmentStore = (*MemorySignerCommitmentStore)(nil)
