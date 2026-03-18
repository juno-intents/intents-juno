package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

var (
	ErrTipTooLow = errors.New("checkpoint: tip too low for confirmations")
)

type ChainCheckpoint struct {
	Height           uint64
	BlockHash        common.Hash
	FinalOrchardRoot common.Hash
}

type ChainSource interface {
	TipHeight(ctx context.Context) (uint64, error)
	CheckpointAtHeight(ctx context.Context, height uint64) (ChainCheckpoint, error)
}

type SignerConfig struct {
	BaseChainID     uint64
	BridgeContract  common.Address
	CommitmentStore SignerCommitmentStore

	Now func() time.Time
}

type SignatureMessageV1 struct {
	Operator   common.Address
	Digest     common.Hash
	Signature  []byte
	Checkpoint Checkpoint

	SignedAt time.Time
}

type Signer struct {
	src         ChainSource
	signer      DigestSigner
	operator    common.Address
	baseChainID uint64
	bridge      common.Address
	commitments SignerCommitmentStore
	now         func() time.Time
}

func NewSigner(src ChainSource, signer DigestSigner, cfg SignerConfig) (*Signer, error) {
	if src == nil {
		return nil, errors.New("checkpoint: nil chain source")
	}
	if signer == nil {
		return nil, errors.New("checkpoint: nil digest signer")
	}
	if cfg.BaseChainID == 0 {
		return nil, errors.New("checkpoint: base chain id must be non-zero")
	}
	if cfg.BridgeContract == (common.Address{}) {
		return nil, errors.New("checkpoint: bridge contract must be non-zero")
	}
	if cfg.CommitmentStore == nil {
		return nil, errors.New("checkpoint: commitment store must be non-nil")
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	return &Signer{
		src:         src,
		signer:      signer,
		operator:    signer.Address(),
		baseChainID: cfg.BaseChainID,
		bridge:      cfg.BridgeContract,
		commitments: cfg.CommitmentStore,
		now:         nowFn,
	}, nil
}

func (s *Signer) SignTipMinusConfirmations(ctx context.Context, confirmations uint64) (SignatureMessageV1, error) {
	tip, err := s.src.TipHeight(ctx)
	if err != nil {
		return SignatureMessageV1{}, fmt.Errorf("checkpoint: fetch tip height: %w", err)
	}
	if tip < confirmations {
		return SignatureMessageV1{}, ErrTipTooLow
	}
	return s.SignHeight(ctx, tip-confirmations)
}

func (s *Signer) SignHeight(ctx context.Context, height uint64) (SignatureMessageV1, error) {
	ch, err := s.src.CheckpointAtHeight(ctx, height)
	if err != nil {
		return SignatureMessageV1{}, fmt.Errorf("checkpoint: fetch checkpoint fields: %w", err)
	}
	if ch.Height != height {
		return SignatureMessageV1{}, fmt.Errorf("checkpoint: height mismatch: want %d got %d", height, ch.Height)
	}

	cp := Checkpoint{
		Height:           ch.Height,
		BlockHash:        ch.BlockHash,
		FinalOrchardRoot: ch.FinalOrchardRoot,
		BaseChainID:      s.baseChainID,
		BridgeContract:   s.bridge,
	}

	digest := Digest(cp)
	if err := s.commitments.RecordCommitment(ctx, SignerCommitment{
		BaseChainID:    s.baseChainID,
		BridgeContract: s.bridge,
		Operator:       s.operator,
		Height:         height,
		Digest:         digest,
		SignedAt:       s.now().UTC(),
	}); err != nil {
		return SignatureMessageV1{}, err
	}
	sig, err := s.signer.SignDigest(ctx, digest)
	if err != nil {
		return SignatureMessageV1{}, err
	}

	return SignatureMessageV1{
		Operator:   s.operator,
		Digest:     digest,
		Signature:  sig,
		Checkpoint: cp,
		SignedAt:   s.now(),
	}, nil
}
