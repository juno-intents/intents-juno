package checkpoint

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
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
	BaseChainID    uint64
	BridgeContract common.Address

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
	key         *ecdsa.PrivateKey
	operator    common.Address
	baseChainID uint64
	bridge      common.Address
	now         func() time.Time
}

func NewSigner(src ChainSource, key *ecdsa.PrivateKey, cfg SignerConfig) (*Signer, error) {
	if src == nil {
		return nil, errors.New("checkpoint: nil chain source")
	}
	if key == nil {
		return nil, errors.New("checkpoint: nil private key")
	}
	if cfg.BaseChainID == 0 {
		return nil, errors.New("checkpoint: base chain id must be non-zero")
	}
	if cfg.BridgeContract == (common.Address{}) {
		return nil, errors.New("checkpoint: bridge contract must be non-zero")
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	return &Signer{
		src:         src,
		key:         key,
		operator:    crypto.PubkeyToAddress(key.PublicKey),
		baseChainID: cfg.BaseChainID,
		bridge:      cfg.BridgeContract,
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
	sig, err := SignDigest(s.key, digest)
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
