package checkpoint

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type fakeChainSource struct {
	tip    uint64
	blocks map[uint64]ChainCheckpoint
	errTip error
}

func (f *fakeChainSource) TipHeight(ctx context.Context) (uint64, error) {
	_ = ctx
	if f.errTip != nil {
		return 0, f.errTip
	}
	return f.tip, nil
}

func (f *fakeChainSource) CheckpointAtHeight(ctx context.Context, height uint64) (ChainCheckpoint, error) {
	_ = ctx
	b, ok := f.blocks[height]
	if !ok {
		return ChainCheckpoint{}, errors.New("not found")
	}
	return b, nil
}

func TestSigner_SignTipMinusConfirmations(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	wantOperator := crypto.PubkeyToAddress(key.PublicKey)

	baseChainID := uint64(8453)
	bridge := common.HexToAddress("0x000000000000000000000000000000000000bEEF")

	src := &fakeChainSource{
		tip: 223,
		blocks: map[uint64]ChainCheckpoint{
			123: {
				Height:           123,
				BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
				FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
			},
		},
	}

	s, err := NewSigner(src, key, SignerConfig{
		BaseChainID:    baseChainID,
		BridgeContract: bridge,
		Now:            time.Now,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	msg, err := s.SignTipMinusConfirmations(ctx, 100)
	if err != nil {
		t.Fatalf("SignTipMinusConfirmations: %v", err)
	}
	if msg.Operator != wantOperator {
		t.Fatalf("operator mismatch: got %s want %s", msg.Operator, wantOperator)
	}
	if msg.Checkpoint.Height != 123 {
		t.Fatalf("height mismatch: got %d want %d", msg.Checkpoint.Height, 123)
	}
	wantDigest := common.HexToHash("0x688fcd90cce56cb44480c50331d4d35fe77bc15b43cffe150042570c49692e4a")
	if msg.Digest != wantDigest {
		t.Fatalf("digest mismatch: got %s want %s", msg.Digest, wantDigest)
	}

	gotOp, err := RecoverSigner(msg.Digest, msg.Signature)
	if err != nil {
		t.Fatalf("RecoverSigner: %v", err)
	}
	if gotOp != wantOperator {
		t.Fatalf("signature recover mismatch: got %s want %s", gotOp, wantOperator)
	}
}

func TestSigner_SignTipMinusConfirmations_RejectsWhenTipTooLow(t *testing.T) {
	t.Parallel()

	key, err := crypto.HexToECDSA("4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}

	src := &fakeChainSource{
		tip:    50,
		blocks: map[uint64]ChainCheckpoint{},
	}

	s, err := NewSigner(src, key, SignerConfig{
		BaseChainID:    8453,
		BridgeContract: common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		Now:            time.Now,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	_, err = s.SignTipMinusConfirmations(context.Background(), 100)
	if err == nil {
		t.Fatalf("expected error")
	}
}
