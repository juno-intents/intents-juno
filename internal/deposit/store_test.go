package deposit

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

func TestMemoryStore_UpsertConfirmed_DedupesAndRejectsMismatch(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()

	var id [32]byte
	id[0] = 0x01

	var cm [32]byte
	cm[0] = 0xaa

	var recip [20]byte
	recip[19] = 0x01

	d := Deposit{
		DepositID:     id,
		Commitment:    cm,
		LeafIndex:     7,
		Amount:        1000,
		BaseRecipient: recip,
	}

	job, created, err := s.UpsertConfirmed(context.Background(), d)
	if err != nil {
		t.Fatalf("UpsertConfirmed #1: %v", err)
	}
	if !created {
		t.Fatalf("expected created=true")
	}
	if job.State != StateConfirmed {
		t.Fatalf("state: got %v want %v", job.State, StateConfirmed)
	}

	_, created, err = s.UpsertConfirmed(context.Background(), d)
	if err != nil {
		t.Fatalf("UpsertConfirmed #2: %v", err)
	}
	if created {
		t.Fatalf("expected created=false")
	}

	d2 := d
	d2.Amount = 2000
	_, _, err = s.UpsertConfirmed(context.Background(), d2)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestMemoryStore_StateMachine(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()

	var id [32]byte
	id[0] = 0x01

	var cm [32]byte
	cm[0] = 0xaa

	var recip [20]byte
	copy(recip[:], common.HexToAddress("0x0000000000000000000000000000000000000456").Bytes())

	_, _, err := s.UpsertConfirmed(context.Background(), Deposit{
		DepositID:     id,
		Commitment:    cm,
		LeafIndex:     7,
		Amount:        1000,
		BaseRecipient: recip,
	})
	if err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	// Cannot mark proof ready before requesting it.
	if err := s.SetProofReady(context.Background(), id, []byte{0x01}); err == nil {
		t.Fatalf("expected error")
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if err := s.MarkProofRequested(context.Background(), id, cp); err != nil {
		t.Fatalf("MarkProofRequested: %v", err)
	}

	if err := s.SetProofReady(context.Background(), id, []byte{0x02}); err != nil {
		t.Fatalf("SetProofReady: %v", err)
	}

	var txHash [32]byte
	txHash[0] = 0x77
	if err := s.MarkFinalized(context.Background(), id, txHash); err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}

	// Idempotent.
	if err := s.MarkFinalized(context.Background(), id, txHash); err != nil {
		t.Fatalf("MarkFinalized #2: %v", err)
	}

	job, err := s.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != StateFinalized {
		t.Fatalf("state: got %v want %v", job.State, StateFinalized)
	}
	if job.TxHash != txHash {
		t.Fatalf("txHash mismatch")
	}
}

