package deposit

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

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
		DepositID:        id,
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		BaseRecipient:    recip,
		ProofWitnessItem: []byte{0x01, 0x02, 0x03},
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

func TestMemoryStore_UpsertSeen_RefreshesWitnessWithoutMismatch(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	var id [32]byte
	id[0] = 0x11

	var cm [32]byte
	cm[0] = 0xbb

	var recip [20]byte
	recip[19] = 0x02

	original := Deposit{
		DepositID:        id,
		Commitment:       cm,
		LeafIndex:        9,
		Amount:           2000,
		BaseRecipient:    recip,
		ProofWitnessItem: []byte{0x01, 0x02, 0x03},
		JunoHeight:       101,
	}

	if _, created, err := s.UpsertSeen(ctx, original); err != nil {
		t.Fatalf("UpsertSeen #1: %v", err)
	} else if !created {
		t.Fatalf("expected created=true")
	}

	refreshed := original
	refreshed.ProofWitnessItem = []byte{0x04, 0x05, 0x06}
	refreshed.JunoHeight = 202

	job, created, err := s.UpsertSeen(ctx, refreshed)
	if err != nil {
		t.Fatalf("UpsertSeen #2: %v", err)
	}
	if created {
		t.Fatalf("expected created=false")
	}
	if !bytes.Equal(job.Deposit.ProofWitnessItem, refreshed.ProofWitnessItem) {
		t.Fatalf("witness = %x, want %x", job.Deposit.ProofWitnessItem, refreshed.ProofWitnessItem)
	}
	if job.Deposit.JunoHeight != refreshed.JunoHeight {
		t.Fatalf("juno height = %d, want %d", job.Deposit.JunoHeight, refreshed.JunoHeight)
	}
}

func TestMemoryStore_Get_DefensiveCopyWitness(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	var id [32]byte
	id[0] = 0x01
	var cm [32]byte
	cm[0] = 0xaa
	var recip [20]byte
	recip[19] = 0x01

	origWitness := []byte{0x10, 0x20, 0x30}
	if _, _, err := s.UpsertConfirmed(ctx, Deposit{
		DepositID:        id,
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		BaseRecipient:    recip,
		ProofWitnessItem: origWitness,
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	job, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get #1: %v", err)
	}
	if len(job.Deposit.ProofWitnessItem) != len(origWitness) {
		t.Fatalf("witness len mismatch")
	}
	job.Deposit.ProofWitnessItem[0] ^= 0xff

	job2, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get #2: %v", err)
	}
	if job2.Deposit.ProofWitnessItem[0] != origWitness[0] {
		t.Fatalf("store witness mutated by caller")
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

func TestMemoryStore_ListByState(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	mkDeposit := func(tag byte) Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return Deposit{
			DepositID:     id,
			Commitment:    cm,
			LeafIndex:     uint64(tag),
			Amount:        1000 + uint64(tag),
			BaseRecipient: recip,
		}
	}

	d1 := mkDeposit(0x01)
	d2 := mkDeposit(0x02)

	if _, _, err := s.UpsertConfirmed(ctx, d1); err != nil {
		t.Fatalf("UpsertConfirmed d1: %v", err)
	}
	if _, _, err := s.UpsertConfirmed(ctx, d2); err != nil {
		t.Fatalf("UpsertConfirmed d2: %v", err)
	}

	var txHash [32]byte
	txHash[0] = 0x77
	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if err := s.MarkProofRequested(ctx, d2.DepositID, cp); err != nil {
		t.Fatalf("MarkProofRequested d2: %v", err)
	}
	if err := s.SetProofReady(ctx, d2.DepositID, []byte{0x01}); err != nil {
		t.Fatalf("SetProofReady d2: %v", err)
	}
	if err := s.MarkFinalized(ctx, d2.DepositID, txHash); err != nil {
		t.Fatalf("MarkFinalized d2: %v", err)
	}

	confirmed, err := s.ListByState(ctx, StateConfirmed, 10)
	if err != nil {
		t.Fatalf("ListByState confirmed: %v", err)
	}
	if len(confirmed) != 1 {
		t.Fatalf("confirmed len: got %d want 1", len(confirmed))
	}
	if confirmed[0].Deposit.DepositID != d1.DepositID {
		t.Fatalf("confirmed id: got %x want %x", confirmed[0].Deposit.DepositID, d1.DepositID)
	}

	finalized, err := s.ListByState(ctx, StateFinalized, 10)
	if err != nil {
		t.Fatalf("ListByState finalized: %v", err)
	}
	if len(finalized) != 1 {
		t.Fatalf("finalized len: got %d want 1", len(finalized))
	}
	if finalized[0].Deposit.DepositID != d2.DepositID {
		t.Fatalf("finalized id: got %x want %x", finalized[0].Deposit.DepositID, d2.DepositID)
	}

	limited, err := s.ListByState(ctx, StateConfirmed, 1)
	if err != nil {
		t.Fatalf("ListByState confirmed limit=1: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("limited len: got %d want 1", len(limited))
	}
}

func TestMemoryStore_CountByState(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	mkDeposit := func(tag byte) Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return Deposit{
			DepositID:     id,
			Commitment:    cm,
			LeafIndex:     uint64(tag),
			Amount:        1000 + uint64(tag),
			BaseRecipient: recip,
		}
	}

	d1 := mkDeposit(0x11)
	d2 := mkDeposit(0x12)
	d3 := mkDeposit(0x13)

	for _, dep := range []Deposit{d1, d2, d3} {
		if _, _, err := s.UpsertConfirmed(ctx, dep); err != nil {
			t.Fatalf("UpsertConfirmed(%x): %v", dep.DepositID[:4], err)
		}
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if err := s.MarkProofRequested(ctx, d2.DepositID, cp); err != nil {
		t.Fatalf("MarkProofRequested d2: %v", err)
	}
	if err := s.MarkProofRequested(ctx, d3.DepositID, cp); err != nil {
		t.Fatalf("MarkProofRequested d3: %v", err)
	}
	if err := s.SetProofReady(ctx, d3.DepositID, []byte{0x01}); err != nil {
		t.Fatalf("SetProofReady d3: %v", err)
	}
	if err := s.MarkFinalized(ctx, d3.DepositID, [32]byte{0x77}); err != nil {
		t.Fatalf("MarkFinalized d3: %v", err)
	}

	confirmedCount, err := s.CountByState(ctx, StateConfirmed)
	if err != nil {
		t.Fatalf("CountByState confirmed: %v", err)
	}
	if confirmedCount != 1 {
		t.Fatalf("confirmed count: got %d want 1", confirmedCount)
	}

	proofRequestedCount, err := s.CountByState(ctx, StateProofRequested)
	if err != nil {
		t.Fatalf("CountByState proof_requested: %v", err)
	}
	if proofRequestedCount != 1 {
		t.Fatalf("proof_requested count: got %d want 1", proofRequestedCount)
	}

	finalizedCount, err := s.CountByState(ctx, StateFinalized)
	if err != nil {
		t.Fatalf("CountByState finalized: %v", err)
	}
	if finalizedCount != 1 {
		t.Fatalf("finalized count: got %d want 1", finalizedCount)
	}
}

func TestMemoryStore_RepairFinalizedOverridesRejectedState(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()

	var id [32]byte
	id[0] = 0x81

	var cm [32]byte
	cm[0] = 0xb1

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

	var rejectedTxHash [32]byte
	rejectedTxHash[0] = 0x91
	if err := s.MarkRejected(context.Background(), id, "deposit skipped by bridge", rejectedTxHash); err != nil {
		t.Fatalf("MarkRejected: %v", err)
	}

	var mintedTxHash [32]byte
	mintedTxHash[0] = 0x92
	if err := s.RepairFinalized(context.Background(), id, mintedTxHash); err != nil {
		t.Fatalf("RepairFinalized: %v", err)
	}

	job, err := s.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != StateFinalized {
		t.Fatalf("state: got %v want %v", job.State, StateFinalized)
	}
	if job.TxHash != mintedTxHash {
		t.Fatalf("tx hash: got %x want %x", job.TxHash, mintedTxHash)
	}
	if job.RejectionReason != "" {
		t.Fatalf("rejection reason: got %q want empty", job.RejectionReason)
	}
}

func TestMemoryStore_ClaimConfirmed_LeaseBehavior(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	var id [32]byte
	id[0] = 0x01
	var cm [32]byte
	cm[0] = 0xaa
	var recip [20]byte
	recip[0] = 0x11

	if _, _, err := s.UpsertConfirmed(ctx, Deposit{
		DepositID:     id,
		Commitment:    cm,
		LeafIndex:     7,
		Amount:        1000,
		BaseRecipient: recip,
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	first, err := s.ClaimConfirmed(ctx, "worker-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimConfirmed worker-a: %v", err)
	}
	if len(first) != 1 || first[0].Deposit.DepositID != id {
		t.Fatalf("unexpected first claim result")
	}

	other, err := s.ClaimConfirmed(ctx, "worker-b", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimConfirmed worker-b: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("expected worker-b to be excluded while lease active")
	}

	time.Sleep(100 * time.Millisecond)

	afterExpiry, err := s.ClaimConfirmed(ctx, "worker-b", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimConfirmed worker-b after expiry: %v", err)
	}
	if len(afterExpiry) != 1 || afterExpiry[0].Deposit.DepositID != id {
		t.Fatalf("expected worker-b to claim after lease expiry")
	}
}

func TestMemoryStore_ClaimConfirmed_ReclaimsProofRequestedAfterLeaseExpiry(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	var id [32]byte
	id[0] = 0x31
	var cm [32]byte
	cm[0] = 0xaa
	var recip [20]byte
	recip[0] = 0x22

	if _, _, err := s.UpsertConfirmed(ctx, Deposit{
		DepositID:     id,
		Commitment:    cm,
		LeafIndex:     7,
		Amount:        1000,
		BaseRecipient: recip,
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	if claimed, err := s.ClaimConfirmed(ctx, "worker-a", 80*time.Millisecond, 10); err != nil {
		t.Fatalf("ClaimConfirmed worker-a: %v", err)
	} else if len(claimed) != 1 {
		t.Fatalf("expected worker-a claim, got %d", len(claimed))
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if err := s.MarkProofRequested(ctx, id, cp); err != nil {
		t.Fatalf("MarkProofRequested: %v", err)
	}
	if sameOwner, err := s.ClaimConfirmed(ctx, "worker-a", 80*time.Millisecond, 10); err != nil {
		t.Fatalf("ClaimConfirmed same owner: %v", err)
	} else if len(sameOwner) != 1 {
		t.Fatalf("expected same owner to reclaim proof-requested job, got %d", len(sameOwner))
	}
	if other, err := s.ClaimConfirmed(ctx, "worker-b", 80*time.Millisecond, 10); err != nil {
		t.Fatalf("ClaimConfirmed worker-b: %v", err)
	} else if len(other) != 0 {
		t.Fatalf("expected other worker to be excluded while proof-request lease active")
	}

	time.Sleep(100 * time.Millisecond)

	if afterExpiry, err := s.ClaimConfirmed(ctx, "worker-b", 80*time.Millisecond, 10); err != nil {
		t.Fatalf("ClaimConfirmed worker-b after expiry: %v", err)
	} else if len(afterExpiry) != 1 || afterExpiry[0].State != StateProofRequested {
		t.Fatalf("expected worker-b to reclaim proof-requested job after expiry, got %+v", afterExpiry)
	}
}

func TestMemoryStore_PrepareNextBatch_PersistsAssemblingWindow(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	mkDeposit := func(tag byte) Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return Deposit{
			DepositID:     id,
			Commitment:    cm,
			LeafIndex:     uint64(tag),
			Amount:        1000 + uint64(tag),
			BaseRecipient: recip,
		}
	}

	d1 := mkDeposit(0x01)
	d2 := mkDeposit(0x02)
	if _, _, err := s.UpsertConfirmed(ctx, d1); err != nil {
		t.Fatalf("UpsertConfirmed(d1): %v", err)
	}
	if _, _, err := s.UpsertConfirmed(ctx, d2); err != nil {
		t.Fatalf("UpsertConfirmed(d2): %v", err)
	}

	var batchID [32]byte
	batchID[0] = 0xaa
	batch, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, batchID, 2, 3*time.Minute, 10, now)
	if err != nil {
		t.Fatalf("PrepareNextBatch #1: %v", err)
	}
	if ready {
		t.Fatalf("expected assembling batch to stay open")
	}
	if batch.BatchID != batchID {
		t.Fatalf("batch id mismatch: got=%x want=%x", batch.BatchID, batchID)
	}
	if got, want := batch.State, BatchStateAssembling; got != want {
		t.Fatalf("batch state: got=%s want=%s", got, want)
	}
	if len(batch.DepositIDs) != 1 || batch.DepositIDs[0] != d1.DepositID {
		t.Fatalf("assembled deposits after first prepare: got=%x", batch.DepositIDs)
	}

	persisted, err := s.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if got, want := len(persisted.DepositIDs), 1; got != want {
		t.Fatalf("persisted deposit count: got=%d want=%d", got, want)
	}

	var ignoredNewBatchID [32]byte
	ignoredNewBatchID[0] = 0xbb
	readyBatch, ready, err := s.PrepareNextBatch(ctx, "worker-b", time.Minute, ignoredNewBatchID, 2, 3*time.Minute, 10, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("PrepareNextBatch #2: %v", err)
	}
	if !ready {
		t.Fatalf("expected batch to close at max items")
	}
	if readyBatch.BatchID != batchID {
		t.Fatalf("expected existing durable batch to be reused: got=%x want=%x", readyBatch.BatchID, batchID)
	}
	if got, want := readyBatch.State, BatchStateClosed; got != want {
		t.Fatalf("ready batch state: got=%s want=%s", got, want)
	}
	if got, want := len(readyBatch.DepositIDs), 2; got != want {
		t.Fatalf("ready batch deposit count: got=%d want=%d", got, want)
	}
}

func TestMemoryStore_PrepareNextBatch_ClosesOnAge(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	var id [32]byte
	id[0] = 0x01
	var cm [32]byte
	cm[0] = 0x01
	var recip [20]byte
	recip[19] = 0x01
	if _, _, err := s.UpsertConfirmed(ctx, Deposit{
		DepositID:     id,
		Commitment:    cm,
		LeafIndex:     1,
		Amount:        1000,
		BaseRecipient: recip,
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	var batchID [32]byte
	batchID[0] = 0xcc
	if _, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, batchID, 25, 3*time.Minute, 10, now); err != nil {
		t.Fatalf("PrepareNextBatch #1: %v", err)
	} else if ready {
		t.Fatalf("expected first prepare to keep batch open")
	}

	batch, ready, err := s.PrepareNextBatch(ctx, "worker-b", time.Minute, [32]byte{}, 25, 3*time.Minute, 10, now.Add(4*time.Minute))
	if err != nil {
		t.Fatalf("PrepareNextBatch #2: %v", err)
	}
	if !ready {
		t.Fatalf("expected aged batch to close")
	}
	if batch.BatchID != batchID {
		t.Fatalf("batch id mismatch: got=%x want=%x", batch.BatchID, batchID)
	}
	if got, want := batch.State, BatchStateClosed; got != want {
		t.Fatalf("batch state: got=%s want=%s", got, want)
	}
}

func TestMemoryStore_SplitBatch(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	mkDeposit := func(tag byte) Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return Deposit{
			DepositID:     id,
			Commitment:    cm,
			LeafIndex:     uint64(tag),
			Amount:        1000 + uint64(tag),
			BaseRecipient: recip,
		}
	}
	d1 := mkDeposit(0x01)
	d2 := mkDeposit(0x02)
	if _, _, err := s.UpsertConfirmed(ctx, d1); err != nil {
		t.Fatalf("UpsertConfirmed(d1): %v", err)
	}
	if _, _, err := s.UpsertConfirmed(ctx, d2); err != nil {
		t.Fatalf("UpsertConfirmed(d2): %v", err)
	}

	var batchID [32]byte
	batchID[0] = 0xdd
	if _, _, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, batchID, 2, 3*time.Minute, 10, now); err != nil {
		t.Fatalf("PrepareNextBatch #1: %v", err)
	}
	batch, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, [32]byte{}, 2, 3*time.Minute, 10, now)
	if err != nil {
		t.Fatalf("PrepareNextBatch #2: %v", err)
	}
	if !ready || batch.State != BatchStateClosed {
		t.Fatalf("expected closed batch before split, got state=%s ready=%v", batch.State, ready)
	}

	var splitBatchID [32]byte
	splitBatchID[0] = 0xee
	left, right, err := s.SplitBatch(ctx, "worker-a", batchID, splitBatchID, [][32]byte{d2.DepositID})
	if err != nil {
		t.Fatalf("SplitBatch: %v", err)
	}
	if got, want := len(left.DepositIDs), 1; got != want {
		t.Fatalf("left count: got=%d want=%d", got, want)
	}
	if got, want := len(right.DepositIDs), 1; got != want {
		t.Fatalf("right count: got=%d want=%d", got, want)
	}
	if left.DepositIDs[0] != d1.DepositID {
		t.Fatalf("left deposit mismatch: got=%x want=%x", left.DepositIDs[0], d1.DepositID)
	}
	if right.DepositIDs[0] != d2.DepositID {
		t.Fatalf("right deposit mismatch: got=%x want=%x", right.DepositIDs[0], d2.DepositID)
	}
}

func TestMemoryStore_SplitBatch_ResetsProofRequestedState(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()

	mkDeposit := func(tag byte) Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return Deposit{
			DepositID:     id,
			Commitment:    cm,
			LeafIndex:     uint64(tag),
			Amount:        1000 + uint64(tag),
			BaseRecipient: recip,
		}
	}
	d1 := mkDeposit(0x11)
	d2 := mkDeposit(0x12)
	for _, dep := range []Deposit{d1, d2} {
		if _, _, err := s.UpsertConfirmed(ctx, dep); err != nil {
			t.Fatalf("UpsertConfirmed(%x): %v", dep.DepositID[:4], err)
		}
	}

	batchID := [32]byte{0xad}
	if _, _, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, batchID, 2, 3*time.Minute, 10, now); err != nil {
		t.Fatalf("PrepareNextBatch #1: %v", err)
	}
	batch, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, [32]byte{}, 2, 3*time.Minute, 10, now)
	if err != nil {
		t.Fatalf("PrepareNextBatch #2: %v", err)
	}
	if !ready || batch.State != BatchStateClosed {
		t.Fatalf("expected closed batch before split, got state=%s ready=%v", batch.State, ready)
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := s.MarkBatchProofRequested(ctx, "worker-a", batchID, cp); err != nil {
		t.Fatalf("MarkBatchProofRequested: %v", err)
	}

	splitBatchID := [32]byte{0xae}
	left, right, err := s.SplitBatch(ctx, "worker-a", batchID, splitBatchID, [][32]byte{d2.DepositID})
	if err != nil {
		t.Fatalf("SplitBatch: %v", err)
	}
	if left.State != BatchStateClosed || right.State != BatchStateClosed {
		t.Fatalf("split batches must be closed: left=%s right=%s", left.State, right.State)
	}
	if left.ProofRequested || right.ProofRequested {
		t.Fatalf("split batches must clear proof_requested flag")
	}
	if left.Checkpoint != (checkpoint.Checkpoint{}) || right.Checkpoint != (checkpoint.Checkpoint{}) {
		t.Fatalf("split batches must clear checkpoint state")
	}

	for _, depositID := range [][32]byte{d1.DepositID, d2.DepositID} {
		job, err := s.Get(ctx, depositID)
		if err != nil {
			t.Fatalf("Get(%x): %v", depositID[:4], err)
		}
		if job.State != StateConfirmed {
			t.Fatalf("job %x state: got=%s want=%s", depositID[:4], job.State, StateConfirmed)
		}
	}
}

func TestMemoryStore_UpsertConfirmed_SourceEventReplay(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	src := &SourceEvent{
		ChainID:  84532,
		LogIndex: 7,
	}
	src.TxHash[0] = 0xaa

	var id [32]byte
	id[0] = 0x41
	var cm [32]byte
	cm[0] = 0xca
	var recip [20]byte
	recip[19] = 0x04

	dep := Deposit{
		DepositID:     id,
		Commitment:    cm,
		LeafIndex:     7,
		Amount:        1000,
		BaseRecipient: recip,
		SourceEvent:   src,
	}

	if _, created, err := s.UpsertConfirmed(ctx, dep); err != nil {
		t.Fatalf("UpsertConfirmed #1: %v", err)
	} else if !created {
		t.Fatalf("expected created=true")
	}

	if _, created, err := s.UpsertConfirmed(ctx, dep); err != nil {
		t.Fatalf("UpsertConfirmed replay: %v", err)
	} else if created {
		t.Fatalf("expected replay created=false")
	}

	conflict := dep
	conflict.DepositID[0] = 0x42
	conflict.Commitment[0] = 0xcb
	conflict.LeafIndex = 8
	if _, _, err := s.UpsertConfirmed(ctx, conflict); !errors.Is(err, ErrDepositMismatch) {
		t.Fatalf("expected ErrDepositMismatch on conflicting source replay, got %v", err)
	}
}

func TestMemoryStore_MarkBatchSubmitted(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	mkDeposit := func(tag byte) Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return Deposit{
			DepositID:     id,
			Commitment:    cm,
			LeafIndex:     uint64(tag),
			Amount:        1000 + uint64(tag),
			BaseRecipient: recip,
		}
	}

	d1 := mkDeposit(0x01)
	d2 := mkDeposit(0x02)
	if _, _, err := s.UpsertConfirmed(ctx, d1); err != nil {
		t.Fatalf("UpsertConfirmed d1: %v", err)
	}
	if _, _, err := s.UpsertConfirmed(ctx, d2); err != nil {
		t.Fatalf("UpsertConfirmed d2: %v", err)
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	seal := []byte{0x99}
	batchID := [32]byte{0x42}
	operatorSigs := [][]byte{{0xaa}, {0xbb}}

	attempt, err := s.MarkBatchSubmitted(ctx, "worker-a", batchID, [][32]byte{d1.DepositID, d2.DepositID}, cp, operatorSigs, seal)
	if err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	if attempt.BatchID != batchID {
		t.Fatalf("batch id: got %x want %x", attempt.BatchID, batchID)
	}
	if attempt.Owner != "worker-a" {
		t.Fatalf("owner: got %q want %q", attempt.Owner, "worker-a")
	}
	if attempt.Epoch != 1 {
		t.Fatalf("epoch: got %d want 1", attempt.Epoch)
	}
	if attempt.Checkpoint != cp {
		t.Fatalf("checkpoint mismatch")
	}
	if !bytes.Equal(attempt.ProofSeal, seal) {
		t.Fatalf("proof seal mismatch")
	}
	if len(attempt.OperatorSignatures) != len(operatorSigs) {
		t.Fatalf("operator signatures len: got %d want %d", len(attempt.OperatorSignatures), len(operatorSigs))
	}
	if err := s.SetBatchSubmissionTxHash(ctx, batchID, [32]byte{0x77}); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	claimed, err := s.ClaimSubmittedAttempts(ctx, "worker-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(claimed) != 1 {
		t.Fatalf("claimed attempts len: got %d want 1", len(claimed))
	}
	if claimed[0].TxHash != ([32]byte{0x77}) {
		t.Fatalf("tx hash mismatch")
	}

	if _, err := s.MarkBatchSubmitted(ctx, "worker-a", batchID, [][32]byte{d1.DepositID, d2.DepositID}, cp, operatorSigs, seal); err != nil {
		t.Fatalf("MarkBatchSubmitted replay: %v", err)
	}

	j1, err := s.Get(ctx, d1.DepositID)
	if err != nil {
		t.Fatalf("Get d1: %v", err)
	}
	j2, err := s.Get(ctx, d2.DepositID)
	if err != nil {
		t.Fatalf("Get d2: %v", err)
	}
	if j1.State != StateSubmitted || j2.State != StateSubmitted {
		t.Fatalf("unexpected states: d1=%v d2=%v", j1.State, j2.State)
	}
	if j1.Checkpoint != cp || j2.Checkpoint != cp {
		t.Fatalf("checkpoint mismatch")
	}
	if string(j1.ProofSeal) != string(seal) || string(j2.ProofSeal) != string(seal) {
		t.Fatalf("proof seal mismatch")
	}

	confirmed, err := s.ClaimConfirmed(ctx, "worker-b", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimConfirmed after submit: %v", err)
	}
	if len(confirmed) != 0 {
		t.Fatalf("expected submitted deposits to be excluded from ClaimConfirmed")
	}
}

func TestMemoryStore_SubmittedAttemptsHonorClaimTTLAndClearOnFinalize(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	var id [32]byte
	id[0] = 0x01
	var cm [32]byte
	cm[0] = 0xaa
	var recip [20]byte
	recip[0] = 0x11

	if _, _, err := s.UpsertConfirmed(ctx, Deposit{
		DepositID:     id,
		Commitment:    cm,
		LeafIndex:     7,
		Amount:        1000,
		BaseRecipient: recip,
	}); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	batchID := [32]byte{0x55}
	seal := []byte{0x99}

	if _, err := s.MarkBatchSubmitted(ctx, "worker-a", batchID, [][32]byte{id}, cp, [][]byte{{0xaa}}, seal); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}

	preClaimOther, err := s.ClaimSubmittedAttempts(ctx, "worker-b", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts worker-b before owner claim: %v", err)
	}
	if len(preClaimOther) != 0 {
		t.Fatalf("expected worker-b exclusion before owner claim while fresh submit attempt lease is active")
	}

	first, err := s.ClaimSubmittedAttempts(ctx, "worker-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts worker-a: %v", err)
	}
	if len(first) != 1 || first[0].BatchID != batchID {
		t.Fatalf("unexpected first claim result")
	}

	other, err := s.ClaimSubmittedAttempts(ctx, "worker-b", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts worker-b: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("expected worker-b exclusion while attempt lease active")
	}

	time.Sleep(100 * time.Millisecond)

	afterExpiry, err := s.ClaimSubmittedAttempts(ctx, "worker-b", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts worker-b after expiry: %v", err)
	}
	if len(afterExpiry) != 1 || afterExpiry[0].BatchID != batchID {
		t.Fatalf("expected worker-b to claim after expiry")
	}

	var txHash [32]byte
	txHash[0] = 0x77
	if err := s.SetBatchSubmissionTxHash(ctx, batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}
	if err := s.FinalizeBatch(ctx, [][32]byte{id}, cp, seal, txHash); err != nil {
		t.Fatalf("FinalizeBatch: %v", err)
	}

	attempts, err := s.ClaimSubmittedAttempts(ctx, "worker-b", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts after finalize: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected submitted attempts to clear after finalize")
	}
}

func TestMemoryStore_ClaimBatchesHonorsOlderThanAndLease(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	d1 := Deposit{
		DepositID:     [32]byte{0x41},
		Commitment:    [32]byte{0x42},
		LeafIndex:     1,
		Amount:        1000,
		BaseRecipient: [20]byte{0x01},
	}
	d2 := Deposit{
		DepositID:     [32]byte{0x43},
		Commitment:    [32]byte{0x44},
		LeafIndex:     2,
		Amount:        2000,
		BaseRecipient: [20]byte{0x02},
	}
	if _, _, err := s.UpsertConfirmed(ctx, d1); err != nil {
		t.Fatalf("UpsertConfirmed d1: %v", err)
	}
	if _, _, err := s.UpsertConfirmed(ctx, d2); err != nil {
		t.Fatalf("UpsertConfirmed d2: %v", err)
	}

	now := time.Date(2020, 3, 20, 12, 0, 0, 0, time.UTC)
	batchID := [32]byte{0x45}
	if _, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, batchID, 2, 3*time.Minute, 10, now); err != nil {
		t.Fatalf("PrepareNextBatch #1: %v", err)
	} else if ready {
		t.Fatalf("expected assembling batch on first prepare")
	}
	batch, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, [32]byte{}, 2, 3*time.Minute, 10, now)
	if err != nil {
		t.Fatalf("PrepareNextBatch #2: %v", err)
	}
	if !ready {
		t.Fatalf("expected closed batch to be ready")
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := s.MarkBatchProofRequested(ctx, "worker-a", batch.BatchID, cp); err != nil {
		t.Fatalf("MarkBatchProofRequested: %v", err)
	}

	claimed, err := s.ClaimBatches(ctx, "repair-a", 80*time.Millisecond, []BatchState{BatchStateProofRequested}, time.Now().Add(time.Second), 10)
	if err != nil {
		t.Fatalf("ClaimBatches repair-a: %v", err)
	}
	if len(claimed) != 1 || claimed[0].BatchID != batchID {
		t.Fatalf("unexpected claimed batches: %#v", claimed)
	}

	other, err := s.ClaimBatches(ctx, "repair-b", 80*time.Millisecond, []BatchState{BatchStateProofRequested}, time.Now().Add(time.Second), 10)
	if err != nil {
		t.Fatalf("ClaimBatches repair-b: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("expected repair-b exclusion while batch lease active")
	}

	time.Sleep(100 * time.Millisecond)

	afterExpiry, err := s.ClaimBatches(ctx, "repair-b", 80*time.Millisecond, []BatchState{BatchStateProofRequested}, time.Now().Add(time.Second), 10)
	if err != nil {
		t.Fatalf("ClaimBatches repair-b after expiry: %v", err)
	}
	if len(afterExpiry) != 1 || afterExpiry[0].BatchID != batchID {
		t.Fatalf("expected repair-b to claim batch after expiry")
	}

	tooOld, err := s.ClaimBatches(ctx, "repair-c", 80*time.Millisecond, []BatchState{BatchStateProofRequested}, time.Now().Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("ClaimBatches repair-c olderThan: %v", err)
	}
	if len(tooOld) != 0 {
		t.Fatalf("expected olderThan filter to exclude recently updated batch")
	}
}

func TestMemoryStore_ResetBatchClearsSubmittedMetadataAndRequeuesDeposits(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	d1 := Deposit{
		DepositID:     [32]byte{0x51},
		Commitment:    [32]byte{0x52},
		LeafIndex:     1,
		Amount:        1000,
		BaseRecipient: [20]byte{0x03},
	}
	d2 := Deposit{
		DepositID:     [32]byte{0x53},
		Commitment:    [32]byte{0x54},
		LeafIndex:     2,
		Amount:        2000,
		BaseRecipient: [20]byte{0x04},
	}
	if _, _, err := s.UpsertConfirmed(ctx, d1); err != nil {
		t.Fatalf("UpsertConfirmed d1: %v", err)
	}
	if _, _, err := s.UpsertConfirmed(ctx, d2); err != nil {
		t.Fatalf("UpsertConfirmed d2: %v", err)
	}

	now := time.Date(2020, 3, 20, 12, 0, 0, 0, time.UTC)
	batchID := [32]byte{0x55}
	if _, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, batchID, 2, 3*time.Minute, 10, now); err != nil {
		t.Fatalf("PrepareNextBatch #1: %v", err)
	} else if ready {
		t.Fatalf("expected assembling batch on first prepare")
	}
	batch, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, [32]byte{}, 2, 3*time.Minute, 10, now)
	if err != nil {
		t.Fatalf("PrepareNextBatch #2: %v", err)
	}
	if !ready {
		t.Fatalf("expected closed batch to be ready")
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	if _, err := s.MarkBatchProofRequested(ctx, "worker-a", batch.BatchID, cp); err != nil {
		t.Fatalf("MarkBatchProofRequested: %v", err)
	}
	if _, err := s.MarkBatchProofReady(ctx, "worker-a", batch.BatchID, cp, [][]byte{{0xaa}}, []byte{0x99}); err != nil {
		t.Fatalf("MarkBatchProofReady: %v", err)
	}
	if _, err := s.MarkBatchSubmitted(ctx, "worker-a", batch.BatchID, batch.DepositIDs, cp, [][]byte{{0xaa}}, []byte{0x99}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	if err := s.SetBatchSubmissionTxHash(ctx, batch.BatchID, [32]byte{0xde, 0xad}); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	reset, err := s.ResetBatch(ctx, "repair-a", batchID)
	if err != nil {
		t.Fatalf("ResetBatch: %v", err)
	}
	if reset.State != BatchStateClosed {
		t.Fatalf("reset state: got %s want %s", reset.State, BatchStateClosed)
	}
	if reset.Checkpoint != (checkpoint.Checkpoint{}) {
		t.Fatalf("expected reset checkpoint to be cleared, got %+v", reset.Checkpoint)
	}
	if reset.ProofRequested {
		t.Fatalf("expected proof_requested to be false after reset")
	}
	if len(reset.OperatorSignatures) != 0 {
		t.Fatalf("expected operator signatures to be cleared")
	}
	if len(reset.ProofSeal) != 0 {
		t.Fatalf("expected proof seal to be cleared")
	}
	if reset.TxHash != ([32]byte{}) {
		t.Fatalf("expected reset tx hash to be cleared")
	}

	attempts, err := s.ClaimSubmittedAttempts(ctx, "repair-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected submitted batch attempts to clear after reset")
	}

	for _, depositID := range batch.DepositIDs {
		job, err := s.Get(ctx, depositID)
		if err != nil {
			t.Fatalf("Get(%x): %v", depositID[:4], err)
		}
		if job.State != StateConfirmed {
			t.Fatalf("job %x state: got %s want %s", depositID[:4], job.State, StateConfirmed)
		}
		if job.Checkpoint != (checkpoint.Checkpoint{}) {
			t.Fatalf("job %x checkpoint not cleared: %+v", depositID[:4], job.Checkpoint)
		}
		if len(job.ProofSeal) != 0 {
			t.Fatalf("job %x proof seal should be cleared", depositID[:4])
		}
		if job.TxHash != ([32]byte{}) {
			t.Fatalf("job %x tx hash should be cleared", depositID[:4])
		}
	}

	confirmed, err := s.ClaimConfirmed(ctx, "worker-b", time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimConfirmed: %v", err)
	}
	if len(confirmed) != 2 {
		t.Fatalf("expected two confirmed deposits after reset, got %d", len(confirmed))
	}
}

func TestMemoryStore_RequeueSubmittedBatch_ClearsRecordedTxHash(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	var id [32]byte
	id[0] = 0x31

	var cm [32]byte
	cm[0] = 0x32

	var recip [20]byte
	recip[19] = 0x33

	dep := Deposit{
		DepositID:     id,
		Commitment:    cm,
		LeafIndex:     7,
		Amount:        1000,
		BaseRecipient: recip,
	}
	if _, _, err := s.UpsertConfirmed(ctx, dep); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	batchID := [32]byte{0x34}
	if _, err := s.MarkBatchSubmitted(ctx, "worker-a", batchID, [][32]byte{id}, cp, [][]byte{{0xaa}}, []byte{0x99}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	var txHash [32]byte
	txHash[0] = 0x77
	if err := s.SetBatchSubmissionTxHash(ctx, batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	if err := s.RequeueSubmittedBatch(ctx, batchID); err != nil {
		t.Fatalf("RequeueSubmittedBatch: %v", err)
	}

	job, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != StateConfirmed {
		t.Fatalf("job state: got %s want %s", job.State, StateConfirmed)
	}
	if job.TxHash != ([32]byte{}) {
		t.Fatalf("expected tx hash to be cleared, got %x", job.TxHash)
	}

	claimed, err := s.ClaimSubmittedAttempts(ctx, "worker-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(claimed) != 0 {
		t.Fatalf("expected submitted batch attempts to be cleared, got %d", len(claimed))
	}
}

func TestMemoryStore_ApplyBatchOutcome_RequeuesUnresolvedDeposits(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	var finalizedID [32]byte
	finalizedID[0] = 0x41
	var unresolvedID [32]byte
	unresolvedID[0] = 0x42
	var cm [32]byte
	cm[0] = 0x43
	var recip [20]byte
	recip[19] = 0x44

	for _, id := range [][32]byte{finalizedID, unresolvedID} {
		if _, _, err := s.UpsertConfirmed(ctx, Deposit{
			DepositID:     id,
			Commitment:    cm,
			LeafIndex:     7,
			Amount:        1000,
			BaseRecipient: recip,
		}); err != nil {
			t.Fatalf("UpsertConfirmed(%x): %v", id[:1], err)
		}
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	batchID := [32]byte{0x45}
	if _, err := s.MarkBatchSubmitted(ctx, "owner-a", batchID, [][32]byte{finalizedID, unresolvedID}, cp, [][]byte{{0x01}}, []byte{0x02}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}
	var txHash [32]byte
	txHash[0] = 0x55
	if err := s.SetBatchSubmissionTxHash(ctx, batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	if err := s.ApplyBatchOutcome(ctx, batchID, txHash, [][32]byte{finalizedID}, nil, "deposit skipped by bridge"); err != nil {
		t.Fatalf("ApplyBatchOutcome: %v", err)
	}

	finalizedJob, err := s.Get(ctx, finalizedID)
	if err != nil {
		t.Fatalf("Get(finalized): %v", err)
	}
	if finalizedJob.State != StateFinalized {
		t.Fatalf("finalized state: got %s want %s", finalizedJob.State, StateFinalized)
	}

	unresolvedJob, err := s.Get(ctx, unresolvedID)
	if err != nil {
		t.Fatalf("Get(unresolved): %v", err)
	}
	if unresolvedJob.State != StateConfirmed {
		t.Fatalf("unresolved state: got %s want %s", unresolvedJob.State, StateConfirmed)
	}
	if unresolvedJob.TxHash != ([32]byte{}) {
		t.Fatalf("unresolved tx hash should be cleared, got %x", unresolvedJob.TxHash)
	}
	if unresolvedJob.RejectionReason != "" {
		t.Fatalf("unresolved rejection reason should be cleared, got %q", unresolvedJob.RejectionReason)
	}

	batch, err := s.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if batch.State != BatchStateClosed {
		t.Fatalf("batch state: got %s want %s", batch.State, BatchStateClosed)
	}
	if batch.TxHash != ([32]byte{}) {
		t.Fatalf("batch tx hash should be cleared, got %x", batch.TxHash)
	}

	claimed, err := s.ClaimSubmittedAttempts(ctx, "worker-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(claimed) != 0 {
		t.Fatalf("expected submitted batch attempts to be cleared, got %d", len(claimed))
	}
}

func TestMemoryStore_FinalizeBatch_Atomic(t *testing.T) {
	t.Parallel()

	s := NewMemoryStore()
	ctx := context.Background()

	mkDeposit := func(tag byte) Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return Deposit{
			DepositID:     id,
			Commitment:    cm,
			LeafIndex:     uint64(tag),
			Amount:        1000 + uint64(tag),
			BaseRecipient: recip,
		}
	}

	d1 := mkDeposit(0x01)
	d2 := mkDeposit(0x02)

	if _, _, err := s.UpsertConfirmed(ctx, d1); err != nil {
		t.Fatalf("UpsertConfirmed d1: %v", err)
	}
	if _, _, err := s.UpsertConfirmed(ctx, d2); err != nil {
		t.Fatalf("UpsertConfirmed d2: %v", err)
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	seal := []byte{0x99}
	var txHash [32]byte
	txHash[0] = 0x77

	var missing [32]byte
	missing[0] = 0xff
	if err := s.FinalizeBatch(ctx, [][32]byte{d1.DepositID, missing, d2.DepositID}, cp, seal, txHash); err == nil {
		t.Fatalf("expected finalize batch error")
	}

	j1, err := s.Get(ctx, d1.DepositID)
	if err != nil {
		t.Fatalf("Get d1: %v", err)
	}
	if j1.State != StateConfirmed {
		t.Fatalf("d1 state changed on failed batch: got %v want %v", j1.State, StateConfirmed)
	}
	j2, err := s.Get(ctx, d2.DepositID)
	if err != nil {
		t.Fatalf("Get d2: %v", err)
	}
	if j2.State != StateConfirmed {
		t.Fatalf("d2 state changed on failed batch: got %v want %v", j2.State, StateConfirmed)
	}

	if err := s.FinalizeBatch(ctx, [][32]byte{d1.DepositID, d2.DepositID}, cp, seal, txHash); err != nil {
		t.Fatalf("FinalizeBatch: %v", err)
	}
	j1, err = s.Get(ctx, d1.DepositID)
	if err != nil {
		t.Fatalf("Get d1 after finalize: %v", err)
	}
	j2, err = s.Get(ctx, d2.DepositID)
	if err != nil {
		t.Fatalf("Get d2 after finalize: %v", err)
	}
	if j1.State != StateFinalized || j2.State != StateFinalized {
		t.Fatalf("unexpected states after finalize: d1=%v d2=%v", j1.State, j2.State)
	}
	if j1.TxHash != txHash || j2.TxHash != txHash {
		t.Fatalf("tx hash mismatch")
	}

	// Idempotent replay with same tx hash.
	if err := s.FinalizeBatch(ctx, [][32]byte{d1.DepositID, d2.DepositID}, cp, seal, txHash); err != nil {
		t.Fatalf("FinalizeBatch replay: %v", err)
	}

	var otherTx [32]byte
	otherTx[0] = 0x55
	if err := s.FinalizeBatch(ctx, [][32]byte{d1.DepositID}, cp, seal, otherTx); err == nil {
		t.Fatalf("expected tx hash mismatch on finalized deposit")
	}
}
