package deposit

import (
	"bytes"
	"context"
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
