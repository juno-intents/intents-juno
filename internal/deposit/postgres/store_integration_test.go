//go:build integration

package postgres

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/deposit"
)

func TestStore_StateMachine(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	// Pin for deterministic integration tests.
	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id [32]byte
	id[0] = 0x01
	var cm [32]byte
	cm[0] = 0xaa
	var recip [20]byte
	copy(recip[:], common.HexToAddress("0x0000000000000000000000000000000000000456").Bytes())

	d := deposit.Deposit{
		DepositID:        id,
		Commitment:       cm,
		LeafIndex:        7,
		Amount:           1000,
		BaseRecipient:    recip,
		ProofWitnessItem: bytes.Repeat([]byte{0x01}, 1848),
	}

	job, created, err := s.UpsertConfirmed(ctx, d)
	if err != nil {
		t.Fatalf("UpsertConfirmed #1: %v", err)
	}
	if !created {
		t.Fatalf("expected created=true")
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %v want %v", job.State, deposit.StateConfirmed)
	}

	_, created, err = s.UpsertConfirmed(ctx, d)
	if err != nil {
		t.Fatalf("UpsertConfirmed #2: %v", err)
	}
	if created {
		t.Fatalf("expected created=false")
	}

	confirmed, err := s.ListByState(ctx, deposit.StateConfirmed, 10)
	if err != nil {
		t.Fatalf("ListByState confirmed: %v", err)
	}
	if len(confirmed) != 1 {
		t.Fatalf("confirmed len: got %d want 1", len(confirmed))
	}
	if confirmed[0].Deposit.DepositID != id {
		t.Fatalf("confirmed deposit id mismatch")
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
	if err := s.SetProofReady(ctx, id, []byte{0x02}); err != nil {
		t.Fatalf("SetProofReady: %v", err)
	}

	var txHash [32]byte
	txHash[0] = 0x77
	if err := s.MarkFinalized(ctx, id, txHash); err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}

	// Idempotent.
	if err := s.MarkFinalized(ctx, id, txHash); err != nil {
		t.Fatalf("MarkFinalized #2: %v", err)
	}

	got, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.State != deposit.StateFinalized {
		t.Fatalf("state: got %v want %v", got.State, deposit.StateFinalized)
	}

	finalized, err := s.ListByState(ctx, deposit.StateFinalized, 10)
	if err != nil {
		t.Fatalf("ListByState finalized: %v", err)
	}
	if len(finalized) != 1 {
		t.Fatalf("finalized len: got %d want 1", len(finalized))
	}
	if finalized[0].Deposit.DepositID != id {
		t.Fatalf("finalized deposit id mismatch")
	}

	d2 := d
	d2.Amount = 2000
	_, _, err = s.UpsertConfirmed(ctx, d2)
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestStore_CountByState(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	mkDeposit := func(tag byte) deposit.Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return deposit.Deposit{
			DepositID:        id,
			Commitment:       cm,
			LeafIndex:        uint64(tag),
			Amount:           1000 + uint64(tag),
			BaseRecipient:    recip,
			ProofWitnessItem: bytes.Repeat([]byte{tag}, 1848),
		}
	}

	d1 := mkDeposit(0x21)
	d2 := mkDeposit(0x22)
	d3 := mkDeposit(0x23)
	for _, dep := range []deposit.Deposit{d1, d2, d3} {
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

	confirmedCount, err := s.CountByState(ctx, deposit.StateConfirmed)
	if err != nil {
		t.Fatalf("CountByState confirmed: %v", err)
	}
	if confirmedCount != 1 {
		t.Fatalf("confirmed count: got %d want 1", confirmedCount)
	}

	proofRequestedCount, err := s.CountByState(ctx, deposit.StateProofRequested)
	if err != nil {
		t.Fatalf("CountByState proof_requested: %v", err)
	}
	if proofRequestedCount != 1 {
		t.Fatalf("proof_requested count: got %d want 1", proofRequestedCount)
	}

	finalizedCount, err := s.CountByState(ctx, deposit.StateFinalized)
	if err != nil {
		t.Fatalf("CountByState finalized: %v", err)
	}
	if finalizedCount != 1 {
		t.Fatalf("finalized count: got %d want 1", finalizedCount)
	}
}

func TestStore_UpsertSeen_RefreshesWitnessWithoutMismatch(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id [32]byte
	id[0] = 0x21
	var cm [32]byte
	cm[0] = 0xcc
	var recip [20]byte
	recip[19] = 0x03

	original := deposit.Deposit{
		DepositID:        id,
		Commitment:       cm,
		LeafIndex:        11,
		Amount:           3000,
		BaseRecipient:    recip,
		ProofWitnessItem: bytes.Repeat([]byte{0x01}, 1848),
		JunoHeight:       111,
	}

	if _, created, err := s.UpsertSeen(ctx, original); err != nil {
		t.Fatalf("UpsertSeen #1: %v", err)
	} else if !created {
		t.Fatalf("expected created=true")
	}

	refreshed := original
	refreshed.ProofWitnessItem = bytes.Repeat([]byte{0x02}, 1848)
	refreshed.JunoHeight = 222

	job, created, err := s.UpsertSeen(ctx, refreshed)
	if err != nil {
		t.Fatalf("UpsertSeen #2: %v", err)
	}
	if created {
		t.Fatalf("expected created=false")
	}
	if !bytes.Equal(job.Deposit.ProofWitnessItem, refreshed.ProofWitnessItem) {
		t.Fatalf("witness = %x, want %x", job.Deposit.ProofWitnessItem[:8], refreshed.ProofWitnessItem[:8])
	}
	if job.Deposit.JunoHeight != refreshed.JunoHeight {
		t.Fatalf("juno height = %d, want %d", job.Deposit.JunoHeight, refreshed.JunoHeight)
	}
}

func TestStore_UpsertSeen_AllowsWitnessRefresh(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id [32]byte
	id[0] = 0x22
	var cm [32]byte
	cm[0] = 0xcc
	var recip [20]byte
	copy(recip[:], common.HexToAddress("0x0000000000000000000000000000000000000789").Bytes())

	original := deposit.Deposit{
		DepositID:        id,
		Commitment:       cm,
		LeafIndex:        11,
		Amount:           3000,
		BaseRecipient:    recip,
		ProofWitnessItem: bytes.Repeat([]byte{0x01}, 1848),
		JunoHeight:       123,
	}
	if _, created, err := s.UpsertSeen(ctx, original); err != nil {
		t.Fatalf("UpsertSeen #1: %v", err)
	} else if !created {
		t.Fatalf("expected created=true")
	}

	refreshed := original
	refreshed.ProofWitnessItem = bytes.Repeat([]byte{0x02}, 1848)
	refreshed.JunoHeight = 456

	job, created, err := s.UpsertSeen(ctx, refreshed)
	if err != nil {
		t.Fatalf("UpsertSeen #2: %v", err)
	}
	if created {
		t.Fatalf("expected created=false")
	}
	if !bytes.Equal(job.Deposit.ProofWitnessItem, refreshed.ProofWitnessItem) {
		t.Fatalf("witness mismatch")
	}
	if job.Deposit.JunoHeight != refreshed.JunoHeight {
		t.Fatalf("juno height = %d, want %d", job.Deposit.JunoHeight, refreshed.JunoHeight)
	}
}

func TestStore_UpsertConfirmed_SourceEventReplay(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	src := &deposit.SourceEvent{
		ChainID:  84532,
		LogIndex: 11,
	}
	src.TxHash[0] = 0xaa

	var id [32]byte
	id[0] = 0x71
	var cm [32]byte
	cm[0] = 0xe1
	var recip [20]byte
	copy(recip[:], common.HexToAddress("0x0000000000000000000000000000000000000456").Bytes())

	dep := deposit.Deposit{
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
	conflict.DepositID[0] = 0x72
	conflict.Commitment[0] = 0xe2
	conflict.LeafIndex = 8
	if _, _, err := s.UpsertConfirmed(ctx, conflict); !errors.Is(err, deposit.ErrDepositMismatch) {
		t.Fatalf("expected ErrDepositMismatch on conflicting source replay, got %v", err)
	}
}

func TestStore_PrepareNextBatch_PersistsAndSplitsDurableBatch(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	mkDeposit := func(tag byte) deposit.Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return deposit.Deposit{
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

	batchID := [32]byte{0xaa}
	batch, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, batchID, 2, 3*time.Minute, 10, now)
	if err != nil {
		t.Fatalf("PrepareNextBatch #1: %v", err)
	}
	if ready {
		t.Fatalf("expected first prepare to keep batch open")
	}
	if got, want := batch.State, deposit.BatchStateAssembling; got != want {
		t.Fatalf("batch state: got=%s want=%s", got, want)
	}
	if got, want := len(batch.DepositIDs), 1; got != want {
		t.Fatalf("batch deposit count after first prepare: got=%d want=%d", got, want)
	}

	persisted, err := s.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch: %v", err)
	}
	if got, want := len(persisted.DepositIDs), 1; got != want {
		t.Fatalf("persisted deposit count: got=%d want=%d", got, want)
	}

	readyBatch, ready, err := s.PrepareNextBatch(ctx, "worker-b", time.Minute, [32]byte{0xbb}, 2, 3*time.Minute, 10, now.Add(30*time.Second))
	if err != nil {
		t.Fatalf("PrepareNextBatch #2: %v", err)
	}
	if !ready {
		t.Fatalf("expected second prepare to close batch")
	}
	if readyBatch.BatchID != batchID {
		t.Fatalf("expected durable batch reuse: got=%x want=%x", readyBatch.BatchID, batchID)
	}
	if got, want := readyBatch.State, deposit.BatchStateClosed; got != want {
		t.Fatalf("closed batch state: got=%s want=%s", got, want)
	}
	if got, want := len(readyBatch.DepositIDs), 2; got != want {
		t.Fatalf("closed batch deposit count: got=%d want=%d", got, want)
	}

	splitBatchID := [32]byte{0xcc}
	left, right, err := s.SplitBatch(ctx, "worker-c", batchID, splitBatchID, [][32]byte{d2.DepositID})
	if err != nil {
		t.Fatalf("SplitBatch: %v", err)
	}
	if got, want := len(left.DepositIDs), 1; got != want {
		t.Fatalf("left deposit count: got=%d want=%d", got, want)
	}
	if got, want := len(right.DepositIDs), 1; got != want {
		t.Fatalf("right deposit count: got=%d want=%d", got, want)
	}
	if left.DepositIDs[0] != d1.DepositID {
		t.Fatalf("left deposit mismatch: got=%x want=%x", left.DepositIDs[0], d1.DepositID)
	}
	if right.DepositIDs[0] != d2.DepositID {
		t.Fatalf("right deposit mismatch: got=%x want=%x", right.DepositIDs[0], d2.DepositID)
	}
}

func TestStore_SplitBatch_ResetsProofRequestedState(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	mkDeposit := func(tag byte) deposit.Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return deposit.Deposit{
			DepositID:        id,
			Commitment:       cm,
			LeafIndex:        uint64(tag),
			Amount:           1000 + uint64(tag),
			BaseRecipient:    recip,
			ProofWitnessItem: bytes.Repeat([]byte{tag}, 1848),
		}
	}

	d1 := mkDeposit(0x11)
	d2 := mkDeposit(0x12)
	for _, dep := range []deposit.Deposit{d1, d2} {
		if _, _, err := s.UpsertConfirmed(ctx, dep); err != nil {
			t.Fatalf("UpsertConfirmed(%x): %v", dep.DepositID[:4], err)
		}
	}

	batchID := [32]byte{0xda}
	if _, _, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, batchID, 2, 3*time.Minute, 10, now); err != nil {
		t.Fatalf("PrepareNextBatch #1: %v", err)
	}
	batch, ready, err := s.PrepareNextBatch(ctx, "worker-a", time.Minute, [32]byte{}, 2, 3*time.Minute, 10, now)
	if err != nil {
		t.Fatalf("PrepareNextBatch #2: %v", err)
	}
	if !ready || batch.State != deposit.BatchStateClosed {
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

	splitBatchID := [32]byte{0xdb}
	left, right, err := s.SplitBatch(ctx, "worker-a", batchID, splitBatchID, [][32]byte{d2.DepositID})
	if err != nil {
		t.Fatalf("SplitBatch: %v", err)
	}
	if left.State != deposit.BatchStateClosed || right.State != deposit.BatchStateClosed {
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
		if job.State != deposit.StateConfirmed {
			t.Fatalf("job %x state: got=%s want=%s", depositID[:4], job.State, deposit.StateConfirmed)
		}
	}
}

func TestStore_MarkRejectedDoesNotOverrideFinalizedState(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id [32]byte
	id[0] = 0x09
	var cm [32]byte
	cm[0] = 0x09
	var recip [20]byte
	copy(recip[:], common.HexToAddress("0x0000000000000000000000000000000000000456").Bytes())

	d := deposit.Deposit{
		DepositID:        id,
		Commitment:       cm,
		LeafIndex:        9,
		Amount:           1000,
		BaseRecipient:    recip,
		ProofWitnessItem: bytes.Repeat([]byte{0x01}, 1848),
	}
	if _, _, err := s.UpsertConfirmed(ctx, d); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
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
	if err := s.SetProofReady(ctx, id, []byte{0x02}); err != nil {
		t.Fatalf("SetProofReady: %v", err)
	}

	var txHash [32]byte
	txHash[0] = 0x77
	if err := s.MarkFinalized(ctx, id, txHash); err != nil {
		t.Fatalf("MarkFinalized: %v", err)
	}
	if err := s.MarkRejected(ctx, id, "skipped", txHash); !errors.Is(err, deposit.ErrInvalidTransition) {
		t.Fatalf("MarkRejected after finalized: got %v want %v", err, deposit.ErrInvalidTransition)
	}

	job, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateFinalized {
		t.Fatalf("state: got %v want %v", job.State, deposit.StateFinalized)
	}
	if job.TxHash != txHash {
		t.Fatalf("tx hash changed: got %x want %x", job.TxHash, txHash)
	}
}

func TestStore_ApplyBatchOutcomeDoesNotOverrideRejectedState(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id [32]byte
	id[0] = 0x0a
	var cm [32]byte
	cm[0] = 0x0a
	var recip [20]byte
	copy(recip[:], common.HexToAddress("0x0000000000000000000000000000000000000456").Bytes())

	d := deposit.Deposit{
		DepositID:        id,
		Commitment:       cm,
		LeafIndex:        10,
		Amount:           1000,
		BaseRecipient:    recip,
		ProofWitnessItem: bytes.Repeat([]byte{0x01}, 1848),
	}
	if _, _, err := s.UpsertConfirmed(ctx, d); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
	}

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
		FinalOrchardRoot: common.HexToHash("0x1112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30"),
		BaseChainID:      31337,
		BridgeContract:   common.HexToAddress("0x0000000000000000000000000000000000000123"),
	}
	batchID := [32]byte{0xbb}
	if _, err := s.MarkBatchSubmitted(ctx, "owner-a", batchID, [][32]byte{id}, cp, [][]byte{[]byte{0x01}}, []byte{0x02}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}

	var rejectedTxHash [32]byte
	rejectedTxHash[0] = 0x55
	if err := s.MarkRejected(ctx, id, "deposit skipped by bridge", rejectedTxHash); err != nil {
		t.Fatalf("MarkRejected: %v", err)
	}

	var outcomeTxHash [32]byte
	outcomeTxHash[0] = 0x66
	if err := s.ApplyBatchOutcome(ctx, batchID, outcomeTxHash, [][32]byte{id}, nil, "deposit skipped by bridge"); err != nil {
		t.Fatalf("ApplyBatchOutcome: %v", err)
	}

	job, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateRejected {
		t.Fatalf("state: got %v want %v", job.State, deposit.StateRejected)
	}
	if job.TxHash != rejectedTxHash {
		t.Fatalf("tx hash changed: got %x want %x", job.TxHash, rejectedTxHash)
	}
	if job.RejectionReason != "deposit skipped by bridge" {
		t.Fatalf("rejection reason: got %q", job.RejectionReason)
	}
}

func TestStore_RepairFinalizedOverridesRejectedState(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id [32]byte
	id[0] = 0x81
	var cm [32]byte
	cm[0] = 0x81
	var recip [20]byte
	copy(recip[:], common.HexToAddress("0x0000000000000000000000000000000000000456").Bytes())

	d := deposit.Deposit{
		DepositID:        id,
		Commitment:       cm,
		LeafIndex:        10,
		Amount:           1000,
		BaseRecipient:    recip,
		ProofWitnessItem: bytes.Repeat([]byte{0x01}, 1848),
	}
	if _, _, err := s.UpsertConfirmed(ctx, d); err != nil {
		t.Fatalf("UpsertConfirmed: %v", err)
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
	if err := s.SetProofReady(ctx, id, []byte{0x02}); err != nil {
		t.Fatalf("SetProofReady: %v", err)
	}

	var rejectedTxHash [32]byte
	rejectedTxHash[0] = 0x55
	if err := s.MarkRejected(ctx, id, "deposit skipped by bridge", rejectedTxHash); err != nil {
		t.Fatalf("MarkRejected: %v", err)
	}

	var mintedTxHash [32]byte
	mintedTxHash[0] = 0x66
	if err := s.RepairFinalized(ctx, id, mintedTxHash); err != nil {
		t.Fatalf("RepairFinalized: %v", err)
	}

	job, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateFinalized {
		t.Fatalf("state: got %v want %v", job.State, deposit.StateFinalized)
	}
	if job.TxHash != mintedTxHash {
		t.Fatalf("tx hash changed: got %x want %x", job.TxHash, mintedTxHash)
	}
	if job.RejectionReason != "" {
		t.Fatalf("rejection reason: got %q want empty", job.RejectionReason)
	}
}

func TestStore_FinalizeBatch_IsAtomic(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	// Pin for deterministic integration tests.
	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	mkDeposit := func(tag byte) deposit.Deposit {
		var id [32]byte
		id[0] = tag
		var cm [32]byte
		cm[0] = tag
		var recip [20]byte
		recip[19] = tag
		return deposit.Deposit{
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
	j2, err := s.Get(ctx, d2.DepositID)
	if err != nil {
		t.Fatalf("Get d2: %v", err)
	}
	if j1.State != deposit.StateConfirmed || j2.State != deposit.StateConfirmed {
		t.Fatalf("state changed on failed batch: d1=%v d2=%v", j1.State, j2.State)
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
	if j1.State != deposit.StateFinalized || j2.State != deposit.StateFinalized {
		t.Fatalf("unexpected states after finalize: d1=%v d2=%v", j1.State, j2.State)
	}
	if j1.TxHash != txHash || j2.TxHash != txHash {
		t.Fatalf("tx hash mismatch")
	}
}

func TestStore_SubmittedAttemptsPersistAndResumeDeterministically(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id [32]byte
	id[0] = 0x01
	var cm [32]byte
	cm[0] = 0xaa
	var recip [20]byte
	recip[0] = 0x11

	if _, _, err := s.UpsertConfirmed(ctx, deposit.Deposit{
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
	operatorSigs := [][]byte{{0xaa}, {0xbb}}

	attempt, err := s.MarkBatchSubmitted(ctx, "worker-a", batchID, [][32]byte{id}, cp, operatorSigs, seal)
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
	if len(attempt.DepositIDs) != 1 || attempt.DepositIDs[0] != id {
		t.Fatalf("unexpected deposit ids: %#v", attempt.DepositIDs)
	}
	if len(attempt.OperatorSignatures) != len(operatorSigs) {
		t.Fatalf("operator sig len: got %d want %d", len(attempt.OperatorSignatures), len(operatorSigs))
	}

	claimedConfirmed, err := s.ClaimConfirmed(ctx, "worker-b", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimConfirmed after submit: %v", err)
	}
	if len(claimedConfirmed) != 0 {
		t.Fatalf("expected submitted deposits to be excluded from ClaimConfirmed")
	}

	var txHash [32]byte
	txHash[0] = 0x77
	if err := s.SetBatchSubmissionTxHash(ctx, batchID, txHash); err != nil {
		t.Fatalf("SetBatchSubmissionTxHash: %v", err)
	}

	claimedAttempts, err := s.ClaimSubmittedAttempts(ctx, "worker-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(claimedAttempts) != 1 {
		t.Fatalf("submitted attempts len: got %d want 1", len(claimedAttempts))
	}
	if claimedAttempts[0].TxHash != txHash {
		t.Fatalf("tx hash mismatch")
	}

	if err := s.FinalizeBatch(ctx, [][32]byte{id}, cp, seal, txHash); err != nil {
		t.Fatalf("FinalizeBatch: %v", err)
	}

	claimedAttempts, err = s.ClaimSubmittedAttempts(ctx, "worker-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts after finalize: %v", err)
	}
	if len(claimedAttempts) != 0 {
		t.Fatalf("expected finalized batch attempt to be cleared")
	}
}

func TestStore_ClaimConfirmed_ReclaimsProofRequestedAfterLeaseExpiry(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id [32]byte
	id[0] = 0x61
	var cm [32]byte
	cm[0] = 0xaa
	var recip [20]byte
	recip[0] = 0x33

	if _, _, err := s.UpsertConfirmed(ctx, deposit.Deposit{
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
	} else if len(afterExpiry) != 1 || afterExpiry[0].State != deposit.StateProofRequested {
		t.Fatalf("expected worker-b to reclaim proof-requested job after expiry, got %+v", afterExpiry)
	}
}

func TestStore_RequeueSubmittedBatch(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var id [32]byte
	id[0] = 0x91
	var cm [32]byte
	cm[0] = 0xaa
	var recip [20]byte
	recip[0] = 0x11

	if _, _, err := s.UpsertConfirmed(ctx, deposit.Deposit{
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
	batchID := [32]byte{0x92}
	if _, err := s.MarkBatchSubmitted(ctx, "worker-a", batchID, [][32]byte{id}, cp, [][]byte{{0xaa}}, []byte{0x99}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}

	if err := s.RequeueSubmittedBatch(ctx, batchID); err != nil {
		t.Fatalf("RequeueSubmittedBatch: %v", err)
	}

	attempts, err := s.ClaimSubmittedAttempts(ctx, "worker-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected stale submitted batch attempt to be cleared")
	}

	job, err := s.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if job.State != deposit.StateConfirmed {
		t.Fatalf("state: got %s want %s", job.State, deposit.StateConfirmed)
	}
	if len(job.ProofSeal) != 0 {
		t.Fatalf("proof seal should be cleared, got %x", job.ProofSeal)
	}

	claimedConfirmed, err := s.ClaimConfirmed(ctx, "worker-b", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimConfirmed after requeue: %v", err)
	}
	if len(claimedConfirmed) != 1 || claimedConfirmed[0].Deposit.DepositID != id {
		t.Fatalf("unexpected claimed confirmed jobs: %#v", claimedConfirmed)
	}
}

func TestStore_ClaimBatchesAndResetBatch(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	const pgImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

	port := mustFreePort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)

	containerID := dockerRunPostgres(t, ctx, pgImage, port)
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", containerID).Run() })

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	pool := dialPostgres(t, ctx, dsn)
	t.Cleanup(pool.Close)

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	d1 := deposit.Deposit{
		DepositID:     [32]byte{0xa1},
		Commitment:    [32]byte{0xa2},
		LeafIndex:     1,
		Amount:        1000,
		BaseRecipient: [20]byte{0x01},
	}
	d2 := deposit.Deposit{
		DepositID:     [32]byte{0xa3},
		Commitment:    [32]byte{0xa4},
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
	batchID := [32]byte{0xa5}
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

	claimed, err := s.ClaimBatches(ctx, "repair-a", 80*time.Millisecond, []deposit.BatchState{deposit.BatchStateProofRequested}, time.Now().Add(time.Second), 10)
	if err != nil {
		t.Fatalf("ClaimBatches: %v", err)
	}
	if len(claimed) != 1 || claimed[0].BatchID != batchID {
		t.Fatalf("unexpected claimed batches: %#v", claimed)
	}

	if _, err := s.MarkBatchProofReady(ctx, "worker-a", batch.BatchID, cp, [][]byte{{0xaa}}, []byte{0x99}); err != nil {
		t.Fatalf("MarkBatchProofReady: %v", err)
	}
	if _, err := s.MarkBatchSubmitted(ctx, "worker-a", batch.BatchID, batch.DepositIDs, cp, [][]byte{{0xaa}}, []byte{0x99}); err != nil {
		t.Fatalf("MarkBatchSubmitted: %v", err)
	}

	reset, err := s.ResetBatch(ctx, "repair-a", batchID)
	if err != nil {
		t.Fatalf("ResetBatch: %v", err)
	}
	if reset.State != deposit.BatchStateClosed {
		t.Fatalf("reset state: got %s want %s", reset.State, deposit.BatchStateClosed)
	}
	if reset.Checkpoint != (checkpoint.Checkpoint{}) {
		t.Fatalf("expected reset checkpoint to be cleared, got %+v", reset.Checkpoint)
	}
	if reset.ProofRequested {
		t.Fatalf("expected proof_requested to be false after reset")
	}

	attempts, err := s.ClaimSubmittedAttempts(ctx, "repair-a", 80*time.Millisecond, 10)
	if err != nil {
		t.Fatalf("ClaimSubmittedAttempts: %v", err)
	}
	if len(attempts) != 0 {
		t.Fatalf("expected submitted attempts to clear after reset")
	}

	for _, depositID := range batch.DepositIDs {
		job, err := s.Get(ctx, depositID)
		if err != nil {
			t.Fatalf("Get(%x): %v", depositID[:4], err)
		}
		if job.State != deposit.StateConfirmed {
			t.Fatalf("job %x state: got %s want %s", depositID[:4], job.State, deposit.StateConfirmed)
		}
	}
}

func mustFreePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")
}

func dockerRunPostgres(t *testing.T, ctx context.Context, image string, hostPort string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker",
		"run",
		"--rm",
		"-d",
		"-e", "POSTGRES_USER=postgres",
		"-e", "POSTGRES_PASSWORD=postgres",
		"-e", "POSTGRES_DB=postgres",
		"-p", "127.0.0.1:"+hostPort+":5432",
		image,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker run postgres: %v: %s", err, string(out))
	}
	return strings.TrimSpace(string(out))
}

func dialPostgres(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		cctx, cancel := context.WithTimeout(ctx, 1*time.Second)
		pool, err := pgxpool.New(cctx, dsn)
		if err == nil {
			if err := pool.Ping(cctx); err == nil {
				cancel()
				return pool
			}
			pool.Close()
		}
		cancel()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("postgres not ready: %s", dsn)
	return nil
}
