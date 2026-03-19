//go:build integration

package postgres

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/withdraw"
)

func TestStore_ClaimAndBatch_StateMachine(t *testing.T) {
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

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)

	w0 := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, Expiry: now.Add(24 * time.Hour)}
	w1 := withdraw.Withdrawal{ID: seq32(0x20), Amount: 2, FeeBps: 0, RecipientUA: []byte{0x02}, Expiry: now.Add(24 * time.Hour)}
	w2 := withdraw.Withdrawal{ID: seq32(0x40), Amount: 3, FeeBps: 0, RecipientUA: []byte{0x03}, Expiry: now.Add(24 * time.Hour)}
	w3 := withdraw.Withdrawal{ID: seq32(0x60), Amount: 4, FeeBps: 0, RecipientUA: []byte{0x04}, Expiry: now.Add(24 * time.Hour)}

	if _, created, err := s.UpsertRequested(ctx, w0); err != nil || !created {
		t.Fatalf("UpsertRequested w0: created=%v err=%v", created, err)
	}
	if status, err := s.GetWithdrawalStatus(ctx, w0.ID); err != nil {
		t.Fatalf("GetWithdrawalStatus requested: %v", err)
	} else if status != withdraw.WithdrawalStatusRequested {
		t.Fatalf("requested status: got %s want %s", status, withdraw.WithdrawalStatusRequested)
	}
	if _, created, err := s.UpsertRequested(ctx, w1); err != nil || !created {
		t.Fatalf("UpsertRequested w1: created=%v err=%v", created, err)
	}
	if _, created, err := s.UpsertRequested(ctx, w2); err != nil || !created {
		t.Fatalf("UpsertRequested w2: created=%v err=%v", created, err)
	}
	if _, created, err := s.UpsertRequested(ctx, w3); err != nil || !created {
		t.Fatalf("UpsertRequested w3: created=%v err=%v", created, err)
	}

	// Dedupe.
	if _, created, err := s.UpsertRequested(ctx, w2); err != nil || created {
		t.Fatalf("UpsertRequested w2 #2: created=%v err=%v", created, err)
	}

	// Claim deterministically by id.
	fenceA := testFence("a")
	fenceC := testFence("c")

	claimed, err := s.ClaimUnbatched(ctx, fenceA, 10*time.Second, 2)
	if err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}
	if len(claimed) != 2 || claimed[0].ID != w0.ID || claimed[1].ID != w1.ID {
		t.Fatalf("unexpected claimed order/size")
	}

	batchID := seq32(0x99)
	if err := s.CreatePlannedBatch(ctx, fenceA, withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w0.ID, w1.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	if status, err := s.GetWithdrawalStatus(ctx, w0.ID); err != nil {
		t.Fatalf("GetWithdrawalStatus batched: %v", err)
	} else if status != withdraw.WithdrawalStatusBatched {
		t.Fatalf("batched status: got %s want %s", status, withdraw.WithdrawalStatusBatched)
	}

	// Remaining withdrawal should still be claimable.
	claimed2, err := s.ClaimUnbatched(ctx, fenceA, 10*time.Second, 1)
	if err != nil {
		t.Fatalf("ClaimUnbatched #2: %v", err)
	}
	if len(claimed2) != 1 || claimed2[0].ID != w2.ID {
		t.Fatalf("expected only w2 to remain")
	}

	claimed3, err := s.ClaimUnbatched(ctx, fenceC, 20*time.Millisecond, 1)
	if err != nil {
		t.Fatalf("ClaimUnbatched w3 by c: %v", err)
	}
	if len(claimed3) != 1 || claimed3[0].ID != w3.ID {
		t.Fatalf("expected c to claim w3")
	}
	time.Sleep(60 * time.Millisecond)
	if err := s.CreatePlannedBatch(ctx, fenceC, withdraw.Batch{
		ID:            seq32(0x98),
		WithdrawalIDs: [][32]byte{w3.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch with expired own claim: %v", err)
	}

	// Batch state machine.
	if err := s.SetBatchSigned(ctx, batchID, fenceA, []byte{0x01}); err == nil {
		t.Fatalf("expected error signing before marking signing")
	}
	if err := s.MarkBatchSigning(ctx, batchID, fenceA); err != nil {
		t.Fatalf("MarkBatchSigning: %v", err)
	}
	if err := s.ResetBatchSigning(ctx, batchID, fenceA, []byte(`{"v":"replanned"}`)); err != nil {
		t.Fatalf("ResetBatchSigning: %v", err)
	}
	bReset, err := s.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch after ResetBatchSigning: %v", err)
	}
	if bReset.State != withdraw.BatchStatePlanned {
		t.Fatalf("state after ResetBatchSigning: got %s want %s", bReset.State, withdraw.BatchStatePlanned)
	}
	if got, want := string(bReset.TxPlan), `{"v":"replanned"}`; got != want {
		t.Fatalf("tx plan after ResetBatchSigning: got %q want %q", got, want)
	}
	if err := s.MarkBatchSigning(ctx, batchID, fenceA); err != nil {
		t.Fatalf("MarkBatchSigning after ResetBatchSigning: %v", err)
	}
	if err := s.SetBatchSigned(ctx, batchID, fenceA, []byte{0x01}); err != nil {
		t.Fatalf("SetBatchSigned: %v", err)
	}
	if err := s.ResetBatchPlanned(ctx, batchID, fenceA, []byte(`{"v":"broadcast-replanned"}`)); err != nil {
		t.Fatalf("ResetBatchPlanned from signed: %v", err)
	}
	bSignedReset, err := s.GetBatch(ctx, batchID)
	if err != nil {
		t.Fatalf("GetBatch after ResetBatchPlanned from signed: %v", err)
	}
	if bSignedReset.State != withdraw.BatchStatePlanned {
		t.Fatalf("state after ResetBatchPlanned from signed: got %s want %s", bSignedReset.State, withdraw.BatchStatePlanned)
	}
	if got, want := string(bSignedReset.TxPlan), `{"v":"broadcast-replanned"}`; got != want {
		t.Fatalf("tx plan after ResetBatchPlanned from signed: got %q want %q", got, want)
	}
	if err := s.MarkBatchSigning(ctx, batchID, fenceA); err != nil {
		t.Fatalf("MarkBatchSigning after ResetBatchPlanned from signed: %v", err)
	}
	if err := s.SetBatchSigned(ctx, batchID, fenceA, []byte{0x01}); err != nil {
		t.Fatalf("SetBatchSigned after ResetBatchPlanned from signed: %v", err)
	}
	if err := s.SetBatchSigned(ctx, batchID, fenceA, []byte{0x02}); !errors.Is(err, withdraw.ErrBatchMismatch) {
		t.Fatalf("expected ErrBatchMismatch, got %v", err)
	}
	if err := s.MarkBatchBroadcastLocked(ctx, batchID, fenceA); err != nil {
		t.Fatalf("MarkBatchBroadcastLocked: %v", err)
	}
	if err := s.ResetBatchPlanned(ctx, batchID, fenceA, []byte(`{"v":"should-not-work"}`)); !errors.Is(err, withdraw.ErrInvalidTransition) {
		t.Fatalf("expected ResetBatchPlanned to fail after broadcast lock, got %v", err)
	}

	if err := s.SetBatchBroadcasted(ctx, batchID, fenceA, "tx1"); err != nil {
		t.Fatalf("SetBatchBroadcasted: %v", err)
	}
	if err := s.SetBatchBroadcasted(ctx, batchID, fenceA, "tx2"); !errors.Is(err, withdraw.ErrBatchMismatch) {
		t.Fatalf("expected ErrBatchMismatch, got %v", err)
	}
	if err := s.SetBatchConfirmed(ctx, batchID, fenceA); !errors.Is(err, withdraw.ErrInvalidTransition) {
		t.Fatalf("expected SetBatchConfirmed to require juno confirmation, got %v", err)
	}
	if err := s.MarkBatchJunoConfirmed(ctx, batchID, fenceA); err != nil {
		t.Fatalf("MarkBatchJunoConfirmed: %v", err)
	}
	if bConfirmed, err := s.GetBatch(ctx, batchID); err != nil {
		t.Fatalf("GetBatch after MarkBatchJunoConfirmed: %v", err)
	} else if bConfirmed.State != withdraw.BatchStateJunoConfirmed {
		t.Fatalf("state after MarkBatchJunoConfirmed: got %s want %s", bConfirmed.State, withdraw.BatchStateJunoConfirmed)
	}
	if status, err := s.GetWithdrawalStatus(ctx, w0.ID); err != nil {
		t.Fatalf("GetWithdrawalStatus after MarkBatchJunoConfirmed: %v", err)
	} else if status != withdraw.WithdrawalStatusBatched {
		t.Fatalf("status after MarkBatchJunoConfirmed: got %s want %s", status, withdraw.WithdrawalStatusBatched)
	}

	if err := s.SetBatchConfirmed(ctx, batchID, fenceA); err != nil {
		t.Fatalf("SetBatchConfirmed: %v", err)
	}
	if status, err := s.GetWithdrawalStatus(ctx, w0.ID); err != nil {
		t.Fatalf("GetWithdrawalStatus paid: %v", err)
	} else if status != withdraw.WithdrawalStatusPaid {
		t.Fatalf("paid status: got %s want %s", status, withdraw.WithdrawalStatusPaid)
	}
	if err := s.MarkBatchFinalizing(ctx, batchID, fenceA); err != nil {
		t.Fatalf("MarkBatchFinalizing: %v", err)
	}
}

func TestStore_FencedBatchMutationAndFailureBookkeeping(t *testing.T) {
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

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	fenceA := testFence("a")
	fenceB := withdraw.Fence{Owner: "b", LeaseVersion: 2}

	w := withdraw.Withdrawal{ID: seq32(0x70), Amount: 5, FeeBps: 0, RecipientUA: []byte{0x05}, Expiry: now.Add(24 * time.Hour)}
	if _, created, err := s.UpsertRequested(ctx, w); err != nil || !created {
		t.Fatalf("UpsertRequested: created=%v err=%v", created, err)
	}
	if _, err := s.ClaimUnbatched(ctx, fenceA, 10*time.Second, 1); err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}

	batchID := seq32(0xa1)
	if err := s.CreatePlannedBatch(ctx, fenceA, withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}
	if err := s.AdoptBatch(ctx, batchID, fenceB); err != nil {
		t.Fatalf("AdoptBatch: %v", err)
	}
	if err := s.MarkBatchSigning(ctx, batchID, fenceA); !errors.Is(err, withdraw.ErrInvalidTransition) {
		t.Fatalf("expected stale fence rejection, got %v", err)
	}
	if err := s.MarkBatchSigning(ctx, batchID, fenceB); err != nil {
		t.Fatalf("MarkBatchSigning with adopted fence: %v", err)
	}
	if err := s.SetBatchSigned(ctx, batchID, fenceB, []byte{0x09}); err != nil {
		t.Fatalf("SetBatchSigned: %v", err)
	}
	if err := s.MarkBatchBroadcastLocked(ctx, batchID, fenceB); err != nil {
		t.Fatalf("MarkBatchBroadcastLocked: %v", err)
	}
	if err := s.SetBatchBroadcasted(ctx, batchID, fenceB, "tx-mark-paid"); err != nil {
		t.Fatalf("SetBatchBroadcasted: %v", err)
	}
	if err := s.MarkBatchJunoConfirmed(ctx, batchID, fenceB); err != nil {
		t.Fatalf("MarkBatchJunoConfirmed: %v", err)
	}
	if got, err := s.RecordBatchFailure(ctx, batchID, fenceB, "broadcast", "broadcast_failed", "rpc unavailable"); err != nil {
		t.Fatalf("RecordBatchFailure: %v", err)
	} else if got.FailureCount != 1 || got.LastErrorCode != "broadcast_failed" {
		t.Fatalf("unexpected failure bookkeeping: %+v", got)
	}
	if got, err := s.RecordBatchMarkPaidFailure(ctx, batchID, fenceB, "base relay down", now.Add(time.Minute)); err != nil {
		t.Fatalf("RecordBatchMarkPaidFailure: %v", err)
	} else if got.MarkPaidFailures != 1 || got.LastMarkPaidError != "base relay down" || got.State != withdraw.BatchStateJunoConfirmed {
		t.Fatalf("unexpected mark-paid bookkeeping: %+v", got)
	}
	if err := s.ResetBatchMarkPaidFailures(ctx, batchID, fenceB); err != nil {
		t.Fatalf("ResetBatchMarkPaidFailures: %v", err)
	}
	if err := s.MarkBatchDLQ(ctx, batchID, fenceB); err != nil {
		t.Fatalf("MarkBatchDLQ: %v", err)
	}
	if listed, err := s.ListBatchesByState(ctx, withdraw.BatchStateSigned); err != nil {
		t.Fatalf("ListBatchesByState: %v", err)
	} else if len(listed) != 0 {
		t.Fatalf("expected DLQed batch to be filtered from state listing, got %d", len(listed))
	}
}

func TestStore_EnsureSchema_UpgradesLegacyWithdrawalBatchesWithoutDLQColumn(t *testing.T) {
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

	if _, err := pool.Exec(ctx, `
CREATE TABLE withdrawal_batches (
	batch_id BYTEA PRIMARY KEY,
	state SMALLINT NOT NULL,
	tx_plan BYTEA NOT NULL,
	signed_tx BYTEA,
	juno_txid TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

	CONSTRAINT batch_id_len CHECK (octet_length(batch_id) = 32),
	CONSTRAINT state_range CHECK (state >= 1 AND state <= 7),
	CONSTRAINT juno_txid_nonempty CHECK (juno_txid IS NULL OR juno_txid <> '')
);`); err != nil {
		t.Fatalf("seed legacy withdrawal_batches: %v", err)
	}

	s, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	var hasDLQ bool
	if err := pool.QueryRow(ctx, `
SELECT EXISTS (
	SELECT 1
	FROM information_schema.columns
	WHERE table_schema = 'public'
	  AND table_name = 'withdrawal_batches'
	  AND column_name = 'dlq_at'
)`).Scan(&hasDLQ); err != nil {
		t.Fatalf("query dlq_at column: %v", err)
	}
	if !hasDLQ {
		t.Fatalf("expected EnsureSchema to add withdrawal_batches.dlq_at")
	}

	if count, err := s.CountDLQBatches(ctx); err != nil {
		t.Fatalf("CountDLQBatches: %v", err)
	} else if count != 0 {
		t.Fatalf("expected zero dlq batches after schema upgrade, got %d", count)
	}
}

func TestStore_UpsertRequested_RoundTripsBaseEventMetadata(t *testing.T) {
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

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	w := withdraw.Withdrawal{
		ID:                 seq32(0x11),
		Amount:             1,
		FeeBps:             0,
		RecipientUA:        []byte{0x01},
		Expiry:             now.Add(24 * time.Hour),
		BaseBlockNumber:    123,
		BaseBlockHash:      seq32(0x21),
		BaseTxHash:         seq32(0x41),
		BaseLogIndex:       7,
		BaseFinalitySource: "safe",
	}

	if _, created, err := s.UpsertRequested(ctx, w); err != nil {
		t.Fatalf("UpsertRequested: %v", err)
	} else if !created {
		t.Fatalf("expected created=true")
	}

	got, err := s.GetWithdrawal(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetWithdrawal: %v", err)
	}
	if !withdrawalEqual(got, w) {
		t.Fatalf("round trip mismatch: got=%+v want=%+v", got, w)
	}
}

func TestStore_UpsertRequested_RejectsDuplicateBaseEventKeyAcrossWithdrawalIDs(t *testing.T) {
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

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	w0 := withdraw.Withdrawal{
		ID:                 seq32(0x11),
		Amount:             1,
		FeeBps:             0,
		RecipientUA:        []byte{0x01},
		Expiry:             now.Add(24 * time.Hour),
		BaseBlockNumber:    123,
		BaseBlockHash:      seq32(0x21),
		BaseTxHash:         seq32(0x41),
		BaseLogIndex:       7,
		BaseFinalitySource: "safe",
	}
	if _, created, err := s.UpsertRequested(ctx, w0); err != nil {
		t.Fatalf("UpsertRequested w0: %v", err)
	} else if !created {
		t.Fatalf("expected created=true")
	}

	w1 := w0
	w1.ID = seq32(0x12)
	if _, _, err := s.UpsertRequested(ctx, w1); !errors.Is(err, withdraw.ErrWithdrawalMismatch) {
		t.Fatalf("expected ErrWithdrawalMismatch for duplicate base event key, got %v", err)
	}
}

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func testFence(owner string) withdraw.Fence {
	return withdraw.Fence{Owner: owner, LeaseVersion: 1}
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
