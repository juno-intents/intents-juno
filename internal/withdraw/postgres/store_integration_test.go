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

	w0 := withdraw.Withdrawal{ID: seq32(0x00), Amount: 1, FeeBps: 0, RecipientUA: []byte{0x01}, ProofWitnessItem: []byte{0x10}, Expiry: now.Add(24 * time.Hour)}
	w1 := withdraw.Withdrawal{ID: seq32(0x20), Amount: 2, FeeBps: 0, RecipientUA: []byte{0x02}, ProofWitnessItem: []byte{0x20}, Expiry: now.Add(24 * time.Hour)}
	w2 := withdraw.Withdrawal{ID: seq32(0x40), Amount: 3, FeeBps: 0, RecipientUA: []byte{0x03}, ProofWitnessItem: []byte{0x30}, Expiry: now.Add(24 * time.Hour)}

	if _, created, err := s.UpsertRequested(ctx, w0); err != nil || !created {
		t.Fatalf("UpsertRequested w0: created=%v err=%v", created, err)
	}
	if _, created, err := s.UpsertRequested(ctx, w1); err != nil || !created {
		t.Fatalf("UpsertRequested w1: created=%v err=%v", created, err)
	}
	if _, created, err := s.UpsertRequested(ctx, w2); err != nil || !created {
		t.Fatalf("UpsertRequested w2: created=%v err=%v", created, err)
	}

	// Dedupe.
	if _, created, err := s.UpsertRequested(ctx, w2); err != nil || created {
		t.Fatalf("UpsertRequested w2 #2: created=%v err=%v", created, err)
	}

	// Claim deterministically by id.
	claimed, err := s.ClaimUnbatched(ctx, "a", 10*time.Second, 2)
	if err != nil {
		t.Fatalf("ClaimUnbatched: %v", err)
	}
	if len(claimed) != 2 || claimed[0].ID != w0.ID || claimed[1].ID != w1.ID {
		t.Fatalf("unexpected claimed order/size")
	}

	batchID := seq32(0x99)
	if err := s.CreatePlannedBatch(ctx, "a", withdraw.Batch{
		ID:            batchID,
		WithdrawalIDs: [][32]byte{w0.ID, w1.ID},
		State:         withdraw.BatchStatePlanned,
		TxPlan:        []byte(`{"v":1}`),
	}); err != nil {
		t.Fatalf("CreatePlannedBatch: %v", err)
	}

	// Remaining withdrawal should still be claimable.
	claimed2, err := s.ClaimUnbatched(ctx, "a", 10*time.Second, 10)
	if err != nil {
		t.Fatalf("ClaimUnbatched #2: %v", err)
	}
	if len(claimed2) != 1 || claimed2[0].ID != w2.ID {
		t.Fatalf("expected only w2 to remain")
	}

	// Batch state machine.
	if err := s.SetBatchSigned(ctx, batchID, []byte{0x01}); err == nil {
		t.Fatalf("expected error signing before marking signing")
	}
	if err := s.MarkBatchSigning(ctx, batchID); err != nil {
		t.Fatalf("MarkBatchSigning: %v", err)
	}
	if err := s.SetBatchSigned(ctx, batchID, []byte{0x01}); err != nil {
		t.Fatalf("SetBatchSigned: %v", err)
	}
	if err := s.SetBatchSigned(ctx, batchID, []byte{0x02}); !errors.Is(err, withdraw.ErrBatchMismatch) {
		t.Fatalf("expected ErrBatchMismatch, got %v", err)
	}

	if err := s.SetBatchBroadcasted(ctx, batchID, "tx1"); err != nil {
		t.Fatalf("SetBatchBroadcasted: %v", err)
	}
	if err := s.SetBatchBroadcasted(ctx, batchID, "tx2"); !errors.Is(err, withdraw.ErrBatchMismatch) {
		t.Fatalf("expected ErrBatchMismatch, got %v", err)
	}

	if err := s.SetBatchConfirmed(ctx, batchID); err != nil {
		t.Fatalf("SetBatchConfirmed: %v", err)
	}
	if err := s.MarkBatchFinalizing(ctx, batchID); err != nil {
		t.Fatalf("MarkBatchFinalizing: %v", err)
	}
}

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
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
