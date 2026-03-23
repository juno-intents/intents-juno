//go:build integration

package postgres

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/proof"
)

func TestStore_AllocatorAndDedupe(t *testing.T) {
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

	store, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	now := time.Date(2026, 2, 11, 13, 0, 0, 0, time.UTC)
	job := proof.JobRequest{
		JobID:        common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01, 0x02},
		PrivateInput: []byte{0x03},
		Deadline:     now.Add(10 * time.Minute),
		Priority:     1,
	}

	created, err := store.UpsertJob(ctx, job, 72*time.Hour)
	if err != nil {
		t.Fatalf("UpsertJob first: %v", err)
	}
	if !created {
		t.Fatalf("expected first insert")
	}
	created, err = store.UpsertJob(ctx, job, 72*time.Hour)
	if err != nil {
		t.Fatalf("UpsertJob duplicate: %v", err)
	}
	if created {
		t.Fatalf("expected dedupe on repeated job_id")
	}

	mismatch := job
	mismatch.Pipeline = "withdraw"
	_, err = store.UpsertJob(ctx, mismatch, 72*time.Hour)
	if !errors.Is(err, proof.ErrJobMismatch) {
		t.Fatalf("expected ErrJobMismatch, got %v", err)
	}

	// Request retries may bump deadline/priority while retaining the same job id
	// and proof payload identity.
	retryDeadline := job
	retryDeadline.Deadline = job.Deadline.Add(5 * time.Minute)
	created, err = store.UpsertJob(ctx, retryDeadline, 72*time.Hour)
	if err != nil {
		t.Fatalf("UpsertJob retry deadline update: %v", err)
	}
	if created {
		t.Fatalf("expected dedupe on retry deadline update")
	}

	retryPriority := job
	retryPriority.Priority = job.Priority + 1
	created, err = store.UpsertJob(ctx, retryPriority, 72*time.Hour)
	if err != nil {
		t.Fatalf("UpsertJob retry priority update: %v", err)
	}
	if created {
		t.Fatalf("expected dedupe on retry priority update")
	}

	const workers = 64
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ids  = make([]uint64, 0, workers)
		errs = make([]error, 0)
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := store.AllocateRequestID(ctx, 8453)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			ids = append(ids, id)
		}()
	}
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("allocator errors: %v", errs)
	}
	if len(ids) != workers {
		t.Fatalf("ids: got %d want %d", len(ids), workers)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for i := 0; i < workers; i++ {
		want := uint64(i + 1)
		if ids[i] != want {
			t.Fatalf("ids[%d]: got %d want %d", i, ids[i], want)
		}
	}
}

func TestStore_ClaimForSubmissionSkipsActiveLeaseEvenForSameOwner(t *testing.T) {
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

	store, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	now := time.Date(2026, 3, 23, 16, 0, 0, 0, time.UTC)
	job := proof.JobRequest{
		JobID:        common.HexToHash("0x7ef54f9b1b47c7276375b70ddb2ea3d3a11e6aa0c0d003981c1f3f9a3bf191bf"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(15 * time.Minute),
		Priority:     1,
	}

	if _, err := store.UpsertJob(ctx, job, 72*time.Hour); err != nil {
		t.Fatalf("UpsertJob: %v", err)
	}

	first, claimed, err := store.ClaimForSubmission(ctx, job.JobID, "requestor-a", 15*time.Minute, 8453)
	if err != nil {
		t.Fatalf("ClaimForSubmission first: %v", err)
	}
	if !claimed {
		t.Fatalf("expected first claim to succeed")
	}
	if got, want := first.AttemptCount, 1; got != want {
		t.Fatalf("first attempt count: got %d want %d", got, want)
	}

	second, claimed, err := store.ClaimForSubmission(ctx, job.JobID, "requestor-a", 15*time.Minute, 8453)
	if err != nil {
		t.Fatalf("ClaimForSubmission second: %v", err)
	}
	if claimed {
		t.Fatalf("expected second claim to skip while lease is active")
	}
	if got, want := second.AttemptCount, 1; got != want {
		t.Fatalf("second attempt count: got %d want %d", got, want)
	}
	if got, want := second.RequestID, first.RequestID; got != want {
		t.Fatalf("request id: got %d want %d", got, want)
	}
	if got, want := second.State, proof.StateSubmitting; got != want {
		t.Fatalf("state: got %s want %s", got, want)
	}
}

func TestStore_RejectsStaleFailureAfterFulfillment(t *testing.T) {
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

	store, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	now := time.Date(2026, 3, 23, 16, 0, 0, 0, time.UTC)
	job := proof.JobRequest{
		JobID:        common.HexToHash("0xd9686e62f1292819c937bb25a2da5002b9d38be7bbce2715f5f078d0baa9b36b"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(15 * time.Minute),
		Priority:     1,
	}

	if _, err := store.UpsertJob(ctx, job, 72*time.Hour); err != nil {
		t.Fatalf("UpsertJob: %v", err)
	}
	rec, claimed, err := store.ClaimForSubmission(ctx, job.JobID, "requestor-a", 15*time.Minute, 8453)
	if err != nil {
		t.Fatalf("ClaimForSubmission: %v", err)
	}
	if !claimed {
		t.Fatalf("expected claim to succeed")
	}
	if _, err := store.MarkFulfilled(ctx, job.JobID, "requestor-a", rec.RequestID, []byte{0xaa}, map[string]string{"provider": "sp1"}, "sp1-network-mainnet"); err != nil {
		t.Fatalf("MarkFulfilled: %v", err)
	}

	_, err = store.MarkFailed(ctx, job.JobID, "requestor-a", rec.RequestID, "sp1_request_unfulfillable", "stale failure", true)
	if !errors.Is(err, proof.ErrTerminalState) {
		t.Fatalf("expected ErrTerminalState, got %v", err)
	}

	got, err := store.GetJob(ctx, job.JobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.State != proof.StateFulfilled {
		t.Fatalf("state: got %s want %s", got.State, proof.StateFulfilled)
	}
	if got.ErrorCode != "" {
		t.Fatalf("error code: got %q want empty", got.ErrorCode)
	}
}

func TestStore_RejectsStaleFulfillmentAfterTerminalFailure(t *testing.T) {
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

	store, err := New(pool)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}

	now := time.Date(2026, 3, 23, 16, 0, 0, 0, time.UTC)
	job := proof.JobRequest{
		JobID:        common.HexToHash("0x159b2d7d89c20341161a0e1ea0a88dd401d6f7415c0f371fe7c93be2021cf2cc"),
		Pipeline:     "withdraw",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(15 * time.Minute),
		Priority:     1,
	}

	if _, err := store.UpsertJob(ctx, job, 72*time.Hour); err != nil {
		t.Fatalf("UpsertJob: %v", err)
	}
	rec, claimed, err := store.ClaimForSubmission(ctx, job.JobID, "requestor-a", 15*time.Minute, 8453)
	if err != nil {
		t.Fatalf("ClaimForSubmission: %v", err)
	}
	if !claimed {
		t.Fatalf("expected claim to succeed")
	}
	if _, err := store.MarkFailed(ctx, job.JobID, "requestor-a", rec.RequestID, "sp1_invalid_input", "bad witness", false); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	_, err = store.MarkFulfilled(ctx, job.JobID, "requestor-a", rec.RequestID, []byte{0xbb}, map[string]string{"provider": "sp1"}, "sp1-network-mainnet")
	if !errors.Is(err, proof.ErrTerminalState) {
		t.Fatalf("expected ErrTerminalState, got %v", err)
	}

	got, err := store.GetJob(ctx, job.JobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.State != proof.StateFailedTerminal {
		t.Fatalf("state: got %s want %s", got.State, proof.StateFailedTerminal)
	}
	if got.ErrorCode != "sp1_invalid_input" {
		t.Fatalf("error code: got %q want %q", got.ErrorCode, "sp1_invalid_input")
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
		cctx, cancel := context.WithTimeout(ctx, time.Second)
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
