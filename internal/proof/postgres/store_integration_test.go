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
