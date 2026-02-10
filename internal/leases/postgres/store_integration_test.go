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
	"github.com/juno-intents/intents-juno/internal/leases"
)

func TestStore_TryAcquireRenewRelease(t *testing.T) {
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

	l, ok, err := s.TryAcquire(ctx, "leader", "a", 2*time.Second)
	if err != nil {
		t.Fatalf("TryAcquire: %v", err)
	}
	if !ok || l.Owner != "a" {
		t.Fatalf("unexpected lease after acquire: ok=%v owner=%q", ok, l.Owner)
	}

	l2, ok, err := s.TryAcquire(ctx, "leader", "b", 2*time.Second)
	if err != nil {
		t.Fatalf("TryAcquire #2: %v", err)
	}
	if ok || l2.Owner != "a" {
		t.Fatalf("expected held by a: ok=%v owner=%q", ok, l2.Owner)
	}

	if _, ok, err := s.Renew(ctx, "leader", "b", 2*time.Second); !errors.Is(err, leases.ErrNotOwner) || ok {
		t.Fatalf("expected ErrNotOwner on renew by b: ok=%v err=%v", ok, err)
	}

	if _, ok, err := s.Renew(ctx, "leader", "a", 3*time.Second); err != nil || !ok {
		t.Fatalf("expected renew by a: ok=%v err=%v", ok, err)
	}

	if err := s.Release(ctx, "leader", "b"); !errors.Is(err, leases.ErrNotOwner) {
		t.Fatalf("expected ErrNotOwner on release by b: %v", err)
	}

	if err := s.Release(ctx, "leader", "a"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Idempotent.
	if err := s.Release(ctx, "leader", "a"); err != nil {
		t.Fatalf("Release #2: %v", err)
	}

	_, ok, err = s.TryAcquire(ctx, "leader", "b", 1*time.Second)
	if err != nil || !ok {
		t.Fatalf("expected acquire by b: ok=%v err=%v", ok, err)
	}

	// After expiry, a new owner can steal.
	time.Sleep(1100 * time.Millisecond)
	l3, ok, err := s.TryAcquire(ctx, "leader", "c", 1*time.Second)
	if err != nil {
		t.Fatalf("TryAcquire steal: %v", err)
	}
	if !ok || l3.Owner != "c" {
		t.Fatalf("expected steal by c: ok=%v owner=%q", ok, l3.Owner)
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
