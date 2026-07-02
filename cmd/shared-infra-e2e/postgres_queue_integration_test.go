//go:build integration

package main

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/queue"
)

const postgresIntegrationImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

func TestCheckPostgresQueue_RoundTripsProbe(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	dsn := newPostgresIntegrationDSN(t, ctx)
	pool := dialPostgres(t, ctx, dsn)
	defer pool.Close()

	rep, err := checkPostgresQueue(ctx, config{
		QueueDriver:      queue.DriverPostgres,
		QueuePostgresDSN: dsn,
		TopicPrefix:      "shared.infra.e2e.test",
		AckTimeout:       5 * time.Second,
	})
	if err != nil {
		t.Fatalf("checkPostgresQueue: %v", err)
	}
	if rep.Driver != queue.DriverPostgres {
		t.Fatalf("driver = %q, want %q", rep.Driver, queue.DriverPostgres)
	}
	if !strings.HasPrefix(rep.Topic, "shared.infra.e2e.test.") {
		t.Fatalf("topic = %q", rep.Topic)
	}
	if rep.Group == "" {
		t.Fatalf("expected consumer group")
	}
	if rep.PayloadBytes == 0 {
		t.Fatalf("expected payload bytes")
	}

	var payload string
	if err := pool.QueryRow(ctx, `
		SELECT convert_from(payload, 'UTF8')
		FROM queue_messages
		WHERE topic = $1
	`, rep.Topic).Scan(&payload); err != nil {
		t.Fatalf("query queue message: %v", err)
	}
	if !strings.Contains(payload, `"version":"shared.infra.e2e.postgres_queue.v1"`) {
		t.Fatalf("payload = %q", payload)
	}
}

func newPostgresIntegrationDSN(t *testing.T, ctx context.Context) string {
	t.Helper()

	port := freeTCPPort(t)
	containerID := dockerRunPostgres(t, ctx, postgresIntegrationImage, port)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	})
	return "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
}

func freeTCPPort(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen free tcp port: %v", err)
	}
	defer func() { _ = l.Close() }()
	return fmt.Sprintf("%d", l.Addr().(*net.TCPAddr).Port)
}

func dockerRunPostgres(t *testing.T, ctx context.Context, image string, port string) string {
	t.Helper()

	out, err := exec.CommandContext(
		ctx,
		"docker",
		"run",
		"-d",
		"--rm",
		"-p", "127.0.0.1:"+port+":5432",
		"-e", "POSTGRES_USER=postgres",
		"-e", "POSTGRES_PASSWORD=postgres",
		"-e", "POSTGRES_DB=postgres",
		image,
	).CombinedOutput()
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
		cancel()
		if err == nil {
			pingCtx, pingCancel := context.WithTimeout(ctx, time.Second)
			err = pool.Ping(pingCtx)
			pingCancel()
			if err == nil {
				return pool
			}
			pool.Close()
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("postgres not ready: %s", dsn)
	return nil
}
