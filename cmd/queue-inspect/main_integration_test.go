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

func TestPostgresInspectorIntegrationInspectAllAndMissingGroup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := queue.NewProducer(queue.ProducerConfig{
		Driver:       queue.DriverPostgres,
		PostgresPool: pool,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("first")); err != nil {
		t.Fatalf("Publish first: %v", err)
	}
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("second")); err != nil {
		t.Fatalf("Publish second: %v", err)
	}
	if err := producer.Publish(ctx, "proof.fulfillments.v1", []byte("fulfilled")); err != nil {
		t.Fatalf("Publish fulfillment: %v", err)
	}

	consumer, err := queue.NewConsumer(ctx, queue.ConsumerConfig{
		Driver:                queue.DriverPostgres,
		PostgresPool:          pool,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "queue-inspect-integration",
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	msg := readQueueMessage(t, consumer)
	if got, want := string(msg.Value), "first"; got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
	if err := msg.Ack(ctx); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatalf("consumer close: %v", err)
	}

	inspector := postgresInspector{pool: pool}
	allRows, err := inspector.Inspect(ctx, nil, nil)
	if err != nil {
		t.Fatalf("Inspect all: %v", err)
	}
	proofRequestor := findQueueStatsRow(t, allRows, "proof.requests.v1", "proof-requestor")
	if got, want := proofRequestor.MessageCount, int64(2); got != want {
		t.Fatalf("proof request message count = %d, want %d", got, want)
	}
	if got, want := proofRequestor.NextSeq, int64(2); got != want {
		t.Fatalf("proof request next seq = %d, want %d", got, want)
	}
	if got, want := proofRequestor.Backlog, int64(1); got != want {
		t.Fatalf("proof request backlog = %d, want %d", got, want)
	}
	topicOnly := findQueueStatsRow(t, allRows, "proof.fulfillments.v1", "")
	if got, want := topicOnly.MessageCount, int64(1); got != want {
		t.Fatalf("topic-only fulfillment count = %d, want %d", got, want)
	}

	filteredRows, err := inspector.Inspect(ctx, []string{"proof.requests.v1"}, []string{"deposit-relayer"})
	if err != nil {
		t.Fatalf("Inspect filtered: %v", err)
	}
	if len(filteredRows) != 1 {
		t.Fatalf("filtered row count = %d, want 1: %#v", len(filteredRows), filteredRows)
	}
	if got, want := filteredRows[0].ConsumerGroup, "deposit-relayer"; got != want {
		t.Fatalf("filtered group = %q, want %q", got, want)
	}
	if got, want := filteredRows[0].Backlog, int64(2); got != want {
		t.Fatalf("filtered missing-group backlog = %d, want %d", got, want)
	}
}

func readQueueMessage(t *testing.T, consumer queue.Consumer) queue.Message {
	t.Helper()
	select {
	case msg := <-consumer.Messages():
		return msg
	case err := <-consumer.Errors():
		t.Fatalf("consumer error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for queue message")
	}
	return queue.Message{}
}

func findQueueStatsRow(t *testing.T, rows []queueStatsRow, topic, group string) queueStatsRow {
	t.Helper()
	for _, row := range rows {
		if row.Topic == topic && row.ConsumerGroup == group {
			return row
		}
	}
	t.Fatalf("missing queue stats row topic=%s group=%s rows=%#v", topic, group, rows)
	return queueStatsRow{}
}

func newPostgresIntegrationPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()

	port := freeTCPPort(t)
	containerID := dockerRunPostgres(t, ctx, postgresIntegrationImage, port)
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", containerID).Run()
	})

	dsn := "postgres://postgres:postgres@127.0.0.1:" + port + "/postgres?sslmode=disable"
	return dialPostgres(t, ctx, dsn)
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
