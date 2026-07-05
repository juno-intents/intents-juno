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

func TestPostgresInspectorIntegrationTargetedBacklogOnlyCountsVisibleGroups(t *testing.T) {
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
	targeted, ok := producer.(queue.TargetedProducer)
	if !ok {
		t.Fatalf("postgres producer does not support targeted delivery")
	}
	if err := targeted.PublishToGroup(ctx, "proof.fulfillments.v1", "deposit-relayer-proof", []byte("fulfilled")); err != nil {
		t.Fatalf("PublishToGroup: %v", err)
	}

	inspector := postgresInspector{pool: pool}
	allRows, err := inspector.Inspect(ctx, nil, nil)
	if err != nil {
		t.Fatalf("Inspect all: %v", err)
	}
	target := findQueueStatsRow(t, allRows, "proof.fulfillments.v1", "deposit-relayer-proof")
	if got, want := target.Backlog, int64(1); got != want {
		t.Fatalf("target backlog = %d, want %d", got, want)
	}

	filteredRows, err := inspector.Inspect(ctx, []string{"proof.fulfillments.v1"}, []string{"deposit-relayer-proof", "withdraw-finalizer-proof"})
	if err != nil {
		t.Fatalf("Inspect filtered: %v", err)
	}
	target = findQueueStatsRow(t, filteredRows, "proof.fulfillments.v1", "deposit-relayer-proof")
	if got, want := target.Backlog, int64(1); got != want {
		t.Fatalf("filtered target backlog = %d, want %d", got, want)
	}
	idle := findQueueStatsRow(t, filteredRows, "proof.fulfillments.v1", "withdraw-finalizer-proof")
	if got, want := idle.Backlog, int64(0); got != want {
		t.Fatalf("filtered idle backlog = %d, want %d", got, want)
	}
}

func TestPostgresInspectorIntegrationLegacySchemaWithoutTargetColumn(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	if _, err := pool.Exec(ctx, legacyPostgresQueueSchemaSQL); err != nil {
		t.Fatalf("create legacy queue schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO queue_messages (topic, seq, payload, created_at)
VALUES
	('proof.fulfillments.v1', 1, decode('6669727374', 'hex'), now()),
	('proof.fulfillments.v1', 2, decode('7365636f6e64', 'hex'), now());
INSERT INTO queue_group_offsets (consumer_group, topic, next_seq, created_at, updated_at)
VALUES ('legacy-proof-group', 'proof.fulfillments.v1', 1, now(), now());
`); err != nil {
		t.Fatalf("seed legacy queue schema: %v", err)
	}

	inspector := postgresInspector{pool: pool}
	hasTargetColumn, err := inspector.hasTargetConsumerGroupColumn(ctx)
	if err != nil {
		t.Fatalf("hasTargetConsumerGroupColumn: %v", err)
	}
	if hasTargetColumn {
		t.Fatalf("legacy schema unexpectedly has target_consumer_group")
	}
	rows, err := inspector.Inspect(ctx, []string{"proof.fulfillments.v1"}, []string{"legacy-proof-group"})
	if err != nil {
		t.Fatalf("Inspect legacy schema: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("legacy row count = %d, want 1: %#v", len(rows), rows)
	}
	row := rows[0]
	if got, want := row.Topic, "proof.fulfillments.v1"; got != want {
		t.Fatalf("topic = %q, want %q", got, want)
	}
	if got, want := row.ConsumerGroup, "legacy-proof-group"; got != want {
		t.Fatalf("consumer group = %q, want %q", got, want)
	}
	if got, want := row.MessageCount, int64(2); got != want {
		t.Fatalf("message count = %d, want %d", got, want)
	}
	if got, want := row.Backlog, int64(2); got != want {
		t.Fatalf("backlog = %d, want %d", got, want)
	}
}

const legacyPostgresQueueSchemaSQL = `
CREATE TABLE queue_topic_sequences (
	topic TEXT PRIMARY KEY,
	next_seq BIGINT NOT NULL DEFAULT 1,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	CONSTRAINT queue_topic_sequences_topic_nonempty CHECK (topic <> ''),
	CONSTRAINT queue_topic_sequences_next_seq_positive CHECK (next_seq > 0)
);

CREATE TABLE queue_messages (
	topic TEXT NOT NULL,
	seq BIGINT NOT NULL,
	payload BYTEA NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (topic, seq),
	CONSTRAINT queue_messages_topic_nonempty CHECK (topic <> ''),
	CONSTRAINT queue_messages_seq_positive CHECK (seq > 0)
);

CREATE TABLE queue_group_offsets (
	consumer_group TEXT NOT NULL,
	topic TEXT NOT NULL,
	next_seq BIGINT NOT NULL DEFAULT 1,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (consumer_group, topic),
	CONSTRAINT queue_group_offsets_group_nonempty CHECK (consumer_group <> ''),
	CONSTRAINT queue_group_offsets_topic_nonempty CHECK (topic <> ''),
	CONSTRAINT queue_group_offsets_next_seq_positive CHECK (next_seq > 0)
);

CREATE TABLE queue_deliveries (
	topic TEXT NOT NULL,
	seq BIGINT NOT NULL,
	consumer_group TEXT NOT NULL,
	attempt_count INTEGER NOT NULL DEFAULT 0,
	lease_owner TEXT,
	lease_expires_at TIMESTAMPTZ,
	acked_at TIMESTAMPTZ,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
	PRIMARY KEY (topic, seq, consumer_group),
	FOREIGN KEY (topic, seq) REFERENCES queue_messages(topic, seq) ON DELETE CASCADE,
	CONSTRAINT queue_deliveries_group_nonempty CHECK (consumer_group <> ''),
	CONSTRAINT queue_deliveries_attempt_nonnegative CHECK (attempt_count >= 0)
);
`

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
