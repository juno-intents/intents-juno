//go:build integration

package queue

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const postgresIntegrationImage = "postgres@sha256:4327b9fd295502f326f44153a1045a7170ddbfffed1c3829798328556cfd09e2"

func TestPostgresQueueIntegration_RoundTripAndResume(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := NewProducer(ProducerConfig{
		Driver:       DriverPostgres,
		PostgresPool: pool,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	consumer, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		PostgresPool:          pool,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "integration-a",
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("first")); err != nil {
		t.Fatalf("Publish first: %v", err)
	}
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("second")); err != nil {
		t.Fatalf("Publish second: %v", err)
	}

	first := readQueueMessage(t, consumer)
	if got, want := string(first.Value), "first"; got != want {
		t.Fatalf("first = %q, want %q", got, want)
	}
	if err := first.Ack(ctx); err != nil {
		t.Fatalf("ack first: %v", err)
	}
	if err := consumer.Close(); err != nil {
		t.Fatalf("close first consumer: %v", err)
	}

	resumed, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		PostgresPool:          pool,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "integration-b",
	})
	if err != nil {
		t.Fatalf("NewConsumer resumed: %v", err)
	}
	defer func() { _ = resumed.Close() }()

	second := readQueueMessage(t, resumed)
	if got, want := string(second.Value), "second"; got != want {
		t.Fatalf("second after resume = %q, want %q", got, want)
	}
	if err := second.Ack(ctx); err != nil {
		t.Fatalf("ack second: %v", err)
	}
}

func TestPostgresQueueIntegration_TargetedDeliveryDoesNotBlockUnrelatedGroups(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := NewProducer(ProducerConfig{
		Driver:       DriverPostgres,
		PostgresPool: pool,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()
	targeted, ok := producer.(TargetedProducer)
	if !ok {
		t.Fatalf("postgres producer does not support targeted delivery")
	}

	if err := targeted.PublishToGroup(ctx, "proof.fulfillments.v1", "deposit-relayer-proof", []byte("targeted-first")); err != nil {
		t.Fatalf("PublishToGroup: %v", err)
	}
	if err := producer.Publish(ctx, "proof.fulfillments.v1", []byte("broadcast-second")); err != nil {
		t.Fatalf("Publish broadcast: %v", err)
	}

	idle, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		PostgresPool:          pool,
		Group:                 "withdraw-finalizer-proof",
		Topics:                []string{"proof.fulfillments.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "idle",
	})
	if err != nil {
		t.Fatalf("NewConsumer idle: %v", err)
	}
	defer func() { _ = idle.Close() }()
	idleMsg := readQueueMessage(t, idle)
	if got, want := string(idleMsg.Value), "broadcast-second"; got != want {
		t.Fatalf("idle value = %q, want %q", got, want)
	}
	if err := idleMsg.Ack(ctx); err != nil {
		t.Fatalf("ack idle: %v", err)
	}

	target, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		PostgresPool:          pool,
		Group:                 "deposit-relayer-proof",
		Topics:                []string{"proof.fulfillments.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "target",
	})
	if err != nil {
		t.Fatalf("NewConsumer target: %v", err)
	}
	defer func() { _ = target.Close() }()

	first := readQueueMessage(t, target)
	if got, want := string(first.Value), "targeted-first"; got != want {
		t.Fatalf("target first value = %q, want %q", got, want)
	}
	if err := first.Ack(ctx); err != nil {
		t.Fatalf("ack target first: %v", err)
	}
	second := readQueueMessage(t, target)
	if got, want := string(second.Value), "broadcast-second"; got != want {
		t.Fatalf("target second value = %q, want %q", got, want)
	}
}

func TestPostgresQueueIntegration_EnqueueTxCommitsWithTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	store := &postgresQueueStore{pool: pool}
	if err := store.ensureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := EnqueuePostgresTx(ctx, tx, "proof.requests.v1", []byte("tx-committed")); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("EnqueuePostgresTx: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	consumer, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		PostgresPool:          pool,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "tx-commit",
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	msg := readQueueMessage(t, consumer)
	if got, want := string(msg.Value), "tx-committed"; got != want {
		t.Fatalf("message value = %q, want %q", got, want)
	}
}

func TestPostgresQueueIntegration_EnqueueTxRollsBackWithTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	store := &postgresQueueStore{pool: pool}
	if err := store.ensureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := EnqueuePostgresTx(ctx, tx, "proof.requests.v1", []byte("tx-rolled-back")); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("EnqueuePostgresTx: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback tx: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM queue_messages WHERE topic = $1`, "proof.requests.v1").Scan(&count); err != nil {
		t.Fatalf("count messages: %v", err)
	}
	if count != 0 {
		t.Fatalf("queue_messages count = %d, want 0 after rollback", count)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM queue_topic_sequences WHERE topic = $1`, "proof.requests.v1").Scan(&count); err != nil {
		t.Fatalf("count topic sequences: %v", err)
	}
	if count != 0 {
		t.Fatalf("queue_topic_sequences count = %d, want 0 after rollback", count)
	}
}

func TestPostgresQueueIntegration_SameGroupConsumersLeaseAndOrdering(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := NewProducer(ProducerConfig{
		Driver:       DriverPostgres,
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

	consumerA, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		PostgresPool:          pool,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: 250 * time.Millisecond,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "same-group-a",
	})
	if err != nil {
		t.Fatalf("NewConsumer A: %v", err)
	}
	defer func() { _ = consumerA.Close() }()

	consumerB, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		PostgresPool:          pool,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: 250 * time.Millisecond,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "same-group-b",
	})
	if err != nil {
		t.Fatalf("NewConsumer B: %v", err)
	}
	defer func() { _ = consumerB.Close() }()

	stale, owner := readQueueMessageFromEither(t, consumerA, consumerB)
	if got, want := string(stale.Value), "first"; got != want {
		t.Fatalf("initial value = %q, want %q", got, want)
	}
	assertNoQueueMessages(t, consumerA, consumerB, 80*time.Millisecond)
	time.Sleep(300 * time.Millisecond)
	assertNoQueueMessages(t, consumerA, consumerB, 80*time.Millisecond)

	var retry Message
	switch owner {
	case "a":
		if err := consumerA.Close(); err != nil {
			t.Fatalf("close owner consumer a: %v", err)
		}
		time.Sleep(270 * time.Millisecond)
		retry = readQueueMessage(t, consumerB)
	case "b":
		if err := consumerB.Close(); err != nil {
			t.Fatalf("close owner consumer b: %v", err)
		}
		time.Sleep(270 * time.Millisecond)
		retry = readQueueMessage(t, consumerA)
	default:
		t.Fatalf("unexpected owner %q", owner)
	}
	if got, want := string(retry.Value), "first"; got != want {
		t.Fatalf("retry value = %q, want %q", got, want)
	}
	if err := stale.Ack(ctx); err == nil {
		t.Fatal("stale ack succeeded")
	}

	if err := retry.Ack(ctx); err != nil {
		t.Fatalf("ack retry: %v", err)
	}
	var second Message
	if owner == "a" {
		second = readQueueMessage(t, consumerB)
	} else {
		second = readQueueMessage(t, consumerA)
	}
	if got, want := string(second.Value), "second"; got != want {
		t.Fatalf("second value = %q, want %q", got, want)
	}
	if err := second.Ack(ctx); err != nil {
		t.Fatalf("ack second: %v", err)
	}
}

func TestPostgresQueueIntegration_InitialPositionLatest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := NewProducer(ProducerConfig{
		Driver:       DriverPostgres,
		PostgresPool: pool,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("old")); err != nil {
		t.Fatalf("Publish old: %v", err)
	}

	consumer, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                  DriverPostgres,
		PostgresPool:            pool,
		Group:                   "proof-requestor",
		Topics:                  []string{"proof.requests.v1"},
		PostgresInitialPosition: PostgresInitialPositionLatest,
		PostgresLeaseDuration:   time.Minute,
		PostgresPollInterval:    time.Millisecond,
		PostgresOwner:           "latest-consumer",
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	assertNoQueueMessage(t, consumer, 80*time.Millisecond)

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("new")); err != nil {
		t.Fatalf("Publish new: %v", err)
	}
	got := readQueueMessage(t, consumer)
	if string(got.Value) != "new" {
		t.Fatalf("initial latest value = %q, want new", string(got.Value))
	}
	if err := got.Ack(ctx); err != nil {
		t.Fatalf("ack new: %v", err)
	}
}

func TestPostgresQueueIntegration_ExplicitInitialSequence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := NewProducer(ProducerConfig{
		Driver:       DriverPostgres,
		PostgresPool: pool,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	for _, payload := range []string{"one", "two", "three"} {
		if err := producer.Publish(ctx, "proof.requests.v1", []byte(payload)); err != nil {
			t.Fatalf("Publish %s: %v", payload, err)
		}
	}

	consumer, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                   DriverPostgres,
		PostgresPool:             pool,
		Group:                    "proof-requestor",
		Topics:                   []string{"proof.requests.v1"},
		PostgresInitialSequences: map[string]int64{"proof.requests.v1": 3},
		PostgresLeaseDuration:    time.Minute,
		PostgresPollInterval:     time.Millisecond,
		PostgresOwner:            "explicit-seq-consumer",
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	got := readQueueMessage(t, consumer)
	if string(got.Value) != "three" {
		t.Fatalf("explicit initial sequence value = %q, want three", string(got.Value))
	}
	if err := got.Ack(ctx); err != nil {
		t.Fatalf("ack three: %v", err)
	}
}

func TestPostgresQueueIntegration_RenewsWithSlowPollInterval(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := NewProducer(ProducerConfig{
		Driver:       DriverPostgres,
		PostgresPool: pool,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("first")); err != nil {
		t.Fatalf("Publish first: %v", err)
	}

	consumerA, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                   DriverPostgres,
		PostgresPool:             pool,
		Group:                    "proof-requestor",
		Topics:                   []string{"proof.requests.v1"},
		PostgresLeaseDuration:    120 * time.Millisecond,
		PostgresMaxLeaseDuration: time.Second,
		PostgresPollInterval:     time.Second,
		PostgresOwner:            "slow-poll-a",
	})
	if err != nil {
		t.Fatalf("NewConsumer A: %v", err)
	}
	defer func() { _ = consumerA.Close() }()

	first := readQueueMessage(t, consumerA)
	if got, want := string(first.Value), "first"; got != want {
		t.Fatalf("initial value = %q, want %q", got, want)
	}

	consumerB, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                   DriverPostgres,
		PostgresPool:             pool,
		Group:                    "proof-requestor",
		Topics:                   []string{"proof.requests.v1"},
		PostgresLeaseDuration:    120 * time.Millisecond,
		PostgresMaxLeaseDuration: time.Second,
		PostgresPollInterval:     time.Millisecond,
		PostgresOwner:            "slow-poll-b",
	})
	if err != nil {
		t.Fatalf("NewConsumer B: %v", err)
	}
	defer func() { _ = consumerB.Close() }()

	time.Sleep(180 * time.Millisecond)
	assertNoQueueMessages(t, consumerA, consumerB, 80*time.Millisecond)
}

func TestPostgresQueueIntegration_UnackedRetriesAfterMaxLease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := NewProducer(ProducerConfig{
		Driver:       DriverPostgres,
		PostgresPool: pool,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("retry")); err != nil {
		t.Fatalf("Publish retry: %v", err)
	}

	consumerA, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                   DriverPostgres,
		PostgresPool:             pool,
		Group:                    "proof-requestor",
		Topics:                   []string{"proof.requests.v1"},
		PostgresLeaseDuration:    100 * time.Millisecond,
		PostgresMaxLeaseDuration: 250 * time.Millisecond,
		PostgresPollInterval:     time.Millisecond,
		PostgresOwner:            "bounded-a",
	})
	if err != nil {
		t.Fatalf("NewConsumer A: %v", err)
	}
	defer func() { _ = consumerA.Close() }()

	consumerB, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                   DriverPostgres,
		PostgresPool:             pool,
		Group:                    "proof-requestor",
		Topics:                   []string{"proof.requests.v1"},
		PostgresLeaseDuration:    100 * time.Millisecond,
		PostgresMaxLeaseDuration: 250 * time.Millisecond,
		PostgresPollInterval:     time.Millisecond,
		PostgresOwner:            "bounded-b",
	})
	if err != nil {
		t.Fatalf("NewConsumer B: %v", err)
	}
	defer func() { _ = consumerB.Close() }()

	first, _ := readQueueMessageFromEither(t, consumerA, consumerB)
	if got, want := string(first.Value), "retry"; got != want {
		t.Fatalf("initial value = %q, want %q", got, want)
	}
	assertNoQueueMessages(t, consumerA, consumerB, 120*time.Millisecond)

	time.Sleep(250 * time.Millisecond)
	retry, _ := readQueueMessageFromEither(t, consumerA, consumerB)
	if got, want := string(retry.Value), "retry"; got != want {
		t.Fatalf("retry value = %q, want %q", got, want)
	}
	if err := first.Ack(ctx); err == nil {
		t.Fatal("stale first ack succeeded")
	}
	if err := retry.Ack(ctx); err != nil {
		t.Fatalf("ack retry: %v", err)
	}
}

func TestPostgresQueueIntegration_ExpiredAckBeforeReclaimFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := NewProducer(ProducerConfig{
		Driver:       DriverPostgres,
		PostgresPool: pool,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("expired")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	consumer, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                   DriverPostgres,
		PostgresPool:             pool,
		Group:                    "proof-requestor",
		Topics:                   []string{"proof.requests.v1"},
		PostgresLeaseDuration:    80 * time.Millisecond,
		PostgresMaxLeaseDuration: 80 * time.Millisecond,
		PostgresPollInterval:     time.Second,
		PostgresOwner:            "expired-ack",
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	msg := readQueueMessage(t, consumer)
	if err := consumer.Close(); err != nil {
		t.Fatalf("close consumer: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if err := msg.Ack(ctx); err == nil {
		t.Fatal("expired ack succeeded before reclaim")
	}
}

func TestPostgresQueueIntegration_ExpiredRenewBeforeReclaimFails(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	store := &postgresQueueStore{pool: pool}
	if err := store.ensureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	if err := store.enqueue(ctx, "proof.requests.v1", []byte("expired")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	records, err := store.claim(ctx, postgresQueueClaimConfig{
		group:            "proof-requestor",
		topics:           []string{"proof.requests.v1"},
		owner:            "expired-renew",
		initialPosition:  PostgresInitialPositionEarliest,
		leaseDuration:    80 * time.Millisecond,
		materializeLimit: 1,
		limit:            1,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}

	time.Sleep(100 * time.Millisecond)
	err = store.renew(ctx, "proof-requestor", records[0].topic, records[0].seq, records[0].owner, records[0].attempt, time.Minute)
	if !strings.Contains(fmt.Sprint(err), errPostgresQueueStaleLease.Error()) {
		t.Fatalf("renew err = %v, want stale lease", err)
	}
}

func TestPostgresQueueIntegration_AckUsesStatementTimeAfterRowLockWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	store := &postgresQueueStore{pool: pool}
	rec := claimPostgresIntegrationRecord(t, ctx, store, 120*time.Millisecond)
	tx := lockPostgresIntegrationDelivery(t, ctx, pool, rec)

	errCh := make(chan error, 1)
	go func() {
		errCh <- store.ack(ctx, "proof-requestor", rec.topic, rec.seq, rec.owner, rec.attempt)
	}()

	time.Sleep(160 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit lock tx: %v", err)
	}
	err := <-errCh
	if !strings.Contains(fmt.Sprint(err), errPostgresQueueStaleAck.Error()) {
		t.Fatalf("ack err = %v, want stale ack", err)
	}
}

func TestPostgresQueueIntegration_RenewUsesStatementTimeAfterRowLockWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	store := &postgresQueueStore{pool: pool}
	rec := claimPostgresIntegrationRecord(t, ctx, store, 120*time.Millisecond)
	tx := lockPostgresIntegrationDelivery(t, ctx, pool, rec)

	errCh := make(chan error, 1)
	go func() {
		errCh <- store.renew(ctx, "proof-requestor", rec.topic, rec.seq, rec.owner, rec.attempt, time.Minute)
	}()

	time.Sleep(160 * time.Millisecond)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit lock tx: %v", err)
	}
	err := <-errCh
	if !strings.Contains(fmt.Sprint(err), errPostgresQueueStaleLease.Error()) {
		t.Fatalf("renew err = %v, want stale lease", err)
	}
}

func TestPostgresQueueIntegration_ConcurrentProducersNoLossOrDuplicates(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	producer, err := NewProducer(ProducerConfig{
		Driver:       DriverPostgres,
		PostgresPool: pool,
	})
	if err != nil {
		t.Fatalf("NewProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	const totalMessages = 50
	var wg sync.WaitGroup
	errCh := make(chan error, totalMessages)
	for i := 0; i < totalMessages; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("payload-%02d", i))
			if err := producer.Publish(ctx, "proof.requests.v1", payload); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}

	rows, err := pool.Query(ctx, `
		SELECT seq, encode(payload, 'escape')
		FROM queue_messages
		WHERE topic = $1
		ORDER BY seq
	`, "proof.requests.v1")
	if err != nil {
		t.Fatalf("query queued messages: %v", err)
	}
	defer rows.Close()

	wantBySeq := make([]string, 0, totalMessages)
	for rows.Next() {
		var seq int64
		var payload string
		if err := rows.Scan(&seq, &payload); err != nil {
			t.Fatalf("scan queued message: %v", err)
		}
		wantSeq := int64(len(wantBySeq) + 1)
		if seq != wantSeq {
			t.Fatalf("seq = %d at position %d, want %d", seq, len(wantBySeq), wantSeq)
		}
		wantBySeq = append(wantBySeq, payload)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate queued messages: %v", err)
	}
	if len(wantBySeq) != totalMessages {
		t.Fatalf("queued messages = %d, want %d", len(wantBySeq), totalMessages)
	}

	consumer, err := NewConsumer(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		PostgresPool:          pool,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "concurrent-consumer",
	})
	if err != nil {
		t.Fatalf("NewConsumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	seen := make(map[string]struct{}, totalMessages)
	for i := 0; i < totalMessages; i++ {
		msg := readQueueMessage(t, consumer)
		got := string(msg.Value)
		if got != wantBySeq[i] {
			t.Fatalf("delivered payload at seq %d = %q, want %q", i+1, got, wantBySeq[i])
		}
		if _, ok := seen[got]; ok {
			t.Fatalf("duplicate delivered payload %q", got)
		}
		seen[got] = struct{}{}
		if err := msg.Ack(ctx); err != nil {
			t.Fatalf("ack %d: %v", i+1, err)
		}
	}
	if len(seen) != totalMessages {
		t.Fatalf("seen messages = %d, want %d", len(seen), totalMessages)
	}
}

func TestPostgresQueueIntegration_ConcurrentSchemaCreation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool := newPostgresIntegrationPool(t, ctx)
	defer pool.Close()

	const workers = 16
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				producer, err := NewProducer(ProducerConfig{
					Driver:       DriverPostgres,
					PostgresPool: pool,
				})
				if err != nil {
					errCh <- err
					return
				}
				errCh <- producer.Close()
				return
			}
			consumer, err := NewConsumer(ctx, ConsumerConfig{
				Driver:                DriverPostgres,
				PostgresPool:          pool,
				Group:                 "schema-" + strconv.Itoa(i),
				Topics:                []string{"proof.requests.v1"},
				PostgresLeaseDuration: time.Minute,
				PostgresPollInterval:  time.Millisecond,
				PostgresOwner:         "schema-" + strconv.Itoa(i),
			})
			if err != nil {
				errCh <- err
				return
			}
			errCh <- consumer.Close()
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent startup: %v", err)
		}
	}
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

func claimPostgresIntegrationRecord(t *testing.T, ctx context.Context, store *postgresQueueStore, lease time.Duration) postgresQueueRecord {
	t.Helper()

	if err := store.ensureSchema(ctx); err != nil {
		t.Fatalf("ensure schema: %v", err)
	}
	if err := store.enqueue(ctx, "proof.requests.v1", []byte("locked")); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	records, err := store.claim(ctx, postgresQueueClaimConfig{
		group:            "proof-requestor",
		topics:           []string{"proof.requests.v1"},
		owner:            "lock-wait",
		initialPosition:  PostgresInitialPositionEarliest,
		leaseDuration:    lease,
		materializeLimit: 1,
		limit:            1,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	return records[0]
}

func lockPostgresIntegrationDelivery(t *testing.T, ctx context.Context, pool *pgxpool.Pool, rec postgresQueueRecord) pgx.Tx {
	t.Helper()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		SELECT 1
		FROM queue_deliveries
		WHERE consumer_group = $1
		  AND topic = $2
		  AND seq = $3
		FOR UPDATE
	`, "proof-requestor", rec.topic, rec.seq); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("lock delivery: %v", err)
	}
	return tx
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

func readQueueMessageFromEither(t *testing.T, a Consumer, b Consumer) (Message, string) {
	t.Helper()

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case msg, ok := <-a.Messages():
			if !ok {
				t.Fatal("consumer a messages channel closed")
			}
			return msg, "a"
		case msg, ok := <-b.Messages():
			if !ok {
				t.Fatal("consumer b messages channel closed")
			}
			return msg, "b"
		case err, ok := <-a.Errors():
			if ok && err != nil {
				t.Fatalf("consumer a error: %v", err)
			}
		case err, ok := <-b.Errors():
			if ok && err != nil {
				t.Fatalf("consumer b error: %v", err)
			}
		case <-timer.C:
			t.Fatal("timeout waiting for queue message")
		}
	}
}

func assertNoQueueMessages(t *testing.T, a Consumer, b Consumer, wait time.Duration) {
	t.Helper()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case msg, ok := <-a.Messages():
		if ok {
			t.Fatalf("unexpected message from consumer a: topic=%s value=%q", msg.Topic, string(msg.Value))
		}
	case msg, ok := <-b.Messages():
		if ok {
			t.Fatalf("unexpected message from consumer b: topic=%s value=%q", msg.Topic, string(msg.Value))
		}
	case err, ok := <-a.Errors():
		if ok && err != nil {
			t.Fatalf("consumer a error: %v", err)
		}
	case err, ok := <-b.Errors():
		if ok && err != nil {
			t.Fatalf("consumer b error: %v", err)
		}
	case <-timer.C:
	}
}
