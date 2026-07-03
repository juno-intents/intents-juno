package queue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/queueauth"
)

func TestPostgresQueueDeliversPerTopicInPublishOrder(t *testing.T) {
	t.Parallel()

	backend := newTestPostgresQueueBackend(time.Now)
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	consumer, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
	}, backend)
	if err != nil {
		t.Fatalf("newPostgresConsumerWithBackend: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("first")); err != nil {
		t.Fatalf("Publish first: %v", err)
	}
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("second")); err != nil {
		t.Fatalf("Publish second: %v", err)
	}

	first := readQueueMessage(t, consumer)
	if got, want := string(first.Value), "first"; got != want {
		t.Fatalf("first value = %q, want %q", got, want)
	}
	if err := first.Ack(ctx); err != nil {
		t.Fatalf("ack first: %v", err)
	}

	second := readQueueMessage(t, consumer)
	if got, want := string(second.Value), "second"; got != want {
		t.Fatalf("second value = %q, want %q", got, want)
	}
	if err := second.Ack(ctx); err != nil {
		t.Fatalf("ack second: %v", err)
	}
}

func TestPostgresQueueRetriesUnackedAfterLeaseExpires(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	backend := newTestPostgresQueueBackend(func() time.Time { return now })
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx := context.Background()
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("retry-me")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	consumerA, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: 10 * time.Millisecond,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "a",
	}, backend)
	if err != nil {
		t.Fatalf("new consumer a: %v", err)
	}
	first := readQueueMessage(t, consumerA)
	if got, want := string(first.Value), "retry-me"; got != want {
		t.Fatalf("first value = %q, want %q", got, want)
	}
	if err := consumerA.Close(); err != nil {
		t.Fatalf("close consumer a: %v", err)
	}

	now = now.Add(11 * time.Millisecond)
	consumerB, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "b",
	}, backend)
	if err != nil {
		t.Fatalf("new consumer b: %v", err)
	}
	defer func() { _ = consumerB.Close() }()

	retry := readQueueMessage(t, consumerB)
	if got, want := string(retry.Value), "retry-me"; got != want {
		t.Fatalf("retry value = %q, want %q", got, want)
	}
	if err := retry.Ack(ctx); err != nil {
		t.Fatalf("ack retry: %v", err)
	}
}

func TestPostgresQueueRejectsStaleAckAfterLeaseReclaim(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	backend := newTestPostgresQueueBackend(func() time.Time { return now })
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx := context.Background()
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("first")); err != nil {
		t.Fatalf("Publish first: %v", err)
	}
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("second")); err != nil {
		t.Fatalf("Publish second: %v", err)
	}

	consumerA, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: 10 * time.Millisecond,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "a",
	}, backend)
	if err != nil {
		t.Fatalf("new consumer a: %v", err)
	}
	stale := readQueueMessage(t, consumerA)
	if err := consumerA.Close(); err != nil {
		t.Fatalf("close consumer a: %v", err)
	}

	now = now.Add(11 * time.Millisecond)
	consumerB, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "b",
	}, backend)
	if err != nil {
		t.Fatalf("new consumer b: %v", err)
	}
	defer func() { _ = consumerB.Close() }()

	retry := readQueueMessage(t, consumerB)
	if got, want := string(retry.Value), "first"; got != want {
		t.Fatalf("retry value = %q, want %q", got, want)
	}
	if err := stale.Ack(ctx); err == nil {
		t.Fatal("stale ack succeeded")
	}
	assertNoQueueMessage(t, consumerB, 30*time.Millisecond)

	if err := retry.Ack(ctx); err != nil {
		t.Fatalf("ack retry: %v", err)
	}
	second := readQueueMessage(t, consumerB)
	if got, want := string(second.Value), "second"; got != want {
		t.Fatalf("second value = %q, want %q", got, want)
	}
}

func TestPostgresQueueRejectsAckAfterLeaseExpiresBeforeReclaim(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	backend := newTestPostgresQueueBackend(func() time.Time { return now })
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx := context.Background()
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("expired")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	consumer, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                   DriverPostgres,
		Group:                    "proof-requestor",
		Topics:                   []string{"proof.requests.v1"},
		PostgresLeaseDuration:    10 * time.Millisecond,
		PostgresMaxLeaseDuration: 10 * time.Millisecond,
		PostgresPollInterval:     time.Minute,
		PostgresOwner:            "a",
	}, backend)
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	msg := readQueueMessage(t, consumer)
	if err := consumer.Close(); err != nil {
		t.Fatalf("close consumer: %v", err)
	}

	now = now.Add(11 * time.Millisecond)
	if err := msg.Ack(ctx); err == nil {
		t.Fatal("expired ack succeeded before reclaim")
	}
}

func TestPostgresQueueRejectsRenewAfterLeaseExpiresBeforeReclaim(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	backend := newTestPostgresQueueBackend(func() time.Time { return now })
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx := context.Background()
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("expired")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	records, err := backend.claim(ctx, postgresQueueClaimConfig{
		group:            "proof-requestor",
		topics:           []string{"proof.requests.v1"},
		owner:            "a",
		initialPosition:  PostgresInitialPositionEarliest,
		leaseDuration:    10 * time.Millisecond,
		materializeLimit: 1,
		limit:            1,
	})
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}

	now = now.Add(11 * time.Millisecond)
	err = backend.renew(ctx, "proof-requestor", records[0].topic, records[0].seq, records[0].owner, records[0].attempt, time.Minute)
	if !errors.Is(err, errPostgresQueueStaleLease) {
		t.Fatalf("renew err = %v, want stale lease", err)
	}
}

func TestPostgresQueueRejectsMaxLeaseShorterThanLease(t *testing.T) {
	t.Parallel()

	backend := newTestPostgresQueueBackend(time.Now)
	ctx := context.Background()
	_, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                   DriverPostgres,
		Group:                    "proof-requestor",
		Topics:                   []string{"proof.requests.v1"},
		PostgresLeaseDuration:    time.Minute,
		PostgresMaxLeaseDuration: time.Second,
		PostgresPollInterval:     time.Millisecond,
	}, backend)
	if err == nil {
		t.Fatal("new consumer succeeded with max lease shorter than lease")
	}
}

func TestPostgresQueueConsumerResumeSkipsAckedMessages(t *testing.T) {
	t.Parallel()

	backend := newTestPostgresQueueBackend(time.Now)
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx := context.Background()
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("acked")); err != nil {
		t.Fatalf("Publish acked: %v", err)
	}

	consumerA, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "a",
	}, backend)
	if err != nil {
		t.Fatalf("new consumer a: %v", err)
	}
	msg := readQueueMessage(t, consumerA)
	if err := msg.Ack(ctx); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if err := consumerA.Close(); err != nil {
		t.Fatalf("close consumer a: %v", err)
	}

	consumerB, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "proof-requestor",
		Topics:                []string{"proof.requests.v1"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "b",
	}, backend)
	if err != nil {
		t.Fatalf("new consumer b: %v", err)
	}
	defer func() { _ = consumerB.Close() }()

	assertNoQueueMessage(t, consumerB, 30*time.Millisecond)

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("new")); err != nil {
		t.Fatalf("Publish new: %v", err)
	}
	got := readQueueMessage(t, consumerB)
	if string(got.Value) != "new" {
		t.Fatalf("resumed consumer value = %q, want new", string(got.Value))
	}
}

func TestPostgresQueueInitialPositionLatestSkipsExistingMessages(t *testing.T) {
	t.Parallel()

	backend := newTestPostgresQueueBackend(time.Now)
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx := context.Background()
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("old")); err != nil {
		t.Fatalf("Publish old: %v", err)
	}

	consumer, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                  DriverPostgres,
		Group:                   "proof-requestor",
		Topics:                  []string{"proof.requests.v1"},
		PostgresInitialPosition: PostgresInitialPositionLatest,
		PostgresLeaseDuration:   time.Minute,
		PostgresPollInterval:    time.Millisecond,
	}, backend)
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	assertNoQueueMessage(t, consumer, 30*time.Millisecond)

	if err := producer.Publish(ctx, "proof.requests.v1", []byte("new")); err != nil {
		t.Fatalf("Publish new: %v", err)
	}
	got := readQueueMessage(t, consumer)
	if string(got.Value) != "new" {
		t.Fatalf("initial latest consumer value = %q, want new", string(got.Value))
	}
}

func TestPostgresQueueExplicitInitialSequence(t *testing.T) {
	t.Parallel()

	backend := newTestPostgresQueueBackend(time.Now)
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx := context.Background()
	for _, payload := range []string{"one", "two", "three"} {
		if err := producer.Publish(ctx, "proof.requests.v1", []byte(payload)); err != nil {
			t.Fatalf("Publish %s: %v", payload, err)
		}
	}

	consumer, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                   DriverPostgres,
		Group:                    "proof-requestor",
		Topics:                   []string{"proof.requests.v1"},
		PostgresInitialSequences: map[string]int64{"proof.requests.v1": 3},
		PostgresLeaseDuration:    time.Minute,
		PostgresPollInterval:     time.Millisecond,
	}, backend)
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	got := readQueueMessage(t, consumer)
	if string(got.Value) != "three" {
		t.Fatalf("explicit initial sequence value = %q, want three", string(got.Value))
	}
}

func TestPostgresQueueDoesNotAdvancePastEarlierUnackedMessage(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	backend := newTestPostgresQueueBackend(func() time.Time { return now })
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx := context.Background()
	if err := producer.Publish(ctx, "withdrawals.requested.v2", []byte("first")); err != nil {
		t.Fatalf("Publish first: %v", err)
	}
	if err := producer.Publish(ctx, "withdrawals.requested.v2", []byte("second")); err != nil {
		t.Fatalf("Publish second: %v", err)
	}

	consumerA, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "withdraw-coordinator",
		Topics:                []string{"withdrawals.requested.v2"},
		PostgresLeaseDuration: 10 * time.Millisecond,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "a",
	}, backend)
	if err != nil {
		t.Fatalf("new consumer a: %v", err)
	}
	first := readQueueMessage(t, consumerA)
	if got, want := string(first.Value), "first"; got != want {
		t.Fatalf("first value = %q, want %q", got, want)
	}
	if err := consumerA.Close(); err != nil {
		t.Fatalf("close consumer a: %v", err)
	}

	now = now.Add(11 * time.Millisecond)
	consumerB, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "withdraw-coordinator",
		Topics:                []string{"withdrawals.requested.v2"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
		PostgresOwner:         "b",
	}, backend)
	if err != nil {
		t.Fatalf("new consumer b: %v", err)
	}
	defer func() { _ = consumerB.Close() }()

	retry := readQueueMessage(t, consumerB)
	if got, want := string(retry.Value), "first"; got != want {
		t.Fatalf("retry value = %q, want %q", got, want)
	}
	if err := retry.Ack(ctx); err != nil {
		t.Fatalf("ack retry: %v", err)
	}

	second := readQueueMessage(t, consumerB)
	if got, want := string(second.Value), "second"; got != want {
		t.Fatalf("second value = %q, want %q", got, want)
	}
}

func TestPostgresQueuePreservesCriticalTopicWirePayload(t *testing.T) {
	t.Parallel()

	backend := newTestPostgresQueueBackend(time.Now)
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	codec := queueauth.New(queueauth.Config{
		KeyID:  "ops-1",
		Secret: []byte("super-secret-key"),
		Now: func() time.Time {
			return time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
		},
		Rand: bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)),
	})
	raw := []byte(`{"version":"deposits.event.v2"}`)
	wire, err := queueauth.WrapPayload(codec, "deposits.event.v2", raw)
	if err != nil {
		t.Fatalf("WrapPayload: %v", err)
	}

	ctx := context.Background()
	if err := producer.Publish(ctx, "deposits.event.v2", wire); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	consumer, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "deposit-relayer",
		Topics:                []string{"deposits.event.v2"},
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
	}, backend)
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	msg := readQueueMessage(t, consumer)
	if !bytes.Equal(msg.Value, wire) {
		t.Fatalf("wire payload changed: got %x want %x", msg.Value, wire)
	}
	unwrapped, err := queueauth.UnwrapPayload(codec, msg.Topic, msg.Value)
	if err != nil {
		t.Fatalf("UnwrapPayload: %v", err)
	}
	if !bytes.Equal(unwrapped, raw) {
		t.Fatalf("unwrapped payload changed: got %s want %s", unwrapped, raw)
	}
}

func TestPostgresQueueAcceptsProductionTopicNames(t *testing.T) {
	t.Parallel()

	topics := []string{
		"proof.requests.v1",
		"proof.fulfillments.v1",
		"proof.failures.v1",
		"ops.alerts.v1",
		"checkpoints.signatures.v1",
		"checkpoints.package.v1",
		"checkpoints.packages.v1",
		"deposits.event.v2",
		"withdrawals.requested.v2",
	}
	backend := newTestPostgresQueueBackend(time.Now)
	producer, err := newPostgresProducerWithBackend(backend)
	if err != nil {
		t.Fatalf("newPostgresProducerWithBackend: %v", err)
	}
	defer func() { _ = producer.Close() }()

	ctx := context.Background()
	for _, topic := range topics {
		if err := producer.Publish(ctx, topic, []byte(topic)); err != nil {
			t.Fatalf("Publish(%s): %v", topic, err)
		}
	}

	consumer, err := newPostgresConsumerWithBackend(ctx, ConsumerConfig{
		Driver:                DriverPostgres,
		Group:                 "compat",
		Topics:                topics,
		PostgresLeaseDuration: time.Minute,
		PostgresPollInterval:  time.Millisecond,
	}, backend)
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	defer func() { _ = consumer.Close() }()

	got := make([]string, 0, len(topics))
	for range topics {
		msg := readQueueMessage(t, consumer)
		if string(msg.Value) != msg.Topic {
			t.Fatalf("topic/payload mismatch: topic=%q payload=%q", msg.Topic, string(msg.Value))
		}
		got = append(got, msg.Topic)
	}
	sort.Strings(got)
	want := append([]string(nil), topics...)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("topics got=%v want=%v", got, want)
	}
}

func readQueueMessage(t *testing.T, consumer Consumer) Message {
	t.Helper()

	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case msg, ok := <-consumer.Messages():
			if !ok {
				t.Fatal("messages channel closed")
			}
			return msg
		case err, ok := <-consumer.Errors():
			if ok && err != nil {
				t.Fatalf("consumer error: %v", err)
			}
		case <-timer.C:
			t.Fatal("timeout waiting for queue message")
		}
	}
}

func assertNoQueueMessage(t *testing.T, consumer Consumer, wait time.Duration) {
	t.Helper()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case msg, ok := <-consumer.Messages():
		if ok {
			t.Fatalf("unexpected message: topic=%s value=%q", msg.Topic, string(msg.Value))
		}
	case err, ok := <-consumer.Errors():
		if ok && err != nil {
			t.Fatalf("consumer error: %v", err)
		}
	case <-timer.C:
	}
}

type testPostgresQueueBackend struct {
	mu         sync.Mutex
	now        func() time.Time
	nextSeq    map[string]int64
	offsets    map[testPostgresQueueOffsetKey]int64
	messages   map[string][]testPostgresQueueMessage
	deliveries map[testPostgresQueueDeliveryKey]*testPostgresQueueDelivery
}

type testPostgresQueueMessage struct {
	topic     string
	seq       int64
	payload   []byte
	createdAt time.Time
}

type testPostgresQueueDeliveryKey struct {
	group string
	topic string
	seq   int64
}

type testPostgresQueueOffsetKey struct {
	group string
	topic string
}

type testPostgresQueueDelivery struct {
	acked        bool
	leaseOwner   string
	leaseExpires time.Time
	attempts     int
}

func newTestPostgresQueueBackend(now func() time.Time) *testPostgresQueueBackend {
	return &testPostgresQueueBackend{
		now:        now,
		nextSeq:    make(map[string]int64),
		offsets:    make(map[testPostgresQueueOffsetKey]int64),
		messages:   make(map[string][]testPostgresQueueMessage),
		deliveries: make(map[testPostgresQueueDeliveryKey]*testPostgresQueueDelivery),
	}
}

func (b *testPostgresQueueBackend) ensureSchema(context.Context) error {
	return nil
}

func (b *testPostgresQueueBackend) enqueue(_ context.Context, topic string, payload []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextSeq[topic]++
	b.messages[topic] = append(b.messages[topic], testPostgresQueueMessage{
		topic:     topic,
		seq:       b.nextSeq[topic],
		payload:   append([]byte(nil), payload...),
		createdAt: b.now().UTC(),
	})
	return nil
}

func (b *testPostgresQueueBackend) claim(_ context.Context, cfg postgresQueueClaimConfig) ([]postgresQueueRecord, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now().UTC()
	for _, topic := range cfg.topics {
		b.ensureOffsetLocked(cfg, topic)
		nextSeq := b.offsets[testPostgresQueueOffsetKey{group: cfg.group, topic: topic}]
		for _, msg := range b.messages[topic] {
			if msg.seq < nextSeq {
				continue
			}
			key := testPostgresQueueDeliveryKey{group: cfg.group, topic: topic, seq: msg.seq}
			if _, ok := b.deliveries[key]; !ok {
				b.deliveries[key] = &testPostgresQueueDelivery{}
			}
		}
	}

	var out []postgresQueueRecord
	for _, topic := range cfg.topics {
		for _, msg := range b.messages[topic] {
			if len(out) >= cfg.limit {
				return out, nil
			}
			key := testPostgresQueueDeliveryKey{group: cfg.group, topic: topic, seq: msg.seq}
			delivery := b.deliveries[key]
			if delivery == nil || delivery.acked {
				continue
			}
			if b.hasEarlierUnackedLocked(cfg.group, topic, msg.seq, now) {
				continue
			}
			if !delivery.leaseExpires.IsZero() && delivery.leaseExpires.After(now) {
				continue
			}
			delivery.attempts++
			delivery.leaseOwner = cfg.owner
			delivery.leaseExpires = now.Add(cfg.leaseDuration)
			out = append(out, postgresQueueRecord{
				topic:     msg.topic,
				seq:       msg.seq,
				attempt:   delivery.attempts,
				owner:     delivery.leaseOwner,
				payload:   append([]byte(nil), msg.payload...),
				createdAt: msg.createdAt,
				claimedAt: now,
			})
		}
	}
	return out, nil
}

func (b *testPostgresQueueBackend) ensureOffsetLocked(cfg postgresQueueClaimConfig, topic string) {
	key := testPostgresQueueOffsetKey{group: cfg.group, topic: topic}
	if _, ok := b.offsets[key]; ok {
		return
	}
	if cfg.initialSequences != nil && cfg.initialSequences[topic] > 0 {
		b.offsets[key] = cfg.initialSequences[topic]
		return
	}
	if cfg.initialPosition == PostgresInitialPositionLatest {
		b.offsets[key] = b.nextSeq[topic] + 1
		return
	}
	b.offsets[key] = 1
}

func (b *testPostgresQueueBackend) hasEarlierUnackedLocked(group, topic string, seq int64, now time.Time) bool {
	for key, delivery := range b.deliveries {
		if key.group != group || key.topic != topic || key.seq >= seq || delivery.acked {
			continue
		}
		if delivery.leaseExpires.IsZero() || delivery.leaseExpires.After(now) {
			return true
		}
	}
	return false
}

func (b *testPostgresQueueBackend) ack(_ context.Context, group, topic string, seq int64, owner string, attempt int) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := testPostgresQueueDeliveryKey{group: group, topic: topic, seq: seq}
	delivery := b.deliveries[key]
	if delivery == nil {
		return errors.New("delivery not found")
	}
	if delivery.acked || delivery.leaseOwner != owner || delivery.attempts != attempt || !delivery.leaseExpires.After(b.now().UTC()) {
		return errors.New("stale ack token")
	}
	delivery.acked = true
	delivery.leaseOwner = ""
	delivery.leaseExpires = time.Time{}
	b.advanceOffsetLocked(group, topic)
	return nil
}

func (b *testPostgresQueueBackend) advanceOffsetLocked(group, topic string) {
	offsetKey := testPostgresQueueOffsetKey{group: group, topic: topic}
	next := b.offsets[offsetKey]
	if next <= 0 {
		next = 1
	}
	for {
		delivery := b.deliveries[testPostgresQueueDeliveryKey{group: group, topic: topic, seq: next}]
		if delivery == nil || !delivery.acked {
			break
		}
		next++
	}
	b.offsets[offsetKey] = next
}

func (b *testPostgresQueueBackend) renew(_ context.Context, group, topic string, seq int64, owner string, attempt int, leaseDuration time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := testPostgresQueueDeliveryKey{group: group, topic: topic, seq: seq}
	delivery := b.deliveries[key]
	if delivery == nil {
		return errors.New("delivery not found")
	}
	if delivery.acked || delivery.leaseOwner != owner || delivery.attempts != attempt || !delivery.leaseExpires.After(b.now().UTC()) {
		return errPostgresQueueStaleLease
	}
	delivery.leaseExpires = b.now().UTC().Add(leaseDuration)
	return nil
}

func (b *testPostgresQueueBackend) close() error {
	return nil
}
