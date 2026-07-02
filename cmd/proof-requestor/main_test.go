package main

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/juno-intents/intents-juno/internal/queue"
)

type stubReadyDependency struct {
	calls int
	err   error
}

func (s *stubReadyDependency) Ready(context.Context) error {
	s.calls++
	return s.err
}

type fakeDialConn struct {
	closed bool
}

func (c *fakeDialConn) Close() error {
	c.closed = true
	return nil
}

func TestReadyCheckFromDependency_UsesReady(t *testing.T) {
	t.Parallel()

	dep := &stubReadyDependency{}
	check := readyCheckFromDependency(dep)
	if check == nil {
		t.Fatalf("expected readiness check")
	}
	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if dep.calls != 1 {
		t.Fatalf("calls: got %d want 1", dep.calls)
	}
}

func TestProofRequestorReadinessCheck_ShortCircuitsOnDBFailure(t *testing.T) {
	t.Parallel()

	queueCalled := false
	proverCalled := false
	check := proofRequestorReadinessCheck(
		func(context.Context) error { return errors.New("db down") },
		func(context.Context) error {
			queueCalled = true
			return nil
		},
		func(context.Context) error {
			proverCalled = true
			return nil
		},
	)
	if check == nil {
		t.Fatalf("expected readiness check")
	}

	err := check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("unexpected err: %v", err)
	}
	if queueCalled || proverCalled {
		t.Fatalf("later checks should not run when db fails first")
	}
}

func TestProofRequestorReadinessCheck_RunsAllChecks(t *testing.T) {
	t.Parallel()

	order := make([]string, 0, 3)
	check := proofRequestorReadinessCheck(
		func(context.Context) error {
			order = append(order, "db")
			return nil
		},
		func(context.Context) error {
			order = append(order, "queue")
			return nil
		},
		func(context.Context) error {
			order = append(order, "prover")
			return nil
		},
	)

	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if got, want := strings.Join(order, ","), "db,queue,prover"; got != want {
		t.Fatalf("order: got %q want %q", got, want)
	}
}

func TestKafkaBrokerReadinessCheckWithDialer_SucceedsWhenAnyBrokerIsReachable(t *testing.T) {
	t.Parallel()

	var closedGood bool
	check := kafkaBrokerReadinessCheckWithDialer(
		[]string{"bad:9092", "good:9092"},
		func(_ context.Context, network, address string) (io.Closer, error) {
			if network != "tcp" {
				t.Fatalf("network: got %q want tcp", network)
			}
			if address == "bad:9092" {
				return nil, errors.New("dial failed")
			}
			conn := &fakeDialConn{}
			return closerFunc(func() error {
				closedGood = true
				return conn.Close()
			}), nil
		},
	)

	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if !closedGood {
		t.Fatalf("expected successful broker connection to close")
	}
}

func TestKafkaBrokerReadinessCheckWithDialer_FailsWhenAllBrokersFail(t *testing.T) {
	t.Parallel()

	check := kafkaBrokerReadinessCheckWithDialer(
		[]string{"bad-a:9092", "bad-b:9092"},
		func(context.Context, string, string) (io.Closer, error) {
			return nil, errors.New("dial failed")
		},
	)

	err := check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "dial failed") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestKafkaBrokerReadinessCheckWithDialer_EmptyBrokersIsNoop(t *testing.T) {
	t.Parallel()

	if check := kafkaBrokerReadinessCheckWithDialer(nil, nil); check != nil {
		t.Fatalf("expected nil check")
	}
}

func TestProofRequestorQueueConfigs_DefaultKafka(t *testing.T) {
	t.Parallel()

	opts := proofRequestorQueueOptions{
		Driver:        "",
		Brokers:       "broker-a:9092, broker-b:9092",
		Group:         "proof-requestor",
		InputTopic:    "proof.requests.v1",
		QueueMaxBytes: 1234,
		MaxLineBytes:  5678,
	}

	consumerCfg, err := proofRequestorConsumerConfig(opts)
	if err != nil {
		t.Fatalf("proofRequestorConsumerConfig: %v", err)
	}
	if consumerCfg.Driver != queue.DriverKafka {
		t.Fatalf("consumer driver = %q, want %q", consumerCfg.Driver, queue.DriverKafka)
	}
	if !reflect.DeepEqual(consumerCfg.Brokers, []string{"broker-a:9092", "broker-b:9092"}) {
		t.Fatalf("consumer brokers = %#v", consumerCfg.Brokers)
	}
	if consumerCfg.PostgresDSN != "" {
		t.Fatalf("consumer PostgresDSN = %q, want empty", consumerCfg.PostgresDSN)
	}
	if consumerCfg.Group != "proof-requestor" || !reflect.DeepEqual(consumerCfg.Topics, []string{"proof.requests.v1"}) {
		t.Fatalf("consumer group/topics = %q/%#v", consumerCfg.Group, consumerCfg.Topics)
	}
	if consumerCfg.KafkaMaxBytes != 1234 || consumerCfg.MaxLineBytes != 5678 {
		t.Fatalf("consumer byte limits = %d/%d", consumerCfg.KafkaMaxBytes, consumerCfg.MaxLineBytes)
	}

	producerCfg, err := proofRequestorProducerConfig(opts)
	if err != nil {
		t.Fatalf("proofRequestorProducerConfig: %v", err)
	}
	if producerCfg.Driver != queue.DriverKafka {
		t.Fatalf("producer driver = %q, want %q", producerCfg.Driver, queue.DriverKafka)
	}
	if !reflect.DeepEqual(producerCfg.Brokers, []string{"broker-a:9092", "broker-b:9092"}) {
		t.Fatalf("producer brokers = %#v", producerCfg.Brokers)
	}
	if producerCfg.PostgresDSN != "" {
		t.Fatalf("producer PostgresDSN = %q, want empty", producerCfg.PostgresDSN)
	}
}

func TestProofRequestorQueueConfigs_PostgresDSNEnv(t *testing.T) {
	t.Setenv("PROOF_REQUESTOR_QUEUE_POSTGRES_DSN", " postgres://queue-user:queue-pass@127.0.0.1:5432/queue_db?sslmode=disable ")

	opts := proofRequestorQueueOptions{
		Driver:         " postgres ",
		PostgresDSNEnv: "PROOF_REQUESTOR_QUEUE_POSTGRES_DSN",
		Group:          "proof-requestor",
		InputTopic:     "proof.requests.v1",
		QueueMaxBytes:  1234,
		MaxLineBytes:   5678,
	}

	consumerCfg, err := proofRequestorConsumerConfig(opts)
	if err != nil {
		t.Fatalf("proofRequestorConsumerConfig: %v", err)
	}
	if consumerCfg.Driver != queue.DriverPostgres {
		t.Fatalf("consumer driver = %q, want %q", consumerCfg.Driver, queue.DriverPostgres)
	}
	if consumerCfg.PostgresDSN != "postgres://queue-user:queue-pass@127.0.0.1:5432/queue_db?sslmode=disable" {
		t.Fatalf("consumer PostgresDSN = %q", consumerCfg.PostgresDSN)
	}
	if len(consumerCfg.Brokers) != 0 {
		t.Fatalf("consumer brokers = %#v, want none", consumerCfg.Brokers)
	}

	producerCfg, err := proofRequestorProducerConfig(opts)
	if err != nil {
		t.Fatalf("proofRequestorProducerConfig: %v", err)
	}
	if producerCfg.Driver != queue.DriverPostgres {
		t.Fatalf("producer driver = %q, want %q", producerCfg.Driver, queue.DriverPostgres)
	}
	if producerCfg.PostgresDSN != "postgres://queue-user:queue-pass@127.0.0.1:5432/queue_db?sslmode=disable" {
		t.Fatalf("producer PostgresDSN = %q", producerCfg.PostgresDSN)
	}
	if len(producerCfg.Brokers) != 0 {
		t.Fatalf("producer brokers = %#v, want none", producerCfg.Brokers)
	}
}

func TestProofRequestorQueueConfigs_PostgresFallsBackToStoreDSNEnv(t *testing.T) {
	t.Setenv("POSTGRES_DSN", " postgres://store-user:store-pass@127.0.0.1:5432/store_db?sslmode=disable ")

	opts := proofRequestorQueueOptions{
		Driver:              queue.DriverPostgres,
		StorePostgresDSNEnv: "POSTGRES_DSN",
		Group:               "proof-requestor",
		InputTopic:          "proof.requests.v1",
	}

	consumerCfg, err := proofRequestorConsumerConfig(opts)
	if err != nil {
		t.Fatalf("proofRequestorConsumerConfig: %v", err)
	}
	if consumerCfg.PostgresDSN != "postgres://store-user:store-pass@127.0.0.1:5432/store_db?sslmode=disable" {
		t.Fatalf("consumer PostgresDSN = %q", consumerCfg.PostgresDSN)
	}

	producerCfg, err := proofRequestorProducerConfig(opts)
	if err != nil {
		t.Fatalf("proofRequestorProducerConfig: %v", err)
	}
	if producerCfg.PostgresDSN != "postgres://store-user:store-pass@127.0.0.1:5432/store_db?sslmode=disable" {
		t.Fatalf("producer PostgresDSN = %q", producerCfg.PostgresDSN)
	}
}

type closerFunc func() error

func (fn closerFunc) Close() error { return fn() }
