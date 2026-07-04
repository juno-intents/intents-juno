package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/leases"
	"github.com/juno-intents/intents-juno/internal/queue"
)

type recordingCheckpointSignerProducer struct {
	name  string
	calls *[]string
}

func (p *recordingCheckpointSignerProducer) Publish(_ context.Context, topic string, payload []byte) error {
	if p.calls != nil {
		*p.calls = append(*p.calls, p.name+":"+topic+":"+string(payload))
	}
	return nil
}

func (p *recordingCheckpointSignerProducer) Close() error {
	return nil
}

func TestLoadDigestSigner_AWSKMSRequiresOperatorAddress(t *testing.T) {
	_, _, err := loadDigestSigner(context.Background(), "aws-kms", "arn:aws:kms:us-east-1:123:key/test")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "OPERATOR_ADDRESS") {
		t.Fatalf("expected OPERATOR_ADDRESS error, got %v", err)
	}
}

func TestLoadDigestSigner_RejectsUnknownDriver(t *testing.T) {
	_, _, err := loadDigestSigner(context.Background(), "bad-driver", "")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported signer driver") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type stubLeaseStore struct {
	renewLease leases.Lease
	renewOK    bool
	renewErr   error

	acquireLease leases.Lease
	acquireOK    bool
	acquireErr   error

	renewCalls   int
	acquireCalls int
}

func (s *stubLeaseStore) TryAcquire(_ context.Context, _ string, _ string, _ time.Duration) (leases.Lease, bool, error) {
	s.acquireCalls++
	return s.acquireLease, s.acquireOK, s.acquireErr
}

func (s *stubLeaseStore) Renew(_ context.Context, _ string, _ string, _ time.Duration) (leases.Lease, bool, error) {
	s.renewCalls++
	return s.renewLease, s.renewOK, s.renewErr
}

func (s *stubLeaseStore) Release(_ context.Context, _ string, _ string) error {
	return nil
}

func (s *stubLeaseStore) Get(_ context.Context, _ string) (leases.Lease, error) {
	return leases.Lease{}, leases.ErrNotFound
}

func TestHoldLease_ReacquiresExpiredLease(t *testing.T) {
	t.Parallel()

	store := &stubLeaseStore{
		renewErr:  leases.ErrExpired,
		acquireOK: true,
		acquireLease: leases.Lease{
			Name:      "checkpoint-signer",
			Owner:     "node-a",
			Version:   2,
			ExpiresAt: time.Now().Add(15 * time.Second),
		},
	}

	ok, err := holdLease(context.Background(), store, "checkpoint-signer", "node-a", 15*time.Second)
	if err != nil {
		t.Fatalf("holdLease: %v", err)
	}
	if !ok {
		t.Fatalf("expected lease reacquire to succeed")
	}
	if store.renewCalls != 1 {
		t.Fatalf("renew calls: got %d want 1", store.renewCalls)
	}
	if store.acquireCalls != 1 {
		t.Fatalf("acquire calls: got %d want 1", store.acquireCalls)
	}
}

func TestHoldLease_PropagatesUnexpectedRenewError(t *testing.T) {
	t.Parallel()

	store := &stubLeaseStore{
		renewErr: errors.New("boom"),
	}

	ok, err := holdLease(context.Background(), store, "checkpoint-signer", "node-a", 15*time.Second)
	if err == nil {
		t.Fatalf("expected error")
	}
	if ok {
		t.Fatalf("expected no leadership on unexpected error")
	}
	if store.acquireCalls != 0 {
		t.Fatalf("acquire calls: got %d want 0", store.acquireCalls)
	}
}

type readinessChainSource struct {
	tip uint64
	err error
}

func (s *readinessChainSource) TipHeight(context.Context) (uint64, error) {
	if s.err != nil {
		return 0, s.err
	}
	return s.tip, nil
}

func (s *readinessChainSource) CheckpointAtHeight(context.Context, uint64) (checkpoint.ChainCheckpoint, error) {
	return checkpoint.ChainCheckpoint{}, nil
}

func TestJunoRPCReadinessCheck_ProbesTipHeight(t *testing.T) {
	t.Parallel()

	src := &readinessChainSource{tip: 123}
	if err := junoRPCReadinessCheck(src, time.Second)(context.Background()); err != nil {
		t.Fatalf("junoRPCReadinessCheck: %v", err)
	}

	src.err = errors.New("rpc down")
	if err := junoRPCReadinessCheck(src, time.Second)(context.Background()); err == nil {
		t.Fatalf("expected readiness error")
	}
}

func TestSignerReadinessCheck_RequiresDBAndRPC(t *testing.T) {
	t.Parallel()

	dbCalls := 0
	rpcCalls := 0
	check := signerReadinessCheck(
		func(context.Context) error {
			dbCalls++
			return nil
		},
		func(context.Context) error {
			rpcCalls++
			return nil
		},
	)
	if err := check(context.Background()); err != nil {
		t.Fatalf("signerReadinessCheck: %v", err)
	}
	if dbCalls != 1 || rpcCalls != 1 {
		t.Fatalf("expected both checks to run, got db=%d rpc=%d", dbCalls, rpcCalls)
	}

	rpcCalls = 0
	check = signerReadinessCheck(
		func(context.Context) error { return errors.New("db down") },
		func(context.Context) error {
			rpcCalls++
			return nil
		},
	)
	if err := check(context.Background()); err == nil {
		t.Fatalf("expected db readiness error")
	}
	if rpcCalls != 0 {
		t.Fatalf("expected rpc check to be skipped after db failure, got %d calls", rpcCalls)
	}
}

func TestCheckpointSignerQueueProducerConfig_PostgresFallsBackToStoreDSN(t *testing.T) {
	t.Parallel()

	cfg, err := checkpointSignerQueueProducerConfig(checkpointSignerQueueOptions{
		Driver:           queue.DriverPostgres,
		StorePostgresDSN: "postgres://state-db",
	})
	if err != nil {
		t.Fatalf("checkpointSignerQueueProducerConfig: %v", err)
	}
	if got, want := cfg.Driver, queue.DriverPostgres; got != want {
		t.Fatalf("Driver = %q, want %q", got, want)
	}
	if got, want := cfg.PostgresDSN, "postgres://state-db"; got != want {
		t.Fatalf("PostgresDSN = %q, want %q", got, want)
	}
}

func TestCheckpointSignerQueueProducerConfig_PostgresDSNEnvOverridesStoreDSN(t *testing.T) {
	t.Setenv("CHECKPOINT_SIGNER_QUEUE_DSN", "postgres://queue-db")

	cfg, err := checkpointSignerQueueProducerConfig(checkpointSignerQueueOptions{
		Driver:           queue.DriverPostgres,
		PostgresDSNEnv:   "CHECKPOINT_SIGNER_QUEUE_DSN",
		StorePostgresDSN: "postgres://state-db",
	})
	if err != nil {
		t.Fatalf("checkpointSignerQueueProducerConfig: %v", err)
	}
	if got, want := cfg.Driver, queue.DriverPostgres; got != want {
		t.Fatalf("Driver = %q, want %q", got, want)
	}
	if got, want := cfg.PostgresDSN, "postgres://queue-db"; got != want {
		t.Fatalf("PostgresDSN = %q, want %q", got, want)
	}
}

func TestCheckpointSignerQueueProducer_MirrorsToShadowPostgres(t *testing.T) {
	t.Parallel()

	var calls []string
	var configs []queue.ProducerConfig
	factory := func(_ context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		configs = append(configs, cfg)
		name := cfg.Driver
		if len(configs) > 1 {
			name = "shadow-" + cfg.Driver
		}
		return &recordingCheckpointSignerProducer{name: name, calls: &calls}, nil
	}

	producer, err := checkpointSignerQueueProducer(context.Background(), checkpointSignerQueueProducerOptions{
		Driver:            queue.DriverKafka,
		Brokers:           []string{"broker-1:9098"},
		StorePostgresDSN:  "postgres://state-db",
		ShadowDriver:      queue.DriverPostgres,
		ShadowPostgresDSN: "postgres://shadow-db",
		ShadowRequired:    true,
		ShadowTimeout:     time.Second,
	}, factory)
	if err != nil {
		t.Fatalf("checkpointSignerQueueProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	if err := producer.Publish(context.Background(), "checkpoints.signatures.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("producer configs = %d, want 2", len(configs))
	}
	if got, want := configs[0].Driver, queue.DriverKafka; got != want {
		t.Fatalf("primary driver = %q, want %q", got, want)
	}
	if got, want := configs[1].Driver, queue.DriverPostgres; got != want {
		t.Fatalf("shadow driver = %q, want %q", got, want)
	}
	if got, want := configs[1].PostgresDSN, "postgres://shadow-db"; got != want {
		t.Fatalf("shadow PostgresDSN = %q, want %q", got, want)
	}
	if got, want := strings.Join(calls, ","), "kafka:checkpoints.signatures.v1:payload,shadow-postgres:checkpoints.signatures.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
}

func TestCheckpointSignerQueueProducer_RejectsDuplicateShadowDriver(t *testing.T) {
	t.Parallel()

	_, err := checkpointSignerQueueProducer(context.Background(), checkpointSignerQueueProducerOptions{
		Driver:           queue.DriverPostgres,
		StorePostgresDSN: "postgres://state-db",
		ShadowDriver:     queue.DriverPostgres,
		ShadowRequired:   true,
		ShadowTimeout:    time.Second,
	}, nil)
	if err == nil {
		t.Fatalf("expected duplicate shadow driver error")
	}
	if !strings.Contains(err.Error(), "shadow queue driver must differ") {
		t.Fatalf("error = %v, want duplicate shadow driver error", err)
	}
}

func TestCheckpointSignerQueueProducer_OptionalShadowInitUsesTimeout(t *testing.T) {
	t.Parallel()

	var configs []queue.ProducerConfig
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		configs = append(configs, cfg)
		if len(configs) == 1 {
			return &recordingCheckpointSignerProducer{name: "primary"}, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	producer, err := checkpointSignerQueueProducer(context.Background(), checkpointSignerQueueProducerOptions{
		Driver:            queue.DriverKafka,
		Brokers:           []string{"broker-1:9098"},
		StorePostgresDSN:  "postgres://state-db",
		ShadowDriver:      queue.DriverPostgres,
		ShadowPostgresDSN: "postgres://shadow-db",
		ShadowTimeout:     10 * time.Millisecond,
	}, factory)
	if err != nil {
		t.Fatalf("checkpointSignerQueueProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()
	if len(configs) != 2 {
		t.Fatalf("producer configs = %d, want 2", len(configs))
	}
}
