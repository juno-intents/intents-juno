package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/juno-intents/intents-juno/internal/queueauth"
)

type stubCheckpointProducer struct {
	topic    string
	payloads [][]byte
	err      error
}

func (p *stubCheckpointProducer) Publish(_ context.Context, topic string, payload []byte) error {
	p.topic = topic
	p.payloads = append(p.payloads, append([]byte(nil), payload...))
	return p.err
}

func (p *stubCheckpointProducer) Close() error {
	return nil
}

type recordingCheckpointAggregatorProducer struct {
	name  string
	calls *[]string
}

func (p *recordingCheckpointAggregatorProducer) Publish(_ context.Context, topic string, payload []byte) error {
	if p.calls != nil {
		*p.calls = append(*p.calls, p.name+":"+topic+":"+string(payload))
	}
	return nil
}

func (p *recordingCheckpointAggregatorProducer) Close() error {
	return nil
}

type noEmittedListPackageStore struct {
	*checkpoint.MemoryPackageStore
}

func (s *noEmittedListPackageStore) ListByState(ctx context.Context, state checkpoint.PackageState) ([]checkpoint.PackageRecord, error) {
	if state == checkpoint.PackageStateEmitted {
		return nil, errors.New("emitted checkpoint packages must not be restored via full ListByState")
	}
	return s.MemoryPackageStore.ListByState(ctx, state)
}

func TestPublishCheckpointPackage_MarksEmittedAfterPublish(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	now := time.Unix(1_700_000_000, 0).UTC()

	store := checkpoint.NewMemoryPackageStore()
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      1,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	if err := agg.RestorePendingPackage(checkpoint.CheckpointPackageV1{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("RestorePendingPackage: %v", err)
	}

	producer := &stubCheckpointProducer{}
	pkg := checkpoint.CheckpointPackageV1{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	}
	if err := publishCheckpointPackage(context.Background(), persist, agg, producer, nil, "checkpoints.packages.v1", pkg); err != nil {
		t.Fatalf("publishCheckpointPackage: %v", err)
	}

	rec, err := store.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if rec.State != checkpoint.PackageStateEmitted {
		t.Fatalf("state: got %s want %s", rec.State, checkpoint.PackageStateEmitted)
	}
	if len(producer.payloads) != 1 {
		t.Fatalf("publish calls: got %d want 1", len(producer.payloads))
	}
}

func TestPublishCheckpointPackage_SignsCriticalQueuePayload(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	now := time.Unix(1_700_000_000, 0).UTC()

	store := &noEmittedListPackageStore{MemoryPackageStore: checkpoint.NewMemoryPackageStore()}
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      1,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	if err := agg.RestorePendingPackage(checkpoint.CheckpointPackageV1{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("RestorePendingPackage: %v", err)
	}

	producer := &stubCheckpointProducer{}
	codec := queueauth.New(queueauth.Config{
		KeyID:  "ops-1",
		Secret: []byte("super-secret-key"),
		Now:    func() time.Time { return now },
		Rand:   strings.NewReader(strings.Repeat("a", 32)),
	})
	pkg := checkpoint.CheckpointPackageV1{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	}
	if err := publishCheckpointPackage(context.Background(), persist, agg, producer, codec, "checkpoints.packages.v1", pkg); err != nil {
		t.Fatalf("publishCheckpointPackage: %v", err)
	}
	if len(producer.payloads) != 1 {
		t.Fatalf("publish calls: got %d want 1", len(producer.payloads))
	}
	raw, err := codec.Unwrap("checkpoints.packages.v1", producer.payloads[0])
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got := string(raw); !strings.Contains(got, `"version":"checkpoints.package.v1"`) {
		t.Fatalf("unexpected raw payload %s", got)
	}
}

func TestCheckpointAggregatorQueueConfigs_PostgresFallsBackToStoreDSN(t *testing.T) {
	t.Parallel()

	opts := checkpointAggregatorQueueOptions{
		Driver:           queue.DriverPostgres,
		StorePostgresDSN: "postgres://state-db",
		Group:            "checkpoint-aggregator",
		Topics:           []string{"checkpoints.signatures.v1"},
		QueueMaxBytes:    123,
		MaxLineBytes:     456,
	}
	consumerCfg, err := checkpointAggregatorConsumerConfig(opts)
	if err != nil {
		t.Fatalf("checkpointAggregatorConsumerConfig: %v", err)
	}
	if got, want := consumerCfg.Driver, queue.DriverPostgres; got != want {
		t.Fatalf("consumer Driver = %q, want %q", got, want)
	}
	if got, want := consumerCfg.PostgresDSN, "postgres://state-db"; got != want {
		t.Fatalf("consumer PostgresDSN = %q, want %q", got, want)
	}
	if got, want := consumerCfg.Group, "checkpoint-aggregator"; got != want {
		t.Fatalf("consumer Group = %q, want %q", got, want)
	}
	if got, want := strings.Join(consumerCfg.Topics, ","), "checkpoints.signatures.v1"; got != want {
		t.Fatalf("consumer Topics = %q, want %q", got, want)
	}

	producerCfg, err := checkpointAggregatorProducerConfig(opts)
	if err != nil {
		t.Fatalf("checkpointAggregatorProducerConfig: %v", err)
	}
	if got, want := producerCfg.Driver, queue.DriverPostgres; got != want {
		t.Fatalf("producer Driver = %q, want %q", got, want)
	}
	if got, want := producerCfg.PostgresDSN, "postgres://state-db"; got != want {
		t.Fatalf("producer PostgresDSN = %q, want %q", got, want)
	}
}

func TestCheckpointAggregatorQueueConfigs_PostgresDSNEnvOverridesStoreDSN(t *testing.T) {
	t.Setenv("CHECKPOINT_AGGREGATOR_QUEUE_DSN", "postgres://queue-db")

	opts := checkpointAggregatorQueueOptions{
		Driver:           queue.DriverPostgres,
		PostgresDSNEnv:   "CHECKPOINT_AGGREGATOR_QUEUE_DSN",
		StorePostgresDSN: "postgres://state-db",
		Group:            "checkpoint-aggregator",
		Topics:           []string{"checkpoints.signatures.v1"},
	}
	consumerCfg, err := checkpointAggregatorConsumerConfig(opts)
	if err != nil {
		t.Fatalf("checkpointAggregatorConsumerConfig: %v", err)
	}
	if got, want := consumerCfg.PostgresDSN, "postgres://queue-db"; got != want {
		t.Fatalf("consumer PostgresDSN = %q, want %q", got, want)
	}
	producerCfg, err := checkpointAggregatorProducerConfig(opts)
	if err != nil {
		t.Fatalf("checkpointAggregatorProducerConfig: %v", err)
	}
	if got, want := producerCfg.PostgresDSN, "postgres://queue-db"; got != want {
		t.Fatalf("producer PostgresDSN = %q, want %q", got, want)
	}
}

func TestCheckpointAggregatorQueueProducer_MirrorsToShadowPostgres(t *testing.T) {
	t.Parallel()

	var calls []string
	var configs []queue.ProducerConfig
	factory := func(_ context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		configs = append(configs, cfg)
		name := cfg.Driver
		if len(configs) > 1 {
			name = "shadow-" + cfg.Driver
		}
		return &recordingCheckpointAggregatorProducer{name: name, calls: &calls}, nil
	}

	producer, err := checkpointAggregatorQueueProducer(context.Background(), checkpointAggregatorQueueOptions{
		Driver:            queue.DriverKafka,
		Brokers:           []string{"broker-1:9098"},
		StorePostgresDSN:  "postgres://state-db",
		ShadowDriver:      queue.DriverPostgres,
		ShadowPostgresDSN: "postgres://shadow-db",
		ShadowRequired:    true,
		ShadowTimeout:     time.Second,
	}, factory)
	if err != nil {
		t.Fatalf("checkpointAggregatorQueueProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()

	if err := producer.Publish(context.Background(), "checkpoints.packages.v1", []byte("payload")); err != nil {
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
	if got, want := strings.Join(calls, ","), "kafka:checkpoints.packages.v1:payload,shadow-postgres:checkpoints.packages.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
}

func TestCheckpointAggregatorQueueProducer_RejectsDuplicateShadowDriver(t *testing.T) {
	t.Parallel()

	_, err := checkpointAggregatorQueueProducer(context.Background(), checkpointAggregatorQueueOptions{
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

func TestCheckpointAggregatorQueueProducer_OptionalShadowInitUsesTimeout(t *testing.T) {
	t.Parallel()

	var configs []queue.ProducerConfig
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		configs = append(configs, cfg)
		if len(configs) == 1 {
			return &recordingCheckpointAggregatorProducer{name: "primary"}, nil
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}

	producer, err := checkpointAggregatorQueueProducer(context.Background(), checkpointAggregatorQueueOptions{
		Driver:            queue.DriverKafka,
		Brokers:           []string{"broker-1:9098"},
		StorePostgresDSN:  "postgres://state-db",
		ShadowDriver:      queue.DriverPostgres,
		ShadowPostgresDSN: "postgres://shadow-db",
		ShadowTimeout:     10 * time.Millisecond,
	}, factory)
	if err != nil {
		t.Fatalf("checkpointAggregatorQueueProducer: %v", err)
	}
	defer func() { _ = producer.Close() }()
	if len(configs) != 2 {
		t.Fatalf("producer configs = %d, want 2", len(configs))
	}
}

func TestReplayOpenCheckpointPackages_ReemitsPersistedPackages(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	now := time.Unix(1_700_000_000, 0).UTC()

	store := checkpoint.NewMemoryPackageStore()
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	payload, err := json.Marshal(checkpointPackageV1{
		Version:         "checkpoints.package.v1",
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if _, err := persist.Persist(context.Background(), checkpoint.PackageEnvelope{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Payload:         payload,
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      1,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	producer := &stubCheckpointProducer{}

	if err := replayOpenCheckpointPackages(context.Background(), persist, agg, producer, nil, "checkpoints.packages.v1", slog.Default()); err != nil {
		t.Fatalf("replayOpenCheckpointPackages: %v", err)
	}

	rec, err := store.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if rec.State != checkpoint.PackageStateEmitted {
		t.Fatalf("state: got %s want %s", rec.State, checkpoint.PackageStateEmitted)
	}
	if len(producer.payloads) != 1 {
		t.Fatalf("publish calls: got %d want 1", len(producer.payloads))
	}
}

func TestPublishCheckpointPackage_LeavesPackageOpenOnPublishFailure(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	now := time.Unix(1_700_000_000, 0).UTC()

	store := checkpoint.NewMemoryPackageStore()
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      1,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}

	pkg := checkpoint.CheckpointPackageV1{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	}
	producer := &stubCheckpointProducer{err: errors.New("publish failed")}

	if err := publishCheckpointPackage(context.Background(), persist, agg, producer, nil, "checkpoints.packages.v1", pkg); err == nil {
		t.Fatalf("expected publish error")
	}

	rec, err := store.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if rec.State != checkpoint.PackageStateOpen {
		t.Fatalf("state: got %s want %s", rec.State, checkpoint.PackageStateOpen)
	}
}

func TestRestoreCheckpointState_SkipsReplayForAlreadyEmittedPackages(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	now := time.Unix(1_700_000_000, 0).UTC()

	store := checkpoint.NewMemoryPackageStore()
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	payload, err := json.Marshal(checkpointPackageV1{
		Version:         "checkpoints.package.v1",
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if _, err := persist.Persist(context.Background(), checkpoint.PackageEnvelope{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Payload:         payload,
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if _, err := persist.MarkEmitted(context.Background(), digest); err != nil {
		t.Fatalf("MarkEmitted: %v", err)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      1,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	producer := &stubCheckpointProducer{}

	if err := restoreCheckpointState(context.Background(), persist, agg, producer, nil, "checkpoints.packages.v1", slog.Default()); err != nil {
		t.Fatalf("restoreCheckpointState: %v", err)
	}
	if len(producer.payloads) != 0 {
		t.Fatalf("expected no replay for emitted package, got %d publishes", len(producer.payloads))
	}
}

func TestPinBacklogMetricsCountsDueAndRetryPackages(t *testing.T) {
	t.Parallel()

	store := checkpoint.NewMemoryPackageStore()
	now := time.Unix(1_700_000_000, 0).UTC()
	bridge := common.HexToAddress("0x000000000000000000000000000000000000bEEF")

	for _, rec := range []checkpoint.PackageRecord{
		{
			Digest: common.HexToHash("0x0101010101010101010101010101010101010101010101010101010101010101"),
			Checkpoint: checkpoint.Checkpoint{
				Height:           100,
				BlockHash:        common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
				FinalOrchardRoot: common.HexToHash("0x1212121212121212121212121212121212121212121212121212121212121212"),
				BaseChainID:      8453,
				BridgeContract:   bridge,
			},
			OperatorSetHash:  common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			Payload:          []byte(`{"digest":"pending-due"}`),
			PinState:         checkpoint.PackagePinStatePending,
			PinNextAttemptAt: now.Add(-time.Second),
			State:            checkpoint.PackageStateOpen,
			PersistedAt:      now.Add(-2 * time.Second),
		},
		{
			Digest: common.HexToHash("0x0202020202020202020202020202020202020202020202020202020202020202"),
			Checkpoint: checkpoint.Checkpoint{
				Height:           101,
				BlockHash:        common.HexToHash("0x2121212121212121212121212121212121212121212121212121212121212121"),
				FinalOrchardRoot: common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
				BaseChainID:      8453,
				BridgeContract:   bridge,
			},
			OperatorSetHash:  common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			Payload:          []byte(`{"digest":"failed-due"}`),
			PinState:         checkpoint.PackagePinStateFailed,
			PinAttempts:      1,
			PinNextAttemptAt: now.Add(-time.Second),
			State:            checkpoint.PackageStateOpen,
			PersistedAt:      now.Add(-time.Second),
		},
		{
			Digest: common.HexToHash("0x0303030303030303030303030303030303030303030303030303030303030303"),
			Checkpoint: checkpoint.Checkpoint{
				Height:           102,
				BlockHash:        common.HexToHash("0x3131313131313131313131313131313131313131313131313131313131313131"),
				FinalOrchardRoot: common.HexToHash("0x3232323232323232323232323232323232323232323232323232323232323232"),
				BaseChainID:      8453,
				BridgeContract:   bridge,
			},
			OperatorSetHash:  common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			Payload:          []byte(`{"digest":"failed-later"}`),
			PinState:         checkpoint.PackagePinStateFailed,
			PinAttempts:      2,
			PinNextAttemptAt: now.Add(time.Minute),
			State:            checkpoint.PackageStateOpen,
			PersistedAt:      now,
		},
	} {
		if err := store.UpsertPackage(context.Background(), rec); err != nil {
			t.Fatalf("UpsertPackage(%s): %v", rec.Digest, err)
		}
	}

	backlog, retryBacklog, err := pinBacklogMetrics(context.Background(), store, now)
	if err != nil {
		t.Fatalf("pinBacklogMetrics: %v", err)
	}
	if backlog != 2 {
		t.Fatalf("backlog = %d, want 2", backlog)
	}
	if retryBacklog != 1 {
		t.Fatalf("retry backlog = %d, want 1", retryBacklog)
	}
}

func TestPublishCheckpointPackage_SkipsDurablyEmittedDigestAfterCacheEviction(t *testing.T) {
	t.Parallel()

	makePackage := func(height uint64, suffix string, createdAt time.Time) (checkpoint.Checkpoint, checkpoint.CheckpointPackageV1, []byte) {
		cp := checkpoint.Checkpoint{
			Height:           height,
			BlockHash:        common.HexToHash("0x" + strings.Repeat(suffix, 64)),
			FinalOrchardRoot: common.HexToHash("0x" + strings.Repeat(string(suffix[0]+1), 64)),
			BaseChainID:      8453,
			BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
		}
		digest := checkpoint.Digest(cp)
		operatorSetHash := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		payload, err := json.Marshal(checkpointPackageV1{
			Version:         "checkpoints.package.v1",
			Digest:          digest,
			Checkpoint:      cp,
			OperatorSetHash: operatorSetHash,
			CreatedAt:       createdAt,
		})
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		return cp, checkpoint.CheckpointPackageV1{
			Digest:          digest,
			Checkpoint:      cp,
			OperatorSetHash: operatorSetHash,
			CreatedAt:       createdAt,
		}, payload
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	store := checkpoint.NewMemoryPackageStore()
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	cpOld, pkgOld, payloadOld := makePackage(123, "1", now)
	if _, err := persist.Persist(context.Background(), checkpoint.PackageEnvelope{
		Digest:          pkgOld.Digest,
		Checkpoint:      cpOld,
		OperatorSetHash: pkgOld.OperatorSetHash,
		Payload:         payloadOld,
	}); err != nil {
		t.Fatalf("Persist old: %v", err)
	}
	if _, err := persist.MarkEmitted(context.Background(), pkgOld.Digest); err != nil {
		t.Fatalf("MarkEmitted old: %v", err)
	}

	now = now.Add(time.Minute)
	cpNew, pkgNew, payloadNew := makePackage(124, "2", now)
	if _, err := persist.Persist(context.Background(), checkpoint.PackageEnvelope{
		Digest:          pkgNew.Digest,
		Checkpoint:      cpNew,
		OperatorSetHash: pkgNew.OperatorSetHash,
		Payload:         payloadNew,
	}); err != nil {
		t.Fatalf("Persist new: %v", err)
	}
	if _, err := persist.MarkEmitted(context.Background(), pkgNew.Digest); err != nil {
		t.Fatalf("MarkEmitted new: %v", err)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cpOld.BaseChainID,
		BridgeContract: cpOld.BridgeContract,
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      1,
		MaxEmitted:     1,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	producer := &stubCheckpointProducer{}

	if err := restoreCheckpointState(context.Background(), persist, agg, producer, nil, "checkpoints.packages.v1", slog.Default()); err != nil {
		t.Fatalf("restoreCheckpointState: %v", err)
	}
	if len(producer.payloads) != 0 {
		t.Fatalf("expected no replay during restore, got %d publishes", len(producer.payloads))
	}

	if err := publishCheckpointPackage(context.Background(), persist, agg, producer, nil, "checkpoints.packages.v1", pkgOld); err != nil {
		t.Fatalf("publishCheckpointPackage old emitted: %v", err)
	}
	if len(producer.payloads) != 0 {
		t.Fatalf("expected durably emitted package to be skipped, got %d publishes", len(producer.payloads))
	}

	stored, err := store.Get(context.Background(), pkgOld.Digest)
	if err != nil {
		t.Fatalf("store.Get old: %v", err)
	}
	if stored.State != checkpoint.PackageStateEmitted {
		t.Fatalf("stored state: got %s want %s", stored.State, checkpoint.PackageStateEmitted)
	}
}

type blobReadinessStore struct {
	existsCalls int
	err         error
}

func (s *blobReadinessStore) Put(context.Context, string, []byte, blobstore.PutOptions) error {
	return nil
}
func (s *blobReadinessStore) Get(context.Context, string) (blobstore.Object, error) {
	return blobstore.Object{}, nil
}
func (s *blobReadinessStore) Delete(context.Context, string) error { return nil }
func (s *blobReadinessStore) Exists(context.Context, string) (bool, error) {
	s.existsCalls++
	return false, s.err
}

func TestBlobStoreReadinessCheck_UsesExists(t *testing.T) {
	t.Parallel()

	store := &blobReadinessStore{}
	if err := blobStoreReadinessCheck(store, time.Second)(context.Background()); err != nil {
		t.Fatalf("blobStoreReadinessCheck: %v", err)
	}
	if store.existsCalls != 1 {
		t.Fatalf("exists calls: got %d want 1", store.existsCalls)
	}

	store.err = errors.New("blob unavailable")
	if err := blobStoreReadinessCheck(store, time.Second)(context.Background()); err == nil {
		t.Fatalf("expected readiness error")
	}
}

func TestAggregatorReadinessCheck_RequiresDBAndBlob(t *testing.T) {
	t.Parallel()

	dbCalls := 0
	blobCalls := 0
	check := aggregatorReadinessCheck(
		func(context.Context) error {
			dbCalls++
			return nil
		},
		func(context.Context) error {
			blobCalls++
			return nil
		},
	)
	if err := check(context.Background()); err != nil {
		t.Fatalf("aggregatorReadinessCheck: %v", err)
	}
	if dbCalls != 1 || blobCalls != 1 {
		t.Fatalf("expected both checks to run, got db=%d blob=%d", dbCalls, blobCalls)
	}

	blobCalls = 0
	check = aggregatorReadinessCheck(
		func(context.Context) error { return errors.New("db down") },
		func(context.Context) error {
			blobCalls++
			return nil
		},
	)
	if err := check(context.Background()); err == nil {
		t.Fatalf("expected db readiness error")
	}
	if blobCalls != 0 {
		t.Fatalf("expected blob check to be skipped after db failure, got %d calls", blobCalls)
	}
}
