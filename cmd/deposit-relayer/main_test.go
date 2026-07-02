package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/deposit"
	"github.com/juno-intents/intents-juno/internal/depositrelayer"
	"github.com/juno-intents/intents-juno/internal/queue"
)

type recordingDepositProofProducer struct {
	name       string
	calls      *[]string
	publishErr error
	closed     bool
}

func (p *recordingDepositProofProducer) Publish(_ context.Context, topic string, payload []byte) error {
	if p.calls != nil {
		*p.calls = append(*p.calls, p.name+":"+topic+":"+string(payload))
	}
	return p.publishErr
}

func (p *recordingDepositProofProducer) Close() error {
	p.closed = true
	return nil
}

type blockingDepositProofProducer struct{}

func (p *blockingDepositProofProducer) Publish(ctx context.Context, _ string, _ []byte) error {
	<-ctx.Done()
	return ctx.Err()
}

func (p *blockingDepositProofProducer) Close() error {
	return nil
}

func TestIsCheckpointPermanentError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "invalid checkpoint", err: depositrelayer.ErrInvalidCheckpoint, want: true},
		{name: "wrapped invalid checkpoint", err: errors.New("wrap: " + depositrelayer.ErrInvalidCheckpoint.Error()), want: false},
		{name: "transient", err: errors.New("temporary queue outage"), want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isCheckpointPermanentError(tc.err); got != tc.want {
				t.Fatalf("isCheckpointPermanentError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestParseDepositSourceEvent(t *testing.T) {
	t.Parallel()

	chainID := uint64(84532)
	logIndex := uint64(3)

	tests := []struct {
		name    string
		msg     depositEventV2
		want    *deposit.SourceEvent
		wantErr bool
	}{
		{
			name: "legacy payload without source event",
			msg:  depositEventV2{},
			want: nil,
		},
		{
			name: "complete source event",
			msg: depositEventV2{
				ChainID:  &chainID,
				TxHash:   common.HexToHash("0x01").Hex(),
				LogIndex: &logIndex,
			},
			want: &deposit.SourceEvent{
				ChainID:  chainID,
				TxHash:   [32]byte(common.HexToHash("0x01")),
				LogIndex: logIndex,
			},
		},
		{
			name: "partial source event rejected",
			msg: depositEventV2{
				ChainID: &chainID,
				TxHash:  common.HexToHash("0x01").Hex(),
			},
			wantErr: true,
		},
		{
			name: "invalid tx hash rejected",
			msg: depositEventV2{
				ChainID:  &chainID,
				TxHash:   "0x1234",
				LogIndex: &logIndex,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseDepositSourceEvent(tc.msg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDepositSourceEvent: %v", err)
			}
			switch {
			case got == nil && tc.want == nil:
			case got == nil || tc.want == nil:
				t.Fatalf("source event mismatch: got=%v want=%v", got, tc.want)
			case *got != *tc.want:
				t.Fatalf("source event mismatch: got=%+v want=%+v", *got, *tc.want)
			}
		})
	}
}

func TestDefaultClaimTTLDelegatesToRelayerSafeLease(t *testing.T) {
	t.Parallel()

	if got := defaultDepositRelayerClaimTTL(); got != 0 {
		t.Fatalf("defaultDepositRelayerClaimTTL() = %s, want 0 to delegate to depositrelayer.New", got)
	}
}

func TestDepositProofQueueProducerConfiguresPostgresShadow(t *testing.T) {
	var configs []queue.ProducerConfig
	var calls []string
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		configs = append(configs, cfg)
		name := cfg.Driver
		if len(configs) == 2 {
			name = "shadow-" + cfg.Driver
		}
		return &recordingDepositProofProducer{name: name, calls: &calls}, nil
	}

	producer, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:           queue.DriverKafka,
		Brokers:          []string{"b-1.example:9098", "b-2.example:9098"},
		StorePostgresDSN: "postgres://state-db",
		ShadowDriver:     queue.DriverPostgres,
		ShadowTimeout:    10 * time.Millisecond,
	}, factory)
	if err != nil {
		t.Fatalf("proofQueueProducer: %v", err)
	}
	if err := producer.Publish(context.Background(), "proof.requests.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("config count = %d, want 2", len(configs))
	}
	if got, want := configs[0].Driver, queue.DriverKafka; got != want {
		t.Fatalf("primary driver = %q, want %q", got, want)
	}
	if got, want := strings.Join(configs[0].Brokers, ","), "b-1.example:9098,b-2.example:9098"; got != want {
		t.Fatalf("primary brokers = %q, want %q", got, want)
	}
	if got, want := configs[1].Driver, queue.DriverPostgres; got != want {
		t.Fatalf("shadow driver = %q, want %q", got, want)
	}
	if got, want := configs[1].PostgresDSN, "postgres://state-db"; got != want {
		t.Fatalf("shadow PostgresDSN = %q, want %q", got, want)
	}
	if got, want := strings.Join(calls, ","), "kafka:proof.requests.v1:payload,shadow-postgres:proof.requests.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
}

func TestDepositProofQueueProducerToleratesOptionalShadowInitFailure(t *testing.T) {
	shadowErr := errors.New("shadow init down")
	var calls []string
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		if cfg.Driver == queue.DriverPostgres {
			return nil, shadowErr
		}
		return &recordingDepositProofProducer{name: cfg.Driver, calls: &calls}, nil
	}

	producer, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:           queue.DriverKafka,
		Brokers:          []string{"b-1.example:9098"},
		StorePostgresDSN: "postgres://state-db",
		ShadowDriver:     queue.DriverPostgres,
		ShadowTimeout:    10 * time.Millisecond,
		Log:              log,
	}, factory)
	if err != nil {
		t.Fatalf("proofQueueProducer: %v", err)
	}
	if err := producer.Publish(context.Background(), "proof.requests.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got, want := strings.Join(calls, ","), "kafka:proof.requests.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if got := logBuf.String(); !strings.Contains(got, "proof shadow queue failed open") || !strings.Contains(got, "stage=init") || !strings.Contains(got, "shadow init down") {
		t.Fatalf("log = %q, want observable optional shadow init failure", got)
	}
}

func TestDepositProofQueueProducerOptionalShadowUsesTimeout(t *testing.T) {
	var calls []string
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		if cfg.Driver == queue.DriverPostgres {
			return &blockingDepositProofProducer{}, nil
		}
		return &recordingDepositProofProducer{name: cfg.Driver, calls: &calls}, nil
	}

	producer, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:           queue.DriverKafka,
		Brokers:          []string{"b-1.example:9098"},
		StorePostgresDSN: "postgres://state-db",
		ShadowDriver:     queue.DriverPostgres,
		ShadowTimeout:    10 * time.Millisecond,
		Log:              log,
	}, factory)
	if err != nil {
		t.Fatalf("proofQueueProducer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if err := producer.Publish(ctx, "proof.requests.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("Publish took %s, want optional shadow timeout to bound publish latency", elapsed)
	}
	if got, want := strings.Join(calls, ","), "kafka:proof.requests.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if got := logBuf.String(); !strings.Contains(got, "proof shadow queue failed open") || !strings.Contains(got, "stage=publish") || !strings.Contains(got, "topic=proof.requests.v1") {
		t.Fatalf("log = %q, want observable optional shadow publish failure", got)
	}
}

func TestDepositProofQueueProducerRejectsUnsafeOptionalShadowTimeout(t *testing.T) {
	_, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:           queue.DriverKafka,
		Brokers:          []string{"b-1.example:9098"},
		StorePostgresDSN: "postgres://state-db",
		ShadowDriver:     queue.DriverPostgres,
		ShadowTimeout:    0,
	}, func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		return &recordingDepositProofProducer{name: cfg.Driver}, nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--proof-shadow-queue-timeout must be > 0") {
		t.Fatalf("error = %v, want shadow timeout validation error", err)
	}
}

func TestDepositProofQueueProducerLogsOptionalShadowConfigFailure(t *testing.T) {
	var calls []string
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	t.Setenv("JUNO_TEST_MISSING_PROOF_SHADOW_DSN", "")
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		return &recordingDepositProofProducer{name: cfg.Driver, calls: &calls}, nil
	}

	producer, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:               queue.DriverKafka,
		Brokers:              []string{"b-1.example:9098"},
		ShadowDriver:         queue.DriverPostgres,
		ShadowPostgresDSNEnv: "JUNO_TEST_MISSING_PROOF_SHADOW_DSN",
		ShadowTimeout:        10 * time.Millisecond,
		Log:                  log,
	}, factory)
	if err != nil {
		t.Fatalf("proofQueueProducer: %v", err)
	}
	if err := producer.Publish(context.Background(), "proof.requests.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got, want := strings.Join(calls, ","), "kafka:proof.requests.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if got := logBuf.String(); !strings.Contains(got, "proof shadow queue failed open") || !strings.Contains(got, "stage=configure") || !strings.Contains(got, "JUNO_TEST_MISSING_PROOF_SHADOW_DSN") {
		t.Fatalf("log = %q, want observable optional shadow config failure", got)
	}
}

func TestDepositProofQueueProducerOptionalShadowInitUsesTimeout(t *testing.T) {
	var calls []string
	releaseShadow := make(chan struct{})
	defer close(releaseShadow)
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		if cfg.Driver == queue.DriverPostgres {
			select {
			case <-releaseShadow:
				return &recordingDepositProofProducer{name: "shadow-" + cfg.Driver}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &recordingDepositProofProducer{name: cfg.Driver, calls: &calls}, nil
	}

	start := time.Now()
	producer, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:           queue.DriverKafka,
		Brokers:          []string{"b-1.example:9098"},
		StorePostgresDSN: "postgres://state-db",
		ShadowDriver:     queue.DriverPostgres,
		ShadowTimeout:    10 * time.Millisecond,
	}, factory)
	if err != nil {
		t.Fatalf("proofQueueProducer: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("proofQueueProducer took %s, want optional shadow init timeout to bound startup latency", elapsed)
	}
	if err := producer.Publish(context.Background(), "proof.requests.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got, want := strings.Join(calls, ","), "kafka:proof.requests.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
}

func TestDepositProofQueueProducerRequiredShadowRequiresDriver(t *testing.T) {
	_, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:         queue.DriverKafka,
		Brokers:        []string{"b-1.example:9098"},
		ShadowRequired: true,
	}, func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		return &recordingDepositProofProducer{name: cfg.Driver}, nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--proof-shadow-queue-required requires --proof-shadow-queue-driver") {
		t.Fatalf("error = %v, want required shadow driver error", err)
	}
}

func TestDepositProofQueueProducerLogsOptionalUnsupportedShadowDriver(t *testing.T) {
	var calls []string
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	producer, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:        queue.DriverKafka,
		Brokers:       []string{"b-1.example:9098"},
		ShadowDriver:  "typo",
		ShadowTimeout: 10 * time.Millisecond,
		Log:           log,
	}, func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		return &recordingDepositProofProducer{name: cfg.Driver, calls: &calls}, nil
	})
	if err != nil {
		t.Fatalf("proofQueueProducer: %v", err)
	}
	if err := producer.Publish(context.Background(), "proof.requests.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got, want := strings.Join(calls, ","), "kafka:proof.requests.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
	if got := logBuf.String(); !strings.Contains(got, "proof shadow queue failed open") || !strings.Contains(got, "stage=configure") || !strings.Contains(got, "unsupported proof shadow queue driver") {
		t.Fatalf("log = %q, want observable optional unsupported shadow driver", got)
	}
}

func TestDepositProofQueueProducerRequiredUnsupportedShadowDriverFailsClosed(t *testing.T) {
	var primary *recordingDepositProofProducer
	_, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:         queue.DriverKafka,
		Brokers:        []string{"b-1.example:9098"},
		ShadowDriver:   "typo",
		ShadowRequired: true,
		ShadowTimeout:  10 * time.Millisecond,
	}, func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		primary = &recordingDepositProofProducer{name: cfg.Driver}
		return primary, nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported proof shadow queue driver") {
		t.Fatalf("error = %v, want unsupported shadow queue driver", err)
	}
	if primary == nil || !primary.closed {
		t.Fatalf("primary closed = %v, want true after required unsupported shadow", primary != nil && primary.closed)
	}
}
