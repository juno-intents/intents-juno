package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/junorpc"
	"github.com/juno-intents/intents-juno/internal/proverinput"
	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/juno-intents/intents-juno/internal/withdraw"
	"github.com/juno-intents/intents-juno/internal/withdrawfinalizer"
	"github.com/juno-intents/intents-juno/internal/witnessextract"
	"github.com/juno-intents/intents-juno/internal/witnessitem"
)

type recordingWithdrawProofProducer struct {
	name       string
	calls      *[]string
	publishErr error
	closed     bool
}

func (p *recordingWithdrawProofProducer) Publish(_ context.Context, topic string, payload []byte) error {
	if p.calls != nil {
		*p.calls = append(*p.calls, p.name+":"+topic+":"+string(payload))
	}
	return p.publishErr
}

func (p *recordingWithdrawProofProducer) Close() error {
	p.closed = true
	return nil
}

type blockingWithdrawProofProducer struct{}

func (p *blockingWithdrawProofProducer) Publish(ctx context.Context, _ string, _ []byte) error {
	<-ctx.Done()
	return ctx.Err()
}

func (p *blockingWithdrawProofProducer) Close() error {
	return nil
}

func TestValidateWithdrawProofInputConfig_RequiresOWalletOVK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ovk       []byte
		wantError string
	}{
		{
			name:      "missing",
			ovk:       nil,
			wantError: "--owallet-ovk is required",
		},
		{
			name:      "wrong length",
			ovk:       []byte{0x01},
			wantError: "--owallet-ovk is required",
		},
		{
			name: "valid",
			ovk:  bytes.Repeat([]byte{0x42}, 32),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validateWithdrawProofInputConfig(tc.ovk)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("validateWithdrawProofInputConfig: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("validateWithdrawProofInputConfig() error = %v, want substring %q", err, tc.wantError)
			}
		})
	}
}

func TestWithdrawFinalizerQueueConsumerConfig_PostgresFallsBackToStoreDSN(t *testing.T) {
	t.Parallel()

	cfg, err := withdrawFinalizerQueueConsumerConfig(withdrawFinalizerQueueOptions{
		Driver:           queue.DriverPostgres,
		StorePostgresDSN: "postgres://state-db",
		Group:            "withdraw-finalizer",
		Topics:           []string{"checkpoints.packages.v1"},
		QueueMaxBytes:    123,
		MaxLineBytes:     456,
	})
	if err != nil {
		t.Fatalf("withdrawFinalizerQueueConsumerConfig: %v", err)
	}
	if got, want := cfg.Driver, queue.DriverPostgres; got != want {
		t.Fatalf("Driver = %q, want %q", got, want)
	}
	if got, want := cfg.PostgresDSN, "postgres://state-db"; got != want {
		t.Fatalf("PostgresDSN = %q, want %q", got, want)
	}
	if got, want := cfg.Group, "withdraw-finalizer"; got != want {
		t.Fatalf("Group = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.Topics, ","), "checkpoints.packages.v1"; got != want {
		t.Fatalf("Topics = %q, want %q", got, want)
	}
}

func TestWithdrawFinalizerQueueConsumerConfig_PostgresDSNEnvOverridesStoreDSN(t *testing.T) {
	t.Setenv("WITHDRAW_FINALIZER_QUEUE_DSN", "postgres://queue-db")

	cfg, err := withdrawFinalizerQueueConsumerConfig(withdrawFinalizerQueueOptions{
		Driver:           queue.DriverPostgres,
		PostgresDSNEnv:   "WITHDRAW_FINALIZER_QUEUE_DSN",
		StorePostgresDSN: "postgres://state-db",
		Group:            "withdraw-finalizer",
		Topics:           []string{"checkpoints.packages.v1"},
	})
	if err != nil {
		t.Fatalf("withdrawFinalizerQueueConsumerConfig: %v", err)
	}
	if got, want := cfg.PostgresDSN, "postgres://queue-db"; got != want {
		t.Fatalf("PostgresDSN = %q, want %q", got, want)
	}
}

func TestWithdrawProofQueueProducerConfiguresPostgresShadow(t *testing.T) {
	var configs []queue.ProducerConfig
	var calls []string
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		configs = append(configs, cfg)
		name := cfg.Driver
		if len(configs) == 2 {
			name = "shadow-" + cfg.Driver
		}
		return &recordingWithdrawProofProducer{name: name, calls: &calls}, nil
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

func TestWithdrawProofQueueTransportDefaultsToMainQueue(t *testing.T) {
	got, err := proofQueueDriverOrDefault("", queue.DriverKafka)
	if err != nil {
		t.Fatalf("proofQueueDriverOrDefault empty kafka: %v", err)
	}
	if want := queue.DriverKafka; got != want {
		t.Fatalf("proofQueueDriverOrDefault empty = %q, want %q", got, want)
	}
	got, err = proofQueueDriverOrDefault(queue.DriverPostgres, queue.DriverKafka)
	if err != nil {
		t.Fatalf("proofQueueDriverOrDefault override: %v", err)
	}
	if want := queue.DriverPostgres; got != want {
		t.Fatalf("proofQueueDriverOrDefault override = %q, want %q", got, want)
	}
	if got, want := strings.Join(proofQueueBrokersOrDefault(nil, []string{"main-1:9098"}), ","), "main-1:9098"; got != want {
		t.Fatalf("proofQueueBrokersOrDefault empty = %q, want %q", got, want)
	}
	if got, want := strings.Join(proofQueueBrokersOrDefault([]string{"proof-1:9098"}, []string{"main-1:9098"}), ","), "proof-1:9098"; got != want {
		t.Fatalf("proofQueueBrokersOrDefault override = %q, want %q", got, want)
	}
}

func TestWithdrawProofQueueTransportRequiresExplicitDriverWhenMainQueueIsPostgres(t *testing.T) {
	if _, err := proofQueueDriverOrDefault("", queue.DriverPostgres); err == nil || !strings.Contains(err.Error(), "--proof-queue-driver is required when --queue-driver=postgres") {
		t.Fatalf("proofQueueDriverOrDefault error = %v", err)
	}
}

func TestWithdrawProofQueueTransportAllowsMockProofWithPostgresMainQueue(t *testing.T) {
	got, err := proofQueueDriverForProofClient("mock", "", queue.DriverPostgres)
	if err != nil {
		t.Fatalf("proofQueueDriverForProofClient mock: %v", err)
	}
	if got != "" {
		t.Fatalf("proofQueueDriverForProofClient mock = %q, want empty unused driver", got)
	}
}

func TestWithdrawProofQueueConsumerConfiguresPostgres(t *testing.T) {
	cfg, err := proofQueueConsumerConfig(proofQueueConsumerOptions{
		Driver:           queue.DriverPostgres,
		StorePostgresDSN: "postgres://state-db",
		Group:            "withdraw-proof-group",
		Topics:           []string{"proof.fulfillments.v1", "proof.failures.v1"},
		QueueMaxBytes:    123,
		MaxLineBytes:     456,
	})
	if err != nil {
		t.Fatalf("proofQueueConsumerConfig: %v", err)
	}
	if got, want := cfg.Driver, queue.DriverPostgres; got != want {
		t.Fatalf("Driver = %q, want %q", got, want)
	}
	if got, want := cfg.PostgresDSN, "postgres://state-db"; got != want {
		t.Fatalf("PostgresDSN = %q, want %q", got, want)
	}
	if got, want := cfg.Group, "withdraw-proof-group"; got != want {
		t.Fatalf("Group = %q, want %q", got, want)
	}
	if got, want := strings.Join(cfg.Topics, ","), "proof.fulfillments.v1,proof.failures.v1"; got != want {
		t.Fatalf("Topics = %q, want %q", got, want)
	}
}

func TestWithdrawProofQueueProducerConfiguresPostgresPrimary(t *testing.T) {
	var configs []queue.ProducerConfig
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		configs = append(configs, cfg)
		return &recordingWithdrawProofProducer{name: cfg.Driver}, nil
	}

	producer, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:           queue.DriverPostgres,
		StorePostgresDSN: "postgres://state-db",
	}, factory)
	if err != nil {
		t.Fatalf("proofQueueProducer: %v", err)
	}
	if err := producer.Publish(context.Background(), "proof.requests.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(configs) != 1 {
		t.Fatalf("config count = %d, want 1", len(configs))
	}
	if got, want := configs[0].Driver, queue.DriverPostgres; got != want {
		t.Fatalf("primary driver = %q, want %q", got, want)
	}
	if got, want := configs[0].PostgresDSN, "postgres://state-db"; got != want {
		t.Fatalf("primary PostgresDSN = %q, want %q", got, want)
	}
}

func TestWithdrawProofQueueProducerToleratesOptionalShadowInitFailure(t *testing.T) {
	shadowErr := errors.New("shadow init down")
	var calls []string
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		if cfg.Driver == queue.DriverPostgres {
			return nil, shadowErr
		}
		return &recordingWithdrawProofProducer{name: cfg.Driver, calls: &calls}, nil
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

func TestWithdrawProofQueueProducerOptionalShadowUsesTimeout(t *testing.T) {
	var calls []string
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		if cfg.Driver == queue.DriverPostgres {
			return &blockingWithdrawProofProducer{}, nil
		}
		return &recordingWithdrawProofProducer{name: cfg.Driver, calls: &calls}, nil
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

func TestWithdrawProofQueueProducerRejectsUnsafeOptionalShadowTimeout(t *testing.T) {
	_, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:           queue.DriverKafka,
		Brokers:          []string{"b-1.example:9098"},
		StorePostgresDSN: "postgres://state-db",
		ShadowDriver:     queue.DriverPostgres,
		ShadowTimeout:    0,
	}, func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		return &recordingWithdrawProofProducer{name: cfg.Driver}, nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--proof-shadow-queue-timeout must be > 0") {
		t.Fatalf("error = %v, want shadow timeout validation error", err)
	}
}

func TestWithdrawProofQueueProducerLogsOptionalShadowConfigFailure(t *testing.T) {
	var calls []string
	var logBuf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuf, nil))
	t.Setenv("JUNO_TEST_MISSING_PROOF_SHADOW_DSN", "")
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		return &recordingWithdrawProofProducer{name: cfg.Driver, calls: &calls}, nil
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

func TestWithdrawProofQueueProducerOptionalShadowInitUsesTimeout(t *testing.T) {
	var calls []string
	releaseShadow := make(chan struct{})
	defer close(releaseShadow)
	factory := func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		if cfg.Driver == queue.DriverPostgres {
			select {
			case <-releaseShadow:
				return &recordingWithdrawProofProducer{name: "shadow-" + cfg.Driver}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return &recordingWithdrawProofProducer{name: cfg.Driver, calls: &calls}, nil
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

func TestWithdrawProofQueueProducerRequiredShadowRequiresDriver(t *testing.T) {
	_, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:         queue.DriverKafka,
		Brokers:        []string{"b-1.example:9098"},
		ShadowRequired: true,
	}, func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		return &recordingWithdrawProofProducer{name: cfg.Driver}, nil
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "--proof-shadow-queue-required requires --proof-shadow-queue-driver") {
		t.Fatalf("error = %v, want required shadow driver error", err)
	}
}

func TestWithdrawProofQueueProducerLogsOptionalUnsupportedShadowDriver(t *testing.T) {
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
		return &recordingWithdrawProofProducer{name: cfg.Driver, calls: &calls}, nil
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

func TestWithdrawProofQueueProducerRequiredUnsupportedShadowDriverFailsClosed(t *testing.T) {
	var primary *recordingWithdrawProofProducer
	_, err := proofQueueProducer(context.Background(), proofQueueProducerOptions{
		Driver:         queue.DriverKafka,
		Brokers:        []string{"b-1.example:9098"},
		ShadowDriver:   "typo",
		ShadowRequired: true,
		ShadowTimeout:  10 * time.Millisecond,
	}, func(ctx context.Context, cfg queue.ProducerConfig) (queue.Producer, error) {
		primary = &recordingWithdrawProofProducer{name: cfg.Driver}
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

func TestValidateWithdrawWitnessExtractorConfig_DisabledAllowsEmpty(t *testing.T) {
	t.Parallel()

	if err := validateWithdrawWitnessExtractorConfig(withdrawWitnessExtractorConfig{}); err != nil {
		t.Fatalf("validateWithdrawWitnessExtractorConfig: %v", err)
	}
}

func TestValidateWithdrawWitnessExtractorConfig_EnabledRequiresFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       withdrawWitnessExtractorConfig
		wantError string
	}{
		{
			name: "missing scan url",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:    true,
				WalletID:   "wallet-1",
				RPCURL:     "http://127.0.0.1:8232",
				RPCUserEnv: "JUNO_RPC_USER",
				RPCPassEnv: "JUNO_RPC_PASS",
			},
			wantError: "--juno-scan-url is required",
		},
		{
			name: "missing wallet id",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:    true,
				ScanURL:    "http://127.0.0.1:8080",
				RPCURL:     "http://127.0.0.1:8232",
				RPCUserEnv: "JUNO_RPC_USER",
				RPCPassEnv: "JUNO_RPC_PASS",
			},
			wantError: "--juno-scan-wallet-id is required",
		},
		{
			name: "missing rpc url",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:    true,
				ScanURL:    "http://127.0.0.1:8080",
				WalletID:   "wallet-1",
				RPCUserEnv: "JUNO_RPC_USER",
				RPCPassEnv: "JUNO_RPC_PASS",
			},
			wantError: "--juno-rpc-url is required",
		},
		{
			name: "missing rpc user env",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:  true,
				ScanURL:  "http://127.0.0.1:8080",
				WalletID: "wallet-1",
				RPCURL:   "http://127.0.0.1:8232",
			},
			wantError: "--juno-rpc-user-env is required",
		},
		{
			name: "missing rpc pass env",
			cfg: withdrawWitnessExtractorConfig{
				Enabled:    true,
				ScanURL:    "http://127.0.0.1:8080",
				WalletID:   "wallet-1",
				RPCURL:     "http://127.0.0.1:8232",
				RPCUserEnv: "JUNO_RPC_USER",
			},
			wantError: "--juno-rpc-pass-env is required",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateWithdrawWitnessExtractorConfig(tc.cfg)
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error: got %q want substring %q", err.Error(), tc.wantError)
			}
		})
	}
}

func TestNewWithdrawWitnessExtractor_RequiresRPCCredentials(t *testing.T) {
	cfg := withdrawWitnessExtractorConfig{
		Enabled:       true,
		ScanURL:       "http://127.0.0.1:8080",
		WalletID:      "wallet-1",
		ScanBearerEnv: "JUNO_SCAN_BEARER_TOKEN",
		RPCURL:        "http://127.0.0.1:8232",
		RPCUserEnv:    "JUNO_RPC_USER",
		RPCPassEnv:    "JUNO_RPC_PASS",
	}
	t.Setenv("JUNO_RPC_USER", "")
	t.Setenv("JUNO_RPC_PASS", "")

	_, err := newWithdrawWitnessExtractor(cfg, nil)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "missing junocashd RPC credentials") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithdrawWitnessExtractor_ExtractPersistsScanBackfillCursor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 20, 12, 0, 0, 0, time.UTC)
	store := withdraw.NewMemoryStore(func() time.Time { return now })

	scan := &stubWitnessScanClient{
		notes: []witnessextract.WalletNote{
			{
				TxID:        strings.Repeat("ab", 32),
				ActionIndex: 2,
				Position:    ptrInt64(7),
			},
		},
		witness: witnessextract.WitnessResponse{
			AnchorHeight: 321,
			Root:         "0x" + strings.Repeat("cd", 32),
			Paths:        []witnessextract.WitnessPath{{Position: 7, AuthPath: testAuthPathHex()}},
		},
	}
	rpc := &stubWitnessRPCClient{action: testRPCAction()}
	extractor := &withdrawWitnessExtractor{
		walletID: "wallet-1",
		builder:  witnessextract.New(scan, rpc),
		minAnchorHeight: func(context.Context, string) (int64, error) {
			return 123, nil
		},
		cursorStore: store,
	}

	var withdrawalID [32]byte
	withdrawalID[0] = 0x11
	recipientRaw := bytes.Repeat([]byte{0x7a}, 43)
	anchorHeight := int64(321)

	got, err := extractor.ExtractWithdrawWitness(context.Background(), withdrawfinalizer.WithdrawWitnessExtractRequest{
		TxHash:       strings.Repeat("ab", 32),
		ActionIndex:  2,
		AnchorHeight: &anchorHeight,
		WithdrawalID: withdrawalID,
		RecipientUA:  recipientRaw,
	})
	if err != nil {
		t.Fatalf("ExtractWithdrawWitness: %v", err)
	}
	if len(got) != proverinput.WithdrawWitnessItemLen {
		t.Fatalf("witness item len: got %d want %d", len(got), proverinput.WithdrawWitnessItemLen)
	}

	height, updatedAt, ok, err := store.GetScanBackfillCursor(context.Background(), "wallet-1")
	if err != nil {
		t.Fatalf("GetScanBackfillCursor: %v", err)
	}
	if !ok || height != 123 || updatedAt.IsZero() {
		t.Fatalf("cursor persistence mismatch: ok=%v height=%d updatedAt=%s", ok, height, updatedAt)
	}
}

func TestWithdrawWitnessExtractor_ExtractUsesTxHashActionAnchorAndIdentity(t *testing.T) {
	t.Parallel()

	scan := &stubWitnessScanClient{
		notes: []witnessextract.WalletNote{
			{
				TxID:        strings.Repeat("ab", 32),
				ActionIndex: 2,
				Position:    ptrInt64(7),
			},
		},
		witness: witnessextract.WitnessResponse{
			AnchorHeight: 321,
			Root:         "0x" + strings.Repeat("cd", 32),
			Paths: []witnessextract.WitnessPath{
				{
					Position: 7,
					AuthPath: testAuthPathHex(),
				},
			},
		},
	}
	rpc := &stubWitnessRPCClient{
		action: testRPCAction(),
	}
	extractor := &withdrawWitnessExtractor{
		walletID: "wallet-1",
		builder:  witnessextract.New(scan, rpc),
	}

	var withdrawalID [32]byte
	for i := range withdrawalID {
		withdrawalID[i] = byte(i + 1)
	}
	recipientRaw := bytes.Repeat([]byte{0x7a}, 43)
	anchorHeight := int64(321)

	got, err := extractor.ExtractWithdrawWitness(context.Background(), withdrawfinalizer.WithdrawWitnessExtractRequest{
		TxHash:       strings.Repeat("ab", 32),
		ActionIndex:  2,
		AnchorHeight: &anchorHeight,
		WithdrawalID: withdrawalID,
		RecipientUA:  recipientRaw,
	})
	if err != nil {
		t.Fatalf("ExtractWithdrawWitness: %v", err)
	}
	if len(got) != proverinput.WithdrawWitnessItemLen {
		t.Fatalf("witness item len: got %d want %d", len(got), proverinput.WithdrawWitnessItemLen)
	}
	if !bytes.Equal(got[:32], withdrawalID[:]) {
		t.Fatalf("withdrawal id prefix mismatch")
	}
	if !bytes.Equal(got[32:32+43], recipientRaw) {
		t.Fatalf("recipient raw prefix mismatch")
	}
	if gotWallet := scan.gotWalletID; gotWallet != "wallet-1" {
		t.Fatalf("wallet id: got %q want %q", gotWallet, "wallet-1")
	}
	if scan.gotAnchorHeight == nil || *scan.gotAnchorHeight != anchorHeight {
		t.Fatalf("anchor height: got %v want %d", scan.gotAnchorHeight, anchorHeight)
	}
	if gotTxID, wantTxID := rpc.gotTxID, strings.Repeat("ab", 32); gotTxID != wantTxID {
		t.Fatalf("txid: got %q want %q", gotTxID, wantTxID)
	}
	if got, want := rpc.gotActionIndex, uint32(2); got != want {
		t.Fatalf("action index: got %d want %d", got, want)
	}
}

func TestWithdrawWitnessExtractor_ExtractRejectsInvalidRecipientUALength(t *testing.T) {
	t.Parallel()

	extractor := &withdrawWitnessExtractor{
		walletID: "wallet-1",
		builder:  witnessextract.New(&stubWitnessScanClient{}, &stubWitnessRPCClient{}),
	}
	_, err := extractor.ExtractWithdrawWitness(context.Background(), withdrawfinalizer.WithdrawWitnessExtractRequest{
		TxHash:       strings.Repeat("ab", 32),
		ActionIndex:  0,
		WithdrawalID: [32]byte{},
		RecipientUA:  []byte{0x01},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "recipient ua must be 43 bytes") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWithdrawWitnessExtractor_ExtractFallbacksByExpectedValue(t *testing.T) {
	t.Parallel()

	expectedValue := uint64(995)
	scan := &stubWitnessScanClient{
		notes: []witnessextract.WalletNote{
			{
				TxID:        strings.Repeat("ab", 32),
				ActionIndex: 0,
				Position:    ptrInt64(2),
				ValueZat:    2500000,
			},
			{
				TxID:        strings.Repeat("ab", 32),
				ActionIndex: 2,
				Position:    ptrInt64(7),
				ValueZat:    expectedValue,
			},
		},
		witness: witnessextract.WitnessResponse{
			AnchorHeight: 321,
			Root:         "0x" + strings.Repeat("cd", 32),
			Paths: []witnessextract.WitnessPath{
				{
					Position: 7,
					AuthPath: testAuthPathHex(),
				},
			},
		},
	}
	rpc := &stubWitnessRPCClient{
		action: testRPCAction(),
	}
	extractor := &withdrawWitnessExtractor{
		walletID: "wallet-1",
		builder:  witnessextract.New(scan, rpc),
	}

	recipientRaw := bytes.Repeat([]byte{0x7a}, 43)
	anchorHeight := int64(321)
	_, err := extractor.ExtractWithdrawWitness(context.Background(), withdrawfinalizer.WithdrawWitnessExtractRequest{
		TxHash:           strings.Repeat("ab", 32),
		ActionIndex:      0,
		ExpectedValueZat: &expectedValue,
		AnchorHeight:     &anchorHeight,
		WithdrawalID:     [32]byte{},
		RecipientUA:      recipientRaw,
	})
	if err != nil {
		t.Fatalf("ExtractWithdrawWitness: %v", err)
	}
	if got, want := rpc.gotActionIndex, uint32(2); got != want {
		t.Fatalf("action index: got %d want %d", got, want)
	}
}

func TestWithdrawWitnessExtractor_RefreshUsesAnchorAndStoredWitness(t *testing.T) {
	t.Parallel()

	originalAuth := testAuthPathHex()
	refreshedAuth := testAuthPathHexWithSeed(0x44)
	action := testRPCAction()

	var withdrawalID [32]byte
	withdrawalID[0] = 0xaa
	recipientRaw := bytes.Repeat([]byte{0x7a}, 43)
	var recipientRawFixed [43]byte
	copy(recipientRawFixed[:], recipientRaw)

	originalWitness, err := witnessitem.EncodeWithdrawItem(
		withdrawalID,
		recipientRawFixed,
		7,
		mustAuthPathFromHex(t, originalAuth),
		witnessitem.OrchardAction{
			Nullifier:     action.Nullifier,
			RK:            action.RK,
			CMX:           action.CMX,
			EphemeralKey:  action.EphemeralKey,
			EncCiphertext: action.EncCiphertext,
			OutCiphertext: action.OutCiphertext,
			CV:            action.CV,
		},
	)
	if err != nil {
		t.Fatalf("EncodeWithdrawItem: %v", err)
	}

	scan := &stubWitnessScanClient{
		witness: witnessextract.WitnessResponse{
			AnchorHeight: 654,
			Root:         "0x" + strings.Repeat("ef", 32),
			Paths: []witnessextract.WitnessPath{
				{
					Position: 7,
					AuthPath: refreshedAuth,
				},
			},
		},
	}
	extractor := &withdrawWitnessExtractor{
		walletID: "wallet-1",
		builder:  witnessextract.New(scan, &stubWitnessRPCClient{}),
	}

	root, refreshed, err := extractor.RefreshWithdrawWitness(context.Background(), 654, originalWitness)
	if err != nil {
		t.Fatalf("RefreshWithdrawWitness: %v", err)
	}
	if root != common.HexToHash(scan.witness.Root) {
		t.Fatalf("root mismatch: got=%s want=%s", root.Hex(), common.HexToHash(scan.witness.Root).Hex())
	}
	if scan.gotAnchorHeight == nil || *scan.gotAnchorHeight != 654 {
		t.Fatalf("anchor height: got %v want 654", scan.gotAnchorHeight)
	}
	if len(scan.gotPositions) != 1 || scan.gotPositions[0] != 7 {
		t.Fatalf("positions mismatch: got=%v want=[7]", scan.gotPositions)
	}
	if len(refreshed) != proverinput.WithdrawWitnessItemLen {
		t.Fatalf("refreshed witness len: got %d want %d", len(refreshed), proverinput.WithdrawWitnessItemLen)
	}
	if !bytes.Equal(refreshed[:32+43+4], originalWitness[:32+43+4]) {
		t.Fatalf("identity prefix changed")
	}
}

func TestWithdrawWitnessExtractor_ExtractDefersWhenAnchorBelowTxMinimumHeight(t *testing.T) {
	t.Parallel()

	scan := &stubWitnessScanClient{
		notes: []witnessextract.WalletNote{
			{
				TxID:        strings.Repeat("ab", 32),
				ActionIndex: 0,
				Position:    ptrInt64(7),
				ValueZat:    995,
			},
		},
		witness: witnessextract.WitnessResponse{
			AnchorHeight: 321,
			Root:         "0x" + strings.Repeat("cd", 32),
			Paths: []witnessextract.WitnessPath{
				{
					Position: 7,
					AuthPath: testAuthPathHex(),
				},
			},
		},
	}
	rpc := &stubWitnessRPCClient{
		action: testRPCAction(),
	}

	var gotAnchorTxID string
	extractor := &withdrawWitnessExtractor{
		walletID: "wallet-1",
		builder:  witnessextract.New(scan, rpc),
		minAnchorHeight: func(_ context.Context, txid string) (int64, error) {
			gotAnchorTxID = txid
			return 500, nil
		},
	}

	recipientRaw := bytes.Repeat([]byte{0x7a}, 43)
	anchorHeight := int64(321)
	_, err := extractor.ExtractWithdrawWitness(context.Background(), withdrawfinalizer.WithdrawWitnessExtractRequest{
		TxHash:           strings.Repeat("ab", 32),
		ActionIndex:      0,
		ExpectedValueZat: ptrUint64(995),
		AnchorHeight:     &anchorHeight,
		WithdrawalID:     [32]byte{},
		RecipientUA:      recipientRaw,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "anchor height 321 below tx minimum anchor height 500") {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAnchorTxID != strings.Repeat("ab", 32) {
		t.Fatalf("anchor guard txid: got %q want %q", gotAnchorTxID, strings.Repeat("ab", 32))
	}
	if rpc.gotTxID != "" {
		t.Fatalf("expected orchard action lookup to be skipped when anchor is below tx minimum height, got txid=%q", rpc.gotTxID)
	}
}

func TestWithdrawWitnessExtractor_ExtractSkipsAnchorGuardWhenTxMetadataMissing(t *testing.T) {
	t.Parallel()

	scan := &stubWitnessScanClient{
		notes: []witnessextract.WalletNote{
			{
				TxID:        strings.Repeat("ab", 32),
				ActionIndex: 0,
				Position:    ptrInt64(7),
				ValueZat:    995,
			},
		},
		witness: witnessextract.WitnessResponse{
			AnchorHeight: 654,
			Root:         "0x" + strings.Repeat("cd", 32),
			Paths: []witnessextract.WitnessPath{
				{
					Position: 7,
					AuthPath: testAuthPathHex(),
				},
			},
		},
	}
	rpc := &stubWitnessRPCClient{
		action: testRPCAction(),
	}

	var gotAnchorTxID string
	extractor := &withdrawWitnessExtractor{
		walletID: "wallet-1",
		builder:  witnessextract.New(scan, rpc),
		minAnchorHeight: func(_ context.Context, txid string) (int64, error) {
			gotAnchorTxID = txid
			return 0, junorpc.ErrTxNotFound
		},
	}

	recipientRaw := bytes.Repeat([]byte{0x7a}, 43)
	anchorHeight := int64(654)
	got, err := extractor.ExtractWithdrawWitness(context.Background(), withdrawfinalizer.WithdrawWitnessExtractRequest{
		TxHash:           strings.Repeat("ab", 32),
		ActionIndex:      0,
		ExpectedValueZat: ptrUint64(995),
		AnchorHeight:     &anchorHeight,
		WithdrawalID:     [32]byte{},
		RecipientUA:      recipientRaw,
	})
	if err != nil {
		t.Fatalf("ExtractWithdrawWitness: %v", err)
	}
	if len(got) != proverinput.WithdrawWitnessItemLen {
		t.Fatalf("witness len: got %d want %d", len(got), proverinput.WithdrawWitnessItemLen)
	}
	if gotAnchorTxID != strings.Repeat("ab", 32) {
		t.Fatalf("anchor guard txid: got %q want %q", gotAnchorTxID, strings.Repeat("ab", 32))
	}
	if rpc.gotTxID != strings.Repeat("ab", 32) {
		t.Fatalf("expected orchard action lookup to proceed, got txid=%q", rpc.gotTxID)
	}
}

type stubWitnessScanClient struct {
	notes           []witnessextract.WalletNote
	notesByWallet   map[string][]witnessextract.WalletNote
	walletIDs       []string
	witness         witnessextract.WitnessResponse
	gotWalletID     string
	gotAnchorHeight *int64
	gotPositions    []uint32
}

func (s *stubWitnessScanClient) ListWalletIDs(_ context.Context) ([]string, error) {
	if len(s.walletIDs) > 0 {
		return append([]string(nil), s.walletIDs...), nil
	}
	if len(s.notesByWallet) > 0 {
		out := make([]string, 0, len(s.notesByWallet))
		for walletID := range s.notesByWallet {
			out = append(out, walletID)
		}
		return out, nil
	}
	return []string{"wallet-1"}, nil
}

func (s *stubWitnessScanClient) ListWalletNotes(_ context.Context, walletID string) ([]witnessextract.WalletNote, error) {
	s.gotWalletID = walletID
	if s.notesByWallet != nil {
		return append([]witnessextract.WalletNote(nil), s.notesByWallet[walletID]...), nil
	}
	return append([]witnessextract.WalletNote(nil), s.notes...), nil
}

func (s *stubWitnessScanClient) OrchardWitness(_ context.Context, anchorHeight *int64, positions []uint32) (witnessextract.WitnessResponse, error) {
	if anchorHeight != nil {
		v := *anchorHeight
		s.gotAnchorHeight = &v
	}
	s.gotPositions = append([]uint32(nil), positions...)
	return s.witness, nil
}

type stubWitnessRPCClient struct {
	action         junorpc.OrchardAction
	gotTxID        string
	gotActionIndex uint32
}

func TestScanHTTPClientListWalletNotesRequestsOutgoingDirectionAndFiltersResponse(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/wallets/wallet-a/notes" {
			t.Fatalf("path: got %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("limit"); got != "1000" {
			t.Fatalf("limit: got %q want 1000", got)
		}
		if got := r.URL.Query().Get("direction"); got != "outgoing" {
			t.Fatalf("direction: got %q want outgoing", got)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"notes": []map[string]any{
				{
					"direction":    "incoming",
					"txid":         "bad",
					"action_index": 0,
					"value_zat":    1,
				},
				{
					"direction":    "outgoing",
					"txid":         "good",
					"action_index": 1,
					"value_zat":    2,
					"position":     42,
				},
			},
		})
	}))
	defer srv.Close()

	client := &scanHTTPClient{
		baseURL: srv.URL,
		hc:      &http.Client{Timeout: time.Second},
	}
	notes, err := client.ListWalletNotes(context.Background(), "wallet-a")
	if err != nil {
		t.Fatalf("ListWalletNotes: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("notes len: got %d want 1: %#v", len(notes), notes)
	}
	if notes[0].TxID != "good" || notes[0].ActionIndex != 1 || notes[0].ValueZat != 2 {
		t.Fatalf("note: got %#v", notes[0])
	}
	if notes[0].Position == nil || *notes[0].Position != 42 {
		t.Fatalf("position: got %#v want 42", notes[0].Position)
	}
}

func (s *stubWitnessRPCClient) GetOrchardAction(_ context.Context, txid string, actionIndex uint32) (junorpc.OrchardAction, error) {
	s.gotTxID = txid
	s.gotActionIndex = actionIndex
	return s.action, nil
}

func testRPCAction() junorpc.OrchardAction {
	var out junorpc.OrchardAction
	out.Nullifier[0] = 0x01
	out.RK[0] = 0x02
	out.CMX[0] = 0x03
	out.EphemeralKey[0] = 0x04
	out.EncCiphertext[0] = 0x05
	out.OutCiphertext[0] = 0x06
	out.CV[0] = 0x07
	return out
}

func testAuthPathHex() []string {
	return testAuthPathHexWithSeed(0x01)
}

func testAuthPathHexWithSeed(seed byte) []string {
	out := make([]string, 32)
	for i := 0; i < 32; i++ {
		chunk := make([]byte, 32)
		chunk[0] = seed + byte(i)
		out[i] = "0x" + bytesToHex(chunk)
	}
	return out
}

func mustAuthPathFromHex(t *testing.T, pathHex []string) [][32]byte {
	t.Helper()

	if len(pathHex) != 32 {
		t.Fatalf("auth path len: got=%d want=32", len(pathHex))
	}
	out := make([][32]byte, 0, len(pathHex))
	for i, raw := range pathHex {
		b, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
		if err != nil {
			t.Fatalf("decode auth path[%d]: %v", i, err)
		}
		if len(b) != 32 {
			t.Fatalf("auth path[%d] len: got=%d want=32", i, len(b))
		}
		var item [32]byte
		copy(item[:], b)
		out = append(out, item)
	}
	return out
}

func bytesToHex(in []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(in)*2)
	for i, b := range in {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}

func ptrInt64(v int64) *int64 {
	return &v
}

func ptrUint64(v uint64) *uint64 {
	return &v
}
