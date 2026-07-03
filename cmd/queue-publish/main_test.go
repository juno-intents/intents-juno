package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/juno-intents/intents-juno/internal/queueauth"
)

type recordingQueuePublishProducer struct {
	name       string
	calls      *[]string
	publishErr error
	closed     bool
}

func (p *recordingQueuePublishProducer) Publish(_ context.Context, topic string, payload []byte) error {
	if p.calls != nil {
		*p.calls = append(*p.calls, p.name+":"+topic+":"+string(payload))
	}
	return p.publishErr
}

func (p *recordingQueuePublishProducer) Close() error {
	p.closed = true
	return nil
}

func TestLoadPayloads_Inline(t *testing.T) {
	t.Parallel()

	payloads, err := loadPayloads(`{"version":"v1"}`, nil, nil)
	if err != nil {
		t.Fatalf("loadPayloads: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("payload count: got=%d want=1", len(payloads))
	}
	if string(payloads[0]) != `{"version":"v1"}` {
		t.Fatalf("payload mismatch: %q", string(payloads[0]))
	}
}

func TestLoadPayloads_File(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	payloadPath := filepath.Join(tmpDir, "payload.json")
	if err := os.WriteFile(payloadPath, []byte(`{"version":"v2"}`), 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	payloads, err := loadPayloads("", []string{payloadPath}, nil)
	if err != nil {
		t.Fatalf("loadPayloads: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("payload count: got=%d want=1", len(payloads))
	}
	if string(payloads[0]) != `{"version":"v2"}` {
		t.Fatalf("payload mismatch: %q", string(payloads[0]))
	}
}

func TestLoadPayloads_StdinFallback(t *testing.T) {
	t.Parallel()

	payloads, err := loadPayloads("", nil, bytes.NewBufferString(`{"version":"v3"}`))
	if err != nil {
		t.Fatalf("loadPayloads: %v", err)
	}
	if len(payloads) != 1 {
		t.Fatalf("payload count: got=%d want=1", len(payloads))
	}
	if string(payloads[0]) != `{"version":"v3"}` {
		t.Fatalf("payload mismatch: %q", string(payloads[0]))
	}
}

func TestLoadPayloads_EmptyInput(t *testing.T) {
	t.Parallel()

	_, err := loadPayloads("", nil, bytes.NewBufferString(" \n\t"))
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRunMain_StdioPublishesLines(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--topic", "example.topic",
			"--payload", `{"version":"v1"}`,
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	if got := out.String(); got != "{\"version\":\"v1\"}\n" {
		t.Fatalf("unexpected stdout: %q", got)
	}
	if got := errOut.String(); got == "" {
		t.Fatal("expected audit log")
	}
}

func TestRunMain_SignsCriticalTopic(t *testing.T) {
	t.Setenv("QUEUE_AUTH_SECRET", "super-secret-key")

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--topic", "deposits.event.v2",
			"--payload", `{"version":"deposits.event.v2"}`,
			"--queue-auth-key-id", "ops-1",
			"--queue-auth-hmac-env", "QUEUE_AUTH_SECRET",
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	codec := queueauth.New(queueauth.Config{
		KeyID:  "ops-1",
		Secret: []byte("super-secret-key"),
	})
	raw, err := codec.Unwrap("deposits.event.v2", bytes.TrimSpace(out.Bytes()))
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if got := string(raw); got != `{"version":"deposits.event.v2"}` {
		t.Fatalf("payload mismatch: %q", got)
	}
	if got := errOut.String(); got == "" {
		t.Fatal("expected audit log")
	}
}

func TestRunMain_RejectsUnsignedCriticalTopic(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--topic", "deposits.event.v2",
			"--payload", `{"version":"deposits.event.v2"}`,
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunMain_DryRunSkipsPublish(t *testing.T) {
	t.Setenv("QUEUE_AUTH_SECRET", "super-secret-key")

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--topic", "deposits.event.v2",
			"--payload", `{"version":"deposits.event.v2"}`,
			"--queue-auth-key-id", "ops-1",
			"--queue-auth-hmac-env", "QUEUE_AUTH_SECRET",
			"--dry-run",
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no publish output, got %q", out.String())
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte(`"status":"dry_run"`)) {
		t.Fatalf("expected dry_run audit record, got %q", got)
	}
}

func TestRunMain_DryRunPostgresDoesNotRequireDSN(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "postgres",
			"--topic", "example.topic",
			"--payload", `{"version":"v1"}`,
			"--dry-run",
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no publish output, got %q", out.String())
	}
	if got := errOut.String(); !bytes.Contains([]byte(got), []byte(`"status":"dry_run"`)) {
		t.Fatalf("expected dry_run audit record, got %q", got)
	}
}

func TestRunMain_DryRunRejectsUnsupportedQueueDriver(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "typo",
			"--topic", "example.topic",
			"--payload", `{"version":"v1"}`,
			"--dry-run",
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunMain_ToleratesOptionalBadShadowConfig(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--shadow-queue-driver", "postgres",
			"--topic", "example.topic",
			"--payload", `{"version":"v1"}`,
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	if got := out.String(); got != "{\"version\":\"v1\"}\n" {
		t.Fatalf("unexpected stdout: %q", got)
	}
}

func TestRunMain_DryRunRequiredPostgresShadowRequiresDSN(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "stdio",
			"--shadow-queue-driver", "postgres",
			"--shadow-queue-required",
			"--topic", "example.topic",
			"--payload", `{"version":"v1"}`,
			"--dry-run",
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestQueuePublishProducerConfiguresShadow(t *testing.T) {
	t.Setenv("QUEUE_POSTGRES_DSN", "postgres://user:pass@127.0.0.1:5432/db")

	var configs []queue.ProducerConfig
	var calls []string
	factory := func(cfg queue.ProducerConfig) (queue.Producer, error) {
		configs = append(configs, cfg)
		name := cfg.Driver
		if len(configs) == 2 {
			name = "shadow-" + cfg.Driver
		}
		return &recordingQueuePublishProducer{name: name, calls: &calls}, nil
	}

	producer, err := queuePublishProducer(queuePublishProducerOptions{
		Driver:               queue.DriverKafka,
		Brokers:              "b-1.example:9098,b-2.example:9098",
		ShadowDriver:         queue.DriverPostgres,
		ShadowPostgresDSNEnv: "QUEUE_POSTGRES_DSN",
	}, io.Discard, factory)
	if err != nil {
		t.Fatalf("queuePublishProducer: %v", err)
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
	if got, want := configs[1].PostgresDSN, "postgres://user:pass@127.0.0.1:5432/db"; got != want {
		t.Fatalf("shadow PostgresDSN = %q, want %q", got, want)
	}
	if got, want := strings.Join(calls, ","), "kafka:proof.requests.v1:payload,shadow-postgres:proof.requests.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
}

func TestQueuePublishProducerConfiguresPostgresPrimaryKafkaShadow(t *testing.T) {
	t.Setenv("QUEUE_POSTGRES_DSN", "postgres://user:pass@127.0.0.1:5432/db")

	var configs []queue.ProducerConfig
	var calls []string
	factory := func(cfg queue.ProducerConfig) (queue.Producer, error) {
		configs = append(configs, cfg)
		name := cfg.Driver
		if len(configs) == 2 {
			name = "shadow-" + cfg.Driver
		}
		return &recordingQueuePublishProducer{name: name, calls: &calls}, nil
	}

	producer, err := queuePublishProducer(queuePublishProducerOptions{
		Driver:         queue.DriverPostgres,
		PostgresDSNEnv: "QUEUE_POSTGRES_DSN",
		ShadowDriver:   queue.DriverKafka,
		ShadowBrokers:  "b-1.example:9098,b-2.example:9098",
	}, io.Discard, factory)
	if err != nil {
		t.Fatalf("queuePublishProducer: %v", err)
	}
	if err := producer.Publish(context.Background(), "proof.requests.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if len(configs) != 2 {
		t.Fatalf("config count = %d, want 2", len(configs))
	}
	if got, want := configs[0].Driver, queue.DriverPostgres; got != want {
		t.Fatalf("primary driver = %q, want %q", got, want)
	}
	if got, want := configs[0].PostgresDSN, "postgres://user:pass@127.0.0.1:5432/db"; got != want {
		t.Fatalf("primary PostgresDSN = %q, want %q", got, want)
	}
	if got, want := configs[1].Driver, queue.DriverKafka; got != want {
		t.Fatalf("shadow driver = %q, want %q", got, want)
	}
	if got, want := strings.Join(configs[1].Brokers, ","), "b-1.example:9098,b-2.example:9098"; got != want {
		t.Fatalf("shadow brokers = %q, want %q", got, want)
	}
	if got, want := strings.Join(calls, ","), "postgres:proof.requests.v1:payload,shadow-kafka:proof.requests.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
}

func TestQueuePublishProducerCanRequireShadow(t *testing.T) {
	shadowErr := errors.New("shadow down")
	factory := func(cfg queue.ProducerConfig) (queue.Producer, error) {
		producer := &recordingQueuePublishProducer{name: cfg.Driver}
		if cfg.Driver == queue.DriverStdio {
			producer.publishErr = shadowErr
		}
		return producer, nil
	}

	producer, err := queuePublishProducer(queuePublishProducerOptions{
		Driver:         queue.DriverKafka,
		Brokers:        "b-1.example:9098",
		ShadowDriver:   queue.DriverStdio,
		ShadowRequired: true,
	}, io.Discard, factory)
	if err != nil {
		t.Fatalf("queuePublishProducer: %v", err)
	}
	if err := producer.Publish(context.Background(), "proof.requests.v1", []byte("payload")); !errors.Is(err, shadowErr) {
		t.Fatalf("Publish error = %v, want shadow error", err)
	}
}

func TestQueuePublishProducerToleratesOptionalShadowInitFailure(t *testing.T) {
	shadowErr := errors.New("shadow init down")
	var calls []string
	factory := func(cfg queue.ProducerConfig) (queue.Producer, error) {
		if cfg.Driver == queue.DriverStdio {
			return nil, shadowErr
		}
		return &recordingQueuePublishProducer{name: cfg.Driver, calls: &calls}, nil
	}

	producer, err := queuePublishProducer(queuePublishProducerOptions{
		Driver:       queue.DriverKafka,
		Brokers:      "b-1.example:9098",
		ShadowDriver: queue.DriverStdio,
	}, io.Discard, factory)
	if err != nil {
		t.Fatalf("queuePublishProducer: %v", err)
	}
	if err := producer.Publish(context.Background(), "proof.requests.v1", []byte("payload")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got, want := strings.Join(calls, ","), "kafka:proof.requests.v1:payload"; got != want {
		t.Fatalf("calls = %q, want %q", got, want)
	}
}

func TestRunMain_DryRunKafkaRequiresBrokers(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runMain(
		[]string{
			"--queue-driver", "kafka",
			"--topic", "example.topic",
			"--payload", `{"version":"v1"}`,
			"--dry-run",
		},
		bytes.NewBuffer(nil),
		&out,
		&errOut,
	)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestProducerConfigForQueueDriverPostgresRequiresDSN(t *testing.T) {
	t.Parallel()

	_, err := producerConfigForQueueDriver("postgres", "", "", "", nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestProducerConfigForQueueDriverPostgresUsesDSNEnv(t *testing.T) {
	t.Setenv("QUEUE_POSTGRES_DSN", "postgres://user:pass@127.0.0.1:5432/db")

	cfg, err := producerConfigForQueueDriver("postgres", "", "", "QUEUE_POSTGRES_DSN", nil)
	if err != nil {
		t.Fatalf("producerConfigForQueueDriver: %v", err)
	}
	if cfg.PostgresDSN != "postgres://user:pass@127.0.0.1:5432/db" {
		t.Fatalf("PostgresDSN = %q", cfg.PostgresDSN)
	}
}
