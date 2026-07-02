package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/juno-intents/intents-juno/internal/pgxpoolutil"
	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/juno-intents/intents-juno/internal/queueauth"
)

type stringListFlag []string

func (f *stringListFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, ",")
}

func (f *stringListFlag) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("value must not be empty")
	}
	*f = append(*f, v)
	return nil
}

func main() {
	if err := runMain(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type auditRecord struct {
	Topic         string `json:"topic"`
	Critical      bool   `json:"critical"`
	DryRun        bool   `json:"dryRun"`
	KeyID         string `json:"keyId,omitempty"`
	PayloadSHA256 string `json:"payloadSha256"`
	WireSHA256    string `json:"wireSha256,omitempty"`
	PayloadBytes  int    `json:"payloadBytes"`
	WireBytes     int    `json:"wireBytes,omitempty"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
}

func runMain(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) error {
	var payloadFiles stringListFlag
	fs := flag.NewFlagSet("queue-publish", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	queueDriver := fs.String("queue-driver", queue.DriverKafka, "queue driver: kafka|postgres|stdio")
	queueBrokers := fs.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")
	queuePostgresDSN := fs.String("queue-postgres-dsn", "", "Postgres DSN for postgres queue driver")
	queuePostgresDSNEnv := fs.String("queue-postgres-dsn-env", "", "env var containing Postgres DSN for postgres queue driver")
	shadowQueueDriver := fs.String("shadow-queue-driver", "", "optional shadow queue driver: kafka|postgres|stdio")
	shadowQueueBrokers := fs.String("shadow-queue-brokers", "", "comma-separated shadow queue brokers (required for kafka shadow)")
	shadowQueuePostgresDSN := fs.String("shadow-queue-postgres-dsn", "", "Postgres DSN for postgres shadow queue driver")
	shadowQueuePostgresDSNEnv := fs.String("shadow-queue-postgres-dsn-env", "", "env var containing Postgres DSN for postgres shadow queue driver")
	shadowQueueRequired := fs.Bool("shadow-queue-required", false, "fail publish when the shadow queue publish fails")
	topic := fs.String("topic", "", "queue topic (required)")
	payload := fs.String("payload", "", "inline payload body")
	fs.Var(&payloadFiles, "payload-file", "payload file path (repeatable)")
	dryRun := fs.Bool("dry-run", false, "validate payloads and emit audit logs without publishing")
	queueAuthKeyID := fs.String("queue-auth-key-id", "", "critical-topic signing key id")
	queueAuthKeyIDEnv := fs.String("queue-auth-key-id-env", queueauth.DefaultKeyIDEnv, "env var containing critical-topic signing key id")
	queueAuthHMACEnv := fs.String("queue-auth-hmac-env", queueauth.DefaultHMACEnv, "env var containing critical-topic HMAC secret")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*topic) == "" {
		return errors.New("--topic is required")
	}
	keyID := queueauth.ResolveKeyID(*queueAuthKeyID, *queueAuthKeyIDEnv)
	criticalQueueCodec := queueauth.New(queueauth.Config{
		KeyID:  keyID,
		Secret: queueauth.ResolveSecret("", *queueAuthHMACEnv),
	})

	payloads, err := loadPayloads(strings.TrimSpace(*payload), payloadFiles, stdin)
	if err != nil {
		return err
	}
	if err := validateQueuePublishConfig(*queueDriver, *queueBrokers, *queuePostgresDSN, *queuePostgresDSNEnv, *dryRun); err != nil {
		return err
	}
	if err := validateShadowQueuePublishConfig(*shadowQueueDriver, *shadowQueueBrokers, *shadowQueuePostgresDSN, *shadowQueuePostgresDSNEnv, *shadowQueueRequired); err != nil {
		return err
	}

	var producer queue.Producer
	ctx := context.Background()
	for _, p := range payloads {
		if len(bytes.TrimSpace(p)) == 0 {
			continue
		}
		rec := auditRecord{
			Topic:         *topic,
			Critical:      queueauth.IsCriticalTopic(*topic),
			DryRun:        *dryRun,
			KeyID:         keyID,
			PayloadSHA256: sha256Hex(p),
			PayloadBytes:  len(p),
		}
		wirePayload, err := queueauth.WrapPayload(criticalQueueCodec, *topic, p)
		if err != nil {
			rec.Status = "rejected"
			rec.Error = err.Error()
			writeAuditRecord(stderr, rec)
			return err
		}
		rec.WireSHA256 = sha256Hex(wirePayload)
		rec.WireBytes = len(wirePayload)
		if *dryRun {
			rec.Status = "dry_run"
			writeAuditRecord(stderr, rec)
			continue
		}
		if producer == nil {
			producer, err = queuePublishProducer(queuePublishProducerOptions{
				Driver:               *queueDriver,
				Brokers:              *queueBrokers,
				PostgresDSN:          *queuePostgresDSN,
				PostgresDSNEnv:       *queuePostgresDSNEnv,
				ShadowDriver:         *shadowQueueDriver,
				ShadowBrokers:        *shadowQueueBrokers,
				ShadowPostgresDSN:    *shadowQueuePostgresDSN,
				ShadowPostgresDSNEnv: *shadowQueuePostgresDSNEnv,
				ShadowRequired:       *shadowQueueRequired,
			}, stdout, queue.NewProducer)
			if err != nil {
				return err
			}
			defer func() { _ = producer.Close() }()
		}
		if err := producer.Publish(ctx, *topic, wirePayload); err != nil {
			rec.Status = "publish_failed"
			rec.Error = err.Error()
			writeAuditRecord(stderr, rec)
			return err
		}
		rec.Status = "published"
		writeAuditRecord(stderr, rec)
	}
	return nil
}

type queueProducerFactory func(queue.ProducerConfig) (queue.Producer, error)

type queuePublishProducerOptions struct {
	Driver               string
	Brokers              string
	PostgresDSN          string
	PostgresDSNEnv       string
	ShadowDriver         string
	ShadowBrokers        string
	ShadowPostgresDSN    string
	ShadowPostgresDSNEnv string
	ShadowRequired       bool
}

func validateQueuePublishConfig(driver, brokers, postgresDSN, postgresDSNEnv string, dryRun bool) error {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "", queue.DriverKafka:
		if len(queue.SplitCommaList(brokers)) == 0 {
			return errors.New("--queue-brokers is required when --queue-driver=kafka")
		}
	case queue.DriverPostgres:
		if dryRun {
			return nil
		}
		if _, err := pgxpoolutil.ResolveDSN(postgresDSN, postgresDSNEnv); err != nil {
			return err
		}
	case queue.DriverStdio:
		return nil
	default:
		return fmt.Errorf("unsupported queue driver %q", driver)
	}
	return nil
}

func validateShadowQueuePublishConfig(driver, brokers, postgresDSN, postgresDSNEnv string, required bool) error {
	normalizedDriver := strings.ToLower(strings.TrimSpace(driver))
	if normalizedDriver == "" {
		if required {
			return errors.New("--shadow-queue-required requires --shadow-queue-driver")
		}
		return nil
	}
	switch normalizedDriver {
	case queue.DriverKafka, queue.DriverPostgres, queue.DriverStdio:
	default:
		return fmt.Errorf("unsupported shadow queue driver %q", driver)
	}
	if !required {
		return nil
	}
	if err := validateQueuePublishConfig(driver, brokers, postgresDSN, postgresDSNEnv, false); err != nil {
		return fmt.Errorf("shadow queue: %w", err)
	}
	return nil
}

func queuePublishProducer(opts queuePublishProducerOptions, stdout io.Writer, factory queueProducerFactory) (queue.Producer, error) {
	if factory == nil {
		factory = queue.NewProducer
	}
	primaryCfg, err := producerConfigForQueueDriver(opts.Driver, opts.Brokers, opts.PostgresDSN, opts.PostgresDSNEnv, stdout)
	if err != nil {
		return nil, err
	}
	primary, err := factory(primaryCfg)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(opts.ShadowDriver) == "" {
		return primary, nil
	}

	shadowCfg, err := producerConfigForQueueDriver(opts.ShadowDriver, opts.ShadowBrokers, opts.ShadowPostgresDSN, opts.ShadowPostgresDSNEnv, stdout)
	if err != nil {
		if !opts.ShadowRequired {
			return primary, nil
		}
		_ = primary.Close()
		return nil, fmt.Errorf("configure shadow queue producer: %w", err)
	}
	shadow, err := factory(shadowCfg)
	if err != nil {
		if !opts.ShadowRequired {
			return primary, nil
		}
		_ = primary.Close()
		return nil, fmt.Errorf("init shadow queue producer: %w", err)
	}
	producer, err := queue.NewMirrorProducer(primary, shadow, queue.MirrorProducerConfig{RequireShadow: opts.ShadowRequired})
	if err != nil {
		_ = primary.Close()
		_ = shadow.Close()
		return nil, err
	}
	return producer, nil
}

func producerConfigForQueueDriver(driver, brokers, postgresDSN, postgresDSNEnv string, stdout io.Writer) (queue.ProducerConfig, error) {
	cfg := queue.ProducerConfig{
		Driver: strings.TrimSpace(driver),
		Writer: stdout,
	}
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case queue.DriverKafka, "":
		cfg.Driver = queue.DriverKafka
		cfg.Brokers = queue.SplitCommaList(brokers)
	case queue.DriverPostgres:
		resolvedDSN, err := pgxpoolutil.ResolveDSN(postgresDSN, postgresDSNEnv)
		if err != nil {
			return queue.ProducerConfig{}, err
		}
		cfg.Driver = queue.DriverPostgres
		cfg.PostgresDSN = resolvedDSN
	case queue.DriverStdio:
		cfg.Driver = queue.DriverStdio
	default:
		return queue.ProducerConfig{}, fmt.Errorf("unsupported queue driver %q", driver)
	}
	return cfg, nil
}

func loadPayloads(payloadInline string, payloadFiles []string, stdin io.Reader) ([][]byte, error) {
	payloads := make([][]byte, 0, len(payloadFiles)+1)
	if payloadInline != "" {
		payloads = append(payloads, []byte(payloadInline))
	}
	for _, filePath := range payloadFiles {
		b, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read payload file %q: %w", filePath, err)
		}
		payloads = append(payloads, b)
	}
	if len(payloads) > 0 {
		return payloads, nil
	}
	if stdin == nil {
		return nil, errors.New("payload is required via --payload, --payload-file, or stdin")
	}
	b, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin payload: %w", err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, errors.New("payload is required via --payload, --payload-file, or stdin")
	}
	return [][]byte{b}, nil
}

func writeAuditRecord(w io.Writer, rec auditRecord) {
	if w == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(rec)
}

func sha256Hex(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
