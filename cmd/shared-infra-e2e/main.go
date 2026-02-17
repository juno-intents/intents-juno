package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/queue"
)

type config struct {
	PostgresDSN   string
	KafkaBrokers  []string
	TopicPrefix   string
	Timeout       time.Duration
	OutputPath    string
	MaxLineBytes  int
	KafkaMaxBytes int
	AckTimeout    time.Duration
}

type report struct {
	Version        string         `json:"version"`
	GeneratedAtUTC string         `json:"generated_at_utc"`
	DurationMS     int64          `json:"duration_ms"`
	Postgres       postgresReport `json:"postgres"`
	Kafka          kafkaReport    `json:"kafka"`
}

type postgresReport struct {
	Table       string `json:"table"`
	ProbeID     string `json:"probe_id"`
	RoundTripMS int64  `json:"round_trip_ms"`
}

type kafkaReport struct {
	Topic        string `json:"topic"`
	Group        string `json:"group"`
	PayloadBytes int    `json:"payload_bytes"`
	RoundTripMS  int64  `json:"round_trip_ms"`
}

func main() {
	if err := runMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdout io.Writer) error {
	cfg, err := parseArgs(args)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	started := time.Now()
	rep := report{
		Version:        "shared.infra.e2e.v1",
		GeneratedAtUTC: started.UTC().Format(time.RFC3339),
	}

	var pgRep postgresReport
	if err := runWithRetry(ctx, 2*time.Second, func(stepCtx context.Context) error {
		out, err := checkPostgres(stepCtx, cfg)
		if err != nil {
			return err
		}
		pgRep = out
		return nil
	}); err != nil {
		return fmt.Errorf("postgres check: %w", err)
	}
	rep.Postgres = pgRep

	var kRep kafkaReport
	if err := runWithRetry(ctx, 2*time.Second, func(stepCtx context.Context) error {
		out, err := checkKafka(stepCtx, cfg)
		if err != nil {
			return err
		}
		kRep = out
		return nil
	}); err != nil {
		return fmt.Errorf("kafka check: %w", err)
	}
	rep.Kafka = kRep
	rep.DurationMS = time.Since(started).Milliseconds()

	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}

	if cfg.OutputPath == "-" {
		_, err = fmt.Fprintf(stdout, "%s\n", out)
		return err
	}

	if err := os.MkdirAll(filepath.Dir(cfg.OutputPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(cfg.OutputPath, append(out, '\n'), 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "wrote report: %s\n", cfg.OutputPath)
	return err
}

func parseArgs(args []string) (config, error) {
	var cfg config
	var brokersRaw string

	fs := flag.NewFlagSet("shared-infra-e2e", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	fs.StringVar(&cfg.PostgresDSN, "postgres-dsn", "", "Postgres DSN (required)")
	fs.StringVar(&brokersRaw, "kafka-brokers", "", "comma-separated Kafka brokers (required)")
	fs.StringVar(&cfg.TopicPrefix, "topic-prefix", "shared.infra.e2e", "Kafka probe topic prefix")
	fs.DurationVar(&cfg.Timeout, "timeout", 90*time.Second, "overall timeout")
	fs.StringVar(&cfg.OutputPath, "output", "-", "output path or '-' for stdout")
	fs.IntVar(&cfg.MaxLineBytes, "max-line-bytes", 1<<20, "maximum stdin line size")
	fs.IntVar(&cfg.KafkaMaxBytes, "kafka-max-bytes", 10<<20, "maximum Kafka message size")
	fs.DurationVar(&cfg.AckTimeout, "queue-ack-timeout", 5*time.Second, "queue ack timeout")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.PostgresDSN = strings.TrimSpace(cfg.PostgresDSN)
	if cfg.PostgresDSN == "" {
		return cfg, errors.New("--postgres-dsn is required")
	}

	cfg.KafkaBrokers = parseBrokers(brokersRaw)
	if len(cfg.KafkaBrokers) == 0 {
		return cfg, errors.New("--kafka-brokers is required")
	}

	cfg.TopicPrefix = strings.TrimSpace(cfg.TopicPrefix)
	if cfg.TopicPrefix == "" {
		return cfg, errors.New("--topic-prefix must not be empty")
	}
	if cfg.Timeout <= 0 {
		return cfg, errors.New("--timeout must be > 0")
	}
	if cfg.MaxLineBytes <= 0 {
		return cfg, errors.New("--max-line-bytes must be > 0")
	}
	if cfg.KafkaMaxBytes <= 0 {
		return cfg, errors.New("--kafka-max-bytes must be > 0")
	}
	if cfg.AckTimeout <= 0 {
		return cfg, errors.New("--queue-ack-timeout must be > 0")
	}

	return cfg, nil
}

func parseBrokers(raw string) []string {
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func runWithRetry(ctx context.Context, interval time.Duration, fn func(context.Context) error) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	var lastErr error
	for {
		if err := fn(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			if lastErr == nil {
				return ctx.Err()
			}
			return fmt.Errorf("%w (last error: %v)", ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}

func checkPostgres(ctx context.Context, cfg config) (postgresReport, error) {
	const probeTable = "infra_e2e_probe"
	pool, err := pgxpool.New(ctx, cfg.PostgresDSN)
	if err != nil {
		return postgresReport{}, fmt.Errorf("new pool: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return postgresReport{}, fmt.Errorf("ping: %w", err)
	}

	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS infra_e2e_probe (
			id TEXT PRIMARY KEY,
			value TEXT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`); err != nil {
		return postgresReport{}, fmt.Errorf("ensure table: %w", err)
	}

	probeID := uuid.NewString()
	probeValue := fmt.Sprintf("probe-%d", time.Now().UTC().UnixNano())

	start := time.Now()
	if _, err := pool.Exec(ctx, `INSERT INTO infra_e2e_probe(id, value) VALUES ($1, $2)`, probeID, probeValue); err != nil {
		return postgresReport{}, fmt.Errorf("insert: %w", err)
	}
	var got string
	if err := pool.QueryRow(ctx, `SELECT value FROM infra_e2e_probe WHERE id = $1`, probeID).Scan(&got); err != nil {
		return postgresReport{}, fmt.Errorf("select: %w", err)
	}
	if got != probeValue {
		return postgresReport{}, fmt.Errorf("value mismatch: got=%q want=%q", got, probeValue)
	}
	_, _ = pool.Exec(ctx, `DELETE FROM infra_e2e_probe WHERE id = $1`, probeID)

	return postgresReport{
		Table:       probeTable,
		ProbeID:     probeID,
		RoundTripMS: time.Since(start).Milliseconds(),
	}, nil
}

func checkKafka(ctx context.Context, cfg config) (kafkaReport, error) {
	topic := fmt.Sprintf("%s.%d", cfg.TopicPrefix, time.Now().UTC().UnixNano())
	group := fmt.Sprintf("%s.group.%s", cfg.TopicPrefix, uuid.NewString())
	payload := []byte(fmt.Sprintf(`{"version":"shared.infra.e2e.kafka.v1","time":"%s"}`,
		time.Now().UTC().Format(time.RFC3339Nano),
	))

	producer, err := queue.NewProducer(queue.ProducerConfig{
		Driver:  queue.DriverKafka,
		Brokers: cfg.KafkaBrokers,
	})
	if err != nil {
		return kafkaReport{}, fmt.Errorf("new producer: %w", err)
	}
	defer func() { _ = producer.Close() }()

	consumer, err := queue.NewConsumer(ctx, queue.ConsumerConfig{
		Driver:        queue.DriverKafka,
		Brokers:       cfg.KafkaBrokers,
		Group:         group,
		Topics:        []string{topic},
		KafkaMaxBytes: cfg.KafkaMaxBytes,
		MaxLineBytes:  cfg.MaxLineBytes,
	})
	if err != nil {
		return kafkaReport{}, fmt.Errorf("new consumer: %w", err)
	}
	defer func() { _ = consumer.Close() }()

	start := time.Now()
	if err := producer.Publish(ctx, topic, payload); err != nil {
		return kafkaReport{}, fmt.Errorf("publish: %w", err)
	}

	msgCh := consumer.Messages()
	errCh := consumer.Errors()
	for {
		select {
		case <-ctx.Done():
			return kafkaReport{}, ctx.Err()
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if err != nil {
				return kafkaReport{}, fmt.Errorf("consume error: %w", err)
			}
		case msg, ok := <-msgCh:
			if !ok {
				return kafkaReport{}, errors.New("consumer closed before receiving probe payload")
			}
			if msg.Topic != topic {
				ackCtx, ackCancel := context.WithTimeout(context.Background(), cfg.AckTimeout)
				_ = msg.Ack(ackCtx)
				ackCancel()
				continue
			}
			if string(msg.Value) != string(payload) {
				return kafkaReport{}, fmt.Errorf("payload mismatch on topic %s", topic)
			}
			ackCtx, ackCancel := context.WithTimeout(context.Background(), cfg.AckTimeout)
			err = msg.Ack(ackCtx)
			ackCancel()
			if err != nil {
				return kafkaReport{}, fmt.Errorf("ack: %w", err)
			}

			return kafkaReport{
				Topic:        topic,
				Group:        group,
				PayloadBytes: len(payload),
				RoundTripMS:  time.Since(start).Milliseconds(),
			}, nil
		}
	}
}
