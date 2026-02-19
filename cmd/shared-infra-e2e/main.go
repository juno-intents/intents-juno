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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/segmentio/kafka-go"
)

type config struct {
	PostgresDSN          string
	KafkaBrokers         []string
	CheckpointIPFSAPIURL string
	TopicPrefix          string
	Timeout              time.Duration
	OutputPath           string
	MaxLineBytes         int
	KafkaMaxBytes        int
	AckTimeout           time.Duration
}

type report struct {
	Version        string           `json:"version"`
	GeneratedAtUTC string           `json:"generated_at_utc"`
	DurationMS     int64            `json:"duration_ms"`
	Postgres       postgresReport   `json:"postgres"`
	Kafka          kafkaReport      `json:"kafka"`
	Checkpoint     checkpointReport `json:"checkpoint"`
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

type checkpointReport struct {
	Digest             string `json:"digest"`
	CID                string `json:"cid"`
	SignerCount        int    `json:"signer_count"`
	Threshold          int    `json:"threshold"`
	PublishRoundTripMS int64  `json:"publish_round_trip_ms"`
	FetchRoundTripMS   int64  `json:"fetch_round_trip_ms"`
}

type checkpointPackageV1 struct {
	Version         string                `json:"version"`
	Digest          common.Hash           `json:"digest"`
	Checkpoint      checkpoint.Checkpoint `json:"checkpoint"`
	OperatorSetHash common.Hash           `json:"operatorSetHash"`
	Signers         []common.Address      `json:"signers"`
	Signatures      []string              `json:"signatures"`
	CreatedAt       time.Time             `json:"createdAt"`
}

var checkpointProbePrivateKeys = []string{
	"4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a",
	"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
	"59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
}

const (
	checkpointProbeThreshold      = 3
	checkpointProbeBaseChainID    = 84532
	checkpointProbeBridgeAddrHex  = "0x000000000000000000000000000000000000bEEF"
	checkpointProbeMaxResponseLen = 1 << 20
)

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

	var cpRep checkpointReport
	if err := runWithRetry(ctx, 2*time.Second, func(stepCtx context.Context) error {
		out, err := checkCheckpointIPFS(stepCtx, cfg)
		if err != nil {
			return err
		}
		cpRep = out
		return nil
	}); err != nil {
		return fmt.Errorf("checkpoint ipfs check: %w", err)
	}
	rep.Checkpoint = cpRep

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
	fs.StringVar(&cfg.CheckpointIPFSAPIURL, "checkpoint-ipfs-api-url", "", "IPFS API URL for checkpoint publish/pin validation (required)")
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
	cfg.CheckpointIPFSAPIURL = strings.TrimSpace(cfg.CheckpointIPFSAPIURL)
	if cfg.CheckpointIPFSAPIURL == "" {
		return cfg, errors.New("--checkpoint-ipfs-api-url is required")
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
	if err := ensureKafkaTopic(ctx, cfg.KafkaBrokers, topic); err != nil {
		return kafkaReport{}, fmt.Errorf("ensure topic: %w", err)
	}

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

func ensureKafkaTopic(ctx context.Context, brokers []string, topic string) error {
	brokers = parseBrokers(strings.Join(brokers, ","))
	if len(brokers) == 0 {
		return errors.New("kafka topic creation requires at least one broker")
	}
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return errors.New("kafka topic is required")
	}

	dialer := &kafka.Dialer{Timeout: 10 * time.Second}
	var lastErr error

	for _, broker := range brokers {
		conn, err := dialer.DialContext(ctx, "tcp", broker)
		if err != nil {
			lastErr = fmt.Errorf("dial broker %s: %w", broker, err)
			continue
		}

		controller, err := conn.Controller()
		_ = conn.Close()
		if err != nil {
			lastErr = fmt.Errorf("lookup controller via %s: %w", broker, err)
			continue
		}

		controllerAddr := fmt.Sprintf("%s:%d", controller.Host, controller.Port)
		controllerConn, err := dialer.DialContext(ctx, "tcp", controllerAddr)
		if err != nil {
			lastErr = fmt.Errorf("dial controller %s: %w", controllerAddr, err)
			continue
		}

		err = controllerConn.CreateTopics(kafka.TopicConfig{
			Topic:             topic,
			NumPartitions:     1,
			ReplicationFactor: 1,
		})
		closeErr := controllerConn.Close()

		if err == nil || isTopicAlreadyExistsError(err) {
			return nil
		}
		if closeErr != nil {
			lastErr = fmt.Errorf("create topic %s via %s: %w (close: %v)", topic, controllerAddr, err, closeErr)
			continue
		}
		lastErr = fmt.Errorf("create topic %s via %s: %w", topic, controllerAddr, err)
	}

	if lastErr == nil {
		lastErr = errors.New("unable to create kafka topic")
	}
	return lastErr
}

func isTopicAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	var kafkaErr kafka.Error
	return errors.As(err, &kafkaErr) && kafkaErr == kafka.TopicAlreadyExists
}

func checkCheckpointIPFS(ctx context.Context, cfg config) (checkpointReport, error) {
	bridge := common.HexToAddress(checkpointProbeBridgeAddrHex)
	now := time.Now().UTC()

	blockHashSeed := sha256.Sum256([]byte("shared.infra.e2e.checkpoint.block." + now.Format(time.RFC3339Nano)))
	orchardRootSeed := sha256.Sum256([]byte("shared.infra.e2e.checkpoint.root." + now.Format(time.RFC3339Nano)))

	cp := checkpoint.Checkpoint{
		Height:           uint64(now.Unix()),
		BlockHash:        common.BytesToHash(blockHashSeed[:]),
		FinalOrchardRoot: common.BytesToHash(orchardRootSeed[:]),
		BaseChainID:      checkpointProbeBaseChainID,
		BridgeContract:   bridge,
	}
	digest := checkpoint.Digest(cp)

	operators := make([]common.Address, 0, len(checkpointProbePrivateKeys))
	signatures := make([][]byte, 0, len(checkpointProbePrivateKeys))
	for _, keyHex := range checkpointProbePrivateKeys {
		key, err := crypto.HexToECDSA(keyHex)
		if err != nil {
			return checkpointReport{}, fmt.Errorf("decode checkpoint probe key: %w", err)
		}
		operator := crypto.PubkeyToAddress(key.PublicKey)
		operators = append(operators, operator)
		sig, err := checkpoint.SignDigest(key, digest)
		if err != nil {
			return checkpointReport{}, fmt.Errorf("sign checkpoint digest: %w", err)
		}
		signatures = append(signatures, sig)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      operators,
		Threshold:      checkpointProbeThreshold,
		MaxOpen:        1,
		MaxEmitted:     8,
		Now:            time.Now,
	})
	if err != nil {
		return checkpointReport{}, fmt.Errorf("init probe aggregator: %w", err)
	}

	var pkg *checkpoint.CheckpointPackageV1
	for i := range operators {
		out, ok, err := agg.AddSignature(checkpoint.SignatureMessageV1{
			Operator:   operators[i],
			Digest:     digest,
			Signature:  signatures[i],
			Checkpoint: cp,
			SignedAt:   now,
		})
		if err != nil {
			return checkpointReport{}, fmt.Errorf("add probe signature: %w", err)
		}
		if ok {
			pkg = out
		}
	}
	if pkg == nil {
		return checkpointReport{}, errors.New("checkpoint probe did not emit package")
	}

	verifier, err := checkpoint.NewQuorumVerifier(operators, checkpointProbeThreshold)
	if err != nil {
		return checkpointReport{}, fmt.Errorf("init probe quorum verifier: %w", err)
	}
	if _, err := verifier.VerifyCheckpointSignatures(cp, pkg.Signatures); err != nil {
		return checkpointReport{}, fmt.Errorf("verify checkpoint signatures: %w", err)
	}

	payloadBody := checkpointPackageV1{
		Version:         "checkpoints.package.v1",
		Digest:          pkg.Digest,
		Checkpoint:      pkg.Checkpoint,
		OperatorSetHash: pkg.OperatorSetHash,
		Signers:         append([]common.Address(nil), pkg.Signers...),
		Signatures:      make([]string, 0, len(pkg.Signatures)),
		CreatedAt:       pkg.CreatedAt.UTC(),
	}
	for _, sig := range pkg.Signatures {
		payloadBody.Signatures = append(payloadBody.Signatures, "0x"+hex.EncodeToString(sig))
	}
	payload, err := json.Marshal(payloadBody)
	if err != nil {
		return checkpointReport{}, fmt.Errorf("marshal checkpoint package payload: %w", err)
	}

	pinner, err := checkpoint.NewHTTPIPFSPinner(checkpoint.HTTPIPFSConfig{
		APIURL: cfg.CheckpointIPFSAPIURL,
	})
	if err != nil {
		return checkpointReport{}, fmt.Errorf("init ipfs pinner: %w", err)
	}
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: checkpoint.NewMemoryPackageStore(),
		IPFSPinner:   pinner,
		Now:          time.Now,
	})
	if err != nil {
		return checkpointReport{}, fmt.Errorf("init package persistence: %w", err)
	}

	publishStarted := time.Now()
	rec, err := persist.Persist(ctx, checkpoint.PackageEnvelope{
		Digest:          payloadBody.Digest,
		Checkpoint:      payloadBody.Checkpoint,
		OperatorSetHash: payloadBody.OperatorSetHash,
		Payload:         payload,
	})
	publishMS := time.Since(publishStarted).Milliseconds()
	if err != nil {
		return checkpointReport{}, fmt.Errorf("persist probe package: %w", err)
	}
	if strings.TrimSpace(rec.IPFSCID) == "" {
		return checkpointReport{}, errors.New("ipfs probe returned empty cid")
	}

	if err := ensureIPFSPin(ctx, cfg.CheckpointIPFSAPIURL, rec.IPFSCID); err != nil {
		return checkpointReport{}, err
	}

	fetchStarted := time.Now()
	gotPayload, err := fetchIPFSPayload(ctx, cfg.CheckpointIPFSAPIURL, rec.IPFSCID)
	fetchMS := time.Since(fetchStarted).Milliseconds()
	if err != nil {
		return checkpointReport{}, err
	}
	if !bytes.Equal(gotPayload, payload) {
		return checkpointReport{}, fmt.Errorf("ipfs payload mismatch: cid=%s", rec.IPFSCID)
	}

	return checkpointReport{
		Digest:             payloadBody.Digest.Hex(),
		CID:                rec.IPFSCID,
		SignerCount:        len(payloadBody.Signers),
		Threshold:          checkpointProbeThreshold,
		PublishRoundTripMS: publishMS,
		FetchRoundTripMS:   fetchMS,
	}, nil
}

func ensureIPFSPin(ctx context.Context, apiURL string, cid string) error {
	cid = strings.TrimSpace(cid)
	if cid == "" {
		return errors.New("ipfs pin probe cid is required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(apiURL), "/") + "/api/v0/pin/ls?arg=" + url.QueryEscape(cid)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return fmt.Errorf("build ipfs pin/ls request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("call ipfs pin/ls: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, checkpointProbeMaxResponseLen))
	if err != nil {
		return fmt.Errorf("read ipfs pin/ls response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ipfs pin/ls failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out struct {
		Keys map[string]json.RawMessage `json:"Keys"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("parse ipfs pin/ls response: %w", err)
	}
	for key := range out.Keys {
		if key == cid {
			return nil
		}
	}
	return fmt.Errorf("ipfs pin/ls missing cid %s", cid)
}

func fetchIPFSPayload(ctx context.Context, apiURL string, cid string) ([]byte, error) {
	cid = strings.TrimSpace(cid)
	if cid == "" {
		return nil, errors.New("ipfs fetch cid is required")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(apiURL), "/") + "/api/v0/cat?arg=" + url.QueryEscape(cid)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build ipfs cat request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("call ipfs cat: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, checkpointProbeMaxResponseLen))
	if err != nil {
		return nil, fmt.Errorf("read ipfs cat response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ipfs cat failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return raw, nil
}
