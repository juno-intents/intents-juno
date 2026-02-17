package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	leasespg "github.com/juno-intents/intents-juno/internal/leases/postgres"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/queue"
	withdrawpg "github.com/juno-intents/intents-juno/internal/withdraw/postgres"
	"github.com/juno-intents/intents-juno/internal/withdrawfinalizer"
)

type envelope struct {
	Version string `json:"version"`
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

func main() {
	var (
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")

		baseChainID     = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		bridgeAddr      = flag.String("bridge-address", "", "Bridge contract address (required)")
		operators       = flag.String("operators", "", "comma-separated operator addresses for checkpoint quorum verification (required)")
		threshold       = flag.Int("operator-threshold", 0, "operator signature threshold for checkpoint quorum verification (required)")
		withdrawImageID = flag.String("withdraw-image-id", "", "withdraw zkVM image id (bytes32 hex, required)")
		owalletOVK      = flag.String("owallet-ovk", "", "optional 32-byte OWallet OVK hex for binary guest private input mode")

		baseRelayerURL     = flag.String("base-relayer-url", "", "base-relayer HTTP URL (required)")
		baseRelayerAuthEnv = flag.String("base-relayer-auth-env", "BASE_RELAYER_AUTH_TOKEN", "env var containing base-relayer bearer auth token (required)")

		owner        = flag.String("owner", "", "unique finalizer owner id (required; used for DB leases)")
		leaseTTL     = flag.Duration("lease-ttl", 30*time.Second, "per-batch lease TTL")
		maxBatches   = flag.Int("max-batches", 10, "maximum batches to finalize per tick")
		tickInterval = flag.Duration("tick-interval", 1*time.Second, "finalizer tick interval")
		gasLimit     = flag.Uint64("gas-limit", 0, "optional gas limit override; 0 => estimate")

		submitTimeout = flag.Duration("submit-timeout", 5*time.Minute, "per-batch timeout (proof request + base-relayer)")

		proofDriver        = flag.String("proof-driver", "queue", "proof client driver: queue|mock")
		proofRequestTopic  = flag.String("proof-request-topic", "proof.requests.v1", "proof request topic")
		proofResultTopic   = flag.String("proof-result-topic", "proof.fulfillments.v1", "proof fulfillment topic")
		proofFailureTopic  = flag.String("proof-failure-topic", "proof.failures.v1", "proof failure topic")
		proofResponseGroup = flag.String("proof-response-group", "", "proof response consumer group (required for kafka when proof-driver=queue)")
		proofPriority      = flag.Int("proof-priority", 1, "proof request priority")
		proofMockSeal      = flag.String("proof-mock-seal", "0x99", "mock proof seal hex used when --proof-driver=mock")

		queueDriver   = flag.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
		queueBrokers  = flag.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")
		queueGroup    = flag.String("queue-group", "withdraw-finalizer", "queue consumer group (required for kafka)")
		queueTopics   = flag.String("queue-topics", "checkpoints.packages.v1", "comma-separated queue topics")
		maxLineBytes  = flag.Int("max-line-bytes", 1<<20, "maximum stdin line size for stdio driver (bytes)")
		queueMaxBytes = flag.Int("queue-max-bytes", 10<<20, "maximum kafka message size for consumer reads (bytes)")
		ackTimeout    = flag.Duration("queue-ack-timeout", 5*time.Second, "timeout for queue message acknowledgements")

		blobDriver     = flag.String("blob-driver", blobstore.DriverS3, "blobstore driver: s3|memory")
		blobBucket     = flag.String("blob-bucket", "", "S3 bucket for durable withdrawal proof artifacts (required for s3)")
		blobPrefix     = flag.String("blob-prefix", "withdraw-finalizer", "blob key prefix")
		blobMaxGetSize = flag.Int64("blob-max-get-size", 16<<20, "max blob get size in bytes")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *postgresDSN == "" || *baseChainID == 0 || *bridgeAddr == "" || *operators == "" || *threshold <= 0 || *withdrawImageID == "" || *baseRelayerURL == "" || *owner == "" {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn, --base-chain-id, --bridge-address, --operators, --operator-threshold, --withdraw-image-id, --base-relayer-url, and --owner are required")
		os.Exit(2)
	}
	if !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	if *leaseTTL <= 0 || *maxBatches <= 0 || *tickInterval <= 0 || *submitTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: durations and --max-batches must be > 0")
		os.Exit(2)
	}
	if *maxLineBytes <= 0 || *queueMaxBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-line-bytes and --queue-max-bytes must be > 0")
		os.Exit(2)
	}
	if *ackTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: --queue-ack-timeout must be > 0")
		os.Exit(2)
	}
	if *proofPriority < 0 {
		fmt.Fprintln(os.Stderr, "error: --proof-priority must be >= 0")
		os.Exit(2)
	}
	if *blobMaxGetSize <= 0 {
		fmt.Fprintln(os.Stderr, "error: --blob-max-get-size must be > 0")
		os.Exit(2)
	}
	if normalizeBlobDriver(*blobDriver) == blobstore.DriverS3 && strings.TrimSpace(*blobBucket) == "" {
		fmt.Fprintln(os.Stderr, "error: --blob-bucket is required when --blob-driver=s3")
		os.Exit(2)
	}

	bridge := common.HexToAddress(*bridgeAddr)
	imageID, err := parseHash32Strict(*withdrawImageID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --withdraw-image-id: %v\n", err)
		os.Exit(2)
	}
	owalletOVKBytes, err := decodeHexBytesOptional(*owalletOVK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --owallet-ovk: %v\n", err)
		os.Exit(2)
	}
	if n := len(owalletOVKBytes); n != 0 && n != 32 {
		fmt.Fprintf(os.Stderr, "error: --owallet-ovk must be 32 bytes when set, got %d\n", n)
		os.Exit(2)
	}
	operatorAddrs, err := checkpoint.ParseOperatorAddressesCSV(*operators)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --operators: %v\n", err)
		os.Exit(2)
	}

	authToken := os.Getenv(*baseRelayerAuthEnv)
	if authToken == "" {
		fmt.Fprintf(os.Stderr, "error: missing base-relayer auth token in env %s\n", *baseRelayerAuthEnv)
		os.Exit(2)
	}

	hc := &http.Client{
		Timeout: *submitTimeout,
	}
	baseClient, err := httpapi.NewClient(*baseRelayerURL, authToken, httpapi.WithHTTPClient(hc))
	if err != nil {
		log.Error("init base-relayer client", "err", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	consumer, err := queue.NewConsumer(ctx, queue.ConsumerConfig{
		Driver:        *queueDriver,
		Brokers:       queue.SplitCommaList(*queueBrokers),
		Group:         *queueGroup,
		Topics:        queue.SplitCommaList(*queueTopics),
		KafkaMaxBytes: *queueMaxBytes,
		MaxLineBytes:  *maxLineBytes,
	})
	if err != nil {
		log.Error("init queue consumer", "err", err)
		os.Exit(2)
	}
	defer func() { _ = consumer.Close() }()

	proofRequester, proofCleanup, err := initProofClient(ctx, initProofClientConfig{
		driver:             *proofDriver,
		queueDriver:        *queueDriver,
		queueBrokers:       queue.SplitCommaList(*queueBrokers),
		proofRequestTopic:  *proofRequestTopic,
		proofResultTopic:   *proofResultTopic,
		proofFailureTopic:  *proofFailureTopic,
		proofGroup:         *proofResponseGroup,
		maxLineBytes:       *maxLineBytes,
		queueMaxBytes:      *queueMaxBytes,
		ackTimeout:         *ackTimeout,
		mockSeal:           *proofMockSeal,
		log:                log,
		defaultGroupPrefix: "withdraw-finalizer-proof-",
	})
	if err != nil {
		log.Error("init proof client", "err", err)
		os.Exit(2)
	}
	defer proofCleanup()

	pool, err := pgxpool.New(ctx, *postgresDSN)
	if err != nil {
		log.Error("init pgx pool", "err", err)
		os.Exit(2)
	}
	defer pool.Close()

	store, err := withdrawpg.New(pool)
	if err != nil {
		log.Error("init withdraw store", "err", err)
		os.Exit(2)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		log.Error("ensure withdraw schema", "err", err)
		os.Exit(2)
	}

	artifactStore, err := newBlobStore(ctx, *blobDriver, *blobBucket, *blobPrefix, *blobMaxGetSize)
	if err != nil {
		log.Error("init blob store", "err", err)
		os.Exit(2)
	}

	leaseStore, err := leasespg.New(pool)
	if err != nil {
		log.Error("init lease store", "err", err)
		os.Exit(2)
	}
	if err := leaseStore.EnsureSchema(ctx); err != nil {
		log.Error("ensure lease schema", "err", err)
		os.Exit(2)
	}

	f, err := withdrawfinalizer.New(withdrawfinalizer.Config{
		Owner:               *owner,
		LeaseTTL:            *leaseTTL,
		MaxBatches:          *maxBatches,
		BaseChainID:         *baseChainID,
		BridgeAddress:       bridge,
		WithdrawImageID:     imageID,
		OperatorAddresses:   operatorAddrs,
		OperatorThreshold:   *threshold,
		GasLimit:            *gasLimit,
		ProofRequestTimeout: *submitTimeout,
		ProofPriority:       *proofPriority,
		OWalletOVKBytes:     owalletOVKBytes,
	}, store, leaseStore, baseClient, proofRequester, log)
	if err != nil {
		log.Error("init withdraw finalizer", "err", err)
		os.Exit(2)
	}
	f.WithBlobStore(artifactStore)

	log.Info("withdraw finalizer started",
		"owner", *owner,
		"baseChainID", *baseChainID,
		"bridge", bridge,
		"proofDriver", *proofDriver,
		"proofRequestTopic", *proofRequestTopic,
		"proofResultTopic", *proofResultTopic,
		"proofFailureTopic", *proofFailureTopic,
		"maxBatches", *maxBatches,
		"leaseTTL", leaseTTL.String(),
		"tickInterval", tickInterval.String(),
		"queueDriver", *queueDriver,
		"blobDriver", normalizeBlobDriver(*blobDriver),
		"blobBucket", strings.TrimSpace(*blobBucket),
		"blobPrefix", strings.TrimSpace(*blobPrefix),
	)

	t := time.NewTicker(*tickInterval)
	defer t.Stop()
	msgCh := consumer.Messages()
	errCh := consumer.Errors()

	for {
		select {
		case <-ctx.Done():
			log.Info("shutdown", "reason", ctx.Err())
			return
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if err != nil {
				log.Error("queue consume error", "err", err)
			}
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, *submitTimeout)
			err := f.Tick(cctx)
			cancel()
			if err != nil {
				log.Error("tick", "err", err)
			}
		case qmsg, ok := <-msgCh:
			if !ok {
				return
			}
			line := qmsg.Value
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				ackMessage(qmsg, *ackTimeout, log)
				continue
			}

			var env envelope
			if err := json.Unmarshal(line, &env); err != nil {
				log.Error("parse input json", "err", err)
				ackMessage(qmsg, *ackTimeout, log)
				continue
			}

			switch env.Version {
			case "checkpoints.package.v1":
				var cpMsg checkpointPackageV1
				if err := json.Unmarshal(line, &cpMsg); err != nil {
					log.Error("parse checkpoint package", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				if cpMsg.Version != "checkpoints.package.v1" {
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				if want := checkpoint.Digest(cpMsg.Checkpoint); cpMsg.Digest != want {
					log.Error("checkpoint digest mismatch", "want", want, "got", cpMsg.Digest)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}

				sigs := make([][]byte, 0, len(cpMsg.Signatures))
				for i, s := range cpMsg.Signatures {
					b, err := decodeHexBytes(s)
					if err != nil {
						log.Error("decode operator signature", "err", err, "index", i)
						sigs = nil
						break
					}
					sigs = append(sigs, b)
				}
				if sigs == nil {
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}

				cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := f.IngestCheckpoint(cctx, withdrawfinalizer.CheckpointPackage{
					Checkpoint:         cpMsg.Checkpoint,
					OperatorSignatures: sigs,
				})
				cancel()
				if err != nil {
					log.Error("ingest checkpoint", "err", err)
				}
				ackMessage(qmsg, *ackTimeout, log)
			default:
				ackMessage(qmsg, *ackTimeout, log)
				continue
			}
		}
	}
}

func ackMessage(msg queue.Message, timeout time.Duration, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := msg.Ack(ctx); err != nil {
		log.Error("ack queue message", "topic", msg.Topic, "err", err)
	}
}

type initProofClientConfig struct {
	driver             string
	queueDriver        string
	queueBrokers       []string
	proofRequestTopic  string
	proofResultTopic   string
	proofFailureTopic  string
	proofGroup         string
	maxLineBytes       int
	queueMaxBytes      int
	ackTimeout         time.Duration
	mockSeal           string
	log                *slog.Logger
	defaultGroupPrefix string
}

func initProofClient(ctx context.Context, cfg initProofClientConfig) (proofclient.Client, func(), error) {
	switch strings.ToLower(strings.TrimSpace(cfg.driver)) {
	case "mock":
		seal, err := decodeHexBytes(cfg.mockSeal)
		if err != nil {
			return nil, func() {}, fmt.Errorf("decode --proof-mock-seal: %w", err)
		}
		return &proofclient.StaticClient{Result: proofclient.Result{Seal: seal}}, func() {}, nil
	case "queue":
		if strings.EqualFold(strings.TrimSpace(cfg.queueDriver), queue.DriverStdio) {
			return nil, func() {}, fmt.Errorf("proof-driver=queue is incompatible with queue-driver=stdio; use --proof-driver=mock for local stdio mode")
		}
		group := strings.TrimSpace(cfg.proofGroup)
		if group == "" {
			hostname, _ := os.Hostname()
			hostname = strings.TrimSpace(hostname)
			if hostname == "" {
				hostname = "local"
			}
			group = cfg.defaultGroupPrefix + hostname
		}

		producer, err := queue.NewProducer(queue.ProducerConfig{
			Driver:  cfg.queueDriver,
			Brokers: cfg.queueBrokers,
		})
		if err != nil {
			return nil, func() {}, err
		}
		consumer, err := queue.NewConsumer(ctx, queue.ConsumerConfig{
			Driver:        cfg.queueDriver,
			Brokers:       cfg.queueBrokers,
			Group:         group,
			Topics:        []string{cfg.proofResultTopic, cfg.proofFailureTopic},
			KafkaMaxBytes: cfg.queueMaxBytes,
			MaxLineBytes:  cfg.maxLineBytes,
		})
		if err != nil {
			_ = producer.Close()
			return nil, func() {}, err
		}
		client, err := proofclient.NewQueueClient(proofclient.QueueConfig{
			RequestTopic: cfg.proofRequestTopic,
			ResultTopic:  cfg.proofResultTopic,
			FailureTopic: cfg.proofFailureTopic,
			Producer:     producer,
			Consumer:     consumer,
			AckTimeout:   cfg.ackTimeout,
			Log:          cfg.log,
		})
		if err != nil {
			_ = producer.Close()
			_ = consumer.Close()
			return nil, func() {}, err
		}
		cleanup := func() {
			_ = consumer.Close()
			_ = producer.Close()
		}
		return client, cleanup, nil
	default:
		return nil, func() {}, fmt.Errorf("unsupported proof driver %q", cfg.driver)
	}
}

func decodeHexBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if s == "" {
		return nil, fmt.Errorf("empty hex")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	return b, nil
}

func decodeHexBytesOptional(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	return b, nil
}

func parseHash32Strict(s string) (common.Hash, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return common.Hash{}, fmt.Errorf("expected 32-byte hex, got len %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode hex: %w", err)
	}
	return common.BytesToHash(b), nil
}

func normalizeBlobDriver(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	if s == "" {
		return blobstore.DriverS3
	}
	return s
}

func newBlobStore(ctx context.Context, driver string, bucket string, prefix string, maxGetSize int64) (blobstore.Store, error) {
	cfg := blobstore.Config{
		Driver:     normalizeBlobDriver(driver),
		Bucket:     strings.TrimSpace(bucket),
		Prefix:     strings.TrimSpace(prefix),
		MaxGetSize: maxGetSize,
	}

	if cfg.Driver == blobstore.DriverS3 {
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("load aws config: %w", err)
		}
		cfg.S3Client = awss3.NewFromConfig(awsCfg)
	}

	return blobstore.New(cfg)
}
