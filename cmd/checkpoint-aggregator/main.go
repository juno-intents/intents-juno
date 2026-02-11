package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	checkpointpg "github.com/juno-intents/intents-juno/internal/checkpoint/postgres"
	"github.com/juno-intents/intents-juno/internal/queue"
)

type signatureMessageV1 struct {
	Version    string                `json:"version"`
	Operator   common.Address        `json:"operator"`
	Digest     common.Hash           `json:"digest"`
	Signature  string                `json:"signature"`
	Checkpoint checkpoint.Checkpoint `json:"checkpoint"`
	SignedAt   time.Time             `json:"signedAt"`
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
		baseChainID = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address (required)")

		operatorsFlag = flag.String("operators", "", "comma-separated operator addresses (required)")
		thresholdFlag = flag.Int("threshold", 0, "signatures required (required)")

		maxLineBytes = flag.Int("max-line-bytes", 1<<20, "maximum input line size (bytes)")
		maxOpen      = flag.Int("max-open", 4, "maximum distinct checkpoint digests tracked concurrently")
		maxEmitted   = flag.Int("max-emitted", 128, "maximum emitted digests remembered for dedupe")

		postgresDSN    = flag.String("postgres-dsn", "", "Postgres DSN (required when --store-driver=postgres)")
		storeDriver    = flag.String("store-driver", "postgres", "checkpoint package metadata store driver: postgres|memory")
		blobDriver     = flag.String("blob-driver", blobstore.DriverS3, "checkpoint mirror blobstore driver: s3|memory")
		blobBucket     = flag.String("blob-bucket", "", "S3 bucket for checkpoint package mirror (required for s3)")
		blobPrefix     = flag.String("blob-prefix", "checkpoint-packages", "checkpoint package mirror key prefix")
		blobMaxGet     = flag.Int64("blob-max-get-size", 16<<20, "max blob get size in bytes")
		ipfsEnabled    = flag.Bool("ipfs-enabled", true, "enable IPFS pinning for checkpoint packages")
		ipfsAPIURL     = flag.String("ipfs-api-url", "http://127.0.0.1:5001", "IPFS API URL used for package pinning")
		persistTimeout = flag.Duration("persist-timeout", 30*time.Second, "timeout for package persistence (IPFS + blob + db)")

		queueDriver     = flag.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
		queueBrokers    = flag.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")
		queueGroup      = flag.String("queue-group", "checkpoint-aggregator", "queue consumer group (required for kafka)")
		queueInTopics   = flag.String("queue-input-topics", "checkpoints.signatures.v1", "comma-separated queue input topics")
		queueOutTopic   = flag.String("queue-output-topic", "checkpoints.packages.v1", "queue output topic")
		queueMaxBytes   = flag.Int("queue-max-bytes", 10<<20, "maximum kafka message size for consumer reads (bytes)")
		queueAckTimeout = flag.Duration("queue-ack-timeout", 5*time.Second, "timeout for queue message acknowledgements")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *baseChainID == 0 || *bridgeAddr == "" || *operatorsFlag == "" || *thresholdFlag <= 0 {
		fmt.Fprintln(os.Stderr, "error: --base-chain-id, --bridge-address, --operators, and --threshold are required")
		os.Exit(2)
	}
	if !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	if *maxLineBytes <= 0 || *queueMaxBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-line-bytes and --queue-max-bytes must be > 0")
		os.Exit(2)
	}
	if *maxOpen < 0 || *maxEmitted < 0 {
		fmt.Fprintln(os.Stderr, "error: --max-open and --max-emitted must be >= 0")
		os.Exit(2)
	}
	if strings.TrimSpace(*queueOutTopic) == "" {
		fmt.Fprintln(os.Stderr, "error: --queue-output-topic is required")
		os.Exit(2)
	}
	if *queueAckTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: --queue-ack-timeout must be > 0")
		os.Exit(2)
	}
	if *persistTimeout <= 0 || *blobMaxGet <= 0 {
		fmt.Fprintln(os.Stderr, "error: --persist-timeout and --blob-max-get-size must be > 0")
		os.Exit(2)
	}
	if normalizeBlobDriver(*blobDriver) == blobstore.DriverS3 && strings.TrimSpace(*blobBucket) == "" {
		fmt.Fprintln(os.Stderr, "error: --blob-bucket is required when --blob-driver=s3")
		os.Exit(2)
	}
	if *ipfsEnabled && strings.TrimSpace(*ipfsAPIURL) == "" {
		fmt.Fprintln(os.Stderr, "error: --ipfs-api-url is required when --ipfs-enabled=true")
		os.Exit(2)
	}

	bridge := common.HexToAddress(*bridgeAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		packageStore checkpoint.PackageStore
		pool         *pgxpool.Pool
		err          error
	)
	switch strings.ToLower(strings.TrimSpace(*storeDriver)) {
	case "postgres":
		if strings.TrimSpace(*postgresDSN) == "" {
			fmt.Fprintln(os.Stderr, "error: --postgres-dsn is required when --store-driver=postgres")
			os.Exit(2)
		}
		pool, err = pgxpool.New(ctx, *postgresDSN)
		if err != nil {
			log.Error("init pgx pool", "err", err)
			os.Exit(2)
		}
		defer pool.Close()

		pgStore, err := checkpointpg.New(pool)
		if err != nil {
			log.Error("init checkpoint store", "err", err)
			os.Exit(2)
		}
		if err := pgStore.EnsureSchema(ctx); err != nil {
			log.Error("ensure checkpoint store schema", "err", err)
			os.Exit(2)
		}
		packageStore = pgStore
	case "memory":
		packageStore = checkpoint.NewMemoryPackageStore()
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported --store-driver %q\n", *storeDriver)
		os.Exit(2)
	}

	mirrorStore, err := newBlobStore(ctx, *blobDriver, *blobBucket, *blobPrefix, *blobMaxGet)
	if err != nil {
		log.Error("init blob store", "err", err)
		os.Exit(2)
	}

	var pinner checkpoint.IPFSPinner
	if *ipfsEnabled {
		pinner, err = checkpoint.NewHTTPIPFSPinner(checkpoint.HTTPIPFSConfig{
			APIURL: *ipfsAPIURL,
		})
		if err != nil {
			log.Error("init ipfs pinner", "err", err)
			os.Exit(2)
		}
	}

	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: packageStore,
		BlobStore:    mirrorStore,
		BlobPrefix:   "",
		IPFSPinner:   pinner,
		Now:          time.Now,
	})
	if err != nil {
		log.Error("init package persistence", "err", err)
		os.Exit(2)
	}

	consumer, err := queue.NewConsumer(ctx, queue.ConsumerConfig{
		Driver:        *queueDriver,
		Brokers:       queue.SplitCommaList(*queueBrokers),
		Group:         *queueGroup,
		Topics:        queue.SplitCommaList(*queueInTopics),
		KafkaMaxBytes: *queueMaxBytes,
		MaxLineBytes:  *maxLineBytes,
	})
	if err != nil {
		log.Error("init queue consumer", "err", err)
		os.Exit(2)
	}
	defer func() { _ = consumer.Close() }()

	producer, err := queue.NewProducer(queue.ProducerConfig{
		Driver:  *queueDriver,
		Brokers: queue.SplitCommaList(*queueBrokers),
	})
	if err != nil {
		log.Error("init queue producer", "err", err)
		os.Exit(2)
	}
	defer func() { _ = producer.Close() }()

	ops, err := parseOperatorList(*operatorsFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --operators: %v\n", err)
		os.Exit(2)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    *baseChainID,
		BridgeContract: bridge,
		Operators:      ops,
		Threshold:      *thresholdFlag,
		MaxOpen:        *maxOpen,
		MaxEmitted:     *maxEmitted,
		Now:            time.Now,
	})
	if err != nil {
		log.Error("init aggregator", "err", err)
		os.Exit(2)
	}

	log.Info("checkpoint aggregator started",
		"baseChainID", *baseChainID,
		"bridge", bridge,
		"threshold", *thresholdFlag,
		"operators", len(ops),
		"queueDriver", *queueDriver,
		"queueOutTopic", *queueOutTopic,
		"storeDriver", strings.ToLower(strings.TrimSpace(*storeDriver)),
		"blobDriver", normalizeBlobDriver(*blobDriver),
		"blobBucket", strings.TrimSpace(*blobBucket),
		"blobPrefix", strings.TrimSpace(*blobPrefix),
		"ipfsEnabled", *ipfsEnabled,
		"ipfsAPIURL", strings.TrimSpace(*ipfsAPIURL),
	)
	msgCh := consumer.Messages()
	errCh := consumer.Errors()

	for {
		select {
		case err, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if err != nil {
				log.Error("queue consume error", "err", err)
			}
		case msg, ok := <-msgCh:
			if !ok {
				return
			}
			line := bytes.TrimSpace(msg.Value)
			if len(line) == 0 {
				ackMessage(msg, *queueAckTimeout, log)
				continue
			}

			var in signatureMessageV1
			if err := json.Unmarshal(line, &in); err != nil {
				log.Error("parse input json", "err", err)
				ackMessage(msg, *queueAckTimeout, log)
				continue
			}
			if in.Version != "checkpoints.signature.v1" {
				ackMessage(msg, *queueAckTimeout, log)
				continue
			}

			sig, err := decodeHexSignature(in.Signature)
			if err != nil {
				log.Error("decode signature", "err", err)
				ackMessage(msg, *queueAckTimeout, log)
				continue
			}

			pkg, ok, err := agg.AddSignature(checkpoint.SignatureMessageV1{
				Operator:   in.Operator,
				Digest:     in.Digest,
				Signature:  sig,
				Checkpoint: in.Checkpoint,
				SignedAt:   in.SignedAt,
			})
			if err != nil {
				log.Error("add signature", "err", err, "operator", in.Operator, "digest", in.Digest)
				ackMessage(msg, *queueAckTimeout, log)
				continue
			}
			if !ok || pkg == nil {
				ackMessage(msg, *queueAckTimeout, log)
				continue
			}

			out := checkpointPackageV1{
				Version:         "checkpoints.package.v1",
				Digest:          pkg.Digest,
				Checkpoint:      pkg.Checkpoint,
				OperatorSetHash: pkg.OperatorSetHash,
				Signers:         pkg.Signers,
				Signatures:      make([]string, 0, len(pkg.Signatures)),
				CreatedAt:       pkg.CreatedAt.UTC(),
			}
			for _, s := range pkg.Signatures {
				out.Signatures = append(out.Signatures, "0x"+hex.EncodeToString(s))
			}

			payload, err := json.Marshal(out)
			if err != nil {
				log.Error("marshal output", "err", err)
				ackMessage(msg, *queueAckTimeout, log)
				continue
			}
			pctx, pcancel := context.WithTimeout(ctx, *persistTimeout)
			_, err = persist.Persist(pctx, checkpoint.PackageEnvelope{
				Digest:          out.Digest,
				Checkpoint:      out.Checkpoint,
				OperatorSetHash: out.OperatorSetHash,
				Payload:         payload,
			})
			pcancel()
			if err != nil {
				log.Error("persist checkpoint package", "err", err, "digest", out.Digest)
				continue
			}
			if err := producer.Publish(ctx, *queueOutTopic, payload); err != nil {
				log.Error("publish output", "err", err, "topic", *queueOutTopic)
				continue
			}
			ackMessage(msg, *queueAckTimeout, log)
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

func parseOperatorList(s string) ([]common.Address, error) {
	parts := strings.Split(s, ",")
	out := make([]common.Address, 0, len(parts))
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !common.IsHexAddress(p) {
			return nil, fmt.Errorf("bad address at index %d", i)
		}
		out = append(out, common.HexToAddress(p))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty operator list")
	}
	return out, nil
}

func decodeHexSignature(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, fmt.Errorf("empty signature")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex signature")
	}
	return b, nil
}

func normalizeBlobDriver(driver string) string {
	driver = strings.ToLower(strings.TrimSpace(driver))
	if driver == "" {
		return blobstore.DriverS3
	}
	return driver
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
