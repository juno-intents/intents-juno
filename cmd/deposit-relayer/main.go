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

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/deposit"
	depositpg "github.com/juno-intents/intents-juno/internal/deposit/postgres"
	"github.com/juno-intents/intents-juno/internal/depositrelayer"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/proofclient"
	"github.com/juno-intents/intents-juno/internal/queue"
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

type depositEventV1 struct {
	Version          string `json:"version"`
	CM               string `json:"cm"`
	LeafIndex        uint64 `json:"leafIndex"`
	Amount           uint64 `json:"amount"`
	Memo             string `json:"memo"`
	ProofWitnessItem string `json:"proofWitnessItem,omitempty"`
}

func main() {
	var (
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required when --store-driver=postgres)")
		storeDriver = flag.String("store-driver", "postgres", "deposit store driver: postgres|memory")

		baseChainID = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required; must fit uint32 for deposit memo domain separation)")
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address (required)")
		operators   = flag.String("operators", "", "comma-separated operator addresses for checkpoint quorum verification (required)")
		threshold   = flag.Int("operator-threshold", 0, "operator signature threshold for checkpoint quorum verification (required)")

		depositImageID = flag.String("deposit-image-id", "", "deposit zkVM image id (bytes32 hex, required)")
		owalletIVK     = flag.String("owallet-ivk", "", "optional 64-byte OWallet IVK hex for binary guest private input mode")

		baseRelayerURL     = flag.String("base-relayer-url", "", "base-relayer HTTP URL (required)")
		baseRelayerAuthEnv = flag.String("base-relayer-auth-env", "BASE_RELAYER_AUTH_TOKEN", "env var containing base-relayer bearer auth token (required)")

		maxItems      = flag.Int("max-items", 25, "maximum items per mint batch")
		maxAge        = flag.Duration("max-age", 3*time.Minute, "maximum batch age before flushing")
		dedupeMax     = flag.Int("dedupe-max", 10_000, "max deposit ids remembered for in-memory dedupe")
		claimTTL      = flag.Duration("claim-ttl", 30*time.Second, "ttl for claimed confirmed deposits")
		owner         = flag.String("owner", "", "unique worker identity used for deposit claim leases (default: hostname-pid)")
		gasLimit      = flag.Uint64("gas-limit", 0, "optional gas limit override; 0 => estimate")
		flushEvery    = flag.Duration("flush-interval", 1*time.Second, "interval for time-based flush checks")
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
		queueGroup    = flag.String("queue-group", "deposit-relayer", "queue consumer group (required for kafka)")
		queueTopics   = flag.String("queue-topics", "deposits.event.v1,checkpoints.packages.v1", "comma-separated queue topics")
		maxLineBytes  = flag.Int("max-line-bytes", 1<<20, "maximum stdin line size for stdio driver (bytes)")
		queueMaxBytes = flag.Int("queue-max-bytes", 10<<20, "maximum kafka message size for consumer reads (bytes)")
		ackTimeout    = flag.Duration("queue-ack-timeout", 5*time.Second, "timeout for queue message acknowledgements")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *baseChainID == 0 || *bridgeAddr == "" || *operators == "" || *threshold <= 0 || *depositImageID == "" || *baseRelayerURL == "" {
		fmt.Fprintln(os.Stderr, "error: --base-chain-id, --bridge-address, --operators, --operator-threshold, --deposit-image-id, and --base-relayer-url are required")
		os.Exit(2)
	}
	if *baseChainID > uint64(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "error: --base-chain-id must fit uint32 (deposit memo uses 4-byte chain id)")
		os.Exit(2)
	}
	if !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	if *maxItems <= 0 || *dedupeMax <= 0 || *maxLineBytes <= 0 || *queueMaxBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-items, --dedupe-max, --max-line-bytes, and --queue-max-bytes must be > 0")
		os.Exit(2)
	}
	if *maxAge <= 0 || *claimTTL <= 0 || *flushEvery <= 0 || *submitTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-age, --claim-ttl, --flush-interval, and --submit-timeout must be > 0")
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

	bridge := common.HexToAddress(*bridgeAddr)
	imageID, err := parseHash32Strict(*depositImageID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --deposit-image-id: %v\n", err)
		os.Exit(2)
	}
	owalletIVKBytes, err := decodeHexBytesOptional(*owalletIVK)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --owallet-ivk: %v\n", err)
		os.Exit(2)
	}
	if n := len(owalletIVKBytes); n != 0 && n != 64 {
		fmt.Fprintf(os.Stderr, "error: --owallet-ivk must be 64 bytes when set, got %d\n", n)
		os.Exit(2)
	}
	operatorAddrs, err := checkpoint.ParseOperatorAddressesCSV(*operators)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --operators: %v\n", err)
		os.Exit(2)
	}
	workerOwner := strings.TrimSpace(*owner)
	if workerOwner == "" {
		host, err := os.Hostname()
		if err != nil || strings.TrimSpace(host) == "" {
			host = "deposit-relayer"
		}
		workerOwner = fmt.Sprintf("%s-%d", host, os.Getpid())
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

	var (
		pool  *pgxpool.Pool
		store deposit.Store
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

		pgStore, err := depositpg.New(pool)
		if err != nil {
			log.Error("init deposit store", "err", err)
			os.Exit(2)
		}
		if err := pgStore.EnsureSchema(ctx); err != nil {
			log.Error("ensure deposit schema", "err", err)
			os.Exit(2)
		}
		store = pgStore
	case "memory":
		store = deposit.NewMemoryStore()
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported --store-driver %q\n", *storeDriver)
		os.Exit(2)
	}

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
		driver:            *proofDriver,
		queueDriver:       *queueDriver,
		queueBrokers:      queue.SplitCommaList(*queueBrokers),
		proofRequestTopic: *proofRequestTopic,
		proofResultTopic:  *proofResultTopic,
		proofFailureTopic: *proofFailureTopic,
		proofGroup:        *proofResponseGroup,
		maxLineBytes:      *maxLineBytes,
		queueMaxBytes:     *queueMaxBytes,
		ackTimeout:        *ackTimeout,
		mockSeal:          *proofMockSeal,
		log:               log,
	})
	if err != nil {
		log.Error("init proof client", "err", err)
		os.Exit(2)
	}
	defer proofCleanup()

	relayer, err := depositrelayer.New(depositrelayer.Config{
		BaseChainID:         uint32(*baseChainID),
		BridgeAddress:       bridge,
		DepositImageID:      imageID,
		OperatorAddresses:   operatorAddrs,
		OperatorThreshold:   *threshold,
		MaxItems:            *maxItems,
		MaxAge:              *maxAge,
		DedupeMax:           *dedupeMax,
		Owner:               workerOwner,
		ClaimTTL:            *claimTTL,
		GasLimit:            *gasLimit,
		ProofRequestTimeout: *submitTimeout,
		ProofPriority:       *proofPriority,
		Now:                 time.Now,
		OWalletIVKBytes:     owalletIVKBytes,
	}, store, baseClient, proofRequester, log)
	if err != nil {
		log.Error("init deposit relayer", "err", err)
		os.Exit(2)
	}

	log.Info("deposit relayer started",
		"baseChainID", *baseChainID,
		"bridge", bridge,
		"proofDriver", *proofDriver,
		"proofRequestTopic", *proofRequestTopic,
		"proofResultTopic", *proofResultTopic,
		"proofFailureTopic", *proofFailureTopic,
		"maxItems", *maxItems,
		"maxAge", maxAge.String(),
		"claimTTL", claimTTL.String(),
		"owner", workerOwner,
		"flushInterval", flushEvery.String(),
		"queueDriver", *queueDriver,
		"storeDriver", strings.ToLower(strings.TrimSpace(*storeDriver)),
	)

	t := time.NewTicker(*flushEvery)
	defer t.Stop()
	msgCh := consumer.Messages()
	errCh := consumer.Errors()

	for {
		select {
		case <-ctx.Done():
			log.Info("shutdown", "reason", ctx.Err())
			// Use a fresh context so we can flush a final batch even though ctx is already canceled.
			cctx, cancel := withTimeout(context.Background(), *submitTimeout)
			_ = relayer.Flush(cctx)
			cancel()
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
			cctx, cancel := withTimeout(ctx, *submitTimeout)
			err := relayer.FlushDue(cctx)
			cancel()
			if err != nil {
				log.Error("flush due", "err", err)
			}
		case qmsg, ok := <-msgCh:
			if !ok {
				// Input stream closed (stdio EOF or consumer shutdown): flush any remaining and exit.
				cctx, cancel := withTimeout(context.Background(), *submitTimeout)
				_ = relayer.Flush(cctx)
				cancel()
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
				if sigs == nil || len(sigs) == 0 {
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}

				cctx, cancel := withTimeout(ctx, *submitTimeout)
				err = relayer.IngestCheckpoint(cctx, depositrelayer.CheckpointPackage{
					Checkpoint:         cpMsg.Checkpoint,
					OperatorSignatures: sigs,
				})
				cancel()
				if err != nil {
					log.Error("ingest checkpoint", "err", err)
				}
				ackMessage(qmsg, *ackTimeout, log)

			case "deposits.event.v1":
				var depMsg depositEventV1
				if err := json.Unmarshal(line, &depMsg); err != nil {
					log.Error("parse deposit event", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				if depMsg.Version != "deposits.event.v1" {
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				cm, err := parseHash32Strict(depMsg.CM)
				if err != nil {
					log.Error("parse cm", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				memoBytes, err := decodeHexBytes(depMsg.Memo)
				if err != nil {
					log.Error("parse memo", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				proofWitnessItem, err := decodeHexBytesOptional(depMsg.ProofWitnessItem)
				if err != nil {
					log.Error("parse proofWitnessItem", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}

				cctx, cancel := withTimeout(ctx, *submitTimeout)
				err = relayer.IngestDeposit(cctx, depositrelayer.DepositEvent{
					Commitment:       cm,
					LeafIndex:        depMsg.LeafIndex,
					Amount:           depMsg.Amount,
					Memo:             memoBytes,
					ProofWitnessItem: proofWitnessItem,
				})
				cancel()
				if err != nil {
					log.Error("ingest deposit", "err", err)
				}
				ackMessage(qmsg, *ackTimeout, log)
			default:
				ackMessage(qmsg, *ackTimeout, log)
				continue
			}
		}
	}
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

func ackMessage(msg queue.Message, timeout time.Duration, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := msg.Ack(ctx); err != nil {
		log.Error("ack queue message", "topic", msg.Topic, "err", err)
	}
}

type initProofClientConfig struct {
	driver            string
	queueDriver       string
	queueBrokers      []string
	proofRequestTopic string
	proofResultTopic  string
	proofFailureTopic string
	proofGroup        string
	maxLineBytes      int
	queueMaxBytes     int
	ackTimeout        time.Duration
	mockSeal          string
	log               *slog.Logger
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
			group = "deposit-relayer-proof-" + hostname
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

func parseHash32Strict(s string) (common.Hash, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return common.Hash{}, fmt.Errorf("expected 32-byte hex, got len %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return common.Hash{}, fmt.Errorf("decode hex: %w", err)
	}
	var out common.Hash
	copy(out[:], b)
	return out, nil
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
