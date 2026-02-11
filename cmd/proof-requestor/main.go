package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/boundless"
	"github.com/juno-intents/intents-juno/internal/proof"
	"github.com/juno-intents/intents-juno/internal/proof/postgres"
	"github.com/juno-intents/intents-juno/internal/proofrequestor"
	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/juno-intents/intents-juno/internal/secrets"
)

func main() {
	var (
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")
		storeDriver = flag.String("store-driver", "postgres", "store driver: postgres|memory")
		owner       = flag.String("owner", "", "unique requestor instance id (required)")

		requestorAddress      = flag.String("requestor-address", "", "shared requestor EVM address (required)")
		requestorKeySecretARN = flag.String("requestor-key-secret-arn", "", "secret key reference for requestor private key (required)")
		requestorKeyEnv       = flag.String("requestor-key-env", "PROOF_REQUESTOR_KEY", "env var name used when --secrets-driver=env")
		secretsDriver         = flag.String("secrets-driver", "aws", "secrets driver: aws|env")

		submissionMode      = flag.String("submission-mode", boundless.SubmissionModeOffchainPrimaryOnchainFallback, "submission mode")
		orderStreamURL      = flag.String("order-stream-url", "", "Boundless offchain order stream URL")
		boundlessMarketAddr = flag.String("boundless-market-address", "", "Boundless market contract address")
		chainID             = flag.Uint64("chain-id", 0, "boundless chain id (required)")

		inputTopic   = flag.String("input-topic", "proof.requests.v1", "proof request input topic")
		resultTopic  = flag.String("result-topic", "proof.fulfillments.v1", "proof fulfillment output topic")
		failureTopic = flag.String("failure-topic", "proof.failures.v1", "proof failure output topic")

		maxInflight = flag.Int("max-inflight-requests", 2000, "maximum concurrent in-flight proof jobs")
		pollEvery   = flag.Duration("poll-interval", 2*time.Second, "poll interval")
		reqTimeout  = flag.Duration("request-timeout", 15*time.Minute, "per request timeout")
		callbackTTL = flag.Duration("callback-idempotency-ttl", 72*time.Hour, "callback idempotency ttl")

		onchainFallbackEnabled  = flag.Bool("onchain-fallback-enabled", true, "enable onchain fallback submission")
		onchainFundingMode      = flag.String("onchain-funding-mode", boundless.FundingModeMinMaxBalance, "onchain fallback funding mode")
		onchainMinBalanceWei    = flag.String("onchain-min-balance-wei", "50000000000000000", "onchain fallback min balance (wei)")
		onchainTargetBalanceWei = flag.String("onchain-target-balance-wei", "500000000000000000", "onchain fallback target balance (wei)")
		onchainMaxPriceWei      = flag.String("onchain-max-price-per-proof-wei", "2000000000000000", "onchain fallback max price per proof (wei)")
		onchainMaxStakeWei      = flag.String("onchain-max-stake-per-proof-wei", "1000000000000000", "onchain fallback max stake per proof (wei)")

		queueDriver   = flag.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
		queueBrokers  = flag.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")
		queueGroup    = flag.String("queue-group", "proof-requestor", "queue consumer group")
		maxLineBytes  = flag.Int("max-line-bytes", 1<<20, "max stdin line bytes for stdio driver")
		queueMaxBytes = flag.Int("queue-max-bytes", 10<<20, "max kafka message size to consume")
		ackTimeout    = flag.Duration("queue-ack-timeout", 5*time.Second, "queue message ack timeout")

		boundlessBin          = flag.String("boundless-bin", "", "boundless submit/funding binary path (required)")
		boundlessMaxRespBytes = flag.Int("boundless-max-response-bytes", 1<<20, "max response bytes from boundless binary")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *owner == "" || *requestorAddress == "" || *requestorKeySecretARN == "" || *chainID == 0 || *boundlessBin == "" {
		fmt.Fprintln(os.Stderr, "error: --owner, --requestor-address, --requestor-key-secret-arn, --chain-id, and --boundless-bin are required")
		os.Exit(2)
	}
	if *maxInflight <= 0 || *maxLineBytes <= 0 || *queueMaxBytes <= 0 || *boundlessMaxRespBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-inflight-requests, --max-line-bytes, --queue-max-bytes, and --boundless-max-response-bytes must be > 0")
		os.Exit(2)
	}
	if *ackTimeout <= 0 || *reqTimeout <= 0 || *pollEvery <= 0 || *callbackTTL <= 0 {
		fmt.Fprintln(os.Stderr, "error: timeout/interval values must be > 0")
		os.Exit(2)
	}
	if !common.IsHexAddress(*requestorAddress) {
		fmt.Fprintln(os.Stderr, "error: --requestor-address must be a valid hex address")
		os.Exit(2)
	}
	marketAddress := common.Address{}
	if strings.TrimSpace(*boundlessMarketAddr) != "" {
		if !common.IsHexAddress(*boundlessMarketAddr) {
			fmt.Fprintln(os.Stderr, "error: --boundless-market-address must be a valid hex address")
			os.Exit(2)
		}
		marketAddress = common.HexToAddress(*boundlessMarketAddr)
	}
	onchainMin, err := parseBigInt(*onchainMinBalanceWei)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --onchain-min-balance-wei: %v\n", err)
		os.Exit(2)
	}
	onchainTarget, err := parseBigInt(*onchainTargetBalanceWei)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --onchain-target-balance-wei: %v\n", err)
		os.Exit(2)
	}
	onchainMaxPrice, err := parseBigInt(*onchainMaxPriceWei)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --onchain-max-price-per-proof-wei: %v\n", err)
		os.Exit(2)
	}
	onchainMaxStake, err := parseBigInt(*onchainMaxStakeWei)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --onchain-max-stake-per-proof-wei: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	secretProvider, err := newSecretProvider(ctx, *secretsDriver)
	if err != nil {
		log.Error("init secrets provider", "err", err)
		os.Exit(2)
	}
	secretRef := *requestorKeySecretARN
	if strings.EqualFold(strings.TrimSpace(*secretsDriver), "env") {
		secretRef = *requestorKeyEnv
	}
	requestorPrivateKey, err := secretProvider.Get(ctx, secretRef)
	if err != nil {
		log.Error("load requestor private key", "err", err, "ref", secretRef)
		os.Exit(2)
	}

	consumer, err := queue.NewConsumer(ctx, queue.ConsumerConfig{
		Driver:        *queueDriver,
		Brokers:       queue.SplitCommaList(*queueBrokers),
		Group:         *queueGroup,
		Topics:        []string{*inputTopic},
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

	var store proof.Store
	switch strings.ToLower(strings.TrimSpace(*storeDriver)) {
	case "postgres":
		if *postgresDSN == "" {
			fmt.Fprintln(os.Stderr, "error: --postgres-dsn is required when --store-driver=postgres")
			os.Exit(2)
		}
		pool, err := pgxpool.New(ctx, *postgresDSN)
		if err != nil {
			log.Error("init pgx pool", "err", err)
			os.Exit(2)
		}
		defer pool.Close()

		pgStore, err := postgres.New(pool)
		if err != nil {
			log.Error("init proof postgres store", "err", err)
			os.Exit(2)
		}
		if err := pgStore.EnsureSchema(ctx); err != nil {
			log.Error("ensure proof postgres schema", "err", err)
			os.Exit(2)
		}
		store = pgStore
	case "memory":
		store = proof.NewMemoryStore(time.Now)
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported --store-driver %q\n", *storeDriver)
		os.Exit(2)
	}

	boundlessClient, err := boundless.NewExecClient(boundless.ExecClientConfig{
		Binary:           *boundlessBin,
		MaxResponseBytes: *boundlessMaxRespBytes,
	})
	if err != nil {
		log.Error("init boundless exec client", "err", err)
		os.Exit(2)
	}

	svc, err := proofrequestor.New(proofrequestor.Config{
		Owner:                      *owner,
		ChainID:                    *chainID,
		RequestTimeout:             *reqTimeout,
		CallbackIdempotencyTTL:     *callbackTTL,
		RequestorAddress:           common.HexToAddress(*requestorAddress),
		RequestorPrivateKey:        requestorPrivateKey,
		OrderStreamURL:             strings.TrimSpace(*orderStreamURL),
		MarketAddress:              marketAddress,
		SubmissionMode:             *submissionMode,
		OnchainFallbackEnabled:     *onchainFallbackEnabled,
		OnchainFallbackFundingMode: *onchainFundingMode,
		OnchainMinBalanceWei:       onchainMin,
		OnchainTargetBalanceWei:    onchainTarget,
		OnchainMaxPricePerProofWei: onchainMaxPrice,
		OnchainMaxStakePerProofWei: onchainMaxStake,
	}, store, boundlessClient, log)
	if err != nil {
		log.Error("init proof requestor service", "err", err)
		os.Exit(2)
	}

	worker, err := proofrequestor.NewWorker(proofrequestor.WorkerConfig{
		InputTopic:   *inputTopic,
		ResultTopic:  *resultTopic,
		FailureTopic: *failureTopic,
		MaxInflight:  *maxInflight,
		AckTimeout:   *ackTimeout,
	}, svc, consumer, producer, log)
	if err != nil {
		log.Error("init proof requestor worker", "err", err)
		os.Exit(2)
	}

	log.Info("proof-requestor started",
		"owner", *owner,
		"chain_id", *chainID,
		"requestor_address", *requestorAddress,
		"submission_mode", *submissionMode,
		"input_topic", *inputTopic,
		"result_topic", *resultTopic,
		"failure_topic", *failureTopic,
		"max_inflight_requests", *maxInflight,
		"poll_interval", pollEvery.String(),
		"request_timeout", reqTimeout.String(),
		"callback_idempotency_ttl", callbackTTL.String(),
	)

	if err := worker.Run(ctx); err != nil {
		log.Error("proof-requestor exited with error", "err", err)
		os.Exit(1)
	}
}

func newSecretProvider(ctx context.Context, driver string) (secrets.Provider, error) {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "aws":
		return secrets.NewAWS(ctx)
	case "env":
		return secrets.NewEnv(), nil
	default:
		return nil, fmt.Errorf("unsupported secrets driver %q", driver)
	}
}

func parseBigInt(v string) (*big.Int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("empty value")
	}
	out, ok := new(big.Int).SetString(v, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal")
	}
	if out.Sign() < 0 {
		return nil, fmt.Errorf("must be >= 0")
	}
	return out, nil
}
