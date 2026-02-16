package main

import (
	"context"
	"encoding/json"
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
	"github.com/juno-intents/intents-juno/internal/leases"
	leasespg "github.com/juno-intents/intents-juno/internal/leases/postgres"
	"github.com/juno-intents/intents-juno/internal/prooffunder"
	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/juno-intents/intents-juno/internal/secrets"
)

func main() {
	var (
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")
		leaseDriver = flag.String("lease-driver", "postgres", "lease driver: postgres|memory")
		ownerID     = flag.String("owner-id", "", "unique funder instance id (required)")
		leaseName   = flag.String("lease-name", "proof-funder", "lease name for active/passive funder")
		leaseTTL    = flag.Duration("lease-ttl", 15*time.Second, "lease TTL")

		ownerAddress      = flag.String("owner-address", "", "centralized funder owner address (required)")
		ownerKeySecretARN = flag.String("owner-key-secret-arn", "", "secret reference for centralized funder private key (required)")
		ownerKeyEnv       = flag.String("owner-key-env", "PROOF_FUNDER_KEY", "env var name used when --secrets-driver=env")
		secretsDriver     = flag.String("secrets-driver", "aws", "secrets driver: aws|env")

		requestorAddress = flag.String("requestor-address", "", "shared requestor address to fund (required)")
		checkInterval    = flag.Duration("check-interval", 30*time.Second, "requestor balance check interval")

		minBalanceWei      = flag.String("min-balance-wei", "50000000000000000", "minimum requestor balance before topup")
		targetBalanceWei   = flag.String("target-balance-wei", "200000000000000000", "target requestor balance after topup")
		criticalBalanceWei = flag.String("critical-balance-wei", "10000000000000000", "critical low-balance alert threshold")
		maxTopUpPerTxWei   = flag.String("max-topup-per-tx-wei", "200000000000000000", "maximum topup per transaction")

		alertTopic = flag.String("alert-topic", "ops.alerts.v1", "critical alert topic")

		queueDriver  = flag.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
		queueBrokers = flag.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")

		boundlessBin          = flag.String("boundless-bin", "", "boundless submit/funding binary path (required)")
		boundlessMaxRespBytes = flag.Int("boundless-max-response-bytes", 1<<20, "max response bytes from boundless binary")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if *ownerID == "" || *ownerAddress == "" || *ownerKeySecretARN == "" || *requestorAddress == "" || *boundlessBin == "" {
		fmt.Fprintln(os.Stderr, "error: --owner-id, --owner-address, --owner-key-secret-arn, --requestor-address, and --boundless-bin are required")
		os.Exit(2)
	}
	if *leaseTTL <= 0 || *checkInterval <= 0 || *boundlessMaxRespBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --lease-ttl, --check-interval, and --boundless-max-response-bytes must be > 0")
		os.Exit(2)
	}
	if !common.IsHexAddress(*ownerAddress) || !common.IsHexAddress(*requestorAddress) {
		fmt.Fprintln(os.Stderr, "error: --owner-address and --requestor-address must be valid hex addresses")
		os.Exit(2)
	}

	minBalance, err := parseBigInt(*minBalanceWei)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --min-balance-wei: %v\n", err)
		os.Exit(2)
	}
	targetBalance, err := parseBigInt(*targetBalanceWei)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --target-balance-wei: %v\n", err)
		os.Exit(2)
	}
	criticalBalance, err := parseBigInt(*criticalBalanceWei)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --critical-balance-wei: %v\n", err)
		os.Exit(2)
	}
	maxTopup, err := parseBigInt(*maxTopUpPerTxWei)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: --max-topup-per-tx-wei: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	secretProvider, err := newSecretProvider(ctx, *secretsDriver)
	if err != nil {
		log.Error("init secrets provider", "err", err)
		os.Exit(2)
	}
	secretRef := *ownerKeySecretARN
	if strings.EqualFold(strings.TrimSpace(*secretsDriver), "env") {
		secretRef = *ownerKeyEnv
	}
	ownerPrivateKey, err := secretProvider.Get(ctx, secretRef)
	if err != nil {
		log.Error("load owner private key", "err", err, "ref", secretRef)
		os.Exit(2)
	}

	var leaseStore leases.Store
	switch strings.ToLower(strings.TrimSpace(*leaseDriver)) {
	case "postgres":
		if *postgresDSN == "" {
			fmt.Fprintln(os.Stderr, "error: --postgres-dsn is required when --lease-driver=postgres")
			os.Exit(2)
		}
		pool, err := pgxpool.New(ctx, *postgresDSN)
		if err != nil {
			log.Error("init pgx pool", "err", err)
			os.Exit(2)
		}
		defer pool.Close()

		pgLeaseStore, err := leasespg.New(pool)
		if err != nil {
			log.Error("init lease store", "err", err)
			os.Exit(2)
		}
		if err := pgLeaseStore.EnsureSchema(ctx); err != nil {
			log.Error("ensure lease schema", "err", err)
			os.Exit(2)
		}
		leaseStore = pgLeaseStore
	case "memory":
		leaseStore = leases.NewMemoryStore(time.Now)
	default:
		fmt.Fprintf(os.Stderr, "error: unsupported --lease-driver %q\n", *leaseDriver)
		os.Exit(2)
	}

	boundlessClient, err := boundless.NewExecClient(boundless.ExecClientConfig{
		Binary:           *boundlessBin,
		MaxResponseBytes: *boundlessMaxRespBytes,
		OwnerAddress:     common.HexToAddress(*ownerAddress),
		OwnerPrivateKey:  ownerPrivateKey,
	})
	if err != nil {
		log.Error("init boundless exec client", "err", err)
		os.Exit(2)
	}

	alertProducer, err := queue.NewProducer(queue.ProducerConfig{
		Driver:  *queueDriver,
		Brokers: queue.SplitCommaList(*queueBrokers),
	})
	if err != nil {
		log.Error("init alert producer", "err", err)
		os.Exit(2)
	}
	defer func() { _ = alertProducer.Close() }()

	service, err := prooffunder.New(prooffunder.Config{
		LeaseName:          *leaseName,
		LeaseTTL:           *leaseTTL,
		CheckInterval:      *checkInterval,
		OwnerAddress:       common.HexToAddress(*ownerAddress),
		RequestorAddress:   common.HexToAddress(*requestorAddress),
		MinBalanceWei:      minBalance,
		TargetBalanceWei:   targetBalance,
		CriticalBalanceWei: criticalBalance,
		MaxTopUpPerTxWei:   maxTopup,
	}, *ownerID, leaseStore, boundlessClient, &queueAlerter{
		topic:    *alertTopic,
		producer: alertProducer,
		log:      log,
	})
	if err != nil {
		log.Error("init proof funder service", "err", err)
		os.Exit(2)
	}
	service.WithLogger(log)

	log.Info("proof-funder started",
		"owner_id", *ownerID,
		"lease_name", *leaseName,
		"check_interval", checkInterval.String(),
		"owner_address", *ownerAddress,
		"requestor_address", *requestorAddress,
		"min_balance_wei", minBalance.String(),
		"target_balance_wei", targetBalance.String(),
		"critical_balance_wei", criticalBalance.String(),
		"max_topup_per_tx_wei", maxTopup.String(),
		"alert_topic", *alertTopic,
	)

	ticker := time.NewTicker(*checkInterval)
	defer ticker.Stop()

	_ = service.Tick(ctx)
	for {
		select {
		case <-ctx.Done():
			log.Info("shutdown", "reason", ctx.Err())
			return
		case <-ticker.C:
			if err := service.Tick(ctx); err != nil {
				log.Error("proof-funder tick", "err", err)
			}
		}
	}
}

type queueAlerter struct {
	topic    string
	producer queue.Producer
	log      *slog.Logger
}

func (a *queueAlerter) EmitCritical(ctx context.Context, message string, fields map[string]string) error {
	if a == nil || a.producer == nil {
		return nil
	}
	payload, err := json.Marshal(map[string]any{
		"version":  "ops.alert.v1",
		"severity": "critical",
		"message":  message,
		"fields":   fields,
		"time":     time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	if err := a.producer.Publish(ctx, a.topic, payload); err != nil {
		return err
	}
	a.log.Warn("critical alert emitted", "topic", a.topic, "message", message)
	return nil
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
	if out.Sign() <= 0 {
		return nil, fmt.Errorf("must be > 0")
	}
	return out, nil
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
