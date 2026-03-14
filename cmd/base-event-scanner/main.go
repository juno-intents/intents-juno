package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/chainscanner"
	"github.com/juno-intents/intents-juno/internal/healthz"
	"github.com/juno-intents/intents-juno/internal/pgxpoolutil"
	"github.com/juno-intents/intents-juno/internal/queue"
)

func main() {
	if err := runMain(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// eventPayload is the JSON envelope published for each WithdrawRequested event.
// Fields match the coordinator's withdrawRequestedV1 struct; extra fields
// (blockNumber, txHash, logIndex) are harmlessly ignored by the coordinator.
type eventPayload struct {
	Version        string `json:"version"`
	WithdrawalID   string `json:"withdrawalId"`
	Requester      string `json:"requester"`
	Amount         uint64 `json:"amount"`
	RecipientUA    string `json:"recipientUA"`
	Expiry         uint64 `json:"expiry"`
	FeeBps         uint32 `json:"feeBps"`
	BlockNumber    uint64 `json:"blockNumber"`
	BlockHash      string `json:"blockHash"`
	TxHash         string `json:"txHash"`
	LogIndex       uint   `json:"logIndex"`
	FinalitySource string `json:"finalitySource"`
}

func runMain(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("base-event-scanner", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	baseRPCURL := fs.String("base-rpc-url", "", "Base chain RPC URL (required)")
	bridgeAddress := fs.String("bridge-address", "", "Bridge contract address (required)")
	postgresDSN := fs.String("postgres-dsn", "", "Postgres DSN (required)")
	postgresMinConns := fs.Int("postgres-min-conns", int(pgxpoolutil.DefaultMinConns), "minimum pgxpool connections")
	postgresMaxConns := fs.Int("postgres-max-conns", int(pgxpoolutil.DefaultMaxConns), "maximum pgxpool connections")
	postgresHealthCheckPeriod := fs.Duration(
		"postgres-health-check-period",
		pgxpoolutil.DefaultHealthCheckPeriod,
		"pgxpool health check period",
	)
	startBlock := fs.Int64("start-block", 0, "starting block number (0 = resume from DB state)")
	pollInterval := fs.Duration("poll-interval", 5*time.Second, "poll interval")
	maxBlocksPerPoll := fs.Int64("max-blocks-per-poll", 1000, "maximum blocks per poll")
	headMode := fs.String("head-mode", chainscanner.HeadModeSafe, "Base head mode: safe|finalized")
	fallbackDepth := fs.Int64("fallback-depth", 64, "fallback confirmation depth when safe/finalized tags are unavailable")

	healthPort := fs.Int("health-port", 0, "HTTP port for /livez, /readyz, and /healthz endpoints (0 = disabled)")

	queueDriver := fs.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
	queueBrokers := fs.String("queue-brokers", "", "comma-separated Kafka broker addresses")
	withdrawEventTopic := fs.String("withdraw-event-topic", "withdrawals.requested.v2", "Kafka topic for withdraw events")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*baseRPCURL) == "" {
		return errors.New("--base-rpc-url is required")
	}
	if !common.IsHexAddress(strings.TrimSpace(*bridgeAddress)) {
		return errors.New("--bridge-address must be a valid hex address")
	}
	if strings.TrimSpace(*postgresDSN) == "" {
		return errors.New("--postgres-dsn is required")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	// Connect to Postgres.
	poolCfg, err := pgxpoolutil.ParseConfig(strings.TrimSpace(*postgresDSN), pgxpoolutil.Settings{
		MinConns:          int32(*postgresMinConns),
		MaxConns:          int32(*postgresMaxConns),
		HealthCheckPeriod: *postgresHealthCheckPeriod,
	})
	if err != nil {
		return fmt.Errorf("parse pgx pool config: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()

	stateStore, err := chainscanner.NewPgStateStore(pool)
	if err != nil {
		return fmt.Errorf("create state store: %w", err)
	}
	if err := stateStore.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("ensure scanner schema: %w", err)
	}

	// Connect to Base RPC.
	client, err := ethclient.DialContext(ctx, strings.TrimSpace(*baseRPCURL))
	if err != nil {
		return fmt.Errorf("dial base rpc: %w", err)
	}
	defer client.Close()

	// Create queue producer.
	producer, err := queue.NewProducer(queue.ProducerConfig{
		Driver:  *queueDriver,
		Brokers: queue.SplitCommaList(*queueBrokers),
		Writer:  stdout,
	})
	if err != nil {
		return fmt.Errorf("create queue producer: %w", err)
	}
	defer func() { _ = producer.Close() }()

	topic := strings.TrimSpace(*withdrawEventTopic)

	scanner, err := chainscanner.NewBaseScanner(chainscanner.BaseScannerConfig{
		Client:           client,
		BridgeAddr:       common.HexToAddress(strings.TrimSpace(*bridgeAddress)),
		StateStore:       stateStore,
		ServiceName:      "base-event-scanner",
		MaxBlocksPerPoll: *maxBlocksPerPoll,
		PollInterval:     *pollInterval,
		HeadMode:         *headMode,
		FallbackDepth:    *fallbackDepth,
	})
	if err != nil {
		return fmt.Errorf("create base scanner: %w", err)
	}

	go func() {
		if err := healthz.ListenAndServe(
			ctx,
			healthz.ListenAddr(*healthPort),
			"base-event-scanner",
			healthz.WithReadinessCheck(pgxpoolutil.ReadinessCheck(pool, pgxpoolutil.DefaultReadyTimeout)),
		); err != nil {
			slog.Error("healthz server", "err", err)
		}
	}()

	slog.Info("starting base-event-scanner",
		"bridge", *bridgeAddress,
		"start_block", *startBlock,
		"poll_interval", pollInterval.String(),
		"max_blocks_per_poll", *maxBlocksPerPoll,
	)

	return scanner.Run(ctx, *startBlock, func(ctx context.Context, event chainscanner.WithdrawRequestedEvent) error {
		if !event.Amount.IsUint64() {
			return fmt.Errorf("amount overflows uint64: %s", event.Amount.String())
		}
		if event.FeeBps > uint64(^uint32(0)) {
			return fmt.Errorf("feeBps overflows uint32: %d", event.FeeBps)
		}
		// Warn about non-standard recipientUA. The ZK circuit requires exactly
		// 43 bytes (raw Orchard receiver). Other lengths will be rejected by the
		// coordinator and the user's funds will be locked until refund expiry.
		if len(event.RecipientUA) != 43 {
			slog.Warn("withdrawal has non-standard recipientUA length (will be rejected by coordinator)",
				"withdrawal_id", fmt.Sprintf("0x%x", event.WithdrawalID),
				"recipient_ua_len", len(event.RecipientUA),
				"block", event.BlockNumber,
			)
		}
		payload := eventPayload{
			Version:        "withdrawals.requested.v2",
			WithdrawalID:   fmt.Sprintf("0x%x", event.WithdrawalID),
			Requester:      event.Requester.Hex(),
			Amount:         event.Amount.Uint64(),
			RecipientUA:    fmt.Sprintf("0x%x", event.RecipientUA),
			Expiry:         event.Expiry,
			FeeBps:         uint32(event.FeeBps),
			BlockNumber:    event.BlockNumber,
			BlockHash:      event.BlockHash.Hex(),
			TxHash:         event.TxHash.Hex(),
			LogIndex:       event.LogIndex,
			FinalitySource: event.FinalitySource,
		}

		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal event: %w", err)
		}

		if err := producer.Publish(ctx, topic, encoded); err != nil {
			return fmt.Errorf("publish event: %w", err)
		}

		slog.Info("published withdraw event",
			"withdrawal_id", payload.WithdrawalID,
			"block", event.BlockNumber,
			"tx", event.TxHash.Hex(),
		)
		return nil
	})
}
