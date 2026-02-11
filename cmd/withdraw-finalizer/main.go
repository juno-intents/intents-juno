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
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	leasespg "github.com/juno-intents/intents-juno/internal/leases/postgres"
	"github.com/juno-intents/intents-juno/internal/proverexec"
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

		baseRelayerURL     = flag.String("base-relayer-url", "", "base-relayer HTTP URL (required)")
		baseRelayerAuthEnv = flag.String("base-relayer-auth-env", "BASE_RELAYER_AUTH_TOKEN", "env var containing base-relayer bearer auth token (required)")

		owner        = flag.String("owner", "", "unique finalizer owner id (required; used for DB leases)")
		leaseTTL     = flag.Duration("lease-ttl", 30*time.Second, "per-batch lease TTL")
		maxBatches   = flag.Int("max-batches", 10, "maximum batches to finalize per tick")
		tickInterval = flag.Duration("tick-interval", 1*time.Second, "finalizer tick interval")
		gasLimit     = flag.Uint64("gas-limit", 0, "optional gas limit override; 0 => estimate")

		submitTimeout      = flag.Duration("submit-timeout", 5*time.Minute, "per-batch timeout (prover + base-relayer)")
		proverBin          = flag.String("prover-bin", "", "path to prover command binary (required)")
		proverMaxRespBytes = flag.Int("prover-max-response-bytes", 1<<20, "max prover response size (bytes)")

		queueDriver   = flag.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
		queueBrokers  = flag.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")
		queueGroup    = flag.String("queue-group", "withdraw-finalizer", "queue consumer group (required for kafka)")
		queueTopics   = flag.String("queue-topics", "checkpoints.packages.v1", "comma-separated queue topics")
		maxLineBytes  = flag.Int("max-line-bytes", 1<<20, "maximum stdin line size for stdio driver (bytes)")
		queueMaxBytes = flag.Int("queue-max-bytes", 10<<20, "maximum kafka message size for consumer reads (bytes)")
		ackTimeout    = flag.Duration("queue-ack-timeout", 5*time.Second, "timeout for queue message acknowledgements")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *postgresDSN == "" || *baseChainID == 0 || *bridgeAddr == "" || *operators == "" || *threshold <= 0 || *withdrawImageID == "" || *baseRelayerURL == "" || *owner == "" || *proverBin == "" {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn, --base-chain-id, --bridge-address, --operators, --operator-threshold, --withdraw-image-id, --base-relayer-url, --prover-bin, and --owner are required")
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
	if *proverMaxRespBytes <= 0 || *ackTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: --prover-max-response-bytes and --queue-ack-timeout must be > 0")
		os.Exit(2)
	}

	bridge := common.HexToAddress(*bridgeAddr)
	imageID, err := parseHash32Strict(*withdrawImageID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --withdraw-image-id: %v\n", err)
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

	proverClient, err := proverexec.New(*proverBin, *proverMaxRespBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: init prover client: %v\n", err)
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
		Owner:             *owner,
		LeaseTTL:          *leaseTTL,
		MaxBatches:        *maxBatches,
		BaseChainID:       *baseChainID,
		BridgeAddress:     bridge,
		WithdrawImageID:   imageID,
		OperatorAddresses: operatorAddrs,
		OperatorThreshold: *threshold,
		GasLimit:          *gasLimit,
	}, store, leaseStore, baseClient, proverClient, log)
	if err != nil {
		log.Error("init withdraw finalizer", "err", err)
		os.Exit(2)
	}

	log.Info("withdraw finalizer started",
		"owner", *owner,
		"baseChainID", *baseChainID,
		"bridge", bridge,
		"maxBatches", *maxBatches,
		"leaseTTL", leaseTTL.String(),
		"tickInterval", tickInterval.String(),
		"queueDriver", *queueDriver,
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
