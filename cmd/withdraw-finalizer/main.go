package main

import (
	"bufio"
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

type staticProver struct {
	seal []byte
}

func (p *staticProver) Prove(_ context.Context, _ common.Hash, _ []byte) ([]byte, error) {
	return p.seal, nil
}

func main() {
	var (
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")

		baseChainID = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address (required)")
		withdrawImageID = flag.String("withdraw-image-id", "", "withdraw zkVM image id (bytes32 hex, required)")

		baseRelayerURL     = flag.String("base-relayer-url", "", "base-relayer HTTP URL (required)")
		baseRelayerAuthEnv = flag.String("base-relayer-auth-env", "BASE_RELAYER_AUTH_TOKEN", "env var containing base-relayer bearer auth token (required)")

		owner        = flag.String("owner", "", "unique finalizer owner id (required; used for DB leases)")
		leaseTTL     = flag.Duration("lease-ttl", 30*time.Second, "per-batch lease TTL")
		maxBatches   = flag.Int("max-batches", 10, "maximum batches to finalize per tick")
		tickInterval = flag.Duration("tick-interval", 1*time.Second, "finalizer tick interval")
		gasLimit     = flag.Uint64("gas-limit", 0, "optional gas limit override; 0 => estimate")

		submitTimeout = flag.Duration("submit-timeout", 5*time.Minute, "per-batch timeout (prover + base-relayer)")
		staticSealHex = flag.String("static-seal-hex", "0x01", "static seal bytes (hex) used by the built-in mock prover")

		maxLineBytes = flag.Int("max-line-bytes", 1<<20, "maximum input line size (bytes)")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *postgresDSN == "" || *baseChainID == 0 || *bridgeAddr == "" || *withdrawImageID == "" || *baseRelayerURL == "" || *owner == "" {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn, --base-chain-id, --bridge-address, --withdraw-image-id, --base-relayer-url, and --owner are required")
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
	if *maxLineBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-line-bytes must be > 0")
		os.Exit(2)
	}

	bridge := common.HexToAddress(*bridgeAddr)
	imageID, err := parseHash32Strict(*withdrawImageID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --withdraw-image-id: %v\n", err)
		os.Exit(2)
	}

	authToken := os.Getenv(*baseRelayerAuthEnv)
	if authToken == "" {
		fmt.Fprintf(os.Stderr, "error: missing base-relayer auth token in env %s\n", *baseRelayerAuthEnv)
		os.Exit(2)
	}

	sealBytes, err := decodeHexBytes(*staticSealHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --static-seal-hex: %v\n", err)
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
		Owner:          *owner,
		LeaseTTL:       *leaseTTL,
		MaxBatches:     *maxBatches,
		BaseChainID:    *baseChainID,
		BridgeAddress:  bridge,
		WithdrawImageID: imageID,
		GasLimit:       *gasLimit,
	}, store, leaseStore, baseClient, &staticProver{seal: sealBytes}, log)
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
	)

	lineCh := make(chan []byte, 16)
	errCh := make(chan error, 1)
	go scanLines(os.Stdin, *maxLineBytes, lineCh, errCh)

	t := time.NewTicker(*tickInterval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("shutdown", "reason", ctx.Err())
			return
		case err := <-errCh:
			if err != nil {
				log.Error("stdin read error", "err", err)
				os.Exit(1)
			}
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, *submitTimeout)
			err := f.Tick(cctx)
			cancel()
			if err != nil {
				log.Error("tick", "err", err)
			}
		case line := <-lineCh:
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}

			var env envelope
			if err := json.Unmarshal(line, &env); err != nil {
				log.Error("parse input json", "err", err)
				continue
			}

			switch env.Version {
			case "checkpoints.package.v1":
				var msg checkpointPackageV1
				if err := json.Unmarshal(line, &msg); err != nil {
					log.Error("parse checkpoint package", "err", err)
					continue
				}
				if msg.Version != "checkpoints.package.v1" {
					continue
				}
				if want := checkpoint.Digest(msg.Checkpoint); msg.Digest != want {
					log.Error("checkpoint digest mismatch", "want", want, "got", msg.Digest)
					continue
				}

				sigs := make([][]byte, 0, len(msg.Signatures))
				for i, s := range msg.Signatures {
					b, err := decodeHexBytes(s)
					if err != nil {
						log.Error("decode operator signature", "err", err, "index", i)
						sigs = nil
						break
					}
					sigs = append(sigs, b)
				}
				if sigs == nil {
					continue
				}

				cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
				err := f.IngestCheckpoint(cctx, withdrawfinalizer.CheckpointPackage{
					Checkpoint:         msg.Checkpoint,
					OperatorSignatures: sigs,
				})
				cancel()
				if err != nil {
					log.Error("ingest checkpoint", "err", err)
				}
			default:
				continue
			}
		}
	}
}

func scanLines(r *os.File, maxLineBytes int, out chan<- []byte, errCh chan<- error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024), maxLineBytes)

	for sc.Scan() {
		b := append([]byte(nil), sc.Bytes()...)
		out <- b
	}
	if err := sc.Err(); err != nil {
		errCh <- err
		return
	}
	errCh <- nil
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
