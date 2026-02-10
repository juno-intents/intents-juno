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
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/depositrelayer"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
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
	Version   string `json:"version"`
	CM        string `json:"cm"`
	LeafIndex uint64 `json:"leafIndex"`
	Amount    uint64 `json:"amount"`
	Memo      string `json:"memo"`
}

type staticProver struct {
	seal []byte
}

func (p *staticProver) Prove(_ context.Context, _ common.Hash, _ []byte) ([]byte, error) {
	return p.seal, nil
}

func main() {
	var (
		baseChainID = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required; must fit uint32 for deposit memo domain separation)")
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address (required)")

		depositImageID = flag.String("deposit-image-id", "", "deposit zkVM image id (bytes32 hex, required)")

		baseRelayerURL    = flag.String("base-relayer-url", "", "base-relayer HTTP URL (required)")
		baseRelayerAuthEnv = flag.String("base-relayer-auth-env", "BASE_RELAYER_AUTH_TOKEN", "env var containing base-relayer bearer auth token (required)")

		maxItems    = flag.Int("max-items", 25, "maximum items per mint batch")
		maxAge      = flag.Duration("max-age", 3*time.Minute, "maximum batch age before flushing")
		dedupeMax   = flag.Int("dedupe-max", 10_000, "max deposit ids remembered for in-memory dedupe")
		gasLimit    = flag.Uint64("gas-limit", 0, "optional gas limit override; 0 => estimate")
		flushEvery  = flag.Duration("flush-interval", 1*time.Second, "interval for time-based flush checks")
		submitTimeout = flag.Duration("submit-timeout", 5*time.Minute, "per-batch timeout (prover + base-relayer)")

		staticSealHex = flag.String("static-seal-hex", "0x01", "static seal bytes (hex) used by the built-in mock prover")

		maxLineBytes = flag.Int("max-line-bytes", 1<<20, "maximum input line size (bytes)")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *baseChainID == 0 || *bridgeAddr == "" || *depositImageID == "" || *baseRelayerURL == "" {
		fmt.Fprintln(os.Stderr, "error: --base-chain-id, --bridge-address, --deposit-image-id, and --base-relayer-url are required")
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
	if *maxItems <= 0 || *dedupeMax <= 0 || *maxLineBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-items, --dedupe-max, and --max-line-bytes must be > 0")
		os.Exit(2)
	}
	if *maxAge <= 0 || *flushEvery <= 0 || *submitTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-age, --flush-interval, and --submit-timeout must be > 0")
		os.Exit(2)
	}

	bridge := common.HexToAddress(*bridgeAddr)
	imageID, err := parseHash32Strict(*depositImageID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse --deposit-image-id: %v\n", err)
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

	relayer, err := depositrelayer.New(depositrelayer.Config{
		BaseChainID:    uint32(*baseChainID),
		BridgeAddress:  bridge,
		DepositImageID: imageID,
		MaxItems:       *maxItems,
		MaxAge:         *maxAge,
		DedupeMax:      *dedupeMax,
		GasLimit:       *gasLimit,
		Now:            time.Now,
	}, baseClient, &staticProver{seal: sealBytes}, log)
	if err != nil {
		log.Error("init deposit relayer", "err", err)
		os.Exit(2)
	}

	log.Info("deposit relayer started",
		"baseChainID", *baseChainID,
		"bridge", bridge,
		"maxItems", *maxItems,
		"maxAge", maxAge.String(),
		"flushInterval", flushEvery.String(),
	)

	lineCh := make(chan []byte, 16)
	errCh := make(chan error, 1)
	go scanLines(os.Stdin, *maxLineBytes, lineCh, errCh)

	t := time.NewTicker(*flushEvery)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("shutdown", "reason", ctx.Err())
			// Use a fresh context so we can flush a final batch even though ctx is already canceled.
			cctx, cancel := withTimeout(context.Background(), *submitTimeout)
			_ = relayer.Flush(cctx)
			cancel()
			return
		case err := <-errCh:
			if err != nil {
				log.Error("stdin read error", "err", err)
				os.Exit(1)
			}
			// EOF: flush any remaining and exit.
			cctx, cancel := withTimeout(context.Background(), *submitTimeout)
			_ = relayer.Flush(cctx)
			cancel()
			return
		case <-t.C:
			cctx, cancel := withTimeout(ctx, *submitTimeout)
			err := relayer.FlushDue(cctx)
			cancel()
			if err != nil {
				log.Error("flush due", "err", err)
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
				if sigs == nil || len(sigs) == 0 {
					continue
				}

				cctx, cancel := withTimeout(ctx, *submitTimeout)
				err = relayer.IngestCheckpoint(cctx, depositrelayer.CheckpointPackage{
					Checkpoint:         msg.Checkpoint,
					OperatorSignatures: sigs,
				})
				cancel()
				if err != nil {
					log.Error("ingest checkpoint", "err", err)
				}

			case "deposits.event.v1":
				var msg depositEventV1
				if err := json.Unmarshal(line, &msg); err != nil {
					log.Error("parse deposit event", "err", err)
					continue
				}
				if msg.Version != "deposits.event.v1" {
					continue
				}
				cm, err := parseHash32Strict(msg.CM)
				if err != nil {
					log.Error("parse cm", "err", err)
					continue
				}
				memoBytes, err := decodeHexBytes(msg.Memo)
				if err != nil {
					log.Error("parse memo", "err", err)
					continue
				}

				cctx, cancel := withTimeout(ctx, *submitTimeout)
				err = relayer.IngestDeposit(cctx, depositrelayer.DepositEvent{
					Commitment: cm,
					LeafIndex:  msg.LeafIndex,
					Amount:     msg.Amount,
					Memo:       memoBytes,
				})
				cancel()
				if err != nil {
					log.Error("ingest deposit", "err", err)
				}
			default:
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
