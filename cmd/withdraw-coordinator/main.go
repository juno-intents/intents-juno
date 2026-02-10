package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/policy"
	"github.com/juno-intents/intents-juno/internal/withdraw"
	withdrawpg "github.com/juno-intents/intents-juno/internal/withdraw/postgres"
	"github.com/juno-intents/intents-juno/internal/withdrawcoordinator"
)

type envelope struct {
	Version string `json:"version"`
}

type withdrawRequestedV1 struct {
	Version string `json:"version"`

	WithdrawalID string `json:"withdrawalId"`
	Requester    string `json:"requester"`
	Amount       uint64 `json:"amount"`

	RecipientUA string `json:"recipientUA"` // hex bytes (no 0x required)
	Expiry      uint64 `json:"expiry"`      // unix seconds
	FeeBps      uint32 `json:"feeBps"`
}

type mockPlanner struct{}

func (p *mockPlanner) Plan(_ context.Context, batchID [32]byte, ws []withdraw.Withdrawal) ([]byte, error) {
	type item struct {
		WithdrawalID string `json:"withdrawalId"`
		Amount       uint64 `json:"amount"`
		Fee          uint64 `json:"fee"`
		NetAmount    uint64 `json:"netAmount"`
		ExpiryUnix   uint64 `json:"expiryUnix"`
		RecipientUA  string `json:"recipientUA"`
	}
	type plan struct {
		Version string `json:"version"`
		BatchID string `json:"batchId"`
		Items   []item `json:"items"`
	}

	// Deterministic output.
	ws2, err := withdraw.SelectForBatch(ws, len(ws))
	if err != nil {
		return nil, err
	}

	out := plan{
		Version: "txplan.mock.v1",
		BatchID: "0x" + hex.EncodeToString(batchID[:]),
		Items:   make([]item, 0, len(ws2)),
	}
	for _, w := range ws2 {
		fee, net, err := withdraw.ComputeFeeAndNet(w.Amount, w.FeeBps)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item{
			WithdrawalID: "0x" + hex.EncodeToString(w.ID[:]),
			Amount:       w.Amount,
			Fee:          fee,
			NetAmount:    net,
			ExpiryUnix:   uint64(w.Expiry.Unix()),
			RecipientUA:  "0x" + hex.EncodeToString(w.RecipientUA),
		})
	}
	return json.Marshal(out)
}

type hashSigner struct{}

func (s *hashSigner) Sign(_ context.Context, txPlan []byte) ([]byte, error) {
	sum := sha256.Sum256(txPlan)
	return sum[:], nil
}

type hashBroadcaster struct{}

func (b *hashBroadcaster) Broadcast(_ context.Context, rawTx []byte) (string, error) {
	sum := sha256.Sum256(rawTx)
	return "0x" + hex.EncodeToString(sum[:]), nil
}

type immediateConfirmer struct{}

func (c *immediateConfirmer) WaitConfirmed(_ context.Context, _ string) error { return nil }

func main() {
	var (
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")

		maxItems     = flag.Int("max-items", 50, "maximum withdrawals per Juno payout tx")
		maxAge       = flag.Duration("max-age", 3*time.Minute, "maximum batch age before flushing")
		claimTTL     = flag.Duration("claim-ttl", 30*time.Second, "per-withdrawal claim TTL in DB")
		tickInterval = flag.Duration("tick-interval", 1*time.Second, "coordinator tick interval")

		safetyMargin   = flag.Duration("expiry-safety-margin", policy.DefaultWithdrawExpirySafetyMargin, "minimum time-to-expiry required to broadcast (refuse if below this unless expiry extension is enabled)")
		maxExtension   = flag.Duration("max-expiry-extension", 12*time.Hour, "max per-withdrawal expiry extension allowed by contract")
		maxExtendBatch = flag.Int("max-extend-batch", policy.DefaultMaxExtendBatch, "max withdrawal ids per extendWithdrawExpiryBatch call")

		owner = flag.String("owner", "", "unique coordinator owner id (required; used for DB claims)")

		maxLineBytes = flag.Int("max-line-bytes", 1<<20, "maximum input line size (bytes)")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *postgresDSN == "" || *owner == "" {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn and --owner are required")
		os.Exit(2)
	}
	if *maxItems <= 0 || *maxExtendBatch <= 0 || *maxLineBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-items, --max-extend-batch, and --max-line-bytes must be > 0")
		os.Exit(2)
	}
	if *maxAge <= 0 || *claimTTL <= 0 || *tickInterval <= 0 || *safetyMargin <= 0 || *maxExtension <= 0 {
		fmt.Fprintln(os.Stderr, "error: durations must be > 0")
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
		log.Error("ensure schema", "err", err)
		os.Exit(2)
	}

	coord, err := withdrawcoordinator.New(withdrawcoordinator.Config{
		Owner:    *owner,
		MaxItems: *maxItems,
		MaxAge:   *maxAge,
		ClaimTTL: *claimTTL,
		ExpiryPolicy: policy.WithdrawExpiryConfig{
			SafetyMargin: *safetyMargin,
			MaxExtension: *maxExtension,
			MaxBatch:     *maxExtendBatch,
		},
		Now: time.Now,
	}, store, &mockPlanner{}, &hashSigner{}, &hashBroadcaster{}, &immediateConfirmer{}, log)
	if err != nil {
		log.Error("init coordinator", "err", err)
		os.Exit(2)
	}

	log.Info("withdraw coordinator started",
		"owner", *owner,
		"maxItems", *maxItems,
		"maxAge", maxAge.String(),
		"claimTTL", claimTTL.String(),
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
			if err := coord.Tick(ctx); err != nil {
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
			case "withdrawals.requested.v1":
				var msg withdrawRequestedV1
				if err := json.Unmarshal(line, &msg); err != nil {
					log.Error("parse withdraw requested", "err", err)
					continue
				}
				if msg.Version != "withdrawals.requested.v1" {
					continue
				}
				id, err := parseHash32(msg.WithdrawalID)
				if err != nil {
					log.Error("parse withdrawalId", "err", err)
					continue
				}
				requester, err := parseAddr20(msg.Requester)
				if err != nil {
					log.Error("parse requester", "err", err)
					continue
				}
				ua, err := decodeHexBytes(msg.RecipientUA)
				if err != nil {
					log.Error("parse recipientUA", "err", err)
					continue
				}
				expiry := time.Unix(int64(msg.Expiry), 0).UTC()

				w := withdraw.Withdrawal{
					ID:          id,
					Requester:   requester,
					Amount:      msg.Amount,
					FeeBps:      msg.FeeBps,
					RecipientUA: ua,
					Expiry:      expiry,
				}

				cctx, cancel := withTimeout(ctx, 5*time.Second)
				err = coord.IngestWithdrawRequested(cctx, w)
				cancel()
				if err != nil {
					log.Error("ingest withdrawal", "err", err)
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

func parseHash32(s string) ([32]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 64 {
		return [32]byte{}, fmt.Errorf("expected 32-byte hex, got len %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("decode hex: %w", err)
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func parseAddr20(s string) ([20]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if len(s) != 40 {
		return [20]byte{}, fmt.Errorf("expected 20-byte hex address, got len %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return [20]byte{}, fmt.Errorf("decode hex: %w", err)
	}
	var out [20]byte
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
