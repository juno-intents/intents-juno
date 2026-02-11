package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/bridgeapi"
	depositpg "github.com/juno-intents/intents-juno/internal/deposit/postgres"
	withdrawpg "github.com/juno-intents/intents-juno/internal/withdraw/postgres"
)

func main() {
	var (
		listenAddr = flag.String("listen", "127.0.0.1:8082", "HTTP listen address")

		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")

		baseChainID = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address (required)")
		oWalletUA   = flag.String("owallet-ua", "", "oWallet unified address (required)")

		refundWindowSeconds = flag.Uint64("refund-window-seconds", 24*60*60, "on-chain refund window in seconds")

		rateLimitPerSecond = flag.Float64("rate-limit-per-ip-per-second", 20, "per-IP refill rate for API rate limiting")
		rateLimitBurst     = flag.Int("rate-limit-burst", 40, "per-IP burst capacity for API rate limiting")
		rateLimitMaxIPs    = flag.Int("rate-limit-max-tracked-ips", 10000, "maximum tracked client IP entries in rate limiter")

		memoCacheTTL        = flag.Duration("memo-cache-ttl", 30*time.Second, "TTL for deposit memo response cache")
		memoCacheMaxEntries = flag.Int("memo-cache-max-entries", 10000, "maximum cached deposit memo responses")

		readHeaderTimeout = flag.Duration("read-header-timeout", 5*time.Second, "http.Server ReadHeaderTimeout")
		readTimeout       = flag.Duration("read-timeout", 10*time.Second, "http.Server ReadTimeout")
		writeTimeout      = flag.Duration("write-timeout", 10*time.Second, "http.Server WriteTimeout")
		idleTimeout       = flag.Duration("idle-timeout", 60*time.Second, "http.Server IdleTimeout")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *postgresDSN == "" || *baseChainID == 0 || *bridgeAddr == "" || *oWalletUA == "" {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn, --base-chain-id, --bridge-address, and --owallet-ua are required")
		os.Exit(2)
	}
	if !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	if *baseChainID > uint64(^uint32(0)) {
		fmt.Fprintln(os.Stderr, "error: --base-chain-id must fit uint32")
		os.Exit(2)
	}
	if *listenAddr == "" {
		fmt.Fprintln(os.Stderr, "error: --listen must be non-empty")
		os.Exit(2)
	}
	if *readHeaderTimeout <= 0 || *readTimeout <= 0 || *writeTimeout <= 0 || *idleTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: timeouts must be > 0")
		os.Exit(2)
	}
	if *rateLimitPerSecond <= 0 || *rateLimitBurst <= 0 || *rateLimitMaxIPs <= 0 {
		fmt.Fprintln(os.Stderr, "error: rate limit settings must be > 0")
		os.Exit(2)
	}
	if *memoCacheTTL <= 0 || *memoCacheMaxEntries <= 0 {
		fmt.Fprintln(os.Stderr, "error: memo cache settings must be > 0")
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

	depositStore, err := depositpg.New(pool)
	if err != nil {
		log.Error("init deposit store", "err", err)
		os.Exit(2)
	}
	if err := depositStore.EnsureSchema(ctx); err != nil {
		log.Error("ensure deposit schema", "err", err)
		os.Exit(2)
	}

	withdrawStore, err := withdrawpg.New(pool)
	if err != nil {
		log.Error("init withdraw store", "err", err)
		os.Exit(2)
	}
	if err := withdrawStore.EnsureSchema(ctx); err != nil {
		log.Error("ensure withdraw schema", "err", err)
		os.Exit(2)
	}

	withdrawReader, err := bridgeapi.NewPostgresWithdrawalReader(pool)
	if err != nil {
		log.Error("init withdrawal status reader", "err", err)
		os.Exit(2)
	}

	handler, err := bridgeapi.NewHandler(bridgeapi.Config{
		BaseChainID:             uint32(*baseChainID),
		BridgeAddress:           common.HexToAddress(*bridgeAddr),
		OWalletUA:               *oWalletUA,
		RefundWindowSeconds:     *refundWindowSeconds,
		RateLimitPerIPPerSecond: *rateLimitPerSecond,
		RateLimitBurst:          *rateLimitBurst,
		RateLimitMaxTrackedIPs:  *rateLimitMaxIPs,
		MemoCacheTTL:            *memoCacheTTL,
		MemoCacheMaxEntries:     *memoCacheMaxEntries,
		Now:                     time.Now,
	}, depositStore, withdrawReader)
	if err != nil {
		log.Error("init bridge api handler", "err", err)
		os.Exit(2)
	}

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: *readHeaderTimeout,
		ReadTimeout:       *readTimeout,
		WriteTimeout:      *writeTimeout,
		IdleTimeout:       *idleTimeout,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("bridge-api listening", "addr", *listenAddr, "baseChainID", *baseChainID, "bridge", *bridgeAddr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown", "reason", ctx.Err())
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
