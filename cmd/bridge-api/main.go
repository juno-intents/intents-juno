package main

import (
	"context"
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
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/bridgeapi"
	"github.com/juno-intents/intents-juno/internal/bridgeconfig"
	depositpg "github.com/juno-intents/intents-juno/internal/deposit/postgres"
	"github.com/juno-intents/intents-juno/internal/healthz"
	"github.com/juno-intents/intents-juno/internal/pgxpoolutil"
	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
	withdrawpg "github.com/juno-intents/intents-juno/internal/withdraw/postgres"
)

func main() {
	var (
		listenAddr = flag.String("listen", "127.0.0.1:8082", "HTTP listen address")

		postgresDSN               = flag.String("postgres-dsn", "", "Postgres DSN (required)")
		postgresMinConns          = flag.Int("postgres-min-conns", int(pgxpoolutil.DefaultMinConns), "minimum pgxpool connections")
		postgresMaxConns          = flag.Int("postgres-max-conns", int(pgxpoolutil.DefaultMaxConns), "maximum pgxpool connections")
		postgresHealthCheckPeriod = flag.Duration(
			"postgres-health-check-period",
			pgxpoolutil.DefaultHealthCheckPeriod,
			"pgxpool health check period",
		)
		baseRPCURL = flag.String("base-rpc-url", "", "Base chain RPC URL (required)")

		baseChainID = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address (required)")
		wjunoAddr   = flag.String("wjuno-address", "", "WJuno token contract address (optional, returned by /v1/config)")
		oWalletUA   = flag.String("owallet-ua", "", "oWallet unified address (required)")

		withdrawalExpiryWindowSeconds = flag.Uint64(
			"withdrawal-expiry-window-seconds",
			24*60*60,
			"on-chain withdrawal expiry window in seconds",
		)
		minDepositAmount                = flag.Uint64("min-deposit-amount", 0, "minimum deposit amount (0 = no minimum)")
		depositMinConfirmations         = flag.Int64("deposit-min-confirmations", 1, "default deposit confirmations used to seed runtime settings")
		withdrawPlannerMinConfirmations = flag.Int64("withdraw-planner-min-confirmations", 1, "default withdraw planner confirmations used to seed runtime settings")
		withdrawBatchConfirmations      = flag.Int64("withdraw-batch-confirmations", 1, "default withdraw batch confirmations used to seed runtime settings")
		minWithdrawAmount               = flag.Uint64("min-withdraw-amount", 0, "minimum withdrawal amount (0 = no minimum)")
		feeBps                          = flag.Uint("fee-bps", 0, "bridge fee in basis points (informational, returned by /v1/config)")

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

	if *postgresDSN == "" || *baseRPCURL == "" || *baseChainID == 0 || *bridgeAddr == "" || *oWalletUA == "" {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn, --base-rpc-url, --base-chain-id, --bridge-address, and --owallet-ua are required")
		os.Exit(2)
	}
	if !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	if *wjunoAddr != "" && !common.IsHexAddress(*wjunoAddr) {
		fmt.Fprintln(os.Stderr, "error: --wjuno-address must be a valid hex address")
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
	if *depositMinConfirmations <= 0 || *withdrawPlannerMinConfirmations <= 0 || *withdrawBatchConfirmations <= 0 {
		fmt.Fprintln(os.Stderr, "error: runtime confirmation defaults must be > 0")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	poolCfg, err := pgxpoolutil.ParseConfig(strings.TrimSpace(*postgresDSN), pgxpoolutil.Settings{
		MinConns:          int32(*postgresMinConns),
		MaxConns:          int32(*postgresMaxConns),
		HealthCheckPeriod: *postgresHealthCheckPeriod,
	})
	if err != nil {
		log.Error("parse pgx pool config", "err", err)
		os.Exit(2)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Error("init pgx pool", "err", err)
		os.Exit(2)
	}
	defer pool.Close()

	baseClient, err := ethclient.DialContext(ctx, *baseRPCURL)
	if err != nil {
		log.Error("dial base rpc", "err", err)
		os.Exit(2)
	}
	defer baseClient.Close()

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

	runtimeStore, err := runtimeconfig.New(pool)
	if err != nil {
		log.Error("init runtime settings store", "err", err)
		os.Exit(2)
	}
	if err := runtimeStore.EnsureSchema(ctx); err != nil {
		log.Error("ensure runtime settings schema", "err", err)
		os.Exit(2)
	}
	if _, err := runtimeStore.EnsureDefaults(ctx, runtimeconfig.Settings{
		DepositMinConfirmations:         *depositMinConfirmations,
		WithdrawPlannerMinConfirmations: *withdrawPlannerMinConfirmations,
		WithdrawBatchConfirmations:      *withdrawBatchConfirmations,
	}, "bridge-api"); err != nil {
		log.Error("ensure runtime settings defaults", "err", err)
		os.Exit(2)
	}
	runtimeSettingsCache, err := runtimeconfig.NewCache(runtimeStore, 5*time.Second, log)
	if err != nil {
		log.Error("init runtime settings cache", "err", err)
		os.Exit(2)
	}
	go runtimeSettingsCache.Start(ctx)

	bridgeReader, err := bridgeconfig.NewReader(baseClient, common.HexToAddress(*bridgeAddr))
	if err != nil {
		log.Error("init bridge settings reader", "err", err)
		os.Exit(2)
	}
	bridgeSettingsCache, err := bridgeconfig.NewCache(bridgeReader, 5*time.Second, log)
	if err != nil {
		log.Error("init bridge settings cache", "err", err)
		os.Exit(2)
	}
	go bridgeSettingsCache.Start(ctx)

	withdrawReader, err := bridgeapi.NewPostgresWithdrawalReader(pool)
	if err != nil {
		log.Error("init withdrawal status reader", "err", err)
		os.Exit(2)
	}

	depositLister, err := bridgeapi.NewPostgresDepositLister(pool)
	if err != nil {
		log.Error("init deposit lister", "err", err)
		os.Exit(2)
	}

	withdrawalLister, err := bridgeapi.NewPostgresWithdrawalLister(pool)
	if err != nil {
		log.Error("init withdrawal lister", "err", err)
		os.Exit(2)
	}

	var wjunoAddress common.Address
	if *wjunoAddr != "" {
		wjunoAddress = common.HexToAddress(*wjunoAddr)
	}

	handler, err := bridgeapi.NewHandler(bridgeapi.Config{
		BaseChainID:                   uint32(*baseChainID),
		BridgeAddress:                 common.HexToAddress(*bridgeAddr),
		WJunoAddress:                  wjunoAddress,
		OWalletUA:                     *oWalletUA,
		WithdrawalExpiryWindowSeconds: *withdrawalExpiryWindowSeconds,
		MinDepositAmount:              *minDepositAmount,
		DepositMinConfirmations:       *depositMinConfirmations,
		MinWithdrawAmount:             *minWithdrawAmount,
		FeeBps:                        uint32(*feeBps),
		RuntimeSettings:               runtimeSettingsCache,
		BridgeSettings:                bridgeSettingsCache,
		RateLimitPerIPPerSecond:       *rateLimitPerSecond,
		RateLimitBurst:                *rateLimitBurst,
		RateLimitMaxTrackedIPs:        *rateLimitMaxIPs,
		MemoCacheTTL:                  *memoCacheTTL,
		MemoCacheMaxEntries:           *memoCacheMaxEntries,
		DepositLister:                 depositLister,
		WithdrawalLister:              withdrawalLister,
		ReadinessCheck: healthz.CombineReadinessChecks(
			pgxpoolutil.ReadinessCheck(pool, pgxpoolutil.DefaultReadyTimeout),
			runtimeSettingsCache.Ready,
			bridgeSettingsCache.Ready,
		),
		Now: time.Now,
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
