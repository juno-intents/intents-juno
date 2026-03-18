package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/backoffice"
	"github.com/juno-intents/intents-juno/internal/backoffice/alerts"
	"github.com/juno-intents/intents-juno/internal/bridgeconfig"
	dlqpg "github.com/juno-intents/intents-juno/internal/dlq/postgres"
	"github.com/juno-intents/intents-juno/internal/emf"
	"github.com/juno-intents/intents-juno/internal/envutil"
	ethutil "github.com/juno-intents/intents-juno/internal/eth"
	"github.com/juno-intents/intents-juno/internal/healthz"
	"github.com/juno-intents/intents-juno/internal/pgxpoolutil"
	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
)

func main() {
	var (
		listenAddr                = flag.String("listen", ":8090", "HTTP listen address")
		postgresDSN               = flag.String("postgres-dsn", "", "Postgres DSN (required)")
		postgresDSNEnv            = flag.String("postgres-dsn-env", "", "env var containing the Postgres DSN")
		postgresMinConns          = flag.Int("postgres-min-conns", int(pgxpoolutil.DefaultMinConns), "minimum pgxpool connections")
		postgresMaxConns          = flag.Int("postgres-max-conns", int(pgxpoolutil.DefaultMaxConns), "maximum pgxpool connections")
		postgresHealthCheckPeriod = flag.Duration(
			"postgres-health-check-period",
			pgxpoolutil.DefaultHealthCheckPeriod,
			"pgxpool health check period",
		)
		baseRPCURL = flag.String("base-rpc-url", "", "Base chain RPC URL (required)")

		junoRPCURL     = flag.String("juno-rpc-url", "", "Juno RPC URL (optional, for MPC wallet balance)")
		junoRPCURLsRaw = flag.String("juno-rpc-urls", "", "Comma-separated Juno RPC URLs (optional, tried in order for MPC wallet balance)")
		junoRPCUser    = flag.String("juno-rpc-user", "", "Juno RPC basic auth username")
		junoRPCPass    = flag.String("juno-rpc-pass", "", "Juno RPC basic auth password")

		authSecret = flag.String("auth-secret", "", "Bearer token for API auth (required)")

		rateLimitPerSecond = flag.Float64("rate-limit-per-second", 5, "Per-IP rate limit refill rate")
		rateLimitBurst     = flag.Int("rate-limit-burst", 10, "Per-IP rate limit burst capacity")

		bridgeAddr                = flag.String("bridge-address", "", "Bridge contract address on Base (required)")
		wjunoAddr                 = flag.String("wjuno-address", "", "wJUNO contract address on Base (required)")
		opRegistryAddr            = flag.String("operator-registry-address", "", "OperatorRegistry contract address (required)")
		feeDistAddr               = flag.String("fee-distributor-address", "", "FeeDistributor contract address (optional)")
		owalletUA                 = flag.String("owallet-ua", "", "Juno unified address displayed as the MPC bridge wallet (optional)")
		sp1RequestorStr           = flag.String("sp1-requestor-address", "", "SP1 prover requestor address (optional)")
		sp1RPCURL                 = flag.String("sp1-rpc-url", "", "SP1 prover network RPC URL (optional, for prover balance)")
		operatorAddrsRaw          = flag.String("operator-addresses", "", "Comma-separated list of operator addresses")
		baseRelayerSignerAddrsRaw = flag.String("base-relayer-signer-addresses", "", "Comma-separated list of Base relayer signer addresses")

		serviceURLsRaw                  = flag.String("service-urls", "", "Comma-separated list of service healthz URLs to poll")
		operatorEndpointsRaw            = flag.String("operator-endpoints", "", "Comma-separated addr=host:port pairs for gRPC health check")
		kafkaBrokersRaw                 = flag.String("kafka-brokers", "", "Comma-separated Kafka broker addresses for health probe")
		ipfsApiURL                      = flag.String("ipfs-api-url", "", "IPFS API URL for health probe (e.g. http://host:5001)")
		ipfsApiBearerToken              = flag.String("ipfs-api-bearer-token", "", "optional IPFS API bearer token for the health probe")
		ipfsApiBearerTokenEnv           = flag.String("ipfs-api-bearer-token-env", "BACKOFFICE_IPFS_API_BEARER_TOKEN", "env var containing an optional IPFS API bearer token")
		depositMinConfirmations         = flag.Int64("deposit-min-confirmations", 1, "default deposit confirmations used to seed runtime settings")
		withdrawPlannerMinConfirmations = flag.Int64("withdraw-planner-min-confirmations", 1, "default withdraw planner confirmations used to seed runtime settings")
		withdrawBatchConfirmations      = flag.Int64("withdraw-batch-confirmations", 1, "default withdraw batch confirmations used to seed runtime settings")
		minDepositAdminKeyEnv           = flag.String("min-deposit-admin-key-env", "MIN_DEPOSIT_ADMIN_PRIVATE_KEY", "env var containing the dedicated minDepositAdmin private key")
		minDepositUpdateGasLimit        = flag.Uint64("min-deposit-update-gas-limit", 0, "optional gas limit override for setMinDepositAmount")

		alertCheckInterval = flag.Duration("alert-check-interval", 30*time.Second, "Alert engine check interval")

		operatorGasMinWeiStr    = flag.String("operator-gas-min-wei", "500000000000000000", "Min operator ETH balance (wei)")
		baseRelayerGasMinWeiStr = flag.String("base-relayer-gas-min-wei", "1000000000000000", "Min Base relayer signer ETH balance (wei)")
		proverFundsMinWeiStr    = flag.String("prover-funds-min-wei", "1000000000000000000", "Min prover ETH balance (wei)")
	)
	flag.Parse()

	// Suppress unused variable warning for alertCheckInterval.
	_ = alertCheckInterval

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	metricsEmitter, err := emf.New(emf.Config{
		Namespace: emf.OperationsNamespace,
		Writer:    os.Stdout,
		Now:       time.Now,
		Fields: map[string]any{
			"service": "backoffice",
		},
	})
	if err != nil {
		log.Error("init metrics emitter", "err", err)
		os.Exit(2)
	}

	// Validate required flags.
	resolvedPostgresDSN, err := pgxpoolutil.ResolveDSN(*postgresDSN, *postgresDSNEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	if *baseRPCURL == "" {
		fmt.Fprintln(os.Stderr, "error: --base-rpc-url is required")
		os.Exit(2)
	}
	if *authSecret == "" {
		fmt.Fprintln(os.Stderr, "error: --auth-secret is required")
		os.Exit(2)
	}
	if *bridgeAddr == "" || !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	if *wjunoAddr == "" || !common.IsHexAddress(*wjunoAddr) {
		fmt.Fprintln(os.Stderr, "error: --wjuno-address must be a valid hex address")
		os.Exit(2)
	}
	if *opRegistryAddr == "" || !common.IsHexAddress(*opRegistryAddr) {
		fmt.Fprintln(os.Stderr, "error: --operator-registry-address must be a valid hex address")
		os.Exit(2)
	}
	if *depositMinConfirmations <= 0 || *withdrawPlannerMinConfirmations <= 0 || *withdrawBatchConfirmations <= 0 {
		fmt.Fprintln(os.Stderr, "error: runtime confirmation defaults must be > 0")
		os.Exit(2)
	}

	// Parse operator addresses.
	var operatorAddresses []common.Address
	if raw := strings.TrimSpace(*operatorAddrsRaw); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !common.IsHexAddress(s) {
				fmt.Fprintf(os.Stderr, "error: invalid operator address: %s\n", s)
				os.Exit(2)
			}
			operatorAddresses = append(operatorAddresses, common.HexToAddress(s))
		}
	}

	var baseRelayerSignerAddresses []common.Address
	if raw := strings.TrimSpace(*baseRelayerSignerAddrsRaw); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if !common.IsHexAddress(s) {
				fmt.Fprintf(os.Stderr, "error: invalid base relayer signer address: %s\n", s)
				os.Exit(2)
			}
			baseRelayerSignerAddresses = append(baseRelayerSignerAddresses, common.HexToAddress(s))
		}
	}

	// Parse service URLs (format: "label=url" or plain "url").
	var serviceEntries []backoffice.ServiceEntry
	if raw := strings.TrimSpace(*serviceURLsRaw); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			var label, url string
			parts := strings.SplitN(s, "=", 2)
			if len(parts) == 2 && !strings.HasPrefix(parts[0], "http") {
				label, url = parts[0], parts[1]
			} else {
				label, url = s, s
			}
			serviceEntries = append(serviceEntries, backoffice.ServiceEntry{Label: label, URL: url})
		}
	}

	// Parse operator endpoints (addr=host:port pairs).
	var operatorEndpoints []backoffice.OperatorEndpoint
	if raw := strings.TrimSpace(*operatorEndpointsRaw); raw != "" {
		for _, pair := range strings.Split(raw, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) != 2 || !common.IsHexAddress(parts[0]) || parts[1] == "" {
				fmt.Fprintf(os.Stderr, "error: invalid operator-endpoint pair (expected addr=host:port): %s\n", pair)
				os.Exit(2)
			}
			operatorEndpoints = append(operatorEndpoints, backoffice.OperatorEndpoint{
				Address:  common.HexToAddress(parts[0]),
				Endpoint: parts[1],
			})
		}
	}

	// Parse Kafka brokers.
	var kafkaBrokers []string
	if raw := strings.TrimSpace(*kafkaBrokersRaw); raw != "" {
		for _, b := range strings.Split(raw, ",") {
			b = strings.TrimSpace(b)
			if b != "" {
				kafkaBrokers = append(kafkaBrokers, b)
			}
		}
	}

	// Parse wei thresholds.
	operatorGasMinWei := new(big.Int)
	if _, ok := operatorGasMinWei.SetString(*operatorGasMinWeiStr, 10); !ok {
		fmt.Fprintln(os.Stderr, "error: --operator-gas-min-wei must be a valid integer")
		os.Exit(2)
	}
	baseRelayerGasMinWei := new(big.Int)
	if _, ok := baseRelayerGasMinWei.SetString(*baseRelayerGasMinWeiStr, 10); !ok {
		fmt.Fprintln(os.Stderr, "error: --base-relayer-gas-min-wei must be a valid integer")
		os.Exit(2)
	}
	proverFundsMinWei := new(big.Int)
	if _, ok := proverFundsMinWei.SetString(*proverFundsMinWeiStr, 10); !ok {
		fmt.Fprintln(os.Stderr, "error: --prover-funds-min-wei must be a valid integer")
		os.Exit(2)
	}

	// Optional addresses.
	var sp1Requestor common.Address
	if s := strings.TrimSpace(*sp1RequestorStr); s != "" && common.IsHexAddress(s) {
		sp1Requestor = common.HexToAddress(s)
	}
	var feeDistributor common.Address
	if s := strings.TrimSpace(*feeDistAddr); s != "" && common.IsHexAddress(s) {
		feeDistributor = common.HexToAddress(s)
	}
	junoRPCURLs := splitCSVStrings(*junoRPCURLsRaw)
	if single := strings.TrimSpace(*junoRPCURL); single != "" {
		junoRPCURLs = append([]string{single}, junoRPCURLs...)
	}
	junoRPCURLs = uniqueStrings(junoRPCURLs)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Connect to Postgres.
	poolCfg, err := pgxpoolutil.ParseConfig(resolvedPostgresDSN, pgxpoolutil.Settings{
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

	// Connect to Base RPC.
	baseClient, err := ethclient.DialContext(ctx, *baseRPCURL)
	if err != nil {
		log.Error("dial base rpc", "err", err)
		os.Exit(2)
	}
	defer baseClient.Close()

	// Initialize DLQ store.
	dlqStore, err := dlqpg.New(pool)
	if err != nil {
		log.Error("init dlq store", "err", err)
		os.Exit(2)
	}
	if err := dlqStore.EnsureSchema(ctx); err != nil {
		log.Error("ensure dlq schema", "err", err)
		os.Exit(2)
	}

	// Initialize alert store.
	alertStore := alerts.NewStore(pool)
	if err := alertStore.EnsureSchema(ctx); err != nil {
		log.Error("ensure alert schema", "err", err)
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
	}, "backoffice"); err != nil {
		log.Error("ensure runtime settings defaults", "err", err)
		os.Exit(2)
	}

	settingsAuditStore, err := backoffice.NewSettingsAuditStore(pool)
	if err != nil {
		log.Error("init settings audit store", "err", err)
		os.Exit(2)
	}
	if err := settingsAuditStore.EnsureSchema(ctx); err != nil {
		log.Error("ensure settings audit schema", "err", err)
		os.Exit(2)
	}

	bridgeReader, err := bridgeconfig.NewReader(baseClient, common.HexToAddress(*bridgeAddr))
	if err != nil {
		log.Error("init bridge settings reader", "err", err)
		os.Exit(2)
	}
	initialBridgeSettings, err := bridgeReader.Load(ctx)
	if err != nil {
		log.Error("load bridge settings", "err", err)
		os.Exit(2)
	}
	bridgeSettingsCache, err := bridgeconfig.NewCache(bridgeReader, 5*time.Second, log)
	if err != nil {
		log.Error("init bridge settings cache", "err", err)
		os.Exit(2)
	}
	go bridgeSettingsCache.Start(ctx)

	var minDepositUpdater backoffice.MinDepositUpdater
	minDepositAdminKey := strings.TrimSpace(os.Getenv(*minDepositAdminKeyEnv))
	if minDepositAdminKey == "" {
		log.Warn("min deposit admin updates disabled; no private key configured", "env", *minDepositAdminKeyEnv)
	} else {
		keys, err := ethutil.ParsePrivateKeysHexList(minDepositAdminKey)
		if err != nil {
			log.Error("parse min deposit admin private key", "err", err, "env", *minDepositAdminKeyEnv)
			os.Exit(2)
		}
		if len(keys) != 1 {
			log.Error("min deposit admin env must contain exactly one private key", "env", *minDepositAdminKeyEnv)
			os.Exit(2)
		}
		signer := ethutil.NewLocalSigner(keys[0])
		if initialBridgeSettings.MinDepositAdmin != signer.Address() {
			log.Error(
				"configured min deposit admin signer does not match on-chain minDepositAdmin",
				"expected", initialBridgeSettings.MinDepositAdmin.Hex(),
				"got", signer.Address().Hex(),
			)
			os.Exit(2)
		}
		minDepositUpdater, err = backoffice.NewMinDepositTxUpdater(
			ctx,
			baseClient,
			common.HexToAddress(*bridgeAddr),
			signer,
			*minDepositUpdateGasLimit,
		)
		if err != nil {
			log.Error("init min deposit updater", "err", err)
			os.Exit(2)
		}
	}

	// Build server.
	srv, err := backoffice.New(backoffice.ServerConfig{
		Pool:       pool,
		BaseClient: baseClient,
		SP1RPCURL:  strings.TrimSpace(*sp1RPCURL),

		JunoRPCURL:  strings.TrimSpace(*junoRPCURL),
		JunoRPCURLs: junoRPCURLs,
		JunoRPCUser: strings.TrimSpace(*junoRPCUser),
		JunoRPCPass: strings.TrimSpace(*junoRPCPass),

		DLQStore:          dlqStore,
		AlertStore:        alertStore,
		RuntimeStore:      runtimeStore,
		BridgeSettings:    bridgeSettingsCache,
		SettingsAudit:     settingsAuditStore,
		MinDepositUpdater: minDepositUpdater,

		BridgeAddress:              common.HexToAddress(*bridgeAddr),
		WJunoAddress:               common.HexToAddress(*wjunoAddr),
		OperatorRegistryAddress:    common.HexToAddress(*opRegistryAddr),
		FeeDistributorAddress:      feeDistributor,
		OWalletUA:                  strings.TrimSpace(*owalletUA),
		SP1RequestorAddress:        sp1Requestor,
		OperatorAddresses:          operatorAddresses,
		BaseRelayerSignerAddresses: baseRelayerSignerAddresses,

		ServiceEntries:     serviceEntries,
		OperatorEndpoints:  operatorEndpoints,
		KafkaBrokers:       kafkaBrokers,
		IPFSApiURL:         strings.TrimSpace(*ipfsApiURL),
		IPFSApiBearerToken: envutil.ResolveOptional(*ipfsApiBearerToken, *ipfsApiBearerTokenEnv),

		AuthSecret: *authSecret,

		RateLimitPerSecond: *rateLimitPerSecond,
		RateLimitBurst:     *rateLimitBurst,

		OperatorGasMinWei:      operatorGasMinWei,
		BaseRelayerFundsMinWei: baseRelayerGasMinWei,
		ProverFundsMinWei:      proverFundsMinWei,
		MetricsEmitter:         metricsEmitter,
		ReadinessCheck: healthz.CombineReadinessChecks(
			pgxpoolutil.ReadinessCheck(pool, pgxpoolutil.DefaultReadyTimeout),
			bridgeSettingsCache.Ready,
			chainReadinessCheck(baseClient),
		),

		Log: log,
	})
	if err != nil {
		log.Error("init backoffice server", "err", err)
		os.Exit(2)
	}
	defer srv.Close()

	httpSrv := &http.Server{
		Addr:              *listenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("backoffice listening", "addr", *listenAddr)
		errCh <- httpSrv.ListenAndServe()
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
	_ = httpSrv.Shutdown(shutdownCtx)
}

func splitCSVStrings(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		if value := strings.TrimSpace(part); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

type chainIDReader interface {
	ChainID(context.Context) (*big.Int, error)
}

func chainReadinessCheck(reader chainIDReader) func(context.Context) error {
	if reader == nil {
		return func(context.Context) error {
			return errors.New("backoffice: nil chain reader")
		}
	}
	return func(ctx context.Context) error {
		_, err := reader.ChainID(ctx)
		return err
	}
}
