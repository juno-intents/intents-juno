package main

import (
	"context"
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
	dlqpg "github.com/juno-intents/intents-juno/internal/dlq/postgres"
)

func main() {
	var (
		listenAddr  = flag.String("listen", ":8090", "HTTP listen address")
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")
		baseRPCURL  = flag.String("base-rpc-url", "", "Base chain RPC URL (required)")

		junoRPCURL  = flag.String("juno-rpc-url", "", "Juno RPC URL (optional, for MPC wallet balance)")
		junoRPCUser = flag.String("juno-rpc-user", "", "Juno RPC basic auth username")
		junoRPCPass = flag.String("juno-rpc-pass", "", "Juno RPC basic auth password")

		authSecret = flag.String("auth-secret", "", "Bearer token for API auth (required)")

		rateLimitPerSecond = flag.Float64("rate-limit-per-second", 5, "Per-IP rate limit refill rate")
		rateLimitBurst     = flag.Int("rate-limit-burst", 10, "Per-IP rate limit burst capacity")

		bridgeAddr      = flag.String("bridge-address", "", "Bridge contract address on Base (required)")
		wjunoAddr       = flag.String("wjuno-address", "", "wJUNO contract address on Base (required)")
		opRegistryAddr  = flag.String("operator-registry-address", "", "OperatorRegistry contract address (required)")
		feeDistAddr     = flag.String("fee-distributor-address", "", "FeeDistributor contract address (optional)")
		sp1RequestorStr = flag.String("sp1-requestor-address", "", "SP1 prover requestor address (optional)")
		sp1RPCURL       = flag.String("sp1-rpc-url", "", "SP1 prover network RPC URL (optional, for prover balance)")
		operatorAddrsRaw = flag.String("operator-addresses", "", "Comma-separated list of operator addresses")

		serviceURLsRaw = flag.String("service-urls", "", "Comma-separated list of service healthz URLs to poll")

		alertCheckInterval = flag.Duration("alert-check-interval", 30*time.Second, "Alert engine check interval")

		operatorGasMinWeiStr = flag.String("operator-gas-min-wei", "500000000000000000", "Min operator ETH balance (wei)")
		proverFundsMinWeiStr = flag.String("prover-funds-min-wei", "1000000000000000000", "Min prover ETH balance (wei)")
	)
	flag.Parse()

	// Suppress unused variable warning for alertCheckInterval.
	_ = alertCheckInterval

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Validate required flags.
	if *postgresDSN == "" {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn is required")
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

	// Parse service URLs.
	var serviceURLs []string
	if raw := strings.TrimSpace(*serviceURLsRaw); raw != "" {
		for _, s := range strings.Split(raw, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				serviceURLs = append(serviceURLs, s)
			}
		}
	}

	// Parse wei thresholds.
	operatorGasMinWei := new(big.Int)
	if _, ok := operatorGasMinWei.SetString(*operatorGasMinWeiStr, 10); !ok {
		fmt.Fprintln(os.Stderr, "error: --operator-gas-min-wei must be a valid integer")
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Connect to Postgres.
	pool, err := pgxpool.New(ctx, *postgresDSN)
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

	// Build server.
	srv, err := backoffice.New(backoffice.ServerConfig{
		Pool:       pool,
		BaseClient: baseClient,
		SP1RPCURL:  strings.TrimSpace(*sp1RPCURL),

		JunoRPCURL:  strings.TrimSpace(*junoRPCURL),
		JunoRPCUser: strings.TrimSpace(*junoRPCUser),
		JunoRPCPass: strings.TrimSpace(*junoRPCPass),

		DLQStore:   dlqStore,
		AlertStore: alertStore,

		BridgeAddress:           common.HexToAddress(*bridgeAddr),
		WJunoAddress:            common.HexToAddress(*wjunoAddr),
		OperatorRegistryAddress: common.HexToAddress(*opRegistryAddr),
		FeeDistributorAddress:   feeDistributor,
		SP1RequestorAddress:     sp1Requestor,
		OperatorAddresses:       operatorAddresses,

		ServiceURLs: serviceURLs,

		AuthSecret: *authSecret,

		RateLimitPerSecond: *rateLimitPerSecond,
		RateLimitBurst:     *rateLimitBurst,

		OperatorGasMinWei: operatorGasMinWei,
		ProverFundsMinWei: proverFundsMinWei,

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
