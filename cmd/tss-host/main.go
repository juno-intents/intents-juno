package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/emf"
	"github.com/juno-intents/intents-juno/internal/pgxpoolutil"
	"github.com/juno-intents/intents-juno/internal/tsshost"
	withdrawpg "github.com/juno-intents/intents-juno/internal/withdraw/postgres"
)

func main() {
	var signerArgs multiValueFlag

	var (
		listenAddr = flag.String("listen-addr", "127.0.0.1:8443", "listen address")

		tlsCertFile  = flag.String("tls-cert-file", "", "server TLS cert PEM file (required)")
		tlsKeyFile   = flag.String("tls-key-file", "", "server TLS key PEM file (required)")
		clientCAFile = flag.String("client-ca-file", "", "client CA PEM file (required for mTLS)")

		signerBin          = flag.String("signer-bin", "", "path to signer command binary (required; typically tss-signer)")
		signerMaxRespBytes = flag.Int("signer-max-response-bytes", 1<<20, "max signer response size (bytes)")

		maxBodyBytes   = flag.Int64("max-body-bytes", 1<<20, "max HTTP request body size (bytes)")
		maxTxPlanBytes = flag.Int("max-txplan-bytes", 1<<20, "max decoded txPlan size (bytes)")
		maxSessions    = flag.Int("max-sessions", 1024, "max in-memory sessions for idempotency")
		authTokenEnv   = flag.String("auth-token-env", "TSS_AUTH_TOKEN", "env var containing the shared bearer token for /v1/sign (required)")

		baseChainID = flag.Uint("base-chain-id", 0, "Base/EVM chain id used to validate withdrawal tx plans (required)")
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address used to validate withdrawal tx plans (required)")

		postgresDSN               = flag.String("postgres-dsn", "", "Postgres DSN (required unless --postgres-dsn-env is set)")
		postgresDSNEnv            = flag.String("postgres-dsn-env", "", "env var containing Postgres DSN (required unless --postgres-dsn is set)")
		postgresMinConns          = flag.Int("postgres-min-conns", int(pgxpoolutil.DefaultMinConns), "minimum pgxpool connections")
		postgresMaxConns          = flag.Int("postgres-max-conns", int(pgxpoolutil.DefaultMaxConns), "maximum pgxpool connections")
		postgresHealthCheckPeriod = flag.Duration("postgres-health-check-period", pgxpoolutil.DefaultHealthCheckPeriod, "pgxpool health check period")

		readHeaderTimeout = flag.Duration("read-header-timeout", 5*time.Second, "http.Server ReadHeaderTimeout")
		readTimeout       = flag.Duration("read-timeout", 120*time.Second, "http.Server ReadTimeout")
		writeTimeout      = flag.Duration("write-timeout", 120*time.Second, "http.Server WriteTimeout")
		idleTimeout       = flag.Duration("idle-timeout", 120*time.Second, "http.Server IdleTimeout")
	)
	flag.Var(&signerArgs, "signer-arg", "argument passed to signer binary (repeatable)")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	metricsEmitter, err := emf.New(emf.Config{
		Namespace: emf.OperationsNamespace,
		Writer:    os.Stdout,
		Now:       time.Now,
		Fields: map[string]any{
			"service": "tss-host",
		},
	})
	if err != nil {
		log.Error("init metrics emitter", "err", err)
		os.Exit(2)
	}

	if *listenAddr == "" {
		log.Error("missing --listen-addr")
		os.Exit(2)
	}
	if *maxBodyBytes <= 0 || *maxTxPlanBytes <= 0 || *maxSessions <= 0 {
		log.Error("invalid size limits")
		os.Exit(2)
	}
	if *signerMaxRespBytes <= 0 {
		log.Error("invalid signer limits")
		os.Exit(2)
	}
	if *signerBin == "" {
		log.Error("missing --signer-bin")
		os.Exit(2)
	}
	authToken := strings.TrimSpace(os.Getenv(strings.TrimSpace(*authTokenEnv)))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	resolvedPostgresDSN, err := pgxpoolutil.ResolveDSN(*postgresDSN, *postgresDSNEnv)
	if err != nil {
		log.Error("resolve postgres dsn", "err", err)
		os.Exit(2)
	}
	if err := validateSecureTSSHostConfig(secureTSSHostConfig{
		ListenAddr:   *listenAddr,
		ClientCAFile: *clientCAFile,
		AuthToken:    authToken,
		BaseChainID:  *baseChainID,
		BridgeAddr:   *bridgeAddr,
		PostgresDSN:  resolvedPostgresDSN,
	}); err != nil {
		log.Error("invalid secure config", "err", err)
		os.Exit(2)
	}

	signer, err := tsshost.NewExecSigner(*signerBin, signerArgs.Values(), *signerMaxRespBytes)
	if err != nil {
		log.Error("init signer", "err", err)
		os.Exit(2)
	}

	var (
		pool     *pgxpool.Pool
		verifier tsshost.Verifier
		dbReady  func(context.Context) error
	)
	poolCfg, cfgErr := pgxpoolutil.ParseConfig(resolvedPostgresDSN, pgxpoolutil.Settings{
		MinConns:          int32(*postgresMinConns),
		MaxConns:          int32(*postgresMaxConns),
		HealthCheckPeriod: *postgresHealthCheckPeriod,
	})
	if cfgErr != nil {
		log.Error("parse pgx pool config", "err", cfgErr)
		os.Exit(2)
	}
	pool, err = pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Error("connect postgres", "err", err)
		os.Exit(2)
	}
	defer pool.Close()

	withdrawStore, storeErr := withdrawpg.New(pool)
	if storeErr != nil {
		log.Error("init withdraw store", "err", storeErr)
		os.Exit(2)
	}
	verifier = tsshost.NewWithdrawBatchVerifier(withdrawStore, tsshost.WithdrawBatchVerifierConfig{
		BaseChainID:   uint32(*baseChainID),
		BridgeAddress: common.HexToAddress(strings.TrimSpace(*bridgeAddr)),
	})
	dbReady = pgxpoolutil.ReadinessCheck(pool, pgxpoolutil.DefaultReadyTimeout)
	if verifier == nil {
		log.Error("missing withdrawal verifier configuration")
		os.Exit(2)
	}

	h := tsshost.NewHandler(signer, tsshost.Config{
		MaxBodyBytes:   *maxBodyBytes,
		MaxTxPlanBytes: *maxTxPlanBytes,
		MaxSessions:    *maxSessions,
		ReadinessCheck: combineReadinessChecks(signerReadinessCheck(signer), dbReady),
		Verifier:       verifier,
		AuthToken:      authToken,
		Now:            time.Now,
	})

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           h,
		ReadHeaderTimeout: *readHeaderTimeout,
		ReadTimeout:       *readTimeout,
		WriteTimeout:      *writeTimeout,
		IdleTimeout:       *idleTimeout,
		MaxHeaderBytes:    1 << 20,
	}

	if reporter, ok := h.(interface {
		MetricsSnapshot() tsshost.MetricsSnapshot
	}); ok {
		go emitTSSMetricsLoop(ctx, reporter, metricsEmitter, 15*time.Second, log)
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("tss-host starting", "addr", *listenAddr, "tls", true, "mtls", true, "batch_verifier", verifier != nil)
		tlsCfg, err := buildTLSConfig(*tlsCertFile, *tlsKeyFile, *clientCAFile)
		if err != nil {
			errCh <- err
			return
		}
		srv.TLSConfig = tlsCfg
		errCh <- srv.ListenAndServeTLS("", "")
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown", "reason", ctx.Err())
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}

func buildTLSConfig(certFile string, keyFile string, clientCAFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("missing --tls-cert-file/--tls-key-file")
	}
	if clientCAFile == "" {
		return nil, fmt.Errorf("missing --client-ca-file")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}

	caPEM, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client ca file: %w", err)
	}
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caPEM); !ok {
		return nil, fmt.Errorf("parse client ca file")
	}
	cfg.ClientCAs = pool
	cfg.ClientAuth = tls.RequireAndVerifyClientCert

	return cfg, nil
}

func validatePrivateListenAddr(addr string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("parse listen addr: %w", err)
	}
	switch host {
	case "", "0.0.0.0", "::":
		return fmt.Errorf("listen host %q must not be wildcard", host)
	case "localhost":
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("listen host %q must be localhost or an IP literal", host)
	}
	if ip.IsLoopback() || ip.IsPrivate() {
		return nil
	}
	return fmt.Errorf("listen host %q must be loopback or private", host)
}

type secureTSSHostConfig struct {
	ListenAddr   string
	ClientCAFile string
	AuthToken    string
	BaseChainID  uint
	BridgeAddr   string
	PostgresDSN  string
}

func validateSecureTSSHostConfig(cfg secureTSSHostConfig) error {
	if strings.TrimSpace(cfg.ClientCAFile) == "" {
		return fmt.Errorf("missing --client-ca-file")
	}
	if err := validatePrivateListenAddr(cfg.ListenAddr); err != nil {
		return fmt.Errorf("invalid --listen-addr: %w", err)
	}
	if strings.TrimSpace(cfg.AuthToken) == "" {
		return fmt.Errorf("missing auth token env")
	}
	if cfg.BaseChainID == 0 {
		return fmt.Errorf("missing --base-chain-id")
	}
	if !common.IsHexAddress(strings.TrimSpace(cfg.BridgeAddr)) {
		return fmt.Errorf("invalid --bridge-address")
	}
	if strings.TrimSpace(cfg.PostgresDSN) == "" {
		return fmt.Errorf("missing postgres dsn")
	}
	return nil
}

type readyChecker interface {
	Ready(context.Context) error
}

func signerReadinessCheck(signer any) func(context.Context) error {
	ready, ok := signer.(readyChecker)
	if !ok {
		return nil
	}
	return ready.Ready
}

func combineReadinessChecks(checks ...func(context.Context) error) func(context.Context) error {
	filtered := make([]func(context.Context) error, 0, len(checks))
	for _, check := range checks {
		if check != nil {
			filtered = append(filtered, check)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return func(ctx context.Context) error {
		for _, check := range filtered {
			if err := check(ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

func emitTSSMetricsLoop(
	ctx context.Context,
	reporter interface {
		MetricsSnapshot() tsshost.MetricsSnapshot
	},
	emitter *emf.Emitter,
	interval time.Duration,
	log *slog.Logger,
) {
	emit := func() {
		if err := emitTSSMetrics(reporter, emitter); err != nil && log != nil {
			log.Warn("emit tss metrics", "err", err)
		}
	}
	emit()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			emit()
		}
	}
}

func emitTSSMetrics(
	reporter interface {
		MetricsSnapshot() tsshost.MetricsSnapshot
	},
	emitter *emf.Emitter,
) error {
	if reporter == nil || emitter == nil {
		return nil
	}
	snapshot := reporter.MetricsSnapshot()
	saturation := 0.0
	if snapshot.SessionCapacity > 0 {
		saturation = float64(snapshot.SessionCount) / float64(snapshot.SessionCapacity)
	}
	return emitter.Emit(
		emf.Metric{Name: "TSSSessionCount", Unit: emf.UnitCount, Value: float64(snapshot.SessionCount)},
		emf.Metric{Name: "TSSSessionSaturation", Unit: emf.UnitNone, Value: saturation},
	)
}

type multiValueFlag struct {
	values []string
}

func (m *multiValueFlag) String() string {
	if m == nil {
		return ""
	}
	return strings.Join(m.values, ",")
}

func (m *multiValueFlag) Set(v string) error {
	if m == nil {
		return fmt.Errorf("invalid flag receiver")
	}
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("flag value cannot be blank")
	}
	m.values = append(m.values, v)
	return nil
}

func (m *multiValueFlag) Values() []string {
	if m == nil {
		return nil
	}
	out := make([]string, len(m.values))
	copy(out, m.values)
	return out
}
