package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/juno-intents/intents-juno/internal/blobstore"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/healthz"
	"github.com/juno-intents/intents-juno/internal/junorpc"
	leasespg "github.com/juno-intents/intents-juno/internal/leases/postgres"
	"github.com/juno-intents/intents-juno/internal/pgxpoolutil"
	"github.com/juno-intents/intents-juno/internal/policy"
	"github.com/juno-intents/intents-juno/internal/queue"
	"github.com/juno-intents/intents-juno/internal/runtimeconfig"
	"github.com/juno-intents/intents-juno/internal/tss"
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
	// Optional per-withdrawal witness payload for binary withdraw guest input.
	ProofWitnessItem string `json:"proofWitnessItem,omitempty"`
	Expiry           uint64 `json:"expiry"` // unix seconds
	FeeBps           uint32 `json:"feeBps"`
}

type withdrawRequestedV2 struct {
	Version string `json:"version"`

	WithdrawalID string `json:"withdrawalId"`
	Requester    string `json:"requester"`
	Amount       uint64 `json:"amount"`

	RecipientUA      string `json:"recipientUA"`
	ProofWitnessItem string `json:"proofWitnessItem,omitempty"`
	Expiry           uint64 `json:"expiry"`
	FeeBps           uint32 `json:"feeBps"`
	BlockNumber      uint64 `json:"blockNumber"`
	BlockHash        string `json:"blockHash"`
	TxHash           string `json:"txHash"`
	LogIndex         uint   `json:"logIndex"`
	FinalitySource   string `json:"finalitySource"`
}

type withdrawRequestedMessage struct {
	Version          string
	WithdrawalID     string
	Requester        string
	Amount           uint64
	RecipientUA      string
	ProofWitnessItem string
	Expiry           uint64
	FeeBps           uint32
	BlockNumber      uint64
	BlockHash        string
	TxHash           string
	LogIndex         uint
	FinalitySource   string
}

const (
	runtimeModeFull = "full"
)

func main() {
	var (
		postgresDSN               = flag.String("postgres-dsn", "", "Postgres DSN (required unless --postgres-dsn-env is set)")
		postgresDSNEnv            = flag.String("postgres-dsn-env", "", "env var containing Postgres DSN (required unless --postgres-dsn is set)")
		postgresMinConns          = flag.Int("postgres-min-conns", int(pgxpoolutil.DefaultMinConns), "minimum pgxpool connections")
		postgresMaxConns          = flag.Int("postgres-max-conns", int(pgxpoolutil.DefaultMaxConns), "maximum pgxpool connections")
		postgresHealthCheckPeriod = flag.Duration(
			"postgres-health-check-period",
			pgxpoolutil.DefaultHealthCheckPeriod,
			"pgxpool health check period",
		)
		runtimeMode = flag.String("runtime-mode", runtimeModeFull, "coordinator runtime mode (production binary supports only: full)")

		maxItems             = flag.Int("max-items", 50, "maximum withdrawals per Juno payout tx")
		maxAge               = flag.Duration("max-age", 3*time.Minute, "maximum batch age before flushing")
		claimTTL             = flag.Duration("claim-ttl", 30*time.Second, "per-withdrawal claim TTL in DB")
		tickInterval         = flag.Duration("tick-interval", 1*time.Second, "coordinator tick interval")
		rebroadcastBaseDelay = flag.Duration("rebroadcast-base-delay", 30*time.Second, "minimum delay before retrying a missing Juno tx")
		rebroadcastMaxDelay  = flag.Duration("rebroadcast-max-delay", 10*time.Minute, "maximum delay before retrying a missing Juno tx")

		leaderElection  = flag.Bool("leader-election", true, "enable leader election via DB lease")
		leaderLeaseName = flag.String("leader-lease-name", "withdraw-coordinator", "lease name used for leader election")
		leaderLeaseTTL  = flag.Duration("leader-lease-ttl", 15*time.Second, "leader lease TTL (renewed each tick)")

		safetyMargin   = flag.Duration("expiry-safety-margin", policy.DefaultWithdrawExpirySafetyMargin, "minimum time-to-expiry required to broadcast")
		maxExtension   = flag.Duration("max-expiry-extension", 12*time.Hour, "max per-withdrawal expiry extension allowed by contract")
		maxExtendBatch = flag.Int("max-extend-batch", policy.DefaultMaxExtendBatch, "max withdrawal ids per extendWithdrawExpiryBatch call")

		owner = flag.String("owner", "", "unique coordinator owner id (required; used for DB claims)")

		queueDriver   = flag.String("queue-driver", queue.DriverKafka, "queue driver: kafka|stdio")
		queueBrokers  = flag.String("queue-brokers", "", "comma-separated queue brokers (required for kafka)")
		queueGroup    = flag.String("queue-group", "withdraw-coordinator", "queue consumer group (required for kafka)")
		queueTopics   = flag.String("queue-topics", "withdrawals.requested.v2", "comma-separated queue topics")
		maxLineBytes  = flag.Int("max-line-bytes", 1<<20, "maximum stdin line size for stdio driver (bytes)")
		queueMaxBytes = flag.Int("queue-max-bytes", 10<<20, "maximum kafka message size for consumer reads (bytes)")
		ackTimeout    = flag.Duration("queue-ack-timeout", 5*time.Second, "timeout for queue message acknowledgements")

		blobDriver     = flag.String("blob-driver", blobstore.DriverS3, "blobstore driver: s3|memory")
		blobBucket     = flag.String("blob-bucket", "", "S3 bucket for durable withdrawal artifacts (required for s3)")
		blobPrefix     = flag.String("blob-prefix", "withdraw-coordinator", "blob key prefix")
		blobMaxGetSize = flag.Int64("blob-max-get-size", 16<<20, "max blob get size in bytes")

		// Planner (juno-txbuild)
		txbuildBin              = flag.String("juno-txbuild-bin", "juno-txbuild", "path to juno-txbuild binary")
		junoWalletID            = flag.String("juno-wallet-id", "", "juno-txbuild wallet id (required)")
		junoChangeAddress       = flag.String("juno-change-address", "", "juno-txbuild change address (required)")
		junoCoinType            = flag.Uint("juno-coin-type", 0, "ZIP-32 coin type for juno-txbuild")
		junoAccount             = flag.Uint("juno-account", 0, "unified account id for juno-txbuild")
		junoMinConf             = flag.Int64("juno-minconf", 1, "minimum confirmations for juno-txbuild input note selection")
		junoExpiryOffset        = flag.Uint("juno-expiry-offset", 40, "juno tx expiry offset (min 4)")
		junoFeeMultiplier       = flag.Uint64("juno-fee-multiplier", 1, "juno-txbuild fee multiplier")
		junoFeeAddZat           = flag.Uint64("juno-fee-add-zat", 0, "juno-txbuild extra absolute fee")
		junoMinChangeZat        = flag.Uint64("juno-min-change-zat", 0, "juno-txbuild min change amount")
		junoMinNoteZat          = flag.Uint64("juno-min-note-zat", 0, "juno-txbuild min note amount")
		junoScanURL             = flag.String("juno-scan-url", "", "optional juno-scan URL for juno-txbuild")
		junoScanBearerEnv       = flag.String("juno-scan-bearer-env", "JUNO_SCAN_BEARER_TOKEN", "env var for optional juno-scan bearer token")
		depositMinConfirmations = flag.Int64("deposit-min-confirmations", 1, "default deposit confirmations used to seed runtime settings")

		// Juno RPC (broadcast + confirm)
		junoRPCURL        = flag.String("juno-rpc-url", "", "junocashd JSON-RPC URL (required)")
		junoRPCUserEnv    = flag.String("juno-rpc-user-env", "JUNO_RPC_USER", "env var containing junocashd RPC username")
		junoRPCPassEnv    = flag.String("juno-rpc-pass-env", "JUNO_RPC_PASS", "env var containing junocashd RPC password")
		junoRPCTimeout    = flag.Duration("juno-rpc-timeout", 10*time.Second, "junocashd RPC timeout")
		junoRPCMaxResp    = flag.Int64("juno-rpc-max-response-bytes", 5<<20, "max bytes in junocashd RPC response")
		junoConfirmations = flag.Int64("juno-confirmations", 1, "required Juno confirmations before marking batch confirmed")
		junoConfirmPoll   = flag.Duration("juno-confirm-poll", 5*time.Second, "poll interval while waiting for Juno confirmations")
		junoConfirmWait   = flag.Duration("juno-confirm-max-wait", 30*time.Second, "maximum wait per confirmation check before yielding pending/missing status")

		// Signer (tss-host)
		tssURL            = flag.String("tss-url", "", "tss-host base url (required; must be https unless --tss-insecure-http)")
		tssInsecureHTTP   = flag.Bool("tss-insecure-http", false, "allow tss-url over plain http (DANGEROUS; dev only)")
		tssTimeout        = flag.Duration("tss-timeout", 120*time.Second, "tss request timeout")
		tssMaxRespBytes   = flag.Int64("tss-max-response-bytes", 1<<20, "max tss response size (bytes)")
		tssServerCAFile   = flag.String("tss-server-ca-file", "", "server root CA PEM file (optional; defaults to system roots)")
		tssServerName     = flag.String("tss-server-name", "", "optional TLS server name override for tss-url certificate validation")
		tssClientCertFile = flag.String("tss-client-cert-file", "", "client cert PEM file (optional; for mTLS)")
		tssClientKeyFile  = flag.String("tss-client-key-file", "", "client key PEM file (optional; for mTLS)")

		// Base expiry extension path
		baseChainID         = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		bridgeAddr          = flag.String("bridge-address", "", "Bridge contract address (required)")
		baseRelayerURL      = flag.String("base-relayer-url", "", "base-relayer HTTP URL (required)")
		baseRelayerAuthEnv  = flag.String("base-relayer-auth-env", "BASE_RELAYER_AUTH_TOKEN", "env var containing base-relayer bearer auth token")
		baseRelayerTimeout  = flag.Duration("base-relayer-timeout", 30*time.Second, "base-relayer timeout")
		extendGasLimit      = flag.Uint64("extend-gas-limit", 0, "optional gas limit override for extendWithdrawExpiryBatch")
		extendSignerBin     = flag.String("extend-signer-bin", "", "path to external extend signer binary (required; must support `sign-digest --digest <0x..> --json`)")
		extendSignerMaxResp = flag.Int("extend-signer-max-response-bytes", 1<<20, "max extend signer response size (bytes)")

		healthPort = flag.Int("health-port", 0, "HTTP port for /livez, /readyz, and /healthz endpoints (0 = disabled)")
	)
	flag.Parse()
	mode, err := normalizeRuntimeMode(*runtimeMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	postgresDSNValue, err := resolveRequiredFlagOrEnv("--postgres-dsn", *postgresDSN, *postgresDSNEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	devMode := devModeEnabled()

	if *owner == "" {
		fmt.Fprintln(os.Stderr, "error: --owner is required")
		os.Exit(2)
	}
	if mode == runtimeModeFull {
		if *junoRPCURL == "" || *tssURL == "" {
			fmt.Fprintln(os.Stderr, "error: --juno-rpc-url and --tss-url are required")
			os.Exit(2)
		}
		if *junoWalletID == "" || *junoChangeAddress == "" {
			fmt.Fprintln(os.Stderr, "error: --juno-wallet-id and --juno-change-address are required")
			os.Exit(2)
		}
		if *baseChainID == 0 || *bridgeAddr == "" || *baseRelayerURL == "" {
			fmt.Fprintln(os.Stderr, "error: --base-chain-id, --bridge-address, and --base-relayer-url are required")
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
	}
	if *maxItems <= 0 || *maxExtendBatch <= 0 || *maxLineBytes <= 0 || *queueMaxBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-items, --max-extend-batch, --max-line-bytes, and --queue-max-bytes must be > 0")
		os.Exit(2)
	}
	if *maxAge <= 0 || *claimTTL <= 0 || *tickInterval <= 0 || *safetyMargin <= 0 || *maxExtension <= 0 {
		fmt.Fprintln(os.Stderr, "error: durations must be > 0")
		os.Exit(2)
	}
	if *rebroadcastBaseDelay <= 0 || *rebroadcastMaxDelay <= 0 || *rebroadcastMaxDelay < *rebroadcastBaseDelay {
		fmt.Fprintln(os.Stderr, "error: rebroadcast delays must be > 0 and max >= base")
		os.Exit(2)
	}
	if *leaderLeaseTTL <= 0 {
		fmt.Fprintln(os.Stderr, "error: --leader-lease-ttl must be > 0")
		os.Exit(2)
	}
	if mode == runtimeModeFull {
		if *junoConfirmations <= 0 || *junoConfirmPoll <= 0 || *junoConfirmWait <= 0 || *junoRPCTimeout <= 0 || *junoRPCMaxResp <= 0 {
			fmt.Fprintln(os.Stderr, "error: juno rpc and confirmation settings must be > 0")
			os.Exit(2)
		}
		if *junoMinConf <= 0 || *junoExpiryOffset < 4 || *junoFeeMultiplier == 0 {
			fmt.Fprintln(os.Stderr, "error: juno txbuild settings invalid (--juno-minconf > 0, --juno-expiry-offset >= 4, --juno-fee-multiplier >= 1)")
			os.Exit(2)
		}
		if *depositMinConfirmations <= 0 {
			fmt.Fprintln(os.Stderr, "error: --deposit-min-confirmations must be > 0")
			os.Exit(2)
		}
		if *baseRelayerTimeout <= 0 {
			fmt.Fprintln(os.Stderr, "error: --base-relayer-timeout must be > 0")
			os.Exit(2)
		}
		if *extendSignerBin == "" || *extendSignerMaxResp <= 0 {
			fmt.Fprintln(os.Stderr, "error: --extend-signer-bin is required and --extend-signer-max-response-bytes must be > 0")
			os.Exit(2)
		}
		if *tssInsecureHTTP && !devMode {
			fmt.Fprintln(os.Stderr, "error: --tss-insecure-http requires JUNO_DEV_MODE=true")
			os.Exit(2)
		}
		if !devMode {
			if strings.TrimSpace(*tssServerCAFile) == "" {
				fmt.Fprintln(os.Stderr, "error: --tss-server-ca-file is required in production mode")
				os.Exit(2)
			}
			if strings.TrimSpace(*tssClientCertFile) == "" || strings.TrimSpace(*tssClientKeyFile) == "" {
				fmt.Fprintln(os.Stderr, "error: --tss-client-cert-file and --tss-client-key-file are required in production mode")
				os.Exit(2)
			}
		}
	}
	if *ackTimeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: --queue-ack-timeout must be > 0")
		os.Exit(2)
	}
	if *blobMaxGetSize <= 0 {
		fmt.Fprintln(os.Stderr, "error: --blob-max-get-size must be > 0")
		os.Exit(2)
	}
	if normalizeBlobDriver(*blobDriver) == blobstore.DriverS3 && strings.TrimSpace(*blobBucket) == "" {
		fmt.Fprintln(os.Stderr, "error: --blob-bucket is required when --blob-driver=s3")
		os.Exit(2)
	}

	junoRPCUser := ""
	junoRPCPass := ""
	baseRelayerAuth := ""
	scanBearerToken := ""
	if mode == runtimeModeFull {
		junoRPCUser = os.Getenv(*junoRPCUserEnv)
		junoRPCPass = os.Getenv(*junoRPCPassEnv)
		if junoRPCUser == "" || junoRPCPass == "" {
			fmt.Fprintf(os.Stderr, "error: missing junocashd RPC credentials in env %s/%s\n", *junoRPCUserEnv, *junoRPCPassEnv)
			os.Exit(2)
		}
		baseRelayerAuth = os.Getenv(*baseRelayerAuthEnv)
		if baseRelayerAuth == "" {
			fmt.Fprintf(os.Stderr, "error: missing base-relayer auth token in env %s\n", *baseRelayerAuthEnv)
			os.Exit(2)
		}
		scanBearerToken = strings.TrimSpace(os.Getenv(*junoScanBearerEnv))
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
		KafkaLogger:   &slogKafkaLogger{log},
	})
	if err != nil {
		log.Error("init queue consumer", "err", err)
		os.Exit(2)
	}
	defer func() { _ = consumer.Close() }()

	poolCfg, err := pgxpoolutil.ParseConfig(strings.TrimSpace(postgresDSNValue), pgxpoolutil.Settings{
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

	store, err := withdrawpg.New(pool)
	if err != nil {
		log.Error("init withdraw store", "err", err)
		os.Exit(2)
	}
	if err := store.EnsureSchema(ctx); err != nil {
		log.Error("ensure schema", "err", err)
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
		WithdrawPlannerMinConfirmations: *junoMinConf,
		WithdrawBatchConfirmations:      *junoConfirmations,
	}, "withdraw-coordinator"); err != nil {
		log.Error("ensure runtime settings defaults", "err", err)
		os.Exit(2)
	}
	runtimeSettingsCache, err := runtimeconfig.NewCache(runtimeStore, 5*time.Second, log)
	if err != nil {
		log.Error("init runtime settings cache", "err", err)
		os.Exit(2)
	}
	go runtimeSettingsCache.Start(ctx)

	artifactStore, err := newBlobStore(ctx, *blobDriver, *blobBucket, *blobPrefix, *blobMaxGetSize)
	if err != nil {
		log.Error("init blob store", "err", err)
		os.Exit(2)
	}

	var (
		planner     withdrawcoordinator.Planner
		signer      withdrawcoordinator.Signer
		broadcaster withdrawcoordinator.Broadcaster
		confirmer   withdrawcoordinator.Confirmer
		extender    withdrawcoordinator.ExpiryExtender
		paidMarker  withdrawcoordinator.PaidMarker
	)
	txBuildPlanner, err := withdrawcoordinator.NewTxBuildPlanner(withdrawcoordinator.TxBuildPlannerConfig{
		Binary:           *txbuildBin,
		WalletID:         *junoWalletID,
		ChangeAddress:    *junoChangeAddress,
		BaseChainID:      uint32(*baseChainID),
		BridgeAddress:    common.HexToAddress(*bridgeAddr),
		CoinType:         uint32(*junoCoinType),
		Account:          uint32(*junoAccount),
		MinConfirmations: *junoMinConf,
		ExpiryOffset:     uint32(*junoExpiryOffset),
		FeeMultiplier:    *junoFeeMultiplier,
		FeeAddZat:        *junoFeeAddZat,
		MinChangeZat:     *junoMinChangeZat,
		MinNoteZat:       *junoMinNoteZat,
		RPCURL:           *junoRPCURL,
		RPCUser:          junoRPCUser,
		RPCPass:          junoRPCPass,
		ScanURL:          *junoScanURL,
		ScanBearerToken:  scanBearerToken,
	})
	if err != nil {
		log.Error("init txbuild planner", "err", err)
		os.Exit(2)
	}
	planner = txBuildPlanner.WithRuntimeSettings(runtimeSettingsCache)

	tssHTTPClient, err := newTSSHTTPClient(*tssTimeout, *tssServerCAFile, *tssClientCertFile, *tssClientKeyFile, *tssServerName)
	if err != nil {
		log.Error("init tss http client", "err", err)
		os.Exit(2)
	}

	tssOpts := []tss.Option{
		tss.WithHTTPClient(tssHTTPClient),
		tss.WithMaxResponseBytes(*tssMaxRespBytes),
	}
	if *tssInsecureHTTP {
		tssOpts = append(tssOpts, tss.WithInsecureHTTP())
	}
	signer, err = tss.NewClient(*tssURL, tssOpts...)
	if err != nil {
		log.Error("init tss client", "err", err)
		os.Exit(2)
	}

	junoClient, err := junorpc.New(*junoRPCURL, junoRPCUser, junoRPCPass,
		junorpc.WithTimeout(*junoRPCTimeout),
		junorpc.WithMaxResponseBytes(*junoRPCMaxResp),
	)
	if err != nil {
		log.Error("init junocashd rpc", "err", err)
		os.Exit(2)
	}

	broadcaster, err = withdrawcoordinator.NewJunoBroadcaster(junoClient)
	if err != nil {
		log.Error("init juno broadcaster", "err", err)
		os.Exit(2)
	}
	junoConfirmer, err := withdrawcoordinator.NewJunoConfirmer(junoClient, *junoConfirmations, *junoConfirmPoll, *junoConfirmWait)
	if err != nil {
		log.Error("init juno confirmer", "err", err)
		os.Exit(2)
	}
	confirmer = junoConfirmer.WithRuntimeSettings(runtimeSettingsCache)

	baseClient, err := httpapi.NewClient(*baseRelayerURL, baseRelayerAuth, httpapi.WithHTTPClient(&http.Client{Timeout: *baseRelayerTimeout}))
	if err != nil {
		log.Error("init base-relayer client", "err", err)
		os.Exit(2)
	}
	extendSigner, err := withdrawcoordinator.NewExecExtendSigner(*extendSignerBin, *extendSignerMaxResp)
	if err != nil {
		log.Error("init extend signer", "err", err)
		os.Exit(2)
	}
	extender, err = withdrawcoordinator.NewBaseExpiryExtender(withdrawcoordinator.BaseExpiryExtenderConfig{
		BaseChainID:   *baseChainID,
		BridgeAddress: common.HexToAddress(*bridgeAddr),
		GasLimit:      *extendGasLimit,
	}, baseClient, extendSigner)
	if err != nil {
		log.Error("init expiry extender", "err", err)
		os.Exit(2)
	}
	paidMarker, err = withdrawcoordinator.NewBasePaidMarker(withdrawcoordinator.BasePaidMarkerConfig{
		BaseChainID:   *baseChainID,
		BridgeAddress: common.HexToAddress(*bridgeAddr),
		GasLimit:      *extendGasLimit,
	}, baseClient, extendSigner)
	if err != nil {
		log.Error("init paid marker", "err", err)
		os.Exit(2)
	}

	var elector *withdrawcoordinator.LeaderElector
	if *leaderElection {
		leaseStore, err := leasespg.New(pool)
		if err != nil {
			log.Error("init lease store", "err", err)
			os.Exit(2)
		}
		if err := leaseStore.EnsureSchema(ctx); err != nil {
			log.Error("ensure lease schema", "err", err)
			os.Exit(2)
		}
		readinessChecker := readinessFunc(func(ctx context.Context) error {
			return healthz.CombineReadinessChecks(baseClient.Ready, runtimeSettingsCache.Ready)(ctx)
		})
		elector, err = withdrawcoordinator.NewLeaderElector(
			leaseStore,
			*leaderLeaseName,
			*owner,
			*leaderLeaseTTL,
			withdrawcoordinator.WithReadinessChecker(readinessChecker),
		)
		if err != nil {
			log.Error("init leader elector", "err", err)
			os.Exit(2)
		}
	}

	coord, err := withdrawcoordinator.New(withdrawcoordinator.Config{
		Owner:                *owner,
		MaxItems:             *maxItems,
		MaxAge:               *maxAge,
		ClaimTTL:             *claimTTL,
		RebroadcastBaseDelay: *rebroadcastBaseDelay,
		RebroadcastMaxDelay:  *rebroadcastMaxDelay,
		ExpiryPolicy: policy.WithdrawExpiryConfig{
			SafetyMargin: *safetyMargin,
			MaxExtension: *maxExtension,
			MaxBatch:     *maxExtendBatch,
		},
		Now: time.Now,
	}, store, planner, signer, broadcaster, confirmer, junoConfirmer, log)
	if err != nil {
		log.Error("init coordinator", "err", err)
		os.Exit(2)
	}
	if extender != nil {
		coord.WithExpiryExtender(extender)
	}
	if paidMarker != nil {
		coord.WithPaidMarker(paidMarker)
	}
	coord.WithBlobStore(artifactStore)

	go func() {
		if err := healthz.ListenAndServe(
			ctx,
			healthz.ListenAddr(*healthPort),
			"withdraw-coordinator",
			healthz.WithReadinessCheck(healthz.CombineReadinessChecks(
				pgxpoolutil.ReadinessCheck(pool, pgxpoolutil.DefaultReadyTimeout),
				baseClient.Ready,
				runtimeSettingsCache.Ready,
			)),
		); err != nil {
			log.Error("healthz server", "err", err)
		}
	}()

	log.Info("withdraw coordinator started",
		"runtimeMode", mode,
		"owner", *owner,
		"maxItems", *maxItems,
		"maxAge", maxAge.String(),
		"claimTTL", claimTTL.String(),
		"tickInterval", tickInterval.String(),
		"junoRPC", *junoRPCURL,
		"junoConfirmations", *junoConfirmations,
		"baseChainID", *baseChainID,
		"bridge", common.HexToAddress(*bridgeAddr),
		"queueDriver", *queueDriver,
		"blobDriver", normalizeBlobDriver(*blobDriver),
		"blobBucket", strings.TrimSpace(*blobBucket),
		"blobPrefix", strings.TrimSpace(*blobPrefix),
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
			if elector != nil {
				leader, err := elector.Tick(ctx)
				if err != nil {
					log.Error("leader election tick", "err", err)
					continue
				}
				if !leader {
					log.Info("not leader, skipping tick")
					continue
				}
			}

			if err := coord.Tick(ctx); err != nil {
				if errors.Is(err, withdrawcoordinator.ErrRebroadcastExhausted) {
					log.Error("CRITICAL: rebroadcast attempts exhausted, manual intervention required", "err", err)
				} else {
					log.Error("tick", "err", err)
				}
			}
		case qmsg, ok := <-msgCh:
			if !ok {
				return
			}
			log.Info("queue message received", "topic", qmsg.Topic, "len", len(qmsg.Value))
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
			case "withdrawals.requested.v1", "withdrawals.requested.v2":
				reqMsg, err := parseWithdrawRequestedMessage(line)
				if err != nil {
					log.Error("parse withdraw requested", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				id, err := parseHash32(reqMsg.WithdrawalID)
				if err != nil {
					log.Error("parse withdrawalId", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				requester, err := parseAddr20(reqMsg.Requester)
				if err != nil {
					log.Error("parse requester", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				ua, err := decodeHexBytes(reqMsg.RecipientUA)
				if err != nil {
					log.Error("parse recipientUA", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				// The ZK circuit requires exactly 43 bytes (raw Orchard receiver:
				// 11-byte diversifier + 32-byte pk_d). Reject anything else to
				// prevent batches that the finalizer cannot process.
				const orchardRawReceiverLen = 43
				if len(ua) != orchardRawReceiverLen {
					log.Error("reject withdrawal: recipientUA must be 43 bytes (raw Orchard receiver)",
						"got_len", len(ua),
						"withdrawal_id", reqMsg.WithdrawalID,
					)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				proofWitnessItem, err := decodeHexBytesOptional(reqMsg.ProofWitnessItem)
				if err != nil {
					log.Error("parse proofWitnessItem", "err", err)
					ackMessage(qmsg, *ackTimeout, log)
					continue
				}
				expiry := time.Unix(int64(reqMsg.Expiry), 0).UTC()

				w := withdraw.Withdrawal{
					ID:               id,
					Requester:        requester,
					Amount:           reqMsg.Amount,
					FeeBps:           reqMsg.FeeBps,
					RecipientUA:      ua,
					ProofWitnessItem: proofWitnessItem,
					Expiry:           expiry,
				}

				cctx, cancel := withTimeout(ctx, 5*time.Second)
				err = coord.IngestWithdrawRequested(cctx, w)
				cancel()
				if err != nil {
					log.Error("ingest withdrawal", "err", err)
					if shouldAckWithdrawIngestError(err) {
						ackMessage(qmsg, *ackTimeout, log)
					} else {
						log.Warn("leaving withdrawal message unacked for retry", "id", reqMsg.WithdrawalID, "err", err)
					}
					continue
				}
				log.Info("withdrawal ingested", "id", reqMsg.WithdrawalID, "amount", reqMsg.Amount)
				ackMessage(qmsg, *ackTimeout, log)

			default:
				ackMessage(qmsg, *ackTimeout, log)
				continue
			}
		}
	}
}

func parseWithdrawRequestedMessage(line []byte) (withdrawRequestedMessage, error) {
	var env envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return withdrawRequestedMessage{}, err
	}

	switch env.Version {
	case "withdrawals.requested.v1":
		var raw withdrawRequestedV1
		if err := json.Unmarshal(line, &raw); err != nil {
			return withdrawRequestedMessage{}, err
		}
		return withdrawRequestedMessage{
			Version:          raw.Version,
			WithdrawalID:     raw.WithdrawalID,
			Requester:        raw.Requester,
			Amount:           raw.Amount,
			RecipientUA:      raw.RecipientUA,
			ProofWitnessItem: raw.ProofWitnessItem,
			Expiry:           raw.Expiry,
			FeeBps:           raw.FeeBps,
		}, nil
	case "withdrawals.requested.v2":
		var raw withdrawRequestedV2
		if err := json.Unmarshal(line, &raw); err != nil {
			return withdrawRequestedMessage{}, err
		}
		if strings.TrimSpace(raw.BlockHash) == "" {
			return withdrawRequestedMessage{}, errors.New("withdrawals.requested.v2 missing blockHash")
		}
		if strings.TrimSpace(raw.FinalitySource) == "" {
			return withdrawRequestedMessage{}, errors.New("withdrawals.requested.v2 missing finalitySource")
		}
		return withdrawRequestedMessage{
			Version:          raw.Version,
			WithdrawalID:     raw.WithdrawalID,
			Requester:        raw.Requester,
			Amount:           raw.Amount,
			RecipientUA:      raw.RecipientUA,
			ProofWitnessItem: raw.ProofWitnessItem,
			Expiry:           raw.Expiry,
			FeeBps:           raw.FeeBps,
			BlockNumber:      raw.BlockNumber,
			BlockHash:        raw.BlockHash,
			TxHash:           raw.TxHash,
			LogIndex:         raw.LogIndex,
			FinalitySource:   raw.FinalitySource,
		}, nil
	default:
		return withdrawRequestedMessage{}, fmt.Errorf("unsupported withdraw request version %q", env.Version)
	}
}

type readinessFunc func(context.Context) error

func (f readinessFunc) Ready(ctx context.Context) error {
	return f(ctx)
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

func ackMessage(msg queue.Message, timeout time.Duration, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := msg.Ack(ctx); err != nil {
		log.Error("ack queue message", "topic", msg.Topic, "err", err)
	}
}

func shouldAckWithdrawIngestError(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, withdraw.ErrInvalidConfig):
		return true
	case errors.Is(err, withdraw.ErrWithdrawalMismatch):
		return true
	default:
		return false
	}
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

func decodeHexBytesOptional(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
	if s == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	return b, nil
}

func normalizeRuntimeMode(v string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(v))
	switch mode {
	case "", runtimeModeFull:
		return runtimeModeFull, nil
	case "mock":
		return "", fmt.Errorf("--runtime-mode=mock is not supported in this binary")
	default:
		return "", fmt.Errorf("--runtime-mode must be %s", runtimeModeFull)
	}
}

func normalizeBlobDriver(v string) string {
	s := strings.TrimSpace(strings.ToLower(v))
	if s == "" {
		return blobstore.DriverS3
	}
	return s
}

func resolveRequiredFlagOrEnv(flagName string, flagValue string, envName string) (string, error) {
	flagValue = strings.TrimSpace(flagValue)
	envName = strings.TrimSpace(envName)
	if flagValue != "" {
		if envName != "" {
			return "", fmt.Errorf("%s and --postgres-dsn-env are mutually exclusive", flagName)
		}
		return flagValue, nil
	}
	if envName == "" {
		return "", fmt.Errorf("%s or --postgres-dsn-env is required", flagName)
	}
	value := strings.TrimSpace(os.Getenv(envName))
	if value == "" {
		return "", fmt.Errorf("missing %s in env %s", flagName, envName)
	}
	return value, nil
}

func devModeEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("JUNO_DEV_MODE"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func newBlobStore(ctx context.Context, driver string, bucket string, prefix string, maxGetSize int64) (blobstore.Store, error) {
	cfg := blobstore.Config{
		Driver:     normalizeBlobDriver(driver),
		Bucket:     strings.TrimSpace(bucket),
		Prefix:     strings.TrimSpace(prefix),
		MaxGetSize: maxGetSize,
	}

	if cfg.Driver == blobstore.DriverS3 {
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("load aws config: %w", err)
		}
		cfg.S3Client = awss3.NewFromConfig(awsCfg)
	}

	return blobstore.New(cfg)
}

func newTSSHTTPClient(timeout time.Duration, serverCAFile string, clientCertFile string, clientKeyFile string, serverName string) (*http.Client, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("tss timeout must be > 0")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	if strings.TrimSpace(serverName) != "" {
		tlsCfg.ServerName = strings.TrimSpace(serverName)
	}

	// If a CA file is provided, trust ONLY that CA (avoid mixing in system roots accidentally).
	if serverCAFile != "" {
		caPEM, err := os.ReadFile(serverCAFile)
		if err != nil {
			return nil, fmt.Errorf("read server ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caPEM); !ok {
			return nil, fmt.Errorf("parse server ca file")
		}
		tlsCfg.RootCAs = pool
	}

	if clientCertFile != "" || clientKeyFile != "" {
		if clientCertFile == "" || clientKeyFile == "" {
			return nil, fmt.Errorf("tss client cert requires both --tss-client-cert-file and --tss-client-key-file")
		}
		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}

// slogKafkaLogger adapts slog.Logger to the kafka.Logger interface (Printf method).
type slogKafkaLogger struct {
	log *slog.Logger
}

func (l *slogKafkaLogger) Printf(msg string, args ...interface{}) {
	l.log.Info(fmt.Sprintf(msg, args...), "component", "kafka-reader")
}
