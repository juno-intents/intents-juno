package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
	"github.com/juno-intents/intents-juno/internal/junorpc"
	leasespg "github.com/juno-intents/intents-juno/internal/leases/postgres"
	"github.com/juno-intents/intents-juno/internal/policy"
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
	Expiry      uint64 `json:"expiry"`      // unix seconds
	FeeBps      uint32 `json:"feeBps"`
}

func main() {
	var (
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")

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

		maxLineBytes = flag.Int("max-line-bytes", 1<<20, "maximum input line size (bytes)")

		// Planner (juno-txbuild)
		txbuildBin        = flag.String("juno-txbuild-bin", "juno-txbuild", "path to juno-txbuild binary")
		junoWalletID      = flag.String("juno-wallet-id", "", "juno-txbuild wallet id (required)")
		junoChangeAddress = flag.String("juno-change-address", "", "juno-txbuild change address (required)")
		junoCoinType      = flag.Uint("juno-coin-type", 0, "ZIP-32 coin type for juno-txbuild")
		junoAccount       = flag.Uint("juno-account", 0, "unified account id for juno-txbuild")
		junoMinConf       = flag.Int64("juno-minconf", 1, "minimum confirmations for juno-txbuild input note selection")
		junoExpiryOffset  = flag.Uint("juno-expiry-offset", 40, "juno tx expiry offset (min 4)")
		junoFeeMultiplier = flag.Uint64("juno-fee-multiplier", 1, "juno-txbuild fee multiplier")
		junoFeeAddZat     = flag.Uint64("juno-fee-add-zat", 0, "juno-txbuild extra absolute fee")
		junoMinChangeZat  = flag.Uint64("juno-min-change-zat", 0, "juno-txbuild min change amount")
		junoMinNoteZat    = flag.Uint64("juno-min-note-zat", 0, "juno-txbuild min note amount")
		junoScanURL       = flag.String("juno-scan-url", "", "optional juno-scan URL for juno-txbuild")
		junoScanBearerEnv = flag.String("juno-scan-bearer-env", "JUNO_SCAN_BEARER_TOKEN", "env var for optional juno-scan bearer token")

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
		tssTimeout        = flag.Duration("tss-timeout", 10*time.Second, "tss request timeout")
		tssMaxRespBytes   = flag.Int64("tss-max-response-bytes", 1<<20, "max tss response size (bytes)")
		tssServerCAFile   = flag.String("tss-server-ca-file", "", "server root CA PEM file (optional; defaults to system roots)")
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
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *postgresDSN == "" || *owner == "" {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn and --owner are required")
		os.Exit(2)
	}
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
	if *maxItems <= 0 || *maxExtendBatch <= 0 || *maxLineBytes <= 0 {
		fmt.Fprintln(os.Stderr, "error: --max-items, --max-extend-batch, and --max-line-bytes must be > 0")
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
	if *junoConfirmations <= 0 || *junoConfirmPoll <= 0 || *junoConfirmWait <= 0 || *junoRPCTimeout <= 0 || *junoRPCMaxResp <= 0 {
		fmt.Fprintln(os.Stderr, "error: juno rpc and confirmation settings must be > 0")
		os.Exit(2)
	}
	if *junoMinConf <= 0 || *junoExpiryOffset < 4 || *junoFeeMultiplier == 0 {
		fmt.Fprintln(os.Stderr, "error: juno txbuild settings invalid (--juno-minconf > 0, --juno-expiry-offset >= 4, --juno-fee-multiplier >= 1)")
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

	junoRPCUser := os.Getenv(*junoRPCUserEnv)
	junoRPCPass := os.Getenv(*junoRPCPassEnv)
	if junoRPCUser == "" || junoRPCPass == "" {
		fmt.Fprintf(os.Stderr, "error: missing junocashd RPC credentials in env %s/%s\n", *junoRPCUserEnv, *junoRPCPassEnv)
		os.Exit(2)
	}

	baseRelayerAuth := os.Getenv(*baseRelayerAuthEnv)
	if baseRelayerAuth == "" {
		fmt.Fprintf(os.Stderr, "error: missing base-relayer auth token in env %s\n", *baseRelayerAuthEnv)
		os.Exit(2)
	}

	scanBearerToken := strings.TrimSpace(os.Getenv(*junoScanBearerEnv))

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

	planner, err := withdrawcoordinator.NewTxBuildPlanner(withdrawcoordinator.TxBuildPlannerConfig{
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

	tssHTTPClient, err := newTSSHTTPClient(*tssTimeout, *tssServerCAFile, *tssClientCertFile, *tssClientKeyFile)
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
	signer, err := tss.NewClient(*tssURL, tssOpts...)
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

	broadcaster, err := withdrawcoordinator.NewJunoBroadcaster(junoClient)
	if err != nil {
		log.Error("init juno broadcaster", "err", err)
		os.Exit(2)
	}
	confirmer, err := withdrawcoordinator.NewJunoConfirmer(junoClient, *junoConfirmations, *junoConfirmPoll, *junoConfirmWait)
	if err != nil {
		log.Error("init juno confirmer", "err", err)
		os.Exit(2)
	}

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
	extender, err := withdrawcoordinator.NewBaseExpiryExtender(withdrawcoordinator.BaseExpiryExtenderConfig{
		BaseChainID:   *baseChainID,
		BridgeAddress: common.HexToAddress(*bridgeAddr),
		GasLimit:      *extendGasLimit,
	}, baseClient, extendSigner)
	if err != nil {
		log.Error("init expiry extender", "err", err)
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
		elector, err = withdrawcoordinator.NewLeaderElector(leaseStore, *leaderLeaseName, *owner, *leaderLeaseTTL)
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
	}, store, planner, signer, broadcaster, confirmer, log)
	if err != nil {
		log.Error("init coordinator", "err", err)
		os.Exit(2)
	}
	coord.WithExpiryExtender(extender)

	log.Info("withdraw coordinator started",
		"owner", *owner,
		"maxItems", *maxItems,
		"maxAge", maxAge.String(),
		"claimTTL", claimTTL.String(),
		"tickInterval", tickInterval.String(),
		"junoRPC", *junoRPCURL,
		"junoConfirmations", *junoConfirmations,
		"baseChainID", *baseChainID,
		"bridge", common.HexToAddress(*bridgeAddr),
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
			if elector != nil {
				leader, err := elector.Tick(ctx)
				if err != nil {
					log.Error("leader election tick", "err", err)
					continue
				}
				if !leader {
					continue
				}
			}

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

func newTSSHTTPClient(timeout time.Duration, serverCAFile string, clientCertFile string, clientKeyFile string) (*http.Client, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("tss timeout must be > 0")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
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
