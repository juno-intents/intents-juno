package main

import (
	"context"
	"flag"
	"fmt"
	"io"
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
	"github.com/juno-intents/intents-juno/internal/eth"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
)

type config struct {
	RPCURL                     string
	ChainID                    uint64
	ListenAddr                 string
	KeysEnv                    string
	TokenEnv                   string
	MinTipGwei                 int64
	GasMult                    float64
	PollInterval               time.Duration
	ReplaceAfter               time.Duration
	MaxReplacements            int
	BumpPercent                int
	MaxFeeCapGwei              int64
	AllowedContracts           []common.Address
	AllowedSelectors           [][]byte
	TLSCertFile                string
	TLSKeyFile                 string
	MinReadyBalanceWei         uint64
	RateLimitPerSecond         float64
	RateLimitBurst             int
	RateLimitMaxTrackedClients int
	IdempotencyTTL             time.Duration
	IdempotencyMaxKeys         int
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	authToken := os.Getenv(cfg.TokenEnv)
	if authToken == "" {
		fmt.Fprintf(os.Stderr, "error: missing auth token in env %s\n", cfg.TokenEnv)
		os.Exit(2)
	}

	keysRaw := os.Getenv(cfg.KeysEnv)
	if keysRaw == "" {
		fmt.Fprintf(os.Stderr, "error: missing private keys in env %s\n", cfg.KeysEnv)
		os.Exit(2)
	}
	keys, err := eth.ParsePrivateKeysHexList(keysRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse keys: %v\n", err)
		os.Exit(2)
	}

	signers := make([]eth.Signer, 0, len(keys))
	signerAddrs := make([]common.Address, 0, len(keys))
	for _, key := range keys {
		signer := eth.NewLocalSigner(key)
		signers = append(signers, signer)
		signerAddrs = append(signerAddrs, signer.Address())
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startupCtx, cancelStartup := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStartup()

	client, err := ethclient.DialContext(startupCtx, cfg.RPCURL)
	if err != nil {
		log.Error("dial rpc", "err", err)
		os.Exit(1)
	}
	defer client.Close()

	chainID := new(big.Int).SetUint64(cfg.ChainID)
	gotChainID, err := client.ChainID(startupCtx)
	if err != nil {
		log.Error("fetch chain id", "err", err)
		os.Exit(1)
	}
	if gotChainID.Cmp(chainID) != 0 {
		log.Error("chain id mismatch", "want", chainID.String(), "got", gotChainID.String())
		os.Exit(2)
	}

	minTipWei := new(big.Int).Mul(big.NewInt(cfg.MinTipGwei), big.NewInt(1_000_000_000))
	var maxFeeCap *big.Int
	if cfg.MaxFeeCapGwei > 0 {
		maxFeeCap = new(big.Int).Mul(big.NewInt(cfg.MaxFeeCapGwei), big.NewInt(1_000_000_000))
	}
	relayer, err := eth.NewRelayer(client, signers, eth.RelayerConfig{
		ChainID:                chainID,
		GasLimitMultiplier:     cfg.GasMult,
		MinTipCap:              minTipWei,
		MaxFeeCap:              maxFeeCap,
		ReceiptPollInterval:    cfg.PollInterval,
		ReplaceAfter:           cfg.ReplaceAfter,
		MaxReplacements:        cfg.MaxReplacements,
		ReplacementBumpPercent: cfg.BumpPercent,
		MinReplacementTipBump:  big.NewInt(1_000_000_000),
		MinReplacementFeeBump:  big.NewInt(1_000_000_000),
		Now:                    time.Now,
		Sleep:                  nil,
	})
	if err != nil {
		log.Error("init relayer", "err", err)
		os.Exit(2)
	}

	handler := httpapi.NewHandler(relayer, httpapi.Config{
		ReadinessCheck:             httpapi.MinSignerBalanceReadinessCheck(client, signerAddrs, new(big.Int).SetUint64(cfg.MinReadyBalanceWei)),
		AuthToken:                  authToken,
		AllowedContracts:           cfg.AllowedContracts,
		AllowedSelectors:           cfg.AllowedSelectors,
		MaxBodyBytes:               1 << 20,
		MaxWaitSeconds:             300,
		IdempotencyTTL:             cfg.IdempotencyTTL,
		IdempotencyMaxKeys:         cfg.IdempotencyMaxKeys,
		RateLimitPerSecond:         cfg.RateLimitPerSecond,
		RateLimitBurst:             cfg.RateLimitBurst,
		RateLimitMaxTrackedClients: cfg.RateLimitMaxTrackedClients,
		Now:                        time.Now,
	})

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", srv.Addr)
		if cfg.TLSCertFile != "" {
			errCh <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown", "signal", ctx.Err())
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

func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("base-relayer", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		cfg                 config
		allowedContractsRaw string
		allowedSelectorsRaw string
	)
	fs.StringVar(&cfg.RPCURL, "rpc-url", "", "Base/EVM JSON-RPC URL (required)")
	fs.Uint64Var(&cfg.ChainID, "chain-id", 0, "EVM chain id (required)")
	fs.StringVar(&cfg.ListenAddr, "listen", "127.0.0.1:8080", "HTTP listen address")
	fs.StringVar(&cfg.KeysEnv, "keys-env", "BASE_RELAYER_PRIVATE_KEYS", "env var containing comma-separated hex private keys")
	fs.StringVar(&cfg.TokenEnv, "auth-env", "BASE_RELAYER_AUTH_TOKEN", "env var containing bearer auth token (required)")
	fs.Int64Var(&cfg.MinTipGwei, "min-tip-gwei", 1, "minimum priority fee (gwei)")
	fs.Float64Var(&cfg.GasMult, "gas-mult", 1.2, "gas limit multiplier when estimating")
	fs.DurationVar(&cfg.PollInterval, "poll-interval", 2*time.Second, "receipt poll interval")
	fs.DurationVar(&cfg.ReplaceAfter, "replace-after", 15*time.Second, "send replacement after this long without a receipt")
	fs.IntVar(&cfg.MaxReplacements, "max-replacements", 3, "maximum number of replacement transactions")
	fs.IntVar(&cfg.BumpPercent, "bump-percent", 15, "replacement fee bump percentage")
	fs.Int64Var(&cfg.MaxFeeCapGwei, "max-fee-cap-gwei", 0, "maximum gas fee cap in gwei (0 disables the cap)")
	fs.StringVar(&allowedContractsRaw, "allowed-contracts", "", "comma-separated list of allowed contract addresses (required)")
	fs.StringVar(&allowedSelectorsRaw, "allowed-selectors", "", "comma-separated list of allowed calldata selectors (required)")
	fs.StringVar(&cfg.TLSCertFile, "tls-cert-file", "", "PEM certificate for HTTPS listener")
	fs.StringVar(&cfg.TLSKeyFile, "tls-key-file", "", "PEM private key for HTTPS listener")
	fs.Uint64Var(&cfg.MinReadyBalanceWei, "min-ready-balance-wei", 0, "minimum per-signer balance required for /readyz in wei (0 disables readiness balance checks)")
	fs.Float64Var(&cfg.RateLimitPerSecond, "rate-limit-per-second", 20, "per-client refill rate for ingress rate limiting")
	fs.IntVar(&cfg.RateLimitBurst, "rate-limit-burst", 40, "per-client burst capacity for ingress rate limiting")
	fs.IntVar(&cfg.RateLimitMaxTrackedClients, "rate-limit-max-tracked-clients", 10_000, "maximum tracked client entries in the ingress rate limiter")
	fs.DurationVar(&cfg.IdempotencyTTL, "idempotency-ttl", 15*time.Minute, "retention window for completed idempotent send requests")
	fs.IntVar(&cfg.IdempotencyMaxKeys, "idempotency-max-keys", 10_000, "maximum tracked idempotency keys")

	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if cfg.RPCURL == "" || cfg.ChainID == 0 {
		return config{}, fmt.Errorf("--rpc-url and --chain-id are required")
	}
	if cfg.ListenAddr == "" {
		return config{}, fmt.Errorf("--listen must be non-empty")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return config{}, fmt.Errorf("--tls-cert-file and --tls-key-file must be provided together")
	}
	if cfg.MinTipGwei < 0 || cfg.GasMult <= 0 || cfg.PollInterval <= 0 || cfg.ReplaceAfter <= 0 {
		return config{}, fmt.Errorf("relayer settings must be positive")
	}
	if cfg.MaxReplacements < 0 || cfg.BumpPercent <= 0 {
		return config{}, fmt.Errorf("replacement settings must be valid")
	}
	if cfg.MaxFeeCapGwei < 0 {
		return config{}, fmt.Errorf("--max-fee-cap-gwei must be >= 0")
	}
	if cfg.RateLimitPerSecond <= 0 || cfg.RateLimitBurst <= 0 || cfg.RateLimitMaxTrackedClients <= 0 {
		return config{}, fmt.Errorf("rate limit settings must be > 0")
	}
	if cfg.IdempotencyTTL <= 0 || cfg.IdempotencyMaxKeys <= 0 {
		return config{}, fmt.Errorf("idempotency settings must be > 0")
	}

	if raw := strings.TrimSpace(allowedContractsRaw); raw != "" {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !common.IsHexAddress(item) {
				return config{}, fmt.Errorf("invalid allowed contract address %q", item)
			}
			cfg.AllowedContracts = append(cfg.AllowedContracts, common.HexToAddress(item))
		}
	}
	if len(cfg.AllowedContracts) == 0 {
		return config{}, fmt.Errorf("--allowed-contracts must contain at least one address")
	}
	if raw := strings.TrimSpace(allowedSelectorsRaw); raw != "" {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if !strings.HasPrefix(item, "0x") || len(item) != 10 {
				return config{}, fmt.Errorf("invalid allowed selector %q", item)
			}
			selector := common.FromHex(item)
			if len(selector) != 4 {
				return config{}, fmt.Errorf("invalid allowed selector %q", item)
			}
			cfg.AllowedSelectors = append(cfg.AllowedSelectors, selector)
		}
	}
	if len(cfg.AllowedSelectors) == 0 {
		return config{}, fmt.Errorf("--allowed-selectors must contain at least one selector")
	}

	return cfg, nil
}
