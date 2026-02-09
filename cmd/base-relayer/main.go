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
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/juno-intents/intents-juno/internal/eth"
	"github.com/juno-intents/intents-juno/internal/eth/httpapi"
)

func main() {
	var (
		rpcURL      = flag.String("rpc-url", "", "Base/EVM JSON-RPC URL (required)")
		chainIDFlag = flag.Uint64("chain-id", 0, "EVM chain id (required)")
		listenAddr  = flag.String("listen", "127.0.0.1:8080", "HTTP listen address")

		keysEnv  = flag.String("keys-env", "BASE_RELAYER_PRIVATE_KEYS", "env var containing comma-separated hex private keys")
		tokenEnv = flag.String("auth-env", "BASE_RELAYER_AUTH_TOKEN", "env var containing bearer auth token (required)")

		minTipGwei   = flag.Int64("min-tip-gwei", 1, "minimum priority fee (gwei)")
		gasMult      = flag.Float64("gas-mult", 1.2, "gas limit multiplier when estimating")
		pollInterval = flag.Duration("poll-interval", 2*time.Second, "receipt poll interval")
		replaceAfter = flag.Duration("replace-after", 15*time.Second, "send replacement after this long without a receipt")
		maxReplace   = flag.Int("max-replacements", 3, "maximum number of replacement transactions")
		bumpPercent  = flag.Int("bump-percent", 15, "replacement fee bump percentage")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *rpcURL == "" || *chainIDFlag == 0 {
		fmt.Fprintln(os.Stderr, "error: --rpc-url and --chain-id are required")
		os.Exit(2)
	}

	authToken := os.Getenv(*tokenEnv)
	if authToken == "" {
		fmt.Fprintf(os.Stderr, "error: missing auth token in env %s\n", *tokenEnv)
		os.Exit(2)
	}

	keysRaw := os.Getenv(*keysEnv)
	if keysRaw == "" {
		fmt.Fprintf(os.Stderr, "error: missing private keys in env %s\n", *keysEnv)
		os.Exit(2)
	}
	keys, err := eth.ParsePrivateKeysHexList(keysRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse keys: %v\n", err)
		os.Exit(2)
	}

	signers := make([]eth.Signer, 0, len(keys))
	for _, k := range keys {
		signers = append(signers, eth.NewLocalSigner(k))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startupCtx, cancelStartup := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStartup()

	client, err := ethclient.DialContext(startupCtx, *rpcURL)
	if err != nil {
		log.Error("dial rpc", "err", err)
		os.Exit(1)
	}
	defer client.Close()

	chainID := new(big.Int).SetUint64(*chainIDFlag)
	gotChainID, err := client.ChainID(startupCtx)
	if err != nil {
		log.Error("fetch chain id", "err", err)
		os.Exit(1)
	}
	if gotChainID.Cmp(chainID) != 0 {
		log.Error("chain id mismatch", "want", chainID.String(), "got", gotChainID.String())
		os.Exit(2)
	}

	minTipWei := new(big.Int).Mul(big.NewInt(*minTipGwei), big.NewInt(1_000_000_000))

	relayer, err := eth.NewRelayer(client, signers, eth.RelayerConfig{
		ChainID:                chainID,
		GasLimitMultiplier:     *gasMult,
		MinTipCap:              minTipWei,
		ReceiptPollInterval:    *pollInterval,
		ReplaceAfter:           *replaceAfter,
		MaxReplacements:        *maxReplace,
		ReplacementBumpPercent: *bumpPercent,
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
		AuthToken:      authToken,
		MaxBodyBytes:   1 << 20,
		MaxWaitSeconds: 300,
	})

	srv := &http.Server{
		Addr:              *listenAddr,
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
