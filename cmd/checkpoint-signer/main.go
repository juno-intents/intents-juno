package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
	"github.com/juno-intents/intents-juno/internal/eth"
	"github.com/juno-intents/intents-juno/internal/junorpc"
)

type junoChainSource struct {
	c *junorpc.Client
}

func (s *junoChainSource) TipHeight(ctx context.Context) (uint64, error) {
	info, err := s.c.GetBlockChainInfo(ctx)
	if err != nil {
		return 0, err
	}
	return info.Blocks, nil
}

func (s *junoChainSource) CheckpointAtHeight(ctx context.Context, height uint64) (checkpoint.ChainCheckpoint, error) {
	h, err := s.c.GetBlockHash(ctx, height)
	if err != nil {
		return checkpoint.ChainCheckpoint{}, err
	}
	b, err := s.c.GetBlock(ctx, h)
	if err != nil {
		return checkpoint.ChainCheckpoint{}, err
	}
	return checkpoint.ChainCheckpoint{
		Height:           b.Height,
		BlockHash:        b.Hash,
		FinalOrchardRoot: b.FinalOrchardRoot,
	}, nil
}

type outputMessageV1 struct {
	Version    string                `json:"version"`
	Operator   common.Address        `json:"operator"`
	Digest     common.Hash           `json:"digest"`
	Signature  string                `json:"signature"`
	Checkpoint checkpoint.Checkpoint `json:"checkpoint"`
	SignedAt   time.Time             `json:"signedAt"`
}

func main() {
	var (
		junoRPCURL = flag.String("juno-rpc-url", "", "junocashd JSON-RPC URL (required)")

		rpcUserEnv = flag.String("juno-rpc-user-env", "JUNO_RPC_USER", "env var containing junocashd RPC username")
		rpcPassEnv = flag.String("juno-rpc-pass-env", "JUNO_RPC_PASS", "env var containing junocashd RPC password")

		operatorKeyEnv = flag.String("operator-key-env", "CHECKPOINT_SIGNER_PRIVATE_KEY", "env var containing operator ECDSA private key (32-byte hex)")

		baseChainID   = flag.Uint64("base-chain-id", 0, "Base/EVM chain id (required)")
		bridgeAddr    = flag.String("bridge-address", "", "Bridge contract address (required)")
		confirmations = flag.Uint64("confirmations", 100, "confirmations (k) for checkpoint height h = tip - k")

		pollInterval = flag.Duration("poll-interval", 2*time.Second, "poll interval for tip height")
		rpcTimeout   = flag.Duration("rpc-timeout", 10*time.Second, "HTTP client timeout for junocashd RPC calls")
	)
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *junoRPCURL == "" || *baseChainID == 0 || *bridgeAddr == "" {
		fmt.Fprintln(os.Stderr, "error: --juno-rpc-url, --base-chain-id, and --bridge-address are required")
		os.Exit(2)
	}
	if *pollInterval <= 0 {
		fmt.Fprintln(os.Stderr, "error: --poll-interval must be > 0")
		os.Exit(2)
	}
	if !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --bridge-address must be a valid hex address")
		os.Exit(2)
	}
	bridge := common.HexToAddress(*bridgeAddr)

	rpcUser := os.Getenv(*rpcUserEnv)
	rpcPass := os.Getenv(*rpcPassEnv)
	if rpcUser == "" || rpcPass == "" {
		fmt.Fprintf(os.Stderr, "error: missing junocashd RPC credentials in env %s/%s\n", *rpcUserEnv, *rpcPassEnv)
		os.Exit(2)
	}

	keyRaw := os.Getenv(*operatorKeyEnv)
	if keyRaw == "" {
		fmt.Fprintf(os.Stderr, "error: missing operator private key in env %s\n", *operatorKeyEnv)
		os.Exit(2)
	}
	// Reuse eth key parser to keep errors sanitized (never include key material).
	keys, err := eth.ParsePrivateKeysHexList(keyRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parse operator key: %v\n", err)
		os.Exit(2)
	}
	if len(keys) != 1 {
		fmt.Fprintln(os.Stderr, "error: operator key env must contain exactly one private key")
		os.Exit(2)
	}

	// Ensure key is valid up-front (crypto.HexToECDSA already did), but keep a local copy typed as ecdsa key.
	key := keys[0]
	operator := crypto.PubkeyToAddress(key.PublicKey)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rpc, err := junorpc.New(*junoRPCURL, rpcUser, rpcPass,
		junorpc.WithTimeout(*rpcTimeout),
		junorpc.WithMaxResponseBytes(5<<20),
	)
	if err != nil {
		log.Error("init junocashd rpc", "err", err)
		os.Exit(2)
	}

	src := &junoChainSource{c: rpc}
	signer, err := checkpoint.NewSigner(src, key, checkpoint.SignerConfig{
		BaseChainID:    *baseChainID,
		BridgeContract: bridge,
		Now:            time.Now,
	})
	if err != nil {
		log.Error("init checkpoint signer", "err", err)
		os.Exit(2)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	t := time.NewTicker(*pollInterval)
	defer t.Stop()

	log.Info("checkpoint signer started",
		"operator", operator,
		"confirmations", *confirmations,
		"baseChainID", *baseChainID,
		"bridge", bridge,
	)

	var lastDigest common.Hash
	for {
		select {
		case <-ctx.Done():
			log.Info("shutdown", "reason", ctx.Err())
			return
		case <-t.C:
		}

		// Per-iteration timeout to avoid wedging the loop on slow RPC.
		iterCtx, cancel := context.WithTimeout(ctx, *rpcTimeout)
		msg, err := signer.SignTipMinusConfirmations(iterCtx, *confirmations)
		cancel()

		if err != nil {
			if errors.Is(err, checkpoint.ErrTipTooLow) {
				log.Debug("tip too low for confirmations; waiting")
				continue
			}
			log.Error("sign checkpoint", "err", err)
			continue
		}

		if msg.Digest == lastDigest {
			continue
		}
		lastDigest = msg.Digest

		out := outputMessageV1{
			Version:    "checkpoints.signature.v1",
			Operator:   msg.Operator,
			Digest:     msg.Digest,
			Signature:  "0x" + hex.EncodeToString(msg.Signature),
			Checkpoint: msg.Checkpoint,
			SignedAt:   msg.SignedAt.UTC(),
		}

		if err := enc.Encode(out); err != nil {
			log.Error("write output", "err", err)
			continue
		}
	}
}
