package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5/pgxpool"
	internaleth "github.com/juno-intents/intents-juno/internal/eth"
	"github.com/juno-intents/intents-juno/internal/depositrepair"
	"github.com/juno-intents/intents-juno/internal/pgxpoolutil"
)

func main() {
	var (
		postgresDSN = flag.String("postgres-dsn", "", "Postgres DSN (required)")
		baseRPCURL  = flag.String("base-rpc-url", "", "Base RPC URL or comma-separated URLs (required)")
		bridgeAddr  = flag.String("bridge-address", "", "Bridge contract address (required)")
		limit       = flag.Int("limit", 100, "maximum distinct tx hashes to inspect")
	)
	flag.Parse()

	if strings.TrimSpace(*postgresDSN) == "" || strings.TrimSpace(*baseRPCURL) == "" || !common.IsHexAddress(*bridgeAddr) {
		fmt.Fprintln(os.Stderr, "error: --postgres-dsn, --base-rpc-url, and a valid --bridge-address are required")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	poolCfg, err := pgxpoolutil.ParseConfig(strings.TrimSpace(*postgresDSN), pgxpoolutil.Settings{})
	if err != nil {
		log.Error("parse pgx config", "err", err)
		os.Exit(2)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Error("init pgx pool", "err", err)
		os.Exit(2)
	}
	defer pool.Close()

	baseClient, err := internaleth.DialMultiRPCClient(ctx, *baseRPCURL)
	if err != nil {
		log.Error("dial base rpc", "err", err)
		os.Exit(2)
	}
	defer baseClient.Close()

	store, err := depositrepair.NewPostgresStore(pool)
	if err != nil {
		log.Error("init repair store", "err", err)
		os.Exit(2)
	}
	repairer, err := depositrepair.New(store, baseClient, common.HexToAddress(*bridgeAddr))
	if err != nil {
		log.Error("init repairer", "err", err)
		os.Exit(2)
	}

	results, err := repairer.RepairAll(ctx, *limit)
	if err != nil {
		log.Error("repair failed", "err", err)
		os.Exit(1)
	}

	var finalized, rejected, unresolved int
	for _, result := range results {
		finalized += result.FinalizedCount
		rejected += result.RejectedCount
		unresolved += result.UnresolvedCount
		log.Info(
			"repaired deposit batch outcome",
			"txHash", common.Hash(result.TxHash).Hex(),
			"deposits", result.DepositCount,
			"finalized", result.FinalizedCount,
			"rejected", result.RejectedCount,
			"unresolved", result.UnresolvedCount,
		)
	}

	log.Info("deposit batch repair complete",
		"txHashes", len(results),
		"finalized", finalized,
		"rejected", rejected,
		"unresolved", unresolved,
	)
}
