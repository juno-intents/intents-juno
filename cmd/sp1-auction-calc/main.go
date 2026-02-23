package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/juno-intents/intents-juno/internal/pricing"
)

type output struct {
	Version                      string `json:"version"`
	ChainID                      uint64 `json:"chain_id"`
	CycleCount                   uint64 `json:"cycle_count"`
	ExecutorHz                   uint64 `json:"executor_hz"`
	ProverHz                     uint64 `json:"prover_hz"`
	BlockTimeSeconds             uint64 `json:"block_time_seconds"`
	ExecutionSeconds             uint64 `json:"execution_seconds"`
	ProvingSeconds               uint64 `json:"proving_seconds"`
	RampUpStartSeconds           uint64 `json:"ramp_up_start_seconds"`
	RampUpPeriodSeconds          uint64 `json:"ramp_up_period_seconds"`
	RampUpPeriodBlocks           uint64 `json:"ramp_up_period_blocks"`
	LockTimeoutSeconds           uint64 `json:"lock_timeout_seconds"`
	TimeoutSeconds               uint64 `json:"timeout_seconds"`
	MinPriceWeiPerGCycle         string `json:"min_price_wei_per_gcycle"`
	MaxPriceWeiPerGCycle         string `json:"max_price_wei_per_gcycle"`
	MinPriceWei                  string `json:"min_price_wei"`
	MaxPriceWei                  string `json:"max_price_wei"`
	RecommendedLockCollateralWei string `json:"recommended_lock_collateral_wei"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	var (
		chainID         uint64
		cycleCount      uint64
		executorHz      uint64
		proverHz        uint64
		blockTime       uint64
		minPerGCycleWei string
		maxPerGCycleWei string
	)

	fs := flag.NewFlagSet("sp1-auction-calc", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Uint64Var(&chainID, "chain-id", 8453, "chain id (8453 base mainnet, 84532 base sepolia, 11155111 eth sepolia)")
	fs.Uint64Var(&cycleCount, "cycle-count", 0, "proof cycle count")
	fs.Uint64Var(&executorHz, "executor-hz", 30_000_000, "executor speed in Hz")
	fs.Uint64Var(&proverHz, "prover-hz", 1_000_000, "prover speed in Hz")
	fs.Uint64Var(&blockTime, "block-time-seconds", 2, "target chain block time in seconds")
	fs.StringVar(&minPerGCycleWei, "min-price-wei-per-gcycle", "100000000000000", "minimum price in wei per GCycle")
	fs.StringVar(&maxPerGCycleWei, "max-price-wei-per-gcycle", "250000000000000", "maximum price in wei per GCycle")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if cycleCount == 0 {
		return fmt.Errorf("--cycle-count must be > 0")
	}

	minPricePerGCycle, err := parseBigInt(minPerGCycleWei)
	if err != nil {
		return fmt.Errorf("--min-price-wei-per-gcycle: %w", err)
	}
	maxPricePerGCycle, err := parseBigInt(maxPerGCycleWei)
	if err != nil {
		return fmt.Errorf("--max-price-wei-per-gcycle: %w", err)
	}

	profile, err := pricing.ComputeAuctionProfile(pricing.AuctionProfileInput{
		CycleCount:           cycleCount,
		ExecutorHz:           executorHz,
		ProverHz:             proverHz,
		BlockTimeSeconds:     blockTime,
		MinPriceWeiPerGCycle: minPricePerGCycle,
		MaxPriceWeiPerGCycle: maxPricePerGCycle,
	})
	if err != nil {
		return err
	}

	res := output{
		Version:                      "sp1.auction.profile.v1",
		ChainID:                      chainID,
		CycleCount:                   profile.CycleCount,
		ExecutorHz:                   executorHz,
		ProverHz:                     proverHz,
		BlockTimeSeconds:             blockTime,
		ExecutionSeconds:             profile.ExecutionSeconds,
		ProvingSeconds:               profile.ProvingSeconds,
		RampUpStartSeconds:           profile.RampUpStartSeconds,
		RampUpPeriodSeconds:          profile.RampUpPeriodSeconds,
		RampUpPeriodBlocks:           profile.RampUpPeriodBlocks,
		LockTimeoutSeconds:           profile.LockTimeoutSeconds,
		TimeoutSeconds:               profile.TimeoutSeconds,
		MinPriceWeiPerGCycle:         minPricePerGCycle.String(),
		MaxPriceWeiPerGCycle:         maxPricePerGCycle.String(),
		MinPriceWei:                  profile.MinPriceWei.String(),
		MaxPriceWei:                  profile.MaxPriceWei.String(),
		RecommendedLockCollateralWei: pricing.RecommendedLockCollateralWei(chainID).String(),
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

func parseBigInt(v string) (*big.Int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("empty value")
	}
	out, ok := new(big.Int).SetString(v, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal")
	}
	if out.Sign() < 0 {
		return nil, fmt.Errorf("must be >= 0")
	}
	return out, nil
}
