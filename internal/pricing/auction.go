package pricing

import (
	"fmt"
	"math"
	"math/big"
)

const gCycle = uint64(1_000_000_000)

var (
	lockCollateralBaseMainnet, _ = new(big.Int).SetString("20000000000000000000", 10) // 20 ZKC
	lockCollateralTestnet, _     = new(big.Int).SetString("5000000000000000000", 10)  // 5 ZKC
)

type AuctionProfileInput struct {
	CycleCount           uint64
	ExecutorHz           uint64
	ProverHz             uint64
	BlockTimeSeconds     uint64
	MinPriceWeiPerGCycle *big.Int
	MaxPriceWeiPerGCycle *big.Int
}

type AuctionProfile struct {
	CycleCount uint64

	ExecutionSeconds    uint64
	ProvingSeconds      uint64
	RampUpStartSeconds  uint64
	RampUpPeriodSeconds uint64
	RampUpPeriodBlocks  uint64
	LockTimeoutSeconds  uint64
	TimeoutSeconds      uint64

	MinPriceWei *big.Int
	MaxPriceWei *big.Int
}

func ComputeAuctionProfile(in AuctionProfileInput) (AuctionProfile, error) {
	if in.ExecutorHz == 0 {
		return AuctionProfile{}, fmt.Errorf("pricing: executor_hz must be > 0")
	}
	if in.ProverHz == 0 {
		return AuctionProfile{}, fmt.Errorf("pricing: prover_hz must be > 0")
	}
	if in.BlockTimeSeconds == 0 {
		return AuctionProfile{}, fmt.Errorf("pricing: block_time_seconds must be > 0")
	}
	if !isPositiveOrZero(in.MinPriceWeiPerGCycle) {
		return AuctionProfile{}, fmt.Errorf("pricing: min_price_wei_per_gcycle must be >= 0")
	}
	if !isPositiveOrZero(in.MaxPriceWeiPerGCycle) {
		return AuctionProfile{}, fmt.Errorf("pricing: max_price_wei_per_gcycle must be >= 0")
	}
	if in.MaxPriceWeiPerGCycle.Cmp(in.MinPriceWeiPerGCycle) < 0 {
		return AuctionProfile{}, fmt.Errorf("pricing: max_price_wei_per_gcycle must be >= min_price_wei_per_gcycle")
	}

	timeCycles := in.CycleCount
	if timeCycles == 0 {
		timeCycles = 1
	}
	priceCycles := in.CycleCount
	if priceCycles == 0 {
		priceCycles = gCycle
	}

	execSeconds := ceilDiv(timeCycles, in.ExecutorHz)
	provingSeconds := ceilDiv(timeCycles, in.ProverHz)

	rampUpStart, err := mulChecked(execSeconds, 5)
	if err != nil {
		return AuctionProfile{}, err
	}
	rampUpPeriodSeconds, err := mulChecked(execSeconds, 10)
	if err != nil {
		return AuctionProfile{}, err
	}
	rampUpPeriodBlocks := ceilDiv(rampUpPeriodSeconds, in.BlockTimeSeconds)

	lockTimeout, err := mulChecked(provingSeconds, 5)
	if err != nil {
		return AuctionProfile{}, err
	}
	if lockTimeout > math.MaxUint64-3 {
		return AuctionProfile{}, fmt.Errorf("pricing: lock timeout overflow")
	}
	lockTimeout = (lockTimeout + 3) / 4 // ceil(1.25 * proving_seconds)

	timeout, err := mulChecked(provingSeconds, 3)
	if err != nil {
		return AuctionProfile{}, err
	}

	minPrice := scaleWeiPerGCycle(in.MinPriceWeiPerGCycle, priceCycles)
	maxPrice := scaleWeiPerGCycle(in.MaxPriceWeiPerGCycle, priceCycles)

	return AuctionProfile{
		CycleCount: in.CycleCount,

		ExecutionSeconds:    execSeconds,
		ProvingSeconds:      provingSeconds,
		RampUpStartSeconds:  rampUpStart,
		RampUpPeriodSeconds: rampUpPeriodSeconds,
		RampUpPeriodBlocks:  rampUpPeriodBlocks,
		LockTimeoutSeconds:  lockTimeout,
		TimeoutSeconds:      timeout,
		MinPriceWei:         minPrice,
		MaxPriceWei:         maxPrice,
	}, nil
}

func RecommendedLockCollateralWei(chainID uint64) *big.Int {
	switch chainID {
	case 84532, 11155111:
		return new(big.Int).Set(lockCollateralTestnet)
	default:
		return new(big.Int).Set(lockCollateralBaseMainnet)
	}
}

func isPositiveOrZero(v *big.Int) bool {
	return v != nil && v.Sign() >= 0
}

func scaleWeiPerGCycle(weiPerGCycle *big.Int, cycles uint64) *big.Int {
	if cycles == 0 {
		cycles = 1
	}
	numerator := new(big.Int).Mul(new(big.Int).SetUint64(cycles), weiPerGCycle)
	numerator.Add(numerator, new(big.Int).SetUint64(gCycle-1))
	return numerator.Div(numerator, new(big.Int).SetUint64(gCycle))
}

func ceilDiv(n, d uint64) uint64 {
	return (n + d - 1) / d
}

func mulChecked(a, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a > math.MaxUint64/b {
		return 0, fmt.Errorf("pricing: uint64 overflow (%d * %d)", a, b)
	}
	return a * b, nil
}
