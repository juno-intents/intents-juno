package pricing

import (
	"math/big"
	"testing"
)

func TestComputeAuctionProfile_Baseline500MCycles(t *testing.T) {
	t.Parallel()

	profile, err := ComputeAuctionProfile(AuctionProfileInput{
		CycleCount:           500_000_000,
		ExecutorHz:           30_000_000,
		ProverHz:             1_000_000,
		BlockTimeSeconds:     2,
		MinPriceWeiPerGCycle: big.NewInt(100_000_000_000_000),
		MaxPriceWeiPerGCycle: big.NewInt(250_000_000_000_000),
	})
	if err != nil {
		t.Fatalf("ComputeAuctionProfile: %v", err)
	}

	if got, want := profile.ExecutionSeconds, uint64(17); got != want {
		t.Fatalf("execution seconds: got %d want %d", got, want)
	}
	if got, want := profile.ProvingSeconds, uint64(500); got != want {
		t.Fatalf("proving seconds: got %d want %d", got, want)
	}
	if got, want := profile.RampUpStartSeconds, uint64(85); got != want {
		t.Fatalf("ramp up start: got %d want %d", got, want)
	}
	if got, want := profile.RampUpPeriodSeconds, uint64(170); got != want {
		t.Fatalf("ramp up period seconds: got %d want %d", got, want)
	}
	if got, want := profile.RampUpPeriodBlocks, uint64(85); got != want {
		t.Fatalf("ramp up period blocks: got %d want %d", got, want)
	}
	if got, want := profile.LockTimeoutSeconds, uint64(625); got != want {
		t.Fatalf("lock timeout: got %d want %d", got, want)
	}
	if got, want := profile.TimeoutSeconds, uint64(1500); got != want {
		t.Fatalf("timeout: got %d want %d", got, want)
	}

	if got, want := profile.MinPriceWei.String(), "50000000000000"; got != want {
		t.Fatalf("min price wei: got %s want %s", got, want)
	}
	if got, want := profile.MaxPriceWei.String(), "125000000000000"; got != want {
		t.Fatalf("max price wei: got %s want %s", got, want)
	}
}

func TestComputeAuctionProfile_ZeroCycleUsesOneGCycleFloor(t *testing.T) {
	t.Parallel()

	profile, err := ComputeAuctionProfile(AuctionProfileInput{
		CycleCount:           0,
		ExecutorHz:           30_000_000,
		ProverHz:             1_000_000,
		BlockTimeSeconds:     2,
		MinPriceWeiPerGCycle: big.NewInt(100_000_000_000_000),
		MaxPriceWeiPerGCycle: big.NewInt(250_000_000_000_000),
	})
	if err != nil {
		t.Fatalf("ComputeAuctionProfile: %v", err)
	}

	if got, want := profile.MinPriceWei.String(), "100000000000000"; got != want {
		t.Fatalf("min price wei: got %s want %s", got, want)
	}
	if got, want := profile.MaxPriceWei.String(), "250000000000000"; got != want {
		t.Fatalf("max price wei: got %s want %s", got, want)
	}
}

func TestRecommendedLockCollateralWei(t *testing.T) {
	t.Parallel()

	if got, want := RecommendedLockCollateralWei(8453).String(), "20000000000000000000"; got != want {
		t.Fatalf("mainnet lock collateral: got %s want %s", got, want)
	}
	if got, want := RecommendedLockCollateralWei(84532).String(), "5000000000000000000"; got != want {
		t.Fatalf("base sepolia lock collateral: got %s want %s", got, want)
	}
	if got, want := RecommendedLockCollateralWei(11155111).String(), "5000000000000000000"; got != want {
		t.Fatalf("eth sepolia lock collateral: got %s want %s", got, want)
	}
}
