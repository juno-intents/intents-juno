package prooffunder

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/leases"
)

type fakeFundingClient struct {
	balance    *big.Int
	topupCalls int
	lastTopup  *big.Int
}

func (c *fakeFundingClient) RequestorBalanceWei(_ context.Context, _ common.Address) (*big.Int, error) {
	return new(big.Int).Set(c.balance), nil
}

func (c *fakeFundingClient) TopUpRequestor(_ context.Context, _ common.Address, amountWei *big.Int) (string, error) {
	c.topupCalls++
	c.lastTopup = new(big.Int).Set(amountWei)
	c.balance = new(big.Int).Add(c.balance, amountWei)
	return "0xtopup", nil
}

func TestComputeTopUpAmount(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		bal    string
		min    string
		target string
		max    string
		want   string
	}{
		{
			name:   "no topup above min",
			bal:    "60",
			min:    "50",
			target: "500",
			max:    "1000",
			want:   "0",
		},
		{
			name:   "topup to target below min",
			bal:    "10",
			min:    "50",
			target: "500",
			max:    "1000",
			want:   "490",
		},
		{
			name:   "topup capped by max per tx",
			bal:    "10",
			min:    "50",
			target: "500",
			max:    "120",
			want:   "120",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, shouldTopUp := ComputeTopUpAmount(
				mustBig(tc.bal),
				mustBig(tc.min),
				mustBig(tc.target),
				mustBig(tc.max),
			)
			if !shouldTopUp && tc.want != "0" {
				t.Fatalf("shouldTopUp=false but want %s", tc.want)
			}
			if got.Cmp(mustBig(tc.want)) != 0 {
				t.Fatalf("amount: got %s want %s", got.String(), tc.want)
			}
		})
	}
}

func TestService_LeaseAllowsSingleActiveTopupLoop(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 11, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	leaseStore := leases.NewMemoryStore(nowFn)
	client := &fakeFundingClient{balance: big.NewInt(10)}
	cfg := Config{
		LeaseName:          "proof-funder",
		LeaseTTL:           15 * time.Second,
		CheckInterval:      1 * time.Second,
		OwnerAddress:       common.HexToAddress("0x000000000000000000000000000000000000beef"),
		RequestorAddress:   common.HexToAddress("0x000000000000000000000000000000000000cafe"),
		MinBalanceWei:      big.NewInt(50),
		TargetBalanceWei:   big.NewInt(200),
		CriticalBalanceWei: big.NewInt(20),
		MaxTopUpPerTxWei:   big.NewInt(100),
	}

	a, err := New(cfg, "funder-a", leaseStore, client, nil)
	if err != nil {
		t.Fatalf("New a: %v", err)
	}
	b, err := New(cfg, "funder-b", leaseStore, client, nil)
	if err != nil {
		t.Fatalf("New b: %v", err)
	}

	if err := a.Tick(context.Background()); err != nil {
		t.Fatalf("a.Tick: %v", err)
	}
	if err := b.Tick(context.Background()); err != nil {
		t.Fatalf("b.Tick: %v", err)
	}
	if got, want := client.topupCalls, 1; got != want {
		t.Fatalf("topup calls: got %d want %d", got, want)
	}
	if got, want := client.lastTopup.String(), "100"; got != want {
		t.Fatalf("topup amount: got %s want %s", got, want)
	}
}

func TestService_Tick_NoTopUpWhenBalanceAboveMin(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	leaseStore := leases.NewMemoryStore(nowFn)
	client := &fakeFundingClient{balance: big.NewInt(75)}
	svc, err := New(Config{
		LeaseName:          "proof-funder",
		LeaseTTL:           15 * time.Second,
		CheckInterval:      time.Second,
		OwnerAddress:       common.HexToAddress("0x000000000000000000000000000000000000beef"),
		RequestorAddress:   common.HexToAddress("0x000000000000000000000000000000000000cafe"),
		MinBalanceWei:      big.NewInt(50),
		TargetBalanceWei:   big.NewInt(200),
		CriticalBalanceWei: big.NewInt(20),
		MaxTopUpPerTxWei:   big.NewInt(100),
	}, "funder-a", leaseStore, client, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := svc.Tick(context.Background()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if client.topupCalls != 0 {
		t.Fatalf("expected no topup, got %d calls", client.topupCalls)
	}
}

func mustBig(v string) *big.Int {
	out, ok := new(big.Int).SetString(v, 10)
	if !ok {
		panic("invalid big int: " + v)
	}
	return out
}
