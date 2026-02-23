package prooffunder

import (
	"context"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/leases"
)

type fakeFundingClient struct {
	balance *big.Int
}

func (c *fakeFundingClient) RequestorBalanceWei(_ context.Context, _ common.Address) (*big.Int, error) {
	return new(big.Int).Set(c.balance), nil
}

func TestService_LeaseAllowsSingleActiveCheckLoop(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 11, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	leaseStore := leases.NewMemoryStore(nowFn)
	client := &fakeFundingClient{balance: big.NewInt(60)}
	cfg := Config{
		LeaseName:          "proof-funder",
		LeaseTTL:           15 * time.Second,
		CheckInterval:      1 * time.Second,
		RequestorAddress:   common.HexToAddress("0x000000000000000000000000000000000000cafe"),
		MinBalanceWei:      big.NewInt(50),
		CriticalBalanceWei: big.NewInt(20),
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
}

func TestService_Tick_InsufficientBalanceReturnsRefillAmount(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 12, 0, 0, 0, time.UTC)
	nowFn := func() time.Time { return now }

	leaseStore := leases.NewMemoryStore(nowFn)
	client := &fakeFundingClient{balance: big.NewInt(17)}
	svc, err := New(Config{
		LeaseName:          "proof-funder",
		LeaseTTL:           15 * time.Second,
		CheckInterval:      time.Second,
		RequestorAddress:   common.HexToAddress("0x000000000000000000000000000000000000cafe"),
		MinBalanceWei:      big.NewInt(50),
		CriticalBalanceWei: big.NewInt(20),
	}, "funder-a", leaseStore, client, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	err = svc.Tick(context.Background())
	if err == nil {
		t.Fatalf("expected insufficient balance error")
	}
	if !strings.Contains(err.Error(), "refill_wei=33") {
		t.Fatalf("expected refill hint, got: %v", err)
	}
}
