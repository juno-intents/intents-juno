package main

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

type stubBalanceClient struct {
	calls    int
	lastAddr common.Address
	balance  *big.Int
	err      error
}

func (c *stubBalanceClient) RequestorBalanceWei(_ context.Context, requestor common.Address) (*big.Int, error) {
	c.calls++
	c.lastAddr = requestor
	if c.err != nil {
		return nil, c.err
	}
	if c.balance == nil {
		return nil, nil
	}
	return new(big.Int).Set(c.balance), nil
}

func TestProofFunderReadinessCheck_ShortCircuitsOnDBFailure(t *testing.T) {
	t.Parallel()

	sp1Called := false
	check := proofFunderReadinessCheck(
		func(context.Context) error { return errors.New("db down") },
		func(context.Context) error {
			sp1Called = true
			return nil
		},
	)
	if check == nil {
		t.Fatalf("expected readiness check")
	}

	err := check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "db down") {
		t.Fatalf("unexpected err: %v", err)
	}
	if sp1Called {
		t.Fatalf("later checks should not run when db fails first")
	}
}

func TestProofFunderReadinessCheck_RunsAllChecks(t *testing.T) {
	t.Parallel()

	order := make([]string, 0, 2)
	check := proofFunderReadinessCheck(
		func(context.Context) error {
			order = append(order, "db")
			return nil
		},
		func(context.Context) error {
			order = append(order, "sp1")
			return nil
		},
	)

	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if got, want := strings.Join(order, ","), "db,sp1"; got != want {
		t.Fatalf("order: got %q want %q", got, want)
	}
}

func TestSP1BalanceReadinessCheck_UsesBalanceProbe(t *testing.T) {
	t.Parallel()

	requestor := common.HexToAddress("0x000000000000000000000000000000000000beef")
	client := &stubBalanceClient{balance: big.NewInt(42)}
	check := sp1BalanceReadinessCheck(client, requestor)
	if check == nil {
		t.Fatalf("expected readiness check")
	}

	if err := check(context.Background()); err != nil {
		t.Fatalf("check: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("calls: got %d want 1", client.calls)
	}
	if client.lastAddr != requestor {
		t.Fatalf("requestor: got %s want %s", client.lastAddr.Hex(), requestor.Hex())
	}
}

func TestSP1BalanceReadinessCheck_RejectsNilBalance(t *testing.T) {
	t.Parallel()

	client := &stubBalanceClient{}
	check := sp1BalanceReadinessCheck(client, common.HexToAddress("0x000000000000000000000000000000000000beef"))
	err := check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty balance") {
		t.Fatalf("unexpected err: %v", err)
	}
}
