package httpapi

import (
	"context"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

type stubBalanceReader struct {
	balances map[common.Address]*big.Int
	err      error
}

func (s *stubBalanceReader) BalanceAt(_ context.Context, account common.Address, _ *big.Int) (*big.Int, error) {
	if s.err != nil {
		return nil, s.err
	}
	balance, ok := s.balances[account]
	if !ok {
		return big.NewInt(0), nil
	}
	return new(big.Int).Set(balance), nil
}

func TestMinSignerBalanceReadinessCheck_RequiresEverySignerToBeFunded(t *testing.T) {
	t.Parallel()

	addr1 := common.HexToAddress("0x0000000000000000000000000000000000000001")
	addr2 := common.HexToAddress("0x0000000000000000000000000000000000000002")

	check := MinSignerBalanceReadinessCheck(&stubBalanceReader{
		balances: map[common.Address]*big.Int{
			addr1: big.NewInt(5),
			addr2: big.NewInt(1),
		},
	}, []common.Address{addr1, addr2}, big.NewInt(2))

	if check == nil {
		t.Fatalf("expected readiness check")
	}
	err := check(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if want := addr2.Hex(); err != nil && !contains(err.Error(), want) {
		t.Fatalf("error %q missing signer %s", err.Error(), want)
	}
}

func TestMinSignerBalanceReadinessCheck_PropagatesBalanceErrors(t *testing.T) {
	t.Parallel()

	addr := common.HexToAddress("0x0000000000000000000000000000000000000001")
	check := MinSignerBalanceReadinessCheck(&stubBalanceReader{
		err: errors.New("rpc down"),
	}, []common.Address{addr}, big.NewInt(2))

	err := check(context.Background())
	if err == nil {
		t.Fatalf("expected error")
	}
	if !contains(err.Error(), "rpc down") {
		t.Fatalf("error %q missing backend failure", err.Error())
	}
}

func contains(s string, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (func() bool { return stringIndex(s, sub) >= 0 })())
}

func stringIndex(s string, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
