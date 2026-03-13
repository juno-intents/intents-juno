package httpapi

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

type BalanceReader interface {
	BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error)
}

func MinSignerBalanceReadinessCheck(reader BalanceReader, signers []common.Address, minBalance *big.Int) func(context.Context) error {
	if reader == nil || len(signers) == 0 || minBalance == nil || minBalance.Sign() <= 0 {
		return nil
	}

	required := new(big.Int).Set(minBalance)
	signerSet := append([]common.Address(nil), signers...)

	return func(ctx context.Context) error {
		for _, signer := range signerSet {
			balance, err := reader.BalanceAt(ctx, signer, nil)
			if err != nil {
				return fmt.Errorf("signer %s balance unavailable: %w", signer.Hex(), err)
			}
			if balance == nil {
				return fmt.Errorf("signer %s balance unavailable", signer.Hex())
			}
			if balance.Cmp(required) < 0 {
				return fmt.Errorf("signer %s balance %s below minimum %s", signer.Hex(), balance.String(), required.String())
			}
		}
		return nil
	}
}
