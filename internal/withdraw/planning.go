package withdraw

import (
	"bytes"
	"math/bits"
	"slices"
)

const bpsDenominator = uint64(10_000)

// ComputeFeeAndNet matches Bridge._computeFeeAndNet (contracts/src/Bridge.sol):
//
//	fee = floor(amount * feeBps / 10000)
//	net = amount - fee
//
// It uses 128-bit intermediate math to avoid uint64 overflow.
func ComputeFeeAndNet(amount uint64, feeBps uint32) (fee uint64, net uint64, err error) {
	if feeBps > uint32(bpsDenominator) {
		return 0, 0, ErrInvalidFeeBps
	}

	hi, lo := bits.Mul64(amount, uint64(feeBps))
	fee, _ = bits.Div64(hi, lo, bpsDenominator)
	net = amount - fee
	return fee, net, nil
}

// SelectForBatch returns up to maxItems withdrawals, sorted deterministically by ID ascending.
// It rejects duplicate IDs.
func SelectForBatch(withdrawals []Withdrawal, maxItems int) ([]Withdrawal, error) {
	if maxItems <= 0 {
		return nil, ErrInvalidConfig
	}
	if len(withdrawals) == 0 {
		return nil, nil
	}

	out := make([]Withdrawal, len(withdrawals))
	copy(out, withdrawals)

	slices.SortFunc(out, func(a, b Withdrawal) int {
		return bytes.Compare(a.ID[:], b.ID[:])
	})

	for i := 1; i < len(out); i++ {
		if out[i].ID == out[i-1].ID {
			return nil, ErrDuplicateWithdrawalID
		}
	}

	if len(out) > maxItems {
		out = out[:maxItems]
	}
	return out, nil
}
