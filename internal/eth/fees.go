package eth

import (
	"errors"
	"math/big"
)

var ErrInvalidFeeArgs = errors.New("eth: invalid fee args")

// Calc1559Fees returns conservative EIP-1559 fee caps based on the latest block base fee.
//
// Policy:
// - tipCap = max(suggestedTipCap, minTipCap)
// - feeCap = 2*baseFee + tipCap
func Calc1559Fees(baseFee, suggestedTipCap, minTipCap *big.Int) (tipCap, feeCap *big.Int, err error) {
	if baseFee == nil || suggestedTipCap == nil || minTipCap == nil {
		return nil, nil, ErrInvalidFeeArgs
	}
	if baseFee.Sign() < 0 || suggestedTipCap.Sign() < 0 || minTipCap.Sign() < 0 {
		return nil, nil, ErrInvalidFeeArgs
	}

	tip := new(big.Int).Set(suggestedTipCap)
	if tip.Cmp(minTipCap) < 0 {
		tip.Set(minTipCap)
	}

	fee := new(big.Int).Mul(baseFee, big.NewInt(2))
	fee.Add(fee, tip)

	return tip, fee, nil
}

// Bump1559Fees bumps EIP-1559 fee caps by a percentage, with a minimum absolute bump.
//
// This is intended for replacement transactions. Geth's txpool enforces that replacements must
// be sufficiently higher-priced than the transactions they replace; percentage bumps alone can
// be rounded away for small values, so we additionally enforce a minimum increment.
func Bump1559Fees(tipCap, feeCap *big.Int, bumpPercent int, minTipBump, minFeeCapBump *big.Int) (newTipCap, newFeeCap *big.Int, err error) {
	if tipCap == nil || feeCap == nil {
		return nil, nil, ErrInvalidFeeArgs
	}
	if tipCap.Sign() < 0 || feeCap.Sign() < 0 {
		return nil, nil, ErrInvalidFeeArgs
	}
	if bumpPercent <= 0 {
		return nil, nil, ErrInvalidFeeArgs
	}
	if minTipBump != nil && minTipBump.Sign() < 0 {
		return nil, nil, ErrInvalidFeeArgs
	}
	if minFeeCapBump != nil && minFeeCapBump.Sign() < 0 {
		return nil, nil, ErrInvalidFeeArgs
	}

	pct := big.NewInt(int64(100 + bumpPercent))
	hundred := big.NewInt(100)

	newTip := new(big.Int).Mul(tipCap, pct)
	newTip.Div(newTip, hundred)
	if minTipBump != nil && minTipBump.Sign() > 0 {
		min := new(big.Int).Add(tipCap, minTipBump)
		if newTip.Cmp(min) < 0 {
			newTip = min
		}
	}

	newFee := new(big.Int).Mul(feeCap, pct)
	newFee.Div(newFee, hundred)
	if minFeeCapBump != nil && minFeeCapBump.Sign() > 0 {
		min := new(big.Int).Add(feeCap, minFeeCapBump)
		if newFee.Cmp(min) < 0 {
			newFee = min
		}
	}

	// Ensure feeCap is always >= tipCap.
	if newFee.Cmp(newTip) < 0 {
		newFee = new(big.Int).Set(newTip)
	}

	return newTip, newFee, nil
}

