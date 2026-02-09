package eth

import (
	"math/big"
	"testing"
)

func bi(v int64) *big.Int { return big.NewInt(v) }

func TestCalc1559Fees_UsesMinTipAndTwoXBaseFee(t *testing.T) {
	baseFee := bi(100)
	suggestedTip := bi(2)
	minTip := bi(5)

	tip, fee, err := Calc1559Fees(baseFee, suggestedTip, minTip)
	if err != nil {
		t.Fatalf("Calc1559Fees: %v", err)
	}
	if tip.Cmp(bi(5)) != 0 {
		t.Fatalf("tip: got %s want %s", tip, bi(5))
	}
	// feeCap = 2*baseFee + tip = 205
	if fee.Cmp(bi(205)) != 0 {
		t.Fatalf("fee: got %s want %s", fee, bi(205))
	}
}

func TestBump1559Fees_BumpsWithMinIncrementAndKeepsFeeAboveTip(t *testing.T) {
	oldTip := bi(1)
	oldFee := bi(2)

	newTip, newFee, err := Bump1559Fees(oldTip, oldFee, 10, bi(1), bi(1))
	if err != nil {
		t.Fatalf("Bump1559Fees: %v", err)
	}

	// 1*1.10 rounds to 1; min bump forces at least 2.
	if newTip.Cmp(bi(2)) != 0 {
		t.Fatalf("newTip: got %s want %s", newTip, bi(2))
	}
	// 2*1.10 rounds to 2; min bump forces at least 3.
	if newFee.Cmp(bi(3)) != 0 {
		t.Fatalf("newFee: got %s want %s", newFee, bi(3))
	}
	if newFee.Cmp(newTip) < 0 {
		t.Fatalf("feeCap must be >= tipCap: fee=%s tip=%s", newFee, newTip)
	}
}
