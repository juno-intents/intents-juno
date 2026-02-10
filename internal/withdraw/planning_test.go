package withdraw

import (
	"errors"
	"testing"
	"time"
)

func seq32(start byte) (out [32]byte) {
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

func TestComputeFeeAndNet_Vectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		amount  uint64
		feeBps  uint32
		wantFee uint64
		wantNet uint64
		wantErr error
	}{
		{name: "zero_fee", amount: 123, feeBps: 0, wantFee: 0, wantNet: 123},
		{name: "50bps", amount: 10_000, feeBps: 50, wantFee: 50, wantNet: 9_950},
		{name: "max_fee", amount: 123, feeBps: 10_000, wantFee: 123, wantNet: 0},
		{name: "reject_gt_10000", amount: 1, feeBps: 10_001, wantErr: ErrInvalidFeeBps},
		{name: "max_uint64_full_fee", amount: ^uint64(0), feeBps: 10_000, wantFee: ^uint64(0), wantNet: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fee, net, err := ComputeFeeAndNet(tt.amount, tt.feeBps)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected err %v, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if fee != tt.wantFee {
				t.Fatalf("fee: got %d want %d", fee, tt.wantFee)
			}
			if net != tt.wantNet {
				t.Fatalf("net: got %d want %d", net, tt.wantNet)
			}
		})
	}
}

func TestSelectForBatch_DeterministicSortAndLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)
	in := []Withdrawal{
		{ID: seq32(0x20), Amount: 2, FeeBps: 0, Expiry: now.Add(10 * time.Hour), RecipientUA: []byte{0x02}},
		{ID: seq32(0x00), Amount: 1, FeeBps: 0, Expiry: now.Add(10 * time.Hour), RecipientUA: []byte{0x01}},
		{ID: seq32(0x40), Amount: 3, FeeBps: 0, Expiry: now.Add(10 * time.Hour), RecipientUA: []byte{0x03}},
	}

	got, err := SelectForBatch(in, 2)
	if err != nil {
		t.Fatalf("SelectForBatch: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len: got %d want %d", len(got), 2)
	}
	if got[0].ID != seq32(0x00) || got[1].ID != seq32(0x20) {
		t.Fatalf("unexpected order: %x %x", got[0].ID, got[1].ID)
	}
}

func TestSelectForBatch_RejectsDuplicates(t *testing.T) {
	t.Parallel()

	id := seq32(0x00)
	_, err := SelectForBatch([]Withdrawal{{ID: id}, {ID: id}}, 10)
	if !errors.Is(err, ErrDuplicateWithdrawalID) {
		t.Fatalf("expected ErrDuplicateWithdrawalID, got %v", err)
	}
}

func TestSelectForBatch_RejectsInvalidMaxItems(t *testing.T) {
	t.Parallel()

	_, err := SelectForBatch([]Withdrawal{}, 0)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestWithdrawal_Validate_RejectsRecipientUATooLong(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 9, 0, 0, 0, 0, time.UTC)

	w := Withdrawal{
		ID:          seq32(0x01),
		Amount:      1,
		FeeBps:      0,
		RecipientUA: make([]byte, 257),
		Expiry:      now.Add(24 * time.Hour),
	}
	if err := w.Validate(); err == nil {
		t.Fatalf("expected error")
	}
}
