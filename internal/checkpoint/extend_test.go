package checkpoint

import (
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestExtendWithdrawDigest_GoldenVector(t *testing.T) {
	t.Parallel()

	ids := [][32]byte{
		[32]byte(common.HexToHash("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")),
		[32]byte(common.HexToHash("0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")),
	}

	got, err := ExtendWithdrawDigest(
		ids,
		1730000000,
		8453,
		common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	)
	if err != nil {
		t.Fatalf("ExtendWithdrawDigest: %v", err)
	}

	want := common.HexToHash("0x096b6960ecac1de01b1d37dea33c1b774f83c442c9a69e0c84b0f90ef0fbfef8")
	if got != want {
		t.Fatalf("digest mismatch:\n got  %s\n want %s", got, want)
	}
}

func TestExtendWithdrawDigest_RejectsUnsortedOrDuplicateIDs(t *testing.T) {
	t.Parallel()

	id0 := [32]byte(common.HexToHash("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	id1 := [32]byte(common.HexToHash("0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))

	_, err := ExtendWithdrawDigest(
		[][32]byte{id1, id0},
		1730000000,
		8453,
		common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	)
	if !errors.Is(err, ErrInvalidExtendInput) {
		t.Fatalf("expected ErrInvalidExtendInput for unsorted ids, got %v", err)
	}

	_, err = ExtendWithdrawDigest(
		[][32]byte{id0, id0},
		1730000000,
		8453,
		common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	)
	if !errors.Is(err, ErrInvalidExtendInput) {
		t.Fatalf("expected ErrInvalidExtendInput for duplicate ids, got %v", err)
	}
}

func TestMarkWithdrawPaidDigest_GoldenVector(t *testing.T) {
	t.Parallel()

	ids := [][32]byte{
		[32]byte(common.HexToHash("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")),
		[32]byte(common.HexToHash("0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")),
	}

	got, err := MarkWithdrawPaidDigest(
		ids,
		8453,
		common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	)
	if err != nil {
		t.Fatalf("MarkWithdrawPaidDigest: %v", err)
	}

	want := common.HexToHash("0x101f5ce86f5fa3558a6ee9534d5753f4a1ddb5b995f679a43d0c2a8a6288d3b4")
	if got != want {
		t.Fatalf("digest mismatch:\n got  %s\n want %s", got, want)
	}
}

func TestMarkWithdrawPaidDigest_RejectsUnsortedOrDuplicateIDs(t *testing.T) {
	t.Parallel()

	id0 := [32]byte(common.HexToHash("0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	id1 := [32]byte(common.HexToHash("0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))

	_, err := MarkWithdrawPaidDigest(
		[][32]byte{id1, id0},
		8453,
		common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	)
	if !errors.Is(err, ErrInvalidMarkWithdrawPaidInput) {
		t.Fatalf("expected ErrInvalidMarkWithdrawPaidInput for unsorted ids, got %v", err)
	}

	_, err = MarkWithdrawPaidDigest(
		[][32]byte{id0, id0},
		8453,
		common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	)
	if !errors.Is(err, ErrInvalidMarkWithdrawPaidInput) {
		t.Fatalf("expected ErrInvalidMarkWithdrawPaidInput for duplicate ids, got %v", err)
	}
}
