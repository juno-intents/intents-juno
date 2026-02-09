package memo

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustLoadHex(t *testing.T, name string) []byte {
	t.Helper()

	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	s := strings.TrimSpace(string(b))
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return out
}

func must20(t *testing.T, s string) [20]byte {
	t.Helper()

	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	if len(b) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(b))
	}
	var out [20]byte
	copy(out[:], b)
	return out
}

func must32(t *testing.T, s string) [32]byte {
	t.Helper()

	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func TestDepositMemoV1_Golden(t *testing.T) {
	golden := mustLoadHex(t, "deposit_v1_valid.hex")

	const chainID = uint32(8453)
	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")

	got, err := ParseDepositMemoV1(golden, chainID, bridge)
	if err != nil {
		t.Fatalf("ParseDepositMemoV1: %v", err)
	}

	if got.BaseChainID != chainID {
		t.Fatalf("BaseChainID: got %d want %d", got.BaseChainID, chainID)
	}
	if got.BridgeAddr != bridge {
		t.Fatalf("BridgeAddr mismatch")
	}

	wantRecipient := must20(t, "90f8bf6a479f320ead074411a4b0e7944ea8c9c1")
	if got.BaseRecipient != wantRecipient {
		t.Fatalf("BaseRecipient mismatch")
	}
	if got.Nonce != 0x0102030405060708 {
		t.Fatalf("Nonce: got 0x%x want 0x%x", got.Nonce, uint64(0x0102030405060708))
	}
	if got.Flags != 0xAABBCCDD {
		t.Fatalf("Flags: got 0x%x want 0x%x", got.Flags, uint32(0xAABBCCDD))
	}

	enc := got.Encode()
	if !bytes.Equal(enc[:], golden) {
		t.Fatalf("Encode mismatch vs golden")
	}
}

func TestDepositMemoV1_RejectsInvalidLength(t *testing.T) {
	const chainID = uint32(8453)
	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")

	_, err := ParseDepositMemoV1(make([]byte, 0), chainID, bridge)
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("expected ErrInvalidLength, got %v", err)
	}
}

func TestDepositMemoV1_RejectsInvalidMagic(t *testing.T) {
	golden := mustLoadHex(t, "deposit_v1_valid.hex")

	const chainID = uint32(8453)
	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")

	golden[0] ^= 0xff
	_, err := ParseDepositMemoV1(golden, chainID, bridge)
	if !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("expected ErrInvalidMagic, got %v", err)
	}
}

func TestDepositMemoV1_RejectsDomainMismatch(t *testing.T) {
	golden := mustLoadHex(t, "deposit_v1_valid.hex")

	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")
	_, err := ParseDepositMemoV1(golden, 1, bridge)
	if !errors.Is(err, ErrDomainMismatch) {
		t.Fatalf("expected ErrDomainMismatch(chainID), got %v", err)
	}

	const chainID = uint32(8453)
	wrongBridge := must20(t, "0000000000000000000000000000000000000001")

	_, err = ParseDepositMemoV1(golden, chainID, wrongBridge)
	if !errors.Is(err, ErrDomainMismatch) {
		t.Fatalf("expected ErrDomainMismatch(bridge), got %v", err)
	}
}

func TestDepositMemoV1_RejectsInvalidChecksum(t *testing.T) {
	golden := mustLoadHex(t, "deposit_v1_valid.hex")

	const chainID = uint32(8453)
	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")

	// Flip a byte covered by the CRC.
	golden[40] ^= 0x01
	_, err := ParseDepositMemoV1(golden, chainID, bridge)
	if !errors.Is(err, ErrInvalidChecksum) {
		t.Fatalf("expected ErrInvalidChecksum, got %v", err)
	}
}

func TestDepositMemoV1_RejectsNonZeroPadding(t *testing.T) {
	golden := mustLoadHex(t, "deposit_v1_valid.hex")

	const chainID = uint32(8453)
	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")

	golden[len(golden)-1] = 0x01
	_, err := ParseDepositMemoV1(golden, chainID, bridge)
	if !errors.Is(err, ErrNonZeroPadding) {
		t.Fatalf("expected ErrNonZeroPadding, got %v", err)
	}
}

func TestWithdrawalMemoV1_Golden(t *testing.T) {
	golden := mustLoadHex(t, "withdrawal_v1_valid.hex")

	const chainID = uint32(8453)
	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")

	got, err := ParseWithdrawalMemoV1(golden, chainID, bridge)
	if err != nil {
		t.Fatalf("ParseWithdrawalMemoV1: %v", err)
	}

	if got.BaseChainID != chainID {
		t.Fatalf("BaseChainID: got %d want %d", got.BaseChainID, chainID)
	}
	if got.BridgeAddr != bridge {
		t.Fatalf("BridgeAddr mismatch")
	}

	wantWithdrawalID := must32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if got.WithdrawalID != wantWithdrawalID {
		t.Fatalf("WithdrawalID mismatch")
	}
	wantBatchID := must32(t, "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	if got.BatchID != wantBatchID {
		t.Fatalf("BatchID mismatch")
	}
	if got.Flags != 0x11223344 {
		t.Fatalf("Flags: got 0x%x want 0x%x", got.Flags, uint32(0x11223344))
	}

	enc := got.Encode()
	if !bytes.Equal(enc[:], golden) {
		t.Fatalf("Encode mismatch vs golden")
	}
}

func TestWithdrawalMemoV1_RejectsInvalidMagic(t *testing.T) {
	golden := mustLoadHex(t, "withdrawal_v1_valid.hex")

	const chainID = uint32(8453)
	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")

	golden[0] ^= 0xff
	_, err := ParseWithdrawalMemoV1(golden, chainID, bridge)
	if !errors.Is(err, ErrInvalidMagic) {
		t.Fatalf("expected ErrInvalidMagic, got %v", err)
	}
}

func TestWithdrawalMemoV1_RejectsInvalidChecksum(t *testing.T) {
	golden := mustLoadHex(t, "withdrawal_v1_valid.hex")

	const chainID = uint32(8453)
	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")

	// Flip a byte covered by the CRC.
	golden[40] ^= 0x01
	_, err := ParseWithdrawalMemoV1(golden, chainID, bridge)
	if !errors.Is(err, ErrInvalidChecksum) {
		t.Fatalf("expected ErrInvalidChecksum, got %v", err)
	}
}

func TestWithdrawalMemoV1_RejectsNonZeroPadding(t *testing.T) {
	golden := mustLoadHex(t, "withdrawal_v1_valid.hex")

	const chainID = uint32(8453)
	bridge := must20(t, "1234567890abcdef1234567890abcdef12345678")

	golden[len(golden)-1] = 0x01
	_, err := ParseWithdrawalMemoV1(golden, chainID, bridge)
	if !errors.Is(err, ErrNonZeroPadding) {
		t.Fatalf("expected ErrNonZeroPadding, got %v", err)
	}
}
