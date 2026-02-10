package idempotency

import (
	"encoding/hex"
	"strings"
	"testing"
)

func mustHash32(t *testing.T, s string) [32]byte {
	t.Helper()

	s = strings.TrimSpace(strings.TrimPrefix(s, "0x"))
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

func TestDepositIDV1_Vectors(t *testing.T) {
	cm := mustHash32(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	tests := []struct {
		name      string
		leafIndex uint64
		want      [32]byte
	}{
		{
			name:      "leaf0",
			leafIndex: 0,
			want:      mustHash32(t, "11817f77f8cd0ac8b09b9ee546147a341256e16a4e000c6f7dde10cf89538c79"),
		},
		{
			name:      "leaf1",
			leafIndex: 1,
			want:      mustHash32(t, "3586619ba76600584824650f84bdff4f8647a46e248f7766eff73774ce469fc1"),
		},
		{
			name:      "leaf0102030405060708",
			leafIndex: 0x0102030405060708,
			want:      mustHash32(t, "b7d9a32e04c4e56e6709768e831bd6532c786c208c76d1c0e8942bec713b6e17"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DepositIDV1(cm, tt.leafIndex)
			if got != tt.want {
				t.Fatalf("DepositIDV1 mismatch: got %x want %x", got, tt.want)
			}
		})
	}
}

