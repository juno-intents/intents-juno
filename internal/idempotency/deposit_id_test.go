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
			want:      mustHash32(t, "b4a0ea76a331f40daeed74b0eb98b2b4e4589b89c8594233288b437cef32d5d1"),
		},
		{
			name:      "leaf1",
			leafIndex: 1,
			want:      mustHash32(t, "5954e7bccaf375ef1fd3b6cd98eb232533bb15255e28409729cc0b4701cf2d40"),
		},
		{
			name:      "guest_vector_leaf01020304",
			leafIndex: 0x01020304,
			want:      mustHash32(t, "bc0d27e33687de6a88da7055aa24664601360166e373ebc9b7b7c22fe212c187"),
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
