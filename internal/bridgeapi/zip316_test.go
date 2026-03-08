package bridgeapi

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDecodeOrchardRawFromUA_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string // hex-encoded 43-byte Orchard receiver
		hrp  string
	}{
		{
			name: "testnet address",
			raw:  "aabbccdd00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233440011",
			hrp:  "jtest",
		},
		{
			name: "mainnet address",
			raw:  "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b",
			hrp:  "j",
		},
		{
			name: "all zeros",
			raw:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			hrp:  "jtest",
		},
		{
			name: "all ff",
			raw:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			hrp:  "jtest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rawBytes, err := hex.DecodeString(tt.raw)
			if err != nil {
				t.Fatalf("hex decode: %v", err)
			}
			if len(rawBytes) != 43 {
				t.Fatalf("raw length: got %d want 43", len(rawBytes))
			}

			ua, err := encodeOrchardRawUA(rawBytes, tt.hrp)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}

			decoded, err := DecodeOrchardRawFromUA(ua)
			if err != nil {
				t.Fatalf("decode(%q): %v", ua, err)
			}

			if !bytes.Equal(decoded, rawBytes) {
				t.Fatalf("round-trip failed:\n  want: %x\n  got:  %x", rawBytes, decoded)
			}
		})
	}
}

func TestDecodeOrchardRawFromUA_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ua   string
	}{
		{name: "empty input", ua: ""},
		{name: "no separator", ua: "abcdef"},
		{name: "uppercase chars", ua: "JTEST1abc"},
		{name: "too short", ua: "jtest1qqqqq"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := DecodeOrchardRawFromUA(tt.ua)
			if err == nil {
				t.Fatalf("expected error for %q", tt.ua)
			}
		})
	}
}

func TestDecodeOrchardRawFromUA_BadChecksum(t *testing.T) {
	t.Parallel()

	rawBytes := make([]byte, 43)
	for i := range rawBytes {
		rawBytes[i] = byte(i)
	}
	ua, err := encodeOrchardRawUA(rawBytes, "jtest")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// Corrupt the last character (part of checksum).
	corrupted := ua[:len(ua)-1] + "q"
	if corrupted == ua {
		corrupted = ua[:len(ua)-1] + "p"
	}

	_, err = DecodeOrchardRawFromUA(corrupted)
	if err == nil {
		t.Fatal("expected error for corrupted checksum")
	}
}
