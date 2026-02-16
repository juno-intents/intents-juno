package junokey

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ripemd160"
)

var errDecodeBase58Check = errors.New("decode base58check failed")

func TestTestnetWIFCompressed_PayloadRoundTrip(t *testing.T) {
	t.Parallel()

	keyHex := "0x4c0883a69102937d6231471b5dbb6204fe5129617082794e8a16f3f6c52b7d03"
	wif, err := TestnetWIFCompressed(keyHex)
	if err != nil {
		t.Fatalf("TestnetWIFCompressed: %v", err)
	}

	payload, err := decodeBase58CheckForTest(wif)
	if err != nil {
		t.Fatalf("decode base58check: %v", err)
	}
	if len(payload) != 34 {
		t.Fatalf("payload len: got %d want 34", len(payload))
	}
	if payload[0] != 0xEF {
		t.Fatalf("prefix: got 0x%02x want 0xEF", payload[0])
	}
	if payload[33] != 0x01 {
		t.Fatalf("compression flag: got 0x%02x want 0x01", payload[33])
	}

	wantKey, _ := hex.DecodeString(strings.TrimPrefix(keyHex, "0x"))
	if !bytes.Equal(payload[1:33], wantKey) {
		t.Fatalf("payload key mismatch")
	}
}

func TestTestnetTransparentAddress_PayloadRoundTrip(t *testing.T) {
	t.Parallel()

	keyHex := "0x4c0883a69102937d6231471b5dbb6204fe5129617082794e8a16f3f6c52b7d03"
	addr, err := TestnetTransparentAddress(keyHex)
	if err != nil {
		t.Fatalf("TestnetTransparentAddress: %v", err)
	}

	payload, err := decodeBase58CheckForTest(addr)
	if err != nil {
		t.Fatalf("decode base58check: %v", err)
	}
	if len(payload) != 22 {
		t.Fatalf("payload len: got %d want 22", len(payload))
	}
	if payload[0] != 0x1D || payload[1] != 0x25 {
		t.Fatalf("prefix: got %x want 1d25", payload[:2])
	}

	keyBytes, _ := hex.DecodeString(strings.TrimPrefix(keyHex, "0x"))
	priv, err := crypto.ToECDSA(keyBytes)
	if err != nil {
		t.Fatalf("crypto.ToECDSA: %v", err)
	}
	compressed := crypto.CompressPubkey(&priv.PublicKey)
	sha := sha256.Sum256(compressed)
	r := ripemd160.New()
	if _, err := r.Write(sha[:]); err != nil {
		t.Fatalf("ripemd write: %v", err)
	}
	wantHash160 := r.Sum(nil)
	if !bytes.Equal(payload[2:], wantHash160) {
		t.Fatalf("pubkey hash mismatch")
	}
}

func TestParsePrivateKeyHex_RejectsWrongLength(t *testing.T) {
	t.Parallel()

	_, err := ParsePrivateKeyHex("0x1234")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func decodeBase58CheckForTest(encoded string) ([]byte, error) {
	raw, err := decodeBase58ForTest(encoded)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, errDecodeBase58Check
	}
	payload := raw[:len(raw)-4]
	checksum := raw[len(raw)-4:]
	want := doubleSHA256(payload)[:4]
	if !bytes.Equal(checksum, want) {
		return nil, errDecodeBase58Check
	}
	return payload, nil
}

func decodeBase58ForTest(s string) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, errDecodeBase58Check
	}
	table := make(map[rune]int64, len(base58Alphabet))
	for i, r := range base58Alphabet {
		table[r] = int64(i)
	}

	n := big.NewInt(0)
	base := big.NewInt(58)
	for _, r := range s {
		val, ok := table[r]
		if !ok {
			return nil, errDecodeBase58Check
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(val))
	}

	decoded := n.Bytes()
	leadingZeros := 0
	for _, ch := range s {
		if ch == '1' {
			leadingZeros++
			continue
		}
		break
	}
	if leadingZeros > 0 {
		out := make([]byte, leadingZeros+len(decoded))
		copy(out[leadingZeros:], decoded)
		return out, nil
	}
	return decoded, nil
}
