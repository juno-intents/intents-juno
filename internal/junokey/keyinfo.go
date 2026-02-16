package junokey

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ripemd160"
)

var ErrInvalidPrivateKey = errors.New("junokey: invalid private key")

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func ParsePrivateKeyHex(raw string) ([]byte, error) {
	v := strings.TrimSpace(raw)
	v = strings.TrimPrefix(v, "0x")
	v = strings.TrimPrefix(v, "0X")
	if len(v) != 64 {
		return nil, ErrInvalidPrivateKey
	}
	key, err := hex.DecodeString(v)
	if err != nil {
		return nil, ErrInvalidPrivateKey
	}
	if _, err := crypto.ToECDSA(key); err != nil {
		return nil, ErrInvalidPrivateKey
	}
	return key, nil
}

func TestnetWIFCompressed(rawPrivateKeyHex string) (string, error) {
	key, err := ParsePrivateKeyHex(rawPrivateKeyHex)
	if err != nil {
		return "", err
	}
	payload := make([]byte, 0, 34)
	payload = append(payload, 0xEF)
	payload = append(payload, key...)
	payload = append(payload, 0x01)
	return base58CheckEncode(payload), nil
}

func TestnetTransparentAddress(rawPrivateKeyHex string) (string, error) {
	key, err := ParsePrivateKeyHex(rawPrivateKeyHex)
	if err != nil {
		return "", err
	}
	priv, err := crypto.ToECDSA(key)
	if err != nil {
		return "", ErrInvalidPrivateKey
	}
	compressedPubKey := crypto.CompressPubkey(&priv.PublicKey)

	sha := sha256.Sum256(compressedPubKey)
	ripe := ripemd160.New()
	if _, err := ripe.Write(sha[:]); err != nil {
		return "", err
	}
	hash160 := ripe.Sum(nil)

	payload := make([]byte, 0, 22)
	payload = append(payload, 0x1D, 0x25)
	payload = append(payload, hash160...)
	return base58CheckEncode(payload), nil
}

func base58CheckEncode(payload []byte) string {
	withChecksum := make([]byte, 0, len(payload)+4)
	withChecksum = append(withChecksum, payload...)
	withChecksum = append(withChecksum, doubleSHA256(payload)[:4]...)
	return base58Encode(withChecksum)
}

func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	out := make([]byte, 0, len(input)*2)
	for x.Cmp(zero) > 0 {
		x.QuoRem(x, base, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}

	for i := 0; i < len(input) && input[i] == 0; i++ {
		out = append(out, base58Alphabet[0])
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func doubleSHA256(input []byte) []byte {
	first := sha256.Sum256(input)
	second := sha256.Sum256(first[:])
	return second[:]
}
