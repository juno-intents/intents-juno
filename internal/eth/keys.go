package eth

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

var ErrInvalidPrivateKey = errors.New("eth: invalid private key")

// ParsePrivateKeysHexList parses one or more secp256k1 private keys from a comma-separated hex string.
//
// Input format:
// - keys separated by commas
// - each key is 32 bytes hex, with optional 0x prefix
//
// The returned error is sanitized and must not include key material.
func ParsePrivateKeysHexList(s string) ([]*ecdsa.PrivateKey, error) {
	parts := strings.Split(s, ",")
	var out []*ecdsa.PrivateKey
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.TrimPrefix(p, "0x")
		key, err := crypto.HexToECDSA(p)
		if err != nil {
			return nil, fmt.Errorf("%w: index %d", ErrInvalidPrivateKey, i)
		}
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, ErrInvalidPrivateKey
	}
	return out, nil
}
