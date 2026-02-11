package operatorkey

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	ErrInvalidAddress = errors.New("operatorkey: invalid address")
)

// EnsurePrivateKeyFile loads a secp256k1 private key from path, generating one if absent.
// The key is stored as lowercase hex without 0x prefix and mode 0600 on Unix.
func EnsurePrivateKeyFile(path string) (*ecdsa.PrivateKey, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false, fmt.Errorf("operatorkey: key path required")
	}

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		keyHex := strings.TrimSpace(strings.TrimPrefix(string(raw), "0x"))
		key, parseErr := crypto.HexToECDSA(keyHex)
		if parseErr != nil {
			return nil, false, fmt.Errorf("operatorkey: parse key %s: %w", path, parseErr)
		}
		return key, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("operatorkey: read key %s: %w", path, err)
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, false, fmt.Errorf("operatorkey: generate key: %w", err)
	}
	keyHex := strings.ToLower(common.Bytes2Hex(crypto.FromECDSA(key)))

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("operatorkey: create key dir: %w", err)
	}
	if err := writeFile0600(path, []byte(keyHex+"\n")); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

func OperatorIDFromPrivateKey(key *ecdsa.PrivateKey) string {
	addr := crypto.PubkeyToAddress(key.PublicKey)
	return strings.ToLower(addr.Hex())
}

func NormalizeAddress(input string) (string, error) {
	v := strings.TrimSpace(input)
	if !common.IsHexAddress(v) {
		return "", ErrInvalidAddress
	}
	return strings.ToLower(common.HexToAddress(v).Hex()), nil
}

func writeFile0600(path string, bytes []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("operatorkey: open key for write %s: %w", path, err)
	}
	if _, err := f.Write(bytes); err != nil {
		_ = f.Close()
		return fmt.Errorf("operatorkey: write key %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("operatorkey: sync key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("operatorkey: close key %s: %w", path, err)
	}
	return nil
}

