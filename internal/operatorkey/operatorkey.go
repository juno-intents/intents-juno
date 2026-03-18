package operatorkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/scrypt"
)

var (
	ErrInvalidAddress     = errors.New("operatorkey: invalid address")
	ErrMissingPassphrase  = errors.New("operatorkey: passphrase required")
	ErrUnsupportedFormat  = errors.New("operatorkey: unsupported key format")
	ErrEncryptedKeyFormat = errors.New("operatorkey: encrypted key file")
)

type StorageFormat string

const (
	FormatEncrypted StorageFormat = "encrypted"
)

const encryptedFileVersion = "operatorkey.encrypted.v1"

type GenerateOptions struct {
	Format     StorageFormat
	Passphrase string
}

type LoadOptions struct {
	Passphrase string
}

type encryptedFile struct {
	Version   string `json:"version"`
	SaltHex   string `json:"salt_hex"`
	NonceHex  string `json:"nonce_hex"`
	CipherHex string `json:"cipher_hex"`
}

// GeneratePrivateKeyFile loads or creates an encrypted secp256k1 private key at path.
func GeneratePrivateKeyFile(path string, opts GenerateOptions) (*ecdsa.PrivateKey, bool, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false, fmt.Errorf("operatorkey: key path required")
	}
	if opts.Format == "" {
		opts.Format = FormatEncrypted
	}

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		key, loadErr := loadPrivateKeyBytes(path, raw, LoadOptions{Passphrase: opts.Passphrase})
		if loadErr != nil {
			return nil, false, loadErr
		}
		return key, false, nil
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, fmt.Errorf("operatorkey: read key %s: %w", path, err)
	}

	if opts.Format == FormatEncrypted && strings.TrimSpace(opts.Passphrase) == "" {
		return nil, false, ErrMissingPassphrase
	}

	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, false, fmt.Errorf("operatorkey: generate key: %w", err)
	}
	keyHex := strings.ToLower(common.Bytes2Hex(crypto.FromECDSA(key)))

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("operatorkey: create key dir: %w", err)
	}
	encoded, err := marshalPrivateKeyFile(keyHex, opts)
	if err != nil {
		return nil, false, err
	}
	if err := writeFile0600(path, encoded); err != nil {
		return nil, false, err
	}
	return key, true, nil
}

// LoadPrivateKeyFile loads an existing private key and fails if the file is missing.
func LoadPrivateKeyFile(path string, opts LoadOptions) (*ecdsa.PrivateKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("operatorkey: key path required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("operatorkey: read key %s: %w", path, err)
	}
	return loadPrivateKeyBytes(path, raw, opts)
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

func marshalPrivateKeyFile(keyHex string, opts GenerateOptions) ([]byte, error) {
	switch opts.Format {
	case FormatEncrypted:
		if strings.TrimSpace(opts.Passphrase) == "" {
			return nil, ErrMissingPassphrase
		}
		sealed, err := encryptKeyHex(keyHex, opts.Passphrase)
		if err != nil {
			return nil, err
		}
		encoded, err := json.MarshalIndent(sealed, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("operatorkey: marshal encrypted key: %w", err)
		}
		return append(encoded, '\n'), nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, opts.Format)
	}
}

func loadPrivateKeyBytes(path string, raw []byte, opts LoadOptions) (*ecdsa.PrivateKey, error) {
	keyHex, err := decodePrivateKeyHex(raw, opts)
	if err != nil {
		return nil, fmt.Errorf("operatorkey: parse key %s: %w", path, err)
	}
	key, parseErr := crypto.HexToECDSA(keyHex)
	if parseErr != nil {
		return nil, fmt.Errorf("operatorkey: parse key %s: %w", path, parseErr)
	}
	return key, nil
}

func decodePrivateKeyHex(raw []byte, opts LoadOptions) (string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "{") {
		if strings.TrimSpace(opts.Passphrase) == "" {
			return "", ErrMissingPassphrase
		}
		return decryptKeyHex([]byte(trimmed), opts.Passphrase)
	}
	return "", fmt.Errorf("%w: plaintext", ErrUnsupportedFormat)
}

func encryptKeyHex(keyHex string, passphrase string) (*encryptedFile, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("operatorkey: read salt: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("operatorkey: read nonce: %w", err)
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("operatorkey: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("operatorkey: create gcm: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(keyHex), nil)
	return &encryptedFile{
		Version:   encryptedFileVersion,
		SaltHex:   hex.EncodeToString(salt),
		NonceHex:  hex.EncodeToString(nonce),
		CipherHex: hex.EncodeToString(ciphertext),
	}, nil
}

func decryptKeyHex(raw []byte, passphrase string) (string, error) {
	var file encryptedFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return "", fmt.Errorf("%w: %v", ErrEncryptedKeyFormat, err)
	}
	if file.Version != encryptedFileVersion {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedFormat, file.Version)
	}
	salt, err := hex.DecodeString(file.SaltHex)
	if err != nil {
		return "", fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := hex.DecodeString(file.NonceHex)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := hex.DecodeString(file.CipherHex)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("operatorkey: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("operatorkey: create gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt key: %w", err)
	}
	return strings.TrimSpace(string(plaintext)), nil
}

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, 1<<15, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("operatorkey: derive key: %w", err)
	}
	return key, nil
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
