package operatorkey

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratePrivateKeyFile_PlaintextRejected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	key, created, err := GeneratePrivateKeyFile(path, GenerateOptions{Format: StorageFormat("plaintext")})
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("GeneratePrivateKeyFile plaintext: got %v want %v", err, ErrUnsupportedFormat)
	}
	if key != nil {
		t.Fatalf("expected nil key")
	}
	if created {
		t.Fatalf("expected created=false")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected key file to remain absent, got %v", statErr)
	}
}

func TestLoadPrivateKeyFile_MissingFails(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.key")
	if _, err := LoadPrivateKeyFile(path, LoadOptions{}); err == nil {
		t.Fatalf("expected missing file error")
	}
}

func TestGeneratePrivateKeyFile_EncryptedAndLoad(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "operator.key")
	passphrase := "correct horse battery staple"

	key, created, err := GeneratePrivateKeyFile(path, GenerateOptions{
		Format:     FormatEncrypted,
		Passphrase: passphrase,
	})
	if err != nil {
		t.Fatalf("GeneratePrivateKeyFile encrypted: %v", err)
	}
	if !created {
		t.Fatalf("expected encrypted file to be created")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytesContains(raw, []byte(OperatorIDFromPrivateKey(key))) {
		t.Fatalf("expected encrypted file not to contain plaintext operator id")
	}
	if bytesContains(raw, []byte("0x")) {
		t.Fatalf("expected encrypted file not to look like plaintext hex")
	}

	loaded, err := LoadPrivateKeyFile(path, LoadOptions{Passphrase: passphrase})
	if err != nil {
		t.Fatalf("LoadPrivateKeyFile encrypted: %v", err)
	}
	if OperatorIDFromPrivateKey(loaded) != OperatorIDFromPrivateKey(key) {
		t.Fatalf("loaded key mismatch")
	}
}

func TestGeneratePrivateKeyFile_DefaultsToEncrypted(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "operator.key")
	passphrase := "default encrypted secret"

	key, created, err := GeneratePrivateKeyFile(path, GenerateOptions{Passphrase: passphrase})
	if err != nil {
		t.Fatalf("GeneratePrivateKeyFile default: %v", err)
	}
	if !created {
		t.Fatalf("expected encrypted file to be created")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytesContains(raw, []byte(OperatorIDFromPrivateKey(key))) {
		t.Fatalf("expected default key file not to contain plaintext operator id")
	}

	if _, err := LoadPrivateKeyFile(path, LoadOptions{}); err == nil {
		t.Fatalf("expected encrypted default file to require a passphrase")
	}
}

func TestGeneratePrivateKeyFile_DefaultWithoutPassphraseFailsBeforeWriting(t *testing.T) {
	t.Parallel()

	baseDir := t.TempDir()
	keyDir := filepath.Join(baseDir, "operator")
	path := filepath.Join(keyDir, "operator.key")

	key, created, err := GeneratePrivateKeyFile(path, GenerateOptions{})
	if !errors.Is(err, ErrMissingPassphrase) {
		t.Fatalf("GeneratePrivateKeyFile default missing passphrase: got %v want %v", err, ErrMissingPassphrase)
	}
	if key != nil {
		t.Fatalf("expected nil key on missing passphrase")
	}
	if created {
		t.Fatalf("expected created to be false on missing passphrase")
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected key file to remain absent, got %v", statErr)
	}
	if _, statErr := os.Stat(keyDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("expected key dir to remain absent, got %v", statErr)
	}
}

func TestLoadPrivateKeyFile_EncryptedRequiresPassphrase(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "operator.key")
	if _, _, err := GeneratePrivateKeyFile(path, GenerateOptions{
		Format:     FormatEncrypted,
		Passphrase: "secret",
	}); err != nil {
		t.Fatalf("GeneratePrivateKeyFile encrypted: %v", err)
	}

	if _, err := LoadPrivateKeyFile(path, LoadOptions{}); err == nil {
		t.Fatalf("expected missing passphrase error")
	}
}

func TestNormalizeAddress(t *testing.T) {
	t.Parallel()

	const in = "0x52908400098527886E0F7030069857D2E4169EE7"
	got, err := NormalizeAddress(in)
	if err != nil {
		t.Fatalf("NormalizeAddress: %v", err)
	}
	if got != "0x52908400098527886e0f7030069857d2e4169ee7" {
		t.Fatalf("normalized: got %q", got)
	}

	if _, err := NormalizeAddress("0x1234"); err == nil {
		t.Fatalf("expected invalid address error")
	}
}

func bytesContains(haystack []byte, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
