package operatorkey

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGeneratePrivateKeyFile_PlaintextCreatesAndReuses(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	key1, created1, err := GeneratePrivateKeyFile(path, GenerateOptions{Format: FormatPlaintext})
	if err != nil {
		t.Fatalf("GeneratePrivateKeyFile create: %v", err)
	}
	if !created1 {
		t.Fatalf("created1: got false want true")
	}
	addr1 := OperatorIDFromPrivateKey(key1)
	if len(addr1) != 42 || addr1[:2] != "0x" {
		t.Fatalf("operator id format invalid: %q", addr1)
	}

	key2, created2, err := LoadOrGeneratePlaintextPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("LoadOrGeneratePlaintextPrivateKeyFile reuse: %v", err)
	}
	if created2 {
		t.Fatalf("created2: got true want false")
	}
	addr2 := OperatorIDFromPrivateKey(key2)
	if addr2 != addr1 {
		t.Fatalf("address mismatch: got %q want %q", addr2, addr1)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat key: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("permissions: got %o want 600", got)
		}
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
