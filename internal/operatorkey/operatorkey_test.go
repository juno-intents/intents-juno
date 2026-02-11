package operatorkey

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEnsurePrivateKeyFile_CreatesAndReuses(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	key1, created1, err := EnsurePrivateKeyFile(path)
	if err != nil {
		t.Fatalf("EnsurePrivateKeyFile create: %v", err)
	}
	if !created1 {
		t.Fatalf("created1: got false want true")
	}
	addr1 := OperatorIDFromPrivateKey(key1)
	if len(addr1) != 42 || addr1[:2] != "0x" {
		t.Fatalf("operator id format invalid: %q", addr1)
	}

	key2, created2, err := EnsurePrivateKeyFile(path)
	if err != nil {
		t.Fatalf("EnsurePrivateKeyFile reuse: %v", err)
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

