package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUFVK(t *testing.T) {
	t.Parallel()

	got, err := resolveUFVK("jviewregtest1abc", "")
	if err != nil {
		t.Fatalf("resolveUFVK direct: %v", err)
	}
	if got != "jviewregtest1abc" {
		t.Fatalf("ufvk mismatch: %q", got)
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "ufvk.txt")
	if err := os.WriteFile(p, []byte("jviewregtest1file\n"), 0o600); err != nil {
		t.Fatalf("write ufvk file: %v", err)
	}
	got, err = resolveUFVK("", p)
	if err != nil {
		t.Fatalf("resolveUFVK file: %v", err)
	}
	if got != "jviewregtest1file" {
		t.Fatalf("ufvk from file mismatch: %q", got)
	}
}

func TestResolveUFVK_RejectsBadInput(t *testing.T) {
	t.Parallel()

	if _, err := resolveUFVK("", ""); err == nil {
		t.Fatalf("expected error for missing sources")
	}
	if _, err := resolveUFVK("a", "b"); err == nil {
		t.Fatalf("expected error for conflicting sources")
	}
}

func TestReadLimited(t *testing.T) {
	t.Parallel()

	b, err := readLimited(bytes.NewBufferString("abc"), 3)
	if err != nil {
		t.Fatalf("readLimited: %v", err)
	}
	if string(b) != "abc" {
		t.Fatalf("read mismatch: %q", string(b))
	}

	if _, err := readLimited(bytes.NewBufferString("abcd"), 3); err == nil {
		t.Fatalf("expected limit error")
	}
}
