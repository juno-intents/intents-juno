package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestRun_GeneratesAndPrintsJSON(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "operator.key")
	var out bytes.Buffer

	if err := run([]string{
		"generate",
		"-private-key-path", keyPath,
		"-fee-recipient", "0x52908400098527886E0F7030069857D2E4169EE7",
		"-storage-format", "encrypted",
		"-passphrase", "secret",
	}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	var v output
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if v.OperatorID == "" {
		t.Fatalf("operator_id missing")
	}
	if v.PrivateKeyPath != keyPath {
		t.Fatalf("private_key_path: got %q want %q", v.PrivateKeyPath, keyPath)
	}
	if v.FeeRecipient != "0x52908400098527886e0f7030069857d2e4169ee7" {
		t.Fatalf("fee_recipient: got %q", v.FeeRecipient)
	}
	if !v.PrivateKeyCreated {
		t.Fatalf("expected private_key_created to be true")
	}
	if v.StorageFormat != "encrypted" {
		t.Fatalf("storage_format: got %q want %q", v.StorageFormat, "encrypted")
	}
}

func TestRun_RejectsInvalidFeeRecipient(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "operator.key")
	var out bytes.Buffer

	err := run([]string{
		"generate",
		"-private-key-path", keyPath,
		"-fee-recipient", "0x1234",
		"-storage-format", "encrypted",
		"-passphrase", "secret",
	}, &out)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRun_InspectFailsForMissingKey(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "missing.key")
	var out bytes.Buffer

	err := run([]string{
		"inspect",
		"-private-key-path", keyPath,
	}, &out)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRun_GenerateRejectsPlaintextStorage(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "operator.key")
	var out bytes.Buffer

	err := run([]string{
		"generate",
		"-private-key-path", keyPath,
		"-storage-format", "plaintext",
		"-passphrase", "secret",
	}, &out)
	if err == nil {
		t.Fatalf("expected error")
	}
}
