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
		"-private-key-path", keyPath,
		"-fee-recipient", "0x52908400098527886E0F7030069857D2E4169EE7",
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
}

func TestRun_RejectsInvalidFeeRecipient(t *testing.T) {
	t.Parallel()

	keyPath := filepath.Join(t.TempDir(), "operator.key")
	var out bytes.Buffer

	err := run([]string{
		"-private-key-path", keyPath,
		"-fee-recipient", "0x1234",
	}, &out)
	if err == nil {
		t.Fatalf("expected error")
	}
}

