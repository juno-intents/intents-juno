package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeValidProofInputs(t *testing.T, path string) {
	t.Helper()

	payload := map[string]any{
		"version":          "bridge-e2e.proof_inputs.v1",
		"generated_at_utc": "2026-02-17T00:00:00Z",
		"chain_id":         84532,
		"bridge_contract":  "0x1111111111111111111111111111111111111111",
		"checkpoint": map[string]any{
			"height":           123,
			"blockHash":        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"finalOrchardRoot": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"baseChainId":      84532,
			"bridgeContract":   "0x1111111111111111111111111111111111111111",
		},
		"operator_signatures": []string{
			"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1b",
			"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1c",
		},
		"deposit": map[string]any{
			"proof_input": map[string]any{
				"pipeline":      "deposit",
				"image_id":      "0x000000000000000000000000000000000000000000000000000000000000aa01",
				"journal":       "0x010203",
				"private_input": "0x00",
			},
			"deposit_id": "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"recipient":  "0x1111111111111111111111111111111111111111",
			"amount":     "100000",
		},
		"withdraw": map[string]any{
			"proof_input": map[string]any{
				"pipeline":      "withdraw",
				"image_id":      "0x000000000000000000000000000000000000000000000000000000000000aa02",
				"journal":       "0x040506",
				"private_input": "0x00",
			},
			"recipient_ua_hex": "0x010203",
			"withdrawal_id":    "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			"net_amount":       "9950",
		},
	}

	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal proof inputs: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write proof inputs: %v", err)
	}
}

func TestParseArgs_Valid(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "sender.key")
	proofFile := filepath.Join(tmp, "bridge-proof-inputs.json")
	depositSeal := filepath.Join(tmp, "deposit.seal.hex")
	withdrawSeal := filepath.Join(tmp, "withdraw.seal.hex")

	writeFile(t, keyFile, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n")
	writeValidProofInputs(t, proofFile)
	writeFile(t, depositSeal, "0x1234\n")
	writeFile(t, withdrawSeal, "0xabcd\n")

	cfg, err := parseArgs([]string{
		"--rpc-url", "https://sepolia.base.org",
		"--sender-key-file", keyFile,
		"--proof-inputs-file", proofFile,
		"--deposit-seal-file", depositSeal,
		"--withdraw-seal-file", withdrawSeal,
		"--run-timeout", "12m",
	})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if cfg.RPCURL != "https://sepolia.base.org" {
		t.Fatalf("unexpected rpc url: %q", cfg.RPCURL)
	}
	if cfg.RunTimeout.String() != "12m0s" {
		t.Fatalf("unexpected timeout: %s", cfg.RunTimeout)
	}
	if len(cfg.DepositSeal) == 0 || len(cfg.WithdrawSeal) == 0 {
		t.Fatalf("expected non-empty seals")
	}
}

func TestParseArgs_RequiresProofInputsFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "sender.key")
	depositSeal := filepath.Join(tmp, "deposit.seal.hex")
	withdrawSeal := filepath.Join(tmp, "withdraw.seal.hex")

	writeFile(t, keyFile, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n")
	writeFile(t, depositSeal, "0x1234\n")
	writeFile(t, withdrawSeal, "0xabcd\n")

	_, err := parseArgs([]string{
		"--rpc-url", "https://sepolia.base.org",
		"--sender-key-file", keyFile,
		"--deposit-seal-file", depositSeal,
		"--withdraw-seal-file", withdrawSeal,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "--proof-inputs-file") {
		t.Fatalf("expected proof-inputs-file error, got: %v", err)
	}
}

func TestParseArgs_RejectsInvalidSealHex(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	keyFile := filepath.Join(tmp, "sender.key")
	proofFile := filepath.Join(tmp, "bridge-proof-inputs.json")
	depositSeal := filepath.Join(tmp, "deposit.seal.hex")
	withdrawSeal := filepath.Join(tmp, "withdraw.seal.hex")

	writeFile(t, keyFile, "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n")
	writeValidProofInputs(t, proofFile)
	writeFile(t, depositSeal, "not-hex\n")
	writeFile(t, withdrawSeal, "0xabcd\n")

	_, err := parseArgs([]string{
		"--rpc-url", "https://sepolia.base.org",
		"--sender-key-file", keyFile,
		"--proof-inputs-file", proofFile,
		"--deposit-seal-file", depositSeal,
		"--withdraw-seal-file", withdrawSeal,
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "deposit seal") {
		t.Fatalf("expected deposit seal error, got: %v", err)
	}
}

func TestLoadProofBundle_RejectsVersion(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	proofFile := filepath.Join(tmp, "bridge-proof-inputs.json")
	writeValidProofInputs(t, proofFile)

	raw, err := os.ReadFile(proofFile)
	if err != nil {
		t.Fatalf("read proof file: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal proof file: %v", err)
	}
	v["version"] = "bad.version"
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal proof file: %v", err)
	}
	if err := os.WriteFile(proofFile, out, 0o600); err != nil {
		t.Fatalf("write proof file: %v", err)
	}

	_, err = loadProofBundle(proofFile)
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported proof inputs version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadProofBundle_Valid(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	proofFile := filepath.Join(tmp, "bridge-proof-inputs.json")
	writeValidProofInputs(t, proofFile)

	got, err := loadProofBundle(proofFile)
	if err != nil {
		t.Fatalf("loadProofBundle: %v", err)
	}
	if got.ChainID != 84532 {
		t.Fatalf("unexpected chain id: %d", got.ChainID)
	}
	if got.BridgeContract.Hex() != "0x1111111111111111111111111111111111111111" {
		t.Fatalf("unexpected bridge contract: %s", got.BridgeContract.Hex())
	}
	if len(got.OperatorSigs) != 2 {
		t.Fatalf("unexpected operator sig count: %d", len(got.OperatorSigs))
	}
	if len(got.DepositJournal) == 0 || len(got.WithdrawJournal) == 0 {
		t.Fatalf("expected non-empty journals")
	}
}
