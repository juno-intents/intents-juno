package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMain_DepositGolden(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := runMain([]string{
		"deposit",
		"--base-chain-id", "8453",
		"--bridge-address", "0x1234567890abcdef1234567890abcdef12345678",
		"--recipient", "0x90f8bf6a479f320ead074411a4b0e7944ea8c9c1",
		"--nonce", "72623859790382856", // 0x0102030405060708
		"--flags", "2864434397", // 0xAABBCCDD
	}, &out)
	if err != nil {
		t.Fatalf("runMain deposit: %v", err)
	}

	goldenPath := filepath.Join("..", "..", "internal", "memo", "testdata", "deposit_v1_valid.hex")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	got := strings.TrimSpace(out.String())
	want := "0x" + strings.TrimSpace(string(golden))
	if got != want {
		t.Fatalf("deposit memo mismatch\nwant=%s\n got=%s", want, got)
	}
}

func TestRunMain_WithdrawGolden(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := runMain([]string{
		"withdraw",
		"--base-chain-id", "8453",
		"--bridge-address", "0x1234567890abcdef1234567890abcdef12345678",
		"--withdrawal-id", "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"--batch-id", "0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		"--flags", "287454020", // 0x11223344
	}, &out)
	if err != nil {
		t.Fatalf("runMain withdraw: %v", err)
	}

	goldenPath := filepath.Join("..", "..", "internal", "memo", "testdata", "withdrawal_v1_valid.hex")
	golden, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	got := strings.TrimSpace(out.String())
	want := "0x" + strings.TrimSpace(string(golden))
	if got != want {
		t.Fatalf("withdraw memo mismatch\nwant=%s\n got=%s", want, got)
	}
}

func TestRunMain_RejectsInvalidHexLength(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := runMain([]string{
		"withdraw",
		"--base-chain-id", "8453",
		"--bridge-address", "0x1234567890abcdef1234567890abcdef12345678",
		"--withdrawal-id", "0x1234",
		"--batch-id", "0x202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
	}, &out)
	if err == nil {
		t.Fatalf("expected invalid withdrawal-id length error")
	}
}
