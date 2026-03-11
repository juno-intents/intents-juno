package main

import (
	"context"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestLoadDigestSigner_LocalEnv(t *testing.T) {
	t.Setenv("TEST_CHECKPOINT_SIGNER_PRIVATE_KEY", "4f3edf983ac636a65a842ce7c78d9aa706d3b113b37c2b1b4c1c5f5d8f5e2d3a")

	signer, operator, err := loadDigestSigner(context.Background(), "local-env", "", "TEST_CHECKPOINT_SIGNER_PRIVATE_KEY")
	if err != nil {
		t.Fatalf("loadDigestSigner: %v", err)
	}
	if signer == nil {
		t.Fatalf("expected signer")
	}
	want := common.HexToAddress("0xeD99D54580044F325C6e9E12236fa90A165257ff")
	if operator != want {
		t.Fatalf("operator mismatch: got %s want %s", operator, want)
	}
}

func TestLoadDigestSigner_AWSKMSRequiresOperatorAddress(t *testing.T) {
	_, _, err := loadDigestSigner(context.Background(), "aws-kms", "arn:aws:kms:us-east-1:123:key/test", "IGNORED")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "OPERATOR_ADDRESS") {
		t.Fatalf("expected OPERATOR_ADDRESS error, got %v", err)
	}
}

func TestLoadDigestSigner_RejectsUnknownDriver(t *testing.T) {
	_, _, err := loadDigestSigner(context.Background(), "bad-driver", "", "IGNORED")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported signer driver") {
		t.Fatalf("unexpected error: %v", err)
	}
}
