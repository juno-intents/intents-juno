package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type fakeProvisioner struct {
	result checkpoint.SignerKeyProvisionResult
	err    error
}

func (f fakeProvisioner) EnsureKMSKey(_ context.Context, _ checkpoint.SignerKeyProvisionConfig) (checkpoint.SignerKeyProvisionResult, error) {
	return f.result, f.err
}

func TestRunMainRequiresAliasWhenProvisioningNewKey(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	err := runMain([]string{
		"--operator-address", "0x1111111111111111111111111111111111111111",
		"--private-key", "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, &stdout, func(context.Context, string, string) (signerProvisioner, error) {
		t.Fatalf("provisioner factory should not be called")
		return nil, nil
	}, func(context.Context, string, string) (string, error) {
		t.Fatalf("account lookup should not be called")
		return "", nil
	})
	if err == nil || !strings.Contains(err.Error(), "--alias-name is required") {
		t.Fatalf("expected missing alias error, got %v", err)
	}
}

func TestRunMainPrintsProvisionResultJSON(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	err := runMain([]string{
		"--operator-address", "0x1111111111111111111111111111111111111111",
		"--key-id", "arn:aws:kms:us-east-1:021490342184:key/existing",
	}, &stdout, func(context.Context, string, string) (signerProvisioner, error) {
		return fakeProvisioner{
			result: checkpoint.SignerKeyProvisionResult{
				KeyID:           "existing",
				KeyARN:          "arn:aws:kms:us-east-1:021490342184:key/existing",
				OperatorAddress: common.HexToAddress("0x1111111111111111111111111111111111111111"),
				Reused:          true,
			},
		}, nil
	}, func(context.Context, string, string) (string, error) {
		return "", nil
	})
	if err != nil {
		t.Fatalf("runMain: %v", err)
	}
	if !strings.Contains(stdout.String(), "\"keyArn\":\"arn:aws:kms:us-east-1:021490342184:key/existing\"") {
		t.Fatalf("stdout missing key arn json: %s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "\"reused\":true") {
		t.Fatalf("stdout missing reused json: %s", stdout.String())
	}
}
