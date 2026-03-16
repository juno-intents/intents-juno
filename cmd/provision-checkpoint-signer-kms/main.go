package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type signerProvisioner interface {
	EnsureKMSKey(context.Context, checkpoint.SignerKeyProvisionConfig) (checkpoint.SignerKeyProvisionResult, error)
}

type provisionerFactory func(ctx context.Context, profile, region string) (signerProvisioner, error)
type accountLookup func(ctx context.Context, profile, region string) (string, error)

type outputJSON struct {
	KeyID           string `json:"keyId"`
	KeyARN          string `json:"keyArn"`
	AliasName       string `json:"aliasName,omitempty"`
	OperatorAddress string `json:"operatorAddress"`
	Reused          bool   `json:"reused"`
}

func main() {
	if err := runMain(os.Args[1:], os.Stdout, newAWSProvisioner, lookupAWSAccount); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runMain(args []string, stdout io.Writer, newProvisioner provisionerFactory, lookupAccount accountLookup) error {
	fs := flag.NewFlagSet("provision-checkpoint-signer-kms", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	awsProfile := fs.String("aws-profile", "", "AWS shared config profile")
	awsRegion := fs.String("aws-region", "", "AWS region")
	accountID := fs.String("account-id", "", "Expected AWS account ID")
	keyID := fs.String("key-id", "", "Existing KMS key ID/ARN to validate and reuse")
	aliasName := fs.String("alias-name", "", "KMS alias name to create/update when provisioning a new key")
	operatorID := fs.String("operator-id", "", "Operator identifier")
	operatorAddress := fs.String("operator-address", "", "Expected operator Ethereum address")
	privateKeyHex := fs.String("private-key", "", "Operator private key hex (required when creating a new imported key)")
	privateKeyFile := fs.String("private-key-file", "", "File containing operator private key hex")
	description := fs.String("description", "", "KMS key description when provisioning a new key")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*operatorAddress) == "" || !common.IsHexAddress(strings.TrimSpace(*operatorAddress)) {
		return errors.New("--operator-address must be a valid hex address")
	}
	if strings.TrimSpace(*keyID) == "" {
		if strings.TrimSpace(*aliasName) == "" {
			return errors.New("--alias-name is required when --key-id is not provided")
		}
	}
	if strings.TrimSpace(*privateKeyHex) != "" && strings.TrimSpace(*privateKeyFile) != "" {
		return errors.New("use only one of --private-key or --private-key-file")
	}

	operatorAddr := common.HexToAddress(strings.TrimSpace(*operatorAddress))
	var privateKey *ecdsa.PrivateKey
	if strings.TrimSpace(*keyID) == "" {
		loadedKey, err := loadPrivateKey(strings.TrimSpace(*privateKeyHex), strings.TrimSpace(*privateKeyFile))
		if err != nil {
			return err
		}
		privateKey = loadedKey
	}

	if strings.TrimSpace(*accountID) != "" {
		actualAccount, err := lookupAccount(context.Background(), strings.TrimSpace(*awsProfile), strings.TrimSpace(*awsRegion))
		if err != nil {
			return fmt.Errorf("lookup aws account: %w", err)
		}
		if actualAccount != strings.TrimSpace(*accountID) {
			return fmt.Errorf("aws account mismatch: expected %s got %s", strings.TrimSpace(*accountID), actualAccount)
		}
	}

	provisioner, err := newProvisioner(context.Background(), strings.TrimSpace(*awsProfile), strings.TrimSpace(*awsRegion))
	if err != nil {
		return err
	}
	result, err := provisioner.EnsureKMSKey(context.Background(), checkpoint.SignerKeyProvisionConfig{
		KeyID:           strings.TrimSpace(*keyID),
		AliasName:       strings.TrimSpace(*aliasName),
		OperatorID:      strings.TrimSpace(*operatorID),
		OperatorAddress: operatorAddr,
		PrivateKey:      privateKey,
		Description:     strings.TrimSpace(*description),
	})
	if err != nil {
		return err
	}

	return json.NewEncoder(stdout).Encode(outputJSON{
		KeyID:           result.KeyID,
		KeyARN:          result.KeyARN,
		AliasName:       result.AliasName,
		OperatorAddress: result.OperatorAddress.Hex(),
		Reused:          result.Reused,
	})
}

func loadPrivateKey(inline, filePath string) (*ecdsa.PrivateKey, error) {
	var raw string
	switch {
	case inline != "":
		raw = inline
	case filePath != "":
		bytes, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read private key file: %w", err)
		}
		raw = string(bytes)
	default:
		return nil, errors.New("--private-key or --private-key-file is required when --key-id is not provided")
	}
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "0x"))
	key, err := crypto.HexToECDSA(raw)
	if err != nil {
		return nil, fmt.Errorf("parse secp256k1 private key: %w", err)
	}
	return key, nil
}

func newAWSProvisioner(ctx context.Context, profile, region string) (signerProvisioner, error) {
	cfg, err := loadAWSConfig(ctx, profile, region)
	if err != nil {
		return nil, err
	}
	return checkpoint.NewSignerKeyProvisioner(kms.NewFromConfig(cfg)), nil
}

func lookupAWSAccount(ctx context.Context, profile, region string) (string, error) {
	cfg, err := loadAWSConfig(ctx, profile, region)
	if err != nil {
		return "", err
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(aws.ToString(out.Account)), nil
}

func loadAWSConfig(ctx context.Context, profile, region string) (aws.Config, error) {
	opts := make([]func(*awsconfig.LoadOptions) error, 0, 2)
	if profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load aws config: %w", err)
	}
	return cfg, nil
}
