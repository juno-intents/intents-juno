package checkpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"strings"

	aws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type signerKeyProvisionClient interface {
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	EnableKey(ctx context.Context, params *kms.EnableKeyInput, optFns ...func(*kms.Options)) (*kms.EnableKeyOutput, error)
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	CreateKey(ctx context.Context, params *kms.CreateKeyInput, optFns ...func(*kms.Options)) (*kms.CreateKeyOutput, error)
	GetParametersForImport(ctx context.Context, params *kms.GetParametersForImportInput, optFns ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error)
	ImportKeyMaterial(ctx context.Context, params *kms.ImportKeyMaterialInput, optFns ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error)
	CreateAlias(ctx context.Context, params *kms.CreateAliasInput, optFns ...func(*kms.Options)) (*kms.CreateAliasOutput, error)
	UpdateAlias(ctx context.Context, params *kms.UpdateAliasInput, optFns ...func(*kms.Options)) (*kms.UpdateAliasOutput, error)
}

type SignerKeyProvisionConfig struct {
	KeyID           string
	AliasName       string
	OperatorID      string
	OperatorAddress common.Address
	PrivateKey      *ecdsa.PrivateKey
	Description     string
	Tags            map[string]string
}

type SignerKeyProvisionResult struct {
	KeyID           string
	KeyARN          string
	AliasName       string
	OperatorAddress common.Address
	Reused          bool
}

type SignerKeyProvisioner struct {
	client signerKeyProvisionClient
	rand   io.Reader
}

type kmsPKCS8PrivateKeyInfo struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type kmsSEC1PrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func NewSignerKeyProvisioner(client signerKeyProvisionClient) *SignerKeyProvisioner {
	return &SignerKeyProvisioner{
		client: client,
		rand:   rand.Reader,
	}
}

func (p *SignerKeyProvisioner) EnsureKMSKey(ctx context.Context, cfg SignerKeyProvisionConfig) (SignerKeyProvisionResult, error) {
	if p == nil || p.client == nil {
		return SignerKeyProvisionResult{}, errors.New("checkpoint: nil signer key provisioner")
	}
	if p.rand == nil {
		p.rand = rand.Reader
	}
	if cfg.OperatorAddress == (common.Address{}) {
		return SignerKeyProvisionResult{}, errors.New("checkpoint: operator address required")
	}
	cfg.KeyID = strings.TrimSpace(cfg.KeyID)
	cfg.AliasName = strings.TrimSpace(cfg.AliasName)
	cfg.OperatorID = strings.TrimSpace(cfg.OperatorID)
	cfg.Description = strings.TrimSpace(cfg.Description)

	if cfg.KeyID != "" {
		return p.ensureExistingKey(ctx, cfg.KeyID, cfg.OperatorAddress)
	}
	if cfg.AliasName == "" {
		return SignerKeyProvisionResult{}, errors.New("checkpoint: alias name required when key id is not provided")
	}
	if cfg.PrivateKey == nil {
		return SignerKeyProvisionResult{}, errors.New("checkpoint: private key required when key id is not provided")
	}
	if err := validateProvisionPrivateKey(cfg.PrivateKey, cfg.OperatorAddress); err != nil {
		return SignerKeyProvisionResult{}, err
	}

	meta, err := p.describeKey(ctx, cfg.AliasName)
	switch {
	case err == nil:
		result, validateErr := p.validateKeyMetadata(ctx, meta, cfg.OperatorAddress)
		if validateErr == nil {
			result.AliasName = cfg.AliasName
			return result, nil
		}
	case isKMSNotFound(err):
		meta = nil
	default:
		return SignerKeyProvisionResult{}, err
	}

	created, err := p.createAndImportKey(ctx, cfg)
	if err != nil {
		return SignerKeyProvisionResult{}, err
	}
	if meta == nil {
		if _, err := p.client.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(cfg.AliasName),
			TargetKeyId: aws.String(created.KeyARN),
		}); err != nil {
			if !isKMSAlreadyExists(err) {
				return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: create kms alias %s: %w", cfg.AliasName, err)
			}
			meta = &kmstypes.KeyMetadata{}
		}
	}
	if meta != nil {
		if _, err := p.client.UpdateAlias(ctx, &kms.UpdateAliasInput{
			AliasName:   aws.String(cfg.AliasName),
			TargetKeyId: aws.String(created.KeyARN),
		}); err != nil {
			return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: update kms alias %s: %w", cfg.AliasName, err)
		}
	}

	created.AliasName = cfg.AliasName
	return created, nil
}

func (p *SignerKeyProvisioner) ensureExistingKey(ctx context.Context, keyID string, operatorAddress common.Address) (SignerKeyProvisionResult, error) {
	meta, err := p.describeKey(ctx, keyID)
	if err != nil {
		return SignerKeyProvisionResult{}, err
	}
	return p.validateKeyMetadata(ctx, meta, operatorAddress)
}

func (p *SignerKeyProvisioner) describeKey(ctx context.Context, keyID string) (*kmstypes.KeyMetadata, error) {
	out, err := p.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, fmt.Errorf("checkpoint: describe kms key %s: %w", keyID, err)
	}
	if out == nil || out.KeyMetadata == nil {
		return nil, fmt.Errorf("checkpoint: describe kms key %s returned empty metadata", keyID)
	}
	return out.KeyMetadata, nil
}

func (p *SignerKeyProvisioner) validateKeyMetadata(ctx context.Context, meta *kmstypes.KeyMetadata, operatorAddress common.Address) (SignerKeyProvisionResult, error) {
	if meta == nil {
		return SignerKeyProvisionResult{}, errors.New("checkpoint: nil kms key metadata")
	}
	if meta.KeySpec != kmstypes.KeySpecEccSecgP256k1 {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: unsupported kms key spec %q", meta.KeySpec)
	}
	if meta.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: unsupported kms key usage %q", meta.KeyUsage)
	}
	if meta.Origin != kmstypes.OriginTypeExternal {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: kms key must use imported external material, got %q", meta.Origin)
	}
	switch meta.KeyState {
	case kmstypes.KeyStateEnabled:
	case kmstypes.KeyStateDisabled:
		if _, err := p.client.EnableKey(ctx, &kms.EnableKeyInput{KeyId: meta.KeyId}); err != nil {
			return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: enable kms key %s: %w", aws.ToString(meta.Arn), err)
		}
	default:
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: kms key %s is not usable in state %q", aws.ToString(meta.Arn), meta.KeyState)
	}

	pubOut, err := p.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: meta.Arn})
	if err != nil {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: get kms public key %s: %w", aws.ToString(meta.Arn), err)
	}
	if pubOut == nil {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: get kms public key %s returned empty output", aws.ToString(meta.Arn))
	}
	addr, err := parseKMSPublicKeyAddress(pubOut.PublicKey)
	if err != nil {
		return SignerKeyProvisionResult{}, err
	}
	if addr != operatorAddress {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: operator address mismatch: expected %s got %s", operatorAddress, addr)
	}

	return SignerKeyProvisionResult{
		KeyID:           aws.ToString(meta.KeyId),
		KeyARN:          aws.ToString(meta.Arn),
		OperatorAddress: addr,
		Reused:          true,
	}, nil
}

func (p *SignerKeyProvisioner) createAndImportKey(ctx context.Context, cfg SignerKeyProvisionConfig) (SignerKeyProvisionResult, error) {
	createOut, err := p.client.CreateKey(ctx, &kms.CreateKeyInput{
		Description: aws.String(cfg.Description),
		KeySpec:     kmstypes.KeySpecEccSecgP256k1,
		KeyUsage:    kmstypes.KeyUsageTypeSignVerify,
		Origin:      kmstypes.OriginTypeExternal,
		Tags:        kmsProvisionTags(cfg),
	})
	if err != nil {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: create kms key: %w", err)
	}
	if createOut == nil || createOut.KeyMetadata == nil {
		return SignerKeyProvisionResult{}, errors.New("checkpoint: create kms key returned empty metadata")
	}
	meta := createOut.KeyMetadata

	importParams, err := p.client.GetParametersForImport(ctx, &kms.GetParametersForImportInput{
		KeyId:             meta.Arn,
		WrappingAlgorithm: kmstypes.AlgorithmSpecRsaesOaepSha256,
		WrappingKeySpec:   kmstypes.WrappingKeySpecRsa4096,
	})
	if err != nil {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: get import parameters for %s: %w", aws.ToString(meta.Arn), err)
	}
	if importParams == nil || len(importParams.PublicKey) == 0 || len(importParams.ImportToken) == 0 {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: import parameters for %s are incomplete", aws.ToString(meta.Arn))
	}

	wrappingKey, err := parseKMSWrappingPublicKey(importParams.PublicKey)
	if err != nil {
		return SignerKeyProvisionResult{}, err
	}
	privateKeyDER, err := MarshalSecp256k1PKCS8PrivateKey(cfg.PrivateKey)
	if err != nil {
		return SignerKeyProvisionResult{}, err
	}
	encryptedKeyMaterial, err := rsa.EncryptOAEP(sha256.New(), p.rand, wrappingKey, privateKeyDER, nil)
	if err != nil {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: wrap imported key material: %w", err)
	}
	if _, err := p.client.ImportKeyMaterial(ctx, &kms.ImportKeyMaterialInput{
		KeyId:                meta.Arn,
		EncryptedKeyMaterial: encryptedKeyMaterial,
		ImportToken:          importParams.ImportToken,
		ExpirationModel:      kmstypes.ExpirationModelTypeKeyMaterialDoesNotExpire,
	}); err != nil {
		return SignerKeyProvisionResult{}, fmt.Errorf("checkpoint: import key material for %s: %w", aws.ToString(meta.Arn), err)
	}

	importedMeta, err := p.describeKey(ctx, aws.ToString(meta.Arn))
	if err != nil {
		return SignerKeyProvisionResult{}, err
	}
	result, err := p.validateKeyMetadata(ctx, importedMeta, cfg.OperatorAddress)
	if err != nil {
		return SignerKeyProvisionResult{}, err
	}
	result.Reused = false
	return result, nil
}

func kmsProvisionTags(cfg SignerKeyProvisionConfig) []kmstypes.Tag {
	tags := map[string]string{
		"intents-juno:role": "checkpoint-signer",
	}
	if cfg.OperatorID != "" {
		tags["intents-juno:operator-id"] = cfg.OperatorID
	}
	for k, v := range cfg.Tags {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		tags[k] = v
	}
	out := make([]kmstypes.Tag, 0, len(tags))
	for k, v := range tags {
		out = append(out, kmstypes.Tag{
			TagKey:   aws.String(k),
			TagValue: aws.String(v),
		})
	}
	return out
}

func validateProvisionPrivateKey(key *ecdsa.PrivateKey, expected common.Address) error {
	if key == nil {
		return errors.New("checkpoint: private key required")
	}
	if key.Curve == nil || key.Curve.Params() == nil || key.Curve.Params().N == nil || key.Curve.Params().N.Cmp(crypto.S256().Params().N) != 0 {
		return errors.New("checkpoint: private key must use secp256k1")
	}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return errors.New("checkpoint: invalid private key public point")
	}
	if got := crypto.PubkeyToAddress(key.PublicKey); got != expected {
		return fmt.Errorf("checkpoint: operator address mismatch: expected %s got %s", expected, got)
	}
	return nil
}

func MarshalSecp256k1PKCS8PrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	if err := validateProvisionPrivateKey(key, crypto.PubkeyToAddress(key.PublicKey)); err != nil {
		return nil, err
	}

	curveOIDBytes, err := asn1.Marshal(secp256k1CurveOID())
	if err != nil {
		return nil, fmt.Errorf("checkpoint: marshal secp256k1 curve oid: %w", err)
	}
	privateScalar := crypto.FromECDSA(key)
	innerDER, err := asn1.Marshal(kmsSEC1PrivateKey{
		Version:       1,
		PrivateKey:    privateScalar,
		NamedCurveOID: secp256k1CurveOID(),
		PublicKey: asn1.BitString{
			Bytes:     crypto.FromECDSAPub(&key.PublicKey),
			BitLength: len(crypto.FromECDSAPub(&key.PublicKey)) * 8,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("checkpoint: marshal secp256k1 private key: %w", err)
	}

	outerDER, err := asn1.Marshal(kmsPKCS8PrivateKeyInfo{
		Version: 0,
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: secp256k1PublicKeyOID(),
			Parameters: asn1.RawValue{
				FullBytes: curveOIDBytes,
			},
		},
		PrivateKey: innerDER,
	})
	if err != nil {
		return nil, fmt.Errorf("checkpoint: marshal pkcs8 private key: %w", err)
	}
	return outerDER, nil
}

func parseKMSWrappingPublicKey(der []byte) (*rsa.PublicKey, error) {
	if len(der) == 0 {
		return nil, errors.New("checkpoint: empty kms wrapping public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: parse kms wrapping public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("checkpoint: kms wrapping public key is not RSA")
	}
	return pub, nil
}

func isKMSNotFound(err error) bool {
	var notFound *kmstypes.NotFoundException
	return errors.As(err, &notFound)
}

func isKMSAlreadyExists(err error) bool {
	var alreadyExists *kmstypes.AlreadyExistsException
	return errors.As(err, &alreadyExists)
}
