package checkpoint

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"testing"
	"time"

	aws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type fakeSignerKeyProvisionClient struct {
	describeKeyFn            func(context.Context, *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error)
	enableKeyFn              func(context.Context, *kms.EnableKeyInput) (*kms.EnableKeyOutput, error)
	getPublicKeyFn           func(context.Context, *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	createKeyFn              func(context.Context, *kms.CreateKeyInput) (*kms.CreateKeyOutput, error)
	getParametersForImportFn func(context.Context, *kms.GetParametersForImportInput) (*kms.GetParametersForImportOutput, error)
	importKeyMaterialFn      func(context.Context, *kms.ImportKeyMaterialInput) (*kms.ImportKeyMaterialOutput, error)
	createAliasFn            func(context.Context, *kms.CreateAliasInput) (*kms.CreateAliasOutput, error)
	updateAliasFn            func(context.Context, *kms.UpdateAliasInput) (*kms.UpdateAliasOutput, error)
}

func (f *fakeSignerKeyProvisionClient) DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return f.describeKeyFn(ctx, params)
}

func (f *fakeSignerKeyProvisionClient) EnableKey(ctx context.Context, params *kms.EnableKeyInput, _ ...func(*kms.Options)) (*kms.EnableKeyOutput, error) {
	return f.enableKeyFn(ctx, params)
}

func (f *fakeSignerKeyProvisionClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	return f.getPublicKeyFn(ctx, params)
}

func (f *fakeSignerKeyProvisionClient) CreateKey(ctx context.Context, params *kms.CreateKeyInput, _ ...func(*kms.Options)) (*kms.CreateKeyOutput, error) {
	return f.createKeyFn(ctx, params)
}

func (f *fakeSignerKeyProvisionClient) GetParametersForImport(ctx context.Context, params *kms.GetParametersForImportInput, _ ...func(*kms.Options)) (*kms.GetParametersForImportOutput, error) {
	return f.getParametersForImportFn(ctx, params)
}

func (f *fakeSignerKeyProvisionClient) ImportKeyMaterial(ctx context.Context, params *kms.ImportKeyMaterialInput, _ ...func(*kms.Options)) (*kms.ImportKeyMaterialOutput, error) {
	return f.importKeyMaterialFn(ctx, params)
}

func (f *fakeSignerKeyProvisionClient) CreateAlias(ctx context.Context, params *kms.CreateAliasInput, _ ...func(*kms.Options)) (*kms.CreateAliasOutput, error) {
	return f.createAliasFn(ctx, params)
}

func (f *fakeSignerKeyProvisionClient) UpdateAlias(ctx context.Context, params *kms.UpdateAliasInput, _ ...func(*kms.Options)) (*kms.UpdateAliasOutput, error) {
	return f.updateAliasFn(ctx, params)
}

type pkcs8PrivateKeyInfo struct {
	Version    int
	Algorithm  pkcs8AlgorithmIdentifier
	PrivateKey []byte
}

type pkcs8AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type pkcs8ECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func TestMarshalSecp256k1PKCS8PrivateKey_EncodesNamedCurve(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	der, err := MarshalSecp256k1PKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalSecp256k1PKCS8PrivateKey: %v", err)
	}

	var outer pkcs8PrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		t.Fatalf("asn1.Unmarshal outer: %v", err)
	}
	if outer.Version != 0 {
		t.Fatalf("outer version: got %d want 0", outer.Version)
	}
	if !outer.Algorithm.Algorithm.Equal(secp256k1PublicKeyOID()) {
		t.Fatalf("algorithm oid mismatch: got %v want %v", outer.Algorithm.Algorithm, secp256k1PublicKeyOID())
	}

	var namedCurveOID asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(outer.Algorithm.Parameters.FullBytes, &namedCurveOID); err != nil {
		t.Fatalf("asn1.Unmarshal named curve: %v", err)
	}
	if !namedCurveOID.Equal(secp256k1CurveOID()) {
		t.Fatalf("curve oid mismatch: got %v want %v", namedCurveOID, secp256k1CurveOID())
	}

	var inner pkcs8ECPrivateKey
	if _, err := asn1.Unmarshal(outer.PrivateKey, &inner); err != nil {
		t.Fatalf("asn1.Unmarshal inner: %v", err)
	}
	if inner.Version != 1 {
		t.Fatalf("inner version: got %d want 1", inner.Version)
	}
	if got, want := hex.EncodeToString(inner.PrivateKey), hex.EncodeToString(crypto.FromECDSA(key)); got != want {
		t.Fatalf("private key mismatch: got %s want %s", got, want)
	}
	if !inner.NamedCurveOID.Equal(secp256k1CurveOID()) {
		t.Fatalf("inner curve oid mismatch: got %v want %v", inner.NamedCurveOID, secp256k1CurveOID())
	}
}

func TestSignerKeyProvisioner_ReuseExplicitKeyWhenValid(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	operator := crypto.PubkeyToAddress(key.PublicKey)
	keyID := "arn:aws:kms:us-east-1:021490342184:key/existing"

	client := &fakeSignerKeyProvisionClient{
		describeKeyFn: func(_ context.Context, params *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
			if got := aws.ToString(params.KeyId); got != keyID {
				t.Fatalf("DescribeKey key id: got %q want %q", got, keyID)
			}
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					Arn:      aws.String(keyID),
					KeyId:    aws.String("existing"),
					KeySpec:  kmstypes.KeySpecEccSecgP256k1,
					KeyUsage: kmstypes.KeyUsageTypeSignVerify,
					Origin:   kmstypes.OriginTypeExternal,
					KeyState: kmstypes.KeyStateEnabled,
				},
			}, nil
		},
		enableKeyFn: func(_ context.Context, _ *kms.EnableKeyInput) (*kms.EnableKeyOutput, error) {
			t.Fatalf("EnableKey should not be called for enabled keys")
			return nil, nil
		},
		getPublicKeyFn: func(_ context.Context, params *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			if got := aws.ToString(params.KeyId); got != keyID {
				t.Fatalf("GetPublicKey key id: got %q want %q", got, keyID)
			}
			return &kms.GetPublicKeyOutput{
				KeyId:             aws.String(keyID),
				KeySpec:           kmstypes.KeySpecEccSecgP256k1,
				KeyUsage:          kmstypes.KeyUsageTypeSignVerify,
				PublicKey:         mustMarshalKMSPublicKey(t, &key.PublicKey),
				SigningAlgorithms: []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha256},
			}, nil
		},
		createKeyFn: func(_ context.Context, _ *kms.CreateKeyInput) (*kms.CreateKeyOutput, error) {
			t.Fatalf("CreateKey should not be called when explicit key is valid")
			return nil, nil
		},
		getParametersForImportFn: func(_ context.Context, _ *kms.GetParametersForImportInput) (*kms.GetParametersForImportOutput, error) {
			t.Fatalf("GetParametersForImport should not be called when explicit key is valid")
			return nil, nil
		},
		importKeyMaterialFn: func(_ context.Context, _ *kms.ImportKeyMaterialInput) (*kms.ImportKeyMaterialOutput, error) {
			t.Fatalf("ImportKeyMaterial should not be called when explicit key is valid")
			return nil, nil
		},
		createAliasFn: func(_ context.Context, _ *kms.CreateAliasInput) (*kms.CreateAliasOutput, error) {
			t.Fatalf("CreateAlias should not be called when explicit key is valid")
			return nil, nil
		},
		updateAliasFn: func(_ context.Context, _ *kms.UpdateAliasInput) (*kms.UpdateAliasOutput, error) {
			t.Fatalf("UpdateAlias should not be called when explicit key is valid")
			return nil, nil
		},
	}

	provisioner := NewSignerKeyProvisioner(client)
	result, err := provisioner.EnsureKMSKey(context.Background(), SignerKeyProvisionConfig{
		KeyID:           keyID,
		OperatorID:      operator.Hex(),
		OperatorAddress: operator,
	})
	if err != nil {
		t.Fatalf("EnsureKMSKey: %v", err)
	}
	if !result.Reused {
		t.Fatalf("expected existing key to be reused")
	}
	if result.KeyARN != keyID {
		t.Fatalf("key arn mismatch: got %s want %s", result.KeyARN, keyID)
	}
}

func TestSignerKeyProvisioner_RejectsExplicitKeyAddressMismatch(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyID := "arn:aws:kms:us-east-1:021490342184:key/existing"

	client := &fakeSignerKeyProvisionClient{
		describeKeyFn: func(_ context.Context, _ *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					Arn:      aws.String(keyID),
					KeyId:    aws.String("existing"),
					KeySpec:  kmstypes.KeySpecEccSecgP256k1,
					KeyUsage: kmstypes.KeyUsageTypeSignVerify,
					Origin:   kmstypes.OriginTypeExternal,
					KeyState: kmstypes.KeyStateEnabled,
				},
			}, nil
		},
		enableKeyFn: func(_ context.Context, _ *kms.EnableKeyInput) (*kms.EnableKeyOutput, error) {
			t.Fatalf("EnableKey should not be called")
			return nil, nil
		},
		getPublicKeyFn: func(_ context.Context, _ *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				KeyId:             aws.String(keyID),
				KeySpec:           kmstypes.KeySpecEccSecgP256k1,
				KeyUsage:          kmstypes.KeyUsageTypeSignVerify,
				PublicKey:         mustMarshalKMSPublicKey(t, &key.PublicKey),
				SigningAlgorithms: []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha256},
			}, nil
		},
	}

	provisioner := NewSignerKeyProvisioner(client)
	_, err = provisioner.EnsureKMSKey(context.Background(), SignerKeyProvisionConfig{
		KeyID:           keyID,
		OperatorID:      "0x1111111111111111111111111111111111111111",
		OperatorAddress: common.HexToAddress("0x1111111111111111111111111111111111111111"),
	})
	if err == nil {
		t.Fatalf("expected explicit key address mismatch to fail")
	}
}

func TestSignerKeyProvisioner_CreatesImportedKeyWhenAliasMissing(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	operator := crypto.PubkeyToAddress(key.PublicKey)
	aliasName := "alias/intents-juno-preview-op1-checkpoint-signer"
	keyARN := "arn:aws:kms:us-east-1:021490342184:key/new"

	wrappingKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	wrappingPublicKeyDER, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
	}

	var importedCiphertext []byte
	client := &fakeSignerKeyProvisionClient{
		describeKeyFn: func(_ context.Context, params *kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
			switch got := aws.ToString(params.KeyId); got {
			case aliasName:
				return nil, &kmstypes.NotFoundException{Message: aws.String("not found")}
			case keyARN:
				return &kms.DescribeKeyOutput{
					KeyMetadata: &kmstypes.KeyMetadata{
						Arn:      aws.String(keyARN),
						KeyId:    aws.String("new"),
						KeySpec:  kmstypes.KeySpecEccSecgP256k1,
						KeyUsage: kmstypes.KeyUsageTypeSignVerify,
						Origin:   kmstypes.OriginTypeExternal,
						KeyState: kmstypes.KeyStateEnabled,
					},
				}, nil
			default:
				t.Fatalf("DescribeKey key id: got %q want one of %q or %q", got, aliasName, keyARN)
			}
			return nil, nil
		},
		enableKeyFn: func(_ context.Context, _ *kms.EnableKeyInput) (*kms.EnableKeyOutput, error) {
			t.Fatalf("EnableKey should not be called for new keys")
			return nil, nil
		},
		getPublicKeyFn: func(_ context.Context, params *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			if got := aws.ToString(params.KeyId); got != keyARN {
				t.Fatalf("GetPublicKey key id: got %q want %q", got, keyARN)
			}
			return &kms.GetPublicKeyOutput{
				KeyId:             aws.String(keyARN),
				KeySpec:           kmstypes.KeySpecEccSecgP256k1,
				KeyUsage:          kmstypes.KeyUsageTypeSignVerify,
				PublicKey:         mustMarshalKMSPublicKey(t, &key.PublicKey),
				SigningAlgorithms: []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecEcdsaSha256},
			}, nil
		},
		createKeyFn: func(_ context.Context, params *kms.CreateKeyInput) (*kms.CreateKeyOutput, error) {
			if params.Origin != kmstypes.OriginTypeExternal {
				t.Fatalf("CreateKey origin: got %q want %q", params.Origin, kmstypes.OriginTypeExternal)
			}
			if params.KeySpec != kmstypes.KeySpecEccSecgP256k1 {
				t.Fatalf("CreateKey key spec: got %q want %q", params.KeySpec, kmstypes.KeySpecEccSecgP256k1)
			}
			if params.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
				t.Fatalf("CreateKey key usage: got %q want %q", params.KeyUsage, kmstypes.KeyUsageTypeSignVerify)
			}
			return &kms.CreateKeyOutput{
				KeyMetadata: &kmstypes.KeyMetadata{
					Arn:      aws.String(keyARN),
					KeyId:    aws.String("new"),
					KeySpec:  kmstypes.KeySpecEccSecgP256k1,
					KeyUsage: kmstypes.KeyUsageTypeSignVerify,
					Origin:   kmstypes.OriginTypeExternal,
					KeyState: kmstypes.KeyStatePendingImport,
				},
			}, nil
		},
		getParametersForImportFn: func(_ context.Context, params *kms.GetParametersForImportInput) (*kms.GetParametersForImportOutput, error) {
			if got := aws.ToString(params.KeyId); got != keyARN {
				t.Fatalf("GetParametersForImport key id: got %q want %q", got, keyARN)
			}
			if params.WrappingAlgorithm != kmstypes.AlgorithmSpecRsaesOaepSha256 {
				t.Fatalf("wrapping algorithm: got %q want %q", params.WrappingAlgorithm, kmstypes.AlgorithmSpecRsaesOaepSha256)
			}
			if params.WrappingKeySpec != kmstypes.WrappingKeySpecRsa4096 {
				t.Fatalf("wrapping key spec: got %q want %q", params.WrappingKeySpec, kmstypes.WrappingKeySpecRsa4096)
			}
			return &kms.GetParametersForImportOutput{
				ImportToken:       []byte("import-token"),
				PublicKey:         wrappingPublicKeyDER,
				ParametersValidTo: aws.Time(time.Now().Add(time.Hour)),
			}, nil
		},
		importKeyMaterialFn: func(_ context.Context, params *kms.ImportKeyMaterialInput) (*kms.ImportKeyMaterialOutput, error) {
			if got := aws.ToString(params.KeyId); got != keyARN {
				t.Fatalf("ImportKeyMaterial key id: got %q want %q", got, keyARN)
			}
			importedCiphertext = append([]byte(nil), params.EncryptedKeyMaterial...)
			if params.ExpirationModel != kmstypes.ExpirationModelTypeKeyMaterialDoesNotExpire {
				t.Fatalf("expiration model: got %q want %q", params.ExpirationModel, kmstypes.ExpirationModelTypeKeyMaterialDoesNotExpire)
			}
			return &kms.ImportKeyMaterialOutput{}, nil
		},
		createAliasFn: func(_ context.Context, params *kms.CreateAliasInput) (*kms.CreateAliasOutput, error) {
			if got := aws.ToString(params.AliasName); got != aliasName {
				t.Fatalf("CreateAlias alias: got %q want %q", got, aliasName)
			}
			if got := aws.ToString(params.TargetKeyId); got != keyARN {
				t.Fatalf("CreateAlias target: got %q want %q", got, keyARN)
			}
			return &kms.CreateAliasOutput{}, nil
		},
		updateAliasFn: func(_ context.Context, _ *kms.UpdateAliasInput) (*kms.UpdateAliasOutput, error) {
			t.Fatalf("UpdateAlias should not be called when alias is missing")
			return nil, nil
		},
	}

	provisioner := NewSignerKeyProvisioner(client)
	result, err := provisioner.EnsureKMSKey(context.Background(), SignerKeyProvisionConfig{
		AliasName:       aliasName,
		OperatorID:      operator.Hex(),
		OperatorAddress: operator,
		PrivateKey:      key,
		Description:     "preview checkpoint signer",
	})
	if err != nil {
		t.Fatalf("EnsureKMSKey: %v", err)
	}
	if result.Reused {
		t.Fatalf("expected new key to be created")
	}
	if result.KeyARN != keyARN {
		t.Fatalf("key arn mismatch: got %s want %s", result.KeyARN, keyARN)
	}
	if len(importedCiphertext) == 0 {
		t.Fatalf("expected encrypted key material to be uploaded")
	}
}
