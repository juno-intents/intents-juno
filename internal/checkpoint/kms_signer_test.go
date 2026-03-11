package checkpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	aws "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type fakeKMSClient struct {
	getPublicKeyFn func(context.Context, *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error)
	signFn         func(context.Context, *kms.SignInput) (*kms.SignOutput, error)
}

func (f *fakeKMSClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if f.getPublicKeyFn == nil {
		return nil, errors.New("unexpected GetPublicKey call")
	}
	return f.getPublicKeyFn(ctx, params)
}

func (f *fakeKMSClient) Sign(ctx context.Context, params *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if f.signFn == nil {
		return nil, errors.New("unexpected Sign call")
	}
	return f.signFn(ctx, params)
}

type ecdsaDER struct {
	R *big.Int
	S *big.Int
}

type subjectPublicKeyInfo struct {
	Algorithm        pkAlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type pkAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

func TestKMSDigestSigner_SignDigest(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyID := "arn:aws:kms:us-east-1:021490342184:key/test"
	operator := crypto.PubkeyToAddress(key.PublicKey)
	publicKeyDER := mustMarshalKMSPublicKey(t, &key.PublicKey)

	client := &fakeKMSClient{
		getPublicKeyFn: func(_ context.Context, params *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			if got := aws.ToString(params.KeyId); got != keyID {
				t.Fatalf("GetPublicKey key id: got %q want %q", got, keyID)
			}
			return &kms.GetPublicKeyOutput{
				KeyId:             aws.String(keyID),
				KeySpec:           types.KeySpecEccSecgP256k1,
				KeyUsage:          types.KeyUsageTypeSignVerify,
				PublicKey:         publicKeyDER,
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil
		},
		signFn: func(_ context.Context, params *kms.SignInput) (*kms.SignOutput, error) {
			if got := aws.ToString(params.KeyId); got != keyID {
				t.Fatalf("Sign key id: got %q want %q", got, keyID)
			}
			if got := params.MessageType; got != types.MessageTypeDigest {
				t.Fatalf("Sign message type: got %q want %q", got, types.MessageTypeDigest)
			}
			if got := params.SigningAlgorithm; got != types.SigningAlgorithmSpecEcdsaSha256 {
				t.Fatalf("Sign algorithm: got %q want %q", got, types.SigningAlgorithmSpecEcdsaSha256)
			}
			digest := common.BytesToHash(params.Message)
			der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
			if err != nil {
				t.Fatalf("SignASN1: %v", err)
			}
			return &kms.SignOutput{
				KeyId:     aws.String(keyID),
				Signature: der,
			}, nil
		},
	}

	signer, err := NewKMSDigestSigner(context.Background(), client, KMSDigestSignerConfig{
		KeyID:           keyID,
		ExpectedAddress: operator,
	})
	if err != nil {
		t.Fatalf("NewKMSDigestSigner: %v", err)
	}
	if got := signer.Address(); got != operator {
		t.Fatalf("Address: got %s want %s", got, operator)
	}

	cp := Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := Digest(cp)

	sig, err := signer.SignDigest(context.Background(), digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length: got %d want 65", len(sig))
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatalf("signature v: got %d want 27/28", sig[64])
	}

	got, err := RecoverSigner(digest, sig)
	if err != nil {
		t.Fatalf("RecoverSigner: %v", err)
	}
	if got != operator {
		t.Fatalf("recovered address mismatch: got %s want %s", got, operator)
	}
}

func TestKMSDigestSigner_RejectsAddressMismatch(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyID := "arn:aws:kms:us-east-1:021490342184:key/test"

	client := &fakeKMSClient{
		getPublicKeyFn: func(_ context.Context, _ *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				KeyId:             aws.String(keyID),
				KeySpec:           types.KeySpecEccSecgP256k1,
				KeyUsage:          types.KeyUsageTypeSignVerify,
				PublicKey:         mustMarshalKMSPublicKey(t, &key.PublicKey),
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil
		},
	}

	_, err = NewKMSDigestSigner(context.Background(), client, KMSDigestSignerConfig{
		KeyID:           keyID,
		ExpectedAddress: common.HexToAddress("0x0000000000000000000000000000000000000001"),
	})
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestKMSDigestSigner_NormalizesHighS(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	keyID := "arn:aws:kms:us-east-1:021490342184:key/test"
	operator := crypto.PubkeyToAddress(key.PublicKey)
	publicKeyDER := mustMarshalKMSPublicKey(t, &key.PublicKey)

	client := &fakeKMSClient{
		getPublicKeyFn: func(_ context.Context, _ *kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
			return &kms.GetPublicKeyOutput{
				KeyId:             aws.String(keyID),
				KeySpec:           types.KeySpecEccSecgP256k1,
				KeyUsage:          types.KeyUsageTypeSignVerify,
				PublicKey:         publicKeyDER,
				SigningAlgorithms: []types.SigningAlgorithmSpec{types.SigningAlgorithmSpecEcdsaSha256},
			}, nil
		},
		signFn: func(_ context.Context, params *kms.SignInput) (*kms.SignOutput, error) {
			digest := common.BytesToHash(params.Message)
			r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
			if err != nil {
				t.Fatalf("ecdsa.Sign: %v", err)
			}
			highS := new(big.Int).Set(s)
			if highS.Cmp(secp256k1HalfOrder()) <= 0 {
				highS.Sub(secp256k1Order(), highS)
			}
			der, err := asn1.Marshal(ecdsaDER{R: r, S: highS})
			if err != nil {
				t.Fatalf("asn1.Marshal: %v", err)
			}
			return &kms.SignOutput{KeyId: aws.String(keyID), Signature: der}, nil
		},
	}

	signer, err := NewKMSDigestSigner(context.Background(), client, KMSDigestSignerConfig{
		KeyID:           keyID,
		ExpectedAddress: operator,
	})
	if err != nil {
		t.Fatalf("NewKMSDigestSigner: %v", err)
	}

	digest := common.HexToHash("0x688fcd90cce56cb44480c50331d4d35fe77bc15b43cffe150042570c49692e4a")
	sig, err := signer.SignDigest(context.Background(), digest)
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}

	var s big.Int
	s.SetBytes(sig[32:64])
	if s.Cmp(secp256k1HalfOrder()) > 0 {
		t.Fatalf("expected low-s signature, got s=%s", &s)
	}
}

func mustMarshalKMSPublicKey(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkAlgorithmIdentifier{
			Algorithm:  secp256k1PublicKeyOID(),
			Parameters: secp256k1CurveOID(),
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     crypto.FromECDSAPub(pub),
			BitLength: len(crypto.FromECDSAPub(pub)) * 8,
		},
	})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	return der
}
