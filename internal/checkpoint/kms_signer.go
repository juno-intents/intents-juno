package checkpoint

import (
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	errInvalidKMSPublicKey = errors.New("checkpoint: invalid kms public key")

	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidSecp256k1   = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

	secp256k1OrderValue     = new(big.Int).Set(crypto.S256().Params().N)
	secp256k1HalfOrderValue = new(big.Int).Rsh(new(big.Int).Set(crypto.S256().Params().N), 1)
)

type kmsClient interface {
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(ctx context.Context, params *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
}

type KMSDigestSignerConfig struct {
	KeyID           string
	ExpectedAddress common.Address
}

type KMSDigestSigner struct {
	client  kmsClient
	keyID   string
	address common.Address
}

type kmsSubjectPublicKeyInfo struct {
	Algorithm        kmsAlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type kmsAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type kmsECDSASignature struct {
	R *big.Int
	S *big.Int
}

func NewKMSDigestSigner(ctx context.Context, client kmsClient, cfg KMSDigestSignerConfig) (*KMSDigestSigner, error) {
	if client == nil {
		return nil, errors.New("checkpoint: nil kms client")
	}
	keyID := strings.TrimSpace(cfg.KeyID)
	if keyID == "" {
		return nil, errors.New("checkpoint: kms key id required")
	}

	out, err := client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &keyID})
	if err != nil {
		return nil, fmt.Errorf("checkpoint: get kms public key: %w", err)
	}
	if out.KeySpec != types.KeySpecEccSecgP256k1 {
		return nil, fmt.Errorf("checkpoint: unsupported kms key spec %q", out.KeySpec)
	}
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("checkpoint: unsupported kms key usage %q", out.KeyUsage)
	}
	if !containsSigningAlgorithm(out.SigningAlgorithms, types.SigningAlgorithmSpecEcdsaSha256) {
		return nil, fmt.Errorf("checkpoint: kms key does not support %s", types.SigningAlgorithmSpecEcdsaSha256)
	}

	addr, err := parseKMSPublicKeyAddress(out.PublicKey)
	if err != nil {
		return nil, err
	}
	if cfg.ExpectedAddress != (common.Address{}) && cfg.ExpectedAddress != addr {
		return nil, fmt.Errorf("checkpoint: operator address mismatch: expected %s got %s", cfg.ExpectedAddress, addr)
	}

	return &KMSDigestSigner{
		client:  client,
		keyID:   keyID,
		address: addr,
	}, nil
}

func (s *KMSDigestSigner) Address() common.Address {
	if s == nil {
		return common.Address{}
	}
	return s.address
}

func (s *KMSDigestSigner) SignDigest(ctx context.Context, digest common.Hash) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("checkpoint: nil kms signer")
	}
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:            &s.keyID,
		Message:          digest[:],
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("checkpoint: sign digest with kms: %w", err)
	}
	return normalizeKMSSignature(out.Signature, digest, s.address)
}

func containsSigningAlgorithm(have []types.SigningAlgorithmSpec, want types.SigningAlgorithmSpec) bool {
	for _, candidate := range have {
		if candidate == want {
			return true
		}
	}
	return false
}

func parseKMSPublicKeyAddress(der []byte) (common.Address, error) {
	if len(der) == 0 {
		return common.Address{}, fmt.Errorf("%w: empty spki", errInvalidKMSPublicKey)
	}

	var spki kmsSubjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: parse spki: %v", errInvalidKMSPublicKey, err)
	}
	if len(rest) != 0 {
		return common.Address{}, fmt.Errorf("%w: trailing bytes", errInvalidKMSPublicKey)
	}
	if !spki.Algorithm.Algorithm.Equal(oidECPublicKey) {
		return common.Address{}, fmt.Errorf("%w: unexpected algorithm oid %s", errInvalidKMSPublicKey, spki.Algorithm.Algorithm)
	}

	var curveOID asn1.ObjectIdentifier
	if len(spki.Algorithm.Parameters.FullBytes) == 0 {
		return common.Address{}, fmt.Errorf("%w: missing curve parameters", errInvalidKMSPublicKey)
	}
	if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &curveOID); err != nil {
		return common.Address{}, fmt.Errorf("%w: parse curve oid: %v", errInvalidKMSPublicKey, err)
	}
	if !curveOID.Equal(oidSecp256k1) {
		return common.Address{}, fmt.Errorf("%w: unexpected curve oid %s", errInvalidKMSPublicKey, curveOID)
	}

	pub, err := crypto.UnmarshalPubkey(spki.SubjectPublicKey.Bytes)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: decode secp256k1 point: %v", errInvalidKMSPublicKey, err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

func normalizeKMSSignature(sigDER []byte, digest common.Hash, signer common.Address) ([]byte, error) {
	if len(sigDER) == 0 {
		return nil, errors.New("checkpoint: empty kms signature")
	}

	var parsed kmsECDSASignature
	rest, err := asn1.Unmarshal(sigDER, &parsed)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: parse kms signature: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("checkpoint: kms signature has trailing bytes")
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, errors.New("checkpoint: kms signature missing r or s")
	}
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return nil, errors.New("checkpoint: kms signature r and s must be positive")
	}
	if parsed.R.Cmp(secp256k1OrderValue) >= 0 || parsed.S.Cmp(secp256k1OrderValue) >= 0 {
		return nil, errors.New("checkpoint: kms signature r or s exceeds curve order")
	}

	s := new(big.Int).Set(parsed.S)
	if s.Cmp(secp256k1HalfOrderValue) > 0 {
		s.Sub(secp256k1OrderValue, s)
	}

	sig := make([]byte, 65)
	parsed.R.FillBytes(sig[:32])
	s.FillBytes(sig[32:64])

	for _, v := range []byte{0, 1} {
		sig[64] = v
		got, err := RecoverSigner(digest, sig)
		if err == nil && got == signer {
			sig[64] += 27
			return sig, nil
		}
	}

	return nil, errors.New("checkpoint: could not derive recovery id for kms signature")
}

func secp256k1Order() *big.Int {
	return new(big.Int).Set(secp256k1OrderValue)
}

func secp256k1HalfOrder() *big.Int {
	return new(big.Int).Set(secp256k1HalfOrderValue)
}

func secp256k1PublicKeyOID() asn1.ObjectIdentifier {
	return append(asn1.ObjectIdentifier(nil), oidECPublicKey...)
}

func secp256k1CurveOID() asn1.ObjectIdentifier {
	return append(asn1.ObjectIdentifier(nil), oidSecp256k1...)
}
