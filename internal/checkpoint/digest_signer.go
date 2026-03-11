package checkpoint

import (
	"context"
	"crypto/ecdsa"
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// DigestSigner signs checkpoint digests for a single operator identity.
type DigestSigner interface {
	Address() common.Address
	SignDigest(ctx context.Context, digest common.Hash) ([]byte, error)
}

type LocalDigestSigner struct {
	key  *ecdsa.PrivateKey
	addr common.Address
}

func NewLocalDigestSigner(key *ecdsa.PrivateKey) (*LocalDigestSigner, error) {
	if key == nil {
		return nil, errors.New("checkpoint: nil private key")
	}
	return &LocalDigestSigner{
		key:  key,
		addr: crypto.PubkeyToAddress(key.PublicKey),
	}, nil
}

func (s *LocalDigestSigner) Address() common.Address {
	if s == nil {
		return common.Address{}
	}
	return s.addr
}

func (s *LocalDigestSigner) SignDigest(_ context.Context, digest common.Hash) ([]byte, error) {
	if s == nil {
		return nil, errors.New("checkpoint: nil digest signer")
	}
	return SignDigest(s.key, digest)
}
