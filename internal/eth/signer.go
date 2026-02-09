package eth

import (
	"crypto/ecdsa"
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

var ErrInvalidSigner = errors.New("eth: invalid signer")

// Signer signs EVM transactions for a single from-address.
//
// Production signers may be backed by KMS/HSM; tests and local dev can use LocalSigner.
type Signer interface {
	Address() common.Address
	SignTx(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error)
}

type LocalSigner struct {
	key  *ecdsa.PrivateKey
	addr common.Address
}

func NewLocalSigner(key *ecdsa.PrivateKey) *LocalSigner {
	var addr common.Address
	if key != nil {
		addr = crypto.PubkeyToAddress(key.PublicKey)
	}
	return &LocalSigner{key: key, addr: addr}
}

func (s *LocalSigner) Address() common.Address { return s.addr }

func (s *LocalSigner) SignTx(tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	if s.key == nil || tx == nil || chainID == nil || chainID.Sign() <= 0 {
		return nil, ErrInvalidSigner
	}
	signer := types.LatestSignerForChainID(chainID)
	return types.SignTx(tx, signer, s.key)
}
