package checkpoint

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	// These MUST match the EIP-712 domain in contracts/src/Bridge.sol.
	EIP712DomainName    = "WJUNO Bridge"
	EIP712DomainVersion = "1"
)

var (
	// See OpenZeppelin EIP712.sol.
	eip712DomainTypeHash = crypto.Keccak256Hash([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	eip712NameHash       = crypto.Keccak256Hash([]byte(EIP712DomainName))
	eip712VersionHash    = crypto.Keccak256Hash([]byte(EIP712DomainVersion))

	checkpointTypeHash = crypto.Keccak256Hash([]byte(
		"Checkpoint(uint64 height,bytes32 blockHash,bytes32 finalOrchardRoot,uint256 baseChainId,address bridgeContract)",
	))

	ErrInvalidSignature = errors.New("checkpoint: invalid signature")
)

// Checkpoint is the off-chain mirror of Bridge.Checkpoint (contracts/src/Bridge.sol).
type Checkpoint struct {
	Height           uint64         `json:"height"`
	BlockHash        common.Hash    `json:"blockHash"`
	FinalOrchardRoot common.Hash    `json:"finalOrchardRoot"`
	BaseChainID      uint64         `json:"baseChainId"`
	BridgeContract   common.Address `json:"bridgeContract"`
}

// Digest computes the EIP-712 digest for checkpoint signing as implemented by Bridge.checkpointDigest.
//
// The digest is:
//
//	keccak256("\x19\x01" || domainSeparator || structHash)
//
// where:
// - domainSeparator = keccak256(abi.encode(domainTypeHash, nameHash, versionHash, chainId, verifyingContract))
// - structHash = keccak256(abi.encode(checkpointTypeHash, height, blockHash, finalOrchardRoot, baseChainId, bridgeContract))
func Digest(cp Checkpoint) common.Hash {
	domainSep := domainSeparator(cp.BaseChainID, cp.BridgeContract)
	structHash := structHash(cp)
	return crypto.Keccak256Hash([]byte{0x19, 0x01}, domainSep[:], structHash[:])
}

// SignDigest signs an EIP-712 digest and returns a 65-byte Ethereum signature: r(32) || s(32) || v(1).
//
// v is normalized to 27/28 (as expected by OpenZeppelin ECDSA.recover on-chain).
func SignDigest(key *ecdsa.PrivateKey, digest common.Hash) ([]byte, error) {
	if key == nil {
		return nil, errors.New("checkpoint: nil private key")
	}
	sig, err := crypto.Sign(digest[:], key)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: sign digest: %w", err)
	}
	if len(sig) != 65 {
		return nil, fmt.Errorf("checkpoint: unexpected signature length %d", len(sig))
	}
	if sig[64] < 27 {
		sig[64] += 27
	}
	return sig, nil
}

// RecoverSigner recovers the Ethereum address that created sig over digest.
//
// sig must be 65 bytes with v in {0,1,27,28}.
func RecoverSigner(digest common.Hash, sig []byte) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("%w: length %d", ErrInvalidSignature, len(sig))
	}

	// go-ethereum expects v in {0,1}.
	s := make([]byte, 65)
	copy(s, sig)
	switch s[64] {
	case 0, 1:
		// ok
	case 27, 28:
		s[64] -= 27
	default:
		return common.Address{}, fmt.Errorf("%w: bad v %d", ErrInvalidSignature, s[64])
	}

	pub, err := crypto.SigToPub(digest[:], s)
	if err != nil {
		return common.Address{}, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
	}
	return crypto.PubkeyToAddress(*pub), nil
}

func domainSeparator(chainID uint64, verifyingContract common.Address) common.Hash {
	// abi.encode(bytes32,bytes32,bytes32,uint256,address)
	b := make([]byte, 0, 32*5)
	b = append(b, eip712DomainTypeHash[:]...)
	b = append(b, eip712NameHash[:]...)
	b = append(b, eip712VersionHash[:]...)
	b = append(b, encodeUint256FromUint64(chainID)...)
	b = append(b, encodeAddress(verifyingContract)...)
	return crypto.Keccak256Hash(b)
}

func structHash(cp Checkpoint) common.Hash {
	// abi.encode(bytes32,uint64,bytes32,bytes32,uint256,address)
	b := make([]byte, 0, 32*6)
	b = append(b, checkpointTypeHash[:]...)
	b = append(b, encodeUint256FromUint64(cp.Height)...)
	b = append(b, cp.BlockHash[:]...)
	b = append(b, cp.FinalOrchardRoot[:]...)
	b = append(b, encodeUint256FromUint64(cp.BaseChainID)...)
	b = append(b, encodeAddress(cp.BridgeContract)...)
	return crypto.Keccak256Hash(b)
}

func encodeUint256FromUint64(v uint64) []byte {
	var out [32]byte
	binary.BigEndian.PutUint64(out[24:], v)
	return out[:]
}

func encodeAddress(a common.Address) []byte {
	var out [32]byte
	copy(out[12:], a[:])
	return out[:]
}
