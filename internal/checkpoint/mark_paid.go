package checkpoint

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

var (
	markWithdrawPaidTypeHash = crypto.Keccak256Hash([]byte(
		"MarkWithdrawPaid(bytes32 withdrawalIdsHash,uint256 baseChainId,address bridgeContract)",
	))

	ErrInvalidMarkWithdrawPaidInput = errors.New("checkpoint: invalid mark withdraw paid input")
)

// MarkWithdrawPaidDigest computes the EIP-712 digest used by Bridge.markWithdrawPaidBatch signatures.
//
// withdrawalIDs must be sorted ascending and unique.
func MarkWithdrawPaidDigest(withdrawalIDs [][32]byte, baseChainID uint64, bridgeContract common.Address) (common.Hash, error) {
	if len(withdrawalIDs) == 0 {
		return common.Hash{}, fmt.Errorf("%w: empty withdrawal ids", ErrInvalidMarkWithdrawPaidInput)
	}
	if baseChainID == 0 {
		return common.Hash{}, fmt.Errorf("%w: base chain id must be non-zero", ErrInvalidMarkWithdrawPaidInput)
	}
	if bridgeContract == (common.Address{}) {
		return common.Hash{}, fmt.Errorf("%w: bridge contract must be non-zero", ErrInvalidMarkWithdrawPaidInput)
	}

	for i := 1; i < len(withdrawalIDs); i++ {
		if bytes.Compare(withdrawalIDs[i][:], withdrawalIDs[i-1][:]) <= 0 {
			return common.Hash{}, fmt.Errorf("%w: ids must be sorted ascending and unique", ErrInvalidMarkWithdrawPaidInput)
		}
	}

	packed := make([]byte, 0, len(withdrawalIDs)*32)
	for _, id := range withdrawalIDs {
		packed = append(packed, id[:]...)
	}
	idsHash := crypto.Keccak256Hash(packed)

	// abi.encode(bytes32,bytes32,uint256,address)
	b := make([]byte, 0, 32*4)
	b = append(b, markWithdrawPaidTypeHash[:]...)
	b = append(b, idsHash[:]...)
	b = append(b, encodeUint256FromUint64(baseChainID)...)
	b = append(b, encodeAddress(bridgeContract)...)
	structHash := crypto.Keccak256Hash(b)

	domainSep := domainSeparator(baseChainID, bridgeContract)
	return crypto.Keccak256Hash([]byte{0x19, 0x01}, domainSep[:], structHash[:]), nil
}
