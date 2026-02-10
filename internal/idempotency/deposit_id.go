package idempotency

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

const depositIDPrefixV1 = "deposit"

// DepositIDV1 computes the canonical deposit id.
//
// Spec:
//
//	depositId = keccak256("deposit" || cm || leafIndexBE)
//
// where leafIndexBE is the 8-byte big-endian encoding of the Orchard commitment tree leaf index.
func DepositIDV1(cm [32]byte, leafIndex uint64) [32]byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write([]byte(depositIDPrefixV1))
	_, _ = h.Write(cm[:])

	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], leafIndex)
	_, _ = h.Write(idx[:])

	sum := h.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out
}

