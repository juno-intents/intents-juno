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
//	depositId = keccak256("deposit" || cm || leafIndexBE32)
//
// where leafIndexBE32 is the 4-byte big-endian encoding of the Orchard commitment tree leaf index.
// This matches the SP1 deposit guest witness format (`leaf_index: u32`).
func DepositIDV1(cm [32]byte, leafIndex uint64) [32]byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write([]byte(depositIDPrefixV1))
	_, _ = h.Write(cm[:])

	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], uint32(leafIndex))
	_, _ = h.Write(idx[:])

	sum := h.Sum(nil)
	var out [32]byte
	copy(out[:], sum)
	return out
}
