package idempotency

import (
	"bytes"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

// DepositBatchIDV1 computes a deterministic, order-independent batch identifier
// for deposit proof requests.
func DepositBatchIDV1(depositIDs []common.Hash) common.Hash {
	if len(depositIDs) == 0 {
		return common.Hash{}
	}

	ids := append([]common.Hash(nil), depositIDs...)
	slices.SortFunc(ids, func(a, b common.Hash) int {
		return bytes.Compare(a[:], b[:])
	})

	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write([]byte("WJUNO_DEPOSIT_BATCH_V1"))
	for _, id := range ids {
		_, _ = h.Write(id[:])
	}
	sum := h.Sum(nil)
	return common.BytesToHash(sum)
}

// ProofJobIDV1 computes the centralized proof job id:
// keccak256(pipeline || batch_id || image_id || journal_hash || private_input_hash).
func ProofJobIDV1(pipeline string, batchID common.Hash, imageID common.Hash, journal []byte, privateInput []byte) common.Hash {
	hJournal := keccak256(journal)
	hInput := keccak256(privateInput)

	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write([]byte(pipeline))
	_, _ = h.Write(batchID[:])
	_, _ = h.Write(imageID[:])
	_, _ = h.Write(hJournal[:])
	_, _ = h.Write(hInput[:])
	return common.BytesToHash(h.Sum(nil))
}

func keccak256(v []byte) common.Hash {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(v)
	return common.BytesToHash(h.Sum(nil))
}
