package idempotency

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestDepositBatchIDV1_DeterministicAndOrderIndependent(t *testing.T) {
	t.Parallel()

	id1 := common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111")
	id2 := common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222")
	id3 := common.HexToHash("0x3333333333333333333333333333333333333333333333333333333333333333")

	a := DepositBatchIDV1([]common.Hash{id1, id2, id3})
	b := DepositBatchIDV1([]common.Hash{id3, id2, id1})
	if a != b {
		t.Fatalf("deposit batch id must be order independent")
	}
}

func TestProofJobIDV1_DomainSeparated(t *testing.T) {
	t.Parallel()

	batchID := common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	imageID := common.HexToHash("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	journal := []byte{0x01, 0x02, 0x03}
	privateInput := []byte{0x04, 0x05}

	deposit := ProofJobIDV1("deposit", batchID, imageID, journal, privateInput)
	withdraw := ProofJobIDV1("withdraw", batchID, imageID, journal, privateInput)
	if deposit == withdraw {
		t.Fatalf("pipeline domain separation failed")
	}

	changedJournal := ProofJobIDV1("deposit", batchID, imageID, []byte{0x01, 0x02, 0x09}, privateInput)
	if deposit == changedJournal {
		t.Fatalf("journal hash must affect job id")
	}

	changedInput := ProofJobIDV1("deposit", batchID, imageID, journal, []byte{0x04, 0x08})
	if deposit == changedInput {
		t.Fatalf("private input hash must affect job id")
	}
	if bytes.Equal(deposit[:], make([]byte, 32)) {
		t.Fatalf("job id must not be zero")
	}
}
