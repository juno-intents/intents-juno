package deposit

import (
	"fmt"

	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type State uint8

const (
	StateUnknown State = iota
	StateSeen
	StateConfirmed
	StateProofRequested
	StateProofReady
	StateSubmitted
	StateFinalized
	StateRejected
)

func (s State) String() string {
	switch s {
	case StateSeen:
		return "seen"
	case StateConfirmed:
		return "confirmed"
	case StateProofRequested:
		return "proof_requested"
	case StateProofReady:
		return "proof_ready"
	case StateSubmitted:
		return "submitted"
	case StateFinalized:
		return "finalized"
	case StateRejected:
		return "rejected"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

type Deposit struct {
	DepositID     [32]byte
	Commitment    [32]byte
	LeafIndex     uint64
	Amount        uint64
	BaseRecipient [20]byte

	// SourceEvent identifies the originating scanner event when available.
	// It is optional for backward compatibility with legacy producers.
	SourceEvent *SourceEvent

	// ProofWitnessItem is the optional per-deposit witness payload expected by
	// the deposit guest, excluding checkpoint fields, IVK, and item count.
	// Layout must match proverinput.DepositWitnessItemLen.
	ProofWitnessItem []byte

	// JunoHeight is the Juno chain height at which this deposit was observed.
	// Zero means unknown (legacy rows).
	JunoHeight int64
}

type SourceEvent struct {
	ChainID  uint64
	TxHash   [32]byte
	LogIndex uint64
}

type Job struct {
	Deposit Deposit
	State   State

	Checkpoint checkpoint.Checkpoint

	ProofSeal       []byte
	TxHash          [32]byte
	RejectionReason string
}

type SubmittedBatchAttempt struct {
	BatchID [32]byte

	DepositIDs [][32]byte

	Owner string
	Epoch uint64

	Checkpoint         checkpoint.Checkpoint
	OperatorSignatures [][]byte

	ProofSeal []byte
	TxHash    [32]byte
}
