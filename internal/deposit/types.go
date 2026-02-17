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

	// ProofWitnessItem is the optional per-deposit witness payload expected by
	// the deposit guest, excluding checkpoint fields, IVK, and item count.
	// Layout must match proverinput.DepositWitnessItemLen.
	ProofWitnessItem []byte
}

type Job struct {
	Deposit Deposit
	State   State

	Checkpoint checkpoint.Checkpoint

	ProofSeal []byte
	TxHash    [32]byte
}
