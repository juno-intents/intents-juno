package withdraw

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidConfig         = errors.New("withdraw: invalid config")
	ErrInvalidFeeBps         = errors.New("withdraw: invalid fee bps")
	ErrDuplicateWithdrawalID = errors.New("withdraw: duplicate withdrawal id")
)

// Withdrawal is the off-chain record corresponding to a Bridge.WithdrawRequested event.
//
// Amounts are uint64 in this repo scaffold; production should use uint256-compatible math end-to-end.
type Withdrawal struct {
	ID [32]byte

	Requester   [20]byte
	Amount      uint64
	FeeBps      uint32
	RecipientUA []byte
	// ProofWitnessItem is the optional per-withdrawal witness payload expected
	// by the withdraw guest, excluding checkpoint fields, OVK, and item count.
	// Layout must match proverinput.WithdrawWitnessItemLen.
	ProofWitnessItem []byte

	// Expiry is the on-chain expiry time (block.timestamp seconds) as a UTC time.
	Expiry time.Time
}

func (w Withdrawal) Validate() error {
	if w.ID == ([32]byte{}) {
		return fmt.Errorf("%w: missing id", ErrInvalidConfig)
	}
	// Amount can be zero on-chain? Bridge rejects amount==0. Keep the same invariant.
	if w.Amount == 0 {
		return fmt.Errorf("%w: amount must be > 0", ErrInvalidConfig)
	}
	if w.FeeBps > 10_000 {
		return ErrInvalidFeeBps
	}
	if len(w.RecipientUA) == 0 {
		return fmt.Errorf("%w: missing recipient UA", ErrInvalidConfig)
	}
	// Bridge.MAX_UA_BYTES = 256.
	if len(w.RecipientUA) > 256 {
		return fmt.Errorf("%w: recipient UA too long", ErrInvalidConfig)
	}
	if w.Expiry.IsZero() {
		return fmt.Errorf("%w: missing expiry", ErrInvalidConfig)
	}
	return nil
}
