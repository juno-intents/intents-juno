package e2eorch

import (
	"encoding/json"
	"fmt"
	"time"
)

// Report captures the full outcome of an e2e orchestrator run.
// It is serialised to JSON and written to stdout / a file for CI consumption.
type Report struct {
	// Overall result.
	Success   bool      `json:"success"`
	StartTime time.Time `json:"startTime"`
	EndTime   time.Time `json:"endTime"`
	Duration  string    `json:"duration"` // human-readable

	// Per-phase results.
	Deposit    *DepositResult    `json:"deposit,omitempty"`
	Withdrawal *WithdrawalResult `json:"withdrawal,omitempty"`

	// Post-run invariant checks.
	Invariants []InvariantCheck `json:"invariants,omitempty"`

	// If the run failed, Error contains a short description.
	Error string `json:"error,omitempty"`
}

// WithdrawalResult captures timing and outcome for the withdrawal phase.
type WithdrawalResult struct {
	Success      bool   `json:"success"`
	WithdrawalID string `json:"withdrawalId,omitempty"`
	Amount       string `json:"amount,omitempty"`
	FeeBps       uint64 `json:"feeBps,omitempty"`

	// Timing breakdown.
	RequestedAt   *time.Time `json:"requestedAt,omitempty"`
	BatchedAt     *time.Time `json:"batchedAt,omitempty"`
	BroadcastedAt *time.Time `json:"broadcastedAt,omitempty"`
	ConfirmedAt   *time.Time `json:"confirmedAt,omitempty"`
	FinalizedAt   *time.Time `json:"finalizedAt,omitempty"`
	TotalDuration string     `json:"totalDuration,omitempty"`

	// On-chain confirmation.
	BaseTxHash string `json:"baseTxHash,omitempty"`
	JunoTxID   string `json:"junoTxId,omitempty"`
	BatchID    string `json:"batchId,omitempty"`

	// On-chain view after finalization.
	OnChainFinalized bool `json:"onChainFinalized"`
	OnChainRefunded  bool `json:"onChainRefunded"`

	// Final API state.
	FinalState string `json:"finalState,omitempty"`

	Error string `json:"error,omitempty"`
}

// InvariantCheck records the result of a single post-run invariant assertion.
type InvariantCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details,omitempty"`
}

// Finalize sets the EndTime, Duration, and overall Success based on phase results.
func (r *Report) Finalize() {
	r.EndTime = time.Now().UTC()
	r.Duration = r.EndTime.Sub(r.StartTime).Round(time.Millisecond).String()

	r.Success = true
	if r.Deposit != nil && !r.Deposit.Success {
		r.Success = false
	}
	if r.Withdrawal != nil && !r.Withdrawal.Success {
		r.Success = false
	}
	for _, inv := range r.Invariants {
		if !inv.Passed {
			r.Success = false
			break
		}
	}
}

// JSON returns the report as indented JSON bytes.
func (r *Report) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	return append(b, '\n'), nil
}

// NewReport creates a Report with StartTime set to now.
func NewReport() *Report {
	return &Report{
		StartTime: time.Now().UTC(),
	}
}
