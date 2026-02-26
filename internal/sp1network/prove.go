package sp1network

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

const DefaultSubmissionPath = "sp1-network-mainnet"

type FundingClient interface {
	RequestorBalanceWei(ctx context.Context, requestor common.Address) (*big.Int, error)
}

type ProveError struct {
	Code      string
	Retryable bool
	Cause     error
}

func (e *ProveError) Error() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	if strings.TrimSpace(e.Code) != "" {
		b.WriteString(strings.TrimSpace(e.Code))
	}
	if e.Cause != nil {
		if b.Len() > 0 {
			b.WriteString(": ")
		}
		b.WriteString(e.Cause.Error())
	}
	if b.Len() == 0 {
		return "sp1 prove failed"
	}
	return b.String()
}

func (e *ProveError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func AsProveError(err error) (*ProveError, bool) {
	var target *ProveError
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

func ClassifyProveError(err error) (code string, retryable bool, message string) {
	if err == nil {
		return "", false, ""
	}
	if p, ok := AsProveError(err); ok {
		code = strings.TrimSpace(p.Code)
		if code == "" {
			code = "sp1_prove_error"
		}
		return code, p.Retryable, p.Error()
	}

	message = err.Error()
	normalized := strings.ToLower(strings.TrimSpace(message))
	switch {
	case strings.Contains(normalized, "unexecutable"):
		return "sp1_request_unexecutable", false, message
	case strings.Contains(normalized, "program vkey mismatch"),
		strings.Contains(normalized, "journal mismatch"),
		strings.Contains(normalized, "unsupported image id"),
		strings.Contains(normalized, "decode prover request"),
		strings.Contains(normalized, "decode prover journal"),
		strings.Contains(normalized, "decode prover private_input"):
		return "sp1_invalid_input", false, message
	case strings.Contains(normalized, "program simulation failed"):
		return "sp1_simulation_failed", false, message
	case strings.Contains(normalized, "timed out during the auction"):
		return "sp1_request_auction_timeout", true, message
	case strings.Contains(normalized, "timed out"),
		strings.Contains(normalized, "timeout"):
		return "sp1_request_timeout", true, message
	case strings.Contains(normalized, "unfulfillable"):
		return "sp1_request_unfulfillable", true, message
	default:
		return "sp1_prove_error", true, message
	}
}

func NewPermanentError(code string, cause error) error {
	return &ProveError{
		Code:      strings.TrimSpace(code),
		Retryable: false,
		Cause:     cause,
	}
}

func NewRetryableError(code string, cause error) error {
	return &ProveError{
		Code:      strings.TrimSpace(code),
		Retryable: true,
		Cause:     cause,
	}
}

func ValidateFundingAddress(address common.Address) error {
	if address == (common.Address{}) {
		return fmt.Errorf("%w: requestor address is required", ErrInvalidConfig)
	}
	return nil
}
