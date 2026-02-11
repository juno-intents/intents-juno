package boundless

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const (
	SubmissionModeOffchainPrimaryOnchainFallback = "offchain_primary_onchain_fallback"
	FundingModeMinMaxBalance                     = "MinMaxBalance"
)

type SubmitRequest struct {
	RequestID           uint64
	ChainID             uint64
	RequestorAddress    common.Address
	RequestorPrivateKey string
	OrderStreamURL      string
	MarketAddress       common.Address

	JobID        common.Hash
	Pipeline     string
	ImageID      common.Hash
	Journal      []byte
	PrivateInput []byte
	Deadline     time.Time
	Priority     int
}

type OnchainSubmitRequest struct {
	SubmitRequest

	FundingMode string

	MinBalanceWei       *big.Int
	TargetBalanceWei    *big.Int
	MaxPricePerProofWei *big.Int
	MaxStakePerProofWei *big.Int
}

type SubmitResponse struct {
	RequestID      uint64
	SubmissionPath string
	Seal           []byte
	Metadata       map[string]string
	TxHash         string
}

type Submitter interface {
	SubmitOffchain(ctx context.Context, req SubmitRequest) (SubmitResponse, error)
	SubmitOnchain(ctx context.Context, req OnchainSubmitRequest) (SubmitResponse, error)
}

type FundingClient interface {
	RequestorBalanceWei(ctx context.Context, requestor common.Address) (*big.Int, error)
	TopUpRequestor(ctx context.Context, requestor common.Address, amountWei *big.Int) (string, error)
}

type SubmitError struct {
	Code      string
	Retryable bool
	Cause     error
}

func (e *SubmitError) Error() string {
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
		return "boundless submit failed"
	}
	return b.String()
}

func (e *SubmitError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func AsSubmitError(err error) (*SubmitError, bool) {
	var target *SubmitError
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

func ClassifySubmitError(err error) (code string, retryable bool, message string) {
	if err == nil {
		return "", false, ""
	}
	if s, ok := AsSubmitError(err); ok {
		code = strings.TrimSpace(s.Code)
		if code == "" {
			code = "boundless_submit_error"
		}
		return code, s.Retryable, s.Error()
	}
	return "boundless_submit_error", true, err.Error()
}

func CopyMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func ValidateFundingMode(mode string) error {
	if strings.TrimSpace(mode) != FundingModeMinMaxBalance {
		return fmt.Errorf("%w: unsupported funding mode %q", ErrInvalidConfig, mode)
	}
	return nil
}
