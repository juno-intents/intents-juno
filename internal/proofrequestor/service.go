package proofrequestor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/boundless"
	"github.com/juno-intents/intents-juno/internal/proof"
)

type Status string

const (
	StatusFulfilled Status = "fulfilled"
	StatusFailed    Status = "failed"
	StatusSkipped   Status = "skipped"
)

type Config struct {
	Owner                  string
	ChainID                uint64
	RequestTimeout         time.Duration
	CallbackIdempotencyTTL time.Duration

	SubmissionMode string

	OnchainFallbackEnabled     bool
	OnchainFallbackFundingMode string
	OnchainMinBalanceWei       *big.Int
	OnchainTargetBalanceWei    *big.Int
	OnchainMaxPricePerProofWei *big.Int
	OnchainMaxStakePerProofWei *big.Int
}

type Outcome struct {
	Status Status

	JobID        string
	RequestID    uint64
	SubmissionPath string
	FallbackUsed bool

	Seal     []byte
	Metadata map[string]string

	Retryable    bool
	ErrorCode    string
	ErrorMessage string
}

type Service struct {
	cfg Config

	store     proof.Store
	submitter boundless.Submitter
	log       *slog.Logger
}

func New(cfg Config, store proof.Store, submitter boundless.Submitter, log *slog.Logger) (*Service, error) {
	if store == nil || submitter == nil {
		return nil, fmt.Errorf("%w: nil dependency", proof.ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.Owner) == "" {
		return nil, fmt.Errorf("%w: owner is required", proof.ErrInvalidConfig)
	}
	if cfg.ChainID == 0 {
		return nil, fmt.Errorf("%w: chain id is required", proof.ErrInvalidConfig)
	}
	if cfg.RequestTimeout <= 0 || cfg.CallbackIdempotencyTTL <= 0 {
		return nil, fmt.Errorf("%w: timeouts must be > 0", proof.ErrInvalidConfig)
	}
	if strings.TrimSpace(cfg.SubmissionMode) == "" {
		cfg.SubmissionMode = boundless.SubmissionModeOffchainPrimaryOnchainFallback
	}
	if cfg.OnchainFallbackEnabled {
		if err := boundless.ValidateFundingMode(cfg.OnchainFallbackFundingMode); err != nil {
			return nil, err
		}
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return &Service{
		cfg:       cfg,
		store:     store,
		submitter: submitter,
		log:       log,
	}, nil
}

func (s *Service) ProcessJob(ctx context.Context, job proof.JobRequest) (Outcome, error) {
	if err := job.Validate(); err != nil {
		return Outcome{}, err
	}

	if _, err := s.store.UpsertJob(ctx, job, s.cfg.CallbackIdempotencyTTL); err != nil {
		return Outcome{}, err
	}
	rec, claimed, err := s.store.ClaimForSubmission(ctx, job.JobID, s.cfg.Owner, s.cfg.RequestTimeout, s.cfg.ChainID)
	if err != nil {
		return Outcome{}, err
	}
	if !claimed {
		out := Outcome{
			Status:        StatusSkipped,
			JobID:          job.JobID.Hex(),
			RequestID:      rec.RequestID,
			SubmissionPath: rec.SubmissionPath,
			Seal:           append([]byte(nil), rec.Seal...),
			Metadata:       cloneMetadata(rec.Metadata),
			Retryable:      rec.Retryable,
			ErrorCode:      rec.ErrorCode,
			ErrorMessage:   rec.ErrorMessage,
		}
		switch rec.State {
		case proof.StateFulfilled:
			out.Status = StatusFulfilled
		case proof.StateFailedRetry, proof.StateFailedTerminal:
			out.Status = StatusFailed
		}
		return out, nil
	}

	baseReq := boundless.SubmitRequest{
		RequestID:   rec.RequestID,
		ChainID:     s.cfg.ChainID,
		JobID:       job.JobID,
		Pipeline:    job.Pipeline,
		ImageID:     job.ImageID,
		Journal:     append([]byte(nil), job.Journal...),
		PrivateInput: append([]byte(nil), job.PrivateInput...),
		Deadline:    job.Deadline,
		Priority:    job.Priority,
	}

	runCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()

	resp, err := s.submitter.SubmitOffchain(runCtx, baseReq)
	if err == nil {
		return s.markFulfilled(ctx, job.JobID, rec.RequestID, resp, false)
	}
	s.log.Warn("offchain submission failed; evaluating fallback", "job_id", job.JobID, "request_id", rec.RequestID, "err", err)

	if s.cfg.SubmissionMode == boundless.SubmissionModeOffchainPrimaryOnchainFallback && s.cfg.OnchainFallbackEnabled {
		onReq := boundless.OnchainSubmitRequest{
			SubmitRequest:         baseReq,
			FundingMode:           s.cfg.OnchainFallbackFundingMode,
			MinBalanceWei:         cloneBigInt(s.cfg.OnchainMinBalanceWei),
			TargetBalanceWei:      cloneBigInt(s.cfg.OnchainTargetBalanceWei),
			MaxPricePerProofWei:   cloneBigInt(s.cfg.OnchainMaxPricePerProofWei),
			MaxStakePerProofWei:   cloneBigInt(s.cfg.OnchainMaxStakePerProofWei),
		}
		onResp, onErr := s.submitter.SubmitOnchain(runCtx, onReq)
		if onErr == nil {
			return s.markFulfilled(ctx, job.JobID, rec.RequestID, onResp, true)
		}
		code, retryable, message := boundless.ClassifySubmitError(onErr)
		if _, markErr := s.store.MarkFailed(ctx, job.JobID, s.cfg.Owner, rec.RequestID, code, message, retryable); markErr != nil {
			return Outcome{}, markErr
		}
		return Outcome{
			Status:       StatusFailed,
			JobID:        job.JobID.Hex(),
			RequestID:    rec.RequestID,
			Retryable:    retryable,
			ErrorCode:    code,
			ErrorMessage: message,
		}, nil
	}

	code, retryable, message := boundless.ClassifySubmitError(err)
	if _, markErr := s.store.MarkFailed(ctx, job.JobID, s.cfg.Owner, rec.RequestID, code, message, retryable); markErr != nil {
		return Outcome{}, markErr
	}
	return Outcome{
		Status:       StatusFailed,
		JobID:        job.JobID.Hex(),
		RequestID:    rec.RequestID,
		Retryable:    retryable,
		ErrorCode:    code,
		ErrorMessage: message,
	}, nil
}

func (s *Service) markFulfilled(ctx context.Context, jobID common.Hash, requestID uint64, resp boundless.SubmitResponse, fallback bool) (Outcome, error) {
	submissionPath := strings.TrimSpace(resp.SubmissionPath)
	if submissionPath == "" {
		if fallback {
			submissionPath = "onchain"
		} else {
			submissionPath = "offchain"
		}
	}
	rec, err := s.store.MarkFulfilled(ctx, jobID, s.cfg.Owner, requestID, resp.Seal, resp.Metadata, submissionPath)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{
		Status:         StatusFulfilled,
		JobID:          jobID.Hex(),
		RequestID:      rec.RequestID,
		SubmissionPath: rec.SubmissionPath,
		FallbackUsed:   fallback,
		Seal:           append([]byte(nil), rec.Seal...),
		Metadata:       cloneMetadata(rec.Metadata),
	}, nil
}

func cloneMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneBigInt(v *big.Int) *big.Int {
	if v == nil {
		return nil
	}
	return new(big.Int).Set(v)
}
