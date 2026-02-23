package proofrequestor

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/proof"
	sp1 "github.com/juno-intents/intents-juno/internal/sp1network"
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
}

type Outcome struct {
	Status Status

	JobID          string
	RequestID      uint64
	SubmissionPath string
	FallbackUsed   bool

	Seal     []byte
	Metadata map[string]string

	Retryable    bool
	ErrorCode    string
	ErrorMessage string
}

type Service struct {
	cfg Config

	store  proof.Store
	prover sp1.Client
	log    *slog.Logger
}

func New(cfg Config, store proof.Store, prover sp1.Client, log *slog.Logger) (*Service, error) {
	if store == nil || prover == nil {
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
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return &Service{
		cfg:    cfg,
		store:  store,
		prover: prover,
		log:    log,
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
			Status:         StatusSkipped,
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

	runCtx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()

	seal, err := s.prover.Prove(
		runCtx,
		job.ImageID,
		append([]byte(nil), job.Journal...),
		append([]byte(nil), job.PrivateInput...),
	)
	if err == nil {
		return s.markFulfilled(ctx, job.JobID, rec.RequestID, seal)
	}
	code, retryable, message := sp1.ClassifyProveError(err)
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

func (s *Service) markFulfilled(ctx context.Context, jobID common.Hash, requestID uint64, seal []byte) (Outcome, error) {
	metadata := map[string]string{
		"provider":   "sp1",
		"proof_type": "groth16",
	}
	rec, err := s.store.MarkFulfilled(
		ctx,
		jobID,
		s.cfg.Owner,
		requestID,
		append([]byte(nil), seal...),
		metadata,
		sp1.DefaultSubmissionPath,
	)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{
		Status:         StatusFulfilled,
		JobID:          jobID.Hex(),
		RequestID:      rec.RequestID,
		SubmissionPath: rec.SubmissionPath,
		FallbackUsed:   false,
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
