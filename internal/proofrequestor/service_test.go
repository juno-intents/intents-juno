package proofrequestor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/boundless"
	"github.com/juno-intents/intents-juno/internal/proof"
)

type stubSubmitter struct {
	offchainCalls int
	onchainCalls  int
	offchainResp  boundless.SubmitResponse
	onchainResp   boundless.SubmitResponse
	offchainErr   error
	onchainErr    error
}

func (s *stubSubmitter) SubmitOffchain(_ context.Context, _ boundless.SubmitRequest) (boundless.SubmitResponse, error) {
	s.offchainCalls++
	if s.offchainErr != nil {
		return boundless.SubmitResponse{}, s.offchainErr
	}
	return s.offchainResp, nil
}

func (s *stubSubmitter) SubmitOnchain(_ context.Context, _ boundless.OnchainSubmitRequest) (boundless.SubmitResponse, error) {
	s.onchainCalls++
	if s.onchainErr != nil {
		return boundless.SubmitResponse{}, s.onchainErr
	}
	return s.onchainResp, nil
}

func TestService_PrefersOffchainAndFallsBackOnFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 9, 0, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	submitter := &stubSubmitter{
		offchainErr: errors.New("offchain failed"),
		onchainResp: boundless.SubmitResponse{
			RequestID:      1,
			SubmissionPath: "onchain",
			Seal:           []byte{0xaa},
		},
	}
	svc, err := New(Config{
		Owner:                     "requestor-a",
		ChainID:                   8453,
		RequestTimeout:            5 * time.Second,
		CallbackIdempotencyTTL:    72 * time.Hour,
		SubmissionMode:            boundless.SubmissionModeOffchainPrimaryOnchainFallback,
		OnchainFallbackEnabled:    true,
		OnchainFallbackFundingMode: boundless.FundingModeMinMaxBalance,
	}, store, submitter, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	job := proof.JobRequest{
		JobID:        common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(2 * time.Minute),
		Priority:     3,
	}

	out, err := svc.ProcessJob(context.Background(), job)
	if err != nil {
		t.Fatalf("ProcessJob: %v", err)
	}
	if got, want := out.Status, StatusFulfilled; got != want {
		t.Fatalf("status: got %s want %s", got, want)
	}
	if submitter.offchainCalls != 1 {
		t.Fatalf("offchain calls: got %d want 1", submitter.offchainCalls)
	}
	if submitter.onchainCalls != 1 {
		t.Fatalf("onchain calls: got %d want 1", submitter.onchainCalls)
	}
	if out.SubmissionPath != "onchain" {
		t.Fatalf("submission path: got %q want onchain", out.SubmissionPath)
	}
}

func TestService_DoesNotFallbackWhenOffchainSucceeds(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 10, 0, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	submitter := &stubSubmitter{
		offchainResp: boundless.SubmitResponse{
			RequestID:      1,
			SubmissionPath: "offchain",
			Seal:           []byte{0xbb},
		},
	}
	svc, err := New(Config{
		Owner:                     "requestor-a",
		ChainID:                   8453,
		RequestTimeout:            5 * time.Second,
		CallbackIdempotencyTTL:    72 * time.Hour,
		SubmissionMode:            boundless.SubmissionModeOffchainPrimaryOnchainFallback,
		OnchainFallbackEnabled:    true,
		OnchainFallbackFundingMode: boundless.FundingModeMinMaxBalance,
	}, store, submitter, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	job := proof.JobRequest{
		JobID:        common.HexToHash("0x4314e7904fd1808ad5a2394a4e8e6cf6ccf8802f27195be7d87da01f5c23a1ee"),
		Pipeline:     "withdraw",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(2 * time.Minute),
		Priority:     1,
	}

	out, err := svc.ProcessJob(context.Background(), job)
	if err != nil {
		t.Fatalf("ProcessJob: %v", err)
	}
	if got, want := out.Status, StatusFulfilled; got != want {
		t.Fatalf("status: got %s want %s", got, want)
	}
	if submitter.offchainCalls != 1 {
		t.Fatalf("offchain calls: got %d want 1", submitter.offchainCalls)
	}
	if submitter.onchainCalls != 0 {
		t.Fatalf("onchain calls: got %d want 0", submitter.onchainCalls)
	}
	if out.SubmissionPath != "offchain" {
		t.Fatalf("submission path: got %q want offchain", out.SubmissionPath)
	}
}

