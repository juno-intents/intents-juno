package proofrequestor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/proof"
	sp1 "github.com/juno-intents/intents-juno/internal/sp1network"
)

type stubProver struct {
	calls int
	seal  []byte
	err   error
}

func (s *stubProver) Prove(_ context.Context, _ common.Hash, _ []byte, _ []byte) ([]byte, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return append([]byte(nil), s.seal...), nil
}

func TestService_ProofSuccess(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 10, 0, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	prover := &stubProver{seal: []byte{0xbb}}
	svc, err := New(Config{
		Owner:                  "requestor-a",
		ChainID:                8453,
		RequestTimeout:         5 * time.Second,
		CallbackIdempotencyTTL: 72 * time.Hour,
	}, store, prover, nil)
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
	if prover.calls != 1 {
		t.Fatalf("prove calls: got %d want 1", prover.calls)
	}
	if got, want := out.SubmissionPath, sp1.DefaultSubmissionPath; got != want {
		t.Fatalf("submission path: got %q want %q", got, want)
	}
	if got, want := out.Metadata["provider"], "sp1"; got != want {
		t.Fatalf("metadata provider: got %q want %q", got, want)
	}
}

func TestService_ProofFailureClassification(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 9, 0, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	prover := &stubProver{err: sp1.NewPermanentError("sp1_invalid_input", errors.New("invalid witness"))}
	svc, err := New(Config{
		Owner:                  "requestor-a",
		ChainID:                8453,
		RequestTimeout:         5 * time.Second,
		CallbackIdempotencyTTL: 72 * time.Hour,
	}, store, prover, nil)
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
	if got, want := out.Status, StatusFailed; got != want {
		t.Fatalf("status: got %s want %s", got, want)
	}
	if out.ErrorCode != "sp1_invalid_input" {
		t.Fatalf("error code: got %q", out.ErrorCode)
	}
	if out.Retryable {
		t.Fatalf("expected non-retryable failure")
	}
}

func TestService_SkipsDuplicateDeliveryWhileLeaseActive(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 23, 16, 0, 0, 0, time.UTC)
	store := proof.NewMemoryStore(func() time.Time { return now })
	prover := &stubProver{seal: []byte{0xbb}}
	svc, err := New(Config{
		Owner:                  "requestor-a",
		ChainID:                8453,
		RequestTimeout:         5 * time.Minute,
		CallbackIdempotencyTTL: 72 * time.Hour,
	}, store, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	job := proof.JobRequest{
		JobID:        common.HexToHash("0x76f9b89ef12ee0d6d0f937ae9b73985a27bb85b6d0e9dd6fa738517a826ffba4"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(2 * time.Minute),
		Priority:     1,
	}

	if _, err := store.UpsertJob(context.Background(), job, 72*time.Hour); err != nil {
		t.Fatalf("UpsertJob: %v", err)
	}
	if _, claimed, err := store.ClaimForSubmission(context.Background(), job.JobID, "requestor-a", 5*time.Minute, 8453); err != nil {
		t.Fatalf("ClaimForSubmission: %v", err)
	} else if !claimed {
		t.Fatalf("expected initial claim to succeed")
	}

	out, err := svc.ProcessJob(context.Background(), job)
	if err != nil {
		t.Fatalf("ProcessJob: %v", err)
	}
	if got, want := out.Status, StatusSkipped; got != want {
		t.Fatalf("status: got %s want %s", got, want)
	}
	if prover.calls != 0 {
		t.Fatalf("prove calls: got %d want 0", prover.calls)
	}
}

func TestService_RecoversFulfillmentWhenStaleFailureLosesRace(t *testing.T) {
	t.Parallel()

	job := proof.JobRequest{
		JobID:        common.HexToHash("0x47c8d01d300c2ab17fddbd845cf987e16c5c5fd7f93d41822b5edcb36cd4e550"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     time.Date(2026, 3, 23, 16, 5, 0, 0, time.UTC),
		Priority:     1,
	}

	store := &terminalStateStore{
		record: proof.JobRecord{
			Job:            job,
			RequestID:      17,
			State:          proof.StateFulfilled,
			SubmissionPath: "sp1-network-mainnet",
			Seal:           []byte{0xaa},
			Metadata:       map[string]string{"provider": "sp1"},
		},
	}
	prover := &stubProver{err: sp1.NewRetryableError("sp1_request_unfulfillable", errors.New("auction returned unfulfillable"))}

	svc, err := New(Config{
		Owner:                  "requestor-a",
		ChainID:                8453,
		RequestTimeout:         5 * time.Minute,
		CallbackIdempotencyTTL: 72 * time.Hour,
	}, store, prover, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	out, err := svc.ProcessJob(context.Background(), job)
	if err != nil {
		t.Fatalf("ProcessJob: %v", err)
	}
	if got, want := out.Status, StatusFulfilled; got != want {
		t.Fatalf("status: got %s want %s", got, want)
	}
	if got, want := out.RequestID, uint64(17); got != want {
		t.Fatalf("request id: got %d want %d", got, want)
	}
	if got, want := out.SubmissionPath, "sp1-network-mainnet"; got != want {
		t.Fatalf("submission path: got %q want %q", got, want)
	}
	if len(out.Seal) == 0 {
		t.Fatalf("expected recovered seal")
	}
}

type terminalStateStore struct {
	record proof.JobRecord
}

func (s *terminalStateStore) UpsertJob(_ context.Context, _ proof.JobRequest, _ time.Duration) (bool, error) {
	return false, nil
}

func (s *terminalStateStore) AllocateRequestID(_ context.Context, _ uint64) (uint64, error) {
	return 0, nil
}

func (s *terminalStateStore) ClaimForSubmission(_ context.Context, _ common.Hash, _ string, _ time.Duration, _ uint64) (proof.JobRecord, bool, error) {
	rec := s.record
	rec.State = proof.StateSubmitting
	rec.ProcessingOwner = "requestor-a"
	rec.ProcessingExpiresAt = time.Now().Add(time.Minute)
	return rec, true, nil
}

func (s *terminalStateStore) MarkFulfilled(_ context.Context, _ common.Hash, _ string, _ uint64, _ []byte, _ map[string]string, _ string) (proof.JobRecord, error) {
	return s.record, proof.ErrTerminalState
}

func (s *terminalStateStore) MarkFailed(_ context.Context, _ common.Hash, _ string, _ uint64, _ string, _ string, _ bool) (proof.JobRecord, error) {
	return s.record, proof.ErrTerminalState
}

func (s *terminalStateStore) GetJob(_ context.Context, _ common.Hash) (proof.JobRecord, error) {
	return s.record, nil
}
