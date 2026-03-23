package proof

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestMemoryStore_DedupeOnRepeatedJobID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 11, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })

	job := JobRequest{
		JobID:        common.HexToHash("0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01, 0x02},
		PrivateInput: []byte{0x03, 0x04},
		Deadline:     now.Add(5 * time.Minute),
		Priority:     1,
	}

	created, err := store.UpsertJob(context.Background(), job, 72*time.Hour)
	if err != nil {
		t.Fatalf("UpsertJob first: %v", err)
	}
	if !created {
		t.Fatalf("expected first insert to be created")
	}

	created, err = store.UpsertJob(context.Background(), job, 72*time.Hour)
	if err != nil {
		t.Fatalf("UpsertJob second: %v", err)
	}
	if created {
		t.Fatalf("expected repeated job_id to dedupe")
	}

	mismatch := job
	mismatch.Pipeline = "withdraw"
	_, err = store.UpsertJob(context.Background(), mismatch, 72*time.Hour)
	if !errors.Is(err, ErrJobMismatch) {
		t.Fatalf("expected ErrJobMismatch, got %v", err)
	}
}

func TestMemoryStore_RequestIDAllocatorConcurrent(t *testing.T) {
	t.Parallel()

	store := NewMemoryStore(time.Now)
	const workers = 100

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		got  = make([]uint64, 0, workers)
		errs = make([]error, 0)
	)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := store.AllocateRequestID(context.Background(), 8453)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			got = append(got, id)
		}()
	}
	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("unexpected allocator errors: %v", errs)
	}
	if len(got) != workers {
		t.Fatalf("ids: got %d want %d", len(got), workers)
	}

	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	for i := 0; i < workers; i++ {
		want := uint64(i + 1)
		if got[i] != want {
			t.Fatalf("ids[%d]: got %d want %d", i, got[i], want)
		}
	}
}

func TestMemoryStore_ClaimForSubmissionSkipsActiveLeaseEvenForSameOwner(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 23, 16, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	job := JobRequest{
		JobID:        common.HexToHash("0x4314e7904fd1808ad5a2394a4e8e6cf6ccf8802f27195be7d87da01f5c23a1ee"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(15 * time.Minute),
		Priority:     1,
	}

	if _, err := store.UpsertJob(context.Background(), job, 72*time.Hour); err != nil {
		t.Fatalf("UpsertJob: %v", err)
	}

	first, claimed, err := store.ClaimForSubmission(context.Background(), job.JobID, "requestor-a", 15*time.Minute, 8453)
	if err != nil {
		t.Fatalf("ClaimForSubmission first: %v", err)
	}
	if !claimed {
		t.Fatalf("expected first claim to succeed")
	}
	if got, want := first.AttemptCount, 1; got != want {
		t.Fatalf("first attempt count: got %d want %d", got, want)
	}

	second, claimed, err := store.ClaimForSubmission(context.Background(), job.JobID, "requestor-a", 15*time.Minute, 8453)
	if err != nil {
		t.Fatalf("ClaimForSubmission second: %v", err)
	}
	if claimed {
		t.Fatalf("expected second claim to skip while lease is active")
	}
	if got, want := second.AttemptCount, 1; got != want {
		t.Fatalf("second attempt count: got %d want %d", got, want)
	}
	if got, want := second.RequestID, first.RequestID; got != want {
		t.Fatalf("request id: got %d want %d", got, want)
	}
	if got, want := second.State, StateSubmitting; got != want {
		t.Fatalf("state: got %s want %s", got, want)
	}
}

func TestMemoryStore_RejectsStaleFailureAfterFulfillment(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 23, 16, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	job := JobRequest{
		JobID:        common.HexToHash("0xe91ea2b8651687490c4f8c6f501c1081a679a98a18b0cab1ac31f16c72154840"),
		Pipeline:     "deposit",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa01"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(15 * time.Minute),
		Priority:     1,
	}

	if _, err := store.UpsertJob(context.Background(), job, 72*time.Hour); err != nil {
		t.Fatalf("UpsertJob: %v", err)
	}
	rec, claimed, err := store.ClaimForSubmission(context.Background(), job.JobID, "requestor-a", 15*time.Minute, 8453)
	if err != nil {
		t.Fatalf("ClaimForSubmission: %v", err)
	}
	if !claimed {
		t.Fatalf("expected claim to succeed")
	}
	if _, err := store.MarkFulfilled(context.Background(), job.JobID, "requestor-a", rec.RequestID, []byte{0xaa}, map[string]string{"provider": "sp1"}, "sp1-network-mainnet"); err != nil {
		t.Fatalf("MarkFulfilled: %v", err)
	}

	_, err = store.MarkFailed(context.Background(), job.JobID, "requestor-a", rec.RequestID, "sp1_request_unfulfillable", "stale failure", true)
	if !errors.Is(err, ErrTerminalState) {
		t.Fatalf("expected ErrTerminalState, got %v", err)
	}

	got, err := store.GetJob(context.Background(), job.JobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.State != StateFulfilled {
		t.Fatalf("state: got %s want %s", got.State, StateFulfilled)
	}
	if got.ErrorCode != "" {
		t.Fatalf("error code: got %q want empty", got.ErrorCode)
	}
}

func TestMemoryStore_RejectsStaleFulfillmentAfterTerminalFailure(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 23, 16, 0, 0, 0, time.UTC)
	store := NewMemoryStore(func() time.Time { return now })
	job := JobRequest{
		JobID:        common.HexToHash("0x564bb6981487b80ca3af9f12aa5a03c3d8dbd44ec1d8c6b75f2c505c4f760d2c"),
		Pipeline:     "withdraw",
		ImageID:      common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"),
		Journal:      []byte{0x01},
		PrivateInput: []byte{0x02},
		Deadline:     now.Add(15 * time.Minute),
		Priority:     1,
	}

	if _, err := store.UpsertJob(context.Background(), job, 72*time.Hour); err != nil {
		t.Fatalf("UpsertJob: %v", err)
	}
	rec, claimed, err := store.ClaimForSubmission(context.Background(), job.JobID, "requestor-a", 15*time.Minute, 8453)
	if err != nil {
		t.Fatalf("ClaimForSubmission: %v", err)
	}
	if !claimed {
		t.Fatalf("expected claim to succeed")
	}
	if _, err := store.MarkFailed(context.Background(), job.JobID, "requestor-a", rec.RequestID, "sp1_invalid_input", "bad witness", false); err != nil {
		t.Fatalf("MarkFailed: %v", err)
	}

	_, err = store.MarkFulfilled(context.Background(), job.JobID, "requestor-a", rec.RequestID, []byte{0xbb}, map[string]string{"provider": "sp1"}, "sp1-network-mainnet")
	if !errors.Is(err, ErrTerminalState) {
		t.Fatalf("expected ErrTerminalState, got %v", err)
	}

	got, err := store.GetJob(context.Background(), job.JobID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.State != StateFailedTerminal {
		t.Fatalf("state: got %s want %s", got.State, StateFailedTerminal)
	}
	if got.ErrorCode != "sp1_invalid_input" {
		t.Fatalf("error code: got %q want %q", got.ErrorCode, "sp1_invalid_input")
	}
}
